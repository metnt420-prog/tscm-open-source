"""
WiFi C2 Source Tracker — identifies attacker's phone/hotspot from WiFi scan data.
Maps WiFi devices with signal strength to estimate proximity.
"""
import subprocess, re, time
import numpy as np

class WiFiC2Tracker:
    """Track WiFi devices that could be C2 sources."""
    
    SUSPICIOUS_SSID_PATTERNS = [
        (r'pwned', 'honeypot_or_c2'),
        (r'DIRECT-', 'wifi_direct_c2'),
        (r'iPhone', 'iphone_hotspot'),
        (r'AndroidAP', 'android_hotspot'),
        (r'moto', 'motorola_phone'),
        (r'Galaxy', 'samsung_phone'),
        (r'Pixel', 'pixel_phone'),
    ]
    
    def __init__(self, log):
        self.log = log
        self.known_devices = {}  # BSSID -> {ssid, signal_history, first_seen}
        self.last_scan = 0
        
    def scan(self, observer_lat, observer_lon):
        """Scan WiFi and identify C2 sources. Returns list of detections."""
        now = time.time()
        if now - self.last_scan < 15:
            return []
        self.last_scan = now
        
        detections = []
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'],
                capture_output=True, text=True, timeout=10
            )
            
            current_ssid = ''
            current_bssid = ''
            current_signal = 0
            current_auth = ''
            current_channel = 0
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                m = re.match(r'SSID\s+\d+\s*:\s*(.*)', line)
                if m:
                    current_ssid = m.group(1).strip()
                    
                m = re.match(r'BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})', line)
                if m:
                    current_bssid = m.group(1).lower()
                    
                m = re.match(r'Signal\s*:\s*(\d+)%', line)
                if m:
                    current_signal = int(m.group(1))
                    
                m = re.match(r'Authentication\s*:\s*(.*)', line)
                if m:
                    current_auth = m.group(1).strip()
                    
                m = re.match(r'Channel\s*:\s*(\d+)', line)
                if m:
                    current_channel = int(m.group(1))
                    # End of BSSID block — process
                    if current_bssid and current_signal > 0:
                        self._process_device(
                            current_ssid, current_bssid, current_signal,
                            current_auth, current_channel,
                            observer_lat, observer_lon, detections)
                        
            # Check for hidden SSIDs (empty SSID with WPA)
            if current_bssid and not current_ssid and current_signal > 0:
                self._process_device(
                    '(hidden)', current_bssid, current_signal,
                    current_auth, current_channel,
                    observer_lat, observer_lon, detections)
                    
        except Exception as e:
            pass
        
        return detections
    
    def _process_device(self, ssid, bssid, signal, auth, channel, lat, lon, detections):
        """Check if this WiFi device is a C2 source."""
        # Track all devices
        if bssid not in self.known_devices:
            self.known_devices[bssid] = {
                'ssid': ssid, 'signal_history': [], 'first_seen': time.time(),
                'auth': auth, 'channel': channel
            }
        self.known_devices[bssid]['signal_history'].append((time.time(), signal))
        self.known_devices[bssid]['last_seen'] = time.time()
        
        # Check if suspicious
        is_suspicious = False
        c2_type = 'unknown_wifi'
        
        # Check SSID patterns
        for pattern, ctype in self.SUSPICIOUS_SSID_PATTERNS:
            if re.search(pattern, ssid, re.IGNORECASE):
                is_suspicious = True
                c2_type = ctype
                break
        
        # Hidden SSID with strong signal
        if (ssid == '(hidden)' or not ssid) and signal > 30:
            is_suspicious = True
            c2_type = 'hidden_network'
        
        # Phone hotspot (cell phone running C2 app)
        if any(k in ssid.lower() for k in ['moto', 'iphone', 'android', 'galaxy', 'pixel', '5g']):
            is_suspicious = True
            c2_type = 'phone_hotspot'
        
        # "pwned" = obvious C2 or honeypot
        if 'pwned' in ssid.lower():
            is_suspicious = True
            c2_type = 'c2_honeypot'
        
        if is_suspicious:
            # Estimate distance from signal (rough: every 6dB = double distance)
            # -30dBm = ~1m, -60dBm = ~10m, -80dBm = ~50m
            # Signal % is approximate: 100% ≈ -30dBm, 50% ≈ -60dBm
            est_distance_m = max(1, 10 ** ((100 - signal) / 40))  # rough estimate
            
            detections.append({
                'detector': f'wifi_c2_{c2_type}',
                'ssid': ssid,
                'bssid': bssid,
                'signal': signal,
                'channel': channel,
                'auth': auth,
                'c2_type': c2_type,
                'est_distance_m': est_distance_m,
                'info': f'WIFI C2: {ssid} ({c2_type}) {signal}% ch={channel} ~{est_distance_m:.0f}m'
            })
            
            if signal > 50:
                self.log.warning(f"WIFI C2 NEARBY: {ssid} ({c2_type}) signal={signal}% BSSID={bssid} ch={channel}")
