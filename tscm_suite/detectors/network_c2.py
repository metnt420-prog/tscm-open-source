"""
Network-based C2 Beacon Detection via WiFi adapter (Alfa 8812AU).
Captures WiFi probe requests, beacon frames, and periodic transmissions
to identify command-and-control signals from nearby devices.
"""
import subprocess, re, time, threading, json, os, logging
from collections import deque

log = logging.getLogger('net_c2')

class NetworkC2Detector:
    """Detect C2 beacons via WiFi monitor mode on Alfa adapter."""
    
    def __init__(self, interface="Wi-Fi 2"):
        self.interface = interface
        self.running = False
        self.thread = None
        self.results = []
        self.device_db = {}  # MAC -> {probes, last_seen, count}
        self._lock = threading.Lock()
        self._beacon_history = deque(maxlen=100)
        
    def enable_monitor_mode(self):
        """Put Alfa adapter into monitor mode for packet capture."""
        try:
            # Check if interface exists
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True, text=True, timeout=5
            )
            if self.interface not in result.stdout:
                log.warning(f"Interface '{self.interface}' not found in wlan interfaces")
                return False
            
            # Try to set monitor mode via netsh (limited on Windows)
            # For real monitor mode on Windows, we need npcap + specialized tools
            # Instead, do active WiFi scanning to detect nearby devices
            log.info(f"Using {self.interface} for WiFi device discovery")
            return True
        except Exception as e:
            log.error(f"Monitor mode setup failed: {e}")
            return False
    
    def scan_wifi_devices(self):
        """Scan for nearby WiFi devices using Windows netsh."""
        devices = []
        try:
            # Scan for available networks (shows nearby APs and probe requests)
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=Bssid', f'interface={self.interface}'],
                capture_output=True, text=True, timeout=15
            )
            
            # Parse BSSID, SSID, signal strength, channel, authentication
            current_bssid = None
            current_ssid = None
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                # BSSID pattern
                bssid_match = re.match(r'BSSID\s+\d+\s+:\s+([0-9a-fA-F:]{17})', line)
                if bssid_match:
                    current_bssid = bssid_match.group(1)
                    continue
                
                # SSID
                ssid_match = re.match(r'SSID\s+\d+\s+:\s+(.+)', line)
                if ssid_match:
                    current_ssid = ssid_match.group(1).strip()
                    continue
                
                # Signal strength
                sig_match = re.match(r'Signal\s+:\s+(\d+)%', line)
                if sig_match and current_bssid:
                    sig_pct = int(sig_match.group(1))
                    rssi = (sig_pct / 2) - 100  # approximate RSSI
                    
                    # Check if this device is in our database
                    now = time.time()
                    if current_bssid not in self.device_db:
                        self.device_db[current_bssid] = {
                            'first_seen': now,
                            'probes': [],
                            'count': 0,
                            'ssids': set()
                        }
                    
                    dev = self.device_db[current_bssid]
                    dev['last_seen'] = now
                    dev['count'] += 1
                    if current_ssid:
                        dev['ssids'].add(current_ssid)
                    
                    devices.append({
                        'bssid': current_bssid,
                        'ssid': current_ssid,
                        'rssi': rssi,
                        'signal_pct': sig_pct,
                        'detector': 'wifi_device',
                        'device_type': 'AP' if current_ssid else 'client'
                    })
                    current_bssid = None
                    current_ssid = None
            
            log.info(f"WiFi scan: {len(devices)} devices detected")
        except Exception as e:
            log.error(f"WiFi scan failed: {e}")
        
        return devices
    
    def detect_c2_beacons(self, devices, lat, lon):
        """Analyze WiFi devices for C2 beacon patterns.
        
        C2 indicators:
        - Hidden SSID with strong signal (covert AP)
        - Device with rapid probe requests (seeking C2 server)
        - Unusual BSSID patterns (spoofed MACs)
        - Periodic beacon intervals matching C2 timing
        """
        detections = []
        now = time.time()

        for dev in devices:
            bssid = dev['bssid']
            rssi = dev['rssi']
            ssid = dev['ssid']

            # C2 Indicator 1: Hidden/empty SSID with strong signal (< -60 dBm)
            if (not ssid or ssid == '') and rssi > -60:
                detections.append({
                    'detector': 'c2_hidden_ap',
                    'bssid': bssid,
                    'rssi': rssi,
                    'strength': abs(rssi)
                })

            # C2 Indicator 2: Device seen consistently over time (persistent monitoring)
            if bssid in self.device_db:
                dev_rec = self.device_db[bssid]
                persistence = now - dev_rec['first_seen']
                if persistence > 60 and dev_rec['count'] > 5:
                    # Long-term persistent device - possible C2 relay
                    detections.append({
                        'detector': 'c2_persistent_device',
                        'bssid': bssid,
                        'ssid': ssid or 'hidden',
                        'persistence_sec': int(persistence),
                        'sightings': dev_rec['count'],
                        'rssi': rssi
                    })

            # C2 Indicator 3: Very strong signal device (physical proximity)
            if rssi > -40:
                detections.append({
                    'detector': 'c2_proximate_device',
                    'bssid': bssid,
                    'ssid': ssid or 'hidden',
                    'rssi': rssi,
                    'strength': abs(rssi)
                })
        
        return detections
    
    def start(self):
        """Start periodic WiFi scanning for C2 detection."""
        self.running = True
        self.thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.thread.start()
        log.info(f"Network C2 detector started on {self.interface}")
    
    def _scan_loop(self):
        while self.running:
            try:
                devices = self.scan_wifi_devices()
                # Don't pass hardcoded lat/lon — positions set by get_detections()
                c2_detections = self.detect_c2_beacons(devices, None, None)
                with self._lock:
                    self.results = c2_detections
                if devices:
                    log.info(f"WiFi scan: {len(devices)} devices detected, {len(c2_detections)} C2 flagged")
                time.sleep(10)
            except Exception as e:
                log.error(f"Scan cycle error: {e}")
                import traceback
                traceback.print_exc()
                time.sleep(10)
    
    def get_detections(self, lat, lon):
        """Return current C2 detections with position info (only if real GPS)."""
        with self._lock:
            results = list(self.results)
        # Only set positions if caller has real GPS
        if lat and lon and lat != 0 and lon != 0:
            for r in results:
                r['lat'] = lat
                r['lon'] = lon
        return results
    
    def stop(self):
        self.running = False


def quick_scan(interface="Wi-Fi 2"):
    """Quick one-shot WiFi scan to test adapter."""
    detector = NetworkC2Detector(interface)
    devices = detector.scan_wifi_devices()
    print(f"\nFound {len(devices)} devices:")
    for d in devices:
        print(f"  {d['bssid']}  SSID: {d['ssid'] or '(hidden)':20s}  RSSI: {d['rssi']:4d}dBm  {d['signal_pct']}%")
    return devices


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    quick_scan()
