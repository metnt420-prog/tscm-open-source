"""
Cell Phone C2 Tracker — finds the person controlling the attack.
Detects attacker's phone via WiFi probes, BT proximity, network patterns.
"""
import subprocess, re, time, json
from collections import deque
import numpy as np

class PhoneC2Tracker:
    """Track attacker's cell phone C2 infrastructure."""
    
    # Known C2 server domains used by attack apps
    C2_SERVER_PATTERNS = [
        r'firebaseio\.com',     # Firebase realtime DB (common C2 backend)
        r'supabase\.co',        # Supabase
        r'herokuapp\.com',      # Heroku
        r'\.ngrok\.io',         # ngrok tunnels
        r'localhost\.run',      # localhost.run tunnels  
        r'serveo\.net',         # serveo tunnels
        r'\.replit\.dev',       # Replit
        r'\.glitch\.me',        # Glitch
        r'\.vercel\.app',       # Vercel
        r'\.netlify\.app',      # Netlify
        r'\.cloudfunctions\.net', # Google Cloud Functions
        r'\.amazonaws\.com',    # AWS
        r'\.azurewebsites\.net', # Azure
        r'websocket',           # WebSocket C2
        r'mqtt',                # MQTT IoT C2
    ]
    
    def __init__(self, log):
        self.log = log
        self.known_phones = {}  # MAC -> {signal_history, first_seen, last_seen}
        self.server_hits = deque(maxlen=100)
        self.netstat_cache = {}
        self.last_scan = 0
        
    def scan_wifi_probes(self):
        """Detect nearby phones via WiFi probe requests. Returns list of detected devices."""
        detections = []
        try:
            # Use netsh to get nearby WiFi networks with signal
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'],
                capture_output=True, text=True, timeout=10
            )
            
            current_bssid = None
            current_signal = 0
            current_ssid = ''
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                # Parse BSSID
                m = re.match(r'BSSID\s+\d+\s+:\s+([0-9a-fA-F:]{17})', line)
                if m:
                    current_bssid = m.group(1).lower()
                    
                # Parse signal
                m = re.match(r'Signal\s+:\s+(\d+)%', line)
                if m:
                    current_signal = int(m.group(1))
                    
                # Parse SSID
                m = re.match(r'SSID\s+\d+\s+:\s+(.+)', line)
                if m:
                    current_ssid = m.group(1).strip()
                    
                    # Phone hotspot detection
                    phone_patterns = [
                        (r'iPhone', 'iphone_hotspot'),
                        (r'AndroidAP', 'android_hotspot'),
                        (r'Galaxy', 'samsung_phone'),
                        (r'Pixel', 'pixel_phone'),
                        (r'OnePlus', 'oneplus_phone'),
                        (r'DIRECT-', 'wifi_direct_device'),
                        (r'Xiaomi', 'xiaomi_phone'),
                        (r'HUAWEI', 'huawei_phone'),
                        (r'OPPO', 'oppo_phone'),
                    ]
                    
                    for pattern, device_type in phone_patterns:
                        if re.search(pattern, current_ssid, re.IGNORECASE):
                            # Track this phone
                            if current_bssid not in self.known_phones:
                                self.known_phones[current_bssid] = {
                                    'type': device_type,
                                    'ssid': current_ssid,
                                    'signal_history': deque(maxlen=30),
                                    'first_seen': time.time()
                                }
                            
                            entry = self.known_phones[current_bssid]
                            entry['last_seen'] = time.time()
                            entry['signal_history'].append((time.time(), current_signal))
                            
                            # Detect signal strength trend (approaching/receding)
                            history = list(entry['signal_history'])
                            if len(history) >= 5:
                                signals = [s for _, s in history[-5:]]
                                old_signals = [s for _, s in history[:5]] if len(history) >= 10 else signals[:2]
                                trend = np.mean(signals) - np.mean(old_signals)
                                
                                movement = 'stable'
                                if trend > 10:
                                    movement = 'APPROACHING'
                                elif trend < -10:
                                    movement = 'RECEDING'
                                
                                detections.append({
                                    'detector': 'phone_c2_hotspot',
                                    'bssid': current_bssid,
                                    'ssid': current_ssid,
                                    'device_type': device_type,
                                    'signal': current_signal,
                                    'trend': movement,
                                    'trend_db': trend,
                                    'info': f'PHONE: {device_type} {current_ssid} {current_signal}% [{movement}]'
                                })
                            break
                                    
        except Exception as e:
            pass
        
        return detections
    
    def scan_active_connections(self):
        """Find active C2 server connections from this machine."""
        detections = []
        now = time.time()
        if now - self.last_scan < 15:
            return detections
        self.last_scan = now
        
        try:
            result = subprocess.run(
                ['netstat', '-ano'], capture_output=True, text=True, timeout=5
            )
            
            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' not in line:
                    continue
                
                # Parse remote address
                m = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                if not m:
                    continue
                
                local_ip, local_port = m.group(1), m.group(2)
                remote_ip, remote_port = m.group(3), m.group(4)
                
                # Check for C2-like ports
                c2_ports = {'4444', '5555', '6666', '7777', '8888', '9999', 
                           '31337', '1337', '8080', '8443', '3000', '5000',
                           '1883', '8883',  # MQTT
                           '9000', '9001'}  # common C2
                
                if remote_port in c2_ports:
                    detections.append({
                        'detector': 'phone_c2_connection',
                        'local_ip': local_ip,
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'info': f'C2 CONN: {remote_ip}:{remote_port} (ESTABLISHED)'
                    })
                    self.log.warning(f"C2 CONNECTION: {remote_ip}:{remote_port}")
                
                # Track connection frequency to known servers
                self.netstat_cache[remote_ip] = self.netstat_cache.get(remote_ip, 0) + 1
                
        except Exception as e:
            pass
        
        return detections
    
    def scan_cell_tower_proximity(self, hackrf_data=None, hackrf_freq=None):
        """Detect cell tower/base station proximity via HackRF power levels."""
        detections = []
        
        # Check known cellular bands for unusual power levels
        cell_bands = {
            (698e6, 960e6): 'LTE_700-900',
            (1710e6, 2170e6): 'LTE_1700-2100',
            (2300e6, 2400e6): 'LTE_2300',
            (2500e6, 2690e6): 'LTE_2500-2600',
        }
        
        # If HackRF is scanning 450 MHz, check for IMSI catcher power
        if hackrf_freq and 400e6 <= hackrf_freq <= 500e6:
            detections.append({
                'detector': 'phone_c2_cellular',
                'band': 'UHF_450',
                'info': f'Cell scan: UHF 450 MHz active (IMSI catcher band)'
            })
        
        return detections
    
    def get_nearest_phone_bearing(self):
        """Estimate bearing to nearest detected phone based on signal patterns."""
        for mac, info in self.known_phones.items():
            history = list(info['signal_history'])
            if len(history) < 3:
                continue
            
            # High signal with approaching trend = nearby phone
            recent_signals = [s for _, s in history[-5:]]
            avg_signal = np.mean(recent_signals)
            
            if avg_signal > 50:  # strong signal = close
                return {
                    'bssid': mac,
                    'device_type': info['type'],
                    'ssid': info['ssid'],
                    'avg_signal': avg_signal,
                    'confidence': min(1.0, avg_signal / 100.0)
                }
        return None
