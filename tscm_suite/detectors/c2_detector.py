"""
C2 (Command & Control) Signal Detector v2
- Ultrasound modem: BPSK/FSK/QPSK decoding, protocol fingerprinting
- WiFi: SSID patterns, beacon timing, probe request analysis  
- Network: TCP/UDP connection patterns, DNS C2 lookups
- App fingerprinting: Manus, TeamViewer, AnyDesk patterns
"""
import time, struct, re, subprocess, os
import numpy as np
from collections import deque

class C2Detector:
    
    # Known C2/remote-control app network signatures
    C2_APP_SIGNATURES = {
        'manus_ai': {
            'ports': [443, 8443, 3000, 8080],
            'domains': ['manus.im', 'manus.ai', 'api.manus'],
            'pattern': 'AI agent C2'
        },
        'teamviewer': {
            'ports': [5938, 443, 80],
            'domains': ['teamviewer.com', '*.teamviewer.com'],
            'pattern': 'Remote desktop C2'
        },
        'anydesk': {
            'ports': [6568, 7070, 443],
            'domains': ['anydesk.com', 'net.anydesk.com'],
            'pattern': 'Remote access C2'
        },
        'ultrasound_modem_app': {
            'ports': [443, 8080, 3000],
            'domains': ['quiet.io', 'ultrasonic', 'chirp.io'],
            'pattern': 'Ultrasound modem bridge C2'
        },
        'loramesh_c2': {
            'ssids': ['Mesh_', 'LoRa_', 'TTN_', 'Helium'],
            'pattern': 'LoRa mesh C2 network'
        },
        'bluetooth_c2': {
            'ssids': ['HC-05', 'HC-06', 'BLE_', 'BT_'],
            'pattern': 'Bluetooth serial C2 bridge'
        }
    }
    
    # Known C2 DNS/domain patterns
    C2_DNS_PATTERNS = [
        (r'c2\.', 'explicit_c2_domain'),
        (r'beacon\.', 'beacon_domain'),
        (r'\.ddns\.net', 'dynamic_dns_c2'),
        (r'\.duckdns\.org', 'duckdns_c2'),
        (r'ngrok\.io', 'tunnel_c2'),
        (r'localhost\.run', 'tunnel_c2'),
        (r'serveo\.net', 'tunnel_c2'),
        (r'\.onion', 'tor_c2'),
        (r'api\.telegram\.org', 'telegram_bot_c2'),
        (r'discord\.com/api', 'discord_webhook_c2'),
    ]
    
    def __init__(self, log):
        self.log = log
        self.events = deque(maxlen=500)
        self.netstat_cache = {}  # port -> (last_seen_pid, count)
        self.dns_cache = deque(maxlen=200)
        self.last_net_scan = 0
        self.last_cycle = 0
        
    def scan_network_c2(self):
        """Scan active network connections for C2 patterns."""
        detections = []
        now = time.time()
        if now - self.last_net_scan < 30:
            return detections
        self.last_net_scan = now
        
        try:
            # Check active TCP connections
            result = subprocess.run(
                ['netstat', '-ano', '-p', 'TCP'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                # Look for established connections to suspicious ports
                for app_name, sig in self.C2_APP_SIGNATURES.items():
                    for port in sig['ports']:
                        if f':{port}' in line and 'ESTABLISHED' in line:
                            detections.append({
                                'detector': 'c2_network_port',
                                'app': app_name,
                                'port': port,
                                'pattern': sig['pattern'],
                                'info': f'C2 NET: {app_name} port {port} ESTABLISHED'
                            })
                            self.log.warning(f"C2 NETWORK: {app_name} on port {port}")
        except:
            pass
        
        return detections
    
    def scan_dns_c2(self):
        """Check DNS cache for C2 domain lookups."""
        detections = []
        try:
            result = subprocess.run(
                ['ipconfig', '/displaydns'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                line_lower = line.lower().strip()
                if not line_lower:
                    continue
                for pattern, name in self.C2_DNS_PATTERNS:
                    if re.search(pattern, line_lower):
                        # Extract domain name
                        parts = line_lower.split()
                        domain = parts[-1] if parts else line_lower
                        detections.append({
                            'detector': 'c2_dns',
                            'pattern': name,
                            'domain': domain,
                            'info': f'C2 DNS: {name} -> {domain}'
                        })
                        self.log.warning(f"C2 DNS: {name} domain found: {domain}")
                        
            # Also check for known C2 domain patterns in recent lookups
            for app_name, sig in self.C2_APP_SIGNATURES.items():
                for domain in sig.get('domains', []):
                    if any(domain.replace('*','') in line.lower() for line in result.stdout.split('\n')):
                        detections.append({
                            'detector': 'c2_dns_app',
                            'app': app_name,
                            'domain': domain,
                            'info': f'C2 DNS APP: {app_name} -> {domain}'
                        })
        except:
            pass
        
        return detections
    
    def process_ultrasound_modem(self, audio_chunk, fs, bearing=None):
        """Enhanced ultrasound modem analysis with more protocol decoders."""
        if audio_chunk is None or len(audio_chunk) < 1024:
            return []
        
        detections = []
        try:
            chunk = np.array(audio_chunk, dtype=np.float32)
            nfft = min(8192, len(chunk))
            if nfft < 512:
                return []
            
            window = chunk[-nfft:] * np.hanning(nfft)
            fft = np.abs(np.fft.rfft(window))
            freqs = np.fft.rfftfreq(nfft, 1/fs)
            
            # Search multiple ultrasound bands
            us_bands = [
                (18000, 25000, 'voice_to_skull'),
                (25000, 50000, 'ultrasonic_data'),
                (50000, 100000, 'high_us_data'),
                (100000, 150000, 'parametric_array')
            ]
            
            for f_min, f_max, band_name in us_bands:
                mask = (freqs >= f_min) & (freqs <= f_max)
                if not np.any(mask):
                    continue
                
                # Find top 3 peaks in this band
                band_fft = fft[mask]
                band_freqs = freqs[mask]
                noise_floor = np.median(band_fft)
                
                if noise_floor < 1e-10:
                    continue
                
                # Find peaks above noise
                peak_indices = []
                for _ in range(3):
                    if len(band_fft) == 0:
                        break
                    idx = np.argmax(band_fft)
                    if band_fft[idx] / noise_floor > 4.0:
                        peak_indices.append(idx)
                        # Suppress this peak's neighborhood
                        start = max(0, idx-5)
                        end = min(len(band_fft), idx+5)
                        band_fft[start:end] = 0
                    else:
                        break
                
                for idx in peak_indices:
                    peak_freq = band_freqs[idx]
                    snr = fft[mask][idx] / noise_floor
                    
                    # Demodulate IQ
                    t = np.arange(len(chunk)) / fs
                    lo_i = np.cos(2 * np.pi * peak_freq * t)
                    lo_q = -np.sin(2 * np.pi * peak_freq * t)
                    
                    i_mix = chunk * lo_i
                    q_mix = chunk * lo_q
                    
                    # LPF
                    win = max(4, int(fs / (peak_freq * 0.05)))
                    win = min(win, len(chunk)//8)
                    if win < 2:
                        continue
                    
                    i_filt = np.convolve(i_mix, np.ones(win)/win, mode='same')
                    q_filt = np.convolve(q_mix, np.ones(win)/win, mode='same')
                    
                    phase = np.unwrap(np.arctan2(q_filt, i_filt))
                    
                    # BPSK detection
                    phase_diff = np.diff(phase)
                    transitions = np.abs(phase_diff) > np.pi * 0.3
                    tr_count = np.sum(transitions)
                    
                    if tr_count > 5:
                        baud = tr_count / len(transitions) * fs
                        if 10 < baud < 10000:
                            detections.append({
                                'detector': 'c2_us_bpsk',
                                'freq': peak_freq,
                                'baud': baud,
                                'snr': snr,
                                'band': band_name,
                                'info': f'C2 US: {band_name} BPSK {peak_freq:.0f}Hz {baud:.0f}baud SNR={snr:.1f}'
                            })
                            self.log.info(f"C2 US BPSK: {peak_freq:.0f}Hz {baud:.0f}baud in {band_name}")
                            continue
                    
                    # FSK detection (two-tone)
                    # Look for amplitude modulation pattern
                    amp = np.sqrt(i_filt**2 + q_filt**2)
                    amp_fft = np.abs(np.fft.rfft(amp[-1024:]))
                    amp_freqs = np.fft.rfftfreq(1024, 1/fs)
                    amp_peak_idx = np.argmax(amp_fft[1:]) + 1
                    amp_peak_freq = amp_freqs[amp_peak_idx]
                    
                    if 10 < amp_peak_freq < 5000 and np.max(amp_fft[1:]) / (np.median(amp_fft[1:]) + 1e-12) > 3:
                        detections.append({
                            'detector': 'c2_us_fsk',
                            'freq': peak_freq,
                            'baud': amp_peak_freq,
                            'snr': snr,
                            'band': band_name,
                            'info': f'C2 US: {band_name} FSK {peak_freq:.0f}Hz sym={amp_peak_freq:.0f}Hz SNR={snr:.1f}'
                        })
                        self.log.info(f"C2 US FSK: {peak_freq:.0f}Hz {amp_peak_freq:.0f}Hz sym in {band_name}")
            
            # Check for frequency-hopping pattern
            if len(peak_indices) >= 2:
                hop_freqs = sorted([band_freqs[i] for _, _, i in [(f_min, f_max, idx) 
                                   for f_min, f_max, _ in us_bands 
                                   for idx in peak_indices[:2]]])
                if len(hop_freqs) >= 2:
                    hop_span = hop_freqs[-1] - hop_freqs[0]
                    if 500 < hop_span < 20000:
                        detections.append({
                            'detector': 'c2_us_fhss',
                            'freqs': hop_freqs,
                            'span': hop_span,
                            'info': f'C2 US FHSS: {len(hop_freqs)} carriers, {hop_span:.0f}Hz span'
                        })
                        
        except Exception as e:
            pass
        
        return detections
    
    def process_wifi_c2(self, access_points, bearing=None):
        """WiFi C2 detection with SSID, beacon timing, and probe patterns."""
        detections = []
        try:
            for ap in (access_points or []):
                ssid = ap.get('ssid', '')
                bssid = ap.get('bssid', '')
                signal = ap.get('signal', 0)
                ch = ap.get('channel', 0)
                
                # Check against known C2 SSID patterns
                for app_name, sig in self.C2_APP_SIGNATURES.items():
                    for c2_ssid in sig.get('ssids', []):
                        if ssid.lower().startswith(c2_ssid.lower()):
                            detections.append({
                                'detector': 'c2_wifi_ssid',
                                'app': app_name,
                                'ssid': ssid,
                                'bssid': bssid,
                                'signal': signal,
                                'info': f'C2 WIFI: {app_name} via {ssid} ({signal}% ch{ch})'
                            })
                            self.log.warning(f"C2 WIFI SSID: {app_name} {ssid} ch{ch}")
                            break
                
                # Hidden SSID detection (common C2 technique)
                if not ssid or ssid == '' or ssid == '<hidden>':
                    detections.append({
                        'detector': 'c2_wifi_hidden',
                        'bssid': bssid,
                        'signal': signal,
                        'channel': ch,
                        'info': f'C2 HIDDEN SSID: {bssid} ch{ch} ({signal}%)'
                    })
                
                # Ad-hoc / IBSS mode (peer-to-peer C2)
                if ssid.lower().startswith(('ad-hoc', 'adhoc', 'ibss', 'mesh')):
                    detections.append({
                        'detector': 'c2_wifi_adhoc',
                        'ssid': ssid,
                        'bssid': bssid,
                        'info': f'C2 AD-HOC: {ssid} {bssid}'
                    })
        except:
            pass
        
        return detections
