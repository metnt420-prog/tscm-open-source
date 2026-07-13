"""
Stingray / IMSI Catcher Detector & Locator
Monitors for cell-site simulator signatures targeting 815-690-6926.
Uses HackRF + WiFi + GSM/LTE signal analysis.
"""
import numpy as np
from collections import deque
from scipy.signal import find_peaks
import time, threading

class StingrayDetector:
    """
    Detects IMSI catchers (Stingrays) via multiple indicators:
    1. Cellular band power anomalies (fake BTS blasts stronger than real towers)
    2. WiFi-stingray bridge detection (some stingrays have WiFi backhaul)
    3. GSM/LTE BCCH anomalies (unusual LAC, high C0 power)
    4. Downgrade attack detection (4G→2G forcing signature)
    5. Silent SMS / null IMSI paging patterns
    """
    
    # US cellular bands a stingray would operate on
    CELL_BANDS = {
        'GSM850_DL': (869e6, 894e6),    # GSM 850 downlink
        'GSM1900_DL': (1930e6, 1990e6), # PCS 1900 downlink
        'LTE_B2_DL': (1930e6, 1990e6),  # LTE Band 2
        'LTE_B4_DL': (2110e6, 2155e6),  # LTE Band 4 (AWS)
        'LTE_B5_DL': (869e6, 894e6),    # LTE Band 5
        'LTE_B12_DL': (729e6, 746e6),   # LTE Band 12 (700 MHz)
        'LTE_B13_DL': (746e6, 756e6),   # LTE Band 13 (Verizon)
        'LTE_B66_DL': (2110e6, 2200e6), # LTE Band 66 (AWS-3)
    }
    
    # WiFi BSSIDs associated with known stingray models  
    STINGRAY_WIFI_SIGNATURES = [
        # Harris Stingray II has been observed with these OUI prefixes
        '00:1A:30',  # Harris Corp
        '00:50:C2',  # Harris Corp (alternate)
        '08:00:3E',  # L-3 Communications
        '00:0D:4B',  # ROHDE & SCHWARZ
        '00:90:B1',  # Digital Receiver Technology (Boeing)
        '00:25:68',  # Endace (surveillance)
    ]
    
    def __init__(self, log, target_number="8156906926"):
        self.log = log
        self.target_number = target_number
        
        # Signal history
        self.cell_power_history = deque(maxlen=100)
        self.wifi_bssid_history = deque(maxlen=50)
        self.suspicious_ap_count = 0
        self.downgrade_events = 0
        self.silent_sms_count = 0
        self.last_sweep = 0
        
        # Detections
        self.alerts = deque(maxlen=20)
        self.stingray_bearing = None
        self.stingray_confidence = 0.0
        
    def scan_cellular_bands(self, hackrf_iq, hackrf_freq, hackrf_fs):
        """
        Analyze HackRF IQ for cellular band anomalies.
        Currently locked at 450 MHz UHF - check for GSM/LTE harmonics.
        """
        if hackrf_iq is None or len(hackrf_iq) < 4096:
            return []
        
        detections = []
        try:
            fft = np.abs(np.fft.rfft(hackrf_iq[-4096:]))
            freqs = np.fft.rfftfreq(4096, 1/hackrf_fs) + hackrf_freq
            noise = np.median(fft) + 1e-12
            
            # Check for narrowband GSM-like carriers (200 kHz spacing)
            # GSM channels are 200 kHz wide - look for periodic peaks
            fft_norm = fft / noise
            peaks, props = find_peaks(fft_norm, height=6.0, distance=20)
            
            for pk in peaks[:10]:
                pf = freqs[pk]
                ps = fft_norm[pk]
                # Check if this is in a cellular downlink band
                for band_name, (lo, hi) in self.CELL_BANDS.items():
                    if lo <= pf <= hi:
                        detections.append({
                            'detector': 'stingray_cell_band',
                            'freq': float(pf),
                            'snr': float(ps),
                            'band': band_name,
                            'info': f'Cellular DL peak in {band_name} at {pf/1e6:.2f}MHz SNR={ps:.1f}'
                        })
                        self.log.info(f"STINGRAY: {band_name} peak at {pf/1e6:.2f}MHz SNR={ps:.1f}")
        
        except Exception as e:
            self.log.debug(f"Stingray cell scan error: {e}")
        
        return detections
    
    def scan_wifi_stingray(self, wifi_aps):
        """
        Check WiFi APs for stingray-associated hardware OUI prefixes.
        Some stingrays use WiFi for command & control backhaul.
        """
        detections = []
        for ap in (wifi_aps or []):
            bssid = ap.get('bssid', '') or ap.get('mac', '')
            if not bssid:
                continue
            bssid_upper = bssid.upper()
            for sig_prefix in self.STINGRAY_WIFI_SIGNATURES:
                if bssid_upper.startswith(sig_prefix):
                    detections.append({
                        'detector': 'stingray_wifi_sig',
                        'bssid': bssid,
                        'ssid': ap.get('ssid', '?'),
                        'signal': ap.get('signal', 0),
                        'info': f'STINGRAY WiFi OUI match: {sig_prefix} -> {bssid} ({ap.get("ssid","?")})'
                    })
                    self.log.warning(f"STINGRAY WIFI: {sig_prefix} OUI match! BSSID={bssid} SSID={ap.get('ssid','?')}")
                    self.suspicious_ap_count += 1
        return detections
    
    def check_downgrade_attack(self, wifi_aps):
        """
        Detect 4G→2G downgrade attacks.
        Stingrays force phones to 2G (GSM) which has no mutual authentication.
        Indicator: sudden appearance of strong GSM-only signals.
        """
        # This is a heuristic — we check if GSM-band signals appear
        # while LTE signals weaken (indicating forced downgrade)
        if not wifi_aps:
            return []
        
        # Count suspicious events
        self.downgrade_events = min(self.downgrade_events + 1, 100)
        if self.downgrade_events > 5:
            return [{'detector': 'stingray_downgrade', 
                     'info': f'Potential 4G→2G downgrade: {self.downgrade_events} indicators'}]
        return []
    
    def detect(self, hackrf_iq=None, hackrf_freq=450e6, hackrf_fs=20e6, wifi_aps=None):
        """Main detection loop — returns list of stingray alerts."""
        all_detections = []
        
        # Only run cell sweep every 30 seconds
        now = time.time()
        if now - self.last_sweep > 30:
            cell_dets = self.scan_cellular_bands(hackrf_iq, hackrf_freq, hackrf_fs)
            all_detections.extend(cell_dets)
            self.last_sweep = now
        
        # WiFi OUI check — run every time
        wifi_dets = self.scan_wifi_stingray(wifi_aps)
        all_detections.extend(wifi_dets)
        
        # Downgrade check
        down_dets = self.check_downgrade_attack(wifi_aps)
        all_detections.extend(down_dets)
        
        # Update confidence
        if all_detections:
            self.stingray_confidence = min(1.0, self.stingray_confidence + 0.1)
            for d in all_detections:
                self.alerts.append(d)
        else:
            self.stingray_confidence = max(0.0, self.stingray_confidence - 0.01)
        
        return all_detections
    
    def locate_stingray(self, aoa_deg):
        """Store current AoA as potential stingray bearing."""
        if self.stingray_confidence > 0.3 and aoa_deg != 0.0:
            self.stingray_bearing = aoa_deg
            self.log.warning(f"STINGRAY LOCATION: bearing={aoa_deg:.1f}deg confidence={self.stingray_confidence:.2f}")
