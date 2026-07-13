"""
WiFi-Ultrasound Correlation Engine
Finds the attacker by correlating WiFi device activity with ultrasound modem activity.

The attacker's phone:
1. Runs the ultrasound modem app (produces US carriers we detect)
2. Connects to WiFi (shows up in our WiFi scan)
3. When the modem transmits, the phone's WiFi may show increased traffic

By correlating these, we can identify WHICH WiFi device is the attacker's phone.
"""
import time, numpy as np
from collections import deque

class CorrelationEngine:
    """Correlate WiFi activity with ultrasound activity to find the C2 phone."""
    
    def __init__(self, log):
        self.log = log
        self.wifi_events = deque(maxlen=200)    # (timestamp, bssid, ssid, signal, channel)
        self.ultrasound_events = deque(maxlen=200)  # (timestamp, freq, detector, snr)
        self.correlations = deque(maxlen=50)
        
    def record_wifi(self, bssid, ssid, signal, channel):
        """Record a WiFi observation."""
        self.wifi_events.append((time.time(), bssid, ssid, signal, channel))
    
    def record_ultrasound(self, freq, detector, snr):
        """Record an ultrasound observation."""
        self.ultrasound_events.append((time.time(), freq, detector, snr))
    
    def analyze(self):
        """Find correlations between WiFi and ultrasound activity."""
        now = time.time()
        window = 60  # 60 second correlation window
        
        # Get recent events
        recent_wifi = [e for e in self.wifi_events if now - e[0] < window]
        recent_us = [e for e in self.ultrasound_events if now - e[0] < window]
        
        if len(recent_wifi) < 3 or len(recent_us) < 3:
            return []
        
        results = []
        
        # For each WiFi device, check if its signal changes correlate with US activity
        # Group WiFi events by BSSID
        wifi_by_bssid = {}
        for ts, bssid, ssid, signal, channel in recent_wifi:
            if bssid not in wifi_by_bssid:
                wifi_by_bssid[bssid] = {'ssid': ssid, 'signals': [], 'channel': channel}
            wifi_by_bssid[bssid]['signals'].append((ts, signal))
        
        # Group US events by time bins (5 second bins)
        us_by_time = {}
        for ts, freq, detector, snr in recent_us:
            bin_key = int(ts / 5) * 5
            if bin_key not in us_by_time:
                us_by_time[bin_key] = []
            us_by_time[bin_key].append((freq, detector, snr))
        
        # For each BSSID, compute correlation between signal changes and US activity
        for bssid, info in wifi_by_bssid.items():
            if len(info['signals']) < 3:
                continue
            
            # WiFi signal variance (device that fluctuates = active data transfer)
            signals = [s for _, s in info['signals']]
            signal_var = np.var(signals)
            signal_mean = np.mean(signals)
            
            # Count US events during this BSSID's observation period
            wifi_times = [t for t, _ in info['signals']]
            wifi_start = min(wifi_times)
            wifi_end = max(wifi_times)
            
            us_count = sum(1 for t, _, _, _ in self.ultrasound_events 
                          if wifi_start <= t <= wifi_end)
            
            # Correlation score:
            # High signal variance + high US count = likely the C2 phone
            # (phone is actively communicating via both WiFi and ultrasound)
            if signal_mean > 0:
                var_score = min(signal_var / (signal_mean ** 2 + 1), 1.0)
            else:
                var_score = 0
            
            us_score = min(us_count / 10.0, 1.0)
            
            correlation = var_score * 0.4 + us_score * 0.6
            
            if correlation > 0.3:
                results.append({
                    'bssid': bssid,
                    'ssid': info['ssid'],
                    'channel': info['channel'],
                    'signal_mean': float(signal_mean),
                    'signal_var': float(signal_var),
                    'us_events': us_count,
                    'correlation': float(correlation),
                    'info': f"CORRELATED: {info['ssid']} ({bssid[-8:]}) ch={info['channel']} sig={signal_mean:.0f}% var={signal_var:.1f} us_events={us_count} corr={correlation:.2f}"
                })
                
                if correlation > 0.6:
                    self.log.warning(f"C2 PHONE IDENTIFIED: {info['ssid']} ({bssid[-8:]}) correlation={correlation:.2f}")
        
        # Sort by correlation
        results.sort(key=lambda x: x['correlation'], reverse=True)
        
        for r in results:
            self.correlations.append(r)
        
        return results
