"""
WiFi CSI (Channel State Information) analysis for presence/motion detection.
Uses netsh signal data as proxy for CSI on Windows (no monitor mode needed).
Tracks BSSID signal strength, channel utilization, and AP count changes.
"""
import time, subprocess, re, json, os, threading
from collections import deque, defaultdict
import numpy as np

class WifiCSIAnalyzer:
    """
    WiFi environment analysis using available Windows tools.
    Detects:
    - Sudden RSSI changes (motion/presence through walls)
    - New AP appearances (stingray/WiFi pineapple)
    - Channel utilization spikes (jamming/deauth attacks)
    - AP count anomalies (mobile surveillance unit)
    """
    
    def __init__(self, log, interface="Wi-Fi"):
        self.log = log
        self.interface = interface
        self.rssi_history = defaultdict(lambda: deque(maxlen=30))
        self.ap_count_history = deque(maxlen=30)
        self.channel_activity = defaultdict(lambda: deque(maxlen=20))
        self.alerts = deque(maxlen=50)
        self.last_scan = 0
        self.min_scan_interval = 5
        
    def scan_csi(self, access_points):
        """Analyze current WiFi environment and detect anomalies."""
        if not access_points:
            return []
        
        now = time.time()
        if now - self.last_scan < self.min_scan_interval:
            return []
        self.last_scan = now
        
        detections = []
        current_count = len(access_points)
        self.ap_count_history.append(current_count)
        
        # 1. AP count anomaly (new APs suddenly appearing = mobile unit)
        if len(self.ap_count_history) >= 5:
            avg_count = np.mean(list(self.ap_count_history)[:-1])
            if current_count > avg_count * 2.0 and current_count > 10:
                detections.append({
                    'detector': 'wifi_ap_surge',
                    'count': current_count,
                    'avg': avg_count,
                    'info': f'AP count surge: {current_count} vs avg {avg_count:.0f}'
                })
                self.log.warning(f"WiFi CSI: AP SURGE {current_count} (avg {avg_count:.0f}) - possible mobile unit")
        
        # 2. Per-AP RSSI tracking (motion detection)
        for ap in access_points:
            bssid = ap.get('bssid', '')
            ssid = ap.get('ssid', '?')
            signal = ap.get('signal', 0)
            ch = ap.get('channel', 0)
            
            if not bssid or signal == 0:
                continue
            
            # Track channel activity
            if ch:
                self.channel_activity[ch].append(signal)
            
            # Track RSSI
            self.rssi_history[bssid].append((now, signal))
            history = self.rssi_history[bssid]
            
            if len(history) >= 5:
                signals = [s for _, s in history]
                mean_sig = np.mean(signals)
                std_sig = np.std(signals)
                
                # 3. Sudden RSSI drop = someone walked between AP and us (motion)
                if std_sig > 10 and abs(signal - mean_sig) > 15:
                    detections.append({
                        'detector': 'wifi_motion',
                        'bssid': bssid,
                        'ssid': ssid,
                        'signal': signal,
                        'mean': mean_sig,
                        'info': f'Motion via {ssid}: RSSI {signal}% vs mean {mean_sig:.0f}%'
                    })
                
                # 4. Consistent signal increase = approaching transmitter
                if len(history) >= 10:
                    recent = [s for _, s in list(history)[-5:]]
                    old = [s for _, s in list(history)[:5]]
                    if np.mean(recent) - np.mean(old) > 15:
                        detections.append({
                            'detector': 'wifi_approaching',
                            'bssid': bssid,
                            'ssid': ssid,
                            'delta': np.mean(recent) - np.mean(old),
                            'info': f'Approaching: {ssid} +{np.mean(recent)-np.mean(old):.0f}%'
                        })
        
        # 5. Channel utilization spike (possible WiFi jammer)
        for ch, signals in self.channel_activity.items():
            if len(signals) >= 3:
                avg_ch = np.mean(list(signals)[-3:])
                if avg_ch > 80:  # very high RSSI on one channel
                    detections.append({
                        'detector': 'wifi_channel_anomaly',
                        'channel': ch,
                        'avg_signal': avg_ch,
                        'info': f'Channel {ch} anomaly: avg signal {avg_ch:.0f}%'
                    })
        
        for d in detections:
            self.alerts.append(d)
        
        return detections
    
    def get_ap_positions_over_time(self, access_points, lat, lon):
        """Build local AP position map from RSSI + GPS over time."""
        result = []
        for ap in (access_points or []):
            bssid = ap.get('bssid', '')
            signal = ap.get('signal', 0)
            if bssid and signal > 0:
                # RSSI to distance: ~1m per 2% signal drop from 100%
                dist_m = max(1, (100 - signal) * 2)
                result.append({
                    'bssid': bssid,
                    'ssid': ap.get('ssid', '?'),
                    'signal': signal,
                    'est_distance_m': dist_m,
                    'observer_lat': lat,
                    'observer_lon': lon,
                    'channel': ap.get('channel', 0)
                })
        return result
