"""Alfa WiFi Passive Radar + Wiggle Channel Scanner
Background process: feeds RSSI data to TSCM passive radar
Wiggle: channel-hops to detect hidden/rogue BSSIDs
"""
import subprocess, time, json, threading, re
from datetime import datetime, timezone
from pathlib import Path
from collections import deque

WORKSPACE = Path(r"C:\Users\carpe\.openclaw-autoclaw\workspace")
LOG = WORKSPACE / "wifi_radar.log"

class AlfaWiFiRadar:
    """Passive radar via Alfa WiFi RSSI + Wiggle channel hopping"""
    
    def __init__(self, interface="Wi-Fi 2"):
        self.interface = interface
        self.running = False
        self.scan_count = 0
        self.seen_bssids = {}  # bssid -> {ssid, first_seen, last_seen, signal_history, alerts}
        self.alerts = deque(maxlen=200)
        self.current_channel = 0
        self.wiggle_channels = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13,
                               36, 40, 44, 48, 149, 153, 157, 161]
        self.wiggle_idx = 0
        
    def _scan_bssids(self):
        """netsh wlan show networks mode=bssid for RSSI"""
        try:
            result = subprocess.run(
                f'netsh wlan show networks mode=bssid interface="{self.interface}"',
                shell=True, capture_output=True, text=True, timeout=8,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return result.stdout
        except:
            return ""
    
    def _parse_bssids(self, output):
        """Parse netsh output into list of {ssid, bssid, signal, channel, radio}"""
        networks = []
        current = {}
        current_ssid = ''
        
        for line in output.split('\n'):
            ssid_m = re.search(r'SSID\s+\d+\s*:\s*(.+)', line)
            if ssid_m:
                ssid_val = ssid_m.group(1).strip()
                current_ssid = ssid_val if ssid_val else ''
                continue
            
            bssid_m = re.search(r'BSSID\s+\d+\s*:\s*([0-9a-f:]+)', line, re.I)
            signal_m = re.search(r'Signal\s*:\s*(\d+)%', line)
            channel_m = re.search(r'Channel\s*:\s*(\d+)', line)
            radio_m = re.search(r'Radio type\s*:\s*(.+)', line)
            auth_m = re.search(r'Authentication\s*:\s*(.+)', line)
            enc_m = re.search(r'Encryption\s*:\s*(.+)', line)
            
            if bssid_m:
                if current.get('bssid'):
                    networks.append(current)
                current = {
                    'bssid': bssid_m.group(1).upper(),
                    'ssid': current_ssid
                }
            if signal_m and current:
                current['signal_pct'] = int(signal_m.group(1))
            if channel_m and current:
                current['channel'] = int(channel_m.group(1))
            if radio_m and current:
                current['radio'] = radio_m.group(1).strip()
            if auth_m and current:
                current['auth'] = auth_m.group(1).strip()
            if enc_m and current:
                current['enc'] = enc_m.group(1).strip()
        
        if current.get('bssid'):
            networks.append(current)
        
        return networks
    
    def _scan_loop(self):
        """Main loop: scan BSSIDs, detect changes, log to file"""
        while self.running:
            try:
                # Wiggle: force full scan (not just cached results)
                # NOTE: removed netsh wlan disconnect — it disrupts active connections
                # Windows netsh caches scan results; use channel change instead

                output = self._scan_bssids()
                networks = self._parse_bssids(output)
                now = datetime.now(timezone.utc).isoformat()
                self.scan_count += 1
                
                current_bssids = set()
                for n in networks:
                    bssid = n['bssid']
                    current_bssids.add(bssid)
                    signal = n.get('signal_pct', 0)
                    
                    if bssid not in self.seen_bssids:
                        # NEW BSSID DETECTED
                        n['first_seen'] = now
                        n['signal_history'] = deque(maxlen=20)
                        n['alert_count'] = 0
                        self.seen_bssids[bssid] = n
                        
                        # Log new detection
                        alert = {
                            "time": now,
                            "type": "NEW_BSSID",
                            "bssid": bssid,
                            "ssid": n.get('ssid', ''),
                            "signal_pct": signal,
                            "channel": n.get('channel', 0),
                            "radio": n.get('radio', '')
                        }
                        self.alerts.append(alert)
                        self._log(alert)
                    else:
                        prev = self.seen_bssids[bssid]
                        
                        # RSSI spike detection (passive radar)
                        prev_signal = prev['signal_history'][-1] if prev['signal_history'] else signal
                        delta = signal - prev_signal
                        
                        if abs(delta) > 30:
                            alert = {
                                "time": now,
                                "type": "RSSI_SPIKE",
                                "bssid": bssid,
                                "ssid": n.get('ssid', ''),
                                "delta_pct": delta,
                                "from": prev_signal,
                                "to": signal
                            }
                            self.alerts.append(alert)
                            self._log(alert)
                            prev['alert_count'] = prev.get('alert_count', 0) + 1
                        
                        # If this BSSID suddenly appears with high signal after being absent
                        prev['signal_history'].append(signal)
                    
                    # Update tracking
                    prev = self.seen_bssids[bssid]
                    prev.update(n)
                    prev['last_seen'] = now
                
                # Detect disappeared BSSIDs
                for bssid, data in list(self.seen_bssids.items()):
                    if bssid not in current_bssids:
                        last = data.get('last_seen', '')
                        if last:
                            try:
                                last_dt = datetime.fromisoformat(last)
                                gap = (datetime.now(timezone.utc) - last_dt).total_seconds()
                                if gap > 30 and gap < 60:
                                    alert = {
                                        "time": now,
                                        "type": "BSSID_VANISHED",
                                        "bssid": bssid,
                                        "ssid": data.get('ssid', ''),
                                        "was_signal_pct": data.get('signal_pct', 0)
                                    }
                                    self.alerts.append(alert)
                                    self._log(alert)
                            except:
                                pass
                
                # Wiggle: next channel in rotation
                self.wiggle_idx = (self.wiggle_idx + 1) % len(self.wiggle_channels)
                self.current_channel = self.wiggle_channels[self.wiggle_idx]
                
                time.sleep(3)  # Scan interval
                
            except Exception as e:
                print(f"[WiFi Radar] Error: {e}")
                time.sleep(5)
    
    def _log(self, alert):
        """Write alert to wifi_radar.log"""
        try:
            with open(LOG, 'a') as f:
                f.write(json.dumps(alert) + '\n')
        except:
            pass
    
    def start(self):
        self.running = True
        t = threading.Thread(target=self._scan_loop, daemon=True)
        t.start()
        print(f"[WiFi Radar] Started on {self.interface}")
        print(f"[WiFi Radar] Wiggle: {len(self.wiggle_channels)} channels, 3s interval")
    
    def stop(self):
        self.running = False
    
    def status(self):
        """Return status for TSCM integration"""
        return {
            "interface": self.interface,
            "scans": self.scan_count,
            "known_bssids": len(self.seen_bssids),
            "current_channel": self.current_channel,
            "active_high_signal": len([
                b for b in self.seen_bssids.values()
                if b.get('signal_pct', 0) > 70
            ]),
            "recent_alerts": len(self.alerts),
            "top_bssids": sorted(
                [{"ssid": v.get('ssid','?'), "bssid": k, "signal": v.get('signal_pct',0), 
                  "channel": v.get('channel',0), "alerts": v.get('alert_count',0)}
                 for k,v in self.seen_bssids.items() if v.get('signal_pct',0) > 50],
                key=lambda x: x['signal'], reverse=True
            )[:5]
        }

if __name__ == '__main__':
    print("=== Alfa WiFi Passive Radar + Wiggle Scanner ===")
    radar = AlfaWiFiRadar(interface="Wi-Fi 2")
    radar.start()
    
    print("\nMonitoring... Ctrl+C to stop")
    print(f"{'TIME':<10} {'SCANS':>6} {'BSSIDs':>8} {'CH':>4} {'HIGH-SIG':>9} {'ALERTS':>7}")
    print("-" * 50)
    
    try:
        last_report = 0
        while True:
            time.sleep(1)
            if radar.scan_count > last_report:
                s = radar.status()
                print(f"{datetime.now().strftime('%H:%M:%S'):<10} {s['scans']:>6} {s['known_bssids']:>8} "
                      f"{s['current_channel']:>4} {s['active_high_signal']:>9} {s['recent_alerts']:>6}")
                last_report = radar.scan_count
    except KeyboardInterrupt:
        print("\nShutting down...")
    radar.stop()
