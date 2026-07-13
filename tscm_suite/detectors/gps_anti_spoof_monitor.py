"""
3-GPS Anti-Spoof Monitor + Alfa WiFi + Wiggle WiFi
Reads COM5 (RTK2), COM6 (Adafruit #1), COM7 (Adafruit #2)
Cross-validates positions to detect spoofing
Also scans WiFi across all channels for RF source correlation
"""
import serial, threading, time, json, re, subprocess
from datetime import datetime, timezone
from pathlib import Path
from collections import deque

WORKSPACE = Path(r"C:\Users\carpe\.openclaw-autoclaw\workspace")

class GPSReceiver:
    """Reads NMEA from a GPS serial port."""
    def __init__(self, port, name, baud=9600):
        self.port = port
        self.name = name
        self.baud = baud
        self.ser = None
        self.latest = {"lat": None, "lon": None, "alt": None, "hdop": None,
                        "fix": 0, "sats": 0, "time": None, "speed": None,
                        "last_update": None, "sentences": 0, "errors": 0}
        self.running = False
        self.thread = None
        
    def _parse_nmea(self, line):
        """Parse NMEA sentences, return parsed dict or None."""
        line = line.strip()
        if not line.startswith('$'):
            return None
        
        parts = line.split(',')
        talker = parts[0][1:]
        
        try:
            if talker.endswith('GGA') and len(parts) >= 15:
                # $GPGGA or $GNGGA
                time_str = parts[1]
                lat_raw = parts[2]
                lat_dir = parts[3]
                lon_raw = parts[4]
                lon_dir = parts[5]
                fix = int(parts[6]) if parts[6] else 0
                sats = int(parts[7]) if parts[7] else 0
                hdop = float(parts[8]) if parts[8] else None
                alt = float(parts[9]) if parts[9] else None
                
                lat = None
                lon = None
                if lat_raw:
                    d = float(lat_raw[:2])
                    m = float(lat_raw[2:])
                    lat = d + m/60.0
                    if lat_dir == 'S':
                        lat = -lat
                if lon_raw:
                    d = float(lon_raw[:3])
                    m = float(lon_raw[3:])
                    lon = d + m/60.0
                    if lon_dir == 'W':
                        lon = -lon
                
                return {"type": "GGA", "time": time_str, "lat": lat, "lon": lon,
                        "fix": fix, "sats": sats, "hdop": hdop, "alt": alt}
            
            elif talker.endswith('RMC') and len(parts) >= 12:
                # $GPRMC or $GNRMC
                time_str = parts[1]
                status = parts[2]
                lat_raw = parts[3]
                lat_dir = parts[4]
                lon_raw = parts[5]
                lon_dir = parts[6]
                speed = float(parts[7]) if parts[7] else None
                
                lat = None
                lon = None
                if lat_raw:
                    d = float(lat_raw[:2])
                    m = float(lat_raw[2:])
                    lat = d + m/60.0
                    if lat_dir == 'S':
                        lat = -lat
                if lon_raw:
                    d = float(lon_raw[:3])
                    m = float(lon_raw[3:])
                    lon = d + m/60.0
                    if lon_dir == 'W':
                        lon = -lon
                
                return {"type": "RMC", "time": time_str, "lat": lat, "lon": lon,
                        "status": status, "speed": speed}
            
            elif talker.endswith('GSA') and len(parts) >= 18:
                # Satellite data
                mode = parts[2]
                pdop = float(parts[15]) if parts[15] else None
                hdop = float(parts[16]) if parts[16] else None
                vdop = float(parts[17].split('*')[0]) if parts[17] else None
                return {"type": "GSA", "mode": mode, "pdop": pdop, "hdop": hdop, "vdop": vdop}
                
        except (ValueError, IndexError) as e:
            self.latest["errors"] += 1
        return None
    
    def _read_loop(self):
        """Background thread: read NMEA and parse."""
        while self.running:
            try:
                if self.ser is None:
                    self.ser = serial.Serial(self.port, self.baud, timeout=1)
                    print(f"[{self.name}] Opened {self.port} @ {self.baud}")
                
                line = self.ser.readline().decode('ascii', errors='replace')
                result = self._parse_nmea(line)
                
                if result:
                    self.latest["sentences"] += 1
                    if result.get("lat") is not None:
                        self.latest.update({
                            "lat": result.get("lat"),
                            "lon": result.get("lon"),
                            "last_update": datetime.now(timezone.utc).isoformat()
                        })
                    if result.get("alt") is not None:
                        self.latest["alt"] = result.get("alt")
                    if result.get("fix") is not None:
                        self.latest["fix"] = result.get("fix")
                    if result.get("sats") is not None:
                        self.latest["sats"] = result.get("sats")
                    if result.get("hdop") is not None:
                        self.latest["hdop"] = result.get("hdop")
                    if result.get("speed") is not None:
                        self.latest["speed"] = result.get("speed")
                    if result.get("time"):
                        self.latest["time"] = result.get("time")
                    
            except serial.SerialException:
                time.sleep(2)
                self.ser = None
            except Exception as e:
                self.latest["errors"] += 1
                time.sleep(0.5)
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._read_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        self.running = False
        if self.ser:
            self.ser.close()


class GPSAntiSpoofMonitor:
    """Cross-validates 3 GPS receivers to detect spoofing."""
    def __init__(self, receivers):
        self.receivers = receivers
        self.home = None
        self.spoof_events = deque(maxlen=1000)
        self.history = deque(maxlen=600)  # 10 min at 1 Hz
        
        # Load home position
        home_file = WORKSPACE / "gps_home.json"
        if home_file.exists():
            with open(home_file) as f:
                data = json.load(f)
                self.home = (data.get("lat"), data.get("lon"))
                print(f"[ANTI-SPOOF] Home: {self.home}")
    
    def check(self):
        """Check all receivers, return alerts."""
        alerts = []
        positions = []
        
        for rx in self.receivers:
            if rx.latest["lat"] is not None and rx.latest["lon"] is not None:
                positions.append({
                    "name": rx.name,
                    "lat": rx.latest["lat"],
                    "lon": rx.latest["lon"],
                    "fix": rx.latest["fix"],
                    "sats": rx.latest["sats"],
                    "hdop": rx.latest["hdop"],
                    "sentences": rx.latest["sentences"]
                })
        
        if len(positions) < 2:
            return alerts
        
        # Cross-validation checks
        for i in range(len(positions)):
            for j in range(i+1, len(positions)):
                p1, p2 = positions[i], positions[j]
                
                # Distance between GPS positions
                dist = self._haversine(p1["lat"], p1["lon"], p2["lat"], p2["lon"])
                
                # SPOOF CHECK 1: Positions diverge by >50m
                if dist > 50:
                    alerts.append({
                        "type": "POSITION_DIVERGENCE",
                        "severity": "HIGH",
                        "gps_a": p1["name"],
                        "gps_b": p2["name"],
                        "distance_m": round(dist, 1),
                        "a_pos": f"{p1['lat']:.6f},{p1['lon']:.6f}",
                        "b_pos": f"{p2['lat']:.6f},{p2['lon']:.6f}"
                    })
                
                # SPOOF CHECK 2: Satellite count mismatch >5
                if abs(p1["sats"] - p2["sats"]) > 5:
                    alerts.append({
                        "type": "SATELLITE_MISMATCH",
                        "severity": "MEDIUM",
                        "gps_a": p1["name"],
                        "gps_b": p2["name"],
                        "a_sats": p1["sats"],
                        "b_sats": p2["sats"]
                    })
        
        # SPOOF CHECK 3: Position jump from home >500m
        if self.home:
            for p in positions:
                dist_home = self._haversine(self.home[0], self.home[1], p["lat"], p["lon"])
                if dist_home > 500:
                    alerts.append({
                        "type": "POSITION_JUMP",
                        "severity": "HIGH", 
                        "gps": p["name"],
                        "distance_from_home_m": round(dist_home, 1),
                        "position": f"{p['lat']:.6f},{p['lon']:.6f}"
                    })
        
        # Record history
        self.history.append({
            "time": datetime.now(timezone.utc).isoformat(),
            "positions": positions,
            "alerts": len(alerts)
        })
        
        # Log spoof events
        for alert in alerts:
            self.spoof_events.append({
                "time": datetime.now(timezone.utc).isoformat(),
                **alert
            })
        
        return alerts
    
    @staticmethod
    def _haversine(lat1, lon1, lat2, lon2):
        from math import radians, sin, cos, sqrt, atan2
        R = 6371000
        dlat = radians(lat2 - lat1)
        dlon = radians(lon2 - lon1)
        a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
        return R * 2 * atan2(sqrt(a), sqrt(1-a))
    
    def status(self):
        """Get current status for API/TSCM dashboard."""
        positions = []
        for rx in self.receivers:
            positions.append({
                "name": rx.name,
                "lat": rx.latest["lat"],
                "lon": rx.latest["lon"],
                "fix": rx.latest["fix"],
                "sats": rx.latest["sats"],
                "hdop": rx.latest["hdop"],
                "updated": rx.latest["last_update"]
            })
        return {
            "gps_count": len([p for p in positions if p["lat"] is not None]),
            "positions": positions,
            "home": self.home,
            "recent_spoof_alerts": len([e for e in self.spoof_events]),
            "cross_validated": len(positions) >= 2
        }


class AlfaWiFiScanner:
    """Scans WiFi with Alfa adapter (Realtek 8812AU), returns BSSID+RSSI for passive radar."""
    def __init__(self, interface="Wi-Fi 2"):
        self.interface = interface
        self.running = False
        self.thread = None
        self.latest_scan = []
        self.scan_count = 0
        
    def _scan_once(self):
        """Single netsh BSSID scan — returns list of {ssid, bssid, signal, channel}."""
        try:
            result = subprocess.run(
                f'netsh wlan show networks mode=bssid interface="{self.interface}"',
                shell=True, capture_output=True, text=True, timeout=8
            )
            output = result.stdout
            
            networks = []
            current = {}
            
            for line in output.split('\n'):
                ssid_m = re.search(r'SSID\s+\d+\s*:\s*(.+)', line)
                bssid_m = re.search(r'BSSID\s+\d+\s*:\s*([0-9a-f:]+)', line, re.I)
                signal_m = re.search(r'Signal\s*:\s*(\d+)%', line)
                channel_m = re.search(r'Channel\s*:\s*(\d+)', line)
                radio_m = re.search(r'Radio type\s*:\s*(.+)', line)
                
                if bssid_m:
                    if current.get('bssid'):
                        networks.append(current)
                    current = {'bssid': bssid_m.group(1)}
                if ssid_m and current:
                    current['ssid'] = ssid_m.group(1).strip()
                if signal_m and current:
                    current['signal_pct'] = int(signal_m.group(1))
                if channel_m and current:
                    current['channel'] = int(channel_m.group(1))
                if radio_m and current:
                    current['radio'] = radio_m.group(1).strip()
            
            if current.get('bssid'):
                networks.append(current)
            
            return networks
            
        except Exception as e:
            print(f"[WiFi] Scan error: {e}")
            return []
    
    def _wiggle_scan(self):
        """Wiggle WiFi: hop through channels to capture hidden BSSIDs.
        NOTE: netsh wlan disconnect removed — it disrupts active connections."""
        # Scan all channels
        all_networks = []
        channels_to_scan = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13, 
                           36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165]
        
        for ch in channels_to_scan[:8]:  # Limit to 8 channels per cycle for speed
            networks = self._scan_once()
            for n in networks:
                n['scan_channel'] = ch
                all_networks.append(n)
            self.scan_count += 1
            time.sleep(0.5)
        
        return all_networks
    
    def _scan_loop(self):
        """Background: scan WiFi, detect new BSSIDs, track RSSI."""
        seen_bssids = {}
        
        while self.running:
            networks = self._scan_once()
            now = datetime.now(timezone.utc)
            
            for n in networks:
                bssid = n.get('bssid', '')
                if bssid not in seen_bssids:
                    n['first_seen'] = now.isoformat()
                    seen_bssids[bssid] = n
                
                # Track RSSI changes (passive radar)
                prev = seen_bssids[bssid]
                prev_signal = prev.get('signal_pct', 0)
                new_signal = n.get('signal_pct', 0)
                
                if abs(new_signal - prev_signal) > 20:
                    # RSSI spike > 20% — possible new device or movement
                    n['rssi_alert'] = True
                    n['rssi_delta'] = new_signal - prev_signal
                
                seen_bssids[bssid].update(n)
                seen_bssids[bssid]['last_seen'] = now.isoformat()
            
            self.latest_scan = networks
            self.scan_count += 1
            time.sleep(5)  # Scan every 5 seconds
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        self.running = False
    
    def get_rssi_feed(self):
        """Returns [{bssid, ssid, signal_pct, channel}] for passive radar."""
        return self.latest_scan


if __name__ == '__main__':
    print("=== 3-GPS Anti-Spoof + Alfa WiFi + Wiggle WiFi ===")
    
    # Start all 3 GPS receivers
    gps_receivers = [
        GPSReceiver("COM5", "u-blox ZED-F9P RTK2", baud=38400),
        GPSReceiver("COM6", "Adafruit GPS #1 (STM32)", baud=9600),
        GPSReceiver("COM7", "Adafruit GPS #2 (STM32)", baud=9600),
    ]
    
    for rx in gps_receivers:
        rx.start()
        print(f"  Started {rx.name} on {rx.port} @ {rx.baud}")
    
    # Start anti-spoof monitor
    monitor = GPSAntiSpoofMonitor(gps_receivers)
    
    # Start Alfa WiFi scanner
    wifi = AlfaWiFiScanner(interface="Wi-Fi 2")
    wifi.start()
    print("  Started Alfa WiFi scanner on Wi-Fi 2")
    
    # Main loop
    print("\nMonitoring... (Ctrl+C to stop)")
    print(f"{'TIME':<20} {'GPS1':>12} {'GPS2':>12} {'GPS3':>12} {'WiFi':>6} {'ALERTS':>8}")
    print("-" * 75)
    
    try:
        while True:
            alerts = monitor.check()
            
            # Status line
            p1 = f"{gps_receivers[0].latest['lat']:.6f}" if gps_receivers[0].latest['lat'] else "---"
            p2 = f"{gps_receivers[1].latest['lat']:.6f}" if gps_receivers[1].latest['lat'] else "---"
            p3 = f"{gps_receivers[2].latest['lat']:.6f}" if gps_receivers[2].latest['lat'] else "---"
            
            now = datetime.now().strftime("%H:%M:%S")
            print(f"{now:<20} {p1:>12} {p2:>12} {p3:>12} {wifi.scan_count:>6} {len(alerts):>8}")
            
            # Alert detail
            for alert in alerts:
                print(f"  ⚠️  {alert['type']}: {alert.get('gps_a','?')} vs {alert.get('gps_b','?')} — {alert.get('distance_m','?')}m")
            
            # WiFi RSSI feed
            rssi = wifi.get_rssi_feed()
            if rssi:
                high_signal = [n for n in rssi if n.get('signal_pct', 0) > 80]
                if high_signal:
                    print(f"  📶 Top RSSI: {high_signal[0].get('ssid','?')} @ {high_signal[0]['signal_pct']}% ch{high_signal[0].get('channel','?')}")
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down...")
    
    for rx in gps_receivers:
        rx.stop()
    wifi.stop()
    print("Done.")
