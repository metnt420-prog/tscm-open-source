"""
Real GPS — auto-detects ALL NMEA GPS devices + laptop GPS + phone location.
No synthetic positions, no hardcoded fallbacks — only live device data.
"""
import json, os, time, math, threading, logging

log = logging.getLogger('real_gps')

class NMEAGPS:
    """Single NMEA GPS receiver on a serial port."""
    def __init__(self, port, baud=38400):
        self.port = port
        self.baud = baud
        self.serial = None
        self.lat = 0.0
        self.lon = 0.0
        self.alt = 0.0
        self.has_fix = False
        self.rtk_fix = False
        self.hdop = 99.0
        self.sats = 0
        self.running = False
        self._thread = None
        self._last_update = 0

    def start(self):
        try:
            import serial
            self.serial = serial.Serial(self.port, self.baud, timeout=2)
            self.running = True
            self._thread = threading.Thread(target=self._read_loop, daemon=True)
            self._thread.start()
            return True
        except Exception as e:
            log.debug(f"GPS {self.port}: open failed: {e}")
            return False

    def _read_loop(self):
        while self.running and self.serial:
            try:
                line = self.serial.readline().decode('ascii', errors='ignore').strip()
                if line.startswith('$'):
                    self._parse_nmea(line)
            except Exception:
                time.sleep(0.1)

    def _parse_nmea(self, line):
        parts = line.split('*')[0].split(',')
        sentence = parts[0][3:6]
        try:
            if sentence == 'GGA':
                # $GNGGA,hhmmss.ss,ll,ll,N,mmm,mmm,E,q,nn,...
                if len(parts) > 6 and parts[6]:
                    quality = int(parts[6])
                    self.has_fix = quality >= 1
                    self.rtk_fix = quality >= 4
                    if quality >= 1 and parts[2] and parts[4]:
                        lat_deg = float(parts[2])
                        lon_deg = float(parts[4])
                        lat_sign = -1 if parts[3] == 'S' else 1
                        lon_sign = -1 if parts[5] == 'W' else 1
                        self.lat = lat_sign * (int(lat_deg/100) + (lat_deg % 100) / 60.0)
                        self.lon = lon_sign * (int(lon_deg/100) + (lon_deg % 100) / 60.0)
                        if len(parts) > 9 and parts[9]:
                            self.alt = float(parts[9])
                        self.sats = int(parts[7]) if len(parts) > 7 and parts[7] else 0
                        self.hdop = float(parts[8]) if len(parts) > 8 and parts[8] else 99.0
                        self._last_update = time.time()
            elif sentence in ('RMC', 'GNS') and len(parts) > 5:
                if parts[2] == 'A' or (len(parts) > 6 and parts[6]):
                    if parts[3] and parts[5]:
                        lat_deg = float(parts[3])
                        lon_deg = float(parts[5])
                        lat_sign = -1 if parts[4] == 'S' else 1
                        lon_sign = -1 if parts[6] == 'W' else 1
                        self.lat = lat_sign * (int(lat_deg/100) + (lat_deg % 100) / 60.0)
                        self.lon = lon_sign * (int(lon_deg/100) + (lon_deg % 100) / 60.0)
                        self.has_fix = True
                        self._last_update = time.time()
        except (ValueError, IndexError):
            pass

    def stop(self):
        self.running = False
        if self.serial:
            try: self.serial.close()
            except: pass

    def age_seconds(self):
        return time.time() - self._last_update if self._last_update else 9999


class RealGPS:
    """Multi-source GPS: only real positions, no hardcoded fallback."""
    def __init__(self, primary_gps):
        """primary_gps is the GPSInterface object from tscm_final.py (ZED-F9P on COM5)."""
        self.primary = primary_gps
        self.secondary_gps = []  # Additional NMEA GPS receivers
        self.laptop_lat = 0.0
        self.laptop_lon = 0.0
        self.laptop_has_fix = False
        self.last_laptop_read = 0
        self.phone_lat = 0.0
        self.phone_lon = 0.0
        self.phone_has_fix = False
        self.last_phone_read = 0
        self._spoof_alert = False
        self._discover_secondary_gps()

    def _discover_secondary_gps(self):
        """Auto-detect additional NMEA GPS devices on other COM ports. Runs in background thread."""
        self._discovery_done = threading.Event()

        def _do_discovery():
            try:
                import serial.tools.list_ports
                all_ports = [p.device for p in serial.tools.list_ports.comports()]
                # Skip COM5 (primary) and ports already claimed by TGAM/Cyton
                skip = {'COM5'}  # Primary GPS already handled by GPSInterface
                for port in all_ports:
                    if port in skip:
                        continue
                    # Quick probe: open at 9600 and 38400, look for NMEA
                    for baud in [9600, 38400, 115200]:
                        try:
                            import serial as _s
                            ser = _s.Serial(port, baud, timeout=3)
                            data = b''
                            start = time.time()
                            while time.time() - start < 2.5:
                                chunk = ser.read(256)
                                if chunk: data += chunk
                            ser.close()
                            decoded = data.decode('ascii', errors='ignore')
                            nmea = [l for l in decoded.split('\n') if '$G' in l[:3]]
                            if nmea:
                                gps = NMEAGPS(port, baud)
                                if gps.start():
                                    self.secondary_gps.append(gps)
                                    log.info(f"Secondary GPS found: {port} @ {baud} ({len(nmea)} NMEA lines)")
                                    break  # Found GPS on this port, don't try other bauds
                        except Exception:
                            continue
            except Exception as e:
                log.debug(f"GPS discovery error: {e}")
            finally:
                self._discovery_done.set()

        threading.Thread(target=_do_discovery, daemon=True).start()

    def get_position(self):
        """Return only real GPS positions. Weighted average for 1m target.
        Weight = 1/hdop^2 (lower HDOP = higher weight = more trusted).
        When ZED-F9P has RTK fix (hdop<1), it dominates the average.
        When only laptop GPS available, uses it alone with its accuracy."""
        sources = []

        # Primary ZED-F9P (from GPSInterface — already running)
        if self.primary.has_fix:
            # Check thread health — if primary hasn't updated in 10s, flag it
            age = time.time() - getattr(self.primary, '_last_nmea_time', time.time())
            if age > 10:
                log.warning(f"Primary GPS stale: {age:.0f}s since last NMEA")
            sources.append({
                'lat': self.primary.lat, 'lon': self.primary.lon,
                'hdop': float(self.primary.hdop) if self.primary.hdop else 0.7,
                'source': 'zed-f9p', 'rtk': self.primary.rtk_fix,
                'age': 0, 'accuracy_m': float(self.primary.hdop) * 2.5 if self.primary.hdop else 2.0
            })

        # Secondary GPS receivers (auto-discovered NMEA)
        for i, gps in enumerate(self.secondary_gps):
            if gps.has_fix and gps.age_seconds() < 30:
                sources.append({
                    'lat': gps.lat, 'lon': gps.lon,
                    'hdop': gps.hdop, 'source': f'gps-{gps.port}',
                    'rtk': gps.rtk_fix, 'age': gps.age_seconds(),
                    'accuracy_m': gps.hdop * 2.5 if gps.hdop < 50 else 50.0
                })

        # Laptop GPS every 30s
        if time.time() - self.last_laptop_read > 30:
            self._read_laptop_gps()
        if self.laptop_has_fix:
            sources.append({
                'lat': self.laptop_lat, 'lon': self.laptop_lon,
                'hdop': 5.0, 'source': 'laptop', 'rtk': False,
                'age': time.time() - self.last_laptop_read,
                'accuracy_m': self._laptop_accuracy_m if hasattr(self, '_laptop_accuracy_m') else 50.0
            })

        # Phone GPS (manual set via set_phone_location)
        if self.phone_has_fix and time.time() - self.last_phone_read < 600:
            sources.append({
                'lat': self.phone_lat, 'lon': self.phone_lon,
                'hdop': 3.0, 'source': 'phone', 'rtk': False,
                'age': time.time() - self.last_phone_read,
                'accuracy_m': 10.0
            })

        if not sources:
            return {'has_fix': False, 'lat': 0, 'lon': 0, 'sources': 0,
                    'all_sources': [], 'spoof_alert': False,
                    'agreement_1m': False, 'estimated_accuracy_m': 999}

        # Cross-validate all sources
        if len(sources) >= 2:
            max_dist = 0
            pair_dists = []
            for i in range(len(sources)):
                for j in range(i+1, len(sources)):
                    d = self._haversine(sources[i]['lat'], sources[i]['lon'],
                                       sources[j]['lat'], sources[j]['lon'])
                    max_dist = max(max_dist, d)
                    pair_dists.append(d)
            self._spoof_alert = max_dist > 0.050  # >50m = possible spoof
            self._agreement_1m = max_dist < 0.001  # <1m = tight agreement
        else:
            self._spoof_alert = False
            self._agreement_1m = sources[0].get('rtk', False)  # Single RTK source counts

        # Weighted average: weight = 1/accuracy^2 (better accuracy = more weight)
        # If any source has RTK fix with hdop<1, it gets 100x weight
        total_w = 0
        w_lat = 0
        w_lon = 0
        for s in sources:
            acc = s.get('accuracy_m', 50.0)
            w = 1.0 / (acc * acc)
            if s.get('rtk'):
                w *= 100  # RTK is vastly more precise
            # Age penalty: reduce weight for stale data
            age_s = s.get('age', 0)
            if age_s > 10:
                w *= max(0.1, 1.0 - age_s / 60.0)
            w_lat += s['lat'] * w
            w_lon += s['lon'] * w
            total_w += w

        if total_w > 0:
            avg_lat = w_lat / total_w
            avg_lon = w_lon / total_w
        else:
            avg_lat = sources[0]['lat']
            avg_lon = sources[0]['lon']

        # Estimated accuracy of the weighted average
        # With 2+ agreeing sources, accuracy improves
        if len(sources) >= 2 and not self._spoof_alert:
            est_acc = min(s.get('accuracy_m', 50.0) for s in sources) / math.sqrt(len(sources))
        else:
            est_acc = min(s.get('accuracy_m', 50.0) for s in sources)

        # If RTK fixed with hdop<1, claim sub-meter accuracy
        rtk_sources = [s for s in sources if s.get('rtk')]
        if rtk_sources:
            est_acc = min(est_acc, 0.5)  # RTK can do sub-meter

        return {
            'has_fix': True, 'lat': avg_lat, 'lon': avg_lon,
            'hdop': min(s.get('hdop', 99.0) for s in sources),
            'sources': len(sources), 'all_sources': sources,
            'spoof_alert': self._spoof_alert,
            'agreement_1m': getattr(self, '_agreement_1m', False),
            'estimated_accuracy_m': round(est_acc, 1)
        }

    def set_phone_location(self, lat, lon):
        """Set phone GPS position (from Google Maps sharing or manual input)."""
        self.phone_lat = lat
        self.phone_lon = lon
        self.phone_has_fix = True
        self.last_phone_read = time.time()

    def _read_laptop_gps(self):
        """Windows Location API — reads actual accuracy for 1m target."""
        self.last_laptop_read = time.time()
        try:
            import asyncio
            async def _get():
                from winrt.windows.devices.geolocation import Geolocator, PositionAccuracy
                locator = Geolocator()
                locator.desired_accuracy = PositionAccuracy.HIGH
                pos = await locator.get_geoposition_async()
                return pos
            pos = asyncio.run(_get())
            if pos and pos.coordinate and pos.coordinate.point:
                self.laptop_lat = pos.coordinate.point.position.latitude
                self.laptop_lon = pos.coordinate.point.position.longitude
                self._laptop_accuracy_m = getattr(pos.coordinate, 'accuracy', 50.0)
                self.laptop_has_fix = True
        except Exception:
            self.laptop_has_fix = False

    def _haversine(self, lat1, lon1, lat2, lon2):
        R = 6371
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

    def stop(self):
        for gps in self.secondary_gps:
            gps.stop()
