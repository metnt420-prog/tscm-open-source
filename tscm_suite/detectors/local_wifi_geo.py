"""
Local WiFi AP Geolocation using RSSI + GPS position history.
Triangulates APs from multiple observer positions without WiGLE.
"""
import math, time, json, os
from collections import defaultdict, deque
import numpy as np

class LocalWifiGeolocator:
    """
    Triangulates WiFi APs using signal strength from multiple GPS positions.
    As the observer moves, we collect RSSI readings at different locations.
    Uses weighted centroid + RSSI range estimation.
    
    RSSI to distance: d = 10^((tx_power - rssi) / (10 * n))
    where tx_power is assumed AP transmit power (typically 20 dBm at 1m)
    and n is path loss exponent (2.0 free space, 3-4 indoors)
    """
    
    def __init__(self, log, cache_dir="models"):
        self.log = log
        self.cache_dir = cache_dir
        self.cache_file = os.path.join(cache_dir, 'local_wifi_geo.json')
        
        # Per-AP readings: {bssid: [(lat, lon, rssi, timestamp), ...]}
        self.readings = defaultdict(list)
        # Estimated positions: {bssid: (lat, lon, confidence, last_update)}
        self.positions = {}
        # Max readings per AP
        self.max_readings = 50
        
        self.tx_power_dbm = -30  # assumed AP power at 1m (typical)
        self.path_loss_n = 2.5    # indoor/urban exponent
        self.min_readings = 3     # need at least 3 positions to triangulate
        
        self._load_cache()
    
    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    self.positions = data.get('positions', {})
                    if 'readings' in data:
                        for k, v in data['readings'].items():
                            self.readings[k] = v
            except:
                pass
    
    def _save_cache(self):
        os.makedirs(self.cache_dir, exist_ok=True)
        try:
            with open(self.cache_file, 'w') as f:
                json.dump({'positions': self.positions, 'readings': dict(self.readings)}, f)
        except:
            pass
    
    def add_reading(self, bssid, lat, lon, rssi, channel=0):
        """Record a WiFi AP RSSI reading at current GPS position."""
        if not bssid or not lat or not lon:
            return
        
        self.readings[bssid].append((float(lat), float(lon), float(rssi), time.time()))
        # Keep only recent readings
        if len(self.readings[bssid]) > self.max_readings:
            self.readings[bssid] = self.readings[bssid][-self.max_readings:]
        
        # Try to estimate position if we have enough readings
        if len(self.readings[bssid]) >= self.min_readings:
            self._estimate_position(bssid)
    
    def _rssi_to_distance(self, rssi):
        """Convert RSSI to estimated distance in meters."""
        # d = 10^((tx_power - rssi) / (10 * n))
        if rssi >= 0:
            return 1.0
        return 10 ** ((self.tx_power_dbm - rssi) / (10 * self.path_loss_n))
    
    def _estimate_position(self, bssid):
        """Triangulate AP position from multiple readings using weighted centroid."""
        readings = self.readings[bssid]
        if len(readings) < self.min_readings:
            return
        
        # Weighted centroid: each reading position weighted by 1/distance
        weights = []
        lats = []
        lons = []
        
        for lat, lon, rssi, ts in readings:
            d = self._rssi_to_distance(rssi)
            w = 1.0 / max(d, 0.1)  # weight by proximity
            weights.append(w)
            lats.append(lat)
            lons.append(lon)
        
        total_w = sum(weights)
        if total_w < 0.001:
            return
        
        # Weighted centroid
        est_lat = sum(w * lat for w, lat in zip(weights, lats)) / total_w
        est_lon = sum(w * lon for w, lon in zip(weights, lons)) / total_w
        
        # Confidence: higher when readings are consistent and from different angles
        # Check angular spread of readings from centroid
        angles = []
        for lat, lon, rssi, ts in readings:
            dy = lat - est_lat
            dx = lon - est_lon
            angles.append(math.atan2(dy, dx) * 180 / math.pi)
        
        angle_spread = max(angles) - min(angles) if len(angles) > 2 else 30
        # Normalize: > 60 degree spread = high confidence, < 10 = low
        conf = min(1.0, angle_spread / 90.0) * min(1.0, len(readings) / 10.0)
        
        # Average RSSI for strength indicator
        avg_rssi = sum(r[2] for r in readings) / len(readings)
        
        self.positions[bssid] = {
            'lat': est_lat,
            'lon': est_lon,
            'confidence': conf,
            'avg_rssi': avg_rssi,
            'readings': len(readings),
            'last_update': time.time()
        }
        
        if conf > 0.3 and len(readings) >= 5:
            self.log.info(f"WiFi GEO: {bssid} -> ({est_lat:.5f}, {est_lon:.5f}) conf={conf:.2f} from {len(readings)} readings")
        
        # Save periodically
        if len(self.readings) % 20 == 0:
            self._save_cache()
    
    def get_geolocated_aps(self, access_points):
        """
        Process a list of WiFi APs and return ones with estimated positions.
        Also records new readings.
        """
        result = []
        for ap in (access_points or []):
            bssid = ap.get('bssid', '')
            ssid = ap.get('ssid', '?')
            rssi = ap.get('signal', 0)
            channel = ap.get('channel', 0)
            
            # Convert percentage to dBm if needed
            if rssi > 0 and rssi <= 100:
                rssi_dbm = -100 + rssi  # approximate conversion
            else:
                rssi_dbm = rssi
            
            # Check if we have an estimated position
            geo = self.positions.get(bssid)
            entry = {
                'bssid': bssid,
                'ssid': ssid,
                'signal': rssi,
                'channel': channel,
                'rssi_dbm': rssi_dbm,
                'geolocated': False
            }
            
            if geo and geo['confidence'] > 0.2:
                entry['lat'] = geo['lat']
                entry['lon'] = geo['lon']
                entry['geolocated'] = True
                entry['confidence'] = geo['confidence']
                entry['geo_readings'] = geo['readings']
            
            result.append(entry)
        
        return result
    
    def update_from_gps(self, lat, lon, access_points):
        """Record current GPS position with all visible WiFi APs."""
        if not lat or not lon:
            return
        
        for ap in (access_points or []):
            bssid = ap.get('bssid', '')
            rssi = ap.get('signal', 0)
            if rssi > 0 and rssi <= 100:
                rssi_dbm = -100 + rssi
            else:
                rssi_dbm = rssi
            
            if bssid:
                self.add_reading(bssid, lat, lon, rssi_dbm)

    def get_current_position(self):
        if not self.readings:
            return None
        o_lats, o_lons = [], []
        for bssid, rd in self.readings.items():
            for r in rd[-50:]:
                o_lats.append(r['lat']); o_lons.append(r['lon'])
        if not o_lats:
            return None
        return {
            'lat': sum(o_lats)/len(o_lats), 'lon': sum(o_lons)/len(o_lons),
            'confidence': min(1.0, len(o_lats)/50)
        }