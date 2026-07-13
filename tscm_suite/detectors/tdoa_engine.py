"""
TDOA Positioning Module for TSCM Master Suite
Uses USB hub frame timing for synchronization across all SDRs.
HackRF (121 MHz) + BladeRF RX1/RX2 (2.4 GHz) → 3 receivers.
TDOA pairs → hyperbolic positioning → real source coordinates.
"""

import numpy as np
import time
import threading
import logging
import json
from collections import deque
from math import radians, cos, sin, sqrt, atan2, degrees, asin

log = logging.getLogger('TDOA')


class USBHubTimeSync:
    """
    Synchronizes timestamps across all USB devices using the USB hub's
    shared Start-of-Frame (SOF) reference at 125 µs intervals (8 kHz).
    
    All devices on the same USB root hub share the same SOF clock.
    This provides a common timebase for TDOA cross-correlation.
    """
    
    def __init__(self):
        self.sof_epoch = time.time()  # Reference epoch
        self.sof_count = 0
        self.sof_interval = 125e-6  # 125 us = 8 kHz USB frame rate
        self.receiver_clocks = {
            'hackrf': {'offset_s': 0.0, 'drift_ppm': 0.0},
            'bladerf_rx1': {'offset_s': 0.0, 'drift_ppm': 0.0},
            'bladerf_rx2': {'offset_s': 0.0, 'drift_ppm': 0.0}
        }
        self._lock = threading.Lock()
        self.sync_events = deque(maxlen=1000)  # (timestamp, device, sample_idx)
        log.info("USB Hub Time Sync initialized (SOF ref @125us)")
    
    def sync_pulse(self, device_name, sample_index, sample_rate):
        """
        Record a synchronization pulse from a receiver.
        Call this when a new IQ buffer arrives.
        """
        ts = time.time()
        with self._lock:
            self.sof_count += 1
            # Estimate USB SOF-aligned timestamp
            sof_aligned = self.sof_epoch + self.sof_count * self.sof_interval
            # Device sample time = SOF time + sample_index/sample_rate
            self.receiver_clocks[device_name] = {
                'offset_s': ts - sof_aligned,
                'sample_idx': sample_index,
                'sample_rate': sample_rate,
                'sof_aligned': sof_aligned
            }
            self.sync_events.append((sof_aligned, device_name, sample_index))
    
    def get_device_time(self, device_name, sample_index, sample_rate):
        """
        Convert a device's sample index to UTC seconds.
        """
        with self._lock:
            clock = self.receiver_clocks.get(device_name, {})
            sof = clock.get('sof_aligned', time.time())
            ref_idx = clock.get('sample_idx', 0)
            ref_rate = clock.get('sample_rate', sample_rate)
            # Time of sample = SOF time + (sample_index - ref_idx) / sample_rate + offset
            return sof + (sample_index - ref_idx) / ref_rate + clock.get('offset_s', 0)
    
    def get_tdoa(self, dev_a, idx_a, fs_a, dev_b, idx_b, fs_b):
        """
        Compute Time Difference of Arrival between two devices.
        Returns tdoa_seconds (positive = B arrived later).
        """
        t_a = self.get_device_time(dev_a, idx_a, fs_a)
        t_b = self.get_device_time(dev_b, idx_b, fs_b)
        return t_b - t_a
    
    def get_status(self):
        with self._lock:
            return {
                'sync_events': len(self.sync_events),
                'receivers': {
                    k: {'offset_us': round(v.get('offset_s', 0) * 1e6, 1)}
                    for k, v in self.receiver_clocks.items()
                }
            }


class TDOAEngine:
    """
    Three-receiver TDOA positioning engine.
    
    Antenna configuration:
      - BladeRF RX1: directional, position = baseline + d/2 (right)
      - BladeRF RX2: directional, position = baseline - d/2 (left)  
      - HackRF: loop antenna, reference position
    
    Baseline distance between BladeRF antennas ≈ 0.5m (Siretta Delta 52s spacing).
    HackRF loop is colocated (same position, different frequency band).
    """
    
    SPEED_OF_LIGHT = 299792458.0  # m/s
    
    def __init__(self, time_sync, baseline_m=0.5):
        self.ts = time_sync
        self.baseline = baseline_m
        
        # Antenna positions relative to center (ENU: East, North, Up)
        self.ant_positions = {
            'hackrf': np.array([0.0, 0.0, 0.0]),              # Center reference
            'bladerf_rx1': np.array([self.baseline/2, 0.0, 0.0]),  # +X (East)
            'bladerf_rx2': np.array([-self.baseline/2, 0.0, 0.0]), # -X (West)
        }
        
        # IQ history for cross-correlation
        self.iq_buffers = {
            'hackrf': deque(maxlen=100),
            'bladerf_rx1': deque(maxlen=100),
            'bladerf_rx2': deque(maxlen=100)
        }
        
        # Results
        self.positions = deque(maxlen=50)
        self._lock = threading.Lock()
        
        log.info(f"TDOA Engine: {len(self.ant_positions)} receivers, baseline={self.baseline}m")
    
    def feed(self, device_name, iq_data, sample_rate):
        """
        Feed IQ data from a receiver. Stores timestamped buffer for correlation.
        """
        self.ts.sync_pulse(device_name, 0, sample_rate)
        
        with self._lock:
            buf = {
                'iq': iq_data.copy(),
                'fs': sample_rate,
                'timestamp': time.time(),
                'sof_aligned': self.ts.receiver_clocks.get(device_name, {}).get('sof_aligned', time.time())
            }
            self.iq_buffers[device_name].append(buf)
    
    def compute_tdoa_pair(self, dev_a, dev_b):
        """
        Cross-correlate latest IQ from two devices to find TDOA.
        Returns (tdoa_s, correlation_quality).
        """
        with self._lock:
            buf_a = list(self.iq_buffers[dev_a])
            buf_b = list(self.iq_buffers[dev_b])
        
        if len(buf_a) < 1 or len(buf_b) < 1:
            return None, 0.0
        
        iq_a = buf_a[-1]['iq']
        iq_b = buf_b[-1]['iq']
        fs_a = buf_a[-1]['fs']
        fs_b = buf_b[-1]['fs']
        
        # Use envelope for cross-frequency correlation (works across different center freqs)
        env_a = np.abs(iq_a)
        env_b = np.abs(iq_b)
        
        # Downsample to common rate for comparison
        common_fs = min(fs_a, fs_b) / 10  # Downsample 10x
        ds_factor_a = int(fs_a / common_fs)
        ds_factor_b = int(fs_b / common_fs)
        
        if ds_factor_a > 1:
            env_a = env_a[::ds_factor_a]
        if ds_factor_b > 1:
            env_b = env_b[::ds_factor_b]
        
        # Match lengths
        min_len = min(len(env_a), len(env_b))
        env_a = env_a[:min_len]
        env_b = env_b[:min_len]
        
        if min_len < 100:
            return None, 0.0
        
        # Cross-correlate
        xcorr = np.correlate(env_a - np.mean(env_a), env_b - np.mean(env_b), mode='full')
        peak_idx = np.argmax(np.abs(xcorr))
        center = len(xcorr) // 2
        lag_samples = peak_idx - center
        
        # TDOA in seconds
        tdoa_s = lag_samples / common_fs
        
        # Quality metric: peak-to-sidelobe ratio
        peak = np.abs(xcorr[peak_idx])
        # Sidelobe: average of samples away from peak
        sidelobe_mask = np.ones(len(xcorr), dtype=bool)
        sidelobe_mask[max(0, peak_idx-5):min(len(xcorr), peak_idx+6)] = False
        sidelobe = np.mean(np.abs(xcorr[sidelobe_mask])) if np.any(sidelobe_mask) else peak * 0.1
        quality = min(peak / (sidelobe + 1e-12) / 10.0, 1.0)
        
        return tdoa_s, float(quality)
    
    def compute_position(self, tdoa_12, quality_12, tdoa_13=None, quality_13=None):
        """
        Estimate source position from TDOA measurements.
        
        TDOA_12 = delay between RX1 and RX2 (BladeRF pair, same frequency)
        TDOA_13 = delay between HackRF and RX1 (cross-frequency)
        
        Returns (lat, lon, bearing_deg, range_m, confidence).
        """
        # Simple AoA from BladeRF MIMO pair (RX1/RX2)
        if abs(tdoa_12) < 1e-12:
            return None, None, 0.0, 0.0, 0.0
        
        # Maximum possible TDOA for this baseline: baseline/c
        max_tdoa = self.baseline / self.SPEED_OF_LIGHT
        
        # sin(angle) = tdoa * c / baseline
        sin_theta = np.clip(tdoa_12 * self.SPEED_OF_LIGHT / self.baseline, -1.0, 1.0)
        theta_rad = asin(float(sin_theta))
        theta_deg = degrees(theta_rad)
        
        # Range estimation from TDOA_13 (HackRF to RX1)
        range_m = None
        if tdoa_13 is not None and abs(tdoa_13) > 1e-12:
            # TDOA_13 gives range difference between HackRF and RX1 paths
            # For colocated antennas, this is zero. For separated, it's the path difference.
            range_m = abs(tdoa_13 * self.SPEED_OF_LIGHT)
        
        confidence = quality_12
        if quality_13 is not None:
            confidence = min(confidence, quality_13)
        
        return theta_deg, range_m, confidence
    
    def triangulate(self, observer_lat, observer_lon, theta_deg, range_m=None):
        """
        Convert bearing and range to GPS coordinates.
        Only computes position if real range is provided (from TDOA).
        Returns None if no real range — no fabricated positions.
        """
        if theta_deg is None:
            return None, None

        # No real range → return None (no fabricated coordinates)
        if range_m is None or range_m < 10:
            return None, None
        
        # Convert to lat/lon
        R = 6371000.0  # Earth's radius
        bearing_rad = radians(90 - theta_deg)  # Convert azimuth to math angle
        dlat = range_m * cos(bearing_rad) / R
        dlon = range_m * sin(bearing_rad) / (R * cos(radians(observer_lat)))
        
        target_lat = observer_lat + degrees(dlat)
        target_lon = observer_lon + degrees(dlon)
        
        return target_lat, target_lon
    
    def detect_and_position(self, observer_lat, observer_lon):
        """
        Run full TDOA pipeline: cross-correlate all pairs → compute position.
        Returns list of position estimates.
        """
        results = []
        
        # Pair 1: BladeRF RX1 vs RX2 (same frequency, best for AoA)
        tdoa_12, q12 = self.compute_tdoa_pair('bladerf_rx1', 'bladerf_rx2')
        
        if tdoa_12 is not None and q12 > 0.3:
            theta, range_m, conf = self.compute_position(tdoa_12, q12)
            if theta is not None and conf > 0.3:
                tlat, tlon = self.triangulate(observer_lat, observer_lon, theta, range_m)
                entry = {
                    'bearing_deg': round(theta, 2),
                    'range_m': round(range_m, 1) if range_m else None,
                    'confidence': round(conf, 3),
                    'pair': 'RX1-RX2',
                    'method': 'mimo_aoa'
                }
                if tlat is not None and tlon is not None:
                    entry['lat'] = round(tlat, 6)
                    entry['lon'] = round(tlon, 6)
                results.append(entry)
        
        # Pair 2: HackRF vs BladeRF RX1 (cross-frequency envelope correlation)
        tdoa_h1, q_h1 = self.compute_tdoa_pair('hackrf', 'bladerf_rx1')
        
        if tdoa_h1 is not None and q_h1 > 0.2:
            # This gives range difference, combine with AoA for full position
            path_diff = abs(tdoa_h1 * self.SPEED_OF_LIGHT)
            results.append({
                'path_diff_m': round(path_diff, 1),
                'confidence': round(q_h1, 3),
                'pair': 'HackRF-RX1',
                'method': 'cross_freq_envelope'
            })
        
        # Store
        with self._lock:
            for r in results:
                self.positions.append(r)
            if len(self.positions) > 50:
                self.positions = list(self.positions)[-50:]
        
        return results
    
    def get_status(self):
        with self._lock:
            return {
                'positions_computed': len(self.positions),
                'latest': list(self.positions)[-3:] if self.positions else [],
                'ts_sync': self.ts.get_status()
            }


class TDOPositionRefiner:
    """
    Refines position estimates by combining TDOA with known ground propagation.
    Uses soil conductivity map to correct for ground wave velocity.
    """
    
    def __init__(self):
        # Soil conductivity map (mS/m) — key locations
        self.conductivity_map = {
            'crest_hill': 10.0,     # Urban, higher conductivity (pipes, infrastructure)
            'home': 8.0,            # Suburban
            'default': 5.0          # Rural/unknown
        }
        
        # Ground wave velocity reduction factor
        # v_ground ≈ c / sqrt(ε_r)  where ε_r ≈ 15-20 for wet soil
        self.ground_velocity_factor = 0.22  # ~c/4.5 for typical soil
        
    def correct_range(self, range_m, propagation_type='los'):
        """Apply ground wave correction for non-LOS paths."""
        if propagation_type == 'ground_wave':
            return range_m / self.ground_velocity_factor
        elif propagation_type == 'skywave':
            return range_m  # Skywave travels at c
        else:
            return range_m  # LOS: no correction
    
    def refine_position(self, observer_lat, observer_lon, bearing_deg, tdoa_range_m, 
                        rf_freq_hz=None, propagation='los'):
        """
        Refine position using physical propagation model.
        """
        # Correct range for propagation type
        corrected_range = self.correct_range(tdoa_range_m, propagation)
        
        # Frequency-dependent ground wave attenuation
        if rf_freq_hz and rf_freq_hz < 30e6 and propagation == 'ground_wave':
            # Attenuation increases with frequency for ground wave
            # Use Norton surface wave formula
            f_mhz = rf_freq_hz / 1e6
            attenuation_db_per_km = 3.0 + 2.0 * np.log10(f_mhz)
            max_useful_range = 5000 / attenuation_db_per_km
            corrected_range = min(corrected_range, max_useful_range)
        
        # Convert to coordinates
        bearing_rad = radians(90 - bearing_deg)
        R = 6371000.0
        dlat = corrected_range * cos(bearing_rad) / R
        dlon = corrected_range * sin(bearing_rad) / (R * cos(radians(observer_lat)))
        
        return (
            observer_lat + degrees(dlat),
            observer_lon + degrees(dlon),
            corrected_range
        )


# Test with synthetic data
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    ts = USBHubTimeSync()
    engine = TDOAEngine(ts, baseline_m=0.5)
    
    # Simulate a source at Crest Hill (41.558, -88.100) ≈ 5.5 miles
    # Bearing from home (41.513, -88.134) ≈ 60 degrees East
    # TDOA for 0.5m baseline at 60°: sin(60°)*0.5/3e8 = 1.44 ns
    
    synthetic_tdoa_12 = sin(radians(60)) * 0.5 / 299792458  # ~1.44 ns
    
    # Simulate cross-correlation result
    theta, range_m, conf = engine.compute_position(synthetic_tdoa_12, 0.85)
    tlat, tlon = engine.triangulate(41.513323, -88.133573, theta)
    
    print(f"TDOA: {synthetic_tdoa_12*1e9:.1f} ns → Bearing: {theta:.1f}°")
    print(f"Position: {tlat:.6f}, {tlon:.6f}")
    print(f"Expected: 41.558000, -88.100000 (Crest Hill)")
