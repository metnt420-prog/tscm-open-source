"""
Device Fingerprinter — creates unique RF fingerprints for each transmitter.
Each device has a unique "RF DNA" based on:
- Phase noise pattern (oscillator imperfections)
- Frequency drift rate (crystal quality)
- Turn-on transient (power amplifier signature)
- Modulation imperfections (unique to each transmitter)

This lets us track a SPECIFIC device even if it changes frequency.
If they shut off their phone, we can recognize it when it comes back on.
"""
import numpy as np
from collections import deque
import time, hashlib

class DeviceFingerprinter:
    """Create and match RF device fingerprints."""
    
    def __init__(self, log):
        self.log = log
        self.fingerprints = {}  # fp_hash -> {features, first_seen, last_seen, detections}
        self.known_devices = {}  # device_name -> fp_hash
        
    def extract_features(self, iq_data, fs, freq_center=0):
        """Extract unique RF features from IQ data."""
        if len(iq_data) < 4096:
            return None
        
        features = {}
        n = len(iq_data)
        
        # 1. Phase noise profile
        # Remove carrier and look at residual phase
        iq_centered = iq_data - np.mean(iq_data)
        phase = np.angle(iq_centered)
        
        # Phase difference (instantaneous frequency deviation)
        dphase = np.diff(phase)
        dphase = np.unwrap(dphase)
        
        # Phase noise spectral density
        phase_fft = np.abs(np.fft.rfft(dphase[-2048:]))
        phase_noise = phase_fft / (np.median(phase_fft) + 1e-12)
        features['phase_noise_profile'] = phase_noise[:64].tolist()  # first 64 bins
        features['phase_noise_total'] = float(np.std(dphase))
        
        # 2. Frequency drift (short-term stability)
        # Instantaneous frequency over time
        inst_freq = dphase * fs / (2 * np.pi)
        window_size = min(100, len(inst_freq) // 10)
        if window_size > 1:
            drift = np.convolve(inst_freq, np.ones(window_size)/window_size, mode='valid')
            features['freq_drift_rate'] = float(np.polyfit(range(len(drift)), drift, 1)[0])
            features['freq_drift_jitter'] = float(np.std(np.diff(drift)))
        else:
            features['freq_drift_rate'] = 0.0
            features['freq_drift_jitter'] = 0.0
        
        # 3. Amplitude envelope characteristics
        envelope = np.abs(iq_centered)
        features['amp_mean'] = float(np.mean(envelope))
        features['amp_std'] = float(np.std(envelope))
        features['amp_skew'] = float(np.mean((envelope - np.mean(envelope))**3) / (np.std(envelope)**3 + 1e-12))
        
        # 4. Turn-on transient detection
        # Look for sudden amplitude jumps (device powering up)
        amp_diff = np.abs(np.diff(envelope))
        transient_idx = np.argmax(amp_diff)
        features['transient_strength'] = float(amp_diff[transient_idx])
        features['transient_position'] = float(transient_idx / len(amp_diff))
        
        # 5. Modulation quality (constellation spread)
        # Normalize to unit circle and measure deviation
        if features['amp_mean'] > 0:
            normalized = iq_centered / (features['amp_mean'] + 1e-12)
            features['modulation_error'] = float(np.std(np.abs(normalized) - 1.0))
        else:
            features['modulation_error'] = 0.0
        
        # 6. Create hash fingerprint
        fp_data = [
            round(features['phase_noise_total'], 4),
            round(features['freq_drift_rate'], 2),
            round(features['freq_drift_jitter'], 2),
            round(features['amp_skew'], 3),
            round(features['modulation_error'], 4)
        ]
        fp_str = ','.join(str(x) for x in fp_data)
        fp_hash = hashlib.md5(fp_str.encode()).hexdigest()[:12]
        features['fp_hash'] = fp_hash
        
        return features, fp_hash
    
    def record_device(self, fp_hash, features, detector_name, freq, bearing, snr):
        """Record a device fingerprint observation."""
        now = time.time()
        
        if fp_hash not in self.fingerprints:
            self.fingerprints[fp_hash] = {
                'features': features,
                'first_seen': now,
                'last_seen': now,
                'detections': [],
                'freqs': set(),
                'bearings': [],
                'total_obs': 0
            }
        
        fp = self.fingerprints[fp_hash]
        fp['last_seen'] = now
        fp['total_obs'] += 1
        if freq > 0:
            fp['freqs'].add(round(freq / 1000))  # kHz resolution
        if bearing is not None and abs(bearing) > 0.5:
            fp['bearings'].append(bearing)
        fp['detections'].append({
            'ts': now, 'detector': detector_name,
            'freq': freq, 'bearing': bearing, 'snr': snr
        })
        
        # Keep only last 100 detections per device
        if len(fp['detections']) > 100:
            fp['detections'] = fp['detections'][-100:]
    
    def match_device(self, features, fp_hash):
        """Check if this matches a known device."""
        if fp_hash in self.fingerprints:
            return self.fingerprints[fp_hash]
        
        # Try fuzzy match — compare key features
        for known_hash, known_fp in self.fingerprints.items():
            known = known_fp['features']
            score = 0
            
            # Phase noise similarity
            pn_diff = abs(features.get('phase_noise_total', 0) - known.get('phase_noise_total', 0))
            if pn_diff < 0.1: score += 2
            
            # Drift rate similarity
            dr_diff = abs(features.get('freq_drift_rate', 0) - known.get('freq_drift_rate', 0))
            if dr_diff < 10: score += 2
            
            # Modulation error similarity
            me_diff = abs(features.get('modulation_error', 0) - known.get('modulation_error', 0))
            if me_diff < 0.05: score += 2
            
            if score >= 4:  # 4+ out of 6 = likely same device
                return known_fp
        
        return None
    
    def get_tracked_devices(self, min_obs=3):
        """Get all tracked devices with enough observations."""
        results = []
        for fp_hash, fp in self.fingerprints.items():
            if fp['total_obs'] < min_obs:
                continue
            
            # Calculate dominant bearing
            bearings = fp['bearings']
            if len(bearings) >= 3:
                # Circular mean
                x = np.mean([np.cos(np.radians(b)) for b in bearings[-20:]])
                y = np.mean([np.sin(np.radians(b)) for b in bearings[-20:]])
                dominant_bearing = np.degrees(np.arctan2(y, x))
            else:
                dominant_bearing = bearings[-1] if bearings else None
            
            results.append({
                'fp_hash': fp_hash,
                'total_obs': fp['total_obs'],
                'freqs': sorted(fp['freqs']),
                'dominant_bearing': dominant_bearing,
                'first_seen': fp['first_seen'],
                'last_seen': fp['last_seen'],
                'freq_count': len(fp['freqs']),
                'is_hopping': len(fp['freqs']) > 3  # frequency hopping = C2 device
            })
        
        return sorted(results, key=lambda x: x['total_obs'], reverse=True)
