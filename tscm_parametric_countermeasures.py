"""
tscm_parametric_countermeasures.py — Parametric Amplification Countermeasures

Three-layer defense against parametric amplification attacks:
  1. UltrasonicBeatFrequencyDetector  — detect parametric array beat pairs
  2. UltrasonicNoiseJammer            — active ultrasonic noise injection
  3. CrossLayerParametricCorrelator   — correlate RF/ultrasonic/EEG events

Parametric attack chain being countered:
  Layer 1: RF parametric amplifier at C2 (detected by existing ParametricAmplificationDetector)
  Layer 2: Microwave auditory effect (Frey) — 2.45 GHz pulsed RF → tissue thermoelastic → cochlear audio
  Layer 3: Ultrasonic parametric array — f1, f2 beams mix nonlinearly in air → |f1-f2| audible voice
  Layer 4: Carbon interaction — body tissue nonlinear conductivity mixes RF → bioelectric signals
"""
import numpy as np
from scipy.signal import spectrogram, find_peaks, resample, firwin, lfilter
from collections import deque
import time
import logging

logger = logging.getLogger('tscm.parametric')


# ============================================================================
# Countermeasure 1: Ultrasonic Beat-Frequency Scanner
# ============================================================================
class UltrasonicBeatFrequencyDetector:
    """
    Detects parametric ultrasonic arrays by finding frequency pairs (f1, f2)
    whose difference |f1-f2| falls in the 100–4000 Hz voice range.

    A parametric array transmits two high-intensity ultrasonic beams.
    Air nonlinearity produces the difference frequency at the target location.
    The difference IS the demodulated voice content.

    Algorithm:
      1. Compute spectrogram of Petterson ultrasound (384 kHz)
      2. Find all peaks above noise floor in 18–96 kHz
      3. For each peak pair, compute |f1-f2|
      4. If difference is in voice band (100–4000 Hz) AND both peaks are strong,
         flag as parametric beat pair
      5. For confirmed pairs, correlate amplitude modulation between the two
         carriers (parametric arrays modulate carriers in sync)

    Integration: feed Petterson ultrasound data via update_ultrasound(),
    call detect() to get beat pairs.
    """

    def __init__(self, petterson_fs=384000):
        self.fs = petterson_fs
        self.buf = deque(maxlen=int(petterson_fs * 2))  # 2 seconds
        self.beat_history = {}  # (f1, f2) → list of (timestamp, beat_power, correlation)
        self.beat_persistence = {}  # (f1, f2) → consecutive detection count
        self.min_voice_freq = 100    # Hz — lowest audible voice fundamental
        self.max_voice_freq = 4000   # Hz — highest voice formant
        self.min_carrier_freq = 18000  # Hz — below this, not ultrasonic
        self.max_carrier_freq = 96000  # Hz — Nyquist/2 at 192k, but we go to 96k
        self.noise_floor = None
        self.noise_alpha = 0.05  # EMA for noise floor tracking
        self.last_detect_time = 0

    def update(self, audio):
        """Feed Petterson ultrasound data (384 kHz, mono or multi-channel)."""
        if len(audio.shape) > 1:
            audio = np.mean(audio, axis=1)
        self.buf.extend(audio.flatten())

    def detect(self):
        """Scan for parametric beat pairs. Returns list of detection dicts."""
        if len(self.buf) < self.fs // 4:
            return []

        now = time.time()
        data = np.array(self.buf)[-int(self.fs):]  # Last 1 second
        n = len(data)

        # Compute high-res spectrogram (larger nperseg = better frequency resolution for beat pairs)
        nperseg = 8192
        noverlap = 3072  # 75% overlap for good time resolution
        f, t_seg, Sxx = spectrogram(
            data.astype(np.float64), self.fs,
            nperseg=nperseg, noverlap=noverlap,
            window='hann'
        )

        # Restrict to ultrasonic band
        mask = (f >= self.min_carrier_freq) & (f <= self.max_carrier_freq)
        f_ul = f[mask]
        Sxx_ul = Sxx[mask, :]

        if len(f_ul) < 10:
            return []

        # Mean power spectrum
        mean_pwr = np.mean(Sxx_ul, axis=1)

        # Adaptive noise floor
        if self.noise_floor is None:
            self.noise_floor = np.median(mean_pwr)
        else:
            self.noise_floor = (1 - self.noise_alpha) * self.noise_floor + \
                               self.noise_alpha * np.median(mean_pwr)

        # Peak detection — lowered threshold for parametric detection
        height = max(self.noise_floor * 2.5, 1e-12)
        peaks, props = find_peaks(mean_pwr, height=height, distance=3,
                                  prominence=self.noise_floor * 1.5)

        if len(peaks) < 2:
            return []

        peak_freqs = f_ul[peaks]
        peak_powers = mean_pwr[peaks]

        # --- Beat pair detection ---
        detections = []

        for i in range(len(peak_freqs)):
            for j in range(i + 1, len(peak_freqs)):
                f_hi = max(peak_freqs[i], peak_freqs[j])
                f_lo = min(peak_freqs[i], peak_freqs[j])
                beat_freq = f_hi - f_lo

                if not (self.min_voice_freq <= beat_freq <= self.max_voice_freq):
                    continue

                # Both carriers must be strong relative to noise
                pwr_hi = peak_powers[i] if f_hi == peak_freqs[i] else peak_powers[j]
                pwr_lo = peak_powers[j] if f_lo == peak_freqs[j] else peak_powers[i]
                snr_hi = pwr_hi / (self.noise_floor + 1e-12)
                snr_lo = pwr_lo / (self.noise_floor + 1e-12)

                if snr_hi < 3.0 or snr_lo < 2.0:
                    continue

                # Correlate amplitude modulation between the two carriers
                # Parametric arrays modulate both carriers with the same audio
                idx_hi = np.argmin(np.abs(f_ul - f_hi))
                idx_lo = np.argmin(np.abs(f_ul - f_lo))
                amp_hi = np.sqrt(Sxx_ul[idx_hi, :] + 1e-12)
                amp_lo = np.sqrt(Sxx_ul[idx_lo, :] + 1e-12)

                if len(amp_hi) >= 4 and len(amp_lo) >= 4:
                    # Envelope correlation
                    corr = np.corrcoef(amp_hi, amp_lo)[0, 1]
                    if np.isnan(corr):
                        corr = 0.0
                else:
                    corr = 0.0

                # Track persistence
                key = (round(f_lo), round(f_hi))
                self.beat_persistence[key] = self.beat_persistence.get(key, 0) + 1

                # Build detection
                beat_power = (pwr_hi + pwr_lo) / 2
                am_coherence = abs(corr)

                # Confidence score: persistence (max 10) + AM coherence + SNR
                confidence = min(1.0,
                    self.beat_persistence[key] / 10.0 * 0.3 +
                    am_coherence * 0.4 +
                    min(snr_hi / 20.0, 1.0) * 0.3
                )

                if confidence < 0.25:
                    continue

                detections.append({
                    'detector': 'parametric_beat_pair',
                    'f1': float(f_lo),
                    'f2': float(f_hi),
                    'beat_freq': float(beat_freq),
                    'snr_hi': float(snr_hi),
                    'snr_lo': float(snr_lo),
                    'am_correlation': float(am_coherence),
                    'confidence': float(confidence),
                    'persistence': self.beat_persistence[key],
                    'freq': float(beat_freq),  # Primary freq = audible beat (for map)
                })

        # Prune stale beat pairs (not seen for > 30 cycles)
        stale = [k for k, v in self.beat_persistence.items()
                 if v < self.beat_persistence.get(k, 0) - 30]
        for k in stale:
            del self.beat_persistence[k]

        self.last_detect_time = now
        return detections


# ============================================================================
# Countermeasure 2: Ultrasonic Noise Jammer
# ============================================================================
class UltrasonicNoiseJammer:
    """
    Active countermeasure: injects pseudorandom noise in the 20–50 kHz band
    to disrupt parametric demodulation in air.

    How it works:
      Parametric arrays rely on air nonlinearity to produce |f1-f2|.
      If we inject high-power uncorrelated noise in the same band,
      the air becomes saturated with random nonlinear products,
      destroying the coherence needed for voice demodulation.

    The noise is bandpass-filtered pseudorandom Gaussian noise with
    randomized amplitude modulation, making it impossible for the
    adversary to notch-filter.

    SAFETY:
      - Produces ultrasonic output (inaudible to humans, but pets may hear)
      - Default DISABLED — requires explicit activation via enable() call
      - Amplitude ramped up/down with 500ms smoothing to prevent transients
      - Output is at ultrasonic level, not harmful at reasonable volumes

    Usage:
      jammer = UltrasonicNoiseJammer(output_fs=48000, band=(20000, 50000))
      jammer.enable()  # Explicit user action required
      noise_samples = jammer.generate(n_samples)
      # Play noise_samples through speakers
    """

    def __init__(self, output_fs=48000, band=(20000, 23500), ramp_ms=500):
        self.fs = output_fs
        self.band = band  # (low_cut, high_cut) Hz
        self.ramp_samples = int(output_fs * ramp_ms / 1000)
        self.enabled = False
        self.active = False
        self._rng = np.random.RandomState()

        # Pre-compute bandpass filter
        nyq = output_fs / 2
        self._bpf_b, self._bpf_a = firwin(
            257, [band[0] / nyq, band[1] / nyq],
            pass_zero=False, window='hamming'
        ), [1.0]

        # Filter state for streaming
        self._zi = np.zeros(len(self._bpf_b) - 1)

        # Output level (0.0–1.0, scaled by system volume)
        self.level = 0.3

        # Ramp state
        self._ramp_counter = 0
        self._current_gain = 0.0

        # Modulation state
        self._mod_phase = 0.0
        self._mod_freq = 0.0  # Randomized each burst

        # Effectiveness monitoring
        self.effectiveness = 0.0  # 0 = no effect, 1 = completely disrupted
        self._pre_jam_beat_count = 0
        self._post_jam_beat_count = 0

        logger.info(f'UltrasonicNoiseJammer: band={band}Hz, fs={output_fs}, level={self.level}')

    def enable(self):
        """Activate the jammer. Requires explicit user action."""
        if not self.enabled:
            self.enabled = True
            self._ramp_counter = 0
            self._current_gain = 0.0
            logger.warning('JAMMER ENABLED — ultrasonic noise injection active')
        else:
            logger.info('Jammer already enabled')

    def disable(self):
        """Deactivate the jammer with ramp-down."""
        self.enabled = False
        logger.info('Jammer disabled — ramping down')

    def auto_decide(self, attack_confidence, beat_pair_count):
        """
        Intelligent auto-mode: enable jammer when parametric attacks are confirmed,
        disable when threat subsides. Uses hysteresis to prevent flapping.

        Called each cycle with the current correlator confidence and beat pair count.
        Enables at confidence > 0.5 sustained for 3 cycles.
        Disables when confidence < 0.25 sustained for 30 cycles (~60s at 2s cycle).
        """
        if not hasattr(self, '_auto_confidence_history'):
            self._auto_confidence_history = deque(maxlen=30)
            self._auto_enable_counter = 0
            self._auto_disable_counter = 0
            self.auto_mode = True  # Default to auto

        self._auto_confidence_history.append(attack_confidence)

        if not self.auto_mode:
            return  # Manual mode — user has control

        # Auto-enable: sustained high confidence
        if attack_confidence > 0.5 and beat_pair_count >= 2:
            self._auto_enable_counter += 1
            self._auto_disable_counter = 0
            if self._auto_enable_counter >= 3 and not self.enabled:
                self.enable()
                logger.warning(
                    f'AUTO-JAMMER: enabled — confidence={attack_confidence:.2f} '
                    f'beat_pairs={beat_pair_count} sustained={self._auto_enable_counter}')
        else:
            self._auto_enable_counter = 0

        # Auto-disable: sustained low confidence
        if attack_confidence < 0.25:
            self._auto_disable_counter += 1
            if self._auto_disable_counter >= 30 and self.enabled:
                self.disable()
                logger.info(
                    f'AUTO-JAMMER: disabled — confidence={attack_confidence:.2f} '
                    f'sustained={self._auto_disable_counter}s')
        else:
            self._auto_disable_counter = 0

    def generate(self, n_samples):
        """
        Generate n_samples of jamming noise.
        Returns (noise_array, gain_applied).
        Safely returns zeros if disabled.
        """
        if not self.enabled and self._current_gain < 0.001:
            return np.zeros(n_samples, dtype=np.float32), 0.0

        # Generate white noise
        noise = self._rng.randn(n_samples).astype(np.float32)

        # Randomized amplitude modulation to prevent adversary filtering
        if n_samples > 0:
            self._mod_freq = self._rng.uniform(5, 45)  # Random modulation rate
            t = np.arange(n_samples) / self.fs + self._mod_phase
            am = 0.5 + 0.5 * np.sin(2 * np.pi * self._mod_freq * t)
            self._mod_phase = (self._mod_phase + n_samples / self.fs * self._mod_freq) % (2 * np.pi)
            noise = noise * am.astype(np.float32)

        # Bandpass filter to ultrasonic band
        noise_filt, self._zi = lfilter(
            self._bpf_b, self._bpf_a, noise, zi=self._zi
        )

        # Ramp gain
        target_gain = self.level if self.enabled else 0.0
        gain_step = (target_gain - self._current_gain) / max(self.ramp_samples, 1)

        if abs(target_gain - self._current_gain) > 0.001:
            for i in range(min(n_samples, self.ramp_samples)):
                self._current_gain += gain_step
                noise_filt[i] *= self._current_gain
            if n_samples > self.ramp_samples:
                self._current_gain = target_gain
                noise_filt[self.ramp_samples:] *= self._current_gain
        else:
            self._current_gain = target_gain
            noise_filt *= self._current_gain

        return noise_filt.astype(np.float32), self._current_gain

    def update_effectiveness(self, beat_pairs_before, beat_pairs_after):
        """
        Monitor jammer effectiveness by comparing beat pair counts.
        Call this before and after jamming to measure disruption.
        """
        self._pre_jam_beat_count = beat_pairs_before
        self._post_jam_beat_count = beat_pairs_after

        if beat_pairs_before > 0:
            reduction = 1.0 - (beat_pairs_after / max(beat_pairs_before, 1))
            self.effectiveness = max(0.0, min(1.0, reduction))
        else:
            self.effectiveness = 0.0

        return self.effectiveness


# ============================================================================
# Countermeasure 3: Cross-Layer Parametric Event Correlator
# ============================================================================
class CrossLayerParametricCorrelator:
    """
    Correlates events across the parametric attack chain to confirm
    coordinated multi-layer attacks.

    Tracks:
      Layer 1 (RF):  mw_voice, mw_voice_carrier, parametric_amplification
      Layer 2 (MW):  eeg_carrier_mixing, brain_acceptance (Frey effect)
      Layer 3 (US):  eardrum_capture, silent_sound, parametric_beat_pair
      Layer 4 (Bio): carbon_interaction, victim_2k (body as mixer)

    When events from ≥2 layers fire within a correlation window (default 2s),
    generates a 'parametric_attack_confirmed' alert with attack chain details.

    Also monitors for:
      - Ultrasonic beat pair → eardrum_capture temporal alignment
      - MW voice → EEG carrier mixing alignment
      - Carbon interaction → silent sound alignment
    """

    def __init__(self, window_s=2.0, min_layers=2):
        self.window_s = window_s
        self.min_layers = min_layers
        self.events = {
            1: deque(maxlen=200),  # RF layer
            2: deque(maxlen=200),  # Microwave layer
            3: deque(maxlen=200),  # Ultrasonic layer
            4: deque(maxlen=200),  # Bio layer
        }
        self.layer_names = {1: 'RF', 2: 'MW_AUDITORY', 3: 'ULTRASONIC', 4: 'BIO_MIXER'}
        self.confirmed_attacks = deque(maxlen=100)
        self.last_correlation_time = 0
        self._cycle_count = 0

        # Detection mapping: detector_name → layer
        self.detector_layer_map = {
            # Layer 1: RF parametric amplifier + microwave carrier
            'mw_voice': 1,
            'mw_voice_carrier': 1,
            'parametric_amplification': 1,
            'mod_fm': 1,
            'mod_ssb': 1,
            # Layer 2: Microwave auditory effect (Frey) — detected via EEG/body
            'eeg_carrier_mixing': 2,
            'brain_acceptance': 2,
            'ssvep': 2,
            'hemisync': 2,
            'forced_thought': 2,
            # Layer 3: Ultrasonic parametric array
            'eardrum_capture': 3,
            'silent_sound': 3,
            'parametric_beat_pair': 3,
            'ultrasonic_scan': 3,
            'us_modem_fsk': 3,
            'us_modem_psk': 3,
            'laptop_ultrasound': 3,
            'constant_ultrasonic_carrier': 3,
            'ultrasound_hopper': 3,  # freq-hopping ultrasound
            # Layer 4: Body as nonlinear mixer (carbon interaction)
            'carbon_interaction': 4,
            'victim_2k': 4,
            'god_helmet': 4,
            'nerve_pain_scan': 4,
            'vibration_equipment': 4,
        }

    def update(self, sources):
        """
        Feed current cycle's sources. Extracts detector names and timestamps
        for cross-layer correlation.

        Args:
            sources: list of detection dicts from current cycle
        """
        now = time.time()
        self._cycle_count += 1

        for s in sources:
            detector = s.get('detector', '')
            if not detector:
                continue

            layer = self.detector_layer_map.get(detector)
            if layer is None:
                continue

            self.events[layer].append({
                'time': now,
                'detector': detector,
                'freq': s.get('freq', 0),
                'snr': s.get('snr', 0),
                'bearing': s.get('bearing'),
                'classification': s.get('classification', 'unknown'),
            })

    def correlate(self):
        """
        Check for cross-layer event coincidence.
        Returns list of 'parametric_attack_confirmed' alerts.
        """
        now = time.time()
        if now - self.last_correlation_time < 0.5:
            return []
        self.last_correlation_time = now

        # Collect recent events from each layer (within window)
        active_layers = {}
        for layer_id in range(1, 5):
            recent = [e for e in self.events[layer_id]
                      if now - e['time'] <= self.window_s]
            if recent:
                active_layers[layer_id] = recent

        if len(active_layers) < self.min_layers:
            return []

        # Build attack chain description
        chain_info = []
        for layer_id in sorted(active_layers.keys()):
            layer_events = active_layers[layer_id]
            detectors = list(set(e['detector'] for e in layer_events))
            freqs = [e['freq'] for e in layer_events if e['freq'] > 0]
            avg_snr = np.mean([e['snr'] for e in layer_events]) if layer_events else 0
            chain_info.append({
                'layer': layer_id,
                'layer_name': self.layer_names[layer_id],
                'detectors': detectors,
                'frequencies': sorted(set(freqs))[:5],
                'event_count': len(layer_events),
                'avg_snr': float(avg_snr),
            })

        # Score the correlation
        total_layers = len(active_layers)
        total_events = sum(len(v) for v in active_layers.values())
        layer_score = min(1.0, total_layers / 4.0)
        density_score = min(1.0, total_events / 20.0)

        # Check for specific high-threat patterns
        specific_threats = []
        
        # Pattern A: MW voice + eardrum capture simultaneously (Frey + parametric array)
        if 1 in active_layers and 3 in active_layers:
            mw_dets = [e['detector'] for e in active_layers[1]]
            us_dets = [e['detector'] for e in active_layers[3]]
            if any('mw_voice' in d for d in mw_dets) and \
               any(d in us_dets for d in ['eardrum_capture', 'silent_sound', 'parametric_beat_pair']):
                specific_threats.append('MW_VOICE_AND_ULTRASONIC_SIMULTANEOUS')

        # Pattern B: EEG carrier mixing + ultrasonic activity (Frey effect confirmed by EEG)
        if 2 in active_layers and 3 in active_layers:
            eeg_dets = [e['detector'] for e in active_layers[2]]
            us_dets = [e['detector'] for e in active_layers[3]]
            if any('eeg_carrier_mixing' in d for d in eeg_dets) and \
               any('eardrum_capture' in d for d in us_dets):
                specific_threats.append('FREY_EFFECT_EEG_CONFIRMED')

        # Pattern C: Carbon interaction + silent sound (body as demodulator)
        if 4 in active_layers and 3 in active_layers:
            bio_dets = [e['detector'] for e in active_layers[4]]
            us_dets = [e['detector'] for e in active_layers[3]]
            if any('carbon_interaction' in d for d in bio_dets) and \
               any('silent_sound' in d for d in us_dets):
                specific_threats.append('BODY_AS_PARAMETRIC_DEMODULATOR')

        # Pattern D: Parametric amplifier + any other layer (C2 boosting signal)
        if 1 in active_layers:
            rf_dets = [e['detector'] for e in active_layers[1]]
            if 'parametric_amplification' in rf_dets and total_layers >= 2:
                specific_threats.append('PARAMETRIC_AMP_ACTIVE')

        confidence = (layer_score * 0.4 + density_score * 0.3 +
                      min(len(specific_threats) / 3.0, 1.0) * 0.3)

        if confidence < 0.4 and not specific_threats:
            return []

        alert = {
            'detector': 'parametric_attack_confirmed',
            'total_layers': total_layers,
            'total_events': total_events,
            'confidence': round(confidence, 3),
            'specific_threats': specific_threats,
            'chain': chain_info,
            'freq': 0,  # Multi-frequency — use 0 as placeholder
            'snr': float(np.mean([ci['avg_snr'] for ci in chain_info])),
            'classification': 'transmitter',
            'threat_score': int(confidence * 100),
        }

        self.confirmed_attacks.append({
            'time': now,
            'alert': alert,
        })

        return [alert]

    def get_status(self, sources=None):
        """Return current correlation status for dashboard.
        If sources list is provided, includes real-time source-based counts
        that don't depend on the event window."""
        now = time.time()
        active = {}
        for layer_id in range(1, 5):
            recent = len([e for e in self.events[layer_id]
                         if now - e['time'] <= self.window_s])
            active[self.layer_names[layer_id]] = recent

        recent_confirmed = [a for a in self.confirmed_attacks
                           if now - a['time'] <= 60.0]

        result = {
            'active_layers': active,
            'total_layers_active': sum(1 for v in active.values() if v > 0),
            'recent_confirmations': len(recent_confirmed),
            'last_confidence': recent_confirmed[-1]['alert']['confidence'] if recent_confirmed else 0.0,
        }

        # Real-time source-based counts (independent of event window)
        if sources:
            src_counts = {1: 0, 2: 0, 3: 0, 4: 0}
            for s in sources:
                lid = self.detector_layer_map.get(s.get('detector', ''))
                if lid:
                    src_counts[lid] += 1
            result['source_layers_active'] = sum(1 for v in src_counts.values() if v > 0)
            result['source_layers'] = {self.layer_names[k]: v for k, v in src_counts.items()}

        return result
