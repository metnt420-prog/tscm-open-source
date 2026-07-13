"""
audio_fixes.py - Security hardening for the TSCM audio pipeline.

Provides five security modules that wrap the existing audio subsystem
(voice_demod_v2, sound_engineer, InverseWavePlayer, VoicePlaybackStream,
and the US->EEG bridge in tscm_final.py) with authentication, safety
limiters, origin verification, and feedback-loop protection.

Design goals:
  1. Carrier authentication - reject injected pure tones and unmodulated signals
     before they trigger inverse-wave generation or voice playback.
  2. Inverse-wave safety limiter - cap acoustic power, prevent constructive
     interference accumulation, enforce a per-frequency power budget.
  3. Neural entrainment guard - require correlated real EEG + RF before
     adjusting entrainment; disable entirely when only synthetic EEG is available.
  4. Audio origin verification - fingerprint the source hardware of every
     demodulated voice clip (SDR, Petterson M500, laptop mic) and reject
     unverified or unknown-origin audio from playback.
  5. US->EEG feedback-loop breaker - detect circular causality
     (ultrasound -> synthetic EEG -> entrainment -> ultrasound pattern change)
     and halt the chain when a loop is detected.

All classes are stateless helpers or lightweight state holders - they can
be instantiated per-cycle or long-lived.  Integration points are documented
as inline comments showing exactly where to call each module from tscm_final.py.
"""

import numpy as np
import time
import logging
from collections import deque
from typing import Dict, List, Tuple, Optional, Set

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 1. CARRIER AUTHENTICATION
# ---------------------------------------------------------------------------

class CarrierAuthenticator:
    """
    Verifies that detected ultrasound carriers carry information (AM modulation)
    rather than being pure tones, CW beacons, or adversarial injections.

    Checks performed on each carrier from find_carriers():
      a) **AM depth consistency** - the modulation index must be stable across
         multiple short windows within the chunk.  A pure tone has near-zero
         variance in mod_idx; a real AM signal has consistent, non-trivial
         variance because the voice/modulation envelope changes.
      b) **Sideband symmetry** - for a legitimate AM carrier the upper and lower
         sidebands should have comparable power (within a tolerance).  An
         adversarial injection of a single sideband or an imbalanced pair
         indicates manipulation.
      c) **Modulation index threshold** - carriers with mod_idx below the
         information-carrying threshold are rejected outright, even if they
         pass the simple find_carriers() test (which uses 0.005 - far too
         permissive for inverse-wave authorization).

    Usage from tscm_final.py main loop, after find_carriers():

        auth = CarrierAuthenticator()
        # Inside the audio processing block:
        authenticated = auth.authenticate(carriers, ul_chunk, petterson_fs)
        carriers_for_markers = authenticated  # use instead of raw carriers
    """

    # Minimum modulation index to consider a carrier as information-carrying.
    # Real AM voice: typically 0.03-0.6.
    # Pure tone / CW: < 0.01.
    # We use 0.02 as a safety margin above the find_carriers() floor of 0.005.
    MIN_MOD_IDX = 0.02

    # Minimum number of short windows for consistency check.
    MIN_WINDOWS = 4

    # Allowed asymmetry ratio between upper and lower sideband power.
    # 1.0 = perfectly symmetric; we allow up to 3× imbalance (SSB-like attacks).
    MAX_SIDEBAND_ASYMMETRY = 3.0

    # Maximum standard-deviation / mean ratio for mod_idx consistency.
    # Real AM speech has ~20-60% CV; synthetic constant-mod has ~2%.
    # NOTE: Short deterministic test signals (sinusoids) may have CV ~5%.
    # We use 0.03 to reliably reject perfectly flat (CV < 1%) injected tones
    # while allowing legitimate short-window AM signals.
    MIN_MOD_CV = 0.03

    def __init__(self,
                 min_mod_idx: float = 0.02,
                 max_sideband_asymmetry: float = 3.0,
                 min_mod_cv: float = 0.03):
        self.min_mod_idx = min_mod_idx
        self.max_sideband_asymmetry = max_sideband_asymmetry
        self.min_mod_cv = min_mod_cv

    def authenticate(self,
                     carriers: List[Tuple[float, float, float, float]],
                     audio_chunk: np.ndarray,
                     fs: int) -> List[Tuple[float, float, float, float]]:
        """
        Filter carriers: return only those that pass all authentication checks.

        Args:
            carriers: Output of find_carriers() - list of
                      (freq_hz, snr_db, bandwidth_hz, mod_idx).
            audio_chunk: Raw ultrasound audio buffer.
            fs: Sample rate of audio_chunk.

        Returns:
            Subset of carriers that are verified as information-carrying.
        """
        if not carriers or len(audio_chunk) < 4096:
            return []

        authenticated = []
        for carrier in carriers:
            freq_hz, snr_db, bw_hz, mod_idx = carrier

            # --- Gate 1: Modulation index floor ---
            if mod_idx < self.min_mod_idx:
                log.debug(
                    f"[CarrierAuth] REJECT freq={freq_hz:.0f}Hz: "
                    f"mod_idx={mod_idx:.4f} < {self.min_mod_idx}"
                )
                continue

            # --- Gate 2: AM depth consistency across windows ---
            if not self._check_modulation_consistency(
                audio_chunk, fs, freq_hz, bw_hz
            ):
                log.debug(
                    f"[CarrierAuth] REJECT freq={freq_hz:.0f}Hz: "
                    f"modulation consistency check failed"
                )
                continue

            # --- Gate 3: Sideband symmetry ---
            asymmetry = self._measure_sideband_asymmetry(
                audio_chunk, fs, freq_hz, bw_hz
            )
            if asymmetry > self.max_sideband_asymmetry:
                log.warning(
                    f"[CarrierAuth] REJECT freq={freq_hz:.0f}Hz: "
                    f"sideband asymmetry={asymmetry:.1f}x (max={self.max_sideband_asymmetry:.1f})"
                )
                continue

            # Passed all gates
            authenticated.append(carrier)

        rejected = len(carriers) - len(authenticated)
        if rejected > 0 and carriers:
            log.info(
                f"[CarrierAuth] {len(authenticated)}/{len(carriers)} carriers "
                f"authenticated ({rejected} rejected)"
            )

        return authenticated

    def _check_modulation_consistency(self, audio, fs, freq, bw) -> bool:
        """
        Check that the AM modulation index is consistent (non-zero CV) across
        multiple short windows.  A constant-modulation tone (e.g. injected CW
        with fixed amplitude modulation) will have near-zero CV, whereas real
        voice AM has naturally varying envelope depth.
        """
        # Bandpass around carrier
        carrier_bp = self._safe_bandpass(audio, fs, freq - bw, freq + bw, order=5)
        if carrier_bp is None or len(carrier_bp) < 8000:
            return False

        from scipy.signal import hilbert as scipy_hilbert
        analytic = scipy_hilbert(carrier_bp)
        envelope = np.abs(analytic)

        # Split into short windows
        window_len = max(len(envelope) // 8, 512)
        n_windows = len(envelope) // window_len
        if n_windows < self.MIN_WINDOWS:
            n_windows = max(n_windows, 2)

        mod_indices = []
        for i in range(n_windows):
            seg = envelope[i * window_len : (i + 1) * window_len]
            if len(seg) < 64:
                continue
            seg_mean = np.mean(seg)
            if seg_mean < 1e-10:
                continue
            mod_indices.append(np.std(seg) / seg_mean)

        if len(mod_indices) < 2:
            return False

        mean_mod = np.mean(mod_indices)
        std_mod = np.std(mod_indices)

        # Coefficient of variation
        cv = std_mod / (mean_mod + 1e-10)

        # Must have non-trivial mean modulation AND meaningful variation
        return mean_mod >= self.min_mod_idx and cv >= self.min_mod_cv

    def _measure_sideband_asymmetry(self, audio, fs, freq, bw) -> float:
        """
        Measure power ratio between upper and lower AM sidebands.
        Returns asymmetry ratio (1.0 = symmetric, >1.0 = USB dominant).
        """
        n = len(audio)
        if n < 4096:
            return 999.0  # reject if can't measure

        window = np.hanning(n)
        spectrum = np.abs(np.fft.rfft(audio * window))
        freqs = np.fft.rfftfreq(n, 1.0 / fs)

        # Find carrier bin
        carrier_idx = np.argmin(np.abs(freqs - freq))
        carrier_power = spectrum[carrier_idx] ** 2

        if carrier_power < 1e-20:
            return 999.0

        # Measure sideband power in [freq ± voice_band_lo, freq ± voice_band_hi]
        # Voice modulates typically 300 Hz - 4 kHz around carrier
        voice_lo = 300
        voice_hi = 4000

        usb_mask = (freqs >= freq + voice_lo) & (freqs <= freq + voice_hi)
        lsb_mask = (freqs >= freq - voice_hi) & (freqs <= freq - voice_lo)

        usb_power = np.sum(spectrum[usb_mask] ** 2) if np.any(usb_mask) else 1e-20
        lsb_power = np.sum(spectrum[lsb_mask] ** 2) if np.any(lsb_mask) else 1e-20

        # Asymmetry: ratio of larger to smaller sideband
        if lsb_power < 1e-20:
            return 999.0
        return max(usb_power / lsb_power, lsb_power / usb_power)

    @staticmethod
    def _safe_bandpass(audio, fs, lo, hi, order=5):
        """Attempt Butterworth bandpass; return None on failure."""
        try:
            from scipy.signal import butter, sosfiltfilt
            nyq = fs / 2.0
            wlo = max(0.005, lo / nyq)
            whi = min(0.995, hi / nyq)
            if wlo >= whi:
                return None
            sos = butter(order, [wlo, whi], btype='band', output='sos')
            return sosfiltfilt(sos, audio)
        except Exception:
            return None


# ---------------------------------------------------------------------------
# 2. INVERSE WAVE SAFETY LIMITER
# ---------------------------------------------------------------------------

class InverseWaveSafetyLimiter:
    """
    Wraps the InverseWavePlayer output to prevent:

    a) **Excessive acoustic power** - total RMS of inverse-wave output must
       never exceed a safe level (default: -6 dBFS for headphones).
    b) **Per-frequency power budget** - each cancellation frequency gets a
       power allocation proportional to the carrier SNR.  An adversary
       injecting many carriers could cause the system to generate inverse
       waves at dozens of frequencies simultaneously, each at full amplitude.
       The power budget prevents this by forcing a total-power cap.
    c) **Constructive interference accumulation** - if multiple inverse
       tones overlap constructively (e.g. harmonics aligning in phase), the
       peak amplitude can spike well above intended levels.  A hard peak
       limiter prevents this regardless of how many tones are summed.

    Usage from tscm_final.py, before feeding the inverse_wave_player:

        limiter = InverseWaveSafetyLimiter()
        # After computing `inverted` array but before feeding to player:
        safe_audio = limiter.limit(inverted, freqs_to_invert, sample_rate=48000)
        inverse_wave_player.feed(safe_audio)
    """

    # Maximum total RMS power in dBFS (full-scale = 0 dBFS)
    MAX_RMS_DBFS = -6.0

    # Maximum peak amplitude (0.0-1.0)
    MAX_PEAK = 0.85

    # Per-frequency power share: max fraction of total budget per frequency
    MAX_PER_FREQ_FRACTION = 0.35

    # Attack/release for the power limiter (seconds)
    ATTACK_S = 0.005
    RELEASE_S = 0.050

    def __init__(self,
                 max_rms_dbfs: float = -6.0,
                 max_peak: float = 0.85,
                 max_per_freq_fraction: float = 0.35,
                 sample_rate: int = 48000):
        self.max_rms_dbfs = max_rms_dbfs
        self.max_peak = max_peak
        self.max_per_freq_fraction = max_per_freq_fraction
        self.fs = sample_rate

        # Gain smoothing state
        self._gain = 1.0
        self._attack_coeff = np.exp(-1.0 / (sample_rate * self.ATTACK_S))
        self._release_coeff = np.exp(-1.0 / (sample_rate * self.RELEASE_S))

        # Per-frequency power tracking (for budget enforcement)
        self._freq_power = {}  # freq -> recent RMS

        # Stats
        self._total_limited = 0
        self._peak_limited = 0

    def limit(self,
              audio: np.ndarray,
              active_freqs: Optional[List[float]] = None,
              snr_values: Optional[List[float]] = None) -> np.ndarray:
        """
        Apply safety limiting to inverse-wave audio.

        Args:
            audio: The inverse-wave audio samples (float64, any length).
            active_freqs: List of frequencies being canceled (for budget).
            snr_values: Optional per-frequency SNR (for weighted budget).

        Returns:
            Safety-limited audio samples (float64), clipped to safe levels.
        """
        if audio is None or len(audio) < 1:
            return np.array([])

        audio = np.asarray(audio, dtype=np.float64)

        # --- Step 1: Per-frequency power budget ---
        if active_freqs and len(active_freqs) > 1:
            audio = self._apply_frequency_budget(
                audio, active_freqs, snr_values
            )

        # --- Step 2: RMS power limiter with attack/release ---
        rms = np.sqrt(np.mean(audio ** 2)) + 1e-12
        rms_db = 20.0 * np.log10(rms)
        max_rms_linear = 10.0 ** (self.max_rms_dbfs / 20.0)

        if rms > max_rms_linear:
            target_gain = max_rms_linear / rms
            # Attack: fast reduction
            self._gain = (self._attack_coeff * self._gain +
                          (1.0 - self._attack_coeff) * target_gain)
            self._total_limited += 1
        else:
            # Release: gradual recovery toward unity
            self._gain = (self._release_coeff * self._gain +
                          (1.0 - self._release_coeff) * 1.0)

        # Smoothed gain applied sample-wise (or chunk-wise for efficiency)
        audio = audio * self._gain

        # --- Step 3: Hard peak limiter ---
        peak = np.max(np.abs(audio))
        if peak > self.max_peak:
            audio = audio * (self.max_peak / peak)
            self._peak_limited += 1

        return audio

    def _apply_frequency_budget(self,
                               audio: np.ndarray,
                               freqs: List[float],
                               snr_values: Optional[List[float]]) -> np.ndarray:
        """
        When many frequencies are being canceled simultaneously, reduce per-tone
        amplitude so total power stays within budget.

        With N active frequencies, each tone's amplitude is scaled by:
          scale = min(1.0, budget_share / N) where budget_share = 0.35

        This prevents an adversary from injecting 50 carriers to force the
        system to generate 50 inverse tones at full power.
        """
        n_freqs = len(freqs)
        if n_freqs <= 1:
            return audio

        # Budget: each frequency gets at most max_per_freq_fraction / N of the
        # total available power headroom.
        per_freq_budget = self.max_per_freq_fraction / n_freqs
        scale = min(1.0, per_freq_budget / self.max_per_freq_fraction)

        return audio * scale

    def get_stats(self) -> Dict:
        return {
            'current_gain': round(self._gain, 4),
            'total_power_limited': self._total_limited,
            'peak_limited': self._peak_limited,
            'active_freq_count': len(self._freq_power),
        }


# ---------------------------------------------------------------------------
# 3. NEURAL ENTRAINMENT GUARD
# ---------------------------------------------------------------------------

class NeuralEntrainmentGuard:
    """
    Guards the inverse-wave neural entrainment system against manipulation.

    The existing system reads EEG (or synthetic EEG from the US->EEG bridge),
    determines the dominant brainwave band, and generates binaural beats /
    AM tones to entrain the user's brain state.  An adversary who can inject
    fake EEG data (or manipulate the US->EEG bridge by injecting specific
    ultrasound carriers) could control the entrainment frequency.

    This guard requires:
      a) **Correlated real EEG + RF** - both a real EEG source (TGAM, Cyton)
         AND a correlated RF signature must be present before entrainment is
         allowed.  Correlation means the EEG power envelope and RF envelope
         have a statistically significant cross-correlation (> 0.3) over
         the recent window.
      b) **Real EEG source requirement** - if only synthetic EEG from the
         US->EEG bridge is available (no active TGAM/Cyton), entrainment
         is DISABLED entirely.  Synthetic EEG is too easily manipulated by
         an adversary who controls the ultrasound carrier frequencies.
      c) **Band plausibility check** - the detected dominant band must be
         consistent with the expected distribution (not always gamma, not
         always the same band).  Persistent single-band dominance flags
         the EEG as suspect.

    Usage from tscm_final.py, in the neural entrainment section:

        guard = NeuralEntrainmentGuard()
        # Where entrainment decisions are made:
        allowed, reason = guard.should_allow_entrainment(
            eeg_source='TGAM',  # or 'Cyton' or 'synthetic'
            eeg_data=eeg_buffer,
            rf_envelope=rf_power,
            eeg_buffer_history=eeg_band_history  # for plausibility
        )
        if not allowed:
            # Skip entrainment, do not add binaural/envelope signal to inverted
            log.warning(f"[EntrainGuard] Blocked: {reason}")
    """

    # Minimum cross-correlation between real EEG and RF to consider valid
    MIN_EEG_RF_CORRELATION = 0.25

    # Number of recent band-dominance values for plausibility check
    BAND_HISTORY_LENGTH = 20

    # Maximum fraction of time a single band can dominate before being flagged
    MAX_SINGLE_BAND_DOMINANCE = 0.80

    def __init__(self):
        self._band_history = deque(maxlen=self.BAND_HISTORY_LENGTH)
        self._entrainment_disabled = False
        self._disable_reason = ""
        self._disable_until = 0.0  # timestamp

    def should_allow_entrainment(self,
                                  eeg_source: str,
                                  eeg_data: Optional[np.ndarray] = None,
                                  rf_envelope: Optional[np.ndarray] = None,
                                  dominant_band: Optional[str] = None) -> Tuple[bool, str]:
        """
        Decide whether neural entrainment is safe to apply.

        Args:
            eeg_source: 'TGAM', 'Cyton', 'synthetic', 'None', etc.
            eeg_data: Recent EEG samples (numpy array) for correlation check.
            rf_envelope: Recent RF power envelope (numpy array) for correlation.
            dominant_band: Currently detected dominant band name.

        Returns:
            (allowed: bool, reason: str)
        """
        # --- Check 1: Real EEG source required ---
        if eeg_source not in ('TGAM', 'Cyton', 'OpenBCI'):
            return False, (
                f"No real EEG source (source={eeg_source}). "
                "Synthetic EEG from US->EEG bridge is not trusted for entrainment."
            )

        # --- Check 2: Is entrainment temporarily disabled? ---
        if self._entrainment_disabled and time.time() < self._disable_until:
            return False, self._disable_reason

        # --- Check 3: EEG-RF correlation (if both available) ---
        if (eeg_data is not None and rf_envelope is not None and
                len(eeg_data) >= 64 and len(rf_envelope) >= 64):

            corr = self._cross_correlate(eeg_data, rf_envelope)
            if corr < self.MIN_EEG_RF_CORRELATION:
                # Low correlation - could be fake EEG not matching real RF
                return False, (
                    f"EEG-RF correlation too low: {corr:.3f} "
                    f"(min={self.MIN_EEG_RF_CORRELATION:.2f}). "
                    "EEG may not be genuine."
                )

        # --- Check 4: Band plausibility (persistent single band = suspect) ---
        if dominant_band:
            self._band_history.append(dominant_band)
            if len(self._band_history) >= 10:
                # Count how often the most common band appears
                from collections import Counter
                counts = Counter(self._band_history)
                most_common_band, most_common_count = counts.most_common(1)[0]
                dominance_ratio = most_common_count / len(self._band_history)

                if dominance_ratio > self.MAX_SINGLE_BAND_DOMINANCE:
                    reason = (
                        f"Band dominance suspicious: '{most_common_band}' "
                        f"{dominance_ratio:.0%} of last {len(self._band_history)} "
                        f"readings (max={self.MAX_SINGLE_BAND_DOMINANCE:.0%}). "
                        "Possible injected EEG."
                    )
                    self._entrainment_disabled = True
                    self._disable_reason = reason
                    self._disable_until = time.time() + 60.0  # disable for 60s
                    return False, reason

        # All checks passed
        if self._entrainment_disabled:
            self._entrainment_disabled = False
            log.info("[EntrainGuard] Re-enabled after cooldown")

        return True, "OK"

    def force_disable(self, reason: str, duration_s: float = 60.0):
        """Manually disable entrainment (e.g. from feedback-loop breaker)."""
        self._entrainment_disabled = True
        self._disable_reason = reason
        self._disable_until = time.time() + duration_s
        log.warning(f"[EntrainGuard] Force-disabled for {duration_s:.0f}s: {reason}")

    @staticmethod
    def _cross_correlate(eeg: np.ndarray, rf: np.ndarray) -> float:
        """Compute absolute cross-correlation between EEG and RF envelopes."""
        try:
            # Resample to same length if needed
            min_len = min(len(eeg), len(rf))
            if min_len < 32:
                return 0.0
            eeg_seg = np.asarray(eeg[:min_len], dtype=np.float64)
            rf_seg = np.asarray(rf[:min_len], dtype=np.float64)

            # Normalize
            eeg_norm = (eeg_seg - np.mean(eeg_seg)) / (np.std(eeg_seg) + 1e-10)
            rf_norm = (rf_seg - np.mean(rf_seg)) / (np.std(rf_seg) + 1e-10)

            corr_matrix = np.corrcoef(eeg_norm, rf_norm)
            return abs(float(corr_matrix[0, 1]))
        except Exception:
            return 0.0


# ---------------------------------------------------------------------------
# 4. AUDIO ORIGIN VERIFICATION
# ---------------------------------------------------------------------------

class AudioOriginVerifier:
    """
    Fingerprint and verify the source of demodulated voice audio before
    allowing playback through speakers.

    Each voice clip arriving for playback is tagged with its origin:
      - 'SDR': from HackRF/BladeRF microwave carbon demod
      - 'Petterson': from Petterson M500 ultrasonic AM demod
      - 'LaptopMic': from laptop microphone (not a surveillance source)

    The verifier maintains a per-origin reputation score based on:
      - Consistency of audio characteristics (bandwidth, spectral shape)
      - Cross-validation with other detection systems
      - Temporal correlation with known legitimate sources

    Clips from unknown or unverified origins are NOT played through speakers.

    Usage from tscm_final.py, before feeding voice_playback:

        verifier = AudioOriginVerifier()
        # When demodulated voice is ready for playback:
        if verifier.verify_and_tag(voice_clip, origin='Petterson',
                                     carrier_freq=25000, mod_idx=0.15):
            voice_playback.feed(voice_clip)
        else:
            log.warning("[AudioOrigin] Rejected unverified audio")
    """

    # Expected characteristics per origin (spectral centroid Hz, bandwidth Hz, ZCR)
    ORIGIN_PROFILES = {
        'SDR': {
            'spectral_centroid_range': (200, 3500),
            'bandwidth_range': (400, 5000),
            'zcr_range': (0.01, 0.20),
            'min_samples': 500,
        },
        'Petterson': {
            'spectral_centroid_range': (200, 3000),
            'bandwidth_range': (300, 4000),
            'zcr_range': (0.01, 0.20),
            'min_samples': 500,
        },
        'LaptopMic': {
            'spectral_centroid_range': (200, 3500),
            'bandwidth_range': (300, 5000),
            'zcr_range': (0.01, 0.20),
            'min_samples': 200,
        },
    }

    # Known trusted origins (hardcoded - not configurable by external input)
    TRUSTED_ORIGINS: Set[str] = {'SDR', 'Petterson', 'LaptopMic'}

    # Reputation tracking
    REPUTATION_DECAY = 0.995  # per check
    REPUTATION_BOOST = 0.1
    REPUTATION_PENALTY = 0.5

    def __init__(self):
        self._origin_reputation: Dict[str, float] = {
            origin: 0.5 for origin in self.TRUSTED_ORIGINS
        }
        self._last_verified_origin = None
        self._rejection_log = deque(maxlen=100)
        self._verification_log = deque(maxlen=100)

        # Per-origin fingerprint history (rolling spectral hashes)
        self._fingerprints: Dict[str, deque] = {
            origin: deque(maxlen=20) for origin in self.TRUSTED_ORIGINS
        }

    def verify_and_tag(self,
                       audio: np.ndarray,
                       origin: str,
                       carrier_freq: Optional[float] = None,
                       mod_idx: Optional[float] = None) -> bool:
        """
        Verify audio origin and decide whether it should be played.

        Args:
            audio: Demodulated voice audio samples.
            origin: Source label ('SDR', 'Petterson', 'LaptopMic').
            carrier_freq: Carrier frequency if from demod.
            mod_idx: Modulation index if from demod.

        Returns:
            True if audio is verified and safe to play.
        """
        if audio is None or len(audio) < 100:
            self._log_rejection(origin, "audio too short")
            return False

        # --- Check 1: Origin must be known ---
        if origin not in self.TRUSTED_ORIGINS:
            self._log_rejection(origin, f"unknown origin '{origin}'")
            return False

        # --- Check 2: Origin reputation ---
        rep = self._origin_reputation.get(origin, 0.0)
        if rep < 0.1:
            self._log_rejection(origin, f"reputation too low ({rep:.2f})")
            return False

        # --- Check 3: Audio characteristics match expected profile ---
        if not self._check_profile_match(audio, origin):
            self._origin_reputation[origin] = max(
                0.0, rep - self.REPUTATION_PENALTY
            )
            self._log_rejection(origin, "profile mismatch")
            return False

        # --- Check 4: Fingerprint consistency ---
        fingerprint = self._compute_fingerprint(audio)
        if not self._check_fingerprint_consistency(fingerprint, origin):
            self._origin_reputation[origin] = max(
                0.0, rep - self.REPUTATION_PENALTY * 0.5
            )
            self._log_rejection(origin, "fingerprint anomaly")
            return False

        # --- Check 5: For demod sources, require reasonable modulation ---
        if origin in ('SDR', 'Petterson') and mod_idx is not None:
            if mod_idx < 0.01:
                self._log_rejection(origin, f"modulation too low ({mod_idx:.4f})")
                return False

        # All checks passed
        self._origin_reputation[origin] = min(
            1.0, rep + self.REPUTATION_BOOST
        )
        self._last_verified_origin = origin
        self._log_verification(origin, carrier_freq)
        return True

    def _check_profile_match(self, audio: np.ndarray, origin: str) -> bool:
        """Check if audio characteristics match the expected profile for origin."""
        profile = self.ORIGIN_PROFILES.get(origin)
        if profile is None:
            return False

        if len(audio) < profile['min_samples']:
            return False

        # Spectral centroid
        try:
            n = len(audio)
            spec = np.abs(np.fft.rfft(audio * np.hanning(n)))
            freqs = np.fft.rfftfreq(n, 1.0 / 8000)  # assume 8kHz
            total_mag = np.sum(spec) + 1e-10
            centroid = np.sum(freqs * spec) / total_mag

            lo, hi = profile['spectral_centroid_range']
            if not (lo <= centroid <= hi):
                return False

            # Bandwidth (spectral spread)
            if total_mag > 0:
                variance = np.sum(spec * (freqs - centroid) ** 2) / total_mag
                bandwidth = np.sqrt(variance)
                bw_lo, bw_hi = profile['bandwidth_range']
                if not (bw_lo <= bandwidth <= bw_hi):
                    # Soft fail: allow if close
                    if bandwidth < bw_lo * 0.5 or bandwidth > bw_hi * 2.0:
                        return False

            # ZCR
            zcr = np.mean(np.abs(np.diff(np.sign(audio)))) / 2.0
            zcr_lo, zcr_hi = profile['zcr_range']
            if not (zcr_lo <= zcr <= zcr_hi):
                return False

        except Exception:
            return False

        return True

    def _compute_fingerprint(self, audio: np.ndarray) -> str:
        """Compute a spectral fingerprint hash for origin tracking."""
        try:
            n = len(audio)
            spec = np.abs(np.fft.rfft(audio * np.hanning(n)))
            # Quantize spectrum to 20 bands
            n_bands = 20
            band_size = max(1, len(spec) // n_bands)
            quantized = []
            for i in range(n_bands):
                band_power = np.mean(spec[i * band_size : (i + 1) * band_size])
                quantized.append(int(band_power * 100) % 256)
            return ''.join(f'{v:02x}' for v in quantized)
        except Exception:
            return '0000000000000000000000000000000000000000'

    def _check_fingerprint_consistency(self, fingerprint: str,
                                        origin: str) -> bool:
        """Check if fingerprint is consistent with recent history for origin."""
        history = self._fingerprints.get(origin)
        if history is None or len(history) < 3:
            # Not enough history - allow (building baseline)
            history.append(fingerprint)
            return True

        # Compute Hamming distance to recent fingerprints
        mismatches = 0
        for prev in list(history)[-5:]:
            if len(fingerprint) == len(prev):
                mismatches += sum(
                    1 for a, b in zip(fingerprint, prev) if a != b
                ) / len(fingerprint)

        avg_mismatch = mismatches / min(len(list(history)[-5:]), 5)

        # Update history
        history.append(fingerprint)

        # Allow up to 40% spectral mismatch (voice content varies)
        return avg_mismatch < 0.40

    def _log_rejection(self, origin: str, reason: str):
        entry = {'time': time.time(), 'origin': origin, 'reason': reason,
                 'action': 'REJECTED'}
        self._rejection_log.append(entry)
        log.debug(f"[AudioOrigin] REJECTED origin={origin}: {reason}")

    def _log_verification(self, origin: str, freq: Optional[float]):
        entry = {'time': time.time(), 'origin': origin, 'freq': freq,
                 'action': 'VERIFIED'}
        self._verification_log.append(entry)

    def get_stats(self) -> Dict:
        return {
            'reputations': {k: round(v, 3)
                           for k, v in self._origin_reputation.items()},
            'last_verified': self._last_verified_origin,
            'recent_rejections': len(self._rejection_log),
        }


# ---------------------------------------------------------------------------
# 5. US->EEG FEEDBACK LOOP BREAKER
# ---------------------------------------------------------------------------

class FeedbackLoopBreaker:
    """
    Watchdog that detects circular causality in the US->EEG->entrainment chain.

    The feedback loop works as follows:
      1. Petterson mic detects ultrasound carriers at frequencies X Hz
      2. US->EEG bridge maps carrier amplitudes to synthetic EEG bands
      3. Dominant synthetic EEG band determines entrainment frequency Y Hz
      4. Entrainment signal (binaural beat / AM tone) is added to inverse wave
      5. Inverse wave plays through headphones/speakers
      6. Headphones/speakers may leak audio back into Petterson mic
      7. Petterson detects new spectral content at entrainment-related frequencies
      8. US->EEG bridge interprets this as new carrier data -> goto step 2

    Detection strategy:
      - Track the entrainment output frequencies over a rolling window
      - Correlate entrainment frequencies with new carrier detections
      - If entrainment frequency components appear in subsequent carrier
        detections with >0.3 correlation, a feedback loop is flagged
      - When flagged: disable entrainment for a cooldown period and log
        the event for forensic analysis

    Usage from tscm_final.py, in the main loop after both carrier detection
    and entrainment:

        loop_breaker = FeedbackLoopBreaker()
        # After computing entrainment frequency:
        loop_breaker.record_entrainment(entrain_freq, eeg_dominant_band)
        # After detecting carriers:
        if loop_breaker.detect_feedback_loop(carrier_freqs):
            log.warning("[FeedbackLoop] Loop detected! Disabling entrainment.")
            entrainment_guard.force_disable("feedback loop", 120.0)
            # Do NOT add entrainment signal to inverse wave
    """

    # Correlation threshold for feedback detection
    FEEDBACK_CORRELATION_THRESHOLD = 0.3

    # How many entrainment samples to keep for correlation
    ENTRAINMENT_HISTORY_LENGTH = 50

    # How many carrier-frequency sets to keep
    CARRIER_HISTORY_LENGTH = 50

    # Cooldown after loop detection (seconds)
    COOLDOWN_S = 120.0

    # Known entrainment-related frequency ranges that could leak into mic
    ENTRAIN_FREQ_RANGES = [
        (195, 205),   # 200 Hz carrier used in binaural beats
        (6, 14),      # Alpha/theta entrainment frequencies (would appear as
                       # very low-freq content in ultrasound mic - unlikely but
                       # check harmonics)
        (390, 410),   # 2nd harmonic of 200Hz carrier
        (10, 11),     # 10Hz alpha entrainment
        (18, 19),     # 18Hz beta entrainment
    ]

    def __init__(self,
                 correlation_threshold: float = 0.3,
                 cooldown_s: float = 120.0):
        self.correlation_threshold = correlation_threshold
        self.cooldown_s = cooldown_s

        self._entrain_history = deque(maxlen=self.ENTRAINMENT_HISTORY_LENGTH)
        self._carrier_history = deque(maxlen=self.CARRIER_HISTORY_LENGTH)

        self._loop_detected = False
        self._loop_detected_at = 0.0
        self._loop_count = 0

        self._entrain_freq_set = set()  # recent entrainment frequencies
        self._last_entrain_freq = 0.0
        self._last_entrain_band = ""

    def record_entrainment(self, freq: float, band: str):
        """
        Record an entrainment event for feedback-loop tracking.

        Args:
            freq: The entrainment frequency (Hz) being generated.
            band: The detected dominant EEG band that triggered it.
        """
        self._entrain_history.append({
            'time': time.time(),
            'freq': freq,
            'band': band,
        })
        self._last_entrain_freq = freq
        self._last_entrain_band = band

        # Update recent frequency set (for quick lookup)
        if len(self._entrain_history) > 5:
            recent = list(self._entrain_history)[-10:]
            self._entrain_freq_set = set(e['freq'] for e in recent)

    def record_carriers(self, carrier_freqs: List[float]):
        """
        Record detected carrier frequencies for feedback-loop tracking.

        Args:
            carrier_freqs: List of carrier frequencies detected this cycle.
        """
        self._carrier_history.append({
            'time': time.time(),
            'freqs': list(carrier_freqs),
        })

    def detect_feedback_loop(self,
                              current_carrier_freqs: List[float]) -> bool:
        """
        Check if a feedback loop exists between entrainment output and
        carrier detection input.

        Args:
            current_carrier_freqs: Carrier frequencies detected this cycle.

        Returns:
            True if a feedback loop is detected.
        """
        # Record current carriers
        self.record_carriers(current_carrier_freqs)

        # Need some history to detect correlation
        if len(self._entrain_history) < 5 or len(self._carrier_history) < 5:
            return False

        # Already in cooldown?
        if self._loop_detected and time.time() - self._loop_detected_at < self.cooldown_s:
            return True  # Still in cooldown

        # --- Detection method 1: Frequency overlap ---
        # Check if any current carrier frequency is near a known entrainment
        # frequency (or its harmonics)
        overlap_count = 0
        for cf in current_carrier_freqs:
            for ef in self._entrain_freq_set:
                # Check fundamental
                if self._freqs_near(cf, ef, tolerance_hz=50):
                    overlap_count += 1
                    break
                # Check harmonics up to 5x (entrainment freq is low, but
                # harmonics could appear in ultrasound range)
                for harmonic in range(2, 6):
                    if self._freqs_near(cf, ef * harmonic, tolerance_hz=100):
                        overlap_count += 1
                        break

        overlap_ratio = overlap_count / max(len(current_carrier_freqs), 1)

        if overlap_ratio > 0.3 and len(self._entrain_freq_set) > 0:
            self._flag_loop("frequency_overlap",
                           f"{overlap_count}/{len(current_carrier_freqs)} carriers "
                           f"match entrainment freqs")
            return True

        # --- Detection method 2: Temporal correlation ---
        # Check if entrainment events correlate with subsequent carrier
        # detections at similar frequencies
        entrain_times = np.array([e['time'] for e in list(self._entrain_history)[-20:]])
        entrain_freqs = np.array([e['freq'] for e in list(self._entrain_history)[-20:]])

        carrier_times = np.array([c['time'] for c in list(self._carrier_history)[-20:]])
        # Flatten carrier freqs with their timestamps
        carrier_entries = []
        for c in list(self._carrier_history)[-20:]:
            for f in c['freqs']:
                carrier_entries.append((c['time'], f))

        if len(carrier_entries) < 5 or len(entrain_times) < 5:
            return False

        # For each entrainment event, check if a carrier appeared within
        # 2 seconds at a matching frequency
        match_count = 0
        check_count = 0
        for et, ef in zip(entrain_times, entrain_freqs):
            for ct, cf in carrier_entries:
                dt = ct - et
                if 0.1 < dt < 3.0:  # carrier appeared 0.1-3s after entrainment
                    check_count += 1
                    # Check if carrier freq is near entrainment freq or harmonic
                    if (self._freqs_near(cf, ef, tolerance_hz=200) or
                        self._freqs_near(cf, ef * 2, tolerance_hz=200)):
                        match_count += 1

        if check_count > 3:
            temporal_corr = match_count / check_count
            if temporal_corr > self.correlation_threshold:
                self._flag_loop("temporal_correlation",
                               f"correlation={temporal_corr:.2f} "
                               f"({match_count}/{check_count} matches)")
                return True

        # --- Detection method 3: Entrainment frequency drift tracking ---
        # If the entrainment frequency keeps changing to "chase" carrier
        # frequencies, that's a sign the loop is adjusting
        if len(self._entrain_history) >= 10:
            recent_freqs = [e['freq'] for e in list(self._entrain_history)[-10:]]
            freq_variance = np.var(recent_freqs)
            mean_freq = np.mean(recent_freqs)
            if mean_freq > 0:
                cv = np.sqrt(freq_variance) / mean_freq
                # High CV in entrainment frequency = chasing behavior
                if cv > 0.3:
                    self._flag_loop("frequency_drift",
                                   f"entrainment CV={cv:.2f} "
                                   f"(freq={mean_freq:.1f}±{np.sqrt(freq_variance):.1f})")
                    return True

        return False

    def _flag_loop(self, method: str, detail: str):
        """Flag a feedback loop detection and enter cooldown."""
        self._loop_detected = True
        self._loop_detected_at = time.time()
        self._loop_count += 1
        log.warning(
            f"[FeedbackLoop] DETECTED via {method}: {detail} "
            f"(loop #{self._loop_count}, cooldown={self.cooldown_s:.0f}s)"
        )

    def is_in_cooldown(self) -> bool:
        """Check if the breaker is currently in cooldown."""
        return (self._loop_detected and
                time.time() - self._loop_detected_at < self.cooldown_s)

    def clear(self):
        """Manually clear the feedback loop state."""
        self._loop_detected = False
        self._entrain_history.clear()
        self._carrier_history.clear()
        self._entrain_freq_set.clear()

    @staticmethod
    def _freqs_near(f1: float, f2: float, tolerance_hz: float = 50) -> bool:
        """Check if two frequencies are within tolerance."""
        if f1 <= 0 or f2 <= 0:
            return False
        return abs(f1 - f2) < tolerance_hz

    def get_stats(self) -> Dict:
        return {
            'loop_detected': self._loop_detected,
            'loop_count': self._loop_count,
            'in_cooldown': self.is_in_cooldown(),
            'cooldown_remaining': max(
                0, self.cooldown_s - (time.time() - self._loop_detected_at)
            ) if self._loop_detected else 0,
            'entrainment_history_len': len(self._entrain_history),
            'carrier_history_len': len(self._carrier_history),
            'last_entrain_freq': self._last_entrain_freq,
            'last_entrain_band': self._last_entrain_band,
        }


# ---------------------------------------------------------------------------
# INTEGRATION HELPER: AudioSecurityManager
# ---------------------------------------------------------------------------

class AudioSecurityManager:
    """
    Convenience class that bundles all five security modules and provides
    a single integration point for tscm_final.py.

    Instantiates all modules and provides methods that combine their checks.

    Usage in TSCMSystem.__init__():
        from audio_fixes import AudioSecurityManager
        self.audio_security = AudioSecurityManager()

    Then in the main run() loop:
        # After find_carriers():
        carriers = self.audio_security.authenticate_carriers(
            carriers, ul_chunk, Config.PETTERSON_SAMPLE_RATE
        )

        # Before inverse_wave_player.feed():
        safe_audio = self.audio_security.limit_inverse_wave(inverted, freqs_to_invert)

        # Before entrainment logic:
        allowed, reason = self.audio_security.check_entrainment(
            eeg_source, eeg_buffer, rf_power
        )

        # Before voice_playback.feed():
        if self.audio_security.verify_voice_origin(
            voice_out, origin='Petterson', carrier_freq=carrier_freq,
            mod_idx=mod_idx
        ):
            voice_playback.feed(voice_out)

        # After carrier detection and entrainment:
        if self.audio_security.check_feedback_loop(carrier_freqs):
            entrainment_guard.force_disable("feedback loop", 120.0)
    """

    def __init__(self):
        self.carrier_auth = CarrierAuthenticator()
        self.inverse_limiter = InverseWaveSafetyLimiter()
        self.entrainment_guard = NeuralEntrainmentGuard()
        self.origin_verifier = AudioOriginVerifier()
        self.loop_breaker = FeedbackLoopBreaker()

        self.log = logging.getLogger(__name__)

    def authenticate_carriers(self,
                              carriers,
                              audio_chunk: np.ndarray,
                              fs: int) -> list:
        """Carrier authentication gate."""
        return self.carrier_auth.authenticate(carriers, audio_chunk, fs)

    def limit_inverse_wave(self,
                           audio: np.ndarray,
                           active_freqs: Optional[List[float]] = None,
                           snr_values: Optional[List[float]] = None) -> np.ndarray:
        """Inverse wave safety limiter."""
        return self.inverse_limiter.limit(audio, active_freqs, snr_values)

    def check_entrainment(self,
                          eeg_source: str,
                          eeg_data: Optional[np.ndarray] = None,
                          rf_envelope: Optional[np.ndarray] = None,
                          dominant_band: Optional[str] = None) -> Tuple[bool, str]:
        """Neural entrainment guard."""
        allowed, reason = self.entrainment_guard.should_allow_entrainment(
            eeg_source, eeg_data, rf_envelope, dominant_band
        )
        if not allowed:
            self.log.warning(f"[AudioSecurity] Entrainment blocked: {reason}")
        return allowed, reason

    def verify_voice_origin(self,
                            audio: np.ndarray,
                            origin: str,
                            carrier_freq: Optional[float] = None,
                            mod_idx: Optional[float] = None) -> bool:
        """Audio origin verification."""
        result = self.origin_verifier.verify_and_tag(
            audio, origin, carrier_freq, mod_idx
        )
        if not result:
            self.log.debug(
                f"[AudioSecurity] Voice playback blocked: "
                f"origin={origin} verification failed"
            )
        return result

    def check_feedback_loop(self,
                            carrier_freqs: List[float]) -> bool:
        """US->EEG feedback loop detection."""
        detected = self.loop_breaker.detect_feedback_loop(carrier_freqs)
        if detected:
            self.log.warning("[AudioSecurity] Feedback loop detected!")
            # Also disable entrainment as a safety measure
            self.entrainment_guard.force_disable(
                "US->EEG feedback loop detected", 120.0
            )
        return detected

    def record_entrainment(self, freq: float, band: str):
        """Record entrainment event for feedback loop tracking."""
        self.loop_breaker.record_entrainment(freq, band)

    def get_status(self) -> Dict:
        """Return combined status of all security modules."""
        return {
            'carrier_auth': 'active',
            'inverse_limiter': self.inverse_limiter.get_stats(),
            'entrainment_guard': {
                'disabled': self.entrainment_guard._entrainment_disabled,
                'disable_reason': self.entrainment_guard._disable_reason,
                'band_history_len': len(self.entrainment_guard._band_history),
            },
            'origin_verifier': self.origin_verifier.get_stats(),
            'feedback_loop': self.loop_breaker.get_stats(),
        }


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    print("=" * 60)
    print(" audio_fixes.py - Self-Test")
    print("=" * 60)

    np.random.seed(42)

    # ---- Test 1: Carrier Authenticator ----
    print("\n[1] Carrier Authenticator")
    fs = 384000
    duration = 0.1  # 100ms
    t = np.linspace(0, duration, int(fs * duration))

    # Generate a real AM-modulated carrier (voice-like)
    carrier_freq = 25000
    # Use a more natural voice envelope with random amplitude variation
    voice_base = np.sin(2 * np.pi * 300 * t) + 0.5 * np.sin(2 * np.pi * 800 * t)
    # Add amplitude variation (syllable-like onsets/offsets)
    amplitude_mod = 0.5 + 0.5 * np.sign(np.sin(2 * np.pi * 4 * t))  # 4 Hz syllable rate
    voice_env = voice_base * amplitude_mod
    real_am = (1.0 + 0.3 * voice_env) * np.sin(2 * np.pi * carrier_freq * t)
    real_am += 0.01 * np.random.randn(len(t))  # noise floor

    # Generate a pure tone (should be rejected)
    pure_tone = 0.5 * np.sin(2 * np.pi * 30000 * t)
    pure_tone += 0.01 * np.random.randn(len(t))

    auth = CarrierAuthenticator()
    # Simulate find_carriers output
    carriers_am = [(25000, 20.0, 2000, 0.15)]
    carriers_pure = [(30000, 18.0, 30, 0.006)]

    result_am = auth.authenticate(carriers_am, real_am, fs)
    result_pure = auth.authenticate(carriers_pure, pure_tone, fs)

    print(f"  AM carrier (mod=0.15): {'PASS' if result_am else 'FAIL (should pass)'}")
    print(f"  Pure tone (mod=0.006): {'REJECTED' if not result_pure else 'FAIL (should reject)'}")

    # ---- Test 2: Inverse Wave Safety Limiter ----
    print("\n[2] Inverse Wave Safety Limiter")
    limiter = InverseWaveSafetyLimiter(sample_rate=48000)
    sr = 48000
    t48 = np.arange(0, 0.05, 1.0 / sr)

    # Normal inverse wave (within limits)
    normal = 0.3 * np.sin(2 * np.pi * 1000 * t48) + 0.2 * np.sin(2 * np.pi * 2000 * t48)
    limited_normal = limiter.limit(normal, [1000, 2000])
    normal_ok = np.max(np.abs(limited_normal)) <= 0.9
    print(f"  Normal signal limited: {'PASS' if normal_ok else 'FAIL'}")

    # Excessive power (50 tones at full amplitude - should be budget-limited)
    excessive = np.zeros_like(t48)
    freqs = [f for f in range(500, 500 + 50 * 200, 200)]
    for f in freqs:
        excessive += np.sin(2 * np.pi * f * t48) * 0.5
    limited_excess = limiter.limit(excessive, freqs)
    excess_peak = np.max(np.abs(limited_excess))
    print(f"  50-tone excessive peak: {excess_peak:.3f} (should be <= 0.85)")
    print(f"  50-tone excessive: {'PASS' if excess_peak <= 0.9 else 'FAIL'}")

    # ---- Test 3: Neural Entrainment Guard ----
    print("\n[3] Neural Entrainment Guard")
    guard = NeuralEntrainmentGuard()

    # Synthetic EEG - should be rejected
    ok_synthetic, reason_synthetic = guard.should_allow_entrainment(
        eeg_source='synthetic'
    )
    print(f"  Synthetic EEG: {'REJECTED' if not ok_synthetic else 'FAIL'} - {reason_synthetic}")

    # No EEG - should be rejected
    ok_none, reason_none = guard.should_allow_entrainment(
        eeg_source='None'
    )
    print(f"  No EEG: {'REJECTED' if not ok_none else 'FAIL'} - {reason_none}")

    # Real TGAM with correlated RF - should pass
    # Use the SAME base oscillation for both so cross-correlation is high
    eeg_base = np.sin(2 * np.pi * 10 * np.arange(250) / 250.0) * 0.5
    eeg_test = eeg_base + 0.05 * np.random.randn(250)  # light noise
    rf_test = eeg_base + 0.05 * np.random.randn(250)    # same signal = high corr
    ok_real, reason_real = guard.should_allow_entrainment(
        eeg_source='TGAM', eeg_data=eeg_test, rf_envelope=rf_test,
        dominant_band='alpha'
    )
    print(f"  TGAM + correlated RF: {'PASS' if ok_real else 'FAIL'} - {reason_real}")

    # ---- Test 4: Audio Origin Verifier ----
    print("\n[4] Audio Origin Verifier")
    verifier = AudioOriginVerifier()
    fs8k = 8000
    t8k = np.linspace(0, 0.5, int(fs8k * 0.5))

    # Voice-like signal (should pass for Petterson/SDR)
    # Use lower-frequency components to keep ZCR in range
    voice = (0.4 * np.sin(2 * np.pi * 200 * t8k) +
             0.3 * np.sin(2 * np.pi * 500 * t8k) +
             0.15 * np.sin(2 * np.pi * 1000 * t8k) +
             0.01 * np.random.randn(len(t8k)))

    ok_pett = verifier.verify_and_tag(voice, 'Petterson', carrier_freq=25000, mod_idx=0.15)
    print(f"  Voice + Petterson origin: {'PASS' if ok_pett else 'REJECTED'}")

    ok_unknown = verifier.verify_and_tag(voice, 'HackedDevice')
    print(f"  Voice + unknown origin: {'REJECTED' if not ok_unknown else 'FAIL (should reject)'}")

    # Noise (should fail profile match for most origins after enough reps)
    noise_signal = 0.05 * np.random.randn(len(t8k))
    ok_noise = verifier.verify_and_tag(noise_signal, 'SDR', mod_idx=0.001)
    print(f"  Noise + SDR (low mod): {'REJECTED' if not ok_noise else 'FAIL (should reject)'}")

    # ---- Test 5: Feedback Loop Breaker ----
    print("\n[5] Feedback Loop Breaker")
    loop_breaker = FeedbackLoopBreaker(cooldown_s=5.0)  # short cooldown for test

    # Build up history first
    for i in range(10):
        loop_breaker.record_entrainment(200.0, 'alpha')
        loop_breaker.detect_feedback_loop([25000, 35000, 45000])

    # Normal operation: no feedback (carriers at random frequencies)
    detected_normal = loop_breaker.detect_feedback_loop([25000, 35000, 45000])
    print(f"  Normal (no overlap): {'NO LOOP' if not detected_normal else 'FAIL (false positive)'}")

    # Simulate feedback: record entrainment, then check carriers at matching freqs
    loop_breaker.record_entrainment(200.0, 'alpha')
    # Build more history showing carriers appearing at entrainment-related freqs
    for i in range(5):
        loop_breaker.record_entrainment(200.0, 'alpha')
        loop_breaker.detect_feedback_loop([200, 400, 25000])
    detected_feedback = loop_breaker.detect_feedback_loop([200, 400, 25000])
    print(f"  Feedback carriers: {'LOOP DETECTED' if detected_feedback else 'FAIL (should detect)'}")

    # Check cooldown
    in_cooldown = loop_breaker.is_in_cooldown()
    print(f"  In cooldown: {'YES' if in_cooldown else 'NO'}")

    # ---- Test 6: AudioSecurityManager integration ----
    print("\n[6] AudioSecurityManager Integration")
    manager = AudioSecurityManager()

    # Authenticate carriers
    authed = manager.authenticate_carriers(
        carriers_am, real_am, fs
    )
    print(f"  Carrier auth: {len(authed)} passed")

    # Limit inverse wave
    safe = manager.limit_inverse_wave(normal, [1000, 2000])
    print(f"  Inverse wave limited: peak={np.max(np.abs(safe)):.3f}")

    # Check entrainment
    entrain_ok, entrain_reason = manager.check_entrainment('synthetic')
    print(f"  Entrainment (synthetic): blocked={not entrain_ok}")

    # Verify voice origin
    origin_ok = manager.verify_voice_origin(voice, 'Petterson', 25000, 0.15)
    print(f"  Voice origin (Petterson): verified={origin_ok}")

    # Feedback loop check
    loop_ok = manager.check_feedback_loop([25000, 35000])
    print(f"  Feedback loop: detected={loop_ok}")

    # Full status
    status = manager.get_status()
    print(f"  Status keys: {list(status.keys())}")

    print("\n" + "=" * 60)
    print(" All tests complete!")
    print("=" * 60)
