"""
AI Sound Engineer for TSCM Suite
Processes demodulated ultrasonic/audio signals for clarity and analysis.
- Voice Activity Detection (energy + zero-crossing rate)
- Minimum statistics noise estimation
- Spectral noise gating with soft-gate and noise floor tracking
- Bandpass filter (speech band 80Hz - 8kHz)
- Spectral subtraction (Wiener-style denoise)
- De-hum notch filters (60Hz + harmonics 120/180/240Hz)
- Presence boost via peaking EQ biquad (center 3kHz, Q=1.5, +4dB)
- Formant enhancement (500Hz, 1.5kHz, 2.5kHz, 3.5kHz)
- Adaptive dynamic range compression
- Peak normalization (-1dB headroom)
- WAV file output with timestamped filenames
- Live playback output (float32 clipped to [-1, 1])
"""

import numpy as np
import os
import time
import logging
from datetime import datetime, timezone
from collections import deque

try:
    from scipy.signal import butter, lfilter, sosfilt, sosfiltfilt, iirfilter, sosfilt_zi
    from scipy.io import wavfile
    from scipy.ndimage import uniform_filter1d
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False

try:
    import soundfile as sf
    SOUNDFILE_AVAILABLE = True
except ImportError:
    SOUNDFILE_AVAILABLE = False


def _biquad_peaking_sos(freq, gain_db, Q, fs):
    """
    Design a 2nd-order section (SOS) for peaking EQ.
    
    Args:
        freq: Center frequency in Hz
        gain_db: Gain in dB (positive = boost, negative = cut)
        Q: Quality factor
        fs: Sample rate
    
    Returns:
        numpy array shape (1, 6) — a single second-order section
    """
    A = 10.0 ** (gain_db / 40.0)
    w0 = 2.0 * np.pi * freq / fs
    alpha = np.sin(w0) / (2.0 * Q)
    cos_w0 = np.cos(w0)
    
    b0 = 1.0 + alpha * A
    b1 = -2.0 * cos_w0
    b2 = 1.0 - alpha * A
    a0 = 1.0 + alpha / A
    a1 = -2.0 * cos_w0
    a2 = 1.0 - alpha / A

    # Normalize by a0
    sos = np.array([[b0 / a0, b1 / a0, b2 / a0, 1.0, a1 / a0, a2 / a0]])
    return sos


def _notch_sos(freq, Q, fs):
    """
    Design a notch (band-reject) filter as a second-order section.
    
    Args:
        freq: Notch frequency in Hz
        Q: Quality factor (higher = narrower notch)
        fs: Sample rate
    
    Returns:
        numpy array shape (1, 6) — a single second-order section
    """
    w0 = 2.0 * np.pi * freq / fs
    alpha = np.sin(w0) / (2.0 * Q)
    cos_w0 = np.cos(w0)
    
    b0 = 1.0
    b1 = -2.0 * cos_w0
    b2 = 1.0
    a0 = 1.0 + alpha
    a1 = -2.0 * cos_w0
    a2 = 1.0 - alpha
    
    sos = np.array([[b0 / a0, b1 / a0, b2 / a0, 1.0, a1 / a0, a2 / a0]])
    return sos


class VoiceActivityDetector:
    """
    Frame-level VAD using energy + zero-crossing rate.
    
    Returns a boolean mask indicating which frames contain voice activity.
    Voice frames have higher energy and moderate zero-crossing rates
    (silence is low energy; high ZCR typically indicates unvoiced noise).
    """
    
    def __init__(self, fs, frame_size=256, hop=128,
                 energy_threshold_db=-45, zcr_max=0.35,
                 energy_weight=0.7, zcr_weight=0.3):
        self.fs = fs
        self.frame_size = frame_size
        self.hop = hop
        self.energy_threshold_db = energy_threshold_db
        self.zcr_max = zcr_max
        self.energy_weight = energy_weight
        self.zcr_weight = zcr_weight
        
        # Running estimates for adaptive thresholds
        self._energy_history = deque(maxlen=30)
        self._zcr_history = deque(maxlen=30)
    
    def detect(self, audio):
        """
        Run VAD on an audio signal.
        
        Args:
            audio: float64 numpy array, mono
        
        Returns:
            frame_mask: boolean array, True where voice is detected
            num_frames: total number of frames
            hop: the hop size used
        """
        n = len(audio)
        if n < self.frame_size:
            return np.array([True]), 1, self.hop
        
        num_frames = (n - self.frame_size) // self.hop + 1
        energies = np.zeros(num_frames)
        zcrs = np.zeros(num_frames)
        
        for i in range(num_frames):
            frame = audio[i * self.hop : i * self.hop + self.frame_size]
            
            # Energy in dB
            rms = np.sqrt(np.mean(frame ** 2))
            energies[i] = 20.0 * np.log10(rms + 1e-10)
            
            # Zero-crossing rate
            crossings = np.sum(np.abs(np.diff(np.sign(frame)))) / (2.0 * len(frame))
            zcrs[i] = crossings
        
        # Update running history for adaptive threshold
        if len(energies) > 0:
            self._energy_history.extend(energies.tolist())
            self._zcr_history.extend(zcrs.tolist())
        
        # Compute adaptive energy threshold: use median of recent energy
        # as baseline, then set threshold relative to that
        if len(self._energy_history) >= 10:
            median_energy = np.median(list(self._energy_history))
            adaptive_threshold = median_energy + (self.energy_threshold_db - (-30))
            adaptive_threshold = max(self.energy_threshold_db, min(adaptive_threshold, -25))
        else:
            adaptive_threshold = self.energy_threshold_db
        
        # Score each frame: weighted combination of energy and ZCR
        voice_scores = np.zeros(num_frames)
        for i in range(num_frames):
            # Energy score: how much above threshold (clamped to [0,1])
            e_score = np.clip((energies[i] - adaptive_threshold) / 20.0, 0.0, 1.0)
            
            # ZCR score: penalize very high ZCR (likely noise/clicks)
            z_score = 1.0 - np.clip((zcrs[i] - 0.05) / (self.zcr_max - 0.05), 0.0, 1.0)
            
            voice_scores[i] = self.energy_weight * e_score + self.zcr_weight * z_score
        
        # Hysteresis smoothing: require at least 2 consecutive voice frames
        frame_mask = voice_scores > 0.35
        smoothed = np.copy(frame_mask)
        for i in range(1, len(smoothed)):
            if frame_mask[i] and not frame_mask[i - 1]:
                smoothed[i] = False  # Need confirmation next frame
        # Also look-ahead for fast onsets
        for i in range(len(smoothed) - 1):
            if not smoothed[i] and frame_mask[i] and frame_mask[i + 1]:
                smoothed[i] = True
        
        return smoothed, num_frames, self.hop


class MinimumStatisticsNoiseEstimator:
    """
    Tracks running minimum of spectral magnitudes across frames to
    estimate the noise floor robustly — works even when the signal
    starts immediately (no reliance on an initial silence period).
    """
    
    def __init__(self, frame_size, num_bins, num_frames_tracking=80,
                 bias=1.5, decay_per_frame=0.995):
        self.frame_size = frame_size
        self.num_bins = num_bins
        self.tracking_length = num_frames_tracking
        self.bias = bias
        self.decay = decay_per_frame
        
        # Circular buffer of spectral magnitudes
        self._mag_buffer = np.zeros((num_frames_tracking, num_bins))
        self._buf_idx = 0
        self._buffer_full = False
        self._frame_count = 0
        
        # Current noise estimate
        self.noise_spectrum = np.zeros(num_bins)
    
    def update(self, magnitude_spectrum):
        """
        Feed a new magnitude spectrum. Updates the noise estimate.
        
        Args:
            magnitude_spectrum: numpy array of shape (num_bins,)
        
        Returns:
            noise_spectrum: current noise estimate, shape (num_bins,)
        """
        # Store in circular buffer
        self._mag_buffer[self._buf_idx] = magnitude_spectrum
        self._buf_idx = (self._buf_idx + 1) % self.tracking_length
        
        if not self._buffer_full and self._buf_idx == 0:
            self._buffer_full = True
        
        self._frame_count += 1
        
        # Running minimum across the buffer
        if self._buffer_full:
            min_spectrum = np.min(self._mag_buffer, axis=0)
        else:
            min_spectrum = np.min(self._mag_buffer[:self._buf_idx], axis=0) if self._buf_idx > 0 else magnitude_spectrum
        
        # Apply bias (minimum statistics tends to underestimate)
        biased_min = min_spectrum * self.bias
        
        # Smooth update with exponential decay — never increase faster than decay
        # but allow decrease to follow drops in noise floor
        if self._frame_count == 1:
            self.noise_spectrum = biased_min.copy()
        else:
            # Only update upward with decay; downward tracks immediately
            increasing = biased_min > self.noise_spectrum
            self.noise_spectrum[increasing] = (
                self.decay * self.noise_spectrum[increasing] +
                (1 - self.decay) * biased_min[increasing]
            )
            self.noise_spectrum[~increasing] = biased_min[~increasing]
        
        return self.noise_spectrum


class AISoundEngineer:
    """
    AI-powered audio post-processing for TSCM voice recovery.
    
    Pipeline:
    1. Voice Activity Detection (skip silent frames)
    2. De-hum notch filters (60Hz + harmonics)
    3. Spectral gate (soft-gate with minimum statistics noise floor)
    4. Bandpass filter (speech band 80Hz - 8kHz)
    5. Spectral subtraction (Wiener-style denoise)
    6. Presence boost (peaking EQ at 3kHz, Q=1.5, +4dB)
    7. Formant enhancement (500Hz, 1.5kHz, 2.5kHz, 3.5kHz)
    8. Adaptive dynamic range compression
    9. Peak normalize (-1dB headroom)
    10. Save WAV file
    
    Backward-compatible interface: process_audio() and flush() still work.
    New: process_for_playback() returns float32 audio clipped to [-1, 1].
    """
    
    def __init__(self, output_dir="demod_audio", sample_rate=8000,
                 noise_gate_db=-40, speech_band=(80, 8000),
                 presence_boost_db=3, presence_freq=(2000, 4000)):
        self.output_dir = output_dir
        self.fs = sample_rate
        # Keep legacy params for backward compatibility but use improved defaults internally
        self.noise_gate_db = noise_gate_db
        self.speech_band = speech_band
        self.presence_boost_db = presence_boost_db
        self.presence_freq = presence_freq
        self.file_counter = 0
        self.processed_count = 0
        self.log = logging.getLogger(__name__)
        
        # Legacy rolling noise floor (kept for get_stats backward compat)
        self.noise_floor = deque(maxlen=50)
        self.noise_floor_db = -60
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        if not SCIPY_AVAILABLE:
            self.log.warning("scipy not available - sound engineer limited")
        
        # Build all filters
        self._build_filters()
    
    def _build_filters(self):
        """Pre-compute all IIR filters for the processing chain."""
        if not SCIPY_AVAILABLE:
            return
        
        nyq = self.fs / 2.0
        
        # 1. Speech bandpass: 80Hz - 8kHz (Butterworth 4th order)
        low = max(0.001, self.speech_band[0] / nyq)
        high = min(0.999, self.speech_band[1] / nyq)
        try:
            self.speech_bpf = butter(4, [low, high], btype='band', output='sos')
        except Exception:
            self.speech_bpf = None
        
        # 2. De-hum notch filters: 60Hz and harmonics
        self.dehum_sos = []
        for hum_freq in [60, 120, 180, 240]:
            # Use a higher Q for fundamental, slightly lower for harmonics
            Q = 30.0 if hum_freq == 60 else 20.0
            if hum_freq < nyq:
                self.dehum_sos.append(_notch_sos(hum_freq, Q, self.fs))
        self.dehum_sos = np.vstack(self.dehum_sos) if self.dehum_sos else None
        
        # 3. Presence boost: proper peaking EQ at 3kHz, Q=1.5, +4dB
        self.presence_eq_sos = _biquad_peaking_sos(
            freq=3000.0, gain_db=4.0, Q=1.5, fs=self.fs
        )
        
        # 4. Formant enhancement: gentle boosts at key formant frequencies
        #    F1 ~500Hz, F2 ~1500Hz, F3 ~2500Hz, F4 ~3500Hz
        #    Use +2dB boost with moderate Q for natural enhancement
        formant_freqs = [500.0, 1500.0, 2500.0, 3500.0]
        formant_gains = [2.0, 2.5, 2.0, 1.5]
        formant_qs = [1.2, 1.5, 1.5, 1.8]
        
        formant_sos_list = []
        for f, g, q in zip(formant_freqs, formant_gains, formant_qs):
            if f < nyq:
                formant_sos_list.append(_biquad_peaking_sos(f, g, q, self.fs))
        
        self.formant_sos = np.vstack(formant_sos_list) if formant_sos_list else None
        
        # 5. Legacy presence filter (backward compat, but not used in new pipeline)
        try:
            low_p = max(0.001, self.presence_freq[0] / nyq)
            self.presence_filter = butter(2, low_p, btype='low', output='sos')
        except Exception:
            self.presence_filter = None
    
    def process_audio(self, audio_data, label="demod", source_hw="unknown",
                      freq=None, detector_type=None):
        """
        Full processing pipeline for demodulated audio. Backward-compatible.
        
        Args:
            audio_data: numpy float array (mono)
            label: descriptive label for the file
            source_hw: which hardware captured it (RF, Audio, etc.)
            freq: carrier frequency if known
            detector_type: which detector produced it
            
        Returns:
            dict with 'output_path', 'duration_sec', 'peak_db', 'rms_db', 'snr_est'
            or None if processing failed
        """
        processed = self._process_pipeline(audio_data)
        if processed is None:
            return None
        
        try:
            # Save
            output_path = self._save_processed(processed, label)
            
            # Metrics
            peak_db = 20 * np.log10(np.max(np.abs(processed)) + 1e-10)
            rms_db = 20 * np.log10(np.sqrt(np.mean(processed ** 2)) + 1e-10)
            
            result = {
                'output_path': output_path,
                'duration_sec': len(processed) / self.fs,
                'peak_db': peak_db,
                'rms_db': rms_db,
                'label': label,
                'source_hw': source_hw,
                'freq': freq,
                'detector_type': detector_type,
                'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            }
            
            self.processed_count += 1
            self.log.info(f"[SoundEngineer] Processed {label}: {result['duration_sec']:.1f}s, "
                         f"peak={peak_db:.1f}dB, rms={rms_db:.1f}dB -> {output_path}")
            
            return result
            
        except Exception as e:
            self.log.error(f"[SoundEngineer] Processing failed for {label}: {e}")
            return None
    
    def process_for_playback(self, audio_data):
        """
        Process audio for live streaming. Returns float32 audio clipped to [-1, 1].
        Same pipeline as process_audio but skips file I/O and returns raw samples.
        
        Args:
            audio_data: numpy float array (mono)
            
        Returns:
            numpy float32 array clipped to [-1, 1], or None if processing failed
        """
        processed = self._process_pipeline(audio_data)
        if processed is None:
            return None
        
        return np.clip(processed, -1.0, 1.0).astype(np.float32)
    
    def _process_pipeline(self, audio_data):
        """
        Core processing pipeline. Returns float64 processed audio or None.
        """
        if not SCIPY_AVAILABLE:
            self.log.warning("scipy not available - cannot process audio")
            return None
        
        if audio_data is None or len(audio_data) < 100:
            return None
        
        try:
            audio = np.asarray(audio_data, dtype=np.float64)
            
            # 1. Voice Activity Detection
            vad = VoiceActivityDetector(self.fs, frame_size=256, hop=128)
            voice_mask, num_frames, hop = vad.detect(audio)
            
            # Compute overall voice activity ratio
            voice_ratio = np.mean(voice_mask)
            
            # If there's essentially no voice, still process but log it
            if voice_ratio < 0.05:
                self.log.debug(f"[SoundEngineer] Low voice activity ({voice_ratio:.1%}), processing anyway")
            
            # 2. De-hum: notch filters at 60Hz + harmonics
            if self.dehum_sos is not None:
                audio = sosfiltfilt(self.dehum_sos, audio)
            
            # 3. Spectral gate with soft-gate and minimum statistics noise floor
            audio = self._spectral_gate_v2(audio, voice_mask, hop)
            
            # 4. Speech bandpass filter
            if self.speech_bpf is not None:
                audio = sosfiltfilt(self.speech_bpf, audio)
            
            # 5. Spectral subtraction with minimum statistics noise estimate
            audio = self._spectral_subtraction_v2(audio)
            
            # 6. Presence boost via peaking EQ (3kHz, Q=1.5, +4dB)
            audio = sosfiltfilt(self.presence_eq_sos, audio)
            
            # 7. Formant enhancement (500Hz, 1.5kHz, 2.5kHz, 3.5kHz)
            if self.formant_sos is not None:
                audio = sosfiltfilt(self.formant_sos, audio)
            
            # 8. Adaptive dynamic range compression
            audio = self._compress_adaptive(audio)
            
            # 9. Peak normalize to -1dB
            audio = self._normalize(audio)
            
            # Update legacy noise floor estimate for stats backward compat
            noise_segment = audio[:min(len(audio), self.fs)]
            rms = np.sqrt(np.mean(noise_segment ** 2))
            if rms > 0:
                self.noise_floor.append(rms)
                if self.noise_floor:
                    self.noise_floor_db = 20 * np.log10(np.mean(self.noise_floor) + 1e-10)
            
            return audio
            
        except Exception as e:
            self.log.error(f"[SoundEngineer] Pipeline failed: {e}")
            return None
    
    # ------------------------------------------------------------------
    #  Spectral Gate v2 — soft-gate with minimum statistics noise floor
    # ------------------------------------------------------------------
    def _spectral_gate_v2(self, audio, voice_mask, hop, frame_size=256):
        """
        Spectral noise gate with:
        - Minimum statistics noise floor estimation (no dependence on initial silence)
        - Soft gating (smooth transition, no hard cutoff)
        - Proper overlap-add with COLA-normalized window
        - Voice activity awareness: apply gentler gating during voice frames
        """
        n = len(audio)
        output = np.zeros(n)
        window = np.hanning(frame_size)
        
        # Proper overlap-add normalization: sum of squared windows at each sample
        # divided by frame_size (or just accumulate window sums)
        window_sum = np.zeros(n)
        
        # Minimum statistics noise estimator
        num_bins = frame_size // 2 + 1
        noise_est = MinimumStatisticsNoiseEstimator(
            frame_size=frame_size,
            num_bins=num_bins,
            num_frames_tracking=80,
            bias=1.5
        )
        
        num_frames = (n - frame_size) // hop + 1
        
        for i in range(num_frames):
            start = i * hop
            frame = audio[start:start + frame_size]
            windowed = frame * window
            
            spectrum = np.fft.rfft(windowed)
            magnitude = np.abs(spectrum)
            phase = np.angle(spectrum)
            
            # Update noise estimate (minimum statistics — works without initial silence)
            noise_level = noise_est.update(magnitude)
            
            # Soft gate: use a fixed threshold relative to the noise floor
            # Threshold = noise floor + gate_offset
            gate_offset_db = 8.0  # Only suppress bins 8dB above the estimated noise
            gate_offset_linear = 10.0 ** (gate_offset_db / 20.0)
            threshold = noise_level * gate_offset_linear
            
            # During voice frames, use a gentler threshold (don't kill quiet speech)
            is_voice = False
            frame_idx = i
            if frame_idx < len(voice_mask):
                is_voice = bool(voice_mask[frame_idx])
            
            if is_voice:
                # During voice: only suppress bins well below noise floor
                voice_threshold = noise_level * 0.5  # 50% of noise floor
                threshold = np.minimum(threshold, voice_threshold)
            
            # Soft gate with smooth ramp (6dB transition zone)
            ramp_width = threshold * 0.3 + 1e-10
            gate_factor = np.clip((magnitude - threshold) / ramp_width, 0.0, 1.0)
            
            # Apply gate
            gated_mag = magnitude * gate_factor
            
            # Reconstruct
            gated_spectrum = gated_mag * np.exp(1j * phase)
            reconstructed = np.fft.irfft(gated_spectrum, frame_size)
            
            # Overlap-add with window
            output[start:start + frame_size] += reconstructed * window
            window_sum[start:start + frame_size] += window ** 2
        
        # Normalize overlap-add to avoid amplitude artifacts
        window_sum = np.maximum(window_sum, 1e-8)
        output /= window_sum
        
        return output
    
    # ------------------------------------------------------------------
    #  Spectral Subtraction v2 — minimum statistics noise estimation
    # ------------------------------------------------------------------
    def _spectral_subtraction_v2(self, audio, frame_size=512, hop=256,
                                  over_subtraction=1.2, spectral_floor=0.02):
        """
        Spectral subtraction with minimum statistics noise estimation.
        No dependence on initial silence — works when signal starts immediately.
        """
        n = len(audio)
        output = np.zeros(n)
        window = np.hanning(frame_size)
        window_sum = np.zeros(n)
        
        num_bins = frame_size // 2 + 1
        
        # Two-pass approach:
        # Pass 1: estimate noise using minimum statistics
        num_frames = (n - frame_size) // hop + 1
        noise_est = MinimumStatisticsNoiseEstimator(
            frame_size=frame_size,
            num_bins=num_bins,
            num_frames_tracking=80,
            bias=1.2
        )
        
        # First pass: just update noise estimator
        for i in range(num_frames):
            start = i * hop
            frame = audio[start:start + frame_size]
            windowed = frame * window
            mag = np.abs(np.fft.rfft(windowed))
            noise_est.update(mag)
        
        noise_spectrum = noise_est.noise_spectrum
        
        # Second pass: apply spectral subtraction
        for i in range(num_frames):
            start = i * hop
            frame = audio[start:start + frame_size]
            windowed = frame * window
            spectrum = np.fft.rfft(windowed)
            mag = np.abs(spectrum)
            phase = np.angle(spectrum)
            
            # Spectral subtraction with adaptive over-subtraction
            cleaned = mag ** 2 - over_subtraction * noise_spectrum ** 2
            cleaned = np.maximum(cleaned, spectral_floor * noise_spectrum ** 2)
            cleaned = np.sqrt(cleaned)
            
            # Wiener-style gain: soft transition
            wiener_gain = cleaned / (mag + 1e-10)
            wiener_gain = np.clip(wiener_gain, spectral_floor, 1.0)
            cleaned = mag * wiener_gain
            
            cleaned_spectrum = cleaned * np.exp(1j * phase)
            reconstructed = np.fft.irfft(cleaned_spectrum, frame_size)
            output[start:start + frame_size] += reconstructed * window
            window_sum[start:start + frame_size] += window ** 2
        
        # Normalize overlap-add
        window_sum = np.maximum(window_sum, 1e-8)
        output /= window_sum
        
        return output
    
    # ------------------------------------------------------------------
    #  Adaptive Dynamic Range Compression
    # ------------------------------------------------------------------
    def _compress_adaptive(self, audio, ratio=4.0, attack_ms=10, release_ms=100,
                           rms_window_sec=0.5):
        """
        Dynamic range compression with adaptive threshold.
        Threshold is set at (signal RMS over a window) - 6dB.
        """
        n = len(audio)
        
        # Estimate signal RMS over a rolling window
        window_samples = int(self.fs * rms_window_sec)
        window_samples = max(window_samples, 1)
        
        # Compute rolling RMS using cumulative sum
        squared = audio ** 2
        cumsum = np.cumsum(np.concatenate(([0.0], squared)))
        
        # RMS for each sample: mean of last window_samples
        # For the start where we don't have a full window, use available samples
        rms_signal = np.zeros(n)
        for i in range(n):
            start_idx = max(0, i - window_samples + 1)
            count = i - start_idx + 1
            rms_signal[i] = np.sqrt((cumsum[i + 1] - cumsum[start_idx]) / count)
        
        # Median RMS as the overall signal level estimate
        median_rms = np.median(rms_signal) + 1e-10
        median_rms_db = 20.0 * np.log10(median_rms)
        
        # Adaptive threshold: median RMS - 6dB (but not below -50dB)
        threshold_db = max(median_rms_db - 6.0, -50.0)
        threshold = 10.0 ** (threshold_db / 20.0)
        
        # Sample-by-sample compression with smoothing
        attack_coeff = np.exp(-1.0 / (self.fs * attack_ms / 1000.0))
        release_coeff = np.exp(-1.0 / (self.fs * release_ms / 1000.0))
        
        output = np.zeros(n)
        gain = 1.0
        
        for i in range(n):
            input_level = abs(audio[i])
            
            if input_level > threshold:
                target_gain = (threshold / (input_level + 1e-10)) ** (1.0 - 1.0 / ratio)
            else:
                target_gain = 1.0
            
            # Smooth gain with attack/release
            if target_gain < gain:
                gain = attack_coeff * gain + (1.0 - attack_coeff) * target_gain
            else:
                gain = release_coeff * gain + (1.0 - release_coeff) * target_gain
            
            output[i] = audio[i] * gain
        
        return output
    
    # ------------------------------------------------------------------
    #  Legacy methods (kept for backward compatibility)
    # ------------------------------------------------------------------
    def _spectral_gate(self, audio, frame_size=256, hop=128):
        """Legacy spectral gate — kept for reference but not used in new pipeline."""
        n = len(audio)
        output = np.zeros(n)
        
        if len(audio) < frame_size:
            return audio
        
        for i in range(0, n - frame_size, hop):
            frame = audio[i:i+frame_size]
            windowed = frame * np.hanning(frame_size)
            spectrum = np.fft.rfft(windowed)
            magnitude = np.abs(spectrum)
            phase = np.angle(spectrum)
            
            frame_max_db = 20 * np.log10(np.max(magnitude) + 1e-10)
            threshold_db = max(self.noise_floor_db, frame_max_db + self.noise_gate_db)
            threshold_linear = 10 ** (threshold_db / 20)
            
            ramp = np.clip((magnitude - threshold_linear) / (threshold_linear * 0.5 + 1e-10), 0, 1)
            gated = magnitude * ramp
            
            gated_spectrum = gated * np.exp(1j * phase)
            reconstructed = np.fft.irfft(gated_spectrum, frame_size)
            output[i:i+frame_size] += reconstructed * np.hanning(frame_size)
        
        return output
    
    def _spectral_subtraction(self, audio, frame_size=512, hop=256,
                              over_subtraction=1.5, spectral_floor=0.01):
        """Legacy spectral subtraction — kept for reference but not used in new pipeline."""
        n = len(audio)
        output = np.zeros(n)
        
        noise_len = min(int(self.fs * 0.2), len(audio) // 4)
        if noise_len < frame_size:
            return audio
        
        noise_frames = []
        for i in range(0, noise_len - frame_size, hop):
            frame = audio[i:i+frame_size] * np.hanning(frame_size)
            noise_frames.append(np.abs(np.fft.rfft(frame)))
        
        if noise_frames:
            noise_spectrum = np.mean(noise_frames, axis=0)
        else:
            return audio
        
        for i in range(0, n - frame_size, hop):
            frame = audio[i:i+frame_size]
            windowed = frame * np.hanning(frame_size)
            spectrum = np.fft.rfft(windowed)
            mag = np.abs(spectrum)
            phase = np.angle(spectrum)
            
            cleaned = mag**2 - over_subtraction * noise_spectrum**2
            cleaned = np.maximum(cleaned, spectral_floor * noise_spectrum**2)
            cleaned = np.sqrt(cleaned)
            
            cleaned_spectrum = cleaned * np.exp(1j * phase)
            reconstructed = np.fft.irfft(cleaned_spectrum, frame_size)
            output[i:i+frame_size] += reconstructed * np.hanning(frame_size)
        
        return output
    
    def _compress(self, audio, threshold_db=-20, ratio=4.0, attack_ms=10, release_ms=100):
        """Legacy compressor — kept for backward compat, not used in new pipeline."""
        n = len(audio)
        attack_coeff = np.exp(-1.0 / (self.fs * attack_ms / 1000))
        release_coeff = np.exp(-1.0 / (self.fs * release_ms / 1000))
        threshold = 10 ** (threshold_db / 20)
        
        output = np.zeros(n)
        gain = 1.0
        
        for i in range(n):
            input_level = abs(audio[i])
            
            if input_level > threshold:
                target_gain = threshold / (input_level + 1e-10)
                target_gain = target_gain ** (1 - 1/ratio)
            else:
                target_gain = 1.0
            
            if target_gain < gain:
                gain = attack_coeff * gain + (1 - attack_coeff) * target_gain
            else:
                gain = release_coeff * gain + (1 - release_coeff) * target_gain
            
            output[i] = audio[i] * gain
        
        return output
    
    # ------------------------------------------------------------------
    #  Shared utilities
    # ------------------------------------------------------------------
    def _normalize(self, audio, target_db=-1.0):
        """Peak normalize to target dB."""
        peak = np.max(np.abs(audio))
        if peak < 1e-10:
            return audio
        target_linear = 10 ** (target_db / 20)
        return audio * (target_linear / peak)
    
    def _save_processed(self, audio, label):
        """Save processed audio as WAV file."""
        self.file_counter += 1
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_label = "".join(c for c in label if c.isalnum() or c in ('_', '-'))[:30]
        filename = f"{timestamp}_{self.file_counter:04d}_{safe_label}_processed.wav"
        filepath = os.path.join(self.output_dir, filename)
        
        audio_int16 = np.clip(audio * 32767, -32768, 32767).astype(np.int16)
        wavfile.write(filepath, self.fs, audio_int16)
        return filepath
    
    def _save_raw(self, audio, label):
        """Save raw (unprocessed) audio as WAV fallback."""
        self.file_counter += 1
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_label = "".join(c for c in label if c.isalnum() or c in ('_', '-'))[:30]
        filename = f"{timestamp}_{self.file_counter:04d}_{safe_label}_raw.wav"
        filepath = os.path.join(self.output_dir, filename)
        
        audio_int16 = np.clip(np.asarray(audio, dtype=np.float64) * 32767, -32768, 32767).astype(np.int16)
        wavfile.write(filepath, self.fs, audio_int16)
        return filepath
    
    def get_stats(self):
        """Return processing statistics."""
        return {
            'files_processed': self.processed_count,
            'file_counter': self.file_counter,
            'noise_floor_db': self.noise_floor_db,
            'output_dir': self.output_dir
        }


class VoiceDemodChain:
    """
    Integrates AIC demod with sound engineer for complete voice recovery.
    Bridges the TSCM detection output to clean voice files.
    
    Backward-compatible: existing process_audio(), feed_demod(), flush()
    interfaces still work. New: process_for_playback() for live streaming.
    """
    
    def __init__(self, sample_rate=8000, output_dir="demod_audio"):
        self.fs = sample_rate
        self.engineer = AISoundEngineer(
            output_dir=output_dir,
            sample_rate=sample_rate,
            noise_gate_db=-35,
            presence_boost_db=4,
            presence_freq=(2000, 4500)
        )
        self.voice_buffer = deque(maxlen=sample_rate * 10)
        self.last_voice_time = 0
        self.min_clip_length = sample_rate * 0.5
        self.log = logging.getLogger(__name__)
    
    def feed_demod(self, audio_chunk, label="aic_demod", source_hw="RF",
                   freq=None, detector_type=None):
        """
        Feed demodulated audio from AIC or other source.
        Accumulates into buffer and processes when enough audio collected.
        """
        if audio_chunk is None or len(audio_chunk) < 100:
            return None
        
        rms = np.sqrt(np.mean(np.asarray(audio_chunk, dtype=np.float64) ** 2))
        if rms < 0.001:
            return None
        
        self.voice_buffer.extend(np.asarray(audio_chunk, dtype=np.float64).flatten())
        self.last_voice_time = time.time()
        
        return None
    
    def flush(self, label="voice_clip", source_hw="RF", freq=None,
              detector_type=None):
        """
        Flush the voice buffer, process through sound engineer, save.
        Call this periodically or when a detection event triggers.
        """
        if len(self.voice_buffer) < self.min_clip_length:
            return None
        
        audio = np.array(self.voice_buffer)
        self.voice_buffer.clear()
        
        result = self.engineer.process_audio(
            audio, label=label,
            source_hw=source_hw,
            freq=freq,
            detector_type=detector_type
        )
        
        if result:
            self.log.info(f"[VoiceDemod] Saved voice clip: {result['output_path']} "
                         f"({result['duration_sec']:.1f}s)")
        
        return result
    
    def process_for_playback(self, audio_data):
        """
        Process audio for live streaming. Delegates to the sound engineer.
        Returns float32 clipped to [-1, 1] or None.
        """
        return self.engineer.process_for_playback(audio_data)
    
    def get_stats(self):
        """Get combined stats."""
        stats = self.engineer.get_stats()
        stats['buffer_samples'] = len(self.voice_buffer)
        stats['buffer_seconds'] = len(self.voice_buffer) / self.fs
        stats['last_voice_time'] = self.last_voice_time
        return stats


# Integration helper for TSCM script
def create_sound_engineer(output_dir="demod_audio"):
    """Create and return a VoiceDemodChain ready for use."""
    return VoiceDemodChain(
        sample_rate=8000,
        output_dir=output_dir
    )


if __name__ == "__main__":
    # Self-test: generate a test tone, process it, verify output
    import tempfile
    
    print("Testing AI Sound Engineer v2...")
    
    fs = 8000
    duration = 3.0
    t = np.linspace(0, duration, int(fs * duration))
    
    # Generate voice-like signal: fundamental + harmonics + noise
    fundamental = 0.3 * np.sin(2 * np.pi * 200 * t)
    harmonics = 0.15 * np.sin(2 * np.pi * 400 * t) + 0.1 * np.sin(2 * np.pi * 600 * t)
    noise = 0.02 * np.random.randn(len(t))
    
    # Add carrier artifact (simulating ultrasonic demod residue)
    carrier = 0.05 * np.sin(2 * np.pi * 19500 * t)
    
    # Add 60Hz hum
    hum = 0.03 * np.sin(2 * np.pi * 60 * t) + 0.015 * np.sin(2 * np.pi * 120 * t)
    
    test_signal = fundamental + harmonics + noise + carrier + hum
    
    with tempfile.TemporaryDirectory() as tmpdir:
        engineer = AISoundEngineer(output_dir=tmpdir, sample_rate=fs)
        result = engineer.process_audio(test_signal, label="test_voice", source_hw="RF")
        
        if result:
            print(f"  Output: {result['output_path']}")
            print(f"  Duration: {result['duration_sec']:.1f}s")
            print(f"  Peak: {result['peak_db']:.1f} dB")
            print(f"  RMS: {result['rms_db']:.1f} dB")
            print(f"  File exists: {os.path.exists(result['output_path'])}")
            
            try:
                read_rate, read_data = wavfile.read(result['output_path'])
                print(f"  WAV valid: rate={read_rate}, samples={len(read_data)}, dtype={read_data.dtype}")
            except Exception as e:
                print(f"  WAV read error: {e}")
            
            print("PASS - Sound Engineer working!")
        else:
            print("FAIL - processing returned None")
    
    # Test process_for_playback
    print("\nTesting process_for_playback()...")
    playback_audio = engineer.process_for_playback(test_signal)
    if playback_audio is not None:
        print(f"  Output dtype: {playback_audio.dtype}")
        print(f"  Output shape: {playback_audio.shape}")
        print(f"  Min/Max: [{playback_audio.min():.4f}, {playback_audio.max():.4f}]")
        print(f"  Clipped to [-1,1]: {playback_audio.min() >= -1.0 and playback_audio.max() <= 1.0}")
        print("PASS - process_for_playback working!")
    else:
        print("FAIL - process_for_playback returned None")
    
    # Test VoiceDemodChain
    print("\nTesting VoiceDemodChain...")
    chain = VoiceDemodChain(sample_rate=fs, output_dir=tmpdir)
    
    chunk_size = fs // 2
    for i in range(0, len(test_signal), chunk_size):
        chunk = test_signal[i:i+chunk_size]
        chain.feed_demod(chunk, label="chain_test")
    
    result = chain.flush(label="chain_test_voice")
    if result:
        print(f"  Chain output: {result['output_path']}")
        print("PASS - VoiceDemodChain working!")
    else:
        print("  Chain output: None (buffer too short or too quiet)")
    
    # Test VAD
    print("\nTesting Voice Activity Detection...")
    vad = VoiceActivityDetector(fs, frame_size=256, hop=128)
    
    # Create test signal with silence + voice + silence
    silence1 = np.zeros(int(fs * 0.5))
    voice = 0.3 * np.sin(2 * np.pi * 200 * t[:int(fs * 1.5)])
    silence2 = np.zeros(int(fs * 0.5))
    vad_signal = np.concatenate([silence1, voice, silence2])
    
    mask, n_frames, hop_size = vad.detect(vad_signal)
    voice_ratio = np.mean(mask)
    print(f"  Voice frames: {np.sum(mask)}/{n_frames} ({voice_ratio:.1%})")
    print(f"  Expected ~75% voice (1.5s voice out of 2.5s total)")
    
    if 0.5 < voice_ratio < 0.95:
        print("PASS - VAD working!")
    else:
        print("WARN - VAD ratio outside expected range")
    
    # Test biquad helpers
    print("\nTesting biquad filter design...")
    peaking = _biquad_peaking_sos(3000, 4.0, 1.5, fs)
    print(f"  Peaking EQ SOS shape: {peaking.shape}")
    notch = _notch_sos(60, 30, fs)
    print(f"  Notch SOS shape: {notch.shape}")
    print("PASS - biquad filters designed!")
    
    print("\nAll tests complete!")
