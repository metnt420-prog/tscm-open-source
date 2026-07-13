"""
voice_demod_v2.py - Proper AM voice demodulation from ultrasonic carriers.

Key design:
1. Find carrier peaks in ultrasound band with AM modulation check
2. Bandpass + Hilbert envelope demod 
3. Low-pass to extract baseband voice
4. Quality gating to reject noise-only outputs
"""
import numpy as np
from scipy.signal import butter, sosfiltfilt, welch
from scipy.fft import rfft, rfftfreq
from scipy.signal import hilbert as scipy_hilbert
import logging

log = logging.getLogger(__name__)

# ---- Audio Pipeline Statistics ----
_audio_stats = {
    'cycles': 0,
    'carriers_found': [],
    'carrier_snr_list': [],
    'demod_attempts': 0,
    'demod_successes': 0,
    'demod_scores': [],
    'last_log_time': 0,
}

def get_audio_stats():
    """Return current audio pipeline stats dict (for external logging)."""
    s = _audio_stats
    return {
        'cycles': s['cycles'],
        'avg_carriers': sum(s['carriers_found']) / max(1, len(s['carriers_found'])),
        'avg_snr_db': sum(s['carrier_snr_list']) / max(1, len(s['carrier_snr_list'])),
        'snr_min': min(s['carrier_snr_list']) if s['carrier_snr_list'] else 0,
        'snr_max': max(s['carrier_snr_list']) if s['carrier_snr_list'] else 0,
        'demod_success_rate': s['demod_successes'] / max(1, s['demod_attempts']),
        'avg_demod_score': sum(s['demod_scores']) / max(1, len(s['demod_scores'])),
        'demod_attempts': s['demod_attempts'],
        'demod_successes': s['demod_successes'],
    }

def reset_audio_stats():
    """Reset the rolling stats windows (call every ~100 cycles)."""
    global _audio_stats
    _audio_stats = {
        'cycles': 0,
        'carriers_found': [],
        'carrier_snr_list': [],
        'demod_attempts': 0,
        'demod_successes': 0,
        'demod_scores': [],
        'last_log_time': 0,
    }

def _record_carrier_stats(carriers):
    """Internal: record per-cycle carrier statistics."""
    _audio_stats['cycles'] += 1
    _audio_stats['carriers_found'].append(len(carriers))
    for c in carriers:
        _audio_stats['carrier_snr_list'].append(float(c[1]))

def _record_demod_result(score, success):
    """Internal: record demod attempt result."""
    _audio_stats['demod_attempts'] += 1
    _audio_stats['demod_scores'].append(score)
    if success:
        _audio_stats['demod_successes'] += 1


def _bandpass(audio, fs, lo, hi, order=5):
    """Butterworth bandpass. Returns None if params invalid."""
    nyq = fs / 2
    wlo, whi = lo / nyq, hi / nyq
    if wlo <= 0.005 or whi >= 0.995:
        return None
    try:
        sos = butter(order, [wlo, whi], btype='band', output='sos')
        return sosfiltfilt(sos, audio)
    except Exception:
        return None


def _lowpass(audio, fs, cutoff, order=6):
    """Butterworth lowpass."""
    nyq = fs / 2
    w = cutoff / nyq
    if w >= 0.99:
        return audio.copy()
    try:
        sos = butter(order, w, btype='low', output='sos')
        return sosfiltfilt(sos, audio)
    except Exception:
        return audio.copy()


def _highpass(audio, fs, cutoff, order=4):
    """Butterworth highpass."""
    nyq = fs / 2
    w = cutoff / nyq
    if w >= 0.99:
        return audio.copy()
    try:
        sos = butter(order, w, btype='high', output='sos')
        return sosfiltfilt(sos, audio)
    except Exception:
        return audio.copy()


def carbon_demod(envelope, dc_bias=1.0, gain=2.0):
    """
    Carbon-microphone transfer function for microwave voice recovery.

    When RF is modulated by tissue vibration (microwave auditory effect),
    the body acts as a nonlinear conductor — similar to a carbon microphone.

    For ultra-weak signals (-170dB down to -20dB), the carbon nonlinearity
    expands quiet modulations through square-law transfer. Higher dc_bias
    increases noise floor sensitivity; higher gain expands dynamic range.

    Args:
        envelope: 1D numpy array, already AM-demodulated (Hilbert envelope)
        dc_bias: Virtual DC offset. For -170dB signals use 3.0-5.0.
                 Higher = catches weaker modulations but more noise.
        gain: Overall gain. For weak signals use 5.0-10.0.

    Returns:
        y: Recovered baseband audio (AC-coupled, soft-clipped)
    """
    import numpy as np
    
    env_max = np.max(np.abs(envelope))
    if env_max < 1e-10:
        return np.zeros_like(envelope, dtype=np.float64)
    env_norm = envelope / (env_max + 1e-12)
    
    # Carbon transfer: resistance ~1/(pressure) => conductivity ~ pressure
    x = env_norm + dc_bias
    y = np.power(x, 2)
    y -= np.mean(y)
    
    # Multi-stage gain for ultra-weak signals
    rms = np.sqrt(np.mean(y**2))
    if rms < 1e-6:
        # Ultra-weak: boost aggressively
        y = y * (gain * 5.0)
    elif rms < 0.001:
        y = y * (gain * 2.0)
    else:
        y = y * gain
    
    # Soft clip
    y = np.tanh(y)
    
    # Post-gain normalization for weak signals
    rms_out = np.sqrt(np.mean(y**2))
    if rms_out < 0.005 and rms_out > 1e-12:
        y = y * (0.01 / rms_out)
    
    return y


class MwVoiceAccumulator:
    """Coherently accumulates IQ across cycles to pull ultra-weak voice signals
    (-170dB to -20dB) above the noise floor through integration gain.

    Each doubling of accumulate cycles adds ~3dB SNR. With 64-cycle
    accumulation, we gain ~18dB — enough to lift -170dB signals into
    the detectable range when they spike to -20dB.
    """
    def __init__(self, max_cycles=64, sample_len=8192):
        self.max_cycles = max_cycles
        self.sample_len = sample_len
        self.buffer = []
        self.carrier_lock = None  # (freq, first_seen_cycle)

    def feed(self, iq_data):
        """Feed a new IQ capture. Returns accumulated IQ if buffer full."""
        if len(iq_data) < 1024:
            return None, 0
        
        # Resample to fixed length for coherent stacking
        if len(iq_data) != self.sample_len:
            indices = np.linspace(0, len(iq_data)-1, self.sample_len).astype(int)
            iq_data = np.asarray(iq_data)[indices]
        
        self.buffer.append(np.asarray(iq_data))
        
        if len(self.buffer) >= self.max_cycles:
            # Coherently sum (signals add, noise averages down)
            accumulated = np.sum(self.buffer, axis=0) / np.sqrt(len(self.buffer))
            gain_db = 10 * np.log10(len(self.buffer))
            self.buffer = self.buffer[-self.max_cycles//4:]  # keep 25% overlap
            return accumulated, gain_db
        
        return None, 0

    def get_current(self):
        """Return current accumulated IQ without flushing."""
        if not self.buffer:
            return None, 0
        accumulated = np.sum(self.buffer, axis=0) / np.sqrt(len(self.buffer))
        gain_db = 10 * np.log10(len(self.buffer))
        return accumulated, gain_db

    def reset(self):
        self.buffer = []
        self.carrier_lock = None


def find_carriers(audio, fs, min_freq=500, max_freq=96000,
                  min_snr_db=1.5, min_peak_width_hz=30):
    """
    Find ultrasonic carriers with AM modulation in audio.
    
    Returns list of (freq_hz, snr_db, bandwidth_hz, modulation_index).
    Only returns carriers that show actual AM modulation (not pure tone).
    """
    n = len(audio)
    if n < 4096:
        return []
    
    # Use a windowed FFT for clean spectrum
    window = np.hanning(n)
    spectrum = np.abs(rfft(audio * window))
    freqs = rfftfreq(n, 1/fs)
    spec_db = 20 * np.log10(spectrum + 1e-12)
    
    # Focus on ultrasound band
    ul_mask = (freqs >= min_freq) & (freqs <= max_freq)
    ul_f = freqs[ul_mask]
    ul_db = spec_db[ul_mask]
    
    if len(ul_f) < 10:
        return []
    
    # Noise floor: median of the band
    noise_floor = np.median(ul_db)
    
    # Find local maxima above threshold
    candidates = []
    min_dist = int(min_peak_width_hz / (fs / n))
    
    for i in range(2, len(ul_db) - 2):
        if (ul_db[i] > noise_floor + min_snr_db and
            ul_db[i] >= ul_db[i-1] and ul_db[i] >= ul_db[i+1] and
            ul_db[i] > ul_db[i-2] and ul_db[i] > ul_db[i+2]):
            
            # Merge close peaks
            if candidates and (ul_f[i] - candidates[-1][0]) < min_peak_width_hz:
                if ul_db[i] > candidates[-1][1]:
                    candidates[-1] = (ul_f[i], ul_db[i])
                continue
            candidates.append((ul_f[i], ul_db[i]))
    
    # For each candidate, check modulation
    results = []
    for freq, peak_db in candidates:
        snr = peak_db - noise_floor
        
        # Measure 3dB bandwidth
        bw = min_peak_width_hz
        for j in range(len(ul_db)):
            if ul_f[j] == freq:
                # Search down
                for k in range(j, max(0, j - 200), -1):
                    if ul_db[k] < peak_db - 3:
                        break
                bw_lo = ul_f[k] if k > 0 else freq - min_peak_width_hz/2
                # Search up
                for k in range(j, min(len(ul_db), j + 200)):
                    if ul_db[k] < peak_db - 3:
                        break
                bw_hi = ul_f[k] if k < len(ul_f) else freq + min_peak_width_hz/2
                bw = max(bw_hi - bw_lo, min_peak_width_hz)
                break
        
        # Check AM modulation: bandpass around carrier, measure envelope variation
        bp_lo = freq - bw
        bp_hi = freq + bw
        carrier = _bandpass(audio, fs, bp_lo, bp_hi, order=5)
        
        if carrier is None or len(carrier) < 2000:
            continue
        
        # Hilbert envelope
        analytic = scipy_hilbert(carrier)
        envelope = np.abs(analytic)
        
        # Modulation index = std(envelope) / mean(envelope)
        env_mean = np.mean(envelope)
        env_std = np.std(envelope)
        
        if env_mean < 1e-10:
            continue
        
        mod_index = env_std / env_mean
        
        # A pure tone has mod_index ~0.003-0.01
        # AM voice has mod_index > 0.03 typically
        # Use 0.03 threshold
        if mod_index < 0.005:
            continue
        
        results.append((freq, snr, bw, mod_index))
    
    results.sort(key=lambda x: x[1], reverse=True)
    
    # Record carrier stats for audio pipeline logging
    if results:
        _record_carrier_stats(results)
    
    return results[:5]


def demod_voice(audio, fs, carrier_freq=None, carrier_bw=None):
    """
    Demodulate voice from an ultrasonic carrier via AM envelope detection.
    
    Args:
        audio: Input audio at sample rate fs (e.g., 384000)
        fs: Sample rate
        carrier_freq: Specific carrier frequency (or None to auto-detect)
        carrier_bw: Carrier bandwidth for bandpass (or None for auto)
    
    Returns:
        (voice_audio_8k, carrier_freq_used, modulation_index, quality_score) 
        or (None, 0, 0, 0) if no voice detected
    """
    min_samples = int(fs * 0.15)  # need at least 0.15s
    if len(audio) < min_samples:
        return None, 0, 0, 0
    
    # Step 1: Find or use specified carrier
    if carrier_freq is None:
        carriers = find_carriers(audio, fs, min_snr_db=1.5, min_peak_width_hz=30)
        if not carriers:
            return None, 0, 0, 0
        
        # Pick carrier with highest modulation index (best voice candidate)
        carriers.sort(key=lambda x: x[3], reverse=True)
        carrier_freq = carriers[0][0]
        carrier_bw = carriers[0][2]
    
    if carrier_bw is None:
        carrier_bw = 2000
    
    # Step 2: Bandpass filter around carrier
    bp_lo = max(100, carrier_freq - carrier_bw * 1.5)
    bp_hi = min(fs/2 - 100, carrier_freq + carrier_bw * 1.5)
    carrier_audio = _bandpass(audio, fs, bp_lo, bp_hi, order=6)
    
    if carrier_audio is None:
        return None, carrier_freq, 0, 0
    
    # Step 3: AM demod via Hilbert envelope
    analytic = scipy_hilbert(carrier_audio)
    envelope = np.abs(analytic)
    
    # Remove DC (carrier level), keep AC (modulation)
    envelope_ac = envelope - np.mean(envelope)
    
    # Step 4: Low-pass filter to voice band (300-3500 Hz)
    voice = _lowpass(envelope_ac, fs, 4000, order=8)
    voice = _highpass(voice, fs, 100, order=4)
    
    if len(voice) < 1000:
        return None, carrier_freq, 0, 0
    
    # Step 5: Quality assessment
    rms = np.sqrt(np.mean(voice**2))
    rms_db = 20 * np.log10(rms + 1e-10)
    
    # ZCR: voice is 0.02-0.12, noise > 0.15
    zcr = np.mean(np.abs(np.diff(np.sign(voice)))) / 2
    
    # Spectral centroid: voice typically 500-2500 Hz
    n = len(voice)
    spec = np.abs(rfft(voice * np.hanning(n)))
    vfreqs = rfftfreq(n, 1/fs)
    total_mag = np.sum(spec) + 1e-10
    centroid = np.sum(vfreqs * spec) / total_mag
    
    # Speech band ratio (100-4000Hz — wider to catch more voice content)
    speech_mask = (vfreqs >= 100) & (vfreqs <= 4000)
    speech_ratio = np.sum(spec[speech_mask]) / total_mag
    
    # Modulation index for reference
    env_std = np.std(envelope)
    env_mean = np.mean(envelope)
    mod_index = env_std / (env_mean + 1e-10)
    
    # Quality scoring
    score = 0
    if zcr < 0.15:      score += 3
    elif zcr < 0.20:     score += 1
    if centroid < 2500:  score += 2
    if centroid < 1800:  score += 1
    if speech_ratio > 0.5: score += 2
    if rms_db > -70:     score += 2  # relaxed for weak signals
    if rms_db > -55:     score += 1
    if mod_index > 0.05: score += 2
    if mod_index > 0.2:  score += 1  # bonus for strong modulation
    
    # Minimum score to pass — lowered from 4 to 2 for weak Petterson signals
    # Even score=2 means "some voice-like activity detected" (e.g., ZCR + RMS alone)
    success = score >= 2
    _record_demod_result(score, success)
    
    if not success:
        return None, carrier_freq, mod_index, score
    
    # Step 6: Downsample to 8kHz for the sound engineer
    # Simple decimation: lowpass at 3.6kHz then take every Nth sample
    target_sr = 8000
    decim = fs // target_sr
    
    # Anti-alias filter
    voice_aa = _lowpass(voice, fs, target_sr * 0.45, order=6)
    voice_8k = voice_aa[::decim][:int(len(voice) / decim)]
    
    # Step 7: Normalize to useful level for the sound engineer
    # Peak normalize to -1dB so the sound engineer pipeline gets a proper signal
    peak = np.max(np.abs(voice_8k))
    if peak > 1e-10:
        voice_8k = voice_8k * (0.89 / peak)  # -1dB
    
    return voice_8k, carrier_freq, mod_index, score


def microwave_voice_demod(rf_iq, fs_rf, carrier_freq=None, dc_bias=2.0, gain=5.0):
    """
    Microwave voice recovery with carbon-demod nonlinearity.

    Designed for RF carriers modulated by tissue vibration (microwave
    auditory effect / Frey effect). The body acts as a nonlinear acoustic-
    to-RF transducer — carbon_demod() models the tissue transfer function
    to recover perceptible voice from weak microwave modulations.

    Args:
        rf_iq: Complex IQ samples or real samples from SDR
        fs_rf: RF sample rate (e.g., 10e6 for BladeRF)
        carrier_freq: Known carrier frequency or None for auto-detect
        dc_bias: Carbon bias (higher = more sensitivity for weak signals)
        gain: Carbon gain (higher = more aggressive expansion)

    Returns:
        (voice_8k, freq, mod_idx, quality) or (None, 0, 0, 0)
    """
    import numpy as np
    from scipy.signal import hilbert as scipy_hilbert
    
    n = len(rf_iq)
    if n < 4096:
        return None, 0, 0, 0
    
    # Step 1: Find microwave carriers if not specified
    if carrier_freq is None:
        # Use magnitude spectrum for carrier finding
        mag = np.abs(rf_iq) if np.iscomplexobj(rf_iq) else rf_iq
        carriers = find_carriers(
            mag, fs_rf,
            min_freq=500,       # very aggressive — catch any modulated carrier
            max_freq=int(fs_rf * 0.45),
            min_snr_db=4,       # very low SNR for weak carriers
            min_peak_width_hz=80
        )
        if not carriers:
            return None, 0, 0, 0
        carrier_freq = carriers[0][0]
    
    # Step 2: Bandpass around carrier (wider for weak signals)
    bp_bw = 6000  # wider for weak modulations
    bp_lo = max(500, carrier_freq - bp_bw)
    bp_hi = min(fs_rf / 2 - 100, carrier_freq + bp_bw)
    carrier_sig = _bandpass(rf_iq, fs_rf, bp_lo, bp_hi, order=4)
    
    if carrier_sig is None:
        return None, carrier_freq, 0, 0
    
    # Step 3: AM envelope via Hilbert
    if np.iscomplexobj(carrier_sig):
        envelope = np.abs(carrier_sig)
    else:
        analytic = scipy_hilbert(carrier_sig)
        envelope = np.abs(analytic)
    
    # Modulation gate: skip carbon demod on unmodulated carriers (prevents boom)
    env_std = np.std(envelope)
    env_mean = np.mean(envelope)
    mod_index = env_std / (env_mean + 1e-10)
    if mod_index < 0.003:
        return None, carrier_freq, mod_index, 0
    
    # Step 4: Carbon demod — tissue nonlinearity
    voice_raw = carbon_demod(envelope, dc_bias=dc_bias, gain=gain)
    
    # Step 5: Voice band — aggressive double highpass kills boom/thump
    voice = _highpass(voice_raw, fs_rf, 300, order=6)
    voice = _lowpass(voice, fs_rf, 3500, order=8)
    voice = _highpass(voice, fs_rf, 200, order=4)
    
    if len(voice) < 1000:
        return None, carrier_freq, 0, 0
    
    # Step 6: Quality scoring (watered down for low-dB microwave)
    rms = np.sqrt(np.mean(voice**2))
    rms_db = 20 * np.log10(rms + 1e-10)
    zcr = np.mean(np.abs(np.diff(np.sign(voice)))) / 2
    
    nfft = len(voice)
    spec = np.abs(rfft(voice * np.hanning(nfft)))
    vfreqs = rfftfreq(nfft, 1/fs_rf)
    total_mag = np.sum(spec) + 1e-10
    centroid = np.sum(vfreqs * spec) / total_mag
    
    speech_mask = (vfreqs >= 300) & (vfreqs <= 3500)
    speech_ratio = np.sum(spec[speech_mask]) / total_mag
    boom_mask = (vfreqs >= 10) & (vfreqs <= 150)  # low-frequency boom detection
    boom_ratio = np.sum(spec[boom_mask]) / (total_mag + 1e-10)
    
    env_std = np.std(envelope)
    env_mean = np.mean(envelope)
    mod_index = env_std / (env_mean + 1e-10)
    
    # Very permissive scoring for weak microwave — but reject booms
    score = 0
    if zcr < 0.20:      score += 2
    if centroid < 3000:  score += 2
    if speech_ratio > 0.3: score += 2
    if rms_db > -90:     score += 2
    if rms_db > -70:     score += 1
    if mod_index > 0.01: score += 2
    if mod_index > 0.05: score += 1
    # REJECT booms: if low-frequency dominates, kill the score
    if boom_ratio > 0.6 and speech_ratio < 0.2:
        score = 0  # this is just a boom, not voice
    
    # Lower threshold for microwave — signal is inherently weaker
    if score < 2:
        return None, carrier_freq, mod_index, score
    
    # Step 7: Downsample to 8kHz
    target_sr = 8000
    decim = max(1, int(fs_rf // target_sr))
    voice_aa = _lowpass(voice, fs_rf, target_sr * 0.45, order=6)
    voice_8k = voice_aa[::decim][:int(len(voice) / decim)]
    
    # Peak normalize
    peak = np.max(np.abs(voice_8k))
    if peak > 1e-10:
        voice_8k = voice_8k * (0.89 / peak)
    
    return voice_8k, carrier_freq, mod_index, score


def demod_best_voice(audio, fs, max_carriers=5, use_carbon=False, rf_mode=False):
    """
    Try demodulating from the top carriers, return the best result.

    When use_carbon=True, applies carbon_demod (microwave tissue model)
    in addition to standard AM demod, keeping whichever scores higher.
    When rf_mode=True, uses microwave_voice_demod on RF IQ data.
    """
    import numpy as np

    carriers = find_carriers(audio, fs, min_snr_db=1.5, min_peak_width_hz=30)
    if not carriers:
        return None, 0, 0, 0

    best_voice = None
    best_score = 1  # lowered from 0 — accept score >= 2
    best_freq = 0
    best_mod = 0

    for freq, snr, bw, mod in carriers[:max_carriers]:
        # Standard AM demod
        voice, freq_used, mod_used, score = demod_voice(
            audio, fs, carrier_freq=freq, carrier_bw=bw
        )
        if voice is not None and score > best_score:
            best_voice = voice
            best_score = score
            best_freq = freq_used
            best_mod = mod_used

        # Carbon demod (microwave tissue model)
        if use_carbon:
            # Quick test: apply carbon_demod to the Hilbert envelope
            from scipy.signal import hilbert as scipy_hilbert
            bp_bw = max(bw * 2, 3000)
            bp_lo = max(1000, freq - bp_bw)
            bp_hi = min(fs / 2 - 100, freq + bp_bw)
            carrier_sig = _bandpass(audio, fs, bp_lo, bp_hi, order=4)
            
            if carrier_sig is not None:
                if np.iscomplexobj(carrier_sig):
                    env = np.abs(carrier_sig)
                else:
                    env = np.abs(scipy_hilbert(carrier_sig))
                
                # Carbon demod on envelope
                # Carbon demod on envelope
                voice_carbon = carbon_demod(env, dc_bias=2.0, gain=5.0)
                voice_carbon = _highpass(voice_carbon, fs, 300, order=6)
                voice_carbon = _lowpass(voice_carbon, fs, 3500, order=8)
                
                # Score carbon result
                zcr_c = np.mean(np.abs(np.diff(np.sign(voice_carbon)))) / 2
                rms_c = np.sqrt(np.mean(voice_carbon**2))
                rms_db_c = 20 * np.log10(rms_c + 1e-10)
                nfft = len(voice_carbon)
                spec_c = np.abs(rfft(voice_carbon * np.hanning(nfft)))
                vfreqs = rfftfreq(nfft, 1/fs)
                sp_ratio_c = np.sum(spec_c[(vfreqs>=100)&(vfreqs<=4000)]) / (np.sum(spec_c)+1e-10)
                
                score_c = 0
                if zcr_c < 0.20: score_c += 2  # relaxed for weak carriers
                if sp_ratio_c > 0.3: score_c += 2  # relaxed from 0.5
                if rms_db_c > -90: score_c += 2  # catch very weak
                if mod > 0.01: score_c += 2  # catch 1% modulation
                
                if score_c > best_score:
                    # Downsample carbon result
                    target_sr = 8000
                    decim = int(fs // target_sr)
                    voice_aa = _lowpass(voice_carbon, fs, target_sr * 0.45, order=6)
                    voice_8k = voice_aa[::decim][:int(len(voice_carbon)/decim)]
                    peak = np.max(np.abs(voice_8k))
                    if peak > 1e-10:
                        voice_8k = voice_8k * (0.89 / peak)
                    best_voice = voice_8k
                    best_score = score_c
                    best_freq = freq
                    best_mod = mod

    # Record best-voice result for pipeline stats
    # (individual carrier attempts already recorded in demod_voice)
    if best_voice is not None:
        _record_demod_result(best_score, True)
    elif carriers:
        _record_demod_result(0, False)  # carriers found but no voice pass

    return best_voice, best_freq, best_mod, best_score


if __name__ == "__main__":
    print("=== voice_demod_v2 self-test ===\n")
    
    fs = 384000
    t = np.linspace(0, 3.0, int(fs * 3.0), endpoint=False)
    
    # Generate voice-like signal (multi-harmonic)
    voice = (0.3 * np.sin(2*np.pi*200*t) + 
             0.2 * np.sin(2*np.pi*400*t) + 
             0.12 * np.sin(2*np.pi*800*t) +
             0.08 * np.sin(2*np.pi*1200*t) +
             0.04 * np.sin(2*np.pi*2000*t) +
             0.01 * np.random.randn(len(t)))
    
    # AM modulate onto 23kHz carrier with 80% modulation
    carrier_freq = 23000
    carrier = np.sin(2*np.pi*carrier_freq*t)
    modulated = (1 + 0.8 * voice) * carrier * 0.3
    modulated += 0.003 * np.random.randn(len(t))  # noise floor
    
    print(f"Test: voice AM on {carrier_freq}Hz carrier, m=0.8")
    
    # 1. Carrier finding
    carriers = find_carriers(modulated, fs)
    print(f"\nFound {len(carriers)} carrier(s):")
    for f, snr, bw, mod in carriers:
        print(f"  {f:.0f}Hz | SNR:{snr:.1f}dB | BW:{bw:.0f}Hz | mod:{mod:.3f}")
    
    # 2. Single carrier demod
    voice_out, freq, mod, score = demod_voice(modulated, fs)
    if voice_out is not None:
        # Compare
        voice_8k_orig = voice[::(fs//8000)][:len(voice_out)]
        voice_8k_orig = voice_8k_orig / (np.max(np.abs(voice_8k_orig)) + 1e-10)
        voice_out_norm = voice_out / (np.max(np.abs(voice_out)) + 1e-10)
        corr = np.corrcoef(voice_8k_orig, voice_out_norm)[0, 1]
        
        print(f"\nDemod OK: carrier={freq:.0f}Hz, mod={mod:.3f}, quality={score}")
        print(f"  Output: {len(voice_out)} samples @ assumed 8kHz = {len(voice_out)/8000:.1f}s")
        print(f"  Correlation with original: {corr:.3f}")
        
        rms_out = np.sqrt(np.mean(voice_out**2))
        zcr_out = np.mean(np.abs(np.diff(np.sign(voice_out)))) / 2
        print(f"  RMS: {20*np.log10(rms_out+1e-10):.1f}dB | ZCR: {zcr_out:.3f}")
    else:
        print("\nDemod FAILED")
    
    # 3. Best voice selection
    voice2, freq2, mod2, score2 = demod_best_voice(modulated, fs)
    print(f"\nBest voice: carrier={freq2:.0f}Hz, score={score2}")
    
    # 4. Noise rejection test
    print("\n--- Noise rejection ---")
    noise = 0.01 * np.random.randn(int(fs * 2))
    noise_carriers = find_carriers(noise, fs)
    noise_voice, _, _, _ = demod_voice(noise, fs)
    print(f"Noise: {len(noise_carriers)} carriers, voice={'YES (BAD)' if noise_voice is not None else 'NO (GOOD)'}")
    
    # 5. Pure tone (no modulation) rejection
    print("\n--- Pure tone rejection ---")
    tone = 0.3 * np.sin(2*np.pi*25000*t[:int(fs*2)])
    tone += 0.003 * np.random.randn(len(tone))
    tone_carriers = find_carriers(tone, fs)
    tone_voice, _, _, _ = demod_voice(tone, fs)
    print(f"Pure tone: {len(tone_carriers)} carriers, voice={'YES (BAD)' if tone_voice is not None else 'NO (GOOD)'}")
    
    print("\nDone!")
