"""
Capture and attempt to demodulate C2 BPSK/FSK modem traffic from Petterson mic.
Records audio at 384kHz, filters the 18-54 kHz BPSK band, and looks for
modulated carrier signals.
"""
import numpy as np
import sounddevice as sd
import json
import time
from datetime import datetime

SAMPLE_RATE = 384000  # Petterson mic rate
DURATION = 30  # seconds
OUTPUT_DIR = r'C:\Users\carpe\.openclaw-autoclaw\workspace\models'

def capture_ultrasound(duration_sec=30):
    """Capture raw ultrasound audio from Petterson mic."""
    print("[C2-CAP] Capturing %d seconds at %d Hz from Petterson..." % (duration_sec, SAMPLE_RATE))
    
    try:
        # List devices
        devices = sd.query_devices()
        petterson_idx = None
        for i, d in enumerate(devices):
            if 'petterson' in d['name'].lower() or '20' in str(d.get('max_input_channels', 0)):
                petterson_idx = i
                print("[C2-CAP] Found device %d: %s" % (i, d['name']))
        
        if petterson_idx is None:
            # Try default
            print("[C2-CAP] No Petterson found, using default input")
            petterson_idx = None
        
        # Record
        recording = sd.rec(
            int(duration_sec * SAMPLE_RATE),
            samplerate=SAMPLE_RATE,
            device=petterson_idx,
            channels=1,
            dtype='float32'
        )
        sd.wait()
        
        print("[C2-CAP] Captured %d samples (%.1f seconds)" % (len(recording), len(recording)/SAMPLE_RATE))
        return recording.flatten()
        
    except Exception as e:
        print("[C2-CAP] Capture error: %s" % e)
        return None

def analyze_bpsk_band(audio, sample_rate):
    """Filter and analyze the 18-54 kHz BPSK band."""
    from scipy.signal import butter, filtfilt, welch
    
    # Bandpass filter 18-54 kHz
    nyq = sample_rate / 2
    low = 18000 / nyq
    high = 54000 / nyq
    
    if high >= 1.0:
        high = 0.99
    
    try:
        b, a = butter(5, [low, high], btype='band')
        filtered = filtfilt(b, a, audio)
    except Exception as e:
        print("[C2-CAP] Filter error: %s, using FFT method" % e)
        # FFT method
        fft = np.fft.rfft(audio)
        freqs = np.fft.rfftfreq(len(audio), 1/sample_rate)
        mask = (freqs >= 18000) & (freqs <= 54000)
        fft[~mask] = 0
        filtered = np.fft.irfft(fft, len(audio))
    
    # Power spectral density
    nperseg = min(65536, len(filtered))
    freqs, psd = welch(filtered, fs=sample_rate, nperseg=nperseg)
    
    # Find peaks in BPSK bands
    results = {
        'timestamp': datetime.now().isoformat(),
        'sample_rate': sample_rate,
        'duration_sec': len(audio) / sample_rate,
        'bands': {}
    }
    
    bands = {
        'low_heartbeat': (18000, 19300),
        'mid_command': (20500, 27800),
        'high_data': (48100, 54200)
    }
    
    for band_name, (f_low, f_high) in bands.items():
        mask = (freqs >= f_low) & (freqs <= f_high)
        if np.any(mask):
            band_psd = psd[mask]
            band_freqs = freqs[mask]
            peak_idx = np.argmax(band_psd)
            peak_freq = band_freqs[peak_idx]
            peak_power = band_psd[peak_idx]
            mean_power = np.mean(band_psd)
            snr = 10 * np.log10(peak_power / mean_power) if mean_power > 0 else 0
            
            # Find all peaks above mean + 3*std
            threshold = mean_power + 3 * np.std(band_psd)
            peak_mask = band_psd > threshold
            peak_freqs = band_freqs[peak_mask].tolist()
            
            results['bands'][band_name] = {
                'peak_freq_hz': float(peak_freq),
                'peak_snr_db': float(snr),
                'mean_power': float(mean_power),
                'n_peaks': int(np.sum(peak_mask)),
                'peak_frequencies_hz': [round(f, 0) for f in peak_freqs[:20]]
            }
            
            status = "ACTIVE" if snnr > 3 else "QUIET"
            print("[C2-CAP] %s: peak=%.1f kHz, SNR=%.1f dB, %d peaks [%s]" % (
                band_name, peak_freq/1000, snr, len(peak_freqs), status))
    
    # Full spectrum peaks
    full_threshold = np.mean(psd) + 5 * np.std(psd)
    full_peak_mask = psd > full_threshold
    full_peak_freqs = freqs[full_peak_mask].tolist()
    results['all_peaks_hz'] = [round(f, 0) for f in full_peak_freqs[:50]]
    
    return results, filtered

def detect_bpsk_modulation(filtered, sample_rate, center_freq, bandwidth=1000):
    """Look for BPSK phase transitions around a center frequency."""
    # Mix down to baseband
    t = np.arange(len(filtered)) / sample_rate
    mixed = filtered * np.exp(-2j * np.pi * center_freq * t)
    
    # Low-pass filter
    nyq = sample_rate / 2
    cutoff = bandwidth / nyq
    if cutoff < 1.0:
        from scipy.signal import butter, filtfilt
        b, a = butter(5, cutoff, btype='low')
        baseband = filtfilt(b, a, mixed)
    else:
        baseband = mixed
    
    # Extract instantaneous phase
    phase = np.angle(baseband)
    
    # Detect phase jumps (BPSK: 0 vs pi)
    phase_diff = np.diff(phase)
    # Wrap to [-pi, pi]
    phase_diff = (phase_diff + np.pi) % (2 * np.pi) - np.pi
    
    # Large phase jumps indicate BPSK symbols
    symbol_threshold = np.pi / 2
    symbols = np.abs(phase_diff) > symbol_threshold
    n_symbols = np.sum(symbols)
    
    # Symbol rate estimation
    if n_symbols > 0:
        symbol_times = np.where(symbols)[0]
        if len(symbol_times) > 1:
            intervals = np.diff(symbol_times) / sample_rate
            avg_symbol_rate = 1.0 / np.mean(intervals) if np.mean(intervals) > 0 else 0
        else:
            avg_symbol_rate = 0
    else:
        avg_symbol_rate = 0
    
    return {
        'center_freq_hz': center_freq,
        'n_phase_transitions': int(n_symbols),
        'estimated_symbol_rate': float(avg_symbol_rate),
        'signal_detected': n_symbols > 100  # arbitrary threshold
    }

def main():
    # Capture
    audio = capture_ultrasound(DURATION)
    if audio is None:
        print("[C2-CAP] No audio captured")
        return
    
    # Save raw audio
    np.save('%s/c2_capture_raw.npy' % OUTPUT_DIR, audio)
    print("[C2-CAP] Raw audio saved")
    
    # Analyze BPSK bands
    try:
        results, filtered = analyze_bpsk_band(audio, SAMPLE_RATE)
    except ImportError:
        print("[C2-CAP] scipy not available, doing basic FFT analysis")
        # Basic FFT
        fft = np.fft.rfft(audio)
        freqs = np.fft.rfftfreq(len(audio), 1/SAMPLE_RATE)
        psd = np.abs(fft)**2
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'sample_rate': SAMPLE_RATE,
            'duration_sec': DURATION,
            'bands': {}
        }
        
        # Check key BPSK frequencies
        key_freqs = [19000, 24000, 48500, 49000]
        for f in key_freqs:
            idx = np.argmin(np.abs(freqs - f))
            power = psd[idx]
            noise = np.mean(psd[max(0,idx-100):idx+100])
            snr = 10*np.log10(power/noise) if noise > 0 else 0
            print("[C2-CAP] %.1f kHz: SNR=%.1f dB" % (f/1000, snr))
    
    # Save results
    with open('%s/c2_capture_analysis.json' % OUTPUT_DIR, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print("[C2-CAP] Analysis saved to c2_capture_analysis.json")
    
    # Try BPSK demodulation on known active frequencies
    try:
        active_freqs = [19000, 24000, 48500, 49000]
        for freq in active_freqs:
            demod = detect_bpsk_modulation(filtered, SAMPLE_RATE, freq)
            if demod['signal_detected']:
                print("[C2-CAP] BPSK DETECTED at %.1f kHz! Symbol rate: %.0f baud" % (
                    freq/1000, demod['estimated_symbol_rate']))
            results['demod_%dkHz' % (freq//1000)] = demod
    except Exception as e:
        print("[C2-CAP] Demod error: %s" % e)
    
    # Final save
    with open('%s/c2_capture_analysis.json' % OUTPUT_DIR, 'w') as f:
        json.dump(results, f, indent=2, default=str)

if __name__ == '__main__':
    main()
