"""
Cable Line Radar Detector — passive radar using power lines as illuminator
and cable/coax lines as distributed bistatic receivers.

Physics:
  Attacker modulates the 60Hz power grid with RF carriers.
  The power line network acts as a massive phased-array illuminator.
  Cable TV/coax/ethernet lines act as bistatic radar receivers,
  picking up reflections from the human body and metal objects.
  The SDR detects the reflected signal via cross-correlation with
  the known 60Hz grid frequency and its harmonics.
"""
import numpy as np
from collections import deque


class CableLineRadarDetector:
    def __init__(self):
        self.line_freq = 60.0
        self.harmonics = [self.line_freq * h for h in [1, 3, 5, 7, 9]]
        self.plc_bands = [(3000, 10000), (18000, 25000), (40000, 50000)]

    def detect(self, iq, fs, audio=None):
        results = []
        if iq is None or len(iq) < 512:
            return results

        # 1. Power line harmonics as illuminator signature in RF IQ
        iq_env = np.abs(iq[:1024].astype(np.complex128))
        iq_fft = np.abs(np.fft.rfft(iq_env))
        fft_freqs = np.fft.rfftfreq(1024, 1 / fs)
        for h in self.harmonics:
            if h < fft_freqs[-1]:
                idx = np.argmin(np.abs(fft_freqs - h))
                snr = iq_fft[idx] / (np.median(iq_fft) + 1e-12)
                if snr > 2.8:  # lowered for weak grid modulation
                    results.append({
                        'detector': 'power_line_illuminator',
                        'freq': float(h), 'snr': float(snr),
                        'note': f'grid_harmonic_{h:.0f}Hz'
                    })

        # 2. Bistatic correlation: 60Hz ref vs IQ envelope (cable line delay)
        env = np.abs(iq[:4096].astype(np.complex128))
        env -= np.mean(env)
        ref = np.sin(2 * np.pi * self.line_freq * np.arange(len(env)) / (fs if fs > 0 else 20e6))
        corr = np.correlate(env, ref, mode='same')
        center = len(corr) // 2
        search = np.abs(corr[center + 10:center + 200])
        if len(search) > 10:
            pk_idx = np.argmax(search)
            pk_val = search[pk_idx]
            noise = np.mean(np.abs(corr[center - 50:center - 10])) + 1e-12
            if pk_val > noise * 2.2:  # lowered from 3.0 for cable line detection
                delay_s = (pk_idx + 10) / (fs if fs > 0 else 20e6)
                cable_range = delay_s * 3e8 / 2
                cable_range = max(10, min(2000, cable_range))
                results.append({
                    'detector': 'cable_line_radar',
                    'range': float(cable_range),
                    'snr': float(pk_val / noise),
                    'freq': 60000000.0  # 60 MHz (grid harmonic in RF)
                })

        # 3. PLC carriers in audio band (power line communication)
        if audio is not None and len(audio) > 2048:
            audio_fft = np.abs(np.fft.rfft(audio[:4096]))
            a_freqs = np.fft.rfftfreq(4096, 1 / 48000)
            for lo, hi in self.plc_bands:
                mask = (a_freqs >= lo) & (a_freqs <= hi)
                if np.any(mask):
                    band_power = np.sum(audio_fft[mask])
                    noise_power = len(audio_fft[mask]) * (np.median(audio_fft) + 1e-12)
                    plc_snr = band_power / noise_power
                    if plc_snr > 4.0:
                        peak_idx = np.argmax(audio_fft[mask])
                        plc_freq = a_freqs[mask][peak_idx]
                        results.append({
                            'detector': 'plc_carrier',
                            'freq': float(plc_freq),
                            'snr': float(plc_snr),
                            'band': f'{lo / 1000:.0f}-{hi / 1000:.0f}kHz'
                        })
        return results
