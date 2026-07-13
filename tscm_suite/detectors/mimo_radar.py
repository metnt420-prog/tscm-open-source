#!/usr/bin/env python3
"""Superheterodyne FMCW MIMO Radar for BladeRF xA9.
TX1: transmits chirps. RX1/RX2: receive reflections.
Dechirp -> range profile -> AoA -> micro-Doppler -> operator fingerprinting.
"""
import os, time, threading, hashlib, logging, subprocess, tempfile
from collections import deque
import numpy as np
from scipy.signal import find_peaks
from scipy.fft import fft
import datetime

try:
    import json
except: pass

class BladeRFMimoRadar:
    def __init__(self, tscm, cli_path=None):
        self.tscm = tscm
        self.cli_path = cli_path or os.path.join(
            os.environ.get('ProgramFiles', r'C:\Program Files'), 'bladeRF', 'x64', 'bladeRF-cli.exe')
        self.tx_tmpdir = os.path.join(tempfile.gettempdir(), 'bladerf_radar')
        os.makedirs(self.tx_tmpdir, exist_ok=True)
        self.log = tscm.log if tscm else logging.getLogger("MimoRadar")
        self.running = False
        self.thread = None
        # Radar params - use Config values if available
        try:
            from __main__ import Config
            self.fc = Config.BLADERF_FREQ
            self.bw = 10e6
            self.fs = Config.BLADERF_SAMPLE_RATE
            self.ant_spacing = Config.ANTENNA_SPACING
        except:
            self.fc = 2400e6
            self.bw = 10e6
            self.fs = 10e6
            self.ant_spacing = 0.5

        self.chirp_dur = 0.001
        self.prf = 100
        self.samples_per_chirp = int(self.fs * self.chirp_dur)
        self.range_res = 3e8 / (2 * self.bw)
        self.max_range = 3000

        # Micro-Doppler tracking
        self.md_history = deque(maxlen=256)
        self.heart_rates = deque(maxlen=10)
        self.breath_rates = deque(maxlen=10)
        self._last_tx_time = 0

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._radar_loop, daemon=True)
        self.thread.start()
        self.log.info("MIMO Radar: FMCW active (%d MHz BW, %.0fm res)" % (self.bw/1e6, self.range_res))

    def stop(self): self.running = False

    def _generate_chirp(self):
        t = np.arange(self.samples_per_chirp) / self.fs
        phase = 2 * np.pi * (self.bw / (2 * self.chirp_dur)) * t**2
        chirp = np.exp(1j * phase).astype(np.complex64)
        window = np.hanning(self.samples_per_chirp)
        return (chirp * window).astype(np.complex64)

    def _tx_chirp(self, chirp):
        """TX chirp via BladeRF CLI.
        DISABLED: bladeRF-cli subprocess calls crash NIOS firmware when
        CLI bridge is already using the device. TX handled by tscm_final.py."""
        return True

    def _radar_loop(self):
        chirp = self._generate_chirp()
        while self.running:
            try:
                now = time.time()
                if now - self._last_tx_time < 1.0 / self.prf:
                    time.sleep(0.001)
                    continue
                self._last_tx_time = now

                # TX chirp
                self._tx_chirp(chirp)

                # RX from TSCM
                if self.tscm is None:
                    continue
                iq1, iq2 = self.tscm._capture_bladerf()
                if iq1 is None:
                    continue

                # Superheterodyne dechirp
                ref = np.conj(chirp[:len(iq1)]) if len(chirp) >= len(iq1) else np.conj(np.resize(chirp, len(iq1)))
                dechirped1 = iq1 * ref
                dechirped2 = iq2 * ref if iq2 is not None else None

                # Range FFT
                range_profile1 = np.abs(fft(dechirped1))
                range_profile2 = np.abs(fft(dechirped2)) if dechirped2 is not None else None

                # Find targets
                noise_floor = np.median(range_profile1[:len(range_profile1)//2]) * 3
                peaks, _ = find_peaks(range_profile1[:len(range_profile1)//2],
                                      height=noise_floor, distance=5)
                target_ranges = []
                for p in peaks[:10]:
                    rng = p * 3e8 / (2 * self.bw * self.samples_per_chirp) * self.fs
                    if 1 < rng < self.max_range:
                        amp = float(range_profile1[p])
                        # AoA from MIMO phase
                        aoa = 0.0
                        if range_profile2 is not None and p < len(range_profile2):
                            p1 = np.angle(dechirped1[p])
                            p2 = np.angle(dechirped2[p])
                            pd = np.angle(np.exp(1j*(p2-p1)))
                            st = pd * 3e8/(2*np.pi*self.fc*self.ant_spacing)
                            aoa = np.degrees(np.arcsin(np.clip(st, -1, 1)))
                        target_ranges.append({'range': rng, 'aoa': aoa, 'amp': amp})

                # Micro-Doppler biometrics
                hr_val, br_val = 0, 0
                if peaks:
                    best_peak = peaks[np.argmax(range_profile1[peaks])]
                    phase_now = np.angle(dechirped1[best_peak])
                    self.md_history.append(phase_now)
                    if len(self.md_history) > 64:
                        phases = np.array(list(self.md_history))
                        pd = np.diff(np.unwrap(phases))
                        if len(pd) > 32:
                            md_spec = np.abs(fft(pd * np.hanning(len(pd))))
                            md_f = np.fft.fftfreq(len(pd), 1.0/self.prf)
                            pm = md_f > 0
                            md_f, md_spec = md_f[pm], md_spec[pm]
                            if len(md_f) > 0:
                                bm = (md_f >= 0.1) & (md_f <= 0.5)
                                if np.any(bm): self.breath_rates.append(float(md_f[bm][np.argmax(md_spec[bm])]))
                                hm = (md_f >= 0.8) & (md_f <= 3.0)
                                if np.any(hm): self.heart_rates.append(float(md_f[hm][np.argmax(md_spec[hm])]))
                    hr_val = np.mean(list(self.heart_rates))*60 if self.heart_rates else 0
                    br_val = np.mean(list(self.breath_rates))*60 if self.breath_rates else 0

                # Report
                if target_ranges:
                    lat = self.tscm.gps.lat if self.tscm.gps and self.tscm.gps.has_fix else 0
                    lon = self.tscm.gps.lon if self.tscm.gps and self.tscm.gps.has_fix else 0
                    fp = hashlib.sha256(
                        f"{hr_val:.1f}:{br_val:.1f}:{target_ranges[0]['range']:.0f}".encode()
                    ).hexdigest()[:16] if hr_val > 0 else ''
                    self.tscm.detection_markers.append({
                        'detector': 'mimo_radar_target',
                        'details': {
                            'targets': target_ranges[:5],
                            'count': len(target_ranges),
                            'heart_rate_bpm': round(hr_val, 1),
                            'breath_rate_bpm': round(br_val, 1),
                            'operator_fp': fp
                        },
                        'lat': lat, 'lon': lon,
                        'time': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'source': 'Radar',
                        'aoa': float(target_ranges[0]['aoa']) if target_ranges else 0.0
                    })

            except Exception as e:
                time.sleep(0.1)
