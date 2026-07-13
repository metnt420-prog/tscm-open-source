#!/usr/bin/env python
"""
GNU Radio Full Pipeline — TSCM Integration
Connects all demod chains to live TSCM IQ stream.

Chains:
  1. PLC: Audio ADC → FFT → Beacon/Addr/Cmd detection
  2. Ultrasound: Petterson 384k → BPSK/FSK → C2 payload
  3. MW Voice: BladeRF 2.45G → AM demod → Whisper → text
  4. mmWave: WiFi harmonic → noise floor → 5G detection

Run: C:\ProgramData\radioconda\python.exe gnuradio_pipeline.py --live
"""

import numpy as np
import json, os, time, hashlib, threading, queue
from collections import deque
from datetime import datetime

# Local imports
from plc_demod_flowgraph import PLCDemodulator
from c2_demod_gnuradio import SimpleDemodulator

class GNURadioPipeline:
    """Master pipeline connecting all GNU Radio chains to TSCM."""
    
    def __init__(self):
        self.plc = PLCDemodulator(sample_rate=48000)
        self.rf_demod = SimpleDemodulator()
        self.iq_queue = queue.Queue(maxsize=50)
        self.audio_queue = queue.Queue(maxsize=50)
        self.evidence_log = []
        self.running = False
        
        # Evidence chain
        self.chain_prev = hashlib.sha256(b'TSCM_GNU_PIPELINE_INIT').hexdigest()
        
    def start(self):
        """Start pipeline processing threads."""
        self.running = True
        
        # PLC processing thread
        self.plc_thread = threading.Thread(target=self._plc_worker, daemon=True)
        self.plc_thread.start()
        
        # RF IQ processing thread
        self.iq_thread = threading.Thread(target=self._iq_worker, daemon=True)
        self.iq_thread.start()
        
        print("GNU Radio Pipeline: ACTIVE")
        print("  PLC worker: running")
        print("  IQ worker: running")
        
    def stop(self):
        """Stop pipeline."""
        self.running = False
        print("GNU Radio Pipeline: STOPPED")
    
    def feed_audio(self, audio_chunk, sample_rate=48000):
        """Feed audio data from PLC/audio ADC."""
        try:
            self.audio_queue.put_nowait({
                'data': np.array(audio_chunk).flatten(),
                'sample_rate': sample_rate,
                'timestamp': time.time()
            })
        except queue.Full:
            pass
    
    def feed_iq(self, iq_data, sample_rate, center_freq, source='hackrf'):
        """Feed IQ data from HackRF or BladeRF."""
        try:
            self.iq_queue.put_nowait({
                'data': np.array(iq_data).flatten(),
                'sample_rate': sample_rate,
                'center_freq': center_freq,
                'source': source,
                'timestamp': time.time()
            })
        except queue.Full:
            pass
    
    def _plc_worker(self):
        """Process PLC audio chunks."""
        while self.running:
            try:
                chunk = self.audio_queue.get(timeout=1)
                result = self.plc.process_audio(chunk['data'])
                
                # Log significant detections
                if result.get('beacon') or result.get('command'):
                    self._log_evidence('plc_c2', result)
                    
            except queue.Empty:
                continue
            except Exception as e:
                print(f"PLC worker error: {e}")
    
    def _iq_worker(self):
        """Process RF IQ chunks."""
        while self.running:
            try:
                chunk = self.iq_queue.get(timeout=1)
                
                # Route by frequency
                freq = chunk['center_freq']
                
                if freq < 10e3:
                    # VLF/HF: PLC command decoding
                    mode = 'fsk'
                elif 15e3 < freq < 55e3:
                    # Ultrasound: BPSK C2 decoding
                    mode = 'bpsk'
                elif freq > 1e9:
                    # Microwave: AM voice
                    mode = 'am'
                else:
                    mode = 'auto'
                
                result = self.rf_demod.process_iq(
                    chunk['data'], chunk['sample_rate'], freq, mode
                )
                
                if result.get('decoded') or result.get('symbols'):
                    self._log_evidence(f'c2_demod_{mode}', result)
                    
            except queue.Empty:
                continue
            except Exception as e:
                pass  # Silent on individual errors
    
    def _log_evidence(self, detector, result):
        """Log to SHA-256 evidence chain."""
        evidence = {
            'timestamp_iso': datetime.utcnow().isoformat() + 'Z',
            'detector': detector,
            'chain_prev': self.chain_prev,
            'data': str(result)[:500]
        }
        evidence['chain_hash'] = hashlib.sha256(
            json.dumps(evidence, default=str).encode()
        ).hexdigest()
        self.chain_prev = evidence['chain_hash']
        self.evidence_log.append(evidence)
    
    def get_status(self):
        """Return pipeline status."""
        return {
            'running': self.running,
            'iq_queue_size': self.iq_queue.qsize(),
            'audio_queue_size': self.audio_queue.qsize(),
            'evidence_count': len(self.evidence_log),
            'chain_hash': self.chain_prev[:16]
        }


# ============================================================
# Ultrasound BPSK C2 Decoder (dedicated chain)
# ============================================================

class UltrasoundBPSKDecoder:
    """
    Dedicated ultrasound BPSK/FSK decoder.
    
    Targets:
      - 18-19 kHz: BPSK heartbeat
      - 24-27 kHz: BPSK command data  
      - 48-54 kHz: FSK data exfiltration
      
    Petterson M500 at 384 kHz → downconvert → demod → bytes
    """
    
    # Known ultrasound C2 channels
    CHANNELS = {
        'bpsk_heartbeat': (19000, 200, 'BPSK heartbeat/sync'),
        'bpsk_cmd_low': (24000, 500, 'BPSK command low'),
        'bpsk_cmd_high': (27000, 500, 'BPSK command high'),
        'fsk_exfil_low': (48000, 1000, 'FSK exfil low'),
        'fsk_exfil_high': (54000, 1000, 'FSK exfil high'),
        'bpks_voice': (23700, 400, 'BPSK voice_to_skull'),
        'bpks_data': (48600, 1000, 'BPSK ultrasonic_data'),
        'fsk_alt': (23719, 200, 'FSK alternative'),
    }
    
    def __init__(self, fs=384000):
        self.fs = fs  # Petterson sample rate
        self.detected_channels = {}
        self.payload_buf = deque(maxlen=1000)
        
    def scan_channels(self, iq_chunk):
        """Scan all known ultrasound C2 channels."""
        if len(iq_chunk) < 4096:
            return []
        
        fft = np.abs(np.fft.fft(iq_chunk))
        freqs = np.fft.fftfreq(len(iq_chunk), 1/self.fs)
        # Use positive frequencies only
        pos_mask = freqs >= 0
        fft = fft[pos_mask]
        freqs = freqs[pos_mask]
        noise_floor = np.median(fft)
        
        detections = []
        for name, (center, bw, desc) in self.CHANNELS.items():
            lo = max(0, np.searchsorted(freqs, center - bw))
            hi = min(len(fft), np.searchsorted(freqs, center + bw))
            
            if lo < hi:
                signal = np.max(fft[lo:hi])
                snr = 20 * np.log10(signal / (noise_floor + 1e-12))
                
                if snr > 10:
                    peak_idx = lo + np.argmax(fft[lo:hi])
                    peak_freq = freqs[peak_idx]
                    
                    detection = {
                        'channel': name,
                        'center_freq': center,
                        'peak_freq': round(float(peak_freq), 1),
                        'snr_db': round(float(snr), 1),
                        'description': desc,
                        'active': True,
                        'timestamp': time.time()
                    }
                    
                    # Try BPSK demod if strong enough
                    if snr > 15 and 'bpsk' in name:
                        symbols = self._bpsk_demod(iq_chunk, peak_freq, baud_rate=130)
                        if symbols and len(symbols) > 8:
                            detection['symbols'] = symbols[:200]
                            detection['symbol_count'] = len(symbols)
                            # Try ASCII decode
                            if len(symbols) >= 64:
                                text = []
                                for i in range(0, len(symbols)-8, 8):
                                    byte = sum(symbols[i+j] << (7-j) for j in range(8) if i+j < len(symbols))
                                    if 32 <= byte < 127:
                                        text.append(chr(byte))
                                if text:
                                    detection['decoded_text'] = ''.join(text)[:100]
                    
                    # Try FSK demod if applicable
                    if snr > 12 and 'fsk' in name:
                        sym = self._fsk_demod(iq_chunk, peak_freq, baud_rate=200)
                        if sym and len(sym) > 8:
                            detection['fsk_symbols'] = sym[:200]
                    
                    detections.append(detection)
                    self.detected_channels[name] = detection
        
        return detections
    
    def _bpsk_demod(self, iq, carrier, baud_rate=130):
        """BPSK demodulation for ultrasound carriers."""
        if len(iq) < 100:
            return None
        
        # Local oscillator mixing
        t = np.arange(len(iq)) / self.fs
        lo = np.exp(-2j * np.pi * carrier * t)
        baseband = iq * lo
        
        # Low-pass filter at 2× baud rate
        from scipy.signal import butter, lfilter
        nyq = self.fs / 2
        b, a = butter(2, baud_rate * 2 / nyq, btype='low')
        filtered = lfilter(b, a, baseband.real)
        
        # Sample at baud rate
        samples_per_symbol = int(self.fs / baud_rate)
        symbols = []
        for i in range(samples_per_symbol // 2, len(filtered), samples_per_symbol):
            if len(symbols) < 500:
                symbols.append(1 if filtered[i] > 0 else 0)
        
        return symbols
    
    def _fsk_demod(self, iq, center, baud_rate=200):
        """FSK demodulation — detect frequency shifts."""
        # FM discriminator
        phase = np.unwrap(np.angle(iq))
        freq = np.diff(phase) * self.fs / (2 * np.pi)
        
        # Integrate over symbol period
        samples_per_symbol = int(self.fs / baud_rate)
        symbols = []
        for i in range(0, len(freq) - samples_per_symbol, samples_per_symbol):
            avg_freq = np.mean(freq[i:i + samples_per_symbol])
            symbols.append(1 if avg_freq > center else 0)
        
        return symbols[:500] if symbols else None


# ============================================================
# Live Pipeline Runner
# ============================================================

if __name__ == '__main__':
    print("=" * 55)
    print("GNU RADIO FULL PIPELINE — TSCM INTEGRATION")
    print("=" * 55)
    
    # Test pipeline init
    pipeline = GNURadioPipeline()
    
    # Test PLC demod with synthetic data
    fs = 48000
    t = np.arange(fs) / fs
    beacon = 0.3 * np.sin(2 * np.pi * 480 * t)
    pipeline.feed_audio(beacon, fs)
    
    # Test BPSK decoder with synthetic ultrasound
    bpsk = UltrasoundBPSKDecoder(fs=384000)
    t_us = np.arange(8192) / 384000
    # 24 kHz BPSK carrier
    carrier = np.exp(2j * np.pi * 24000 * t_us)
    bpsk_iq = carrier + 0.01 * (np.random.randn(8192) + 1j * np.random.randn(8192))
    
    hits = bpsk.scan_channels(bpsk_iq)
    print(f"\nUltrasound channels detected: {len(hits)}")
    for h in hits:
        print(f"  {h['channel']}: {h['peak_freq']} Hz, SNR={h['snr_db']} dB")
    
    # Start pipeline
    pipeline.start()
    
    # Let PLC worker process
    import time as _time
    _time.sleep(2)
    
    status = pipeline.get_status()
    print(f"\nPipeline status: {status['evidence_count']} evidence entries")
    print(f"Chain hash: {status['chain_hash']}")
    
    pipeline.stop()
    print("\nPipeline test complete. Ready for live TSCM integration.")
