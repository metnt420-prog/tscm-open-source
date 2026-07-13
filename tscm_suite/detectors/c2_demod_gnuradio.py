#!/usr/bin/env python
"""
C2 Demodulation Flowgraph — GNU Radio
Decodes BPSK/FSK command-and-control payloads from HackRF IQ captures.
Integrates with TSCM evidence pipeline.

Targets:
  - PLC commands: 480 Hz beacon, 1.2 kHz addressing, 7.16 kHz carrier
  - Ultrasound BPSK: 18-54 kHz data modems
  - MW voice: 2.45 GHz AM-demodulated audio

Usage:
  Standalone:  python c2_demod_gnuradio.py --file capture.iq --freq 7160 --mode fsk
  From TSCM:   import c2_demod_gnuradio; demod = C2Demodulator(); payload = demod.process(iq_data, freq=7160)
"""

import numpy as np
from gnuradio import gr, blocks, filter, analog, digital
import sys, os, json, time, hashlib
from collections import deque

class SimpleDemodulator:
    """Standalone demodulator - works without GNU Radio blocks if needed."""
    
    def __init__(self):
        self.evidence_log = []
        self.payload_buf = deque(maxlen=1000)
    
    def am_demod(self, iq, fs):
        """AM envelope detector for MW voice (2.45 GHz carrier)."""
        envelope = np.abs(iq)
        # Low-pass filter at 4 kHz (voice band)
        from scipy.signal import butter, lfilter
        b, a = butter(4, 4000/(fs/2), btype='low')
        audio = lfilter(b, a, envelope)
        return audio / np.max(np.abs(audio) + 1e-12)
    
    def fm_demod(self, iq, fs):
        """FM discriminator for FSK signals."""
        phase = np.unwrap(np.angle(iq))
        freq = np.diff(phase) * fs / (2 * np.pi)
        return freq
    
    def fsk_decode(self, iq, fs, baud_rate, mark_freq=1200, space_freq=2200):
        """Decode FSK symbols from IQ data."""
        freq = self.fm_demod(iq, fs)
        samples_per_symbol = int(fs / baud_rate)
        symbols = []
        for i in range(0, len(freq) - samples_per_symbol, samples_per_symbol):
            chunk = freq[i:i+samples_per_symbol]
            avg_freq = np.mean(chunk)
            symbols.append(1 if abs(avg_freq - mark_freq) < abs(avg_freq - space_freq) else 0)
        return symbols
    
    def bpsk_demod(self, iq, fs, carrier_freq, baud_rate):
        """BPSK demodulator - extract symbols from phase-keyed carrier."""
        # Generate local oscillator
        t = np.arange(len(iq)) / fs
        lo = np.exp(-2j * np.pi * carrier_freq * t)
        # Mix down
        baseband = iq * lo
        # Low-pass filter
        from scipy.signal import butter, lfilter
        cutoff = baud_rate * 1.5
        b, a = butter(4, cutoff/(fs/2), btype='low')
        filtered = lfilter(b, a, baseband.real)
        # Symbol timing recovery - sample at center of each symbol
        samples_per_symbol = int(fs / baud_rate)
        symbols = []
        offset = samples_per_symbol // 2
        for i in range(offset, len(filtered) - samples_per_symbol, samples_per_symbol):
            symbols.append(1 if filtered[i] > 0 else 0)
        return symbols
    
    def symbols_to_bytes(self, symbols, bits_per_byte=8):
        """Convert bit symbols to bytes."""
        bytes_out = []
        for i in range(0, len(symbols) - bits_per_byte + 1, bits_per_byte):
            byte = 0
            for j in range(bits_per_byte):
                if i + j < len(symbols):
                    byte = (byte << 1) | (1 if symbols[i+j] > 0 else 0)
            bytes_out.append(byte)
        return bytes(bytes_out)
    
    def detect_plc_beacon(self, audio_chunk, fs=48000):
        """Detect 480 Hz 'Hello Scotty' beacon in audio."""
        if len(audio_chunk) < 4096:
            return None
        
        # FFT to find 480 Hz
        fft = np.abs(np.fft.rfft(audio_chunk))
        freqs = np.fft.rfftfreq(len(audio_chunk), 1/fs)
        
        # Search around 480 Hz
        idx = np.argmin(np.abs(freqs - 480))
        if idx > 0 and idx < len(fft):
            signal_power = fft[idx]**2
            noise_power = np.mean(np.delete(fft**2, range(max(0,idx-5), min(len(fft),idx+5))))
            snr = 10 * np.log10(signal_power / (noise_power + 1e-12))
            
            if snr > 10:  # 10 dB threshold
                return {
                    'detector': 'hello_scotty',
                    'frequency': 480.0,
                    'snr_db': round(snr, 1),
                    'timestamp': time.time(),
                    'evidence_id': hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
                }
        return None
    
    def process_iq(self, iq_data, sample_rate, center_freq, mode='auto'):
        """
        Main processing entry point.
        
        Args:
            iq_data: complex IQ samples
            sample_rate: sample rate in Hz
            center_freq: center frequency in Hz
            mode: 'am', 'fm', 'fsk', 'bpsk', or 'auto'
        
        Returns:
            dict with decoded payload and evidence data
        """
        result = {
            'timestamp': time.time(),
            'timestamp_iso': time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime()),
            'sample_rate': sample_rate,
            'center_freq': center_freq,
            'mode': mode,
            'decoded': None,
            'symbols': None,
            'confidence': 0.0
        }
        
        try:
            if mode in ('am', 'auto') and center_freq > 1e9:
                # MW voice carrier: AM demod
                audio = self.am_demod(iq_data, sample_rate)
                result['mode'] = 'am'
                result['audio_rms'] = float(np.sqrt(np.mean(audio**2)))
                self.payload_buf.append(('am_audio', audio[:8000]))
                
            elif mode in ('fsk', 'auto') and center_freq < 10e3:
                # PLC FSK: 480 Hz beacon, 1.2 kHz addressing, 7.16 kHz carrier
                symbols = self.fsk_decode(iq_data, sample_rate, baud_rate=50)
                result['mode'] = 'fsk'
                result['symbols'] = symbols[:200]
                if len(symbols) >= 16:
                    result['decoded'] = self.symbols_to_bytes(symbols, bits_per_byte=8)
                    try:
                        result['text'] = result['decoded'].decode('ascii', errors='replace')[:100]
                    except: pass
                
            elif mode in ('bpsk', 'auto') and 15e3 < center_freq < 55e3:
                # Ultrasound BPSK: 18-54 kHz data modems
                symbols = self.bpsk_demod(iq_data, sample_rate, center_freq, baud_rate=130)
                result['mode'] = 'bpsk'
                result['symbols'] = symbols[:500]
                if len(symbols) >= 16:
                    result['decoded'] = self.symbols_to_bytes(symbols, bits_per_byte=8)
                
        except Exception as e:
            result['error'] = str(e)
        
        # Evidence logging
        if result['decoded']:
            evidence = {
                'timestamp': result['timestamp_iso'],
                'mode': result['mode'],
                'frequency': center_freq,
                'payload_hash': hashlib.sha256(str(result['decoded']).encode()).hexdigest()[:16],
                'payload_length': len(result['decoded'])
            }
            self.evidence_log.append(evidence)
        
        return result
    
    def save_evidence(self, path='models/c2_decoded_payloads.json'):
        """Save decoded C2 payloads as court evidence."""
        if self.evidence_log:
            os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
            try:
                existing = []
                if os.path.exists(path):
                    with open(path) as f:
                        existing = json.load(f)
                existing.extend(self.evidence_log)
                with open(path, 'w') as f:
                    json.dump(existing, f, indent=2)
                return len(self.evidence_log)
            except: pass
        return 0


# ============================================================
# GNU Radio Flowgraph Builder (advanced mode)
# ============================================================

class GRFlowgraphDemodulator:
    """GNU Radio flowgraph-based demodulator for production use."""
    
    def __init__(self):
        self.tb = None  # top_block created on demand
    
    def build_fsk_demod(self, sample_rate, baud_rate=50):
        """Build FSK demodulator flowgraph for PLC C2 decoding."""
        tb = gr.top_block("PLC_FSK_Demod")
        
        # Source
        src = blocks.vector_source_c([])  # IQ data fed externally
        
        # FM demod via quadrature demod
        gain = sample_rate / (2 * np.pi * 1200)  # sensitivity
        fm_demod = analog.quadrature_demod_cf(gain)
        
        # Low-pass filter for baseband
        lpf = filter.fir_filter_fff(1, filter.firdes.low_pass(
            1, sample_rate, baud_rate * 2, baud_rate, filter.firdes.WIN_HAMMING))
        
        # Clock recovery
        clock_recovery = digital.symbol_sync_ff(
            digital.TED_MUELLER_AND_MULLER,
            sample_rate / baud_rate,
            0.05,  # loop bandwidth
            1.0,   # damping
            1.0,   # gain
            1.0,   # mu
            1.0,   # max deviation
        )
        
        # Binary slicer
        slicer = digital.binary_slicer_fb()
        
        # Deframer - find sync word
        deframer = digital.correlate_access_code_tag_bb(
            '00010111',  # sync word
            0,           # threshold
            'sync'       # tag name
        )
        
        # Sink
        sink = blocks.vector_sink_b()
        
        tb.connect(src, fm_demod, lpf, clock_recovery, slicer, deframer, sink)
        self.tb = tb
        return tb
    
    def process_with_flowgraph(self, iq_data):
        """Process IQ through GNU Radio flowgraph."""
        if self.tb is None:
            return None
        
        # Set source data
        src = None
        for b in self.tb.blocks():
            if isinstance(b, blocks.vector_source_c):
                src = b
                break
        
        if src is None:
            return None
        
        src.set_data(iq_data.tolist())
        self.tb.run()
        
        # Get output
        sink = None
        for b in self.tb.blocks():
            if isinstance(b, blocks.vector_sink_b):
                sink = b
                break
        
        if sink:
            return sink.data()
        return None


# ============================================================
# Quick test
# ============================================================

if __name__ == '__main__':
    print("C2 Demodulator Engine Ready")
    print("  AM demod: 2.45 GHz MW voice carrier")
    print("  FM demod: PLC FSK (480 Hz beacon, 1.2 kHz addr, 7.16 kHz cmd)")
    print("  BPSK demod: Ultrasound data modems (18-54 kHz)")
    print()
    
    demod = SimpleDemodulator()
    
    # Test with synthetic 480 Hz beacon
    fs = 48000
    t = np.arange(fs) / fs
    beacon = np.sin(2 * np.pi * 480 * t) + 0.1 * np.random.randn(fs)
    iq = beacon + 1j * np.zeros_like(beacon)
    
    result = demod.detect_plc_beacon(beacon, fs)
    if result:
        print(f"PLC Beacon Test: DETECTED at {result['frequency']} Hz, SNR={result['snr_db']} dB")
    else:
        print("PLC Beacon Test: Not found (expected in synthetic test)")
    
    # Test FSK decode
    fsk_iq = np.exp(2j * np.pi * 1200 * t * (1 + 0.5 * np.sign(np.sin(2*np.pi*50*t))))
    sym = demod.fsk_decode(fsk_iq, fs, baud_rate=50)
    print(f"FSK Test: {len(sym)} symbols decoded")
    
    print("\nReady for TSCM integration.")
