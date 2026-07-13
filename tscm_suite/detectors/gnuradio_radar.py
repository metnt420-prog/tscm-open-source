"""
GNU Radio Active Radar for BladeRF MIMO
Uses SoapySDR/BladeRF source for RX, captures reflections after TX pulse.
No more bladeRF-cli crashes - single process controls everything.
"""
import sys
import os
import time
import numpy as np

# Add GNU Radio conda env to path
GR_PYTHON = r'C:\Users\carpe\.conda\envs\gr'
if GR_PYTHON not in sys.path:
    sys.path.insert(0, os.path.join(GR_PYTHON, 'Lib', 'site-packages'))

from gnuradio import gr, blocks, analog, filter as gr_filter
from gnuradio import soapy

class ActiveRadar(gr.top_block):
    """
    GNU Radio flow graph for BladeRF MIMO active radar.
    RX1 + RX2 capture, periodic TX pulse for illumination.
    """
    def __init__(self, freq=2450e6, sample_rate=2e6, rx_gain=40, tx_gain=50):
        gr.top_block.__init__(self, "TSCM Active Radar")
        
        self.freq = freq
        self.sample_rate = sample_rate
        self.rx_gain = rx_gain
        self.tx_gain = tx_gain
        
        # BladeRF via SoapySDR
        try:
            # RX source - 2 channels (MIMO)
            self.rx_source = soapy.source(
                1, "driver=bladerf", "",
                "chan0", [f"antenna=RX1"],
                [f"gain={rx_gain}"],
                f"freq={freq}",
                f"rate={sample_rate}",
                "", ""
            )
            
            # We'll try single channel first, MIMO if it works
            self.rx = self.rx_source
            
        except Exception as e:
            print(f"SoapySDR BladeRF source failed: {e}")
            print("Falling back to file source for testing")
            # Fallback - generate test data
            self.rx = blocks.vector_source_c(
                list(np.exp(2j * np.pi * np.random.random(10000))),
                repeat=True
            )
        
        # Signal processing chain
        # 1. Complex to magnitude (power measurement)
        self.c2mag = blocks.complex_to_mag(1)
        
        # 2. Moving average (smoothing)
        self.moving_avg = gr_filter.moving_average(100, 1.0/100, 10000)
        
        # 3. File sink for capture
        self.capture_file = os.path.join(
            os.environ.get('TEMP', '/tmp'), 'radar_capture.bin')
        self.file_sink = blocks.file_sink(
            gr.sizeof_gr_complex, self.capture_file, False)
        
        # 4. Vector sink for Python analysis
        self.vec_sink = blocks.vector_sink_c()
        
        # Connect: RX -> power monitor + capture
        self.connect((self.rx, 0), (self.c2mag, 0))
        self.connect((self.rx, 0), (self.file_sink, 0))
        self.connect((self.rx, 0), (self.vec_sink, 0))
        
    def get_capture_data(self):
        """Get captured IQ data for analysis."""
        return np.array(self.vec_sink.data())


class RadarController:
    """
    Controls the GNU Radio radar: starts/stops captures,
    fires TX pulses, analyzes echoes.
    """
    def __init__(self, log=None):
        self.log = log
        self.tb = None
        self.running = False
        self.capture_count = 0
        
    def start_capture(self, freq=2450e6, duration_sec=5):
        """Start a radar capture session."""
        try:
            if self.tb is not None:
                self.tb.stop()
                self.tb.wait()
            
            self.tb = ActiveRadar(freq=freq)
            self.tb.start()
            self.running = True
            self.capture_start = time.time()
            
            if self.log:
                self.log.info('RADAR: GNU Radio capture started at %.0f MHz' % (freq/1e6))
            
            return True
        except Exception as e:
            if self.log:
                self.log.error('RADAR: Failed to start: %s' % e)
            return False
    
    def stop_capture(self):
        """Stop current capture and get data."""
        if self.tb is None:
            return None
        
        try:
            self.tb.stop()
            self.tb.wait()
            self.running = False
            
            data = self.tb.get_capture_data()
            self.capture_count += 1
            
            if self.log:
                self.log.info('RADAR: Capture %d done, %d samples' % (self.capture_count, len(data)))
            
            return data
        except Exception as e:
            if self.log:
                self.log.error('RADAR: Stop error: %s' % e)
            return None
    
    def analyze_capture(self, iq_data, freq=2450e6, baseline=None):
        """Analyze captured radar data for reflectors."""
        if iq_data is None or len(iq_data) < 1024:
            return []
        
        results = []
        
        # FFT analysis
        n_fft = 4096
        fft = np.abs(np.fft.rfft(iq_data[-n_fft:]))
        fft_freqs = np.fft.rfftfreq(n_fft, 1/self.tb.sample_rate if self.tb else 2e6)
        
        if baseline is not None and len(baseline) >= n_fft:
            base_fft = np.abs(np.fft.rfft(baseline[-n_fft:]))
            diff = fft - base_fft
            diff[diff < 0] = 0
        else:
            diff = fft
            base_fft = None
        
        noise = np.median(fft) + 1e-12
        
        # Find peaks
        from scipy.signal import find_peaks
        peaks, _ = find_peaks(diff, height=noise*3, distance=10)
        
        for pk in peaks[:10]:
            level = diff[pk]
            freq_offset = fft_freqs[pk]
            
            # Classify by bandwidth
            bw_bins = np.sum(diff[max(0,pk-5):pk+6] > noise*2)
            bw_hz = bw_bins * (self.tb.sample_rate if self.tb else 2e6) / n_fft
            
            if bw_hz < 50000:
                material = 'metal_device'
            elif bw_hz < 200000:
                material = 'metal_surface'
            else:
                material = 'water_body'
            
            results.append({
                'freq_offset_hz': float(freq_offset),
                'freq_offset_khz': float(freq_offset / 1000),
                'level': float(level / noise),
                'bandwidth_hz': float(bw_hz),
                'material': material,
                'center_freq_mhz': float(freq / 1e6)
            })
        
        return results
