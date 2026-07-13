"""
Loop Antenna Direction Finder
Uses the loop antenna's figure-8 null pattern to determine signal direction.

A loop antenna has:
- Maximum signal when the loop plane is PERPENDICULAR to the source
- NULL (minimum signal) when the loop plane FACES the source

By comparing signal levels at different antenna orientations,
we can determine the bearing to the signal source WITHOUT 180° ambiguity.

The loop is connected to headphones (device 5) for inverse wave TX.
But we can ALSO read the loop's induced voltage from the sound card input.
"""
import numpy as np
import time
from collections import deque

class LoopDirectionFinder:
    """Find signal direction using the loop antenna's null pattern."""
    
    def __init__(self, log, audio_input_device=None):
        self.log = log
        self.audio_input_device = audio_input_device
        self.bearing_history = deque(maxlen=30)
        self.last_reading = None
        self.calibrated = False
        # Loop orientation: which compass direction does the loop PLANE face
        # This needs to be calibrated by finding the null of a known source
        self.loop_plane_heading = None  # degrees from north
        
    def compute_bearing_from_null(self, signal_samples, fs, freq_of_interest=None):
        """
        Analyze signal from loop antenna to find the null direction.
        
        The null occurs when the loop plane faces the source.
        The peak occurs when the loop is edge-on to the source.
        
        For a stationary loop, we can't rotate it. But we CAN:
        1. Compare the loop signal with the Petterson (omni) signal
        2. If loop signal < Petterson signal at a given frequency,
           the source is in the null direction (loop plane faces it)
        3. If loop signal > Petterson, source is in the peak direction
        """
        if len(signal_samples) < 1024:
            return None
        
        # FFT to find signal levels at different frequencies
        fft = np.abs(np.fft.rfft(signal_samples))
        freqs = np.fft.rfftfreq(len(signal_samples), 1/fs)
        noise = np.median(fft) + 1e-12
        
        # Find strongest carriers
        from scipy.signal import find_peaks
        peaks, props = find_peaks(fft, height=noise*3, distance=5)
        
        if len(peaks) == 0:
            return None
        
        # Get the strongest peak
        strongest = peaks[np.argmax(fft[peaks])]
        freq = freqs[strongest]
        level = fft[strongest] / noise  # SNR
        
        return {
            'freq': freq,
            'snr': level,
            'level_raw': fft[strongest],
            'null_direction': self.loop_plane_heading  # source is in this direction if signal is weak
        }
    
    def compare_loop_vs_omni(self, loop_signal, omni_signal, fs):
        """
        Compare loop antenna signal with omnidirectional Petterson signal.
        
        Key insight: 
        - If loop_signal < omni_signal at a frequency → source is in NULL direction
          (loop plane faces source)
        - If loop_signal > omni_signal → source is in PEAK direction  
          (loop is edge-on to source, which is 90° from loop plane)
        
        This gives us bearing WITHOUT 180° ambiguity!
        """
        if len(loop_signal) < 1024 or len(omni_signal) < 1024:
            return None
        
        min_len = min(len(loop_signal), len(omni_signal))
        loop_fft = np.abs(np.fft.rfft(loop_signal[:min_len]))
        omni_fft = np.abs(np.fft.rfft(omni_signal[:min_len]))
        freqs = np.fft.rfftfreq(min_len, 1/fs)
        
        # Find carriers present in both
        loop_noise = np.median(loop_fft) + 1e-12
        omni_noise = np.median(omni_fft) + 1e-12
        
        # Normalize both FFTs
        loop_norm = loop_fft / loop_noise
        omni_norm = omni_fft / omni_noise
        
        # Find peaks in the omnidirectional signal (real sources)
        from scipy.signal import find_peaks
        peaks, _ = find_peaks(omni_norm, height=3, distance=5)
        
        results = []
        for pk in peaks[:10]:
            freq = freqs[pk]
            if freq < 100: continue
            
            loop_snr = loop_norm[pk]
            omni_snr = omni_norm[pk]
            
            if omni_snr < 3: continue  # not a real signal
            
            # Ratio tells us direction
            # ratio < 1: source in null direction (loop plane faces source)
            # ratio > 1: source in peak direction (edge-on to source)
            # ratio ≈ 1: ambiguous (source at 45° to loop)
            ratio = loop_snr / (omni_snr + 1e-12)
            
            if self.loop_plane_heading is not None:
                if ratio < 0.7:
                    # Source is in NULL direction = loop plane heading
                    bearing = self.loop_plane_heading
                    confidence = 1.0 - ratio
                elif ratio > 1.3:
                    # Source is in PEAK direction = 90° from loop plane
                    bearing = (self.loop_plane_heading + 90) % 360
                    if bearing > 180: bearing -= 360
                    confidence = ratio - 1.0
                else:
                    bearing = None
                    confidence = 0
            else:
                bearing = None
                confidence = 0
            
            results.append({
                'freq': freq,
                'loop_snr': float(loop_snr),
                'omni_snr': float(omni_snr),
                'ratio': float(ratio),
                'bearing': bearing,
                'confidence': float(confidence),
                'direction': 'null' if ratio < 0.7 else ('peak' if ratio > 1.3 else 'ambiguous')
            })
        
        return results
