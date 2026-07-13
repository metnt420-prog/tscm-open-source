"""
Voice Decoder v3 - Captures TSCM's demodulated audio output via Stereo Mix
The TSCM already demodulates MW voice + ultrasound carriers and plays them
through speakers (device 7). Stereo Mix captures everything the sound card outputs.
We just need to grab it and run Whisper on it.

This avoids competing with TSCM for the Petterson mic.
"""
import numpy as np
import sounddevice as sd
from scipy.io import wavfile
from scipy.signal import butter, sosfiltfilt, resample_poly
from collections import deque
import threading
import time
import json
import os
import sys
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

WS = r'C:\Users\carpe\.openclaw-autoclaw\workspace'
OUTPUT_DIR = WS + '\\decoded_voice'
WAV_DIR = OUTPUT_DIR + '\\wav'
os.makedirs(WAV_DIR, exist_ok=True)
VOICE_LOG = WS + '\\models\\decoded_voice_log.json'

# Config
LAPTOP_MIC_DEVICE = 21  # Intel Smart Sound mic array, 4ch, 48kHz
LAPTOP_MIC_FS = 48000
CAPTURE_SECONDS = 15    # 15s segments for Whisper
WHISPER_MODEL = 'base'

# Carriers detected on laptop mic array
# Ch 1 shows 669-676 Hz PLC command band
# Ch 0 shows 60/120 Hz mains (injection locking)
# Also try standard MW voice demod bands
DEMOD_BANDS = [
    ('baseband_voice', 100, 4000),       # Full voice band
    ('plc_voice', 500, 1000),             # PLC command band (669-676Hz seen)
    ('vlf_voice', 30, 300),               # VLF / ELF voice carrier
    ('ultrasound_19k', 18500, 20000),     # 19.5kHz silent sound carrier (near Nyquist)
    ('mid_us', 6000, 10000),              # Mid-ultrasound (eardrum_capture band)
    ('low_us', 2000, 6000),              # Low ultrasound (C2 BPSK band)
]


class VoiceDecoder:
    def __init__(self):
        self.running = False
        self.audio_buf = deque(maxlen=LAPTOP_MIC_FS * 120)  # 2 min buffer
        self.lock = threading.Lock()
        self.fs = LAPTOP_MIC_FS
        self.whisper_model = None
        self.decode_count = 0
        self.words_found = 0
        self.stream = None
        self.device_used = None

    def load_whisper(self):
        print('[VOICE] Loading Whisper %s...' % WHISPER_MODEL)
        import whisper
        self.whisper_model = whisper.load_model(WHISPER_MODEL)
        print('[VOICE] Whisper ready')

    def audio_callback(self, indata, frames, time_info, status):
        # Use channel 1 (PLC/voice band active) or channel 0
        with self.lock:
            ch1 = indata[:, 1] if indata.shape[1] > 1 and np.max(np.abs(indata[:, 1])) > 0.0001 else indata[:, 0]
            self.audio_buf.extend(ch1)

    def start_capture(self):
        # Try Stereo Mix first (captures TSCM speaker output)
        for dev_id, name in [(21, 'Laptop mic array'), (19, 'Realtek mic')]:
            try:
                fs = 48000
                ch = 4 if dev_id == 21 else 2
                self.stream = sd.InputStream(
                    device=dev_id, samplerate=fs, channels=ch, dtype='float32',
                    blocksize=fs // 5, callback=self.audio_callback
                )
                self.stream.start()
                self.device_used = name
                print('[VOICE] Capturing from %s (dev %d) at %d Hz' % (name, dev_id, fs))
                return True
            except Exception as e:
                print('[VOICE] Dev %d (%s) failed: %s' % (dev_id, name, str(e)[:80]))
        return False

    def transcribe(self, audio_16k):
        if self.whisper_model is None:
            return ''
        min_samples = 30 * 16000
        if len(audio_16k) < min_samples:
            audio_16k = np.pad(audio_16k, (0, min_samples - len(audio_16k)))
        try:
            result = self.whisper_model.transcribe(audio_16k, fp16=False, language='en')
            return result.get('text', '').strip()
        except:
            return ''

    def process_segment(self):
        with self.lock:
            if len(self.audio_buf) < self.fs * CAPTURE_SECONDS:
                return None
            audio = np.array(list(self.audio_buf)[-self.fs * CAPTURE_SECONDS:])

        fs = self.fs
        results = {}

        # Demodulate each band
        for band_name, lo, hi in DEMOD_BANDS:
            nyq = fs / 2
            if lo >= nyq or hi >= nyq or lo <= 0:
                continue
            wlo = lo / nyq
            whi = min(hi / nyq, 0.99)
            if wlo <= 0 or whi >= 1 or wlo >= whi:
                continue
            try:
                sos = butter(6, [wlo, whi], btype='band', output='sos')
                filtered = sosfiltfilt(sos, audio)
                # Hilbert envelope demodulation
                analytic = hilbert(filtered)
                envelope = np.abs(analytic)
                # Low-pass to voice
                vlo = 100 / nyq
                vhi = min(3400 / nyq, 0.99)
                if vlo > 0 and vhi < 1:
                    sos_v = butter(6, [vlo, vhi], btype='band', output='sos')
                    voice = sosfiltfilt(sos_v, envelope)
                else:
                    voice = envelope
                # Normalize
                peak = np.max(np.abs(voice))
                if peak > 0:
                    voice = voice / peak * 0.8  # leave headroom
                demod_16k = resample_poly(voice, 16000, fs).astype(np.float32)
                results[band_name] = demod_16k
            except:
                continue

        # Also try raw audio bandpass to voice (for direct audible speech)
        try:
            nyq = fs / 2
            sos_raw = butter(6, [100 / nyq, min(4000 / nyq, 0.99)], btype='band', output='sos')
            raw_voice = sosfiltfilt(sos_raw, audio)
            raw_16k = resample_poly(raw_voice, 16000, fs).astype(np.float32)
            peak = np.max(np.abs(raw_16k))
            if peak > 0:
                raw_16k = raw_16k / peak * 0.8
            results['raw_voice'] = raw_16k
        except:
            pass

        # Mix all demodulated channels
        if results:
            max_len = max(len(v) for v in results.values())
            mixed = np.zeros(max_len, dtype=np.float32)
            count = 0
            for audio_ch in results.values():
                if len(audio_ch) == max_len:
                    mixed += audio_ch
                else:
                    mixed += np.pad(audio_ch, (0, max_len - len(audio_ch)))
                count += 1
            if count > 0:
                mixed /= count
            results['mixed'] = mixed

        return results

    def run(self):
        self.running = True
        print('[VOICE] Waiting for buffer (%ds)...' % CAPTURE_SECONDS)
        while self.running and len(self.audio_buf) < self.fs * CAPTURE_SECONDS:
            time.sleep(1)
        print('[VOICE] Buffer filled, decoding every %ds' % CAPTURE_SECONDS)

        last_save_time = 0

        while self.running:
            try:
                results = self.process_segment()
                if results is None:
                    time.sleep(2)
                    continue

                self.decode_count += 1
                all_text = []

                for key in ['mixed', 'baseband_voice', 'plc_voice', 'raw_voice', 'vlf_voice',
                            'ultrasound_19k', 'mid_us', 'low_us']:
                    if key in results:
                        text = self.transcribe(results[key])
                        if text and len(text) > 2:
                            words = [w for w in text.split() if len(w) > 1]
                            if len(words) >= 2:
                                all_text.append((key, text))

                timestamp = datetime.now().isoformat()

                if all_text:
                    self.words_found += sum(len(t.split()) for _, t in all_text)
                    record = {
                        'timestamp': timestamp,
                        'decode_count': self.decode_count,
                        'source': self.device_used,
                        'transcriptions': [{'channel': k, 'text': t} for k, t in all_text],
                        'total_words': self.words_found
                    }

                    try:
                        existing = json.loads(open(VOICE_LOG).read()) if os.path.exists(VOICE_LOG) else []
                    except:
                        existing = []
                    existing.append(record)
                    with open(VOICE_LOG, 'w') as f:
                        json.dump(existing, f, indent=2)

                    # Save WAV of mixed channel
                    if 'mixed' in results:
                        vf = results['mixed']
                        peak = np.max(np.abs(vf))
                        if peak > 0:
                            vf = vf / peak * 32767
                        wav_path = WAV_DIR + '\\decoded_%s.wav' % datetime.now().strftime('%Y%m%d_%H%M%S')
                        wavfile.write(wav_path, 16000, vf.astype(np.int16))

                    for key, text in all_text:
                        print('[VOICE] %s: %s' % (key, text))
                else:
                    if self.decode_count % 12 == 0:
                        print('[VOICE] #%d: listening... (%d total words so far)' % (self.decode_count, self.words_found))

                time.sleep(CAPTURE_SECONDS)

            except Exception as e:
                print('[VOICE] Error: %s' % str(e)[:120])
                time.sleep(5)

    def stop(self):
        self.running = False
        if self.stream:
            self.stream.stop()
            self.stream.close()


def main():
    print('=' * 50)
    print('MW VOICE / SILENT SOUND DECODER v3')
    print('Source: Stereo Mix (TSCM speaker output)')
    print('Demod: TSCM does it -> we capture output -> Whisper')
    print('=' * 50)

    dec = VoiceDecoder()
    dec.load_whisper()

    if not dec.start_capture():
        print('FATAL: Cannot start audio capture')
        return

    try:
        dec.run()
    except KeyboardInterrupt:
        dec.stop()
        print('Stopped. %d words in %d decodes' % (dec.words_found, dec.decode_count))

if __name__ == '__main__':
    main()
