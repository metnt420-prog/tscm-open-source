"""
Whisper Transcriber v2 - sync, reliable, plugs into TSCM Petterson pipeline.
"""
import numpy as np
from scipy.signal import resample_poly
from scipy.io import wavfile
from collections import deque
import json, os, hashlib, time
from datetime import datetime

WS = r'C:\Users\carpe\.openclaw-autoclaw\workspace'
VOICE_DIR = WS + '\\transcribed_voice'
os.makedirs(VOICE_DIR, exist_ok=True)
TRANSCRIPT_LOG = WS + '\\models\\transcribed_voice_evidence.json'

class WhisperTranscriber:
    def __init__(self, model_name='tiny'):
        self.model_name = model_name
        self.model = None
        self.audio_buffer = deque()
        self.total_words = 0
        self.decode_count = 0
        self.chain_hash = hashlib.sha256(b'GENESIS_VOICE').hexdigest()[:16]
        self.last_decode_time = 0
        self._load_attempted = False

    def _load_model(self):
        if self._load_attempted:
            return
        self._load_attempted = True
        try:
            import whisper
            self.model = whisper.load_model(self.model_name)
            print('[WHISPER] Model %s loaded' % self.model_name)
        except Exception as e:
            print('[WHISPER] Load error: %s' % str(e)[:120])

    def feed(self, audio, fs):
        """Feed demodulated audio. Transcribes when 30s accumulated."""
        # Lazy-load model on first feed
        if self.model is None and not self._load_attempted:
            self._load_model()
        
        if self.model is None or audio is None or len(audio) == 0:
            return

        audio = np.array(audio, dtype=np.float32).flatten()
        audio = audio[np.isfinite(audio)]
        if len(audio) < 100:
            return

        # Normalize and resample to 16kHz
        peak = np.max(np.abs(audio))
        if peak > 1e-10:
            audio = audio / peak
        if fs != 16000:
            n = int(len(audio) * 16000 / fs)
            try:
                audio = resample_poly(audio, 16000, fs).astype(np.float32)
            except:
                return

        # Accumulate
        self.audio_buffer.extend(audio.tolist())

        # Transcribe when we have 30+ seconds (don't do it too often)
        now = time.time()
        if len(self.audio_buffer) >= 30 * 16000 and (now - self.last_decode_time) > 30:
            self.last_decode_time = now
            segment = np.array(list(self.audio_buffer)[:30 * 16000], dtype=np.float32)
            # Keep last 5s for overlap
            self.audio_buffer = deque(list(self.audio_buffer)[25 * 16000:])
            try:
                self._transcribe(segment)
            except Exception as e:
                print('[WHISPER] Transcribe error: %s' % str(e)[:120])

    def _transcribe(self, audio_16k):
        """Run Whisper and log."""
        if self.model is None or len(audio_16k) < 30 * 16000:
            return

        try:
            result = self.model.transcribe(audio_16k, fp16=False, language='en')
            text = result.get('text', '').strip()
        except Exception as e:
            return

        if not text or len(text) < 4:
            return

        # Filter known hallucinations
        if text.startswith('Thanks for') or text.startswith('Thank you'):
            if len(text.split()) <= 5:
                return
        if text == 'you' or text == 'you you':
            return

        words = len(text.split())
        if words < 3:
            return

        self.decode_count += 1
        self.total_words += words
        timestamp = datetime.now().isoformat()

        # Save WAV
        wav_name = 'voice_%s_%04d.wav' % (datetime.now().strftime('%Y%m%d_%H%M%S'), self.decode_count)
        wav_path = os.path.join(VOICE_DIR, wav_name)
        wav_int = (audio_16k * 32767).clip(-32768, 32767).astype(np.int16)
        wavfile.write(wav_path, 16000, wav_int)

        # Hash chain
        data_str = json.dumps({'text': text, 'ts': timestamp, 'prev': self.chain_hash})
        self.chain_hash = hashlib.sha256(data_str.encode()).hexdigest()[:16]

        record = {
            'timestamp': timestamp,
            'decode_id': self.decode_count,
            'text': text,
            'words': words,
            'total_words': self.total_words,
            'wav_file': wav_name,
            'chain_hash': self.chain_hash,
        }

        try:
            existing = json.loads(open(TRANSCRIPT_LOG).read()) if os.path.exists(TRANSCRIPT_LOG) else []
        except:
            existing = []
        existing.append(record)
        with open(TRANSCRIPT_LOG, 'w') as f:
            json.dump(existing, f, indent=2)

        print('[VOICE] #%d (%d words): %s' % (self.decode_count, words, text[:150]))

    def stop(self):
        pass
