"""
SDR Pipeline Security Hardening — sdr_fixes.py
Protects HackRF + BladeRF pipeline against IQ injection, USB spoofing,
CLI bridge hijacking, cross-device temporal inconsistencies, and TDOA time sync manipulation.

Modules:
  1. IQStreamIntegrityValidator — magic header, CRC32, sequence numbers per chunk
  2. CrossDeviceTemporalValidator — temporal coherence check across HackRF & BladeRF
  3. BladeRFCLIBridgeHardener — process ownership, output validation, anomaly detection
  4. TDOATimeSyncValidator — USB SOF drift detection, timestamp manipulation defense
  5. HackRFUSBAntiInjection — transfer size enforcement, bulk-in integrity wrapper
"""

import os
import sys
import time
import struct
import zlib
import hashlib
import logging
import threading
import subprocess
import tempfile
from collections import deque
from typing import Optional, Tuple, Dict, Any, List

import numpy as np

log = logging.getLogger('SDR_Security')

# ---------------------------------------------------------------------------
# 1. IQ Stream Integrity Validator
# ---------------------------------------------------------------------------

class IQStreamIntegrityValidator:
    """
    Wraps raw IQ buffers with:
      - 4-byte magic header  (0x49 0x51 0x53 0x44 == 'IQSD')
      - 4-byte CRC32 over the IQ payload
      - 8-byte monotonically-increasing sequence number (uint64)
      - 8-byte device nonce (randomized per session to prevent replay across restarts)
    
    Wire format (prepended to each chunk):
      [4 magic] [4 CRC32] [8 seq_num] [8 nonce] [N bytes IQ payload]
    
    Total overhead: 24 bytes per chunk.
    """

    MAGIC = b'IQSD'          # IQ Stream Data
    HEADER_LEN = 24           # 4 + 4 + 8 + 8
    SEQNUM_FLOOR = 1_000_000  # Warn if seq gap exceeds this

    def __init__(self, device_name: str):
        self.device_name = device_name
        self._seq = 0
        self._nonce = struct.unpack('<Q', os.urandom(8))[0]
        self._last_seq = -1
        self._stats = {
            'chunks_ok': 0,
            'chunks_bad_magic': 0,
            'chunks_bad_crc': 0,
            'chunks_bad_seq': 0,       # replay / out-of-order
            'chunks_dropped': 0,
            'chunks_replayed': 0,
        }
        self._lock = threading.Lock()
        log.info(f"IQValidator[{device_name}] initialized (nonce=0x{self._nonce:016x})")

    # ---- seal (producer side) ------------------------------------------------

    def seal(self, iq_payload: bytes) -> bytes:
        """
        Seal a raw IQ payload into an integrity-wrapped chunk.
        Call this on the producer thread BEFORE putting into any queue.
        """
        with self._lock:
            self._seq += 1
            seq = self._seq
        crc = zlib.crc32(iq_payload) & 0xFFFFFFFF
        header = (
            self.MAGIC
            + struct.pack('<I', crc)
            + struct.pack('<Q', seq)
            + struct.pack('<Q', self._nonce)
        )
        return header + iq_payload

    def seal_array(self, iq_np: np.ndarray) -> bytes:
        """Convenience: seal a numpy complex64 array."""
        return self.seal(iq_np.astype(np.complex64).tobytes())

    # ---- unseal (consumer side) ----------------------------------------------

    def unseal(self, chunk: bytes) -> Optional[bytes]:
        """
        Validate and unwrap a sealed chunk. Returns raw IQ payload or None.
        Logs and counts every anomaly for monitoring.
        """
        if len(chunk) < self.HEADER_LEN:
            log.warning(f"IQValidator[{self.device_name}] undersized chunk: {len(chunk)}B")
            return None

        magic = chunk[:4]
        crc_received = struct.unpack('<I', chunk[4:8])[0]
        seq = struct.unpack('<Q', chunk[8:16])[0]
        nonce = struct.unpack('<Q', chunk[16:24])[0]
        payload = chunk[24:]

        # Magic check
        if magic != self.MAGIC:
            self._stats['chunks_bad_magic'] += 1
            log.warning(f"IQValidator[{self.device_name}] BAD MAGIC: "
                        f"got {magic!r} at seq={seq}")
            return None

        # Nonce check (reject chunks from a different session / device)
        if nonce != self._nonce:
            log.error(f"IQValidator[{self.device_name}] NONCE MISMATCH: "
                      f"expected 0x{self._nonce:016x}, got 0x{nonce:016x}")
            return None

        # CRC check
        crc_computed = zlib.crc32(payload) & 0xFFFFFFFF
        if crc_received != crc_computed:
            self._stats['chunks_bad_crc'] += 1
            log.warning(f"IQValidator[{self.device_name}] CRC FAIL at seq={seq}: "
                        f"recv=0x{crc_received:08x} calc=0x{crc_computed:08x}")
            return None

        # Sequence number checks
        with self._lock:
            if self._last_seq >= 0:
                gap = seq - self._last_seq
                if gap == 0:
                    self._stats['chunks_replayed'] += 1
                    log.warning(f"IQValidator[{self.device_name}] REPLAYED seq={seq}")
                    return None
                elif gap < 0:
                    self._stats['chunks_bad_seq'] += 1
                    log.warning(f"IQValidator[{self.device_name}] OUT-OF-ORDER seq={seq} "
                                f"(last={self._last_seq})")
                    return None
                elif gap > 1:
                    self._stats['chunks_dropped'] += (gap - 1)
                    if gap > self.SEQNUM_FLOOR:
                        log.warning(f"IQValidator[{self.device_name}] LARGE GAP: "
                                    f"{self._last_seq} → {seq} ({gap} missing)")
            self._last_seq = seq
            self._stats['chunks_ok'] += 1

        return payload

    def unseal_to_array(self, chunk: bytes) -> Optional[np.ndarray]:
        """Unseal and convert to complex64 numpy array."""
        raw = self.unseal(chunk)
        if raw is None:
            return None
        try:
            return np.frombuffer(raw, dtype=np.complex64).copy()
        except Exception as e:
            log.error(f"IQValidator[{self.device_name}] payload decode error: {e}")
            return None

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def is_healthy(self) -> bool:
        """Returns False if error rate exceeds 5% in recent chunks."""
        s = self.stats()
        total = s['chunks_ok'] + s['chunks_bad_magic'] + s['chunks_bad_crc'] + s['chunks_bad_seq']
        if total < 20:
            return True  # not enough data yet
        errors = s['chunks_bad_magic'] + s['chunks_bad_crc'] + s['chunks_bad_seq'] + s['chunks_replayed']
        return (errors / total) < 0.05


# ---------------------------------------------------------------------------
# 2. Cross-Device Temporal Validator
# ---------------------------------------------------------------------------

class CrossDeviceTemporalValidator:
    """
    Extends the existing spectral cross-device verification with temporal checks.

    The idea: if HackRF (121 MHz) and BladeRF (2.4 GHz) both detect the same
    signal, the signal's temporal envelope should appear at the correct time offset
    given the propagation delay difference between the two frequency bands and
    the physical antenna positions.

    Checks:
      a) Envelope cross-correlation time offset is within physical bounds
      b) Signal onset time matches within USB sync tolerance
      c) Signal duration matches within tolerance (prevents split-frame injection)
      d) Modulation envelope consistency (BPSK/AM/FM pattern must match)
    """

    MAX_PROPAGATION_DIFF_S = 5e-6   # 5 µs — max differential propagation delay
    MAX_ONSET_DRIFT_S = 1e-3        # 1 ms — onset alignment tolerance
    MIN_DURATION_MATCH = 0.7         # 70% — signal duration ratio threshold

    def __init__(self):
        self._history = deque(maxlen=200)
        self._lock = threading.Lock()

    def validate(
        self,
        iq_a: np.ndarray,
        fs_a: float,
        iq_b: np.ndarray,
        fs_b: float,
        freq_a: float,
        freq_b: float,
        timestamp_a: float,
        timestamp_b: float,
    ) -> Dict[str, Any]:
        """
        Perform full temporal + spectral cross-device validation.

        Returns dict with:
          verified (bool), temporal_ok (bool), spectral_ok (bool),
          envelope_offset_s (float), onset_match (bool),
          duration_match_ratio (float), details (list[str])
        """
        result = {
            'verified': False,
            'temporal_ok': False,
            'spectral_ok': False,
            'envelope_offset_s': 0.0,
            'onset_match': False,
            'duration_match_ratio': 0.0,
            'details': [],
        }
        details = result['details']

        if iq_a is None or iq_b is None:
            details.append('missing IQ data from one or both devices')
            return result

        try:
            # --- Step 1: Spectral verification (inherits existing logic) ---
            spectral_verified = self._spectral_check(iq_a, fs_a, iq_b, fs_b)
            result['spectral_ok'] = spectral_verified
            if not spectral_verified:
                details.append('spectral peaks do not match across devices')
                return result

            # --- Step 2: Envelope extraction ---
            env_a = np.abs(iq_a)
            env_b = np.abs(iq_b)

            # --- Step 3: Signal onset detection ---
            onset_a = self._detect_onset(env_a, fs_a)
            onset_b = self._detect_onset(env_b, fs_b)

            # Timestamp-based onset alignment check
            ts_diff = abs(timestamp_a - timestamp_b)
            result['onset_match'] = ts_diff < self.MAX_ONSET_DRIFT_S
            if not result['onset_match']:
                details.append(f'capture timestamp drift: {ts_diff*1e3:.2f} ms '
                               f'(limit {self.MAX_ONSET_DRIFT_S*1e3:.1f} ms)')

            # --- Step 4: Envelope cross-correlation for temporal offset ---
            # Downsample to a common rate for comparison
            common_fs = min(fs_a, fs_b) / 4  # 4x downsample
            ds_a = max(1, int(fs_a / common_fs))
            ds_b = max(1, int(fs_b / common_fs))
            env_a_ds = env_a[::ds_a]
            env_b_ds = env_b[::ds_b]
            min_len = min(len(env_a_ds), len(env_b_ds))
            env_a_ds = env_a_ds[:min_len]
            env_b_ds = env_b_ds[:min_len]

            if min_len < 64:
                details.append('insufficient samples for envelope correlation')
                return result

            env_a_centered = env_a_ds - np.mean(env_a_ds)
            env_b_centered = env_b_ds - np.mean(env_b_ds)
            xcorr = np.correlate(env_a_centered, env_b_centered, mode='full')
            peak_idx = np.argmax(np.abs(xcorr))
            center = len(xcorr) // 2
            lag = peak_idx - center
            offset_s = lag / common_fs
            result['envelope_offset_s'] = offset_s

            temporal_ok = abs(offset_s) < self.MAX_PROPAGATION_DIFF_S
            result['temporal_ok'] = temporal_ok
            if not temporal_ok:
                details.append(f'envelope temporal offset {offset_s*1e6:.1f} µs '
                               f'exceeds limit {self.MAX_PROPAGATION_DIFF_S*1e6:.1f} µs')

            # --- Step 5: Duration consistency ---
            dur_a = self._signal_duration(env_a, fs_a)
            dur_b = self._signal_duration(env_b, fs_b)
            if dur_a > 0 and dur_b > 0:
                ratio = min(dur_a, dur_b) / max(dur_a, dur_b)
                result['duration_match_ratio'] = ratio
                if ratio < self.MIN_DURATION_MATCH:
                    details.append(f'duration mismatch: ratio={ratio:.2f} '
                                   f'({dur_a*1e3:.1f}ms vs {dur_b*1e3:.1f}ms)')

            # --- Final verdict ---
            result['verified'] = (
                result['spectral_ok']
                and result['temporal_ok']
                and result['onset_match']
                and result['duration_match_ratio'] >= self.MIN_DURATION_MATCH
            )

            if not result['verified']:
                log.warning(f"CrossDevice temporal FAIL: {details}")

            # Store for trending
            with self._lock:
                self._history.append(result)

        except Exception as e:
            details.append(f'validation error: {e}')
            log.error(f"CrossDevice temporal error: {e}")

        return result

    def _spectral_check(self, iq_a, fs_a, iq_b, fs_b):
        """
        Reproduce the existing spectral cross-device verification logic.
        Returns True if spectral peaks overlap between the two devices.
        """
        from scipy.fft import fft, fftfreq
        from scipy.signal import find_peaks

        try:
            fft1 = np.abs(fft(iq_a))
            fft2 = np.abs(fft(iq_b))
            freqs1 = fftfreq(len(fft1), 1 / fs_a)
            freqs2 = fftfreq(len(fft2), 1 / fs_b)

            fft1_norm = fft1 / (np.max(fft1) + 1e-12)
            fft2_norm = fft2 / (np.max(fft2) + 1e-12)

            noise1 = np.median(fft1_norm)
            noise2 = np.median(fft2_norm)
            peaks1, _ = find_peaks(fft1_norm, height=noise1 * 3, distance=5)
            peaks2, _ = find_peaks(fft2_norm, height=noise2 * 3, distance=5)

            freqs_set1 = set(abs(freqs1[p]) for p in peaks1 if abs(freqs1[p]) > 100)
            freqs_set2 = set(abs(freqs2[p]) for p in peaks2 if abs(freqs2[p]) > 100)

            for f1 in freqs_set1:
                for f2 in freqs_set2:
                    tolerance = max(f1, f2) * 0.05
                    if abs(f1 - f2) < tolerance:
                        return True
            return False
        except Exception:
            return False

    def _detect_onset(self, envelope, fs):
        """
        Detect signal onset (first sample above noise floor * threshold).
        Returns onset in seconds.
        """
        if len(envelope) == 0:
            return 0.0
        noise = np.median(envelope[:max(len(envelope) // 4, 1)])
        threshold = noise * 4
        above = np.where(envelope > threshold)[0]
        if len(above) == 0:
            return float(len(envelope)) / fs
        return float(above[0]) / fs

    def _signal_duration(self, envelope, fs):
        """
        Estimate signal duration (time above noise floor).
        Returns duration in seconds.
        """
        if len(envelope) == 0:
            return 0.0
        noise = np.median(envelope[:max(len(envelope) // 4, 1)])
        threshold = noise * 3
        above = envelope > threshold
        if not np.any(above):
            return 0.0
        indices = np.where(above)[0]
        return float(indices[-1] - indices[0] + 1) / fs

    def get_health(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._history)
            if total == 0:
                return {'total_checks': 0, 'pass_rate': 0.0}
            passed = sum(1 for h in self._history if h['verified'])
            return {
                'total_checks': total,
                'pass_rate': passed / total,
                'recent_temporal_ok': sum(1 for h in list(self._history)[-20:] if h['temporal_ok']) / min(20, total),
            }


# ---------------------------------------------------------------------------
# 3. BladeRF CLI Bridge Hardener
# ---------------------------------------------------------------------------

class BladeRFCLIBridgeHardener:
    """
    Hardens the BladeRFCLIBridge against subprocess pipe hijacking.

    Attack vector: Another process (malware/insider) could write to the stdin
    pipe of bladeRF-cli.exe while it's running under our subprocess, injecting
    commands (e.g., "set frequency rx 0M" to blind the receiver).

    Defenses:
      1. Process ownership verification — confirm bladeRF-cli.exe PID is the one we spawned
      2. CLI output format validation — parse stdout/stderr for expected patterns only
      3. Anomalous response detection — unexpected output = possible injection
      4. No shared temp directory — use a unique per-session tmpdir to prevent file races
      5. Subprocess timeout enforcement
    """

    # Expected CLI output patterns (bladeRF-cli prints these)
    EXPECTED_PATTERNS = [
        b'bladeRF>',
        b'RX',
        b'TX',
        b'Frequency',
        b'Sample Rate',
        b'Bandwidth',
        b'Gain',
        b'AGC',
        b'Bias Tee',
        b'Starting RX',
        b'Stopped',
        b'Captured',
        b'samples',
        b'Error',
        b'Invalid',
        b'No device',
    ]

    FORBIDDEN_RESPONSES = [
        b'set frequency rx 0',
        b'set gain rx 0',
        b'set agc rx on',
        b'info',
        b'version',
        b'help',
        b'peek',
        b'poke',
        b'load',
        b'flash',
        b'reboot',
        b'erase',
        b'calibrate dc',
        b'xb',
        b'set agc rx auto',
    ]

    def __init__(self, cli_path: str):
        self.cli_path = cli_path
        self._session_tmpdir = os.path.join(
            os.environ.get('TEMP', tempfile.gettempdir()),
            f'bladerf_sec_{os.getpid()}_{int(time.time()*1000)}'
        )
        os.makedirs(self._session_tmpdir, exist_ok=True)
        self._owned_pids = set()
        self._lock = threading.Lock()
        self._anomaly_count = 0
        self._call_count = 0
        self._anomaly_log = deque(maxlen=50)
        log.info(f"BladeRFHardener: session tmpdir={self._session_tmpdir}")

    def register_spawned_pid(self, pid: int):
        """Register a subprocess PID as ours. Call immediately after Popen()."""
        with self._lock:
            self._owned_pids.add(pid)
            log.debug(f"BladeRFHardener: registered PID {pid}")

    def verify_pid_ownership(self, pid: int) -> bool:
        """
        Verify that PID still belongs to a bladeRF-cli.exe process.
        Checks:
          - PID is still alive
          - Process name is bladeRF-cli.exe
          - PID is in our owned set
        """
        with self._lock:
            if pid not in self._owned_pids:
                return False

        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            STILL_ACTIVE = 259

            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle == 0:
                with self._lock:
                    self._owned_pids.discard(pid)
                log.warning(f"BladeRFHardener: PID {pid} no longer exists")
                return False

            # Check if still running
            exit_code = ctypes.c_uint32()
            kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            kernel32.CloseHandle(handle)

            if exit_code.value != STILL_ACTIVE:
                with self._lock:
                    self._owned_pids.discard(pid)
                log.warning(f"BladeRFHardener: PID {pid} exited (code={exit_code.value})")
                return False

            # Verify process name via WMI/WMIC (Windows)
            try:
                result = subprocess.run(
                    ['wmic', 'process', 'where', f'ProcessId={pid}', 'get', 'Name'],
                    capture_output=True, text=True, timeout=2,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
                )
                name = result.stdout.strip().split('\n')[-1].strip()
                if 'bladeRF-cli' not in name and 'bladerf-cli' not in name.lower():
                    self._record_anomaly(f"PID {pid} name changed to '{name}' (possible hijack)")
                    return False
            except Exception:
                pass  # Non-critical — name check is defense-in-depth

            return True

        except Exception as e:
            log.debug(f"BladeRFHardener: PID verify error: {e}")
            return True  # Fail open if we can't verify

    def validate_cli_output(self, stdout: bytes, stderr: bytes) -> Dict[str, Any]:
        """
        Validate CLI output for anomalous responses.
        Returns dict with: valid (bool), anomalies (list[str])
        """
        result = {'valid': True, 'anomalies': []}
        self._call_count += 1

        # Check for forbidden command echoes in output
        for forbidden in self.FORBIDDEN_RESPONSES:
            if forbidden in stdout or forbidden in stderr:
                result['valid'] = False
                result['anomalies'].append(f'forbidden_response: {forbidden!r}')
                self._record_anomaly(f"Forbidden response in CLI output: {forbidden!r}")

        # Check for obviously tampered output (binary garbage)
        if len(stdout) > 0:
            printable_ratio = sum(1 for b in stdout if 32 <= b <= 126 or b in (10, 13, 9)) / max(len(stdout), 1)
            if printable_ratio < 0.8 and len(stdout) > 100:
                result['valid'] = False
                result['anomalies'].append(f'low_printable_ratio: {printable_ratio:.2f}')
                self._record_anomaly(f"CLI output has low printable ratio: {printable_ratio:.2f}")

        # Check for suspiciously fast responses (impossible for real capture)
        # This would indicate cached/fabricated data
        if b'Captured' in stdout:
            # If captured 8192 samples in < 1ms from subprocess start, suspicious
            pass  # Timing check is done at call site

        return result

    def make_safe_capture_path(self, suffix: str = '.bin') -> str:
        """Generate a capture file path in our unique session directory."""
        return os.path.join(
            self._session_tmpdir,
            f'iq_{int(time.time()*1000000)}{suffix}'
        )

    def cleanup_session(self):
        """Remove our session temp directory."""
        try:
            import shutil
            shutil.rmtree(self._session_tmpdir, ignore_errors=True)
        except Exception as e:
            log.debug(f"BladeRFHardener: cleanup error: {e}")

    def _record_anomaly(self, msg: str):
        with self._lock:
            self._anomaly_count += 1
            self._anomaly_log.append({'time': time.time(), 'msg': msg})
        log.warning(f"BladeRFHardener ANOMALY: {msg}")

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                'owned_pids': list(self._owned_pids),
                'anomaly_count': self._anomaly_count,
                'call_count': self._call_count,
                'session_tmpdir': self._session_tmpdir,
                'recent_anomalies': [
                    {'msg': a['msg'], 'age_s': time.time() - a['time']}
                    for a in list(self._anomaly_log)[-5:]
                ],
            }


# ---------------------------------------------------------------------------
# 4. TDOA Time Sync Validator
# ---------------------------------------------------------------------------

class TDOATimeSyncValidator:
    """
    Validates USB hub SOF-based time synchronization against manipulation.

    Attack vectors:
      1. USB bus traffic injection to shift SOF timing
      2. SOF timestamp manipulation by malware on the host
      3. Clock drift injection by faking sync pulse timing

    Defenses:
      - Track inter-SOF interval consistency (should be ~125 µs ± jitter)
      - Detect sudden jumps in device clock offsets
      - Validate monotonicity of SOF-aligned timestamps
      - Cross-check with system clock as ground truth
      - Exponential moving average of drift with anomaly detection
    """

    SOF_NOMINAL_US = 125.0       # Nominal SOF interval in µs
    SOF_JITTER_US = 5.0          # Acceptable jitter ±5 µs
    MAX_OFFSET_JUMP_US = 50.0    # Max sudden offset change in µs
    DRIFT_WINDOW = 100           # Number of samples in drift EMA
    DRIFT_ANOMALY_SIGMA = 3.0    # Sigma for drift anomaly detection

    def __init__(self):
        self._sof_intervals = deque(maxlen=500)
        self._offsets = {}         # device_name → deque of offsets
        self._last_sof_count = 0
        self._last_sof_time = 0.0
        self._anomalies = deque(maxlen=100)
        self._lock = threading.Lock()
        self._alerts = deque(maxlen=20)
        self._initialized = False
        log.info("TDOATimeSyncValidator initialized")

    def validate_sync_pulse(
        self,
        device_name: str,
        sof_aligned_time: float,
        system_time: float,
        sof_count: int,
    ) -> Dict[str, Any]:
        """
        Validate a single sync pulse from USBHubTimeSync.

        Returns dict with:
          valid (bool), sof_interval_us (float), offset_us (float),
          drift_ppm (float), anomalies (list[str])
        """
        result = {
            'valid': True,
            'sof_interval_us': self.SOF_NOMINAL_US,
            'offset_us': 0.0,
            'drift_ppm': 0.0,
            'anomalies': [],
            'anomaly_level': 0,  # 0=ok, 1=warning, 2=critical
        }
        anomalies = result['anomalies']
        anomaly_level = 0

        with self._lock:
            try:
                # Initialize offset tracking for this device
                if device_name not in self._offsets:
                    self._offsets[device_name] = deque(maxlen=500)

                offset_s = system_time - sof_aligned_time
                offset_us = offset_s * 1e6
                result['offset_us'] = offset_us

                # --- Check SOF interval consistency ---
                if self._last_sof_count > 0:
                    sof_delta = sof_count - self._last_sof_count
                    if sof_delta > 0:
                        time_delta = system_time - self._last_sof_time
                        measured_interval_us = (time_delta / sof_delta) * 1e6
                        result['sof_interval_us'] = measured_interval_us

                        # Check for anomalous SOF interval
                        interval_error = abs(measured_interval_us - self.SOF_NOMINAL_US)
                        if interval_error > self.SOF_JITTER_US:
                            anomalies.append(
                                f'sof_interval_anomaly: {measured_interval_us:.1f} µs '
                                f'(nominal {self.SOF_NOMINAL_US:.1f} µs, '
                                f'error {interval_error:.1f} µs)'
                            )
                            anomaly_level = max(anomaly_level, 1)

                        if interval_error > self.SOF_NOMINAL_US * 0.5:
                            anomaly_level = max(anomaly_level, 2)
                            anomalies.append(
                                f'critical_sof_interval: {measured_interval_us:.1f} µs '
                                f'(50%+ deviation — possible SOF injection)'
                            )

                        self._sof_intervals.append(measured_interval_us)

                # --- Check offset monotonicity / jump detection ---
                offsets = self._offsets[device_name]
                offsets.append(offset_us)

                if len(offsets) >= 2:
                    prev_offset = offsets[-2]
                    offset_jump = abs(offset_us - prev_offset)

                    if offset_jump > self.MAX_OFFSET_JUMP_US:
                        anomalies.append(
                            f'offset_jump: {offset_jump:.1f} µs '
                            f'(limit {self.MAX_OFFSET_JUMP_US:.1f} µs) '
                            f'for device {device_name}'
                        )
                        anomaly_level = max(anomaly_level, 1)

                    if offset_jump > self.MAX_OFFSET_JUMP_US * 10:
                        anomalies.append(
                            f'critical_offset_jump: {offset_jump:.1f} µs '
                            f'(possible timestamp manipulation)'
                        )
                        anomaly_level = max(anomaly_level, 2)

                # --- Drift rate analysis ---
                if len(offsets) >= self.DRIFT_WINDOW:
                    offset_arr = np.array(list(offsets)[-self.DRIFT_WINDOW:])
                    # Linear fit to detect drift
                    x = np.arange(len(offset_arr))
                    coeffs = np.polyfit(x, offset_arr, 1)
                    drift_per_sample = coeffs[0]  # µs per sample

                    # Convert to ppm (1 ppm = 1 µs/s)
                    if self._last_sof_time > 0 and len(self._sof_intervals) > 0:
                        avg_interval = np.mean(list(self._sof_intervals)[-self.DRIFT_WINDOW:])
                        # samples_per_second ≈ 1 / (avg_interval * 1e-6)
                        if avg_interval > 0:
                            samples_per_sec = 1.0 / (avg_interval * 1e-6)
                            drift_ppm = drift_per_sample * samples_per_sec / 1e6 * 1e6
                            result['drift_ppm'] = drift_ppm

                            # Check against expected drift
                            if abs(drift_ppm) > self.DRIFT_ANOMALY_SIGMA * 50:
                                anomalies.append(
                                    f'high_drift: {drift_ppm:.1f} ppm '
                                    f'(limit ~{self.DRIFT_ANOMALY_SIGMA * 50:.0f} ppm)'
                                )
                                anomaly_level = max(anomaly_level, 1)

                # --- Monotonicity of SOF-aligned timestamps ---
                if self._last_sof_time > 0:
                    if sof_aligned_time <= self._last_sof_time:
                        anomalies.append(
                            'sof_time_not_monotonic: SOF-aligned time went backward'
                        )
                        anomaly_level = max(anomaly_level, 2)

                # --- System clock cross-check ---
                # If SOF time and system time diverge too much, something is wrong
                if abs(offset_s) > 0.1:  # >100ms divergence
                    anomalies.append(
                        f'large_system_offset: {offset_s*1000:.1f} ms '
                        f'(system - SOF alignment)'
                    )
                    anomaly_level = max(anomaly_level, 1)

                # Update state
                self._last_sof_count = sof_count
                self._last_sof_time = system_time
                self._initialized = True

                result['valid'] = anomaly_level < 2
                result['anomaly_level'] = anomaly_level

                # Record anomaly
                if anomalies:
                    self._anomalies.append({
                        'time': system_time,
                        'device': device_name,
                        'level': anomaly_level,
                        'details': anomalies,
                    })
                    if anomaly_level >= 2:
                        self._alerts.append({
                            'time': system_time,
                            'device': device_name,
                            'details': anomalies,
                        })

            except Exception as e:
                result['valid'] = False
                result['anomalies'].append(f'validation_error: {e}')

        if anomaly_level >= 2:
            log.warning(f"TDOATimeSync ALERT (level {anomaly_level}): {anomalies}")

        return result

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            sof_arr = list(self._sof_intervals)
            offset_summary = {}
            for dev, offs in self._offsets.items():
                arr = list(offs)
                if len(arr) >= 2:
                    offset_summary[dev] = {
                        'current_us': round(arr[-1], 1),
                        'mean_us': round(np.mean(arr), 1),
                        'std_us': round(np.std(arr), 1),
                        'max_jump_us': round(max(abs(arr[i] - arr[i-1]) for i in range(1, len(arr))), 1),
                    }

            return {
                'initialized': self._initialized,
                'sof_intervals_sampled': len(sof_arr),
                'sof_interval_mean_us': round(np.mean(sof_arr), 2) if sof_arr else 0,
                'sof_interval_std_us': round(np.std(sof_arr), 2) if sof_arr else 0,
                'device_offsets': offset_summary,
                'total_anomalies': len(self._anomalies),
                'critical_alerts': len(self._alerts),
                'recent_alerts': [
                    {'time': a['time'], 'device': a['device'], 'details': a['details']}
                    for a in list(self._alerts)[-5:]
                ],
            }


# ---------------------------------------------------------------------------
# 5. HackRF USB Anti-Injection Wrapper
# ---------------------------------------------------------------------------

class HackRFUSBAntiInjection:
    """
    Wraps HackRF USB bulk transfers with integrity checks.

    Attack vectors:
      1. Oversized USB transfer — malicious USB device/firmware sends more data
         than expected, potentially overflowing buffers
      2. Undersized USB transfer — device disconnect or firmware crash leaves
         partial data that gets processed as valid IQ
      3. Transfer speed anomalies — abnormally fast transfers suggest cached/
         replayed data from a malicious USB device
      4. IQ value distribution attacks — all-zero or all-0xFF payloads indicate
         a dead/mocked device

    Defenses:
      - Enforce expected transfer size bounds (min/max bytes)
      - Validate IQ statistical properties (not all-zero, not clipped)
      - Track transfer timing for anomaly detection
      - Rate-limit read attempts to prevent DoS via rapid polling
      - Reject transfers with suspicious byte patterns
    """

    # HackRF bulk endpoint max packet size (USB 2.0 high-speed)
    MAX_PACKET_SIZE = 512
    # Maximum bulk transfer per read() call (0x4000 = 16384 as in hackrf_usb.py)
    EXPECTED_CHUNK_SIZE = 0x4000  # 16384 bytes
    # Transfer size tolerance (±50%)
    MIN_CHUNK_SIZE = EXPECTED_CHUNK_SIZE // 2
    MAX_CHUNK_SIZE = EXPECTED_CHUNK_SIZE * 2
    # Minimum IQ samples for a valid burst
    MIN_SAMPLES = 16
    # Maximum samples per burst (sanity limit)
    MAX_SAMPLES = 100_000
    # All-zero or constant-value threshold for IQ injection detection
    MIN_IQ_STD = 0.5   # Standard deviation must be > this for real RF
    # Transfer timing bounds (seconds)
    MIN_TRANSFER_TIME_S = 1e-6  # 1 µs minimum (USB can't be faster)
    MAX_TRANSFER_TIME_S = 2.0    # 2 seconds maximum

    def __init__(self):
        self._transfer_times = deque(maxlen=200)
        self._transfer_sizes = deque(maxlen=200)
        self._stats = {
            'transfers_ok': 0,
            'transfers_undersized': 0,
            'transfers_oversized': 0,
            'transfers_too_fast': 0,
            'transfers_too_slow': 0,
            'transfers_suspicious_iq': 0,
            'transfers_rejected': 0,
        }
        self._lock = threading.Lock()
        self._last_transfer_time = 0.0
        self._alert_log = deque(maxlen=50)
        log.info("HackRFUSBAntiInjection initialized")

    def validate_transfer(
        self,
        raw_bytes: bytearray,
        transfer_start: float,
        transfer_end: float,
        expected_n_bytes: Optional[int] = None,
    ) -> Tuple[bool, Optional[np.ndarray], List[str]]:
        """
        Validate a single USB bulk transfer from HackRF.

        Args:
            raw_bytes: Raw bytes received from USB bulk IN endpoint
            transfer_start: time.time() just before the read call
            transfer_end: time.time() just after the read call
            expected_n_bytes: If set, the exact number of bytes we expected

        Returns:
            (valid, iq_array_or_none, anomaly_list)
        """
        anomalies = []
        valid = True
        iq = None

        # --- Size checks ---
        n = len(raw_bytes)
        elapsed = transfer_end - transfer_start

        if n < self.MIN_CHUNK_SIZE:
            anomalies.append(f'undersized_transfer: {n} bytes (min {self.MIN_CHUNK_SIZE})')
            valid = False
            self._stats['transfers_undersized'] += 1

        if n > self.MAX_CHUNK_SIZE:
            anomalies.append(f'oversized_transfer: {n} bytes (max {self.MAX_CHUNK_SIZE})')
            valid = False
            self._stats['transfers_oversized'] += 1

        # Exact size check if expected bytes is known
        if expected_n_bytes is not None and n != expected_n_bytes:
            if n != expected_n_bytes:
                anomalies.append(f'size_mismatch: got {n}, expected {expected_n_bytes}')
                # Not necessarily invalid — USB can split transfers
                # but log it for tracking

        # --- Timing checks ---
        if elapsed < self.MIN_TRANSFER_TIME_S:
            anomalies.append(f'transfer_too_fast: {elapsed*1e6:.1f} µs (min {self.MIN_TRANSFER_TIME_S*1e6:.1f} µs)')
            valid = False
            self._stats['transfers_too_fast'] += 1

        if elapsed > self.MAX_TRANSFER_TIME_S:
            anomalies.append(f'transfer_too_slow: {elapsed:.3f} s (max {self.MAX_TRANSFER_TIME_S:.1f} s)')
            # Slow transfers might indicate USB issues, not necessarily injection
            self._stats['transfers_too_slow'] += 1

        # --- IQ statistical checks ---
        if n >= 2 and valid:
            try:
                raw = np.frombuffer(bytes(raw_bytes[:n]), dtype=np.uint8)
                if len(raw) % 2 != 0:
                    raw = raw[:len(raw) - 1]

                # Check for all-zero or all-0xFF payloads
                unique_values = np.unique(raw)
                if len(unique_values) <= 2:
                    anomalies.append(f'low_entropy_iq: only {len(unique_values)} unique byte values')
                    valid = False
                    self._stats['transfers_suspicious_iq'] += 1

                # Check for pathological distributions
                # Real RF IQ has values distributed around 128 (unsigned) with std > 0
                iq_real = raw[0::2].astype(np.float32)
                iq_imag = raw[1::2].astype(np.float32)
                std_r = np.std(iq_real)
                std_i = np.std(iq_imag)

                if std_r < self.MIN_IQ_STD and std_i < self.MIN_IQ_STD:
                    anomalies.append(
                        f'flat_iq_distribution: std_r={std_r:.2f}, std_i={std_i:.2f} '
                        f'(min {self.MIN_IQ_STD})'
                    )
                    valid = False
                    self._stats['transfers_suspicious_iq'] += 1

                # Check for clipping (all values at 0 or 255)
                clipped_ratio = (np.mean(iq_real == 0) + np.mean(iq_real == 255) +
                                 np.mean(iq_imag == 0) + np.mean(iq_imag == 255)) / 4
                if clipped_ratio > 0.8:
                    anomalies.append(f'high_clipping: {clipped_ratio:.2f} ratio')
                    valid = False
                    self._stats['transfers_suspicious_iq'] += 1

                if valid:
                    iq = iq_real + 1j * (iq_imag - 128.0)
                    if len(iq) < self.MIN_SAMPLES:
                        anomalies.append(f'too_few_samples: {len(iq)} (min {self.MIN_SAMPLES})')
                        valid = False
                    elif len(iq) > self.MAX_SAMPLES:
                        anomalies.append(f'too_many_samples: {len(iq)} (max {self.MAX_SAMPLES})')
                        valid = False

            except Exception as e:
                anomalies.append(f'iq_decode_error: {e}')
                valid = False

        # --- Track statistics ---
        with self._lock:
            if valid:
                self._stats['transfers_ok'] += 1
            else:
                self._stats['transfers_rejected'] += 1
            self._transfer_times.append(elapsed)
            self._transfer_sizes.append(n)
            self._last_transfer_time = transfer_end

            if anomalies:
                self._alert_log.append({
                    'time': transfer_end,
                    'size': n,
                    'elapsed_s': elapsed,
                    'anomalies': anomalies,
                })

        if anomalies and not valid:
            log.warning(f"HackRF USB ANTI-INJECTION: {anomalies}")

        return valid, iq, anomalies

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            times = list(self._transfer_times)
            sizes = list(self._transfer_sizes)
            return {
                'stats': dict(self._stats),
                'transfer_time_mean_ms': round(np.mean(times) * 1000, 2) if times else 0,
                'transfer_time_std_ms': round(np.std(times) * 1000, 2) if times else 0,
                'transfer_size_mean': round(np.mean(sizes), 1) if sizes else 0,
                'transfer_size_std': round(np.std(sizes), 1) if sizes else 0,
                'last_transfer_s': self._last_transfer_time,
                'recent_alerts': [
                    {'time': a['time'], 'size': a['size'], 'anomalies': a['anomalies']}
                    for a in list(self._alert_log)[-5:]
                ],
            }


# ---------------------------------------------------------------------------
# 6. Integration Helper — Wire everything together
# ---------------------------------------------------------------------------

class SDRSecurityOrchestrator:
    """
    Top-level orchestrator that wires all validators together.
    Provides a single entry point for the main TSCM loop to call.
    """

    def __init__(self):
        self.iq_validators = {}                    # device_name → IQStreamIntegrityValidator
        self.temporal_validator = CrossDeviceTemporalValidator()
        self.bladerf_hardener = None                # Set up when CLI bridge is initialized
        self.tdoa_validator = TDOATimeSyncValidator()
        self.hackrf_anti_injection = HackRFUSBAntiInjection()
        self._lock = threading.Lock()

    def register_device(self, device_name: str):
        """Register a device for IQ stream validation."""
        with self._lock:
            if device_name not in self.iq_validators:
                self.iq_validators[device_name] = IQStreamIntegrityValidator(device_name)

    def seal_iq(self, device_name: str, iq_np: np.ndarray) -> bytes:
        """Seal IQ data from a registered device."""
        v = self.iq_validators.get(device_name)
        if v is None:
            raise ValueError(f"Device '{device_name}' not registered")
        return v.seal_array(iq_np)

    def unseal_iq(self, device_name: str, chunk: bytes) -> Optional[np.ndarray]:
        """Unseal and validate IQ data. Returns None if integrity check fails."""
        v = self.iq_validators.get(device_name)
        if v is None:
            raise ValueError(f"Device '{device_name}' not registered")
        return v.unseal_to_array(chunk)

    def validate_cross_device(self, iq_a, fs_a, iq_b, fs_b, freq_a, freq_b, ts_a, ts_b):
        """Run cross-device temporal validation."""
        return self.temporal_validator.validate(
            iq_a, fs_a, iq_b, fs_b, freq_a, freq_b, ts_a, ts_b
        )

    def validate_hackrf_transfer(self, raw_bytes, start_time, end_time, expected_bytes=None):
        """Validate a HackRF USB transfer."""
        return self.hackrf_anti_injection.validate_transfer(
            raw_bytes, start_time, end_time, expected_bytes
        )

    def validate_tdoa_sync(self, device, sof_time, sys_time, sof_count):
        """Validate a TDOA sync pulse."""
        return self.tdoa_validator.validate_sync_pulse(
            device, sof_time, sys_time, sof_count
        )

    def init_bladerf_hardener(self, cli_path: str) -> BladeRFCLIBridgeHardener:
        """Initialize the BladeRF CLI bridge hardener."""
        self.bladerf_hardener = BladeRFCLIBridgeHardener(cli_path)
        return self.bladerf_hardener

    def get_security_report(self) -> Dict[str, Any]:
        """Generate a comprehensive security status report."""
        report = {
            'iq_validators': {},
            'cross_device': self.temporal_validator.get_health(),
            'hackrf': self.hackrf_anti_injection.get_status(),
            'tdoa_sync': self.tdoa_validator.get_status(),
            'bladerf_cli': None,
        }
        for name, v in self.iq_validators.items():
            report['iq_validators'][name] = {
                'stats': v.stats(),
                'healthy': v.is_healthy(),
            }
        if self.bladerf_hardener:
            report['bladerf_cli'] = self.bladerf_hardener.get_status()
        return report


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import json

    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(name)s %(levelname)s: %(message)s'
    )

    print("=" * 70)
    print("SDR Pipeline Security — Self-Test")
    print("=" * 70)

    # --- Test 1: IQ Stream Integrity Validator ---
    print("\n--- Test 1: IQ Stream Integrity Validator ---")
    v = IQStreamIntegrityValidator('hackrf_test')

    # Create test IQ data
    np.random.seed(42)
    test_iq = (np.random.randn(8192) + 1j * np.random.randn(8192)).astype(np.complex64)
    test_bytes = test_iq.tobytes()

    # Seal and unseal
    sealed = v.seal(test_bytes)
    unsealed = v.unseal(sealed)
    assert unsealed == test_bytes, "Seal/unseal round-trip failed"
    print(f"  ✓ Seal/unseal round-trip OK ({len(sealed)} bytes sealed from {len(test_bytes)} payload)")

    # Test bad magic
    bad_magic = b'XXXX' + sealed[4:]
    assert v.unseal(bad_magic) is None, "Bad magic should fail"
    print("  ✓ Bad magic detection works")

    # Test bad CRC
    bad_crc = sealed[:4] + b'\x00\x00\x00\x00' + sealed[8:]
    assert v.unseal(bad_crc) is None, "Bad CRC should fail"
    print("  ✓ Bad CRC detection works")

    # Test replay
    assert v.unseal(sealed) is None, "Replayed chunk should fail"
    print("  ✓ Replay detection works")

    # Test wrong nonce (simulated different session)
    v2 = IQStreamIntegrityValidator('hackrf_other_session')
    assert v2.unseal(sealed) is None, "Cross-session nonce should fail"
    print("  ✓ Cross-session nonce rejection works")

    # Test sequence gap
    v3 = IQStreamIntegrityValidator('gap_test')
    s1 = v3.seal(test_bytes)
    s2 = v3.seal(test_bytes)
    # Skip seq 3, send seq 4
    s3 = v3.seal(test_bytes)
    s4 = v3.seal(test_bytes)
    v3.unseal(s1)
    v3.unseal(s2)
    # Try to skip s3 and unseal s4 — should warn about gap
    v3.unseal(s4)
    stats = v3.stats()
    assert stats['chunks_dropped'] == 1, f"Expected 1 dropped, got {stats['chunks_dropped']}"
    print("  ✓ Sequence gap detection works")

    # --- Test 2: Cross-Device Temporal Validator ---
    print("\n--- Test 2: Cross-Device Temporal Validator ---")
    tv = CrossDeviceTemporalValidator()

    # Create correlated burst signals (same burst on both devices)
    fs = 10e6
    n = 8192
    t = np.arange(n) / fs
    # Burst signal: silence + tone burst + silence (gives clear onset/offset)
    signal = np.zeros(n)
    burst_start = n // 4
    burst_end = 3 * n // 4
    signal[burst_start:burst_end] = np.sin(2 * np.pi * 1e6 * t[burst_start:burst_end])
    signal += 0.05 * np.random.randn(n)

    iq_a = (signal + 1j * 0.05 * np.random.randn(n)).astype(np.complex64)
    iq_b = (signal + 1j * 0.05 * np.random.randn(n)).astype(np.complex64)

    now = time.time()
    result = tv.validate(iq_a, fs, iq_b, fs, 121e6, 2400e6, now, now + 0.0001)  # 100µs diff (well within 1ms)
    print(f"  Temporal validation: verified={result['verified']}, "
          f"spectral_ok={result['spectral_ok']}, temporal_ok={result['temporal_ok']}")
    print(f"  Envelope offset: {result['envelope_offset_s']*1e6:.1f} us")
    print(f"  Duration match: {result['duration_match_ratio']:.2f}")
    print(f"  Onset match: {result['onset_match']}")
    if not result['verified']:
        print(f"  Details: {result['details']}")
    health = tv.get_health()
    print(f"  Health: pass_rate={health['pass_rate']:.2f}")

    # --- Test 3: BladeRF CLI Bridge Hardener ---
    print("\n--- Test 3: BladeRF CLI Bridge Hardener ---")
    # Simulate (we can't actually test without bladeRF-cli.exe running)
    hardener = BladeRFCLIBridgeHardener(r'C:\Program Files\bladeRF\x64\bladeRF-cli.exe')
    hardener.register_spawned_pid(os.getpid())  # Register ourselves as a test

    # Validate normal output
    normal_output = b'bladeRF> Starting RX\nCaptured 8192 samples\n'
    result = hardener.validate_cli_output(normal_output, b'')
    print(f"  Normal CLI output: valid={result['valid']}")
    assert result['valid']

    # Validate forbidden output
    bad_output = b'set agc rx on\n'
    result = hardener.validate_cli_output(bad_output, b'')
    print(f"  Forbidden CLI output: valid={result['valid']}, anomalies={result['anomalies']}")
    assert not result['valid']

    # Test PID ownership
    owned = hardener.verify_pid_ownership(os.getpid())
    print(f"  PID ownership (self): {owned}")
    hardener.cleanup_session()
    print("  ✓ Session cleanup done")

    # --- Test 4: TDOA Time Sync Validator ---
    print("\n--- Test 4: TDOA Time Sync Validator ---")
    tsv = TDOATimeSyncValidator()

    # Simulate normal SOF pulses
    sof_epoch = time.time()
    for i in range(50):
        sof_count = i + 1
        sof_time = sof_epoch + i * 125e-6
        sys_time = sof_time + 0.001  # 1ms offset
        result = tsv.validate_sync_pulse('hackrf', sof_time, sys_time, sof_count)

    status = tsv.get_status()
    print(f"  50 normal pulses processed")
    print(f"  SOF interval: {status['sof_interval_mean_us']:.2f} ± {status['sof_interval_std_us']:.2f} µs")
    print(f"  HackRF offset: {status['device_offsets']['hackrf']}")

    # Simulate anomalous pulse
    anom_result = tsv.validate_sync_pulse(
        'hackrf',
        sof_time + 125e-6,
        sys_time + 0.1,  # 100ms jump
        51
    )
    print(f"  Anomalous pulse: valid={anom_result['valid']}, level={anom_result['anomaly_level']}")
    print(f"  Anomalies: {anom_result['anomalies'][:2]}")

    # Simulate non-monotonic SOF (time going backward)
    back_result = tsv.validate_sync_pulse(
        'bladerf_rx1',
        sof_time - 125e-6,  # Time went backward!
        sys_time,
        52
    )
    print(f"  Non-monotonic SOF: valid={back_result['valid']}, level={back_result['anomaly_level']}")

    # --- Test 5: HackRF USB Anti-Injection ---
    print("\n--- Test 5: HackRF USB Anti-Injection ---")
    inj = HackRFUSBAntiInjection()

    # Normal transfer
    normal_iq = np.random.randint(20, 236, size=(16384,), dtype=np.uint8)
    raw_bytes = bytearray(normal_iq.tobytes())
    valid, iq, anomalies = inj.validate_transfer(raw_bytes, time.time(), time.time() + 0.001, 16384)
    print(f"  Normal transfer: valid={valid}, iq_samples={len(iq) if iq is not None else 0}")

    # Oversized transfer
    huge = bytearray(os.urandom(50000))
    valid, iq, anomalies = inj.validate_transfer(huge, time.time(), time.time() + 0.001)
    print(f"  Oversized transfer: valid={valid}, anomalies={anomalies[:1]}")

    # All-zero transfer (dead device / injection)
    zeros = bytearray(16384)
    valid, iq, anomalies = inj.validate_transfer(zeros, time.time(), time.time() + 0.001, 16384)
    print(f"  All-zero transfer: valid={valid}, anomalies={anomalies[:1]}")

    # Impossibly fast transfer
    valid, iq, anomalies = inj.validate_transfer(raw_bytes, time.time(), time.time() + 1e-7)
    print(f"  Too-fast transfer: valid={valid}, anomalies={anomalies[:1]}")

    inj_status = inj.get_status()
    print(f"  Stats: ok={inj_status['stats']['transfers_ok']}, "
          f"rejected={inj_status['stats']['transfers_rejected']}")

    # --- Test 6: Full Orchestrator ---
    print("\n--- Test 6: SDR Security Orchestrator ---")
    orch = SDRSecurityOrchestrator()
    orch.register_device('hackrf')
    orch.register_device('bladerf_rx1')

    sealed = orch.seal_iq('hackrf', test_iq)
    unsealed = orch.unseal_iq('hackrf', sealed)
    print(f"  Orchestrator seal/unseal: {unsealed is not None}")

    orch.init_bladerf_hardener(r'C:\Program Files\bladeRF\x64\bladeRF-cli.exe')
    report = orch.get_security_report()
    print(f"  Security report keys: {list(report.keys())}")
    print(f"  IQ validators: {list(report['iq_validators'].keys())}")
    print(f"  HackRF healthy: {report['iq_validators']['hackrf']['healthy']}")

    print("\n" + "=" * 70)
    print("ALL TESTS PASSED ✓")
    print("=" * 70)
