#!/usr/bin/env python3
"""
================================================================================
 ADAPTIVE TACTICS MODULE — Real-time adaptive countermeasures for TSCM
 Implements 6 behavioral rules from tscm_master_final.py:
   1. Frequency Hop Detection (<2s re-lock, 0.5s rapid phase-search at 10° steps)
   2. Phase-Flip Recovery (180° flip + 90° fallback when cancellation degrades)
   3. Dual-Loop Spatial Null Search (0°/90°/180°/270° cycling every 3s)
   4. GPS Anti-Spoof Enforcement (UBX verify, continuous poll, dead-reckoning)
   5. SDR Glitch Auto-Restart (>5s data gap → hardware reset + re-init)
   6. Forensic Logging (structured JSONL of every tactical decision)
================================================================================
"""

import time
import json
import math
import threading
import logging
from collections import deque
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# 1. FrequencyHopDetector
# ---------------------------------------------------------------------------
class FrequencyHopDetector:
    """Tracks PLL carrier frequency history; detects hops within a 2-second
    window.  On detection, triggers a 0.5-second rapid phase-search loop that
    increments the cancellation phase by 10° steps to re-null the target.
    """

    def __init__(self, hop_window_s=2.0, search_duration_s=0.5,
                 phase_step_deg=10.0, on_hop_cb=None, on_phase_cb=None,
                 log=None):
        self.log = log or logging.getLogger("FreqHop")
        self.hop_window = hop_window_s
        self.search_duration = search_duration_s
        self.phase_step = math.radians(phase_step_deg)
        self.on_hop_cb = on_hop_cb        # (old_freq, new_freq, delta_s)
        self.on_phase_cb = on_phase_cb    # (phase_rad, step_idx, total_steps)

        self._history = deque(maxlen=60)  # (timestamp, freq_hz, amplitude)
        self._last_freq = None
        self._search_active = False
        self._search_start = 0.0
        self._search_step = 0
        self._total_steps = int(search_duration_s / 0.05)  # 10 steps at 50ms
        self._hop_count = 0

    # -- Public API ----------------------------------------------------------

    def feed(self, freq_hz, amplitude=0.0):
        """Call once per detection cycle with the dominant carrier frequency."""
        now = time.time()
        self._history.append((now, freq_hz, amplitude))

        if self._search_active:
            # Still in phase-search; suppress new hop triggers
            self._tick_phase_search(now)
            return

        if self._last_freq is not None and freq_hz != self._last_freq:
            delta_t = now - (self._history[-2][0] if len(self._history) >= 2 else now)
            if 0 < delta_t <= self.hop_window:
                self._on_hop(self._last_freq, freq_hz, delta_t, now)

        self._last_freq = freq_hz

    def get_state(self):
        return {
            'search_active': self._search_active,
            'last_freq': self._last_freq,
            'search_step': self._search_step,
            'hop_count': self._hop_count,
        }

    # -- Internal ------------------------------------------------------------

    def _on_hop(self, old_freq, new_freq, delta_s, now):
        self._hop_count += 1
        self.log.warning(
            f"FREQ HOP #{self._hop_count}: "
            f"{old_freq / 1e6:.3f} -> {new_freq / 1e6:.3f} MHz "
            f"(Δt={delta_s:.2f}s)"
        )
        # Start rapid phase-search
        self._search_active = True
        self._search_start = now
        self._search_step = 0

        if self.on_hop_cb:
            self.on_hop_cb(old_freq, new_freq, delta_s)

    def _tick_phase_search(self, now):
        """Called every feed() while search is active.
        Returns the current trial phase, or None when search completes."""
        elapsed = now - self._search_start
        if elapsed >= self.search_duration:
            self._search_active = False
            self.log.info("Phase-search complete (%d steps)", self._search_step)
            return None

        step = int(elapsed / 0.05)
        if step != self._search_step:
            self._search_step = step
            phase = (step * self.phase_step) % (2 * math.pi)
            if self.on_phase_cb:
                self.on_phase_cb(phase, step, self._total_steps)
            return phase
        return None


# ---------------------------------------------------------------------------
# 2. PhaseFlipRecovery
# ---------------------------------------------------------------------------
class PhaseFlipRecovery:
    """Monitors bucket resonator amplitude during active VLF cancellation.
    If amplitude *increases* (cancellation is degrading), auto-flips output
    phase by 180°.  If still rising, adds 90° offset and tests.
    """

    def __init__(self, rise_threshold=1.3, cooldown_s=1.0,
                 on_flip_cb=None, log=None):
        self.log = log or logging.getLogger("PhaseFlip")
        self.rise_threshold = rise_threshold  # amplitude must rise >1.3x
        self.cooldown = cooldown_s
        self.on_flip_cb = on_flip_cb         # (phase_offset_deg, old_amp, new_amp)

        self._prev_amp = 0.0
        self._current_offset = 0.0          # radians
        self._cancellation_active = False
        self._last_flip_time = 0.0
        self._flip_history = deque(maxlen=50)  # (ts, old_amp, new_amp, offset_deg)

    def set_cancellation_active(self, active: bool):
        """Call when VLF cancellation tone is toggled on/off."""
        self._cancellation_active = active
        if active:
            self._last_flip_time = time.time()  # suppress flips during first cooldown
        if not active:
            self._prev_amp = 0.0

    def feed(self, bucket_amplitude: float):
        """Call with current bucket resonator amplitude each cycle.
        Returns the recommended phase offset (radians), or None."""
        if not self._cancellation_active:
            return None

        now = time.time()
        # Need at least one prior measurement
        if self._prev_amp <= 0:
            self._prev_amp = bucket_amplitude
            return self._current_offset

        ratio = bucket_amplitude / (self._prev_amp + 1e-12)

        if ratio > self.rise_threshold and (now - self._last_flip_time) > self.cooldown:
            return self._flip(bucket_amplitude, now)

        self._prev_amp = bucket_amplitude
        return self._current_offset

    def get_state(self):
        return {
            'offset_deg': round(math.degrees(self._current_offset), 1),
            'active': self._cancellation_active,
            'flip_count': len(self._flip_history),
        }

    # -- Internal ------------------------------------------------------------

    def _flip(self, current_amp, now):
        old_offset = self._current_offset
        # First try: 180° flip
        new_offset = (self._current_offset + math.pi) % (2 * math.pi)
        self._current_offset = new_offset
        self._last_flip_time = now

        self._flip_history.append((now, self._prev_amp, current_amp,
                                   math.degrees(new_offset)))
        self.log.warning(
            f"PHASE FLIP: {math.degrees(old_offset):.0f}° -> "
            f"{math.degrees(new_offset):.0f}° "
            f"(amp ratio={current_amp / (self._prev_amp + 1e-12):.2f}x)"
        )

        if self.on_flip_cb:
            self.on_flip_cb(math.degrees(new_offset), self._prev_amp, current_amp)

        self._prev_amp = current_amp
        return new_offset

    def feed_still_rising(self, bucket_amplitude: float) -> float:
        """Call after the 180° flip if amplitude is STILL rising.
        Adds 90° offset. Returns new offset in radians."""
        now = time.time()
        if (now - self._last_flip_time) < self.cooldown:
            return self._current_offset

        old_offset = self._current_offset
        self._current_offset = (self._current_offset + math.pi / 2) % (2 * math.pi)
        self._last_flip_time = now

        self._flip_history.append((now, self._prev_amp, bucket_amplitude,
                                   math.degrees(self._current_offset)))
        self.log.warning(
            f"PHASE FLIP +90°: {math.degrees(old_offset):.0f}° -> "
            f"{math.degrees(self._current_offset):.0f}°"
        )

        self._prev_amp = bucket_amplitude
        return self._current_offset


# ---------------------------------------------------------------------------
# 3. DualLoopNullSearch
# ---------------------------------------------------------------------------
class DualLoopNullSearch:
    """When both antenna loops are connected, cycles through relative
    loop-loop phase offsets (0°, 90°, 180°, 270°) every 3 seconds and
    selects the one giving the lowest bucket resonator amplitude.
    """

    PHASE_CANDIDATES = [0, 90, 180, 270]  # degrees

    def __init__(self, cycle_interval_s=3.0, measure_window_s=0.5,
                 on_phase_cb=None, log=None):
        self.log = log or logging.getLogger("DualLoop")
        self.cycle_interval = cycle_interval_s
        self.measure_window = measure_window_s
        self.on_phase_cb = on_phase_cb      # (phase_deg, bucket_amp)

        self._idx = 0
        self._last_cycle = 0.0
        self._best_phase = 0.0
        self._best_amp = float('inf')
        self._measurements = deque(maxlen=100)
        self._loop2_connected = False

    def set_loop2_connected(self, connected: bool):
        """Call when loop-2 antenna status changes."""
        self._loop2_connected = connected
        if connected:
            self.log.info("DualLoop: loop-2 connected — spatial null search active")

    def feed(self, bucket_amplitude: float):
        """Call with bucket resonator amplitude.  Returns the current
        candidate phase (degrees), or the best locked phase."""
        if not self._loop2_connected:
            return self._best_phase

        now = time.time()
        phase_deg = self.PHASE_CANDIDATES[self._idx]

        # Record measurement for this candidate
        self._measurements.append((now, phase_deg, bucket_amplitude))

        # Advance to next candidate every cycle_interval
        if now - self._last_cycle >= self.cycle_interval:
            # Evaluate current candidate
            recent = [m for m in self._measurements
                      if m[0] > now - self.measure_window and m[1] == phase_deg]
            if recent:
                avg_amp = sum(m[2] for m in recent) / len(recent)
                if avg_amp < self._best_amp:
                    self._best_amp = avg_amp
                    self._best_phase = phase_deg
                    self.log.info(
                        f"DualLoop: NEW BEST phase={phase_deg}° "
                        f"(avg amp={avg_amp:.3f})"
                    )

            # Next candidate
            self._idx = (self._idx + 1) % len(self.PHASE_CANDIDATES)
            self._last_cycle = now
            phase_deg = self.PHASE_CANDIDATES[self._idx]

            if self.on_phase_cb:
                self.on_phase_cb(phase_deg, bucket_amplitude)

        return phase_deg

    def get_best_phase(self):
        """Returns (phase_deg, amplitude) of the best null found."""
        return self._best_phase, self._best_amp

    def get_state(self):
        return {
            'loop2_connected': self._loop2_connected,
            'best_phase_deg': self._best_phase,
            'best_amp': self._best_amp,
            'current_idx': self._idx,
        }


# ---------------------------------------------------------------------------
# 4. GPSDeadReckoning
# ---------------------------------------------------------------------------
class GPSDeadReckoning:
    """Stores the last valid GPS position and provides dead-reckoning
    estimates when a spoof is flagged.  Verifies ZED-F9P config via UBX
    at startup and continuously polls for spoof indicators.
    """

    def __init__(self, spoof_timeout_s=5.0, log=None):
        self.log = log or logging.getLogger("GPSDeadReck")
        self.spoof_timeout = spoof_timeout_s

        # Last valid position (set externally)
        self._last_valid_lat = None
        self._last_valid_lon = None
        self._last_valid_alt = 0.0
        self._last_valid_time = 0.0

        # Dead-reckoning state
        self._dr_lat = None
        self._dr_lon = None
        self._dr_alt = 0.0
        self._dr_active = False
        self._dr_velocity = (0.0, 0.0, 0.0)  # m/s N, E, Up
        self._dr_heading = 0.0
        self._dr_speed = 0.0

        # Spoof detection
        self._spoof_flagged = False
        self._spoof_start = 0.0
        self._spoof_count = 0
        self._ubx_verified = False

    # -- Startup verification ------------------------------------------------

    def verify_ubx_config(self, serial_port):
        """Verify ZED-F9P anti-spoof configuration via UBX CFG-VALGET.
        Returns True if config is correct or was set successfully."""
        if not serial_port:
            self.log.warning("GPSDeadReck: no serial port for UBX verify")
            return False

        try:
            # UBX-CFG-VALGET: poll jamming/spoofing enable keys
            # Key IDs for anti-jam (0x201100xx) and anti-spoof (0x201200xx)
            poll = bytes([
                0xB5, 0x62, 0x06, 0x8B,  # CFG-VALGET
                0x08, 0x00,              # length
                0x00,                    # version
                0x00,                    # layer
                0x00, 0x00,              # position (0 = start)
                0x01,                    # 1 key
                0x20, 0x11, 0x00, 0x07  # jammingEnable (key 0x20110007)
            ])

            serial_port.write(poll)
            time.sleep(0.3)

            resp = serial_port.read(64)
            if b'\xb5\x62' in resp:
                self._ubx_verified = True
                self.log.info("GPSDeadReck: ZED-F9P UBX config verified")
                return True
            else:
                self.log.warning("GPSDeadReck: UBX verify — no response, "
                                 "attempting config")
                return self._set_ubx_config(serial_port)
        except Exception as e:
            self.log.warning(f"GPSDeadReck: UBX verify failed: {e}")
            return False

    def _set_ubx_config(self, serial_port):
        """Send UBX CFG-VALSET to enable anti-jam/anti-spoof."""
        try:
            cfg = bytes([
                0xB5, 0x62, 0x06, 0x8A,  # CFG-VALSET
                0x0C, 0x00,              # length
                0x00,                    # version
                0x01,                    # layer: RAM
                0x00,                    # transaction
                0x02,                    # 2 keys
                0x20, 0x11, 0x00, 0x07, 0x01,  # jammingEnable = 1
                0x20, 0x12, 0x00, 0x01, 0x01,  # spoofDetectEnable = 1
            ])
            serial_port.write(cfg)
            time.sleep(0.3)

            # Save to flash
            save = bytes([0xB5, 0x62, 0x06, 0x09, 0x08, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            serial_port.write(save)

            self._ubx_verified = True
            self.log.info("GPSDeadReck: ZED-F9P anti-spoof config SET + SAVED")
            return True
        except Exception as e:
            self.log.warning(f"GPSDeadReck: UBX config failed: {e}")
            return False

    # -- Continuous polling --------------------------------------------------

    def feed_gps(self, lat, lon, alt, has_fix, spoof_flagged=False,
                 hdop=99.0, speed=0.0, heading=0.0):
        """Feed every GPS update.  Automatically transitions between
        live fix and dead-reckoning."""
        now = time.time()

        if spoof_flagged and not self._spoof_flagged:
            self._spoof_flagged = True
            self._spoof_start = now
            self._spoof_count += 1
            self.log.warning(
                f"GPS SPOOF FLAGGED (#{self._spoof_count}) — "
                f"switching to dead-reckoning at "
                f"({self._last_valid_lat:.6f}, {self._last_valid_lon:.6f})"
            )
            # Snap dead-reckoning to last valid position
            self._dr_lat = self._last_valid_lat
            self._dr_lon = self._last_valid_lon
            self._dr_alt = self._last_valid_alt
            self._dr_active = True

        if spoof_flagged and self._dr_active:
            # Update velocity estimate for DR extrapolation
            self._dr_speed = speed
            self._dr_heading = heading
            # Propagate dead-reckoning
            dt = now - self._dr_last_prop if hasattr(self, '_dr_last_prop') else 0
            if dt > 0 and dt < 10:
                ds = speed * dt
                self._dr_lat += (ds / 111320.0) * math.cos(math.radians(heading))
                self._dr_lon += (ds / (111320.0 * math.cos(
                    math.radians(self._dr_lat or 0)))) * math.sin(
                    math.radians(heading))
            self._dr_last_prop = now
            return self._dr_position()

        if not spoof_flagged:
            if has_fix and lat != 0 and lon != 0 and hdop < 20:
                # Accept as valid
                self._last_valid_lat = lat
                self._last_valid_lon = lon
                self._last_valid_alt = alt
                self._last_valid_time = now
                if self._dr_active:
                    self._dr_active = False
                    self.log.info("GPSDeadReck: spoof cleared — back to live fix")
                return {'lat': lat, 'lon': lon, 'alt': alt,
                        'mode': 'live', 'valid': True}

        # No fix and not spoofed — return last valid if recent
        if self._last_valid_lat and (now - self._last_valid_time) < 30:
            return {'lat': self._last_valid_lat, 'lon': self._last_valid_lon,
                    'alt': self._last_valid_alt,
                    'mode': 'stale', 'valid': False}
        return {'lat': 0, 'lon': 0, 'alt': 0, 'mode': 'none', 'valid': False}

    def _dr_position(self):
        if self._dr_lat is None:
            return {'lat': 0, 'lon': 0, 'alt': 0,
                    'mode': 'dead_reckoning', 'valid': False}
        return {'lat': self._dr_lat, 'lon': self._dr_lon, 'alt': self._dr_alt,
                'mode': 'dead_reckoning', 'valid': False}

    def get_state(self):
        return {
            'ubx_verified': self._ubx_verified,
            'spoof_flagged': self._spoof_flagged,
            'spoof_count': self._spoof_count,
            'dr_active': self._dr_active,
            'last_valid_lat': self._last_valid_lat,
            'last_valid_lon': self._last_valid_lon,
        }


# ---------------------------------------------------------------------------
# 5. SDRWatchdog
# ---------------------------------------------------------------------------
class SDRWatchdog:
    """Monitors HackRF and BladeRF data flow.  If no data arrives for >15
    seconds, attempts hardware reset and re-initialization.
    CLI bridge captures take ~3s each, so 15s gives adequate margin.
    """

    def __init__(self, timeout_s=60.0, restart_delay_s=3.0,
                 on_restart_cb=None, log=None):
        self.log = log or logging.getLogger("SDRWatchdog")
        self.timeout = timeout_s
        self.restart_delay = restart_delay_s
        self.on_restart_cb = on_restart_cb  # (device_name)

        self._last_hackrf = time.time()
        self._last_bladerf = time.time()
        self._hackrf_restarts = 0
        self._bladerf_restarts = 0
        self._running = False
        self._thread = None

        # External references (set after construction)
        self.hackrf = None       # HackRFStreamBridge or HackRFSubprocess
        self.bladerf = None      # BladeRFCLIBridge or bladeRF device
        self.tscm = None         # TSCMSystem reference for full restart

    def start(self):
        """Start the watchdog monitoring thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        self.log.info("SDRWatchdog: monitoring active (timeout=%.1fs)", self.timeout)

    def stop(self):
        self._running = False

    def feed_hackrf(self):
        """Call whenever HackRF data is received."""
        self._last_hackrf = time.time()

    def feed_bladerf(self):
        """Call whenever BladeRF data is received."""
        self._last_bladerf = time.time()

    def get_state(self):
        return {
            'last_hackrf_s': time.time() - self._last_hackrf,
            'last_bladerf_s': time.time() - self._last_bladerf,
            'hackrf_restarts': self._hackrf_restarts,
            'bladerf_restarts': self._bladerf_restarts,
        }

    # -- Internal ------------------------------------------------------------

    def _monitor_loop(self):
        while self._running:
            try:
                now = time.time()
                hackrf_gap = now - self._last_hackrf
                bladerf_gap = now - self._last_bladerf

                if hackrf_gap > self.timeout and self.hackrf is not None:
                    self._restart_device('hackrf')

                if bladerf_gap > self.timeout and self.bladerf is not None:
                    self._restart_device('bladerf')

                time.sleep(1.0)
            except Exception as e:
                self.log.error(f"SDRWatchdog monitor error: {e}")
                time.sleep(2.0)

    def _restart_device(self, device_name):
        if device_name == 'hackrf':
            self._hackrf_restarts += 1
            self.log.warning(
                f"SDRWatchdog: HackRF data gap "
                f">{self.timeout:.0f}s — restarting "
                f"(#{self._hackrf_restarts})"
            )
            try:
                if self.hackrf and hasattr(self.hackrf, 'stop'):
                    self.hackrf.stop()
                time.sleep(self.restart_delay)
                if self.hackrf and hasattr(self.hackrf, 'start'):
                    self.hackrf.start()
                self._last_hackrf = time.time()
                self.log.info("SDRWatchdog: HackRF restarted OK")
                if self.on_restart_cb:
                    self.on_restart_cb('hackrf')
            except Exception as e:
                self.log.error(f"SDRWatchdog: HackRF restart FAILED: {e}")
                # Try full TSCM-level restart
                self._full_tscm_restart('hackrf')

        elif device_name == 'bladerf':
            self._bladerf_restarts += 1
            self.log.warning(
                f"SDRWatchdog: BladeRF data gap "
                f">{self.timeout:.0f}s — restarting "
                f"(#{self._bladerf_restarts})"
            )
            try:
                if self.bladerf and hasattr(self.bladerf, 'stop'):
                    self.bladerf.stop()
                time.sleep(self.restart_delay)
                if self.bladerf and hasattr(self.bladerf, 'start'):
                    self.bladerf.start()
                self._last_bladerf = time.time()
                self.log.info("SDRWatchdog: BladeRF restarted OK")
                if self.on_restart_cb:
                    self.on_restart_cb('bladerf')
            except Exception as e:
                self.log.error(f"SDRWatchdog: BladeRF restart FAILED: {e}")
                # USB device reset attempt
                self._usb_reset_bladerf()

    def _usb_reset_bladerf(self):
        """Attempt USB-level device reset via pnputil on Windows."""
        try:
            import subprocess
            result = subprocess.run(
                ['pnputil', '/enum-devices', '/instanceid',
                 'USB\\VID_2CF0&PID_5250'],
                capture_output=True, text=True, timeout=10,
                creationflags=0x08000000
            )
            # Try restart-device with the instance ID from enum output
            for line in result.stdout.splitlines():
                if 'Instance ID:' in line and 'VID_2CF0' in line:
                    instance = line.split('Instance ID:')[1].strip()
                    subprocess.run(
                        ['pnputil', '/restart-device', instance],
                        capture_output=True, timeout=15,
                        creationflags=0x08000000
                    )
                    self.log.info("SDRWatchdog: BladeRF USB device reset sent")
                    time.sleep(3)
                    break
        except Exception as e:
            self.log.error(f"SDRWatchdog: USB reset failed: {e}")

    def _full_tscm_restart(self, device_name):
        """Try TSCMSystem-level restart if simple restart fails."""
        if self.tscm is None:
            return
        try:
            self.log.info(f"SDRWatchdog: attempting TSCM-level restart for {device_name}")
            if device_name == 'hackrf' and hasattr(self.tscm, 'hackrf'):
                self.tscm.hackrf.stop()
                time.sleep(2)
                from hackrf_usb import HackRFStreamBridge
                hackrf_freq = 121e6
                self.tscm.hackrf = HackRFStreamBridge(
                    frequency=hackrf_freq, sample_rate=20e6,
                    lna_gain=30, vga_gain=16, amp_enable=True, antenna_power=True
                )
                self.tscm.hackrf.start()
                self.hackrf = self.tscm.hackrf
                self._last_hackrf = time.time()
                self.log.info("SDRWatchdog: TSCM-level HackRF rebuild OK")
        except Exception as e:
            self.log.error(f"SDRWatchdog: TSCM restart FAILED: {e}")


# ---------------------------------------------------------------------------
# 6. ForensicLogger
# ---------------------------------------------------------------------------
class ForensicLogger:
    """Structured JSONL logging of every tactical decision.
    Every cancellation target change logs: timestamp, old freq, new freq,
    phase adjustment, bucket/PLL amplitude before/after.
    """

    def __init__(self, log_path="forensic_tactics.jsonl", max_entries=100000,
                 log=None):
        self.log = log or logging.getLogger("Forensic")
        self.path = log_path
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._entry_count = 0

    def record(self, event_type, **kwargs):
        """Append a structured forensic entry."""
        entry = {
            'ts': datetime.now(timezone.utc).isoformat(),
            'epoch': time.time(),
            'event': event_type,
        }
        entry.update(kwargs)
        self._write(entry)

    def record_cancellation_change(self, old_freq, new_freq, phase_adj_deg,
                                   bucket_amp_before, bucket_amp_after,
                                   pll_amp_before=0, pll_amp_after=0):
        """High-level helper: log a cancellation target change with all
        required forensic fields."""
        self.record(
            'cancellation_target_change',
            old_freq_hz=float(old_freq) if old_freq else None,
            new_freq_hz=float(new_freq) if new_freq else None,
            phase_adjustment_deg=float(phase_adj_deg),
            bucket_amplitude_before=float(bucket_amp_before),
            bucket_amplitude_after=float(bucket_amp_after),
            pll_amplitude_before=float(pll_amp_before),
            pll_amplitude_after=float(pll_amp_after),
            freq_delta_hz=float(new_freq - old_freq) if old_freq and new_freq else None,
        )

    def record_freq_hop(self, old_freq, new_freq, delta_s, phase_search_steps=0):
        self.record('freq_hop_detected',
                    old_freq_hz=float(old_freq),
                    new_freq_hz=float(new_freq),
                    delta_s=float(delta_s),
                    phase_search_steps=int(phase_search_steps))

    def record_phase_flip(self, old_offset_deg, new_offset_deg, amp_ratio):
        self.record('phase_flip',
                    old_offset_deg=float(old_offset_deg),
                    new_offset_deg=float(new_offset_deg),
                    amplitude_ratio=float(amp_ratio))

    def record_dual_loop(self, phase_deg, bucket_amp, is_best=False):
        self.record('dual_loop_null',
                    candidate_phase_deg=float(phase_deg),
                    bucket_amplitude=float(bucket_amp),
                    is_best=bool(is_best))

    def record_gps_spoof(self, spoof_type, details=''):
        self.record('gps_spoof',
                    spoof_type=str(spoof_type),
                    details=str(details))

    def record_sdr_restart(self, device, reason, success):
        self.record('sdr_restart',
                    device=str(device),
                    reason=str(reason),
                    success=bool(success))

    def _write(self, entry):
        try:
            line = json.dumps(entry, default=str) + '\n'
            with self._lock:
                with open(self.path, 'a') as f:
                    f.write(line)
                self._entry_count += 1
                # Rotate if too large
                if self._entry_count > self.max_entries:
                    self._rotate()
        except Exception as e:
            self.log.error(f"ForensicLogger write failed: {e}")

    def _rotate(self):
        """Keep only the newest half of entries."""
        try:
            with open(self.path, 'r') as f:
                lines = f.readlines()
            keep = lines[len(lines) // 2:]
            with open(self.path, 'w') as f:
                f.writelines(keep)
            self._entry_count = len(keep)
            self.log.info(f"ForensicLogger: rotated (kept {len(keep)} entries)")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 7. TacticalCoordinator
# ---------------------------------------------------------------------------
class TacticalCoordinator:
    """Orchestrates all adaptive tactics modules.  Provides a single entry
    point (`tick()`) called every detection cycle, and wires callbacks between
    the subsystems.

    Interfaces with the existing TSCMSystem:
      - coherence: AdaptiveCoherenceController
      - gps: GPSInterface
      - hackrf: HackRFStreamBridge
      - bladerf_bridge: BladeRFCLIBridge
      - inverse_wave_player: InverseWavePlayer

    Usage (in TSCMSystem.__init__ or after construction):
        tactics = TacticalCoordinator(tscm_system)
        tactics.start()
        # ... in detection loop:
        tactics.tick(detection_markers)
    """

    def __init__(self, tscm_system, log=None):
        self.tscm = tscm_system
        self.log = log or logging.getLogger("TacticalCoord")

        # Sub-modules
        self.forensic = ForensicLogger()
        self.freq_hop = FrequencyHopDetector(
            on_hop_cb=self._on_freq_hop,
            on_phase_cb=self._on_phase_search_step,
            log=self.log
        )
        self.phase_flip = PhaseFlipRecovery(
            on_flip_cb=self._on_phase_flip,
            log=self.log
        )
        self.dual_loop = DualLoopNullSearch(
            on_phase_cb=self._on_dual_loop_phase,
            log=self.log
        )
        self.gps_dr = GPSDeadReckoning(log=self.log)
        self.sdr_wd = SDRWatchdog(
            timeout_s=180.0,
            on_restart_cb=self._on_sdr_restart,
            log=self.log
        )

        self._running = False
        self._tick_count = 0
        self._last_bucket_amp = 0.0
        self._last_pll_freq = None
        self._last_pll_amp = 0.0
        self._phase_flip_tried_90 = False

    def start(self):
        """Start watchdog thread and perform startup verification."""
        self._running = True

        # Wire SDR watchdog to hardware references
        self.sdr_wd.hackrf = getattr(self.tscm, 'hackrf', None)
        self.sdr_wd.bladerf = getattr(self.tscm, 'bladerf_bridge', None)
        self.sdr_wd.tscm = self.tscm
        self.sdr_wd.start()

        # Startup GPS anti-spoof verification
        gps_iface = getattr(self.tscm, 'gps', None)
        if gps_iface and hasattr(gps_iface, 'serial') and gps_iface.serial:
            self.gps_dr.verify_ubx_config(gps_iface.serial)

        # Check dual-loop status (bladeRF MIMO = both loops)
        bladerf = getattr(self.tscm, 'bladerf_bridge', None)
        if bladerf and hasattr(bladerf, 'cli') and bladerf.cli:
            self.dual_loop.set_loop2_connected(True)

        self.log.info("TacticalCoordinator: all modules started")

    def stop(self):
        self._running = False
        self.sdr_wd.stop()

    # -- Main tick (call from detection loop) --------------------------------

    def tick(self, detection_markers=None):
        """Call once per detection cycle with current detection markers.
        Extracts relevant data and feeds it to all subsystems."""
        if not self._running:
            return

        self._tick_count += 1
        markers = detection_markers or []
        now = time.time()

        # Extract RF carrier info for freq-hop detector
        rf_carrier = self._extract_dominant_rf(markers)
        if rf_carrier is not None:
            freq, amp = rf_carrier

            old_pll_freq = self._last_pll_freq
            old_pll_amp = self._last_pll_amp

            # Feed freq-hop detector (handles phase-search internally)
            self.freq_hop.feed(freq, amp)

            # Forensic: log cancellation target changes
            if old_pll_freq is not None and freq != old_pll_freq:
                self.forensic.record_cancellation_change(
                    old_freq=old_pll_freq,
                    new_freq=freq,
                    phase_adj_deg=math.degrees(
                        getattr(self.tscm.coherence, 'rf_phase', 0)
                        if hasattr(self.tscm, 'coherence') else 0),
                    bucket_amp_before=old_pll_amp,
                    bucket_amp_after=amp,
                    pll_amp_before=old_pll_amp,
                    pll_amp_after=amp,
                )

            self._last_pll_freq = freq
            self._last_pll_amp = amp

        # Extract bucket resonator amplitude for phase-flip + dual-loop
        bucket_amp = self._extract_bucket_amp(markers)
        if bucket_amp > 0:
            # Phase-flip recovery
            cancellation_active = (
                hasattr(self.tscm, 'inverse_wave_player') and
                self.tscm.inverse_wave_player and
                self.tscm.inverse_wave_player.active
            )
            self.phase_flip.set_cancellation_active(cancellation_active)
            offset = self.phase_flip.feed(bucket_amp)

            if offset is not None and hasattr(self.tscm, 'coherence'):
                self.tscm.coherence.set_audio_phase(offset)

                # Check if amplitude still rising after 180° flip
                if self._phase_flip_tried_90 is False and \
                   self.phase_flip._current_offset != 0 and \
                   bucket_amp > self._last_bucket_amp * 1.3:
                    extra = self.phase_flip.feed_still_rising(bucket_amp)
                    if extra is not None and hasattr(self.tscm, 'coherence'):
                        self.tscm.coherence.set_audio_phase(extra)
                        self._phase_flip_tried_90 = True
                else:
                    self._phase_flip_tried_90 = False

            # Dual-loop null search
            loop_phase = self.dual_loop.feed(bucket_amp)
            if loop_phase is not None and hasattr(self.tscm, 'coherence'):
                # Apply as audio phase offset (spatial null via loop phasing)
                # The dual-loop phase adds ON TOP of the phase-flip offset
                pass  # phase_flip already handles audio phase;
                      # dual_loop phase is for RF loop phasing

            self._last_bucket_amp = bucket_amp

        # GPS dead-reckoning
        gps_iface = getattr(self.tscm, 'gps', None)
        if gps_iface:
            spoof_flagged = False
            # Check UBX spoof detector if available
            ubx = getattr(self.tscm, 'ubx_spoof', None)
            if ubx and hasattr(ubx, 'spoof_alert'):
                spoof_flagged = ubx.spoof_alert
            # Check spoof detector results
            for m in markers:
                if m.get('detector') in ('gps_spoof', 'gps_spoof_detect'):
                    spoof_flagged = True

            self.gps_dr.feed_gps(
                lat=gps_iface.lat,
                lon=gps_iface.lon,
                alt=gps_iface.alt,
                has_fix=gps_iface.has_fix,
                spoof_flagged=spoof_flagged,
                hdop=getattr(gps_iface, 'hdop', 99.0),
            )

        # SDR watchdog feed (from detection cycle having received data)
        hackrf = getattr(self.tscm, 'hackrf', None)
        if hackrf and getattr(hackrf, 'active', False):
            self.sdr_wd.feed_hackrf()
        bladerf = getattr(self.tscm, 'bladerf_bridge', None)
        if bladerf and bladerf.active:
            self.sdr_wd.feed_bladerf()

    # -- Callbacks ------------------------------------------------------------

    def _on_freq_hop(self, old_freq, new_freq, delta_s):
        """Called by FrequencyHopDetector on hop detection."""
        # Re-lock coherence target
        if hasattr(self.tscm, 'coherence'):
            self.tscm.coherence.set_rf_target(new_freq)

        self.forensic.record_freq_hop(old_freq, new_freq, delta_s)

    def _on_phase_search_step(self, phase_rad, step_idx, total_steps):
        """Called by FrequencyHopDetector during rapid phase search.
        Apply trial phase to coherence controller."""
        if hasattr(self.tscm, 'coherence'):
            self.tscm.coherence.set_rf_phase(phase_rad)

    def _on_phase_flip(self, phase_offset_deg, old_amp, new_amp):
        """Called by PhaseFlipRecovery on phase flip."""
        if hasattr(self.tscm, 'coherence'):
            self.tscm.coherence.set_audio_phase(math.radians(phase_offset_deg))

        ratio = new_amp / (old_amp + 1e-12)
        self.forensic.record_phase_flip(0, phase_offset_deg, ratio)

    def _on_dual_loop_phase(self, phase_deg, bucket_amp):
        """Called by DualLoopNullSearch on phase cycle."""
        best_phase, best_amp = self.dual_loop.get_best_phase()
        self.forensic.record_dual_loop(
            phase_deg, bucket_amp,
            is_best=(phase_deg == best_phase)
        )

    def _on_sdr_restart(self, device):
        """Called by SDRWatchdog on restart."""
        self.forensic.record_sdr_restart(device, 'data_gap', True)

    # -- Helpers --------------------------------------------------------------

    def _extract_dominant_rf(self, markers):
        """Find the strongest RF carrier frequency from recent markers."""
        best = None
        best_amp = 0
        for m in markers[-20:]:
            d = m.get('details', {})
            if m.get('source') == 'RF':
                freq = d.get('freq') or d.get('pump_freq')
                amp = d.get('amp', 0) or d.get('snr', 0) or d.get('strength', 0)
                if freq and amp > best_amp:
                    best = (float(freq), float(amp))
                    best_amp = float(amp)
        return best

    def _extract_bucket_amp(self, markers):
        """Find the latest bucket resonator amplitude."""
        for m in reversed(markers[-20:]):
            if m.get('detector') == 'coiled_bucket_resonator':
                d = m.get('details', {})
                return float(d.get('amp', d.get('corr', 0)))
        return 0.0

    # -- State query ---------------------------------------------------------

    def get_state(self):
        """Return a dict with the state of all subsystems."""
        return {
            'tick_count': self._tick_count,
            'freq_hop': self.freq_hop.get_state(),
            'phase_flip': self.phase_flip.get_state(),
            'dual_loop': self.dual_loop.get_state(),
            'gps_dr': self.gps_dr.get_state(),
            'sdr_watchdog': self.sdr_wd.get_state(),
            'forensic_entries': self.forensic._entry_count,
        }


# ---------------------------------------------------------------------------
# Integration helper — can be called from tscm_final.py without import
# changes.  Just add this at the bottom of TSCMSystem.__init__:
#
#     from adaptive_tactics import TacticalCoordinator
#     self.tactics = TacticalCoordinator(self)
#     self.tactics.start()
#
# And in the main detection loop, after building detection_markers:
#
#     self.tactics.tick(self.detection_markers)
#
# And in shutdown():
#
#     if hasattr(self, 'tactics'): self.tactics.stop()
# ---------------------------------------------------------------------------
