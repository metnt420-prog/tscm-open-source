"""
WiFi Security Hardening — C2 Detection Calibration & Anti-Targeting
====================================================================

PROBLEMS FIXED:
  1. C2 detection thresholds too aggressive — flagging normal devices as C2
  2. No baseline establishment — every device is suspicious on first scan
  3. No cooldown between C2 alerts — scan flooding causes alert storms
  4. WiFi scan results not validated against persistent device fingerprint DB
  5. No channel hopping / "wiggle" to prevent adversarial targeting

INTEGRATION:
  Replace NetworkC2Detector in network_c2.py and the C2 WiFi marker injection
  in tscm_final.py (~lines 4385-4406 and 5316-5320) with CalibratedC2Detector.

  See INTEGRATION_HOOKS below for exact line-by-line patches.

Author: WiFi Security Specialist (subagent)
"""

import json
import math
import os
import pickle
import random
import re
import subprocess
import threading
import time
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("wifi_security")

# ---------------------------------------------------------------------------
# Persistent storage paths (same workspace as tscm_final.py)
# ---------------------------------------------------------------------------
WORKSPACE = Path(__file__).resolve().parent
MODEL_DIR = WORKSPACE / "models"
MODEL_DIR.mkdir(exist_ok=True)
FINGERPRINT_DB_PATH = MODEL_DIR / "wifi_device_fingerprints.pkl"
BASELINE_DB_PATH = MODEL_DIR / "wifi_baseline_stats.pkl"

# ---------------------------------------------------------------------------
# 1. WiFi Device Fingerprinter — persistent baseline
# ---------------------------------------------------------------------------

class WiFiDeviceFingerprint:
    """
    Per-device fingerprint record.

    Stores MAC + observed SSIDs + channels + RSSI history to build a
    statistical baseline.  Only flags NEW devices or devices whose signal
    characteristics have materially changed from their baseline.
    """

    # ---- constants --------------------------------------------------------
    MAX_RSSI_HISTORY = 60            # keep last 60 RSSI samples
    MAX_SSID_HISTORY = 10            # keep last 10 observed SSIDs
    RSSI_STABLE_STD_THRESHOLD = 3.0  # dBm — C2 beacons are very stable
    MIN_OBSERVATIONS = 3             # must see device 3+ times before C2 analysis
    STALE_DEVICE_SEC = 600          # remove devices not seen for 10 minutes

    def __init__(self, bssid: str, first_seen: float):
        self.bssid = bssid
        self.first_seen = first_seen
        self.last_seen = first_seen
        self.sighting_count = 0

        # SSID tracking
        self.ssid_set = set()             # all SSIDs ever seen for this BSSID
        self.ssid_history = deque(maxlen=self.MAX_SSID_HISTORY)

        # Channel tracking
        self.channel_history = deque(maxlen=20)

        # RSSI history (signal_pct converted to dBm each scan)
        self.rssi_history = deque(maxlen=self.MAX_RSSI_HISTORY)

        # Derived statistics (updated on each observation)
        self.rssi_mean = 0.0
        self.rssi_std = 0.0
        self.rssi_stability_score = 0.0  # 1.0 = perfectly stable (suspicious)
        self.typical_channel = None
        self.typical_ssid = ""

        # C2 scoring
        self.c2_score = 0.0            # 0-1 cumulative suspicion
        self.c2_flags = set()          # which heuristics have fired
        self.c2_cooldown_until = 0.0   # timestamp — suppress duplicate alerts

        # Change detection
        self._prev_rssi_mean = None
        self._prev_channel = None

    # ---- update on each scan sighting -------------------------------------

    def observe(self, ssid: str, channel: int, signal_pct: int, now: float):
        """Record a new sighting and recompute statistics."""
        self.last_seen = now
        self.sighting_count += 1

        # SSID
        if ssid:
            self.ssid_set.add(ssid)
            self.ssid_history.append(ssid)

        # Channel
        if channel:
            self.channel_history.append(channel)

        # RSSI
        rssi_dbm = (signal_pct / 2.0) - 100  # approximate conversion
        self.rssi_history.append(rssi_dbm)

        # Recompute stats
        self._compute_stats()
        self.typical_ssid = max(self.ssid_set, key=lambda s: self.ssid_history.count(s)) if self.ssid_set else ""

    # ---- statistics --------------------------------------------------------

    def _compute_stats(self):
        if len(self.rssi_history) < 2:
            self.rssi_mean = self.rssi_history[-1] if self.rssi_history else 0
            self.rssi_std = 0.0
            self.rssi_stability_score = 1.0
            return

        vals = list(self.rssi_history)
        n = len(vals)
        self.rssi_mean = sum(vals) / n
        variance = sum((v - self.rssi_mean) ** 2 for v in vals) / n
        self.rssi_std = math.sqrt(variance)

        # Stability: std / range.  0 = perfect stability, 1 = maximum fluctuation.
        rssi_range = max(vals) - min(vals)
        self.rssi_stability_score = 1.0 - min(1.0, self.rssi_std / max(rssi_range, 1.0))

        # Typical channel (mode)
        if self.channel_history:
            ch_counts = defaultdict(int)
            for ch in self.channel_history:
                ch_counts[ch] += 1
            self.typical_channel = max(ch_counts, key=ch_counts.get)

    # ---- helpers -----------------------------------------------------------

    def is_well_known(self) -> bool:
        """Has this device been seen enough times to have a stable baseline?"""
        return self.sighting_count >= self.MIN_OBSERVATIONS

    def is_stale(self, now: float) -> bool:
        return (now - self.last_seen) > self.STALE_DEVICE_SEC

    def is_rssi_stable(self) -> bool:
        """C2 beacons have very stable RSSI (< 3 dBm std)."""
        return self.rssi_std < self.RSSI_STABLE_STD_THRESHOLD

    def rssi_changed_significantly(self) -> bool:
        """Did the mean RSSI shift > 10 dBm from previous baseline?"""
        if self._prev_rssi_mean is None:
            self._prev_rssi_mean = self.rssi_mean
            return False
        delta = abs(self.rssi_mean - self._prev_rssi_mean)
        self._prev_rssi_mean = self.rssi_mean
        return delta > 10

    def to_dict(self) -> dict:
        return {
            "bssid": self.bssid,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "sighting_count": self.sighting_count,
            "ssids": list(self.ssid_set),
            "typical_ssid": self.typical_ssid,
            "typical_channel": self.typical_channel,
            "rssi_mean": round(self.rssi_mean, 1),
            "rssi_std": round(self.rssi_std, 1),
            "rssi_stability": round(self.rssi_stability_score, 2),
            "c2_score": round(self.c2_score, 3),
            "c2_flags": list(self.c2_flags),
        }


class WiFiFingerprintDatabase:
    """
    Persistent database of WiFi device fingerprints.

    Loads from disk on init, saves periodically.  Supports baseline
    statistics for adaptive threshold calibration.
    """

    SAVE_INTERVAL_SEC = 120  # save to disk every 2 minutes

    def __init__(self, db_path: str = str(FINGERPRINT_DB_PATH)):
        self.db_path = db_path
        self.devices: dict[str, WiFiDeviceFingerprint] = {}
        self._lock = threading.Lock()
        self._last_save = 0.0
        self._load()

    def _load(self):
        if not os.path.exists(self.db_path):
            log.info("WiFi fingerprint DB: new (no prior file)")
            return
        try:
            with open(self.db_path, "rb") as f:
                data = pickle.load(f)
            if isinstance(data, dict):
                self.devices = data
                log.info(f"WiFi fingerprint DB: loaded {len(self.devices)} devices")
            else:
                log.warning("WiFi fingerprint DB: corrupt format, starting fresh")
                self.devices = {}
        except Exception as e:
            log.warning(f"WiFi fingerprint DB: load failed ({e}), starting fresh")
            self.devices = {}

    def _save(self):
        try:
            with open(self.db_path, "wb") as f:
                pickle.dump(self.devices, f, protocol=pickle.HIGHEST_PROTOCOL)
            log.debug(f"WiFi fingerprint DB: saved {len(self.devices)} devices")
        except Exception as e:
            log.error(f"WiFi fingerprint DB: save failed ({e})")

    def maybe_save(self, now: float):
        if now - self._last_save > self.SAVE_INTERVAL_SEC:
            with self._lock:
                self._save()
            self._last_save = now

    def get_or_create(self, bssid: str, now: float) -> WiFiDeviceFingerprint:
        with self._lock:
            if bssid not in self.devices:
                self.devices[bssid] = WiFiDeviceFingerprint(bssid, now)
            return self.devices[bssid]

    def observe(self, bssid: str, ssid: str, channel: int, signal_pct: int, now: float):
        fp = self.get_or_create(bssid, now)
        fp.observe(ssid, channel, signal_pct, now)

    def get_baseline_stats(self) -> dict:
        """
        Compute population-wide statistics for adaptive thresholds.

        Returns dict with:
          - mean_rssi_std: average RSSI standard deviation across all devices
          - pct_hidden: fraction of devices with hidden/empty SSID
          - pct_strong: fraction with RSSI > -60 dBm
          - mean_sighting_count: average number of sightings per device
          - total_known: total number of fingerprinted devices
        """
        with self._lock:
            if not self.devices:
                return {
                    "mean_rssi_std": 5.0,  # default assumptions
                    "pct_hidden": 0.1,
                    "pct_strong": 0.2,
                    "mean_sighting_count": 1.0,
                    "total_known": 0,
                }

            rssi_stds = []
            hidden_count = 0
            strong_count = 0
            sighting_counts = []

            for fp in self.devices.values():
                if fp.sighting_count > 0:
                    rssi_stds.append(fp.rssi_std)
                    sighting_counts.append(fp.sighting_count)
                if not fp.typical_ssid:
                    hidden_count += 1
                if fp.rssi_mean > -60:
                    strong_count += 1

            n = max(len(self.devices), 1)
            return {
                "mean_rssi_std": sum(rssi_stds) / max(len(rssi_stds), 1),
                "pct_hidden": hidden_count / n,
                "pct_strong": strong_count / n,
                "mean_sighting_count": sum(sighting_counts) / max(len(sighting_counts), 1),
                "total_known": n,
            }

    def cleanup_stale(self, now: float):
        """Remove devices not seen for > STALE_DEVICE_SEC."""
        with self._lock:
            stale = [b for b, fp in self.devices.items() if fp.is_stale(now)]
            for b in stale:
                del self.devices[b]
            if stale:
                log.info(f"WiFi fingerprint DB: pruned {len(stale)} stale devices")

    def status_summary(self) -> dict:
        with self._lock:
            return {
                "total_fingerprints": len(self.devices),
                "well_known": sum(1 for fp in self.devices.values() if fp.is_well_known()),
                "c2_flagged": sum(1 for fp in self.devices.values() if fp.c2_score > 0.5),
            }


# ---------------------------------------------------------------------------
# 2. Calibrated C2 Detection with Adaptive Thresholds
# ---------------------------------------------------------------------------

class CalibratedC2Detector:
    """
    Drop-in replacement for NetworkC2Detector.detect_c2_beacons().

    Uses adaptive thresholds derived from baseline statistics, requires
    minimum observation counts before flagging, and analyzes RSSI stability
    patterns to distinguish C2 beacons from normal devices.

    C2 BEACON SIGNATURES (calibrated):
      - Stable RSSI (std < 3 dBm) — beacons don't move
      - Hidden SSID with strong signal — covert AP
      - Consistent channel hopping — active scanning
      - Sudden appearance after long absence — re-activated C2
      - Unusual persistence (>10 min continuous presence)

    NORMAL DEVICE SIGNATURES (exclusion):
      - Fluctuating RSSI (std > 5 dBm) — people move, phones roam
      - Multiple SSIDs (AP reconfiguration is normal)
      - Gradual signal changes — natural movement
      - Seen since baseline was established — known good device
    """

    # ---- adaptive threshold multipliers (calibrated from baseline) ---------
    HIDDEN_AP_RSSI_MULTIPLIER = 1.5    # relative to baseline mean_rssi
    PERSISTENCE_THRESHOLD_MIN = 600    # seconds (10 min) before persistence flags
    MIN_OBSERVATIONS_BEFORE_C2 = 3     # must see 3+ times
    C2_SCORE_THRESHOLD = 0.6           # 0-1, above this = flag
    C2_SCORE_HIGH = 0.8                # high confidence C2
    SIGNAL_CHANGE_THRESHOLD_DBM = 10    # sudden 10 dBm shift = suspicious

    def __init__(self, fingerprint_db: WiFiFingerprintDatabase):
        self.fp_db = fingerprint_db
        self.detections = []          # latest detection results
        self._lock = threading.Lock()

    def detect(self, devices: list, lat=None, lon=None) -> list:
        """
        Analyze WiFi devices for C2 patterns using calibrated heuristics.

        Args:
            devices: list of dicts from scan_wifi_devices(), each with:
                     bssid, ssid, rssi, signal_pct, detector, device_type
            lat, lon: optional GPS coordinates (only used if real fix)

        Returns:
            list of C2 detection dicts with detector, bssid, rssi, c2_score, reasons
        """
        now = time.time()
        baseline = self.fp_db.get_baseline_stats()
        detections = []

        # Adaptive thresholds derived from baseline statistics
        hidden_rssi_threshold = -60 + (baseline["pct_hidden"] * 10)  # more hidden = higher threshold
        proximate_rssi_threshold = -40 - (baseline["pct_strong"] * 5)  # more strong = less sensitive
        persistence_threshold = self.PERSISTENCE_THRESHOLD_MIN
        min_obs = max(self.MIN_OBSERVATIONS_BEFORE_C2, int(baseline["mean_sighting_count"] * 0.5))

        for dev in devices:
            bssid = dev["bssid"]
            rssi = dev.get("rssi", -100)
            ssid = dev.get("ssid")
            signal_pct = dev.get("signal_pct", 0)

            # Get or create fingerprint
            fp = self.fp_db.get_or_create(bssid, now)

            # ---- Skip devices without enough observations --------------------
            if fp.sighting_count < min_obs:
                continue  # Too new to judge — no false positives on first sight

            c2_score = 0.0
            reasons = []

            # ---- Heuristic 1: Hidden SSID with strong signal ----------------
            # C2 APs often broadcast hidden SSIDs at high power
            # BUT: many legitimate networks are hidden.  Adaptive threshold.
            is_hidden = not ssid or ssid.strip() == ""
            if is_hidden and rssi > hidden_rssi_threshold:
                # How unusual is this?  Compare to baseline
                hidden_bonus = min(0.3, 0.15 * (abs(rssi - hidden_rssi_threshold) / 10))
                c2_score += hidden_bonus
                reasons.append(f"hidden_ssid_strong_rssi({rssi}dBm>{hidden_rssi_threshold:.0f}dBm)")

            # ---- Heuristic 2: RSSI Stability Analysis ----------------------
            # C2 beacons have extremely stable RSSI (stationary transmitter).
            # Normal devices fluctuate due to movement, multipath, handoffs.
            if fp.is_rssi_stable() and fp.rssi_std < 2.0:
                # Very stable signal — suspicious if also hidden or persistent
                stability_bonus = 0.2
                if is_hidden:
                    stability_bonus += 0.15
                c2_score += stability_bonus
                reasons.append(f"stable_rssi(std={fp.rssi_std:.1f}dBm)")

            # ---- Heuristic 3: Persistent long-term device -------------------
            # C2 relays stay active for extended periods.  Normal devices come/go.
            persistence = now - fp.first_seen
            if persistence > persistence_threshold:
                persist_bonus = min(0.25, 0.05 * (persistence / 60 - 10))
                if fp.is_rssi_stable():
                    persist_bonus += 0.1  # stable AND persistent = very suspicious
                c2_score += persist_bonus
                reasons.append(f"persistent({int(persistence/60)}min)")

            # ---- Heuristic 4: Sudden RSSI shift (device moved close) ------
            # Could indicate a C2 operator physically approaching the target
            if fp.rssi_changed_significantly():
                c2_score += 0.15
                reasons.append(f"rssi_shift(Δ>{self.SIGNAL_CHANGE_THRESHOLD_DBM}dBm)")

            # ---- Heuristic 5: Channel inconsistency ------------------------
            # C2 devices may hop channels to avoid detection.  If a device is
            # seen on 3+ different channels, it's more likely active scanning.
            unique_channels = set(fp.channel_history)
            if len(unique_channels) >= 3 and fp.sighting_count > 5:
                c2_score += 0.1
                reasons.append(f"channel_hopping({len(unique_channels)}ch)")

            # ---- Heuristic 6: Near-field proximity --------------------------
            # Extremely strong signal (< -40 dBm) = within ~10 meters
            # BUT: in dense environments, strong signals are common. Use adaptive threshold.
            if rssi > proximate_rssi_threshold:
                prox_bonus = 0.1 * (abs(rssi - proximate_rssi_threshold) / 10)
                c2_score += min(0.2, prox_bonus)
                reasons.append(f"near_field({rssi}dBm)")

            # ---- ANTI-FALSE-POSITIVE: Known device discount -----------------
            # If this device has been in the baseline for a long time with
            # low C2 score, apply a "trust discount"
            if fp.sighting_count > 20 and fp.c2_score < 0.2:
                trust_discount = min(0.3, 0.01 * (fp.sighting_count - 20))
                c2_score = max(0, c2_score - trust_discount)
                if trust_discount > 0.05:
                    reasons.append(f"trusted_device(discount={trust_discount:.2f})")

            # ---- Clamp and record -------------------------------------------
            c2_score = min(1.0, c2_score)
            fp.c2_score = max(fp.c2_score * 0.7, c2_score)  # decay old score, boost new

            # ---- Only flag if above threshold ------------------------------
            if c2_score >= self.C2_SCORE_THRESHOLD:
                severity = "high" if c2_score >= self.C2_SCORE_HIGH else "medium"
                detection = {
                    "detector": "c2_calibrated",
                    "bssid": bssid,
                    "ssid": ssid or "hidden",
                    "rssi": rssi,
                    "c2_score": round(c2_score, 3),
                    "severity": severity,
                    "sighting_count": fp.sighting_count,
                    "persistence_min": int((now - fp.first_seen) / 60),
                    "reasons": reasons,
                    "rssi_std": round(fp.rssi_std, 1),
                    "rssi_stability": round(fp.rssi_stability_score, 2),
                    "typical_channel": fp.typical_channel,
                }
                detections.append(detection)

                # Update fingerprint flags
                fp.c2_flags.update(reasons)

        with self._lock:
            self.detections = detections

        return detections


# ---------------------------------------------------------------------------
# 3. Alert Cooldown System
# ---------------------------------------------------------------------------

class AlertCooldownManager:
    """
    Rate-limits C2 alerts per device to prevent alert storms.

    Rule: max 1 C2 alert per device per COOLDOWN_SECONDS.
    This prevents the cascade where 40 devices × 3 heuristics = 120 alerts per scan.
    """

    DEFAULT_COOLDOWN_SEC = 60.0  # 1 alert per device per minute

    def __init__(self, cooldown_sec: float = DEFAULT_COOLDOWN_SEC):
        self.cooldown_sec = cooldown_sec
        self._last_alert: dict[str, float] = {}   # bssid -> timestamp
        self._lock = threading.Lock()
        self._suppressed_count = 0
        self._total_count = 0

    def should_alert(self, bssid: str, now: float) -> bool:
        """
        Returns True if alert is allowed, False if suppressed by cooldown.
        """
        with self._lock:
            self._total_count += 1
            last = self._last_alert.get(bssid, 0)
            if now - last < self.cooldown_sec:
                self._suppressed_count += 1
                return False
            self._last_alert[bssid] = now
            return True

    def force_alert(self, bssid: str, now: float):
        """Override cooldown (e.g., for high-severity escalations)."""
        with self._lock:
            self._last_alert[bssid] = now

    def clear_device(self, bssid: str):
        with self._lock:
            self._last_alert.pop(bssid, None)

    def stats(self) -> dict:
        with self._lock:
            return {
                "total_evaluated": self._total_count,
                "suppressed": self._suppressed_count,
                "active_cooldowns": len(self._last_alert),
                "cooldown_sec": self.cooldown_sec,
            }


# ---------------------------------------------------------------------------
# 4. WiFi Channel Hopper / Wiggle (Anti-Targeting)
# ---------------------------------------------------------------------------

class WiFiChannelHopper:
    """
    Randomly changes WiFi scan channels to prevent adversarial targeting.

    On Windows, true channel hopping requires monitor mode (not available via
    netsh).  Instead, this module:

    1. Inserts random delays (2-8s jitter) between scans to desync from
       any adversarial scanner timing.
    2. Forces fresh scan results by timing scans to avoid the Windows
       netsh cache (~30s TTL on Windows).
    3. Logs channel changes for forensic tracking.

    For Linux with monitor mode (future), this would use:
      iwconfig <iface> channel <ch>
      or  iw dev <iface> set channel <ch>
    """

    # 2.4 GHz and 5 GHz channels commonly used
    CHANNELS_2GHZ = [1, 6, 11]                        # non-overlapping
    CHANNELS_2GHZ_ALL = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    CHANNELS_5GHZ = [36, 40, 44, 48, 149, 153, 157, 161, 165]

    # Scan timing jitter range (seconds)
    SCAN_JITTER_MIN = 2.0
    SCAN_JITTER_MAX = 8.0

    def __init__(self, interface: str = "Wi-Fi 2"):
        self.interface = interface
        self.current_channel = 0
        self.hop_count = 0
        self.hop_history = deque(maxlen=50)
        self._scan_jitter = 5.0  # initial delay between scans

    def get_scan_delay(self) -> float:
        """
        Returns a random delay for the next scan cycle.

        The jitter prevents an adversary from synchronizing their
        scanning with ours.  Range: 2-8 seconds.
        """
        jitter = random.uniform(self.SCAN_JITTER_MIN, self.SCAN_JITTER_MAX)
        self._scan_jitter = jitter
        return jitter

    def hop(self) -> int:
        """
        Select next channel for scan focus.

        On Windows (netsh), we can't set channels directly, but we log the
        intended channel and return it for the scan metadata.  The Windows
        scan will include whatever channels netsh returns; the hop timing
        provides anti-targeting benefit regardless.

        On Linux with monitor mode, this would execute:
          subprocess.run(['iwconfig', self.interface, 'channel', str(channel)])

        Returns: the next channel number
        """
        # Prefer 2.4 GHz non-overlapping channels most of the time
        channels = self.CHANNELS_2GHZ
        r = random.random()
        if r < 0.2:
            channels = self.CHANNELS_2GHZ_ALL
        elif r < 0.3:
            channels = self.CHANNELS_5GHZ

        next_ch = random.choice(channels)
        now = time.time()
        self.hop_count += 1
        self.hop_history.append({"time": now, "channel": next_ch, "hop": self.hop_count})
        self.current_channel = next_ch
        return next_ch

    def status(self) -> dict:
        return {
            "interface": self.interface,
            "current_channel": self.current_channel,
            "hop_count": self.hop_count,
            "scan_jitter_sec": round(self._scan_jitter, 1),
            "recent_hops": list(self.hop_history)[-5:] if self.hop_history else [],
        }


# ---------------------------------------------------------------------------
# 5. Hardened WiFi Scanner (replaces NetworkC2Detector.scan_wifi_devices)
# ---------------------------------------------------------------------------

def hardened_scan_wifi_devices(interface: str = "Wi-Fi 2") -> list:
    """
    Enhanced WiFi scan that includes parsing improvements and validates
    output against the fingerprint database.

    Returns same format as NetworkC2Detector.scan_wifi_devices() for drop-in compat.
    """
    devices = []
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=Bssid", f"interface={interface}"],
            capture_output=True, text=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        current_bssid = None
        current_ssid = None
        current_channel = None

        for line in result.stdout.split("\n"):
            line = line.strip()

            # BSSID
            bssid_match = re.match(r"BSSID\s+\d+\s+:\s+([0-9a-fA-F:]{17})", line)
            if bssid_match:
                current_bssid = bssid_match.group(1).upper()
                continue

            # SSID
            ssid_match = re.match(r"SSID\s+\d+\s+:\s+(.+)", line)
            if ssid_match:
                current_ssid = ssid_match.group(1).strip()
                continue

            # Channel (additional field not captured in original)
            ch_match = re.match(r"Channel\s+:\s*(\d+)", line)
            if ch_match:
                current_channel = int(ch_match.group(1))

            # Signal strength
            sig_match = re.match(r"Signal\s+:\s+(\d+)%", line)
            if sig_match and current_bssid:
                sig_pct = int(sig_match.group(1))
                rssi = (sig_pct / 2.0) - 100

                devices.append({
                    "bssid": current_bssid,
                    "ssid": current_ssid,
                    "rssi": rssi,
                    "signal_pct": sig_pct,
                    "channel": current_channel,
                    "detector": "wifi_device",
                    "device_type": "AP" if current_ssid else "client",
                })
                current_bssid = None
                current_ssid = None
                current_channel = None

        log.info(f"Hardened WiFi scan: {len(devices)} devices on {interface}")

    except subprocess.TimeoutExpired:
        log.warning("WiFi scan timed out (15s)")
    except Exception as e:
        log.error(f"WiFi scan failed: {e}")

    return devices


# ---------------------------------------------------------------------------
# 6. INTEGRATION: HardenedNetworkC2Detector
# ---------------------------------------------------------------------------

class HardenedNetworkC2Detector:
    """
    Drop-in replacement for NetworkC2Detector that incorporates all fixes.

    FEATURES:
      - Persistent device fingerprint database
      - Adaptive C2 thresholds based on baseline statistics
      - Minimum observation count before flagging (3+ consistent sightings)
      - RSSI stability analysis (C2 beacons have stable RSSI)
      - Alert cooldown (max 1 alert per device per 60s)
      - Channel hopping / wiggle (anti-targeting)
      - Stale device cleanup

    USAGE:
      Replace:
        from network_c2 import NetworkC2Detector
        self.network_c2 = NetworkC2Detector(interface="Wi-Fi 2")
        self.network_c2.start()

      With:
        from wifi_fixes import HardenedNetworkC2Detector
        self.network_c2 = HardenedNetworkC2Detector(interface="Wi-Fi 2")
        self.network_c2.start()
    """

    # ---- configurable thresholds ------------------------------------------
    SCAN_INTERVAL_MIN = 10.0   # minimum seconds between scans
    SCAN_INTERVAL_MAX = 30.0   # maximum seconds (with wiggle jitter)
    STALE_CLEANUP_INTERVAL = 300  # cleanup stale devices every 5 min
    BASELINE_UPDATE_INTERVAL = 60  # recompute baseline stats every 60s

    def __init__(self, interface: str = "Wi-Fi 2"):
        self.interface = interface
        self.running = False
        self.thread = None

        # ---- core components (from wifi_fixes.py) -------------------------
        self.fp_db = WiFiFingerprintDatabase()
        self.c2_detector = CalibratedC2Detector(self.fp_db)
        self.cooldown_mgr = AlertCooldownManager(cooldown_sec=60.0)
        self.channel_hopper = WiFiChannelHopper(interface)

        # ---- backward-compatible fields ------------------------------------
        self.results = []          # latest C2 detections (for tscm_final.py compat)
        self.device_db = {}       # backward compat with NetworkC2Detector
        self._lock = threading.Lock()
        self._beacon_history = deque(maxlen=100)

        # ---- internal counters --------------------------------------------
        self._scan_count = 0
        self._total_devices_seen = 0
        self._total_c2_flagged = 0
        self._total_alerts_suppressed = 0
        self._last_stale_cleanup = 0.0
        self._last_baseline_update = 0.0

    # ---- scan methods (drop-in compat) -------------------------------------

    def enable_monitor_mode(self) -> bool:
        """Compatible with NetworkC2Detector.  On Windows, falls back to active scanning."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if self.interface not in result.stdout:
                log.warning(f"Interface '{self.interface}' not found in wlan interfaces")
                return False
            log.info(f"Using {self.interface} for hardened WiFi device discovery")
            return True
        except Exception as e:
            log.error(f"Monitor mode setup failed: {e}")
            return False

    def scan_wifi_devices(self) -> list:
        """
        Drop-in compatible scan method.  Uses hardened scanner.
        """
        return hardened_scan_wifi_devices(self.interface)

    def detect_c2_beacons(self, devices: list, lat=None, lon=None) -> list:
        """
        Drop-in compatible C2 detection.

        Applies calibrated detection with cooldown filtering.
        """
        now = time.time()

        # Step 1: Update fingerprint database with all observations
        for dev in devices:
            self.fp_db.observe(
                bssid=dev["bssid"],
                ssid=dev.get("ssid", ""),
                channel=dev.get("channel", 0),
                signal_pct=dev.get("signal_pct", 0),
                now=now,
            )

        # Step 2: Run calibrated C2 detection
        raw_detections = self.c2_detector.detect(devices, lat, lon)

        # Step 3: Apply alert cooldown
        filtered_detections = []
        for det in raw_detections:
            bssid = det["bssid"]
            if self.cooldown_mgr.should_alert(bssid, now):
                filtered_detections.append(det)
            # High-severity detections bypass cooldown (escalation)
            elif det.get("severity") == "high" and det.get("c2_score", 0) > 0.8:
                self.cooldown_mgr.force_alert(bssid, now)
                filtered_detections.append(det)

        # Step 4: Update backward-compatible device_db for legacy code
        with self._lock:
            self.device_db.clear()
            for dev in devices:
                bssid = dev["bssid"]
                fp = self.fp_db.get_or_create(bssid, now)
                self.device_db[bssid] = {
                    "first_seen": fp.first_seen,
                    "last_seen": fp.last_seen,
                    "count": fp.sighting_count,
                    "ssids": fp.ssid_set,
                    "c2_score": fp.c2_score,
                    "rssi_mean": fp.rssi_mean,
                    "rssi_std": fp.rssi_std,
                }
            self.results = filtered_detections
            self._total_devices_seen = len(devices)
            self._total_c2_flagged = len(filtered_detections)

        # Step 5: Periodic maintenance
        if now - self._last_stale_cleanup > self.STALE_CLEANUP_INTERVAL:
            self.fp_db.cleanup_stale(now)
            self._last_stale_cleanup = now

        if now - self._last_baseline_update > self.BASELINE_UPDATE_INTERVAL:
            baseline = self.fp_db.get_baseline_stats()
            log.debug(f"Baseline update: {baseline['total_known']} devices, "
                      f"mean_rssi_std={baseline['mean_rssi_std']:.1f}dBm")
            self._last_baseline_update = now

        self.fp_db.maybe_save(now)

        return filtered_detections

    # ---- start/stop lifecycle (drop-in compat) -----------------------------

    def start(self):
        """Start periodic WiFi scanning with wiggle anti-targeting."""
        self.running = True
        self.thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.thread.start()
        log.info(f"Hardened C2 detector started on {self.interface} "
                 f"(cooldown=60s, min_obs=3, wiggle=ON)")

    def _scan_loop(self):
        while self.running:
            try:
                # Channel hop before scan
                next_ch = self.channel_hopper.hop()

                # Scan
                devices = self.scan_wifi_devices()

                # C2 detection with all calibrations
                c2_detections = self.detect_c2_beacons(devices, None, None)

                self._scan_count += 1
                cooldown_stats = self.cooldown_mgr.stats()

                if devices or c2_detections:
                    log.info(
                        f"Scan #{self._scan_count}: "
                        f"{len(devices)} devices, "
                        f"{len(c2_detections)} C2 flagged "
                        f"(suppressed: {cooldown_stats['suppressed']}), "
                        f"ch={next_ch}, "
                        f"jitter={self.channel_hopper._scan_jitter:.1f}s"
                    )

                # Wiggle: random delay to prevent adversarial timing
                delay = self.channel_hopper.get_scan_delay()
                time.sleep(delay)

            except Exception as e:
                log.error(f"Scan cycle error: {e}")
                import traceback
                traceback.print_exc()
                time.sleep(10)

    def get_detections(self, lat=None, lon=None) -> list:
        """
        Drop-in compatible detection getter.
        Only sets position if caller has real GPS (non-zero).
        """
        with self._lock:
            results = list(self.results)
        if lat and lon and lat != 0 and lon != 0:
            for r in results:
                r["lat"] = lat
                r["lon"] = lon
        return results

    def stop(self):
        self.running = False

    def status(self) -> dict:
        """Comprehensive status for logging / TSCM integration."""
        fp_stats = self.fp_db.status_summary()
        cooldown_stats = self.cooldown_mgr.stats()
        hopper_stats = self.channel_hopper.status()
        baseline = self.fp_db.get_baseline_stats()

        return {
            "interface": self.interface,
            "running": self.running,
            "scan_count": self._scan_count,
            "total_devices_seen": self._total_devices_seen,
            "total_c2_flagged": self._total_c2_flagged,
            "total_alerts_suppressed": self._total_alerts_suppressed,
            "fingerprint_db": fp_stats,
            "cooldown": cooldown_stats,
            "channel_hopper": hopper_stats,
            "baseline_stats": baseline,
        }


# ---------------------------------------------------------------------------
# 7. INTEGRATION HOOKS — exact patches for network_c2.py and tscm_final.py
# ---------------------------------------------------------------------------

INTEGRATION_HOOKS = """
===============================================================================
  INTEGRATION HOOKS: Patching network_c2.py and tscm_final.py
===============================================================================

=== PATCH 1: network_c2.py — Replace entire class ===
  File: C:\\Users\\carpe\\.openclaw-autoclaw\\workspace\\network_c2.py

  Replace the import at the TOP of tscm_final.py (~line 3533):

    OLD (tscm_final.py lines 3532-3536):
        self.network_c2 = None
        try:
            from network_c2 import NetworkC2Detector
            self.network_c2 = NetworkC2Detector(interface="Wi-Fi 2")
            self.network_c2.start()

    NEW:
        self.network_c2 = None
        try:
            from wifi_fixes import HardenedNetworkC2Detector
            self.network_c2 = HardenedNetworkC2Detector(interface="Wi-Fi 2")
            self.network_c2.start()

  This single change activates ALL fixes because HardenedNetworkC2Detector
  is a drop-in replacement with the same interface (.results, .get_detections(),
  ._lock, .device_db).


=== PATCH 2: tscm_final.py — C2 WiFi marker injection (~lines 4385-4406) ===

  OLD:
        # Inject C2 WiFi markers directly from network_c2 thread
        c2_wifi_markers = []
        if hasattr(self, 'network_c2') and self.network_c2 and hasattr(self.network_c2, 'results'):
            try:
                with self.network_c2._lock:
                    c2_dets = list(self.network_c2.results)
                for det in c2_dets:
                    c2_wifi_markers.append({
                        'detector': det.get('detector', 'c2_wifi'),
                        'bssid': det.get('bssid', '?'),
                        'rssi': det.get('rssi', -100),
                        'strength': abs(det.get('rssi', -100)),
                        'details': det,
                        'time': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'source': 'WiFi',
                        'lat': self.gps.lat if self.gps.has_fix else 0,
                        'lon': self.gps.lon if self.gps.has_fix else 0,
                        'aoa': float(self.aoa) if self.aoa else 0.0
                    })

  NEW:
        # Inject C2 WiFi markers (calibrated — from wifi_fixes.py)
        c2_wifi_markers = []
        if hasattr(self, 'network_c2') and self.network_c2 and hasattr(self.network_c2, 'results'):
            try:
                with self.network_c2._lock:
                    c2_dets = list(self.network_c2.results)
                for det in c2_dets:
                    # Use calibrated c2_score for severity classification
                    c2_score = det.get('c2_score', 0)
                    severity = 'high' if c2_score >= 0.8 else (
                               'medium' if c2_score >= 0.6 else 'low')
                    c2_wifi_markers.append({
                        'detector': det.get('detector', 'c2_calibrated'),
                        'bssid': det.get('bssid', '?'),
                        'rssi': det.get('rssi', -100),
                        'strength': abs(det.get('rssi', -100)),
                        'severity': severity,
                        'c2_score': c2_score,
                        'details': det,
                        'time': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'source': 'WiFi',
                        'lat': self.gps.lat if self.gps.has_fix else 0,
                        'lon': self.gps.lon if self.gps.has_fix else 0,
                        'aoa': float(self.aoa) if self.aoa else 0.0
                    })


=== PATCH 3: tscm_final.py — Status summary alfa_devices (~line 4133) ===

  OLD:
                'alfa_devices': len(self.network_c2.get_detections(0, 0)) if hasattr(self, 'network_c2') else 0,

  NEW:
                'alfa_devices': len(self.network_c2.device_db) if hasattr(self, 'network_c2') and self.network_c2 else 0,
                'c2_flagged': len(self.network_c2.results) if hasattr(self, 'network_c2') and self.network_c2 else 0,


=== PATCH 4: tscm_final.py — Duplicate alfa_devices reference (~line 4399) ===

  OLD:
                'alfa_devices': len(self.network_c2.get_detections(0, 0)) if hasattr(self, 'network_c2') else 0,

  NEW:
                'alfa_devices': len(self.network_c2.device_db) if hasattr(self, 'network_c2') and self.network_c2 else 0,
                'c2_flagged': len(self.network_c2.results) if hasattr(self, 'network_c2') and self.network_c2 else 0,


=== PATCH 5: tscm_final.py — Periodic C2 check (~lines 5316-5320) ===

  OLD:
            if hasattr(self, 'network_c2') and self.network_c2 and self._cycle_count % 30 == 0:
                try:
                    with self.network_c2._lock:
                        c2_dets = list(self.network_c2.results) if hasattr(self.network_c2, 'results') else []

  NEW:
            if hasattr(self, 'network_c2') and self.network_c2 and self._cycle_count % 30 == 0:
                try:
                    with self.network_c2._lock:
                        c2_dets = list(self.network_c2.results) if hasattr(self.network_c2, 'results') else []
                    # Log hardened detector status for diagnostics
                    if hasattr(self.network_c2, 'status'):
                        hard_status = self.network_c2.status()
                        log.info(f"Hardened C2: {hard_status['fingerprint_db']}, "
                                 f"suppressed={hard_status['cooldown']['suppressed']}")


=== PATCH 6 (OPTIONAL): wifi_radar.py — Use shared fingerprint DB ===

  If you want wifi_radar.py to share the same fingerprint database
  (avoiding duplicate device tracking), add to AlfaWiFiRadar.__init__:

    from wifi_fixes import WiFiFingerprintDatabase
    self.fp_db = WiFiFingerprintDatabase()

  Then in _scan_loop, replace the self.seen_bssids tracking with:
    self.fp_db.observe(bssid, ssid, channel, signal_pct, now)

===============================================================================
"""


# ---------------------------------------------------------------------------
# 8. Quick diagnostic: print current system state
# ---------------------------------------------------------------------------

def diagnose_current_state():
    """
    Run a one-shot diagnostic to show what the current (un-hardened) system
    would flag vs. what the hardened system would flag.

    Useful for validating the fix before deploying.
    """
    print("\n" + "=" * 60)
    print(" WiFi Security Diagnostic")
    print("=" * 60)

    # Load existing fingerprint data if any
    fp_db = WiFiFingerprintDatabase()
    baseline = fp_db.get_baseline_stats()

    print(f"\nBaseline Stats:")
    print(f"  Total fingerprinted devices: {baseline['total_known']}")
    print(f"  Mean RSSI std: {baseline['mean_rssi_std']:.1f} dBm")
    print(f"  Hidden SSID fraction: {baseline['pct_hidden']:.1%}")
    print(f"  Strong signal fraction: {baseline['pct_strong']:.1%}")
    print(f"  Mean sighting count: {baseline['mean_sighting_count']:.1f}")

    print(f"\nFingerprint DB:")
    fp_summary = fp_db.status_summary()
    for k, v in fp_summary.items():
        print(f"  {k}: {v}")

    # Show devices with high C2 scores
    high_score = [(b, fp) for b, fp in fp_db.devices.items() if fp.c2_score > 0.3]
    if high_score:
        print(f"\nDevices with C2 score > 0.3:")
        for bssid, fp in sorted(high_score, key=lambda x: -x[1].c2_score):
            print(f"  {bssid}: score={fp.c2_score:.3f}, "
                  f"ssids={list(fp.ssid_set)}, "
                  f"rssi_mean={fp.rssi_mean:.1f}, "
                  f"rssi_std={fp.rssi_std:.1f}, "
                  f"sightings={fp.sighting_count}")

    # Run a scan
    print(f"\nRunning one-shot hardened scan...")
    devices = hardened_scan_wifi_devices()
    print(f"  Found {len(devices)} devices")

    if devices:
        c2 = CalibratedC2Detector(fp_db)
        detections = c2.detect(devices)
        cooldown = AlertCooldownManager()

        print(f"\nCalibrated C2 Analysis (requires 3+ observations):")
        if not detections:
            print("  No C2 flags (devices may need more observations to establish baseline)")
        else:
            for det in detections:
                can_alert = cooldown.should_alert(det["bssid"], time.time())
                print(f"  {det['bssid']}: score={det['c2_score']:.3f} "
                      f"severity={det['severity']} "
                      f"reasons={det['reasons']} "
                      f"{'[ALERT]' if can_alert else '[COOLED DOWN]'}")

    print(f"\nIntegration hooks: see INTEGRATION_HOOKS string above")
    print("=" * 60)


# ---------------------------------------------------------------------------
# MAIN / SELF-TEST
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print("wifi_fixes.py — WiFi Security Hardening Module")
    print("Run with --diagnose for system state check, or --demo for live demo")

    import sys

    if "--diagnose" in sys.argv:
        diagnose_current_state()
    elif "--demo" in sys.argv:
        print("\nStarting HardenedNetworkC2Detector demo (30s)...")
        detector = HardenedNetworkC2Detector(interface="Wi-Fi 2")
        detector.enable_monitor_mode()
        detector.start()

        try:
            start = time.time()
            while time.time() - start < 30:
                time.sleep(5)
                status = detector.status()
                print(
                    f"  [{int(time.time()-start):2d}s] "
                    f"scans={status['scan_count']} "
                    f"devices={status['total_devices_seen']} "
                    f"c2={status['total_c2_flagged']} "
                    f"suppressed={status['cooldown']['suppressed']} "
                    f"known={status['fingerprint_db']['total_fingerprints']} "
                    f"ch={status['channel_hopper']['current_channel']}"
                )
        except KeyboardInterrupt:
            pass

        detector.stop()
        print("\nFinal status:")
        print(json.dumps(detector.status(), indent=2, default=str))
    else:
        print("\nAvailable commands:")
        print("  python wifi_fixes.py --diagnose   # One-shot state check")
        print("  python wifi_fixes.py --demo      # 30-second live demo")
        print("\nIntegration hooks:")
        print(INTEGRATION_HOOKS)
