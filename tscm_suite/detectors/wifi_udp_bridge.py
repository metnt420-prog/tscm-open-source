"""
wifi_udp_bridge.py — UDP WiFi Bridge for TSCM System
=====================================================

PROBLEM SOLVED:
  The Alfa WiFi adapter is in a Kali VM running in monitor mode.
  WiFi scan data arrives via UDP port 9999 from the Kali VM as JSON.
  The old code ran `netsh wlan show networks` on Windows — WRONG.

  This module:
  1. Replaces WiFiUDPListener with EnhancedWiFiUDPListener that parses
     device JSON from Kali and feeds it into the CalibratedC2Detector pipeline.
  2. Provides UDPChannelHopper to send channel change commands BACK to
     Kali via UDP port 9998.
  3. Makes HardenedNetworkC2Detector consume UDP data instead of netsh.

INTEGRATION:
  See INTEGRATION_INSTRUCTIONS at the bottom of this file.

KALI → WINDOWS (port 9999):
  Single device JSON:
    {"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "Hidden", "channel": 6,
     "signal_pct": 85, "freq": 2437}

  Batch (list):
    [{"bssid":"AA:BB:CC:DD:EE:FF", "ssid":"Hidden", "channel":6,
      "signal_pct":85, "freq":2437}, ...]

WINDOWS → KALI (port 9998):
  {"action": "set_channel", "channel": 6}
  {"action": "hop_random"}
  {"action": "hop_sequence", "channels": [1,6,11,36,149]}

Author: WiFi UDP Integration Specialist (subagent)
"""

import json
import logging
import math
import os
import random
import socket
import struct
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

log = logging.getLogger("wifi_udp_bridge")

# ---------------------------------------------------------------------------
# Paths — workspace-relative
# ---------------------------------------------------------------------------
WORKSPACE = Path(__file__).resolve().parent
MODEL_DIR = WORKSPACE / "models"
MODEL_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Try to import the fingerprint database from wifi_fixes.py
# ---------------------------------------------------------------------------
try:
    from wifi_fixes import (
        WiFiDeviceFingerprint,
        WiFiFingerprintDatabase,
        CalibratedC2Detector,
        AlertCooldownManager,
    )
    WIFI_FIXES_AVAILABLE = True
except ImportError:
    WIFI_FIXES_AVAILABLE = False
    log.warning("wifi_fixes.py not available — UDP bridge will operate in "
                "standalone mode (no fingerprint/C2 calibration)")


# ═══════════════════════════════════════════════════════════════════════════
# 1. EnhancedWiFiUDPListener
# ═══════════════════════════════════════════════════════════════════════════

class EnhancedWiFiUDPListener:
    """
    Replaces the basic WiFiUDPListener.

    Receives WiFi device data via UDP from Kali VM's Alfa adapter in monitor
    mode, parses JSON, and feeds it into:
      - CalibratedC2Detector (via fingerprint database) for C2 analysis
      - An optional raw callback for legacy code (alfa_mimo, high_power_wifi)

    KALI SENDS (port 9999):
      Single device:
        {"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "Hidden", "channel": 6,
         "signal_pct": 85, "freq": 2437}

      Batch (list of devices):
        [{"bssid":"...", ...}, {"bssid":"...", ...}, ...]

      Optional fields: "type" ("AP"|"client"), "manufacturer", "first_seen"

    DATA FLOW:
      Kali Alfa → UDP 9999 → EnhancedWiFiUDPListener
        → CalibratedC2Detector.detect() → self.c2_detections
        → fingerprint_db.observe() → persistent baseline
        → callback(det) → legacy _on_wifi_detection()
    """

    def __init__(
        self,
        port: int = 9999,
        bind_host: str = "0.0.0.0",  # Accept from Kali VM (not just localhost)
        callback: Optional[Callable] = None,
        enable_c2: bool = True,
        fingerprint_db: Optional["WiFiFingerprintDatabase"] = None,
    ):
        self.port = port
        self.bind_host = bind_host
        self.callback = callback  # Legacy callback (e.g., TSCM._on_wifi_detection)
        self.enable_c2 = enable_c2
        self.running = True

        # --- Packet counters ---
        self.packet_count = 0
        self.device_count = 0
        self.last_packet_time = 0.0
        self.last_device_time = 0.0

        # --- Device buffer (recent devices from UDP) ---
        self._recent_devices: List[dict] = []
        self._recent_lock = threading.Lock()
        self._recent_max = 200  # keep last 200 device observations

        # --- C2 integration (from wifi_fixes.py) ---
        self.c2_detections: List[dict] = []
        self._c2_lock = threading.Lock()
        self._c2_stats = {
            "total_devices_fed": 0,
            "total_c2_flagged": 0,
            "last_c2_time": 0.0,
        }

        if self.enable_c2 and WIFI_FIXES_AVAILABLE:
            self.fp_db = fingerprint_db or WiFiFingerprintDatabase()
            self.c2_detector = CalibratedC2Detector(self.fp_db)
            self.cooldown_mgr = AlertCooldownManager(cooldown_sec=60.0)
            self._last_stale_cleanup = 0.0
            self._last_baseline_update = 0.0
            log.info("UDP bridge: C2 calibration + fingerprinting ENABLED")
        elif self.enable_c2 and not WIFI_FIXES_AVAILABLE:
            log.warning("UDP bridge: C2 requested but wifi_fixes.py not available")

        # --- UDP socket ---
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(2.0)
        try:
            self.sock.bind((self.bind_host, self.port))
        except OSError as e:
            log.error(f"UDP bind failed on {self.bind_host}:{self.port}: {e}")
            self.sock = None

        # --- Listener thread ---
        self.thread = threading.Thread(target=self._loop, daemon=True, name="wifi-udp-listen")
        self.thread.start()
        log.info(f"EnhancedWiFiUDPListener on {self.bind_host}:{self.port}")

    def _parse_devices(self, raw_data: bytes) -> List[dict]:
        """
        Parse UDP payload into a list of device dicts.

        Accepts:
          - Single device JSON:  {"bssid": "...", ...}
          - Batch list JSON:     [{"bssid": "...", ...}, ...]

        Normalizes all fields to the format expected by CalibratedC2Detector:
          bssid, ssid, rssi, signal_pct, channel, detector, device_type
        """
        text = raw_data.decode("utf-8", errors="replace").strip()
        if not text:
            return []

        data = json.loads(text)

        # Single device dict
        if isinstance(data, dict):
            data = [data]

        # Must be a list now
        if not isinstance(data, list):
            return []

        devices = []
        for item in data:
            bssid = item.get("bssid", "").strip().upper()
            if not bssid or len(bssid) != 17:
                continue  # skip invalid BSSID

            ssid = item.get("ssid", "")
            if isinstance(ssid, str):
                ssid = ssid.strip()
            else:
                ssid = ""

            signal_pct = int(item.get("signal_pct", 0))
            # Convert signal_pct to approximate RSSI (dBm)
            # signal_pct ranges 0-100, maps roughly to -100 to -30 dBm
            rssi = (signal_pct / 2.0) - 100 if signal_pct > 0 else -100

            channel = int(item.get("channel", 0))
            freq = int(item.get("freq", 0))

            # If no channel but freq, derive channel
            if channel == 0 and freq > 0:
                channel = self._freq_to_channel(freq)

            device_type = item.get("type", "AP" if ssid else "client")
            if isinstance(device_type, str):
                device_type = device_type.upper()
                if device_type not in ("AP", "CLIENT"):
                    device_type = "AP" if ssid else "client"

            devices.append({
                "bssid": bssid,
                "ssid": ssid,
                "rssi": rssi,
                "signal_pct": signal_pct,
                "channel": channel,
                "freq": freq,
                "detector": "wifi_device",
                "device_type": device_type,
                "source": "udp_kali",
                "timestamp": time.time(),
            })

        return devices

    @staticmethod
    def _freq_to_channel(freq_mhz: int) -> int:
        """Convert frequency (MHz) to WiFi channel number."""
        # 2.4 GHz
        if 2412 <= freq_mhz <= 2484:
            return (freq_mhz - 2407) // 5
        # 5 GHz (some common ones)
        if 5170 <= freq_mhz <= 5825:
            return (freq_mhz - 5000) // 5
        return 0

    def _loop(self):
        """Main listener loop — receives UDP, parses, feeds C2 pipeline."""
        if self.sock is None:
            log.error("UDP socket not available — listener exiting")
            return

        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                now = time.time()
                self.packet_count += 1
                self.last_packet_time = now

                # Parse devices from JSON payload
                devices = self._parse_devices(data)
                if not devices:
                    # Log rate-limited for non-device packets
                    if self.packet_count <= 3 or self.packet_count % 500 == 0:
                        log.debug(f"UDP: non-device packet #{self.packet_count} "
                                  f"from {addr} ({len(data)}B)")
                    continue

                self.device_count += len(devices)
                self.last_device_time = now

                # Rate-limited logging
                if self.device_count <= 10 or self.device_count % 100 == 0:
                    log.info(f"UDP: {len(devices)} devices from {addr} "
                             f"(total: {self.device_count})")

                # Store in recent buffer
                with self._recent_lock:
                    self._recent_devices.extend(devices)
                    # Trim to max
                    if len(self._recent_devices) > self._recent_max:
                        self._recent_devices = self._recent_devices[-self._recent_max:]

                # Feed into C2 pipeline
                if self.enable_c2 and WIFI_FIXES_AVAILABLE:
                    self._feed_c2_pipeline(devices, now)

                # Call legacy callback for each device
                if self.callback:
                    for dev in devices:
                        try:
                            self.callback(dev)
                        except Exception as e:
                            log.debug(f"Legacy callback error: {e}")

            except socket.timeout:
                continue
            except json.JSONDecodeError:
                if self.packet_count <= 5 or self.packet_count % 100 == 0:
                    log.debug(f"UDP: malformed JSON packet #{self.packet_count}")
            except OSError:
                # Socket was closed
                break
            except Exception as e:
                log.debug(f"UDP listener error: {e}")

    def _feed_c2_pipeline(self, devices: list, now: float):
        """
        Feed devices into the fingerprint database and C2 detector.

        This replaces the netsh scan → C2 detection flow. Instead of
        scanning locally, we use the Kali VM's monitor-mode data.
        """
        try:
            # Step 1: Update fingerprint database
            for dev in devices:
                self.fp_db.observe(
                    bssid=dev["bssid"],
                    ssid=dev.get("ssid", ""),
                    channel=dev.get("channel", 0),
                    signal_pct=dev.get("signal_pct", 0),
                    now=now,
                )

            # Step 2: Run calibrated C2 detection
            raw_detections = self.c2_detector.detect(devices)

            # Step 3: Apply alert cooldown
            filtered = []
            for det in raw_detections:
                bssid = det["bssid"]
                if self.cooldown_mgr.should_alert(bssid, now):
                    filtered.append(det)
                elif det.get("severity") == "high" and det.get("c2_score", 0) > 0.8:
                    self.cooldown_mgr.force_alert(bssid, now)
                    filtered.append(det)

            # Step 4: Store results
            with self._c2_lock:
                self.c2_detections = filtered

            self._c2_stats["total_devices_fed"] += len(devices)
            self._c2_stats["total_c2_flagged"] = len(filtered)
            if filtered:
                self._c2_stats["last_c2_time"] = now

            # Step 5: Periodic maintenance
            if now - self._last_stale_cleanup > 300:
                self.fp_db.cleanup_stale(now)
                self._last_stale_cleanup = now
            if now - self._last_baseline_update > 60:
                self._last_baseline_update = now

            self.fp_db.maybe_save(now)

            if filtered:
                log.warning(f"C2 UDP: {len(filtered)} devices flagged from "
                            f"{len(devices)} UDP devices")

        except Exception as e:
            log.error(f"C2 pipeline feed error: {e}")

    # ---- Public API (compatible with HardenedNetworkC2Detector) ----------

    def get_recent_devices(self) -> List[dict]:
        """Return recent device observations from UDP feed."""
        with self._recent_lock:
            return list(self._recent_devices)

    def get_c2_detections(self) -> List[dict]:
        """Return latest C2 detections (thread-safe)."""
        with self._c2_lock:
            return list(self.c2_detections)

    def get_detections(self, lat=None, lon=None) -> List[dict]:
        """
        Drop-in compatible with HardenedNetworkC2Detector.get_detections().
        Only sets position if caller has real GPS (non-zero).
        """
        with self._c2_lock:
            results = list(self.c2_detections)
        if lat and lon and lat != 0 and lon != 0:
            for r in results:
                r["lat"] = lat
                r["lon"] = lon
        return results

    # Backward-compat fields for tscm_final.py
    @property
    def results(self) -> List[dict]:
        """Alias for c2_detections (backward compat)."""
        with self._c2_lock:
            return list(self.c2_detections)

    @property
    def _lock(self):
        """Backward-compat lock for tscm_final.py's `with self.network_c2._lock`."""
        return self._c2_lock

    @property
    def device_db(self) -> dict:
        """Backward-compat device database. Returns fingerprint summaries."""
        if WIFI_FIXES_AVAILABLE and hasattr(self, 'fp_db'):
            now = time.time()
            db = {}
            for bssid, fp in self.fp_db.devices.items():
                db[bssid] = {
                    "first_seen": fp.first_seen,
                    "last_seen": fp.last_seen,
                    "count": fp.sighting_count,
                    "ssids": fp.ssid_set,
                    "c2_score": fp.c2_score,
                    "rssi_mean": fp.rssi_mean,
                    "rssi_std": fp.rssi_std,
                }
            return db
        return {}

    def status(self) -> dict:
        """Status summary for diagnostics."""
        return {
            "source": "udp_kali",
            "port": self.port,
            "running": self.running,
            "packet_count": self.packet_count,
            "device_count": self.device_count,
            "last_packet_age_sec": round(time.time() - self.last_packet_time, 1) if self.last_packet_time else None,
            "last_device_age_sec": round(time.time() - self.last_device_time, 1) if self.last_device_time else None,
            "c2_stats": self._c2_stats,
            "c2_detections_count": len(self.c2_detections),
            "fingerprint_count": len(self.fp_db.devices) if WIFI_FIXES_AVAILABLE and hasattr(self, 'fp_db') else 0,
            "wifi_fixes_available": WIFI_FIXES_AVAILABLE,
        }

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════
# 2. UDPChannelHopper
# ═══════════════════════════════════════════════════════════════════════════

class UDPChannelHopper:
    """
    Sends channel hop commands to the Kali VM via UDP on port 9998.

    Kali VM should be listening on UDP 9998 and execute the commands
    using `iw dev <iface> set channel <ch>` in monitor mode.

    COMMANDS (JSON → Kali on UDP 9998):
      {"action": "set_channel", "channel": 6}
      {"action": "hop_random"}
      {"action": "hop_sequence", "channels": [1, 6, 11, 36, 149]}
      {"action": "scan_all"}

    This REPLACES the old WiFiChannelHopper from wifi_fixes.py which only
    logged channel changes (couldn't actually set channels on Windows netsh).
    With the Kali VM, we have real monitor mode control.
    """

    # Common WiFi channels
    CHANNELS_2GHZ = [1, 6, 11]  # Non-overlapping
    CHANNELS_2GHZ_ALL = list(range(1, 14))  # 1-13
    CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                     116, 120, 124, 128, 132, 136, 140, 144, 149, 153,
                     157, 161, 165]

    def __init__(
        self,
        target_host: str = "127.0.0.1",
        port: int = 9998,
        default_interface: str = "wlan0",
    ):
        self.target_host = target_host
        self.port = port
        self.default_interface = default_interface

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2.0)

        self.current_channel = 0
        self.hop_count = 0
        self.send_count = 0
        self.fail_count = 0
        self.hop_history = deque(maxlen=50)
        self._lock = threading.Lock()

        log.info(f"UDPChannelHopper → {self.target_host}:{self.port} "
                 f"(iface: {self.default_interface})")

    def _send_command(self, cmd: dict) -> bool:
        """Send a JSON command to the Kali VM. Returns True on success."""
        try:
            payload = json.dumps(cmd).encode("utf-8")
            self.sock.sendto(payload, (self.target_host, self.port))
            with self._lock:
                self.send_count += 1
            return True
        except socket.timeout:
            with self._lock:
                self.fail_count += 1
            log.warning(f"Channel hop send timeout to {self.target_host}:{self.port}")
            return False
        except OSError as e:
            with self._lock:
                self.fail_count += 1
            log.error(f"Channel hop send error: {e}")
            return False

    def set_channel(self, channel: int) -> bool:
        """
        Set Kali's Alfa adapter to a specific channel.

        Kali should execute: iw dev <iface> set channel <channel>
        """
        cmd = {"action": "set_channel", "channel": channel}
        success = self._send_command(cmd)
        if success:
            with self._lock:
                self.current_channel = channel
                self.hop_count += 1
                self.hop_history.append({
                    "time": time.time(),
                    "channel": channel,
                    "action": "set",
                    "hop": self.hop_count,
                })
            log.info(f"Channel → {channel} (hop #{self.hop_count})")
        return success

    def hop_random(self) -> int:
        """
        Hop to a random channel (80% 2.4GHz non-overlapping, 20% 5GHz).
        Returns the channel number.
        """
        r = random.random()
        if r < 0.6:
            pool = self.CHANNELS_2GHZ
        elif r < 0.8:
            pool = self.CHANNELS_2GHZ_ALL
        else:
            pool = self.CHANNELS_5GHZ

        ch = random.choice(pool)
        self.set_channel(ch)
        return ch

    def hop_sequence(self, channels: List[int]) -> bool:
        """
        Send a channel hop sequence to Kali.
        Kali should cycle through them in order.
        """
        cmd = {"action": "hop_sequence", "channels": channels}
        return self._send_command(cmd)

    def scan_all(self) -> bool:
        """
        Tell Kali to scan all channels (return to channel hopping mode).
        """
        cmd = {"action": "scan_all"}
        return self._send_command(cmd)

    def get_scan_delay(self) -> float:
        """
        Return a random jitter delay (2-8s) for the next scan cycle.
        Compatible with the old WiFiChannelHopper interface.
        """
        return random.uniform(2.0, 8.0)

    @property
    def _scan_jitter(self) -> float:
        """Backward-compat: latest jitter value."""
        return random.uniform(2.0, 8.0)

    def status(self) -> dict:
        """Status summary."""
        with self._lock:
            return {
                "target": f"{self.target_host}:{self.port}",
                "interface": self.default_interface,
                "current_channel": self.current_channel,
                "hop_count": self.hop_count,
                "send_count": self.send_count,
                "fail_count": self.fail_count,
                "recent_hops": list(self.hop_history)[-5:] if self.hop_history else [],
            }

    def stop(self):
        try:
            self.sock.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════
# 3. UDPBridgeNetworkC2 (Unified replacement for HardenedNetworkC2Detector)
# ═══════════════════════════════════════════════════════════════════════════

class UDPBridgeNetworkC2:
    """
    Unified drop-in replacement for HardenedNetworkC2Detector.

    Combines EnhancedWiFiUDPListener + UDPChannelHopper into a single
    object that presents the SAME interface as HardenedNetworkC2Detector
    (used by tscm_final.py as self.network_c2).

    This is the MAIN CLASS that tscm_final.py should instantiate instead
    of HardenedNetworkC2Detector or NetworkC2Detector.

    USAGE (in tscm_final.py):
      from wifi_udp_bridge import UDPBridgeNetworkC2

      self.network_c2 = UDPBridgeNetworkC2(
          udp_port=Config.WIFI_UDP_PORT,
          bind_host="0.0.0.0",       # Accept from Kali VM
          hop_host="127.0.0.1",     # Kali VM (or its IP)
          hop_port=9998,
          callback=self._on_wifi_detection,
      )
      self.network_c2.start()

    INTERFACE COMPATIBILITY (HardenedNetworkC2Detector):
      .results          → list of C2 detections
      .device_db        → dict of device fingerprints
      ._lock            → threading.Lock for thread-safe access
      .get_detections(lat, lon) → filtered detections with GPS
      .start()          → begin listening
      .stop()           → stop listener
      .status()         → diagnostic status dict
      .interface        → string (for logging)
      .running          → bool
    """

    SCAN_INTERVAL_MIN = 10.0
    SCAN_INTERVAL_MAX = 30.0

    def __init__(
        self,
        udp_port: int = 9999,
        bind_host: str = "0.0.0.0",
        hop_host: str = "127.0.0.1",
        hop_port: int = 9998,
        callback: Optional[Callable] = None,
        interface: str = "Alfa (Kali UDP)",
    ):
        self.interface = interface
        self.running = False

        # Core components
        self.udp_listener = EnhancedWiFiUDPListener(
            port=udp_port,
            bind_host=bind_host,
            callback=callback,
            enable_c2=True,
        )
        self.channel_hopper = UDPChannelHopper(
            target_host=hop_host,
            port=hop_port,
        )

        # Background channel hop thread
        self._hop_thread = None
        self._hop_running = False

        # Counters
        self._scan_count = 0

        log.info(f"UDPBridgeNetworkC2 initialized: UDP in={bind_host}:{udp_port}, "
                 f"hop out={hop_host}:{hop_port}")

    def start(self):
        """Start listening and channel hopping."""
        self.running = True
        # UDP listener is already running (started in __init__)
        # Start the channel hop thread
        self._hop_running = True
        self._hop_thread = threading.Thread(
            target=self._hop_loop, daemon=True, name="wifi-hop-loop"
        )
        self._hop_thread.start()
        log.info("UDPBridgeNetworkC2 started (UDP listener + channel hopper)")

    def _hop_loop(self):
        """Periodically send channel hop commands to Kali."""
        while self._hop_running:
            try:
                # Check if we're getting data
                age = time.time() - self.udp_listener.last_device_time
                if age < 30:
                    # Data is flowing — hop to cover more spectrum
                    self.channel_hopper.hop_random()
                    self._scan_count += 1
                else:
                    # No data recently — maybe tell Kali to scan_all
                    if self._scan_count % 3 == 0:
                        self.channel_hopper.scan_all()
                    self._scan_count += 1

                # Jitter delay
                delay = self.channel_hopper.get_scan_delay()
                time.sleep(delay)

            except Exception as e:
                log.error(f"Hop loop error: {e}")
                time.sleep(10)

    # ---- Drop-in compat interface ----

    @property
    def results(self) -> list:
        """C2 detection results (backward compat)."""
        return self.udp_listener.results

    @property
    def _lock(self):
        return self.udp_listener._lock

    @property
    def device_db(self) -> dict:
        return self.udp_listener.device_db

    def get_detections(self, lat=None, lon=None) -> list:
        return self.udp_listener.get_detections(lat, lon)

    def scan_wifi_devices(self) -> list:
        """
        For backward compat: return recent devices from UDP feed.
        Does NOT trigger a netsh scan.
        """
        return self.udp_listener.get_recent_devices()

    def detect_c2_beacons(self, devices=None, lat=None, lon=None) -> list:
        """
        For backward compat: return C2 detections.
        Devices from UDP feed are already analyzed in real-time.
        """
        return self.udp_listener.get_c2_detections()

    def enable_monitor_mode(self) -> bool:
        """
        For backward compat: monitor mode is handled by Kali VM.
        Always returns True (Kali is already in monitor mode).
        """
        return True

    def stop(self):
        self.running = False
        self._hop_running = False
        self.udp_listener.stop()
        self.channel_hopper.stop()

    def status(self) -> dict:
        """Combined status from listener + hopper."""
        listener_status = self.udp_listener.status()
        hopper_status = self.channel_hopper.status()
        return {
            "interface": self.interface,
            "running": self.running,
            "scan_count": self._scan_count,
            "source": "udp_kali",
            "udp_listener": listener_status,
            "channel_hopper": hopper_status,
            "total_devices_seen": listener_status.get("device_count", 0),
            "total_c2_flagged": listener_status.get("c2_stats", {}).get("total_c2_flagged", 0),
            "fingerprint_count": listener_status.get("fingerprint_count", 0),
        }


# ═══════════════════════════════════════════════════════════════════════════
# 4. INTEGRATION INSTRUCTIONS
# ═══════════════════════════════════════════════════════════════════════════

INTEGRATION_INSTRUCTIONS = r'''
===============================================================================
  INTEGRATION: Replacing netsh WiFi scanning with UDP bridge in tscm_final.py
===============================================================================

OVERVIEW:
  The Alfa WiFi adapter is in a Kali VM running in monitor mode. WiFi scan
  data comes via UDP port 9999 from Kali as JSON. We need to:
    1. Replace HardenedNetworkC2Detector (netsh) with UDPBridgeNetworkC2 (UDP)
    2. Feed UDP device data into the C2 fingerprint pipeline
    3. Send channel hop commands back to Kali via UDP port 9998
    4. Keep the same interface so tscm_final.py code works unchanged


=== PATCH 1: tscm_final.py — Replace WiFi listener + network_c2 init ===
  Location: Around lines 3870-3890 in tscm_final.py

  FIND (the old WiFi listener + network_c2 setup):

        # WiFi listener
        self.wifi_listener = WiFiUDPListener(port=Config.WIFI_UDP_PORT,
                                              callback=self._on_wifi_detection)
        # Network C2 detection via Alfa WiFi adapter
        self.network_c2 = None
        try:
            # WiFi HARDENING: Use calibrated C2 detector with fingerprinting + wiggle
            try:
                from wifi_fixes import HardenedNetworkC2Detector
                self.network_c2 = HardenedNetworkC2Detector(interface="Wi-Fi 2")
                self.network_c2.start()
                self.log.info("Network C2 detector started on Wi-Fi 2 (HARDENED - calibrated, wiggle active)")
            except ImportError:
                from network_c2 import NetworkC2Detector
                self.network_c2 = NetworkC2Detector(interface="Wi-Fi 2")
                self.network_c2.start()
                self.log.info("Network C2 detector started on Wi-Fi 2 (Alfa)")
        except Exception as e:
            self.log.debug(f"Network C2 detector not available: {e}")

  REPLACE WITH:

        # WiFi listener + C2 detection via UDP from Kali VM (Alfa monitor mode)
        self.wifi_listener = None  # No longer needed — UDPBridgeNetworkC2 handles it
        self.network_c2 = None
        try:
            from wifi_udp_bridge import UDPBridgeNetworkC2
            self.network_c2 = UDPBridgeNetworkC2(
                udp_port=Config.WIFI_UDP_PORT,
                bind_host="0.0.0.0",       # Accept from Kali VM (not just localhost)
                hop_host="127.0.0.1",      # Kali VM IP (change if different)
                hop_port=9998,             # Kali listens for hop commands here
                callback=self._on_wifi_detection,
                interface="Alfa (Kali UDP)",
            )
            self.network_c2.start()
            self.log.info("Network C2 detector: UDP bridge to Kali VM "
                          f"(port {Config.WIFI_UDP_PORT} in, 9998 out)")
        except Exception as e:
            self.log.warning(f"UDP bridge not available, falling back: {e}")
            # Fallback: try the old netsh approach
            try:
                from wifi_fixes import HardenedNetworkC2Detector
                self.network_c2 = HardenedNetworkC2Detector(interface="Wi-Fi 2")
                self.network_c2.start()
                self.log.warning("Fallback: HardenedNetworkC2Detector on Wi-Fi 2 (netsh)")
            except Exception as e2:
                self.log.debug(f"Network C2 detector not available: {e2}")


=== PATCH 2: tscm_final.py — Remove old WiFiUDPListener import ===
  Location: Near the top of tscm_final.py where imports are done.

  The old WiFiUDPListener class (line ~2839) can remain in the file
  for backward compat, but it won't be used. No import change needed since
  WiFiUDPListener was defined inline in tscm_final.py.


=== PATCH 3: tscm_final.py — _on_wifi_detection needs minor tweak ===
  Location: Around line 4801

  The existing _on_wifi_detection callback should work AS-IS with the
  UDP bridge. The UDPBridgeNetworkC2 passes device dicts to the callback
  in the same format. No change needed here.


=== PATCH 4: tscm_final.py — alfa_devices count in summary ===
  Location: Lines ~4485 and ~4791

  These lines already work because UDPBridgeNetworkC2 has backward-compat
  .device_db property. No change needed.


=== PATCH 5: Config — bind_host change ===
  Location: Line ~256 in tscm_final.py

  FIND:
    WIFI_UDP_BIND_HOST = "127.0.0.1"                 # Bind WiFi UDP to localhost only

  REPLACE WITH (if Kali VM is on a different host):
    WIFI_UDP_BIND_HOST = "0.0.0.0"                   # Accept from Kali VM

  If Kali VM is localhost (e.g., WSL2 or bridged), 0.0.0.0 is safer.


=== PATCH 6: Add Config entries for hop target ===
  Location: In the Config class, near WIFI_UDP_PORT

  ADD:
    WIFI_UDP_HOP_HOST = "127.0.0.1"   # Kali VM target for channel hop commands
    WIFI_UDP_HOP_PORT = 9998           # Kali VM listens for hop commands here


=== KALI VM SETUP ===

  On the Kali VM, the Alfa adapter should:
  1. Run in monitor mode:  airmon-ng start wlan0
  2. Scan and send results via UDP:
     A simple Python script on Kali:
     
     import socket, json, subprocess
     
     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
     
     # Channel hop listener (receives commands from Windows)
     hop_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
     hop_sock.bind(("0.0.0.0", 9998))
     hop_sock.settimeout(5.0)
     
     while True:
         # Check for hop commands
         try:
             cmd_data, addr = hop_sock.recvfrom(4096)
             cmd = json.loads(cmd_data.decode())
             if cmd["action"] == "set_channel":
                 subprocess.run(["iw", "dev", "wlan0mon", "set", "channel",
                                str(cmd["channel"])])
             elif cmd["action"] == "hop_random":
                 import random
                 ch = random.choice([1,6,11,36,40,44,48,149,153,157,161,165])
                 subprocess.run(["iw", "dev", "wlan0mon", "set", "channel", str(ch)])
             elif cmd["action"] == "scan_all":
                 pass  # Kali's own hop script handles this
         except socket.timeout:
             pass
         
         # Scan and send
         result = subprocess.run(
             ["airodump-ng", "-w", "/dev/null", "--output-format", "csv",
              "-r", "1", "--write-interval", "1", "wlan0mon"],
             capture_output=True, text=True, timeout=5
         )
         # Parse and send each detected device...
         # Or use airodump-ng's JSON output:
         #   airodump-ng --output-format json -w /tmp/scan wlan0mon
     
     # Alternatively, use scapy:
     from scapy.all import *
     iface = "wlan0mon"
     
     def send_device(pkt):
         if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
             bssid = pkt.addr2
             ssid = pkt[Dot11Elt].info.decode() if pkt.haslayer(Dot11Elt) else ""
             rssi = int(pkt.dBm_AntSignal) if hasattr(pkt, 'dBm_AntSignal') else -80
             signal_pct = max(0, min(100, int((rssi + 100) * 2)))
             ch = int(ord(pkt[Dot11Elt:3].info)) if pkt.haslayer(Dot11Elt) else 0
             freq = 2412 + (ch - 1) * 5 if 1 <= ch <= 14 else 0
             
             device = {
                 "bssid": bssid.upper(),
                 "ssid": ssid,
                 "channel": ch,
                 "signal_pct": signal_pct,
                 "freq": freq,
             }
             sock.sendto(json.dumps(device).encode(), ("WINDOWS_IP", 9999))
     
     sniff(iface=iface, prn=send_device, store=0)


=== VERIFICATION ===

  After applying patches, verify with:

  1. Start Kali VM with Alfa in monitor mode
  2. Start the Kali scanner (scapy script above)
  3. Start tscm_final.py on Windows
  4. Check logs for:
     - "UDP bridge to Kali VM (port 9999 in, 9998 out)"
     - "UDP: N devices from ('192.168.x.x', 12345)"
  5. Open live map and check alfa_devices count > 0
  6. Watch for C2 flags if suspicious devices are detected

===============================================================================
'''


# ═══════════════════════════════════════════════════════════════════════════
# 5. SELF-TEST / DEMO
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if "--test" in sys.argv:
        print("=== Testing EnhancedWiFiUDPListener ===")

        def test_callback(dev):
            print(f"  CALLBACK: {dev['bssid']} SSID={dev.get('ssid','')!r} "
                  f"ch={dev.get('channel',0)} sig={dev.get('signal_pct',0)}%")

        listener = EnhancedWiFiUDPListener(
            port=9999,
            bind_host="0.0.0.0",
            callback=test_callback,
        )

        print("Listening on UDP 9999... Send test data:")
        print("  echo '{\"bssid\":\"AA:BB:CC:DD:EE:FF\",\"ssid\":\"TestNet\",\"channel\":6,\"signal_pct\":85,\"freq\":2437}' | nc -u 127.0.0.1 9999")
        print("  Press Ctrl+C to stop\n")

        try:
            while True:
                time.sleep(5)
                status = listener.status()
                print(f"  [{time.strftime('%H:%M:%S')}] "
                      f"pkts={status['packet_count']} "
                      f"devs={status['device_count']} "
                      f"c2={status['c2_detections_count']} "
                      f"fps={status['fingerprint_count']}")
        except KeyboardInterrupt:
            pass

        listener.stop()

    elif "--hop-test" in sys.argv:
        print("=== Testing UDPChannelHopper ===")

        target = sys.argv[sys.argv.index("--hop-test") + 1] if (
            sys.argv.index("--hop-test") + 1 < len(sys.argv)
        ) else "127.0.0.1"

        hopper = UDPChannelHopper(target_host=target)

        print(f"Sending test hops to {target}:9998")
        print("  (Kali must be listening on UDP 9998)\n")

        # Test commands
        hopper.set_channel(6)
        time.sleep(0.5)
        hopper.hop_random()
        time.sleep(0.5)
        hopper.hop_sequence([1, 6, 11, 36, 149])
        time.sleep(0.5)
        hopper.scan_all()

        print(f"\nStatus: {hopper.status()}")
        hopper.stop()

    elif "--integration" in sys.argv:
        print("=== Full Integration Test (UDPBridgeNetworkC2) ===")

        def test_callback(dev):
            print(f"  DET: {dev['bssid']} SSID={dev.get('ssid','')!r} "
                  f"ch={dev.get('channel',0)} sig={dev.get('signal_pct',0)}%")

        bridge = UDPBridgeNetworkC2(
            udp_port=9999,
            bind_host="0.0.0.0",
            hop_host="127.0.0.1",
            hop_port=9998,
            callback=test_callback,
        )
        bridge.start()

        print("Full bridge running. Send WiFi data to UDP 9999.")
        print("Channel hop commands going to UDP 9998.\n")

        try:
            while True:
                time.sleep(10)
                status = bridge.status()
                print(f"  [{time.strftime('%H:%M:%S')}] "
                      f"scans={status['scan_count']} "
                      f"devs={status['total_devices_seen']} "
                      f"c2={status['total_c2_flagged']} "
                      f"fps={status['fingerprint_count']} "
                      f"ch={status['channel_hopper']['current_channel']}")
        except KeyboardInterrupt:
            pass

        bridge.stop()

    else:
        print("wifi_udp_bridge.py — UDP WiFi Bridge for TSCM System")
        print("\nCommands:")
        print("  python wifi_udp_bridge.py --test         # Test UDP listener only")
        print("  python wifi_udp_bridge.py --hop-test [IP]  # Test channel hopper")
        print("  python wifi_udp_bridge.py --integration  # Full bridge test")
        print("\nIntegration instructions:")
        print(INTEGRATION_INSTRUCTIONS)
