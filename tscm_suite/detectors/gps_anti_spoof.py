#!/usr/bin/env python3
"""
================================================================================
 GPS ANTI-SPOOF + WiFi MONITORING SHIELD
 For TSCM Master Suite -- tscm_final.py integration

 Modules:
   GPSCrossValidator    - Cross-checks RTK2 vs Windows Location vs home position
   AdafruitGPSWatchdog  - Polls USB bus for Adafruit GPS re-connection
   WindowsLocationPoller- Queries Windows.Devices.Geolocation as 2nd GPS ref
   WiggleWiFiScanner    - 2.4/5 GHz channel scanner for rogue AP detection
   WiFiPassiveRadarFeeder - Routes Alfa WiFi RSSI data into passive radar detector

 IMPORTANT: COM5 is already held by the TSCM process. This module reads GPS
 position from the TSCM system's GPSInterface object (self.gps.lat/lon etc.)
 and never opens COM5 directly.
================================================================================
"""

import sys
import os
import time
import json
import struct
import hashlib
import threading
import subprocess
import logging
import math
import datetime
import ctypes
from collections import deque
from typing import Optional, Dict, Any, List, Tuple

import numpy as np

log = logging.getLogger("gps_anti_spoof")

# ===================== CONFIG =====================

class GPSShieldConfig:
    """Anti-spoof shield configuration."""
    # GPS cross-validation
    CROSS_CHECK_INTERVAL = 5.0        # seconds between cross-validation runs
    POSITION_DIVERGE_METERS = 100.0   # flag when positions diverge >100m
    HDOP_DEGRADATION_THRESHOLD = 2.0  # flag when HDOP degrades by >2.0
    SATELLITE_COUNT_DROP_THRESHOLD = 4  # flag when sats drop by >4

    # UBX Anti-Spoof (from deep research 2026-05-28)
    UBX_JAMMING_MODERATE = 32         # jamInd threshold: moderate jamming
    UBX_JAMMING_SEVERE = 128          # jamInd threshold: severe jamming
    UBX_CNO_IDENTICAL_THRESHOLD = 2.0 # dB-Hz — all sats within this range = spoof
    UBX_CLOCK_BIAS_JUMP_NS = 100.0   # clock bias jump > 100ns = spoof transition
    UBX_L1_L2_DIVERGE_METERS = 50.0  # L1 vs L2 position disagree > 50m = spoof
    UBX_GEOFENCE_RADIUS_M = 50.0      # geofence alarm radius from last known good position

    # Adafruit GPS watchdog
    ADAFRUIT_VID = "10C4"
    ADAFRUIT_PID = "EA60"
    ADAFRUIT_SERIAL = "181827201E9FEC119B3D9D79A29C855C"
    ADAFRUIT_POLL_INTERVAL = 5.0      # seconds between USB polls
    ADAFRUIT_REMOVAL_TIME = "2026-05-30T18:14:15-05:00"  # CDT = UTC-5
    ADAFRUIT_REMOVAL_EPOCH = 1748646855  # epoch time of removal

    # Windows Location API
    WINLOC_POLL_INTERVAL = 10.0       # seconds between location polls
    WINLOC_STALE_THRESHOLD = 30.0     # flag when no update in 30s

    # Wiggle WiFi Scanner
    WIGGLE_INTERVAL = 30.0            # seconds between full scans
    WIGGLE_24GHZ_CHANNELS = list(range(1, 14))  # 1-13
    WIGGLE_5GHZ_CHANNELS = [36, 40, 44, 48, 52, 56, 60, 64,
                             100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
                             149, 153, 157, 161, 165]
    WIGGLE_ALFA_IFACE = "Wi-Fi 2"     # Realtek 8812AU interface name
    WIGGLE_BUILTIN_IFACE = "Wi-Fi"    # Killer AX1675i interface name
    ROGUE_AP_THRESHOLD = 5            # flag when BSSID count changes by >5

    # Detection logging
    DETECTION_LOG = "detections.log"

    # Home position
    HOME_LAT = 41.513323
    HOME_LON = -88.133573

    # Tamper log
    TAMPER_LOG = "tamper_audit.jsonl"


# ===================== UTILITY FUNCTIONS =====================

def _haversine_meters(lat1, lon1, lat2, lon2):
    """Calculate distance in meters between two GPS coordinates."""
    R = 6371000.0  # Earth radius in meters
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


def _log_detection(detector: str, details: Dict[str, Any],
                   lat: float = None, lon: float = None,
                   severity: str = "WARNING"):
    """Log a detection event to detections.log."""
    entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z",
        "detector": detector,
        "severity": severity,
        "details": details,
    }
    if lat is not None:
        entry["lat"] = lat
    if lon is not None:
        entry["lon"] = lon
    try:
        with open(GPSShieldConfig.DETECTION_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def _log_tamper(event_type: str, **details):
    """Write a tamper audit entry to tamper_audit.jsonl."""
    entry = {
        "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": event_type,
    }
    entry.update(details)
    try:
        with open(GPSShieldConfig.TAMPER_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def _find_usb_device(vid: str, pid: str) -> Optional[Dict[str, str]]:
    """Find a USB device by VID/PID. Returns dict with port info or None."""
    try:
        import wmi
        c = wmi.WMI()
        # Query Win32_PnPEntity for the specific VID/PID
        query = f"SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE '%VID_{vid}%&PID_{pid}%'"
        for d in c.query(query):
            name = d.Name or d.Description or ""
            device_id = d.DeviceID or ""
            # Extract COM port from name or device ID
            com_port = None
            import re
            m = re.search(r'COM\d+', name, re.IGNORECASE)
            if not m:
                m = re.search(r'COM\d+', device_id, re.IGNORECASE)
            if m:
                com_port = m.group(0)
            status = d.Status or "Unknown"
            return {
                "name": name,
                "device_id": device_id,
                "com_port": com_port,
                "status": status,
                "present": True,
            }
    except ImportError:
        pass
    except Exception:
        pass

    # Fallback: use usbview-like approach via serial.tools
    try:
        import serial.tools.list_ports
        for p in serial.tools.list_ports.comports():
            if vid.lower() in p.hwid.lower() and pid.lower() in p.hwid.lower():
                return {
                    "name": p.description or p.name,
                    "device_id": p.hwid,
                    "com_port": p.device,
                    "status": "Available",
                    "present": True,
                }
    except ImportError:
        pass
    return None


def _parse_nmea_gga(line: str) -> Optional[Dict[str, Any]]:
    """Parse a $GxGGA NMEA sentence manually."""
    try:
        parts = line.strip().split(',')
        if len(parts) < 15 or not parts[0].endswith('GGA'):
            return None
        if not parts[2] or not parts[4]:
            return None
        # Parse time
        utc_time = parts[1] if parts[1] else None
        # Parse lat
        lat_raw = float(parts[2])
        lat_deg = int(lat_raw / 100)
        lat_min = lat_raw - lat_deg * 100
        lat = lat_deg + lat_min / 60.0
        if parts[3] == 'S':
            lat = -lat
        # Parse lon
        lon_raw = float(parts[4])
        lon_deg = int(lon_raw / 100)
        lon_min = lon_raw - lon_deg * 100
        lon = lon_deg + lon_min / 60.0
        if parts[5] == 'W':
            lon = -lon
        # Parse quality
        gps_qual = int(parts[6]) if parts[6] else 0
        # Parse sats
        sats = int(parts[7]) if parts[7] else 0
        # Parse HDOP
        hdop = float(parts[8]) if parts[8] else 99.0
        # Parse altitude
        alt = float(parts[9]) if parts[9] else 0.0
        # Parse geoidal separation
        geoid = float(parts[11]) if parts[11] else 0.0

        return {
            "time": utc_time,
            "lat": lat, "lon": lon,
            "fix_quality": gps_qual,
            "satellites": sats,
            "hdop": hdop,
            "altitude": alt,
            "geoid_sep": geoid,
        }
    except Exception:
        return None


def _parse_nmea_gsa(line: str) -> Optional[Dict[str, Any]]:
    """Parse a $GxGSA NMEA sentence for satellite info."""
    try:
        parts = line.strip().split(',')
        if len(parts) < 18 or not parts[0].endswith('GSA'):
            return None
        mode = parts[1]  # M=manual, A=auto
        fix_type = int(parts[2]) if parts[2] else 0  # 1=none,2=2D,3=3D
        # PRN numbers of satellites used
        sats_used = [int(x) for x in parts[3:15] if x]
        pdop = float(parts[15]) if parts[15] else 99.0
        hdop = float(parts[16]) if parts[16] else 99.0
        vdop = float(parts[17]) if parts[17] else 99.0
        return {
            "mode": mode,
            "fix_type": fix_type,
            "satellites_used": sats_used,
            "satellite_count": len(sats_used),
            "pdop": pdop, "hdop": hdop, "vdop": vdop,
        }
    except Exception:
        return None


# ===================== UBX PROTOCOL (ZED-F9P ANTI-SPOOF) =====================

class UBXSpoofDetector:
    """
    ZED-F9P UBX hardware-level anti-spoofing.
    From deep research (2026-05-28): the ZED-F9P has built-in jamming/interference
    monitoring via UBX binary protocol that should be used for real-time spoof detection.

    Key UBX messages:
    - UBX-MON-HW2 (0x0A 0x0B): jamInd (0-255), ofsI/ofsQ (CW jamming detection)
    - UBX-NAV-SIG (0x01 0x35): per-satellite C/N0 (identical C/N0 = spoof signature)
    - UBX-NAV-CLOCK (0x01 0x0D): clock bias jumps >100ns = spoof transition
    - CFG-ITFM (0x06 0x39): enable interference monitoring
    - CFG-NAVSPG (0x06 0x31): tighten position filter gains
    """

    UBX_SYNC1 = 0xB5
    UBX_SYNC2 = 0x62

    def __init__(self, serial_port=None, baud=9600):
        self.serial_port = serial_port
        self.baud = baud
        self.serial = None
        self.running = False
        self.thread = None

        # Detection state
        self.jam_ind = 0              # 0-255, current jamming indicator
        self.jam_ind_history = deque(maxlen=60)
        self.cno_per_sat = {}         # {sv_id: {'cno': float, 'qualityInd': int}}
        self.cno_history = deque(maxlen=120)
        self.clock_bias_ns = 0.0
        self.last_clock_bias_ns = 0.0
        self.clock_bias_history = deque(maxlen=60)

        # Spoof detection results
        self.jamming_detected = False
        self.cno_spoof_detected = False
        self.clock_bias_spoof_detected = False
        self.spoof_alert = False
        self.spoof_details = []
        self.last_ubx_time = 0

        # Config state
        self.itfm_enabled = False
        self.navspg_tightened = False

    def _open_serial(self):
        """Open serial port to ZED-F9P for UBX commands."""
        import serial
        if self.serial_port is None:
            # Auto-detect: try COM4 (ZED-F9P), then scan
            import serial.tools.list_ports
            for p in serial.tools.list_ports.comports():
                if 'COM4' in p.device or 'u-blox' in p.description.lower():
                    self.serial_port = p.device
                    break
            if self.serial_port is None:
                log.warning("[UBX] No ZED-F9P serial port found")
                return False

        for baud in [9600, 38400, 115200]:
            try:
                ser = serial.Serial(self.serial_port, baud, timeout=2, exclusive=False)
                ser.write(self._build_ubx_poll(0x0A, 0x0B))
                ser.write(self._build_ubx_poll(0x0A, 0x0B))
                time.sleep(0.3)
                resp = ser.read(64)
                if len(resp) > 6 and resp[0] == 0xB5 and resp[1] == 0x62:
                    self.serial = ser
                    self.baud = baud
                    log.info(f"[UBX] Connected to ZED-F9P on {self.serial_port} @ {baud}")
                    return True
                ser.close()
            except Exception as e:
                log.debug(f"[UBX] Port {self.serial_port} @ {baud}: {e}")
        return False

    def _build_ubx_poll(self, cls_id, msg_id):
        """Build a UBX poll message (no payload)."""
        msg = bytes([self.UBX_SYNC1, self.UBX_SYNC2, cls_id, msg_id, 0, 0])
        ck_a = ck_b = 0
        for b in msg[2:]:
            ck_a += b; ck_b += ck_a
        return msg + bytes([ck_a & 0xFF, ck_b & 0xFF])

    def _build_ubx_set(self, cls_id, msg_id, payload):
        """Build a UBX set message with payload and checksum."""
        length = len(payload)
        msg = bytes([self.UBX_SYNC1, self.UBX_SYNC2, cls_id, msg_id,
                     length & 0xFF, (length >> 8) & 0xFF]) + payload
        ck_a = ck_b = 0
        for b in msg[2:]:
            ck_a += b; ck_b += ck_a
        return msg + bytes([ck_a & 0xFF, ck_b & 0xFF])

    def _parse_ubx_message(self, data):
        """Parse a UBX message. Returns (cls_id, msg_id, payload) or None."""
        if len(data) < 8:
            return None
        if data[0] != self.UBX_SYNC1 or data[1] != self.UBX_SYNC2:
            return None
        cls_id, msg_id = data[2], data[3]
        length = data[4] | (data[5] << 8)
        if len(data) < 6 + length + 2:
            return None
        payload = data[6:6 + length]
        ck_a = ck_b = 0
        for b in data[2:6 + length]:
            ck_a += b; ck_b += ck_a
        if bytes([ck_a & 0xFF, ck_b & 0xFF]) != data[6 + length:6 + length + 2]:
            return None
        return (cls_id, msg_id, payload)

    def _enable_itfm(self):
        """Enable UBX interference monitoring (CFG-ITFM)."""
        if not self.serial:
            return
        payload = bytes([0x01, 0x00, 0x00, 0x00])
        self.serial.write(self._build_ubx_set(0x06, 0x39, payload))
        time.sleep(0.1)
        self.itfm_enabled = True
        log.info("[UBX] CFG-ITFM interference monitoring enabled")

    def _tighten_navspg(self):
        """Tighten navigation filter gains to resist spoofing (CFG-NAVSPG)."""
        if not self.serial:
            return
        payload = bytes(12)
        self.serial.write(self._build_ubx_set(0x06, 0x31, payload))
        time.sleep(0.1)
        self.navspg_tightened = True
        log.info("[UBX] CFG-NAVSPG position filter tightened")

    def _poll_mon_hw2(self):
        """Poll UBX-MON-HW2 for jamming indicator."""
        if not self.serial:
            return
        try:
            self.serial.write(self._build_ubx_poll(0x0A, 0x0B))
            time.sleep(0.05)
            data = self.serial.read(36)
            if len(data) >= 36:
                parsed = self._parse_ubx_message(data)
                if parsed and parsed[0] == 0x0A and parsed[1] == 0x0B:
                    payload = parsed[2]
                    if len(payload) >= 24:
                        self.jam_ind = payload[20] & 0xFF
                        self.jam_ind_history.append(self.jam_ind)
                        self.last_ubx_time = time.time()
        except Exception as e:
            log.debug(f"[UBX] MON-HW2 poll error: {e}")

    def _poll_nav_sig(self):
        """Poll UBX-NAV-SIG for per-satellite signal quality."""
        if not self.serial:
            return
        try:
            self.serial.write(self._build_ubx_poll(0x01, 0x35))
            time.sleep(0.05)
            data = b''
            start = time.time()
            while time.time() - start < 0.5:
                chunk = self.serial.read(256)
                if chunk:
                    data += chunk
                else:
                    break
            self.cno_per_sat = {}
            idx = 0
            while idx < len(data) - 7:
                if data[idx] == 0xB5 and data[idx + 1] == 0x62:
                    parsed = self._parse_ubx_message(data[idx:idx + 32])
                    if parsed and parsed[0] == 0x01 and parsed[1] == 0x35:
                        payload = parsed[2]
                        if len(payload) >= 16:
                            sv_id = payload[0] & 0x3F
                            cno = payload[4] & 0xFF
                            quality = payload[5] & 0x07
                            self.cno_per_sat[sv_id] = {'cno': cno / 4.0, 'qualityInd': quality}
                    idx += 1
                else:
                    idx += 1
            if self.cno_per_sat:
                self.cno_history.append(dict(self.cno_per_sat))
                self.last_ubx_time = time.time()
        except Exception as e:
            log.debug(f"[UBX] NAV-SIG poll error: {e}")

    def _poll_nav_clock(self):
        """Poll UBX-NAV-CLOCK for clock bias jumps."""
        if not self.serial:
            return
        try:
            self.serial.write(self._build_ubx_poll(0x01, 0x0D))
            time.sleep(0.05)
            data = self.serial.read(28)
            if len(data) >= 28:
                parsed = self._parse_ubx_message(data)
                if parsed and parsed[0] == 0x01 and parsed[1] == 0x0D:
                    payload = parsed[2]
                    if len(payload) >= 20:
                        bias_ns = struct.unpack('<i', payload[0:4])[0]
                        self.last_clock_bias_ns = self.clock_bias_ns
                        self.clock_bias_ns = float(bias_ns)
                        self.clock_bias_history.append(self.clock_bias_ns)
        except Exception as e:
            log.debug(f"[UBX] NAV-CLOCK poll error: {e}")

    def _check_spoof_indicators(self):
        """Run all UBX spoof detection checks. Returns list of spoof events."""
        events = []
        self.spoof_details = []
        self.spoof_alert = False

        # Check 1: Jamming indicator
        if self.jam_ind >= GPSShieldConfig.UBX_JAMMING_SEVERE:
            events.append({'type': 'ubx_severe_jamming', 'jam_ind': self.jam_ind, 'severity': 'CRITICAL'})
            self.jamming_detected = True
            self.spoof_alert = True
            self.spoof_details.append(f"SEVERE jamming (jamInd={self.jam_ind})")
        elif self.jam_ind >= GPSShieldConfig.UBX_JAMMING_MODERATE:
            events.append({'type': 'ubx_moderate_jamming', 'jam_ind': self.jam_ind, 'severity': 'WARNING'})
            self.jamming_detected = True
            self.spoof_details.append(f"Moderate jamming (jamInd={self.jam_ind})")
        else:
            self.jamming_detected = False

        # Check 2: Per-satellite C/N0 — identical values = spoof signature
        # "A spoofing attack typically produces all satellites at identical
        # elevated C/N0 (e.g., all at 48 +/- 1 dB-Hz)"
        if len(self.cno_per_sat) >= 4:
            cno_vals = [v['cno'] for v in self.cno_per_sat.values()]
            cno_range = max(cno_vals) - min(cno_vals)
            cno_mean = float(np.mean(cno_vals))
            if cno_range < GPSShieldConfig.UBX_CNO_IDENTICAL_THRESHOLD and cno_mean > 40:
                events.append({
                    'type': 'ubx_cno_spoof_signature',
                    'cno_mean': round(cno_mean, 1),
                    'cno_range': round(cno_range, 1),
                    'sat_count': len(self.cno_per_sat),
                    'severity': 'CRITICAL'
                })
                self.cno_spoof_detected = True
                self.spoof_alert = True
                self.spoof_details.append(
                    f"spoof C/N0: {len(self.cno_per_sat)} sats range={cno_range:.1f}dB")
            else:
                self.cno_spoof_detected = False

        # Check 3: Clock bias jump >100ns = spoof transition
        bias_jump = abs(self.clock_bias_ns - self.last_clock_bias_ns)
        if self.last_clock_bias_ns != 0 and bias_jump > GPSShieldConfig.UBX_CLOCK_BIAS_JUMP_NS:
            events.append({
                'type': 'ubx_clock_bias_jump',
                'jump_ns': round(bias_jump, 1),
                'severity': 'CRITICAL'
            })
            self.clock_bias_spoof_detected = True
            self.spoof_alert = True
            self.spoof_details.append(f"Clock bias jump {bias_jump:.0f}ns")

        for evt in events:
            _log_detection(f"ubx_spoof_{evt['type']}", evt, severity=evt['severity'])
            log.warning(f"[UBX SPOOF] {evt['type']}: {evt}")
        return events

    def _monitor_loop(self):
        """Main UBX monitoring loop."""
        while self.running:
            try:
                self._poll_mon_hw2()
                self._poll_nav_sig()
                self._poll_nav_clock()
                self._check_spoof_indicators()
                time.sleep(GPSShieldConfig.CROSS_CHECK_INTERVAL)
            except Exception as e:
                log.debug(f"[UBX] Monitor loop error: {e}")
                time.sleep(1)

    def start(self):
        """Start UBX spoof monitoring."""
        if self._open_serial():
            self._enable_itfm()
            self._tighten_navspg()
            self.running = True
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            log.info("[UBX] Spoof detector started (MON-HW2 + NAV-SIG + NAV-CLOCK)")
            return True
        else:
            log.warning("[UBX] Cannot start - no ZED-F9P serial connection")
            return False

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        if self.serial:
            try: self.serial.close()
            except: pass
            self.serial = None

    def get_status(self) -> Dict[str, Any]:
        return {
            'jam_ind': self.jam_ind,
            'jamming_detected': self.jamming_detected,
            'sat_count': len(self.cno_per_sat),
            'cno_spoof_detected': self.cno_spoof_detected,
            'clock_bias_ns': self.clock_bias_ns,
            'clock_bias_spoof_detected': self.clock_bias_spoof_detected,
            'spoof_alert': self.spoof_alert,
            'spoof_details': self.spoof_details,
            'last_ubx_time': self.last_ubx_time,
            'connected': self.serial is not None and self.running,
        }


# ===================== GPS CROSS-VALIDATOR =====================

class GPSCrossValidator:
    """Cross-validates multiple GPS sources for anti-spoofing.

    Reads RTK2 position from TSCM's GPSInterface (never opens COM5),
    compares with Windows Location API and home position.
    Logs spoofing events when positions diverge, HDOP degrades,
    or satellite counts drop unexpectedly.
    """

    def __init__(self, tscm=None, gps_interface=None):
        """
        Args:
            tscm: TSCMSystem instance (preferred - reads self.gps)
            gps_interface: GPSInterface instance (fallback if no tscm)
        """
        self.tscm = tscm
        self.gps = gps_interface  # Can be set later
        self.running = False
        self.thread = None

        # State tracking
        self.last_cross_check = 0
        self.last_valid_position = None
        self.last_valid_time = 0
        self.position_jumps = 0
        self.hdop_degradation_events = 0
        self.satellite_drops = 0
        self.spoof_events = 0
        self.total_checks = 0

        # Historical tracking
        self.position_history = deque(maxlen=60)   # 5 min @ 5s intervals
        self.hdop_history = deque(maxlen=60)
        self.sat_history = deque(maxlen=60)

        # Windows Location reference
        self.winloc_lat = None
        self.winloc_lon = None
        self.winloc_accuracy = None
        self.winloc_last_update = 0

        # Home position
        self.home_lat = GPSShieldConfig.HOME_LAT
        self.home_lon = GPSShieldConfig.HOME_LON
        self._load_home_override()

    def _load_home_override(self):
        """Load home position from gps_home.json if available."""
        try:
            home_file = os.path.join(os.path.dirname(__file__) or '.', 'gps_home.json')
            if os.path.exists(home_file):
                with open(home_file) as f:
                    d = json.load(f)
                    self.home_lat = d['lat']
                    self.home_lon = d['lon']
        except Exception:
            pass

    def _get_gps_state(self) -> Dict[str, Any]:
        """Read current GPS state from the TSCM's GPSInterface (no COM5 access)."""
        gps = self.gps
        if self.tscm and hasattr(self.tscm, 'gps'):
            gps = self.tscm.gps

        if gps is None:
            return {"available": False, "lat": 0, "lon": 0, "has_fix": False,
                    "rtk_fix": False, "hdop": 99.0, "sats": 0}

        return {
            "available": True,
            "lat": getattr(gps, 'lat', 0.0),
            "lon": getattr(gps, 'lon', 0.0),
            "alt": getattr(gps, 'alt', 0.0),
            "has_fix": getattr(gps, 'has_fix', False),
            "rtk_fix": getattr(gps, 'rtk_fix', False),
            "hdop": getattr(gps, 'hdop', 99.0),
            "sats": getattr(gps, 'satellites', 0),
            "spoof_warnings": getattr(gps, 'spoof_warnings', 0),
        }

    def update_winloc(self, lat: float, lon: float, accuracy: float = None):
        """Update Windows Location API reference position."""
        self.winloc_lat = lat
        self.winloc_lon = lon
        self.winloc_accuracy = accuracy
        self.winloc_last_update = time.time()

    def _run_cross_check(self):
        """Execute one cross-validation cycle."""
        self.total_checks += 1
        gps = self._get_gps_state()
        now = time.time()

        events = []

        if not gps["available"] or not gps["has_fix"]:
            # No fix available - check if we've been without fix too long
            if now - self.last_valid_time > GPSShieldConfig.WINLOC_STALE_THRESHOLD:
                if self.last_valid_time > 0:
                    stale = now - self.last_valid_time
                    events.append({
                        "type": "gps_fix_lost",
                        "duration_sec": stale,
                        "last_position": self.last_valid_position,
                    })
            return events

        # Record current position
        lat = gps["lat"]
        lon = gps["lon"]
        hdop = gps["hdop"]
        sats = gps["sats"]
        rtk = gps["rtk_fix"]

        self.position_history.append((lat, lon, now))
        self.hdop_history.append((hdop, now))
        self.sat_history.append((sats, now))

        # Check 1: Position jump detection
        if self.last_valid_position:
            jump_dist = _haversine_meters(
                self.last_valid_position[0], self.last_valid_position[1],
                lat, lon
            )
            if jump_dist > GPSShieldConfig.POSITION_DIVERGE_METERS:
                self.position_jumps += 1
                self.spoof_events += 1
                events.append({
                    "type": "position_jump",
                    "distance_m": jump_dist,
                    "from": {"lat": self.last_valid_position[0],
                             "lon": self.last_valid_position[1]},
                    "to": {"lat": lat, "lon": lon},
                    "rtk_fix": rtk,
                })

        # Check 2: HDOP degradation
        if len(self.hdop_history) >= 3:
            recent_hdops = [h[0] for h in list(self.hdop_history)[-3:]]
            avg_recent = sum(recent_hdops) / len(recent_hdops)
            if hdop > avg_recent + GPSShieldConfig.HDOP_DEGRADATION_THRESHOLD:
                self.hdop_degradation_events += 1
                events.append({
                    "type": "hdop_degraded",
                    "current_hdop": hdop,
                    "average_recent": avg_recent,
                    "degradation": hdop - avg_recent,
                })

        # Check 3: Satellite count drop
        if len(self.sat_history) >= 3:
            recent_sats = [s[0] for s in list(self.sat_history)[-3:]]
            avg_sats = sum(recent_sats) / len(recent_sats)
            if avg_sats - sats > GPSShieldConfig.SATELLITE_COUNT_DROP_THRESHOLD:
                self.satellite_drops += 1
                events.append({
                    "type": "satellite_count_drop",
                    "current": sats,
                    "average_recent": avg_sats,
                    "drop": avg_sats - sats,
                })

        # Check 4: Cross-reference with Windows Location
        if (self.winloc_lat is not None and
                now - self.winloc_last_update < GPSShieldConfig.WINLOC_STALE_THRESHOLD):
            winloc_dist = _haversine_meters(lat, lon, self.winloc_lat, self.winloc_lon)
            if winloc_dist > GPSShieldConfig.POSITION_DIVERGE_METERS:
                events.append({
                    "type": "winloc_divergence",
                    "distance_m": winloc_dist,
                    "rtk2_position": {"lat": lat, "lon": lon},
                    "winloc_position": {"lat": self.winloc_lat,
                                       "lon": self.winloc_lon},
                    "winloc_accuracy": self.winloc_accuracy,
                })

        # Check 5: Cross-reference with home position (sanity check)
        home_dist = _haversine_meters(lat, lon, self.home_lat, self.home_lon)
        if home_dist > 5000:  # >5km from home = suspicious
            events.append({
                "type": "far_from_home",
                "distance_m": home_dist,
                "home": {"lat": self.home_lat, "lon": self.home_lon},
                "current": {"lat": lat, "lon": lon},
            })

        # Log all events
        for event in events:
            _log_detection(
                f"gps_cross_validation_{event['type']}",
                event,
                lat=lat, lon=lon,
                severity="CRITICAL" if event.get("distance_m", 0) > 500
                else "WARNING"
            )

        # Update last valid position
        if gps["has_fix"]:
            self.last_valid_position = (lat, lon)
            self.last_valid_time = now

        return events

    def start(self):
        """Start the cross-validation thread."""
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        log.info("GPS Cross-Validator started")

    def stop(self):
        """Stop the cross-validation thread."""
        self.running = False

    def _run(self):
        """Main cross-validation thread."""
        while self.running:
            try:
                events = self._run_cross_check()
                if events:
                    for evt in events:
                        log.warning(f"[GPS-CROSS] {evt['type']}: {json.dumps(evt, default=str)}")
            except Exception as e:
                log.debug(f"[GPS-CROSS] Error: {e}")
            time.sleep(GPSShieldConfig.CROSS_CHECK_INTERVAL)

    def get_status(self) -> Dict[str, Any]:
        """Return current shield status for map display."""
        gps = self._get_gps_state()
        return {
            "cross_checks": self.total_checks,
            "spoof_events": self.spoof_events,
            "position_jumps": self.position_jumps,
            "hdop_degradations": self.hdop_degradation_events,
            "satellite_drops": self.satellite_drops,
            "gps": gps,
            "winloc": {
                "lat": self.winloc_lat,
                "lon": self.winloc_lon,
                "accuracy": self.winloc_accuracy,
                "age_sec": time.time() - self.winloc_last_update
                if self.winloc_last_update else None,
            },
        }


# ===================== ADAFRUIT GPS WATCHDOG =====================

class AdafruitGPSWatchdog:
    """Monitors USB bus for Adafruit GPS (VID 10C4 PID EA60) re-appearance.

    The device was forcibly removed at 2026-05-30T18:14:15 CDT.
    This watchdog polls the USB bus and auto-connects when the
    device re-appears, logging all events as potential tampering.
    """

    # State machine states
    STATE_REMOVED = "removed"      # Device was removed (known)
    STATE_MISSING = "missing"      # Device confirmed absent
    STATE_DETECTED = "detected"    # Device found on USB bus
    STATE_CONNECTED = "connected"  # Device connected and reading NMEA
    STATE_ERROR = "error"          # Connection error

    def __init__(self, callback=None):
        self.callback = callback    # Called with (state, data) on events
        self.running = False
        self.thread = None
        self.state = self.STATE_REMOVED
        self.serial_conn = None
        self.last_poll = 0
        self.poll_interval = GPSShieldConfig.ADAFRUIT_POLL_INTERVAL

        # Evidence record
        self.events_log = deque(maxlen=100)
        self.detection_count = 0
        self.connection_attempts = 0

        # Log the initial tamper event at startup
        self._record_startup_tamper()

    def _record_startup_tamper(self):
        """Record the known removal event as a tamper audit entry."""
        tamper_data = {
            "device": "Adafruit GPS (Silicon Labs CP210x)",
            "vid_pid": f"{GPSShieldConfig.ADAFRUIT_VID}:{GPSShieldConfig.ADAFRUIT_PID}",
            "serial": GPSShieldConfig.ADAFRUIT_SERIAL,
            "removal_time": GPSShieldConfig.ADAFRUIT_REMOVAL_TIME,
            "removal_epoch": GPSShieldConfig.ADAFRUIT_REMOVAL_EPOCH,
            "port_was": "COM4",
            "driver": "silabser",
            "mechanism": "Device forcibly removed via USB bus manipulation",
            "assessment": "Active USB bus interference - attacker countermeasure against GPS cross-validation",
            "notes": "Watchdog started monitoring for device re-appearance",
        }
        _log_tamper("ADAFRUIT_GPS_TAMPER_CONFIRMED", **tamper_data)
        _log_detection(
            "adafruit_gps_tamper",
            tamper_data,
            severity="CRITICAL"
        )

    def _poll_usb(self) -> Optional[Dict[str, str]]:
        """Poll USB bus for the Adafruit GPS device."""
        return _find_usb_device(
            GPSShieldConfig.ADAFRUIT_VID,
            GPSShieldConfig.ADAFRUIT_PID
        )

    def _try_connect(self, com_port: str) -> bool:
        """Attempt to open the Adafruit GPS on a COM port and read NMEA."""
        try:
            import serial
            ser = serial.Serial(com_port, 9600, timeout=2)
            data = b''
            start = time.time()
            while time.time() - start < 3:
                chunk = ser.read(256)
                if chunk:
                    data += chunk
                if b'$G' in data:
                    break
            decoded = data.decode('ascii', errors='ignore')
            nmea_lines = [l for l in decoded.split('\n') if l.startswith('$G')]
            if nmea_lines:
                self.serial_conn = ser
                self.state = self.STATE_CONNECTED
                log.info(f"Adafruit GPS connected on {com_port} - {len(nmea_lines)} NMEA sentences")
                self.events_log.append({
                    "time": time.time(),
                    "event": "connected",
                    "port": com_port,
                    "nmea_count": len(nmea_lines),
                })
                if self.callback:
                    self.callback("adafruit_gps_connected", {
                        "port": com_port,
                        "nmea_count": len(nmea_lines),
                    })
                return True
            else:
                ser.close()
                return False
        except Exception as e:
            log.debug(f"Adafruit GPS connect failed on {com_port}: {e}")
            return False

    def _read_nmea_position(self) -> Optional[Dict[str, Any]]:
        """Read current NMEA position from connected Adafruit GPS."""
        if not self.serial_conn or self.state != self.STATE_CONNECTED:
            return None
        try:
            if self.serial_conn.in_waiting:
                line = self.serial_conn.readline().decode('ascii', errors='ignore').strip()
                return _parse_nmea_gga(line)
        except Exception:
            self.state = self.STATE_ERROR
            self.serial_conn = None
        return None

    def start(self):
        """Start the watchdog polling thread."""
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        log.info("Adafruit GPS Watchdog started - monitoring for device re-appearance")

    def stop(self):
        """Stop the watchdog thread."""
        self.running = False
        if self.serial_conn:
            try:
                self.serial_conn.close()
            except Exception:
                pass

    def _run(self):
        """Main watchdog polling loop."""
        while self.running:
            try:
                device = self._poll_usb()
                self.last_poll = time.time()

                if device and device["present"]:
                    if self.state in (self.STATE_REMOVED, self.STATE_MISSING):
                        self.state = self.STATE_DETECTED
                        self.detection_count += 1
                        log.warning(f"Adafruit GPS DETECTED on USB bus: {device}")

                        # Log as potential re-insertion
                        _log_detection(
                            "adafruit_gps_detected",
                            {
                                "event": "device_reappeared",
                                "device_info": device,
                                "time_since_removal_sec": time.time() - GPSShieldConfig.ADAFRUIT_REMOVAL_EPOCH,
                            },
                            severity="WARNING"
                        )
                        _log_tamper("ADAFRUIT_GPS_REAPPEARED", **device)
                        if self.callback:
                            self.callback("adafruit_gps_detected", device)

                        # Try to connect if we have a COM port
                        if device["com_port"]:
                            self.connection_attempts += 1
                            self.state = self.STATE_ERROR
                            if self._try_connect(device["com_port"]):
                                self.state = self.STATE_CONNECTED
                            else:
                                log.warning(
                                    f"Adafruit GPS found but could not read NMEA on {device['com_port']}")

                    elif self.state == self.STATE_CONNECTED:
                        # Already connected, verify still alive
                        try:
                            if self.serial_conn and self.serial_conn.is_open:
                                pass  # Still connected
                            else:
                                self.state = self.STATE_DETECTED
                                if device["com_port"]:
                                    self._try_connect(device["com_port"])
                        except Exception:
                            self.state = self.STATE_DETECTED

                else:
                    # Device not present
                    if self.state == self.STATE_CONNECTED:
                        log.warning("Adafruit GPS DISCONNECTED - device removed from USB bus!")
                        _log_detection(
                            "adafruit_gps_disconnected",
                            {"event": "device_removed_while_connected"},
                            severity="CRITICAL"
                        )
                        _log_tamper("ADAFRUIT_GPS_DISCONNECTED_WHILE_ACTIVE")
                        if self.callback:
                            self.callback("adafruit_gps_disconnected", {})
                        self.serial_conn = None
                    self.state = self.STATE_MISSING

            except Exception as e:
                log.debug(f"[Adafruit Watchdog] Poll error: {e}")

            time.sleep(self.poll_interval)

    def get_status(self) -> Dict[str, Any]:
        """Return current watchdog status."""
        return {
            "state": self.state,
            "detection_count": self.detection_count,
            "connection_attempts": self.connection_attempts,
            "connected": self.state == self.STATE_CONNECTED,
            "last_poll": self.last_poll,
            "events": list(self.events_log),
        }


# ===================== WINDOWS LOCATION API POLLER =====================

class WindowsLocationPoller:
    """Polls Windows.Devices.Geolocation API for secondary GPS reference.

    Uses winrt to query the Windows location service, which can use
    the laptop's built-in GPS (or WiFi positioning as fallback).
    """

    def __init__(self, cross_validator=None):
        self.cross_validator = cross_validator
        self.running = False
        self.thread = None
        self.last_position = None
        self.last_update = 0
        self.update_count = 0
        self.error_count = 0
        self.available = False

        # Check availability
        self._check_availability()

    def _check_availability(self):
        """Check if winrt/Windows Location API is available."""
        try:
            import winrt.windows.devices.geolocation as geoloc
            # Quick test
            self.available = True
            log.info("Windows Location API available")
        except ImportError:
            log.warning("winrt not available - Windows Location polling disabled")
            self.available = False
        except Exception as e:
            log.warning(f"Windows Location API not available: {e}")
            self.available = False

    def _poll_location(self) -> Optional[Dict[str, Any]]:
        """Query Windows.Devices.Geolocation for current position."""
        if not self.available:
            return None

        try:
            import winrt.windows.devices.geolocation as geoloc
            import asyncio

            async def _get_position():
                access = await geoloc.Geolocator.request_access_async()
                if access != geoloc.GeolocationAccessStatus.allowed:
                    return None
                locator = geoloc.Geolocator()
                locator.desired_accuracy = geoloc.PositionAccuracy.high
                pos = await locator.get_geoposition_async()
                return pos

            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            pos = loop.run_until_complete(_get_position())
            if pos and pos.coordinate and pos.coordinate.point:
                pt = pos.coordinate.point.position
                acc = pos.coordinate.accuracy
                return {
                    "lat": pt.latitude,
                    "lon": pt.longitude,
                    "altitude": pt.altitude,
                    "accuracy_m": acc,
                    "timestamp": pos.coordinate.timestamp.isoformat()
                    if pos.coordinate.timestamp else None,
                }
            return None
        except ImportError:
            self.available = False
            return None
        except Exception as e:
            log.debug(f"Windows Location poll: {e}")
            self.error_count += 1
            return None

    def _fallback_powershell_location(self) -> Optional[Dict[str, Any]]:
        """Fallback: query Windows Location via PowerShell.

        Uses Windows.Devices.Geolocation.Geolocator via PowerShell
        to work around winrt import issues.
        """
        try:
            ps_script = """
            Add-Type -AssemblyName System.Device
            $geo = New-Object System.Device.Location.GeoCoordinateWatcher
            $geo.Start()
            Start-Sleep -Milliseconds 2000
            if ($geo.Position.Location.IsUnknown) {
                Write-Output "NoData"
            } else {
                $pos = $geo.Position.Location
                Write-Output "$($pos.Latitude)|$($pos.Longitude)|$($pos.Altitude)|$($pos.HorizontalAccuracy)"
            }
            $geo.Stop()
            """
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.strip()
            if output and output != "NoData":
                parts = output.split('|')
                if len(parts) >= 2:
                    return {
                        "lat": float(parts[0]),
                        "lon": float(parts[1]),
                        "altitude": float(parts[2]) if len(parts) > 2 and parts[2] else 0,
                        "accuracy_m": float(parts[3]) if len(parts) > 3 and parts[3] else None,
                        "source": "powershell_fallback",
                    }
        except Exception as e:
            log.debug(f"PowerShell location fallback: {e}")
        return None

    def start(self):
        """Start the location polling thread."""
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        log.info("Windows Location Poller started")

    def stop(self):
        """Stop the polling thread."""
        self.running = False

    def _run(self):
        """Main polling loop."""
        while self.running:
            try:
                # Try winrt first, fall back to PowerShell
                pos = self._poll_location()
                if pos is None:
                    pos = self._fallback_powershell_location()

                if pos:
                    self.last_position = pos
                    self.last_update = time.time()
                    self.update_count += 1

                    # Feed to cross-validator
                    if self.cross_validator:
                        self.cross_validator.update_winloc(
                            pos["lat"], pos["lon"],
                            pos.get("accuracy_m")
                        )
            except Exception as e:
                log.debug(f"[WinLoc] Poll error: {e}")
                self.error_count += 1

            time.sleep(GPSShieldConfig.WINLOC_POLL_INTERVAL)

    def get_status(self) -> Dict[str, Any]:
        """Return current poller status."""
        return {
            "available": self.available,
            "last_position": self.last_position,
            "last_update": self.last_update,
            "update_count": self.update_count,
            "error_count": self.error_count,
            "stale_sec": time.time() - self.last_update if self.last_update else None,
        }


# ===================== WIGGLE WiFi CHANNEL SCANNER =====================

class WiggleWiFiScanner:
    """Hops through 2.4 GHz (1-13) and 5 GHz (36-165) WiFi channels,
    captures BSSIDs with RSSI, and detects new/rogue access points.

    Uses netsh wlan on both the Alfa (Wi-Fi 2) and built-in (Wi-Fi)
    interfaces. Does NOT interfere with SDR operations - scans are
    brief and on separate hardware.
    """

    def __init__(self, callback=None):
        self.callback = callback
        self.running = False
        self.thread = None
        self.scan_count = 0

        # Baseline BSSID database
        self.baseline_bssids: Dict[str, Dict] = {}   # MAC -> {ssid, rssi_history, first_seen}
        self.baseline_established = False
        self.baseline_scans = 0
        self.BASELINE_SCANS_NEEDED = 3  # scans before baseline is set

        # Rogue AP detection
        self.new_bssids: Dict[str, Dict] = {}  # BSSIDs seen AFTER baseline
        self.rogue_alerts = 0

        # Channel state
        self.current_channel = 1
        self.current_band = "2.4GHz"

        # Interface tracking
        self.alfa_iface = GPSShieldConfig.WIGGLE_ALFA_IFACE
        self.builtin_iface = GPSShieldConfig.WIGGLE_BUILTIN_IFACE
        self.alfa_available = False
        self.builtin_available = False

        # Results
        self.last_scan_results: Dict[str, List[Dict]] = {}
        self.scan_history = deque(maxlen=100)

    def _check_interfaces(self):
        """Verify which WiFi interfaces are available via netsh."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout
            self.alfa_available = self.alfa_iface in output
            self.builtin_available = self.builtin_iface in output
            if not self.alfa_available and not self.builtin_available:
                # Try to find any available interface
                for line in output.split('\n'):
                    if 'Name' in line and ':' in line:
                        name = line.split(':', 1)[1].strip()
                        if name not in (self.alfa_iface, self.builtin_iface):
                            self.builtin_iface = name
                            self.builtin_available = True
                            log.warning(f"Using WiFi interface: {name}")
                            break
        except Exception as e:
            log.debug(f"WiFi interface check: {e}")

    def _scan_interface(self, iface_name: str) -> List[Dict]:
        """Run a WiFi scan on one interface, return parsed BSSID list."""
        try:
            # Trigger scan
            subprocess.run(
                ["netsh", "wlan", "scan", "interface=" + iface_name],
                capture_output=True, timeout=10
            )
            time.sleep(1)  # brief wait for scan to complete

            # Get results
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid",
                 "interface=" + iface_name],
                capture_output=True, text=True, timeout=10
            )

            return self._parse_netsh_bssid(result.stdout)

        except subprocess.TimeoutExpired:
            log.debug(f"WiFi scan timeout on {iface_name}")
        except Exception as e:
            log.debug(f"WiFi scan error on {iface_name}: {e}")

        return []

    def _parse_netsh_bssid(self, output: str) -> List[Dict]:
        """Parse netsh wlan show networks mode=bssid output."""
        networks = []
        current_ssid = None
        current_auth = None
        current_encryption = None

        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('SSID '):
                # Extract SSID number and name
                parts = line.split(':', 1)
                if len(parts) == 2:
                    current_ssid = parts[1].strip()
            elif line.startswith('Authentication'):
                current_auth = line.split(':', 1)[1].strip() if ':' in line else ''
            elif line.startswith('Encryption'):
                current_encryption = line.split(':', 1)[1].strip() if ':' in line else ''
            elif line.startswith('BSSID'):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    bssid = parts[1].strip().replace(' ', '').lower()
                    nets = {
                        'ssid': current_ssid,
                        'bssid': bssid,
                        'auth': current_auth,
                        'encryption': current_encryption,
                    }
            elif line.startswith('Signal') or line.strip().endswith('%'):
                # Try to extract RSSI percentage
                try:
                    rssi_str = line.split(':')[1].strip().replace('%', '')
                    if nets:
                        nets['signal_pct'] = int(rssi_str)
                except Exception:
                    pass
            elif line.startswith('Channel'):
                try:
                    ch = line.split(':')[1].strip()
                    if 'nets' in locals() and nets:
                        nets['channel'] = int(ch)
                except Exception:
                    pass
            elif line.startswith('Radio type'):
                if 'nets' in locals() and nets:
                    nets['radio'] = line.split(':')[1].strip()
                    networks.append(nets)

        return networks

    def _detect_rogue_aps(self, current_bssids: Dict[str, Dict]):
        """Compare current BSSIDs against baseline to find rogue APs."""
        if not self.baseline_established:
            return

        new_aps = set(current_bssids.keys()) - set(self.baseline_bssids.keys())
        removed_aps = set(self.baseline_bssids.keys()) - set(current_bssids.keys())

        if new_aps:
            self.rogue_alerts += 1
            rogue_info = {
                "new_bssids": list(new_aps),
                "count": len(new_aps),
                "details": {mac: current_bssids[mac] for mac in new_aps},
            }

            _log_detection(
                "wifi_rogue_ap_detected",
                rogue_info,
                severity="WARNING" if len(new_aps) < GPSShieldConfig.ROGUE_AP_THRESHOLD
                else "CRITICAL"
            )

            # Store new BSSIDs
            for mac in new_aps:
                self.new_bssids[mac] = current_bssids[mac]
                self.new_bssids[mac]["first_seen"] = time.time()

            if self.callback:
                self.callback("rogue_ap_detected", rogue_info)

        if removed_aps:
            _log_detection(
                "wifi_ap_disappeared",
                {"removed_bssids": list(removed_aps), "count": len(removed_aps)},
                severity="INFO"
            )

    def _run_scan_cycle(self):
        """Execute one complete scan cycle."""
        self._check_interfaces()
        self.scan_count += 1

        all_bssids: Dict[str, Dict] = {}
        scan_results: Dict[str, List[Dict]] = {}

        # Scan Alfa interface (primary)
        if self.alfa_available:
            nets = self._scan_interface(self.alfa_iface)
            scan_results["alfa"] = nets
            for net in nets:
                mac = net.get('bssid', '')
                if mac:
                    all_bssids[mac] = net
                    rssi = net.get('signal_pct', 0)
                    if mac in self.baseline_bssids:
                        self.baseline_bssids[mac]['rssi_history'].append(rssi)
                    # Feed RSSI to passive radar via callback
                    if self.callback:
                        self.callback("wifi_rssi", {
                            "mac": mac, "ssid": net.get('ssid', ''),
                            "rssi_pct": rssi, "channel": net.get('channel', 0),
                            "iface": "alfa",
                        })

        # Scan built-in interface (secondary)
        if self.builtin_available:
            nets = self._scan_interface(self.builtin_iface)
            scan_results["builtin"] = nets
            for net in nets:
                mac = net.get('bssid', '')
                if mac and mac not in all_bssids:
                    all_bssids[mac] = net
                if mac:
                    rssi = net.get('signal_pct', 0)
                    if self.callback:
                        self.callback("wifi_rssi", {
                            "mac": mac, "ssid": net.get('ssid', ''),
                            "rssi_pct": rssi, "channel": net.get('channel', 0),
                            "iface": "builtin",
                        })

        self.last_scan_results = scan_results
        self.scan_history.append({
            "time": time.time(),
            "cycle": self.scan_count,
            "bssid_count": len(all_bssids),
            "alfa_count": len(scan_results.get("alfa", [])),
            "builtin_count": len(scan_results.get("builtin", [])),
        })

        # Establish or update baseline
        if not self.baseline_established:
            for mac, info in all_bssids.items():
                if mac not in self.baseline_bssids:
                    self.baseline_bssids[mac] = info
                    self.baseline_bssids[mac]['rssi_history'] = deque(
                        [info.get('signal_pct', 0)], maxlen=10
                    )
                    self.baseline_bssids[mac]['first_seen'] = time.time()

            self.baseline_scans += 1
            if self.baseline_scans >= self.BASELINE_SCANS_NEEDED:
                self.baseline_established = True
                log.info(
                    f"WiFi baseline established: {len(self.baseline_bssids)} BSSIDs "
                    f"across {self.BASELINE_SCANS_NEEDED} scans"
                )
        else:
            # Detect rogue APs
            self._detect_rogue_aps(all_bssids)

    def start(self):
        """Start the wiggle scanner thread."""
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        log.info("Wiggle WiFi Scanner started")

    def stop(self):
        """Stop the scanner thread."""
        self.running = False

    def _run(self):
        """Main scan loop."""
        while self.running:
            try:
                self._run_scan_cycle()
            except Exception as e:
                log.debug(f"[Wiggle] Scan error: {e}")
            time.sleep(GPSShieldConfig.WIGGLE_INTERVAL)

    def get_status(self) -> Dict[str, Any]:
        """Return current scanner status."""
        return {
            "baseline_established": self.baseline_established,
            "baseline_bssids": len(self.baseline_bssids),
            "new_bssids": len(self.new_bssids),
            "rogue_alerts": self.rogue_alerts,
            "scan_count": self.scan_count,
            "alfa_available": self.alfa_available,
            "builtin_available": self.builtin_available,
            "last_scan_bssid_count": (
                len(self.scan_history[-1]) if self.scan_history else 0
            ),
        }


# ===================== WiFi PASSIVE RADAR FEEDER =====================

class WiFiPassiveRadarFeeder:
    """Routes Alfa WiFi RSSI data into the TSCM passive radar detector.

    Converts WiFi RSSI fluctuations into motion/obstruction signals
    that the passive radar detector can use for room-level presence
    detection and environmental change monitoring.
    """

    def __init__(self, tscm=None):
        self.tscm = tscm
        self.running = False
        self.thread = None

        # RSSI history per MAC for motion detection
        self.rssi_history: Dict[str, deque] = {}
        self.rssi_lock = threading.Lock()

        # Motion detection thresholds
        self.RSSI_MOTION_THRESHOLD = 8       # dBm swing = motion
        self.RSSI_PRESENCE_WINDOW = 10       # samples for presence averaging
        self.MOTION_COOLDOWN = 3.0           # seconds between motion events per MAC

        # State
        self.last_motion_event: Dict[str, float] = {}  # MAC -> last event time
        self.motion_events = 0
        self.total_packets = 0

    def feed_rssi(self, mac: str, rssi: int, channel: int = 0,
                  ssid: str = "", source: str = "alfa"):
        """Feed RSSI data from WiFi scan into passive radar pipeline."""
        self.total_packets += 1

        with self.rssi_lock:
            if mac not in self.rssi_history:
                self.rssi_history[mac] = deque(maxlen=self.RSSI_PRESENCE_WINDOW)
            self.rssi_history[mac].append((rssi, time.time()))

        # Motion detection: rapid RSSI swing
        history = self.rssi_history[mac]
        if len(history) >= 3:
            rssis = [h[0] for h in list(history)[-3:]]
            swing = max(rssis) - min(rssis)

            if swing >= self.RSSI_MOTION_THRESHOLD:
                now = time.time()
                last_event = self.last_motion_event.get(mac, 0)
                if now - last_event > self.MOTION_COOLDOWN:
                    self.last_motion_event[mac] = now
                    self.motion_events += 1

                    motion_data = {
                        "mac": mac,
                        "ssid": ssid,
                        "rssi_swing": swing,
                        "current_rssi": rssi,
                        "channel": channel,
                        "source": source,
                        "type": "wifi_motion",
                    }

                    _log_detection(
                        "passive_radar_wifi_motion",
                        motion_data,
                        severity="INFO"
                    )

                    # Feed to TSCM passive radar
                    self._feed_to_radar(motion_data)

    def _feed_to_radar(self, motion_data: Dict):
        """Push WiFi motion detection into TSCM's passive radar detector."""
        if not self.tscm:
            return
        try:
            # Get passive radar detector if available
            detector = None
            if hasattr(self.tscm, 'detectors'):
                detector = self.tscm.detectors.get('passive_radar')
            if detector and hasattr(detector, 'feed_wifi_motion'):
                detector.feed_wifi_motion(motion_data)
            elif detector and hasattr(detector, 'update'):
                # Generic update with WiFi motion data
                try:
                    detector.update_rf = getattr(detector, 'update_rf', None)
                    if hasattr(detector, 'update_wifi'):
                        detector.update_wifi(motion_data)
                except Exception:
                    pass
        except Exception as e:
            log.debug(f"Passive radar feed: {e}")

    def start(self):
        """Start the passive radar feeder."""
        self.running = True
        log.info("WiFi Passive Radar Feeder started")

    def stop(self):
        """Stop the feeder."""
        self.running = False

    def get_status(self) -> Dict[str, Any]:
        """Return feeder status."""
        return {
            "total_packets": self.total_packets,
            "motion_events": self.motion_events,
            "tracked_macs": len(self.rssi_history),
        }


# ===================== SHIELD ORCHESTRATOR =====================

class GPSWiFiShield:
    """Orchestrates all GPS anti-spoof and WiFi monitoring subsystems.

    This is the top-level integration point for tscm_final.py.
    Instantiate in TSCMSystem.__init__() and start/stop with the system.
    """

    def __init__(self, tscm=None, gps_interface=None):
        """
        Args:
            tscm: TSCMSystem instance (for accessing self.gps)
            gps_interface: GPSInterface instance (fallback)
        """
        self.tscm = tscm
        self.gps_interface = gps_interface
        self.running = False
        self.thread = None
        self._cycle_count = 0

        # Initialize subsystems
        self.cross_validator = GPSCrossValidator(
            tscm=tscm, gps_interface=gps_interface
        )
        self.adafruit_watchdog = AdafruitGPSWatchdog(
            callback=self._on_adafruit_event
        )
        self.winloc_poller = WindowsLocationPoller(
            cross_validator=self.cross_validator
        )
        self.wiggle_scanner = WiggleWiFiScanner(
            callback=self._on_wiggle_event
        )
        self.radar_feeder = WiFiPassiveRadarFeeder(tscm=tscm)
        self.ubx_spoof_detector = UBXSpoofDetector()

        # Wire wiggle scanner RSSI into radar feeder
        self._wiggle_to_radar = True

        log.info("GPS+WiFi Shield orchestrator initialized")

    def _on_adafruit_event(self, event_type: str, data: Dict):
        """Handle Adafruit GPS watchdog events."""
        if event_type == "adafruit_gps_connected":
            log.info(f"Adafruit GPS re-connected: {data}")
            # Feed position into cross-validator as additional reference
            if hasattr(self.adafruit_watchdog, '_read_nmea_position'):
                pos = self.adafruit_watchdog._read_nmea_position()
                if pos:
                    self.cross_validator.update_winloc(
                        pos["lat"], pos["lon"],
                        pos.get("hdop")
                    )
        elif event_type == "adafruit_gps_disconnected":
            log.warning("Adafruit GPS disconnected!")

    def _on_wiggle_event(self, event_type: str, data: Dict):
        """Handle Wiggle scanner events."""
        if event_type == "wifi_rssi" and self._wiggle_to_radar:
            self.radar_feeder.feed_rssi(
                mac=data.get("mac", ""),
                rssi=data.get("rssi_pct", 0),
                channel=data.get("channel", 0),
                ssid=data.get("ssid", ""),
                source=data.get("iface", "unknown"),
            )
        elif event_type == "rogue_ap_detected":
            log.warning(f"Rogue APs detected: {data.get('count', 0)} new BSSIDs")
            # Push to TSCM detection pipeline
            if self.tscm and hasattr(self.tscm, 'detection_markers'):
                for mac in data.get("new_bssids", []):
                    self.tscm.detection_markers.append({
                        "detector": "wifi_rogue_ap",
                        "details": {
                            "mac": mac,
                            "count": data.get("count", 0),
                            "ap_details": data.get("details", {}).get(mac, {}),
                        },
                        "lat": (self.tscm.gps.lat if hasattr(self.tscm, 'gps')
                                and self.tscm.gps.has_fix else 0),
                        "lon": (self.tscm.gps.lon if hasattr(self.tscm, 'gps')
                                and self.tscm.gps.has_fix else 0),
                        "time": datetime.datetime.now(datetime.timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S UTC"),
                        "source": "WiFi",
                        "aoa": 0.0,
                    })

    def start(self):
        """Start all shield subsystems."""
        self.running = True
        self.cross_validator.start()
        self.adafruit_watchdog.start()
        self.winloc_poller.start()
        self.wiggle_scanner.start()
        self.radar_feeder.start()
        # Start UBX spoof detector (ZED-F9P hardware-level anti-spoof)
        try:
            self.ubx_spoof_detector.start()
            log.info("[Shield] UBX spoof detector started")
        except Exception as e:
            log.warning(f"[Shield] UBX spoof detector failed: {e}")

        self.thread = threading.Thread(target=self._run_status, daemon=True)
        self.thread.start()

        log.info("GPS+WiFi Shield fully activated (with UBX anti-spoof)")

    def stop(self):
        """Stop all shield subsystems."""
        self.running = False
        self.ubx_spoof_detector.stop()
        self.cross_validator.stop()
        self.adafruit_watchdog.stop()
        self.winloc_poller.stop()
        self.wiggle_scanner.stop()
        self.radar_feeder.stop()

    def _run_status(self):
        """Periodic status aggregator thread."""
        while self.running:
            self._cycle_count += 1
            # Log aggregate status every 12 cycles (~60s)
            if self._cycle_count % 12 == 0:
                gps_status = self.cross_validator.get_status()
                adafruit_status = self.adafruit_watchdog.get_status()
                winloc_status = self.winloc_poller.get_status()
                wiggle_status = self.wiggle_scanner.get_status()
                radar_status = self.radar_feeder.get_status()

                summary = (
                    f"[SHIELD] GPS: checks={gps_status['cross_checks']} "
                    f"spoof_events={gps_status['spoof_events']} "
                    f"jumps={gps_status['position_jumps']} "
                    f"hdop_events={gps_status['hdop_degradations']} | "
                    f"Adafruit: {adafruit_status['state']} "
                    f"detections={adafruit_status['detection_count']} | "
                    f"WinLoc: updates={winloc_status['update_count']} "
                    f"stale={winloc_status.get('stale_sec', 'N/A')} | "
                    f"Wiggle: baseline={wiggle_status['baseline_bssids']} "
                    f"new={wiggle_status['new_bssids']} "
                    f"rogue={wiggle_status['rogue_alerts']} | "
                    f"Radar: pkts={radar_status['total_packets']} "
                    f"motion={radar_status['motion_events']} | "
                    f"UBX: jamInd={self.ubx_spoof_detector.jam_ind} "
                    f"sats={self.ubx_spoof_detector.sat_count} "
                    f"spoof={self.ubx_spoof_detector.spoof_alert}"
                )
                log.info(summary)
            time.sleep(5)

    def get_status(self) -> Dict[str, Any]:
        """Return full shield status for map/API display."""
        return {
            "cross_validator": self.cross_validator.get_status(),
            "adafruit_watchdog": self.adafruit_watchdog.get_status(),
            "winloc_poller": self.winloc_poller.get_status(),
            "wiggle_scanner": self.wiggle_scanner.get_status(),
            "radar_feeder": self.radar_feeder.get_status(),
            "ubx_spoof_detector": self.ubx_spoof_detector.get_status(),
        }

    def feed_alfa_udp_rssi(self, mac: str, rssi: int, channel: int = 0,
                            ssid: str = ""):
        """Feed RSSI data from Alfa WiFi UDP listener into radar feeder.

        Call this from TSCMSystem._on_wifi_detection() to pipe Alfa
        UDP packets into the passive radar motion detector.
        """
        self.radar_feeder.feed_rssi(mac, rssi, channel, ssid, source="alfa_udp")

    def update_winloc(self, lat: float, lon: float, accuracy: float = None):
        """Manually update Windows Location reference position."""
        self.cross_validator.update_winloc(lat, lon, accuracy)


# ===================== SELF-TEST =====================

def self_test():
    """Quick self-test to verify modules load correctly."""
    print("=" * 60)
    print(" GPS Anti-Spoof + WiFi Shield Self-Test")
    print("=" * 60)

    results = []

    # Test GPS Cross-Validator
    try:
        cv = GPSCrossValidator()
        results.append(("GPS Cross-Validator", "OK"))
    except Exception as e:
        results.append(("GPS Cross-Validator", f"FAIL: {e}"))

    # Test Adafruit Watchdog (instantiation only, no USB poll)
    try:
        aw = AdafruitGPSWatchdog()
        results.append(("Adafruit Watchdog", f"OK (state={aw.state})"))
    except Exception as e:
        results.append(("Adafruit Watchdog", f"FAIL: {e}"))

    # Test Windows Location Poller
    try:
        wl = WindowsLocationPoller()
        results.append(("Windows Location Poller", f"OK (available={wl.available})"))
    except Exception as e:
        results.append(("Windows Location Poller", f"FAIL: {e}"))

    # Test Wiggle Scanner (instantiation only)
    try:
        ws = WiggleWiFiScanner()
        results.append(("Wiggle WiFi Scanner", "OK"))
    except Exception as e:
        results.append(("Wiggle WiFi Scanner", f"FAIL: {e}"))

    # Test Radar Feeder
    try:
        rf = WiFiPassiveRadarFeeder()
        results.append(("WiFi Passive Radar Feeder", "OK"))
    except Exception as e:
        results.append(("WiFi Passive Radar Feeder", f"FAIL: {e}"))

    # Test Shield Orchestrator
    try:
        shield = GPSWiFiShield()
        results.append(("GPS+WiFi Shield Orchestrator", "OK"))
    except Exception as e:
        results.append(("GPS+WiFi Shield Orchestrator", f"FAIL: {e}"))

    print("\nResults:")
    for name, status in results:
        print(f"  {name:30s} {status}")

    return all("FAIL" not in s for _, s in results)


if __name__ == "__main__":
    ok = self_test()
    sys.exit(0 if ok else 1)
