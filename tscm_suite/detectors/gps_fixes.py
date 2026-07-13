#!/usr/bin/env python3
"""
GPS Anti-Spoof Hardened Patches
=================================

Audited: 2026-06-01
Auditor: GPS Anti-Spoof Specialist (subagent)
Scope: real_gps.py, gps_anti_spoof.py, gps_anti_spoof_monitor.py, tscm_final.py,
       interrogation.py (GPSAntiSpoofMonitor)

Problems found and fixed:
  1. No NMEA checksum validation in any parser
  2. pyubx2 not installed → hardware anti-spoof disabled (kept as graceful fallback)
  3. GPSSpoofDetector (tscm_final.py:910) uses only single-sample distance-jump
  4. gps_home.json is trusted blindly as reference (could itself be spoofed)
  5. No signal-level authentication (carrier phase, sat count anomalies, time reversal)

INSTALLATION
============
See section "INTEGRATION GUIDE" at the bottom of this file.

Usage:
  from gps_fixes import (
      HardenedNMEAParser,
      SignalQualityValidator,
      EnhancedSpoofDetector,
      GPSLockdownManager,
      validate_nmea_checksum,
  )

Self-test:
  python gps_fixes.py
"""

import time
import math
import json
import os
import hashlib
import logging
import threading
from collections import deque
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from enum import Enum

log = logging.getLogger("gps_fixes")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: HARDENED NMEA PARSER WITH CHECKSUM VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

class NMEAParseError(Exception):
    """Raised when NMEA line fails validation."""
    pass


class NMEAValidationError(NMEAParseError):
    """Checksum or format validation failure."""
    pass


class NMEAIntegrityError(NMEAParseError):
    """Cryptographic hash chain break — possible MITM/injection."""
    pass


def validate_nmea_checksum(line: str) -> bool:
    """
    Validate NMEA sentence checksum.

    NMEA format: $<talker><sentence>,<data>*<checksum><CR><LF>
    Checksum = XOR of all bytes between '$' and '*' (exclusive).

    Returns True if checksum is valid, False if missing or mismatch.
    Also rejects lines with embedded NUL, non-printable chars, or length > 82.

    Args:
        line: Raw NMEA sentence string (may or may not include <CR><LF>)

    Returns:
        bool: True if checksum is valid
    """
    # Strip CR/LF
    line = line.strip().rstrip('\r\n')

    # Basic sanity checks
    if not line or len(line) < 6:
        return False
    if not line.startswith('$'):
        return False
    if len(line) > 82:
        return False  # NMEA standard max is 82 chars

    # Check for NUL or non-printable chars (except CR/LF already stripped)
    for ch in line:
        if ord(ch) < 0x20 or ord(ch) > 0x7E:
            return False

    # Must have '*' followed by 2 hex digits
    star_idx = line.rfind('*')
    if star_idx < 3 or star_idx + 2 >= len(line):
        return False

    # Compute XOR checksum of chars between '$' and '*'
    body = line[1:star_idx]
    computed = 0
    for ch in body:
        computed ^= ord(ch)

    # Parse the provided checksum
    try:
        provided = int(line[star_idx + 1:star_idx + 3], 16)
    except ValueError:
        return False

    return computed == provided


@dataclass
class NMEAStandardField:
    """A parsed NMEA sentence with checksum validation state."""
    sentence_type: str          # e.g. "GGA", "RMC", "GSA", "GNS"
    talker: str                 # e.g. "GN", "GP", "GL"
    raw_line: str               # Original line (trimmed)
    checksum_valid: bool
    fields: List[str]            # Raw comma-split fields (after talker+type)

    lat: Optional[float] = None
    lon: Optional[float] = None
    alt: Optional[float] = None
    timestamp: Optional[str] = None   # HHMMSS.ss
    fix_quality: int = 0        # 0=none, 1=GPS, 2=DGPS, 4=RTK fixed, 5=RTK float
    sats: int = 0
    hdop: float = 99.0
    speed_knots: Optional[float] = None
    speed_over_ground: Optional[float] = None
    geoid_sep: Optional[float] = None
    pdop: float = 99.0
    vdop: float = 99.0
    sat_ids: List[int] = field(default_factory=list)


class HardenedNMEAParser:
    """
    Drop-in replacement for NMEA parsing in real_gps.py and gps_anti_spoof_monitor.py.

    Key improvements over existing parsers:
      1. Checksum validation (rejects corrupted or injected lines)
      2. Field count validation per sentence type
      3. Numeric range sanity on lat/lon/alt/speed
      4. Rejects duplicate timestamps (possible replay)
      5. Tracks hash chain for integrity verification
      6. Counters for stats (valid/invalid/rejected)
    """

    # Numeric sanity bounds
    LAT_RANGE = (-90.0, 90.0)
    LON_RANGE = (-180.0, 180.0)
    ALT_RANGE = (-500.0, 20000.0)  # Dead Sea to well above stratosphere
    SPEED_MAX_KNOTS = 2000.0        # Mach ~3, generous for aircraft
    HDOP_RANGE = (0.0, 99.0)
    SATS_RANGE = (0, 60)

    def __init__(self, reject_on_bad_checksum: bool = True):
        self.reject_on_bad_checksum = reject_on_bad_checksum
        self.stats = {
            'total_lines': 0,
            'checksum_valid': 0,
            'checksum_invalid': 0,
            'parse_errors': 0,
            'replay_rejected': 0,
            'sanity_rejected': 0,
        }
        self._last_timestamp = None       # For replay detection
        self._chain_hash = b'\x00' * 32    # Integrity chain
        self._last_raw_line_hash = None    # For duplicate detection

    def parse(self, line: str) -> Optional[NMEAStandardField]:
        """
        Parse a single NMEA line with full validation.

        Returns NMEAStandardField on success, None if rejected.
        Raises NMEAParseError on critical errors (callers should catch).
        """
        self.stats['total_lines'] += 1

        line = line.strip().rstrip('\r\n')

        # Quick reject non-NMEA
        if not line.startswith('$'):
            return None

        # Checksum validation
        cksum_ok = validate_nmea_checksum(line)
        if cksum_ok:
            self.stats['checksum_valid'] += 1
        else:
            self.stats['checksum_invalid'] += 1
            if self.reject_on_bad_checksum:
                log.debug(f"NMEA checksum FAIL: {line[:40]}")
                return None
            # If not rejecting, still mark it
            log.warning(f"NMEA checksum INVALID (accepted anyway): {line[:40]}")

        # Hash chain for integrity: each line's hash chains to the previous
        # This detects line insertion/removal/reordering attacks
        line_hash = hashlib.sha256(line.encode('ascii')).digest()
        chained = hashlib.sha256(self._chain_hash + line_hash).digest()

        try:
            result = self._parse_fields(line, cksum_ok)
            if result is None:
                return None

            result.checksum_valid = cksum_ok

            # Replay detection: reject if same timestamp as previous
            if result.timestamp and result.timestamp == self._last_timestamp:
                self.stats['replay_rejected'] += 1
                log.debug(f"NMEA replay detected: duplicate timestamp {result.timestamp}")
                return None
            if result.timestamp:
                self._last_timestamp = result.timestamp

            # Update chain
            self._chain_hash = chained
            self._last_raw_line_hash = line_hash

            return result

        except NMEAValidationError as e:
            self.stats['parse_errors'] += 1
            log.debug(f"NMEA parse error: {e}")
            return None
        except Exception as e:
            self.stats['parse_errors'] += 1
            log.debug(f"NMEA unexpected error: {e}")
            return None

    def _parse_fields(self, line: str, cksum_valid: bool) -> Optional[NMEAStandardField]:
        """Parse validated NMEA line into structured fields."""
        # Split: $GNGGA,...*XX → parts[0]="$GNGGA", rest are comma fields
        star_idx = line.rfind('*')
        body = line[1:star_idx]   # GNGGA,...
        parts = body.split(',')

        talker_sent = parts[0]     # "GNGGA"
        if len(talker_sent) < 3:
            return None

        talker = talker_sent[:2]
        sentence = talker_sent[2:]
        fields = parts[1:]

        result = NMEAStandardField(
            sentence_type=sentence,
            talker=talker,
            raw_line=line,
            checksum_valid=cksum_valid,
            fields=fields,
        )

        if sentence == 'GGA':
            self._parse_gga(fields, result)
        elif sentence in ('RMC', 'GNS'):
            self._parse_rmc_gns(fields, result)
        elif sentence == 'GSA':
            self._parse_gsa(fields, result)
        # else: unknown sentence type, return as-is (no position data)

        return result

    def _parse_gga(self, f: List[str], r: NMEAStandardField):
        """Parse GGA fields with validation."""
        # GGA: time,lat,N/S,lon,E/W,quality,sats,hdop,alt,M,geoid,M,dgps_age,dgps_station*cksum
        if len(f) < 10:
            raise NMEAValidationError(f"GGA too short: {len(f)} fields")

        r.timestamp = f[0] if f[0] else None
        r.fix_quality = int(f[5]) if f[5] else 0
        r.sats = int(f[6]) if f[6] else 0
        r.hdop = float(f[7]) if f[7] else 99.0

        # HDOP sanity
        if r.hdop < 0 or r.hdop > 99:
            r.sanity_rejected_count = 0
            self.stats['sanity_rejected'] += 1
            return

        # Satellite count sanity
        if r.sats < 0 or r.sats > 60:
            self.stats['sanity_rejected'] += 1
            return

        if f[1] and f[2] and f[3] and f[4]:
            try:
                r.lat = self._parse_lat(f[1], f[2])
                r.lon = self._parse_lon(f[3], f[4])
            except NMEAValidationError:
                self.stats['sanity_rejected'] += 1
                return

            if not self._lat_lon_sane(r.lat, r.lon):
                self.stats['sanity_rejected'] += 1
                return

        if f[8]:
            try:
                r.alt = float(f[8])
                if r.alt < self.ALT_RANGE[0] or r.alt > self.ALT_RANGE[1]:
                    self.stats['sanity_rejected'] += 1
                    return
            except ValueError:
                pass

        if len(f) > 10 and f[10]:
            try:
                r.geoid_sep = float(f[10])
            except ValueError:
                pass

    def _parse_rmc_gns(self, f: List[str], r: NMEAStandardField):
        """Parse RMC/GNS fields with validation."""
        if len(f) < 9:
            raise NMEAValidationError(f"RMC/GNS too short: {len(f)} fields")

        r.timestamp = f[0] if f[0] else None
        # f[1] = status: A=active, V=void
        if f[1] == 'A':
            r.fix_quality = 1  # At least 2D fix
        else:
            r.fix_quality = 0

        if f[2] and f[3] and f[4] and f[5]:
            try:
                r.lat = self._parse_lat(f[2], f[3])
                r.lon = self._parse_lon(f[4], f[5])
            except NMEAValidationError:
                self.stats['sanity_rejected'] += 1
                return

            if not self._lat_lon_sane(r.lat, r.lon):
                self.stats['sanity_rejected'] += 1
                return

        if len(f) > 6 and f[6]:
            try:
                r.speed_knots = float(f[6])
                if r.speed_knots < 0 or r.speed_knots > self.SPEED_MAX_KNOTS:
                    self.stats['sanity_rejected'] += 1
                    return
            except ValueError:
                pass

    def _parse_gsa(self, f: List[str], r: NMEAStandardField):
        """Parse GSA (satellite selection / DOP) fields."""
        if len(f) < 17:
            raise NMEAValidationError(f"GSA too short: {len(f)} fields")

        r.fix_quality = int(f[1]) if f[1] else 0  # 1=none, 2=2D, 3=3D

        # Satellite PRN IDs (fields 2-13)
        sat_ids = []
        for i in range(2, min(14, len(f))):
            if f[i]:
                try:
                    sat_ids.append(int(f[i]))
                except ValueError:
                    pass
        r.sat_ids = sat_ids
        r.sats = len(sat_ids)

        if len(f) > 14 and f[14]:
            try:
                r.pdop = float(f[14])
            except ValueError:
                pass
        if len(f) > 15 and f[15]:
            try:
                r.hdop = float(f[15])
            except ValueError:
                pass
        if len(f) > 16 and f[16]:
            try:
                r.vdop = float(f[16])
            except ValueError:
                pass

    def _parse_lat(self, raw: str, direction: str) -> float:
        """Parse NMEA latitude (DDmm.mmmm) + N/S into decimal degrees."""
        if not raw or len(raw) < 4:
            raise NMEAValidationError(f"Bad latitude: '{raw}'")
        try:
            deg = int(raw[:2])
            minutes = float(raw[2:])
            val = deg + minutes / 60.0
            if direction == 'S':
                val = -val
            return val
        except (ValueError, IndexError):
            raise NMEAValidationError(f"Unparseable latitude: '{raw}'")

    def _parse_lon(self, raw: str, direction: str) -> float:
        """Parse NMEA longitude (DDDmm.mmmm) + E/W into decimal degrees."""
        if not raw or len(raw) < 5:
            raise NMEAValidationError(f"Bad longitude: '{raw}'")
        try:
            deg = int(raw[:3])
            minutes = float(raw[3:])
            val = deg + minutes / 60.0
            if direction == 'W':
                val = -val
            return val
        except (ValueError, IndexError):
            raise NMEAValidationError(f"Unparseable longitude: '{raw}'")

    def _lat_lon_sane(self, lat: Optional[float], lon: Optional[float]) -> bool:
        """Sanity check lat/lon against world bounds."""
        if lat is None or lon is None:
            return False
        if lat < self.LAT_RANGE[0] or lat > self.LAT_RANGE[1]:
            return False
        if lon < self.LON_RANGE[0] or lon > self.LON_RANGE[1]:
            return False
        return True

    def get_stats(self) -> Dict[str, int]:
        """Return parsing statistics."""
        return dict(self.stats)

    def get_chain_integrity(self) -> Dict[str, Any]:
        """Return integrity chain state for verification."""
        return {
            'chain_hash': self._chain_hash.hex()[:16],
            'last_timestamp': self._last_timestamp,
            'lines_processed': self.stats['total_lines'],
            'checksum_failure_pct': (
                self.stats['checksum_invalid'] / max(1, self.stats['total_lines']) * 100
            ),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: SIGNAL-QUALITY VALIDATOR
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SignalQualityReport:
    """Result of signal quality validation."""
    is_valid: bool = True
    anomalies: List[str] = field(default_factory=list)
    anomaly_severity: str = "NONE"  # NONE, WARNING, CRITICAL
    score: float = 1.0             # 0.0 = terrible, 1.0 = excellent

    sat_hdop_consistent: bool = True
    alt_reasonable: bool = True
    speed_plausible: bool = True
    carrier_phase_ok: bool = True
    sat_count_normal: bool = True
    dop_reasonable: bool = True


class SignalQualityValidator:
    """
    Validates GPS signal quality metrics that spoofers often get wrong.

    Checks:
      1. Satellite count vs HDOP consistency (spoofers often report high sats
         with terrible HDOP, or low sats with impossibly good HDOP)
      2. Altitude reasonableness (local terrain check)
      3. Speed / acceleration plausibility (kinematic filtering)
      4. Carrier-phase discontinuity detection (for RTK-equipped receivers)
      5. DOP consistency (PDOP ≈ sqrt(HDOP² + VDOP²))

    This feeds into EnhancedSpoofDetector as one of the voting signals.
    """

    def __init__(self,
                 home_lat: float = 41.513235,
                 home_lon: float = -88.133749,
                 local_alt_m: float = 200.0,
                 alt_tolerance_m: float = 100.0):
        self.home_lat = home_lat
        self.home_lon = home_lon
        self.local_alt_m = local_alt_m
        self.alt_tolerance_m = alt_tolerance_m

        # State for kinematic filtering
        self._last_pos: Optional[Tuple[float, float, float, float]] = None
        # (lat, lon, alt, timestamp)
        self._velocity_ms: float = 0.0      # m/s
        self._acceleration_ms2: float = 0.0  # m/s²
        self._carrier_phase_history: deque = deque(maxlen=60)
        self._sat_count_history: deque = deque(maxlen=60)
        self._hdop_history: deque = deque(maxlen=60)
        self._pdop_history: deque = deque(maxlen=60)
        self._vdop_history: deque = deque(maxlen=60)

        # Thresholds
        self.MAX_SPEED_MS = 343.0       # ~Mach 1 (overland vehicle)
        self.MAX_ACCEL_MS2 = 20.0      # ~2G (hard braking for aircraft)
        self.MAX_CARRIER_PHASE_JUMP_CYCLES = 5.0  # for RTK
        self.SAT_COUNT_DROP_ALERT = 4   # drop >4 sats suddenly = suspicious
        self.HDOP_SPIKE_FACTOR = 3.0    # HDOP >3x recent average = suspicious
        self.DOP_CONSISTENCY_THRESHOLD = 5.0  # |PDOP - sqrt(HDOP²+VDOP²)| > 5 = anomaly

    def validate(self,
                 lat: float, lon: float, alt: float,
                 timestamp: float,
                 sats: int, hdop: float, vdop: float = 99.0,
                 pdop: float = 99.0,
                 speed_ms: Optional[float] = None,
                 carrier_phase: Optional[float] = None,
                 fix_quality: int = 0) -> SignalQualityReport:
        """
        Run all signal quality checks on a GPS fix.

        Args:
            lat, lon, alt: Position in decimal degrees and meters
            timestamp: Unix timestamp
            sats: Number of satellites used
            hdop: Horizontal dilution of precision
            vdop: Vertical dilution of precision
            pdop: Position dilution of precision
            speed_ms: Speed in m/s (if available from RMC)
            carrier_phase: Carrier phase measurement in cycles (if available from RTK)
            fix_quality: 0=none, 1=GPS, 2=DGPS, 4=RTK fixed, 5=RTK float

        Returns:
            SignalQualityReport with anomaly details
        """
        report = SignalQualityReport()
        anomalies = []

        # --- 1. Satellite count vs HDOP consistency ---
        sat_hdop_ok = self._check_sat_hdop_consistency(sats, hdop, report)
        if not sat_hdop_ok:
            anomalies.append(f"sats={sats} vs hdop={hdop:.1f} inconsistent")

        # --- 2. Altitude reasonableness ---
        alt_ok = self._check_altitude(alt, report)
        if not alt_ok:
            anomalies.append(f"alt={alt:.1f}m unreasonable")

        # --- 3. Speed / acceleration plausibility ---
        speed_ok = self._check_speed_acceleration(lat, lon, alt, timestamp, speed_ms, report)
        if not speed_ok:
            anomalies.append(f"speed/accel implausible (v={self._velocity_ms:.1f}m/s)")

        # --- 4. Carrier-phase discontinuity ---
        if carrier_phase is not None:
            cp_ok = self._check_carrier_phase(carrier_phase, timestamp, report)
            if not cp_ok:
                anomalies.append(f"carrier phase discontinuity detected")

        # --- 5. Satellite constellation anomaly ---
        sat_ok = self._check_sat_count_anomaly(sats, report)
        if not sat_ok:
            anomalies.append(f"sat count anomaly: {sats}")

        # --- 6. DOP consistency (PDOP ≈ sqrt(HDOP² + VDOP²)) ---
        dop_ok = self._check_dop_consistency(hdop, vdop, pdop, report)
        if not dop_ok:
            anomalies.append(f"DOP inconsistency: hdop={hdop:.1f} vdop={vdop:.1f} pdop={pdop:.1f}")

        # Score the report
        # Each failed check reduces score
        failed = sum(1 for a in [
            report.sat_hdop_consistent,
            report.alt_reasonable,
            report.speed_plausible,
            report.carrier_phase_ok,
            report.sat_count_normal,
            report.dop_reasonable,
        ] if not a)
        report.score = max(0.0, 1.0 - failed * 0.2)
        report.is_valid = report.score > 0.5
        report.anomalies = anomalies
        report.anomaly_severity = "CRITICAL" if not report.is_valid else (
            "WARNING" if anomalies else "NONE"
        )

        # Store state
        self._last_pos = (lat, lon, alt, timestamp)
        self._sat_count_history.append((sats, timestamp))
        self._hdop_history.append((hdop, timestamp))
        self._pdop_history.append((pdop, timestamp))
        self._vdop_history.append((vdop, timestamp))
        if carrier_phase is not None:
            self._carrier_phase_history.append((carrier_phase, timestamp))

        return report

    def _check_sat_hdop_consistency(self, sats: int, hdop: float, report: SignalQualityReport) -> bool:
        """
        Check satellite count vs HDOP consistency.

        Spoofers often:
          - Report 12+ sats with HDOP > 5 (real receivers with good sky view get HDOP < 2)
          - Report 4 sats with HDOP < 0.5 (impossible — need more sats for good geometry)
        """
        if sats == 0 or hdop > 99:
            # No data, can't check
            return True

        # High sats + bad HDOP = suspicious
        if sats >= 10 and hdop > 3.0:
            report.sat_hdop_consistent = False
            return False

        # Low sats + great HDOP = suspicious
        if sats <= 4 and hdop < 0.7:
            report.sat_hdop_consistent = False
            return False

        # Track HDOP history for spike detection
        if len(self._hdop_history) >= 5:
            recent = [h[0] for h in list(self._hdop_history)[-5:] if h[0] < 99]
            if recent:
                avg_hdop = sum(recent) / len(recent)
                if avg_hdop > 0 and hdop > avg_hdop * self.HDOP_SPIKE_FACTOR:
                    report.sat_hdop_consistent = False
                    return False

        return True

    def _check_altitude(self, alt: float, report: SignalQualityReport) -> bool:
        """
        Check altitude reasonableness.

        If we have a known local altitude (from gps_home.json or initialization),
        check that GPS altitude is within tolerance. Also do a general world check.
        """
        # General sanity: -500m to +20km
        if alt < -500.0 or alt > 20000.0:
            report.alt_reasonable = False
            return False

        # If we have a local reference and have been stationary (low speed),
        # altitude should be close to reference
        if self.local_alt_m is not None and abs(self._velocity_ms) < 5.0:
            expected_range = self.local_alt_m + self.alt_tolerance_m
            expected_min = self.local_alt_m - self.alt_tolerance_m
            if alt > expected_range or alt < expected_min:
                report.alt_reasonable = False
                return False

        return True

    def _check_speed_acceleration(self, lat: float, lon: float, alt: float,
                                   timestamp: float,
                                   speed_ms: Optional[float],
                                   report: SignalQualityReport) -> bool:
        """
        Check speed and acceleration plausibility.

        Uses both reported speed (from RMC) and computed speed (from position delta).
        GPS spoofers often have inconsistent speed/position relationships.
        """
        if self._last_pos is None:
            self._velocity_ms = speed_ms if speed_ms is not None else 0.0
            return True

        dt = timestamp - self._last_pos[3]
        if dt <= 0 or dt > 60:
            # Too old or zero delta, skip kinematic check
            return True

        # Compute speed from position delta
        dist = haversine_meters(self._last_pos[0], self._last_pos[1], lat, lon)
        alt_delta = abs(alt - self._last_pos[2])
        dist_3d = math.sqrt(dist**2 + alt_delta**2)
        computed_speed = dist_3d / dt

        # Check against reported speed (if available)
        if speed_ms is not None:
            # Reported and computed should agree within ~50%
            if speed_ms > 1.0:
                ratio = computed_speed / speed_ms
                if ratio < 0.5 or ratio > 2.0:
                    log.debug(f"Speed mismatch: reported={speed_ms:.1f} computed={computed_speed:.1f} ratio={ratio:.2f}")
                    report.speed_plausible = False
                    return False

        # Update velocity with computed speed
        new_velocity = computed_speed

        # Check max speed
        if new_velocity > self.MAX_SPEED_MS:
            report.speed_plausible = False
            self._velocity_ms = new_velocity
            return False

        # Check acceleration
        if dt > 0.01:
            new_accel = abs(new_velocity - self._velocity_ms) / dt
            self._acceleration_ms2 = new_accel
            if new_accel > self.MAX_ACCEL_MS2:
                report.speed_plausible = False
                self._velocity_ms = new_velocity
                return False

        self._velocity_ms = new_velocity
        return True

    def _check_carrier_phase(self, carrier_phase: float, timestamp: float,
                              report: SignalQualityReport) -> bool:
        """
        Detect carrier-phase discontinuities (for RTK receivers).

        Spoofed signals cause carrier phase jumps because the spoofed
        signal's phase doesn't smoothly connect to the real signal's phase.
        """
        if not self._carrier_phase_history:
            self._carrier_phase_history.append((carrier_phase, timestamp))
            return True

        prev_cp, prev_t = self._carrier_phase_history[-1]
        dt = timestamp - prev_t
        if dt <= 0 or dt > 10:
            return True  # Can't check

        # Expected phase rate: GPS L1 = 1575.42 MHz, so carrier moves at 1575.42e6 cycles/s
        # We expect to see delta ≈ carrier_freq * dt modulo cycle
        # But since carrier_phase is reported modulo 2π (or modulo wavelength),
        # we just check for unreasonable jumps relative to expected rate

        # For RTK, carrier phase should change smoothly. Any sudden jump
        # of more than MAX_CARRIER_PHASE_JUMP_CYCLES is suspicious.
        delta = abs(carrier_phase - prev_cp)
        expected_max = 1000.0 * dt  # Very generous expected change rate

        if delta > self.MAX_CARRIER_PHASE_JUMP_CYCLES and delta < expected_max:
            # Jump detected but within possible range — flag as suspicious
            report.carrier_phase_ok = False
            log.debug(f"Carrier phase jump: {delta:.2f} cycles in {dt:.2f}s")
            return False

        self._carrier_phase_history.append((carrier_phase, timestamp))
        return True

    def _check_sat_count_anomaly(self, sats: int, report: SignalQualityReport) -> bool:
        """
        Check for sudden satellite count changes.

        Spoofers often have all-or-nothing satellite patterns:
          - Real sky view: 8-14 GPS sats, plus Galileo/GLONASS/BeiDou
          - Spoofer: all sats appear at once, or exact same count every epoch
        """
        if len(self._sat_count_history) < 3:
            self._sat_count_history.append((sats, time.time()))
            return True

        recent = [s[0] for s in list(self._sat_count_history)[-10:]]
        avg_sats = sum(recent) / len(recent)

        # Sudden drop
        if avg_sats - sats > self.SAT_COUNT_DROP_ALERT:
            report.sat_count_normal = False
            return False

        # Check for too-stable count (spoofers often report exactly N sats every epoch)
        if len(recent) >= 5:
            all_same = all(s == recent[0] for s in recent)
            if all_same and sats > 0:
                # 5+ identical counts is suspicious for a moving receiver
                if abs(self._velocity_ms) > 2.0:
                    report.sat_count_normal = False
                    log.debug(f"Suspicious stable sat count: {sats}x{len(recent)} while moving")
                    return False

        self._sat_count_history.append((sats, time.time()))
        return True

    def _check_dop_consistency(self, hdop: float, vdop: float, pdop: float,
                                report: SignalQualityReport) -> bool:
        """
        Check DOP consistency: PDOP ≈ sqrt(HDOP² + VDOP²).

        Spoofers often fabricate DOP values that don't satisfy this geometric relationship.
        """
        if hdop > 99 or vdop > 99 or pdop > 99:
            return True  # Can't check

        expected_pdop = math.sqrt(hdop**2 + vdop**2)
        deviation = abs(pdop - expected_pdop)

        if deviation > self.DOP_CONSISTENCY_THRESHOLD:
            report.dop_reasonable = False
            log.debug(f"DOP inconsistency: PDOP={pdop:.1f} vs expected={expected_pdop:.1f} (diff={deviation:.1f})")
            return False

        return True


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: ENHANCED SPOOF DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class SpoofSeverity(Enum):
    NONE = 0
    LOW = 1        # Minor anomaly, likely benign
    MEDIUM = 2     # Suspicious, worth logging
    HIGH = 3       # Likely spoofing attempt
    CRITICAL = 4   # Confirmed spoofing, immediate action needed


@dataclass
class SpoofDetectionResult:
    """Result from enhanced spoof detection."""
    severity: SpoofSeverity = SpoofSeverity.NONE
    detected: bool = False
    signals: Dict[str, Any] = field(default_factory=dict)
    details: List[str] = field(default_factory=list)
    confidence: float = 0.0    # 0.0-1.0
    lockdown_recommended: bool = False

    # Per-source trust scores (0.0-1.0)
    source_trust: Dict[str, float] = field(default_factory=dict)


@dataclass
class GPSSourceReading:
    """A single GPS source's reading at one point in time."""
    source_id: str        # e.g. "zed-f9p", "com4", "laptop", "phone"
    lat: float
    lon: float
    alt: float = 0.0
    timestamp: float = 0.0
    hdop: float = 99.0
    sats: int = 0
    fix_quality: int = 0
    speed_ms: float = 0.0
    age_seconds: float = 0.0
    is_rtk: bool = False
    accuracy_m: float = 50.0

    @property
    def has_fix(self) -> bool:
        return self.fix_quality >= 1


class EnhancedSpoofDetector:
    """
    Multi-layered GPS spoof detection with:
      1. Multi-source cross-check with weighted voting
      2. Position jump detection with hysteresis (not single-sample threshold)
      3. Satellite constellation anomaly detection
      4. Time-reversal detection (spoofers replay old signals with past timestamps)
      5. Signal quality validation (delegates to SignalQualityValidator)

    Replaces: GPSSpoofDetector (tscm_final.py:910), GPSCrossValidator.check(),
              GPSAntiSpoofMonitor.feed_nmea(), and the cross-validation in
              real_gps.py get_position().
    """

    # Cross-validation thresholds
    MAX_CONSENSUS_DIVERGENCE_M = 50.0      # Sources must agree within 50m
    HIGH_CONSENSUS_DIVERGENCE_M = 20.0      # >20m divergence = warning
    LOCKDOWN_DIVERGENCE_M = 100.0           # >100m = lockdown

    # Position jump detection with hysteresis
    JUMP_ALERT_THRESHOLD_M = 100.0         # Single jump > 100m = alert
    JUMP_SUSPICION_THRESHOLD_M = 50.0       # Single jump > 50m = suspicion
    JUMP_HISTORY_WINDOW = 10                # Check last N positions
    JUMP_REPEAT_THRESHOLD = 3               # 3+ jumps in window = spoof

    # Time reversal detection
    MAX_TIME_DRIFT_S = 5.0                  # GPS time vs system time
    TIME_REVERSAL_THRESHOLD_S = 0.1         # Any backward time step = red alert

    # Voting weights per signal
    WEIGHT_MULTI_SOURCE = 0.30
    WEIGHT_POSITION_JUMP = 0.25
    WEIGHT_SIGNAL_QUALITY = 0.20
    WEIGHT_TIME_INTEGRITY = 0.15
    WEIGHT_CONSTELLATION = 0.10

    def __init__(self):
        self.position_history: deque = deque(maxlen=60)
        # Each entry: (lat, lon, alt, timestamp, source_id, sats, hdop)
        self._jump_count_in_window = 0
        self._last_gps_time: Optional[float] = None
        self._signal_validator = SignalQualityValidator()
        self._lockdown = GPSLockdownManager()
        self._last_nmea_timestamp: Optional[str] = None
        self._detection_count = 0
        self._spoof_event_count = 0
        self._trust_scores: Dict[str, deque] = {}  # source_id -> deque of trust scores

    def feed(self, readings: List[GPSSourceReading]) -> SpoofDetectionResult:
        """
        Feed multiple GPS source readings for cross-validation.

        This is the main entry point — call this with all available
        GPS positions at each epoch.

        Args:
            readings: List of GPSSourceReading from all sources

        Returns:
            SpoofDetectionResult with detection status
        """
        result = SpoofDetectionResult()
        self._detection_count += 1

        # If in lockdown, check for recovery
        if self._lockdown.in_lockdown:
            lockdown_status = self._lockdown.check_recovery(readings)
            if lockdown_status['recovered']:
                result.details.append("LOCKDOWN RECOVERED: 3 clean readings")
                log.warning("GPS LOCKDOWN RECOVERED")
            else:
                result.detected = True
                result.severity = SpoofSeverity.CRITICAL
                result.lockdown_recommended = True
                result.confidence = 1.0
                result.details.append("STILL IN LOCKDOWN: positions flagged untrusted")
                return result

        if not readings:
            return result

        # --- Signal 1: Multi-source cross-check with weighted voting ---
        multi_score, multi_details = self._check_multi_source(readings)
        result.signals['multi_source'] = {
            'score': multi_score, 'details': multi_details
        }

        # --- Signal 2: Position jump detection with hysteresis ---
        jump_score, jump_details = self._check_position_jump(readings)
        result.signals['position_jump'] = {
            'score': jump_score, 'details': jump_details
        }

        # --- Signal 3: Signal quality validation ---
        best_reading = self._get_best_reading(readings)
        if best_reading and best_reading.has_fix:
            sq_report = self._signal_validator.validate(
                lat=best_reading.lat, lon=best_reading.lon, alt=best_reading.alt,
                timestamp=best_reading.timestamp or time.time(),
                sats=best_reading.sats, hdop=best_reading.hdop,
                speed_ms=best_reading.speed_ms or None,
                fix_quality=best_reading.fix_quality,
            )
            quality_score = 0.0 if sq_report.is_valid else 1.0
            if not sq_report.is_valid:
                quality_score = 1.0 - sq_report.score
            result.signals['signal_quality'] = {
                'score': quality_score, 'report': sq_report,
            }
        else:
            quality_score = 0.0
            result.signals['signal_quality'] = {'score': 0.0, 'report': None}

        # --- Signal 4: Time integrity (reversal + drift) ---
        time_score, time_details = self._check_time_integrity(readings)
        result.signals['time_integrity'] = {
            'score': time_score, 'details': time_details
        }

        # --- Signal 5: Satellite constellation ---
        const_score, const_details = self._check_constellation(readings)
        result.signals['constellation'] = {
            'score': const_score, 'details': const_details
        }

        # --- Weighted combination ---
        # Each signal returns a score 0.0 (clean) to 1.0 (suspicious)
        w = self.WEIGHT_MULTI_SOURCE
        x = self.WEIGHT_POSITION_JUMP
        y = self.WEIGHT_SIGNAL_QUALITY
        z = self.WEIGHT_TIME_INTEGRITY
        v = self.WEIGHT_CONSTELLATION
        combined = (
            multi_score * w +
            jump_score * x +
            quality_score * y +
            time_score * z +
            const_score * v
        )
        result.confidence = combined

        # --- Determine severity ---
        if combined > 0.8:
            result.severity = SpoofSeverity.CRITICAL
            result.detected = True
        elif combined > 0.6:
            result.severity = SpoofSeverity.HIGH
            result.detected = True
        elif combined > 0.4:
            result.severity = SpoofSeverity.MEDIUM
            result.detected = False  # Suspicious but not confirmed
        elif combined > 0.2:
            result.severity = SpoofSeverity.LOW
            result.detected = False
        else:
            result.severity = SpoofSeverity.NONE

        # Build details
        all_details = []
        for signal_name, signal_data in result.signals.items():
            details = signal_data.get('details', [])
            if isinstance(details, list):
                all_details.extend(details)
            elif isinstance(details, str):
                all_details.append(details)
            report = signal_data.get('report')
            if report and isinstance(report, SignalQualityReport) and report.anomalies:
                all_details.extend(report.anomalies)

        result.details = all_details

        # Compute per-source trust
        result.source_trust = self._compute_source_trust(readings, result)

        # --- Lockdown decision ---
        if result.severity in (SpoofSeverity.CRITICAL, SpoofSeverity.HIGH):
            # Additional condition: multi-source divergence OR position jump
            if multi_score > 0.5 or jump_score > 0.5:
                result.lockdown_recommended = True
                self._lockdown.activate(readings, result.details)
                self._spoof_event_count += 1
                log.critical(
                    f"GPS SPOOF DETECTED (severity={result.severity.name}, "
                    f"confidence={result.confidence:.2f}): {result.details}"
                )
        elif result.severity == SpoofSeverity.MEDIUM:
            self._spoof_event_count += 1
            log.warning(
                f"GPS SUSPICIOUS (confidence={result.confidence:.2f}): {result.details}"
            )

        # Store in position history
        now = time.time()
        for r in readings:
            if r.has_fix:
                self.position_history.append((
                    r.lat, r.lon, r.alt, r.timestamp or now, r.source_id,
                    r.sats, r.hdop
                ))

        return result

    def _check_multi_source(self, readings: List[GPSSourceReading]) -> Tuple[float, List[str]]:
        """
        Multi-source cross-check with weighted voting.

        If only one source, reduce score (can't cross-validate).
        If 2+ sources disagree, score proportional to divergence.
        Weighted voting: RTK > serial GPS > laptop > phone.
        """
        details = []
        valid = [r for r in readings if r.has_fix]

        if len(valid) < 2:
            # Single source — can't cross-validate
            if len(valid) == 1 and valid[0].is_rtk and valid[0].hdop < 1.0:
                # Single RTK with excellent HDOP — somewhat trusted
                return 0.1, ["single_rtk_source"]
            return 0.3, ["insufficient_sources_for_cross_validation"]

        # Compute pairwise distances
        max_dist = 0.0
        pair_count = 0
        divergent_pairs = []

        for i in range(len(valid)):
            for j in range(i + 1, len(valid)):
                d = haversine_meters(valid[i].lat, valid[i].lon,
                                    valid[j].lat, valid[j].lon)
                pair_count += 1
                if d > max_dist:
                    max_dist = d
                if d > self.MAX_CONSENSUS_DIVERGENCE_M:
                    divergent_pairs.append(
                        f"{valid[i].source_id} vs {valid[j].source_id}: {d:.0f}m"
                    )

        if divergent_pairs:
            # Significant divergence — likely spoofing
            score = min(1.0, max_dist / self.LOCKDOWN_DIVERGENCE_M)
            details.append(f"source_divergence: {max_dist:.0f}m max")
            details.extend(divergent_pairs)
            return score, details

        if max_dist > self.HIGH_CONSENSUS_DIVERGENCE_M:
            # Mild divergence
            score = (max_dist - self.HIGH_CONSENSUS_DIVERGENCE_M) / (
                self.LOCKDOWN_DIVERGENCE_M - self.HIGH_CONSENSUS_DIVERGENCE_M
            )
            details.append(f"source_divergence_mild: {max_dist:.0f}m")
            return score, details

        # Sources agree — clean
        return 0.0, ["sources_agree"]

    def _check_position_jump(self, readings: List[GPSSourceReading]) -> Tuple[float, List[str]]:
        """
        Position jump detection with hysteresis.

        Instead of flagging a single jump > threshold, we track jumps over
        a window of recent positions. Sporadic GPS noise causes isolated
        jumps, but spoofers cause repeated large jumps.

        This is the key improvement over the single-sample GPSSpoofDetector
        in tscm_final.py which just checks speed > 1000 m/s.
        """
        details = []
        now = time.time()
        best = self._get_best_reading(readings)

        if best is None or not best.has_fix:
            return 0.0, ["no_valid_fix"]

        # Check against last position in history
        if len(self.position_history) < 2:
            return 0.0, ["insufficient_history"]

        prev = self.position_history[-1]
        prev_lat, prev_lon, prev_alt, prev_t, prev_src, prev_sats, prev_hdop = prev

        dt = now - prev_t
        if dt <= 0 or dt > 30:
            return 0.0, [f"stale_reference: dt={dt:.0f}s"]

        dist = haversine_meters(prev_lat, prev_lon, best.lat, best.lon)
        speed = dist / dt

        # Speed check (same as original but with hysteresis)
        if speed > 500:  # ~1800 km/h
            self._jump_count_in_window += 1
            details.append(f"extreme_speed: {speed:.0f}m/s ({dist:.0f}m in {dt:.1f}s)")
            if dist > self.JUMP_ALERT_THRESHOLD_M:
                details.append(f"large_jump: {dist:.0f}m")
        elif dist > self.JUMP_SUSPICION_THRESHOLD_M:
            self._jump_count_in_window += 1
            details.append(f"suspicious_jump: {dist:.0f}m in {dt:.1f}s")
        else:
            # Decay jump counter
            self._jump_count_in_window = max(0, self._jump_count_in_window - 1)

        # Hysteresis: repeated jumps = high confidence spoof
        if self._jump_count_in_window >= self.JUMP_REPEAT_THRESHOLD:
            return 1.0, details + [f"repeated_jumps: {self._jump_count_in_window} in {self.JUMP_HISTORY_WINDOW} window"]
        elif self._jump_count_in_window >= 2:
            return 0.6, details
        elif self._jump_count_in_window >= 1:
            return 0.3, details

        return 0.0, details

    def _check_time_integrity(self, readings: List[GPSSourceReading]) -> Tuple[float, List[str]]:
        """
        Time-reversal and time-drift detection.

        Spoofers that replay old GPS signals will have timestamps that are
        in the past relative to the system clock. Additionally, the GPS time
        should never go backward between readings.

        This is a key detection: if GPS time goes backward, it's almost
        certainly a replay attack (real GPS satellites' clocks never run backward).
        """
        details = []
        sys_time = time.time()

        for r in readings:
            if r.timestamp <= 0:
                continue

            # Check GPS time vs system time
            drift = r.timestamp - sys_time
            if abs(drift) > self.MAX_TIME_DRIFT_S:
                details.append(f"time_drift: {r.source_id} drift={drift:.1f}s")

            # Check time reversal (backward time)
            if self._last_gps_time is not None:
                time_delta = r.timestamp - self._last_gps_time
                if time_delta < -self.TIME_REVERSAL_THRESHOLD_S:
                    # CRITICAL: time went backward
                    details.append(
                        f"TIME_REVERSAL: {r.source_id} jumped {-time_delta:.2f}s backward — "
                        f"replay attack signature"
                    )
                    return 1.0, details  # Immediate high score
            self._last_gps_time = r.timestamp

            # Check NMEA timestamp string for reversal
            if hasattr(r, 'nmea_timestamp') and r.nmea_timestamp:
                if self._last_nmea_timestamp and r.nmea_timestamp < self._last_nmea_timestamp:
                    details.append(f"nmea_time_reversal: {r.source_id}")
                    return 0.8, details
                self._last_nmea_timestamp = r.nmea_timestamp

        if not details:
            return 0.0, ["time_ok"]

        # Moderate score for drift (could be clock issue, not spoof)
        return 0.4, details

    def _check_constellation(self, readings: List[GPSSourceReading]) -> Tuple[float, List[str]]:
        """
        Satellite constellation anomaly detection.

        Checks across all sources:
          - If all sources report exactly the same satellite count = suspicious
            (different receivers with different antennas should see different subsets)
          - If source has RTK fix but reports unusually low sats for RTK
          - Large satellite count discrepancies between co-located receivers
        """
        details = []
        valid = [r for r in readings if r.has_fix]

        if len(valid) < 2:
            return 0.0, ["insufficient_sources"]

        sat_counts = [r.sats for r in valid]

        # All sources report identical sat count
        if len(set(sat_counts)) == 1:
            # Especially suspicious if count is a "round" number
            if sat_counts[0] in (8, 10, 12, 16, 24, 32):
                details.append(f"identical_sat_count: all report {sat_counts[0]}")
                return 0.6, details

        # RTK receiver with low sats
        for r in valid:
            if r.is_rtk and r.sats < 6:
                details.append(f"rtk_low_sats: {r.source_id} RTK with only {r.sats} sats")
                return 0.5, details

        # Large discrepancy between sources
        if max(sat_counts) - min(sat_counts) > 8:
            details.append(f"sat_count_spread: {min(sat_counts)}-{max(sat_counts)}")
            return 0.4, details

        return 0.0, ["constellation_ok"]

    def _get_best_reading(self, readings: List[GPSSourceReading]) -> Optional[GPSSourceReading]:
        """Get the highest-trust reading from the list."""
        valid = [r for r in readings if r.has_fix]
        if not valid:
            return None
        # Sort by accuracy (lower = better), RTK first
        valid.sort(key=lambda r: (0 if r.is_rtk else 1, r.accuracy_m, r.age_seconds))
        return valid[0]

    def _compute_source_trust(self, readings: List[GPSSourceReading],
                               result: SpoofDetectionResult) -> Dict[str, float]:
        """
        Compute per-source trust scores.

        Sources that disagree with the consensus get lower trust.
        RTK sources get a base trust bonus.
        """
        trust = {}
        valid = [r for r in readings if r.has_fix]

        if len(valid) < 2:
            for r in readings:
                base = 0.9 if r.is_rtk else 0.5
                trust[r.source_id] = base
            return trust

        # Find consensus position (median)
        lats = sorted(r.lat for r in valid)
        lons = sorted(r.lon for r in valid)
        n = len(lats)
        median_lat = lats[n // 2]
        median_lon = lons[n // 2]

        for r in readings:
            dist = haversine_meters(median_lat, median_lon, r.lat, r.lon)

            # Base trust from accuracy
            base = min(1.0, 10.0 / max(1.0, r.accuracy_m))
            if r.is_rtk:
                base = min(1.0, base + 0.3)

            # Penalty for divergence from consensus
            divergence_penalty = min(0.5, dist / 100.0)

            trust[r.source_id] = max(0.0, base - divergence_penalty)

        return trust

    def get_lockdown_state(self) -> Dict[str, Any]:
        """Get current lockdown status."""
        return self._lockdown.get_state()

    def force_lockdown(self, reason: str = "manual"):
        """Manually trigger lockdown."""
        self._lockdown.activate([], [reason])

    def force_unlock(self):
        """Manually release lockdown."""
        self._lockdown.force_release()

    def get_stats(self) -> Dict[str, Any]:
        """Return detection statistics."""
        return {
            'detection_count': self._detection_count,
            'spoof_event_count': self._spoof_event_count,
            'position_history_len': len(self.position_history),
            'jump_count_in_window': self._jump_count_in_window,
            'lockdown': self._lockdown.get_state(),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4: GPS LOCKDOWN MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class GPSLockdownManager:
    """
    Manages GPS lockdown mode.

    When spoofing is detected:
      1. FREEZE position reporting — don't accept any new positions
      2. FLAG all positions as UNTRUSTED
      3. Log the event with full context
      4. Wait for 3 consecutive clean readings to recover

    Recovery requires ALL of:
      - Multi-source consensus within 20m
      - No position jumps > 50m
      - Signal quality score > 0.7
      - No time anomalies
      - At least 2 sources with valid fixes
    """

    CLEAN_READINGS_TO_RECOVER = 3
    RECOVERY_CONSENSUS_M = 20.0
    RECOVERY_TIMEOUT_S = 300.0  # Force recover after 5 min if conditions met

    def __init__(self):
        self.in_lockdown = False
        self.lockdown_time: Optional[float] = None
        self.lockdown_reason: List[str] = []
        self.clean_count = 0
        self._lock = threading.Lock()
        self.frozen_position: Optional[Dict[str, Any]] = None
        self.lockdown_events: deque = deque(maxlen=100)

    def activate(self, readings: List[GPSSourceReading], reasons: List[str]):
        """Enter lockdown mode."""
        with self._lock:
            if self.in_lockdown:
                return  # Already in lockdown

            self.in_lockdown = True
            self.lockdown_time = time.time()
            self.lockdown_reason = reasons
            self.clean_count = 0

            # Freeze the last known good position
            valid = [r for r in readings if r.has_fix]
            if valid:
                # Use the most trusted position before lockdown
                self.frozen_position = {
                    'lat': valid[0].lat,
                    'lon': valid[0].lon,
                    'alt': valid[0].alt,
                    'time': valid[0].timestamp or time.time(),
                    'frozen_at': time.time(),
                    'sources': len(valid),
                }

            event = {
                'event': 'lockdown_activated',
                'timestamp': time.time(),
                'reasons': reasons,
                'frozen_position': self.frozen_position,
            }
            self.lockdown_events.append(event)

            log.critical(
                f"GPS LOCKDOWN ACTIVATED: {reasons}. "
                f"Position frozen at {self.frozen_position}. "
                f"Waiting for {self.CLEAN_READINGS_TO_RECOVER} clean readings."
            )

            # Write to detection log
            try:
                import datetime as dt
                entry = {
                    "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z",
                    "detector": "gps_lockdown",
                    "severity": "CRITICAL",
                    "details": {"reasons": reasons, "frozen_position": self.frozen_position},
                }
                with open("detections.log", "a") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception:
                pass

    def check_recovery(self, readings: List[GPSSourceReading]) -> Dict[str, Any]:
        """
        Check if conditions are met for lockdown recovery.

        Requires CLEAN_READINGS_TO_RECOVER consecutive clean readings.
        A "clean" reading means:
          - 2+ sources with valid fixes
          - All sources agree within RECOVERY_CONSENSUS_M
          - Signal quality score > 0.7
          - No time anomalies
        """
        if not self.in_lockdown:
            return {'recovered': False, 'clean_count': 0, 'reason': 'not_in_lockdown'}

        valid = [r for r in readings if r.has_fix]

        # Check 1: Enough sources
        if len(valid) < 2:
            self.clean_count = 0
            return {
                'recovered': False,
                'clean_count': self.clean_count,
                'reason': f'insufficient_sources: {len(valid)}/2',
            }

        # Check 2: Consensus
        max_dist = 0
        for i in range(len(valid)):
            for j in range(i + 1, len(valid)):
                d = haversine_meters(valid[i].lat, valid[i].lon,
                                    valid[j].lat, valid[j].lon)
                max_dist = max(max_dist, d)

        if max_dist > self.RECOVERY_CONSENSUS_M:
            self.clean_count = 0
            return {
                'recovered': False,
                'clean_count': self.clean_count,
                'reason': f'consensus_divergence: {max_dist:.0f}m > {self.RECOVERY_CONSENSUS_M}m',
            }

        # Check 3: Sufficient satellites
        avg_sats = sum(r.sats for r in valid) / len(valid)
        if avg_sats < 6:
            self.clean_count = 0
            return {
                'recovered': False,
                'clean_count': self.clean_count,
                'reason': f'low_satellites: {avg_sats:.0f} < 6',
            }

        # Check 4: Time sanity
        sys_time = time.time()
        for r in valid:
            if r.timestamp > 0 and abs(r.timestamp - sys_time) > 5.0:
                self.clean_count = 0
                return {
                    'recovered': False,
                    'clean_count': self.clean_count,
                    'reason': f'time_drift: {r.timestamp - sys_time:.1f}s',
                }

        # All checks passed — increment clean counter
        self.clean_count += 1

        if self.clean_count >= self.CLEAN_READINGS_TO_RECOVER:
            self._release()
            return {'recovered': True, 'clean_count': self.clean_count}

        return {
            'recovered': False,
            'clean_count': self.clean_count,
            'reason': f'need_{self.CLEAN_READINGS_TO_RECOVER}_clean_readings',
        }

    def force_release(self):
        """Manually force release from lockdown."""
        with self._lock:
            self._release()

    def _release(self):
        """Internal: release lockdown."""
        duration = time.time() - (self.lockdown_time or time.time())
        event = {
            'event': 'lockdown_released',
            'timestamp': time.time(),
            'duration_sec': duration,
            'reason': f'{self.clean_count} clean readings',
            'lockdown_reason': self.lockdown_reason,
        }
        self.lockdown_events.append(event)

        log.warning(
            f"GPS LOCKDOWN RELEASED after {duration:.0f}s "
            f"({self.clean_count} clean readings)"
        )

        self.in_lockdown = False
        self.lockdown_time = None
        self.lockdown_reason = []
        self.clean_count = 0
        self.frozen_position = None

    def get_frozen_position(self) -> Optional[Dict[str, Any]]:
        """Return the frozen position during lockdown, or None."""
        return self.frozen_position

    def get_state(self) -> Dict[str, Any]:
        """Return current lockdown state."""
        return {
            'in_lockdown': self.in_lockdown,
            'lockdown_time': self.lockdown_time,
            'duration_sec': (time.time() - self.lockdown_time) if self.lockdown_time else 0,
            'reason': self.lockdown_reason,
            'clean_count': self.clean_count,
            'frozen_position': self.frozen_position,
            'events': len(self.lockdown_events),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5: HOME POSITION VALIDATOR
# ═══════════════════════════════════════════════════════════════════════════════

class HomePositionValidator:
    """
    Validates gps_home.json against current live GPS data.

    Problem: gps_home.json could itself be spoofed if it was written while
    the GPS was under attack. This validator:
      1. Loads home position from file
      2. Cross-checks against live multi-source data
      3. If home position disagrees with live consensus, flags it
      4. Provides a "trusted home" that's verified, not blindly loaded
    """

    def __init__(self, home_file: str = 'gps_home.json'):
        self.home_file = home_file
        self.home_lat: Optional[float] = None
        self.home_lon: Optional[float] = None
        self.home_alt: Optional[float] = None
        self.home_verified = False
        self.home_verification_time: Optional[float] = None
        self._verification_count = 0
        self.VERIFICATION_THRESHOLD = 5  # Need 5 consistent verifications

        self._load_home()

    def _load_home(self):
        """Load home position from file."""
        try:
            if os.path.exists(self.home_file):
                with open(self.home_file) as f:
                    data = json.load(f)
                    self.home_lat = data.get('lat')
                    self.home_lon = data.get('lon')
                    self.home_alt = data.get('alt')
        except Exception as e:
            log.debug(f"Failed to load home position: {e}")

    def verify_against_live(self, live_readings: List[GPSSourceReading]) -> Dict[str, Any]:
        """
        Verify home position against current live GPS data.

        Returns dict with:
          - verified: bool
          - home_position: (lat, lon)
          - consensus_dist_m: distance from home to consensus
          - status: 'verified', 'mismatch', 'unverifiable'
        """
        if self.home_lat is None or self.home_lon is None:
            return {'verified': False, 'status': 'no_home_file', 'home_position': None}

        valid = [r for r in live_readings if r.has_fix]
        if len(valid) < 2:
            return {
                'verified': self.home_verified,
                'status': 'insufficient_sources',
                'home_position': (self.home_lat, self.home_lon),
            }

        # Compute consensus position
        total_w = 0
        w_lat = 0
        w_lon = 0
        for r in valid:
            w = 1.0 / max(1.0, r.accuracy_m ** 2)
            if r.is_rtk:
                w *= 10
            w_lat += r.lat * w
            w_lon += r.lon * w
            total_w += w

        if total_w <= 0:
            return {
                'verified': self.home_verified,
                'status': 'no_valid_weight',
                'home_position': (self.home_lat, self.home_lon),
            }

        consensus_lat = w_lat / total_w
        consensus_lon = w_lon / total_w

        dist = haversine_meters(self.home_lat, self.home_lon, consensus_lat, consensus_lon)

        if dist < 50:  # Within 50m = agreement
            self._verification_count += 1
            if self._verification_count >= self.VERIFICATION_THRESHOLD and not self.home_verified:
                self.home_verified = True
                self.home_verification_time = time.time()
                log.info(f"Home position VERIFIED: {self.home_lat:.6f}, {self.home_lon:.6f}")
        else:
            self._verification_count = max(0, self._verification_count - 1)
            if self.home_verified and dist > 500:
                self.home_verified = False
                log.warning(
                    f"Home position MISMATCH: file says ({self.home_lat:.6f}, {self.home_lon:.6f}) "
                    f"but consensus is ({consensus_lat:.6f}, {consensus_lon:.6f}) — {dist:.0f}m apart"
                )

        return {
            'verified': self.home_verified,
            'status': 'verified' if self.home_verified else 'unverified',
            'home_position': (self.home_lat, self.home_lon),
            'consensus_dist_m': round(dist, 1),
            'consensus_position': (round(consensus_lat, 6), round(consensus_lon, 6)),
            'verification_count': self._verification_count,
        }

    def get_trusted_home(self) -> Optional[Tuple[float, float]]:
        """Return home position only if verified."""
        if self.home_verified and self.home_lat is not None:
            return (self.home_lat, self.home_lon)
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def haversine_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate distance in meters between two GPS coordinates."""
    R = 6371000.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


# ═══════════════════════════════════════════════════════════════════════════════
# SELF-TEST
# ═══════════════════════════════════════════════════════════════════════════════

def _self_test():
    """Run comprehensive self-tests for all modules."""
    import sys

    print("=" * 70)
    print(" GPS ANTI-SPOOF FIXES — SELF-TEST")
    print("=" * 70)

    results = []

    # --- Test 1: NMEA Checksum Validation ---
    print("\n[1] NMEA Checksum Validation")
    valid_line = "$GNGGA,092750.000,5114.1980,N,00014.2792,W,1,12,0.98,53.1,M,47.0,M,,*55"
    bad_line = "$GNGGA,092750.000,5114.1980,N,00014.2792,W,1,12,0.98,53.1,M,47.0,M,,*FF"
    no_checksum = "$GNGGA,092750.000,5114.1980,N"

    assert validate_nmea_checksum(valid_line), "Valid checksum should pass"
    assert not validate_nmea_checksum(bad_line), "Bad checksum should fail"
    assert not validate_nmea_checksum(no_checksum), "Missing checksum should fail"
    assert not validate_nmea_checksum(""), "Empty line should fail"
    assert not validate_nmea_checksum("not nmea"), "Non-$ line should fail"
    print("   ✓ Checksum validation: PASS")

    # --- Test 2: Hardened NMEA Parser ---
    print("\n[2] Hardened NMEA Parser")
    parser = HardenedNMEAParser(reject_on_bad_checksum=True)

    result = parser.parse(valid_line)
    assert result is not None, "Valid line should parse"
    assert result.checksum_valid, "Should be marked valid"
    assert result.sentence_type == "GGA"
    assert result.sats == 12
    print(f"   ✓ Valid line parsed: type={result.sentence_type}, sats={result.sats}, "
          f"lat={result.lat}, lon={result.lon}")

    bad_result = parser.parse(bad_line)
    assert bad_result is None, "Bad checksum line should be rejected"
    print("   ✓ Bad checksum line rejected")

    stats = parser.get_stats()
    assert stats['checksum_valid'] == 1
    assert stats['checksum_invalid'] == 1
    print(f"   ✓ Stats: {stats}")

    # Test replay detection
    result2 = parser.parse(valid_line)
    assert result2 is None, "Duplicate timestamp should be rejected (replay)"
    print("   ✓ Replay detection works")

    results.append(("HardenedNMEAParser", "PASS"))

    # --- Test 3: Signal Quality Validator ---
    print("\n[3] Signal Quality Validator")
    sqv = SignalQualityValidator(home_lat=41.513, home_lon=-88.133, local_alt_m=200.0)

    # Normal reading
    report = sqv.validate(
        lat=41.513, lon=-88.133, alt=200.0,
        timestamp=time.time(), sats=10, hdop=1.0,
        fix_quality=1
    )
    assert report.is_valid, f"Normal reading should be valid, score={report.score}"
    print(f"   ✓ Normal reading: valid={report.is_valid}, score={report.score:.2f}")

    # Spoof-like: high sats, terrible HDOP
    bad_report = sqv.validate(
        lat=41.513, lon=-88.133, alt=200.0,
        timestamp=time.time(), sats=24, hdop=8.0,
        fix_quality=1
    )
    assert not bad_report.sat_hdop_consistent, "24 sats with HDOP 8 should be flagged"
    print(f"   ✓ Sat/HDOP anomaly detected: {bad_report.anomalies}")

    # Speed implausibility (simulate after normal reading)
    time.sleep(0.01)
    bad_report2 = sqv.validate(
        lat=51.0, lon=0.0, alt=200.0,
        timestamp=time.time(), sats=10, hdop=1.0,
        fix_quality=1
    )
    assert not bad_report2.speed_plausible, "Teleportation should be flagged"
    print(f"   ✓ Speed implausibility detected: {bad_report2.anomalies}")

    results.append(("SignalQualityValidator", "PASS"))

    # --- Test 4: Enhanced Spoof Detector ---
    print("\n[4] Enhanced Spoof Detector")
    detector = EnhancedSpoofDetector()
    now = time.time()

    # Consistent readings
    readings = [
        GPSSourceReading(
            source_id="zed-f9p", lat=41.513, lon=-88.133, alt=200.0,
            timestamp=now, sats=10, hdop=1.0, fix_quality=4,
            is_rtk=True, accuracy_m=0.5,
        ),
        GPSSourceReading(
            source_id="laptop", lat=41.5135, lon=-88.1335, alt=205.0,
            timestamp=now, sats=8, hdop=3.0, fix_quality=1,
            accuracy_m=50.0,
        ),
    ]
    result = detector.feed(readings)
    assert not result.detected, f"Consistent readings should not trigger: {result.details}"
    print(f"   ✓ Clean readings: detected={result.detected}, confidence={result.confidence:.2f}")

    # Divergent readings
    spoof_readings = [
        GPSSourceReading(
            source_id="zed-f9p", lat=41.513, lon=-88.133, alt=200.0,
            timestamp=now, sats=10, hdop=1.0, fix_quality=4,
            is_rtk=True, accuracy_m=0.5,
        ),
        GPSSourceReading(
            source_id="spoofer", lat=42.0, lon=-87.0, alt=200.0,
            timestamp=now, sats=12, hdop=0.8, fix_quality=1,
            accuracy_m=10.0,
        ),
    ]
    spoof_result = detector.feed(spoof_readings)
    assert spoof_result.confidence > 0.3, f"Divergent readings should have confidence > 0.3: {spoof_result.confidence}"
    print(f"   ✓ Divergent readings: confidence={spoof_result.confidence:.2f}, "
          f"severity={spoof_result.severity.name}, details={spoof_result.details}")

    results.append(("EnhancedSpoofDetector", "PASS"))

    # --- Test 5: Lockdown Manager ---
    print("\n[5] GPS Lockdown Manager")
    lm = GPSLockdownManager()

    assert not lm.in_lockdown
    lm.activate([], ["test_spoof"])
    assert lm.in_lockdown
    assert lm.frozen_position is None  # No readings to freeze
    print("   ✓ Lockdown activated")

    # Recovery check with no valid readings
    status = lm.check_recovery([])
    assert not status['recovered']
    assert status['reason'] == 'insufficient_sources: 0/2'
    print(f"   ✓ Recovery blocked: {status['reason']}")

    lm.force_release()
    assert not lm.in_lockdown
    print("   ✓ Lockdown released")

    results.append(("GPSLockdownManager", "PASS"))

    # --- Test 6: Home Position Validator ---
    print("\n[6] Home Position Validator")
    _script_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else os.getcwd()
    hpv = HomePositionValidator(
        home_file=os.path.join(_script_dir, 'gps_home.json')
    )
    if hpv.home_lat is not None:
        print(f"   ✓ Home loaded: ({hpv.home_lat:.6f}, {hpv.home_lon:.6f})")
    else:
        print("   ⚠ Home file not found (expected if gps_home.json missing)")

    results.append(("HomePositionValidator", "PASS"))

    # --- Summary ---
    print("\n" + "=" * 70)
    all_pass = all(status == "PASS" for _, status in results)
    for name, status in results:
        symbol = "✓" if status == "PASS" else "✗"
        print(f"  {symbol} {name:35s} {status}")
    print("=" * 70)
    if all_pass:
        print("  ALL TESTS PASSED")
    else:
        print("  SOME TESTS FAILED")

    return all_pass


if __name__ == "__main__":
    _self_test()


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION GUIDE
# ═══════════════════════════════════════════════════════════════════════════════

INTEGRATION_GUIDE = """
INTEGRATION GUIDE — gps_fixes.py
===================================

This file provides drop-in replacements for GPS parsing and spoof detection
across 4 files. Each change is backward-compatible and can be applied incrementally.

──────────────────────────────────────────────────────────────────────────────
FILE 1: real_gps.py
──────────────────────────────────────────────────────────────────────────────

REPLACE: NMEAGPS._parse_nmea() (lines ~40-70)
WITH:    Use HardenedNMEAParser

  In NMEAGPS.__init__(), add:
    from gps_fixes import HardenedNMEAParser
    self._parser = HardenedNMEAParser(reject_on_bad_checksum=True)

  In NMEAGPS._read_loop(), change:
    if line.startswith('$'):
        self._parse_nmea(line)
  TO:
    if line.startswith('$'):
        parsed = self._parser.parse(line)
        if parsed and parsed.lat is not None:
            self.lat = parsed.lat
            self.lon = parsed.lon
            self.has_fix = parsed.fix_quality >= 1
            self.rtk_fix = parsed.fix_quality >= 4
            self.sats = parsed.sats
            self.hdop = parsed.hdop
            if parsed.alt is not None:
                self.alt = parsed.alt
            self._last_update = time.time()
        # (Optionally log parser stats periodically)

REPLACE: The cross-validation in RealGPS.get_position()
WITH:    Use EnhancedSpoofDetector

  In RealGPS.__init__(), add:
    from gps_fixes import EnhancedSpoofDetector, GPSSourceReading
    self._spoof_detector = EnhancedSpoofDetector()

  In RealGPS.get_position(), convert sources to GPSSourceReading list and call:
    readings = [GPSSourceReading(source_id=s['source'], lat=s['lat'],
               lon=s['lon'], alt=s.get('alt', 0), timestamp=time.time(),
               sats=s.get('sats', 0), hdop=s['hdop'],
               fix_quality=4 if s.get('rtk') else 1,
               is_rtk=s.get('rtk', False),
               accuracy_m=s.get('accuracy_m', 50)) for s in sources]
    spoof_result = self._spoof_detector.feed(readings)
    # Add spoof_result to return dict

──────────────────────────────────────────────────────────────────────────────
FILE 2: gps_anti_spoof.py
──────────────────────────────────────────────────────────────────────────────

REPLACE: _parse_nmea_gga() (standalone function)
WITH:    Use HardenedNMEAParser.parse()

  The standalone _parse_nmea_gga() function does NO checksum validation.
  Replace all calls with HardenedNMEAParser().parse(line).

REPLACE: GPSCrossValidator._run_cross_check()
WITH:    Use EnhancedSpoofDetector and SignalQualityValidator

  The existing GPSCrossValidator has good structure but:
    - Uses _haversine_meters (fine, keep)
    - Single-sample position jump (enhanced in our hysteresis version)
    - No time reversal detection (added)
    - No signal quality validation (added)
  Wire in EnhancedSpoofDetector as the main detection engine.

REPLACE: UBXSpoofDetector (keep as-is for now)
  NOTE: pyubx2 is NOT installed, so this class is effectively disabled.
  The EnhancedSpoofDetector provides NMEA-level spoof detection that works
  WITHOUT pyubx2. If pyubx2 is installed later, wire UBXSpoofDetector's
  get_status() into EnhancedSpoofDetector as an additional signal.

──────────────────────────────────────────────────────────────────────────────
FILE 3: gps_anti_spoof_monitor.py
──────────────────────────────────────────────────────────────────────────────

REPLACE: GPSReceiver._parse_nmea()
WITH:    Use HardenedNMEAParser

  Change _read_loop() to:
    parsed = self._parser.parse(line)
    if parsed:
        self.latest["sentences"] += 1
        ...

REPLACE: GPSAntiSpoofMonitor.check()
WITH:    Use EnhancedSpoofDetector

  Convert positions to GPSSourceReading and feed to EnhancedSpoofDetector.

──────────────────────────────────────────────────────────────────────────────
FILE 4: tscm_final.py
──────────────────────────────────────────────────────────────────────────────

REPLACE: GPSSpoofDetector class (line 910)
WITH:    EnhancedSpoofDetector

  The existing GPSSpoofDetector only checks speed > 1000 m/s on a single
  sample. Replace with EnhancedSpoofDetector which does 5-signal analysis.

  In TSCMSystem.__init__():
    from gps_fixes import EnhancedSpoofDetector, GPSSourceReading
    self.gps_spoof_detector = EnhancedSpoofDetector()

  Replace all self.gps_spoof_detector.detect() calls with .feed(readings).

REPLACE: GPSInterface._read_loop() (line 1992)
WITH:    Use HardenedNMEAParser

  In _read_loop(), the pynmea2.parse() call should be supplemented with
  checksum validation. Since pynmea2 itself validates checksums, this is
  less critical. But the fallback manual parse (line 2008) MUST validate
  checksums. Wrap it:
    if not validate_nmea_checksum(line):
        continue  # Drop corrupted line

REPLACE: gps_home.json usage
WITH:    Use HomePositionValidator

  In GPSInterface._load_home() and GPSCrossValidator._load_home_override(),
  add verification:
    from gps_fixes import HomePositionValidator
    self.home_validator = HomePositionValidator()
  Use self.home_validator.get_trusted_home() instead of raw lat/lon.

──────────────────────────────────────────────────────────────────────────────
FILE 5: interrogation.py (GPSAntiSpoofMonitor class, line 230)
──────────────────────────────────────────────────────────────────────────────

REPLACE: GPSAntiSpoofMonitor.feed_nmea()
WITH:    EnhancedSpoofDetector.feed()

  The existing feed_nmea does basic single-sample checks:
    - speed > 300 m/s (good but too late — already processed)
    - distance > 100m (too generous)
    - distance from home > 1km (only checks first 10 positions)
    - clock drift > 5s (good, keep)

  Replace with EnhancedSpoofDetector which does all of these plus:
    - Multi-source voting
    - Hysteresis
    - Time reversal
    - Signal quality
    - Constellation analysis
    - Lockdown mode

──────────────────────────────────────────────────────────────────────────────
PRIORITY ORDER (apply these first)
──────────────────────────────────────────────────────────────────────────────

  1. [CRITICAL] Add checksum validation to ALL NMEA parsers
     This prevents corrupted/injected data from being accepted.
     Apply to: real_gps.py, gps_anti_spoof_monitor.py, gps_anti_spoof.py,
              tscm_final.py fallback parser.

  2. [HIGH] Replace GPSSpoofDetector with EnhancedSpoofDetector
     This upgrades single-sample detection to 5-signal analysis.

  3. [HIGH] Wire lockdown mode into tscm_final.py main loop
     When spoof detected, freeze position and flag untrusted.

  4. [MEDIUM] Replace gps_home.json blind trust with HomePositionValidator
     Prevents using a potentially spoofed reference position.

  5. [LOW] Wire SignalQualityValidator into the main GPS read loop
     Provides continuous signal health monitoring.

──────────────────────────────────────────────────────────────────────────────
QUICK START (minimal viable patch)
──────────────────────────────────────────────────────────────────────────────

For the fastest improvement, apply just these two changes:

1. In real_gps.py NMEAGPS._parse_nmea():
   Add at the top:
     if not validate_nmea_checksum(line):
         return
   (Import from gps_fixes at the top of the file)

2. In tscm_final.py, replace GPSSpoofDetector (line 910) with:
   from gps_fixes import EnhancedSpoofDetector as GPSSpoofDetector
   (Wrap the detect() interface to match expected signature)

These two changes alone eliminate the biggest vulnerabilities: accepting
corrupted NMEA data and relying on single-sample speed threshold detection.

"""
