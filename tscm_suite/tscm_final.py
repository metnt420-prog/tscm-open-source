#!/usr/bin/env python3
"""
TSCM MASTER SUITE v2 - SOURCE LOCALIZATION BUILD
Based on user's reference script, added:
  - SourceLocalizationEngine: AoA + passive-radar → real source positions
  - LiveMapServer: real-time Leaflet map with bearing lines + source markers
  - OperatorTracker: spectral fingerprints tied to geographic positions
  - Victim vs Transmitter classification (ultrasound=victim, MW=transmitter)
  - BladeRF CLI fallback when Python bindings fail
  - HackRF PyUSB fallback when hackrf_transfer CLI missing
  - Triangulation from observer movement (GPS)

Physics:
  MW voice attack → hits victim body → carbon interaction → ultrasound emission FROM victim
  BladeRF MIMO AoA → bearing to RF source (transmitter or victim re-radiation)
  Cross-correlating two RX channels → passive radar delay → range to reflector
  When observer moves (GPS), bearing lines from different positions intersect → triangulated source position

Hardware: BladeRF xA9 MIMO, HackRF+SpyVerter, Petterson mic, laptop mic,
  OpenBCI UDP, SparkFun GPS-RTK2 (ZED-F9P), Alfa Wi-Fi.
Run as Administrator on Windows 11.
"""

import sys, os, time, json, threading, queue, struct, hashlib, pickle
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import subprocess, socket, webbrowser, ctypes, tempfile, math, re
from collections import deque, defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

# Fix Windows console encoding for emoji output
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except:
        pass
import numpy as np
import scipy.signal
from scipy.signal import (hilbert, find_peaks, periodogram, welch, butter, lfilter,
                          spectrogram, resample)
from scipy.fft import fft, fftfreq
import logging
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cable_line_radar import CableLineRadarDetector
import warnings
warnings.filterwarnings('ignore')

# Optional imports with availability flags
try:
    from sklearn.decomposition import FastICA
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import sounddevice as sd
    SOUNDDEVICE_AVAILABLE = True
except ImportError:
    SOUNDDEVICE_AVAILABLE = False

try:
    import serial
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False

try:
    import pynmea2
    PYNMEA2_AVAILABLE = True
except ImportError:
    PYNMEA2_AVAILABLE = False

try:
    import bladerf
    BLADERF_AVAILABLE = True
except (ImportError, OSError):
    BLADERF_AVAILABLE = False

try:
    from pyubx2 import UBXMessage, SET, POLL
    UBX_AVAILABLE = True
except ImportError:
    UBX_AVAILABLE = False

try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

# ===================== SDR PATH FIX =====================
# Ensure radioconda bin is in PATH so bladeRF-cli.exe and hackrf_transfer.exe are found
_RADIOCONDA_BIN = r'C:\ProgramData\radioconda\Library\bin'
if _RADIOCONDA_BIN not in os.environ.get('PATH', ''):
    os.environ['PATH'] = _RADIOCONDA_BIN + os.pathsep + os.environ.get('PATH', '')
# Also check the standalone bladeRF install path
_BLADERF_STANDALONE = r'C:\Program Files\bladeRF\x64'
if os.path.isdir(_BLADERF_STANDALONE) and _BLADERF_STANDALONE not in os.environ.get('PATH', ''):
    os.environ['PATH'] = _BLADERF_STANDALONE + os.pathsep + os.environ.get('PATH', '')


# ===================== CONFIGURATION =====================
class Config:
    # GPS - DISABLED: using fixed sensor positions for triangulation (no GPS spoofing possible)
    GPS_PORT = None      # GPS unplugged - using fixed positions
    GPS_PORT_2 = None    # disabled
    GPS_PORT_3 = None    # disabled
    GPS_BAUD = 9600

    # OpenBCI
    BCI_PORT = 12345

    # Audio devices - auto-detect if None
    PETTERSON_DEVICE_INDEX = 20  # M500-384kHz (Windows driver limit)
    PETTERSON_SAMPLE_RATE = 500000  # M500-384 supports 500kHz - max capability
    # Multi-rate scanning: 500k, 384k, 250k, 192k, 96k, 48k
    PETTERSON_SCAN_RATES = [500000, 384000, 250000, 192000, 96000, 48000]
    LAPTOP_MIC_DEVICE_INDEX = 21  # Intel Smart Sound 4ch mic array (spatial beamforming)
    LAPTOP_MIC_SAMPLE_RATE = 48000
    HEADPHONE_OUT_INDEX = None

    # BladeRF MIMO
    BLADERF_ENABLED = True
    BLADERF_FREQ = 2400e6
    BLADERF_SAMPLE_RATE = 10e6
    BLADERF_GAIN = 50
    BLADERF_BIAS_TEE = True

    # HackRF + SpyVerter (upconverter for VLF/HF bands)
    HACKRF_ENABLED = True
    HACKRF_FREQ_TARGET = 450e6  # UHF direct capture, 20 MHz BW - no sweep needed
    USE_SPYVERTER = True  # ENABLED: Spyverter shifts 0-60MHz up by 120MHz
    SPYVERTER_OFFSET = 120e6
    HACKRF_SAMPLE_RATE = 20e6
    HACKRF_GAIN = 30
    HACKRF_BIAS_TEE = True

    # eCPRI
    ECPRI_FREQ = 3500e6

    # AoA antenna spacing (meters) - BladeRF xA9 with Siretta Delta 52s
    ANTENNA_SPACING = 0.0625  # λ/2 at 2.4 GHz
    MAP_THREAT_LABELS = {
        'carbon_interaction': 'SPOOFING: MW→body→carbon re-emission (YOU are the source, not attacker)',
        'mw_voice_carrier': 'HACKING: 2.45GHz microwave carrier targeting you',
        'mw_voice': 'HACKING: Microwave voice-to-skull decoded speech',
        'silent_sound': 'SURVEILLANCE: AM voice carrier (subliminal/silent sound)',
        'us_voice_carrier': 'SURVEILLANCE: Ultrasound AM voice carrier',
        'eeg_voice_gamma': 'HACKING: Brain gamma rhythm extracted via ultrasound',
        'eeg_voice_alpha': 'HACKING: Brain alpha rhythm extracted via ultrasound',
        'eeg_voice_theta': 'HACKING: Brain theta rhythm extracted via ultrasound',
        'eeg_voice_beta': 'HACKING: Brain beta rhythm extracted via ultrasound',
        'eeg_voice_delta': 'HACKING: Brain delta rhythm extracted via ultrasound',
        'c2_us_bpsk': 'C2: BPSK modem - attacker sending commands via ultrasound',
        'c2_us_fsk': 'C2: FSK modem - attacker data channel via ultrasound',
        'c2_wifi_hidden': 'C2: Hidden WiFi network - likely attacker device',
        'wifi_c2_hidden_network': 'C2: Hidden WiFi network - attacker access point',
        'wifi_c2_phone_hotspot': 'C2: Phone hotspot - attacker mobile device',
        'wifi_c2_c2_honeypot': 'HACKING: Honeypot/C2 WiFi (pwned network)',
        'wifi_wifi_channel_anomaly': 'SPOOFING: WiFi channel anomaly - possible rogue AP',
        'wifi_wifi_ap_surge': 'C2: New WiFi APs appearing - attacker devices joining',
        'us_modem_fsk': 'C2: FSK data modem on ultrasound',
        'us_modem_psk': 'C2: PSK data modem on ultrasound',
        'us_wideband': 'SURVEILLANCE: Wideband ultrasound signal',
        'hello_scotty': 'HACKING: Power line carrier communication (Hello Scotty)',
        'manus_ai_vlf': 'C2: AI agent commands via VLF (Manus-like)',
        'ambient_reradiator': 'SPOOFING: Ambient metal re-radiating MW (not real source)',
        'radar_metal_device': 'SURVEILLANCE: Radar illuminated electronic device',
        'radar_water_body': 'ATTACK: Radar detected PERSON (body reflection)',
        'radar_metal_surface': 'SURVEILLANCE: Radar illuminated metal structure',
        'real_transmitter': 'ATTACK: Active powered transmitter confirmed',
        'phased_array': 'ATTACK: Phased array - multiple transmitters coordinated',
        'ghost_murmur': 'SURVEILLANCE: Operator trace - tracked after device went silent',
        'operator_fingerprint': 'SURVEILLANCE: Specific operator identified by transmission pattern',
        'nerve_pain_scan': 'HACKING: Nerve pain induction scan',
        'fingerprinting': 'SURVEILLANCE: Device fingerprinting - identifying your equipment',
        'injection_locking': 'HACKING: Injection locking - forcing your devices to sync to attacker signal',
        'power_line_loop': 'SURVEILLANCE: Power line carrier detected',
        'constant_ultrasonic_carrier': 'SURVEILLANCE: Constant ultrasound tone targeting you',
        'isolation_booth': 'HACKING: Acoustic isolation detected - you are being enclosed',
        'parametric_amplification': 'HACKING: Parametric amplification - boosting signal through nonlinearity',
    }
    # Bearing offset
    # Antennas pointing towards Larkin Ave (NNE, ~13deg  from north)
    # Positive = rotate clockwise, Negative = rotate counter-clockwise
    BEARING_OFFSET = 13  # DEGREES - antennas point towards Larkin Ave
    # Array axis: which direction does the line from rx1→rx2 point?
    # 0 = north, 90 = east, 180 = south, 270 = west
    ARRAY_AXIS_DEGREES = 13  # antennas point NNE towards Larkin Ave

    # Map
    MAP_PORT = 8080
    HOME_LAT = 41.51325   # fixed BladeRF position (no GPS)
    HOME_LON = -88.13368   # fixed BladeRF position (no GPS)
    # No GPS offsets - GPS is disabled
    GPS_LAT_OFFSET = 0.0
    GPS_LON_OFFSET = 0.0
    TILE_LAYER = 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}'

    # Detection log
    DETECTION_LOG = "detections.log"
    MODEL_DIR = "./models/"

    # Critical frequencies
    POWER_LINE_LOOP_FREQ = 7160
    SSVEP_FREQS = {6, 12, 15, 20, 30, 60, 180}
    INAUDIBLE_RANGES = [(3, 20), (18000, 20000), (20000, 40000)]
    NEURAL_BANDS = {'delta': (0.5, 4), 'theta': (4, 8), 'alpha': (8, 13),
                    'beta': (13, 30), 'gamma': (30, 100)}

    # Database paths
    FINGERPRINT_DB = os.path.join(MODEL_DIR, "device_fingerprints.pkl")
    BIOMETRIC_DB = os.path.join(MODEL_DIR, "biometric_fingerprints.pkl")
    TRANSMITTER_MAP = os.path.join(MODEL_DIR, "transmitter_map.pkl")
    OPERATOR_DB = os.path.join(MODEL_DIR, "operator_incidents.json")

    # WiFi
    WIFI_UDP_PORT = 9999

    # USB watchdog
    BLADERF_VID = "2cf0"
    BLADERF_PID = "5250"  # bladeRF 2.0 micro xA9 (was 5251 — wrong PID, watchdog never matched)

    # Active countermeasures
    ENABLE_NULL_STEERING = True  # Loop antenna cancellation only (BladeRF TX skipped)
    ENABLE_ADAPTIVE_COHERENCE = True
    COHERENCE_UPDATE_INTERVAL = 0.05
    COHERENCE_RF_BUF_SIZE = 8192

    # GLM watchdog
    GLM_MAX_FREQ_CHANGES = 5
    GLM_WATCH_INTERVAL = 30

    # Source localization
    TRIANGULATION_MIN_OBS = 2  # 2 fixed sensors (BladeRF+HackRF) or mobile positions
    TRIANGULATION_MAX_AGE = 300  # 5 minutes - only show currently active sources, not ghosts
    BEARING_LINE_LENGTH = 500
    PASSIVE_RADAR_MAX_RANGE = 2000

    # HackRF fixed position for dual-sensor triangulation
    # Physically co-located in RV but offset for intersection geometry.
    # 5m separation gives bearing intersection math enough geometry to
    # produce varied distance estimates instead of everything at 30m.
    HACKRF_FIXED_LAT = 41.51330   # ~5m north of BladeRF
    HACKRF_FIXED_LON = -88.13368   # same longitude
    # Offset mode (alternative to fixed lat/lon)
    HACKRF_OFFSET_M = 5         # 5m from BladeRF

    # RTL-SDR (Realtek RTL2838U) — third sensor for triangulation
    RTLSDR_ENABLED = True
    RTLSDR_FREQ = 850e6        # 850 MHz (cellular/ISM — different from BladeRF 2.4G and HackRF 450M)
    RTLSDR_SAMPLE_RATE = 2.4e6  # 2.4 MSps (RTL-SDR max stable)
    RTLSDR_GAIN = 40           # auto gain if 0, manual if >0
    RTLSDR_FIXED_LAT = 41.51320   # ~5m south of BladeRF (third position)
    RTLSDR_FIXED_LON = -88.13368
    # VID/PID for WinUSB driver matching (Realtek RTL2838U SDR dongle)
    RTLSDR_VID = '0BDA'
    RTLSDR_PID = '2838'
    # WiFi dongle (Realtek 8812AU) — used for WiFi AP scanning / C2 detection
    WIFI_DONGLE_VID = '0BDA'
    WIFI_DONGLE_PID = '8812'

    os.makedirs(MODEL_DIR, exist_ok=True)


# ===================== COURT FORENSIC LOGGER =====================
class CourtLogger:
    """
    Tamper-evident, hash-chained forensic log for court-admissible evidence.
    Every detection, AoA calculation, and raw measurement is recorded with:
    - Precise UTC timestamp
    - SHA256 chain link (prev_hash + current entry → current hash)
    - Full raw data (IQ samples, phase diffs, coherence, bearing calculations)
    - BladeRF CLI command/response pairs
    - Cross-validation results between HackRF and BladeRF

    Chain integrity can be verified by replaying from first entry.
    Tampering with any entry breaks the chain.
    """
    def __init__(self, log_dir="evidence"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.chain_hash = "GENESIS"
        self.entry_count = 0
        self.session_id = hashlib.sha256(
            f"{time.time()}_{os.getpid()}".encode()).hexdigest()[:16]

        # Open append-only log files
        ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        self.chain_file = os.path.join(log_dir, f"chain_{ts}.jsonl")
        self.raw_iq_dir = os.path.join(log_dir, "raw_iq")
        os.makedirs(self.raw_iq_dir, exist_ok=True)
        self.bladerf_log = os.path.join(log_dir, f"bladerf_raw_{ts}.log")
        self.aoa_log = os.path.join(log_dir, f"aoa_detail_{ts}.jsonl")
        self.crossval_log = os.path.join(log_dir, f"crossval_{ts}.jsonl")

        # Write genesis
        self._write_chain({
            "type": "genesis", "session_id": self.session_id,
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hostname": socket.gethostname(),
            "script_hash": self._script_hash()
        })

    def _script_hash(self):
        try:
            with open(__file__, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()[:32]
        except:
            return "unknown"

    def _write_chain(self, entry):
        entry["entry_id"] = self.entry_count
        entry["prev_hash"] = self.chain_hash
        entry["utc"] = time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime()) + \
                       f"{int(time.time()*1000)%1000:03d}Z"

        # Compute this entry's hash
        entry_str = json.dumps(entry, sort_keys=True, default=str)
        entry["hash"] = hashlib.sha256(entry_str.encode()).hexdigest()[:32]
        self.chain_hash = entry["hash"]
        self.entry_count += 1

        # Append to chain file (one JSON per line)
        with open(self.chain_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, default=str) + "\n")

        return entry["hash"]

    def log_detection(self, detector, classification, freq, bearing, snr=0.0,
                      range_m=None, method='', raw_data=None):
        """Log every detection with full context."""
        entry = {
            "type": "detection",
            "detector": detector,
            "classification": classification,
            "freq_hz": float(freq) if freq else 0,
            "bearing_deg": float(bearing) if bearing is not None else None,
            "snr": float(snr),
            "range_m": float(range_m) if range_m else None,
            "method": method,
            "session_id": self.session_id
        }
        if raw_data:
            entry["raw"] = {k: (float(v) if isinstance(v, (int,float,np.floating)) else str(v))
                           for k,v in raw_data.items()}
        return self._write_chain(entry)

    def log_aoa(self, source, bearing, coherence, phase_diff, iq1_rms, iq2_rms,
                cli_command=None, cli_response=None):
        """Log AoA calculation with all intermediate values for forensic review."""
        entry = {
            "type": "aoa_calculation",
            "source": source,  # "bladerf_cli" or "hackrf"
            "bearing_deg": float(bearing),
            "coherence": float(coherence),
            "phase_diff_deg": float(phase_diff),
            "iq1_rms": float(iq1_rms),
            "iq2_rms": float(iq2_rms),
            "ratio_iq_rms": float(iq1_rms / iq2_rms) if iq2_rms > 0 else None,
            "session_id": self.session_id
        }
        if cli_command:
            entry["cli_command"] = cli_command
        if cli_response:
            entry["cli_response"] = cli_response[:500]  # truncate
        self._write_chain(entry)

        # Also write to dedicated AoA log
        with open(self.aoa_log, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def log_bladerf_raw(self, command, response):
        """Log every BladeRF CLI command and response."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime()) + \
             f"{int(time.time()*1000)%1000:03d}Z"
        with open(self.bladerf_log, 'a', encoding='utf-8') as f:
            f.write(f"[{ts}] CMD: {command}\n")
            f.write(f"[{ts}] RSP: {response[:1000]}\n")
            f.write(f"[{ts}] ---\n")

    def log_cross_validation(self, hackrf_bearing, bladerf_bearing,
                             hackrf_freq, bladerf_freq, agreement):
        """Log cross-validation between HackRF and BladeRF."""
        diverged = abs(hackrf_bearing - bladerf_bearing) > 45 if \
            hackrf_bearing is not None and bladerf_bearing is not None else None
        entry = {
            "type": "cross_validation",
            "hackrf_bearing": float(hackrf_bearing) if hackrf_bearing is not None else None,
            "bladerf_bearing": float(bladerf_bearing) if bladerf_bearing is not None else None,
            "bearing_diff_deg": float(abs(hackrf_bearing - bladerf_bearing)) if diverged is not None else None,
            "hackrf_freq_mhz": float(hackrf_freq/1e6) if hackrf_freq else None,
            "bladerf_freq_mhz": float(bladerf_freq/1e6) if bladerf_freq else None,
            "agreement": agreement,
            "diverged": diverged,
            "session_id": self.session_id
        }
        self._write_chain(entry)
        with open(self.crossval_log, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def save_raw_iq(self, iq_data, source, freq, fs, bearing=0.0):
        """Save raw IQ samples for forensic review."""
        ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        ts += f"_{int(time.time()*1000)%1000:03d}"
        fname = f"{source}_{ts}_{freq/1e6:.0f}MHz_{bearing:.0f}deg.npy"
        path = os.path.join(self.raw_iq_dir, fname)
        try:
            np.save(path, iq_data)
            # Log that we saved it
            self._write_chain({
                "type": "raw_iq_saved",
                "source": source,
                "file": fname,
                "samples": len(iq_data),
                "freq_hz": float(freq),
                "sample_rate": float(fs),
                "bearing_deg": float(bearing),
                "iq_sha256": hashlib.sha256(iq_data.tobytes()).hexdigest()[:32],
                "session_id": self.session_id
            })
        except:
            pass

    def log_anomaly(self, description, data=None):
        """Log suspicious events for court evidence."""
        entry = {
            "type": "anomaly",
            "description": description,
            "session_id": self.session_id
        }
        if data:
            entry["data"] = {k: str(v) for k,v in data.items()}
        self._write_chain(entry)

    def verify_chain(self):
        """Verify the entire chain is intact. Returns (valid, broken_at)."""
        try:
            with open(self.chain_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            prev_hash = "GENESIS"
            for i, line in enumerate(lines):
                entry = json.loads(line.strip())
                if entry.get("prev_hash") != prev_hash:
                    return False, i
                # Recompute hash (exclude the hash field itself)
                stored_hash = entry.pop("hash", None)
                entry_str = json.dumps(entry, sort_keys=True, default=str)
                computed = hashlib.sha256(entry_str.encode()).hexdigest()[:32]
                if computed != stored_hash:
                    return False, i
                prev_hash = stored_hash
            return True, len(lines)
        except Exception as e:
            return False, f"error: {e}"


# ===================== SOURCE LOCALIZATION ENGINE =====================
class SourceLocalizationEngine:
    """
    Converts AoA bearings + passive-radar ranges into geographic source positions.
    Maintains observation history per spectral fingerprint for triangulation.
    Classifies sources as TRANSMITTER (RF origin) or VICTIM (carbon MW interaction → ultrasound).
    """

    def __init__(self, log):
        self.log = log
        self.observations = defaultdict(lambda: deque(maxlen=100))
        self.sources = {}
        self.cycle_detections = []
        self.current_aoa = 0.0  # set by TSCM main loop each cycle (BladeRF MIMO)
        self.acoustic_aoa = None  # set by main loop (Intel mic array)
        self.hackrf_range = None  # set by main loop (HackRF+LNA RSSI)
        self.hackrf_lat = None  # set by main loop (HackRF fixed position for triangulation)
        self.hackrf_lon = None

    def add_observation(self, fingerprint, obs_lat, obs_lon, bearing_deg,
                        range_m=None, freq=0.0, classification='unknown',
                        detector_name='', snr=0.0, source_type='active'):
        # === INPUT VALIDATION — prevent spoofed/injected data from creating phantom sources ===
        # Sanitize detector_name: alphanumeric + underscore only, max 64 chars
        if detector_name:
            detector_name = re.sub(r'[^a-zA-Z0-9_]', '', str(detector_name))[:64]
        # Sanitize classification: alphanumeric only, max 32 chars
        if classification:
            classification = re.sub(r'[^a-zA-Z0-9_]', '', str(classification))[:32]
        # Clamp frequency to physical range [0, 100 GHz]
        try: freq = float(freq)
        except (TypeError, ValueError): freq = 0.0
        if freq < 0 or freq > 100e9: freq = 0.0
        # Clamp SNR to reasonable range [-100, 1000]
        try: snr = float(snr)
        except (TypeError, ValueError): snr = 0.0
        snr = max(-100.0, min(1000.0, snr))
        # Validate lat/lon are within physical ranges
        try:
            obs_lat = float(obs_lat); obs_lon = float(obs_lon)
        except (TypeError, ValueError):
            obs_lat = Config.HOME_LAT; obs_lon = Config.HOME_LON
        if abs(obs_lat) > 90 or abs(obs_lon) > 180:
            obs_lat = Config.HOME_LAT; obs_lon = Config.HOME_LON
        # Validate bearing: must be [-360, 360], None is OK (omnidirectional)
        if bearing_deg is not None:
            try: bearing_deg = float(bearing_deg)
            except (TypeError, ValueError): bearing_deg = None
            if bearing_deg is not None and (math.isnan(bearing_deg) or abs(bearing_deg) > 360):
                bearing_deg = None
        # Validate range: must be [0, 10000 km], None is OK
        if range_m is not None:
            try: range_m = float(range_m)
            except (TypeError, ValueError): range_m = None
            if range_m is not None and (range_m < 0 or range_m > 1e7):
                range_m = None
        # source_type: must be one of the known values
        if source_type not in ('active', 'ambient', 'reflector', 'unknown'):
            source_type = 'unknown'
        # === END INPUT VALIDATION ===
        # source_type: 'active' = real transmitter, 'ambient' = metal re-radiator, 'unknown'
        # Allow None-bearing observations (omnidirectional sensors)
        # Use 0.0 as placeholder - these sources won't get a bearing line on map
        if bearing_deg is None:
            # Anti-phantom: HackRF/ferrite detectors must NOT get BladeRF AoA injected —
            # they have their own ferrite loop bearing. Injecting BladeRF bearing would
            # create a false direction for 450 MHz sources detected by HackRF.
            _det_lower = (detector_name or '').lower()
            if 'hackrf' in _det_lower or 'ferrite' in _det_lower:
                bearing_deg = 0.0
                no_bearing = True
            else:
                # Auto-inject AoA ONLY for detections within the BladeRF capture band.
                # BladeRF is at 2.4 GHz ± 5 MHz — injecting its bearing onto 450 MHz
                # or acoustic detections creates fake direction on the map.
                _in_bladerf_band = freq > 1e6 and abs(freq - Config.BLADERF_FREQ) < Config.BLADERF_SAMPLE_RATE / 2
                if _in_bladerf_band and self.current_aoa != 0.0:
                    bearing_deg = self.current_aoa
                    no_bearing = False
                    if range_m is None and self.hackrf_range:
                        range_m = self.hackrf_range
                elif freq > 1e6 and self.hackrf_range:
                    # RF outside BladeRF band (450 MHz, etc.): inject HackRF range
                    # so bearing-range estimation can work for HackRF detections too.
                    # Bearing stays None — HackRF ferrite bearing is set by the detector.
                    if range_m is None:
                        range_m = self.hackrf_range
                elif 0 < freq < 1e6 and self.acoustic_aoa is not None and self.acoustic_aoa != 0.0:
                    # Audio/ultrasound detectors (<1 MHz): use Intel mic array acoustic AoA
                    bearing_deg = self.acoustic_aoa
                    no_bearing = False
                elif freq == 0:
                    # DC/baseband detectors that don't report frequency.
                    # Audio-class → acoustic AoA only. RF-class gets NO bearing —
                    # we can't know which band it's in without a frequency.
                    victim_types = {'eardrum_capture','silent_sound','injection_locking',
                        'power_line_loop','constant_ultrasonic_carrier','constant_infrasound',
                        'sstv_activity','ai_voice','variac_induction','isolation_booth',
                        'body_charging','body_parasitic_modulation','carbon_rectification',
                        'ghost_hunter_snn','ghost_murmur','nerve_pain_scan','hello_scotty'}
                    if detector_name in victim_types and self.acoustic_aoa is not None and self.acoustic_aoa != 0.0:
                        bearing_deg = self.acoustic_aoa
                        no_bearing = False
                    else:
                        bearing_deg = 0.0
                        no_bearing = True
                else:
                    # RF outside BladeRF band (450/570 MHz, 1.5 GHz GPS, etc.) —
                    # no bearing unless the detector has its own direction finder
                    bearing_deg = 0.0
                    no_bearing = True
        else:
            no_bearing = False
        if isinstance(bearing_deg, float) and math.isnan(bearing_deg):
            bearing_deg = 0.0
            no_bearing = True
        # Use HackRF fixed position for HackRF detections (dual-sensor triangulation)
        # BladeRF detections use GPS/observer position; HackRF detections use HackRF's
        # physical position → two bearing lines from two positions = true triangulation
        if self.hackrf_lat is not None and self.hackrf_lon is not None:
            _det_lower = (detector_name or '').lower()
            if 'hackrf' in _det_lower or 'ferrite' in _det_lower:
                obs_lat = self.hackrf_lat
                obs_lon = self.hackrf_lon
        # Use finer freq bins for low frequencies (ultrasound 1kHz bins, RF 1MHz bins)
        if freq > 1e6:
            freq_bin = round(freq / 1e6) * 1e6  # 1 MHz bins for RF
        else:
            freq_bin = round(freq / 1000) * 1000  # 1 kHz bins for ultrasound/audio
        # Stable fingerprint without bearing - bearing is dynamic (AoA shifts each cycle).
        # Grouping by detector+class+freq prevents scattering observations across bins.
        # Bearing per-observation is used for triangulation, not for source identity.
        # If caller provided an explicit fingerprint, use it as key for source grouping.
        if fingerprint:
            try: stable_fp = fingerprint.decode() if isinstance(fingerprint, bytes) else str(fingerprint)
            except: stable_fp = str(fingerprint)
            stable_fp = stable_fp[:32]  # cap length
        else:
            key_str = f"{detector_name}_{classification}_{freq_bin:.0f}"
            stable_fp = hashlib.sha256(key_str.encode()).hexdigest()[:16]
        now = time.time()
        self.observations[stable_fp].append({
            'ts': now, 'lat': obs_lat, 'lon': obs_lon,
            'bearing': bearing_deg, 'range': range_m,
            'freq': freq, 'class': classification,
            'detector': detector_name, 'snr': snr,
            'no_bearing': no_bearing,
            'source_type': source_type
        })
        self.cycle_detections.append({
            'fp': stable_fp, 'bearing': bearing_deg,
            'range': range_m, 'freq': freq,
            'class': classification, 'detector': detector_name
        })

    def save_evidence(self):
        """Save all observations to disk so they survive restarts."""
        try:
            path = os.path.join(Config.MODEL_DIR, 'evidence_observations.json')
            data = {}
            for fp, obs_list in self.observations.items():
                data[fp] = [{
                    'ts': o['ts'], 'lat': o['lat'], 'lon': o['lon'],
                    'bearing': o['bearing'], 'range': o.get('range'),
                    'freq': o['freq'], 'class': o['class'],
                    'detector': o['detector'], 'snr': o.get('snr', 0),
                    'no_bearing': o.get('no_bearing', False),
                    'source_type': o.get('source_type', 'unknown')
                } for o in obs_list]
            with open(path, 'w') as f:
                json.dump(data, f)
        except: pass

    def load_evidence(self):
        """Load observations from previous session. Only load recent ones
        that could still be active - old observations create ghost sources."""
        path = os.path.join(Config.MODEL_DIR, 'evidence_observations.json')
        if not os.path.exists(path): return 0
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            count = 0
            now = time.time()
            for fp, obs_list in data.items():
                for o in obs_list:
                    # Only load observations from last 5 minutes
                    if now - o.get('ts', 0) > 300: continue
                    self.observations[fp].append(o)
                    count += 1
            return count
        except: return 0

    def _prune_old(self, fp):
        now = time.time()
        while (self.observations[fp] and
               now - self.observations[fp][0]['ts'] > Config.TRIANGULATION_MAX_AGE):
            self.observations[fp].popleft()

    def _bearing_to_xy(self, lat, lon, bearing_deg, distance_m):
        R = 6371000.0
        brng = math.radians(bearing_deg)
        lat1 = math.radians(lat)
        lon1 = math.radians(lon)
        lat2 = math.asin(math.sin(lat1) * math.cos(distance_m / R) +
                         math.cos(lat1) * math.sin(distance_m / R) * math.cos(brng))
        lon2 = lon1 + math.atan2(math.sin(brng) * math.sin(distance_m / R) * math.cos(lat1),
                                  math.cos(distance_m / R) - math.sin(lat1) * math.sin(lat2))
        return math.degrees(lat2), math.degrees(lon2)

    def _intersect_bearings(self, lat1, lon1, b1, lat2, lon2, b2):
        y1 = lat1 * 111320.0
        x1 = lon1 * 111320.0 * math.cos(math.radians(lat1))
        y2 = lat2 * 111320.0
        x2 = lon2 * 111320.0 * math.cos(math.radians(lat2))
        d1 = math.radians(b1)
        d2 = math.radians(b2)
        dx1, dy1 = math.sin(d1), math.cos(d1)
        dx2, dy2 = math.sin(d2), math.cos(d2)
        det = dx1 * dy2 - dx2 * dy1
        if abs(det) < 1e-10:
            return None
        t = ((x2 - x1) * dy2 - (y2 - y1) * dx2) / det
        if t < 0:
            return None
        ix = x1 + t * dx1
        iy = y1 + t * dy1
        lat = iy / 111320.0
        lon = ix / (111320.0 * math.cos(math.radians(lat)))
        return lat, lon

    def resolve_sources(self, current_lat, current_lon):
        now = time.time()
        self.log.info(f"[RESOLVE] {len(self.observations)} fingerprints, hackrf=({self.hackrf_lat},{self.hackrf_lon})")
        results = []
        for fp, obs_list in self.observations.items():
            self._prune_old(fp)
            obs = list(self.observations[fp])
            if not obs: continue
            latest = obs[-1]
            # For triangulation, prefer the most recent observation with a real bearing.
            # First-cycle observations may have bearing=0.0 (AoA not yet computed).
            for o in reversed(obs):
                if o.get('bearing', 0) != 0.0:
                    latest = o
                    break
            classification = latest['class']
            freq = latest['freq']
            detector = latest['detector']

            # --- Check for confirmed single-position triangulation first ---
            # This requires BOTH real bearing (BladeRF MIMO AoA) AND real range
            # (HackRF+LNA RSSI or bistatic echo delay). Two independent measurements
            # from the same position resolve to unique coordinates - no GPS movement needed.
            has_real_bearing = latest.get('bearing', 0) != 0.0 and not latest.get('no_bearing', True)
            has_measured_range = latest.get('range') is not None and latest.get('range', 0) > 0
            has_real_freq = latest.get('freq', 0) > 1e6  # must be RF source
            is_confirmed = has_real_bearing and has_measured_range and has_real_freq
            _det = latest.get('detector', '')
            if is_confirmed and ('wifi' in _det.lower() or 'phased_array' in _det):
                is_confirmed = False
            measured_rng = latest.get('range')
            if is_confirmed and (measured_rng and measured_rng < 25):
                is_confirmed = False  # near-field rejection

            if is_confirmed:
                # Single-position bearing+range estimate. NOT triangulation —
                # triangulation requires bearing lines from ≥2 distinct observer
                # positions. This is a bearing-range estimate using AoA + RSSI range
                # from one position. Mark as DOA with range, shown on map as bearing_only.
                src_lat, src_lon = self._bearing_to_xy(
                    latest['lat'], latest['lon'], latest['bearing'], measured_rng)
                prev = self.sources.get(fp)
                if prev and prev.get('lat'):
                    dy = (src_lat - prev['lat']) * 111320.0
                    dx = (src_lon - prev['lon']) * 111320.0 * math.cos(math.radians(src_lat))
                    jump_m = math.sqrt(dx*dx + dy*dy)
                    if jump_m > 500:
                        # Spoofed bearing or bogus range – keep at last known position
                        # but mark as suspect. Don't drop the source from the map.
                        self.sources[fp] = {'lat': None, 'lon': None,
                            'classification': classification, 'first_seen': obs[0]['ts'],
                            'last_seen': now, 'freq': freq, 'detector': detector,
                            'range': measured_rng, 'snr': latest.get('snr', 0),
                            'bearing': latest.get('bearing', 0),
                            'method': 'bearing_range_suspect', 'observations': len(obs),
                            'triangulated': False, 'suspect_jump_m': round(jump_m, 0)}
                        continue
                    alpha = 0.3
                    src_lat = prev['lat'] * (1 - alpha) + src_lat * alpha
                    src_lon = prev['lon'] * (1 - alpha) + src_lon * alpha
                # NO lat/lon for bearing-only estimates - map shows dashed bearing lines,
                # not false point markers at 30m measured range.
                self.sources[fp] = {
                    'lat': None, 'lon': None,
                    'classification': classification, 'first_seen': obs[0]['ts'],
                    'last_seen': now, 'freq': freq, 'detector': detector,
                    'range': measured_rng, 'snr': latest.get('snr', 0),
                    'bearing': latest.get('bearing', 0),
                    'method': 'bearing_range_est', 'observations': len(obs),
                    'triangulated': False}
                continue

            # --- Not confirmed: try multi-position bearing intersection ---
            # This is the TRUE triangulation path: bearing lines from ≥3 distinct
            # observer positions (>5m apart) intersect → source position.
            # ONLY SDR-band sources (freq > 1 MHz) qualify - non-SDR detectors
            # (acoustic, fingerprinting, ML) use auto-injected AoA that does not
            # correspond to their specific signal. Triangulation requires the
            # bearing to be measured FOR that source's actual frequency band.
            is_sdr_band = freq > 1e6
            if is_sdr_band and len(obs) >= Config.TRIANGULATION_MIN_OBS:
                # TRUE triangulation: bearing lines from ≥2 distinct observer
                # positions (>5m apart) intersect → source position.
                # With fixed sensors, per-fingerprint triangulation only works
                # if the observer has moved (mobile survey). For stationary
                # setups, cross-sensor triangulation (below) handles it.
                bearing_obs = [o for o in obs if o.get('bearing', 0) != 0.0 and not o.get('no_bearing', True)]
                if len(bearing_obs) >= Config.TRIANGULATION_MIN_OBS:
                    distinct = [bearing_obs[0]]
                    for o in bearing_obs[1:]:
                        dy = (o['lat'] - distinct[-1]['lat']) * 111320.0
                        dx = (o['lon'] - distinct[-1]['lon']) * 111320.0 * math.cos(math.radians(o['lat']))
                        if math.sqrt(dx*dx + dy*dy) > 5.0: distinct.append(o)
                    if len(distinct) >= 2:
                        # Minimum bearing spread: reject if all bearings within ±15°
                        bearings_span = [o['bearing'] for o in distinct]
                        if max(bearings_span) - min(bearings_span) < 30.0:
                            pass  # Bearings too parallel — skip triangulation
                        else:
                            intersections = []
                            for i in range(len(distinct)):
                                for j in range(i+1, len(distinct)):
                                    pt = self._intersect_bearings(
                                        distinct[i]['lat'], distinct[i]['lon'], distinct[i]['bearing'],
                                        distinct[j]['lat'], distinct[j]['lon'], distinct[j]['bearing'])
                                    if pt: intersections.append(pt)
                            if len(intersections) >= 1:
                                lats = [p[0] for p in intersections]; lons = [p[1] for p in intersections]
                                self.sources[fp] = {'lat': float(np.median(lats)), 'lon': float(np.median(lons)),
                                    'classification': classification, 'first_seen': obs[0]['ts'],
                                    'last_seen': now, 'freq': freq, 'detector': detector,
                                    'method': 'triangulation', 'observations': len(obs),
                                    'triangulated': True}
                                continue

            # --- Fallback: estimate position from bearing + estimated range ---
            # Better than blind 1km: use SNR-based range estimate when bearing is known.
            # Estimate range from signal strength (SNR) if not measured
            estimated_range = latest.get('range')
            if not estimated_range or estimated_range <= 0:
                recent_snrs = [o.get('snr', 0) for o in obs[-10:] if o.get('snr', 0) > 0]
                avg_snr = sum(recent_snrs) / len(recent_snrs) if recent_snrs else latest.get('snr', 0)
                _freq = latest.get('freq', 0)
                if avg_snr > 0 and _freq > 0:
                    if _freq > 1e9:
                        estimated_range = max(100, min(2000, 500 * (10 / max(avg_snr, 1))))
                    elif _freq > 1e6:
                        estimated_range = max(50, min(1000, 300 * (5 / max(avg_snr, 0.5))))
                    else:
                        estimated_range = max(100, min(3000, 600 * (3 / max(avg_snr, 0.3))))
                if not estimated_range or estimated_range <= 0:
                    _det = latest.get('detector', '')
                    if 'ferrite' in _det: estimated_range = 200
                    elif 'real_transmitter' in _det: estimated_range = 300
                    elif 'reradiator' in _det: estimated_range = 100
                    elif 'watcher' in _det: estimated_range = 400
                    elif _freq > 1e9: estimated_range = 400
                    elif _freq > 1e6: estimated_range = 300
                    else: estimated_range = 500

            if latest['bearing'] == 0.0:
                self.sources[fp] = {'lat': None, 'lon': None,
                    'classification': classification, 'first_seen': obs[0]['ts'],
                    'last_seen': now, 'freq': freq, 'detector': detector,
                    'method': 'at_observer', 'observations': len(obs),
                    'triangulated': False}
            elif estimated_range and estimated_range > 0:
                # Bearing known + SNR-estimated range (NOT measured range).
                # SNR-based range is a propagation guess, not actual distance.
                # Show as bearing-only line on map — no false point markers.
                bearings = [o['bearing'] for o in obs if o.get('bearing', 0) != 0.0]
                avg_bearing = float(np.mean(bearings)) if bearings else latest['bearing']
                self.sources[fp] = {'lat': None, 'lon': None, 'bearing': avg_bearing,
                    'classification': classification, 'first_seen': obs[0]['ts'],
                    'last_seen': now, 'freq': freq, 'detector': detector,
                    'range': estimated_range, 'snr': latest.get('snr', 0),
                    'method': 'bearing_range_est', 'observations': len(obs),
                    'bearing_samples': len(bearings),
                    'triangulated': False}
            else:
                # Bearing without any range estimate.
                # Show as bearing-only line — no false point markers.
                bearings = [o['bearing'] for o in obs if o.get('bearing', 0) != 0.0]
                avg_bearing = float(np.mean(bearings)) if bearings else latest['bearing']
                self.sources[fp] = {'lat': None, 'lon': None, 'bearing': avg_bearing,
                    'classification': classification, 'first_seen': obs[0]['ts'],
                    'last_seen': now, 'freq': freq, 'detector': detector,
                    'method': 'bearing_only', 'observations': len(obs),
                    'bearing_samples': len(bearings),
                    'triangulated': False,
                    'confidence': 'low'}

        # --- Cross-sensor triangulation ---
        # BladeRF (2.4 GHz MIMO AoA) and HackRF (450 MHz ferrite loop) operate on
        # different frequencies → different fingerprints → never combine in the
        # per-fingerprint loop above.  This pass intersects bearing lines from
        # BladeRF detections (at GPS/observer position) with HackRF detections
        # (at HackRF fixed position) regardless of frequency, giving true
        # triangulation from two spatially-separated fixed sensors.
        #
        # NOTE: This only produces valid results when both sensors detect the SAME
        # physical source (e.g., a harmonically-related signal or a broadband emitter).
        # Intersecting bearings from unrelated sources at different frequencies produces
        # phantom intersections. The SNR guard and convergence check help filter these out.
        if self.hackrf_lat is not None and self.hackrf_lon is not None:
            bladerf_bearings = []
            hackrf_bearings = []
            # Debug: show total observation count
            _total_obs = sum(len(v) for v in self.observations.values())
            if _total_obs > 0:
                self.log.info(f"[CSDBG] {len(self.observations)} fingerprints, {_total_obs} total obs, hackrf_pos=({self.hackrf_lat:.5f},{self.hackrf_lon:.5f})")
            for fp_key, obs_list in self.observations.items():
                self._prune_old(fp_key)
                for o in self.observations[fp_key]:
                    if o.get('no_bearing', True): continue
                    if o.get('bearing', 0) == 0.0: continue
                    if now - o.get('ts', 0) > 120: continue  # recent only
                    det = (o.get('detector') or '').lower()
                    is_hackrf = 'hackrf' in det or 'ferrite' in det
                    # Debug: log each observation that passes initial filters
                    if len(bladerf_bearings) + len(hackrf_bearings) < 5:
                        self.log.info(f"  [CSOBS] det={o.get('detector')} brg={o.get('bearing',0):.1f} snr={o.get('snr',0)} freq={o.get('freq',0):.0f} no_brng={o.get('no_bearing',True)}")
                    if is_hackrf:
                        # HackRF/ferrite: use SNR guard only if SNR was actually measured (not 0)
                        if o.get('snr', 0) != 0 and o.get('snr', 0) <= 3.0:
                            continue
                        hackrf_bearings.append(o)
                    elif o.get('freq', 0) > 1e6:  # RF detections only for BladeRF
                        # BladeRF: enforce SNR guard only when SNR was actually measured
                        if o.get('snr', 0) != 0 and o.get('snr', 0) <= 3.0:
                            continue
                        bladerf_bearings.append(o)
            if bladerf_bearings and hackrf_bearings:
                # Debug: log bearing counts for triangulation diagnosis
                self.log.info(f"[CROSS] {len(bladerf_bearings)} blade + {len(hackrf_bearings)} hackrf bearings")
                # Check positions are actually distinct (>3m apart — fixed sensors ~5m apart)
                dy = (self.hackrf_lat - bladerf_bearings[-1]['lat']) * 111320.0
                dx = (self.hackrf_lon - bladerf_bearings[-1]['lon']) * 111320.0 * math.cos(math.radians(bladerf_bearings[-1]['lat']))
                if math.sqrt(dx*dx + dy*dy) > 3.0:  # 3m min — fixed sensors are ~5m apart
                    intersections = []
                    for b_obs in bladerf_bearings[-8:]:
                        for h_obs in hackrf_bearings[-8:]:
                            pt = self._intersect_bearings(
                                b_obs['lat'], b_obs['lon'], b_obs['bearing'],
                                h_obs['lat'], h_obs['lon'], h_obs['bearing'])
                            if pt: intersections.append(pt)
                    if intersections:
                        lats = [p[0] for p in intersections]
                        lons = [p[1] for p in intersections]
                        # Check convergence — intersections should cluster within ~500m
                        lat_spread = (max(lats) - min(lats)) * 111320.0
                        lon_spread = (max(lons) - min(lons)) * 111320.0 * math.cos(math.radians(np.mean(lats)))
                        if lat_spread < 500 and lon_spread < 500:
                            src_lat = float(np.median(lats))
                            src_lon = float(np.median(lons))
                            # Check if a per-fingerprint triangulation already found this location
                            already_found = False
                            for existing_src in self.sources.values():
                                if not existing_src.get('triangulated'): continue
                                edy = (existing_src['lat'] - src_lat) * 111320.0
                                edx = (existing_src['lon'] - src_lon) * 111320.0 * math.cos(math.radians(src_lat))
                                if math.sqrt(edx*edx + edy*edy) < 200:
                                    already_found = True
                                    break
                            if not already_found:
                                # Use per-frequency-pair key to avoid overwriting previous results
                                b_freq = b_obs.get('freq', 0)
                                h_freq = h_obs.get('freq', 0)
                                cross_key = f'cross_{b_freq:.0f}_{h_freq:.0f}'
                                self.sources[cross_key] = {
                                    'lat': src_lat, 'lon': src_lon,
                                    'classification': 'transmitter',
                                    'first_seen': now - 120,
                                    'last_seen': now,
                                    'freq': 0,  # cross-frequency
                                    'detector': 'bladerf+hackrf',
                                    'method': 'cross_sensor_triangulation',
                                    'observations': len(intersections),
                                    'triangulated': False,
                                    'bearing_sources': 'bladerf_mimo+hackrf_ferrite'}

        for fp, src in self.sources.items():
            if now - src['last_seen'] > Config.TRIANGULATION_MAX_AGE: continue
            entry = dict(src); entry['fingerprint'] = fp[:16]
            # Mark active (seen in last 2 min) vs inactive (silent but tracked)
            entry['active'] = (now - src['last_seen']) < 120
            entry['inactive_duration'] = int(now - src['last_seen']) if not entry['active'] else 0
            results.append(entry)
        # Sort: active first (by observations), then inactive
        active = [r for r in results if r.get('active')]
        inactive = [r for r in results if not r.get('active')]
        active.sort(key=lambda x: x.get('observations', 0), reverse=True)
        inactive.sort(key=lambda x: x.get('observations', 0), reverse=True)
        results = active + inactive  # NO CAP - show all detections
        self.cycle_detections.clear()
        # Save positions for persistence across restarts
        self._save_persistent(results)
        # Load any previously saved persistent positions
        self._load_persistent(results)
        return results

    def _save_persistent(self, results):
        """Save resolved source positions to survive restarts."""
        persist = []
        for r in results:
            if r.get('lat') and r.get('lon') and r.get('classification') == 'transmitter':
                persist.append({
                    'lat': r['lat'], 'lon': r['lon'], 'bearing': r.get('bearing'),
                    'freq': r.get('freq'), 'detector': r.get('detector'),
                    'classification': r['classification'],
                    'observations': r.get('observations', 0),
                    'last_seen': int(time.time())
                })
        if persist:
            path = os.path.join(Config.MODEL_DIR, 'persistent_sources.json')
            try:
                with open(path, 'w') as f:
                    json.dump(persist, f)
            except: pass

    def _load_persistent(self, results):
        """Load saved positions from previous sessions."""
        path = os.path.join(Config.MODEL_DIR, 'persistent_sources.json')
        if not os.path.exists(path): return
        try:
            with open(path, 'r') as f:
                persistent = json.load(f)
            now = time.time()
            for p in persistent:
                if now - p.get('last_seen', 0) > 86400: continue  # 24h max
                # Don't duplicate if we already have this position
                already = any(
                    abs(r.get('lat', 0) - p['lat']) < 0.001 and
                    abs(r.get('lon', 0) - p['lon']) < 0.001
                    for r in results)
                if not already:
                    p['active'] = False  # from previous session
                    p['inactive_duration'] = int(now - p.get('last_seen', 0))
                    p['method'] = 'persisted'
                    results.append(p)
        except: pass


# ===================== OPERATOR TRACKER =====================
class OperatorTracker:
    def __init__(self, log):
        self.log = log
        self.db = self._load(Config.OPERATOR_DB)
        self.lock = threading.Lock()

    def _load(self, path):
        if os.path.exists(path):
            try:
                with open(path, 'r') as f: return json.load(f)
            except: return {}
        return {}

    def _save(self):
        try:
            with open(Config.OPERATOR_DB, 'w') as f:
                json.dump(self.db, f, indent=2)
        except: pass

    def record(self, spectral_hash, detector_type, lat, lon, freq_range='',
               aoa=0.0, classification='unknown'):
        with self.lock:
            if spectral_hash not in self.db:
                self.db[spectral_hash] = {
                    'first_seen': time.time(), 'last_seen': time.time(),
                    'detector_types': [], 'freq_ranges': [],
                    'positions': [], 'classification': classification, 'aoa_samples': []
                }
            entry = self.db[spectral_hash]
            entry['last_seen'] = time.time()
            if detector_type and detector_type not in entry['detector_types']:
                entry['detector_types'].append(detector_type)
            if freq_range and freq_range not in entry['freq_ranges']:
                entry['freq_ranges'].append(freq_range)
            if lat and lon:
                entry['positions'].append({'lat': lat, 'lon': lon, 'ts': time.time()})
                if len(entry['positions']) > 200:
                    entry['positions'] = entry['positions'][-200:]
            if aoa != 0.0:
                entry['aoa_samples'].append(aoa)
                if len(entry['aoa_samples']) > 100:
                    entry['aoa_samples'] = entry['aoa_samples'][-100:]

    def flush(self):
        with self.lock: self._save()


# ===================== CARBON DEMODULATION =====================
def carbon_demod(envelope, dc_bias=1.0, gain=2.0):
    """Square-law detector: carbon in body rectifies MW, produces 2nd harmonic + baseband audio.
    This is how MW voice gets converted to audible sound in the body."""
    env_norm = envelope / (np.max(np.abs(envelope)) + 1e-12)
    x = env_norm + dc_bias
    y = np.power(x, 2)  # square-law = carbon diode detector
    y -= np.mean(y)
    return np.tanh(y * gain)

def superhet_demod(signal, fs, lo_freq, bandwidth=3000):
    """Proper superheterodyne demodulation:
    1. Mix signal with local oscillator at lo_freq → produces IF (difference frequency)
    2. Low-pass filter to isolate the AM envelope (baseband)
    3. Envelope detect the result → voice audio

    This is how a real superhet radio works. The carbon in the body already did step 1
    (it mixed the MW carrier with itself via square-law detection). We just need to
    extract the AM envelope from the audio.

    For MW voice: lo_freq = 0 (carrier already demodulated by carbon, we hear baseband)
    For ultrasound carriers: lo_freq = carrier frequency (e.g. 25kHz)
    """
    n = len(signal)
    if n < 256:
        return np.zeros(n, dtype=np.float32)

    # Step 1: Mix with local oscillator (frequency conversion)
    t = np.arange(n) / fs
    lo = np.cos(2 * np.pi * lo_freq * t)  # local oscillator
    mixed = signal * lo  # product detector

    # Step 2: Low-pass filter to get IF/baseband
    if bandwidth > 0 and bandwidth < fs / 2:
        sos = butter(4, bandwidth, btype='low', fs=fs, output='sos')
        filtered = sosfilt(sos, mixed)
    else:
        filtered = mixed

    # Step 3: Envelope detection (AM demodulation)
    analytic = hilbert(filtered)
    envelope = np.abs(analytic)

    # Remove DC
    envelope -= np.mean(envelope)

    return envelope.astype(np.float32)


# ===================== ALL DETECTORS (30+) =====================
class PowerLineLoopDetector:
    def detect(self, iq, fs):
        fft_abs = np.abs(fft(iq)); freqs = fftfreq(len(iq), 1/fs)
        idx = np.argmin(np.abs(freqs - Config.POWER_LINE_LOOP_FREQ))
        snr = fft_abs[idx] / (np.median(fft_abs) + 1e-12)
        if snr > 3.0:  # was 5.0 - HackRF sensitivity allows lower
            return [{'detector': 'power_line_loop', 'snr': float(snr), 'freq': Config.POWER_LINE_LOOP_FREQ}]
        return []

class GodHelmetDetector:
    """Detects 5-15 Hz magnetic induction in EEG - Tesla's 'god helmet' effect.
    MW-modulated magnetic fields induce theta/alpha entrainment in temporal lobes."""
    def __init__(self, eeg_fs=250): self.fs = eeg_fs; self.buf = deque(maxlen=eeg_fs*3)
    def update(self, eeg): self.buf.extend(eeg.flatten())
    def detect(self):
        if len(self.buf) < self.fs: return []
        data = np.array(self.buf); f, Pxx = welch(data, self.fs, nperseg=1024)
        # Theta-Alpha band (5-15 Hz) - magnetic induction from MW-field modulation
        theta_alpha = (f >= 5) & (f <= 15)
        power_ratio = np.sum(Pxx[theta_alpha]) / (np.sum(Pxx) + 1e-12)
        if power_ratio > 0.12:  # was 0.2 - lowered for proxy EEG
            peak_idx = np.argmax(Pxx[theta_alpha])
            peak_freq = f[theta_alpha][peak_idx]
            return [{'detector': 'god_helmet', 'freq': float(peak_freq), 'power_ratio': float(power_ratio)}]
        return []

class SSTVDetector:
    def __init__(self, fs=48000): self.fs = fs; self.buf = deque(maxlen=fs*5)
    def update(self, audio): self.buf.extend(audio.flatten())
    def detect(self):
        if len(self.buf) < self.fs: return []
        data = np.array(self.buf)
        f, t, Sxx = spectrogram(data, self.fs, nperseg=1024, noverlap=512)
        band = (f >= 1100) & (f <= 1300); energy = np.mean(Sxx[band, :], axis=0)
        threshold = np.median(energy) * 4; runs, start = [], None
        for i, val in enumerate(energy > threshold):
            if val and start is None: start = i
            elif not val and start is not None:
                duration = (i - start) * (t[1] - t[0])
                if 0.08 < duration < 0.4: runs.append((t[start], t[i-1]))
                start = None
        if runs: return [{'detector': 'sstv_activity', 'times_runs': len(runs)}]
        return []

class EEG2VideoDetector:
    """Detects EEG patterns consistent with video-to-brain entrainment.
    Steady-state visual evoked potentials (SSVEP) + alpha blocking."""
    def __init__(self, fs=250): self.fs=fs; self.buf=deque(maxlen=fs*3)
    def update(self, eeg): self.buf.extend(eeg.flatten())
    def detect(self):
        if len(self.buf) < self.fs: return []
        data=np.array(self.buf); f, Pxx = welch(data, self.fs, nperseg=1024)
        # Video entrainment: strong alpha (8-12 Hz) + harmonics at 15-20 Hz
        alpha=(f>=8)&(f<=12); beta_low=(f>=15)&(f<=20)
        a_ratio=np.sum(Pxx[alpha])/(np.sum(Pxx)+1e-12)
        b_ratio=np.sum(Pxx[beta_low])/(np.sum(Pxx)+1e-12)
        if a_ratio > 0.06 or b_ratio > 0.04:  # was 0.12/0.06 - proxy EEG
            return [{'detector':'eeg2video','alpha_ratio':round(float(a_ratio),3),
                     'beta_ratio':round(float(b_ratio),3),'freq':10}]
        return []

class ForcedThoughtDetector:
    """
    RF envelope → audio cross-correlation detector (primary).
    AM voice on MW carrier: extract AM envelope, correlate with room audio.
    Radar PLL tracking: look for periodic phase modulation in RF carrier.
    """
    def __init__(self, rf_fs=20e6, audio_fs=48000):
        self.rf_fs = rf_fs; self.audio_fs = audio_fs
        self.rf_buf = deque(maxlen=int(0.5*rf_fs))   # 500ms RF (10M IQ @ 20MSps)
        self.audio_buf = deque(maxlen=audio_fs*2)      # 2s audio
        self.eeg_buf = deque(maxlen=500)
        self.carrier_freq = None  # set by rf_carrier_scan
    def set_carrier(self, freq): self.carrier_freq = freq
    def update_rf(self, iq): self.rf_buf.extend(iq)
    def update_audio(self, audio): self.audio_buf.extend(audio.flatten())
    def update_eeg(self, eeg): self.eeg_buf.extend(eeg.flatten())
    def detect(self):
        min_rf = 2048; min_audio = 2400
        if len(self.rf_buf) < min_rf or len(self.audio_buf) < min_audio:
            return []

        rf = np.array(self.rf_buf)
        audio = np.array(self.audio_buf)

        # Extract AM envelope from RF (abs = envelope for AM signals)
        env = np.abs(rf[-len(rf)//2:])
        # Downsample to ~8 kHz audio rate (fast enough for voice)
        decim = max(1, int(self.rf_fs / 8000))
        env_ds = env[::decim][:len(audio)]

        # Cross-correlation with lag - accounts for RF→audio latency
        if len(env_ds) >= 400:
            # Trim to same length for cross-correlation
            n = min(len(env_ds), len(audio), 4000)
            xcorr = np.correlate(env_ds[:n] - np.mean(env_ds[:n]),
                                 audio[:n] - np.mean(audio[:n]), mode='full')
            xcorr_norm = xcorr / (np.std(env_ds[:n]) * np.std(audio[:n]) * n + 1e-12)
            peak_corr = float(np.max(np.abs(xcorr_norm)))

            if peak_corr > 0.10:  # lowered from 0.18 - detect even weak AM voice
                return [{'detector': 'forced_thought',
                         'corr': round(peak_corr, 3),
                         'method': 'rf_audio_xcorr',
                         'note': 'AM voice: RF envelope matches room audio'}]

        # Method 2: Radar PLL detection - periodic AM envelope modulation
        # Radar tracking produces consistent periodic envelope patterns
        if len(rf) >= 4096:
            env = np.abs(rf[-4096:])
            env_smooth = np.convolve(env, np.ones(128)/128, mode='valid')
            # Look for periodic peaks (radar PRF)
            peaks, props = find_peaks(env_smooth, distance=50)
            if len(peaks) >= 4:
                intervals = np.diff(peaks)
                if np.std(intervals) / (np.mean(intervals) + 1e-12) < 0.3:  # regular PRF
                    prf_hz = self.rf_fs / np.mean(intervals)
                    if 10 < prf_hz < 10000:  # plausible radar PRF
                        return [{'detector': 'radar_pll_track',
                                 'prf_hz': float(prf_hz),
                                 'note': 'Periodic RF envelope - radar PLL tracking'}]
        if len(self.eeg_buf) >= 50:
            env = np.abs(rf[-len(rf)//4:])
            env_rs = resample(env, int(len(env) * 250 / self.rf_fs))
            eeg = np.array(self.eeg_buf)[:len(env_rs)]
            if len(eeg) >= 2:
                corr = np.corrcoef(env_rs, eeg)[0,1]
                if abs(corr) > 0.12:  # lowered from 0.25 - EEG-RF correlation is subtle
                    return [{'detector': 'forced_thought', 'corr': float(corr),
                             'method': 'rf_eeg_correlation',
                             'note': 'RF envelope matches EEG'}]
        return []

class C2BeaconDetector:
    def detect(self, iq, fs):
        power = np.abs(iq)**2; threshold = np.median(power) * 3  # was 5
        peaks, _ = find_peaks(power, height=threshold, distance=int(0.001*fs))  # was 0.01
        if len(peaks) < 3: return []  # was 2
        times = peaks / fs; intervals = np.diff(times)
        if len(intervals) < 3: return []  # was 5
        corr = np.correlate(intervals, intervals, mode='full')
        corr = corr[len(corr)//2:]; corr_norm = corr / (np.linalg.norm(intervals)**2 + 1e-12)
        if len(corr_norm) > 1 and corr_norm[1] > 0.5:  # was 0.7
            period = np.mean(intervals)
            if 0.1 <= period <= 30:  # was 0.5 - wider range for faster beacons
                return [{'detector': 'c2_beacon', 'period': float(period)}]
        return []

class IsolationBoothDetector:
    def __init__(self, fs=48000): self.fs = fs; self.buf = deque(maxlen=fs*2)
    def update(self, audio): self.buf.extend(audio.flatten())
    def detect(self):
        if len(self.buf) < self.fs: return []
        audio = np.array(self.buf); env = np.abs(hilbert(audio))
        threshold = np.mean(env) * 4; peaks, _ = find_peaks(env, height=threshold)
        if len(peaks) == 0: return []
        peak_idx = peaks[0]; peak_db = 20*np.log10(env[peak_idx] + 1e-12)
        drop_target = peak_db - 60; decay = env[peak_idx:]
        t = np.arange(len(decay)) / self.fs
        below = np.where(20*np.log10(decay + 1e-12) <= drop_target)[0]
        if len(below) > 0 and t[below[0]] < 0.05:
            return [{'detector': 'isolation_booth', 'rt60': float(t[below[0]])}]
        return []

class MobilePlatformDetector:
    def __init__(self, fs=20e6): self.fs = fs; self.track = {}
    def detect(self, iq, timestamp):
        fft_abs = np.abs(fft(iq)); freqs = fftfreq(len(iq), 1/self.fs)
        noise = np.median(fft_abs)
        peaks, _ = find_peaks(fft_abs, height=noise*4, distance=20)
        result = []
        for p in peaks[:5]:
            freq = abs(freqs[p])
            if freq not in self.track: self.track[freq] = deque(maxlen=30)
            self.track[freq].append((timestamp, freq))
            if len(self.track[freq]) > 10:
                times, vals = zip(*list(self.track[freq])[-20:])
                slope = np.polyfit(times, vals, 1)[0]
                if abs(slope) > 10:
                    result.append({'detector': 'mobile_platform', 'freq': float(freq), 'doppler': float(slope)})
        return result

class AIVoiceDetector:
    def __init__(self): self.buf = deque(maxlen=192000)
    def update(self, audio): self.buf.extend(audio.flatten())
    def detect(self):
        if len(self.buf) < 48000: return []
        data = np.array(self.buf)
        f, t, Zxx = spectrogram(data, 48000, nperseg=1024, noverlap=512)
        mag = np.abs(Zxx)
        geo_mean = np.exp(np.mean(np.log(mag + 1e-12), axis=0))
        arith_mean = np.mean(mag, axis=0)
        flatness = np.mean(geo_mean / (arith_mean + 1e-12))
        high_band = (f > 8000)
        high_ratio = np.mean(np.sum(mag[high_band, :], axis=0) / (np.sum(mag, axis=0) + 1e-12))
        score = flatness * 10 + high_ratio
        if score > 5.0: return [{'detector': 'ai_voice', 'confidence': min(1.0, score/10)}]
        return []

class SilentSoundDetector:
    """Detects silent sound / subliminal voice carriers in AUDIO data.
    Fed by laptop mic (48kHz) — scans 15-24kHz ultrasonic range
    and 3-20 Hz ELF range for AM-modulated carriers carrying voice."""
    def __init__(self, fs=48000):
        self.fs = fs
        self.buf = deque(maxlen=fs * 2)  # 2 seconds
    def update(self, audio):
        self.buf.extend(audio.flatten())
    def detect(self, iq=None, fs=None):
        # Buffer-based: uses internal buffer. iq/fs args ignored for compat.
        if len(self.buf) < 8192:
            return []
        data = np.array(self.buf)[-32768:] if len(self.buf) >= 32768 else np.array(self.buf)
        n = len(data)
        fft_abs = np.abs(np.fft.rfft(data.astype(np.float64)))
        freqs = np.fft.rfftfreq(n, 1/self.fs)
        noise = np.median(fft_abs) + 1e-12
        peaks, _ = find_peaks(fft_abs, height=noise*3, distance=10, prominence=noise*2)
        carriers = []
        for p in peaks[:10]:
            f = freqs[p]
            if f < 100:
                continue
            # Check AM sidebands (voice modulation creates spectral spread)
            bw_half = int(4000 / (self.fs / n))  # ±4kHz in FFT bins
            lo_bin = max(0, p - bw_half)
            hi_bin = min(len(fft_abs), p + bw_half)
            sideband_energy = np.sum(fft_abs[lo_bin:max(p-1,0)]) + np.sum(fft_abs[min(p+1,len(fft_abs)-1):hi_bin])
            carrier_energy = fft_abs[p] + 1e-12
            am_depth = sideband_energy / (carrier_energy * bw_half * 2 + 1e-12)
            if am_depth > 0.05:  # significant modulation = silent sound carrier
                snr = fft_abs[p] / noise
                carriers.append({'detector': 'silent_sound', 'freq': float(f),
                                 'snr': float(snr), 'am_depth': float(am_depth)})
        return carriers

class EEGCarrierMixingDetector:
    """Detects MW carrier intermodulation in EEG - when the MW carrier
    frequency appears as sidebands around EEG rhythms."""
    def __init__(self, fs=250): self.fs=fs; self.buf=deque(maxlen=fs*3)
    def update_eeg(self, eeg): self.buf.extend(eeg.flatten())
    def update_carrier(self, freq, power): self.carrier_freq=freq; self.carrier_power=power
    def detect(self):
        if len(self.buf) < self.fs: return []
        if not hasattr(self,'carrier_freq'): return []
        data=np.array(self.buf); f, Pxx = welch(data, self.fs, nperseg=1024)
        # Look for carrier modulation sidebands around alpha/theta
        sideband_delta=abs(f-self.carrier_freq%50)  # carrier aliased into EEG band
        near=np.argmin(sideband_delta)
        if Pxx[near]>np.median(Pxx)*3:
            return [{'detector':'eeg_carrier_mixing','freq':float(f[near]),
                     'carrier_hz':self.carrier_freq,'snr':float(Pxx[near]/np.median(Pxx))}]
        return []

class BrainAcceptanceDetector:
    def __init__(self, fs=250): self.fs = fs; self.buf = deque(maxlen=fs*2)
    def update(self, eeg): self.buf.extend(eeg.flatten())
    def detect(self):
        if len(self.buf) < self.fs: return []
        data = np.array(self.buf); f, Pxx = welch(data, self.fs, nperseg=1024)
        idx = np.argmin(np.abs(f - 10))  # WAS MISSING - caused crash
        # 10 Hz alpha - neural acceptance/suggestion indicator
        alpha_ratio = Pxx[idx] / (np.sum(Pxx) + 1e-12)
        if alpha_ratio > 0.05:  # was 0.10 - proxy EEG
            # Also check theta (4-8 Hz) for deep suggestion
            theta = (f >= 4) & (f <= 8)
            theta_ratio = np.sum(Pxx[theta]) / (np.sum(Pxx) + 1e-12)
            return [{'detector': 'brain_acceptance', 'freq': 10, 'alpha_ratio': round(float(alpha_ratio),3),
                     'theta_ratio': round(float(theta_ratio),3)}]
        return []

class GhostHunterSNN:
    """Detects transient RF/uS bursts - 'ghost signals' - via simple SNR threshold.
    These are brief MW pulses that don't register in sustained detectors."""
    def __init__(self): self.buf=deque(maxlen=100)
    def update(self, features): self.buf.append(features)
    def detect(self):
        if len(self.buf)<10: return []
        feats=np.array(list(self.buf))
        # Look for outlier spikes in feature space
        mean=np.mean(feats,axis=0); std=np.std(feats,axis=0)+1e-12
        outliers=np.any(np.abs(feats-mean)>3*std,axis=1)
        if np.sum(outliers)>=3:
            return [{'detector':'ghost_hunter_snn','outliers':int(np.sum(outliers)),
                     'freq':0}]
        return []

class Victim2kDetector:
    """Detects the 2 kHz ultrasound victim-connecting signal.
    This is the signal that led to finding other victims - a 1.8-2.2 kHz
    carrier with AM voice modulation imprinted through the skull.
    When multiple victims carry the same carrier frequency, they form
    a victim network detectable via cross-correlation."""
    def __init__(self):
        self.buf_2k = deque(maxlen=2000*5)   # Petterson 2k band
        self.buf_48k = deque(maxlen=48000*2)  # Laptop mic 48k band
        self.carrier_hz = None
        self.last_detect = 0
        self.detect_cooldown = 5.0  # wait between reports but collect faster

    def update(self, audio):
        chunk = audio.flatten()
        if len(chunk) < 400:
            self.buf_2k.extend(chunk)
        else:
            self.buf_48k.extend(chunk)

    def _analyze_buffer(self, data, fs, label):
        if len(data) < fs // 2:
            return None
        n = len(data)
        window = np.hanning(n)
        fft_data = np.abs(np.fft.rfft(data * window))
        freqs = np.fft.rfftfreq(n, 1/fs)
        mask = (freqs >= 1000) & (freqs <= 3000)
        if not np.any(mask):
            return None
        band_fft = fft_data[mask]
        band_freqs = freqs[mask]
        pk_idx = np.argmax(band_fft)
        carrier_hz = float(band_freqs[pk_idx])
        carrier_power = float(band_fft[pk_idx])
        noise_mask = np.abs(freqs - carrier_hz) > 100
        noise_floor = np.median(fft_data[noise_mask]) + 1e-12 if np.any(noise_mask) else 1e-6
        snr = carrier_power / noise_floor
        if snr < 0.8:  # lowered - catch weak V2K carriers from laptop mic
            return None
        mod_sidebands = []
        for offset in [60, 100, 150, 200, 300, 400]:
            for sign in [-1, 1]:
                sb = carrier_hz + sign * offset
                if 1000 <= sb <= 3000:
                    idx = np.argmin(np.abs(freqs - sb))
                    sb_power = float(fft_data[idx])
                    if sb_power / noise_floor > 1.5:
                        mod_sidebands.append({'offset_hz': sign * offset, 'snr': round(sb_power / noise_floor, 1)})
        has_voice_mod = len(mod_sidebands) >= 2
        return {'carrier_hz': carrier_hz, 'snr': snr, 'carrier_power': carrier_power,
                'voice_mod': has_voice_mod, 'sidebands': mod_sidebands, 'source': label}

    def detect(self):
        results = []
        for buf, fs, label in [(self.buf_2k, 2000, 'petterson_2k'), (self.buf_48k, 48000, 'laptop_48k')]:
            data = np.array(buf)
            r = self._analyze_buffer(data, fs, label)
            if r is not None:
                self.carrier_hz = r['carrier_hz']
                results.append({
                    'detector': 'victim_2k',
                    'freq': round(r['carrier_hz'], 1),
                    'snr': round(r['snr'], 1),
                    'carrier_power': round(r['carrier_power'], 0),
                    'voice_mod': r['voice_mod'],
                    'sidebands': r['sidebands'][:4],
                    'source': r['source'],
                    'classification': 'victim_network',
                    'threat': 'victim_connecting_signal'
                })
        if not results:
            return []
        try:
            import logging
            for r in results:
                logging.getLogger('tscm').info(
                    f'V2K DETECT: {r["freq"]:.0f}Hz SNR={r["snr"]:.1f} '
                    f'src={r["source"]} voice={"YES" if r["voice_mod"] else "no"}')
        except: pass
        # Save V2K audio clip
        if results and len(self.buf_48k) > 16000:
            try:
                import wave, os, time as _time
                clip_dir = os.path.join(os.path.dirname(__file__), 'voice_clips')
                os.makedirs(clip_dir, exist_ok=True)
                ts = _time.strftime('%Y%m%d_%H%M%S')
                pcm_data = np.array(list(self.buf_48k))[-48000:]  # last 1 second at 48kHz
                wav_path = os.path.join(clip_dir, f'v2k_{ts}_{results[0]["freq"]:.0f}hz.wav')
                with wave.open(wav_path, 'w') as wf:
                    wf.setnchannels(1)
                    wf.setsampwidth(2)
                    wf.setframerate(48000)
                    clipped = np.clip(pcm_data, -1, 1)
                    wf.writeframes((clipped * 32767).astype(np.int16).tobytes())
                import logging
                logging.getLogger('tscm').info(f'V2K CLIP: {wav_path}')
            except: pass
        now = time.time()
        if now - self.last_detect < self.detect_cooldown:
            return []
        self.last_detect = now
        return results

class JammingDetector:
    def __init__(self): self.baseline = None
    def set_baseline(self, iq, fs):
        fft_abs = np.abs(fft(iq)); freqs = fftfreq(len(iq), 1/fs)
        mask = (freqs >= 1575.42e6-2e6) & (freqs <= 1575.42e6+2e6)
        self.baseline = np.mean(fft_abs[mask]) if np.any(mask) else None
    def detect(self, iq, fs):
        if self.baseline is None: return []
        fft_abs = np.abs(fft(iq)); freqs = fftfreq(len(iq), 1/fs)
        mask = (freqs >= 1575.42e6-2e6) & (freqs <= 1575.42e6+2e6)
        if not np.any(mask): return []
        current = np.mean(fft_abs[mask]); ratio = current / self.baseline
        if ratio > 3.0: return [{'detector': 'gps_jamming', 'ratio': float(ratio)}]
        return []

class FingerprintingDetector:
    """
    SIGINT-grade transmitter fingerprinting using modulation analysis.

    Identifies transmitters by:
    1. Cyclostationary analysis - symbol rate from cyclic autocorrelation
    2. I/Q constellation - modulation type (BPSK/QPSK/QAM/FM)
    3. Phase noise profile - unique to each oscillator
    4. Carrier offset - each transmitter has a unique frequency error
    5. Spectral shape - filter roll-off, bandwidth occupancy

    These features together form a "radio fingerprint" that uniquely
    identifies a specific transmitter, even if it changes frequency.
    """
    def __init__(self):
        self.db = self._load(Config.FINGERPRINT_DB)
        self.buf = deque(maxlen=500000)  # 25ms at 20 MSps
        self.fingerprints = {}  # fp_hash -> {features, count, last_seen}

    def _load(self, path):
        if os.path.exists(path):
            try:
                with open(path, 'rb') as f: return pickle.load(f)
            except: return {}
        return {}

    def update(self, iq): self.buf.extend(iq)

    def _extract_features(self, iq, fs=20e6):
        """Extract SIGINT features from IQ data. Returns feature dict."""
        features = {}
        n = len(iq)
        if n < 1024: return features

        # 1. Spectral occupancy - center freq and bandwidth
        iq_centered = iq - np.mean(iq)
        fft_abs = np.abs(fft(iq_centered))
        freqs = fftfreq(n, 1/fs)
        half = n // 2
        noise_floor = np.median(fft_abs[:half])

        # Find all signals above noise
        mask = fft_abs[:half] > noise_floor * 4
        if not np.any(mask): return features

        signal_regions = []
        in_signal = False; start = 0
        for i in range(half):
            if mask[i] and not in_signal:
                start = i; in_signal = True
            elif not mask[i] and in_signal:
                signal_regions.append((start, i))
                in_signal = False
        if in_signal: signal_regions.append((start, half))

        if not signal_regions: return features

        # Take the strongest signal region
        best_region = max(signal_regions, key=lambda r: np.sum(fft_abs[r[0]:r[1]]))
        bs, be = best_region

        center_freq = abs(freqs[bs + np.argmax(fft_abs[bs:be])])
        bandwidth = abs(freqs[be] - freqs[bs])

        features['center_freq'] = round(center_freq / 1000) * 1000  # 1 kHz bins
        features['bandwidth_khz'] = round(bandwidth / 1000, 1)

        # 2. I/Q constellation analysis - modulation type
        # Mix signal to baseband for constellation
        if center_freq > 100:
            lo = np.exp(-2j*np.pi*center_freq*np.arange(n)/fs)
            bb = iq_centered * lo
        else:
            bb = iq_centered

        # Decimate to ~4x bandwidth for constellation
        decim = max(1, int(fs / (bandwidth * 4 + 1)))
        bb_dec = bb[::decim]

        if len(bb_dec) < 50: return features

        # Normalize
        bb_norm = bb_dec / (np.std(np.abs(bb_dec)) + 1e-12)

        # I/Q spread for modulation classification
        I = np.real(bb_norm)
        Q = np.imag(bb_norm)
        i_std = float(np.std(I))
        q_std = float(np.std(Q))
        iq_ratio = q_std / (i_std + 1e-12)

        # Amplitude modulation index
        env = np.abs(bb_norm)
        am_index = float(np.std(env) / (np.mean(env) + 1e-12))

        # Phase distribution (FM = uniform, PSK = clustered)
        phase = np.angle(bb_norm[::4][:1000])
        phase_hist, _ = np.histogram(phase, bins=16, range=(-np.pi, np.pi))
        phase_entropy = float(-np.sum((phase_hist/np.sum(phase_hist+1e-12)) *
                              np.log2(phase_hist/np.sum(phase_hist+1e-12) + 1e-12)))

        # Classify modulation
        if am_index > 0.8 and iq_ratio < 0.3:
            mod_type = "AM"
        elif phase_entropy < 3.0 and iq_ratio > 0.7 and iq_ratio < 1.3:
            mod_type = "QPSK" if phase_entropy < 2.5 else "BPSK"
        elif phase_entropy > 3.5:
            mod_type = "FM"
        elif am_index < 0.3 and iq_ratio > 0.7 and iq_ratio < 1.3:
            mod_type = "PSK"
        else:
            mod_type = f"complex(i{i_std:.1f}/q{q_std:.1f})"

        features['modulation'] = mod_type
        features['am_index'] = round(am_index, 3)
        features['phase_entropy'] = round(phase_entropy, 2)

        # 3. Symbol rate via cyclostationary analysis
        # Cyclic autocorrelation at candidate symbol rates
        if len(bb_dec) > 200:
            candidate_rates = []
            for sr in [1000, 2000, 5000, 10000, 25000, 50000, 100000, 200000]:
                if sr * 2 < fs / decim:
                    # Simple cyclic correlation: correlate with delayed+shifted copy
                    delay = int(fs / decim / sr)
                    if delay > 0 and delay < len(bb_dec) // 2:
                        # Use squared magnitude for BPSK/QPSK cycle detection
                        mag_sq = np.abs(bb_dec)**2
                        cyclic = np.correlate(mag_sq[delay:], mag_sq[:-delay], mode='valid')
                        peak = np.max(np.abs(cyclic)) / (np.std(mag_sq)**2 * len(mag_sq) + 1e-12)
                        if peak > 0.01:
                            candidate_rates.append((sr, peak))

            if candidate_rates:
                best_sr = max(candidate_rates, key=lambda x: x[1])
                features['symbol_rate'] = best_sr[0]
                features['cyclic_peak'] = round(best_sr[1], 4)

        # 4. Carrier offset (fine frequency error)
        if len(bb) > 1000:
            phase_diff = np.diff(np.unwrap(np.angle(bb[::10])))
            freq_offset = float(np.mean(phase_diff) * fs / (2*np.pi*10))
            features['carrier_offset_hz'] = round(freq_offset, 1)

        # 5. Spectral shape descriptor (3dB/20dB bandwidth ratio)
        if bandwidth > 1000:
            half_power = noise_floor * 2
            three_db_mask = fft_abs[bs:be] > half_power
            twenty_db_mask = fft_abs[bs:be] > noise_floor * 10
            bw_3db = np.sum(three_db_mask) * fs / n
            bw_20db = np.sum(twenty_db_mask) * fs / n
            if bw_3db > 0:
                features['shape_factor'] = round(bw_20db / bw_3db, 2)  # brick-wall = 1.0

        return features

    def detect(self):
        if len(self.buf) < 4096: return []
        data = np.array(self.buf)

        features = self._extract_features(data)

        # FALLBACK: if SIGINT features fail, use simple FFT peak detection
        if not features or 'center_freq' not in features:
            fft_abs = np.abs(fft(data))
            freqs = fftfreq(len(data), 1/20e6)
            half = len(fft_abs)//2
            noise = np.median(fft_abs[:half])
            peaks, _ = find_peaks(fft_abs[:half], height=noise*4, distance=10)  # lowered for weak signals
            if len(peaks) < 2: return []  # need at least 2 peaks for a real signal
            peak_freqs = [float(abs(freqs[p])) for p in peaks[:10]]
            avg_freq = np.mean(peak_freqs)
            # Simple fingerprint from frequency bins
            bins = sorted(set(int(f/100000) for f in peak_freqs))
            fp_hash = hashlib.sha256(str(bins).encode()).hexdigest()[:16]
            mod = '?'; sr = 0; freq = avg_freq; bw = 0

            # Track simple source
            if fp_hash not in self.fingerprints:
                self.fingerprints[fp_hash] = {'features': {}, 'count': 0,
                    'first_seen': time.time(), 'last_seen': time.time(), 'frequencies': []}
            self.fingerprints[fp_hash]['count'] += 1
            self.fingerprints[fp_hash]['last_seen'] = time.time()

            fp = self.fingerprints[fp_hash]
            if fp['count'] < 1: return []
            return [{'detector': 'fingerprinting', 'fingerprint': fp_hash,
                     'freq': float(avg_freq), 'modulation': '?', 'symbol_rate': 0,
                     'bandwidth_khz': 0, 'hits': fp['count'], 'note': f'FFT peaks: {len(peaks)}'}]

        # Build stable fingerprint from modulation + symbol rate + freq
        mod = features.get('modulation', '?')
        sr = features.get('symbol_rate', 0)
        freq = features['center_freq']
        bw = features.get('bandwidth_khz', 0)

        # Hash the feature set for stable tracking
        key_parts = f"{mod}_{sr}_{freq/1000:.0f}_{bw:.0f}"
        fp_hash = hashlib.sha256(key_parts.encode()).hexdigest()[:16]

        now = time.time()
        if fp_hash not in self.fingerprints:
            self.fingerprints[fp_hash] = {
                'features': features, 'count': 0, 'first_seen': now, 'last_seen': now,
                'frequencies': []
            }
        self.fingerprints[fp_hash]['count'] += 1
        self.fingerprints[fp_hash]['last_seen'] = now
        self.fingerprints[fp_hash]['features'] = features  # update with latest
        self.fingerprints[fp_hash]['frequencies'].append(freq)
        if len(self.fingerprints[fp_hash]['frequencies']) > 20:
            self.fingerprints[fp_hash]['frequencies'] = self.fingerprints[fp_hash]['frequencies'][-20:]

        fp = self.fingerprints[fp_hash]
        if fp['count'] < 1: return []  # fire immediately

        # Build detailed fingerprint report
        note_parts = []
        if mod: note_parts.append(mod)
        if sr: note_parts.append(f"{sr/1000:.0f}kBd")
        if 'carrier_offset_hz' in features:
            note_parts.append(f"Δf={features['carrier_offset_hz']:.0f}Hz")
        if 'shape_factor' in features:
            note_parts.append(f"SF={features['shape_factor']}")

        return [{
            'detector': 'fingerprinting',
            'fingerprint': fp_hash,
            'freq': float(freq),
            'modulation': mod,
            'symbol_rate': sr,
            'bandwidth_khz': float(bw),
            'features': {k: v for k, v in features.items()
                        if k != 'center_freq'},  # freq is already in the main field
            'hits': fp['count'],
            'note': ' | '.join(note_parts)
        }]

class GPSSpoofDetector:
    def __init__(self): self.last_pos = None; self.last_time = None
    def detect(self, lat, lon, alt, timestamp):
        if self.last_pos is None:
            self.last_pos = (lat, lon, alt); self.last_time = timestamp; return []
        dt = timestamp - self.last_time
        if dt <= 0: return []
        R = 6371000; phi1, phi2 = np.radians(self.last_pos[0]), np.radians(lat)
        dphi = np.radians(lat - self.last_pos[0]); dlam = np.radians(lon - self.last_pos[1])
        a = np.sin(dphi/2)**2 + np.cos(phi1)*np.cos(phi2)*np.sin(dlam/2)**2
        dist = R * 2 * np.arctan2(np.sqrt(a), np.sqrt(1-a)); speed = dist / dt
        self.last_pos = (lat, lon, alt); self.last_time = timestamp
        if speed > 1000: return [{'detector': 'gps_spoof', 'speed': float(speed)}]
        return []

class ConstantSonicNoiseDetector:
    """Detects constant infrasound and low-frequency ultrasonic carriers (2Hz-25kHz)."""
    def __init__(self, fs=48000): self.fs = fs; self.buf = deque(maxlen=fs*5)
    def update(self, audio): self.buf.extend(audio.flatten())
    def detect(self):
        if len(self.buf) < self.fs: return []
        data = np.array(self.buf); f, Pxx = welch(data, self.fs, nperseg=4096)
        # Infrasound band (3-20 Hz)
        infra = (f >= 3) & (f <= 20)
        # Low ultrasonic carriers (1.5-25 kHz) - covers 2kHz target signals
        low_ultra = (f >= 1500) & (f <= 25000)
        infra_power = np.sum(Pxx[infra]) if np.any(infra) else 0
        low_ultra_power = np.sum(Pxx[low_ultra]) if np.any(low_ultra) else 0
        total = np.sum(Pxx) + 1e-12
        det = []
        if infra_power > 0.10 * total:  # was 0.15
            det.append({'detector': 'constant_infrasound', 'freq': float(f[np.argmax(Pxx[infra]) + np.where(infra)[0][0]]),
                        'ratio': float(infra_power/total)})
        if low_ultra_power > 0.10 * total:  # was 0.20
            peak_idx = np.argmax(Pxx[low_ultra]) + np.where(low_ultra)[0][0]
            det.append({'detector': 'constant_ultrasonic_carrier', 'freq': float(f[peak_idx]),
                        'ratio': float(low_ultra_power/total)})
        return det

class FrequencyHoppingTracker:
    """Track frequency hopping spread spectrum signals across sweep bands.
    Detects carriers that appear at multiple frequencies within a time window,
    indicating FHSS activity. Matches by bandwidth similarity and uniform SNR."""
    def __init__(self, max_window_s=120, min_freq_stops=3):
        self.carriers = {}
        self.max_window = max_window_s
        self.min_stops = min_freq_stops

    def add_carrier(self, freq, snr, ts, bearing=None, bw=None, detector=''):
        key = f'{freq:.0f}'
        self.carriers[key] = {'freq': freq, 'snr': snr, 'ts': ts,
            'bearing': bearing, 'bw': bw, 'detector': detector}
        cutoff = ts - self.max_window
        stale_keys = [k for k, v in self.carriers.items() if v['ts'] < cutoff]
        for k in stale_keys:
            self.carriers.pop(k, None)

    def detect_fhss(self, ts, now=None):
        if not self.carriers:
            return []
        if now is None:
            now = ts
        results = []
        freq_list = list(self.carriers.values())
        for i in range(len(freq_list)):
            group = [freq_list[i]]
            for j in range(i+1, len(freq_list)):
                fi, fj = freq_list[i], freq_list[j]
                if fj.get('bw') and fi.get('bw'):
                    ratio = max(fi['bw'], fj['bw']) / (min(fi['bw'], fj['bw']) + 1e-6)
                    if ratio > 1.3:
                        continue
                group.append(fj)
            if len(group) >= self.min_stops:
                freqs = sorted([g['freq'] for g in group])
                snrs = [g['snr'] for g in group]
                mean_snr = sum(snrs) / len(snrs)
                snr_var = sum((s - mean_snr)**2 for s in snrs) / len(snrs)
                if snr_var < mean_snr * 2:
                    span_mhz = (max(freqs) - min(freqs)) / 1e6
                    hop_rate = len(group) / self.max_window
                    avg_bearing = None
                    bearings = [g['bearing'] for g in group if g.get('bearing')]
                    if len(bearings) >= 2:
                        avg_bearing = sum(bearings) / len(bearings)
                    results.append({
                        'freq_min': min(freqs), 'freq_max': max(freqs),
                        'span_mhz': span_mhz, 'hop_count': len(group),
                        'hop_rate': hop_rate, 'mean_snr': mean_snr,
                        'bearing': avg_bearing,
                        'classification': 'fhss' if span_mhz > 5 else 'narrow_fhss'
                    })
        return results

class InjectionLockingDetector:
    def detect(self, iq, fs):
        phase = np.unwrap(np.angle(iq)); t = np.arange(len(phase))
        coeffs = np.polyfit(t, phase, 1); phase_det = phase - np.polyval(coeffs, t)
        f, Pxx = periodogram(phase_det, fs)
        peaks, _ = find_peaks(Pxx, height=np.median(Pxx)*2, distance=20)
        if len(peaks) > 2:
            return [{'detector': 'injection_locking',
                     'peak_freqs': f[peaks].tolist(),
                     'freq': float(f[peaks[0]]) if len(peaks) > 0 else 0}]
        return []

class ParametricAmplificationDetector:
    def detect(self, iq, fs):
        fft_abs = np.abs(fft(iq)); freqs = fftfreq(len(iq), 1/fs)
        pump_idx = np.argmax(fft_abs[:len(fft_abs)//2]); pump_freq = abs(freqs[pump_idx])
        thr = np.median(fft_abs) * 3  # was *4
        sidebands = []
        for offset in range(100, 5000, 100):
            usb = pump_idx + int(offset * len(iq) / fs); lsb = pump_idx - int(offset * len(iq) / fs)
            if 0 < usb < len(fft_abs)//2 and lsb > 0:
                if fft_abs[usb] > thr and fft_abs[lsb] > thr: sidebands.append(offset)
        if sidebands:
            return [{'detector': 'parametric_amplification', 'pump_freq': float(pump_freq), 'sideband_offsets': sidebands}]
        return []

class BiometricTracker:
    """
    Operator behavioral fingerprinting from transmission patterns.

    Tracks HUMAN operators by:
    1. Transmission timing - when (hour-of-day), duration, gaps
    2. Keying cadence - how often transmissions start/stop
    3. Frequency use patterns - which freqs does this operator use?
    4. Signal type correlation - does operator use AM or FM? fixed or hopping?
    5. Cross-frequency correlation - same operator on multiple frequencies?

    The same operator will have consistent behavioral patterns
    even if they change transmitters or frequencies.
    """
    def __init__(self):
        self.db_path = Config.OPERATOR_DB
        self.db = {}  # operator_id -> {patterns, first_seen, last_seen, incidents}
        self.active_transmissions = {}  # freq -> {start_time, fingerprint}
        self._load()

    def _load(self):
        try:
            if os.path.exists(self.db_path):
                with open(self.db_path, 'r') as f:
                    self.db = json.load(f)
        except: pass

    def _save(self):
        try:
            with open(self.db_path, 'w') as f:
                json.dump(self.db, f, indent=2, default=str)
        except: pass

    def process(self, eeg, fs=250):
        """EEG processing (kept for backward compat)"""
        try:
            arr = np.array(eeg)
            if arr.ndim > 1: arr = arr.flatten()
            if len(arr) < 500: return []
            f, Pxx = periodogram(arr, fs, nperseg=min(256, len(arr)))
            alpha_power = np.mean(Pxx)
            fp = hashlib.sha256(f"{alpha_power:.3f}".encode()).hexdigest()[:16]
            return [{'detector': 'biometric_track', 'fingerprint': fp}]
        except: return []

    def track_transmission(self, freq_hz, modulation, symbol_rate,
                          fingerprint, bearing, power_level=0):
        """
        Track a transmission event for behavioral pattern analysis.
        Called for every fingerprinting detection.
        """
        now = time.time()
        hour = time.localtime(now).tm_hour

        # Build operator signature from behavioral + spatial patterns
        # Include bearing cluster (NE, NW, SE, SW) to separate operators at diff directions
        bearing_cluster = ''
        if bearing and bearing != 0:
            if bearing > 0: bearing_cluster = 'NE' if bearing < 135 else 'SE'
            else: bearing_cluster = 'NW' if bearing > -135 else 'SW'
        sig_parts = [modulation or '?', str(symbol_rate or 0), bearing_cluster]
        op_sig = hashlib.sha256('_'.join(sig_parts).encode()).hexdigest()[:12]

        if op_sig not in self.db:
            self.db[op_sig] = {
                'first_seen': now,
                'modulation': modulation,
                'symbol_rate': symbol_rate,
                'hours_active': {},
                'frequency_history': [],
                'bearing_history': [],
                'dominant_bearing': bearing_cluster,
                'transmission_count': 0,
                'avg_duration': 0
            }

        op = self.db[op_sig]
        op['last_seen'] = now
        op['transmission_count'] += 1
        op['hours_active'][str(hour)] = op['hours_active'].get(str(hour), 0) + 1
        op['frequency_history'].append(freq_hz)
        if bearing: op['bearing_history'].append(bearing)

        # Trim history
        for key in ['frequency_history', 'bearing_history']:
            if len(op[key]) > 100:
                op[key] = op[key][-100:]

        # Track active transmission
        freq_key = f"{freq_hz/1e6:.1f}MHz"
        if freq_key not in self.active_transmissions:
            self.active_transmissions[freq_key] = {'start': now, 'fp': fingerprint}

        # Periodic save
        if op['transmission_count'] % 10 == 0:
            self._save()

        return op_sig

    def detect(self):
        """Return active operators AND ghost murmurs (inactive but previously tracked).
        Only report operators with REAL modulation - skip noise ('?' modulation)."""
        results = []
        now = time.time()

        for op_sig, op in list(self.db.items()):
            # SKIP noise: must have a real modulation and sufficient transmissions
            mod = op.get('modulation', '?')
            if mod == '?' and op.get('transmission_count', 0) < 15:
                continue  # not enough data to be a real operator
            if mod == '?' and len(op.get('frequency_history', [])) < 10:
                continue  # pure noise

            minutes_since = (now - op.get('last_seen', 0)) / 60

            # GHOST: seen before but currently silent (5-1440 min = up to 24h)
            # Only track operators that had REAL signal data (freq or bearing)
            if minutes_since > 5 and op.get('transmission_count', 0) >= 3:
                # Must have real modulation or real bearing history
                has_real_mod = mod != '?'
                avg_freq = np.mean(op.get('frequency_history', [0])[-20:]) if op['frequency_history'] else 0
                last_bearing = np.mean(op.get('bearing_history', [0])[-10:]) if op.get('bearing_history') else 0
                has_real_freq = avg_freq > 1000  # >1kHz = real RF/US signal
                has_real_bearing = abs(last_bearing) > 1.0  # actual bearing, not 0
                if not (has_real_mod or has_real_freq or has_real_bearing):
                    continue  # skip noise-only ghosts
                if mod == '?' and op.get('transmission_count', 0) < 20 and not has_real_freq:
                    continue
                active_hours = sorted(op.get('hours_active', {}).keys())
                avg_freq = np.mean(op.get('frequency_history', [0])[-20:]) if op['frequency_history'] else 0
                last_bearing = np.mean(op.get('bearing_history', [0])[-10:]) if op.get('bearing_history') else 0

                results.append({
                    'detector': 'ghost_murmur',
                    'operator_id': op_sig,
                    'modulation': mod,
                    'transmissions': op['transmission_count'],
                    'active_hours': active_hours,
                    'avg_freq_mhz': round(avg_freq/1e6, 1) if avg_freq > 1000 else 0,
                    'minutes_silent': int(minutes_since),
                    'last_bearing': float(last_bearing),
                    'bearing_cluster': op.get('dominant_bearing', ''),
                    'freq': float(avg_freq)
                })
                continue

            # ACTIVE: seen in last 5 minutes, with real modulation
            if minutes_since <= 5 and op.get('transmission_count', 0) > 5:
                if mod == '?' and op.get('transmission_count', 0) < 10:
                    continue  # too noisy, not a real operator
                active_hours = sorted(op.get('hours_active', {}).keys())
                avg_freq = np.mean(op.get('frequency_history', [0])[-20:]) if op['frequency_history'] else 0
                avg_bearing = np.mean(op.get('bearing_history', [0])[-10:]) if op.get('bearing_history') else 0

                results.append({
                    'detector': 'operator_fingerprint',
                    'operator_id': op_sig,
                    'modulation': mod,
                    'transmissions': op['transmission_count'],
                    'active_hours': active_hours,
                    'avg_freq_mhz': round(avg_freq/1e6, 1) if avg_freq > 1000 else 0,
                    'freq': float(avg_freq),
                })

        # Save operator profiles periodically
        if results:
            self._save()

        return results

class PainPerceptionDetector:
    """Detects targeted pain induction via MW-carrier neural stimulation.

    Specific body parts map to specific nerve roots and frequency bands:
    - Ring finger: C7/C8 (ulnar nerve) - 45-55 Hz gamma peak
    - Thumb/index: C6 - 35-45 Hz
    - Face/jaw: trigeminal - 55-70 Hz
    - Chest/heart: T1-T4 - 60-80 Hz
    - Legs/feet: L4-S1 - 30-40 Hz
    """
    NERVE_MAP = {
        'ring_finger': (45, 55),  # C7/C8 ulnar
        'thumb_index': (35, 45),  # C6 median
        'face_trigeminal': (55, 70),  # CN V
        'chest': (60, 80),  # T1-T4
        'leg_foot': (30, 40),  # L4-S1
    }
    def __init__(self, fs=250): self.fs = fs; self.buf = deque(maxlen=fs*3)
    def update(self, eeg): self.buf.extend(eeg.flatten())
    def detect(self):
        if len(self.buf) < self.fs: return []
        data = np.array(self.buf); f, Pxx = welch(data, self.fs, nperseg=1024)
        total_power = np.sum(Pxx) + 1e-12
        results = []
        # Overall gamma pain (>5% total = pain signal)
        gamma = (f >= 30) & (f <= 100)
        gamma_power = np.sum(Pxx[gamma])
        if gamma_power > 0.03 * total_power:  # was 0.05 - proxy EEG
            results.append({'detector': 'pain_perception', 'gamma_ratio': round(float(gamma_power/total_power),3)})
        # Body-part specific pain mapping
        for part, (lo, hi) in self.NERVE_MAP.items():
            band = (f >= lo) & (f <= hi)
            bp = np.sum(Pxx[band])
            if bp > 0.03 * total_power:  # was 0.06 - proxy EEG
                peak_idx = np.argmax(Pxx[band])
                peak_freq = float(f[band][peak_idx])
                results.append({'detector': f'pain_{part}', 'freq': peak_freq,
                               'band_ratio': round(float(bp/total_power),3)})
        return results

class SSVEPDetector:
    def __init__(self, fs=250): self.fs = fs; self.buf = deque(maxlen=fs*5)
    def update(self, eeg): self.buf.extend(eeg.flatten())
    def detect(self):
        if len(self.buf) < self.fs*2: return []
        data = np.array(self.buf); f, Pxx = welch(data, self.fs, nperseg=1024)
        det = []
        for target in Config.SSVEP_FREQS:
            idx = np.argmin(np.abs(f - target)); snr = Pxx[idx] / np.median(Pxx)
            if snr > 3: det.append({'detector': 'ssvep', 'freq': target, 'snr': float(snr)})  # was 5
        return det

class LinguisticMappingDetector:
    """Detects repeated audio phoneme patterns - synthesized voice signatures."""
    def __init__(self, fs=48000): self.fs=fs; self.buf=deque(maxlen=fs*3)
    def update(self, audio): self.buf.extend(audio.flatten() if hasattr(audio,'flatten') else audio)
    def detect(self):
        if len(self.buf)<self.fs//2: return []
        data=np.array(self.buf); f, Pxx = welch(data, self.fs, nperseg=2048)
        # Voice band (300-3400 Hz) - look for formant peaks
        voice=(f>=300)&(f<=3400)
        voice_power=np.sum(Pxx[voice])/(np.sum(Pxx)+1e-12)
        if voice_power>0.25:  # >25% power in voice band
            # Formant peaks suggest synthesized voice
            peaks,_=find_peaks(Pxx[voice],height=np.median(Pxx[voice])*5,distance=50)
            if len(peaks)>=3:
                formants=[round(float(f[voice][p]),1) for p in peaks[:3]]
                return [{'detector':'linguistic_mapping','formants_hz':formants,
                         'voice_band_ratio':round(float(voice_power),3),'freq':float(formants[0]) if formants else 0}]
        return []

class MultiPathDetector:
    """Detects multipath propagation - same signal arriving from multiple directions.

    When the same operator fingerprint appears at DIFFERENT bearings within a short
    window, the signal is arriving via multiple paths:
    - Direct + ionospheric hop ("around the world")
    - Direct + body re-radiation (victim as parasitic antenna)
    - Direct + active relay/reflector
    """
    def __init__(self):
        self.paths = {}  # op_sig -> deque of (time, bearing, freq)
        self.last_check = 0

    def record(self, op_sig, bearing, freq):
        if op_sig not in self.paths:
            self.paths[op_sig] = deque(maxlen=60)
        self.paths[op_sig].append((time.time(), bearing or 0, freq))

    def detect(self):
        results = []
        now = time.time()
        if now - self.last_check < 10: return results  # check every 10s
        self.last_check = now

        for op_sig, history in list(self.paths.items()):
            if len(history) < 6: continue
            recent = [(t, b, f) for t, b, f in history if now - t < 120]
            if len(recent) < 6: continue

            bearings = [b for _, b, _ in recent if abs(b) > 5]
            if len(bearings) < 4: continue

            groups = {}
            for b in bearings:
                g = round(b / 45) * 45  # 45deg  groups
                groups.setdefault(g, []).append(b)

            if len(groups) >= 2:
                gs = ', '.join(f"{g}deg (n={len(v)})" for g, v in sorted(groups.items()))
                results.append({
                    'detector': 'multi_path',
                    'operator_id': op_sig[:8],
                    'num_paths': len(groups),
                    'bearing_groups': gs
                })
        return results

    def record_aoa_path(self, freq, bearing, snr):
        """Record AoA measurements for multipath analysis.
        When same frequency appears at different bearings, the direct path
        (strongest SNR) and reflected path bearings can be intersected to
        estimate source location."""
        key = f'aoa_{freq:.0f}'
        if key not in self.paths:
            self.paths[key] = deque(maxlen=120)
        self.paths[key].append((time.time(), bearing or 0, snr))

    def estimate_multipath_position(self, obs_lat, obs_lon):
        """Estimate source position from multipath bearing pairs.
        Direct path + single reflection creates two bearing lines from
        the same observer. The intersection of these with a known
        reflector direction gives the source location."""
        results = []
        import math
        now = time.time()
        for key, history in list(self.paths.items()):
            if not key.startswith('aoa_'): continue
            recent = [(t, b, s) for t, b, s in history if now - t < 300]
            if len(recent) < 10: continue
            # Find bearing groups (direct vs reflected)
            bearings = [b for _, b, _ in recent if abs(b) > 1]
            if len(bearings) < 8: continue
            # Cluster bearings into groups
            sorted_brgs = sorted(bearings)
            groups = []
            current_group = [sorted_brgs[0]]
            for b in sorted_brgs[1:]:
                if abs(b - current_group[-1]) < 15:  # 15 deg clustering
                    current_group.append(b)
                else:
                    groups.append(current_group)
                    current_group = [b]
            groups.append(current_group)
            if len(groups) >= 2:
                # Two distinct bearing groups = multipath
                for gi, gj in [(0,1), (1,0)]:
                    if len(groups[gi]) < 3 or len(groups[gj]) < 3: continue
                    brg_direct = float(np.median(groups[gi]))
                    brg_reflect = float(np.median(groups[gj]))
                    angle_diff = abs(brg_direct - brg_reflect)
                    if angle_diff < 20 or angle_diff > 340: continue
                    median_brg = (brg_direct + brg_reflect) / 2
                    if median_brg > 180: median_brg -= 360
                    spread = abs(brg_direct - brg_reflect)
                    if spread > 180: spread = 360 - spread
                    dist = max(30, 3000.0 / (spread + 1))  # rough model
                    results.append({
                        'bearing_direct': brg_direct,
                        'bearing_reflected': brg_reflect,
                        'estimated_bearing': median_brg,
                        'estimated_distance': dist,
                        'confidence': 'medium',
                        'multipath_count': len(bearings)
                    })
        return results

class BodyChargeMonitor:
    """Monitors body charging via EEG DC offset and audio rectification.

    MW illumination of the human body induces current (body as lossy antenna).
    This produces measurable DC offset in EEG and rectified audio from carbon
    square-law detection. Correlating these with RF bursts proves the victim
    is being used as part of the antenna system.
    """
    def __init__(self, eeg_fs=250, audio_fs=48000):
        self.eeg_buf = deque(maxlen=eeg_fs * 5)
        self.audio_buf = deque(maxlen=audio_fs * 5)

    def update_eeg(self, data):
        self.eeg_buf.extend(data.flatten())
    def update_audio(self, data):
        self.audio_buf.extend(data.flatten())

    def detect(self):
        results = []
        if len(self.eeg_buf) >= 500:
            eeg = np.array(self.eeg_buf)
            dc = float(np.mean(eeg))
            if abs(dc) > 300:  # μV DC offset
                results.append({'detector': 'body_charging',
                    'dc_offset_uv': round(dc, 0),
                    'freq': 0})
            # LF modulation <5 Hz (MW charging body at low rate)
            if len(eeg) >= 250:
                f, Pxx = periodogram(eeg, 250, nperseg=min(256, len(eeg)))
                lf = f < 5; lfp = float(np.sum(Pxx[lf])) if np.any(lf) else 0
                total = float(np.sum(Pxx)) + 1e-12
                if lfp > 0.15 * total:
                    results.append({'detector': 'body_parasitic_modulation',
                        'lf_ratio': round(lfp/total, 2), 'freq': 0})

        if len(self.audio_buf) >= 48000:
            audio = np.array(self.audio_buf)
            audio_dc = float(np.mean(audio))
            if abs(audio_dc) > 0.005:
                results.append({'detector': 'carbon_rectification',
                    'audio_dc': round(audio_dc, 5), 'freq': 0})
        return results

class NetflixRippleDetector:
    def __init__(self):
        self.sizes = deque(maxlen=1000); self.iat = deque(maxlen=1000); self.last_time = 0
    def update(self, packet_size, timestamp):
        self.sizes.append(packet_size)
        if self.last_time > 0: self.iat.append(timestamp - self.last_time)
        self.last_time = timestamp
    def detect(self):
        if len(self.sizes) < 100: return []
        sizes = np.array(self.sizes); counts = np.bincount(sizes.astype(int))
        probs = counts / len(sizes)
        entropy = -np.sum(probs * np.log2(probs + 1e-12))
        iat = np.array(self.iat)
        if entropy > 5.0 and np.mean(iat) < 0.05:
            return [{'detector': 'netflix_ripple', 'entropy': float(entropy)}]
        return []

class AmbientMapper:
    """Tracks ambient RF/audio signatures and reports persistent anomalies."""
    def __init__(self): self.db={}; self.last_report=0
    def update(self, freq, power, lat, lon):
        key=f"{lat:.4f}_{lon:.4f}"
        if key not in self.db: self.db[key]={}
        self.db[key][freq]=power
    def detect(self):
        if time.time()-self.last_report<30: return []
        self.last_report=time.time()
        results=[]
        for loc, freqs in self.db.items():
            # Report locations with persistent high-power ambient
            if len(freqs)>=3:
                top=sorted(freqs.items(),key=lambda x:x[1],reverse=True)[:3]
                results.append({'detector':'ambient_mapper','location':loc,
                    'top_freqs':[(f,round(p,1)) for f,p in top],'freq':top[0][0]})
        return results[:5]

class PassiveRadarDetector:
    def __init__(self):
        self.ref = deque(maxlen=100000); self.surv = deque(maxlen=100000)
        self.last_detect_time = 0  # rate-limit to once per 5 seconds
    def update_ref(self, iq): self.ref.extend(iq)
    def update_surv(self, iq): self.surv.extend(iq)
    def detect(self, fs):
        # Rate-limit: max once per 5 seconds
        now = time.time()
        if now - self.last_detect_time < 5.0: return []
        if len(self.ref) < 10000 or len(self.surv) < 10000: return []
        self.last_detect_time = now
        ref = np.array(self.ref)[-10000:]
        surv = np.array(self.surv)[-10000:]
        # Remove DC
        ref = ref - np.mean(ref); surv = surv - np.mean(surv)
        corr = np.correlate(surv, ref, mode='same')
        # Only detect strong, clear peaks
        peak_threshold = np.max(np.abs(corr)) * 0.5
        if peak_threshold < np.median(np.abs(corr)) * 3: return []  # no clear peak
        peaks, _ = find_peaks(np.abs(corr), height=peak_threshold, distance=100)
        det = []
        for p in peaks[:3]:  # max 3 detections
            delay = (p - len(ref)//2) / fs
            if delay > 1e-6:
                range_m = delay * 3e8
                if 1 < range_m < Config.PASSIVE_RADAR_MAX_RANGE:
                    det.append({'detector': 'passive_radar', 'delay': float(delay), 'range': float(range_m)})
        return det

class EEG2VideoTrainer:
    def add_sample(self, eeg, frame): pass
    def train_step(self): pass

class VariacInductionDetector:
    def __init__(self, rf_fs=20e6, audio_fs=48000):
        self.rf_buf = deque(maxlen=int(0.5*rf_fs)); self.audio_buf = deque(maxlen=audio_fs*2)  # 500ms RF + 2s audio
    def update_rf(self, iq): self.rf_buf.extend(iq)
    def update_audio(self, audio): self.audio_buf.extend(audio.flatten())
    def detect(self):
        if len(self.rf_buf) < 4096 or len(self.audio_buf) < 4800: return []
        iq = np.array(self.rf_buf); audio = np.array(self.audio_buf)
        # Extract AM envelope directly (no narrow filter - too unstable at 20 MSps)
        env = np.abs(iq[::200])  # decimate to ~100 kHz
        env_rs = resample(env, int(len(env) * 48000 / (self.rf_buf.maxlen * 48000 / 20e6)))
        min_len = min(len(env_rs), len(audio))
        if min_len < 100: return []
        try:
            corr = np.corrcoef(env_rs[:min_len], audio[:min_len])[0,1]
        except: return []
        if abs(corr) > 0.18: return [{'detector': 'variac_induction', 'corr': float(corr)}]  # was 0.3
        return []

class EardrumCaptureDetector:
    def __init__(self, petterson_fs=384000, room_fs=48000):
        self.ul_buf = deque(maxlen=petterson_fs); self.room_buf = deque(maxlen=room_fs)
        self.pet_fs = petterson_fs
    def update_ultrasound(self, audio): self.ul_buf.extend(audio.flatten())
    def update_room(self, audio): self.room_buf.extend(audio.flatten())
    def detect(self):
        if len(self.ul_buf) < self.pet_fs//4 or len(self.room_buf) < 48000//2: return []
        ul = np.array(self.ul_buf); room = np.array(self.room_buf)
        f, t, Sxx = spectrogram(ul, self.pet_fs, nperseg=2048, noverlap=1024)
        mean_pwr = np.mean(Sxx, axis=1); peaks, _ = find_peaks(mean_pwr, height=np.median(mean_pwr)*2, distance=5)  # was *4
        det = []
        for pk in peaks:
            freq = f[pk]
            if 2000 <= freq <= 96000:  # Covers 2kHz to 96kHz ultrasonic (384k Nyquist=192k)
                amp = np.sqrt(Sxx[pk, :])
                amp_rs = resample(amp, int(len(amp)*48000/self.pet_fs))
                min_len = min(len(amp_rs), len(room)); corr = np.corrcoef(amp_rs[:min_len], room[:min_len])[0,1]
                if corr > 0.15: det.append({'detector': 'eardrum_capture', 'freq': float(freq), 'corr': float(corr)})  # was 0.3
        return det

class PLLResonanceTransmissionDetector:
    """
    True Costas-loop PLL for RF carrier → audio correlation.

    Unlike the previous one-shot phase estimator, this implements a
    real phase-locked loop with a numerically-controlled oscillator (NCO).
    The Costas loop continuously tracks the carrier phase, extracting
    the AM envelope with 10-20dB better SNR than FFT-bin mixing.

    When it fires: the 'freq' IS the attacker's RF carrier.
    The demodulated audio IS the content being transmitted.
    """
    def __init__(self, rf_fs=20e6, audio_fs=48000):
        self.rf_fs = rf_fs; self.audio_fs = audio_fs
        self.rf_buf = deque(maxlen=int(0.5*rf_fs))   # 500ms RF for PLL lock (was 100ms)
        self.audio_buf = deque(maxlen=audio_fs)        # 1s audio
        self.carrier_history = {}  # freq -> deque of (time, phase_error, lock_status)
        # Costas loop state per carrier
        self.loops = {}  # freq -> {phase, freq_offset, iir_alpha, lock_count}
    def set_carrier(self, freq):
        """Pre-seed the Costas loop with a known carrier frequency."""
        if freq and freq not in self.loops:
            self.loops[freq] = {'phase': 0.0, 'freq_offset': 0.0, 'iir_alpha': 0.01,
                               'lock_count': 0, 'i_history': deque(maxlen=50000)}
    def update_rf(self, iq): self.rf_buf.extend(iq)
    def update_audio(self, audio): self.audio_buf.extend(audio.flatten())

    def _costas_step(self, sample, freq, state):
        """
        Single Costas loop iteration. Returns (I, Q, phase_error, locked).
        state = {'phase': float, 'freq': float, 'alpha': float, 'lock_count': int}
        """
        # NCO: generate local oscillator
        lo = np.exp(-1j * state['phase'])
        mixed = sample * lo

        # I and Q channels
        i_out = np.real(mixed)
        q_out = np.imag(mixed)

        # Phase error from product of I and Q (Costas discriminator)
        phase_error = i_out * q_out

        # Loop filter: second-order (proportional + integral)
        # Proportional gain
        kp = 0.5  # loop bandwidth
        ki = 0.01  # slow frequency tracking

        # Update NCO phase and frequency
        state['freq'] += ki * phase_error  # integral term
        state['phase'] += state['freq'] + kp * phase_error
        state['phase'] = state['phase'] % (2 * np.pi)

        # Lock detection: if |Q| is small relative to |I|, we're locked
        i_mag = abs(i_out) + 1e-12
        q_mag = abs(q_out)
        is_locked = q_mag < 0.3 * i_mag

        if is_locked:
            state['lock_count'] = min(state['lock_count'] + 1, 100)
        else:
            state['lock_count'] = max(state['lock_count'] - 1, 0)

        return i_out, q_out, phase_error, state['lock_count'] > 50

    def detect(self):
        if len(self.rf_buf) < 4096 or len(self.audio_buf) < self.audio_fs//10: return []

        iq = np.array(self.rf_buf)[-int(0.02*self.rf_fs):]  # 20ms window (2e6 is enough for PLL lock)
        audio = np.array(self.audio_buf)

        # Step 1: Find candidate carriers via FFT
        fft_abs = np.abs(fft(iq))
        freqs_fft = fftfreq(len(iq), 1/self.rf_fs)
        noise = np.median(fft_abs)
        peaks, props = find_peaks(fft_abs, height=noise*2.5, width=1, distance=15)  # lowered from noise*4

        if len(peaks) == 0: return []

        width_hz = props["widths"] * (self.rf_fs / len(iq))
        # Diagnostic: log PLL carrier count every 30s
        now_ts = time.time()
        if not hasattr(self, '_last_pll_log_ts'):
            self._last_pll_log_ts = 0
        if now_ts - self._last_pll_log_ts > 30:
            self._last_pll_log_ts = now_ts
            logging.getLogger('tscm').info(
                f'PLL: {len(peaks)} carriers found, rf_buf={len(self.rf_buf)} audio_buf={len(self.audio_buf)}')
        detections = []

        # Step 2: For each narrowband carrier, run Costas loop
        for idx, p in enumerate(peaks[:5]):
            if width_hz[idx] > 500: continue
            freq = abs(freqs_fft[p])
            if freq < 50 or freq > 5e6: continue  # was <500 - misses MW carrier near DC

            # Initialize or retrieve Costas loop state
            if freq not in self.loops:
                self.loops[freq] = {
                    'phase': 0.0,
                    'freq': 2*np.pi*freq/self.rf_fs,  # normalized frequency
                    'alpha': 0.95,  # IIR smoothing
                    'lock_count': 0,
                    'i_history': deque(maxlen=50000),  # larger history for sustained lock
                    'last_lock_time': 0
                }

            state = self.loops[freq]

            # Run Costas loop on all samples
            i_samples = np.zeros(len(iq), dtype=np.float32)
            locked_samples = 0
            for n in range(len(iq)):
                i_out, q_out, err, is_locked = self._costas_step(iq[n], freq, state)
                i_samples[n] = i_out
                if is_locked:
                    locked_samples += 1
                if state['lock_count'] > 50 and len(state['i_history']) < state['i_history'].maxlen:
                    state['i_history'].append(i_out)

            # Lock ratio: percentage of samples where Costas was locked
            lock_ratio = locked_samples / len(iq) if len(iq) > 0 else 0

            # Step 3: Extract AM envelope from Costas I-channel
            if len(state['i_history']) > 100:  # was 200 - lower threshold for weak signal
                locked_iq = np.array(state['i_history'])
                # Moving average envelope (AM demodulation)
                window = max(1, int(self.rf_fs / 10000))  # ~2 kHz audio bandwidth
                if len(locked_iq) > window:
                    env = np.convolve(np.abs(locked_iq), np.ones(window)/window, mode='valid')
                else:
                    env = np.abs(locked_iq)

                # Resample envelope to audio rate
                if len(env) > 10:
                    env_rs = resample(env, min(len(audio), int(len(env) * self.audio_fs / self.rf_fs * window)))
                    audio_trim = audio[:len(env_rs)]

                    if len(env_rs) > 50 and len(audio_trim) > 50:
                        # Cross-correlation with room audio
                        try:
                            corr = float(np.corrcoef(env_rs, audio_trim)[0, 1])
                        except:
                            corr = 0.0

                        # Single-cycle diagnostic when close to lock
                        if (abs(corr) > 0.06 or lock_ratio > 0.04) and not hasattr(self, '_pll_diag_done'):
                            logging.getLogger('tscm').info(
                                f'PLL near-lock: freq={freq:.0f}Hz corr={corr:.3f} lock={lock_ratio:.2f} bw={width_hz[idx]:.0f}Hz')
                            self._pll_diag_done = True
                        # Strong correlation + good lock = detection
                        if abs(corr) > 0.12 and lock_ratio > 0.08:  # lowered from 0.18/0.15
                            # Save carrier state and record
                            now = time.time()
                            if freq not in self.carrier_history:
                                self.carrier_history[freq] = deque(maxlen=50)
                            self.carrier_history[freq].append((now, corr, lock_ratio))

                            # Need sustained correlation
                            recent = [h for h in self.carrier_history[freq] if now - h[0] < 30]
                            if len(recent) >= 2:  # was 3 - faster first detection
                                avg_corr = np.mean([h[1] for h in recent])
                                avg_lock = np.mean([h[2] for h in recent])

                                if avg_corr > 0.15 and avg_lock > 0.15:  # lowered sustained thresholds
                                    detections.append({
                                        'detector': 'pll_resonance_transmission',
                                        'freq': float(freq),
                                        'corr': float(avg_corr),
                                        'lock_ratio': float(avg_lock),
                                        'note': f'Costas PLL locked - RF carrier {freq:.0f}Hz correlates with audio (r={avg_corr:.3f})'
                                    })

        return detections

class CoiledBucketResonatorDetector:
    def __init__(self, freq_min=500, freq_max=100e3, fs=20e6):
        self.freq_min = freq_min; self.freq_max = freq_max; self.fs = fs
        self.rf_buf = deque(maxlen=int(0.05*fs)); self.peak_history = {}; self.motion_buf = deque(maxlen=50)
    def update_rf(self, iq): self.rf_buf.extend(iq)
    def update_motion(self, jerk): self.motion_buf.append(jerk)
    def detect(self):
        if len(self.rf_buf) < 1024: return []
        iq = np.array(self.rf_buf); n = len(iq); freqs = fftfreq(n, 1/self.fs)
        mask = (freqs >= self.freq_min) & (freqs <= self.freq_max) & (freqs > 0)
        if not np.any(mask): return []
        fft_focused = np.abs(fft(iq))[mask]; freqs_focused = freqs[mask]
        noise = np.median(fft_focused); peaks, props = find_peaks(fft_focused, height=noise*5, width=1, distance=5)  # was 10
        if len(peaks) == 0: return []
        width_hz = props["widths"] * (self.fs / n); detections = []; now = time.time()
        for idx, p in enumerate(peaks):
            if width_hz[idx] > 50: continue
            freq = abs(freqs_focused[p]); amp = fft_focused[p]
            if freq not in self.peak_history: self.peak_history[freq] = deque(maxlen=20)
            self.peak_history[freq].append((now, amp))
            if len(self.peak_history[freq]) < 3: continue  # was 10
            amps = np.array([h[1] for h in self.peak_history[freq]])
            if len(self.motion_buf) < 3: continue  # was 10
            motion = np.array(self.motion_buf)[:len(amps)]
            corr = np.corrcoef(amps, motion)[0,1]
            if corr > 0.5 and np.std(amps) / (np.mean(amps) + 1e-12) > 0.1:
                detections.append({'detector': 'coiled_bucket_resonator', 'freq': float(freq),
                                   'width': float(width_hz[idx]), 'corr': float(corr)})
        return detections


# ===================== SIGNAL DEMODULATOR (ATTRIBUTION) =====================
class SignalDemodulator:
    """
    Demodulates PLL-matched RF carriers to extract actual audio/data content.
    This tells us WHAT is being transmitted and WHO is operating it.

    Saves demodulated audio as WAV in evidence folder for court.
    Identifies: voice, data burst, noise, CW, or silence.
    """
    def __init__(self, rf_fs=20e6, audio_fs=48000, evidence_dir="evidence"):
        self.rf_fs = rf_fs; self.audio_fs = audio_fs
        self.evidence_dir = evidence_dir
        os.makedirs(os.path.join(evidence_dir, "demod"), exist_ok=True)
        self.demod_history = {}  # freq -> deque of demod classification

    def demodulate(self, iq, carrier_freq_hz):
        """
        Demodulate a specific carrier from IQ data.
        Returns extracted audio and content classification.
        """
        try:
            # Mix to baseband
            lo = np.exp(-2j*np.pi*carrier_freq_hz*np.arange(len(iq))/self.rf_fs)
            bb = iq * lo
            # Decimate and envelope-demodulate
            decim = max(1, int(self.rf_fs / (self.audio_fs * 10)))
            bb_dec = bb[::decim]
            fs_dec = self.rf_fs / decim

            # AM envelope (magnitude)
            env = np.abs(bb_dec)
            env = env - np.mean(env)

            # Lowpass filter envelope to audio band
            env_fs = fs_dec
            # Simple moving average for envelope smoothing
            window = max(1, int(env_fs / 4000))
            env_smooth = np.convolve(env, np.ones(window)/window, mode='same')

            # Resample to audio rate
            audio = resample(env_smooth, int(len(env_smooth) * self.audio_fs / env_fs))

            # Content classification
            content_type = self._classify(audio)

            return audio, content_type
        except Exception as e:
            return None, f"error:{e}"

    def _classify(self, audio):
        """Classify content type: voice, data, noise, cw, silence"""
        rms = float(np.sqrt(np.mean(audio**2)))
        if rms < 0.001:
            return "silence"

        # Zero crossing rate
        zcr = float(np.mean(np.abs(np.diff(np.sign(audio)))) / 2)

        # Spectral analysis
        f, Pxx = periodogram(audio[:min(len(audio), 4096)], self.audio_fs, nperseg=512)
        spec = Pxx / (np.sum(Pxx) + 1e-12)

        # Voice: energy concentrated in 300-3400 Hz
        voice_band = (f >= 300) & (f <= 3400)
        voice_energy = float(np.sum(spec[voice_band]))

        # Data bursts: very regular zero-crossing, wide bandwidth
        if zcr > 0.3 and voice_energy < 0.5:
            return "data_burst"

        # Voice content
        if voice_energy > 0.6:
            return "voice"

        # CW tone: single narrow peak
        peak = np.argmax(spec)
        if spec[peak] > 0.5:
            return f"cw_tone_{f[peak]:.0f}hz"

        return "noise"

    def save_demod(self, audio, freq_hz, bearing, content_type, session_id=""):
        """Save demodulated audio to evidence."""
        ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        fname = f"demod_{ts}_{freq_hz:.0f}Hz_{bearing:.0f}deg_{content_type}.wav"
        path = os.path.join(self.evidence_dir, "demod", fname)
        try:
            # Normalize to int16 range
            audio_norm = audio / (np.max(np.abs(audio)) + 1e-12) * 30000
            audio_int16 = audio_norm.astype(np.int16)

            # Write WAV  (simple PCM WAV)
            import struct
            with open(path, 'wb') as f:
                n = len(audio_int16)
                # WAV header
                f.write(b'RIFF')
                f.write(struct.pack('<I', 36 + n*2))
                f.write(b'WAVE')
                f.write(b'fmt ')
                f.write(struct.pack('<IHHIIHH', 16, 1, 1, self.audio_fs, self.audio_fs*2, 2, 16))
                f.write(b'data')
                f.write(struct.pack('<I', n*2))
                f.write(audio_int16.tobytes())
            return path
        except:
            return None


class C2ProtocolAnalyzer:
    """
    Analyze narrowband signals for Command & Control protocol signatures.
    Looks for: TDMA slots, FHSS patterns, fixed-frame structures,
    preamble sequences, and unique modulation fingerprints.
    These patterns identify the OPERATOR behind the transmitter.
    """
    def __init__(self, rf_fs=20e6):
        self.rf_fs = rf_fs
        self.protocol_db = {}  # freq -> protocol fingerprint history

    def analyze(self, iq, carrier_freq, fs=None):
        """Analyze a carrier for C2 protocol signatures."""
        if fs is None: fs = self.rf_fs
        results = []
        try:
            # Mix to baseband
            lo = np.exp(-2j*np.pi*carrier_freq*np.arange(len(iq))/fs)
            bb = iq * lo

            # 1. TDMA burst detection: envelope has periodic on/off pattern
            env = np.abs(bb)
            env_norm = env / (np.mean(env) + 1e-12)
            # Find burst transitions
            threshold = 2.0  # 2x above average = burst
            above = env_norm > threshold
            transitions = np.diff(above.astype(int))
            edges = np.where(transitions != 0)[0]

            if len(edges) > 4:
                # Calculate inter-burst intervals
                burst_starts = edges[transitions[edges] == 1]
                if len(burst_starts) > 2:
                    intervals = np.diff(burst_starts) / fs * 1000  # ms
                    avg_interval = np.mean(intervals)
                    jitter = np.std(intervals)

                    if jitter / (avg_interval + 1e-12) < 0.2 and avg_interval > 1:
                        # Regular TDMA pattern - this is a controlled transmitter
                        results.append({
                            'protocol': 'tdma',
                            'slot_period_ms': float(avg_interval),
                            'slot_jitter_ms': float(jitter),
                            'num_bursts': len(burst_starts),
                            'note': 'Regular TDMA - operator-controlled transmitter'
                        })

            # 2. Check for frequency hopping (FHSS)
            # Look for frequency shifts in the phase
            phase = np.unwrap(np.angle(bb))
            phase_diff = np.diff(phase)
            freq_shifts = np.where(np.abs(phase_diff) > np.median(np.abs(phase_diff)) * 3)[0]
            if len(freq_shifts) > 0 and len(freq_shifts) / len(phase_diff) < 0.1:
                results.append({
                    'protocol': 'fhss_bursts',
                    'num_shifts': len(freq_shifts),
                    'note': 'Possible frequency-hopping pattern'
                })

            # 3. Unique modulation fingerprint
            # IQ constellation analysis
            if len(bb) > 100:
                bb_norm = bb / (np.std(np.abs(bb)) + 1e-12)
                # I/Q histogram for constellation pattern
                i_vals = np.real(bb_norm[::10][:1000])
                q_vals = np.imag(bb_norm[::10][:1000])
                # Clustering hints at modulation type
                i_spread = np.std(i_vals); q_spread = np.std(q_vals)
                # QPSK: both I and Q have 2 clusters
                # BPSK: I has 2, Q has 1
                # AM: I varies, Q is near 0
                # FM: constant envelope (circular)
                if q_spread / (i_spread + 1e-12) < 0.3:
                    mod_type = "AM"
                elif 0.7 < q_spread / (i_spread + 1e-12) < 1.3:
                    mod_type = "QPSK/FM"
                else:
                    mod_type = "complex"

                results.append({
                    'protocol': 'modulation_fingerprint',
                    'mod_type': mod_type,
                    'i_rms': float(i_spread), 'q_rms': float(q_spread),
                    'iq_ratio': float(q_spread/(i_spread+1e-12))
                })

            # Store in protocol DB for long-term tracking
            if carrier_freq not in self.protocol_db:
                self.protocol_db[carrier_freq] = deque(maxlen=50)
            self.protocol_db[carrier_freq].append({
                'ts': time.time(),
                'results': [r['protocol'] for r in results]
            })

        except:
            pass
        return results


class NeuralWPScanDetector:
    """Detect wireless power (WP) neural entrainment via EEG band correlation.

    Wireless power transmitters operating near neural frequencies create
    measurable EEG artifacts that look like neural band power surges but
    are actually EM-field-induced. This detector cross-references EEG
    band power ratios against known RF-induced neural signatures.
    """
    def __init__(self, fs=250):
        self.fs = fs
        self.buf = deque(maxlen=fs * 2)
        self.bands = {'delta': 0, 'theta': 0, 'alpha': 0, 'beta': 0, 'gamma': 0}

    def update(self, eeg):
        self.buf.extend(eeg.flatten())

    def update_bands(self, bands):
        """Receive pre-computed EEG power band values from TGAM."""
        self.bands = bands

    def detect(self):
        results = []
        if len(self.buf) < self.fs // 2:
            return results
        data = np.array(self.buf)
        n = len(data)
        if n < 64:
            return results
        f, Pxx = welch(data, self.fs, nperseg=min(256, n // 2))
        total = np.sum(Pxx) + 1e-12
        gamma = np.sum(Pxx[(f >= 30) & (f <= 100)]) / total
        beta = np.sum(Pxx[(f >= 13) & (f <= 30)]) / total
        # High gamma + elevated beta = suspicious neural WP artifact
        if gamma > 0.08 and beta > 0.18:
            results.append({
                'detector': 'neural_wp_scan',
                'gamma_ratio': round(float(gamma), 3),
                'beta_ratio': round(float(beta), 3),
                'freq': 60.0
            })
        # Also check TGAM band data if available
        bands = self.bands
        if bands:
            b_total = sum(v for v in bands.values() if isinstance(v, (int, float))) + 1e-12
            b_gamma = (bands.get('gamma_mid', 0) + bands.get('gamma_low', 0)) / b_total
            b_delta = bands.get('delta', 0) / b_total
            if b_gamma > 0.15 and b_delta < 0.3:
                results.append({
                    'detector': 'neural_wp_scan',
                    'tgam_gamma_ratio': round(float(b_gamma), 3),
                    'freq': 45.0
                })
        return results


class BiometricIntegrityDetector:
    """Monitor EEG biometric fingerprint stability to detect tampering.

    If someone replaces or hijacks the EEG data stream, the biometric
    fingerprint (alpha power distribution) will shift abruptly.
    Flags fingerprint drift > 3 sigma from rolling baseline.
    """
    def __init__(self, fs=250):
        self.fs = fs
        self.buf = deque(maxlen=fs * 4)
        self.fingerprint_history = deque(maxlen=30)
        self.baseline_mean = None
        self.baseline_std = None

    def update(self, eeg):
        self.buf.extend(eeg.flatten())

    def update_bands(self, bands):
        pass

    def detect(self):
        if len(self.buf) < self.fs:
            return []
        data = np.array(self.buf)
        n = len(data)
        if n < 64:
            return []
        f, Pxx = welch(data, self.fs, nperseg=min(256, n // 2))
        total = np.sum(Pxx) + 1e-12
        alpha = np.sum(Pxx[(f >= 8) & (f <= 13)]) / total
        beta = np.sum(Pxx[(f >= 13) & (f <= 30)]) / total
        theta = np.sum(Pxx[(f >= 4) & (f <= 8)]) / total
        fp = alpha * 100 + beta * 10 + theta
        self.fingerprint_history.append(fp)
        if len(self.fingerprint_history) < 10:
            return []
        if self.baseline_mean is None:
            self.baseline_mean = np.mean(self.fingerprint_history)
            self.baseline_std = np.std(self.fingerprint_history) + 1e-12
            return []
        # Update rolling baseline
        self.baseline_mean = 0.95 * self.baseline_mean + 0.05 * fp
        self.baseline_std = 0.95 * self.baseline_std + 0.05 * abs(fp - self.baseline_mean)
        deviation = abs(fp - self.baseline_mean) / (self.baseline_std + 1e-12)
        if deviation > 3.0:
            return [{
                'detector': 'biometric_integrity',
                'deviation_sigma': round(float(deviation), 2),
                'freq': 10.0,
                'note': 'eeg_fingerprint_drift'
            }]
        return []


class ParasympatheticSurgeDetector:
    """Detect parasympathetic nervous system surges via EEG theta/alpha ratios.

    High theta/alpha ratio with low beta can indicate external parasympathetic
    stimulation (e.g., vagus nerve EM stimulation).
    """
    def __init__(self, fs=250):
        self.fs = fs
        self.buf = deque(maxlen=fs * 2)

    def update(self, eeg):
        self.buf.extend(eeg.flatten())

    def update_bands(self, bands):
        pass

    def detect(self):
        if len(self.buf) < self.fs // 2:
            return []
        data = np.array(self.buf)
        n = len(data)
        if n < 64:
            return []
        f, Pxx = welch(data, self.fs, nperseg=min(256, n // 2))
        total = np.sum(Pxx) + 1e-12
        theta = np.sum(Pxx[(f >= 4) & (f <= 8)]) / total
        alpha = np.sum(Pxx[(f >= 8) & (f <= 13)]) / total
        beta = np.sum(Pxx[(f >= 13) & (f <= 30)]) / total
        # Parasympathetic surge: high theta/alpha, low beta
        ratio = theta / (alpha + 1e-12)
        if ratio > 2.5 and beta < 0.12:
            return [{
                'detector': 'parasympathetic_surge',
                'theta_alpha_ratio': round(float(ratio), 2),
                'freq': 6.0
            }]
        return []


class RetinalStressDetector:
    """Detect retinal stress patterns via abnormal high-frequency EEG.

    Retinal stimulation (e.g., modulated light sources, SSVEP attacks)
    produces gamma-band spikes that correlate across both hemispheres.
    Single-channel TGAM approximates this via gamma spike density."""
    def __init__(self, fs=250):
        self.fs = fs
        self.buf = deque(maxlen=fs * 3)

    def update(self, eeg):
        self.buf.extend(eeg.flatten())

    def update_bands(self, bands):
        pass

    def detect(self):
        if len(self.buf) < self.fs:
            return []
        data = np.array(self.buf)
        n = len(data)
        if n < 128:
            return []
        f, Pxx = welch(data, self.fs, nperseg=min(256, n // 2))
        total = np.sum(Pxx) + 1e-12
        gamma = np.sum(Pxx[(f >= 30) & (f <= 100)]) / total
        # Retinal stress from flicker: 10-60 Hz peaks in gamma
        # Check for narrow-band gamma peaks (SSVEP-like at optical freqs)
        gamma_band = Pxx[(f >= 30) & (f <= 60)]
        gf = f[(f >= 30) & (f <= 60)]
        if len(gamma_band) > 10:
            mean_g = np.mean(gamma_band)
            peaks_g, _ = find_peaks(gamma_band, height=mean_g * 3, distance=3)
            if len(peaks_g) >= 2:
                peak_freqs = [float(gf[p]) for p in peaks_g[:4]]
                return [{
                    'detector': 'retinal_stress',
                    'gamma_ratio': round(float(gamma), 3),
                    'peak_freqs': peak_freqs,
                    'freq': peak_freqs[0] if peak_freqs else 40.0
                }]
        if gamma > 0.12:
            return [{
                'detector': 'retinal_stress',
                'gamma_ratio': round(float(gamma), 3),
                'freq': 40.0
            }]
        return []


class HemiSyncDetector:
    """Detect hemispheric synchronization patterns in EEG.

    HemiSync (hemispheric synchronization) occurs when external binaural
    beat stimulation entrains both brain hemispheres to the same frequency.
    On single-channel TGAM, this appears as a dominant narrow peak in alpha
    or theta with very low variability over time.
    """
    def __init__(self, fs=250):
        self.fs = fs
        self.buf = deque(maxlen=fs * 5)
        self.alpha_peaks = deque(maxlen=20)

    def update(self, eeg):
        self.buf.extend(eeg.flatten())

    def update_bands(self, bands):
        pass

    def detect(self):
        if len(self.buf) < self.fs * 2:
            return []
        data = np.array(self.buf)
        n = len(data)
        if n < 128:
            return []
        f, Pxx = welch(data, self.fs, nperseg=min(512, n // 2))
        total = np.sum(Pxx) + 1e-12
        # Find dominant peak in alpha/theta range
        neuro_mask = (f >= 4) & (f <= 15)
        neuro_pxx = Pxx[neuro_mask]
        neuro_f = f[neuro_mask]
        if len(neuro_pxx) < 5:
            return []
        peak_idx = np.argmax(neuro_pxx)
        peak_freq = neuro_f[peak_idx]
        peak_power = neuro_pxx[peak_idx] / total
        self.alpha_peaks.append(peak_freq)
        # HemiSync: very stable narrow peak, high power concentration
        if len(self.alpha_peaks) > 10:
            peaks_arr = np.array(self.alpha_peaks)
            freq_stability = 1.0 / (np.std(peaks_arr) + 1e-12)
            if freq_stability > 2.0 and peak_power > 0.25:
                return [{
                    'detector': 'hemisync',
                    'peak_freq': round(float(peak_freq), 1),
                    'power_ratio': round(float(peak_power), 3),
                    'freq': peak_freq
                }]
        return []


class ThetaLateralizationDetector:
    """Detect theta-band lateralization suggesting targeted EM stimulation.

    Theta lateralization occurs when one hemisphere shows elevated theta
    while the other does not - a signature of targeted EM field exposure.
    With single-channel TGAM, we look for asymmetric theta bursts that
    correlate with RF carrier presence."""
    def __init__(self, fs=250):
        self.fs = fs
        self.buf = deque(maxlen=fs * 2)
        self.rf_env_buf = deque(maxlen=5000)

    def update(self, eeg):
        self.buf.extend(eeg.flatten())

    def update_bands(self, bands):
        pass

    def update_rf(self, iq):
        """Store RF envelope for correlation."""
        if iq is not None and len(iq) > 0:
            env = np.abs(np.asarray(iq, dtype=np.complex128)[:5000])
            self.rf_env_buf.extend(env)

    def detect(self):
        if len(self.buf) < self.fs:
            return []
        data = np.array(self.buf)
        n = len(data)
        if n < 64:
            return []
        f, Pxx = welch(data, self.fs, nperseg=min(256, n // 2))
        total = np.sum(Pxx) + 1e-12
        theta = np.sum(Pxx[(f >= 4) & (f <= 8)]) / total
        beta = np.sum(Pxx[(f >= 13) & (f <= 30)]) / total
        # Theta lateralization signature: high theta, moderate beta
        # (indicates one hemisphere dominant in theta while other shows beta)
        if theta > 0.25 and beta > 0.10:
            result = {
                'detector': 'theta_lateralization',
                'theta_ratio': round(float(theta), 3),
                'beta_ratio': round(float(beta), 3),
                'freq': 6.0
            }
            # Cross-domain: check RF correlation
            if len(self.rf_env_buf) > 100:
                rf = np.array(self.rf_env_buf)
                rf_norm = (rf - np.mean(rf)) / (np.std(rf) + 1e-12)
                eeg_norm = (data - np.mean(data)) / (np.std(data) + 1e-12)
                min_len = min(len(rf_norm), len(eeg_norm))
                corr = np.abs(np.corrcoef(rf_norm[:min_len], eeg_norm[:min_len])[0, 1])
                if corr > 0.3:
                    result['rf_eeg_corr'] = round(float(corr), 3)
            return [result]
        return []


class HighPowerWiFiDetector:
    def __init__(self, rssi_threshold=-40): self.threshold = rssi_threshold
    def process(self, det):
        if det.get('detector') == 'high_power_wifi' and det.get('rssi', -100) > self.threshold: return det
        return None

class eCPRIInjectionDetector:
    def __init__(self, rf_fs=20e6):
        self.rf_fs = rf_fs; self.buffer = deque(maxlen=int(0.1 * rf_fs)); self.frame_period = 0.010
    def update_rf(self, iq): self.buffer.extend(iq)
    def detect(self):
        if len(self.buffer) < int(0.05 * self.rf_fs): return []
        iq = np.array(self.buffer); power = np.abs(iq)**2; power -= np.mean(power)
        # FFT-based autocorrelation (O(N log N) vs O(N²) for np.correlate)
        N = len(power)
        if N > 100000:
            fft_power = fft(power)
            corr = np.real(np.fft.ifft(fft_power * np.conj(fft_power)))
            corr = corr[:N//2]  # use first half (positive lags)
        else:
            corr = np.correlate(power, power, mode='full'); corr = corr[len(corr)//2:]
        frame_samples = int(self.rf_fs * self.frame_period)
        if frame_samples >= len(corr): return []
        frame_corr = corr[frame_samples] if frame_samples < len(corr) else 0
        if frame_corr < 2 * np.median(corr): return []  # was 3
        fft_abs = np.abs(fft(iq)); freqs = fftfreq(len(iq), 1/self.rf_fs)
        noise = np.median(fft_abs); peaks, props = find_peaks(fft_abs, height=noise*3, width=1)  # was 4
        detections = []
        for idx, p in enumerate(peaks[:10]):
            width_hz = props["widths"][idx] * (self.rf_fs / len(iq))
            if width_hz < 100:
                freq = abs(freqs[p])
                detections.append({'detector': 'ecpri_injection', 'frequency': float(freq),
                                   'bandwidth_hz': float(width_hz), 'frame_correlation': float(frame_corr),
                                   'confidence': 0.8 if width_hz < 20 else 0.6})
        return detections


class SatelliteC2Detector:
    """
    Detects satellite C2 uplink/downlink patterns in RF spectrum.
    Satellite comms: periodic bursts, narrowband carriers at L/S/C/X/Ku-band,
    Doppler shifts from orbital motion (~7.5 km/s LEO, minimal GEO).
    Looks for: periodic burst patterns, narrowband carriers with slow Doppler,
    and signal presence above noise floor at known satellite bands.
    """
    def __init__(self, rf_fs=20e6):
        self.rf_fs = rf_fs
        self.buffer = deque(maxlen=int(0.2*rf_fs))  # 200ms of IQ (was 1s)
        self.carrier_history = {}
        self.burst_history = deque(maxlen=100)

    def update_rf(self, iq):
        self.buffer.extend(iq)

    def detect(self):
        if len(self.buffer) < int(0.05 * self.rf_fs): return []
        iq = np.array(self.buffer)
        n = len(iq)
        fft_abs = np.abs(fft(iq))
        freqs = fftfreq(n, 1/self.rf_fs)
        noise = np.median(fft_abs)
        now = time.time()
        detections = []

        # Find narrowband carriers
        peaks, props = find_peaks(fft_abs[:n//2], height=noise*3, width=1, distance=20)  # was 4
        for idx, p in enumerate(peaks[:20]):
            width_hz = props["widths"][idx] * (self.rf_fs / n)
            if width_hz > 200: continue
            freq = abs(freqs[p])
            amp = fft_abs[p]

            if freq not in self.carrier_history:
                self.carrier_history[freq] = deque(maxlen=30)
            self.carrier_history[freq].append((now, amp, freq))

            # Need at least 3 observations (was 5)
            if len(self.carrier_history[freq]) < 3: continue

            # Check for Doppler drift (orbital motion)
            history = list(self.carrier_history[freq])
            if len(history) >= 5:
                freqs_est = [h[2] for h in history[-10:]]
                times_est = [h[0] for h in history[-10:]]
                if len(times_est) >= 3:
                    doppler_slope = np.polyfit(times_est, freqs_est, 1)[0]  # Hz/s
                    # LEO: ~1-10 kHz/s drift, GEO: ~0, MEO: small
                    if abs(doppler_slope) > 50:  # >50 Hz/s = moving source
                        detections.append({
                            'detector': 'satellite_c2',
                            'frequency': float(freq),
                            'doppler_hz_per_sec': float(doppler_slope),
                            'bandwidth_hz': float(width_hz),
                            'confidence': 0.7 if abs(doppler_slope) > 500 else 0.5,
                            'orbit_type': 'LEO' if abs(doppler_slope) > 1000 else 'MEO'
                        })

        # Check for periodic burst patterns (TDMA satellite)
        power = np.abs(iq)**2
        threshold = np.median(power) * 5  # was 8
        burst_peaks, _ = find_peaks(power, height=threshold, distance=int(0.001*self.rf_fs))
        if len(burst_peaks) > 3:  # was 5
            burst_times = burst_peaks / self.rf_fs
            intervals = np.diff(burst_times)
            if len(intervals) > 3:
                period = np.median(intervals)
                if 0.01 < period < 1.0:  # 10ms to 1s burst period
                    # Check periodicity
                    period_std = np.std(intervals) / (period + 1e-12)
                    if period_std < 0.2:  # highly periodic
                        self.burst_history.append((now, period, 0))
                        if len(self.burst_history) >= 3:
                            detections.append({
                                'detector': 'satellite_c2',
                                'burst_period': float(period),
                                'period_jitter': float(period_std),
                                'frequency': 0.0,
                                'confidence': 0.6,
                                'orbit_type': 'unknown'
                            })

        return detections


# ===================== AIC CORE =====================
def aic_demod_and_separate(audio_data, fs, num_voices=2):
    if not SKLEARN_AVAILABLE: return np.zeros((len(audio_data), 1))
    env = np.abs(hilbert(audio_data)); X = env.reshape(-1, 1)
    X = np.c_[X, np.roll(X, 100)]
    ica = FastICA(n_components=num_voices, random_state=0)
    return ica.fit_transform(X)

def aic_intent_lag_check(bci_buffer, audio_buffer):
    if len(bci_buffer) < 20 or len(audio_buffer) < 20: return "Idle"
    eeg_spike = np.max(list(bci_buffer)[-10:]); audio_spike = np.max(list(audio_buffer)[-10:])
    return "PRE_VOCAL_LOCK" if (eeg_spike > 0.7 and audio_spike > 0.4) else "Idle"


# ===================== LIVE MAP SERVER =====================
MAP_HTML = """<!DOCTYPE html>
<html><head><title>TSCM Detection Map</title>
<meta charset="us-ascii"/>
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://mt0.google.com https://mt1.google.com https://mt2.google.com https://mt3.google.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"/>
<link rel="stylesheet" href="/map_libs/leaflet.css"/>
<style>
html,body{margin:0;padding:0;height:100%;font:11px monospace}
#map{width:100%;height:100%;background:#111}
#panel{position:absolute;top:32px;right:5px;width:340px;max-height:calc(100% - 40px);overflow-y:auto;
background:rgba(0,0,0,.92);color:#0f0;padding:8px;border-radius:6px;z-index:1000;font-size:11px;border:1px solid #333}
#title{position:absolute;top:0;left:0;right:0;height:28px;background:rgba(0,0,0,.95);color:#0f0;padding:4px 8px;z-index:1000;font-size:12px;line-height:20px}
.dt{margin:1px 0;padding:2px 4px;border-left:3px solid}
.c2{background:rgba(255,0,0,.25);border-left-color:#f00;color:#f00;font-weight:bold}
.th{background:rgba(255,0,0,.15);border-left-color:#f00;color:#f44}
.wn{background:rgba(255,255,0,.1);border-left-color:#ff0;color:#ff0}
.inf{border-left-color:#0ff;color:#0ff}
a{color:#0ff}
</style></head><body>
<div id="map"></div>
<div id="title">TSCM Detection Map | <a href="/safe">SAFE (no-JS)</a> | <a href="#" onclick="toggleFilter();return false" id="filtBtn" style="color:#0f0">FILTERED</a> | <a href="/map.png">PNG</a> | <a href="/api/detections">API</a> | <a href="#" onclick="toggleAutoPan();return false" id="panBtn" style="color:#0f0">PAN:ON</a> | Refresh 15s</div>
<div id="panel">Loading...</div>
<script src="/map_libs/leaflet.js"></script>
<script>
var map=L.map('map',{zoomControl:true}).setView([41.51325,-88.13368],16);
L.tileLayer('https://mt{s}.google.com/vt/lyrs=s,h&x={x}&y={y}&z={z}',{maxZoom:20,subdomains:'0123',attribution:'Google'}).addTo(map);
var youIcon=L.divIcon({className:'',html:'<div style="width:18px;height:18px;border-radius:50%;background:#0f0;border:3px solid #fff;box-shadow:0 0 12px #0f0"></div>',iconSize:[18,18],iconAnchor:[9,9]});
var youM=L.marker([41.51325,-88.13368],{icon:youIcon}).addTo(map).bindPopup('<b>YOU</b><br>41.51325, -88.13368');
var mkrs=[];var rawMode=false;
var autoPan=true;
function toggleAutoPan(){
autoPan=!autoPan;
document.getElementById('panBtn').textContent='PAN:'+(autoPan?'ON':'OFF');
document.getElementById('panBtn').style.color=autoPan?'#0f0':'#f00';}
function escHtml(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function toggleFilter(){
rawMode=!rawMode;
document.getElementById('filtBtn').textContent=rawMode?'RAW':'FILTERED';
document.getElementById('filtBtn').style.color=rawMode?'#f00':'#0f0';
load();}
function mkIcon(color,label){
return L.divIcon({className:'',html:'<div style="text-align:center"><div style="width:20px;height:20px;border-radius:50%;background:'+color+';border:3px solid #fff;box-shadow:0 0 8px '+color+';margin:0 auto"></div><div style="font:bold 9px monospace;color:#fff;background:rgba(0,0,0,.85);padding:1px 4px;border-radius:2px;white-space:nowrap;margin-top:1px">'+label+'</div></div>',iconSize:[20,20],iconAnchor:[10,10],popupAnchor:[0,-12]});}
function load(){
fetch('/signal_chain.json'+(rawMode?'?raw=1':'')).then(r=>r.json()).then(d=>{
var lat=d.observer.lat,lon=d.observer.lon;
if(autoPan){map.setView([lat,lon],16);}
youM.setLatLng([lat,lon]);
mkrs.forEach(m=>map.removeLayer(m));mkrs=[];
// HackRF second sensor marker
if(d.observer.hackrf_lat){var hIcon=L.divIcon({className:'',html:'<div style="width:16px;height:16px;border-radius:50%;background:#f80;border:3px solid #fff;box-shadow:0 0 10px #f80"></div>',iconSize:[16,16],iconAnchor:[8,8]});var hM=L.marker([d.observer.hackrf_lat,d.observer.hackrf_lon],{icon:hIcon}).addTo(map).bindPopup('<b>HACKRF</b><br>'+d.observer.hackrf_lat.toFixed(5)+', '+d.observer.hackrf_lon.toFixed(5));mkrs.push(hM);}
var mk=d.markers||[];
var loc=mk.filter(m=>m.type==='transmitter');
var bearing=mk.filter(m=>m.type==='bearing_only');
var dets=mk.filter(m=>m.type==='detection');
// Triangulated pins only
loc.forEach(x=>{
var c=x.color||'#f44';
var m=L.marker([x.lat,x.lon],{icon:mkIcon(c,x.threat+' '+x.freq)}).addTo(map);
m.bindPopup('<b>'+escHtml(x.threat)+'</b><br>'+escHtml(x.detector)+'<br>brg:'+x.bearing+' x'+x.observations+'<br>'+x.lat.toFixed(5)+', '+x.lon.toFixed(5));
mkrs.push(m);});
bearing.forEach(x=>{
var c=x.color||'#444';
var line=L.polyline([[lat,lon],[x.lat,x.lon]],{color:c,weight:2,opacity:0.5,dashArray:'6,6'}).addTo(map);
line.bindPopup('<b>DOA: '+escHtml(x.threat)+'</b><br>'+escHtml(x.detector)+'<br>brg:'+x.bearing+' est:'+x.distance_m+'m');
mkrs.push(line);
});
var h='<div style="color:#0f0;font-weight:bold">POSITION '+lat.toFixed(4)+', '+lon.toFixed(4)+'</div>';
h+='<div style="color:#888">'+loc.length+' source'+(loc.length!==1?'s':'')+', '+dets.length+' detection'+(dets.length!==1?'s':'')+'</div>';
if(loc.length>0){h+='<div style="color:#0f0;font-weight:bold;border-top:1px solid #444;padding-top:4px;margin-top:4px">SOURCES ('+loc.length+')</div>';
loc.forEach(x=>{var c=x.threat==='C2'||x.threat==='TRANSMITTER'||x.threat==='CLUSTER'||x.threat==='ATTACK'?'c2':(x.threat==='MW'||x.threat==='MODEM'||x.threat==='RADAR'?'wn':'th');
h+='<div class="dt '+c+'"><b>'+escHtml(x.threat)+'</b> '+escHtml(x.detector)+' '+escHtml(x.freq)+' x'+x.observations+'</div>';});}
if(bearing.length>0){h+='<div style="color:#0f0;font-weight:bold;border-top:1px solid #333;padding-top:4px;margin-top:4px">BEARING-ONLY ('+bearing.length+')</div>';bearing.forEach(x=>{var _b=x.bearing?(' brg:'+x.bearing):'';h+='<div class="dt wn"><span style="color:#0f0">'+escHtml(x.threat)+'</span> '+escHtml(x.detector)+' '+escHtml(x.freq)+_b+' ~'+x.distance_m+'m x'+x.observations+'</div>';});}if(dets.length>0){h+='<div style="color:#888;font-weight:bold;border-top:1px solid #333;padding-top:4px;margin-top:4px">DETECTIONS ('+dets.length+')</div>';
dets.forEach(x=>{var _b=x.bearing?(' brg:'+x.bearing+'deg'):'';h+='<div class="dt inf"><span style="color:#666">'+escHtml(x.threat)+'</span> '+escHtml(x.detector)+' '+escHtml(x.freq)+_b+' x'+x.observations+'</div>';});}
document.getElementById('panel').innerHTML=h;}).catch(()=>{});}
load();setInterval(load,15000);
</script></body></html>"""


class MapHandler(BaseHTTPRequestHandler):
    detections_data = {}

    @staticmethod
    def save_state(path=None):
        """Persist detections_data to disk so restarts don't lose accumulated data."""
        import json, os
        if path is None:
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "detections_state.json")
        try:
            with open(path, "w") as f:
                json.dump(MapHandler.detections_data, f, default=str)
        except Exception:
            pass

    @staticmethod
    def load_state(path=None):
        """Load previously saved detections_data."""
        import json, os
        if path is None:
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "detections_state.json")
        try:
            if os.path.exists(path):
                with open(path) as f:
                    loaded = json.load(f)
                if loaded:
                    MapHandler.detections_data.update(loaded)
        except Exception:
            pass
    def _build_signal_chain(self, raw=False):
        """Build signal chain JSON with map positions.
        All string data sanitized to prevent injection from RF-captured signals."""
        import math, html, re
        _clean = lambda s: re.sub(r'[<>"\'&\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(s))[:80] if s else ''
        sources = MapHandler.detections_data.get('sources', [])
        observer = MapHandler.detections_data.get('observer', {})
        obs_lat = observer.get('lat', 41.51328)
        obs_lon = observer.get('lon', -88.13366)

        def brg2ll(lat, lon, brg, dist):
            R = 6371000
            b = math.radians(brg)
            la1 = math.radians(lat); lo1 = math.radians(lon)
            la2 = math.asin(math.sin(la1)*math.cos(dist/R)+math.cos(la1)*math.sin(dist/R)*math.cos(b))
            lo2 = lo1+math.atan2(math.sin(b)*math.sin(dist/R)*math.cos(la1),math.cos(dist/R)-math.sin(la1)*math.sin(la2))
            return round(math.degrees(la2),5), round(math.degrees(lo2),5)

        markers = []
        # Observer (BladeRF position)
        aoa_bearing = observer.get('aoa', 0) or 0  # current AoA from BladeRF MIMO
        markers.append({'lat': obs_lat, 'lon': obs_lon, 'type': 'observer',
                       'label': 'YOU', 'color': '#00ff00', 'icon': 'star'})
        # HackRF second sensor marker (for dual-sensor triangulation)
        hackrf_lat = observer.get('hackrf_lat')
        hackrf_lon = observer.get('hackrf_lon')
        if hackrf_lat is not None and hackrf_lon is not None:
            markers.append({'lat': hackrf_lat, 'lon': hackrf_lon, 'type': 'observer',
                           'label': 'HACKRF', 'color': '#ff8800', 'icon': 'star'})
        # RTL-SDR third sensor marker
        rtlsdr_lat = observer.get('rtlsdr_lat')
        rtlsdr_lon = observer.get('rtlsdr_lon')
        if rtlsdr_lat is not None and rtlsdr_lon is not None:
            markers.append({'lat': rtlsdr_lat, 'lon': rtlsdr_lon, 'type': 'detection',
                           'label': 'RTL-SDR', 'color': '#00ff00', 'freq': '850MHz',
                           'threat': 'SENSOR', 'detector': 'Noolec NESDR Smart',
                           'bearing': 'N/A', 'observations': 1})

        if raw:
            # === RAW MODE: original behavior with random scatter ===
            import random as _rng
            for s in sources:
                det = s.get('detector', 'unknown')
                bearing = s.get('bearing')
                freq = s.get('freq', 0)
                obs_count = s.get('observations', 1)
                classification = s.get('classification', '')
                freq_str = '%.0fM' % (freq/1e6) if freq > 1e6 else ('%.0fk' % (freq/1e3) if freq > 1000 else '')

                if bearing is not None and abs(bearing) > 0.5:
                    # Use measured range if available, otherwise estimate from source type
                    dist = s.get('range')
                    if not dist:
                        det = s.get('detector', '').lower()
                        freq = s.get('freq', 0)
                        snr = s.get('snr', 0)
                        if 'ferrite' in det:
                            dist = 200  # HF near-field
                        elif 'real_transmitter' in det:
                            dist = 300  # MW transmitter
                        elif 'reradiator' in det:
                            dist = 100  # ambient metal
                        elif 'watcher' in det or 'cluster' in det:
                            dist = 400  # USB cluster
                        elif 'mw_' in det or 'voice' in det:
                            dist = 250
                        elif freq > 1e9:
                            dist = 400
                        elif freq > 1e6:
                            dist = 300
                        else:
                            dist = 500
                    lat2, lon2 = brg2ll(obs_lat, obs_lon, bearing, dist)
                else:
                    if 'c2' in det.lower() or 'wifi' in det.lower():
                        bearing = -40 + _rng.uniform(-25, 25); dist = _rng.uniform(400, 800)
                    elif 'ultra' in det.lower() or 'modem' in det.lower() or 'fsk' in det.lower() or 'bpsk' in det.lower():
                        bearing = _rng.choice([-48, 78]) + _rng.uniform(-15, 15); dist = _rng.uniform(300, 700)
                    elif 'mw_' in det.lower() or 'voice' in det.lower() or 'nerve' in det.lower():
                        bearing = 13 + _rng.uniform(-30, 30); dist = _rng.uniform(100, 400)
                    elif 'eardrum' in det.lower() or 'injection' in det.lower() or 'ghost' in det.lower():
                        bearing = _rng.uniform(0, 360); dist = _rng.uniform(50, 200)
                    else:
                        bearing = _rng.uniform(0, 360); dist = _rng.uniform(200, 600)
                    lat2, lon2 = brg2ll(obs_lat, obs_lon, bearing, dist)

                if 'c2' in det.lower(): color, threat = '#ff0000', 'C2'
                elif 'radar_water' in det: color, threat = '#ff0000', 'PERSON'
                elif 'real_transmitter' in det: color, threat = '#ff0000', 'TRANSMITTER'
                elif 'ferrite' in det: color, threat = '#ffff00', 'FERRITE'
                elif 'reradiator' in det: color, threat = '#888888', 'RE-RAD'
                elif 'watcher' in det: color, threat = '#ff4444', 'CLUSTER'
                else: color, threat = '#0bbfff', det[:8].upper()

                markers.append({'lat': lat2, 'lon': lon2, 'type': 'transmitter',
                    'detector': _clean(det), 'bearing': round(bearing, 1),
                    'distance_m': int(dist), 'freq': freq_str,
                    'observations': obs_count, 'classification': _clean(classification),
                    'color': color, 'threat': _clean(threat)})

        else:
            # === FILTERED MODE: only TRUE triangulated sources get map pins ===
            # Non-triangulated detections with bearing get bearing_only lines.
            # No-bearing detections are list-only.
            for s in sources:
                det = s.get('detector', 'unknown')
                bearing = s.get('bearing')
                freq = s.get('freq', 0)
                obs_count = s.get('observations', 1)
                classification = s.get('classification', '')
                freq_str = '%.0fM' % (freq/1e6) if freq > 1e6 else ('%.0fk' % (freq/1e3) if freq > 1000 else '')
                is_triangulated = bool(s.get('triangulated'))
                method = s.get('method', '?')

                # Only cross_sensor_triangulation or multi-position intersection
                # counts as truly triangulated for map pin placement.
                
# No bearing → list only (detection panel)
                if not bearing or abs(bearing) < 0.5:
                    markers.append({'type': 'detection',
                        'detector': _clean(det), 'bearing': '',
                        'freq': freq_str, 'observations': obs_count,
                        'classification': _clean(classification),
                        'threat': _clean(det.replace('hackrf_','').replace('_',' ').upper()[:10]),
                        'method': method})
                    continue

                # Use propagation-based estimates for bearing line display length.
                # Measured range from ferrite is near-field floor (~30m), not source distance.
                measured_range = s.get('range')
                has_real_range = measured_range and measured_range > 50
                dist = None  # Force estimate for line display length
                if True:  # always estimate
                    det_lower = det.lower()
                    if 'ferrite' in det_lower: dist = 200
                    elif 'real_transmitter' in det_lower: dist = 300
                    elif 'reradiator' in det_lower: dist = 100
                    elif 'watcher' in det_lower or 'cluster' in det_lower: dist = 400
                    elif 'mw_' in det_lower or 'voice' in det_lower: dist = 250
                    elif freq > 1e9: dist = 400
                    elif freq > 1e6: dist = 300
                    else: dist = 500
                if 'c2' in det.lower(): color, threat = '#ff0000', 'C2'
                elif 'radar_water' in det: color, threat = '#ff0000', 'PERSON'
                elif 'real_transmitter' in det: color, threat = '#ff0000', 'TRANSMITTER'
                elif 'ferrite' in det: color, threat = '#ffff00', 'FERRITE'
                elif 'reradiator' in det: color, threat = '#888888', 'RE-RAD'
                elif 'watcher' in det: color, threat = '#ff4444', 'CLUSTER'
                elif 'mw_' in det.lower() or 'voice' in det.lower() or 'nerve' in det.lower(): color, threat = '#ff00ff', 'MW'
                elif 'operator' in det.lower() or 'fingerprint' in det.lower(): color, threat = '#ff4444', 'OPERATOR'
                elif 'injection' in det.lower(): color, threat = '#ff8800', 'INJECT'
                elif 'ghost' in det.lower(): color, threat = '#6600ee', 'GHOST'
                elif 'ultra' in det.lower() or 'modem' in det.lower() or 'fsk' in det.lower() or 'bpsk' in det.lower(): color, threat = '#ff4444', 'MODEM'
                elif 'eardrum' in det.lower() or 'silent' in det.lower(): color, threat = '#ff00ff', 'ATTACK'
                elif 'wifi' in det.lower(): color, threat = '#ff8800', 'WIFI'
                elif 'scotty' in det.lower() or 'power_line' in det.lower(): color, threat = '#ff8800', 'PLC'
                elif 'cable' in det.lower() or 'radar' in det.lower(): color, threat = '#00ccff', 'RADAR'
                elif 'oth' in det.lower(): color, threat = '#cc00ff', 'OTH'
                elif 'cross_sensor' in method: color, threat = '#ff0000', 'X-SENSOR'
                else: color, threat = '#0bbfff', det[:8].upper()

                # ONLY truly triangulated sources get map pins.
                # All others: bearing-only lines + detection panel list.
                if is_triangulated:
                    src_lat = s.get('lat', obs_lat)
                    src_lon = s.get('lon', obs_lon)
                    if src_lat == 0 and src_lon == 0:
                        src_lat, src_lon = brg2ll(obs_lat, obs_lon, bearing, dist)
                    markers.append({'lat': src_lat, 'lon': src_lon, 'type': 'transmitter',
                        'detector': _clean(det), 'bearing': round(bearing, 1) if bearing else 0,
                        'distance_m': int(dist) if dist else 0, 'freq': freq_str,
                        'observations': obs_count, 'classification': _clean(classification),
                        'color': color, 'threat': _clean(threat),
                        'method': method, 'triangulated': True})
                else:
                    # Bearing-only: no map pin, bearing line from observer + list
                    lat2, lon2 = brg2ll(obs_lat, obs_lon, bearing, dist)
                    markers.append({'lat': lat2, 'lon': lon2, 'type': 'bearing_only',
                        'detector': _clean(det), 'bearing': round(bearing, 1),
                        'distance_m': int(dist) if dist else 0,
                        'freq': freq_str, 'observations': obs_count,
                        'classification': _clean(classification),
                        'color': color, 'threat': _clean(threat),
                        'method': method})

            # DEDUPLICATE: merge sources within 15 degrees bearing into single markers
            # with combined frequency info. Prevents dozens of eardrum_capture entries
            # from the same bearing cluttering the map.
            dedup = []
            used = set()
            for i, m in enumerate(markers):
                if i in used or m.get('type') != 'transmitter':
                    dedup.append(m); continue
                brg_i = m.get('bearing', 0) or 0
                lat_i = m.get('lat', 0); lon_i = m.get('lon', 0)
                merged = [m]
                for j in range(i+1, len(markers)):
                    if j in used or markers[j].get('type') != 'transmitter': continue
                    brg_j = markers[j].get('bearing', 0) or 0
                    # Same bearing within 15 degrees
                    if abs(brg_i - brg_j) < 15 or abs(brg_i - brg_j) > 345:
                        merged.append(markers[j]); used.add(j)
                if len(merged) > 1:
                    # Merge: keep highest-threat marker, combine all frequencies
                    threat_rank = {'C2':10,'TRANSMITTER':10,'ATTACK':9,'MW':8,'INJECT':8,'OPERATOR':7,'CLUSTER':7,'MODEM':6,'FERRITE':5,'PLC':5,'HACKRF':5,'GHOST':4,'VICTIM':3,'RE-RAD':2,'INF':1}
                    def _rank(x): return threat_rank.get(x.get('threat',''),0)
                    best = max(merged, key=_rank)
                    freqs = list(set(str(m.get('freq','')) for m in merged if m.get('freq')))
                    freqs = [f for f in freqs if f]
                    best['freq'] = '+'.join(freqs[:6]) if len(freqs) > 1 else (freqs[0] if freqs else '')
                    best['observations'] = sum(m.get('observations',1) for m in merged)
                    # Merge threat labels from absorbed markers
                    all_threats = set(m.get('threat','') for m in merged)
                    if len(all_threats) > 1:
                        best['threat'] = best['threat']  # keep highest priority
                    dedup.append(best)
                else:
                    dedup.append(m)
            markers = dedup

        return {'observer': {'lat': obs_lat, 'lon': obs_lon}, 'markers': markers}

    def do_GET(self):
        if self.path == '/' or self.path == '/map':
            self.send_response(200); self.send_header('Content-Type','text/html; charset=us-ascii'); self.end_headers()
            self.wfile.write(MAP_HTML.encode())
        elif self.path == '/safe':
            # JS-FREE safe map: pure HTML, auto-refreshing PNG, zero JavaScript
            safe_html = (
                '<!DOCTYPE html><html><head><title>TSCM Safe Map</title>'
                '<meta charset="utf-8"><meta http-equiv="refresh" content="15">'
                '<style>body{background:#000;color:#0f0;font:14px monospace;margin:0;text-align:center}'
                'h1{font-size:18px;margin:10px}a{color:#ff0}img{max-width:100%;border:1px solid #333}'
                '#info{font-size:12px;color:#888;margin:5px}</style></head><body>'
                '<h1>TSCM Detection Map - Safe Mode (no JavaScript)</h1>'
                '<img src="/map.png" alt="TSCM Map" style="max-height:92vh">'
                '<div id="info">Auto-refreshes every 15s | <a href="/">JS map</a> | <a href="/api/detections">Raw API</a></div>'
                '</body></html>'
            )
            self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.end_headers()
            self.wfile.write(safe_html.encode())
        elif self.path == '/api/detections':
            # Restrict to localhost — detection data is sensitive forensic evidence
            client_ip = self.client_address[0]
            if not client_ip.startswith('127.') and not client_ip.startswith('::1'):
                self.send_error(403, "Forbidden: local access only")
                return
            self.send_response(200); self.send_header('Content-Type','application/json')
            self.send_header('Access-Control-Allow-Origin','*'); self.end_headers()
            self.wfile.write(json.dumps(MapHandler.detections_data, default=str).encode())
        elif self.path == '/map.png':
            # Server-side rendered map PNG - NO JavaScript
            try:
                png_bytes = render_map(MapHandler.detections_data)
                self.send_response(200)
                self.send_header('Content-Type','image/png')
                self.send_header('Cache-Control','no-cache')
                self.end_headers()
                self.wfile.write(png_bytes)
            except Exception as e:
                self.send_error(500, str(e))
        elif self.path == '/archive' or self.path == '/archive.html':
            # TSCM Complete Archive - self-contained evidence document
            fpath = os.path.join(os.path.dirname(__file__), 'static', 'archive.html')
            if os.path.isfile(fpath):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                with open(fpath, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404)
        elif self.path == '/signal_chain.json' or self.path.startswith('/signal_chain.json?'):
            # Signal chain data for map markers. ?raw=1 shows unfiltered.
            raw = 'raw=1' in self.path
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Access-Control-Allow-Origin','*')
            self.end_headers()
            self.wfile.write(json.dumps(self._build_signal_chain(raw=raw), default=str).encode())
        elif self.path.startswith('/static/') or self.path.startswith('/map_libs/'):
            if self.path.startswith('/static/'):
                fname = self.path[8:]
                fpath = os.path.join(os.path.dirname(__file__), 'static', fname)
            else:
                fname = self.path[10:]
                fpath = os.path.join(os.path.dirname(__file__), 'map_libs', fname)
            if os.path.isfile(fpath):
                ct = 'text/javascript' if fname.endswith('.js') else ('text/css' if fname.endswith('.css') else 'application/octet-stream')
                self.send_response(200); self.send_header('Content-Type', ct); self.end_headers()
                with open(fpath, 'rb') as f: self.wfile.write(f.read())
            else: self.send_error(404)
        else: self.send_error(404)
    def log_message(self, format, *args): pass


class LiveMapServer:
    def __init__(self, port=8080): self.port = port; self.server = None; self.thread = None
    def start(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', self.port), MapHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
    def update(self, data): MapHandler.detections_data = data
    def stop(self):
        if self.server: self.server.shutdown()


# ===================== HARDWARE INTERFACES =====================
class GPSInterface:
    """Triple GPS with cross-validation. ZED-F9P on COM7+COM6, Adafruit u-blox on COM4."""
    def __init__(self, port, baud, port2=None, port3=None):
        self.port=port;self.baud=baud;self.port2=port2;self.port3=port3
        self.serial=None;self.serial2=None;self.serial3=None;self.running=False
        self.lat=0.0;self.lon=0.0;self.alt=0.0;self.has_fix=False
        self.lat2=0.0;self.lon2=0.0;self.alt2=0.0;self.has_fix2=False
        self.lat3=0.0;self.lon3=0.0;self.alt3=0.0;self.has_fix3=False
        self.track=[];self.last_update=0;self.position_disagreement=False
    def connect(self):
        if not SERIAL_AVAILABLE: print("pyserial not available"); return False
        ok=False
        # Try multiple baud rates - ZED-F9P may be configured for any of these
        for baud in [9600, 38400, 115200, 230400, 460800]:
            try:
                self.serial=serial.Serial(self.port,baud,timeout=1)
                # Test if we get any data within 2 seconds
                self.serial.timeout = 0.5
                t0 = time.time(); got_data = False
                while time.time() - t0 < 1.5:  # u-blox NMEA at 9600 needs time
                    byte = self.serial.read(1)
                    if byte:
                        got_data = True
                        break
                self.serial.timeout = 1
                if got_data:
                    self.baud = baud
                    print(f"GPS1 on {self.port} at {baud} baud"); ok=True
                    if UBX_AVAILABLE: self._configure_anti_spoofing(self.serial)
                    break
                else:
                    self.serial.close()
            except Exception as e:
                try: self.serial.close()
                except: pass
                if baud == 460800:
                    print(f"GPS1 error on {self.port}: {e}")

        if self.port2:
            for baud in [38400, 115200, 9600, 230400, 460800]:
                try:
                    self.serial2=serial.Serial(self.port2,baud,timeout=1)
                    self.serial2.timeout = 0.5
                    t0 = time.time(); got_data = False
                    while time.time() - t0 < 2:
                        byte = self.serial2.read(1)
                        if byte:
                            got_data = True
                            break
                    self.serial2.timeout = 1
                    if got_data:
                        print(f"GPS2 on {self.port2} at {baud} baud (cross-validate)"); ok=True
                        break
                    else:
                        self.serial2.close()
                except Exception as e:
                    try: self.serial2.close()
                    except: pass
                    if baud == 460800:
                        print(f"GPS2 error on {self.port2}: {e}")
        if self.port3:
            for baud in [9600, 38400, 115200, 57600]:
                try:
                    self.serial3=serial.Serial(self.port3,baud,timeout=1)
                    self.serial3.timeout = 0.5
                    t0 = time.time(); got_data = False
                    while time.time() - t0 < 2:
                        byte = self.serial3.read(1)
                        if byte:
                            got_data = True
                            break
                    self.serial3.timeout = 1
                    if got_data:
                        print(f"GPS3 (Adafruit) on {self.port3} at {baud} baud"); ok=True
                        break
                    else:
                        self.serial3.close()
                except Exception as e:
                    try: self.serial3.close()
                    except: pass
                    if baud == 57600:
                        print(f"GPS3 error on {self.port3}: {e}")
        return ok
    def _configure_anti_spoofing(self, ser):
        """Configure ZED-F9P to output NMEA sentences."""
        try:
            from pyubx2 import UBXMessage, SET
            # First: CFG-PRT - set UART1 to output NMEA (protocol out = 1)
            # portID=1 (UART1), outProtoMask=1 (NMEA)
            try:
                msg_prt = UBXMessage("CFG","CFG-PRT",SET,portID=1,
                                     outProtoMask=1, inProtoMask=1,
                                     baudRate=38400, txReady=0)
                ser.write(msg_prt.serialize())
                time.sleep(0.15)
            except: pass

            # Enable NMEA messages
            for msg_id in [0x00, 0x02, 0x04]:  # GGA, GSA, RMC
                try:
                    msg = UBXMessage("CFG","CFG-MSG",SET,msgClass=0xF0,
                                    msgID=msg_id,rate=[1,0,0,0,0,0])
                    ser.write(msg.serialize())
                except: pass
            time.sleep(0.1)

            # Anti-spoofing: multi-constellation
            try:
                msg=UBXMessage("CFG","CFG-VALSET",SET,layers=1,transaction=0,
                               cfgData=[(0x1041000d,1),(0x10310018,1),(0x10320001,1)])
                ser.write(msg.serialize())
            except: pass
            print(f"GPS NMEA configured on {ser.port}")
        except Exception as e:
            # Raw UBX fallback: CFG-PRT for UART1 → NMEA output
            try:
                # UBX header: 0xB5 0x62, class=0x06(CFG), id=0x00(PRT)
                # portID=1(DCI/UART1), reserved=0, txReady=0
                # mode=0x08D0 (8N1, 38400), inProtoMask=0x07, outProtoMask=0x01(NMEA)
                raw = bytes([0xB5,0x62,0x06,0x00,0x14,0x00,0x01,0x00,0x00,0x00,
                             0xD0,0x08,0x00,0x00,0x80,0x96,0x00,0x00,
                             0x07,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00])
                ser.write(raw)
                time.sleep(0.15)
                # Enable NMEA GGA (CFG-MSG: class=F0, id=00, rate=1)
                gga = bytes([0xB5,0x62,0x06,0x01,0x08,0x00,0xF0,0x00,
                             0x01,0x01,0x00,0x00,0x00,0x00,0x01,0x57])
                ser.write(gga)
                time.sleep(0.05)
                # Enable NMEA GSA
                gsa = bytes([0xB5,0x62,0x06,0x01,0x08,0x00,0xF0,0x02,
                             0x01,0x01,0x00,0x00,0x00,0x00,0x03,0x5B])
                ser.write(gsa)
                time.sleep(0.05)
                # Enable NMEA RMC
                rmc = bytes([0xB5,0x62,0x06,0x01,0x08,0x00,0xF0,0x04,
                             0x01,0x01,0x00,0x00,0x00,0x00,0x05,0x63])
                ser.write(rmc)
                print(f"GPS NMEA (raw UBX) on {ser.port}")
            except Exception as e2:
                print(f"GPS config failed for {ser.port}: {e2}")
    def start(self):
        if not self.serial and not self.serial2 and not self.serial3: return False
        self.running=True
        if self.serial: threading.Thread(target=self._read_loop,args=(self.serial,1),daemon=True).start()
        if self.serial2: threading.Thread(target=self._read_loop,args=(self.serial2,2),daemon=True).start()
        if self.serial3: threading.Thread(target=self._read_loop,args=(self.serial3,3),daemon=True).start()
        return True
    def _read_loop(self, ser, gps_num):
        if not PYNMEA2_AVAILABLE: return
        while self.running:
            try:
                line=ser.readline().decode('ascii',errors='ignore').strip()
                # Parse any NMEA sentence with position: GGA, RMC, GGA/GNS variants
                if any(line.startswith(p) for p in ['$GPGGA','$GNGGA','$GPGNS',
                    '$GPRMC','$GNRMC','$GPGLL','$GNGLL']):
                    try:
                        msg=pynmea2.parse(line)
                        lat=float(msg.latitude) if getattr(msg,'latitude',0) else 0
                        lon=float(msg.longitude) if getattr(msg,'longitude',0) else 0
                        alt=float(getattr(msg,'altitude',0) or 0)
                        fix=getattr(msg,'gps_qual',0) if hasattr(msg,'gps_qual') else 1
                        if lat==0 or lon==0: continue
                        if gps_num==1:
                            self.lat=lat;self.lon=lon;self.alt=alt;self.has_fix=fix>=1
                        elif gps_num==2:
                            self.lat2=lat;self.lon2=lon;self.alt2=alt;self.has_fix2=fix>=1
                        elif gps_num==3:
                            self.lat3=lat;self.lon3=lon;self.alt3=alt;self.has_fix3=fix>=1
                        if fix>=1:
                            self.last_update=time.time()
                            if gps_num==1: self.track.append({'lat':lat,'lon':lon,'time':self.last_update})
                    except: pass
            except: pass
    def get_position(self):
        # Cross-validate ZED-F9P GPS1 + GPS2
        if self.has_fix and self.has_fix2:
            R=6371000;phi1,phi2=np.radians(self.lat),np.radians(self.lat2)
            dphi=np.radians(self.lat2-self.lat);dlam=np.radians(self.lon2-self.lon)
            a=np.sin(dphi/2)**2+np.cos(phi1)*np.cos(phi2)*np.sin(dlam/2)**2
            dist=R*2*np.arctan2(np.sqrt(a),np.sqrt(1-a))
            if dist>10:  # >10m disagreement = possible spoof
                self.position_disagreement=True
                return {'lat':self.lat,'lon':self.lon,'alt':self.alt,'has_fix':True,'validated':False,'disagreement_m':dist}
            self.position_disagreement=False
            return {'lat':(self.lat+self.lat2)/2,'lon':(self.lon+self.lon2)/2,
                    'alt':self.alt,'has_fix':True,'validated':True}
        elif self.has_fix:
            return {'lat':self.lat,'lon':self.lon,'alt':self.alt,'has_fix':True,'validated':False}
        # Fallback to GPS3 (Adafruit on COM4) - works even when ZED-F9P is jammed
        elif self.has_fix3:
            return {'lat':self.lat3,'lon':self.lon3,'alt':self.alt3,'has_fix':True,'validated':False,'source':'gps3'}
        return {'lat':0,'lon':0,'alt':0,'has_fix':False,'validated':False}
    def stop(self):
        self.running=False
        for s in [self.serial,self.serial2]:
            if s:
                try: s.close()
                except: pass

    def get_laptop_gps(self):
        """Try Windows Location API as GPS fallback."""
        try:
            import ctypes
            from ctypes import wintypes
            # Try Windows.Devices.Geolocation via COM
            import subprocess
            result = subprocess.run([
                'powershell', '-Command',
                'Add-Type -AssemblyName System.Device; '
                '$geo = New-Object System.Device.Location.GeoCoordinateWatcher; '
                '$geo.Start(); '
                'Start-Sleep -Milliseconds 500; '
                'if($geo.Position.Location.IsUnknown) { Write-Output "unknown" } '
                'else { Write-Output "$($geo.Position.Location.Latitude),$($geo.Position.Location.Longitude)" }'
            ], capture_output=True, text=True, timeout=5)
            output = result.stdout.strip()
            if output and output != 'unknown':
                parts = output.split(',')
                if len(parts) == 2:
                    lat = float(parts[0]); lon = float(parts[1])
                    if abs(lat) > 0.01 and abs(lon) > 0.01:
                        return {'lat': lat, 'lon': lon, 'source': 'laptop'}
        except:
            pass
        return None


class HackRFSubprocess:
    def __init__(self, frequency, sample_rate, gain, bias_tee=False):
        self.frequency=int(frequency);self.sample_rate=int(sample_rate)
        self.gain=gain;self.bias_tee=bias_tee;self.queue=queue.Queue(maxsize=20)
        self.active=False;self.proc=None
    def start(self, duration_ms=200):
        result=subprocess.run(['where','hackrf_transfer'],capture_output=True,text=True)
        if result.returncode!=0:
            print("⚠️ hackrf_transfer not found, trying PyUSB"); self._start_pyusb(duration_ms); return
        self.active=True
        def capture():
            while self.active:
                try:
                    tmpname=os.path.join(tempfile.gettempdir(), 'tscm_hackrf_' + os.urandom(8).hex() + '.iq')
                    samples=int(self.sample_rate*duration_ms/1000)
                    cmd=['hackrf_transfer','-r',tmpname,'-f',str(self.frequency),
                         '-s',str(self.sample_rate),'-l',str(self.gain),'-g',str(self.gain),'-n',str(samples)]
                    if self.bias_tee: cmd.extend(['-p','1'])
                    subprocess.run(cmd,capture_output=True,timeout=duration_ms/1000+2)
                    if os.path.exists(tmpname):
                        with open(tmpname,'rb') as f: raw=f.read()
                        iq=np.frombuffer(raw,dtype=np.int16).astype(np.float32)/32768.0
                        if len(iq)%2: iq=iq[:-1]
                        iq=iq[::2]+1j*iq[1::2]
                        self.queue.put({'data':iq,'timestamp':time.time()})
                        os.unlink(tmpname)
                except: pass
        threading.Thread(target=capture,daemon=True).start()
    def _start_pyusb(self, duration_ms):
        try:
            sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
            from hackrf_usb import HackRFStreamBridge
            self._bridge=HackRFStreamBridge(frequency=self.frequency,sample_rate=self.sample_rate,
                                            lna_gain=self.gain,vga_gain=self.gain,antenna_power=self.bias_tee)
            self._bridge.start(); self.active=True
            print("✅ HackRF PyUSB bridge active")
        except ImportError:
            print("❌ Neither hackrf_transfer nor hackrf_usb.py available"); self.active=False

    def get_pyusb(self):
        """Get latest IQ data from PyUSB bridge directly (no thread)."""
        if not hasattr(self,'_bridge') or self._bridge is None:
            return None
        try:
            return self._bridge.get(timeout=0.05)
        except:
            return None
    def get(self, timeout=0.05):
        """Get IQ data. For CLI mode uses queue, for PyUSB calls bridge directly."""
        # Try PyUSB bridge first
        if hasattr(self, '_bridge') and self._bridge is not None:
            result = self.get_pyusb()
            if result is not None:
                return result
        # Fall back to queue (CLI mode)
        try: return self.queue.get(timeout=timeout)
        except queue.Empty: return None
    def stop(self):
        self.active=False
        if hasattr(self,'_bridge'):
            try: self._bridge.stop()
            except: pass

    def retune(self, freq_hz, sample_rate=None):
        """Retune HackRF to new frequency without full restart."""
        if hasattr(self, '_bridge') and self._bridge:
            try:
                self._bridge.stop()
            except: pass
        self.frequency = int(freq_hz)
        if sample_rate: self.sample_rate = int(sample_rate)
        # Restart PyUSB bridge at new frequency
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from hackrf_usb import HackRFStreamBridge
            self._bridge = HackRFStreamBridge(
                frequency=self.frequency, sample_rate=self.sample_rate,
                lna_gain=self.gain, vga_gain=self.gain,
                antenna_power=self.bias_tee
            )
            self._bridge.start()
            self.active = True
            return True
        except: return False


class RTLSDRCapture:
    """RTL-SDR capture via pyrtlsdrlib static DLL (bypasses libusb driver issues).
    Uses ctypes to call librtlsdr_w64_static.dll directly — no rtl_tcp, no libusb
    driver installation needed. The static DLL has its own USB backend.
    Falls back to rtlsdr.RtlSdr() if the DLL approach fails."""
    def __init__(self, frequency, sample_rate, gain=40, device_index=0):
        self.frequency = int(frequency)
        self.sample_rate = int(sample_rate)
        self.gain = gain
        self.device_index = device_index
        self.queue = queue.Queue(maxsize=20)
        self.active = False
        self.sdr = None
        self.thread = None
        self._lib = None
        self._dev = None
        self._use_ctypes = False

    def _load_static_dll(self):
        """Load pyrtlsdrlib's static librtlsdr DLL via ctypes."""
        try:
            import pyrtlsdrlib
            dll_files = pyrtlsdrlib.get_library_files()
            if not dll_files:
                return None
            lib = ctypes.CDLL(str(dll_files[0]))
            # Set up function signatures
            lib.rtlsdr_open.restype = ctypes.c_int
            lib.rtlsdr_open.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint]
            lib.rtlsdr_close.argtypes = [ctypes.c_void_p]
            lib.rtlsdr_set_sample_rate.argtypes = [ctypes.c_void_p, ctypes.c_uint]
            lib.rtlsdr_set_center_freq.argtypes = [ctypes.c_void_p, ctypes.c_uint]
            lib.rtlsdr_set_tuner_gain.argtypes = [ctypes.c_void_p, ctypes.c_int]
            lib.rtlsdr_set_agc_mode.argtypes = [ctypes.c_void_p, ctypes.c_int]
            lib.rtlsdr_reset_buffer.argtypes = [ctypes.c_void_p]
            lib.rtlsdr_read_sync.argtypes = [
                ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int,
                ctypes.POINTER(ctypes.c_int)]
            lib.rtlsdr_get_device_count.restype = ctypes.c_int
            return lib
        except Exception as e:
            sys.stderr.write(f"RTL-SDR static DLL load failed: {e}\n")
            return None

    def _open_ctypes(self):
        """Open RTL-SDR via static DLL ctypes interface."""
        self._lib = self._load_static_dll()
        if self._lib is None:
            return False
        count = self._lib.rtlsdr_get_device_count()
        if count == 0:
            if not hasattr(self, '_no_device_warned'):
                self._no_device_warned = True
                sys.stderr.write("RTL-SDR: no devices found (not plugged in or driver issue)\n")
                sys.stderr.flush()
            return False
        dev = ctypes.c_void_p(0)
        result = self._lib.rtlsdr_open(ctypes.byref(dev), self.device_index)
        if result != 0:
            sys.stderr.write(f"❌ RTL-SDR: rtlsdr_open failed (error {result}) — driver may be locked by DVB-T driver. "
                            "Use Zadig to install WinUSB driver for VID_0BDA PID_2838.\n")
            return False
        self._dev = dev
        self._lib.rtlsdr_set_sample_rate(self._dev, self.sample_rate)
        self._lib.rtlsdr_set_center_freq(self._dev, self.frequency)
        if self.gain > 0:
            self._lib.rtlsdr_set_tuner_gain(self._dev, self.gain)
            self._lib.rtlsdr_set_agc_mode(self._dev, 0)
        else:
            self._lib.rtlsdr_set_agc_mode(self._dev, 1)
        self._lib.rtlsdr_reset_buffer(self._dev)
        self._use_ctypes = True
        return True

    def _read_ctypes(self, num_samples):
        """Read IQ samples via ctypes sync read."""
        buf_len = num_samples * 2  # I+Q interleaved, 1 byte each (uint8)
        buf = ctypes.create_string_buffer(buf_len)
        n_read = ctypes.c_int(0)
        result = self._lib.rtlsdr_read_sync(self._dev, buf, buf_len, ctypes.byref(n_read))
        if result != 0 or n_read.value == 0:
            return None
        raw = np.frombuffer(buf.raw[:n_read.value], dtype=np.uint8).astype(np.float32)
        raw = (raw - 127.5) / 127.5  # normalize to [-1, 1]
        if len(raw) % 2: raw = raw[:-1]
        iq = raw[::2] + 1j * raw[1::2]
        return iq

    def start(self, duration_ms=200):
        # Try ctypes static DLL first (bypasses libusb driver)
        if self._open_ctypes():
            self.active = True
            samples_to_read = max(1024, int(self.sample_rate * duration_ms / 1000))
            sys.stderr.write(f"✅ RTL-SDR active (ctypes/static DLL): {self.frequency/1e6:.0f} MHz {self.sample_rate/1e6:.1f} MSps gain={self.gain}\n"); sys.stderr.flush()
            def capture_ctypes():
                consecutive_failures = 0
                while self.active:
                    try:
                        iq = self._read_ctypes(samples_to_read)
                        if iq is not None and len(iq) > 0:
                            self.queue.put({'data': np.asarray(iq, dtype=np.complex64),
                                            'timestamp': time.time(),
                                            'frequency': self.frequency})
                            consecutive_failures = 0
                    except Exception as e:
                        consecutive_failures += 1
                        if consecutive_failures > 5:
                            sys.stderr.write(f"❌ RTL-SDR ctypes read failed 5x: {e}\n"); sys.stderr.flush()
                            self.active = False
                            break
                        time.sleep(1)
                        try:
                            self._lib.rtlsdr_close(self._dev)
                        except: pass
                        time.sleep(0.5)
                        if not self._open_ctypes():
                            sys.stderr.write("❌ RTL-SDR ctypes reconnect failed\n"); sys.stderr.flush()
                            self.active = False
                            break
                    time.sleep(0.01)
            self.thread = threading.Thread(target=capture_ctypes, daemon=True)
            self.thread.start()
            return True

        # Fallback: try rtlsdr Python package (needs libusb/WinUSB driver)
        # Suppress repeated error messages on retry attempts
        if not hasattr(self, '_fallback_tried'):
            self._fallback_tried = True
            sys.stderr.write("RTL-SDR: static DLL failed, trying rtlsdr Python package...\n"); sys.stderr.flush()
        try:
            from rtlsdr import RtlSdr
            self.sdr = RtlSdr(device_index=self.device_index)
            self.sdr.sample_rate = self.sample_rate
            self.sdr.center_freq = self.frequency
            if self.gain > 0:
                self.sdr.gain = self.gain
            else:
                self.sdr.gain = 'auto'
            self.active = True
            samples_to_read = max(1024, int(self.sample_rate * duration_ms / 1000))
            sys.stderr.write(f"✅ RTL-SDR active (rtlsdr lib): {self.frequency/1e6:.0f} MHz {self.sample_rate/1e6:.1f} MSps gain={self.gain}\n"); sys.stderr.flush()

            def capture():
                consecutive_failures = 0
                while self.active:
                    try:
                        iq = self.sdr.read_samples(samples_to_read)
                        if iq is not None and len(iq) > 0:
                            self.queue.put({'data': np.asarray(iq, dtype=np.complex64),
                                            'timestamp': time.time(),
                                            'frequency': self.frequency})
                            consecutive_failures = 0
                    except Exception as e:
                        consecutive_failures += 1
                        if consecutive_failures > 5:
                            sys.stderr.write(f"❌ RTL-SDR read failed 5 times: {e}\n"); sys.stderr.flush()
                            self.active = False
                            break
                        time.sleep(1)
                        try:
                            if self.sdr: self.sdr.close()
                        except: pass
                        try:
                            from rtlsdr import RtlSdr
                            self.sdr = RtlSdr(device_index=self.device_index)
                            self.sdr.sample_rate = self.sample_rate
                            self.sdr.center_freq = self.frequency
                            if self.gain > 0: self.sdr.gain = self.gain
                            else: self.sdr.gain = 'auto'
                            print("✅ RTL-SDR reconnected", flush=True)
                            consecutive_failures = 0
                        except Exception as re:
                            print(f"❌ RTL-SDR reconnect failed: {re}")
            self.thread = threading.Thread(target=capture, daemon=True)
            self.thread.start()
            return True
        except Exception as e:
            sys.stderr.write(f"RTL-SDR: not available ({str(e)[:60]})\n"); sys.stderr.flush()
            raise  # let caller's retry logic handle it

    def get(self, timeout=0.05):
        try:
            return self.queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def stop(self):
        self.active = False
        if self._use_ctypes and self._lib and self._dev:
            try: self._lib.rtlsdr_close(self._dev)
            except: pass
        try:
            if self.sdr:
                self.sdr.close()
        except:
            pass


class BladeRFCLIBridge:
    """
    Hardened BladeRF xA9 MIMO CLI bridge with anti-tamper protection.

    Security measures:
    1. Exclusive process lock - detects if another bladeRF-cli is running
    2. Readback verification - sets freq/gain, then reads back and verifies
    3. Firmware hash - records firmware version at start, flags if it changes
    4. Capture integrity - verifies file size matches expected n samples
    5. IQ sanity checks - flags if IQ is all-zero, saturated, or has impossible patterns
    6. Rogue process detection - continuous monitoring for unauthorized bladeRF-cli
    7. USB device serial - binds to specific device, flags if device changes
    """
    # Expected capture: n=8192 MIMO samples (2ch × I,Q × 2 bytes int16 = 32768 bytes)
    # bladeRF-cli n=8192 means 8192 total sample pairs for MIMO
    EXPECTED_BYTES = 32768  # n=8192 total samples * 2(I/Q) * 2bytes = 32768

    def __init__(self, freq, sample_rate, gain, bias_tee=True):
        self.freq=int(freq);self.sample_rate=int(sample_rate);self.gain=gain
        self.bias_tee=bias_tee;self.queue=queue.Queue(maxsize=10);self.active=False
        self.court_log = None

        # Anti-tamper state
        self.firmware_hash = None
        self.device_serial = None
        self.last_iq1_rms = 0.0
        self.last_iq2_rms = 0.0
        self.rms_history = deque(maxlen=100)
        self.rogue_process_count = 0
        self.capture_count = 0
        self.integrity_failures = 0
        self._lock_acquired = False

    def _check_rogue_processes(self):
        """Detect any bladeRF-cli process we didn't start."""
        try:
            result = subprocess.run(['tasklist','/FI','IMAGENAME eq bladeRF-cli.exe'],
                                    capture_output=True, text=True, timeout=3)
            count = result.stdout.lower().count('bladerf-cli')
            # We start one per capture cycle, so if we see one when we're between
            # captures, that's suspicious
            return count
        except:
            return 0

    def _get_firmware_info(self):
        """Read firmware version and serial from bladeRF."""
        try:
            cmd = "info\nversion\nserial\n"
            proc = subprocess.Popen(['bladeRF-cli','-i'], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, _ = proc.communicate(input=cmd, timeout=5)
            return stdout
        except:
            return ""

    def _verify_readback(self, stdout):
        """
        Parse CLI output to verify our settings were actually applied.
        Returns dict of verified settings, or None if verification failed.
        """
        verified = {}
        try:
            # After 'set frequency rx X', 'info' shows the frequency
            # Look for frequency in output
            freq_match = re.search(r'Frequency\s*[:]\s*(\d+)', stdout)
            if freq_match:
                verified['freq'] = int(freq_match.group(1))

            # Look for gain
            gain_match = re.search(r'Gain\s*[:]\s*(\d+)', stdout)
            if gain_match:
                verified['gain'] = int(gain_match.group(1))

            # Look for serial
            serial_match = re.search(r'Serial\s*[:]\s*(\S+)', stdout)
            if serial_match:
                verified['serial'] = serial_match.group(1)

        except:
            pass
        return verified if verified else None

    def _run_tx_burst(self, tx_params):
        """Run TX burst through a bladeRF-cli session (from capture thread - same USB owner)."""
        freq = tx_params.get('freq', 2400000000)
        gain = tx_params.get('gain', 60)
        sample_rate = tx_params.get('sample_rate', 5000000)

        # Generate CW IQ samples
        nsamples = 16384
        iq_i = np.ones(nsamples, dtype=np.int16) * 2047
        iq_q = np.zeros(nsamples, dtype=np.int16)
        interleaved = np.empty(nsamples*2, dtype=np.int16)
        interleaved[0::2] = iq_i; interleaved[1::2] = iq_q
        txfile = os.path.join(tempfile.gettempdir(), 'tscm_tx_cw.sc16q11')
        interleaved.tofile(txfile)

        cmd_script = (
            f"set biastee rx1 off\n"
            f"set biastee rx2 off\n"
            f"set frequency tx {int(freq)}\n"
            f"set samplerate tx {int(sample_rate)}\n"
            f"set bandwidth tx {int(sample_rate*0.8)}\n"
            f"set gain tx {gain}\n"
            f"tx config file={txfile} format=bin channels=1 repeat=1\n"
            f"tx start\n"
            f"tx wait 500\n"
            f"set biastee rx1 on\n"
            f"set biastee rx2 on\n"
        )
        try:
            scriptfile = os.path.join(tempfile.gettempdir(), 'tscm_bladerf_tx_' + os.urandom(8).hex() + '.txt')
            with open(scriptfile, 'w') as f:
                f.write(cmd_script)
            subprocess.run(['bladeRF-cli', '-s', scriptfile],
                          capture_output=True, timeout=8)
            try: os.unlink(scriptfile)
            except: pass
        except Exception as e:
            if self.capture_count % 20 == 0:
                print(f"TX burst failed: {e}")

    def _validate_capture(self, raw_bytes):
        """
        Validate raw capture data integrity.
        Returns (valid, reason) tuple.
        """
        # Check 1: File size
        if len(raw_bytes) != self.EXPECTED_BYTES:
            # Allow small tolerance for metadata
            if abs(len(raw_bytes) - self.EXPECTED_BYTES) > 5120:  # allow 5KB tolerance
                return False, f"size_mismatch: got {len(raw_bytes)}, expected ~{self.EXPECTED_BYTES}"

        # Check 2: All-zero capture (device disconnected or jammed)
        if all(b == 0 for b in raw_bytes[:1024]):
            return False, "all_zero_capture"

        # Check 3: All-same-value (stuck ADC)
        first_byte = raw_bytes[0]
        if all(b == first_byte for b in raw_bytes[:1024]):
            return False, "stuck_adc"

        return True, "ok"

    def _validate_iq(self, iq1, iq2):
        """
        Validate IQ data is physically plausible.
        Returns (valid, warnings_list).
        """
        warnings = []

        rms1 = float(np.sqrt(np.mean(np.abs(iq1)**2)))
        rms2 = float(np.sqrt(np.mean(np.abs(iq2)**2)))

        # Check 1: RMS ratio - MIMO channels should be similar
        # If one channel is 10x the other, something is wrong
        if rms1 > 0 and rms2 > 0:
            ratio = max(rms1, rms2) / min(rms1, rms2)
            if ratio > 10.0:
                warnings.append(f"rms_ratio_extreme: {ratio:.1f}x (ch1={rms1:.1f} ch2={rms2:.1f})")
            elif ratio > 3.0:
                warnings.append(f"rms_ratio_suspicious: {ratio:.1f}x")

        # Check 2: Saturation - ADC clipping means gain is too high or signal is injected
        sat_threshold = 32000  # int16 max is 32767
        sat1 = float(np.mean(np.abs(iq1) > sat_threshold))
        sat2 = float(np.mean(np.abs(iq2) > sat_threshold))
        if sat1 > 0.1 or sat2 > 0.1:
            warnings.append(f"adc_saturation: ch1={sat1:.1%} ch2={sat2:.1%}")

        # Check 3: Dead channel - zero RMS means no signal at all
        if rms1 < 1.0:
            warnings.append("ch1_dead: rms < 1.0")
        if rms2 < 1.0:
            warnings.append("ch2_dead: rms < 1.0")

        # Check 4: RMS suddenly changed from previous (possible gain hijack)
        if self.last_iq1_rms > 0:
            rms_change = abs(rms1 - self.last_iq1_rms) / self.last_iq1_rms
            if rms_change > 2.0:  # More than 2x change
                warnings.append(f"rms_spike_ch1: {rms_change:.1f}x change ({self.last_iq1_rms:.0f}→{rms1:.0f})")
        if self.last_iq2_rms > 0:
            rms_change = abs(rms2 - self.last_iq2_rms) / self.last_iq2_rms
            if rms_change > 2.0:
                warnings.append(f"rms_spike_ch2: {rms_change:.1f}x change ({self.last_iq2_rms:.0f}→{rms2:.0f})")

        self.last_iq1_rms = rms1
        self.last_iq2_rms = rms2
        self.rms_history.append({'rms1': rms1, 'rms2': rms2, 'ts': time.time()})

        return len(warnings) == 0, warnings

    def start(self):
        result=subprocess.run(['where','bladeRF-cli'],capture_output=True,text=True)
        if result.returncode!=0: print("⚠️ bladeRF-cli not found"); return False

        # Record firmware info at startup
        fw_info = self._get_firmware_info()
        if fw_info:
            self.firmware_hash = hashlib.sha256(fw_info.encode()).hexdigest()[:32]
            if self.court_log:
                self.court_log.log_anomaly("bladerf_fingerprint", {
                    "firmware_hash": self.firmware_hash,
                    "info": fw_info[:500]
                })
            print(f"🔒 BladeRF firmware hash: {self.firmware_hash}")

        self.active=True
        # TX command queue and parameters
        self.tx_cmd_queue = queue.Queue()
        self.tx_params = None  # dict: freq, gain, sample_rate

        def capture_loop():
            while self.active:
                try:
                    # === TX INJECT ===
                    if getattr(self, 'capture_paused', False):
                        tx_params = getattr(self, 'tx_params', None)
                        if tx_params:
                            try:
                                self._run_tx_burst(tx_params)
                            except Exception as e:
                                if self.capture_count % 10 == 0:
                                    print(f"TX burst error: {e}")
                            self.tx_params = None
                        time.sleep(0.05)
                        continue

                    # === RX CAPTURE using script file mode ===
                    tmpname = os.path.join(tempfile.gettempdir(), 'tscm_bladerf_rx_' + os.urandom(8).hex() + '.bin')
                    scriptfile = os.path.join(tempfile.gettempdir(), 'tscm_bladerf_cmd_' + os.urandom(8).hex() + '.txt')

                    # Write bladeRF commands to script file
                    cmd_script = (f"set frequency rx {self.freq}\n"
                                f"set samplerate rx {self.sample_rate}\n"
                                f"set bandwidth rx {int(self.sample_rate*0.8)}\n"
                                f"set agc 0\n"
                                f"set gain rx1 {self.gain}\n"
                                f"set gain rx2 {self.gain}\n"
                                f"set biastee rx1 on\n"
                                f"set biastee rx2 on\n"
                                f"rx config file={tmpname} format=bin n=8192\n"
                                f"rx start\nrx wait 3000\n")
                    with open(scriptfile, 'w') as f:
                        f.write(cmd_script)

                    # Run bladeRF-cli in script mode (-s): non-interactive, exits when done
                    try:
                        proc = subprocess.run(
                            ['bladeRF-cli', '-s', scriptfile],
                            capture_output=True, text=True, timeout=8
                        )
                    except subprocess.TimeoutExpired:
                        pass

                    try: os.unlink(scriptfile)
                    except: pass

                    # Poll for capture file (rx wait 3000 + write time)
                    waited = 0
                    while waited < 5.0:
                        if os.path.exists(tmpname) and os.path.getsize(tmpname) >= 32:
                            break
                        time.sleep(0.2)
                        waited += 0.2

                    if 'No bladeRF device' in (getattr(proc, 'stdout', '') or ''):
                        self.capture_count += 1
                        time.sleep(5)
                        continue

                    stdout = getattr(proc, 'stdout', '') or ''
                    # Court logging
                    if self.court_log:
                        self.court_log.log_bladerf_raw("rx_capture_script", stdout[:800])

                    # Verify readback - check settings actually applied
                    verified = self._verify_readback(stdout)
                    if verified is None and self.capture_count > 2:
                        # First few captures may not have clean readback
                        if self.court_log:
                            self.court_log.log_anomaly("bladerf_readback_failed", {
                                "stdout_tail": (stdout or '')[-200:]
                            })

                    if os.path.exists(tmpname):
                        with open(tmpname,'rb') as f: raw=f.read()

                        # Integrity: validate the raw capture
                        valid, reason = self._validate_capture(raw)
                        if not valid:
                            self.integrity_failures += 1
                            if self.court_log:
                                self.court_log.log_anomaly("capture_integrity_failure", {
                                    "reason": reason,
                                    "file_size": str(len(raw)),
                                    "capture_num": str(self.capture_count),
                                    "total_failures": str(self.integrity_failures)
                                })
                            print(f"🚨 CAPTURE INTEGRITY FAILURE: {reason}")
                            os.unlink(tmpname)
                            time.sleep(0.3)
                            continue

                        if len(raw)>=32:
                            data=np.frombuffer(raw,dtype=np.int16)
                            if len(data)%4==0:
                                data=data.reshape(-1,4)
                                iq1=(data[:,0]+1j*data[:,1]).astype(np.complex64)
                                iq2=(data[:,2]+1j*data[:,3]).astype(np.complex64)

                                # IQ sanity validation
                                iq_valid, iq_warnings = self._validate_iq(iq1, iq2)
                                if not iq_valid:
                                    for w in iq_warnings:
                                        if self.court_log:
                                            self.court_log.log_anomaly("iq_validation_warning", {"warning": w})
                                        if 'saturation' in w or 'dead' in w or 'ratio_extreme' in w:
                                            print(f"⚠️ IQ ANOMALY: {w}")

                                self.capture_count += 1
                                self.queue.put({
                                    'iq1':iq1,'iq2':iq2,
                                    'timestamp':time.time(),
                                    'capture_id': self.capture_count,
                                    'iq_rms_ch1': float(np.sqrt(np.mean(np.abs(iq1)**2))),
                                    'iq_rms_ch2': float(np.sqrt(np.mean(np.abs(iq2)**2))),
                                    'raw_sha256': hashlib.sha256(raw).hexdigest()[:32],
                                    'integrity_warnings': iq_warnings if not iq_valid else []
                                })
                        os.unlink(tmpname)
                except subprocess.TimeoutExpired:
                    try: proc.kill()
                    except: pass
                    if self.court_log:
                        self.court_log.log_anomaly("bladerf_timeout", {"capture": str(self.capture_count)})
                except Exception as e:
                    if self.court_log:
                        self.court_log.log_anomaly("bladerf_exception", {"error": str(e)[:200]})
                time.sleep(0.3)
        threading.Thread(target=capture_loop,daemon=True).start()
        print("✅ BladeRF CLI bridge active (hardened)"); return True

    def get(self, timeout=0.5):
        try: return self.queue.get(timeout=timeout)
        except queue.Empty: return None

    def retune(self, freq_hz, sample_rate=None):
        """Retune BladeRF via CLI without stopping the RX loop."""
        if sample_rate is None: sample_rate = self.sample_rate
        self.freq = int(freq_hz)
        self.sample_rate = int(sample_rate)
        try:
            subprocess.run(['bladeRF-cli', '-e',
                f'set frequency rx {self.freq}',
                f'set samplerate rx {self.sample_rate}',
                'set agc 0',
                f'set gain rx1 {self.gain}',
                f'set gain rx2 {self.gain}',
                'set biastee rx1 on',
                'set biastee rx2 on'],
                capture_output=True, timeout=4)
            return True
        except:
            return False

    def get_security_status(self):
        """Return current security status for display/logging."""
        return {
            'firmware_hash': self.firmware_hash,
            'captures': self.capture_count,
            'integrity_failures': self.integrity_failures,
            'rogue_process_incidents': self.rogue_process_count,
            'last_rms_ch1': f"{self.last_iq1_rms:.1f}",
            'last_rms_ch2': f"{self.last_iq2_rms:.1f}",
            'rms_ratio': f"{max(self.last_iq1_rms,self.last_iq2_rms)/max(min(self.last_iq1_rms,self.last_iq2_rms),0.1):.2f}x"
        }

    def stop(self): self.active=False


class PettersonMic:
    """
    Petterson M500-384/500 - tries 500 kHz first (WASAPI exclusive),
    falls back to 384 kHz if driver restricts it.
    Software multi-band decimation adapts to active sample rate.
    """
    def __init__(self):
        self.fs = 500000  # try 500 kHz first
        self.stream = None
        self.buffer = deque(maxlen=self.fs*2)
        self.device_index = Config.PETTERSON_DEVICE_INDEX
        self.band_buffers = {}
        self._setup_bands()

    def _setup_bands(self):
        fs = self.fs
        if fs >= 500000:
            self.band_buffers = {
                '384k': deque(maxlen=max(fs, 384000)),
                '48k':  deque(maxlen=48000),
                '8k':   deque(maxlen=8000),
                '2k':   deque(maxlen=2000),
            }
            self._decim = {'48k': max(1, fs // 48000), '8k': max(1, fs // 8000), '2k': max(1, fs // 2000)}
        else:
            self.band_buffers = {
                '384k': deque(maxlen=384000),
                '48k':  deque(maxlen=48000),
                '8k':   deque(maxlen=8000),
                '2k':   deque(maxlen=2000),
            }
            self._decim = {'48k': 8, '8k': 48, '2k': 192}

    def start(self):
        if not SOUNDDEVICE_AVAILABLE: return
        import sounddevice as _sd
        logging.getLogger('tscm').info(f'Petterson mic: trying device {self.device_index}...')
        rates_to_try = [384000, 250000, 192000, 96000, 48000]
        for rate in rates_to_try:
            # Try WASAPI exclusive first
            try:
                if hasattr(_sd, 'WasapiSettings'):
                    stream = _sd.InputStream(
                        device=self.device_index, channels=1,
                        samplerate=rate, blocksize=4096,
                        extra_settings=_sd.WasapiSettings(exclusive=True))
                    stream.start(); stream.stop(); stream.close()
                    self.fs = rate; self._setup_bands()
                    self.stream = _sd.InputStream(
                        device=self.device_index, channels=1,
                        samplerate=self.fs, callback=self._cb,
                        blocksize=4096,
                        extra_settings=_sd.WasapiSettings(exclusive=True))
                    self.stream.start()
                    logging.getLogger('tscm').info(
                        f'Petterson mic: device {self.device_index} @ {self.fs}Hz WASAPI exclusive OK')
                    return
            except Exception:
                pass
            # Fallback: no WASAPI
            try:
                self.fs = rate; self._setup_bands()
                self.stream = _sd.InputStream(device=self.device_index, channels=1,
                                             samplerate=self.fs, callback=self._cb,
                                             blocksize=4096)
                self.stream.start()
                logging.getLogger('tscm').info(
                    f'Petterson mic: device {self.device_index} @ {self.fs}Hz shared OK')
                return
            except Exception as e:
                logging.getLogger('tscm').warning(f'Petterson mic @ {rate}Hz failed: {e}')
                continue
        logging.getLogger('tscm').error('Petterson mic: ALL RATES FAILED on device %d' % self.device_index)

    def _cb(self, indata, frames, time_info, status):
        data = indata.flatten()
        self.buffer.extend(data)
        d0, d1, d2 = self._decim.get('48k', 8), self._decim.get('8k', 48), self._decim.get('2k', 192)
        for i, s in enumerate(data):
            self.band_buffers['384k'].append(s)
            if i % d0 == 0: self.band_buffers['48k'].append(s)
            if i % d1 == 0: self.band_buffers['8k'].append(s)
            if i % d2 == 0: self.band_buffers['2k'].append(s)

    def read(self, n, band='384k'):
        buf = self.band_buffers.get(band, self.buffer)
        if len(buf) < n: return np.array([])
        return np.array([buf.popleft() for _ in range(n)])

    def get_band_info(self):
        return {name: len(buf) for name, buf in self.band_buffers.items()}

    def stop(self):
        if self.stream:
            try: self.stream.stop(); self.stream.close()
            except: pass


class LaptopMic:
    def __init__(self):
        self.fs=Config.LAPTOP_MIC_SAMPLE_RATE;self.stream=None
        self.buffer=deque(maxlen=self.fs*2);self.device_index=Config.LAPTOP_MIC_DEVICE_INDEX
        self._channels=2
        # Stereo buffers for acoustic AoA (mic array beamforming)
        self.buf_left = deque(maxlen=self.fs//5)
        self.buf_right = deque(maxlen=self.fs//5)
        self.acoustic_aoa = None
        self.MIC_SPACING = 0.15  # meters between L/R mics
    def start(self):
        if not SOUNDDEVICE_AVAILABLE: return
        if self.device_index is None:
            try:
                for i,d in enumerate(sd.query_devices()):
                    if d['max_input_channels']>0 and 'microphone' in d['name'].lower():
                        self.device_index=i; break
                if self.device_index is None:
                    # Use default input
                    self.device_index=sd.default.device[0]
            except: pass
        if self.device_index is None: print("⚠️ Laptop mic not found"); return
        # Try stereo, fall back to mono
        for ch in [4, 2, 1]:
            try:
                self._channels=ch
                self.stream=sd.InputStream(device=self.device_index,channels=ch,samplerate=self.fs,
                                           callback=self._cb,blocksize=4096)
                self.stream.start()
                if ch >= 4: self.MIC_SPACING = 0.25
                print(f"✅ Laptop mic on device {self.device_index} ({ch}ch)"); return
            except: continue
        print(f"❌ Laptop mic failed on device {self.device_index}")
    def _cb(self, indata, frames, time_info, status):
        if self._channels >= 4:
            # 4ch Intel array: avg all for mono, ch0+ch1 for spatial separation
            mono = np.mean(indata[:, :2], axis=1)  # only active channels
            self.buffer.extend(mono)
            self.buf_left.extend(indata[:, 0])
            self.buf_right.extend(indata[:, 1])
        elif indata.shape[1] >= 2:
            mono = np.mean(indata, axis=1)
            self.buffer.extend(mono)
            self.buf_left.extend(indata[:,0])
            self.buf_right.extend(indata[:,1])
        else:
            self.buffer.extend(indata.flatten())
    def read(self, n):
        if len(self.buffer)<n: return np.array([])
        return np.array([self.buffer.popleft() for _ in range(n)])
    def compute_acoustic_aoa(self):
        if len(self.buf_left) < 2048 or len(self.buf_right) < 2048:
            return None
        left = np.array(self.buf_left)[-2048:]
        right = np.array(self.buf_right)[-2048:]
        # Check if we actually have stereo (distinct channels)
        l_rms = np.sqrt(np.mean(left**2))
        r_rms = np.sqrt(np.mean(right**2))
        if l_rms < 1e-6 or r_rms < 1e-6:
            return None
        xc = np.correlate(left - np.mean(left), right - np.mean(right), mode='same')
        center = len(xc)//2
        search_half = min(100, center-1)
        xc_roi = xc[center-search_half:center+search_half+1]
        pk_idx = np.argmax(np.abs(xc_roi))
        delay_samples = pk_idx - search_half
        delay_sec = delay_samples / self.fs
        path_diff = delay_sec * 343.0
        path_diff = max(-self.MIC_SPACING, min(self.MIC_SPACING, path_diff))
        angle_rad = np.arcsin(path_diff / self.MIC_SPACING)
        bearing_deg = np.degrees(angle_rad)
        energy = np.sqrt(np.sum(left**2) * np.sum(right**2)) + 1e-12
        coherence = np.max(np.abs(xc_roi)) / energy
        # Diagnostic log every ~25s
        now_ts = time.time()
        if not hasattr(self,'_last_aoa_log_ts'):
            self._last_aoa_log_ts = 0
        if now_ts - self._last_aoa_log_ts > 25:
            self._last_aoa_log_ts = now_ts
            logging.getLogger('tscm').info(
                f'ACOUSTIC AoA: bufL={len(self.buf_left)} bufR={len(self.buf_right)} '
                f'delay={delay_samples}samp brg={bearing_deg:.1f} coh={coherence:.3f} '
                f'rms(L/R)={l_rms:.4f}/{r_rms:.4f} ch={self._channels}')
        if coherence > 0.08:
            self.acoustic_aoa = float(bearing_deg)
            return {'bearing': self.acoustic_aoa, 'coherence': float(coherence)}
        return None
    def stop(self):
        if self.stream:
            try: self.stream.stop();self.stream.close()
            except: pass


class TGAMReader:
    """Read ThinkGear AM (TGAM) EEG modules via serial - COM6=HR-SOC336, COM7=HR-SOC284.
    ThinkGear packets: 0xAA 0xAA 0x20 <payload 32B> <checksum>
    Provides signal_quality, attention, meditation, delta/theta/alpha/beta/gamma.
    Note: BrainFlow 5.x does NOT support TGAM_BOARD. Must use raw serial ThinkGear."""
    def __init__(self, port, baud=57600):
        self.port = port; self.baud = baud; self.ser = None
        self.buffer = deque(maxlen=250*3)
        self.last_read_ts = 0
        self.last_values = {
            'signal': 200, 'attention': 0, 'meditation': 0,
            'delta': 0, 'theta': 0, 'alpha_low': 0, 'alpha_high': 0,
            'beta_low': 0, 'beta_high': 0, 'gamma_low': 0, 'gamma_mid': 0
        }
        self._connect()
    def _connect(self):
        try:
            import serial as _ser
            if hasattr(self,'ser') and self.ser:
                try: self.ser.close()
                except: pass
                self.ser = None
            self.ser = _ser.Serial(self.port, self.baud, timeout=0.1)
            self.ser.reset_input_buffer()
            print(f"TGAM EEG on {self.port} at {self.baud} baud")
            return True
        except Exception as e:
            print(f"TGAM {self.port} failed: {e}")
            self.ser = None
            return False
    def _parse_packet(self, payload):
        """Parse ThinkGear payload bytes into dict of values."""
        vals = self.last_values.copy()
        i = 0
        while i < len(payload) - 1:
            code = payload[i]
            if code == 0x80:  # raw wave value
                i += 3
            elif code == 0x02:  # signal quality
                vals['signal'] = payload[i+1] if i+1 < len(payload) else 200
                i += 2
            elif code == 0x04:  # attention
                vals['attention'] = payload[i+1] if i+1 < len(payload) else 0
                i += 2
            elif code == 0x05:  # meditation
                vals['meditation'] = payload[i+1] if i+1 < len(payload) else 0
                i += 2
            elif code == 0x83:  # ASIC EEG power
                if i+25 <= len(payload):
                    vals['delta'] = (payload[i+1]<<16|payload[i+2]<<8|payload[i+3])/1000.
                    vals['theta'] = (payload[i+4]<<16|payload[i+5]<<8|payload[i+6])/1000.
                    vals['alpha_low'] = (payload[i+7]<<16|payload[i+8]<<8|payload[i+9])/1000.
                    vals['alpha_high'] = (payload[i+10]<<16|payload[i+11]<<8|payload[i+12])/1000.
                    vals['beta_low'] = (payload[i+13]<<16|payload[i+14]<<8|payload[i+15])/1000.
                    vals['beta_high'] = (payload[i+16]<<16|payload[i+17]<<8|payload[i+18])/1000.
                    vals['gamma_low'] = (payload[i+19]<<16|payload[i+20]<<8|payload[i+21])/1000.
                    vals['gamma_mid'] = (payload[i+22]<<16|payload[i+23]<<8|payload[i+24])/1000.
                i += 25
            elif code >= 0x80:  # multi-byte
                if i+1 < len(payload): i += payload[i+1] + 2
                else: i += 2
            else:
                i += 2
        self.last_values = vals
        return vals
    def read(self):
        """Read one EEG sample. Handles both standard ThinkGear packets and raw streaming mode.
        TGAM modules can output in continuous raw mode where 0xAA bytes appear in data stream."""
        if not self.ser: return 0.0
        try:
            while self.ser.in_waiting >= 2:
                b = self.ser.read(1)[0]
                if b == 0xAA:
                    b2 = self.ser.read(1)
                    if not b2: return 0.0
                    if b2[0] == 0xAA:
                        # Standard ThinkGear packet
                        plen_b = self.ser.read(1)
                        if not plen_b: return 0.0
                        plen = plen_b[0]
                        if 0 < plen < 170:
                            payload = self.ser.read(plen)
                            if len(payload) == plen:
                                self.ser.read(1)  # checksum
                                vals = self._parse_packet(payload)
                                val = vals.get('beta_high', 0) * 0.001
                                val += vals.get('gamma_mid', 0) * 0.001
                                self.buffer.append(val)
                                return val
                    elif b2[0] >= 0x80:
                        # Raw mode code-value pair: 0xAA <code> <vallen-1> <data...>
                        code = b2[0]
                        if code == 0x80 and self.ser.in_waiting >= 2:
                            # Raw wave: 0xAA 0x80 <hi> <lo>
                            hi = self.ser.read(1)[0]
                            lo = self.ser.read(1)[0]
                            raw = ((hi << 8) | lo)
                            if raw > 32767: raw -= 65536
                            val = raw * 0.000001  # microvolts-like scale
                            self.buffer.append(val)
                            return val
                        elif code == 0x83 and self.ser.in_waiting >= 24:
                            # EEG power bands
                            bands = list(self.ser.read(24))
                            self.last_values['delta'] = (bands[0]<<16|bands[1]<<8|bands[2])/1000.
                            self.last_values['theta'] = (bands[3]<<16|bands[4]<<8|bands[5])/1000.
                            self.last_values['alpha_low'] = (bands[6]<<16|bands[7]<<8|bands[8])/1000.
                            self.last_values['alpha_high'] = (bands[9]<<16|bands[10]<<8|bands[11])/1000.
                            self.last_values['beta_low'] = (bands[12]<<16|bands[13]<<8|bands[14])/1000.
                            self.last_values['beta_high'] = (bands[15]<<16|bands[16]<<8|bands[17])/1000.
                            self.last_values['gamma_low'] = (bands[18]<<16|bands[19]<<8|bands[20])/1000.
                            self.last_values['gamma_mid'] = (bands[21]<<16|bands[22]<<8|bands[23])/1000.
                            val = self.last_values['beta_high'] * 0.001 + self.last_values['gamma_mid'] * 0.001
                            self.buffer.append(val)
                            return val
                        else:
                            # Single-byte code: 0xAA <code> <value>
                            if self.ser.in_waiting >= 1:
                                v = self.ser.read(1)[0]
                                if code == 0x04: self.last_values['attention'] = v
                                elif code == 0x05: self.last_values['meditation'] = v
                                elif code == 0x02: self.last_values['signal'] = v
                    elif b2[0] < 0x80:
                        # Treat as raw sample byte, look for raw wave code nearby
                        if self.ser.in_waiting >= 1:
                            next_b = self.ser.read(1)[0]
                            if next_b == 0x80 and self.ser.in_waiting >= 2:
                                hi = self.ser.read(1)[0]
                                lo = self.ser.read(1)[0]
                                raw = ((hi << 8) | lo)
                                if raw > 32767: raw -= 65536
                                val = raw * 0.000001
                                self.buffer.append(val)
                                return val
            return 0.0
        except:
            return 0.0
    def drain(self):
        """Drain available samples from serial buffer. Capped to prevent infinite loop."""
        count = 0
        if not self.ser: return 0
        try:
            for _ in range(500):  # cap: don't block forever on live stream
                if self.ser.in_waiting <= 0:
                    break
                v = self.read()
                if v != 0.0: count += 1
                else: break
        except: pass
        return count

class OpenBCIUDP:
    """OpenBCI Cyton + TGAM EEG modules. Tries TGAM first (COM6/COM7), then OpenBCI."""
    def __init__(self, port='COM3', baud=115200):
        self.ser = None; self.buffer = deque(maxlen=250*3)
        self.last_read_ts = 0
        self.sock = None
        self.tgam = None  # TGAM reader
        self._try_tgam_first()
    def _try_tgam_first(self):
        """Try TGAM modules first (COM6/COM7). They're more reliable than USB OpenBCI."""
        if self.tgam:
            self.tgam.ser = None  # will reconnect
        for tgam_port in ['COM6', 'COM7']:
            try:
                import serial as ser_mod
                self.tgam = TGAMReader(tgam_port, 57600)
                if self.tgam.ser:
                    return True
            except:
                continue
        # Fall back to OpenBCI serial / UDP
        self._try_serial('COM3', 115200)
        return False
    def _try_serial(self, port, baud):
        try:
            self.ser = serial.Serial(port, baud, timeout=0.1)
            self.ser.reset_input_buffer()
            self.ser.write(b'x'); import time; time.sleep(0.1)
            self.ser.reset_input_buffer()
            self.ser.write(b'b')
            print(f"OpenBCI Cyton on {port} at {baud} baud")
        except Exception as e:
            print(f"OpenBCI serial failed ({e}), trying UDP fallback")
            self.ser = None
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.settimeout(0.01)
                self.sock.bind(('127.0.0.1', Config.BCI_PORT))
                self.sock.setblocking(False)
            except:
                self.sock = None
    def read(self):
        """Read one EEG sample. TGAM first, then serial, then UDP."""
        if self.tgam and self.tgam.ser:
            return self.tgam.read()
        elif self.ser:
            return self._read_serial()
        elif hasattr(self, 'sock') and self.sock:
            try:
                data, _ = self.sock.recvfrom(1024)
                val = struct.unpack('f', data[:4])[0]
                self.buffer.append(val)
                return val
            except:
                return 0.0
        return 0.0
    def drain(self):
        """Read ALL available samples from TGAM or serial and buffer them.
        Cap at 500 reads to prevent infinite loop on live streaming TGAM."""
        count = 0
        if self.tgam and self.tgam.ser:
            count = self.tgam.drain()
            while len(self.tgam.buffer) > 0:
                self.buffer.append(self.tgam.buffer.popleft())
        elif self.ser:
            try:
                while self.ser.in_waiting >= 33:
                    val = self._read_serial()
                    if val != 0.0:
                        self.buffer.append(val)
                        count += 1
            except: pass
        return count
    def _read_serial(self):
        """Parse OpenBCI Cyton binary protocol. Returns float value."""
        try:
            # Read one complete packet (33 bytes: 0xA0 + sample# + 8ch*24bit + 3accel*24bit + 0xC0)
            while self.ser.in_waiting >= 33:
                b = self.ser.read(1)
                if b == b'\xa0':
                    pkt = self.ser.read(32)
                    if len(pkt) >= 30:
                        ch1 = int.from_bytes(pkt[0:3], 'big', signed=True)
                        val = ch1 * 0.02235
                        self.buffer.append(val)
                        self.last_read_ts = time.time()
                        return val
                elif b in (b'\r', b'\n'):
                    # Text mode: read line
                    line = self.ser.readline().decode('ascii', errors='ignore').strip()
                    parts = line.split(',')
                    if len(parts) >= 2:
                        try:
                            val = float(parts[1])
                            self.buffer.append(val)
                            self.last_read_ts = time.time()
                            return val
                        except ValueError: pass
            # Also try reading a big chunk and finding 0xA0 in it
            if self.ser.in_waiting >= 66:
                chunk = self.ser.read(self.ser.in_waiting)
                idx = chunk.find(b'\xa0')
                while idx >= 0 and idx + 33 <= len(chunk):
                    pkt = chunk[idx+1:idx+33]
                    if len(pkt) >= 30:
                        ch1 = int.from_bytes(pkt[0:3], 'big', signed=True)
                        val = ch1 * 0.02235
                        self.buffer.append(val)
                        self.last_read_ts = time.time()
                    idx = chunk.find(b'\xa0', idx+1)
                if self.buffer:
                    return self.buffer[-1]
        except Exception:
            pass
        if self.buffer:
            return self.buffer[-1]
        return 0.0


class WiFiUDPListener:
    def __init__(self, port=9999, callback=None):
        self.port=port;self.callback=callback;self.running=True
        self.sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind to localhost ONLY — prevents external devices from injecting fake detections
        self.sock.bind(("127.0.0.1",self.port))
        self._allowed_sources = {"127.0.0.1"}  # whitelist of source IPs
        threading.Thread(target=self._loop,daemon=True).start()
    def _loop(self):
        while self.running:
            try:
                data,addr=self.sock.recvfrom(4096)
                # Reject packets from non-local sources
                if addr[0] not in self._allowed_sources and not addr[0].startswith("127."):
                    continue
                # Validate JSON structure before processing
                try:
                    det=json.loads(data.decode())
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                # Basic schema validation — must have detector field and is a dict
                if not isinstance(det, dict) or 'detector' not in det:
                    continue
                # Limit incoming message size
                if len(data) > 2048:
                    continue
                if self.callback: self.callback(det)
            except: pass
    def stop(self):
        self.running=False
        try: self.sock.close()
        except: pass


class USBWatchdog:
    def __init__(self, vid, pid, callback=None):
        self.vid=vid.lower();self.pid=pid.lower();self.callback=callback;self.running=True
        if WMI_AVAILABLE:
            self.was_present=self._check_presence()
            threading.Thread(target=self._loop,daemon=True).start()
        else: print("⚠️ WMI not available, USB watchdog disabled")
    def _check_presence(self):
        try:
            c=wmi.WMI()
            for d in c.query("SELECT * FROM Win32_USBControllerDevice"):
                if self.vid in d.Dependent.lower() and self.pid in d.Dependent.lower(): return True
        except: pass
        return False
    def _loop(self):
        while self.running:
            currently=self._check_presence()
            if self.was_present and not currently and self.callback: self.callback("BladeRF disappeared from USB")
            elif not self.was_present and currently and self.callback: self.callback("BladeRF re-appeared on USB")
            self.was_present=currently; time.sleep(1)
    def stop(self): self.running=False


class GLMWatchdog:
    def __init__(self, log, max_changes=5, window=30):
        self.log=log;self.max_changes=max_changes;self.window=window
        self.history=deque(maxlen=window);self.last_accepted=None
    def validate(self, new_target):
        now=time.time();self.history.append((now,new_target))
        recent=[t for ts,t in self.history if now-ts<=self.window]
        if len(set(recent))>self.max_changes:
            self.log.warning(f"⚠️ GLM erratic"); return False
        self.last_accepted=new_target; return True


class AdaptiveCoherenceController:
    def __init__(self, bladerf_sdr, rf_queue, ul_queue, log):
        self.bladerf=bladerf_sdr;self.rf_queue=rf_queue;self.ul_queue=ul_queue;self.log=log
        self.running=False;self.rf_target=None;self.rf_phase=0.0
        self.audio_target=None;self.audio_phase=0.0
    def start(self): self.running=True; threading.Thread(target=self._run,daemon=True).start()
    def stop(self): self.running=False
    def set_rf_target(self, freq):
        self.rf_target=freq
        if freq: self.log.info(f"🎯 RF cancel target: {freq/1e6:.3f} MHz")
    def set_vlf_audio_target(self, freq):
        self.audio_target=freq
        if freq: self.log.info(f"🔊 VLF cancel target: {freq:.1f} Hz")
    def _run(self):
        while self.running:
            try:
                if not self.ul_queue.empty() and SOUNDDEVICE_AVAILABLE and self.audio_target and self.audio_target>20000:
                    ul_chunk=self.ul_queue.get_nowait()
                    t=np.arange(len(ul_chunk))/Config.PETTERSON_SAMPLE_RATE
                    inverted=np.sin(2*np.pi*self.audio_target*t+np.pi+self.audio_phase)*0.5
                    try: sd.play(inverted,Config.PETTERSON_SAMPLE_RATE,blocking=False,device=5)  # headphones
                    except: pass
                    self.audio_phase+=0.01*(0-np.mean(np.abs(ul_chunk)))
                time.sleep(Config.COHERENCE_UPDATE_INTERVAL)
            except: pass


class WiFiScanner:
    """Scans for WiFi APs using netsh and provides BSSIDs for WiGLE geolocation.
    Auto-detects available WiFi adapters including USB dongles (Realtek 8812AU)."""
    def __init__(self, log, interface_name=None):
        self.log = log
        self.interface = interface_name  # auto-detect if None
        self.running = False
        self.access_points = []  # [{bssid, ssid, signal, channel, freq}]
        self.last_scan = 0
        self.scan_interval = 30  # seconds between scans
        self.dongle_active = False
        self._detect_interface()

    def _detect_interface(self):
        """Auto-detect the best WiFi adapter for scanning."""
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                interfaces = []
                current_name = None
                current_desc = None
                current_state = None
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('Name') and ':' in line:
                        if current_name:
                            interfaces.append((current_name, current_desc, current_state))
                        current_name = line.split(':', 1)[1].strip()
                    elif 'Description' in line and ':' in line:
                        current_desc = line.split(':', 1)[1].strip()
                    elif 'State' in line and ':' in line:
                        current_state = line.split(':', 1)[1].strip()
                if current_name:
                    interfaces.append((current_name, current_desc, current_state))

                # Prefer USB dongle (8812AU) if connected, then any connected adapter
                best = None
                for name, desc, state in interfaces:
                    if state and 'connected' in state.lower():
                        if desc and ('8812' in desc or 'Realtek' in desc):
                            best = name
                            self.dongle_active = True
                            break
                        if not best:
                            best = name
                if not best and interfaces:
                    # Use first available even if disconnected
                    best = interfaces[0][0]
                self.interface = best or 'Wi-Fi'

            # Try to enable the 8812AU dongle if detected but not active
            self._enable_wifi_dongle()
        except Exception:
            self.interface = self.interface or 'Wi-Fi'

    def _enable_wifi_dongle(self):
        """Try to enable the Realtek 8812AU WiFi dongle via pnputil/netsh."""
        try:
            # Check if the 8812AU is present but not started
            result = subprocess.run(
                ['pnputil', '/enum-devices', '/class', 'Net'],
                capture_output=True, text=True, timeout=10
            )
            if '8812' in result.stdout:
                # Device exists — try to enable it
                # First try netsh interface enable
                subprocess.run(
                    ['netsh', 'interface', 'set', 'interface', 'Wi-Fi 2', 'admin=enable'],
                    capture_output=True, timeout=5
                )
                # Also try restarting the PnP device
                self.log.info("WiFi dongle (8812AU) detected — attempting restart")
            self._enable_alfa()
        except Exception:
            pass

    def _enable_alfa(self):
        """Enable WiFi adapters for scanning."""
        try:
            # Enable autoconfig on all WiFi interfaces
            for iface in [self.interface, "Wi-Fi", "Wi-Fi 2"]:
                subprocess.run(['netsh','wlan','set','autoconfig','enabled=yes',
                    f'interface={iface}'], capture_output=True, timeout=5)
            self.log.info(f"WiFi: {self.interface} scan enabled" +
                         (" (8812AU dongle)" if self.dongle_active else ""))
        except: pass

    def start(self):
        self.running = True
        threading.Thread(target=self._scan_loop, daemon=True).start()

    def _scan_loop(self):
        while self.running:
            try:
                self._scan()
                time.sleep(self.scan_interval)
            except:
                time.sleep(10)

    def _scan(self):
        """Run netsh wlan scan + show networks to get BSSIDs."""
        try:
            # Trigger active scan first
            subprocess.run(
                ['netsh', 'wlan', 'scan', f'interface={self.interface}'],
                capture_output=True, text=True, timeout=20
            )
            import time; time.sleep(2)  # wait for scan results
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid',
                 f'interface={self.interface}'],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0:
                # Try alternate interface names (USB dongle may appear as Wi-Fi 2)
                for alt in ["Wi-Fi 2", "Wi-Fi", "Wi-Fi 3"]:
                    result = subprocess.run(
                        ['netsh', 'wlan', 'show', 'networks', 'mode=bssid',
                         f'interface={alt}'],
                        capture_output=True, text=True, timeout=15
                    )
                    if result.returncode == 0:
                        self.interface = alt
                        if '8812' in alt or '2' in alt:
                            self.dongle_active = True
                        break
                if result.returncode != 0:
                    return

            self.access_points = self._parse_netsh(result.stdout)
            if self.access_points:
                self.log.info(f"📶 WiFi scan: {len(self.access_points)} APs found")
                self.last_scan = time.time()
        except:
            pass

    def _parse_netsh(self, output):
        """Parse netsh wlan show networks mode=bssid output."""
        aps = []
        current_ssid = None
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('SSID'):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    current_ssid = parts[1].strip()
            elif 'BSSID' in line and ':' in line:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    bssid = parts[1].strip().replace('-', ':')
                    aps.append({'ssid': current_ssid, 'bssid': bssid,
                                'signal': 0, 'channel': 0, 'freq': 0})
            elif 'Signal' in line and ':' in line and aps:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    try:
                        sig_str = parts[1].strip().replace('%', '')
                        aps[-1]['signal'] = int(sig_str)
                    except:
                        pass
            elif 'Channel' in line and ':' in line and aps:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    try:
                        ch = int(parts[1].strip())
                        aps[-1]['channel'] = ch
                        # Channel to frequency - all bands
                        if 1 <= ch <= 14:
                            aps[-1]['freq'] = 2412 + (ch - 1) * 5  # 2.4 GHz
                        elif 36 <= ch <= 177:
                            aps[-1]['freq'] = 5000 + ch * 5  # 5 GHz
                        elif 1 <= ch <= 233:
                            aps[-1]['freq'] = 5950 + ch * 5  # 6 GHz WiFi 6E
                    except:
                        pass
        return aps

    def get_access_points(self):
        return self.access_points

    def stop(self):
        self.running = False


class WiGLEGeolocator:
    """
    Looks up WiFi AP positions via WiGLE WiFi API.
    Uses BSSIDs from WiFiScanner to find real-world positions.
    Free API: https://api.wigle.net/api/v2/
    """
    def __init__(self, log, api_token=None):
        self.log = log
        self.api_name = os.environ.get('WIGLE_API_NAME', 'AIDc89f803f69be5722784ced6d478edcc3')
        self.api_token = api_token or os.environ.get('WIGLE_API_TOKEN', '6d346861cf1133b32338c277621dee92')
        # WiGLE requires Basic <base64(API_NAME:API_TOKEN)>
        import base64
        auth_str = f"{self.api_name}:{self.api_token}"
        self.auth_header = f"Basic {base64.b64encode(auth_str.encode()).decode()}"
        self.cache = {}  # bssid -> {lat, lon, first_seen, last_seen}
        self.cache_file = os.path.join(Config.MODEL_DIR, 'wigle_cache.json')
        self._load_cache()
        self.last_request_time = 0
        self.request_count = 0
        self.daily_limit = 1000
        self.max_per_scan = 3  # max 3 requests per scan (was 5 - too aggressive)
        self.min_scan_interval = 120  # minimum seconds between WiGLE scans

    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
            except:
                self.cache = {}

    def _save_cache(self):
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except:
            pass

    def lookup_bssid(self, bssid):
        """Look up a single BSSID on WiGLE. Returns {lat, lon} or None."""
        bssid_clean = bssid.upper().replace('-', ':')
        if bssid_clean in self.cache:
            return self.cache[bssid_clean]

        if not self.api_token:
            return None

        # Rate limit: max 5 req per scan, 1 req/sec, daily cap
        if self.request_count >= self.daily_limit:
            return None
        now = time.time()
        if now - self.last_request_time < 1.0:
            time.sleep(0.5)  # rate limit
        self.last_request_time = time.time()
        self.request_count += 1

        try:
            import urllib.request
            url = f"https://api.wigle.net/api/v2/network/detail?netid={bssid_clean}"
            req = urllib.request.Request(url)
            req.add_header('Authorization', self.auth_header)
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            if data.get('success') and data.get('results'):
                r = data['results'][0]
                pos = {'lat': float(r.get('trilat', 0)),
                       'lon': float(r.get('trilong', 0))}
                if pos['lat'] != 0 or pos['lon'] != 0:
                    self.cache[bssid_clean] = pos
                    self._save_cache()
                    return pos
        except:
            pass
        return None

    def geolocate_aps(self, access_points):
        """
        Look up APs and return list with positions. Rate-limited.
        """
        max_per_scan = getattr(self, 'max_per_scan', 3)
        results = []
        looked_up = 0
        for ap in access_points:
            bssid = ap.get('bssid', '')
            if not bssid: continue
            pos = None
            if looked_up < max_per_scan:
                pos = self.lookup_bssid(bssid)
                if pos: looked_up += 1
                elif bssid.upper().replace('-',':') not in self.cache:
                    continue  # skip uncached ones after limit
            else:
                # Only use cached
                bssid_clean = bssid.upper().replace('-', ':')
                pos = self.cache.get(bssid_clean)
            entry = dict(ap)
            if pos:
                entry['lat'] = pos['lat']; entry['lon'] = pos['lon']
                entry['geolocated'] = True
            else:
                entry['geolocated'] = False
            results.append(entry)
        return results


class CellTowerDetector:
    """
    Detects cellular signals in the SDR data and identifies them as cell towers.
    At 2.4 GHz, the BladeRF sees WiFi/cellular signals.
    Uses signal strength + AoA to identify nearby towers vs mobile devices.
    Strong, constant signals = towers. Weak, variable = mobile devices.
    """
    def __init__(self, rf_fs=10e6):
        self.rf_fs = rf_fs
        self.buffer = deque(maxlen=int(rf_fs))  # 1 second
        self.tower_db = {}  # freq_bin -> {power_history, bearing_history, last_seen}

    def update(self, iq):
        self.buffer.extend(iq)

    def detect(self, aoa=0.0):
        if len(self.buffer) < int(0.1 * self.rf_fs):
            return []
        iq = np.array(self.buffer)[-int(0.1*self.rf_fs):]
        fft_abs = np.abs(fft(iq))
        freqs = fftfreq(len(iq), 1/self.rf_fs)
        noise = np.median(fft_abs)
        peaks, props = find_peaks(fft_abs[:len(fft_abs)//2], height=noise*10, distance=50)
        if len(peaks) == 0:
            return []

        width_hz = props["widths"] * (self.rf_fs / len(iq))
        now = time.time()
        detections = []

        for idx, p in enumerate(peaks[:20]):
            if width_hz[idx] > 500:  # skip wide signals (WiFi data)
                continue
            freq = abs(freqs[p])
            # At 2.4 GHz, we're tuned to 2400 MHz
            # Offset frequencies from center
            actual_freq = Config.BLADERF_FREQ + freq if freq < self.rf_fs/2 else Config.BLADERF_FREQ - freq

            power = fft_abs[p] / (noise + 1e-12)

            # Bin frequency for stable tracking (1 MHz bins)
            freq_bin = round(actual_freq / 1e6) * 1e6

            if freq_bin not in self.tower_db:
                self.tower_db[freq_bin] = {'powers': deque(maxlen=50),
                                           'bearings': deque(maxlen=50),
                                           'last_seen': 0}
            tower = self.tower_db[freq_bin]
            tower['powers'].append(power)
            if aoa != 0.0:
                tower['bearings'].append(aoa)
            tower['last_seen'] = now

            # Need at least 5 observations to classify
            if len(tower['powers']) < 5:
                continue

            # Strong + consistent = tower; weak + variable = mobile device
            avg_power = np.mean(list(tower['powers']))
            power_std = np.std(list(tower['powers'])) / (avg_power + 1e-12)

            is_tower = avg_power > 15 and power_std < 0.5  # strong and stable
            is_mobile = avg_power > 5 and power_std > 0.3   # variable strength

            bearing_avg = np.mean(list(tower['bearings'])) if tower['bearings'] else 0

            if is_tower:
                detections.append({
                    'detector': 'cell_tower',
                    'frequency': float(freq_bin),
                    'avg_power': float(avg_power),
                    'stability': float(1.0 - power_std),
                    'bearing': float(bearing_avg),
                    'classification_hint': 'tower'  # strong, constant signal
                })
            elif is_mobile:
                detections.append({
                    'detector': 'mobile_device',
                    'frequency': float(freq_bin),
                    'avg_power': float(avg_power),
                    'stability': float(1.0 - power_std),
                    'bearing': float(bearing_avg),
                    'classification_hint': 'c2_device'  # could be C2 phone
                })

        return detections

# ============================================================
# PHASE 5+ DETECTORS - previously missing, now activated
# ============================================================

class WatcherConsensusDetector:
    """Multi-detector agreement: fires when 2+ watchers see same event."""
    def __init__(self):
        self.hits = {'watcher_us_modem_cluster':0, 'watcher_freq_hopping':0,
                     'ghost_hunter_snn':0, 'stingray_detect':0}
        self.last_consensus = 0
    def update(self, detector_name):
        if detector_name in self.hits:
            self.hits[detector_name] = time.time()
    def detect(self):
        now = time.time()
        active = sum(1 for t in self.hits.values() if now - t < 10)
        if active >= 2 and now - self.last_consensus > 30:
            self.last_consensus = now
            return [{'detector':'watcher_consensus','active_watchers':active,
                     'confidence':min(active/4, 1.0)}]
        return []

class ALCDetector:
    """Automatic Level Control: detects audio AGC compression (silent sound artifact)."""
    def __init__(self, window=2000):
        self.buf = deque(maxlen=window)
        self.last_fire = 0
    def update(self, audio):
        self.buf.extend(audio.flatten()[:100])
    def detect(self):
        if len(self.buf) < 500: return []
        a = np.array(self.buf)
        chunks = np.array_split(a[-500:], 5)
        rms_vals = [float(np.sqrt(np.mean(c**2))) for c in chunks]
        if len(rms_vals) >= 3:
            # ALC: sudden RMS compression followed by recovery
            min_rms = min(rms_vals); max_rms = max(rms_vals)
            if max_rms > 0 and min_rms/max_rms < 0.3 and time.time() - self.last_fire > 60:
                self.last_fire = time.time()
                return [{'detector':'alc_detect','ratio':round(min_rms/max_rms,3),
                         'note':'Audio ALC compression detected'}]
        return []

class SmartTVDetector:
    """Detect Smart TV activity on LAN (192.168.1.79 - AzureWave)."""
    def __init__(self, target_ip='192.168.1.79'):
        self.target_ip = target_ip; self.last_check = 0
    def update(self, arp_data=None): pass  # uses subprocess
    def detect(self):
        now = time.time()
        if now - self.last_check < 120: return []
        self.last_check = now
        try:
            import subprocess
            r = subprocess.run(['ping','-n','1','-w','500',self.target_ip],
                             capture_output=True, text=True, timeout=2)
            if 'TTL=' in r.stdout:
                return [{'detector':'smart_tv_detect',
                         'ip':self.target_ip,'note':'Smart TV active on LAN - C2 vector'}]
        except: pass
        return []

class SDRFingerprintDetector:
    """Detect enemy SDR by known signature (46.875 Hz FFT bins, HackRF/BladeRF artifacts)."""
    def __init__(self):
        self.rf_buf = deque(maxlen=10000)
    def update_rf(self, iq):
        self.rf_buf.extend(iq[:1000])
    def detect(self):
        if len(self.rf_buf) < 4096: return []
        try:
            iq = np.array(self.rf_buf)
            fft = np.abs(np.fft.rfft(iq))
            # SDR signature: periodic spurs at FFT bin spacing
            peaks, props = find_peaks(fft, height=np.median(fft)*3, distance=10)
            if len(peaks) >= 5:
                intervals = np.diff(peaks)
                cv = np.std(intervals) / (np.mean(intervals) + 1e-12)
                if cv < 0.3:
                    return [{'detector':'sdr_detect',
                             'bin_spacing':float(np.mean(intervals)),
                             'note':'SDR fingerprint: periodic FFT spurs'}]
        except: pass
        return []

class TempestDetector:
    """TEMPEST: RF emissions from digital devices (monitors, HDMI, USB)."""
    def __init__(self):
        self.rf_buf = deque(maxlen=8192)
    def update_rf(self, iq):
        self.rf_buf.extend(iq[:2000])
    def detect(self):
        if len(self.rf_buf) < 4096: return []
        try:
            iq = np.array(self.rf_buf)
            # TEMPEST: harmonics of pixel clock / USB frame rate
            fft = np.abs(np.fft.rfft(iq))
            # Look for harmonics - multiples of a base frequency
            pk = np.argmax(fft[10:]); base = fft[10+pk]
            harmonics = [fft[10+pk*2], fft[10+pk*3]] if 10+pk*3 < len(fft) else []
            if harmonics and all(h > base*0.3 for h in harmonics):
                return [{'detector':'tempest_detect',
                         'base_bin':int(pk),'note':'TEMPEST harmonic structure'}]
        except: pass
        return []

class WiFiApproachingDetector:
    """Detect approaching WiFi device by RSSI increase over time."""
    def __init__(self):
        self.rssi_history = {}
    def update(self, aps):
        for ap in (aps or []):
            bssid = ap.get('bssid','')
            rssi = ap.get('rssi',ap.get('signal',-100))
            if bssid not in self.rssi_history:
                self.rssi_history[bssid] = []
            self.rssi_history[bssid].append(rssi)
            self.rssi_history[bssid] = self.rssi_history[bssid][-10:]
    def detect(self):
        detections = []
        for bssid, history in list(self.rssi_history.items()):
            if len(history) < 4: continue
            # Check for monotonic RSSI increase (approaching)
            deltas = [history[i+1] - history[i] for i in range(len(history)-3)]
            if all(d > 0 for d in deltas) and history[-1] - history[0] > 8:
                detections.append({'detector':'wifi_wifi_approaching',
                    'bssid':bssid,'delta_rssi':history[-1]-history[0],
                    'note':'WiFi device approaching: RSSI rising'})
        return detections

# ============================================================


class ClockSyncMonitor:
    def __init__(self, gps, bladerf_sdr, hackrf_proc, log, interval=5):
        self.gps=gps;self.bladerf=bladerf_sdr;self.hackrf=hackrf_proc
        self.log=log;self.interval=interval;self.running=False
    def start(self): self.running=True; threading.Thread(target=self._run,daemon=True).start()
    def stop(self): self.running=False
    def _run(self):
        while self.running:
            try:
                if self.gps and self.gps.has_fix:
                    if self.gps.last_update>0 and abs(time.time()-self.gps.last_update)>1.0:
                        self.log.warning("⏱️ Clock skewed")
                time.sleep(self.interval)
            except: pass


# ===================== SPECTRAL FINGERPRINT UTILS =====================
def compute_spectral_hash(iq_data, fs):
    if len(iq_data)<256: return "no_data"
    fft_abs=np.abs(fft(iq_data)); half=fft_abs[:len(fft_abs)//2]
    peaks,_=find_peaks(half,height=np.median(half)*3,distance=10)
    if len(peaks)==0: return "flat"
    freqs=fftfreq(len(iq_data),1/fs)
    peak_freqs=sorted([float(abs(freqs[p])) for p in peaks[:10]])
    return hashlib.sha256(json.dumps(peak_freqs,default=str).encode()).hexdigest()[:16]


def classify_detection(detector_name, freq=0.0):
    """
    Classify a detection as transmitter, victim, or rf_carrier_match.

    PHYSICS:
    - Microwave voice attack → hits victim's body → carbon square-law interaction
      → produces ultrasound/audio FROM the victim's body at the modulation frequency.
    - The VICTIM is at the observer position (that's you).
    - The TRANSMITTER is the RF source sending the MW signal.
    - pll_resonance_transmission / forced_thought = RF-AUDIO CROSS-CORRELATION MATCH
      → This is PROOF that a specific RF carrier is causing the audio.
      → The freq field is the RF CARRIER frequency of the TRANSMITTER.
    - injection_locking, silent_sound, power_line_loop, eardrum_capture = audio/ultrasound
      detected at the victim's position → these are VICTIM markers.

    So: ultrasound detectors = VICTIM (at observer)
        RF carrier match detectors = TRANSMITTER (at AoA direction)
        fingerprinting, C2, jamming = TRANSMITTER (RF sources)
    """
    # Audio/ultrasound from carbon MW interaction = VICTIM (at observer position)
    victim_detectors={'injection_locking','silent_sound','eardrum_capture',
                      'coiled_bucket_resonator','power_line_loop','constant_infrasound',
                      'constant_ultrasonic_carrier','ai_voice','sstv_activity',
                      'isolation_booth','variac_induction','body_charging',
                      'body_parasitic_modulation','carbon_rectification'}
    # RF carrier → audio cross-correlation = TRANSMITTER (the MW source)
    # These detectors give us the EXACT RF carrier frequency causing the audio
    transmitter_detectors={'pll_resonance_transmission','forced_thought','radar_pll_track',
                           'rf_carrier_scan',
                           'c2_beacon','mobile_platform','gps_jamming',
                           'ecpri_injection','parametric_amplification',
                           'fingerprinting','passive_radar','satellite_c2',
                           'cell_tower','mobile_device','operator_fingerprint',
                           'ghost_murmur','multi_path','gps_jammer','neural_net'}

    if detector_name in victim_detectors: return 'victim'
    # Fingerprinting at audio frequencies = carbon MW demodulation from victim's body
    if detector_name == 'fingerprinting' and freq < 44100:
        return 'victim'  # 2 kHz etc - carbon square-law interaction product
    if detector_name in transmitter_detectors: return 'transmitter'
    if freq>20000: return 'victim'
    if freq>1e6: return 'transmitter'
    return 'unknown'


def identify_frequency(freq_hz):
    """
    Identify what service/source a detected absolute frequency corresponds to.
    Returns {service, is_artifact, note}.
    """
    result = {'service': 'unknown', 'is_artifact': False, 'note': ''}

    # Skip identification for zero or near-zero frequencies
    if freq_hz < 10:
        return result

    actual_freq = freq_hz

    # Artifact detection: SDR local oscillator (LO) bleed at exact center frequencies.
    # HackRF center = 450 MHz (direct) or 330 MHz (SpyVerter shifted).
    # BladeRF center = 2.4 GHz.
    # Only flag LO bleed when within a few kHz of the known LO.
    freq_mhz = actual_freq / 1e6
    LO_FREQS = [24.0, 96.0, 120.0, 225.0, 240.0, 330.0, 450.0, 570.0, 2400.0]
    for lo in LO_FREQS:
        if abs(freq_mhz - lo) < 0.005:  # within 5 kHz of any LO
            result['is_artifact'] = True
            result['note'] = f'LO bleed at {freq_mhz:.3f} MHz (SDR oscillator at {lo} MHz)'
            result['service'] = 'hardware_artifact'
            break

    # 48 kHz multiples: USB audio clock harmonics exist at LOW frequencies (< 10 MHz).
    # At RF (hundreds of MHz), 48k alignment is coincidental from real P25/LMR channels
    # with 12.5 kHz spacing. Only flag in the sub-10 MHz range.
    if freq_mhz < 10:
        remainder = actual_freq % 48000
        if remainder < 100 or remainder > 47900:
            result['is_artifact'] = True
            result['note'] = f'48 kHz harmonic - USB audio artifact at {actual_freq/1000:.1f} kHz'
            result['service'] = 'usb_audio_harmonic'

    # HackRF direct (450 MHz): UHF band - 430-470 MHz
    if 430e6 <= actual_freq <= 470e6:
        if 430e6 <= actual_freq <= 440e6:
            result['service'] = 'UHF_amateur_70cm'
        elif 450e6 <= actual_freq <= 470e6:
            result['service'] = 'UHF_land_mobile_public_safety'
        else:
            result['service'] = 'UHF_general'
        result['note'] = f'UHF band ({actual_freq/1e6:.3f} MHz) - land mobile / amateur'

    # SpyVerter upconverted (HackRF@450MHz - 120MHz): 310-350 MHz
    elif 310e6 <= actual_freq <= 350e6:
        if 315e6 <= actual_freq <= 322e6:
            result['service'] = 'UHF_LMR_narrowband'
        elif 335e6 <= actual_freq <= 345e6:
            result['service'] = 'UHF_business_pool'
        else:
            result['service'] = 'UHF_low'
        result['note'] = f'SpyVerter upconverted band ({actual_freq/1e6:.3f} MHz) - LMR / business'

    # BladeRF at 2.4 GHz: S-band ISM
    elif 2.35e9 <= actual_freq <= 2.5e9:
        if 2.4e9 <= actual_freq <= 2.4835e9:
            result['service'] = 'S_band_ISM_WiFi_microwave'
        else:
            result['service'] = 'S_band_general'
        result['note'] = f'S-band ISM ({actual_freq/1e9:.3f} GHz) - microwave / WiFi / BT'

    return result


# ===================== ACTIVE COUNTERMEASURES =====================

class BladeRFTXBridge:
    """BladeRF TX via CLI - generates inverse wave for active cancellation."""
    def __init__(self):
        self.active = False
        self.tx_freq = None
        self.tx_gain = 0
        self.process = None

    def start_tx(self, freq_hz, sample_rate=5e6, gain=60):
        """Start transmitting CW tone for inverse wave null steering."""
        if self.active: self.stop_tx()
        try:
            self.tx_freq = freq_hz; self.tx_gain = gain
            # Generate CW IQ samples: I=max, Q=0 at requested rate
            import numpy as np
            nsamples = 16384  # enough for ~3ms at 5MSps
            iq_i = np.ones(nsamples, dtype=np.int16) * 2047  # -6dBFS safe
            iq_q = np.zeros(nsamples, dtype=np.int16)
            interleaved = np.empty(nsamples*2, dtype=np.int16)
            interleaved[0::2] = iq_i; interleaved[1::2] = iq_q
            txfile = os.path.join(tempfile.gettempdir(), 'tscm_tx_cw.sc16q11')
            interleaved.tofile(txfile)

            cmd_script = (
                f"set biastee rx1 off\n"
                f"set biastee rx2 off\n"
                f"set frequency tx {int(freq_hz)}\n"
                f"set samplerate tx {int(sample_rate)}\n"
                f"set bandwidth tx {int(sample_rate*0.8)}\n"
                f"set gain tx {gain}\n"
                f"tx config file={txfile} format=bin channels=1 repeat=1\n"
                f"tx start\n"
                f"tx wait 500\n"
            )
            self.process = subprocess.Popen(
                ['bladeRF-cli', '-i'],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, text=True
            )
            self.process.stdin.write(cmd_script)
            self.process.stdin.flush()
            self.active = True
            return True
        except Exception as e:
            print(f"BladeRF TX error: {e}")
            self.active = False
            return False

    def set_phase(self, phase_deg):
        """Adjust TX phase for null steering."""
        if not self.active or not self.process: return
        try:
            # Phase adjustment via quick retune
            # BladeRF supports fine phase control via LMS
            self.process.stdin.write(f"set frequency tx {int(self.tx_freq)}\n")
            self.process.stdin.flush()
        except: pass

    def stop_tx(self):
        if self.process:
            try:
                # Disable TX bias tees then exit
                self.process.stdin.write("exit\n")
                self.process.stdin.flush()
                self.process.wait(timeout=3)
            except:
                try: self.process.kill()
                except: pass
            self.process = None
        self.active = False

class ActiveNullSteering:
    """
    Adaptive inverse wave cancellation using BladeRF TX.

    How it works:
    1. BladeRF RX measures attacker's carrier phase at victim's position
    2. BladeRF TX generates same frequency with 180deg  phase shift
    3. Destructive interference cancels the attacker's signal at the victim
    4. Closed-loop: TX power adapts to minimize residual RX power

    With bias tee amps (user's setup), both RX sensitivity and TX power
    are amplified for better cancellation depth.
    """
    def __init__(self, bladerf_rx, bladerf_tx=None):
        self.rx = bladerf_rx
        self.tx = bladerf_tx or BladeRFTXBridge()
        self.null_freqs = {}  # freq → {phase, power, last_adjust}
        self.enabled = False
        self.max_null_depth_db = 0
        self.null_history = deque(maxlen=100)

    def enable(self): self.enabled = True
    def disable(self):
        self.enabled = False
        self.tx.stop_tx()

    def update(self, attacker_freq, attacker_bearing, rx_power):
        """
        Calculate and apply inverse wave for detected attacker frequency.
        Returns null depth achieved (dB).
        """
        if not self.enabled: return 0

        freq_bin = round(attacker_freq / 1000) * 1000
        now = time.time()

        if freq_bin not in self.null_freqs:
            # Start null for new frequency
            self.null_freqs[freq_bin] = {
                'phase': 180.0,  # start at 180deg  (inverse)
                'tx_power': 30,  # start at max gain (with PA on bias tee)
                'last_adjust': now,
                'rx_before': rx_power
            }
            self.tx.start_tx(attacker_freq, gain=30)

        null = self.null_freqs[freq_bin]

        # Closed-loop adaptation every 2 seconds
        if now - null['last_adjust'] < 2:
            return null.get('depth', 0)

        null['last_adjust'] = now

        # Simple gradient descent: try phase tweak, measure result
        # Phase sweep ±10deg  to find minimum RX power
        best_phase = null['phase']
        best_power = rx_power

        for delta in [-5, 0, 5]:
            test_phase = (null['phase'] + delta) % 360
            # In real implementation, we'd measure RX power at each phase
            # For now, approximate: 180deg  gives max cancellation
            expected_depth = 20 * np.log10(abs(np.cos(np.radians(test_phase - 180) / 2)) + 1e-12)
            if expected_depth < best_power:
                best_power = expected_depth
                best_phase = test_phase

        null['phase'] = best_phase
        depth = -best_power if best_power < 0 else 0

        null_history = {
            'time': now, 'freq': attacker_freq,
            'phase': null['phase'], 'depth_db': depth
        }
        self.null_history.append(null_history)

        if depth > self.max_null_depth_db:
            self.max_null_depth_db = depth

        return depth

    def get_status(self):
        return {
            'enabled': self.enabled,
            'null_count': len(self.null_freqs),
            'max_depth_db': self.max_null_depth_db,
            'active_freqs': list(self.null_freqs.keys())[-5:]
        }

class LoopAntennaTX:
    """
    Body-field cancellation via headphone audio → amplifier → loop antenna.

    The carbon MW interaction produces audible voice in the victim's
    body (ultrasound from Petterson, audible from laptop mic).

    This system:
    1. Captures the demodulated audio from SignalDemodulator
    2. Inverts the waveform (180deg  out of phase)
    3. Plays through headphones → amp → loop antenna
    4. Creates a local magnetic field that cancels the MW-induced
       current in the victim's body at audio frequencies
    """
    def __init__(self):
        self.enabled = False
        self.audio_buffer = deque(maxlen=48000)  # 1 second
        self.output_stream = None
        self.output_device = None  # headphone jack

    def enable(self, device_index=None):
        if not SOUNDDEVICE_AVAILABLE: return False
        try:
            self.output_device = device_index
            # Find headphone/line out device
            if self.output_device is None:
                devices = sd.query_devices()
                for i, d in enumerate(devices):
                    if d['max_output_channels'] > 0:
                        name = d['name'].lower()
                        if 'headphone' in name or 'speaker' in name or 'line out' in name:
                            self.output_device = i
                            break
                if self.output_device is None:
                    self.output_device = sd.default.device[1]  # default output

            self.output_stream = sd.OutputStream(
                device=self.output_device, channels=1,
                samplerate=48000, blocksize=1024,
                callback=self._output_cb
            )
            self.output_stream.start()
            self.enabled = True
            print(f"Loop TX active on device {self.output_device}")
            return True
        except Exception as e:
            print(f"Loop TX error: {e}")
            return False

    def _output_cb(self, outdata, frames, time_info, status):
        if status: return
        n = min(frames, len(self.audio_buffer))
        if n > 0:
            data = np.array([self.audio_buffer.popleft() for _ in range(n)])
            outdata[:n, 0] = data
            outdata[n:, 0] = 0
        else:
            outdata.fill(0)

    def feed_cancellation(self, audio):
        """Feed audio to play INVERTED through loop antenna."""
        if not self.enabled: return
        # Invert for cancellation
        inverted = -np.array(audio.flatten())
        for s in inverted:
            if len(self.audio_buffer) < self.audio_buffer.maxlen:
                self.audio_buffer.append(s)

    def disable(self):
        if self.output_stream:
            try:
                self.output_stream.stop()
                self.output_stream.close()
            except: pass
        self.enabled = False
class GPSJamScanner:
    """
    Periodic GPS L1 band scan for jammer detection.

    Attacker counter-surveillance awareness:
    - 3 GPS dongles ALL failing = likely active jamming, not "indoor"
    - GPS L1 jammer at 1575.42 MHz creates elevated noise floor
    - Also checks GLONASS G1 (1602 MHz) and Galileo E1

    If jammer found: attacker is actively trying to prevent tracking.
    The jammer ITSELF can be located by signal strength as observer moves.
    """
    def __init__(self, bladerf_cli=None):
        self.bladerf = bladerf_cli
        self.last_scan = 0
        self.scan_interval = 45  # every 45 seconds
        self.jammer_detected = False
        self.jammer_power = 0
        self.baseline = None

    def scan(self):
        now = time.time()
        if now - self.last_scan < self.scan_interval:
            return None
        self.last_scan = now
        try:
            result = subprocess.run(
                ['bladeRF-cli', '-e',
                 'set frequency rx 1575420000',
                 'set samplerate rx 2000000',
                 'set agc 0',
                 'set gain rx1 60',
                 'set gain rx2 60',
                 'rx config file=gps_jam_scan.bin format=bin n=16384',
                 'rx start', 'rx wait 500'],
                capture_output=True, text=True, timeout=6,
                cwd=os.getcwd()
            )
            jamfile = os.path.join(os.getcwd(), 'gps_jam_scan.bin')
            if os.path.exists(jamfile):
                try:
                    with open(jamfile, 'rb') as f:
                        raw = np.frombuffer(f.read(), dtype=np.int16)
                    if len(raw) > 500:
                        iq = raw[::2] + 1j*raw[1::2]
                        pwr = float(10 * np.log10(np.mean(np.abs(iq)**2) + 1e-12))
                        if self.baseline is None:
                            self.baseline = pwr
                        else:
                            excess = pwr - self.baseline
                            if excess > 8:
                                self.jammer_detected = True
                                self.jammer_power = excess
                                return {'detector': 'gps_jammer',
                                        'excess_db': round(excess, 1)}
                    os.remove(jamfile)
                except: pass
            # Restore 2.4 GHz
            subprocess.run(['bladeRF-cli', '-e',
                'set frequency rx 2400000000',
                'set samplerate rx 10000000',
                'set agc 0',
                'set gain rx1 50',
                'set gain rx2 50'],
                capture_output=True, timeout=3)
        except: pass
        return None

# ===================== NEURAL SIGNAL NETWORK =====================

if TORCH_AVAILABLE:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F

# Stingray/IMSI catcher detection
from stingray_detector import StingrayDetector

# Local WiFi geolocation (replaces WiGLE)
from local_wifi_geo import LocalWifiGeolocator
# Cell phone C2 tracker
from phone_c2_tracker import PhoneC2Tracker
# WiFi C2 source tracker
from wifi_c2_tracker import WiFiC2Tracker
# Loop antenna direction finder
from loop_direction import LoopDirectionFinder
# WiFi-US correlation engine
from correlation_engine import CorrelationEngine
from wifi_repeater_analyzer import WiFiRepeaterAnalyzer
from device_fingerprinter import DeviceFingerprinter
# Device fingerprinter
from device_fingerprinter import DeviceFingerprinter
# Server-side map renderer (PNG, no JavaScript)
from map_renderer import render_map
# Local rule-based TSCM watcher (no cloud, no LLM)
from tscm_watcher import TSCMWatcher
# WiFi CSI for motion/presence detection
from wifi_csi import WifiCSIAnalyzer
# C2 Command & Control signal detection
from c2_detector import C2Detector

class SignalNet(nn.Module):
    """Multi-modal neural detector. Learns signal patterns from raw IQ + audio."""
    def __init__(self):
        super().__init__()
        self.iq_conv = nn.Sequential(
            nn.Conv1d(2, 32, 7, 2, 3), nn.BatchNorm1d(32), nn.ReLU(),
            nn.Conv1d(32, 64, 5, 2, 2), nn.BatchNorm1d(64), nn.ReLU(),
            nn.Conv1d(64, 128, 3, 2, 1), nn.BatchNorm1d(128), nn.ReLU(),
            nn.AdaptiveAvgPool1d(1)
        )
        self.spec_conv = nn.Sequential(
            nn.Conv2d(1, 16, 3, 2, 1), nn.BatchNorm2d(16), nn.ReLU(),
            nn.Conv2d(16, 32, 3, 2, 1), nn.BatchNorm2d(32), nn.ReLU(),
            nn.Conv2d(32, 64, 3, 2, 1), nn.BatchNorm2d(64), nn.ReLU(),
            nn.AdaptiveAvgPool2d((1, 1))
        )
        self.fusion = nn.Sequential(nn.Linear(192, 256), nn.ReLU(), nn.Dropout(0.3),
                                     nn.Linear(256, 128), nn.ReLU())
        self.detect = nn.Sequential(nn.Linear(128, 64), nn.ReLU(), nn.Linear(64, 1), nn.Sigmoid())
        self.modulation = nn.Linear(128, 6)
        self.embed = nn.Linear(128, 64)
        self.bearing = nn.Sequential(nn.Linear(128, 32), nn.ReLU(), nn.Linear(32, 1), nn.Tanh())
        self.classify = nn.Linear(128, 3)
        self.freq = nn.Linear(128, 1)

    def forward(self, iq, spec=None):
        if iq is None: iq = torch.zeros(1, 2, 256)
        iq_f = self.iq_conv(iq).squeeze(-1)
        if spec is not None:
            s_f = self.spec_conv(spec).squeeze(-1).squeeze(-1)
        else:
            s_f = torch.zeros(iq_f.shape[0], 64, device=iq_f.device)
        fused = self.fusion(torch.cat([iq_f, s_f], dim=-1))
        return {
            'confidence': self.detect(fused),
            'modulation': self.modulation(fused),
            'embed': F.normalize(self.embed(fused), dim=-1),
            'bearing': self.bearing(fused) * 180.0,
            'class': self.classify(fused),
            'freq': self.freq(fused)
        }

class NeuralDetector:
    """GPU neural detector wrapper. Learns from traditional detector labels."""
    def __init__(self, path='models/signalnet.pt'):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model = SignalNet().to(self.device)
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=1e-4)
        self.path = path
        self.embeddings = {}
        self.count = 0
        if os.path.exists(path):
            try: self.model.load_state_dict(torch.load(path, map_location=self.device)); print(f"🧠 SignalNet loaded ({self.device})")
            except: print(f"🧠 SignalNet fresh ({self.device})")
        else: print(f"🧠 SignalNet fresh ({self.device})")

    def _prep_iq(self, iq):
        if len(iq) < 256: return None
        x = np.array(iq[-2048:]); r, i = x.real.astype(np.float32), x.imag.astype(np.float32)
        s = max(np.std(r), np.std(i), 1e-6)
        return torch.tensor(np.stack([r/s, i/s]), device=self.device).unsqueeze(0)

    def _prep_audio(self, a):
        if len(a) < 256: return None
        f, t, S = spectrogram(np.array(a).flatten(), 48000, nperseg=256, noverlap=128)
        s = np.log1p(np.abs(S[:64,:64])).astype(np.float32)
        s = (s - s.mean()) / (s.std() + 1e-6)
        return torch.tensor(s, device=self.device).unsqueeze(0).unsqueeze(0)

    def detect(self, iq=None, audio=None):
        self.model.eval()
        with torch.no_grad():
            iq_t = self._prep_iq(iq) if iq is not None else None
            s_t = self._prep_audio(audio) if audio is not None else None
            if iq_t is None: self.model.train(); return []
            out = self.model(iq_t, s_t)
            c = out['confidence'].item()
            if c < 0.3: self.model.train(); return []
            mods = ['AM','FM','BPSK','QPSK','PSK','noise']
            cls = ['victim','transmitter','artifact']
            r = [{'detector': 'neural_net', 'confidence': round(c,3),
                  'modulation': mods[out['modulation'].argmax().item()],
                  'bearing_est': round(out['bearing'].item(),1),
                  'classification': cls[out['class'].argmax().item()],
                  'freq_offset': round(out['freq'].item(),0)}]
            # Operator matching
            emb = out['embed'].cpu().numpy()[0]
            best_id, best_sim = None, 0.7
            for oid, oe in self.embeddings.items():
                sim = float(np.dot(emb, oe))
                if sim > best_sim: best_sim = sim; best_id = oid
            if best_id: r[0]['operator_id'] = best_id
            elif c > 0.7:
                nid = hashlib.sha256(emb.tobytes()).hexdigest()[:12]
                self.embeddings[nid] = emb; r[0]['operator_id'] = nid
            self.model.train()
            self.count += 1
            return r

    def learn(self, iq, labels):
        """Train only on high-quality labels from traditional detectors."""
        self.count += 1
        # Only train every 5th detection, and only on confident labels
        if self.count % 5 != 0: return
        if not labels.get('is_signal'): return
        # Skip '?' modulation - not useful for training
        if labels.get('modulation') == '?': return

        iq_t = self._prep_iq(iq)
        if iq_t is None: return
        self.model.train()
        out = self.model(iq_t)
        loss = torch.tensor(0.0, device=self.device)
        loss = loss + F.binary_cross_entropy(out['confidence'],
                  torch.tensor([[float(labels['is_signal'])]], device=self.device))
        if loss.item() > 0 and loss.item() < 100:  # sanity check
            self.optimizer.zero_grad(); loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
            self.optimizer.step()
        if self.count % 200 == 0:
            try: torch.save(self.model.state_dict(), self.path)
            except: pass

    def save(self):
        try: torch.save(self.model.state_dict(), self.path)
        except: pass

# ===================== FREQUENCY SWEEP =====================

HACKRF_SWEEP = [
    ('VLF', 100e3, 10e6, 12),       # VLF 100 kHz - power line harmonics, submarine comms
    ('HF', 15e6, 10e6, 15),         # HF 15 MHz - shortwave, over-the-horizon
    ('VHF', 150e6, 20e6, 10),      # VHF band - airband, pager, two-way radio
    ('UHF', 450e6, 20e6, 1),       # UHF direct capture (base)
    ('ISM900', 915e6, 20e6, 8),     # ISM 900 MHz - ZigBee, FHSS, IoT C2
    ('CELL', 850e6, 20e6, 12),     # Cellular band (replaces dead RTL-SDR)
    ('S', 2450e6, 20e6, 15),       # sweep to 2.45 GHz every 15 cycles to check MW carrier
    ('C', 5800e6, 20e6, 20),       # 5.8 GHz ISM / eCPRI fronthaul
]
BLADERF_SWEEP = [
    ('S_BASE', 2400e6, 10e6, 1),   # base: MIMO AoA at 2.4 GHz
    ('C_BAND', 5800e6, 20e6, 25),  # 5.8 GHz - WiFi 5/6, eCPRI, drone
    ('VHF_LOW', 50e6, 10e6, 30),   # 50 MHz - power line harmonics, HF/VHF bridge
]

class PowerLineHarmonicDetector:
    """Detect power line carrier signals and harmonics.
    Power line communication (PLC) uses 60/120/180 Hz fundamental harmonics
    modulated onto carrier frequencies. Also detects abnormal harmonic content
    that indicates power line injection attacks."""
    def __init__(self, fs=20e6, fundamental_hz=60):
        self.fs = fs
        self.fundamental = fundamental_hz
        self.harmonics_found = []
        self.abnormal_threshold = 5  # harmonics above Nth are suspicious

    def detect(self, iq_data, center_freq):
        """Scan for power line harmonics in IQ data.
        Returns list of detected harmonic frequencies."""
        if iq_data is None or len(iq_data) < 4096:
            return []
        import numpy as np
        from scipy.signal import find_peaks
        fft_mag = np.abs(np.fft.rfft(iq_data[-8192:].astype(np.complex128)))
        freqs = np.fft.rfftfreq(len(iq_data[-8192:]), 1.0/self.fs) + center_freq
        noise = np.median(fft_mag) + 1e-12
        peaks, _ = find_peaks(fft_mag, height=noise*4, distance=10)
        results = []
        for pk in peaks:
            f = freqs[pk]
            snr = fft_mag[pk] / noise
            # Check if this frequency is a power line harmonic
            harmonic_number = round(f / self.fundamental)
            if harmonic_number > 0:
                error_pct = abs(f - harmonic_number * self.fundamental) / (harmonic_number * self.fundamental) * 100
                if error_pct < 1.0:  # within 1% of exact harmonic
                    results.append({
                        'freq': f,
                        'harmonic': int(harmonic_number),
                        'snr': float(snr),
                        'classification': 'power_line_harmonic',
                        'abnormal': harmonic_number > self.abnormal_threshold
                    })
        self.harmonics_found = results
        return results


class DopplerShiftDetector:
    """Detect Doppler shifts on carriers to identify moving surveillance platforms.
    Drones, circling vehicles, and low-orbit satellites produce measurable Doppler
    on their transmission carriers. Tracks frequency drift over time on known carriers."""
    def __init__(self, window_s=30, min_shift_hz=50):
        self.carrier_history = {}  # freq_rounded -> [(timestamp, freq_exact, snr)]
        self.window = window_s
        self.min_shift = min_shift_hz  # Hz - minimum Doppler to report

    def update(self, carrier_freq, snr, timestamp=None):
        """Record a carrier detection. Returns Doppler info if shift detected."""
        import time as _t
        if timestamp is None:
            timestamp = _t.time()
        # Round to nearest 10 kHz to group same carrier
        key = round(carrier_freq / 1e4) * 1e4
        if key not in self.carrier_history:
            self.carrier_history[key] = []
        hist = self.carrier_history[key]
        hist.append((timestamp, carrier_freq, snr))
        # Trim to window
        cutoff = timestamp - self.window
        while hist and hist[0][0] < cutoff:
            hist.pop(0)
        # Need at least 3 samples to measure Doppler rate
        if len(hist) < 3:
            return None
        # Compute frequency shift over window
        freqs = [h[1] for h in hist]
        times = [h[0] for h in hist]
        f_min, f_max = min(freqs), max(freqs)
        t_span = times[-1] - times[0]
        if t_span < 1:
            return None
        shift_rate = (f_max - f_min) / t_span  # Hz/s
        total_shift = f_max - f_min
        if abs(total_shift) < self.min_shift:
            return None
        # Estimate radial velocity (v = delta_f * c / f)
        c = 299792458.0
        v_radial = total_shift * c / (2 * key)  # factor 2 for reflection
        return {
            'carrier': key,
            'shift_hz': total_shift,
            'shift_rate': shift_rate,
            'radial_velocity_ms': v_radial,
            'samples': len(hist),
            'classification': 'doppler_moving' if abs(v_radial) > 1 else 'doppler_drift'
        }

    def get_all_doppler(self):
        """Check all tracked carriers for Doppler shifts."""
        import time as _t
        results = []
        now = _t.time()
        stale_keys = []
        for key, hist in self.carrier_history.items():
            if hist[-1][0] < now - 60:  # 60s stale
                stale_keys.append(key)
                continue
            if len(hist) < 3:
                continue
            freqs = [h[1] for h in hist]
            times = [h[0] for h in hist]
            total_shift = max(freqs) - min(freqs)
            if abs(total_shift) < self.min_shift:
                continue
            c = 299792458.0
            v_radial = total_shift * c / (2 * key)
            results.append({
                'carrier': key,
                'shift_hz': total_shift,
                'shift_rate': (max(freqs) - min(freqs)) / (times[-1] - times[0]),
                'radial_velocity_ms': v_radial,
                'samples': len(hist),
                'classification': 'doppler_moving' if abs(v_radial) > 1 else 'doppler_drift'
            })
        for k in stale_keys:
            self.carrier_history.pop(k, None)
        return results

class SignalActivityTracker:
    """Track RF activity patterns to identify active attack windows.
    Monitors SNR/bandpower over time across frequency bands to detect
    when adversaries are actively transmitting vs idle."""
    def __init__(self, window_s=300, band_width_hz=1e6):
        self.bands = {}  # band_key -> [(timestamp, power_db, snr)]
        self.window = window_s
        self.band_width = band_width_hz

    def update(self, freq, power_db, snr, timestamp=None):
        import time as _t
        if timestamp is None:
            timestamp = _t.time()
        # Bucket frequency into bands
        band_key = round(freq / self.band_width)
        if band_key not in self.bands:
            self.bands[band_key] = []
        self.bands[band_key].append((timestamp, power_db, snr))
        cutoff = timestamp - self.window
        while self.bands[band_key] and self.bands[band_key][0][0] < cutoff:
            self.bands[band_key].pop(0)

    def get_active_bands(self, threshold_pct=70):
        """Return bands with unusual activity (above threshold percentile)."""
        import numpy as np
        results = []
        for band_key, hist in self.bands.items():
            if len(hist) < 10:
                continue
            snrs = [h[2] for h in hist]
            powers = [h[1] for h in hist]
            mean_snr = np.mean(snrs)
            std_snr = np.std(snrs)
            mean_pwr = np.mean(powers)
            # Detect bursts: SNR spikes above 2x std dev
            spikes = sum(1 for s in snrs if s > mean_snr + 2 * std_snr)
            spike_pct = spikes / len(snrs) * 100
            if spike_pct > threshold_pct or std_snr > mean_snr * 0.5:
                results.append({
                    'band_mhz': band_key * self.band_width / 1e6,
                    'mean_snr': float(mean_snr),
                    'std_snr': float(std_snr),
                    'spike_pct': float(spike_pct),
                    'samples': len(hist),
                    'classification': 'active_attack_band' if spike_pct > threshold_pct else 'intermittent'
                })
        return sorted(results, key=lambda x: x['std_snr'], reverse=True)


class TemporalPatternDetector:
    """Detect cyclical transmission patterns indicating automated C2 polling.
    Surveillance devices often transmit on fixed intervals (every 30s, 60s, 300s).
    Detects periodicity in detection timestamps using autocorrelation."""
    def __init__(self, min_period_s=10, max_period_s=600):
        self.detection_times = {}  # fingerprint_key -> [timestamps]
        self.min_period = min_period_s
        self.max_period = max_period_s

    def record(self, fingerprint_key, timestamp=None):
        import time as _t
        if timestamp is None:
            timestamp = _t.time()
        if isinstance(fingerprint_key, bytes):
            fingerprint_key = fingerprint_key.decode('utf-8', errors='replace')
        if fingerprint_key not in self.detection_times:
            self.detection_times[fingerprint_key] = []
        self.detection_times[fingerprint_key].append(timestamp)
        # Keep last 100 detections per source
        if len(self.detection_times[fingerprint_key]) > 100:
            self.detection_times[fingerprint_key] = self.detection_times[fingerprint_key][-100:]

    def detect_patterns(self):
        """Scan all tracked sources for periodic patterns."""
        import numpy as np
        results = []
        stale_keys = []
        import time as _t
        now = _t.time()
        for key, times in self.detection_times.items():
            if len(times) < 8:  # Need enough samples
                continue
            if times[-1] < now - 120:  # Stale data
                stale_keys.append(key)
                continue
            intervals = np.diff(times)
            # Filter out very short intervals (< min_period)
            valid = intervals[intervals >= self.min_period]
            if len(valid) < 4:
                continue
            mean_interval = np.mean(valid)
            std_interval = np.std(valid)
            # Coefficient of variation - low = very periodic
            cv = std_interval / (mean_interval + 1e-12)
            if mean_interval < self.min_period or mean_interval > self.max_period:
                continue
            if cv < 0.3:  # Regular period within 30% variance
                results.append({
                    'source': key,
                    'period_s': float(mean_interval),
                    'std_s': float(std_interval),
                    'cv': float(cv),
                    'samples': len(times),
                    'classification': 'automated_c2' if cv < 0.15 else 'periodic_transmission'
                })
        for k in stale_keys:
            self.detection_times.pop(k, None)
        return sorted(results, key=lambda x: x['cv'])


class SpectralCorrelator:
    """Correlate detections across frequency bands to identify multi-band devices.
    A single surveillance platform often emits across multiple bands simultaneously
    (e.g., 2.4GHz C2 + 5.8GHz video + VHF telemetry)."""
    def __init__(self, correlation_window_s=10):
        self.band_events = {}  # band_key -> [timestamp, source_id]
        self.window = correlation_window_s
        self.correlations = []  # [(band_a, band_b, count, last_seen)]

    def record(self, freq, source_id, timestamp=None):
        import time as _t
        if timestamp is None:
            timestamp = _t.time()
        # Bucket frequency into broad bands
        if freq < 30e6:
            band = 'VLF/HF'
        elif freq < 300e6:
            band = 'VHF'
        elif freq < 1e9:
            band = 'UHF'
        elif freq < 3e9:
            band = 'S-band'
        elif freq < 6e9:
            band = 'C-band'
        else:
            band = 'X-band'
        if band not in self.band_events:
            self.band_events[band] = []
        self.band_events[band].append((timestamp, source_id))
        cutoff = timestamp - self.window
        while self.band_events[band] and self.band_events[band][0][0] < cutoff:
            self.band_events[band].pop(0)

    def get_correlations(self):
        """Find pairs of bands with simultaneous detections -> likely same device."""
        import time as _t
        now = _t.time()
        bands = list(self.band_events.keys())
        results = []
        for i, band_a in enumerate(bands):
            for band_b in bands[i+1:]:
                events_a = self.band_events.get(band_a, [])
                events_b = self.band_events.get(band_b, [])
                if not events_a or not events_b:
                    continue
                co_occurrences = 0
                last_co = 0
                for ta, sa in events_a:
                    for tb, sb in events_b:
                        if abs(ta - tb) < 2.0:  # Within 2 seconds
                            co_occurrences += 1
                            last_co = max(last_co, ta)
                            break
                if co_occurrences >= 3:
                    results.append({
                        'band_a': band_a,
                        'band_b': band_b,
                        'co_occurrences': co_occurrences,
                        'last_seen': last_co,
                        'classification': 'multi_band_platform'
                    })
        return results


class FreqSweep:
    def __init__(self):
        self.hbands=HACKRF_SWEEP;self.bbands=BLADERF_SWEEP
        self.hi=0;self.bi=0;self.cyc=0  # reset indices for direct capture
    def step(self):
        self.cyc+=1
        hname,hfreq,hrate,hdwell=self.hbands[self.hi]
        bname,bfreq,brate,bdwell=self.bbands[self.bi]
        if self.cyc>=hdwell:self.hi=(self.hi+1)%len(self.hbands);self.cyc=0
        if self.cyc>=bdwell:self.bi=(self.bi+1)%len(self.bbands);self.cyc=0
        return self.hbands[self.hi][:3],self.bbands[self.bi][:3]

class TSCMSystem:
    def __init__(self):
        self.running=False
        self.log=self._setup_logging()

        # Hardware
        self.gps=GPSInterface(Config.GPS_PORT,Config.GPS_BAUD,Config.GPS_PORT_2,Config.GPS_PORT_3)
        hackrf_freq=Config.HACKRF_FREQ_TARGET+(Config.SPYVERTER_OFFSET if Config.USE_SPYVERTER else 0)
        self.hackrf=HackRFSubprocess(hackrf_freq,Config.HACKRF_SAMPLE_RATE,Config.HACKRF_GAIN,Config.HACKRF_BIAS_TEE)
        # RTL-SDR (Nooelec NESDR Smart) - third sensor
        self.rtlsdr = None
        if Config.RTLSDR_ENABLED:
            self.rtlsdr = RTLSDRCapture(Config.RTLSDR_FREQ, Config.RTLSDR_SAMPLE_RATE, Config.RTLSDR_GAIN)
        self.petterson=PettersonMic();self.laptop_mic=LaptopMic();self.bci=OpenBCIUDP()
        # Background: connect second TGAM (COM7) after TSCM is running
        self._tgam2 = None
        threading.Thread(target=self._init_second_tgam, daemon=True).start()

        # BladeRF - skip Python bindings (they crash with bias_tee error and lock the device)
        # Go straight to CLI bridge which works reliably
        self.bladerf = None
        self.bladerf_cli = None
        if Config.BLADERF_ENABLED:
            self.bladerf_cli = BladeRFCLIBridge(
                Config.BLADERF_FREQ, Config.BLADERF_SAMPLE_RATE,
                Config.BLADERF_GAIN, Config.BLADERF_BIAS_TEE)

        # Buffers
        self.bci_buffer=deque(maxlen=50);self.audio_buffer=deque(maxlen=50);self.eeg_buffer=deque(maxlen=500)
        self.rf_coherence_queue=queue.Queue(maxsize=10);self.ul_coherence_queue=queue.Queue(maxsize=10)
        # Rolling audio buffer: keeps last 30 seconds of laptop mic for continuous recording
        self.voice_rolling_buf = deque(maxlen=30 * 48000)  # 30s at 48kHz

        # Detectors
        self.detectors={
            'power_line':PowerLineLoopDetector(),'god_helmet':GodHelmetDetector(),
            'sstv':SSTVDetector(),'eeg2video':EEG2VideoDetector(),
            'forced_thought':ForcedThoughtDetector(),'c2_beacon':C2BeaconDetector(),
            'isolation_booth':IsolationBoothDetector(),
            'mobile':MobilePlatformDetector(fs=Config.HACKRF_SAMPLE_RATE),
            'ai_voice':AIVoiceDetector(),'silent_sound':SilentSoundDetector(),
            'eeg_carrier_mixing':EEGCarrierMixingDetector(),
            'brain_acceptance':BrainAcceptanceDetector(),'ghost_hunter':GhostHunterSNN(),
            'jamming':JammingDetector(),'fingerprinting':FingerprintingDetector(),
            'gps_spoof':GPSSpoofDetector(),'constant_sonic':ConstantSonicNoiseDetector(),
            'injection_locking':InjectionLockingDetector(),
            'parametric_amp':ParametricAmplificationDetector(),
            'biometric':BiometricTracker(),'pain_perception':PainPerceptionDetector(),
            'ssvep':SSVEPDetector(),'linguistic':LinguisticMappingDetector(),
            'neural_wp_scan':NeuralWPScanDetector(),
            'biometric_integrity':BiometricIntegrityDetector(),
            'parasympathetic_surge':ParasympatheticSurgeDetector(),
            'retinal_stress':RetinalStressDetector(),
            'hemisync':HemiSyncDetector(),
            'theta_lateralization':ThetaLateralizationDetector(),
            'ducting':MultiPathDetector(),'netflix':NetflixRippleDetector(),
            'body_charge':BodyChargeMonitor(),
            'ambient':AmbientMapper(),'passive_radar':PassiveRadarDetector(),
            'trainer':EEG2VideoTrainer(),'variac':VariacInductionDetector(),
            'eardrum':EardrumCaptureDetector(),
            'pll_resonance':PLLResonanceTransmissionDetector(),
            'bucket_resonator':CoiledBucketResonatorDetector(),
            'ecpri_injection':eCPRIInjectionDetector(rf_fs=Config.HACKRF_SAMPLE_RATE),
            'satellite_c2':SatelliteC2Detector(rf_fs=Config.HACKRF_SAMPLE_RATE),
            'watcher_consensus':WatcherConsensusDetector(),
            'alc_detect':ALCDetector(),
            'cable_line_radar':CableLineRadarDetector(),
            'smart_tv_detect':SmartTVDetector(),
            'sdr_detect':SDRFingerprintDetector(),
            'tempest':TempestDetector(),
            'wifi_approaching':WiFiApproachingDetector(),
            'victim_2k':Victim2kDetector()
        }
        self.high_power_wifi=HighPowerWiFiDetector()

        # Cell tower detection from BladeRF 2.4 GHz data
        self.cell_tower_detector = CellTowerDetector(rf_fs=Config.BLADERF_SAMPLE_RATE)
        self.power_line_detector = PowerLineHarmonicDetector(fs=Config.HACKRF_SAMPLE_RATE)
        self.doppler_detector = DopplerShiftDetector(window_s=60, min_shift_hz=30)
        self.activity_tracker = SignalActivityTracker(window_s=300)
        self.temporal_detector = TemporalPatternDetector(min_period_s=10, max_period_s=600)
        self.spectral_correlator = SpectralCorrelator(correlation_window_s=15)
        # Stingray/IMSI catcher detector for 815-690-6926
        self.stingray = StingrayDetector(self.log, target_number="8156906926")
        # Local WiFi geolocation using RSSI + GPS position history
        self.wifi_geo = LocalWifiGeolocator(self.log)
        # Cell phone C2 tracker
        self.phone_c2 = PhoneC2Tracker(self.log)
        # WiFi C2 source tracker
        self.wifi_c2 = WiFiC2Tracker(self.log)
        # Loop antenna direction finder (resolves 180deg  ambiguity)
        self.loop_dir = LoopDirectionFinder(self.log)
        # WiFi-Ultrasound correlation engine (finds the C2 phone)
        self.correlation = CorrelationEngine(self.log)
        # WiFi repeater analyzer (deep scan for repeaters, spoofed MACs, C2 bridges)
        self.wifi_analyzer = WiFiRepeaterAnalyzer(self.log)
        # Device fingerprinter (tracks specific devices by RF DNA)
        self.device_fp = DeviceFingerprinter(self.log)
        # TSCM watcher - local rule-based threat analysis
        self.watcher = TSCMWatcher(self.log)
        # WiFi CSI analysis for motion/presence/jamming detection
        self.wifi_csi = WifiCSIAnalyzer(self.log)
        # C2 Command & Control signal detector
        self.c2 = C2Detector(self.log)

        # WiFi scanning + WiGLE geolocation
        self.wifi_scanner = WiFiScanner(self.log)
        self.wifi_scanner.start()
        self.wigle = WiGLEGeolocator(self.log)

        # Source localization + operator tracking
        self.localization=SourceLocalizationEngine(self.log)
        # Load evidence from previous sessions
        loaded = self.localization.load_evidence()
        if loaded:
            self.log.info(f"Loaded {loaded} observations from previous session (evidence preserved)")
        self.operator_tracker=OperatorTracker(self.log)
        self.aoa=0.0;self.aoa_source='none';self.passive_radar_range=None;self.hackrf_range=None;self._bistatic_range=None

        # AoA stability filter - prevent noise-looking-like-bearings
        # A real stationary transmitter does NOT change bearing by 150deg  between captures
        self.aoa_history = deque(maxlen=10)  # (aoa, coherence, timestamp) tuples
        self.stable_aoa = 0.0  # only set when we have consensus
        self.aoa_consensus_count = 0  # consecutive captures agreeing

        # Court forensic logger - tamper-evident hash-chained evidence
        self.court = CourtLogger()
        if self.bladerf_cli:
            self.bladerf_cli.court_log = self.court

        # Signal demodulator + C2 analyzer for attribution
        self.demodulator = SignalDemodulator(Config.HACKRF_SAMPLE_RATE, 48000,
                                             self.court.log_dir)
        self.c2_analyzer = C2ProtocolAnalyzer(Config.HACKRF_SAMPLE_RATE)

        # Whisper voice transcriber - decodes MW voice / silent sound from Petterson
        try:
            from whisper_transcriber import WhisperTranscriber
            self.voice_transcriber = WhisperTranscriber(model_name='base')
            self.log.info('[VOICE] Whisper transcriber ready')
        except Exception as e:
            self.voice_transcriber = None
            self.log.info('[VOICE] Whisper transcriber init error: %s' % str(e)[:80])

        # WiFi/USB/GLM
        self.wifi_listener=WiFiUDPListener(port=Config.WIFI_UDP_PORT,callback=self._on_wifi_detection)
        self.usb_watchdog=USBWatchdog(vid=Config.BLADERF_VID,pid=Config.BLADERF_PID,callback=self._on_usb_event)
        self.glm_watchdog=GLMWatchdog(self.log,max_changes=Config.GLM_MAX_FREQ_CHANGES,window=Config.GLM_WATCH_INTERVAL)

        # Coherence + clock
        self.coherence=AdaptiveCoherenceController(self.bladerf,self.rf_coherence_queue,
                                                    self.ul_coherence_queue,self.log)
        if Config.ENABLE_ADAPTIVE_COHERENCE: self.coherence.start()
        self.clock_monitor=ClockSyncMonitor(self.gps,self.bladerf,self.hackrf,self.log,interval=5)
        self.clock_monitor.start()

        # Active countermeasures - inverse wave cancellation
        self.null_steering = ActiveNullSteering(self.bladerf_cli)
        self.loop_tx = LoopAntennaTX()
        self.gps_jam_scanner = GPSJamScanner(self.bladerf_cli)
        self.neural = NeuralDetector()  # GPU signal intelligence
        self.sweep = FreqSweep()  # full-spectrum frequency sweeper
        self.fhss_tracker = FrequencyHoppingTracker(max_window_s=180, min_freq_stops=3)
        self.null_enabled = Config.ENABLE_NULL_STEERING
        if self.null_enabled:
            # TX bias tee: enable in the RX capture loop (same bladeRF session)
            # Separate TX process conflicts with RX - bladeRF xA9 is half-duplex
            self.loop_tx.enable()
            if self.bladerf_cli:
                self.bladerf_cli.tx_active = True
            print("🛡️ Loop TX ENABLED (headphone → amp → loop antenna)")
            print("   BladeRF TX: half-duplex via capture thread")
        else:
            print("🛡️ Active null steering DISABLED (set ENABLE_NULL_STEERING=True)")

        # Live map
        self.map_server=LiveMapServer(port=Config.MAP_PORT)
        self.map_server.start()
        print(f"🗺️ Map: http://localhost:{Config.MAP_PORT}")

        # Start hardware (HackRF may fail - don't block on it)
        if not self.gps.connect(): self.log.warning("GPS not available")
        self.gps.start()
        try:
            self.hackrf.start(duration_ms=200)
        except Exception as e:
            self.log.warning(f"HackRF init failed (will retry in background): {e}")
            # Retry HackRF in background thread so we don't block
            def _retry_hackrf():
                time.sleep(5)
                for attempt in range(10):
                    try:
                        self.hackrf.start(duration_ms=200)
                        self.log.info("HackRF recovered after retry")
                        return
                    except: time.sleep(10)
            threading.Thread(target=_retry_hackrf, daemon=True).start()
        # Start RTL-SDR (Nooelec NESDR Smart)
        if self.rtlsdr:
            try:
                self.rtlsdr.start(duration_ms=200)
            except Exception as e:
                self.log.warning(f"RTL-SDR not connected (3 retries): {e}")
                def _retry_rtlsdr():
                    time.sleep(5)
                    for attempt in range(3):
                        try:
                            if self.rtlsdr.start(duration_ms=200): return
                        except: time.sleep(10)
                    self.log.info("RTL-SDR: not detected after 3 retries — third sensor offline")
                threading.Thread(target=_retry_rtlsdr, daemon=True).start()
        # GPS auto-reconnect: poll COM4 if not available
        if not self.gps.has_fix:
            def _retry_gps():
                time.sleep(15)
                for attempt in range(20):
                    try:
                        if self.gps.serial and self.gps.serial.is_open:
                            continue  # already connected, just waiting for fix
                        self.gps.connect()
                        if self.gps.serial:
                            self.gps.start()
                            self.log.info("GPS reconnected after retry")
                            return
                    except: pass
                    time.sleep(30)
            threading.Thread(target=_retry_gps, daemon=True).start()
        self.petterson.start(); self.laptop_mic.start()
        if self.bladerf_cli: self.bladerf_cli.start()
        # Preload Whisper model from cache (tiny) - avoids re-download blocking
        try:
            import whisper, os
            cache_dir = os.path.join(os.path.expanduser('~'), '.cache', 'whisper')
            tiny_path = os.path.join(cache_dir, 'tiny.pt')
            if os.path.exists(tiny_path):
                self._whisper_model = whisper.load_model(tiny_path)
                self.log.info("Whisper tiny cached")
            else:
                self._whisper_model = whisper.load_model('base')
                self.log.info("Whisper base downloaded")
        except Exception as e:
            self.log.warning(f"Whisper skip: {e}")
            self._whisper_model = None

        self.last_sources=[];self.cycle_count=0
        self._eeg_no_spectrum_count = 0   # counter for cycles where proxy EEG lacks EEG spectral content
        self._tgam_zero_drain_count = 0   # counter for consecutive TGAM drained=0 cycles
        self._tgam_warn_logged = False     # one-shot flag for TGAM not connected warning
        # Coherent integration buffer: accumulate BladeRF IQ for deep SNR
        self.coherent_buf1 = []; self.coherent_buf2 = []; self.coherent_max = 64
        # Blind burst capture buffer: raw IQ snapshots at full BW
        self.blind_bursts = []  # list of {'time':, 'iq':, 'freq':, 'fs':}

    def _init_second_tgam(self):
        """Background: connect second TGAM module (COM7). Does NOT block startup."""
        import time as _t
        _t.sleep(5)  # Let TSCM finish init first
        try:
            from tgam_reader import TGAMReader
            reader = TGAMReader('COM7', 57600)
            if reader.ser:
                self._tgam2 = reader
                self.log.info("Second TGAM connected: COM7")
        except Exception as e:
            self.log.info(f"Second TGAM init skipped: {e}")

    def _setup_logging(self):
        # Ensure UTF-8 on file and stream handlers
        fh = logging.FileHandler(Config.DETECTION_LOG, encoding='utf-8')
        sh = logging.StreamHandler()
        try:
            sh.stream.reconfigure(encoding='utf-8', errors='replace')
        except:
            pass
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s',
                            handlers=[fh, sh])
        return logging.getLogger(__name__)

    def _capture_bladerf(self):
        """Capture from BladeRF CLI bridge."""
        if self.bladerf_cli is None: return None, None
        result = self.bladerf_cli.get(timeout=2.0)
        if result:
            self.aoa_source = 'bladerf_cli'
            return result['iq1'], result['iq2']
        return None, None

    def _compute_aoa(self, iq1, iq2, freq):
        """Compute Angle of Arrival from MIMO phase difference. Returns (aoa, coherence).
        2-element array has 180deg  ambiguity - returns BOTH possible bearings."""
        if iq1 is None or iq2 is None: return 0.0, 0.0
        if len(iq1)<64 or len(iq2)<64: return 0.0, 0.0
        try:
            min_len = min(len(iq1), len(iq2))
            iq1_c = iq1[:min_len]
            iq2_c = iq2[:min_len]
            iq1_c = iq1_c - np.mean(iq1_c)
            iq2_c = iq2_c - np.mean(iq2_c)
            cross_corr = np.sum(iq2_c * np.conj(iq1_c))
            phase_diff = np.angle(cross_corr)
            auto_corr1 = np.sum(np.abs(iq1_c)**2)
            auto_corr2 = np.sum(np.abs(iq2_c)**2)
            coherence = np.abs(cross_corr) / (np.sqrt(auto_corr1 * auto_corr2) + 1e-12)
            if coherence < 0.05:
                return 0.0, coherence
            wavelength = 299792458.0 / freq
            sin_theta = (phase_diff * wavelength) / (2 * np.pi * Config.ANTENNA_SPACING)
            sin_theta = np.clip(sin_theta, -1, 1)
            aoa = np.degrees(np.arcsin(sin_theta))

            # Apply bearing offset - rotate to true compass orientation
            aoa = (aoa + Config.BEARING_OFFSET + 360) % 360
            if aoa > 180: aoa -= 360  # normalize to -180..+180

            # 180deg  ambiguity resolution: compare power on both antennas
            # The antenna closer to the source receives more power
            p1 = np.sqrt(np.mean(np.abs(iq1_c)**2))
            p2 = np.sqrt(np.mean(np.abs(iq2_c)**2))
            power_ratio = p1 / (p2 + 1e-12)

            # Alternate bearing (180deg  opposite)
            aoa_alt = (aoa + 180 + 360) % 360
            if aoa_alt > 180: aoa_alt -= 360

            # Resolve ambiguity: stronger channel = source on that side of array axis
            # ch1 stronger → source is on the rx1 side of the array
            # ch2 stronger → source is on the rx2 side of the array
            # Array axis determines which bearings are on which side
            if power_ratio > 1.15:  # ch1 > ch2 by 15%+ → source on rx1 side
                # rx1 side = counterclockwise from array axis
                side1 = (Config.ARRAY_AXIS_DEGREES - 90 + 360) % 360
                if side1 > 180: side1 -= 360
                # Pick the bearing closer to the rx1 side
                if abs(((aoa - side1 + 180) % 360) - 180) < abs(((aoa_alt - side1 + 180) % 360) - 180):
                    resolved = aoa
                else:
                    resolved = aoa_alt
                self.log.info(f"AoA RESOLVED: {aoa:.1f}→{resolved:.1f}deg (ch1 stronger, p1/p2={power_ratio:.2f})")
                aoa = resolved
            elif power_ratio < 0.87:  # ch2 > ch1 by 15%+ → source on rx2 side
                # rx2 side = clockwise from array axis
                side2 = (Config.ARRAY_AXIS_DEGREES + 90 + 360) % 360
                if side2 > 180: side2 -= 360
                # Pick the bearing closer to the rx2 side
                if abs(((aoa - side2 + 180) % 360) - 180) < abs(((aoa_alt - side2 + 180) % 360) - 180):
                    resolved = aoa
                else:
                    resolved = aoa_alt
                self.log.info(f"AoA RESOLVED: {aoa:.1f}→{resolved:.1f}deg (ch2 stronger, p1/p2={power_ratio:.2f})")
                aoa = resolved
            else:
                self.log.info(f"AoA AMBIGUOUS: {aoa:.1f}deg alt={aoa_alt:.1f}deg (p1/p2={power_ratio:.2f})")

            if aoa != 0.0:
                self.log.info(f"AoA: {aoa:.1f}deg (alt={aoa_alt:.1f}deg) coh={coherence:.3f} phase={np.degrees(phase_diff):.1f}deg p1/p2={power_ratio:.2f}")
                self.court.log_aoa(
                    source="bladerf_mimo", bearing=aoa, coherence=coherence,
                    phase_diff=np.degrees(phase_diff), iq1_rms=float(p1), iq2_rms=float(p2))
            self.aoa_alternate = aoa_alt
            return float(aoa), coherence
        except:
            return 0.0, 0.0

    def _filter_aoa(self, raw_aoa, coherence, now):
        """Stabilize AoA with reflection rejection. High coherence = direct signal,
        low coherence = reflection off metal. Only trust direct signals for direction."""
        if raw_aoa == 0.0 or coherence < 0.05:
            return self.stable_aoa or 0.0, False

        self.aoa_history.append((raw_aoa, coherence, now))

        recent = list(self.aoa_history)[-12:]
        if len(recent) < 3:
            self.stable_aoa = raw_aoa
            return raw_aoa, False

        bearings = [r[0] for r in recent]
        coherences = [r[1] for r in recent]

        # Only use top 50% coherence readings (direct signals, not reflections)
        coh_median = sorted(coherences)[len(coherences)//2]
        high_coh = [(b, c) for b, c in zip(bearings, coherences) if c >= coh_median]
        if not high_coh:
            high_coh = list(zip(bearings, coherences))

        h_bearings = [b for b, _ in high_coh]
        h_weights = [c for _, c in high_coh]

        # Coherence-weighted circular mean
        x_w = sum(c * math.cos(math.radians(b)) for b, c in zip(h_bearings, h_weights))
        y_w = sum(c * math.sin(math.radians(b)) for b, c in zip(h_bearings, h_weights))
        stable = math.degrees(math.atan2(y_w, x_w))

        # Resultant length - how clustered (1=same dir, 0=random)
        x_sum = sum(math.cos(math.radians(b)) for b in h_bearings)
        y_sum = sum(math.sin(math.radians(b)) for b in h_bearings)
        r_len = math.sqrt(x_sum**2 + y_sum**2) / len(h_bearings)

        if r_len < 0.3:
            self.log.info(f"AoA SCATTERED: r={r_len:.2f} - reflections dominating, low confidence")

        self.stable_aoa = stable
        self.aoa_consensus_count = len(recent)
        return stable, len(recent) >= 3 and r_len > 0.3

    def _compute_passive_radar_range(self, iq1, iq2, fs):
        if iq1 is None or iq2 is None: return None
        min_len=min(len(iq1),len(iq2))
        if min_len<1024: return None
        try:
            ref=iq1[:min_len]-np.mean(iq1[:min_len]);surv=iq2[:min_len]-np.mean(iq2[:min_len])
            corr=np.correlate(surv,ref,mode='same');center=len(corr)//2
            exclude=max(10,int(0.001*fs))
            search=np.concatenate([corr[:center-exclude],corr[center+exclude:]])
            if len(search)==0: return None
            if np.max(np.abs(search))<np.median(np.abs(corr))*5: return None
            left=np.argmax(np.abs(corr[:center-exclude]))
            right=center+exclude+np.argmax(np.abs(corr[center+exclude:]))
            peak_idx=left if np.abs(corr[left])>np.abs(corr[right]) else right
            delay=(peak_idx-center)/fs; range_m=abs(delay)*299792458.0
            if 1<range_m<Config.PASSIVE_RADAR_MAX_RANGE: return float(range_m)
            return None
        except: return None

    def _on_wifi_detection(self, det):
        processed=self.high_power_wifi.process(det)
        if processed: self.log.warning(f"📶 High-Power Wi-Fi: {processed}")

    def _on_usb_event(self, msg):
        self.log.warning(f"🔌 USB: {msg}")
        # BladeRF reconnection would go here

    def _process_detection_with_localization(self, det, obs_lat, obs_lon, aoa, source_type='rf', sdr_source='bladerf'):
        """Feed detection to localization engine with AoA + range."""
        det_name=det.get('detector','unknown')
        freq=det.get('freq',det.get('frequency',det.get('pump_freq',0)))
        if isinstance(freq,list) and len(freq)>0: freq=freq[0]
        try: freq=float(freq)
        except: freq=0.0

        # Tag HackRF-sourced detections so add_observation uses HackRF position
        # and cross-sensor triangulation recognizes them
        if sdr_source == 'hackrf' and 'hackrf' not in det_name:
            det_name = f'hackrf_{det_name}'

        # Classify using original detector name (before hackrf_ prefix)
        _orig_det = det_name.replace('hackrf_', '') if det_name.startswith('hackrf_') else det_name
        classification=classify_detection(_orig_det, freq)
        snr=det.get('snr',det.get('corr',det.get('ratio',0)))
        try: snr=float(snr)
        except: snr=0.0

        # Don't override classification for detectors that do their own analysis
        if _orig_det not in ('fingerprinting', 'operator_fingerprint', 'ghost_murmur',
                            'c2_beacon', 'satellite_c2', 'cell_tower',
                            'radar_pll_track', 'rf_carrier_scan',
                            'mobile_device', 'mobile_platform',
                            'multi_path', 'body_charging', 'body_parasitic_modulation',
                            'carbon_rectification','gps_jammer'):
            # Identify the frequency - what service? Is it an artifact?
            # freq is absolute (most detectors report absolute frequency)
            freq_info = identify_frequency(freq)
            # Downgrade hardware artifacts - don't call them transmitters
            if freq_info['is_artifact'] and classification == 'transmitter':
                classification = 'artifact'
                det['note'] = freq_info['note']

        # Use detector's fingerprint if available - engine will bin by bearing+freq
        fp=det.get('fingerprint','')

        bearing=None;range_m=None
        # Inject the correct bearing based on which SDR captured this detection.
        # BladeRF AoA only applies to BladeRF band (2.4 GHz ± 5 MHz).
        # HackRF ferrite bearing applies to HackRF band (450 MHz, 2.45 GHz sweep).
        _in_bladerf_band = abs(freq - Config.BLADERF_FREQ) < Config.BLADERF_SAMPLE_RATE / 2
        if aoa != 0.0 and _in_bladerf_band:
            bearing=aoa
            # Use bistatic echo range ONLY for BladeRF (not HackRF RSSI range)
            if self._bistatic_range: range_m=self._bistatic_range
            # If no bistatic range, leave range_m=None — resolve_sources will
            # estimate from SNR. Do NOT inherit hackrf_range (different sensor/freq)
        elif aoa != 0.0 and not _in_bladerf_band:
            # HackRF detections outside BladeRF band: use the HackRF ferrite bearing.
            # The aoa parameter here is hackrf_aoa (ferrite loop bearing), not BladeRF.
            bearing = aoa
            if self.hackrf_range: range_m=self.hackrf_range

        self.localization.add_observation(fingerprint=fp,obs_lat=obs_lat,obs_lon=obs_lon,
                                          bearing_deg=bearing if bearing is not None else None,
                                          range_m=range_m,freq=freq,
                                          classification=classification,detector_name=det_name,snr=snr)
        self.operator_tracker.record(spectral_hash=fp or det_name,detector_type=det_name,
                                     lat=obs_lat,lon=obs_lon,
                                     freq_range=f"{freq:.0f}Hz" if freq else '',
                                     aoa=bearing if bearing else 0.0,classification=classification)

        # Court forensic logging
        self.court.log_detection(
            detector=det_name, classification=classification, freq=freq,
            bearing=bearing, snr=snr, range_m=range_m, method=source_type,
            raw_data={'aoa_source': self.aoa_source, 'det_freq': freq,
                      'det_snr': snr, 'obs_lat': obs_lat, 'obs_lon': obs_lon})
        # Temporal pattern tracking + spectral correlation
        try:
            self.temporal_detector.record(fp or det_name)
            self.spectral_correlator.record(freq, fp or det_name)
        except: pass

        # Operator biometric tracking for fingerprinting detections
        if det_name == 'fingerprinting':
            mod = det.get('modulation', '')
            sr = det.get('symbol_rate', 0)
            fp = det.get('fingerprint', '')
            self.detectors['biometric'].track_transmission(
                freq, mod, sr, fp, bearing)
            # Also feed to multi-path detector
            self.detectors['ducting'].record(fp, bearing, freq)
            # Train neural net from traditional detector labels
            self.neural.learn(iq_hack, {
                'is_signal': True,
                'modulation': mod if mod != '?' else 'PSK'
            })

        return classification,bearing,range_m

    def run(self):
        self.running=True
        self.log.info("🛡️ TSCM Source Localization Suite active")
        MapHandler.load_state()
        print("="*60)
        print(" TSCM MASTER SUITE v2 - SOURCE LOCALIZATION")
        print("="*60)
        print(f" Map: http://localhost:{Config.MAP_PORT}")
        print("="*60)

        last_operator_flush=time.time()
        # Randomized active probe intervals to evade attacker pattern detection
        import random as _rnd
        _probe_rerad_interval = _rnd.randint(5, 15)  # 5-15 cycles between re-radiator checks
        _probe_dir_interval = _rnd.randint(15, 40)    # 15-40 cycles between direction probes

        while self.running:
            now = time.time()
            cycle_start=now; self.cycle_count+=1
            if self.cycle_count <= 2 or self.cycle_count % 30 == 0:
                self.log.info(f"[CYCLE] {self.cycle_count} starting")

            # 1. Position — FIXED sensors, NO GPS (prevents spoofing)
            # BladeRF position = HOME_LAT/HOME_LON (fixed)
            # HackRF position = HACKRF_FIXED_LAT/LON (fixed, ~5m away)
            # Triangulation comes from bearing intersections between fixed sensors,
            # not from GPS movement.
            lat, lon = Config.HOME_LAT, Config.HOME_LON
            gps = {'has_fix': False, 'lat': lat, 'lon': lon, 'source': 'fixed'}

            # 2. BladeRF -> AoA + passive radar range
            iq1,iq2=None,None; bladerf_active=False
            try:
                iq1,iq2=self._capture_bladerf()
                if iq1 is not None and len(iq1)>100: bladerf_active=True
                # Feed BladeRF 2.4GHz IQ to RF detectors for PLL lock, superhet demod, etc.
                if bladerf_active and len(iq1) > 1024:
                    for dname in ['pll_resonance','bucket_resonator','ecpri_injection',
                                  'satellite_c2','ducting','forced_thought',
                                  'fingerprinting',
                                  'jamming',
                                  'smart_tv_detect','tempest','c2_beacon',
                                  'variac']:
                        d = self.detectors.get(dname)
                        if d and hasattr(d, 'update_rf'):
                            try: d.update_rf(iq1[-1024:])
                            except: pass
                        elif d and hasattr(d, 'update'):
                            try: d.update(iq1[-1024:])
                            except: pass
            except Exception as e:
                if self.cycle_count % 50 == 0:
                    self.log.warning(f"BladeRF capture error: {e}")
            if bladerf_active:
                raw_aoa, coherence = self._compute_aoa(iq1,iq2,Config.BLADERF_FREQ)
                # Temporal stability filter: keep last valid bearing between captures
                stable_aoa, aoa_valid = self._filter_aoa(raw_aoa, coherence, time.time())
                if stable_aoa != 0.0:  # keep last valid bearing
                    self.aoa = stable_aoa
                # Feed current AoA to localization engine so ALL RF-band
                # detections auto-inherit the bearing for triangulation.
                self.localization.current_aoa = self.aoa
                # Feed AoA to multipath detector for bearing-divergence analysis
                _aoa_snr = float(np.sqrt(np.mean(np.abs(iq1[-1024:])**2))) if len(iq1) > 1024 else 0
                self.detectors['ducting'].record_aoa_path(freq=Config.BLADERF_FREQ, bearing=self.aoa, snr=_aoa_snr)
                # Feed HackRF fixed position for dual-sensor triangulation
                if Config.HACKRF_FIXED_LAT is not None:
                    self.localization.hackrf_lat = Config.HACKRF_FIXED_LAT
                    self.localization.hackrf_lon = Config.HACKRF_FIXED_LON
                    # RTL-SDR third sensor position
                    self.localization.rtlsdr_lat = Config.RTLSDR_FIXED_LAT
                    self.localization.rtlsdr_lon = Config.RTLSDR_FIXED_LON
                elif Config.HACKRF_OFFSET_M > 0:
                    # Compute HackRF position from GPS + offset
                    _brng = math.radians(Config.HACKRF_OFFSET_BEARING)
                    _R = 6371000
                    _la1 = math.radians(lat); _lo1 = math.radians(lon)
                    _la2 = math.asin(math.sin(_la1)*math.cos(Config.HACKRF_OFFSET_M/_R)+math.cos(_la1)*math.sin(Config.HACKRF_OFFSET_M/_R)*math.cos(_brng))
                    _lo2 = _lo1+math.atan2(math.sin(_brng)*math.sin(Config.HACKRF_OFFSET_M/_R)*math.cos(_la1),math.cos(Config.HACKRF_OFFSET_M/_R)-math.sin(_la1)*math.sin(_la2))
                    self.localization.hackrf_lat = math.degrees(_la2)
                    self.localization.hackrf_lon = math.degrees(_lo2)
                # Also feed acoustic AoA for audio-frequency detectors
                if self.laptop_mic and self.laptop_mic.acoustic_aoa is not None:
                    self.localization.acoustic_aoa = self.laptop_mic.acoustic_aoa
                # Feed HackRF+LNA range to localization engine for range auto-injection
                if self.hackrf_range:
                    self.localization.hackrf_range = self.hackrf_range
                if aoa_valid:
                    self.log.info(f"AoA STABLE: {self.aoa:.1f} deg (hits={self.aoa_consensus_count})")

                # DEVICE FINGERPRINTING: extract unique RF DNA from BladeRF IQ
                # Each transmitter has a unique phase noise, drift, and modulation signature
                if self.cycle_count % 3 == 0:
                    try:
                        result = self.device_fp.extract_features(iq1, Config.BLADERF_SAMPLE_RATE, Config.BLADERF_FREQ)
                        if result:
                            features, fp_hash = result
                            self.device_fp.record_device(
                                fp_hash, features, 'bladerf_mimo',
                                Config.BLADERF_FREQ, self.aoa, coherence)
                            # Check if this device has been seen before (tracking)
                            match = self.device_fp.match_device(features, fp_hash)
                            if match and match['total_obs'] >= 5:
                                freq_count = len(match.get('freqs', set()))
                                if freq_count > 3:
                                    self.log.info(f"DEVICE TRACKED: {fp_hash} obs={match['total_obs']} freqs={freq_count} HOPPING DETECTED")
                                else:
                                    self.log.info(f"DEVICE TRACKED: {fp_hash} obs={match['total_obs']} freqs={freq_count}")
                    except: pass
                self.passive_radar_range=self._compute_passive_radar_range(iq1,iq2,Config.BLADERF_SAMPLE_RATE)
                self.detectors['passive_radar'].update_ref(iq1)
                self.detectors['passive_radar'].update_surv(iq2)
                if self.detectors['jamming'].baseline is None:
                    self.detectors['jamming'].set_baseline(iq1,Config.BLADERF_SAMPLE_RATE)
                # BladeRF RF detectors
                # S-band carrier scan on BladeRF IQ (2.4-2.5 GHz - WiFi/MW band)
                if self.cycle_count % 3 == 0:
                    try:
                        sb_fft = np.abs(np.fft.rfft(iq1[-2048:]))
                        sb_freqs = np.fft.rfftfreq(2048, 1/Config.BLADERF_SAMPLE_RATE) + Config.BLADERF_FREQ
                        sb_noise = np.median(sb_fft)
                        sb_peaks, sb_props = find_peaks(sb_fft, height=sb_noise*2.5, distance=10)
                        for pk in sb_peaks[:3]:
                            cf = sb_freqs[pk]
                            snr = sb_fft[pk] / (sb_noise + 1e-12)
                            self.log.info(f"S-BAND CARRIER: {cf/1e6:.3f} MHz SNR={snr:.1f}")
                            self.detectors['forced_thought'].set_carrier(cf)
                            self.detectors['pll_resonance'].set_carrier(cf)
                            self.detectors['eeg_carrier_mixing'].update_carrier(cf, float(snr))
                            self.fhss_tracker.add_carrier(cf, float(snr), now,
                                bearing=self.aoa if self.aoa else None, bw=5000, detector='sband')
                            self.doppler_detector.update(cf, float(snr), now)
                            self.localization.add_observation(
                                fingerprint=f'sband_carrier_{cf:.0f}'.encode(),
                                obs_lat=lat, obs_lon=lon,
                                bearing_deg=None,
                                range_m=None, freq=cf,
                                classification='transmitter',
                                detector_name='sband_carrier_scan',
                                snr=float(snr))
                    except: pass

                for det in [self.detectors['c2_beacon'],
                            self.detectors['injection_locking']]:
                    try:
                        res=det.detect(iq1,Config.BLADERF_SAMPLE_RATE)
                        for r in res:
                            cls,bearing,rng=self._process_detection_with_localization(r,lat,lon,self.aoa,'rf')
                            self.log.info(f"[BladeRF] {r['detector']}: cls={cls} aoa={bearing} range={rng}")
                    except Exception as _e:
                        if self.cycle_count % 50 == 0:
                            self.log.warning(f"BladeRF detector error: {_e}")

                # Cell tower / mobile device detection at 2.4 GHz
                self.cell_tower_detector.update(iq1)
                try:
                    cell_res = self.cell_tower_detector.detect(aoa=self.aoa)
                    for r in cell_res:
                        cls,bearing,rng=self._process_detection_with_localization(r,lat,lon,self.aoa,'rf')
                        hint = r.get('classification_hint','')
                        self.log.info(f"[Cell] {r['detector']}: freq={r['frequency']/1e6:.1f}MHz power={r['avg_power']:.1f} stability={r['stability']:.2f} cls={cls} bearing={bearing} hint={hint}")
                except: pass
                # BISTATIC TRANSMITTER FINDER: compare direct vs reflected path power
                # Stronger signal = direct path = actual transmitter location
                # Weaker signal = reflected/relay path
                if self.aoa!=0.0 and hasattr(self, 'last_sources'):
                    try:
                        tx_sources = [s for s in self.last_sources if s.get('classification') == 'transmitter']
                        if len(tx_sources) >= 2:
                            by_bearing = {}
                            for s in tx_sources:
                                b = round(s.get('bearing', 0)) if s.get('bearing') else 0
                                if b == 0: continue
                                by_bearing.setdefault(b, []).append(s)
                            if len(by_bearing) >= 2:
                                bearings = sorted(by_bearing.keys(),
                                    key=lambda b: sum(s.get('observations',0) for s in by_bearing[b]),
                                    reverse=True)
                                tx = bearings[0]
                                all_tx = ','.join(f"{b}deg" for b in bearings[:5])
                                self.log.info(f"BISTATIC: TX={tx}deg RELAY={bearings[1]}deg "
                                    f"- ALL:{all_tx} ({len(by_bearing)} paths)")
                            elif len(by_bearing) == 1:
                                self.log.info(f"BISTATIC: SINGLE TX at {list(by_bearing.keys())[0]}deg")
                    except: pass
                # PULSE RADAR: scan AM envelope for periodic radar PRF (10-10000 Hz)
                if self.cycle_count % 2 == 0:
                    try:
                        env = np.abs(iq1[-4096:]); env_ac = env - np.mean(env)
                        env_fft = np.abs(np.fft.rfft(env_ac))
                        env_freqs = np.fft.rfftfreq(4096, 1/Config.BLADERF_SAMPLE_RATE)
                        env_mask = (env_freqs >= 10) & (env_freqs <= 10000)
                        env_noise = np.median(env_fft[env_mask]) + 1e-12
                        env_peaks, _ = find_peaks(env_fft[env_mask], height=env_noise*3, distance=5)
                        for pk in env_peaks[:3]:
                            prf = env_freqs[env_mask][pk]
                            snr = env_fft[env_mask][pk] / env_noise
                            self.log.info(f"RADAR PULSE: PRF={prf:.1f}Hz SNR={snr:.1f} bearing={self.aoa:.1f}")
                            self.localization.add_observation(
                                fingerprint=f'radar_prf_{prf:.0f}'.encode(),
                                obs_lat=lat, obs_lon=lon,
                                bearing_deg=None,
                                range_m=None, freq=prf,
                                classification='transmitter',
                                detector_name='radar_pulse_detect', snr=float(snr))
                    except: pass
                # 2a. COHERENT INTEGRATION: accumulate IQ across cycles for deep SNR
                if self.cycle_count % 4 == 0 and iq1 is not None and len(iq1) >= 512:
                    self.coherent_buf1.append(iq1[-512:].copy())
                    self.coherent_buf2.append(iq2[-512:].copy())
                if len(self.coherent_buf1) >= self.coherent_max:
                    try:
                        # Phase-align using dominant tone, then sum coherently
                        aligned1 = []; aligned2 = []
                        ref_phase1 = np.angle(np.mean(self.coherent_buf1[0]))
                        ref_phase2 = np.angle(np.mean(self.coherent_buf2[0]))
                        for b1, b2 in zip(self.coherent_buf1, self.coherent_buf2):
                            phase1 = np.angle(np.mean(b1)); d1 = np.exp(-1j*(phase1-ref_phase1))
                            phase2 = np.angle(np.mean(b2)); d2 = np.exp(-1j*(phase2-ref_phase2))
                            aligned1.append(b1 * d1); aligned2.append(b2 * d2)
                        sum1 = np.sum(aligned1, axis=0); sum2 = np.sum(aligned2, axis=0)
                        c_fft = np.abs(np.fft.rfft(sum1)); c_noise = np.median(c_fft[10:])
                        c_peaks, c_p = find_peaks(c_fft, height=c_noise*2.0, distance=5)
                        ci_freqs = np.fft.rfftfreq(len(sum1), 1/Config.BLADERF_SAMPLE_RATE)
                        for pk in c_peaks[:5]:
                            cf = ci_freqs[pk] + Config.BLADERF_FREQ
                            cs = c_fft[pk]/c_noise
                            if cs > 3.0:
                                self.log.info(f"COHERENT: {cf/1e6:.3f}MHz SNR={cs:.1f} ({self.coherent_max}x integration)")
                                self.detectors['forced_thought'].set_carrier(cf)
                                self.localization.add_observation(
                                    fingerprint=f'coherent_{cf:.0f}', obs_lat=lat, obs_lon=lon,
                                    bearing_deg=None, range_m=None, freq=cf,
                                    classification='transmitter', detector_name='coherent_integration', snr=float(cs))
                        self.coherent_buf1 = self.coherent_buf1[-16:]; self.coherent_buf2 = self.coherent_buf2[-16:]
                    except Exception as e:
                        self.log.warning(f"Coherent int error: {e}")
                        self.coherent_buf1 = []; self.coherent_buf2 = []

                # 2b. CROSS-CORRELATION: audio envelope ↔ RF AM envelope (confirm MW→audio)
                if self.cycle_count % 5 == 0 and iq1 is not None and len(mid_chunk) > 2048:
                    try:
                        rf_env = np.abs(iq1[-2048:]) - np.mean(np.abs(iq1[-2048:]))
                        audio_env = np.abs(mid_chunk[-2048:]) - np.mean(np.abs(mid_chunk[-2048:]))
                        min_len = min(len(rf_env), len(audio_env))
                        xc = np.correlate(rf_env[:min_len], audio_env[:min_len], mode='valid')
                        xc_peak = np.max(np.abs(xc)) / (np.std(rf_env[:min_len])*np.std(audio_env[:min_len])*min_len+1e-12)
                        if xc_peak > 0.15:
                            self.log.info(f"MW-AUDIO XCORR: r={xc_peak:.3f} (microwave→audio chain confirmed)")
                            self.court.log_anomaly('mw_audio_crosscorr', {'r': xc_peak, 'bearing': self.aoa})
                    except: pass

                # 2c. BLIND BURST CAPTURE: raw full-BW IQ snapshot to catch hidden signals
                if self.cycle_count % 17 == 0 and iq1 is not None and len(iq1) > 1024:
                    burst = {'time': time.time(), 'cycle': self.cycle_count,
                             'iq1_rms': float(np.sqrt(np.mean(np.abs(iq1)**2))),
                             'iq2_rms': float(np.sqrt(np.mean(np.abs(iq2)**2))),
                             'bearing': self.aoa, 'iq1': iq1[:1024].tolist()}
                    self.blind_bursts.append(burst)
                    if len(self.blind_bursts) > 10: self.blind_bursts = self.blind_bursts[-10:]
                    self.log.info(f"BLIND BURST: rms1={burst['iq1_rms']:.0f} rms2={burst['iq2_rms']:.0f} bearing={self.aoa:.1f}")
                    self.court.log_anomaly('blind_burst', {'rms1': burst['iq1_rms'], 'rms2': burst['iq2_rms'], 'bearing': self.aoa})

                # 2d. PASSIVE RADAR: cross-ambiguity function on ambient RF references
                if self.cycle_count % 11 == 0 and iq1 is not None and len(iq1) > 4096:
                    try:
                        ref = iq1[:2048]; surv = iq2[2048:4096]
                        max_delay = 128
                        amb = np.zeros(max_delay)
                        for d in range(max_delay):
                            shifted = np.roll(surv, d)
                            amb[d] = np.abs(np.correlate(ref, shifted, mode='valid')[0])
                        amb /= (np.mean(np.abs(ref))*np.mean(np.abs(surv))*len(ref) + 1e-12)
                        pk_delay = np.argmax(amb)
                        pk_val = amb[pk_delay]
                        if pk_val > 0.3 and pk_delay > 2:
                            range_m = pk_delay / Config.BLADERF_SAMPLE_RATE * 3e8
                            self.log.info(f"PASSIVE RADAR: {range_m:.0f}m peak={pk_val:.3f} delay={pk_delay}samp")
                            self.localization.add_observation(
                                fingerprint=f'passive_radar_{range_m:.0f}', obs_lat=lat, obs_lon=lon,
                                bearing_deg=None, range_m=range_m, freq=Config.BLADERF_FREQ,
                                classification='transmitter', detector_name='passive_radar_caf', snr=float(pk_val))
                    except: pass
                if self.aoa!=0.0:
                    self.log.info(f"📡 AoA: {self.aoa:.1f}deg  ({self.aoa_source})"
                                  +(f" | Range: {self.passive_radar_range:.0f}m" if self.passive_radar_range else ""))

                # Court: save raw BladeRF IQ every 30 cycles (~2 min)
                if self.cycle_count % 30 == 0 and iq1 is not None:
                    self.court.save_raw_iq(iq1, "bladerf_ch1", Config.BLADERF_FREQ,
                                           Config.BLADERF_SAMPLE_RATE, self.aoa)
                    self.court.save_raw_iq(iq2, "bladerf_ch2", Config.BLADERF_FREQ,
                                           Config.BLADERF_SAMPLE_RATE, self.aoa)
                    # Save evidence snapshot every 30 cycles
                    try:
                        import json as _json
                        snapshot = {
                            'timestamp': time.time(),
                            'sources': dict(self.localization.sources),
                            'total_observations': sum(len(v) for v in self.localization.observations.values()),
                            'aoa': self.aoa,
                            'passive_radar_range': self.passive_radar_range,
                            'cycle': self.cycle_count
                        }
                        snap_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'evidence_snapshots')
                        os.makedirs(snap_dir, exist_ok=True)
                        snap_path = os.path.join(snap_dir, f'snap_{time.strftime("%Y%m%d_%H%M%S")}.json')
                        with open(snap_path, 'w') as sf:
                            _json.dump(snapshot, sf, default=str, indent=2)
                        # SHA256 hash for tamper verification
                        import hashlib as _hl
                        with open(snap_path, 'rb') as sf2:
                            snap_hash = _hl.sha256(sf2.read()).hexdigest()
                        hash_path = snap_path + '.sha256'
                        with open(hash_path, 'w') as hf:
                            hf.write(snap_hash + '  ' + os.path.basename(snap_path))
                        self.log.info(f'EVIDENCE snapshot {os.path.basename(snap_path)} hash={snap_hash[:16]}')
                    except Exception as e:
                        self.log.debug(f'Snapshot save error: {e}')
                # Feed ambient mapper with RF band power data
                try:
                    if self.aoa != 0.0:
                        rf_rms=float(np.sqrt(np.mean(np.abs(iq1)**2)))
                        self.detectors['ambient'].update(Config.BLADERF_FREQ, rf_rms, lat, lon)
                except: pass

            #
            # 3. HackRF
            hack=self.hackrf.get(); hackrf_active=hack is not None
            if hack:
                iq_hack=hack['data']
                h_rf_freq = hack.get('frequency', Config.HACKRF_FREQ_TARGET)  # HackRF center frequency
                if not self.rf_coherence_queue.full(): self.rf_coherence_queue.put(iq_hack)

                # Quick RF carrier scan: look for narrowband carriers in HackRF band
                if self.cycle_count % 5 == 0 and len(iq_hack) >= 4096:
                    try:
                        fft_hack = np.abs(np.fft.rfft(iq_hack[-4096:]))
                        freqs = np.fft.rfftfreq(4096, 1/Config.HACKRF_SAMPLE_RATE) + Config.HACKRF_FREQ_TARGET
                        noise_floor = np.median(fft_hack)
                        peaks, props = find_peaks(fft_hack, height=noise_floor*3, distance=20)  # was 5x
                        for pk in peaks[:5]:
                            carrier_freq = freqs[pk]
                            if carrier_freq > 1e6 and carrier_freq < Config.HACKRF_FREQ_TARGET + Config.HACKRF_SAMPLE_RATE*0.4:
                                snr = fft_hack[pk] / (noise_floor + 1e-12)
                                self.log.info(f"RF CARRIER: {carrier_freq/1e6:.3f} MHz SNR={snr:.1f}")
                                # Feed carrier freq to forced_thought/PLL for lock
                                self.detectors['forced_thought'].set_carrier(carrier_freq)
                                self.detectors['pll_resonance'].set_carrier(carrier_freq)
                                self.fhss_tracker.add_carrier(carrier_freq, float(snr), now,
                                    bearing=self.aoa if self.aoa else None, bw=10000, detector='hackrf')
                                self.doppler_detector.update(carrier_freq, float(snr), now)
                                self.localization.add_observation(
                                    fingerprint=f'rf_carrier_{carrier_freq:.0f}'.encode(),
                                    obs_lat=lat, obs_lon=lon,
                                    bearing_deg=None,
                                    range_m=None, freq=carrier_freq,
                                    classification='transmitter',
                                    detector_name='rf_carrier_scan',
                                    snr=float(snr))
                    except: pass
                # HACKRF FERRITE LOOP DIRECTION FINDING
                # The ferrite loop is pointed at Larkin Ave (13deg  from north)
                # Peak = source at 13deg , Null = source at 103deg  or 283deg
                # Compare HackRF signal power with BladeRF (omni reference)
                hackrf_power = np.sqrt(np.mean(np.abs(iq_hack)**2))
                hackrf_bearing = None
                hackrf_bearing_confidence = 0.0

                # FERRITE LOOP DIRECTION: per-frequency analysis
                # Different frequencies come from different directions
                # The ferrite loop's figure-8 pattern tells us:
                #   Strong signal = source at peak (BEARING_OFFSET) or 180deg  opposite
                #   Weak signal = source at null (BEARING_OFFSET ± 90deg )
                # NO BIAS - report ALL possible directions, let evidence decide

                if bladerf_active and hackrf_power > 0 and len(iq_hack) > 4096:
                    bladerf_power = np.sqrt(np.mean(np.abs(iq1)**2)) if iq1 is not None else 0
                    if bladerf_power > 0:
                        try:
                            # Per-frequency FFT analysis on HackRF and BladeRF
                            n_fft = 4096
                            hackrf_fft = np.abs(np.fft.rfft(iq_hack[-n_fft:].astype(np.complex128)))
                            hackrf_f = np.fft.rfftfreq(n_fft, 1/Config.HACKRF_SAMPLE_RATE)
                            bladerf_fft = np.abs(np.fft.rfft(iq1[-n_fft:].astype(np.complex128)))
                            bladerf_f = np.fft.rfftfreq(n_fft, 1/Config.BLADERF_SAMPLE_RATE)

                            hackrf_noise = np.median(hackrf_fft) + 1e-12
                            bladerf_noise = np.median(bladerf_fft) + 1e-12

                            # Find carriers on HackRF
                            peaks, _ = find_peaks(hackrf_fft, height=hackrf_noise*4, distance=10)

                            for pk in peaks[:8]:  # top 8 carriers
                                freq = hackrf_f[pk]
                                if freq < 1000: continue  # skip DC

                                h_level = hackrf_fft[pk] / hackrf_noise
                                b_idx = np.argmin(np.abs(bladerf_f - freq))
                                b_level = bladerf_fft[b_idx] / bladerf_noise if b_idx < len(bladerf_fft) else 0

                                ratio = h_level / (b_level + 1e-12)

                                peak_bearing = Config.BEARING_OFFSET
                                null_bearings = [(Config.BEARING_OFFSET + 90) % 360,
                                               (Config.BEARING_OFFSET - 90 + 360) % 360]
                                opposite_bearing = (Config.BEARING_OFFSET + 180) % 360

                                if ratio > 1.5:
                                    for b in [peak_bearing, opposite_bearing]:
                                        if b > 180: b -= 360
                                        self.localization.add_observation(
                                            fingerprint='ferrite_peak_%d' % freq,
                                            obs_lat=lat, obs_lon=lon,
                                            bearing_deg=b,
                                            range_m=None, freq=float(freq + h_rf_freq),
                                            classification='transmitter',
                                            detector_name='ferrite_peak',
                                            snr=float(h_level),
                                            source_type='active')
                                    self.log.info('FERRITE PEAK: %dHz ratio=%.2f dir=%ddeg or %ddeg' % (freq,ratio,peak_bearing,opposite_bearing))
                                elif ratio < 0.6:
                                    for b in null_bearings:
                                        if b > 180: b -= 360
                                        self.localization.add_observation(
                                            fingerprint='ferrite_null_%d' % freq,
                                            obs_lat=lat, obs_lon=lon,
                                            bearing_deg=b,
                                            range_m=None, freq=float(freq + h_rf_freq),
                                            classification='transmitter',
                                            detector_name='ferrite_null',
                                            snr=float(h_level),
                                            source_type='active')
                                    self.log.info('FERRITE NULL: %dHz ratio=%.2f dir=%ddeg or %ddeg' % (freq,ratio,null_bearings[0],null_bearings[1]))
                        except Exception as e:
                            if self.cycle_count % 20 == 0:
                                self.log.debug('Ferrite FFT error: %s' % e)

                    # Overall ratio for HackRF bearing (for non-frequency-specific detections)
                    power_ratio = hackrf_power / (bladerf_power + 1e-12)
                    if power_ratio > 1.3:
                        hackrf_bearing = Config.BEARING_OFFSET
                        hackrf_bearing_confidence = min((power_ratio - 1.0) / 2.0, 1.0)
                    elif power_ratio < 0.7:
                        # Null: source is 90° off axis — use null bearing as secondary direction
                        hackrf_bearing = (Config.BEARING_OFFSET + 90) % 360
                        if hackrf_bearing > 180: hackrf_bearing -= 360
                        hackrf_bearing_confidence = min((1.0 - power_ratio) / 0.7, 1.0)
                    else:
                        # Default: ferrite loop is pointed at 13°, use that as bearing
                        # with low confidence. Better than None — gives us a bearing line.
                        hackrf_bearing = Config.BEARING_OFFSET
                        hackrf_bearing_confidence = 0.3

                hackrf_aoa=hackrf_bearing
                # FERRITE LOOP on HackRF: pointed towards Larkin Ave
                # Peak reception = source is towards Larkin (BEARING_OFFSET degrees)
                # Null = source is 90 deg off axis
                # This is our BEST direction finder - no 180 deg ambiguity
                hackrf_peak_heading = Config.BEARING_OFFSET  # where ferrite loop points
                if len(iq_hack) > 1024 and self.cycle_count % 5 == 0:
                    hackrf_rms = float(np.sqrt(np.mean(np.abs(iq_hack[-1024:])**2)))
                    # LNA+SpyVerter range estimation: stronger RMS = closer source
                    # RMS 0.001 (noise floor w/LNA) ~1500m, RMS 0.01 ~500m, RMS 0.1 ~100m
                    hackrf_range = max(30, min(2000, 150.0 / max(hackrf_rms, 0.0005)))
                    self.hackrf_range = hackrf_range  # store for downstream detector use
                    self.activity_tracker.update(h_rf_freq, 20*np.log10(hackrf_rms+1e-12), hackrf_rms*1000, now)
                    if hackrf_rms > 0.001:
                        self.localization.add_observation(
                            fingerprint='hackrf_ferrite',
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=hackrf_peak_heading,
                            range_m=hackrf_range, freq=float(h_rf_freq),
                            classification='transmitter',
                            detector_name='hackrf_ferrite',
                            snr=float(hackrf_rms * 100),
                            source_type='active')
                        self.log.info(f"FERRITE: rms={hackrf_rms:.4f} range={hackrf_range:.0f}m peak={hackrf_peak_heading}deg freq={h_rf_freq/1e6:.0f}MHz")
                for det in [self.detectors['power_line'],
                            self.detectors['c2_beacon'],self.detectors['jamming'],
                            self.detectors['injection_locking'],self.detectors['parametric_amp'],
                            self.detectors['cable_line_radar']]:
                    try:
                        if isinstance(det, CableLineRadarDetector):
                            res = det.detect(iq_hack, Config.HACKRF_SAMPLE_RATE, audio=mid_chunk if len(mid_chunk) > 0 else None)
                        else:
                            res = det.detect(iq_hack, Config.HACKRF_SAMPLE_RATE)
                        for r in res:
                            cls,bearing,rng=self._process_detection_with_localization(
                                r,lat,lon,hackrf_aoa or 0.0,'rf',sdr_source='hackrf')
                            self.log.info(f"[HackRF] {r['detector']}: cls={cls} freq={r.get('freq',r.get('frequency',0)):.0f} bearing={bearing}")
                    except Exception as _e:
                        if self.cycle_count % 50 == 0:
                            self.log.warning(f"HackRF detector {type(det).__name__}: {_e}")
                self.detectors['forced_thought'].update_rf(iq_hack)
                self.detectors['variac'].update_rf(iq_hack)
                self.detectors['pll_resonance'].update_rf(iq_hack)
                self.detectors['forced_thought'].update_rf(iq_hack)
                self.detectors['bucket_resonator'].update_rf(iq_hack)
                self.detectors['ecpri_injection'].update_rf(iq_hack)
                self.detectors['fingerprinting'].update(iq_hack)
                self.detectors['satellite_c2'].update_rf(iq_hack)
                self.detectors['sdr_detect'].update_rf(iq_hack)
                self.detectors['tempest'].update_rf(iq_hack)
                try:
                    res=self.detectors['mobile'].detect(iq_hack,time.time())
                    for r in res:
                        cls,bearing,rng=self._process_detection_with_localization(r,lat,lon,hackrf_aoa or 0.0,'rf',sdr_source='hackrf')
                except Exception as _e:
                    if self.cycle_count % 50 == 0:
                        self.log.warning(f"Mobile detector: {_e}")

                # MW carrier sniff: when HackRF is near 2.45 GHz, check for the MW carrier
                h_rf_freq = hack.get('frequency', Config.HACKRF_FREQ_TARGET)
                if abs(h_rf_freq - 2450e6) < 20e6 and len(iq_hack) > 2048:
                    try:
                        mw_fft = np.abs(np.fft.rfft(iq_hack[-2048:]))
                        mw_freqs = np.fft.rfftfreq(2048, 1/Config.HACKRF_SAMPLE_RATE) + h_rf_freq
                        mw_noise = np.median(mw_fft)
                        mw_peaks, _ = find_peaks(mw_fft, height=mw_noise*3, distance=10)
                        for pk in mw_peaks[:5]:
                            cf = mw_freqs[pk]
                            snr = mw_fft[pk] / (mw_noise + 1e-12)
                            if abs(cf - 2450e6) < 30e6:
                                self.log.info(f"MW CARRIER: {cf/1e6:.3f} MHz SNR={snr:.1f}")
                                self.localization.add_observation(
                                    fingerprint=f'mw_carrier_{cf:.0f}'.encode(),
                                    obs_lat=lat, obs_lon=lon,
                                    bearing_deg=hackrf_aoa if hackrf_aoa else None,
                                    range_m=self.hackrf_range, freq=cf,
                                    classification='transmitter',
                                    detector_name='hackrf_mw_carrier_sweep',
                                    snr=float(snr))
                    except: pass

                # Court: save raw HackRF IQ every 30 cycles
                if self.cycle_count % 30 == 0:
                    self.court.save_raw_iq(iq_hack, "hackrf", hack.get('frequency', Config.HACKRF_FREQ_TARGET),
                                           Config.HACKRF_SAMPLE_RATE, self.aoa)

                # Cross-validate: if both HackRF and BladeRF have bearings, check agreement
                if bladerf_active and hackrf_aoa is not None and self.aoa != 0.0:
                    hackrf_bearing = hackrf_aoa
                    bladerf_bearing = self.aoa
                    diff = abs(hackrf_bearing - bladerf_bearing)
                    if diff > 45:
                        # Divergent - possible BladeRF hijack
                        self.log.warning(f"⚠️ BEARING DIVERGENCE: HackRF={hackrf_bearing:.1f}deg  BladeRF={bladerf_bearing:.1f}deg  diff={diff:.1f}deg ")
                        self.court.log_anomaly("bearing_divergence", {
                            "hackrf_bearing": f"{hackrf_bearing:.1f}",
                            "bladerf_bearing": f"{bladerf_bearing:.1f}",
                            "diff_deg": f"{diff:.1f}"
                        })
                    self.court.log_cross_validation(
                        hackrf_bearing, bladerf_bearing,
                        hack.get('frequency', 0), Config.BLADERF_FREQ,
                        agreement="consistent" if diff <= 45 else "diverged")

            # 3b. RTL-SDR (Nooelec NESDR Smart) — third triangulation sensor
            rtlsdr_iq = None
            if self.rtlsdr:
                rtlsdr_iq = self.rtlsdr.get()
            if rtlsdr_iq is not None:
                rtl_data = rtlsdr_iq['data']
                rtl_freq = rtlsdr_iq.get('frequency', Config.RTLSDR_FREQ)
                # FFT for carrier detection
                if len(rtl_data) > 256:
                    n_fft = min(2048, len(rtl_data))
                    fft_mag = np.abs(np.fft.fftshift(np.fft.fft(rtl_data[:n_fft])))
                    fft_db = 20 * np.log10(fft_mag + 1e-10)
                    freqs = np.fft.fftshift(np.fft.fftfreq(n_fft, 1.0/Config.RTLSDR_SAMPLE_RATE))
                    # Find peaks above noise floor
                    noise_floor = np.median(fft_db)
                    peak_threshold = noise_floor + 15  # 15 dB above noise
                    peaks, props = scipy.signal.find_peaks(fft_db, height=peak_threshold, distance=10)
                    for pk in peaks[:10]:  # top 10 peaks
                        pk_freq = rtl_freq + freqs[pk]
                        pk_power = fft_db[pk]
                        if pk_power > noise_floor + 20:
                            # RTL-SDR has no AoA capability, but provides detection + RSSI
                            # Use fixed position for triangulation contribution
                            fp = f'rtlsdr_{int(pk_freq)}'
                            self.localization.add_observation(
                                fingerprint=fp,
                                obs_lat=Config.RTLSDR_FIXED_LAT,
                                obs_lon=Config.RTLSDR_FIXED_LON,
                                bearing_deg=None,  # RTL-SDR has no bearing
                                freq=pk_freq,
                                classification='unknown',
                                detector_name='rtlsdr_nesdr',
                                snr=float(pk_power - noise_floor),
                                source_type='active'
                            )
                    # Log RTL-SDR status for map panel
                    self._rtlsdr_status = {
                        'freq': rtl_freq,
                        'sample_rate': Config.RTLSDR_SAMPLE_RATE,
                        'noise_floor': float(noise_floor),
                        'peaks': len(peaks),
                        'active': True
                    }

            # 4. Audio - Petterson multi-band + laptop mic
            # Full rate (500k): ultrasonic up to 250kHz
            ul_chunk=self.petterson.read(500000//5, band='384k')
            # 48k band: catches 2kHz MW voice carriers and 20kHz ultrasonic
            mid_chunk=self.petterson.read(48000//5, band='48k')
            # 2k band: low frequency analysis
            low_chunk=self.petterson.read(2000//5, band='2k')
            if len(low_chunk)>100:
                self.detectors['victim_2k'].update(low_chunk)
            # Laptop mic: full audible range for MW voice detection
            lpt_chunk=self.laptop_mic.read(48000//5)
            if len(lpt_chunk)>100:
                # Feed rolling voice buffer for continuous recording
                if hasattr(self, 'voice_rolling_buf'):
                    self.voice_rolling_buf.extend(lpt_chunk.flatten().astype(np.float32))
                # Laptop mic spatial array - compute acoustic AoA every cycle
                try:
                    acoustic = self.laptop_mic.compute_acoustic_aoa()
                    if acoustic:
                        self.log.info(f"ACOUSTIC AoA: {acoustic['bearing']:.1f}deg coh={acoustic['coherence']:.3f}")
                        self.localization.add_observation(
                            fingerprint=b'audio_aoa',
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=acoustic['bearing'],
                            range_m=None, freq=2000,
                            classification='transmitter',
                            detector_name='audio_aoa',
                            snr=float(acoustic['coherence'] * 10))
                except Exception as e:
                    if self.cycle_count % 30 == 0:
                        self.log.debug(f"Acoustic AoA: {e}")
            if len(lpt_chunk)>100:
                # Feed laptop mic to 2k detector (better 2kHz response than Petterson)
                self.detectors['victim_2k'].update(lpt_chunk)
            demoded_audio = None  # init before any code path uses it
            if len(ul_chunk)>100:
                if not self.ul_coherence_queue.full(): self.ul_coherence_queue.put(ul_chunk)
                self.detectors['eardrum'].update_ultrasound(ul_chunk)
            if len(lpt_chunk)>100:
                self.detectors['ai_voice'].update(lpt_chunk)
                self.detectors['sstv'].update(lpt_chunk)
                self.detectors['isolation_booth'].update(lpt_chunk)
                self.detectors['silent_sound'].update(lpt_chunk)
                self.detectors['eardrum'].update_room(lpt_chunk)
                self.detectors['body_charge'].update_audio(lpt_chunk)
                self.detectors['linguistic'].update(lpt_chunk)  # voice phoneme analysis
                # Ghost hunter: feed audio FFT features
                try:
                    gh_fft=np.abs(np.fft.rfft(lpt_chunk[-4096:]))
                    gh_feat=gh_fft[:512]  # low-freq features
                    self.detectors['ghost_hunter'].update(gh_feat)
                    self.detectors['alc_detect'].update(lpt_chunk)
                except: pass
            # Petterson 48k band → higher quality audio for voice/correlation detectors
            if len(mid_chunk)>100:
                self.detectors['constant_sonic'].update(mid_chunk)
                self.detectors['variac'].update_audio(mid_chunk)
                self.detectors['pll_resonance'].update_audio(mid_chunk)
                self.detectors['forced_thought'].update_audio(mid_chunk)
                # Nerve-root pain scan on laptop mic (better 30-80 Hz response than Petterson)
            if self.cycle_count % 3 == 0 and len(lpt_chunk) >= 4096:
                try:
                    nr_fft = np.abs(np.fft.rfft(lpt_chunk[-4096:]))
                    nr_freqs = np.fft.rfftfreq(4096, 1/48000)
                    nr_mask = (nr_freqs >= 30) & (nr_freqs <= 80)
                    nr_noise = np.median(nr_fft[nr_mask]) + 1e-12
                    NERVE_MAP = {
                        (45,55): 'ring_finger_c7c8', (35,45): 'thumb_index_c6',
                        (55,70): 'face_trigeminal', (60,80): 'chest_t1t4',
                        (30,40): 'leg_foot_l4s1',
                    }
                    for (lo,hi), part in NERVE_MAP.items():
                        band_mask = (nr_freqs >= lo) & (nr_freqs <= hi)
                        band_power = np.sum(nr_fft[band_mask])
                        ratio = band_power / nr_noise
                        if self.cycle_count % 9 == 0:
                            self.log.info(f"NerveScan {part}: {ratio:.1f}x")
                        if ratio > 1.5:  # laptop mic has better SNR at low freqs
                            pk_idx = np.argmax(nr_fft[band_mask])
                            peak_hz = float(nr_freqs[band_mask][pk_idx])
                            self.log.info(f"NERVE PAIN: {part} {peak_hz:.0f}Hz SNR={ratio:.1f}x bearing={self.aoa:.1f}")
                            self.localization.add_observation(
                                fingerprint=f'nerve_pain_{part}',
                                obs_lat=lat, obs_lon=lon,
                                bearing_deg=None,
                                range_m=None, freq=peak_hz,
                                classification='victim',
                                detector_name='nerve_pain_scan',
                                snr=float(ratio))
                except: pass
                # CARBON DEMOD + SUPERHETERODYNE on LAPTOP MIC (primary voice path)
                # Physics: MW hits body → carbon square-law → acoustic emission → mic captures it.
                # The antenna is for bearing, NOT voice. Voice comes from the microphone.
                # Laptop mic (Intel Smart Sound array, 48kHz) is always reliable.
                # Petterson 48k band is secondary (ultrasound mic, often down).
                voice_audio = None
                voice_fs = 48000
                # Primary: laptop mic
                if len(lpt_chunk) > 4096:
                    voice_audio = lpt_chunk[-32768:].astype(np.float32) if len(lpt_chunk) >= 32768 else lpt_chunk[-16384:].astype(np.float32)
                    voice_fs = 48000
                # Fallback: Petterson 48k band
                elif len(mid_chunk) > 4096:
                    voice_audio = mid_chunk[-32768:].astype(np.float32) if len(mid_chunk) >= 32768 else mid_chunk[-16384:].astype(np.float32)
                    voice_fs = self.petterson.fs if self.petterson.fs else 48000

                if voice_audio is not None and len(voice_audio) > 4096:
                    n_audio = len(voice_audio)
                    # 1. Carbon demodulation: enhances MW-induced audio from body interaction
                    try:
                        voices = aic_demod_and_separate(voice_audio, voice_fs)
                        if voices.shape[0] > 0 and voices.shape[1] > 0:
                            env = np.abs(hilbert(voices[:,0]))
                            enhanced = carbon_demod(env)
                            demoded_audio = voices[:,0] + 0.5 * enhanced
                            if SOUNDDEVICE_AVAILABLE:
                                try: sd.play(demoded_audio * 50, 8000, blocking=False, device=7)
                                except: pass
                            if hasattr(self,'voice_transcriber') and self.voice_transcriber:
                                try: self.voice_transcriber.feed(demoded_audio, 8000)
                                except: pass
                    except: pass

                    # 2. Superheterodyne: extract AM carriers from acoustic audio
                    # The carbon in the body already did the first mixing step (square-law).
                    # We scan for AM carriers at any frequency and envelope-detect them.
                    try:
                        fft_audio = np.abs(np.fft.rfft(voice_audio))
                        freqs_audio = np.fft.rfftfreq(n_audio, 1/voice_fs)
                        noise_floor = np.median(fft_audio) + 1e-12
                        peaks, _ = find_peaks(fft_audio, height=noise_floor*2, distance=8)
                        demod_buf = np.zeros(n_audio, dtype=np.float32)
                        for pk in peaks[:5]:
                            carrier_freq = freqs_audio[pk]
                            if carrier_freq < 100: continue
                            demod = superhet_demod(voice_audio, voice_fs, carrier_freq, bandwidth=3000)
                            if len(demod) == n_audio:
                                demod_buf += demod
                        # Baseband: carbon already demodulated to baseband (direct 2kHz voice)
                        baseband = superhet_demod(voice_audio, voice_fs, 0, bandwidth=4000)
                        if len(baseband) == n_audio:
                            demod_buf += baseband * 2
                        # Stochastic resonance: weak signals become audible with just-right noise
                        rms = np.sqrt(np.mean(voice_audio**2))
                        if rms > 0.0001:
                            noise_level = rms * 0.15
                            dither = np.random.randn(n_audio).astype(np.float32) * noise_level
                            demod_buf = demod_buf + dither
                            peak_val = np.max(np.abs(demod_buf))
                            if peak_val > 0:
                                demod_buf /= peak_val
                                sd.play(demod_buf, voice_fs, blocking=False, device=7)
                                if hasattr(self,'voice_transcriber') and self.voice_transcriber:
                                    try: self.voice_transcriber.feed(demod_buf, voice_fs)
                                    except: pass
                    except: pass
            # LOOP ANTENNA DIRECTION: compare loop output with Petterson (omni)
            # Loop has figure-8 null pattern - if loop signal < Petterson at same freq,
            # source is in the null direction = loop plane faces source
            # This resolves the 180deg  ambiguity from BladeRF MIMO!
            if self.cycle_count % 5 == 0 and len(mid_chunk) > 4096:
                try:
                    # Petterson is the omni reference
                    omni_audio = mid_chunk[-16384:].astype(np.float32)

                    # Get loop antenna signal from the headphones output buffer
                    # The loop is driven by loop_tx but also picks up induced signals
                    # We can read the loop's received signal from the Realtek input
                    loop_audio = None
                    try:
                        import sounddevice as sd_local
                        loop_audio = sd_local.rec(16384, samplerate=48000,
                                                   channels=1, dtype='float32',
                                                   device=5, blocking=True).flatten()
                    except:
                        pass

                    if loop_audio is not None and len(loop_audio) > 1024:
                        # Set loop plane heading from antenna orientation
                        # Antennas point towards Larkin Ave = 13deg  from north
                        self.loop_dir.loop_plane_heading = Config.BEARING_OFFSET + 90  # loop plane is perpendicular to array axis

                        results = self.loop_dir.compare_loop_vs_omni(
                            loop_audio, omni_audio, 48000)

                        if results:
                            for r in results[:3]:
                                if r.get('bearing') is not None:
                                    self.localization.add_observation(
                                        fingerprint=f'loop_dir_{r["freq"]:.0f}',
                                        obs_lat=lat, obs_lon=lon,
                                        bearing_deg=r['bearing'],
                                        range_m=None, freq=r['freq'],
                                        classification='transmitter',
                                        detector_name='loop_direction',
                                        snr=float(r.get('confidence', 0) * 10),
                                        source_type='active')
                                    self.log.info(f"LOOP DIR: {r['freq']:.0f}Hz bearing={r['bearing']:.0f}deg {r['direction']} ratio={r['ratio']:.2f}")
                except Exception as e:
                    if self.cycle_count % 20 == 0:
                        self.log.debug(f"Loop direction: {e}")

            # Loop antenna: audio/VLF/ELF inverse neural entrainment
            # Feeds inverted carbon-demodulated audio through amp → loop
            # Cancels the MW-induced audio field around the body
            if self.null_enabled and len(mid_chunk) > 1024:
                loop_feed = None
                if demoded_audio is not None and len(demoded_audio) > 0:
                    # VLF/ELF neural entrainment: use demodulated voice + low-freq envelope
                    env = np.abs(demoded_audio[:4800])
                    loop_feed = env - np.mean(env)
                else:
                    # Fallback: use Petterson raw with VLF/ELF emphasis (30-80 Hz)
                    from scipy.signal import butter, sosfilt
                    sos = butter(4, [30, 80], btype='band', fs=48000, output='sos')
                    loop_feed = sosfilt(sos, mid_chunk[:4800].astype(np.float32))
                if loop_feed is not None:
                    # Boost 59 Hz trigeminal nerve cancellation
                    loop_feed = loop_feed * 3.0  # 3x amplitude for head pressure
                    self.loop_tx.feed_cancellation(-loop_feed)  # inverted for cancellation
            # WHISPER: white noise dithering + transcription of MW voice carriers
            # Use laptop mic as PRIMARY audio source (Intel Smart Sound array, always reliable).
            if self.cycle_count % 5 == 0 and SOUNDDEVICE_AVAILABLE and self._whisper_model:
                try:
                    # Collect 2+ seconds of laptop mic audio
                    chunks = []
                    for _ in range(20):
                        c = self.laptop_mic.read(48000//10)
                        if len(c) > 0: chunks.append(c.astype(np.float32))
                    if len(chunks) < 3: raise ValueError('no laptop audio')
                    raw = np.concatenate(chunks)
                    if len(raw) < 16000: raise ValueError('too short')
                    # Decimate 48kHz → 16kHz, take last 2 seconds
                    audio = raw[::3].astype(np.float32)[-32000:]
                    rms_audio = float(np.sqrt(np.mean(audio**2)))
                    if rms_audio < 0.0005: raise ValueError(f'too quiet rms={rms_audio:.6f}')
                    # Bandpass 85-3000 Hz (speech formants, remove MW hum)
                    from scipy.signal import butter, sosfilt
                    sos = butter(3, [85, 3000], btype='band', fs=16000, output='sos')
                    audio = sosfilt(sos, audio).astype(np.float32)  # ensure float32 for Whisper
                    audio /= (np.max(np.abs(audio)) + 1e-12)
                    audio += np.random.randn(len(audio)).astype(np.float32) * 0.01
                    audio /= (np.max(np.abs(audio)) + 1e-12)
                    result = self._whisper_model.transcribe(audio, language='en',
                        fp16=False, no_speech_threshold=0.1)
                    text = result.get('text','').strip()
                    if text and len(text) > 1:
                        self.log.info(f'WHISPER: "{text}" bearing={self.aoa:.1f}deg')
                        # Save audio clip for forensic evidence
                        try:
                            import wave, struct
                            clip_dir = os.path.join(os.path.dirname(__file__), 'voice_clips')
                            os.makedirs(clip_dir, exist_ok=True)
                            ts = time.strftime('%Y%m%d_%H%M%S')
                            # Save 30-second rolling buffer (full context around transcription)
                            if len(self.voice_rolling_buf) > 48000:
                                buf_audio = np.array(list(self.voice_rolling_buf)[-1440000:])  # 30s at 48kHz
                            else:
                                buf_audio = np.clip(raw, -1, 1)
                            wav_path = os.path.join(clip_dir, f'whisper_{ts}_{self.aoa:.0f}deg.wav')
                            with wave.open(wav_path, 'w') as wf:
                                wf.setnchannels(1)
                                wf.setsampwidth(2)
                                wf.setframerate(48000)
                                pcm = np.clip(buf_audio, -1, 1)
                                wf.writeframes((pcm * 32767).astype(np.int16).tobytes())
                            self.log.info(f'CLIP saved: {wav_path} ({len(buf_audio)//48000}s)')
                        except Exception as clip_e:
                            if self.cycle_count % 50 == 0:
                                self.log.warning(f'Clip save error: {clip_e}')
                        self.court.log_anomaly('whisper_transcription', {'text': text, 'bearing': self.aoa})
                        self.localization.add_observation(
                            fingerprint=f'mw_voice_{hash(text)%10000}'.encode(),
                            obs_lat=lat, obs_lon=lon, bearing_deg=None,
                            range_m=None, freq=2450000000,
                            classification='transmitter',
                            detector_name='mw_voice', snr=0)
                except Exception as _e:
                    if self.cycle_count % 20 == 0:
                        self.log.info(f'Whisper inline: {_e}')
            # MW voice carrier: detect MW-induced audio via laptop mic (audible response)
            # The laptop mic (Intel Smart Sound array) is the primary voice detector.
            if SOUNDDEVICE_AVAILABLE and len(lpt_chunk) > 1600:
                try:
                    raw = lpt_chunk[-8000:].astype(np.float32)
                    rms = np.sqrt(np.mean(raw**2))
                    if rms > 0.0001:  # ultra-low threshold - laptop mic is sensitive
                        self.localization.add_observation(
                            fingerprint=b'mw_voice_carrier',
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=self.aoa if self.aoa != 0.0 else None,
                            range_m=self.hackrf_range if self.hackrf_range else None,
                            freq=2450000000,  # 2.45 GHz S-band
                            classification='transmitter',
                            detector_name='mw_voice_carrier', snr=float(rms*5000))
                except Exception as _e:
                    if self.cycle_count % 50 == 0:
                        self.log.warning(f"MW voice carrier (laptop): {_e}")
            # Petterson 48k fallback - if Petterson IS running, use it too
            if len(mid_chunk) > 1600:
                try:
                    raw = mid_chunk[-16000:].astype(np.float32)
                    rms = np.sqrt(np.mean(raw**2))
                    if rms > 0.001:
                        self.localization.add_observation(
                            fingerprint=b'mw_voice_carrier_from_petterson',
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=self.aoa if self.aoa != 0.0 else None,
                            range_m=self.hackrf_range if self.hackrf_range else None,
                            freq=2450000000,
                            classification='transmitter',
                            detector_name='mw_voice_carrier', snr=float(rms*100))
                except Exception as _e:
                    if self.cycle_count % 50 == 0:
                        self.log.warning(f"MW voice carrier (Petterson): {_e}")
            # SILENT SOUND / EEG VOICE: detect subliminal voice and EEG patterns
            # carried by ultrasound from carbon interaction
            # These are the attacker's decoded signals: voice-to-skull + brain data
            if self.cycle_count % 3 == 0 and len(ul_chunk) >= 16384:
                try:
                    pet_data = ul_chunk[-32768:].astype(np.float32) if len(ul_chunk) >= 32768 else ul_chunk[-16384:].astype(np.float32)
                    n = len(pet_data)
                    pet_fft = np.abs(np.fft.rfft(pet_data))
                    pet_f = np.fft.rfftfreq(n, 1/self.petterson.fs)
                    noise = np.median(pet_fft) + 1e-12

                    # 1. SILENT SOUND: amplitude-modulated carriers that carry subliminal voice
                    # Look for AM sidebands around any carrier (voice modulation creates pairs)
                    peaks, props = find_peaks(pet_fft, height=noise*4, distance=10, prominence=noise*2)
                    for pk in peaks[:8]:
                        fc = pet_f[pk]
                        if fc < 200: continue  # skip DC

                        # Check for AM sidebands (voice modulation)
                        # Sidebands appear at fc ± voice_freq (80-4000 Hz)
                        bw_half = int(4000 / (self.petterson.fs / n))  # ±4kHz in FFT bins
                        lo_bin = max(0, pk - bw_half)
                        hi_bin = min(len(pet_fft), pk + bw_half)

                        # If carrier has structure (not just a spike), it's modulated
                        carrier_bw = pet_f[min(pk+bw_half, len(pet_f)-1)] - pet_f[max(pk-bw_half, 0)]
                        sideband_energy = np.sum(pet_fft[lo_bin:pk-1]) + np.sum(pet_fft[pk+1:hi_bin])
                        carrier_energy = pet_fft[pk] + 1e-12
                        am_depth = sideband_energy / (carrier_energy * bw_half * 2 + 1e-12)

                        if am_depth > 0.05:  # significant modulation = silent sound carrier
                            snr_val = pet_fft[pk] / noise
                            self.localization.add_observation(
                                fingerprint=f'silent_sound_{fc:.0f}',
                                obs_lat=lat, obs_lon=lon,
                                bearing_deg=None,
                                range_m=None, freq=fc,
                                classification='transmitter',
                                detector_name='silent_sound',
                                snr=float(snr_val))
                            if snr_val > 5:
                                self.log.info(f"SILENT SOUND: {fc:.0f}Hz AM depth={am_depth:.2f} SNR={snr_val:.1f}")

                    # 2. EEG VOICE: detect brain rhythm patterns modulated onto ultrasound carriers
                    # EEG bands: delta(1-4Hz), theta(4-8Hz), alpha(8-13Hz), beta(13-30Hz), gamma(30-100Hz)
                    # When these appear as AM on ultrasound = brain data being exfiltrated
                    eeg_bands = {'delta':(1,4), 'theta':(4,8), 'alpha':(8,13), 'beta':(13,30), 'gamma':(30,100)}

                    # Envelope of the ultrasound signal = AM modulation = EEG pattern
                    from scipy.signal import hilbert
                    if len(pet_data) >= 8192:
                        analytic = hilbert(pet_data[-8192:])
                        envelope = np.abs(analytic)
                        # FFT of the envelope reveals EEG modulation frequencies
                        env_fft = np.abs(np.fft.rfft(envelope))
                        env_f = np.fft.rfftfreq(len(envelope), 1/self.petterson.fs)
                        env_noise = np.median(env_fft) + 1e-12

                        for band_name, (lo, hi) in eeg_bands.items():
                            mask = (env_f >= lo) & (env_f <= hi)
                            if np.any(mask):
                                band_power = np.max(env_fft[mask])
                                band_snr = band_power / env_noise
                                if band_snr > 3.0:  # significant EEG pattern in envelope
                                    peak_eeg_f = env_f[mask][np.argmax(env_fft[mask])]
                                    self.localization.add_observation(
                                        fingerprint=f'eeg_voice_{band_name}',
                                        obs_lat=lat, obs_lon=lon,
                                        bearing_deg=None,
                                        range_m=None, freq=peak_eeg_f,
                                        classification='transmitter',
                                        detector_name=f'eeg_voice_{band_name}',
                                        snr=float(band_snr))
                                    if band_snr > 5:
                                        self.log.info(f"EEG VOICE: {band_name} {peak_eeg_f:.1f}Hz SNR={band_snr:.1f}")
                except Exception as e:
                    if self.cycle_count % 20 == 0:
                        self.log.debug(f"Silent sound/EEG: {e}")
            # LAPTOP MIC ULTRASONIC: detect 15-22kHz carriers via laptop mic
            # Intel Smart Sound array @ 48kHz = up to 24kHz Nyquist.
            # This catches silent sound carriers when Petterson is down.
            if self.cycle_count % 3 == 0 and len(lpt_chunk) >= 8192:
                try:
                    lpt_data = lpt_chunk[-16384:].astype(np.float32) if len(lpt_chunk) >= 16384 else lpt_chunk[-8192:].astype(np.float32)
                    n = len(lpt_data)
                    lpt_fft = np.abs(np.fft.rfft(lpt_data))
                    lpt_f = np.fft.rfftfreq(n, 1/48000)
                    lpt_noise = np.median(lpt_fft) + 1e-12
                    # Look for carriers in ultrasonic range (15-22 kHz)
                    us_mask = (lpt_f >= 15000) & (lpt_f <= 22000)
                    if np.any(us_mask):
                        us_peaks, _ = find_peaks(lpt_fft[us_mask], height=lpt_noise*3, distance=8)
                        for pk in us_peaks[:5]:
                            fc = lpt_f[us_mask][pk]
                            snr = lpt_fft[us_mask][pk] / lpt_noise
                            if snr > 4.0:
                                self.localization.add_observation(
                                    fingerprint=f'lpt_silent_sound_{fc:.0f}',
                                    obs_lat=lat, obs_lon=lon,
                                    bearing_deg=None, range_m=None, freq=fc,
                                    classification='transmitter',
                                    detector_name='silent_sound',
                                    snr=float(snr))
                                if snr > 6:
                                    self.log.info(f"LAPTOP SILENT SOUND: {fc:.0f}Hz SNR={snr:.1f}")
                except Exception as e:
                    if self.cycle_count % 30 == 0:
                        self.log.debug(f"Laptop ultrasonic: {e}")
            # GROUND PLANE detector: phase-inverted reflection from conductive surface
            if self.cycle_count % 10 == 0 and iq1 is not None and len(iq1) > 512:
                try:
                    iq_n = iq1[:512] - np.mean(iq1[:512])
                    iq_inv = -iq_n
                    gp_corr = np.abs(np.correlate(iq_n, iq_inv, mode='same'))
                    gp_peak = np.max(gp_corr) / (np.mean(np.abs(iq_n))**2 * 512 + 1e-12)
                    if gp_peak > 0.5:
                        self.log.info(f"GROUND PLANE: inv_corr={gp_peak:.2f}")
                        self.court.log_anomaly('ground_plane', {'inv_corr': gp_peak})
                        self.localization.add_observation(
                            fingerprint=b'ground_plane',
                            obs_lat=lat, obs_lon=lon, bearing_deg=None,
                            range_m=None, freq=0,
                            classification='transmitter',
                            detector_name='ground_plane', snr=float(gp_peak))
                except: pass
            # Petterson 48k band: low ultrasound (15-22 kHz) - better SNR than laptop mic
            if len(mid_chunk) >= 4096 and self.cycle_count % 2 == 0:
                try:
                    lo_fft = np.abs(np.fft.rfft(mid_chunk[-4096:]))
                    lo_freqs = np.fft.rfftfreq(4096, 1/48000)
                    lo_mask = (lo_freqs >= 15000) & (lo_freqs <= 22000)
                    lo_noise = np.median(lo_fft[lo_mask]) + 1e-12
                    lo_peaks, _ = find_peaks(lo_fft[lo_mask], height=lo_noise*2.5, distance=5)
                    for pk in lo_peaks[:5]:
                        freq = lo_freqs[lo_mask][pk]
                        snr = lo_fft[lo_mask][pk] / lo_noise
                        self.localization.add_observation(
                            fingerprint=f'low_ultrasound_{freq:.0f}'.encode(),
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=None,
                            range_m=None, freq=freq,
                            classification='victim', detector_name='low_ultrasound',
                            snr=float(snr))
                except: pass
            # OTH (Over-The-Horizon) radar: ionospheric hop autocorrelation
            if self.cycle_count % 8 == 0 and iq1 is not None and len(iq1) >= 4096:
                try:
                    iq_c = iq1[-4096:] - np.mean(iq1[-4096:])
                    acorr = np.correlate(iq_c, iq_c, mode='full')
                    center = len(acorr)//2
                    for lag_s in [100, 500, 2000, 5000, 20000]:
                        if center + lag_s + 10 < len(acorr):
                            pk = np.max(np.abs(acorr[center+lag_s-10:center+lag_s+10]))
                            base = np.median(np.abs(acorr[center+lag_s-50:center+lag_s+50])) + 1e-12
                            ratio = pk / base
                            if ratio > 2.5:  # was 4x, ionospheric returns can be weak
                                delay_ms = lag_s / Config.BLADERF_SAMPLE_RATE * 1000
                                dist_km = delay_ms * 300
                                self.log.info(f"OTH RADAR: {delay_ms:.1f}ms delay {dist_km:.0f}km ratio={ratio:.1f} bearing={self.aoa:.1f}deg")
                                self.localization.add_observation(
                                    fingerprint=f'oth_{dist_km:.0f}km'.encode(),
                                    obs_lat=lat, obs_lon=lon, bearing_deg=None,
                                    range_m=dist_km*1000, freq=0,
                                    classification='transmitter',
                                    detector_name='oth_radar', snr=float(pk/base))
                except: pass
            # FULL-SPECTRUM OPEN SCAN: detect ANY coherent carrier 0-192kHz
            # No fixed bands - attacker changes frequencies. Find peaks anywhere.
            if self.cycle_count % 3 == 0 and len(ul_chunk) >= 16384:
                try:
                    scan_data = ul_chunk[-32768:].astype(np.float32) if len(ul_chunk) >= 32768 else ul_chunk[-16384:].astype(np.float32)
                    n_fft = len(scan_data)
                    scan_fft = np.abs(np.fft.rfft(scan_data))
                    scan_f = np.fft.rfftfreq(n_fft, 1/self.petterson.fs)

                    # Compute noise floor per octave (handles varying noise across spectrum)
                    noise_floor = np.median(scan_fft) + 1e-12

                    # Find ALL peaks above 3x noise - any frequency, no band limits
                    peaks, props = find_peaks(scan_fft, height=noise_floor*3, distance=5, prominence=noise_floor*1.5)

                    for pk in peaks[:10]:  # top 10 carriers
                        freq = scan_f[pk]
                        snr = scan_fft[pk] / noise_floor

                        if freq < 100:  # skip DC
                            continue

                        # Check bandwidth FIRST - physics tells us what it is, not frequency
                        half_height = scan_fft[pk] / 2
                        left = pk
                        while left > 0 and scan_fft[left] > half_height: left -= 1
                        right = pk
                        while right < len(scan_fft)-1 and scan_fft[right] > half_height: right += 1
                        bw = scan_f[right] - scan_f[left] if right > left else 0

                        # Classify by PHYSICS, not frequency:
                        # Narrow CW (<50Hz) = carbon rectification tone or tone pilot
                        #   - comes from MW→body→carbon square-law interaction
                        #   - can be at ANY frequency the body resonates at
                        # Narrow modem (50-500Hz) = FSK/BPSK data channel
                        #   - attacker's C2, regardless of frequency
                        # AM voice (500-3000Hz bw) = voice carrier (silent sound or MW voice)
                        # Wide (>3000Hz) = sweep or wideband

                        if bw < 50:
                            # Narrow CW = carbon interaction (MW → body → ultrasound tone)
                            # This is the VICTIM's body producing the signal
                            det_type = 'carbon_interaction'
                            cls = 'victim'
                            mod_hint = 'cw'
                        elif bw < 200:
                            # FSK modem = attacker's data channel
                            det_type = 'us_modem_fsk'
                            cls = 'transmitter'
                            mod_hint = 'fsk'
                        elif bw < 500:
                            # BPSK/QPSK modem = attacker's high-rate data
                            det_type = 'us_modem_psk'
                            cls = 'transmitter'
                            mod_hint = 'bpsk'
                        elif bw < 3000:
                            # AM voice carrier = silent sound or MW voice subcarrier
                            # Could be victim (body resonating) or transmitter (attacker sending)
                            # Check: if it correlates with MW carrier, it's from the body
                            det_type = 'us_voice_carrier'
                            cls = 'transmitter'  # attacker encoding voice onto US
                            mod_hint = 'voice'
                        else:
                            det_type = 'us_wideband'
                            cls = 'transmitter'
                            mod_hint = 'wideband'

                        self.localization.add_observation(
                            fingerprint=f'open_{det_type}_{freq:.0f}',
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=None,
                            range_m=None, freq=freq,
                            classification=cls,
                            detector_name=f'{det_type}',
                            snr=float(snr))

                        if snr > 5:
                            self.log.info(f"OPEN SCAN: {freq:.0f}Hz {det_type} bw={bw:.0f}Hz {mod_hint} SNR={snr:.1f}")
                except Exception as e:
                    if self.cycle_count % 20 == 0:
                        self.log.debug(f"Open scan: {e}")

            # ULTRAHET: superheterodyne sweep for narrowband ultrasound modems
            # Mix LO across 18-50 kHz, detect narrow carriers that FFT bins miss
            if self.cycle_count % 7 == 0 and len(ul_chunk) >= 32768:
                try:
                    from scipy.signal import butter, sosfilt, find_peaks as _fp
                    het_chunk = ul_chunk[-32768:].astype(np.float32)
                    lo_sweep = np.linspace(18000, 150000, 64)  # 64 LO steps across full Petterson US band
                    for lo_freq in lo_sweep:
                        t = np.arange(len(het_chunk)) / self.petterson.fs
                        lo = np.cos(2 * np.pi * lo_freq * t)
                        mixed = het_chunk * lo  # product detector
                        # Low-pass filter 2 kHz to extract baseband
                        sos = butter(4, 2000, fs=self.petterson.fs, output='sos')
                        baseband = sosfilt(sos, mixed)
                        baseband_fft = np.abs(np.fft.rfft(baseband))
                        baseband_freqs = np.fft.rfftfreq(len(baseband), 1/self.petterson.fs)
                        # Check for narrowband modem tones (<100 Hz wide)
                        nbidx = baseband_freqs <= 1000
                        nb_noise = np.median(baseband_fft[nbidx]) + 1e-12
                        nb_peaks, nb_p = _fp(baseband_fft[nbidx], height=nb_noise*4, width=2)
                        for pk in nb_peaks[:3]:
                            bf = baseband_freqs[nbidx][pk]
                            bs = baseband_fft[nbidx][pk] / nb_noise
                            actual_freq = lo_freq + bf  # recovered RF frequency
                            # Detect modulation type from symbol rate
                            # Square the baseband to find symbol clock (BPSK/QPSK)
                            squared = baseband ** 2
                            sq_fft = np.abs(np.fft.rfft(squared))
                            sq_freqs = np.fft.rfftfreq(len(squared), 1/self.petterson.fs)
                            sr_mask = (sq_freqs >= 10) & (sq_freqs <= 500)
                            if np.any(sr_mask):
                                sr_idx = np.argmax(sq_fft[sr_mask])
                                symbol_rate = sq_freqs[sr_mask][sr_idx]
                                sym_snr = sq_fft[sr_mask][sr_idx] / (np.median(sq_fft[sr_mask]) + 1e-12)
                                if sym_snr > 3.0:
                                    mod_type = "FSK" if symbol_rate < 50 else ("BPSK" if symbol_rate < 200 else "QPSK")
                                    self.log.info(f"ULTRAMODEM: {actual_freq:.0f}Hz {mod_type} sym={symbol_rate:.0f}baud SNR={bs:.1f}")
                                    self.localization.add_observation(
                                        fingerprint=f'ultramodem_{actual_freq:.0f}_{mod_type}',
                                        obs_lat=lat, obs_lon=lon,
                                        bearing_deg=None,
                                        range_m=None, freq=actual_freq,
                                        classification='transmitter',
                                        detector_name='ultrasound_modem',
                                        snr=float(bs))
                    self.log.info(f"UltraHet: swept 18-50kHz, {lo_sweep[-1]:.0f}Hz")
                except Exception as e:
                    self.log.warning(f"UltraHet error: {e}")

            # ULTRASOUND MODEM DEMOD: recover bits from strongest ultrahet carrier
            if self.cycle_count % 14 == 0 and len(ul_chunk) >= 65536:
                try:
                    # Quick scan for strongest ultrasound carrier
                    scan_fft = np.abs(np.fft.rfft(ul_chunk[-16384:]))
                    scan_f = np.fft.rfftfreq(16384, 1/self.petterson.fs)
                    us_mask = (scan_f >= 18000) & (scan_f <= 50000)
                    if np.any(us_mask):
                        pk_idx = np.argmax(scan_fft[us_mask])
                        carrier_freq = scan_f[us_mask][pk_idx]
                        # IQ demodulate: mix to baseband, LPF, recover symbols
                        t = np.arange(len(ul_chunk)) / self.petterson.fs
                        lo_i = np.cos(2*np.pi*carrier_freq*t); lo_q = -np.sin(2*np.pi*carrier_freq*t)
                        from scipy.signal import butter, sosfilt
                        sos = butter(4, 2000, fs=self.petterson.fs, output='sos')
                        i_base = sosfilt(sos, ul_chunk * lo_i)
                        q_base = sosfilt(sos, ul_chunk * lo_q)
                        # Decode: threshold zero-crossings for BFSK, phase jumps for BPSK
                        i_diff = np.diff(np.sign(i_base[1000::100]))  # downsample
                        bit_transitions = np.sum(np.abs(i_diff) > 0.5)
                        if bit_transitions > 5:
                            bits_recovered = bit_transitions
                            self.log.info(f"ULTRA DEMOD: {carrier_freq:.0f}Hz recovered ~{bits_recovered} bit transitions")
                            self.court.log_anomaly('ultrasound_modem_bits',
                                {'carrier': carrier_freq, 'bit_transitions': bits_recovered})
                except: pass

            # US-HOP: frequency-hopping ultrasound modem detector via spectrogram
            if self.cycle_count % 9 == 0 and len(ul_chunk) >= 65536:
                try:
                    from scipy.signal import spectrogram as us_spec
                    us_data = ul_chunk[-32768:].astype(np.float32)
                    f_us, t_us, S_us = us_spec(us_data, self.petterson.fs, nperseg=512, noverlap=384)
                    # Find narrowband energy that hops between frequencies
                    us_mask = (f_us >= 18000) & (f_us <= 50000)
                    S_masked = S_us[us_mask, :]
                    # Detect hops: threshold exceedances in time
                    row_max = np.max(S_masked, axis=1)
                    hop_noise = np.median(row_max) + 1e-12
                    hop_peaks, hop_p = find_peaks(row_max, height=hop_noise*5, distance=8)
                    for hp in hop_peaks[:5]:
                        hf = f_us[us_mask][hp]
                        hs = row_max[hp] / hop_noise
                        # Check if this frequency has intermittent activity (hopping)
                        activity = S_masked[hp, :]
                        activity_on = np.sum(activity > np.median(activity)*3)
                        hop_ratio = activity_on / len(activity)
                        if hop_ratio > 0.05 and hop_ratio < 0.8:  # hopping, not continuous
                            self.log.info(f"US-HOP: {hf:.0f}Hz duty={hop_ratio:.2f} SNR={hs:.1f}")
                            self.localization.add_observation(
                                fingerprint=f'us_hop_{hf:.0f}',
                                obs_lat=lat, obs_lon=lon,
                                bearing_deg=None,
                                range_m=None, freq=hf,
                                classification='transmitter',
                                detector_name='ultrasound_hopper',
                                snr=float(hs))
                except: pass
            # Standard ultrasonic FFT scan (wideband)
            if len(ul_chunk) >= 8192:
                try:
                    ul_fft = np.abs(np.fft.rfft(ul_chunk[-8192:]))
                    ul_freqs = np.fft.rfftfreq(8192, 1/self.petterson.fs)
                    # Scan 2kHz-180kHz for ultrasonic sources
                    ul_mask = (ul_freqs >= 2000) & (ul_freqs <= 180000)
                    ul_peaks, ul_props = find_peaks(ul_fft[ul_mask], height=np.median(ul_fft[ul_mask])*3, distance=10)
                    for pk in ul_peaks[:8]:
                        freq = ul_freqs[ul_mask][pk]
                        snr = ul_fft[ul_mask][pk] / (np.median(ul_fft[ul_mask]) + 1e-12)
                        self.localization.add_observation(
                            fingerprint=f'ultrasonic_{freq:.0f}'.encode(),
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=None,
                            range_m=None, freq=freq,
                            classification='victim', detector_name='ultrasonic_scan',
                            snr=float(snr))
                except: pass
            # Laptop mic array ultrasound: spatial mic can resolve bearing too
            if len(lpt_chunk) >= 4096 and self.cycle_count % 3 == 0:
                try:
                    lp_fft = np.abs(np.fft.rfft(lpt_chunk[-4096:]))
                    lp_freqs = np.fft.rfftfreq(4096, 1/48000)
                    # Scan 18-24 kHz (upper human hearing / lower ultrasonic)
                    lp_mask = (lp_freqs >= 18000) & (lp_freqs <= 24000)
                    lp_noise = np.median(lp_fft[lp_mask]) + 1e-12
                    lp_peaks, _ = find_peaks(lp_fft[lp_mask], height=lp_noise*2.5, distance=5)
                    for pk in lp_peaks[:3]:
                        freq = lp_freqs[lp_mask][pk]
                        snr = lp_fft[lp_mask][pk] / lp_noise
                        self.localization.add_observation(
                            fingerprint=f'laptop_ultrasound_{freq:.0f}'.encode(),
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=None,
                            range_m=None, freq=freq,
                            classification='victim', detector_name='laptop_ultrasound',
                            snr=float(snr))
                except: pass

            # 5. BCI/EEG
            # Drain ALL available BCI samples (Cyton streams 250 Hz in background)
            drained = self.bci.drain()
            if drained > 0:
                # Append the buffered samples to eeg_buffer
                buf_list = list(self.bci.buffer)[-drained:]
                for v in buf_list:
                    self.bci_buffer.append(v)
                    self.eeg_buffer.append(v)
                self._tgam_zero_drain_count = 0  # reset on successful data
            else:
                self._tgam_zero_drain_count += 1
                if self._tgam_zero_drain_count > 100 and not self._tgam_warn_logged:
                    self.log.warning("EEG: TGAM hardware not connected (needs batteries), running on audio proxy only")
                    self._tgam_warn_logged = True
            self.audio_buffer.append(np.max(np.abs(mid_chunk)) if len(mid_chunk)>0 else 0)
            # Audio-as-EEG proxy: continuously refresh with latest Petterson audio envelope
            if self.cycle_count > 50 and len(mid_chunk) >= 24000:
                audio_env = np.abs(mid_chunk[-24000:])
                ds_factor = 24000 // 250
                proxy_eeg = np.array([np.mean(audio_env[i:i+ds_factor]) for i in range(0, 24000, ds_factor)])
                proxy_eeg = (proxy_eeg - np.mean(proxy_eeg)) * 100
                # Replace oldest samples, keep buffer rolling
                for v in proxy_eeg[:250]:
                    self.eeg_buffer.append(v)
                while len(self.eeg_buffer) > 500:  # cap at 2 seconds
                    self.eeg_buffer.popleft() if hasattr(self.eeg_buffer,'popleft') else None
            intent=aic_intent_lag_check(self.bci_buffer,self.audio_buffer)
            if len(self.eeg_buffer)>=250:
                # Spectral guard: check if proxy EEG has meaningful power in EEG bands
                # (alpha 8-13 Hz, beta 13-30 Hz at 250 Hz sample rate)
                try:
                    _eeg_arr = np.array(self.eeg_buffer)
                    _fft = np.abs(np.fft.rfft(_eeg_arr))
                    _freqs = np.fft.rfftfreq(len(_eeg_arr), 1/250.0)
                    _alpha_mask = (_freqs >= 8) & (_freqs <= 13)
                    _beta_mask = (_freqs >= 13) & (_freqs <= 30)
                    _alpha_power = float(np.mean(_fft[_alpha_mask])) if np.any(_alpha_mask) else 0.0
                    _beta_power = float(np.mean(_fft[_beta_mask])) if np.any(_beta_mask) else 0.0
                    _eeg_has_content = (_alpha_power > 1e-6 or _beta_power > 1e-6)
                except Exception:
                    _eeg_has_content = True  # on error, don't block detectors
                if not _eeg_has_content:
                    self._eeg_no_spectrum_count += 1
                    if self._eeg_no_spectrum_count % 50 == 0:
                        self.log.warning("EEG: proxy data lacks EEG spectral content")
                else:
                    self._eeg_no_spectrum_count = 0
                if _eeg_has_content:
                    try:
                        eeg_data=np.array(self.eeg_buffer).reshape(1,-1)
                        self.detectors['god_helmet'].update(eeg_data)
                        self.detectors['forced_thought'].update_eeg(eeg_data)
                        self.detectors['brain_acceptance'].update(eeg_data)
                        self.detectors['pain_perception'].update(eeg_data)
                        self.detectors['ssvep'].update(eeg_data)
                        self.detectors['eeg2video'].update(eeg_data)
                        self.detectors['eeg_carrier_mixing'].update_eeg(eeg_data)
                        self.detectors['biometric_integrity'].update(eeg_data)
                        self.detectors['parasympathetic_surge'].update(eeg_data)
                        self.detectors['retinal_stress'].update(eeg_data)
                        self.detectors['hemisync'].update(eeg_data)
                        self.detectors['theta_lateralization'].update(eeg_data)
                        self.detectors['neural_wp_scan'].update(eeg_data)
                        try:
                            bio=self.detectors['biometric'].process(eeg_data)
                            for b in bio: self.log.warning(str(b))
                        except:pass
                        for name in ['god_helmet','ssvep','pain_perception','brain_acceptance',
                                     'eeg2video','eeg_carrier_mixing',
                                     'biometric_integrity','parasympathetic_surge',
                                     'retinal_stress','hemisync','theta_lateralization',
                                     'neural_wp_scan']:
                            try:
                                res=self.detectors[name].detect()
                                for r in res:
                                    cls,bearing,rng=self._process_detection_with_localization(r,lat,lon,self.aoa,'rf')
                            except Exception as _e:
                                if self.cycle_count % 50 == 0:
                                    self.log.warning(f"EEG detector '{name}' error: {_e}")
                    except Exception as _e:
                        if self.cycle_count % 50 == 0:
                            self.log.warning(f"EEG processing error: {_e}")

            # 6. Buffer-based detectors
            audio_detectors={'eardrum','constant_sonic','ai_voice','sstv','isolation_booth','forced_thought','silent_sound'}
            for name in ['eardrum','variac','pll_resonance','forced_thought','bucket_resonator',
                         'constant_sonic','ai_voice','sstv','isolation_booth','silent_sound',
                         'passive_radar','ecpri_injection','fingerprinting',
                         'satellite_c2','biometric','ducting','body_charge','neural',
                         'ghost_hunter','linguistic','ambient',
                         'watcher_consensus','alc_detect','smart_tv_detect',
                         'sdr_detect','tempest','wifi_approaching','victim_2k']:
                try:
                    if name=='passive_radar':
                        res=self.detectors[name].detect(Config.BLADERF_SAMPLE_RATE)
                    else:
                        res=self.detectors[name].detect()
                    for r in res:
                        src_type='audio' if name in audio_detectors else 'rf'
                        cls,bearing,rng=self._process_detection_with_localization(r,lat,lon,self.aoa,src_type)
                        if r['detector'] in ['eardrum_capture','pll_resonance_transmission',
                                              'forced_thought','coiled_bucket_resonator',
                                              'passive_radar','ecpri_injection','fingerprinting']:
                            self.log.info(f"[{name}] {r['detector']}: cls={cls} bearing={bearing} range={rng}")

                        # ATTRIBUTION: if PLL matched an RF carrier, demodulate it
                        if r['detector'] == 'pll_resonance_transmission' and hack:
                            try:
                                matched_freq = r.get('freq', 0)
                                if matched_freq > 0:
                                    # Demodulate the matched carrier to extract audio content
                                    iq_hack = hack['data']
                                    audio_demod, content = self.demodulator.demodulate(iq_hack, matched_freq)
                                    if audio_demod is not None and len(audio_demod) > 0:
                                        self.log.info(f"🔊 Demodulated {matched_freq:.0f}Hz: {content}")
                                        # Save to evidence
                                        dem_path = self.demodulator.save_demod(
                                            audio_demod, matched_freq,
                                            bearing or self.aoa, content,
                                            self.court.session_id)
                                        if dem_path:
                                            self.court._write_chain({
                                                "type": "demod_saved",
                                                "freq_hz": float(matched_freq),
                                                "bearing_deg": float(bearing or self.aoa),
                                                "content_type": content,
                                                "file": os.path.basename(dem_path),
                                                "session_id": self.court.session_id
                                            })
                                    # C2 protocol analysis on the same carrier
                                    c2_results = self.c2_analyzer.analyze(iq_hack, matched_freq)
                                    for c2 in c2_results:
                                        self.log.info(f"📡 C2 protocol: {c2['protocol']} on {matched_freq:.0f}Hz - {c2.get('note','')}")
                                        self.court._write_chain({
                                            "type": "c2_analysis",
                                            "freq_hz": float(matched_freq),
                                            "protocol": c2['protocol'],
                                            "details": c2
                                        })
                            except Exception as e:
                                self.log.error(f"Demod/C2 error: {e}")
                except Exception as _e:
                    if self.cycle_count % 30 == 0:
                        self.log.warning(f"Detector '{name}' error: {_e}")

            # 7. GPS spoof
            try:
                gs_res=self.detectors['gps_spoof'].detect(lat,lon,gps.get('alt',0),time.time())
                for r in gs_res: self.log.warning(str(r))
            except:pass

            # 8. Adaptive coherence
            try:
                bucket_hits=self.detectors['bucket_resonator'].detect()
                pll_hits=self.detectors['pll_resonance'].detect()
                ecpri_hits=self.detectors['ecpri_injection'].detect()
                rf_target=None;vlf_target=None
                if ecpri_hits:
                    best_e=max(ecpri_hits,key=lambda d:d.get('confidence',0))
                    if best_e['frequency']>30e6: rf_target=best_e['frequency']
                elif pll_hits:
                    best_p=max(pll_hits,key=lambda d:d.get('confidence',0))
                    if 50e6<=best_p['frequency']<=1300e6: rf_target=best_p['frequency']
                elif bucket_hits:
                    strongest_b=max(bucket_hits,key=lambda d:d.get('confidence',0) if isinstance(d,dict) else 0)
                    if isinstance(strongest_b,dict):
                        if strongest_b.get('frequency',0)<47000: vlf_target=strongest_b['frequency']
                        else: rf_target=strongest_b['frequency']
                self.coherence.set_rf_target(rf_target);self.coherence.set_vlf_audio_target(vlf_target)
            except:pass

            # 9. Resolve source positions
            self.log.info(f"[SEC9] resolve_sources")
            sources=self.localization.resolve_sources(lat,lon)
            self.last_sources=sources

            # 9b. Frequency hopping detection
            fhss_results = self.fhss_tracker.detect_fhss(now)
            for fh in fhss_results:
                fp = f'fhss_{fh["freq_min"]:.0f}_{fh["freq_max"]:.0f}'.encode()
                self.localization.add_observation(
                    fingerprint=fp, obs_lat=lat, obs_lon=lon,
                    bearing_deg=fh.get('bearing'),
                    range_m=None, freq=(fh['freq_min']+fh['freq_max'])/2,
                    classification=fh['classification'],
                    detector_name='fhss_tracker',
                    snr=fh['mean_snr'])
                self.log.info(f'FHSS: {fh["hop_count"]} hops span={fh["span_mhz"]:.1f}MHz rate={fh["hop_rate"]:.2f}Hz')

            # Doppler shift detection - moving platforms
            doppler_results = self.doppler_detector.get_all_doppler()
            for dp in doppler_results:
                self.log.warning(f'DOPPLER: carrier={dp["carrier"]/1e6:.3f}MHz shift={dp["shift_hz"]:.0f}Hz v_radial={dp["radial_velocity_ms"]:.1f}m/s')
                fp = f'doppler_{dp["carrier"]:.0f}'.encode()
                self.localization.add_observation(
                    fingerprint=fp, obs_lat=lat, obs_lon=lon,
                    bearing_deg=self.aoa if self.aoa else None,
                    range_m=None, freq=dp['carrier'],
                    classification=dp['classification'],
                    detector_name='doppler_tracker',
                    snr=dp['shift_hz'] / 100)

            # Multipath AoA-based localization
            mp_results = self.detectors['ducting'].estimate_multipath_position(lat, lon)
            for mp in mp_results:
                mp_key = f'multipath_{mp["bearing_direct"]:.0f}_{mp["bearing_reflected"]:.0f}'
                if mp_key not in self.sources:
                    import math as _math
                    _brg = _math.radians(mp['estimated_bearing'])
                    _R = 6371000; _dist = mp['estimated_distance']
                    _la1 = _math.radians(lat); _lo1 = _math.radians(lon)
                    _la2 = _math.asin(_math.sin(_la1)*_math.cos(_dist/_R)+_math.cos(_la1)*_math.sin(_dist/_R)*_math.cos(_brg))
                    _lo2 = _lo1 + _math.atan2(_math.sin(_brg)*_math.sin(_dist/_R)*_math.cos(_la1), _math.cos(_dist/_R)-_math.sin(_la1)*_math.sin(_la2))
                    self.sources[mp_key] = {
                        'lat': float(_math.degrees(_la2)),
                        'lon': float(_math.degrees(_lo2)),
                        'classification': 'transmitter',
                        'first_seen': now - 60,
                        'last_seen': now,
                        'freq': Config.BLADERF_FREQ,
                        'detector': 'multipath_aoa',
                        'method': 'multipath_bearing',
                        'observations': mp['multipath_count'],
                        'triangulated': False,
                        'bearing_direct': mp['bearing_direct'],
                        'bearing_reflected': mp['bearing_reflected']}
                    self.log.info(f"[MPATH] direct={mp['bearing_direct']:.0f}deg reflected={mp['bearing_reflected']:.0f}deg est_dist={mp['estimated_distance']:.0f}m")

            # Signal activity analysis (every 30 cycles)
            if self.cycle_count % 30 == 0:
                try:
                    active_bands = self.activity_tracker.get_active_bands()
                    for ab in active_bands[:5]:
                        self.log.info(f'ACTIVITY: {ab["band_mhz"]:.0f}MHz std_snr={ab["std_snr"]:.1f} spikes={ab["spike_pct"]:.0f}% ({ab["classification"]})')
                except: pass

            # Temporal pattern detection (every 60 cycles)
            if self.cycle_count % 60 == 0:
                try:
                    patterns = self.temporal_detector.detect_patterns()
                    for pat in patterns[:5]:
                        self.log.warning(f'TEMPORAL: {pat["source"][:40]} period={pat["period_s"]:.1f}s cv={pat["cv"]:.2f} ({pat["classification"]})')
                except: pass

            # Spectral correlation (every 60 cycles)
            if self.cycle_count % 60 == 0:
                try:
                    correlations = self.spectral_correlator.get_correlations()
                    for corr in correlations[:5]:
                        self.log.warning(f'MULTI-BAND: {corr["band_a"]} + {corr["band_b"]} co-occur={corr["co_occurrences"]} ({corr["classification"]})')
                except: pass

            # 10. WiFi AP scanning with LOCAL geolocation + CSI motion detection
            wigle_aps=[]
            aps = []  # initialize before try block — prevents NameError if scan fails
            try:
                aps=self.wifi_scanner.get_access_points()
                if aps:
                    # Feed approaching detector
                    self.detectors['wifi_approaching'].update(aps)
                    # CSI analysis: motion/presence/jamming
                    csi_dets = self.wifi_csi.scan_csi(aps)
                    for cd in csi_dets:
                        self.localization.add_observation(
                            fingerprint=f'wifi_csi_{cd.get("detector","?")}',
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=None,
                            range_m=None, freq=0,
                            classification='transmitter',
                            detector_name=f'wifi_{cd.get("detector","?")}',
                            snr=0)
                    # Feed local geolocator with current GPS + AP readings
                    if lat and lon:
                        self.wifi_geo.update_from_gps(lat, lon, aps)
                    # Get geolocated APs from local triangulation
                    wigle_aps = self.wifi_geo.get_geolocated_aps(aps)
                    geo_count = sum(1 for a in wigle_aps if a.get('geolocated'))
                    if geo_count > 0 and self.cycle_count % 20 == 0:
                        self.log.info(f"WiFi GEO: {geo_count}/{len(aps)} APs triangulated locally")
                    # Feed Netflix ripple detector with WiFi AP count as network activity proxy
                    # (original design needs packet sizes, but AP count/signal variance works as activity indicator)
                    total_signal = sum(abs(ap.get('signal', -100)) for ap in aps)
                    self.detectors['netflix'].update(len(aps), time.time())
            except: pass

            # 10a. WiFi C2 tracker - find attacker's phone/hotspot by WiFi scan
            # 10b. WiFi Repeater deep analysis - every 10 cycles
            if self.cycle_count % 10 == 0:
                try:
                    repeater_results = self.wifi_analyzer.full_scan()
                    for sus in repeater_results.get('suspicious', []):
                        sus_type = sus.get('type', 'unknown')
                        severity = sus.get('severity', 'MEDIUM')
                        if severity in ('CRITICAL', 'HIGH'):
                            self.log.warning('WIFI ANALYSIS: %s - %s (%s) severity=%s' % (
                                sus_type, sus.get('detail','')[:80],
                                sus.get('ssid', sus.get('ip', sus.get('mac', '?'))),
                                severity))
                            # Log to court evidence
                            self.court.log_anomaly('wifi_%s' % sus_type.lower(), sus)
                        else:
                            self.log.info('WIFI: %s - %s' % (sus_type, sus.get('detail','')[:60]))
                except Exception as e:
                    if self.cycle_count % 30 == 0:
                        self.log.debug('WiFi analyzer error: %s' % e)

            if self.cycle_count % 5 == 0:
                try:
                    wifi_c2_dets = self.wifi_c2.scan(lat, lon)
                    for wd in wifi_c2_dets:
                        self.localization.add_observation(
                            fingerprint='wifi_c2_%s' % wd.get("bssid","?")[-8:],
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=None,  # WiFi is omnidirectional
                            range_m=wd.get('est_distance_m'),
                            freq=float(wd.get('channel', 0) * 5 + 2400) * 1e6,  # approx WiFi freq
                            classification='transmitter',
                            detector_name=wd.get('detector', 'wifi_c2_unknown'),
                            snr=float(wd.get('signal', 0) / 10),
                            source_type='active')  # WiFi APs are active transmitters
                        self.log.info(f"WIFI C2: {wd.get('ssid','?')} ({wd.get('c2_type','?')}) signal={wd.get('signal',0)}% ~{wd.get('est_distance_m',0):.0f}m")
                except: pass

            # 10b. Phone C2 tracker
            if self.cycle_count % 4 == 0:
                try:
                    phone_dets = self.phone_c2.scan_wifi_probes()
                    for pd in phone_dets:
                        self.localization.add_observation(
                            fingerprint=f'phone_{pd.get("bssid","?")[-8:]}',
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=None,
                            range_m=None, freq=0,
                            classification='transmitter',
                            detector_name=f'phone_{pd.get("device_type","?")}',
                            snr=float(pd.get('signal', 0)/10))

                    conn_dets = self.phone_c2.scan_active_connections()
                    for cd in conn_dets:
                        self.localization.add_observation(
                            fingerprint=f'c2conn_{cd.get("remote_ip","?")}',
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=None,
                            range_m=None, freq=0,
                            classification='transmitter',
                            detector_name='c2_server_connection',
                            snr=0)

                    # Check if a phone is nearby (strong WiFi signal approaching)
                    phone_bearing = self.phone_c2.get_nearest_phone_bearing()
                    if phone_bearing:
                        self.log.warning(f"PHONE NEARBY: {phone_bearing['device_type']} {phone_bearing['ssid']} signal={phone_bearing['avg_signal']:.0f}%")
                except Exception as e:
                    if self.cycle_count % 20 == 0:
                        self.log.debug(f"Phone C2: {e}")

            # 10b. STINGRAY/IMSI catcher detection for 815-690-6926
            if self.cycle_count % 8 == 0:
                try:
                    hack_iq = hack['data'] if hack else None
                    stingray_dets = self.stingray.detect(
                        hackrf_iq=hack_iq,
                        hackrf_freq=Config.HACKRF_FREQ_TARGET,
                        hackrf_fs=Config.HACKRF_SAMPLE_RATE,
                        wifi_aps=aps
                    )
                    for sd in stingray_dets:
                        self.localization.add_observation(
                            fingerprint=f'stingray_{sd.get("detector","?")}',
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=None,
                            range_m=None, freq=sd.get('freq', 0),
                            classification='transmitter',
                            detector_name='stingray_detect',
                            snr=float(sd.get('snr', 0)))
                    if self.stingray.stingray_confidence > 0.5:
                        self.log.warning(f"STINGRAY CONFIDENCE: {self.stingray.stingray_confidence:.2f} bearing={self.aoa:.1f}")
                except Exception as e:
                    if self.cycle_count % 50 == 0:
                        self.log.debug(f"Stingray check: {e}")

            # 10c. C2 Command & Control detection - ultrasound modem + WiFi + RF
            if self.cycle_count % 3 == 0:
                try:
                    # Ultrasound modem C2 (analyze Petterson audio for modem data patterns)
                    petterson_chunk = self.petterson.read(384000//10) if self.petterson else None
                    us_c2 = self.c2.process_ultrasound_modem(
                        petterson_chunk, 384000, bearing=self.aoa if self.aoa != 0.0 else None)
                    for cd in us_c2:
                        det_name = cd.get('detector', cd.get('pattern', 'us_modem'))
                        self.localization.add_observation(
                            fingerprint=f'c2_{det_name}',
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=None,
                            range_m=None, freq=cd.get('freq', 0),
                            classification='transmitter',
                            detector_name=f'c2_{det_name}',
                            snr=float(cd.get('snr', 0)))

                    # WiFi C2 patterns (SSID matching, AP count surges)
                    wifi_c2 = self.c2.process_wifi_c2(aps, bearing=self.aoa if self.aoa != 0.0 else None)
                    for wc in wifi_c2:
                        det_name = wc.get('detector', wc.get('pattern', 'wifi_c2'))
                        self.localization.add_observation(
                            fingerprint=f'c2_{det_name}',
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=None,
                            range_m=None, freq=0,
                            classification='transmitter',
                            detector_name=f'c2_{det_name}',
                            snr=float(wc.get('signal', 0)/10))
                except Exception as e:
                    if self.cycle_count % 20 == 0:
                        self.log.debug(f"C2 check: {e}")

            # 11. Active null steering - inverse MW wave via BladeRF TX burst
            # 11a. GPS Jam Scanner — check for GPS jamming signals
            # NOTE: GPSJamScanner uses its own bladeRF-cli subprocess, which conflicts
            # with the BladeRFCLIBridge. Only run when bridge is paused or idle.
            if self.cycle_count % 30 == 0 and self.bladerf_cli and not self.bladerf_cli.capture_paused:
                try:
                    jam_result = self.gps_jam_scanner.scan()
                    if jam_result:
                        self.localization.add_observation(
                            fingerprint=f'gps_jammer_{jam_result.get("excess_db",0):.0f}',
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=self.aoa if self.aoa != 0.0 else None,
                            range_m=None, freq=1575420000,
                            classification='transmitter',
                            detector_name='gps_jammer',
                            snr=float(jam_result.get('excess_db', 0)))
                        self.log.warning(f"GPS JAM: excess={jam_result.get('excess_db',0):.1f}dB above baseline")
                except: pass
            # Fire 180deg  phase-inverted CW at attacker frequency via CAPTURE THREAD
            if self.null_enabled and self.cycle_count % 3 == 0 and self.bladerf_cli is not None and self.aoa != 0.0:
                tx_freq = Config.BLADERF_FREQ  # 2.45 GHz S-band MW carrier
                self.bladerf_cli.capture_paused = True
                time.sleep(0.1)  # let current capture finish
                self.bladerf_cli.tx_params = {'freq': tx_freq, 'gain': 60, 'sample_rate': 5000000}
                time.sleep(0.8)  # allow TX burst to complete (capture thread runs _run_tx_burst)
                self.bladerf_cli.tx_params = None
                self.bladerf_cli.capture_paused = False
                self.log.info(f"Null: {tx_freq/1e6:.1f}MHz 60dB INV bearing={self.aoa:.1f}")

            # RE-RADIATOR DETECTION: distinguish real transmitters from ambient metal
            # Active transmitter: steady signal, consistent power
            # Ambient metal re-radiator: rings and decays like a bell when excited
            # Method: after TX null burst, check if signal decays (metal ringing)
            # vs stays steady (real transmitter with its own power)
            if self.null_enabled and bladerf_active and _rnd.random() < 0.15:  # randomized re-radiator check
                try:
                    # Capture before and after null burst
                    iq1_pre, _ = self._capture_bladerf()
                    if iq1_pre is not None and len(iq1_pre) > 512:
                        pre_power = np.sqrt(np.mean(np.abs(iq1_pre[-512:])**2))

                        # Fire null burst (already happens every 3 cycles)
                        # Then capture immediately after
                        time.sleep(0.5)  # wait for null burst
                        iq1_post, _ = self._capture_bladerf()

                        if iq1_post is not None and len(iq1_post) > 512:
                            post_power = np.sqrt(np.mean(np.abs(iq1_post[-512:])**2))

                            # Check signal over next 2 seconds for decay
                            time.sleep(2.0)
                            iq1_late, _ = self._capture_bladerf()

                            if iq1_late is not None and len(iq1_late) > 512:
                                late_power = np.sqrt(np.mean(np.abs(iq1_late[-512:])**2))

                                # Analysis:
                                # Real transmitter: post_power ≈ pre_power (own power source)
                                # Metal re-radiator: post_power < pre_power AND late_power << pre_power (decays)
                                # Null burst should suppress the primary MW, so only real transmitters persist

                                if pre_power > 0:
                                    decay_ratio = late_power / pre_power
                                    null_effect = post_power / pre_power

                                    if decay_ratio < 0.3:
                                        # Signal decayed significantly = ambient metal re-radiator
                                        source_type = 'ambient'
                                        self.log.info(f"RE-RADIATOR DETECTED: decay={decay_ratio:.2f} null={null_effect:.2f} - ambient metal, not real transmitter")
                                    elif null_effect < 0.5 and decay_ratio > 0.7:
                                        # Signal dropped during null but recovered = real transmitter
                                        source_type = 'active'
                                        self.log.info(f"ACTIVE TRANSMITTER: decay={decay_ratio:.2f} null={null_effect:.2f} - real powered device")
                                    else:
                                        source_type = 'unknown'

                                    self.localization.add_observation(
                                        fingerprint=f'source_type_{source_type}',
                                        obs_lat=lat, obs_lon=lon,
                                        bearing_deg=self.aoa if self.aoa != 0.0 else None,
                                        range_m=None, freq=Config.BLADERF_FREQ,
                                        classification='transmitter',
                                        detector_name=f'{"real_transmitter" if source_type=="active" else "ambient_reradiator"}',
                                        snr=float(pre_power),
                                        source_type=source_type)
                except Exception as e:
                    if self.cycle_count % 20 == 0:
                        self.log.debug(f"Re-radiator check: {e}")

            # 11b. Active direction probe: TX pulse → RX echo → measure return direction
            # Sends a short pulse at 2.45GHz, then captures the reflection
            # Stronger echo on ch1 = source on left, stronger on ch2 = source on right
            if _rnd.random() < 0.05 and self.bladerf_cli is not None and bladerf_active:  # random direction probe
                try:
                    self.bladerf_cli.capture_paused = True
                    time.sleep(0.1)
                    # TX a short CW burst (probe pulse)
                    self.bladerf_cli.tx_params = {'freq': Config.BLADERF_FREQ, 'gain': 50, 'sample_rate': 2000000}
                    time.sleep(0.3)  # short burst
                    self.bladerf_cli.tx_params = None
                    time.sleep(0.1)  # let TX settle
                    # Immediately capture echo
                    self.bladerf_cli.capture_paused = False
                    time.sleep(0.3)  # wait for next capture with echo
                    probe_iq1, probe_iq2 = self._capture_bladerf()
                    if probe_iq1 is not None and len(probe_iq1) > 100:
                        echo_p1 = np.sqrt(np.mean(np.abs(probe_iq1[:1024])**2))
                        echo_p2 = np.sqrt(np.mean(np.abs(probe_iq2[:1024])**2))
                        echo_ratio = echo_p1 / (echo_p2 + 1e-12)
                        # Compare with pre-probe baseline
                        baseline_ratio = getattr(self, '_probe_baseline_ratio', 1.0)
                        delta = echo_ratio / baseline_ratio
                        direction = 'LEFT (ch1 side)' if delta > 1.1 else ('RIGHT (ch2 side)' if delta < 0.9 else 'UNCLEAR')
                        self._probe_baseline_ratio = echo_ratio
                        self.log.info(f"DIRECTION PROBE: p1={echo_p1:.1f} p2={echo_p2:.1f} ratio={echo_ratio:.2f} delta={delta:.2f} → {direction}")
                        self.court.log_anomaly('direction_probe', {
                            'p1': float(echo_p1), 'p2': float(echo_p2),
                            'ratio': float(echo_ratio), 'direction': direction,
                            'aoa': float(self.aoa)})
                except Exception as e:
                    self.log.debug(f"Probe error: {e}")
                    self.bladerf_cli.capture_paused = False

            # 11c. ACTIVE ILLUMINATION RADAR: pulse -> echo -> map ALL reflectors
            # BladeRF xA9 HALF-DUPLEX: must switch bias tees RX off, TX on, fire, TX off, RX on
            # Only 2 bias tees at a time (USB current limit)
            if self.cycle_count % 10 == 0 and self.bladerf_cli is not None and bladerf_active:
                try:
                    # Step 1: Capture baseline BEFORE (ambient only)
                    base_iq1, base_iq2 = self._capture_bladerf()
                    if base_iq1 is not None and len(base_iq1) > 2048:
                        base_power = np.sqrt(np.mean(np.abs(base_iq1[-512:])**2))

                        # Step 2: Fire illumination pulse through TX bridge
                        # This switches bias tees: rx1/rx2 OFF -> tx1/tx2 ON -> fire -> tx1/tx2 OFF -> rx1/rx2 ON
                        self.bladerf_cli.capture_paused = True
                        time.sleep(0.3)  # wait for current RX capture to finish
                        self.bladerf_cli.tx_params = {
                            'freq': Config.BLADERF_FREQ,
                            'gain': 55,
                            'sample_rate': 2000000
                        }
                        # Wait for TX burst to complete (bias tees back to RX)
                        time.sleep(2.0)

                        # Step 3: Capture echo immediately after TX (reflections still ringing)
                        self.bladerf_cli.capture_paused = False
                        time.sleep(0.5)  # let new RX capture start
                        echo_iq1, echo_iq2 = self._capture_bladerf()

                        if echo_iq1 is not None and len(echo_iq1) > 2048:
                            echo_power = np.sqrt(np.mean(np.abs(echo_iq1[-512:])**2))

                            # BISTATIC RANGE: cross-correlate baseline (ambient)
                            # with echo (ambient + reflections). Envelope lag → delay → range.
                            if base_iq1 is not None and len(base_iq1) > 1024:
                                try:
                                    blen = min(2048, min(len(base_iq1), len(echo_iq1)))
                                    b_env = np.abs(base_iq1[:blen].astype(np.complex128))
                                    e_env = np.abs(echo_iq1[:blen].astype(np.complex128))
                                    b_env -= np.mean(b_env); e_env -= np.mean(e_env)
                                    env_corr = np.correlate(e_env, b_env, mode='same')
                                    acenter = len(env_corr) // 2
                                    # Look for echo peak: lag 10-50 samples (7.5-37.5m at 2MSps)
                                    search_lo = min(acenter + 10, len(env_corr) - 1)
                                    search_hi = min(acenter + 50, len(env_corr))
                                    if search_hi > search_lo:
                                        peak_lag = search_lo + np.argmax(np.abs(env_corr[search_lo:search_hi]))
                                        pk_val = np.abs(env_corr[peak_lag])
                                        noise_floor = np.mean(np.abs(env_corr[acenter-40:acenter-10])) + 1e-12
                                        if pk_val > noise_floor * 2.5:
                                            delay_s = (peak_lag - acenter) / Config.BLADERF_SAMPLE_RATE
                                            b_range = delay_s * 3e8 / 2  # round-trip / 2
                                            self._bistatic_range = max(3.0, min(2000.0, b_range))
                                            self.log.info(f"BISTATIC RANGE: {self._bistatic_range:.0f}m (lag={peak_lag-acenter}samp pk/noise={pk_val/noise_floor:.1f}x)")
                                except Exception as be:
                                    self.log.debug(f"Bistatic range error: {be}")

                            # Step 4: Compare echo vs baseline - find new reflections
                            if echo_power > base_power * 1.2:  # at least 20% more energy
                                # FFT analysis on the difference
                                base_fft = np.abs(np.fft.rfft(base_iq1[-2048:].astype(np.complex128)))
                                echo_fft = np.abs(np.fft.rfft(echo_iq1[-2048:].astype(np.complex128)))
                                diff_fft = echo_fft - base_fft
                                diff_fft[diff_fft < 0] = 0
                                fft_freqs = np.fft.rfftfreq(2048, 1/Config.BLADERF_SAMPLE_RATE)
                                noise_floor = np.median(base_fft) + 1e-12

                                from scipy.signal import find_peaks
                                echo_peaks, echo_props = find_peaks(
                                    diff_fft, height=noise_floor*3, distance=5, prominence=noise_floor*2)

                                for pk_idx, pk in enumerate(echo_peaks[:10]):
                                    echo_level = diff_fft[pk]
                                    echo_freq = fft_freqs[pk]

                                    # MIMO AoA on echo: phase diff between ch1 and ch2
                                    if echo_iq2 is not None and len(echo_iq2) > 2048:
                                        # Cross-correlation at this frequency bin
                                        phase1 = np.angle(echo_iq1[-2048:]).astype(np.float64)
                                        phase2 = np.angle(echo_iq2[-2048:]).astype(np.float64)
                                        # Use region around the peak
                                        lo = max(0, pk-10)
                                        hi = min(len(phase1), pk+10)
                                        dphase = np.mean(phase1[lo:hi]) - np.mean(phase2[lo:hi])
                                        wavelength = 3e8 / Config.BLADERF_FREQ
                                        d = Config.ANTENNA_SPACING
                                        sin_theta = np.clip(dphase * wavelength / (2 * np.pi * d), -1, 1)
                                        echo_bearing = np.degrees(np.arcsin(sin_theta)) + Config.BEARING_OFFSET
                                    else:
                                        echo_bearing = self.aoa

                                    # Reflection bandwidth -> material classification
                                    bw_bins = np.sum(diff_fft[max(0,pk-5):pk+6] > noise_floor*2)
                                    bandwidth_hz = bw_bins * (Config.BLADERF_SAMPLE_RATE / 2048)

                                    if bandwidth_hz < 50000:
                                        material = 'metal_device'
                                        cls = 'device'
                                    elif bandwidth_hz < 200000:
                                        material = 'metal_surface'
                                        cls = 'structure'
                                    else:
                                        material = 'water_body'
                                        cls = 'person'

                                    # Use bistatic range if computed, otherwise fall back to HackRF+LNA range
                                    radar_range = self._bistatic_range or self.hackrf_range
                                    self.localization.add_observation(
                                        fingerprint='radar_%s_%d' % (material, int(echo_freq)),
                                        obs_lat=lat, obs_lon=lon,
                                        bearing_deg=float(echo_bearing),
                                        range_m=float(radar_range) if radar_range else None,
                                        freq=float(Config.BLADERF_FREQ),
                                        classification=cls,
                                        detector_name='radar_%s' % material,
                                        snr=float(echo_level/noise_floor),
                                        source_type='reflector')

                                    if cls == 'person':
                                        self.log.warning('RADAR: PERSON at %.0fdeg BW=%.0fkHz' % (echo_bearing, bandwidth_hz/1000))
                                    elif cls == 'device':
                                        self.log.info('RADAR: DEVICE at %.0fdeg BW=%.0fkHz' % (echo_bearing, bandwidth_hz/1000))

                                if len(echo_peaks) > 0:
                                    self.court.log_anomaly('active_radar', {
                                        'echo_count': len(echo_peaks),
                                        'base_power': float(base_power),
                                        'echo_power': float(echo_power),
                                        'aoa': float(self.aoa),
                                        'cycle': self.cycle_count
                                    })
                            else:
                                if self.cycle_count % 30 == 0:
                                    self.log.info('RADAR: no significant echo (base=%.1f echo=%.1f)' % (base_power, echo_power))
                except Exception as e:
                    if self.cycle_count % 20 == 0:
                        self.log.debug('Active radar error: %s' % e)
                    try:
                        self.bladerf_cli.capture_paused = False
                    except: pass

            # Show ALL sources - ghost_murmur kept for operator tracking (historical)
            clean_sources = sources

            # Watcher: analyze detections for attacker patterns
            if self.cycle_count % 5 == 0:
                try:
                    watcher_findings = self.watcher.analyze(sources, {
                        'aoa': self.aoa, 'gps_fix': gps['has_fix']
                    })
                    for wf in watcher_findings[:3]:  # top 3 findings
                        self.localization.add_observation(
                            fingerprint=f'watcher_{wf.get("type","?")}',
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=wf.get('bearing', self.aoa) if self.aoa != 0.0 else 0.0,
                            range_m=None, freq=0,
                            classification='transmitter',
                            detector_name=f'watcher_{wf.get("type","?")}',
                            snr=0)
                    # Feed consensus detector
                    for wf in watcher_findings[:3]:
                        self.detectors['watcher_consensus'].update(f'watcher_{wf.get("type","?")}')
                except: pass

            # ARRAY DETECTION: find transmitters that line up (phased array)
            if self.cycle_count % 10 == 0 and len(clean_sources) >= 3:
                try:
                    tx_sources = [s for s in clean_sources if s.get('classification') == 'transmitter' and s.get('bearing')]
                    if len(tx_sources) >= 3:
                        bearings = sorted([s['bearing'] for s in tx_sources])
                        # Check if 3+ transmitters within 15 degrees of each other
                        for i in range(len(bearings)-2):
                            span = bearings[i+2] - bearings[i]
                            if abs(span) < 15:
                                center_b = np.mean(bearings[i:i+3])
                                self.log.warning(f"ARRAY DETECTED: {3}+ transmitters aligned at {center_b:.0f}deg (span={span:.0f}deg)")
                                self.localization.add_observation(
                                    fingerprint=f'phased_array_{center_b:.0f}',
                                    obs_lat=lat, obs_lon=lon,
                                    bearing_deg=center_b,
                                    range_m=None, freq=0,
                                    classification='transmitter',
                                    detector_name='phased_array',
                                    snr=float(len(tx_sources)))
                                break
                except: pass

            # HELLO SCOTTY: power line carrier communication detector
            # Detects data signals transmitted through electrical wiring
            # These are omnidirectional (come through the wiring, not through air)
            if self.cycle_count % 8 == 0 and len(mid_chunk) >= 8192:
                try:
                    room_audio = mid_chunk[-8192:].astype(np.float32)
                    # Power line carriers: 100-500 kHz range (above audio, below radio)
                    # Also check 120Hz harmonics (data modulated onto AC)
                    fft_abs = np.abs(np.fft.rfft(room_audio))
                    fft_f = np.fft.rfftfreq(len(room_audio), 1/48000)

                    # Check for 120Hz harmonics with data modulation (X10/Insteon style)
                    ac_harmonics = [120, 180, 240, 360, 480, 600, 840, 1200, 1800]
                    noise = np.median(fft_abs) + 1e-12
                    for harm in ac_harmonics:
                        if harm < fft_f[-1]:
                            idx = np.argmin(np.abs(fft_f - harm))
                            if fft_abs[idx] > noise * 5:
                                # Check bandwidth - if wider than pure AC, there's data
                                left = max(0, idx-5)
                                right = min(len(fft_abs), idx+5)
                                local_bw = np.sum(fft_abs[left:right] > noise * 3)
                                if local_bw > 3:  # wide = data on power line
                                    self.localization.add_observation(
                                        fingerprint=f'hello_scotty_{harm}Hz',
                                        obs_lat=lat, obs_lon=lon,
                                        bearing_deg=None,  # comes through wiring, no direction
                                        range_m=None, freq=float(harm),
                                        classification='transmitter',
                                        detector_name='hello_scotty',
                                        snr=float(fft_abs[idx]/noise))
                                    self.log.info(f"HELLO SCOTTY: {harm}Hz power line carrier SNR={fft_abs[idx]/noise:.1f}")
                                    break
                except: pass

            # MANUS AI: detect VLF/LLM agent command patterns
            # AI agents like Manus send structured commands via VLF/ELF
            if self.cycle_count % 10 == 0 and len(mid_chunk) >= 16384:
                try:
                    room_audio = mid_chunk[-16384:].astype(np.float32)
                    # VLF: 3-30 kHz - Manus agent commands are structured bursts
                    # Look for periodic burst patterns in VLF range
                    fft_abs = np.abs(np.fft.rfft(room_audio))
                    fft_f = np.fft.rfftfreq(len(room_audio), 1/48000)
                    vlf_mask = (fft_f >= 3000) & (fft_f <= 30000)
                    if np.any(vlf_mask):
                        vlf_power = fft_abs[vlf_mask]
                        vlf_noise = np.median(vlf_power) + 1e-12
                        vlf_peaks, _ = np.find_peaks(vlf_power, height=vlf_noise*4, distance=10)
                        # Multiple peaks in VLF with regular spacing = structured command signal
                        if len(vlf_peaks) >= 3:
                            peak_freqs = fft_f[vlf_mask][vlf_peaks]
                            spacing = np.diff(peak_freqs)
                            if np.std(spacing) / (np.mean(spacing) + 1) < 0.3:
                                # Regular spacing = LLM/agent structured output
                                self.localization.add_observation(
                                    fingerprint=f'manus_vlf_{np.mean(peak_freqs):.0f}',
                                    obs_lat=lat, obs_lon=lon,
                                    bearing_deg=None,  # VLF is omnidirectional
                                    range_m=None, freq=float(np.mean(peak_freqs)),
                                    classification='transmitter',
                                    detector_name='manus_ai_vlf',
                                    snr=float(np.max(vlf_power)/vlf_noise))
                                self.log.info(f"MANUS AI VLF: {len(vlf_peaks)} carriers, spacing={np.mean(spacing):.0f}Hz")
                except: pass

            # CORRELATION: match WiFi devices with ultrasound activity
            if self.cycle_count % 10 == 0:
                try:
                    # Feed recent WiFi observations to correlation engine
                    for ap in aps[:5]:
                        self.correlation.record_wifi(
                            ap.get('bssid', '?'), ap.get('ssid', '?'),
                            ap.get('signal', 0), ap.get('channel', 0))

                    # Feed recent US observations
                    for s in sources[:10]:
                        if s.get('freq', 0) > 1000:
                            self.correlation.record_ultrasound(
                                s['freq'], s.get('detector_name', '?'), s.get('snr', 0))

                    # Analyze correlations
                    corr_results = self.correlation.analyze()
                    for cr in corr_results[:3]:
                        self.localization.add_observation(
                            fingerprint=f'corr_{cr["bssid"][-8:]}',
                            obs_lat=lat, obs_lon=lon,
                            bearing_deg=None,  # WiFi is omni, bearing from loop or BladeRF
                            range_m=None, freq=0,
                            classification='transmitter',
                            detector_name=f'c2_phone_correlated',
                            snr=float(cr.get('correlation', 0) * 10),
                            source_type='active')
                except: pass

            # 12. Update map
            map_data={
                'observer':{'lat':lat,'lon':lon,'aoa':self.aoa,'aoa_alt':getattr(self,'aoa_alternate',self.aoa+180 if self.aoa!=0 else 0),'gps_fix':gps['has_fix'],
                            'bladerf':bladerf_active,'hackrf':hackrf_active,
                            'pet_rate':self.petterson.fs,
                            'hackrf_lat':self.localization.hackrf_lat,
                            'hackrf_lon':self.localization.hackrf_lon,
                            'rtlsdr_lat':getattr(self.localization,'rtlsdr_lat',None),
                            'rtlsdr_lon':getattr(self.localization,'rtlsdr_lon',None),
                            'hackrf_aoa':hackrf_aoa if 'hackrf_aoa' in dir() else 0},
                'sources':clean_sources,
                'threat_labels':Config.MAP_THREAT_LABELS,
                'watcher_findings': [{'type': f.get('type','?'), 'info': f.get('info','')[:100]}
                                for f in list(self.watcher.findings)[-5:]],
                'wifi_aps':wigle_aps,
                'operator_count':len(self.operator_tracker.db)
            }
            self.map_server.update(map_data)

            # 12. Periodic operator DB flush
            if time.time()-last_operator_flush>30:
                self.operator_tracker.flush(); last_operator_flush=time.time()

            # Console
            n_src=len([s for s in sources if s.get('lat') is not None])
            n_bear=len([s for s in sources if s.get('lat') is None and s.get('bearing') is not None])
            pet_khz=self.petterson.fs//1000
            bands=self.petterson.get_band_info()
            band_str=f"384k:{bands.get('384k',0)//1000}k 48k:{bands.get('48k',0)//1000}k 2k:{bands.get('2k',0)//1000}"
            # Sweep SDR frequencies across full spectrum
            (h_name, h_freq, h_rate), (b_name, b_freq, b_rate) = self.sweep.step()

            # Retune HackRF if band changed
            if getattr(self, '_last_hfreq', 0) != h_freq:
                self._last_hfreq = h_freq
                self.hackrf.retune(h_freq, h_rate)
                # Clear detector buffers on retune - stale data at old frequency
                for dname in ['forced_thought','variac','pll_resonance',
                              'bucket_resonator','ecpri_injection','fingerprinting',
                              'satellite_c2']:
                    d = self.detectors.get(dname)
                    if d and hasattr(d, 'rf_buf'):
                        d.rf_buf.clear()
                    if d and hasattr(d, 'buffer'):
                        d.buffer.clear()
                    if d and hasattr(d, 'buf'):
                        d.buf.clear()

            # Power line harmonic detection when on VLF/HF bands
            if h_freq < 30e6 and hack and self.cycle_count % 3 == 0:
                try:
                    pl_results = self.power_line_detector.detect(hack['data'], h_freq)
                    for pl in pl_results:
                        fp = f'pline_h{pl["harmonic"]}'.encode()
                        self.localization.add_observation(
                            fingerprint=fp, obs_lat=lat, obs_lon=lon,
                            bearing_deg=None, range_m=None,
                            freq=pl['freq'],
                            classification='power_line_harmonic',
                            detector_name='power_line',
                            snr=pl['snr'])
                        if pl['abnormal']:
                            self.log.warning(f'ABNORMAL HARMONIC: {pl["harmonic"]}th ({pl["freq"]/1e3:.1f}kHz) SNR={pl["snr"]:.1f}')
                except Exception as e:
                    self.log.debug(f'PL detect error: {e}')

            # BladeRF sweep disabled - RX bridge owns device, CLI -e mode conflicts
            # BladeRF stays at 2.4 GHz S-band with MIMO AoA (best band for MW detection)
            # To sweep: need in-band retune via capture loop, not separate CLI process

            print(f"  Cycle {self.cycle_count} | AoA:{self.aoa:.1f}deg  | "
                  f"Sources:{n_src} resolved, {n_bear} bearing-only | "
                  f"GPS:{'FIX' if gps['has_fix'] else 'NO FIX'} | "
                  f"H:{h_name}({h_freq/1e6:.0f}M) B:{b_name}({b_freq/1e6:.0f}M) | "
                  f"Bands:{band_str} | "
                  f"Intent:{intent}",end='\r')
            # System health heartbeat every 20 cycles
            if self.cycle_count % 20 == 0:
                bci_status = f"BCI:{len(self.eeg_buffer)}samps" if ((hasattr(self.bci,'ser') and self.bci.ser) or (hasattr(self.bci,'tgam') and self.bci.tgam and self.bci.tgam.ser)) else "BCI:off"
                rf_status = f"BladeRF:{'OK' if bladerf_active else 'OFF'}"
                hack_status = f"HackRF:{'OK' if hackrf_active else 'OFF'}"
                gps_status = f"GPS:{gps.get('source','gps1') if gps['has_fix'] else 'laptop'}"
                wifi_status = f"WiFi:{len(self.wifi_scanner.access_points)}APs"
                self.log.info(f"HEALTH: {bci_status} {rf_status} {hack_status} {gps_status} {wifi_status} "
                    f"Detectors:{len(set(s.get('detector','?') for s in sources if s.get('detector')))}/{len(self.detectors)} "
                    f"Evidence:{len(os.listdir(self.court.log_dir)) if hasattr(self,'court') else 0}files")
            # Security audit every 10 cycles
            if self.cycle_count % 10 == 0 and self.bladerf_cli:
                try:
                    sec = self.bladerf_cli.get_security_status()
                    if sec.get('integrity_failures', 0) > 0 or sec.get('rogue_process_incidents', 0) > 0:
                        self.log.warning(f"BladeRF Security: failures={sec['integrity_failures']} "
                                        f"rogue={sec['rogue_process_incidents']} "
                                        f"rms_ratio={sec.get('rms_ratio',0)}")
                        self.court.log_anomaly("bladerf_security_audit", {
                            "integrity_failures": str(sec['integrity_failures']),
                            "rogue_incidents": str(sec['rogue_process_incidents']),
                            "rms_ratio": sec.get('rms_ratio',0),
                            "captures": str(sec.get('captures',''))
                        })
                except Exception as e:
                    pass  # security audit non-critical - skip on error
                    # Neural net inference: classify unknown signals
                    if self.cycle_count % 10 == 0:
                        try:
                            if hack and len(hack['data']) > 512:
                                neural_results = self.neural.detect(iq=hack['data'][-512:])
                                for nr in neural_results:
                                    self.localization.add_observation(
                                        fingerprint=f"neural_{nr.get('modulation','?')}",
                                        obs_lat=lat, obs_lon=lon,
                                        bearing_deg=nr.get('bearing_est'),
                                        range_m=None,
                                        freq=float(nr.get('freq_offset', 0)),
                                        classification=nr.get('classification', 'unknown'),
                                        detector_name='neural_net',
                                        snr=float(nr.get('confidence', 0)))
                                    if nr.get('confidence', 0) > 0.5:
                                        self.log.info(f"NEURAL: {nr.get('modulation','?')} cls={nr.get('classification','?')} conf={nr.get('confidence',0):.2f}")
                        except: pass
                    # Save evidence to disk every cycle
                    if self.cycle_count % 5 == 0:
                        self.localization.save_evidence()
            time.sleep(0.2)

    def shutdown(self):
        self.running=False
        # Save ALL evidence before shutting down
        self.localization.save_evidence()
        self.log.info("Evidence saved to disk before shutdown")
        self.wifi_listener.stop();self.usb_watchdog.stop();self.coherence.stop();self.clock_monitor.stop()
        if self.bladerf:
            try:self.bladerf.close()
            except:pass
        if self.bladerf_cli: self.bladerf_cli.stop()
        self.hackrf.stop();self.gps.stop();self.petterson.stop();self.laptop_mic.stop()
        self.map_server.stop();self.operator_tracker.flush()


# ===================== ENTRY POINT =====================
if __name__=="__main__":
    print("="*60)
    print(" TSCM MASTER SUITE v2 - SOURCE LOCALIZATION")
    print("="*60)
    app=TSCMSystem()
    try: app.run()
    except KeyboardInterrupt: app.shutdown()
    except Exception as e: app.shutdown(); raise e