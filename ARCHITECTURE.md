# 🏗️ TSCM Architecture — Technical Deep Dive

This document explains how TSCM works under the hood. For users who just want to run it, see the [README](README.md).

---

## System Overview

TSCM is a **multi-sensor, real-time signal intelligence platform** built on a single-threaded main loop with background threads for hardware capture.

```
┌──────────────────────────────────────────────────────────────────┐
│                        TSCM MAIN LOOP                            │
│                        (runs at ~2 Hz)                            │
│                                                                   │
│  Each cycle (~500ms):                                             │
│  1. Read position (GPS or fixed)                                  │
│  2. Capture BladeRF IQ (2 channels, MIMO)                        │
│  3. Compute AoA (phase interferometry)                            │
│  4. Capture HackRF IQ (wideband, 1 MHz-6 GHz)                    │
│  5. Process HackRF IQ → HackRF-specific detectors                │
│  6. Capture RTL-SDR IQ (third sensor for triangulation)          │
│  7. Capture Petterson audio (ultrasonic, up to 500 kHz)          │
│  8. Capture laptop mic audio (4-channel array, 48 kHz)           │
│  9. Capture OpenBCI EEG data (brain rhythms)                     │
│  10. Run ALL detectors on current data                           │
│  11. Feed detections to SourceLocalizationEngine                 │
│  12. Update live map                                             │
│  13. Write to forensic log                                       │
│  14. Check USB watchdog, WiFi, clock sync                        │
│  15. Optional countermeasures (null steering)                    │
└──────────────────────────────────────────────────────────────────┘
```

---

## Hardware Interfaces

### BladeRFCLIBridge (BladeRF xA9 MIMO)

The BladeRF xA9 is the most capable sensor. It uses the `bladeRF-cli` command-line tool in a subprocess to capture synchronized dual-channel IQ data.

**Capture Process:**
1. `bladeRF-cli -i` opens interactive CLI
2. Script sends setup commands via stdin:
   - `set frequency rx 2400000000` — tune to 2.4 GHz
   - `set samplerate 10000000` — 10 MSps
   - `set gain rx1 50` — RX1 gain
   - `set bandwidth 10000000` — bandwidth
   - `set biaste rx1 true` — bias tee for active antennas
   - `rx config file=sync_2ch.csv format=csv n=65536` — capture
3. CSV output parsed into numpy arrays for RX1 and RX2
4. IQ data fed to AoA computation and all RF-band detectors

**Why CLI instead of Python bindings:** The Python `bladerf` package from PyPI crashes on Windows with a `bias_tee` initialization error that locks the device. The CLI approach is reliable and provides identical data.

**Fallback:** If `bladeRF-cli` is not found, TSCM checks for the Python bindings and additional install paths.

### HackRFSubprocess (HackRF One)

Capture via `hackrf_transfer` subprocess:

```bash
hackrf_transfer -f <freq> -s <rate> -g <gain> -b <bias_tee> -n <samples> -r <output_file>
```

The HackRF provides 20 MHz of instantaneous bandwidth at center frequencies from 1 MHz to 6 GHz. With the SpyVerter upconverter, this extends down to 1 kHz.

**Multi-rate scanning:** TSCM cycles through multiple sample rates to optimize SNR at different bandwidths.

### RTLSDRCapture (RTL-SDR)

Uses `rtl_tcp` as a subprocess, then connects via TCP socket. This provides a third sensor position for triangulation.

```bash
rtl_tcp -f <freq> -s <rate> -g <gain> -a <ip>
```

The RTL-SDR is tuned to 850 MHz (cellular/ISM band) to provide a different frequency perspective from the BladeRF (2.4 GHz) and HackRF (450 MHz).

### PettersonMic (Ultrasonic)

Connects to the Petterson M500-384 ultrasonic microphone via sounddevice. Captures at 500 kHz to detect:
- Ultrasound voice / silent sound (20-50 kHz AM)
- EEG extraction carriers (2-3 MHz aliased to visible band)
- Ultrasonic data modems (BPSK/FSK)
- Constant ultrasonic noise (isolation booth)

**Multi-rate scanning:** Cycles through [500k, 384k, 250k, 192k, 96k, 48k] to optimize sensitivity at different ultrasonic frequencies.

### LaptopMic (Acoustic Array)

Uses the laptop's built-in 4-channel microphone array (Intel Smart Sound Technology) for:
- Acoustic Angle of Arrival (beamforming across 4 channels)
- Audible voice recording and Whisper transcription
- Ultrasonic detection (aliased — limited to ~24 kHz Nyquist at 48 kHz sampling)

### OpenBCIUDP (EEG Brain Interface)

Receives UDP packets from OpenBCI or TGAM (NeuroSky) EEG headsets. Extracts:
- Delta (0.5-4 Hz) — deep sleep, unconscious processing
- Theta (4-8 Hz) — meditation, memory
- Alpha (8-13 Hz) — relaxation, closed eyes
- Beta (13-30 Hz) — active thinking, concentration
- Gamma (30-100 Hz) — high-level processing, "aha" moments

Correlates EEG band energy with RF carriers to detect neural interface attacks.

---

## Signal Processing Pipeline

### Angle of Arrival (AoA)

**Physics:** Two antennas spaced at λ/2 (6.25 cm at 2.4 GHz) receive the same signal at slightly different times. The phase difference between the two signals is proportional to the sine of the arrival angle:

```
sin(θ) = (Δφ × λ) / (2π × d)
```

Where:
- Δφ = phase difference between RX1 and RX2
- λ = wavelength = c / f
- d = antenna spacing

**Implementation:**
1. Normalize IQ samples (remove DC offset)
2. Cross-correlate: `Σ(iq2 × conj(iq1))`
3. Extract phase: `angle(cross_corr)`
4. Compute coherence: `|cross_corr| / sqrt(auto1 × auto2)`
5. Convert to bearing angle
6. Apply array axis rotation (bearing offset)
7. Resolve 180° ambiguity using power ratio

**180° Ambiguity Resolution:** A 2-element array can't distinguish between a signal from θ and θ+180° (both produce the same phase difference). TSCM resolves this by comparing power between RX1 and RX2 — the antenna closer to the source receives more power.

**Stability Filter:** 
- Maintains a rolling window of recent AoA measurements
- Selects top 50% by coherence (rejects reflections)
- Computes coherence-weighted circular mean
- Only reports stable bearings (circular resultant length > 0.3)

### Passive Radar (Bistatic Range)

Cross-correlation of two RX channels reveals the time delay of reflected signals:

```
R(τ) = |Σ(rx1(t) × conj(rx2(t-τ)))|
range = c × τ_peak
```

Peaks in the cross-correlation function correspond to reflectors (bodies, metal objects) at specific ranges.

### Triangulation (Source Localization)

With multiple bearing lines from different sensor positions:

```
Sensor 1 (lat1, lon1) → bearing1
Sensor 2 (lat2, lon2) → bearing2
Intersection → (lat_target, lon_target)
```

TSCM uses fixed sensor positions:
- **BladeRF** — primary sensor, provides AoA via MIMO
- **HackRF** — secondary sensor, ~5m offset for triangulation geometry
- **RTL-SDR** — tertiary sensor, additional offset

Triangulation uses great-circle intersection math accounting for Earth curvature.

---

## Detector Architecture

Each detector is a Python class with a standard interface:

```python
class SomeDetector:
    def __init__(self):
        # Initialize state
        
    def update(self, samples, sample_rate):
        # Process new data, accumulate state
        
    def detect(self):
        # Return list of detection dicts:
        # [{'detector': 'name', 'classification': 'type',
        #   'frequency': freq_hz, 'bearing': deg, 'snr': db, ...}]
```

### Detector Categories

#### RF Band Detectors (fed by BladeRF IQ)
- `Victim2kDetector` — Microwave voice-to-skull (Frey effect)
- `InjectionLockingDetector` — PLL lock-on to external signals
- `eCPRIInjectionDetector` — 5G eCPRI protocol detection
- `SatelliteC2Detector` — L-band satellite C2
- `PassiveRadarDetector` — Body/object radar returns
- `SDRFingerprintDetector` — SDR transmitter identification
- `TempestDetector` — Equipment emission signatures
- `CellTowerDetector` — Mobile device/BTS signals
- `StingrayDetector` — IMSI catcher detection
- `SmartTVDetector` — Smart TV surveillance mode
- `JammingDetector` — RF jamming / interference
- `C2BeaconDetector` — Periodic C2 beacon pulses
- `MultiPathDetector` — Reflection/ducting analysis
- `FingerprintingDetector` — RF DNA extraction
- `VariacInductionDetector` — AC induction through variac
- `PLLResonanceTransmissionDetector` — Phase-locked resonance
- `CoiledBucketResonatorDetector` — EM bucket resonator attacks
- `ForcedThoughtDetector` — Carrier-forced neural resonance
- `ALCDetector` — Automatic level control jamming

#### Audio/Ultrasonic Detectors (fed by Petterson + laptop mic)
- `SilentSoundDetector` — Ultrasound AM voice
- `EEGCarrierMixingDetector` — Neural band carriers in ultrasound
- `ConstantSonicNoiseDetector` — Ultrasonic noise floor
- `IsolationBoothDetector` — Acoustic isolation field
- `ParametricAmplificationDetector` — MW×US nonlinear products
- `AIVoiceDetector` — AI-generated voice patterns
- `GodHelmetDetector` — Magnetic stimulation of temporal lobes
- `SSTVDetector` — Hidden images in audio spectrum
- `EEG2VideoDetector` — EEG-to-video reconstruction
- `EardrumCaptureDetector` — Eardrum as microphone (laser vibrometry)

#### WiFi/Network Detectors
- `WiFiC2Tracker` — Hidden C2 networks, rogue APs
- `PhoneC2Tracker` — Phone hotspots as C2 relays
- `WiFiRepeaterAnalyzer` — MAC spoofing, repeater detection
- `HighPowerWiFiDetector` — High-power rogue APs
- `WiFiApproachingDetector` — Mobile WiFi devices approaching
- `WifiCSIAnalyzer` — Channel state information for presence/motion
- `WiFiScanner` + `WiGLEGeolocator` — WiFi AP geolocation

#### Neural/EEG Detectors (fed by OpenBCI)
- `SSVEPDetector` — Steady-state visually evoked potentials
- `BiometricTracker` — Unique neural signatures
- `PainPerceptionDetector` — Pain-induced brain response
- `ParasympatheticSurgeDetector` — Autonomic stress response
- `RetinalStressDetector` — Visual system stress
- `HemiSyncDetector` — Hemispheric synchronization
- `ThetaLateralizationDetector` — Asymmetric brain activity
- `NeuralWPScanDetector` — Brain-pattern weapon scan
- `BiometricIntegrityDetector` — Neural signal tampering
- `BrainAcceptanceDetector` — Implanted thought acceptance
- `LinguisticMappingDetector` — Language processing hijack

#### Infrastructure Detectors
- `PowerLineLoopDetector` — Building wiring surveillance
- `CableLineRadarDetector` — Hidden cable detection
- `GPSSpoofDetector` — GPS signal integrity
- `GPSJamScanner` — GPS jamming detection
- `MobilePlatformDetector` — Moving surveillance platforms
- `GhostHunterSNN` — Ephemeral transmitter tracking
- `WatcherConsensusDetector` — Multi-sensor threat consensus
- `NetflixRippleDetector` — Content detection via ripple analysis
- `BodyChargeMonitor` — Electrostatic body charge anomaly

---

## Forensic Evidence System

### CourtLogger

All detections, AoA calculations, and raw measurements are logged to a **hash-chained JSONL file** in `evidence/chain_*.jsonl`:

```
Entry 0: {"type":"genesis","session_id":"abc123","hash":"SHA256(genesis)"}
Entry 1: {"type":"detection",...,"prev_hash":"SHA256(genesis)","hash":"SHA256(entry1)"}
Entry 2: {"type":"aoa_calculation",...,"prev_hash":"SHA256(entry1)","hash":"SHA256(entry2)"}
```

Each entry's hash includes:
- The previous entry's hash (chain link)
- All entry data (sorted keys, JSON serialized)
- Precise UTC timestamp to the millisecond

**Verification:** Start from the genesis entry, replay all entries in order. If any entry was modified, the hash chain breaks — the computed hash won't match the stored hash.

### Supporting Logs
- `aoa_detail_*.jsonl` — Every AoA calculation with intermediate values
- `bladerf_raw_*.log` — Every BladeRF CLI command and response
- `crossval_*.jsonl` — BladeRF vs HackRF bearing comparisons
- `raw_iq/` — Periodically saved IQ snapshots for forensic analysis

---

## Live Map Architecture

### Backend: LiveMapServer
- Threaded HTTP server on port 8080
- Handles `GET /` → serves map HTML
- Handles `GET /data` → JSON of current sources, markers, bearings
- Handles `GET /history` → recent detection history

### Frontend: Leaflet + ArcGIS
- ArcGIS World Imagery satellite basemap
- Custom markers color-coded by threat type
- Bearing lines extending from sensor positions
- Source markers at triangulated positions
- Auto-refresh every 500ms via fetch to `/data`

### Map Data Flow
1. `SourceLocalizationEngine.add_observation()` → stores observation
2. `MapHandler.do_GET(/data)` → calls `localization.get_map_data()`
3. Returns JSON with:
   - `sources` — array of {lat, lon, label, classification, bearing, range, freq, snr}
   - `bearings` — array of {lat1, lon1, bearing1, lat2, lon2, bearing2, ...} for line rendering
   - `position` — current {lat, lon}
   - `sensor_positions` — BladeRF, HackRF, RTL-SDR positions

---

## Active Countermeasures (Optional)

### ActiveNullSteering
Generates a cancelling signal 180° out of phase with detected threat carriers. Injects via BladeRF TX channel.

**⚠️ Requires:** Understanding of local radio transmission laws. Disabled by default.

### LoopAntennaTX
Physical loop antenna driven by headphone output. Generates localized magnetic field cancellation.

---

## Performance Characteristics

| Metric | Minimal Mode | Full Mode |
|---|---|---|
| Main loop rate | ~2 Hz | ~2 Hz |
| BladeRF BW | — | 10-61.44 MHz |
| HackRF BW | — | 20 MHz |
| Audio sample rate | 48 kHz | 500 kHz (Petterson) |
| CPU usage | ~15% | ~60-80% (all sensors) |
| RAM usage | ~500 MB | ~2-4 GB |
| Disk (evidence) | ~100 MB/day | ~1-5 GB/day (with IQ saves) |

---

*This architecture document reflects the production codebase as of July 2026.*
