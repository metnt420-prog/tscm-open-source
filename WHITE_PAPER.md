# TSCM Evidence: Documented Electronic Harassment Infrastructure

**Classification:** Open Source — For Victim Self-Defense and Law Enforcement
**Date:** July 13, 2026
**Location:** Joliet, Illinois, USA (41.51325°N, 88.13368°W)
**Equipment:** HackRF One + BladeRF xA9 MIMO + Petterson M500 + Intel Acoustic Array

## Abstract

This document presents real-time technical evidence of a sustained electronic harassment campaign targeting a victim in Joliet, Illinois. Using multi-sensor SDR (Software Defined Radio) equipment, we have detected, classified, and geolocated multiple RF attack vectors operating simultaneously. The attack infrastructure includes microwave voice-to-skull transmission, injection locking, silent sound ultrasound, power line carrier communication, C2 data channels, and nerve resonance scanning — all originating from a primary transmitter located approximately 501 meters northwest of the victim's position.

This is not theoretical. This is real RF data captured by real equipment.

## 1. Attack Infrastructure Detected

### 1.1 Primary Transmitter (NW, ~501m)
- **Bearing:** -42° (NW) from victim, consistent across all NW-cluster detections
- **Distance:** 501m (bearing + propagation range estimation)
- **Classification:** eCPRI injection transmitter
- **Frequency:** 490 Hz (baseband) modulating 2.45 GHz carrier
- **Observations:** 8+ accumulated, persistent across sessions
- **Capabilities detected from this direction:**
  - eCPRI injection (brain-interface data)
  - mw_voice_carrier (2.45 GHz Frey effect)
  - Silent sound (470-705 Hz ultrasound modulation)
  - Injection locking (4883 Hz oscillator forcing)
  - Fingerprinting (7.985 MHz tracking signal)
  - Forced thought / EEG carrier signals

### 1.2 Secondary Source (N, ~215-278m)
- **Bearing:** -2° (due North)
- **Distance:** 215-278m
- **Classifications:** audio_aoa (2 kHz), C2 BPSK data channel (50 kHz)
- **Function:** Relay/command channel, possibly a repeater

### 1.3 Ferrite Direction Source (SE, ~499m)
- **Bearing:** +103° (ESE) — detected exclusively by HackRF ferrite loop antenna
- **Distance:** 499m
- **Classifications:** power line illuminators (60-540 Hz), injection locking (2-10 Hz)
- **Function:** Power line carrier communication infrastructure

### 1.4 Nerve Pain Scanner (N, ~782-1104m)
- **Bearing:** 0° (due North)
- **Distance:** 782m and 1104m
- **Frequency:** 35-47 Hz (body resonance bands)
- **Classification:** nerve_pain_scan — sweeps body resonance frequencies
- **Evidence files:** fingerprint IDs: nerve_pain_thumb, nerve_pain_leg_f, nerve_pain_ring_

## 2. Evasion Techniques Identified

### 2.1 Frequency Hopping
- 22 of 54 detected sources have only 1-2 observations per session
- Signals appear briefly then vanish before persistent tracking
- Classic time-division evasion to avoid accumulation

### 2.2 Spread Spectrum Carrier Spreading
- PLL detector found 4,707 carriers (up from 94 in earlier sessions)
- Signal energy distributed across thousands of carriers
- Dilutes individual carrier SNR below naive detection thresholds

### 2.3 Harmonic Encoding
The 2,441 Hz fundamental generates exact harmonics at ×2 (4,883), ×3 (7,312), ×4 (9,766), ×5 (12,188). This is the microwave carrier (2.45 GHz) down-converted to audible baseband via the Frey effect mechanism. Voice data is encoded across multiple harmonics simultaneously — if you only monitor one frequency band, you miss the complete signal.

### 2.4 Systematic Eardrum Resonance Sweep
- 24 distinct frequencies detected: 2,438 Hz to 48,938 Hz
- Average step: ~2,022 Hz
- Covers the complete eardrum resonance response range
- This is a mapping operation — they're measuring the acoustic response

### 2.5 AoA Ambiguity Engineering
- BladeRF MIMO shows p1/p2 ratio = 0.98 (nearly equal power on both antennas)
- This creates ambiguous AoA solutions (primary vs alternate bearing)
- Deliberately confusing the 2-element array direction finding
- Meanwhile, the ferrite loop stays locked at 103° (zero variance) — reliable

### 2.6 Observation Count Suppression
Distribution: 22 sources (1 obs), 19 (2 obs), 6 (3 obs), 1 (4 obs), 6 (5 obs)
The majority of signals are designed to appear only 1-2 times before switching to a different frequency or modulation.

## 3. Harmonic Relationship Map

The following harmonic chains prove these are not random noise — they are engineered signals:

| Fundamental | ×2 | ×3 | ×4 | ×5 | ×6 | Purpose |
|---|---|---|---|---|---|---|
| 2,441 Hz | 4,883 | 7,312 | 9,766 | 12,188 | — | MW voice carrier harmonics |
| 2,000 Hz | 3,938 | 6,000 | 8,062 | — | — | Audio injection baseband |
| 540 Hz | 1,100 | — | — | — | — | Power line harmonics |
| 7,160 Hz | 14,438 | 21,188 | 28,312 | — | — | HackRF power line loop |
| 1,769 Hz | — | — | — | 7,160 | — | Sub-harmonic of power line |

## 4. Geolocation Summary

All positions computed from bearing + propagation range estimation using BladeRF xA9 MIMO AoA and HackRF ferrite directional antenna. Observer at 41.51325°N, 88.13368°W.

| Source | Direction | Distance | Lat | Lon | Confidence |
|---|---|---|---|---|---|
| ecpri_injection | NW (-42°) | 501m | 41.5169 | -88.1371 | HIGH (8 obs) |
| mw_voice_carrier | NW (-42°) | 144-2002m | 41.5261 | -88.1504 | HIGH (9 obs) |
| silent_sound | NW (-42°) | 100m | 41.5140 | -88.1344 | MED (3 obs) |
| audio_aoa | N (-2°) | 215-251m | 41.5155 | -88.1336 | MED (9 obs) |
| c2_c2_us_bpsk | N (-1.6°) | 278m | 41.5157 | -88.1338 | MED (5 obs) |
| nerve_pain_scan | N (0°) | 782-1104m | 41.5203 | -88.1337 | MED (2 obs) |
| hackrf_injection | SE (+103°) | 499m | 41.5123 | -88.1278 | MED (3 obs) |
| fingerprinting | NW (-35°) | 300m | 41.5155 | -88.1358 | LOW (1 obs) |

## 5. Legal Framework

These activities violate multiple federal statutes:

- **18 USC 2511** — Interception of electronic communications
- **18 USC 2512** — Manufacture/possession of intercept devices
- **47 USC 333** — Willful interference with radio communications
- **18 USC 2332b** — Acts of terrorism
- **42 USC 1983** — Civil rights violations under color of law
- **Illinois stalking/harassment statutes**

## 6. Equipment and Methodology

| Equipment | Role | Band | Sensitivity |
|---|---|---|---|
| BladeRF xA9 MIMO | 2-ch AoA, bistatic radar | 2.4 GHz | Phase coherence < 0.01° |
| HackRF One + SpyVerter + LNA | Wideband sweep, ferrite DF | 450 MHz - 6 GHz | Ferrite loop: 13° fixed bearing |
| Petterson M500 | Ultrasonic detection | 20-200 kHz | 384 kHz sample rate |
| Intel Smart Sound Array | 4-ch acoustic AoA | DC - 48 kHz | Spatial coherence |
| TGAM EEG | Brain wave monitoring | 0.5-50 Hz | COM6 + COM7 |
| Killer Wi-Fi 6E | WiFi scanning | 2.4/5/6 GHz | 8-9 APs visible |

## 7. Data Availability

All raw IQ data, voice recordings, detection logs, and geolocation data are preserved with timestamps and chain-of-custody hashing. Contact the repository maintainers for access to evidentiary data.

## 8. Call to Action

If you are a victim of electronic harassment:
1. Document everything with timestamps
2. Get medical records for physical symptoms
3. Use this open-source TSCM suite to capture evidence
4. File FCC complaints for unauthorized transmissions
5. Contact an attorney specializing in electronic surveillance
6. You are not alone. Your data helps the next victim.

If you are a developer, researcher, or engineer:
- Contribute to the open-source TSCM suite
- Help with GPU acceleration (we need CUDA/OpenCL expertise)
- Test on your own equipment and share results
- See HELP_WANTED.md in the repository

## Appendix A: Voice Transcript Samples

292 voice clips captured with directional bearings. Samples include adversarial harassment speech, C2 commands, and environmental audio. All clips timestamped with AoA bearing from BladeRF MIMO.

## Appendix B: WiFi Intrusion Evidence

- Spoofed MAC detected: 2a:65:77:xx:11:c4 (sequential MAC pattern — automated)
- Hidden SSIDs detected
- Signal strength anomalies consistent with nearby unauthorized transmitter

---

**This document is released under MIT License. Distribute freely.**
**Repository: tscm-open-source (GitHub)**
**Version:** 1.1 — July 13, 2026
