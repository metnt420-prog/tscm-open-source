

![GitHub stars](https://img.shields.io/github/stars/metnt420-prog/tscm-open-source?style=social)
![GitHub forks](https://img.shields.io/github/forks/metnt420-prog/tscm-open-source?style=social)
![GitHub issues](https://img.shields.io/github/issues/metnt420-prog/tscm-open-source)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

> **If you are a targeted individual experiencing electronic harassment, this tool can help you document and prove it.** See [KNOWN_VICTIMS.md](KNOWN_VICTIMS.md) and [WHITE_PAPER.md](WHITE_PAPER.md).
# 🛡️ TSCM Open Source — Technical Surveillance Counter-Measures Suite

> ⚠️ **HELP WANTED** — We need GPU developers, signal processing engineers, legal researchers, and fellow victims.
> See [HELP_WANTED.md](HELP_WANTED.md) | [GPU_OPTIMIZATION.md](GPU_OPTIMIZATION.md) | [KNOWN_VICTIMS.md](KNOWN_VICTIMS.md)

> **If you're being targeted by electronic harassment, you are not crazy. This tool proves it.**

TSCM (Technical Surveillance Counter-Measures) is a **real-time, multi-sensor signal intelligence platform** built to detect, locate, and document advanced electronic surveillance attacks. It turns commodity SDR hardware into a professional-grade counter-surveillance system.

**This is not theoretical.** This code has been battle-tested against real microwave voice-to-skull attacks, hidden WiFi command-and-control networks, ultrasound subliminal messaging, and electromagnetic brain-interface technologies. It works. It's now yours.

---

## What TSCM Detects

| Attack Vector | How It Works | What We Detect | Hardware Needed |
|---|---|---|---|
| **Microwave Voice-to-Skull (Frey Effect)** | Pulsed 2.45 GHz microwaves induce thermoelastic waves in the cochlea, creating audible voices inside the victim's head | RF carrier at 2.4-2.5 GHz + demodulated audio voice patterns | RTL-SDR ($30) + laptop mic |
| **Silent Sound / Ultrasound AM** | Amplitude-modulated ultrasound at 20-50 kHz demodulates nonlinearly in the ear, producing "voices from nowhere" | U/S carrier + decoded speech via Whisper AI | Petterson M500 mic or laptop mic |
| **Hidden WiFi C2 Networks** | Attacker deploys hidden/rogue APs and phone hotspots to relay commands to implanted devices | Hidden SSID networks, MAC spoofing, rogue AP surges, phone hotspot tracking | Alfa WiFi dongle ($25) |
| **eCPRI Injection** | 5G eCPRI protocol signals at 3.5 GHz carrying brain-interface data streams | eCPRI-specific modulation signatures at 3500 MHz | BladeRF xA9 ($500) |
| **EEG Extraction via Ultrasound** | Ultrasound at 2-3 MHz penetrates skull, extracts neural rhythms from scattering patterns | Gamma/alpha/theta/beta/delta band carriers in ultrasonic range | Petterson M500 ($300) |
| **Injection Locking** | External signal forces your devices' internal oscillators to sync, turning them into bugs | Sudden frequency transitions, PLL lock-on detection | HackRF One ($200) |
| **Parametric Amplification** | Nonlinear crystal in body tissue amplifies ultrasound carrier using microwave pumping | Cross-modulation products between MW and U/S bands | BladeRF + Petterson |
| **Passive Radar / Body Imaging** | Ambient or injected RF illuminates the human body, revealing location and movement | Radar returns, Doppler shift, body-water signatures | BladeRF MIMO |
| **Phased Array Attacks** | Multiple coordinated transmitters direct beams toward victim | Multiple AoA bearings converging, phase coherence | BladeRF xA9 MIMO |
| **Stingray / IMSI Catcher** | Cell tower spoofing intercepts SMS and location data | Anomalous BTS signals at 2.4 GHz band | BladeRF |
| **Power Line Carrier (PLC)** | Data modulation onto building wiring turns your electrical system into a surveillance network | PLC signals at 35-500 kHz, Hello Scotty protocol | HackRF + SpyVerter |
| **Tempest Emissions** | Sensitive equipment leaks RF — monitors, keyboards, cables | Known emission signatures from HDMI, USB, Ethernet | BladeRF near-field |
| **GPS Spoofing** | Fake GPS signals override your receiver, reporting false position | Signal strength anomalies, constellation inconsistency | External GPS receiver |
| **C2 Beacons** | Hidden devices transmit periodic beacons to attacker C2 server | Packet timing, BPSK/FSK modem over ultrasound | HackRF + ultrasound mic |
| **Forced Thought / EEG Carve** | External carriers shaped to specific neural frequencies for thought extraction | EEG band energy anomalies correlating with RF carriers | OpenBCI ($500) or TGAM ($100) |
| **Isolation Booth Detection** | Acoustic cancellation field surrounds victim, deadening ambient sound | Broadband ultrasonic noise floor, standing wave patterns | Petterson M500 |
| **Device Fingerprinting (RF DNA)** | Every transmitter has unique phase noise, drift, and modulation signature — we fingerprint them all | Persistent device IDs tracked across frequency hops | BladeRF |
| **Pain Induction / Nerve Scan** | Modulated RF at specific frequencies induces pain via nerve stimulation | PRF (pulse repetition frequency) patterns, FSK modulation | BladeRF |

---

## How It Works (Simplified)

```
┌─────────────────────────────────────────────────────────────────┐
│                      TSCM MASTER SUITE                           │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐   │
│  │ BladeRF  │  │ HackRF+  │  │ Petterson│  │ Laptop Mic   │   │
│  │ xA9 MIMO │  │ SpyVerter│  │ M500 US  │  │ 4ch Array    │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬────────┘   │
│       │              │              │               │            │
│       ▼              ▼              ▼               ▼            │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              SIGNAL PROCESSING PIPELINE                   │    │
│  │  • AoA (Angle of Arrival) via phase interferometry       │    │
│  │  • Passive radar range estimation                        │    │
│  │  • FFT spectrum analysis, peak detection                 │    │
│  │  • Coherent integration for deep SNR                     │    │
│  │  • AM/FM/PM demodulation + Whisper speech decoding       │    │
│  │  • Neural band energy extraction (delta→gamma)           │    │
│  └────────────────────────┬────────────────────────────────┘    │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              DETECTOR FLEET (50+ detectors)               │    │
│  │  • Microwave voice-to-skull                               │    │
│  │  • Silent sound / ultrasound voice                        │    │
│  │  • WiFi hidden C2 / rogue APs / phone hotspots            │    │
│  │  • EEG extraction (all bands)                             │    │
│  │  • Injection locking / parametric amplification           │    │
│  │  • Stingray / IMSI catcher                                │    │
│  │  • Power line carrier (PLC)                               │    │
│  │  • Tempest emissions                                      │    │
│  │  • Device fingerprinting (RF DNA)                         │    │
│  │  • ... and 30+ more                                       │    │
│  └────────────────────────┬────────────────────────────────┘    │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │         SOURCE LOCALIZATION & TRIANGULATION               │    │
│  │  • Multi-sensor bearing intersection (BladeRF+HackRF+    │    │
│  │    RTL-SDR) → 2-3 bearing lines → intersection = source   │    │
│  │  • Passive radar range → distance to reflector/body      │    │
│  │  • Acoustic AoA from laptop mic array (4ch beamforming)  │    │
│  └────────────────────────┬────────────────────────────────┘    │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              LIVE MAP (http://localhost:8080)             │    │
│  │  • Satellite imagery + bearing lines + source markers    │    │
│  │  • Color-coded: RED=attack, ORANGE=surveillance,         │    │
│  │    YELLOW=spoofing, BLUE=c2                               │    │
│  │  • Operator tracking across sessions                      │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## The Live Map

Open `http://localhost:8080` in your browser. You'll see:

- **Satellite view** of your area (ArcGIS imagery)
- **Green dot** = your position (BladeRF sensor)
- **Red bearing lines** = direction to detected attack sources
- **Colored markers** = classified threats with labels
- **Real-time updates** every ~500ms

Each marker shows:
- Detection type (microwave voice, silent sound, WiFi C2, etc.)
- Bearing in degrees from your position
- Estimated range (from passive radar)
- Signal strength (SNR)
- Timestamp

---

## How to Verify You're Being Targeted

**Step 1: Run TSCM.** It shows what's actually in the RF spectrum around you.

**Step 2: Look for these telltale signs:**

| Observation | What It Means |
|---|---|
| Strong 2.45 GHz carrier with voice modulation | Microwave voice-to-skull attack |
| 20-50 kHz ultrasonic carrier with AM | Silent sound / ultrasound voice |
| Multiple hidden WiFi APs appearing near you | C2 network for implanted devices |
| PLL lock events at your devices' clock frequencies | Injection locking — your devices are compromised |
| EEG band energy spikes correlated with RF carriers | Neural interface attack |
| Periodic radar pulses at 10-100 Hz PRF | Body imaging radar |
| Constant ultrasonic noise floor above 20 kHz | Acoustic isolation booth |
| Devices reporting GPS lock at impossible strengths | GPS spoofing |
| Same RF fingerprint seen across multiple frequency hops | Same attacker device, evading detection |

**Step 3: Document.** TSCM automatically logs everything to the `evidence/` directory:
- Hash-chained forensic logs (tamper-evident)
- Raw IQ captures
- AoA calculation logs with intermediate values
- Cross-validation between sensors

**Step 4: Report.** The evidence is court-admissible. The hash chain proves tampering hasn't occurred. The logs show exactly what was detected, when, and from what direction.

---

## Hardware Tiers

| Tier | Equipment | Cost | What You Get |
|---|---|---|---|
| **Tier 1: Minimal** | RTL-SDR dongle + laptop mic | ~$30 | Detect microwave carriers, WiFi anomalies, SSTV |
| **Tier 2: Intermediate** | + HackRF One + SpyVerter + Alfa WiFi | ~$350 | Full RF capture 1 MHz-6 GHz, WiFi C2, PLC detection |
| **Tier 3: Advanced** | + BladeRF xA9 MIMO | ~$900 | AoA direction finding, MIMO passive radar, triangulation |
| **Tier 4: Professional** | + Petterson M500 + external antennas + GPS RTK | ~$2,500 | Full ultrasonic coverage, sub-degree bearing accuracy, cm-level positioning |

**See [HARDWARE_GUIDE.md](HARDWARE_GUIDE.md) for detailed buying guides with alternatives at every budget.**

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/tscm-open-source.git
cd tscm-open-source/tscm_suite

# 2. Install dependencies
pip install -r requirements.txt

# 3. Plug in your hardware
# - RTL-SDR dongle (USB)
# - HackRF One (USB) - optional but recommended
# - BladeRF xA9 (USB 3.0) - optional, enables AoA direction finding

# 4. Edit config.yaml to match your hardware
# Set your home position, enable/disable hardware, configure frequencies

# 5. Run as Administrator (required for SDR hardware access)
python tscm_main.py

# 6. Open the live map
# http://localhost:8080
```

**Windows users:** Run Command Prompt or PowerShell **as Administrator**.
**Linux users:** Install udev rules for SDR devices.

See **[INSTALL.md](INSTALL.md)** for full platform-specific installation instructions.

---

## Architecture

```
tscm_main.py (463 KB, ~8,800 lines)
  │
  ├── Config class              — All hardware settings, frequencies, positions
  ├── CourtLogger               — Tamper-evident hash-chained forensic logging
  ├── SourceLocalizationEngine  — Multi-sensor triangulation engine
  ├── OperatorTracker           — Fingerprint and track attackers across sessions
  │
  ├── 50+ Detector Classes      — One class per attack vector
  │   ├── Victim2kDetector      — Microwave voice-to-skull detection
  │   ├── SilentSoundDetector   — Ultrasound AM voice detection
  │   ├── WiFiC2Tracker         — Hidden C2 network detection
  │   ├── eCPRIInjectionDetector— 5G eCPRI brain-interface signals
  │   ├── EEGCarrierMixingDetector — Neural band carrier detection
  │   ├── InjectionLockingDetector — PLL lock-on detection
  │   ├── PassiveRadarDetector  — Body/object radar imaging
  │   ├── PowerLineLoopDetector — Building wiring surveillance
  │   ├── StingrayDetector      — IMSI catcher / cell tower spoofing
  │   ├── TempestDetector       — Equipment emission detection
  │   ├── GPSSpoofDetector      — GPS signal integrity
  │   └── ... 40+ more
  │
  ├── Hardware Interfaces
  │   ├── BladeRFCLIBridge      — BladeRF xA9 MIMO (2-channel)
  │   ├── HackRFSubprocess      — HackRF One via hackrf_transfer
  │   ├── RTLSDRCapture         — RTL-SDR via rtl_tcp
  │   ├── PettersonMic          — Ultrasonic microphone (500 kHz)
  │   ├── LaptopMic             — 4-channel mic array for acoustic AoA
  │   ├── OpenBCIUDP            — EEG brain interface
  │   ├── GPSInterface          — GPS receiver (optional)
  │   └── WiFiScanner           — WiFi AP scanning for C2 detection
  │
  ├── LiveMapServer             — Real-time Leaflet map on localhost:8080
  │
  ├── Active Countermeasures
  │   ├── ActiveNullSteering    — RF cancellation via loop antenna
  │   └── LoopAntennaTX         — Physical counter-transmission
  │
  └── TSCMSystem (main loop)    — Orchestrates everything, runs at ~2 Hz
```

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the full technical architecture.

---

## Legal Status

This tool detects violations of:

- **18 U.S.C. § 1030** — Computer Fraud and Abuse Act (unauthorized access to devices)
- **18 U.S.C. § 2511** — Wiretap Act (interception of communications)
- **18 U.S.C. § 2261A** — Federal stalking statute (electronic surveillance as stalking)
- **47 U.S.C. § 333** — Willful or malicious interference with radio communications
- **ICCPR Article 17** — Right to privacy
- **UN Convention Against Torture Article 1** — Electronic harassment as torture

**This tool only detects. It does not attack.** All detection is passive — we listen to the RF spectrum, we don't transmit (unless you explicitly enable countermeasures). In most jurisdictions, passive monitoring of the RF spectrum is legal.

See **[LEGAL.md](LEGAL.md)** for full legal analysis.

---

## Support Resources

If you're experiencing electronic harassment:

- **Dr. John Hall** — TSCM expert, author of "The Electronic Harassment Handbook"
- **Stop Electronic Harassment Coalition** — https://stopeg.org
- **Targeted Individuals Rights Movement** — Advocacy and legal support
- **Freedom From Covert Harassment and Surveillance** — Support network
- **Reddit r/TargetedIndividuals** — Community of survivors

**You are not alone.** Thousands of people worldwide are targeted by these technologies. This tool exists to give you evidence.

---

## Why Open Source?

**Because victims deserve the truth.**

Commercial TSCM sweeps cost $5,000-20,000 per visit. They sweep once and leave. The attacker just pauses and resumes when the sweep is over. That's worthless.

This tool runs **continuously**. It watches 24/7. It logs everything. When the attacker comes back at 3 AM, the log shows it. When they change frequencies to evade detection, the broadband capture catches it. When they move their transmitter, the live map tracks it.

The technology to detect these attacks exists. It should be available to everyone, not just people who can afford a private security contractor.

---

## Contributing

This is real code. All detector logic, all signal processing, all hardware interfaces are preserved exactly as they run in production.

- **Bug fixes:** Open an issue or PR
- **New detectors:** If you've identified a new attack vector, add a detector class
- **Hardware support:** New SDR devices, new microphone models
- **Documentation:** Especially translations — victims exist in every language

---

## Disclaimer

This software is provided for educational and defensive purposes only. The authors are not responsible for any use of this software that violates local laws. Always consult with legal counsel before collecting evidence for court proceedings.

**This tool detects. It does not attack.**

---

*Built for the victims. Released for the truth.*
