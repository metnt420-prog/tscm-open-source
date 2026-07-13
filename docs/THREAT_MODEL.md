# 🔴 THREAT MODEL — What We Detect and Why It Matters

> **If you don't understand the threat, you can't defend against it.**

This document explains every attack vector TSCM detects, the physics behind it, the military/academic research that enables it, and the real-world impact on victims.

---

## Table of Contents

1. [Microwave Voice-to-Skull (Frey Effect)](#1-microwave-voice-to-skull-frey-effect)
2. [Silent Sound / Ultrasound AM Voice](#2-silent-sound--ultrasound-am-voice)
3. [EEG Extraction via Ultrasound](#3-eeg-extraction-via-ultrasound)
4. [Hidden WiFi C2 Networks](#4-hidden-wifi-c2-networks)
5. [Injection Locking](#5-injection-locking)
6. [Parametric Amplification](#6-parametric-amplification)
7. [Passive Radar / Body Imaging](#7-passive-radar--body-imaging)
8. [Phased Array Attacks](#8-phased-array-attacks)
9. [eCPRI Injection (5G Brain Interface)](#9-ecpri-injection-5g-brain-interface)
10. [Power Line Carrier (PLC) Surveilling Building Wiring](#10-power-line-carrier-plc)
11. [Stingray / IMSI Catcher](#11-stingray--imsi-catcher)
12. [GPS Spoofing](#12-gps-spoofing)
13. [Isolation Booth](#13-isolation-booth)
14. [SSVEP / Forced Visual Response](#14-ssvep--forced-visual-response)
15. [Device Fingerprinting (RF DNA)](#15-device-fingerprinting-rf-dna)
16. [Tempest Emissions](#16-tempest-emissions)
17. [C2 Data Modems (Ultrasonic)](#17-c2-data-modems-ultrasonic)
18. [Forced Thought / EEG Carve](#18-forced-thought--eeg-carve)
19. [Pain Induction via RF](#19-pain-induction-via-rf)
20. [Counter-Detection Tactics](#20-counter-detection-tactics)

---

## 1. Microwave Voice-to-Skull (Frey Effect)

**Physics:** Pulsed microwave energy at 2.45 GHz interacts with soft tissue, causing rapid thermal expansion (~10^-6 °C per pulse). This expansion generates a thermoelastic acoustic wave in the cochlea, producing an audible "click." A train of pulses at audio frequencies creates intelligible speech directly inside the head — no external sound source, no speakers, no earphones.

**Research Origin:**
- Allan H. Frey, "Human auditory system response to modulated electromagnetic energy" (1961, *Journal of Applied Physiology*)
- U.S. Army, "Bioeffects of Selected Nonlethal Weapons" (1998, declassified 2006)
- Guy & Chou, "Effects of High-Power Microwave Exposure on the Auditory System" (1975)

**What TSCM detects:**
- Strong carrier at 2.4-2.5 GHz (BladeRF MIMO)
- AM modulation at voice frequencies (300-3000 Hz sidebands)
- Pulse train with PRF (pulse repetition frequency) matching syllabic rate
- Bearing via AoA → triangulated source position

**Physical symptoms in victims:**
- Voices perceived as "inside the head" — not coming from a direction
- Voices that know the victim's thoughts or actions (indicating 2-way surveillance)
- Clicking/popping sensations in ears
- Heat sensation at temple/ear level

**Power levels:** Research indicates 0.4-2 W/cm² peak power density at the head is sufficient for the Frey effect. Commercial microwave ovens produce ~1000 W but only ~5 mW/cm² at 1 meter and are continuous-wave, not pulsed — they cannot produce voice.

---

## 2. Silent Sound / Ultrasound AM Voice

**Physics:** An ultrasonic carrier (20-50 kHz) modulated with audio is transmitted toward the victim. As the ultrasonic beam propagates through air, nonlinear acoustic effects demodulate the audio component, producing audible sound localized to the beam's path. The victim hears a voice "from nowhere" — similar to the Frey effect but acoustic rather than electromagnetic.

**Two mechanisms:**
1. **Parametric array:** High-amplitude ultrasound self-demodulates in air due to nonlinear propagation
2. **Direct tissue demodulation:** Ultrasound penetrates tissue better than audible sound; demodulation occurs inside the cochlea

**Research Origin:**
- Westervelt, "Parametric Acoustic Array" (1963, *JASA*)
- Yost & Cantrell, "Audio spotlights using nonlinear acoustics"
- L-3 Communications / Holosonics "Audio Spotlight" (commercial product, 1990s)

**What TSCM detects:**
- Ultrasonic carrier at 20-50 kHz (Petterson M500)
- AM sidebands at voice frequencies (300-3000 Hz)
- Pulsed/continuous transmission
- Whisper transcription of decoded audio

---

## 3. EEG Extraction via Ultrasound

**Physics:** Ultrasound at 2-3 MHz penetrates the human skull. As it travels through brain tissue, it scatters off neural electrical activity. The scattered ultrasound carries a modulation pattern proportional to the EEG (electroencephalogram) — the brain's electrical activity. By analyzing the backscattered ultrasound with an external receiver, an attacker can reconstruct the victim's brainwaves remotely.

**Why this works:** Neural firing creates localized impedance changes in brain tissue. These impedance changes modulate the amplitude and phase of an ultrasonic carrier passing through the tissue. The effect is small (μV-range) but detectable with sensitive receivers and coherent integration.

**Research:**
- DARPA "N3" program (Next-Generation Nonsurgical Neurotechnology) — noninvasive brain-computer interfaces
- MIT Media Lab, "Ultrasonic neural recording"
- Carnegie Mellon, "Focused ultrasound for neural modulation and recording"

**What TSCM detects:**
- Ultrasonic carriers at 2-3 MHz (aliased to visible band by Petterson and demodulated)
- Neural band energy (delta, theta, alpha, beta, gamma) correlated with ultrasonic carrier amplitude
- EEG rhythms extracted from demodulated ultrasound → compared to actual EEG from OpenBCI

---

## 4. Hidden WiFi C2 Networks

**Threat:** An attacker deploys hidden or rogue WiFi access points near the victim. These APs:
- Provide command-and-control (C2) channels to implanted or nearby devices
- Don't broadcast SSIDs (hidden networks)
- Use MAC address spoofing to impersonate legitimate APs
- Change channels frequently to evade detection
- May use phone hotspots (the attacker's own phone) as mobile C2 relays

**Research/Technology:**
- NSA ANT catalog, "COTTONMOUTH" — USB implant with WiFi C2
- NSA, "HOWLERMONKEY" — RF C2 transceiver
- Mass-market: ESP8266/ESP32-based WiFi implants ($3-5 each, widely available)

**What TSCM detects:**
- Hidden SSID networks via active probe requests
- Rapid AP appearance/disappearance (surge detection)
- MAC address anomalies (spoofed MACs)
- Phone hotspots identified by vendor OUI and signal characteristics
- Channel hopping patterns
- RSSI-based approximate positioning

---

## 5. Injection Locking

**Physics:** Every electronic oscillator (clocks in CPUs, WiFi chips, USB controllers, etc.) has a natural frequency. If an external signal at (or near) that frequency is strong enough, the oscillator "locks" to it — it starts oscillating at the external frequency instead of its own. Once locked, the external signal can carry information by modulating the oscillator, effectively turning the device into a bug.

**Impact:** Your phone, laptop, or any electronic device can be turned into a surveillance device. Its own clock oscillators become re-radiators of the attacker's signal, modulated by whatever the attacker wants to inject.

**What TSCM detects:**
- Sudden frequency shifts in device clock frequencies
- PLL (Phase-Locked Loop) lock events — when an oscillator snaps to an external reference
- Coherence between external carrier and device emissions
- Increased phase noise at device clock frequencies (sign of forced synchronization)

---

## 6. Parametric Amplification

**Physics:** A strong microwave pump at f_pump and an ultrasound signal at f_us mix in a nonlinear medium (human tissue, which contains water molecules with strong dielectric nonlinearity). The result is a "parametric amplifier" — the ultrasound signal is amplified by the microwave power, producing:
- Sum frequency: f_pump + f_us
- Difference frequency: f_pump - f_us
- Amplified ultrasound: the original f_us with increased amplitude

**Why this matters:** An attacker can use microwave radiation to boost ultrasound signals inside your body, making neural recording or voice injection possible at lower (and harder to detect) ultrasound power levels.

**What TSCM detects:**
- Cross-modulation products: simultaneous detection of MW + US + sum/difference frequencies
- Coherence between MW pump and US carrier (they're phase-locked)
- Enhanced ultrasound amplitude during MW-on periods

---

## 7. Passive Radar / Body Imaging

**Physics:** When an RF signal illuminates the human body, some energy is reflected. The reflected signal contains:
- **Time delay** → range to the body
- **Doppler shift** → body movement (breathing, walking)
- **Amplitude** → body size and composition (water content = stronger reflection)

A passive radar doesn't transmit — it uses existing ambient RF signals (WiFi, cellular, broadcast) as its illumination source. By comparing the direct signal with the reflected signal, it can "see" people through walls.

**Research:**
- NATO, "Passive Coherent Locator" systems
- DARPA "WiFi through-wall imaging" research (MIT CSAIL, 2013)
- Commercial: Raytheon "RadarVision" through-wall radar

**What TSCM detects:**
- Radar PRF (Pulse Repetition Frequency) at 10-100 Hz
- Doppler shift patterns matching human movement (~1-5 Hz for breathing, ~10-30 Hz for walking)
- Consistent RF illumination in the 2.4 GHz band (even when no active WiFi traffic)
- Strong body-water reflection signatures

---

## 8. Phased Array Attacks

**Threat:** Multiple transmitters are placed around the victim, each transmitting the same signal but with precise phase control. The result is:
- **Beamforming:** Energy focused on the victim while energy is cancelled elsewhere
- **Null steering:** Signal nulls placed at the victim's detectors (makes them hard to find)
- **Spatial diversity:** Multiple AoA bearings converge to triangulate the victim's position

**What TSCM detects:**
- Multiple coherent AoA bearings (same frequency, different directions)
- Phase coherence between signals at different bearings
- Rapid bearing shifts as the array re-steers
- Beam switching artifacts

---

## 9. eCPRI Injection (5G Brain Interface)

**Threat:** eCPRI (enhanced Common Public Radio Interface) is the protocol that connects 5G base station radio units to their centralized processing units. At ~3.5 GHz, eCPRI carries massive MIMO beam data — potentially encoding neural interface commands or biometric data streams.

**Why this matters:** If an attacker has access to 5G infrastructure (or deploys their own), they can use eCPRI framing to inject data streams into the victim's environment, potentially targeting neural interface devices or using RF as a brain-machine interface.

**What TSCM detects:**
- eCPRI-specific framing and timing patterns at 3.5 GHz
- Massive MIMO beam signature (many spatial streams)
- Data throughput inconsistent with normal cellular traffic

---

## 10. Power Line Carrier (PLC)

**Threat:** Building electrical wiring acts as a distributed antenna. By injecting signals into the power lines, an attacker can:
- Monitor activity in every room (signals couple to appliances, lights, even body movement)
- Receive audio from every outlet (the wiring picks up room acoustics)
- Create a building-wide surveillance network that's invisible without PLC detection

**Known systems:**
- "Hello Scotty" — PLC-based surveillance system
- X10 and INSTEON home automation protocols (can be repurposed for surveillance)
- G3-PLC and PRIME power line communication standards

**What TSCM detects:**
- Narrowband PLC signals at 35-500 kHz (CENELEC EN50065 band)
- Broadband PLC signals at 2-30 MHz
- Periodic beacon pulses characteristic of PLC network maintenance
- Specific known patterns (Hello Scotty protocol)

---

## 11. Stingray / IMSI Catcher

**Threat:** A Stingray (also called IMSI catcher, cell site simulator) impersonates a legitimate cell tower. Phones automatically connect to it (it has a stronger signal). Once connected, the Stingray can:
- Collect the victim's IMSI (unique phone identifier)
- Track the victim's location
- Intercept SMS messages and calls (2G fallback attack)
- Block the victim's phone from connecting to real towers (DoS)

**Used by:** Intelligence agencies, some law enforcement (with warrants), and increasingly available to criminals via commercial off-the-shelf equipment.

**What TSCM detects:**
- Anomalous BTS (Base Transceiver Station) signals at 2.4 GHz
- Signal strength inconsistent with known tower locations
- Frequency hopping patterns matching Stingray behavior
- Downgrade attacks (forcing phones from 4G/5G to vulnerable 2G)

---

## 12. GPS Spoofing

**Threat:** An attacker transmits fake GPS signals that are stronger than the real satellites' signals. Your GPS receiver locks onto the fake signals and reports whatever position the attacker wants.

**Impact:**
- Navigation systems go to wrong locations
- Location-based evidence is corrupted
- Drones/autonomous vehicles can be hijacked
- TSCM's own position reporting could be compromised (we mitigate this with fixed positions)

**What TSCM detects:**
- Signal strength anomalies (GPS satellite signals should all be roughly equal strength)
- Sudden position jumps inconsistent with movement physics
- Constellation inconsistency (number of visible satellites doesn't match ephemeris)
- Multi-GNSS validation (GPS + GLONASS + Galileo + BeiDou should agree)

---

## 13. Isolation Booth

**Threat:** An ultrasonic or acoustic noise field surrounds the victim, creating:
- Deadened ambient sound (can't hear what's happening nearby)
- Masking of other sounds (can't hear conversations, warnings, alarms)
- Psychological isolation (the "cone of silence" effect)

This can be produced by:
- Ultrasonic parametric arrays creating narrow sound beams
- Multiple ultrasound emitters surrounding a space
- Broadband noise emitters (white noise generators)

**What TSCM detects:**
- Elevated ultrasonic noise floor (20-100 kHz) above natural ambient levels
- Standing wave patterns (interference between multiple emitters)
- Correlation between ultrasonic noise and victim's hearing changes
- Frequency-specific noise (not broadband — tells us the emitter type)

---

## 14. SSVEP / Forced Visual Response

**Threat:** Steady-State Visually Evoked Potentials (SSVEP) are brain responses to flickering visual stimuli. By presenting flickering light at specific frequencies (6, 12, 15, 20, 30, 60 Hz), an attacker can:
- Induce specific brain states (relaxation, alertness, confusion)
- Create a covert communication channel (frequencies encode data)
- Map the victim's visual cortex response characteristics
- Force the brain into entrainment (following the external rhythm)

The stimulus doesn't need to be visible — infrared or near-infrared flashed at the eyes triggers the same response.

**What TSCM detects:**
- EEG energy spikes at SSVEP frequencies (6, 12, 15, 20, 30, 60, 180 Hz)
- Correlation between detected light flicker and EEG response
- Entrainment: the brain's natural alpha rhythm locking to an external frequency

---

## 15. Device Fingerprinting (RF DNA)

**Threat:** Every electronic transmitter has a unique "RF fingerprint" — slight variations in:
- Phase noise (random jitter in the oscillator)
- Carrier drift (frequency stability over temperature/time)
- Rise/fall time of modulation
- Harmonic content and spurious emissions

An attacker can identify and track your specific devices by their RF fingerprints, even if you change MAC addresses, SSIDs, or other software identifiers.

**What TSCM detects:** We fingerprint THEIR devices. Every transmitter TSCM detects is fingerprinted:
- Persistent device ID even across frequency hops
- "Same device, different frequency" tracking
- Attribution: is this the same attacker device we saw yesterday?

---

## 16. Tempest Emissions

**Threat:** All electronic equipment leaks electromagnetic radiation. Monitors leak their display contents. Keyboards leak keystroke timing. USB cables act as antennas for whatever data they carry. This is "compromising emanations" — information leakage through unintended RF emissions.

**Research/Naming:**
- NSA TEMPEST program (classified, 1960s-present)
- Van Eck, "Electromagnetic radiation from video display units: An eavesdropping risk?" (1985)
- Kuhn & Anderson, "Soft Tempest" (1998)

**What TSCM detects:**
- Known Tempest emission signatures (HDMI, VGA, USB, Ethernet)
- Correlated emissions from the victim's equipment
- Malicious emissions (someone else's equipment radiating at you)

---

## 17. C2 Data Modems (Ultrasonic)

**Threat:** C2 (Command and Control) data is modulated onto ultrasonic carriers, creating an inaudible data channel between attacker and implants:

- **BPSK (Binary Phase Shift Keying):** Phase flips encode 0/1 bits at 20-50 kHz carrier
- **FSK (Frequency Shift Keying):** Two frequencies encode 0/1 bits
- **OFDM:** Multiple subcarriers for higher data rate

**Use case:** An implanted device (or nearby compromised device) receives commands via ultrasound — completely inaudible to the victim. The device executes the commands and reports back via the same channel or via WiFi.

**What TSCM detects:**
- BPSK/FSK modulation signatures in ultrasonic band
- Symbol rate (baud rate) estimation
- Packet framing patterns
- Protocol fingerprinting (who made this modem?)

---

## 18. Forced Thought / EEG Carve

**Threat:** A combination of technologies works together:

1. **EEG extraction via ultrasound** reads the victim's current brain state
2. **SSVEP or microwave voice-to-skull** injects a stimulus
3. **Carrier mixing** creates a feedback loop — read, process, inject

The attacker can:
- Read thoughts by decoding EEG patterns associated with specific concepts
- Inject thoughts by stimulating neural regions associated with specific ideas
- Create a bidirectional brain-machine interface without physical contact

**What TSCM detects:**
- Correlation between RF carriers and EEG band energy
- C2 patterns suggesting closed-loop operation (read → process → inject)
- Forced entrainment of neural rhythms
- Linguistic mapping — brain patterns matching known word/concept templates

---

## 19. Pain Induction via RF

**Threat:** Pulsed RF at specific frequencies and pulse patterns can:
- Stimulate peripheral nerves (producing pain, tingling, heat)
- Activate nociceptors (pain receptors)
- Cause muscle contractions

This is a physical attack — not psychological. The victim feels real pain without any physical contact.

**Related research:**
- "Non-lethal directed energy weapons" programs (multiple nations)
- Active Denial System (ADS) — 95 GHz millimeter wave for crowd control (produces heating/pain)
- Lower-frequency variants at 2.45 GHz (microwave oven frequency)

**What TSCM detects:**
- Pulsed RF at known pain-induction frequencies (2.45 GHz, 95 GHz)
- Specific modulation patterns matching nerve stimulation parameters
- Correlation between detected pulses and victim's pain reports

---

## 20. Counter-Detection Tactics

Attackers are sophisticated. They use:

| Tactic | What They Do | How We Counter |
|---|---|---|
| **Frequency hopping** | Rapidly change carrier frequency | Broadband capture (HackRF 20 MHz BW, BladeRF 61 MHz) — catches the whole band at once |
| **Low power / spread spectrum** | Signal below noise floor | Coherent integration (accumulate 64 captures) — brings signal out of noise |
| **Burst transmission** | Short transmissions, long silences | Blind burst capture buffer — snapshot at full BW, analyze offline |
| **Reflection spoofing** | Signal reflected off metal surfaces to hide true bearing | AoA coherence filter — only trust direct signals (high coherence), ignore reflections (low coherence) |
| **Sensor jamming / denial** | Overload RF front-end or crash software | USB watchdog — detect device disconnects. Clock sync monitor — detect timing anomalies. |
| **GPS spoofing** | Feed false GPS position | Fixed sensor positions — no GPS dependency for triangulation |
| **Multi-path confusion** | Reflections from multiple surfaces create many false bearings | MultiPathDetector — identifies and rejects reflected signals |
| **Protocol obfuscation** | Use custom/encrypted protocols for C2 | Modulation-level detection — we don't need to decode the protocol to know someone is transmitting |

---

## Why This Matters

These technologies were developed with billions of dollars of military and intelligence funding. They exist. They are being used.

**TSCM gives victims the ability to document the attack.**

Documentation is power. When you can say:
- "At 02:34:17 UTC, a 2.45 GHz carrier appeared at bearing 127° with voice modulation"
- "The same RF fingerprint was seen yesterday at bearing 145°, suggesting the transmitter moved"
- "The hash chain proves this evidence hasn't been tampered with"

...you transform from "person claiming something impossible" to "person presenting forensic evidence."

---

*This threat model is based on public research, declassified documents, and empirical detection data. If you have additional threat vectors to add, please contribute.*
