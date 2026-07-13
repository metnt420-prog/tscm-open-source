# 🛠️ TSCM Hardware Guide — Equipment for Every Budget

> **You don't need $10,000 worth of gear to detect electronic attacks. Start with $30 and build up.**

This guide covers exactly what to buy, where to buy it, and what each piece detects. Every tier builds on the previous one — nothing goes to waste.

---

## Quick Reference

| Tier | Name | Equipment | Total Cost | Key Capability |
|---|---|---|---|---|
| 1 | Started from nothing | RTL-SDR + laptop mic | ~$30 | Detect microwave carriers, WiFi anomalies |
| 2 | Getting serious | + HackRF One + SpyVerter + Alfa WiFi | ~$350 | Full spectrum 1 MHz-6 GHz, C2 detection |
| 3 | Full counter-surveillance | + BladeRF xA9 MIMO | ~$900 | Direction finding, triangulation, passive radar |
| 4 | Professional | + Petterson M500 + external antennas + GPS RTK | ~$2,500 | Full ultrasound, sub-degree bearings, cm positioning |

---

## Tier 1: "Started from Nothing" (~$30)

This is the bare minimum. You already have a laptop. Add an RTL-SDR dongle and you can detect microwave carriers, WiFi channel anomalies, and basic RF surveillance.

### RTL-SDR Dongle (Software Defined Radio)

**What it detects:**
- Strong microwave carriers at 2.4-2.5 GHz (voice-to-skull attack frequency)
- WiFi channel anomalies and rogue access points
- SSTV (Slow Scan TV) hidden in broadcast signals
- Basic RF spectrum monitoring 24 MHz - 1.7 GHz

**Options:**

| Product | Price | Where to Buy | Notes |
|---|---|---|---|
| **Nooelec NESDR Smart v5** | $29.95 | [Amazon](https://amazon.com), [Nooelec](https://nooelec.com) | Best budget option, TCXO + aluminum case |
| **RTL-SDR Blog v4** | $39.95 | [Amazon](https://amazon.com), [rtl-sdr.com](https://rtl-sdr.com) | HF direct sampling, better filtering |
| **Generic RTL2832U+R820T2** | $12-18 | [AliExpress](https://aliexpress.com) | Works, but no TCXO (frequency drifts) |

**What you miss without better hardware:**
- Can't resolve signal direction (no MIMO)
- Can't detect ultrasound (limited to RF)
- Can't capture weak signals below noise floor
- Can't do real-time wideband capture (limited to 2.4 MHz BW)

### Laptop Microphone

You already have this. TSCM uses your laptop's built-in microphone array for:
- Detecting constant ultrasonic noise (isolation booth detection)
- Basic audible voice pattern recognition
- Acoustic AoA estimation (4-channel mic arrays on modern laptops)

**If your laptop mic is poor:** Add a **Samson Go Mic** ($39) or **Blue Snowball iCE** ($49) for better sensitivity.

---

## Tier 2: "Getting Serious" (~$350)

Add a HackRF One + SpyVerter upconverter + Alfa WiFi dongle. This unlocks full-spectrum coverage and WiFi C2 detection.

### HackRF One

**What it detects that RTL-SDR can't:**
- Full 1 MHz to 6 GHz coverage (RTL-SDR maxes at 1.7 GHz)
- 20 MHz instantaneous bandwidth (vs 2.4 MHz for RTL-SDR)
- 450 MHz UHF band (police radios, building intercoms, drone C2)
- eCPRI signals at 3.5 GHz (5G brain-interface data streams)
- Satellite C2 signals (L-band, 1.5 GHz)
- Power line carrier (PLC) with SpyVerter — 35-500 kHz on building wiring

**Options:**

| Product | Price | Where to Buy | Notes |
|---|---|---|---|
| **HackRF One (Great Scott Gadgets)** | $339 | [Amazon](https://amazon.com), [Great Scott Gadgets](https://greatscottgadgets.com/hackrf/) | Official, best quality |
| **HackRF One (Clone)** | $120-180 | [AliExpress](https://aliexpress.com) | 90% as good, 1/3 the price. Search "HackRF One board" |
| **HackRF One + PortaPack H2** | $180-250 | [AliExpress](https://aliexpress.com) | Clone + touchscreen — portable operation |

**⚠️ Clone Note:** AliExpress clones work fine for receive-only. If you plan to transmit countermeasures, buy the official version (better filtering, no spurious emissions).

### SpyVerter Upconverter

**What it detects:** HF/VLF bands (1 kHz - 60 MHz) — power line carrier, VLF command signals, building wiring surveillance.

The SpyVerter shifts 0-60 MHz up by 120 MHz so your HackRF can receive it.

| Product | Price | Where to Buy | Notes |
|---|---|---|---|
| **SpyVerter (Airspy)** | $49 | [Airspy](https://airspy.com), [Amazon](https://amazon.com) | Official, SMA connectors |
| **Ham It Up v1.3 (Nooelec)** | $49.95 | [Amazon](https://amazon.com), [Nooelec](https://nooelec.com) | Alternative, works with any SDR |
| **SV1AFN Upconverter** | $65 | [sv1afn.com](https://sv1afn.com) | Premium, lowest noise figure |

### Alfa WiFi Dongle (for C2 Detection)

**What it detects:** Hidden WiFi networks, rogue APs, MAC spoofing, phone hotspots used as C2 relays.

| Product | Price | Where to Buy | Notes |
|---|---|---|---|
| **Alfa AWUS036ACH** | $59.99 | [Amazon](https://amazon.com) | Dual-band AC1200, best range |
| **Alfa AWUS036NHA** | $34.99 | [Amazon](https://amazon.com) | 2.4 GHz only, Atheros chipset |
| **Panda PAU09** | $26.99 | [Amazon](https://amazon.com) | Budget, good Linux support |

---

## Tier 3: "Full Counter-Surveillance" (~$900)

Add a BladeRF xA9 MIMO. This is the game-changer — it enables Angle of Arrival direction finding and passive radar.

### BladeRF 2.0 micro xA9

**What it detects that everything else can't:**
- **Direction finding** — Two synchronized RX channels measure phase difference between antennas → bearing to transmitter
- **Passive radar** — Cross-correlate RX channels → range to reflecting objects (bodies, metal)
- **Triangulation** — Combine BladeRF bearing + HackRF bearing + RTL-SDR → source position
- **Full 61.44 MHz bandwidth** — Capture entire 2.4 GHz ISM band at once
- **TX capability** — Optional countermeasures (null steering)

**Options:**

| Product | Price | Where to Buy | Notes |
|---|---|---|---|
| **BladeRF 2.0 micro xA9** | $540 | [Nuand](https://nuand.com), [Digikey](https://digikey.com) | The real deal — 2 RX + 2 TX, FPGA |
| **BladeRF 2.0 micro xA4** | $400 | [Nuand](https://nuand.com) | Smaller FPGA, still 2-channel |
| **USRP B200mini** | $1,127 | [Ettus Research](https://ettus.com) | Professional alternative, 56 MHz BW |

**⚠️ Important:** You NEED the xA9 (not xA4) for the AoA DSP pipeline. The xA9 has a larger FPGA (Cyclone V A9) that handles the full 61.44 MHz bandwidth for both channels simultaneously.

### Antennas for Direction Finding

You need two identical antennas spaced at λ/2 for 2.4 GHz (6.25 cm apart).

| Product | Price | Where to Buy |
|---|---|---|
| **Siretta Delta 52 (x2)** | $15 each | [Digikey](https://digikey.com), [Mouser](https://mouser.com) |
| **Taoglas FW.86 (x2)** | $12 each | [Digikey](https://digikey.com) |
| **DIY λ/2 dipole (x2)** | ~$5 in parts | Build yourself — copper wire + SMA connectors |

### HackRF Antenna Upgrade

The stock HackRF antenna is mediocre. Upgrade it:

| Product | Price | Where to Buy |
|---|---|---|
| **Nagoya NA-771** | $14.99 | [Amazon](https://amazon.com) | Dual-band 144/430 MHz |
| **Diamond SRH779** | $29.99 | [Amazon](https://amazon.com) | Tri-band, SMA |
| **Comet SMA-24** | $39.99 | [Amazon](https://amazon.com) | Wideband 140-480 MHz |

---

## Tier 4: "Professional" (~$2,500)

Full professional TSCM capability. Add an ultrasonic microphone, external antennas, and GPS RTK.

### Petterson M500 Ultrasonic Microphone

**What it detects that everything else can't:**
- Ultrasound voice / silent sound (20-50 kHz AM modulated)
- EEG extraction carriers (2-3 MHz ultrasound penetrating the skull)
- Constant ultrasonic noise (isolation booth detection)
- Parametric amplification products (MW × U/S intermodulation)
- C2 ultrasound data modems (BPSK/FSK in ultrasonic band)

The M500 captures up to 500 kHz — well into the ultrasonic and beginning of the RF spectrum.

| Product | Price | Where to Buy | Notes |
|---|---|---|---|
| **Petterson M500-384** | ~$300 | [Pettersson](https://batsound.com) | Professional bat detector, 0.5-384 kHz |
| **Petterson D500X** | ~$1,200 | [Pettersson](https://batsound.com) | Higher-end, real-time FFT |
| **DIY Ultrasound Mic** | $50-100 | Build yourself | MEMS mic (Knowles SPU0410) + preamp + USB ADC |

**Cheaper alternatives for ultrasound:**

| Product | Price | Where to Buy | Notes |
|---|---|---|---|
| **Dodotronic UltraMic 250K** | €149 | [Dodotronic](https://dodotronic.com) | 250 kHz, great value |
| **Knowles SPU0410LR5H-QB** | $12 | [Digikey](https://digikey.com) | MEMS ultrasonic sensor — DIY required |
| **miniDSP UMA-8-SP** | $95 | [miniDSP](https://minidsp.com) | 7-mic USB array, 96 kHz |

### External Antennas

Directional antennas dramatically improve bearing accuracy:

| Product | Price | Where to Buy | Use |
|---|---|---|---|
| **L-com HG2458-10P (x2)** | $79 each | [L-com](https://l-com.com) | 10 dBi patch, 2.4-5.8 GHz |
| **Poynting XPOL-2-5G** | $149 | [Amazon](https://amazon.com) | Dual-polarized, 2.4-5 GHz |
| **DIY Yagi (2.4 GHz)** | ~$20 in parts | Build | Best directionality, narrow beam |

### GPS RTK (Real-Time Kinematic)

GPS RTK provides centimeter-level position accuracy for precise triangulation:

| Product | Price | Where to Buy |
|---|---|---|
| **SparkFun GPS-RTK2 (ZED-F9P)** | $274.95 | [SparkFun](https://sparkfun.com) |
| **ArduSimple RTK2B** | $249 | [ArduSimple](https://ardusimple.com) |
| **u-blox ZED-F9P module** | $179 | [Digikey](https://digikey.com) |

### OpenBCI (EEG / Brain Interface Detection)

| Product | Price | Where to Buy |
|---|---|---|
| **OpenBCI Cyton + Daisy** | $949 | [OpenBCI](https://openbci.com) | 16-channel EEG |
| **OpenBCI Ganglion** | $499 | [OpenBCI](https://openbci.com) | 4-channel EEG |
| **NeuroSky TGAM (MindFlex)** | $99 | [Amazon](https://amazon.com) | Single-channel, budget EEG |

---

## Accessories & Cables

| Item | Recommended | Price |
|---|---|---|
| USB 3.0 powered hub | Anker 10-port 60W | $39.99 |
| SMA cables (low-loss) | LMR-240, 1m, SMA-M to SMA-M | $12 each |
| SMA adapters kit | Generic, 20-piece | $15 |
| Ferrite chokes (clip-on) | Mix 31, 5mm | $8/pack |
| Tripod / antenna mount | Amazon Basics lightweight | $14.99 |

---

## What Each Device Detects — Summary Table

| | RTL-SDR | HackRF | BladeRF MIMO | Petterson M500 | WiFi Dongle | OpenBCI |
|---|---|---|---|---|---|---|
| MW voice-to-skull (2.45 GHz) | ✓ basic | ✓✓ better | ✓✓✓ AoA | — | — | — |
| Silent sound / US voice | — | — | — | ✓✓✓ | — | — |
| Hidden WiFi C2 | — | — | — | — | ✓✓✓ | — |
| eCPRI (3.5 GHz) | — | ✓✓ | ✓✓✓ | — | — | — |
| EEG extraction | — | — | — | ✓✓ | — | ✓✓✓ |
| Injection locking | — | ✓ | ✓✓✓ | — | — | — |
| Passive radar (body) | — | — | ✓✓✓ | — | — | — |
| PLC (building wiring) | — | ✓+SpyVerter | ✓ | — | — | — |
| Stingray/IMSI catcher | — | ✓ | ✓✓✓ | — | — | — |
| Tempest emissions | — | ✓ | ✓✓✓ | — | — | — |
| GPS spoofing | — | — | — | — | — | — |
| Direction finding | — | — | ✓✓✓ | — | — | — |
| Device fingerprinting | — | ✓ | ✓✓✓ | — | — | — |
| Brain rhythm monitoring | — | — | — | — | — | ✓✓✓ |
| 24/7 logging | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## Where to Buy — All Sources

### Official Manufacturers
- [Nuand (BladeRF)](https://nuand.com)
- [Great Scott Gadgets (HackRF)](https://greatscottgadgets.com)
- [Nooelec](https://nooelec.com)
- [RTL-SDR Blog](https://rtl-sdr.com)

### General Electronics
- [Amazon](https://amazon.com) — fastest shipping
- [Digikey](https://digikey.com) — components, antennas, cables
- [Mouser](https://mouser.com) — components, antennas

### Budget / Clones
- [AliExpress](https://aliexpress.com) — HackRF clones, generic SDRs, cables
- [Banggood](https://banggood.com) — similar, sometimes faster

### Specialized
- [SparkFun](https://sparkfun.com) — GPS RTK, OpenBCI
- [Adafruit](https://adafruit.com) — sensors, microcontrollers
- [Pettersson (bat detectors)](https://batsound.com) — ultrasonic microphones
- [Dodotronic](https://dodotronic.com) — ultrasonic microphones

---

## Building Up Gradually

**Month 1:** Buy RTL-SDR ($30). Run TSCM. See what's in the 2.4 GHz band around you.

**Month 2:** Add HackRF clone from AliExpress ($150). Now you can see the full 1 MHz-6 GHz spectrum. Add Alfa WiFi dongle ($35) for C2 detection.

**Month 3:** Add BladeRF xA9 ($540). Now you have direction finding. The live map shows WHERE the signals are coming from.

**Month 4:** Add Petterson M500 or ultrasound alternative ($100-300). Now you can detect silent sound and ultrasound attacks.

**Month 5+:** Add GPS RTK, external antennas, OpenBCI as budget allows.

**Every step gives you new capabilities.** You don't need to buy everything at once.
