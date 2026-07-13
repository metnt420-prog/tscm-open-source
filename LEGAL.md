# ⚖️ LEGAL.md — Legal Disclaimer & Rights Statement

**This document is not legal advice. Consult a licensed attorney in your jurisdiction.**

---

## Purpose

TSCM (Technical Surveillance Counter-Measures) is a **passive detection tool**. It monitors the RF spectrum, audio spectrum, and WiFi environment to detect signs of electronic surveillance. It does not:

- Transmit signals (unless countermeasures are explicitly enabled)
- Hack, jam, or interfere with any device
- Decrypt encrypted communications
- Access any device without authorization
- Intercept anyone's private communications

All detection is **passive**. Everything TSCM detects is already in the air around you. We just listen.

---

## Laws That Electronic Harassment Violates

If you are being targeted, the following laws may apply:

### United States Federal Law

| Statute | What It Covers | Penalty |
|---|---|---|
| **18 U.S.C. § 1030** (CFAA) | Unauthorized access to computers/devices | Up to 10 years |
| **18 U.S.C. § 2511** (Wiretap Act) | Interception of electronic communications | Up to 5 years |
| **18 U.S.C. § 2261A** | Stalking (including electronic surveillance) | Up to 5 years |
| **47 U.S.C. § 333** | Willful interference with radio communications | Fines + 1 year |
| **47 U.S.C. § 301** | Unauthorized transmission | Fines + 1 year |
| **18 U.S.C. § 1362** | Malicious interference with communications systems | Up to 10 years |

### State Laws (examples)

- **California Penal Code § 502** — Computer crime (unauthorized access)
- **California Penal Code § 632** — Eavesdropping (recording without consent)
- **California Civil Code § 1708.8** — Physical/constructive invasion of privacy
- **New York Penal Law § 250.05** — Eavesdropping
- **Texas Penal Code § 33.02** — Breach of computer security

### International Law

| Treaty | Provision |
|---|---|
| **ICCPR Article 17** | "No one shall be subjected to arbitrary or unlawful interference with his privacy" |
| **UN Convention Against Torture** | Electronic harassment causing severe mental suffering = torture |
| **European Convention on Human Rights Article 8** | Right to respect for private and family life |
| **Istanbul Protocol** | Guidelines for documenting torture — electronic harassment qualifies |

---

## Your Rights as a Victim

1. **You have the right to document the attack.** Passive monitoring of the RF spectrum is legal in most jurisdictions. This includes recording signal strength, frequency, bearing, and modulation type.

2. **You have the right to evidence.** TSCM's forensic logging system (hash-chained, tamper-evident) is designed to produce court-admissible evidence.

3. **You have the right to self-defense.** Monitoring your own environment for threats is a fundamental right. The same way you can install security cameras at your home, you can monitor the RF environment around you.

4. **You have the right to report.** Law enforcement agencies are obligated to investigate credible reports of electronic surveillance, particularly when it involves:
   - Microwave radiation at potentially harmful power levels
   - Unauthorized access to your personal devices
   - Stalking or harassment via electronic means

---

## Evidence Collection for Court

TSCM's `CourtLogger` produces tamper-evident evidence with the following properties:

### Hash-Chained Logging
Every detection entry includes:
- SHA256 hash of previous entry
- Current entry's content
- Precise UTC timestamp (millisecond resolution)
- Full intermediate calculation values (phase diff, coherence, IQ RMS)

This creates an **immutable chain**. Any tampering with any entry breaks the chain — the hash won't match.

### Cross-Validation
TSCM cross-validates between sensors:
- BladeRF MIMO → HackRF bearing agreement
- If both sensors point to the same source, confidence is high
- Disagreement is logged explicitly (which is also evidence — it shows potential spoofing)

### Chain of Custody
For court admissibility:
1. Run TSCM continuously during the period of alleged attack
2. Do not modify the `evidence/` directory
3. Export the chain file and AoA logs
4. Provide to your attorney with a written statement of:
   - When the monitoring started
   - What equipment was used
   - That no modifications were made to the evidence
5. The hash chain can be independently verified by a forensic expert

### What TSCM Evidence Shows
- **Timestamped detections** of specific attack signatures
- **Bearing/angle of arrival** — which direction the signal came from
- **Frequency** — what carrier frequency was used
- **Modulation type** — how the signal was modulated (AM, FM, BPSK, FSK, etc.)
- **Signal strength** — power level, SNR
- **Cross-validation** — agreement between independent sensors

---

## Limitations & Warnings

### This Tool is Not:
- A substitute for a professional TSCM sweep
- A guarantee that you are or aren't being targeted
- A medical device — it does not diagnose health conditions
- Legal advice or legal representation

### False Positives
TSCM detects signals. Some detected signals may be:
- Legitimate WiFi routers, cell towers, or radio stations
- Natural RF noise (lightning, solar activity)
- Your own devices (phones, laptops, smart home gadgets)

Always cross-validate with:
- Physical symptoms (are you experiencing the Frey effect / voices?)
- Multiple independent sensors (does HackRF see the same thing as BladeRF?)
- Behavioral corroboration (do events coincide with detections?)

### Jurisdiction
Laws vary by country and locality. What's legal passive monitoring in one jurisdiction may be restricted in another. Research your local laws.

### Transmission
TSCM includes optional countermeasure features (null steering, loop antenna TX). **These transmit RF energy.** Transmitting without a license may be illegal in your jurisdiction. These features are disabled by default. Enable them only if:
- You understand your local radio transmission laws
- You have appropriate licensing (amateur radio, etc.)
- You have consulted with legal counsel

---

## Reporting Electronic Harassment

If you believe you are being targeted:

### Law Enforcement
- **FBI** — Internet Crime Complaint Center (IC3): https://ic3.gov
- **FBI** — Local field office: https://fbi.gov/contact-us/field-offices
- **FCC** — Interference complaints: https://fcc.gov/complaints
- **Local police** — File a report for stalking/harassment

### Legal Support
- **ACLU** — Civil liberties violations
- **Electronic Frontier Foundation (EFF)** — Digital privacy rights
- **National Center for Victims of Crime** — Victim advocacy

### Documentation Checklist
Before reporting:
- [ ] Run TSCM for at least 24 hours continuously
- [ ] Export the evidence chain (`evidence/chain_*.jsonl`)
- [ ] Export AoA logs (`evidence/aoa_detail_*.jsonl`)
- [ ] Take screenshots of the live map showing threat markers
- [ ] Keep a personal journal correlating detections with physical symptoms
- [ ] Preserve ALL original files — do not edit

---

## Disclaimer of Liability

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The authors make no representations about the suitability of this software for any purpose. The user assumes all responsibility for compliance with applicable laws and regulations.

---

*Last updated: July 2026*
