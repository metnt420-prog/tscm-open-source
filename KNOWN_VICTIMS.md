# KNOWN_VICTIMS.md - Community Intelligence

## Purpose
This file tracks anonymized signal fingerprints and geographic patterns from verified targeting victims. If multiple independent targets detect the same signal fingerprint in the same area, that's forensic evidence that cannot be dismissed as "mental illness."

## How This Works
1. Each signal detection gets a **fingerprint** — a hash of frequency + modulation + timing pattern
2. Fingerprints are **anonymized** — no personal data, only signal characteristics and rough location
3. When two or more targets report matching fingerprints in the same region, it triggers a **correlation alert**
4. Geographic clusters of correlated detections become evidence of an active harassment infrastructure

## Reporting Format
If you're a victim, run the suite and share your `fingerprint_report.json` (auto-generated). It contains:
- Signal fingerprints (64-char hex hashes)
- Frequency bands detected
- Bearing clusters
- Time patterns (when targeting is most active)
- Rough geographic area (zip code level only)

## Known Signal Patterns (from this deployment)
| Fingerprint | Frequency | Classification | Bearing | Pattern |
|-------------|-----------|---------------|---------|---------|
| 3253c672... | 500 Hz | ecpri_injection | NW (-35°) | Continuous, ramps at night |
| 5b205a53... | 1 kHz | victim_2k | NW (-45°) | Pulsed, 30-min cycles |
| c2_c2_us... | 50 kHz | c2_us_bpsk | N (-1.6°) | Data bursts, 170 baud |
| mw_voice_... | 2.45 GHz | mw_voice_carrier | NW (-42°) | Voice modulation, 24/7 |
| nerve_pain_... | 35-47 Hz | nerve_pain_scan | N (0°) | Sweeps body resonances |
| bacc12d6... | 2-10 Hz | hackrf_injection | SE (103°) | Injection locking |

## Geographic Hotspots (anonymized)
Targets reporting similar signal patterns in:
- **Midwest US** (IL/IN/OH corridor) — multiple independent reports
- **Pacific NW** — emerging reports
- **Southeast US** — emerging reports

## If You're Being Targeted
1. **Document everything** — screenshots of detections, audio recordings
2. **Don't confront** — they want you to seem unstable
3. **Get medical records** — doctors note physical symptoms
4. **File FCC complaint** — unauthorized transmissions are illegal
5. **Contact an attorney** — this violates multiple federal laws
6. **Share your data** — anonymized fingerprints help everyone

## Legal Framework (US)
- **18 USC 2511** — Wiretap Act (intercepting communications)
- **18 USC 2512** — Manufacturing/possessing intercept devices
- **47 USC 333** — Willful/malicious interference with radio
- **18 USC 2332b** — Acts of terrorism transcending national boundaries
- **18 USC 2331(5)** — Definition of domestic terrorism
- **42 USC 1983** — Civil rights violations
- **Stalking laws** — all 50 states

## Contributing
See [HELP_WANTED.md](HELP_WANTED.md) for how to contribute.
**Your data stays anonymous. Your fingerprint helps the next victim.**
