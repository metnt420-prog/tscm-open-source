# Changelog

## v1.2 (2026-07-13)

### New Features
- **7 new sweep bands**: VLF 100kHz, HF 15MHz, VHF 150MHz, ISM 915MHz, Cellular 850MHz, C-band 5.8GHz
- **Frequency Hopping Tracker**: Detects FHSS signals across sweep bands
- **Power Line Harmonic Detector**: Scans VLF/HF for 60Hz harmonics (PLC injection)
- **Evidence Snapshots**: Timestamped JSON every ~2 min for court chain-of-evidence
- **Bearing-only map display**: Dashed bearing lines, no false pins

### Bug Fixes
- False location markers eliminated (at_observer, bearing_range_est, 500m_est branches)
- Added `now = time.time()` at cycle start (NameError crash fix)
- FHSS tracker properly integrated into detection loop

### Distribution
- GitHub: https://github.com/metnt420-prog/tscm-open-source
- 5 public gists, 2 mirror repos, 7 issues, GitHub Pages

## v1.1 (2026-07-12)
- Initial release: 44 detectors, BladeRF/HackRF AoA, cross-sensor triangulation, live map
