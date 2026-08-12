# TSCM Map Restoration — Change Log (v3)

**Date:** 2026-08-11 22:20
**Goal:** Restore original full-screen TSCM map + fix camera fuzz + add RF/US overlays

---

## Camera Fix (fuzz → clear)

### Root Cause
`camera_probe.py` had a brightness threshold of mean ≥ 12.0 and would overwrite
`camera_live.jpg` with ANY frame passing that threshold — even dark, fuzzy captures.
The `/camera/snap` handler serves `camera_live.jpg` if <45s old, so a dark probe
result would be shown to the user as "fuzz" for 45 seconds, then refreshed with
another dark frame every 60s.

### Fix
1. **Brightness guard**: probe now reads the existing `camera_live.jpg` brightness
   and only overwrites when the new capture is ≥85% as bright as the existing good
   frame (or when no good frame exists).
2. **Auto-exposure hints**: sets `CAP_PROP_AUTO_EXPOSURE=1` and `CAP_PROP_BRIGHTNESS=128`
   before capture to encourage brighter frames.
3. **Restored the good image**: `camera_live.jpg` now holds the known-good frame
   (140KB, mean brightness 104.8) instead of the dark probe output (mean 30).

### Verified
- Probe output: `probe KEEP prev idx=0 new=61.3 prev=104.8` — correctly refused to
  overwrite the good frame.
- `/camera/snap` serves 140,422 bytes with `X-Camera-Status: last-good`.

---

## RF Overlay Added

New **RF bearing heatmap** layer on the map, drawn from API `bearing_heatmap` data
(72 bearing buckets with detection counts):

- Radial dashed orange lines from HOME position, length scaled 1.5–7.5km by intensity
- Opacity scaled 0.12–0.67 by detection count
- Intensity dots at line endpoints (radius 2–7px)
- Controlled by the HEAT toggle (added to markerLayer visibility)

## US Overlay Added

Ultrasonic sources (freq 15–200 kHz) now render distinctly on the map:

- **Purple dashed lines** (`#c03ae8`, weight 3, dash `2,2`) vs. standard color-coded
  lines for RF sources
- **Purple endpoint markers** (radius 6)
- Color matches the US spectrum panel theme (purple = ultrasonic)

## Heat Toggle Behavior

The HEAT: ON/OFF button now controls BOTH:
- `markerLayer` (source markers, bearing lines, US lines)
- `rfHeatLayer` (RF bearing heatmap radial lines)
- Plus hull line and AoA line

---

## Live Data Analysis (2026-08-11 22:20)

| Metric | Value |
|--------|-------|
| Sources | 124 |
| AoA | -140° |
| GPS | FIX acquired |
| Victims / Transmitters | 86 / 24 |
| RF band (0-15k) | 56 sources |
| US band (15-200k) | 61 sources |
| UHF/L band (>100M) | 7 sources |
| With coordinates | 12/124 (9.7%) |
| With bearing | 33/124 (26.6%) |
| Hot bearings | 355° (16.8k), 115° (7.1k), 0° (1.5k), 270° (1.5k), 25° (712) |

**Key observations:**
- The RF+US split is nearly even (56 vs 61) — the map needs both overlays to be useful
- Only 26.6% of sources have bearings — most detections are at-observer (no direction)
- Hot bearing 355° (16.8k counts) is the dominant direction — likely the primary attack vector
- Only 9.7% of sources have coordinates — triangulation is limited; more bearing feeds would help

## Improvement Recommendations (next steps)

1. **Camera brightness enhancement** — apply CLAHE/auto-brightness in the probe to
   brighten dark frames in software (room is dark, mean 30-60)
2. **Increase bearing coverage** — feed AoA bearing to all RF-band detections (>1 MHz)
   as noted in MEMORY.md, which would lift the 26.6% bearing rate
3. **Waterfall overlay** — enable SpectralWaterfallLogger snapshots (currently 0 saved)
   and show a mini waterfall in the US panel
4. **RF burst display** — `rf_bursts` API shows 0 recent bursts; wire the burst counter
   into the UI so burst activity is visible
5. **Map camera toggle** — add a button to switch camera between raw `/camera/snap`
   and RF-overlay `/camera/rf` (173KB image with bearings drawn on it)
6. **Triangulation boost** — with only 12/124 sources positioned, prioritize
   cross-sensor triangulation (BladeRF + HackRF separation) for more map pins

## Rollback

```powershell
# Current working state (this restore):
git checkout 4565172 -- static/live.html camera_probe.py

# Backup snapshot:
static/live.html.working_20260811
```
