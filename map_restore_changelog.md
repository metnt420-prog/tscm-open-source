# TSCM Map Restoration — Change Log (Final)

**Date:** 2026-08-11
**Goal:** Restore the original full-screen TSCM live tracking map with heatmap toggle

---

## Root Cause

The original working map was `tscm_suite/static/live.html` — a full-screen Leaflet map
with camera window, ultrasonic spectrum panels, detection sidebar, bearing lines,
convex hull, and range rings.

During the evening session (17:45+), a new top-level `static/live.html` was created
as a "QUAD RF v3" page — a different, stripped-down 2-column layout (RF polar plot
+ small map). The TSCM server (`tscm_final.py`) serves from the top-level
`static/live.html`, so users saw this wrong map instead of the original.

The "QUAD RF v3" page appeared black/broken because:
- Dark background (`#060608`) with small panels
- Map was in a half-width grid cell, not full-screen
- Marker opacity had been reduced to near-invisible levels
- Aggregate bearing heatmap was commented out

## What Was Done

### Fix: Replaced top-level `static/live.html` with the original `tscm_suite/static/live.html`

The original full-screen live tracking map is now served at `/live`. It includes:

| Feature | Details |
|---------|---------|
| **Full-screen Leaflet map** | 100vw × 100vh, OSM streets + Esri satellite + Google satellite layer toggle |
| **Camera window** | 220×126px preview in status panel (top-right), refreshes every 3s |
| **Ultrasonic spectrum** | Petterson M500 (0-192 kHz) + Laptop spatial array (0-24 kHz) spectrograms |
| **Detection sidebar** | Left panel with all sources, color-coded by detector type |
| **Bearing lines** | Dashed lines from home position to source endpoints |
| **Map markers** | Color-coded circle markers with rich tooltips (freq, bearing, classification) |
| **Convex hull** | Orange dashed polygon connecting outermost detection endpoints |
| **AoA line** | Red bearing line from home position |
| **Range rings** | 100m, 300m, 1km, 3km, 8km circles around home |
| **Hardware status** | BladeRF, HackRF, RTL-SDR, Petterson rates in status panel |
| **Keyboard shortcuts** | R=refresh, F=fit bounds, H=go home |

### Added: Heatmap toggle button

A "HEAT: ON/OFF" button in the status panel that toggles the detection overlay layer
(markers, bearing lines, convex hull, AoA line). Default: ON. Button opacity drops
to 0.5 when off.

### Kept: All v3 detectors

All 27+ parametric countermeasures detectors remain active in `tscm_final.py`:
ultrasonic_scan, carbon_interaction, silent_sound, low_ultrasound, nerve_pain_scan,
laptop_ultrasound, victim_2k, hidden_silent_sound, eardrum_capture,
hackrf_power_line_illuminator, fingerprinting, hackrf_injection_locking,
parametric_attack_confirmed, parametric_beat_pair, forced_thought, god_helmet,
ssvep, retinal_stress, ecpri_injection, eeg2video, eeg_voice_gamma,
mw_voice_carrier, rtlsdr_nesdr, wifi_wifi_channel_anomaly, injection_locking,
bladerf+hackrf, hackrf_ferrite, audio_aoa, hackrf_power_line_loop

## Verification (2026-08-11 22:04)

| Check | Result |
|-------|--------|
| Server listening | Port 8081 (8080 unavailable, suite auto-bound to 8081) |
| `/live` page | 200 OK, 17,561 bytes |
| heat-btn toggle | Present, `toggleHeat()` function defined |
| Camera feed | JPEG 140,422 bytes |
| API | 57 sources, AoA -140°, GPS fix, BladeRF ON, HackRF ON |
| Full-screen map | OSM + Esri + Google satellite layers |
| Camera window | Embedded in status panel |
| Ultrasonic spectrum | Petterson + Laptop canvases present |
| Detection sidebar | Present with source list |
| Bearing lines / hull / AoA | All rendered via markerLayer |

## Access

- **Map:** http://localhost:8081/live (or http://localhost:8081/ → redirects to /live)
- **Safe (no-JS):** http://localhost:8081/safe
- **Dashboard:** http://localhost:8081/dashboard

## Rollback

```powershell
# Current working version (this restore):
git checkout 1e33758 -- static/live.html

# The QUAD RF v3 page (broken, for reference):
git checkout c375f9c -- static/live.html

# Original tscm_suite version (pre-session, no heatmap toggle):
copy tscm_suite\static\live.html static\live.html
```

Backup snapshot: `static/live.html.working_20260811`
