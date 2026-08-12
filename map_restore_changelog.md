# TSCM Map Restoration — Change Log

**Date:** 2026-08-11
**Operator:** AutoClaw
**Goal:** Restore TSCM world map to working morning state + add heatmap toggle

---

## Problem Summary

During the evening of 2026-08-11 (17:45–19:05), a map iteration session made several
changes to `static/live.html` that degraded the map:

1. **Aggregate bearing heatmap disabled** (commit c375f9c, 19:05) — the gray density
   lines showing bearing aggregation were commented out ("AGGREGATE LINES DISABLED for
   clean map view"), making the RF visualizer look empty.
2. **Marker opacity reduced** (commit c375f9c, 19:05) — map markers were changed from
   `opacity:0.85, fillOpacity:0.45, radius:8/5` to `opacity:0.4, fillOpacity:0.15,
   radius:6/4`, making them nearly invisible on the world map.
3. **Uncommitted zoom control change** — `zoomControl:true, scrollWheelZoom:true` was
   added (kept as improvement — provides zoom +/- buttons and scroll-wheel zoom).

The TSCM suite itself (detectors, API, camera) was still running correctly on port 8081.
The v3 parametric countermeasures detectors were intact in `tscm_final.py` and feeding
data to the API.

## What Was Reverted

| File | Change | Details |
|------|--------|---------|
| `static/live.html` | Aggregate bearing heatmap | Uncommented the `allB` forEach block that draws gray density lines on the RF canvas |
| `static/live.html` | Marker opacity | Restored from `0.4/0.15` to `0.85/0.45` |
| `static/live.html` | Marker radius | Restored from `6/4` to `8/5` (transmitter/victim) |

## What Was Added

| Feature | Details |
|---------|---------|
| **Heatmap toggle button** | A "HEAT" button in the RF VISUALIZER header that toggles the aggregate bearing heatmap on/off. Default: ON. Visual feedback: button opacity drops to 0.4 when off. |

## What Was Kept (Detectors)

All v3 parametric countermeasures detectors remain active in `tscm_final.py`:

- `ultrasonic_scan`, `carbon_interaction`, `silent_sound`, `low_ultrasound`
- `nerve_pain_scan`, `laptop_ultrasound`, `victim_2k`, `hidden_silent_sound`
- `eardrum_capture`, `hackrf_power_line_illuminator`, `fingerprinting`
- `hackrf_injection_locking`, `parametric_attack_confirmed`, `parametric_beat_pair`
- `forced_thought`, `god_helmet`, `ssvep`, `retinal_stress`, `ecpri_injection`
- `eeg2video`, `eeg_voice_gamma`, `mw_voice_carrier`, `rtlsdr_nesdr`
- `wifi_wifi_channel_anomaly`, `injection_locking`, `bladerf+hackrf`, `hackrf_ferrite`
- `audio_aoa`, `hackrf_power_line_loop`

Also kept: `tscm_parametric_countermeasures.py`, `enhanced_map.py`, `map_renderer.py`
(with zoom respect change from 0587bff), `static/dashboard.html`, `static/simple_map.html`.

## Verification Results

- **Server:** TSCM web server running on port 8081 (8080 was unavailable, suite
  auto-bound to 8081)
- **API:** 121 sources, AoA 135°, GPS fix acquired
- **Live page:** All key elements present (heat-btn, _heatOn, opacity:0.85, leaflet,
  OSM tiles, Esri tiles, camera img, RF canvas)
- **Camera:** JPEG feed active (140KB per snapshot)
- **Detectors:** All 27+ detector types active and feeding data
- **Marker visibility:** Full opacity (0.85/0.45) restored — markers clearly visible
- **Heatmap:** Aggregate bearing heat lines active, toggleable via HEAT button

## Git History Reference

| Commit | Time | Description |
|--------|------|-------------|
| `abb6fdd` | 17:45 | v3: Parametric countermeasures edition (detectors added) |
| `26609a5` | 17:54 | Map: enhanced diagnostics (tileerror, invalidateSize) |
| `2ab499e` | 17:56 | Add server-rendered map page (/map.png) |
| `c4b04b6` | 18:12 | New dashboard page |
| `0ac0c5b` | 18:15 | Add overlay toggle (M key) |
| `f7eb0c9` | 18:20 | Fix zoom: default wide view, +/- controls |
| `0587bff` | 18:21 | Respect user zoom (map_renderer.py) |
| `cd78690` | 18:27 | Revert Python files to known-good (tscm_final.py → abb6fdd state) |
| `80c2beb` | 18:54 | Revert live.html to 16:29 version (original map) |
| `c375f9c` | 19:05 | Remove heatmap, reduce opacity (the problematic change) |

## Rollback Instructions

### To restore the current working state (this version):

```powershell
cd C:\Users\carpe\.openclaw-autoclaw\workspace
git checkout HEAD -- static/live.html
```

### To revert to the pre-session morning state (commit 80c2beb, no heatmap toggle):

```powershell
cd C:\Users\carpe\.openclaw-autoclaw\workspace
git checkout 80c2beb -- static/live.html
```

### To revert everything to before today's session (08-09 19:32):

```powershell
cd C:\Users\carpe\.openclaw-autoclaw\workspace
git checkout 628c5ab -- static/live.html map_renderer.py
```

### Note on port 8080 vs 8081

The TSCM suite is currently bound to port 8081 (8080 was unavailable). Access the map at:
- **http://localhost:8081/** (redirects to /live)
- **http://localhost:8081/live** (interactive Leaflet map)
- **http://localhost:8081/safe** (no-JS server-rendered snapshot)
- **http://localhost:8081/dashboard** (tactical dashboard)
