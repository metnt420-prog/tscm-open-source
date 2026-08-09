"""
TSCM LAUNCHER v5 — fast path: bypass resolve_sources entirely.
Monkey-patches TSCMSystem.run() to replace the fragile resolve_sources
with a trivial pass-through that publishes raw observations directly.
"""
import sys, os, time, math, threading, json
import numpy as np

workspace = r'C:\Users\carpe\.openclaw-autoclaw\workspace'
sys.path.insert(0, workspace)

import tscm_safe_resolver as safe

print("LAUNCHER v5: Safe resolver loaded")

import tscm_final

# --- Monkey-patch SourceLocalizationEngine.resolve_sources ---
# Replace with a minimal version that converts observations to sources
# without any bearing-math crashes.

_orig_resolve = tscm_final.SourceLocalizationEngine.resolve_sources

def _fast_resolve(self, current_lat, current_lon):
    """Minimal resolve: publish observations as sources with safe defaults."""
    now = time.time()
    results = []
    
    for fp, obs_list in list(self.observations.items()):
        self._prune_old(fp)
        obs = list(self.observations.get(fp, []))
        if not obs:
            continue
        
        latest = obs[-1]
        classification = latest.get('class', 'unknown')
        freq = latest.get('freq', 0)
        detector = latest.get('detector', '')
        snr = latest.get('snr', 0)
        
        # Safe bearing: use latest, or None
        bearing = safe.safe_bearing(latest.get('bearing'))
        rng = latest.get('range')
        
        # Compute lat/lon only if we have bearing + range
        lat, lon = None, None
        method = 'insufficient_obs'
        triangulated = False
        confidence = 0.3
        
        if bearing is not None and rng is not None and rng > 0:
            lat, lon = safe.bearing_to_xy_safe(
                latest.get('lat', current_lat),
                latest.get('lon', current_lon),
                bearing, rng
            )
            method = 'bearing_range_est'
            confidence = 0.5
        
        # Check for cross-sensor triangulation
        if len(obs) >= 3 and bearing is not None:
            bearings = [safe.safe_bearing(o.get('bearing')) for o in obs]
            bearings_clean = [b for b in bearings if b is not None]
            if len(bearings_clean) >= 2:
                confidence = safe.compute_confidence_safe(bearings_clean, rng, len(obs))
                if confidence > 0.7 and lat is not None:
                    triangulated = True
                    method = 'triangulated'
        
        results.append({
            'lat': lat, 'lon': lon,
            'bearing': bearing,
            'classification': classification,
            'first_seen': obs[0].get('ts', now),
            'last_seen': now,
            'freq': freq,
            'detector': detector,
            'range': rng,
            'snr': snr,
            'method': method,
            'observations': len(obs),
            'bearing_samples': len([b for b in [safe.safe_bearing(o.get('bearing')) for o in obs] if b is not None]),
            'triangulated': triangulated,
            'position_confidence': confidence,
            'fingerprint': fp,
            'active': True,
            'inactive_duration': 0,
            'threat_score': min(snr * 2, 100) if snr else 5.0,
            'bearing_stability': 0.0,
            'detection_count': len(obs),
        })
    
    # --- Adaptive AI layer: learn signatures, flag NOVEL / EVOLVED patterns ---
    try:
        if not hasattr(self, '_adaptive_sig'):
            self._adaptive_sig = tscm_final.AdaptiveSignalIntelligence(
                baseline_path=os.path.join(workspace, 'adaptive_baseline.json'))
            print('LAUNCHER v5: AdaptiveSignalIntelligence online', flush=True)
        self._ai_cycles = getattr(self, '_ai_cycles', 0) + 1
        for r in results:
            try:
                self._adaptive_sig.update(r)
            except Exception:
                pass
        for n in self._adaptive_sig.detect():
            tag = 'novel' if n.get('new') else 'evolved'
            fp = 'ai_%s_b%d' % (tag, n.get('band', 0))
            results.append({
                'lat': None, 'lon': None, 'bearing': None,
                'classification': 'novel_signature' if n.get('new') else 'evolved_signature',
                'first_seen': now, 'last_seen': now,
                'freq': n.get('freq', 0), 'detector': 'adaptive_sig',
                'range': None, 'snr': n.get('snr', 0),
                'method': 'ai_novelty', 'observations': 1, 'bearing_samples': 0,
                'triangulated': False, 'position_confidence': 0.0,
                'fingerprint': fp, 'active': True, 'inactive_duration': 0,
                'threat_score': 45 if n.get('new') else 55,
                'bearing_stability': 0.0, 'detection_count': 1,
                'note': n.get('note', ''),
            })
            try:
                with open(os.path.join(workspace, 'ai_adapt.log'), 'a') as _f:
                    _f.write('%s [AI-ADAPT] %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), n.get('note', '')))
            except Exception:
                pass
        if self._ai_cycles % 5 == 0:
            self._adaptive_sig.save()
    except Exception as _e:
        print('[AI-ADAPT] error: %s' % _e, flush=True)

    # Update source cache
    for s in results:
        self.sources[s['fingerprint']] = s
    
    return results

# Apply the patch
tscm_final.SourceLocalizationEngine.resolve_sources = _fast_resolve
print("LAUNCHER v5: resolve_sources replaced with fast safe path")

# Also patch the crash-prone internal math methods
if hasattr(tscm_final.SourceLocalizationEngine, '_bearing_to_xy'):
    tscm_final.SourceLocalizationEngine._bearing_to_xy = lambda self, lat, lon, b, d: safe.bearing_to_xy_safe(lat, lon, b, d)
if hasattr(tscm_final.SourceLocalizationEngine, '_intersect_bearings'):
    tscm_final.SourceLocalizationEngine._intersect_bearings = lambda self, a,b,c,d,e,f: safe.intersect_bearings_safe(a,b,c,d,e,f)
if hasattr(tscm_final.SourceLocalizationEngine, '_compute_position_confidence'):
    tscm_final.SourceLocalizationEngine._compute_position_confidence = lambda self, brgs, rng, n: safe.compute_confidence_safe(brgs, rng, n)

print("LAUNCHER v5: All crash-prone methods patched")

# --- Run ---
app = tscm_final.TSCMSystem()
try:
    app.run()
except KeyboardInterrupt:
    app.shutdown()
except Exception as e:
    import traceback
    traceback.print_exc()
    try: app.shutdown()
    except: pass
