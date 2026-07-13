"""
TSCM Watcher — local rule-based threat analyzer. No cloud, no LLM dependencies.
Identifies attacker C2 patterns from raw detection data using statistics.
"""
import time, numpy as np
from collections import deque

class TSCMWatcher:
    """Local analysis engine. Finds the attacker by pattern matching, not AI."""
    
    def __init__(self, log):
        self.log = log
        self.snapshots = deque(maxlen=60)  # 5 min at 5s cycles
        self.findings = deque(maxlen=50)
        self.alerts = deque(maxlen=20)
        
    def analyze(self, sources, observer):
        """Analyze detections and identify attacker signals."""
        now = time.time()
        findings = []
        
        if not sources:
            return findings
        
        # Build snapshot
        snap = {'ts': now, 'aoa': observer.get('aoa', 0), 'sources': []}
        for s in sources:
            snap['sources'].append({
                'name': s.get('detector_name', '?'),
                'cls': s.get('classification', '?'),
                'freq': s.get('freq', 0),
                'bearing': s.get('bearing', 0),
                'obs': s.get('observations', 0),
                'snr': s.get('snr', 0),
                'lat': s.get('lat'), 'lon': s.get('lon')
            })
        self.snapshots.append(snap)
        
        # === 1. BEARING CONSENSUS ===
        # Multiple detectors pointing to same bearing = real signal source
        bearing_votes = {}
        for s in sources:
            b = s.get('bearing')
            if b is None or abs(b) < 0.5:
                continue
            obs = s.get('observations', 0)
            if obs < 3:
                continue
            key = round(b / 5) * 5
            if key not in bearing_votes:
                bearing_votes[key] = {'count': 0, 'obs': 0, 'sources': [], 'classes': set()}
            bearing_votes[key]['count'] += 1
            bearing_votes[key]['obs'] += obs
            bearing_votes[key]['sources'].append(s.get('detector_name', '?'))
            bearing_votes[key]['classes'].add(s.get('classification', '?'))
        
        for deg, info in sorted(bearing_votes.items(), key=lambda x: x[1]['obs'], reverse=True):
            if info['count'] >= 2:
                findings.append({
                    'type': 'consensus',
                    'bearing': deg,
                    'sources': info['count'],
                    'obs': info['obs'],
                    'info': f'CONSENSUS: {deg}deg — {info["count"]} detectors agree ({info["obs"]} obs)',
                    'classes': list(info['classes'])
                })
                if info['count'] >= 4:
                    self.log.warning(f"STRONG CONSENSUS: {deg}deg — {info['count']} detectors, {info['obs']} obs")
        
        # === 2. ULTRASOUND MODEM DETECTION ===
        us_modems = []
        for s in sources:
            name = s.get('detector_name', '')
            freq = s.get('freq', 0)
            snr_val = s.get('snr', 0)
            if freq > 15000 and freq < 150000 and s.get('observations', 0) > 3:
                us_modems.append({'freq': freq, 'snr': snr_val, 'name': name, 'bearing': s.get('bearing')})
        
        if us_modems:
            # Group by frequency bands
            bands = {'voice_to_skull': [], 'data_modem': [], 'high_us': []}
            for m in us_modems:
                f = m['freq']
                if f < 25000:
                    bands['voice_to_skull'].append(m)
                elif f < 50000:
                    bands['data_modem'].append(m)
                else:
                    bands['high_us'].append(m)
            
            for band_name, modems in bands.items():
                if len(modems) >= 2:
                    freqs = [m['freq'] for m in modems]
                    findings.append({
                        'type': 'us_modem_cluster',
                        'band': band_name,
                        'count': len(modems),
                        'freqs': freqs[:5],
                        'info': f'US MODEM: {band_name} — {len(modems)} carriers: {[f"{f/1000:.1f}k" for f in freqs[:3]]}'
                    })
            
            # Single strong modem
            for m in sorted(us_modems, key=lambda x: x['snr'], reverse=True)[:3]:
                if m['snr'] > 5:
                    findings.append({
                        'type': 'strong_modem',
                        'freq': m['freq'],
                        'snr': m['snr'],
                        'bearing': m['bearing'],
                        'info': f'STRONG MODEM: {m["freq"]/1000:.1f}kHz SNR={m["snr"]:.1f} @ {m["bearing"]}deg'
                    })
        
        # === 3. FREQUENCY HOPPING ===
        if len(self.snapshots) >= 6:
            recent_freqs = {}
            for snap in list(self.snapshots)[-6:]:
                for s in snap['sources']:
                    f = s.get('freq', 0)
                    if f > 15000:
                        key = round(f / 1000) * 1000  # 1kHz bins
                        recent_freqs[key] = recent_freqs.get(key, 0) + 1
            
            # Frequencies that appear/disappear = hopping
            active_bins = [k for k, v in recent_freqs.items() if v >= 3]
            if len(active_bins) >= 3:
                findings.append({
                    'type': 'freq_hopping',
                    'bins': len(active_bins),
                    'span': max(active_bins) - min(active_bins) if active_bins else 0,
                    'info': f'FREQ HOPPING: {len(active_bins)} bins across {max(active_bins)-min(active_bins)}Hz span'
                })
        
        # === 4. NEW THREAT APPEARANCE ===
        if len(self.snapshots) >= 3:
            old_names = set()
            for snap in list(self.snapshots)[-4:-1]:
                for s in snap['sources']:
                    old_names.add(s['name'])
            for s in sources:
                name = s.get('detector_name', '?')
                if name not in old_names and name != '?' and s.get('observations', 0) >= 3:
                    findings.append({
                        'type': 'new_threat',
                        'name': name,
                        'bearing': s.get('bearing'),
                        'info': f'NEW THREAT: {name} appeared @ {s.get("bearing")}deg'
                    })
                    self.log.warning(f"NEW THREAT DETECTED: {name}")
        
        # === 5. SNR SPIKE ===
        for s in sources:
            if s.get('snr', 0) > 10 and s.get('observations', 0) > 2:
                findings.append({
                    'type': 'snr_spike',
                    'name': s.get('detector_name', '?'),
                    'snr': s['snr'],
                    'bearing': s.get('bearing'),
                    'info': f'SNR SPIKE: {s["detector_name"]} SNR={s["snr"]:.1f} @ {s.get("bearing")}deg'
                })
        
        # Store findings
        for f in findings:
            f['ts'] = now
            self.findings.append(f)
        
        return findings
    
    def get_attacker_bearing(self):
        """Return the most likely attacker bearing based on all analysis."""
        bearings = [f['bearing'] for f in self.findings 
                   if f.get('bearing') and abs(f['bearing']) > 0.5 
                   and time.time() - f.get('ts', 0) < 300]
        if not bearings:
            return None
        return round(np.median(bearings))
    
    def get_summary(self):
        """One-line summary of current threat assessment."""
        recent = [f for f in self.findings if time.time() - f.get('ts', 0) < 120]
        if not recent:
            return "Monitoring — no threats identified yet"
        
        consensus = [f for f in recent if f['type'] == 'consensus']
        modems = [f for f in recent if 'modem' in f['type']]
        threats = [f for f in recent if f['type'] == 'new_threat']
        
        parts = []
        if consensus:
            top = sorted(consensus, key=lambda x: x['obs'], reverse=True)[0]
            parts.append(f"Primary bearing: {top['bearing']}deg ({top['sources']} detectors)")
        if modems:
            parts.append(f"{len(modems)} modem signals")
        if threats:
            parts.append(f"{len(threats)} new threats")
        
        return ' | '.join(parts) if parts else "Monitoring"
