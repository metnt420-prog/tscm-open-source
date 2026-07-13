"""
Server-side map renderer - generates PNG using Pillow.
Pure Python image generation. No JavaScript. Detailed detection map.
"""
from PIL import Image, ImageDraw, ImageFont
import math
import io
import time

OBS_LAT = 41.51325
OBS_LON = -88.13368

DETECTOR_COLORS = {
    'eardrum_capture': (224, 64, 255),
    'injection_locking': (255, 136, 0),
    'silent_sound': (0, 255, 255),
    'fingerprinting': (160, 160, 160),
    'ultrasonic_scan': (224, 64, 255),
    'laptop_ultrasound': (224, 64, 255),
    'c2_c2_us_bpsk': (255, 68, 68),
    'c2_c2_us_fsk': (255, 68, 68),
    'c2_c2_wifi_hidden': (255, 68, 68),
    'c2_c2_wifi_hidden': (255, 68, 68),
    'wifi_c2_hidden_network': (255, 68, 68),
    'wifi_c2_phone_hotspot': (255, 68, 68),
    'wifi_c2_c2_honeypot': (255, 0, 0),
    'carbon_interaction': (0, 255, 136),
    'mw_voice_carrier': (255, 0, 255),
    'eeg_voice_gamma': (255, 255, 0),
    'eeg_voice': (255, 255, 0),
    'hello_scotty': (255, 136, 0),
    'manus_ai_vlf': (136, 0, 255),
    'radar_metal_device': (255, 136, 0),
    'radar_water_body': (255, 0, 0),
    'radar_metal_surface': (170, 170, 170),
    'ferrite_peak': (255, 255, 0),
    'ferrite_null': (255, 255, 0),
    'hackrf_ferrite': (255, 255, 0),
    'ghost_murmur': (98, 0, 238),
    'phased_array': (255, 102, 0),
    'oth_radar': (255, 102, 0),
    'operator_fingerprint': (98, 0, 238),
    'ambient_reradiator': (160, 160, 160),
    'real_transmitter': (255, 0, 0),
    'ground_plane': (160, 160, 160),
    'nerve_pain_scan': (255, 0, 255),
    'parametric_amplification': (255, 136, 0),
    'isolation_booth': (255, 68, 68),
    'variac_induction': (255, 136, 0),
    'power_line_loop': (255, 136, 0),
    'constant_ultrasonic_carrier': (224, 64, 255),
    'ultrasound_modem': (255, 68, 68),
    'us_modem_fsk': (255, 68, 68),
    'ultrasound_hopper': (224, 64, 255),
    'low_ultrasound': (224, 64, 255),
    'watcher_us_modem_cluster': (255, 68, 68),
    'wifi_wifi_channel_anomaly': (255, 136, 68),
    'wifi_wifi_motion': (255, 136, 68),
    'wifi_wifi_approaching': (255, 0, 0),
    'wifi_wifi_ap_surge': (255, 136, 68),
    'wifi_c2_wifi_direct_c2': (255, 0, 0),
    'c2_server_connection': (255, 0, 0),
}

THREAT_LABELS = {
    'eardrum_capture': 'SURVEILLANCE',
    'silent_sound': 'ATTACK',
    'c2_c2_us_bpsk': 'C2 MODEM',
    'c2_c2_us_fsk': 'C2 MODEM',
    'c2_c2_wifi_hidden': 'C2 WIFI',
    'wifi_c2_hidden_network': 'C2 HIDDEN',
    'wifi_c2_phone_hotspot': 'C2 PHONE',
    'wifi_c2_c2_honeypot': 'C2 HONEYPOT',
    'carbon_interaction': 'MW ATTACK',
    'mw_voice_carrier': 'MW VOICE',
    'hello_scotty': 'POWER LINE C2',
    'manus_ai_vlf': 'AI AGENT C2',
    'radar_water_body': 'RADAR: PERSON',
    'radar_metal_device': 'RADAR: DEVICE',
    'wifi_wifi_approaching': 'APPROACHING',
    'wifi_c2_wifi_direct_c2': 'WIFI DIRECT C2',
    'c2_server_connection': 'C2 SERVER',
    'watcher_us_modem_cluster': 'MODEM CLUSTER',
    'real_transmitter': 'TRANSMITTER',
    'oth_radar': 'OTH RADAR',
}

def bearing_to_xy(cx, cy, bearing_deg, distance_m, scale):
    brg = math.radians(bearing_deg)
    dx = math.sin(brg) * distance_m * scale
    dy = -math.cos(brg) * distance_m * scale
    return int(cx + dx), int(cy + dy)

def render_map(detections_data, width=1400, height=950):
    sources = detections_data.get('sources', [])
    observer = detections_data.get('observer', {})
    
    aoa = observer.get('aoa', 0)
    gps_fix = observer.get('gps_fix', False)
    bladerf = observer.get('bladerf', False)
    hackrf = observer.get('hackrf', False)
    
    img = Image.new('RGB', (width, height), (10, 10, 20))
    draw = ImageDraw.Draw(img)
    
    try:
        font = ImageFont.truetype("consola.ttf", 12)
        font_sm = ImageFont.truetype("consola.ttf", 10)
        font_lg = ImageFont.truetype("consola.ttf", 14)
        font_title = ImageFont.truetype("consola.ttf", 16)
    except:
        font = ImageFont.load_default()
        font_sm = font
        font_lg = font
        font_title = font
    
    # Layout: map on left 68%, panel on right 32%
    map_w = int(width * 0.68)
    map_top = 35
    map_bot = height - 25
    
    cx = map_w // 2
    cy = (map_top + map_bot) // 2
    
    scale = min(map_w, map_bot - map_top) / 2800
    
    # Grid
    draw.rectangle([0, map_top, map_w, map_bot], fill=(15, 15, 30))
    
    # Range rings with labels
    for dist_m in [50, 100, 200, 500, 1000]:
        r = int(dist_m * scale)
        if 5 < r < map_w//2:
            draw.ellipse([cx-r, cy-r, cx+r, cy+r], outline=(35, 35, 55), width=1)
            if dist_m >= 100:
                draw.text((cx+r+3, cy-7), '%dm' % dist_m, fill=(60, 60, 90), font=font_sm)
    
    # Compass
    for brg, label in [(0, 'N'), (45, 'NE'), (90, 'E'), (135, 'SE'), 
                       (180, 'S'), (225, 'SW'), (270, 'W'), (315, 'NW')]:
        ex, ey = bearing_to_xy(cx, cy, brg, 1100, scale)
        draw.line([(cx, cy), (ex, ey)], fill=(30, 30, 50), width=1)
        draw.text((ex-4, ey-6), label, fill=(70, 70, 100), font=font_sm)
    
    # AoA line (bright red)
    if abs(aoa) > 0.5:
        ax, ay = bearing_to_xy(cx, cy, aoa, 1100, scale)
        draw.line([(cx, cy), (ax, ay)], fill=(255, 40, 40), width=3)
        # AoA label
        mx, my = bearing_to_xy(cx, cy, aoa, 600, scale)
        draw.text((mx+5, my-8), 'AoA %.0fdeg' % aoa, fill=(255, 80, 80), font=font)
    
    # Plot sources with bearings
    no_bearing = {}
    doa_count = 0
    
    for s in sources:
        det = s.get('detector', 'unknown')
        freq = s.get('freq', 0)
        bearing = s.get('bearing')
        obs_count = s.get('observations', 1)
        classification = s.get('classification', '')
        range_m = s.get('range')
        triangulated = s.get('triangulated', False)
        
        color = DETECTOR_COLORS.get(det, (11, 191, 255))
        
        # Triangulated sources: dot + solid line at estimated range
        if triangulated and bearing is not None and abs(bearing) > 0.5:
            dist = range_m if range_m and range_m > 0 else (200 if 'radar' in det else 600)
            sx, sy = bearing_to_xy(cx, cy, bearing, dist, scale)
            r = max(3, min(10, obs_count // 8 + 3))
            
            # Dot
            draw.ellipse([sx-r, sy-r, sx+r, sy+r], fill=color, outline=(255,255,255))
            # Line
            draw.line([(cx, cy), (sx, sy)], fill=tuple(c//2 for c in color), width=1)
            
            # Label with threat type
            threat = THREAT_LABELS.get(det, det[:12])
            freq_str = '%.0fM' % (freq/1e6) if freq > 1e6 else ('%.0fk' % (freq/1e3) if freq > 1000 else '')
            label = '%s %s' % (threat, freq_str)
            draw.text((sx+r+3, sy-7), label, fill=color, font=font_sm)
            
            # Extra bright ring for C2/hacking threats
            if 'c2' in det.lower() or 'attack' in classification.lower():
                draw.ellipse([sx-r-3, sy-r-3, sx+r+3, sy+r+3], outline=(255, 0, 0), width=2)
        # DOA known but not triangulated: dashed bearing line only (no position dot)
        elif not triangulated and bearing is not None and abs(bearing) > 0.5:
            doa_count += 1
            sx, sy = bearing_to_xy(cx, cy, bearing, 500, scale)
            # Dashed line effect: alternating segments
            steps = 8
            for i in range(steps):
                t0 = i / steps; t1 = (i + 0.55) / steps
                if i % 2 == 0:
                    x0 = int(cx + (sx - cx) * t0)
                    y0 = int(cy + (sy - cy) * t0)
                    x1 = int(cx + (sx - cx) * t1)
                    y1 = int(cy + (sy - cy) * t1)
                    draw.line([(x0, y0), (x1, y1)], fill=(200, 200, 0), width=1)
            # Small dim label at 2/3 distance
            lx, ly = bearing_to_xy(cx, cy, bearing, 333, scale)
            det_short = det[:14]
            draw.text((lx+2, ly-7), '%s %.0fdeg' % (det_short, bearing), fill=(200, 200, 0), font=font_sm)
        else:
            if det not in no_bearing:
                no_bearing[det] = {'count': 0, 'color': color, 'freqs': [], 'class': classification}
            no_bearing[det]['count'] += obs_count
            if freq > 0:
                no_bearing[det]['freqs'].append(freq)
    
    # Observer marker (drawn last, on top)
    draw.ellipse([cx-6, cy-6, cx+6, cy+6], fill=(255, 255, 255), outline=(0, 255, 0), width=2)
    draw.text((cx+10, cy-7), 'YOU', fill=(0, 255, 0), font=font_lg)
    
    # ========== RIGHT PANEL ==========
    px = map_w + 15
    py = map_top + 5
    
    # System status
    gps_str = 'GPS:FIX' if gps_fix else 'GPS:NO FIX'
    draw.text((px, py), 'TSCM STATUS', fill=(0, 255, 0), font=font_lg)
    py += 20
    draw.text((px, py), 'BladeRF: %s  HackRF: %s' % ('ON' if bladerf else 'OFF', 'ON' if hackrf else 'OFF'), fill=(0, 200, 0), font=font)
    py += 16
    draw.text((px, py), '%s  AoA: %.1fdeg' % (gps_str, aoa), fill=(0, 200, 0), font=font)
    py += 16
    draw.text((px, py), 'Sources: %d total' % len(sources), fill=(0, 200, 0), font=font)
    py += 22
    
    # Bearing sources count
    bearing_count = sum(1 for s in sources if s.get('bearing') and abs(s.get('bearing',0))>0.5)
    draw.text((px, py), 'Bearing sources: %d' % bearing_count, fill=(255, 200, 0), font=font)
    py += 22
    
    # Threat summary
    draw.text((px, py), '--- THREATS ---', fill=(255, 0, 0), font=font_lg)
    py += 20
    
    # Group by threat level
    threats = {}
    for det, info in no_bearing.items():
        if any(k in det.lower() for k in ['c2', 'attack', 'hacking', 'honeypot', 'approaching', 'direct']):
            threats[det] = info
    
    for det, info in sorted(threats.items(), key=lambda x: x[1]['count'], reverse=True)[:8]:
        freq_str = ''
        if info['freqs']:
            f = info['freqs'][0]
            freq_str = '%.0fM' % (f/1e6) if f > 1e6 else ('%.0fk' % (f/1e3) if f > 1000 else '')
        threat = THREAT_LABELS.get(det, det[:18])
        text = '%s %s x%d' % (threat, freq_str, info['count'])
        # Red background highlight
        draw.rectangle([px-2, py-1, px+len(text)*7+5, py+13], fill=(60, 0, 0))
        draw.text((px, py), text, fill=info['color'], font=font)
        py += 16
    
    py += 8
    draw.text((px, py), '--- DETECTIONS ---', fill=(0, 200, 200), font=font_lg)
    py += 20
    
    for det, info in sorted(no_bearing.items(), key=lambda x: x[1]['count'], reverse=True)[:20]:
        freq_str = ''
        if info['freqs']:
            f = info['freqs'][0]
            freq_str = '%.0fM' % (f/1e6) if f > 1e6 else ('%.0fk' % (f/1e3) if f > 1000 else '')
        text = '%s %s x%d' % (det[:20], freq_str, info['count'])
        draw.text((px, py), text, fill=info['color'], font=font_sm)
        py += 14
        if py > height - 40:
            draw.text((px, py), '...+%d more' % (len(no_bearing) - 20), fill=(100,100,100), font=font_sm)
            break
    
    # ========== TITLE BAR ==========
    draw.rectangle([0, 0, width, 28], fill=(0, 0, 0))
    title = 'TSCM Detection Map | %d Sources | AoA: %.0fdeg | GPS:%s | %s' % (
        len(sources), aoa, 'FIX' if gps_fix else 'NO FIX', time.strftime('%H:%M:%S'))
    draw.text((8, 5), title, fill=(0, 255, 0), font=font_title)
    
    # ========== BOTTOM KEY ==========
    draw.rectangle([0, height-22, width, height], fill=(0, 0, 0))
    key_items = [('C2/HACK', (255,68,68)), ('MW VOICE', (255,0,255)), ('CARBON', (0,255,136)),
                 ('SILENT', (0,255,255)), ('EEG', (255,255,0)), ('SCOTTY/MANUS', (255,136,0)),
                 ('RADAR', (255,0,0)), ('FERRITE', (255,255,0)), ('ULTRA', (224,64,255)),
                 ('APPROACH', (255,0,0))]
    kx = 8
    for label, col in key_items:
        draw.rectangle([kx, height-18, kx+10, height-8], fill=col)
        draw.text((kx+13, height-19), label, fill=col, font=font_sm)
        kx += 13 + len(label) * 6 + 12
    
    # Separator line between map and panel
    draw.line([(map_w, map_top), (map_w, map_bot)], fill=(50, 50, 80), width=2)
    
    buf = io.BytesIO()
    img.save(buf, format='PNG', optimize=True)
    buf.seek(0)
    return buf.getvalue()
