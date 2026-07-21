"""
Server-side map renderer with Google satellite tiles.
Pre-renders PNG in background thread, serves cached result instantly.
"""
from PIL import Image, ImageDraw, ImageFont
import math
import io
import time
import threading
import urllib.request
import os

OBS_LAT = 41.51325
OBS_LON = -88.13368
TILE_DIR = os.path.join(os.path.dirname(__file__), 'tile_cache')
os.makedirs(TILE_DIR, exist_ok=True)

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

_cached_map_png = None
_cache_lock = threading.Lock()
_last_render_time = 0

TILE_SERVERS = [
    'https://mt0.google.com/vt/lyrs=s',
    'https://mt1.google.com/vt/lyrs=s',
    'https://mt2.google.com/vt/lyrs=s',
]
_tile_server_idx = 0

# Pre-generated blank tile (256x256 gray placeholder)
_BLANK_TILE = None

def _get_blank_tile():
    """Generate a 256x256 gray placeholder tile when downloads fail."""
    global _BLANK_TILE
    if _BLANK_TILE is not None:
        return _BLANK_TILE
    try:
        img = Image.new('RGB', (256, 256), (45, 45, 50))
        # Add subtle grid for cartographic feel
        draw = ImageDraw.Draw(img)
        for i in range(0, 256, 64):
            draw.line([(i, 0), (i, 255)], fill=(50, 50, 55), width=1)
            draw.line([(0, i), (255, i)], fill=(50, 50, 55), width=1)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        _BLANK_TILE = buf.getvalue()
        return _BLANK_TILE
    except:
        return None

def _get_cached_tile(z, x, y):
    path = os.path.join(TILE_DIR, '%d_%d_%d.png' % (z, x, y))
    if os.path.exists(path):
        with open(path, 'rb') as f:
            return f.read()
    return None

def _save_tile(z, x, y, data):
    path = os.path.join(TILE_DIR, '%d_%d_%d.png' % (z, x, y))
    try:
        with open(path, 'wb') as f:
            f.write(data)
    except:
        pass

def _download_tile(z, x, y, timeout=5):
    global _tile_server_idx
    cached = _get_cached_tile(z, x, y)
    if cached:
        return cached
    for attempt in range(3):
        server = TILE_SERVERS[_tile_server_idx % len(TILE_SERVERS)]
        _tile_server_idx += 1
        # Google tiles: https://mt0.google.com/vt/lyrs=s&x=X&y=Y&z=Z
        url = '%s&x=%d&y=%d&z=%d' % (server, x, y, z)
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'TSCM/2.0 (counter-surveillance; contact@example.com)',
                'Accept': 'image/png'
            })
            data = urllib.request.urlopen(req, timeout=timeout).read()
            if len(data) > 500:  # Google tiles are larger than blank placeholder
                _save_tile(z, x, y, data)
                return data
        except:
            continue
    # All servers failed — return blank placeholder tile so map still renders
    return _get_blank_tile()

def _ll2px(lat, lon, zoom, tile_size=256):
    """Lat/lon to global pixel at zoom level."""
    r = math.radians(lat)
    n = 2.0 ** zoom
    x = (lon + 180) / 360 * n * tile_size
    y = (1 - math.log(math.tan(r) + 1 / math.cos(r)) / math.pi) / 2 * n * tile_size
    return x, y

def _haversine(lat1, lon1, lat2, lon2):
    """Distance in meters between two GPS points."""
    r = 6371000
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
    return r * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

def bearing_to_xy(cx, cy, bearing_deg, distance_m, scale):
    brg = math.radians(bearing_deg)
    dx = math.sin(brg) * distance_m * scale
    dy = -math.cos(brg) * distance_m * scale
    return int(cx + dx), int(cy + dy)

def render_map(detections_data, width=3200, height=1800, zoom=14):
    """Render full sat map with overlay. Returns PNG bytes.
    zoom=14 shows wider area for situational awareness."""
    sources = detections_data.get('sources', [])
    observer = detections_data.get('observer', {})
    
    aoa = observer.get('aoa', 0)
    gps_fix = observer.get('gps_fix', False)
    bladerf = observer.get('bladerf', False)
    hackrf = observer.get('hackrf', False)
    
    TS = 256  # tile size
    
    # Layout: map takes 85% of width, small legend panel on right
    map_w = int(width * 0.85)
    map_top = 10
    map_bot = height - 10
    
    cx = map_w // 2
    cy = (map_top + map_bot) // 2
    
    # Base image
    img = Image.new('RGB', (width, height), (10, 10, 20))
    
    # ---- Download & composite satellite tiles ----
    observed_lat = observer.get('lat', OBS_LAT)
    observed_lon = observer.get('lon', OBS_LON)
    
    obs_px, obs_py = _ll2px(observed_lat, observed_lon, zoom, TS)
    
    # Tile range covering the map area
    tx_min = int((obs_px - map_w/2) // TS)
    tx_max = int((obs_px + map_w/2) // TS)
    ty_min = int((obs_py - (map_bot - map_top)/2) // TS)
    ty_max = int((obs_py + (map_bot - map_top)/2) // TS)
    
    tiles_needed = (tx_max - tx_min + 1) * (ty_max - ty_min + 1)
    got = 0
    for tx in range(tx_min, tx_max + 1):
        for ty in range(ty_min, ty_max + 1):
            tile_data = _download_tile(zoom, tx, ty)
            if tile_data:
                try:
                    tm = Image.open(io.BytesIO(tile_data))
                    ox = int(tx * TS - (obs_px - map_w/2))
                    oy = int(ty * TS - (obs_py - (map_top + map_bot)/2))
                    img.paste(tm, (ox, oy))
                    got += 1
                except:
                    pass
    
    # If we got zero tiles (offline), draw a basic grid
    if got == 0:
        for x in range(0, map_w, int(map_w/8)):
            for y in range(map_top, map_bot, int((map_bot-map_top)/8)):
                draw_tmp = ImageDraw.Draw(img)
                draw_tmp.line([(x, map_top), (x, map_bot)], fill=(20, 20, 40), width=1)
                draw_tmp.line([(0, y), (map_w, y)], fill=(20, 20, 40), width=1)
    
    # ---- Overlay drawing ----
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
    
    # Scale: pixels per meter at this zoom level
    # At zoom 16, 1 pixel ≈ 2.39m at equator. At lat 41.5°, ≈ 2.39 * cos(41.5°) ≈ 1.79m
    meters_per_pixel = 156543.0339 * math.cos(math.radians(observed_lat)) / (2 ** zoom)
    scale = 1.0 / meters_per_pixel  # pixels per meter
    
    # Range rings for zoom=17 (~1.3m/pixel): house-scale detail
    for dist_m in [50, 100, 200, 500, 1000, 2000]:
        r = int(dist_m * scale)
        if 5 < r < map_w//2:
            draw.ellipse([cx-r, cy-r, cx+r, cy+r], outline=(50, 50, 70, 128), width=1)
            draw.text((cx+r+3, cy-7), '%dm' % dist_m, fill=(80, 200, 80), font=font_sm)
    
    # Compass - stretch to map edge
    map_radius_px = min(map_w//2 - 20, (map_bot-map_top)//2 - 20)
    for brg, label in [(0, 'N'), (45, 'NE'), (90, 'E'), (135, 'SE'), 
                       (180, 'S'), (225, 'SW'), (270, 'W'), (315, 'NW')]:
        ex, ey = bearing_to_xy(cx, cy, brg, map_radius_px * meters_per_pixel, scale)
        draw.line([(cx, cy), (ex, ey)], fill=(60, 60, 80), width=1)
        draw.text((ex-4, ey-6), label, fill=(100, 100, 130), font=font_sm)
    
    # AoA line (bright red) - clamp to visible map edge with endpoint marker
    if abs(aoa) > 0.5:
        # Compute line from center to edge of visible map area
        rad = math.radians(aoa)
        dx = math.sin(rad)
        dy = -math.cos(rad)
        # Clamp to map bounds
        t_max = 1e9
        if dx > 0: t_max = min(t_max, (map_w - cx - 15) / dx)
        elif dx < 0: t_max = min(t_max, (15 - cx) / dx)
        if dy > 0: t_max = min(t_max, (map_bot - cy - 15) / dy)
        elif dy < 0: t_max = min(t_max, (map_top + 15 - cy) / dy)
        edge_dist = int(max(1, t_max))  # pixels from center to edge
        ax = int(cx + dx * edge_dist)
        ay = int(cy + dy * edge_dist)
        draw.line([(cx, cy), (ax, ay)], fill=(255, 40, 40), width=3)
        # Endpoint marker so you can see where it stops
        r = 6
        draw.ellipse([ax-r, ay-r, ax+r, ay+r], fill=None, outline=(255, 40, 40), width=2)
        draw.line([(ax-r-2, ay), (ax+r+2, ay)], fill=(255, 40, 40), width=1)
        draw.line([(ax, ay-r-2), (ax, ay+r+2)], fill=(255, 40, 40), width=1)
        # Label at midpoint
        mx = int(cx + dx * edge_dist * 0.4)
        my = int(cy + dy * edge_dist * 0.4)
        draw.text((mx+5, my-8), 'AoA %.0fdeg' % aoa, fill=(255, 80, 80), font=font)
    
    # Plot sources
    no_bearing = {}
    
    for s in sources:
        det = s.get('detector', 'unknown')
        freq = s.get('freq', 0)
        bearing = s.get('bearing')
        obs_count = s.get('observations', 1)
        classification = s.get('classification', '')
        range_m = s.get('range')
        triangulated = s.get('triangulated', False)
        lat = s.get('lat')
        lon = s.get('lon')
        
        color = DETECTOR_COLORS.get(det, (11, 191, 255))
        
        has_position = (lat is not None and lon is not None and abs(lat) > 0.001 and abs(lon) > 0.001)
        
        if triangulated and bearing is not None and abs(bearing) > 0.5:
            dist = range_m if range_m and range_m > 0 else (200 if 'radar' in det else 600)
            # Stretch line to map edge so user sees endpoint direction
            edge_dist = map_radius_px * meters_per_pixel * 3
            sx_edge, sy_edge = bearing_to_xy(cx, cy, bearing, edge_dist, scale)
            draw.line([(cx, cy), (sx_edge, sy_edge)], fill=(100, 100, 100), width=1)
            sx, sy = bearing_to_xy(cx, cy, bearing, dist, scale)
            r = max(3, min(10, obs_count // 8 + 3))
            
            draw.ellipse([sx-r, sy-r, sx+r, sy+r], fill=color, outline=(255,255,255))
            draw.line([(cx, cy), (sx, sy)], fill=tuple(c//2 for c in color), width=1)
            
            threat = THREAT_LABELS.get(det, det[:12])
            freq_str = '%.0fM' % (freq/1e6) if freq > 1e6 else ('%.0fk' % (freq/1e3) if freq > 1000 else '')
            label = '%s %s' % (threat, freq_str)
            draw.text((sx+r+3, sy-7), label, fill=color, font=font_sm)
            
            if 'c2' in det.lower() or 'attack' in classification.lower():
                draw.ellipse([sx-r-3, sy-r-3, sx+r+3, sy+r+3], outline=(255, 0, 0), width=2)
        
        elif has_position:
            # Draw source with known GPS position (from cross-sensor intersection)
            px, py = _ll2px(lat, lon, zoom, TS)
            tile_px = (obs_px - px) / scale
            tile_py = (obs_py - py) / scale
            sx = int(cx - tile_px)
            sy = int(cy - tile_py)
            # Clamp to map bounds
            if 10 < sx < map_w - 10 and 10 < sy < map_bot - 10:
                r = max(4, min(12, obs_count // 6 + 4))
                # Red crosshair for positioned threats
                draw.ellipse([sx-r, sy-r, sx+r, sy+r], fill=None, outline=(255, 60, 60), width=2)
                draw.line([(sx-r-2, sy), (sx+r+2, sy)], fill=(255, 60, 60), width=1)
                draw.line([(sx, sy-r-2), (sx, sy+r+2)], fill=(255, 60, 60), width=1)
                # Line from observer to position
                draw.line([(cx, cy), (sx, sy)], fill=(255, 60, 60, 100), width=1)
                # Distance label
                dist_m = int(_haversine(observed_lat, observed_lon, lat, lon))
                label = '%s %.0fm' % (det[:10], dist_m)
                draw.text((sx+r+3, sy-7), label, fill=(255, 100, 100), font=font_sm)
        
        elif not triangulated and bearing is not None and abs(bearing) > 0.5:
            edge_dist = map_radius_px * meters_per_pixel * 3
            sx_edge, sy_edge = bearing_to_xy(cx, cy, bearing, edge_dist, scale)
            # Thin full line to edge
            draw.line([(cx, cy), (sx_edge, sy_edge)], fill=(80, 80, 30), width=1)
            # Dashed segment near observer
            sx, sy = bearing_to_xy(cx, cy, bearing, 500, scale)
            steps = 8
            for i in range(steps):
                t0 = i / steps; t1 = (i + 0.55) / steps
                if i % 2 == 0:
                    x0 = int(cx + (sx - cx) * t0)
                    y0 = int(cy + (sy - cy) * t0)
                    x1 = int(cx + (sx - cx) * t1)
                    y1 = int(cy + (sy - cy) * t1)
                    draw.line([(x0, y0), (x1, y1)], fill=(200, 200, 0), width=1)
            lx, ly = bearing_to_xy(cx, cy, bearing, 333, scale)
            det_short = det[:14]
            draw.text((lx+2, ly-7), '%s %.0fdeg' % (det_short, bearing), fill=(200, 200, 0), font=font_sm)
        else:
            if det not in no_bearing:
                no_bearing[det] = {'count': 0, 'color': color, 'freqs': [], 'class': classification}
            no_bearing[det]['count'] += obs_count
            if freq > 0:
                no_bearing[det]['freqs'].append(freq)
    
    # Observer marker
    draw.ellipse([cx-6, cy-6, cx+6, cy+6], fill=(255, 255, 255), outline=(0, 255, 0), width=2)
    draw.text((cx+10, cy-7), 'YOU', fill=(0, 255, 0), font=font_lg)
    
    # Right panel
    px = map_w + 15
    py = map_top + 5
    
    gps_str = 'GPS:FIX' if gps_fix else 'GPS:NO FIX'
    draw.text((px, py), 'TSCM STATUS', fill=(0, 255, 0), font=font_lg)
    py += 20
    draw.text((px, py), 'BladeRF: %s  HackRF: %s' % ('ON' if bladerf else 'OFF', 'ON' if hackrf else 'OFF'), fill=(0, 200, 0), font=font)
    py += 16
    draw.text((px, py), '%s  AoA: %.1fdeg' % (gps_str, aoa), fill=(0, 200, 0), font=font)
    py += 16
    draw.text((px, py), 'Sources: %d total  Tiles: %d/%d' % (len(sources), got, tiles_needed), fill=(0, 200, 0), font=font)
    py += 22
    
    bearing_count = sum(1 for s in sources if s.get('bearing') and abs(s.get('bearing',0))>0.5)
    draw.text((px, py), 'Bearing sources: %d' % bearing_count, fill=(255, 200, 0), font=font)
    py += 22
    
    draw.text((px, py), '--- THREATS ---', fill=(255, 0, 0), font=font_lg)
    py += 20
    
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
            remaining = len(no_bearing) - 20
            if remaining > 0:
                draw.text((px, py), '...+%d more' % remaining, fill=(100,100,100), font=font_sm)
            break
    
    # Title bar
    draw.rectangle([0, 0, width, 28], fill=(0, 0, 0))
    title = 'TSCM Map | %d Sources | AoA: %.0fdeg | %s | %s' % (
        len(sources), aoa, 'GPS' if gps_fix else 'NO GPS', time.strftime('%H:%M:%S'))
    draw.text((8, 5), title, fill=(0, 255, 0), font=font_title)
    
    # Bottom key
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
    
    # Separator
    draw.line([(map_w, map_top), (map_w, map_bot)], fill=(50, 50, 80), width=2)
    
    buf = io.BytesIO()
    img.save(buf, format='PNG', optimize=True)
    buf.seek(0)
    return buf.getvalue()
