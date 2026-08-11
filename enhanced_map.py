"""
Enhanced Map Renderer with:
- Convex hull / coverage polygon around all detections
- Address-level tooltips via reverse geocoding (Nominatim fallback)
- Auto-fit viewport to entire detection area with padding
- Endpoint markers
- Fathom Information Design aesthetic
"""
from PIL import Image, ImageDraw, ImageFont
import math, io, time, threading, urllib.request, json, os, hashlib
from collections import defaultdict

# Reuse existing tile infrastructure
from map_renderer import (
    _download_tile, _ll2px, _haversine, TILE_DIR, DETECTOR_COLORS, THREAT_LABELS
)

OBS_LAT = 41.51325
OBS_LON = -88.13368

# Address cache to avoid rate-limiting Nominatim
ADDR_CACHE = {}
ADDR_CACHE_FILE = os.path.join(os.path.dirname(__file__), 'address_cache.json')
if os.path.exists(ADDR_CACHE_FILE):
    try:
        with open(ADDR_CACHE_FILE) as f:
            ADDR_CACHE = json.load(f)
    except:
        pass

def _save_addr_cache():
    try:
        with open(ADDR_CACHE_FILE, 'w') as f:
            json.dump(ADDR_CACHE, f)
    except:
        pass

def reverse_geocode(lat, lon):
    """Look up street address from lat/lon using Nominatim or cached data."""
    key = f"{lat:.5f},{lon:.5f}"
    if key in ADDR_CACHE:
        return ADDR_CACHE[key]
    try:
        url = f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=json&zoom=18&addressdetails=1"
        req = urllib.request.Request(url, headers={
            'User-Agent': 'TSCM/3.0 (counter-surveillance; contact@tscm.local)',
            'Accept': 'application/json'
        })
        data = urllib.request.urlopen(req, timeout=5).read()
        result = json.loads(data)
        addr = result.get('display_name', f'{lat:.5f}, {lon:.5f}')
        ADDR_CACHE[key] = addr
        _save_addr_cache()
        return addr
    except:
        fallback = f"{lat:.5f}, {lon:.5f}"
        ADDR_CACHE[key] = fallback
        return fallback

def compute_convex_hull(points):
    """Graham scan convex hull. Returns list of (lat, lon) tuples in CCW order."""
    if len(points) < 3:
        return points
    
    def cross(o, a, b):
        return (a[0]-o[0])*(b[1]-o[1]) - (a[1]-o[1])*(b[0]-o[0])
    
    pts = sorted(set(points))
    if len(pts) <= 1:
        return pts
    
    lower = []
    for p in pts:
        while len(lower) >= 2 and cross(lower[-2], lower[-1], p) <= 0:
            lower.pop()
        lower.append(p)
    
    upper = []
    for p in reversed(pts):
        while len(upper) >= 2 and cross(upper[-2], upper[-1], p) <= 0:
            upper.pop()
        upper.append(p)
    
    return lower[:-1] + upper[:-1]

def render_enhanced_map(detections_data, width=3200, height=1800, zoom=None):
    """Enhanced map with coverage polygon, addresses, endpoints."""
    sources = detections_data.get('sources', [])
    observer = detections_data.get('observer', {})
    aoa = observer.get('aoa', 0)
    gps_fix = observer.get('gps_fix', False)
    observed_lat = observer.get('lat', OBS_LAT)
    observed_lon = observer.get('lon', OBS_LON)
    
    TS = 256
    map_w = int(width * 0.82)
    map_top, map_bot = 10, height - 10
    cx, cy = map_w // 2, (map_top + map_bot) // 2
    
    # Collect positions for auto-zoom and hull
    positions = [(observed_lat, observed_lon)]
    for s in sources:
        lat = s.get('lat')
        lon = s.get('lon')
        if lat and lon and abs(lat) > 0.001 and abs(lon) > 0.001:
            positions.append((lat, lon))
    
    # Auto-zoom: wide overview by default, zoom in only if markers are very tight
    if zoom is None and len(positions) > 1:
        lats = [p[0] for p in positions]
        lons = [p[1] for p in positions]
        lat_span = max(lats) - min(lats)
        lon_span = max(lons) - min(lons)
        max_span = max(lat_span, lon_span) * 1.15  # 15% padding
        if max_span > 0.1:
            zoom = 11
        elif max_span > 0.05:
            zoom = 12
        elif max_span > 0.02:
            zoom = 13
        elif max_span > 0.01:
            zoom = 14
        elif max_span > 0.005:
            zoom = 15
        elif max_span > 0.002:
            zoom = 16
        else:
            zoom = 17
    if zoom is None:
        zoom = 14  # wide area overview, not building-level
    zoom = max(12, min(20, int(zoom)))
    
    # Base image
    img = Image.new('RGB', (width, height), (248, 249, 250))  # Fathom: light grey bg
    
    # Tile layer
    obs_px, obs_py = _ll2px(observed_lat, observed_lon, zoom, TS)
    tx_min = int((obs_px - map_w/2) // TS)
    tx_max = int((obs_px + map_w/2) // TS)
    ty_min = int((obs_py - (map_bot - map_top)/2) // TS)
    ty_max = int((obs_py + (map_bot - map_top)/2) // TS)
    
    scale = 1.0 / (156543.0339 * math.cos(math.radians(observed_lat)) / (2 ** zoom))
    
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
    
    # Fallback grid if no tiles
    draw = ImageDraw.Draw(img)
    if got == 0:
        for x in range(0, map_w, int(map_w/8)):
            draw.line([(x, map_top), (x, map_bot)], fill=(220, 222, 224), width=1)
        for y in range(map_top, map_bot, int((map_bot-map_top)/10)):
            draw.line([(0, y), (map_w, y)], fill=(220, 222, 224), width=1)
    
    # Fonts
    try:
        font = ImageFont.truetype("consola.ttf", 11)
        font_sm = ImageFont.truetype("consola.ttf", 9)
        font_lg = ImageFont.truetype("consola.ttf", 13)
        font_title = ImageFont.truetype("consola.ttf", 14)
    except:
        font = font_sm = font_lg = font_title = ImageFont.load_default()
    
    # === COVERAGE POLYGON (convex hull) ===
    valid_positions = [(lat, lon) for lat, lon in positions if abs(lat) > 0.001]
    if len(valid_positions) >= 3:
        hull = compute_convex_hull(valid_positions)
        if len(hull) >= 3:
            hull_px = []
            for lat, lon in hull:
                hx, hy = _ll2px(lat, lon, zoom, TS)
                px = int(cx + (hx - obs_px) / scale)
                py = int(cy + (hy - obs_py) / scale)
                hull_px.append((px, py))
            
            # Draw filled hull
            if len(hull_px) >= 3:
                draw.polygon(hull_px, fill=(232, 148, 58, 30), outline=(232, 148, 58), width=2)
            
            # Draw hull edge with dashed endpoints
            for i, (px, py) in enumerate(hull_px):
                # Endpoint marker
                r = 5
                draw.ellipse([px-r, py-r, px+r, py+r], fill=None, outline=(200, 50, 0), width=2)
                draw.line([(px-r-2, py), (px+r+2, py)], fill=(200, 50, 0), width=1)
                draw.line([(px, py-r-2), (px, py+r+2)], fill=(200, 50, 0), width=1)
    
    # === RANGE RINGS ===
    for dist_m in [100, 300, 1000, 3000, 8000]:
        r = int(dist_m * scale)
        if 5 < r < map_w // 2:
            draw.ellipse([cx-r, cy-r, cx+r, cy+r], outline=(180, 182, 186), width=1)
            draw.text((cx+r+2, cy-6), f'{dist_m}m', fill=(100, 110, 130), font=font_sm)
    
    # === AoA LINE (clamp to map edge so endpoint is visible) ===
    if abs(aoa) > 0.5:
        # Compute line from center to edge of map
        # Find intersection with map rectangle
        rad = math.radians(aoa)
        dx = math.sin(rad)
        dy = -math.cos(rad)
        # Clamp to map bounds
        t_max = 1e9
        if dx > 0:
            t_max = min(t_max, (map_w - cx - 10) / dx)
        elif dx < 0:
            t_max = min(t_max, (10 - cx) / dx)
        if dy > 0:
            t_max = min(t_max, (map_bot - cy - 10) / dy)
        elif dy < 0:
            t_max = min(t_max, (map_top + 10 - cy) / dy)
        
        edge_dist = max(1, t_max - 30)  # 30px before edge
        ax = int(cx + dx * edge_dist)
        ay = int(cy + dy * edge_dist)
        
        # Draw the AoA line to edge
        draw.line([(cx, cy), (ax, ay)], fill=(180, 40, 40), width=3)
        # Endpoint marker so you can see where it stops
        r = 6
        draw.ellipse([ax-r, ay-r, ax+r, ay+r], fill=None, outline=(180, 40, 40), width=2)
        draw.line([(ax-r-2, ay), (ax+r+2, ay)], fill=(180, 40, 40), width=1)
        draw.line([(ax, ay-r-2), (ax, ay+r+2)], fill=(180, 40, 40), width=1)
        
        # Label at midpoint (visible regardless of direction)
        mx = int(cx + dx * edge_dist * 0.45)
        my = int(cy + dy * edge_dist * 0.45)
        draw.text((mx+5, my-8), f'AoA {aoa:.0f}°', fill=(180, 60, 60), font=font)
    
    # === PLOT SOURCES WITH ADDRESSES ===
    for s in sources:
        det = s.get('detector', 'unknown')
        lat = s.get('lat')
        lon = s.get('lon')
        bearing = s.get('bearing')
        tri = s.get('triangulated', False)
        color = DETECTOR_COLORS.get(det, (60, 80, 120))
        
        if lat and lon and abs(lat) > 0.001:
            hx, hy = _ll2px(lat, lon, zoom, TS)
            sx = int(cx + (hx - obs_px) / scale)
            sy = int(cy + (hy - obs_py) / scale)
            
            if 0 < sx < map_w and 0 < sy < map_bot:
                # Marker with address tooltip
                r = 4
                draw.ellipse([sx-r, sy-r, sx+r, sy+r], fill=color, outline=(255,255,255), width=1)
                
                # Address label (show first 30 chars)
                addr = reverse_geocode(lat, lon)
                addr_short = addr[:40] if len(addr) > 40 else addr
                # Display on hover — since this is PNG, show key label
                threat = THREAT_LABELS.get(det, det[:12])
                label = f'{threat}'
                draw.text((sx+6, sy-7), label, fill=color, font=font_sm)
                # Draw address in a small box below
                if addr_short and addr_short != f'{lat:.5f}, {lon:.5f}':
                    # Truncate for label
                    parts = addr_short.split(',')
                    street = parts[0].strip()[:25]
                    draw.text((sx+6, sy+5), street, fill=(80, 90, 110), font=font_sm)
        
        elif bearing and abs(bearing) > 0.5:
            edge_dist = map_w * 2
            bx = int(cx + math.sin(math.radians(bearing)) * edge_dist)
            by = int(cy - math.cos(math.radians(bearing)) * edge_dist)
            draw.line([(cx, cy), (bx, by)], fill=tuple(c//2 for c in color), width=1)
    
    # === OBSERVER ===
    draw.ellipse([cx-7, cy-7, cx+7, cy+7], fill=(255, 255, 255), outline=(46, 125, 50), width=3)
    draw.text((cx+12, cy-9), 'YOU', fill=(46, 125, 50), font=font_lg)
    
    # === RIGHT PANEL (Fathom: clean sidebar) ===
    px = map_w + 20
    py = map_top + 5
    
    draw.text((px, py), 'TSCM COVERAGE ANALYSIS', fill=(33, 37, 51), font=font_lg)
    py += 22
    
    # Coverage stats
    max_dist = 0; area_km2 = 0
    if len(valid_positions) > 1:
        lats = [p[0] for p in valid_positions]
        lons = [p[1] for p in valid_positions]
        lat_span_m = (max(lats) - min(lats)) * 111319
        lon_span_m = (max(lons) - min(lons)) * 111319 * math.cos(math.radians(observed_lat))
        area_km2 = (lat_span_m * lon_span_m) / 1e6
        max_dist = max(_haversine(p1[0], p1[1], p2[0], p2[1]) 
                      for i, p1 in enumerate(valid_positions) 
                      for p2 in valid_positions[i+1:]) if len(valid_positions) > 2 else 0
    
    draw.text((px, py), f'Coverage: {max_dist/1000:.1f} km spread', fill=(80, 90, 110), font=font)
    py += 14
    draw.text((px, py), f'Area: ~{area_km2:.1f} km²', fill=(80, 90, 110), font=font)
    py += 14
    draw.text((px, py), f'Endpoints: {len(hull) if len(valid_positions) >=3 else 0}', fill=(80, 90, 110), font=font)
    py += 14
    draw.text((px, py), f'GPS: {"FIX" if gps_fix else "NO FIX"}', 
              fill=(46, 125, 50) if gps_fix else (200, 50, 0), font=font)
    py += 14
    draw.text((px, py), f'AoA: {aoa:.0f}°', fill=(180, 60, 60), font=font)
    py += 18
    
    # Detection breakdown
    draw.text((px, py), 'SIGNAL DISTRIBUTION', fill=(33, 37, 51), font=font)
    py += 16
    det_counts = defaultdict(int)
    for s in sources:
        det_counts[s.get('detector', 'unknown')[:20]] += 1
    
    for det_name, count in sorted(det_counts.items(), key=lambda x: -x[1])[:15]:
        color = DETECTOR_COLORS.get(det_name, (60, 80, 120))
        bar_w = min(count * 4, 140)
        draw.rectangle([px, py, px + bar_w, py + 10], fill=color)
        draw.text((px + bar_w + 4, py - 1), f'{det_name} x{count}', fill=(80, 90, 110), font=font_sm)
        py += 12
    
    # Separator
    draw.line([(map_w, map_top), (map_w, map_bot)], fill=(200, 202, 206), width=2)
    
    # Title bar
    draw.rectangle([0, 0, width, 28], fill=(33, 37, 51))
    draw.text((10, 6), f'TSCM COVERAGE MAP | {len(sources)} Sources | Zoom {zoom} | {time.strftime("%H:%M:%S UTC")}', 
              fill=(255, 255, 255), font=font_title)
    
    # Bottom legend
    draw.rectangle([0, height-22, width, height], fill=(33, 37, 51))
    legend_items = [
        ('C2/Attack', (200,50,50)), ('MW Voice', (200,50,180)), ('Silent Sound', (232,148,58)),
        ('Ultrasound', (150,50,220)), ('EEG', (220,220,30)), ('Fingerprint', (60,80,120)),
        ('Hull Boundary', (232,148,58))
    ]
    kx = 12
    for label, col in legend_items:
        draw.rectangle([kx, height-19, kx+12, height-7], fill=col)
        draw.text((kx+15, height-19), label, fill=(200,202,206), font=font_sm)
        kx += 15 + len(label) * 7 + 16
    
    buf = io.BytesIO()
    img.save(buf, format='PNG', optimize=True)
    buf.seek(0)
    return buf.getvalue()


def latlon_to_pixel(lat, lon, zoom, center_lat, center_lon, map_w, map_h):
    """Convert lat/lon to pixel in the rendered map at given zoom."""
    TS = 256
    cp_x, cp_y = _ll2px(center_lat, center_lon, zoom, TS)
    p_x, p_y = _ll2px(lat, lon, zoom, TS)
    scale = 1.0 / (156543.0339 * math.cos(math.radians(center_lat)) / (2 ** zoom))
    cx, cy = map_w // 2, map_h // 2
    return int(cx + (p_x - cp_x) / scale), int(cy + (p_y - cp_y) / scale)
