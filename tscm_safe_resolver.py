"""tscm_safe_resolver.py - None-safe geometry helpers for resolve_sources"""
import math, numpy as np

def safe_bearing(b):
    if b is None: return None
    try: return float(b)
    except: return None

def safe_mean(values):
    clean = [v for v in values if v is not None]
    return float(np.mean(clean)) if clean else None

def bearing_to_xy_safe(lat, lon, bearing_deg, distance_m):
    if bearing_deg is None or distance_m is None or distance_m <= 0:
        return lat, lon
    try: brng = math.radians(float(bearing_deg))
    except: return lat, lon
    if lat is None or lon is None: return 41.51325, -88.13368
    R, lat1, lon1 = 6371000.0, math.radians(lat), math.radians(lon)
    lat2 = math.asin(math.sin(lat1)*math.cos(distance_m/R)+math.cos(lat1)*math.sin(distance_m/R)*math.cos(brng))
    lon2 = lon1+math.atan2(math.sin(brng)*math.sin(distance_m/R)*math.cos(lat1),math.cos(distance_m/R)-math.sin(lat1)*math.sin(lat2))
    return math.degrees(lat2), math.degrees(lon2)

def intersect_bearings_safe(lat1, lon1, b1, lat2, lon2, b2):
    if None in (b1,b2,lat1,lat2,lon1,lon2): return None
    try: d1,d2 = math.radians(float(b1)), math.radians(float(b2))
    except: return None
    y1,x1=lat1*111320.0,lon1*111320.0*math.cos(math.radians(lat1))
    y2,x2=lat2*111320.0,lon2*111320.0*math.cos(math.radians(lat2))
    dx1,dy1,dx2,dy2=math.sin(d1),math.cos(d1),math.sin(d2),math.cos(d2)
    det=dx1*dy2-dx2*dy1
    if abs(det)<1e-10: return None
    t=((x2-x1)*dy2-(y2-y1)*dx2)/det
    ix,iy=x1+t*dx1,y1+t*dy1
    return iy/111320.0, ix/(111320.0*math.cos(math.radians(iy/111320.0)))

def compute_confidence_safe(bearings, rng, obs_n):
    clean=[b for b in bearings if b is not None]
    if len(clean)<2: return 0.3
    try:
        a=np.array(clean,dtype=float)
        s,c=np.sin(np.radians(a)),np.cos(np.radians(a))
        R=np.sqrt(float(np.mean(s))**2+float(np.mean(c))**2)
        bc=float(R); rc=0.5 if rng and rng>0 else 1.0; oc=min(obs_n/20.0,1.0)
        return round(bc*0.5+rc*0.3+oc*0.2,2)
    except: return 0.3
