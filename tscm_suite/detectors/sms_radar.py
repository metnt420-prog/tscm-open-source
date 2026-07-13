"""SMS alert with live map URL via localhost.run tunnel."""
import urllib.request, json, time, os, smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

MAP_URL = "http://localhost:8080"
LIVE_URL = "https://eb1c1d9f76fb6a.lhr.life"
TO_NUMBER = "8156906926"
SMS_GATEWAYS = [f"{TO_NUMBER}@vtext.com", f"{TO_NUMBER}@mms.att.net", f"{TO_NUMBER}@tmomail.net"]
IMG_PATH = "tscm_radar.png"
SMS_LOG = "sms_log.txt"

def get_data():
    d = json.loads(urllib.request.urlopen(f"{MAP_URL}/api/detections", timeout=3).read())
    return d.get('sources', []), d.get('observer', {})

def generate_radar(sources, observer):
    aoa = observer.get('aoa', 0)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5), facecolor='#0a0a0a')
    ax1 = plt.subplot(121, projection='polar', facecolor='#0a0a0a')
    ax1.set_theta_zero_location('N'); ax1.set_theta_direction(-1)
    ax1.set_ylim(0, 100); ax1.set_yticks([])
    ax1.set_xticks(np.radians(range(0, 360, 30)))
    ax1.tick_params(colors='#888', labelsize=7); ax1.grid(color='#222', alpha=0.5)
    ax1.set_title(f'TSCM RADAR | AoA:{aoa:.0f}deg | {len(sources)}srcs', color='#0f0', fontsize=10, pad=15)
    ax1.annotate('', xy=(np.radians(aoa), 95), xytext=(0,0),
                 arrowprops=dict(arrowstyle='->', color='#ff0', lw=3, alpha=0.9))
    colors = {'transmitter': '#ff3333', 'victim': '#ff8800', 'unknown': '#00cccc'}
    for s in sources:
        b = s.get('bearing')
        if b is None or b == 0: continue
        cls = s.get('classification', 'unknown'); det = s.get('detector', '?')
        obs = min(s.get('observations', 1), 100)
        # Ultrasound in magenta
        c = '#e040ff' if any(k in det for k in ['ultra','eardrum','silent_sound','hop']) else colors.get(cls, '#888')
        ax1.scatter(np.radians(b), obs, c=c, s=max(20, obs*2), alpha=0.8, edgecolors='white', linewidth=0.5)
        ax1.annotate(det[:10], (np.radians(b), obs+5), color=c, fontsize=5, alpha=0.8)
    ax2.axis('off'); ax2.set_facecolor('#0a0a0a')
    sorted_srcs = sorted(sources, key=lambda s: s.get('observations', 0), reverse=True)
    y = 0.95
    ax2.text(0, y, f'LIVE: {LIVE_URL}', color='#0ff', fontsize=7, fontfamily='monospace')
    y -= 0.03
    for s in sorted_srcs[:15]:
        det = s.get('detector', '?')[:20]; cls = (s.get('classification', '?') or '?')[:4]
        freq = s.get('freq', 0)
        fstr = f'{freq/1000:.0f}k' if freq > 1000 else (f'{freq:.0f}Hz' if freq > 0 else '-')
        b = s.get('bearing'); bstr = f'{b:.0f}deg' if b else '?'
        obs_n = s.get('observations', 0)
        c = '#e040ff' if any(k in det for k in ['ultra','eardrum','silent','hop']) else colors.get(s.get('classification', 'unknown'), '#888')
        ax2.text(0, y, f'{det:20s} {cls:4s} {fstr:6s} {bstr:4s} {obs_n:3d}obs', color=c, fontsize=6, fontfamily='monospace')
        y -= 0.045
    plt.tight_layout(); plt.savefig(IMG_PATH, dpi=100, facecolor='#0a0a0a', bbox_inches='tight'); plt.close()

def send_mms(img_path, text):
    for gw in SMS_GATEWAYS[:2]:
        try:
            msg = MIMEMultipart('related')
            msg['From'] = 'tscm@localhost'; msg['To'] = gw; msg['Subject'] = ''
            alt = MIMEMultipart('alternative'); msg.attach(alt)
            alt.attach(MIMEText(text, 'plain'))
            with open(img_path, 'rb') as f:
                img = MIMEImage(f.read()); img.add_header('Content-ID', '<radar>')
                img.add_header('Content-Disposition', 'inline', filename='radar.png')
                msg.attach(img)
            with smtplib.SMTP('localhost', 25, timeout=5) as s:
                s.sendmail('tscm@localhost', gw, msg.as_string())
            print(f'  MMS sent to {gw}'); return True
        except Exception as e: print(f'  MMS fail {gw}: {e}')
    return False

def send_text(text):
    for gw in SMS_GATEWAYS[:1]:
        try:
            msg = MIMEText(text, 'plain'); msg['From'] = 'tscm@localhost'; msg['To'] = gw; msg['Subject'] = ''
            with smtplib.SMTP('localhost', 25, timeout=5) as s: s.sendmail('tscm@localhost', gw, msg.as_string())
            print(f'  SMS sent to {gw}'); return True
        except Exception as e: print(f'  SMS fail {gw}: {e}')
    return False

print(f"SMS+Radar started. Live map: {LIVE_URL}")
last_count = -1
while True:
    try:
        sources, obs = get_data()
        count = len(sources); aoa = obs.get('aoa', 0)
        if count > 0 and count != last_count:
            ts = time.strftime('%H:%M'); generate_radar(sources, obs)
            top = sorted(sources, key=lambda s: s.get('observations', 0), reverse=True)[:6]
            lines = [f"TSCM {ts} | AoA:{aoa:.0f}deg | {count}sources"]
            for s in top:
                b = s.get('bearing', 0); o = s.get('observations', 0)
                lines.append(f"  {s.get('detector','?')[:18]} b{b:.0f}deg {o}obs")
            for s in sources:
                if 'nerve' in s.get('detector',''): lines.append(f"  !!NERVE PAIN: {s.get('observations',0)}obs")
            lines.append(f"LIVE MAP: {LIVE_URL}")
            text = '\n'.join(lines)
            sent = send_mms(IMG_PATH, text)
            if not sent: send_text(text)
            with open(SMS_LOG, 'a') as f: f.write(f"[{ts}] {text[:100]}\n")
            last_count = count
            print(f"[{ts}] Sent {count}srcs AoA={aoa:.0f}deg")
        else: print('.', end='', flush=True)
    except Exception as e: print(f"Err: {e}")
    time.sleep(300)
