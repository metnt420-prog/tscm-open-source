#!/usr/bin/env python3
"""SMS alerts for TSCM detections via Twilio. Sends map link + source summary every 5 min."""
import time, json, urllib.request, sys, os

TO_NUMBER = "+18156906926"
# Using email-to-SMS gateway for now (no Twilio key)
# 815-690-6926 carrier lookup needed for @mms gateway
# Common: @vtext.com (Verizon), @mms.att.net (AT&T), @tmomail.net (T-Mobile)
# Will use SMTP to send via email-to-SMS

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

MAP_URL = "http://localhost:8080"

def send_sms_via_email(number, message_body):
    """Send SMS via email-to-SMS gateway. Tries major carriers."""
    # Carrier email-to-SMS gateways (try all common ones)
    gateways = [
        f"{number}@vtext.com",      # Verizon
        f"{number}@mms.att.net",    # AT&T
        f"{number}@tmomail.net",    # T-Mobile
        f"{number}@messaging.sprintpcs.com",  # Sprint
        f"{number}@msg.fi.google.com",  # Google Fi
    ]
    
    msg = MIMEMultipart()
    msg['From'] = "tscm@localhost"
    msg['Subject'] = ""
    msg.attach(MIMEText(message_body, 'plain'))
    
    sent = False
    for gw in gateways[:3]:  # try top 3
        try:
            msg['To'] = gw
            with smtplib.SMTP('localhost', 25, timeout=5) as s:
                s.sendmail("tscm@localhost", gw, msg.as_string())
            print(f"  Sent to {gw}")
            sent = True
        except Exception as e:
            print(f"  Failed {gw}: {e}")
    
    return sent

def get_source_summary():
    try:
        d = json.loads(urllib.request.urlopen(f"{MAP_URL}/api/detections", timeout=3).read())
        srcs = d.get('sources', [])
        obs = d.get('observer', {})
        aoa = obs.get('aoa', 0)
        
        lines = [f"TSCM UPDATE - {time.strftime('%H:%M:%S')}"]
        lines.append(f"AoA:{aoa:.0f}deg | GPS:{'FIX' if obs.get('gps_fix') else 'NO'}")
        lines.append(f"Sources: {len(srcs)} | {MAP_URL}")
        lines.append("")
        
        # Top 5 by observations
        top = sorted(srcs, key=lambda s: s.get('observations', 0), reverse=True)[:8]
        for s in top:
            det = s.get('detector', '?')
            obs_n = s.get('observations', 0)
            bearing = s.get('bearing', None)
            freq = s.get('freq', 0)
            b_str = f"{bearing:.0f}deg" if bearing else "?"
            f_str = f"{freq/1000:.0f}kHz" if freq > 1000 else (f"{freq:.0f}Hz" if freq > 0 else "-")
            lines.append(f"  {det[:20]:20s} {b_str:5s} {f_str:6s} {obs_n}obs")
        
        # Nerve pain specifically
        for s in srcs:
            if 'nerve' in s.get('detector', ''):
                lines.append(f"  >> NERVE PAIN: {s.get('observations',0)}obs")
        
        return '\n'.join(lines)
    except Exception as e:
        return f"TSCM: error fetching data - {e}"

# Main loop - send every 300 seconds
print("SMS Alert started for 815-690-6926")
last_hash = ""
while True:
    try:
        summary = get_source_summary()
        # Only send if data changed or 5 min since last
        new_hash = str(hash(summary))
        if new_hash != last_hash:
            print(f"\n--- {time.strftime('%H:%M:%S')} ---")
            print(summary)
            sent = send_sms_via_email("8156906926", summary)  # user's number
            if not sent:
                # Fallback: log to file
                with open('sms_log.txt','a') as f:
                    f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {summary}\n")
            last_hash = new_hash
        else:
            print(f".", end="", flush=True)
    except Exception as e:
        print(f"Alert error: {e}")
    time.sleep(300)  # 5 minutes
