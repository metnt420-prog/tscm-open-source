"""
Continuous WiFi intrusion monitor.
Watches for attacker devices reconnecting after router reset.
Alerts on: pwned, moto g, spoofed MACs, new unknown devices.
"""
import subprocess
import json
import time
from datetime import datetime

KNOWN_SAFE = {
    'min': 'YOUR ROUTER',
    'OpenBCI-3D8A': 'YOUR BCI',
    'NTGR_VMB_1406851472': 'NEARBY NETGEAR',
    'ILTruckAndRV-5': 'NEARBY BUSINESS',
    'ILTuckAndRV-2.4': 'NEARBY BUSINESS',
    'TricorRacing': 'NEARBY BUSINESS',
    'VCC-Guest': 'JOLIET COLLEGE',
    'VCC-Program': 'JOLIET COLLEGE',
    'VCC-Secure': 'JOLIET COLLEGE',
}

ATTACKER_SSIDS = {'pwned', 'moto g 5G (2022)_1073'}

OUTPUT = r'C:\Users\carpe\.openclaw-autoclaw\workspace\models\wifi_intrusion_log.json'
CHECK_INTERVAL = 30  # seconds

def scan_wifi():
    r = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                       capture_output=True, text=True, timeout=15)
    networks = {}
    current = ''
    for line in r.stdout.split('\n'):
        l = line.strip()
        if 'SSID' in l and ':' in l and 'BSSID' not in l:
            current = l.split(':', 1)[1].strip()
            if current and current not in networks:
                networks[current] = {'signal': '', 'channel': '', 'auth': '', 'bssid': '', 'spoofed': False}
        elif current and current in networks:
            if 'Signal' in l:
                networks[current]['signal'] = l.split(':', 1)[1].strip()
            elif 'Channel' in l:
                networks[current]['channel'] = l.split(':', 1)[1].strip()
            elif 'Authentication' in l:
                networks[current]['auth'] = l.split(':', 1)[1].strip()
            elif 'BSSID' in l and ':' in l:
                mac = l.split(':', 1)[1].strip()
                networks[current]['bssid'] = mac
                try:
                    first = int(mac.split(':')[0].replace('-', ''), 16)
                    networks[current]['spoofed'] = bool(first & 0x02)
                except:
                    pass
    return networks

def main():
    print("[WIFI-MON] Starting continuous WiFi intrusion monitor...")
    print("[WIFI-MON] Checking every %d seconds" % CHECK_INTERVAL)
    
    alerts = []
    baseline = None
    
    while True:
        try:
            networks = scan_wifi()
            ts = datetime.now().isoformat()
            
            new_alerts = []
            
            # Check for attacker SSIDs
            for ssid in ATTACKER_SSIDS:
                if ssid in networks:
                    alert = {
                        'timestamp': ts,
                        'type': 'ATTACKER_DEVICE',
                        'ssid': ssid,
                        'details': networks[ssid]
                    }
                    new_alerts.append(alert)
                    print("[ALERT] %s ATTACKER DEVICE: %s (%s)" % (ts[:19], ssid, networks[ssid]['signal']))
            
            # Check for new unknown devices
            if baseline is not None:
                for ssid in networks:
                    if ssid not in baseline and ssid not in KNOWN_SAFE:
                        alert = {
                            'timestamp': ts,
                            'type': 'NEW_UNKNOWN_DEVICE',
                            'ssid': ssid,
                            'details': networks[ssid]
                        }
                        new_alerts.append(alert)
                        print("[ALERT] %s NEW DEVICE: %s (%s)" % (ts[:19], ssid, networks[ssid]['signal']))
            
            # Check for spoofed MACs on unknown networks
            for ssid, info in networks.items():
                if info.get('spoofed') and ssid not in KNOWN_SAFE and ssid not in ATTACKER_SSIDS:
                    alert = {
                        'timestamp': ts,
                        'type': 'SPOOFED_MAC',
                        'ssid': ssid,
                        'bssid': info.get('bssid', ''),
                        'details': info
                    }
                    new_alerts.append(alert)
                    print("[ALERT] %s SPOOFED MAC: %s (%s)" % (ts[:19], ssid, info.get('bssid', '')))
            
            # Status
            n_known = sum(1 for s in networks if s in KNOWN_SAFE)
            n_unknown = len(networks) - n_known
            print("[WIFI-MON] %s | %d networks (%d known, %d unknown) | %d alerts" % (
                ts[:19], len(networks), n_known, n_unknown, len(new_alerts)))
            
            # Save alerts
            if new_alerts:
                alerts.extend(new_alerts)
                with open(OUTPUT, 'w') as f:
                    json.dump(alerts, f, indent=2, default=str)
            
            baseline = networks
            time.sleep(CHECK_INTERVAL)
            
        except KeyboardInterrupt:
            print("[WIFI-MON] Stopped")
            break
        except Exception as e:
            print("[WIFI-MON] Error: %s" % e)
            time.sleep(10)

if __name__ == '__main__':
    main()
