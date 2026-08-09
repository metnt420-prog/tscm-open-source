"""bladeRF_tx_watchdog.py - kill rogue persistent bladeRF-cli sessions.

Incident 2026-08-09: BladeRFTXBridge.start_tx() (null-steering path) spawns a
persistent interactive 'bladeRF-cli -i' that holds the bladeRF USB device
exclusively. Every RX capture subprocess then fails with 'device in use' ->
the map shows BladeRF OFF while the hardware appears powered and TX 'going',
and the 2.4 GHz channel goes blind (AoA freezes).

Legitimate bladeRF-cli invocations in this suite are all SHORT-LIVED:
  - capture:  'bladeRF-cli -s <script>'  (timeout 8s)
  - tx burst: 'bladeRF-cli -s <script>'  (<3s)
  - firmware: 'bladeRF-cli -i' with communicate(timeout=5)
  - gps scan: 'bladeRF-cli -e ...'       (timeout 6s)

Therefore any bladeRF-cli process alive > MAX_AGE_S is rogue. This watchdog
kills it and logs the event (forensic trail for the evidence package).

Run:  python bladeRF_tx_watchdog.py   (keep as background service)
"""
import subprocess
import time
import os
import json
from datetime import datetime

MAX_AGE_S = 45        # kill any bladeRF-cli alive longer than this
HARD_AGE_S = 120      # even '-s' scripts stuck this long are hung -> kill
CHECK_EVERY_S = 15
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   'bladeRF_tx_watchdog.log')


def log(msg):
    line = f"{datetime.now().isoformat(timespec='seconds')} | {msg}"
    print(line, flush=True)
    try:
        with open(LOG, 'a') as f:
            f.write(line + "\n")
    except Exception:
        pass


def list_bladerf():
    """Return list of {pid, age_s, cmdline} for bladeRF-cli.exe processes."""
    ps = (
        "Get-CimInstance Win32_Process -Filter \"Name='bladeRF-cli.exe'\" | "
        "ForEach-Object { [PSCustomObject]@{ "
        "  ProcessId=$_.ProcessId; "
        "  Created=$_.CreationDate.ToString('yyyy-MM-dd HH:mm:ss'); "
        "  CmdLine=$_.CommandLine } } | ConvertTo-Json -Compress"
    )
    out = subprocess.run(['powershell', '-NoProfile', '-Command', ps],
                         capture_output=True, text=True, timeout=20)
    raw = (out.stdout or '').strip()
    if not raw:
        return []
    procs = json.loads(raw)
    if isinstance(procs, dict):
        procs = [procs]
    now = datetime.now()
    result = []
    for p in procs:
        try:
            created = datetime.strptime(str(p.get('Created'))[:19],
                                        '%Y-%m-%d %H:%M:%S')
            age = (now - created).total_seconds()
        except Exception:
            age = HARD_AGE_S + 1  # unknown age -> treat as suspect
        result.append({'pid': int(p.get('ProcessId') or 0),
                       'age': age,
                       'cmd': str(p.get('CmdLine') or '')})
    return result


def main():
    log(f"watchdog started (max_age={MAX_AGE_S}s check={CHECK_EVERY_S}s)")
    while True:
        try:
            for p in list_bladerf():
                pid = p['pid']
                if not pid:
                    continue
                age = p['age']
                cmd = p['cmd']
                interactive = '-i' in cmd
                if age > MAX_AGE_S and (interactive or age > HARD_AGE_S):
                    log(f"KILL rogue bladeRF-cli pid={pid} age={age:.0f}s "
                        f"interactive={interactive} cmd='{cmd[:80]}'")
                    try:
                        subprocess.run(['taskkill', '/PID', str(pid), '/F'],
                                       capture_output=True, timeout=10)
                    except Exception as e:
                        log(f"taskkill failed: {e}")
        except Exception as e:
            log(f"watchdog error: {e}")
        time.sleep(CHECK_EVERY_S)


if __name__ == '__main__':
    main()
