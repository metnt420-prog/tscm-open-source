"""tscm_launcher_supervisor.py - keepalive daemon for tscm_launcher_v5.py.

The suite has hard-crashed natively (ntdll.dll access violation, 2026-08-09
14:33:12, last log 14:33:08) and wedged earlier the same day (13:32). Nothing
was supervising the launcher, so the map went dark until manual restart.
This daemon restarts it within ~8s of any exit. Logs to launcher_supervisor.log.

Run:  python tscm_launcher_supervisor.py   (keep as background service)
"""
import subprocess
import sys
import os
import time
import datetime

ENV = os.environ.copy()
ENV['PATH'] = r'C:\Program Files\bladeRF\x64;C:\ProgramData\radioconda\Library\bin;' + ENV.get('PATH', '')
ENV['KMP_DUPLICATE_LIB_OK'] = 'TRUE'
ENV['OPENBLAS_CORETYPE'] = 'NEHALEM'

WORKDIR = r'C:\Users\carpe\.openclaw-autoclaw\workspace'
SCRIPT = 'tscm_launcher_v5.py'
LOG = os.path.join(WORKDIR, 'launcher_supervisor.log')
RESTART_DELAY_S = 8


def log(msg):
    line = f"[{datetime.datetime.now().isoformat(timespec='seconds')}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG, 'a') as f:
            f.write(line + '\n')
    except Exception:
        pass


def main():
    log("supervisor starting")
    while True:
        try:
            log("launching launcher_v5")
            proc = subprocess.Popen([sys.executable, SCRIPT], cwd=WORKDIR, env=ENV,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            rc = proc.wait()
            log(f"launcher exited rc={rc} - restarting in {RESTART_DELAY_S}s")
        except Exception as e:
            log(f"supervisor error: {e}")
        time.sleep(RESTART_DELAY_S)


if __name__ == '__main__':
    main()
