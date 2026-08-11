"""
TSCM Watchdog — PID-aware health monitor with jittered check intervals.
WIGGLE: Randomized intervals (±20%) to prevent adversary timing attacks.
Only kills the specific TSCM PID — not all Python processes.
"""
import subprocess, os, time, socket, sys, random
from datetime import datetime

LOG = r'C:\Users\carpe\.openclaw-autoclaw\workspace\watchdog_guardian.py.log'
TSCM_SCRIPT = r'C:\Users\carpe\.openclaw-autoclaw\workspace\tscm_final.py'
PYTHON = r'C:\Program Files\AutoClaw\resources\python\python.exe'
MAP_PORT = 8080
PID_FILE = r'C:\Users\carpe\.openclaw-autoclaw\workspace\tscm.pid'
CHECK_INTERVAL = 300
MAX_CONSECUTIVE_RESTARTS = 3

_rng = random.SystemRandom()

def jitter(sec, pct=0.20):
    return sec * (1.0 + _rng.uniform(-pct, pct))

def log(msg):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f'{ts} [WATCHDOG] {msg}'
    print(line)
    with open(LOG, 'a') as f:
        f.write(line + '\n')

def get_tscm_pid():
    try:
        with open(PID_FILE, 'r') as f:
            return int(f.read().strip())
    except:
        return None

def is_tscm_running():
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect(('127.0.0.1', MAP_PORT))
        s.sendall(b'GET / HTTP/1.0\r\n\r\n')
        resp = s.recv(64)
        s.close()
        return b'200' in resp
    except:
        return False

def kill_tscm():
    pid = get_tscm_pid()
    if pid:
        try:
            subprocess.run(['taskkill', '/PID', str(pid)], capture_output=True, timeout=5)
            time.sleep(3)
        except:
            pass
        try:
            subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True, timeout=5)
            log(f'Force-killed TSCM PID {pid}')
        except:
            pass
    else:
        log('No PID file found, cannot selectively kill')
    time.sleep(8)

def launch_tscm():
    env = os.environ.copy()
    env['KMP_DUPLICATE_LIB_OK'] = 'TRUE'
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    proc = subprocess.Popen(
        [PYTHON, TSCM_SCRIPT],
        env=env,
        creationflags=subprocess.CREATE_NEW_CONSOLE
    )
    with open(PID_FILE, 'w') as f:
        f.write(str(proc.pid))
    log(f'TSCM launched (PID {proc.pid})')

if __name__ == '__main__':
    log('Watchdog started (PID-aware, jittered intervals)')
    consecutive_restarts = 0

    while True:
        try:
            if is_tscm_running():
                consecutive_restarts = 0
            else:
                log('TSCM not responding — restarting (PID-aware)')
                kill_tscm()
                launch_tscm()
                consecutive_restarts += 1
                if consecutive_restarts >= MAX_CONSECUTIVE_RESTARTS:
                    log(f'ALERT: {consecutive_restarts} consecutive restarts — hardware may need attention')
                time.sleep(jitter(60, pct=0.33))

            time.sleep(jitter(CHECK_INTERVAL, pct=0.20))
        except Exception as e:
            log(f'Watchdog error: {e}')
            time.sleep(jitter(CHECK_INTERVAL, pct=0.20))
