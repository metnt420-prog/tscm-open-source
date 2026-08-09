# tscm_watchdog.py - KEEPALIVE DAEMON
# Wraps tscm_final.py, auto-restarts on ANY crash

import subprocess, sys, os, time, datetime

ENV = os.environ.copy()
ENV['PATH'] = r'C:\Program Files\bladeRF\x64;C:\ProgramData\radioconda\Library\bin;' + ENV.get('PATH','')
ENV['KMP_DUPLICATE_LIB_OK'] = 'TRUE'
ENV['OPENBLAS_CORETYPE'] = 'NEHALEM'

WORKDIR = r'C:\Users\carpe\.openclaw-autoclaw\workspace'
SCRIPT = 'tscm_final.py'  # Full suite: real resolve_sources with cross-sensor triangulation
MAX_RESTARTS = 100
RESTART_DELAY = 10  # seconds

restart_count = 0
start_time = time.time()

print(f'[{datetime.datetime.now()}] TSCM WATCHDOG STARTING')
print(f'  Script: {SCRIPT}')
print(f'  Working dir: {WORKDIR}')

while restart_count < MAX_RESTARTS:
    try:
        print(f'[{datetime.datetime.now()}] LAUNCH #{restart_count+1}')
        proc = subprocess.Popen(
            [sys.executable, SCRIPT],
            cwd=WORKDIR,
            env=ENV,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        # Monitor - read output lines
        for line in proc.stdout:
            line = line.strip()
            if line:
                # Filter noise
                if 'Warning' in line or 'warning' in line or 'ERROR' in line or 'Error' in line or 'CRASH' in line or 'Traceback' in line:
                    print(f'  [{datetime.datetime.now().strftime("%H:%M:%S")}] {line[:120]}')
        
        proc.wait()
        exit_code = proc.returncode
        elapsed = time.time() - start_time
        
        if exit_code == 0 or exit_code == -15:  # clean exit or SIGTERM
            print(f'[{datetime.datetime.now()}] Clean exit (code {exit_code}), watchdog stopping')
            break
        
        print(f'[{datetime.datetime.now()}] CRASHED (exit {exit_code}) after {elapsed:.0f}s total')
        
    except Exception as e:
        print(f'[{datetime.datetime.now()}] WATCHDOG EXCEPTION: {e}')
    
    restart_count += 1
    if restart_count < MAX_RESTARTS:
        print(f'[{datetime.datetime.now()}] Restarting in {RESTART_DELAY}s (attempt {restart_count}/{MAX_RESTARTS})')
        time.sleep(RESTART_DELAY)

print(f'[{datetime.datetime.now()}] WATCHDOG EXITING after {restart_count} restarts in {time.time()-start_time:.0f}s')
