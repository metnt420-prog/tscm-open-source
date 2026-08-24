"""tscm_launcher_supervisor.py - keepalive daemon for tscm_launcher_v5.py
and camera_daemon.py.

The suite has hard-crashed natively (ntdll.dll access violation, 2026-08-09
14:33:12, last log 14:33:08) and wedged earlier the same day (13:32). Nothing
was supervising the launcher, so the map went dark until manual restart.
This daemon restarts it within ~8s of any exit. Logs to launcher_supervisor.log.

FIX 2026-08-12: camera_daemon.py is now supervised here too, so the live
camera frame stays fresh (8s cadence) and is automatically restarted if the
daemon dies. Previously no process supervised the daemon, and the camera
fell back to a 3-day-old corrupted frame.

Run:  python tscm_launcher_supervisor.py   (keep as background service)
"""
import subprocess
import sys
import os
import time
import datetime
import ctypes
from ctypes import wintypes

ENV = os.environ.copy()
ENV['PATH'] = r'C:\Program Files\bladeRF\x64;C:\ProgramData\radioconda\Library\bin;' + ENV.get('PATH', '')
ENV['KMP_DUPLICATE_LIB_OK'] = 'TRUE'
ENV['OPENBLAS_CORETYPE'] = 'NEHALEM'

WORKDIR = r'C:\Users\carpe\.openclaw-autoclaw\workspace'
SCRIPT = 'tscm_launcher_v5.py'
CAMERA_SCRIPT = 'camera_daemon.py'
LOG = os.path.join(WORKDIR, 'launcher_supervisor.log')
RESTART_DELAY_S = 8
MEM_LIMIT_MB = 5000  # auto-restart launcher above this RSS to prevent OOM from leaks


def _rss_mb(pid):
    """Working-set size (MB) of a process via Windows psapi. None on failure."""
    try:
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        h = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h:
            return None
        class _PMC(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]
        pmc = _PMC()
        pmc.cb = ctypes.sizeof(_PMC)
        ok = ctypes.windll.psapi.GetProcessMemoryInfo(
            h, ctypes.byref(pmc), ctypes.sizeof(_PMC))
        ctypes.windll.kernel32.CloseHandle(h)
        if ok:
            return pmc.WorkingSetSize / (1024 * 1024)
    except Exception:
        pass
    return None


def log(msg):
    line = f"[{datetime.datetime.now().isoformat(timespec='seconds')}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG, 'a') as f:
            f.write(line + '\n')
    except Exception:
        pass


def spawn(name, script):
    log(f"launching {script}")
    return subprocess.Popen([sys.executable, script], cwd=WORKDIR, env=ENV,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    log("supervisor starting (launcher + camera daemon)")
    proc = spawn("launcher", SCRIPT)
    cam = spawn("camera", CAMERA_SCRIPT)
    while True:
        rc = proc.poll()
        crc = cam.poll()
        if rc is not None:
            log(f"launcher exited rc={rc} - restarting in {RESTART_DELAY_S}s")
            time.sleep(RESTART_DELAY_S)
            proc = spawn("launcher", SCRIPT)
        if crc is not None:
            log(f"camera daemon exited rc={crc} - restarting in {RESTART_DELAY_S}s")
            time.sleep(RESTART_DELAY_S)
            cam = spawn("camera", CAMERA_SCRIPT)
        # Memory-bloat guard: launcher leaks over time; restart before OOM.
        try:
            _rss = _rss_mb(proc.pid)
            if _rss is not None and _rss > MEM_LIMIT_MB:
                log(f"launcher memory bloat {_rss:.0f}MB > {MEM_LIMIT_MB}MB - restarting")
                try:
                    subprocess.run(['taskkill', '/F', '/T', '/PID', str(proc.pid)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    proc.kill()
                time.sleep(RESTART_DELAY_S)
                proc = spawn("launcher", SCRIPT)
        except Exception:
            pass
        time.sleep(2)


if __name__ == '__main__':
    main()
