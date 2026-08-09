"""camera_probe.py - capture webcam frame in a SEPARATE process.

The suite's /camera/snap handler must never call cv2 in-process: the broken
NVIDIA Broadcast virtual camera driver corrupts the heap (STATUS_HEAP_CORRUPTION,
crash-loop observed 2026-08-09). This probe runs as a child process so any
driver crash kills only this probe, never the suite.

Behavior: try real cameras (skips NVIDIA virtual), save a bright frame to
camera_live.jpg. Exit 0 on success, 1 on failure. Run by the suite at most
once per minute.
"""
import sys
import os
import time

OUT = r"C:\Users\carpe\.openclaw-autoclaw\workspace\camera_live.jpg"
MARK = r"C:\Users\carpe\.openclaw-autoclaw\workspace\camera_probe_mark.txt"

def main():
    try:
        import cv2
        import numpy as np
    except Exception as e:
        _fail("no cv2: %s" % e)
        return 1
    # try real cameras first (skip NVIDIA virtual which is known-broken)
    indices = [0, 1, 2]
    names = []
    try:
        from pygrabber.dshow_graph import FilterGraph
        names = FilterGraph().get_input_devices()
    except Exception:
        pass
    order = []
    for i, name in zip(indices, names + [""] * max(0, len(indices) - len(names))):
        if "nvidia" in name.lower() or "broadcast" in name.lower():
            continue
        order.append(i)
    if not order:
        order = [0, 1, 2]
    for idx in order:
        try:
            cap = cv2.VideoCapture(idx, cv2.CAP_DSHOW)
            if not cap.isOpened():
                cap.release()
                continue
            best = None
            best_mean = 0.0
            for _ in range(4):
                ok, frame = cap.read()
                if ok and frame is not None:
                    g = np.asarray(frame, dtype=np.uint8)
                    if g.ndim == 3:
                        m = float(g.mean(axis=2).mean())
                    else:
                        m = float(g.mean())
                    if m > best_mean:
                        best_mean = m
                        best = frame
                time.sleep(0.12)
            cap.release()
            if best is not None and best_mean >= 12.0:
                ok2, buf = cv2.imencode(".jpg", best, [cv2.IMWRITE_JPEG_QUALITY, 70])
                if ok2:
                    with open(OUT, "wb") as f:
                        f.write(buf.tobytes())
                    with open(MARK, "w") as f:
                        f.write("%d ok idx=%d mean=%.1f" % (time.time(), idx, best_mean))
                    print("probe OK idx=%d mean=%.1f" % (idx, best_mean))
                    return 0
        except Exception as e:
            continue
    _fail("no usable camera frame")
    return 1

def _fail(msg):
    try:
        with open(MARK, "w") as f:
            f.write("%d fail %s" % (time.time(), msg))
    except Exception:
        pass
    print("probe FAIL: %s" % msg)

if __name__ == "__main__":
    sys.exit(main())
