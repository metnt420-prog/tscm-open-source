"""camera_probe.py - capture webcam frame in a SEPARATE process.

The suite's /camera/snap handler must never open cv2 in-process: the broken
NVIDIA Broadcast virtual camera driver corrupts the heap (STATUS_HEAP_CORRUPTION,
crash-loop observed 2026-08-09). This probe runs as a child process so any
driver crash kills only this probe, never the suite.

FIX 2026-08-12 (quality-aware selection): the previous brightness-only guard
locked in a corrupted "bright" frame (mean 104.8, noise-floor 44, 84% of
spectral energy above 0.5*Nyquist = white-noise/static image) for 3 days and
rejected every newer, cleaner frame. Selection now scores frames on QUALITY
first: noise floor (residual std after 5x5 blur) and high-frequency share.
A frame must be "clean" (noise < 12, hf_share < 0.6) before it can replace
the stored image; brightness is only a tie-breaker among clean frames.

Behavior: try real cameras (skips NVIDIA virtual), save a clean frame to
camera_live.jpg. Exit 0 on success, 1 on failure. Run by the suite at most
once per minute (the camera_daemon keeps the frame fresh every 8s).
"""
import sys
import os
import time

OUT = r"C:\Users\carpe\.openclaw-autoclaw\workspace\camera_live.jpg"
MARK = r"C:\Users\carpe\.openclaw-autoclaw\workspace\camera_probe_mark.txt"

NOISE_MAX = 12.0      # residual std after 5x5 blur; >this = fuzzy/static frame
HF_SHARE_MAX = 0.60   # fraction of DFT energy above 0.5*Nyquist; >this = noise-dominated
MIN_BRIGHTNESS = 8.0  # absolute floor (a truly dark lens is also unusable)


def frame_quality(gray):
    """Return (noise_floor, hf_share, mean) for a grayscale uint8 frame."""
    import cv2
    import numpy as np
    g = gray.astype(np.float32)
    mean = float(g.mean())
    blur = cv2.blur(g, (5, 5))
    noise = float((g - blur).std())
    h, w = g.shape
    dft = np.fft.fftshift(np.fft.fft2(g))
    mag = np.abs(dft)
    cy, cx = h // 2, w // 2
    yy, xx = np.ogrid[:h, :w]
    r = np.sqrt((yy - cy) ** 2 + (xx - cx) ** 2)
    rmax = min(cy, cx)
    total = mag.sum() + 1e-9
    hf = float(mag[(r > 0.5 * rmax)].sum() / total)
    return noise, hf, mean


def is_clean(gray):
    noise, hf, mean = frame_quality(gray)
    return (noise < NOISE_MAX) and (hf < HF_SHARE_MAX) and (mean >= MIN_BRIGHTNESS), (noise, hf, mean)


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

    # Existing frame: remember its quality so we never regress to a worse one.
    prev_clean = False
    prev_q = (0.0, 0.0, 0.0)
    try:
        if os.path.exists(OUT):
            _pi = cv2.imread(OUT)
            if _pi is not None:
                _pg = cv2.cvtColor(_pi, cv2.COLOR_BGR2GRAY)
                prev_clean, prev_q = is_clean(_pg)
    except Exception:
        pass

    best_clean = None       # best QUALITY frame found this run
    best_clean_mean = 0.0
    best_any = None         # fallback: any frame (only used if no clean found AND none stored)
    best_any_mean = 0.0
    for idx in order:
        try:
            cap = cv2.VideoCapture(idx, cv2.CAP_DSHOW)
            if not cap.isOpened():
                cap.release()
                continue
            try:
                cap.set(cv2.CAP_PROP_AUTO_EXPOSURE, 1)
            except Exception:
                pass
            try:
                cap.set(cv2.CAP_PROP_BRIGHTNESS, 128)
            except Exception:
                pass
            for _ in range(4):
                ok, frame = cap.read()
                if ok and frame is not None:
                    g = np.asarray(frame, dtype=np.uint8)
                    if g.ndim == 3:
                        gray = cv2.cvtColor(g, cv2.COLOR_BGR2GRAY)
                        m = float(gray.mean())
                    else:
                        gray = g
                        m = float(gray.mean())
                    if m > best_any_mean:
                        best_any_mean = m
                        best_any = frame
                    clean, (noise, hf, mean) = is_clean(gray)
                    if clean and m > best_clean_mean:
                        best_clean_mean = m
                        best_clean = frame
                time.sleep(0.12)
            cap.release()
        except Exception:
            continue

    if best_clean is not None:
        # CLAHE contrast lift for dark-but-clean frames (room lighting is poor).
        try:
            if best_clean_mean < 60.0:
                _lab = cv2.cvtColor(best_clean, cv2.COLOR_BGR2LAB)
                _l, _a, _b = cv2.split(_lab)
                _clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
                _l2 = _clahe.apply(_l)
                _target = 120.0
                _cur = float(_l2.mean())
                if _cur > 0:
                    _l2 = cv2.convertScaleAbs(_l2, alpha=min(2.2, _target / _cur), beta=6)
                _lab2 = cv2.merge([_l2, _a, _b])
                best_clean = cv2.cvtColor(_lab2, cv2.COLOR_LAB2BGR)
        except Exception:
            pass
        ok2, buf = cv2.imencode(".jpg", best_clean, [cv2.IMWRITE_JPEG_QUALITY, 75])
        if ok2:
            with open(OUT, "wb") as f:
                f.write(buf.tobytes())
            with open(MARK, "w") as f:
                f.write("%d ok-clean idx chosen mean=%.1f (prev_clean=%s)" % (
                    time.time(), best_clean_mean, prev_clean))
            print("probe OK-CLEAN mean=%.1f" % best_clean_mean)
            return 0
    elif prev_clean:
        # Nothing clean this run but we already have a clean stored frame: keep it.
        with open(MARK, "w") as f:
            f.write("%d keep existing clean frame" % time.time())
        print("probe KEEP existing clean frame")
        return 0
    elif best_any is not None:
        # No clean frame ever and none stored: store best-effort rather than nothing.
        ok2, buf = cv2.imencode(".jpg", best_any, [cv2.IMWRITE_JPEG_QUALITY, 75])
        if ok2:
            with open(OUT, "wb") as f:
                f.write(buf.tobytes())
            with open(MARK, "w") as f:
                f.write("%d ok-best-effort mean=%.1f (NO CLEAN FRAME AVAILABLE)" % (
                    time.time(), best_any_mean))
            print("probe OK-BEST-EFFORT mean=%.1f" % best_any_mean)
            return 0
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
