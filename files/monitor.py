"""
monitor.py — Core file system watcher using watchdog.
Tracks modification rates, computes entropy, detects ransomware-like bursts.
"""

import os
import time
import math
import hashlib
import threading
import collections
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ── tuneable thresholds ──────────────────────────────────────────────────────
BURST_WINDOW_SECS   = 10   # sliding window for event counting
BURST_THRESHOLD     = 15   # events in window → alert
ENTROPY_THRESHOLD   = 7.2  # bits/byte (encrypted/compressed data ~= 8)
# ────────────────────────────────────────────────────────────────────────────


def file_entropy(path: str, sample_bytes: int = 65536) -> float:
    """Shannon entropy of first `sample_bytes` of file (0–8 bits/byte)."""
    try:
        with open(path, "rb") as f:
            data = f.read(sample_bytes)
        if not data:
            return 0.0
        freq = collections.Counter(data)
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in freq.values())
    except (OSError, PermissionError):
        return 0.0


def file_hash(path: str) -> str:
    """MD5 of file (fast enough for decoy checking)."""
    h = hashlib.md5()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except (OSError, PermissionError):
        pass
    return h.hexdigest()


class HoneypotEventHandler(FileSystemEventHandler):
    """Watchdog handler that feeds events into the threat engine."""

    def __init__(self, engine):
        super().__init__()
        self.engine = engine

    def on_any_event(self, event):
        if event.is_directory:
            return
        self.engine.record_event(event)


class ThreatEngine:
    """
    Sliding-window event counter + entropy checker.
    Calls `alert_callback(reason, path)` when thresholds are crossed.
    """

    def __init__(self, watched_paths: list, decoy_paths: set,
                 alert_callback, log_callback):
        self.watched_paths   = [str(p) for p in watched_paths]
        self.decoy_paths     = {str(p) for p in decoy_paths}
        self.alert_callback  = alert_callback
        self.log_callback    = log_callback

        self._event_times: collections.deque = collections.deque()
        self._lock          = threading.Lock()
        self._alerted       = False          # one-shot per session
        self._baseline: dict[str, str] = {}  # path → hash for decoys
        self._observer      = None

    # ── public API ──────────────────────────────────────────────────────────

    def start(self):
        self._snapshot_decoys()
        handler  = HoneypotEventHandler(self)
        self._observer = Observer()
        for p in self.watched_paths:
            if os.path.isdir(p):
                self._observer.schedule(handler, p, recursive=True)
        self._observer.start()
        self.log_callback(f"👁  Watching: {', '.join(self.watched_paths)}")

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join()

    def reset_alert(self):
        self._alerted = False
        self.log_callback("🔄  Alert state reset — monitoring resumed.")

    def record_event(self, event):
        now = time.time()
        path = str(getattr(event, "src_path", ""))

        with self._lock:
            self._event_times.append(now)
            # purge old
            while self._event_times and self._event_times[0] < now - BURST_WINDOW_SECS:
                self._event_times.popleft()
            burst = len(self._event_times)

        # ── decoy tampered? ─────────────────────────────────────────────────
        if path in self.decoy_paths:
            new_hash = file_hash(path)
            old_hash = self._baseline.get(path, "")
            if old_hash and new_hash != old_hash:
                self._fire_alert("🍯  DECOY FILE MODIFIED", path)
                return

        # ── burst? ──────────────────────────────────────────────────────────
        if burst >= BURST_THRESHOLD and not self._alerted:
            self._fire_alert(
                f"⚡  RAPID FILE CHANGES — {burst} events in {BURST_WINDOW_SECS}s", path)
            return

        # ── high entropy? ────────────────────────────────────────────────────
        if os.path.isfile(path):
            ent = file_entropy(path)
            if ent >= ENTROPY_THRESHOLD:
                self.log_callback(
                    f"⚠  High entropy {ent:.2f} bits/byte: {Path(path).name}")

    # ── internal ────────────────────────────────────────────────────────────

    def _snapshot_decoys(self):
        for p in self.decoy_paths:
            if os.path.isfile(p):
                self._baseline[p] = file_hash(p)

    def _fire_alert(self, reason: str, path: str):
        if self._alerted:
            return
        self._alerted = True
        self.log_callback(f"🚨  ALERT: {reason} — {Path(path).name}")
        self.alert_callback(reason, path)
