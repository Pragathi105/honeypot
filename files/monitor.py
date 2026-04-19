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
import getpass
import difflib
from datetime import datetime
from pathlib import Path
from alerts import capture_screenshot
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ── tuneable thresholds ──────────────────────────────────────────────────────
BURST_WINDOW_SECS   = 10   # sliding window for event counting
BURST_THRESHOLD     = 15   # events in window → alert
ENTROPY_THRESHOLD   = 7.2  # bits/byte (encrypted/compressed data ~= 8)
# ────────────────────────────────────────────────────────────────────────────


def normalize(path: str) -> str:
    """Normalize path so Windows backslash vs forward slash never causes mismatches."""
    return str(Path(path).resolve()).lower()


def get_process_info(path: str) -> dict:
    """Get current user and system info at moment of alert."""
    hostname = os.environ.get("COMPUTERNAME", "")
    if not hostname:
        try:
            hostname = os.uname().nodename
        except AttributeError:
            hostname = "unknown"
    return {
        "user":     getpass.getuser(),
        "hostname": hostname,
        "pid":      os.getpid(),
        "time":     datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def file_entropy(path: str, sample_bytes: int = 65536) -> float:
    """Shannon entropy of first `sample_bytes` of file (0-8 bits/byte)."""
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


def read_text_preview(path: str, max_chars: int = 12000) -> str | None:
    """Read a text preview for diffing. Returns None for non-text files."""
    try:
        data = Path(path).read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return None
    return data[:max_chars]


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
    Calls alert_callback(reason, path) when thresholds are crossed.
    """

    def __init__(self, watched_paths: list, decoy_paths: set,
                 alert_callback, log_callback):
        self.watched_paths   = [str(p) for p in watched_paths]
        # normalize all decoy paths on creation
        self.decoy_paths     = {normalize(str(p)) for p in decoy_paths}
        self.alert_callback  = alert_callback
        self.log_callback    = log_callback

        self._event_times: collections.deque = collections.deque()
        self._lock          = threading.Lock()
        self._alerted       = False
        self._baseline: dict = {}   # normalized path -> hash
        self._baseline_text: dict = {}  # normalized path -> original text preview
        self._observer      = None

    # public API

    def start(self):
        self._snapshot_decoys()
        handler = HoneypotEventHandler(self)
        self._observer = Observer()
        for p in self.watched_paths:
            if os.path.isdir(p):
                self._observer.schedule(handler, p, recursive=True)
        self._observer.start()
        self.log_callback(f"Watching: {', '.join(self.watched_paths)}")
        self.log_callback(f"Decoys registered: {len(self.decoy_paths)} files")

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join()

    def reset_alert(self):
        self._alerted = False
        self.log_callback("Alert state reset - monitoring resumed.")

    def record_event(self, event):
        now  = time.time()
        raw  = str(getattr(event, "src_path", ""))
        path = normalize(raw)   # normalize incoming event path

        print(f"[DEBUG] Event  : {path}")
        print(f"[DEBUG] InDecoy: {path in self.decoy_paths}")

        with self._lock:
            self._event_times.append(now)
            while self._event_times and self._event_times[0] < now - BURST_WINDOW_SECS:
                self._event_times.popleft()
            burst = len(self._event_times)

        # decoy tampered?
        decoy_hit = self._check_decoy_event(event)
        if decoy_hit:
            reason, alert_path = decoy_hit
            self._fire_alert(reason, alert_path)
            return

        # burst?
        if burst >= BURST_THRESHOLD and not self._alerted:
            self._fire_alert(
                f"RAPID FILE CHANGES - {burst} events in {BURST_WINDOW_SECS}s", raw)
            return

        # high entropy?
        if os.path.isfile(raw):
            ent = file_entropy(raw)
            if ent >= ENTROPY_THRESHOLD:
                self._fire_alert(
                    f"HIGH ENTROPY FILE - {ent:.2f} bits/byte",
                    raw,
                )
                return

    # internal

    def _event_paths(self, event) -> list[tuple[str, str]]:
        """Return normalized/raw path pairs for all relevant event paths."""
        pairs: list[tuple[str, str]] = []
        seen: set[str] = set()
        for attr in ("src_path", "dest_path"):
            raw = str(getattr(event, attr, "") or "")
            if not raw:
                continue
            normalized = normalize(raw)
            if normalized in seen:
                continue
            seen.add(normalized)
            pairs.append((normalized, raw))
        return pairs

    def _check_decoy_event(self, event):
        event_type = getattr(event, "event_type", "")
        for normalized, raw in self._event_paths(event):
            if normalized not in self.decoy_paths:
                continue

            old_hash = self._baseline.get(normalized, "")
            exists_now = os.path.isfile(raw)
            new_hash = file_hash(raw) if exists_now else ""

            print(f"[DEBUG] DecoyEvent: {event_type} {normalized}")
            print(f"[DEBUG] OldHash: {old_hash}")
            print(f"[DEBUG] NewHash: {new_hash}")
            print(f"[DEBUG] Exists : {exists_now}")

            if not old_hash:
                return ("DECOY FILE MODIFIED (no baseline)", raw)
            if not exists_now:
                return ("DECOY FILE MOVED OR DELETED", raw)
            if new_hash != old_hash:
                return ("DECOY FILE MODIFIED", raw)

        return None

    def _snapshot_decoys(self):
        """Take MD5 baseline of every decoy file using normalized paths."""
        for p in self.decoy_paths:
            if os.path.isfile(p):
                self._baseline[p] = file_hash(p)
                self._baseline_text[p] = read_text_preview(p)
                print(f"[DEBUG] Snapshot: {p} -> {self._baseline[p]}")
            else:
                print(f"[DEBUG] Snapshot MISSING: {p}")

    def _build_diff_lines(self, path: str) -> list[dict]:
        normalized = normalize(path)
        before = self._baseline_text.get(normalized)
        after = read_text_preview(path)
        if before is None or after is None:
            return []

        before_lines = before.splitlines()
        after_lines = after.splitlines()
        matcher = difflib.SequenceMatcher(a=before_lines, b=after_lines)
        diff_lines: list[dict] = []

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                continue
            if tag in ("replace", "delete"):
                for offset, line in enumerate(before_lines[i1:i2], start=i1 + 1):
                    diff_lines.append({
                        "kind": "-",
                        "line_no": offset,
                        "text": line,
                    })
            if tag in ("replace", "insert"):
                for offset, line in enumerate(after_lines[j1:j2], start=j1 + 1):
                    diff_lines.append({
                        "kind": "+",
                        "line_no": offset,
                        "text": line,
                    })

        return diff_lines[:24]

    def _fire_alert(self, reason: str, path: str):
        if self._alerted:
            self.log_callback("Alert already active - dismiss first to reset.")
            return
        self._alerted = True

        # insider threat info
        info = get_process_info(path)
        self.log_callback(
            f"User: {info['user']} on {info['hostname']} at {info['time']}"
        )
        self._write_threat_log(reason, path, info)

        # screenshot - safe, never blocks the alert
        try:
            diff_lines = []
            if reason.startswith("DECOY FILE"):
                diff_lines = self._build_diff_lines(path)
            evidence_path = capture_screenshot(reason, path=path, diff_lines=diff_lines)
            self.log_callback(f"Screenshot saved: {evidence_path}")
        except Exception as e:
            self.log_callback(f"Screenshot failed: {e}")

        # fire the popup
        self.log_callback(f"ALERT: {reason} - {Path(path).name}")
        self.alert_callback(reason, path)

    def _write_threat_log(self, reason, path, info):
        """Write persistent threat log to disk."""
        log_path = Path.home() / "SilentSentinel_Evidence" / "threat_log.txt"
        log_path.parent.mkdir(exist_ok=True)
        with open(log_path, "a") as f:
            f.write(
                f"[{info['time']}] "
                f"User={info['user']} "
                f"Host={info['hostname']} "
                f"PID={info['pid']} "
                f"Reason={reason} "
                f"File={path}\n"
            )
        self.log_callback(f"Threat logged: ~/SilentSentinel_Evidence/threat_log.txt")
