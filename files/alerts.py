"""
alerts.py — Delivers threat alerts via Tkinter popup and optional e-mail.
"""

import threading
import requests
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
from pathlib import Path
from PIL import ImageGrab

# holds reference to the main Tk root (set by gui.py on startup)
_root: tk.Tk | None = None

def set_root(root: tk.Tk):
    """Called once from gui.py to register the main Tk window."""
    global _root
    _root = root


# ── Screenshot capture ────────────────────────────────────────────────────────

def capture_screenshot(reason: str):
    """Capture screen at moment of alert and save as evidence."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = Path.home() / "HoneyShield_Evidence"
    folder.mkdir(exist_ok=True)
    path = folder / f"alert_{timestamp}.png"
    screenshot = ImageGrab.grab()
    screenshot.save(path)
    return path


# ── Tkinter popup ─────────────────────────────────────────────────────────────

def _evidence_dir() -> Path:
    folder = Path.home() / "HoneyShield_Evidence"
    folder.mkdir(exist_ok=True)
    return folder


def _open_folder(folder: Path):
    import platform
    import subprocess

    if platform.system() == "Windows":
        subprocess.Popen(["explorer", str(folder)])
    elif platform.system() == "Darwin":
        subprocess.Popen(["open", str(folder)])
    else:
        subprocess.Popen(["xdg-open", str(folder)])


def _center_window(win: tk.Toplevel):
    win.update_idletasks()
    width = win.winfo_width()
    height = win.winfo_height()
    screen_w = win.winfo_screenwidth()
    screen_h = win.winfo_screenheight()
    x = max((screen_w - width) // 2, 0)
    y = max((screen_h - height) // 2, 0)
    win.geometry(f"+{x}+{y}")


def show_popup_alert(
    reason: str,
    path: str,
    on_quarantine=None,
    on_backup=None,
    on_dismiss=None,
):
    """
    Schedule the alert popup on the main Tk thread using after().
    This is the correct way to show Tkinter windows from background threads.
    """
    def _build():
        win = tk.Toplevel(_root)
        win.title("  HONEYPOT ALERT")
        win.configure(bg="#1a0000")
        win.resizable(False, False)
        win.attributes("-topmost", True)
        win.lift()
        win.focus_force()

        # ── header ──────────────────────────────────────────────────────────
        tk.Label(win, text="  THREAT DETECTED",
                 font=("Courier New", 18, "bold"),
                 fg="#ff3333", bg="#1a0000").pack(padx=30, pady=(20, 5))

        ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        tk.Label(win, text=ts, font=("Courier New", 9),
                 fg="#888888", bg="#1a0000").pack()

        tk.Frame(win, bg="#ff3333", height=1).pack(fill="x", padx=20, pady=10)

        # ── reason ──────────────────────────────────────────────────────────
        tk.Label(win, text=reason, font=("Courier New", 11),
                 fg="#ffcccc", bg="#1a0000", wraplength=420,
                 justify="center").pack(padx=20)

        if path:
            short = path if len(path) < 55 else "..." + path[-52:]
            tk.Label(win, text=f"File:  {short}",
                     font=("Courier New", 9), fg="#ff8888",
                     bg="#1a0000").pack(pady=(4, 0))

        tk.Frame(win, bg="#330000", height=1).pack(fill="x", padx=20, pady=12)

        # ── recommendations ─────────────────────────────────────────────────
        for rec in [
            "1. Do NOT pay any ransom demand.",
            "2. Disconnect from the internet immediately.",
            "3. Run a full antivirus scan.",
            "4. Restore files from backup.",
        ]:
            tk.Label(win, text=rec, font=("Courier New", 9),
                     fg="#ffaa00", bg="#1a0000",
                     anchor="w").pack(padx=30, anchor="w")

        tk.Frame(win, bg="#330000", height=1).pack(fill="x", padx=20, pady=12)

        # ── buttons ─────────────────────────────────────────────────────────
        btn_frame = tk.Frame(win, bg="#1a0000")
        btn_frame.pack(pady=(0, 20))

        def _quarantine():
            if on_quarantine:
                on_quarantine()
            messagebox.showinfo("Done",
                "Decoy files restored.",
                parent=win)

        def _backup():
            if on_backup:
                on_backup()
            else:
                _open_folder(_evidence_dir())

        def _dismiss():
            if on_dismiss:
                on_dismiss()
            win.destroy()

        tk.Button(btn_frame, text="  Quarantine Decoys",
                  command=_quarantine,
                  bg="#8b0000", fg="white",
                  font=("Courier New", 10, "bold"),
                  relief="flat", padx=12, pady=6).pack(side="left", padx=8)

        tk.Button(btn_frame, text="  Open Evidence Folder",
                  command=_backup,
                  bg="#333300", fg="#ffff88",
                  font=("Courier New", 10),
                  relief="flat", padx=12, pady=6).pack(side="left", padx=8)

        tk.Button(btn_frame, text="Dismiss",
                  command=_dismiss,
                  bg="#222222", fg="#888888",
                  font=("Courier New", 10),
                  relief="flat", padx=12, pady=6).pack(side="left", padx=8)

        win.protocol("WM_DELETE_WINDOW", _dismiss)
        _center_window(win)

    # ── schedule on main thread safely ──────────────────────────────────────
    if _root:
        _root.after(0, _build)
    else:
        threading.Thread(target=_build, daemon=True).start()

# ── Telegram alert ────────────────────────────────────────────────────────────

def send_telegram_alert(bot_token: str, chat_id: str,
                        reason: str, path: str):
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = (
        f"🚨 HoneyShield Alert\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🕒 Time   : {ts}\n"
        f"⚡ Reason : {reason}\n"
        f"📄 File   : {path}\n\n"
        f"⚠ Disconnect internet immediately!"
    )
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        requests.post(url, json={
            "chat_id": chat_id,
            "text": msg
        }, timeout=10)
    except Exception as e:
        print(f"[Telegram] Failed: {e}")
