"""
alerts.py — Delivers threat alerts via Tkinter popup and optional e-mail.
"""

import threading
import requests
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
from pathlib import Path
from textwrap import wrap
from PIL import Image, ImageDraw, ImageFont, ImageGrab

# holds reference to the main Tk root (set by gui.py on startup)
_root: tk.Tk | None = None

def set_root(root: tk.Tk):
    """Called once from gui.py to register the main Tk window."""
    global _root
    _root = root


# ── Screenshot capture ────────────────────────────────────────────────────────

def _load_font(size: int, bold: bool = False):
    candidates = [
        "C:/Windows/Fonts/consolab.ttf" if bold else "C:/Windows/Fonts/consola.ttf",
        "C:/Windows/Fonts/courbd.ttf" if bold else "C:/Windows/Fonts/cour.ttf",
    ]
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def _wrap_lines(prefix: str, text: str, width: int) -> list[str]:
    content = f"{prefix}{text}" if prefix else text
    wrapped = wrap(content, width=width, replace_whitespace=False, drop_whitespace=False)
    return wrapped or [content]


def _annotate_screenshot(
    screenshot: Image.Image,
    reason: str,
    path: str,
    diff_lines: list[dict],
) -> Image.Image:
    panel_width = 680
    padding = 24
    bg = "#101010"
    fg = "#f0f0f0"
    muted = "#a0a0a0"
    accent = "#ff4d4d"
    add_bg = "#15351d"
    add_fg = "#9ef0a8"
    del_bg = "#3b1616"
    del_fg = "#ff9c9c"
    info_bg = "#1e1e1e"
    info_fg = "#f5d37d"

    title_font = _load_font(22, bold=True)
    body_font = _load_font(16)
    code_font = _load_font(15)

    row_height = 24
    chars_per_line = 62

    lines: list[tuple[str, str]] = []
    lines.append(("title", "Modified Content"))
    lines.append(("meta", f"Reason: {reason}"))
    lines.append(("meta", f"File: {Path(path).name}"))
    lines.append(("meta", path))
    lines.append(("spacer", ""))

    if diff_lines:
        for entry in diff_lines:
            line_no = entry.get("line_no")
            prefix = f"{entry['kind']} "
            if line_no is not None:
                prefix = f"{entry['kind']} L{line_no}: "
            for wrapped in _wrap_lines(prefix, entry["text"], chars_per_line):
                lines.append((entry["kind"], wrapped))
                prefix = "  "
    else:
        lines.append(("info", "No textual diff preview available for this file."))

    content_height = padding * 2 + 90 + row_height * len(lines)
    canvas_height = max(screenshot.height, content_height)
    canvas = Image.new("RGB", (screenshot.width + panel_width, canvas_height), bg)
    canvas.paste(screenshot, (0, 0))

    draw = ImageDraw.Draw(canvas)
    panel_left = screenshot.width
    draw.rectangle(
        [(panel_left, 0), (canvas.width, canvas.height)],
        fill=bg,
    )
    draw.line(
        [(panel_left, 0), (panel_left, canvas.height)],
        fill="#2a2a2a",
        width=3,
    )

    y = padding
    draw.text((panel_left + padding, y), "SilentSentinel Evidence", fill=accent, font=title_font)
    y += 42
    draw.text((panel_left + padding, y), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), fill=muted, font=body_font)
    y += 36

    for kind, text in lines:
        if kind == "spacer":
            y += 12
            continue

        if kind == "title":
            draw.text((panel_left + padding, y), text, fill=fg, font=body_font)
            y += 28
            continue

        if kind == "meta":
            draw.text((panel_left + padding, y), text, fill=muted, font=body_font)
            y += row_height
            continue

        fill = info_bg
        text_fill = info_fg
        if kind == "+":
            fill = add_bg
            text_fill = add_fg
        elif kind == "-":
            fill = del_bg
            text_fill = del_fg

        draw.rounded_rectangle(
            [
                (panel_left + padding, y - 2),
                (canvas.width - padding, y + row_height - 2),
            ],
            radius=6,
            fill=fill,
        )
        draw.text((panel_left + padding + 10, y), text, fill=text_fill, font=code_font)
        y += row_height + 4

    return canvas


def capture_screenshot(reason: str, path: str = "", diff_lines: list[dict] | None = None):
    """Capture screen at moment of alert and save as evidence."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = Path.home() / "SilentSentinel_Evidence"
    folder.mkdir(exist_ok=True)
    evidence_path = folder / f"alert_{timestamp}.png"
    screenshot = ImageGrab.grab()
    if diff_lines:
        screenshot = _annotate_screenshot(screenshot, reason, path, diff_lines)
    screenshot.save(evidence_path)
    return evidence_path


# ── Tkinter popup ─────────────────────────────────────────────────────────────

def _evidence_dir() -> Path:
    folder = Path.home() / "SilentSentinel_Evidence"
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
                        reason: str, path: str) -> tuple[bool, str]:
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = (
        f"🚨 SilentSentinel Alert\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🕒 Time   : {ts}\n"
        f"⚡ Reason : {reason}\n"
        f"📄 File   : {path}\n\n"
        f"⚠ Disconnect internet immediately!"
    )
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        response = requests.post(url, json={
            "chat_id": chat_id,
            "text": msg
        }, timeout=10)
        response.raise_for_status()
        data = response.json()
        if not data.get("ok"):
            return False, data.get("description", "Telegram rejected the message.")
        return True, "Telegram message sent."
    except requests.HTTPError:
        if response.status_code == 404:
            return False, "Bot token is invalid or malformed. Re-copy it from @BotFather."
        try:
            data = response.json()
            return False, data.get("description", f"HTTP {response.status_code}")
        except Exception:
            return False, f"HTTP {response.status_code}: {response.text[:200]}"
    except requests.RequestException as e:
        return False, f"Network error: {e}"
    except Exception as e:
        return False, f"Unexpected error: {e}"
