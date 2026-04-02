"""
alerts.py — Delivers threat alerts via Tkinter popup and optional e-mail.
"""

import threading
import smtplib
import tkinter as tk
from tkinter import messagebox
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


# ── Tkinter popup ─────────────────────────────────────────────────────────────

def show_popup_alert(reason: str, path: str, on_quarantine=None, on_backup=None):
    """
    Display a red-themed alert window on the main thread.
    Buttons: Quarantine Decoys | Open Backup Folder | Dismiss
    """

    def _build():
        win = tk.Tk()
        win.title("⚠  HONEYPOT ALERT")
        win.configure(bg="#1a0000")
        win.resizable(False, False)
        win.attributes("-topmost", True)

        # ── header ──────────────────────────────────────────────────────────
        hdr = tk.Label(win, text="🚨  THREAT DETECTED",
                       font=("Courier New", 18, "bold"),
                       fg="#ff3333", bg="#1a0000")
        hdr.pack(padx=30, pady=(20, 5))

        ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        tk.Label(win, text=ts, font=("Courier New", 9),
                 fg="#888888", bg="#1a0000").pack()

        tk.Frame(win, bg="#ff3333", height=1).pack(fill="x", padx=20, pady=10)

        # ── reason ──────────────────────────────────────────────────────────
        tk.Label(win, text=reason, font=("Courier New", 11),
                 fg="#ffcccc", bg="#1a0000", wraplength=420,
                 justify="center").pack(padx=20)

        if path:
            short = path if len(path) < 55 else "…" + path[-52:]
            tk.Label(win, text=f"File:  {short}",
                     font=("Courier New", 9), fg="#ff8888",
                     bg="#1a0000").pack(pady=(4, 0))

        tk.Frame(win, bg="#330000", height=1).pack(fill="x", padx=20, pady=12)

        # ── recommendations ─────────────────────────────────────────────────
        recs = [
            "1. Do NOT pay any ransom demand.",
            "2. Disconnect from the internet immediately.",
            "3. Run a full antivirus scan.",
            "4. Restore files from backup.",
        ]
        for rec in recs:
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
            messagebox.showinfo("Done", "Decoy files quarantined (backed up & re-created).",
                                parent=win)

        def _backup():
            import subprocess, platform
            folder = str(__import__("pathlib").Path.home())
            if platform.system() == "Windows":
                subprocess.Popen(["explorer", folder])
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", folder])
            else:
                subprocess.Popen(["xdg-open", folder])

        tk.Button(win, text="🛡  Quarantine Decoys",
                  command=_quarantine,
                  bg="#8b0000", fg="white",
                  font=("Courier New", 10, "bold"),
                  relief="flat", padx=12, pady=6).pack(
            side="left", padx=8, in_=btn_frame)

        tk.Button(win, text="💾  Open Backup Folder",
                  command=_backup,
                  bg="#333300", fg="#ffff88",
                  font=("Courier New", 10),
                  relief="flat", padx=12, pady=6).pack(
            side="left", padx=8, in_=btn_frame)

        tk.Button(win, text="Dismiss",
                  command=win.destroy,
                  bg="#222222", fg="#888888",
                  font=("Courier New", 10),
                  relief="flat", padx=12, pady=6).pack(
            side="left", padx=8, in_=btn_frame)

        win.eval("tk::PlaceWindow . center")
        win.mainloop()

    t = threading.Thread(target=_build, daemon=True)
    t.start()


# ── E-mail alert ──────────────────────────────────────────────────────────────

def send_email_alert(
    smtp_host: str, smtp_port: int,
    sender: str, password: str,
    recipient: str,
    reason: str, path: str
):
    """
    Send a plain-text threat notification via SMTP (e.g. Gmail).
    Call this in a background thread so it doesn't block the UI.
    """
    subject = "🚨 HoneyShield — Ransomware Activity Detected"
    ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body    = f"""HoneyShield Threat Alert
========================
Time  : {ts}
Reason: {reason}
File  : {path}

Immediate recommendations:
  1. Disconnect from the internet.
  2. Do NOT pay any ransom demand.
  3. Run a full antivirus scan.
  4. Restore files from a clean backup.

— HoneyShield Ransomware Early-Warning System
"""
    msg = MIMEMultipart()
    msg["From"]    = sender
    msg["To"]      = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    def _send():
        try:
            with smtplib.SMTP_SSL(smtp_host, smtp_port) as s:
                s.login(sender, password)
                s.sendmail(sender, recipient, msg.as_string())
        except Exception as exc:
            print(f"[Email] Failed to send alert: {exc}")

    threading.Thread(target=_send, daemon=True).start()
