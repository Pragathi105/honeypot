"""
gui.py — HoneyShield dashboard (Tkinter).
Dark terminal aesthetic with live event log and status indicators.
"""

import os
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from pathlib import Path
from datetime import datetime

from decoys  import create_decoys, restore_decoys, remove_decoys, get_decoy_dir
from monitor import ThreatEngine
from alerts  import show_popup_alert, send_telegram_alert, set_root

# ── colour palette ────────────────────────────────────────────────────────────
BG       = "#0d0d0d"
BG2      = "#141414"
BG3      = "#1c1c1c"
ACCENT   = "#00ff88"
DANGER   = "#ff3333"
WARN     = "#ffaa00"
DIM      = "#444444"
TEXT     = "#cccccc"
TEXT_DIM = "#555555"
FONT_MONO= ("Courier New", 10)
FONT_BIG = ("Courier New", 14, "bold")
FONT_SM  = ("Courier New", 9)


class HoneyShieldApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("HoneyShield — Ransomware Early-Warning System")
        root.configure(bg=BG)
        root.geometry("860x640")
        root.minsize(760, 560)

        self.engine: ThreatEngine | None = None
        self.decoy_paths: list[Path]     = []
        self.watch_dir    = tk.StringVar(value=str(Path.home() / "Documents"))
        self.running      = tk.BooleanVar(value=False)
        self.telegram_cfg = {}   # populated via telegram settings dialog

        self._build_ui()
        set_root(root)   # register root with alerts.py for thread-safe popups
        self._log("HoneyShield ready. Choose a folder and click Start Monitoring.")

    # ══════════════════════════════════════════════════════════════════════════
    # UI construction
    # ══════════════════════════════════════════════════════════════════════════

    def _build_ui(self):
        # ── top bar ──────────────────────────────────────────────────────────
        top = tk.Frame(self.root, bg=BG, pady=10)
        top.pack(fill="x", padx=20)

        tk.Label(top, text="HoneyShield", font=FONT_BIG,
                 fg=ACCENT, bg=BG).pack(side="left")

        self.status_lbl = tk.Label(top, text="IDLE",
                                   font=("Courier New", 11, "bold"),
                                   fg=DIM, bg=BG)
        self.status_lbl.pack(side="right")

        # ── watch path row ────────────────────────────────────────────────────
        path_row = tk.Frame(self.root, bg=BG2, pady=8, padx=12)
        path_row.pack(fill="x", padx=20, pady=(0, 8))

        tk.Label(path_row, text="Watch folder:", font=FONT_SM,
                 fg=TEXT_DIM, bg=BG2).pack(side="left")

        tk.Entry(path_row, textvariable=self.watch_dir,
                 bg=BG3, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", font=FONT_SM, width=50).pack(
            side="left", padx=(6, 6))

        self._btn(path_row, "Browse", self._browse_folder,
                  fg=TEXT_DIM).pack(side="left", padx=4)

        # ── stat cards ────────────────────────────────────────────────────────
        cards = tk.Frame(self.root, bg=BG)
        cards.pack(fill="x", padx=20, pady=(0, 10))

        self.stat_decoys  = self._stat_card(cards, "Decoy Files",  "0", ACCENT)
        self.stat_events  = self._stat_card(cards, "Events",       "0", TEXT)
        self.stat_alerts  = self._stat_card(cards, "Alerts",       "0", DANGER)
        self.stat_entropy = self._stat_card(cards, "High Entropy", "0", WARN)
        self._event_count  = 0
        self._alert_count  = 0
        self._entropy_count = 0

        # ── log area ──────────────────────────────────────────────────────────
        log_frame = tk.Frame(self.root, bg=BG3, bd=0)
        log_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        tk.Label(log_frame, text=" EVENT LOG", font=FONT_SM,
                 fg=DIM, bg=BG3, anchor="w").pack(fill="x", padx=4, pady=(4, 0))

        self.log_box = scrolledtext.ScrolledText(
            log_frame,
            bg=BG3, fg=TEXT, font=FONT_MONO,
            state="disabled", relief="flat",
            wrap="word", bd=0,
            selectbackground=DIM,
        )
        self.log_box.pack(fill="both", expand=True, padx=4, pady=4)

        self.log_box.tag_configure("alert", foreground=DANGER)
        self.log_box.tag_configure("warn",  foreground=WARN)
        self.log_box.tag_configure("ok",    foreground=ACCENT)
        self.log_box.tag_configure("dim",   foreground=TEXT_DIM)

        # ── bottom toolbar ────────────────────────────────────────────────────
        bar = tk.Frame(self.root, bg=BG, pady=8)
        bar.pack(fill="x", padx=20)

        self.start_btn = self._btn(bar, "Start Monitoring",
                                   self._toggle_monitoring,
                                   bg="#003322", fg=ACCENT,
                                   font=("Courier New", 11, "bold"))
        self.start_btn.pack(side="left", padx=(0, 8))

        self._btn(bar, "Restore Decoys",
                  self._restore_decoys).pack(side="left", padx=4)
        self._btn(bar, "Remove Decoys",
                  self._remove_decoys).pack(side="left", padx=4)
        self._btn(bar, "Telegram Settings",
                  self._open_telegram_settings).pack(side="left", padx=4)
        self._btn(bar, "Help",
                  self._show_help).pack(side="right")

    # ══════════════════════════════════════════════════════════════════════════
    # Widget helpers
    # ══════════════════════════════════════════════════════════════════════════

    def _btn(self, parent, text, cmd, bg=BG3, fg=TEXT, font=FONT_SM):
        return tk.Button(parent, text=text, command=cmd,
                         bg=bg, fg=fg, font=font,
                         relief="flat", padx=10, pady=5,
                         activebackground=DIM,
                         cursor="hand2")

    def _stat_card(self, parent, label, value, colour):
        frame = tk.Frame(parent, bg=BG2, padx=14, pady=8)
        frame.pack(side="left", expand=True, fill="x", padx=4)
        val_lbl = tk.Label(frame, text=value,
                           font=("Courier New", 22, "bold"),
                           fg=colour, bg=BG2)
        val_lbl.pack()
        tk.Label(frame, text=label, font=FONT_SM,
                 fg=TEXT_DIM, bg=BG2).pack()
        return val_lbl

    # ══════════════════════════════════════════════════════════════════════════
    # Logging (thread-safe via after)
    # ══════════════════════════════════════════════════════════════════════════

    def _log(self, msg: str):
        self.root.after(0, self._log_sync, msg)

    def _log_sync(self, msg: str):
        ts   = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}]  {msg}\n"

        tag = "dim"
        ml  = msg.lower()
        if "alert" in ml or "decoy" in ml and "modif" in ml:
            tag = "alert"
        elif "entropy" in ml or "warn" in ml or "high" in ml:
            tag = "warn"
        elif any(k in ml for k in ("ready", "created", "restored",
                                   "start", "watching", "saved",
                                   "sent", "registered", "snapshot")):
            tag = "ok"

        self.log_box.config(state="normal")
        self.log_box.insert("end", line, tag)
        self.log_box.see("end")
        self.log_box.config(state="disabled")

        if "entropy" in ml:
            self._entropy_count += 1
            self.stat_entropy.config(text=str(self._entropy_count))
        if tag in ("ok", "dim"):
            self._event_count += 1
            self.stat_events.config(text=str(self._event_count))

    # ══════════════════════════════════════════════════════════════════════════
    # Actions
    # ══════════════════════════════════════════════════════════════════════════

    def _browse_folder(self):
        d = filedialog.askdirectory(initialdir=self.watch_dir.get())
        if d:
            self.watch_dir.set(d)

    def _toggle_monitoring(self):
        if self.running.get():
            self._stop_monitoring()
        else:
            self._start_monitoring()

    def _start_monitoring(self):
        watch = self.watch_dir.get()
        if not os.path.isdir(watch):
            messagebox.showerror("Error", f"Folder not found:\n{watch}")
            return

        self._log(f"Creating decoy files in {watch} ...")
        self.decoy_paths = create_decoys(watch, self._log)
        self.stat_decoys.config(text=str(len(self.decoy_paths)))

        # normalize paths to avoid Windows backslash mismatch
        decoy_set = {str(Path(p).resolve()) for p in self.decoy_paths}

        self.engine = ThreatEngine(
            watched_paths=[watch],
            decoy_paths=decoy_set,
            alert_callback=self._on_alert,
            log_callback=self._log,
        )
        self.engine.start()

        self.running.set(True)
        self.start_btn.config(text="Stop Monitoring",
                              bg="#330000", fg=DANGER)
        self.status_lbl.config(text="ACTIVE", fg=ACCENT)

    def _stop_monitoring(self):
        if self.engine:
            self.engine.stop()
            self.engine = None
        self.running.set(False)
        self.start_btn.config(text="Start Monitoring",
                              bg="#003322", fg=ACCENT)
        self.status_lbl.config(text="IDLE", fg=DIM)
        self._log("Monitoring stopped.")

    def _on_alert(self, reason: str, path: str):
        # update alert counter and status on main thread
        self.root.after(0, self._update_alert_ui, reason, path)

    def _update_alert_ui(self, reason: str, path: str):
        self._alert_count += 1
        self.stat_alerts.config(text=str(self._alert_count))
        self.status_lbl.config(text="THREAT", fg=DANGER)

        # show popup — reset alert state when dismissed
        show_popup_alert(
            reason, path,
            on_quarantine=lambda: self._restore_decoys(),
            on_dismiss=lambda: self._reset_alert_state(),
        )

        # telegram alert if configured
        if self.telegram_cfg.get("bot_token") and self.telegram_cfg.get("chat_id"):
            send_telegram_alert(
                bot_token = self.telegram_cfg["bot_token"],
                chat_id   = self.telegram_cfg["chat_id"],
                reason    = reason,
                path      = path,
            )
            self._log("Telegram alert sent.")

    def _reset_alert_state(self):
        """Called when user clicks Dismiss on the alert popup."""
        if self.engine:
            self.engine.reset_alert()
        self.status_lbl.config(text="ACTIVE", fg=ACCENT)
        self._log("Alert dismissed - monitoring resumed.")

    def _restore_decoys(self):
        if not self.watch_dir.get():
            return
        restore_decoys(self.watch_dir.get(), self._log)
        self.decoy_paths = list(
            get_decoy_dir(self.watch_dir.get()).glob("*"))
        self.stat_decoys.config(text=str(len(self.decoy_paths)))
        if self.engine:
            self.engine.decoy_paths = {
                str(Path(p).resolve()).lower() for p in self.decoy_paths
            }
            self.engine._snapshot_decoys()
            self.engine.reset_alert()

    def _remove_decoys(self):
        if not messagebox.askyesno("Confirm", "Remove all decoy files?"):
            return
        remove_decoys(self.watch_dir.get(), self._log)
        self.decoy_paths = []
        self.stat_decoys.config(text="0")

    # ── Telegram settings dialog ──────────────────────────────────────────────

    def _open_telegram_settings(self):
        win = tk.Toplevel(self.root)
        win.title("Telegram Alert Settings")
        win.configure(bg=BG)
        win.resizable(False, False)

        fields = [
            ("Bot Token", "bot_token", "123456789:ABCDefgh..."),
            ("Chat ID",   "chat_id",   "123456789"),
        ]
        entries = {}
        for i, (label, key, placeholder) in enumerate(fields):
            tk.Label(win, text=label, font=FONT_SM,
                     fg=TEXT, bg=BG).grid(row=i, column=0,
                     sticky="e", padx=12, pady=8)
            var = tk.StringVar(value=self.telegram_cfg.get(key, placeholder))
            tk.Entry(win, textvariable=var,
                     bg=BG3, fg=TEXT, insertbackground=ACCENT,
                     relief="flat", font=FONT_MONO, width=40).grid(
                row=i, column=1, padx=12, pady=8)
            entries[key] = var

        def _save():
            self.telegram_cfg = {k: v.get() for k, v in entries.items()}
            self._log("Telegram settings saved.")
            win.destroy()

        tk.Button(win, text="Save", command=_save,
                  bg=BG3, fg=ACCENT, font=FONT_SM,
                  relief="flat", padx=12, pady=6).grid(
            row=len(fields), column=0, columnspan=2, pady=12)

    # ── Help dialog ───────────────────────────────────────────────────────────

    def _show_help(self):
        msg = (
            "HoneyShield - Ransomware Early-Warning System\n\n"
            "How it works:\n"
            "  1. Creates hidden decoy files with fake sensitive data.\n"
            "  2. Monitors your chosen folder in real time.\n"
            "  3. If files change rapidly OR a decoy is modified,\n"
            "     you get an instant pop-up alert.\n\n"
            "Thresholds:\n"
            "  Burst  : 15+ file events in 10 seconds\n"
            "  Entropy: >7.2 bits/byte (encrypted data)\n"
            "  Decoy  : any change to a honeypot file\n\n"
            "Buttons:\n"
            "  Restore Decoys    - re-create decoy files after tampering\n"
            "  Remove Decoys     - clean up all honeypot files\n"
            "  Telegram Settings - get alerts via Telegram bot\n"
        )
        messagebox.showinfo("Help", msg)


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    app  = HoneyShieldApp(root)
    root.protocol("WM_DELETE_WINDOW",
                  lambda: (app._stop_monitoring(), root.destroy()))
    root.mainloop()


if __name__ == "__main__":
    main()
