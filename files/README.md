# 🍯 HoneyShield — Personal Ransomware Early-Warning System

A lightweight desktop honeypot that detects ransomware-like activity on your
PC **before** your real files get encrypted.

---

## How it works

```
Desktop / Documents folder
        │
        ├── .honeypot_decoys/          ← hidden folder with fake "sensitive" files
        │       bank_statement_2024.txt
        │       passwords_backup.txt
        │       tax_return_2023.txt
        │       credit_cards_vault.txt
        │       medical_records_private.txt
        │
        └── your real files …
```

HoneyShield watches the folder in real time using **watchdog**.  
Three threat signals trigger an alert:

| Signal | Default threshold |
|--------|------------------|
| **Burst rate** | ≥ 15 file events in 10 seconds |
| **File entropy** | ≥ 7.2 bits/byte (encrypted/compressed) |
| **Decoy tamper** | *Any* change to a honeypot file |

When triggered:
- 🚨 Pop-up alert window (dark-red, always-on-top)
- 📲 Optional Telegram alert
- 🔄 One-click decoy restore

---

## Quick start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch the GUI
python main.py
```

Tkinter ships with Python on macOS and Windows.  
On Linux: `sudo apt install python3-tk`

---

## Project layout

```
honeypot/
├── main.py          # entry point
├── gui.py           # Tkinter dashboard
├── monitor.py       # watchdog + threat engine
├── decoys.py        # honeypot file generator
├── alerts.py        # popup + email alerting
└── requirements.txt
```

---

## Telegram alerts (optional)

Click **Telegram Settings** in the dashboard and fill in:

| Field | Example |
|-------|---------|
| Bot Token | `123456789:ABCDefgh...` |
| Chat ID | `123456789` |

---

## Extending the project

- **More decoy types** — add a new `(filename, generator)` tuple to  
  `DECOY_TEMPLATES` in `decoys.py`.
- **Change thresholds** — edit `BURST_THRESHOLD`, `BURST_WINDOW_SECS`,  
  `ENTROPY_THRESHOLD` at the top of `monitor.py`.
- **Watch multiple folders** — pass a list of paths to `ThreatEngine`.
- **More alert channels** — add another sender function in `alerts.py` and
  call it from `gui.py`.

---

## Educational note

This tool is designed for **awareness and early detection** only.  
It does **not** stop ransomware — disconnect from the internet immediately  
upon any alert and restore from a clean offline backup.
