"""
decoys.py — Creates and manages honeypot decoy files with realistic fake content.
"""

import os
import random
import string
import shutil
from pathlib import Path
from datetime import datetime, timedelta

# ── where decoys live ────────────────────────────────────────────────────────
DECOY_DIR_NAME = ".honeypot_decoys"

# ── fake data helpers ────────────────────────────────────────────────────────

def _rand_name(first_names, last_names):
    return f"{random.choice(first_names)} {random.choice(last_names)}"

def _rand_date(start_year=2022, end_year=2024):
    start = datetime(start_year, 1, 1)
    end   = datetime(end_year, 12, 31)
    delta = end - start
    return (start + timedelta(days=random.randint(0, delta.days))).strftime("%Y-%m-%d")

def _rand_amount():
    return f"${random.randint(100, 9999):,}.{random.randint(0,99):02d}"

def _rand_card():
    prefix = random.choice(["4", "5", "37", "6011"])
    digits = prefix + "".join(random.choices(string.digits, k=16 - len(prefix)))
    return " ".join(digits[i:i+4] for i in range(0, 16, 4))

def _rand_password():
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(random.choices(chars, k=random.randint(10, 18)))

# ── decoy content generators ─────────────────────────────────────────────────

FIRST_NAMES = ["James","Sarah","Michael","Emily","David","Jessica","Robert","Jennifer"]
LAST_NAMES  = ["Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis"]
BANKS       = ["Chase","Bank of America","Wells Fargo","Citibank","US Bank"]
MERCHANTS   = ["Amazon","Walmart","Target","Best Buy","Costco","Apple Store","Uber"]

def _make_bank_statement() -> str:
    name  = _rand_name(FIRST_NAMES, LAST_NAMES)
    bank  = random.choice(BANKS)
    acct  = "****" + "".join(random.choices(string.digits, k=4))
    lines = [
        f"{bank} — Monthly Statement",
        f"Account Holder : {name}",
        f"Account Number : {acct}",
        f"Statement Date : {_rand_date()}",
        "",
        f"{'Date':<14}{'Description':<30}{'Amount':>12}{'Balance':>12}",
        "-" * 70,
    ]
    balance = random.randint(2000, 15000)
    for _ in range(random.randint(8, 18)):
        amt     = random.choice([-1, 1]) * random.randint(5, 800)
        balance += amt
        lines.append(
            f"{_rand_date():<14}{random.choice(MERCHANTS):<30}"
            f"{_rand_amount():>12}${balance:>10,.2f}"
        )
    lines += ["", f"Closing Balance: ${balance:,.2f}"]
    return "\n".join(lines)


def _make_password_list() -> str:
    lines = ["# Personal Passwords — DO NOT SHARE", "# Last updated: " + _rand_date(), ""]
    sites = [
        "gmail.com", "facebook.com", "amazon.com", "netflix.com",
        "paypal.com", "linkedin.com", "dropbox.com", "github.com",
        "apple.com", "microsoft.com", "twitter.com", "instagram.com",
    ]
    for site in random.sample(sites, k=random.randint(6, 10)):
        user = random.choice(FIRST_NAMES).lower() + str(random.randint(10, 99))
        pw   = _rand_password()
        lines.append(f"{site:<25} user: {user:<20} pass: {pw}")
    return "\n".join(lines)


def _make_tax_return() -> str:
    name = _rand_name(FIRST_NAMES, LAST_NAMES)
    year = random.randint(2021, 2023)
    ssn  = f"***-**-{random.randint(1000,9999)}"
    income = random.randint(45000, 120000)
    lines = [
        f"U.S. Individual Income Tax Return — {year}",
        f"Name    : {name}",
        f"SSN     : {ssn}",
        f"Address : {random.randint(100,9999)} Main St, Anytown, CA {random.randint(90001,96999)}",
        "",
        f"Wages & Salaries    : ${income:>10,}",
        f"Interest Income     : ${random.randint(50, 800):>10,}",
        f"Total Income        : ${income + random.randint(50, 800):>10,}",
        f"Standard Deduction  : ${12950:>10,}",
        f"Taxable Income      : ${max(0, income - 12950):>10,}",
        f"Tax Owed            : ${int((income - 12950) * 0.22):>10,}",
        f"Refund / Amount Due : ${random.randint(0, 3000):>10,}",
    ]
    return "\n".join(lines)


def _make_credit_cards() -> str:
    lines = ["Credit Card Information — Personal Vault", ""]
    card_types = ["Visa", "Mastercard", "Amex", "Discover"]
    for _ in range(random.randint(2, 4)):
        ctype = random.choice(card_types)
        exp   = f"{random.randint(1,12):02d}/{random.randint(25,30)}"
        cvv   = "".join(random.choices(string.digits, k=3))
        lines += [
            f"Type    : {ctype}",
            f"Number  : {_rand_card()}",
            f"Expiry  : {exp}",
            f"CVV     : {cvv}",
            "",
        ]
    return "\n".join(lines)


def _make_medical_records() -> str:
    name   = _rand_name(FIRST_NAMES, LAST_NAMES)
    dob    = _rand_date(1960, 1995)
    conds  = random.sample(
        ["Hypertension","Type 2 Diabetes","Asthma","Migraine","High Cholesterol"], k=2)
    meds   = random.sample(
        ["Lisinopril 10mg","Metformin 500mg","Albuterol","Ibuprofen 400mg"], k=2)
    return "\n".join([
        "CONFIDENTIAL MEDICAL RECORD",
        f"Patient Name : {name}",
        f"Date of Birth: {dob}",
        f"Insurance ID : {random.randint(100000000, 999999999)}",
        "",
        "Diagnoses:",
        *[f"  - {c}" for c in conds],
        "",
        "Current Medications:",
        *[f"  - {m}" for m in meds],
        "",
        f"Last Visit   : {_rand_date()}",
    ])


# registry: (filename, generator_fn)
DECOY_TEMPLATES = [
    ("bank_statement_2024.txt",     _make_bank_statement),
    ("passwords_backup.txt",        _make_password_list),
    ("tax_return_2023.txt",         _make_tax_return),
    ("credit_cards_vault.txt",      _make_credit_cards),
    ("medical_records_private.txt", _make_medical_records),
]

# ── public API ────────────────────────────────────────────────────────────────

def get_decoy_dir(base_dir: str) -> Path:
    return Path(base_dir) / DECOY_DIR_NAME


def create_decoys(base_dir: str, log_callback=print) -> list[Path]:
    """Generate all decoy files; return list of their paths."""
    decoy_dir = get_decoy_dir(base_dir)
    decoy_dir.mkdir(parents=True, exist_ok=True)

    # hide folder on Windows
    try:
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(str(decoy_dir), 2)  # FILE_ATTRIBUTE_HIDDEN
    except Exception:
        pass

    created = []
    for filename, generator in DECOY_TEMPLATES:
        path = decoy_dir / filename
        content = generator()
        path.write_text(content, encoding="utf-8")
        created.append(path)
        log_callback(f"  🍯  Created decoy: {filename}")

    return created


def restore_decoys(base_dir: str, log_callback=print) -> None:
    """Re-create all decoy files (after a tampering event)."""
    log_callback("🔄  Restoring decoy files…")
    create_decoys(base_dir, log_callback)
    log_callback("✅  Decoys restored.")


def remove_decoys(base_dir: str, log_callback=print) -> None:
    """Delete the decoy directory entirely."""
    decoy_dir = get_decoy_dir(base_dir)
    if decoy_dir.exists():
        shutil.rmtree(decoy_dir)
        log_callback("🗑   Decoy files removed.")
