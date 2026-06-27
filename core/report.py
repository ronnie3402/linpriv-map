import os
import json
import re
import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# ─────────────────────────────────────────────
# Scan Directory
# ─────────────────────────────────────────────

def create_scan_directory():
    """
    scans/ folder automatically banata hai agar exist nahi karta.
    """
    scans_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scans")
    if not os.path.exists(scans_dir):
        os.makedirs(scans_dir)
    return scans_dir


# ─────────────────────────────────────────────
# ANSI Color Stripper
# ─────────────────────────────────────────────

def strip_ansi(text: str) -> str:
    """Terminal color codes hata ke plain text return karta hai."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub("", text)


# ─────────────────────────────────────────────
# Plain Text Report
# ─────────────────────────────────────────────

def generate_plain_report(captured_output: str) -> str:
    """
    Captured terminal output se plain text report banata hai.
    ANSI codes remove karta hai.
    """
    return strip_ansi(captured_output)


def save_text_report(captured_output: str, filename: str):
    """
    Plain text report scans/ folder mein save karta hai.
    - Agar extension nahi hai to .txt automatically add hogi.
    - Same naam ki file hogi to overwrite ho jayegi.
    """
    scans_dir = create_scan_directory()

    # Extension check
    if not filename.endswith(".txt"):
        filename = filename + ".txt"

    filepath = os.path.join(scans_dir, filename)
    plain_text = generate_plain_report(captured_output)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(plain_text)

    print(f"\n  {Fore.GREEN + Style.BRIGHT}[+] Text report saved :{Style.RESET_ALL} {filepath}")


# ─────────────────────────────────────────────
# JSON Report
# ─────────────────────────────────────────────

def save_json_report(findings, filename=None):
    """
    Findings ko JSON format mein save karta hai.
    - Agar filename diya hai to wo use hoga.
    - Agar filename nahi diya to timestamp use hoga.
    """
    scans_dir = create_scan_directory()

    # Filename handling
    if filename:
        # Agar .json extension nahi hai to add karo
        if not filename.endswith(".json"):
            filename = filename + ".json"
    else:
        # Fallback to timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{timestamp}.json"

    filepath = os.path.join(scans_dir, filename)

    report = {
        "tool"      : "linpriv-map",
        "version"   : "1.0",
        "timestamp" : datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "findings"  : findings
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print(f"\n  {Fore.GREEN + Style.BRIGHT}[+] JSON report saved :{Style.RESET_ALL} {filepath}")