import subprocess
import os
import json

# ─────────────────────────────────────────────
# Command Runner
# ─────────────────────────────────────────────

def run_command(cmd: str) -> str:
    """
    Shell command run karta hai aur output string mein return karta hai.
    Koi bhi error pe empty string return karta hai.
    """
    try:
        result = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.DEVNULL,
            timeout=60
        )
        return result.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


# ─────────────────────────────────────────────
# File Helpers
# ─────────────────────────────────────────────

def read_file(path: str) -> str:
    """File ka content string mein return karta hai. Error pe empty string."""
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def file_exists(path: str) -> bool:
    """File ya directory exist karti hai ya nahi."""
    return os.path.exists(path)

def is_readable(path: str) -> bool:
    """File current user ke liye readable hai ya nahi."""
    return os.access(path, os.R_OK)

def is_writable(path: str) -> bool:
    """File current user ke liye writable hai ya nahi."""
    return os.access(path, os.W_OK)


# ─────────────────────────────────────────────
# GTFOBins Loader
# ─────────────────────────────────────────────

_gtfobins_cache = None

def load_gtfobins() -> dict:
    """
    Local gtfobins.json load karta hai.
    Pehli baar disk se padhta hai, baad mein cache use karta hai.
    """
    global _gtfobins_cache
    if _gtfobins_cache is not None:
        return _gtfobins_cache

    # Is file ka location: core/utils.py → upar jao → data/gtfobins.json
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    json_path = os.path.join(base_dir, "data", "gtfobins.json")

    try:
        with open(json_path, "r") as f:
            _gtfobins_cache = json.load(f)
    except Exception:
        _gtfobins_cache = {}

    return _gtfobins_cache


def gtfo_lookup(binary_name: str, bit_type: str):
    """
    GTFOBins JSON mein binary dhundta hai.
    bit_type: 'suid' ya 'guid'
    Returns: dict ya None
    """
    db = load_gtfobins()
    binary = os.path.basename(binary_name).lower()
    entry = db.get(binary)
    if entry is None:
        return None
    return entry.get(bit_type)


# ─────────────────────────────────────────────
# Output File Saver
# ─────────────────────────────────────────────

def save_output(filepath: str, content: str):
    """ANSI color codes strip karke plain text file mein save karta hai."""
    import re
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean = ansi_escape.sub("", content)
    try:
        with open(filepath, "w") as f:
            f.write(clean)
        print(f"\n[+] Output saved to: {filepath}")
    except Exception as e:
        print(f"\n[!] Could not save output: {e}")