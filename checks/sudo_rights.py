from core import vectors
from core.utils import run_command
from core.printer import (
    print_section, print_critical, print_high,
    print_info, print_not_found
)

VECTOR_NAME = vectors.SUDO_RIGHTS

# Binaries jo sudo ke saath dangerous hain
DANGEROUS_SUDO_BINS = [
    "bash", "sh", "zsh", "fish",
    "python", "python3", "perl", "ruby", "lua", "node", "php",
    "awk", "gawk", "find", "vim", "vi", "nano",
    "less", "more", "man",
    "tar", "zip", "cp", "mv", "tee", "dd",
    "cat", "wget", "curl", "gcc", "make",
    "env", "nmap", "strace", "base64",
    "mount", "chown", "chmod",
    "docker", "kubectl", "git",
    "nc", "netcat", "socat", "openssl"
]


def run() -> list:
    print_section(VECTOR_NAME)

    raw = run_command("sudo -n -l 2>/dev/null")

    if not raw:
        print_not_found("Sudo Rights", {
            "Checked": "sudo -l",
            "Result" : "No sudo rights found or sudo not available"
        })
        return [{"vector": vectors.SUDO_RIGHTS, "severity": "CLEAN", "count": 0}]

    lines = raw.splitlines()

    # NOPASSWD entries dhundo
    nopasswd_entries = [
        l.strip() for l in lines if "NOPASSWD" in l.upper()
    ]

    # Saari command entries dhundo
    all_entries = [
        l.strip() for l in lines if "(" in l and ")" in l
    ]

    # ─────────────────────────────────────────────
    # Case 1 — NOPASSWD + Dangerous Binary
    # ─────────────────────────────────────────────
    dangerous_found = []
    for entry in nopasswd_entries:
        for binary in DANGEROUS_SUDO_BINS:
            # Binary name match karo — poora word match
            if f"/{binary}" in entry or f" {binary}" in entry:
                dangerous_found.append(
                    f"{entry}  →  [{binary}]"
                )

    if dangerous_found:
        print_critical("NOPASSWD Sudo with Dangerous Binary", {
            "Entries"  : dangerous_found,
            "Risk"     : "Can run binary as root without password — direct privesc path",
            "Next Step": "Run: sudo <binary> and spawn shell via GTFOBins technique",
            "Reference": "https://gtfobins.github.io/"
        })
        return [{"vector": "Sudo NOPASSWD (Dangerous)", "severity": "CRITICAL", "count": len(dangerous_found)}]

    # ─────────────────────────────────────────────
    # Case 2 — NOPASSWD but unknown binary
    # ─────────────────────────────────────────────
    if nopasswd_entries:
        print_high("NOPASSWD Sudo Entry Found", {
            "Entries"  : nopasswd_entries,
            "Risk"     : "Can run command as root without password — verify if binary is abusable",
            "Next Step": "Look up each binary on GTFOBins",
            "Reference": "https://gtfobins.github.io/"
        })
        return [{"vector": "Sudo NOPASSWD", "severity": "HIGH", "count": len(nopasswd_entries)}]

    # ─────────────────────────────────────────────
    # Case 3 — Sudo entries but password required
    # ─────────────────────────────────────────────
    if all_entries:
        print_info("Sudo Entries Found (Password Required)", {
            "Entries"  : all_entries,
            "Risk"     : "Password required — check if any listed binary is abusable",
            "Next Step": "If password known, check each binary on GTFOBins",
            "Reference": "https://gtfobins.github.io/"
        })
        return [{"vector": "Sudo Rights (Password)", "severity": "INFO", "count": len(all_entries)}]

    # ─────────────────────────────────────────────
    # Case 4 — Sudo output mila but koi entry nahi
    # ─────────────────────────────────────────────
    print_not_found("Sudo Rights", {
        "Checked": "sudo -l",
        "Result" : "Sudo available but no command entries found"
    })
    return [{"vector": "Sudo Rights", "severity": "CLEAN", "count": 0}]