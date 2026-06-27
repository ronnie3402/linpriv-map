from core import vectors
import os
from core.utils import run_command, gtfo_lookup
from core.printer import (
    print_section, print_critical, print_high,
    print_info, print_not_found
)

VECTOR_NAME = vectors.SUID_GUID

EXPECTED_PATHS = {
    "pkexec" : "/usr/bin/pkexec",
    "mount"  : "/usr/bin/mount",
    "umount" : "/usr/bin/umount",
    "su"     : "/usr/bin/su",
    "sudo"   : "/usr/bin/sudo",
    "passwd" : "/usr/bin/passwd",
    "newgrp" : "/usr/bin/newgrp",
    "gpasswd": "/usr/bin/gpasswd",
    "chsh"   : "/usr/bin/chsh",
    "chfn"   : "/usr/bin/chfn",
}


def run() -> list:
    """
    SUID, GUID aur Sticky Bit misconfigurations check karta hai.
    Returns: list of result dicts for summary table.
    """
    print_section(VECTOR_NAME)
    results = []

    results += _check_suid()
    results += _check_guid()
    results += _check_sticky_bit()

    return results


# ─────────────────────────────────────────────
# SUID Check
# ─────────────────────────────────────────────

def _check_suid() -> list:
    raw = run_command("find / -perm -4000 -type f 2>/dev/null")
    binaries = [b.strip() for b in raw.splitlines() if b.strip()]

    if not binaries:
        print_not_found("SUID Binaries", {
            "Checked": "find / -perm -4000 -type f",
            "Result" : "No SUID binaries found"
        })
        return [{"vector": "SUID Binaries", "severity": "CLEAN", "count": 0}]

    exploitable = []
    normal      = []
    hints       = {}

    for binary in binaries:
        binary_name = os.path.basename(binary).lower()

        # Expected path check — agar expected path par hai toh normal
        if binary_name in EXPECTED_PATHS:
            if binary == EXPECTED_PATHS[binary_name]:
                normal.append(f"{binary}  (expected SUID — not exploitable)")
                continue
            else:
                # Unexpected path par mila — CRITICAL
                exploitable.append(binary)
                hints[binary] = {
                    "exploitable": True,
                    "risk": f"'{binary_name}' found at unexpected path — possible backdoor or hijack",
                    "command": f"Investigate: ls -la {binary} && file {binary}",
                    "reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation"
                }
                continue

        # Normal GTFOBins lookup
        info = gtfo_lookup(binary, "suid")
        if info is None:
            normal.append(f"{binary}  (not in GTFOBins — verify manually)")
        elif info.get("exploitable"):
            exploitable.append(binary)
            hints[binary] = info
        else:
            normal.append(f"{binary}  (expected SUID — not exploitable)")

    if exploitable:
        print_critical("SUID Binaries Found", {
            "Binaries" : exploitable,
            "Risk"     : "These binaries run as root regardless of calling user",
            "Next Step": "Check each binary below for exploit command",
            "Reference": "https://gtfobins.github.io/"
        })
        # Har exploitable binary ka alag hint
        for binary in exploitable:
            hint = hints[binary]
            print_critical(f"Exploit → {os.path.basename(binary)}", {
                "Binary"   : binary,
                "Risk"     : hint.get("risk", ""),
                "Command"  : hint.get("command", "See reference"),
                "Reference": hint.get("reference", "https://gtfobins.github.io/")
            })

    if normal:
        print_info("SUID Binaries (Not Exploitable / Unverified)", {
            "Binaries": normal
        })

    if not exploitable and not normal:
        print_not_found("SUID Binaries", {
            "Checked": "find / -perm -4000 -type f",
            "Result" : "No SUID binaries found"
        })

    count    = len(exploitable)
    severity = "CRITICAL" if count > 0 else "CLEAN"
    return [{"vector": "SUID Binaries", "severity": severity, "count": count}]


# ─────────────────────────────────────────────
# GUID Check
# ─────────────────────────────────────────────

def _check_guid() -> list:
    raw = run_command("find / -perm -2000 -type f 2>/dev/null")
    binaries = [b.strip() for b in raw.splitlines() if b.strip()]

    if not binaries:
        print_not_found("GUID Binaries", {
            "Checked": "find / -perm -2000 -type f",
            "Result" : "No GUID binaries found"
        })
        return [{"vector": "GUID Binaries", "severity": "CLEAN", "count": 0}]

    exploitable = []
    normal      = []
    hints       = {}

    for binary in binaries:
        binary_name = os.path.basename(binary).lower()

        # Expected path check — agar expected path par hai toh normal
        if binary_name in EXPECTED_PATHS:
            if binary == EXPECTED_PATHS[binary_name]:
                normal.append(f"{binary}  (expected GUID — not exploitable)")
                continue
            else:
                # Unexpected path par mila — CRITICAL
                exploitable.append(binary)
                hints[binary] = {
                    "exploitable": True,
                    "risk": f"'{binary_name}' found at unexpected path — possible backdoor or hijack",
                    "command": f"Investigate: ls -la {binary} && file {binary}",
                    "reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation"
                }
                continue

        # Normal GTFOBins lookup
        info = gtfo_lookup(binary, "guid")
        if info is None:
            normal.append(f"{binary}  (not in GTFOBins — verify manually)")
        elif info.get("exploitable"):
            exploitable.append(binary)
            hints[binary] = info
        else:
            normal.append(f"{binary}  (expected GUID — not exploitable)")

    if exploitable:
        print_critical("GUID Binaries Found", {
            "Binaries" : exploitable,
            "Risk"     : "Runs with group owner privileges — can abuse group access",
            "Next Step": "Check each binary below for exploit command",
            "Reference": "https://gtfobins.github.io/"
        })
        for binary in exploitable:
            hint = hints[binary]
            print_critical(f"Exploit → {os.path.basename(binary)}", {
                "Binary"   : binary,
                "Risk"     : hint.get("risk", ""),
                "Command"  : hint.get("command", "See reference"),
                "Reference": hint.get("reference", "https://gtfobins.github.io/")
            })

    if normal:
        print_info("GUID Binaries (Not Exploitable / Unverified)", {
            "Binaries": normal
        })

    if not exploitable and not normal:
        print_not_found("GUID Binaries", {
            "Checked": "find / -perm -2000 -type f",
            "Result" : "No GUID binaries found"
        })

    count    = len(exploitable)
    severity = "CRITICAL" if count > 0 else "CLEAN"
    return [{"vector": "GUID Binaries", "severity": severity, "count": count}]


# ─────────────────────────────────────────────
# Sticky Bit Check
# ─────────────────────────────────────────────

def _check_sticky_bit() -> list:
    """
    World-writable directories WITHOUT sticky bit — dangerous.
    Sticky bit hona NORMAL hai (jaise /tmp).
    """
    raw = run_command("find / -type d -perm -0002 ! -perm -1000 2>/dev/null")
    dirs = [d.strip() for d in raw.splitlines() if d.strip()]

    if not dirs:
        print_not_found("Sticky Bit Misconfiguration", {
            "Checked": "World-writable directories without sticky bit",
            "Result" : "No misconfiguration found"
        })
        return [{"vector": "Sticky Bit", "severity": "CLEAN", "count": 0}]

    print_high("World-Writable Directories WITHOUT Sticky Bit", {
        "Directories": dirs,
        "Risk"       : "Any user can delete or replace files in these directories",
        "Next Step"  : "Check if any root process or cron job writes to these dirs",
        "Reference"  : "https://book.hacktricks.xyz/linux-hardening/privilege-escalation"
    })
    return [{"vector": "Sticky Bit", "severity": "HIGH", "count": len(dirs)}]