from core import vectors
import os
from core.utils import run_command, gtfo_lookup
from core.printer import (
    print_section, print_critical, print_high,
    print_info, print_not_found
)

VECTOR_NAME = vectors.SUID_GUID

EXPECTED_PATHS = {
    # Core Auth & User Management
    "pkexec"  : "/usr/bin/pkexec",
    "su"      : "/usr/bin/su",
    "sudo"    : "/usr/bin/sudo",
    "passwd"  : "/usr/bin/passwd",
    "newgrp"  : "/usr/bin/newgrp",
    "gpasswd" : "/usr/bin/gpasswd",
    "chsh"    : "/usr/bin/chsh",
    "chfn"    : "/usr/bin/chfn",
    "chage"   : "/usr/bin/chage",
    "expiry"  : "/usr/bin/expiry",

    # File System & Mounting
    "mount"       : "/usr/bin/mount",
    "umount"      : "/usr/bin/umount",
    "fusermount"  : "/usr/bin/fusermount",
    "fusermount3" : "/usr/bin/fusermount3",

    # Network, SSH & Cron
    "ping"        : "/usr/bin/ping",
    "ping6"       : "/usr/bin/ping6",
    "ssh-keysign" : "/usr/lib/openssh/ssh-keysign",
    "crontab"     : "/usr/bin/crontab",

    # Background Daemons & Helpers
    "unix_chkpwd"               : "/usr/sbin/unix_chkpwd",
    "polkit-agent-helper-1"     : "/usr/lib/polkit-1/polkit-agent-helper-1",
    "dbus-daemon-launch-helper" : "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "snap-confine"              : "/usr/lib/snapd/snap-confine",
    "vmware-user-suid-wrapper"  : "/usr/bin/vmware-user-suid-wrapper"
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
            "Risk"     : "Executes with the privileges of the file's owner (typically root) — allows potential root access",
            "Next Step": "Check each binary below for exploit command",
            "Reference": "https://gtfobins.github.io/"
        })
        # Har exploitable binary ka alag hint
        for binary in exploitable:
            hint = hints[binary]
            try:
                import stat
                st = os.stat(binary)
                mode = oct(st.st_mode)[-4:]
                owner = "root" if st.st_uid == 0 else str(st.st_uid)
            except Exception:
                mode = "unknown"
                owner = "unknown"

            print_critical(f"Exploit → {os.path.basename(binary)}", {
                "Binary"   : binary,
                "Owner"    : owner,
                "Mode"     : mode,
                "Risk"     : hint.get("risk", ""),
                "Command"  : hint.get("command", "See reference"),
                "Reference": hint.get("reference", "https://gtfobins.github.io/")
            })

    if normal:
        display = normal[:10]
        remaining = len(normal) - 10
        
        fields = {"Binaries": display}
        if remaining > 0:
            fields["Note"] = f"...and {remaining} more (use --verbose to see all)"
        
        print_info("SUID Binaries (Not Exploitable / Unverified)", fields)

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
            "Risk"     : "Executes with the privileges of the file's group owner — may allow group-level escalation or access to sensitive group resources",
            "Next Step": "Check each binary below for exploit command",
            "Reference": "https://gtfobins.github.io/"
        })
        for binary in exploitable:
            hint = hints[binary]
            try:
                import stat
                st = os.stat(binary)
                mode = oct(st.st_mode)[-4:]
                owner = "root" if st.st_uid == 0 else str(st.st_uid)
            except Exception:
                mode = "unknown"
                owner = "unknown"

            print_critical(f"Exploit → {os.path.basename(binary)}", {
                "Binary"   : binary,
                "Owner"    : owner,
                "Mode"     : mode,
                "Risk"     : hint.get("risk", ""),
                "Command"  : hint.get("command", "See reference"),
                "Reference": hint.get("reference", "https://gtfobins.github.io/")
            })

    if normal:
        display = normal[:10]
        remaining = len(normal) - 10
        
        fields = {"Binaries": display}
        if remaining > 0:
            fields["Note"] = f"...and {remaining} more (use --verbose to see all)"
        
        print_info("GUID Binaries (Not Exploitable / Unverified)", fields)

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