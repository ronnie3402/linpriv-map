import os
from core.utils import file_exists, is_readable, is_writable, run_command
from core import vectors
from core.printer import (
    print_section, print_critical, print_high,
    print_info, print_not_found
)

VECTOR_NAME = vectors.WEAK_FILE_PERMS

# Files jinki permissions check karni hain
CRITICAL_FILES = {
    "/etc/passwd"          : "rw",
    "/etc/shadow"          : "rw",
    "/etc/sudoers"         : "rw",
    "/etc/ssh/sshd_config" : "rw",
    "/root/.ssh/authorized_keys" : "rw",
}


def run() -> list:
    print_section(VECTOR_NAME)
    results = []

    results += _check_critical_files()
    results += _check_world_readable()
    results += _check_ssh_dir_perms()

    if not results:
        print_not_found("Weak File Permissions", {
            "Checked": "Critical system files and SSH directories",
            "Result" : "No weak file permissions found"
        })
        return [{"vector": vectors.WEAK_FILE_PERMS, "severity": "CLEAN", "count": 0}]

    return results


# ─────────────────────────────────────────────
# Critical Files
# ─────────────────────────────────────────────

def _check_critical_files() -> list:
    writable_critical = []
    readable_critical = []

    for filepath, check in CRITICAL_FILES.items():
        if not file_exists(filepath):
            continue
        if "w" in check and is_writable(filepath):
            writable_critical.append(filepath)
        elif "r" in check and is_readable(filepath):
            # Only flag readable if it's supposed to be restricted
            if filepath in ["/etc/shadow", "/etc/sudoers"]:
                readable_critical.append(filepath)

    if writable_critical:
        print_critical("Writable Critical System Files Found", {
            "Files"    : writable_critical,
            "Risk"     : "Direct modification possible — can add root user or backdoor",
            "Next Step": [
                "/etc/passwd writable → add new root user:",
                "echo 'hacker::0:0:root:/root:/bin/bash' >> /etc/passwd",
                "/etc/sudoers writable → add NOPASSWD entry:",
                "echo '$USER ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"
            ],
            "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files"
        })

    if readable_critical:
        print_high("Readable Restricted Files Found", {
            "Files"    : readable_critical,
            "Risk"     : "Sensitive file readable — credentials or hashes may be exposed",
            "Next Step": "cat /etc/shadow → copy hashes → hashcat offline crack",
            "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation"
        })

    if not writable_critical and not readable_critical:
        return []

    count    = len(writable_critical) + len(readable_critical)
    severity = "CRITICAL" if writable_critical else "HIGH"
    return [{"vector": "Critical File Perms", "severity": severity, "count": count}]


# ─────────────────────────────────────────────
# World Readable Sensitive Files
# ─────────────────────────────────────────────

def _check_world_readable() -> list:
    raw = run_command(
        "find /etc /root -type f -perm -o=r 2>/dev/null"
    )
    files = [f.strip() for f in raw.splitlines() if f.strip()]

    # Filter out expected readable files
    SKIP = ["/etc/passwd", "/etc/group", "/etc/hostname",
            "/etc/hosts", "/etc/resolv.conf", "/etc/os-release"]
    files = [f for f in files if f not in SKIP]

    if not files:
        return []

    print_high("World-Readable Files in Sensitive Directories", {
        "Files"    : files[:15],
        "Risk"     : "Sensitive files readable by any user",
        "Next Step": "Review each file for credentials, keys, or sensitive config",
        "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation"
    })
    return [{"vector": "World Readable Files", "severity": "HIGH", "count": len(files)}]


# ─────────────────────────────────────────────
# SSH Directory Permissions
# ─────────────────────────────────────────────

def _check_ssh_dir_perms() -> list:
    ssh_dirs = ["/root/.ssh", os.path.expanduser("~/.ssh")]
    issues   = []

    for ssh_dir in ssh_dirs:
        if not file_exists(ssh_dir):
            continue
        try:
            mode = oct(os.stat(ssh_dir).st_mode)[-3:]
            if mode != "700":
                issues.append(f"{ssh_dir} → permissions: {mode} (should be 700)")
        except Exception:
            pass

    if not issues:
        return []

    print_high("Insecure SSH Directory Permissions", {
        "Issues"   : issues,
        "Risk"     : "Other users may be able to read SSH keys",
        "Next Step": "Fix with: chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_rsa",
        "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ssh-keys"
    })
    return [{"vector": "SSH Dir Perms", "severity": "HIGH", "count": len(issues)}]