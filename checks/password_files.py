from glob import glob
import os
from core import vectors
from core.utils import (
    file_exists,
    is_readable,
    is_writable
)
from core.printer import (
    print_section,
    print_critical,
    print_high,
    print_not_found
)
import getpass
VECTOR_NAME = vectors.PASSWORD_FILES

SENSITIVE_FILES = [
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.bash_history",
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ed25519",
    "/root/.ssh/authorized_keys",
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_ed25519_key",
    "/home/*/.bash_history",
    "/home/*/.ssh/id_rsa",
    "/home/*/.ssh/id_ed25519",
    "/home/*/.ssh/authorized_keys"
]


def run() -> list:
    print_section(VECTOR_NAME)

    results = []

    results += _check_shadow_file()
    results += _check_sensitive_files()
    results += _check_writable_sensitive_files()

    if not results:
        print_not_found("Password Files", {
            "Checked": ", ".join(SENSITIVE_FILES),
            "Result": "No sensitive readable or writable files found"
        })
        return [{
            "vector": vectors.PASSWORD_FILES,
            "severity": "CLEAN",
            "count": 0
        }]

    return results


# ─────────────────────────────────────────────
# /etc/shadow
# ─────────────────────────────────────────────

def _check_shadow_file() -> list:
    shadow = "/etc/shadow"

    if not file_exists(shadow):
        return []

    if is_readable(shadow):
        print_critical("Readable /etc/shadow Found", {
            "File": shadow,
            "Risk": "Password hashes can be extracted for offline cracking",
            "Next Step": "Review file permissions immediately",
            "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation"
        })

        return [{
            "vector": "Readable /etc/shadow",
            "severity": "CRITICAL",
            "count": 1
        }]

    return []


# ─────────────────────────────────────────────
# Readable Sensitive Files
# ─────────────────────────────────────────────

def _check_sensitive_files() -> list:
    expanded_files = []
    current_uid = os.getuid()
    for pattern in SENSITIVE_FILES:
        if "*" in pattern:
            expanded_files.extend(glob(pattern))
        else:
            expanded_files.append(pattern)

    readable = []
    for f in set(expanded_files):
        if not file_exists(f) or not is_readable(f):
            continue
        # Agar file ka owner current user hai toh skip karo
        try:
            file_uid = os.stat(f).st_uid
            if file_uid == current_uid:
                continue
        except Exception:
            pass
        readable.append(f)

    # /etc/shadow already handled separately
    readable = [f for f in readable if f != "/etc/shadow"]

    if not readable:
        return []

    print_high("Readable Sensitive Files Found", {
        "Files": sorted(readable),
        "Risk": "Sensitive information may be disclosed",
        "Next Step": "Review file contents and permissions manually",
        "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation"
    })

    return [{
        "vector": "Readable Sensitive Files",
        "severity": "HIGH",
        "count": len(readable)
    }]


# ─────────────────────────────────────────────
# Writable Sensitive Files
# ─────────────────────────────────────────────

def _check_writable_sensitive_files() -> list:
    high_risk_files = [
        
        "/etc/shadow",
        "/etc/sudoers",

        "/root/.ssh/authorized_keys",
        "/home/*/.ssh/authorized_keys",

        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ed25519",
        "/home/*/.ssh/id_rsa",
        "/home/*/.ssh/id_ed25519",

        "/etc/ssh/ssh_host_rsa_key",
        "/etc/ssh/ssh_host_ed25519_key"
    ]
    expanded_files = []

    for pattern in high_risk_files:
        if "*" in pattern:
            expanded_files.extend(glob(pattern))
        else:
            expanded_files.append(pattern)

    writable = []

    
    current_uid = os.getuid()

    for f in set(expanded_files):
        if file_exists(f) and is_writable(f):
            try:
                file_uid = os.stat(f).st_uid
                if file_uid == current_uid:
                    continue
            except Exception:
                pass

            writable.append(f)

    if not writable:
        return []

    print_critical("Writable Sensitive Files Found", {
        "Files": sorted(writable),
        "Risk": "Modification of these files may lead to privilege escalation or persistent root access",
        "Next Step": [
            "Check file ownership and permissions",
            "Review whether these files are used for authentication or privilege management"
        ],
        "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation"
    })

    return [{
        "vector": "Writable Sensitive Files",
        "severity": "CRITICAL",
        "count": len(writable)
    }]