from core import vectors
from core.utils import run_command
from core.printer import (
    print_section,
    print_critical,
    print_high,
    print_info,
    print_not_found
)

VECTOR_NAME = vectors.RUNNING_PROCS

INTERESTING_PROCESSES = [
    "mysql",
    "mysqld",
    "postgres",
    "postgresql",
    "mongod",
    "redis",
    "docker",
    "containerd",
    "nginx",
    "apache2",
    "httpd",
    "tomcat",
    "java",
    "python",
    "python3",
    "node",
    "php",
    "ruby",
    "perl",
    "screen",
    "tmux",
    "ansible",
    "jenkins",
    "salt",
    "supervisord"
]


def run() -> list:
    print_section(VECTOR_NAME)

    results = []

    results += _check_root_processes()
    results += _check_interesting_processes()

    if not results:
        print_not_found("Running Processes", {
            "Checked": "ps aux",
            "Result": "No interesting running processes found"
        })

        return [{
            "vector": vectors.RUNNING_PROCS,
            "severity": "CLEAN",
            "count": 0
        }]

    return results


# ─────────────────────────────────────────────
# Root Processes
# ─────────────────────────────────────────────

def _check_root_processes() -> list:
    raw = run_command("ps aux 2>/dev/null")

    if not raw:
        return []

    root_processes = []

    for line in raw.splitlines()[1:]:
        if line.startswith("root "):
            root_processes.append(line)

    if not root_processes:
        return []

    print_info("Processes Running as Root", {
        "Processes": root_processes[:25],
        "Result": (
            f"Showing first {min(len(root_processes), 25)} "
            f"of {len(root_processes)} root processes"
        ),
        "Next Step": (
            "Review custom scripts, services and unusual binaries"
        )
    })

    return [{
        "vector": "Root Processes",
        "severity": "INFO",
        "count": len(root_processes)
    }]


# ─────────────────────────────────────────────
# Interesting Processes
# ─────────────────────────────────────────────

def _check_interesting_processes() -> list:
    raw = run_command("ps aux 2>/dev/null")

    if not raw:
        return []

    found = set()

    for line in raw.splitlines():
        lower_line = line.lower()

        for proc in INTERESTING_PROCESSES:
            if proc.lower() in lower_line:
                found.add(line.strip())

    if not found:
        return []

    severity = "HIGH"

    if any(
        x in " ".join(found).lower()
        for x in ["docker", "containerd", "jenkins"]
    ):
        severity = "CRITICAL"

    printer = print_critical if severity == "CRITICAL" else print_high

    printer("Interesting Processes Found", {
        "Processes": sorted(found),
        "Risk": (
            "Custom services, containers or automation platforms "
            "may provide privilege escalation opportunities"
        ),
        "Next Step": [
            "Inspect process command lines",
            "Check service configuration files",
            "Look for credentials, writable scripts or misconfigurations"
        ],
        "Reference":
            "https://book.hacktricks.xyz/linux-hardening/privilege-escalation"
    })

    return [{
        "vector": "Interesting Processes",
        "severity": severity,
        "count": len(found)
    }]