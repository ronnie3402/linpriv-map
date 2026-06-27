from core import vectors
from core.utils import run_command
from core.printer import (
    print_section,
    print_critical,
    print_high,
    print_info,
    print_not_found
)
import os
current_pid = str(os.getpid())
VECTOR_NAME = vectors.RUNNING_PROCS
MAX_ROOT_DISPLAY = 25
INTERESTING_PROCESSES = [
    "mysqld", "postgres", "postgresql", "mongod",
    "redis-server", "docker", "containerd",
    "apache2", "httpd", "nginx", "tomcat",
    "java", "jenkins", "ansible",
    "salt-minion", "supervisord",
    "screen", "tmux", "kubectl",

    # additional
    "consul",
    "vault",
    "nomad",
    "etcd",
    "rabbitmq",
    "memcached",
    "elasticsearch",
    "grafana",
    "prometheus",
    "gitlab",
    "gitlab-runner",
    "teamcity",
    "rundeck"
]
GUI_SKIP = [
    "gsd-", "gjs", "gnome", "kde", "plasma",
    "blueman", "screensaver", "applet", "xorg",
    "wayland", "dbus", "pulseaudio", "pipewire",
    "gdm", "gvfs", "tracker", "evolution",
    "nautilus", "gedit", "firefox", "chromium","xdg-desktop",
    "xdg-document",
    "xdg-permission",
    "ibus",
    "at-spi",
    "xdg-portal",
    "wireplumber",
    "snap-store"
]

CRITICAL_PROCESSES = [
    "docker",
    "containerd",
    "jenkins",
    "gitlab-runner",
    "ansible",
    "salt-minion",
    "vault",
    "consul",
    "nomad",
    "teamcity",
    "rundeck"
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
        parts = line.split()

        if not parts or parts[0] != "root":
            continue
        # Kernel threads skip karo — [kworker], [migration] etc
        parts = line.split()
        if len(parts) >= 11:
            cmd = parts[10]
            if cmd.startswith("[") and cmd.endswith("]"):
                continue
        root_processes.append(line)

    if not root_processes:
        return []

    print_info("Processes Running as Root", {
        "Processes": root_processes[:MAX_ROOT_DISPLAY],
        "Result": (
            f"Showing first {min(len(root_processes), MAX_ROOT_DISPLAY)} "
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
        parts = line.split()

        if len(parts) > 1:
            pid = parts[1]
            if pid == current_pid:
                continue
        if "linpriv-map" in line.lower():
            continue
        # GUI skip
        parts = line.split()

        if len(parts) < 11:
            continue

        cmd = " ".join(parts[10:]).lower()

        if any(gui_proc in cmd for gui_proc in GUI_SKIP):
            continue
        for proc in INTERESTING_PROCESSES:
            if (
                f"/{proc}" in cmd or
                f" {proc} " in f" {cmd} " or
                cmd.startswith(proc)
            ):
                found.add(line.strip())
                break


    if not found:
        return []

    severity = "HIGH"

    for proc_line in found:
        lower_proc = proc_line.lower()

        if any(
            critical in lower_proc
            for critical in CRITICAL_PROCESSES
        ):
            severity = "CRITICAL"
            break

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