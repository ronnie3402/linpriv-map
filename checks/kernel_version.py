from core import vectors
from core.utils import run_command
from core.printer import (
    print_section, print_info, print_not_found
)

VECTOR_NAME = vectors.KERNEL_VERSION


def run() -> list:
    print_section(VECTOR_NAME)

    kernel_version = run_command("uname -r")
    kernel_full    = run_command("uname -a")

    if not kernel_version:
        print_not_found("Kernel Version", {
            "Checked": "uname -r",
            "Result" : "Could not determine kernel version"
        })
        return [{"vector": vectors.KERNEL_VERSION, "severity": "CLEAN", "count": 0}]

    print_info("Kernel Version Detected", {
        "Version"  : kernel_version,
        "Full Info": kernel_full,
        "Next Step": [
            "Search this version manually for known exploits:",
            f"Google: linux kernel {kernel_version} privilege escalation exploit",
            "Reference: https://www.kernel.org/cve.html",
            "Reference: https://exploit-db.com"
        ]
    })

    return [{"vector": vectors.KERNEL_VERSION, "severity": "INFO", "count": 1}]