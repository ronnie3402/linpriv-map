from core.utils import run_command
from core import vectors
from core.printer import (
    print_section, print_high,
    print_info, print_not_found
)

VECTOR_NAME = vectors.VULN_SOFTWARE

SOFTWARE_LIST = [
    "sudo", "pkexec", "screen", "exim4",
    "php", "mysql", "mariadb", "openssl",
    "apache2", "nginx", "docker", "python3",
    "gcc", "perl", "ruby", "node"
]


def run() -> list:
    print_section(VECTOR_NAME)

    installed = {}

    for software in SOFTWARE_LIST:
        version = run_command(f"{software} --version 2>/dev/null | head -1")
        if not version:
            version = run_command(f"{software} -version 2>/dev/null | head -1")
        if version:
            installed[software] = version

    if not installed:
        print_not_found("Vulnerable Software", {
            "Checked": ", ".join(SOFTWARE_LIST),
            "Result" : "None of the checked software appears to be installed"
        })
        return [{"vector": vectors.VULN_SOFTWARE, "severity": "CLEAN", "count": 0}]

    print_info("Installed Software Versions", {
        "Note"    : "Manually verify each version against known CVEs",
        "Software": [f"{s}: {v}" for s, v in installed.items()]
    })

    print_info("Search These Versions for Known CVEs", {
        "Next Step": [
            "Google: <software> <version> privilege escalation exploit",
            "Check: https://exploit-db.com",
            "Check: https://www.cvedetails.com"
        ],
        "Reference": "https://exploit-db.com"
    })

    return [{"vector": vectors.VULN_SOFTWARE, "severity": "INFO", "count": len(installed)}]