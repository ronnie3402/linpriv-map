from core import vectors
from core.utils import run_command
from core.printer import (
    print_section, print_critical, print_info, print_not_found
)

VECTOR_NAME = vectors.CAPABILITIES 

# Dangerous capabilities aur unka risk
DANGEROUS_CAPS = {
    "cap_setuid"        : "Can change UID to root — direct privilege escalation",
    "cap_setgid"        : "Can change GID — group privilege escalation",
    "cap_sys_admin"     : "Nearly equivalent to root — extremely dangerous",
    "cap_sys_ptrace"    : "Can attach to and manipulate root processes",
    "cap_net_raw"       : "Can create raw sockets — network sniffing/spoofing",
    "cap_dac_override"  : "Can bypass file read/write/execute permission checks",
    "cap_dac_read_search": "Can read any file — including /etc/shadow",
    "cap_chown"         : "Can change ownership of any file",
    "cap_fowner"        : "Can bypass permission checks for file owner",
    "cap_sys_module"    : "Can load/unload kernel modules — full kernel access",
}


def run() -> list:
    print_section(VECTOR_NAME)

    raw = run_command("getcap -r / 2>/dev/null")

    if not raw:
        print_not_found("Linux Capabilities", {
            "Checked": "getcap -r /",
            "Result" : "No capabilities set or getcap not available"
        })
        return [{"vector": vectors.CAPABILITIES, "severity": "CLEAN", "count": 0}]

    lines = raw.splitlines()
    dangerous_found = []
    info_found      = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Line format: /path/to/binary = cap_setuid+eip
        parts  = line.split(" = ")
        binary = parts[0].strip() if len(parts) > 0 else line
        caps   = parts[1].lower() if len(parts) > 1 else ""

        matched = [c for c in DANGEROUS_CAPS if c in caps]

        if matched:
            dangerous_found.append({
                "binary" : binary,
                "caps"   : caps,
                "reasons": matched
            })
        else:
            info_found.append(line)

    # Dangerous capabilities print karo
    if dangerous_found:
        for item in dangerous_found:
            reasons = [
                f"{c} — {DANGEROUS_CAPS[c]}"
                for c in item["reasons"]
            ]
            binary_name = item["binary"].split("/")[-1]
            print_critical(f"Dangerous Capability Found: {binary_name}", {
                "Binary"    : item["binary"],
                "Capability": item["caps"],
                "Risk"      : reasons,
                "Next Step" : "Check GTFOBins for this binary with capabilities set",
                "Reference" : f"https://gtfobins.github.io/gtfobins/{binary_name}/#capabilities"
            })

    # Normal capabilities info mein dikhao
    if info_found:
        print_info("Other Capabilities Found (Review Manually)", {
            "Binaries" : info_found,
            "Next Step": "Verify each on GTFOBins — may still be abusable",
            "Reference": "https://gtfobins.github.io/"
        })

    count    = len(dangerous_found)
    severity = "CRITICAL" if count > 0 else "CLEAN"
    return [{"vector": "Capabilities", "severity": severity, "count": count}]