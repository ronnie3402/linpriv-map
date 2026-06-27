from core import vectors
from core.utils import run_command
from core.printer import (
    print_section,
    print_critical,
    print_high,
    print_info,
    print_not_found
)

VECTOR_NAME = vectors.CAPABILITIES

# Dangerous capabilities aur unka risk
DANGEROUS_CAPS = {
    "cap_setuid": "Can change UID to root — direct privilege escalation",
    "cap_setgid": "Can change GID — group privilege escalation",
    "cap_sys_admin": "Nearly equivalent to root — extremely dangerous",
    "cap_sys_ptrace": "Can attach to and manipulate root processes",
    "cap_dac_override": "Can bypass file read/write/execute permission checks",
    "cap_dac_read_search": "Can read any file — including /etc/shadow",
    "cap_chown": "Can change ownership of any file",
    "cap_fowner": "Can bypass permission checks for file owner",
    "cap_sys_module": "Can load/unload kernel modules — full kernel access",
}
MODERATE_CAPS = {
    "cap_net_raw": "Can create raw sockets — network sniffing/spoofing",
    "cap_net_bind_service": "Can bind to privileged ports (<1024)",
    "cap_sys_nice": "Can modify process priorities",
    "cap_wake_alarm": "Can trigger wake alarms",
    "cap_net_admin": (
        "Can modify network interfaces, firewall rules, routing tables "
        "and perform advanced network administration tasks"
    ),
}

EXPECTED_CAP_BINARIES = [
    "dumpcap",
    "fping",
    "gst-ptp-helper",
    "org_kde_powerdevil",
    "kwin_wayland",
    "ksgrd_network_helper",
    "ping",
    "ping6"
]


# GTFOBins capable binaries
EXPLOITABLE_CAP_BINARIES = {
    "nmap": {
        "command": "nmap --interactive → !sh (older versions only)",
        "recommendation": "Verify Nmap version. Older interactive mode versions may allow shell escape."
    },

    "python": {
        "command": "python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
        "recommendation": "Check whether cap_setuid or similar capabilities are present. If yes, privilege escalation may be possible."
    },

    "python3": {
        "command": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
        "recommendation": "Check whether cap_setuid or similar capabilities are present. If yes, privilege escalation may be possible."
    },

    "perl": {
        "command": "perl -e 'use POSIX (setuid); setuid(0); exec \"/bin/bash\"'",
        "recommendation": "Verify assigned capabilities and test whether UID changes are permitted."
    },

    "ruby": {
        "command": "ruby -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'",
        "recommendation": "Review capabilities carefully. Ruby with elevated capabilities may permit privilege escalation."
    },

    "vim": {
        "command": "vim -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\",\"-c\",\"reset; exec sh\")'",
        "recommendation": "Check if Vim has dangerous capabilities such as cap_setuid or cap_dac_override."
    }
}


def run() -> list:
    print_section(VECTOR_NAME)

    raw = run_command("getcap -r / 2>/dev/null")

    if not raw:
        print_not_found("Linux Capabilities", {
            "Checked": "getcap -r /",
            "Result": "No capabilities set or getcap not available"
        })
        return [{
            "vector": vectors.CAPABILITIES,
            "severity": "CLEAN",
            "count": 0
        }]

    lines = raw.splitlines()

    dangerous_found = []
    high_found = []
    info_found = []
    moderate_found = []

    for line in lines:
        line = line.strip()

        if not line:
            continue

        # Example:
        # /usr/bin/nmap cap_net_raw=eip
        # /usr/bin/python3 = cap_setuid+ep

        if " = " in line:
            parts = line.split(" = ")
        else:
            parts = line.split(None, 1)

        binary = parts[0].strip()
        caps = parts[1].lower() if len(parts) > 1 else ""

        binary_name = binary.split("/")[-1].lower()

        critical_matches = [
            cap for cap in DANGEROUS_CAPS
            if cap in caps
        ]

        moderate_matches = [
            cap for cap in MODERATE_CAPS
            if cap in caps
        ]

        # Priority:
        # CRITICAL > HIGH(GTFOBins) > MODERATE > INFO

        if critical_matches:
            dangerous_found.append({
                "binary": binary,
                "caps": caps,
                "reasons": critical_matches
            })

           
            if binary_name in EXPLOITABLE_CAP_BINARIES:
                high_found.append({
                    "binary": binary,
                    "caps": caps,
                    "name": binary_name
                })

        elif binary_name in EXPLOITABLE_CAP_BINARIES:
            high_found.append({
                "binary": binary,
                "caps": caps,
                "name": binary_name
            })

        elif moderate_matches:

            if binary_name in EXPECTED_CAP_BINARIES:
                info_found.append(
                    f"{binary} ({caps}) "
                    "[expected capability assignment]"
                )

            else:
                moderate_found.append({
                    "binary": binary,
                    "caps": caps,
                    "reasons": moderate_matches
                })

        else:
            info_found.append(line)

    # Print CRITICAL findings
    for item in dangerous_found:
        reasons = [
            f"{cap} — {DANGEROUS_CAPS[cap]}"
            for cap in item["reasons"]
        ]

        binary_name = item["binary"].split("/")[-1]

        print_critical(f"Dangerous Capability Found: {binary_name}", {
            "Binary": item["binary"],
            "Capability": item["caps"],
            "Risk": reasons,
            "Next Step": (
                "Review assigned capabilities, verify exploitability on GTFOBins, "
                "and determine whether the capability permits privilege escalation."
            ),
            "Reference": f"https://gtfobins.github.io/gtfobins/{binary_name}/#capabilities"
        })

    # Print HIGH findings
    for item in high_found:
        print_high(
            f"Potentially Abusable Capability: {item['name']}",
            {
                "Binary"       : item["binary"],
                "Caps"         : item["caps"],
                "Risk": (
                    "GTFOBins-listed binary with Linux capabilities assigned. "
                    "Manual verification recommended."
                ),
                "Command"      : EXPLOITABLE_CAP_BINARIES[item["name"]]["command"],
                "Next Step"    : EXPLOITABLE_CAP_BINARIES[item["name"]]["recommendation"],
                "Reference"    : f"https://gtfobins.github.io/gtfobins/{item['name']}/#capabilities"
            }
        )
    
    # Print MODERATE/HIGH capability findings
    for item in moderate_found:
        print_high(
            f"Potentially Dangerous Capability: {item['binary'].split('/')[-1]}",
            {
                "Binary": item["binary"],
                "Capability": item["caps"],
                "Risk": [
                    f"{cap} — {MODERATE_CAPS[cap]}"
                    for cap in item["reasons"]
                ],
                "Next Step": (
                    "Review whether this capability is expected for the binary "
                    "and determine if it can be abused in the current context."
                ),
                "Reference": "https://man7.org/linux/man-pages/man7/capabilities.7.html"
            }
        )

    # Print INFO findings
    if info_found:
        print_info("Other Capabilities Found (Review Manually)", {
            "Binaries": info_found,
            "Next Step": (
                "Review each capability manually and validate whether the assigned "
                "capabilities introduce privilege escalation opportunities."
            ),
            "Reference": "https://gtfobins.github.io/"
        })

    
    # Return highest severity
    if dangerous_found:
        severity = "CRITICAL"
        count = (
            len(dangerous_found)
            + len(high_found)
            + len(moderate_found)
        )

    elif high_found:
        severity = "HIGH"
        count = len(high_found)

    elif moderate_found:
        severity = "HIGH"
        count = len(moderate_found)

    elif info_found:
        severity = "INFO"
        count = len(info_found)

    else:
        severity = "CLEAN"
        count = 0

    return [{
        "vector": vectors.CAPABILITIES,
        "severity": severity,
        "count": count
    }]