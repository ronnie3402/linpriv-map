from core import vectors
from core.utils import read_file
from core.printer import (
    print_section, print_critical,
    print_high, print_not_found
)

VECTOR_NAME = vectors.NFS_SHARES

def run() -> list:
    print_section(VECTOR_NAME)

    exports = read_file("/etc/exports")

    if not exports:
        print_not_found("NFS Shares", {
            "Checked": "/etc/exports",
            "Result" : "No NFS exports configuration found"
        })
        return [{"vector": vectors.NFS_SHARES, "severity": "CLEAN", "count": 0}]

    lines = [
        line.strip()
        for line in exports.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not lines:
        print_not_found("NFS Shares", {
            "Checked": "/etc/exports",
            "Result" : "No active NFS exports found"
        })
        return [{"vector": "NFS Shares", "severity": "CLEAN", "count": 0}]

    no_root_squash = []
    no_all_squash = []
    normal_exports = []

    for line in lines:
        if "no_root_squash" in line:
            no_root_squash.append(line)
        elif "no_all_squash" in line:
            no_all_squash.append(line)
        else:
            normal_exports.append(line)

    results = []

    if no_root_squash:
        print_critical("NFS Export with no_root_squash Found", {
            "Exports"  : no_root_squash,
            "Risk"     : "Remote root user keeps root privileges on mounted share",
            "Next Step": [
                "Mount the exported share",
                "Create SUID binary on mounted share",
                "Execute binary locally to gain root"
            ],
            "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe"
        })

        results.append({
            "vector": "NFS no_root_squash",
            "severity": "CRITICAL",
            "count": len(no_root_squash)
        })

    if no_all_squash:
        print_high("NFS Export with no_all_squash Found", {
            "Exports"  : no_all_squash,
            "Risk"     : "User identities preserved across NFS share",
            "Next Step": "Review export permissions manually",
            "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation"
        })

        results.append({
            "vector": "NFS no_all_squash",
            "severity": "HIGH",
            "count": len(no_all_squash)
        })

    if normal_exports:
        print_high("NFS Exports Found", {
            "Exports"  : normal_exports,
            "Risk"     : "NFS share present — review export options manually",
            "Next Step": "Check for weak permissions or misconfigurations",
            "Reference": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation"
        })

        results.append({
            "vector": "NFS Exports",
            "severity": "HIGH",
            "count": len(normal_exports)
        })

    return results

