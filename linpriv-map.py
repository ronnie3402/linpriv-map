import sys
import os
import argparse
import io

from colorama import init
init(autoreset=True)

# Core modules
from core.banner import print_banner
from core.printer import print_summary
from core.report import save_text_report, save_json_report
from core import vectors

# Check modules
from checks import (
    suid_guid, sudo_rights, cron_jobs, kernel_version,
    writable_paths, capabilities, env_variables, nfs_shares,
    password_files, service_exploit, port_forwarding,
    user_groups, vuln_software, weak_file_perms, running_procs
)

# ─────────────────────────────────────────────
# All checks registry
# ─────────────────────────────────────────────

ALL_CHECKS = {
    "suid"       : ("SUID / GUID / Sticky Bit", suid_guid),
    "sudo"       : ("Sudo Rights",               sudo_rights),
    "cron"       : ("Cron Jobs",                 cron_jobs),
    "kernel"     : ("Kernel Version",            kernel_version),
    "writable"   : ("Writable Paths",            writable_paths),
    "capabilities": ("Linux Capabilities",       capabilities),
    "env"        : ("Environment Variables",     env_variables),
    "nfs"        : ("NFS Shares",                nfs_shares),
    "passwords"  : ("Password Files",            password_files),
    "services"   : ("Service Exploitation",      service_exploit),
    "ports"      : ("Port Forwarding",           port_forwarding),
    "groups"     : ("User Groups",               user_groups),
    "software"   : ("Vulnerable Software",       vuln_software),
    "fileperms"  : ("Weak File Permissions",     weak_file_perms),
    "procs"      : ("Running Processes",         running_procs),
}


# ─────────────────────────────────────────────
# Argument Parser
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="linpriv-map",
        description=(
            "╔══════════════════════════════════════════════════════════╗\n"
            "║       linpriv-map — Linux Privilege Escalation Mapper    ║\n"
            "║       For CTFs | Pentests | Learning                     ║\n"
            "╚══════════════════════════════════════════════════════════╝\n\n"
            "  Checks 15 privilege escalation vectors on Linux systems.\n"
            "  Outputs color-coded findings with risk level and next steps.\n"
            "  All checks run offline — no internet required.\n"
        ),
        epilog=(
            "Examples:\n"
            "  python3 linpriv-map.py                        Run all checks\n"
            "  python3 linpriv-map.py --check suid           Run single check\n"
            "  python3 linpriv-map.py --severity critical    Show critical only\n"
            "  python3 linpriv-map.py --output scan1         Save as text report\n"
            "  python3 linpriv-map.py --json                 Save as JSON report\n"
            "  python3 linpriv-map.py --output s1 --json     Save both formats\n"
            "  python3 linpriv-map.py --list                 List all modules\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "--check",
        metavar="MODULE",
        help=(
            "Run a specific check module only.\n"
            "Use --list to see all available module names.\n"
            "Example: --check suid\n"
        )
    )

    parser.add_argument(
        "--severity",
        metavar="LEVEL",
        choices=["critical", "high", "info", "clean"],
        help=(
            "Filter summary output by severity level.\n"
            "Choices: critical, high, info, clean\n"
            "Example: --severity critical\n"
        )
    )

    parser.add_argument(
        "--output",
        metavar="FILENAME",
        help=(
            "Save plain text report to scans/<filename>.txt\n"
            ".txt extension added automatically if missing.\n"
            "Example: --output myscan\n"
        )
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Save findings as JSON to scans/YYYY-MM-DD_HH-MM-SS.json\n"
            "Can be combined with --output to save both formats.\n"
        )
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available check modules with their names.\n"
    )

    return parser.parse_args()


# ─────────────────────────────────────────────
# List Checks
# ─────────────────────────────────────────────

def list_checks():
    from colorama import Fore, Style
    print(f"\n{Fore.CYAN + Style.BRIGHT}  Available Check Modules:{Style.RESET_ALL}\n")
    for key, (name, _) in ALL_CHECKS.items():
        print(f"  {Fore.YELLOW}--check {key:<15}{Style.RESET_ALL} {name}")
    print()


# ─────────────────────────────────────────────
# Run Checks
# ─────────────────────────────────────────────

def run_checks(selected=None):
    all_results = []

    if selected:
        if selected not in ALL_CHECKS:
            print(f"\n[!] Unknown module: '{selected}'")
            print(f"    Run with --list to see available modules.\n")
            sys.exit(1)
        _, module = ALL_CHECKS[selected]
        all_results += module.run()
    else:
        for key, (name, module) in ALL_CHECKS.items():
            try:
                all_results += module.run()
            except Exception as e:
                from colorama import Fore, Style
                print(f"\n{Fore.RED}[ERROR] {name} check failed: {e}{Style.RESET_ALL}")

    return all_results


# ─────────────────────────────────────────────
# Filter Results by Severity
# ─────────────────────────────────────────────

def filter_results(results, severity):
    if not severity:
        return results
    return [r for r in results if r.get("severity", "").lower() == severity.lower()]


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    args = parse_args()

    # --list flag
    if args.list:
        print_banner()
        list_checks()
        sys.exit(0)

    # Output capture karo agar --output flag hai
    capture = args.output is not None
    if capture:
        buffer = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buffer

    # Banner
    print_banner()

    # Checks run karo
    results = run_checks(selected=args.check)

    # Severity filter
    filtered = filter_results(results, args.severity)

    # Summary print karo
    print_summary(filtered if args.severity else results)

    # --output: text report save karo
    if capture:
        sys.stdout = old_stdout
        captured = buffer.getvalue()
        print(captured)  # Terminal par bhi dikhao
        save_text_report(captured, args.output)

    # --json: JSON report save karo
    if args.json:
        save_json_report(results)


if __name__ == "__main__":
    main()