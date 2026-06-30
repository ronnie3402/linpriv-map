from colorama import Fore, Style, init

init(autoreset=True)

# ─────────────────────────────────────────────
# Section Header
# ─────────────────────────────────────────────

def print_section(title: str):
    print(f"\n{Fore.MAGENTA + Style.BRIGHT}{'─' * 60}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA + Style.BRIGHT}  Possible Vector: {title}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA + Style.BRIGHT}{'─' * 60}{Style.RESET_ALL}")


# ─────────────────────────────────────────────
# Severity Label Helpers
# ─────────────────────────────────────────────

def label_critical():
    return f"{Fore.RED + Style.BRIGHT}[CRITICAL]{Style.RESET_ALL}"

def label_high():
    return f"{Fore.YELLOW + Style.BRIGHT}[HIGH]{Style.RESET_ALL}"

def label_info():
    return f"{Fore.CYAN}[INFO]{Style.RESET_ALL}"

def label_not_found():
    return f"{Style.DIM}[NOT FOUND]{Style.RESET_ALL}"


# ─────────────────────────────────────────────
# Main Print Functions
# ─────────────────────────────────────────────

def print_critical(title: str, fields: dict):
    print(f"\n{label_critical()} {Fore.RED + Style.BRIGHT}{title}{Style.RESET_ALL}")
    _print_fields(fields)

def print_high(title: str, fields: dict):
    print(f"\n{label_high()} {Fore.YELLOW + Style.BRIGHT}{title}{Style.RESET_ALL}")
    _print_fields(fields)

def print_info(title: str, fields: dict):
    print(f"\n{label_info()} {Fore.CYAN}{title}{Style.RESET_ALL}")
    _print_fields(fields)

def print_not_found(title: str, fields: dict):
    print(f"\n{label_not_found()} {Style.DIM}{title}{Style.RESET_ALL}")
    _print_fields(fields, dim=True)


# ─────────────────────────────────────────────
# Internal Field Printer
# ─────────────────────────────────────────────

def _print_fields(fields: dict, dim: bool = False):
    max_key_len = max((len(k) for k in fields.keys()), default=8)

    for label, value in fields.items():
        padding = " " * (max_key_len - len(label))
        prefix = f"  {Fore.WHITE}{label}{Style.RESET_ALL}{padding} : "

        if dim:
            prefix = f"  {Style.DIM}{label}{padding} : "

        if isinstance(value, list):
            print(f"{prefix}")
            for idx, item in enumerate(value, start=1):
                if dim:
                    print(f"    {Style.DIM}{idx}. {item}{Style.RESET_ALL}")
                else:
                    print(f"    {Fore.WHITE}{idx}.{Style.RESET_ALL} {item}")
        else:
            if dim:
                print(f"{prefix}{Style.DIM}{value}{Style.RESET_ALL}")
            else:
                print(f"{prefix}{value}")


# ─────────────────────────────────────────────
# Summary Table
# ─────────────────────────────────────────────

def print_summary(results: list):
    print(f"\n{Fore.CYAN + Style.BRIGHT}{'═' * 60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN + Style.BRIGHT}  SCAN SUMMARY{Style.RESET_ALL}")
    print(f"{Fore.CYAN + Style.BRIGHT}{'═' * 60}{Style.RESET_ALL}")

    critical_vectors  = 0
    critical_findings = 0
    high_vectors       = 0
    high_findings       = 0

    for r in results:
        severity = str(r.get("severity", "CLEAN")).upper()
        vector   = r.get("vector", "Unknown")
        count    = int(r.get("count", 0) or 0)

        if severity == "CRITICAL":
            critical_vectors += 1
            critical_findings += count
            tag = f"{Fore.RED + Style.BRIGHT}[CRITICAL]{Style.RESET_ALL}"
        elif severity == "HIGH":
            high_vectors += 1
            high_findings += count
            tag = f"{Fore.YELLOW + Style.BRIGHT}[HIGH]    {Style.RESET_ALL}"
        elif severity == "INFO":
            tag = f"{Fore.CYAN}[INFO]    {Style.RESET_ALL}"
        elif severity == "CLEAN":
            tag = f"{Style.DIM}[CLEAN]   {Style.RESET_ALL}"
        else:
            tag = f"{Fore.MAGENTA}[UNKNOWN] {Style.RESET_ALL}"

        # Sirf CRITICAL/HIGH ke liye count dikhao — INFO/CLEAN ke liye nahi
        count_str = ""
        if severity in ("CRITICAL", "HIGH") and count > 0:
            count_str = f"({count})"

        print(f"  {tag} {vector:<28} {Fore.WHITE}{count_str}{Style.RESET_ALL}")

    print(f"{Fore.CYAN + Style.BRIGHT}{'─' * 60}{Style.RESET_ALL}")

    if critical_vectors > 0:
        plural_v = "vector" if critical_vectors == 1 else "vectors"
        plural_f = "finding" if critical_findings == 1 else "findings"
        print(f"  {Fore.RED + Style.BRIGHT}[!] {critical_vectors} CRITICAL {plural_v} "
              f"({critical_findings} {plural_f}) — prioritize these!{Style.RESET_ALL}")

    if high_vectors > 0:
        plural_v = "vector" if high_vectors == 1 else "vectors"
        plural_f = "finding" if high_findings == 1 else "findings"
        print(f"  {Fore.YELLOW + Style.BRIGHT}[!] {high_vectors} HIGH {plural_v} "
              f"({high_findings} {plural_f}) — worth investigating.{Style.RESET_ALL}")

    if critical_vectors == 0 and high_vectors == 0:
        print(f"  {Fore.GREEN + Style.BRIGHT}[+] No critical or high severity vectors found.{Style.RESET_ALL}")

    print(f"{Fore.CYAN + Style.BRIGHT}{'═' * 60}{Style.RESET_ALL}\n")