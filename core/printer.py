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

    critical_count = 0
    high_count = 0

    for r in results:
        severity = r.get("severity", "CLEAN")
        vector   = r.get("vector", "Unknown")
        count    = r.get("count", 0)

        if severity == "CRITICAL":
            critical_count += count
            tag = f"{Fore.RED + Style.BRIGHT}[CRITICAL]{Style.RESET_ALL}"
        elif severity == "HIGH":
            high_count += count
            tag = f"{Fore.YELLOW + Style.BRIGHT}[HIGH]    {Style.RESET_ALL}"
        elif severity == "INFO":
            tag = f"{Fore.CYAN}[INFO]    {Style.RESET_ALL}"
        else:
            tag = f"{Style.DIM}[CLEAN]   {Style.RESET_ALL}"

        count_str = f"({count} finding{'s' if count != 1 else ''})" if count > 0 else ""
        print(f"  {tag} {vector} {Fore.WHITE}{count_str}{Style.RESET_ALL}")

    print(f"{Fore.CYAN + Style.BRIGHT}{'─' * 60}{Style.RESET_ALL}")

    if critical_count > 0:
        print(f"  {Fore.RED + Style.BRIGHT}[!] {critical_count} CRITICAL vector(s) found — prioritize these!{Style.RESET_ALL}")
    if high_count > 0:
        print(f"  {Fore.YELLOW + Style.BRIGHT}[!] {high_count} HIGH vector(s) found — worth investigating.{Style.RESET_ALL}")
    if critical_count == 0 and high_count == 0:
        print(f"  {Fore.GREEN + Style.BRIGHT}[+] No critical or high severity vectors found.{Style.RESET_ALL}")

    print(f"{Fore.CYAN + Style.BRIGHT}{'═' * 60}{Style.RESET_ALL}\n")