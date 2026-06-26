import datetime
import os
import subprocess
from colorama import Fore, Style, init

init(autoreset=True)

def print_banner():
    banner = rf"""
{Fore.RED + Style.BRIGHT}
 _ _                  _                                    
| (_)_ __  _ __  _ __(_)_   __     _ __ ___   __ _ _ __  
| | | '_ \| '_ \| '__| \ \ / /____| '_ ` _ \ / _` | '_ \ 
| | | | | | |_) | |  | |\ V /_____| | | | | | (_| | |_) |
|_|_|_| |_| .__/|_|  |_| \_/      |_| |_| |_|\__,_| .__/ 
           |_|                                       |_|    
{Style.RESET_ALL}"""

    print(banner)
    print(f"{Fore.CYAN + Style.BRIGHT}{'─' * 60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}   Linux Privilege Escalation Mapper  v1.0{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}   For CTFs | Pentests | Learning{Style.RESET_ALL}")
    print(f"{Fore.CYAN + Style.BRIGHT}{'─' * 60}{Style.RESET_ALL}")

    # System Info
    try:
        hostname = subprocess.check_output(
            "hostname", shell=True, stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        hostname = "unknown"

    current_user = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"  {Fore.WHITE}Tool     :{Style.RESET_ALL} linpriv-map")
    print(f"  {Fore.WHITE}Host     :{Style.RESET_ALL} {hostname}")
    print(f"  {Fore.WHITE}User     :{Style.RESET_ALL} {current_user}")
    print(f"  {Fore.WHITE}Date     :{Style.RESET_ALL} {now}")
    print(f"{Fore.CYAN + Style.BRIGHT}{'─' * 60}{Style.RESET_ALL}\n")