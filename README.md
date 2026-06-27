# linpriv-map 🗺️


![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-red)
![License](https://img.shields.io/badge/License-MIT-green)
> A clean, fast, offline Linux Privilege Escalation Mapper for CTFs, Pentests & Learning.
<img width="1686" height="737" alt="asd" src="https://github.com/user-attachments/assets/43c34978-9df8-47f2-8912-6dff0944889d" />

---

## 🔍 What is linpriv-map?

`linpriv-map` is a lightweight alternative to LinPEAS. Instead of dumping everything, it checks **15 specific privilege escalation vectors**, shows **color-coded findings** and suggests **exact next steps** for each finding.

---

## ⚡ Features

- ✅ 15 privilege escalation vectors covered
- ✅ Color-coded output — CRITICAL / HIGH / INFO / NOT FOUND
- ✅ Exploit hints with exact commands for each finding
- ✅ Local GTFOBins reference — no internet required
- ✅ Save reports as plain text or JSON
- ✅ Run all checks or target a specific vector
- ✅ Clean summary table at end of every scan

---

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/ronnie3402/linpriv-map.git
cd linpriv-map

# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the tool
python3 linpriv-map.py --help
```

---

## 🚀 Usage

```bash
# Run all checks
python3 linpriv-map.py

# Run a specific check
python3 linpriv-map.py --check suid

# Show only critical findings in summary
python3 linpriv-map.py --severity critical

# Save plain text report
python3 linpriv-map.py --output myscan

# Save JSON report
python3 linpriv-map.py --json

# Save both formats
python3 linpriv-map.py --output myscan --json

# List all available modules
python3 linpriv-map.py --list

# Help
python3 linpriv-map.py --help
```

---

## 📋 Privilege Escalation Vectors Covered

| # | Module | Checks |
|---|--------|--------|
| 1 | SUID / GUID / Sticky Bit | SUID binaries, GUID binaries, sticky bit misconfig |
| 2 | Sudo Rights | NOPASSWD entries, dangerous sudo binaries |
| 3 | Cron Jobs | /etc/crontab, cron.d, writable cron scripts |
| 4 | Kernel Version | Kernel enumeration for manual CVE lookup |
| 5 | Writable Paths | Writable $PATH dirs, writable system files |
| 6 | Linux Capabilities | cap_setuid, cap_sys_admin and more via getcap |
| 7 | Environment Variables | LD_PRELOAD, LD_LIBRARY_PATH, PYTHONPATH abuse |
| 8 | NFS Shares | no_root_squash, no_all_squash in /etc/exports |
| 9 | Password Files | /etc/shadow readable, writable sensitive files |
| 10 | Service Exploitation | Writable service files and binaries |
| 11 | Port Forwarding | Localhost-only services, tunneling tools |
| 12 | User Groups | docker, lxd, shadow, disk, sudo, adm groups |
| 13 | Vulnerable Software | Installed software version enumeration |
| 14 | Weak File Permissions | Critical file perms, SSH directory permissions |
| 15 | Running Processes | Root processes, interesting services |

---

## 📁 Output Example

# Possible Vector: SUID / GUID / Sticky Bit

---

## 🚨 CRITICAL FINDING

### SUID Binary Found

**Binaries:**
1. `/usr/bin/find`  


**Risk:**  
These binaries run as root regardless of the calling user.

**Next Step:**  
```bash
find . -exec /bin/sh -p \; -quit
```
Reference: https://gtfobins.github.io/

📊 SCAN SUMMARY
```
[CRITICAL] SUID Binaries (1 findings)
[CLEAN]    Sudo Rights
[HIGH]     SSH Dir Perms (1 finding)

[!] 2 CRITICAL vector(s) found — prioritize these!
```
<img width="1682" height="841" alt="out1" src="https://github.com/user-attachments/assets/0ef228f4-cd01-42c8-8213-aa727f9a5c9a" />


---

## ⚠️ Disclaimer

> This tool is intended for **authorized penetration testing, CTF challenges, and educational purposes only**.  
> Use only on systems you own or have explicit permission to test.  
> The author is not responsible for any misuse.

---
## 🧠 Technical Learnings

Building `linpriv-map` taught me the following concepts hands-on:

### 🐍 Python
- Modular project architecture — separating concerns across `core/` and `checks/` packages
- `argparse` — building professional CLI interfaces with flags, help text, and examples
- `subprocess` — running shell commands from Python and capturing output safely
- `colorama` — cross-platform terminal color output
- `glob` — pattern matching for filesystem paths like `/home/*/.ssh/`
- `io.StringIO` — capturing stdout output programmatically for report saving
- `json` — reading and writing structured data for local GTFOBins reference and JSON reports
- `os.path`, `os.access` — checking file existence, read/write permissions portably
- Virtual environments — isolating project dependencies cleanly
- Constants file pattern (`vectors.py`) — avoiding hardcoded strings, making code refactor-safe

### 🔐 Linux Privilege Escalation
- SUID/GUID binaries — how they work and why they are dangerous when set on powerful binaries
- GTFOBins — how common Linux binaries like find, python, vim can be abused for privilege escalation
- Sticky Bit — difference between dangerous world-writable dirs and properly protected ones
- Sudo misconfigurations — NOPASSWD entries, dangerous binary combinations in sudoers
- Cron job abuse — writable scripts called by root cron jobs, PATH hijacking via cron
- Kernel version enumeration — identifying kernel for manual CVE research (DirtyCOW, DirtyPipe etc.)
- Writable PATH hijacking — placing malicious binaries in writable $PATH directories
- Linux Capabilities — cap_setuid, cap_sys_admin, cap_dac_override and their escalation potential
- Environment variable abuse — LD_PRELOAD, LD_LIBRARY_PATH, PYTHONPATH injection techniques
- NFS misconfigurations — no_root_squash and no_all_squash exploitation technique
- Password file exposure — /etc/shadow readable, /etc/passwd writable, SSH private key access
- Service exploitation — writable systemd service files and service binaries running as root
- Port forwarding opportunities — localhost-only services accessible via SSH tunneling or socat
- Dangerous group memberships — docker, lxd, shadow, disk, adm, video, staff group escalation paths
- Weak file permissions — world-readable sensitive files, insecure SSH directory permissions

### 🛠️ Tool Design
- Why clean output matters — LinPEAS dumps everything, targeted tools are more useful
- Offline-first design — storing GTFOBins data locally in JSON for air-gapped environments
- Severity classification — CRITICAL vs HIGH vs INFO vs NOT FOUND and when to use each
- Report generation — stripping ANSI color codes for clean plain text file output
- Structured findings — returning standardized result dicts from every module for summary table
- One-file-one-responsibility — each check module is fully independent and testable
---
## 📜 License

This project is for educational and security analysis purposes only. 
Licensed under the [MIT License](LICENSE).

---

## 👨‍💻 Author

**Rohit** — Built for the cybersecurity community.
*Copyright (c) 2026 Rohit (ronnie3402)*

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---
