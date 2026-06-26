# linpriv-map 🗺️

> A clean, fast, offline Linux Privilege Escalation Mapper for CTFs, Pentests & Learning.

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-red)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 🔍 What is linpriv-map?

`linpriv-map` is a lightweight alternative to LinPEAS.  
Instead of dumping everything, it checks **15 specific privilege escalation vectors**,  
shows **color-coded findings** and suggests **exact next steps** for each finding.

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
git clone https://github.com/<YOUR_USERNAME>/linpriv-map.git
cd linpriv-map
pip3 install -r requirements.txt
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
2. `/usr/bin/python3`

**Risk:**  
These binaries run as root regardless of the calling user.

**Next Step:**  
```bash
find . -exec /bin/sh -p \; -quit
```
## Reference:

https://gtfobins.github.io/

# 📊 SCAN SUMMARY

[CRITICAL] SUID Binaries (2 findings)
[CLEAN]    Sudo Rights
[HIGH]     SSH Dir Perms (1 finding)

[!] 2 CRITICAL vector(s) found — prioritize these!