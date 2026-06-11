# Linux Privilege Escalation Detection Lab
## VM Specifications & Setup Guide

---

## Recommended VM Configuration

| Component | Specification | Notes |
|-----------|-------------|-------|
| **Hypervisor** | VMware Workstation / VirtualBox / Hyper-V | Any Type 2 hypervisor |
| **OS** | Ubuntu 22.04 LTS Server or Desktop | Debian-based for apt package manager |
| **CPU** | 2 cores minimum | 4 cores recommended for multiple background monitors |
| **RAM** | 4 GB minimum | 8 GB recommended |
| **Disk** | 40 GB minimum | 60 GB recommended with snapshots |
| **Network** | NAT or Host-Only | **Isolated from production networks** |
| **Display** | 1280x720 minimum | For dashboard readability |

---

## VM Setup Steps

### Step 1: Download Ubuntu ISO
- Download Ubuntu 22.04 LTS from https://ubuntu.com/download/desktop
- Verify SHA256 checksum before installation

### Step 2: Create VM in Hypervisor
```
Name: Linux-PrivEsc-Lab
Type: Linux
Version: Ubuntu 64-bit
Memory: 4096 MB (8192 MB recommended)
Disk: 40 GB VDI/VMDK (dynamically allocated)
Network: NAT (for updates) or Host-Only (fully isolated)
```

### Step 3: Install Ubuntu
1. Boot from ISO
2. Select "Install Ubuntu"
3. Choose "Minimal Installation" (reduces attack surface for clean baseline)
4. Create user: `securityadmin` / `SecurityAdmin2026!`
5. Check "Install OpenSSH server" (optional, for remote management)
6. Complete installation and reboot

### Step 4: Post-Installation Setup
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential tools
sudo apt install -y python3 python3-pip git curl wget

# Install VM guest additions (for VMware/VirtualBox)
# VMware: sudo apt install open-vm-tools
# VirtualBox: sudo apt install virtualbox-guest-additions-iso

# Reboot
sudo reboot
```

### Step 5: Snapshot Before Lab
```
Name: Linux-PrivEsc-Lab-Clean-Baseline
Description: Clean Ubuntu 22.04 before privilege escalation detection testing
```

---

## Lab Execution Steps

### 1. Copy Lab Files to VM
```bash
# Option A: Clone from GitHub
git clone https://github.com/YOUR_USERNAME/Privilege-Escalation-Detection-Lab.git /opt/PrivEscDetection

# Option B: Copy via SCP/Shared Folder
cp -r /path/to/linux_lab /opt/PrivEscDetection
```

### 2. Run Setup Script
```bash
cd /opt/PrivEscDetection
sudo bash setup_lab.sh
```

### 3. Verify Installation
```bash
# Check directory structure
ls -la /opt/PrivEscDetection/

# Check test user
id labuser

# Check dependencies
python3 --version
auditd --version
```

### 4. Run Vulnerability Assessment
```bash
cd /opt/PrivEscDetection
sudo python3 scripts/assessment/assess_linux_privesc.py
```

### 5. Start Detection Dashboard (Terminal 1)
```bash
cd /opt/PrivEscDetection
sudo python3 scripts/start_linux_detection.py
```

### 6. Run Attack Simulation (Terminal 2)
```bash
cd /opt/PrivEscDetection
sudo python3 scripts/simulation/simulate_linux_privesc.py
```

### 7. Verify Alerts
- Check dashboard for CRITICAL alerts
- Check `/opt/PrivEscDetection/logs/alerts/` for log files
- Check `/opt/PrivEscDetection/reports/incidents/` for JSON reports

### 8. Clean Up
```bash
# Remove simulation artifacts
sudo python3 scripts/simulation/simulate_linux_privesc.py --cleanup

# Or restore VM snapshot
```

---

## Windows vs Linux Lab Comparison

| Feature | Windows Lab | Linux Lab |
|---------|-------------|-----------|
| **Language** | PowerShell | Python 3 + Bash |
| **Privilege Target** | SYSTEM (NT AUTHORITY) | root (UID 0) |
| **Main Attack** | Registry hijacking, Task Scheduler | SUID abuse, cron injection |
| **Monitoring** | Event Log IDs, registry polling | File system monitoring, hash comparison |
| **Honeypots** | Registry keys, credential files | `.bash_history`, `.env`, SSH keys |
| **MITRE Techniques** | T1548.002, T1053.005 | T1548.001, T1053.003 |
| **Real-world Job** | Windows EDR, Microsoft Defender | Linux EDR, CrowdStrike, SentinelOne |
| **Cloud Relevance** | Azure AD, Intune | AWS EC2, GCP, Docker containers |

---

## Troubleshooting

### Issue: Permission denied on scripts
```bash
chmod +x /opt/PrivEscDetection/scripts/*.py
chmod +x /opt/PrivEscDetection/scripts/*/*.py
```

### Issue: auditd not starting
```bash
sudo systemctl enable auditd
sudo systemctl start auditd
sudo systemctl status auditd
```

### Issue: Python module not found
```bash
sudo apt install python3-pip
pip3 install psutil  # if needed for future enhancements
```

### Issue: SUID detector slow on large filesystems
- The detector walks the entire filesystem. On systems with many files, this can take 30-60 seconds.
- Consider excluding `/usr/share/doc` and `/var/log` from the walk for faster baseline recording.

---

## Security Notes

⚠️ **This lab is designed for isolated environments only.**

- Never run attack simulators on production systems
- The honeypot credentials are fake but designed to look real
- The SUID detector creates temporary files in `/tmp` — ensure `/tmp` is cleaned regularly
- Always restore VM snapshot between test sessions

---

## MITRE ATT&CK Coverage (Linux)

| Technique | ID | Detector | Description |
|-----------|-----|----------|-------------|
| **SUID Abuse** | T1548.001 | watch_suid_abuse.py | Abusing SUID binaries to execute as root |
| **Cron Job** | T1053.003 | watch_cron_abuse.py | Creating/modifying cron jobs for persistence |
| **Sudo Misconfig** | T1548.003 | assess_linux_privesc.py | NOPASSWD sudo or sudoers misconfiguration |
| **Credential Dumping** | T1003 | deploy_honeypot_linux.py | Accessing stored credentials |
| **Weak Permissions** | T1222.002 | assess_linux_privesc.py | World-writable system files |
| **Container Escape** | T1610 | assess_linux_privesc.py | Docker group membership abuse |

---

*Document Version: 1.0*
*Last Updated: June 2026*
