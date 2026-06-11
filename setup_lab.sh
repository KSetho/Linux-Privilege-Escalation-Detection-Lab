#!/bin/bash
# setup_lab.sh
# Linux Privilege Escalation Detection Lab - Environment Setup
# Run as root on Ubuntu/Debian VM

set -e

PROJECT_ROOT="/opt/PrivEscDetection"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "================================================"
echo "  LINUX PRIVILEGE ESCALATION DETECTION LAB"
echo "  Environment Setup"
echo "================================================"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[-] Run this script as root (sudo)${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Running as root${NC}"

# Create project structure
echo -e "${CYAN}[*] Creating project structure...${NC}"

mkdir -p $PROJECT_ROOT/{scripts/{detectors,simulation,assessment},honeypots/{credentials,files},logs/{suid,cron,systemd,alerts},reports/{assessments,incidents},documentation/screenshots}

echo -e "${GREEN}[+] Created: $PROJECT_ROOT${NC}"
echo -e "${GREEN}[+] Created: scripts/detectors${NC}"
echo -e "${GREEN}[+] Created: scripts/simulation${NC}"
echo -e "${GREEN}[+] Created: scripts/assessment${NC}"
echo -e "${GREEN}[+] Created: honeypots/credentials${NC}"
echo -e "${GREEN}[+] Created: honeypots/files${NC}"
echo -e "${GREEN}[+] Created: logs/{suid,cron,systemd,alerts}${NC}"
echo -e "${GREEN}[+] Created: reports/{assessments,incidents}${NC}"
echo -e "${GREEN}[+] Created: documentation/screenshots${NC}"

# Create test user (low privilege)
echo -e "${CYAN}[*] Creating test user...${NC}"
if id "labuser" &>/dev/null; then
    echo -e "${YELLOW}[i] User 'labuser' already exists${NC}"
else
    useradd -m -s /bin/bash labuser
    echo "labuser:LabUser2026!" | chpasswd
    usermod -aG users labuser
    echo -e "${GREEN}[+] Created test user: labuser (standard privileges)${NC}"
fi

# Ensure NOT in sudo group
if groups labuser | grep -q "\bsudo\b"; then
    gpasswd -d labuser sudo
    echo -e "${GREEN}[+] Removed labuser from sudo group${NC}"
fi

# Verify
echo -e "${CYAN}[*] User verification:${NC}"
id labuser
echo -e "${CYAN}[*] Group memberships:${NC}"
groups labuser

# Install dependencies
echo -e "${CYAN}[*] Installing dependencies...${NC}"
apt-get update -qq
apt-get install -y -qq python3 python3-pip auditd inotify-tools

echo -e "${GREEN}[+] Python3 installed${NC}"
echo -e "${GREEN}[+] auditd installed${NC}"
echo -e "${GREEN}[+] inotify-tools installed${NC}"

# Enable auditd
systemctl enable auditd
systemctl start auditd
echo -e "${GREEN}[+] auditd service enabled${NC}"

# Set permissions
echo -e "${CYAN}[*] Setting permissions...${NC}"
chown -R root:root $PROJECT_ROOT
chmod -R 755 $PROJECT_ROOT
chmod -R 777 $PROJECT_ROOT/logs
chmod -R 777 $PROJECT_ROOT/reports

echo -e "${GREEN}[+] Permissions configured${NC}"

echo -e "${CYAN}"
echo "================================================"
echo "  LAB ENVIRONMENT READY"
echo "================================================"
echo -e "${NC}"
echo -e "${YELLOW}[!] IMPORTANT: Take VM snapshot now!${NC}"
echo -e "${YELLOW}    Name: 'Linux-PrivEsc-Lab-Clean-Baseline'${NC}"
echo -e "${YELLOW}    Description: Clean Ubuntu before privilege escalation detection testing${NC}"
echo ""
echo -e "${CYAN}Next steps:${NC}"
echo -e "  1. Run: python3 scripts/assessment/assess_linux_privesc.py"
echo -e "  2. Run: python3 scripts/detectors/watch_suid_abuse.py"
echo -e "  3. Run: python3 scripts/simulation/simulate_linux_privesc.py"
