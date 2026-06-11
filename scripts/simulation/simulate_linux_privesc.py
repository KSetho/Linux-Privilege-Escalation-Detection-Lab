#!/usr/bin/env python3
# simulate_linux_privesc.py
# Safe Linux Privilege Escalation Simulator
# Simulates attack behaviors without actual system compromise

import os
import sys
import time
import subprocess

PROJECT_ROOT = "/opt/PrivEscDetection"
SIM_LOG = f"{PROJECT_ROOT}/logs/simulation_{time.strftime('%Y%m%d_%H%M%S')}.log"

class Colors:
    MAGENTA = '\033[95m'
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'

def log(msg):
    entry = f"[{time.strftime('%H:%M:%S')}] [SIM] {msg}"
    print(f"{Colors.MAGENTA}{entry}{Colors.END}")
    with open(SIM_LOG, 'a') as f:
        f.write(entry + "\n")

def simulate_suid_abuse():
    """Simulate SUID binary creation"""
    log("=== SIMULATING SUID ABUSE ===")

    fake_suid = "/tmp/sim_suid_shell"
    with open(fake_suid, 'w') as f:
        f.write("#!/bin/bash\necho 'SIMULATION: SUID shell executed'\n")

    os.chmod(fake_suid, 0o4755)
    log(f"Created fake SUID binary: {fake_suid}")
    log("Your SUID detector should fire CRITICAL alert")

    time.sleep(3)

    if os.path.exists(fake_suid):
        os.remove(fake_suid)
        log("Cleaned up fake SUID binary")

def simulate_cron_abuse():
    """Simulate cron job creation"""
    log("=== SIMULATING CRON ABUSE ===")

    cron_file = "/tmp/sim_cron_test"
    with open(cron_file, 'w') as f:
        f.write("* * * * * root /bin/echo 'SIMULATION_CRON_TEST'\n")

    log(f"Created fake cron file: {cron_file}")
    log("Your cron detector should fire CRITICAL alert")

    time.sleep(3)

    if os.path.exists(cron_file):
        os.remove(cron_file)
        log("Cleaned up fake cron file")

def simulate_sudo_recon():
    """Simulate sudo enumeration"""
    log("=== SIMULATING SUDO RECONNAISSANCE ===")

    commands = [
        "sudo -l",
        "cat /etc/sudoers 2>/dev/null || true",
        "find / -perm -4000 2>/dev/null | head -5"
    ]

    for cmd in commands:
        log(f"Running: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output = result.stdout.strip().split('\n')[:3]
        for line in output:
            if line:
                log(f"  Output: {line}")
        time.sleep(1)

def simulate_file_recon():
    """Simulate attacker searching for credentials"""
    log("=== SIMULATING CREDENTIAL RECON ===")

    search_paths = [
        os.path.expanduser("~/.bash_history"),
        "/opt/PrivEscDetection/honeypots/credentials/.env",
        "/opt/PrivEscDetection/honeypots/credentials/sudoers.bak"
    ]

    for path in search_paths:
        if os.path.exists(path):
            log(f"Reading: {path}")
            try:
                with open(path, 'r') as f:
                    content = f.read()
                log(f"  Read {len(content)} bytes")
            except PermissionError:
                log(f"  Permission denied (expected)")

if __name__ == '__main__':
    print(f"{Colors.RED}!!! LINUX PRIVILEGE ESCALATION SIMULATOR !!!{Colors.END}")
    print(f"{Colors.YELLOW}Target: LAB ENVIRONMENT ONLY{Colors.END}\n")

    for i in range(3, 0, -1):
        print(f"Starting in {i}...")
        time.sleep(1)

    log("Running ALL simulations...")
    simulate_suid_abuse()
    time.sleep(2)
    simulate_cron_abuse()
    time.sleep(2)
    simulate_sudo_recon()
    time.sleep(2)
    simulate_file_recon()

    print(f"\n{Colors.GREEN}[+] Simulation complete. Check detectors for alerts.{Colors.END}")
    print(f"{Colors.CYAN}[i] Log: {SIM_LOG}{Colors.END}")
