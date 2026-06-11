#!/usr/bin/env python3
# assess_linux_privesc.py
# Linux Privilege Escalation Vulnerability Assessment
# Requires: root privileges for full assessment

import os
import stat
import subprocess
import json
from datetime import datetime

PROJECT_ROOT = "/opt/PrivEscDetection"
REPORT_DIR = f"{PROJECT_ROOT}/reports/assessments"

class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    END = '\033[0m'

def print_header():
    print(f"{Colors.CYAN}")
    print("=" * 60)
    print("  LINUX PRIVILEGE ESCALATION VULNERABILITY ASSESSMENT")
    print("=" * 60)
    print(f"{Colors.END}")

def check_root():
    if os.geteuid() != 0:
        print(f"{Colors.RED}[-] Run as root (sudo) for full assessment{Colors.END}")
        return False
    print(f"{Colors.GREEN}[+] Running as root{Colors.END}")
    return True

def check_suid_binaries():
    """Find SUID binaries - attackers abuse these to run as root"""
    print(f"\n{Colors.MAGENTA}[*] Checking SUID binaries...{Colors.END}")

    result = subprocess.run(
        ['find', '/', '-perm', '-4000', '-type', 'f', '-not', '-path', '/proc/*', 
         '-not', '-path', '/sys/*', '-not', '-path', '/dev/*'],
        capture_output=True, text=True
    )

    suid_bins = [b for b in result.stdout.strip().split('\n') if b]

    # Known dangerous SUID binaries
    dangerous = ['nmap', 'vim', 'nano', 'less', 'more', 'cp', 'mv', 'find', 
                 'bash', 'sh', 'python', 'python3', 'perl', 'ruby', 'php',
                 'awk', 'sed', 'ed', 'cat', 'tail', 'head']

    findings = []
    dangerous_found = []

    for binary in suid_bins:
        basename = os.path.basename(binary)
        if basename in dangerous:
            dangerous_found.append(binary)
            findings.append({
                'category': 'SUID Abuse',
                'title': f'Dangerous SUID: {basename}',
                'severity': 'CRITICAL',
                'detail': f'{binary} has SUID bit set - can be abused for root shell',
                'mitre': 'T1548.001',
                'remediation': f'Remove SUID bit: chmod u-s {binary}'
            })
            print(f"  {Colors.RED}[CRITICAL] Dangerous SUID: {binary}{Colors.END}")

    if not dangerous_found:
        print(f"  {Colors.GREEN}[OK] No dangerous SUID binaries found{Colors.END}")

    print(f"  {Colors.YELLOW}[i] Total SUID binaries: {len(suid_bins)}{Colors.END}")

    return findings

def check_sudo_permissions():
    """Check sudo configuration for misconfigurations"""
    print(f"\n{Colors.MAGENTA}[*] Checking sudo permissions...{Colors.END}")

    findings = []

    # Check if current user can sudo without password
    result = subprocess.run(['sudo', '-n', 'true'], capture_output=True)
    if result.returncode == 0:
        findings.append({
            'category': 'Sudo Misconfiguration',
            'title': 'sudo without password enabled',
            'severity': 'CRITICAL',
            'detail': 'Current user can execute sudo without password prompt',
            'mitre': 'T1548.003',
            'remediation': 'Remove NOPASSWD from sudoers configuration'
        })
        print(f"  {Colors.RED}[CRITICAL] sudo without password enabled{Colors.END}")
    else:
        print(f"  {Colors.GREEN}[OK] sudo requires password{Colors.END}")

    # Check sudoers for dangerous entries
    try:
        with open('/etc/sudoers', 'r') as f:
            sudoers = f.read()
            if 'NOPASSWD' in sudoers:
                findings.append({
                    'category': 'Sudo Misconfiguration',
                    'title': 'NOPASSWD found in sudoers',
                    'severity': 'HIGH',
                    'detail': 'NOPASSWD directive found in /etc/sudoers',
                    'mitre': 'T1548.003',
                    'remediation': 'Audit sudoers and remove unnecessary NOPASSWD entries'
                })
                print(f"  {Colors.YELLOW}[HIGH] NOPASSWD found in /etc/sudoers{Colors.END}")
    except PermissionError:
        print(f"  {Colors.YELLOW}[INFO] Cannot read /etc/sudoers (need root){Colors.END}")

    return findings

def check_writable_system_files():
    """Check for world-writable critical system files"""
    print(f"\n{Colors.MAGENTA}[*] Checking writable system files...{Colors.END}")

    findings = []

    # Check /etc/passwd and /etc/shadow
    critical_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
    for critical_file in critical_files:
        if os.path.exists(critical_file):
            mode = os.stat(critical_file).st_mode
            if mode & stat.S_IWOTH:
                findings.append({
                    'category': 'Weak Permissions',
                    'title': f'World-writable: {os.path.basename(critical_file)}',
                    'severity': 'CRITICAL',
                    'detail': f'{critical_file} is world-writable',
                    'mitre': 'T1222.002',
                    'remediation': f'Fix permissions: chmod o-w {critical_file}'
                })
                print(f"  {Colors.RED}[CRITICAL] {critical_file} is world-writable!{Colors.END}")
            else:
                print(f"  {Colors.GREEN}[OK] {critical_file} permissions secure{Colors.END}")

    # Check for writable cron directories
    cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', 
                 '/etc/cron.weekly', '/var/spool/cron/crontabs']
    for cron_dir in cron_dirs:
        if os.path.exists(cron_dir):
            mode = os.stat(cron_dir).st_mode
            if mode & stat.S_IWOTH:
                findings.append({
                    'category': 'Cron Weakness',
                    'title': f'Writable cron directory: {cron_dir}',
                    'severity': 'CRITICAL',
                    'detail': f'{cron_dir} is world-writable - cron injection possible',
                    'mitre': 'T1053.003',
                    'remediation': f'Fix permissions: chmod o-w {cron_dir}'
                })
                print(f"  {Colors.RED}[CRITICAL] {cron_dir} is world-writable{Colors.END}")

    return findings

def check_kernel_exploits():
    """Check kernel version against known exploits"""
    print(f"\n{Colors.MAGENTA}[*] Checking kernel version...{Colors.END}")

    result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
    kernel = result.stdout.strip()
    print(f"  Kernel: {kernel}")

    findings = []

    # Check for known vulnerable kernels (simplified)
    result = subprocess.run(['uname', '-a'], capture_output=True, text=True)
    print(f"  {Colors.YELLOW}[i] {result.stdout.strip()}{Colors.END}")
    print(f"  {Colors.YELLOW}[i] Check https://www.exploit-db.com/ for kernel exploits{Colors.END}")

    return findings

def check_polkit_vulnerability():
    """Check for polkit vulnerabilities (pkexec)"""
    print(f"\n{Colors.MAGENTA}[*] Checking polkit/pkexec...{Colors.END}")

    findings = []

    pkexec_path = '/usr/bin/pkexec'
    if os.path.exists(pkexec_path):
        mode = os.stat(pkexec_path).st_mode
        if mode & 0o4000:  # SUID
            print(f"  {Colors.YELLOW}[PRESENT] pkexec found with SUID bit{Colors.END}")
            findings.append({
                'category': 'Polkit Target',
                'title': 'pkexec SUID binary present',
                'severity': 'MEDIUM',
                'detail': f'{pkexec_path} is SUID - potential polkit exploit target (CVE-2021-4034)',
                'mitre': 'T1548.001',
                'remediation': 'Keep polkit updated: apt update && apt upgrade polkit'
            })

    return findings

def check_docker_group():
    """Check if users are in docker group (instant root)"""
    print(f"\n{Colors.MAGENTA}[*] Checking docker group membership...{Colors.END}")

    findings = []

    try:
        with open('/etc/group', 'r') as f:
            for line in f:
                if line.startswith('docker:'):
                    members = line.strip().split(':')[-1]
                    if members:
                        findings.append({
                            'category': 'Container Escape',
                            'title': 'Users in docker group',
                            'severity': 'HIGH',
                            'detail': f'Users in docker group can escalate to root: {members}',
                            'mitre': 'T1610',
                            'remediation': 'Remove unnecessary users from docker group'
                        })
                        print(f"  {Colors.YELLOW}[HIGH] Docker group members: {members}{Colors.END}")
                    else:
                        print(f"  {Colors.GREEN}[OK] No users in docker group{Colors.END}")
    except Exception as e:
        print(f"  {Colors.YELLOW}[INFO] Could not check docker group: {e}{Colors.END}")

    return findings

def generate_report(findings):
    """Generate assessment report"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M')
    report_path = f"{REPORT_DIR}/assessment_{timestamp}.json"

    report = {
        'timestamp': datetime.now().isoformat(),
        'hostname': os.uname().nodename,
        'user': os.getenv('USER'),
        'kernel': os.uname().release,
        'summary': {
            'critical': len([f for f in findings if f['severity'] == 'CRITICAL']),
            'high': len([f for f in findings if f['severity'] == 'HIGH']),
            'medium': len([f for f in findings if f['severity'] == 'MEDIUM']),
            'total': len(findings)
        },
        'findings': findings,
        'detection_priorities': [
            '1. Monitor SUID binary creation/modification',
            '2. Monitor cron file changes in /etc/cron.d and /etc/crontab',
            '3. Monitor /etc/passwd and /etc/shadow for modifications',
            '4. Deploy honeypot credentials to detect reconnaissance',
            '5. Monitor sudoers file for unauthorized changes',
            '6. Check for docker group membership abuse'
        ]
    }

    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n{Colors.GREEN}[+] Report saved: {report_path}{Colors.END}")

    # Console summary
    print(f"\n{Colors.CYAN}=== ASSESSMENT SUMMARY ==={Colors.END}")
    print(f"  {Colors.RED}CRITICAL: {report['summary']['critical']}{Colors.END}")
    print(f"  {Colors.YELLOW}HIGH:     {report['summary']['high']}{Colors.END}")
    print(f"  {Colors.CYAN}MEDIUM:   {report['summary']['medium']}{Colors.END}")
    print(f"  {Colors.WHITE}TOTAL:    {report['summary']['total']} findings{Colors.END}")

    print(f"\n{Colors.CYAN}=== DETECTION PRIORITIES ==={Colors.END}")
    for priority in report['detection_priorities']:
        print(f"  {priority}")

if __name__ == '__main__':
    print_header()

    if not check_root():
        exit(1)

    all_findings = []
    all_findings.extend(check_suid_binaries())
    all_findings.extend(check_sudo_permissions())
    all_findings.extend(check_writable_system_files())
    all_findings.extend(check_kernel_exploits())
    all_findings.extend(check_polkit_vulnerability())
    all_findings.extend(check_docker_group())

    generate_report(all_findings)
