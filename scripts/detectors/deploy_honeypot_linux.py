#!/usr/bin/env python3
# deploy_honeypot_linux.py
# Honeypot Credential Detector for Linux
# Deploys decoy credentials and monitors for access (T1003)

import os
import time
import json
from datetime import datetime

PROJECT_ROOT = "/opt/PrivEscDetection"
ALERT_DIR = f"{PROJECT_ROOT}/logs/alerts"
REPORT_DIR = f"{PROJECT_ROOT}/reports/incidents"

class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'
    END = '\033[0m'

class LinuxHoneypot:
    def __init__(self):
        self.baseline = {}
        self.deploy()

    def deploy(self):
        print(f"{Colors.CYAN}=== Deploying Linux Honeypot Credentials ==={Colors.END}")
        print(f"{Colors.YELLOW}[i] All credentials are FAKE decoys{Colors.END}\n")

        # Fake .bash_history with "accidentally" typed password
        bash_history = os.path.expanduser("~/.bash_history")
        fake_history = """
# Accidentally typed password in command line:
sudo -S <<< "HoneyRoot@2026!" apt update
mysql -u root -pHoneyDB@2026! -e "SHOW DATABASES"
ssh admin@192.168.1.100
# Oops: echo "HoneyPass@2026!" > /tmp/creds.txt
scp file.txt root@192.168.1.1:/tmp/
"""
        with open(bash_history, 'a') as f:
            f.write(fake_history)
        print(f"  {Colors.GREEN}[+] Bash history honeypot: {bash_history}{Colors.END}")

        # Fake environment file
        env_file = f"{PROJECT_ROOT}/honeypots/credentials/.env"
        env_content = """# Production Environment - DO NOT SHARE
DB_HOST=192.168.1.100
DB_USER=admin
DB_PASS=HoneyDB@2026!
API_KEY=HONEY-API-KEY-12345
SECRET_KEY=HONEY-SECRET-67890
AWS_ACCESS_KEY=AKIAHONEY1234567890
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYHONEYKEY
"""
        with open(env_file, 'w') as f:
            f.write(env_content)
        print(f"  {Colors.GREEN}[+] Environment file honeypot: {env_file}{Colors.END}")

        # Fake sudoers backup
        sudoers_backup = f"{PROJECT_ROOT}/honeypots/credentials/sudoers.bak"
        sudoers_content = """# Sudoers backup - CONFIDENTIAL
root ALL=(ALL:ALL) ALL
admin ALL=(ALL) NOPASSWD: ALL
# Backup password: HoneySudo@2026!
"""
        with open(sudoers_backup, 'w') as f:
            f.write(sudoers_content)
        print(f"  {Colors.GREEN}[+] Sudoers backup honeypot: {sudoers_backup}{Colors.END}")

        # Fake SSH key
        ssh_dir = f"{PROJECT_ROOT}/honeypots/credentials/.ssh"
        os.makedirs(ssh_dir, exist_ok=True)
        with open(f"{ssh_dir}/id_rsa", 'w') as f:
            f.write("""-----BEGIN RSA PRIVATE KEY-----
HONEY-FAKE-SSH-KEY-12345
This is a decoy SSH key for detection purposes
-----END RSA PRIVATE KEY-----
""")
        print(f"  {Colors.GREEN}[+] SSH key honeypot: {ssh_dir}/id_rsa{Colors.END}")

        # Fake database config
        db_config = f"{PROJECT_ROOT}/honeypots/files/db.conf"
        db_content = """[database]
host = 192.168.1.100
port = 3306
user = dbadmin
password = HoneyDBConfig@2026!
database = production
"""
        with open(db_config, 'w') as f:
            f.write(db_content)
        print(f"  {Colors.GREEN}[+] Database config honeypot: {db_config}{Colors.END}")

        # Record baseline access times
        for filepath in [bash_history, env_file, sudoers_backup, f"{ssh_dir}/id_rsa", db_config]:
            if os.path.exists(filepath):
                self.baseline[filepath] = os.path.getatime(filepath)

        print(f"\n{Colors.GREEN}[+] All honeypots deployed{Colors.END}")

    def monitor(self):
        print(f"\n{Colors.YELLOW}[*] Starting honeypot monitor...{Colors.END}")
        print(f"{Colors.GRAY}[i] Press Ctrl+C to stop\n{Colors.END}")

        try:
            while True:
                for filepath, baseline_time in self.baseline.items():
                    if os.path.exists(filepath):
                        current_atime = os.path.getatime(filepath)
                        if current_atime != baseline_time:
                            self.send_alert(filepath, baseline_time, current_atime)
                            self.baseline[filepath] = current_atime

                print(f"{Colors.GRAY}[{datetime.now().strftime('%H:%M:%S')}] Honeypot Monitor active{Colors.END}")
                time.sleep(5)

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Honeypot Monitor stopped{Colors.END}")

    def send_alert(self, filepath, old_time, new_time):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print(f"\n{Colors.RED}!!! HONEYPOT ACCESSED !!!{Colors.END}")
        print(f"{Colors.RED}Time: {timestamp}{Colors.END}")
        print(f"{Colors.RED}Severity: CRITICAL{Colors.END}")
        print(f"{Colors.RED}File: {filepath}{Colors.END}")
        print(f"{Colors.RED}Old Access: {datetime.fromtimestamp(old_time)}{Colors.END}")
        print(f"{Colors.RED}New Access: {datetime.fromtimestamp(new_time)}{Colors.END}")
        print(f"{Colors.RED}Action: Investigate immediately - attacker reconnaissance detected{Colors.END}\n")

        with open(f"{ALERT_DIR}/honeypot_{datetime.now().strftime('%Y%m%d')}.log", 'a') as f:
            f.write(f"\n!!! HONEYPOT ACCESSED !!!\n")
            f.write(f"Time: {timestamp}\n")
            f.write(f"File: {filepath}\n")
            f.write(f"Severity: CRITICAL\n---\n")

        incident = {
            'incident_id': f"HONEY-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'timestamp': timestamp,
            'file': filepath,
            'severity': 'CRITICAL',
            'mitre_id': 'T1003'
        }

        with open(f"{REPORT_DIR}/{incident['incident_id']}.json", 'w') as f:
            json.dump(incident, f, indent=2)

if __name__ == '__main__':
    honeypot = LinuxHoneypot()
    honeypot.monitor()
