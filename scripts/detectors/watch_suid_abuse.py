#!/usr/bin/env python3
# watch_suid_abuse.py
# SUID Binary Abuse Detector
# Monitors for new or modified SUID binaries (T1548.001)

import os
import time
import json
from datetime import datetime

PROJECT_ROOT = "/opt/PrivEscDetection"
LOG_DIR = f"{PROJECT_ROOT}/logs/suid"
ALERT_DIR = f"{PROJECT_ROOT}/logs/alerts"
REPORT_DIR = f"{PROJECT_ROOT}/reports/incidents"

class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'
    END = '\033[0m'

class SUIDMonitor:
    def __init__(self):
        self.baseline = {}
        self.known_suid = set()
        self.record_baseline()

    def record_baseline(self):
        """Record baseline of all SUID binaries"""
        print(f"{Colors.CYAN}[*] Recording SUID baseline...{Colors.END}")

        for root, dirs, files in os.walk('/'):
            # Skip proc/sys/dev to avoid errors
            dirs[:] = [d for d in dirs if d not in ['proc', 'sys', 'dev', 'run']]

            for file in files:
                filepath = os.path.join(root, file)
                try:
                    mode = os.stat(filepath).st_mode
                    if mode & 0o4000:  # SUID bit set
                        self.known_suid.add(filepath)
                        self.baseline[filepath] = {
                            'mode': oct(mode),
                            'size': os.path.getsize(filepath),
                            'mtime': os.path.getmtime(filepath)
                        }
                        print(f"  {Colors.GRAY}Baseline [SUID]: {filepath}{Colors.END}")
                except (PermissionError, OSError, FileNotFoundError):
                    continue

        print(f"{Colors.GREEN}[+] Baseline: {len(self.known_suid)} SUID binaries recorded{Colors.END}")

    def check_new_suid(self):
        """Detect newly created SUID binaries"""
        current_suid = set()

        for root, dirs, files in os.walk('/'):
            dirs[:] = [d for d in dirs if d not in ['proc', 'sys', 'dev', 'run']]

            for file in files:
                filepath = os.path.join(root, file)
                try:
                    mode = os.stat(filepath).st_mode
                    if mode & 0o4000:
                        current_suid.add(filepath)
                except (PermissionError, OSError, FileNotFoundError):
                    continue

        new_suid = current_suid - self.known_suid
        return new_suid

    def check_modified_suid(self):
        """Detect changes to existing SUID binaries"""
        modified = []

        for filepath in self.known_suid:
            try:
                current_mode = os.stat(filepath).st_mode
                current_size = os.path.getsize(filepath)
                current_mtime = os.path.getmtime(filepath)

                baseline = self.baseline[filepath]

                if (oct(current_mode) != baseline['mode'] or 
                    current_size != baseline['size'] or
                    current_mtime != baseline['mtime']):
                    modified.append(filepath)
            except (PermissionError, OSError, FileNotFoundError):
                continue

        return modified

    def send_alert(self, alert_type, filepath, details):
        """Generate alert and incident report"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        alert_msg = f"""
{Colors.RED}!!! SUID ABUSE DETECTED !!!{Colors.END}
{Colors.RED}Time: {timestamp}{Colors.END}
{Colors.RED}Type: {alert_type}{Colors.END}
{Colors.RED}File: {filepath}{Colors.END}
{Colors.RED}Details: {details}{Colors.END}
{Colors.RED}Severity: CRITICAL{Colors.END}
{Colors.RED}MITRE: T1548.001{Colors.END}
"""
        print(alert_msg)

        # Log alert
        with open(f"{ALERT_DIR}/suid_{datetime.now().strftime('%Y%m%d')}.log", 'a') as f:
            f.write(f"""
!!! SUID ABUSE DETECTED !!!
Time: {timestamp}
Type: {alert_type}
File: {filepath}
Details: {details}
Severity: CRITICAL
MITRE: T1548.001
---
""")

        # Generate JSON incident
        incident = {
            'incident_id': f"SUID-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'timestamp': timestamp,
            'alert_type': alert_type,
            'file': filepath,
            'details': details,
            'severity': 'CRITICAL',
            'mitre_id': 'T1548.001'
        }

        with open(f"{REPORT_DIR}/{incident['incident_id']}.json", 'w') as f:
            json.dump(incident, f, indent=2)

    def monitor(self):
        """Main monitoring loop"""
        print(f"{Colors.YELLOW}[*] Monitoring for SUID abuse...{Colors.END}")
        print(f"{Colors.GRAY}[i] Press Ctrl+C to stop\n{Colors.END}")

        alert_count = 0

        try:
            while True:
                # Check for new SUID binaries
                new = self.check_new_suid()
                for filepath in new:
                    alert_count += 1
                    self.send_alert('NEW_SUID_BINARY', filepath, 
                                    'SUID bit set on previously non-SUID file')

                # Check for modified SUID binaries
                modified = self.check_modified_suid()
                for filepath in modified:
                    alert_count += 1
                    self.send_alert('MODIFIED_SUID_BINARY', filepath,
                                    'Existing SUID binary was modified')

                status_color = Colors.RED if alert_count > 0 else Colors.GREEN
                print(f"{Colors.GRAY}[{datetime.now().strftime('%H:%M:%S')}] SUID Monitor active | "
                      f"Baseline: {len(self.known_suid)} | "
                      f"Alerts: {status_color}{alert_count}{Colors.END}")

                time.sleep(5)

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] SUID Monitor stopped{Colors.END}")

if __name__ == '__main__':
    monitor = SUIDMonitor()
    monitor.monitor()
