#!/usr/bin/env python3
# watch_cron_abuse.py
# Cron Job Abuse Detector
# Monitors for new/modified cron jobs (T1053.003)

import os
import time
import hashlib
import json
from datetime import datetime

PROJECT_ROOT = "/opt/PrivEscDetection"
LOG_DIR = f"{PROJECT_ROOT}/logs/cron"
ALERT_DIR = f"{PROJECT_ROOT}/logs/alerts"
REPORT_DIR = f"{PROJECT_ROOT}/reports/incidents"

CRON_PATHS = [
    '/etc/crontab',
    '/etc/cron.d',
    '/etc/cron.daily',
    '/etc/cron.hourly',
    '/etc/cron.weekly',
    '/etc/cron.monthly',
    '/var/spool/cron/crontabs'
]

class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'
    END = '\033[0m'

class CronMonitor:
    def __init__(self):
        self.baseline = {}
        self.record_baseline()

    def get_cron_files(self):
        files = {}
        for path in CRON_PATHS:
            if os.path.isfile(path):
                try:
                    with open(path, 'r') as f:
                        files[path] = f.read()
                except PermissionError:
                    continue
            elif os.path.isdir(path):
                for entry in os.listdir(path):
                    fullpath = os.path.join(path, entry)
                    if os.path.isfile(fullpath):
                        try:
                            with open(fullpath, 'r') as f:
                                files[fullpath] = f.read()
                        except PermissionError:
                            continue
        return files

    def record_baseline(self):
        print(f"{Colors.CYAN}[*] Recording cron baseline...{Colors.END}")
        files = self.get_cron_files()
        for path, content in files.items():
            self.baseline[path] = hashlib.sha256(content.encode()).hexdigest()
            print(f"  {Colors.GRAY}Baseline: {path}{Colors.END}")
        print(f"{Colors.GREEN}[+] Baseline: {len(self.baseline)} cron files recorded{Colors.END}")

    def check_changes(self):
        current = self.get_cron_files()
        alerts = []

        for path in current:
            if path not in self.baseline:
                content = current[path]
                if 'root' in content or 'sudo' in content:
                    alerts.append({'type': 'NEW_CRON_ROOT', 'path': path, 'severity': 'CRITICAL'})
                else:
                    alerts.append({'type': 'NEW_CRON_FILE', 'path': path, 'severity': 'HIGH'})

        for path, content in current.items():
            if path in self.baseline:
                current_hash = hashlib.sha256(content.encode()).hexdigest()
                if current_hash != self.baseline[path]:
                    if 'root' in content or 'sudo' in content:
                        alerts.append({'type': 'MODIFIED_CRON_ROOT', 'path': path, 'severity': 'CRITICAL'})
                    else:
                        alerts.append({'type': 'MODIFIED_CRON', 'path': path, 'severity': 'HIGH'})

        return alerts

    def send_alert(self, alert):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        severity_color = Colors.RED if alert['severity'] == 'CRITICAL' else Colors.YELLOW

        print(f"\n{severity_color}!!! CRON ESCALATION DETECTED !!!{Colors.END}")
        print(f"{severity_color}Time: {timestamp}{Colors.END}")
        print(f"{severity_color}Type: {alert['type']}{Colors.END}")
        print(f"{severity_color}File: {alert['path']}{Colors.END}")
        print(f"{severity_color}Severity: {alert['severity']}{Colors.END}")
        print(f"{severity_color}MITRE: T1053.003{Colors.END}\n")

        with open(f"{ALERT_DIR}/cron_{datetime.now().strftime('%Y%m%d')}.log", 'a') as f:
            f.write(f"\n!!! CRON ESCALATION DETECTED !!!\n")
            f.write(f"Time: {timestamp}\n")
            f.write(f"Type: {alert['type']}\n")
            f.write(f"File: {alert['path']}\n")
            f.write(f"Severity: {alert['severity']}\n")
            f.write(f"MITRE: T1053.003\n---\n")

        incident = {
            'incident_id': f"CRON-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'timestamp': timestamp,
            'alert_type': alert['type'],
            'file': alert['path'],
            'severity': alert['severity'],
            'mitre_id': 'T1053.003'
        }

        with open(f"{REPORT_DIR}/{incident['incident_id']}.json", 'w') as f:
            json.dump(incident, f, indent=2)

    def monitor(self):
        print(f"{Colors.YELLOW}[*] Monitoring for cron abuse...{Colors.END}")
        print(f"{Colors.GRAY}[i] Press Ctrl+C to stop\n{Colors.END}")

        alert_count = 0

        try:
            while True:
                alerts = self.check_changes()
                for alert in alerts:
                    alert_count += 1
                    self.send_alert(alert)

                status_color = Colors.RED if alert_count > 0 else Colors.GREEN
                print(f"{Colors.GRAY}[{datetime.now().strftime('%H:%M:%S')}] Cron Monitor active | "
                      f"Files: {len(self.baseline)} | "
                      f"Alerts: {status_color}{alert_count}{Colors.END}")

                time.sleep(5)

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Cron Monitor stopped{Colors.END}")

if __name__ == '__main__':
    monitor = CronMonitor()
    monitor.monitor()
