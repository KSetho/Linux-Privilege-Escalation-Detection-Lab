#!/usr/bin/env python3
# start_linux_detection.py
# Unified Linux Privilege Escalation Detection Dashboard
# Launches all monitors and displays real-time status

import os
import time
import json
import subprocess
from datetime import datetime

PROJECT_ROOT = "/opt/PrivEscDetection"
LOG_DIR = f"{PROJECT_ROOT}/logs"
ALERT_DIR = f"{LOG_DIR}/alerts"
REPORT_DIR = f"{PROJECT_ROOT}/reports/incidents"

class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'
    WHITE = '\033[97m'
    END = '\033[0m'

class LinuxDetectionDashboard:
    def __init__(self):
        self.processes = {}

    def start_monitor(self, name, script_path):
        """Start a detector as background process"""
        print(f"{Colors.CYAN}[*] Starting {name}...{Colors.END}")
        process = subprocess.Popen(
            ['python3', script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        self.processes[name] = process
        print(f"{Colors.GREEN}[+] {name} started (PID: {process.pid}){Colors.END}")

    def check_process_status(self, name):
        """Check if a monitor process is running"""
        process = self.processes.get(name)
        if process and process.poll() is None:
            return "Running"
        return "Stopped"

    def count_alerts(self):
        """Count alerts from all log files"""
        alert_counts = {}
        total = 0

        if os.path.exists(ALERT_DIR):
            for log_file in os.listdir(ALERT_DIR):
                if log_file.endswith('.log'):
                    filepath = os.path.join(ALERT_DIR, log_file)
                    with open(filepath, 'r') as f:
                        lines = f.read().strip().split('\n')
                        count = len([l for l in lines if '!!!' in l])
                        alert_counts[log_file] = count
                        total += count

        return alert_counts, total

    def get_recent_incidents(self, count=5):
        """Get recent JSON incident reports"""
        incidents = []

        if os.path.exists(REPORT_DIR):
            for filename in os.listdir(REPORT_DIR):
                if filename.endswith('.json'):
                    filepath = os.path.join(REPORT_DIR, filename)
                    mtime = os.path.getmtime(filepath)
                    incidents.append((mtime, filepath))

        incidents.sort(reverse=True)
        recent = []

        for _, filepath in incidents[:count]:
            with open(filepath, 'r') as f:
                data = json.load(f)
                recent.append(data)

        return recent

    def display(self):
        """Render dashboard"""
        os.system('clear')

        print(f"{Colors.CYAN}{'=' * 60}{Colors.END}")
        print(f"{Colors.CYAN}  LINUX PRIVILEGE ESCALATION DETECTION DASHBOARD{Colors.END}")
        print(f"{Colors.CYAN}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.END}\n")

        # Monitor Status
        print(f"{Colors.GRAY}-- MONITOR STATUS --{Colors.END}")
        for name in ['SUID Monitor', 'Cron Monitor', 'Honeypot Monitor']:
            status = self.check_process_status(name)
            color = Colors.GREEN if status == "Running" else Colors.RED
            print(f"  {name}: {color}{status}{Colors.END}")

        # Alerts
        print(f"\n{Colors.GRAY}-- ALERTS TODAY --{Colors.END}")
        alert_counts, total = self.count_alerts()
        for log_file, count in alert_counts.items():
            if count > 0:
                print(f"  {log_file}: {Colors.YELLOW}{count} alerts{Colors.END}")

        color = Colors.RED if total > 0 else Colors.GREEN
        print(f"  Total: {color}{total} alert(s){Colors.END}")

        # Recent Incidents
        print(f"\n{Colors.GRAY}-- RECENT INCIDENTS --{Colors.END}")
        incidents = self.get_recent_incidents()
        if incidents:
            for inc in incidents:
                print(f"  [{Colors.YELLOW}{inc['severity']}{Colors.END}] {inc['alert_type']}")
        else:
            print(f"  {Colors.GREEN}No incidents yet{Colors.END}")

        # System Status
        print(f"\n{Colors.GRAY}-- SYSTEM STATUS --{Colors.END}")
        try:
            with open('/etc/passwd', 'r') as f:
                root_users = [l for l in f if l.startswith('root:')]
            print(f"  {Colors.WHITE}Root accounts: {len(root_users)}{Colors.END}")
        except:
            pass

        try:
            cron_count = len([f for f in os.listdir('/etc/cron.d') if os.path.isfile(f"/etc/cron.d/{f}")])
            print(f"  {Colors.WHITE}Cron jobs: {cron_count}{Colors.END}")
        except:
            pass

        try:
            result = subprocess.run(['find', '/', '-perm', '-4000', '-type', 'f'], 
                                    capture_output=True, text=True)
            suid_count = len([l for l in result.stdout.split('\n') if l])
            print(f"  {Colors.WHITE}SUID binaries: {suid_count}{Colors.END}")
        except:
            pass

        # Quick commands
        print(f"\n{Colors.GRAY}-- QUICK COMMANDS --{Colors.END}")
        print(f"  {Colors.GRAY}Simulate attacks: python3 scripts/simulation/simulate_linux_privesc.py{Colors.END}")
        print(f"  {Colors.GRAY}Run Assessment:   python3 scripts/assessment/assess_linux_privesc.py{Colors.END}")
        print(f"\n{Colors.GRAY}Refreshing every 15 seconds | Ctrl+C to stop{Colors.END}")

    def run(self):
        """Main loop"""
        print(f"{Colors.CYAN}[*] Starting Linux detection components...{Colors.END}")

        self.start_monitor('SUID Monitor', f'{PROJECT_ROOT}/scripts/detectors/watch_suid_abuse.py')
        self.start_monitor('Cron Monitor', f'{PROJECT_ROOT}/scripts/detectors/watch_cron_abuse.py')
        self.start_monitor('Honeypot Monitor', f'{PROJECT_ROOT}/scripts/detectors/deploy_honeypot_linux.py')

        time.sleep(5)
        print(f"{Colors.GREEN}[+] All monitors active{Colors.END}\n")

        try:
            while True:
                self.display()
                time.sleep(15)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Stopping all monitors...{Colors.END}")
            for name, process in self.processes.items():
                process.terminate()
            print(f"{Colors.GREEN}[+] Dashboard stopped{Colors.END}")

if __name__ == '__main__':
    dashboard = LinuxDetectionDashboard()
    dashboard.run()
