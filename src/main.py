from utils.logger import info, warning, error
from report_generator import ReportGenerator
from cis_score import CISScorer
import firewall_audit
import services_audit
import ssh_config_audit
import file_permissions
import rootkit_scan

# Initialize report and scoring
report = ReportGenerator()
scorer = CISScorer()

info('Starting AuditForge full system audit...')

# 1. Firewall & Network Audit
fw_type, fw_status = firewall_audit.check_firewall_status()
if fw_type and 'inactive' not in fw_status.lower():
    report.add_finding('Network', f'{fw_type} firewall enabled', 'PASS')
    scorer.add_check('Network', f'{fw_type} firewall enabled', True)
else:
    report.add_finding('Network', 'No active firewall detected', 'FAIL')
    scorer.add_check('Network', 'No active firewall detected', False)
open_ports = firewall_audit.list_open_ports()
insecure_ports = firewall_audit.detect_insecure_ports(open_ports)
if insecure_ports:
    report.add_finding('Network', 'Insecure/legacy open ports: ' + ', '.join(insecure_ports), 'FAIL')
    scorer.add_check('Network', 'No insecure/legacy open ports', False)
else:
    report.add_finding('Network', 'No insecure/legacy open ports', 'PASS')
    scorer.add_check('Network', 'No insecure/legacy open ports', True)

# 2. Unused Services Audit
active_services = services_audit.list_active_services()
flagged_services = services_audit.cross_check_services(active_services)
if flagged_services:
    for service, reason in flagged_services:
        report.add_finding('Service', f'{service} ({reason})', 'FAIL')
        scorer.add_check('Service', f'{service} ({reason})', False)
else:
    report.add_finding('Service', 'No unnecessary or insecure services detected', 'PASS')
    scorer.add_check('Service', 'No unnecessary or insecure services detected', True)

# 3. SSH Configuration Audit
ssh_findings = ssh_config_audit.parse_ssh_config()
for key, value in ssh_findings.items():
    if value == 'NOT SET':
        report.add_finding('User', f'{key} not set in sshd_config', 'WARN')
        scorer.add_check('User', f'{key} not set in sshd_config', False)
    elif key == 'PermitRootLogin' and value == 'no':
        report.add_finding('User', 'SSH root login disabled', 'PASS')
        scorer.add_check('User', 'SSH root login disabled', True)
    elif key == 'PasswordAuthentication' and value == 'no':
        report.add_finding('User', 'SSH password authentication disabled', 'PASS')
        scorer.add_check('User', 'SSH password authentication disabled', True)
    elif key == 'Protocol' and value == '2':
        report.add_finding('User', 'SSH protocol set to 2', 'PASS')
        scorer.add_check('User', 'SSH protocol set to 2', True)
    elif key == 'MaxAuthTries' and value == '4':
        report.add_finding('User', 'SSH MaxAuthTries set to 4', 'PASS')
        scorer.add_check('User', 'SSH MaxAuthTries set to 4', True)
    elif key == 'Port' and value != '22':
        report.add_finding('User', f'SSH running on non-default port {value}', 'PASS')
        scorer.add_check('User', f'SSH running on non-default port {value}', True)
    else:
        report.add_finding('User', f'SSH setting: {key} = {value}', 'WARN')
        scorer.add_check('User', f'SSH setting: {key} = {value}', False)

# 4. File Permission Check
import os
import stat
FILES = {'/etc/passwd': 0o644, '/etc/shadow': 0o600}
for path, expected_mode in FILES.items():
    try:
        st = os.stat(path)
        actual_mode = stat.S_IMODE(st.st_mode)
        if actual_mode != expected_mode:
            report.add_finding('FileSystem', f'{path} permissions {oct(actual_mode)} (expected {oct(expected_mode)})', 'WARN')
            scorer.add_check('FileSystem', f'{path} permissions', False)
        else:
            report.add_finding('FileSystem', f'{path} permissions OK: {oct(actual_mode)}', 'PASS')
            scorer.add_check('FileSystem', f'{path} permissions', True)
        if st.st_uid != 0:
            report.add_finding('FileSystem', f'{path} not owned by root (uid={st.st_uid})', 'WARN')
            scorer.add_check('FileSystem', f'{path} ownership', False)
        else:
            report.add_finding('FileSystem', f'{path} ownership OK (root)', 'PASS')
            scorer.add_check('FileSystem', f'{path} ownership', True)
    except Exception as e:
        report.add_finding('FileSystem', f'Error checking {path}: {e}', 'FAIL')
        scorer.add_check('FileSystem', f'Error checking {path}', False)

# 5. Rootkit & Malware Checks
rootkit_scan.run_all()  # Logging only, not scored for now

# CIS Score
score, breakdown = scorer.score()
report.set_cis_score(score, breakdown)

# Generate Reports
report.generate_all()

info('AuditForge audit complete. Reports generated in AuditForge/reports/.') 