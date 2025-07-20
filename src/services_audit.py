import subprocess
from utils.logger import info, warning, error

# Essential services allowlist (can be extended)
ALLOWLIST = [
    'sshd', 'systemd', 'cron', 'rsyslog', 'dbus', 'network', 'NetworkManager', 'firewalld', 'ufw'
]
# Legacy/insecure services
LEGACY_SERVICES = ['telnet', 'rsh', 'rlogin', 'rexec', 'xinetd', 'vsftpd', 'wu-ftpd']

def list_active_services():
    output = subprocess.getoutput('systemctl list-units --type=service --state=running --no-pager')
    info('Active services listed.')
    return output

def cross_check_services(active_services_output):
    flagged = []
    for line in active_services_output.splitlines():
        for service in LEGACY_SERVICES:
            if service in line:
                flagged.append((service, 'legacy/insecure'))
        found = False
        for allowed in ALLOWLIST:
            if allowed in line:
                found = True
                break
        if not found and '.service' in line:
            service_name = line.split()[0]
            flagged.append((service_name, 'not in allowlist'))
    for service, reason in flagged:
        warning(f'Service flagged: {service} ({reason})')
    if not flagged:
        info('No unnecessary or insecure services detected.')
    return flagged

if __name__ == "__main__":
    active = list_active_services()
    cross_check_services(active) 