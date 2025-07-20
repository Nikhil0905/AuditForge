import re
from utils.logger import info, warning, error

SSH_CONFIG_PATH = '/etc/ssh/sshd_config'

# Settings to check and their secure values
CHECKS = {
    'PermitRootLogin': 'no',
    'PasswordAuthentication': 'no',
    'MaxAuthTries': '4',
    'Protocol': '2',
    'Port': '22',
}

INSECURE_DEFAULTS = {
    'PermitRootLogin': ['yes'],
    'PasswordAuthentication': ['yes'],
    'MaxAuthTries': ['6', '10'],
    'Protocol': ['1'],
    'Port': ['22'],  # 22 is default, flag for awareness
}

def parse_ssh_config():
    findings = {}
    try:
        with open(SSH_CONFIG_PATH, 'r') as f:
            lines = f.readlines()
        for key in CHECKS:
            for line in lines:
                if line.strip().startswith(key):
                    value = re.split(r'\s+', line.strip(), 1)[1]
                    findings[key] = value
                    break
            else:
                findings[key] = 'NOT SET'
    except Exception as e:
        error(f'Error reading {SSH_CONFIG_PATH}: {e}')
        return {}
    return findings

def highlight_insecure(findings):
    for key, value in findings.items():
        if value == 'NOT SET':
            warning(f'{key} not set in sshd_config.')
        elif key in INSECURE_DEFAULTS and value in INSECURE_DEFAULTS[key]:
            warning(f'Insecure/default SSH setting: {key} = {value}')
        else:
            info(f'SSH setting: {key} = {value}')

if __name__ == "__main__":
    findings = parse_ssh_config()
    highlight_insecure(findings) 