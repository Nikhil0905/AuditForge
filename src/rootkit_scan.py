import subprocess
import shutil
from utils.logger import info, warning, error

def run_chkrootkit():
    if shutil.which('chkrootkit'):
        output = subprocess.getoutput('sudo chkrootkit')
        info('chkrootkit output:\n' + output)
        return output
    else:
        warning('chkrootkit not found.')
        return None

def run_rkhunter():
    if shutil.which('rkhunter'):
        output = subprocess.getoutput('sudo rkhunter --check --sk')
        info('rkhunter output:\n' + output)
        return output
    else:
        warning('rkhunter not found.')
        return None

def manual_checks():
    # Suspicious binaries
    suspicious = subprocess.getoutput('find / -type f -perm -4000 2>/dev/null | grep -E "(nc|netcat|nmap|hydra|john|nikto|suidperl)"')
    if suspicious:
        warning('Suspicious SUID binaries found:\n' + suspicious)
    else:
        info('No suspicious SUID binaries found.')
    # Hidden processes
    hidden = subprocess.getoutput('ps aux | grep "\[.*\]"')
    if hidden:
        warning('Hidden processes detected:\n' + hidden)
    else:
        info('No hidden processes detected.')
    # Kernel module anomalies
    lsmod = subprocess.getoutput('lsmod')
    if 'rootkit' in lsmod.lower():
        warning('Potential rootkit kernel module detected!')
    else:
        info('No suspicious kernel modules detected.')

def run_all():
    run_chkrootkit()
    run_rkhunter()
    manual_checks()

if __name__ == "__main__":
    run_all() 