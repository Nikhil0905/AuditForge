import subprocess
import shutil
from utils.logger import info, warning, error

def check_firewall_status():
    if shutil.which('ufw'):
        status = subprocess.getoutput('sudo ufw status')
        info(f'UFW status:\n{status}')
        return 'ufw', status
    elif shutil.which('firewalld'):
        status = subprocess.getoutput('sudo firewall-cmd --state')
        info(f'firewalld status: {status}')
        return 'firewalld', status
    elif shutil.which('iptables'):
        status = subprocess.getoutput('sudo iptables -L')
        info(f'iptables rules:\n{status}')
        return 'iptables', status
    else:
        warning('No supported firewall found.')
        return None, 'No firewall found.'

def list_open_ports():
    if shutil.which('ss'):
        output = subprocess.getoutput('ss -tuln')
    elif shutil.which('netstat'):
        output = subprocess.getoutput('netstat -tuln')
    else:
        warning('Neither ss nor netstat found.')
        return ''
    info(f'Open ports:\n{output}')
    return output

def detect_insecure_ports(open_ports_output):
    insecure_ports = []
    for line in open_ports_output.splitlines():
        if any(port in line for port in [':23', ':21', ':69', ':111', ':512', ':513', ':514']):
            insecure_ports.append(line)
    if insecure_ports:
        warning(f'Insecure/legacy ports detected:\n' + '\n'.join(insecure_ports))
    else:
        info('No insecure ports detected.')
    return insecure_ports

if __name__ == "__main__":
    fw, fw_status = check_firewall_status()
    open_ports = list_open_ports()
    detect_insecure_ports(open_ports) 