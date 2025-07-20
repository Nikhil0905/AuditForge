import os
import stat
from utils.logger import info, warning, error

FILES = {
    '/etc/passwd': 0o644,
    '/etc/shadow': 0o600,
}

def check_permissions():
    for path, expected_mode in FILES.items():
        try:
            st = os.stat(path)
            actual_mode = stat.S_IMODE(st.st_mode)
            if actual_mode != expected_mode:
                warning(f'{path} permissions {oct(actual_mode)} (expected {oct(expected_mode)})')
            else:
                info(f'{path} permissions OK: {oct(actual_mode)}')
            if st.st_uid != 0:
                warning(f'{path} not owned by root (uid={st.st_uid})')
            else:
                info(f'{path} ownership OK (root)')
        except Exception as e:
            error(f'Error checking {path}: {e}')

if __name__ == "__main__":
    check_permissions() 