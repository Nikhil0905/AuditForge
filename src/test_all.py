import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../utils')))
from utils.logger import info, warning, error

print("\n===== AuditForge Module Test =====\n")
info("===== AuditForge Module Test Start =====")

# Firewall Audit
print("[1] Firewall & Network Audit")
try:
    import firewall_audit
    fw, fw_status = firewall_audit.check_firewall_status()
    open_ports = firewall_audit.list_open_ports()
    firewall_audit.detect_insecure_ports(open_ports)
    print("  - Firewall audit completed.")
except Exception as e:
    error(f"Firewall audit error: {e}")
    print(f"  - Firewall audit error: {e}")

# Services Audit
print("[2] Unused Services Audit")
try:
    import services_audit
    active = services_audit.list_active_services()
    services_audit.cross_check_services(active)
    print("  - Services audit completed.")
except Exception as e:
    error(f"Services audit error: {e}")
    print(f"  - Services audit error: {e}")

# SSH Config Audit
print("[3] SSH Configuration Audit")
try:
    import ssh_config_audit
    findings = ssh_config_audit.parse_ssh_config()
    ssh_config_audit.highlight_insecure(findings)
    print("  - SSH config audit completed.")
except Exception as e:
    error(f"SSH config audit error: {e}")
    print(f"  - SSH config audit error: {e}")

# File Permissions Audit
print("[4] File Permission Check")
try:
    import file_permissions
    file_permissions.check_permissions()
    print("  - File permissions audit completed.")
except Exception as e:
    error(f"File permissions audit error: {e}")
    print(f"  - File permissions audit error: {e}")

# Rootkit Scan
print("[5] Rootkit & Malware Check")
try:
    import rootkit_scan
    rootkit_scan.run_all()
    print("  - Rootkit scan completed.")
except Exception as e:
    error(f"Rootkit scan error: {e}")
    print(f"  - Rootkit scan error: {e}")

print("\n===== Module Test Complete. Check logs in 'reports/' for details. =====\n")
info("===== AuditForge Module Test Complete =====") 