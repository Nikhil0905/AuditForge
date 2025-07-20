# AuditForge

[![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview
AuditForge is a script-based auditing solution for assessing and improving the security configuration of Linux systems. It evaluates compliance with CIS Benchmarks and provides actionable hardening recommendations.

## Features
- Audit firewall rules, running services, SSH configuration, file permissions, and rootkit indicators
- Generate CIS Benchmark-based security score
- Output reports in TXT, HTML, or JSON format
- Modular and extensible
- Dockerized for portability

## Requirements
- Python 3.7+
- sudo/root privileges
- Linux (Ubuntu, Debian, CentOS, etc.)
- (Optional) Docker
- (Optional) Jinja2 for HTML reports

## Setup
```bash
# Clone the repo and enter the directory
cd AuditForge
# Run setup script
bash setup.sh
# Activate the virtual environment
source venv/bin/activate
```

## Usage
Run the audit (from the project root):
```bash
sudo -E PYTHONPATH=AuditForge python3 AuditForge/src/main.py
```

## Folder Structure
- `AuditForge/src/` - Audit modules and main script
- `AuditForge/reports/` - Generated reports
- `AuditForge/utils/` - Utility scripts (e.g., logger)

## Output
- Human-readable `.txt` report
- Structured `.json` report
- (Optional) `.html` dashboard (if Jinja2 is installed)
- Log files in `AuditForge/reports/`

## References
- [CIS Benchmark](https://www.cisecurity.org/)
- [chkrootkit](http://www.chkrootkit.org/)
- [psutil](https://pypi.org/project/psutil/)
- [Docker](https://docs.docker.com/)

## License
MIT 