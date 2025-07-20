#!/bin/bash
set -e
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo "AuditForge setup complete. Activate with: source venv/bin/activate"
echo "To run: sudo -E PYTHONPATH=AuditForge python3 AuditForge/src/main.py" 