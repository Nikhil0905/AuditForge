import os
import json
from datetime import datetime
import socket
from utils.logger import info, warning, error
try:
    from jinja2 import Template
    import plotly.graph_objs as go
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

class ReportGenerator:
    def __init__(self, report_dir=None):
        if report_dir is None:
            # Always save in the AuditForge/reports/ folder inside the project root
            project_root = os.path.dirname(os.path.abspath(__file__))
            report_dir = os.path.join(project_root, '..', 'reports')
            report_dir = os.path.abspath(report_dir)
        self.findings = []  # List of dicts: {'category', 'description', 'status'}
        self.cis_score = None
        self.cis_breakdown = None
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.host = socket.gethostname()
        self.report_dir = report_dir
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)

    def add_finding(self, category, description, status):
        self.findings.append({'category': category, 'description': description, 'status': status})

    def set_cis_score(self, score, breakdown):
        self.cis_score = score
        self.cis_breakdown = breakdown

    def _get_report_name(self, ext):
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        return os.path.join(self.report_dir, f'audit_report_{ts}.{ext}')

    def generate_txt(self):
        lines = [f'AuditForge Report - {self.timestamp} (Host: {self.host})', '']
        if self.cis_score is not None:
            lines.append(f'CIS Benchmark Score: {self.cis_score} ({self.cis_breakdown})\n')
        for f in self.findings:
            status = {'PASS': '✅', 'WARN': '⚠️', 'FAIL': '❌'}.get(f['status'], f['status'])
            lines.append(f"[{f['category']}] {status} {f['description']}")
        path = self._get_report_name('txt')
        with open(path, 'w') as f:
            f.write('\n'.join(lines))
        info(f'TXT report generated: {path}')
        return path

    def generate_json(self):
        data = {
            'timestamp': self.timestamp,
            'host': self.host,
            'cis_score': self.cis_score,
            'cis_breakdown': self.cis_breakdown,
            'findings': self.findings
        }
        path = self._get_report_name('json')
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        info(f'JSON report generated: {path}')
        return path

    def generate_html(self):
        if not JINJA2_AVAILABLE:
            warning('Jinja2/Plotly not available, skipping HTML report.')
            return None
        template_str = '''
        <html><head><title>AuditForge Report</title></head><body>
        <h1>AuditForge Report</h1>
        <p><b>Timestamp:</b> {{ timestamp }}<br><b>Host:</b> {{ host }}</p>
        <h2>CIS Benchmark Score: {{ cis_score }}</h2>
        <ul>
        {% for cat, score in cis_breakdown.items() %}
            <li>{{ cat }}: {{ score }}%</li>
        {% endfor %}
        </ul>
        <h2>Findings</h2>
        <table border="1"><tr><th>Category</th><th>Status</th><th>Description</th></tr>
        {% for f in findings %}
            <tr><td>{{ f.category }}</td><td>{{ f.status }}</td><td>{{ f.description }}</td></tr>
        {% endfor %}
        </table>
        </body></html>
        '''
        template = Template(template_str)
        html = template.render(
            timestamp=self.timestamp,
            host=self.host,
            cis_score=self.cis_score,
            cis_breakdown=self.cis_breakdown or {},
            findings=self.findings
        )
        path = self._get_report_name('html')
        with open(path, 'w') as f:
            f.write(html)
        info(f'HTML report generated: {path}')
        return path

    def generate_all(self):
        self.generate_txt()
        self.generate_json()
        self.generate_html()

if __name__ == "__main__":
    rg = ReportGenerator()
    rg.add_finding('Network', 'Firewall enabled', 'PASS')
    rg.add_finding('Service', 'Legacy service detected', 'FAIL')
    rg.add_finding('FileSystem', '/etc/shadow permissions', 'WARN')
    rg.set_cis_score(75.0, {'Network': 100, 'Service': 50, 'FileSystem': 75, 'User': 75})
    rg.generate_all() 