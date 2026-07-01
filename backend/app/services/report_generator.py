from typing import List, Dict, Any
import json
from datetime import datetime
import os
from jinja2 import Template

class ReportGenerator:
    """Generate security reports in various formats"""
    
    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
    
    def generate_html_report(self, scan_result: Dict[str, Any]) -> str:
        """Generate HTML report"""
        template_data = self._prepare_template_data(scan_result)
        
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .score { font-size: 48px; font-weight: bold; }
        .risk-critical { color: #e74c3c; }
        .risk-high { color: #e67e22; }
        .risk-medium { color: #f1c40f; }
        .risk-low { color: #2ecc71; }
        .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .severity-critical { border-left: 5px solid #e74c3c; }
        .severity-high { border-left: 5px solid #e67e22; }
        .severity-medium { border-left: 5px solid #f1c40f; }
        .severity-low { border-left: 5px solid #2ecc71; }
        .category { margin: 20px 0; }
        .category-score { font-size: 24px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SecureCode AI Security Report</h1>
        <p>Generated: {{ timestamp }}</p>
        <p>Scan ID: {{ scan_id }}</p>
    </div>
    
    <h2>Security Score: <span class="score risk-{{ risk_level }}">{{ overall_score }}/100</span></h2>
    <p>Risk Level: <strong>{{ risk_level.upper() }}</strong></p>
    
    <h3>Category Scores</h3>
    {% for category, score in category_scores.items() %}
    <div class="category">
        <span>{{ category.title() }}: </span>
        <span class="category-score">{{ score }}/100</span>
    </div>
    {% endfor %}
    
    <h3>Vulnerability Summary</h3>
    <table>
        <tr>
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
            <th>Total</th>
        </tr>
        <tr>
            <td>{{ summary.critical|default(0) }}</td>
            <td>{{ summary.high|default(0) }}</td>
            <td>{{ summary.medium|default(0) }}</td>
            <td>{{ summary.low|default(0) }}</td>
            <td>{{ summary.total|default(0) }}</td>
        </tr>
    </table>
    
    <h3>Recommendations</h3>
    <ul>
    {% for rec in recommendations %}
        <li>{{ rec }}</li>
    {% endfor %}
    </ul>
    
    <h3>Vulnerabilities ({{ vulnerabilities|length }})</h3>
    {% for vuln in vulnerabilities %}
    <div class="vulnerability severity-{{ vuln.severity }}">
        <h4>{{ vuln.type }}</h4>
        <p><strong>CWE:</strong> {{ vuln.cwe_id }}</p>
        <p><strong>Severity:</strong> {{ vuln.severity }}</p>
        <p><strong>Confidence:</strong> {{ vuln.confidence }}</p>
        <p><strong>File:</strong> {{ vuln.file_path }} (line {{ vuln.line_number }})</p>
        <p><strong>Explanation:</strong> {{ vuln.explanation }}</p>
        {% if vuln.code_snippet %}
        <pre>{{ vuln.code_snippet }}</pre>
        {% endif %}
    </div>
    {% endfor %}
</body>
</html>
"""
        
        return Template(html_template).render(**template_data)
    
    def generate_json_report(self, scan_result: Dict[str, Any]) -> str:
        """Generate JSON report"""
        return json.dumps(scan_result, indent=2, default=str)
    
    def generate_markdown_report(self, scan_result: Dict[str, Any]) -> str:
        """Generate Markdown report"""
        template_data = self._prepare_template_data(scan_result)
        
        md_template = """
# Security Scan Report

**Generated:** {{ timestamp }}
**Scan ID:** {{ scan_id }}

## Overall Security Score: {{ overall_score }}/100
**Risk Level:** {{ risk_level.upper() }}

## Category Scores
{% for category, score in category_scores.items() %}
- **{{ category.title() }}:** {{ score }}/100
{% endfor %}

## Vulnerability Summary
| Severity | Count |
|----------|-------|
| Critical | {{ summary.critical|default(0) }} |
| High | {{ summary.high|default(0) }} |
| Medium | {{ summary.medium|default(0) }} |
| Low | {{ summary.low|default(0) }} |
| **Total** | **{{ summary.total|default(0) }}** |

## Recommendations
{% for rec in recommendations %}
- {{ rec }}
{% endfor %}

## Vulnerabilities ({{ vulnerabilities|length }})
{% for vuln in vulnerabilities %}
### {{ vuln.type }} ({{ vuln.severity.upper() }})
- **CWE:** {{ vuln.cwe_id }}
- **Confidence:** {{ vuln.confidence }}
- **File:** {{ vuln.file_path }}:{{ vuln.line_number }}
- **Explanation:** {{ vuln.explanation }}
{% if vuln.code_snippet %}
```
{{ vuln.code_snippet }}

```
{% endif %}
---
{% endfor %}
"""
        return Template(md_template).render(**template_data)
    
    def _prepare_template_data(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for templates"""
        security_score = scan_result.get('security_score', {})
        summary = scan_result.get('summary', {})
        
        if isinstance(summary, dict) and 'by_severity' in summary:
            severity_counts = summary.get('by_severity', {})
        else:
            severity_counts = summary
        
        return {
            'scan_id': scan_result.get('scan_id', 'unknown'),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'overall_score': security_score.get('overall', 0),
            'risk_level': security_score.get('risk_level', 'unknown'),
            'category_scores': security_score.get('category_scores', {}),
            'summary': {
                'total': len(scan_result.get('vulnerabilities', [])),
                'critical': severity_counts.get('critical', 0),
                'high': severity_counts.get('high', 0),
                'medium': severity_counts.get('medium', 0),
                'low': severity_counts.get('low', 0)
            },
            'recommendations': security_score.get('recommendations', []),
            'vulnerabilities': scan_result.get('vulnerabilities', [])
        }
    
    def save_report(self, scan_result: Dict[str, Any], format: str = 'html') -> str:
        """Save report to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"security_report_{timestamp}.{format}"
        
        if format == 'html':
            content = self.generate_html_report(scan_result)
        elif format == 'json':
            content = self.generate_json_report(scan_result)
        elif format == 'md':
            content = self.generate_markdown_report(scan_result)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        with open(filename, 'w') as f:
            f.write(content)
        
        return filename
