import json
import subprocess
from typing import List, Dict, Any
from .base_scanner import BaseScanner, ScanResult

class GitleaksAdapter(BaseScanner):
    """Adapter for Gitleaks secret detection tool"""
    
    def __init__(self):
        super().__init__()
        self.name = "Gitleaks"
        self.supported_languages = ['all']
        self._get_version()
    
    def _get_version(self):
        try:
            result = subprocess.run(['gitleaks', 'version'], capture_output=True, text=True)
            self.version = result.stdout.strip()
        except:
            self.version = "unknown"
    
    def is_installed(self) -> bool:
        try:
            subprocess.run(['gitleaks', 'version'], capture_output=True, check=True)
            return True
        except:
            return False
    
    def scan(self, directory: str) -> ScanResult:
        import time
        start_time = time.time()
        
        result = ScanResult(
            scanner_name=self.name,
            scanner_version=self.version
        )
        
        if not self.is_installed():
            result.errors.append("Gitleaks is not installed")
            return result
        
        try:
            # Create temporary report file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json') as tmp:
                cmd = [
                    'gitleaks',
                    'detect',
                    '--source', directory,
                    '--report-format', 'json',
                    '--report-path', tmp.name,
                    '--no-git'
                ]
                
                stdout, stderr, returncode = self._run_command(cmd)
                
                # Read the report file
                tmp.seek(0)
                report_content = tmp.read()
                
                if report_content:
                    vulnerabilities = self.parse_output(report_content)
                    result.vulnerabilities = vulnerabilities
                else:
                    result.errors.append("No Gitleaks report generated")
                
                if returncode != 0 and returncode != 1:
                    result.errors.append(f"Gitleaks scan failed: {stderr}")
                
        except Exception as e:
            result.errors.append(f"Error running Gitleaks: {str(e)}")
        
        result.scan_duration = time.time() - start_time
        return result
    
    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parse Gitleaks JSON output to normalized format"""
        normalized = []
        
        try:
            data = json.loads(raw_output)
            
            for finding in data:
                vuln = {
                    'scanner': 'gitleaks',
                    'type': finding.get('Description', 'Hardcoded Secret'),
                    'cwe_id': 'CWE-798',
                    'severity': 'critical',
                    'confidence': finding.get('Confidence', 'Medium').lower(),
                    'file_path': finding.get('File', ''),
                    'line_number': finding.get('StartLine', 0),
                    'explanation': f"Hardcoded secret detected: {finding.get('Description', '')}",
                    'code_snippet': finding.get('Line', ''),
                    'metadata': {
                        'rule_id': finding.get('RuleID', ''),
                        'secret_type': finding.get('Description', ''),
                        'entropy': finding.get('Entropy', 0)
                    }
                }
                normalized.append(vuln)
                
        except json.JSONDecodeError as e:
            print(f"Error parsing Gitleaks output: {e}")
        
        return normalized