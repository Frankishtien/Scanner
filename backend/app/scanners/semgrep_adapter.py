import json
import os
import subprocess
from typing import List, Dict, Any
from .base_scanner import BaseScanner, ScanResult

class SemgrepAdapter(BaseScanner):
    """Adapter for Semgrep SAST tool"""
    
    def __init__(self):
        super().__init__()
        self.name = "Semgrep"
        self.supported_languages = ['python', 'javascript', 'java', 'go', 'ruby', 'php']
        self._get_version()
    
    def _get_version(self):
        try:
            result = subprocess.run(['semgrep', '--version'], capture_output=True, text=True)
            self.version = result.stdout.strip()
        except:
            self.version = "unknown"
    
    def is_installed(self) -> bool:
        try:
            subprocess.run(['semgrep', '--version'], capture_output=True, check=True)
            return True
        except:
            return False
    
    def scan(self, directory: str) -> ScanResult:
        """Execute Semgrep scan"""
        import time
        start_time = time.time()
        
        result = ScanResult(
            scanner_name=self.name,
            scanner_version=self.version
        )
        
        if not self.is_installed():
            result.errors.append("Semgrep is not installed")
            return result
        
        try:
            # Run semgrep with JSON output
            cmd = [
                'semgrep',
                'scan',
                '--json',
                '--quiet',
                '--no-git-ignore',
                directory
            ]
            
            stdout, stderr, returncode = self._run_command(cmd)
            
            if returncode == 0 or returncode == 1:  # 1 means findings found
                vulnerabilities = self.parse_output(stdout)
                result.vulnerabilities = vulnerabilities
                result.files_scanned = len(vulnerabilities)  # Approximate
            else:
                result.errors.append(f"Semgrep scan failed: {stderr}")
            
        except Exception as e:
            result.errors.append(f"Error running Semgrep: {str(e)}")
        
        result.scan_duration = time.time() - start_time
        return result
    
    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parse Semgrep JSON output to normalized format"""
        normalized = []
        
        try:
            data = json.loads(raw_output)
            
            for result in data.get('results', []):
                # Map severity
                severity_map = {
                    'ERROR': 'critical',
                    'WARNING': 'high',
                    'INFO': 'low'
                }
                
                # Get CWE from semgrep rules
                cwe = None
                for extra in result.get('extra', {}).get('metadata', {}).get('cwe', []):
                    if isinstance(extra, str) and extra.startswith('CWE-'):
                        cwe = extra
                        break
                
                if not cwe:
                    cwe = "CWE-Unknown"
                
                vuln = {
                    'scanner': 'semgrep',
                    'type': result.get('check_id', 'Unknown'),
                    'cwe_id': cwe,
                    'severity': severity_map.get(result.get('extra', {}).get('severity'), 'medium'),
                    'confidence': result.get('extra', {}).get('metadata', {}).get('confidence', 'medium'),
                    'file_path': result.get('path', ''),
                    'line_number': result.get('start', {}).get('line', 0),
                    'explanation': result.get('extra', {}).get('message', ''),
                    'code_snippet': result.get('extra', {}).get('lines', ''),
                    'metadata': {
                        'rule_id': result.get('check_id', ''),
                        'rule_source': result.get('extra', {}).get('metadata', {}).get('source', '')
                    }
                }
                normalized.append(vuln)
                
        except json.JSONDecodeError as e:
            print(f"Error parsing Semgrep output: {e}")
        
        return normalized