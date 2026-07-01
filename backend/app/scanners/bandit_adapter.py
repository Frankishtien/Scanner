import json
import os
import subprocess
from typing import List, Dict, Any
from .base_scanner import BaseScanner, ScanResult

class BanditAdapter(BaseScanner):
    """Adapter for Bandit Python security linter"""
    
    def __init__(self):
        super().__init__()
        self.name = "Bandit"
        self.supported_languages = ['python']
        self._get_version()
    
    def _get_version(self):
        try:
            result = subprocess.run(['bandit', '--version'], capture_output=True, text=True)
            self.version = result.stdout.strip()
        except:
            self.version = "unknown"
    
    def is_installed(self) -> bool:
        try:
            subprocess.run(['bandit', '--version'], capture_output=True, check=True)
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
            result.errors.append("Bandit is not installed")
            return result
        
        try:
            # Only scan Python files
            cmd = [
                'bandit',
                '-r',
                '-f', 'json',
                directory
            ]
            
            stdout, stderr, returncode = self._run_command(cmd)
            
            if returncode == 0 or returncode == 1:
                vulnerabilities = self.parse_output(stdout)
                result.vulnerabilities = vulnerabilities
                
                # Get file count
                try:
                    data = json.loads(stdout)
                    result.files_scanned = data.get('metrics', {}).get('_totals', {}).get('loc', 0)
                except:
                    pass
            else:
                result.errors.append(f"Bandit scan failed: {stderr}")
                
        except Exception as e:
            result.errors.append(f"Error running Bandit: {str(e)}")
        
        result.scan_duration = time.time() - start_time
        return result
    
    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parse Bandit JSON output to normalized format"""
        normalized = []
        
        try:
            data = json.loads(raw_output)
            
            for result in data.get('results', []):
                # Map severity
                severity_map = {
                    'HIGH': 'critical',
                    'MEDIUM': 'high',
                    'LOW': 'medium'
                }
                
                # Map confidence
                confidence_map = {
                    'HIGH': 'high',
                    'MEDIUM': 'medium',
                    'LOW': 'low'
                }
                
                vuln = {
                    'scanner': 'bandit',
                    'type': result.get('test_name', 'Unknown'),
                    'cwe_id': result.get('test_id', 'CWE-Unknown'),
                    'severity': severity_map.get(result.get('issue_severity', 'LOW'), 'medium'),
                    'confidence': confidence_map.get(result.get('issue_confidence', 'LOW'), 'low'),
                    'file_path': result.get('filename', ''),
                    'line_number': result.get('line_number', 0),
                    'explanation': result.get('issue_text', ''),
                    'code_snippet': result.get('code', ''),
                    'metadata': {
                        'test_id': result.get('test_id', ''),
                        'more_info': result.get('more_info', '')
                    }
                }
                normalized.append(vuln)
                
        except json.JSONDecodeError as e:
            print(f"Error parsing Bandit output: {e}")
        
        return normalized