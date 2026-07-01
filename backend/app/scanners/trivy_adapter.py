import json
import subprocess
from typing import List, Dict, Any
from .base_scanner import BaseScanner, ScanResult

class TrivyAdapter(BaseScanner):
    """Adapter for Trivy vulnerability scanner (dependency scanning)"""
    
    def __init__(self):
        super().__init__()
        self.name = "Trivy"
        self.supported_languages = ['python', 'javascript', 'java', 'go', 'ruby', 'php']
        self._get_version()
    
    def _get_version(self):
        try:
            result = subprocess.run(['trivy', '--version'], capture_output=True, text=True)
            self.version = result.stdout.split('\n')[0]
        except:
            self.version = "unknown"
    
    def is_installed(self) -> bool:
        try:
            subprocess.run(['trivy', '--version'], capture_output=True, check=True)
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
            result.errors.append("Trivy is not installed")
            return result
        
        try:
            cmd = [
                'trivy',
                'filesystem',
                '--format', 'json',
                '--scanners', 'vuln',
                '--timeout', '5m',
                directory
            ]
            
            stdout, stderr, returncode = self._run_command(cmd)
            
            if returncode == 0 or returncode == 1:
                vulnerabilities = self.parse_output(stdout)
                result.vulnerabilities = vulnerabilities
            else:
                result.errors.append(f"Trivy scan failed: {stderr}")
                
        except Exception as e:
            result.errors.append(f"Error running Trivy: {str(e)}")
        
        result.scan_duration = time.time() - start_time
        return result
    
    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parse Trivy JSON output to normalized format"""
        normalized = []
        
        try:
            data = json.loads(raw_output)
            
            for result in data.get('Results', []):
                target = result.get('Target', '')
                
                for vuln in result.get('Vulnerabilities', []):
                    # Map severity
                    severity_map = {
                        'CRITICAL': 'critical',
                        'HIGH': 'high',
                        'MEDIUM': 'medium',
                        'LOW': 'low'
                    }
                    
                    vuln_data = {
                        'scanner': 'trivy',
                        'type': 'Dependency Vulnerability',
                        'cwe_id': vuln.get('VulnerabilityID', 'CWE-Unknown'),
                        'severity': severity_map.get(vuln.get('Severity', 'LOW'), 'medium'),
                        'confidence': 'high',
                        'file_path': target,
                        'line_number': 0,
                        'explanation': vuln.get('Description', 'Dependency vulnerability found'),
                        'code_snippet': '',
                        'metadata': {
                            'package': vuln.get('PkgName', ''),
                            'installed_version': vuln.get('InstalledVersion', ''),
                            'fixed_version': vuln.get('FixedVersion', ''),
                            'cve_id': vuln.get('VulnerabilityID', ''),
                            'references': vuln.get('References', []),
                            'cvss_score': vuln.get('CVSS', {}).get('nvd', {}).get('V3Score', 0)
                        }
                    }
                    normalized.append(vuln_data)
                    
        except json.JSONDecodeError as e:
            print(f"Error parsing Trivy output: {e}")
        
        return normalized