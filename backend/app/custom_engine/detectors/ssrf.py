import re
from typing import List, Optional
from ..detector import BaseDetector, Vulnerability, Severity, Confidence

class SSRFTDetector(BaseDetector):
    """Detects Server-Side Request Forgery (SSRF) vulnerabilities"""
    
    def __init__(self):
        super().__init__()
        self.vulnerability_type = "Server-Side Request Forgery (SSRF)"
        self.cwe_id = "CWE-918"
        self.severity = Severity.HIGH
        
        self.dangerous_patterns = {
            'python': [
                r"requests\.(get|post|put|delete|head|patch)\s*\(\s*.*\+.*\)",
                r"urllib\.request\.urlopen\s*\(\s*.*\+.*\)",
                r"httpx\.(get|post|put|delete)\s*\(\s*.*\+.*\)",
            ],
            'php': [
                r"file_get_contents\s*\(\s*.*\.\s*\$_(GET|POST|REQUEST)",
                r"curl_exec\s*\(\s*.*\.\s*\$_(GET|POST|REQUEST)",
                r"fopen\s*\(\s*.*\.\s*\$_(GET|POST|REQUEST)",
            ],
            'javascript': [
                r"fetch\s*\(\s*.*\+.*\)",
                r"axios\.(get|post|put|delete)\s*\(\s*.*\+.*\)",
                r"http\.(get|request)\s*\(\s*.*\+.*\)",
            ]
        }
        
        self.safe_patterns = {
            'python': [
                r"allow_redirects\s*=\s*False",
                r"verify\s*=\s*False",
                r"urllib\.parse\.urlparse\s*\(",
            ],
            'php': [
                r"parse_url\s*\(",
                r"filter_var\s*\(\s*.*\s*,\s*FILTER_VALIDATE_URL\s*\)",
            ],
            'javascript': [
                r"new\s+URL\s*\(",
                r"url\.parse\s*\(",
            ]
        }
    
    def get_language(self) -> str:
        return "multi"
    
    def detect(self, file_path: str, content: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        language = self._detect_language(file_path)
        if not language:
            return vulnerabilities
        
        for pattern in self.dangerous_patterns.get(language, []):
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                is_safe = self._check_if_safe(content, match.start(), language)
                if not is_safe:
                    line_number = content[:match.start()].count('\n') + 1
                    vuln = Vulnerability(
                        type=self.vulnerability_type,
                        cwe_id=self.cwe_id,
                        severity=self.severity,
                        confidence=Confidence.MEDIUM,
                        file_path=file_path,
                        line_number=line_number,
                        explanation="Potential SSRF vulnerability detected. User input may be used to make requests to internal or external resources.",
                        code_snippet=self.extract_code_snippet(content, line_number),
                        metadata={
                            "pattern": match.group(),
                            "language": language,
                            "detection_method": "pattern_matching"
                        }
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _detect_language(self, file_path: str) -> Optional[str]:
        if file_path.endswith('.py'):
            return 'python'
        elif file_path.endswith('.php'):
            return 'php'
        elif file_path.endswith('.js') or file_path.endswith('.jsx') or file_path.endswith('.ts'):
            return 'javascript'
        return None
    
    def _check_if_safe(self, content: str, position: int, language: str) -> bool:
        context = content[max(0, position-200):position+200]
        for safe_pattern in self.safe_patterns.get(language, []):
            if re.search(safe_pattern, context, re.IGNORECASE):
                return True
        return False