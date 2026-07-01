import re
from typing import List, Optional
from ..detector import BaseDetector, Vulnerability, Severity, Confidence

class InsecureDeserializationDetector(BaseDetector):
    """Detects Insecure Deserialization vulnerabilities"""
    
    def __init__(self):
        super().__init__()
        self.vulnerability_type = "Insecure Deserialization"
        self.cwe_id = "CWE-502"
        self.severity = Severity.HIGH
        
        self.dangerous_patterns = {
            'python': [
                r"pickle\.loads\s*\(",
                r"pickle\.load\s*\(",
                r"yaml\.load\s*\(\s*.*,\s*Loader\s*=\s*yaml\.(FullLoader|Loader)\s*\)",
                r"yaml\.load\s*\(\s*.*,\s*Loader\s*=\s*yaml\.UnsafeLoader\s*\)",
                r"json\.loads\s*\(\s*.*,\s*object_hook\s*=",
                r"__import__\s*\(\s*['\"]pickle['\"]\)\.loads\s*\(",
            ],
            'php': [
                r"unserialize\s*\(",
                r"__PHP_Incomplete_Class",
                r"O:\s*:\s*\d+:\s*['\"]",
            ],
            'javascript': [
                r"JSON\.parse\s*\(\s*.*\s*,\s*.*\s*\)",
                r"eval\s*\(\s*['\"]JSON\.parse['\"]\s*\)",
                r"require\s*\(\s*['\"]child_process['\"]\)",
            ]
        }
        
        self.safe_patterns = {
            'python': [
                r"yaml\.safe_load\s*\(",
                r"json\.loads\s*\(\s*.*,\s*object_hook\s*=\s*.*\)",
                r"pickle\.loads\s*\(\s*.*,\s*fix_imports\s*=\s*True\s*\)",
                r"marshal\.loads\s*\(",
            ],
            'php': [
                r"json_decode\s*\(",
                r"unserialize\s*\(\s*.*,\s*\[.*\]\s*\)",
            ],
            'javascript': [
                r"JSON\.parse\s*\(\s*.*\s*\)",
                r"Object\.assign\s*\(\s*.*,\s*.*\s*\)",
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
                        confidence=Confidence.HIGH,
                        file_path=file_path,
                        line_number=line_number,
                        explanation="Insecure deserialization detected. Deserializing untrusted data can lead to remote code execution.",
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