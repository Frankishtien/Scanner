import re
from typing import List, Optional
from ..detector import BaseDetector, Vulnerability, Severity, Confidence

class PathTraversalDetector(BaseDetector):
    """Detects Path Traversal vulnerabilities"""
    
    def __init__(self):
        super().__init__()
        self.vulnerability_type = "Path Traversal"
        self.cwe_id = "CWE-22"
        self.severity = Severity.HIGH
        
        self.dangerous_patterns = {
            'python': [
                r"open\s*\(\s*.*\+.*\)",
                r"file\s*\(\s*.*\+.*\)",
                r"os\.path\.join\s*\(\s*.*\+.*\)",
                r"__import__\s*\(\s*['\"]os['\"]\)\.path\.join\s*\(",
            ],
            'php': [
                r"fopen\s*\(\s*.*\.\s*\$_(GET|POST|REQUEST)",
                r"file_get_contents\s*\(\s*.*\.\s*\$_(GET|POST|REQUEST)",
                r"include\s*\(\s*.*\.\s*\$_(GET|POST|REQUEST)",
                r"require\s*\(\s*.*\.\s*\$_(GET|POST|REQUEST)",
            ],
            'javascript': [
                r"fs\.(readFile|writeFile|readFileSync|writeFileSync)\s*\(\s*.*\+.*\)",
                r"path\.join\s*\(\s*.*\+.*\)",
                r"require\s*\(\s*.*\+.*\)",
            ]
        }
        
        self.safe_patterns = {
            'python': [
                r"os\.path\.join\s*\(\s*.*,\s*os\.path\.basename\s*\(",
                r"os\.path\.abspath\s*\(",
                r"os\.path\.realpath\s*\(",
            ],
            'php': [
                r"realpath\s*\(",
                r"basename\s*\(",
                r"str_replace\s*\(\s*['\"]\.\./['\"]",
            ],
            'javascript': [
                r"path\.resolve\s*\(",
                r"path\.normalize\s*\(",
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
                        explanation="Potential Path Traversal vulnerability detected. User input may be used to access files outside the intended directory.",
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