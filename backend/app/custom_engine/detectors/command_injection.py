import re
from typing import List, Optional
from ..detector import BaseDetector, Vulnerability, Severity, Confidence

class CommandInjectionDetector(BaseDetector):
    """Detects Command Injection vulnerabilities"""
    
    def __init__(self):
        super().__init__()
        self.vulnerability_type = "Command Injection"
        self.cwe_id = "CWE-77"
        self.severity = Severity.CRITICAL
        
        # Dangerous patterns for various languages
        self.dangerous_patterns = {
            'python': [
                r"os\.system\s*\(\s*.*\+.*\)",
                r"subprocess\.(call|Popen|run)\s*\(\s*.*\+.*\)",
                r"eval\s*\(\s*.*\+.*\)",
                r"exec\s*\(\s*.*\+.*\)",
                r"__import__\s*\(\s*['\"]os['\"]\)\.system\s*\(",
            ],
            'php': [
                r"system\s*\(\s*.*\.\s*\$_(GET|POST|REQUEST)",
                r"exec\s*\(\s*.*\.\s*\$_(GET|POST|REQUEST)",
                r"shell_exec\s*\(\s*.*\.\s*\$_(GET|POST|REQUEST)",
                r"passthru\s*\(\s*.*\.\s*\$_(GET|POST|REQUEST)",
                r"popen\s*\(\s*.*\.\s*\$_(GET|POST|REQUEST)",
            ],
            'javascript': [
                r"child_process\.(exec|execSync|spawn|spawnSync)\s*\(\s*.*\+.*\)",
                r"eval\s*\(\s*.*\+.*\)",
                r"Function\s*\(\s*.*\+.*\)",
                r"setTimeout\s*\(\s*.*\+.*\s*,\s*\d+\s*\)",
            ]
        }
        
        self.safe_patterns = {
            'python': [
                r"subprocess\.(call|Popen|run)\s*\(\s*\[.*\]\s*\)",
                r"shlex\.quote\s*\(",
                r"subprocess\.list2cmdline\s*\(",
            ],
            'php': [
                r"escapeshellcmd\s*\(",
                r"escapeshellarg\s*\(",
            ],
            'javascript': [
                r"child_process\.execFile\s*\(",
                r"child_process\.execFileSync\s*\(",
            ]
        }
    
    def get_language(self) -> str:
        return "multi"
    
    def detect(self, file_path: str, content: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        language = self._detect_language(file_path)
        if not language:
            return vulnerabilities
        
        # Check for dangerous patterns
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
                        explanation="Potential Command Injection vulnerability detected. User input may be used in system commands without proper sanitization.",
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