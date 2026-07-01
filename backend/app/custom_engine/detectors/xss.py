import ast
import re
from typing import List, Optional
from ..detector import BaseDetector, Vulnerability, Severity, Confidence

class XSSDetector(BaseDetector):
    """Detects Cross-Site Scripting (XSS) vulnerabilities"""
    
    def __init__(self):
        super().__init__()
        self.vulnerability_type = "Cross-Site Scripting (XSS)"
        self.cwe_id = "CWE-79"
        self.severity = Severity.HIGH
        
        self.dangerous_patterns = {
            'python': [
                r"render_template\s*\(\s*.*,\s*.*=.*\)(?!.*\|safe)",  # Jinja2 without safe filter
                r"return\s+['\"]<.*>\s*\+\s*.*",  # Direct HTML concatenation
                r"Markup\s*\(\s*.*\s*\)",  # Markup without sanitization
            ],
            'php': [
                r"echo\s+['\"]<.*>['\"]\s*\.\s*\$_(GET|POST|REQUEST)",
                r"print\s+['\"]<.*>['\"]\s*\.\s*\$_(GET|POST|REQUEST)",
                r"htmlspecialchars\s*\(\s*.*\s*,\s*ENT_QUOTES\s*,\s*['\"]UTF-8['\"]\)(?!\s*,\s*false)",  # Insecure htmlspecialchars
            ],
            'javascript': [
                r"document\.write\s*\(\s*.*\+.*\)",
                r"element\.innerHTML\s*=\s*.*\+.*",
                r"eval\s*\(\s*['\"]\(.*\)",
                r"setTimeout\s*\(\s*['\"]\s*.*\s*['\"]\s*,\s*\d+\s*\)",
            ]
        }
        
        self.safe_patterns = {
            'python': [
                r"escape\s*\(",
                r"\|safe\s*\)",
                r"Markup\.escape\s*\(",
            ],
            'php': [
                r"htmlspecialchars\s*\(\s*.*\s*,\s*ENT_QUOTES\s*,\s*['\"]UTF-8['\"]\s*,\s*false\s*\)",
                r"filter_var\s*\(\s*.*\s*,\s*FILTER_SANITIZE_STRING\s*\)",
            ],
            'javascript': [
                r"textContent\s*=",
                r"innerText\s*=",
                r"DOMPurify\.sanitize\s*\(",
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
                    
                    # Determine if it's reflected, stored, or DOM-based XSS
                    xss_type = self._determine_xss_type(match.group(), language)
                    
                    vuln = Vulnerability(
                        type=f"{self.vulnerability_type} ({xss_type})",
                        cwe_id=self.cwe_id,
                        severity=self.severity,
                        confidence=Confidence.MEDIUM if xss_type == "DOM-based" else Confidence.HIGH,
                        file_path=file_path,
                        line_number=line_number,
                        explanation=f"Potential {xss_type} XSS vulnerability detected. User input may be rendered without proper sanitization.",
                        code_snippet=self.extract_code_snippet(content, line_number),
                        metadata={
                            "pattern": match.group(),
                            "language": language,
                            "xss_type": xss_type,
                            "detection_method": "pattern_matching"
                        }
                    )
                    vulnerabilities.append(vuln)
        
        # AST analysis for JavaScript
        if language == 'javascript':
            vulnerabilities.extend(self._analyze_javascript_ast(content, file_path))
        
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
        context = content[max(0, position-300):position+300]
        for safe_pattern in self.safe_patterns.get(language, []):
            if re.search(safe_pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _determine_xss_type(self, pattern: str, language: str) -> str:
        """Determine if XSS is reflected, stored, or DOM-based"""
        if 'document.write' in pattern or 'innerHTML' in pattern or 'eval' in pattern:
            return "DOM-based"
        elif any(keyword in pattern for keyword in ['GET', 'POST', 'REQUEST', 'input']):
            return "Reflected"
        else:
            return "Stored"
    
    def _analyze_javascript_ast(self, content: str, file_path: str) -> List[Vulnerability]:
        """AST analysis for JavaScript - would use a JS parser in production"""
        # Placeholder - in production use acorn or esprima
        return []