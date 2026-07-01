import ast
import re
from typing import List, Optional
from ..detector import BaseDetector, Vulnerability, Severity, Confidence

class SQLInjectionDetector(BaseDetector):
    """Detects SQL Injection vulnerabilities using AST and pattern analysis"""
    
    def __init__(self):
        super().__init__()
        self.vulnerability_type = "SQL Injection"
        self.cwe_id = "CWE-89"
        self.severity = Severity.CRITICAL
        
        # Dangerous patterns for various languages
        self.dangerous_patterns = {
            'python': [
                r"\.execute\s*\(\s*['\"]\s*SELECT.*\+",
                r"\.execute\s*\(\s*['\"]\s*INSERT.*\+",
                r"\.execute\s*\(\s*['\"]\s*UPDATE.*\+",
                r"\.execute\s*\(\s*['\"]\s*DELETE.*\+",
                r"f['\"]\s*SELECT.*\{.*\}",
                r"%s.*%",
            ],
            'php': [
                r"mysqli_query\s*\(\s*\$.*\s*,\s*['\"]SELECT.*\.",
                r"mysql_query\s*\(\s*['\"]SELECT.*\.",
                r"pg_query\s*\(\s*['\"]SELECT.*\.",
                r"pdo::query\s*\(\s*['\"]SELECT.*\.",
            ],
            'javascript': [
                r"\.query\s*\(\s*['\"]SELECT.*\+",
                r"\.query\s*\(\s*`SELECT.*\${.*}`",
            ]
        }
        
        # Safe patterns (indicating parameterized queries)
        self.safe_patterns = {
            'python': [
                r"\.execute\s*\(\s*['\"]SELECT.*%s.*\),\s*\(.*\)",
                r"\.execute\s*\(\s*['\"]SELECT.*\?,.*\),\s*\(.*\)",
                r"\.execute\s*\(\s*['\"]SELECT.*:.*\),\s*\{.*\}",
            ],
            'php': [
                r"mysqli_prepare\s*\(",
                r"pdo::prepare\s*\(",
                r"pg_prepare\s*\(",
            ],
            'javascript': [
                r"\.query\s*\(\s*['\"]SELECT.*\?,.*\[.*\]\)",
                r"\.query\s*\(\s*['\"]SELECT.*:.*,.*\{.*\}\)",
            ]
        }
    
    def get_language(self) -> str:
        return "multi"
    
    def detect(self, file_path: str, content: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Detect language from file extension
        language = self._detect_language(file_path)
        if not language:
            return vulnerabilities
        
        # Check for dangerous patterns
        for pattern in self.dangerous_patterns.get(language, []):
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                # Check if it's actually safe (parameterized)
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
                        explanation="Potential SQL Injection vulnerability detected. User input may be concatenated directly into SQL queries.",
                        code_snippet=self.extract_code_snippet(content, line_number),
                        metadata={
                            "pattern": match.group(),
                            "language": language,
                            "detection_method": "pattern_matching"
                        }
                    )
                    vulnerabilities.append(vuln)
        
        # If Python, also do AST analysis
        if language == 'python':
            vulnerabilities.extend(self._analyze_python_ast(content, file_path))
        
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
        """Check if the SQL query at position is using parameterized queries"""
        # Look around the position for safe patterns
        context = content[max(0, position-200):position+200]
        for safe_pattern in self.safe_patterns.get(language, []):
            if re.search(safe_pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _analyze_python_ast(self, content: str, file_path: str) -> List[Vulnerability]:
        """AST-based analysis for Python SQL injection"""
        vulnerabilities = []
        
        try:
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                # Check for string concatenation in SQL queries
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    if self._is_sql_operation(node):
                        line_number = node.lineno
                        vuln = Vulnerability(
                            type=self.vulnerability_type,
                            cwe_id=self.cwe_id,
                            severity=self.severity,
                            confidence=Confidence.HIGH,
                            file_path=file_path,
                            line_number=line_number,
                            explanation="String concatenation detected in SQL query. Use parameterized queries instead.",
                            code_snippet=self.extract_code_snippet(content, line_number),
                            metadata={
                                "detection_method": "ast_analysis",
                                "ast_type": "BinOp"
                            }
                        )
                        vulnerabilities.append(vuln)
                
                # Check for f-strings in SQL queries
                elif isinstance(node, ast.JoinedStr):
                    if self._is_sql_operation(node):
                        line_number = node.lineno
                        vuln = Vulnerability(
                            type=self.vulnerability_type,
                            cwe_id=self.cwe_id,
                            severity=self.severity,
                            confidence=Confidence.HIGH,
                            file_path=file_path,
                            line_number=line_number,
                            explanation="F-string detected in SQL query. Use parameterized queries instead.",
                            code_snippet=self.extract_code_snippet(content, line_number),
                            metadata={
                                "detection_method": "ast_analysis",
                                "ast_type": "JoinedStr"
                            }
                        )
                        vulnerabilities.append(vuln)
                        
        except SyntaxError:
            pass
        
        return vulnerabilities
    
    def _is_sql_operation(self, node) -> bool:
        """Check if the AST node might be part of a SQL operation"""
        # This is a simplified check; in production you'd track variable assignments
        try:
            node_str = ast.unparse(node)
            sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE']
            return any(keyword in node_str.upper() for keyword in sql_keywords)
        except:
            return False