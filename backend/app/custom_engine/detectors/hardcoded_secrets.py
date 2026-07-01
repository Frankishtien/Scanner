import re
from typing import List, Optional
from ..detector import BaseDetector, Vulnerability, Severity, Confidence

class HardcodedSecretsDetector(BaseDetector):
    """Detects hardcoded secrets, passwords, API keys, and tokens"""
    
    def __init__(self):
        super().__init__()
        self.vulnerability_type = "Hardcoded Secret"
        self.cwe_id = "CWE-798"
        self.severity = Severity.CRITICAL
        
        # Common secret patterns
        self.secret_patterns = [
            # AWS Keys
            {
                'pattern': r'(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*[\'"]?([A-Z0-9]{20,})[\'"]?',
                'name': 'AWS Access Key',
                'confidence': Confidence.HIGH
            },
            # API Keys
            {
                'pattern': r'(?i)(api_key|apikey|api_token|token)\s*=\s*[\'"]?([a-zA-Z0-9\-_]{20,})[\'"]?',
                'name': 'API Key/Token',
                'confidence': Confidence.MEDIUM
            },
            # JWT Tokens
            {
                'pattern': r'(?i)(jwt|token|bearer)\s*=\s*[\'"]?([a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)[\'"]?',
                'name': 'JWT Token',
                'confidence': Confidence.HIGH
            },
            # Passwords
            {
                'pattern': r'(?i)(password|passwd|pwd)\s*=\s*[\'"]?([^\'\"]{8,})[\'"]?',
                'name': 'Password',
                'confidence': Confidence.MEDIUM
            },
            # GitHub Tokens
            {
                'pattern': r'(?i)github(?:_token|_pat)?\s*=\s*[\'"]?([a-zA-Z0-9\-_]{35,40})[\'"]?',
                'name': 'GitHub Token',
                'confidence': Confidence.HIGH
            },
            # Slack Tokens
            {
                'pattern': r'(?i)slack(?:_token|_webhook)?\s*=\s*[\'"]?([a-zA-Z0-9\-_]{20,})[\'"]?',
                'name': 'Slack Token/Webhook',
                'confidence': Confidence.HIGH
            },
            # Private Keys (PEM format)
            {
                'pattern': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
                'name': 'Private Key',
                'confidence': Confidence.HIGH
            },
            # Database URLs
            {
                'pattern': r'(?i)postgresql://[^:]+:[^@]+@',
                'name': 'PostgreSQL Connection String',
                'confidence': Confidence.HIGH
            },
            {
                'pattern': r'(?i)mysql://[^:]+:[^@]+@',
                'name': 'MySQL Connection String',
                'confidence': Confidence.HIGH
            },
            {
                'pattern': r'(?i)mongodb://[^:]+:[^@]+@',
                'name': 'MongoDB Connection String',
                'confidence': Confidence.HIGH
            }
        ]
    
    def get_language(self) -> str:
        return "multi"
    
    def detect(self, file_path: str, content: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Skip test files and configuration files that might legitimately contain secrets
        if self._should_skip_file(file_path):
            return vulnerabilities
        
        for pattern_info in self.secret_patterns:
            matches = re.finditer(pattern_info['pattern'], content, re.MULTILINE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                # Check if it's in a comment
                if self._is_in_comment(content, match.start()):
                    continue
                
                # Check if it's a placeholder
                if self._is_placeholder(match.group()):
                    continue
                
                # Extract the actual secret (obfuscate in output)
                secret_value = self._obfuscate_secret(match.group())
                
                vuln = Vulnerability(
                    type=f"{self.vulnerability_type} - {pattern_info['name']}",
                    cwe_id=self.cwe_id,
                    severity=self.severity,
                    confidence=pattern_info['confidence'],
                    file_path=file_path,
                    line_number=line_number,
                    explanation=f"Hardcoded {pattern_info['name']} detected in source code. Credentials should be stored in environment variables or secure vault.",
                    code_snippet=self.extract_code_snippet(content, line_number),
                    metadata={
                        "secret_type": pattern_info['name'],
                        "secret_preview": secret_value,
                        "detection_method": "pattern_matching"
                    }
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _should_skip_file(self, file_path: str) -> bool:
        skip_patterns = [
            r'^tests?/',
            r'^test_',
            r'\.md$',
            r'\.txt$',
            r'\.example$',
            r'\.sample$',
            r'/\.env\.example'
        ]
        return any(re.search(pattern, file_path, re.IGNORECASE) for pattern in skip_patterns)
    
    def _is_in_comment(self, content: str, position: int) -> bool:
        """Check if the position is inside a comment"""
        # Simple check for line comments
        line_start = content.rfind('\n', 0, position)
        if line_start == -1:
            line_start = 0
        
        line_content = content[line_start:position]
        
        # Check for line comments
        comment_chars = ['#', '//', ';']
        for char in comment_chars:
            if char in line_content:
                return True
        
        # Check for block comments (multi-line)
        block_comment_starts = ['/*', '"""', "'''"]
        for start in block_comment_starts:
            start_pos = content.rfind(start, 0, position)
            if start_pos != -1:
                end_pos = content.find('*/', start_pos) if start == '/*' else content.find(start, start_pos + len(start))
                if end_pos == -1 or end_pos > position:
                    return True
        
        return False
    
    def _is_placeholder(self, text: str) -> bool:
        placeholders = ['placeholder', 'example', 'sample', 'your_', 'demo', 'test', 'xxx', '___']
        return any(placeholder in text.lower() for placeholder in placeholders)
    
    def _obfuscate_secret(self, text: str) -> str:
        """Obfuscate the secret for display"""
        # Extract the actual secret value
        parts = text.split('=')
        if len(parts) == 2:
            secret = parts[1].strip().strip('"\'' )
            if len(secret) > 8:
                return secret[:4] + '****' + secret[-4:]
        return text