import re
from typing import List, Optional
from ..detector import BaseDetector, Vulnerability, Severity, Confidence

class WeakCryptoDetector(BaseDetector):
    """Detects Weak Cryptography usage"""
    
    def __init__(self):
        super().__init__()
        self.vulnerability_type = "Weak Cryptography"
        self.cwe_id = "CWE-326"
        self.severity = Severity.MEDIUM
        
        self.dangerous_patterns = {
            'python': [
                r"hashlib\.(md5|sha1)\s*\(",
                r"cryptography\.hazmat\.primitives\.hashes\.(MD5|SHA1)\s*\(",
                r"DES\.new\s*\(",
                r"ARC4\.new\s*\(",
                r"RSA\.generate\s*\(\s*1024\s*\)",
                r"Cryptodome\.Cipher\.(DES|ARC4)\.",
                r"hmac\.new\s*\(\s*.*,\s*.*,\s*hashlib\.(md5|sha1)\s*\)",
            ],
            'php': [
                r"md5\s*\(",
                r"sha1\s*\(",
                r"mcrypt_encrypt\s*\(",
                r"openssl_encrypt\s*\(\s*.*,\s*['\"]DES.*['\"]",
                r"password_hash\s*\(\s*.*,\s*PASSWORD_DEFAULT\s*\)",
            ],
            'javascript': [
                r"crypto\.createHash\s*\(\s*['\"]md5['\"]\s*\)",
                r"crypto\.createHash\s*\(\s*['\"]sha1['\"]\s*\)",
                r"crypto\.createCipher\s*\(\s*['\"]DES.*['\"]",
                r"crypto\.createCipheriv\s*\(\s*['\"]DES.*['\"]",
            ]
        }
        
        self.safe_patterns = {
            'python': [
                r"hashlib\.(sha256|sha384|sha512)\s*\(",
                r"cryptography\.hazmat\.primitives\.hashes\.(SHA256|SHA384|SHA512)\s*\(",
                r"Fernet\s*\(",
                r"AES\.new\s*\(",
                r"RSA\.generate\s*\(\s*2048\s*\)",
            ],
            'php': [
                r"password_hash\s*\(\s*.*,\s*PASSWORD_BCRYPT\s*\)",
                r"password_hash\s*\(\s*.*,\s*PASSWORD_ARGON2ID\s*\)",
                r"hash\s*\(\s*['\"]sha256['\"]",
                r"hash\s*\(\s*['\"]sha512['\"]",
            ],
            'javascript': [
                r"crypto\.createHash\s*\(\s*['\"]sha256['\"]\s*\)",
                r"crypto\.createHash\s*\(\s*['\"]sha512['\"]\s*\)",
                r"crypto\.createCipheriv\s*\(\s*['\"]aes-256.*['\"]",
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
                        explanation="Weak cryptographic algorithm detected. Use strong algorithms like SHA-256, SHA-512, or AES-256.",
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