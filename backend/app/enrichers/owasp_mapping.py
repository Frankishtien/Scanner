from typing import Dict, Any, Optional

class OWASPMapper:
    """OWASP Top 10 mapping service"""
    
    OWASP_CATEGORIES = {
        'A01:2021': {
            'name': 'Broken Access Control',
            'description': 'Access control enforces policy such that users cannot act outside of their intended permissions.'
        },
        'A02:2021': {
            'name': 'Cryptographic Failures',
            'description': 'Failures related to cryptography which often lead to sensitive data exposure.'
        },
        'A03:2021': {
            'name': 'Injection',
            'description': 'Injection flaws, such as SQL, NoSQL, OS, and LDAP injection.'
        },
        'A04:2021': {
            'name': 'Insecure Design',
            'description': 'Insecure design refers to risks related to design and architecture flaws.'
        },
        'A05:2021': {
            'name': 'Security Misconfiguration',
            'description': 'Security misconfiguration is the most common issue.'
        },
        'A06:2021': {
            'name': 'Vulnerable and Outdated Components',
            'description': 'Using components with known vulnerabilities.'
        },
        'A07:2021': {
            'name': 'Identification and Authentication Failures',
            'description': 'Authentication failures can allow attackers to compromise user accounts.'
        },
        'A08:2021': {
            'name': 'Software and Data Integrity Failures',
            'description': 'Failures related to software and data integrity.'
        },
        'A09:2021': {
            'name': 'Security Logging and Monitoring Failures',
            'description': 'Insufficient logging and monitoring allows attackers to persist.'
        },
        'A10:2021': {
            'name': 'Server-Side Request Forgery (SSRF)',
            'description': 'SSRF flaws occur whenever a web application fetches a remote resource.'
        }
    }
    
    @classmethod
    def map_cwe_to_owasp(cls, cwe_id: str) -> Optional[str]:
        """Map CWE ID to OWASP Top 10 category"""
        # Mapping from CWE to OWASP categories
        cwe_to_owasp = {
            'CWE-89': 'A03:2021',  # SQL Injection
            'CWE-79': 'A03:2021',  # XSS
            'CWE-77': 'A03:2021',  # Command Injection
            'CWE-22': 'A01:2021',  # Path Traversal
            'CWE-918': 'A10:2021',  # SSRF
            'CWE-798': 'A07:2021',  # Hardcoded Credentials
            'CWE-326': 'A02:2021',  # Weak Cryptography
            'CWE-502': 'A08:2021',  # Insecure Deserialization
        }
        
        owasp_id = cwe_to_owasp.get(cwe_id.upper())
        if owasp_id:
            category = cls.OWASP_CATEGORIES.get(owasp_id, {})
            return f"{owasp_id} - {category.get('name', 'Unknown')}"
        
        return 'Unknown'
    
    @classmethod
    def get_category_description(cls, owasp_id: str) -> str:
        """Get description for an OWASP category"""
        category = cls.OWASP_CATEGORIES.get(owasp_id, {})
        return category.get('description', '')
    
    @classmethod
    def get_all_categories(cls) -> Dict[str, Any]:
        """Get all OWASP categories"""
        return cls.OWASP_CATEGORIES