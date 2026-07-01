from typing import Dict, Any, List, Optional

class CWEMapper:
    """CWE mapping and enrichment service"""
    
    # CWE Database (simplified mapping)
    CWE_DATABASE = {
        'CWE-89': {
            'name': 'SQL Injection',
            'description': 'The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.',
            'owasp': 'A03:2021 Injection',
            'cvss_base': 9.8,
            'severity': 'critical'
        },
        'CWE-79': {
            'name': 'Cross-Site Scripting (XSS)',
            'description': 'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.',
            'owasp': 'A03:2021 Injection',
            'cvss_base': 6.1,
            'severity': 'high'
        },
        'CWE-77': {
            'name': 'Command Injection',
            'description': 'The software constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component.',
            'owasp': 'A03:2021 Injection',
            'cvss_base': 9.8,
            'severity': 'critical'
        },
        'CWE-22': {
            'name': 'Path Traversal',
            'description': 'The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.',
            'owasp': 'A01:2021 Broken Access Control',
            'cvss_base': 7.5,
            'severity': 'high'
        },
        'CWE-918': {
            'name': 'Server-Side Request Forgery (SSRF)',
            'description': 'The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.',
            'owasp': 'A10:2021 Server-Side Request Forgery',
            'cvss_base': 8.6,
            'severity': 'high'
        },
        'CWE-798': {
            'name': 'Hardcoded Credentials',
            'description': 'The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.',
            'owasp': 'A07:2021 Identification and Authentication Failures',
            'cvss_base': 7.8,
            'severity': 'critical'
        },
        'CWE-326': {
            'name': 'Weak Cryptography',
            'description': 'The software uses encryption algorithms that are weak or deprecated, which may allow attackers to decrypt sensitive information.',
            'owasp': 'A02:2021 Cryptographic Failures',
            'cvss_base': 5.9,
            'severity': 'medium'
        },
        'CWE-502': {
            'name': 'Insecure Deserialization',
            'description': 'The software deserializes untrusted data without sufficiently verifying that the resulting data will be valid.',
            'owasp': 'A08:2021 Software and Data Integrity Failures',
            'cvss_base': 8.1,
            'severity': 'high'
        }
    }
    
    # CVSS Scoring metrics
    CVSS_METRICS = {
        'critical': {'base_score': 9.0, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'},
        'high': {'base_score': 7.0, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L'},
        'medium': {'base_score': 5.0, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'},
        'low': {'base_score': 3.0, 'vector': 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N'}
    }
    
    @classmethod
    def enrich_vulnerability(cls, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich vulnerability with CWE, CVSS, OWASP information"""
        cwe_id = vuln.get('cwe_id', '').upper()
        
        # Get CWE info
        cwe_info = cls.CWE_DATABASE.get(cwe_id, {})
        
        # If CWE not found, try to determine from type
        if not cwe_info:
            vuln_type = vuln.get('type', '').lower()
            for cwe, info in cls.CWE_DATABASE.items():
                if info['name'].lower() in vuln_type or vuln_type in info['name'].lower():
                    cwe_info = info
                    cwe_id = cwe
                    break
        
        # Add enrichment info
        enriched = vuln.copy()
        
        if cwe_info:
            enriched['cwe_name'] = cwe_info.get('name', '')
            enriched['cwe_description'] = cwe_info.get('description', '')
            enriched['owasp_category'] = cwe_info.get('owasp', '')
            enriched['cvss_base_score'] = cwe_info.get('cvss_base', 0.0)
            enriched['cvss_vector'] = cls.CVSS_METRICS.get(
                enriched.get('severity', 'medium').lower(),
                cls.CVSS_METRICS['medium']
            )['vector']
        else:
            # Default enrichment
            severity = vuln.get('severity', 'medium').lower()
            enriched['cwe_name'] = 'Unknown'
            enriched['cwe_description'] = 'No CWE information available'
            enriched['owasp_category'] = 'Unknown'
            enriched['cvss_base_score'] = cls.CVSS_METRICS.get(severity, {'base_score': 5.0})['base_score']
            enriched['cvss_vector'] = cls.CVSS_METRICS.get(severity, {'vector': ''})['vector']
        
        # Generate mitigation guidance
        enriched['mitigation'] = cls._get_mitigation(cwe_id)
        
        # References
        enriched['references'] = cls._get_references(cwe_id)
        
        return enriched
    
    @classmethod
    def _get_mitigation(cls, cwe_id: str) -> str:
        """Get mitigation guidance for CWE"""
        mitigation_map = {
            'CWE-89': 'Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.',
            'CWE-79': 'Use proper output encoding. Sanitize user input. Implement Content Security Policy.',
            'CWE-77': 'Avoid using system commands with user input. Use safe APIs for file operations.',
            'CWE-22': 'Use allow-lists for file paths. Validate and sanitize path inputs. Use chroot or containerization.',
            'CWE-918': 'Implement URL allow-lists. Validate and sanitize URLs. Use network segmentation.',
            'CWE-798': 'Use environment variables or secure vaults. Implement proper secret rotation.',
            'CWE-326': 'Use modern encryption algorithms (AES-256, RSA-2048+). Use secure key management.',
            'CWE-502': 'Avoid deserializing untrusted data. Use safe serialization formats. Implement integrity checks.'
        }
        return mitigation_map.get(cwe_id, 'Follow security best practices for this vulnerability type.')
    
    @classmethod
    def _get_references(cls, cwe_id: str) -> List[str]:
        """Get references for CWE"""
        references = [
            f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html",
            "https://owasp.org/Top10/",
            "https://cheatsheetseries.owasp.org/"
        ]
        
        # Add specific references
        if cwe_id == 'CWE-89':
            references.append("https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html")
        elif cwe_id == 'CWE-79':
            references.append("https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html")
        
        return references