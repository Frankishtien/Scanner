from typing import Dict, Any

class CVSSCalculator:
    """CVSS score calculator for vulnerabilities"""
    
    @staticmethod
    def calculate_score(vulnerability: Dict[str, Any]) -> float:
        """Calculate CVSS score based on vulnerability attributes"""
        severity = vulnerability.get('severity', 'medium').lower()
        
        # Base scores based on severity
        severity_scores = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0,
            'info': 0.0
        }
        
        base_score = severity_scores.get(severity, 5.0)
        
        # Adjust based on confidence
        confidence = vulnerability.get('confidence', 'medium').lower()
        confidence_multipliers = {
            'high': 1.0,
            'medium': 0.8,
            'low': 0.5
        }
        
        adjusted_score = base_score * confidence_multipliers.get(confidence, 0.8)
        
        # Round to 1 decimal place
        return round(adjusted_score, 1)
    
    @staticmethod
    def get_vector_string(vulnerability: Dict[str, Any]) -> str:
        """Get CVSS vector string"""
        severity = vulnerability.get('severity', 'medium').lower()
        
        vectors = {
            'critical': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            'high': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L',
            'medium': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
            'low': 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N'
        }
        
        return vectors.get(severity, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N')