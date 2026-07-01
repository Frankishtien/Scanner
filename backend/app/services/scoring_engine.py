from typing import List, Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass, field

class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class SecurityScore:
    overall_score: float
    risk_level: RiskLevel
    category_scores: Dict[str, float]
    vulnerability_counts: Dict[str, int]
    detailed_breakdown: Dict[str, Any]
    recommendations: List[str]

class ScoringEngine:
    """Engine to calculate security scores based on scan results"""
    
    def __init__(self):
        # Define all possible categories with their keywords
        self.category_keywords = {
            'injection': ['sql injection', 'xss', 'cross-site scripting', 'command injection', 
                         'path traversal', 'ssrf', 'injection', 'deserialization'],
            'secrets': ['secret', 'key', 'token', 'password', 'credential', 'hardcoded'],
            'cryptography': ['weak crypto', 'weak cryptography', 'md5', 'sha1', 'des', 'rc4'],
            'authentication': ['authentication', 'session', 'authorization', 'bypass'],
            'dependencies': ['dependency', 'package', 'version', 'cve', 'vulnerable component'],
            'configuration': ['configuration', 'misconfiguration', 'weak config']
        }
        
        # Severity scoring weights
        self.severity_weights = {
            'critical': 10,
            'high': 6,
            'medium': 3,
            'low': 1,
            'info': 0
        }
        
        self.base_score = 100
        self.max_deduction_per_category = 30
        
        self.confidence_modifiers = {
            'high': 1.0,
            'medium': 0.8,
            'low': 0.5
        }
    
    def calculate_score(self, vulnerabilities: List[Dict[str, Any]]) -> SecurityScore:
        """Calculate comprehensive security score from vulnerabilities"""
        if not vulnerabilities:
            return self._get_perfect_score()
        
        # Categorize vulnerabilities based on actual findings
        categorized = self._categorize_vulnerabilities(vulnerabilities)
        
        # Get only categories that have findings
        active_categories = {cat: vulns for cat, vulns in categorized.items() if vulns}
        
        # If no vulnerabilities in any category, return perfect score
        if not active_categories:
            return self._get_perfect_score()
        
        # Calculate category scores
        category_scores = {}
        category_details = {}
        
        for category, vulns in active_categories.items():
            score, details = self._calculate_category_score(vulns, category)
            category_scores[category] = score
            category_details[category] = details
        
        # Calculate overall score
        overall_score = self._calculate_overall_score(category_scores)
        
        # Determine risk level
        risk_level = self._determine_risk_level(overall_score, categorized)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(categorized, category_scores)
        
        # Count vulnerabilities by severity
        severity_counts = self._count_by_severity(vulnerabilities)
        
        return SecurityScore(
            overall_score=overall_score,
            risk_level=risk_level,
            category_scores=category_scores,
            vulnerability_counts=severity_counts,
            detailed_breakdown=category_details,
            recommendations=recommendations
        )
    
    def _get_perfect_score(self) -> SecurityScore:
        """Return perfect score when no vulnerabilities found"""
        return SecurityScore(
            overall_score=100,
            risk_level=RiskLevel.LOW,
            category_scores={},
            vulnerability_counts={},
            detailed_breakdown={},
            recommendations=['No vulnerabilities found. Keep up the good work!']
        )
    
    def _categorize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        """Categorize vulnerabilities into security categories based on their type"""
        categories = {cat: [] for cat in self.category_keywords.keys()}
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '').lower()
            vuln_cwe = vuln.get('cwe_id', '').lower()
            vuln_desc = vuln.get('explanation', '').lower()
            
            # Combine all text for matching
            search_text = f"{vuln_type} {vuln_cwe} {vuln_desc}"
            
            placed = False
            for category, keywords in self.category_keywords.items():
                if any(keyword in search_text for keyword in keywords):
                    categories[category].append(vuln)
                    placed = True
                    break
            
            # If not placed, put in 'other' category (we'll add it dynamically)
            if not placed:
                if 'other' not in categories:
                    categories['other'] = []
                categories['other'].append(vuln)
        
        # Remove empty categories
        return {cat: vulns for cat, vulns in categories.items() if vulns}
    
    def _calculate_category_score(self, vulnerabilities: List[Dict], category: str) -> tuple:
        """Calculate score for a specific category"""
        if not vulnerabilities:
            return 100, {'total': 0, 'deductions': 0}
        
        total_deduction = 0
        details = {
            'total': len(vulnerabilities),
            'by_severity': {},
            'deductions': []
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            confidence = vuln.get('confidence', 'medium').lower()
            
            base_deduction = self.severity_weights.get(severity, 1)
            confidence_mod = self.confidence_modifiers.get(confidence, 0.8)
            adjusted_deduction = base_deduction * confidence_mod
            
            details['by_severity'][severity] = details['by_severity'].get(severity, 0) + 1
            total_deduction += adjusted_deduction
            details['deductions'].append({
                'severity': severity,
                'deduction': adjusted_deduction,
                'type': vuln.get('type', 'Unknown')
            })
        
        total_deduction = min(total_deduction, self.max_deduction_per_category)
        score = max(0, 100 - total_deduction)
        
        return score, details
    
    def _calculate_overall_score(self, category_scores: Dict[str, float]) -> float:
        """Calculate weighted overall score based on active categories"""
        if not category_scores:
            return 100
        
        # Give equal weight to all categories that have findings
        total_weight = len(category_scores)
        if total_weight == 0:
            return 100
        
        # Special handling: if 'other' category exists, give it less weight
        weights = {}
        for cat in category_scores:
            if cat == 'other':
                weights[cat] = 0.5  # Lower weight for uncategorized
            else:
                weights[cat] = 1.0
        
        weighted_sum = 0
        total_weight_sum = 0
        
        for category, score in category_scores.items():
            weight = weights.get(category, 1.0)
            weighted_sum += score * weight
            total_weight_sum += weight
        
        if total_weight_sum > 0:
            return round(weighted_sum / total_weight_sum, 2)
        return 100
    
    def _determine_risk_level(self, score: float, categorized: Dict[str, List]) -> RiskLevel:
        """Determine risk level based on score and vulnerability counts"""
        # Check for critical vulnerabilities
        for category, vulns in categorized.items():
            for vuln in vulns:
                if vuln.get('severity', '').lower() == 'critical':
                    return RiskLevel.CRITICAL
        
        # Score-based risk levels
        if score >= 80:
            return RiskLevel.LOW
        elif score >= 60:
            return RiskLevel.MEDIUM
        elif score >= 40:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL
    
    def _generate_recommendations(self, categorized: Dict[str, List], scores: Dict[str, float]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Category-specific recommendations
        category_recommendations = {
            'injection': 'Implement input validation and use parameterized queries to prevent injection attacks.',
            'secrets': 'Remove hardcoded secrets and use environment variables or a secure vault.',
            'cryptography': 'Use strong cryptographic algorithms like AES-256 and SHA-256.',
            'authentication': 'Implement proper authentication and session management.',
            'dependencies': 'Update vulnerable dependencies to the latest secure versions.',
            'configuration': 'Review and harden security configurations.',
            'other': 'Review these issues and follow security best practices.'
        }
        
        # Check each category with findings
        for category, vulns in categorized.items():
            if not vulns:
                continue
            
            score = scores.get(category, 100)
            
            if score < 70:
                rec = category_recommendations.get(category, 'Address security issues in this category.')
                recommendations.append(f"🚨 {category.title()}: {rec} (Found {len(vulns)} issues)")
            elif score < 85:
                rec = category_recommendations.get(category, 'Review and improve security in this area.')
                recommendations.append(f"⚠️ {category.title()}: {rec} (Found {len(vulns)} issues)")
            
            # Specific high/critical vulnerability recommendations
            for vuln in vulns:
                if vuln.get('severity', '').lower() in ['critical', 'high']:
                    vuln_type = vuln.get('type', 'Unknown')
                    file_path = vuln.get('file_path', '')
                    recommendations.append(f"🔴 Fix high severity {vuln_type} in {file_path}")
        
        # Remove duplicates
        recommendations = list(dict.fromkeys(recommendations))
        
        # Limit recommendations
        return recommendations[:10]
    
    def _count_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            counts[severity] = counts.get(severity, 0) + 1
        return counts