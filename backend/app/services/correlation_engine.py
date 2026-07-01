from typing import List, Dict, Any, Tuple
from collections import defaultdict
import hashlib
import json

class CorrelationEngine:
    """Engine to correlate and deduplicate findings from multiple scanners"""
    
    def __init__(self):
        self.similarity_threshold = 0.8
        self.confidence_weights = {
            'high': 3,
            'medium': 2,
            'low': 1
        }
    
    def correlate(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate findings from multiple scanners.
        Returns a unified list of vulnerabilities with merged metadata.
        """
        if not scan_results:
            return []
        
        # Group findings by signature
        grouped = self._group_by_signature(scan_results)
        
        # Merge correlated findings
        correlated = []
        for signature, findings in grouped.items():
            merged = self._merge_findings(findings)
            correlated.append(merged)
        
        return correlated
    
    def _group_by_signature(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by similarity signature"""
        groups = defaultdict(list)
        
        for finding in findings:
            signature = self._generate_signature(finding)
            groups[signature].append(finding)
        
        return groups
    
    def _generate_signature(self, finding: Dict[str, Any]) -> str:
        """Generate a signature for a finding based on its key attributes"""
        # Normalize file path
        file_path = finding.get('file_path', '').split('/')[-1]  # Use only filename
        
        # Create signature components
        components = [
            finding.get('type', '').lower().strip(),
            finding.get('cwe_id', '').lower().strip(),
            file_path.lower().strip(),
            str(finding.get('line_number', 0))
        ]
        
        # Create hash
        signature_str = '|'.join(components)
        return hashlib.md5(signature_str.encode('utf-8')).hexdigest()
    
    def _merge_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge multiple findings into one consolidated finding"""
        if not findings:
            return {}
        
        # Start with the first finding as base
        merged = findings[0].copy()
        
        # Collect all scanners
        scanners = set()
        for f in findings:
            if 'scanner' in f:
                scanners.add(f['scanner'])
        merged['scanners'] = list(scanners)
        
        # Calculate confidence based on number of scanners
        confidence_score = self._calculate_confidence(findings)
        merged['confidence'] = confidence_score
        
        # Aggregate metadata
        merged['metadata'] = self._aggregate_metadata(findings)
        
        # Find highest severity
        merged['severity'] = self._get_highest_severity(findings)
        
        # Collect all explanations
        explanations = [f.get('explanation', '') for f in findings if f.get('explanation')]
        merged['explanation'] = '; '.join(set(explanations))
        
        # Collect code snippets
        snippets = [f.get('code_snippet', '') for f in findings if f.get('code_snippet')]
        if snippets:
            merged['code_snippet'] = snippets[0]  # Use first snippet
        
        # Mark as correlated
        merged['correlated'] = True
        merged['correlation_count'] = len(findings)
        
        return merged
    
    def _calculate_confidence(self, findings: List[Dict[str, Any]]) -> str:
        """Calculate overall confidence based on multiple findings"""
        total_weight = 0
        max_weight = 0
        
        for finding in findings:
            conf = finding.get('confidence', 'low').lower()
            weight = self.confidence_weights.get(conf, 1)
            total_weight += weight
            max_weight += self.confidence_weights['high']
        
        # Normalize confidence score
        if max_weight > 0:
            score = total_weight / max_weight
            if score >= 0.8:
                return 'high'
            elif score >= 0.5:
                return 'medium'
            else:
                return 'low'
        return 'low'
    
    def _get_highest_severity(self, findings: List[Dict[str, Any]]) -> str:
        """Get the highest severity among findings"""
        severity_order = ['info', 'low', 'medium', 'high', 'critical']
        max_severity = 'low'
        
        for finding in findings:
            severity = finding.get('severity', 'low').lower()
            if severity in severity_order:
                if severity_order.index(severity) > severity_order.index(max_severity):
                    max_severity = severity
        
        return max_severity
    
    def _aggregate_metadata(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate metadata from multiple findings"""
        aggregated = {
            'scanner_count': len(findings),
            'scanners': [f.get('scanner', 'unknown') for f in findings],
            'rules': []
        }
        
        # Collect all rule IDs
        for f in findings:
            if 'metadata' in f:
                if 'rule_id' in f['metadata']:
                    aggregated['rules'].append(f['metadata']['rule_id'])
        
        # Remove duplicates
        aggregated['rules'] = list(set(aggregated['rules']))
        
        return aggregated