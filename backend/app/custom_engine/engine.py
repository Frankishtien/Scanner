import os
from typing import List, Dict, Any, Optional
from pathlib import Path
from .detectors import DetectorFactory
from .detector import Vulnerability

class CustomEngine:
    """Main custom vulnerability detection engine"""
    
    def __init__(self):
        self.detectors = DetectorFactory.get_all_detectors()
        self.supported_extensions = {
            '.py': 'python',
            '.php': 'php',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'javascript',
            '.html': 'html',
            '.htm': 'html',
            '.java': 'java',
            '.go': 'go',
            '.rb': 'ruby'
        }
    
    def scan_directory(self, directory_path: str) -> List[Vulnerability]:
        """Scan all files in a directory"""
        all_vulnerabilities = []
        
        for root, dirs, files in os.walk(directory_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in ['node_modules', '__pycache__', '.git', 'venv', 'env', 'dist', 'build']]
            
            for file in files:
                file_path = os.path.join(root, file)
                ext = os.path.splitext(file)[1].lower()
                
                # Check if file is supported
                if ext in self.supported_extensions:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        vulnerabilities = self.scan_file(file_path, content)
                        all_vulnerabilities.extend(vulnerabilities)
                    except Exception as e:
                        print(f"Error scanning {file_path}: {e}")
                else:
                    # Try to detect language from content for files without extension
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        # Check if it's a code file even without extension
                        detected_lang = self._detect_language_from_content(content)
                        if detected_lang:
                            vulnerabilities = self.scan_file(file_path, content)
                            all_vulnerabilities.extend(vulnerabilities)
                    except Exception as e:
                        pass
        
        return all_vulnerabilities
    
    def scan_file(self, file_path: str, content: str) -> List[Vulnerability]:
        """Scan a single file with all applicable detectors"""
        vulnerabilities = []
        
        # Get extension from file path
        ext = os.path.splitext(file_path)[1].lower()
        language = self.supported_extensions.get(ext)
        
        # If no extension or not supported, try to detect from content
        if not language:
            detected_lang = self._detect_language_from_content(content)
            if detected_lang:
                # Map detected language to extension for detector matching
                ext_map = {
                    'python': '.py',
                    'javascript': '.js',
                    'php': '.php',
                    'java': '.java',
                    'go': '.go',
                    'ruby': '.rb'
                }
                ext = ext_map.get(detected_lang, ext)
                language = self.supported_extensions.get(ext)
        
        if not language:
            return vulnerabilities
        
        # Run all applicable detectors
        for detector in self.detectors:
            detector_lang = detector.get_language()
            if detector_lang in [language, 'multi']:
                try:
                    findings = detector.detect(file_path, content)
                    vulnerabilities.extend(findings)
                except Exception as e:
                    print(f"Error in detector {detector.__class__.__name__} for {file_path}: {e}")
        
        return vulnerabilities
    
    def _detect_language_from_content(self, content: str) -> Optional[str]:
        """Detect programming language from content"""
        if not content or len(content.strip()) < 10:
            return None
        
        # Python detection
        if ('import ' in content or 'from ' in content) and 'def ' in content and ':' in content:
            if 'print(' in content or 'return ' in content:
                return 'python'
        
        # PHP detection
        if '<?php' in content or '<?=' in content:
            return 'php'
        
        # JavaScript detection
        if ('function ' in content or 'const ' in content or 'let ' in content) and \
           ('{' in content and '}' in content) and \
           ('console.log' in content or 'document.' in content or '=>' in content):
            return 'javascript'
        
        # Java detection
        if 'public class' in content or 'private ' in content or 'protected ' in content:
            if 'System.out.println' in content or 'String' in content:
                return 'java'
        
        # Go detection
        if 'package ' in content and 'func ' in content:
            if 'import ' in content or 'return ' in content:
                return 'go'
        
        # Ruby detection
        if 'def ' in content and 'end' in content and 'puts ' in content:
            return 'ruby'
        
        return None
    
    def get_statistics(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Get statistics about found vulnerabilities"""
        stats = {
            'total': len(vulnerabilities),
            'by_severity': {},
            'by_type': {},
            'by_confidence': {}
        }
        
        for vuln in vulnerabilities:
            # By severity
            severity = vuln.severity.value
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # By type
            vuln_type = vuln.type
            stats['by_type'][vuln_type] = stats['by_type'].get(vuln_type, 0) + 1
            
            # By confidence
            confidence = vuln.confidence.value
            stats['by_confidence'][confidence] = stats['by_confidence'].get(confidence, 0) + 1
        
        return stats