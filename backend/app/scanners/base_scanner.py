from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
import json
import subprocess
import tempfile
import os
from pathlib import Path

@dataclass
class ScanResult:
    """Normalized scan result from any scanner"""
    scanner_name: str
    scanner_version: Optional[str] = None
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    files_scanned: int = 0
    scan_duration: float = 0.0
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self):
        return {
            'scanner_name': self.scanner_name,
            'scanner_version': self.scanner_version,
            'vulnerabilities': self.vulnerabilities,
            'files_scanned': self.files_scanned,
            'scan_duration': self.scan_duration,
            'errors': self.errors,
            'metadata': self.metadata
        }

class BaseScanner(ABC):
    """Abstract base class for all scanners"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.supported_languages = []
        self.version = None
        
    @abstractmethod
    def is_installed(self) -> bool:
        """Check if the scanner is installed"""
        pass
    
    @abstractmethod
    def scan(self, directory: str) -> ScanResult:
        """Execute scan on the given directory"""
        pass
    
    @abstractmethod
    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parse scanner output into normalized vulnerability list"""
        pass
    
    def _run_command(self, command: List[str], cwd: Optional[str] = None) -> tuple:
        """Execute a command and return (stdout, stderr, returncode)"""
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", -1
        except Exception as e:
            return "", str(e), -1
    
    def _create_temp_dir(self) -> str:
        """Create a temporary directory for scan artifacts"""
        return tempfile.mkdtemp(prefix=f"{self.name.lower()}_")
    
    def _cleanup_temp_dir(self, temp_dir: str):
        """Clean up temporary directory"""
        import shutil
        try:
            shutil.rmtree(temp_dir)
        except:
            pass