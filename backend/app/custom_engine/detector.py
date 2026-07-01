from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
import re
import ast
import json

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class Vulnerability:
    type: str
    cwe_id: str
    severity: Severity
    confidence: Confidence
    file_path: str
    line_number: int
    explanation: str
    code_snippet: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self):
        return {
            "type": self.type,
            "cwe_id": self.cwe_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "explanation": self.explanation,
            "code_snippet": self.code_snippet,
            "metadata": self.metadata
        }

class BaseDetector(ABC):
    """Base class for all vulnerability detectors"""
    
    def __init__(self):
        self.language = None
        self.vulnerability_type = None
        self.cwe_id = None
        self.severity = Severity.MEDIUM
        
    @abstractmethod
    def detect(self, file_path: str, content: str) -> List[Vulnerability]:
        """Detect vulnerabilities in the given file"""
        pass
    
    @abstractmethod
    def get_language(self) -> str:
        """Return the programming language this detector supports"""
        pass
    
    def analyze_ast(self, content: str) -> Optional[ast.AST]:
        """Parse content into AST if possible"""
        try:
            return ast.parse(content)
        except SyntaxError:
            return None
    
    def extract_code_snippet(self, content: str, line_number: int, context_lines: int = 2) -> str:
        """Extract code snippet around the vulnerability line"""
        lines = content.split('\n')
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        snippet = '\n'.join(lines[start:end])
        return snippet