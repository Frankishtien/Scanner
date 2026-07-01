from .sql_injection import SQLInjectionDetector
from .xss import XSSDetector
from .command_injection import CommandInjectionDetector
from .path_traversal import PathTraversalDetector
from .ssrf import SSRFTDetector
from .hardcoded_secrets import HardcodedSecretsDetector
from .weak_crypto import WeakCryptoDetector
from .insecure_deserialization import InsecureDeserializationDetector

class DetectorFactory:
    """Factory class to manage and create detector instances"""
    
    _detectors = [
        SQLInjectionDetector,
        XSSDetector,
        CommandInjectionDetector,
        PathTraversalDetector,
        SSRFTDetector,
        HardcodedSecretsDetector,
        WeakCryptoDetector,
        InsecureDeserializationDetector
    ]
    
    @classmethod
    def get_all_detectors(cls):
        """Get instances of all detectors"""
        return [detector() for detector in cls._detectors]
    
    @classmethod
    def get_detectors_for_language(cls, language: str):
        """Get detectors that support a specific language"""
        detectors = []
        for detector_cls in cls._detectors:
            detector = detector_cls()
            if detector.get_language() == language or detector.get_language() == 'multi':
                detectors.append(detector)
        return detectors