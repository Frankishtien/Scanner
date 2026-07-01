#!/usr/bin/env python3
"""Test that all imports work correctly"""

def test_imports():
    print("Testing imports...")
    
    # Test custom engine
    from app.custom_engine.engine import CustomEngine
    print("✓ CustomEngine imported")
    
    # Test detectors
    from app.custom_engine.detectors import DetectorFactory
    print("✓ DetectorFactory imported")
    
    # Test scanners
    from app.scanners import SemgrepAdapter, BanditAdapter, GitleaksAdapter, TrivyAdapter
    print("✓ Scanners imported")
    
    # Test services
    from app.services import ScannerManager, CorrelationEngine, ScoringEngine
    print("✓ Services imported")
    
    # Test enrichers
    from app.enrichers import CWEMapper
    print("✓ Enrichers imported")
    
    print("\n✅ All imports successful!")

if __name__ == '__main__':
    test_imports()
