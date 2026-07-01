from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio
from ..scanners.base_scanner import BaseScanner, ScanResult
from ..scanners.semgrep_adapter import SemgrepAdapter
from ..scanners.bandit_adapter import BanditAdapter
from ..scanners.gitleaks_adapter import GitleaksAdapter
from ..scanners.trivy_adapter import TrivyAdapter

class ScannerManager:
    """Manages multiple scanners and coordinates scanning"""
    
    def __init__(self):
        self.scanners = self._initialize_scanners()
        self.max_workers = 4
    
    def _initialize_scanners(self) -> List[BaseScanner]:
        """Initialize all available scanners"""
        scanners = [
            SemgrepAdapter(),
            BanditAdapter(),
            GitleaksAdapter(),
            TrivyAdapter()
        ]
        
        # Filter out scanners that are not installed
        available = [s for s in scanners if s.is_installed()]
        
        if not available:
            print("Warning: No scanners available")
        
        return available
    
    def run_scan(self, directory: str, scanner_names: Optional[List[str]] = None) -> List[ScanResult]:
        """Run scan using all or selected scanners"""
        results = []
        
        # Filter scanners if specific names provided
        scanners_to_run = self.scanners
        if scanner_names:
            scanners_to_run = [s for s in self.scanners if s.name in scanner_names]
        
        # Run scans in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._run_single_scan, scanner, directory): scanner
                for scanner in scanners_to_run
            }
            
            for future in as_completed(futures):
                scanner = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    error_result = ScanResult(scanner_name=scanner.name)
                    error_result.errors.append(f"Scan failed: {str(e)}")
                    results.append(error_result)
        
        return results
    
    def _run_single_scan(self, scanner: BaseScanner, directory: str) -> ScanResult:
        """Run a single scanner"""
        try:
            return scanner.scan(directory)
        except Exception as e:
            result = ScanResult(scanner_name=scanner.name)
            result.errors.append(f"Error during scan: {str(e)}")
            return result
    
    def get_available_scanners(self) -> List[Dict[str, Any]]:
        """Get list of available scanners with metadata"""
        return [
            {
                'name': scanner.name,
                'version': scanner.version,
                'supported_languages': scanner.supported_languages,
                'is_installed': scanner.is_installed()
            }
            for scanner in self.scanners
        ]