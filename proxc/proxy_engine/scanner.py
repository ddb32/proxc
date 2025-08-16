"""
Proxy Scanner - Modular Scanning Architecture

Provides three scan modes:
- Light: Availability checks only (fast)
- Detailed: Full analysis on working proxies (thorough) 
- Full: Combined discovery + validation + analysis (complete)
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Union

from ..proxy_core.models import ProxyInfo, ProxyProtocol, ProxyStatus, ValidationStatus
from ..proxy_core.config import ConfigManager
from ..proxy_core.database import DatabaseManager
from .validation import BatchValidator, ValidationConfig
from .fetchers import ProxyFetcher
from .analysis import ProxyAnalyzer

logger = logging.getLogger(__name__)


class ScanMode(Enum):
    """Available scan modes with different levels of analysis"""
    LIGHT = "light"        # Availability checks only
    DETAILED = "detailed"  # Full analysis on working proxies
    FULL = "full"         # Discovery + validation + analysis


@dataclass
class ScanConfig:
    """Configuration for proxy scanning operations"""
    mode: ScanMode = ScanMode.LIGHT
    
    # Input configuration
    input_file: Optional[str] = None
    input_proxies: Optional[List[ProxyInfo]] = None
    fetch_sources: Optional[List[str]] = None
    fetch_count: int = 100
    
    # Validation settings
    max_workers: int = 20
    timeout: int = 10
    retries: int = 3
    use_async: bool = True  # Use async validation by default for performance
    
    # Analysis settings (for detailed/full modes)
    enable_geolocation: bool = True
    enable_anonymity_check: bool = True
    enable_performance_test: bool = True
    
    # Output settings
    save_to_file: Optional[str] = None
    save_format: str = "auto"  # auto, json, csv, txt
    sync_to_db: bool = False
    
    # Progress reporting
    progress_callback: Optional[Callable] = None
    verbose: bool = False


@dataclass
class ScanResult:
    """Results from a scanning operation"""
    mode: ScanMode
    total_proxies: int = 0
    processed_proxies: int = 0
    
    # Basic results
    working_proxies: List[ProxyInfo] = field(default_factory=list)
    failed_proxies: List[ProxyInfo] = field(default_factory=list)
    error_proxies: List[ProxyInfo] = field(default_factory=list)
    
    # Performance metrics
    scan_duration: float = 0.0
    avg_response_time: float = 0.0
    success_rate: float = 0.0
    
    # Analysis results (for detailed/full modes)
    analyzed_count: int = 0
    geo_resolved_count: int = 0
    anonymity_detected_count: int = 0
    
    # Output information
    saved_to_file: Optional[str] = None
    synced_to_db: bool = False
    
    # Error information
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            'mode': self.mode.value,
            'total_proxies': self.total_proxies,
            'processed_proxies': self.processed_proxies,
            'working_count': len(self.working_proxies),
            'failed_count': len(self.failed_proxies),
            'error_count': len(self.error_proxies),
            'scan_duration': self.scan_duration,
            'avg_response_time': self.avg_response_time,
            'success_rate': self.success_rate,
            'analyzed_count': self.analyzed_count,
            'geo_resolved_count': self.geo_resolved_count,
            'anonymity_detected_count': self.anonymity_detected_count,
            'saved_to_file': self.saved_to_file,
            'synced_to_db': self.synced_to_db,
            'errors': self.errors,
            'warnings': self.warnings,
            'timestamp': self.timestamp.isoformat()
        }


class ScanManager:
    """Manages modular proxy scanning operations"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize components
        self.validator = None
        self.fetcher = None
        self.analyzer = None
        self.db_manager = None
        
        self.logger.info("ScanManager initialized")
    
    def scan(self, scan_config: ScanConfig) -> ScanResult:
        """Execute scan based on configuration"""
        result = ScanResult(mode=scan_config.mode)
        start_time = time.time()
        
        try:
            self.logger.info(f"Starting {scan_config.mode.value} scan...")
            
            # Step 1: Get proxies to scan
            proxies = self._get_input_proxies(scan_config, result)
            if not proxies:
                result.errors.append("No proxies to scan")
                return result
            
            result.total_proxies = len(proxies)
            
            # Step 2: Execute scan based on mode
            if scan_config.mode == ScanMode.LIGHT:
                self._execute_light_scan(proxies, scan_config, result)
            elif scan_config.mode == ScanMode.DETAILED:
                self._execute_detailed_scan(proxies, scan_config, result)
            elif scan_config.mode == ScanMode.FULL:
                self._execute_full_scan(proxies, scan_config, result)
            
            # Step 3: Save results if requested
            if scan_config.save_to_file:
                self._save_results(result, scan_config)
            
            # Step 4: Sync to database if requested
            if scan_config.sync_to_db:
                self._sync_to_database(result, scan_config)
            
        except Exception as e:
            result.errors.append(f"Scan failed: {str(e)}")
            self.logger.error(f"Scan failed: {e}")
        
        # Calculate final metrics
        result.scan_duration = time.time() - start_time
        result.processed_proxies = len(result.working_proxies) + len(result.failed_proxies) + len(result.error_proxies)
        
        if result.processed_proxies > 0:
            result.success_rate = (len(result.working_proxies) / result.processed_proxies) * 100
        
        working_response_times = [p.metrics.response_time for p in result.working_proxies 
                                if p.metrics and p.metrics.response_time]
        if working_response_times:
            result.avg_response_time = sum(working_response_times) / len(working_response_times)
        
        self.logger.info(f"{scan_config.mode.value} scan completed in {result.scan_duration:.1f}s")
        return result
    
    def _get_input_proxies(self, scan_config: ScanConfig, result: ScanResult) -> List[ProxyInfo]:
        """Get proxies from various input sources"""
        proxies = []
        
        # Option 1: Use provided proxy list
        if scan_config.input_proxies:
            proxies = scan_config.input_proxies
            self.logger.info(f"Using {len(proxies)} provided proxies")
        
        # Option 2: Load from file
        elif scan_config.input_file:
            proxies = self._load_proxies_from_file(scan_config.input_file, result)
            self.logger.info(f"Loaded {len(proxies)} proxies from file")
        
        # Option 3: Fetch from sources (full mode)
        elif scan_config.fetch_sources and scan_config.mode == ScanMode.FULL:
            proxies = self._fetch_proxies_from_sources(scan_config, result)
            self.logger.info(f"Fetched {len(proxies)} proxies from sources")
        
        else:
            result.errors.append("No proxy input source specified")
            return []
        
        return proxies
    
    def _load_proxies_from_file(self, file_path: str, result: ScanResult) -> List[ProxyInfo]:
        """Load proxies from file using existing parsers"""
        try:
            from .parsers import SmartProxyParser, extract_proxies_from_text
            
            path = Path(file_path)
            if not path.exists():
                result.errors.append(f"File not found: {file_path}")
                return []
            
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            parser = SmartProxyParser(self.config)
            proxies = []
            
            # Simple text parsing - one proxy per line
            for line in content.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        if '://' in line:
                            parsed = parser.parse_proxy_string(line)
                            if parsed:
                                proxies.append(parsed)
                        else:
                            # IP:PORT format
                            extracted = extract_proxies_from_text(line)
                            proxies.extend(extracted)
                    except Exception as e:
                        result.warnings.append(f"Skipped invalid line: {line[:50]}...")
            
            return proxies
            
        except Exception as e:
            result.errors.append(f"Failed to load file {file_path}: {str(e)}")
            return []
    
    def _fetch_proxies_from_sources(self, scan_config: ScanConfig, result: ScanResult) -> List[ProxyInfo]:
        """Fetch proxies from external sources"""
        try:
            if not self.fetcher:
                self.fetcher = ProxyFetcher(self.config)
            
            if scan_config.fetch_sources:
                proxies = self.fetcher.fetch_proxies(
                    source_names=scan_config.fetch_sources,
                    max_proxies=scan_config.fetch_count
                )
            else:
                proxies = self.fetcher.fetch_proxies(max_proxies=scan_config.fetch_count)
            
            return proxies or []
            
        except Exception as e:
            result.errors.append(f"Failed to fetch proxies: {str(e)}")
            return []
    
    def _execute_light_scan(self, proxies: List[ProxyInfo], scan_config: ScanConfig, result: ScanResult):
        """Execute lightweight scan - availability checks only"""
        self.logger.info(f"Executing light scan on {len(proxies)} proxies...")
        
        # Initialize lightweight validator
        if not self.validator:
            validation_config = ValidationConfig(
                max_workers=scan_config.max_workers,
                connect_timeout=float(scan_config.timeout),
                read_timeout=float(scan_config.timeout * 2),
                total_timeout=float(scan_config.timeout * 3),
                max_retries=scan_config.retries,
                
                # Enable async mode for performance
                use_asyncio=scan_config.use_async,
                
                # Disable heavy analysis for light mode
                enable_https_testing=False,
                enable_anonymity_testing=False,
                enable_speed_testing=False,
                enable_geolocation_check=False,
                
                # Minimize logging for speed
                log_successful_validations=scan_config.verbose,
                log_failed_validations=scan_config.verbose,
                log_detailed_errors=scan_config.verbose
            )
            from ..proxy_engine.validators import EnhancedBatchValidator
            self.validator = EnhancedBatchValidator(self.config, validation_config)
        
        # Execute validation
        validation_result = self.validator.validate_batch(
            proxies, 
            max_workers=scan_config.max_workers,
            progress_callback=scan_config.progress_callback
        )
        
        # Process results
        result.working_proxies = validation_result.get('valid_proxies', [])
        result.failed_proxies = validation_result.get('invalid_proxies', [])
        result.error_proxies = validation_result.get('error_proxies', [])
        
        self.logger.info(f"Light scan completed: {len(result.working_proxies)} working proxies found")
    
    def _execute_detailed_scan(self, proxies: List[ProxyInfo], scan_config: ScanConfig, result: ScanResult):
        """Execute detailed scan - full analysis on provided proxies"""
        self.logger.info(f"Executing detailed scan on {len(proxies)} proxies...")
        
        # Step 1: Basic validation first
        self._execute_light_scan(proxies, scan_config, result)
        
        # Step 2: Detailed analysis on working proxies only
        if result.working_proxies and (scan_config.enable_geolocation or 
                                     scan_config.enable_anonymity_check or 
                                     scan_config.enable_performance_test):
            
            self.logger.info(f"Performing detailed analysis on {len(result.working_proxies)} working proxies...")
            self._analyze_proxies(result.working_proxies, scan_config, result)
        
        self.logger.info(f"Detailed scan completed: analyzed {result.analyzed_count} proxies")
    
    def _execute_full_scan(self, proxies: List[ProxyInfo], scan_config: ScanConfig, result: ScanResult):
        """Execute full scan - discovery + validation + analysis"""
        self.logger.info(f"Executing full scan...")
        
        # Full scan is essentially the same as detailed scan but may include fetching
        self._execute_detailed_scan(proxies, scan_config, result)
        
        self.logger.info("Full scan completed")
    
    def _analyze_proxies(self, proxies: List[ProxyInfo], scan_config: ScanConfig, result: ScanResult):
        """Perform detailed analysis on working proxies"""
        try:
            if not self.analyzer:
                self.analyzer = ProxyAnalyzer(self.config)
            
            analyzed_count = 0
            geo_count = 0
            anonymity_count = 0
            
            for proxy in proxies:
                try:
                    # Perform analysis
                    analysis_result = self.analyzer.analyze_proxy(proxy)
                    analyzed_count += 1
                    
                    # Track what was successfully analyzed
                    if proxy.geo_location:
                        geo_count += 1
                    
                    if proxy.anonymity_level:
                        anonymity_count += 1
                    
                except Exception as e:
                    result.warnings.append(f"Analysis failed for {proxy.address}: {str(e)}")
            
            result.analyzed_count = analyzed_count
            result.geo_resolved_count = geo_count
            result.anonymity_detected_count = anonymity_count
            
        except Exception as e:
            result.errors.append(f"Analysis phase failed: {str(e)}")
    
    def _save_results(self, result: ScanResult, scan_config: ScanConfig):
        """Save scan results to file"""
        try:
            from ..proxy_core.export_utils import save_proxies_to_file
            
            output_path = save_proxies_to_file(
                result.working_proxies,
                scan_config.save_to_file,
                scan_config.save_format
            )
            
            result.saved_to_file = output_path
            self.logger.info(f"Results saved to {output_path}")
            
        except Exception as e:
            result.errors.append(f"Failed to save results: {str(e)}")
    
    def _sync_to_database(self, result: ScanResult, scan_config: ScanConfig):
        """Sync results to database"""
        try:
            if not self.db_manager:
                self.db_manager = DatabaseManager(self.config)
            
            synced_count = 0
            for proxy in result.working_proxies:
                if self.db_manager.add_or_update_proxy(proxy)[0]:
                    synced_count += 1
            
            result.synced_to_db = True
            self.logger.info(f"Synced {synced_count} proxies to database")
            
        except Exception as e:
            result.errors.append(f"Failed to sync to database: {str(e)}")


# Convenience functions for easy usage
def light_scan(proxies: Union[List[ProxyInfo], str], **kwargs) -> ScanResult:
    """Perform lightweight availability scan"""
    config = ScanConfig(mode=ScanMode.LIGHT, **kwargs)
    
    if isinstance(proxies, str):
        config.input_file = proxies
    else:
        config.input_proxies = proxies
    
    scanner = ScanManager()
    return scanner.scan(config)


def detailed_scan(proxies: Union[List[ProxyInfo], str], **kwargs) -> ScanResult:
    """Perform detailed analysis scan"""
    config = ScanConfig(mode=ScanMode.DETAILED, **kwargs)
    
    if isinstance(proxies, str):
        config.input_file = proxies
    else:
        config.input_proxies = proxies
    
    scanner = ScanManager()
    return scanner.scan(config)


def full_scan(sources: Optional[List[str]] = None, count: int = 100, **kwargs) -> ScanResult:
    """Perform full discovery + analysis scan"""
    config = ScanConfig(
        mode=ScanMode.FULL,
        fetch_sources=sources,
        fetch_count=count,
        **kwargs
    )
    
    scanner = ScanManager()
    return scanner.scan(config)


__all__ = [
    'ScanManager', 'ScanMode', 'ScanConfig', 'ScanResult',
    'light_scan', 'detailed_scan', 'full_scan'
]