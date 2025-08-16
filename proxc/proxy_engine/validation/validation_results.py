"""Validation Results - Data structures for proxy validation results"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any

from ...proxy_core.models import (
    ProxyInfo, AnonymityLevel, ProxyStatus, ValidationStatus
)
from .validation_config import ValidationMethod, FailureReason

# Forward declaration for target test results
try:
    from .validation_config import TargetTestResult
    HAS_TARGET_RESULTS = True
except ImportError:
    HAS_TARGET_RESULTS = False


@dataclass
class ValidationResult:
    """Comprehensive validation result with detailed metrics"""
    proxy: ProxyInfo
    is_valid: bool = False
    
    # Performance metrics
    response_time: Optional[float] = None  # milliseconds
    connect_time: Optional[float] = None   # milliseconds
    total_time: Optional[float] = None     # milliseconds
    bytes_transferred: int = 0
    download_speed: Optional[float] = None  # bytes/second
    
    # Error information
    failure_reason: Optional[FailureReason] = None
    error_message: Optional[str] = None
    error_details: Dict[str, Any] = field(default_factory=dict)
    
    # Anonymity analysis
    anonymity_detected: Optional[AnonymityLevel] = None
    real_ip_detected: Optional[str] = None
    proxy_ip_detected: Optional[str] = None
    headers_leaked: List[str] = field(default_factory=list)
    
    # Protocol and feature support
    ssl_supported: bool = False
    ipv6_supported: bool = False
    authentication_required: bool = False
    supports_connect_method: bool = False
    
    # Privacy and security
    dns_leak: bool = False
    webrtc_leak: bool = False
    transparent_proxy: bool = False
    captive_portal_detected: bool = False
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    test_endpoint_used: Optional[str] = None
    validation_method: ValidationMethod = ValidationMethod.HTTP_GET
    user_agent_used: Optional[str] = None
    
    # Statistics (for batch validation)
    retry_count: int = 0
    validation_duration: Optional[float] = None  # Total time spent validating
    
    # Target website testing results
    target_test_results: List = field(default_factory=list)  # List[TargetTestResult] when available
    
    # Chain detection results
    chain_analysis: Optional[Dict[str, Any]] = None  # Chain detection analysis results
    headers_analysis: Optional[Dict[str, Any]] = None  # Headers analysis for anonymity
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'proxy': {
                'host': self.proxy.host,
                'port': self.proxy.port,
                'protocol': self.proxy.protocol.value,
                'proxy_id': self.proxy.proxy_id
            },
            'is_valid': self.is_valid,
            'performance': {
                'response_time': self.response_time,
                'connect_time': self.connect_time,
                'total_time': self.total_time,
                'bytes_transferred': self.bytes_transferred,
                'download_speed': self.download_speed
            },
            'error': {
                'failure_reason': self.failure_reason.value if self.failure_reason else None,
                'error_message': self.error_message,
                'error_details': self.error_details
            },
            'anonymity': {
                'level': self.anonymity_detected.value if self.anonymity_detected else None,
                'real_ip_detected': self.real_ip_detected,
                'proxy_ip_detected': self.proxy_ip_detected,
                'headers_leaked': self.headers_leaked
            },
            'features': {
                'ssl_supported': self.ssl_supported,
                'ipv6_supported': self.ipv6_supported,
                'authentication_required': self.authentication_required,
                'supports_connect_method': self.supports_connect_method
            },
            'privacy': {
                'dns_leak': self.dns_leak,
                'webrtc_leak': self.webrtc_leak,
                'transparent_proxy': self.transparent_proxy,
                'captive_portal_detected': self.captive_portal_detected
            },
            'metadata': {
                'timestamp': self.timestamp.isoformat(),
                'test_endpoint_used': self.test_endpoint_used,
                'validation_method': self.validation_method.value,
                'user_agent_used': self.user_agent_used,
                'retry_count': self.retry_count,
                'validation_duration': self.validation_duration
            },
            'chain_analysis': self.chain_analysis,
            'headers_analysis': self.headers_analysis
        }
    
    def update_proxy_status(self):
        """Update the proxy object based on validation results"""
        if self.is_valid:
            self.proxy.status = ProxyStatus.ACTIVE
            self.proxy.validation_status = ValidationStatus.VALID
            
            if self.anonymity_detected:
                self.proxy.anonymity_level = self.anonymity_detected
        else:
            self.proxy.status = ProxyStatus.FAILED
            self.proxy.validation_status = ValidationStatus.INVALID
        
        # Update metrics if available
        if self.proxy.metrics:
            self.proxy.metrics.last_checked = self.timestamp
            if self.response_time:
                self.proxy.metrics.response_time = self.response_time
            self.proxy.metrics.update_check(
                self.is_valid, 
                self.response_time, 
                self.bytes_transferred
            )


@dataclass  
class BatchValidationResult:
    """Results from batch proxy validation"""
    total_proxies: int
    valid_proxies: int
    invalid_proxies: int
    results: List[ValidationResult] = field(default_factory=list)
    
    # Performance statistics
    total_time: float = 0.0
    average_time_per_proxy: float = 0.0
    proxies_per_second: float = 0.0
    
    # Error statistics
    error_breakdown: Dict[FailureReason, int] = field(default_factory=dict)
    timeout_count: int = 0
    connection_error_count: int = 0
    
    # Configuration used
    config_snapshot: Optional[Dict[str, Any]] = None
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage"""
        if self.total_proxies == 0:
            return 0.0
        return (self.valid_proxies / self.total_proxies) * 100
    
    @property
    def failure_rate(self) -> float:
        """Calculate failure rate as percentage"""
        return 100.0 - self.success_rate
    
    def get_valid_results(self) -> List[ValidationResult]:
        """Get only valid validation results"""
        return [r for r in self.results if r.is_valid]
    
    def get_invalid_results(self) -> List[ValidationResult]:
        """Get only invalid validation results"""
        return [r for r in self.results if not r.is_valid]
    
    def get_results_by_failure_reason(self, reason: FailureReason) -> List[ValidationResult]:
        """Get results filtered by specific failure reason"""
        return [r for r in self.results if r.failure_reason == reason]
    
    def calculate_statistics(self):
        """Calculate and update statistics from results"""
        if not self.results:
            return
        
        self.total_proxies = len(self.results)
        self.valid_proxies = len(self.get_valid_results())
        self.invalid_proxies = len(self.get_invalid_results())
        
        # Calculate timing statistics
        if self.total_time > 0:
            self.average_time_per_proxy = self.total_time / self.total_proxies
            self.proxies_per_second = self.total_proxies / self.total_time
        
        # Calculate error breakdown
        self.error_breakdown.clear()
        for result in self.get_invalid_results():
            if result.failure_reason:
                self.error_breakdown[result.failure_reason] = self.error_breakdown.get(result.failure_reason, 0) + 1
        
        # Count specific error types
        timeout_reasons = [
            FailureReason.TIMEOUT_CONNECT,
            FailureReason.TIMEOUT_READ,
            FailureReason.TIMEOUT_TOTAL
        ]
        self.timeout_count = sum(self.error_breakdown.get(reason, 0) for reason in timeout_reasons)
        
        connection_reasons = [
            FailureReason.CONNECTION_REFUSED,
            FailureReason.CONNECTION_RESET,
            FailureReason.NETWORK_UNREACHABLE,
            FailureReason.HOST_UNREACHABLE
        ]
        self.connection_error_count = sum(self.error_breakdown.get(reason, 0) for reason in connection_reasons)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'summary': {
                'total_proxies': self.total_proxies,
                'valid_proxies': self.valid_proxies,
                'invalid_proxies': self.invalid_proxies,
                'success_rate': self.success_rate,
                'failure_rate': self.failure_rate
            },
            'performance': {
                'total_time': self.total_time,
                'average_time_per_proxy': self.average_time_per_proxy,
                'proxies_per_second': self.proxies_per_second
            },
            'errors': {
                'breakdown': {reason.value: count for reason, count in self.error_breakdown.items()},
                'timeout_count': self.timeout_count,
                'connection_error_count': self.connection_error_count
            },
            'results': [result.to_dict() for result in self.results],
            'config_snapshot': self.config_snapshot
        }