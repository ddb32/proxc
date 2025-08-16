"""Security Configuration - Settings for security analysis features"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Optional


class ChainDetectionMethod(Enum):
    """Methods for detecting proxy chains"""
    HEADER_ANALYSIS = "header_analysis"
    TIMING_ANALYSIS = "timing_analysis"
    RESPONSE_PATTERN = "response_pattern"
    GEOLOCATION = "geolocation"
    ALL_METHODS = "all_methods"


class ChainRiskLevel(Enum):
    """Risk levels for proxy chains"""
    LOW = "low"           # Single proxy, well-configured
    MEDIUM = "medium"     # Short chain (2-3 hops), standard configuration
    HIGH = "high"         # Long chain (4+ hops) or suspicious patterns
    CRITICAL = "critical" # Very long chain or clear obfuscation attempts


@dataclass
class ChainDetectionConfig:
    """Configuration for proxy chain detection"""
    
    # Detection methods
    enabled_methods: List[ChainDetectionMethod] = None
    
    # Thresholds
    max_acceptable_chain_depth: int = 3        # Maximum chain depth before flagging as high risk
    min_confidence_threshold: float = 0.7      # Minimum confidence to consider detection valid
    timing_analysis_samples: int = 3           # Number of timing samples for analysis
    
    # Timeouts
    chain_detection_timeout: float = 10.0      # Maximum time to spend on chain detection
    individual_hop_timeout: float = 3.0       # Timeout for individual hop analysis
    
    # Header analysis
    analyze_via_headers: bool = True           # Analyze Via headers for chain detection
    analyze_forwarded_headers: bool = True     # Analyze X-Forwarded-* headers
    analyze_custom_headers: bool = True        # Analyze custom proxy headers
    
    # Response analysis
    analyze_response_times: bool = True        # Use response time patterns
    analyze_geographic_hops: bool = False      # Check geographic routing (requires geolocation)
    analyze_ssl_chains: bool = False           # Analyze SSL certificate chains
    
    # Risk assessment
    enable_risk_scoring: bool = True           # Calculate chain risk scores
    penalize_long_chains: bool = True          # Higher risk for longer chains
    penalize_mixed_protocols: bool = True      # Higher risk for mixed HTTP/SOCKS chains
    
    # Caching
    cache_chain_analysis: bool = True          # Cache chain detection results
    chain_cache_ttl: int = 7200               # Cache TTL for chain analysis (2 hours)
    
    def __post_init__(self):
        if self.enabled_methods is None:
            self.enabled_methods = [
                ChainDetectionMethod.HEADER_ANALYSIS,
                ChainDetectionMethod.TIMING_ANALYSIS,
                ChainDetectionMethod.RESPONSE_PATTERN
            ]


@dataclass 
class SecurityConfig:
    """Comprehensive security analysis configuration"""
    
    # Chain detection
    chain_detection: ChainDetectionConfig = None
    
    # General security settings
    enable_threat_analysis: bool = True        # Enable general threat analysis
    enable_reputation_checks: bool = False     # Enable reputation/blacklist checks
    enable_honeypot_detection: bool = False    # Enable honeypot detection
    enable_tls_analysis: bool = False          # Enable TLS/certificate analysis
    
    # Honeypot detection settings
    honeypot_confidence_threshold: float = 0.6   # Minimum confidence to flag as honeypot
    honeypot_analysis_timeout: float = 5.0       # Timeout for honeypot analysis
    enable_behavioral_analysis: bool = True      # Enable behavioral pattern detection
    enable_signature_detection: bool = True      # Enable framework signature detection
    
    # TLS analysis settings
    tls_analysis_timeout: float = 10.0           # Timeout for TLS certificate extraction
    tls_target_host: str = "www.google.com"      # Default target host for TLS analysis
    tls_target_port: int = 443                   # Default target port for TLS analysis
    tls_mitm_confidence_threshold: float = 0.5   # Minimum confidence to flag as MITM
    enable_certificate_validation: bool = True   # Enable certificate validation
    enable_mitm_detection: bool = True           # Enable MITM detection
    require_valid_certificate_chain: bool = False  # Require valid certificate chain
    
    # Risk thresholds
    high_risk_threshold: float = 0.7           # Threshold for high-risk classification
    critical_risk_threshold: float = 0.9      # Threshold for critical-risk classification
    
    # Performance
    max_concurrent_security_checks: int = 5   # Max concurrent security analyses
    security_analysis_timeout: float = 30.0   # Overall timeout for security analysis
    
    # Logging and reporting
    detailed_security_logging: bool = False   # Enable detailed security logging
    include_security_recommendations: bool = True  # Include security recommendations
    
    def __post_init__(self):
        if self.chain_detection is None:
            self.chain_detection = ChainDetectionConfig()
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'chain_detection': {
                'enabled_methods': [m.value for m in self.chain_detection.enabled_methods],
                'max_acceptable_chain_depth': self.chain_detection.max_acceptable_chain_depth,
                'min_confidence_threshold': self.chain_detection.min_confidence_threshold,
                'timing_analysis_samples': self.chain_detection.timing_analysis_samples,
                'chain_detection_timeout': self.chain_detection.chain_detection_timeout,
                'individual_hop_timeout': self.chain_detection.individual_hop_timeout,
                'analyze_via_headers': self.chain_detection.analyze_via_headers,
                'analyze_forwarded_headers': self.chain_detection.analyze_forwarded_headers,
                'analyze_custom_headers': self.chain_detection.analyze_custom_headers,
                'analyze_response_times': self.chain_detection.analyze_response_times,
                'analyze_geographic_hops': self.chain_detection.analyze_geographic_hops,
                'analyze_ssl_chains': self.chain_detection.analyze_ssl_chains,
                'enable_risk_scoring': self.chain_detection.enable_risk_scoring,
                'penalize_long_chains': self.chain_detection.penalize_long_chains,
                'penalize_mixed_protocols': self.chain_detection.penalize_mixed_protocols,
                'cache_chain_analysis': self.chain_detection.cache_chain_analysis,
                'chain_cache_ttl': self.chain_detection.chain_cache_ttl,
            },
            'general_security': {
                'enable_threat_analysis': self.enable_threat_analysis,
                'enable_reputation_checks': self.enable_reputation_checks,
                'enable_honeypot_detection': self.enable_honeypot_detection,
                'enable_tls_analysis': self.enable_tls_analysis,
                'honeypot_confidence_threshold': self.honeypot_confidence_threshold,
                'honeypot_analysis_timeout': self.honeypot_analysis_timeout,
                'enable_behavioral_analysis': self.enable_behavioral_analysis,
                'enable_signature_detection': self.enable_signature_detection,
                'tls_analysis_timeout': self.tls_analysis_timeout,
                'tls_target_host': self.tls_target_host,
                'tls_target_port': self.tls_target_port,
                'tls_mitm_confidence_threshold': self.tls_mitm_confidence_threshold,
                'enable_certificate_validation': self.enable_certificate_validation,
                'enable_mitm_detection': self.enable_mitm_detection,
                'require_valid_certificate_chain': self.require_valid_certificate_chain,
                'high_risk_threshold': self.high_risk_threshold,
                'critical_risk_threshold': self.critical_risk_threshold,
                'max_concurrent_security_checks': self.max_concurrent_security_checks,
                'security_analysis_timeout': self.security_analysis_timeout,
                'detailed_security_logging': self.detailed_security_logging,
                'include_security_recommendations': self.include_security_recommendations,
            }
        }