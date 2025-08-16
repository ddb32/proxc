"""Validation Configuration - Settings and enums for proxy validation"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Union, Pattern
import re

from ...proxy_core.models import ProxyProtocol


class ValidationMethod(Enum):
    """Available validation methods"""
    HTTP_GET = "http_get"
    HTTP_CONNECT = "http_connect"
    SOCKS_CONNECT = "socks_connect"
    RAW_SOCKET = "raw_socket"


class ValidationStrictness(Enum):
    """IP validation strictness levels"""
    STRICT = "strict"       # Use strict IPv4 regex (0-255 octets only)
    PERMISSIVE = "permissive"  # Use permissive regex + ipaddress validation
    LOOSE = "loose"         # Basic format checking only


class FailureReason(Enum):
    """Detailed failure reasons for better debugging"""
    TIMEOUT_CONNECT = "timeout_connect"
    TIMEOUT_READ = "timeout_read"
    TIMEOUT_TOTAL = "timeout_total"
    CONNECTION_REFUSED = "connection_refused"
    CONNECTION_RESET = "connection_reset"
    NETWORK_UNREACHABLE = "network_unreachable"
    DNS_RESOLUTION = "dns_resolution"
    INVALID_RESPONSE = "invalid_response"
    AUTH_REQUIRED = "auth_required"
    AUTH_FAILED = "auth_failed"
    SSL_ERROR = "ssl_error"
    PROXY_ERROR = "proxy_error"
    CAPTIVE_PORTAL = "captive_portal"
    DECEPTIVE_RESPONSE = "deceptive_response"
    PROTOCOL_ERROR = "protocol_error"
    HOST_UNREACHABLE = "host_unreachable"
    UNKNOWN_ERROR = "unknown_error"
    # Target-specific failure reasons
    TARGET_BLOCKED = "target_blocked"
    TARGET_CONTENT_MISMATCH = "target_content_mismatch"
    TARGET_HEADERS_MISSING = "target_headers_missing"
    TARGET_STATUS_INVALID = "target_status_invalid"


class TargetTestType(Enum):
    """Types of target website tests"""
    BASIC_ACCESS = "basic_access"           # Simple HTTP request success
    CONTENT_VALIDATION = "content_validation"  # Check response content
    HEADER_VALIDATION = "header_validation"    # Check specific headers
    STATUS_CODE = "status_code"                # Validate HTTP status
    RESPONSE_TIME = "response_time"            # Check response speed
    GEO_BLOCKING = "geo_blocking"              # Test geographic restrictions
    LOGIN_TEST = "login_test"                  # Test authenticated access


class TargetSuccessMetric(Enum):
    """Success metrics for target testing"""
    ALL_PASS = "all_pass"                      # All tests must pass
    MAJORITY_PASS = "majority_pass"            # >50% of tests pass
    ANY_PASS = "any_pass"                      # At least one test passes
    WEIGHTED_SCORE = "weighted_score"          # Weighted score threshold


# Test endpoints for different validation scenarios
VALIDATION_TEST_ENDPOINTS = {
    'ip_check': [
        'http://httpbin.org/ip',
        'http://api.ipify.org?format=json',
        'http://checkip.amazonaws.com',
        'http://icanhazip.com',
        'http://ifconfig.me/ip'
    ],
    'headers_check': [
        'http://httpbin.org/headers',
        'http://httpbin.org/get'
    ],
    'https_check': [
        'https://httpbin.org/ip',
        'https://api.ipify.org?format=json'
    ],
    'speed_test': [
        'http://httpbin.org/bytes/1024',  # 1KB
        'http://httpbin.org/bytes/10240'  # 10KB  
    ]
}

# IPv6 test endpoints
IPV6_TEST_ENDPOINTS = [
    'http://v6.ipv6-test.com/api/myip.php',
    'http://ipv6.icanhazip.com'
]

# Common proxy ports by protocol
COMMON_PROXY_PORTS = {
    ProxyProtocol.HTTP: [8080, 3128, 8118, 8888, 80, 8000, 8008],
    ProxyProtocol.HTTPS: [8443, 443, 8080, 3128],
    ProxyProtocol.SOCKS4: [1080, 1081, 9050],
    ProxyProtocol.SOCKS5: [1080, 1081, 1085, 9050, 9150]
}


@dataclass
class TargetTestConfig:
    """Configuration for testing a specific target website"""
    
    # Basic settings
    url: str
    name: Optional[str] = None
    description: Optional[str] = None
    
    # Test types to perform
    test_types: List[TargetTestType] = field(default_factory=lambda: [TargetTestType.BASIC_ACCESS])
    
    # Success criteria
    success_metric: TargetSuccessMetric = TargetSuccessMetric.ALL_PASS
    success_threshold: float = 0.8  # For weighted/majority scoring
    
    # HTTP request settings
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[str] = None
    params: Dict[str, str] = field(default_factory=dict)
    
    # Validation rules
    expected_status_codes: List[int] = field(default_factory=lambda: [200])
    required_headers: Dict[str, str] = field(default_factory=dict)
    content_patterns: List[str] = field(default_factory=list)  # Regex patterns
    content_must_contain: List[str] = field(default_factory=list)
    content_must_not_contain: List[str] = field(default_factory=list)
    
    # Performance criteria
    max_response_time: Optional[float] = None
    min_content_length: Optional[int] = None
    max_content_length: Optional[int] = None
    
    # Geo-blocking detection
    expected_geo_countries: List[str] = field(default_factory=list)  # ISO country codes
    blocked_geo_countries: List[str] = field(default_factory=list)
    
    # Authentication
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_token: Optional[str] = None
    
    # Weights for scoring (when using WEIGHTED_SCORE)
    test_weights: Dict[TargetTestType, float] = field(default_factory=lambda: {
        TargetTestType.BASIC_ACCESS: 1.0,
        TargetTestType.CONTENT_VALIDATION: 0.8,
        TargetTestType.HEADER_VALIDATION: 0.6,
        TargetTestType.STATUS_CODE: 0.9,
        TargetTestType.RESPONSE_TIME: 0.7,
        TargetTestType.GEO_BLOCKING: 0.5,
        TargetTestType.LOGIN_TEST: 0.9
    })
    
    # Retry settings for this target
    max_retries: int = 3
    retry_delay: float = 1.0
    
    # Enable/disable for this target
    enabled: bool = True
    
    def get_compiled_patterns(self) -> List[Pattern]:
        """Get compiled regex patterns for content validation"""
        return [re.compile(pattern, re.IGNORECASE) for pattern in self.content_patterns]


@dataclass 
class TargetTestResult:
    """Result of testing a proxy against a target website"""
    
    target_name: str
    target_url: str
    success: bool
    overall_score: float = 0.0
    
    # Individual test results
    test_results: Dict[TargetTestType, bool] = field(default_factory=dict)
    test_scores: Dict[TargetTestType, float] = field(default_factory=dict)
    test_details: Dict[TargetTestType, str] = field(default_factory=dict)
    
    # Response details
    status_code: Optional[int] = None
    response_time: Optional[float] = None
    content_length: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    
    # Error information
    error_message: Optional[str] = None
    failure_reason: Optional[FailureReason] = None
    
    # Geo information
    detected_country: Optional[str] = None
    geo_blocked: Optional[bool] = None


# Predefined target configurations for common scenarios
PREDEFINED_TARGETS = {
    'google': TargetTestConfig(
        url='https://www.google.com',
        name='Google Search',
        test_types=[TargetTestType.BASIC_ACCESS, TargetTestType.CONTENT_VALIDATION],
        content_must_contain=['Google', 'search'],
        max_response_time=10.0
    ),
    
    'social_media': TargetTestConfig(
        url='https://twitter.com',
        name='Social Media (Twitter)',
        test_types=[TargetTestType.BASIC_ACCESS, TargetTestType.GEO_BLOCKING],
        expected_status_codes=[200, 302],
        max_response_time=15.0
    ),
    
    'streaming': TargetTestConfig(
        url='https://www.netflix.com',
        name='Streaming Service (Netflix)',
        test_types=[TargetTestType.BASIC_ACCESS, TargetTestType.GEO_BLOCKING],
        success_metric=TargetSuccessMetric.ANY_PASS,
        max_response_time=20.0
    ),
    
    'e_commerce': TargetTestConfig(
        url='https://www.amazon.com',
        name='E-commerce (Amazon)',
        test_types=[TargetTestType.BASIC_ACCESS, TargetTestType.CONTENT_VALIDATION],
        content_must_contain=['Amazon'],
        max_response_time=15.0
    ),
    
    'news': TargetTestConfig(
        url='https://www.bbc.com',
        name='News Site (BBC)',
        test_types=[TargetTestType.BASIC_ACCESS, TargetTestType.GEO_BLOCKING],
        expected_status_codes=[200],
        max_response_time=10.0
    )
}


@dataclass
class ValidationConfig:
    """Enhanced validation configuration with comprehensive settings"""
    
    # Timeout settings (seconds)
    connect_timeout: float = 10.0
    read_timeout: float = 20.0
    total_timeout: float = 30.0
    dns_timeout: float = 5.0
    
    # New features from NEXT_VERSION.md
    custom_test_url: Optional[str] = "https://httpbin.org/ip"  # Custom URL testing
    via_proxy: Optional[str] = None  # Proxy chaining (host:port)
    rate_limit_rps: Optional[float] = None  # Rate limiting (requests per second)
    session_log_file: Optional[str] = None  # Session logging file path
    
    # Target website testing
    target_configs: List[TargetTestConfig] = field(default_factory=list)
    enable_target_testing: bool = False
    target_success_threshold: float = 0.7  # Overall success rate for proxy to pass
    target_parallel_testing: bool = True   # Test targets in parallel
    target_fail_fast: bool = False         # Stop on first target failure
    
    # Retry settings
    max_retries: int = 3
    retry_delay: float = 1.0
    backoff_factor: float = 1.5
    retry_on_failure_reasons: List[FailureReason] = field(default_factory=lambda: [
        FailureReason.TIMEOUT_CONNECT,
        FailureReason.CONNECTION_RESET,
        FailureReason.NETWORK_UNREACHABLE
    ])
    
    # Concurrency settings
    max_workers: int = 20
    min_workers: int = 5
    use_asyncio: bool = True  # Default to async validation for better performance
    max_concurrent_async: int = 100  # Max concurrent async operations
    
    # Validation method preferences by protocol
    validation_methods: Dict[ProxyProtocol, List[ValidationMethod]] = field(default_factory=lambda: {
        ProxyProtocol.HTTP: [ValidationMethod.HTTP_GET, ValidationMethod.RAW_SOCKET],
        ProxyProtocol.HTTPS: [ValidationMethod.HTTP_GET, ValidationMethod.RAW_SOCKET],
        ProxyProtocol.SOCKS4: [ValidationMethod.SOCKS_CONNECT, ValidationMethod.RAW_SOCKET],
        ProxyProtocol.SOCKS5: [ValidationMethod.SOCKS_CONNECT, ValidationMethod.RAW_SOCKET]
    })
    
    # Test endpoints configuration
    test_endpoints: Dict[str, List[str]] = field(default_factory=lambda: VALIDATION_TEST_ENDPOINTS)
    enable_ipv6_testing: bool = True
    enable_https_testing: bool = True
    enable_anonymity_testing: bool = True
    enable_speed_testing: bool = True
    enable_geolocation_check: bool = True
    
    # User agents for testing
    user_agents: List[str] = field(default_factory=lambda: [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0'
    ])
    
    # Response validation settings
    allow_redirects: bool = True
    max_redirects: int = 5
    verify_ssl: bool = False  # Disabled for proxy testing
    check_proxy_headers: bool = True
    detect_captive_portals: bool = True
    detect_deceptive_responses: bool = True
    
    # Smart Caching Configuration
    enable_validation_cache: bool = False   # Enable validation result caching
    cache_ttl: int = 3600                  # Default cache TTL in seconds
    cache_memory_mb: Optional[int] = None  # Max cache memory (auto-calculated if None)
    cache_enable_auto_sizing: bool = True  # Enable dynamic cache sizing
    cache_stats: bool = False              # Show cache statistics
    
    # Chain Detection Configuration
    enable_chain_detection: bool = False    # Enable proxy chain detection
    chain_detection_samples: int = 3        # Number of samples for timing analysis
    chain_max_depth: int = 5               # Maximum acceptable chain depth
    chain_timeout: float = 15.0            # Timeout for chain detection
    chain_confidence_threshold: float = 0.7  # Minimum confidence for chain detection
    
    # Performance thresholds
    max_acceptable_response_time: float = 30.0  # seconds
    min_download_speed: float = 1024  # bytes/second (1KB/s)
    
    # Special testing features
    enable_protocol_detection: bool = True
    enable_dns_leak_detection: bool = False  # Requires external service
    enable_webrtc_leak_detection: bool = False  # Requires browser automation
    
    # Logging and debugging
    log_failed_validations: bool = True
    detailed_error_reporting: bool = False
    save_response_samples: bool = False
    
    @classmethod
    def create_fast_config(cls) -> 'ValidationConfig':
        """Create configuration optimized for speed"""
        return cls(
            connect_timeout=3.0,
            read_timeout=6.0,
            total_timeout=10.0,
            dns_timeout=2.0,
            max_retries=1,
            retry_delay=0.1,
            backoff_factor=1.0,
            max_workers=50,
            max_concurrent_async=200,
            use_asyncio=True,
            enable_anonymity_testing=False,
            enable_speed_testing=False,
            enable_geolocation_check=False,
            enable_ipv6_testing=False,
            enable_https_testing=False,
            check_proxy_headers=False,
            detect_captive_portals=False,
            detect_deceptive_responses=False,
            enable_chain_detection=False,
            enable_target_testing=False,
            allow_redirects=False,
            max_redirects=0,
            verify_ssl=False,
            detailed_error_reporting=False,
            save_response_samples=False,
            log_failed_validations=False
        )
    
    @classmethod
    def create_professional_config(cls) -> 'ValidationConfig':
        """Create configuration for professional-grade high-speed scanning"""
        return cls(
            # Aggressive timeouts for maximum throughput
            connect_timeout=2.5,
            read_timeout=5.0,
            total_timeout=8.0,
            dns_timeout=1.5,
            
            # Minimal retries for speed
            max_retries=1,
            retry_delay=0.05,
            backoff_factor=1.0,
            
            # Maximum concurrency
            max_workers=75,
            max_concurrent_async=300,
            use_asyncio=True,
            
            # Disable non-essential features for speed
            enable_anonymity_testing=False,
            enable_speed_testing=False,
            enable_geolocation_check=False,
            enable_ipv6_testing=False,
            enable_https_testing=False,
            check_proxy_headers=False,
            detect_captive_portals=False,
            detect_deceptive_responses=False,
            enable_chain_detection=False,
            enable_target_testing=False,
            
            # Optimized HTTP settings
            allow_redirects=False,
            max_redirects=0,
            verify_ssl=False,
            
            # Minimal logging for performance
            detailed_error_reporting=False,
            save_response_samples=False,
            log_failed_validations=False,
            
            # Fast test endpoints
            test_endpoints={'ip_check': ['http://checkip.amazonaws.com', 'http://icanhazip.com']},
            
            # Single fast user agent
            user_agents=['Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36']
        )
    
    @classmethod
    def create_thorough_config(cls) -> 'ValidationConfig':
        """Create configuration for comprehensive testing"""
        return cls(
            connect_timeout=15.0,
            read_timeout=30.0,
            total_timeout=45.0,
            max_retries=5,
            enable_anonymity_testing=True,
            enable_speed_testing=True,
            enable_geolocation_check=True,
            check_proxy_headers=True,
            detect_captive_portals=True,
            detect_deceptive_responses=True,
            detailed_error_reporting=True
        )
    
    def add_target_config(self, config: TargetTestConfig):
        """Add a target configuration for testing"""
        self.target_configs.append(config)
        self.enable_target_testing = True
    
    def add_predefined_target(self, target_name: str):
        """Add a predefined target configuration"""
        if target_name in PREDEFINED_TARGETS:
            self.add_target_config(PREDEFINED_TARGETS[target_name])
        else:
            raise ValueError(f"Unknown predefined target: {target_name}")
    
    def add_custom_target(self, url: str, name: Optional[str] = None, **kwargs):
        """Add a custom target configuration"""
        config = TargetTestConfig(url=url, name=name or url, **kwargs)
        self.add_target_config(config)
    
    def get_enabled_targets(self) -> List[TargetTestConfig]:
        """Get list of enabled target configurations"""
        return [target for target in self.target_configs if target.enabled]