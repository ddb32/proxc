"""
Proxy Hunter Validators - Enhanced Robust Version
Improved proxy validation system with comprehensive protocol support,
concurrency, resilience, and structured logging for long-running sessions.

Version: 3.1.0-ENHANCED
Author: Proxy Hunter Development Team
"""

import asyncio
import ipaddress
import json
import logging
import random
import re
import signal
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Union, Tuple
from urllib.parse import urlparse

# Third-party imports
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("❌ requests library required. Install with: pip install requests")
    sys.exit(1)

try:
    import aiohttp
    import asyncio
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import socks
    import sockshandler
    HAS_SOCKS = True
except ImportError:
    try:
        import PySocks as socks
        HAS_SOCKS = True
    except ImportError:
        HAS_SOCKS = False

try:
    import geoip2.database
    import geoip2.errors
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False

# Core imports
from ..proxy_core.models import (
    ProxyInfo, ProxyProtocol, AnonymityLevel, 
    ProxyStatus, ValidationStatus, ThreatLevel, GeoLocation
)
from ..proxy_core.config import ConfigManager
from ..proxy_core.utils import validate_ip_address

# Setup logging
logger = logging.getLogger(__name__)


# ===============================================================================
# IP ADDRESS VALIDATION PATTERNS
# ===============================================================================

# Strict IPv4: Matches only valid octets (0-255)
STRICT_IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
# Permissive IPv4: Current behavior (allows invalid octets, validated later)
PERMISSIVE_IPV4_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
# IPv6 Pattern: Basic IPv6 format matching
IPV6_PATTERN = r'(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}'

# Pre-compiled patterns for better performance
COMPILED_IP_PATTERNS = {
    'ipv4_strict': re.compile(STRICT_IPV4_PATTERN),
    'ipv4_permissive': re.compile(PERMISSIVE_IPV4_PATTERN),
    'ipv6': re.compile(IPV6_PATTERN)
}


def extract_ip_from_text(text: str, strict: bool = True, include_ipv6: bool = False) -> Optional[str]:
    """Centralized IP extraction utility with enhanced validation
    
    Args:
        text: Text to extract IP from
        strict: Use strict IPv4 pattern (True) or permissive pattern (False)
        include_ipv6: Also attempt IPv6 extraction
        
    Returns:
        First valid IP address found, or None
    """
    # Try JSON parsing first for structured responses
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            # Common JSON fields that contain IP addresses
            ip_fields = ['ip', 'origin', 'your_ip', 'client_ip', 'remote_addr', 'clientip', 'address']
            for field in ip_fields:
                if field in data:
                    ip = str(data[field]).split(',')[0].strip()
                    # Try IPv4 first
                    if validate_ip_address(ip):
                        return ip
                    # Try IPv6 if enabled
                    if include_ipv6:
                        try:
                            ipaddress.IPv6Address(ip)
                            return ip
                        except ipaddress.AddressValueError:
                            continue
    except (json.JSONDecodeError, TypeError):
        pass
    
    # Enhanced regex pattern matching with pre-compiled patterns
    # Try IPv4 first
    pattern_key = 'ipv4_strict' if strict else 'ipv4_permissive'
    pattern = COMPILED_IP_PATTERNS[pattern_key]
    matches = pattern.findall(text)
    
    for match in matches:
        if validate_ip_address(match):
            return match
    
    # Try IPv6 if enabled and no IPv4 found
    if include_ipv6:
        ipv6_matches = COMPILED_IP_PATTERNS['ipv6'].findall(text)
        for match in ipv6_matches:
            try:
                ipaddress.IPv6Address(match)
                return match
            except ipaddress.AddressValueError:
                continue
    
    # If strict mode didn't find anything, try permissive as fallback
    if strict:
        return extract_ip_from_text(text, strict=False, include_ipv6=include_ipv6)
        
    return None


# ===============================================================================
# VALIDATION ENUMS AND CONSTANTS
# ===============================================================================

class ValidationMethod(Enum):
    """Available validation methods"""
    HTTP_GET = "http_get"
    HTTP_CONNECT = "http_connect"
    SOCKS_CONNECT = "socks_connect"
    RAW_SOCKET = "raw_socket"


class FailureReason(Enum):
    """Detailed failure reasons for better debugging"""
    TIMEOUT_CONNECT = "timeout_connect"
    TIMEOUT_READ = "timeout_read"
    TIMEOUT_TOTAL = "timeout_total"
    CONNECTION_REFUSED = "connection_refused"
    CONNECTION_RESET = "connection_reset"
    DNS_RESOLUTION = "dns_resolution"
    INVALID_RESPONSE = "invalid_response"
    AUTH_REQUIRED = "auth_required"
    AUTH_FAILED = "auth_failed"
    PROXY_ERROR = "proxy_error"
    SSL_ERROR = "ssl_error"
    CAPTIVE_PORTAL = "captive_portal"
    DECEPTIVE_RESPONSE = "deceptive_response"
    PROTOCOL_ERROR = "protocol_error"
    NETWORK_UNREACHABLE = "network_unreachable"
    HOST_UNREACHABLE = "host_unreachable"
    UNKNOWN_ERROR = "unknown_error"


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


# ===============================================================================
# ENHANCED CONFIGURATION
# ===============================================================================

@dataclass
class ValidationConfig:
    """Enhanced validation configuration with comprehensive settings"""
    
    # Timeout settings (seconds)
    connect_timeout: float = 10.0
    read_timeout: float = 20.0
    total_timeout: float = 30.0
    dns_timeout: float = 5.0
    
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
    custom_test_url: Optional[str] = None  # Custom URL for validation testing
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
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0'
    ])
    
    # Security settings
    verify_ssl: bool = False
    allow_redirects: bool = True
    max_redirects: int = 3
    
    # Advanced settings
    check_proxy_headers: bool = True
    detect_captive_portals: bool = True
    detect_deceptive_responses: bool = True
    minimum_anonymity_level: Optional[AnonymityLevel] = None
    required_country_codes: Optional[List[str]] = None
    excluded_country_codes: Optional[List[str]] = None
    
    # Logging settings
    log_successful_validations: bool = True
    log_failed_validations: bool = True
    log_detailed_errors: bool = True
    log_performance_metrics: bool = True


# ===============================================================================
# ENHANCED VALIDATION RESULT
# ===============================================================================

@dataclass
class ValidationResult:
    """Enhanced validation result with comprehensive information"""
    proxy_id: str
    is_valid: bool = False
    
    # Performance metrics
    response_time: Optional[float] = None  # milliseconds
    connect_time: Optional[float] = None   # milliseconds
    dns_time: Optional[float] = None       # milliseconds
    bytes_transferred: int = 0
    download_speed: Optional[float] = None  # bytes/second
    
    # Error information
    failure_reason: Optional[FailureReason] = None
    error_message: Optional[str] = None
    error_details: Dict[str, Any] = field(default_factory=dict)
    
    # Anonymity analysis
    anonymity_level: Optional[AnonymityLevel] = None
    real_ip_detected: Optional[str] = None
    proxy_ip_detected: Optional[str] = None
    headers_analysis: Dict[str, Any] = field(default_factory=dict)
    
    # Geographic information
    geo_location: Optional[GeoLocation] = None
    
    # Protocol-specific results
    protocol_tested: Optional[ProxyProtocol] = None
    validation_method: Optional[ValidationMethod] = None
    supports_https: Optional[bool] = None
    supports_ipv6: Optional[bool] = None
    
    # Security assessment
    threat_indicators: List[str] = field(default_factory=list)
    is_suspicious: bool = False
    captive_portal_detected: bool = False
    deceptive_response_detected: bool = False
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    test_endpoint_used: Optional[str] = None
    attempts_made: int = 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for logging/storage"""
        return {
            'proxy_id': self.proxy_id,
            'is_valid': self.is_valid,
            'response_time': self.response_time,
            'connect_time': self.connect_time,
            'dns_time': self.dns_time,
            'bytes_transferred': self.bytes_transferred,
            'download_speed': self.download_speed,
            'failure_reason': self.failure_reason.value if self.failure_reason else None,
            'error_message': self.error_message,
            'error_details': self.error_details,
            'anonymity_level': self.anonymity_level.value if self.anonymity_level else None,
            'real_ip_detected': self.real_ip_detected,
            'proxy_ip_detected': self.proxy_ip_detected,
            'headers_analysis': self.headers_analysis,
            'geo_location': self.geo_location.to_dict() if self.geo_location else None,
            'protocol_tested': self.protocol_tested.value if self.protocol_tested else None,
            'validation_method': self.validation_method.value if self.validation_method else None,
            'supports_https': self.supports_https,
            'supports_ipv6': self.supports_ipv6,
            'threat_indicators': self.threat_indicators,
            'is_suspicious': self.is_suspicious,
            'captive_portal_detected': self.captive_portal_detected,
            'deceptive_response_detected': self.deceptive_response_detected,
            'timestamp': self.timestamp.isoformat(),
            'test_endpoint_used': self.test_endpoint_used,
            'attempts_made': self.attempts_made
        }


# ===============================================================================
# IP ADDRESS UTILITIES
# ===============================================================================

def is_ipv4(address: str) -> bool:
    """Check if address is IPv4"""
    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        return False


def is_ipv6(address: str) -> bool:
    """Check if address is IPv6"""
    try:
        ipaddress.IPv6Address(address)
        return True
    except ipaddress.AddressValueError:
        return False


def is_private_ip(address: str) -> bool:
    """Check if IP address is private"""
    try:
        ip = ipaddress.ip_address(address)
        return ip.is_private
    except ipaddress.AddressValueError:
        return False


def get_real_ip(session: requests.Session, timeout: float = 5.0) -> Optional[str]:
    """Get real IP address for anonymity comparison using multiple endpoints"""
    test_urls = [
        'http://api.ipify.org?format=json',
        'http://httpbin.org/ip', 
        'http://checkip.amazonaws.com',
        'http://icanhazip.com',
        'http://ifconfig.me/ip'
    ]
    
    for url in test_urls:
        try:
            response = session.get(url, timeout=timeout)
            if response.status_code == 200:
                # Try JSON parsing first
                if 'json' in response.headers.get('content-type', ''):
                    try:
                        data = response.json()
                        ip = data.get('ip') or data.get('origin', '').split(',')[0].strip()
                        if ip and validate_ip_address(ip):
                            return ip
                    except Exception:
                        pass
                
                # Fallback to text parsing
                text_ip = response.text.strip()
                if validate_ip_address(text_ip):
                    return text_ip
        except Exception:
            continue
    
    return None


# ===============================================================================
# ENHANCED PROXY VALIDATOR
# ===============================================================================

class EnhancedProxyValidator:
    """Enhanced proxy validator with comprehensive protocol support"""
    
    def __init__(self, config: Optional[ValidationConfig] = None):
        self.config = config or ValidationConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._real_ip = None
        self._real_ipv6 = None
        self._shutdown = False
        self._session_cache = {}
        
        # Setup requests session with enhanced configuration
        self.session = self._create_session()
        
        # GeoIP database if available
        self.geoip_reader = None
        self._init_geoip()
        
        # Signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self.logger.info("Enhanced proxy validator initialized")
    
    def _create_session(self) -> requests.Session:
        """Create optimized requests session with enhanced configuration"""
        session = requests.Session()
        
        # Configure retries with extended status codes
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504, 520, 521, 522, 523, 524]
        )
        
        # Enhanced adapter configuration
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=max(self.config.max_workers, 10),
            pool_maxsize=max(self.config.max_workers * 2, 20)
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Optimized headers for better compatibility
        session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        return session
    
    def _init_geoip(self):
        """Initialize GeoIP database if available"""
        if HAS_GEOIP2:
            try:
                # Try common GeoIP database locations
                geoip_paths = [
                    '/usr/share/GeoIP/GeoLite2-City.mmdb',
                    '/var/lib/GeoIP/GeoLite2-City.mmdb',
                    './GeoLite2-City.mmdb',
                    '/opt/GeoIP/GeoLite2-City.mmdb'
                ]
                
                for path in geoip_paths:
                    try:
                        self.geoip_reader = geoip2.database.Reader(path)
                        self.logger.info(f"GeoIP database loaded from {path}")
                        break
                    except FileNotFoundError:
                        continue
                    except Exception as e:
                        self.logger.debug(f"Failed to load GeoIP from {path}: {e}")
                        
            except Exception as e:
                self.logger.warning(f"GeoIP initialization failed: {e}")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info("🛑 Received shutdown signal, stopping validation...")
        self._shutdown = True
    
    def validate_proxy(self, proxy: ProxyInfo) -> ValidationResult:
        """Validate a single proxy with comprehensive testing"""
        result = ValidationResult(proxy_id=proxy.proxy_id)
        result.protocol_tested = proxy.protocol
        
        if self._shutdown:
            result.failure_reason = FailureReason.UNKNOWN_ERROR
            result.error_message = "Validation stopped by user"
            return result
        
        start_time = time.time()
        
        try:
            # Get validation methods for this protocol
            methods = self.config.validation_methods.get(
                proxy.protocol, 
                [ValidationMethod.RAW_SOCKET]
            )
            
            # Try each validation method until one succeeds
            for method in methods:
                try:
                    success = self._validate_with_method(proxy, result, method)
                    if success:
                        result.is_valid = True
                        result.validation_method = method
                        break
                except Exception as e:
                    self.logger.debug(f"Method {method.value} failed for {proxy.address}: {e}")
                    continue
            
            # Additional tests for valid proxies
            if result.is_valid:
                self._perform_additional_tests(proxy, result)
            
        except Exception as e:
            result.failure_reason = FailureReason.UNKNOWN_ERROR
            result.error_message = str(e)
            self.logger.error(f"Validation failed for {proxy.address}: {e}")
        
        # Calculate total time
        total_time = (time.time() - start_time) * 1000
        if not result.response_time:
            result.response_time = total_time
        
        # Update proxy status
        self._update_proxy_status(proxy, result)
        
        # Log result if configured
        if self.config.log_successful_validations and result.is_valid:
            self.logger.info(f"✅ {proxy.address} validated successfully ({result.response_time:.0f}ms)")
        elif self.config.log_failed_validations and not result.is_valid:
            self.logger.debug(f"❌ {proxy.address} validation failed: {result.failure_reason}")
        
        return result
    
    def _validate_with_method(self, proxy: ProxyInfo, result: ValidationResult, 
                            method: ValidationMethod) -> bool:
        """Validate proxy using specific method"""
        
        if method == ValidationMethod.HTTP_GET:
            return self._validate_http_get(proxy, result)
        elif method == ValidationMethod.HTTP_CONNECT:
            return self._validate_http_connect(proxy, result)
        elif method == ValidationMethod.SOCKS_CONNECT:
            return self._validate_socks_connect(proxy, result)
        elif method == ValidationMethod.RAW_SOCKET:
            return self._validate_raw_socket(proxy, result)
        else:
            raise ValueError(f"Unknown validation method: {method}")
    
    def _validate_http_get(self, proxy: ProxyInfo, result: ValidationResult) -> bool:
        """Validate HTTP/HTTPS proxy using GET request"""
        proxy_dict = self._build_proxy_dict(proxy)
        # Use custom test URL if provided, otherwise use default random endpoint
        test_url = self.config.custom_test_url or random.choice(self.config.test_endpoints['ip_check'])
        
        start_time = time.time()
        
        try:
            response = self.session.get(
                test_url,
                proxies=proxy_dict,
                timeout=(self.config.connect_timeout, self.config.read_timeout),
                headers={'User-Agent': random.choice(self.config.user_agents)},
                verify=self.config.verify_ssl,
                allow_redirects=self.config.allow_redirects
            )
            
            response_time = (time.time() - start_time) * 1000
            result.response_time = response_time
            result.test_endpoint_used = test_url
            result.bytes_transferred = len(response.content)
            
            if response.status_code == 200:
                # Check for captive portal or deceptive responses
                if self.config.detect_captive_portals:
                    if self._detect_captive_portal(response):
                        result.captive_portal_detected = True
                        result.failure_reason = FailureReason.CAPTIVE_PORTAL
                        return False
                
                if self.config.detect_deceptive_responses:
                    if self._detect_deceptive_response(response, test_url):
                        result.deceptive_response_detected = True
                        result.failure_reason = FailureReason.DECEPTIVE_RESPONSE
                        return False
                
                # Analyze anonymity if enabled
                if self.config.enable_anonymity_testing:
                    self._analyze_anonymity(proxy, response, result)
                
                return True
            else:
                result.failure_reason = FailureReason.INVALID_RESPONSE
                result.error_message = f"HTTP {response.status_code}"
                return False
                
        except requests.exceptions.ConnectTimeout:
            result.failure_reason = FailureReason.TIMEOUT_CONNECT
            result.error_message = "Connection timeout"
            self.logger.debug(f"Connection timeout for {proxy.address}")
        except requests.exceptions.ReadTimeout:
            result.failure_reason = FailureReason.TIMEOUT_READ
            result.error_message = "Read timeout"
            self.logger.debug(f"Read timeout for {proxy.address}")
        except requests.exceptions.Timeout:
            result.failure_reason = FailureReason.TIMEOUT_TOTAL
            result.error_message = "Request timeout"
            self.logger.debug(f"Total timeout for {proxy.address}")
        except requests.exceptions.ConnectionError as e:
            error_str = str(e).lower()
            if "refused" in error_str:
                result.failure_reason = FailureReason.CONNECTION_REFUSED
                result.error_message = "Connection refused"
            elif "reset" in error_str or "broken pipe" in error_str:
                result.failure_reason = FailureReason.CONNECTION_RESET
                result.error_message = "Connection reset"
            elif "unreachable" in error_str:
                result.failure_reason = FailureReason.NETWORK_UNREACHABLE
                result.error_message = "Network unreachable"
            else:
                result.failure_reason = FailureReason.PROXY_ERROR
                result.error_message = f"Connection error: {str(e)[:100]}"
            self.logger.debug(f"Connection error for {proxy.address}: {result.error_message}")
        except requests.exceptions.SSLError as e:
            result.failure_reason = FailureReason.SSL_ERROR
            result.error_message = f"SSL error: {str(e)[:100]}"
            self.logger.debug(f"SSL error for {proxy.address}")
        except Exception as e:
            result.failure_reason = FailureReason.UNKNOWN_ERROR
            result.error_message = f"Unexpected error: {str(e)[:100]}"
            self.logger.debug(f"Unknown error for {proxy.address}: {result.error_message}")
        
        return False
    
    def _validate_http_connect(self, proxy: ProxyInfo, result: ValidationResult) -> bool:
        """Validate proxy using HTTP CONNECT method"""
        # Implementation for HTTP CONNECT validation
        # This is more complex and requires custom socket handling
        return self._validate_raw_socket(proxy, result)
    
    def _validate_socks_connect(self, proxy: ProxyInfo, result: ValidationResult) -> bool:
        """Validate SOCKS4/5 proxy"""
        if not HAS_SOCKS:
            self.logger.warning("PySocks not available, falling back to raw socket")
            return self._validate_raw_socket(proxy, result)
        
        try:
            start_time = time.time()
            
            # Configure SOCKS
            if proxy.protocol == ProxyProtocol.SOCKS4:
                socks.set_default_proxy(socks.SOCKS4, proxy.host, proxy.port)
            else:  # SOCKS5
                socks.set_default_proxy(
                    socks.SOCKS5, proxy.host, proxy.port,
                    username=proxy.username, password=proxy.password
                )
            
            # Test connection
            socket.socket = socks.socksocket
            
            # Simple connection test to a known host
            test_host, test_port = "httpbin.org", 80
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.connect_timeout)
            
            sock.connect((test_host, test_port))
            
            response_time = (time.time() - start_time) * 1000
            result.response_time = response_time
            
            sock.close()
            
            # Reset socket to default
            socket.socket = socket._original_socket
            socks.set_default_proxy()
            
            return True
            
        except socks.ProxyConnectionError:
            result.failure_reason = FailureReason.PROXY_ERROR
            result.error_message = "SOCKS proxy connection failed"
        except socket.timeout:
            result.failure_reason = FailureReason.TIMEOUT_CONNECT
            result.error_message = "SOCKS connection timeout"
        except Exception as e:
            result.failure_reason = FailureReason.UNKNOWN_ERROR
            result.error_message = f"SOCKS validation failed: {e}"
        finally:
            # Always reset socket
            try:
                socket.socket = socket._original_socket
                socks.set_default_proxy()
            except:
                pass
        
        return False
    
    def _validate_raw_socket(self, proxy: ProxyInfo, result: ValidationResult) -> bool:
        """Validate proxy using raw socket connection"""
        start_time = time.time()
        
        try:
            # Determine address family
            if is_ipv6(proxy.host):
                family = socket.AF_INET6
            else:
                family = socket.AF_INET
            
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(self.config.connect_timeout)
            
            # Connect to proxy
            connect_result = sock.connect_ex((proxy.host, proxy.port))
            
            response_time = (time.time() - start_time) * 1000
            result.response_time = response_time
            result.connect_time = response_time
            
            sock.close()
            
            if connect_result == 0:
                return True
            else:
                result.failure_reason = FailureReason.CONNECTION_REFUSED
                result.error_message = f"Socket connect failed with code {connect_result}"
                return False
                
        except socket.timeout:
            result.failure_reason = FailureReason.TIMEOUT_CONNECT
            result.error_message = "Socket connection timeout"
        except socket.gaierror:
            result.failure_reason = FailureReason.DNS_RESOLUTION
            result.error_message = "DNS resolution failed"
        except Exception as e:
            result.failure_reason = FailureReason.UNKNOWN_ERROR
            result.error_message = f"Socket validation failed: {e}"
        
        return False
    
    def _perform_additional_tests(self, proxy: ProxyInfo, result: ValidationResult):
        """Perform additional tests on valid proxies"""
        
        # HTTPS support test
        if self.config.enable_https_testing and proxy.protocol in [ProxyProtocol.HTTP, ProxyProtocol.HTTPS]:
            result.supports_https = self._test_https_support(proxy)
        
        # IPv6 support test
        if self.config.enable_ipv6_testing:
            result.supports_ipv6 = self._test_ipv6_support(proxy)
        
        # Speed test
        if self.config.enable_speed_testing:
            self._test_speed(proxy, result)
        
        # Geolocation lookup
        if self.config.enable_geolocation_check and result.proxy_ip_detected:
            result.geo_location = self._lookup_geolocation(result.proxy_ip_detected)
    
    def _test_https_support(self, proxy: ProxyInfo) -> bool:
        """Test if proxy supports HTTPS"""
        if not self.config.test_endpoints.get('https_check'):
            return False
        
        proxy_dict = self._build_proxy_dict(proxy)
        test_url = random.choice(self.config.test_endpoints['https_check'])
        
        try:
            response = self.session.get(
                test_url,
                proxies=proxy_dict,
                timeout=(self.config.connect_timeout, self.config.read_timeout),
                verify=self.config.verify_ssl
            )
            return response.status_code == 200
        except Exception:
            return False
    
    def _test_ipv6_support(self, proxy: ProxyInfo) -> bool:
        """Test if proxy supports IPv6"""
        if not is_ipv6(proxy.host):
            return False
        
        # This would require IPv6-enabled test endpoints
        # For now, just check if the proxy host is IPv6
        return True
    
    def _test_speed(self, proxy: ProxyInfo, result: ValidationResult):
        """Test proxy speed"""
        if not self.config.test_endpoints.get('speed_test'):
            return
        
        proxy_dict = self._build_proxy_dict(proxy)
        test_url = random.choice(self.config.test_endpoints['speed_test'])
        
        try:
            start_time = time.time()
            response = self.session.get(
                test_url,
                proxies=proxy_dict,
                timeout=(self.config.connect_timeout, self.config.read_timeout),
                stream=True
            )
            
            if response.status_code == 200:
                content_length = len(response.content)
                elapsed_time = time.time() - start_time
                
                if elapsed_time > 0:
                    result.download_speed = content_length / elapsed_time
                    result.bytes_transferred += content_length
        except Exception as e:
            self.logger.debug(f"Speed test failed for {proxy.address}: {e}")
    
    def _detect_captive_portal(self, response: requests.Response) -> bool:
        """Detect captive portal responses"""
        content = response.text.lower()
        
        # Common captive portal indicators
        captive_indicators = [
            'captive portal',
            'wifi login',
            'internet access',
            'click here to continue',
            'terms and conditions',
            'acceptable use policy'
        ]
        
        return any(indicator in content for indicator in captive_indicators)
    
    def _detect_deceptive_response(self, response: requests.Response, expected_url: str) -> bool:
        """Detect deceptive responses that don't match expected content"""
        
        # Check if we got redirected to a completely different domain
        if response.url and urlparse(response.url).netloc != urlparse(expected_url).netloc:
            return True
        
        # Check for common deceptive content
        content = response.text.lower()
        deceptive_indicators = [
            'this site has been blocked',
            'access denied',
            'content filter',
            'firewall',
            'proxy blocked'
        ]
        
        return any(indicator in content for indicator in deceptive_indicators)
    
    def _analyze_anonymity(self, proxy: ProxyInfo, response: requests.Response, result: ValidationResult):
        """Analyze proxy anonymity level"""
        try:
            # Get real IP if not cached
            if not self._real_ip:
                self._real_ip = get_real_ip(requests.Session(), self.config.connect_timeout)
            
            # Try to extract IP from response
            try:
                proxy_ip = None
                response_text = response.text.strip()
                
                # Try JSON parsing first
                if 'json' in response.headers.get('content-type', ''):
                    try:
                        data = response.json()
                        proxy_ip = data.get('ip') or data.get('origin', '').split(',')[0].strip()
                    except:
                        # Fall back to text parsing if JSON fails
                        proxy_ip = self._extract_ip_from_text(response_text)
                else:
                    # Extract IP from plain text response
                    proxy_ip = self._extract_ip_from_text(response_text)
                
                if proxy_ip and validate_ip_address(proxy_ip):
                    result.proxy_ip_detected = proxy_ip
                    self.logger.debug(f"Detected proxy IP: {proxy_ip}")
                else:
                    self.logger.debug(f"Failed to extract valid IP from response: {response_text[:100]}...")
                    result.proxy_ip_detected = None
                
                # Professional multi-stage anonymity analysis
                if proxy_ip and self._real_ip and self._real_ip in proxy_ip:
                    # Stage 1: Real IP is visible - definitely transparent
                    result.anonymity_level = AnonymityLevel.TRANSPARENT
                    result.real_ip_detected = self._real_ip
                    self.logger.debug(f"TRANSPARENT: Real IP {self._real_ip} detected in response")
                elif proxy_ip:
                    # Stage 2: Proxy IP detected, need header analysis for precise classification
                    result.real_ip_detected = None
                    
                    if self.config.check_proxy_headers:
                        # Professional header analysis
                        try:
                            # Use the proxy object directly for header testing
                            has_proxy_headers, header_analysis = self._has_proxy_headers(proxy, result)
                            
                            # Store detailed header analysis
                            result.headers_analysis = header_analysis
                            
                            if has_proxy_headers:
                                # Proxy headers detected - use score-based classification
                                classification = header_analysis['proxy_indicators']['classification']
                                if classification == 'elite':
                                    result.anonymity_level = AnonymityLevel.ELITE
                                elif classification == 'anonymous':
                                    result.anonymity_level = AnonymityLevel.ANONYMOUS
                                else:
                                    result.anonymity_level = AnonymityLevel.TRANSPARENT
                                
                                self.logger.debug(f"Header-based classification: {classification.upper()} "
                                                f"(score: {header_analysis['proxy_indicators']['anonymity_score']})")
                            else:
                                # No proxy headers detected - likely elite
                                result.anonymity_level = AnonymityLevel.ELITE
                                self.logger.debug("ELITE: No proxy-revealing headers detected")
                                
                        except Exception as e:
                            self.logger.debug(f"Header analysis error: {e}")
                            result.anonymity_level = AnonymityLevel.ANONYMOUS
                    else:
                        # Header checking disabled - use simple classification
                        result.anonymity_level = AnonymityLevel.ANONYMOUS
                        self.logger.debug("ANONYMOUS: Header checking disabled")
                else:
                    # Stage 3: No proxy IP detected - likely transparent or failed detection
                    result.anonymity_level = AnonymityLevel.TRANSPARENT
                    self.logger.debug("TRANSPARENT: No proxy IP detected in response")
                        
            except Exception as e:
                self.logger.debug(f"Failed to analyze anonymity: {e}")
                result.anonymity_level = AnonymityLevel.TRANSPARENT
                
        except Exception as e:
            self.logger.debug(f"Anonymity analysis failed: {e}")
    
    def _extract_ip_from_text(self, text: str, strict: bool = True, include_ipv6: bool = False) -> Optional[str]:
        """Extract IP address using centralized utility function
        
        Args:
            text: Text to extract IP from
            strict: Use strict IPv4 pattern (True) or permissive pattern (False)
            include_ipv6: Also attempt IPv6 extraction
            
        Returns:
            First valid IP address found, or None
        """
        return extract_ip_from_text(text, strict=strict, include_ipv6=include_ipv6)
    
    def _has_proxy_headers(self, proxy: ProxyInfo, result: ValidationResult) -> tuple[bool, dict]:
        """Professional proxy header detection using httpbin.org/headers
        Returns (has_proxy_headers, header_analysis)"""
        
        try:
            # Use httpbin.org/headers which echoes all received headers
            headers_endpoint = 'http://httpbin.org/headers'
            proxy_dict = self._build_proxy_dict(proxy)
            
            response = self.session.get(
                headers_endpoint,
                proxies=proxy_dict,
                timeout=(self.config.connect_timeout, self.config.read_timeout),
                headers={
                    'User-Agent': random.choice(self.config.user_agents),
                    'Accept': 'application/json,text/html,*/*',
                    'Connection': 'close'
                }
            )
            
            if response.status_code != 200:
                return False, {'error': f'Headers endpoint returned {response.status_code}'}
            
            # Parse the response to get the headers that were sent
            try:
                headers_data = response.json()
                received_headers = headers_data.get('headers', {})
            except:
                # If not JSON, try to extract headers from text
                return False, {'error': 'Could not parse headers response'}
            
            # Analyze headers for proxy indicators
            proxy_indicators = self._analyze_proxy_headers(received_headers)
            
            # Store detailed analysis
            header_analysis = {
                'received_headers': received_headers,
                'proxy_indicators': proxy_indicators,
                'proxy_detected': len(proxy_indicators['detected']) > 0,
                'anonymity_score': proxy_indicators['anonymity_score']
            }
            
            return header_analysis['proxy_detected'], header_analysis
            
        except Exception as e:
            self.logger.debug(f"Header analysis failed for {proxy.address}: {e}")
            return False, {'error': str(e)}
    
    def _analyze_proxy_headers(self, headers: dict) -> dict:
        """Analyze headers for proxy indicators with professional scoring"""
        
        # Convert header names to lowercase for consistent checking
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Define proxy-revealing headers with severity scores
        proxy_headers = {
            'x-forwarded-for': {'score': 10, 'description': 'Client IP forwarded by proxy'},
            'x-real-ip': {'score': 10, 'description': 'Real client IP revealed'},
            'x-originating-ip': {'score': 10, 'description': 'Original client IP'},
            'x-remote-ip': {'score': 8, 'description': 'Remote IP header'},
            'x-remote-addr': {'score': 8, 'description': 'Remote address header'},
            'via': {'score': 9, 'description': 'Proxy chain information'},
            'x-proxy-connection': {'score': 7, 'description': 'Proxy connection header'},
            'proxy-connection': {'score': 7, 'description': 'Proxy connection'},
            'x-forwarded-proto': {'score': 5, 'description': 'Protocol forwarded by proxy'},
            'x-forwarded-protocol': {'score': 5, 'description': 'Protocol information'},
            'x-forwarded-host': {'score': 6, 'description': 'Host forwarded by proxy'},
            'x-forwarded-server': {'score': 6, 'description': 'Server forwarded by proxy'},
            'x-cache': {'score': 4, 'description': 'Cache information'},
            'cache-control': {'score': 2, 'description': 'Potential proxy cache control'},
            'x-squid-error': {'score': 8, 'description': 'Squid proxy error header'},
            'x-served-by': {'score': 6, 'description': 'Served by proxy header'},
            'x-cache-lookup': {'score': 4, 'description': 'Cache lookup header'},
            'x-proxy-id': {'score': 8, 'description': 'Proxy identification'}
        }
        
        detected_headers = {}
        total_score = 0
        
        # Check for proxy-revealing headers
        for header_name, header_info in proxy_headers.items():
            if header_name in headers_lower:
                detected_headers[header_name] = {
                    'value': headers_lower[header_name],
                    'score': header_info['score'],
                    'description': header_info['description']
                }
                total_score += header_info['score']
        
        # Additional analysis for specific headers
        analysis_details = []
        
        # Analyze X-Forwarded-For in detail
        if 'x-forwarded-for' in detected_headers:
            xff_value = detected_headers['x-forwarded-for']['value']
            ip_count = len([ip.strip() for ip in xff_value.split(',') if ip.strip()])
            analysis_details.append(f"X-Forwarded-For contains {ip_count} IP(s): {xff_value}")
        
        # Analyze Via header
        if 'via' in detected_headers:
            via_value = detected_headers['via']['value']
            analysis_details.append(f"Via header reveals proxy chain: {via_value}")
        
        # Calculate anonymity score (0-100, higher = more anonymous)
        # Maximum possible score from proxy headers is ~80, so normalize
        max_possible_score = 80
        anonymity_score = max(0, 100 - min(100, (total_score / max_possible_score) * 100))
        
        return {
            'detected': detected_headers,
            'total_score': total_score,
            'anonymity_score': round(anonymity_score, 1),
            'analysis_details': analysis_details,
            'header_count': len(detected_headers),
            'classification': self._classify_by_score(anonymity_score)
        }
    
    def _classify_by_score(self, anonymity_score: float) -> str:
        """Classify anonymity level based on header analysis score"""
        if anonymity_score >= 90:
            return 'elite'
        elif anonymity_score >= 70:
            return 'anonymous'
        else:
            return 'transparent'
    
    
    def _lookup_geolocation(self, ip_address: str) -> Optional[GeoLocation]:
        """Lookup geolocation for IP address with multiple fallbacks"""
        if not ip_address or not validate_ip_address(ip_address):
            return None
        
        # Skip private/local IPs as they won't have meaningful geolocation
        if is_private_ip(ip_address):
            return None
        
        try:
            # Method 1: Try NetworkIntelligence for comprehensive geo lookup
            from ..proxy_core.utils import NetworkIntelligence
            network_intel = NetworkIntelligence({'geoip_db_path': getattr(self, 'geoip_db_path', None)})
            analysis = network_intel.analyze_ip(ip_address)
            
            if analysis.country_code:
                return GeoLocation(
                    country=analysis.country_code,
                    country_code=analysis.country_code,
                    region=analysis.region,
                    city=analysis.city,
                    latitude=0.0,  # Would need additional API data
                    longitude=0.0,
                    timezone=analysis.timezone
                )
                
        except Exception as e:
            self.logger.debug(f"NetworkIntelligence lookup failed for {ip_address}: {e}")
            
        # Method 2: Fallback to GeoIP if available
        try:
            if self.geoip_reader:
                response = self.geoip_reader.city(ip_address)
                return GeoLocation(
                    country=response.country.name,
                    country_code=response.country.iso_code,
                    city=response.city.name,
                    region=response.subdivisions.most_specific.name,
                    latitude=float(response.location.latitude) if response.location.latitude else None,
                    longitude=float(response.location.longitude) if response.location.longitude else None,
                    timezone=response.location.time_zone
                )
        except Exception as e:
            self.logger.debug(f"GeoIP lookup failed for {ip_address}: {e}")
        
        # Method 3: Try free API-based geolocation as last resort (disabled for performance)
        # Uncomment the lines below to enable API-based geolocation lookup
        try:
            return self._api_geolocation_lookup(ip_address)
        except Exception as e:
            self.logger.debug(f"API geolocation lookup failed for {ip_address}: {e}")
            
        return None
    
    def _api_geolocation_lookup(self, ip_address: str) -> Optional[GeoLocation]:
        """Use free API services for geolocation lookup"""
        import requests
        import time
        
        # List of free API services (with rate limiting in mind)
        apis = [
            {
                'url': f'http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,region,regionName,city,timezone',
                'parser': self._parse_ip_api_response
            },
            {
                'url': f'https://ipapi.co/{ip_address}/json/',
                'parser': self._parse_ipapi_response
            },
            {
                'url': f'http://ipwhois.app/json/{ip_address}',
                'parser': self._parse_ipwhois_response
            },
            { 
                'url': f'https://api.ipgeolocation.io/ipgeo?apiKey=9fc53ecef2e342f99a81e9193a57ef38&ip={ip_address}',
                'parser': self._parse_ipgeolocation_response
            }
        ]
        
        for api in apis:
            try:
                # Add a small delay to respect rate limits
                time.sleep(0.1)
                
                response = requests.get(
                    api['url'], 
                    timeout=5,
                    headers={'User-Agent': 'ProxyHunter/1.0'}
                )
                
                if response.status_code == 200:
                    geo_data = api['parser'](response.json())
                    if geo_data:
                        return geo_data
                        
            except Exception as e:
                self.logger.debug(f"API {api['url']} failed: {e}")
                continue
        
        return None
    
    def _parse_ip_api_response(self, data: dict) -> Optional[GeoLocation]:
        """Parse ip-api.com response"""
        if data.get('status') == 'success':
            return GeoLocation(
                country=data.get('country'),
                country_code=data.get('countryCode'),
                region=data.get('regionName'),
                city=data.get('city'),
                latitude=0.0,
                longitude=0.0,
                timezone=data.get('timezone')
            )
        return None
    
    def _parse_ipapi_response(self, data: dict) -> Optional[GeoLocation]:
        """Parse ipapi.co response"""
        if not data.get('error'):
            return GeoLocation(
                country=data.get('country_name'),
                country_code=data.get('country_code'),
                region=data.get('region'),
                city=data.get('city'),
                latitude=data.get('latitude', 0.0) if data.get('latitude') else 0.0,
                longitude=data.get('longitude', 0.0) if data.get('longitude') else 0.0,
                timezone=data.get('timezone')
            )
        return None
    
    def _parse_ipwhois_response(self, data: dict) -> Optional[GeoLocation]:
        """Parse ipwhois.app response"""
        if data.get('success'):
            return GeoLocation(
                country=data.get('country'),
                country_code=data.get('country_code'),
                region=data.get('region'),
                city=data.get('city'),
                latitude=data.get('latitude', 0.0) if data.get('latitude') else 0.0,
                longitude=data.get('longitude', 0.0) if data.get('longitude') else 0.0,
                timezone=data.get('timezone')
            )
        return None
    
    def _parse_ipgeolocation_response(self, data: dict) -> Optional[GeoLocation]:
        """Parse ipgeolocation.io response"""
        # Check if the response contains an error or is invalid
        if 'message' in data and 'error' in data.get('message', '').lower():
            return None
        
        # ipgeolocation.io returns data directly without a success field
        if data.get('country_code2'):  # country_code2 is the standard field
            return GeoLocation(
                country=data.get('country_name'),
                country_code=data.get('country_code2'),  # Use 2-letter code
                region=data.get('state_prov'),
                city=data.get('city'),
                latitude=float(data.get('latitude', 0.0)) if data.get('latitude') else 0.0,
                longitude=float(data.get('longitude', 0.0)) if data.get('longitude') else 0.0,
                timezone=data.get('time_zone', {}).get('name') if data.get('time_zone') else None
            )
        return None
    
    def _build_proxy_dict(self, proxy: ProxyInfo) -> Dict[str, str]:
        """Build proxy dictionary for requests"""
        if proxy.username and proxy.password:
            auth = f"{proxy.username}:{proxy.password}@"
        else:
            auth = ""
        
        proxy_url = f"{proxy.protocol.value}://{auth}{proxy.host}:{proxy.port}"
        
        return {
            'http': proxy_url,
            'https': proxy_url
        }
    
    def _update_proxy_status(self, proxy: ProxyInfo, result: ValidationResult):
        """Update proxy status based on validation result"""
        if result.is_valid:
            proxy.status = ProxyStatus.ACTIVE
            proxy.validation_status = ValidationStatus.VALID
            
            if result.anonymity_level:
                proxy.anonymity_level = result.anonymity_level
            
            if result.geo_location:
                proxy.geo_location = result.geo_location
                
        else:
            proxy.status = ProxyStatus.FAILED
            proxy.validation_status = ValidationStatus.INVALID
        
        # Update metrics
        if proxy.metrics:
            proxy.metrics.last_checked = datetime.utcnow()
            if result.response_time:
                proxy.metrics.response_time = result.response_time
            proxy.metrics.update_check(result.is_valid, result.response_time, result.bytes_transferred)


# ===============================================================================
# ENHANCED BATCH VALIDATOR
# ===============================================================================

class EnhancedBatchValidator:
    """Enhanced batch validator with improved concurrency and resilience"""
    
    def __init__(self, config: Optional[ConfigManager] = None,
                 validation_config: Optional[ValidationConfig] = None):
        self.config = config or ConfigManager()
        self.validation_config = validation_config or ValidationConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._shutdown = False
        
        # Statistics tracking
        self.stats = {
            'total_processed': 0,
            'total_valid': 0,
            'total_invalid': 0,
            'total_errors': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Signal handler
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self.logger.debug("Enhanced batch validator initialized")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info("🛑 Received shutdown signal, stopping batch validation...")
        self._shutdown = True
    
    def validate_batch(self, proxies: List[ProxyInfo],
                      max_workers: Optional[int] = None,
                      progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        """Validate a batch of proxies with enhanced error handling"""
        
        if not proxies:
            return self._empty_result()
        
        # Configuration
        max_workers = max_workers or self.validation_config.max_workers
        max_workers = min(max_workers, len(proxies), 50)  # Reasonable upper limit
        
        self.stats['start_time'] = time.time()
        self.logger.debug(f"🔍 Starting batch validation of {len(proxies)} proxies with {max_workers} workers")
        
        # Result containers
        valid_proxies = []
        invalid_proxies = []
        error_proxies = []
        
        # Validation results for detailed analysis
        validation_results = []
        
        try:
            # Prefer async validation for better performance when available
            if self.validation_config.use_asyncio and HAS_AIOHTTP:
                self.logger.debug(f"🚀 Using high-performance async validation (max concurrent: {self.validation_config.max_concurrent_async})")
                results = self._validate_batch_async(proxies, max_workers, progress_callback)
            else:
                if not HAS_AIOHTTP:
                    self.logger.warning("⚠️  aiohttp not available, using sync validation (slower)")
                else:
                    self.logger.info("📊 Using sync validation (async disabled in config)")
                results = self._validate_batch_sync(proxies, max_workers, progress_callback)
            
            # Process results
            for proxy, result in results:
                validation_results.append(result)
                
                if result.is_valid:
                    valid_proxies.append(proxy)
                    self.stats['total_valid'] += 1
                elif result.failure_reason:
                    invalid_proxies.append(proxy)
                    self.stats['total_invalid'] += 1
                else:
                    error_proxies.append(proxy)
                    self.stats['total_errors'] += 1
                
                self.stats['total_processed'] += 1
                
                # Progress callback
                if progress_callback:
                    progress_callback(self.stats['total_processed'], len(proxies), result)
        
        except KeyboardInterrupt:
            self.logger.info("🛑 Batch validation interrupted by user")
        except Exception as e:
            self.logger.error(f"❌ Batch validation failed: {e}")
        
        self.stats['end_time'] = time.time()
        
        # Generate summary
        return self._generate_batch_result(
            proxies, valid_proxies, invalid_proxies, error_proxies, validation_results
        )
    
    def _validate_batch_sync(self, proxies: List[ProxyInfo], max_workers: int,
                           progress_callback: Optional[callable]) -> List[Tuple[ProxyInfo, ValidationResult]]:
        """Synchronous batch validation using ThreadPoolExecutor"""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ProxyValidator") as executor:
            # Create validator instance for each worker
            validator = EnhancedProxyValidator(self.validation_config)
            
            # Submit all validation tasks
            future_to_proxy = {
                executor.submit(validator.validate_proxy, proxy): proxy 
                for proxy in proxies
            }
            
            # Collect results with timeout handling
            for future in as_completed(future_to_proxy, 
                                     timeout=self.validation_config.total_timeout * len(proxies)):
                if self._shutdown:
                    self.logger.info("🛑 Shutdown requested, cancelling remaining tasks")
                    for f in future_to_proxy:
                        f.cancel()
                    break
                
                proxy = future_to_proxy[future]
                
                try:
                    result = future.result(timeout=self.validation_config.total_timeout)
                    results.append((proxy, result))
                    
                except Exception as e:
                    # Create error result
                    error_result = ValidationResult(proxy_id=proxy.proxy_id)
                    error_result.failure_reason = FailureReason.UNKNOWN_ERROR
                    error_result.error_message = str(e)
                    results.append((proxy, error_result))
                    
                    self.logger.error(f"❌ Validation error for {proxy.address}: {e}")
        
        return results
    
    def _validate_batch_async(self, proxies: List[ProxyInfo], max_workers: int,
                            progress_callback: Optional[callable]) -> List[Tuple[ProxyInfo, ValidationResult]]:
        """Asynchronous batch validation using high-performance async engine"""
        try:
            from .async_validators import AsyncBatchValidator, HAS_AIOHTTP
            
            if not HAS_AIOHTTP:
                self.logger.warning("aiohttp not available, falling back to sync validation")
                return self._validate_batch_sync(proxies, max_workers, progress_callback)
            
            import asyncio
            
            # Use configured max concurrent or sensible default
            max_concurrent = getattr(self.validation_config, 'max_concurrent_async', min(max_workers * 5, 100))
            
            self.logger.debug(f"🚀 Using high-performance async validation with {max_concurrent} max concurrent")
            
            # Create async validator
            async_validator = AsyncBatchValidator(self.validation_config)
            
            # Run async validation with better concurrency
            async_results = asyncio.run(
                async_validator.validate_batch_async(proxies, max_concurrent, progress_callback)
            )
            
            # Convert async results to sync format
            results = []
            for async_result in async_results:
                # Convert AsyncValidationResult to ValidationResult
                sync_result = ValidationResult(proxy_id=async_result.proxy.proxy_id)
                sync_result.is_valid = async_result.is_valid
                sync_result.response_time = async_result.response_time
                sync_result.connect_time = async_result.connect_time
                sync_result.bytes_transferred = async_result.bytes_transferred
                sync_result.download_speed = async_result.download_speed
                sync_result.failure_reason = async_result.failure_reason
                sync_result.error_message = async_result.error_message
                sync_result.anonymity_level = async_result.anonymity_level
                sync_result.real_ip_detected = async_result.real_ip_detected
                sync_result.proxy_ip_detected = async_result.proxy_ip_detected
                sync_result.headers_analysis = async_result.headers_analysis
                sync_result.timestamp = async_result.timestamp
                sync_result.test_endpoint_used = async_result.test_endpoint_used
                sync_result.validation_method = async_result.validation_method
                
                results.append((async_result.proxy, sync_result))
            
            self.logger.debug(f"✅ Async validation completed with {len(results)} results")
            return results
            
        except Exception as e:
            self.logger.error(f"❌ Async validation failed: {e}, falling back to sync")
            return self._validate_batch_sync(proxies, max_workers, progress_callback)
    
    def _generate_batch_result(self, all_proxies: List[ProxyInfo],
                             valid_proxies: List[ProxyInfo],
                             invalid_proxies: List[ProxyInfo],
                             error_proxies: List[ProxyInfo],
                             validation_results: List[ValidationResult]) -> Dict[str, Any]:
        """Generate comprehensive batch validation results"""
        
        duration = self.stats['end_time'] - self.stats['start_time']
        total_checked = len(valid_proxies) + len(invalid_proxies) + len(error_proxies)
        success_rate = (len(valid_proxies) / max(total_checked, 1)) * 100
        
        # Calculate performance metrics
        response_times = [r.response_time for r in validation_results if r.response_time]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Analyze failure reasons
        failure_analysis = {}
        for result in validation_results:
            if not result.is_valid and result.failure_reason:
                reason = result.failure_reason.value
                failure_analysis[reason] = failure_analysis.get(reason, 0) + 1
        
        # Protocol distribution
        protocol_stats = {}
        for proxy in all_proxies:
            protocol = proxy.protocol.value
            protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1
        
        # Anonymity level distribution for valid proxies
        anonymity_stats = {}
        for result in validation_results:
            if result.is_valid and result.anonymity_level:
                level = result.anonymity_level.value
                anonymity_stats[level] = anonymity_stats.get(level, 0) + 1
        
        # Geographic distribution
        country_stats = {}
        for result in validation_results:
            if result.is_valid and result.geo_location:
                country = result.geo_location.country_code or 'Unknown'
                country_stats[country] = country_stats.get(country, 0) + 1
        
        result = {
            # Basic counts
            'total': len(all_proxies),
            'valid': len(valid_proxies),
            'invalid': len(invalid_proxies),
            'errors': len(error_proxies),
            'processed': total_checked,
            
            # Performance metrics
            'duration': duration,
            'success_rate': success_rate,
            'avg_response_time': avg_response_time,
            'proxies_per_second': total_checked / duration if duration > 0 else 0,
            
            # Proxy lists
            'valid_proxies': valid_proxies,
            'invalid_proxies': invalid_proxies,
            'error_proxies': error_proxies,
            
            # Detailed analysis
            'validation_results': validation_results,
            'failure_analysis': failure_analysis,
            'protocol_distribution': protocol_stats,
            'anonymity_distribution': anonymity_stats,
            'country_distribution': country_stats,
            
            # Legacy compatibility
            'valid_count': len(valid_proxies),
            'invalid_count': len(invalid_proxies),
            'error_count': len(error_proxies),
            'validation_duration': duration
        }
        
        # Log summary
        self.logger.debug(
            f"✅ Batch validation completed: {len(valid_proxies)}/{total_checked} valid "
            f"({success_rate:.1f}%) in {duration:.1f}s ({result['proxies_per_second']:.1f} proxies/s)"
        )
        
        # Log failure analysis if there are failures
        if failure_analysis:
            self.logger.debug("📊 Failure analysis:")
            for reason, count in sorted(failure_analysis.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_checked) * 100
                self.logger.debug(f"   {reason}: {count} ({percentage:.1f}%)")
        
        return result
    
    def _empty_result(self) -> Dict[str, Any]:
        """Return empty result structure"""
        return {
            'total': 0,
            'valid': 0,
            'invalid': 0,
            'errors': 0,
            'processed': 0,
            'duration': 0,
            'success_rate': 0,
            'avg_response_time': 0,
            'proxies_per_second': 0,
            'valid_proxies': [],
            'invalid_proxies': [],
            'error_proxies': [],
            'validation_results': [],
            'failure_analysis': {},
            'protocol_distribution': {},
            'anonymity_distribution': {},
            'country_distribution': {},
            'valid_count': 0,
            'invalid_count': 0,
            'error_count': 0,
            'validation_duration': 0
        }


# ===============================================================================
# UTILITY FUNCTIONS AND COMPATIBILITY LAYER
# ===============================================================================

def create_validator(config: Optional[ConfigManager] = None) -> EnhancedProxyValidator:
    """Create enhanced proxy validator"""
    validation_config = ValidationConfig()
    if config:
        # Map config manager settings to validation config
        validation_config.connect_timeout = config.get('validation_timeout', 10)
        validation_config.max_retries = config.get('validation_retries', 3)
        validation_config.max_workers = config.get('max_concurrent_validations', 20)
    
    return EnhancedProxyValidator(validation_config)


def create_batch_validator(config: Optional[ConfigManager] = None,
                          concurrent_tests: int = 20) -> EnhancedBatchValidator:
    """Create enhanced batch validator"""
    validation_config = ValidationConfig(max_workers=concurrent_tests)
    if config:
        validation_config.connect_timeout = config.get('validation_timeout', 10)
        validation_config.max_retries = config.get('validation_retries', 3)
    
    return EnhancedBatchValidator(config, validation_config)


def validate_proxy(proxy: ProxyInfo) -> ValidationResult:
    """Validate single proxy - utility function"""
    validator = create_validator()
    return validator.validate_proxy(proxy)


def validate_proxy_list(proxies: List[ProxyInfo],
                       max_workers: int = 20) -> Dict[str, Any]:
    """Validate proxy list - utility function"""
    validator = create_batch_validator(concurrent_tests=max_workers)
    return validator.validate_batch(proxies)


# Legacy compatibility - keep original classes available
ProxyValidator = EnhancedProxyValidator
BatchValidator = EnhancedBatchValidator
SimpleValidationConfig = ValidationConfig  # Alias for backward compatibility


# ===============================================================================
# EXPORTS
# ===============================================================================

__all__ = [
    # Main classes
    'EnhancedProxyValidator',
    'EnhancedBatchValidator',
    'ProxyValidator',  # Legacy alias
    'BatchValidator',  # Legacy alias
    
    # Configuration
    'ValidationConfig',
    'SimpleValidationConfig',  # Legacy alias
    'ValidationResult',
    
    # Enums
    'ValidationMethod',
    'FailureReason',
    
    # Utility functions
    'create_validator',
    'create_batch_validator',
    'validate_proxy',
    'validate_proxy_list',
    'is_ipv4',
    'is_ipv6',
    'is_private_ip',
    'get_real_ip'
]

logger.info("Enhanced proxy validators module loaded successfully")
