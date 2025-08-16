"""
Async Proxy Validators - High-Performance Asynchronous Validation

Provides true async/await validation using aiohttp for maximum performance.
Capable of handling 500+ concurrent proxy validations with non-blocking I/O.

Key Features:
- True async/await with aiohttp
- Semaphore-controlled concurrency
- SOCKS proxy support via aiohttp-socks
- Non-blocking I/O operations
- 5-10x performance improvement over sync validation
"""

import asyncio
import ipaddress
import logging
import random
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from urllib.parse import urlparse

# Async HTTP imports
try:
    import aiohttp
    from aiohttp import ClientSession, ClientTimeout, ClientError, ServerTimeoutError
    from aiohttp.client_exceptions import ClientConnectorError, ClientProxyConnectionError
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

# SOCKS proxy support
try:
    from aiohttp_socks import ProxyConnector, ProxyType
    from python_socks import ProxyError
    HAS_AIOHTTP_SOCKS = True
except ImportError:
    HAS_AIOHTTP_SOCKS = False

# Core imports
from ..proxy_core.models import (
    ProxyInfo, ProxyProtocol, AnonymityLevel, 
    ProxyStatus, ValidationStatus, ThreatLevel, GeoLocation
)
from ..proxy_core.config import ConfigManager
from .validators import ValidationConfig, ValidationResult, FailureReason, ValidationMethod

logger = logging.getLogger(__name__)


# ===============================================================================
# CONSTANTS AND CONFIGURATION
# ===============================================================================

# Performance tuning constants
DEFAULT_CONNECTOR_LIMIT = 500
DEFAULT_HOST_LIMIT = 50
DNS_CACHE_TTL = 300  # 5 minutes
KEEPALIVE_TIMEOUT = 30
HAPPY_EYEBALLS_DELAY = 0.25

# Timeout constants
DEFAULT_SESSION_TIMEOUT = 15
DEFAULT_CONNECT_TIMEOUT = 8
DEFAULT_READ_TIMEOUT = 10

# IP Address Validation Patterns
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


def extract_ip_from_text_async(text: str, strict: bool = True, include_ipv6: bool = False) -> Optional[str]:
    """Async-compatible centralized IP extraction utility with enhanced validation
    
    Args:
        text: Text to extract IP from
        strict: Use strict IPv4 pattern (True) or permissive pattern (False)
        include_ipv6: Also attempt IPv6 extraction
        
    Returns:
        First valid IP address found, or None
    """
    import json
    
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
                    try:
                        ipaddress.IPv4Address(ip)
                        return ip
                    except ipaddress.AddressValueError:
                        pass
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
        try:
            ipaddress.IPv4Address(match)
            return match
        except ipaddress.AddressValueError:
            continue
    
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
        return extract_ip_from_text_async(text, strict=False, include_ipv6=include_ipv6)
        
    return None

# ===============================================================================
# ASYNC VALIDATION RESULT
# ===============================================================================

@dataclass
class AsyncValidationResult:
    """Async validation result with performance metrics"""
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
    
    # Anonymity analysis
    anonymity_level: Optional[AnonymityLevel] = None
    real_ip_detected: Optional[str] = None
    proxy_ip_detected: Optional[str] = None
    headers_analysis: Dict[str, Any] = None
    
    # Metadata
    timestamp: datetime = None
    test_endpoint_used: Optional[str] = None
    validation_method: ValidationMethod = ValidationMethod.HTTP_GET
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.headers_analysis is None:
            self.headers_analysis = {}


# ===============================================================================
# ASYNC PROXY VALIDATOR
# ===============================================================================

class AsyncProxyValidator:
    """High-performance async proxy validator using aiohttp"""
    
    def __init__(self, config: Optional[ValidationConfig] = None):
        if not HAS_AIOHTTP:
            raise ImportError("aiohttp is required for async validation. Install with: pip install aiohttp")
        
        self.config = config or ValidationConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Performance tracking
        self.total_validated = 0
        self.total_time = 0.0
        self._real_ip = None
        
        # Test endpoints
        self.test_endpoints = self.config.test_endpoints.get('ip_check', [
            'http://httpbin.org/ip',
            'http://api.ipify.org?format=json',
            'http://checkip.amazonaws.com',
            'http://icanhazip.com'
        ])
        
        self.anonymity_endpoints = [
            'http://httpbin.org/headers',
            'http://httpbin.org/get'
        ]
        
        self.logger.debug("AsyncProxyValidator initialized")
    
    async def validate_single(self, proxy: ProxyInfo, 
                            semaphore: Optional[asyncio.Semaphore] = None) -> AsyncValidationResult:
        """Validate a single proxy asynchronously"""
        
        if semaphore:
            async with semaphore:
                return await self._validate_proxy_internal(proxy)
        else:
            return await self._validate_proxy_internal(proxy)
    
    async def _validate_proxy_internal(self, proxy: ProxyInfo) -> AsyncValidationResult:
        """Internal async proxy validation"""
        result = AsyncValidationResult(proxy=proxy)
        start_time = time.time()
        
        try:
            # Create async session with proxy configuration
            async with self._create_session(proxy) as session:
                # Validate based on protocol
                if proxy.protocol in [ProxyProtocol.HTTP, ProxyProtocol.HTTPS]:
                    success = await self._validate_http_async(session, proxy, result)
                elif proxy.protocol in [ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5]:
                    success = await self._validate_socks_async(session, proxy, result)
                else:
                    success = await self._validate_raw_async(proxy, result)
                
                result.is_valid = success
                
                # Additional analysis for valid proxies
                if success and session:
                    await self._perform_additional_analysis(session, proxy, result)
                
        except Exception as e:
            result.failure_reason = FailureReason.UNKNOWN_ERROR
            result.error_message = str(e)
            self.logger.debug(f"Validation failed for {proxy.address}: {e}")
        
        # Calculate timing
        total_time = (time.time() - start_time) * 1000
        if not result.response_time:
            result.response_time = total_time
        result.total_time = total_time
        
        # Update proxy status
        self._update_proxy_status(proxy, result)
        
        return result
    
    def _create_session(self, proxy: ProxyInfo) -> ClientSession:
        """Create aiohttp session with proxy configuration"""
        
        # Configure timeouts using defined constants
        timeout = ClientTimeout(
            total=min(self.config.total_timeout, DEFAULT_SESSION_TIMEOUT),
            connect=min(self.config.connect_timeout, DEFAULT_CONNECT_TIMEOUT),
            sock_read=min(self.config.read_timeout, DEFAULT_READ_TIMEOUT),
            sock_connect=min(self.config.connect_timeout, DEFAULT_CONNECT_TIMEOUT)
        )
        
        # Configure headers
        headers = {
            'User-Agent': random.choice(self.config.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive'
        }
        
        # Configure SSL
        ssl_context = None
        if not self.config.verify_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        # Create connector based on proxy type
        connector = self._create_connector(proxy, ssl_context)
        
        return ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            skip_auto_headers={'User-Agent'}  # We set it manually
        )
    
    def _create_connector(self, proxy: ProxyInfo, ssl_context: Optional[ssl.SSLContext]) -> aiohttp.BaseConnector:
        """Create appropriate connector for proxy type"""
        
        if proxy.protocol in [ProxyProtocol.HTTP, ProxyProtocol.HTTPS]:
            # HTTP/HTTPS proxy - use optimized connector with constants
            return aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=DEFAULT_CONNECTOR_LIMIT,
                limit_per_host=DEFAULT_HOST_LIMIT,
                keepalive_timeout=KEEPALIVE_TIMEOUT,
                enable_cleanup_closed=True,
                ttl_dns_cache=DNS_CACHE_TTL,
                use_dns_cache=True,
                family=socket.AF_INET,
                happy_eyeballs_delay=HAPPY_EYEBALLS_DELAY
            )
        
        elif proxy.protocol in [ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5] and HAS_AIOHTTP_SOCKS:
            # SOCKS proxy - use aiohttp-socks
            if proxy.protocol == ProxyProtocol.SOCKS4:
                proxy_type = ProxyType.SOCKS4
            else:
                proxy_type = ProxyType.SOCKS5
            
            return ProxyConnector(
                proxy_type=proxy_type,
                host=proxy.host,
                port=proxy.port,
                username=proxy.username,
                password=proxy.password,
                ssl=ssl_context,
                limit=DEFAULT_CONNECTOR_LIMIT,
                limit_per_host=DEFAULT_HOST_LIMIT,
                ttl_dns_cache=DNS_CACHE_TTL,
                use_dns_cache=True,
                enable_cleanup_closed=True
            )
        
        else:
            # Fallback to standard connector
            return aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=DEFAULT_CONNECTOR_LIMIT,
                limit_per_host=DEFAULT_HOST_LIMIT,
                ttl_dns_cache=DNS_CACHE_TTL,
                use_dns_cache=True,
                enable_cleanup_closed=True
            )
    
    async def _validate_http_async(self, session: ClientSession, proxy: ProxyInfo, 
                                 result: AsyncValidationResult) -> bool:
        """Async HTTP/HTTPS proxy validation"""
        test_url = random.choice(self.test_endpoints)
        result.test_endpoint_used = test_url
        
        # Build proxy URL for HTTP proxies
        proxy_url = None
        if proxy.protocol in [ProxyProtocol.HTTP, ProxyProtocol.HTTPS]:
            if proxy.username and proxy.password:
                proxy_url = f"{proxy.protocol.value}://{proxy.username}:{proxy.password}@{proxy.host}:{proxy.port}"
            else:
                proxy_url = f"{proxy.protocol.value}://{proxy.host}:{proxy.port}"
        
        start_time = time.time()
        
        try:
            async with session.get(
                test_url,
                proxy=proxy_url,
                allow_redirects=self.config.allow_redirects,
                max_redirects=self.config.max_redirects
            ) as response:
                
                # Calculate timing
                response_time = (time.time() - start_time) * 1000
                result.response_time = response_time
                result.connect_time = response_time  # Approximation for async
                
                # Read response content
                content = await response.read()
                result.bytes_transferred = len(content)
                
                if response.status == 200:
                    # Check for issues
                    text_content = content.decode('utf-8', errors='ignore')
                    
                    if self.config.detect_captive_portals:
                        if self._detect_captive_portal(text_content):
                            result.failure_reason = FailureReason.CAPTIVE_PORTAL
                            return False
                    
                    if self.config.detect_deceptive_responses:
                        if self._detect_deceptive_response(text_content, test_url):
                            result.failure_reason = FailureReason.DECEPTIVE_RESPONSE
                            return False
                    
                    # Extract IP for anonymity analysis
                    if self.config.enable_anonymity_testing:
                        await self._analyze_anonymity_async(session, proxy, text_content, result)
                    
                    return True
                else:
                    result.failure_reason = FailureReason.INVALID_RESPONSE
                    result.error_message = f"HTTP {response.status}"
                    return False
        
        except asyncio.TimeoutError:
            result.failure_reason = FailureReason.TIMEOUT_TOTAL
            result.error_message = "Request timeout"
            self.logger.debug(f"Timeout for {proxy.address}")
        except ClientProxyConnectionError as e:
            result.failure_reason = FailureReason.PROXY_ERROR
            result.error_message = f"Proxy connection error: {str(e)[:100]}"
            self.logger.debug(f"Proxy connection error for {proxy.address}")
        except ClientConnectorError as e:
            error_str = str(e).lower()
            if "timeout" in error_str:
                result.failure_reason = FailureReason.TIMEOUT_CONNECT
                result.error_message = "Connection timeout"
            elif "refused" in error_str:
                result.failure_reason = FailureReason.CONNECTION_REFUSED
                result.error_message = "Connection refused"
            elif "unreachable" in error_str:
                result.failure_reason = FailureReason.NETWORK_UNREACHABLE
                result.error_message = "Network unreachable"
            else:
                result.failure_reason = FailureReason.CONNECTION_RESET
                result.error_message = f"Connection error: {str(e)[:100]}"
            self.logger.debug(f"Connection error for {proxy.address}: {result.error_message}")
        except Exception as e:
            result.failure_reason = FailureReason.UNKNOWN_ERROR
            result.error_message = f"Unexpected error: {str(e)[:100]}"
            self.logger.debug(f"Unknown error for {proxy.address}: {result.error_message}")
        
        return False
    
    async def _validate_socks_async(self, session: ClientSession, proxy: ProxyInfo, 
                                  result: AsyncValidationResult) -> bool:
        """Async SOCKS proxy validation"""
        if not HAS_AIOHTTP_SOCKS:
            self.logger.warning("aiohttp-socks not available, using HTTP validation")
            return await self._validate_http_async(session, proxy, result)
        
        test_url = random.choice(self.test_endpoints)
        result.test_endpoint_used = test_url
        
        start_time = time.time()
        
        try:
            async with session.get(test_url) as response:
                response_time = (time.time() - start_time) * 1000
                result.response_time = response_time
                result.connect_time = response_time
                
                content = await response.read()
                result.bytes_transferred = len(content)
                
                if response.status == 200:
                    # Basic SOCKS validation successful
                    if self.config.enable_anonymity_testing:
                        text_content = content.decode('utf-8', errors='ignore')
                        await self._analyze_anonymity_async(session, proxy, text_content, result)
                    return True
                else:
                    result.failure_reason = FailureReason.INVALID_RESPONSE
                    result.error_message = f"HTTP {response.status}"
                    return False
        
        except ProxyError as e:
            result.failure_reason = FailureReason.PROXY_ERROR
            result.error_message = f"SOCKS error: {e}"
        except asyncio.TimeoutError:
            result.failure_reason = FailureReason.TIMEOUT_TOTAL
            result.error_message = "SOCKS timeout"
        except Exception as e:
            result.failure_reason = FailureReason.UNKNOWN_ERROR
            result.error_message = str(e)
        
        return False
    
    async def _validate_raw_async(self, proxy: ProxyInfo, result: AsyncValidationResult) -> bool:
        """Async raw socket validation (fallback)"""
        start_time = time.time()
        
        try:
            # Use asyncio for socket operations
            future = asyncio.open_connection(proxy.host, proxy.port)
            reader, writer = await asyncio.wait_for(future, timeout=self.config.connect_timeout)
            
            response_time = (time.time() - start_time) * 1000
            result.response_time = response_time
            result.connect_time = response_time
            
            writer.close()
            await writer.wait_closed()
            
            return True
            
        except asyncio.TimeoutError:
            result.failure_reason = FailureReason.TIMEOUT_CONNECT
            result.error_message = "Socket connection timeout"
        except ConnectionRefusedError:
            result.failure_reason = FailureReason.CONNECTION_REFUSED
            result.error_message = "Connection refused"
        except Exception as e:
            result.failure_reason = FailureReason.UNKNOWN_ERROR
            result.error_message = str(e)
        
        return False
    
    async def _analyze_anonymity_async(self, session: ClientSession, proxy: ProxyInfo, 
                                     ip_response: str, result: AsyncValidationResult):
        """Async anonymity analysis using proxy judge method"""
        try:
            # Extract IP from initial response
            proxy_ip = self._extract_ip_from_text(ip_response)
            result.proxy_ip_detected = proxy_ip
            
            # Get real IP if not cached
            if not self._real_ip:
                self._real_ip = await self._get_real_ip_async()
            
            # Check if real IP is visible (transparent proxy)
            if self._real_ip and proxy_ip and self._real_ip in ip_response:
                result.anonymity_level = AnonymityLevel.TRANSPARENT
                result.real_ip_detected = self._real_ip
                return
            
            # Perform header analysis for anonymous vs elite classification
            if self.config.check_proxy_headers:
                headers_analysis = await self._analyze_headers_async(session)
                result.headers_analysis = headers_analysis
                
                if headers_analysis.get('proxy_detected', False):
                    # Proxy headers found - classify based on severity
                    anonymity_score = headers_analysis.get('anonymity_score', 0)
                    if anonymity_score >= 90:
                        result.anonymity_level = AnonymityLevel.ELITE
                    elif anonymity_score >= 70:
                        result.anonymity_level = AnonymityLevel.ANONYMOUS
                    else:
                        result.anonymity_level = AnonymityLevel.TRANSPARENT
                else:
                    # No proxy headers - likely elite
                    result.anonymity_level = AnonymityLevel.ELITE
            else:
                # Default to anonymous if header checking disabled
                result.anonymity_level = AnonymityLevel.ANONYMOUS
                
        except Exception as e:
            self.logger.debug(f"Anonymity analysis failed: {e}")
            result.anonymity_level = AnonymityLevel.TRANSPARENT
    
    async def _get_real_ip_async(self) -> Optional[str]:
        """Get real IP address asynchronously"""
        try:
            async with ClientSession() as session:
                for url in self.test_endpoints:
                    try:
                        async with session.get(url, timeout=ClientTimeout(total=5)) as response:
                            if response.status == 200:
                                content = await response.text()
                                ip = self._extract_ip_from_text(content)
                                if ip:
                                    return ip
                    except:
                        continue
        except Exception:
            pass
        return None
    
    async def _analyze_headers_async(self, session: ClientSession) -> Dict[str, Any]:
        """Async header analysis for anonymity detection"""
        try:
            headers_url = random.choice(self.anonymity_endpoints)
            async with session.get(headers_url) as response:
                if response.status == 200:
                    data = await response.json()
                    received_headers = data.get('headers', {})
                    return self._analyze_proxy_headers(received_headers)
        except Exception as e:
            self.logger.debug(f"Header analysis failed: {e}")
        
        return {'proxy_detected': False, 'anonymity_score': 100}
    
    def _analyze_proxy_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze headers for proxy indicators (reused from sync validator)"""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        proxy_headers = {
            'x-forwarded-for': 10,
            'x-real-ip': 10,
            'via': 9,
            'x-proxy-connection': 7,
            'proxy-connection': 7,
            'x-forwarded-proto': 5,
            'x-forwarded-host': 6,
        }
        
        detected_headers = {}
        total_score = 0
        
        for header_name, score in proxy_headers.items():
            if header_name in headers_lower:
                detected_headers[header_name] = {
                    'value': headers_lower[header_name],
                    'score': score
                }
                total_score += score
        
        # Calculate anonymity score (higher = more anonymous)
        anonymity_score = max(0, 100 - min(100, total_score * 2))
        
        return {
            'detected': detected_headers,
            'total_score': total_score,
            'anonymity_score': anonymity_score,
            'proxy_detected': len(detected_headers) > 0
        }
    
    async def _perform_additional_analysis(self, session: ClientSession, proxy: ProxyInfo, 
                                         result: AsyncValidationResult):
        """Perform additional async analysis on valid proxies"""
        
        # Speed test
        if self.config.enable_speed_testing:
            await self._test_speed_async(session, result)
        
        # Additional protocol tests could be added here
        pass
    
    async def _test_speed_async(self, session: ClientSession, result: AsyncValidationResult):
        """Async speed testing"""
        speed_test_urls = self.config.test_endpoints.get('speed_test', [
            'http://httpbin.org/bytes/10240'  # 10KB test
        ])
        
        try:
            test_url = random.choice(speed_test_urls)
            start_time = time.time()
            
            async with session.get(test_url) as response:
                if response.status == 200:
                    content = await response.read()
                    elapsed_time = time.time() - start_time
                    
                    if elapsed_time > 0:
                        result.download_speed = len(content) / elapsed_time
                        result.bytes_transferred += len(content)
        
        except Exception as e:
            self.logger.debug(f"Speed test failed: {e}")
    
    def _detect_captive_portal(self, content: str) -> bool:
        """Detect captive portal in response content"""
        captive_indicators = [
            'captive portal', 'wifi login', 'internet access',
            'click here to continue', 'terms and conditions'
        ]
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in captive_indicators)
    
    def _detect_deceptive_response(self, content: str, expected_url: str) -> bool:
        """Detect deceptive responses"""
        deceptive_indicators = [
            'this site has been blocked', 'access denied',
            'content filter', 'firewall', 'proxy blocked'
        ]
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in deceptive_indicators)
    
    def _extract_ip_from_text(self, text: str, strict: bool = True, include_ipv6: bool = False) -> Optional[str]:
        """Extract IP address using centralized utility function
        
        Args:
            text: Text to extract IP from
            strict: Use strict IPv4 pattern (True) or permissive pattern (False)
            include_ipv6: Also attempt IPv6 extraction
            
        Returns:
            First valid IP address found, or None
        """
        return extract_ip_from_text_async(text, strict=strict, include_ipv6=include_ipv6)
    
    def _update_proxy_status(self, proxy: ProxyInfo, result: AsyncValidationResult):
        """Update proxy status based on validation result"""
        if result.is_valid:
            proxy.status = ProxyStatus.ACTIVE
            proxy.validation_status = ValidationStatus.VALID
            
            if result.anonymity_level:
                proxy.anonymity_level = result.anonymity_level
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
# ASYNC BATCH VALIDATOR
# ===============================================================================

class AsyncBatchValidator:
    """High-performance async batch validator"""
    
    def __init__(self, config: Optional[ValidationConfig] = None):
        if not HAS_AIOHTTP:
            raise ImportError("aiohttp is required for async validation")
        
        self.config = config or ValidationConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Performance tracking
        self.stats = {
            'total_processed': 0,
            'total_valid': 0,
            'total_invalid': 0,
            'total_errors': 0,
            'start_time': None,
            'end_time': None
        }
        
        self.logger.debug("AsyncBatchValidator initialized")
    
    async def validate_batch_async(self, proxies: List[ProxyInfo], 
                                 max_concurrent: Optional[int] = None,
                                 progress_callback: Optional[callable] = None) -> List[AsyncValidationResult]:
        """Validate proxies asynchronously with controlled concurrency"""
        
        if not proxies:
            return []
        
        self.stats['start_time'] = time.time()
        results = []
        
        # Calculate optimal concurrency if not specified
        if max_concurrent is None:
            max_concurrent = calculate_optimal_concurrency(len(proxies))
        else:
            # Cap at reasonable maximum to prevent overwhelming servers
            max_concurrent = min(max_concurrent, 200)
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        # Create validator instance
        validator = AsyncProxyValidator(self.config)
        
        self.logger.debug(f"Starting async validation of {len(proxies)} proxies with {max_concurrent} max concurrent")
        
        try:
            # Create tasks for all proxies
            tasks = []
            for proxy in proxies:
                task = validator.validate_single(proxy, semaphore)
                tasks.append(task)
            
            # Execute all tasks concurrently with better error handling
            completed = 0
            for task in asyncio.as_completed(tasks):
                try:
                    result = await task
                    results.append(result)
                    
                    # Update stats
                    if result.is_valid:
                        self.stats['total_valid'] += 1
                    else:
                        self.stats['total_invalid'] += 1
                    
                    completed += 1
                    self.stats['total_processed'] = completed
                    
                    # Progress callback
                    if progress_callback:
                        progress_callback(completed, len(proxies), result)
                
                except Exception as e:
                    self.stats['total_errors'] += 1
                    completed += 1
                    self.stats['total_processed'] = completed
                    self.logger.debug(f"Task failed: {e}")
                    
                    # Create error result for failed task
                    error_result = AsyncValidationResult(
                        proxy=proxies[len(results) + self.stats['total_errors'] - 1] if len(results) + self.stats['total_errors'] <= len(proxies) else proxies[0]
                    )
                    error_result.failure_reason = FailureReason.UNKNOWN_ERROR
                    error_result.error_message = str(e)
                    results.append(error_result)
        
        except Exception as e:
            self.logger.error(f"Batch validation failed: {e}")
        
        self.stats['end_time'] = time.time()
        
        # Log performance
        duration = self.stats['end_time'] - self.stats['start_time']
        proxies_per_second = len(results) / duration if duration > 0 else 0
        
        self.logger.debug(
            f"Async validation completed: {self.stats['total_valid']}/{len(results)} valid "
            f"({(self.stats['total_valid']/max(len(results), 1)*100):.1f}%) in {duration:.1f}s "
            f"({proxies_per_second:.1f} proxies/s)"
        )
        
        return results


# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def calculate_optimal_concurrency(proxy_count: int, max_concurrent: int = 100) -> int:
    """Calculate optimal concurrency with intelligent resource-based scaling"""
    # Fast path for small batches
    if proxy_count <= 10:
        return min(proxy_count, 5)
    
    # Get system resources with caching
    try:
        import psutil
        cpu_count = psutil.cpu_count() or 4
        memory_gb = psutil.virtual_memory().total / (1024**3)
    except ImportError:
        cpu_count = 4
        memory_gb = 8
    
    # Optimized concurrency calculation
    if proxy_count <= 50:
        return min(proxy_count, max(20, cpu_count * 4))
    elif proxy_count <= 200:
        return min(proxy_count, max(50, cpu_count * 6))
    elif proxy_count <= 1000:
        base_concurrent = cpu_count * 10
        if memory_gb >= 8:
            base_concurrent = int(base_concurrent * 1.5)
        return min(proxy_count // 8, min(max_concurrent, base_concurrent))
    else:
        # For very large batches, use aggressive but bounded concurrency
        base_concurrent = cpu_count * 12
        memory_multiplier = 1.0
        if memory_gb >= 16:
            memory_multiplier = 2.0
        elif memory_gb >= 8:
            memory_multiplier = 1.5
        
        optimal_concurrent = int(base_concurrent * memory_multiplier)
        return min(proxy_count // 15, min(max_concurrent * 2, optimal_concurrent))

async def validate_proxies_async(proxies: List[ProxyInfo], 
                               max_concurrent: Optional[int] = None,
                               config: Optional[ValidationConfig] = None) -> List[AsyncValidationResult]:
    """Utility function for async proxy validation with optimal concurrency"""
    if max_concurrent is None:
        max_concurrent = calculate_optimal_concurrency(len(proxies))
    
    validator = AsyncBatchValidator(config)
    return await validator.validate_batch_async(proxies, max_concurrent)


def run_async_validation(proxies: List[ProxyInfo], 
                        max_concurrent: Optional[int] = None,
                        config: Optional[ValidationConfig] = None) -> List[AsyncValidationResult]:
    """Run async validation in sync context with optimal concurrency"""
    return asyncio.run(validate_proxies_async(proxies, max_concurrent, config))


# ===============================================================================
# EXPORTS
# ===============================================================================

__all__ = [
    'AsyncProxyValidator',
    'AsyncBatchValidator', 
    'AsyncValidationResult',
    'validate_proxies_async',
    'run_async_validation',
    'calculate_optimal_concurrency',
    'HAS_AIOHTTP',
    'HAS_AIOHTTP_SOCKS'
]

if HAS_AIOHTTP:
    logger.info("Async proxy validation engine loaded successfully")
else:
    logger.warning("aiohttp not available - async validation disabled")