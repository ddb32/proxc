"""Async Proxy Validators - High-performance asynchronous validation using aiohttp"""

import asyncio
import logging
import random
import socket
import ssl
import time
from typing import Optional
import ipaddress

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

from ...proxy_core.models import (
    ProxyInfo, ProxyProtocol, AnonymityLevel, ProxyStatus, ValidationStatus
)
from .validation_config import ValidationConfig, ValidationMethod, FailureReason
from .validation_results import ValidationResult

# Import target validator with conditional loading
try:
    from .target_validator import TargetValidator
    HAS_TARGET_VALIDATOR = True
except ImportError:
    HAS_TARGET_VALIDATOR = False


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
        
        # Initialize target validator if enabled
        self.target_validator = None
        if HAS_TARGET_VALIDATOR and self.config.enable_target_testing:
            try:
                self.target_validator = TargetValidator(self.config)
            except Exception as e:
                self.logger.warning(f"Failed to initialize target validator: {e}")
        
        # Initialize threat analyzer for blocking detection
        self.threat_analyzer = None
        try:
            from ..analysis.threat_analyzer import ThreatAnalyzer
            self.threat_analyzer = ThreatAnalyzer()
        except Exception as e:
            self.logger.warning(f"Failed to initialize threat analyzer: {e}")
        
        # Initialize security systems
        self.security_manager = None
        try:
            from ...security import SecurityManager
            self.security_manager = SecurityManager(
                enable_ip_rotation=False,  # Managed externally for batch operations
                enable_anti_detection=True
            )
        except ImportError:
            self.logger.warning("Security systems not available")
        
        # Initialize smart cache if enabled
        self.validation_cache = None
        if self.config.enable_validation_cache:
            try:
                from ..caching.smart_cache import SmartCache, create_cache_key
                from ..caching.cache_config import CacheConfig
                
                # Create cache configuration from validation config
                cache_config = CacheConfig(
                    validation_ttl=self.config.cache_ttl,
                    max_memory_mb=self.config.cache_memory_mb,
                    enable_auto_sizing=self.config.cache_enable_auto_sizing,
                    enable_validation_cache=True
                )
                
                self.validation_cache = SmartCache(cache_config, "AsyncValidationCache")
                self.create_cache_key = create_cache_key
                self.logger.info("Smart caching enabled for validation results")
                
            except Exception as e:
                self.logger.warning(f"Failed to initialize validation cache: {e}")
                self.validation_cache = None
        
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
        
        self.logger.info("AsyncProxyValidator initialized")
    
    async def validate_single(self, proxy: ProxyInfo, 
                            semaphore: Optional[asyncio.Semaphore] = None) -> ValidationResult:
        """Validate a single proxy asynchronously"""
        
        if semaphore:
            async with semaphore:
                return await self._validate_proxy_internal(proxy)
        else:
            return await self._validate_proxy_internal(proxy)
    
    async def _validate_proxy_internal(self, proxy: ProxyInfo) -> ValidationResult:
        """Internal async proxy validation"""
        start_time = time.time()
        
        # Check cache first if enabled
        cache_key = None
        if self.validation_cache:
            cache_key = self.create_cache_key(
                proxy.host, proxy.port, proxy.protocol.value,
                self.config.custom_test_url or "default",
                self.config.connect_timeout, self.config.read_timeout
            )
            
            cached_result = self.validation_cache.get(cache_key)
            if cached_result is not None:
                # Create result from cached data
                result = ValidationResult(proxy=proxy)
                result.is_valid = cached_result['is_valid']
                result.response_time = cached_result.get('response_time')
                result.failure_reason = cached_result.get('failure_reason')
                result.error_message = cached_result.get('error_message')
                result.anonymity_detected = cached_result.get('anonymity_detected')
                result.total_time = (time.time() - start_time) * 1000
                
                # Update proxy status from cached result
                result.update_proxy_status()
                
                self.logger.debug(f"Cache hit for {proxy.address}")
                return result
        
        # Cache miss - perform actual validation
        result = ValidationResult(proxy=proxy)
        
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
                    
                    # Perform target website testing if enabled and proxy is valid
                    if success and self.target_validator:
                        target_results = await self.target_validator.validate_proxy_targets(proxy, session)
                        if target_results:
                            result.target_test_results = target_results
                            
                            # Update overall validation based on target success rate
                            target_success = self.target_validator.meets_target_threshold(target_results)
                            if not target_success:
                                result.is_valid = False
                                result.failure_reason = FailureReason.TARGET_BLOCKED
                                success = False
                
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
        result.update_proxy_status()
        
        # Cache the validation result if enabled
        if self.validation_cache and cache_key:
            try:
                # Prepare cacheable data (only essential fields to minimize memory)
                cache_data = {
                    'is_valid': result.is_valid,
                    'response_time': result.response_time,
                    'failure_reason': result.failure_reason,
                    'error_message': result.error_message,
                    'anonymity_detected': result.anonymity_detected,
                    'timestamp': time.time()
                }
                
                # Cache with appropriate TTL based on result
                is_success = result.is_valid
                self.validation_cache.put(
                    cache_key, cache_data, 
                    result_type="validation", 
                    is_success=is_success
                )
                
                self.logger.debug(f"Cached validation result for {proxy.address}")
                
            except Exception as e:
                self.logger.debug(f"Failed to cache validation result: {e}")
        
        return result
    
    def _create_session(self, proxy: ProxyInfo) -> ClientSession:
        """Create aiohttp session with proxy configuration"""
        
        # Configure timeouts - optimized for fast scanning
        timeout = ClientTimeout(
            total=min(self.config.total_timeout, 15),  # Cap total timeout at 15s
            connect=min(self.config.connect_timeout, 8),  # Cap connect timeout at 8s
            sock_read=min(self.config.read_timeout, 10),  # Cap read timeout at 10s
            sock_connect=min(self.config.connect_timeout, 8)  # Explicit socket connect timeout
        )
        
        # Configure headers with anti-detection
        if self.security_manager:
            # Use stealth headers from anti-detection system
            headers = self.security_manager.get_stealth_headers("http://httpbin.org/ip", proxy)
        else:
            # Fallback to standard headers
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
        """Create appropriate connector for proxy type with professional-grade optimization"""
        
        if proxy.protocol in [ProxyProtocol.HTTP, ProxyProtocol.HTTPS]:
            # HTTP/HTTPS proxy - use highly optimized connector for maximum throughput
            return aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=1000,  # Maximum connection pool size
                limit_per_host=100,  # High per-host limit for speed
                keepalive_timeout=5,  # Shorter keepalive for faster turnover
                enable_cleanup_closed=True,
                ttl_dns_cache=600,  # 10 min DNS cache for efficiency
                use_dns_cache=True,
                family=socket.AF_INET,  # Force IPv4 for consistency
                happy_eyeballs_delay=0.1,  # Faster connection attempts
                sock_connect_timeout=self.config.connect_timeout,  # Explicit socket timeout
                resolver_timeout=self.config.dns_timeout,  # DNS resolution timeout
                tcp_nodelay=True  # Disable Nagle's algorithm for faster small requests
            )
        
        elif proxy.protocol in [ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5] and HAS_AIOHTTP_SOCKS:
            # SOCKS proxy - use aiohttp-socks with professional optimization
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
                limit=1000,  # Maximum connection limit for speed
                limit_per_host=100,  # High per-host limit
                ttl_dns_cache=600,  # Extended DNS cache
                use_dns_cache=True,
                enable_cleanup_closed=True,
                keepalive_timeout=5,  # Fast keepalive turnover
                resolver_timeout=self.config.dns_timeout
            )
        
        else:
            # Fallback to standard connector with professional optimization
            return aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=1000,  # Maximum connections
                limit_per_host=100,  # High per-host limit
                ttl_dns_cache=600,  # Extended DNS cache
                use_dns_cache=True,
                enable_cleanup_closed=True,
                keepalive_timeout=5,  # Fast keepalive turnover
                sock_connect_timeout=self.config.connect_timeout,
                resolver_timeout=self.config.dns_timeout,
                tcp_nodelay=True
            )
    
    async def _validate_http_async(self, session: ClientSession, proxy: ProxyInfo, 
                                 result: ValidationResult) -> bool:
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
        
        # Apply anti-detection timing delays
        if self.security_manager:
            await self.security_manager.apply_request_timing(test_url)
        
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
                            result.captive_portal_detected = True
                            return False
                    
                    if self.config.detect_deceptive_responses:
                        if self._detect_deceptive_response(text_content, test_url):
                            result.failure_reason = FailureReason.DECEPTIVE_RESPONSE
                            return False
                    
                    # CAPTCHA/Automation blocking detection
                    if self.threat_analyzer:
                        blocking_analysis = self.threat_analyzer.analyze_captcha_blocking(
                            text_content, 
                            dict(response.headers),
                            response.status
                        )
                        
                        if blocking_analysis['captcha_detected'] or blocking_analysis['automation_blocking']:
                            # Store blocking information in proxy's security assessment
                            if not hasattr(proxy, 'security_assessment') or proxy.security_assessment is None:
                                from ...proxy_core.models import SecurityAssessment
                                proxy.security_assessment = SecurityAssessment()
                            
                            proxy.security_assessment.update_blocking_info(blocking_analysis)
                            
                            # Determine if this should fail validation
                            blocking_score = self.threat_analyzer.calculate_blocking_score(blocking_analysis)
                            if blocking_score > 0.7:  # High confidence blocking
                                result.failure_reason = FailureReason.TARGET_BLOCKED
                                result.error_message = f"Automation blocking detected: {blocking_analysis.get('blocking_service', 'unknown')}"
                                return False
                    
                    # Extract IP for anonymity analysis
                    if self.config.enable_anonymity_testing:
                        await self._analyze_anonymity_async(session, proxy, text_content, result)
                    
                    return True
                else:
                    # Check for blocking even on non-200 responses
                    if self.threat_analyzer and response.status in [403, 429, 503]:
                        try:
                            content = await response.read()
                            text_content = content.decode('utf-8', errors='ignore')
                            
                            blocking_analysis = self.threat_analyzer.analyze_captcha_blocking(
                                text_content, 
                                dict(response.headers),
                                response.status
                            )
                            
                            if blocking_analysis['captcha_detected'] or blocking_analysis['automation_blocking']:
                                # Store blocking information
                                if not hasattr(proxy, 'security_assessment') or proxy.security_assessment is None:
                                    from ...proxy_core.models import SecurityAssessment
                                    proxy.security_assessment = SecurityAssessment()
                                
                                proxy.security_assessment.update_blocking_info(blocking_analysis)
                                result.failure_reason = FailureReason.TARGET_BLOCKED
                                result.error_message = f"Blocked by {blocking_analysis.get('blocking_service', 'security service')}"
                                return False
                        except Exception as e:
                            self.logger.debug(f"Error analyzing blocking for status {response.status}: {e}")
                    
                    result.failure_reason = FailureReason.INVALID_RESPONSE
                    result.error_message = f"HTTP {response.status}"
                    return False
        
        except asyncio.TimeoutError:
            result.failure_reason = FailureReason.TIMEOUT_TOTAL
            result.error_message = "Request timeout"
        except ClientProxyConnectionError as e:
            result.failure_reason = FailureReason.PROXY_ERROR
            result.error_message = f"Proxy connection error: {e}"
        except ClientConnectorError as e:
            if "timeout" in str(e).lower():
                result.failure_reason = FailureReason.TIMEOUT_CONNECT
            elif "refused" in str(e).lower():
                result.failure_reason = FailureReason.CONNECTION_REFUSED
            else:
                result.failure_reason = FailureReason.CONNECTION_RESET
            result.error_message = str(e)
        except Exception as e:
            result.failure_reason = FailureReason.UNKNOWN_ERROR
            result.error_message = str(e)
        
        return False
    
    async def _validate_socks_async(self, session: ClientSession, proxy: ProxyInfo, 
                                  result: ValidationResult) -> bool:
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
    
    async def _validate_raw_async(self, proxy: ProxyInfo, result: ValidationResult) -> bool:
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
                                     ip_response: str, result: ValidationResult):
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
                result.anonymity_detected = AnonymityLevel.TRANSPARENT
                result.real_ip_detected = self._real_ip
                result.transparent_proxy = True
                return
            
            # Perform header analysis for anonymous vs elite classification
            if self.config.check_proxy_headers:
                headers_analysis = await self._analyze_headers_async(session)
                result.headers_analysis = headers_analysis
                
                if headers_analysis.get('proxy_detected', False):
                    # Proxy headers found - classify based on severity
                    anonymity_score = headers_analysis.get('anonymity_score', 0)
                    if anonymity_score >= 90:
                        result.anonymity_detected = AnonymityLevel.ELITE
                    elif anonymity_score >= 70:
                        result.anonymity_detected = AnonymityLevel.ANONYMOUS
                    else:
                        result.anonymity_detected = AnonymityLevel.TRANSPARENT
                else:
                    # No proxy headers - likely elite
                    result.anonymity_detected = AnonymityLevel.ELITE
            else:
                # Default to anonymous if header checking disabled
                result.anonymity_detected = AnonymityLevel.ANONYMOUS
                
        except Exception as e:
            self.logger.debug(f"Anonymity analysis failed: {e}")
            result.anonymity_detected = AnonymityLevel.TRANSPARENT
    
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
    
    async def _analyze_headers_async(self, session: ClientSession) -> dict:
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
    
    def _analyze_proxy_headers(self, headers: dict) -> dict:
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
                                         result: ValidationResult):
        """Perform additional async analysis on valid proxies"""
        
        # Speed test
        if self.config.enable_speed_testing:
            await self._test_speed_async(session, result)
        
        # Chain detection analysis
        if self.config.enable_chain_detection and hasattr(session, '_connector'):
            await self._perform_chain_detection(session, proxy, result)
    
    async def _perform_chain_detection(self, session: ClientSession, proxy: ProxyInfo, 
                                     result: ValidationResult):
        """Perform proxy chain detection analysis"""
        try:
            # Make a request to get headers for chain analysis
            test_url = random.choice(self.test_endpoints)
            response_times = []
            all_headers = {}
            response_content = ""
            
            # Collect multiple samples for timing analysis
            for i in range(min(3, self.config.chain_detection_samples or 3)):
                start_time = time.time()
                try:
                    async with session.get(test_url, timeout=ClientTimeout(total=15)) as response:
                        response_time = (time.time() - start_time) * 1000
                        response_times.append(response_time)
                        
                        # Store headers from the last successful request
                        if response.status == 200:
                            all_headers = dict(response.headers)
                            if i == 0:  # Only read content once to avoid overhead
                                content_bytes = await response.read()
                                response_content = content_bytes.decode('utf-8', errors='ignore')
                        
                        # Brief delay between samples
                        await asyncio.sleep(0.5)
                        
                except Exception as e:
                    self.logger.debug(f"Chain detection sample {i+1} failed: {e}")
                    continue
            
            # Perform chain analysis if we have sufficient data
            if all_headers and response_times:
                chain_analysis = await self.threat_analyzer.analyze_proxy_chain(
                    proxy, all_headers, response_content, response_times
                )
                
                # Update proxy's security assessment with chain information
                if not hasattr(proxy, 'security_assessment') or proxy.security_assessment is None:
                    from ...proxy_core.models import SecurityAssessment
                    proxy.security_assessment = SecurityAssessment()
                
                proxy.security_assessment.update_chain_info(chain_analysis)
                
                # Store chain analysis in validation result
                result.chain_analysis = chain_analysis
                
                # Log significant findings
                if chain_analysis.get('is_chain_detected', False):
                    chain_depth = chain_analysis.get('chain_depth', 0)
                    confidence = chain_analysis.get('chain_confidence', 0.0)
                    risk_level = chain_analysis.get('risk_level', 'low')
                    
                    self.logger.info(f"Chain detected on {proxy.address}: "
                                   f"depth={chain_depth}, confidence={confidence:.2f}, risk={risk_level}")
                    
                    # Add chain detection to proxy tags for easy filtering
                    proxy.add_tag(f"chain:{chain_depth}")
                    if risk_level in ['high', 'critical']:
                        proxy.add_tag(f"high-risk-chain")
                
        except Exception as e:
            self.logger.debug(f"Chain detection failed for {proxy.address}: {e}")
            # Don't fail validation due to chain detection errors
            pass
    
    async def _test_speed_async(self, session: ClientSession, result: ValidationResult):
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
    
    def _extract_ip_from_text(self, text: str) -> Optional[str]:
        """Extract IP address from text response"""
        import re
        import json
        
        # Try JSON parsing first
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return data.get('ip') or data.get('origin', '').split(',')[0].strip()
        except:
            pass
        
        # Fallback to regex
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        matches = re.findall(ip_pattern, text)
        
        for match in matches:
            try:
                ipaddress.IPv4Address(match)
                return match
            except ipaddress.AddressValueError:
                continue
        
        return None


def create_async_validator(config: Optional[ValidationConfig] = None) -> AsyncProxyValidator:
    """Create asynchronous proxy validator"""
    return AsyncProxyValidator(config)