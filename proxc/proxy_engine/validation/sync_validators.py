"""Synchronous Proxy Validators - Synchronous validation using requests"""

import logging
import random
import socket
import ssl
import time
from typing import Optional
import ipaddress

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from urllib3.poolmanager import PoolManager
    from urllib3.pools import HTTPConnectionPool, HTTPSConnectionPool
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import socks
    HAS_SOCKS = True
except ImportError:
    try:
        import PySocks as socks
        HAS_SOCKS = True
    except ImportError:
        HAS_SOCKS = False

from ...proxy_core.models import (
    ProxyInfo, ProxyProtocol, AnonymityLevel, ProxyStatus, ValidationStatus
)
from .validation_config import ValidationConfig, ValidationMethod, FailureReason
from .validation_results import ValidationResult
from ..analysis.geo_analyzer import GeoAnalyzer
from .retry_manager import (
    IntelligentRetryManager, RetryConfig, RetryStrategy, JitterType,
    create_retry_config_from_validation_config
)


class PersistentHTTPConnectionPool:
    """Persistent HTTP connection pool for optimal performance"""
    
    def __init__(self, config: Optional['ValidationConfig'] = None):
        if config:
            self.pool_connections = config.http_pool_connections
            self.pool_maxsize = config.http_pool_maxsize
            self.pool_block = config.http_pool_block
            self.connection_timeout = config.pool_connection_timeout
            self.read_timeout = config.pool_read_timeout
            self.keep_alive = config.pool_keep_alive
        else:
            # Default values
            self.pool_connections = 150
            self.pool_maxsize = 300
            self.pool_block = False
            self.connection_timeout = 10.0
            self.read_timeout = 30.0
            self.keep_alive = True
        
        self._pools = {}
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def get_adapter(self, max_retries: int = 3) -> HTTPAdapter:
        """Get optimized HTTP adapter with persistent connection pool"""
        
        class PersistentHTTPAdapter(HTTPAdapter):
            def __init__(self, pool_connections, pool_maxsize, pool_block, connection_timeout, read_timeout, keep_alive, max_retries):
                self.pool_connections = pool_connections
                self.pool_maxsize = pool_maxsize  
                self.pool_block = pool_block
                self.connection_timeout = connection_timeout
                self.read_timeout = read_timeout
                self.keep_alive = keep_alive
                super().__init__(max_retries=max_retries)
            
            def init_poolmanager(self, *args, **kwargs):
                """Initialize pool manager with optimized settings"""
                kwargs.update({
                    'num_pools': self.pool_connections,
                    'maxsize': self.pool_maxsize,
                    'block': self.pool_block,
                    # Connection pool optimizations
                    'retries': False,  # Handle retries at adapter level
                    'timeout': urllib3.Timeout(connect=self.connection_timeout, read=self.read_timeout),
                    # Keep-alive optimization
                    'headers': {'Connection': 'keep-alive' if self.keep_alive else 'close'},
                })
                return super().init_poolmanager(*args, **kwargs)
        
        return PersistentHTTPAdapter(
            self.pool_connections, 
            self.pool_maxsize, 
            self.pool_block,
            self.connection_timeout,
            self.read_timeout,
            self.keep_alive,
            max_retries
        )


# Global connection pool instance for reuse across validators
_global_connection_pool = None

def get_global_connection_pool(config: Optional['ValidationConfig'] = None) -> PersistentHTTPConnectionPool:
    """Get global connection pool instance"""
    global _global_connection_pool
    if _global_connection_pool is None:
        _global_connection_pool = PersistentHTTPConnectionPool(config)
    return _global_connection_pool


class PersistentSOCKSConnectionPool:
    """Persistent SOCKS connection pool for optimal SOCKS proxy validation"""
    
    def __init__(self, config: Optional['ValidationConfig'] = None):
        if config:
            self.max_connections = config.socks_pool_connections
            self.pool_block = config.socks_pool_block
            self.connection_timeout = config.pool_connection_timeout
            self.read_timeout = config.pool_read_timeout
            self.keep_alive = config.pool_keep_alive
        else:
            # Default values
            self.max_connections = 100
            self.pool_block = False
            self.connection_timeout = 10.0
            self.read_timeout = 30.0
            self.keep_alive = True
            
        self._socks4_pools = {}
        self._socks5_pools = {}
        self._pool_lock = logging.getLogger().__class__.__module__  # Simple lock substitute
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    def get_socks_session(self, proxy: 'ProxyInfo') -> requests.Session:
        """Get a requests session configured for SOCKS proxy with connection reuse"""
        
        if not HAS_SOCKS:
            raise ImportError("PySocks library required for SOCKS connection pooling")
        
        # Create pool key based on proxy details
        pool_key = f"{proxy.protocol.value}://{proxy.host}:{proxy.port}"
        
        # Create session with SOCKS proxy configuration
        session = requests.Session()
        
        # Configure SOCKS proxy settings
        if proxy.protocol == ProxyProtocol.SOCKS4:
            proxy_url = f"socks4://{proxy.host}:{proxy.port}"
            if proxy.username:
                proxy_url = f"socks4://{proxy.username}@{proxy.host}:{proxy.port}"
        else:  # SOCKS5
            proxy_url = f"socks5://{proxy.host}:{proxy.port}"
            if proxy.username and proxy.password:
                proxy_url = f"socks5://{proxy.username}:{proxy.password}@{proxy.host}:{proxy.port}"
            elif proxy.username:
                proxy_url = f"socks5://{proxy.username}@{proxy.host}:{proxy.port}"
        
        # Configure session with SOCKS proxy
        session.proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        
        # Optimize session for connection reuse based on configuration
        pool_size = min(20, self.max_connections // 5)  # Dynamic pool sizing
        adapter = HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_size * 2,
            max_retries=3
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set headers based on configuration
        session.headers.update({
            'Connection': 'keep-alive' if self.keep_alive else 'close',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1'
        })
        
        return session
    
    def create_socks_socket(self, proxy: 'ProxyInfo', target_host: str, target_port: int) -> socket.socket:
        """Create a persistent SOCKS socket connection"""
        
        if not HAS_SOCKS:
            raise ImportError("PySocks library required for SOCKS socket connections")
        
        # Create SOCKS socket
        if proxy.protocol == ProxyProtocol.SOCKS4:
            sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            sock.set_proxy(socks.SOCKS4, proxy.host, proxy.port, username=proxy.username)
        else:  # SOCKS5
            sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            sock.set_proxy(socks.SOCKS5, proxy.host, proxy.port, 
                          username=proxy.username, password=proxy.password)
        
        # Configure socket options for better performance
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        # Connect to target through SOCKS proxy
        sock.connect((target_host, target_port))
        
        return sock


# Global SOCKS connection pool instance
_global_socks_pool = None

def get_global_socks_pool(config: Optional['ValidationConfig'] = None) -> PersistentSOCKSConnectionPool:
    """Get global SOCKS connection pool instance"""
    global _global_socks_pool
    if _global_socks_pool is None:
        _global_socks_pool = PersistentSOCKSConnectionPool(config)
    return _global_socks_pool


class SyncProxyValidator:
    """Synchronous proxy validator using requests"""
    
    def __init__(self, config: Optional[ValidationConfig] = None):
        if not HAS_REQUESTS:
            raise ImportError("requests library required. Install with: pip install requests")
        
        self.config = config or ValidationConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._real_ip = None
        
        # Create session
        self.session = self._create_session()
        
        # Initialize geo analyzer for country detection
        self.geo_analyzer = GeoAnalyzer()
        
        # Initialize intelligent retry manager
        if getattr(self.config, 'enable_intelligent_retries', True):
            retry_config = self._create_retry_config()
            self.retry_manager = IntelligentRetryManager(retry_config)
            self.logger.info("SyncProxyValidator initialized with intelligent retry manager")
        else:
            self.retry_manager = None
            self.logger.info("SyncProxyValidator initialized without retry manager")
        
        self.logger.info("SyncProxyValidator initialized")
    
    def _create_retry_config(self) -> RetryConfig:
        """Create retry configuration from validation config"""
        # Map string values to enums
        strategy_map = {
            'exponential_backoff': RetryStrategy.EXPONENTIAL_BACKOFF,
            'linear_backoff': RetryStrategy.LINEAR_BACKOFF,
            'fixed_interval': RetryStrategy.FIXED_INTERVAL,
            'adaptive': RetryStrategy.ADAPTIVE
        }
        
        jitter_map = {
            'none': JitterType.NONE,
            'full': JitterType.FULL,
            'equal': JitterType.EQUAL,
            'decorrelated': JitterType.DECORRELATED
        }
        
        return RetryConfig(
            max_retries=self.config.max_retries,
            base_delay=self.config.retry_delay,
            max_delay=getattr(self.config, 'retry_max_delay', 60.0),
            backoff_multiplier=self.config.backoff_factor,
            jitter_type=jitter_map.get(getattr(self.config, 'retry_jitter_type', 'equal'), JitterType.EQUAL),
            strategy=strategy_map.get(getattr(self.config, 'retry_strategy', 'exponential_backoff'), RetryStrategy.EXPONENTIAL_BACKOFF),
            retryable_reasons=self.config.retry_on_failure_reasons,
            enable_circuit_breaker=getattr(self.config, 'enable_circuit_breaker', True),
            circuit_breaker_threshold=getattr(self.config, 'circuit_breaker_threshold', 5),
            circuit_breaker_timeout=getattr(self.config, 'circuit_breaker_timeout', 30.0),
            adaptive_success_threshold=getattr(self.config, 'adaptive_success_threshold', 0.8),
            adaptive_failure_threshold=getattr(self.config, 'adaptive_failure_threshold', 0.3),
            adaptive_window_size=getattr(self.config, 'adaptive_window_size', 10),
            enable_retry_budget=getattr(self.config, 'enable_retry_budget', True),
            retry_budget_per_minute=getattr(self.config, 'retry_budget_per_minute', 100),
            retry_budget_window=getattr(self.config, 'retry_budget_window', 60.0)
        )
    
    def _create_session(self) -> requests.Session:
        """Create configured requests session with persistent connection pool"""
        session = requests.Session()
        
        # Configure retries
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504, 520, 521, 522, 523, 524]
        )
        
        # Use global persistent connection pool for optimal performance
        connection_pool = get_global_connection_pool(self.config)
        adapter = connection_pool.get_adapter(max_retries=retry_strategy)
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Default headers
        session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        return session
    
    def validate_proxy(self, proxy: ProxyInfo) -> ValidationResult:
        """Validate a single proxy"""
        result = ValidationResult(proxy=proxy)
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
                    if self.retry_manager:
                        # Use intelligent retry system
                        proxy_key = f"{proxy.host}:{proxy.port}"
                        success = self._validate_with_intelligent_retry(proxy, result, method, proxy_key)
                    else:
                        # Use basic validation without retries
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
        result.total_time = total_time
        
        # Update proxy status
        result.update_proxy_status()
        
        # Perform geographic analysis for valid proxies to populate country information
        if result.is_valid:
            try:
                geo_result = self.geo_analyzer.analyze_proxy(proxy)
                if geo_result.success:
                    self.logger.debug(f"Geographic analysis completed for {proxy.host} - Country: {proxy.geo_location.country_code if proxy.geo_location else 'Unknown'}")
                else:
                    self.logger.debug(f"Geographic analysis failed for {proxy.host}: {geo_result.error_message}")
            except Exception as e:
                self.logger.warning(f"Geographic analysis error for {proxy.host}: {e}")
        
        return result
    
    def _validate_with_intelligent_retry(self, proxy: ProxyInfo, result: ValidationResult,
                                       method: ValidationMethod, proxy_key: str) -> bool:
        """Validate proxy using specific method with intelligent retry"""
        last_exception = None
        start_time = time.time()
        
        for attempt in range(self.retry_manager.config.max_retries + 1):
            try:
                success = self._validate_with_method(proxy, result, method)
                
                if success and attempt > 0:
                    self.retry_manager.record_success(proxy_key)
                    total_time = time.time() - start_time
                    self.logger.info(f"Retry successful for {proxy.address} after {attempt} attempts in {total_time:.2f}s")
                
                return success
                
            except Exception as e:
                last_exception = e
                
                # Determine failure reason
                failure_reason = self.retry_manager._classify_exception(e)
                
                # Update result with failure information
                result.failure_reason = failure_reason
                result.error_message = str(e)
                
                # Check if we should retry
                if not self.retry_manager.should_retry(failure_reason, proxy_key, attempt):
                    break
                
                # Calculate delay
                delay = self.retry_manager.calculate_delay(attempt, failure_reason)
                
                # Record failure
                self.retry_manager.record_failure(proxy_key, failure_reason, attempt, delay)
                
                self.logger.debug(f"Retry {attempt + 1}/{self.retry_manager.config.max_retries} for {proxy.address} after {delay:.2f}s delay (reason: {failure_reason.value})")
                
                # Wait before retry
                time.sleep(delay)
        
        # All retries exhausted, raise the last exception
        if last_exception:
            raise last_exception
        
        return False
    
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
            return False
    
    def _validate_http_get(self, proxy: ProxyInfo, result: ValidationResult) -> bool:
        """Validate HTTP proxy using GET request"""
        test_url = random.choice(self.config.test_endpoints['ip_check'])
        result.test_endpoint_used = test_url
        
        # Configure proxy URL
        proxy_url = None
        if proxy.protocol in [ProxyProtocol.HTTP, ProxyProtocol.HTTPS]:
            if proxy.username and proxy.password:
                proxy_url = f"{proxy.protocol.value}://{proxy.username}:{proxy.password}@{proxy.host}:{proxy.port}"
            else:
                proxy_url = f"{proxy.protocol.value}://{proxy.host}:{proxy.port}"
        
        proxies = {'http': proxy_url, 'https': proxy_url} if proxy_url else None
        
        start_time = time.time()
        
        try:
            # Set random user agent
            headers = {'User-Agent': random.choice(self.config.user_agents)}
            
            response = self.session.get(
                test_url,
                proxies=proxies,
                timeout=(self.config.connect_timeout, self.config.read_timeout),
                allow_redirects=self.config.allow_redirects,
                verify=self.config.verify_ssl,
                headers=headers
            )
            
            response_time = (time.time() - start_time) * 1000
            result.response_time = response_time
            result.connect_time = response_time  # Approximation for sync
            result.user_agent_used = headers['User-Agent']
            
            if response.status_code == 200:
                content = response.text
                result.bytes_transferred = len(response.content)
                
                # Check for issues
                if self.config.detect_captive_portals:
                    if self._detect_captive_portal(content):
                        result.failure_reason = FailureReason.CAPTIVE_PORTAL
                        result.captive_portal_detected = True
                        return False
                
                if self.config.detect_deceptive_responses:
                    if self._detect_deceptive_response(content, test_url):
                        result.failure_reason = FailureReason.DECEPTIVE_RESPONSE
                        return False
                
                # Extract IP for anonymity analysis
                if self.config.enable_anonymity_testing:
                    self._analyze_anonymity(proxy, content, result)
                
                return True
            else:
                result.failure_reason = FailureReason.INVALID_RESPONSE
                result.error_message = f"HTTP {response.status_code}"
                return False
        
        except requests.exceptions.ConnectTimeout:
            result.failure_reason = FailureReason.TIMEOUT_CONNECT
            result.error_message = "Connection timeout"
        except requests.exceptions.ReadTimeout:
            result.failure_reason = FailureReason.TIMEOUT_READ
            result.error_message = "Read timeout"
        except requests.exceptions.Timeout:
            result.failure_reason = FailureReason.TIMEOUT_TOTAL
            result.error_message = "Request timeout"
        except requests.exceptions.ConnectionError as e:
            if "refused" in str(e).lower():
                result.failure_reason = FailureReason.CONNECTION_REFUSED
            elif "reset" in str(e).lower():
                result.failure_reason = FailureReason.CONNECTION_RESET
            else:
                result.failure_reason = FailureReason.CONNECTION_RESET
            result.error_message = str(e)
        except requests.exceptions.ProxyError as e:
            result.failure_reason = FailureReason.PROXY_ERROR
            result.error_message = str(e)
        except Exception as e:
            result.failure_reason = FailureReason.UNKNOWN_ERROR
            result.error_message = str(e)
        
        return False
    
    def _validate_http_connect(self, proxy: ProxyInfo, result: ValidationResult) -> bool:
        """Validate HTTP proxy using CONNECT method"""
        # This would require low-level socket programming
        # For now, fallback to GET method
        return self._validate_http_get(proxy, result)
    
    def _validate_socks_connect(self, proxy: ProxyInfo, result: ValidationResult) -> bool:
        """Validate SOCKS proxy using persistent connection pool"""
        if not HAS_SOCKS:
            self.logger.debug("PySocks not available, using HTTP validation")
            return self._validate_http_get(proxy, result)
        
        test_url = random.choice(self.config.test_endpoints['ip_check'])
        result.test_endpoint_used = test_url
        
        try:
            # Use persistent SOCKS connection pool for better performance
            socks_pool = get_global_socks_pool(self.config)
            socks_session = socks_pool.get_socks_session(proxy)
            
            start_time = time.time()
            
            # Set random user agent
            headers = {'User-Agent': random.choice(self.config.user_agents)}
            
            response = socks_session.get(
                test_url,
                timeout=(self.config.connect_timeout, self.config.read_timeout),
                verify=self.config.verify_ssl,
                headers=headers
            )
            
            response_time = (time.time() - start_time) * 1000
            result.response_time = response_time
            result.connect_time = response_time
            result.user_agent_used = headers['User-Agent']
            
            if response.status_code == 200:
                result.bytes_transferred = len(response.content)
                
                # Check for issues
                if self.config.detect_captive_portals:
                    if self._detect_captive_portal(response.text):
                        result.failure_reason = FailureReason.CAPTIVE_PORTAL
                        result.captive_portal_detected = True
                        return False
                
                if self.config.detect_deceptive_responses:
                    if self._detect_deceptive_response(response.text, test_url):
                        result.failure_reason = FailureReason.DECEPTIVE_RESPONSE
                        return False
                
                if self.config.enable_anonymity_testing:
                    self._analyze_anonymity(proxy, response.text, result)
                
                return True
            else:
                result.failure_reason = FailureReason.INVALID_RESPONSE
                result.error_message = f"HTTP {response.status_code}"
                return False
                
        except requests.exceptions.ConnectTimeout:
            result.failure_reason = FailureReason.TIMEOUT_CONNECT
            result.error_message = "SOCKS connection timeout"
        except requests.exceptions.ReadTimeout:
            result.failure_reason = FailureReason.TIMEOUT_READ
            result.error_message = "SOCKS read timeout"
        except requests.exceptions.Timeout:
            result.failure_reason = FailureReason.TIMEOUT_TOTAL
            result.error_message = "SOCKS request timeout"
        except requests.exceptions.ConnectionError as e:
            if "refused" in str(e).lower():
                result.failure_reason = FailureReason.CONNECTION_REFUSED
            elif "reset" in str(e).lower():
                result.failure_reason = FailureReason.CONNECTION_RESET
            else:
                result.failure_reason = FailureReason.CONNECTION_RESET
            result.error_message = f"SOCKS connection error: {e}"
        except requests.exceptions.ProxyError as e:
            result.failure_reason = FailureReason.PROXY_ERROR
            result.error_message = f"SOCKS proxy error: {e}"
        except Exception as e:
            result.failure_reason = FailureReason.PROXY_ERROR
            result.error_message = f"SOCKS validation error: {e}"
        
        return False
    
    def _validate_raw_socket(self, proxy: ProxyInfo, result: ValidationResult) -> bool:
        """Validate proxy using raw socket connection"""
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.connect_timeout)
            
            sock.connect((proxy.host, proxy.port))
            
            response_time = (time.time() - start_time) * 1000
            result.response_time = response_time
            result.connect_time = response_time
            
            sock.close()
            return True
            
        except socket.timeout:
            result.failure_reason = FailureReason.TIMEOUT_CONNECT
            result.error_message = "Socket connection timeout"
        except ConnectionRefusedError:
            result.failure_reason = FailureReason.CONNECTION_REFUSED
            result.error_message = "Connection refused"
        except Exception as e:
            result.failure_reason = FailureReason.UNKNOWN_ERROR
            result.error_message = str(e)
        
        return False
    
    def _perform_additional_tests(self, proxy: ProxyInfo, result: ValidationResult):
        """Perform additional tests on valid proxies"""
        # Test HTTPS support
        if self.config.enable_https_testing:
            self._test_https_support(proxy, result)
        
        # Test speed
        if self.config.enable_speed_testing:
            self._test_speed(proxy, result)
    
    def _test_https_support(self, proxy: ProxyInfo, result: ValidationResult):
        """Test HTTPS support"""
        try:
            https_url = random.choice(self.config.test_endpoints['https_check'])
            proxy_url = f"{proxy.protocol.value}://{proxy.host}:{proxy.port}"
            
            response = self.session.get(
                https_url,
                proxies={'https': proxy_url},
                timeout=(self.config.connect_timeout, self.config.read_timeout),
                verify=False
            )
            
            result.ssl_supported = response.status_code == 200
            
        except Exception:
            result.ssl_supported = False
    
    def _test_speed(self, proxy: ProxyInfo, result: ValidationResult):
        """Test download speed"""
        try:
            speed_url = random.choice(self.config.test_endpoints['speed_test'])
            proxy_url = f"{proxy.protocol.value}://{proxy.host}:{proxy.port}"
            
            start_time = time.time()
            response = self.session.get(
                speed_url,
                proxies={'http': proxy_url},
                timeout=(self.config.connect_timeout, self.config.read_timeout)
            )
            elapsed_time = time.time() - start_time
            
            if response.status_code == 200 and elapsed_time > 0:
                bytes_downloaded = len(response.content)
                result.download_speed = bytes_downloaded / elapsed_time
                result.bytes_transferred += bytes_downloaded
                
        except Exception:
            pass
    
    def _analyze_anonymity(self, proxy: ProxyInfo, ip_response: str, result: ValidationResult):
        """Analyze anonymity level"""
        try:
            # Extract IP from response
            proxy_ip = self._extract_ip_from_text(ip_response)
            result.proxy_ip_detected = proxy_ip
            
            # Get real IP if not cached
            if not self._real_ip:
                self._real_ip = self._get_real_ip()
            
            # Check if real IP is visible (transparent proxy)
            if self._real_ip and proxy_ip and self._real_ip in ip_response:
                result.anonymity_detected = AnonymityLevel.TRANSPARENT
                result.real_ip_detected = self._real_ip
                result.transparent_proxy = True
                return
            
            # Perform header analysis for anonymous vs elite classification
            if self.config.check_proxy_headers:
                headers_analysis = self._analyze_headers(proxy)
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
    
    def _get_real_ip(self) -> Optional[str]:
        """Get real IP address"""
        try:
            for url in self.config.test_endpoints['ip_check']:
                try:
                    response = self.session.get(url, timeout=5)
                    if response.status_code == 200:
                        ip = self._extract_ip_from_text(response.text)
                        if ip:
                            return ip
                except:
                    continue
        except Exception:
            pass
        return None
    
    def _analyze_headers(self, proxy: ProxyInfo) -> dict:
        """Analyze headers for proxy indicators"""
        try:
            headers_url = random.choice(self.config.test_endpoints['headers_check'])
            proxy_url = f"{proxy.protocol.value}://{proxy.host}:{proxy.port}"
            
            response = self.session.get(
                headers_url,
                proxies={'http': proxy_url},
                timeout=(self.config.connect_timeout, self.config.read_timeout)
            )
            
            if response.status_code == 200:
                data = response.json()
                received_headers = data.get('headers', {})
                return self._analyze_proxy_headers(received_headers)
        except Exception as e:
            self.logger.debug(f"Header analysis failed: {e}")
        
        return {'proxy_detected': False, 'anonymity_score': 100}
    
    def _analyze_proxy_headers(self, headers: dict) -> dict:
        """Analyze headers for proxy indicators"""
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
    
    def get_retry_stats(self) -> dict:
        """Get retry manager statistics"""
        if self.retry_manager:
            return self.retry_manager.get_stats()
        else:
            return {"retry_manager_enabled": False}
    
    def reset_circuit_breakers(self):
        """Reset all circuit breakers"""
        if self.retry_manager:
            self.retry_manager.reset_all_circuit_breakers()
    
    def reset_circuit_breaker(self, proxy_key: str):
        """Reset circuit breaker for specific proxy"""
        if self.retry_manager:
            self.retry_manager.reset_circuit_breaker(proxy_key)


def create_sync_validator(config: Optional[ValidationConfig] = None) -> SyncProxyValidator:
    """Create synchronous proxy validator"""
    return SyncProxyValidator(config)