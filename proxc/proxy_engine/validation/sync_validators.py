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
        
        self.logger.info("SyncProxyValidator initialized")
    
    def _create_session(self) -> requests.Session:
        """Create configured requests session"""
        session = requests.Session()
        
        # Configure retries
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504, 520, 521, 522, 523, 524]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.config.max_workers,
            pool_maxsize=self.config.max_workers * 2
        )
        
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
        """Validate SOCKS proxy"""
        if not HAS_SOCKS:
            self.logger.debug("PySocks not available, using HTTP validation")
            return self._validate_http_get(proxy, result)
        
        test_url = random.choice(self.config.test_endpoints['ip_check'])
        result.test_endpoint_used = test_url
        
        try:
            # Configure SOCKS proxy
            if proxy.protocol == ProxyProtocol.SOCKS4:
                socks.set_default_proxy(socks.SOCKS4, proxy.host, proxy.port, 
                                       username=proxy.username)
            else:  # SOCKS5
                socks.set_default_proxy(socks.SOCKS5, proxy.host, proxy.port,
                                       username=proxy.username, password=proxy.password)
            
            # Monkey patch socket
            original_socket = socket.socket
            socket.socket = socks.socksocket
            
            start_time = time.time()
            
            try:
                response = requests.get(
                    test_url,
                    timeout=(self.config.connect_timeout, self.config.read_timeout),
                    verify=self.config.verify_ssl
                )
                
                response_time = (time.time() - start_time) * 1000
                result.response_time = response_time
                result.connect_time = response_time
                
                if response.status_code == 200:
                    result.bytes_transferred = len(response.content)
                    
                    if self.config.enable_anonymity_testing:
                        self._analyze_anonymity(proxy, response.text, result)
                    
                    return True
                    
            finally:
                # Restore socket
                socket.socket = original_socket
                
        except Exception as e:
            result.failure_reason = FailureReason.PROXY_ERROR
            result.error_message = str(e)
        
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


def create_sync_validator(config: Optional[ValidationConfig] = None) -> SyncProxyValidator:
    """Create synchronous proxy validator"""
    return SyncProxyValidator(config)