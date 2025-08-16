"""Target Website Validator - Test proxies against specific target websites"""

import asyncio
import logging
import re
import time
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

# HTTP imports
try:
    import aiohttp
    from aiohttp import ClientSession, ClientTimeout, ClientError
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

# Import our models
from ...proxy_core.models import ProxyInfo, ProxyProtocol
from .validation_config import (
    TargetTestConfig, 
    TargetTestResult, 
    TargetTestType, 
    TargetSuccessMetric,
    FailureReason,
    ValidationConfig
)


class TargetValidator:
    """Validator for testing proxies against specific target websites"""
    
    def __init__(self, config: ValidationConfig):
        """Initialize target validator
        
        Args:
            config: Validation configuration with target settings
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        if not HAS_AIOHTTP:
            raise ImportError("aiohttp required for target validation. Install with: pip install aiohttp")
    
    async def validate_proxy_targets(self, proxy: ProxyInfo, session: Optional[ClientSession] = None) -> List[TargetTestResult]:
        """Validate proxy against all configured targets
        
        Args:
            proxy: Proxy to test
            session: Optional aiohttp session to reuse
            
        Returns:
            List of target test results
        """
        if not self.config.enable_target_testing:
            return []
        
        targets = self.config.get_enabled_targets()
        if not targets:
            return []
        
        results = []
        
        # Create session if not provided
        should_close_session = session is None
        if session is None:
            timeout = ClientTimeout(
                connect=self.config.connect_timeout,
                sock_read=self.config.read_timeout,
                total=self.config.total_timeout
            )
            session = ClientSession(timeout=timeout)
        
        try:
            if self.config.target_parallel_testing:
                # Test all targets in parallel
                tasks = [
                    self._test_target(proxy, target, session) 
                    for target in targets
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Convert exceptions to failed results
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        self.logger.error(f"Target test error for {targets[i].name}: {result}")
                        results[i] = TargetTestResult(
                            target_name=targets[i].name or targets[i].url,
                            target_url=targets[i].url,
                            success=False,
                            error_message=str(result),
                            failure_reason=FailureReason.UNKNOWN_ERROR
                        )
            else:
                # Test targets sequentially
                for target in targets:
                    try:
                        result = await self._test_target(proxy, target, session)
                        results.append(result)
                        
                        # Check fail-fast setting
                        if self.config.target_fail_fast and not result.success:
                            self.logger.debug(f"Stopping target tests due to failure: {target.name}")
                            break
                            
                    except Exception as e:
                        self.logger.error(f"Target test error for {target.name}: {e}")
                        results.append(TargetTestResult(
                            target_name=target.name or target.url,
                            target_url=target.url,
                            success=False,
                            error_message=str(e),
                            failure_reason=FailureReason.UNKNOWN_ERROR
                        ))
                        
                        if self.config.target_fail_fast:
                            break
        
        finally:
            if should_close_session:
                await session.close()
        
        return results
    
    async def _test_target(self, proxy: ProxyInfo, target: TargetTestConfig, session: ClientSession) -> TargetTestResult:
        """Test proxy against a specific target
        
        Args:
            proxy: Proxy to test
            target: Target configuration
            session: aiohttp session
            
        Returns:
            Target test result
        """
        result = TargetTestResult(
            target_name=target.name or target.url,
            target_url=target.url,
            success=False
        )
        
        start_time = time.time()
        
        try:
            # Build proxy URL
            proxy_url = self._build_proxy_url(proxy)
            
            # Prepare request
            headers = dict(target.headers)
            if 'User-Agent' not in headers:
                headers['User-Agent'] = self.config.user_agents[0] if self.config.user_agents else \
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            
            # Make request through proxy
            async with session.request(
                method=target.method,
                url=target.url,
                headers=headers,
                data=target.data,
                params=target.params,
                proxy=proxy_url,
                allow_redirects=self.config.allow_redirects,
                max_redirects=self.config.max_redirects,
                ssl=False if not self.config.verify_ssl else None
            ) as response:
                
                # Record response details
                result.status_code = response.status
                result.response_time = time.time() - start_time
                result.headers = dict(response.headers)
                
                # Read content
                content = await response.text()
                result.content_length = len(content)
                
                # Run individual tests
                await self._run_individual_tests(target, result, response, content)
                
                # Calculate overall success
                result.success, result.overall_score = self._calculate_overall_success(target, result)
        
        except Exception as e:
            result.response_time = time.time() - start_time
            result.error_message = str(e)
            result.failure_reason = self._classify_error(e)
            
            self.logger.debug(f"Target test failed for {target.name}: {e}")
        
        return result
    
    async def _run_individual_tests(self, target: TargetTestConfig, result: TargetTestResult, 
                                  response: aiohttp.ClientResponse, content: str):
        """Run individual test types for a target
        
        Args:
            target: Target configuration
            result: Result object to populate
            response: HTTP response
            content: Response content
        """
        for test_type in target.test_types:
            try:
                if test_type == TargetTestType.BASIC_ACCESS:
                    success = await self._test_basic_access(target, response, content)
                    
                elif test_type == TargetTestType.STATUS_CODE:
                    success = await self._test_status_code(target, response)
                    
                elif test_type == TargetTestType.CONTENT_VALIDATION:
                    success = await self._test_content_validation(target, content)
                    
                elif test_type == TargetTestType.HEADER_VALIDATION:
                    success = await self._test_header_validation(target, response)
                    
                elif test_type == TargetTestType.RESPONSE_TIME:
                    success = await self._test_response_time(target, result)
                    
                elif test_type == TargetTestType.GEO_BLOCKING:
                    success = await self._test_geo_blocking(target, response, content)
                    
                elif test_type == TargetTestType.LOGIN_TEST:
                    success = await self._test_login(target, response, content)
                    
                else:
                    success = False
                    result.test_details[test_type] = "Unknown test type"
                
                result.test_results[test_type] = success
                result.test_scores[test_type] = 1.0 if success else 0.0
                
            except Exception as e:
                self.logger.debug(f"Individual test {test_type} failed: {e}")
                result.test_results[test_type] = False
                result.test_scores[test_type] = 0.0
                result.test_details[test_type] = str(e)
    
    async def _test_basic_access(self, target: TargetTestConfig, response: aiohttp.ClientResponse, content: str) -> bool:
        """Test basic access to target"""
        return 200 <= response.status < 400 and len(content) > 0
    
    async def _test_status_code(self, target: TargetTestConfig, response: aiohttp.ClientResponse) -> bool:
        """Test HTTP status code"""
        return response.status in target.expected_status_codes
    
    async def _test_content_validation(self, target: TargetTestConfig, content: str) -> bool:
        """Test content validation rules"""
        # Check required content
        for required_text in target.content_must_contain:
            if required_text.lower() not in content.lower():
                return False
        
        # Check forbidden content
        for forbidden_text in target.content_must_not_contain:
            if forbidden_text.lower() in content.lower():
                return False
        
        # Check regex patterns
        patterns = target.get_compiled_patterns()
        for pattern in patterns:
            if not pattern.search(content):
                return False
        
        # Check content length limits
        if target.min_content_length and len(content) < target.min_content_length:
            return False
        if target.max_content_length and len(content) > target.max_content_length:
            return False
        
        return True
    
    async def _test_header_validation(self, target: TargetTestConfig, response: aiohttp.ClientResponse) -> bool:
        """Test header validation rules"""
        for header_name, expected_value in target.required_headers.items():
            actual_value = response.headers.get(header_name, '')
            if expected_value.lower() not in actual_value.lower():
                return False
        return True
    
    async def _test_response_time(self, target: TargetTestConfig, result: TargetTestResult) -> bool:
        """Test response time requirements"""
        if target.max_response_time and result.response_time:
            return result.response_time <= target.max_response_time
        return True
    
    async def _test_geo_blocking(self, target: TargetTestConfig, response: aiohttp.ClientResponse, content: str) -> bool:
        """Test geo-blocking detection"""
        # Look for common geo-blocking indicators
        geo_block_indicators = [
            'not available in your country',
            'geo-restricted',
            'region blocked',
            'location not supported',
            'vpn detected',
            'proxy detected'
        ]
        
        content_lower = content.lower()
        for indicator in geo_block_indicators:
            if indicator in content_lower:
                return False
        
        # Check for redirect to geo-block pages
        if response.status in [301, 302, 403]:
            location = response.headers.get('Location', '')
            if any(keyword in location.lower() for keyword in ['geo', 'block', 'region', 'country']):
                return False
        
        return True
    
    async def _test_login(self, target: TargetTestConfig, response: aiohttp.ClientResponse, content: str) -> bool:
        """Test login functionality"""
        if not target.auth_username or not target.auth_password:
            return True  # Skip if no auth configured
        
        # Look for login success indicators
        login_success_indicators = [
            'welcome',
            'dashboard',
            'logout',
            'profile',
            'account'
        ]
        
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in login_success_indicators)
    
    def _calculate_overall_success(self, target: TargetTestConfig, result: TargetTestResult) -> Tuple[bool, float]:
        """Calculate overall success and score for target test
        
        Args:
            target: Target configuration
            result: Test result with individual scores
            
        Returns:
            Tuple of (success, score)
        """
        if not result.test_results:
            return False, 0.0
        
        if target.success_metric == TargetSuccessMetric.ALL_PASS:
            success = all(result.test_results.values())
            score = 1.0 if success else 0.0
            
        elif target.success_metric == TargetSuccessMetric.ANY_PASS:
            success = any(result.test_results.values())
            score = 1.0 if success else 0.0
            
        elif target.success_metric == TargetSuccessMetric.MAJORITY_PASS:
            passed_count = sum(result.test_results.values())
            total_count = len(result.test_results)
            score = passed_count / total_count if total_count > 0 else 0.0
            success = score > 0.5
            
        elif target.success_metric == TargetSuccessMetric.WEIGHTED_SCORE:
            total_weight = 0.0
            weighted_score = 0.0
            
            for test_type, passed in result.test_results.items():
                weight = target.test_weights.get(test_type, 1.0)
                total_weight += weight
                if passed:
                    weighted_score += weight
            
            score = weighted_score / total_weight if total_weight > 0 else 0.0
            success = score >= target.success_threshold
            
        else:
            success = False
            score = 0.0
        
        return success, score
    
    def _build_proxy_url(self, proxy: ProxyInfo) -> str:
        """Build proxy URL for aiohttp"""
        if proxy.protocol in [ProxyProtocol.HTTP, ProxyProtocol.HTTPS]:
            return f"http://{proxy.host}:{proxy.port}"
        elif proxy.protocol == ProxyProtocol.SOCKS4:
            return f"socks4://{proxy.host}:{proxy.port}"
        elif proxy.protocol == ProxyProtocol.SOCKS5:
            return f"socks5://{proxy.host}:{proxy.port}"
        else:
            return f"http://{proxy.host}:{proxy.port}"
    
    def _classify_error(self, error: Exception) -> FailureReason:
        """Classify error into failure reason"""
        error_str = str(error).lower()
        
        if 'timeout' in error_str:
            return FailureReason.TIMEOUT_TOTAL
        elif 'connection' in error_str and 'refused' in error_str:
            return FailureReason.CONNECTION_REFUSED
        elif 'connection' in error_str and 'reset' in error_str:
            return FailureReason.CONNECTION_RESET
        elif 'dns' in error_str or 'resolve' in error_str:
            return FailureReason.DNS_RESOLUTION
        elif 'ssl' in error_str or 'certificate' in error_str:
            return FailureReason.SSL_ERROR
        elif 'proxy' in error_str:
            return FailureReason.PROXY_ERROR
        elif 'blocked' in error_str or 'forbidden' in error_str:
            return FailureReason.TARGET_BLOCKED
        else:
            return FailureReason.UNKNOWN_ERROR
    
    def calculate_target_success_rate(self, target_results: List[TargetTestResult]) -> float:
        """Calculate overall success rate across all targets
        
        Args:
            target_results: List of target test results
            
        Returns:
            Success rate (0.0 to 1.0)
        """
        if not target_results:
            return 0.0
        
        successful_tests = sum(1 for result in target_results if result.success)
        return successful_tests / len(target_results)
    
    def meets_target_threshold(self, target_results: List[TargetTestResult]) -> bool:
        """Check if target test results meet the configured threshold
        
        Args:
            target_results: List of target test results
            
        Returns:
            True if threshold is met
        """
        success_rate = self.calculate_target_success_rate(target_results)
        return success_rate >= self.config.target_success_threshold


# Utility functions for target testing
def create_target_config_from_url(url: str, **kwargs) -> TargetTestConfig:
    """Create a target configuration from URL with optional parameters"""
    return TargetTestConfig(url=url, **kwargs)


def load_targets_from_list(urls: List[str]) -> List[TargetTestConfig]:
    """Load target configurations from a list of URLs"""
    return [TargetTestConfig(url=url, name=url) for url in urls]


def get_predefined_target_names() -> List[str]:
    """Get list of available predefined target names"""
    from .validation_config import PREDEFINED_TARGETS
    return list(PREDEFINED_TARGETS.keys())