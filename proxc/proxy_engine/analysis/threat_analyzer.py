"""Threat Analyzer - Security threat assessment and risk analysis"""

import logging
from typing import Optional, Tuple, Dict, List, Any

from ...proxy_core.models import (
    ProxyInfo, ThreatLevel
)
from ...proxy_core.config import ConfigManager
from ...proxy_core.utils import NetworkIntelligence, NetworkAnalysis
from .analysis_results import AnalysisResult, AnalysisType


class ThreatAnalyzer:
    """Threat assessment and security analysis"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.network_intel = NetworkIntelligence()
        self.logger = logging.getLogger(__name__)
    
    def analyze_proxy(self, proxy: ProxyInfo) -> AnalysisResult:
        """Perform threat analysis of proxy"""
        result = AnalysisResult(
            proxy_id=proxy.proxy_id,
            analysis_type=AnalysisType.THREAT,
            success=False
        )
        
        try:
            # Perform network analysis for threat detection
            network_analysis = self.network_intel.analyze_ip(proxy.host)
            
            # Analyze threats
            threat_data = {
                'threat_types': network_analysis.threat_types,
                'blacklist_status': network_analysis.blacklist_status,
                'is_tor': network_analysis.is_tor,
                'is_vpn': network_analysis.is_vpn,
                'is_proxy': network_analysis.is_proxy,
                'ports_open': network_analysis.ports_open,
                'services_detected': network_analysis.services_detected
            }
            
            # Calculate threat level and score
            threat_level, threat_score = self._assess_threat_level(network_analysis)
            
            # Update proxy threat level
            proxy.threat_level = threat_level
            
            result.success = True
            result.data = threat_data
            result.score = threat_score
            result.confidence = 0.8
            
            self.logger.debug(f"Threat analysis completed for {proxy.host}")
            
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            result.score = 0.0
            result.confidence = 0.0
            self.logger.error(f"Threat analysis failed for {proxy.host}: {e}")
        
        return result
    
    async def analyze_honeypot_indicators(self, proxy: ProxyInfo, headers: Dict[str, str],
                                        response_content: str = "", status_code: int = 200,
                                        response_times: List[float] = None) -> AnalysisResult:
        """Perform honeypot analysis of proxy"""
        result = AnalysisResult(
            proxy_id=proxy.proxy_id,
            analysis_type=AnalysisType.HONEYPOT,
            success=False
        )
        
        try:
            # Check if honeypot detection is enabled
            if not getattr(self.config, 'enable_honeypot_detection', False):
                result.success = True
                result.data = {'honeypot_detection_disabled': True}
                result.score = 100.0  # No honeypot detected (analysis disabled)
                result.confidence = 0.0
                return result
            
            # Import honeypot detector (lazy import to avoid circular dependencies)
            try:
                from ..security.honeypot_detector import HoneypotDetector
                from ..security.security_config import SecurityConfig
                
                # Create security config if not available
                security_config = SecurityConfig()
                security_config.enable_honeypot_detection = True
                
                detector = HoneypotDetector(security_config)
                
                # Perform honeypot analysis
                honeypot_result = await detector.analyze_honeypot_indicators(
                    proxy, headers, response_content, status_code, response_times
                )
                
                # Convert honeypot analysis to AnalysisResult format
                result.success = True
                result.data = honeypot_result.to_dict()
                
                # Calculate score (inverse of honeypot likelihood)
                if honeypot_result.is_honeypot_detected:
                    # High honeypot likelihood = low usability score
                    result.score = max(0.0, 100.0 - honeypot_result.risk_score)
                else:
                    # No honeypot detected = high usability score
                    result.score = 100.0
                
                result.confidence = honeypot_result.confidence
                
                self.logger.debug(f"Honeypot analysis completed for {proxy.host}: "
                                f"detected={honeypot_result.is_honeypot_detected}, "
                                f"confidence={honeypot_result.confidence:.2f}")
                
            except ImportError as ie:
                self.logger.warning(f"Honeypot detector not available: {ie}")
                result.success = False
                result.error_message = "Honeypot detector module not available"
                result.score = 0.0
                result.confidence = 0.0
                
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            result.score = 0.0
            result.confidence = 0.0
            self.logger.error(f"Honeypot analysis failed for {proxy.host}: {e}")
        
        return result
    
    async def analyze_tls_fingerprint(self, proxy: ProxyInfo, target_host: str = "www.google.com",
                                    target_port: int = 443) -> AnalysisResult:
        """Perform TLS fingerprinting analysis of proxy"""
        result = AnalysisResult(
            proxy_id=proxy.proxy_id,
            analysis_type=AnalysisType.TLS,
            success=False
        )
        
        try:
            # Check if TLS analysis is enabled
            if not getattr(self.config, 'enable_tls_analysis', False):
                result.success = True
                result.data = {'tls_analysis_disabled': True}
                result.score = 100.0  # No TLS issues detected (analysis disabled)
                result.confidence = 0.0
                return result
            
            # Import TLS fingerprinter (lazy import to avoid circular dependencies)
            try:
                from ..security.tls_fingerprinter import TLSFingerprinter
                from ..security.security_config import SecurityConfig
                
                # Create security config if not available
                security_config = SecurityConfig()
                security_config.enable_tls_analysis = True
                
                fingerprinter = TLSFingerprinter(security_config)
                
                # Perform TLS analysis
                tls_result = await fingerprinter.analyze_tls_fingerprint(
                    proxy, target_host, target_port
                )
                
                # Convert TLS analysis to AnalysisResult format
                result.success = True
                result.data = tls_result.to_dict()
                
                # Use security score from TLS analysis
                result.score = tls_result.security_score
                
                # Set confidence based on TLS analysis results
                if tls_result.is_tls_available:
                    if tls_result.certificate_valid and not tls_result.mitm_detected:
                        result.confidence = 0.9
                    elif tls_result.certificate_valid:
                        result.confidence = 0.7
                    else:
                        result.confidence = 0.5
                else:
                    result.confidence = 0.0
                
                self.logger.debug(f"TLS analysis completed for {proxy.host}: "
                                f"tls_available={tls_result.is_tls_available}, "
                                f"security_score={tls_result.security_score:.2f}, "
                                f"mitm_detected={tls_result.mitm_detected}")
                
            except ImportError as ie:
                self.logger.warning(f"TLS fingerprinter not available: {ie}")
                result.success = False
                result.error_message = "TLS fingerprinter module not available"
                result.score = 0.0
                result.confidence = 0.0
                
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            result.score = 0.0
            result.confidence = 0.0
            self.logger.error(f"TLS analysis failed for {proxy.host}: {e}")
        
        return result
    
    def _assess_threat_level(self, network_analysis: NetworkAnalysis) -> Tuple[ThreatLevel, float]:
        """Assess threat level and calculate security score"""
        risk_score = 0
        security_score = 100.0
        
        # Check blacklist status
        blacklisted_count = sum(1 for listed in network_analysis.blacklist_status.values() if listed)
        if blacklisted_count > 0:
            risk_score += blacklisted_count * 25
            security_score -= blacklisted_count * 30
        
        # Check for dangerous threat types
        dangerous_threats = ['tor_exit_node', 'blacklisted', 'hosting_provider']
        for threat in network_analysis.threat_types:
            if threat in dangerous_threats:
                risk_score += 20
                security_score -= 25
        
        # Check for suspicious services
        suspicious_ports = [1080, 3128, 8080, 8888, 9050]  # Common proxy/Tor ports
        for port in network_analysis.ports_open:
            if port in suspicious_ports:
                risk_score += 5
                security_score -= 5
        
        # Determine threat level
        if risk_score >= 75:
            threat_level = ThreatLevel.CRITICAL
        elif risk_score >= 50:
            threat_level = ThreatLevel.HIGH
        elif risk_score >= 25:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW
        
        return threat_level, max(0.0, min(100.0, security_score))
    
    def analyze_captcha_blocking(self, response_content: str, response_headers: dict, 
                                status_code: int) -> dict:
        """Analyze response for CAPTCHA and automation blocking patterns
        
        Args:
            response_content: HTTP response body content
            response_headers: HTTP response headers
            status_code: HTTP status code
            
        Returns:
            Dictionary with blocking analysis results
        """
        blocking_analysis = {
            'captcha_detected': False,
            'automation_blocking': False,
            'blocking_type': None,
            'blocking_confidence': 0.0,
            'blocking_service': None,
            'details': []
        }
        
        try:
            content_lower = response_content.lower()
            headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
            
            # CAPTCHA Detection
            captcha_indicators = self._detect_captcha_patterns(content_lower, headers_lower)
            if captcha_indicators['detected']:
                blocking_analysis['captcha_detected'] = True
                blocking_analysis['blocking_type'] = 'captcha'
                blocking_analysis['blocking_service'] = captcha_indicators['service']
                blocking_analysis['blocking_confidence'] = captcha_indicators['confidence']
                blocking_analysis['details'].extend(captcha_indicators['details'])
            
            # Automation Blocking Detection
            automation_indicators = self._detect_automation_blocking(content_lower, headers_lower, status_code)
            if automation_indicators['detected']:
                blocking_analysis['automation_blocking'] = True
                if not blocking_analysis['blocking_type']:
                    blocking_analysis['blocking_type'] = 'automation_blocking'
                blocking_analysis['blocking_confidence'] = max(
                    blocking_analysis['blocking_confidence'],
                    automation_indicators['confidence']
                )
                blocking_analysis['details'].extend(automation_indicators['details'])
            
            # Bot Detection
            bot_indicators = self._detect_bot_blocking(content_lower, headers_lower)
            if bot_indicators['detected']:
                blocking_analysis['automation_blocking'] = True
                if not blocking_analysis['blocking_type']:
                    blocking_analysis['blocking_type'] = 'bot_detection'
                blocking_analysis['blocking_service'] = bot_indicators.get('service', 'unknown')
                blocking_analysis['blocking_confidence'] = max(
                    blocking_analysis['blocking_confidence'],
                    bot_indicators['confidence']
                )
                blocking_analysis['details'].extend(bot_indicators['details'])
            
        except Exception as e:
            self.logger.debug(f"Error analyzing blocking patterns: {e}")
            blocking_analysis['details'].append(f"Analysis error: {str(e)}")
        
        return blocking_analysis
    
    def _detect_captcha_patterns(self, content: str, headers: dict) -> dict:
        """Detect CAPTCHA patterns in response"""
        result = {'detected': False, 'service': None, 'confidence': 0.0, 'details': []}
        
        # Common CAPTCHA services and their indicators
        captcha_services = {
            'cloudflare': [
                'cloudflare', 'cf-ray', 'challenge', 'captcha',
                'please enable cookies', 'checking your browser',
                'ddos protection', 'ray id'
            ],
            'recaptcha': [
                'recaptcha', 'g-recaptcha', 'grecaptcha',
                'i\'m not a robot', 'verify you are human'
            ],
            'hcaptcha': [
                'hcaptcha', 'h-captcha', 'please verify you are human',
                'hcaptcha.com'
            ],
            'funcaptcha': [
                'funcaptcha', 'arkoselabs', 'fun captcha',
                'please complete the security check'
            ],
            'generic': [
                'captcha', 'security check', 'verify human',
                'are you a robot', 'bot protection'
            ]
        }
        
        # Check content for CAPTCHA indicators
        for service, indicators in captcha_services.items():
            matches = sum(1 for indicator in indicators if indicator in content)
            if matches > 0:
                confidence = min(0.9, matches * 0.3)
                if confidence > result['confidence']:
                    result['detected'] = True
                    result['service'] = service
                    result['confidence'] = confidence
                    result['details'].append(f"CAPTCHA detected: {service} ({matches} indicators)")
        
        # Check headers for CAPTCHA-related information
        captcha_headers = [
            'cf-ray', 'cf-cache-status', 'server'
        ]
        
        for header in captcha_headers:
            if header in headers:
                header_value = headers[header]
                if 'cloudflare' in header_value or 'cf-' in header:
                    result['detected'] = True
                    result['service'] = 'cloudflare'
                    result['confidence'] = max(result['confidence'], 0.6)
                    result['details'].append(f"Cloudflare header detected: {header}")
        
        return result
    
    def _detect_automation_blocking(self, content: str, headers: dict, status_code: int) -> dict:
        """Detect automation/bot blocking patterns"""
        result = {'detected': False, 'confidence': 0.0, 'details': []}
        
        # Common automation blocking phrases
        blocking_phrases = [
            'access denied', 'blocked', 'forbidden',
            'rate limited', 'too many requests',
            'suspicious activity', 'automated request',
            'bot detected', 'proxy detected',
            'vpn detected', 'unusual traffic',
            'security policy violation'
        ]
        
        # Check for blocking phrases
        matches = sum(1 for phrase in blocking_phrases if phrase in content)
        if matches > 0:
            result['detected'] = True
            result['confidence'] = min(0.8, matches * 0.2)
            result['details'].append(f"Automation blocking phrases detected ({matches} matches)")
        
        # Check HTTP status codes indicative of blocking
        blocking_status_codes = [403, 429, 503, 418]  # 418 = "I'm a teapot" (often used for bot detection)
        if status_code in blocking_status_codes:
            result['detected'] = True
            result['confidence'] = max(result['confidence'], 0.7)
            result['details'].append(f"Blocking status code: {status_code}")
        
        # Check for rate limiting headers
        rate_limit_headers = [
            'x-ratelimit-remaining', 'x-rate-limit-remaining',
            'retry-after', 'x-retry-after'
        ]
        
        for header in rate_limit_headers:
            if header in headers:
                result['detected'] = True
                result['confidence'] = max(result['confidence'], 0.6)
                result['details'].append(f"Rate limiting header: {header}")
        
        return result
    
    def _detect_bot_blocking(self, content: str, headers: dict) -> dict:
        """Detect bot/proxy specific blocking patterns"""
        result = {'detected': False, 'service': None, 'confidence': 0.0, 'details': []}
        
        # Service-specific bot blocking patterns
        bot_services = {
            'distil_networks': [
                'distil networks', 'distil_r_captcha', 'distilnetworks.com'
            ],
            'imperva': [
                'imperva', 'incapsula', 'incap_ses'
            ],
            'akamai': [
                'akamai', 'ghost', 'reference #'
            ],
            'cloudfront': [
                'cloudfront', 'request blocked'
            ],
            'perimeterx': [
                'perimeterx', 'px-captcha', 'human verification'
            ]
        }
        
        # Check for service-specific patterns
        for service, patterns in bot_services.items():
            matches = sum(1 for pattern in patterns if pattern in content)
            if matches > 0:
                result['detected'] = True
                result['service'] = service
                result['confidence'] = min(0.9, matches * 0.4)
                result['details'].append(f"Bot blocking service detected: {service}")
                break
        
        # Generic bot detection patterns
        if not result['detected']:
            generic_patterns = [
                'javascript required', 'enable javascript',
                'browser verification', 'checking browser',
                'loading...', 'please wait',
                'security check in progress'
            ]
            
            matches = sum(1 for pattern in generic_patterns if pattern in content)
            if matches > 1:  # Require multiple matches for generic patterns
                result['detected'] = True
                result['service'] = 'generic'
                result['confidence'] = min(0.7, matches * 0.2)
                result['details'].append(f"Generic bot detection patterns ({matches} matches)")
        
        return result
    
    def calculate_blocking_score(self, blocking_analysis: dict) -> float:
        """Calculate blocking likelihood score (0.0 to 1.0)
        
        Args:
            blocking_analysis: Result from analyze_captcha_blocking
            
        Returns:
            Blocking score where 1.0 = definitely blocked, 0.0 = not blocked
        """
        if not blocking_analysis:
            return 0.0
        
        base_score = 0.0
        
        # CAPTCHA detection contributes heavily to blocking score
        if blocking_analysis['captcha_detected']:
            base_score = max(base_score, 0.8)
        
        # Automation blocking detection
        if blocking_analysis['automation_blocking']:
            base_score = max(base_score, 0.7)
        
        # Apply confidence multiplier
        confidence = blocking_analysis.get('blocking_confidence', 0.0)
        final_score = base_score * confidence
        
        return min(1.0, final_score)
    
    async def analyze_proxy_chain(self, proxy: ProxyInfo, headers: Dict[str, str],
                                response_content: str = "", response_times: List[float] = None) -> Dict[str, Any]:
        """Analyze proxy for chain detection and security implications
        
        Args:
            proxy: ProxyInfo object
            headers: HTTP response headers
            response_content: Response body content
            response_times: List of response times for timing analysis
            
        Returns:
            Dictionary with chain analysis results
        """
        try:
            from ..security.chain_detector import ChainDetector
            from ..security.security_config import ChainDetectionConfig
            
            # Create chain detection config
            chain_config = ChainDetectionConfig(
                max_acceptable_chain_depth=3,
                min_confidence_threshold=0.7,
                analyze_via_headers=True,
                analyze_forwarded_headers=True,
                analyze_response_times=True,
                enable_risk_scoring=True
            )
            
            # Perform chain analysis
            detector = ChainDetector(chain_config)
            chain_result = await detector.analyze_proxy_chain(
                proxy, headers, response_content, response_times
            )
            
            # Convert to dict for integration with existing threat analysis
            chain_analysis = {
                'is_chain_detected': chain_result.is_chain_detected,
                'chain_depth': chain_result.chain_info.chain_depth,
                'chain_confidence': chain_result.confidence,
                'risk_level': chain_result.risk_level.value,
                'risk_score': chain_result.risk_score,
                'detected_proxies': chain_result.chain_info.detected_proxies,
                'proxy_software': chain_result.chain_info.proxy_software,
                'mixed_protocols': chain_result.chain_info.mixed_protocols,
                'inconsistencies': chain_result.chain_info.inconsistencies,
                'has_anomalies': chain_result.chain_info.has_anomalies,
                'matched_signatures': chain_result.matched_signatures,
                'analysis_time': chain_result.analysis_time
            }
            
            self.logger.debug(f"Chain analysis completed for {proxy.address}: "
                            f"depth={chain_analysis['chain_depth']}, "
                            f"confidence={chain_analysis['chain_confidence']:.2f}")
            
            return chain_analysis
            
        except ImportError:
            self.logger.warning("Chain detection module not available")
            return {
                'is_chain_detected': False,
                'chain_depth': 0,
                'error': 'Chain detection module not available'
            }
        except Exception as e:
            self.logger.error(f"Chain analysis failed for {proxy.address}: {e}")
            return {
                'is_chain_detected': False,
                'chain_depth': 0,
                'error': str(e)
            }


def create_threat_analyzer(config: Optional[ConfigManager] = None) -> ThreatAnalyzer:
    """Create threat analyzer"""
    return ThreatAnalyzer(config)


def analyze_proxy_threats_only(proxy: ProxyInfo) -> AnalysisResult:
    """Analyze only threat information"""
    analyzer = create_threat_analyzer()
    return analyzer.analyze_proxy(proxy)