"""Honeypot Detector - Identification and analysis of honeypot proxy services"""

import logging
import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

from .security_config import SecurityConfig, ChainRiskLevel
from .security_utils import SecurityUtils
from ...proxy_core.models import ProxyInfo, ProxyProtocol


@dataclass
class HoneypotSignature:
    """Signature pattern for honeypot detection"""
    name: str
    description: str
    pattern_type: str  # 'response', 'header', 'behavioral', 'network'
    detection_patterns: Dict[str, Any]
    confidence_weight: float = 1.0
    risk_level: str = "medium"  # low, medium, high, critical
    
    def matches(self, data: Dict[str, Any]) -> Tuple[bool, float]:
        """Check if data matches this signature pattern"""
        if self.pattern_type == 'response':
            return self._match_response_pattern(data)
        elif self.pattern_type == 'header':
            return self._match_header_pattern(data)
        elif self.pattern_type == 'behavioral':
            return self._match_behavioral_pattern(data)
        elif self.pattern_type == 'network':
            return self._match_network_pattern(data)
        else:
            return False, 0.0
    
    def _match_response_pattern(self, data: Dict[str, Any]) -> Tuple[bool, float]:
        """Match response content patterns indicating honeypot"""
        response_content = data.get('response_content', '')
        status_code = data.get('status_code', 0)
        
        confidence = 0.0
        matches = 0
        
        # Check for honeypot framework signatures
        framework_patterns = self.detection_patterns.get('framework_signatures', [])
        for pattern in framework_patterns:
            if pattern.lower() in response_content.lower():
                matches += 1
                confidence += 0.4
        
        # Check for templated/generic responses
        template_patterns = self.detection_patterns.get('template_indicators', [])
        for pattern in template_patterns:
            if pattern.lower() in response_content.lower():
                matches += 1
                confidence += 0.3
        
        # Check for artificial error patterns
        error_patterns = self.detection_patterns.get('artificial_errors', [])
        for pattern in error_patterns:
            if pattern.lower() in response_content.lower():
                matches += 1
                confidence += 0.5
        
        # Check response length patterns (suspiciously consistent lengths)
        expected_length = self.detection_patterns.get('suspicious_length_range', (0, 0))
        if expected_length[0] > 0 and expected_length[0] <= len(response_content) <= expected_length[1]:
            matches += 1
            confidence += 0.2
        
        return matches > 0, min(1.0, confidence * self.confidence_weight)
    
    def _match_header_pattern(self, data: Dict[str, Any]) -> Tuple[bool, float]:
        """Match header patterns indicating honeypot"""
        headers = data.get('headers', {})
        
        confidence = 0.0
        matches = 0
        
        # Check for honeypot-specific headers
        honeypot_headers = self.detection_patterns.get('honeypot_headers', [])
        for header_name in honeypot_headers:
            if header_name.lower() in {k.lower() for k in headers.keys()}:
                matches += 1
                confidence += 0.6
        
        # Check for suspicious server signatures
        server_header = headers.get('server', headers.get('Server', ''))
        suspicious_servers = self.detection_patterns.get('suspicious_servers', [])
        for server_pattern in suspicious_servers:
            if server_pattern.lower() in server_header.lower():
                matches += 1
                confidence += 0.4
        
        # Check for missing expected headers (sign of incomplete implementation)
        missing_headers = self.detection_patterns.get('typically_missing', [])
        missing_count = sum(1 for header in missing_headers 
                          if header.lower() not in {k.lower() for k in headers.keys()})
        if missing_count >= len(missing_headers) * 0.7:  # 70% or more missing
            matches += 1
            confidence += 0.3
        
        # Check for header value patterns
        header_patterns = self.detection_patterns.get('header_value_patterns', {})
        for header_name, pattern in header_patterns.items():
            header_value = headers.get(header_name, headers.get(header_name.title(), ''))
            if pattern.lower() in header_value.lower():
                matches += 1
                confidence += 0.3
        
        return matches > 0, min(1.0, confidence * self.confidence_weight)
    
    def _match_behavioral_pattern(self, data: Dict[str, Any]) -> Tuple[bool, float]:
        """Match behavioral patterns indicating honeypot"""
        response_times = data.get('response_times', [])
        response_history = data.get('response_history', [])
        
        confidence = 0.0
        matches = 0
        
        # Check for artificially consistent response times
        if len(response_times) >= 3:
            if statistics.pstdev(response_times) < 0.01:  # Very low deviation
                matches += 1
                confidence += 0.4
        
        # Check for identical responses across multiple requests
        if len(response_history) >= 2:
            identical_responses = sum(1 for i in range(1, len(response_history))
                                    if response_history[i] == response_history[0])
            if identical_responses >= len(response_history) * 0.8:  # 80%+ identical
                matches += 1
                confidence += 0.5
        
        # Check for artificial delay patterns
        min_expected_delay = self.detection_patterns.get('artificial_delay_ms', 0)
        if response_times and min(response_times) >= min_expected_delay / 1000:
            matches += 1
            confidence += 0.3
        
        return matches > 0, min(1.0, confidence * self.confidence_weight)
    
    def _match_network_pattern(self, data: Dict[str, Any]) -> Tuple[bool, float]:
        """Match network-level patterns indicating honeypot"""
        proxy_info = data.get('proxy_info')
        network_data = data.get('network_data', {})
        
        confidence = 0.0
        matches = 0
        
        # Check for suspicious port patterns
        suspicious_ports = self.detection_patterns.get('suspicious_ports', [])
        if proxy_info and proxy_info.port in suspicious_ports:
            matches += 1
            confidence += 0.3
        
        # Check for hosting provider patterns
        hosting_patterns = self.detection_patterns.get('hosting_indicators', [])
        host_info = network_data.get('host_info', '')
        for pattern in hosting_patterns:
            if pattern.lower() in host_info.lower():
                matches += 1
                confidence += 0.2
        
        return matches > 0, min(1.0, confidence * self.confidence_weight)


@dataclass
class HoneypotAnalysisResult:
    """Result of honeypot analysis"""
    proxy_id: str
    is_honeypot_detected: bool = False
    confidence: float = 0.0
    risk_level: str = "low"
    risk_score: float = 0.0
    matched_signatures: List[str] = field(default_factory=list)
    honeypot_type: Optional[str] = None  # framework, behavioral, network
    indicators: List[str] = field(default_factory=list)
    analysis_time: float = 0.0
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'proxy_id': self.proxy_id,
            'is_honeypot_detected': self.is_honeypot_detected,
            'confidence': self.confidence,
            'risk_level': self.risk_level,
            'risk_score': self.risk_score,
            'matched_signatures': self.matched_signatures,
            'honeypot_type': self.honeypot_type,
            'indicators': self.indicators,
            'analysis_time': self.analysis_time,
            'error_message': self.error_message
        }


class HoneypotDetector:
    """Advanced honeypot proxy detection and analysis"""
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize detection signatures
        self.signatures = self._load_detection_signatures()
        
        self.logger.info(f"HoneypotDetector initialized with {len(self.signatures)} signatures")
    
    def _load_detection_signatures(self) -> List[HoneypotSignature]:
        """Load predefined honeypot detection signatures"""
        signatures = []
        
        # T-Pot honeypot framework detection
        signatures.append(HoneypotSignature(
            name="tpot_framework",
            description="T-Pot honeypot framework indicators",
            pattern_type="response",
            detection_patterns={
                'framework_signatures': ['t-pot', 'tpot', 'honeypot'],
                'template_indicators': ['default apache page', 'it works!'],
                'artificial_errors': ['connection refused by policy']
            },
            confidence_weight=0.9,
            risk_level="high"
        ))
        
        # Generic proxy honeypot detection
        signatures.append(HoneypotSignature(
            name="generic_proxy_honeypot", 
            description="Generic proxy honeypot patterns",
            pattern_type="response",
            detection_patterns={
                'template_indicators': [
                    'proxy test page', 'test proxy server', 'proxy service',
                    'this is a proxy', 'proxy endpoint', 'demo proxy'
                ],
                'artificial_errors': [
                    'proxy unavailable', 'service temporarily unavailable',
                    'proxy maintenance mode'
                ],
                'suspicious_length_range': (50, 200)  # Suspiciously short responses
            },
            confidence_weight=0.7,
            risk_level="medium"
        ))
        
        # HoneyProxy specific detection
        signatures.append(HoneypotSignature(
            name="honeyproxy_framework",
            description="HoneyProxy framework detection",
            pattern_type="header",
            detection_patterns={
                'suspicious_servers': ['honeyproxy', 'honey-proxy', 'hproxy'],
                'honeypot_headers': ['x-honeypot', 'x-trap', 'x-honey'],
                'typically_missing': ['x-forwarded-for', 'via']
            },
            confidence_weight=0.8,
            risk_level="high"
        ))
        
        # Behavioral honeypot detection
        signatures.append(HoneypotSignature(
            name="artificial_behavior",
            description="Artificial behavioral patterns",
            pattern_type="behavioral",
            detection_patterns={
                'artificial_delay_ms': 500  # Artificial 500ms+ delays
            },
            confidence_weight=0.6,
            risk_level="medium"
        ))
        
        # Network-based honeypot detection
        signatures.append(HoneypotSignature(
            name="suspicious_network_setup",
            description="Suspicious network configuration patterns",
            pattern_type="network",
            detection_patterns={
                'suspicious_ports': [8080, 3128, 8888],  # Common honeypot ports
                'hosting_indicators': ['honeypot', 'research', 'security lab']
            },
            confidence_weight=0.5,
            risk_level="low"
        ))
        
        # Kippo/Cowrie SSH honeypot (for SOCKS proxies)
        signatures.append(HoneypotSignature(
            name="ssh_honeypot_backend",
            description="SSH honeypot backend detection",
            pattern_type="header",
            detection_patterns={
                'suspicious_servers': ['kippo', 'cowrie'],
                'header_value_patterns': {
                    'server': 'openssh'  # Default OpenSSH without version
                }
            },
            confidence_weight=0.7,
            risk_level="medium"
        ))
        
        return signatures
    
    async def analyze_honeypot_indicators(self, proxy: ProxyInfo, headers: Dict[str, str],
                                        response_content: str = "", status_code: int = 200,
                                        response_times: List[float] = None,
                                        response_history: List[str] = None) -> HoneypotAnalysisResult:
        """Perform comprehensive honeypot analysis"""
        start_time = time.time()
        result = HoneypotAnalysisResult(proxy_id=proxy.proxy_id)
        
        try:
            # Prepare analysis data
            analysis_data = {
                'headers': headers,
                'response_content': response_content,
                'status_code': status_code,
                'response_times': response_times or [],
                'response_history': response_history or [],
                'proxy_info': proxy,
                'network_data': {}  # Could be extended with network intelligence
            }
            
            # Check against detection signatures
            total_confidence = 0.0
            matched_count = 0
            risk_scores = []
            detected_types = set()
            
            for signature in self.signatures:
                matches, confidence = signature.matches(analysis_data)
                
                if matches and confidence > 0.3:
                    result.matched_signatures.append(signature.name)
                    result.indicators.append(signature.description)
                    total_confidence += confidence
                    matched_count += 1
                    detected_types.add(signature.pattern_type)
                    
                    # Convert risk level to numeric score
                    risk_level_scores = {
                        'low': 25, 'medium': 50, 'high': 75, 'critical': 100
                    }
                    risk_scores.append(risk_level_scores.get(signature.risk_level, 50))
            
            # Calculate overall confidence and detection result
            if matched_count > 0:
                result.confidence = min(1.0, total_confidence / matched_count)
                result.is_honeypot_detected = result.confidence >= 0.6  # 60% confidence threshold
                result.risk_score = max(risk_scores) if risk_scores else 0
                
                # Determine primary honeypot type
                if 'response' in detected_types:
                    result.honeypot_type = 'framework'
                elif 'behavioral' in detected_types:
                    result.honeypot_type = 'behavioral'
                elif 'network' in detected_types:
                    result.honeypot_type = 'network'
                else:
                    result.honeypot_type = 'unknown'
                
                # Set risk level based on score
                if result.risk_score >= 75:
                    result.risk_level = 'critical'
                elif result.risk_score >= 50:
                    result.risk_level = 'high'
                elif result.risk_score >= 25:
                    result.risk_level = 'medium'
                else:
                    result.risk_level = 'low'
            else:
                result.confidence = 0.0
                result.is_honeypot_detected = False
                result.risk_level = 'low'
                result.risk_score = 0.0
            
            self.logger.debug(f"Honeypot analysis completed for {proxy.address}: "
                            f"detected={result.is_honeypot_detected}, "
                            f"confidence={result.confidence:.2f}, "
                            f"type={result.honeypot_type}")
            
        except Exception as e:
            result.error_message = str(e)
            self.logger.error(f"Honeypot analysis failed for {proxy.address}: {e}")
        
        result.analysis_time = time.time() - start_time
        return result
    
    def quick_honeypot_check(self, response_content: str, headers: Dict[str, str]) -> bool:
        """Quick check for obvious honeypot indicators"""
        # Check for obvious framework signatures
        honeypot_indicators = [
            't-pot', 'tpot', 'honeypot', 'honeyproxy', 'honey-proxy',
            'kippo', 'cowrie', 'proxy test page'
        ]
        
        content_lower = response_content.lower()
        for indicator in honeypot_indicators:
            if indicator in content_lower:
                return True
        
        # Check for honeypot headers
        header_keys = {k.lower() for k in headers.keys()}
        honeypot_headers = {'x-honeypot', 'x-trap', 'x-honey'}
        
        return bool(header_keys & honeypot_headers)
    
    def get_signature_info(self) -> List[Dict[str, Any]]:
        """Get information about loaded detection signatures"""
        return [
            {
                'name': sig.name,
                'description': sig.description,
                'pattern_type': sig.pattern_type,
                'confidence_weight': sig.confidence_weight,
                'risk_level': sig.risk_level
            }
            for sig in self.signatures
        ]


# Convenience functions

async def detect_honeypot(proxy: ProxyInfo, headers: Dict[str, str],
                         response_content: str = "", status_code: int = 200,
                         response_times: List[float] = None,
                         config: Optional[SecurityConfig] = None) -> HoneypotAnalysisResult:
    """Convenience function for honeypot detection"""
    detector = HoneypotDetector(config)
    return await detector.analyze_honeypot_indicators(
        proxy, headers, response_content, status_code, response_times
    )


def quick_honeypot_check(response_content: str, headers: Dict[str, str]) -> bool:
    """Quick synchronous check for honeypot indicators"""
    detector = HoneypotDetector()
    return detector.quick_honeypot_check(response_content, headers)