"""Proxy Chain Detector - Multi-hop proxy detection and analysis"""

import asyncio
import logging
import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

from .security_config import (
    ChainDetectionConfig, ChainDetectionMethod, ChainRiskLevel, SecurityConfig
)
from .security_utils import SecurityUtils, parse_proxy_headers, calculate_chain_risk
from ...proxy_core.models import ProxyInfo, ProxyProtocol


@dataclass
class ChainSignature:
    """Signature pattern for proxy chain detection"""
    name: str
    description: str
    pattern_type: str  # 'header', 'timing', 'response'
    detection_patterns: Dict[str, Any]
    confidence_weight: float = 1.0
    
    def matches(self, data: Dict[str, Any]) -> Tuple[bool, float]:
        """Check if data matches this signature pattern"""
        if self.pattern_type == 'header':
            return self._match_header_pattern(data)
        elif self.pattern_type == 'timing':
            return self._match_timing_pattern(data)
        elif self.pattern_type == 'response':
            return self._match_response_pattern(data)
        else:
            return False, 0.0
    
    def _match_header_pattern(self, data: Dict[str, Any]) -> Tuple[bool, float]:
        """Match header-based patterns"""
        headers = data.get('headers', {})
        proxy_headers = parse_proxy_headers(headers)
        
        confidence = 0.0
        matches = 0
        total_checks = 0
        
        # Check for required headers
        required_headers = self.detection_patterns.get('required_headers', [])
        for header in required_headers:
            total_checks += 1
            if header in proxy_headers:
                matches += 1
                confidence += 0.3
        
        # Check chain depth
        expected_depth = self.detection_patterns.get('min_chain_depth', 0)
        actual_depth = SecurityUtils.calculate_chain_depth(proxy_headers)
        if actual_depth >= expected_depth:
            matches += 1
            confidence += 0.4
        total_checks += 1
        
        # Check for specific patterns
        header_patterns = self.detection_patterns.get('header_patterns', {})
        for header_name, pattern in header_patterns.items():
            total_checks += 1
            header_value = proxy_headers.get(header_name, '')
            if isinstance(header_value, str) and pattern in header_value:
                matches += 1
                confidence += 0.2
        
        match_ratio = matches / max(1, total_checks)
        final_confidence = min(1.0, confidence * self.confidence_weight * match_ratio)
        
        return matches > 0, final_confidence
    
    def _match_timing_pattern(self, data: Dict[str, Any]) -> Tuple[bool, float]:
        """Match timing-based patterns"""
        timing_data = data.get('timing', {})
        response_times = timing_data.get('response_times', [])
        
        if len(response_times) < 2:
            return False, 0.0
        
        # Check for timing anomalies that suggest chain overhead
        min_expected_overhead = self.detection_patterns.get('min_overhead_ms', 100)
        avg_response_time = statistics.mean(response_times)
        
        confidence = 0.0
        
        # Higher response times suggest more hops
        if avg_response_time > min_expected_overhead:
            confidence += 0.5
        
        # Check for timing variance (multiple hops can cause more variance)
        if len(response_times) > 2:
            variance = statistics.variance(response_times)
            if variance > self.detection_patterns.get('min_variance', 100):
                confidence += 0.3
        
        return confidence > 0.4, confidence * self.confidence_weight
    
    def _match_response_pattern(self, data: Dict[str, Any]) -> Tuple[bool, float]:
        """Match response content patterns"""
        response_content = data.get('response_content', '')
        headers = data.get('headers', {})
        
        confidence = 0.0
        
        # Check for proxy-specific content patterns
        content_patterns = self.detection_patterns.get('content_patterns', [])
        for pattern in content_patterns:
            if pattern.lower() in response_content.lower():
                confidence += 0.3
        
        # Check for proxy software signatures in headers
        server_header = headers.get('server', '')
        proxy_signatures = self.detection_patterns.get('proxy_signatures', [])
        for signature in proxy_signatures:
            if signature.lower() in server_header.lower():
                confidence += 0.4
        
        return confidence > 0.3, confidence * self.confidence_weight


@dataclass
class ProxyChainInfo:
    """Information about detected proxy chain"""
    chain_depth: int = 0
    detected_proxies: List[str] = field(default_factory=list)
    via_headers: List[Dict[str, str]] = field(default_factory=list)
    forwarded_ips: List[str] = field(default_factory=list)
    proxy_software: List[str] = field(default_factory=list)
    mixed_protocols: bool = False
    inconsistencies: List[str] = field(default_factory=list)
    geographic_anomaly_score: float = 0.0
    
    @property
    def is_chain_detected(self) -> bool:
        return self.chain_depth > 1
    
    @property
    def has_anomalies(self) -> bool:
        return (len(self.inconsistencies) > 0 or 
                self.mixed_protocols or 
                self.geographic_anomaly_score > 0.3)


@dataclass
class ChainAnalysisResult:
    """Result of chain analysis"""
    proxy_id: str
    is_chain_detected: bool = False
    confidence: float = 0.0
    chain_info: ProxyChainInfo = field(default_factory=ProxyChainInfo)
    risk_level: ChainRiskLevel = ChainRiskLevel.LOW
    risk_score: float = 0.0
    matched_signatures: List[str] = field(default_factory=list)
    analysis_time: float = 0.0
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'proxy_id': self.proxy_id,
            'is_chain_detected': self.is_chain_detected,
            'confidence': self.confidence,
            'chain_info': {
                'chain_depth': self.chain_info.chain_depth,
                'detected_proxies': self.chain_info.detected_proxies,
                'via_headers': self.chain_info.via_headers,
                'forwarded_ips': self.chain_info.forwarded_ips,
                'proxy_software': self.chain_info.proxy_software,
                'mixed_protocols': self.chain_info.mixed_protocols,
                'inconsistencies': self.chain_info.inconsistencies,
                'geographic_anomaly_score': self.chain_info.geographic_anomaly_score,
                'is_chain_detected': self.chain_info.is_chain_detected,
                'has_anomalies': self.chain_info.has_anomalies,
            },
            'risk_level': self.risk_level.value,
            'risk_score': self.risk_score,
            'matched_signatures': self.matched_signatures,
            'analysis_time': self.analysis_time,
            'error_message': self.error_message
        }


class ChainDetector:
    """Advanced proxy chain detection and analysis"""
    
    def __init__(self, config: Optional[ChainDetectionConfig] = None):
        self.config = config or ChainDetectionConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize detection signatures
        self.signatures = self._load_detection_signatures()
        
        self.logger.info(f"ChainDetector initialized with {len(self.signatures)} signatures")
    
    def _load_detection_signatures(self) -> List[ChainSignature]:
        """Load predefined detection signatures"""
        signatures = []
        
        # Via header-based detection
        signatures.append(ChainSignature(
            name="via_header_chain",
            description="Multiple Via headers indicating proxy chain",
            pattern_type="header",
            detection_patterns={
                'required_headers': ['via'],
                'min_chain_depth': 2
            },
            confidence_weight=0.9
        ))
        
        # X-Forwarded-For chain detection
        signatures.append(ChainSignature(
            name="xff_chain",
            description="Multiple IPs in X-Forwarded-For header",
            pattern_type="header", 
            detection_patterns={
                'required_headers': ['x_forwarded_for'],
                'min_chain_depth': 2
            },
            confidence_weight=0.8
        ))
        
        # Common proxy software signatures
        signatures.append(ChainSignature(
            name="squid_proxy_chain",
            description="Squid proxy in chain",
            pattern_type="response",
            detection_patterns={
                'proxy_signatures': ['squid'],
                'content_patterns': ['x-squid-error', 'generated by squid']
            },
            confidence_weight=0.7
        ))
        
        # Timing-based chain detection
        signatures.append(ChainSignature(
            name="high_latency_chain",
            description="High latency suggesting multiple hops",
            pattern_type="timing",
            detection_patterns={
                'min_overhead_ms': 200,
                'min_variance': 50
            },
            confidence_weight=0.6
        ))
        
        # Mixed protocol detection
        signatures.append(ChainSignature(
            name="mixed_protocol_chain",
            description="Mixed HTTP/SOCKS protocols in chain",
            pattern_type="header",
            detection_patterns={
                'header_patterns': {
                    'via': 'HTTP/1.1',  # Look for HTTP protocol indicators
                }
            },
            confidence_weight=0.8
        ))
        
        return signatures
    
    async def analyze_proxy_chain(self, proxy: ProxyInfo, headers: Dict[str, str],
                                response_content: str = "", response_times: List[float] = None) -> ChainAnalysisResult:
        """Perform comprehensive proxy chain analysis"""
        start_time = time.time()
        result = ChainAnalysisResult(proxy_id=proxy.proxy_id)
        
        try:
            # Prepare analysis data
            analysis_data = {
                'headers': headers,
                'response_content': response_content,
                'timing': {
                    'response_times': response_times or []
                }
            }
            
            # Parse proxy headers
            proxy_headers = parse_proxy_headers(headers)
            
            # Build chain information
            chain_info = ProxyChainInfo(
                chain_depth=SecurityUtils.calculate_chain_depth(proxy_headers),
                via_headers=proxy_headers.get('via', []),
                forwarded_ips=proxy_headers.get('x_forwarded_for', []),
                proxy_software=SecurityUtils.extract_proxy_software(proxy_headers),
                mixed_protocols=SecurityUtils.detect_mixed_protocols(proxy_headers),
                inconsistencies=SecurityUtils.detect_header_inconsistencies(proxy_headers),
                geographic_anomaly_score=SecurityUtils.calculate_geographic_anomaly_score(
                    proxy_headers.get('x_forwarded_for', [])
                )
            )
            
            # Collect all proxy identifiers
            chain_info.detected_proxies = []
            for via_entry in chain_info.via_headers:
                proxy_name = via_entry.get('proxy_name', '')
                if proxy_name:
                    chain_info.detected_proxies.append(proxy_name)
            
            # Add forwarded IPs that aren't already in detected_proxies
            for ip in chain_info.forwarded_ips:
                if ip not in chain_info.detected_proxies:
                    chain_info.detected_proxies.append(ip)
            
            result.chain_info = chain_info
            
            # Check against detection signatures
            total_confidence = 0.0
            matched_count = 0
            
            for signature in self.signatures:
                if ChainDetectionMethod.ALL_METHODS in self.config.enabled_methods or \
                   self._method_for_signature(signature) in self.config.enabled_methods:
                    
                    matches, confidence = signature.matches(analysis_data)
                    if matches and confidence > 0.3:
                        result.matched_signatures.append(signature.name)
                        total_confidence += confidence
                        matched_count += 1
            
            # Calculate overall confidence
            if matched_count > 0:
                result.confidence = min(1.0, total_confidence / matched_count)
                result.is_chain_detected = result.confidence >= self.config.min_confidence_threshold
            else:
                result.confidence = 0.0
                result.is_chain_detected = False
            
            # Calculate risk assessment
            if self.config.enable_risk_scoring:
                risk_level_str, risk_score = calculate_chain_risk(
                    chain_info.chain_depth,
                    chain_info.inconsistencies,
                    chain_info.mixed_protocols,
                    chain_info.geographic_anomaly_score
                )
                result.risk_level = ChainRiskLevel(risk_level_str)
                result.risk_score = risk_score
            
            self.logger.debug(f"Chain analysis completed for {proxy.address}: "
                            f"chain_detected={result.is_chain_detected}, "
                            f"confidence={result.confidence:.2f}, "
                            f"depth={chain_info.chain_depth}")
            
        except Exception as e:
            result.error_message = str(e)
            self.logger.error(f"Chain analysis failed for {proxy.address}: {e}")
        
        result.analysis_time = time.time() - start_time
        return result
    
    def _method_for_signature(self, signature: ChainSignature) -> ChainDetectionMethod:
        """Map signature type to detection method"""
        if signature.pattern_type == 'header':
            return ChainDetectionMethod.HEADER_ANALYSIS
        elif signature.pattern_type == 'timing':
            return ChainDetectionMethod.TIMING_ANALYSIS
        elif signature.pattern_type == 'response':
            return ChainDetectionMethod.RESPONSE_PATTERN
        else:
            return ChainDetectionMethod.ALL_METHODS
    
    async def quick_chain_check(self, headers: Dict[str, str]) -> bool:
        """Quick check to see if headers suggest a proxy chain"""
        proxy_headers = parse_proxy_headers(headers)
        chain_depth = SecurityUtils.calculate_chain_depth(proxy_headers)
        return chain_depth > 1
    
    def update_config(self, config: ChainDetectionConfig):
        """Update detection configuration"""
        self.config = config
        self.logger.info("Chain detection configuration updated")
    
    def get_signature_info(self) -> List[Dict[str, Any]]:
        """Get information about loaded detection signatures"""
        return [
            {
                'name': sig.name,
                'description': sig.description,
                'pattern_type': sig.pattern_type,
                'confidence_weight': sig.confidence_weight
            }
            for sig in self.signatures
        ]


# Convenience functions

async def detect_proxy_chain(proxy: ProxyInfo, headers: Dict[str, str], 
                           response_content: str = "", response_times: List[float] = None,
                           config: Optional[ChainDetectionConfig] = None) -> ChainAnalysisResult:
    """Convenience function for proxy chain detection"""
    detector = ChainDetector(config)
    return await detector.analyze_proxy_chain(proxy, headers, response_content, response_times)


def quick_chain_check(headers: Dict[str, str]) -> bool:
    """Quick synchronous check for proxy chain indicators"""
    proxy_headers = parse_proxy_headers(headers)
    return SecurityUtils.calculate_chain_depth(proxy_headers) > 1