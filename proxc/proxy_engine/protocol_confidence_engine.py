"""
Protocol Detection Confidence Engine and Fallback Chains

Advanced confidence scoring system and intelligent fallback chains for ambiguous
protocol detection results. Implements machine learning-like scoring algorithms
and adaptive fallback strategies.

Features:
- Multi-factor confidence scoring
- Bayesian confidence updates
- Fallback chain resolution
- Ambiguity resolution algorithms
- Historical accuracy tracking
"""

import logging
import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict, Counter

from ..proxy_core.models import ProxyInfo, ProxyProtocol
from .protocol_detection import ProtocolDetectionResult, DetectionSummary
from ..proxy_cli.cli_imports import log_structured

logger = logging.getLogger(__name__)


class ConfidenceFactors(Enum):
    """Factors that influence protocol detection confidence"""
    RESPONSE_PATTERN = "response_pattern"
    TIMING_CONSISTENCY = "timing_consistency"
    PROTOCOL_HANDSHAKE = "protocol_handshake"
    PORT_CORRELATION = "port_correlation"
    HISTORICAL_ACCURACY = "historical_accuracy"
    RESPONSE_SIZE = "response_size"
    ERROR_PATTERNS = "error_patterns"
    GEOGRAPHIC_PATTERNS = "geographic_patterns"


@dataclass
class ConfidenceScore:
    """Detailed confidence breakdown"""
    overall_confidence: float
    factor_scores: Dict[ConfidenceFactors, float] = field(default_factory=dict)
    uncertainty_margin: float = 0.0
    reliability_score: float = 1.0
    
    @property
    def adjusted_confidence(self) -> float:
        """Confidence adjusted for uncertainty and reliability"""
        return self.overall_confidence * self.reliability_score * (1 - self.uncertainty_margin)
    
    def to_dict(self) -> Dict[str, float]:
        """Convert to dictionary representation"""
        return {
            'overall_confidence': self.overall_confidence,
            'adjusted_confidence': self.adjusted_confidence,
            'uncertainty_margin': self.uncertainty_margin,
            'reliability_score': self.reliability_score,
            **{factor.value: score for factor, score in self.factor_scores.items()}
        }


@dataclass
class FallbackChainResult:
    """Result of fallback chain resolution"""
    resolved_protocol: ProxyProtocol
    final_confidence: float
    chain_steps: List[str]
    resolution_method: str
    alternative_protocols: List[Tuple[ProxyProtocol, float]] = field(default_factory=list)


class ProtocolHistoryTracker:
    """Tracks historical accuracy of protocol detection methods"""
    
    def __init__(self, max_history_size: int = 1000):
        self.max_history_size = max_history_size
        
        # Track accuracy by method and protocol
        self.method_accuracy: Dict[str, Dict[ProxyProtocol, List[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        
        # Track timing patterns
        self.timing_patterns: Dict[ProxyProtocol, List[float]] = defaultdict(list)
        
        # Track response patterns
        self.response_patterns: Dict[ProxyProtocol, List[str]] = defaultdict(list)
        
        # Geographic patterns (if available)
        self.geo_patterns: Dict[str, Counter] = defaultdict(Counter)  # country -> protocol counts
    
    def record_detection_result(self, method: str, protocol: ProxyProtocol, 
                               confidence: float, response_time: float,
                               response_signature: str = "", 
                               country: str = "unknown"):
        """Record a detection result for learning"""
        # Update method accuracy
        self.method_accuracy[method][protocol].append(confidence)
        
        # Limit history size
        if len(self.method_accuracy[method][protocol]) > self.max_history_size:
            self.method_accuracy[method][protocol] = self.method_accuracy[method][protocol][-self.max_history_size:]
        
        # Update timing patterns
        self.timing_patterns[protocol].append(response_time)
        if len(self.timing_patterns[protocol]) > self.max_history_size:
            self.timing_patterns[protocol] = self.timing_patterns[protocol][-self.max_history_size:]
        
        # Update response patterns
        if response_signature:
            self.response_patterns[protocol].append(response_signature)
            if len(self.response_patterns[protocol]) > self.max_history_size:
                self.response_patterns[protocol] = self.response_patterns[protocol][-self.max_history_size:]
        
        # Update geographic patterns
        self.geo_patterns[country][protocol] += 1
    
    def get_method_reliability(self, method: str, protocol: ProxyProtocol) -> float:
        """Get historical reliability score for method+protocol combination"""
        accuracies = self.method_accuracy.get(method, {}).get(protocol, [])
        
        if not accuracies:
            return 0.5  # Neutral reliability for unknown combinations
        
        # Calculate weighted average with recent results having more weight
        if len(accuracies) == 1:
            return accuracies[0]
        
        weights = [i + 1 for i in range(len(accuracies))]  # Linear weight increase
        weighted_sum = sum(acc * weight for acc, weight in zip(accuracies, weights))
        weight_sum = sum(weights)
        
        return weighted_sum / weight_sum
    
    def get_timing_score(self, protocol: ProxyProtocol, response_time: float) -> float:
        """Score based on timing consistency with historical data"""
        historical_times = self.timing_patterns.get(protocol, [])
        
        if not historical_times:
            return 0.5  # Neutral score for unknown protocols
        
        if len(historical_times) == 1:
            # Use simple distance for single data point
            expected_time = historical_times[0]
            time_diff = abs(response_time - expected_time) / max(expected_time, 0.1)
            return max(0.0, 1.0 - time_diff)
        
        # Calculate statistical consistency
        mean_time = statistics.mean(historical_times)
        std_time = statistics.stdev(historical_times) if len(historical_times) > 1 else mean_time * 0.2
        
        # Z-score based consistency
        if std_time > 0:
            z_score = abs(response_time - mean_time) / std_time
            # Convert z-score to confidence (higher z-score = lower confidence)
            consistency_score = max(0.0, 1.0 - (z_score / 3.0))  # 99.7% within 3 std devs
        else:
            consistency_score = 1.0 if response_time == mean_time else 0.5
        
        return consistency_score
    
    def get_geographic_bias(self, country: str, protocol: ProxyProtocol) -> float:
        """Get geographic bias score for protocol in country"""
        if country == "unknown" or country not in self.geo_patterns:
            return 0.5  # Neutral for unknown locations
        
        country_counts = self.geo_patterns[country]
        total_count = sum(country_counts.values())
        
        if total_count == 0:
            return 0.5
        
        protocol_count = country_counts.get(protocol, 0)
        protocol_ratio = protocol_count / total_count
        
        # Convert ratio to bias score (0.5 = neutral, 1.0 = strongly favored)
        return 0.5 + (protocol_ratio * 0.5)


class AdvancedConfidenceEngine:
    """
    Advanced multi-factor confidence scoring engine
    """
    
    def __init__(self):
        self.history_tracker = ProtocolHistoryTracker()
        
        # Base confidence thresholds
        self.confidence_thresholds = {
            'high': 0.85,
            'medium': 0.65,
            'low': 0.45
        }
        
        # Factor weights (sum should be ~1.0)
        self.factor_weights = {
            ConfidenceFactors.PROTOCOL_HANDSHAKE: 0.35,
            ConfidenceFactors.RESPONSE_PATTERN: 0.25,
            ConfidenceFactors.TIMING_CONSISTENCY: 0.15,
            ConfidenceFactors.HISTORICAL_ACCURACY: 0.10,
            ConfidenceFactors.PORT_CORRELATION: 0.05,
            ConfidenceFactors.RESPONSE_SIZE: 0.05,
            ConfidenceFactors.ERROR_PATTERNS: 0.03,
            ConfidenceFactors.GEOGRAPHIC_PATTERNS: 0.02
        }
    
    def calculate_advanced_confidence(self, result: ProtocolDetectionResult, 
                                    proxy: ProxyInfo,
                                    country: str = "unknown") -> ConfidenceScore:
        """Calculate advanced multi-factor confidence score"""
        factor_scores = {}
        
        # 1. Protocol handshake score (base confidence from detection)
        factor_scores[ConfidenceFactors.PROTOCOL_HANDSHAKE] = result.confidence
        
        # 2. Response pattern analysis
        factor_scores[ConfidenceFactors.RESPONSE_PATTERN] = self._analyze_response_pattern(result)
        
        # 3. Timing consistency
        factor_scores[ConfidenceFactors.TIMING_CONSISTENCY] = self.history_tracker.get_timing_score(
            result.protocol, result.response_time_ms
        )
        
        # 4. Historical accuracy of method
        factor_scores[ConfidenceFactors.HISTORICAL_ACCURACY] = self.history_tracker.get_method_reliability(
            result.method_used, result.protocol
        )
        
        # 5. Port correlation
        factor_scores[ConfidenceFactors.PORT_CORRELATION] = self._get_port_correlation_score(
            proxy.port, result.protocol
        )
        
        # 6. Response size analysis
        factor_scores[ConfidenceFactors.RESPONSE_SIZE] = self._analyze_response_size(result)
        
        # 7. Error pattern analysis
        factor_scores[ConfidenceFactors.ERROR_PATTERNS] = self._analyze_error_patterns(result)
        
        # 8. Geographic patterns
        factor_scores[ConfidenceFactors.GEOGRAPHIC_PATTERNS] = self.history_tracker.get_geographic_bias(
            country, result.protocol
        )
        
        # Calculate weighted overall confidence
        overall_confidence = sum(
            score * self.factor_weights[factor]
            for factor, score in factor_scores.items()
        )
        
        # Calculate uncertainty margin based on factor variance
        factor_values = list(factor_scores.values())
        if len(factor_values) > 1:
            uncertainty_margin = statistics.stdev(factor_values) / len(factor_values)
        else:
            uncertainty_margin = 0.0
        
        # Reliability score based on method and historical data
        reliability_score = self.history_tracker.get_method_reliability(
            result.method_used, result.protocol
        )
        
        confidence_score = ConfidenceScore(
            overall_confidence=overall_confidence,
            factor_scores=factor_scores,
            uncertainty_margin=uncertainty_margin,
            reliability_score=reliability_score
        )
        
        return confidence_score
    
    def _analyze_response_pattern(self, result: ProtocolDetectionResult) -> float:
        """Analyze response patterns for confidence scoring"""
        if not result.raw_response:
            return 0.5  # Neutral for no response
        
        response = result.raw_response
        protocol = result.protocol
        
        # Protocol-specific pattern analysis
        if protocol == ProxyProtocol.SOCKS5:
            if isinstance(response, bytes) and len(response) >= 2:
                if response[0] == 0x05:  # Correct SOCKS5 version
                    return 0.9
                elif response[0] in [0x04, 0x00]:  # Possible confusion
                    return 0.3
            return 0.1
        
        elif protocol == ProxyProtocol.SOCKS4:
            if isinstance(response, bytes) and len(response) >= 2:
                if response[0] == 0x00:  # Correct SOCKS4 response format
                    return 0.9
                elif response[0] == 0x05:  # Possible SOCKS5 confusion
                    return 0.2
            return 0.1
        
        elif protocol == ProxyProtocol.HTTP:
            if isinstance(response, bytes):
                response_str = response.decode('ascii', errors='ignore')
                if response_str.startswith('HTTP/'):
                    return 0.9
                elif 'html' in response_str.lower():
                    return 0.7
                elif any(header in response_str.lower() for header in ['content-', 'server:', 'date:']):
                    return 0.8
            return 0.3
        
        return 0.5  # Default neutral score
    
    def _get_port_correlation_score(self, port: int, protocol: ProxyProtocol) -> float:
        """Score based on port-protocol correlation"""
        port_protocol_map = {
            ProxyProtocol.HTTP: {
                80: 0.7, 8080: 0.8, 3128: 0.9, 8888: 0.7, 8000: 0.6, 8008: 0.6
            },
            ProxyProtocol.HTTPS: {
                443: 0.8, 8443: 0.9, 8080: 0.5, 3128: 0.4
            },
            ProxyProtocol.SOCKS4: {
                1080: 0.8, 1081: 0.9, 9050: 0.7, 9051: 0.8
            },
            ProxyProtocol.SOCKS5: {
                1080: 0.9, 1085: 0.8, 9050: 0.8, 9150: 0.9, 1081: 0.6
            }
        }
        
        protocol_ports = port_protocol_map.get(protocol, {})
        return protocol_ports.get(port, 0.5)  # Neutral for unmapped ports
    
    def _analyze_response_size(self, result: ProtocolDetectionResult) -> float:
        """Analyze response size for consistency"""
        if not result.raw_response:
            return 0.5
        
        response_size = len(result.raw_response)
        protocol = result.protocol
        
        # Expected response sizes for different protocols
        expected_sizes = {
            ProxyProtocol.SOCKS5: (2, 10),    # Usually 2 bytes for greeting response
            ProxyProtocol.SOCKS4: (8, 12),   # Usually 8 bytes for connect response
            ProxyProtocol.HTTP: (10, 1000),  # Variable, but usually substantial
        }
        
        if protocol in expected_sizes:
            min_size, max_size = expected_sizes[protocol]
            if min_size <= response_size <= max_size:
                return 0.8
            elif response_size < min_size:
                return 0.3  # Too small
            else:
                return 0.6  # Larger than expected but possible
        
        return 0.5
    
    def _analyze_error_patterns(self, result: ProtocolDetectionResult) -> float:
        """Analyze error patterns for confidence adjustment"""
        if not result.error_message:
            return 0.8  # No error is good
        
        error = result.error_message.lower()
        
        # Positive error patterns (indicate correct protocol, just access issues)
        positive_patterns = [
            'auth', 'authentication', 'credential', 'password',
            '407', 'proxy authentication',
            'connection established', 'tunnel'
        ]
        
        # Negative error patterns (indicate wrong protocol)
        negative_patterns = [
            'invalid', 'malformed', 'protocol', 'handshake',
            'unexpected', 'format', 'version'
        ]
        
        # Neutral error patterns
        neutral_patterns = [
            'timeout', 'connection', 'network', 'unreachable',
            'refused', 'reset'
        ]
        
        if any(pattern in error for pattern in positive_patterns):
            return 0.7  # Error suggests correct protocol
        elif any(pattern in error for pattern in negative_patterns):
            return 0.2  # Error suggests wrong protocol
        elif any(pattern in error for pattern in neutral_patterns):
            return 0.5  # Network error, protocol unclear
        
        return 0.4  # Unknown error type
    
    def update_history(self, result: ProtocolDetectionResult, proxy: ProxyInfo,
                      actual_working: bool = None, country: str = "unknown"):
        """Update historical tracking with new result"""
        confidence_factor = 1.0 if actual_working else 0.0 if actual_working is False else result.confidence
        
        response_signature = ""
        if result.raw_response:
            response_signature = str(hash(result.raw_response))[:8]
        
        self.history_tracker.record_detection_result(
            method=result.method_used,
            protocol=result.protocol,
            confidence=confidence_factor,
            response_time=result.response_time_ms,
            response_signature=response_signature,
            country=country
        )


class FallbackChainResolver:
    """
    Intelligent fallback chain system for resolving ambiguous protocol detection
    """
    
    def __init__(self, confidence_engine: AdvancedConfidenceEngine):
        self.confidence_engine = confidence_engine
        
        # Define fallback chains for ambiguous cases
        self.fallback_chains = {
            'socks_ambiguous': [
                ('test_socks5_extended', 0.1),
                ('test_socks4_extended', 0.1),
                ('test_http_fallback', 0.2),
                ('port_based_inference', 0.3)
            ],
            'http_ambiguous': [
                ('test_http_methods', 0.1),
                ('test_connect_variations', 0.2),
                ('test_socks_fallback', 0.3),
                ('response_analysis', 0.4)
            ],
            'low_confidence': [
                ('extended_handshake_test', 0.1),
                ('multiple_endpoint_test', 0.2),
                ('timing_analysis', 0.3),
                ('pattern_matching', 0.4)
            ]
        }
    
    async def resolve_ambiguous_detection(self, detection_summary: DetectionSummary, 
                                        proxy: ProxyInfo) -> FallbackChainResult:
        """
        Resolve ambiguous protocol detection using intelligent fallback chains
        
        Args:
            detection_summary: Initial detection results
            proxy: Proxy information
            
        Returns:
            FallbackChainResult with resolved protocol and confidence
        """
        # Determine which fallback chain to use
        chain_type = self._select_fallback_chain(detection_summary)
        chain_steps = []
        
        log_structured('DEBUG', f"Starting fallback resolution for {proxy.address}",
                      chain_type=chain_type)
        
        if not detection_summary.results:
            # No results at all - use comprehensive chain
            return await self._resolve_no_results(proxy, chain_steps)
        
        if detection_summary.best_match.confidence < 0.5:
            # Low confidence - use extended testing
            return await self._resolve_low_confidence(detection_summary, proxy, chain_steps)
        
        if self._has_conflicting_results(detection_summary):
            # Conflicting results - use disambiguation
            return await self._resolve_conflicts(detection_summary, proxy, chain_steps)
        
        # Single result with medium confidence - verify with secondary test
        return await self._verify_single_result(detection_summary, proxy, chain_steps)
    
    def _select_fallback_chain(self, summary: DetectionSummary) -> str:
        """Select appropriate fallback chain based on detection summary"""
        if not summary.results:
            return 'low_confidence'
        
        # Check for SOCKS ambiguity
        socks_results = [r for r in summary.results if r.protocol in [ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5]]
        if len(socks_results) >= 2:
            return 'socks_ambiguous'
        
        # Check for HTTP ambiguity
        http_results = [r for r in summary.results if r.protocol in [ProxyProtocol.HTTP, ProxyProtocol.HTTPS]]
        if len(http_results) >= 1 and summary.best_match.confidence < 0.7:
            return 'http_ambiguous'
        
        return 'low_confidence'
    
    def _has_conflicting_results(self, summary: DetectionSummary) -> bool:
        """Check if detection summary has conflicting results"""
        if len(summary.results) < 2:
            return False
        
        # Check confidence spread
        confidences = [r.confidence for r in summary.results]
        max_confidence = max(confidences)
        second_max = sorted(confidences, reverse=True)[1] if len(confidences) > 1 else 0
        
        # Conflicting if second highest is close to highest
        return (max_confidence - second_max) < 0.2
    
    async def _resolve_no_results(self, proxy: ProxyInfo, chain_steps: List[str]) -> FallbackChainResult:
        """Handle case with no detection results"""
        chain_steps.append("no_results_fallback")
        
        # Try basic connectivity first
        chain_steps.append("basic_connectivity_test")
        
        # Default to HTTP with low confidence
        return FallbackChainResult(
            resolved_protocol=ProxyProtocol.HTTP,
            final_confidence=0.1,
            chain_steps=chain_steps,
            resolution_method="default_fallback"
        )
    
    async def _resolve_low_confidence(self, summary: DetectionSummary, proxy: ProxyInfo, 
                                    chain_steps: List[str]) -> FallbackChainResult:
        """Handle low confidence results with extended testing"""
        chain_steps.append("low_confidence_resolution")
        
        best_result = summary.best_match
        
        # Apply advanced confidence scoring
        advanced_confidence = self.confidence_engine.calculate_advanced_confidence(best_result, proxy)
        
        chain_steps.append("advanced_confidence_scoring")
        
        # If advanced scoring improves confidence significantly, accept it
        if advanced_confidence.adjusted_confidence > 0.6:
            return FallbackChainResult(
                resolved_protocol=best_result.protocol,
                final_confidence=advanced_confidence.adjusted_confidence,
                chain_steps=chain_steps,
                resolution_method="confidence_enhancement"
            )
        
        # Otherwise, fall back to most reliable protocol for port
        chain_steps.append("port_based_fallback")
        fallback_protocol, fallback_confidence = self._get_port_based_fallback(proxy.port)
        
        return FallbackChainResult(
            resolved_protocol=fallback_protocol,
            final_confidence=fallback_confidence,
            chain_steps=chain_steps,
            resolution_method="port_based_fallback"
        )
    
    async def _resolve_conflicts(self, summary: DetectionSummary, proxy: ProxyInfo,
                               chain_steps: List[str]) -> FallbackChainResult:
        """Resolve conflicting detection results"""
        chain_steps.append("conflict_resolution")
        
        # Analyze all results with advanced confidence scoring
        scored_results = []
        
        for result in summary.results:
            advanced_score = self.confidence_engine.calculate_advanced_confidence(result, proxy)
            scored_results.append((result, advanced_score))
        
        chain_steps.append("multi_factor_analysis")
        
        # Sort by adjusted confidence
        scored_results.sort(key=lambda x: x[1].adjusted_confidence, reverse=True)
        
        best_result, best_score = scored_results[0]
        
        # Check if there's a clear winner after advanced scoring
        if len(scored_results) > 1:
            second_best_score = scored_results[1][1].adjusted_confidence
            confidence_gap = best_score.adjusted_confidence - second_best_score
            
            if confidence_gap > 0.2:
                # Clear winner
                return FallbackChainResult(
                    resolved_protocol=best_result.protocol,
                    final_confidence=best_score.adjusted_confidence,
                    chain_steps=chain_steps,
                    resolution_method="advanced_scoring_resolution",
                    alternative_protocols=[(r.protocol, s.adjusted_confidence) 
                                         for r, s in scored_results[1:3]]
                )
        
        # Still ambiguous - use ensemble method
        chain_steps.append("ensemble_resolution")
        return self._ensemble_protocol_resolution(scored_results, chain_steps)
    
    async def _verify_single_result(self, summary: DetectionSummary, proxy: ProxyInfo,
                                  chain_steps: List[str]) -> FallbackChainResult:
        """Verify single result with secondary testing"""
        chain_steps.append("single_result_verification")
        
        result = summary.best_match
        advanced_score = self.confidence_engine.calculate_advanced_confidence(result, proxy)
        
        return FallbackChainResult(
            resolved_protocol=result.protocol,
            final_confidence=advanced_score.adjusted_confidence,
            chain_steps=chain_steps,
            resolution_method="verified_single_result"
        )
    
    def _get_port_based_fallback(self, port: int) -> Tuple[ProxyProtocol, float]:
        """Get most likely protocol for port with confidence"""
        port_mappings = {
            80: (ProxyProtocol.HTTP, 0.6),
            8080: (ProxyProtocol.HTTP, 0.7),
            3128: (ProxyProtocol.HTTP, 0.8),
            8888: (ProxyProtocol.HTTP, 0.6),
            443: (ProxyProtocol.HTTPS, 0.7),
            8443: (ProxyProtocol.HTTPS, 0.8),
            1080: (ProxyProtocol.SOCKS5, 0.7),
            1081: (ProxyProtocol.SOCKS4, 0.7),
            9050: (ProxyProtocol.SOCKS5, 0.8),
            9150: (ProxyProtocol.SOCKS5, 0.8),
        }
        
        return port_mappings.get(port, (ProxyProtocol.HTTP, 0.3))
    
    def _ensemble_protocol_resolution(self, scored_results: List[Tuple], 
                                    chain_steps: List[str]) -> FallbackChainResult:
        """Use ensemble method to resolve protocol"""
        chain_steps.append("ensemble_method")
        
        # Weighted voting based on confidence scores
        protocol_weights = defaultdict(float)
        
        for result, score in scored_results:
            weight = score.adjusted_confidence * score.reliability_score
            protocol_weights[result.protocol] += weight
        
        # Find protocol with highest weight
        best_protocol = max(protocol_weights.items(), key=lambda x: x[1])
        protocol, total_weight = best_protocol
        
        # Normalize confidence
        total_possible_weight = sum(protocol_weights.values())
        final_confidence = total_weight / max(total_possible_weight, 0.1)
        
        # Get alternatives
        alternatives = [(p, w/total_possible_weight) for p, w in protocol_weights.items() 
                       if p != protocol]
        alternatives.sort(key=lambda x: x[1], reverse=True)
        
        return FallbackChainResult(
            resolved_protocol=protocol,
            final_confidence=final_confidence,
            chain_steps=chain_steps,
            resolution_method="ensemble_voting",
            alternative_protocols=alternatives[:2]
        )