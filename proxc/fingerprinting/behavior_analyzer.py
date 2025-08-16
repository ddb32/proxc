"""
Proxy Behavior Analysis System
=============================

Analyzes proxy connection behavior patterns including response timing,
connection management, SSL behavior, and protocol compliance for
advanced proxy detection and classification.
"""

import asyncio
import logging
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Union, Any, Deque

# Third-party imports with fallbacks
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Import our core types
from . import ProxyType, ConfidenceLevel
from ..proxy_core.models import ProxyInfo

logger = logging.getLogger(__name__)


class BehaviorType(Enum):
    """Types of proxy behavior patterns"""
    TIMING_PATTERN = "timing_pattern"
    CONNECTION_MANAGEMENT = "connection_management"
    SSL_BEHAVIOR = "ssl_behavior"
    PROTOCOL_COMPLIANCE = "protocol_compliance"
    ERROR_HANDLING = "error_handling"


class ConnectionState(Enum):
    """Connection state tracking"""
    NEW = "new"
    ESTABLISHED = "established"
    KEEP_ALIVE = "keep_alive"
    CLOSED = "closed"
    ERROR = "error"


@dataclass
class BehaviorPattern:
    """Definition of a proxy behavior pattern"""
    name: str
    behavior_type: BehaviorType
    proxy_types: Set[ProxyType] = field(default_factory=set)
    
    # Timing characteristics
    response_time_range: Optional[Tuple[float, float]] = None  # (min, max) in ms
    response_time_variance: Optional[float] = None  # Expected variance
    
    # Connection characteristics
    supports_keep_alive: Optional[bool] = None
    connection_reuse_rate: Optional[float] = None
    max_connections_per_host: Optional[int] = None
    
    # SSL/TLS characteristics
    ssl_negotiation_time: Optional[Tuple[float, float]] = None
    supported_ssl_versions: Set[str] = field(default_factory=set)
    ssl_cipher_preferences: List[str] = field(default_factory=list)
    
    # Protocol compliance
    http_version_support: Set[str] = field(default_factory=set)
    header_modification_patterns: List[str] = field(default_factory=list)
    
    # Error patterns
    error_response_patterns: List[str] = field(default_factory=list)
    timeout_behavior: Optional[str] = None
    
    confidence_weight: float = 1.0
    description: str = ""


@dataclass
class ConnectionMetrics:
    """Metrics for a single connection attempt"""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    response_time: float = 0.0  # milliseconds
    connection_time: float = 0.0  # Time to establish connection
    ssl_handshake_time: Optional[float] = None
    
    # Connection details
    state: ConnectionState = ConnectionState.NEW
    keep_alive_supported: bool = False
    http_version: Optional[str] = None
    
    # Response characteristics
    status_code: Optional[int] = None
    response_size: int = 0
    headers_received: Dict[str, str] = field(default_factory=dict)
    
    # Error information
    error_type: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class BehaviorAnalysisResult:
    """Result of proxy behavior analysis"""
    proxy_type: Optional[ProxyType] = None
    confidence: ConfidenceLevel = ConfidenceLevel.VERY_LOW
    confidence_score: float = 0.0
    
    # Behavioral characteristics
    detected_patterns: List[BehaviorPattern] = field(default_factory=list)
    timing_consistency: float = 0.0  # 0-1 scale
    connection_reliability: float = 0.0  # 0-1 scale
    protocol_compliance_score: float = 0.0  # 0-1 scale
    
    # Statistical data
    avg_response_time: float = 0.0
    response_time_variance: float = 0.0
    success_rate: float = 0.0
    
    # Connection behavior
    supports_keep_alive: bool = False
    connection_reuse_efficiency: float = 0.0
    
    # Analysis metadata
    analysis_duration: float = 0.0
    total_connections_analyzed: int = 0
    analysis_timestamp: datetime = field(default_factory=datetime.utcnow)


class ConnectionBehaviorTracker:
    """Tracks connection behavior for a single proxy"""
    
    def __init__(self, max_history: int = 100):
        self.max_history = max_history
        self.connection_history: Deque[ConnectionMetrics] = deque(maxlen=max_history)
        self.timing_history: Deque[float] = deque(maxlen=max_history)
        self.success_history: Deque[bool] = deque(maxlen=max_history)
        
        # Connection state tracking
        self.active_connections: Dict[str, datetime] = {}  # connection_id -> start_time
        self.keep_alive_connections: Set[str] = set()
        
        # Behavior statistics
        self.total_connections = 0
        self.successful_connections = 0
        self.failed_connections = 0
        self.total_bytes_transferred = 0
        
        # Timing statistics
        self.min_response_time = float('inf')
        self.max_response_time = 0.0
        self.avg_response_time = 0.0
        
    def record_connection(self, metrics: ConnectionMetrics):
        """Record connection metrics"""
        self.connection_history.append(metrics)
        self.timing_history.append(metrics.response_time)
        self.success_history.append(metrics.status_code is not None and 200 <= metrics.status_code < 400)
        
        # Update statistics
        self.total_connections += 1
        if metrics.status_code and 200 <= metrics.status_code < 400:
            self.successful_connections += 1
        else:
            self.failed_connections += 1
        
        self.total_bytes_transferred += metrics.response_size
        
        # Update timing stats
        if metrics.response_time > 0:
            self.min_response_time = min(self.min_response_time, metrics.response_time)
            self.max_response_time = max(self.max_response_time, metrics.response_time)
            
            if self.timing_history:
                self.avg_response_time = statistics.mean(self.timing_history)
        
        # Track keep-alive behavior
        if metrics.keep_alive_supported:
            connection_id = f"{metrics.timestamp.timestamp()}"
            self.keep_alive_connections.add(connection_id)
    
    def get_timing_patterns(self) -> Dict[str, float]:
        """Analyze timing patterns"""
        if len(self.timing_history) < 3:
            return {}
        
        times = list(self.timing_history)
        
        return {
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'std_dev': statistics.stdev(times) if len(times) > 1 else 0,
            'variance': statistics.variance(times) if len(times) > 1 else 0,
            'min': min(times),
            'max': max(times),
            'range': max(times) - min(times),
            'consistency': 1.0 - (statistics.stdev(times) / statistics.mean(times)) if statistics.mean(times) > 0 else 0
        }
    
    def get_connection_patterns(self) -> Dict[str, Any]:
        """Analyze connection patterns"""
        if not self.connection_history:
            return {}
        
        recent_connections = list(self.connection_history)[-20:]  # Last 20 connections
        
        # Calculate success rate
        success_rate = self.successful_connections / self.total_connections if self.total_connections > 0 else 0
        
        # Analyze keep-alive usage
        keep_alive_rate = sum(1 for c in recent_connections if c.keep_alive_supported) / len(recent_connections)
        
        # Analyze HTTP version usage
        http_versions = [c.http_version for c in recent_connections if c.http_version]
        version_distribution = {}
        if http_versions:
            from collections import Counter
            version_counter = Counter(http_versions)
            total = sum(version_counter.values())
            version_distribution = {v: count/total for v, count in version_counter.items()}
        
        return {
            'success_rate': success_rate,
            'keep_alive_rate': keep_alive_rate,
            'avg_connection_time': statistics.mean([c.connection_time for c in recent_connections if c.connection_time > 0]) if recent_connections else 0,
            'http_version_distribution': version_distribution,
            'connection_reliability': success_rate * keep_alive_rate,
            'total_connections': self.total_connections,
            'bytes_per_connection': self.total_bytes_transferred / self.total_connections if self.total_connections > 0 else 0
        }
    
    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect behavioral anomalies"""
        anomalies = []
        
        if len(self.timing_history) < 10:
            return anomalies
        
        timing_patterns = self.get_timing_patterns()
        
        # Detect timing anomalies
        if timing_patterns.get('consistency', 0) < 0.3:  # High variance
            anomalies.append({
                'type': 'high_timing_variance',
                'severity': 'medium',
                'description': 'Highly inconsistent response times',
                'value': timing_patterns.get('consistency', 0)
            })
        
        # Detect connection anomalies
        connection_patterns = self.get_connection_patterns()
        
        if connection_patterns.get('success_rate', 0) < 0.5:
            anomalies.append({
                'type': 'low_success_rate',
                'severity': 'high',
                'description': 'Low connection success rate',
                'value': connection_patterns.get('success_rate', 0)
            })
        
        # Detect unusual response times
        mean_time = timing_patterns.get('mean', 0)
        if mean_time > 10000:  # > 10 seconds
            anomalies.append({
                'type': 'slow_response',
                'severity': 'medium',
                'description': 'Unusually slow response times',
                'value': mean_time
            })
        
        return anomalies


class BehaviorAnalyzer:
    """Main behavior analysis engine"""
    
    def __init__(self):
        self.behavior_patterns: List[BehaviorPattern] = []
        self.proxy_trackers: Dict[str, ConnectionBehaviorTracker] = {}
        self._initialize_patterns()
    
    def _initialize_patterns(self):
        """Initialize built-in behavior patterns"""
        
        # Squid proxy patterns
        self.behavior_patterns.append(BehaviorPattern(
            name="squid_timing_pattern",
            behavior_type=BehaviorType.TIMING_PATTERN,
            proxy_types={ProxyType.SQUID},
            response_time_range=(50, 500),  # Typical Squid response times
            response_time_variance=0.3,
            supports_keep_alive=True,
            connection_reuse_rate=0.8,
            confidence_weight=0.7,
            description="Squid proxy timing characteristics"
        ))
        
        # TinyProxy patterns  
        self.behavior_patterns.append(BehaviorPattern(
            name="tinyproxy_minimal_pattern",
            behavior_type=BehaviorType.PROTOCOL_COMPLIANCE,
            proxy_types={ProxyType.TINYPROXY},
            response_time_range=(20, 200),  # Fast, minimal proxy
            supports_keep_alive=False,  # Often disabled in simple configs
            http_version_support={"1.0", "1.1"},
            confidence_weight=0.6,
            description="TinyProxy minimal feature set"
        ))
        
        # Nginx proxy patterns
        self.behavior_patterns.append(BehaviorPattern(
            name="nginx_reverse_proxy_pattern",
            behavior_type=BehaviorType.CONNECTION_MANAGEMENT,
            proxy_types={ProxyType.NGINX},
            response_time_range=(30, 300),
            supports_keep_alive=True,
            connection_reuse_rate=0.9,
            max_connections_per_host=100,
            http_version_support={"1.1", "2.0"},
            confidence_weight=0.8,
            description="Nginx reverse proxy behavior"
        ))
        
        # HAProxy patterns
        self.behavior_patterns.append(BehaviorPattern(
            name="haproxy_load_balancer_pattern",
            behavior_type=BehaviorType.CONNECTION_MANAGEMENT,
            proxy_types={ProxyType.HAPROXY},
            response_time_range=(20, 150),  # Very fast load balancer
            supports_keep_alive=True,
            connection_reuse_rate=0.95,
            header_modification_patterns=["X-Forwarded-For", "X-Forwarded-Proto"],
            confidence_weight=0.8,
            description="HAProxy load balancer behavior"
        ))
        
        # Cloudflare patterns
        self.behavior_patterns.append(BehaviorPattern(
            name="cloudflare_cdn_pattern",
            behavior_type=BehaviorType.SSL_BEHAVIOR,
            proxy_types={ProxyType.CLOUDFLARE},
            response_time_range=(10, 100),  # Very fast CDN
            supports_keep_alive=True,
            connection_reuse_rate=0.95,
            supported_ssl_versions={"TLSv1.2", "TLSv1.3"},
            header_modification_patterns=["CF-Ray", "CF-Cache-Status"],
            confidence_weight=0.9,
            description="Cloudflare CDN behavior"
        ))
        
        logger.info(f"Initialized {len(self.behavior_patterns)} behavior patterns")
    
    def get_tracker(self, proxy_info: ProxyInfo) -> ConnectionBehaviorTracker:
        """Get or create behavior tracker for proxy"""
        key = f"{proxy_info.ip}:{proxy_info.port}"
        
        if key not in self.proxy_trackers:
            self.proxy_trackers[key] = ConnectionBehaviorTracker()
        
        return self.proxy_trackers[key]
    
    def analyze_connection(
        self,
        proxy_info: ProxyInfo,
        test_url: str = "http://httpbin.org/get",
        timeout: int = 10
    ) -> BehaviorAnalysisResult:
        """Analyze proxy behavior through test connections"""
        
        start_time = time.time()
        tracker = self.get_tracker(proxy_info)
        
        if not HAS_REQUESTS:
            return BehaviorAnalysisResult(
                confidence=ConfidenceLevel.VERY_LOW,
                confidence_score=0.0,
                analysis_duration=time.time() - start_time
            )
        
        # Perform test connections
        connection_results = []
        
        try:
            # Test basic connectivity
            metrics = self._test_connection(proxy_info, test_url, timeout)
            if metrics:
                tracker.record_connection(metrics)
                connection_results.append(metrics)
            
            # Test keep-alive behavior
            keep_alive_metrics = self._test_keep_alive(proxy_info, test_url, timeout)
            if keep_alive_metrics:
                tracker.record_connection(keep_alive_metrics)
                connection_results.append(keep_alive_metrics)
            
            # Test multiple requests for timing analysis
            for _ in range(3):
                timing_metrics = self._test_connection(proxy_info, test_url, timeout // 2)
                if timing_metrics:
                    tracker.record_connection(timing_metrics)
                    connection_results.append(timing_metrics)
                time.sleep(0.5)  # Small delay between tests
        
        except Exception as e:
            logger.error(f"Behavior analysis failed for {proxy_info.ip}:{proxy_info.port}: {e}")
        
        # Analyze collected data
        result = self._analyze_behavior_patterns(tracker, connection_results)
        result.analysis_duration = time.time() - start_time
        result.total_connections_analyzed = len(connection_results)
        
        return result
    
    def _test_connection(
        self,
        proxy_info: ProxyInfo,
        test_url: str,
        timeout: int
    ) -> Optional[ConnectionMetrics]:
        """Test basic connection behavior"""
        
        metrics = ConnectionMetrics()
        
        try:
            proxy_url = f"http://{proxy_info.ip}:{proxy_info.port}"
            proxies = {'http': proxy_url, 'https': proxy_url}
            
            start_time = time.time()
            
            response = requests.get(
                test_url,
                proxies=proxies,
                timeout=timeout,
                verify=False
            )
            
            metrics.response_time = (time.time() - start_time) * 1000
            metrics.status_code = response.status_code
            metrics.response_size = len(response.content)
            metrics.headers_received = dict(response.headers)
            metrics.state = ConnectionState.ESTABLISHED
            
            # Check keep-alive support
            connection_header = response.headers.get('Connection', '').lower()
            metrics.keep_alive_supported = 'keep-alive' in connection_header
            
            # Extract HTTP version
            if hasattr(response.raw, 'version'):
                if response.raw.version == 11:
                    metrics.http_version = "1.1"
                elif response.raw.version == 10:
                    metrics.http_version = "1.0"
                elif response.raw.version == 20:
                    metrics.http_version = "2.0"
            
            return metrics
            
        except requests.exceptions.ProxyError as e:
            metrics.state = ConnectionState.ERROR
            metrics.error_type = "proxy_error"
            metrics.error_message = str(e)
            return metrics
        except requests.exceptions.Timeout as e:
            metrics.state = ConnectionState.ERROR
            metrics.error_type = "timeout"
            metrics.error_message = str(e)
            return metrics
        except Exception as e:
            metrics.state = ConnectionState.ERROR
            metrics.error_type = "general_error"
            metrics.error_message = str(e)
            return metrics
    
    def _test_keep_alive(
        self,
        proxy_info: ProxyInfo,
        test_url: str,
        timeout: int
    ) -> Optional[ConnectionMetrics]:
        """Test keep-alive behavior specifically"""
        
        try:
            proxy_url = f"http://{proxy_info.ip}:{proxy_info.port}"
            proxies = {'http': proxy_url, 'https': proxy_url}
            
            # Create session to test keep-alive
            session = requests.Session()
            session.proxies = proxies
            
            start_time = time.time()
            
            # Make first request
            response1 = session.get(test_url, timeout=timeout, verify=False)
            
            # Make second request immediately to test connection reuse
            response2 = session.get(test_url, timeout=timeout, verify=False)
            
            total_time = (time.time() - start_time) * 1000
            
            # If keep-alive worked, second request should be faster
            metrics = ConnectionMetrics()
            metrics.response_time = total_time / 2  # Average of both requests
            metrics.status_code = response2.status_code
            metrics.response_size = len(response2.content)
            metrics.headers_received = dict(response2.headers)
            metrics.keep_alive_supported = response1.headers.get('Connection', '').lower() == 'keep-alive'
            metrics.state = ConnectionState.KEEP_ALIVE if metrics.keep_alive_supported else ConnectionState.ESTABLISHED
            
            session.close()
            return metrics
            
        except Exception as e:
            logger.debug(f"Keep-alive test failed: {e}")
            return None
    
    def _analyze_behavior_patterns(
        self,
        tracker: ConnectionBehaviorTracker,
        recent_connections: List[ConnectionMetrics]
    ) -> BehaviorAnalysisResult:
        """Analyze behavior patterns against known signatures"""
        
        result = BehaviorAnalysisResult()
        
        # Get behavioral statistics
        timing_patterns = tracker.get_timing_patterns()
        connection_patterns = tracker.get_connection_patterns()
        
        # Update result with basic stats
        result.avg_response_time = timing_patterns.get('mean', 0)
        result.response_time_variance = timing_patterns.get('variance', 0)
        result.timing_consistency = timing_patterns.get('consistency', 0)
        result.success_rate = connection_patterns.get('success_rate', 0)
        result.supports_keep_alive = connection_patterns.get('keep_alive_rate', 0) > 0.5
        result.connection_reliability = connection_patterns.get('connection_reliability', 0)
        
        # Match against behavior patterns
        pattern_matches = []
        
        for pattern in self.behavior_patterns:
            match_score = self._match_pattern(pattern, timing_patterns, connection_patterns)
            if match_score > 0.3:  # Minimum threshold
                pattern_matches.append((pattern, match_score))
        
        # Sort by match score
        pattern_matches.sort(key=lambda x: x[1], reverse=True)
        
        if pattern_matches:
            best_pattern, best_score = pattern_matches[0]
            result.proxy_type = list(best_pattern.proxy_types)[0] if best_pattern.proxy_types else None
            result.detected_patterns = [p for p, s in pattern_matches]
            result.confidence_score = best_score
            result.confidence = self._score_to_confidence_level(best_score)
        
        # Calculate protocol compliance score
        result.protocol_compliance_score = self._calculate_protocol_compliance(recent_connections)
        
        return result
    
    def _match_pattern(
        self,
        pattern: BehaviorPattern,
        timing_patterns: Dict[str, float],
        connection_patterns: Dict[str, Any]
    ) -> float:
        """Match behavioral data against a pattern"""
        
        match_score = 0.0
        total_checks = 0
        
        # Check timing characteristics
        if pattern.response_time_range and 'mean' in timing_patterns:
            min_time, max_time = pattern.response_time_range
            mean_time = timing_patterns['mean']
            
            if min_time <= mean_time <= max_time:
                match_score += 1.0
            elif mean_time < min_time * 2 or mean_time > max_time * 0.5:
                match_score += 0.5  # Partial match
            
            total_checks += 1
        
        # Check response time variance
        if pattern.response_time_variance and 'consistency' in timing_patterns:
            expected_consistency = 1.0 - pattern.response_time_variance
            actual_consistency = timing_patterns['consistency']
            
            if abs(expected_consistency - actual_consistency) < 0.3:
                match_score += 1.0
            elif abs(expected_consistency - actual_consistency) < 0.5:
                match_score += 0.5
            
            total_checks += 1
        
        # Check keep-alive support
        if pattern.supports_keep_alive is not None:
            keep_alive_rate = connection_patterns.get('keep_alive_rate', 0)
            expected = pattern.supports_keep_alive
            
            if (expected and keep_alive_rate > 0.7) or (not expected and keep_alive_rate < 0.3):
                match_score += 1.0
            elif (expected and keep_alive_rate > 0.3) or (not expected and keep_alive_rate < 0.7):
                match_score += 0.5
            
            total_checks += 1
        
        # Check connection success rate (reliability indicator)
        success_rate = connection_patterns.get('success_rate', 0)
        if success_rate > 0.8:
            match_score += 0.5  # Bonus for reliable proxies
        
        # Apply confidence weight
        if total_checks > 0:
            normalized_score = (match_score / total_checks) * pattern.confidence_weight
            return min(normalized_score, 1.0)
        else:
            return 0.0
    
    def _calculate_protocol_compliance(self, connections: List[ConnectionMetrics]) -> float:
        """Calculate HTTP protocol compliance score"""
        if not connections:
            return 0.0
        
        compliance_factors = []
        
        # Check HTTP status code compliance
        valid_status_codes = 0
        for conn in connections:
            if conn.status_code and 100 <= conn.status_code <= 599:
                valid_status_codes += 1
        
        compliance_factors.append(valid_status_codes / len(connections))
        
        # Check header compliance
        proper_headers = 0
        for conn in connections:
            if conn.headers_received:
                # Check for proper header formatting (basic check)
                if 'Content-Type' in conn.headers_received or 'Server' in conn.headers_received:
                    proper_headers += 1
        
        if connections:
            compliance_factors.append(proper_headers / len(connections))
        
        # Check HTTP version usage
        http_versions = [c.http_version for c in connections if c.http_version]
        if http_versions:
            # Bonus for using modern HTTP versions
            modern_versions = sum(1 for v in http_versions if v in ['1.1', '2.0'])
            compliance_factors.append(modern_versions / len(http_versions))
        
        return statistics.mean(compliance_factors) if compliance_factors else 0.0
    
    def _score_to_confidence_level(self, score: float) -> ConfidenceLevel:
        """Convert match score to confidence level"""
        if score >= 0.9:
            return ConfidenceLevel.HIGH
        elif score >= 0.7:
            return ConfidenceLevel.MEDIUM
        elif score >= 0.5:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW
    
    def batch_analyze(
        self,
        proxy_list: List[ProxyInfo],
        max_concurrent: int = 5
    ) -> List[Tuple[ProxyInfo, BehaviorAnalysisResult]]:
        """Perform batch behavior analysis"""
        results = []
        
        # Simple sequential processing with limit
        for i, proxy in enumerate(proxy_list[:max_concurrent]):
            try:
                result = self.analyze_connection(proxy)
                results.append((proxy, result))
                
                # Add small delay to be respectful
                if i < len(proxy_list) - 1:
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Behavior analysis failed for {proxy.ip}:{proxy.port}: {e}")
                error_result = BehaviorAnalysisResult(
                    confidence=ConfidenceLevel.VERY_LOW,
                    confidence_score=0.0
                )
                results.append((proxy, error_result))
        
        return results
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of behavior analysis results"""
        if not self.proxy_trackers:
            return {}
        
        total_proxies = len(self.proxy_trackers)
        total_connections = sum(t.total_connections for t in self.proxy_trackers.values())
        successful_connections = sum(t.successful_connections for t in self.proxy_trackers.values())
        
        # Calculate average metrics
        avg_response_time = statistics.mean([
            t.avg_response_time for t in self.proxy_trackers.values()
            if t.avg_response_time > 0
        ]) if self.proxy_trackers else 0
        
        return {
            'total_proxies_analyzed': total_proxies,
            'total_connections_tested': total_connections,
            'overall_success_rate': successful_connections / total_connections if total_connections > 0 else 0,
            'average_response_time': avg_response_time,
            'behavior_patterns_available': len(self.behavior_patterns),
            'proxies_with_keep_alive': sum(
                1 for t in self.proxy_trackers.values()
                if any(c.keep_alive_supported for c in t.connection_history)
            )
        }