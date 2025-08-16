"""
Intelligent Validation Engine - Phase 3.3.5, 3.3.7, 3.3.8

Advanced concurrent validation with intelligent rate limiting, confidence scoring,
and smart retry mechanisms with exponential backoff.

Features:
- Adaptive rate limiting based on target server responses
- Intelligent retry mechanisms with exponential backoff
- Circuit breaker patterns for failing services
- Validation result confidence scoring with uncertainty quantification  
- Concurrent validation with resource management
- Performance-based validation scheduling
- Adaptive timeout and concurrency adjustment
- Comprehensive error categorization and handling
"""

import asyncio
import logging
import math
import random
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum, IntEnum
from typing import Dict, List, Optional, Tuple, Union, Set, Callable, Any
import threading
import weakref

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from ..proxy_core.models import ProxyInfo, ProxyProtocol, ValidationStatus, ThreatLevel
from .advanced_validation_engine import HealthScore, ResponseTimeMetrics, ValidationHistory
from .sla_monitoring import AdaptiveTimeoutManager, TimeoutConfiguration
from ..proxy_cli.cli_imports import log_structured, print_info, print_warning

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"        # Normal operation
    OPEN = "open"           # Failing, reject requests
    HALF_OPEN = "half_open" # Testing recovery


class RetryStrategy(Enum):
    """Retry strategy types"""
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    FIXED_INTERVAL = "fixed_interval"
    FIBONACCI_BACKOFF = "fibonacci_backoff"
    ADAPTIVE = "adaptive"


class ValidationErrorCategory(Enum):
    """Validation error categories for retry decisions"""
    NETWORK_TIMEOUT = "network_timeout"
    CONNECTION_REFUSED = "connection_refused"
    DNS_RESOLUTION = "dns_resolution"
    SSL_ERROR = "ssl_error"
    HTTP_ERROR = "http_error"
    PROXY_AUTH_FAILED = "proxy_auth_failed"
    PROXY_PROTOCOL_ERROR = "proxy_protocol_error"
    RATE_LIMITED = "rate_limited"
    SERVER_ERROR = "server_error"
    UNKNOWN = "unknown"


class ConfidenceFactors(Enum):
    """Factors that influence validation confidence"""
    SAMPLE_SIZE = "sample_size"
    CONSISTENCY = "consistency"
    RESPONSE_TIME_STABILITY = "response_time_stability"
    SUCCESS_RATE = "success_rate"
    ERROR_PATTERN = "error_pattern"
    VALIDATION_METHOD = "validation_method"
    TIME_SPAN = "time_span"
    EXTERNAL_CONFIRMATION = "external_confirmation"


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    failure_threshold: int = 5
    recovery_timeout: timedelta = field(default_factory=lambda: timedelta(minutes=1))
    success_threshold: int = 3
    half_open_max_calls: int = 3


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    max_requests_per_second: float = 10.0
    burst_capacity: int = 20
    adaptive_adjustment: bool = True
    min_interval_ms: float = 50.0
    max_interval_ms: float = 5000.0


@dataclass
class RetryConfig:
    """Retry mechanism configuration"""
    max_attempts: int = 3
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    base_delay_ms: float = 100.0
    max_delay_ms: float = 30000.0
    backoff_multiplier: float = 2.0
    jitter: bool = True
    retryable_errors: Set[ValidationErrorCategory] = field(default_factory=lambda: {
        ValidationErrorCategory.NETWORK_TIMEOUT,
        ValidationErrorCategory.CONNECTION_REFUSED,
        ValidationErrorCategory.RATE_LIMITED,
        ValidationErrorCategory.SERVER_ERROR
    })


@dataclass
class ValidationResult:
    """Enhanced validation result with confidence scoring"""
    proxy_address: str
    is_valid: bool
    status: ValidationStatus
    response_time_ms: float
    confidence_score: float = 0.0
    uncertainty: float = 0.0
    error_category: Optional[ValidationErrorCategory] = None
    error_message: Optional[str] = None
    attempt_count: int = 1
    validation_method: str = "unknown"
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            **asdict(self),
            'status': self.status.value if self.status else None,
            'error_category': self.error_category.value if self.error_category else None,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ValidationConfidence:
    """Detailed confidence assessment for validation results"""
    overall_confidence: float = 0.0
    uncertainty: float = 0.0
    factor_scores: Dict[ConfidenceFactors, float] = field(default_factory=dict)
    sample_size: int = 0
    consistency_score: float = 0.0
    stability_score: float = 0.0
    method_reliability: float = 0.0
    external_confirmation: bool = False
    confidence_explanation: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            **asdict(self),
            'factor_scores': {k.value: v for k, v in self.factor_scores.items()}
        }


class CircuitBreaker:
    """Circuit breaker implementation for validation targets"""
    
    def __init__(self, config: CircuitBreakerConfig = None):
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.half_open_calls = 0
        self.lock = threading.Lock()
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        
        with self.lock:
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._move_to_half_open()
                else:
                    raise Exception("Circuit breaker is OPEN - rejecting call")
            
            elif self.state == CircuitState.HALF_OPEN:
                if self.half_open_calls >= self.config.half_open_max_calls:
                    raise Exception("Circuit breaker HALF_OPEN - max calls exceeded")
                self.half_open_calls += 1
        
        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result
        
        except Exception as e:
            self._on_failure()
            raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit should attempt to reset"""
        if self.last_failure_time is None:
            return True
        
        return datetime.now() - self.last_failure_time >= self.config.recovery_timeout
    
    def _move_to_half_open(self):
        """Move circuit to half-open state"""
        self.state = CircuitState.HALF_OPEN
        self.half_open_calls = 0
        log_structured('INFO', f"Circuit breaker moving to HALF_OPEN state")
    
    def _on_success(self):
        """Handle successful operation"""
        with self.lock:
            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= self.config.success_threshold:
                    self._reset()
            else:
                self.failure_count = 0
    
    def _on_failure(self):
        """Handle failed operation"""
        with self.lock:
            self.failure_count += 1
            self.last_failure_time = datetime.now()
            
            if self.state == CircuitState.HALF_OPEN:
                self._trip()
            elif self.failure_count >= self.config.failure_threshold:
                self._trip()
    
    def _reset(self):
        """Reset circuit to closed state"""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.half_open_calls = 0
        log_structured('INFO', f"Circuit breaker RESET to CLOSED state")
    
    def _trip(self):
        """Trip circuit to open state"""
        self.state = CircuitState.OPEN
        self.success_count = 0
        self.half_open_calls = 0
        log_structured('WARNING', f"Circuit breaker TRIPPED to OPEN state")
    
    def get_state(self) -> Dict[str, Any]:
        """Get current circuit breaker state"""
        return {
            'state': self.state.value,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'last_failure_time': self.last_failure_time.isoformat() if self.last_failure_time else None,
            'half_open_calls': self.half_open_calls
        }


class AdaptiveRateLimiter:
    """Intelligent rate limiter with adaptive adjustment"""
    
    def __init__(self, config: RateLimitConfig = None):
        self.config = config or RateLimitConfig()
        self.tokens = self.config.burst_capacity
        self.last_refill = time.time()
        self.request_times = deque(maxlen=100)
        
        # Adaptive parameters
        self.current_rate = self.config.max_requests_per_second
        self.success_rate_window = deque(maxlen=50)
        self.response_time_window = deque(maxlen=50)
        
        self.lock = threading.Lock()
    
    async def acquire(self, tokens: int = 1) -> bool:
        """Acquire rate limit tokens"""
        
        with self.lock:
            self._refill_tokens()
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                self.request_times.append(time.time())
                return True
            
            return False
    
    def _refill_tokens(self):
        """Refill tokens based on rate limit"""
        current_time = time.time()
        time_elapsed = current_time - self.last_refill
        
        tokens_to_add = time_elapsed * self.current_rate
        self.tokens = min(self.config.burst_capacity, self.tokens + tokens_to_add)
        self.last_refill = current_time
    
    def record_response(self, success: bool, response_time_ms: float):
        """Record response for adaptive adjustment"""
        
        if not self.config.adaptive_adjustment:
            return
        
        self.success_rate_window.append(success)
        self.response_time_window.append(response_time_ms)
        
        # Adjust rate based on recent performance
        if len(self.success_rate_window) >= 10:
            self._adjust_rate()
    
    def _adjust_rate(self):
        """Adjust rate based on success rate and response times"""
        
        success_rate = sum(self.success_rate_window) / len(self.success_rate_window)
        avg_response_time = statistics.mean(self.response_time_window)
        
        # Increase rate if high success and low response time
        if success_rate > 0.95 and avg_response_time < 1000:
            self.current_rate = min(
                self.config.max_requests_per_second * 2,
                self.current_rate * 1.1
            )
        
        # Decrease rate if low success or high response time
        elif success_rate < 0.8 or avg_response_time > 3000:
            self.current_rate = max(
                self.config.max_requests_per_second * 0.1,
                self.current_rate * 0.8
            )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        
        recent_success_rate = 0.0
        if self.success_rate_window:
            recent_success_rate = sum(self.success_rate_window) / len(self.success_rate_window)
        
        recent_avg_response_time = 0.0
        if self.response_time_window:
            recent_avg_response_time = statistics.mean(self.response_time_window)
        
        return {
            'current_rate': self.current_rate,
            'available_tokens': self.tokens,
            'recent_success_rate': recent_success_rate,
            'recent_avg_response_time': recent_avg_response_time,
            'total_requests': len(self.request_times)
        }


class SmartRetryManager:
    """Intelligent retry manager with multiple strategies"""
    
    def __init__(self, config: RetryConfig = None):
        self.config = config or RetryConfig()
        self.fibonacci_cache = [1, 1]  # For Fibonacci backoff
    
    async def execute_with_retry(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with intelligent retry logic"""
        
        last_exception = None
        
        for attempt in range(1, self.config.max_attempts + 1):
            try:
                result = await func(*args, **kwargs)
                return result
            
            except Exception as e:
                last_exception = e
                error_category = self._categorize_error(e)
                
                # Check if error is retryable
                if error_category not in self.config.retryable_errors:
                    log_structured('DEBUG', f"Non-retryable error: {error_category.value}")
                    break
                
                # Don't retry on last attempt
                if attempt >= self.config.max_attempts:
                    break
                
                # Calculate delay
                delay = self._calculate_delay(attempt, error_category)
                
                log_structured('DEBUG', f"Retry attempt {attempt}/{self.config.max_attempts} "
                             f"after {delay:.1f}ms delay",
                             error_category=error_category.value)
                
                await asyncio.sleep(delay / 1000.0)
        
        # All retry attempts failed
        if last_exception:
            raise last_exception
    
    def _categorize_error(self, error: Exception) -> ValidationErrorCategory:
        """Categorize error for retry decision"""
        
        error_str = str(error).lower()
        
        if 'timeout' in error_str or 'timed out' in error_str:
            return ValidationErrorCategory.NETWORK_TIMEOUT
        elif 'connection refused' in error_str or 'connection reset' in error_str:
            return ValidationErrorCategory.CONNECTION_REFUSED
        elif 'dns' in error_str or 'name resolution' in error_str:
            return ValidationErrorCategory.DNS_RESOLUTION
        elif 'ssl' in error_str or 'certificate' in error_str:
            return ValidationErrorCategory.SSL_ERROR
        elif 'rate limit' in error_str or '429' in error_str:
            return ValidationErrorCategory.RATE_LIMITED
        elif '5' in error_str[:3]:  # 5xx errors
            return ValidationErrorCategory.SERVER_ERROR
        elif 'http' in error_str or '4' in error_str[:3]:
            return ValidationErrorCategory.HTTP_ERROR
        elif 'auth' in error_str or 'unauthorized' in error_str:
            return ValidationErrorCategory.PROXY_AUTH_FAILED
        elif 'proxy' in error_str or 'socks' in error_str:
            return ValidationErrorCategory.PROXY_PROTOCOL_ERROR
        else:
            return ValidationErrorCategory.UNKNOWN
    
    def _calculate_delay(self, attempt: int, error_category: ValidationErrorCategory) -> float:
        """Calculate retry delay based on strategy and error type"""
        
        if self.config.strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            delay = self.config.base_delay_ms * (self.config.backoff_multiplier ** (attempt - 1))
        
        elif self.config.strategy == RetryStrategy.LINEAR_BACKOFF:
            delay = self.config.base_delay_ms * attempt
        
        elif self.config.strategy == RetryStrategy.FIXED_INTERVAL:
            delay = self.config.base_delay_ms
        
        elif self.config.strategy == RetryStrategy.FIBONACCI_BACKOFF:
            while len(self.fibonacci_cache) < attempt:
                next_val = self.fibonacci_cache[-1] + self.fibonacci_cache[-2]
                self.fibonacci_cache.append(next_val)
            
            delay = self.config.base_delay_ms * self.fibonacci_cache[attempt - 1]
        
        elif self.config.strategy == RetryStrategy.ADAPTIVE:
            # Adaptive delay based on error type
            base_multiplier = {
                ValidationErrorCategory.NETWORK_TIMEOUT: 2.0,
                ValidationErrorCategory.CONNECTION_REFUSED: 1.5,
                ValidationErrorCategory.RATE_LIMITED: 3.0,
                ValidationErrorCategory.SERVER_ERROR: 2.5,
                ValidationErrorCategory.DNS_RESOLUTION: 1.0
            }.get(error_category, 1.0)
            
            delay = self.config.base_delay_ms * base_multiplier * (attempt ** 1.5)
        
        else:
            delay = self.config.base_delay_ms
        
        # Apply jitter if enabled
        if self.config.jitter:
            jitter_factor = 0.1  # ±10% jitter
            jitter = delay * jitter_factor * (2 * random.random() - 1)
            delay += jitter
        
        # Clamp to min/max bounds
        delay = max(self.config.base_delay_ms, min(self.config.max_delay_ms, delay))
        
        return delay


class ValidationConfidenceScorer:
    """
    Advanced confidence scoring for validation results with uncertainty quantification
    """
    
    def __init__(self):
        self.factor_weights = {
            ConfidenceFactors.SAMPLE_SIZE: 0.25,
            ConfidenceFactors.CONSISTENCY: 0.20,
            ConfidenceFactors.RESPONSE_TIME_STABILITY: 0.15,
            ConfidenceFactors.SUCCESS_RATE: 0.15,
            ConfidenceFactors.ERROR_PATTERN: 0.10,
            ConfidenceFactors.VALIDATION_METHOD: 0.08,
            ConfidenceFactors.TIME_SPAN: 0.05,
            ConfidenceFactors.EXTERNAL_CONFIRMATION: 0.02
        }
        
        # Method reliability scores
        self.method_reliability = {
            'http_request': 0.9,
            'socks_handshake': 0.95,
            'tcp_connect': 0.8,
            'protocol_detection': 0.85,
            'anonymous_test': 0.7,
            'speed_test': 0.6
        }
    
    def calculate_confidence(self, validation_history: List[ValidationResult],
                           response_metrics: ResponseTimeMetrics = None,
                           external_confirmations: int = 0) -> ValidationConfidence:
        """Calculate comprehensive confidence score"""
        
        if not validation_history:
            return ValidationConfidence()
        
        factor_scores = {}
        confidence_explanations = []
        
        # Sample size factor
        sample_size = len(validation_history)
        factor_scores[ConfidenceFactors.SAMPLE_SIZE] = self._score_sample_size(sample_size)
        
        if sample_size < 5:
            confidence_explanations.append(f"Low sample size ({sample_size} validations)")
        elif sample_size >= 20:
            confidence_explanations.append(f"High sample size ({sample_size} validations)")
        
        # Consistency factor
        consistency_score = self._score_consistency(validation_history)
        factor_scores[ConfidenceFactors.CONSISTENCY] = consistency_score
        
        if consistency_score < 70:
            confidence_explanations.append("Inconsistent validation results")
        elif consistency_score >= 90:
            confidence_explanations.append("Highly consistent results")
        
        # Response time stability
        if response_metrics and response_metrics.measurements:
            stability_score = self._score_response_time_stability(response_metrics)
            factor_scores[ConfidenceFactors.RESPONSE_TIME_STABILITY] = stability_score
            
            if stability_score < 70:
                confidence_explanations.append("Unstable response times")
        
        # Success rate factor
        success_rate = sum(1 for r in validation_history if r.is_valid) / len(validation_history)
        factor_scores[ConfidenceFactors.SUCCESS_RATE] = success_rate * 100
        
        # Error pattern analysis
        error_pattern_score = self._score_error_patterns(validation_history)
        factor_scores[ConfidenceFactors.ERROR_PATTERN] = error_pattern_score
        
        # Validation method reliability
        method_score = self._score_validation_methods(validation_history)
        factor_scores[ConfidenceFactors.VALIDATION_METHOD] = method_score
        
        # Time span coverage
        time_span_score = self._score_time_span(validation_history)
        factor_scores[ConfidenceFactors.TIME_SPAN] = time_span_score
        
        # External confirmation
        external_score = min(100, external_confirmations * 25)
        factor_scores[ConfidenceFactors.EXTERNAL_CONFIRMATION] = external_score
        
        if external_confirmations > 0:
            confidence_explanations.append(f"{external_confirmations} external confirmations")
        
        # Calculate weighted overall confidence
        overall_confidence = self._calculate_weighted_confidence(factor_scores)
        
        # Calculate uncertainty based on variance and gaps
        uncertainty = self._calculate_uncertainty(factor_scores, validation_history)
        
        return ValidationConfidence(
            overall_confidence=overall_confidence,
            uncertainty=uncertainty,
            factor_scores=factor_scores,
            sample_size=sample_size,
            consistency_score=consistency_score,
            stability_score=factor_scores.get(ConfidenceFactors.RESPONSE_TIME_STABILITY, 0),
            method_reliability=method_score,
            external_confirmation=external_confirmations > 0,
            confidence_explanation=confidence_explanations
        )
    
    def _score_sample_size(self, sample_size: int) -> float:
        """Score based on validation sample size"""
        if sample_size >= 50:
            return 100.0
        elif sample_size >= 20:
            return 90.0
        elif sample_size >= 10:
            return 75.0
        elif sample_size >= 5:
            return 60.0
        elif sample_size >= 3:
            return 40.0
        elif sample_size >= 1:
            return 20.0
        else:
            return 0.0
    
    def _score_consistency(self, validation_history: List[ValidationResult]) -> float:
        """Score result consistency"""
        if len(validation_history) < 2:
            return 50.0
        
        # Group by similar time periods
        grouped_results = self._group_by_time_window(validation_history, timedelta(hours=1))
        
        consistent_groups = 0
        for group in grouped_results:
            if len(group) >= 2:
                success_rate = sum(1 for r in group if r.is_valid) / len(group)
                if success_rate == 1.0 or success_rate == 0.0:
                    consistent_groups += 1
        
        return (consistent_groups / len(grouped_results)) * 100 if grouped_results else 50.0
    
    def _score_response_time_stability(self, metrics: ResponseTimeMetrics) -> float:
        """Score response time stability"""
        if not metrics.measurements or len(metrics.measurements) < 3:
            return 50.0
        
        # Calculate coefficient of variation
        cv = metrics.std_dev / metrics.mean if metrics.mean > 0 else float('inf')
        
        # Score based on stability (lower CV = higher score)
        if cv <= 0.1:
            return 100.0
        elif cv <= 0.3:
            return 85.0
        elif cv <= 0.5:
            return 70.0
        elif cv <= 1.0:
            return 50.0
        else:
            return max(0, 50 - (cv - 1.0) * 25)
    
    def _score_error_patterns(self, validation_history: List[ValidationResult]) -> float:
        """Score based on error pattern analysis"""
        errors = [r for r in validation_history if not r.is_valid and r.error_category]
        
        if not errors:
            return 100.0  # No errors = good pattern
        
        # Analyze error diversity
        error_types = set(r.error_category for r in errors)
        
        # Single error type suggests consistent issue
        if len(error_types) == 1:
            return 80.0
        
        # Multiple error types suggest instability
        diversity_penalty = min(40, len(error_types) * 10)
        return max(0, 100 - diversity_penalty)
    
    def _score_validation_methods(self, validation_history: List[ValidationResult]) -> float:
        """Score based on validation method reliability"""
        if not validation_history:
            return 0.0
        
        method_scores = []
        for result in validation_history:
            method_reliability = self.method_reliability.get(result.validation_method, 0.5)
            method_scores.append(method_reliability * 100)
        
        return statistics.mean(method_scores)
    
    def _score_time_span(self, validation_history: List[ValidationResult]) -> float:
        """Score based on time span coverage"""
        if len(validation_history) < 2:
            return 20.0
        
        timestamps = [r.timestamp for r in validation_history]
        time_span = max(timestamps) - min(timestamps)
        
        # Score based on coverage duration
        if time_span >= timedelta(days=1):
            return 100.0
        elif time_span >= timedelta(hours=6):
            return 80.0
        elif time_span >= timedelta(hours=1):
            return 60.0
        elif time_span >= timedelta(minutes=15):
            return 40.0
        else:
            return 20.0
    
    def _group_by_time_window(self, results: List[ValidationResult], 
                            window: timedelta) -> List[List[ValidationResult]]:
        """Group results by time windows"""
        if not results:
            return []
        
        sorted_results = sorted(results, key=lambda r: r.timestamp)
        groups = []
        current_group = [sorted_results[0]]
        
        for result in sorted_results[1:]:
            if result.timestamp - current_group[0].timestamp <= window:
                current_group.append(result)
            else:
                groups.append(current_group)
                current_group = [result]
        
        if current_group:
            groups.append(current_group)
        
        return groups
    
    def _calculate_weighted_confidence(self, factor_scores: Dict[ConfidenceFactors, float]) -> float:
        """Calculate weighted overall confidence"""
        total_weight = 0.0
        weighted_sum = 0.0
        
        for factor, score in factor_scores.items():
            weight = self.factor_weights.get(factor, 0.0)
            weighted_sum += score * weight
            total_weight += weight
        
        return weighted_sum / total_weight if total_weight > 0 else 0.0
    
    def _calculate_uncertainty(self, factor_scores: Dict[ConfidenceFactors, float],
                             validation_history: List[ValidationResult]) -> float:
        """Calculate uncertainty based on score variance and gaps"""
        
        # Score variance uncertainty
        scores = list(factor_scores.values())
        if len(scores) > 1:
            score_variance = statistics.variance(scores)
            variance_uncertainty = min(50, score_variance / 100)
        else:
            variance_uncertainty = 25
        
        # Sample size uncertainty
        sample_size = len(validation_history)
        if sample_size >= 20:
            sample_uncertainty = 5
        elif sample_size >= 10:
            sample_uncertainty = 15
        elif sample_size >= 5:
            sample_uncertainty = 25
        else:
            sample_uncertainty = 40
        
        # Missing factor uncertainty
        missing_factors = len(self.factor_weights) - len(factor_scores)
        missing_uncertainty = missing_factors * 5
        
        total_uncertainty = min(100, variance_uncertainty + sample_uncertainty + missing_uncertainty)
        return total_uncertainty


# Export key classes
__all__ = [
    'CircuitState', 'RetryStrategy', 'ValidationErrorCategory', 'ConfidenceFactors',
    'CircuitBreakerConfig', 'RateLimitConfig', 'RetryConfig', 
    'ValidationResult', 'ValidationConfidence',
    'CircuitBreaker', 'AdaptiveRateLimiter', 'SmartRetryManager', 'ValidationConfidenceScorer'
]