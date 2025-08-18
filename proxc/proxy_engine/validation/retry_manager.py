"""
Intelligent Retry Manager - Advanced retry strategies with exponential backoff

This module provides sophisticated retry logic for proxy validation with:
- Exponential backoff with jitter
- Failure reason-based retry decisions
- Adaptive timeout adjustment
- Circuit breaker pattern
- Retry budget management
"""

import asyncio
import random
import time
import logging
from typing import Optional, Callable, Any, List, Dict
from dataclasses import dataclass, field
from enum import Enum

from .validation_config import FailureReason


class RetryStrategy(Enum):
    """Available retry strategies"""
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    FIXED_INTERVAL = "fixed_interval"
    ADAPTIVE = "adaptive"


class JitterType(Enum):
    """Types of jitter for backoff"""
    NONE = "none"
    FULL = "full"
    EQUAL = "equal"
    DECORRELATED = "decorrelated"


@dataclass
class RetryAttempt:
    """Record of a retry attempt"""
    attempt_number: int
    timestamp: float
    failure_reason: FailureReason
    delay_used: float
    total_elapsed: float


@dataclass
class RetryConfig:
    """Configuration for retry behavior"""
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    backoff_multiplier: float = 2.0
    jitter_type: JitterType = JitterType.EQUAL
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    
    # Failure reason specific settings
    retryable_reasons: List[FailureReason] = field(default_factory=lambda: [
        FailureReason.TIMEOUT_CONNECT,
        FailureReason.TIMEOUT_READ,
        FailureReason.CONNECTION_RESET,
        FailureReason.NETWORK_UNREACHABLE,
        FailureReason.DNS_RESOLUTION
    ])
    
    # Circuit breaker settings
    enable_circuit_breaker: bool = True
    circuit_breaker_threshold: int = 5  # failures before opening circuit
    circuit_breaker_timeout: float = 30.0  # seconds to wait before half-open
    
    # Adaptive settings
    adaptive_success_threshold: float = 0.8  # success rate to reduce delays
    adaptive_failure_threshold: float = 0.3  # failure rate to increase delays
    adaptive_window_size: int = 10  # number of attempts to consider
    
    # Budget management
    enable_retry_budget: bool = True
    retry_budget_per_minute: int = 100  # max retries per minute
    retry_budget_window: float = 60.0  # budget window in seconds


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, no retries allowed
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerState:
    """Circuit breaker state tracking"""
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    last_failure_time: float = 0.0
    last_success_time: float = 0.0
    next_attempt_time: float = 0.0


class RetryBudget:
    """Manages retry budget to prevent retry storms"""
    
    def __init__(self, config: RetryConfig):
        self.config = config
        self.attempts: List[float] = []
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def can_retry(self) -> bool:
        """Check if retry is allowed within budget"""
        if not self.config.enable_retry_budget:
            return True
        
        current_time = time.time()
        window_start = current_time - self.config.retry_budget_window
        
        # Remove old attempts outside the window
        self.attempts = [t for t in self.attempts if t >= window_start]
        
        # Check if we're within budget
        within_budget = len(self.attempts) < self.config.retry_budget_per_minute
        
        if not within_budget:
            self.logger.warning(f"Retry budget exceeded: {len(self.attempts)} attempts in last {self.config.retry_budget_window}s")
        
        return within_budget
    
    def record_attempt(self):
        """Record a retry attempt"""
        self.attempts.append(time.time())


class IntelligentRetryManager:
    """Advanced retry manager with exponential backoff and circuit breaker"""
    
    def __init__(self, config: RetryConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Circuit breaker state per proxy endpoint
        self.circuit_states: Dict[str, CircuitBreakerState] = {}
        
        # Retry budget management
        self.retry_budget = RetryBudget(config)
        
        # Adaptive retry tracking
        self.recent_attempts: List[RetryAttempt] = []
        
        # Performance metrics
        self.stats = {
            'total_retries': 0,
            'successful_retries': 0,
            'circuit_breaker_trips': 0,
            'budget_rejections': 0,
            'adaptive_adjustments': 0
        }
        
        self.logger.info("IntelligentRetryManager initialized with exponential backoff")
    
    def should_retry(self, failure_reason: FailureReason, proxy_key: str, attempt_number: int) -> bool:
        """Determine if a failure should trigger a retry"""
        
        # Check retry budget first
        if not self.retry_budget.can_retry():
            self.stats['budget_rejections'] += 1
            return False
        
        # Check max retries
        if attempt_number >= self.config.max_retries:
            return False
        
        # Check if failure reason is retryable
        if failure_reason not in self.config.retryable_reasons:
            self.logger.debug(f"Failure reason {failure_reason.value} is not retryable")
            return False
        
        # Check circuit breaker
        if self.config.enable_circuit_breaker:
            circuit_state = self._get_circuit_state(proxy_key)
            if circuit_state.state == CircuitState.OPEN:
                if time.time() < circuit_state.next_attempt_time:
                    self.logger.debug(f"Circuit breaker OPEN for {proxy_key}")
                    return False
                else:
                    # Move to half-open state
                    circuit_state.state = CircuitState.HALF_OPEN
                    self.logger.info(f"Circuit breaker HALF-OPEN for {proxy_key}")
        
        return True
    
    def calculate_delay(self, attempt_number: int, failure_reason: FailureReason) -> float:
        """Calculate delay before next retry with intelligent backoff"""
        
        if self.config.strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            delay = self.config.base_delay * (self.config.backoff_multiplier ** attempt_number)
        elif self.config.strategy == RetryStrategy.LINEAR_BACKOFF:
            delay = self.config.base_delay * (attempt_number + 1)
        elif self.config.strategy == RetryStrategy.FIXED_INTERVAL:
            delay = self.config.base_delay
        elif self.config.strategy == RetryStrategy.ADAPTIVE:
            delay = self._calculate_adaptive_delay(attempt_number, failure_reason)
        else:
            delay = self.config.base_delay
        
        # Cap at max delay
        delay = min(delay, self.config.max_delay)
        
        # Apply jitter
        delay = self._apply_jitter(delay)
        
        # Adaptive adjustment based on recent success/failure rates
        if self.config.strategy == RetryStrategy.ADAPTIVE:
            delay = self._apply_adaptive_adjustment(delay)
        
        return delay
    
    def _calculate_adaptive_delay(self, attempt_number: int, failure_reason: FailureReason) -> float:
        """Calculate adaptive delay based on failure patterns"""
        base_delay = self.config.base_delay
        
        # Adjust based on failure reason severity
        reason_multipliers = {
            FailureReason.TIMEOUT_CONNECT: 1.5,
            FailureReason.TIMEOUT_READ: 1.2,
            FailureReason.CONNECTION_RESET: 2.0,
            FailureReason.NETWORK_UNREACHABLE: 3.0,
            FailureReason.DNS_RESOLUTION: 1.8,
            FailureReason.SSL_ERROR: 1.0,
            FailureReason.AUTH_FAILED: 0.5  # Fast retry for auth issues
        }
        
        multiplier = reason_multipliers.get(failure_reason, 1.0)
        adaptive_delay = base_delay * multiplier * (self.config.backoff_multiplier ** attempt_number)
        
        return adaptive_delay
    
    def _apply_jitter(self, delay: float) -> float:
        """Apply jitter to prevent thundering herd"""
        if self.config.jitter_type == JitterType.NONE:
            return delay
        elif self.config.jitter_type == JitterType.FULL:
            return random.uniform(0, delay)
        elif self.config.jitter_type == JitterType.EQUAL:
            jitter = delay * 0.1 * random.random()
            return delay + random.uniform(-jitter, jitter)
        elif self.config.jitter_type == JitterType.DECORRELATED:
            # Decorrelated jitter: next delay based on previous delay
            if hasattr(self, '_last_delay'):
                return random.uniform(self.config.base_delay, delay * 3)
            else:
                return delay
        
        return delay
    
    def _apply_adaptive_adjustment(self, delay: float) -> float:
        """Apply adaptive adjustment based on recent success rates"""
        if len(self.recent_attempts) < self.config.adaptive_window_size:
            return delay
        
        # Calculate recent success rate
        recent_window = self.recent_attempts[-self.config.adaptive_window_size:]
        failures = sum(1 for attempt in recent_window if attempt.failure_reason != FailureReason.UNKNOWN_ERROR)
        failure_rate = failures / len(recent_window)
        
        if failure_rate < self.config.adaptive_failure_threshold:
            # Low failure rate, reduce delays
            adjustment = 0.8
            self.stats['adaptive_adjustments'] += 1
        elif failure_rate > (1.0 - self.config.adaptive_success_threshold):
            # High failure rate, increase delays
            adjustment = 1.5
            self.stats['adaptive_adjustments'] += 1
        else:
            adjustment = 1.0
        
        return delay * adjustment
    
    def _get_circuit_state(self, proxy_key: str) -> CircuitBreakerState:
        """Get or create circuit breaker state for proxy"""
        if proxy_key not in self.circuit_states:
            self.circuit_states[proxy_key] = CircuitBreakerState()
        return self.circuit_states[proxy_key]
    
    def record_failure(self, proxy_key: str, failure_reason: FailureReason, attempt_number: int, delay_used: float):
        """Record a retry failure"""
        current_time = time.time()
        
        # Record attempt
        attempt = RetryAttempt(
            attempt_number=attempt_number,
            timestamp=current_time,
            failure_reason=failure_reason,
            delay_used=delay_used,
            total_elapsed=0.0  # Will be calculated when complete
        )
        self.recent_attempts.append(attempt)
        self.retry_budget.record_attempt()
        
        # Keep only recent attempts for adaptive behavior
        max_history = self.config.adaptive_window_size * 2
        if len(self.recent_attempts) > max_history:
            self.recent_attempts = self.recent_attempts[-max_history:]
        
        # Update circuit breaker
        if self.config.enable_circuit_breaker:
            circuit_state = self._get_circuit_state(proxy_key)
            circuit_state.failure_count += 1
            circuit_state.last_failure_time = current_time
            
            # Check if circuit should open
            if (circuit_state.state == CircuitState.CLOSED and 
                circuit_state.failure_count >= self.config.circuit_breaker_threshold):
                circuit_state.state = CircuitState.OPEN
                circuit_state.next_attempt_time = current_time + self.config.circuit_breaker_timeout
                self.stats['circuit_breaker_trips'] += 1
                self.logger.warning(f"Circuit breaker OPENED for {proxy_key} after {circuit_state.failure_count} failures")
        
        self.stats['total_retries'] += 1
    
    def record_success(self, proxy_key: str):
        """Record a successful operation"""
        if self.config.enable_circuit_breaker:
            circuit_state = self._get_circuit_state(proxy_key)
            circuit_state.failure_count = 0
            circuit_state.last_success_time = time.time()
            
            if circuit_state.state != CircuitState.CLOSED:
                circuit_state.state = CircuitState.CLOSED
                self.logger.info(f"Circuit breaker CLOSED for {proxy_key}")
        
        self.stats['successful_retries'] += 1
    
    async def retry_with_backoff(self, operation: Callable, proxy_key: str, *args, **kwargs) -> Any:
        """Execute operation with intelligent retry and backoff"""
        last_exception = None
        start_time = time.time()
        
        for attempt in range(self.config.max_retries + 1):
            try:
                result = await operation(*args, **kwargs) if asyncio.iscoroutinefunction(operation) else operation(*args, **kwargs)
                
                if attempt > 0:
                    self.record_success(proxy_key)
                    total_time = time.time() - start_time
                    self.logger.info(f"Retry successful for {proxy_key} after {attempt} attempts in {total_time:.2f}s")
                
                return result
                
            except Exception as e:
                last_exception = e
                
                # Determine failure reason
                failure_reason = self._classify_exception(e)
                
                # Check if we should retry
                if not self.should_retry(failure_reason, proxy_key, attempt):
                    break
                
                # Calculate delay
                delay = self.calculate_delay(attempt, failure_reason)
                
                # Record failure
                self.record_failure(proxy_key, failure_reason, attempt, delay)
                
                self.logger.debug(f"Retry {attempt + 1}/{self.config.max_retries} for {proxy_key} after {delay:.2f}s delay (reason: {failure_reason.value})")
                
                # Wait before retry
                if asyncio.iscoroutinefunction(operation):
                    await asyncio.sleep(delay)
                else:
                    time.sleep(delay)
        
        # All retries exhausted
        if last_exception:
            raise last_exception
    
    def _classify_exception(self, exception: Exception) -> FailureReason:
        """Classify exception to determine failure reason"""
        exception_str = str(exception).lower()
        exception_type = type(exception).__name__.lower()
        
        if 'timeout' in exception_str or 'timeout' in exception_type:
            if 'connect' in exception_str:
                return FailureReason.TIMEOUT_CONNECT
            elif 'read' in exception_str:
                return FailureReason.TIMEOUT_READ
            else:
                return FailureReason.TIMEOUT_TOTAL
        elif 'connection' in exception_str:
            if 'refused' in exception_str:
                return FailureReason.CONNECTION_REFUSED
            elif 'reset' in exception_str:
                return FailureReason.CONNECTION_RESET
            else:
                return FailureReason.CONNECTION_RESET
        elif 'network' in exception_str or 'unreachable' in exception_str:
            return FailureReason.NETWORK_UNREACHABLE
        elif 'dns' in exception_str or 'name' in exception_str:
            return FailureReason.DNS_RESOLUTION
        elif 'ssl' in exception_str or 'certificate' in exception_str:
            return FailureReason.SSL_ERROR
        elif 'auth' in exception_str or 'unauthorized' in exception_str:
            return FailureReason.AUTH_FAILED
        else:
            return FailureReason.UNKNOWN_ERROR
    
    def get_stats(self) -> Dict[str, Any]:
        """Get retry manager statistics"""
        return {
            **self.stats,
            'circuit_breaker_states': {
                key: {
                    'state': state.state.value,
                    'failure_count': state.failure_count,
                    'last_failure_time': state.last_failure_time,
                    'last_success_time': state.last_success_time
                }
                for key, state in self.circuit_states.items()
            },
            'recent_attempts_count': len(self.recent_attempts),
            'retry_budget_remaining': self.config.retry_budget_per_minute - len(self.retry_budget.attempts)
        }
    
    def reset_circuit_breaker(self, proxy_key: str):
        """Manually reset circuit breaker for a proxy"""
        if proxy_key in self.circuit_states:
            self.circuit_states[proxy_key] = CircuitBreakerState()
            self.logger.info(f"Circuit breaker manually reset for {proxy_key}")
    
    def reset_all_circuit_breakers(self):
        """Reset all circuit breakers"""
        self.circuit_states.clear()
        self.logger.info("All circuit breakers reset")


def create_retry_manager(config: Optional[RetryConfig] = None) -> IntelligentRetryManager:
    """Create retry manager with default or custom configuration"""
    if config is None:
        config = RetryConfig()
    return IntelligentRetryManager(config)


def create_retry_config_from_validation_config(validation_config) -> RetryConfig:
    """Create retry config from existing validation config"""
    return RetryConfig(
        max_retries=getattr(validation_config, 'max_retries', 3),
        base_delay=getattr(validation_config, 'retry_delay', 1.0),
        backoff_multiplier=getattr(validation_config, 'backoff_factor', 1.5),
        retryable_reasons=getattr(validation_config, 'retry_on_failure_reasons', [
            FailureReason.TIMEOUT_CONNECT,
            FailureReason.CONNECTION_RESET,
            FailureReason.NETWORK_UNREACHABLE
        ])
    )