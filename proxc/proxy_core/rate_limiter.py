"""Intelligent Rate Limiter for ProxyHunter

This module provides sophisticated rate limiting capabilities including:
- Per-source adaptive rate limiting
- Global request throttling
- Intelligent jitter and timing randomization
- Request pattern obfuscation
- Anti-detection mechanisms
"""

import asyncio
import logging
import random
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from contextlib import asynccontextmanager, contextmanager
import statistics

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    # Basic rate limiting
    requests_per_second: float = 0.5  # 1 request per 2 seconds
    burst_size: int = 3  # Allow burst of N requests
    
    # Jitter and randomization
    jitter_min: float = 0.1  # Minimum jitter in seconds
    jitter_max: float = 0.5  # Maximum jitter in seconds
    timing_randomization: bool = True
    
    # Adaptive behavior
    adaptive_delays: bool = True
    success_rate_threshold: float = 0.8  # Threshold to reduce delays
    failure_rate_threshold: float = 0.3   # Threshold to increase delays
    adaptation_factor: float = 1.2        # Multiplier for delay adjustments
    
    # Global limits
    global_requests_per_minute: int = 30
    global_concurrent_requests: int = 10
    
    # Anti-detection
    human_behavior_simulation: bool = True
    pause_between_batches: bool = True
    batch_size: int = 5
    batch_pause_min: float = 2.0
    batch_pause_max: float = 8.0


@dataclass
class RequestMetrics:
    """Metrics for tracking request patterns"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    last_request_time: Optional[datetime] = None
    average_response_time: float = 0.0
    recent_response_times: deque = field(default_factory=lambda: deque(maxlen=10))
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate"""
        if self.total_requests == 0:
            return 0.0
        return self.successful_requests / self.total_requests
    
    @property
    def failure_rate(self) -> float:
        """Calculate failure rate"""
        return 1.0 - self.success_rate
    
    def record_request(self, success: bool, response_time: float = 0.0):
        """Record a request outcome"""
        self.total_requests += 1
        self.last_request_time = datetime.utcnow()
        
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
        
        if response_time > 0:
            self.recent_response_times.append(response_time)
            if self.recent_response_times:
                self.average_response_time = statistics.mean(self.recent_response_times)


class TokenBucket:
    """Token bucket implementation for rate limiting"""
    
    def __init__(self, rate: float, capacity: int = None):
        self.rate = rate  # tokens per second
        self.capacity = capacity or max(1, int(rate * 2))  # bucket capacity
        self.tokens = self.capacity
        self.last_update = time.time()
        self._lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens from the bucket"""
        with self._lock:
            now = time.time()
            elapsed = now - self.last_update
            
            # Add tokens based on elapsed time
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    def time_until_available(self, tokens: int = 1) -> float:
        """Calculate time until tokens are available"""
        with self._lock:
            if self.tokens >= tokens:
                return 0.0
            
            needed_tokens = tokens - self.tokens
            return needed_tokens / self.rate


class AdaptiveRateController:
    """Adaptive rate controller that adjusts based on success/failure rates"""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.base_delay = 1.0 / config.requests_per_second
        self.current_delay = self.base_delay
        self.metrics = RequestMetrics()
        self.adjustment_history = deque(maxlen=20)
        self._lock = threading.Lock()
        
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def get_delay(self) -> float:
        """Get current delay with adaptive adjustment"""
        with self._lock:
            if self.config.adaptive_delays and self.metrics.total_requests > 5:
                self._adapt_delay()
            
            delay = self.current_delay
            
            # Add jitter if enabled
            if self.config.timing_randomization:
                jitter = random.uniform(self.config.jitter_min, self.config.jitter_max)
                delay += jitter
            
            return delay
    
    def _adapt_delay(self):
        """Adapt delay based on recent performance"""
        success_rate = self.metrics.success_rate
        
        if success_rate >= self.config.success_rate_threshold:
            # High success rate - can be more aggressive
            new_delay = self.current_delay / self.config.adaptation_factor
            new_delay = max(new_delay, self.base_delay * 0.5)  # Don't go below 50% of base
            
            if new_delay != self.current_delay:
                self.current_delay = new_delay
                self.adjustment_history.append(('decrease', datetime.utcnow(), success_rate))
                self.logger.debug(f"Decreased delay to {self.current_delay:.2f}s (success_rate: {success_rate:.2f})")
        
        elif success_rate <= self.config.failure_rate_threshold:
            # High failure rate - need to back off
            new_delay = self.current_delay * self.config.adaptation_factor
            new_delay = min(new_delay, self.base_delay * 5.0)  # Don't go above 5x base
            
            if new_delay != self.current_delay:
                self.current_delay = new_delay
                self.adjustment_history.append(('increase', datetime.utcnow(), success_rate))
                self.logger.debug(f"Increased delay to {self.current_delay:.2f}s (success_rate: {success_rate:.2f})")
    
    def record_request(self, success: bool, response_time: float = 0.0):
        """Record request outcome for adaptive behavior"""
        with self._lock:
            self.metrics.record_request(success, response_time)


class SourceRateLimiter:
    """Rate limiter for individual proxy sources"""
    
    def __init__(self, source_name: str, config: RateLimitConfig):
        self.source_name = source_name
        self.config = config
        
        # Rate limiting components
        self.token_bucket = TokenBucket(config.requests_per_second, config.burst_size)
        self.adaptive_controller = AdaptiveRateController(config)
        
        # Request tracking
        self.request_times = deque(maxlen=100)
        self.batch_request_count = 0
        
        # Threading
        self._lock = threading.Lock()
        
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def acquire(self) -> float:
        """Acquire permission to make a request, returns delay time"""
        with self._lock:
            now = time.time()
            
            # Check token bucket
            if not self.token_bucket.consume():
                # Wait for tokens to be available
                wait_time = self.token_bucket.time_until_available()
                return wait_time
            
            # Get adaptive delay
            delay = self.adaptive_controller.get_delay()
            
            # Check for batch pause
            if self.config.pause_between_batches:
                self.batch_request_count += 1
                if self.batch_request_count >= self.config.batch_size:
                    batch_pause = random.uniform(
                        self.config.batch_pause_min, 
                        self.config.batch_pause_max
                    )
                    delay += batch_pause
                    self.batch_request_count = 0
                    self.logger.debug(f"Adding batch pause: {batch_pause:.2f}s")
            
            # Human behavior simulation
            if self.config.human_behavior_simulation:
                delay += self._calculate_human_delay()
            
            self.request_times.append(now)
            return delay
    
    def _calculate_human_delay(self) -> float:
        """Calculate additional delay to simulate human behavior"""
        # Occasionally add longer pauses to simulate human reading/thinking
        if random.random() < 0.1:  # 10% chance
            return random.uniform(5.0, 15.0)
        
        # Small random variations
        return random.uniform(0.1, 1.0)
    
    def record_request_outcome(self, success: bool, response_time: float = 0.0):
        """Record the outcome of a request"""
        self.adaptive_controller.record_request(success, response_time)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics for this source"""
        with self._lock:
            recent_requests = len([
                t for t in self.request_times 
                if time.time() - t < 60  # Last minute
            ])
            
            return {
                'source_name': self.source_name,
                'current_delay': self.adaptive_controller.current_delay,
                'base_delay': self.adaptive_controller.base_delay,
                'success_rate': self.adaptive_controller.metrics.success_rate,
                'total_requests': self.adaptive_controller.metrics.total_requests,
                'recent_requests_per_minute': recent_requests,
                'tokens_available': self.token_bucket.tokens,
                'batch_count': self.batch_request_count
            }


class GlobalRateLimiter:
    """Global rate limiter that coordinates across all sources"""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        
        # Global controls
        self.global_token_bucket = TokenBucket(
            config.global_requests_per_minute / 60.0,  # Convert to per-second
            config.global_requests_per_minute
        )
        
        self.concurrent_requests = 0
        self.max_concurrent = config.global_concurrent_requests
        
        # Source-specific limiters
        self.source_limiters: Dict[str, SourceRateLimiter] = {}
        
        # Global tracking
        self.global_request_times = deque(maxlen=1000)
        self.global_metrics = RequestMetrics()
        
        # Threading
        self._lock = threading.Lock()
        self._semaphore = threading.Semaphore(self.max_concurrent)
        
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def get_source_limiter(self, source_name: str, 
                          source_config: Optional[RateLimitConfig] = None) -> SourceRateLimiter:
        """Get or create a rate limiter for a specific source"""
        with self._lock:
            if source_name not in self.source_limiters:
                config = source_config or self.config
                self.source_limiters[source_name] = SourceRateLimiter(source_name, config)
            
            return self.source_limiters[source_name]
    
    @contextmanager
    def acquire_global_slot(self):
        """Acquire a global concurrent request slot"""
        if not self._semaphore.acquire(blocking=False):
            # Wait for global token bucket
            wait_time = self.global_token_bucket.time_until_available()
            if wait_time > 0:
                time.sleep(wait_time)
            
            self._semaphore.acquire()
        
        try:
            with self._lock:
                self.concurrent_requests += 1
                self.global_request_times.append(time.time())
            
            yield
            
        finally:
            with self._lock:
                self.concurrent_requests -= 1
            
            self._semaphore.release()
    
    @asynccontextmanager
    async def acquire_global_slot_async(self):
        """Async version of acquire_global_slot"""
        # Convert semaphore to async
        await asyncio.to_thread(self._semaphore.acquire)
        
        try:
            with self._lock:
                self.concurrent_requests += 1
                self.global_request_times.append(time.time())
            
            yield
            
        finally:
            with self._lock:
                self.concurrent_requests -= 1
            
            self._semaphore.release()
    
    def should_throttle_globally(self) -> bool:
        """Check if global throttling should be applied"""
        with self._lock:
            # Check concurrent requests
            if self.concurrent_requests >= self.max_concurrent:
                return True
            
            # Check global rate
            if not self.global_token_bucket.consume():
                return True
            
            return False
    
    def record_global_request(self, success: bool, response_time: float = 0.0):
        """Record a global request outcome"""
        with self._lock:
            self.global_metrics.record_request(success, response_time)
    
    def get_global_metrics(self) -> Dict[str, Any]:
        """Get global rate limiting metrics"""
        with self._lock:
            now = time.time()
            recent_requests = len([
                t for t in self.global_request_times 
                if now - t < 60  # Last minute
            ])
            
            source_metrics = {
                name: limiter.get_metrics() 
                for name, limiter in self.source_limiters.items()
            }
            
            return {
                'global': {
                    'concurrent_requests': self.concurrent_requests,
                    'max_concurrent': self.max_concurrent,
                    'requests_per_minute': recent_requests,
                    'success_rate': self.global_metrics.success_rate,
                    'total_requests': self.global_metrics.total_requests,
                    'average_response_time': self.global_metrics.average_response_time
                },
                'sources': source_metrics,
                'configuration': {
                    'global_requests_per_minute': self.config.global_requests_per_minute,
                    'global_concurrent_requests': self.config.global_concurrent_requests,
                    'adaptive_delays': self.config.adaptive_delays,
                    'human_behavior_simulation': self.config.human_behavior_simulation
                }
            }


class IntelligentRateLimiter:
    """Main rate limiter with intelligent features"""
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self.global_limiter = GlobalRateLimiter(self.config)
        self.logger = logging.getLogger(__name__)
        
        # Request pattern analysis
        self.pattern_analyzer = RequestPatternAnalyzer()
        
        # Anti-detection features
        self.user_agent_pool = self._initialize_user_agents()
        self.current_user_agent_index = 0
        
        self.logger.info("IntelligentRateLimiter initialized")
    
    def _initialize_user_agents(self) -> List[str]:
        """Initialize pool of User-Agent strings"""
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36"
        ]
    
    @contextmanager
    def rate_limited_request(self, source_name: str, 
                           source_config: Optional[RateLimitConfig] = None):
        """Context manager for rate-limited requests"""
        
        # Get source-specific limiter
        source_limiter = self.global_limiter.get_source_limiter(source_name, source_config)
        
        # Acquire source-specific delay
        source_delay = source_limiter.acquire()
        
        # Apply delay if needed
        if source_delay > 0:
            self.logger.debug(f"Rate limiting {source_name}: waiting {source_delay:.2f}s")
            time.sleep(source_delay)
        
        # Acquire global slot
        with self.global_limiter.acquire_global_slot():
            start_time = time.time()
            success = False
            
            try:
                yield {
                    'user_agent': self.get_rotating_user_agent(),
                    'headers': self.get_anti_detection_headers()
                }
                success = True
                
            except Exception as e:
                self.logger.debug(f"Request failed for {source_name}: {e}")
                raise
            
            finally:
                # Record request outcome
                response_time = time.time() - start_time
                source_limiter.record_request_outcome(success, response_time)
                self.global_limiter.record_global_request(success, response_time)
                
                # Record pattern for analysis
                self.pattern_analyzer.record_request(source_name, success, response_time)
    
    @asynccontextmanager
    async def rate_limited_request_async(self, source_name: str,
                                       source_config: Optional[RateLimitConfig] = None):
        """Async context manager for rate-limited requests"""
        
        # Get source-specific limiter
        source_limiter = self.global_limiter.get_source_limiter(source_name, source_config)
        
        # Acquire source-specific delay
        source_delay = await asyncio.to_thread(source_limiter.acquire)
        
        # Apply delay if needed
        if source_delay > 0:
            self.logger.debug(f"Rate limiting {source_name}: waiting {source_delay:.2f}s")
            await asyncio.sleep(source_delay)
        
        # Acquire global slot
        async with self.global_limiter.acquire_global_slot_async():
            start_time = time.time()
            success = False
            
            try:
                yield {
                    'user_agent': self.get_rotating_user_agent(),
                    'headers': self.get_anti_detection_headers()
                }
                success = True
                
            except Exception as e:
                self.logger.debug(f"Async request failed for {source_name}: {e}")
                raise
            
            finally:
                # Record request outcome
                response_time = time.time() - start_time
                source_limiter.record_request_outcome(success, response_time)
                self.global_limiter.record_global_request(success, response_time)
                
                # Record pattern for analysis
                self.pattern_analyzer.record_request(source_name, success, response_time)
    
    def get_rotating_user_agent(self) -> str:
        """Get a rotating User-Agent string"""
        user_agent = self.user_agent_pool[self.current_user_agent_index]
        self.current_user_agent_index = (self.current_user_agent_index + 1) % len(self.user_agent_pool)
        return user_agent
    
    def get_anti_detection_headers(self) -> Dict[str, str]:
        """Get headers designed to avoid detection"""
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice([
                'en-US,en;q=0.5',
                'en-GB,en;q=0.9',
                'en-CA,en;q=0.8',
                'en-AU,en;q=0.7'
            ]),
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Occasionally add optional headers
        if random.random() < 0.3:
            headers['Cache-Control'] = 'max-age=0'
        
        if random.random() < 0.2:
            headers['Sec-Fetch-Dest'] = 'document'
            headers['Sec-Fetch-Mode'] = 'navigate'
            headers['Sec-Fetch-Site'] = 'none'
        
        return headers
    
    def get_metrics_report(self) -> Dict[str, Any]:
        """Get comprehensive metrics report"""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'rate_limiting': self.global_limiter.get_global_metrics(),
            'patterns': self.pattern_analyzer.get_analysis_report(),
            'configuration': {
                'requests_per_second': self.config.requests_per_second,
                'burst_size': self.config.burst_size,
                'adaptive_delays': self.config.adaptive_delays,
                'human_behavior_simulation': self.config.human_behavior_simulation
            }
        }


class RequestPatternAnalyzer:
    """Analyzes request patterns to optimize rate limiting"""
    
    def __init__(self):
        self.request_history = deque(maxlen=1000)
        self.source_patterns = defaultdict(list)
        self._lock = threading.Lock()
    
    def record_request(self, source_name: str, success: bool, response_time: float):
        """Record a request for pattern analysis"""
        with self._lock:
            record = {
                'timestamp': datetime.utcnow(),
                'source': source_name,
                'success': success,
                'response_time': response_time
            }
            
            self.request_history.append(record)
            self.source_patterns[source_name].append(record)
            
            # Keep only recent patterns per source
            if len(self.source_patterns[source_name]) > 100:
                self.source_patterns[source_name] = self.source_patterns[source_name][-100:]
    
    def get_analysis_report(self) -> Dict[str, Any]:
        """Get pattern analysis report"""
        with self._lock:
            if not self.request_history:
                return {}
            
            # Overall patterns
            recent_requests = [
                r for r in self.request_history 
                if (datetime.utcnow() - r['timestamp']).seconds < 300  # Last 5 minutes
            ]
            
            overall_success_rate = sum(1 for r in recent_requests if r['success']) / len(recent_requests) if recent_requests else 0
            
            # Per-source analysis
            source_analysis = {}
            for source, records in self.source_patterns.items():
                if records:
                    recent_source_records = [
                        r for r in records 
                        if (datetime.utcnow() - r['timestamp']).seconds < 300
                    ]
                    
                    if recent_source_records:
                        success_rate = sum(1 for r in recent_source_records if r['success']) / len(recent_source_records)
                        avg_response_time = statistics.mean(r['response_time'] for r in recent_source_records)
                        
                        source_analysis[source] = {
                            'recent_requests': len(recent_source_records),
                            'success_rate': success_rate,
                            'average_response_time': avg_response_time,
                            'recommendation': self._get_recommendation(success_rate, avg_response_time)
                        }
            
            return {
                'overall': {
                    'recent_requests': len(recent_requests),
                    'success_rate': overall_success_rate
                },
                'sources': source_analysis
            }
    
    def _get_recommendation(self, success_rate: float, avg_response_time: float) -> str:
        """Get recommendation based on patterns"""
        if success_rate < 0.5:
            return "increase_delay"
        elif success_rate > 0.9 and avg_response_time < 2.0:
            return "decrease_delay"
        else:
            return "maintain"


# Global rate limiter instance
_global_rate_limiter: Optional[IntelligentRateLimiter] = None


def get_rate_limiter(config: Optional[RateLimitConfig] = None) -> IntelligentRateLimiter:
    """Get global rate limiter instance"""
    global _global_rate_limiter
    
    if _global_rate_limiter is None:
        _global_rate_limiter = IntelligentRateLimiter(config)
    
    return _global_rate_limiter