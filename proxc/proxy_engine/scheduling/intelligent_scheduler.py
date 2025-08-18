"""Intelligent Scheduler with Priority-Based Queue and Resource Awareness

Advanced scheduling system that:
- Manages priority-based validation queues across tiers
- Implements resource-aware scheduling with load balancing
- Provides time-zone optimization for global proxies
- Handles burst detection and throttling
- Supports adaptive scheduling algorithms
- Implements circuit breaker patterns for reliability
"""

import asyncio
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional, Callable, Any, Tuple, Set
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, Future
import heapq
import random

from ...proxy_core.models import ProxyInfo, TierLevel, ProxyStatus, ValidationStatus
from .tier_manager import TierManager
from ..validation.validation_config import ValidationConfig

logger = logging.getLogger(__name__)


class SchedulingStrategy(Enum):
    """Scheduling strategies for different scenarios"""
    PRIORITY_FIRST = "priority_first"           # Schedule highest priority first
    ROUND_ROBIN = "round_robin"                 # Round-robin across tiers
    WEIGHTED_FAIR = "weighted_fair"             # Weighted fair queuing
    ADAPTIVE_LOAD = "adaptive_load"             # Adaptive based on system load
    TIME_ZONE_AWARE = "timezone_aware"          # Consider geographical time zones


class CircuitBreakerState(Enum):
    """Circuit breaker states for handling failures"""
    CLOSED = "closed"        # Normal operation
    OPEN = "open"           # Circuit is open, blocking requests
    HALF_OPEN = "half_open" # Testing if service is back


@dataclass
class SchedulingJob:
    """Represents a scheduled validation job"""
    proxy: ProxyInfo
    priority: float
    scheduled_time: datetime
    tier: TierLevel
    attempt_count: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)
    job_id: str = field(default_factory=lambda: f"job_{int(time.time() * 1000000)}")
    
    def __lt__(self, other):
        """For priority queue ordering (lower priority value = higher priority)"""
        return (self.priority, self.scheduled_time) < (other.priority, other.scheduled_time)


@dataclass
class CircuitBreaker:
    """Circuit breaker for handling service failures"""
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_calls: int = 3
    
    state: CircuitBreakerState = CircuitBreakerState.CLOSED
    failure_count: int = 0
    last_failure_time: Optional[datetime] = None
    half_open_calls: int = 0
    
    def record_success(self):
        """Record a successful operation"""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.CLOSED
            self.failure_count = 0
            self.half_open_calls = 0
            logger.info("Circuit breaker closed - service recovered")
    
    def record_failure(self):
        """Record a failed operation"""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        
        if self.state == CircuitBreakerState.CLOSED and self.failure_count >= self.failure_threshold:
            self.state = CircuitBreakerState.OPEN
            logger.warning(f"Circuit breaker opened - {self.failure_count} failures detected")
        elif self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.OPEN
            self.half_open_calls = 0
            logger.warning("Circuit breaker reopened during half-open test")
    
    def can_execute(self) -> bool:
        """Check if operation can be executed"""
        if self.state == CircuitBreakerState.CLOSED:
            return True
        elif self.state == CircuitBreakerState.OPEN:
            if (self.last_failure_time and 
                (datetime.utcnow() - self.last_failure_time).total_seconds() > self.recovery_timeout):
                self.state = CircuitBreakerState.HALF_OPEN
                self.half_open_calls = 0
                logger.info("Circuit breaker moved to half-open state")
                return True
            return False
        else:  # HALF_OPEN
            if self.half_open_calls < self.half_open_max_calls:
                self.half_open_calls += 1
                return True
            return False


class ResourceMonitor:
    """Monitors system resources and provides load metrics"""
    
    def __init__(self):
        self.cpu_history = deque(maxlen=60)  # Last 60 measurements
        self.memory_history = deque(maxlen=60)
        self.active_validations = 0
        self.max_concurrent = 100
        self.last_update = datetime.utcnow()
        
        # Try to import psutil for system monitoring
        self.has_psutil = False
        try:
            import psutil
            self.psutil = psutil
            self.has_psutil = True
        except ImportError:
            logger.warning("psutil not available - using basic resource monitoring")
    
    def update_metrics(self):
        """Update resource metrics"""
        now = datetime.utcnow()
        
        # Update at most once per second
        if (now - self.last_update).total_seconds() < 1.0:
            return
        
        if self.has_psutil:
            try:
                cpu_percent = self.psutil.cpu_percent(interval=None)
                memory_percent = self.psutil.virtual_memory().percent
                
                self.cpu_history.append(cpu_percent)
                self.memory_history.append(memory_percent)
            except Exception as e:
                logger.debug(f"Failed to update system metrics: {e}")
        else:
            # Fallback to basic metrics
            load_factor = min(self.active_validations / max(self.max_concurrent, 1), 1.0)
            self.cpu_history.append(load_factor * 100)
            self.memory_history.append(load_factor * 50)
        
        self.last_update = now
    
    def get_load_factor(self) -> float:
        """Get current system load factor (0.0 - 1.0)"""
        self.update_metrics()
        
        if not self.cpu_history:
            return 0.0
        
        # Combine CPU, memory, and active validation metrics
        cpu_avg = sum(self.cpu_history) / len(self.cpu_history) / 100.0
        memory_avg = sum(self.memory_history) / len(self.memory_history) / 100.0
        validation_load = self.active_validations / self.max_concurrent
        
        # Weighted average
        load_factor = (cpu_avg * 0.4 + memory_avg * 0.3 + validation_load * 0.3)
        return min(load_factor, 1.0)
    
    def is_system_overloaded(self, threshold: float = 0.8) -> bool:
        """Check if system is overloaded"""
        return self.get_load_factor() > threshold


class IntelligentScheduler:
    """Advanced scheduler for proxy validation with intelligent resource management"""
    
    def __init__(self, tier_manager: TierManager, max_concurrent_validations: int = 100):
        self.tier_manager = tier_manager
        self.max_concurrent_validations = max_concurrent_validations
        
        # Priority queues for each tier
        self.priority_queues: Dict[TierLevel, List[SchedulingJob]] = {
            tier: [] for tier in TierLevel
        }
        
        # Resource management
        self.resource_monitor = ResourceMonitor()
        self.resource_monitor.max_concurrent = max_concurrent_validations
        
        # Active validation tracking
        self.active_validations: Dict[str, SchedulingJob] = {}
        self.completed_validations: deque = deque(maxlen=10000)
        
        # Circuit breakers per tier
        self.circuit_breakers: Dict[TierLevel, CircuitBreaker] = {
            tier: CircuitBreaker() for tier in TierLevel
        }
        
        # Scheduling strategy
        self.strategy = SchedulingStrategy.WEIGHTED_FAIR
        self.strategy_weights = {
            TierLevel.TIER_1: 0.4,
            TierLevel.TIER_2: 0.35,
            TierLevel.TIER_3: 0.15,
            TierLevel.TIER_4: 0.1
        }
        
        # Burst detection and throttling
        self.burst_detector = self._create_burst_detector()
        self.throttle_state = False
        self.throttle_until = None
        
        # Statistics
        self.scheduling_stats = {
            'total_scheduled': 0,
            'total_executed': 0,
            'total_failures': 0,
            'avg_wait_time': 0.0,
            'tier_distribution': {tier: 0 for tier in TierLevel}
        }
        
        # Threading
        self._lock = threading.RLock()
        self._running = False
        self._scheduler_thread = None
        
        logger.info(f"IntelligentScheduler initialized with max {max_concurrent_validations} concurrent validations")
    
    def _create_burst_detector(self) -> Dict[str, Any]:
        """Create burst detection configuration"""
        return {
            'window_size': 60,  # seconds
            'request_history': deque(maxlen=1000),
            'burst_threshold': 50,  # requests per minute
            'throttle_duration': 30  # seconds
        }
    
    def schedule_proxy_validation(self, proxy: ProxyInfo, 
                                priority_override: Optional[float] = None,
                                delay_seconds: float = 0) -> str:
        """Schedule a proxy for validation"""
        
        with self._lock:
            # Calculate priority
            if priority_override is not None:
                priority = priority_override
            else:
                priority = self.tier_manager.calculate_validation_priority(proxy)
            
            # Create scheduling job
            scheduled_time = datetime.utcnow() + timedelta(seconds=delay_seconds)
            job = SchedulingJob(
                proxy=proxy,
                priority=priority,
                scheduled_time=scheduled_time,
                tier=proxy.tier_level
            )
            
            # Add to appropriate priority queue
            heapq.heappush(self.priority_queues[proxy.tier_level], job)
            
            # Update statistics
            self.scheduling_stats['total_scheduled'] += 1
            self.scheduling_stats['tier_distribution'][proxy.tier_level] += 1
            
            logger.debug(f"Scheduled {proxy.address} for validation (tier: {proxy.tier_level.name}, priority: {priority:.3f})")
            
            return job.job_id
    
    def schedule_proxies_batch(self, proxies: List[ProxyInfo], 
                             spread_over_minutes: int = 5) -> List[str]:
        """Schedule multiple proxies with intelligent spreading"""
        
        job_ids = []
        
        # Group proxies by tier for better resource allocation
        tier_groups = defaultdict(list)
        for proxy in proxies:
            tier_groups[proxy.tier_level].append(proxy)
        
        # Schedule each tier group with appropriate delays
        total_delay = 0
        for tier in sorted(tier_groups.keys(), key=lambda t: t.value):  # Higher priority tiers first
            tier_proxies = tier_groups[tier]
            tier_config = self.tier_manager.get_tier_config(tier)
            
            # Calculate delays for this tier
            if len(tier_proxies) > 1:
                max_delay = spread_over_minutes * 60 * tier_config.resource_allocation_percentage
                delay_increment = max_delay / len(tier_proxies)
            else:
                delay_increment = 0
            
            for i, proxy in enumerate(tier_proxies):
                delay = total_delay + (i * delay_increment)
                job_id = self.schedule_proxy_validation(proxy, delay_seconds=delay)
                job_ids.append(job_id)
            
            total_delay += delay_increment * len(tier_proxies)
        
        logger.info(f"Scheduled {len(proxies)} proxies across {len(tier_groups)} tiers")
        return job_ids
    
    def get_next_validation_job(self) -> Optional[SchedulingJob]:
        """Get the next validation job based on current strategy"""
        
        with self._lock:
            # Check if we're at capacity
            if len(self.active_validations) >= self.max_concurrent_validations:
                return None
            
            # Check for system overload
            if self.resource_monitor.is_system_overloaded():
                logger.debug("System overloaded, throttling new validations")
                return None
            
            # Check throttle state
            if self._is_throttled():
                return None
            
            # Select job based on strategy
            if self.strategy == SchedulingStrategy.PRIORITY_FIRST:
                return self._get_highest_priority_job()
            elif self.strategy == SchedulingStrategy.WEIGHTED_FAIR:
                return self._get_weighted_fair_job()
            elif self.strategy == SchedulingStrategy.TIME_ZONE_AWARE:
                return self._get_timezone_aware_job()
            else:
                return self._get_weighted_fair_job()  # Default fallback
    
    def _get_highest_priority_job(self) -> Optional[SchedulingJob]:
        """Get highest priority job across all tiers"""
        all_jobs = []
        
        for tier, queue in self.priority_queues.items():
            if queue and self.circuit_breakers[tier].can_execute():
                # Only consider jobs that are due
                due_jobs = [job for job in queue if job.scheduled_time <= datetime.utcnow()]
                if due_jobs:
                    all_jobs.extend(due_jobs)
        
        if not all_jobs:
            return None
        
        # Sort by priority and return highest
        all_jobs.sort(key=lambda j: (j.priority, j.scheduled_time))
        best_job = all_jobs[0]
        
        # Remove from appropriate queue
        self.priority_queues[best_job.tier].remove(best_job)
        heapq.heapify(self.priority_queues[best_job.tier])
        
        return best_job
    
    def _get_weighted_fair_job(self) -> Optional[SchedulingJob]:
        """Get job using weighted fair queuing"""
        
        # Calculate current allocation per tier
        current_allocation = defaultdict(int)
        for job in self.active_validations.values():
            current_allocation[job.tier] += 1
        
        # Find tier that is most under-allocated relative to its weight
        best_tier = None
        best_ratio = float('inf')
        
        for tier, weight in self.strategy_weights.items():
            if not self.priority_queues[tier] or not self.circuit_breakers[tier].can_execute():
                continue
            
            # Check for due jobs
            due_jobs = [job for job in self.priority_queues[tier] 
                       if job.scheduled_time <= datetime.utcnow()]
            if not due_jobs:
                continue
            
            expected_allocation = self.max_concurrent_validations * weight
            current = current_allocation[tier]
            
            if current < expected_allocation:
                ratio = current / expected_allocation if expected_allocation > 0 else 0
                if ratio < best_ratio:
                    best_ratio = ratio
                    best_tier = tier
        
        if best_tier is None:
            return None
        
        # Get highest priority job from selected tier
        queue = self.priority_queues[best_tier]
        due_jobs = [job for job in queue if job.scheduled_time <= datetime.utcnow()]
        
        if not due_jobs:
            return None
        
        # Sort and get best
        due_jobs.sort(key=lambda j: (j.priority, j.scheduled_time))
        best_job = due_jobs[0]
        
        # Remove from queue
        queue.remove(best_job)
        heapq.heapify(queue)
        
        return best_job
    
    def _get_timezone_aware_job(self) -> Optional[SchedulingJob]:
        """Get job considering geographical time zones for optimal scheduling"""
        
        current_hour = datetime.utcnow().hour
        
        # Prefer proxies in time zones where it's currently low-traffic hours
        # (e.g., early morning local time: 2-6 AM)
        preferred_timezones = []
        
        # This is a simplified implementation - in production, you'd use actual timezone data
        for offset in range(-12, 13):  # UTC-12 to UTC+12
            tz_hour = (current_hour + offset) % 24
            if 2 <= tz_hour <= 6:  # Low traffic hours
                preferred_timezones.append(offset)
        
        # First try to get jobs from preferred timezones
        for tier, queue in self.priority_queues.items():
            if not queue or not self.circuit_breakers[tier].can_execute():
                continue
            
            for job in queue:
                if job.scheduled_time > datetime.utcnow():
                    continue
                
                # Check if proxy is in preferred timezone (simplified)
                if job.proxy.geo_location and job.proxy.geo_location.timezone:
                    # This is simplified - real implementation would parse timezone
                    preferred = True  # Placeholder
                    if preferred:
                        queue.remove(job)
                        heapq.heapify(queue)
                        return job
        
        # Fallback to weighted fair if no timezone preference matches
        return self._get_weighted_fair_job()
    
    def _is_throttled(self) -> bool:
        """Check if scheduler is currently throttled"""
        if not self.throttle_state:
            return False
        
        if self.throttle_until and datetime.utcnow() > self.throttle_until:
            self.throttle_state = False
            self.throttle_until = None
            logger.info("Throttling disabled - resuming normal scheduling")
            return False
        
        return True
    
    def start_validation_job(self, job: SchedulingJob) -> bool:
        """Mark validation job as started"""
        
        with self._lock:
            if job.job_id in self.active_validations:
                return False
            
            # Check burst detection
            self._update_burst_detection()
            
            # Update resource monitoring
            self.resource_monitor.active_validations += 1
            
            # Track active validation
            self.active_validations[job.job_id] = job
            
            logger.debug(f"Started validation job {job.job_id} for {job.proxy.address}")
            return True
    
    def complete_validation_job(self, job_id: str, success: bool, 
                              execution_time: Optional[float] = None) -> bool:
        """Mark validation job as completed"""
        
        with self._lock:
            if job_id not in self.active_validations:
                return False
            
            job = self.active_validations[job_id]
            
            # Update circuit breaker
            if success:
                self.circuit_breakers[job.tier].record_success()
            else:
                self.circuit_breakers[job.tier].record_failure()
            
            # Update statistics
            self.scheduling_stats['total_executed'] += 1
            if not success:
                self.scheduling_stats['total_failures'] += 1
            
            if execution_time:
                wait_time = (datetime.utcnow() - job.created_at).total_seconds()
                current_avg = self.scheduling_stats['avg_wait_time']
                total_executed = self.scheduling_stats['total_executed']
                self.scheduling_stats['avg_wait_time'] = (
                    (current_avg * (total_executed - 1) + wait_time) / total_executed
                )
            
            # Move to completed
            self.completed_validations.append({
                'job_id': job_id,
                'proxy_address': job.proxy.address,
                'tier': job.tier.name,
                'success': success,
                'execution_time': execution_time,
                'completed_at': datetime.utcnow(),
                'wait_time': (datetime.utcnow() - job.created_at).total_seconds()
            })
            
            # Remove from active
            del self.active_validations[job_id]
            self.resource_monitor.active_validations -= 1
            
            logger.debug(f"Completed validation job {job_id} - success: {success}")
            return True
    
    def _update_burst_detection(self):
        """Update burst detection and apply throttling if needed"""
        now = datetime.utcnow()
        detector = self.burst_detector
        
        # Add current request
        detector['request_history'].append(now)
        
        # Count requests in window
        window_start = now - timedelta(seconds=detector['window_size'])
        recent_requests = [
            req_time for req_time in detector['request_history']
            if req_time >= window_start
        ]
        
        # Check for burst
        if len(recent_requests) > detector['burst_threshold']:
            if not self.throttle_state:
                self.throttle_state = True
                self.throttle_until = now + timedelta(seconds=detector['throttle_duration'])
                logger.warning(f"Burst detected ({len(recent_requests)} requests/min) - throttling for {detector['throttle_duration']}s")
    
    def get_queue_statistics(self) -> Dict[str, Any]:
        """Get comprehensive queue and scheduling statistics"""
        
        with self._lock:
            queue_sizes = {tier.name: len(queue) for tier, queue in self.priority_queues.items()}
            circuit_states = {tier.name: breaker.state.value for tier, breaker in self.circuit_breakers.items()}
            
            # Calculate average wait times per tier
            tier_wait_times = defaultdict(list)
            for completion in list(self.completed_validations)[-1000:]:  # Last 1000 completions
                tier_wait_times[completion['tier']].append(completion['wait_time'])
            
            avg_wait_times = {}
            for tier_name, wait_times in tier_wait_times.items():
                avg_wait_times[tier_name] = sum(wait_times) / len(wait_times) if wait_times else 0
            
            return {
                'queue_sizes': queue_sizes,
                'active_validations': len(self.active_validations),
                'max_concurrent': self.max_concurrent_validations,
                'system_load': self.resource_monitor.get_load_factor(),
                'circuit_breaker_states': circuit_states,
                'throttle_active': self.throttle_state,
                'scheduling_strategy': self.strategy.value,
                'tier_weights': {tier.name: weight for tier, weight in self.strategy_weights.items()},
                'average_wait_times': avg_wait_times,
                'scheduling_stats': self.scheduling_stats.copy(),
                'recent_completions': len(self.completed_validations)
            }
    
    def adjust_strategy(self, new_strategy: SchedulingStrategy, 
                       new_weights: Optional[Dict[TierLevel, float]] = None):
        """Dynamically adjust scheduling strategy"""
        
        with self._lock:
            old_strategy = self.strategy
            self.strategy = new_strategy
            
            if new_weights:
                self.strategy_weights = new_weights.copy()
            
            logger.info(f"Scheduling strategy changed from {old_strategy.value} to {new_strategy.value}")
    
    def optimize_based_on_performance(self, performance_data: Dict[str, Any]):
        """Optimize scheduling based on performance metrics"""
        
        # Analyze tier performance and adjust weights
        for tier_name, tier_data in performance_data.items():
            try:
                tier = TierLevel[tier_name.upper()]
                
                success_rate = tier_data.get('success_rate', 0)
                avg_response_time = tier_data.get('avg_response_time', 0)
                
                # Adjust weights based on performance
                current_weight = self.strategy_weights[tier]
                
                if success_rate > 0.8 and avg_response_time < 10000:  # Good performance
                    new_weight = min(current_weight * 1.1, 0.6)  # Increase up to 60%
                elif success_rate < 0.3 or avg_response_time > 30000:  # Poor performance
                    new_weight = max(current_weight * 0.9, 0.05)  # Decrease but keep minimum 5%
                else:
                    new_weight = current_weight
                
                if abs(new_weight - current_weight) > 0.01:
                    self.strategy_weights[tier] = new_weight
                    logger.info(f"Adjusted {tier.name} weight to {new_weight:.3f} based on performance")
                
            except (KeyError, ValueError):
                continue
        
        # Normalize weights to sum to 1.0
        total_weight = sum(self.strategy_weights.values())
        if total_weight > 0:
            for tier in self.strategy_weights:
                self.strategy_weights[tier] /= total_weight


def create_intelligent_scheduler(tier_manager: TierManager, 
                               max_concurrent: int = 100) -> IntelligentScheduler:
    """Factory function to create intelligent scheduler"""
    return IntelligentScheduler(tier_manager, max_concurrent)


if __name__ == "__main__":
    # Example usage and testing
    from .tier_manager import create_tier_manager
    from ...proxy_core.models import ProxyInfo, ProxyProtocol
    
    # Create components
    tier_manager = create_tier_manager()
    scheduler = create_intelligent_scheduler(tier_manager, max_concurrent=50)
    
    # Create test proxies
    test_proxies = []
    for i in range(10):
        proxy = ProxyInfo(
            host=f"192.168.1.{i+1}",
            port=8080 + i,
            protocol=ProxyProtocol.HTTP
        )
        # Assign random performance to simulate real data
        proxy.metrics.success_rate = random.uniform(20, 95)
        proxy.metrics.response_time = random.uniform(1000, 20000)
        proxy.metrics.check_count = random.randint(1, 100)
        
        # Assign tier based on performance
        tier = tier_manager.assign_initial_tier(proxy)
        proxy.tier_level = tier
        tier_manager._update_proxy_for_tier(proxy, tier)
        
        test_proxies.append(proxy)
    
    # Schedule proxies
    job_ids = scheduler.schedule_proxies_batch(test_proxies, spread_over_minutes=2)
    print(f"Scheduled {len(job_ids)} validation jobs")
    
    # Simulate getting and completing jobs
    for i in range(5):
        job = scheduler.get_next_validation_job()
        if job:
            print(f"Got job {job.job_id} for {job.proxy.address} (tier: {job.tier.name}, priority: {job.priority:.3f})")
            
            # Simulate starting and completing
            scheduler.start_validation_job(job)
            success = random.random() > 0.3  # 70% success rate
            execution_time = random.uniform(1, 10)
            scheduler.complete_validation_job(job.job_id, success, execution_time)
    
    # Show statistics
    stats = scheduler.get_queue_statistics()
    print(f"\nScheduler Statistics:")
    print(f"Queue sizes: {stats['queue_sizes']}")
    print(f"Active validations: {stats['active_validations']}")
    print(f"System load: {stats['system_load']:.2f}")
    print(f"Total scheduled: {stats['scheduling_stats']['total_scheduled']}")
    print(f"Total executed: {stats['scheduling_stats']['total_executed']}")
    print(f"Average wait time: {stats['scheduling_stats']['avg_wait_time']:.2f}s")