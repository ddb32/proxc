"""Smart Scheduling System for Multi-Tiered Proxy Scanning

Implements intelligent scheduling with priority queues, resource allocation,
adaptive intervals, and workload balancing across scanning tiers.
"""

import logging
import asyncio
import heapq
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import math

# Conditional imports based on what's available
try:
    from ...proxy_core.models import ProxyInfo, TierLevel, RiskCategory, ProxyStatus
    from .tier_manager import TierManager, TierConfiguration
    HAS_MODELS = True
except ImportError:
    HAS_MODELS = False
    # Fallback enum definitions
    class TierLevel(Enum):
        TIER_1 = "tier_1"
        TIER_2 = "tier_2"
        TIER_3 = "tier_3"
        TIER_4 = "tier_4"

logger = logging.getLogger(__name__)


class SchedulingStrategy(Enum):
    """Different scheduling strategies"""
    ROUND_ROBIN = "round_robin"
    PRIORITY_BASED = "priority_based"
    ADAPTIVE = "adaptive"
    LOAD_BALANCED = "load_balanced"


@dataclass
class ScheduledScanJob:
    """Represents a scheduled scanning job"""
    proxy: 'ProxyInfo'
    scheduled_time: datetime
    priority: float
    tier_level: TierLevel
    retry_count: int = 0
    estimated_duration: float = 0.0
    dependencies: List[str] = field(default_factory=list)
    
    def __lt__(self, other):
        """For heapq priority queue ordering"""
        # Higher priority and earlier scheduled time = lower heap value
        return (self.scheduled_time, -self.priority) < (other.scheduled_time, -other.priority)
    
    def is_ready(self) -> bool:
        """Check if job is ready to execute"""
        return datetime.utcnow() >= self.scheduled_time and not self.dependencies


@dataclass
class SchedulingMetrics:
    """Metrics for scheduling performance"""
    jobs_scheduled: int = 0
    jobs_completed: int = 0
    jobs_failed: int = 0
    jobs_cancelled: int = 0
    average_wait_time: float = 0.0
    average_execution_time: float = 0.0
    resource_utilization: Dict[TierLevel, float] = field(default_factory=dict)
    queue_sizes: Dict[TierLevel, int] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.utcnow)


class ScanScheduler:
    """Intelligent scheduling system for proxy scanning operations"""
    
    def __init__(self, tier_manager: TierManager, config: Optional[Dict[str, Any]] = None):
        """
        Initialize scan scheduler
        
        Args:
            tier_manager: TierManager instance for tier-based scheduling
            config: Configuration dictionary
        """
        self.tier_manager = tier_manager
        self.config = config or {}
        
        # Scheduling configuration
        self.strategy = SchedulingStrategy(self.config.get('strategy', 'adaptive'))
        self.max_concurrent_jobs = self.config.get('max_concurrent_jobs', 100)
        self.scheduling_interval = self.config.get('scheduling_interval', 60)  # seconds
        self.adaptive_learning_rate = self.config.get('adaptive_learning_rate', 0.1)
        
        # Priority queues for each tier
        self.job_queues: Dict[TierLevel, List[ScheduledScanJob]] = {
            tier: [] for tier in TierLevel
        }
        
        # Active jobs tracking
        self.active_jobs: Dict[str, ScheduledScanJob] = {}  # proxy_id -> job
        self.completed_jobs: List[ScheduledScanJob] = []
        
        # Resource management
        self.tier_resource_limits: Dict[TierLevel, int] = {}
        self.current_resource_usage: Dict[TierLevel, int] = {tier: 0 for tier in TierLevel}
        
        # Scheduling metrics
        self.metrics = SchedulingMetrics()
        self.performance_history: List[Dict[str, Any]] = []
        
        # Thread management
        self.scheduler_thread: Optional[threading.Thread] = None
        self.is_running = False
        self.lock = threading.RLock()
        
        # Adaptive scheduling parameters
        self.tier_performance_weights: Dict[TierLevel, float] = {
            tier: 1.0 for tier in TierLevel
        }
        self.congestion_factors: Dict[TierLevel, float] = {
            tier: 1.0 for tier in TierLevel
        }
        
        self._initialize_resource_limits()
        logger.info(f"ScanScheduler initialized with {self.strategy.value} strategy")
    
    def _initialize_resource_limits(self):
        """Initialize resource limits based on tier configurations"""
        total_resources = self.max_concurrent_jobs
        
        for tier in TierLevel:
            tier_config = self.tier_manager.get_tier_config(tier)
            allocated_resources = int(total_resources * tier_config.resource_allocation_percentage)
            self.tier_resource_limits[tier] = max(1, allocated_resources)
        
        logger.debug(f"Resource limits: {self.tier_resource_limits}")
    
    def schedule_proxy_scan(self, proxy: 'ProxyInfo', priority_override: Optional[float] = None) -> bool:
        """
        Schedule a proxy for scanning
        
        Args:
            proxy: ProxyInfo object to schedule
            priority_override: Optional priority override
            
        Returns:
            True if successfully scheduled, False otherwise
        """
        with self.lock:
            # Check if already scheduled or active
            if proxy.proxy_id in self.active_jobs:
                logger.debug(f"Proxy {proxy.proxy_id} already scheduled/active")
                return False
            
            # Calculate priority
            if priority_override is not None:
                priority = priority_override
            else:
                priority = self._calculate_scan_priority(proxy)
            
            # Determine scheduling time
            scheduled_time = self._calculate_scheduled_time(proxy)
            
            # Estimate duration
            estimated_duration = self._estimate_scan_duration(proxy)
            
            # Create job
            job = ScheduledScanJob(
                proxy=proxy,
                scheduled_time=scheduled_time,
                priority=priority,
                tier_level=proxy.tier_level,
                estimated_duration=estimated_duration
            )
            
            # Add to appropriate queue
            heapq.heappush(self.job_queues[proxy.tier_level], job)
            self.metrics.jobs_scheduled += 1
            
            logger.debug(f"Scheduled {proxy.proxy_id} in {proxy.tier_level.value} "
                        f"(priority: {priority:.2f}, scheduled: {scheduled_time})")
            
            return True
    
    def _calculate_scan_priority(self, proxy: 'ProxyInfo') -> float:
        """Calculate scanning priority for a proxy"""
        # Base priority from tier manager
        base_priority = self.tier_manager.calculate_validation_priority(proxy)
        
        # Adjust for tier performance weights
        tier_weight = self.tier_performance_weights.get(proxy.tier_level, 1.0)
        
        # Adjust for congestion
        congestion_factor = self.congestion_factors.get(proxy.tier_level, 1.0)
        
        # Calculate final priority
        priority = base_priority * tier_weight / congestion_factor
        
        # Boost priority for overdue scans
        if proxy.next_scheduled_check and datetime.utcnow() > proxy.next_scheduled_check:
            overdue_hours = (datetime.utcnow() - proxy.next_scheduled_check).total_seconds() / 3600
            priority += min(overdue_hours * 0.5, 5.0)  # Up to 5 point boost
        
        # Boost priority for high-performing proxies
        if hasattr(proxy, 'calculate_tier_score'):
            tier_score = proxy.calculate_tier_score()
            if tier_score > 80:
                priority += 1.0
        
        return max(0.1, priority)  # Minimum priority
    
    def _calculate_scheduled_time(self, proxy: 'ProxyInfo') -> datetime:
        """Calculate when a proxy should be scheduled for scanning"""
        now = datetime.utcnow()
        
        # Use existing scheduled time if available and not overdue
        if proxy.next_scheduled_check and proxy.next_scheduled_check > now:
            return proxy.next_scheduled_check
        
        # Calculate based on tier configuration
        tier_config = self.tier_manager.get_tier_config(proxy.tier_level)
        interval_hours = tier_config.validation_interval_hours
        
        # Apply adaptive adjustments
        if self.strategy == SchedulingStrategy.ADAPTIVE:
            # Adjust interval based on recent performance
            if hasattr(proxy, 'metrics'):
                success_rate = getattr(proxy.metrics, 'success_rate', 50.0)
                if success_rate > 90:
                    interval_hours *= 1.2  # Scan less frequently for reliable proxies
                elif success_rate < 30:
                    interval_hours *= 0.5  # Scan more frequently for unreliable proxies
        
        # Add some jitter to avoid thundering herd
        jitter_minutes = (hash(proxy.proxy_id) % 60) - 30
        
        scheduled_time = now + timedelta(hours=interval_hours, minutes=jitter_minutes)
        return scheduled_time
    
    def _estimate_scan_duration(self, proxy: 'ProxyInfo') -> float:
        """Estimate scan duration in seconds"""
        tier_config = self.tier_manager.get_tier_config(proxy.tier_level)
        
        # Base duration from tier timeout settings
        base_duration = (
            tier_config.timeout_multiplier * 30 +  # Base scan time
            tier_config.retry_attempts * 10        # Retry overhead
        )
        
        # Adjust based on historical performance
        if hasattr(proxy, 'metrics') and hasattr(proxy.metrics, 'response_time'):
            if proxy.metrics.response_time > 0:
                # Factor in average response time
                response_factor = min(proxy.metrics.response_time / 1000, 10)  # Max 10x factor
                base_duration *= (1 + response_factor * 0.1)
        
        return base_duration
    
    def start_scheduler(self):
        """Start the background scheduling thread"""
        if self.is_running:
            logger.warning("Scheduler already running")
            return
        
        self.is_running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
        logger.info("Scan scheduler started")
    
    def stop_scheduler(self):
        """Stop the background scheduling thread"""
        if not self.is_running:
            return
        
        self.is_running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        logger.info("Scan scheduler stopped")
    
    def _scheduler_loop(self):
        """Main scheduling loop"""
        while self.is_running:
            try:
                self._process_job_queues()
                self._update_adaptive_parameters()
                self._cleanup_completed_jobs()
                time.sleep(self.scheduling_interval)
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")
                time.sleep(5)  # Wait before retrying
    
    def _process_job_queues(self):
        """Process job queues and dispatch ready jobs"""
        with self.lock:
            ready_jobs = []
            
            # Collect ready jobs from all tiers
            for tier in TierLevel:
                queue = self.job_queues[tier]
                tier_limit = self.tier_resource_limits[tier]
                current_usage = self.current_resource_usage[tier]
                
                while queue and current_usage < tier_limit:
                    if queue[0].is_ready():
                        job = heapq.heappop(queue)
                        ready_jobs.append(job)
                        current_usage += 1
                    else:
                        break  # Queue is time-ordered, so no more ready jobs
                
                self.current_resource_usage[tier] = current_usage
            
            # Sort by priority and dispatch
            ready_jobs.sort(key=lambda j: (-j.priority, j.scheduled_time))
            
            for job in ready_jobs:
                if len(self.active_jobs) < self.max_concurrent_jobs:
                    self._dispatch_job(job)
    
    def _dispatch_job(self, job: ScheduledScanJob):
        """Dispatch a job for execution"""
        self.active_jobs[job.proxy.proxy_id] = job
        job.proxy.status = ProxyStatus.VALIDATING if hasattr(ProxyStatus, 'VALIDATING') else job.proxy.status
        
        logger.debug(f"Dispatched {job.proxy.proxy_id} from {job.tier_level.value}")
        
        # Here you would typically submit the job to a worker pool
        # For now, we'll just simulate completion
        self._simulate_job_completion(job)
    
    def _simulate_job_completion(self, job: ScheduledScanJob):
        """Simulate job completion (placeholder for actual execution)"""
        # This would be replaced with actual scanning logic
        def complete_job():
            time.sleep(job.estimated_duration / 10)  # Simulate work
            self.complete_job(job.proxy.proxy_id, success=True)
        
        # Submit to thread pool for actual execution
        threading.Thread(target=complete_job, daemon=True).start()
    
    def complete_job(self, proxy_id: str, success: bool, error: Optional[str] = None):
        """Mark a job as completed"""
        with self.lock:
            job = self.active_jobs.pop(proxy_id, None)
            if not job:
                logger.warning(f"No active job found for proxy {proxy_id}")
                return
            
            # Update resource usage
            self.current_resource_usage[job.tier_level] -= 1
            
            # Update metrics
            if success:
                self.metrics.jobs_completed += 1
            else:
                self.metrics.jobs_failed += 1
            
            # Update job
            job.proxy.last_checked = datetime.utcnow()
            if hasattr(job.proxy, 'status'):
                job.proxy.status = ProxyStatus.ACTIVE if success else ProxyStatus.INACTIVE
            
            # Store completed job for analysis
            self.completed_jobs.append(job)
            
            # Schedule next scan if successful
            if success:
                next_scan_time = self._calculate_scheduled_time(job.proxy)
                job.proxy.next_scheduled_check = next_scan_time
            
            logger.debug(f"Completed {proxy_id} ({'success' if success else 'failed'})")
    
    def _update_adaptive_parameters(self):
        """Update adaptive scheduling parameters based on performance"""
        if self.strategy != SchedulingStrategy.ADAPTIVE:
            return
        
        # Update tier performance weights based on success rates
        for tier in TierLevel:
            tier_jobs = [job for job in self.completed_jobs[-100:] 
                        if job.tier_level == tier]
            
            if len(tier_jobs) >= 5:  # Need minimum sample size
                success_rate = sum(1 for job in tier_jobs 
                                 if hasattr(job.proxy, 'status') and 
                                 job.proxy.status == ProxyStatus.ACTIVE) / len(tier_jobs)
                
                # Adjust weight based on success rate
                target_weight = 0.5 + success_rate  # Range: 0.5 to 1.5
                current_weight = self.tier_performance_weights[tier]
                
                # Smooth adjustment
                new_weight = (current_weight * (1 - self.adaptive_learning_rate) + 
                             target_weight * self.adaptive_learning_rate)
                
                self.tier_performance_weights[tier] = new_weight
        
        # Update congestion factors based on queue sizes
        for tier in TierLevel:
            queue_size = len(self.job_queues[tier])
            active_jobs = self.current_resource_usage[tier]
            limit = self.tier_resource_limits[tier]
            
            # Calculate congestion factor
            if limit > 0:
                utilization = active_jobs / limit
                queue_pressure = min(queue_size / 10, 2.0)  # Max 2x factor
                congestion = 1.0 + utilization * 0.5 + queue_pressure * 0.3
                
                self.congestion_factors[tier] = congestion
    
    def _cleanup_completed_jobs(self):
        """Clean up old completed jobs"""
        # Keep only last 1000 completed jobs
        if len(self.completed_jobs) > 1000:
            self.completed_jobs = self.completed_jobs[-500:]
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status and metrics"""
        with self.lock:
            return {
                'strategy': self.strategy.value,
                'total_active_jobs': len(self.active_jobs),
                'max_concurrent': self.max_concurrent_jobs,
                'queue_sizes': {
                    tier.value: len(queue) for tier, queue in self.job_queues.items()
                },
                'resource_usage': {
                    tier.value: {
                        'current': usage,
                        'limit': self.tier_resource_limits[tier],
                        'utilization': usage / self.tier_resource_limits[tier] if self.tier_resource_limits[tier] > 0 else 0
                    }
                    for tier, usage in self.current_resource_usage.items()
                },
                'performance_weights': {
                    tier.value: weight for tier, weight in self.tier_performance_weights.items()
                },
                'congestion_factors': {
                    tier.value: factor for tier, factor in self.congestion_factors.items()
                },
                'metrics': {
                    'scheduled': self.metrics.jobs_scheduled,
                    'completed': self.metrics.jobs_completed,
                    'failed': self.metrics.jobs_failed,
                    'success_rate': (self.metrics.jobs_completed / 
                                   max(self.metrics.jobs_completed + self.metrics.jobs_failed, 1)) * 100
                }
            }
    
    def get_next_jobs(self, tier: TierLevel, count: int = 10) -> List[ScheduledScanJob]:
        """Get next jobs for a specific tier"""
        with self.lock:
            queue = self.job_queues[tier]
            ready_jobs = [job for job in queue if job.is_ready()]
            ready_jobs.sort(key=lambda j: (-j.priority, j.scheduled_time))
            return ready_jobs[:count]
    
    def cancel_job(self, proxy_id: str) -> bool:
        """Cancel a scheduled or active job"""
        with self.lock:
            # Check active jobs
            if proxy_id in self.active_jobs:
                job = self.active_jobs.pop(proxy_id)
                self.current_resource_usage[job.tier_level] -= 1
                self.metrics.jobs_cancelled += 1
                logger.info(f"Cancelled active job for {proxy_id}")
                return True
            
            # Check queued jobs
            for tier, queue in self.job_queues.items():
                for i, job in enumerate(queue):
                    if job.proxy.proxy_id == proxy_id:
                        queue.pop(i)
                        heapq.heapify(queue)  # Restore heap property
                        self.metrics.jobs_cancelled += 1
                        logger.info(f"Cancelled queued job for {proxy_id}")
                        return True
            
            return False
    
    def reschedule_failed_jobs(self, max_retries: int = 3):
        """Reschedule failed jobs with exponential backoff"""
        with self.lock:
            failed_jobs = [job for job in self.completed_jobs 
                          if (hasattr(job.proxy, 'status') and 
                              job.proxy.status != ProxyStatus.ACTIVE and 
                              job.retry_count < max_retries)]
            
            for job in failed_jobs:
                job.retry_count += 1
                
                # Exponential backoff
                delay_minutes = 2 ** job.retry_count
                job.scheduled_time = datetime.utcnow() + timedelta(minutes=delay_minutes)
                
                # Lower priority for retries
                job.priority *= 0.8
                
                # Re-queue
                heapq.heappush(self.job_queues[job.tier_level], job)
                
                logger.debug(f"Rescheduled failed job {job.proxy.proxy_id} "
                           f"(retry {job.retry_count}/{max_retries})")


def create_scan_scheduler(tier_manager: TierManager, 
                         config: Optional[Dict[str, Any]] = None) -> ScanScheduler:
    """Factory function to create scan scheduler"""
    return ScanScheduler(tier_manager, config)