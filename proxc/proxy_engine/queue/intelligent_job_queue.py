"""Intelligent Job Queue with Batching and Deduplication

Advanced job queue system that:
- Implements intelligent batching for similar validation tasks
- Provides deduplication to prevent redundant validations
- Supports priority-based scheduling with load balancing
- Handles job persistence and recovery
- Optimizes batch sizes based on system resources
- Implements fair queuing across different sources
"""

import asyncio
import logging
import threading
import time
import hashlib
import pickle
from collections import defaultdict, deque
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Callable, Any, Set, Tuple, Union
from dataclasses import dataclass, field
import heapq
import json
import os

from ...proxy_core.models import ProxyInfo, TierLevel, ProxyStatus, ValidationStatus
from ..scheduling.intelligent_scheduler import SchedulingJob
from ..validation.validation_config import ValidationConfig

logger = logging.getLogger(__name__)


class JobStatus(Enum):
    """Status of jobs in the queue"""
    PENDING = "pending"
    BATCHED = "batched"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    DEDUPLICATED = "deduplicated"


class JobType(Enum):
    """Types of validation jobs"""
    STANDARD_VALIDATION = "standard_validation"
    BULK_VALIDATION = "bulk_validation"
    PRIORITY_VALIDATION = "priority_validation"
    REVALIDATION = "revalidation"
    HEALTH_CHECK = "health_check"


class BatchingStrategy(Enum):
    """Strategies for batching jobs"""
    BY_TIER = "by_tier"
    BY_NETWORK = "by_network"
    BY_PROVIDER = "by_provider"
    BY_GEOGRAPHIC = "by_geographic"
    MIXED_OPTIMAL = "mixed_optimal"


@dataclass
class ValidationJob:
    """Individual validation job with metadata"""
    proxy: ProxyInfo
    job_type: JobType
    priority: float
    created_at: datetime
    source: str  # Source that submitted the job
    tier: TierLevel
    config_override: Optional[Dict[str, Any]] = None
    
    # Job lifecycle
    job_id: str = field(default_factory=lambda: f"job_{int(time.time() * 1000000)}")
    status: JobStatus = JobStatus.PENDING
    attempts: int = 0
    max_attempts: int = 3
    batch_id: Optional[str] = None
    
    # Deduplication
    dedup_key: str = field(init=False)
    
    def __post_init__(self):
        """Generate deduplication key"""
        self.dedup_key = self._generate_dedup_key()
    
    def _generate_dedup_key(self) -> str:
        """Generate unique key for deduplication"""
        key_data = f"{self.proxy.address}:{self.job_type.value}:{self.tier.value}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def __lt__(self, other):
        """For priority queue ordering"""
        return (self.priority, self.created_at) < (other.priority, other.created_at)


@dataclass
class JobBatch:
    """Batch of jobs for efficient processing"""
    batch_id: str
    jobs: List[ValidationJob]
    batch_type: JobType
    tier: TierLevel
    created_at: datetime
    strategy: BatchingStrategy
    
    # Processing metadata
    estimated_duration: float = 0.0
    resource_requirements: Dict[str, float] = field(default_factory=dict)
    priority: float = 0.0
    
    def __post_init__(self):
        """Calculate batch metadata"""
        if self.jobs:
            self.priority = sum(job.priority for job in self.jobs) / len(self.jobs)
            self.estimated_duration = len(self.jobs) * 2.0  # Rough estimate
    
    def __len__(self):
        return len(self.jobs)
    
    def __lt__(self, other):
        """For priority queue ordering"""
        return (self.priority, self.created_at) < (other.priority, other.created_at)


class DeduplicationManager:
    """Manages job deduplication with time-based expiration"""
    
    def __init__(self, expiration_hours: int = 1):
        self.expiration_hours = expiration_hours
        self.dedup_cache: Dict[str, Tuple[datetime, str]] = {}
        self.job_results: Dict[str, Any] = {}
        self._lock = threading.RLock()
    
    def is_duplicate(self, job: ValidationJob) -> Tuple[bool, Optional[str]]:
        """Check if job is a duplicate"""
        with self._lock:
            self._cleanup_expired()
            
            if job.dedup_key in self.dedup_cache:
                cached_time, cached_job_id = self.dedup_cache[job.dedup_key]
                if (datetime.utcnow() - cached_time).total_seconds() < self.expiration_hours * 3600:
                    return True, cached_job_id
                else:
                    # Expired entry
                    del self.dedup_cache[job.dedup_key]
            
            return False, None
    
    def register_job(self, job: ValidationJob):
        """Register job in deduplication cache"""
        with self._lock:
            self.dedup_cache[job.dedup_key] = (datetime.utcnow(), job.job_id)
    
    def store_result(self, job_id: str, result: Any):
        """Store job result for duplicate requests"""
        with self._lock:
            self.job_results[job_id] = {
                'result': result,
                'timestamp': datetime.utcnow()
            }
    
    def get_cached_result(self, job_id: str) -> Optional[Any]:
        """Get cached result for duplicate job"""
        with self._lock:
            if job_id in self.job_results:
                cached = self.job_results[job_id]
                if (datetime.utcnow() - cached['timestamp']).total_seconds() < self.expiration_hours * 3600:
                    return cached['result']
                else:
                    del self.job_results[job_id]
            return None
    
    def _cleanup_expired(self):
        """Remove expired entries"""
        now = datetime.utcnow()
        expired_keys = [
            key for key, (timestamp, _) in self.dedup_cache.items()
            if (now - timestamp).total_seconds() > self.expiration_hours * 3600
        ]
        
        for key in expired_keys:
            del self.dedup_cache[key]
        
        # Clean up results too
        expired_results = [
            job_id for job_id, data in self.job_results.items()
            if (now - data['timestamp']).total_seconds() > self.expiration_hours * 3600
        ]
        
        for job_id in expired_results:
            del self.job_results[job_id]


class BatchOptimizer:
    """Optimizes batch creation based on system resources and job characteristics"""
    
    def __init__(self, max_batch_size: int = 50, min_batch_size: int = 5):
        self.max_batch_size = max_batch_size
        self.min_batch_size = min_batch_size
        self.performance_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
    
    def calculate_optimal_batch_size(self, jobs: List[ValidationJob], 
                                   system_load: float, strategy: BatchingStrategy) -> int:
        """Calculate optimal batch size based on conditions"""
        
        # Base size calculation
        if system_load < 0.3:
            base_size = self.max_batch_size
        elif system_load < 0.6:
            base_size = int(self.max_batch_size * 0.7)
        elif system_load < 0.8:
            base_size = int(self.max_batch_size * 0.5)
        else:
            base_size = self.min_batch_size
        
        # Adjust based on job characteristics
        if strategy == BatchingStrategy.BY_TIER:
            # Tier 1 jobs can be processed in larger batches
            tier_sizes = defaultdict(int)
            for job in jobs:
                tier_sizes[job.tier] += 1
            
            if tier_sizes.get(TierLevel.TIER_1, 0) > tier_sizes.get(TierLevel.TIER_4, 0):
                base_size = int(base_size * 1.2)
        
        elif strategy == BatchingStrategy.BY_NETWORK:
            # Network-based batching can be more efficient
            base_size = int(base_size * 1.1)
        
        # Historical performance adjustment
        strategy_key = f"{strategy.value}_{len(jobs)}"
        if strategy_key in self.performance_history:
            recent_performance = list(self.performance_history[strategy_key])[-10:]
            if recent_performance:
                avg_performance = sum(recent_performance) / len(recent_performance)
                if avg_performance > 0.8:  # Good performance
                    base_size = int(base_size * 1.1)
                elif avg_performance < 0.5:  # Poor performance
                    base_size = int(base_size * 0.8)
        
        return max(self.min_batch_size, min(base_size, len(jobs)))
    
    def record_batch_performance(self, batch: JobBatch, success_rate: float):
        """Record performance for future optimization"""
        strategy_key = f"{batch.strategy.value}_{len(batch.jobs)}"
        self.performance_history[strategy_key].append(success_rate)


class IntelligentJobQueue:
    """Advanced job queue with intelligent batching and deduplication"""
    
    def __init__(self, max_queue_size: int = 10000, 
                 batch_timeout_seconds: int = 30,
                 persistence_file: Optional[str] = None):
        
        self.max_queue_size = max_queue_size
        self.batch_timeout_seconds = batch_timeout_seconds
        self.persistence_file = persistence_file
        
        # Queue management
        self.pending_jobs: List[ValidationJob] = []
        self.job_batches: List[JobBatch] = []
        self.processing_batches: Dict[str, JobBatch] = {}
        self.completed_jobs: deque = deque(maxlen=10000)
        
        # Deduplication and optimization
        self.dedup_manager = DeduplicationManager()
        self.batch_optimizer = BatchOptimizer()
        
        # Source-based fair queuing
        self.source_quotas: Dict[str, int] = defaultdict(lambda: 100)
        self.source_usage: Dict[str, int] = defaultdict(int)
        
        # Statistics and monitoring
        self.queue_stats = {
            'total_submitted': 0,
            'total_deduplicated': 0,
            'total_batched': 0,
            'total_completed': 0,
            'avg_batch_size': 0.0,
            'avg_processing_time': 0.0
        }
        
        # Threading and state
        self._lock = threading.RLock()
        self._running = False
        self._batch_thread = None
        self._persist_thread = None
        
        # Load persisted jobs if file exists
        self._load_persisted_jobs()
        
        logger.info(f"IntelligentJobQueue initialized with max size {max_queue_size}")
    
    def start_processing(self):
        """Start background job processing"""
        if self._running:
            return
        
        self._running = True
        self._batch_thread = threading.Thread(target=self._batch_processing_loop, daemon=True)
        self._batch_thread.start()
        
        if self.persistence_file:
            self._persist_thread = threading.Thread(target=self._persistence_loop, daemon=True)
            self._persist_thread.start()
        
        logger.info("Job queue processing started")
    
    def stop_processing(self):
        """Stop background processing"""
        self._running = False
        
        if self._batch_thread:
            self._batch_thread.join(timeout=10)
        
        if self._persist_thread:
            self._persist_thread.join(timeout=5)
        
        # Final persistence
        if self.persistence_file:
            self._persist_jobs()
        
        logger.info("Job queue processing stopped")
    
    def submit_job(self, proxy: ProxyInfo, job_type: JobType = JobType.STANDARD_VALIDATION,
                   priority: float = 1.0, source: str = "default",
                   config_override: Optional[Dict[str, Any]] = None) -> str:
        """Submit a new validation job"""
        
        with self._lock:
            # Check queue capacity
            if len(self.pending_jobs) >= self.max_queue_size:
                logger.warning("Job queue at capacity, rejecting new job")
                raise Exception("Job queue is full")
            
            # Check source quota
            if self.source_usage[source] >= self.source_quotas[source]:
                logger.warning(f"Source {source} has exceeded quota")
                raise Exception(f"Source quota exceeded for {source}")
            
            # Create job
            job = ValidationJob(
                proxy=proxy,
                job_type=job_type,
                priority=priority,
                created_at=datetime.utcnow(),
                source=source,
                tier=proxy.tier_level,
                config_override=config_override
            )
            
            # Check for duplicates
            is_duplicate, cached_job_id = self.dedup_manager.is_duplicate(job)
            if is_duplicate:
                job.status = JobStatus.DEDUPLICATED
                self.queue_stats['total_deduplicated'] += 1
                
                # Try to return cached result
                cached_result = self.dedup_manager.get_cached_result(cached_job_id)
                if cached_result:
                    logger.debug(f"Returning cached result for duplicate job {job.job_id}")
                    return cached_job_id
            
            # Register job and add to queue
            self.dedup_manager.register_job(job)
            heapq.heappush(self.pending_jobs, job)
            
            # Update statistics
            self.queue_stats['total_submitted'] += 1
            self.source_usage[source] += 1
            
            logger.debug(f"Submitted job {job.job_id} for {proxy.address} (source: {source})")
            return job.job_id
    
    def submit_bulk_jobs(self, proxies: List[ProxyInfo], 
                        job_type: JobType = JobType.BULK_VALIDATION,
                        source: str = "bulk_import") -> List[str]:
        """Submit multiple jobs efficiently"""
        job_ids = []
        
        # Check quota first
        with self._lock:
            available_quota = self.source_quotas[source] - self.source_usage[source]
            if len(proxies) > available_quota:
                logger.warning(f"Bulk submission exceeds quota: {len(proxies)} > {available_quota}")
                proxies = proxies[:available_quota]
        
        # Submit jobs in batches to avoid holding lock too long
        batch_size = 100
        for i in range(0, len(proxies), batch_size):
            batch_proxies = proxies[i:i + batch_size]
            
            for proxy in batch_proxies:
                try:
                    job_id = self.submit_job(proxy, job_type, source=source)
                    job_ids.append(job_id)
                except Exception as e:
                    logger.warning(f"Failed to submit job for {proxy.address}: {e}")
        
        logger.info(f"Submitted {len(job_ids)} bulk jobs from {source}")
        return job_ids
    
    def get_next_batch(self, max_wait_seconds: float = 30.0) -> Optional[JobBatch]:
        """Get next batch of jobs for processing"""
        start_time = time.time()
        
        while time.time() - start_time < max_wait_seconds:
            with self._lock:
                if self.job_batches:
                    batch = heapq.heappop(self.job_batches)
                    self.processing_batches[batch.batch_id] = batch
                    
                    # Update job statuses
                    for job in batch.jobs:
                        job.status = JobStatus.PROCESSING
                        job.batch_id = batch.batch_id
                    
                    logger.debug(f"Retrieved batch {batch.batch_id} with {len(batch.jobs)} jobs")
                    return batch
            
            time.sleep(0.1)
        
        return None
    
    def complete_batch(self, batch_id: str, results: List[Tuple[str, bool, Any]]):
        """Mark batch as completed with results"""
        with self._lock:
            if batch_id not in self.processing_batches:
                logger.warning(f"Unknown batch ID: {batch_id}")
                return
            
            batch = self.processing_batches[batch_id]
            success_count = 0
            
            # Process results
            for job_id, success, result in results:
                job = next((j for j in batch.jobs if j.job_id == job_id), None)
                if job:
                    job.status = JobStatus.COMPLETED if success else JobStatus.FAILED
                    
                    # Store result for deduplication
                    self.dedup_manager.store_result(job_id, result)
                    
                    # Move to completed
                    self.completed_jobs.append({
                        'job_id': job_id,
                        'proxy_address': job.proxy.address,
                        'success': success,
                        'result': result,
                        'completed_at': datetime.utcnow(),
                        'processing_time': (datetime.utcnow() - job.created_at).total_seconds()
                    })
                    
                    if success:
                        success_count += 1
            
            # Update statistics
            self.queue_stats['total_completed'] += len(batch.jobs)
            success_rate = success_count / len(batch.jobs) if batch.jobs else 0
            
            # Record performance for optimization
            self.batch_optimizer.record_batch_performance(batch, success_rate)
            
            # Clean up
            del self.processing_batches[batch_id]
            
            logger.info(f"Completed batch {batch_id}: {success_count}/{len(batch.jobs)} successful")
    
    def _batch_processing_loop(self):
        """Background loop for creating batches"""
        while self._running:
            try:
                with self._lock:
                    if len(self.pending_jobs) >= 5:  # Minimum jobs for batching
                        self._create_batches()
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"Error in batch processing loop: {e}")
                time.sleep(5)
    
    def _create_batches(self):
        """Create batches from pending jobs"""
        if not self.pending_jobs:
            return
        
        # Group jobs by characteristics for optimal batching
        job_groups = self._group_jobs_for_batching()
        
        for group_key, jobs in job_groups.items():
            if len(jobs) < 3:  # Too few jobs to batch
                continue
            
            strategy = self._determine_batching_strategy(jobs)
            optimal_size = self.batch_optimizer.calculate_optimal_batch_size(
                jobs, system_load=0.5, strategy=strategy  # TODO: Get actual system load
            )
            
            # Create batches from this group
            while len(jobs) >= optimal_size:
                batch_jobs = jobs[:optimal_size]
                jobs = jobs[optimal_size:]
                
                batch = JobBatch(
                    batch_id=f"batch_{int(time.time() * 1000000)}",
                    jobs=batch_jobs,
                    batch_type=batch_jobs[0].job_type,
                    tier=batch_jobs[0].tier,
                    created_at=datetime.utcnow(),
                    strategy=strategy
                )
                
                # Remove jobs from pending and add to batch queue
                for job in batch_jobs:
                    job.status = JobStatus.BATCHED
                    if job in self.pending_jobs:
                        self.pending_jobs.remove(job)
                
                heapq.heappush(self.job_batches, batch)
                self.queue_stats['total_batched'] += len(batch_jobs)
                
                # Update average batch size
                total_batches = self.queue_stats['total_batched'] / max(optimal_size, 1)
                self.queue_stats['avg_batch_size'] = self.queue_stats['total_batched'] / max(total_batches, 1)
                
                logger.debug(f"Created batch {batch.batch_id} with {len(batch_jobs)} jobs")
        
        # Re-heapify pending jobs after removals
        heapq.heapify(self.pending_jobs)
    
    def _group_jobs_for_batching(self) -> Dict[str, List[ValidationJob]]:
        """Group jobs by characteristics for optimal batching"""
        groups = defaultdict(list)
        
        for job in self.pending_jobs[:200]:  # Process first 200 jobs
            # Group by tier and job type primarily
            group_key = f"{job.tier.value}_{job.job_type.value}"
            
            # Add network information if available
            if job.proxy.geo_location:
                network_prefix = ".".join(job.proxy.host.split(".")[:2])  # /16 network
                group_key += f"_{network_prefix}"
            
            groups[group_key].append(job)
        
        return groups
    
    def _determine_batching_strategy(self, jobs: List[ValidationJob]) -> BatchingStrategy:
        """Determine optimal batching strategy for job group"""
        if not jobs:
            return BatchingStrategy.MIXED_OPTIMAL
        
        # Analyze job characteristics
        tiers = set(job.tier for job in jobs)
        networks = set(job.proxy.host.split(".")[0] for job in jobs)
        sources = set(job.source for job in jobs)
        
        if len(tiers) == 1:
            return BatchingStrategy.BY_TIER
        elif len(networks) <= 3:
            return BatchingStrategy.BY_NETWORK
        elif len(sources) <= 2:
            return BatchingStrategy.BY_PROVIDER
        else:
            return BatchingStrategy.MIXED_OPTIMAL
    
    def _persistence_loop(self):
        """Background loop for persisting queue state"""
        while self._running:
            try:
                self._persist_jobs()
                time.sleep(60)  # Persist every minute
            except Exception as e:
                logger.error(f"Error in persistence loop: {e}")
                time.sleep(60)
    
    def _persist_jobs(self):
        """Persist job queue state to file"""
        if not self.persistence_file:
            return
        
        try:
            with self._lock:
                state = {
                    'pending_jobs': [self._job_to_dict(job) for job in self.pending_jobs],
                    'job_batches': [self._batch_to_dict(batch) for batch in self.job_batches],
                    'processing_batches': {bid: self._batch_to_dict(batch) 
                                         for bid, batch in self.processing_batches.items()},
                    'queue_stats': self.queue_stats.copy(),
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # Write to temporary file first, then rename for atomic operation
            temp_file = self.persistence_file + ".tmp"
            with open(temp_file, 'w') as f:
                json.dump(state, f, indent=2, default=str)
            
            os.rename(temp_file, self.persistence_file)
            
        except Exception as e:
            logger.error(f"Failed to persist job queue: {e}")
    
    def _load_persisted_jobs(self):
        """Load persisted jobs from file"""
        if not self.persistence_file or not os.path.exists(self.persistence_file):
            return
        
        try:
            with open(self.persistence_file, 'r') as f:
                state = json.load(f)
            
            # TODO: Implement job restoration from persistence
            # This would require serializing/deserializing ProxyInfo objects
            logger.info(f"Loaded persisted state with {len(state.get('pending_jobs', []))} pending jobs")
            
        except Exception as e:
            logger.error(f"Failed to load persisted jobs: {e}")
    
    def _job_to_dict(self, job: ValidationJob) -> Dict[str, Any]:
        """Convert job to dictionary for persistence"""
        return {
            'job_id': job.job_id,
            'proxy_address': job.proxy.address,
            'job_type': job.job_type.value,
            'priority': job.priority,
            'created_at': job.created_at.isoformat(),
            'source': job.source,
            'tier': job.tier.value,
            'status': job.status.value
        }
    
    def _batch_to_dict(self, batch: JobBatch) -> Dict[str, Any]:
        """Convert batch to dictionary for persistence"""
        return {
            'batch_id': batch.batch_id,
            'jobs': [self._job_to_dict(job) for job in batch.jobs],
            'batch_type': batch.batch_type.value,
            'tier': batch.tier.value,
            'created_at': batch.created_at.isoformat(),
            'strategy': batch.strategy.value
        }
    
    def get_queue_statistics(self) -> Dict[str, Any]:
        """Get comprehensive queue statistics"""
        with self._lock:
            return {
                'queue_sizes': {
                    'pending': len(self.pending_jobs),
                    'batched': sum(len(batch.jobs) for batch in self.job_batches),
                    'processing': sum(len(batch.jobs) for batch in self.processing_batches.values()),
                    'completed': len(self.completed_jobs)
                },
                'statistics': self.queue_stats.copy(),
                'source_usage': dict(self.source_usage),
                'source_quotas': dict(self.source_quotas),
                'deduplication_cache_size': len(self.dedup_manager.dedup_cache),
                'batch_count': len(self.job_batches),
                'processing_batch_count': len(self.processing_batches)
            }
    
    def set_source_quota(self, source: str, quota: int):
        """Set quota for a specific source"""
        with self._lock:
            self.source_quotas[source] = quota
            logger.info(f"Set quota for source {source} to {quota}")
    
    def reset_source_usage(self, source: Optional[str] = None):
        """Reset usage counters for source(s)"""
        with self._lock:
            if source:
                self.source_usage[source] = 0
            else:
                self.source_usage.clear()
            logger.info(f"Reset usage for {'all sources' if not source else source}")


def create_intelligent_job_queue(max_queue_size: int = 10000,
                                batch_timeout: int = 30,
                                persistence_file: Optional[str] = None) -> IntelligentJobQueue:
    """Factory function to create intelligent job queue"""
    return IntelligentJobQueue(max_queue_size, batch_timeout, persistence_file)


if __name__ == "__main__":
    # Example usage and testing
    from ...proxy_core.models import ProxyInfo, ProxyProtocol
    import random
    
    # Create job queue
    queue = create_intelligent_job_queue(max_queue_size=1000, persistence_file="test_queue.json")
    queue.start_processing()
    
    # Create test proxies
    test_proxies = []
    for i in range(50):
        proxy = ProxyInfo(
            host=f"192.168.{random.randint(1,10)}.{i+1}",
            port=8080 + i,
            protocol=ProxyProtocol.HTTP
        )
        proxy.tier_level = random.choice(list(TierLevel))
        test_proxies.append(proxy)
    
    # Submit jobs
    print("Submitting jobs...")
    job_ids = []
    for proxy in test_proxies:
        job_id = queue.submit_job(
            proxy, 
            job_type=random.choice(list(JobType)),
            priority=random.uniform(0.1, 1.0),
            source=f"source_{random.randint(1,5)}"
        )
        job_ids.append(job_id)
    
    print(f"Submitted {len(job_ids)} jobs")
    
    # Process some batches
    for i in range(5):
        batch = queue.get_next_batch(max_wait_seconds=5)
        if batch:
            print(f"Processing batch {batch.batch_id} with {len(batch.jobs)} jobs")
            
            # Simulate processing
            results = []
            for job in batch.jobs:
                success = random.random() > 0.3  # 70% success rate
                result = {"success": success, "response_time": random.uniform(1000, 5000)}
                results.append((job.job_id, success, result))
            
            queue.complete_batch(batch.batch_id, results)
        else:
            print("No batches available")
        
        time.sleep(2)
    
    # Show statistics
    stats = queue.get_queue_statistics()
    print(f"\nQueue Statistics:")
    print(f"Pending jobs: {stats['queue_sizes']['pending']}")
    print(f"Batched jobs: {stats['queue_sizes']['batched']}")
    print(f"Processing jobs: {stats['queue_sizes']['processing']}")
    print(f"Completed jobs: {stats['queue_sizes']['completed']}")
    print(f"Total submitted: {stats['statistics']['total_submitted']}")
    print(f"Total deduplicated: {stats['statistics']['total_deduplicated']}")
    print(f"Average batch size: {stats['statistics']['avg_batch_size']:.1f}")
    
    # Stop queue
    queue.stop_processing()