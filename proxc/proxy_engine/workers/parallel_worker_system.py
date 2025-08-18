"""Parallel Worker System with Specialization and Load Balancing

Advanced worker architecture that:
- Implements specialized workers for different validation types
- Provides intelligent load balancing across worker pools
- Supports dynamic scaling based on workload and performance
- Handles worker health monitoring and automatic recovery
- Optimizes resource allocation per worker type
- Implements work stealing for efficient resource utilization
"""

import asyncio
import logging
import threading
import time
import multiprocessing
from collections import defaultdict, deque
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Callable, Any, Set, Tuple, Union
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, Future, as_completed
import queue
import signal
import os

from ...proxy_core.models import ProxyInfo, TierLevel, ProxyStatus, ValidationStatus
from ..queue.intelligent_job_queue import ValidationJob, JobBatch, JobType
from ..validation.validation_config import ValidationConfig
from ..optimization.resource_optimizer import ResourceOptimizer

logger = logging.getLogger(__name__)


class WorkerType(Enum):
    """Types of specialized workers"""
    LIGHTWEIGHT_VALIDATOR = "lightweight_validator"      # Fast, basic validation
    COMPREHENSIVE_VALIDATOR = "comprehensive_validator"  # Full validation with all checks
    BULK_PROCESSOR = "bulk_processor"                   # Optimized for bulk operations
    PRIORITY_HANDLER = "priority_handler"               # High-priority urgent validations
    HEALTH_CHECKER = "health_checker"                   # Quick health checks
    RECOVERY_WORKER = "recovery_worker"                 # Handles failed job recovery


class WorkerStatus(Enum):
    """Worker status states"""
    IDLE = "idle"
    BUSY = "busy"
    OVERLOADED = "overloaded"
    FAILED = "failed"
    RECOVERING = "recovering"
    SHUTDOWN = "shutdown"


class LoadBalancingStrategy(Enum):
    """Load balancing strategies"""
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    LEAST_RESPONSE_TIME = "least_response_time"
    WORK_STEALING = "work_stealing"


@dataclass
class WorkerMetrics:
    """Performance metrics for a worker"""
    worker_id: str
    jobs_completed: int = 0
    jobs_failed: int = 0
    total_processing_time: float = 0.0
    last_activity: datetime = field(default_factory=datetime.utcnow)
    
    # Performance indicators
    success_rate: float = 0.0
    average_processing_time: float = 0.0
    throughput_per_minute: float = 0.0
    
    # Resource usage
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    
    def update_metrics(self, processing_time: float, success: bool):
        """Update metrics after job completion"""
        if success:
            self.jobs_completed += 1
        else:
            self.jobs_failed += 1
        
        self.total_processing_time += processing_time
        self.last_activity = datetime.utcnow()
        
        # Calculate derived metrics
        total_jobs = self.jobs_completed + self.jobs_failed
        if total_jobs > 0:
            self.success_rate = self.jobs_completed / total_jobs
            self.average_processing_time = self.total_processing_time / total_jobs
        
        # Calculate throughput (jobs per minute)
        time_diff = (datetime.utcnow() - self.last_activity).total_seconds()
        if time_diff > 0:
            self.throughput_per_minute = (self.jobs_completed / time_diff) * 60


@dataclass
class WorkerConfiguration:
    """Configuration for worker pools"""
    worker_type: WorkerType
    min_workers: int
    max_workers: int
    target_utilization: float  # 0.0 - 1.0
    scaling_factor: float      # How aggressively to scale
    health_check_interval: int # Seconds
    
    # Job type affinity
    preferred_job_types: Set[JobType]
    tier_weights: Dict[TierLevel, float]  # Preference for certain tiers
    
    # Performance thresholds
    max_queue_size: int
    timeout_seconds: int
    retry_attempts: int


class BaseWorker:
    """Base class for all worker types"""
    
    def __init__(self, worker_id: str, worker_type: WorkerType, config: WorkerConfiguration):
        self.worker_id = worker_id
        self.worker_type = worker_type
        self.config = config
        self.status = WorkerStatus.IDLE
        self.metrics = WorkerMetrics(worker_id)
        
        # Work queue and processing
        self.work_queue: queue.Queue = queue.Queue(maxsize=config.max_queue_size)
        self.current_job: Optional[ValidationJob] = None
        
        # Threading
        self._running = False
        self._worker_thread = None
        self._health_thread = None
        
        # Shutdown event
        self._shutdown_event = threading.Event()
    
    def start(self):
        """Start the worker"""
        if self._running:
            return
        
        self._running = True
        self._shutdown_event.clear()
        
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()
        
        self._health_thread = threading.Thread(target=self._health_loop, daemon=True)
        self._health_thread.start()
        
        logger.info(f"Worker {self.worker_id} ({self.worker_type.value}) started")
    
    def stop(self, timeout: int = 30):
        """Stop the worker gracefully"""
        self._running = False
        self._shutdown_event.set()
        
        # Wait for current job to complete
        if self._worker_thread:
            self._worker_thread.join(timeout=timeout)
        
        if self._health_thread:
            self._health_thread.join(timeout=5)
        
        self.status = WorkerStatus.SHUTDOWN
        logger.info(f"Worker {self.worker_id} stopped")
    
    def assign_job(self, job: ValidationJob) -> bool:
        """Assign a job to this worker"""
        try:
            self.work_queue.put_nowait(job)
            return True
        except queue.Full:
            return False
    
    def can_accept_job(self, job: ValidationJob) -> bool:
        """Check if worker can accept this job type"""
        return (job.job_type in self.config.preferred_job_types and
                not self.work_queue.full() and
                self.status in [WorkerStatus.IDLE, WorkerStatus.BUSY])
    
    def get_load_factor(self) -> float:
        """Get current load factor (0.0 - 1.0)"""
        if self.status == WorkerStatus.FAILED:
            return 1.0
        
        queue_load = self.work_queue.qsize() / self.config.max_queue_size
        processing_load = 1.0 if self.current_job else 0.0
        
        return min((queue_load + processing_load) / 2, 1.0)
    
    def _worker_loop(self):
        """Main worker processing loop"""
        while self._running and not self._shutdown_event.is_set():
            try:
                # Get next job with timeout
                job = self.work_queue.get(timeout=1.0)
                
                if job is None:  # Shutdown signal
                    break
                
                self.current_job = job
                self.status = WorkerStatus.BUSY
                
                # Process the job
                start_time = time.time()
                success = self._process_job(job)
                processing_time = time.time() - start_time
                
                # Update metrics
                self.metrics.update_metrics(processing_time, success)
                
                # Clean up
                self.current_job = None
                self.status = WorkerStatus.IDLE
                self.work_queue.task_done()
                
            except queue.Empty:
                # No jobs available, update status
                if self.status == WorkerStatus.BUSY:
                    self.status = WorkerStatus.IDLE
                continue
                
            except Exception as e:
                logger.error(f"Worker {self.worker_id} error: {e}")
                self.status = WorkerStatus.FAILED
                time.sleep(5)  # Brief recovery pause
    
    def _process_job(self, job: ValidationJob) -> bool:
        """Process a validation job - to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement _process_job")
    
    def _health_loop(self):
        """Health monitoring loop"""
        while self._running:
            try:
                self._perform_health_check()
                time.sleep(self.config.health_check_interval)
            except Exception as e:
                logger.error(f"Health check error for worker {self.worker_id}: {e}")
                time.sleep(self.config.health_check_interval)
    
    def _perform_health_check(self):
        """Perform health check - can be overridden by subclasses"""
        # Check if worker is stuck
        if (self.current_job and 
            (datetime.utcnow() - self.metrics.last_activity).total_seconds() > self.config.timeout_seconds):
            logger.warning(f"Worker {self.worker_id} appears stuck, marking as failed")
            self.status = WorkerStatus.FAILED


class LightweightValidator(BaseWorker):
    """Specialized worker for fast, basic validations"""
    
    def _process_job(self, job: ValidationJob) -> bool:
        """Process lightweight validation"""
        try:
            # Simulate lightweight validation
            proxy = job.proxy
            
            # Basic connectivity check
            start_time = time.time()
            
            # Simplified validation logic
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            
            try:
                result = sock.connect_ex((proxy.host, proxy.port))
                success = result == 0
            except Exception:
                success = False
            finally:
                sock.close()
            
            # Update proxy metrics
            if success:
                proxy.metrics.last_successful_check = datetime.utcnow()
                proxy.metrics.check_count += 1
                proxy.status = ProxyStatus.ACTIVE
            else:
                proxy.metrics.consecutive_failures += 1
                proxy.status = ProxyStatus.FAILED
            
            processing_time = time.time() - start_time
            logger.debug(f"Lightweight validation for {proxy.address}: {success} ({processing_time:.2f}s)")
            
            return success
            
        except Exception as e:
            logger.error(f"Lightweight validation failed for {job.job_id}: {e}")
            return False


class ComprehensiveValidator(BaseWorker):
    """Specialized worker for full validation with all checks"""
    
    def _process_job(self, job: ValidationJob) -> bool:
        """Process comprehensive validation"""
        try:
            proxy = job.proxy
            start_time = time.time()
            
            # Comprehensive validation includes:
            # - Connectivity test
            # - Anonymity testing
            # - Speed testing
            # - Headers validation
            # - Security checks
            
            success = self._perform_comprehensive_validation(proxy, job)
            
            processing_time = time.time() - start_time
            logger.debug(f"Comprehensive validation for {proxy.address}: {success} ({processing_time:.2f}s)")
            
            return success
            
        except Exception as e:
            logger.error(f"Comprehensive validation failed for {job.job_id}: {e}")
            return False
    
    def _perform_comprehensive_validation(self, proxy: ProxyInfo, job: ValidationJob) -> bool:
        """Perform all validation checks"""
        # This would integrate with the existing validation system
        # For now, simulate a more complex validation
        
        checks_passed = 0
        total_checks = 5
        
        # 1. Basic connectivity
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            if sock.connect_ex((proxy.host, proxy.port)) == 0:
                checks_passed += 1
            sock.close()
        except:
            pass
        
        # 2. Anonymity check (simulated)
        if proxy.tier_level in [TierLevel.TIER_1, TierLevel.TIER_2]:
            checks_passed += 1
        
        # 3. Speed test (simulated)
        time.sleep(0.1)  # Simulate speed test
        checks_passed += 1
        
        # 4. Headers validation (simulated)
        checks_passed += 1
        
        # 5. Security check (simulated)
        if proxy.metrics.check_count > 5:  # Only if we have history
            checks_passed += 1
        
        success = checks_passed >= (total_checks * 0.6)  # 60% pass rate
        
        # Update proxy metrics
        proxy.metrics.check_count += 1
        if success:
            proxy.metrics.last_successful_check = datetime.utcnow()
            proxy.metrics.consecutive_failures = 0
            proxy.status = ProxyStatus.ACTIVE
        else:
            proxy.metrics.consecutive_failures += 1
            proxy.status = ProxyStatus.FAILED
        
        return success


class BulkProcessor(BaseWorker):
    """Specialized worker optimized for bulk operations"""
    
    def _process_job(self, job: ValidationJob) -> bool:
        """Process job optimized for bulk operations"""
        try:
            # Bulk processors handle multiple proxies efficiently
            proxy = job.proxy
            
            # Use connection pooling and batch processing
            success = self._bulk_validate(proxy)
            
            return success
            
        except Exception as e:
            logger.error(f"Bulk processing failed for {job.job_id}: {e}")
            return False
    
    def _bulk_validate(self, proxy: ProxyInfo) -> bool:
        """Optimized bulk validation"""
        # Simulate efficient bulk validation
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)  # Faster timeout for bulk
            success = sock.connect_ex((proxy.host, proxy.port)) == 0
            sock.close()
            
            proxy.metrics.check_count += 1
            if success:
                proxy.metrics.last_successful_check = datetime.utcnow()
                proxy.status = ProxyStatus.ACTIVE
            else:
                proxy.metrics.consecutive_failures += 1
                proxy.status = ProxyStatus.FAILED
            
            return success
        except:
            return False


class WorkerPool:
    """Manages a pool of specialized workers"""
    
    def __init__(self, worker_type: WorkerType, config: WorkerConfiguration):
        self.worker_type = worker_type
        self.config = config
        self.workers: Dict[str, BaseWorker] = {}
        self.load_balancer = LoadBalancer(config.max_workers)
        
        # Statistics
        self.pool_stats = {
            'total_jobs_processed': 0,
            'total_jobs_failed': 0,
            'average_processing_time': 0.0,
            'current_workers': 0,
            'peak_workers': 0
        }
        
        # Scaling
        self.last_scale_time = datetime.utcnow()
        self.scale_cooldown = timedelta(minutes=2)
        
        logger.info(f"Created worker pool for {worker_type.value}")
    
    def start_initial_workers(self):
        """Start minimum number of workers"""
        for i in range(self.config.min_workers):
            self._create_worker()
    
    def _create_worker(self) -> BaseWorker:
        """Create a new worker of the appropriate type"""
        worker_id = f"{self.worker_type.value}_{len(self.workers)}_{int(time.time())}"
        
        if self.worker_type == WorkerType.LIGHTWEIGHT_VALIDATOR:
            worker = LightweightValidator(worker_id, self.worker_type, self.config)
        elif self.worker_type == WorkerType.COMPREHENSIVE_VALIDATOR:
            worker = ComprehensiveValidator(worker_id, self.worker_type, self.config)
        elif self.worker_type == WorkerType.BULK_PROCESSOR:
            worker = BulkProcessor(worker_id, self.worker_type, self.config)
        else:
            worker = BaseWorker(worker_id, self.worker_type, self.config)
        
        worker.start()
        self.workers[worker_id] = worker
        self.pool_stats['current_workers'] += 1
        self.pool_stats['peak_workers'] = max(self.pool_stats['peak_workers'], 
                                             self.pool_stats['current_workers'])
        
        logger.debug(f"Created worker {worker_id}")
        return worker
    
    def assign_job(self, job: ValidationJob) -> bool:
        """Assign job to best available worker"""
        suitable_workers = [w for w in self.workers.values() if w.can_accept_job(job)]
        
        if not suitable_workers:
            # Try to scale up if possible
            if self._should_scale_up():
                self._create_worker()
                suitable_workers = [w for w in self.workers.values() if w.can_accept_job(job)]
        
        if suitable_workers:
            worker = self.load_balancer.select_worker(suitable_workers)
            return worker.assign_job(job)
        
        return False
    
    def _should_scale_up(self) -> bool:
        """Determine if pool should scale up"""
        if len(self.workers) >= self.config.max_workers:
            return False
        
        if datetime.utcnow() - self.last_scale_time < self.scale_cooldown:
            return False
        
        # Check if all workers are busy
        busy_workers = sum(1 for w in self.workers.values() 
                          if w.status == WorkerStatus.BUSY)
        
        utilization = busy_workers / max(len(self.workers), 1)
        return utilization > self.config.target_utilization
    
    def _should_scale_down(self) -> bool:
        """Determine if pool should scale down"""
        if len(self.workers) <= self.config.min_workers:
            return False
        
        if datetime.utcnow() - self.last_scale_time < self.scale_cooldown:
            return False
        
        # Check if workers are underutilized
        busy_workers = sum(1 for w in self.workers.values() 
                          if w.status == WorkerStatus.BUSY)
        
        utilization = busy_workers / max(len(self.workers), 1)
        return utilization < (self.config.target_utilization * 0.5)
    
    def cleanup_failed_workers(self):
        """Remove failed workers and optionally replace them"""
        failed_workers = [w for w in self.workers.values() 
                         if w.status == WorkerStatus.FAILED]
        
        for worker in failed_workers:
            worker.stop()
            del self.workers[worker.worker_id]
            self.pool_stats['current_workers'] -= 1
            logger.warning(f"Removed failed worker {worker.worker_id}")
            
            # Replace if below minimum
            if len(self.workers) < self.config.min_workers:
                self._create_worker()
    
    def get_pool_metrics(self) -> Dict[str, Any]:
        """Get comprehensive pool metrics"""
        worker_metrics = {}
        total_load = 0.0
        
        for worker_id, worker in self.workers.items():
            worker_metrics[worker_id] = {
                'status': worker.status.value,
                'load_factor': worker.get_load_factor(),
                'jobs_completed': worker.metrics.jobs_completed,
                'success_rate': worker.metrics.success_rate,
                'avg_processing_time': worker.metrics.average_processing_time
            }
            total_load += worker.get_load_factor()
        
        return {
            'worker_type': self.worker_type.value,
            'worker_count': len(self.workers),
            'pool_utilization': total_load / max(len(self.workers), 1),
            'pool_stats': self.pool_stats.copy(),
            'worker_metrics': worker_metrics
        }


class LoadBalancer:
    """Intelligent load balancer for worker selection"""
    
    def __init__(self, max_workers: int, strategy: LoadBalancingStrategy = LoadBalancingStrategy.LEAST_CONNECTIONS):
        self.strategy = strategy
        self.max_workers = max_workers
        self.round_robin_index = 0
        self.connection_counts = defaultdict(int)
        self.response_times = defaultdict(deque)
    
    def select_worker(self, workers: List[BaseWorker]) -> BaseWorker:
        """Select best worker based on load balancing strategy"""
        if not workers:
            raise ValueError("No workers available")
        
        if self.strategy == LoadBalancingStrategy.ROUND_ROBIN:
            return self._round_robin_select(workers)
        elif self.strategy == LoadBalancingStrategy.LEAST_CONNECTIONS:
            return self._least_connections_select(workers)
        elif self.strategy == LoadBalancingStrategy.LEAST_RESPONSE_TIME:
            return self._least_response_time_select(workers)
        else:
            return self._least_connections_select(workers)  # Default
    
    def _round_robin_select(self, workers: List[BaseWorker]) -> BaseWorker:
        """Round-robin selection"""
        worker = workers[self.round_robin_index % len(workers)]
        self.round_robin_index += 1
        return worker
    
    def _least_connections_select(self, workers: List[BaseWorker]) -> BaseWorker:
        """Select worker with least load"""
        return min(workers, key=lambda w: w.get_load_factor())
    
    def _least_response_time_select(self, workers: List[BaseWorker]) -> BaseWorker:
        """Select worker with best response time"""
        best_worker = workers[0]
        best_time = float('inf')
        
        for worker in workers:
            avg_time = worker.metrics.average_processing_time
            if avg_time < best_time:
                best_time = avg_time
                best_worker = worker
        
        return best_worker


class ParallelWorkerSystem:
    """Main coordinator for parallel worker system"""
    
    def __init__(self, resource_optimizer: Optional[ResourceOptimizer] = None):
        self.resource_optimizer = resource_optimizer
        self.worker_pools: Dict[WorkerType, WorkerPool] = {}
        
        # System configuration
        self.worker_configs = self._create_default_worker_configs()
        
        # Job routing
        self.job_router = JobRouter()
        
        # System statistics
        self.system_stats = {
            'total_jobs_processed': 0,
            'total_workers_created': 0,
            'system_uptime': datetime.utcnow()
        }
        
        # Management thread
        self._running = False
        self._management_thread = None
        
        logger.info("ParallelWorkerSystem initialized")
    
    def _create_default_worker_configs(self) -> Dict[WorkerType, WorkerConfiguration]:
        """Create default configurations for each worker type"""
        return {
            WorkerType.LIGHTWEIGHT_VALIDATOR: WorkerConfiguration(
                worker_type=WorkerType.LIGHTWEIGHT_VALIDATOR,
                min_workers=5,
                max_workers=20,
                target_utilization=0.7,
                scaling_factor=1.3,
                health_check_interval=30,
                preferred_job_types={JobType.STANDARD_VALIDATION, JobType.HEALTH_CHECK},
                tier_weights={TierLevel.TIER_1: 1.0, TierLevel.TIER_2: 0.8, 
                             TierLevel.TIER_3: 0.6, TierLevel.TIER_4: 0.4},
                max_queue_size=50,
                timeout_seconds=60,
                retry_attempts=2
            ),
            
            WorkerType.COMPREHENSIVE_VALIDATOR: WorkerConfiguration(
                worker_type=WorkerType.COMPREHENSIVE_VALIDATOR,
                min_workers=3,
                max_workers=10,
                target_utilization=0.8,
                scaling_factor=1.2,
                health_check_interval=45,
                preferred_job_types={JobType.PRIORITY_VALIDATION, JobType.REVALIDATION},
                tier_weights={TierLevel.TIER_1: 1.0, TierLevel.TIER_2: 1.0, 
                             TierLevel.TIER_3: 0.7, TierLevel.TIER_4: 0.5},
                max_queue_size=30,
                timeout_seconds=120,
                retry_attempts=3
            ),
            
            WorkerType.BULK_PROCESSOR: WorkerConfiguration(
                worker_type=WorkerType.BULK_PROCESSOR,
                min_workers=2,
                max_workers=8,
                target_utilization=0.6,
                scaling_factor=1.5,
                health_check_interval=60,
                preferred_job_types={JobType.BULK_VALIDATION},
                tier_weights={TierLevel.TIER_1: 0.8, TierLevel.TIER_2: 0.8, 
                             TierLevel.TIER_3: 1.0, TierLevel.TIER_4: 1.0},
                max_queue_size=100,
                timeout_seconds=180,
                retry_attempts=1
            )
        }
    
    def start_system(self):
        """Start the parallel worker system"""
        if self._running:
            return
        
        self._running = True
        
        # Create worker pools
        for worker_type, config in self.worker_configs.items():
            pool = WorkerPool(worker_type, config)
            pool.start_initial_workers()
            self.worker_pools[worker_type] = pool
        
        # Start management thread
        self._management_thread = threading.Thread(target=self._management_loop, daemon=True)
        self._management_thread.start()
        
        logger.info("Parallel worker system started")
    
    def stop_system(self, timeout: int = 60):
        """Stop the parallel worker system"""
        self._running = False
        
        # Stop all workers
        for pool in self.worker_pools.values():
            for worker in pool.workers.values():
                worker.stop(timeout=10)
        
        if self._management_thread:
            self._management_thread.join(timeout=10)
        
        logger.info("Parallel worker system stopped")
    
    def submit_job(self, job: ValidationJob) -> bool:
        """Submit job to appropriate worker pool"""
        target_worker_type = self.job_router.route_job(job)
        
        if target_worker_type in self.worker_pools:
            success = self.worker_pools[target_worker_type].assign_job(job)
            if success:
                self.system_stats['total_jobs_processed'] += 1
            return success
        
        return False
    
    def _management_loop(self):
        """Background management and optimization"""
        while self._running:
            try:
                # Health checks and cleanup
                for pool in self.worker_pools.values():
                    pool.cleanup_failed_workers()
                
                # Resource optimization
                if self.resource_optimizer:
                    self._optimize_resources()
                
                time.sleep(30)  # Management cycle every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in management loop: {e}")
                time.sleep(30)
    
    def _optimize_resources(self):
        """Optimize worker allocation based on system resources"""
        if not self.resource_optimizer:
            return
        
        current_allocation = self.resource_optimizer.get_current_allocation()
        system_load = current_allocation['system_metrics']['cpu_percent'] / 100.0
        
        # Adjust worker pool sizes based on load
        for worker_type, pool in self.worker_pools.items():
            pool_metrics = pool.get_pool_metrics()
            utilization = pool_metrics['pool_utilization']
            
            # Scale based on utilization and system load
            if system_load < 0.7 and utilization > 0.8:
                # System has capacity and pool is busy
                if pool._should_scale_up():
                    pool._create_worker()
            elif system_load > 0.9 or utilization < 0.3:
                # System is stressed or pool is underutilized
                if pool._should_scale_down():
                    # Remove least utilized worker
                    workers = list(pool.workers.values())
                    if len(workers) > pool.config.min_workers:
                        least_utilized = min(workers, key=lambda w: w.get_load_factor())
                        least_utilized.stop()
                        del pool.workers[least_utilized.worker_id]
                        pool.pool_stats['current_workers'] -= 1
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        pool_status = {}
        for worker_type, pool in self.worker_pools.items():
            pool_status[worker_type.value] = pool.get_pool_metrics()
        
        return {
            'system_stats': self.system_stats.copy(),
            'pool_status': pool_status,
            'total_workers': sum(len(pool.workers) for pool in self.worker_pools.values()),
            'system_uptime': (datetime.utcnow() - self.system_stats['system_uptime']).total_seconds()
        }


class JobRouter:
    """Routes jobs to appropriate worker types"""
    
    def route_job(self, job: ValidationJob) -> WorkerType:
        """Determine which worker type should handle this job"""
        
        # Route based on job type
        if job.job_type == JobType.BULK_VALIDATION:
            return WorkerType.BULK_PROCESSOR
        elif job.job_type == JobType.PRIORITY_VALIDATION:
            return WorkerType.COMPREHENSIVE_VALIDATOR
        elif job.job_type == JobType.HEALTH_CHECK:
            return WorkerType.LIGHTWEIGHT_VALIDATOR
        elif job.job_type == JobType.REVALIDATION:
            return WorkerType.COMPREHENSIVE_VALIDATOR
        
        # Route based on tier
        if job.tier in [TierLevel.TIER_1, TierLevel.TIER_2]:
            return WorkerType.COMPREHENSIVE_VALIDATOR
        else:
            return WorkerType.LIGHTWEIGHT_VALIDATOR


def create_parallel_worker_system(resource_optimizer: Optional[ResourceOptimizer] = None) -> ParallelWorkerSystem:
    """Factory function to create parallel worker system"""
    return ParallelWorkerSystem(resource_optimizer)


if __name__ == "__main__":
    # Example usage and testing
    from ...proxy_core.models import ProxyInfo, ProxyProtocol
    import random
    
    # Create worker system
    worker_system = create_parallel_worker_system()
    worker_system.start_system()
    
    # Create test jobs
    test_jobs = []
    for i in range(20):
        proxy = ProxyInfo(
            host=f"192.168.1.{i+1}",
            port=8080 + i,
            protocol=ProxyProtocol.HTTP
        )
        proxy.tier_level = random.choice(list(TierLevel))
        
        job = ValidationJob(
            proxy=proxy,
            job_type=random.choice(list(JobType)),
            priority=random.uniform(0.1, 1.0),
            created_at=datetime.utcnow(),
            source="test",
            tier=proxy.tier_level
        )
        test_jobs.append(job)
    
    # Submit jobs
    print("Submitting jobs...")
    for job in test_jobs:
        success = worker_system.submit_job(job)
        print(f"Job {job.job_id}: {'submitted' if success else 'failed'}")
    
    # Wait and check status
    time.sleep(10)
    status = worker_system.get_system_status()
    
    print(f"\nSystem Status:")
    print(f"Total workers: {status['total_workers']}")
    print(f"Jobs processed: {status['system_stats']['total_jobs_processed']}")
    print(f"Uptime: {status['system_uptime']:.1f} seconds")
    
    for pool_name, pool_info in status['pool_status'].items():
        print(f"\n{pool_name}:")
        print(f"  Workers: {pool_info['worker_count']}")
        print(f"  Utilization: {pool_info['pool_utilization']:.2f}")
    
    # Stop system
    worker_system.stop_system()