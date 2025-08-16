"""Dynamic Thread Pool Manager - Adaptive threading based on system performance"""

import asyncio
import logging
import psutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable
from collections import deque

from ...proxy_core.models import ProxyInfo
from ..validation.validation_config import ValidationConfig
from ..validation.validation_results import ValidationResult


@dataclass
class PerformanceMetrics:
    """Performance metrics for adaptive threading"""
    avg_response_time: float = 0.0
    success_rate: float = 0.0
    throughput: float = 0.0  # proxies per second
    cpu_usage: float = 0.0
    memory_usage: float = 0.0  # MB
    error_rate: float = 0.0
    active_threads: int = 0
    queue_size: int = 0
    timestamp: float = field(default_factory=time.time)


@dataclass
class ThreadPoolConfig:
    """Configuration for dynamic thread pool"""
    min_threads: int = 2
    max_threads: int = 100
    initial_threads: int = 10
    scale_factor: float = 1.2  # Multiplier for scaling up/down
    
    # Performance thresholds for scaling decisions
    response_time_threshold: float = 2000.0  # ms - scale up if exceeded
    cpu_threshold: float = 80.0  # % - scale down if exceeded
    memory_threshold: float = 1024.0  # MB - scale down if exceeded
    error_rate_threshold: float = 0.3  # 30% - scale down if exceeded
    success_rate_threshold: float = 0.7  # 70% - scale up if above this
    
    # Monitoring settings
    metrics_window_size: int = 10  # Number of recent metrics to consider
    scaling_cooldown: float = 30.0  # Seconds between scaling decisions
    monitoring_interval: float = 5.0  # Seconds between performance checks


class DynamicThreadPoolManager:
    """Manages dynamic thread pool with performance-based scaling"""
    
    def __init__(self, config: Optional[ThreadPoolConfig] = None):
        self.config = config or ThreadPoolConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Thread pool management
        self.current_threads = self.config.initial_threads
        self.executor: Optional[ThreadPoolExecutor] = None
        self.is_running = False
        
        # Performance monitoring
        self.metrics_history: deque = deque(maxlen=self.config.metrics_window_size)
        self.last_scaling_time = 0.0
        self.monitoring_thread: Optional[threading.Thread] = None
        self.stop_monitoring = threading.Event()
        
        # Statistics
        self.total_tasks = 0
        self.completed_tasks = 0
        self.failed_tasks = 0
        self.scaling_events = []
        
        # Task tracking (thread-safe)
        self.active_tasks = set()
        self.task_start_times = {}
        self.task_lock = threading.RLock()  # Protects task tracking data
        
        self.logger.info(f"DynamicThreadPoolManager initialized with {self.current_threads} initial threads")
    
    def start(self):
        """Start the dynamic thread pool and monitoring"""
        if self.is_running:
            return
        
        self.is_running = True
        self.executor = ThreadPoolExecutor(max_workers=self.current_threads)
        
        # Start performance monitoring
        self.monitoring_thread = threading.Thread(target=self._monitor_performance, daemon=True)
        self.monitoring_thread.start()
        
        self.logger.info("Dynamic thread pool started")
    
    def stop(self):
        """Stop the thread pool and monitoring"""
        if not self.is_running:
            return
        
        self.is_running = False
        self.stop_monitoring.set()
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5.0)
        
        if self.executor:
            self.executor.shutdown(wait=True)
            self.executor = None
        
        self.logger.info("Dynamic thread pool stopped")
    
    def submit_task(self, func: Callable, *args, **kwargs) -> 'TaskFuture':
        """Submit a task to the thread pool with tracking"""
        if not self.is_running or not self.executor:
            raise RuntimeError("Thread pool not started")
        
        with self.task_lock:
            self.total_tasks += 1
            task_id = f"task_{self.total_tasks}"
            
            # Submit to executor
            future = self.executor.submit(func, *args, **kwargs)
            
            # Track task
            self.active_tasks.add(task_id)
            self.task_start_times[task_id] = time.time()
        
        # Wrap future for tracking
        return TaskFuture(future, task_id, self)
    
    def _task_completed(self, task_id: str, success: bool):
        """Called when a task completes"""
        with self.task_lock:
            if task_id in self.active_tasks:
                self.active_tasks.remove(task_id)
            
            if task_id in self.task_start_times:
                del self.task_start_times[task_id]
            
            if success:
                self.completed_tasks += 1
            else:
                self.failed_tasks += 1
    
    def _monitor_performance(self):
        """Monitor system and pool performance"""
        self.logger.debug("Performance monitoring started")
        
        while not self.stop_monitoring.wait(self.config.monitoring_interval):
            try:
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)
                
                # Log metrics periodically
                if len(self.metrics_history) % 5 == 0:
                    self.logger.debug(f"Performance: {metrics.throughput:.1f} proxies/s, "
                                    f"{metrics.avg_response_time:.1f}ms avg, "
                                    f"{metrics.cpu_usage:.1f}% CPU, "
                                    f"{self.current_threads} threads")
                
                # Check if scaling is needed
                if self._should_scale():
                    self._perform_scaling()
                
            except Exception as e:
                self.logger.error(f"Error in performance monitoring: {e}")
    
    def _collect_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics"""
        current_time = time.time()
        
        # Thread-safe access to task data
        with self.task_lock:
            # Calculate response time and success rate from recent tasks
            active_duration = current_time - min(self.task_start_times.values()) if self.task_start_times else 0
            active_threads = len(self.active_tasks)
            completed_tasks_snapshot = self.completed_tasks
            failed_tasks_snapshot = self.failed_tasks
        
        # System metrics with fallback for Android/Termux
        try:
            cpu_usage = psutil.cpu_percent(interval=None)
        except (OSError, PermissionError):
            # Fallback to conservative estimate on Android/Termux
            cpu_usage = 50.0  # Conservative default
        
        try:
            memory_info = psutil.virtual_memory()
            memory_usage = memory_info.used / (1024 * 1024)  # MB
        except (OSError, PermissionError):
            # Fallback memory calculation
            memory_usage = 512.0  # Conservative default MB
        
        # Pool metrics
        queue_size = getattr(self.executor, '_work_queue', None)
        queue_size = queue_size.qsize() if queue_size else 0
        
        # Calculate throughput from recent history
        throughput = 0.0
        if len(self.metrics_history) >= 2:
            recent_completed = completed_tasks_snapshot
            time_window = current_time - self.metrics_history[-1].timestamp
            if time_window > 0:
                throughput = recent_completed / time_window
        
        # Calculate error rate using snapshots
        total_finished = completed_tasks_snapshot + failed_tasks_snapshot
        error_rate = failed_tasks_snapshot / total_finished if total_finished > 0 else 0.0
        success_rate = completed_tasks_snapshot / total_finished if total_finished > 0 else 0.0
        
        return PerformanceMetrics(
            avg_response_time=active_duration * 1000,  # Convert to ms
            success_rate=success_rate,
            throughput=throughput,
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            error_rate=error_rate,
            active_threads=active_threads,
            queue_size=queue_size,
            timestamp=current_time
        )
    
    def _should_scale(self) -> bool:
        """Determine if scaling is needed based on performance metrics"""
        if len(self.metrics_history) < 2:
            return False
        
        # Check cooldown period
        current_time = time.time()
        if current_time - self.last_scaling_time < self.config.scaling_cooldown:
            return False
        
        return True
    
    def _perform_scaling(self):
        """Perform thread pool scaling based on current metrics"""
        if not self.metrics_history:
            return
        
        current_metrics = self.metrics_history[-1]
        current_time = time.time()
        
        # Calculate average metrics over recent window
        recent_metrics = list(self.metrics_history)[-min(3, len(self.metrics_history)):]
        avg_cpu = sum(m.cpu_usage for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_usage for m in recent_metrics) / len(recent_metrics)
        avg_error_rate = sum(m.error_rate for m in recent_metrics) / len(recent_metrics)
        avg_response_time = sum(m.avg_response_time for m in recent_metrics) / len(recent_metrics)
        avg_success_rate = sum(m.success_rate for m in recent_metrics) / len(recent_metrics)
        
        # Scaling decision logic
        scale_up = False
        scale_down = False
        reason = ""
        
        # Scale down conditions (prioritized - safety first)
        if avg_cpu > self.config.cpu_threshold:
            scale_down = True
            reason = f"High CPU usage: {avg_cpu:.1f}%"
        elif avg_memory > self.config.memory_threshold:
            scale_down = True
            reason = f"High memory usage: {avg_memory:.1f}MB"
        elif avg_error_rate > self.config.error_rate_threshold:
            scale_down = True
            reason = f"High error rate: {avg_error_rate:.1%}"
        
        # Scale up conditions (only if not scaling down)
        elif avg_response_time > self.config.response_time_threshold and avg_success_rate > self.config.success_rate_threshold:
            if current_metrics.queue_size > 0:  # There's work waiting
                scale_up = True
                reason = f"High response time: {avg_response_time:.1f}ms with queue: {current_metrics.queue_size}"
        elif current_metrics.queue_size > self.current_threads * 2:  # Queue is backing up
            scale_up = True
            reason = f"Large queue: {current_metrics.queue_size} items"
        
        # Perform scaling
        if scale_up and self.current_threads < self.config.max_threads:
            new_threads = min(
                int(self.current_threads * self.config.scale_factor),
                self.config.max_threads
            )
            self._scale_to(new_threads, f"Scale UP: {reason}")
        
        elif scale_down and self.current_threads > self.config.min_threads:
            new_threads = max(
                int(self.current_threads / self.config.scale_factor),
                self.config.min_threads
            )
            self._scale_to(new_threads, f"Scale DOWN: {reason}")
    
    def _scale_to(self, new_thread_count: int, reason: str):
        """Scale thread pool to specified size"""
        if new_thread_count == self.current_threads:
            return
        
        old_threads = self.current_threads
        self.current_threads = new_thread_count
        self.last_scaling_time = time.time()
        
        # Record scaling event
        scaling_event = {
            'timestamp': time.time(),
            'old_threads': old_threads,
            'new_threads': new_thread_count,
            'reason': reason
        }
        self.scaling_events.append(scaling_event)
        
        # Create new executor with updated thread count
        old_executor = self.executor
        self.executor = ThreadPoolExecutor(max_workers=new_thread_count)
        
        # Shutdown old executor gracefully with proper cleanup
        if old_executor:
            cleanup_thread = threading.Thread(
                target=self._cleanup_executor, 
                args=(old_executor,), 
                daemon=False  # Wait for cleanup
            )
            cleanup_thread.start()
            cleanup_thread.join(timeout=30)  # Ensure cleanup completes
        
        self.logger.info(f"Scaled thread pool: {old_threads} → {new_thread_count} threads. {reason}")
    
    def _cleanup_executor(self, executor):
        """Properly cleanup old executor"""
        try:
            # Use only wait=True for cross-version compatibility
            executor.shutdown(wait=True)
        except Exception as e:
            self.logger.error(f"Error during executor cleanup: {e}")
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get current performance statistics"""
        current_metrics = self.metrics_history[-1] if self.metrics_history else None
        
        with self.task_lock:
            # Thread-safe snapshot of current state
            stats = {
                'current_threads': self.current_threads,
                'total_tasks': self.total_tasks,
                'completed_tasks': self.completed_tasks,
                'failed_tasks': self.failed_tasks,
                'active_tasks': len(self.active_tasks),
                'success_rate': self.completed_tasks / max(1, self.total_tasks),
                'current_metrics': current_metrics,
                'scaling_events': len(self.scaling_events),
                'recent_scaling_events': self.scaling_events[-3:] if self.scaling_events else []
            }
        
        return stats


class TaskFuture:
    """Wrapper around Future with task tracking"""
    
    def __init__(self, future, task_id: str, manager: DynamicThreadPoolManager):
        self.future = future
        self.task_id = task_id
        self.manager = manager
    
    def result(self, timeout=None):
        """Get result and mark task as completed"""
        try:
            result = self.future.result(timeout)
            self.manager._task_completed(self.task_id, True)
            return result
        except Exception as e:
            self.manager._task_completed(self.task_id, False)
            raise
    
    def done(self):
        """Check if task is done"""
        return self.future.done()
    
    def cancel(self):
        """Cancel the task"""
        cancelled = self.future.cancel()
        if cancelled:
            self.manager._task_completed(self.task_id, False)
        return cancelled


class AdaptiveBatchValidator:
    """Enhanced batch validator using dynamic thread pool"""
    
    def __init__(self, validation_config: Optional[ValidationConfig] = None,
                 thread_config: Optional[ThreadPoolConfig] = None):
        self.validation_config = validation_config or ValidationConfig()
        self.thread_manager = DynamicThreadPoolManager(thread_config)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def validate_batch(self, proxies: List[ProxyInfo], 
                      progress_callback: Optional[Callable] = None) -> 'AdaptiveBatchResult':
        """Validate batch with adaptive threading"""
        
        if not proxies:
            return AdaptiveBatchResult(total_proxies=0, results=[])
        
        self.logger.info(f"Starting adaptive batch validation of {len(proxies)} proxies")
        
        # Start thread manager
        self.thread_manager.start()
        
        try:
            return self._execute_batch(proxies, progress_callback)
        finally:
            self.thread_manager.stop()
    
    def _execute_batch(self, proxies: List[ProxyInfo], 
                      progress_callback: Optional[Callable]) -> 'AdaptiveBatchResult':
        """Execute batch validation with dynamic threading"""
        
        from ..validation.sync_validators import SyncProxyValidator
        
        start_time = time.time()
        results = []
        completed = 0
        
        # Submit all validation tasks
        task_futures = []
        for proxy in proxies:
            validator = SyncProxyValidator(self.validation_config)
            future = self.thread_manager.submit_task(validator.validate_proxy, proxy)
            task_futures.append((future, proxy))
        
        # Process completed tasks
        for future, proxy in task_futures:
            try:
                result = future.result()
                results.append(result)
                completed += 1
                
                # Progress callback
                if progress_callback:
                    progress_callback(completed, len(proxies), result)
                
            except Exception as e:
                self.logger.error(f"Validation failed for {proxy.address}: {e}")
                # Create error result
                from ..validation.validation_results import ValidationResult
                from ..validation.validation_config import FailureReason
                
                error_result = ValidationResult(proxy=proxy)
                error_result.failure_reason = FailureReason.UNKNOWN_ERROR
                error_result.error_message = str(e)
                results.append(error_result)
                completed += 1
        
        total_time = time.time() - start_time
        
        # Create result with performance stats
        batch_result = AdaptiveBatchResult(
            total_proxies=len(proxies),
            results=results,
            total_time=total_time,
            performance_stats=self.thread_manager.get_performance_stats()
        )
        
        batch_result.calculate_statistics()
        
        # Log results
        self.logger.info(f"Adaptive validation completed: {batch_result.valid_proxies}/{len(results)} valid "
                        f"({batch_result.success_rate:.1f}%) in {total_time:.1f}s "
                        f"(avg {batch_result.performance_stats['current_threads']} threads)")
        
        return batch_result


@dataclass
class AdaptiveBatchResult:
    """Results from adaptive batch validation"""
    total_proxies: int
    results: List[ValidationResult]
    total_time: float = 0.0
    performance_stats: Optional[Dict[str, Any]] = None
    
    # Calculated statistics
    valid_proxies: int = 0
    invalid_proxies: int = 0
    success_rate: float = 0.0
    average_response_time: float = 0.0
    throughput: float = 0.0
    
    def calculate_statistics(self):
        """Calculate batch statistics"""
        self.valid_proxies = sum(1 for r in self.results if r.is_valid)
        self.invalid_proxies = len(self.results) - self.valid_proxies
        self.success_rate = (self.valid_proxies / len(self.results)) * 100 if self.results else 0.0
        
        # Calculate average response time for valid results
        valid_times = [r.response_time for r in self.results if r.response_time and r.is_valid]
        self.average_response_time = sum(valid_times) / len(valid_times) if valid_times else 0.0
        
        # Calculate throughput
        self.throughput = len(self.results) / self.total_time if self.total_time > 0 else 0.0


# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def create_adaptive_validator(validation_config: Optional[ValidationConfig] = None,
                            thread_config: Optional[ThreadPoolConfig] = None) -> AdaptiveBatchValidator:
    """Create adaptive batch validator with dynamic threading"""
    return AdaptiveBatchValidator(validation_config, thread_config)


def get_optimal_thread_config(proxy_count: int) -> ThreadPoolConfig:
    """Get optimal thread configuration based on proxy count and system resources"""
    
    # Get system info
    cpu_count = psutil.cpu_count()
    memory_gb = psutil.virtual_memory().total / (1024**3)
    
    # Calculate optimal settings based on system and workload
    if proxy_count <= 50:
        # Small batches - conservative threading
        config = ThreadPoolConfig(
            min_threads=2,
            max_threads=min(10, cpu_count * 2),
            initial_threads=5,
            scale_factor=1.5
        )
    elif proxy_count <= 500:
        # Medium batches - moderate threading
        config = ThreadPoolConfig(
            min_threads=5,
            max_threads=min(50, cpu_count * 4),
            initial_threads=15,
            scale_factor=1.3
        )
    else:
        # Large batches - aggressive threading
        config = ThreadPoolConfig(
            min_threads=10,
            max_threads=min(100, cpu_count * 6),
            initial_threads=25,
            scale_factor=1.2
        )
    
    # Adjust based on available memory
    if memory_gb < 4:
        # Low memory - reduce thread counts
        config.max_threads = min(config.max_threads, 20)
        config.initial_threads = min(config.initial_threads, 10)
    elif memory_gb > 16:
        # High memory - allow more threads
        config.max_threads = min(config.max_threads * 2, 200)
    
    return config