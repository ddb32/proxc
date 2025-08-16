"""Professional Performance Monitor - Real-time scanning performance optimization"""

import asyncio
import logging
import psutil
import threading
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from concurrent.futures import ThreadPoolExecutor


@dataclass
class PerformanceMetrics:
    """Real-time performance metrics"""
    timestamp: float
    proxies_per_second: float
    concurrent_tasks: int
    success_rate: float
    avg_response_time: float
    cpu_usage: float
    memory_usage: float
    network_io: Dict[str, float]
    connection_pool_usage: float
    queue_depth: int


@dataclass
class SystemResources:
    """Current system resource utilization"""
    cpu_percent: float
    memory_percent: float
    memory_available_gb: float
    network_connections: int
    active_threads: int
    file_descriptors: int


class PerformanceMonitor:
    """Professional-grade performance monitoring and optimization"""
    
    def __init__(self, optimization_callback: Optional[Callable] = None):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.optimization_callback = optimization_callback
        
        # Performance tracking
        self.metrics_history: deque = deque(maxlen=1000)
        self.resource_history: deque = deque(maxlen=500)
        
        # Real-time counters
        self.total_proxies_processed = 0
        self.total_successful = 0
        self.total_failed = 0
        self.start_time = time.time()
        self.last_reset_time = time.time()
        
        # Performance windows for calculations
        self.response_times: deque = deque(maxlen=1000)
        self.throughput_samples: deque = deque(maxlen=100)
        
        # Monitoring state
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.monitor_interval = 1.0  # Sample every second
        
        # Optimization thresholds
        self.thresholds = {
            'cpu_high': 85.0,
            'cpu_critical': 95.0,
            'memory_high': 85.0,
            'memory_critical': 95.0,
            'success_rate_low': 30.0,
            'response_time_high': 10000.0,  # 10 seconds
            'throughput_low': 10.0  # proxies per second
        }
        
        # Performance recommendations
        self.current_recommendations: List[str] = []
        
        self.logger.info("Professional performance monitor initialized")
    
    def start_monitoring(self):
        """Start background performance monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.start_time = time.time()
        self.last_reset_time = time.time()
        
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            name="PerformanceMonitor",
            daemon=True
        )
        self.monitor_thread.start()
        
        self.logger.info("Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2.0)
        
        self.logger.info("Performance monitoring stopped")
    
    def record_proxy_result(self, success: bool, response_time: float):
        """Record individual proxy validation result"""
        self.total_proxies_processed += 1
        
        if success:
            self.total_successful += 1
        else:
            self.total_failed += 1
        
        if response_time > 0:
            self.response_times.append(response_time)
    
    def record_batch_completion(self, batch_size: int, success_count: int, 
                              duration: float, concurrent_tasks: int):
        """Record batch completion for throughput calculation"""
        if duration > 0:
            throughput = batch_size / duration
            self.throughput_samples.append(throughput)
    
    def _monitoring_loop(self):
        """Main monitoring loop with performance optimization"""
        self.logger.debug("Performance monitoring loop started")
        
        while self.monitoring_active:
            try:
                # Collect current metrics
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)
                
                # Collect system resources
                resources = self._collect_system_resources()
                self.resource_history.append(resources)
                
                # Analyze performance and generate recommendations
                self._analyze_performance(metrics, resources)
                
                # Apply optimizations if callback is provided
                if self.optimization_callback:
                    self._apply_optimizations(metrics, resources)
                
                # Sleep until next monitoring cycle
                time.sleep(self.monitor_interval)
                
            except Exception as e:
                self.logger.error(f"Performance monitoring error: {e}")
                time.sleep(self.monitor_interval * 2)  # Back off on error
        
        self.logger.debug("Performance monitoring loop stopped")
    
    def _collect_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics"""
        current_time = time.time()
        elapsed_time = current_time - self.last_reset_time
        
        # Calculate proxies per second
        proxies_per_second = self.total_proxies_processed / elapsed_time if elapsed_time > 0 else 0.0
        
        # Calculate success rate
        total_processed = self.total_successful + self.total_failed
        success_rate = (self.total_successful / total_processed * 100) if total_processed > 0 else 0.0
        
        # Calculate average response time
        avg_response_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0.0
        
        # Get system metrics with Android/Termux compatibility
        try:
            cpu_usage = psutil.cpu_percent(interval=None)
        except (OSError, PermissionError):
            cpu_usage = 50.0  # Conservative fallback for Android/Termux
        
        try:
            memory = psutil.virtual_memory()
            memory_usage = memory.percent
        except (OSError, PermissionError):
            memory_usage = 60.0  # Conservative fallback
        
        # Network I/O
        try:
            net_io = psutil.net_io_counters()
            network_io = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
        except:
            network_io = {}
        
        return PerformanceMetrics(
            timestamp=current_time,
            proxies_per_second=proxies_per_second,
            concurrent_tasks=threading.active_count(),
            success_rate=success_rate,
            avg_response_time=avg_response_time,
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            network_io=network_io,
            connection_pool_usage=0.0,  # Would need aiohttp session info
            queue_depth=0  # Would need queue info
        )
    
    def _collect_system_resources(self) -> SystemResources:
        """Collect system resource information"""
        memory = psutil.virtual_memory()
        
        try:
            connections = len(psutil.net_connections())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            connections = 0
        
        try:
            # Get file descriptor count (Unix-like systems)
            import resource
            fd_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            # Approximate current usage
            fd_usage = len(psutil.Process().open_files()) + len(psutil.net_connections())
        except:
            fd_usage = 0
        
        # System metrics with Android/Termux compatibility
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
        except (OSError, PermissionError):
            cpu_percent = 50.0  # Conservative fallback
        
        return SystemResources(
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            memory_available_gb=memory.available / (1024**3),
            network_connections=connections,
            active_threads=threading.active_count(),
            file_descriptors=fd_usage
        )
    
    def _analyze_performance(self, metrics: PerformanceMetrics, resources: SystemResources):
        """Analyze performance and generate recommendations"""
        recommendations = []
        
        # CPU Analysis
        if resources.cpu_percent > self.thresholds['cpu_critical']:
            recommendations.append("CRITICAL: Reduce concurrency - CPU usage critical")
        elif resources.cpu_percent > self.thresholds['cpu_high']:
            recommendations.append("WARNING: High CPU usage - consider reducing concurrency")
        
        # Memory Analysis
        if resources.memory_percent > self.thresholds['memory_critical']:
            recommendations.append("CRITICAL: Reduce batch size - Memory usage critical")
        elif resources.memory_percent > self.thresholds['memory_high']:
            recommendations.append("WARNING: High memory usage - monitor batch sizes")
        
        # Success Rate Analysis
        if metrics.success_rate < self.thresholds['success_rate_low']:
            recommendations.append("LOW: Success rate below 30% - check proxy sources")
        
        # Response Time Analysis
        if metrics.avg_response_time > self.thresholds['response_time_high']:
            recommendations.append("SLOW: Average response time > 10s - reduce timeouts")
        
        # Throughput Analysis
        if metrics.proxies_per_second < self.thresholds['throughput_low']:
            recommendations.append("SLOW: Low throughput - increase concurrency if resources allow")
        
        # Network Analysis
        if resources.network_connections > 1000:
            recommendations.append("NETWORK: High connection count - check connection pooling")
        
        self.current_recommendations = recommendations
        
        # Log significant performance issues
        if recommendations:
            for rec in recommendations:
                if rec.startswith("CRITICAL"):
                    self.logger.error(f"Performance: {rec}")
                elif rec.startswith("WARNING"):
                    self.logger.warning(f"Performance: {rec}")
                else:
                    self.logger.info(f"Performance: {rec}")
    
    def _apply_optimizations(self, metrics: PerformanceMetrics, resources: SystemResources):
        """Apply automatic performance optimizations"""
        optimization_suggestions = {}
        
        # CPU-based optimizations
        if resources.cpu_percent > self.thresholds['cpu_critical']:
            optimization_suggestions['reduce_concurrency'] = 0.5  # Reduce by 50%
        elif resources.cpu_percent > self.thresholds['cpu_high']:
            optimization_suggestions['reduce_concurrency'] = 0.8  # Reduce by 20%
        elif resources.cpu_percent < 50 and metrics.proxies_per_second > 0:
            optimization_suggestions['increase_concurrency'] = 1.2  # Increase by 20%
        
        # Memory-based optimizations
        if resources.memory_percent > self.thresholds['memory_critical']:
            optimization_suggestions['reduce_batch_size'] = 0.5
        elif resources.memory_percent > self.thresholds['memory_high']:
            optimization_suggestions['reduce_batch_size'] = 0.8
        
        # Timeout optimizations
        if metrics.avg_response_time > self.thresholds['response_time_high']:
            optimization_suggestions['reduce_timeouts'] = 0.8
        
        # Apply optimizations through callback
        if optimization_suggestions:
            self.optimization_callback(optimization_suggestions)
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        current_time = time.time()
        total_elapsed = current_time - self.start_time
        
        # Calculate overall statistics
        total_processed = self.total_successful + self.total_failed
        overall_success_rate = (self.total_successful / total_processed * 100) if total_processed > 0 else 0.0
        overall_throughput = total_processed / total_elapsed if total_elapsed > 0 else 0.0
        
        # Get current metrics
        current_metrics = self.metrics_history[-1] if self.metrics_history else None
        current_resources = self.resource_history[-1] if self.resource_history else None
        
        # Calculate trends
        recent_throughput = [m.proxies_per_second for m in list(self.metrics_history)[-10:]]
        avg_recent_throughput = sum(recent_throughput) / len(recent_throughput) if recent_throughput else 0.0
        
        recent_success_rates = [m.success_rate for m in list(self.metrics_history)[-10:]]
        avg_recent_success_rate = sum(recent_success_rates) / len(recent_success_rates) if recent_success_rates else 0.0
        
        return {
            'summary': {
                'total_processed': total_processed,
                'total_successful': self.total_successful,
                'total_failed': self.total_failed,
                'overall_success_rate': overall_success_rate,
                'overall_throughput': overall_throughput,
                'total_elapsed_time': total_elapsed
            },
            'current_performance': {
                'proxies_per_second': current_metrics.proxies_per_second if current_metrics else 0.0,
                'success_rate': current_metrics.success_rate if current_metrics else 0.0,
                'avg_response_time': current_metrics.avg_response_time if current_metrics else 0.0,
                'concurrent_tasks': current_metrics.concurrent_tasks if current_metrics else 0
            },
            'system_resources': {
                'cpu_percent': current_resources.cpu_percent if current_resources else 0.0,
                'memory_percent': current_resources.memory_percent if current_resources else 0.0,
                'memory_available_gb': current_resources.memory_available_gb if current_resources else 0.0,
                'network_connections': current_resources.network_connections if current_resources else 0,
                'active_threads': current_resources.active_threads if current_resources else 0
            },
            'trends': {
                'avg_recent_throughput': avg_recent_throughput,
                'avg_recent_success_rate': avg_recent_success_rate,
                'throughput_trend': 'improving' if len(recent_throughput) >= 2 and recent_throughput[-1] > recent_throughput[0] else 'declining'
            },
            'recommendations': self.current_recommendations,
            'optimization_status': len(self.current_recommendations) == 0
        }
    
    def reset_counters(self):
        """Reset performance counters for new measurement period"""
        self.total_proxies_processed = 0
        self.total_successful = 0
        self.total_failed = 0
        self.last_reset_time = time.time()
        self.response_times.clear()
        self.throughput_samples.clear()
        
        self.logger.info("Performance counters reset")


class AdaptiveOptimizer:
    """Adaptive performance optimizer that adjusts settings in real-time"""
    
    def __init__(self, initial_config: Dict[str, Any]):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.current_config = initial_config.copy()
        self.optimization_history: List[Dict[str, Any]] = []
        
        # Performance targets
        self.target_cpu_usage = 75.0  # Target CPU usage percentage
        self.target_success_rate = 80.0  # Target success rate percentage
        self.target_throughput = 50.0  # Target proxies per second
        
        self.logger.info("Adaptive optimizer initialized")
    
    def apply_optimizations(self, suggestions: Dict[str, float]):
        """Apply optimization suggestions and track results"""
        old_config = self.current_config.copy()
        changes_made = []
        
        # Apply concurrency changes
        if 'reduce_concurrency' in suggestions:
            factor = suggestions['reduce_concurrency']
            self.current_config['max_concurrent'] = int(
                self.current_config.get('max_concurrent', 100) * factor
            )
            changes_made.append(f"Reduced concurrency by {(1-factor)*100:.0f}%")
        
        elif 'increase_concurrency' in suggestions:
            factor = suggestions['increase_concurrency']
            self.current_config['max_concurrent'] = min(
                int(self.current_config.get('max_concurrent', 100) * factor),
                500  # Cap at reasonable maximum
            )
            changes_made.append(f"Increased concurrency by {(factor-1)*100:.0f}%")
        
        # Apply batch size changes
        if 'reduce_batch_size' in suggestions:
            factor = suggestions['reduce_batch_size']
            self.current_config['batch_size'] = max(
                int(self.current_config.get('batch_size', 100) * factor),
                10  # Minimum batch size
            )
            changes_made.append(f"Reduced batch size by {(1-factor)*100:.0f}%")
        
        # Apply timeout changes
        if 'reduce_timeouts' in suggestions:
            factor = suggestions['reduce_timeouts']
            self.current_config['timeout'] = max(
                self.current_config.get('timeout', 10.0) * factor,
                2.0  # Minimum timeout
            )
            changes_made.append(f"Reduced timeouts by {(1-factor)*100:.0f}%")
        
        # Record optimization
        if changes_made:
            optimization_record = {
                'timestamp': time.time(),
                'old_config': old_config,
                'new_config': self.current_config.copy(),
                'changes': changes_made,
                'suggestions': suggestions
            }
            self.optimization_history.append(optimization_record)
            
            self.logger.info(f"Applied optimizations: {', '.join(changes_made)}")
            
            return self.current_config
        
        return None
    
    def get_current_config(self) -> Dict[str, Any]:
        """Get current optimized configuration"""
        return self.current_config.copy()
    
    def get_optimization_history(self) -> List[Dict[str, Any]]:
        """Get history of applied optimizations"""
        return self.optimization_history.copy()


def create_performance_monitor(optimization_enabled: bool = True) -> PerformanceMonitor:
    """Create performance monitor with optional adaptive optimization"""
    
    def optimization_callback(suggestions: Dict[str, float]):
        """Default optimization callback"""
        # This would be connected to the actual validation system
        pass
    
    if optimization_enabled:
        return PerformanceMonitor(optimization_callback)
    else:
        return PerformanceMonitor()