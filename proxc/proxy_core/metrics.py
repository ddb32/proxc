"""Proxy Core Metrics - Performance and Health Monitoring"""

import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

# Optional Prometheus support
try:
    from prometheus_client import Counter, Histogram, Gauge, start_http_server, CollectorRegistry
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False

# Import our models (using exact names from previous files)
from .models import ProxyInfo, ProxyStatus, ThreatLevel, AnonymityLevel, ValidationStatus


# ===============================================================================
# METRICS DATA CLASSES
# ===============================================================================

class MetricType(Enum):
    """Types of metrics we collect"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class MetricData:
    """Individual metric data point"""
    name: str
    value: Union[int, float]
    metric_type: MetricType
    timestamp: datetime = field(default_factory=datetime.utcnow)
    labels: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'value': self.value,
            'type': self.metric_type.value,
            'timestamp': self.timestamp.isoformat(),
            'labels': self.labels
        }


@dataclass
class SystemHealth:
    """System health status"""
    total_proxies: int = 0
    active_proxies: int = 0
    valid_proxies: int = 0
    failed_proxies: int = 0
    avg_response_time: float = 0.0
    success_rate: float = 0.0
    last_updated: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ===============================================================================
# MAIN METRICS COLLECTOR
# ===============================================================================

class MetricsCollector:
    """Simple and efficient metrics collection system"""
    
    def __init__(self, enable_prometheus: bool = False, prometheus_port: int = 8000):
        self.enable_prometheus = enable_prometheus and HAS_PROMETHEUS
        self.prometheus_port = prometheus_port
        self.logger = logging.getLogger(__name__)
        
        # Internal storage
        self._metrics = defaultdict(list)
        self._counters = defaultdict(int)
        self._gauges = defaultdict(float)
        self._histograms = defaultdict(list)
        self._timers = defaultdict(deque)
        self._lock = threading.Lock()
        
        # Prometheus metrics (if enabled)
        self._prometheus_registry = None
        self._prometheus_metrics = {}
        
        # Initialize Prometheus if requested
        if self.enable_prometheus:
            self._init_prometheus()
        
        # Log initialization
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f"MetricsCollector initialized (Prometheus: {self.enable_prometheus})")
    
    def _init_prometheus(self):
        """Initialize Prometheus metrics"""
        if not HAS_PROMETHEUS:
            self.logger.warning("Prometheus requested but not available")
            return
        
        try:
            self._prometheus_registry = CollectorRegistry()
            
            # Define Prometheus metrics
            self._prometheus_metrics = {
                'proxies_total': Counter(
                    'proxies_total', 'Total number of proxies discovered',
                    ['source'], registry=self._prometheus_registry
                ),
                'proxies_valid': Gauge(
                    'proxies_valid', 'Number of valid proxies',
                    ['protocol', 'anonymity'], registry=self._prometheus_registry
                ),
                'validation_duration': Histogram(
                    'validation_duration_seconds', 'Proxy validation duration',
                    registry=self._prometheus_registry
                ),
                'proxy_response_time': Histogram(
                    'proxy_response_time_ms', 'Proxy response time in milliseconds',
                    ['protocol'], registry=self._prometheus_registry
                ),
                'validation_success_rate': Gauge(
                    'validation_success_rate', 'Proxy validation success rate',
                    registry=self._prometheus_registry
                )
            }
            
            # Start Prometheus HTTP server
            start_http_server(self.prometheus_port, registry=self._prometheus_registry)
            self.logger.info(f"Prometheus metrics server started on port {self.prometheus_port}")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Prometheus: {e}")
            self.enable_prometheus = False
    
    def increment_counter(self, name: str, value: int = 1, labels: Optional[Dict[str, str]] = None):
        """Increment a counter metric"""
        with self._lock:
            self._counters[name] += value
            
            # Store metric data
            metric = MetricData(name, value, MetricType.COUNTER, labels=labels or {})
            self._metrics[name].append(metric)
            
            # Update Prometheus if enabled
            if self.enable_prometheus and name in self._prometheus_metrics:
                try:
                    if labels:
                        self._prometheus_metrics[name].labels(**labels).inc(value)
                    else:
                        self._prometheus_metrics[name].inc(value)
                except Exception as e:
                    self.logger.debug(f"Prometheus update failed: {e}")
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Set a gauge metric"""
        with self._lock:
            self._gauges[name] = value
            
            # Store metric data
            metric = MetricData(name, value, MetricType.GAUGE, labels=labels or {})
            self._metrics[name].append(metric)
            
            # Update Prometheus if enabled
            if self.enable_prometheus and name in self._prometheus_metrics:
                try:
                    if labels:
                        self._prometheus_metrics[name].labels(**labels).set(value)
                    else:
                        self._prometheus_metrics[name].set(value)
                except Exception as e:
                    self.logger.debug(f"Prometheus update failed: {e}")
    
    def record_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Record a histogram metric"""
        with self._lock:
            self._histograms[name].append(value)
            
            # Keep only last 1000 values for memory efficiency
            if len(self._histograms[name]) > 1000:
                self._histograms[name] = self._histograms[name][-1000:]
            
            # Store metric data
            metric = MetricData(name, value, MetricType.HISTOGRAM, labels=labels or {})
            self._metrics[name].append(metric)
            
            # Update Prometheus if enabled
            if self.enable_prometheus and name in self._prometheus_metrics:
                try:
                    if labels:
                        self._prometheus_metrics[name].labels(**labels).observe(value)
                    else:
                        self._prometheus_metrics[name].observe(value)
                except Exception as e:
                    self.logger.debug(f"Prometheus update failed: {e}")
    
    def record_timer(self, name: str, duration: float, labels: Optional[Dict[str, str]] = None):
        """Record a timer metric (duration in seconds)"""
        with self._lock:
            self._timers[name].append((time.time(), duration))
            
            # Keep only last hour of timer data
            cutoff_time = time.time() - 3600
            while self._timers[name] and self._timers[name][0][0] < cutoff_time:
                self._timers[name].popleft()
            
            # Store metric data
            metric = MetricData(name, duration, MetricType.TIMER, labels=labels or {})
            self._metrics[name].append(metric)
    
    # Convenient methods for proxy-specific metrics
    def record_proxy_discovered(self, source: str, count: int = 1):
        """Record proxy discovery"""
        self.increment_counter('proxies_discovered', count, {'source': source})
    
    def record_proxy_validated(self, proxy: ProxyInfo, is_valid: bool, response_time: Optional[float] = None):
        """Record proxy validation result"""
        # Validation counter
        status = 'valid' if is_valid else 'invalid'
        self.increment_counter('proxies_validated', 1, {'status': status})
        
        # Response time histogram
        if response_time is not None:
            self.record_histogram('proxy_response_time', response_time, 
                                {'protocol': proxy.protocol.value})
        
        # Update Prometheus gauge for valid proxies
        if self.enable_prometheus and is_valid:
            labels = {
                'protocol': proxy.protocol.value,
                'anonymity': proxy.anonymity_level.value
            }
            self.set_gauge('proxies_valid', 1, labels)
    
    def record_validation_duration(self, duration: float):
        """Record validation operation duration"""
        self.record_histogram('validation_duration', duration)
    
    def record_export_operation(self, format_type: str, proxy_count: int):
        """Record export operation"""
        self.increment_counter('exports_total', 1, {'format': format_type})
        self.record_histogram('export_proxy_count', proxy_count, {'format': format_type})
    
    def record_security_threat(self, threat_level: ThreatLevel, proxy_host: str):
        """Record security threat detection"""
        self.increment_counter('security_threats', 1, {'level': threat_level.value})
        self.logger.warning(f"Security threat detected: {threat_level.value} for {proxy_host}")
    
    def get_counter(self, name: str) -> int:
        """Get current counter value"""
        return self._counters.get(name, 0)
    
    def get_gauge(self, name: str) -> float:
        """Get current gauge value"""
        return self._gauges.get(name, 0.0)
    
    def get_histogram_stats(self, name: str) -> Dict[str, float]:
        """Get histogram statistics"""
        values = self._histograms.get(name, [])
        if not values:
            return {'count': 0, 'avg': 0.0, 'min': 0.0, 'max': 0.0}
        
        return {
            'count': len(values),
            'avg': sum(values) / len(values),
            'min': min(values),
            'max': max(values)
        }
    
    def get_timer_stats(self, name: str) -> Dict[str, float]:
        """Get timer statistics for the last hour"""
        current_time = time.time()
        recent_timers = [duration for timestamp, duration in self._timers.get(name, [])
                        if current_time - timestamp < 3600]
        
        if not recent_timers:
            return {'count': 0, 'avg': 0.0, 'min': 0.0, 'max': 0.0}
        
        return {
            'count': len(recent_timers),
            'avg': sum(recent_timers) / len(recent_timers),
            'min': min(recent_timers),
            'max': max(recent_timers)
        }
    
    def get_system_health(self, proxies: List[ProxyInfo]) -> SystemHealth:
        """Generate system health summary"""
        if not proxies:
            return SystemHealth()
        
        total = len(proxies)
        active = sum(1 for p in proxies if p.status == ProxyStatus.ACTIVE)
        valid = sum(1 for p in proxies if p.validation_status == ValidationStatus.VALID)
        failed = sum(1 for p in proxies if p.status == ProxyStatus.FAILED)
        
        # Calculate average response time
        response_times = [p.metrics.response_time for p in proxies 
                         if p.metrics.response_time is not None]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0.0
        
        # Calculate success rate
        success_rate = (valid / total * 100) if total > 0 else 0.0
        
        health = SystemHealth(
            total_proxies=total,
            active_proxies=active,
            valid_proxies=valid,
            failed_proxies=failed,
            avg_response_time=avg_response_time,
            success_rate=success_rate
        )
        
        # Update gauge metrics
        self.set_gauge('system_total_proxies', total)
        self.set_gauge('system_active_proxies', active)
        self.set_gauge('system_success_rate', success_rate)
        
        return health
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all collected metrics"""
        with self._lock:
            return {
                'counters': dict(self._counters),
                'gauges': dict(self._gauges),
                'histograms': {name: self.get_histogram_stats(name) for name in self._histograms},
                'timers': {name: self.get_timer_stats(name) for name in self._timers},
                'collection_time': datetime.utcnow().isoformat()
            }
    
    def export_metrics(self, file_path: str, format_type: str = 'json'):
        """Export metrics to file"""
        try:
            metrics_data = self.get_all_metrics()
            
            if format_type.lower() == 'json':
                with open(file_path, 'w') as f:
                    json.dump(metrics_data, f, indent=2, default=str)
            else:
                raise ValueError(f"Unsupported export format: {format_type}")
            
            self.logger.info(f"Metrics exported to {file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to export metrics: {e}")
            raise
    
    def cleanup_old_metrics(self, hours: int = 24):
        """Clean up metrics older than specified hours"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        with self._lock:
            for metric_name in list(self._metrics.keys()):
                self._metrics[metric_name] = [
                    metric for metric in self._metrics[metric_name]
                    if metric.timestamp > cutoff_time
                ]
                
                # Remove empty metric lists
                if not self._metrics[metric_name]:
                    del self._metrics[metric_name]
        
        self.logger.info(f"Cleaned up metrics older than {hours} hours")
    
    def reset_metrics(self):
        """Reset all metrics (use with caution)"""
        with self._lock:
            self._metrics.clear()
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()
            self._timers.clear()
        
        self.logger.warning("All metrics have been reset")


# ===============================================================================
# PERFORMANCE MONITOR
# ===============================================================================

class PerformanceMonitor:
    """Monitor performance of proxy operations"""
    
    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics = metrics_collector
        self.logger = logging.getLogger(__name__)
    
    def monitor_validation_batch(self, proxies: List[ProxyInfo], 
                               validation_results: Dict[str, List[ProxyInfo]]) -> Dict[str, Any]:
        """Monitor validation batch performance"""
        total_proxies = len(proxies)
        valid_count = len(validation_results.get('valid', []))
        invalid_count = len(validation_results.get('invalid', []))
        error_count = len(validation_results.get('errors', []))
        
        # Calculate rates
        success_rate = (valid_count / total_proxies * 100) if total_proxies > 0 else 0
        error_rate = (error_count / total_proxies * 100) if total_proxies > 0 else 0
        
        # Record metrics
        self.metrics.increment_counter('validation_batches', 1)
        self.metrics.record_histogram('batch_size', total_proxies)
        self.metrics.set_gauge('batch_success_rate', success_rate)
        self.metrics.set_gauge('batch_error_rate', error_rate)
        
        performance_data = {
            'total_proxies': total_proxies,
            'valid_proxies': valid_count,
            'invalid_proxies': invalid_count,
            'error_proxies': error_count,
            'success_rate': success_rate,
            'error_rate': error_rate,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.info(f"Validation batch completed: {valid_count}/{total_proxies} valid ({success_rate:.1f}%)")
        
        return performance_data
    
    def monitor_source_performance(self, source: str, fetched_count: int, 
                                 valid_count: int, fetch_duration: float) -> Dict[str, Any]:
        """Monitor proxy source performance"""
        success_rate = (valid_count / fetched_count * 100) if fetched_count > 0 else 0
        
        # Record metrics
        self.metrics.record_proxy_discovered(source, fetched_count)
        self.metrics.record_timer(f'source_fetch_duration_{source}', fetch_duration)
        self.metrics.set_gauge(f'source_success_rate_{source}', success_rate)
        
        performance_data = {
            'source': source,
            'fetched_count': fetched_count,
            'valid_count': valid_count,
            'success_rate': success_rate,
            'fetch_duration': fetch_duration,
            'proxies_per_second': fetched_count / fetch_duration if fetch_duration > 0 else 0,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.info(f"Source {source}: {fetched_count} fetched, {valid_count} valid ({success_rate:.1f}%)")
        
        return performance_data


# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def create_metrics_collector(enable_prometheus: bool = False, 
                           prometheus_port: int = 8000) -> MetricsCollector:
    """Create metrics collector with specified configuration"""
    return MetricsCollector(enable_prometheus=enable_prometheus, prometheus_port=prometheus_port)


def create_performance_monitor(metrics_collector: MetricsCollector) -> PerformanceMonitor:
    """Create performance monitor"""
    return PerformanceMonitor(metrics_collector)


def timer_decorator(metrics_collector: MetricsCollector, metric_name: str):
    """Decorator to automatically time function execution"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                metrics_collector.record_timer(metric_name, duration)
                return result
            except Exception as e:
                duration = time.time() - start_time
                metrics_collector.record_timer(f"{metric_name}_failed", duration)
                raise
        return wrapper
    return decorator