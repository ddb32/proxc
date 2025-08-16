"""
Queue Monitor for Proxy Hunter Task Queue
==========================================

Provides comprehensive monitoring, health checks, and performance analysis
for the task queue system with real-time metrics and alerting.
"""

import asyncio
import logging
import time
import threading
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

@dataclass
class QueueHealth:
    """Queue health status"""
    healthy: bool
    issues: List[str] = field(default_factory=list)
    score: float = 1.0  # 0.0 to 1.0
    last_check: datetime = field(default_factory=datetime.utcnow)

@dataclass
class PerformanceMetric:
    """Performance metric data point"""
    timestamp: datetime
    metric_name: str
    value: float
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass 
class Alert:
    """Queue monitoring alert"""
    alert_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    message: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    resolved: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

class QueueMonitor:
    """Comprehensive queue monitoring and health system"""
    
    def __init__(self, redis_backend, monitoring_interval: float = 30.0):
        """Initialize queue monitor
        
        Args:
            redis_backend: Redis backend instance
            monitoring_interval: Monitoring check interval in seconds
        """
        self.redis_backend = redis_backend
        self.monitoring_interval = monitoring_interval
        
        # Monitoring state
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        # Health tracking
        self.queue_health: Dict[str, QueueHealth] = {}
        self.health_history: deque = deque(maxlen=1000)  # Keep last 1000 health checks
        
        # Performance tracking
        self.performance_metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.metric_thresholds = {
            'queue_length': 1000,      # Alert if queue length exceeds this
            'processing_rate': 10,     # Alert if processing rate drops below this (tasks/min)
            'error_rate': 0.1,         # Alert if error rate exceeds this (0.0-1.0)
            'average_task_time': 300,  # Alert if average task time exceeds this (seconds)
            'memory_usage': 0.8        # Alert if Redis memory usage exceeds this ratio
        }
        
        # Alerting
        self.active_alerts: List[Alert] = []
        self.alert_callbacks: List[Callable[[Alert], None]] = []
        self.alert_history: deque = deque(maxlen=500)
        
        # Statistics
        self.monitoring_stats = {
            'checks_performed': 0,
            'alerts_triggered': 0,
            'health_issues_detected': 0,
            'performance_anomalies': 0
        }
        
        logger.info(f"Queue monitor initialized with {monitoring_interval}s interval")
    
    def start_monitoring(self):
        """Start background monitoring"""
        if self.monitoring_active:
            logger.warning("Monitoring already active")
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            name="QueueMonitor",
            daemon=True
        )
        self.monitor_thread.start()
        
        logger.info("Queue monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)
        
        logger.info("Queue monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        logger.debug("Monitoring loop started")
        
        while self.monitoring_active:
            try:
                start_time = time.time()
                
                # Perform health checks
                self._perform_health_check()
                
                # Collect performance metrics
                self._collect_performance_metrics()
                
                # Analyze metrics and trigger alerts
                self._analyze_metrics()
                
                # Update statistics
                self.monitoring_stats['checks_performed'] += 1
                
                # Calculate sleep time to maintain interval
                check_duration = time.time() - start_time
                sleep_time = max(0, self.monitoring_interval - check_duration)
                
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                time.sleep(self.monitoring_interval * 2)  # Back off on error
        
        logger.debug("Monitoring loop stopped")
    
    def _perform_health_check(self):
        """Perform comprehensive health check"""
        overall_health = QueueHealth(healthy=True)
        
        try:
            # Check Redis connectivity
            if not self.redis_backend.is_healthy():
                overall_health.healthy = False
                overall_health.issues.append("Redis connection unhealthy")
                overall_health.score -= 0.5
            
            # Check individual queues
            queue_patterns = self.redis_backend.redis_client.keys("proxc:queue:*")
            unique_queues = set()
            
            for pattern in queue_patterns:
                # Extract queue name from key
                parts = pattern.split(':')
                if len(parts) >= 3:
                    queue_name = parts[2]
                    unique_queues.add(queue_name)
            
            for queue_name in unique_queues:
                queue_health = self._check_queue_health(queue_name)
                self.queue_health[queue_name] = queue_health
                
                if not queue_health.healthy:
                    overall_health.healthy = False
                    overall_health.issues.extend([
                        f"Queue {queue_name}: {issue}" for issue in queue_health.issues
                    ])
                    overall_health.score *= queue_health.score
            
            # Check system resources
            self._check_system_resources(overall_health)
            
            # Update health history
            self.health_history.append(overall_health)
            
            if not overall_health.healthy:
                self.monitoring_stats['health_issues_detected'] += 1
                logger.warning(f"Health check failed: {', '.join(overall_health.issues)}")
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            overall_health.healthy = False
            overall_health.issues.append(f"Health check error: {str(e)}")
    
    def _check_queue_health(self, queue_name: str) -> QueueHealth:
        """Check health of a specific queue"""
        health = QueueHealth(healthy=True)
        
        try:
            stats = self.redis_backend.get_queue_stats(queue_name)
            
            # Check queue length
            total_pending = stats.get('total_pending', 0)
            if total_pending > self.metric_thresholds['queue_length']:
                health.healthy = False
                health.issues.append(f"Queue length too high: {total_pending}")
                health.score -= 0.3
            
            # Check error rate
            total_processed = stats.get('total_dequeued', 0)
            total_failed = stats.get('total_failed', 0)
            
            if total_processed > 0:
                error_rate = total_failed / total_processed
                if error_rate > self.metric_thresholds['error_rate']:
                    health.healthy = False
                    health.issues.append(f"Error rate too high: {error_rate:.2%}")
                    health.score -= 0.2
            
            # Check for stalled processing
            failed_in_queue = stats.get('failed_in_queue', 0)
            if failed_in_queue > 50:  # Too many failed tasks queued
                health.healthy = False
                health.issues.append(f"Too many failed tasks: {failed_in_queue}")
                health.score -= 0.1
            
        except Exception as e:
            logger.error(f"Queue health check failed for {queue_name}: {e}")
            health.healthy = False
            health.issues.append(f"Health check error: {str(e)}")
            health.score = 0.0
        
        return health
    
    def _check_system_resources(self, overall_health: QueueHealth):
        """Check system resource health"""
        try:
            # Check Redis memory usage
            redis_info = self.redis_backend.redis_client.info('memory')
            used_memory = redis_info.get('used_memory', 0)
            max_memory = redis_info.get('maxmemory', 0)
            
            if max_memory > 0:
                memory_ratio = used_memory / max_memory
                if memory_ratio > self.metric_thresholds['memory_usage']:
                    overall_health.healthy = False
                    overall_health.issues.append(f"Redis memory usage high: {memory_ratio:.1%}")
                    overall_health.score -= 0.2
            
            # Check Redis connection stats
            clients_connected = redis_info.get('connected_clients', 0)
            if clients_connected > 100:  # Too many connections
                overall_health.issues.append(f"High Redis connection count: {clients_connected}")
                overall_health.score -= 0.1
                
        except Exception as e:
            logger.debug(f"Resource check failed: {e}")
    
    def _collect_performance_metrics(self):
        """Collect comprehensive performance metrics"""
        timestamp = datetime.utcnow()
        
        try:
            # Collect queue metrics for each queue
            queue_patterns = self.redis_backend.redis_client.keys("proxc:stats:*")
            
            for stats_key in queue_patterns:
                try:
                    queue_name = stats_key.split(':')[-1]
                    stats = self.redis_backend.get_queue_stats(queue_name)
                    
                    # Queue length metrics
                    total_pending = stats.get('total_pending', 0)
                    self._record_metric(f"queue_length_{queue_name}", total_pending, timestamp)
                    
                    # Processing rate metrics
                    total_completed = stats.get('total_completed', 0)
                    total_failed = stats.get('total_failed', 0)
                    total_processed = total_completed + total_failed
                    
                    # Calculate processing rate (tasks per minute)
                    if hasattr(self, '_last_metrics_check'):
                        time_delta = (timestamp - self._last_metrics_check).total_seconds() / 60.0
                        if time_delta > 0:
                            last_processed = getattr(self, f'_last_processed_{queue_name}', 0)
                            processing_rate = (total_processed - last_processed) / time_delta
                            self._record_metric(f"processing_rate_{queue_name}", processing_rate, timestamp)
                    
                    setattr(self, f'_last_processed_{queue_name}', total_processed)
                    
                    # Error rate metrics
                    if total_processed > 0:
                        error_rate = total_failed / total_processed
                        self._record_metric(f"error_rate_{queue_name}", error_rate, timestamp)
                    
                    # Priority distribution metrics
                    for priority in [1, 2, 3]:
                        priority_pending = stats.get(f'priority_{priority}_pending', 0)
                        self._record_metric(f"priority_{priority}_pending_{queue_name}", 
                                          priority_pending, timestamp)
                    
                except Exception as e:
                    logger.debug(f"Failed to collect metrics for {stats_key}: {e}")
            
            # Redis performance metrics
            redis_info = self.redis_backend.redis_client.info()
            
            # Memory metrics
            used_memory = redis_info.get('used_memory', 0)
            self._record_metric("redis_memory_used", used_memory, timestamp)
            
            # Connection metrics  
            connected_clients = redis_info.get('connected_clients', 0)
            self._record_metric("redis_connections", connected_clients, timestamp)
            
            # Operations metrics
            total_commands = redis_info.get('total_commands_processed', 0)
            if hasattr(self, '_last_commands'):
                commands_per_sec = (total_commands - self._last_commands) / self.monitoring_interval
                self._record_metric("redis_ops_per_sec", commands_per_sec, timestamp)
            self._last_commands = total_commands
            
            self._last_metrics_check = timestamp
            
        except Exception as e:
            logger.error(f"Failed to collect performance metrics: {e}")
    
    def _record_metric(self, metric_name: str, value: float, timestamp: datetime):
        """Record a performance metric"""
        metric = PerformanceMetric(
            timestamp=timestamp,
            metric_name=metric_name,
            value=value
        )
        self.performance_metrics[metric_name].append(metric)
    
    def _analyze_metrics(self):
        """Analyze metrics and trigger alerts"""
        try:
            current_time = datetime.utcnow()
            
            # Analyze each metric type
            for metric_name, metrics in self.performance_metrics.items():
                if not metrics:
                    continue
                
                recent_metrics = [m for m in metrics 
                                if (current_time - m.timestamp).total_seconds() < 300]  # Last 5 minutes
                
                if len(recent_metrics) < 2:
                    continue
                
                # Calculate trends and averages
                values = [m.value for m in recent_metrics]
                avg_value = sum(values) / len(values)
                
                # Check thresholds
                self._check_metric_thresholds(metric_name, avg_value, current_time)
                
                # Detect anomalies
                self._detect_anomalies(metric_name, recent_metrics)
                
        except Exception as e:
            logger.error(f"Metric analysis failed: {e}")
    
    def _check_metric_thresholds(self, metric_name: str, value: float, timestamp: datetime):
        """Check if metric exceeds thresholds"""
        # Map metric names to thresholds
        threshold_map = {
            'queue_length': self.metric_thresholds['queue_length'],
            'processing_rate': self.metric_thresholds['processing_rate'], 
            'error_rate': self.metric_thresholds['error_rate'],
            'redis_memory_used': self.metric_thresholds['memory_usage'] * 1024*1024*1024  # Convert to bytes
        }
        
        # Check for matching threshold
        for pattern, threshold in threshold_map.items():
            if pattern in metric_name:
                if ((pattern in ['queue_length', 'error_rate', 'redis_memory_used'] and value > threshold) or
                    (pattern == 'processing_rate' and value < threshold)):
                    
                    self._trigger_alert(
                        alert_type="THRESHOLD_EXCEEDED",
                        severity="MEDIUM" if pattern != 'error_rate' else "HIGH",
                        message=f"Metric {metric_name} value {value} exceeds threshold {threshold}",
                        metadata={'metric_name': metric_name, 'value': value, 'threshold': threshold}
                    )
                break
    
    def _detect_anomalies(self, metric_name: str, recent_metrics: List[PerformanceMetric]):
        """Detect anomalies in metric patterns"""
        if len(recent_metrics) < 10:
            return
        
        values = [m.value for m in recent_metrics]
        
        # Simple anomaly detection using standard deviation
        mean_value = sum(values) / len(values)
        variance = sum((x - mean_value) ** 2 for x in values) / len(values)
        std_dev = variance ** 0.5
        
        # Check if latest value is an outlier
        latest_value = values[-1]
        if std_dev > 0 and abs(latest_value - mean_value) > 2 * std_dev:
            self._trigger_alert(
                alert_type="ANOMALY_DETECTED",
                severity="LOW",
                message=f"Anomaly detected in {metric_name}: {latest_value} (mean: {mean_value:.2f}, std: {std_dev:.2f})",
                metadata={'metric_name': metric_name, 'value': latest_value, 'mean': mean_value, 'std_dev': std_dev}
            )
            self.monitoring_stats['performance_anomalies'] += 1
    
    def _trigger_alert(self, alert_type: str, severity: str, message: str, metadata: Dict[str, Any] = None):
        """Trigger a monitoring alert"""
        alert = Alert(
            alert_type=alert_type,
            severity=severity,
            message=message,
            metadata=metadata or {}
        )
        
        # Check for duplicate alerts
        for existing_alert in self.active_alerts:
            if (existing_alert.alert_type == alert_type and 
                existing_alert.message == message and 
                not existing_alert.resolved):
                logger.debug(f"Suppressing duplicate alert: {message}")
                return
        
        self.active_alerts.append(alert)
        self.alert_history.append(alert)
        self.monitoring_stats['alerts_triggered'] += 1
        
        logger.warning(f"Alert triggered [{severity}]: {message}")
        
        # Notify alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")
    
    def add_alert_callback(self, callback: Callable[[Alert], None]):
        """Add callback for alert notifications"""
        self.alert_callbacks.append(callback)
        logger.info("Alert callback registered")
    
    def resolve_alert(self, alert: Alert):
        """Mark alert as resolved"""
        alert.resolved = True
        if alert in self.active_alerts:
            self.active_alerts.remove(alert)
        logger.info(f"Alert resolved: {alert.message}")
    
    def get_monitoring_report(self) -> Dict[str, Any]:
        """Generate comprehensive monitoring report"""
        return {
            'monitoring_active': self.monitoring_active,
            'monitoring_stats': self.monitoring_stats.copy(),
            'queue_health': {name: {
                'healthy': health.healthy,
                'score': health.score,
                'issues_count': len(health.issues),
                'last_check': health.last_check.isoformat()
            } for name, health in self.queue_health.items()},
            'active_alerts': [{
                'type': alert.alert_type,
                'severity': alert.severity,
                'message': alert.message,
                'timestamp': alert.timestamp.isoformat()
            } for alert in self.active_alerts],
            'performance_summary': self._get_performance_summary(),
            'system_health': self._get_system_health_summary()
        }
    
    def _get_performance_summary(self) -> Dict[str, Any]:
        """Get performance metrics summary"""
        summary = {}
        current_time = datetime.utcnow()
        
        for metric_name, metrics in self.performance_metrics.items():
            if not metrics:
                continue
                
            recent_metrics = [m for m in metrics 
                            if (current_time - m.timestamp).total_seconds() < 300]
            
            if recent_metrics:
                values = [m.value for m in recent_metrics]
                summary[metric_name] = {
                    'current': values[-1] if values else 0,
                    'average': sum(values) / len(values),
                    'min': min(values),
                    'max': max(values),
                    'samples': len(values)
                }
        
        return summary
    
    def _get_system_health_summary(self) -> Dict[str, Any]:
        """Get overall system health summary"""
        if not self.health_history:
            return {'overall_health': 'unknown'}
        
        recent_health = list(self.health_history)[-10:]  # Last 10 checks
        healthy_checks = sum(1 for h in recent_health if h.healthy)
        
        return {
            'overall_health': 'healthy' if healthy_checks >= len(recent_health) * 0.8 else 'degraded',
            'health_score': sum(h.score for h in recent_health) / len(recent_health),
            'recent_checks': len(recent_health),
            'healthy_checks': healthy_checks,
            'total_issues': sum(len(h.issues) for h in recent_health)
        }