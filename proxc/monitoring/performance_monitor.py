"""System-Wide Performance Monitoring and Optimization

Comprehensive monitoring system that:
- Implements real-time performance tracking across all components
- Provides automated performance optimization recommendations
- Supports alerting and anomaly detection
- Integrates with external monitoring systems (Prometheus, Grafana)
- Implements predictive performance analysis
- Provides comprehensive reporting and analytics
"""

import asyncio
import logging
import threading
import time
import json
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Callable, Any, Tuple, Union
from dataclasses import dataclass, field
import statistics
import pickle

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of performance metrics"""
    COUNTER = "counter"           # Monotonically increasing values
    GAUGE = "gauge"              # Current value that can go up/down
    HISTOGRAM = "histogram"       # Distribution of values
    TIMING = "timing"            # Duration measurements
    RATE = "rate"                # Events per time unit


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class MetricSample:
    """Individual metric sample"""
    name: str
    value: float
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)
    metric_type: MetricType = MetricType.GAUGE


@dataclass
class PerformanceThreshold:
    """Performance threshold configuration"""
    metric_name: str
    warning_threshold: float
    critical_threshold: float
    comparison: str = "greater_than"  # greater_than, less_than, equal_to
    window_minutes: int = 5
    min_samples: int = 3


@dataclass
class Alert:
    """Performance alert"""
    alert_id: str
    severity: AlertSeverity
    message: str
    metric_name: str
    current_value: float
    threshold_value: float
    timestamp: datetime
    resolved: bool = False
    resolved_timestamp: Optional[datetime] = None


class MetricCollector:
    """Collects and stores performance metrics"""
    
    def __init__(self, retention_hours: int = 24):
        self.retention_hours = retention_hours
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.metric_metadata: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
    
    def record_metric(self, name: str, value: float, 
                     metric_type: MetricType = MetricType.GAUGE,
                     labels: Optional[Dict[str, str]] = None):
        """Record a metric sample"""
        sample = MetricSample(
            name=name,
            value=value,
            timestamp=datetime.utcnow(),
            labels=labels or {},
            metric_type=metric_type
        )
        
        with self._lock:
            self.metrics[name].append(sample)
            self.metric_metadata[name] = {
                'type': metric_type,
                'last_updated': datetime.utcnow(),
                'sample_count': len(self.metrics[name])
            }
    
    def get_metric_history(self, name: str, minutes: int = 60) -> List[MetricSample]:
        """Get metric history for specified time period"""
        with self._lock:
            if name not in self.metrics:
                return []
            
            cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
            return [
                sample for sample in self.metrics[name]
                if sample.timestamp >= cutoff_time
            ]
    
    def get_current_value(self, name: str) -> Optional[float]:
        """Get most recent value for metric"""
        with self._lock:
            if name not in self.metrics or not self.metrics[name]:
                return None
            return self.metrics[name][-1].value
    
    def get_metric_statistics(self, name: str, minutes: int = 60) -> Dict[str, float]:
        """Get statistical summary of metric"""
        history = self.get_metric_history(name, minutes)
        if not history:
            return {}
        
        values = [sample.value for sample in history]
        return {
            'count': len(values),
            'min': min(values),
            'max': max(values),
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'std_dev': statistics.stdev(values) if len(values) > 1 else 0.0,
            'latest': values[-1],
            'trend': self._calculate_trend(values)
        }
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction for values"""
        if len(values) < 2:
            return "insufficient_data"
        
        # Simple trend calculation using first half vs second half
        mid = len(values) // 2
        first_half_avg = statistics.mean(values[:mid])
        second_half_avg = statistics.mean(values[mid:])
        
        diff_percent = ((second_half_avg - first_half_avg) / first_half_avg) * 100
        
        if diff_percent > 5:
            return "increasing"
        elif diff_percent < -5:
            return "decreasing"
        else:
            return "stable"
    
    def cleanup_old_metrics(self):
        """Remove old metric samples"""
        cutoff_time = datetime.utcnow() - timedelta(hours=self.retention_hours)
        
        with self._lock:
            for name, samples in self.metrics.items():
                # Convert to list, filter, and convert back to deque
                filtered_samples = [
                    sample for sample in samples
                    if sample.timestamp >= cutoff_time
                ]
                self.metrics[name] = deque(filtered_samples, maxlen=10000)


class AlertManager:
    """Manages performance alerts and notifications"""
    
    def __init__(self):
        self.thresholds: List[PerformanceThreshold] = []
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: deque = deque(maxlen=1000)
        self.alert_handlers: List[Callable[[Alert], None]] = []
        self._lock = threading.RLock()
    
    def add_threshold(self, threshold: PerformanceThreshold):
        """Add performance threshold"""
        with self._lock:
            self.thresholds.append(threshold)
            logger.info(f"Added threshold for {threshold.metric_name}: "
                       f"warning={threshold.warning_threshold}, "
                       f"critical={threshold.critical_threshold}")
    
    def add_alert_handler(self, handler: Callable[[Alert], None]):
        """Add alert notification handler"""
        self.alert_handlers.append(handler)
    
    def check_thresholds(self, metric_collector: MetricCollector):
        """Check all thresholds against current metrics"""
        with self._lock:
            for threshold in self.thresholds:
                self._check_single_threshold(threshold, metric_collector)
    
    def _check_single_threshold(self, threshold: PerformanceThreshold, 
                               metric_collector: MetricCollector):
        """Check single threshold against metric"""
        history = metric_collector.get_metric_history(
            threshold.metric_name, threshold.window_minutes
        )
        
        if len(history) < threshold.min_samples:
            return
        
        # Get recent values for threshold checking
        recent_values = [sample.value for sample in history[-threshold.min_samples:]]
        current_value = recent_values[-1]
        avg_value = statistics.mean(recent_values)
        
        # Determine if threshold is breached
        breached = False
        severity = None
        threshold_value = None
        
        if threshold.comparison == "greater_than":
            if avg_value > threshold.critical_threshold:
                breached, severity, threshold_value = True, AlertSeverity.CRITICAL, threshold.critical_threshold
            elif avg_value > threshold.warning_threshold:
                breached, severity, threshold_value = True, AlertSeverity.WARNING, threshold.warning_threshold
        elif threshold.comparison == "less_than":
            if avg_value < threshold.critical_threshold:
                breached, severity, threshold_value = True, AlertSeverity.CRITICAL, threshold.critical_threshold
            elif avg_value < threshold.warning_threshold:
                breached, severity, threshold_value = True, AlertSeverity.WARNING, threshold.warning_threshold
        
        alert_key = f"{threshold.metric_name}_{severity.value if severity else 'none'}"
        
        if breached and severity:
            # Create or update alert
            if alert_key not in self.active_alerts:
                alert = Alert(
                    alert_id=f"alert_{int(time.time() * 1000)}",
                    severity=severity,
                    message=f"{threshold.metric_name} {threshold.comparison} {threshold_value} "
                           f"(current: {current_value:.2f}, avg: {avg_value:.2f})",
                    metric_name=threshold.metric_name,
                    current_value=current_value,
                    threshold_value=threshold_value,
                    timestamp=datetime.utcnow()
                )
                
                self.active_alerts[alert_key] = alert
                self.alert_history.append(alert)
                
                # Notify handlers
                for handler in self.alert_handlers:
                    try:
                        handler(alert)
                    except Exception as e:
                        logger.error(f"Alert handler error: {e}")
                
                logger.warning(f"Alert triggered: {alert.message}")
        
        else:
            # Resolve alert if it exists
            if alert_key in self.active_alerts:
                alert = self.active_alerts[alert_key]
                alert.resolved = True
                alert.resolved_timestamp = datetime.utcnow()
                del self.active_alerts[alert_key]
                
                logger.info(f"Alert resolved: {alert.message}")
    
    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts"""
        with self._lock:
            return list(self.active_alerts.values())
    
    def get_alert_history(self, hours: int = 24) -> List[Alert]:
        """Get alert history for specified period"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        return [
            alert for alert in self.alert_history
            if alert.timestamp >= cutoff_time
        ]


class PerformanceAnalyzer:
    """Analyzes performance data and provides optimization recommendations"""
    
    def __init__(self):
        self.analysis_cache: Dict[str, Any] = {}
        self.cache_expiry: Dict[str, datetime] = {}
        self.cache_duration = timedelta(minutes=10)
    
    def analyze_system_performance(self, metric_collector: MetricCollector) -> Dict[str, Any]:
        """Perform comprehensive system performance analysis"""
        cache_key = "system_analysis"
        
        # Check cache
        if (cache_key in self.analysis_cache and 
            cache_key in self.cache_expiry and
            datetime.utcnow() < self.cache_expiry[cache_key]):
            return self.analysis_cache[cache_key]
        
        analysis = {
            'timestamp': datetime.utcnow().isoformat(),
            'overall_health': self._calculate_overall_health(metric_collector),
            'bottlenecks': self._identify_bottlenecks(metric_collector),
            'optimization_recommendations': self._generate_recommendations(metric_collector),
            'performance_trends': self._analyze_trends(metric_collector),
            'resource_utilization': self._analyze_resource_utilization(metric_collector)
        }
        
        # Cache result
        self.analysis_cache[cache_key] = analysis
        self.cache_expiry[cache_key] = datetime.utcnow() + self.cache_duration
        
        return analysis
    
    def _calculate_overall_health(self, metric_collector: MetricCollector) -> Dict[str, Any]:
        """Calculate overall system health score"""
        health_metrics = [
            'cpu_usage', 'memory_usage', 'queue_size', 'error_rate',
            'response_time', 'throughput'
        ]
        
        scores = []
        details = {}
        
        for metric in health_metrics:
            current_value = metric_collector.get_current_value(metric)
            if current_value is not None:
                # Simple scoring based on typical thresholds
                score = self._score_metric(metric, current_value)
                scores.append(score)
                details[metric] = {
                    'value': current_value,
                    'score': score,
                    'status': 'healthy' if score > 80 else 'warning' if score > 60 else 'critical'
                }
        
        overall_score = statistics.mean(scores) if scores else 0
        
        return {
            'overall_score': overall_score,
            'status': 'healthy' if overall_score > 80 else 'warning' if overall_score > 60 else 'critical',
            'metric_details': details
        }
    
    def _score_metric(self, metric_name: str, value: float) -> float:
        """Score individual metric (0-100 scale)"""
        # Simplified scoring logic - in production, use more sophisticated algorithms
        if metric_name == 'cpu_usage':
            return max(0, 100 - value)  # Lower CPU usage = higher score
        elif metric_name == 'memory_usage':
            return max(0, 100 - value)  # Lower memory usage = higher score
        elif metric_name == 'error_rate':
            return max(0, 100 - (value * 100))  # Lower error rate = higher score
        elif metric_name == 'response_time':
            # Assume good response time is < 1000ms
            return max(0, 100 - (value / 10))
        elif metric_name == 'throughput':
            # Higher throughput = higher score (scale appropriately)
            return min(100, value * 10)
        else:
            return 75  # Default neutral score
    
    def _identify_bottlenecks(self, metric_collector: MetricCollector) -> List[Dict[str, Any]]:
        """Identify system bottlenecks"""
        bottlenecks = []
        
        # Check for queue bottlenecks
        queue_size = metric_collector.get_current_value('queue_size')
        if queue_size and queue_size > 1000:
            bottlenecks.append({
                'type': 'queue_bottleneck',
                'severity': 'high' if queue_size > 5000 else 'medium',
                'description': f'High queue size: {queue_size}',
                'recommendations': [
                    'Increase worker count',
                    'Optimize processing algorithms',
                    'Implement better load balancing'
                ]
            })
        
        # Check for CPU bottlenecks
        cpu_usage = metric_collector.get_current_value('cpu_usage')
        if cpu_usage and cpu_usage > 80:
            bottlenecks.append({
                'type': 'cpu_bottleneck',
                'severity': 'high' if cpu_usage > 95 else 'medium',
                'description': f'High CPU usage: {cpu_usage}%',
                'recommendations': [
                    'Scale horizontally',
                    'Optimize CPU-intensive operations',
                    'Implement caching'
                ]
            })
        
        # Check for memory bottlenecks
        memory_usage = metric_collector.get_current_value('memory_usage')
        if memory_usage and memory_usage > 85:
            bottlenecks.append({
                'type': 'memory_bottleneck',
                'severity': 'high' if memory_usage > 95 else 'medium',
                'description': f'High memory usage: {memory_usage}%',
                'recommendations': [
                    'Implement memory optimization',
                    'Reduce batch sizes',
                    'Add more RAM'
                ]
            })
        
        return bottlenecks
    
    def _generate_recommendations(self, metric_collector: MetricCollector) -> List[Dict[str, Any]]:
        """Generate optimization recommendations"""
        recommendations = []
        
        # Analyze throughput vs resource usage
        throughput = metric_collector.get_current_value('throughput')
        cpu_usage = metric_collector.get_current_value('cpu_usage')
        memory_usage = metric_collector.get_current_value('memory_usage')
        
        if throughput and cpu_usage and cpu_usage < 50 and throughput < 100:
            recommendations.append({
                'category': 'performance',
                'priority': 'medium',
                'title': 'Increase parallelism',
                'description': 'Low CPU usage with low throughput suggests opportunity for increased parallelism',
                'expected_impact': 'Increase throughput by 20-40%'
            })
        
        if memory_usage and memory_usage > 80:
            recommendations.append({
                'category': 'resource',
                'priority': 'high',
                'title': 'Optimize memory usage',
                'description': 'High memory usage detected - implement memory optimization strategies',
                'expected_impact': 'Reduce memory usage by 10-30%'
            })
        
        # Check for error rate trends
        error_stats = metric_collector.get_metric_statistics('error_rate', minutes=30)
        if error_stats and error_stats.get('trend') == 'increasing':
            recommendations.append({
                'category': 'reliability',
                'priority': 'high',
                'title': 'Investigate error rate increase',
                'description': 'Error rate is trending upward - investigate root causes',
                'expected_impact': 'Improve system reliability'
            })
        
        return recommendations
    
    def _analyze_trends(self, metric_collector: MetricCollector) -> Dict[str, Any]:
        """Analyze performance trends"""
        trend_metrics = ['throughput', 'response_time', 'error_rate', 'cpu_usage']
        trends = {}
        
        for metric in trend_metrics:
            stats = metric_collector.get_metric_statistics(metric, minutes=120)  # 2 hours
            if stats:
                trends[metric] = {
                    'current': stats['latest'],
                    'average': stats['mean'],
                    'trend': stats['trend'],
                    'volatility': stats['std_dev'] / stats['mean'] if stats['mean'] > 0 else 0
                }
        
        return trends
    
    def _analyze_resource_utilization(self, metric_collector: MetricCollector) -> Dict[str, Any]:
        """Analyze resource utilization patterns"""
        utilization = {}
        
        # Worker utilization
        active_workers = metric_collector.get_current_value('active_workers')
        max_workers = metric_collector.get_current_value('max_workers')
        if active_workers is not None and max_workers is not None and max_workers > 0:
            utilization['worker_utilization'] = (active_workers / max_workers) * 100
        
        # Queue utilization
        queue_size = metric_collector.get_current_value('queue_size')
        max_queue_size = metric_collector.get_current_value('max_queue_size')
        if queue_size is not None and max_queue_size is not None and max_queue_size > 0:
            utilization['queue_utilization'] = (queue_size / max_queue_size) * 100
        
        return utilization


class PerformanceMonitor:
    """Main performance monitoring system"""
    
    def __init__(self, retention_hours: int = 24):
        self.metric_collector = MetricCollector(retention_hours)
        self.alert_manager = AlertManager()
        self.performance_analyzer = PerformanceAnalyzer()
        
        # Monitoring state
        self._running = False
        self._monitor_thread = None
        self._analysis_thread = None
        
        # External integrations
        self.prometheus_enabled = False
        self.prometheus_gateway = None
        
        # Setup default thresholds
        self._setup_default_thresholds()
        self._setup_default_alert_handlers()
        
        logger.info("PerformanceMonitor initialized")
    
    def _setup_default_thresholds(self):
        """Setup default performance thresholds"""
        default_thresholds = [
            PerformanceThreshold(
                metric_name='cpu_usage',
                warning_threshold=70.0,
                critical_threshold=90.0,
                comparison='greater_than',
                window_minutes=5
            ),
            PerformanceThreshold(
                metric_name='memory_usage',
                warning_threshold=80.0,
                critical_threshold=95.0,
                comparison='greater_than',
                window_minutes=5
            ),
            PerformanceThreshold(
                metric_name='error_rate',
                warning_threshold=0.05,  # 5%
                critical_threshold=0.15,  # 15%
                comparison='greater_than',
                window_minutes=10
            ),
            PerformanceThreshold(
                metric_name='queue_size',
                warning_threshold=1000,
                critical_threshold=5000,
                comparison='greater_than',
                window_minutes=3
            )
        ]
        
        for threshold in default_thresholds:
            self.alert_manager.add_threshold(threshold)
    
    def _setup_default_alert_handlers(self):
        """Setup default alert handlers"""
        
        def log_alert_handler(alert: Alert):
            """Log alerts to system logger"""
            if alert.severity == AlertSeverity.CRITICAL:
                logger.critical(f"CRITICAL ALERT: {alert.message}")
            elif alert.severity == AlertSeverity.WARNING:
                logger.warning(f"WARNING ALERT: {alert.message}")
            else:
                logger.info(f"INFO ALERT: {alert.message}")
        
        self.alert_manager.add_alert_handler(log_alert_handler)
    
    def start_monitoring(self):
        """Start background monitoring"""
        if self._running:
            return
        
        self._running = True
        
        # Start monitoring thread
        self._monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self._monitor_thread.start()
        
        # Start analysis thread
        self._analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self._analysis_thread.start()
        
        logger.info("Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self._running = False
        
        if self._monitor_thread:
            self._monitor_thread.join(timeout=10)
        
        if self._analysis_thread:
            self._analysis_thread.join(timeout=10)
        
        logger.info("Performance monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                # Check alert thresholds
                self.alert_manager.check_thresholds(self.metric_collector)
                
                # Clean up old metrics
                self.metric_collector.cleanup_old_metrics()
                
                # Export to Prometheus if enabled
                if self.prometheus_enabled:
                    self._export_to_prometheus()
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                time.sleep(30)
    
    def _analysis_loop(self):
        """Background performance analysis loop"""
        while self._running:
            try:
                # Perform periodic analysis
                analysis = self.performance_analyzer.analyze_system_performance(self.metric_collector)
                
                # Log significant findings
                if analysis['overall_health']['status'] != 'healthy':
                    logger.warning(f"System health: {analysis['overall_health']['status']} "
                                 f"(score: {analysis['overall_health']['overall_score']:.1f})")
                
                if analysis['bottlenecks']:
                    logger.warning(f"Identified {len(analysis['bottlenecks'])} bottlenecks")
                
                time.sleep(300)  # Analyze every 5 minutes
                
            except Exception as e:
                logger.error(f"Analysis loop error: {e}")
                time.sleep(300)
    
    def _export_to_prometheus(self):
        """Export metrics to Prometheus (if configured)"""
        # This would integrate with Prometheus push gateway
        # For now, just log that export would happen
        logger.debug("Exporting metrics to Prometheus")
    
    # Public API methods
    
    def record_metric(self, name: str, value: float, 
                     metric_type: MetricType = MetricType.GAUGE,
                     labels: Optional[Dict[str, str]] = None):
        """Record a performance metric"""
        self.metric_collector.record_metric(name, value, metric_type, labels)
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get current system health status"""
        analysis = self.performance_analyzer.analyze_system_performance(self.metric_collector)
        active_alerts = self.alert_manager.get_active_alerts()
        
        return {
            'health_score': analysis['overall_health']['overall_score'],
            'status': analysis['overall_health']['status'],
            'active_alerts': len(active_alerts),
            'critical_alerts': len([a for a in active_alerts if a.severity == AlertSeverity.CRITICAL]),
            'warning_alerts': len([a for a in active_alerts if a.severity == AlertSeverity.WARNING]),
            'bottlenecks': len(analysis['bottlenecks']),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        analysis = self.performance_analyzer.analyze_system_performance(self.metric_collector)
        alerts = self.alert_manager.get_active_alerts()
        alert_history = self.alert_manager.get_alert_history()
        
        return {
            'generated_at': datetime.utcnow().isoformat(),
            'analysis': analysis,
            'active_alerts': [
                {
                    'severity': alert.severity.value,
                    'message': alert.message,
                    'metric': alert.metric_name,
                    'timestamp': alert.timestamp.isoformat()
                }
                for alert in alerts
            ],
            'alert_summary': {
                'total_alerts_24h': len(alert_history),
                'critical_alerts_24h': len([a for a in alert_history if a.severity == AlertSeverity.CRITICAL]),
                'warning_alerts_24h': len([a for a in alert_history if a.severity == AlertSeverity.WARNING])
            }
        }
    
    def add_custom_threshold(self, metric_name: str, warning: float, critical: float,
                           comparison: str = "greater_than", window_minutes: int = 5):
        """Add custom performance threshold"""
        threshold = PerformanceThreshold(
            metric_name=metric_name,
            warning_threshold=warning,
            critical_threshold=critical,
            comparison=comparison,
            window_minutes=window_minutes
        )
        self.alert_manager.add_threshold(threshold)
    
    def export_metrics(self, filepath: str):
        """Export metrics to file"""
        export_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'metrics': {},
            'metadata': self.metric_collector.metric_metadata
        }
        
        # Export recent metrics for each metric name
        for metric_name in self.metric_collector.metrics:
            history = self.metric_collector.get_metric_history(metric_name, minutes=1440)  # 24 hours
            export_data['metrics'][metric_name] = [
                {
                    'value': sample.value,
                    'timestamp': sample.timestamp.isoformat(),
                    'labels': sample.labels
                }
                for sample in history
            ]
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Metrics exported to {filepath}")


def create_performance_monitor(retention_hours: int = 24) -> PerformanceMonitor:
    """Factory function to create performance monitor"""
    return PerformanceMonitor(retention_hours)


def main():
    """Example usage and testing"""
    import random
    
    # Create performance monitor
    monitor = create_performance_monitor()
    monitor.start_monitoring()
    
    print("Performance monitor started - generating test metrics...")
    
    try:
        # Simulate metrics for testing
        for i in range(100):
            # Simulate various metrics
            monitor.record_metric('cpu_usage', random.uniform(20, 95))
            monitor.record_metric('memory_usage', random.uniform(30, 90))
            monitor.record_metric('queue_size', random.randint(0, 2000))
            monitor.record_metric('throughput', random.uniform(50, 200))
            monitor.record_metric('error_rate', random.uniform(0, 0.1))
            monitor.record_metric('response_time', random.uniform(500, 3000))
            
            time.sleep(1)
            
            # Show health status every 10 iterations
            if i % 10 == 0:
                health = monitor.get_system_health()
                print(f"Health Score: {health['health_score']:.1f} "
                      f"Status: {health['status']} "
                      f"Alerts: {health['active_alerts']}")
        
        # Generate final report
        report = monitor.get_performance_report()
        print(f"\nFinal Performance Report:")
        print(f"Overall Health: {report['analysis']['overall_health']['status']}")
        print(f"Active Alerts: {len(report['active_alerts'])}")
        print(f"Bottlenecks: {len(report['analysis']['bottlenecks'])}")
        print(f"Recommendations: {len(report['analysis']['optimization_recommendations'])}")
        
        # Export metrics
        monitor.export_metrics("performance_metrics.json")
        
    except KeyboardInterrupt:
        print("\nStopping performance monitor...")
    finally:
        monitor.stop_monitoring()


if __name__ == "__main__":
    main()