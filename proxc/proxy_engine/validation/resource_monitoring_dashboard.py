"""Resource Monitoring Dashboard and Reporting System

This module provides comprehensive monitoring dashboards and reporting capabilities
for resource usage, leak detection, and cleanup operations in ProxC.
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from collections import deque

from .resource_leak_detector import ResourceLeakDetector, LeakDetection, get_global_leak_detector
from .session_cleanup import SessionCleanupManager, get_global_cleanup_manager
from .automated_cleanup_triggers import AutomatedCleanupTrigger, get_global_cleanup_trigger


@dataclass
class ResourceMetrics:
    """Resource metrics at a point in time"""
    timestamp: datetime = field(default_factory=datetime.now)
    memory_mb: float = 0.0
    cpu_percent: float = 0.0
    thread_count: int = 0
    connection_count: int = 0
    file_handle_count: int = 0
    active_sessions: int = 0
    pending_cleanup_tasks: int = 0
    cache_hit_ratio: float = 0.0
    validation_rate: float = 0.0  # validations per second
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


@dataclass
class AlertCondition:
    """Defines conditions for generating alerts"""
    name: str
    metric_name: str
    threshold: float
    operator: str  # "gt", "lt", "eq", "gte", "lte"
    severity: str  # "low", "medium", "high", "critical"
    enabled: bool = True
    cooldown_minutes: int = 15
    last_triggered: Optional[datetime] = None
    
    def is_triggered(self, value: float) -> bool:
        """Check if alert condition is triggered"""
        if not self.enabled:
            return False
        
        # Check cooldown
        if self.last_triggered:
            cooldown_elapsed = (datetime.now() - self.last_triggered).total_seconds() / 60
            if cooldown_elapsed < self.cooldown_minutes:
                return False
        
        # Check condition
        if self.operator == "gt":
            return value > self.threshold
        elif self.operator == "gte":
            return value >= self.threshold
        elif self.operator == "lt":
            return value < self.threshold
        elif self.operator == "lte":
            return value <= self.threshold
        elif self.operator == "eq":
            return value == self.threshold
        
        return False


@dataclass
class Alert:
    """Represents an alert"""
    name: str
    severity: str
    message: str
    metric_name: str
    current_value: float
    threshold: float
    triggered_at: datetime = field(default_factory=datetime.now)
    acknowledged: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['triggered_at'] = self.triggered_at.isoformat()
        return data


class ResourceMonitoringDashboard:
    """Main resource monitoring dashboard"""
    
    def __init__(self,
                 leak_detector: Optional[ResourceLeakDetector] = None,
                 cleanup_manager: Optional[SessionCleanupManager] = None,
                 cleanup_trigger: Optional[AutomatedCleanupTrigger] = None,
                 data_retention_hours: int = 24):
        
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Dependencies
        self.leak_detector = leak_detector or get_global_leak_detector()
        self.cleanup_manager = cleanup_manager or get_global_cleanup_manager()
        self.cleanup_trigger = cleanup_trigger or get_global_cleanup_trigger()
        
        # Data storage
        self.data_retention_hours = data_retention_hours
        self.metrics_history = deque(maxlen=int(data_retention_hours * 60))  # 1 minute intervals
        self.leak_history = deque(maxlen=1000)  # Keep last 1000 leaks
        self.alert_history = deque(maxlen=500)   # Keep last 500 alerts
        
        # Alert conditions
        self.alert_conditions = {}
        self._setup_default_alerts()
        
        # Dashboard state
        self.dashboard_enabled = True
        self.collection_interval = 60.0  # seconds
        self.last_collection_time = None
        
        # Reports
        self.reports_enabled = True
        self.report_directory = "monitoring_reports"
        self.daily_report_time = "06:00"  # 6 AM daily report
        
        self.logger.info("ResourceMonitoringDashboard initialized")
    
    def _setup_default_alerts(self):
        """Setup default alert conditions"""
        alerts = [
            AlertCondition(
                name="high_memory_usage",
                metric_name="memory_mb",
                threshold=400.0,
                operator="gt",
                severity="medium",
                cooldown_minutes=10
            ),
            AlertCondition(
                name="critical_memory_usage",
                metric_name="memory_mb",
                threshold=800.0,
                operator="gt",
                severity="critical",
                cooldown_minutes=5
            ),
            AlertCondition(
                name="high_connection_count",
                metric_name="connection_count",
                threshold=750,
                operator="gt",
                severity="medium",
                cooldown_minutes=15
            ),
            AlertCondition(
                name="high_thread_count",
                metric_name="thread_count",
                threshold=80,
                operator="gt",
                severity="medium",
                cooldown_minutes=10
            ),
            AlertCondition(
                name="low_cache_hit_ratio",
                metric_name="cache_hit_ratio",
                threshold=0.7,
                operator="lt",
                severity="low",
                cooldown_minutes=30
            ),
            AlertCondition(
                name="high_pending_cleanups",
                metric_name="pending_cleanup_tasks",
                threshold=50,
                operator="gt",
                severity="high",
                cooldown_minutes=5
            )
        ]
        
        for alert in alerts:
            self.alert_conditions[alert.name] = alert
    
    def collect_metrics(self) -> ResourceMetrics:
        """Collect current resource metrics"""
        try:
            # Get data from various sources
            memory_summary = self.leak_detector.memory_detector.get_memory_summary()
            connection_summary = self.leak_detector.connection_detector.get_connection_summary()
            thread_summary = self.leak_detector.thread_detector.get_thread_summary()
            file_handle_summary = self.leak_detector.file_handle_detector.get_file_handle_summary()
            cleanup_status = self.cleanup_manager.get_cleanup_status()
            
            # Create metrics object
            metrics = ResourceMetrics(
                memory_mb=memory_summary.get('current_mb', 0.0),
                thread_count=thread_summary.get('current_count', 0),
                connection_count=connection_summary.get('total_connections', 0),
                file_handle_count=file_handle_summary.get('current_count', 0),
                active_sessions=cleanup_status['sessions']['active'],
                pending_cleanup_tasks=cleanup_status['cleanup_tasks']['pending']
            )
            
            # Store in history
            self.metrics_history.append(metrics)
            self.last_collection_time = datetime.now()
            
            # Check for alerts
            self._check_alerts(metrics)
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Failed to collect metrics: {e}")
            return ResourceMetrics()  # Return empty metrics
    
    def _check_alerts(self, metrics: ResourceMetrics):
        """Check alert conditions against current metrics"""
        for alert_name, condition in self.alert_conditions.items():
            try:
                # Get metric value
                value = getattr(metrics, condition.metric_name, 0)
                
                # Check if triggered
                if condition.is_triggered(value):
                    condition.last_triggered = datetime.now()
                    
                    # Create alert
                    alert = Alert(
                        name=alert_name,
                        severity=condition.severity,
                        message=f"{condition.metric_name} ({value}) {condition.operator} {condition.threshold}",
                        metric_name=condition.metric_name,
                        current_value=value,
                        threshold=condition.threshold
                    )
                    
                    self.alert_history.append(alert)
                    self.logger.warning(f"ALERT: {alert.message}")
                    
            except Exception as e:
                self.logger.error(f"Failed to check alert condition {alert_name}: {e}")
    
    def get_current_status(self) -> Dict[str, Any]:
        """Get current comprehensive status"""
        current_metrics = self.collect_metrics()
        
        # Get recent leaks
        recent_leaks = []
        leak_status = self.leak_detector.get_comprehensive_status()
        for leak_data in leak_status.get('recent_leaks', []):
            recent_leaks.append(leak_data)
        
        # Get recent alerts
        recent_alerts = []
        for alert in list(self.alert_history)[-10:]:  # Last 10 alerts
            recent_alerts.append(alert.to_dict())
        
        # Calculate trends (if we have enough data)
        trends = self._calculate_trends()
        
        return {
            'timestamp': datetime.now().isoformat(),
            'current_metrics': current_metrics.to_dict(),
            'recent_leaks': recent_leaks,
            'recent_alerts': recent_alerts,
            'trends': trends,
            'system_health': self._assess_system_health(current_metrics),
            'leak_detector_status': leak_status,
            'cleanup_manager_status': self.cleanup_manager.get_cleanup_status(),
            'trigger_system_status': self.cleanup_trigger.get_trigger_status()
        }
    
    def _calculate_trends(self) -> Dict[str, Any]:
        """Calculate trends from historical data"""
        if len(self.metrics_history) < 2:
            return {}
        
        recent_metrics = list(self.metrics_history)
        
        # Calculate memory trend (last hour if available)
        memory_trend = self._calculate_metric_trend([m.memory_mb for m in recent_metrics[-60:]])
        connection_trend = self._calculate_metric_trend([m.connection_count for m in recent_metrics[-60:]])
        thread_trend = self._calculate_metric_trend([m.thread_count for m in recent_metrics[-60:]])
        
        return {
            'memory_mb': memory_trend,
            'connection_count': connection_trend,
            'thread_count': thread_trend,
            'observation_period_minutes': min(len(recent_metrics), 60)
        }
    
    def _calculate_metric_trend(self, values: List[float]) -> Dict[str, float]:
        """Calculate trend for a metric"""
        if len(values) < 2:
            return {'trend': 0.0, 'change_rate': 0.0}
        
        # Simple linear trend calculation
        first_half = values[:len(values)//2]
        second_half = values[len(values)//2:]
        
        first_avg = sum(first_half) / len(first_half) if first_half else 0
        second_avg = sum(second_half) / len(second_half) if second_half else 0
        
        change = second_avg - first_avg
        change_rate = change / first_avg if first_avg > 0 else 0
        
        return {
            'trend': change,
            'change_rate': change_rate,
            'first_half_avg': first_avg,
            'second_half_avg': second_avg
        }
    
    def _assess_system_health(self, metrics: ResourceMetrics) -> Dict[str, Any]:
        """Assess overall system health"""
        health_score = 100.0
        issues = []
        
        # Memory health
        memory_usage = metrics.memory_mb
        if memory_usage > 800:
            health_score -= 30
            issues.append("Critical memory usage")
        elif memory_usage > 400:
            health_score -= 15
            issues.append("High memory usage")
        
        # Connection health
        if metrics.connection_count > 750:
            health_score -= 20
            issues.append("High connection count")
        elif metrics.connection_count > 500:
            health_score -= 10
            issues.append("Moderate connection count")
        
        # Thread health
        if metrics.thread_count > 80:
            health_score -= 15
            issues.append("High thread count")
        
        # Cleanup task backlog
        if metrics.pending_cleanup_tasks > 50:
            health_score -= 25
            issues.append("High cleanup task backlog")
        elif metrics.pending_cleanup_tasks > 20:
            health_score -= 10
            issues.append("Moderate cleanup task backlog")
        
        # Determine health status
        if health_score >= 90:
            status = "excellent"
        elif health_score >= 75:
            status = "good"
        elif health_score >= 60:
            status = "fair"
        elif health_score >= 40:
            status = "poor"
        else:
            status = "critical"
        
        return {
            'score': max(0, health_score),
            'status': status,
            'issues': issues,
            'recommendations': self._get_health_recommendations(issues)
        }
    
    def _get_health_recommendations(self, issues: List[str]) -> List[str]:
        """Get recommendations based on health issues"""
        recommendations = []
        
        for issue in issues:
            if "memory" in issue.lower():
                recommendations.append("Consider reducing batch sizes or enabling more aggressive garbage collection")
            elif "connection" in issue.lower():
                recommendations.append("Review connection pooling settings and close idle connections")
            elif "thread" in issue.lower():
                recommendations.append("Optimize thread pool sizes and review concurrent operations")
            elif "cleanup" in issue.lower():
                recommendations.append("Investigate cleanup bottlenecks and consider increasing cleanup frequency")
        
        if not recommendations:
            recommendations.append("System operating within normal parameters")
        
        return recommendations
    
    def generate_report(self, report_type: str = "daily", 
                       output_file: Optional[str] = None) -> Dict[str, Any]:
        """Generate a comprehensive report"""
        try:
            current_time = datetime.now()
            
            # Determine time range
            if report_type == "hourly":
                start_time = current_time - timedelta(hours=1)
                title = "Hourly Resource Monitoring Report"
            elif report_type == "daily":
                start_time = current_time - timedelta(days=1)
                title = "Daily Resource Monitoring Report"
            elif report_type == "weekly":
                start_time = current_time - timedelta(weeks=1)
                title = "Weekly Resource Monitoring Report"
            else:
                start_time = current_time - timedelta(hours=1)
                title = "Resource Monitoring Report"
            
            # Filter metrics and events by time range
            relevant_metrics = [
                m for m in self.metrics_history 
                if m.timestamp >= start_time
            ]
            
            relevant_leaks = [
                leak for leak in self.leak_history 
                if leak.detected_at >= start_time
            ]
            
            relevant_alerts = [
                alert for alert in self.alert_history 
                if alert.triggered_at >= start_time
            ]
            
            # Calculate statistics
            if relevant_metrics:
                memory_stats = {
                    'min': min(m.memory_mb for m in relevant_metrics),
                    'max': max(m.memory_mb for m in relevant_metrics),
                    'avg': sum(m.memory_mb for m in relevant_metrics) / len(relevant_metrics)
                }
                
                connection_stats = {
                    'min': min(m.connection_count for m in relevant_metrics),
                    'max': max(m.connection_count for m in relevant_metrics),
                    'avg': sum(m.connection_count for m in relevant_metrics) / len(relevant_metrics)
                }
                
                thread_stats = {
                    'min': min(m.thread_count for m in relevant_metrics),
                    'max': max(m.thread_count for m in relevant_metrics),
                    'avg': sum(m.thread_count for m in relevant_metrics) / len(relevant_metrics)
                }
            else:
                memory_stats = connection_stats = thread_stats = {'min': 0, 'max': 0, 'avg': 0}
            
            # Create report
            report = {
                'title': title,
                'generated_at': current_time.isoformat(),
                'time_range': {
                    'start': start_time.isoformat(),
                    'end': current_time.isoformat(),
                    'duration_hours': (current_time - start_time).total_seconds() / 3600
                },
                'summary': {
                    'metrics_collected': len(relevant_metrics),
                    'leaks_detected': len(relevant_leaks),
                    'alerts_triggered': len(relevant_alerts)
                },
                'resource_statistics': {
                    'memory_mb': memory_stats,
                    'connections': connection_stats,
                    'threads': thread_stats
                },
                'leak_analysis': self._analyze_leaks_for_report(relevant_leaks),
                'alert_analysis': self._analyze_alerts_for_report(relevant_alerts),
                'system_health': self._assess_system_health(relevant_metrics[-1] if relevant_metrics else ResourceMetrics()),
                'recommendations': self._generate_report_recommendations(relevant_metrics, relevant_leaks, relevant_alerts)
            }
            
            # Save to file if specified
            if output_file:
                self._save_report_to_file(report, output_file)
            
            return report
            
        except Exception as e:
            self.logger.error(f"Failed to generate {report_type} report: {e}")
            return {}
    
    def _analyze_leaks_for_report(self, leaks: List[LeakDetection]) -> Dict[str, Any]:
        """Analyze leaks for report"""
        if not leaks:
            return {'total': 0, 'by_type': {}, 'by_severity': {}}
        
        by_type = {}
        by_severity = {}
        
        for leak in leaks:
            leak_type = leak.leak_type.value
            severity = leak.severity.value
            
            by_type[leak_type] = by_type.get(leak_type, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        return {
            'total': len(leaks),
            'by_type': by_type,
            'by_severity': by_severity,
            'most_common_type': max(by_type.items(), key=lambda x: x[1])[0] if by_type else None,
            'highest_severity': max(by_severity.items(), key=lambda x: x[1])[0] if by_severity else None
        }
    
    def _analyze_alerts_for_report(self, alerts: List[Alert]) -> Dict[str, Any]:
        """Analyze alerts for report"""
        if not alerts:
            return {'total': 0, 'by_severity': {}, 'by_type': {}}
        
        by_severity = {}
        by_type = {}
        
        for alert in alerts:
            severity = alert.severity
            alert_type = alert.name
            
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_type[alert_type] = by_type.get(alert_type, 0) + 1
        
        return {
            'total': len(alerts),
            'by_severity': by_severity,
            'by_type': by_type,
            'most_frequent': max(by_type.items(), key=lambda x: x[1])[0] if by_type else None
        }
    
    def _generate_report_recommendations(self, metrics: List[ResourceMetrics], 
                                       leaks: List[LeakDetection], 
                                       alerts: List[Alert]) -> List[str]:
        """Generate recommendations for the report"""
        recommendations = []
        
        if not metrics:
            recommendations.append("No metrics data available for analysis")
            return recommendations
        
        # Analyze trends
        memory_values = [m.memory_mb for m in metrics]
        if len(memory_values) > 10:
            memory_trend = (memory_values[-5:]) and (sum(memory_values[-5:]) / 5) - (sum(memory_values[:5]) / 5)
            if memory_trend > 50:
                recommendations.append("Memory usage is trending upward - consider memory optimization")
        
        # Analyze leaks
        critical_leaks = [l for l in leaks if l.severity.value == 4]  # Critical severity
        if critical_leaks:
            recommendations.append(f"{len(critical_leaks)} critical leaks detected - immediate attention required")
        
        # Analyze alerts
        high_priority_alerts = [a for a in alerts if a.severity in ['high', 'critical']]
        if high_priority_alerts:
            recommendations.append(f"{len(high_priority_alerts)} high-priority alerts - review system configuration")
        
        if not recommendations:
            recommendations.append("System operating within normal parameters")
        
        return recommendations
    
    def _save_report_to_file(self, report: Dict[str, Any], filename: str):
        """Save report to file"""
        try:
            os.makedirs(self.report_directory, exist_ok=True)
            filepath = os.path.join(self.report_directory, filename)
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            self.logger.info(f"Report saved to: {filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to save report to {filename}: {e}")
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get all data needed for dashboard display"""
        return {
            'current_status': self.get_current_status(),
            'metrics_history': [m.to_dict() for m in list(self.metrics_history)[-60:]],  # Last hour
            'alert_conditions': {name: asdict(cond) for name, cond in self.alert_conditions.items()},
            'dashboard_config': {
                'enabled': self.dashboard_enabled,
                'collection_interval': self.collection_interval,
                'data_retention_hours': self.data_retention_hours
            }
        }
    
    def shutdown(self):
        """Shutdown monitoring dashboard"""
        self.logger.info("Shutting down ResourceMonitoringDashboard")
        self.dashboard_enabled = False
        
        # Generate final report
        if self.reports_enabled:
            try:
                final_report = self.generate_report("session", f"final_report_{int(time.time())}.json")
                self.logger.info("Final session report generated")
            except Exception as e:
                self.logger.error(f"Failed to generate final report: {e}")
        
        self.logger.info("ResourceMonitoringDashboard shutdown complete")


# Global instance
_global_monitoring_dashboard: Optional[ResourceMonitoringDashboard] = None


def get_global_monitoring_dashboard() -> ResourceMonitoringDashboard:
    """Get or create global monitoring dashboard"""
    global _global_monitoring_dashboard
    if _global_monitoring_dashboard is None:
        _global_monitoring_dashboard = ResourceMonitoringDashboard()
    return _global_monitoring_dashboard


if __name__ == "__main__":
    # Example usage
    dashboard = ResourceMonitoringDashboard()
    
    # Collect some metrics
    for i in range(5):
        metrics = dashboard.collect_metrics()
        print(f"Collected metrics: Memory {metrics.memory_mb:.1f}MB, Threads {metrics.thread_count}")
        time.sleep(2)
    
    # Generate report
    report = dashboard.generate_report("hourly")
    print(f"Generated report with {report.get('summary', {}).get('metrics_collected', 0)} metrics")
    
    # Get dashboard data
    dashboard_data = dashboard.get_dashboard_data()
    print(f"Dashboard data includes {len(dashboard_data['metrics_history'])} metric points")
    
    dashboard.shutdown()