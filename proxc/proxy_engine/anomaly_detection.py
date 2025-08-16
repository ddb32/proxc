#!/usr/bin/env python3
"""
Proxy Behavior Anomaly Detection System - Phase 4.2.3

Advanced anomaly detection system for identifying unusual proxy behavior patterns,
security threats, and performance issues through machine learning and statistical analysis.

Detection Categories:
- Performance anomalies (response time spikes, throughput drops)
- Availability anomalies (unexpected downtime patterns)
- Security anomalies (suspicious traffic patterns, protocol violations)
- Geographic anomalies (location inconsistencies)
- Behavioral anomalies (unusual usage patterns)
- Network anomalies (connection patterns, error types)
"""

import asyncio
import json
import logging
import math
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union
import numpy as np
from scipy import stats
import sqlite3

from ..proxy_core.models import ProxyInfo, ProxyProtocol, ProxyStatus, ThreatLevel
from .performance_tracking import PerformanceTracker, PerformanceMetric


class AnomalyType(Enum):
    """Types of anomalies that can be detected"""
    PERFORMANCE_SPIKE = "performance_spike"
    PERFORMANCE_DROP = "performance_drop"
    AVAILABILITY_DROP = "availability_drop"
    GEOGRAPHIC_INCONSISTENCY = "geographic_inconsistency"
    SECURITY_THREAT = "security_threat"
    PROTOCOL_VIOLATION = "protocol_violation"
    UNUSUAL_TRAFFIC = "unusual_traffic"
    CONNECTION_ANOMALY = "connection_anomaly"
    ERROR_PATTERN = "error_pattern"
    BEHAVIORAL_CHANGE = "behavioral_change"


class AnomalySeverity(Enum):
    """Severity levels for anomalies"""
    LOW = "low"           # Minor deviation, possibly normal
    MEDIUM = "medium"     # Notable deviation, needs attention
    HIGH = "high"         # Significant deviation, requires action
    CRITICAL = "critical" # Severe deviation, immediate action required


@dataclass
class AnomalyAlert:
    """Anomaly detection alert"""
    id: str
    timestamp: datetime
    proxy_id: str
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    
    # Detection details
    metric_name: str
    current_value: float
    expected_value: float
    deviation_score: float
    confidence: float
    
    # Context information
    description: str
    context: Dict[str, Any]
    recommendation: str
    
    # Metadata
    detection_method: str
    false_positive_probability: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'proxy_id': self.proxy_id,
            'anomaly_type': self.anomaly_type.value,
            'severity': self.severity.value,
            'metric_name': self.metric_name,
            'current_value': self.current_value,
            'expected_value': self.expected_value,
            'deviation_score': self.deviation_score,
            'confidence': self.confidence,
            'description': self.description,
            'context': self.context,
            'recommendation': self.recommendation,
            'detection_method': self.detection_method,
            'false_positive_probability': self.false_positive_probability
        }


@dataclass
class AnomalyPattern:
    """Detected anomaly pattern over time"""
    pattern_id: str
    proxy_id: str
    anomaly_type: AnomalyType
    occurrences: List[datetime]
    pattern_description: str
    frequency: float  # Occurrences per day
    severity_trend: str  # increasing, decreasing, stable
    confidence: float


class StatisticalDetector:
    """Statistical anomaly detection methods"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {
            'zscore_threshold': 3.0,
            'iqr_factor': 1.5,
            'min_samples': 10,
            'rolling_window': 50
        }
    
    def detect_outliers_zscore(self, values: List[float], 
                              threshold: float = None) -> List[int]:
        """Detect outliers using Z-score method"""
        if len(values) < self.config['min_samples']:
            return []
        
        threshold = threshold or self.config['zscore_threshold']
        mean_val = statistics.mean(values)
        std_val = statistics.stdev(values)
        
        if std_val == 0:
            return []
        
        outliers = []
        for i, value in enumerate(values):
            z_score = abs((value - mean_val) / std_val)
            if z_score > threshold:
                outliers.append(i)
        
        return outliers
    
    def detect_outliers_iqr(self, values: List[float]) -> List[int]:
        """Detect outliers using Interquartile Range method"""
        if len(values) < self.config['min_samples']:
            return []
        
        q1 = np.percentile(values, 25)
        q3 = np.percentile(values, 75)
        iqr = q3 - q1
        
        lower_bound = q1 - (self.config['iqr_factor'] * iqr)
        upper_bound = q3 + (self.config['iqr_factor'] * iqr)
        
        outliers = []
        for i, value in enumerate(values):
            if value < lower_bound or value > upper_bound:
                outliers.append(i)
        
        return outliers
    
    def detect_change_points(self, values: List[float], 
                           min_change: float = 0.2) -> List[int]:
        """Detect significant change points in time series"""
        if len(values) < 6:  # Need minimum data for change detection
            return []
        
        change_points = []
        window_size = max(3, len(values) // 10)
        
        for i in range(window_size, len(values) - window_size):
            before_window = values[i-window_size:i]
            after_window = values[i:i+window_size]
            
            before_mean = statistics.mean(before_window)
            after_mean = statistics.mean(after_window)
            
            if before_mean == 0:
                continue
            
            change_ratio = abs(after_mean - before_mean) / before_mean
            if change_ratio > min_change:
                change_points.append(i)
        
        return change_points


class BehavioralDetector:
    """Behavioral pattern anomaly detection"""
    
    def __init__(self):
        self.baseline_patterns = {}
        self.learning_period = timedelta(days=7)
    
    def learn_baseline(self, proxy_id: str, 
                      access_patterns: List[Dict[str, Any]]):
        """Learn baseline behavior patterns for a proxy"""
        
        if not access_patterns:
            return
        
        # Analyze access patterns
        hourly_usage = defaultdict(int)
        daily_usage = defaultdict(int)
        protocol_usage = defaultdict(int)
        
        for pattern in access_patterns:
            timestamp = pattern.get('timestamp')
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp)
            elif isinstance(timestamp, (int, float)):
                timestamp = datetime.fromtimestamp(timestamp)
            
            if timestamp:
                hourly_usage[timestamp.hour] += 1
                daily_usage[timestamp.weekday()] += 1
            
            protocol = pattern.get('protocol')
            if protocol:
                protocol_usage[protocol] += 1
        
        # Store baseline patterns
        self.baseline_patterns[proxy_id] = {
            'hourly_usage': dict(hourly_usage),
            'daily_usage': dict(daily_usage),
            'protocol_usage': dict(protocol_usage),
            'total_requests': len(access_patterns),
            'learned_at': datetime.now()
        }
    
    def detect_behavioral_anomalies(self, proxy_id: str,
                                  recent_patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect behavioral anomalies compared to baseline"""
        
        if proxy_id not in self.baseline_patterns:
            return []
        
        baseline = self.baseline_patterns[proxy_id]
        anomalies = []
        
        # Analyze recent patterns
        recent_hourly = defaultdict(int)
        recent_daily = defaultdict(int)
        recent_protocol = defaultdict(int)
        
        for pattern in recent_patterns:
            timestamp = pattern.get('timestamp')
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp)
            
            if timestamp:
                recent_hourly[timestamp.hour] += 1
                recent_daily[timestamp.weekday()] += 1
            
            protocol = pattern.get('protocol')
            if protocol:
                recent_protocol[protocol] += 1
        
        # Compare hourly usage patterns
        baseline_hourly = baseline['hourly_usage']
        for hour in range(24):
            baseline_count = baseline_hourly.get(hour, 0)
            recent_count = recent_hourly.get(hour, 0)
            
            # Calculate expected count based on baseline
            baseline_total = baseline['total_requests']
            recent_total = len(recent_patterns)
            
            if baseline_total > 0:
                expected_count = (baseline_count / baseline_total) * recent_total
                
                # Check for significant deviation
                if expected_count > 0 and recent_count > 0:
                    deviation_ratio = abs(recent_count - expected_count) / expected_count
                    if deviation_ratio > 2.0:  # 200% deviation threshold
                        anomalies.append({
                            'type': 'unusual_hourly_pattern',
                            'hour': hour,
                            'expected': expected_count,
                            'actual': recent_count,
                            'deviation_ratio': deviation_ratio
                        })
        
        # Compare protocol usage
        for protocol, baseline_count in baseline['protocol_usage'].items():
            recent_count = recent_protocol.get(protocol, 0)
            baseline_ratio = baseline_count / baseline['total_requests']
            recent_ratio = recent_count / len(recent_patterns) if recent_patterns else 0
            
            if abs(recent_ratio - baseline_ratio) > 0.5:  # 50% difference threshold
                anomalies.append({
                    'type': 'unusual_protocol_usage',
                    'protocol': protocol,
                    'baseline_ratio': baseline_ratio,
                    'recent_ratio': recent_ratio
                })
        
        return anomalies


class SecurityDetector:
    """Security-focused anomaly detection"""
    
    def __init__(self):
        self.threat_signatures = self._load_threat_signatures()
        self.suspicious_patterns = []
    
    def _load_threat_signatures(self) -> Dict[str, Any]:
        """Load known threat signatures and patterns"""
        return {
            'malicious_user_agents': [
                'sqlmap', 'nikto', 'nmap', 'masscan', 'zap',
                'burpsuite', 'gobuster', 'dirb', 'wfuzz'
            ],
            'suspicious_protocols': ['socks4'],  # SOCKS4 often used maliciously
            'threat_keywords': [
                'attack', 'exploit', 'payload', 'injection',
                'xss', 'csrf', 'backdoor', 'malware'
            ],
            'suspicious_ports': [
                4444, 5555, 6666, 31337, 12345, 54321  # Common backdoor ports
            ]
        }
    
    def detect_security_anomalies(self, proxy: ProxyInfo,
                                 traffic_patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect security-related anomalies"""
        
        anomalies = []
        
        # Check for suspicious user agents
        for pattern in traffic_patterns:
            user_agent = pattern.get('user_agent', '').lower()
            for malicious_ua in self.threat_signatures['malicious_user_agents']:
                if malicious_ua in user_agent:
                    anomalies.append({
                        'type': 'malicious_user_agent',
                        'user_agent': pattern.get('user_agent'),
                        'threat_signature': malicious_ua,
                        'severity': 'high'
                    })
        
        # Check for port scanning patterns
        unique_ports = set()
        for pattern in traffic_patterns:
            target_port = pattern.get('target_port')
            if target_port:
                unique_ports.add(target_port)
        
        if len(unique_ports) > 50:  # Accessing many different ports
            anomalies.append({
                'type': 'port_scanning_behavior',
                'unique_ports_count': len(unique_ports),
                'severity': 'high'
            })
        
        # Check for rapid successive requests (potential DDoS)
        if len(traffic_patterns) > 100:  # High request volume
            timestamps = [p.get('timestamp') for p in traffic_patterns if p.get('timestamp')]
            if timestamps:
                timestamps.sort()
                # Check for requests within very short time windows
                rapid_requests = 0
                for i in range(1, len(timestamps)):
                    if isinstance(timestamps[i], str):
                        current = datetime.fromisoformat(timestamps[i])
                        previous = datetime.fromisoformat(timestamps[i-1])
                    else:
                        current = timestamps[i]
                        previous = timestamps[i-1]
                    
                    if (current - previous).total_seconds() < 0.1:  # Less than 100ms apart
                        rapid_requests += 1
                
                if rapid_requests > 20:  # Many rapid requests
                    anomalies.append({
                        'type': 'potential_ddos_pattern',
                        'rapid_requests_count': rapid_requests,
                        'total_requests': len(traffic_patterns),
                        'severity': 'critical'
                    })
        
        # Check proxy-specific security issues
        if hasattr(proxy, 'threat_level') and proxy.threat_level:
            if proxy.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                anomalies.append({
                    'type': 'high_threat_proxy',
                    'threat_level': proxy.threat_level.value,
                    'severity': 'high'
                })
        
        return anomalies


class AnomalyDetectionEngine:
    """Main anomaly detection engine"""
    
    def __init__(self, performance_tracker: PerformanceTracker = None,
                 config: Dict[str, Any] = None):
        self.performance_tracker = performance_tracker
        self.config = config or self._get_default_config()
        self.logger = logging.getLogger(__name__)
        
        # Detection components
        self.statistical_detector = StatisticalDetector()
        self.behavioral_detector = BehavioralDetector()
        self.security_detector = SecurityDetector()
        
        # Alert storage
        self.alerts = deque(maxlen=1000)
        self.alert_history = {}
        
        # Pattern tracking
        self.detected_patterns = {}
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'detection_interval_minutes': 5,
            'alert_cooldown_minutes': 30,
            'min_confidence_threshold': 0.7,
            'false_positive_threshold': 0.3,
            'pattern_detection_enabled': True,
            'real_time_monitoring': True
        }
    
    async def detect_anomalies(self, proxy: ProxyInfo,
                             context_data: Dict[str, Any] = None) -> List[AnomalyAlert]:
        """Comprehensive anomaly detection for a proxy"""
        
        alerts = []
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        try:
            # Performance anomaly detection
            if self.performance_tracker:
                performance_alerts = await self._detect_performance_anomalies(proxy)
                alerts.extend(performance_alerts)
            
            # Behavioral anomaly detection
            if context_data and 'access_patterns' in context_data:
                behavioral_alerts = await self._detect_behavioral_anomalies(
                    proxy, context_data['access_patterns']
                )
                alerts.extend(behavioral_alerts)
            
            # Security anomaly detection
            if context_data and 'traffic_patterns' in context_data:
                security_alerts = await self._detect_security_anomalies(
                    proxy, context_data['traffic_patterns']
                )
                alerts.extend(security_alerts)
            
            # Geographic anomaly detection
            geographic_alerts = await self._detect_geographic_anomalies(proxy)
            alerts.extend(geographic_alerts)
            
            # Filter alerts by confidence and false positive probability
            filtered_alerts = []
            for alert in alerts:
                if (alert.confidence >= self.config['min_confidence_threshold'] and
                    alert.false_positive_probability <= self.config['false_positive_threshold']):
                    filtered_alerts.append(alert)
            
            # Store alerts for pattern detection
            for alert in filtered_alerts:
                self.alerts.append(alert)
                
                if proxy_id not in self.alert_history:
                    self.alert_history[proxy_id] = []
                self.alert_history[proxy_id].append(alert)
            
            # Pattern detection
            if self.config['pattern_detection_enabled']:
                await self._detect_patterns(proxy_id)
            
            return filtered_alerts
        
        except Exception as e:
            self.logger.error(f"Error detecting anomalies for {proxy_id}: {e}")
            return []
    
    async def _detect_performance_anomalies(self, proxy: ProxyInfo) -> List[AnomalyAlert]:
        """Detect performance-related anomalies"""
        
        alerts = []
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        # Check key performance metrics
        metrics_to_check = [
            PerformanceMetric.RESPONSE_TIME,
            PerformanceMetric.UPTIME,
            PerformanceMetric.SUCCESS_RATE
        ]
        
        for metric in metrics_to_check:
            try:
                # Get recent performance data
                data_points = await self.performance_tracker.get_performance_history(
                    proxy, metric, days=7
                )
                
                if len(data_points) < 10:
                    continue
                
                values = [dp.value for dp in data_points]
                timestamps = [dp.timestamp for dp in data_points]
                
                # Statistical outlier detection
                outlier_indices = self.statistical_detector.detect_outliers_zscore(values)
                
                for idx in outlier_indices:
                    if idx < len(values) and idx < len(timestamps):
                        current_value = values[idx]
                        expected_value = statistics.mean(values)
                        deviation_score = abs(current_value - expected_value) / statistics.stdev(values)
                        
                        # Determine anomaly type and severity
                        if metric == PerformanceMetric.RESPONSE_TIME:
                            anomaly_type = AnomalyType.PERFORMANCE_SPIKE if current_value > expected_value else AnomalyType.PERFORMANCE_DROP
                            severity = self._calculate_severity(deviation_score, [2.0, 3.0, 4.0])
                        elif metric == PerformanceMetric.UPTIME:
                            anomaly_type = AnomalyType.AVAILABILITY_DROP
                            severity = self._calculate_severity(deviation_score, [1.5, 2.5, 3.5])
                        else:
                            anomaly_type = AnomalyType.PERFORMANCE_DROP
                            severity = self._calculate_severity(deviation_score, [2.0, 3.0, 4.0])
                        
                        alert = AnomalyAlert(
                            id=f"{proxy_id}_{metric.value}_{timestamps[idx].timestamp()}",
                            timestamp=timestamps[idx],
                            proxy_id=proxy_id,
                            anomaly_type=anomaly_type,
                            severity=severity,
                            metric_name=metric.value,
                            current_value=current_value,
                            expected_value=expected_value,
                            deviation_score=deviation_score,
                            confidence=min(1.0, deviation_score / 3.0),
                            description=f"{metric.value.replace('_', ' ').title()} anomaly detected",
                            context={'metric': metric.value, 'data_points': len(values)},
                            recommendation=self._get_recommendation(anomaly_type, metric),
                            detection_method="statistical_zscore",
                            false_positive_probability=max(0.1, 1.0 - (deviation_score / 4.0))
                        )
                        alerts.append(alert)
            
            except Exception as e:
                self.logger.error(f"Error detecting {metric.value} anomalies: {e}")
        
        return alerts
    
    async def _detect_behavioral_anomalies(self, proxy: ProxyInfo,
                                         access_patterns: List[Dict[str, Any]]) -> List[AnomalyAlert]:
        """Detect behavioral anomalies"""
        
        alerts = []
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        # Learn baseline if not exists
        if proxy_id not in self.behavioral_detector.baseline_patterns:
            # Use older access patterns as baseline
            baseline_patterns = access_patterns[:-50] if len(access_patterns) > 100 else access_patterns[:len(access_patterns)//2]
            self.behavioral_detector.learn_baseline(proxy_id, baseline_patterns)
            return []  # No anomalies during learning phase
        
        # Detect anomalies in recent patterns
        recent_patterns = access_patterns[-50:] if len(access_patterns) > 50 else access_patterns
        behavioral_anomalies = self.behavioral_detector.detect_behavioral_anomalies(
            proxy_id, recent_patterns
        )
        
        for anomaly in behavioral_anomalies:
            alert = AnomalyAlert(
                id=f"{proxy_id}_behavioral_{int(time.time())}",
                timestamp=datetime.now(),
                proxy_id=proxy_id,
                anomaly_type=AnomalyType.BEHAVIORAL_CHANGE,
                severity=AnomalySeverity.MEDIUM,
                metric_name="behavioral_pattern",
                current_value=anomaly.get('deviation_ratio', 0),
                expected_value=1.0,  # Normal ratio
                deviation_score=anomaly.get('deviation_ratio', 0),
                confidence=0.8,
                description=f"Behavioral anomaly: {anomaly.get('type', 'unknown')}",
                context=anomaly,
                recommendation="Monitor proxy usage patterns for potential security issues",
                detection_method="behavioral_analysis",
                false_positive_probability=0.2
            )
            alerts.append(alert)
        
        return alerts
    
    async def _detect_security_anomalies(self, proxy: ProxyInfo,
                                       traffic_patterns: List[Dict[str, Any]]) -> List[AnomalyAlert]:
        """Detect security-related anomalies"""
        
        alerts = []
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        security_anomalies = self.security_detector.detect_security_anomalies(
            proxy, traffic_patterns
        )
        
        for anomaly in security_anomalies:
            severity_map = {
                'low': AnomalySeverity.LOW,
                'medium': AnomalySeverity.MEDIUM,
                'high': AnomalySeverity.HIGH,
                'critical': AnomalySeverity.CRITICAL
            }
            
            alert = AnomalyAlert(
                id=f"{proxy_id}_security_{int(time.time())}",
                timestamp=datetime.now(),
                proxy_id=proxy_id,
                anomaly_type=AnomalyType.SECURITY_THREAT,
                severity=severity_map.get(anomaly.get('severity', 'medium'), AnomalySeverity.MEDIUM),
                metric_name="security_threat",
                current_value=1.0,  # Threat detected
                expected_value=0.0,  # No threat expected
                deviation_score=3.0,  # High deviation for security threats
                confidence=0.9,
                description=f"Security threat detected: {anomaly.get('type', 'unknown')}",
                context=anomaly,
                recommendation="Investigate security threat and consider blocking proxy",
                detection_method="security_analysis",
                false_positive_probability=0.1
            )
            alerts.append(alert)
        
        return alerts
    
    async def _detect_geographic_anomalies(self, proxy: ProxyInfo) -> List[AnomalyAlert]:
        """Detect geographic inconsistencies"""
        
        alerts = []
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        # Check for geographic inconsistencies
        if hasattr(proxy, 'country') and hasattr(proxy, 'city'):
            if proxy.country and proxy.city:
                # This would normally validate against a geographic database
                # For now, check for obvious inconsistencies
                inconsistencies = []
                
                # Example: Check if city makes sense for country
                country_city_map = {
                    'US': ['New York', 'Los Angeles', 'Chicago', 'Miami'],
                    'GB': ['London', 'Manchester', 'Birmingham'],
                    'DE': ['Berlin', 'Munich', 'Hamburg'],
                    'JP': ['Tokyo', 'Osaka', 'Kyoto']
                }
                
                if proxy.country in country_city_map:
                    expected_cities = country_city_map[proxy.country]
                    if proxy.city not in expected_cities:
                        inconsistencies.append(f"City {proxy.city} not typical for country {proxy.country}")
                
                if inconsistencies:
                    alert = AnomalyAlert(
                        id=f"{proxy_id}_geographic_{int(time.time())}",
                        timestamp=datetime.now(),
                        proxy_id=proxy_id,
                        anomaly_type=AnomalyType.GEOGRAPHIC_INCONSISTENCY,
                        severity=AnomalySeverity.LOW,
                        metric_name="geographic_consistency",
                        current_value=0.0,  # Inconsistent
                        expected_value=1.0,  # Consistent
                        deviation_score=2.0,
                        confidence=0.6,
                        description="Geographic inconsistency detected",
                        context={'inconsistencies': inconsistencies},
                        recommendation="Verify proxy geographic information",
                        detection_method="geographic_validation",
                        false_positive_probability=0.4
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _calculate_severity(self, deviation_score: float, 
                          thresholds: List[float]) -> AnomalySeverity:
        """Calculate severity based on deviation score and thresholds"""
        if deviation_score >= thresholds[2]:
            return AnomalySeverity.CRITICAL
        elif deviation_score >= thresholds[1]:
            return AnomalySeverity.HIGH
        elif deviation_score >= thresholds[0]:
            return AnomalySeverity.MEDIUM
        else:
            return AnomalySeverity.LOW
    
    def _get_recommendation(self, anomaly_type: AnomalyType, 
                          metric: PerformanceMetric) -> str:
        """Get recommendation based on anomaly type and metric"""
        recommendations = {
            AnomalyType.PERFORMANCE_SPIKE: "Check proxy server load and network conditions",
            AnomalyType.PERFORMANCE_DROP: "Monitor proxy performance and consider alternatives",
            AnomalyType.AVAILABILITY_DROP: "Verify proxy availability and connection stability",
            AnomalyType.SECURITY_THREAT: "Investigate security threat and block if confirmed",
            AnomalyType.BEHAVIORAL_CHANGE: "Monitor usage patterns for potential abuse",
            AnomalyType.GEOGRAPHIC_INCONSISTENCY: "Verify proxy location information"
        }
        
        return recommendations.get(anomaly_type, "Monitor proxy and investigate anomaly")
    
    async def _detect_patterns(self, proxy_id: str):
        """Detect recurring anomaly patterns"""
        if proxy_id not in self.alert_history:
            return
        
        alerts = self.alert_history[proxy_id]
        if len(alerts) < 5:
            return
        
        # Group alerts by type
        type_groups = defaultdict(list)
        for alert in alerts:
            type_groups[alert.anomaly_type].append(alert)
        
        # Look for patterns in each type
        for anomaly_type, type_alerts in type_groups.items():
            if len(type_alerts) >= 3:
                timestamps = [alert.timestamp for alert in type_alerts]
                
                # Calculate frequency
                time_span = (max(timestamps) - min(timestamps)).days + 1
                frequency = len(type_alerts) / time_span
                
                # Check if this is a new pattern
                pattern_id = f"{proxy_id}_{anomaly_type.value}"
                if pattern_id not in self.detected_patterns or frequency > self.detected_patterns[pattern_id].frequency * 1.5:
                    pattern = AnomalyPattern(
                        pattern_id=pattern_id,
                        proxy_id=proxy_id,
                        anomaly_type=anomaly_type,
                        occurrences=timestamps,
                        pattern_description=f"Recurring {anomaly_type.value} anomalies",
                        frequency=frequency,
                        severity_trend="increasing" if len(type_alerts) > 3 else "stable",
                        confidence=min(1.0, len(type_alerts) / 10.0)
                    )
                    
                    self.detected_patterns[pattern_id] = pattern
                    self.logger.warning(f"Detected anomaly pattern: {pattern_id} with frequency {frequency:.2f}/day")
    
    def get_anomaly_summary(self, proxy_id: str = None) -> Dict[str, Any]:
        """Get summary of detected anomalies"""
        if proxy_id:
            alerts = [alert for alert in self.alerts if alert.proxy_id == proxy_id]
        else:
            alerts = list(self.alerts)
        
        if not alerts:
            return {'total_alerts': 0}
        
        # Analyze alerts
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)
        recent_alerts = []
        
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        for alert in alerts:
            severity_counts[alert.severity.value] += 1
            type_counts[alert.anomaly_type.value] += 1
            
            if alert.timestamp >= cutoff_time:
                recent_alerts.append(alert)
        
        return {
            'total_alerts': len(alerts),
            'recent_alerts_24h': len(recent_alerts),
            'severity_distribution': dict(severity_counts),
            'type_distribution': dict(type_counts),
            'patterns_detected': len(self.detected_patterns),
            'average_confidence': statistics.mean([a.confidence for a in alerts]),
            'most_common_type': max(type_counts.items(), key=lambda x: x[1])[0] if type_counts else None
        }