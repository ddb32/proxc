"""
Comprehensive Validation Reporting and Analytics Dashboard - Phase 3.3.9

Advanced analytics and reporting system for proxy validation with detailed
insights, trends analysis, and comprehensive dashboards.

Features:
- Real-time validation analytics dashboard
- Performance trend analysis and forecasting
- Comprehensive validation reports with visualizations
- Quality metrics and KPI tracking
- Comparative analysis between proxy sources
- Anomaly detection in validation patterns
- Export capabilities for various formats
- Interactive reporting with drill-down capabilities
"""

import asyncio
import json
import logging
import math
import statistics
import time
from collections import defaultdict, deque, Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Set, Any
import threading

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.figure import Figure
    import seaborn as sns
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

from .advanced_validation_engine import HealthScore, ProxyQualityTier, HealthCriteria
from .sla_monitoring import SLACompliance, SLATier
from .intelligent_validation_engine import ValidationResult, ValidationConfidence, ValidationErrorCategory
from .geo_reputation_validator import GeolocationAccuracy, IPReputationSummary
from ..proxy_core.models import ProxyInfo, ProxyProtocol, ValidationStatus, ThreatLevel
from ..proxy_cli.cli_imports import log_structured, print_info, print_success

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Report output formats"""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    CSV = "csv"
    MARKDOWN = "markdown"
    EXCEL = "excel"


class AnalyticsTimeframe(Enum):
    """Analytics timeframe options"""
    LAST_HOUR = "last_hour"
    LAST_24_HOURS = "last_24_hours"
    LAST_7_DAYS = "last_7_days"
    LAST_30_DAYS = "last_30_days"
    CUSTOM = "custom"


class MetricType(Enum):
    """Validation metric types"""
    SUCCESS_RATE = "success_rate"
    RESPONSE_TIME = "response_time"
    HEALTH_SCORE = "health_score"
    SLA_COMPLIANCE = "sla_compliance"
    REPUTATION_SCORE = "reputation_score"
    GEOLOCATION_ACCURACY = "geolocation_accuracy"
    STABILITY_SCORE = "stability_score"
    CONFIDENCE_SCORE = "confidence_score"


@dataclass
class ValidationMetrics:
    """Comprehensive validation metrics"""
    total_validations: int = 0
    successful_validations: int = 0
    failed_validations: int = 0
    success_rate: float = 0.0
    average_response_time: float = 0.0
    median_response_time: float = 0.0
    response_time_p95: float = 0.0
    average_health_score: float = 0.0
    average_confidence: float = 0.0
    sla_compliance_rate: float = 0.0
    unique_proxies: int = 0
    unique_error_categories: int = 0
    validation_timespan: timedelta = field(default_factory=lambda: timedelta(0))
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            **asdict(self),
            'validation_timespan': self.validation_timespan.total_seconds()
        }


@dataclass
class ProxySourceAnalysis:
    """Analysis for proxy sources"""
    source_name: str
    proxy_count: int = 0
    success_rate: float = 0.0
    average_quality_score: float = 0.0
    quality_distribution: Dict[ProxyQualityTier, int] = field(default_factory=dict)
    protocol_distribution: Dict[ProxyProtocol, int] = field(default_factory=dict)
    country_distribution: Dict[str, int] = field(default_factory=dict)
    common_errors: List[Tuple[ValidationErrorCategory, int]] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            **asdict(self),
            'quality_distribution': {k.value: v for k, v in self.quality_distribution.items()},
            'protocol_distribution': {k.value: v for k, v in self.protocol_distribution.items()},
            'common_errors': [(cat.value, count) for cat, count in self.common_errors]
        }


@dataclass
class TrendAnalysis:
    """Trend analysis for metrics over time"""
    metric_name: str
    timeframe: AnalyticsTimeframe
    data_points: List[Tuple[datetime, float]] = field(default_factory=list)
    trend_direction: str = "stable"  # "increasing", "decreasing", "stable"
    trend_strength: float = 0.0  # 0-1
    slope: float = 0.0
    r_squared: float = 0.0
    forecast_24h: Optional[float] = None
    anomalies: List[Tuple[datetime, float, str]] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            **asdict(self),
            'timeframe': self.timeframe.value,
            'data_points': [(dt.isoformat(), val) for dt, val in self.data_points],
            'anomalies': [(dt.isoformat(), val, reason) for dt, val, reason in self.anomalies]
        }


@dataclass
class ValidationReport:
    """Comprehensive validation report"""
    report_id: str
    generated_at: datetime
    timeframe: AnalyticsTimeframe
    start_time: datetime
    end_time: datetime
    
    # Summary metrics
    overall_metrics: ValidationMetrics
    proxy_count: int = 0
    
    # Detailed analysis
    source_analysis: List[ProxySourceAnalysis] = field(default_factory=list)
    quality_breakdown: Dict[ProxyQualityTier, int] = field(default_factory=dict)
    protocol_breakdown: Dict[ProxyProtocol, int] = field(default_factory=dict)
    country_breakdown: Dict[str, int] = field(default_factory=dict)
    error_analysis: Dict[ValidationErrorCategory, int] = field(default_factory=dict)
    
    # Trend analysis
    trends: List[TrendAnalysis] = field(default_factory=list)
    
    # Performance insights
    top_performers: List[Tuple[str, float]] = field(default_factory=list)  # (proxy_address, score)
    problem_proxies: List[Tuple[str, str]] = field(default_factory=list)   # (proxy_address, issue)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            **asdict(self),
            'generated_at': self.generated_at.isoformat(),
            'timeframe': self.timeframe.value,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'overall_metrics': self.overall_metrics.to_dict(),
            'source_analysis': [s.to_dict() for s in self.source_analysis],
            'quality_breakdown': {k.value: v for k, v in self.quality_breakdown.items()},
            'protocol_breakdown': {k.value: v for k, v in self.protocol_breakdown.items()},
            'error_analysis': {k.value: v for k, v in self.error_analysis.items()},
            'trends': [t.to_dict() for t in self.trends]
        }


class ValidationAnalytics:
    """
    Comprehensive validation analytics engine
    """
    
    def __init__(self, data_retention_days: int = 30):
        self.data_retention = timedelta(days=data_retention_days)
        
        # Data storage
        self.validation_history: Dict[str, List[ValidationResult]] = defaultdict(list)
        self.health_scores: Dict[str, List[Tuple[datetime, HealthScore]]] = defaultdict(list)
        self.sla_compliance_history: Dict[str, List[Tuple[datetime, Dict[SLATier, SLACompliance]]]] = defaultdict(list)
        self.reputation_history: Dict[str, List[Tuple[datetime, IPReputationSummary]]] = defaultdict(list)
        
        # Real-time metrics
        self.current_metrics = ValidationMetrics()
        self.metric_snapshots: deque = deque(maxlen=1000)  # Store periodic snapshots
        
        # Performance tracking
        self.response_time_history: deque = deque(maxlen=5000)
        self.success_rate_history: deque = deque(maxlen=1000)
        
        # Lock for thread safety
        self.lock = threading.Lock()
    
    def record_validation_result(self, proxy_address: str, result: ValidationResult):
        """Record a validation result for analytics"""
        
        with self.lock:
            # Store validation result
            self.validation_history[proxy_address].append(result)
            
            # Update real-time metrics
            self._update_current_metrics(result)
            
            # Clean old data
            self._cleanup_old_data()
    
    def record_health_score(self, proxy_address: str, health_score: HealthScore):
        """Record a health score for analytics"""
        
        with self.lock:
            self.health_scores[proxy_address].append((datetime.now(), health_score))
    
    def record_sla_compliance(self, proxy_address: str, compliance: Dict[SLATier, SLACompliance]):
        """Record SLA compliance data"""
        
        with self.lock:
            self.sla_compliance_history[proxy_address].append((datetime.now(), compliance))
    
    def record_reputation_data(self, proxy_address: str, reputation: IPReputationSummary):
        """Record IP reputation data"""
        
        with self.lock:
            self.reputation_history[proxy_address].append((datetime.now(), reputation))
    
    def generate_comprehensive_report(self, timeframe: AnalyticsTimeframe = AnalyticsTimeframe.LAST_24_HOURS,
                                    custom_start: datetime = None,
                                    custom_end: datetime = None) -> ValidationReport:
        """Generate comprehensive validation report"""
        
        # Determine time range
        start_time, end_time = self._get_timeframe_bounds(timeframe, custom_start, custom_end)
        
        # Collect data for the timeframe
        filtered_data = self._filter_data_by_timeframe(start_time, end_time)
        
        # Generate report ID
        report_id = f"validation_report_{int(time.time())}"
        
        # Create report
        report = ValidationReport(
            report_id=report_id,
            generated_at=datetime.now(),
            timeframe=timeframe,
            start_time=start_time,
            end_time=end_time,
            overall_metrics=self._calculate_overall_metrics(filtered_data),
            proxy_count=len(filtered_data)
        )
        
        # Add detailed analysis
        report.source_analysis = self._analyze_proxy_sources(filtered_data)
        report.quality_breakdown = self._analyze_quality_distribution(filtered_data)
        report.protocol_breakdown = self._analyze_protocol_distribution(filtered_data)
        report.country_breakdown = self._analyze_country_distribution(filtered_data)
        report.error_analysis = self._analyze_error_patterns(filtered_data)
        
        # Generate trend analysis
        report.trends = self._generate_trend_analysis(filtered_data, start_time, end_time)
        
        # Identify top performers and problems
        report.top_performers = self._identify_top_performers(filtered_data)
        report.problem_proxies = self._identify_problem_proxies(filtered_data)
        
        # Generate recommendations
        report.recommendations = self._generate_recommendations(report)
        
        return report
    
    def _get_timeframe_bounds(self, timeframe: AnalyticsTimeframe,
                            custom_start: datetime = None,
                            custom_end: datetime = None) -> Tuple[datetime, datetime]:
        """Get start and end times for timeframe"""
        
        end_time = custom_end or datetime.now()
        
        if timeframe == AnalyticsTimeframe.LAST_HOUR:
            start_time = end_time - timedelta(hours=1)
        elif timeframe == AnalyticsTimeframe.LAST_24_HOURS:
            start_time = end_time - timedelta(hours=24)
        elif timeframe == AnalyticsTimeframe.LAST_7_DAYS:
            start_time = end_time - timedelta(days=7)
        elif timeframe == AnalyticsTimeframe.LAST_30_DAYS:
            start_time = end_time - timedelta(days=30)
        elif timeframe == AnalyticsTimeframe.CUSTOM:
            start_time = custom_start or (end_time - timedelta(hours=24))
        else:
            start_time = end_time - timedelta(hours=24)
        
        return start_time, end_time
    
    def _filter_data_by_timeframe(self, start_time: datetime, 
                                end_time: datetime) -> Dict[str, List[ValidationResult]]:
        """Filter validation data by timeframe"""
        
        filtered_data = {}
        
        for proxy_address, results in self.validation_history.items():
            filtered_results = [
                r for r in results 
                if start_time <= r.timestamp <= end_time
            ]
            
            if filtered_results:
                filtered_data[proxy_address] = filtered_results
        
        return filtered_data
    
    def _calculate_overall_metrics(self, data: Dict[str, List[ValidationResult]]) -> ValidationMetrics:
        """Calculate overall metrics from filtered data"""
        
        all_results = []
        for results in data.values():
            all_results.extend(results)
        
        if not all_results:
            return ValidationMetrics()
        
        # Basic counts
        total_validations = len(all_results)
        successful_validations = sum(1 for r in all_results if r.is_valid)
        failed_validations = total_validations - successful_validations
        
        # Success rate
        success_rate = (successful_validations / total_validations) * 100 if total_validations > 0 else 0
        
        # Response time metrics
        response_times = [r.response_time_ms for r in all_results if r.response_time_ms > 0]
        
        avg_response_time = statistics.mean(response_times) if response_times else 0
        median_response_time = statistics.median(response_times) if response_times else 0
        
        response_time_p95 = 0
        if response_times:
            sorted_times = sorted(response_times)
            p95_index = int(len(sorted_times) * 0.95)
            response_time_p95 = sorted_times[min(p95_index, len(sorted_times) - 1)]
        
        # Confidence metrics
        confidence_scores = [r.confidence_score for r in all_results if r.confidence_score > 0]
        avg_confidence = statistics.mean(confidence_scores) if confidence_scores else 0
        
        # Time span
        timestamps = [r.timestamp for r in all_results]
        validation_timespan = max(timestamps) - min(timestamps) if len(timestamps) > 1 else timedelta(0)
        
        return ValidationMetrics(
            total_validations=total_validations,
            successful_validations=successful_validations,
            failed_validations=failed_validations,
            success_rate=success_rate,
            average_response_time=avg_response_time,
            median_response_time=median_response_time,
            response_time_p95=response_time_p95,
            average_confidence=avg_confidence,
            unique_proxies=len(data),
            validation_timespan=validation_timespan
        )
    
    def _analyze_proxy_sources(self, data: Dict[str, List[ValidationResult]]) -> List[ProxySourceAnalysis]:
        """Analyze validation data by proxy source"""
        
        # Group by source (assuming proxy addresses contain source info)
        source_groups = defaultdict(list)
        
        for proxy_address, results in data.items():
            # Extract source from proxy metadata or use "unknown"
            source = "unknown"
            if results and results[0].metadata.get('source'):
                source = results[0].metadata['source']
            
            source_groups[source].extend(results)
        
        source_analyses = []
        
        for source_name, results in source_groups.items():
            if not results:
                continue
            
            # Calculate metrics for this source
            total_validations = len(results)
            successful_validations = sum(1 for r in results if r.is_valid)
            success_rate = (successful_validations / total_validations) * 100 if total_validations > 0 else 0
            
            # Error analysis
            errors = [r.error_category for r in results if r.error_category]
            error_counts = Counter(errors)
            common_errors = error_counts.most_common(5)
            
            # Unique proxy count
            unique_proxies = len(set(r.proxy_address for r in results))
            
            analysis = ProxySourceAnalysis(
                source_name=source_name,
                proxy_count=unique_proxies,
                success_rate=success_rate,
                common_errors=common_errors
            )
            
            source_analyses.append(analysis)
        
        return source_analyses
    
    def _analyze_quality_distribution(self, data: Dict[str, List[ValidationResult]]) -> Dict[ProxyQualityTier, int]:
        """Analyze quality tier distribution"""
        
        # This would require health scores which aren't directly in ValidationResult
        # For now, return placeholder distribution
        return {
            ProxyQualityTier.PREMIUM: 0,
            ProxyQualityTier.EXCELLENT: 0,
            ProxyQualityTier.GOOD: 0,
            ProxyQualityTier.AVERAGE: 0,
            ProxyQualityTier.POOR: 0,
            ProxyQualityTier.UNUSABLE: 0
        }
    
    def _analyze_protocol_distribution(self, data: Dict[str, List[ValidationResult]]) -> Dict[ProxyProtocol, int]:
        """Analyze protocol distribution"""
        
        protocol_counts = defaultdict(int)
        
        for proxy_address, results in data.items():
            # Extract protocol from metadata or proxy address
            protocol = None
            if results and results[0].metadata.get('protocol'):
                protocol = results[0].metadata['protocol']
            
            if protocol:
                protocol_counts[protocol] += 1
        
        return dict(protocol_counts)
    
    def _analyze_country_distribution(self, data: Dict[str, List[ValidationResult]]) -> Dict[str, int]:
        """Analyze country distribution"""
        
        country_counts = defaultdict(int)
        
        for proxy_address, results in data.items():
            # Extract country from metadata
            country = "Unknown"
            if results and results[0].metadata.get('country'):
                country = results[0].metadata['country']
            
            country_counts[country] += 1
        
        return dict(country_counts)
    
    def _analyze_error_patterns(self, data: Dict[str, List[ValidationResult]]) -> Dict[ValidationErrorCategory, int]:
        """Analyze error patterns"""
        
        error_counts = defaultdict(int)
        
        for results in data.values():
            for result in results:
                if not result.is_valid and result.error_category:
                    error_counts[result.error_category] += 1
        
        return dict(error_counts)
    
    def _generate_trend_analysis(self, data: Dict[str, List[ValidationResult]],
                               start_time: datetime, end_time: datetime) -> List[TrendAnalysis]:
        """Generate trend analysis for key metrics"""
        
        trends = []
        
        # Success rate trend
        success_rate_trend = self._calculate_metric_trend(
            data, MetricType.SUCCESS_RATE, start_time, end_time
        )
        if success_rate_trend:
            trends.append(success_rate_trend)
        
        # Response time trend
        response_time_trend = self._calculate_metric_trend(
            data, MetricType.RESPONSE_TIME, start_time, end_time
        )
        if response_time_trend:
            trends.append(response_time_trend)
        
        return trends
    
    def _calculate_metric_trend(self, data: Dict[str, List[ValidationResult]],
                              metric_type: MetricType, start_time: datetime,
                              end_time: datetime) -> Optional[TrendAnalysis]:
        """Calculate trend for specific metric"""
        
        # Group data by time intervals (hourly)
        interval = timedelta(hours=1)
        current_time = start_time
        data_points = []
        
        while current_time < end_time:
            interval_end = min(current_time + interval, end_time)
            
            # Collect data for this interval
            interval_results = []
            for results in data.values():
                interval_results.extend([
                    r for r in results 
                    if current_time <= r.timestamp < interval_end
                ])
            
            if interval_results:
                if metric_type == MetricType.SUCCESS_RATE:
                    value = (sum(1 for r in interval_results if r.is_valid) / len(interval_results)) * 100
                elif metric_type == MetricType.RESPONSE_TIME:
                    response_times = [r.response_time_ms for r in interval_results if r.response_time_ms > 0]
                    value = statistics.mean(response_times) if response_times else 0
                else:
                    value = 0
                
                data_points.append((current_time, value))
            
            current_time += interval
        
        if len(data_points) < 2:
            return None
        
        # Calculate trend
        trend_analysis = TrendAnalysis(
            metric_name=metric_type.value,
            timeframe=AnalyticsTimeframe.CUSTOM,
            data_points=data_points
        )
        
        # Calculate slope and trend direction
        if HAS_NUMPY:
            x_values = np.array([(dt - data_points[0][0]).total_seconds() for dt, _ in data_points])
            y_values = np.array([value for _, value in data_points])
            
            # Linear regression
            slope, intercept = np.polyfit(x_values, y_values, 1)
            
            trend_analysis.slope = slope
            
            # Determine trend direction
            if abs(slope) < 0.01:  # Threshold for "stable"
                trend_analysis.trend_direction = "stable"
                trend_analysis.trend_strength = 0.0
            elif slope > 0:
                trend_analysis.trend_direction = "increasing"
                trend_analysis.trend_strength = min(1.0, abs(slope) / max(y_values))
            else:
                trend_analysis.trend_direction = "decreasing"
                trend_analysis.trend_strength = min(1.0, abs(slope) / max(y_values))
            
            # Calculate R-squared
            y_mean = np.mean(y_values)
            ss_tot = np.sum((y_values - y_mean) ** 2)
            ss_res = np.sum((y_values - (slope * x_values + intercept)) ** 2)
            trend_analysis.r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0
            
            # Simple forecast (24 hours ahead)
            forecast_x = x_values[-1] + 24 * 3600  # 24 hours in seconds
            trend_analysis.forecast_24h = slope * forecast_x + intercept
        
        return trend_analysis
    
    def _identify_top_performers(self, data: Dict[str, List[ValidationResult]]) -> List[Tuple[str, float]]:
        """Identify top performing proxies"""
        
        proxy_scores = []
        
        for proxy_address, results in data.items():
            if not results:
                continue
            
            # Calculate performance score
            successful_validations = sum(1 for r in results if r.is_valid)
            success_rate = successful_validations / len(results)
            
            # Average response time for successful validations
            successful_times = [r.response_time_ms for r in results if r.is_valid and r.response_time_ms > 0]
            avg_response_time = statistics.mean(successful_times) if successful_times else float('inf')
            
            # Simple scoring: success_rate * (1000 / avg_response_time)
            if avg_response_time > 0 and avg_response_time < 10000:  # Reasonable response time
                score = success_rate * (1000 / avg_response_time)
            else:
                score = success_rate * 0.1
            
            proxy_scores.append((proxy_address, score))
        
        # Return top 10
        return sorted(proxy_scores, key=lambda x: x[1], reverse=True)[:10]
    
    def _identify_problem_proxies(self, data: Dict[str, List[ValidationResult]]) -> List[Tuple[str, str]]:
        """Identify problematic proxies"""
        
        problem_proxies = []
        
        for proxy_address, results in data.items():
            if not results:
                continue
            
            # Calculate success rate
            successful_validations = sum(1 for r in results if r.is_valid)
            success_rate = successful_validations / len(results)
            
            # Identify issues
            issues = []
            
            if success_rate < 0.3:
                issues.append("Low success rate")
            
            # Check for consistent errors
            errors = [r.error_category for r in results if r.error_category]
            if errors:
                most_common_error = Counter(errors).most_common(1)[0]
                if most_common_error[1] / len(results) > 0.5:
                    issues.append(f"Frequent {most_common_error[0].value} errors")
            
            # Check response times
            response_times = [r.response_time_ms for r in results if r.is_valid and r.response_time_ms > 0]
            if response_times:
                avg_response_time = statistics.mean(response_times)
                if avg_response_time > 5000:
                    issues.append("Slow response times")
            
            if issues:
                problem_proxies.append((proxy_address, "; ".join(issues)))
        
        return problem_proxies[:10]  # Return top 10 problem proxies
    
    def _generate_recommendations(self, report: ValidationReport) -> List[str]:
        """Generate actionable recommendations based on report data"""
        
        recommendations = []
        
        # Success rate recommendations
        if report.overall_metrics.success_rate < 70:
            recommendations.append("Overall success rate is low. Consider reviewing proxy sources and validation criteria.")
        
        # Response time recommendations
        if report.overall_metrics.average_response_time > 3000:
            recommendations.append("Average response time is high. Consider implementing timeout optimizations or filtering slow proxies.")
        
        # Error pattern recommendations
        if report.error_analysis:
            top_error = max(report.error_analysis.items(), key=lambda x: x[1])
            if top_error[1] > report.overall_metrics.total_validations * 0.3:
                recommendations.append(f"High frequency of {top_error[0].value} errors. Investigate and address root cause.")
        
        # Quality recommendations
        if report.problem_proxies:
            recommendations.append(f"Identified {len(report.problem_proxies)} problematic proxies. Consider removing or investigating these proxies.")
        
        # Source recommendations
        if len(report.source_analysis) > 1:
            best_source = max(report.source_analysis, key=lambda x: x.success_rate)
            worst_source = min(report.source_analysis, key=lambda x: x.success_rate)
            
            if best_source.success_rate - worst_source.success_rate > 20:
                recommendations.append(f"Source '{best_source.source_name}' performs significantly better than '{worst_source.source_name}'. Consider prioritizing better sources.")
        
        return recommendations
    
    def _update_current_metrics(self, result: ValidationResult):
        """Update real-time metrics with new result"""
        
        self.current_metrics.total_validations += 1
        
        if result.is_valid:
            self.current_metrics.successful_validations += 1
        else:
            self.current_metrics.failed_validations += 1
        
        # Update success rate
        self.current_metrics.success_rate = (
            self.current_metrics.successful_validations / 
            self.current_metrics.total_validations
        ) * 100
        
        # Track response times
        if result.response_time_ms > 0:
            self.response_time_history.append(result.response_time_ms)
            
            # Update average response time
            self.current_metrics.average_response_time = statistics.mean(self.response_time_history)
    
    def _cleanup_old_data(self):
        """Clean up old validation data beyond retention period"""
        
        cutoff_time = datetime.now() - self.data_retention
        
        # Clean validation history
        for proxy_address in list(self.validation_history.keys()):
            self.validation_history[proxy_address] = [
                r for r in self.validation_history[proxy_address]
                if r.timestamp >= cutoff_time
            ]
            
            # Remove empty entries
            if not self.validation_history[proxy_address]:
                del self.validation_history[proxy_address]
        
        # Clean other histories
        for proxy_address in list(self.health_scores.keys()):
            self.health_scores[proxy_address] = [
                (dt, score) for dt, score in self.health_scores[proxy_address]
                if dt >= cutoff_time
            ]
            
            if not self.health_scores[proxy_address]:
                del self.health_scores[proxy_address]
    
    def export_report(self, report: ValidationReport, format_type: ReportFormat,
                     output_path: Path) -> bool:
        """Export report in specified format"""
        
        try:
            if format_type == ReportFormat.JSON:
                with open(output_path, 'w') as f:
                    json.dump(report.to_dict(), f, indent=2, default=str)
            
            elif format_type == ReportFormat.CSV and HAS_PANDAS:
                # Convert to DataFrame and export
                df = pd.DataFrame([report.overall_metrics.to_dict()])
                df.to_csv(output_path, index=False)
            
            elif format_type == ReportFormat.HTML:
                self._export_html_report(report, output_path)
            
            elif format_type == ReportFormat.MARKDOWN:
                self._export_markdown_report(report, output_path)
            
            else:
                log_structured('WARNING', f"Unsupported export format: {format_type}")
                return False
            
            log_structured('INFO', f"Report exported to {output_path}")
            return True
        
        except Exception as e:
            log_structured('ERROR', f"Failed to export report: {e}")
            return False
    
    def _export_html_report(self, report: ValidationReport, output_path: Path):
        """Export report as HTML"""
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Proxy Validation Report - {report.report_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .metric {{ margin: 10px 0; }}
                .section {{ margin: 20px 0; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Proxy Validation Report</h1>
                <p><strong>Report ID:</strong> {report.report_id}</p>
                <p><strong>Generated:</strong> {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Timeframe:</strong> {report.timeframe.value}</p>
            </div>
            
            <div class="section">
                <h2>Overall Metrics</h2>
                <div class="metric"><strong>Total Validations:</strong> {report.overall_metrics.total_validations}</div>
                <div class="metric"><strong>Success Rate:</strong> {report.overall_metrics.success_rate:.1f}%</div>
                <div class="metric"><strong>Average Response Time:</strong> {report.overall_metrics.average_response_time:.1f}ms</div>
                <div class="metric"><strong>Unique Proxies:</strong> {report.overall_metrics.unique_proxies}</div>
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
                <ul>
                    {''.join(f'<li>{rec}</li>' for rec in report.recommendations)}
                </ul>
            </div>
        </body>
        </html>
        """
        
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    def _export_markdown_report(self, report: ValidationReport, output_path: Path):
        """Export report as Markdown"""
        
        markdown_content = f"""# Proxy Validation Report

**Report ID:** {report.report_id}  
**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}  
**Timeframe:** {report.timeframe.value}  

## Overall Metrics

- **Total Validations:** {report.overall_metrics.total_validations}
- **Success Rate:** {report.overall_metrics.success_rate:.1f}%
- **Average Response Time:** {report.overall_metrics.average_response_time:.1f}ms
- **Unique Proxies:** {report.overall_metrics.unique_proxies}

## Recommendations

{chr(10).join(f'- {rec}' for rec in report.recommendations)}

## Error Analysis

| Error Category | Count |
|----------------|-------|
{chr(10).join(f'| {error.value} | {count} |' for error, count in report.error_analysis.items())}
"""
        
        with open(output_path, 'w') as f:
            f.write(markdown_content)
    
    def get_real_time_dashboard_data(self) -> Dict[str, Any]:
        """Get real-time dashboard data"""
        
        return {
            'current_metrics': self.current_metrics.to_dict(),
            'active_proxies': len(self.validation_history),
            'recent_response_times': list(self.response_time_history)[-50:],  # Last 50 measurements
            'recent_success_rates': list(self.success_rate_history)[-20:],    # Last 20 measurements
            'last_updated': datetime.now().isoformat()
        }


# Export key classes
__all__ = [
    'ReportFormat', 'AnalyticsTimeframe', 'MetricType',
    'ValidationMetrics', 'ProxySourceAnalysis', 'TrendAnalysis', 'ValidationReport',
    'ValidationAnalytics'
]