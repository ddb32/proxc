#!/usr/bin/env python3
"""
Historical Performance Tracking System - Phase 4.2.2

Comprehensive system for tracking proxy performance over time, storing historical
data, and providing trend analysis and performance predictions.

Features:
- Time-series performance data storage
- Performance trend analysis and prediction
- Historical comparison and benchmarking
- Performance degradation detection
- Data retention and archival policies
- Performance reporting and visualization
- Statistical analysis and insights
"""

import asyncio
import json
import logging
import sqlite3
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union, Iterator
import numpy as np
from concurrent.futures import ThreadPoolExecutor

from ..proxy_core.models import ProxyInfo, ProxyProtocol, ProxyStatus
from ..proxy_core.database import DatabaseManager


class PerformanceMetric(Enum):
    """Types of performance metrics to track"""
    RESPONSE_TIME = "response_time_ms"
    UPTIME = "uptime_percentage"
    SUCCESS_RATE = "success_rate"
    THROUGHPUT = "throughput_mbps"
    ERROR_RATE = "error_rate"
    AVAILABILITY = "availability"
    LATENCY_P95 = "latency_p95"
    LATENCY_P99 = "latency_p99"


class TrendDirection(Enum):
    """Performance trend directions"""
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    VOLATILE = "volatile"
    INSUFFICIENT_DATA = "insufficient_data"


@dataclass
class PerformanceDataPoint:
    """Single performance measurement"""
    timestamp: datetime
    proxy_id: str
    metric: PerformanceMetric
    value: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'proxy_id': self.proxy_id,
            'metric': self.metric.value,
            'value': self.value,
            'metadata': json.dumps(self.metadata)
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PerformanceDataPoint':
        """Create from dictionary"""
        return cls(
            timestamp=datetime.fromisoformat(data['timestamp']),
            proxy_id=data['proxy_id'],
            metric=PerformanceMetric(data['metric']),
            value=data['value'],
            metadata=json.loads(data.get('metadata', '{}'))
        )


@dataclass
class PerformanceTrend:
    """Performance trend analysis results"""
    proxy_id: str
    metric: PerformanceMetric
    direction: TrendDirection
    trend_strength: float  # 0-1, how strong the trend is
    current_value: float
    historical_average: float
    change_percentage: float
    prediction_7d: Optional[float] = None
    prediction_30d: Optional[float] = None
    confidence_score: float = 0.0
    
    # Statistical data
    data_points: int = 0
    time_span_days: int = 0
    variance: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return asdict(self)


@dataclass
class PerformanceReport:
    """Comprehensive performance report"""
    proxy_id: str
    generated_at: datetime
    report_period_days: int
    
    # Summary statistics
    overall_score: float
    trends: List[PerformanceTrend]
    key_insights: List[str]
    
    # Detailed metrics
    response_time_stats: Dict[str, float]
    uptime_stats: Dict[str, float]
    reliability_stats: Dict[str, float]
    
    # Recommendations
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'proxy_id': self.proxy_id,
            'generated_at': self.generated_at.isoformat(),
            'report_period_days': self.report_period_days,
            'overall_score': self.overall_score,
            'trends': [trend.to_dict() for trend in self.trends],
            'key_insights': self.key_insights,
            'response_time_stats': self.response_time_stats,
            'uptime_stats': self.uptime_stats,
            'reliability_stats': self.reliability_stats,
            'recommendations': self.recommendations
        }


class PerformanceDatabase:
    """Database manager for performance tracking data"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self._init_database()
    
    def _init_database(self):
        """Initialize performance tracking database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS performance_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    proxy_id TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    value REAL NOT NULL,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS performance_summaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    proxy_id TEXT NOT NULL,
                    date TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    min_value REAL,
                    max_value REAL,
                    avg_value REAL,
                    median_value REAL,
                    std_value REAL,
                    sample_count INTEGER,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(proxy_id, date, metric)
                )
            """)
            
            # Create indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_perf_proxy_timestamp ON performance_data(proxy_id, timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_perf_metric_timestamp ON performance_data(metric, timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_summary_proxy_date ON performance_summaries(proxy_id, date)")
    
    def store_data_point(self, data_point: PerformanceDataPoint):
        """Store a single performance data point"""
        with sqlite3.connect(self.db_path) as conn:
            data = data_point.to_dict()
            conn.execute("""
                INSERT INTO performance_data (timestamp, proxy_id, metric, value, metadata)
                VALUES (?, ?, ?, ?, ?)
            """, (data['timestamp'], data['proxy_id'], data['metric'], data['value'], data['metadata']))
    
    def store_data_points_batch(self, data_points: List[PerformanceDataPoint]):
        """Store multiple performance data points efficiently"""
        if not data_points:
            return
        
        with sqlite3.connect(self.db_path) as conn:
            data_list = [
                (dp.to_dict()['timestamp'], dp.to_dict()['proxy_id'], 
                 dp.to_dict()['metric'], dp.to_dict()['value'], dp.to_dict()['metadata'])
                for dp in data_points
            ]
            
            conn.executemany("""
                INSERT INTO performance_data (timestamp, proxy_id, metric, value, metadata)
                VALUES (?, ?, ?, ?, ?)
            """, data_list)
    
    def get_data_points(self, proxy_id: str = None, 
                       metric: PerformanceMetric = None,
                       start_time: datetime = None,
                       end_time: datetime = None,
                       limit: int = None) -> List[PerformanceDataPoint]:
        """Retrieve performance data points with filtering"""
        
        query = "SELECT timestamp, proxy_id, metric, value, metadata FROM performance_data WHERE 1=1"
        params = []
        
        if proxy_id:
            query += " AND proxy_id = ?"
            params.append(proxy_id)
        
        if metric:
            query += " AND metric = ?"
            params.append(metric.value)
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())
        
        query += " ORDER BY timestamp DESC"
        
        if limit:
            query += f" LIMIT {limit}"
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(query, params)
            results = []
            
            for row in cursor.fetchall():
                data = {
                    'timestamp': row[0],
                    'proxy_id': row[1],
                    'metric': row[2],
                    'value': row[3],
                    'metadata': row[4] or '{}'
                }
                results.append(PerformanceDataPoint.from_dict(data))
            
            return results
    
    def cleanup_old_data(self, retention_days: int = 90):
        """Remove old performance data based on retention policy"""
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        with sqlite3.connect(self.db_path) as conn:
            result = conn.execute("""
                DELETE FROM performance_data 
                WHERE timestamp < ?
            """, (cutoff_date.isoformat(),))
            
            deleted_count = result.rowcount
            self.logger.info(f"Cleaned up {deleted_count} old performance data points")
            return deleted_count


class PerformanceTracker:
    """Main performance tracking system"""
    
    def __init__(self, db_path: str = None, config: Dict[str, Any] = None):
        self.db_path = db_path or "performance_tracking.db"
        self.config = config or self._get_default_config()
        self.database = PerformanceDatabase(self.db_path)
        self.logger = logging.getLogger(__name__)
        
        # In-memory buffers for real-time data
        self.data_buffer = deque(maxlen=1000)
        self.last_flush = time.time()
        
        # Statistics cache
        self.stats_cache = {}
        self.cache_ttl = 300  # 5 minutes
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'flush_interval_seconds': 60,
            'batch_size': 100,
            'retention_days': 90,
            'trend_analysis_min_points': 10,
            'prediction_model': 'linear',
            'outlier_threshold_std': 3.0
        }
    
    async def record_performance(self, proxy: ProxyInfo, 
                               metrics: Dict[PerformanceMetric, float],
                               metadata: Dict[str, Any] = None):
        """Record performance metrics for a proxy"""
        
        proxy_id = f"{proxy.host}:{proxy.port}"
        timestamp = datetime.now()
        metadata = metadata or {}
        
        # Create data points
        data_points = []
        for metric, value in metrics.items():
            data_point = PerformanceDataPoint(
                timestamp=timestamp,
                proxy_id=proxy_id,
                metric=metric,
                value=value,
                metadata=metadata.copy()
            )
            data_points.append(data_point)
        
        # Add to buffer
        self.data_buffer.extend(data_points)
        
        # Flush if needed
        if (time.time() - self.last_flush > self.config['flush_interval_seconds'] or 
            len(self.data_buffer) >= self.config['batch_size']):
            await self._flush_buffer()
    
    async def _flush_buffer(self):
        """Flush buffered data to database"""
        if not self.data_buffer:
            return
        
        # Get all data points and clear buffer
        data_points = list(self.data_buffer)
        self.data_buffer.clear()
        
        # Store in database
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, self.database.store_data_points_batch, data_points
            )
            self.last_flush = time.time()
            self.logger.debug(f"Flushed {len(data_points)} performance data points")
        except Exception as e:
            self.logger.error(f"Error flushing performance data: {e}")
            # Re-add to buffer on error
            self.data_buffer.extend(data_points)
    
    async def get_performance_history(self, proxy: ProxyInfo,
                                    metric: PerformanceMetric,
                                    days: int = 30) -> List[PerformanceDataPoint]:
        """Get performance history for a proxy"""
        
        proxy_id = f"{proxy.host}:{proxy.port}"
        start_time = datetime.now() - timedelta(days=days)
        
        return await asyncio.get_event_loop().run_in_executor(
            None, self.database.get_data_points, proxy_id, metric, start_time, None, None
        )
    
    async def analyze_performance_trend(self, proxy: ProxyInfo,
                                      metric: PerformanceMetric,
                                      days: int = 30) -> PerformanceTrend:
        """Analyze performance trend for a specific metric"""
        
        # Get historical data
        data_points = await self.get_performance_history(proxy, metric, days)
        
        if len(data_points) < self.config['trend_analysis_min_points']:
            return PerformanceTrend(
                proxy_id=f"{proxy.host}:{proxy.port}",
                metric=metric,
                direction=TrendDirection.INSUFFICIENT_DATA,
                trend_strength=0.0,
                current_value=0.0,
                historical_average=0.0,
                change_percentage=0.0
            )
        
        # Extract values and timestamps
        values = [dp.value for dp in data_points]
        timestamps = [dp.timestamp.timestamp() for dp in data_points]
        
        # Calculate trend statistics
        current_value = values[0] if values else 0.0  # Most recent (first in DESC order)
        historical_average = statistics.mean(values)
        
        # Linear regression for trend
        if len(values) >= 2:
            # Simple linear regression
            n = len(values)
            sum_x = sum(range(n))
            sum_y = sum(values)
            sum_xy = sum(i * v for i, v in enumerate(values))
            sum_x2 = sum(i * i for i in range(n))
            
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
            
            # Determine trend direction and strength
            if abs(slope) < 0.01:  # Very small slope
                direction = TrendDirection.STABLE
                trend_strength = 0.1
            elif slope > 0:
                direction = TrendDirection.IMPROVING if metric in [PerformanceMetric.UPTIME, PerformanceMetric.SUCCESS_RATE, PerformanceMetric.THROUGHPUT] else TrendDirection.DEGRADING
                trend_strength = min(1.0, abs(slope) * 100)
            else:
                direction = TrendDirection.DEGRADING if metric in [PerformanceMetric.UPTIME, PerformanceMetric.SUCCESS_RATE, PerformanceMetric.THROUGHPUT] else TrendDirection.IMPROVING
                trend_strength = min(1.0, abs(slope) * 100)
            
            # Check for volatility
            variance = statistics.variance(values) if len(values) > 1 else 0
            if variance > historical_average * 0.5:  # High variance
                direction = TrendDirection.VOLATILE
                trend_strength = min(1.0, variance / historical_average)
        else:
            direction = TrendDirection.STABLE
            trend_strength = 0.0
            slope = 0.0
        
        # Calculate change percentage
        if historical_average > 0:
            change_percentage = ((current_value - historical_average) / historical_average) * 100
        else:
            change_percentage = 0.0
        
        # Simple prediction (linear extrapolation)
        prediction_7d = current_value + (slope * 7) if abs(slope) > 0.001 else current_value
        prediction_30d = current_value + (slope * 30) if abs(slope) > 0.001 else current_value
        
        # Confidence score based on data quality
        confidence_score = min(1.0, len(values) / 100.0)  # More data = higher confidence
        if variance > 0:
            coefficient_of_variation = (variance ** 0.5) / historical_average if historical_average > 0 else 1.0
            confidence_score *= max(0.1, 1.0 - coefficient_of_variation)
        
        return PerformanceTrend(
            proxy_id=f"{proxy.host}:{proxy.port}",
            metric=metric,
            direction=direction,
            trend_strength=trend_strength,
            current_value=current_value,
            historical_average=historical_average,
            change_percentage=change_percentage,
            prediction_7d=prediction_7d,
            prediction_30d=prediction_30d,
            confidence_score=confidence_score,
            data_points=len(values),
            time_span_days=days,
            variance=variance if len(values) > 1 else 0.0
        )
    
    async def generate_performance_report(self, proxy: ProxyInfo,
                                        days: int = 30) -> PerformanceReport:
        """Generate comprehensive performance report"""
        
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        # Analyze trends for all metrics
        metrics_to_analyze = [
            PerformanceMetric.RESPONSE_TIME,
            PerformanceMetric.UPTIME,
            PerformanceMetric.SUCCESS_RATE,
            PerformanceMetric.THROUGHPUT
        ]
        
        trends = []
        for metric in metrics_to_analyze:
            trend = await self.analyze_performance_trend(proxy, metric, days)
            trends.append(trend)
        
        # Get detailed statistics
        response_time_data = await self.get_performance_history(proxy, PerformanceMetric.RESPONSE_TIME, days)
        uptime_data = await self.get_performance_history(proxy, PerformanceMetric.UPTIME, days)
        
        # Calculate statistics
        response_time_stats = self._calculate_stats([dp.value for dp in response_time_data])
        uptime_stats = self._calculate_stats([dp.value for dp in uptime_data])
        
        # Calculate overall score
        overall_score = self._calculate_overall_score(trends)
        
        # Generate insights
        key_insights = self._generate_insights(trends)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(trends)
        
        # Calculate reliability stats
        reliability_stats = {
            'availability_percentage': uptime_stats.get('mean', 0),
            'consistency_score': 100 - (uptime_stats.get('std', 0) * 10),  # Lower std = higher consistency
            'reliability_trend': next((t.direction.value for t in trends if t.metric == PerformanceMetric.UPTIME), 'unknown')
        }
        
        return PerformanceReport(
            proxy_id=proxy_id,
            generated_at=datetime.now(),
            report_period_days=days,
            overall_score=overall_score,
            trends=trends,
            key_insights=key_insights,
            response_time_stats=response_time_stats,
            uptime_stats=uptime_stats,
            reliability_stats=reliability_stats,
            recommendations=recommendations
        )
    
    def _calculate_stats(self, values: List[float]) -> Dict[str, float]:
        """Calculate statistical summary"""
        if not values:
            return {}
        
        return {
            'count': len(values),
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'std': statistics.stdev(values) if len(values) > 1 else 0,
            'min': min(values),
            'max': max(values),
            'p95': np.percentile(values, 95) if len(values) >= 2 else max(values),
            'p99': np.percentile(values, 99) if len(values) >= 2 else max(values)
        }
    
    def _calculate_overall_score(self, trends: List[PerformanceTrend]) -> float:
        """Calculate overall performance score from trends"""
        if not trends:
            return 50.0
        
        score = 0.0
        weights = {
            PerformanceMetric.RESPONSE_TIME: 0.3,
            PerformanceMetric.UPTIME: 0.3,
            PerformanceMetric.SUCCESS_RATE: 0.25,
            PerformanceMetric.THROUGHPUT: 0.15
        }
        
        for trend in trends:
            weight = weights.get(trend.metric, 0.1)
            
            # Base score from current value
            if trend.metric == PerformanceMetric.RESPONSE_TIME:
                # Lower response time is better
                base_score = max(0, 100 - (trend.current_value / 10))
            elif trend.metric in [PerformanceMetric.UPTIME, PerformanceMetric.SUCCESS_RATE]:
                # Higher percentage is better
                base_score = trend.current_value
            else:
                # For throughput, normalize to 0-100 scale
                base_score = min(100, trend.current_value * 10)
            
            # Adjust based on trend direction
            if trend.direction == TrendDirection.IMPROVING:
                base_score += trend.trend_strength * 10
            elif trend.direction == TrendDirection.DEGRADING:
                base_score -= trend.trend_strength * 10
            elif trend.direction == TrendDirection.VOLATILE:
                base_score -= trend.trend_strength * 5
            
            score += base_score * weight
        
        return max(0, min(100, score))
    
    def _generate_insights(self, trends: List[PerformanceTrend]) -> List[str]:
        """Generate key insights from performance trends"""
        insights = []
        
        for trend in trends:
            if trend.direction == TrendDirection.INSUFFICIENT_DATA:
                continue
            
            metric_name = trend.metric.value.replace('_', ' ').title()
            
            if trend.direction == TrendDirection.IMPROVING and trend.trend_strength > 0.5:
                insights.append(f"{metric_name} is showing strong improvement ({trend.change_percentage:+.1f}%)")
            elif trend.direction == TrendDirection.DEGRADING and trend.trend_strength > 0.5:
                insights.append(f"{metric_name} is degrading significantly ({trend.change_percentage:+.1f}%)")
            elif trend.direction == TrendDirection.VOLATILE:
                insights.append(f"{metric_name} shows high volatility (variance: {trend.variance:.2f})")
            elif trend.direction == TrendDirection.STABLE:
                insights.append(f"{metric_name} remains stable around {trend.historical_average:.2f}")
        
        return insights
    
    def _generate_recommendations(self, trends: List[PerformanceTrend]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        for trend in trends:
            if trend.direction == TrendDirection.INSUFFICIENT_DATA:
                recommendations.append("Collect more performance data for better analysis")
                continue
            
            if trend.metric == PerformanceMetric.RESPONSE_TIME:
                if trend.direction == TrendDirection.DEGRADING:
                    recommendations.append("Consider investigating network conditions or proxy server load")
                elif trend.current_value > 1000:  # >1s response time
                    recommendations.append("Response time is high - consider switching to a faster proxy")
            
            elif trend.metric == PerformanceMetric.UPTIME:
                if trend.direction == TrendDirection.DEGRADING or trend.current_value < 90:
                    recommendations.append("Uptime is concerning - consider finding alternative proxies")
                elif trend.direction == TrendDirection.VOLATILE:
                    recommendations.append("Uptime is unstable - monitor for patterns or schedule-based issues")
            
            elif trend.metric == PerformanceMetric.SUCCESS_RATE:
                if trend.current_value < 80:
                    recommendations.append("Low success rate - verify proxy configuration and authentication")
        
        return recommendations
    
    async def cleanup_old_data(self):
        """Clean up old performance data based on retention policy"""
        return await asyncio.get_event_loop().run_in_executor(
            None, self.database.cleanup_old_data, self.config['retention_days']
        )


class PerformanceAnalyzer:
    """Advanced performance analysis and comparison tools"""
    
    def __init__(self, tracker: PerformanceTracker):
        self.tracker = tracker
        self.logger = logging.getLogger(__name__)
    
    async def compare_proxies(self, proxies: List[ProxyInfo],
                            metric: PerformanceMetric,
                            days: int = 7) -> Dict[str, Any]:
        """Compare performance between multiple proxies"""
        
        results = {}
        proxy_data = {}
        
        # Get performance data for all proxies
        for proxy in proxies:
            proxy_id = f"{proxy.host}:{proxy.port}"
            data_points = await self.tracker.get_performance_history(proxy, metric, days)
            
            if data_points:
                values = [dp.value for dp in data_points]
                proxy_data[proxy_id] = {
                    'values': values,
                    'mean': statistics.mean(values),
                    'median': statistics.median(values),
                    'std': statistics.stdev(values) if len(values) > 1 else 0,
                    'min': min(values),
                    'max': max(values)
                }
        
        if not proxy_data:
            return {'error': 'No data available for comparison'}
        
        # Rank proxies by performance
        if metric == PerformanceMetric.RESPONSE_TIME:
            # Lower is better for response time
            ranked = sorted(proxy_data.items(), key=lambda x: x[1]['mean'])
        else:
            # Higher is better for other metrics
            ranked = sorted(proxy_data.items(), key=lambda x: x[1]['mean'], reverse=True)
        
        return {
            'metric': metric.value,
            'comparison_period_days': days,
            'proxy_count': len(proxy_data),
            'rankings': [{'proxy_id': pid, 'stats': stats} for pid, stats in ranked],
            'best_proxy': ranked[0][0] if ranked else None,
            'worst_proxy': ranked[-1][0] if ranked else None,
            'performance_spread': {
                'best_value': ranked[0][1]['mean'] if ranked else 0,
                'worst_value': ranked[-1][1]['mean'] if ranked else 0,
                'range': ranked[-1][1]['mean'] - ranked[0][1]['mean'] if len(ranked) >= 2 else 0
            }
        }
    
    async def detect_performance_anomalies(self, proxy: ProxyInfo,
                                         metric: PerformanceMetric,
                                         days: int = 30) -> List[Dict[str, Any]]:
        """Detect performance anomalies using statistical methods"""
        
        data_points = await self.tracker.get_performance_history(proxy, metric, days)
        
        if len(data_points) < 10:
            return []
        
        values = [dp.value for dp in data_points]
        timestamps = [dp.timestamp for dp in data_points]
        
        # Calculate statistical thresholds
        mean_value = statistics.mean(values)
        std_value = statistics.stdev(values)
        threshold = self.tracker.config['outlier_threshold_std']
        
        lower_bound = mean_value - (threshold * std_value)
        upper_bound = mean_value + (threshold * std_value)
        
        # Find anomalies
        anomalies = []
        for i, (value, timestamp) in enumerate(zip(values, timestamps)):
            if value < lower_bound or value > upper_bound:
                severity = 'high' if abs(value - mean_value) > threshold * 2 * std_value else 'medium'
                
                anomalies.append({
                    'timestamp': timestamp.isoformat(),
                    'value': value,
                    'expected_range': (lower_bound, upper_bound),
                    'deviation_std': abs(value - mean_value) / std_value,
                    'severity': severity,
                    'type': 'spike' if value > upper_bound else 'drop'
                })
        
        return anomalies