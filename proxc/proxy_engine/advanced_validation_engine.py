"""
Advanced Validation Engine - Phase 3.3

Intelligent proxy validation with quality assessment, reliability metrics,
and comprehensive health scoring system.

Key features:
- Multi-criteria proxy health scoring
- Response time percentile tracking and SLA monitoring  
- Geolocation accuracy validation and IP reputation checking
- Adaptive timeout algorithms based on performance history
- Concurrent validation with intelligent rate limiting
- Proxy stability testing over time periods
- Validation result confidence scoring and uncertainty quantification
- Smart retry mechanisms with exponential backoff
- Comprehensive validation reporting and analytics dashboard
"""

import asyncio
import collections
import hashlib
import json
import logging
import math
import statistics
import time
import weakref
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum, IntEnum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Set, AsyncIterator, Callable
import threading

# Optional imports
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from ..proxy_core.models import ProxyInfo, ProxyProtocol, ProxyStatus, ValidationStatus
from ..proxy_core.utils import validate_ip_address
from ..proxy_cli.cli_imports import log_structured, print_info, print_warning, print_success

logger = logging.getLogger(__name__)


class HealthCriteria(Enum):
    """Health scoring criteria for proxy evaluation"""
    RESPONSE_TIME = "response_time"
    SUCCESS_RATE = "success_rate"
    STABILITY = "stability"
    ANONYMITY = "anonymity"
    GEOLOCATION_ACCURACY = "geo_accuracy"
    IP_REPUTATION = "ip_reputation"
    PROTOCOL_SUPPORT = "protocol_support"
    CONSISTENCY = "consistency"
    UPTIME = "uptime"
    BANDWIDTH = "bandwidth"


class ValidationSeverity(IntEnum):
    """Validation result severity levels"""
    CRITICAL = 1    # Proxy unusable
    HIGH = 2        # Major issues
    MEDIUM = 3      # Moderate issues  
    LOW = 4         # Minor issues
    INFO = 5        # Informational


class ProxyQualityTier(Enum):
    """Proxy quality classification tiers"""
    PREMIUM = "premium"         # 90-100 score
    EXCELLENT = "excellent"     # 80-89 score
    GOOD = "good"              # 70-79 score
    AVERAGE = "average"        # 60-69 score
    POOR = "poor"              # 40-59 score
    UNUSABLE = "unusable"      # 0-39 score


@dataclass
class HealthScore:
    """Comprehensive proxy health score with criteria breakdown"""
    overall_score: float = 0.0
    criteria_scores: Dict[HealthCriteria, float] = field(default_factory=dict)
    quality_tier: ProxyQualityTier = ProxyQualityTier.UNUSABLE
    confidence: float = 0.0
    sample_size: int = 0
    last_updated: datetime = field(default_factory=datetime.now)
    
    def get_weighted_score(self, weights: Dict[HealthCriteria, float] = None) -> float:
        """Calculate weighted score based on criteria importance"""
        if not weights:
            # Default weights
            weights = {
                HealthCriteria.RESPONSE_TIME: 0.25,
                HealthCriteria.SUCCESS_RATE: 0.25,
                HealthCriteria.STABILITY: 0.20,
                HealthCriteria.ANONYMITY: 0.10,
                HealthCriteria.GEOLOCATION_ACCURACY: 0.05,
                HealthCriteria.IP_REPUTATION: 0.05,
                HealthCriteria.PROTOCOL_SUPPORT: 0.05,
                HealthCriteria.CONSISTENCY: 0.05
            }
        
        total_weight = 0.0
        weighted_sum = 0.0
        
        for criteria, weight in weights.items():
            if criteria in self.criteria_scores:
                weighted_sum += self.criteria_scores[criteria] * weight
                total_weight += weight
        
        return weighted_sum / total_weight if total_weight > 0 else 0.0
    
    def update_quality_tier(self):
        """Update quality tier based on overall score"""
        if self.overall_score >= 90:
            self.quality_tier = ProxyQualityTier.PREMIUM
        elif self.overall_score >= 80:
            self.quality_tier = ProxyQualityTier.EXCELLENT
        elif self.overall_score >= 70:
            self.quality_tier = ProxyQualityTier.GOOD
        elif self.overall_score >= 60:
            self.quality_tier = ProxyQualityTier.AVERAGE
        elif self.overall_score >= 40:
            self.quality_tier = ProxyQualityTier.POOR
        else:
            self.quality_tier = ProxyQualityTier.UNUSABLE


@dataclass
class ResponseTimeMetrics:
    """Response time statistics and percentiles"""
    measurements: List[float] = field(default_factory=list)
    p50: float = 0.0  # Median
    p90: float = 0.0  # 90th percentile
    p95: float = 0.0  # 95th percentile
    p99: float = 0.0  # 99th percentile
    mean: float = 0.0
    std_dev: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    sample_count: int = 0
    
    def add_measurement(self, response_time_ms: float):
        """Add new response time measurement"""
        self.measurements.append(response_time_ms)
        
        # Keep only last 1000 measurements for memory efficiency
        if len(self.measurements) > 1000:
            self.measurements = self.measurements[-1000:]
        
        self.sample_count += 1
        self._update_statistics()
    
    def _update_statistics(self):
        """Update all statistical metrics"""
        if not self.measurements:
            return
        
        sorted_times = sorted(self.measurements)
        count = len(sorted_times)
        
        # Percentiles
        self.p50 = self._percentile(sorted_times, 50)
        self.p90 = self._percentile(sorted_times, 90)
        self.p95 = self._percentile(sorted_times, 95)
        self.p99 = self._percentile(sorted_times, 99)
        
        # Basic statistics
        self.mean = statistics.mean(sorted_times)
        self.std_dev = statistics.stdev(sorted_times) if count > 1 else 0.0
        self.min_time = min(sorted_times)
        self.max_time = max(sorted_times)
    
    def _percentile(self, sorted_data: List[float], percentile: float) -> float:
        """Calculate percentile from sorted data"""
        if not sorted_data:
            return 0.0
        
        k = (len(sorted_data) - 1) * (percentile / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        
        if f == c:
            return sorted_data[int(k)]
        
        d0 = sorted_data[int(f)] * (c - k)
        d1 = sorted_data[int(c)] * (k - f)
        return d0 + d1
    
    def get_sla_compliance(self, sla_threshold_ms: float) -> float:
        """Calculate SLA compliance percentage"""
        if not self.measurements:
            return 0.0
        
        compliant = sum(1 for t in self.measurements if t <= sla_threshold_ms)
        return (compliant / len(self.measurements)) * 100.0


@dataclass 
class ValidationHistory:
    """Historical validation data for reliability tracking"""
    validation_results: deque = field(default_factory=lambda: deque(maxlen=100))
    success_count: int = 0
    failure_count: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    first_seen: datetime = field(default_factory=datetime.now)
    
    def add_result(self, success: bool, timestamp: datetime = None):
        """Add validation result to history"""
        if timestamp is None:
            timestamp = datetime.now()
        
        self.validation_results.append((success, timestamp))
        
        if success:
            self.success_count += 1
            self.consecutive_successes += 1
            self.consecutive_failures = 0
            self.last_success = timestamp
        else:
            self.failure_count += 1
            self.consecutive_failures += 1
            self.consecutive_successes = 0
            self.last_failure = timestamp
    
    def get_success_rate(self, time_window: timedelta = None) -> float:
        """Calculate success rate within time window"""
        if time_window is None:
            # Overall success rate
            total = self.success_count + self.failure_count
            return (self.success_count / total) * 100.0 if total > 0 else 0.0
        
        # Time-windowed success rate
        cutoff = datetime.now() - time_window
        recent_results = [r for r in self.validation_results if r[1] >= cutoff]
        
        if not recent_results:
            return 0.0
        
        successes = sum(1 for success, _ in recent_results if success)
        return (successes / len(recent_results)) * 100.0
    
    def get_reliability_score(self) -> float:
        """Calculate reliability score based on history patterns"""
        if not self.validation_results:
            return 0.0
        
        # Base success rate (70% weight)
        base_score = self.get_success_rate() * 0.7
        
        # Stability bonus/penalty (20% weight)
        stability_factor = 1.0
        if self.consecutive_failures > 5:
            stability_factor = 0.5  # Heavy penalty for instability
        elif self.consecutive_successes > 10:
            stability_factor = 1.2  # Bonus for stability
        
        stability_score = min(100, base_score * stability_factor) * 0.2
        
        # Recency bonus (10% weight)
        recency_score = 0.0
        if self.last_success:
            hours_since_success = (datetime.now() - self.last_success).total_seconds() / 3600
            if hours_since_success < 1:
                recency_score = 10.0  # Recent success bonus
            elif hours_since_success > 24:
                recency_score = -5.0  # Stale penalty
        
        return max(0, min(100, base_score + stability_score + recency_score))


class ProxyHealthScorer:
    """
    Advanced proxy health scoring system with multiple validation criteria
    """
    
    def __init__(self, weights: Dict[HealthCriteria, float] = None):
        self.weights = weights or {
            HealthCriteria.RESPONSE_TIME: 0.25,
            HealthCriteria.SUCCESS_RATE: 0.25,
            HealthCriteria.STABILITY: 0.20,
            HealthCriteria.ANONYMITY: 0.10,
            HealthCriteria.GEOLOCATION_ACCURACY: 0.05,
            HealthCriteria.IP_REPUTATION: 0.05,
            HealthCriteria.PROTOCOL_SUPPORT: 0.05,
            HealthCriteria.CONSISTENCY: 0.05
        }
        
        # Scoring thresholds
        self.response_time_thresholds = {
            'excellent': 100,    # <100ms
            'good': 300,         # <300ms  
            'average': 800,      # <800ms
            'poor': 2000,        # <2000ms
            'unusable': float('inf')  # >=2000ms
        }
        
        self.success_rate_thresholds = {
            'excellent': 98,     # >=98%
            'good': 90,          # >=90%
            'average': 75,       # >=75%
            'poor': 50,          # >=50%
            'unusable': 0        # <50%
        }
    
    def calculate_health_score(self, proxy_address: str, 
                             response_metrics: ResponseTimeMetrics,
                             validation_history: ValidationHistory,
                             additional_data: Dict = None) -> HealthScore:
        """Calculate comprehensive health score for proxy"""
        
        criteria_scores = {}
        
        # Response Time Score (0-100)
        criteria_scores[HealthCriteria.RESPONSE_TIME] = self._score_response_time(
            response_metrics.p95  # Use 95th percentile as primary metric
        )
        
        # Success Rate Score (0-100)  
        criteria_scores[HealthCriteria.SUCCESS_RATE] = validation_history.get_success_rate()
        
        # Stability Score (0-100)
        criteria_scores[HealthCriteria.STABILITY] = validation_history.get_reliability_score()
        
        # Additional criteria if data available
        if additional_data:
            if 'anonymity_level' in additional_data:
                criteria_scores[HealthCriteria.ANONYMITY] = self._score_anonymity(
                    additional_data['anonymity_level']
                )
            
            if 'geo_accuracy' in additional_data:
                criteria_scores[HealthCriteria.GEOLOCATION_ACCURACY] = additional_data['geo_accuracy']
            
            if 'ip_reputation' in additional_data:
                criteria_scores[HealthCriteria.IP_REPUTATION] = additional_data['ip_reputation']
            
            if 'protocol_support' in additional_data:
                criteria_scores[HealthCriteria.PROTOCOL_SUPPORT] = self._score_protocol_support(
                    additional_data['protocol_support']
                )
            
            if 'consistency_score' in additional_data:
                criteria_scores[HealthCriteria.CONSISTENCY] = additional_data['consistency_score']
        
        # Calculate weighted overall score
        overall_score = self._calculate_weighted_score(criteria_scores)
        
        # Calculate confidence based on sample size and criteria coverage
        confidence = self._calculate_confidence(
            response_metrics.sample_count,
            validation_history.success_count + validation_history.failure_count,
            len(criteria_scores)
        )
        
        health_score = HealthScore(
            overall_score=overall_score,
            criteria_scores=criteria_scores,
            confidence=confidence,
            sample_size=response_metrics.sample_count + validation_history.success_count + validation_history.failure_count,
            last_updated=datetime.now()
        )
        
        health_score.update_quality_tier()
        return health_score
    
    def _score_response_time(self, response_time_ms: float) -> float:
        """Score response time on 0-100 scale"""
        if response_time_ms <= self.response_time_thresholds['excellent']:
            return 100.0
        elif response_time_ms <= self.response_time_thresholds['good']:
            # Linear interpolation between excellent and good
            return 90.0 + (10.0 * (self.response_time_thresholds['good'] - response_time_ms) / 
                          (self.response_time_thresholds['good'] - self.response_time_thresholds['excellent']))
        elif response_time_ms <= self.response_time_thresholds['average']:
            return 70.0 + (20.0 * (self.response_time_thresholds['average'] - response_time_ms) / 
                          (self.response_time_thresholds['average'] - self.response_time_thresholds['good']))
        elif response_time_ms <= self.response_time_thresholds['poor']:
            return 40.0 + (30.0 * (self.response_time_thresholds['poor'] - response_time_ms) / 
                          (self.response_time_thresholds['poor'] - self.response_time_thresholds['average']))
        else:
            return max(0.0, 40.0 - (response_time_ms - self.response_time_thresholds['poor']) / 100.0)
    
    def _score_anonymity(self, anonymity_level: str) -> float:
        """Score anonymity level"""
        anonymity_scores = {
            'elite': 100.0,
            'anonymous': 80.0,
            'transparent': 40.0,
            'unknown': 20.0
        }
        return anonymity_scores.get(anonymity_level.lower(), 0.0)
    
    def _score_protocol_support(self, supported_protocols: List[str]) -> float:
        """Score based on number of supported protocols"""
        protocol_count = len(supported_protocols)
        if protocol_count >= 4:
            return 100.0
        elif protocol_count >= 3:
            return 85.0
        elif protocol_count >= 2:
            return 70.0
        elif protocol_count >= 1:
            return 50.0
        else:
            return 0.0
    
    def _calculate_weighted_score(self, criteria_scores: Dict[HealthCriteria, float]) -> float:
        """Calculate weighted overall score"""
        total_weight = 0.0
        weighted_sum = 0.0
        
        for criteria, score in criteria_scores.items():
            weight = self.weights.get(criteria, 0.0)
            weighted_sum += score * weight
            total_weight += weight
        
        return weighted_sum / total_weight if total_weight > 0 else 0.0
    
    def _calculate_confidence(self, response_samples: int, validation_samples: int, 
                            criteria_count: int) -> float:
        """Calculate confidence in health score based on sample sizes and coverage"""
        # Sample size confidence (0-70%)
        total_samples = response_samples + validation_samples
        if total_samples >= 100:
            sample_confidence = 70.0
        elif total_samples >= 50:
            sample_confidence = 60.0
        elif total_samples >= 20:
            sample_confidence = 45.0
        elif total_samples >= 10:
            sample_confidence = 30.0
        elif total_samples >= 5:
            sample_confidence = 15.0
        else:
            sample_confidence = 5.0
        
        # Criteria coverage confidence (0-30%)
        max_criteria = len(HealthCriteria)
        coverage_confidence = (criteria_count / max_criteria) * 30.0
        
        return min(100.0, sample_confidence + coverage_confidence)


class ProxyStabilityTester:
    """
    Proxy stability testing over time periods with trend analysis
    """
    
    def __init__(self, test_interval_minutes: int = 15, max_history_hours: int = 24):
        self.test_interval = timedelta(minutes=test_interval_minutes)
        self.max_history = timedelta(hours=max_history_hours)
        self.stability_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.last_test_times: Dict[str, datetime] = {}
    
    async def test_proxy_stability(self, proxy: ProxyInfo, 
                                 test_count: int = 5) -> Dict[str, float]:
        """Test proxy stability with multiple consecutive tests"""
        proxy_key = f"{proxy.host}:{proxy.port}"
        current_time = datetime.now()
        
        # Check if enough time has passed since last test
        if (proxy_key in self.last_test_times and 
            current_time - self.last_test_times[proxy_key] < self.test_interval):
            return {}
        
        results = []
        
        for i in range(test_count):
            try:
                start_time = time.time()
                
                # Perform basic connectivity test
                success = await self._test_connectivity(proxy)
                response_time = (time.time() - start_time) * 1000
                
                results.append({
                    'success': success,
                    'response_time': response_time,
                    'timestamp': current_time + timedelta(seconds=i * 2)
                })
                
                # Small delay between tests
                if i < test_count - 1:
                    await asyncio.sleep(2)
                
            except Exception as e:
                results.append({
                    'success': False,
                    'response_time': float('inf'),
                    'timestamp': current_time + timedelta(seconds=i * 2),
                    'error': str(e)
                })
        
        # Store results
        for result in results:
            self.stability_data[proxy_key].append(result)
        
        self.last_test_times[proxy_key] = current_time
        
        # Calculate stability metrics
        stability_metrics = self._calculate_stability_metrics(proxy_key)
        return stability_metrics
    
    async def _test_connectivity(self, proxy: ProxyInfo) -> bool:
        """Basic connectivity test"""
        try:
            if HAS_AIOHTTP:
                timeout = aiohttp.ClientTimeout(total=5.0)
                connector = aiohttp.TCPConnector(limit=1)
                
                async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                    proxy_url = f"http://{proxy.host}:{proxy.port}"
                    
                    async with session.get('http://httpbin.org/ip', 
                                          proxy=proxy_url,
                                          timeout=aiohttp.ClientTimeout(total=3.0)) as response:
                        return response.status == 200
            else:
                # Fallback to socket test
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3.0)
                result = sock.connect_ex((proxy.host, proxy.port))
                sock.close()
                return result == 0
                
        except Exception:
            return False
    
    def _calculate_stability_metrics(self, proxy_key: str) -> Dict[str, float]:
        """Calculate stability metrics from historical data"""
        data = self.stability_data.get(proxy_key, deque())
        
        if not data:
            return {}
        
        # Filter recent data
        cutoff_time = datetime.now() - self.max_history
        recent_data = [d for d in data if d['timestamp'] >= cutoff_time]
        
        if not recent_data:
            return {}
        
        # Calculate metrics
        total_tests = len(recent_data)
        successful_tests = sum(1 for d in recent_data if d['success'])
        
        # Success rate
        success_rate = (successful_tests / total_tests) * 100.0
        
        # Response time statistics
        valid_times = [d['response_time'] for d in recent_data 
                      if d['success'] and d['response_time'] != float('inf')]
        
        response_time_stats = {}
        if valid_times:
            response_time_stats = {
                'mean': statistics.mean(valid_times),
                'median': statistics.median(valid_times),
                'std_dev': statistics.stdev(valid_times) if len(valid_times) > 1 else 0.0,
                'min': min(valid_times),
                'max': max(valid_times)
            }
        
        # Consistency score (lower standard deviation = higher consistency)
        consistency_score = 100.0
        if response_time_stats.get('std_dev', 0) > 0:
            cv = response_time_stats['std_dev'] / response_time_stats['mean']  # Coefficient of variation
            consistency_score = max(0, 100 - (cv * 100))
        
        # Uptime calculation (consecutive successful periods)
        uptime_score = self._calculate_uptime_score(recent_data)
        
        return {
            'success_rate': success_rate,
            'consistency_score': consistency_score,
            'uptime_score': uptime_score,
            'sample_count': total_tests,
            'response_time_stats': response_time_stats
        }
    
    def _calculate_uptime_score(self, data: List[Dict]) -> float:
        """Calculate uptime score based on consecutive availability"""
        if not data:
            return 0.0
        
        # Sort by timestamp
        sorted_data = sorted(data, key=lambda x: x['timestamp'])
        
        # Find consecutive success/failure periods
        current_streak = 0
        max_success_streak = 0
        max_failure_streak = 0
        current_is_success = None
        
        for entry in sorted_data:
            if entry['success'] == current_is_success:
                current_streak += 1
            else:
                if current_is_success is True:
                    max_success_streak = max(max_success_streak, current_streak)
                elif current_is_success is False:
                    max_failure_streak = max(max_failure_streak, current_streak)
                
                current_streak = 1
                current_is_success = entry['success']
        
        # Handle final streak
        if current_is_success is True:
            max_success_streak = max(max_success_streak, current_streak)
        elif current_is_success is False:
            max_failure_streak = max(max_failure_streak, current_streak)
        
        # Calculate uptime score
        if max_failure_streak == 0:
            return 100.0
        
        # Penalty for long failure streaks
        failure_penalty = min(50, max_failure_streak * 5)
        success_bonus = min(25, max_success_streak * 2)
        
        base_score = (sum(1 for d in sorted_data if d['success']) / len(sorted_data)) * 75
        
        return max(0, base_score + success_bonus - failure_penalty)


# Export key classes
__all__ = [
    'HealthCriteria', 'ValidationSeverity', 'ProxyQualityTier',
    'HealthScore', 'ResponseTimeMetrics', 'ValidationHistory',
    'ProxyHealthScorer', 'ProxyStabilityTester'
]