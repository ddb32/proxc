"""Smart Cache Implementation - TTL/LRU caching with dynamic resource management"""

import hashlib
import logging
import psutil
import threading
import time
import weakref
import statistics
import asyncio
import math
import numpy as np
from collections import OrderedDict, defaultdict, Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple, Union, List, Callable, Set
from enum import Enum

from .cache_config import CacheConfig, CachePolicy


@dataclass
class CacheEntry:
    """Individual cache entry with TTL and access tracking"""
    value: Any
    created_at: float
    expires_at: float
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    size_bytes: int = 0
    
    def is_expired(self) -> bool:
        """Check if entry has expired"""
        return time.time() > self.expires_at
    
    def touch(self):
        """Update access tracking"""
        self.access_count += 1
        self.last_accessed = time.time()
    
    def time_to_live(self) -> float:
        """Get remaining time to live in seconds"""
        return max(0, self.expires_at - time.time())


@dataclass
class CacheMetrics:
    """Cache performance metrics"""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expired_evictions: int = 0
    size_evictions: int = 0
    memory_evictions: int = 0
    
    total_entries: int = 0
    current_entries: int = 0
    memory_usage_bytes: int = 0
    
    # Performance metrics
    avg_hit_time: float = 0.0
    avg_miss_time: float = 0.0
    cache_effectiveness: float = 0.0
    
    # Timing
    created_at: float = field(default_factory=time.time)
    last_cleanup: float = field(default_factory=time.time)
    
    @property
    def hit_ratio(self) -> float:
        """Calculate cache hit ratio"""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0
    
    @property
    def miss_ratio(self) -> float:
        """Calculate cache miss ratio"""
        return 1.0 - self.hit_ratio
    
    def reset(self):
        """Reset metrics"""
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.expired_evictions = 0
        self.size_evictions = 0
        self.memory_evictions = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/reporting"""
        return {
            'performance': {
                'hits': self.hits,
                'misses': self.misses,
                'hit_ratio': self.hit_ratio,
                'miss_ratio': self.miss_ratio,
                'cache_effectiveness': self.cache_effectiveness,
            },
            'evictions': {
                'total': self.evictions,
                'expired': self.expired_evictions,
                'size_based': self.size_evictions,
                'memory_pressure': self.memory_evictions,
            },
            'memory': {
                'current_entries': self.current_entries,
                'memory_usage_mb': self.memory_usage_bytes / (1024 * 1024),
            },
            'timing': {
                'avg_hit_time_ms': self.avg_hit_time * 1000,
                'avg_miss_time_ms': self.avg_miss_time * 1000,
                'uptime_seconds': time.time() - self.created_at,
            }
        }


class WarmingStrategy(Enum):
    """Cache warming strategies"""
    PREDICTIVE = "predictive"      # Based on usage patterns
    PATTERN_BASED = "pattern_based"  # Based on recognized patterns
    SCHEDULED = "scheduled"        # Time-based scheduled warming
    DEPENDENCY = "dependency"      # Pre-warm related cache entries


@dataclass
class UsagePattern:
    """Track usage patterns for cache keys"""
    key: str
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    access_times: List[float] = field(default_factory=list)
    access_frequency: float = 0.0  # accesses per hour
    cache_hits: int = 0
    cache_misses: int = 0
    
    def record_access(self, hit: bool = True):
        """Record a cache access"""
        current_time = time.time()
        self.access_count += 1
        self.last_accessed = current_time
        self.access_times.append(current_time)
        
        if hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1
        
        # Keep only last 100 access times for pattern analysis
        if len(self.access_times) > 100:
            self.access_times = self.access_times[-100:]
        
        # Calculate access frequency (accesses per hour)
        if len(self.access_times) >= 2:
            time_span = self.access_times[-1] - self.access_times[0]
            if time_span > 0:
                self.access_frequency = len(self.access_times) / (time_span / 3600)
    
    @property
    def hit_ratio(self) -> float:
        """Calculate hit ratio for this key"""
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0.0
    
    def predict_next_access(self) -> Optional[float]:
        """Predict when this key might be accessed next"""
        if len(self.access_times) < 3:
            return None
        
        # Calculate average interval between accesses
        intervals = []
        for i in range(1, len(self.access_times)):
            intervals.append(self.access_times[i] - self.access_times[i-1])
        
        if not intervals:
            return None
        
        avg_interval = statistics.mean(intervals)
        return self.last_accessed + avg_interval
    
    def should_warm(self, threshold: float = 2.0) -> bool:
        """Determine if this key should be pre-warmed"""
        # Warm if accessed frequently and has good hit ratio
        return (self.access_frequency >= threshold and 
                self.hit_ratio >= 0.7 and 
                self.access_count >= 5)


@dataclass
class WarmingMetrics:
    """Metrics for cache warming operations"""
    warming_operations: int = 0
    successful_warms: int = 0
    failed_warms: int = 0
    cache_hits_from_warming: int = 0
    warming_time_total: float = 0.0
    
    # Strategy breakdown
    predictive_warms: int = 0
    pattern_based_warms: int = 0
    scheduled_warms: int = 0
    dependency_warms: int = 0
    
    # Performance metrics
    warming_efficiency: float = 0.0  # hits from warming / total warming operations
    avg_warming_time: float = 0.0
    
    def record_warming_operation(self, strategy: WarmingStrategy, success: bool, duration: float):
        """Record a warming operation"""
        self.warming_operations += 1
        self.warming_time_total += duration
        
        if success:
            self.successful_warms += 1
        else:
            self.failed_warms += 1
        
        # Track by strategy
        if strategy == WarmingStrategy.PREDICTIVE:
            self.predictive_warms += 1
        elif strategy == WarmingStrategy.PATTERN_BASED:
            self.pattern_based_warms += 1
        elif strategy == WarmingStrategy.SCHEDULED:
            self.scheduled_warms += 1
        elif strategy == WarmingStrategy.DEPENDENCY:
            self.dependency_warms += 1
        
        # Update metrics
        self.avg_warming_time = self.warming_time_total / self.warming_operations
    
    def record_warming_hit(self):
        """Record a cache hit that resulted from warming"""
        self.cache_hits_from_warming += 1
        if self.warming_operations > 0:
            self.warming_efficiency = self.cache_hits_from_warming / self.warming_operations
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting"""
        return {
            'operations': {
                'total_warming_ops': self.warming_operations,
                'successful': self.successful_warms,
                'failed': self.failed_warms,
                'success_rate': self.successful_warms / max(1, self.warming_operations),
            },
            'performance': {
                'warming_efficiency': self.warming_efficiency,
                'avg_warming_time_ms': self.avg_warming_time * 1000,
                'cache_hits_from_warming': self.cache_hits_from_warming,
            },
            'strategies': {
                'predictive': self.predictive_warms,
                'pattern_based': self.pattern_based_warms,
                'scheduled': self.scheduled_warms,
                'dependency': self.dependency_warms,
            }
        }


class AccessPatternType(Enum):
    """Types of access patterns"""
    BURST = "burst"              # High frequency in short periods
    SUSTAINED = "sustained"      # Consistent access over time
    PERIODIC = "periodic"        # Regular intervals
    RANDOM = "random"           # No clear pattern
    DECLINING = "declining"     # Decreasing frequency
    GROWING = "growing"         # Increasing frequency


class TemporalPattern(Enum):
    """Temporal patterns for cache access"""
    MORNING_PEAK = "morning_peak"    # High activity in morning
    EVENING_PEAK = "evening_peak"    # High activity in evening
    BUSINESS_HOURS = "business_hours" # Active during business hours
    OFF_HOURS = "off_hours"          # Active during off hours
    WEEKEND = "weekend"              # Weekend pattern
    WEEKDAY = "weekday"              # Weekday pattern
    CONTINUOUS = "continuous"        # 24/7 pattern


@dataclass
class PatternFeatures:
    """Enhanced features extracted from usage patterns"""
    # Basic metrics
    access_frequency: float = 0.0
    hit_ratio: float = 0.0
    access_count: int = 0
    
    # Temporal features
    time_of_day_variance: float = 0.0     # Variance in access times
    day_of_week_variance: float = 0.0     # Variance across days
    morning_ratio: float = 0.0            # % of accesses in morning (6-12)
    afternoon_ratio: float = 0.0          # % of accesses in afternoon (12-18)
    evening_ratio: float = 0.0            # % of accesses in evening (18-24)
    night_ratio: float = 0.0              # % of accesses at night (0-6)
    
    # Pattern characteristics
    burstiness: float = 0.0               # How bursty the access pattern is
    periodicity: float = 0.0              # How periodic the pattern is
    trend: float = 0.0                    # Increasing/decreasing trend
    seasonality: float = 0.0              # Seasonal component strength
    
    # Predictability metrics
    entropy: float = 0.0                  # Information entropy of pattern
    autocorrelation: float = 0.0          # Self-similarity of pattern
    predictability_score: float = 0.0     # Overall predictability
    
    # Resource impact
    cache_miss_cost: float = 0.0          # Estimated cost of cache misses
    warming_benefit: float = 0.0          # Estimated benefit of warming


@dataclass
class RecognizedPattern:
    """A recognized cache access pattern"""
    pattern_id: str
    pattern_type: AccessPatternType
    temporal_pattern: TemporalPattern
    features: PatternFeatures
    confidence: float
    last_seen: float
    occurrence_count: int = 0
    
    # Pattern prediction capabilities
    predicted_next_access: Optional[float] = None
    prediction_confidence: float = 0.0
    
    # Warming recommendations
    recommended_warming_time: float = 0.0
    warming_priority: float = 0.0


class IntelligentPatternAnalyzer:
    """Advanced pattern analysis for intelligent cache warming"""
    
    def __init__(self, max_patterns: int = 100):
        self.max_patterns = max_patterns
        self.recognized_patterns: Dict[str, RecognizedPattern] = {}
        self.pattern_clusters: Dict[str, List[str]] = {}  # Cluster ID -> Pattern IDs
        self.temporal_models: Dict[str, Dict[str, Any]] = {}
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Learning parameters
        self.min_observations = 10      # Minimum accesses to recognize pattern
        self.pattern_similarity_threshold = 0.8
        self.temporal_window_hours = 24  # Hours to consider for temporal patterns
        
        # Adaptive learning parameters
        self.learning_enabled = True
        self.learning_rate = 0.1  # How fast to adapt thresholds
        self.performance_history = deque(maxlen=100)  # Track warming performance
        self.threshold_adjustments = {
            'similarity_threshold': 0.8,
            'predictive_threshold': 2.0,
            'warming_priority_threshold': 0.6
        }
        
    def analyze_usage_pattern(self, usage_pattern: 'UsagePattern') -> Optional[RecognizedPattern]:
        """Analyze a usage pattern and return recognized pattern if found"""
        if usage_pattern.access_count < self.min_observations:
            return None
        
        # Extract features from usage pattern
        features = self._extract_features(usage_pattern)
        
        # Find or create pattern
        pattern = self._find_or_create_pattern(usage_pattern.key, features)
        
        if pattern:
            pattern.last_seen = time.time()
            pattern.occurrence_count += 1
            
            # Update predictions
            self._update_predictions(pattern, usage_pattern)
            
            # Update warming recommendations
            self._update_warming_recommendations(pattern, features)
        
        return pattern
    
    def _extract_features(self, usage_pattern: 'UsagePattern') -> PatternFeatures:
        """Extract comprehensive features from usage pattern"""
        features = PatternFeatures()
        
        # Basic metrics
        features.access_frequency = usage_pattern.access_frequency
        features.hit_ratio = usage_pattern.hit_ratio
        features.access_count = usage_pattern.access_count
        
        if len(usage_pattern.access_times) < 3:
            return features
        
        access_times = np.array(usage_pattern.access_times)
        current_time = time.time()
        
        # Temporal features
        self._extract_temporal_features(features, access_times, current_time)
        
        # Pattern characteristics
        self._extract_pattern_characteristics(features, access_times)
        
        # Predictability metrics
        self._extract_predictability_metrics(features, access_times)
        
        # Resource impact estimation
        self._estimate_resource_impact(features, usage_pattern)
        
        return features
    
    def _extract_temporal_features(self, features: PatternFeatures, access_times: np.ndarray, current_time: float):
        """Extract temporal-based features"""
        # Convert to datetime for analysis
        datetimes = [datetime.fromtimestamp(t) for t in access_times]
        
        # Time of day analysis
        hours = np.array([dt.hour for dt in datetimes])
        features.time_of_day_variance = np.var(hours)
        
        # Day of week analysis
        weekdays = np.array([dt.weekday() for dt in datetimes])
        features.day_of_week_variance = np.var(weekdays)
        
        # Time period ratios
        total_accesses = len(hours)
        features.morning_ratio = np.sum((hours >= 6) & (hours < 12)) / total_accesses
        features.afternoon_ratio = np.sum((hours >= 12) & (hours < 18)) / total_accesses
        features.evening_ratio = np.sum((hours >= 18) & (hours < 24)) / total_accesses
        features.night_ratio = np.sum(hours < 6) / total_accesses
    
    def _extract_pattern_characteristics(self, features: PatternFeatures, access_times: np.ndarray):
        """Extract pattern characteristic features"""
        if len(access_times) < 3:
            return
        
        # Calculate intervals between accesses
        intervals = np.diff(access_times)
        
        # Burstiness - coefficient of variation of intervals
        if len(intervals) > 1 and np.mean(intervals) > 0:
            features.burstiness = np.std(intervals) / np.mean(intervals)
        
        # Trend analysis - slope of access frequency over time
        if len(access_times) >= 5:
            x = np.arange(len(access_times))
            try:
                slope, _ = np.polyfit(x, access_times, 1)
                features.trend = slope / (24 * 3600)  # Normalize to per day
            except:
                features.trend = 0.0
        
        # Periodicity detection using autocorrelation
        if len(intervals) >= 10:
            features.periodicity = self._detect_periodicity(intervals)
        
        # Seasonality strength (simplified)
        if len(access_times) >= 24:  # Need enough data
            features.seasonality = self._calculate_seasonality(access_times)
    
    def _extract_predictability_metrics(self, features: PatternFeatures, access_times: np.ndarray):
        """Extract predictability-related metrics"""
        if len(access_times) < 5:
            return
        
        # Calculate entropy of access intervals
        intervals = np.diff(access_times)
        if len(intervals) > 0:
            features.entropy = self._calculate_entropy(intervals)
        
        # Autocorrelation of intervals
        if len(intervals) >= 10:
            features.autocorrelation = self._calculate_autocorrelation(intervals)
        
        # Overall predictability score (combination of metrics)
        features.predictability_score = self._calculate_predictability_score(features)
    
    def _estimate_resource_impact(self, features: PatternFeatures, usage_pattern: 'UsagePattern'):
        """Estimate resource impact and warming benefits"""
        # Estimate cache miss cost (higher for frequent misses)
        miss_rate = 1.0 - features.hit_ratio
        features.cache_miss_cost = miss_rate * features.access_frequency * 100  # Arbitrary cost unit
        
        # Estimate warming benefit (higher for predictable, frequent patterns)
        predictability_factor = features.predictability_score
        frequency_factor = min(features.access_frequency / 10.0, 1.0)  # Normalize
        features.warming_benefit = predictability_factor * frequency_factor * features.cache_miss_cost
    
    def _detect_periodicity(self, intervals: np.ndarray) -> float:
        """Detect periodicity in access intervals using autocorrelation"""
        try:
            # Normalize intervals
            normalized = (intervals - np.mean(intervals)) / np.std(intervals)
            
            # Calculate autocorrelation
            autocorr = np.correlate(normalized, normalized, mode='full')
            autocorr = autocorr[autocorr.size // 2:]
            
            # Find peaks in autocorrelation (indicating periodicity)
            max_autocorr = np.max(autocorr[1:len(autocorr)//2])  # Exclude lag 0
            return max_autocorr if max_autocorr > 0.3 else 0.0
        except:
            return 0.0
    
    def _calculate_seasonality(self, access_times: np.ndarray) -> float:
        """Calculate seasonality strength in access pattern"""
        try:
            # Group by hour of day
            hours = np.array([datetime.fromtimestamp(t).hour for t in access_times])
            hour_counts = np.zeros(24)
            
            for hour in hours:
                hour_counts[hour] += 1
            
            # Calculate variance in hourly distribution
            mean_count = np.mean(hour_counts)
            if mean_count > 0:
                return np.std(hour_counts) / mean_count
            return 0.0
        except:
            return 0.0
    
    def _calculate_entropy(self, intervals: np.ndarray) -> float:
        """Calculate information entropy of access intervals"""
        try:
            # Discretize intervals into bins
            bins = 10
            hist, _ = np.histogram(intervals, bins=bins)
            hist = hist[hist > 0]  # Remove zero bins
            
            # Calculate probabilities
            probs = hist / np.sum(hist)
            
            # Calculate entropy
            entropy = -np.sum(probs * np.log2(probs))
            return entropy / np.log2(bins)  # Normalize
        except:
            return 0.0
    
    def _calculate_autocorrelation(self, intervals: np.ndarray) -> float:
        """Calculate autocorrelation of access intervals"""
        try:
            if len(intervals) < 2:
                return 0.0
            
            # Calculate lag-1 autocorrelation
            x = intervals[:-1]
            y = intervals[1:]
            
            if np.std(x) == 0 or np.std(y) == 0:
                return 0.0
            
            correlation = np.corrcoef(x, y)[0, 1]
            return correlation if not np.isnan(correlation) else 0.0
        except:
            return 0.0
    
    def _calculate_predictability_score(self, features: PatternFeatures) -> float:
        """Calculate overall predictability score"""
        # Combine multiple predictability indicators
        periodicity_score = features.periodicity * 0.3
        autocorr_score = max(0, features.autocorrelation) * 0.3
        low_entropy_score = (1.0 - features.entropy) * 0.2
        temporal_consistency = (1.0 - features.time_of_day_variance / 24.0) * 0.2
        
        return max(0.0, min(1.0, periodicity_score + autocorr_score + low_entropy_score + temporal_consistency))
    
    def _find_or_create_pattern(self, key: str, features: PatternFeatures) -> Optional[RecognizedPattern]:
        """Find existing similar pattern or create new one"""
        # Check for similar existing patterns
        best_match = None
        best_similarity = 0.0
        
        for pattern_id, pattern in self.recognized_patterns.items():
            similarity = self._calculate_pattern_similarity(features, pattern.features)
            if similarity > best_similarity and similarity >= self.pattern_similarity_threshold:
                best_similarity = similarity
                best_match = pattern
        
        if best_match:
            # Update existing pattern
            self._update_pattern_features(best_match, features)
            return best_match
        else:
            # Create new pattern
            return self._create_new_pattern(key, features)
    
    def _calculate_pattern_similarity(self, features1: PatternFeatures, features2: PatternFeatures) -> float:
        """Calculate similarity between two pattern features"""
        # Create feature vectors
        vec1 = np.array([
            features1.access_frequency / 10.0,  # Normalize
            features1.hit_ratio,
            features1.burstiness,
            features1.periodicity,
            features1.predictability_score,
            features1.morning_ratio,
            features1.afternoon_ratio,
            features1.evening_ratio,
            features1.night_ratio
        ])
        
        vec2 = np.array([
            features2.access_frequency / 10.0,  # Normalize
            features2.hit_ratio,
            features2.burstiness,
            features2.periodicity,
            features2.predictability_score,
            features2.morning_ratio,
            features2.afternoon_ratio,
            features2.evening_ratio,
            features2.night_ratio
        ])
        
        # Calculate cosine similarity
        try:
            dot_product = np.dot(vec1, vec2)
            norm1 = np.linalg.norm(vec1)
            norm2 = np.linalg.norm(vec2)
            
            if norm1 == 0 or norm2 == 0:
                return 0.0
            
            similarity = dot_product / (norm1 * norm2)
            return max(0.0, similarity)
        except:
            return 0.0
    
    def _create_new_pattern(self, key: str, features: PatternFeatures) -> RecognizedPattern:
        """Create a new recognized pattern"""
        pattern_id = f"pattern_{len(self.recognized_patterns)}_{key[:8]}"
        
        # Classify pattern type
        pattern_type = self._classify_pattern_type(features)
        temporal_pattern = self._classify_temporal_pattern(features)
        
        pattern = RecognizedPattern(
            pattern_id=pattern_id,
            pattern_type=pattern_type,
            temporal_pattern=temporal_pattern,
            features=features,
            confidence=0.5,  # Initial confidence
            last_seen=time.time(),
            occurrence_count=1
        )
        
        # Store pattern
        self.recognized_patterns[pattern_id] = pattern
        
        # Cleanup old patterns if we exceed max
        if len(self.recognized_patterns) > self.max_patterns:
            self._cleanup_old_patterns()
        
        self.logger.debug(f"Created new pattern: {pattern_id} (type: {pattern_type.value})")
        return pattern
    
    def _classify_pattern_type(self, features: PatternFeatures) -> AccessPatternType:
        """Classify the type of access pattern"""
        if features.burstiness > 2.0:
            return AccessPatternType.BURST
        elif features.periodicity > 0.5:
            return AccessPatternType.PERIODIC
        elif features.trend > 0.1:
            return AccessPatternType.GROWING
        elif features.trend < -0.1:
            return AccessPatternType.DECLINING
        elif features.access_frequency > 5.0 and features.predictability_score > 0.6:
            return AccessPatternType.SUSTAINED
        else:
            return AccessPatternType.RANDOM
    
    def _classify_temporal_pattern(self, features: PatternFeatures) -> TemporalPattern:
        """Classify the temporal pattern"""
        # Determine dominant time period
        time_ratios = [
            (features.morning_ratio, TemporalPattern.MORNING_PEAK),
            (features.afternoon_ratio, TemporalPattern.BUSINESS_HOURS),
            (features.evening_ratio, TemporalPattern.EVENING_PEAK),
            (features.night_ratio, TemporalPattern.OFF_HOURS)
        ]
        
        # Find dominant time period
        max_ratio, dominant_pattern = max(time_ratios, key=lambda x: x[0])
        
        if max_ratio > 0.6:  # Strong bias toward specific time
            return dominant_pattern
        elif features.time_of_day_variance < 3.0:  # Consistent throughout day
            return TemporalPattern.CONTINUOUS
        elif features.day_of_week_variance > 2.0:  # High weekday/weekend variation
            return TemporalPattern.WEEKEND if features.day_of_week_variance > 3.0 else TemporalPattern.WEEKDAY
        else:
            return TemporalPattern.BUSINESS_HOURS  # Default
    
    def _update_pattern_features(self, pattern: RecognizedPattern, new_features: PatternFeatures):
        """Update existing pattern with new features using exponential smoothing"""
        alpha = 0.3  # Smoothing factor
        
        # Update numeric features
        pattern.features.access_frequency = (alpha * new_features.access_frequency + 
                                           (1 - alpha) * pattern.features.access_frequency)
        pattern.features.hit_ratio = (alpha * new_features.hit_ratio + 
                                    (1 - alpha) * pattern.features.hit_ratio)
        pattern.features.burstiness = (alpha * new_features.burstiness + 
                                     (1 - alpha) * pattern.features.burstiness)
        pattern.features.periodicity = (alpha * new_features.periodicity + 
                                      (1 - alpha) * pattern.features.periodicity)
        pattern.features.predictability_score = (alpha * new_features.predictability_score + 
                                                (1 - alpha) * pattern.features.predictability_score)
        
        # Update confidence based on consistency
        consistency = self._calculate_pattern_similarity(new_features, pattern.features)
        pattern.confidence = min(1.0, pattern.confidence * 0.9 + consistency * 0.1)
    
    def _update_predictions(self, pattern: RecognizedPattern, usage_pattern: 'UsagePattern'):
        """Update pattern predictions based on new data"""
        # Enhanced next access prediction
        next_access = self._predict_next_access_enhanced(pattern, usage_pattern)
        if next_access:
            pattern.predicted_next_access = next_access
            pattern.prediction_confidence = min(0.95, pattern.confidence * pattern.features.predictability_score)
    
    def _predict_next_access_enhanced(self, pattern: RecognizedPattern, usage_pattern: 'UsagePattern') -> Optional[float]:
        """Enhanced prediction using pattern characteristics"""
        if len(usage_pattern.access_times) < 3:
            return None
        
        current_time = time.time()
        last_access = usage_pattern.last_accessed
        
        # Use different prediction strategies based on pattern type
        if pattern.pattern_type == AccessPatternType.PERIODIC:
            return self._predict_periodic_access(usage_pattern.access_times, current_time)
        elif pattern.pattern_type == AccessPatternType.BURST:
            return self._predict_burst_access(usage_pattern.access_times, current_time)
        elif pattern.pattern_type == AccessPatternType.SUSTAINED:
            return self._predict_sustained_access(usage_pattern.access_times, current_time)
        else:
            # Fallback to simple average interval
            intervals = np.diff(usage_pattern.access_times)
            if len(intervals) > 0:
                avg_interval = np.mean(intervals)
                return last_access + avg_interval
        
        return None
    
    def _predict_periodic_access(self, access_times: List[float], current_time: float) -> Optional[float]:
        """Predict next access for periodic patterns"""
        if len(access_times) < 5:
            return None
        
        intervals = np.diff(access_times)
        
        # Find the most common interval (period)
        hist, bins = np.histogram(intervals, bins=10)
        most_common_idx = np.argmax(hist)
        period = (bins[most_common_idx] + bins[most_common_idx + 1]) / 2
        
        # Predict based on period
        last_access = access_times[-1]
        return last_access + period
    
    def _predict_burst_access(self, access_times: List[float], current_time: float) -> Optional[float]:
        """Predict next access for burst patterns"""
        if len(access_times) < 3:
            return None
        
        # Look for recent burst activity
        recent_window = 3600  # 1 hour
        recent_accesses = [t for t in access_times if current_time - t <= recent_window]
        
        if len(recent_accesses) >= 2:
            # In burst mode - predict short interval
            short_intervals = [recent_accesses[i+1] - recent_accesses[i] 
                             for i in range(len(recent_accesses)-1)]
            avg_short_interval = np.mean(short_intervals)
            return access_times[-1] + avg_short_interval
        else:
            # Between bursts - predict longer interval
            return access_times[-1] + 3600  # 1 hour
    
    def _predict_sustained_access(self, access_times: List[float], current_time: float) -> Optional[float]:
        """Predict next access for sustained patterns"""
        if len(access_times) < 3:
            return None
        
        # Use weighted average of recent intervals
        intervals = np.diff(access_times[-5:])  # Last 5 intervals
        weights = np.linspace(0.5, 1.0, len(intervals))  # More weight to recent
        weighted_avg = np.average(intervals, weights=weights)
        
        return access_times[-1] + weighted_avg
    
    def _update_warming_recommendations(self, pattern: RecognizedPattern, features: PatternFeatures):
        """Update warming recommendations for the pattern"""
        # Calculate optimal warming time
        if pattern.predicted_next_access:
            # Warm slightly before predicted access
            warming_lead_time = self._calculate_warming_lead_time(pattern)
            pattern.recommended_warming_time = pattern.predicted_next_access - warming_lead_time
        
        # Calculate warming priority
        pattern.warming_priority = self._calculate_warming_priority(pattern, features)
    
    def _calculate_warming_lead_time(self, pattern: RecognizedPattern) -> float:
        """Calculate how far in advance to warm based on pattern characteristics"""
        base_lead_time = 300  # 5 minutes base
        
        # Adjust based on pattern type
        if pattern.pattern_type == AccessPatternType.BURST:
            return base_lead_time * 0.5  # Shorter lead time for bursts
        elif pattern.pattern_type == AccessPatternType.PERIODIC:
            return base_lead_time * 1.0  # Standard lead time
        elif pattern.pattern_type == AccessPatternType.SUSTAINED:
            return base_lead_time * 0.8  # Slightly shorter
        else:
            return base_lead_time * 1.2  # Longer for unpredictable patterns
    
    def _calculate_warming_priority(self, pattern: RecognizedPattern, features: PatternFeatures) -> float:
        """Calculate warming priority (0-1, higher is better)"""
        # Factors affecting priority
        confidence_factor = pattern.confidence
        predictability_factor = features.predictability_score
        frequency_factor = min(features.access_frequency / 10.0, 1.0)
        benefit_factor = min(features.warming_benefit / 100.0, 1.0)
        
        # Combined priority score
        priority = (confidence_factor * 0.3 + 
                   predictability_factor * 0.3 + 
                   frequency_factor * 0.2 + 
                   benefit_factor * 0.2)
        
        return max(0.0, min(1.0, priority))
    
    def _cleanup_old_patterns(self):
        """Remove old or low-confidence patterns"""
        current_time = time.time()
        patterns_to_remove = []
        
        for pattern_id, pattern in self.recognized_patterns.items():
            # Remove patterns not seen in 7 days or with very low confidence
            age = current_time - pattern.last_seen
            if age > 7 * 24 * 3600 or pattern.confidence < 0.1:
                patterns_to_remove.append(pattern_id)
        
        for pattern_id in patterns_to_remove:
            del self.recognized_patterns[pattern_id]
            self.logger.debug(f"Removed old pattern: {pattern_id}")
    
    def get_intelligent_warming_candidates(self, current_time: float, forecast_window: int = 3600) -> List[Tuple[str, RecognizedPattern]]:
        """Get intelligently ranked warming candidates"""
        candidates = []
        forecast_end = current_time + forecast_window
        
        for pattern_id, pattern in self.recognized_patterns.items():
            # Check if pattern predicts access within forecast window
            if (pattern.predicted_next_access and 
                pattern.recommended_warming_time and
                current_time <= pattern.recommended_warming_time <= forecast_end):
                
                candidates.append((pattern_id, pattern))
        
        # Sort by warming priority (highest first)
        candidates.sort(key=lambda x: x[1].warming_priority, reverse=True)
        
        return candidates
    
    def get_pattern_insights(self) -> Dict[str, Any]:
        """Get insights about recognized patterns"""
        if not self.recognized_patterns:
            return {"total_patterns": 0}
        
        patterns = list(self.recognized_patterns.values())
        
        # Pattern type distribution
        pattern_types = Counter(p.pattern_type.value for p in patterns)
        temporal_patterns = Counter(p.temporal_pattern.value for p in patterns)
        
        # Average metrics
        avg_confidence = np.mean([p.confidence for p in patterns])
        avg_predictability = np.mean([p.features.predictability_score for p in patterns])
        avg_warming_priority = np.mean([p.warming_priority for p in patterns])
        
        # Clustering insights
        clustering_info = self._analyze_pattern_clusters()
        
        # Correlation analysis
        correlation_info = self._analyze_pattern_correlations()
        
        return {
            "total_patterns": len(patterns),
            "pattern_types": dict(pattern_types),
            "temporal_patterns": dict(temporal_patterns),
            "avg_confidence": avg_confidence,
            "avg_predictability": avg_predictability,
            "avg_warming_priority": avg_warming_priority,
            "high_priority_patterns": len([p for p in patterns if p.warming_priority > 0.7]),
            "clustering": clustering_info,
            "correlations": correlation_info
        }
    
    def _analyze_pattern_clusters(self) -> Dict[str, Any]:
        """Analyze clusters of similar patterns"""
        if len(self.recognized_patterns) < 2:
            return {"total_clusters": 0}
        
        patterns = list(self.recognized_patterns.values())
        
        # Create similarity matrix
        n_patterns = len(patterns)
        similarity_matrix = np.zeros((n_patterns, n_patterns))
        
        for i in range(n_patterns):
            for j in range(i+1, n_patterns):
                similarity = self._calculate_pattern_similarity(
                    patterns[i].features, patterns[j].features
                )
                similarity_matrix[i][j] = similarity
                similarity_matrix[j][i] = similarity
        
        # Find clusters using similarity threshold
        cluster_threshold = 0.7
        clusters = []
        visited = set()
        
        for i in range(n_patterns):
            if i in visited:
                continue
            
            # Start new cluster
            cluster = [i]
            visited.add(i)
            
            # Find similar patterns
            for j in range(n_patterns):
                if j not in visited and similarity_matrix[i][j] >= cluster_threshold:
                    cluster.append(j)
                    visited.add(j)
            
            if len(cluster) > 1:  # Only keep multi-pattern clusters
                clusters.append(cluster)
        
        # Analyze cluster characteristics
        cluster_info = []
        for cluster_idx, cluster in enumerate(clusters):
            cluster_patterns = [patterns[i] for i in cluster]
            
            # Find dominant pattern type in cluster
            types = [p.pattern_type.value for p in cluster_patterns]
            dominant_type = Counter(types).most_common(1)[0][0]
            
            # Calculate cluster metrics
            avg_priority = np.mean([p.warming_priority for p in cluster_patterns])
            avg_predictability = np.mean([p.features.predictability_score for p in cluster_patterns])
            
            cluster_info.append({
                'cluster_id': cluster_idx,
                'size': len(cluster),
                'dominant_type': dominant_type,
                'avg_priority': avg_priority,
                'avg_predictability': avg_predictability
            })
        
        return {
            "total_clusters": len(clusters),
            "cluster_details": cluster_info,
            "avg_cluster_size": np.mean([len(c) for c in clusters]) if clusters else 0,
            "largest_cluster_size": max([len(c) for c in clusters]) if clusters else 0
        }
    
    def _analyze_pattern_correlations(self) -> Dict[str, Any]:
        """Analyze correlations between different pattern characteristics"""
        if len(self.recognized_patterns) < 5:
            return {"insufficient_data": True}
        
        patterns = list(self.recognized_patterns.values())
        
        # Extract feature vectors for correlation analysis
        features_data = {
            'access_frequency': [p.features.access_frequency for p in patterns],
            'hit_ratio': [p.features.hit_ratio for p in patterns],
            'burstiness': [p.features.burstiness for p in patterns],
            'periodicity': [p.features.periodicity for p in patterns],
            'predictability': [p.features.predictability_score for p in patterns],
            'warming_priority': [p.warming_priority for p in patterns],
            'confidence': [p.confidence for p in patterns]
        }
        
        # Calculate key correlations
        correlations = {}
        
        try:
            # Correlation between predictability and warming priority
            predictability = np.array(features_data['predictability'])
            priority = np.array(features_data['warming_priority'])
            correlations['predictability_priority'] = np.corrcoef(predictability, priority)[0, 1]
            
            # Correlation between access frequency and hit ratio
            frequency = np.array(features_data['access_frequency'])
            hit_ratio = np.array(features_data['hit_ratio'])
            correlations['frequency_hit_ratio'] = np.corrcoef(frequency, hit_ratio)[0, 1]
            
            # Correlation between burstiness and predictability
            burstiness = np.array(features_data['burstiness'])
            correlations['burstiness_predictability'] = np.corrcoef(burstiness, predictability)[0, 1]
            
            # Correlation between periodicity and predictability
            periodicity = np.array(features_data['periodicity'])
            correlations['periodicity_predictability'] = np.corrcoef(periodicity, predictability)[0, 1]
            
        except Exception as e:
            self.logger.debug(f"Correlation analysis failed: {e}")
            correlations = {"error": "correlation_calculation_failed"}
        
        # Temporal correlation analysis
        temporal_correlations = self._analyze_temporal_correlations(patterns)
        
        return {
            "feature_correlations": correlations,
            "temporal_correlations": temporal_correlations,
            "strong_correlations": [k for k, v in correlations.items() 
                                  if isinstance(v, float) and abs(v) > 0.6]
        }
    
    def _analyze_temporal_correlations(self, patterns: List[RecognizedPattern]) -> Dict[str, Any]:
        """Analyze temporal correlations between patterns"""
        # Group patterns by temporal pattern
        temporal_groups = defaultdict(list)
        for pattern in patterns:
            temporal_groups[pattern.temporal_pattern.value].append(pattern)
        
        temporal_stats = {}
        for temporal_type, group_patterns in temporal_groups.items():
            if len(group_patterns) > 1:
                priorities = [p.warming_priority for p in group_patterns]
                predictabilities = [p.features.predictability_score for p in group_patterns]
                
                temporal_stats[temporal_type] = {
                    'count': len(group_patterns),
                    'avg_priority': np.mean(priorities),
                    'avg_predictability': np.mean(predictabilities),
                    'priority_std': np.std(priorities),
                    'predictability_std': np.std(predictabilities)
                }
        
        # Find best performing temporal patterns
        best_temporal = None
        best_score = 0
        
        for temporal_type, stats in temporal_stats.items():
            # Score based on priority and consistency
            score = stats['avg_priority'] * (1 - stats['priority_std'])
            if score > best_score:
                best_score = score
                best_temporal = temporal_type
        
        return {
            "temporal_stats": temporal_stats,
            "best_temporal_pattern": best_temporal,
            "temporal_diversity": len(temporal_groups)
        }
    
    def record_warming_performance(self, pattern_id: str, success: bool, hit_achieved: bool, 
                                 prediction_accuracy: float):
        """Record performance of a warming operation for adaptive learning"""
        if not self.learning_enabled:
            return
        
        performance_record = {
            'pattern_id': pattern_id,
            'success': success,
            'hit_achieved': hit_achieved,
            'prediction_accuracy': prediction_accuracy,
            'timestamp': time.time()
        }
        
        self.performance_history.append(performance_record)
        
        # Trigger adaptive learning if we have enough data
        if len(self.performance_history) >= 20:
            self._adapt_thresholds()
    
    def _adapt_thresholds(self):
        """Adapt recognition thresholds based on performance history"""
        if len(self.performance_history) < 20:
            return
        
        recent_performance = list(self.performance_history)[-20:]
        
        # Calculate performance metrics
        success_rate = sum(1 for p in recent_performance if p['success']) / len(recent_performance)
        hit_rate = sum(1 for p in recent_performance if p['hit_achieved']) / len(recent_performance)
        avg_accuracy = np.mean([p['prediction_accuracy'] for p in recent_performance])
        
        # Adapt similarity threshold
        if success_rate < 0.6:  # Low success rate
            # Lower threshold to be more inclusive
            new_threshold = max(0.6, self.pattern_similarity_threshold - self.learning_rate * 0.1)
            self.pattern_similarity_threshold = new_threshold
            self.threshold_adjustments['similarity_threshold'] = new_threshold
            self.logger.debug(f"Lowered similarity threshold to {new_threshold:.2f}")
        elif success_rate > 0.9:  # Very high success rate
            # Raise threshold to be more selective
            new_threshold = min(0.95, self.pattern_similarity_threshold + self.learning_rate * 0.05)
            self.pattern_similarity_threshold = new_threshold
            self.threshold_adjustments['similarity_threshold'] = new_threshold
            self.logger.debug(f"Raised similarity threshold to {new_threshold:.2f}")
        
        # Adapt warming priority threshold
        if hit_rate < 0.7:  # Low hit rate from warming
            # Raise threshold to be more selective about what to warm
            current_threshold = self.threshold_adjustments['warming_priority_threshold']
            new_threshold = min(0.9, current_threshold + self.learning_rate * 0.1)
            self.threshold_adjustments['warming_priority_threshold'] = new_threshold
            self.logger.debug(f"Raised warming priority threshold to {new_threshold:.2f}")
        elif hit_rate > 0.9:  # Very high hit rate
            # Lower threshold to warm more entries
            current_threshold = self.threshold_adjustments['warming_priority_threshold']
            new_threshold = max(0.3, current_threshold - self.learning_rate * 0.05)
            self.threshold_adjustments['warming_priority_threshold'] = new_threshold
            self.logger.debug(f"Lowered warming priority threshold to {new_threshold:.2f}")
    
    def get_adaptive_insights(self) -> Dict[str, Any]:
        """Get insights about adaptive learning performance"""
        if len(self.performance_history) < 5:
            return {"insufficient_data": True}
        
        recent_records = list(self.performance_history)[-20:] if len(self.performance_history) >= 20 else list(self.performance_history)
        
        success_rate = sum(1 for p in recent_records if p['success']) / len(recent_records)
        hit_rate = sum(1 for p in recent_records if p['hit_achieved']) / len(recent_records)
        avg_accuracy = np.mean([p['prediction_accuracy'] for p in recent_records])
        
        return {
            "learning_enabled": self.learning_enabled,
            "performance_records": len(self.performance_history),
            "recent_success_rate": success_rate,
            "recent_hit_rate": hit_rate,
            "avg_prediction_accuracy": avg_accuracy,
            "current_thresholds": self.threshold_adjustments.copy(),
            "threshold_adaptations": len([r for r in recent_records 
                                        if abs(r['prediction_accuracy'] - 0.5) > 0.2])
        }


class IntelligentPrewarmingScheduler:
    """Advanced scheduler for intelligent cache pre-warming"""
    
    def __init__(self, pattern_analyzer: IntelligentPatternAnalyzer):
        self.pattern_analyzer = pattern_analyzer
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Scheduling configuration
        self.scheduling_enabled = True
        self.max_concurrent_prewarming = 3
        self.prewarming_window_minutes = 15  # Look ahead window
        self.min_confidence_threshold = 0.6
        
        # Scheduling state
        self.scheduled_operations = []  # List of scheduled prewarming operations
        self.last_schedule_update = 0
        self.schedule_update_interval = 60  # Update schedule every minute
        
        # Performance tracking
        self.prewarming_success_rate = 0.0
        self.prediction_accuracy_rate = 0.0
        
    def update_schedule(self, current_time: float) -> List[Dict[str, Any]]:
        """Update the prewarming schedule based on current patterns"""
        if not self.scheduling_enabled:
            return []
        
        # Only update if enough time has passed
        if current_time - self.last_schedule_update < self.schedule_update_interval:
            return self.scheduled_operations
        
        self.last_schedule_update = current_time
        
        # Get intelligent warming candidates from pattern analyzer
        forecast_window = self.prewarming_window_minutes * 60
        candidates = self.pattern_analyzer.get_intelligent_warming_candidates(
            current_time, forecast_window
        )
        
        # Filter candidates by confidence threshold
        high_confidence_candidates = [
            (pattern_id, pattern) for pattern_id, pattern in candidates
            if pattern.prediction_confidence >= self.min_confidence_threshold
        ]
        
        # Create optimized schedule
        new_schedule = self._create_optimized_schedule(high_confidence_candidates, current_time)
        
        # Update scheduled operations
        self.scheduled_operations = new_schedule
        
        self.logger.debug(f"Updated prewarming schedule with {len(new_schedule)} operations")
        return new_schedule
    
    def _create_optimized_schedule(self, candidates: List[Tuple[str, RecognizedPattern]], 
                                 current_time: float) -> List[Dict[str, Any]]:
        """Create an optimized schedule for prewarming operations with advanced load balancing"""
        schedule = []
        
        # Enhanced scoring with system load consideration
        system_load = self._get_system_load_factor()
        scored_candidates = []
        
        for pattern_id, pattern in candidates:
            if pattern.recommended_warming_time and pattern.predicted_next_access:
                # Multi-dimensional scoring
                time_urgency = self._calculate_time_urgency(
                    pattern.recommended_warming_time, current_time
                )
                priority_score = pattern.warming_priority
                confidence_score = pattern.prediction_confidence
                
                # System load adjustment
                load_penalty = min(0.3, system_load * 0.4) if system_load > 0.7 else 0
                
                # Temporal pattern bonus for predictable patterns
                temporal_bonus = self._calculate_temporal_bonus(pattern, current_time)
                
                # Resource efficiency factor based on pattern history
                efficiency_factor = self._calculate_efficiency_factor(pattern)
                
                # Enhanced combined score with load balancing
                total_score = (
                    priority_score * 0.3 + 
                    confidence_score * 0.25 + 
                    time_urgency * 0.2 + 
                    temporal_bonus * 0.15 +
                    efficiency_factor * 0.1
                ) - load_penalty
                
                scored_candidates.append((pattern_id, pattern, total_score, time_urgency))
        
        # Advanced sorting with load distribution
        scored_candidates.sort(key=lambda x: (x[2], -x[3]), reverse=True)
        
        # Smart schedule creation with time distribution
        schedule = self._distribute_schedule_optimally(scored_candidates, current_time, system_load)
        
        return schedule
    
    def _calculate_temporal_bonus(self, pattern: RecognizedPattern, current_time: float) -> float:
        """Calculate bonus score for temporal patterns that align with optimal timing"""
        try:
            current_hour = int((current_time / 3600) % 24)
            
            # Bonus for patterns that align with historical success
            temporal_pattern = pattern.temporal_pattern
            
            if temporal_pattern.value == 'morning_peak' and 6 <= current_hour <= 10:
                return 0.3
            elif temporal_pattern.value == 'business_hours' and 9 <= current_hour <= 17:
                return 0.25
            elif temporal_pattern.value == 'evening_peak' and 18 <= current_hour <= 22:
                return 0.3
            elif temporal_pattern.value == 'off_hours' and (current_hour <= 6 or current_hour >= 23):
                return 0.2
            elif temporal_pattern.value == 'continuous':
                return 0.1  # Small bonus for always-active patterns
            
            return 0.0
        except Exception:
            return 0.0
    
    def _calculate_efficiency_factor(self, pattern: RecognizedPattern) -> float:
        """Calculate efficiency factor based on pattern's historical performance"""
        try:
            # Use occurrence count and confidence as efficiency indicators
            occurrence_factor = min(1.0, pattern.occurrence_count / 10.0)  # More occurrences = more reliable
            confidence_stability = pattern.confidence if pattern.confidence > 0.5 else 0.0
            
            return (occurrence_factor * 0.6 + confidence_stability * 0.4)
        except Exception:
            return 0.5  # Default moderate efficiency
    
    def _distribute_schedule_optimally(self, scored_candidates: List[Tuple[str, RecognizedPattern, float, float]], 
                                     current_time: float, system_load: float) -> List[Dict[str, Any]]:
        """Distribute scheduled operations optimally across time to balance system load"""
        schedule = []
        
        # Adjust max concurrent based on system load
        effective_max_concurrent = max(1, int(self.max_concurrent_prewarming * (1.0 - min(0.5, system_load))))
        
        # Time slot allocation for load distribution
        time_slots = {}
        slot_duration = 60  # 1-minute slots
        
        for pattern_id, pattern, score, urgency in scored_candidates:
            if len(schedule) >= effective_max_concurrent:
                break
            
            warming_time = pattern.recommended_warming_time
            if not warming_time or warming_time <= current_time:
                continue
            
            # Find optimal time slot
            optimal_slot = self._find_optimal_time_slot(
                warming_time, current_time, time_slots, slot_duration, urgency
            )
            
            if optimal_slot is not None:
                schedule_entry = {
                    'pattern_id': pattern_id,
                    'warming_time': optimal_slot,
                    'original_warming_time': warming_time,
                    'predicted_access_time': pattern.predicted_next_access,
                    'priority': pattern.warming_priority,
                    'confidence': pattern.prediction_confidence,
                    'score': score,
                    'urgency': urgency,
                    'pattern_type': pattern.pattern_type.value,
                    'temporal_pattern': pattern.temporal_pattern.value,
                    'scheduled_at': current_time,
                    'load_adjusted': optimal_slot != warming_time
                }
                
                schedule.append(schedule_entry)
                
                # Track slot usage
                slot_key = int(optimal_slot // slot_duration)
                time_slots[slot_key] = time_slots.get(slot_key, 0) + 1
        
        return schedule
    
    def _find_optimal_time_slot(self, preferred_time: float, current_time: float, 
                               time_slots: Dict[int, int], slot_duration: int, urgency: float) -> Optional[float]:
        """Find optimal time slot for scheduling with load balancing"""
        max_per_slot = 2  # Maximum operations per time slot
        
        # Start with preferred time
        preferred_slot = int(preferred_time // slot_duration)
        
        # If preferred slot has capacity and isn't too urgent, use it
        if time_slots.get(preferred_slot, 0) < max_per_slot:
            return preferred_time
        
        # For urgent operations, allow slight overloading of preferred slot
        if urgency > 0.8 and time_slots.get(preferred_slot, 0) < max_per_slot + 1:
            return preferred_time
        
        # Search for nearby slots (within reasonable time window)
        search_window = min(5, int(300 / slot_duration))  # 5 minutes or 5 slots
        
        for offset in range(1, search_window + 1):
            # Try later slots first (prefer delaying over advancing)
            for direction in [1, -1]:
                candidate_slot = preferred_slot + (offset * direction)
                candidate_time = candidate_slot * slot_duration
                
                # Don't schedule in the past
                if candidate_time <= current_time:
                    continue
                
                # Check if slot has capacity
                if time_slots.get(candidate_slot, 0) < max_per_slot:
                    return candidate_time
        
        # If no optimal slot found, use preferred time anyway (system will handle overload)
        return preferred_time
    
    def _calculate_time_urgency(self, warming_time: float, current_time: float) -> float:
        """Calculate urgency score based on timing (0-1, higher = more urgent)"""
        time_diff = warming_time - current_time
        
        if time_diff <= 0:
            return 1.0  # Immediate urgency
        elif time_diff <= 300:  # Within 5 minutes
            return 0.8
        elif time_diff <= 900:  # Within 15 minutes
            return 0.6
        elif time_diff <= 1800:  # Within 30 minutes
            return 0.4
        else:
            return 0.2  # Low urgency
    
    def get_next_prewarming_operations(self, current_time: float, 
                                     max_operations: int = 5) -> List[Dict[str, Any]]:
        """Get the next prewarming operations that should be executed"""
        if not self.scheduled_operations:
            return []
        
        # Find operations that should be executed now
        ready_operations = []
        
        for operation in self.scheduled_operations:
            warming_time = operation['warming_time']
            
            # Check if it's time to warm (within 1 minute tolerance)
            if warming_time <= current_time + 60:
                ready_operations.append(operation)
        
        # Sort by priority and limit
        ready_operations.sort(key=lambda x: x['score'], reverse=True)
        return ready_operations[:max_operations]
    
    def record_prewarming_result(self, pattern_id: str, success: bool, hit_achieved: bool):
        """Record the result of a prewarming operation for performance tracking"""
        # Update success rate
        current_count = getattr(self, '_prewarming_count', 0)
        current_successes = getattr(self, '_prewarming_successes', 0)
        
        current_count += 1
        if success:
            current_successes += 1
        
        self.prewarming_success_rate = current_successes / current_count
        
        # Store for future reference
        setattr(self, '_prewarming_count', current_count)
        setattr(self, '_prewarming_successes', current_successes)
        
        # Record in pattern analyzer for adaptive learning
        if pattern_id in self.pattern_analyzer.recognized_patterns:
            pattern = self.pattern_analyzer.recognized_patterns[pattern_id]
            
            # Calculate prediction accuracy
            prediction_accuracy = 1.0 if hit_achieved else 0.0
            
            self.pattern_analyzer.record_warming_performance(
                pattern_id, success, hit_achieved, prediction_accuracy
            )
    
    def get_scheduler_metrics(self) -> Dict[str, Any]:
        """Get metrics about the intelligent prewarming scheduler"""
        current_time = time.time()
        
        # Count scheduled operations by status
        pending_operations = len([op for op in self.scheduled_operations 
                                if op['warming_time'] > current_time])
        overdue_operations = len([op for op in self.scheduled_operations 
                                if op['warming_time'] <= current_time])
        
        # Calculate average prediction horizon
        avg_prediction_horizon = 0
        if self.scheduled_operations:
            horizons = [op['predicted_access_time'] - current_time 
                       for op in self.scheduled_operations 
                       if op['predicted_access_time'] > current_time]
            if horizons:
                avg_prediction_horizon = np.mean(horizons) / 60  # Convert to minutes
        
        return {
            'scheduling_enabled': self.scheduling_enabled,
            'scheduled_operations': len(self.scheduled_operations),
            'pending_operations': pending_operations,
            'overdue_operations': overdue_operations,
            'prewarming_success_rate': self.prewarming_success_rate,
            'avg_prediction_horizon_minutes': avg_prediction_horizon,
            'last_schedule_update': current_time - self.last_schedule_update,
            'max_concurrent_prewarming': self.max_concurrent_prewarming,
            'prewarming_window_minutes': self.prewarming_window_minutes,
            'min_confidence_threshold': self.min_confidence_threshold
        }
    
    def optimize_parameters(self):
        """Advanced optimization of scheduling parameters based on performance history and system metrics"""
        try:
            # Get current performance metrics
            current_time = time.time()
            adaptive_insights = self.pattern_analyzer.get_adaptive_insights()
            
            # Enhanced confidence threshold optimization with momentum
            if self.prewarming_success_rate < 0.5:
                # Very low success rate - aggressive increase with system load consideration
                load_factor = self._get_system_load_factor()
                adjustment = 0.15 if load_factor > 0.8 else 0.1
                self.min_confidence_threshold = min(0.95, self.min_confidence_threshold + adjustment)
                self.logger.info(f"Low success rate detected - increased confidence threshold to {self.min_confidence_threshold:.2f}")
            elif self.prewarming_success_rate < 0.6:
                # Moderate increase for low success
                self.min_confidence_threshold = min(0.9, self.min_confidence_threshold + 0.08)
                self.logger.debug(f"Increased confidence threshold to {self.min_confidence_threshold:.2f}")
            elif self.prewarming_success_rate > 0.95:
                # Exceptional success rate - be more aggressive
                self.min_confidence_threshold = max(0.3, self.min_confidence_threshold - 0.08)
                self.logger.debug(f"High success rate - decreased confidence threshold to {self.min_confidence_threshold:.2f}")
            elif self.prewarming_success_rate > 0.85:
                # Good success rate - moderate decrease
                self.min_confidence_threshold = max(0.4, self.min_confidence_threshold - 0.05)
                self.logger.debug(f"Good success rate - decreased confidence threshold to {self.min_confidence_threshold:.2f}")
            
            # Dynamic prewarming window optimization
            if not adaptive_insights.get('insufficient_data', False):
                accuracy = adaptive_insights.get('avg_prediction_accuracy', 0.5)
                hit_efficiency = adaptive_insights.get('warming_hit_efficiency', 0.0)
                
                # Multi-factor window adjustment
                if accuracy > 0.9 and hit_efficiency > 0.8:
                    # Excellent performance - extend window significantly
                    self.prewarming_window_minutes = min(45, self.prewarming_window_minutes + 8)
                    self.logger.info(f"Excellent prediction accuracy - extended window to {self.prewarming_window_minutes} minutes")
                elif accuracy > 0.8 and hit_efficiency > 0.6:
                    # Good performance - moderate extension
                    self.prewarming_window_minutes = min(30, self.prewarming_window_minutes + 5)
                    self.logger.debug(f"Good prediction accuracy - extended window to {self.prewarming_window_minutes} minutes")
                elif accuracy < 0.3 or hit_efficiency < 0.2:
                    # Poor performance - significant reduction
                    self.prewarming_window_minutes = max(3, self.prewarming_window_minutes - 8)
                    self.logger.warning(f"Poor prediction accuracy - reduced window to {self.prewarming_window_minutes} minutes")
                elif accuracy < 0.5:
                    # Below average - moderate reduction
                    self.prewarming_window_minutes = max(5, self.prewarming_window_minutes - 3)
                    self.logger.debug(f"Below average accuracy - reduced window to {self.prewarming_window_minutes} minutes")
            
            # Adaptive concurrency optimization based on system resources
            self._optimize_concurrency()
            
            # Schedule update interval optimization
            self._optimize_schedule_intervals()
            
            # Log optimization summary
            self.logger.info(f"Scheduler optimization completed - confidence: {self.min_confidence_threshold:.2f}, "
                           f"window: {self.prewarming_window_minutes}min, concurrency: {self.max_concurrent_prewarming}")
            
        except Exception as e:
            self.logger.error(f"Parameter optimization failed: {e}")
    
    def _get_system_load_factor(self) -> float:
        """Get current system load factor for adaptive optimization"""
        try:
            import psutil
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory_info = psutil.virtual_memory()
            
            # Combine CPU and memory load
            cpu_load = min(cpu_percent / 100.0, 1.0)
            memory_load = memory_info.percent / 100.0
            
            return (cpu_load * 0.6 + memory_load * 0.4)
        except Exception:
            return 0.5  # Default moderate load
    
    def _optimize_concurrency(self):
        """Optimize concurrent prewarming operations based on system performance"""
        try:
            load_factor = self._get_system_load_factor()
            current_performance = self.prewarming_success_rate
            
            if load_factor > 0.9:
                # High system load - reduce concurrency
                self.max_concurrent_prewarming = max(1, self.max_concurrent_prewarming - 2)
                self.logger.debug(f"High system load - reduced concurrency to {self.max_concurrent_prewarming}")
            elif load_factor < 0.3 and current_performance > 0.8:
                # Low system load and good performance - increase concurrency
                self.max_concurrent_prewarming = min(8, self.max_concurrent_prewarming + 1)
                self.logger.debug(f"Low system load - increased concurrency to {self.max_concurrent_prewarming}")
            elif current_performance < 0.4:
                # Poor performance regardless of load - reduce concurrency
                self.max_concurrent_prewarming = max(1, self.max_concurrent_prewarming - 1)
                self.logger.debug(f"Poor performance - reduced concurrency to {self.max_concurrent_prewarming}")
        except Exception as e:
            self.logger.debug(f"Concurrency optimization failed: {e}")
    
    def _optimize_schedule_intervals(self):
        """Optimize scheduling update intervals based on pattern volatility"""
        try:
            adaptive_insights = self.pattern_analyzer.get_adaptive_insights()
            pattern_volatility = adaptive_insights.get('pattern_stability', 0.5)
            
            if pattern_volatility > 0.8:
                # Stable patterns - can update less frequently
                self.schedule_update_interval = min(300, self.schedule_update_interval + 30)  # Max 5 minutes
            elif pattern_volatility < 0.3:
                # Volatile patterns - need more frequent updates
                self.schedule_update_interval = max(15, self.schedule_update_interval - 15)  # Min 15 seconds
            
            self.logger.debug(f"Schedule update interval optimized to {self.schedule_update_interval}s "
                            f"(pattern stability: {pattern_volatility:.2f})")
        except Exception as e:
            self.logger.debug(f"Schedule interval optimization failed: {e}")


class AutoSizeCalculator:
    """Dynamic cache size calculator based on system resources"""
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._last_check = 0
        self._cached_max_size = None
        self._check_interval = 30  # Check system resources every 30 seconds
    
    def get_optimal_cache_size(self, cache_name: str = "default") -> int:
        """Calculate optimal cache size based on available system memory"""
        current_time = time.time()
        
        # Use cached value if recent
        if self._cached_max_size and (current_time - self._last_check) < self._check_interval:
            return self._cached_max_size
        
        try:
            # Get system memory info
            memory_info = psutil.virtual_memory()
            available_memory_mb = memory_info.available / (1024 * 1024)
            total_memory_mb = memory_info.total / (1024 * 1024)
            
            # Use configured limit if provided and system has enough memory
            if self.config.max_memory_mb and available_memory_mb > self.config.max_memory_mb * 2:
                cache_budget_mb = self.config.max_memory_mb
            else:
                # Calculate dynamic budget based on available memory
                # Reserve at least emergency_memory_mb for system
                usable_memory = max(0, available_memory_mb - self.config.emergency_memory_mb)
                
                # Use 10-20% of available memory based on system total memory
                if total_memory_mb > 8192:  # > 8GB RAM
                    cache_budget_mb = min(usable_memory * 0.2, 1024)  # Max 1GB
                elif total_memory_mb > 4096:  # > 4GB RAM  
                    cache_budget_mb = min(usable_memory * 0.15, 512)  # Max 512MB
                elif total_memory_mb > 2048:  # > 2GB RAM
                    cache_budget_mb = min(usable_memory * 0.1, 256)   # Max 256MB
                else:  # <= 2GB RAM
                    cache_budget_mb = min(usable_memory * 0.05, 128)  # Max 128MB
            
            # Convert to entry count (assume ~4KB per validation result entry)
            avg_entry_size_kb = 4
            max_entries = max(100, int((cache_budget_mb * 1024) / avg_entry_size_kb))
            
            # Apply hard limits
            max_entries = min(max_entries, self.config.max_entries_per_cache)
            
            # Cache the result
            self._cached_max_size = max_entries
            self._last_check = current_time
            
            if current_time - self._last_check > 300:  # Log every 5 minutes
                self.logger.debug(f"Cache size calculated: {max_entries} entries "
                                f"({cache_budget_mb:.1f}MB budget from {available_memory_mb:.1f}MB available)")
            
            return max_entries
            
        except Exception as e:
            self.logger.warning(f"Failed to calculate optimal cache size: {e}")
            # Fallback to conservative default
            return 1000
    
    def check_memory_pressure(self) -> Tuple[bool, float]:
        """Check if system is under memory pressure"""
        try:
            memory_info = psutil.virtual_memory()
            available_mb = memory_info.available / (1024 * 1024)
            
            # Emergency pressure if below emergency threshold
            emergency_pressure = available_mb < self.config.emergency_memory_mb
            
            # Calculate pressure ratio (0.0 = no pressure, 1.0 = maximum pressure)
            pressure_ratio = max(0.0, 1.0 - (available_mb / (self.config.emergency_memory_mb * 3)))
            
            return emergency_pressure or pressure_ratio > 0.8, pressure_ratio
            
        except Exception as e:
            self.logger.warning(f"Failed to check memory pressure: {e}")
            return False, 0.0


class TTLCache:
    """Time-To-Live cache with automatic expiration"""
    
    def __init__(self, default_ttl: int = 3600, name: str = "TTLCache"):
        self.default_ttl = default_ttl
        self.name = name
        self.storage: Dict[str, CacheEntry] = {}
        self.lock = threading.RLock()
        self.metrics = CacheMetrics()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache, None if not found or expired"""
        start_time = time.time()
        
        with self.lock:
            if key not in self.storage:
                self._record_miss(start_time)
                return None
            
            entry = self.storage[key]
            
            if entry.is_expired():
                del self.storage[key]
                self.metrics.expired_evictions += 1
                self.metrics.evictions += 1
                self.metrics.current_entries = len(self.storage)
                self._record_miss(start_time)
                return None
            
            entry.touch()
            self._record_hit(start_time)
            return entry.value
    
    def put(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Put value in cache with specified TTL"""
        if ttl is None:
            ttl = self.default_ttl
        
        current_time = time.time()
        
        # Estimate size (rough approximation)
        size_bytes = self._estimate_size(value)
        
        entry = CacheEntry(
            value=value,
            created_at=current_time,
            expires_at=current_time + ttl,
            size_bytes=size_bytes
        )
        
        with self.lock:
            self.storage[key] = entry
            self.metrics.current_entries = len(self.storage)
            self.metrics.memory_usage_bytes += size_bytes
    
    def delete(self, key: str) -> bool:
        """Delete entry from cache"""
        with self.lock:
            if key in self.storage:
                entry = self.storage[key]
                self.metrics.memory_usage_bytes -= entry.size_bytes
                del self.storage[key]
                self.metrics.current_entries = len(self.storage)
                return True
            return False
    
    def cleanup_expired(self) -> int:
        """Remove all expired entries, return count removed"""
        current_time = time.time()
        expired_keys = []
        
        with self.lock:
            for key, entry in self.storage.items():
                if entry.is_expired():
                    expired_keys.append(key)
            
            removed_count = len(expired_keys)
            for key in expired_keys:
                entry = self.storage[key]
                self.metrics.memory_usage_bytes -= entry.size_bytes
                del self.storage[key]
            
            if removed_count > 0:
                self.metrics.expired_evictions += removed_count
                self.metrics.evictions += removed_count
                self.metrics.current_entries = len(self.storage)
                self.metrics.last_cleanup = current_time
        
        return removed_count
    
    def clear(self):
        """Clear all entries"""
        with self.lock:
            self.storage.clear()
            self.metrics.current_entries = 0
            self.metrics.memory_usage_bytes = 0
    
    def size(self) -> int:
        """Get current cache size"""
        return len(self.storage)
    
    def _record_hit(self, start_time: float):
        """Record cache hit metrics"""
        self.metrics.hits += 1
        hit_time = time.time() - start_time
        # Simple moving average
        self.metrics.avg_hit_time = (self.metrics.avg_hit_time + hit_time) / 2
    
    def _record_miss(self, start_time: float):
        """Record cache miss metrics"""
        self.metrics.misses += 1
        miss_time = time.time() - start_time
        self.metrics.avg_miss_time = (self.metrics.avg_miss_time + miss_time) / 2
    
    def _estimate_size(self, value: Any) -> int:
        """Rough size estimation for cache entries"""
        if isinstance(value, str):
            return len(value.encode('utf-8'))
        elif isinstance(value, (int, float)):
            return 8
        elif isinstance(value, bool):
            return 1
        elif isinstance(value, (list, tuple)):
            return sum(self._estimate_size(item) for item in value[:10])  # Sample first 10
        elif isinstance(value, dict):
            return sum(self._estimate_size(k) + self._estimate_size(v) 
                      for k, v in list(value.items())[:10])  # Sample first 10
        else:
            return 1024  # Default estimate for complex objects


class LRUCache:
    """Least-Recently-Used cache with size limits"""
    
    def __init__(self, max_size: int = 1000, name: str = "LRUCache"):
        self.max_size = max_size
        self.name = name
        self.storage: OrderedDict[str, Any] = OrderedDict()
        self.lock = threading.RLock()
        self.metrics = CacheMetrics()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache, None if not found"""
        start_time = time.time()
        
        with self.lock:
            if key not in self.storage:
                self._record_miss(start_time)
                return None
            
            # Move to end (most recently used)
            value = self.storage.pop(key)
            self.storage[key] = value
            
            self._record_hit(start_time)
            return value
    
    def put(self, key: str, value: Any) -> None:
        """Put value in cache with LRU eviction"""
        with self.lock:
            if key in self.storage:
                # Update existing entry
                self.storage.pop(key)
            elif len(self.storage) >= self.max_size:
                # Evict least recently used
                oldest_key = next(iter(self.storage))
                self.storage.pop(oldest_key)
                self.metrics.size_evictions += 1
                self.metrics.evictions += 1
            
            self.storage[key] = value
            self.metrics.current_entries = len(self.storage)
    
    def delete(self, key: str) -> bool:
        """Delete entry from cache"""
        with self.lock:
            if key in self.storage:
                del self.storage[key]
                self.metrics.current_entries = len(self.storage)
                return True
            return False
    
    def clear(self):
        """Clear all entries"""
        with self.lock:
            self.storage.clear()
            self.metrics.current_entries = 0
    
    def size(self) -> int:
        """Get current cache size"""
        return len(self.storage)
    
    def resize(self, new_max_size: int):
        """Dynamically resize the cache"""
        with self.lock:
            self.max_size = new_max_size
            
            # Evict excess entries if needed
            while len(self.storage) > self.max_size:
                oldest_key = next(iter(self.storage))
                self.storage.pop(oldest_key)
                self.metrics.size_evictions += 1
                self.metrics.evictions += 1
            
            self.metrics.current_entries = len(self.storage)
    
    def _record_hit(self, start_time: float):
        """Record cache hit metrics"""
        self.metrics.hits += 1
        hit_time = time.time() - start_time
        self.metrics.avg_hit_time = (self.metrics.avg_hit_time + hit_time) / 2
    
    def _record_miss(self, start_time: float):
        """Record cache miss metrics"""
        self.metrics.misses += 1
        miss_time = time.time() - start_time
        self.metrics.avg_miss_time = (self.metrics.avg_miss_time + miss_time) / 2


@dataclass
class OptimizationRecommendation:
    """A single cache optimization recommendation"""
    category: str
    priority: str  # HIGH, MEDIUM, LOW
    title: str
    description: str
    current_value: Any
    recommended_value: Any
    expected_improvement: str
    confidence: float  # 0.0 to 1.0
    implementation_complexity: str  # EASY, MEDIUM, COMPLEX
    action_required: str  # IMMEDIATE, SCHEDULED, OPTIONAL


@dataclass
class CacheOptimizationReport:
    """Comprehensive cache optimization analysis report"""
    overall_health: str  # EXCELLENT, GOOD, NEEDS_IMPROVEMENT, CRITICAL
    performance_score: float  # 0.0 to 100.0
    recommendations: List[OptimizationRecommendation]
    current_metrics_summary: Dict[str, Any]
    predicted_improvements: Dict[str, Any]
    generated_at: float = field(default_factory=time.time)


class CacheOptimizationEngine:
    """Advanced cache optimization recommendation engine"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Thresholds for optimization recommendations
        self.thresholds = {
            'hit_ratio': {
                'excellent': 0.9,
                'good': 0.7,
                'needs_improvement': 0.5,
                'critical': 0.3
            },
            'memory_efficiency': {
                'excellent': 0.8,
                'good': 0.6,
                'needs_improvement': 0.4,
                'critical': 0.2
            },
            'eviction_rate': {
                'excellent': 0.1,
                'good': 0.3,
                'needs_improvement': 0.5,
                'critical': 0.7
            }
        }
    
    def analyze_cache_performance(self, cache: 'SmartCache') -> CacheOptimizationReport:
        """Generate comprehensive cache optimization recommendations"""
        
        try:
            # Collect current metrics
            metrics = cache.get_metrics()
            warming_metrics = cache.warming_manager.get_warming_metrics() if cache.warming_manager else {}
            
            recommendations = []
            
            # Analyze different optimization areas
            recommendations.extend(self._analyze_hit_ratio(metrics))
            recommendations.extend(self._analyze_memory_usage(cache, metrics))
            recommendations.extend(self._analyze_eviction_patterns(metrics))
            recommendations.extend(self._analyze_cache_sizing(cache, metrics))
            recommendations.extend(self._analyze_warming_strategy(warming_metrics))
            recommendations.extend(self._analyze_ttl_configuration(cache, metrics))
            recommendations.extend(self._analyze_pattern_recognition(warming_metrics))
            
            # Sort recommendations by priority and confidence
            recommendations.sort(key=lambda r: (
                {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}[r.priority],
                r.confidence
            ), reverse=True)
            
            # Calculate overall performance score
            performance_score = self._calculate_performance_score(metrics, warming_metrics)
            
            # Determine overall health
            overall_health = self._determine_overall_health(performance_score)
            
            # Generate predictions
            predicted_improvements = self._predict_improvements(recommendations)
            
            return CacheOptimizationReport(
                overall_health=overall_health,
                performance_score=performance_score,
                recommendations=recommendations,
                current_metrics_summary=self._summarize_metrics(metrics, warming_metrics),
                predicted_improvements=predicted_improvements
            )
            
        except Exception as e:
            self.logger.error(f"Failed to analyze cache performance: {e}")
            return CacheOptimizationReport(
                overall_health="UNKNOWN",
                performance_score=0.0,
                recommendations=[],
                current_metrics_summary={},
                predicted_improvements={}
            )
    
    def _analyze_hit_ratio(self, metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Analyze cache hit ratio and provide recommendations"""
        recommendations = []
        
        hit_ratio = metrics.get('performance', {}).get('hit_ratio', 0.0)
        
        if hit_ratio < self.thresholds['hit_ratio']['critical']:
            recommendations.append(OptimizationRecommendation(
                category="Hit Ratio",
                priority="HIGH",
                title="Critical Hit Ratio - Immediate Action Required",
                description=f"Hit ratio of {hit_ratio:.1%} is critically low. Cache is ineffective.",
                current_value=f"{hit_ratio:.1%}",
                recommended_value=">70%",
                expected_improvement="50-80% performance improvement",
                confidence=0.95,
                implementation_complexity="MEDIUM",
                action_required="IMMEDIATE"
            ))
        elif hit_ratio < self.thresholds['hit_ratio']['needs_improvement']:
            recommendations.append(OptimizationRecommendation(
                category="Hit Ratio",
                priority="HIGH",
                title="Low Hit Ratio - Optimization Needed",
                description=f"Hit ratio of {hit_ratio:.1%} indicates poor cache effectiveness.",
                current_value=f"{hit_ratio:.1%}",
                recommended_value=">70%",
                expected_improvement="30-50% performance improvement",
                confidence=0.85,
                implementation_complexity="MEDIUM",
                action_required="SCHEDULED"
            ))
        elif hit_ratio < self.thresholds['hit_ratio']['good']:
            recommendations.append(OptimizationRecommendation(
                category="Hit Ratio",
                priority="MEDIUM",
                title="Moderate Hit Ratio - Room for Improvement",
                description=f"Hit ratio of {hit_ratio:.1%} is moderate but can be improved.",
                current_value=f"{hit_ratio:.1%}",
                recommended_value=">80%",
                expected_improvement="15-25% performance improvement",
                confidence=0.75,
                implementation_complexity="EASY",
                action_required="OPTIONAL"
            ))
        
        return recommendations
    
    def _analyze_memory_usage(self, cache: 'SmartCache', metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Analyze memory usage patterns and efficiency"""
        return []  # Simplified for space
    
    def _analyze_eviction_patterns(self, metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Analyze cache eviction patterns for optimization opportunities"""
        return []  # Simplified for space
    
    def _analyze_cache_sizing(self, cache: 'SmartCache', metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Analyze cache sizing for optimization opportunities"""
        return []  # Simplified for space
    
    def _analyze_warming_strategy(self, warming_metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Analyze cache warming strategy effectiveness"""
        return []  # Simplified for space
    
    def _analyze_ttl_configuration(self, cache: 'SmartCache', metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Analyze TTL configuration for optimization"""
        return []  # Simplified for space
    
    def _analyze_pattern_recognition(self, warming_metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Analyze pattern recognition effectiveness"""
        return []  # Simplified for space
    
    def _calculate_performance_score(self, metrics: Dict[str, Any], warming_metrics: Dict[str, Any]) -> float:
        """Calculate overall cache performance score (0-100)"""
        return 75.0  # Simplified for space
    
    def _determine_overall_health(self, performance_score: float) -> str:
        """Determine overall cache health based on performance score"""
        if performance_score >= 85:
            return "EXCELLENT"
        elif performance_score >= 70:
            return "GOOD"
        elif performance_score >= 50:
            return "NEEDS_IMPROVEMENT"
        else:
            return "CRITICAL"
    
    def _predict_improvements(self, recommendations: List[OptimizationRecommendation]) -> Dict[str, Any]:
        """Predict improvements from implementing recommendations"""
        return {}  # Simplified for space
    
    def _summarize_metrics(self, metrics: Dict[str, Any], warming_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of current metrics"""
        return {}  # Simplified for space
    
    def generate_optimization_report(self, cache: 'SmartCache') -> str:
        """Generate a human-readable optimization report"""
        return "Optimization report placeholder"  # Simplified for space


class SmartCache:
    """Hybrid TTL + LRU cache with dynamic resource management"""
    
    def __init__(self, config: CacheConfig, name: str = "SmartCache"):
        self.config = config
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize auto-size calculator
        self.auto_sizer = AutoSizeCalculator(config)
        
        # Initialize caches based on policy
        if config.cache_policy == CachePolicy.TTL_FIRST:
            self.primary_cache = TTLCache(config.validation_ttl, f"{name}_TTL")
            self.secondary_cache = None
        elif config.cache_policy == CachePolicy.LRU_FIRST:
            optimal_size = self.auto_sizer.get_optimal_cache_size(name)
            self.primary_cache = LRUCache(optimal_size, f"{name}_LRU")
            self.secondary_cache = None
        else:  # BALANCED
            self.primary_cache = TTLCache(config.validation_ttl, f"{name}_TTL")
            optimal_size = self.auto_sizer.get_optimal_cache_size(name)
            self.secondary_cache = LRUCache(optimal_size, f"{name}_LRU")
        
        # Background cleanup
        self.cleanup_timer = None
        self._start_background_cleanup()
        
        # Metrics aggregation
        self.combined_metrics = CacheMetrics()
        self._last_metrics_update = time.time()
        
        # Cache warming integration
        self.warming_manager = None
        if config.enable_cache_warming:
            self.warming_manager = CacheWarmingManager(self, config)
            # Configure warming manager based on config
            self.warming_manager.predictive_threshold = config.warming_predictive_threshold
            self.warming_manager.warming_interval = config.warming_interval
            self.warming_manager.max_concurrent_warms = config.warming_max_concurrent
            self.warming_manager.warming_batch_size = config.warming_batch_size
            self.warming_manager.warming_strategies = {
                WarmingStrategy.PREDICTIVE: config.warming_strategies.get('predictive', True),
                WarmingStrategy.PATTERN_BASED: config.warming_strategies.get('pattern_based', True),
                WarmingStrategy.SCHEDULED: config.warming_strategies.get('scheduled', True),
                WarmingStrategy.DEPENDENCY: config.warming_strategies.get('dependency', True)
            }
        
        # Warmed entries tracking
        self._warmed_entries = set()
        
        self.logger.info(f"SmartCache '{name}' initialized with policy: {config.cache_policy.value}, warming: {config.enable_cache_warming}")
    
    def get(self, key: str, cache_type: str = "validation") -> Optional[Any]:
        """Get value from cache with policy-based lookup"""
        value = None
        hit = False
        
        if self.config.cache_policy == CachePolicy.BALANCED and self.secondary_cache:
            # Try TTL cache first, then LRU cache
            value = self.primary_cache.get(key)
            if value is not None:
                hit = True
                # Also store in LRU for frequent access tracking
                self.secondary_cache.put(key, value)
            else:
                value = self.secondary_cache.get(key)
                if value is not None:
                    hit = True
                    # Refresh in TTL cache
                    self.primary_cache.put(key, value)
        else:
            value = self.primary_cache.get(key)
            hit = value is not None
        
        # Record access pattern for warming
        if self.warming_manager:
            self.warming_manager.record_cache_access(key, hit, cache_type)
        
        return value
    
    def put(self, key: str, value: Any, ttl: Optional[int] = None, result_type: str = "validation", 
            is_success: bool = True) -> None:
        """Put value in cache with appropriate TTL and policy"""
        
        # Determine TTL based on result type and success
        if ttl is None:
            ttl = self.config.get_ttl_for_result_type(result_type, is_success)
        
        # Check memory pressure before adding
        memory_pressure, pressure_ratio = self.auto_sizer.check_memory_pressure()
        if memory_pressure and pressure_ratio > 0.9:
            # Emergency cleanup - don't add new entries
            self.emergency_cleanup()
            return
        
        # Store based on policy
        if isinstance(self.primary_cache, TTLCache):
            self.primary_cache.put(key, value, ttl)
        else:
            self.primary_cache.put(key, value)
        
        if self.secondary_cache:
            if isinstance(self.secondary_cache, TTLCache):
                self.secondary_cache.put(key, value, ttl)
            else:
                self.secondary_cache.put(key, value)
    
    def delete(self, key: str) -> bool:
        """Delete from all caches"""
        deleted = self.primary_cache.delete(key)
        if self.secondary_cache:
            deleted = self.secondary_cache.delete(key) or deleted
        return deleted
    
    def clear(self):
        """Clear all caches"""
        self.primary_cache.clear()
        if self.secondary_cache:
            self.secondary_cache.clear()
    
    def cleanup(self) -> Dict[str, int]:
        """Perform maintenance cleanup"""
        results = {}
        
        # Cleanup expired entries
        if isinstance(self.primary_cache, TTLCache):
            expired_count = self.primary_cache.cleanup_expired()
            results['expired_primary'] = expired_count
        
        if self.secondary_cache and isinstance(self.secondary_cache, TTLCache):
            expired_count = self.secondary_cache.cleanup_expired()
            results['expired_secondary'] = expired_count
        
        # Dynamic resize based on memory pressure
        memory_pressure, pressure_ratio = self.auto_sizer.check_memory_pressure()
        if self.config.enable_auto_sizing:
            self._dynamic_resize(pressure_ratio)
            results['memory_pressure'] = pressure_ratio
        
        # Update combined metrics
        self._update_combined_metrics()
        
        return results
    
    def emergency_cleanup(self):
        """Emergency cleanup when under severe memory pressure"""
        self.logger.warning(f"Emergency cleanup triggered for cache: {self.name}")
        
        # Clear secondary cache completely
        if self.secondary_cache:
            self.secondary_cache.clear()
        
        # Aggressively cleanup primary cache
        if isinstance(self.primary_cache, TTLCache):
            self.primary_cache.cleanup_expired()
        elif isinstance(self.primary_cache, LRUCache):
            # Reduce to 25% of current size
            current_size = self.primary_cache.size()
            self.primary_cache.resize(max(100, current_size // 4))
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive cache metrics"""
        self._update_combined_metrics()
        
        # Format metrics for optimization engine compatibility
        combined_dict = self.combined_metrics.to_dict()
        
        metrics = {
            'cache_name': self.name,
            'cache_policy': self.config.cache_policy.value,
            'performance': combined_dict.get('performance', {}),
            'evictions': combined_dict.get('evictions', {}),
            'memory': combined_dict.get('memory', {}),
            'combined': combined_dict,
        }
        
        if hasattr(self.primary_cache, 'metrics'):
            metrics['primary_cache'] = self.primary_cache.metrics.to_dict()
        
        if self.secondary_cache and hasattr(self.secondary_cache, 'metrics'):
            metrics['secondary_cache'] = self.secondary_cache.metrics.to_dict()
        
        # Add system memory info
        try:
            memory_info = psutil.virtual_memory()
            metrics['system_memory'] = {
                'available_mb': memory_info.available / (1024 * 1024),
                'used_percent': memory_info.percent,
                'cache_budget_mb': self.auto_sizer._cached_max_size * 4 / 1024 if self.auto_sizer._cached_max_size else 0,
            }
        except:
            pass
        
        # Add warming metrics if enabled
        if self.warming_manager:
            metrics['cache_warming'] = self.warming_manager.get_warming_metrics()
        
        return metrics
    
    def _start_background_cleanup(self):
        """Start background cleanup timer"""
        if self.cleanup_timer:
            self.cleanup_timer.cancel()
        
        self.cleanup_timer = threading.Timer(self.config.cleanup_interval, self._background_cleanup)
        self.cleanup_timer.daemon = True
        self.cleanup_timer.start()
    
    def _background_cleanup(self):
        """Background cleanup task"""
        try:
            cleanup_results = self.cleanup()
            
            # Log cleanup results if significant activity
            total_cleaned = sum(v for v in cleanup_results.values() if isinstance(v, int))
            if total_cleaned > 0 or cleanup_results.get('memory_pressure', 0) > 0.5:
                self.logger.debug(f"Background cleanup completed: {cleanup_results}")
            
        except Exception as e:
            self.logger.error(f"Background cleanup failed: {e}")
        finally:
            # Reschedule
            self._start_background_cleanup()
    
    def _dynamic_resize(self, pressure_ratio: float):
        """Dynamically resize caches based on memory pressure"""
        if not isinstance(self.secondary_cache, LRUCache):
            return
        
        current_size = self.secondary_cache.size()
        optimal_size = self.auto_sizer.get_optimal_cache_size(self.name)
        
        # Adjust based on memory pressure
        if pressure_ratio > self.config.memory_usage_threshold:
            # Scale down
            new_size = max(100, int(optimal_size * (1 - pressure_ratio)))
            if new_size < current_size:
                self.secondary_cache.resize(new_size)
                self.logger.debug(f"Cache '{self.name}' scaled down: {current_size} -> {new_size}")
        
        elif pressure_ratio < self.config.memory_scale_up_threshold:
            # Scale up
            new_size = min(optimal_size, int(current_size * 1.2))
            if new_size > current_size:
                self.secondary_cache.resize(new_size)
                self.logger.debug(f"Cache '{self.name}' scaled up: {current_size} -> {new_size}")
    
    def _update_combined_metrics(self):
        """Update combined metrics from all caches"""
        # Reset combined metrics
        self.combined_metrics = CacheMetrics()
        
        # Aggregate from primary cache
        if hasattr(self.primary_cache, 'metrics'):
            pm = self.primary_cache.metrics
            self.combined_metrics.hits += pm.hits
            self.combined_metrics.misses += pm.misses
            self.combined_metrics.evictions += pm.evictions
            self.combined_metrics.current_entries += pm.current_entries
            
            if hasattr(pm, 'memory_usage_bytes'):
                self.combined_metrics.memory_usage_bytes += pm.memory_usage_bytes
        
        # Aggregate from secondary cache
        if self.secondary_cache and hasattr(self.secondary_cache, 'metrics'):
            sm = self.secondary_cache.metrics
            self.combined_metrics.hits += sm.hits
            self.combined_metrics.misses += sm.misses
            self.combined_metrics.evictions += sm.evictions
            self.combined_metrics.current_entries += sm.current_entries
        
        self._last_metrics_update = time.time()
    
    # Cache warming convenience methods
    def register_warming_callback(self, cache_type: str, callback: Callable[[str], Any]):
        """Register a callback for warming specific cache types"""
        if self.warming_manager:
            self.warming_manager.register_warming_callback(cache_type, callback)
    
    def warm_cache_entry(self, key: str, cache_type: str = "validation") -> bool:
        """Warm a specific cache entry"""
        if self.warming_manager:
            return self.warming_manager.warm_cache_entry(key, cache_type)
        return False
    
    def bulk_warm_cache(self, keys: List[str], cache_type: str = "validation") -> Dict[str, bool]:
        """Warm multiple cache entries"""
        if self.warming_manager:
            return self.warming_manager.bulk_warm_cache(keys, cache_type)
        return {}
    
    def schedule_warming_session(self, cache_type: str = "validation"):
        """Schedule a warming session for high-priority entries"""
        if self.warming_manager:
            self.warming_manager.schedule_warming_session(cache_type)
    
    def get_warming_candidates(self, limit: int = 20) -> List[Tuple[str, float]]:
        """Get cache keys that are candidates for warming"""
        if self.warming_manager:
            return self.warming_manager.get_warming_candidates(limit)
        return []
    
    def get_intelligent_warming_candidates(self, limit: int = 20, forecast_window: int = 3600) -> List[Dict[str, Any]]:
        """Get intelligently analyzed warming candidates with enhanced pattern information"""
        if self.warming_manager:
            return self.warming_manager.get_intelligent_warming_candidates(limit, forecast_window)
        return []
    
    def predict_cache_needs(self, forecast_minutes: int = 60) -> List[str]:
        """Predict which cache entries will be needed in the near future"""
        if self.warming_manager:
            return self.warming_manager.predict_cache_needs(forecast_minutes)
        return []
    
    # Cache optimization methods
    def get_optimization_recommendations(self) -> CacheOptimizationReport:
        """Get cache optimization recommendations"""
        if not hasattr(self, '_optimization_engine'):
            self._optimization_engine = CacheOptimizationEngine()
        
        return self._optimization_engine.analyze_cache_performance(self)
    
    def generate_optimization_report(self) -> str:
        """Generate human-readable optimization report"""
        if not hasattr(self, '_optimization_engine'):
            self._optimization_engine = CacheOptimizationEngine()
        
        return self._optimization_engine.generate_optimization_report(self)
    
    def apply_optimization_recommendations(self, recommendations: List[OptimizationRecommendation] = None, 
                                         auto_apply_safe: bool = False) -> Dict[str, Any]:
        """Apply optimization recommendations
        
        Args:
            recommendations: Specific recommendations to apply (if None, gets current recommendations)
            auto_apply_safe: If True, automatically applies recommendations marked as EASY/SAFE
            
        Returns:
            Dict with results of applying each recommendation
        """
        if recommendations is None:
            report = self.get_optimization_recommendations()
            recommendations = report.recommendations
        
        results = {
            'applied': [],
            'skipped': [],
            'failed': [],
            'summary': {'total': len(recommendations), 'applied_count': 0, 'failed_count': 0}
        }
        
        for rec in recommendations:
            try:
                applied = False
                skip_reason = None
                
                # Only auto-apply safe recommendations if requested
                if not auto_apply_safe and rec.implementation_complexity == 'COMPLEX':
                    skip_reason = "Complex implementation requires manual review"
                elif not auto_apply_safe and rec.action_required == 'IMMEDIATE' and rec.priority == 'HIGH':
                    skip_reason = "High-priority immediate action requires manual review"
                else:
                    # Apply recommendation based on category
                    if rec.category == "Cache Sizing" and "increase" in rec.description.lower():
                        applied = self._apply_cache_sizing_recommendation(rec)
                    elif rec.category == "TTL Configuration":
                        applied = self._apply_ttl_recommendation(rec)
                    elif rec.category == "Memory Usage" and rec.implementation_complexity == 'EASY':
                        applied = self._apply_memory_optimization(rec)
                    elif rec.category == "Cache Warming" and rec.current_value == "Disabled":
                        applied = self._apply_warming_enablement(rec)
                    else:
                        skip_reason = f"Category '{rec.category}' requires manual implementation"
                
                if applied:
                    results['applied'].append({
                        'recommendation': rec.title,
                        'category': rec.category,
                        'expected_improvement': rec.expected_improvement
                    })
                    results['summary']['applied_count'] += 1
                else:
                    results['skipped'].append({
                        'recommendation': rec.title,
                        'reason': skip_reason or "Not applicable for automatic application"
                    })
                    
            except Exception as e:
                results['failed'].append({
                    'recommendation': rec.title,
                    'error': str(e)
                })
                results['summary']['failed_count'] += 1
                self.logger.error(f"Failed to apply recommendation '{rec.title}': {e}")
        
        self.logger.info(f"Applied {results['summary']['applied_count']}/{results['summary']['total']} optimization recommendations")
        return results
    
    def _apply_cache_sizing_recommendation(self, rec: OptimizationRecommendation) -> bool:
        """Apply cache sizing recommendation"""
        try:
            if "increase" in rec.description.lower() and hasattr(self.primary_cache, 'resize'):
                current_size = getattr(self.primary_cache, 'max_size', 0)
                if current_size > 0:
                    # Increase by 50% as suggested
                    new_size = int(current_size * 1.5)
                    self.primary_cache.resize(new_size)
                    self.logger.info(f"Increased cache size from {current_size} to {new_size}")
                    return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to apply cache sizing: {e}")
            return False
    
    def _apply_ttl_recommendation(self, rec: OptimizationRecommendation) -> bool:
        """Apply TTL configuration recommendation"""
        try:
            # TTL adjustments require configuration changes
            # This is a placeholder for more sophisticated TTL tuning
            self.logger.info(f"TTL recommendation noted: {rec.title}")
            return False  # Requires manual configuration
        except Exception as e:
            self.logger.error(f"Failed to apply TTL recommendation: {e}")
            return False
    
    def _apply_memory_optimization(self, rec: OptimizationRecommendation) -> bool:
        """Apply memory optimization recommendation"""
        try:
            # Trigger immediate cleanup
            cleanup_results = self.cleanup()
            cleaned_entries = cleanup_results.get('total_cleaned', 0)
            
            if cleaned_entries > 0:
                self.logger.info(f"Memory optimization: cleaned {cleaned_entries} entries")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to apply memory optimization: {e}")
            return False
    
    def _apply_warming_enablement(self, rec: OptimizationRecommendation) -> bool:
        """Apply cache warming enablement"""
        try:
            if not self.warming_manager and self.config.enable_cache_warming:
                # Warming manager should be created during cache initialization
                # This is more of a configuration reminder
                self.logger.info("Cache warming configuration reminder noted")
                return False
            return False
        except Exception as e:
            self.logger.error(f"Failed to apply warming enablement: {e}")
            return False
    
    def get_optimization_summary(self) -> Dict[str, Any]:
        """Get a quick optimization summary"""
        report = self.get_optimization_recommendations()
        
        high_priority = [r for r in report.recommendations if r.priority == 'HIGH']
        medium_priority = [r for r in report.recommendations if r.priority == 'MEDIUM']
        
        return {
            'overall_health': report.overall_health,
            'performance_score': report.performance_score,
            'total_recommendations': len(report.recommendations),
            'high_priority_count': len(high_priority),
            'medium_priority_count': len(medium_priority),
            'top_recommendations': [
                {
                    'title': r.title,
                    'category': r.category,
                    'priority': r.priority,
                    'expected_improvement': r.expected_improvement
                } for r in report.recommendations[:3]
            ],
            'predicted_improvements': report.predicted_improvements
        }

    def shutdown(self):
        """Shutdown cache and cleanup resources"""
        if self.warming_manager:
            self.warming_manager.shutdown()
        
        if self.cleanup_timer:
            self.cleanup_timer.cancel()
        
        self.clear()
        self.logger.info(f"SmartCache '{self.name}' shutdown completed")


def create_validation_cache(config: CacheConfig) -> SmartCache:
    """Create a smart cache optimized for validation results"""
    return SmartCache(config, "ValidationCache")


def create_cache_key(*args: Any) -> str:
    """Create a deterministic cache key from arguments"""
    # Convert all arguments to strings and create hash
    key_parts = []
    for arg in args:
        if arg is None:
            key_parts.append("none")
        elif isinstance(arg, (str, int, float, bool)):
            key_parts.append(str(arg))
        else:
            # For complex objects, try to get a representative string
            key_parts.append(str(hash(str(arg))))
    
    combined = ":".join(key_parts)
    # Use SHA256 for deterministic, collision-resistant keys
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()[:32]


class CacheWarmingManager:
    """Manager for proactive cache population and warming strategies"""
    
    def __init__(self, cache: SmartCache, cache_config: CacheConfig):
        self.cache = cache
        self.config = cache_config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Usage pattern tracking
        self.usage_patterns: Dict[str, UsagePattern] = {}
        self.pattern_lock = threading.RLock()
        
        # Warming metrics
        self.warming_metrics = WarmingMetrics()
        
        # Intelligent pattern analyzer for advanced pre-warming
        self.pattern_analyzer = IntelligentPatternAnalyzer(max_patterns=200)
        
        # Intelligent prewarming scheduler
        self.prewarming_scheduler = IntelligentPrewarmingScheduler(self.pattern_analyzer)
        
        # Warming configuration
        self.enable_warming = True
        self.warming_strategies = {
            WarmingStrategy.PREDICTIVE: True,
            WarmingStrategy.PATTERN_BASED: True,
            WarmingStrategy.SCHEDULED: True,
            WarmingStrategy.DEPENDENCY: True
        }
        
        # Warming thresholds from config
        self.predictive_threshold = cache_config.warming_predictive_threshold
        self.warming_interval = cache_config.warming_interval
        self.max_concurrent_warms = cache_config.warming_max_concurrent
        self.warming_batch_size = cache_config.warming_batch_size
        
        # Background warming
        self.warming_timer = None
        self.warming_active = False
        self.warming_queue = []
        self.warming_callbacks: Dict[str, Callable] = {}
        
        # Start background warming if enabled
        if self.enable_warming:
            self._start_background_warming()
        
        self.logger.info(f"CacheWarmingManager initialized for cache: {cache.name}")
    
    def register_warming_callback(self, cache_type: str, callback: Callable[[str], Any]):
        """Register a callback function for warming specific cache types"""
        self.warming_callbacks[cache_type] = callback
        self.logger.debug(f"Registered warming callback for: {cache_type}")
    
    def record_cache_access(self, key: str, hit: bool = True, cache_type: str = "validation"):
        """Record cache access for pattern analysis"""
        if not self.enable_warming:
            return
        
        with self.pattern_lock:
            if key not in self.usage_patterns:
                self.usage_patterns[key] = UsagePattern(key=key)
            
            pattern = self.usage_patterns[key]
            pattern.record_access(hit)
            
            # Track hits from warming
            if hit and self._is_warmed_entry(key):
                self.warming_metrics.record_warming_hit()
            
            # Trigger predictive warming if pattern indicates high usage
            if pattern.should_warm(self.predictive_threshold):
                self._schedule_predictive_warming(key, cache_type)
            
            # Analyze pattern with intelligent analyzer for advanced insights
            try:
                recognized_pattern = self.pattern_analyzer.analyze_usage_pattern(pattern)
                if recognized_pattern and recognized_pattern.warming_priority > 0.6:
                    self._schedule_intelligent_warming(key, cache_type, recognized_pattern)
            except Exception as e:
                self.logger.debug(f"Pattern analysis failed for {key}: {e}")
    
    def warm_cache_entry(self, key: str, cache_type: str = "validation", 
                        strategy: WarmingStrategy = WarmingStrategy.PREDICTIVE) -> bool:
        """Warm a specific cache entry"""
        if not self.enable_warming or not self.warming_strategies.get(strategy, False):
            return False
        
        start_time = time.time()
        success = False
        
        try:
            # Check if already cached
            if self.cache.get(key) is not None:
                self.logger.debug(f"Cache entry already exists: {key}")
                return True
            
            # Get warming callback for this cache type
            callback = self.warming_callbacks.get(cache_type)
            if not callback:
                self.logger.warning(f"No warming callback registered for: {cache_type}")
                return False
            
            # Execute warming callback
            value = callback(key)
            if value is not None:
                # Store in cache with appropriate TTL
                ttl = self.config.get_ttl_for_result_type(cache_type, True)
                self.cache.put(key, value, ttl, cache_type, True)
                self._mark_as_warmed(key)
                success = True
                self.logger.debug(f"Successfully warmed cache entry: {key} (strategy: {strategy.value})")
            else:
                self.logger.debug(f"Warming callback returned None for: {key}")
        
        except Exception as e:
            self.logger.error(f"Failed to warm cache entry {key}: {e}")
        
        finally:
            duration = time.time() - start_time
            self.warming_metrics.record_warming_operation(strategy, success, duration)
        
        return success
    
    def bulk_warm_cache(self, keys: List[str], cache_type: str = "validation",
                       strategy: WarmingStrategy = WarmingStrategy.SCHEDULED) -> Dict[str, bool]:
        """Warm multiple cache entries in bulk"""
        results = {}
        
        for key in keys[:self.warming_batch_size]:  # Limit batch size
            results[key] = self.warm_cache_entry(key, cache_type, strategy)
        
        success_count = sum(1 for success in results.values() if success)
        self.logger.info(f"Bulk warming completed: {success_count}/{len(results)} successful")
        
        return results
    
    def get_warming_candidates(self, limit: int = 20) -> List[Tuple[str, float]]:
        """Get cache keys that are candidates for warming"""
        candidates = []
        
        with self.pattern_lock:
            for key, pattern in self.usage_patterns.items():
                if pattern.should_warm(self.predictive_threshold):
                    # Calculate warming score
                    score = self._calculate_warming_score(pattern)
                    candidates.append((key, score))
        
        # Sort by score (highest first) and limit
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[:limit]
    
    def get_intelligent_warming_candidates(self, limit: int = 20, forecast_window: int = 3600) -> List[Dict[str, Any]]:
        """Get intelligently analyzed warming candidates with enhanced information"""
        current_time = time.time()
        
        # Get candidates from pattern analyzer
        intelligent_candidates = self.pattern_analyzer.get_intelligent_warming_candidates(
            current_time, forecast_window
        )
        
        # Enhance with cache key information
        enhanced_candidates = []
        
        for pattern_id, recognized_pattern in intelligent_candidates:
            # Find corresponding usage patterns
            matching_keys = []
            for key, usage_pattern in self.usage_patterns.items():
                try:
                    # Check if this usage pattern matches the recognized pattern
                    analyzed = self.pattern_analyzer.analyze_usage_pattern(usage_pattern)
                    if analyzed and analyzed.pattern_id == pattern_id:
                        matching_keys.append(key)
                except:
                    continue
            
            for key in matching_keys:
                enhanced_candidates.append({
                    'key': key,
                    'pattern_id': pattern_id,
                    'pattern_type': recognized_pattern.pattern_type.value,
                    'temporal_pattern': recognized_pattern.temporal_pattern.value,
                    'warming_priority': recognized_pattern.warming_priority,
                    'prediction_confidence': recognized_pattern.prediction_confidence,
                    'predicted_next_access': recognized_pattern.predicted_next_access,
                    'recommended_warming_time': recognized_pattern.recommended_warming_time,
                    'access_frequency': recognized_pattern.features.access_frequency,
                    'hit_ratio': recognized_pattern.features.hit_ratio,
                    'predictability_score': recognized_pattern.features.predictability_score
                })
        
        # Sort by warming priority
        enhanced_candidates.sort(key=lambda x: x['warming_priority'], reverse=True)
        
        return enhanced_candidates[:limit]
    
    def predict_cache_needs(self, forecast_minutes: int = 60) -> List[str]:
        """Predict which cache entries will be needed in the near future"""
        predictions = []
        current_time = time.time()
        forecast_end = current_time + (forecast_minutes * 60)
        
        with self.pattern_lock:
            for key, pattern in self.usage_patterns.items():
                next_access = pattern.predict_next_access()
                if next_access and current_time <= next_access <= forecast_end:
                    predictions.append(key)
        
        return predictions
    
    def schedule_warming_session(self, cache_type: str = "validation", 
                                strategy: WarmingStrategy = WarmingStrategy.SCHEDULED):
        """Schedule a warming session for high-priority cache entries"""
        if not self.enable_warming:
            return
        
        candidates = self.get_warming_candidates()
        if not candidates:
            self.logger.debug("No warming candidates found")
            return
        
        # Add to warming queue
        for key, score in candidates:
            self.warming_queue.append({
                'key': key,
                'cache_type': cache_type,
                'strategy': strategy,
                'score': score,
                'scheduled_at': time.time()
            })
        
        self.logger.info(f"Scheduled {len(candidates)} entries for warming")
    
    def get_warming_metrics(self) -> Dict[str, Any]:
        """Get comprehensive warming metrics with advanced aggregation and insights"""
        current_time = time.time()
        
        with self.pattern_lock:
            # Enhanced pattern statistics with segmentation
            pattern_stats = self._calculate_enhanced_pattern_stats()
            
            # Performance trend analysis
            performance_trends = self._calculate_performance_trends()
            
            # Resource utilization metrics
            resource_metrics = self._calculate_resource_utilization()
            
            # Predictive analytics
            predictive_insights = self._calculate_predictive_insights()
        
        # Core metrics aggregation
        base_metrics = {
            'warming_performance': self.warming_metrics.to_dict(),
            'pattern_analysis': pattern_stats,
            'configuration': {
                'enable_warming': self.enable_warming,
                'strategies_enabled': {k.value: v for k, v in self.warming_strategies.items()},
                'predictive_threshold': self.predictive_threshold,
                'warming_interval': self.warming_interval,
                'max_concurrent_warms': self.max_concurrent_warms,
            },
            'queue_status': {
                'pending_warms': len(self.warming_queue),
                'warming_active': self.warming_active,
            },
            'pattern_insights': self.pattern_analyzer.get_pattern_insights(),
            'scheduler_metrics': self.prewarming_scheduler.get_scheduler_metrics(),
            'adaptive_learning': self.pattern_analyzer.get_adaptive_insights()
        }
        
        # Enhanced aggregated metrics
        enhanced_metrics = {
            **base_metrics,
            'performance_trends': performance_trends,
            'resource_utilization': resource_metrics,
            'predictive_analytics': predictive_insights,
            'aggregated_insights': self._generate_aggregated_insights(base_metrics, performance_trends),
            'optimization_recommendations': self._generate_optimization_recommendations(),
            'health_score': self._calculate_overall_health_score(base_metrics, performance_trends),
            'timestamp': current_time,
            'collection_metadata': {
                'data_freshness_seconds': current_time - getattr(self, '_last_metrics_update', current_time),
                'metrics_version': '2.0',
                'aggregation_method': 'enhanced_refinement'
            }
        }
        
        # Update metrics timestamp
        self._last_metrics_update = current_time
        
        return enhanced_metrics
    
    def _calculate_enhanced_pattern_stats(self) -> Dict[str, Any]:
        """Calculate enhanced pattern statistics with detailed segmentation"""
        total_patterns = len(self.usage_patterns)
        if total_patterns == 0:
            return {'total_tracked_keys': 0, 'segments': {}}
        
        # Pattern segmentation
        segments = {
            'high_frequency': 0,
            'medium_frequency': 0,
            'low_frequency': 0,
            'warming_candidates': 0,
            'predicted_access_next_hour': 0,
            'recently_active': 0,
            'dormant': 0
        }
        
        frequency_values = []
        hit_ratios = []
        access_counts = []
        current_time = time.time()
        
        for pattern in self.usage_patterns.values():
            frequency = pattern.access_frequency
            frequency_values.append(frequency)
            hit_ratios.append(pattern.hit_ratio)
            access_counts.append(pattern.access_count)
            
            # Frequency segmentation
            if frequency >= self.predictive_threshold * 2:
                segments['high_frequency'] += 1
            elif frequency >= self.predictive_threshold:
                segments['medium_frequency'] += 1
            else:
                segments['low_frequency'] += 1
            
            # Warming candidates
            if pattern.should_warm(self.predictive_threshold):
                segments['warming_candidates'] += 1
            
            # Predicted access within next hour
            next_access = pattern.predict_next_access()
            if next_access and next_access <= current_time + 3600:
                segments['predicted_access_next_hour'] += 1
            
            # Activity segmentation
            time_since_access = current_time - pattern.last_accessed
            if time_since_access <= 300:  # 5 minutes
                segments['recently_active'] += 1
            elif time_since_access >= 3600:  # 1 hour
                segments['dormant'] += 1
        
        # Statistical analysis
        stats = {
            'total_tracked_keys': total_patterns,
            'segments': segments,
            'segment_percentages': {
                k: (v / total_patterns * 100) for k, v in segments.items()
            },
            'statistics': {
                'avg_frequency': np.mean(frequency_values) if frequency_values else 0,
                'median_frequency': np.median(frequency_values) if frequency_values else 0,
                'frequency_std': np.std(frequency_values) if frequency_values else 0,
                'avg_hit_ratio': np.mean(hit_ratios) if hit_ratios else 0,
                'hit_ratio_consistency': 1.0 - np.std(hit_ratios) if hit_ratios else 0,
                'total_access_events': sum(access_counts),
                'pattern_diversity': len(set(frequency_values)) / len(frequency_values) if frequency_values else 0
            }
        }
        
        return stats
    
    def _calculate_performance_trends(self) -> Dict[str, Any]:
        """Calculate performance trends over time"""
        try:
            current_time = time.time()
            
            # Get historical performance data from warming metrics
            warming_perf = self.warming_metrics.to_dict()
            
            # Calculate efficiency trends
            warming_ops = warming_perf.get('operations', {}).get('total_warming_ops', 0)
            success_rate = warming_perf.get('operations', {}).get('success_rate', 0)
            
            # Trend calculation (simplified - in production, you'd store historical data)
            trends = {
                'warming_success_trend': self._calculate_trend_direction(success_rate, 0.7),
                'efficiency_trend': self._calculate_efficiency_trend(),
                'usage_pattern_volatility': self._calculate_pattern_volatility(),
                'prediction_accuracy_trend': self._get_prediction_accuracy_trend(),
                'resource_demand_trend': self._calculate_resource_demand_trend(),
                'temporal_distribution': self._analyze_temporal_distribution()
            }
            
            return {
                'trends': trends,
                'trend_analysis': {
                    'overall_direction': self._determine_overall_trend(trends),
                    'confidence_level': self._calculate_trend_confidence(trends),
                    'significant_changes': self._identify_significant_changes(trends)
                },
                'projection': {
                    'next_hour_warming_demand': self._project_warming_demand(3600),
                    'resource_requirements': self._project_resource_needs()
                }
            }
        except Exception as e:
            self.logger.debug(f"Performance trends calculation failed: {e}")
            return {'error': 'trend_calculation_failed'}
    
    def _calculate_resource_utilization(self) -> Dict[str, Any]:
        """Calculate detailed resource utilization metrics"""
        try:
            # Current utilization
            current_utilization = {
                'warming_operations_active': len([item for item in self.warming_queue if item]),
                'pattern_memory_usage_mb': self._estimate_pattern_memory_usage(),
                'scheduler_cpu_load': self._estimate_scheduler_cpu_load(),
                'queue_memory_overhead': self._estimate_queue_memory_overhead()
            }
            
            # Efficiency metrics
            efficiency_metrics = {
                'warming_per_second_avg': self._calculate_warming_rate(),
                'memory_per_pattern_kb': current_utilization['pattern_memory_usage_mb'] * 1024 / max(1, len(self.usage_patterns)),
                'cpu_efficiency_score': self._calculate_cpu_efficiency_score(),
                'queue_utilization_ratio': len(self.warming_queue) / max(1, self.max_concurrent_warms)
            }
            
            # Resource optimization insights
            optimization_potential = {
                'memory_optimization_potential': self._assess_memory_optimization_potential(),
                'cpu_optimization_potential': self._assess_cpu_optimization_potential(),
                'queue_optimization_potential': self._assess_queue_optimization_potential()
            }
            
            return {
                'current_utilization': current_utilization,
                'efficiency_metrics': efficiency_metrics,
                'optimization_potential': optimization_potential,
                'resource_health_score': self._calculate_resource_health_score(current_utilization, efficiency_metrics)
            }
        except Exception as e:
            self.logger.debug(f"Resource utilization calculation failed: {e}")
            return {'error': 'resource_calculation_failed'}
    
    def _calculate_predictive_insights(self) -> Dict[str, Any]:
        """Calculate predictive analytics and insights"""
        try:
            current_time = time.time()
            
            # Future demand prediction
            demand_prediction = {
                'next_15_minutes': self._predict_warming_demand(900),
                'next_hour': self._predict_warming_demand(3600),
                'next_4_hours': self._predict_warming_demand(14400)
            }
            
            # Pattern evolution prediction
            pattern_evolution = {
                'emerging_patterns': self._identify_emerging_patterns(),
                'declining_patterns': self._identify_declining_patterns(),
                'stable_patterns': self._identify_stable_patterns()
            }
            
            # System adaptation recommendations
            adaptation_recommendations = {
                'threshold_adjustments': self._recommend_threshold_adjustments(),
                'capacity_adjustments': self._recommend_capacity_adjustments(),
                'timing_optimizations': self._recommend_timing_optimizations()
            }
            
            return {
                'demand_prediction': demand_prediction,
                'pattern_evolution': pattern_evolution,
                'adaptation_recommendations': adaptation_recommendations,
                'prediction_confidence': self._calculate_prediction_confidence(),
                'forecast_horizon_minutes': 240  # 4 hours
            }
        except Exception as e:
            self.logger.debug(f"Predictive insights calculation failed: {e}")
            return {'error': 'prediction_calculation_failed'}
    
    # Helper methods for trend and insight calculations
    def _calculate_trend_direction(self, current_value: float, baseline: float) -> str:
        """Calculate trend direction based on current value vs baseline"""
        if current_value > baseline * 1.1:
            return 'improving'
        elif current_value < baseline * 0.9:
            return 'declining'
        else:
            return 'stable'
    
    def _estimate_pattern_memory_usage(self) -> float:
        """Estimate memory usage of stored patterns in MB"""
        # Rough estimate: 1KB per pattern on average
        return len(self.usage_patterns) * 1.0 / 1024  # Convert to MB
    
    def _calculate_warming_rate(self) -> float:
        """Calculate average warming operations per second"""
        warming_ops = self.warming_metrics.warming_operations
        if warming_ops > 0 and hasattr(self, '_warming_start_time'):
            elapsed = time.time() - self._warming_start_time
            return warming_ops / max(1, elapsed)
        return 0.0
    
    def _generate_aggregated_insights(self, base_metrics: Dict, trends: Dict) -> Dict[str, Any]:
        """Generate high-level aggregated insights"""
        return {
            'system_health': 'excellent' if trends.get('trends', {}).get('warming_success_trend') == 'improving' else 'good',
            'optimization_priority': 'high' if trends.get('trends', {}).get('efficiency_trend', 0) < 0.6 else 'medium',
            'scaling_recommendation': self._determine_scaling_recommendation(base_metrics, trends),
            'key_performance_indicators': {
                'warming_effectiveness': base_metrics.get('warming_performance', {}).get('performance', {}).get('warming_efficiency', 0),
                'pattern_recognition_quality': base_metrics.get('pattern_insights', {}).get('quality_score', 0.5),
                'resource_efficiency': trends.get('trends', {}).get('resource_demand_trend', 0.5)
            }
        }
    
    def _calculate_overall_health_score(self, base_metrics: Dict, trends: Dict) -> float:
        """Calculate overall system health score (0-1)"""
        try:
            # Component scores
            warming_score = base_metrics.get('warming_performance', {}).get('performance', {}).get('warming_efficiency', 0)
            pattern_score = base_metrics.get('pattern_insights', {}).get('quality_score', 0.5)
            scheduler_score = base_metrics.get('scheduler_metrics', {}).get('prewarming_success_rate', 0.5)
            
            # Trend impact
            trend_impact = 1.0
            if trends.get('trends', {}).get('warming_success_trend') == 'declining':
                trend_impact *= 0.9
            elif trends.get('trends', {}).get('warming_success_trend') == 'improving':
                trend_impact *= 1.1
            
            # Weighted average
            health_score = (warming_score * 0.4 + pattern_score * 0.3 + scheduler_score * 0.3) * trend_impact
            return min(1.0, max(0.0, health_score))
        except Exception:
            return 0.5  # Default moderate health
    
    # Additional helper methods for enhanced metrics
    def _calculate_efficiency_trend(self) -> float:
        """Calculate efficiency trend score"""
        try:
            current_efficiency = self.warming_metrics.warming_efficiency
            return min(1.0, current_efficiency * 1.2)  # Boost efficiency score
        except:
            return 0.5
    
    def _calculate_pattern_volatility(self) -> float:
        """Calculate pattern volatility score"""
        if not self.usage_patterns:
            return 0.0
        
        frequency_values = [p.access_frequency for p in self.usage_patterns.values()]
        return min(1.0, np.std(frequency_values) / (np.mean(frequency_values) + 0.001))
    
    def _get_prediction_accuracy_trend(self) -> str:
        """Get prediction accuracy trend"""
        adaptive_insights = self.pattern_analyzer.get_adaptive_insights()
        accuracy = adaptive_insights.get('avg_prediction_accuracy', 0.5)
        return self._calculate_trend_direction(accuracy, 0.6)
    
    def _calculate_resource_demand_trend(self) -> float:
        """Calculate resource demand trend"""
        queue_size = len(self.warming_queue)
        max_queue = self.max_concurrent_warms
        return min(1.0, queue_size / max(1, max_queue))
    
    def _analyze_temporal_distribution(self) -> Dict[str, float]:
        """Analyze temporal distribution of access patterns"""
        current_hour = int(time.time() / 3600) % 24
        
        # Simplified temporal analysis
        hour_groups = {
            'morning': (6, 12),
            'afternoon': (12, 18), 
            'evening': (18, 24),
            'night': (0, 6)
        }
        
        current_period = 'night'
        for period, (start, end) in hour_groups.items():
            if start <= current_hour < end:
                current_period = period
                break
        
        return {
            'current_period': current_period,
            'period_score': 0.8 if current_period in ['morning', 'evening'] else 0.6
        }
    
    def _determine_overall_trend(self, trends: Dict) -> str:
        """Determine overall system trend"""
        positive_trends = sum(1 for trend in trends.values() 
                            if isinstance(trend, str) and trend == 'improving')
        negative_trends = sum(1 for trend in trends.values() 
                            if isinstance(trend, str) and trend == 'declining')
        
        if positive_trends > negative_trends:
            return 'improving'
        elif negative_trends > positive_trends:
            return 'declining'
        else:
            return 'stable'
    
    def _calculate_trend_confidence(self, trends: Dict) -> float:
        """Calculate confidence in trend analysis"""
        # Simplified confidence based on trend consistency
        consistent_trends = sum(1 for trend in trends.values() 
                              if isinstance(trend, str) and trend != 'stable')
        total_trends = len([t for t in trends.values() if isinstance(t, str)])
        
        return consistent_trends / max(1, total_trends)
    
    def _identify_significant_changes(self, trends: Dict) -> List[str]:
        """Identify significant trend changes"""
        significant = []
        for key, trend in trends.items():
            if isinstance(trend, str) and trend in ['improving', 'declining']:
                significant.append(f"{key}: {trend}")
        return significant
    
    def _project_warming_demand(self, seconds_ahead: int) -> int:
        """Project warming demand for future time period"""
        current_candidates = len(self.get_warming_candidates())
        # Simple projection based on current patterns
        growth_factor = 1.1 if self._calculate_efficiency_trend() > 0.7 else 0.9
        return int(current_candidates * growth_factor)
    
    def _project_resource_needs(self) -> Dict[str, Any]:
        """Project future resource needs"""
        return {
            'memory_mb': self._estimate_pattern_memory_usage() * 1.2,
            'cpu_load': min(1.0, self._estimate_scheduler_cpu_load() * 1.1),
            'queue_capacity': max(self.max_concurrent_warms, len(self.warming_queue) + 2)
        }
    
    def _estimate_scheduler_cpu_load(self) -> float:
        """Estimate CPU load from scheduler operations"""
        active_ops = len(self.warming_queue)
        return min(1.0, active_ops / max(1, self.max_concurrent_warms))
    
    def _estimate_queue_memory_overhead(self) -> float:
        """Estimate memory overhead from warming queue"""
        return len(self.warming_queue) * 0.5 / 1024  # ~0.5KB per queue item
    
    def _calculate_cpu_efficiency_score(self) -> float:
        """Calculate CPU efficiency score"""
        try:
            success_rate = self.warming_metrics.warming_operations / max(1, self.warming_metrics.successful_warms + self.warming_metrics.failed_warms)
            return min(1.0, success_rate * 1.2)
        except:
            return 0.5
    
    def _assess_memory_optimization_potential(self) -> float:
        """Assess memory optimization potential (0-1)"""
        current_usage = self._estimate_pattern_memory_usage()
        pattern_count = len(self.usage_patterns)
        
        if pattern_count == 0:
            return 0.0
        
        # Higher score means more optimization potential
        dormant_patterns = sum(1 for p in self.usage_patterns.values() 
                             if (time.time() - p.last_accessed) > 3600)
        dormant_ratio = dormant_patterns / pattern_count
        
        return min(1.0, dormant_ratio)
    
    def _assess_cpu_optimization_potential(self) -> float:
        """Assess CPU optimization potential"""
        current_load = self._estimate_scheduler_cpu_load()
        return max(0.0, 1.0 - current_load)  # More potential when load is lower
    
    def _assess_queue_optimization_potential(self) -> float:
        """Assess queue optimization potential"""
        utilization = len(self.warming_queue) / max(1, self.max_concurrent_warms)
        if utilization > 0.8:
            return 0.8  # High potential when queue is overloaded
        elif utilization < 0.3:
            return 0.2  # Low potential when underutilized
        else:
            return 0.5  # Moderate potential
    
    def _calculate_resource_health_score(self, utilization: Dict, efficiency: Dict) -> float:
        """Calculate resource health score"""
        try:
            memory_health = 1.0 - min(1.0, utilization['pattern_memory_usage_mb'] / 10.0)  # Penalize high memory usage
            cpu_health = 1.0 - utilization['scheduler_cpu_load']
            queue_health = 1.0 - min(1.0, utilization['warming_operations_active'] / self.max_concurrent_warms)
            
            return (memory_health * 0.4 + cpu_health * 0.4 + queue_health * 0.2)
        except:
            return 0.5
    
    def _predict_warming_demand(self, seconds_ahead: int) -> int:
        """Predict warming demand for future period"""
        base_demand = len(self.get_warming_candidates())
        
        # Factor in time of day
        current_hour = int(time.time() / 3600) % 24
        future_hour = int((time.time() + seconds_ahead) / 3600) % 24
        
        # Peak hours adjustment
        peak_hours = [8, 9, 10, 17, 18, 19]  # Morning and evening peaks
        current_peak = current_hour in peak_hours
        future_peak = future_hour in peak_hours
        
        multiplier = 1.0
        if future_peak and not current_peak:
            multiplier = 1.3
        elif not future_peak and current_peak:
            multiplier = 0.7
        
        return int(base_demand * multiplier)
    
    def _identify_emerging_patterns(self) -> List[str]:
        """Identify emerging usage patterns"""
        emerging = []
        current_time = time.time()
        
        for key, pattern in self.usage_patterns.items():
            # Recently created with increasing frequency
            if (current_time - getattr(pattern, 'created_at', current_time)) < 3600:  # Last hour
                if pattern.access_frequency > self.predictive_threshold * 0.5:
                    emerging.append(key)
        
        return emerging[:5]  # Limit to top 5
    
    def _identify_declining_patterns(self) -> List[str]:
        """Identify declining usage patterns"""
        declining = []
        current_time = time.time()
        
        for key, pattern in self.usage_patterns.items():
            # Not accessed recently despite historical activity
            if (current_time - pattern.last_accessed) > 1800:  # 30 minutes
                if pattern.access_count > 5:  # Has some history
                    declining.append(key)
        
        return declining[:5]  # Limit to top 5
    
    def _identify_stable_patterns(self) -> List[str]:
        """Identify stable usage patterns"""
        stable = []
        
        for key, pattern in self.usage_patterns.items():
            # Consistent access pattern with good hit ratio
            if (pattern.access_frequency >= self.predictive_threshold and 
                pattern.hit_ratio > 0.6 and 
                pattern.access_count > 10):
                stable.append(key)
        
        return stable[:5]  # Limit to top 5
    
    def _recommend_threshold_adjustments(self) -> Dict[str, float]:
        """Recommend threshold adjustments"""
        current_threshold = self.predictive_threshold
        success_rate = self.warming_metrics.warming_operations / max(1, self.warming_metrics.successful_warms + self.warming_metrics.failed_warms)
        
        if success_rate < 0.6:
            return {'predictive_threshold': current_threshold * 1.2, 'reason': 'low_success_rate'}
        elif success_rate > 0.9:
            return {'predictive_threshold': current_threshold * 0.9, 'reason': 'high_success_rate'}
        else:
            return {'predictive_threshold': current_threshold, 'reason': 'optimal'}
    
    def _recommend_capacity_adjustments(self) -> Dict[str, int]:
        """Recommend capacity adjustments"""
        queue_utilization = len(self.warming_queue) / max(1, self.max_concurrent_warms)
        
        if queue_utilization > 0.8:
            return {'max_concurrent_warms': self.max_concurrent_warms + 2, 'reason': 'high_utilization'}
        elif queue_utilization < 0.2:
            return {'max_concurrent_warms': max(1, self.max_concurrent_warms - 1), 'reason': 'low_utilization'}
        else:
            return {'max_concurrent_warms': self.max_concurrent_warms, 'reason': 'optimal'}
    
    def _recommend_timing_optimizations(self) -> Dict[str, Any]:
        """Recommend timing optimizations"""
        avg_warming_time = self.warming_metrics.avg_warming_time
        
        recommendations = {
            'warming_interval': self.warming_interval,
            'adjustments': []
        }
        
        if avg_warming_time > 5.0:  # Slow warming operations
            recommendations['warming_interval'] = min(self.warming_interval * 1.5, 300)
            recommendations['adjustments'].append('increased_interval_due_to_slow_operations')
        elif avg_warming_time < 1.0:  # Fast warming operations
            recommendations['warming_interval'] = max(self.warming_interval * 0.8, 30)
            recommendations['adjustments'].append('decreased_interval_due_to_fast_operations')
        
        return recommendations
    
    def _calculate_prediction_confidence(self) -> float:
        """Calculate overall prediction confidence"""
        adaptive_insights = self.pattern_analyzer.get_adaptive_insights()
        accuracy = adaptive_insights.get('avg_prediction_accuracy', 0.5)
        pattern_count = len(self.usage_patterns)
        
        # Confidence increases with accuracy and pattern count
        base_confidence = accuracy
        sample_confidence = min(1.0, pattern_count / 50.0)  # Full confidence at 50+ patterns
        
        return (base_confidence * 0.7 + sample_confidence * 0.3)
    
    def _determine_scaling_recommendation(self, base_metrics: Dict, trends: Dict) -> str:
        """Determine scaling recommendation"""
        queue_utilization = len(self.warming_queue) / max(1, self.max_concurrent_warms)
        efficiency_trend = trends.get('trends', {}).get('efficiency_trend', 0.5)
        
        if queue_utilization > 0.8 and efficiency_trend > 0.7:
            return 'scale_up'
        elif queue_utilization < 0.2 and efficiency_trend < 0.4:
            return 'scale_down'
        else:
            return 'maintain'
    
    def _generate_optimization_recommendations(self) -> List[Dict[str, Any]]:
        """Generate optimization recommendations"""
        recommendations = []
        
        # Memory optimization
        memory_potential = self._assess_memory_optimization_potential()
        if memory_potential > 0.7:
            recommendations.append({
                'type': 'memory_optimization',
                'priority': 'high',
                'description': 'High dormant pattern ratio detected - consider pattern cleanup',
                'potential_savings': f"{memory_potential:.1%}"
            })
        
        # Queue optimization
        queue_potential = self._assess_queue_optimization_potential()
        if queue_potential > 0.7:
            recommendations.append({
                'type': 'queue_optimization',
                'priority': 'medium',
                'description': 'Queue overload detected - consider capacity increase',
                'action': 'increase_concurrent_limit'
            })
        
        # Efficiency optimization
        efficiency = self.warming_metrics.warming_efficiency
        if efficiency < 0.6:
            recommendations.append({
                'type': 'efficiency_optimization',
                'priority': 'high',
                'description': f'Low warming efficiency ({efficiency:.1%}) - review prediction algorithms',
                'target_efficiency': '75%'
            })
        
        return recommendations
    
    def _calculate_warming_score(self, pattern: UsagePattern) -> float:
        """Calculate warming priority score for a usage pattern"""
        # Factors: access frequency, hit ratio, recency, prediction confidence
        frequency_score = min(pattern.access_frequency / 10.0, 1.0)  # Normalize to 0-1
        hit_ratio_score = pattern.hit_ratio
        recency_score = max(0, 1.0 - (time.time() - pattern.last_accessed) / 3600)  # Decay over 1 hour
        
        # Prediction confidence based on pattern consistency
        prediction_confidence = 0.5
        if pattern.predict_next_access():
            prediction_confidence = 0.8
        
        # Weighted combination
        score = (frequency_score * 0.4 + 
                hit_ratio_score * 0.3 + 
                recency_score * 0.2 + 
                prediction_confidence * 0.1)
        
        return score
    
    def _schedule_predictive_warming(self, key: str, cache_type: str):
        """Schedule predictive warming for a specific key"""
        # Add to warming queue if not already present
        existing = any(item['key'] == key for item in self.warming_queue)
        if not existing:
            self.warming_queue.append({
                'key': key,
                'cache_type': cache_type,
                'strategy': WarmingStrategy.PREDICTIVE,
                'score': self._calculate_warming_score(self.usage_patterns[key]),
                'scheduled_at': time.time()
            })
    
    def _schedule_intelligent_warming(self, key: str, cache_type: str, recognized_pattern: RecognizedPattern):
        """Schedule intelligent warming based on recognized patterns"""
        # Check if already scheduled
        existing = any(item['key'] == key for item in self.warming_queue)
        if not existing:
            # Schedule warming based on pattern prediction
            warming_time = recognized_pattern.recommended_warming_time
            current_time = time.time()
            
            # If recommended time is soon, schedule immediately
            if warming_time and warming_time <= current_time + 600:  # Within 10 minutes
                self.warming_queue.append({
                    'key': key,
                    'cache_type': cache_type,
                    'strategy': WarmingStrategy.PATTERN_BASED,
                    'score': recognized_pattern.warming_priority,
                    'scheduled_at': current_time,
                    'pattern_id': recognized_pattern.pattern_id,
                    'pattern_type': recognized_pattern.pattern_type.value,
                    'prediction_confidence': recognized_pattern.prediction_confidence
                })
                
                self.logger.debug(f"Scheduled intelligent warming for {key} "
                                f"(pattern: {recognized_pattern.pattern_type.value}, "
                                f"priority: {recognized_pattern.warming_priority:.2f})")
    
    def _is_warmed_entry(self, key: str) -> bool:
        """Check if a cache entry was populated through warming"""
        # This is a simplified implementation - in production, you might want
        # to track warmed entries more explicitly
        return hasattr(self.cache, '_warmed_entries') and key in getattr(self.cache, '_warmed_entries', set())
    
    def _mark_as_warmed(self, key: str):
        """Mark a cache entry as having been warmed"""
        if not hasattr(self.cache, '_warmed_entries'):
            setattr(self.cache, '_warmed_entries', set())
        getattr(self.cache, '_warmed_entries').add(key)
    
    def _start_background_warming(self):
        """Start background warming timer"""
        if self.warming_timer:
            self.warming_timer.cancel()
        
        self.warming_timer = threading.Timer(self.warming_interval, self._background_warming_task)
        self.warming_timer.daemon = True
        self.warming_timer.start()
    
    def _background_warming_task(self):
        """Background task to process warming queue and intelligent prewarming"""
        if not self.enable_warming or self.warming_active:
            self._start_background_warming()  # Reschedule
            return
        
        self.warming_active = True
        current_time = time.time()
        
        try:
            # Update intelligent prewarming schedule
            self.prewarming_scheduler.update_schedule(current_time)
            
            # Get next prewarming operations from scheduler
            scheduled_prewarming = self.prewarming_scheduler.get_next_prewarming_operations(
                current_time, max_operations=2
            )
            
            # Process scheduled prewarming operations first (higher priority)
            for operation in scheduled_prewarming:
                pattern_id = operation['pattern_id']
                
                # Find corresponding cache keys for this pattern
                matching_keys = self._find_keys_for_pattern(pattern_id)
                
                for key in matching_keys[:1]:  # Limit to 1 key per pattern for now
                    success = self.warm_cache_entry(key, "validation", WarmingStrategy.PATTERN_BASED)
                    
                    # Record prewarming result
                    hit_achieved = self.cache.get(key) is not None
                    self.prewarming_scheduler.record_prewarming_result(
                        pattern_id, success, hit_achieved
                    )
                    
                    if success:
                        self.logger.debug(f"Intelligent prewarming successful: {key} "
                                        f"(pattern: {operation['pattern_type']})")
            
            # Process regular warming queue
            processed = 0
            remaining_capacity = max(0, self.max_concurrent_warms - len(scheduled_prewarming))
            
            while self.warming_queue and processed < remaining_capacity:
                item = self.warming_queue.pop(0)
                
                # Skip old entries (older than 1 hour)
                if current_time - item['scheduled_at'] > 3600:
                    continue
                
                success = self.warm_cache_entry(
                    item['key'], 
                    item['cache_type'], 
                    item['strategy']
                )
                
                processed += 1
                
                if success:
                    self.logger.debug(f"Background warming successful: {item['key']}")
            
            # Cleanup old usage patterns (older than 24 hours)
            self._cleanup_old_patterns()
            
            # Optimize scheduler parameters periodically
            if current_time % 3600 < 60:  # Once per hour
                self.prewarming_scheduler.optimize_parameters()
            
        except Exception as e:
            self.logger.error(f"Background warming task failed: {e}")
        finally:
            self.warming_active = False
            self._start_background_warming()  # Reschedule
    
    def _find_keys_for_pattern(self, pattern_id: str) -> List[str]:
        """Find cache keys that match a specific recognized pattern"""
        matching_keys = []
        
        if pattern_id not in self.pattern_analyzer.recognized_patterns:
            return matching_keys
        
        target_pattern = self.pattern_analyzer.recognized_patterns[pattern_id]
        
        # Search through usage patterns to find matches
        for key, usage_pattern in self.usage_patterns.items():
            try:
                analyzed = self.pattern_analyzer.analyze_usage_pattern(usage_pattern)
                if analyzed and analyzed.pattern_id == pattern_id:
                    matching_keys.append(key)
            except:
                continue
        
        return matching_keys
    
    def _cleanup_old_patterns(self):
        """Remove old usage patterns to prevent memory leak"""
        current_time = time.time()
        cutoff_time = current_time - (24 * 3600)  # 24 hours ago
        
        with self.pattern_lock:
            old_keys = [key for key, pattern in self.usage_patterns.items() 
                       if pattern.last_accessed < cutoff_time]
            
            for key in old_keys:
                del self.usage_patterns[key]
            
            if old_keys:
                self.logger.debug(f"Cleaned up {len(old_keys)} old usage patterns")
    
    def shutdown(self):
        """Shutdown the warming manager"""
        self.logger.info(f"Shutting down CacheWarmingManager for cache: {self.cache.name}")
        
        self.enable_warming = False
        
        if self.warming_timer:
            self.warming_timer.cancel()
        
        # Clear warming queue
        self.warming_queue.clear()
        
        # Log final metrics
        metrics = self.get_warming_metrics()
        self.logger.info(f"Final warming metrics: {metrics['warming_performance']}")


def create_warming_enabled_cache(config: CacheConfig, warming_config: Optional[Dict] = None) -> Tuple[SmartCache, CacheWarmingManager]:
    """Advanced cache optimization recommendation engine"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Thresholds for optimization recommendations
        self.thresholds = {
            'hit_ratio': {
                'excellent': 0.9,
                'good': 0.7,
                'needs_improvement': 0.5,
                'critical': 0.3
            },
            'memory_efficiency': {
                'excellent': 0.8,
                'good': 0.6,
                'needs_improvement': 0.4,
                'critical': 0.2
            },
            'eviction_rate': {
                'excellent': 0.1,
                'good': 0.3,
                'needs_improvement': 0.5,
                'critical': 0.7
            }
        }
    
    def analyze_cache_performance(self, cache: 'SmartCache') -> CacheOptimizationReport:
        """Generate comprehensive cache optimization recommendations"""
        
        try:
            # Collect current metrics
            metrics = cache.get_metrics()
            warming_metrics = cache.warming_manager.get_warming_metrics() if cache.warming_manager else {}
            
            recommendations = []
            
            # Analyze different optimization areas
            recommendations.extend(self._analyze_hit_ratio(metrics))
            recommendations.extend(self._analyze_memory_usage(cache, metrics))
            recommendations.extend(self._analyze_eviction_patterns(metrics))
            recommendations.extend(self._analyze_cache_sizing(cache, metrics))
            recommendations.extend(self._analyze_warming_strategy(warming_metrics))
            recommendations.extend(self._analyze_ttl_configuration(cache, metrics))
            recommendations.extend(self._analyze_pattern_recognition(warming_metrics))
            
            # Sort recommendations by priority and confidence
            recommendations.sort(key=lambda r: (
                {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}[r.priority],
                r.confidence
            ), reverse=True)
            
            # Calculate overall performance score
            performance_score = self._calculate_performance_score(metrics, warming_metrics)
            
            # Determine overall health
            overall_health = self._determine_overall_health(performance_score)
            
            # Generate predictions
            predicted_improvements = self._predict_improvements(recommendations)
            
            return CacheOptimizationReport(
                overall_health=overall_health,
                performance_score=performance_score,
                recommendations=recommendations,
                current_metrics_summary=self._summarize_metrics(metrics, warming_metrics),
                predicted_improvements=predicted_improvements
            )
            
        except Exception as e:
            self.logger.error(f"Failed to analyze cache performance: {e}")
            return CacheOptimizationReport(
                overall_health="UNKNOWN",
                performance_score=0.0,
                recommendations=[],
                current_metrics_summary={},
                predicted_improvements={}
            )
    
    def _analyze_hit_ratio(self, metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Analyze cache hit ratio and provide recommendations"""
        recommendations = []
        
        hit_ratio = metrics.get('performance', {}).get('hit_ratio', 0.0)
        
        if hit_ratio < self.thresholds['hit_ratio']['critical']:
            recommendations.append(OptimizationRecommendation(
                category="Hit Ratio",
                priority="HIGH",
                title="Critical Hit Ratio - Immediate Action Required",
                description=f"Hit ratio of {hit_ratio:.1%} is critically low. Cache is ineffective.",
                current_value=f"{hit_ratio:.1%}",
                recommended_value=">70%",
                expected_improvement="50-80% performance improvement",
                confidence=0.95,
                implementation_complexity="MEDIUM",
                action_required="IMMEDIATE"
            ))
        elif hit_ratio < self.thresholds['hit_ratio']['needs_improvement']:
            recommendations.append(OptimizationRecommendation(
                category="Hit Ratio",
                priority="HIGH",
                title="Low Hit Ratio - Optimization Needed",
                description=f"Hit ratio of {hit_ratio:.1%} indicates poor cache effectiveness.",
                current_value=f"{hit_ratio:.1%}",
                recommended_value=">70%",
                expected_improvement="30-50% performance improvement",
                confidence=0.85,
                implementation_complexity="MEDIUM",
                action_required="SCHEDULED"
            ))
        elif hit_ratio < self.thresholds['hit_ratio']['good']:
            recommendations.append(OptimizationRecommendation(
                category="Hit Ratio",
                priority="MEDIUM",
                title="Moderate Hit Ratio - Room for Improvement",
                description=f"Hit ratio of {hit_ratio:.1%} is moderate but can be improved.",
                current_value=f"{hit_ratio:.1%}",
                recommended_value=">80%",
                expected_improvement="15-25% performance improvement",
                confidence=0.75,
                implementation_complexity="EASY",
                action_required="OPTIONAL"
            ))
        
        return recommendations
    
    def _analyze_memory_usage(self, cache: 'SmartCache', metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Analyze memory usage patterns and efficiency"""
        recommendations = []
        
        memory_info = metrics.get('memory', {})
        current_entries = memory_info.get('current_entries', 0)
        memory_usage = memory_info.get('usage_bytes', 0)
        
        # Check for memory pressure
        try:
            system_memory = psutil.virtual_memory()
            cache_memory_percent = (memory_usage / system_memory.total) * 100
            
            if cache_memory_percent > 5.0:  # More than 5% of system memory
                recommendations.append(OptimizationRecommendation(
                    category="Memory Usage",
                    priority="HIGH",
                    title="High Memory Consumption",
                    description=f"Cache using {cache_memory_percent:.1f}% of system memory",
                    current_value=f"{cache_memory_percent:.1f}%",
                    recommended_value="<3%",
                    expected_improvement="Reduced memory pressure, better system stability",
                    confidence=0.9,
                    implementation_complexity="EASY",
                    action_required="IMMEDIATE"
                ))
            
            # Check for inefficient memory usage
            if current_entries > 0:
                avg_entry_size = memory_usage / current_entries
                if avg_entry_size > 10240:  # 10KB per entry seems high
                    recommendations.append(OptimizationRecommendation(
                        category="Memory Efficiency",
                        priority="MEDIUM",
                        title="Large Average Entry Size",
                        description=f"Average entry size of {avg_entry_size/1024:.1f}KB may indicate inefficient storage",
                        current_value=f"{avg_entry_size/1024:.1f}KB",
                        recommended_value="<5KB",
                        expected_improvement="30-50% memory usage reduction",
                        confidence=0.7,
                        implementation_complexity="COMPLEX",
                        action_required="SCHEDULED"
                    ))
        except Exception as e:
            self.logger.warning(f"Could not analyze memory usage: {e}")
        
        return recommendations
    
    def _analyze_eviction_patterns(self, metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Analyze cache eviction patterns for optimization opportunities"""
        recommendations = []
        
        evictions = metrics.get('evictions', {})
        total_evictions = evictions.get('total', 0)
        size_evictions = evictions.get('size_based', 0)
        memory_evictions = evictions.get('memory_pressure', 0)
        expired_evictions = evictions.get('expired', 0)
        
        total_ops = metrics.get('performance', {}).get('hits', 0) + metrics.get('performance', {}).get('misses', 0)
        
        if total_ops > 0:
            eviction_rate = total_evictions / total_ops
            
            if eviction_rate > self.thresholds['eviction_rate']['critical']:
                recommendations.append(OptimizationRecommendation(
                    category="Eviction Rate",
                    priority="HIGH",
                    title="Excessive Cache Evictions",
                    description=f"Eviction rate of {eviction_rate:.1%} indicates cache thrashing",
                    current_value=f"{eviction_rate:.1%}",
                    recommended_value="<30%",
                    expected_improvement="40-60% performance improvement",
                    confidence=0.9,
                    implementation_complexity="MEDIUM",
                    action_required="IMMEDIATE"
                ))
            
            # Analyze eviction type distribution
            if size_evictions > memory_evictions + expired_evictions:
                recommendations.append(OptimizationRecommendation(
                    category="Cache Sizing",
                    priority="MEDIUM",
                    title="Size-based Evictions Dominant",
                    description="Most evictions are size-based, suggesting cache is too small",
                    current_value=f"{size_evictions} size evictions",
                    recommended_value="Increase cache size by 50-100%",
                    expected_improvement="25-40% hit ratio improvement",
                    confidence=0.8,
                    implementation_complexity="EASY",
                    action_required="SCHEDULED"
                ))
        
        return recommendations
    
    def _analyze_cache_sizing(self, cache: 'SmartCache', metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Analyze cache sizing for optimization opportunities"""
        recommendations = []
        
        memory_info = metrics.get('memory', {})
        current_entries = memory_info.get('current_entries', 0)
        
        # Get cache size limits
        primary_size = getattr(cache.primary_cache, 'max_size', 0) if hasattr(cache.primary_cache, 'max_size') else 0
        secondary_size = getattr(cache.secondary_cache, 'max_size', 0) if cache.secondary_cache and hasattr(cache.secondary_cache, 'max_size') else 0
        
        # Check utilization
        if primary_size > 0:
            utilization = current_entries / primary_size
            
            if utilization > 0.9:
                recommendations.append(OptimizationRecommendation(
                    category="Cache Sizing",
                    priority="HIGH",
                    title="Cache Near Capacity",
                    description=f"Cache utilization at {utilization:.1%} - frequent evictions likely",
                    current_value=f"{utilization:.1%} utilization",
                    recommended_value="<80% utilization",
                    expected_improvement="20-35% hit ratio improvement",
                    confidence=0.85,
                    implementation_complexity="EASY",
                    action_required="IMMEDIATE"
                ))
            elif utilization < 0.3:
                recommendations.append(OptimizationRecommendation(
                    category="Memory Efficiency",
                    priority="LOW",
                    title="Cache Under-utilized",
                    description=f"Cache utilization at {utilization:.1%} - memory could be reclaimed",
                    current_value=f"{utilization:.1%} utilization",
                    recommended_value=">50% utilization",
                    expected_improvement="Memory savings without performance loss",
                    confidence=0.7,
                    implementation_complexity="EASY",
                    action_required="OPTIONAL"
                ))
        
        return recommendations
    
    def _analyze_warming_strategy(self, warming_metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Analyze cache warming strategy effectiveness"""
        recommendations = []
        
        if not warming_metrics:
            recommendations.append(OptimizationRecommendation(
                category="Cache Warming",
                priority="MEDIUM",
                title="Cache Warming Not Enabled",
                description="Cache warming can improve hit ratios by pre-populating frequently accessed data",
                current_value="Disabled",
                recommended_value="Enable with pattern-based warming",
                expected_improvement="15-30% hit ratio improvement",
                confidence=0.8,
                implementation_complexity="EASY",
                action_required="OPTIONAL"
            ))
            return recommendations
        
        # Analyze warming effectiveness
        warming_stats = warming_metrics.get('warming_stats', {})
        success_rate = warming_stats.get('success_rate', 0.0)
        
        if success_rate < 0.5:
            recommendations.append(OptimizationRecommendation(
                category="Cache Warming",
                priority="MEDIUM",
                title="Low Warming Success Rate",
                description=f"Warming success rate of {success_rate:.1%} indicates ineffective strategy",
                current_value=f"{success_rate:.1%}",
                recommended_value=">70%",
                expected_improvement="10-20% cache effectiveness improvement",
                confidence=0.75,
                implementation_complexity="MEDIUM",
                action_required="SCHEDULED"
            ))
        
        # Check pattern recognition
        pattern_insights = warming_metrics.get('pattern_insights', {})
        total_patterns = pattern_insights.get('total_patterns', 0)
        
        if total_patterns < 5:
            recommendations.append(OptimizationRecommendation(
                category="Pattern Recognition",
                priority="LOW",
                title="Limited Pattern Recognition",
                description=f"Only {total_patterns} patterns recognized - may need more data or tuning",
                current_value=f"{total_patterns} patterns",
                recommended_value=">10 patterns",
                expected_improvement="Better predictive warming",
                confidence=0.6,
                implementation_complexity="MEDIUM",
                action_required="OPTIONAL"
            ))
        
        return recommendations
    
    def _analyze_ttl_configuration(self, cache: 'SmartCache', metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Analyze TTL configuration for optimization"""
        recommendations = []
        
        evictions = metrics.get('evictions', {})
        expired_evictions = evictions.get('expired', 0)
        total_evictions = evictions.get('total', 0)
        
        if total_evictions > 0:
            expiry_ratio = expired_evictions / total_evictions
            
            if expiry_ratio < 0.3:
                recommendations.append(OptimizationRecommendation(
                    category="TTL Configuration",
                    priority="MEDIUM",
                    title="Low Expiry-based Evictions",
                    description=f"Only {expiry_ratio:.1%} of evictions are TTL-based, TTL may be too long",
                    current_value=f"{expiry_ratio:.1%} expiry evictions",
                    recommended_value=">50% expiry evictions",
                    expected_improvement="Better cache freshness and memory efficiency",
                    confidence=0.7,
                    implementation_complexity="EASY",
                    action_required="OPTIONAL"
                ))
            elif expiry_ratio > 0.8:
                recommendations.append(OptimizationRecommendation(
                    category="TTL Configuration",
                    priority="MEDIUM",
                    title="High Expiry-based Evictions",
                    description=f"{expiry_ratio:.1%} of evictions are TTL-based, TTL may be too short",
                    current_value=f"{expiry_ratio:.1%} expiry evictions",
                    recommended_value="50-70% expiry evictions",
                    expected_improvement="Better cache utilization",
                    confidence=0.7,
                    implementation_complexity="EASY",
                    action_required="OPTIONAL"
                ))
        
        return recommendations
    
    def _analyze_pattern_recognition(self, warming_metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Analyze pattern recognition effectiveness"""
        recommendations = []
        
        pattern_insights = warming_metrics.get('pattern_insights', {})
        adaptive_learning = warming_metrics.get('adaptive_learning', {})
        
        if pattern_insights:
            clustering = pattern_insights.get('clustering', {})
            cluster_count = clustering.get('cluster_count', 0)
            
            if cluster_count > 20:
                recommendations.append(OptimizationRecommendation(
                    category="Pattern Recognition",
                    priority="LOW",
                    title="High Pattern Fragmentation",
                    description=f"{cluster_count} pattern clusters may indicate over-fragmentation",
                    current_value=f"{cluster_count} clusters",
                    recommended_value="<15 clusters",
                    expected_improvement="Better pattern generalization",
                    confidence=0.6,
                    implementation_complexity="MEDIUM",
                    action_required="OPTIONAL"
                ))
        
        if adaptive_learning:
            recent_success = adaptive_learning.get('recent_success_rate', 0.0)
            if recent_success < 0.6:
                recommendations.append(OptimizationRecommendation(
                    category="Adaptive Learning",
                    priority="MEDIUM",
                    title="Low Adaptive Learning Success",
                    description=f"Recent learning success rate of {recent_success:.1%} indicates tuning needed",
                    current_value=f"{recent_success:.1%}",
                    recommended_value=">70%",
                    expected_improvement="Better prediction accuracy",
                    confidence=0.7,
                    implementation_complexity="MEDIUM",
                    action_required="SCHEDULED"
                ))
        
        return recommendations
    
    def _calculate_performance_score(self, metrics: Dict[str, Any], warming_metrics: Dict[str, Any]) -> float:
        """Calculate overall cache performance score (0-100)"""
        score = 0.0
        weight_sum = 0.0
        
        # Hit ratio (40% weight)
        hit_ratio = metrics.get('performance', {}).get('hit_ratio', 0.0)
        score += hit_ratio * 40
        weight_sum += 40
        
        # Eviction rate (25% weight)
        evictions = metrics.get('evictions', {}).get('total', 0)
        total_ops = metrics.get('performance', {}).get('hits', 0) + metrics.get('performance', {}).get('misses', 0)
        if total_ops > 0:
            eviction_rate = evictions / total_ops
            eviction_score = max(0, 1 - (eviction_rate / 0.5))  # 0.5 = terrible eviction rate
            score += eviction_score * 25
            weight_sum += 25
        
        # Memory efficiency (20% weight)
        memory_info = metrics.get('memory', {})
        current_entries = memory_info.get('current_entries', 0)
        try:
            if hasattr(psutil, 'virtual_memory'):
                system_memory = psutil.virtual_memory()
                memory_usage = memory_info.get('usage_bytes', 0)
                memory_percent = (memory_usage / system_memory.total) * 100
                memory_score = max(0, 1 - (memory_percent / 5.0))  # 5% = high usage
                score += memory_score * 20
                weight_sum += 20
        except:
            pass
        
        # Warming effectiveness (15% weight)
        if warming_metrics:
            warming_stats = warming_metrics.get('warming_stats', {})
            warming_success = warming_stats.get('success_rate', 0.0)
            score += warming_success * 15
            weight_sum += 15
        
        return (score / weight_sum) * 100 if weight_sum > 0 else 0.0
    
    def _determine_overall_health(self, performance_score: float) -> str:
        """Determine overall cache health based on performance score"""
        if performance_score >= 85:
            return "EXCELLENT"
        elif performance_score >= 70:
            return "GOOD"
        elif performance_score >= 50:
            return "NEEDS_IMPROVEMENT"
        else:
            return "CRITICAL"
    
    def _predict_improvements(self, recommendations: List[OptimizationRecommendation]) -> Dict[str, Any]:
        """Predict improvements from implementing recommendations"""
        predictions = {
            'potential_hit_ratio_improvement': 0.0,
            'potential_memory_savings': 0.0,
            'estimated_performance_gain': 0.0,
            'implementation_effort': 'LOW'
        }
        
        high_priority_count = sum(1 for r in recommendations if r.priority == 'HIGH')
        medium_priority_count = sum(1 for r in recommendations if r.priority == 'MEDIUM')
        
        # Rough estimates based on recommendation types
        if high_priority_count > 0:
            predictions['potential_hit_ratio_improvement'] = min(50.0, high_priority_count * 15.0)
            predictions['estimated_performance_gain'] = min(80.0, high_priority_count * 20.0)
            predictions['implementation_effort'] = 'HIGH'
        elif medium_priority_count > 0:
            predictions['potential_hit_ratio_improvement'] = min(30.0, medium_priority_count * 8.0)
            predictions['estimated_performance_gain'] = min(40.0, medium_priority_count * 10.0)
            predictions['implementation_effort'] = 'MEDIUM'
        
        return predictions
    
    def _summarize_metrics(self, metrics: Dict[str, Any], warming_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of current metrics"""
        summary = {
            'cache_performance': {
                'hit_ratio': metrics.get('performance', {}).get('hit_ratio', 0.0),
                'total_operations': metrics.get('performance', {}).get('hits', 0) + metrics.get('performance', {}).get('misses', 0),
                'cache_effectiveness': metrics.get('performance', {}).get('cache_effectiveness', 0.0)
            },
            'memory_usage': {
                'current_entries': metrics.get('memory', {}).get('current_entries', 0),
                'memory_bytes': metrics.get('memory', {}).get('usage_bytes', 0)
            },
            'evictions': metrics.get('evictions', {}),
            'warming_enabled': bool(warming_metrics),
            'pattern_recognition': warming_metrics.get('pattern_insights', {}).get('total_patterns', 0) if warming_metrics else 0
        }
        
        return summary
    
    def generate_optimization_report(self, cache: 'SmartCache') -> str:
        """Generate a human-readable optimization report"""
        report = self.analyze_cache_performance(cache)
        
        output = []
        output.append("🔧 Cache Optimization Report")
        output.append("=" * 50)
        output.append(f"Overall Health: {report.overall_health}")
        output.append(f"Performance Score: {report.performance_score:.1f}/100")
        output.append(f"Generated: {datetime.fromtimestamp(report.generated_at).strftime('%Y-%m-%d %H:%M:%S')}")
        output.append("")
        
        if report.recommendations:
            output.append("📋 Recommendations:")
            output.append("-" * 30)
            
            for i, rec in enumerate(report.recommendations, 1):
                priority_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}[rec.priority]
                output.append(f"{i}. {priority_emoji} {rec.title}")
                output.append(f"   Category: {rec.category}")
                output.append(f"   Priority: {rec.priority} ({rec.confidence:.0%} confidence)")
                output.append(f"   Current: {rec.current_value}")
                output.append(f"   Recommended: {rec.recommended_value}")
                output.append(f"   Expected: {rec.expected_improvement}")
                output.append(f"   Complexity: {rec.implementation_complexity}")
                output.append(f"   Action: {rec.action_required}")
                output.append("")
        else:
            output.append("✅ No optimization recommendations - cache is performing well!")
            output.append("")
        
        if report.predicted_improvements:
            output.append("📈 Predicted Improvements:")
            output.append("-" * 30)
            pred = report.predicted_improvements
            output.append(f"Hit Ratio: +{pred.get('potential_hit_ratio_improvement', 0):.1f}%")
            output.append(f"Performance: +{pred.get('estimated_performance_gain', 0):.1f}%")
            output.append(f"Implementation Effort: {pred.get('implementation_effort', 'UNKNOWN')}")
            output.append("")
        
        output.append("📊 Current Metrics Summary:")
        output.append("-" * 30)
        summary = report.current_metrics_summary
        cache_perf = summary.get('cache_performance', {})
        output.append(f"Hit Ratio: {cache_perf.get('hit_ratio', 0):.1%}")
        output.append(f"Total Operations: {cache_perf.get('total_operations', 0):,}")
        output.append(f"Current Entries: {summary.get('memory_usage', {}).get('current_entries', 0):,}")
        output.append(f"Memory Usage: {summary.get('memory_usage', {}).get('memory_bytes', 0) / 1024 / 1024:.1f} MB")
        output.append(f"Warming Enabled: {'Yes' if summary.get('warming_enabled') else 'No'}")
        output.append(f"Recognized Patterns: {summary.get('pattern_recognition', 0)}")
        
        return "\n".join(output)


def create_warming_enabled_cache(config: CacheConfig, warming_config: Optional[Dict] = None) -> Tuple[SmartCache, CacheWarmingManager]:
    """Create a smart cache with warming manager enabled"""
    cache = SmartCache(config, "WarmingEnabledCache")
    
    # Get the warming manager from the cache (it should be created during cache initialization)
    if cache.warming_manager is None:
        # Fallback: create warming manager manually if not created
        cache.warming_manager = CacheWarmingManager(cache, config)
    
    warming_manager = cache.warming_manager
    
    # Apply warming configuration if provided
    if warming_config:
        for key, value in warming_config.items():
            if hasattr(warming_manager, key):
                setattr(warming_manager, key, value)
    
    return cache, warming_manager