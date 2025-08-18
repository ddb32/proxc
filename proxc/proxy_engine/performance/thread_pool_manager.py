"""Dynamic Thread Pool Manager - Adaptive threading based on system performance"""

import asyncio
import json
import logging
import math
import os
import pickle
import psutil
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable, Tuple, Set
from collections import deque, defaultdict
from enum import Enum

# Optional imports for advanced features
try:
    from scipy import stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

from ...proxy_core.models import ProxyInfo
from ..validation.validation_config import ValidationConfig
from ..validation.validation_results import ValidationResult


@dataclass
class PerformanceMetrics:
    """Performance metrics for adaptive threading"""
    avg_response_time: float = 0.0
    success_rate: float = 0.0
    throughput: float = 0.0  # proxies per second
    cpu_usage: float = 0.0
    memory_usage: float = 0.0  # MB
    error_rate: float = 0.0
    active_threads: int = 0
    queue_size: int = 0
    timestamp: float = field(default_factory=time.time)
    
    # Additional predictive metrics
    workload_size: int = 0  # Number of items in batch
    workload_type: str = "mixed"  # http, socks, mixed
    system_load: float = 0.0  # System load average
    network_latency: float = 0.0  # Average network latency


@dataclass
class WorkloadPattern:
    """Historical workload pattern data"""
    workload_size: int
    workload_type: str
    hour_of_day: int
    day_of_week: int
    optimal_threads: int
    actual_performance: PerformanceMetrics
    timestamp: float = field(default_factory=time.time)


@dataclass
class PredictiveConfig:
    """Configuration for predictive load management"""
    enable_historical_learning: bool = True
    history_retention_days: int = 30
    min_samples_for_prediction: int = 5
    prediction_confidence_threshold: float = 0.7
    learning_rate: float = 0.1
    pattern_similarity_threshold: float = 0.8
    
    # Feature weights for similarity calculation
    size_weight: float = 0.4
    type_weight: float = 0.3
    time_weight: float = 0.2
    performance_weight: float = 0.1
    
    # Prediction adjustment factors
    conservative_factor: float = 0.9  # Scale down predictions for safety
    aggressive_factor: float = 1.2   # Scale up predictions for performance
    
    # Predictive scaling settings
    enable_predictive_scaling: bool = True
    prediction_horizon_minutes: int = 5  # How far ahead to predict
    scaling_anticipation_factor: float = 0.8  # How early to scale (0-1)
    trend_detection_window: int = 10  # Number of metrics for trend detection


class PatternType(Enum):
    """Types of workload patterns"""
    BURST = "burst"              # High load for short periods
    SUSTAINED = "sustained"      # Steady load over time
    GRADUAL = "gradual"         # Gradually increasing load
    PERIODIC = "periodic"       # Regular recurring patterns
    RANDOM = "random"           # No clear pattern
    DECLINING = "declining"     # Decreasing load over time


class WorkloadCharacteristics(Enum):
    """Workload characteristics for classification"""
    CPU_BOUND = "cpu_bound"
    IO_BOUND = "io_bound"
    NETWORK_BOUND = "network_bound"
    MEMORY_BOUND = "memory_bound"
    BALANCED = "balanced"


class ScalingDirection(Enum):
    """Scaling direction for predictive algorithms"""
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    MAINTAIN = "maintain"
    AGGRESSIVE_UP = "aggressive_up"
    AGGRESSIVE_DOWN = "aggressive_down"


class PredictionConfidence(Enum):
    """Prediction confidence levels"""
    VERY_LOW = "very_low"      # 0.0-0.2
    LOW = "low"               # 0.2-0.4
    MEDIUM = "medium"         # 0.4-0.6
    HIGH = "high"             # 0.6-0.8
    VERY_HIGH = "very_high"   # 0.8-1.0


class TrendType(Enum):
    """Types of performance trends"""
    INCREASING = "increasing"   # Performance degrading
    DECREASING = "decreasing"   # Performance improving
    STABLE = "stable"          # Performance steady
    VOLATILE = "volatile"       # Performance erratic
    CYCLICAL = "cyclical"      # Performance has cycles


@dataclass
class PredictiveScalingDecision:
    """Result of predictive scaling analysis"""
    direction: ScalingDirection
    target_threads: int
    confidence: float
    confidence_level: PredictionConfidence
    reasoning: str
    prediction_horizon: float  # Minutes ahead
    urgency: float  # 0-1, how urgent the scaling is
    risk_assessment: float  # 0-1, risk of not scaling
    expected_improvement: float  # Expected performance improvement
    fallback_plan: Optional[ScalingDirection] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'direction': self.direction.value,
            'target_threads': self.target_threads,
            'confidence': self.confidence,
            'confidence_level': self.confidence_level.value,
            'reasoning': self.reasoning,
            'prediction_horizon': self.prediction_horizon,
            'urgency': self.urgency,
            'risk_assessment': self.risk_assessment,
            'expected_improvement': self.expected_improvement,
            'fallback_plan': self.fallback_plan.value if self.fallback_plan else None
        }


@dataclass
class TrendAnalysis:
    """Analysis of performance trends for predictive scaling"""
    trend_type: TrendType
    slope: float  # Rate of change
    r_squared: float  # Trend strength (correlation coefficient)
    predicted_value: float  # Predicted future value
    time_to_threshold: Optional[float]  # Minutes until threshold breach
    volatility: float  # Measure of trend stability
    seasonal_component: float  # Seasonal pattern strength
    

@dataclass
class ScalingPrediction:
    """Comprehensive scaling prediction with multiple algorithms"""
    timestamp: float
    current_threads: int
    
    # Multiple prediction approaches
    reactive_decision: PredictiveScalingDecision
    trend_based_decision: PredictiveScalingDecision
    pattern_based_decision: Optional[PredictiveScalingDecision]
    ml_based_decision: Optional[PredictiveScalingDecision]
    
    # Combined decision
    final_decision: PredictiveScalingDecision
    consensus_confidence: float
    
    # Supporting analysis
    trend_analysis: Dict[str, TrendAnalysis]  # metric_name -> analysis
    workload_forecast: Dict[str, float]  # metric predictions
    risk_factors: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'current_threads': self.current_threads,
            'reactive_decision': self.reactive_decision.to_dict(),
            'trend_based_decision': self.trend_based_decision.to_dict(),
            'pattern_based_decision': self.pattern_based_decision.to_dict() if self.pattern_based_decision else None,
            'ml_based_decision': self.ml_based_decision.to_dict() if self.ml_based_decision else None,
            'final_decision': self.final_decision.to_dict(),
            'consensus_confidence': self.consensus_confidence,
            'workload_forecast': self.workload_forecast,
            'risk_factors': self.risk_factors,
            'trend_analysis_count': len(self.trend_analysis)
        }
    

@dataclass
class PatternFeatures:
    """Extracted features from workload patterns"""
    size_trend: float = 0.0           # -1 to 1: decreasing to increasing
    duration_trend: float = 0.0       # -1 to 1: short to long duration
    frequency: float = 0.0            # Requests per minute
    variability: float = 0.0          # Coefficient of variation
    peak_ratio: float = 0.0           # Peak size / average size
    time_of_day_pattern: float = 0.0  # 0-1: how time-dependent
    success_rate_trend: float = 0.0   # -1 to 1: declining to improving
    resource_intensity: float = 0.0   # 0-1: low to high resource usage
    
    # Temporal features
    morning_bias: float = 0.0         # 0-1: preference for morning hours
    evening_bias: float = 0.0         # 0-1: preference for evening hours
    weekday_bias: float = 0.0         # 0-1: preference for weekdays
    weekend_bias: float = 0.0         # 0-1: preference for weekends


@dataclass 
class RecognizedPattern:
    """A recognized workload pattern with metadata"""
    pattern_id: str
    pattern_type: PatternType
    workload_characteristics: WorkloadCharacteristics
    features: PatternFeatures
    confidence: float
    historical_patterns: List[WorkloadPattern]
    optimal_thread_range: Tuple[int, int]  # (min, max)
    predicted_performance: Dict[str, float]
    creation_time: float = field(default_factory=time.time)
    usage_count: int = 0
    last_used: float = field(default_factory=time.time)


@dataclass
class PatternRecognitionConfig:
    """Configuration for pattern recognition algorithms"""
    enable_pattern_recognition: bool = True
    min_patterns_for_recognition: int = 10
    pattern_confidence_threshold: float = 0.6
    max_patterns_to_store: int = 1000
    
    # Feature extraction settings
    trend_window_size: int = 5          # Number of points for trend calculation
    frequency_window_hours: int = 24    # Hours to consider for frequency calculation
    variability_threshold: float = 0.3  # CV threshold for high variability
    
    # Pattern matching settings
    feature_similarity_threshold: float = 0.7
    temporal_similarity_weight: float = 0.3
    performance_similarity_weight: float = 0.4
    structural_similarity_weight: float = 0.3
    
    # Clustering settings
    max_clusters: int = 20
    cluster_merge_threshold: float = 0.6  # Lower threshold for better clustering
    pattern_update_frequency: int = 10   # Update patterns every N workloads (more frequent)


@dataclass
class ThreadPoolConfig:
    """Configuration for dynamic thread pool"""
    min_threads: int = 2
    max_threads: int = 100
    initial_threads: int = 10
    scale_factor: float = 1.2  # Multiplier for scaling up/down
    
    # Performance thresholds for scaling decisions
    response_time_threshold: float = 2000.0  # ms - scale up if exceeded
    cpu_threshold: float = 80.0  # % - scale down if exceeded
    memory_threshold: float = 1024.0  # MB - scale down if exceeded
    error_rate_threshold: float = 0.3  # 30% - scale down if exceeded
    success_rate_threshold: float = 0.7  # 70% - scale up if above this
    
    # Monitoring settings
    metrics_window_size: int = 10  # Number of recent metrics to consider
    scaling_cooldown: float = 30.0  # Seconds between scaling decisions
    monitoring_interval: float = 5.0  # Seconds between performance checks
    
    # Predictive scaling settings
    enable_predictive_scaling: bool = True
    prediction_weight: float = 0.7  # Weight given to predictive vs reactive scaling
    min_prediction_confidence: float = 0.6  # Minimum confidence for predictive scaling
    predictive_scaling_cooldown: float = 60.0  # Cooldown for predictive scaling


class PredictiveScalingEngine:
    """Advanced predictive scaling engine with multiple algorithm approaches"""
    
    def __init__(self, config: Optional[PredictiveConfig] = None):
        self.config = config or PredictiveConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Prediction state
        self.predictions_history: List[ScalingPrediction] = []
        self.trend_analyses: Dict[str, List[TrendAnalysis]] = defaultdict(list)
        
        # Algorithm weights (can be tuned based on performance)
        self.algorithm_weights = {
            'reactive': 0.3,
            'trend_based': 0.4,
            'pattern_based': 0.2,
            'ml_based': 0.1
        }
        
        # Performance tracking
        self.prediction_accuracy: Dict[str, List[float]] = defaultdict(list)
        
        self.logger.info("PredictiveScalingEngine initialized")
    
    def predict_scaling_decision(self, current_metrics: PerformanceMetrics,
                               metrics_history: List[PerformanceMetrics],
                               current_threads: int,
                               pattern_match: Optional[RecognizedPattern] = None) -> ScalingPrediction:
        """Generate comprehensive scaling prediction using multiple algorithms"""
        
        prediction_time = time.time()
        
        # Generate predictions from different algorithms
        reactive_decision = self._reactive_scaling_prediction(current_metrics, current_threads)
        trend_decision = self._trend_based_prediction(metrics_history, current_threads)
        pattern_decision = self._pattern_based_prediction(pattern_match, current_threads) if pattern_match else None
        ml_decision = self._ml_based_prediction(metrics_history, current_threads)
        
        # Combine decisions into final recommendation
        final_decision = self._combine_predictions(
            reactive_decision, trend_decision, pattern_decision, ml_decision, current_threads
        )
        
        # Calculate consensus confidence
        consensus_confidence = self._calculate_consensus_confidence(
            [reactive_decision, trend_decision, pattern_decision, ml_decision]
        )
        
        # Generate trend analysis for key metrics
        trend_analysis = self._analyze_performance_trends(metrics_history)
        
        # Generate workload forecast
        workload_forecast = self._forecast_workload_metrics(metrics_history)
        
        # Assess risk factors
        risk_factors = self._assess_risk_factors(current_metrics, trend_analysis)
        
        prediction = ScalingPrediction(
            timestamp=prediction_time,
            current_threads=current_threads,
            reactive_decision=reactive_decision,
            trend_based_decision=trend_decision,
            pattern_based_decision=pattern_decision,
            ml_based_decision=ml_decision,
            final_decision=final_decision,
            consensus_confidence=consensus_confidence,
            trend_analysis=trend_analysis,
            workload_forecast=workload_forecast,
            risk_factors=risk_factors
        )
        
        # Store prediction for learning
        self.predictions_history.append(prediction)
        if len(self.predictions_history) > 100:  # Keep recent predictions
            self.predictions_history.pop(0)
        
        self.logger.debug(f"Generated scaling prediction: {final_decision.direction.value} "
                         f"to {final_decision.target_threads} threads "
                         f"(confidence: {final_decision.confidence:.2f})")
        
        return prediction
    
    def _reactive_scaling_prediction(self, metrics: PerformanceMetrics, current_threads: int) -> PredictiveScalingDecision:
        """Traditional reactive scaling based on current metrics"""
        
        # Simple reactive logic
        if metrics.cpu_usage > 80 or metrics.memory_usage > 1024:
            return PredictiveScalingDecision(
                direction=ScalingDirection.SCALE_DOWN,
                target_threads=max(2, int(current_threads * 0.8)),
                confidence=0.8,
                confidence_level=PredictionConfidence.HIGH,
                reasoning=f"High resource usage: CPU {metrics.cpu_usage:.1f}%, Memory {metrics.memory_usage:.1f}MB",
                prediction_horizon=0.0,  # Immediate
                urgency=0.9,
                risk_assessment=0.8,
                expected_improvement=0.3
            )
        elif metrics.avg_response_time > 2000 and metrics.success_rate > 0.7:
            return PredictiveScalingDecision(
                direction=ScalingDirection.SCALE_UP,
                target_threads=min(100, int(current_threads * 1.3)),
                confidence=0.7,
                confidence_level=PredictionConfidence.HIGH,
                reasoning=f"High response time: {metrics.avg_response_time:.1f}ms",
                prediction_horizon=0.0,
                urgency=0.7,
                risk_assessment=0.6,
                expected_improvement=0.4
            )
        else:
            return PredictiveScalingDecision(
                direction=ScalingDirection.MAINTAIN,
                target_threads=current_threads,
                confidence=0.6,
                confidence_level=PredictionConfidence.MEDIUM,
                reasoning="Metrics within acceptable ranges",
                prediction_horizon=0.0,
                urgency=0.1,
                risk_assessment=0.2,
                expected_improvement=0.0
            )
    
    def _trend_based_prediction(self, metrics_history: List[PerformanceMetrics], 
                               current_threads: int) -> PredictiveScalingDecision:
        """Trend-based prediction using statistical analysis"""
        
        if len(metrics_history) < 5:
            return PredictiveScalingDecision(
                direction=ScalingDirection.MAINTAIN,
                target_threads=current_threads,
                confidence=0.3,
                confidence_level=PredictionConfidence.LOW,
                reasoning="Insufficient data for trend analysis",
                prediction_horizon=1.0,
                urgency=0.1,
                risk_assessment=0.3,
                expected_improvement=0.0
            )
        
        # Analyze key metric trends
        recent_metrics = metrics_history[-self.config.trend_detection_window:]
        
        # Extract time series data
        timestamps = [m.timestamp for m in recent_metrics]
        response_times = [m.avg_response_time for m in recent_metrics]
        cpu_usage = [m.cpu_usage for m in recent_metrics]
        success_rates = [m.success_rate for m in recent_metrics]
        
        # Calculate trends using linear regression
        response_trend = self._calculate_trend_slope(timestamps, response_times)
        cpu_trend = self._calculate_trend_slope(timestamps, cpu_usage)
        success_trend = self._calculate_trend_slope(timestamps, success_rates)
        
        # Predict future values
        horizon_seconds = self.config.prediction_horizon_minutes * 60
        future_time = timestamps[-1] + horizon_seconds
        
        predicted_response = response_times[-1] + response_trend * horizon_seconds
        predicted_cpu = cpu_usage[-1] + cpu_trend * horizon_seconds
        predicted_success = success_rates[-1] + success_trend * horizon_seconds
        
        # Decision logic based on trends
        if response_trend > 50:  # Response time increasing >50ms per second
            if predicted_response > 3000:  # Will exceed 3s threshold
                return PredictiveScalingDecision(
                    direction=ScalingDirection.SCALE_UP,
                    target_threads=min(100, int(current_threads * 1.4)),
                    confidence=0.75,
                    confidence_level=PredictionConfidence.HIGH,
                    reasoning=f"Response time trend predicts {predicted_response:.0f}ms in {self.config.prediction_horizon_minutes}min",
                    prediction_horizon=self.config.prediction_horizon_minutes,
                    urgency=0.8,
                    risk_assessment=0.7,
                    expected_improvement=0.5
                )
        
        if cpu_trend > 5:  # CPU usage increasing >5% per second
            if predicted_cpu > 85:  # Will exceed 85% threshold
                return PredictiveScalingDecision(
                    direction=ScalingDirection.SCALE_DOWN,
                    target_threads=max(2, int(current_threads * 0.7)),
                    confidence=0.7,
                    confidence_level=PredictionConfidence.HIGH,
                    reasoning=f"CPU trend predicts {predicted_cpu:.1f}% in {self.config.prediction_horizon_minutes}min",
                    prediction_horizon=self.config.prediction_horizon_minutes,
                    urgency=0.9,
                    risk_assessment=0.8,
                    expected_improvement=0.4
                )
        
        if success_trend < -0.05:  # Success rate declining >5% per second
            if predicted_success < 0.6:  # Will drop below 60%
                return PredictiveScalingDecision(
                    direction=ScalingDirection.SCALE_DOWN,
                    target_threads=max(2, int(current_threads * 0.8)),
                    confidence=0.65,
                    confidence_level=PredictionConfidence.MEDIUM,
                    reasoning=f"Success rate trend predicts {predicted_success:.1%} in {self.config.prediction_horizon_minutes}min",
                    prediction_horizon=self.config.prediction_horizon_minutes,
                    urgency=0.7,
                    risk_assessment=0.6,
                    expected_improvement=0.3
                )
        
        # Default: maintain current threads
        return PredictiveScalingDecision(
            direction=ScalingDirection.MAINTAIN,
            target_threads=current_threads,
            confidence=0.5,
            confidence_level=PredictionConfidence.MEDIUM,
            reasoning="Trends suggest stable performance",
            prediction_horizon=self.config.prediction_horizon_minutes,
            urgency=0.2,
            risk_assessment=0.3,
            expected_improvement=0.0
        )
    
    def _pattern_based_prediction(self, pattern: RecognizedPattern, 
                                 current_threads: int) -> PredictiveScalingDecision:
        """Pattern-based prediction using recognized workload patterns"""
        
        if not pattern:
            return None
        
        # Use pattern's optimal thread range
        min_threads, max_threads = pattern.optimal_thread_range
        optimal_threads = int((min_threads + max_threads) / 2)
        
        # Adjust based on pattern characteristics
        if pattern.pattern_type == PatternType.BURST:
            # Burst patterns need aggressive scaling
            target_threads = min(100, max(optimal_threads, int(current_threads * 1.5)))
            direction = ScalingDirection.AGGRESSIVE_UP if target_threads > current_threads else ScalingDirection.MAINTAIN
        elif pattern.pattern_type == PatternType.SUSTAINED:
            # Sustained patterns need stable threading
            target_threads = optimal_threads
            if target_threads > current_threads * 1.2:
                direction = ScalingDirection.SCALE_UP
            elif target_threads < current_threads * 0.8:
                direction = ScalingDirection.SCALE_DOWN
            else:
                direction = ScalingDirection.MAINTAIN
        elif pattern.pattern_type == PatternType.DECLINING:
            # Declining patterns can scale down preemptively
            target_threads = max(2, int(optimal_threads * 0.8))
            direction = ScalingDirection.SCALE_DOWN if target_threads < current_threads else ScalingDirection.MAINTAIN
        else:
            # Default pattern handling
            target_threads = optimal_threads
            direction = ScalingDirection.SCALE_UP if target_threads > current_threads else \
                       ScalingDirection.SCALE_DOWN if target_threads < current_threads else ScalingDirection.MAINTAIN
        
        return PredictiveScalingDecision(
            direction=direction,
            target_threads=target_threads,
            confidence=pattern.confidence,
            confidence_level=self._confidence_to_level(pattern.confidence),
            reasoning=f"Pattern-based: {pattern.pattern_type.value} ({pattern.workload_characteristics.value})",
            prediction_horizon=2.0,  # Pattern-based predictions are medium-term
            urgency=0.6,
            risk_assessment=1.0 - pattern.confidence,
            expected_improvement=pattern.confidence * 0.6
        )
    
    def _ml_based_prediction(self, metrics_history: List[PerformanceMetrics], 
                            current_threads: int) -> Optional[PredictiveScalingDecision]:
        """Machine learning-based prediction (simplified implementation)"""
        
        if len(metrics_history) < 10:
            return None
        
        # Simple ML-like prediction using weighted moving averages and momentum
        recent_metrics = metrics_history[-10:]
        
        # Calculate momentum indicators
        response_momentum = self._calculate_momentum([m.avg_response_time for m in recent_metrics])
        throughput_momentum = self._calculate_momentum([m.throughput for m in recent_metrics])
        cpu_momentum = self._calculate_momentum([m.cpu_usage for m in recent_metrics])
        
        # Combine momentum indicators for prediction
        performance_score = (
            (1.0 - min(response_momentum / 1000, 1.0)) * 0.4 +  # Lower response time momentum is better
            min(throughput_momentum / 5.0, 1.0) * 0.3 +         # Higher throughput momentum is better
            (1.0 - min(cpu_momentum / 50, 1.0)) * 0.3            # Lower CPU momentum is better
        )
        
        # Predict optimal threads based on performance score
        if performance_score < 0.3:  # Poor performance trend
            target_threads = min(100, int(current_threads * 1.3))
            direction = ScalingDirection.SCALE_UP
            confidence = 0.6
        elif performance_score > 0.8:  # Excellent performance trend
            target_threads = max(2, int(current_threads * 0.9))
            direction = ScalingDirection.SCALE_DOWN
            confidence = 0.5
        else:  # Stable performance
            target_threads = current_threads
            direction = ScalingDirection.MAINTAIN
            confidence = 0.4
        
        return PredictiveScalingDecision(
            direction=direction,
            target_threads=target_threads,
            confidence=confidence,
            confidence_level=self._confidence_to_level(confidence),
            reasoning=f"ML-based: performance score {performance_score:.2f}",
            prediction_horizon=3.0,
            urgency=0.5,
            risk_assessment=1.0 - confidence,
            expected_improvement=confidence * 0.4
        )
    
    def _combine_predictions(self, reactive: PredictiveScalingDecision,
                           trend: PredictiveScalingDecision,
                           pattern: Optional[PredictiveScalingDecision],
                           ml: Optional[PredictiveScalingDecision],
                           current_threads: int) -> PredictiveScalingDecision:
        """Combine multiple prediction algorithms into final decision"""
        
        predictions = [reactive, trend]
        weights = [self.algorithm_weights['reactive'], self.algorithm_weights['trend_based']]
        
        if pattern:
            predictions.append(pattern)
            weights.append(self.algorithm_weights['pattern_based'])
        
        if ml:
            predictions.append(ml)
            weights.append(self.algorithm_weights['ml_based'])
        
        # Normalize weights
        total_weight = sum(weights)
        weights = [w / total_weight for w in weights]
        
        # Weighted average of target threads
        weighted_threads = sum(p.target_threads * w for p, w in zip(predictions, weights))
        target_threads = int(weighted_threads)
        
        # Weighted average of confidence
        weighted_confidence = sum(p.confidence * w for p, w in zip(predictions, weights))
        
        # Determine direction
        if target_threads > current_threads * 1.2:
            direction = ScalingDirection.SCALE_UP
        elif target_threads < current_threads * 0.8:
            direction = ScalingDirection.SCALE_DOWN
        else:
            direction = ScalingDirection.MAINTAIN
        
        # Combine reasoning
        reasoning_parts = [f"{p.direction.value}({p.confidence:.2f})" for p in predictions]
        reasoning = f"Combined: {', '.join(reasoning_parts)}"
        
        # Calculate urgency and risk
        urgency = max(p.urgency for p in predictions)
        risk = sum(p.risk_assessment * w for p, w in zip(predictions, weights))
        improvement = sum(p.expected_improvement * w for p, w in zip(predictions, weights))
        
        return PredictiveScalingDecision(
            direction=direction,
            target_threads=target_threads,
            confidence=weighted_confidence,
            confidence_level=self._confidence_to_level(weighted_confidence),
            reasoning=reasoning,
            prediction_horizon=max(p.prediction_horizon for p in predictions),
            urgency=urgency,
            risk_assessment=risk,
            expected_improvement=improvement
        )
    
    def _calculate_trend_slope(self, x_values: List[float], y_values: List[float]) -> float:
        """Calculate linear trend slope using least squares regression"""
        if len(x_values) < 2 or len(y_values) < 2:
            return 0.0
        
        if HAS_SCIPY:
            try:
                # Use scipy.stats for robust linear regression
                slope, intercept, r_value, p_value, std_err = stats.linregress(x_values, y_values)
                return slope
            except ValueError:
                pass
        
        # Fallback to simple calculation
        n = len(x_values)
        if n < 2:
            return 0.0
        
        x_mean = sum(x_values) / n
        y_mean = sum(y_values) / n
        
        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, y_values))
        denominator = sum((x - x_mean) ** 2 for x in x_values)
        
        return numerator / denominator if denominator != 0 else 0.0
    
    def _calculate_momentum(self, values: List[float]) -> float:
        """Calculate momentum (rate of change) for a time series"""
        if len(values) < 3:
            return 0.0
        
        # Calculate recent vs older averages
        mid_point = len(values) // 2
        recent_avg = sum(values[mid_point:]) / (len(values) - mid_point)
        older_avg = sum(values[:mid_point]) / mid_point
        
        return recent_avg - older_avg
    
    def _confidence_to_level(self, confidence: float) -> PredictionConfidence:
        """Convert numerical confidence to confidence level enum"""
        if confidence >= 0.8:
            return PredictionConfidence.VERY_HIGH
        elif confidence >= 0.6:
            return PredictionConfidence.HIGH
        elif confidence >= 0.4:
            return PredictionConfidence.MEDIUM
        elif confidence >= 0.2:
            return PredictionConfidence.LOW
        else:
            return PredictionConfidence.VERY_LOW
    
    def _calculate_consensus_confidence(self, decisions: List[Optional[PredictiveScalingDecision]]) -> float:
        """Calculate consensus confidence across multiple predictions"""
        valid_decisions = [d for d in decisions if d is not None]
        if not valid_decisions:
            return 0.0
        
        # Agreement on direction
        directions = [d.direction for d in valid_decisions]
        direction_consensus = directions.count(max(set(directions), key=directions.count)) / len(directions)
        
        # Average confidence
        avg_confidence = sum(d.confidence for d in valid_decisions) / len(valid_decisions)
        
        # Combined consensus
        return (direction_consensus + avg_confidence) / 2.0
    
    def _analyze_performance_trends(self, metrics_history: List[PerformanceMetrics]) -> Dict[str, TrendAnalysis]:
        """Analyze trends for key performance metrics"""
        if len(metrics_history) < 5:
            return {}
        
        trends = {}
        recent_metrics = metrics_history[-self.config.trend_detection_window:]
        timestamps = [m.timestamp for m in recent_metrics]
        
        # Analyze response time trend
        response_times = [m.avg_response_time for m in recent_metrics]
        trends['response_time'] = self._analyze_single_trend(timestamps, response_times, 'response_time')
        
        # Analyze CPU usage trend
        cpu_values = [m.cpu_usage for m in recent_metrics]
        trends['cpu_usage'] = self._analyze_single_trend(timestamps, cpu_values, 'cpu_usage')
        
        # Analyze throughput trend
        throughput_values = [m.throughput for m in recent_metrics]
        trends['throughput'] = self._analyze_single_trend(timestamps, throughput_values, 'throughput')
        
        return trends
    
    def _analyze_single_trend(self, timestamps: List[float], values: List[float], metric_name: str) -> TrendAnalysis:
        """Analyze trend for a single metric"""
        if HAS_SCIPY:
            try:
                slope, intercept, r_value, p_value, std_err = stats.linregress(timestamps, values)
                r_squared = r_value ** 2
                
                # Predict future value
                future_time = timestamps[-1] + (self.config.prediction_horizon_minutes * 60)
                predicted_value = slope * future_time + intercept
                
                # Calculate volatility
                residuals = [values[i] - (slope * timestamps[i] + intercept) for i in range(len(values))]
                volatility = (sum(r**2 for r in residuals) / len(residuals)) ** 0.5
                
                # Classify trend type
                if abs(slope) < 0.01:  # Very small slope
                    trend_type = TrendType.STABLE
                elif r_squared < 0.3:  # Low correlation
                    trend_type = TrendType.VOLATILE
                elif slope > 0:
                    trend_type = TrendType.INCREASING
                else:
                    trend_type = TrendType.DECREASING
                
                return TrendAnalysis(
                    trend_type=trend_type,
                    slope=slope,
                    r_squared=r_squared,
                    predicted_value=predicted_value,
                    time_to_threshold=None,  # Could be calculated based on thresholds
                    volatility=volatility,
                    seasonal_component=0.0  # Would require more sophisticated analysis
                )
            except ValueError:
                pass
        
        # Fallback for simple trend analysis
        return TrendAnalysis(
            trend_type=TrendType.STABLE,
            slope=0.0,
            r_squared=0.0,
            predicted_value=values[-1] if values else 0.0,
            time_to_threshold=None,
            volatility=0.0,
            seasonal_component=0.0
        )
    
    def _forecast_workload_metrics(self, metrics_history: List[PerformanceMetrics]) -> Dict[str, float]:
        """Generate forecast for key workload metrics"""
        if len(metrics_history) < 3:
            return {}
        
        recent_metrics = metrics_history[-5:]
        forecast = {}
        
        # Simple moving average forecast
        forecast['avg_response_time'] = sum(m.avg_response_time for m in recent_metrics) / len(recent_metrics)
        forecast['cpu_usage'] = sum(m.cpu_usage for m in recent_metrics) / len(recent_metrics)
        forecast['success_rate'] = sum(m.success_rate for m in recent_metrics) / len(recent_metrics)
        forecast['throughput'] = sum(m.throughput for m in recent_metrics) / len(recent_metrics)
        
        return forecast
    
    def _assess_risk_factors(self, current_metrics: PerformanceMetrics, 
                           trends: Dict[str, TrendAnalysis]) -> List[str]:
        """Assess risk factors for current workload"""
        risks = []
        
        # High resource usage risks
        if current_metrics.cpu_usage > 75:
            risks.append(f"High CPU usage: {current_metrics.cpu_usage:.1f}%")
        
        if current_metrics.memory_usage > 800:
            risks.append(f"High memory usage: {current_metrics.memory_usage:.1f}MB")
        
        # Performance degradation risks
        if current_metrics.avg_response_time > 2500:
            risks.append(f"High response time: {current_metrics.avg_response_time:.1f}ms")
        
        if current_metrics.error_rate > 0.2:
            risks.append(f"High error rate: {current_metrics.error_rate:.1%}")
        
        # Trend-based risks
        for metric_name, trend in trends.items():
            if trend.trend_type == TrendType.INCREASING and metric_name in ['response_time', 'cpu_usage']:
                risks.append(f"Increasing {metric_name} trend (slope: {trend.slope:.3f})")
            elif trend.trend_type == TrendType.DECREASING and metric_name in ['throughput', 'success_rate']:
                risks.append(f"Decreasing {metric_name} trend (slope: {trend.slope:.3f})")
            elif trend.trend_type == TrendType.VOLATILE:
                risks.append(f"Volatile {metric_name} (volatility: {trend.volatility:.2f})")
        
        return risks
    
    def get_prediction_statistics(self) -> Dict[str, Any]:
        """Get statistics about prediction engine performance"""
        if not self.predictions_history:
            return {
                'total_predictions': 0,
                'algorithm_performance': {},
                'direction_distribution': {},
                'confidence_distribution': {}
            }
        
        # Direction distribution
        directions = [p.final_decision.direction.value for p in self.predictions_history]
        direction_dist = {d: directions.count(d) for d in set(directions)}
        
        # Confidence distribution
        confidences = [p.final_decision.confidence for p in self.predictions_history]
        confidence_dist = {
            'very_low': len([c for c in confidences if c < 0.2]),
            'low': len([c for c in confidences if 0.2 <= c < 0.4]),
            'medium': len([c for c in confidences if 0.4 <= c < 0.6]),
            'high': len([c for c in confidences if 0.6 <= c < 0.8]),
            'very_high': len([c for c in confidences if c >= 0.8])
        }
        
        return {
            'total_predictions': len(self.predictions_history),
            'direction_distribution': direction_dist,
            'confidence_distribution': confidence_dist,
            'average_confidence': sum(confidences) / len(confidences),
            'algorithm_weights': self.algorithm_weights,
            'recent_predictions': len([p for p in self.predictions_history 
                                     if time.time() - p.timestamp < 3600])  # Last hour
        }


class WorkloadPatternRecognizer:
    """Advanced workload pattern recognition using ML algorithms"""
    
    def __init__(self, config: Optional[PatternRecognitionConfig] = None):
        self.config = config or PatternRecognitionConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Pattern storage
        self.recognized_patterns: Dict[str, RecognizedPattern] = {}
        self.pattern_clusters: Dict[str, List[str]] = defaultdict(list)  # cluster_id -> pattern_ids
        
        # Pattern analysis state
        self.workload_sequence: List[WorkloadPattern] = []
        self.pattern_analysis_window = 100  # Number of recent workloads to analyze
        
        # Feature extraction cache
        self.feature_cache: Dict[str, PatternFeatures] = {}
        self.pattern_update_counter = 0
        
        self.logger.info("WorkloadPatternRecognizer initialized")
    
    def analyze_workload_pattern(self, workload_pattern: WorkloadPattern) -> Optional[RecognizedPattern]:
        """Analyze a new workload pattern and return matching recognized pattern"""
        
        # Add to workload sequence
        self.workload_sequence.append(workload_pattern)
        if len(self.workload_sequence) > self.pattern_analysis_window:
            self.workload_sequence.pop(0)
        
        # Extract features from current context
        features = self._extract_pattern_features(workload_pattern)
        
        # Find matching pattern
        matched_pattern = self._find_matching_pattern(features, workload_pattern)
        
        # Update pattern recognition periodically
        self.pattern_update_counter += 1
        if self.pattern_update_counter % self.config.pattern_update_frequency == 0:
            self._update_pattern_recognition()
        
        # Also trigger update when we have enough patterns but no recognized patterns yet
        if (len(self.workload_sequence) >= self.config.min_patterns_for_recognition and 
            len(self.recognized_patterns) == 0):
            self._update_pattern_recognition()
        
        return matched_pattern
    
    def _extract_pattern_features(self, current_pattern: WorkloadPattern) -> PatternFeatures:
        """Extract comprehensive features from workload pattern and context"""
        
        features = PatternFeatures()
        
        # Get recent workloads for trend analysis
        recent_workloads = self.workload_sequence[-self.config.trend_window_size:]
        if len(recent_workloads) < 2:
            return features
        
        # Calculate size trend
        sizes = [w.workload_size for w in recent_workloads]
        if len(sizes) >= 2:
            features.size_trend = self._calculate_trend(sizes)
        
        # Calculate duration trend (using timestamps)
        if len(recent_workloads) >= 2:
            durations = []
            for i in range(1, len(recent_workloads)):
                duration = recent_workloads[i].timestamp - recent_workloads[i-1].timestamp
                durations.append(duration)
            if durations:
                features.duration_trend = self._calculate_trend(durations)
        
        # Calculate frequency (workloads per minute)
        time_window = self.config.frequency_window_hours * 3600
        current_time = time.time()
        recent_in_window = [w for w in self.workload_sequence 
                           if current_time - w.timestamp <= time_window]
        if recent_in_window:
            features.frequency = len(recent_in_window) * 60 / time_window
        
        # Calculate variability (coefficient of variation)
        if len(sizes) >= 3:
            mean_size = statistics.mean(sizes)
            if mean_size > 0:
                std_size = statistics.stdev(sizes)
                features.variability = std_size / mean_size
        
        # Calculate peak ratio
        if sizes:
            avg_size = statistics.mean(sizes)
            max_size = max(sizes)
            features.peak_ratio = max_size / avg_size if avg_size > 0 else 1.0
        
        # Calculate time-of-day patterns
        features = self._analyze_temporal_patterns(features, recent_workloads)
        
        # Calculate success rate trend
        success_rates = [w.actual_performance.success_rate for w in recent_workloads 
                        if w.actual_performance]
        if len(success_rates) >= 2:
            features.success_rate_trend = self._calculate_trend(success_rates)
        
        # Calculate resource intensity
        cpu_usage = [w.actual_performance.cpu_usage for w in recent_workloads 
                    if w.actual_performance]
        memory_usage = [w.actual_performance.memory_usage for w in recent_workloads 
                       if w.actual_performance]
        
        if cpu_usage and memory_usage:
            avg_cpu = statistics.mean(cpu_usage) / 100.0  # Normalize to 0-1
            avg_memory = statistics.mean(memory_usage) / 1024.0  # Normalize assuming 1GB baseline
            features.resource_intensity = min(1.0, (avg_cpu + avg_memory) / 2.0)
        
        return features
    
    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate trend direction (-1 to 1) using simple linear regression"""
        if len(values) < 2:
            return 0.0
        
        n = len(values)
        x_values = list(range(n))
        
        # Calculate slope using least squares
        x_mean = statistics.mean(x_values)
        y_mean = statistics.mean(values)
        
        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, values))
        denominator = sum((x - x_mean) ** 2 for x in x_values)
        
        if denominator == 0:
            return 0.0
        
        slope = numerator / denominator
        
        # Normalize slope to -1 to 1 range
        # Use range of values to normalize
        value_range = max(values) - min(values)
        if value_range > 0:
            normalized_slope = slope / value_range
            return max(-1.0, min(1.0, normalized_slope))
        
        return 0.0
    
    def _analyze_temporal_patterns(self, features: PatternFeatures, 
                                  workloads: List[WorkloadPattern]) -> PatternFeatures:
        """Analyze temporal patterns in workload data"""
        
        if not workloads:
            return features
        
        # Analyze hour-of-day patterns
        morning_count = sum(1 for w in workloads if 6 <= w.hour_of_day <= 12)
        evening_count = sum(1 for w in workloads if 18 <= w.hour_of_day <= 23)
        total_count = len(workloads)
        
        features.morning_bias = morning_count / total_count if total_count > 0 else 0.0
        features.evening_bias = evening_count / total_count if total_count > 0 else 0.0
        
        # Analyze day-of-week patterns
        weekday_count = sum(1 for w in workloads if w.day_of_week < 5)  # Mon-Fri
        weekend_count = sum(1 for w in workloads if w.day_of_week >= 5)  # Sat-Sun
        
        features.weekday_bias = weekday_count / total_count if total_count > 0 else 0.0
        features.weekend_bias = weekend_count / total_count if total_count > 0 else 0.0
        
        # Calculate time-of-day pattern strength
        hour_counts = defaultdict(int)
        for w in workloads:
            hour_counts[w.hour_of_day] += 1
        
        if hour_counts:
            hour_values = list(hour_counts.values())
            if len(hour_values) > 1:
                # Use coefficient of variation to measure time dependence
                mean_count = statistics.mean(hour_values)
                if mean_count > 0:
                    std_count = statistics.stdev(hour_values) if len(hour_values) > 1 else 0
                    cv = std_count / mean_count
                    features.time_of_day_pattern = min(1.0, cv)
        
        return features
    
    def _find_matching_pattern(self, features: PatternFeatures, 
                              workload: WorkloadPattern) -> Optional[RecognizedPattern]:
        """Find the best matching recognized pattern"""
        
        if not self.recognized_patterns:
            return None
        
        best_match = None
        best_similarity = 0.0
        
        for pattern_id, pattern in self.recognized_patterns.items():
            similarity = self._calculate_pattern_similarity(features, pattern.features, workload)
            
            if similarity > best_similarity and similarity >= self.config.feature_similarity_threshold:
                best_similarity = similarity
                best_match = pattern
        
        if best_match:
            # Update usage statistics
            best_match.usage_count += 1
            best_match.last_used = time.time()
            
            self.logger.debug(f"Matched pattern {best_match.pattern_id} with similarity {best_similarity:.2f}")
        
        return best_match
    
    def _calculate_pattern_similarity(self, features1: PatternFeatures, 
                                    features2: PatternFeatures,
                                    workload: WorkloadPattern) -> float:
        """Calculate similarity between two pattern feature sets"""
        
        # Structural similarity (feature vector distance)
        structural_features1 = [
            features1.size_trend, features1.duration_trend, features1.frequency,
            features1.variability, features1.peak_ratio, features1.resource_intensity
        ]
        structural_features2 = [
            features2.size_trend, features2.duration_trend, features2.frequency,
            features2.variability, features2.peak_ratio, features2.resource_intensity
        ]
        
        structural_similarity = self._calculate_cosine_similarity(structural_features1, structural_features2)
        
        # Temporal similarity
        temporal_features1 = [
            features1.time_of_day_pattern, features1.morning_bias,
            features1.evening_bias, features1.weekday_bias, features1.weekend_bias
        ]
        temporal_features2 = [
            features2.time_of_day_pattern, features2.morning_bias,
            features2.evening_bias, features2.weekday_bias, features2.weekend_bias
        ]
        
        temporal_similarity = self._calculate_cosine_similarity(temporal_features1, temporal_features2)
        
        # Performance similarity
        performance_features1 = [features1.success_rate_trend]
        performance_features2 = [features2.success_rate_trend]
        
        performance_similarity = self._calculate_cosine_similarity(performance_features1, performance_features2)
        
        # Weighted combination
        total_similarity = (
            structural_similarity * self.config.structural_similarity_weight +
            temporal_similarity * self.config.temporal_similarity_weight +
            performance_similarity * self.config.performance_similarity_weight
        )
        
        return total_similarity
    
    def _calculate_cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Calculate cosine similarity between two vectors"""
        if len(vec1) != len(vec2):
            return 0.0
        
        # Calculate dot product
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        
        # Calculate magnitudes
        magnitude1 = math.sqrt(sum(a * a for a in vec1))
        magnitude2 = math.sqrt(sum(a * a for a in vec2))
        
        # Avoid division by zero
        if magnitude1 == 0 or magnitude2 == 0:
            return 0.0
        
        return dot_product / (magnitude1 * magnitude2)
    
    def _update_pattern_recognition(self):
        """Update pattern recognition by analyzing accumulated workload data"""
        
        if len(self.workload_sequence) < self.config.min_patterns_for_recognition:
            return
        
        self.logger.debug("Updating pattern recognition with clustering analysis")
        
        # Extract features for all recent workloads
        all_features = []
        for i, workload in enumerate(self.workload_sequence):
            # Temporarily set sequence position for feature extraction
            temp_sequence = self.workload_sequence[:i+1]
            old_sequence = self.workload_sequence
            self.workload_sequence = temp_sequence
            
            features = self._extract_pattern_features(workload)
            all_features.append((features, workload))
            
            self.workload_sequence = old_sequence
        
        # Perform clustering to identify patterns
        clusters = self._cluster_patterns(all_features)
        
        # Create or update recognized patterns
        for cluster_id, cluster_workloads in clusters.items():
            if len(cluster_workloads) >= self.config.min_patterns_for_recognition:
                self._create_or_update_pattern(cluster_id, cluster_workloads)
        
        # Cleanup old unused patterns
        self._cleanup_unused_patterns()
    
    def _cluster_patterns(self, feature_workload_pairs: List[Tuple[PatternFeatures, WorkloadPattern]]) -> Dict[str, List[Tuple[PatternFeatures, WorkloadPattern]]]:
        """Simple clustering algorithm to group similar workload patterns"""
        
        clusters = {}
        cluster_counter = 0
        
        for features, workload in feature_workload_pairs:
            # Find best matching cluster
            best_cluster = None
            best_similarity = 0.0
            
            for cluster_id, cluster_items in clusters.items():
                if not cluster_items:
                    continue
                
                # Calculate similarity to cluster centroid
                cluster_features = [item[0] for item in cluster_items]
                centroid = self._calculate_centroid(cluster_features)
                similarity = self._calculate_pattern_similarity(features, centroid, workload)
                
                # Use a lower threshold for initial clustering during testing
                merge_threshold = min(self.config.cluster_merge_threshold, 0.6)
                if similarity > best_similarity and similarity >= merge_threshold:
                    best_similarity = similarity
                    best_cluster = cluster_id
            
            # Add to existing cluster or create new one
            if best_cluster:
                clusters[best_cluster].append((features, workload))
            else:
                new_cluster_id = f"cluster_{cluster_counter}"
                clusters[new_cluster_id] = [(features, workload)]
                cluster_counter += 1
            
            # Limit number of clusters
            if len(clusters) >= self.config.max_clusters:
                break
        
        return clusters
    
    def _calculate_centroid(self, feature_list: List[PatternFeatures]) -> PatternFeatures:
        """Calculate centroid (average) of a list of pattern features"""
        if not feature_list:
            return PatternFeatures()
        
        # Average all numeric fields
        return PatternFeatures(
            size_trend=statistics.mean(f.size_trend for f in feature_list),
            duration_trend=statistics.mean(f.duration_trend for f in feature_list),
            frequency=statistics.mean(f.frequency for f in feature_list),
            variability=statistics.mean(f.variability for f in feature_list),
            peak_ratio=statistics.mean(f.peak_ratio for f in feature_list),
            time_of_day_pattern=statistics.mean(f.time_of_day_pattern for f in feature_list),
            success_rate_trend=statistics.mean(f.success_rate_trend for f in feature_list),
            resource_intensity=statistics.mean(f.resource_intensity for f in feature_list),
            morning_bias=statistics.mean(f.morning_bias for f in feature_list),
            evening_bias=statistics.mean(f.evening_bias for f in feature_list),
            weekday_bias=statistics.mean(f.weekday_bias for f in feature_list),
            weekend_bias=statistics.mean(f.weekend_bias for f in feature_list)
        )
    
    def _create_or_update_pattern(self, cluster_id: str, 
                                 cluster_workloads: List[Tuple[PatternFeatures, WorkloadPattern]]):
        """Create or update a recognized pattern from cluster data"""
        
        workloads = [w for _, w in cluster_workloads]
        features_list = [f for f, _ in cluster_workloads]
        
        # Calculate centroid features
        centroid_features = self._calculate_centroid(features_list)
        
        # Classify pattern type
        pattern_type = self._classify_pattern_type(centroid_features, workloads)
        
        # Classify workload characteristics
        workload_chars = self._classify_workload_characteristics(workloads)
        
        # Calculate optimal thread range
        thread_counts = [w.optimal_threads for w in workloads]
        min_threads = min(thread_counts)
        max_threads = max(thread_counts)
        
        # Calculate performance prediction
        performance_scores = []
        for w in workloads:
            if w.actual_performance:
                score = self._calculate_performance_score_from_metrics(w.actual_performance)
                performance_scores.append(score)
        
        avg_performance = statistics.mean(performance_scores) if performance_scores else 0.5
        
        # Calculate confidence based on cluster consistency
        if len(thread_counts) > 1:
            thread_variance = statistics.variance(thread_counts)
            confidence = max(0.1, 1.0 - (thread_variance / max(thread_counts)))
        else:
            confidence = 0.5
        
        # Create or update pattern
        pattern_id = f"pattern_{cluster_id}_{int(time.time())}"
        
        recognized_pattern = RecognizedPattern(
            pattern_id=pattern_id,
            pattern_type=pattern_type,
            workload_characteristics=workload_chars,
            features=centroid_features,
            confidence=confidence,
            historical_patterns=workloads,
            optimal_thread_range=(min_threads, max_threads),
            predicted_performance={
                'success_rate': avg_performance,
                'expected_threads': statistics.mean(thread_counts),
                'performance_variance': statistics.variance(performance_scores) if len(performance_scores) > 1 else 0.0
            }
        )
        
        self.recognized_patterns[pattern_id] = recognized_pattern
        self.pattern_clusters[cluster_id].append(pattern_id)
        
        self.logger.info(f"Created pattern {pattern_id}: {pattern_type.value} "
                        f"({len(workloads)} samples, confidence: {confidence:.2f})")
    
    def _classify_pattern_type(self, features: PatternFeatures, 
                              workloads: List[WorkloadPattern]) -> PatternType:
        """Classify the pattern type based on features"""
        
        # Analyze trends and characteristics
        if features.size_trend > 0.5:
            return PatternType.GRADUAL
        elif features.size_trend < -0.5:
            return PatternType.DECLINING
        elif features.variability > self.config.variability_threshold:
            if features.peak_ratio > 2.0:
                return PatternType.BURST
            else:
                return PatternType.RANDOM
        elif features.time_of_day_pattern > 0.5:
            return PatternType.PERIODIC
        else:
            return PatternType.SUSTAINED
    
    def _classify_workload_characteristics(self, workloads: List[WorkloadPattern]) -> WorkloadCharacteristics:
        """Classify workload characteristics based on resource usage patterns"""
        
        if not workloads:
            return WorkloadCharacteristics.BALANCED
        
        # Analyze resource usage patterns
        cpu_usage = []
        memory_usage = []
        response_times = []
        
        for w in workloads:
            if w.actual_performance:
                cpu_usage.append(w.actual_performance.cpu_usage)
                memory_usage.append(w.actual_performance.memory_usage)
                response_times.append(w.actual_performance.avg_response_time)
        
        if not cpu_usage:
            return WorkloadCharacteristics.BALANCED
        
        avg_cpu = statistics.mean(cpu_usage)
        avg_memory = statistics.mean(memory_usage)
        avg_response = statistics.mean(response_times)
        
        # Classification thresholds
        high_cpu_threshold = 70.0
        high_memory_threshold = 512.0  # MB
        high_response_threshold = 3000.0  # ms
        
        if avg_cpu > high_cpu_threshold and avg_response < high_response_threshold:
            return WorkloadCharacteristics.CPU_BOUND
        elif avg_memory > high_memory_threshold:
            return WorkloadCharacteristics.MEMORY_BOUND
        elif avg_response > high_response_threshold:
            return WorkloadCharacteristics.NETWORK_BOUND
        elif avg_cpu < 30.0 and avg_response > 1000.0:
            return WorkloadCharacteristics.IO_BOUND
        else:
            return WorkloadCharacteristics.BALANCED
    
    def _calculate_performance_score_from_metrics(self, metrics: PerformanceMetrics) -> float:
        """Calculate performance score from metrics"""
        success_score = metrics.success_rate
        throughput_score = min(metrics.throughput / 10.0, 1.0)
        response_score = max(0.0, 1.0 - (metrics.avg_response_time / 5000.0))
        resource_score = max(0.0, 1.0 - (metrics.cpu_usage / 100.0))
        
        return (success_score * 0.4 + throughput_score * 0.3 + 
                response_score * 0.2 + resource_score * 0.1)
    
    def _cleanup_unused_patterns(self):
        """Remove old unused patterns to prevent memory bloat"""
        current_time = time.time()
        patterns_to_remove = []
        
        for pattern_id, pattern in self.recognized_patterns.items():
            # Remove patterns not used in last 7 days
            if current_time - pattern.last_used > 7 * 24 * 3600:
                patterns_to_remove.append(pattern_id)
        
        for pattern_id in patterns_to_remove:
            del self.recognized_patterns[pattern_id]
            # Remove from clusters
            for cluster_id, pattern_ids in self.pattern_clusters.items():
                if pattern_id in pattern_ids:
                    pattern_ids.remove(pattern_id)
        
        if patterns_to_remove:
            self.logger.info(f"Cleaned up {len(patterns_to_remove)} unused patterns")
    
    def get_pattern_statistics(self) -> Dict[str, Any]:
        """Get pattern recognition statistics"""
        if not self.recognized_patterns:
            return {
                'total_patterns': 0,
                'pattern_types': {},
                'workload_characteristics': {},
                'average_confidence': 0.0,
                'most_used_pattern': None
            }
        
        # Count pattern types
        pattern_types = defaultdict(int)
        workload_chars = defaultdict(int)
        confidences = []
        usage_counts = []
        
        for pattern in self.recognized_patterns.values():
            pattern_types[pattern.pattern_type.value] += 1
            workload_chars[pattern.workload_characteristics.value] += 1
            confidences.append(pattern.confidence)
            usage_counts.append(pattern.usage_count)
        
        # Find most used pattern
        most_used_pattern = None
        if usage_counts:
            max_usage = max(usage_counts)
            for pattern in self.recognized_patterns.values():
                if pattern.usage_count == max_usage:
                    most_used_pattern = {
                        'pattern_id': pattern.pattern_id,
                        'pattern_type': pattern.pattern_type.value,
                        'usage_count': pattern.usage_count,
                        'confidence': pattern.confidence
                    }
                    break
        
        return {
            'total_patterns': len(self.recognized_patterns),
            'pattern_types': dict(pattern_types),
            'workload_characteristics': dict(workload_chars),
            'average_confidence': statistics.mean(confidences) if confidences else 0.0,
            'most_used_pattern': most_used_pattern,
            'total_clusters': len(self.pattern_clusters),
            'workload_sequence_length': len(self.workload_sequence)
        }


class PredictiveLoadManager:
    """ML-based predictive load management using historical data"""
    
    def __init__(self, config: Optional[PredictiveConfig] = None):
        self.config = config or PredictiveConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Historical data storage
        self.workload_history: List[WorkloadPattern] = []
        self.performance_cache: Dict[str, List[WorkloadPattern]] = defaultdict(list)
        
        # Prediction model state
        self.feature_means: Dict[str, float] = {}
        self.feature_stds: Dict[str, float] = {}
        self.model_trained = False
        
        # File paths for persistence
        self.history_file = os.path.join(os.path.expanduser("~"), ".proxc_workload_history.pkl")
        self.model_file = os.path.join(os.path.expanduser("~"), ".proxc_prediction_model.pkl")
        
        # Load historical data
        self._load_historical_data()
        
        self.logger.info("PredictiveLoadManager initialized with historical learning")
    
    def predict_optimal_threads(self, workload_size: int, workload_type: str, 
                               current_metrics: Optional[PerformanceMetrics] = None) -> Tuple[int, float]:
        """Predict optimal thread count using historical data"""
        
        if not self.config.enable_historical_learning or len(self.workload_history) < self.config.min_samples_for_prediction:
            # Fallback to heuristic-based prediction
            return self._heuristic_prediction(workload_size, workload_type), 0.5
        
        # Find similar historical patterns
        similar_patterns = self._find_similar_patterns(workload_size, workload_type, current_metrics)
        
        if not similar_patterns:
            return self._heuristic_prediction(workload_size, workload_type), 0.3
        
        # Calculate weighted prediction
        predicted_threads, confidence = self._calculate_weighted_prediction(similar_patterns)
        
        # Apply adjustment factors based on confidence
        if confidence > self.config.prediction_confidence_threshold:
            adjustment = self.config.aggressive_factor if confidence > 0.9 else 1.0
        else:
            adjustment = self.config.conservative_factor
        
        predicted_threads = int(predicted_threads * adjustment)
        
        self.logger.debug(f"Predicted {predicted_threads} threads for workload {workload_size}:{workload_type} "
                         f"(confidence: {confidence:.2f})")
        
        return predicted_threads, confidence
    
    def _find_similar_patterns(self, workload_size: int, workload_type: str,
                              current_metrics: Optional[PerformanceMetrics]) -> List[WorkloadPattern]:
        """Find historically similar workload patterns"""
        similar_patterns = []
        current_time = time.time()
        current_hour = time.localtime(current_time).tm_hour
        current_dow = time.localtime(current_time).tm_wday
        
        for pattern in self.workload_history:
            similarity = self._calculate_pattern_similarity(
                pattern, workload_size, workload_type, current_hour, current_dow, current_metrics
            )
            
            if similarity >= self.config.pattern_similarity_threshold:
                similar_patterns.append((pattern, similarity))
        
        # Sort by similarity and return top patterns
        similar_patterns.sort(key=lambda x: x[1], reverse=True)
        return [pattern for pattern, similarity in similar_patterns[:10]]
    
    def _calculate_pattern_similarity(self, pattern: WorkloadPattern, workload_size: int,
                                    workload_type: str, hour: int, dow: int,
                                    current_metrics: Optional[PerformanceMetrics]) -> float:
        """Calculate similarity between current workload and historical pattern"""
        
        # Size similarity (normalized)
        size_diff = abs(pattern.workload_size - workload_size) / max(pattern.workload_size, workload_size, 1)
        size_similarity = 1.0 - min(size_diff, 1.0)
        
        # Type similarity
        type_similarity = 1.0 if pattern.workload_type == workload_type else 0.5
        
        # Time similarity (hour and day of week)
        hour_diff = min(abs(pattern.hour_of_day - hour), 24 - abs(pattern.hour_of_day - hour))
        hour_similarity = 1.0 - (hour_diff / 12.0)
        
        dow_diff = min(abs(pattern.day_of_week - dow), 7 - abs(pattern.day_of_week - dow))
        dow_similarity = 1.0 - (dow_diff / 3.5)
        
        time_similarity = (hour_similarity + dow_similarity) / 2.0
        
        # Performance similarity (if current metrics available)
        performance_similarity = 0.5  # default
        if current_metrics and pattern.actual_performance:
            cpu_diff = abs(pattern.actual_performance.cpu_usage - current_metrics.cpu_usage) / 100.0
            memory_diff = abs(pattern.actual_performance.memory_usage - current_metrics.memory_usage) / max(
                pattern.actual_performance.memory_usage, current_metrics.memory_usage, 1.0
            )
            performance_similarity = 1.0 - min((cpu_diff + memory_diff) / 2.0, 1.0)
        
        # Weighted similarity score
        total_similarity = (
            size_similarity * self.config.size_weight +
            type_similarity * self.config.type_weight +
            time_similarity * self.config.time_weight +
            performance_similarity * self.config.performance_weight
        )
        
        return total_similarity
    
    def _calculate_weighted_prediction(self, similar_patterns: List[WorkloadPattern]) -> Tuple[float, float]:
        """Calculate weighted prediction from similar patterns"""
        if not similar_patterns:
            return 10.0, 0.0
        
        # Extract thread counts and performance scores
        thread_counts = []
        weights = []
        
        for pattern in similar_patterns:
            # Weight based on performance quality
            performance_score = self._calculate_performance_score(pattern.actual_performance)
            thread_counts.append(pattern.optimal_threads)
            weights.append(performance_score)
        
        # Calculate weighted average
        if sum(weights) > 0:
            weighted_prediction = sum(tc * w for tc, w in zip(thread_counts, weights)) / sum(weights)
        else:
            weighted_prediction = statistics.mean(thread_counts)
        
        # Calculate confidence based on variance and sample size
        if len(thread_counts) > 1:
            variance = statistics.variance(thread_counts)
            confidence = min(1.0, 1.0 / (1.0 + variance / len(thread_counts)))
        else:
            confidence = 0.5
        
        # Boost confidence with more samples
        sample_confidence = min(len(similar_patterns) / 10.0, 1.0)
        final_confidence = (confidence + sample_confidence) / 2.0
        
        return weighted_prediction, final_confidence
    
    def _calculate_performance_score(self, metrics: PerformanceMetrics) -> float:
        """Calculate performance quality score (0-1)"""
        if not metrics:
            return 0.5
        
        # Normalize metrics to 0-1 scale (higher is better)
        success_score = metrics.success_rate
        throughput_score = min(metrics.throughput / 10.0, 1.0)  # Assume 10 proxies/sec is excellent
        response_score = max(0.0, 1.0 - (metrics.avg_response_time / 5000.0))  # 5s is poor
        resource_score = max(0.0, 1.0 - (metrics.cpu_usage / 100.0))  # Lower CPU is better
        
        # Weighted performance score
        performance_score = (
            success_score * 0.4 +
            throughput_score * 0.3 +
            response_score * 0.2 +
            resource_score * 0.1
        )
        
        return max(0.1, min(1.0, performance_score))
    
    def _heuristic_prediction(self, workload_size: int, workload_type: str) -> int:
        """Fallback heuristic-based thread prediction"""
        # Get CPU count for baseline
        cpu_count = psutil.cpu_count() or 4
        
        # Base calculation
        if workload_size <= 10:
            base_threads = min(workload_size, cpu_count)
        elif workload_size <= 100:
            base_threads = min(cpu_count * 2, workload_size // 5)
        else:
            base_threads = min(cpu_count * 4, workload_size // 10)
        
        # Adjust based on workload type
        if workload_type == "socks":
            base_threads = int(base_threads * 0.8)  # SOCKS is more resource intensive
        elif workload_type == "http":
            base_threads = int(base_threads * 1.2)  # HTTP is lighter
        
        return max(2, min(base_threads, 100))
    
    def record_workload_outcome(self, workload_size: int, workload_type: str,
                               threads_used: int, actual_metrics: PerformanceMetrics):
        """Record the outcome of a workload for learning"""
        if not self.config.enable_historical_learning:
            return
        
        current_time = time.time()
        time_struct = time.localtime(current_time)
        
        pattern = WorkloadPattern(
            workload_size=workload_size,
            workload_type=workload_type,
            hour_of_day=time_struct.tm_hour,
            day_of_week=time_struct.tm_wday,
            optimal_threads=threads_used,
            actual_performance=actual_metrics,
            timestamp=current_time
        )
        
        # Add to history
        self.workload_history.append(pattern)
        
        # Add to cache for quick lookup
        cache_key = f"{workload_type}_{workload_size//10*10}"  # Bucket by size ranges
        self.performance_cache[cache_key].append(pattern)
        
        # Cleanup old entries
        self._cleanup_old_entries()
        
        # Update model periodically
        if len(self.workload_history) % 10 == 0:
            self._update_prediction_model()
        
        # Save to disk periodically
        if len(self.workload_history) % 50 == 0:
            self._save_historical_data()
        
        self.logger.debug(f"Recorded workload outcome: {workload_size} items, {threads_used} threads, "
                         f"performance score: {self._calculate_performance_score(actual_metrics):.2f}")
    
    def _cleanup_old_entries(self):
        """Remove old historical entries beyond retention period"""
        cutoff_time = time.time() - (self.config.history_retention_days * 24 * 3600)
        
        # Cleanup main history
        self.workload_history = [p for p in self.workload_history if p.timestamp > cutoff_time]
        
        # Cleanup cache
        for cache_key in list(self.performance_cache.keys()):
            self.performance_cache[cache_key] = [
                p for p in self.performance_cache[cache_key] if p.timestamp > cutoff_time
            ]
            if not self.performance_cache[cache_key]:
                del self.performance_cache[cache_key]
    
    def _update_prediction_model(self):
        """Update simple prediction model parameters"""
        if len(self.workload_history) < 5:
            return
        
        # Extract features for normalization
        sizes = [p.workload_size for p in self.workload_history]
        threads = [p.optimal_threads for p in self.workload_history]
        cpu_usage = [p.actual_performance.cpu_usage for p in self.workload_history if p.actual_performance]
        
        # Calculate means and standard deviations
        self.feature_means = {
            'workload_size': statistics.mean(sizes),
            'optimal_threads': statistics.mean(threads),
            'cpu_usage': statistics.mean(cpu_usage) if cpu_usage else 50.0
        }
        
        if len(sizes) > 1:
            self.feature_stds = {
                'workload_size': statistics.stdev(sizes),
                'optimal_threads': statistics.stdev(threads),
                'cpu_usage': statistics.stdev(cpu_usage) if len(cpu_usage) > 1 else 20.0
            }
        else:
            self.feature_stds = {'workload_size': 1.0, 'optimal_threads': 1.0, 'cpu_usage': 1.0}
        
        self.model_trained = True
    
    def _load_historical_data(self):
        """Load historical data from disk"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'rb') as f:
                    data = pickle.load(f)
                    self.workload_history = data.get('history', [])
                    self.performance_cache = data.get('cache', defaultdict(list))
                    self.feature_means = data.get('means', {})
                    self.feature_stds = data.get('stds', {})
                    self.model_trained = bool(self.feature_means)
                
                self.logger.info(f"Loaded {len(self.workload_history)} historical workload patterns")
        except Exception as e:
            self.logger.warning(f"Could not load historical data: {e}")
            self.workload_history = []
            self.performance_cache = defaultdict(list)
    
    def _save_historical_data(self):
        """Save historical data to disk"""
        try:
            data = {
                'history': self.workload_history,
                'cache': dict(self.performance_cache),
                'means': self.feature_means,
                'stds': self.feature_stds
            }
            
            with open(self.history_file, 'wb') as f:
                pickle.dump(data, f)
            
            self.logger.debug(f"Saved {len(self.workload_history)} historical patterns to disk")
        except Exception as e:
            self.logger.warning(f"Could not save historical data: {e}")
    
    def get_prediction_stats(self) -> Dict[str, Any]:
        """Get prediction system statistics"""
        return {
            'total_patterns': len(self.workload_history),
            'cached_patterns': sum(len(patterns) for patterns in self.performance_cache.values()),
            'model_trained': self.model_trained,
            'retention_days': self.config.history_retention_days,
            'oldest_pattern': min(p.timestamp for p in self.workload_history) if self.workload_history else 0,
            'newest_pattern': max(p.timestamp for p in self.workload_history) if self.workload_history else 0,
            'feature_means': self.feature_means,
            'cache_keys': list(self.performance_cache.keys())
        }


class DynamicThreadPoolManager:
    """Manages dynamic thread pool with performance-based scaling"""
    
    def __init__(self, config: Optional[ThreadPoolConfig] = None, 
                 predictive_config: Optional[PredictiveConfig] = None,
                 pattern_recognition_config: Optional[PatternRecognitionConfig] = None):
        self.config = config or ThreadPoolConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Predictive load management
        self.predictive_manager = PredictiveLoadManager(predictive_config)
        self.enable_predictive = True
        self.current_workload_info: Optional[Tuple[int, str]] = None  # (size, type)
        
        # Pattern recognition for workload analysis
        self.pattern_recognizer = WorkloadPatternRecognizer(pattern_recognition_config)
        self.enable_pattern_recognition = pattern_recognition_config is not None or True
        self.current_workload_pattern: Optional[RecognizedPattern] = None
        
        # Predictive scaling engine
        self.predictive_scaling_engine = PredictiveScalingEngine(predictive_config)
        self.enable_predictive_scaling = getattr(self.config, 'enable_predictive_scaling', True)
        self.last_predictive_scaling_time = 0.0
        self.current_scaling_prediction: Optional[ScalingPrediction] = None
        
        # Thread pool management
        self.current_threads = self.config.initial_threads
        self.executor: Optional[ThreadPoolExecutor] = None
        self.is_running = False
        
        # Performance monitoring
        self.metrics_history: deque = deque(maxlen=self.config.metrics_window_size)
        self.last_scaling_time = 0.0
        self.monitoring_thread: Optional[threading.Thread] = None
        self.stop_monitoring = threading.Event()
        
        # Statistics
        self.total_tasks = 0
        self.completed_tasks = 0
        self.failed_tasks = 0
        self.scaling_events = []
        
        # Task tracking (thread-safe)
        self.active_tasks = set()
        self.task_start_times = {}
        self.recent_response_times = deque(maxlen=100)  # Track recent response times
        self.task_lock = threading.RLock()  # Protects task tracking data
        
        self.logger.info(f"DynamicThreadPoolManager initialized with {self.current_threads} initial threads, "
                        f"predictive load management, and workload pattern recognition")
    
    def start(self):
        """Start the dynamic thread pool and monitoring"""
        if self.is_running:
            return
        
        self.is_running = True
        self.executor = ThreadPoolExecutor(max_workers=self.current_threads)
        
        # Start performance monitoring
        self.monitoring_thread = threading.Thread(target=self._monitor_performance, daemon=True)
        self.monitoring_thread.start()
        
        self.logger.info("Dynamic thread pool started")
    
    def stop(self):
        """Stop the thread pool and monitoring"""
        if not self.is_running:
            return
        
        self.is_running = False
        self.stop_monitoring.set()
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5.0)
        
        if self.executor:
            self.executor.shutdown(wait=True)
            self.executor = None
        
        self.logger.info("Dynamic thread pool stopped")
    
    def set_workload_info(self, workload_size: int, workload_type: str):
        """Set current workload information for predictive management and pattern recognition"""
        self.current_workload_info = (workload_size, workload_type)
        
        # Create workload pattern for analysis
        if self.enable_pattern_recognition and workload_size > 0:
            current_time = time.time()
            time_struct = time.localtime(current_time)
            current_metrics = self.metrics_history[-1] if self.metrics_history else None
            
            workload_pattern = WorkloadPattern(
                workload_size=workload_size,
                workload_type=workload_type,
                hour_of_day=time_struct.tm_hour,
                day_of_week=time_struct.tm_wday,
                optimal_threads=self.current_threads,  # Current guess
                actual_performance=current_metrics or PerformanceMetrics(),
                timestamp=current_time
            )
            
            # Analyze pattern and get recommendations
            recognized_pattern = self.pattern_recognizer.analyze_workload_pattern(workload_pattern)
            self.current_workload_pattern = recognized_pattern
            
            if recognized_pattern:
                # Use pattern-based prediction
                pattern_threads = int(sum(recognized_pattern.optimal_thread_range) / 2)
                pattern_confidence = recognized_pattern.confidence
                
                self.logger.info(f"Pattern recognition: Matched {recognized_pattern.pattern_type.value} pattern "
                               f"({recognized_pattern.workload_characteristics.value}) "
                               f"suggesting {pattern_threads} threads (confidence: {pattern_confidence:.2f})")
                
                # Apply pattern-based scaling if confidence is high
                if pattern_confidence > 0.7 and pattern_threads != self.current_threads:
                    self._scale_to(pattern_threads, 
                                 f"Pattern-based: {recognized_pattern.pattern_type.value} pattern")
                    return  # Skip predictive scaling if pattern-based scaling applied
        
        if self.enable_predictive and workload_size > 0:
            # Get prediction for optimal thread count
            current_metrics = self.metrics_history[-1] if self.metrics_history else None
            predicted_threads, confidence = self.predictive_manager.predict_optimal_threads(
                workload_size, workload_type, current_metrics
            )
            
            # Apply prediction if confidence is sufficient and no pattern-based scaling occurred
            if confidence > 0.5 and predicted_threads != self.current_threads:
                self.logger.info(f"Predictive scaling: {self.current_threads} → {predicted_threads} threads "
                               f"for {workload_size} {workload_type} proxies (confidence: {confidence:.2f})")
                self._scale_to(predicted_threads, f"Predictive: {workload_size} {workload_type} proxies")
    
    def complete_workload(self):
        """Mark current workload as complete and record outcome for learning"""
        if not self.current_workload_info:
            return
        
        workload_size, workload_type = self.current_workload_info
        
        # Calculate final performance metrics
        if self.metrics_history:
            final_metrics = self.metrics_history[-1]
            final_metrics.workload_size = workload_size
            final_metrics.workload_type = workload_type
            
            # Record the outcome for predictive learning
            if self.enable_predictive:
                self.predictive_manager.record_workload_outcome(
                    workload_size, workload_type, self.current_threads, final_metrics
                )
            
            # Update current workload pattern with actual performance for pattern learning
            if self.enable_pattern_recognition and self.current_workload_pattern:
                # Update the pattern's historical data with actual performance
                current_time = time.time()
                time_struct = time.localtime(current_time)
                
                completed_pattern = WorkloadPattern(
                    workload_size=workload_size,
                    workload_type=workload_type,
                    hour_of_day=time_struct.tm_hour,
                    day_of_week=time_struct.tm_wday,
                    optimal_threads=self.current_threads,
                    actual_performance=final_metrics,
                    timestamp=current_time
                )
                
                # Re-analyze with completed data to improve pattern recognition
                self.pattern_recognizer.analyze_workload_pattern(completed_pattern)
            
            self.logger.debug(f"Recorded workload outcome: {workload_size} {workload_type} proxies "
                            f"with {self.current_threads} threads")
        
        self.current_workload_info = None
        self.current_workload_pattern = None
    
    def submit_task(self, func: Callable, *args, **kwargs) -> 'TaskFuture':
        """Submit a task to the thread pool with tracking"""
        if not self.is_running or not self.executor:
            raise RuntimeError("Thread pool not started")
        
        with self.task_lock:
            self.total_tasks += 1
            task_id = f"task_{self.total_tasks}"
            
            # Submit to executor
            future = self.executor.submit(func, *args, **kwargs)
            
            # Track task
            self.active_tasks.add(task_id)
            self.task_start_times[task_id] = time.time()
        
        # Wrap future for tracking
        return TaskFuture(future, task_id, self)
    
    def _task_completed(self, task_id: str, success: bool):
        """Called when a task completes"""
        current_time = time.time()
        
        with self.task_lock:
            if task_id in self.active_tasks:
                self.active_tasks.remove(task_id)
            
            # Calculate and store response time
            if task_id in self.task_start_times:
                response_time = (current_time - self.task_start_times[task_id]) * 1000  # Convert to ms
                self.recent_response_times.append(response_time)
                del self.task_start_times[task_id]
            
            if success:
                self.completed_tasks += 1
            else:
                self.failed_tasks += 1
    
    def _monitor_performance(self):
        """Monitor system and pool performance"""
        self.logger.debug("Performance monitoring started")
        
        while not self.stop_monitoring.wait(self.config.monitoring_interval):
            try:
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)
                
                # Log metrics periodically
                if len(self.metrics_history) % 5 == 0:
                    self.logger.debug(f"Performance: {metrics.throughput:.1f} proxies/s, "
                                    f"{metrics.avg_response_time:.1f}ms avg, "
                                    f"{metrics.cpu_usage:.1f}% CPU, "
                                    f"{self.current_threads} threads")
                
                # Check if scaling is needed
                if self._should_scale():
                    self._perform_scaling()
                
            except Exception as e:
                self.logger.error(f"Error in performance monitoring: {e}")
    
    def _collect_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics"""
        current_time = time.time()
        
        # Thread-safe access to task data
        with self.task_lock:
            # Calculate average response time from recent completed tasks
            avg_response_time = statistics.mean(self.recent_response_times) if self.recent_response_times else 0.0
            active_threads = len(self.active_tasks)
            completed_tasks_snapshot = self.completed_tasks
            failed_tasks_snapshot = self.failed_tasks
        
        # System metrics with fallback for Android/Termux
        try:
            cpu_usage = psutil.cpu_percent(interval=None)
        except (OSError, PermissionError):
            # Fallback to conservative estimate on Android/Termux
            cpu_usage = 50.0  # Conservative default
        
        try:
            memory_info = psutil.virtual_memory()
            memory_usage = memory_info.used / (1024 * 1024)  # MB
        except (OSError, PermissionError):
            # Fallback memory calculation
            memory_usage = 512.0  # Conservative default MB
        
        # Pool metrics
        queue_size = getattr(self.executor, '_work_queue', None)
        queue_size = queue_size.qsize() if queue_size else 0
        
        # Calculate throughput from recent history
        throughput = 0.0
        if len(self.metrics_history) >= 2:
            recent_completed = completed_tasks_snapshot
            time_window = current_time - self.metrics_history[-1].timestamp
            if time_window > 0:
                throughput = recent_completed / time_window
        
        # Calculate error rate using snapshots
        total_finished = completed_tasks_snapshot + failed_tasks_snapshot
        error_rate = failed_tasks_snapshot / total_finished if total_finished > 0 else 0.0
        success_rate = completed_tasks_snapshot / total_finished if total_finished > 0 else 0.0
        
        return PerformanceMetrics(
            avg_response_time=avg_response_time,  # Already in ms
            success_rate=success_rate,
            throughput=throughput,
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            error_rate=error_rate,
            active_threads=active_threads,
            queue_size=queue_size,
            timestamp=current_time
        )
    
    def _should_scale(self) -> bool:
        """Determine if scaling is needed based on performance metrics and predictions"""
        if len(self.metrics_history) < 2:
            return False
        
        current_time = time.time()
        
        # Check standard reactive scaling cooldown
        if current_time - self.last_scaling_time < self.config.scaling_cooldown:
            # For predictive scaling, use separate cooldown
            if (self.enable_predictive_scaling and 
                current_time - self.last_predictive_scaling_time >= 
                getattr(self.config, 'predictive_scaling_cooldown', 60.0)):
                return True
            return False
        
        return True
    
    def _perform_scaling(self):
        """Perform thread pool scaling using predictive algorithms"""
        if not self.metrics_history:
            return
        
        current_metrics = self.metrics_history[-1]
        current_time = time.time()
        
        # Try predictive scaling first if enabled
        if self.enable_predictive_scaling and len(self.metrics_history) >= 5:
            prediction = self.predictive_scaling_engine.predict_scaling_decision(
                current_metrics=current_metrics,
                metrics_history=list(self.metrics_history),
                current_threads=self.current_threads,
                pattern_match=self.current_workload_pattern
            )
            
            self.current_scaling_prediction = prediction
            
            # Apply predictive scaling if confidence is sufficient
            min_confidence = getattr(self.config, 'min_prediction_confidence', 0.6)
            if prediction.final_decision.confidence >= min_confidence:
                self._apply_predictive_scaling_decision(prediction)
                return
            else:
                self.logger.debug(f"Predictive scaling confidence too low: {prediction.final_decision.confidence:.2f} < {min_confidence}")
        
        # Fallback to reactive scaling
        self._perform_reactive_scaling()
    
    def _apply_predictive_scaling_decision(self, prediction: ScalingPrediction):
        """Apply predictive scaling decision"""
        decision = prediction.final_decision
        
        if decision.direction == ScalingDirection.MAINTAIN:
            self.logger.debug(f"Predictive scaling: Maintain {self.current_threads} threads")
            return
        
        # Check if scaling is actually needed
        if (decision.direction in [ScalingDirection.SCALE_UP, ScalingDirection.AGGRESSIVE_UP] and 
            decision.target_threads <= self.current_threads):
            return
        
        if (decision.direction in [ScalingDirection.SCALE_DOWN, ScalingDirection.AGGRESSIVE_DOWN] and 
            decision.target_threads >= self.current_threads):
            return
        
        # Apply bounds
        target_threads = max(self.config.min_threads, 
                           min(self.config.max_threads, decision.target_threads))
        
        if target_threads != self.current_threads:
            reason = f"Predictive ({decision.confidence:.2f}): {decision.reasoning}"
            self._scale_to(target_threads, reason)
            self.last_predictive_scaling_time = time.time()
            
            self.logger.info(f"Applied predictive scaling: {self.current_threads} → {target_threads} threads "
                           f"(confidence: {decision.confidence:.2f}, urgency: {decision.urgency:.2f})")
    
    def _perform_reactive_scaling(self):
        """Perform traditional reactive scaling based on current metrics"""
        current_metrics = self.metrics_history[-1]
        
        # Calculate average metrics over recent window
        recent_metrics = list(self.metrics_history)[-min(3, len(self.metrics_history)):]
        avg_cpu = sum(m.cpu_usage for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_usage for m in recent_metrics) / len(recent_metrics)
        avg_error_rate = sum(m.error_rate for m in recent_metrics) / len(recent_metrics)
        avg_response_time = sum(m.avg_response_time for m in recent_metrics) / len(recent_metrics)
        avg_success_rate = sum(m.success_rate for m in recent_metrics) / len(recent_metrics)
        
        # Scaling decision logic
        scale_up = False
        scale_down = False
        reason = ""
        
        # Scale down conditions (prioritized - safety first)
        if avg_cpu > self.config.cpu_threshold:
            scale_down = True
            reason = f"High CPU usage: {avg_cpu:.1f}%"
        elif avg_memory > self.config.memory_threshold:
            scale_down = True
            reason = f"High memory usage: {avg_memory:.1f}MB"
        elif avg_error_rate > self.config.error_rate_threshold:
            scale_down = True
            reason = f"High error rate: {avg_error_rate:.1%}"
        
        # Scale up conditions (only if not scaling down)
        elif avg_response_time > self.config.response_time_threshold and avg_success_rate > self.config.success_rate_threshold:
            if current_metrics.queue_size > 0:  # There's work waiting
                scale_up = True
                reason = f"High response time: {avg_response_time:.1f}ms with queue: {current_metrics.queue_size}"
        elif current_metrics.queue_size > self.current_threads * 2:  # Queue is backing up
            scale_up = True
            reason = f"Large queue: {current_metrics.queue_size} items"
        
        # Perform scaling
        if scale_up and self.current_threads < self.config.max_threads:
            new_threads = min(
                int(self.current_threads * self.config.scale_factor),
                self.config.max_threads
            )
            self._scale_to(new_threads, f"Scale UP: {reason}")
        
        elif scale_down and self.current_threads > self.config.min_threads:
            new_threads = max(
                int(self.current_threads / self.config.scale_factor),
                self.config.min_threads
            )
            self._scale_to(new_threads, f"Scale DOWN: {reason}")
    
    def _scale_to(self, new_thread_count: int, reason: str):
        """Scale thread pool to specified size"""
        if new_thread_count == self.current_threads:
            return
        
        old_threads = self.current_threads
        self.current_threads = new_thread_count
        self.last_scaling_time = time.time()
        
        # Record scaling event
        scaling_event = {
            'timestamp': time.time(),
            'old_threads': old_threads,
            'new_threads': new_thread_count,
            'reason': reason
        }
        self.scaling_events.append(scaling_event)
        
        # Create new executor with updated thread count
        old_executor = self.executor
        self.executor = ThreadPoolExecutor(max_workers=new_thread_count)
        
        # Shutdown old executor gracefully with proper cleanup
        if old_executor:
            cleanup_thread = threading.Thread(
                target=self._cleanup_executor, 
                args=(old_executor,), 
                daemon=False  # Wait for cleanup
            )
            cleanup_thread.start()
            cleanup_thread.join(timeout=30)  # Ensure cleanup completes
        
        self.logger.info(f"Scaled thread pool: {old_threads} → {new_thread_count} threads. {reason}")
    
    def _cleanup_executor(self, executor):
        """Properly cleanup old executor"""
        try:
            # Use only wait=True for cross-version compatibility
            executor.shutdown(wait=True)
        except Exception as e:
            self.logger.error(f"Error during executor cleanup: {e}")
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get current performance statistics including predictive and pattern recognition data"""
        current_metrics = self.metrics_history[-1] if self.metrics_history else None
        
        with self.task_lock:
            # Thread-safe snapshot of current state
            stats = {
                'current_threads': self.current_threads,
                'total_tasks': self.total_tasks,
                'completed_tasks': self.completed_tasks,
                'failed_tasks': self.failed_tasks,
                'active_tasks': len(self.active_tasks),
                'success_rate': self.completed_tasks / max(1, self.total_tasks),
                'current_metrics': current_metrics,
                'scaling_events': len(self.scaling_events),
                'recent_scaling_events': self.scaling_events[-3:] if self.scaling_events else [],
                'predictive_enabled': self.enable_predictive,
                'pattern_recognition_enabled': self.enable_pattern_recognition,
                'current_workload': self.current_workload_info,
                'current_pattern': {
                    'pattern_id': self.current_workload_pattern.pattern_id,
                    'pattern_type': self.current_workload_pattern.pattern_type.value,
                    'workload_characteristics': self.current_workload_pattern.workload_characteristics.value,
                    'confidence': self.current_workload_pattern.confidence,
                    'optimal_thread_range': self.current_workload_pattern.optimal_thread_range
                } if self.current_workload_pattern else None,
                'prediction_stats': self.predictive_manager.get_prediction_stats() if self.enable_predictive else None,
                'pattern_recognition_stats': self.pattern_recognizer.get_pattern_statistics() if self.enable_pattern_recognition else None,
                'predictive_scaling_enabled': self.enable_predictive_scaling,
                'current_scaling_prediction': self.current_scaling_prediction.to_dict() if self.current_scaling_prediction else None,
                'predictive_scaling_stats': self.predictive_scaling_engine.get_prediction_statistics() if self.enable_predictive_scaling else None
            }
        
        return stats
    
    def get_predictive_recommendation(self, workload_size: int, workload_type: str) -> Dict[str, Any]:
        """Get predictive and pattern-based recommendation for a potential workload"""
        recommendation = {
            'workload_size': workload_size,
            'workload_type': workload_type,
            'current_threads': self.current_threads,
            'predictive_enabled': self.enable_predictive,
            'pattern_recognition_enabled': self.enable_pattern_recognition,
            'predictive_scaling_enabled': self.enable_predictive_scaling
        }
        
        # Pattern-based recommendation
        if self.enable_pattern_recognition:
            current_time = time.time()
            time_struct = time.localtime(current_time)
            current_metrics = self.metrics_history[-1] if self.metrics_history else None
            
            temp_pattern = WorkloadPattern(
                workload_size=workload_size,
                workload_type=workload_type,
                hour_of_day=time_struct.tm_hour,
                day_of_week=time_struct.tm_wday,
                optimal_threads=self.current_threads,
                actual_performance=current_metrics or PerformanceMetrics(),
                timestamp=current_time
            )
            
            pattern_match = self.pattern_recognizer.analyze_workload_pattern(temp_pattern)
            
            if pattern_match:
                pattern_threads = int(sum(pattern_match.optimal_thread_range) / 2)
                recommendation['pattern_based'] = {
                    'matched_pattern': {
                        'pattern_id': pattern_match.pattern_id,
                        'pattern_type': pattern_match.pattern_type.value,
                        'workload_characteristics': pattern_match.workload_characteristics.value,
                        'confidence': pattern_match.confidence
                    },
                    'recommended_threads': pattern_threads,
                    'thread_range': pattern_match.optimal_thread_range,
                    'recommendation': 'scale_up' if pattern_threads > self.current_threads else 
                                   'scale_down' if pattern_threads < self.current_threads else 'maintain'
                }
            else:
                recommendation['pattern_based'] = {'matched_pattern': None}
        
        # Predictive recommendation
        if self.enable_predictive:
            current_metrics = self.metrics_history[-1] if self.metrics_history else None
            predicted_threads, confidence = self.predictive_manager.predict_optimal_threads(
                workload_size, workload_type, current_metrics
            )
            
            recommendation['predictive'] = {
                'predicted_threads': predicted_threads,
                'confidence': confidence,
                'recommendation': 'scale_up' if predicted_threads > self.current_threads else 
                               'scale_down' if predicted_threads < self.current_threads else 'maintain'
            }
        
        # Advanced predictive scaling recommendation
        if self.enable_predictive_scaling and len(self.metrics_history) >= 5:
            current_metrics = self.metrics_history[-1]
            temp_pattern = WorkloadPattern(
                workload_size=workload_size,
                workload_type=workload_type,
                hour_of_day=time.localtime().tm_hour,
                day_of_week=time.localtime().tm_wday,
                optimal_threads=self.current_threads,
                actual_performance=current_metrics or PerformanceMetrics(),
                timestamp=time.time()
            )
            pattern_match = self.pattern_recognizer.analyze_workload_pattern(temp_pattern) if self.enable_pattern_recognition else None
            
            scaling_prediction = self.predictive_scaling_engine.predict_scaling_decision(
                current_metrics=current_metrics,
                metrics_history=list(self.metrics_history),
                current_threads=self.current_threads,
                pattern_match=pattern_match
            )
            
            recommendation['predictive_scaling'] = {
                'final_decision': scaling_prediction.final_decision.to_dict(),
                'reactive_decision': scaling_prediction.reactive_decision.to_dict(),
                'trend_based_decision': scaling_prediction.trend_based_decision.to_dict(),
                'pattern_based_decision': scaling_prediction.pattern_based_decision.to_dict() if scaling_prediction.pattern_based_decision else None,
                'ml_based_decision': scaling_prediction.ml_based_decision.to_dict() if scaling_prediction.ml_based_decision else None,
                'consensus_confidence': scaling_prediction.consensus_confidence,
                'risk_factors': scaling_prediction.risk_factors,
                'workload_forecast': scaling_prediction.workload_forecast
            }
        
        # Combined recommendation (predictive scaling takes highest priority if available)
        if (self.enable_predictive_scaling and 'predictive_scaling' in recommendation and 
            recommendation['predictive_scaling']['consensus_confidence'] > 0.7):
            final_decision = recommendation['predictive_scaling']['final_decision']
            recommendation['final_recommendation'] = final_decision['direction']
            recommendation['final_threads'] = final_decision['target_threads']
            recommendation['reasoning'] = f"predictive_scaling_high_confidence_{final_decision['confidence']:.2f}"
        elif (self.enable_pattern_recognition and 'pattern_based' in recommendation and 
              recommendation['pattern_based']['matched_pattern'] and 
              recommendation['pattern_based']['matched_pattern']['confidence'] > 0.7):
            recommendation['final_recommendation'] = recommendation['pattern_based']['recommendation']
            recommendation['final_threads'] = recommendation['pattern_based']['recommended_threads']
            recommendation['reasoning'] = 'pattern_based_high_confidence'
        elif self.enable_predictive and recommendation.get('predictive', {}).get('confidence', 0) > 0.5:
            recommendation['final_recommendation'] = recommendation['predictive']['recommendation']
            recommendation['final_threads'] = recommendation['predictive']['predicted_threads']
            recommendation['reasoning'] = 'predictive_sufficient_confidence'
        elif (self.enable_predictive_scaling and 'predictive_scaling' in recommendation and 
              recommendation['predictive_scaling']['consensus_confidence'] > 0.4):
            final_decision = recommendation['predictive_scaling']['final_decision']
            recommendation['final_recommendation'] = final_decision['direction']
            recommendation['final_threads'] = final_decision['target_threads']
            recommendation['reasoning'] = f"predictive_scaling_medium_confidence_{final_decision['confidence']:.2f}"
        else:
            recommendation['final_recommendation'] = 'maintain'
            recommendation['final_threads'] = self.current_threads
            recommendation['reasoning'] = 'insufficient_confidence'
        
        return recommendation


class TaskFuture:
    """Wrapper around Future with task tracking"""
    
    def __init__(self, future, task_id: str, manager: DynamicThreadPoolManager):
        self.future = future
        self.task_id = task_id
        self.manager = manager
    
    def result(self, timeout=None):
        """Get result and mark task as completed"""
        try:
            result = self.future.result(timeout)
            self.manager._task_completed(self.task_id, True)
            return result
        except Exception as e:
            self.manager._task_completed(self.task_id, False)
            raise
    
    def done(self):
        """Check if task is done"""
        return self.future.done()
    
    def cancel(self):
        """Cancel the task"""
        cancelled = self.future.cancel()
        if cancelled:
            self.manager._task_completed(self.task_id, False)
        return cancelled


class AdaptiveBatchValidator:
    """Enhanced batch validator using dynamic thread pool"""
    
    def __init__(self, validation_config: Optional[ValidationConfig] = None,
                 thread_config: Optional[ThreadPoolConfig] = None,
                 predictive_config: Optional[PredictiveConfig] = None,
                 pattern_recognition_config: Optional[PatternRecognitionConfig] = None):
        self.validation_config = validation_config or ValidationConfig()
        self.thread_manager = DynamicThreadPoolManager(thread_config, predictive_config, pattern_recognition_config)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def validate_batch(self, proxies: List[ProxyInfo], 
                      progress_callback: Optional[Callable] = None) -> 'AdaptiveBatchResult':
        """Validate batch with adaptive threading"""
        
        if not proxies:
            return AdaptiveBatchResult(total_proxies=0, results=[])
        
        self.logger.info(f"Starting adaptive batch validation of {len(proxies)} proxies")
        
        # Analyze workload type
        workload_type = self._analyze_workload_type(proxies)
        
        # Start thread manager
        self.thread_manager.start()
        
        # Set workload information for predictive management
        self.thread_manager.set_workload_info(len(proxies), workload_type)
        
        try:
            return self._execute_batch(proxies, progress_callback)
        finally:
            # Complete workload for learning
            self.thread_manager.complete_workload()
            self.thread_manager.stop()
    
    def _analyze_workload_type(self, proxies: List[ProxyInfo]) -> str:
        """Analyze the workload type based on proxy protocols"""
        if not proxies:
            return "mixed"
        
        # Count protocol types
        http_count = sum(1 for p in proxies if p.protocol.value in ['http', 'https'])
        socks_count = sum(1 for p in proxies if p.protocol.value in ['socks4', 'socks5'])
        
        # Determine dominant type
        if http_count > socks_count * 2:
            return "http"
        elif socks_count > http_count * 2:
            return "socks"
        else:
            return "mixed"
    
    def _execute_batch(self, proxies: List[ProxyInfo], 
                      progress_callback: Optional[Callable]) -> 'AdaptiveBatchResult':
        """Execute batch validation with dynamic threading"""
        
        from ..validation.sync_validators import SyncProxyValidator
        
        start_time = time.time()
        results = []
        completed = 0
        
        # Submit all validation tasks
        task_futures = []
        for proxy in proxies:
            validator = SyncProxyValidator(self.validation_config)
            future = self.thread_manager.submit_task(validator.validate_proxy, proxy)
            task_futures.append((future, proxy))
        
        # Process completed tasks
        for future, proxy in task_futures:
            try:
                result = future.result()
                results.append(result)
                completed += 1
                
                # Progress callback
                if progress_callback:
                    progress_callback(completed, len(proxies), result)
                
            except Exception as e:
                self.logger.error(f"Validation failed for {proxy.address}: {e}")
                # Create error result
                from ..validation.validation_results import ValidationResult
                from ..validation.validation_config import FailureReason
                
                error_result = ValidationResult(proxy=proxy)
                error_result.failure_reason = FailureReason.UNKNOWN_ERROR
                error_result.error_message = str(e)
                results.append(error_result)
                completed += 1
        
        total_time = time.time() - start_time
        
        # Create result with performance stats
        batch_result = AdaptiveBatchResult(
            total_proxies=len(proxies),
            results=results,
            total_time=total_time,
            performance_stats=self.thread_manager.get_performance_stats()
        )
        
        batch_result.calculate_statistics()
        
        # Log results
        self.logger.info(f"Adaptive validation completed: {batch_result.valid_proxies}/{len(results)} valid "
                        f"({batch_result.success_rate:.1f}%) in {total_time:.1f}s "
                        f"(avg {batch_result.performance_stats['current_threads']} threads)")
        
        return batch_result


@dataclass
class AdaptiveBatchResult:
    """Results from adaptive batch validation"""
    total_proxies: int
    results: List[ValidationResult]
    total_time: float = 0.0
    performance_stats: Optional[Dict[str, Any]] = None
    
    # Calculated statistics
    valid_proxies: int = 0
    invalid_proxies: int = 0
    success_rate: float = 0.0
    average_response_time: float = 0.0
    throughput: float = 0.0
    
    def calculate_statistics(self):
        """Calculate batch statistics"""
        self.valid_proxies = sum(1 for r in self.results if r.is_valid)
        self.invalid_proxies = len(self.results) - self.valid_proxies
        self.success_rate = (self.valid_proxies / len(self.results)) * 100 if self.results else 0.0
        
        # Calculate average response time for valid results
        valid_times = [r.response_time for r in self.results if r.response_time and r.is_valid]
        self.average_response_time = sum(valid_times) / len(valid_times) if valid_times else 0.0
        
        # Calculate throughput
        self.throughput = len(self.results) / self.total_time if self.total_time > 0 else 0.0


# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def create_adaptive_validator(validation_config: Optional[ValidationConfig] = None,
                            thread_config: Optional[ThreadPoolConfig] = None,
                            predictive_config: Optional[PredictiveConfig] = None,
                            pattern_recognition_config: Optional[PatternRecognitionConfig] = None) -> AdaptiveBatchValidator:
    """Create adaptive batch validator with dynamic threading, predictive load management, and pattern recognition"""
    return AdaptiveBatchValidator(validation_config, thread_config, predictive_config, pattern_recognition_config)


def create_predictive_thread_manager(thread_config: Optional[ThreadPoolConfig] = None,
                                    predictive_config: Optional[PredictiveConfig] = None,
                                    pattern_recognition_config: Optional[PatternRecognitionConfig] = None) -> DynamicThreadPoolManager:
    """Create thread manager with predictive load management and pattern recognition"""
    return DynamicThreadPoolManager(thread_config, predictive_config, pattern_recognition_config)


def get_optimal_thread_config(proxy_count: int) -> ThreadPoolConfig:
    """Get optimal thread configuration based on proxy count and system resources"""
    
    # Get system info
    cpu_count = psutil.cpu_count()
    memory_gb = psutil.virtual_memory().total / (1024**3)
    
    # Calculate optimal settings based on system and workload
    if proxy_count <= 50:
        # Small batches - conservative threading
        config = ThreadPoolConfig(
            min_threads=2,
            max_threads=min(10, cpu_count * 2),
            initial_threads=5,
            scale_factor=1.5
        )
    elif proxy_count <= 500:
        # Medium batches - moderate threading
        config = ThreadPoolConfig(
            min_threads=5,
            max_threads=min(50, cpu_count * 4),
            initial_threads=15,
            scale_factor=1.3
        )
    else:
        # Large batches - aggressive threading
        config = ThreadPoolConfig(
            min_threads=10,
            max_threads=min(100, cpu_count * 6),
            initial_threads=25,
            scale_factor=1.2
        )
    
    # Adjust based on available memory
    if memory_gb < 4:
        # Low memory - reduce thread counts
        config.max_threads = min(config.max_threads, 20)
        config.initial_threads = min(config.initial_threads, 10)
    elif memory_gb > 16:
        # High memory - allow more threads
        config.max_threads = min(config.max_threads * 2, 200)
    
    return config