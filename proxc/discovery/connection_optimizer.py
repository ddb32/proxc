"""
Connection Optimizer for Geographic and Performance-Based Timeout Management
===========================================================================

Optimizes connection timeouts and retry strategies based on geographic location,
network conditions, and historical performance data.
"""

import asyncio
import json
import logging
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Union
from pathlib import Path

# Third-party imports with fallbacks
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Import our core models
from ..proxy_core.models import ProxyInfo

logger = logging.getLogger(__name__)


class GeographicRegion(Enum):
    """Geographic regions for optimization"""
    LOCAL = "local"                    # Same city/region
    NATIONAL = "national"              # Same country
    CONTINENTAL = "continental"        # Same continent
    INTERCONTINENTAL = "intercontinental"  # Different continent
    SATELLITE = "satellite"            # Satellite connection
    UNKNOWN = "unknown"               # Unable to determine


class ConnectionQuality(Enum):
    """Connection quality classifications"""
    EXCELLENT = "excellent"  # <100ms, >95% success
    GOOD = "good"           # <300ms, >80% success
    FAIR = "fair"           # <800ms, >60% success
    POOR = "poor"           # <2000ms, >30% success
    BAD = "bad"             # >2000ms or <30% success


@dataclass
class OptimizationResult:
    """Result of connection optimization calculation"""
    recommended_timeout: int
    retry_count: int
    delay_between_retries: float
    expected_success_rate: float
    quality_classification: ConnectionQuality
    confidence_score: float  # 0.0 to 1.0
    reasoning: str


@dataclass
class ConnectionMetrics:
    """Historical connection metrics for optimization"""
    ip: str
    port: int
    
    # Response time metrics
    response_times: List[float] = field(default_factory=list)
    avg_response_time: float = 0.0
    min_response_time: float = float('inf')
    max_response_time: float = 0.0
    
    # Success metrics
    total_attempts: int = 0
    successful_attempts: int = 0
    success_rate: float = 0.0
    
    # Temporal data
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_updated: datetime = field(default_factory=datetime.utcnow)
    
    # Geographic data
    estimated_region: GeographicRegion = GeographicRegion.UNKNOWN
    geographic_confidence: float = 0.0
    
    def update_metrics(self, response_time: float, success: bool):
        """Update metrics with new data point"""
        self.total_attempts += 1
        self.last_updated = datetime.utcnow()
        
        if success:
            self.successful_attempts += 1
            self.response_times.append(response_time)
            
            # Update response time stats
            self.avg_response_time = statistics.mean(self.response_times)
            self.min_response_time = min(self.min_response_time, response_time)
            self.max_response_time = max(self.max_response_time, response_time)
        
        # Update success rate
        self.success_rate = self.successful_attempts / self.total_attempts
    
    def get_quality_classification(self) -> ConnectionQuality:
        """Get connection quality classification"""
        if self.success_rate >= 0.95 and self.avg_response_time < 100:
            return ConnectionQuality.EXCELLENT
        elif self.success_rate >= 0.80 and self.avg_response_time < 300:
            return ConnectionQuality.GOOD
        elif self.success_rate >= 0.60 and self.avg_response_time < 800:
            return ConnectionQuality.FAIR
        elif self.success_rate >= 0.30 and self.avg_response_time < 2000:
            return ConnectionQuality.POOR
        else:
            return ConnectionQuality.BAD


class GeographicOptimizer:
    """Geographic-based connection optimization"""
    
    # Regional timeout multipliers and retry strategies
    REGIONAL_CONFIGS = {
        GeographicRegion.LOCAL: {
            'timeout_multiplier': 1.0,
            'base_timeout': 3,
            'max_retries': 2,
            'retry_delay': 0.5,
            'expected_success': 0.9
        },
        GeographicRegion.NATIONAL: {
            'timeout_multiplier': 1.2,
            'base_timeout': 5,
            'max_retries': 2,
            'retry_delay': 1.0,
            'expected_success': 0.8
        },
        GeographicRegion.CONTINENTAL: {
            'timeout_multiplier': 1.8,
            'base_timeout': 8,
            'max_retries': 3,
            'retry_delay': 1.5,
            'expected_success': 0.7
        },
        GeographicRegion.INTERCONTINENTAL: {
            'timeout_multiplier': 2.5,
            'base_timeout': 12,
            'max_retries': 3,
            'retry_delay': 2.0,
            'expected_success': 0.6
        },
        GeographicRegion.SATELLITE: {
            'timeout_multiplier': 4.0,
            'base_timeout': 20,
            'max_retries': 4,
            'retry_delay': 3.0,
            'expected_success': 0.4
        },
        GeographicRegion.UNKNOWN: {
            'timeout_multiplier': 2.0,
            'base_timeout': 10,
            'max_retries': 3,
            'retry_delay': 1.5,
            'expected_success': 0.6
        }
    }
    
    @classmethod
    def estimate_geographic_region(cls, target_ip: str, source_ip: str = None) -> Tuple[GeographicRegion, float]:
        """
        Estimate geographic region between source and target
        Returns (region, confidence_score)
        """
        # This is a simplified implementation
        # In production, would use GeoIP databases or latency measurements
        
        try:
            # Parse IP addresses to determine if they're in similar ranges
            target_parts = target_ip.split('.')
            if source_ip:
                source_parts = source_ip.split('.')
                
                # Simple heuristic based on IP prefix similarity
                if target_parts[0] == source_parts[0] and target_parts[1] == source_parts[1]:
                    return GeographicRegion.LOCAL, 0.7
                elif target_parts[0] == source_parts[0]:
                    return GeographicRegion.NATIONAL, 0.6
                else:
                    return GeographicRegion.CONTINENTAL, 0.4
            else:
                # No source IP - use conservative estimates
                return GeographicRegion.CONTINENTAL, 0.3
                
        except (ValueError, IndexError):
            return GeographicRegion.UNKNOWN, 0.1
    
    @classmethod
    def calculate_optimized_parameters(
        cls, 
        region: GeographicRegion, 
        base_timeout: int = 10,
        historical_data: Optional[ConnectionMetrics] = None
    ) -> OptimizationResult:
        """Calculate optimized connection parameters for region"""
        
        config = cls.REGIONAL_CONFIGS[region]
        
        # Calculate timeout
        if historical_data and historical_data.response_times:
            # Use historical data for optimization
            avg_time = historical_data.avg_response_time
            timeout = max(int(avg_time * 2.5), config['base_timeout'])
        else:
            # Use regional defaults
            timeout = max(int(base_timeout * config['timeout_multiplier']), config['base_timeout'])
        
        # Calculate retry parameters
        retry_count = config['max_retries']
        retry_delay = config['retry_delay']
        
        # Adjust based on historical success rate
        expected_success = config['expected_success']
        if historical_data:
            if historical_data.success_rate > 0:
                expected_success = min(historical_data.success_rate * 1.1, 1.0)
            
            # Reduce retries for consistently failing targets
            if historical_data.success_rate < 0.2:
                retry_count = max(1, retry_count - 1)
        
        # Calculate confidence score
        confidence = 0.8 if historical_data and historical_data.total_attempts > 10 else 0.5
        
        # Generate reasoning
        reasoning = f"Region: {region.value}, Base timeout: {base_timeout}ms"
        if historical_data:
            reasoning += f", Historical success: {historical_data.success_rate:.1%}"
        
        return OptimizationResult(
            recommended_timeout=timeout,
            retry_count=retry_count,
            delay_between_retries=retry_delay,
            expected_success_rate=expected_success,
            quality_classification=historical_data.get_quality_classification() if historical_data else ConnectionQuality.FAIR,
            confidence_score=confidence,
            reasoning=reasoning
        )


class TimeoutCalculator:
    """Dynamic timeout calculation based on various factors"""
    
    def __init__(self):
        self.performance_cache: Dict[str, List[float]] = {}  # IP -> response times
        self.failure_cache: Dict[str, int] = {}  # IP -> failure count
    
    def record_performance(self, ip: str, response_time: float, success: bool):
        """Record performance data for future optimization"""
        key = ip
        
        if success:
            if key not in self.performance_cache:
                self.performance_cache[key] = []
            
            self.performance_cache[key].append(response_time)
            
            # Keep only recent measurements (last 50)
            if len(self.performance_cache[key]) > 50:
                self.performance_cache[key] = self.performance_cache[key][-50:]
        else:
            self.failure_cache[key] = self.failure_cache.get(key, 0) + 1
    
    def calculate_timeout(
        self, 
        ip: str, 
        base_timeout: int = 10,
        percentile: float = 0.9
    ) -> int:
        """Calculate optimized timeout for specific IP"""
        key = ip
        
        # Check if we have historical data
        if key in self.performance_cache and len(self.performance_cache[key]) >= 3:
            times = self.performance_cache[key]
            
            # Use percentile-based timeout (e.g., 90th percentile + buffer)
            sorted_times = sorted(times)
            idx = int(len(sorted_times) * percentile)
            percentile_time = sorted_times[min(idx, len(sorted_times) - 1)]
            
            # Add buffer for network variation
            timeout = int(percentile_time * 1.5)
        else:
            # No historical data - use base timeout
            timeout = base_timeout
        
        # Adjust for failure rate
        if key in self.failure_cache:
            failure_count = self.failure_cache[key]
            if failure_count > 5:
                # Reduce timeout for consistently failing IPs
                timeout = max(timeout // 2, 2)
        
        return max(timeout, 1)  # Minimum 1 second
    
    def get_retry_strategy(self, ip: str) -> Tuple[int, float]:
        """Get retry count and delay for IP"""
        key = ip
        
        failure_count = self.failure_cache.get(key, 0)
        
        if failure_count < 2:
            return 3, 1.0  # 3 retries, 1s delay
        elif failure_count < 5:
            return 2, 2.0  # 2 retries, 2s delay
        else:
            return 1, 0.5  # 1 retry, 0.5s delay (fast fail)


class ConnectionOptimizer:
    """Main connection optimizer integrating all optimization strategies"""
    
    def __init__(self, cache_file: Optional[str] = None):
        self.geographic_optimizer = GeographicOptimizer()
        self.timeout_calculator = TimeoutCalculator()
        self.connection_metrics: Dict[str, ConnectionMetrics] = {}
        self.cache_file = Path(cache_file) if cache_file else None
        
        # Load cached data
        self._load_cache()
    
    def optimize_connection(
        self,
        target_ip: str,
        target_port: int,
        base_timeout: int = 10,
        source_ip: Optional[str] = None
    ) -> OptimizationResult:
        """Get optimized connection parameters for target"""
        
        # Create key for caching
        key = f"{target_ip}:{target_port}"
        
        # Get or create metrics
        metrics = self.connection_metrics.get(key)
        
        # Estimate geographic region
        region, geo_confidence = self.geographic_optimizer.estimate_geographic_region(
            target_ip, source_ip
        )
        
        # Calculate optimization
        result = self.geographic_optimizer.calculate_optimized_parameters(
            region, base_timeout, metrics
        )
        
        # Adjust with timeout calculator
        calculated_timeout = self.timeout_calculator.calculate_timeout(
            target_ip, base_timeout
        )
        
        # Use the more conservative timeout
        result.recommended_timeout = max(result.recommended_timeout, calculated_timeout)
        
        # Update confidence based on data availability
        if metrics and metrics.total_attempts > 5:
            result.confidence_score = min(result.confidence_score + 0.2, 1.0)
        
        return result
    
    def record_connection_result(
        self,
        target_ip: str,
        target_port: int,
        response_time: float,
        success: bool,
        region: GeographicRegion = GeographicRegion.UNKNOWN
    ):
        """Record connection result for future optimization"""
        
        key = f"{target_ip}:{target_port}"
        
        # Update or create metrics
        if key not in self.connection_metrics:
            self.connection_metrics[key] = ConnectionMetrics(
                ip=target_ip,
                port=target_port,
                estimated_region=region
            )
        
        self.connection_metrics[key].update_metrics(response_time, success)
        
        # Update timeout calculator
        self.timeout_calculator.record_performance(target_ip, response_time, success)
        
        # Save cache periodically
        if len(self.connection_metrics) % 100 == 0:
            self._save_cache()
    
    def get_optimization_summary(self) -> Dict[str, any]:
        """Get summary of optimization data"""
        if not self.connection_metrics:
            return {}
        
        total_connections = len(self.connection_metrics)
        avg_success_rate = statistics.mean([m.success_rate for m in self.connection_metrics.values()])
        avg_response_time = statistics.mean([m.avg_response_time for m in self.connection_metrics.values() if m.response_times])
        
        quality_counts = {}
        for metrics in self.connection_metrics.values():
            quality = metrics.get_quality_classification()
            quality_counts[quality.value] = quality_counts.get(quality.value, 0) + 1
        
        return {
            'total_connections_tracked': total_connections,
            'average_success_rate': avg_success_rate,
            'average_response_time': avg_response_time,
            'quality_distribution': quality_counts,
            'cache_file': str(self.cache_file) if self.cache_file else None
        }
    
    def _load_cache(self):
        """Load cached optimization data"""
        if not self.cache_file or not self.cache_file.exists():
            return
        
        try:
            with open(self.cache_file, 'r') as f:
                data = json.load(f)
            
            # Reconstruct metrics objects
            for key, metrics_data in data.get('connection_metrics', {}).items():
                ip, port = key.split(':')
                metrics = ConnectionMetrics(
                    ip=ip,
                    port=int(port),
                    response_times=metrics_data.get('response_times', []),
                    avg_response_time=metrics_data.get('avg_response_time', 0.0),
                    min_response_time=metrics_data.get('min_response_time', float('inf')),
                    max_response_time=metrics_data.get('max_response_time', 0.0),
                    total_attempts=metrics_data.get('total_attempts', 0),
                    successful_attempts=metrics_data.get('successful_attempts', 0),
                    success_rate=metrics_data.get('success_rate', 0.0),
                    first_seen=datetime.fromisoformat(metrics_data.get('first_seen', datetime.utcnow().isoformat())),
                    last_updated=datetime.fromisoformat(metrics_data.get('last_updated', datetime.utcnow().isoformat())),
                    estimated_region=GeographicRegion(metrics_data.get('estimated_region', 'unknown')),
                    geographic_confidence=metrics_data.get('geographic_confidence', 0.0)
                )
                self.connection_metrics[key] = metrics
            
            logger.info(f"Loaded {len(self.connection_metrics)} cached connection metrics")
            
        except Exception as e:
            logger.warning(f"Failed to load optimization cache: {e}")
    
    def _save_cache(self):
        """Save optimization data to cache"""
        if not self.cache_file:
            return
        
        try:
            # Prepare data for serialization
            cache_data = {
                'connection_metrics': {},
                'last_updated': datetime.utcnow().isoformat()
            }
            
            for key, metrics in self.connection_metrics.items():
                cache_data['connection_metrics'][key] = {
                    'response_times': metrics.response_times[-20:],  # Keep only recent data
                    'avg_response_time': metrics.avg_response_time,
                    'min_response_time': metrics.min_response_time if metrics.min_response_time != float('inf') else 0,
                    'max_response_time': metrics.max_response_time,
                    'total_attempts': metrics.total_attempts,
                    'successful_attempts': metrics.successful_attempts,
                    'success_rate': metrics.success_rate,
                    'first_seen': metrics.first_seen.isoformat(),
                    'last_updated': metrics.last_updated.isoformat(),
                    'estimated_region': metrics.estimated_region.value,
                    'geographic_confidence': metrics.geographic_confidence
                }
            
            # Ensure parent directory exists
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            logger.debug(f"Saved optimization cache with {len(self.connection_metrics)} entries")
            
        except Exception as e:
            logger.warning(f"Failed to save optimization cache: {e}")
    
    def cleanup_old_data(self, max_age_days: int = 30):
        """Remove old connection data to keep cache size manageable"""
        cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)
        
        keys_to_remove = [
            key for key, metrics in self.connection_metrics.items()
            if metrics.last_updated < cutoff_date
        ]
        
        for key in keys_to_remove:
            del self.connection_metrics[key]
        
        if keys_to_remove:
            logger.info(f"Cleaned up {len(keys_to_remove)} old connection entries")
            self._save_cache()


# Convenience functions
def create_connection_optimizer(cache_dir: Optional[str] = None) -> ConnectionOptimizer:
    """Create connection optimizer with optional cache directory"""
    cache_file = None
    if cache_dir:
        cache_file = Path(cache_dir) / "connection_optimization.json"
    
    return ConnectionOptimizer(cache_file)


def optimize_for_ip_list(
    ip_list: List[str],
    optimizer: ConnectionOptimizer,
    base_timeout: int = 10
) -> Dict[str, OptimizationResult]:
    """Batch optimize connection parameters for IP list"""
    results = {}
    
    for ip in ip_list:
        # Use common HTTP proxy port for optimization
        result = optimizer.optimize_connection(ip, 8080, base_timeout)
        results[ip] = result
    
    return results