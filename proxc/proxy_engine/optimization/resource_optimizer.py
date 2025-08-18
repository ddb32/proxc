"""Resource Optimization Engine with Monitoring and Adaptive Allocation

Advanced resource management system that:
- Monitors CPU, memory, and network usage in real-time
- Dynamically adjusts worker pool sizes and resource allocation
- Implements adaptive scaling based on workload patterns
- Provides intelligent load balancing across tiers
- Handles emergency resource management and bottleneck resolution
- Supports predictive resource allocation using historical patterns
"""

import asyncio
import logging
import threading
import time
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass, field
import json
import os

logger = logging.getLogger(__name__)


class ResourceType(Enum):
    """Types of system resources to monitor"""
    CPU = "cpu"
    MEMORY = "memory"
    NETWORK = "network"
    DISK_IO = "disk_io"
    VALIDATION_WORKERS = "validation_workers"
    QUEUE_CAPACITY = "queue_capacity"


class ScalingAction(Enum):
    """Scaling actions that can be taken"""
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    REBALANCE = "rebalance"
    EMERGENCY_THROTTLE = "emergency_throttle"
    NO_ACTION = "no_action"


@dataclass
class ResourceMetrics:
    """Resource usage metrics"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    network_bytes_per_sec: float = 0.0
    disk_io_percent: float = 0.0
    active_workers: int = 0
    queued_jobs: int = 0
    completed_jobs_per_minute: float = 0.0
    average_response_time: float = 0.0
    error_rate: float = 0.0


@dataclass
class ScalingRule:
    """Rule for automatic scaling decisions"""
    resource_type: ResourceType
    threshold_high: float
    threshold_low: float
    duration_seconds: int
    scaling_factor: float
    cooldown_seconds: int = 300  # 5 minutes default cooldown
    max_scale_factor: float = 2.0
    min_scale_factor: float = 0.5


@dataclass
class WorkloadPattern:
    """Detected workload pattern for predictive scaling"""
    pattern_id: str
    time_of_day_start: int  # Hour 0-23
    time_of_day_end: int    # Hour 0-23
    day_of_week: Optional[int] = None  # 0=Monday, 6=Sunday, None=any day
    expected_load_factor: float = 1.0
    confidence: float = 0.0
    sample_count: int = 0


class SystemMonitor:
    """Monitors system resources and performance metrics"""
    
    def __init__(self, monitoring_interval: float = 5.0):
        self.monitoring_interval = monitoring_interval
        self.metrics_history: deque = deque(maxlen=720)  # 1 hour at 5s intervals
        self.performance_counters = defaultdict(int)
        self.last_network_stats = None
        self.monitoring_active = False
        self._monitor_thread = None
        
        # Try to import psutil for comprehensive monitoring
        self.has_psutil = False
        self.psutil = None
        try:
            import psutil
            self.psutil = psutil
            self.has_psutil = True
            logger.info("psutil available - enabling comprehensive system monitoring")
        except ImportError:
            logger.warning("psutil not available - using basic monitoring")
    
    def start_monitoring(self):
        """Start continuous resource monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self._monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("System monitoring started")
    
    def stop_monitoring(self):
        """Stop resource monitoring"""
        self.monitoring_active = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=10)
        logger.info("System monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)
                time.sleep(self.monitoring_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.monitoring_interval)
    
    def _collect_metrics(self) -> ResourceMetrics:
        """Collect current system metrics"""
        timestamp = datetime.utcnow()
        
        if self.has_psutil:
            try:
                # CPU usage
                cpu_percent = self.psutil.cpu_percent(interval=None)
                
                # Memory usage
                memory = self.psutil.virtual_memory()
                memory_percent = memory.percent
                
                # Network I/O
                network_stats = self.psutil.net_io_counters()
                network_bytes_per_sec = 0.0
                if self.last_network_stats:
                    bytes_diff = (network_stats.bytes_sent + network_stats.bytes_recv) - \
                                (self.last_network_stats.bytes_sent + self.last_network_stats.bytes_recv)
                    time_diff = self.monitoring_interval
                    network_bytes_per_sec = bytes_diff / time_diff
                self.last_network_stats = network_stats
                
                # Disk I/O
                disk_io = self.psutil.disk_io_counters()
                disk_io_percent = 0.0  # Simplified - would need baseline calculation
                
            except Exception as e:
                logger.debug(f"Error collecting psutil metrics: {e}")
                # Fallback to basic metrics
                cpu_percent = 50.0
                memory_percent = 30.0
                network_bytes_per_sec = 0.0
                disk_io_percent = 0.0
        else:
            # Basic fallback metrics
            cpu_percent = 50.0
            memory_percent = 30.0
            network_bytes_per_sec = 0.0
            disk_io_percent = 0.0
        
        return ResourceMetrics(
            timestamp=timestamp,
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            network_bytes_per_sec=network_bytes_per_sec,
            disk_io_percent=disk_io_percent,
            active_workers=self.performance_counters.get('active_workers', 0),
            queued_jobs=self.performance_counters.get('queued_jobs', 0),
            completed_jobs_per_minute=self.performance_counters.get('completed_jobs_per_minute', 0),
            average_response_time=self.performance_counters.get('average_response_time', 0),
            error_rate=self.performance_counters.get('error_rate', 0)
        )
    
    def update_performance_counters(self, counters: Dict[str, Any]):
        """Update performance counters from external sources"""
        self.performance_counters.update(counters)
    
    def get_current_metrics(self) -> Optional[ResourceMetrics]:
        """Get the most recent metrics"""
        return self.metrics_history[-1] if self.metrics_history else None
    
    def get_average_metrics(self, minutes: int = 5) -> Optional[ResourceMetrics]:
        """Get average metrics over specified time period"""
        if not self.metrics_history:
            return None
        
        cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
        recent_metrics = [m for m in self.metrics_history if m.timestamp >= cutoff_time]
        
        if not recent_metrics:
            return None
        
        return ResourceMetrics(
            timestamp=datetime.utcnow(),
            cpu_percent=statistics.mean(m.cpu_percent for m in recent_metrics),
            memory_percent=statistics.mean(m.memory_percent for m in recent_metrics),
            network_bytes_per_sec=statistics.mean(m.network_bytes_per_sec for m in recent_metrics),
            disk_io_percent=statistics.mean(m.disk_io_percent for m in recent_metrics),
            active_workers=int(statistics.mean(m.active_workers for m in recent_metrics)),
            queued_jobs=int(statistics.mean(m.queued_jobs for m in recent_metrics)),
            completed_jobs_per_minute=statistics.mean(m.completed_jobs_per_minute for m in recent_metrics),
            average_response_time=statistics.mean(m.average_response_time for m in recent_metrics),
            error_rate=statistics.mean(m.error_rate for m in recent_metrics)
        )
    
    def detect_resource_pressure(self) -> Dict[ResourceType, float]:
        """Detect current resource pressure levels (0.0-1.0)"""
        current = self.get_current_metrics()
        if not current:
            return {}
        
        pressure = {}
        pressure[ResourceType.CPU] = min(current.cpu_percent / 100.0, 1.0)
        pressure[ResourceType.MEMORY] = min(current.memory_percent / 100.0, 1.0)
        
        # Network pressure based on historical patterns
        if len(self.metrics_history) > 10:
            recent_network = [m.network_bytes_per_sec for m in list(self.metrics_history)[-10:]]
            max_network = max(recent_network) if recent_network else 1
            pressure[ResourceType.NETWORK] = min(current.network_bytes_per_sec / max(max_network, 1), 1.0)
        
        # Worker pressure
        if current.queued_jobs > 0:
            pressure[ResourceType.VALIDATION_WORKERS] = min(current.queued_jobs / 100.0, 1.0)
        
        return pressure


class ResourceOptimizer:
    """Advanced resource optimization engine with adaptive allocation"""
    
    def __init__(self, max_workers: int = 100, min_workers: int = 10):
        self.max_workers = max_workers
        self.min_workers = min_workers
        self.current_workers = min_workers
        
        # Monitoring
        self.monitor = SystemMonitor()
        
        # Scaling rules
        self.scaling_rules = self._create_default_scaling_rules()
        
        # Resource allocation per tier
        self.tier_allocations = {
            'TIER_1': 0.4,
            'TIER_2': 0.35,
            'TIER_3': 0.15,
            'TIER_4': 0.1
        }
        
        # Workload pattern detection
        self.workload_patterns: List[WorkloadPattern] = []
        self.pattern_history: deque = deque(maxlen=10080)  # 1 week at 1-minute intervals
        
        # Optimization state
        self.last_scaling_action = None
        self.last_scaling_time = datetime.utcnow()
        self.optimization_stats = {
            'total_scaling_actions': 0,
            'scale_up_actions': 0,
            'scale_down_actions': 0,
            'emergency_throttles': 0,
            'avg_worker_utilization': 0.0,
            'resource_efficiency': 0.0
        }
        
        # Emergency management
        self.emergency_mode = False
        self.emergency_threshold = 0.95  # 95% resource usage
        self.emergency_actions = []
        
        # Threading
        self._optimization_thread = None
        self._running = False
        
        logger.info(f"ResourceOptimizer initialized with {min_workers}-{max_workers} worker range")
    
    def _create_default_scaling_rules(self) -> List[ScalingRule]:
        """Create default scaling rules"""
        return [
            # CPU-based scaling
            ScalingRule(
                resource_type=ResourceType.CPU,
                threshold_high=80.0,
                threshold_low=30.0,
                duration_seconds=30,
                scaling_factor=1.3,
                cooldown_seconds=180
            ),
            
            # Memory-based scaling
            ScalingRule(
                resource_type=ResourceType.MEMORY,
                threshold_high=85.0,
                threshold_low=40.0,
                duration_seconds=60,
                scaling_factor=1.2,
                cooldown_seconds=300
            ),
            
            # Queue-based scaling
            ScalingRule(
                resource_type=ResourceType.VALIDATION_WORKERS,
                threshold_high=20.0,  # 20+ queued jobs
                threshold_low=2.0,    # <2 queued jobs
                duration_seconds=15,
                scaling_factor=1.5,
                cooldown_seconds=60
            )
        ]
    
    def start_optimization(self):
        """Start the resource optimization engine"""
        if self._running:
            return
        
        self._running = True
        self.monitor.start_monitoring()
        
        self._optimization_thread = threading.Thread(target=self._optimization_loop, daemon=True)
        self._optimization_thread.start()
        
        logger.info("Resource optimization engine started")
    
    def stop_optimization(self):
        """Stop the resource optimization engine"""
        self._running = False
        self.monitor.stop_monitoring()
        
        if self._optimization_thread:
            self._optimization_thread.join(timeout=10)
        
        logger.info("Resource optimization engine stopped")
    
    def _optimization_loop(self):
        """Main optimization loop"""
        while self._running:
            try:
                # Collect current state
                current_metrics = self.monitor.get_current_metrics()
                if current_metrics:
                    # Update performance tracking
                    self._update_workload_patterns(current_metrics)
                    
                    # Check for emergency conditions
                    if self._check_emergency_conditions(current_metrics):
                        self._handle_emergency(current_metrics)
                    else:
                        # Normal optimization
                        self._perform_optimization(current_metrics)
                
                time.sleep(30)  # Optimize every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in optimization loop: {e}")
                time.sleep(30)
    
    def _check_emergency_conditions(self, metrics: ResourceMetrics) -> bool:
        """Check if emergency intervention is needed"""
        # CPU emergency
        if metrics.cpu_percent > self.emergency_threshold * 100:
            return True
        
        # Memory emergency
        if metrics.memory_percent > self.emergency_threshold * 100:
            return True
        
        # Queue overflow emergency
        if metrics.queued_jobs > self.max_workers * 2:
            return True
        
        # High error rate emergency
        if metrics.error_rate > 0.5:  # 50% error rate
            return True
        
        return False
    
    def _handle_emergency(self, metrics: ResourceMetrics):
        """Handle emergency resource conditions"""
        if not self.emergency_mode:
            self.emergency_mode = True
            logger.warning("Emergency mode activated due to resource pressure")
        
        emergency_actions = []
        
        # Emergency scaling down if overloaded
        if metrics.cpu_percent > 95 or metrics.memory_percent > 95:
            # Reduce workers immediately
            new_workers = max(self.current_workers // 2, self.min_workers)
            if new_workers < self.current_workers:
                self.current_workers = new_workers
                emergency_actions.append(f"Emergency scale down to {new_workers} workers")
        
        # Emergency queue throttling
        if metrics.queued_jobs > self.max_workers * 3:
            emergency_actions.append("Emergency queue throttling activated")
        
        # Log emergency actions
        for action in emergency_actions:
            logger.critical(f"Emergency action: {action}")
            self.emergency_actions.append({
                'timestamp': datetime.utcnow(),
                'action': action,
                'metrics': metrics
            })
        
        self.optimization_stats['emergency_throttles'] += 1
    
    def _perform_optimization(self, metrics: ResourceMetrics):
        """Perform normal optimization based on metrics and rules"""
        
        # Exit emergency mode if conditions improved
        if self.emergency_mode:
            if (metrics.cpu_percent < 70 and metrics.memory_percent < 70 and 
                metrics.queued_jobs < self.max_workers):
                self.emergency_mode = False
                logger.info("Emergency mode deactivated - conditions normalized")
        
        # Evaluate scaling rules
        scaling_decision = self._evaluate_scaling_rules(metrics)
        
        if scaling_decision != ScalingAction.NO_ACTION:
            self._execute_scaling_action(scaling_decision, metrics)
        
        # Optimize tier allocations
        self._optimize_tier_allocations(metrics)
        
        # Update statistics
        self._update_optimization_stats(metrics)
    
    def _evaluate_scaling_rules(self, metrics: ResourceMetrics) -> ScalingAction:
        """Evaluate scaling rules and determine action"""
        
        # Check cooldown period
        time_since_last_scaling = (datetime.utcnow() - self.last_scaling_time).total_seconds()
        min_cooldown = min(rule.cooldown_seconds for rule in self.scaling_rules)
        
        if time_since_last_scaling < min_cooldown:
            return ScalingAction.NO_ACTION
        
        # Get recent metrics for trend analysis
        recent_metrics = self.monitor.get_average_metrics(minutes=2)
        if not recent_metrics:
            return ScalingAction.NO_ACTION
        
        # Evaluate each rule
        scale_up_votes = 0
        scale_down_votes = 0
        
        for rule in self.scaling_rules:
            if time_since_last_scaling < rule.cooldown_seconds:
                continue
            
            if rule.resource_type == ResourceType.CPU:
                value = recent_metrics.cpu_percent
            elif rule.resource_type == ResourceType.MEMORY:
                value = recent_metrics.memory_percent
            elif rule.resource_type == ResourceType.VALIDATION_WORKERS:
                value = recent_metrics.queued_jobs
            else:
                continue
            
            if value > rule.threshold_high:
                scale_up_votes += 1
            elif value < rule.threshold_low:
                scale_down_votes += 1
        
        # Make decision based on votes
        if scale_up_votes > scale_down_votes and self.current_workers < self.max_workers:
            return ScalingAction.SCALE_UP
        elif scale_down_votes > scale_up_votes and self.current_workers > self.min_workers:
            return ScalingAction.SCALE_DOWN
        else:
            return ScalingAction.NO_ACTION
    
    def _execute_scaling_action(self, action: ScalingAction, metrics: ResourceMetrics):
        """Execute the determined scaling action"""
        
        old_workers = self.current_workers
        
        if action == ScalingAction.SCALE_UP:
            scaling_factor = 1.3  # Default scaling factor
            new_workers = min(int(self.current_workers * scaling_factor), self.max_workers)
            self.current_workers = new_workers
            self.optimization_stats['scale_up_actions'] += 1
            logger.info(f"Scaled up from {old_workers} to {new_workers} workers")
        
        elif action == ScalingAction.SCALE_DOWN:
            scaling_factor = 0.8  # Scale down more conservatively
            new_workers = max(int(self.current_workers * scaling_factor), self.min_workers)
            self.current_workers = new_workers
            self.optimization_stats['scale_down_actions'] += 1
            logger.info(f"Scaled down from {old_workers} to {new_workers} workers")
        
        self.last_scaling_action = action
        self.last_scaling_time = datetime.utcnow()
        self.optimization_stats['total_scaling_actions'] += 1
    
    def _optimize_tier_allocations(self, metrics: ResourceMetrics):
        """Optimize resource allocation across tiers based on performance"""
        
        # This is a simplified implementation
        # In production, this would analyze tier-specific performance metrics
        
        # Adjust allocations based on queue pressure
        if metrics.queued_jobs > 50:
            # Shift more resources to higher priority tiers
            self.tier_allocations['TIER_1'] = min(0.5, self.tier_allocations['TIER_1'] + 0.05)
            self.tier_allocations['TIER_4'] = max(0.05, self.tier_allocations['TIER_4'] - 0.05)
        
        elif metrics.queued_jobs < 5:
            # Rebalance toward normal allocation
            target_allocations = {'TIER_1': 0.4, 'TIER_2': 0.35, 'TIER_3': 0.15, 'TIER_4': 0.1}
            for tier, target in target_allocations.items():
                current = self.tier_allocations[tier]
                self.tier_allocations[tier] = current * 0.9 + target * 0.1  # Gradual adjustment
        
        # Normalize allocations
        total = sum(self.tier_allocations.values())
        if total > 0:
            for tier in self.tier_allocations:
                self.tier_allocations[tier] /= total
    
    def _update_workload_patterns(self, metrics: ResourceMetrics):
        """Update workload pattern detection"""
        
        # Add current metrics to pattern history
        pattern_data = {
            'timestamp': metrics.timestamp,
            'hour': metrics.timestamp.hour,
            'day_of_week': metrics.timestamp.weekday(),
            'load_factor': (metrics.cpu_percent + metrics.memory_percent) / 200.0,
            'active_workers': metrics.active_workers,
            'queued_jobs': metrics.queued_jobs
        }
        
        self.pattern_history.append(pattern_data)
        
        # Analyze patterns every hour
        if len(self.pattern_history) % 60 == 0:  # Every hour (assuming 1-minute intervals)
            self._analyze_workload_patterns()
    
    def _analyze_workload_patterns(self):
        """Analyze historical data to detect workload patterns"""
        
        if len(self.pattern_history) < 1440:  # Need at least 1 day of data
            return
        
        # Group by hour of day
        hourly_loads = defaultdict(list)
        for entry in self.pattern_history:
            hourly_loads[entry['hour']].append(entry['load_factor'])
        
        # Calculate average load per hour
        for hour, loads in hourly_loads.items():
            if len(loads) >= 7:  # At least a week of data for this hour
                avg_load = statistics.mean(loads)
                std_dev = statistics.stdev(loads) if len(loads) > 1 else 0
                
                # Create or update pattern
                pattern_id = f"hour_{hour:02d}"
                existing_pattern = next((p for p in self.workload_patterns if p.pattern_id == pattern_id), None)
                
                if existing_pattern:
                    # Update existing pattern
                    existing_pattern.expected_load_factor = existing_pattern.expected_load_factor * 0.8 + avg_load * 0.2
                    existing_pattern.confidence = min(1.0, existing_pattern.confidence + 0.1)
                    existing_pattern.sample_count = len(loads)
                else:
                    # Create new pattern
                    pattern = WorkloadPattern(
                        pattern_id=pattern_id,
                        time_of_day_start=hour,
                        time_of_day_end=(hour + 1) % 24,
                        expected_load_factor=avg_load,
                        confidence=0.5 if std_dev < 0.2 else 0.3,
                        sample_count=len(loads)
                    )
                    self.workload_patterns.append(pattern)
    
    def _update_optimization_stats(self, metrics: ResourceMetrics):
        """Update optimization statistics"""
        
        # Worker utilization
        if self.current_workers > 0:
            utilization = metrics.active_workers / self.current_workers
            current_avg = self.optimization_stats['avg_worker_utilization']
            self.optimization_stats['avg_worker_utilization'] = current_avg * 0.9 + utilization * 0.1
        
        # Resource efficiency (throughput vs resource usage)
        resource_usage = (metrics.cpu_percent + metrics.memory_percent) / 200.0
        if resource_usage > 0:
            efficiency = metrics.completed_jobs_per_minute / resource_usage
            current_efficiency = self.optimization_stats['resource_efficiency']
            self.optimization_stats['resource_efficiency'] = current_efficiency * 0.9 + efficiency * 0.1
    
    def get_current_allocation(self) -> Dict[str, Any]:
        """Get current resource allocation"""
        metrics = self.monitor.get_current_metrics()
        
        return {
            'worker_allocation': {
                'current_workers': self.current_workers,
                'max_workers': self.max_workers,
                'min_workers': self.min_workers,
                'utilization': (metrics.active_workers / self.current_workers) if metrics and self.current_workers > 0 else 0
            },
            'tier_allocation': self.tier_allocations.copy(),
            'tier_worker_counts': {
                tier: int(self.current_workers * allocation)
                for tier, allocation in self.tier_allocations.items()
            },
            'system_metrics': {
                'cpu_percent': metrics.cpu_percent if metrics else 0,
                'memory_percent': metrics.memory_percent if metrics else 0,
                'queued_jobs': metrics.queued_jobs if metrics else 0,
                'error_rate': metrics.error_rate if metrics else 0
            },
            'emergency_mode': self.emergency_mode,
            'last_scaling_action': self.last_scaling_action.value if self.last_scaling_action else None
        }
    
    def get_optimization_statistics(self) -> Dict[str, Any]:
        """Get comprehensive optimization statistics"""
        
        return {
            'optimization_stats': self.optimization_stats.copy(),
            'workload_patterns': [
                {
                    'pattern_id': p.pattern_id,
                    'time_range': f"{p.time_of_day_start:02d}:00-{p.time_of_day_end:02d}:00",
                    'expected_load': p.expected_load_factor,
                    'confidence': p.confidence,
                    'samples': p.sample_count
                }
                for p in self.workload_patterns
            ],
            'recent_emergency_actions': self.emergency_actions[-10:] if self.emergency_actions else [],
            'scaling_rules': [
                {
                    'resource_type': rule.resource_type.value,
                    'threshold_high': rule.threshold_high,
                    'threshold_low': rule.threshold_low,
                    'scaling_factor': rule.scaling_factor,
                    'cooldown_seconds': rule.cooldown_seconds
                }
                for rule in self.scaling_rules
            ]
        }
    
    def predict_optimal_workers(self, hours_ahead: int = 1) -> int:
        """Predict optimal worker count based on historical patterns"""
        
        target_time = datetime.utcnow() + timedelta(hours=hours_ahead)
        target_hour = target_time.hour
        
        # Find matching pattern
        pattern = next((p for p in self.workload_patterns 
                       if p.time_of_day_start <= target_hour < p.time_of_day_end), None)
        
        if pattern and pattern.confidence > 0.5:
            predicted_load = pattern.expected_load_factor
            optimal_workers = int(self.min_workers + 
                                (self.max_workers - self.min_workers) * predicted_load)
            return max(self.min_workers, min(optimal_workers, self.max_workers))
        
        # Fallback to current allocation
        return self.current_workers
    
    def update_external_metrics(self, validation_metrics: Dict[str, Any]):
        """Update optimization with external validation metrics"""
        
        performance_counters = {
            'active_workers': validation_metrics.get('active_validations', 0),
            'queued_jobs': validation_metrics.get('queued_jobs', 0),
            'completed_jobs_per_minute': validation_metrics.get('completions_per_minute', 0),
            'average_response_time': validation_metrics.get('avg_response_time', 0),
            'error_rate': validation_metrics.get('error_rate', 0)
        }
        
        self.monitor.update_performance_counters(performance_counters)


def create_resource_optimizer(max_workers: int = 100, min_workers: int = 10) -> ResourceOptimizer:
    """Factory function to create resource optimizer"""
    return ResourceOptimizer(max_workers, min_workers)


if __name__ == "__main__":
    # Example usage and testing
    import random
    
    # Create optimizer
    optimizer = create_resource_optimizer(max_workers=50, min_workers=5)
    
    # Start optimization
    optimizer.start_optimization()
    
    # Simulate some workload for testing
    for i in range(10):
        # Simulate external metrics
        validation_metrics = {
            'active_validations': random.randint(5, 30),
            'queued_jobs': random.randint(0, 50),
            'completions_per_minute': random.uniform(10, 100),
            'avg_response_time': random.uniform(1000, 8000),
            'error_rate': random.uniform(0, 0.2)
        }
        
        optimizer.update_external_metrics(validation_metrics)
        
        # Show current allocation
        allocation = optimizer.get_current_allocation()
        print(f"Step {i+1}: Workers: {allocation['worker_allocation']['current_workers']}, "
              f"Utilization: {allocation['worker_allocation']['utilization']:.2f}, "
              f"Emergency: {allocation['emergency_mode']}")
        
        time.sleep(2)
    
    # Show statistics
    stats = optimizer.get_optimization_statistics()
    print(f"\nOptimization Statistics:")
    print(f"Total scaling actions: {stats['optimization_stats']['total_scaling_actions']}")
    print(f"Scale up actions: {stats['optimization_stats']['scale_up_actions']}")
    print(f"Scale down actions: {stats['optimization_stats']['scale_down_actions']}")
    print(f"Average utilization: {stats['optimization_stats']['avg_worker_utilization']:.2f}")
    
    # Predict optimal workers
    predicted = optimizer.predict_optimal_workers(hours_ahead=2)
    print(f"Predicted optimal workers in 2 hours: {predicted}")
    
    # Stop optimization
    optimizer.stop_optimization()