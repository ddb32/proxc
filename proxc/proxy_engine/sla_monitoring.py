"""
SLA Monitoring and Adaptive Timeout System - Phase 3.3.2 & 3.3.4

Advanced SLA tracking with intelligent timeout adaptation based on
proxy performance history and real-time metrics.

Features:
- Multi-tier SLA definitions and monitoring
- Real-time SLA compliance tracking
- Adaptive timeout algorithms based on performance patterns
- Predictive timeout adjustment using historical data
- SLA breach detection and alerting
- Performance trend analysis for timeout optimization
"""

import asyncio
import json
import logging
import math
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Callable

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

from ..proxy_core.models import ProxyInfo, ProxyProtocol
from .advanced_validation_engine import ResponseTimeMetrics, ValidationHistory
from ..proxy_cli.cli_imports import log_structured, print_info, print_warning

logger = logging.getLogger(__name__)


class SLATier(Enum):
    """SLA tier definitions for different service levels"""
    PREMIUM = "premium"      # <100ms, 99.9% uptime
    BUSINESS = "business"    # <300ms, 99.5% uptime  
    STANDARD = "standard"    # <800ms, 99.0% uptime
    BASIC = "basic"         # <2000ms, 95.0% uptime


@dataclass
class SLADefinition:
    """SLA requirements and thresholds"""
    tier: SLATier
    max_response_time_ms: float
    min_uptime_percentage: float
    max_error_rate_percentage: float
    measurement_window_hours: int = 24
    
    @classmethod
    def get_default_slas(cls) -> Dict[SLATier, 'SLADefinition']:
        """Get default SLA definitions for all tiers"""
        return {
            SLATier.PREMIUM: cls(SLATier.PREMIUM, 100.0, 99.9, 0.1, 24),
            SLATier.BUSINESS: cls(SLATier.BUSINESS, 300.0, 99.5, 0.5, 24),
            SLATier.STANDARD: cls(SLATier.STANDARD, 800.0, 99.0, 1.0, 24),
            SLATier.BASIC: cls(SLATier.BASIC, 2000.0, 95.0, 5.0, 24)
        }


@dataclass
class SLACompliance:
    """SLA compliance status and metrics"""
    tier: SLATier
    is_compliant: bool
    compliance_percentage: float
    response_time_compliance: float
    uptime_compliance: float
    error_rate_compliance: float
    breach_count: int = 0
    last_breach: Optional[datetime] = None
    measurement_period: timedelta = field(default_factory=lambda: timedelta(hours=24))
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            **asdict(self),
            'tier': self.tier.value,
            'last_breach': self.last_breach.isoformat() if self.last_breach else None,
            'measurement_period': self.measurement_period.total_seconds()
        }


@dataclass
class TimeoutConfiguration:
    """Adaptive timeout configuration for proxy testing"""
    connect_timeout: float = 5.0
    read_timeout: float = 3.0
    total_timeout: float = 8.0
    
    # Adaptation parameters
    min_timeout: float = 1.0
    max_timeout: float = 30.0
    adaptation_factor: float = 0.1
    confidence_threshold: float = 0.8
    
    # Historical data requirements
    min_samples_for_adaptation: int = 10
    learning_rate: float = 0.05


class SLAMonitor:
    """
    Advanced SLA monitoring system with real-time compliance tracking
    """
    
    def __init__(self, sla_definitions: Dict[SLATier, SLADefinition] = None):
        self.sla_definitions = sla_definitions or SLADefinition.get_default_slas()
        
        # Compliance tracking
        self.compliance_history: Dict[str, Dict[SLATier, deque]] = defaultdict(
            lambda: {tier: deque(maxlen=1000) for tier in SLATier}
        )
        
        # Breach tracking
        self.breach_history: Dict[str, List[Tuple[SLATier, datetime, str]]] = defaultdict(list)
        
        # Real-time metrics
        self.current_compliance: Dict[str, Dict[SLATier, SLACompliance]] = defaultdict(dict)
        
        # Performance tracking for SLA optimization
        self.performance_trends: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
    
    def evaluate_sla_compliance(self, proxy_address: str,
                              response_metrics: ResponseTimeMetrics,
                              validation_history: ValidationHistory) -> Dict[SLATier, SLACompliance]:
        """Evaluate SLA compliance for all tiers"""
        
        compliance_results = {}
        current_time = datetime.now()
        
        for tier, sla_def in self.sla_definitions.items():
            compliance = self._evaluate_tier_compliance(
                proxy_address, tier, sla_def, response_metrics, validation_history, current_time
            )
            
            compliance_results[tier] = compliance
            
            # Store compliance result
            self.compliance_history[proxy_address][tier].append({
                'timestamp': current_time,
                'compliant': compliance.is_compliant,
                'compliance_percentage': compliance.compliance_percentage
            })
            
            # Track breaches
            if not compliance.is_compliant:
                self._record_breach(proxy_address, tier, current_time, compliance)
            
            # Update current compliance
            self.current_compliance[proxy_address][tier] = compliance
        
        return compliance_results
    
    def _evaluate_tier_compliance(self, proxy_address: str, tier: SLATier,
                                sla_def: SLADefinition, response_metrics: ResponseTimeMetrics,
                                validation_history: ValidationHistory,
                                evaluation_time: datetime) -> SLACompliance:
        """Evaluate compliance for a specific SLA tier"""
        
        # Response time compliance
        response_time_compliance = self._evaluate_response_time_compliance(
            response_metrics, sla_def.max_response_time_ms
        )
        
        # Uptime compliance
        measurement_window = timedelta(hours=sla_def.measurement_window_hours)
        uptime_compliance = validation_history.get_success_rate(measurement_window)
        
        # Error rate compliance (inverse of uptime)
        error_rate = 100.0 - uptime_compliance
        error_rate_compliance = 100.0 if error_rate <= sla_def.max_error_rate_percentage else 0.0
        
        # Overall compliance (all criteria must pass)
        is_compliant = (
            response_time_compliance >= 95.0 and  # 95% of requests within SLA
            uptime_compliance >= sla_def.min_uptime_percentage and
            error_rate <= sla_def.max_error_rate_percentage
        )
        
        # Calculate weighted compliance percentage
        compliance_percentage = (
            response_time_compliance * 0.4 +
            uptime_compliance * 0.4 +
            error_rate_compliance * 0.2
        )
        
        # Count recent breaches
        breach_count = self._count_recent_breaches(proxy_address, tier, measurement_window)
        last_breach = self._get_last_breach(proxy_address, tier)
        
        return SLACompliance(
            tier=tier,
            is_compliant=is_compliant,
            compliance_percentage=compliance_percentage,
            response_time_compliance=response_time_compliance,
            uptime_compliance=uptime_compliance,
            error_rate_compliance=error_rate_compliance,
            breach_count=breach_count,
            last_breach=last_breach,
            measurement_period=measurement_window
        )
    
    def _evaluate_response_time_compliance(self, metrics: ResponseTimeMetrics, 
                                         threshold_ms: float) -> float:
        """Calculate response time SLA compliance percentage"""
        if not metrics.measurements:
            return 0.0
        
        compliant_requests = sum(1 for t in metrics.measurements if t <= threshold_ms)
        return (compliant_requests / len(metrics.measurements)) * 100.0
    
    def _record_breach(self, proxy_address: str, tier: SLATier, 
                      timestamp: datetime, compliance: SLACompliance):
        """Record SLA breach"""
        breach_reason = []
        
        if compliance.response_time_compliance < 95.0:
            breach_reason.append("response_time")
        if compliance.uptime_compliance < self.sla_definitions[tier].min_uptime_percentage:
            breach_reason.append("uptime")
        if (100.0 - compliance.uptime_compliance) > self.sla_definitions[tier].max_error_rate_percentage:
            breach_reason.append("error_rate")
        
        breach_info = (tier, timestamp, ",".join(breach_reason))
        self.breach_history[proxy_address].append(breach_info)
        
        # Keep only recent breaches (last 7 days)
        cutoff = timestamp - timedelta(days=7)
        self.breach_history[proxy_address] = [
            b for b in self.breach_history[proxy_address] if b[1] >= cutoff
        ]
        
        log_structured('WARNING', f"SLA breach detected for {proxy_address}",
                      tier=tier.value, reasons=breach_reason)
    
    def _count_recent_breaches(self, proxy_address: str, tier: SLATier, 
                             time_window: timedelta) -> int:
        """Count recent breaches within time window"""
        cutoff = datetime.now() - time_window
        return sum(1 for t, timestamp, _ in self.breach_history[proxy_address] 
                  if t == tier and timestamp >= cutoff)
    
    def _get_last_breach(self, proxy_address: str, tier: SLATier) -> Optional[datetime]:
        """Get timestamp of last breach for tier"""
        tier_breaches = [timestamp for t, timestamp, _ in self.breach_history[proxy_address] 
                        if t == tier]
        return max(tier_breaches) if tier_breaches else None
    
    def get_compliance_summary(self, proxy_address: str) -> Dict[str, any]:
        """Get compliance summary for proxy"""
        if proxy_address not in self.current_compliance:
            return {}
        
        summary = {
            'proxy_address': proxy_address,
            'compliance_by_tier': {},
            'overall_status': 'unknown',
            'best_tier': None,
            'total_breaches': len(self.breach_history[proxy_address])
        }
        
        compliant_tiers = []
        
        for tier, compliance in self.current_compliance[proxy_address].items():
            summary['compliance_by_tier'][tier.value] = compliance.to_dict()
            
            if compliance.is_compliant:
                compliant_tiers.append(tier)
        
        # Determine best achievable tier
        if compliant_tiers:
            # Sort by tier quality (Premium > Business > Standard > Basic)
            tier_order = [SLATier.PREMIUM, SLATier.BUSINESS, SLATier.STANDARD, SLATier.BASIC]
            summary['best_tier'] = next(tier.value for tier in tier_order if tier in compliant_tiers)
            summary['overall_status'] = 'compliant'
        else:
            summary['overall_status'] = 'non_compliant'
        
        return summary


class AdaptiveTimeoutManager:
    """
    Intelligent timeout adaptation based on proxy performance history
    """
    
    def __init__(self, base_config: TimeoutConfiguration = None):
        self.base_config = base_config or TimeoutConfiguration()
        
        # Per-proxy timeout configurations
        self.proxy_timeouts: Dict[str, TimeoutConfiguration] = {}
        
        # Performance history for adaptation
        self.performance_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        
        # Adaptation metadata
        self.adaptation_metadata: Dict[str, dict] = defaultdict(dict)
        
        # Global adaptation statistics
        self.adaptation_stats = {
            'total_adaptations': 0,
            'successful_adaptations': 0,
            'timeout_reductions': 0,
            'timeout_increases': 0
        }
    
    def get_adaptive_timeout(self, proxy_address: str) -> TimeoutConfiguration:
        """Get current adaptive timeout configuration for proxy"""
        return self.proxy_timeouts.get(proxy_address, self.base_config)
    
    def record_performance(self, proxy_address: str, success: bool, 
                         response_time_ms: float, timeout_used: float):
        """Record performance data for timeout adaptation"""
        
        performance_data = {
            'timestamp': datetime.now(),
            'success': success,
            'response_time_ms': response_time_ms,
            'timeout_used': timeout_used,
            'efficiency': response_time_ms / (timeout_used * 1000) if timeout_used > 0 else 0
        }
        
        self.performance_history[proxy_address].append(performance_data)
        
        # Trigger adaptation if enough data available
        if len(self.performance_history[proxy_address]) >= self.base_config.min_samples_for_adaptation:
            self._adapt_timeout(proxy_address)
    
    def _adapt_timeout(self, proxy_address: str):
        """Adapt timeout configuration based on performance history"""
        
        history = self.performance_history[proxy_address]
        if not history:
            return
        
        # Get current configuration
        current_config = self.get_adaptive_timeout(proxy_address)
        
        # Analyze recent performance
        recent_data = list(history)[-50:]  # Last 50 measurements
        
        # Calculate metrics
        success_rate = sum(1 for d in recent_data if d['success']) / len(recent_data)
        avg_response_time = statistics.mean(d['response_time_ms'] for d in recent_data if d['success'])
        response_time_std = statistics.stdev(d['response_time_ms'] for d in recent_data if d['success']) if len([d for d in recent_data if d['success']]) > 1 else 0
        
        # Calculate timeout efficiency
        avg_efficiency = statistics.mean(d['efficiency'] for d in recent_data if d['success'])
        
        # Adaptation decisions
        new_config = TimeoutConfiguration(
            connect_timeout=current_config.connect_timeout,
            read_timeout=current_config.read_timeout,
            total_timeout=current_config.total_timeout,
            min_timeout=current_config.min_timeout,
            max_timeout=current_config.max_timeout,
            adaptation_factor=current_config.adaptation_factor,
            confidence_threshold=current_config.confidence_threshold,
            min_samples_for_adaptation=current_config.min_samples_for_adaptation,
            learning_rate=current_config.learning_rate
        )
        
        # Adaptation logic
        adaptation_made = False
        
        if success_rate >= 0.95 and avg_efficiency < 0.3:
            # High success rate but low efficiency - timeouts may be too high
            reduction_factor = 1.0 - current_config.learning_rate
            new_config.connect_timeout = max(
                current_config.min_timeout,
                current_config.connect_timeout * reduction_factor
            )
            new_config.read_timeout = max(
                current_config.min_timeout,
                current_config.read_timeout * reduction_factor
            )
            new_config.total_timeout = new_config.connect_timeout + new_config.read_timeout
            
            adaptation_made = True
            self.adaptation_stats['timeout_reductions'] += 1
            
        elif success_rate < 0.8:
            # Low success rate - timeouts may be too low
            increase_factor = 1.0 + current_config.learning_rate
            new_config.connect_timeout = min(
                current_config.max_timeout,
                current_config.connect_timeout * increase_factor
            )
            new_config.read_timeout = min(
                current_config.max_timeout,
                current_config.read_timeout * increase_factor
            )
            new_config.total_timeout = new_config.connect_timeout + new_config.read_timeout
            
            adaptation_made = True
            self.adaptation_stats['timeout_increases'] += 1
        
        elif success_rate >= 0.9 and response_time_std > avg_response_time * 0.5:
            # Good success rate but high variability - adjust for consistency
            # Use percentile-based timeout (95th percentile + buffer)
            response_times = [d['response_time_ms'] for d in recent_data if d['success']]
            if response_times:
                p95_response_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
                optimal_timeout = (p95_response_time / 1000) * 1.2  # 20% buffer
                
                new_config.read_timeout = max(
                    current_config.min_timeout,
                    min(current_config.max_timeout, optimal_timeout)
                )
                new_config.total_timeout = new_config.connect_timeout + new_config.read_timeout
                
                adaptation_made = True
        
        if adaptation_made:
            self.proxy_timeouts[proxy_address] = new_config
            self.adaptation_stats['total_adaptations'] += 1
            
            # Record adaptation metadata
            self.adaptation_metadata[proxy_address] = {
                'last_adaptation': datetime.now(),
                'success_rate': success_rate,
                'avg_response_time': avg_response_time,
                'avg_efficiency': avg_efficiency,
                'adaptation_reason': self._get_adaptation_reason(success_rate, avg_efficiency, response_time_std, avg_response_time)
            }
            
            log_structured('INFO', f"Timeout adapted for {proxy_address}",
                          old_config={
                              'connect': current_config.connect_timeout,
                              'read': current_config.read_timeout,
                              'total': current_config.total_timeout
                          },
                          new_config={
                              'connect': new_config.connect_timeout,
                              'read': new_config.read_timeout,
                              'total': new_config.total_timeout
                          },
                          metrics={
                              'success_rate': success_rate,
                              'avg_response_time': avg_response_time,
                              'efficiency': avg_efficiency
                          })
    
    def _get_adaptation_reason(self, success_rate: float, efficiency: float, 
                             std_dev: float, avg_time: float) -> str:
        """Get human-readable reason for timeout adaptation"""
        if success_rate >= 0.95 and efficiency < 0.3:
            return "high_success_low_efficiency"
        elif success_rate < 0.8:
            return "low_success_rate"
        elif success_rate >= 0.9 and std_dev > avg_time * 0.5:
            return "high_variability"
        else:
            return "optimization"
    
    def get_adaptation_summary(self, proxy_address: str = None) -> Dict[str, any]:
        """Get adaptation summary for proxy or global stats"""
        if proxy_address:
            return {
                'proxy_address': proxy_address,
                'current_config': asdict(self.get_adaptive_timeout(proxy_address)),
                'adaptation_metadata': self.adaptation_metadata.get(proxy_address, {}),
                'performance_samples': len(self.performance_history[proxy_address])
            }
        else:
            return {
                'global_stats': self.adaptation_stats,
                'total_proxies_with_adaptations': len(self.proxy_timeouts),
                'total_performance_samples': sum(len(h) for h in self.performance_history.values())
            }


# Export key classes
__all__ = [
    'SLATier', 'SLADefinition', 'SLACompliance', 'TimeoutConfiguration',
    'SLAMonitor', 'AdaptiveTimeoutManager'
]