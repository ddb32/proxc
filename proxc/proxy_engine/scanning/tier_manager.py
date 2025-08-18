"""Multi-Tiered Scanning Architecture

Implements intelligent proxy validation with four-tier system:
- Tier 1 (ACTIVE): 24-hour intervals, lightweight validation
- Tier 2 (AT_RISK): 6-12 hour intervals, comprehensive validation  
- Tier 3 (INACTIVE): Weekly intervals, basic connectivity checks
- Tier 4 (UNKNOWN): On-demand validation with priority-guided scheduling

Provides automatic tier transitions based on performance history and intelligent
resource allocation across tiers.
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Callable, Set
from enum import Enum
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from ...proxy_core.models import ProxyInfo, TierLevel, RiskCategory, ProxyStatus, ValidationStatus
from ..validation.validation_config import ValidationConfig

logger = logging.getLogger(__name__)


class TierValidationType(Enum):
    """Types of validation for different tiers"""
    LIGHTWEIGHT = "lightweight"      # Basic connectivity only
    STANDARD = "standard"             # Standard validation checks
    COMPREHENSIVE = "comprehensive"   # Full validation including security
    MINIMAL = "minimal"               # Absolute minimum checks


@dataclass
class TierConfiguration:
    """Configuration for a specific scanning tier"""
    tier_level: TierLevel
    validation_interval_hours: int
    validation_type: TierValidationType
    max_concurrent_validations: int
    timeout_multiplier: float          # Multiplier for base timeouts
    retry_attempts: int
    priority_weight: float             # Higher = more priority
    resource_allocation_percentage: float  # % of total resources
    
    # Performance thresholds for tier transitions
    promotion_threshold: float         # Score needed to move to higher tier
    demotion_threshold: float          # Score below which to demote
    
    # Validation configuration overrides
    validation_config_overrides: Dict[str, Any]


class TierManager:
    """Manages multi-tiered proxy scanning and validation"""
    
    def __init__(self, base_validation_config: Optional[ValidationConfig] = None):
        self.base_config = base_validation_config or ValidationConfig()
        self.tier_configs = self._initialize_tier_configurations()
        self.validation_stats = {tier: {'total': 0, 'successful': 0, 'failed': 0, 'avg_time': 0.0} 
                               for tier in TierLevel}
        self.tier_transition_stats = {'promotions': 0, 'demotions': 0, 'transitions': []}
        
        # Resource allocation tracking
        self.active_validations = {tier: 0 for tier in TierLevel}
        self.validation_queue = {tier: [] for tier in TierLevel}
        
        # Performance tracking
        self.tier_performance_history = {tier: [] for tier in TierLevel}
        
        logger.info("TierManager initialized with 4-tier scanning architecture")
    
    def _initialize_tier_configurations(self) -> Dict[TierLevel, TierConfiguration]:
        """Initialize default tier configurations"""
        return {
            TierLevel.TIER_1: TierConfiguration(
                tier_level=TierLevel.TIER_1,
                validation_interval_hours=24,
                validation_type=TierValidationType.LIGHTWEIGHT,
                max_concurrent_validations=20,
                timeout_multiplier=0.8,        # Faster timeouts for high-performing proxies
                retry_attempts=2,
                priority_weight=1.0,
                resource_allocation_percentage=0.4,  # 40% of resources
                promotion_threshold=90.0,       # Very high threshold to stay in tier 1
                demotion_threshold=70.0,        # Demote if performance drops
                validation_config_overrides={
                    'connect_timeout': 8.0,
                    'read_timeout': 15.0,
                    'max_retries': 2,
                    'enable_anonymity_testing': False,
                    'enable_speed_testing': False,
                    'check_proxy_headers': False
                }
            ),
            
            TierLevel.TIER_2: TierConfiguration(
                tier_level=TierLevel.TIER_2,
                validation_interval_hours=12,  # Can be 6-12 hours based on performance
                validation_type=TierValidationType.COMPREHENSIVE,
                max_concurrent_validations=15,
                timeout_multiplier=1.0,        # Standard timeouts
                retry_attempts=3,
                priority_weight=0.8,
                resource_allocation_percentage=0.35,  # 35% of resources
                promotion_threshold=80.0,       # Good performance needed for promotion
                demotion_threshold=50.0,        # Moderate threshold for demotion
                validation_config_overrides={
                    'connect_timeout': 10.0,
                    'read_timeout': 20.0,
                    'max_retries': 3,
                    'enable_anonymity_testing': True,
                    'enable_speed_testing': True,
                    'check_proxy_headers': True,
                    'detect_captive_portals': True
                }
            ),
            
            TierLevel.TIER_3: TierConfiguration(
                tier_level=TierLevel.TIER_3,
                validation_interval_hours=168,  # Weekly
                validation_type=TierValidationType.STANDARD,
                max_concurrent_validations=10,
                timeout_multiplier=1.2,        # Longer timeouts for problematic proxies
                retry_attempts=1,
                priority_weight=0.3,
                resource_allocation_percentage=0.15,  # 15% of resources
                promotion_threshold=60.0,       # Lower threshold for improvement
                demotion_threshold=20.0,        # Very low threshold to avoid tier 4
                validation_config_overrides={
                    'connect_timeout': 12.0,
                    'read_timeout': 25.0,
                    'max_retries': 1,
                    'enable_anonymity_testing': False,
                    'enable_speed_testing': False,
                    'check_proxy_headers': False,
                    'allow_redirects': False
                }
            ),
            
            TierLevel.TIER_4: TierConfiguration(
                tier_level=TierLevel.TIER_4,
                validation_interval_hours=24,   # On-demand, but at least daily
                validation_type=TierValidationType.MINIMAL,
                max_concurrent_validations=5,
                timeout_multiplier=1.5,        # Generous timeouts for unknown proxies
                retry_attempts=1,
                priority_weight=0.1,
                resource_allocation_percentage=0.1,  # 10% of resources
                promotion_threshold=40.0,       # Low threshold to get out of tier 4
                demotion_threshold=0.0,         # Can't go lower than tier 4
                validation_config_overrides={
                    'connect_timeout': 15.0,
                    'read_timeout': 30.0,
                    'max_retries': 1,
                    'enable_anonymity_testing': False,
                    'enable_speed_testing': False,
                    'check_proxy_headers': False,
                    'enable_target_testing': False,
                    'detailed_error_reporting': False
                }
            )
        }
    
    def get_tier_config(self, tier: TierLevel) -> TierConfiguration:
        """Get configuration for a specific tier"""
        return self.tier_configs[tier]
    
    def get_validation_config_for_tier(self, tier: TierLevel) -> ValidationConfig:
        """Get ValidationConfig customized for specific tier"""
        tier_config = self.tier_configs[tier]
        
        # Start with base config
        config = ValidationConfig(
            connect_timeout=self.base_config.connect_timeout * tier_config.timeout_multiplier,
            read_timeout=self.base_config.read_timeout * tier_config.timeout_multiplier,
            total_timeout=self.base_config.total_timeout * tier_config.timeout_multiplier,
            max_retries=tier_config.retry_attempts,
            max_workers=min(tier_config.max_concurrent_validations, self.base_config.max_workers)
        )
        
        # Apply tier-specific overrides
        for key, value in tier_config.validation_config_overrides.items():
            if hasattr(config, key):
                setattr(config, key, value)
        
        return config
    
    def assign_initial_tier(self, proxy: ProxyInfo) -> TierLevel:
        """Assign initial tier for a new proxy based on available information"""
        
        # Default to Tier 4 (unknown) for new proxies
        if proxy.metrics.check_count == 0:
            return TierLevel.TIER_4
        
        # Use existing tier score for assignment
        tier_score = proxy.calculate_tier_score()
        
        if tier_score >= 80:
            return TierLevel.TIER_1
        elif tier_score >= 60:
            return TierLevel.TIER_2
        elif tier_score >= 30:
            return TierLevel.TIER_3
        else:
            return TierLevel.TIER_4
    
    def evaluate_tier_transition(self, proxy: ProxyInfo) -> Optional[TierLevel]:
        """Evaluate if a proxy should transition to a different tier"""
        current_tier = proxy.tier_level
        current_config = self.tier_configs[current_tier]
        
        # Calculate current performance score
        performance_score = proxy.calculate_tier_score()
        
        # Track performance history
        self.tier_performance_history[current_tier].append({
            'proxy_id': proxy.proxy_id,
            'score': performance_score,
            'timestamp': datetime.utcnow()
        })
        
        # Limit history size
        if len(self.tier_performance_history[current_tier]) > 1000:
            self.tier_performance_history[current_tier] = self.tier_performance_history[current_tier][-500:]
        
        # Check for promotion (to higher tier - lower number)
        if performance_score >= current_config.promotion_threshold:
            if current_tier.value > 1:  # Can be promoted
                new_tier = TierLevel(current_tier.value - 1)
                logger.info(f"Proxy {proxy.address} promoted from {current_tier.name} to {new_tier.name} (score: {performance_score:.1f})")
                self.tier_transition_stats['promotions'] += 1
                self._record_transition(proxy, current_tier, new_tier, performance_score, 'promotion')
                return new_tier
        
        # Check for demotion (to lower tier - higher number)
        elif performance_score < current_config.demotion_threshold:
            if current_tier.value < 4:  # Can be demoted
                new_tier = TierLevel(current_tier.value + 1)
                logger.info(f"Proxy {proxy.address} demoted from {current_tier.name} to {new_tier.name} (score: {performance_score:.1f})")
                self.tier_transition_stats['demotions'] += 1
                self._record_transition(proxy, current_tier, new_tier, performance_score, 'demotion')
                return new_tier
        
        # No transition needed
        return None
    
    def _record_transition(self, proxy: ProxyInfo, from_tier: TierLevel, to_tier: TierLevel, 
                          score: float, transition_type: str):
        """Record tier transition for analytics"""
        transition_record = {
            'proxy_id': proxy.proxy_id,
            'proxy_address': proxy.address,
            'from_tier': from_tier.value,
            'to_tier': to_tier.value,
            'score': score,
            'transition_type': transition_type,
            'timestamp': datetime.utcnow(),
            'success_rate': proxy.metrics.success_rate,
            'response_time': proxy.metrics.response_time,
            'check_count': proxy.metrics.check_count
        }
        
        self.tier_transition_stats['transitions'].append(transition_record)
        
        # Limit transition history
        if len(self.tier_transition_stats['transitions']) > 10000:
            self.tier_transition_stats['transitions'] = self.tier_transition_stats['transitions'][-5000:]
    
    def update_proxy_tier(self, proxy: ProxyInfo, force_evaluation: bool = False) -> bool:
        """Update proxy tier based on current performance"""
        
        # Always evaluate after validation or if forced
        if force_evaluation or proxy.metrics.check_count > 0:
            new_tier = self.evaluate_tier_transition(proxy)
            
            if new_tier and new_tier != proxy.tier_level:
                old_tier = proxy.tier_level
                proxy.tier_level = new_tier
                
                # Update related fields based on new tier
                self._update_proxy_for_tier(proxy, new_tier)
                
                logger.debug(f"Updated {proxy.address} tier from {old_tier.name} to {new_tier.name}")
                return True
        
        return False
    
    def _update_proxy_for_tier(self, proxy: ProxyInfo, tier: TierLevel):
        """Update proxy fields based on new tier assignment"""
        tier_config = self.tier_configs[tier]
        
        # Update check frequency
        proxy.check_frequency = tier_config.validation_interval_hours
        
        # Update scan priority based on tier
        if tier == TierLevel.TIER_1:
            proxy.scan_priority = min(proxy.scan_priority, 3)  # High priority
        elif tier == TierLevel.TIER_2:
            proxy.scan_priority = min(proxy.scan_priority, 5)  # Medium-high priority
        elif tier == TierLevel.TIER_3:
            proxy.scan_priority = max(proxy.scan_priority, 6)  # Low priority
        else:  # TIER_4
            proxy.scan_priority = max(proxy.scan_priority, 7)  # Very low priority
        
        # Update risk category based on tier
        if tier == TierLevel.TIER_1:
            proxy.risk_category = RiskCategory.ACTIVE
        elif tier == TierLevel.TIER_2:
            proxy.risk_category = RiskCategory.AT_RISK
        elif tier == TierLevel.TIER_3:
            proxy.risk_category = RiskCategory.INACTIVE
        else:  # TIER_4
            proxy.risk_category = RiskCategory.UNKNOWN
        
        # Schedule next check
        proxy.schedule_next_check()
        
        proxy.last_updated = datetime.utcnow()
    
    def get_proxies_due_for_validation(self, proxies: List[ProxyInfo], 
                                     max_per_tier: Optional[Dict[TierLevel, int]] = None) -> Dict[TierLevel, List[ProxyInfo]]:
        """Get proxies due for validation, organized by tier"""
        
        if max_per_tier is None:
            max_per_tier = {
                TierLevel.TIER_1: 50,
                TierLevel.TIER_2: 40,
                TierLevel.TIER_3: 20,
                TierLevel.TIER_4: 10
            }
        
        due_proxies = {tier: [] for tier in TierLevel}
        
        for proxy in proxies:
            if proxy.is_due_for_check:
                tier = proxy.tier_level
                if len(due_proxies[tier]) < max_per_tier.get(tier, 10):
                    due_proxies[tier].append(proxy)
        
        # Sort each tier by priority and performance
        for tier, tier_proxies in due_proxies.items():
            tier_proxies.sort(key=lambda p: (
                p.scan_priority,                    # Lower priority number = higher priority
                -p.calculate_tier_score(),          # Higher score = higher priority
                p.next_scheduled_check or datetime.min  # Earlier scheduled = higher priority
            ))
        
        return due_proxies
    
    def calculate_validation_priority(self, proxy: ProxyInfo) -> float:
        """Calculate validation priority score for proxy scheduling"""
        tier_config = self.tier_configs[proxy.tier_level]
        
        # Base priority from tier weight
        priority = tier_config.priority_weight
        
        # Adjust for scan priority (lower number = higher priority)
        priority += (10 - proxy.scan_priority) * 0.1
        
        # Adjust for overdue status
        if proxy.next_scheduled_check:
            overdue_hours = (datetime.utcnow() - proxy.next_scheduled_check).total_seconds() / 3600
            if overdue_hours > 0:
                priority += min(overdue_hours / 24, 2.0)  # Up to 2 point bonus for being overdue
        
        # Adjust for performance (higher performance = higher priority within tier)
        tier_score = proxy.calculate_tier_score()
        priority += tier_score / 1000  # Small adjustment based on performance
        
        return priority
    
    def get_tier_statistics(self) -> Dict[str, Any]:
        """Get comprehensive tier statistics"""
        return {
            'tier_configurations': {
                tier.name: {
                    'validation_interval_hours': config.validation_interval_hours,
                    'validation_type': config.validation_type.value,
                    'max_concurrent': config.max_concurrent_validations,
                    'resource_allocation': config.resource_allocation_percentage,
                    'promotion_threshold': config.promotion_threshold,
                    'demotion_threshold': config.demotion_threshold
                }
                for tier, config in self.tier_configs.items()
            },
            'validation_stats': self.validation_stats,
            'transition_stats': {
                'total_promotions': self.tier_transition_stats['promotions'],
                'total_demotions': self.tier_transition_stats['demotions'],
                'recent_transitions': len([
                    t for t in self.tier_transition_stats['transitions']
                    if (datetime.utcnow() - t['timestamp']).days < 7
                ])
            },
            'active_validations': self.active_validations,
            'queue_sizes': {tier.name: len(queue) for tier, queue in self.validation_queue.items()},
            'performance_trends': self._calculate_performance_trends()
        }
    
    def _calculate_performance_trends(self) -> Dict[str, Any]:
        """Calculate performance trends across tiers"""
        trends = {}
        
        for tier, history in self.tier_performance_history.items():
            if len(history) >= 10:  # Need minimum data points
                recent_scores = [h['score'] for h in history[-20:]]  # Last 20 scores
                older_scores = [h['score'] for h in history[-40:-20]]  # Previous 20 scores
                
                if older_scores:
                    recent_avg = sum(recent_scores) / len(recent_scores)
                    older_avg = sum(older_scores) / len(older_scores)
                    trend = recent_avg - older_avg
                    
                    trends[tier.name] = {
                        'average_score': recent_avg,
                        'trend': trend,
                        'trend_direction': 'improving' if trend > 2 else 'declining' if trend < -2 else 'stable',
                        'sample_size': len(recent_scores)
                    }
                else:
                    trends[tier.name] = {
                        'average_score': sum(recent_scores) / len(recent_scores),
                        'trend': 0,
                        'trend_direction': 'insufficient_data',
                        'sample_size': len(recent_scores)
                    }
            else:
                trends[tier.name] = {
                    'average_score': 0,
                    'trend': 0,
                    'trend_direction': 'no_data',
                    'sample_size': 0
                }
        
        return trends
    
    def optimize_tier_configurations(self, optimization_data: Dict[str, Any]):
        """Optimize tier configurations based on performance data"""
        logger.info("Optimizing tier configurations based on performance data")
        
        # This is a placeholder for ML-based optimization
        # In a full implementation, this would use machine learning to adjust:
        # - Validation intervals
        # - Resource allocation
        # - Promotion/demotion thresholds
        # - Timeout multipliers
        
        for tier, config in self.tier_configs.items():
            # Example optimization logic
            tier_data = optimization_data.get(tier.name, {})
            
            if tier_data.get('average_response_time', 0) > 10000:  # > 10 seconds
                config.timeout_multiplier *= 1.1  # Increase timeouts
                logger.debug(f"Increased timeout multiplier for {tier.name} to {config.timeout_multiplier:.2f}")
            
            if tier_data.get('success_rate', 0) < 50:  # < 50% success rate
                config.retry_attempts = min(config.retry_attempts + 1, 5)
                logger.debug(f"Increased retry attempts for {tier.name} to {config.retry_attempts}")


def create_tier_manager(base_config: Optional[ValidationConfig] = None) -> TierManager:
    """Factory function to create tier manager"""
    return TierManager(base_config)


if __name__ == "__main__":
    # Example usage and testing
    from ...proxy_core.models import ProxyInfo, ProxyProtocol, ProxyMetrics
    
    # Create tier manager
    tier_manager = create_tier_manager()
    
    # Create test proxies with different performance levels
    test_proxies = [
        # High-performing proxy
        ProxyInfo(host="8.8.8.8", port=8080, protocol=ProxyProtocol.HTTP),
        # Medium-performing proxy  
        ProxyInfo(host="1.1.1.1", port=3128, protocol=ProxyProtocol.HTTP),
        # Poor-performing proxy
        ProxyInfo(host="9.9.9.9", port=8080, protocol=ProxyProtocol.HTTP)
    ]
    
    # Simulate different performance metrics
    test_proxies[0].metrics.success_rate = 95.0
    test_proxies[0].metrics.response_time = 1500
    test_proxies[0].metrics.check_count = 100
    
    test_proxies[1].metrics.success_rate = 70.0
    test_proxies[1].metrics.response_time = 5000
    test_proxies[1].metrics.check_count = 50
    
    test_proxies[2].metrics.success_rate = 30.0
    test_proxies[2].metrics.response_time = 15000
    test_proxies[2].metrics.check_count = 20
    
    # Assign initial tiers
    for proxy in test_proxies:
        initial_tier = tier_manager.assign_initial_tier(proxy)
        proxy.tier_level = initial_tier
        tier_manager._update_proxy_for_tier(proxy, initial_tier)
        print(f"Proxy {proxy.address} assigned to {initial_tier.name} (score: {proxy.calculate_tier_score():.1f})")
    
    # Test tier transitions
    for proxy in test_proxies:
        tier_manager.update_proxy_tier(proxy, force_evaluation=True)
    
    # Show statistics
    stats = tier_manager.get_tier_statistics()
    print(f"\nTier Manager Statistics:")
    print(f"Promotions: {stats['transition_stats']['total_promotions']}")
    print(f"Demotions: {stats['transition_stats']['total_demotions']}")
    
    # Test validation configurations for each tier
    for tier in TierLevel:
        config = tier_manager.get_validation_config_for_tier(tier)
        print(f"\n{tier.name} validation config:")
        print(f"  Connect timeout: {config.connect_timeout}s")
        print(f"  Read timeout: {config.read_timeout}s")
        print(f"  Max retries: {config.max_retries}")
        print(f"  Anonymity testing: {config.enable_anonymity_testing}")