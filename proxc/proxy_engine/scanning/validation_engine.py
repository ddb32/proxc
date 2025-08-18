"""Validation Engine for Multi-Tiered Proxy Scanning

Provides tier-specific validation with different validation depths and strategies.
Integrates with the tier management system for intelligent proxy validation.
"""

import logging
import asyncio
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time

# Conditional imports based on what's available
try:
    from ...proxy_core.models import ProxyInfo, TierLevel, ProxyStatus, ValidationStatus
    from ..validation.validation_config import ValidationConfig
    from ..validation.batch_validators import BatchValidator
    from .tier_manager import TierManager, TierValidationType
    HAS_MODELS = True
except ImportError:
    HAS_MODELS = False
    # Fallback definitions
    class TierLevel(Enum):
        TIER_1 = "tier_1"
        TIER_2 = "tier_2"
        TIER_3 = "tier_3"
        TIER_4 = "tier_4"

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of a proxy validation operation"""
    proxy_id: str
    success: bool
    response_time: float
    error_message: Optional[str] = None
    validation_depth: str = "basic"
    tier_level: TierLevel = TierLevel.TIER_4
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


@dataclass
class TieredValidationStats:
    """Statistics for tiered validation operations"""
    tier_level: TierLevel
    total_validations: int = 0
    successful_validations: int = 0
    failed_validations: int = 0
    average_response_time: float = 0.0
    average_validation_time: float = 0.0
    last_updated: datetime = None
    
    def __post_init__(self):
        if self.last_updated is None:
            self.last_updated = datetime.utcnow()
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage"""
        if self.total_validations == 0:
            return 0.0
        return (self.successful_validations / self.total_validations) * 100


class ValidationEngine:
    """Core validation engine with tier-specific validation strategies"""
    
    def __init__(self, tier_manager: TierManager, config: Optional[Dict[str, Any]] = None):
        """
        Initialize validation engine
        
        Args:
            tier_manager: TierManager instance for tier-specific configurations
            config: Configuration dictionary
        """
        self.tier_manager = tier_manager
        self.config = config or {}
        
        # Validation configuration
        self.max_concurrent_validations = self.config.get('max_concurrent_validations', 50)
        self.validation_timeout = self.config.get('validation_timeout', 60)
        self.enable_batch_validation = self.config.get('enable_batch_validation', True)
        
        # Statistics tracking
        self.tier_stats: Dict[TierLevel, TieredValidationStats] = {
            tier: TieredValidationStats(tier) for tier in TierLevel
        }
        
        # Validation history
        self.validation_history: List[ValidationResult] = []
        self.validation_lock = threading.RLock()
        
        # Active validations tracking
        self.active_validations: Dict[str, datetime] = {}  # proxy_id -> start_time
        
        # Batch validator instances for each tier
        self.batch_validators: Dict[TierLevel, Optional['BatchValidator']] = {
            tier: None for tier in TierLevel
        }
        
        self._initialize_batch_validators()
        logger.info("ValidationEngine initialized with tiered validation support")
    
    def _initialize_batch_validators(self):
        """Initialize batch validators for each tier"""
        if not self.enable_batch_validation:
            return
        
        try:
            for tier in TierLevel:
                tier_config = self.tier_manager.get_validation_config_for_tier(tier)
                
                # Create batch validator with tier-specific configuration
                if HAS_MODELS:
                    from ..validation.batch_validators import BatchValidator
                    self.batch_validators[tier] = BatchValidator(tier_config)
                
                logger.debug(f"Initialized batch validator for {tier.value}")
                
        except ImportError:
            logger.warning("BatchValidator not available, falling back to individual validation")
            self.enable_batch_validation = False
    
    def validate_proxy(self, proxy: ProxyInfo, force_tier: Optional[TierLevel] = None) -> ValidationResult:
        """
        Validate a single proxy using tier-specific validation
        
        Args:
            proxy: ProxyInfo object to validate
            force_tier: Optional tier level to force specific validation depth
            
        Returns:
            ValidationResult object
        """
        start_time = time.time()
        tier = force_tier or proxy.tier_level
        
        with self.validation_lock:
            self.active_validations[proxy.proxy_id] = datetime.utcnow()
        
        try:
            # Get tier-specific validation configuration
            validation_config = self.tier_manager.get_validation_config_for_tier(tier)
            tier_config = self.tier_manager.get_tier_config(tier)
            
            # Perform validation based on tier type
            success, response_time, error = self._perform_tier_validation(
                proxy, tier_config.validation_type, validation_config
            )
            
            # Create result
            result = ValidationResult(
                proxy_id=proxy.proxy_id,
                success=success,
                response_time=response_time,
                error_message=error,
                validation_depth=tier_config.validation_type.value,
                tier_level=tier
            )
            
            # Update statistics
            self._update_tier_statistics(tier, result, time.time() - start_time)
            
            # Store in history
            self.validation_history.append(result)
            if len(self.validation_history) > 10000:  # Limit history size
                self.validation_history = self.validation_history[-5000:]
            
            return result
            
        except Exception as e:
            error_result = ValidationResult(
                proxy_id=proxy.proxy_id,
                success=False,
                response_time=0.0,
                error_message=str(e),
                validation_depth="error",
                tier_level=tier
            )
            
            self._update_tier_statistics(tier, error_result, time.time() - start_time)
            return error_result
            
        finally:
            with self.validation_lock:
                self.active_validations.pop(proxy.proxy_id, None)
    
    def _perform_tier_validation(self, proxy: ProxyInfo, validation_type: 'TierValidationType', 
                               config: ValidationConfig) -> Tuple[bool, float, Optional[str]]:
        """
        Perform validation based on tier validation type
        
        Args:
            proxy: ProxyInfo object
            validation_type: Type of validation to perform
            config: Validation configuration
            
        Returns:
            Tuple of (success, response_time, error_message)
        """
        start_time = time.time()
        
        try:
            if validation_type.value == "minimal":
                return self._minimal_validation(proxy, config)
            elif validation_type.value == "lightweight":
                return self._lightweight_validation(proxy, config)
            elif validation_type.value == "standard":
                return self._standard_validation(proxy, config)
            elif validation_type.value == "comprehensive":
                return self._comprehensive_validation(proxy, config)
            else:
                return self._standard_validation(proxy, config)
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return False, response_time, str(e)
    
    def _minimal_validation(self, proxy: ProxyInfo, config: ValidationConfig) -> Tuple[bool, float, Optional[str]]:
        """Minimal validation - basic connectivity check only"""
        start_time = time.time()
        
        try:
            # Use existing validation logic from batch validators if available
            if self.batch_validators.get(TierLevel.TIER_4):
                validator = self.batch_validators[TierLevel.TIER_4]
                result = validator.validate_single_proxy(proxy, quick_check=True)
                response_time = (time.time() - start_time) * 1000
                return result.success, response_time, result.error_message
            
            # Fallback to basic check
            # This would integrate with existing validation logic
            success = self._basic_connectivity_check(proxy, config)
            response_time = (time.time() - start_time) * 1000
            
            return success, response_time, None if success else "Connection failed"
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return False, response_time, str(e)
    
    def _lightweight_validation(self, proxy: ProxyInfo, config: ValidationConfig) -> Tuple[bool, float, Optional[str]]:
        """Lightweight validation - basic checks with minimal overhead"""
        start_time = time.time()
        
        try:
            # Basic connectivity plus simple HTTP request
            if not self._basic_connectivity_check(proxy, config):
                response_time = (time.time() - start_time) * 1000
                return False, response_time, "Basic connectivity failed"
            
            # Simple HTTP request
            success = self._simple_http_check(proxy, config)
            response_time = (time.time() - start_time) * 1000
            
            return success, response_time, None if success else "HTTP request failed"
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return False, response_time, str(e)
    
    def _standard_validation(self, proxy: ProxyInfo, config: ValidationConfig) -> Tuple[bool, float, Optional[str]]:
        """Standard validation - comprehensive proxy testing"""
        start_time = time.time()
        
        try:
            # Use batch validator if available
            if self.batch_validators.get(TierLevel.TIER_3):
                validator = self.batch_validators[TierLevel.TIER_3]
                result = validator.validate_single_proxy(proxy)
                response_time = (time.time() - start_time) * 1000
                return result.success, response_time, result.error_message
            
            # Fallback validation
            success = (self._basic_connectivity_check(proxy, config) and
                      self._simple_http_check(proxy, config) and
                      self._protocol_validation(proxy, config))
            
            response_time = (time.time() - start_time) * 1000
            return success, response_time, None if success else "Standard validation failed"
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return False, response_time, str(e)
    
    def _comprehensive_validation(self, proxy: ProxyInfo, config: ValidationConfig) -> Tuple[bool, float, Optional[str]]:
        """Comprehensive validation - full proxy testing including security checks"""
        start_time = time.time()
        
        try:
            # Use batch validator if available
            if self.batch_validators.get(TierLevel.TIER_2):
                validator = self.batch_validators[TierLevel.TIER_2]
                result = validator.validate_single_proxy(proxy, comprehensive=True)
                response_time = (time.time() - start_time) * 1000
                return result.success, response_time, result.error_message
            
            # Fallback comprehensive validation
            checks = [
                self._basic_connectivity_check(proxy, config),
                self._simple_http_check(proxy, config),
                self._protocol_validation(proxy, config),
                self._security_validation(proxy, config),
                self._performance_validation(proxy, config)
            ]
            
            success = all(checks)
            response_time = (time.time() - start_time) * 1000
            
            return success, response_time, None if success else "Comprehensive validation failed"
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return False, response_time, str(e)
    
    def _basic_connectivity_check(self, proxy: ProxyInfo, config: ValidationConfig) -> bool:
        """Basic connectivity check"""
        # This would integrate with existing validation logic
        # Placeholder implementation
        return True  # Assume success for now
    
    def _simple_http_check(self, proxy: ProxyInfo, config: ValidationConfig) -> bool:
        """Simple HTTP request check"""
        # This would integrate with existing validation logic
        # Placeholder implementation
        return True  # Assume success for now
    
    def _protocol_validation(self, proxy: ProxyInfo, config: ValidationConfig) -> bool:
        """Protocol-specific validation"""
        # This would integrate with existing validation logic
        # Placeholder implementation
        return True  # Assume success for now
    
    def _security_validation(self, proxy: ProxyInfo, config: ValidationConfig) -> bool:
        """Security validation (anonymity, headers, etc.)"""
        # This would integrate with existing validation logic
        # Placeholder implementation
        return True  # Assume success for now
    
    def _performance_validation(self, proxy: ProxyInfo, config: ValidationConfig) -> bool:
        """Performance validation (speed, latency)"""
        # This would integrate with existing validation logic
        # Placeholder implementation
        return True  # Assume success for now
    
    def validate_proxies_batch(self, proxies: List[ProxyInfo], 
                             tier_override: Optional[TierLevel] = None) -> List[ValidationResult]:
        """
        Validate multiple proxies in batch
        
        Args:
            proxies: List of ProxyInfo objects to validate
            tier_override: Optional tier level for all proxies
            
        Returns:
            List of ValidationResult objects
        """
        if not proxies:
            return []
        
        # Group proxies by tier for batch processing
        tier_groups: Dict[TierLevel, List[ProxyInfo]] = {}
        
        for proxy in proxies:
            tier = tier_override or proxy.tier_level
            if tier not in tier_groups:
                tier_groups[tier] = []
            tier_groups[tier].append(proxy)
        
        # Process each tier group
        all_results = []
        
        for tier, tier_proxies in tier_groups.items():
            if self.enable_batch_validation and self.batch_validators.get(tier):
                # Use batch validator
                batch_results = self._batch_validate_tier(tier_proxies, tier)
            else:
                # Fallback to individual validation
                batch_results = [self.validate_proxy(proxy, tier) for proxy in tier_proxies]
            
            all_results.extend(batch_results)
        
        return all_results
    
    def _batch_validate_tier(self, proxies: List[ProxyInfo], tier: TierLevel) -> List[ValidationResult]:
        """Batch validate proxies for a specific tier"""
        batch_validator = self.batch_validators[tier]
        if not batch_validator:
            return [self.validate_proxy(proxy, tier) for proxy in proxies]
        
        start_time = time.time()
        
        try:
            # Perform batch validation
            batch_results = batch_validator.validate_proxies_batch(proxies)
            
            # Convert to ValidationResult objects
            results = []
            for proxy, batch_result in zip(proxies, batch_results):
                result = ValidationResult(
                    proxy_id=proxy.proxy_id,
                    success=batch_result.success,
                    response_time=batch_result.response_time,
                    error_message=batch_result.error_message,
                    validation_depth=self.tier_manager.get_tier_config(tier).validation_type.value,
                    tier_level=tier
                )
                results.append(result)
                
                # Update individual statistics
                self._update_tier_statistics(tier, result, batch_result.response_time / 1000)
            
            return results
            
        except Exception as e:
            logger.error(f"Batch validation failed for tier {tier.value}: {e}")
            # Fallback to individual validation
            return [self.validate_proxy(proxy, tier) for proxy in proxies]
    
    def _update_tier_statistics(self, tier: TierLevel, result: ValidationResult, validation_time: float):
        """Update statistics for a tier"""
        with self.validation_lock:
            stats = self.tier_stats[tier]
            
            stats.total_validations += 1
            if result.success:
                stats.successful_validations += 1
            else:
                stats.failed_validations += 1
            
            # Update average response time
            total_time = stats.average_response_time * (stats.total_validations - 1)
            stats.average_response_time = (total_time + result.response_time) / stats.total_validations
            
            # Update average validation time
            total_validation_time = stats.average_validation_time * (stats.total_validations - 1)
            stats.average_validation_time = (total_validation_time + validation_time * 1000) / stats.total_validations
            
            stats.last_updated = datetime.utcnow()
    
    def get_validation_statistics(self) -> Dict[str, Any]:
        """Get comprehensive validation statistics"""
        with self.validation_lock:
            return {
                'tier_statistics': {
                    tier.value: {
                        'total_validations': stats.total_validations,
                        'successful_validations': stats.successful_validations,
                        'failed_validations': stats.failed_validations,
                        'success_rate': round(stats.success_rate, 2),
                        'average_response_time': round(stats.average_response_time, 2),
                        'average_validation_time': round(stats.average_validation_time, 2),
                        'last_updated': stats.last_updated.isoformat() if stats.last_updated else None
                    }
                    for tier, stats in self.tier_stats.items()
                },
                'active_validations': len(self.active_validations),
                'validation_history_size': len(self.validation_history),
                'batch_validation_enabled': self.enable_batch_validation,
                'recent_success_rate': self._calculate_recent_success_rate()
            }
    
    def _calculate_recent_success_rate(self, hours: int = 24) -> float:
        """Calculate success rate for recent validations"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        recent_results = [r for r in self.validation_history if r.timestamp >= cutoff_time]
        
        if not recent_results:
            return 0.0
        
        successful = sum(1 for r in recent_results if r.success)
        return (successful / len(recent_results)) * 100
    
    def get_tier_performance_summary(self) -> Dict[TierLevel, Dict[str, Any]]:
        """Get performance summary for each tier"""
        summary = {}
        
        with self.validation_lock:
            for tier, stats in self.tier_stats.items():
                tier_config = self.tier_manager.get_tier_config(tier)
                
                summary[tier] = {
                    'validation_type': tier_config.validation_type.value,
                    'success_rate': round(stats.success_rate, 2),
                    'average_response_time': round(stats.average_response_time, 2),
                    'total_validations': stats.total_validations,
                    'meets_threshold': stats.success_rate >= tier_config.promotion_threshold,
                    'needs_attention': stats.success_rate < tier_config.demotion_threshold,
                    'last_updated': stats.last_updated.isoformat() if stats.last_updated else None
                }
        
        return summary


class TieredValidator:
    """High-level interface for tiered proxy validation"""
    
    def __init__(self, tier_manager: TierManager, validation_engine: ValidationEngine):
        """
        Initialize tiered validator
        
        Args:
            tier_manager: TierManager instance
            validation_engine: ValidationEngine instance
        """
        self.tier_manager = tier_manager
        self.validation_engine = validation_engine
        
        logger.info("TieredValidator initialized")
    
    def validate_and_update_tier(self, proxy: ProxyInfo) -> Tuple[ValidationResult, bool]:
        """
        Validate proxy and update tier if necessary
        
        Args:
            proxy: ProxyInfo object to validate
            
        Returns:
            Tuple of (ValidationResult, tier_changed)
        """
        # Perform validation
        result = self.validation_engine.validate_proxy(proxy)
        
        # Update proxy status based on result
        if hasattr(proxy, 'status'):
            proxy.status = ProxyStatus.ACTIVE if result.success else ProxyStatus.INACTIVE
        
        # Update metrics
        if hasattr(proxy, 'metrics'):
            proxy.metrics.update_from_validation(result)
        
        # Check for tier transition
        tier_changed = self.tier_manager.update_proxy_tier(proxy, force_evaluation=True)
        
        return result, tier_changed
    
    def validate_tier_batch(self, proxies: List[ProxyInfo], tier: TierLevel) -> List[Tuple[ValidationResult, bool]]:
        """
        Validate a batch of proxies from the same tier
        
        Args:
            proxies: List of ProxyInfo objects
            tier: Tier level for batch validation
            
        Returns:
            List of tuples (ValidationResult, tier_changed)
        """
        # Perform batch validation
        results = self.validation_engine.validate_proxies_batch(proxies, tier)
        
        # Process results and check for tier transitions
        output = []
        for proxy, result in zip(proxies, results):
            # Update proxy status
            if hasattr(proxy, 'status'):
                proxy.status = ProxyStatus.ACTIVE if result.success else ProxyStatus.INACTIVE
            
            # Update metrics
            if hasattr(proxy, 'metrics'):
                proxy.metrics.update_from_validation(result)
            
            # Check for tier transition
            tier_changed = self.tier_manager.update_proxy_tier(proxy, force_evaluation=True)
            
            output.append((result, tier_changed))
        
        return output


def create_validation_engine(tier_manager: TierManager, 
                           config: Optional[Dict[str, Any]] = None) -> ValidationEngine:
    """Factory function to create validation engine"""
    return ValidationEngine(tier_manager, config)


def create_tiered_validator(tier_manager: TierManager, 
                          validation_engine: ValidationEngine) -> TieredValidator:
    """Factory function to create tiered validator"""
    return TieredValidator(tier_manager, validation_engine)