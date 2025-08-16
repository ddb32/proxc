"""Cache Configuration - Settings and policies for smart caching"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class CachePolicy(Enum):
    """Cache eviction policies"""
    TTL_FIRST = "ttl_first"        # Expire by time first, then LRU
    LRU_FIRST = "lru_first"        # Use LRU first, then TTL
    BALANCED = "balanced"          # Balance TTL and LRU eviction


@dataclass
class CacheConfig:
    """Configuration for smart caching system"""
    
    # TTL Settings
    validation_ttl: int = 3600      # 1 hour for successful validation results
    failure_ttl: int = 900          # 15 minutes for failed validation results
    geolocation_ttl: int = 86400    # 24 hours for geolocation data
    threat_analysis_ttl: int = 21600  # 6 hours for threat analysis
    
    # Memory Management
    max_memory_mb: Optional[int] = None      # Auto-calculated if None
    enable_auto_sizing: bool = True          # Enable dynamic size adjustment
    memory_usage_threshold: float = 0.8     # Scale down when > 80% of budget
    memory_scale_up_threshold: float = 0.6  # Scale up when < 60% of budget
    emergency_memory_mb: int = 200          # Emergency cleanup threshold
    
    # Cache Behavior
    cache_policy: CachePolicy = CachePolicy.BALANCED
    cleanup_interval: int = 300     # Background cleanup every 5 minutes
    max_entries_per_cache: int = 10000  # Hard limit per cache instance
    
    # Performance
    enable_metrics: bool = True     # Track performance metrics
    stats_interval: int = 600       # Log stats every 10 minutes
    
    # Cache Types
    enable_validation_cache: bool = True
    enable_geolocation_cache: bool = True
    enable_threat_cache: bool = True
    enable_header_analysis_cache: bool = True
    
    def get_ttl_for_result_type(self, result_type: str, is_success: bool = True) -> int:
        """Get appropriate TTL based on result type and success status"""
        if not is_success:
            return self.failure_ttl
            
        ttl_map = {
            'validation': self.validation_ttl,
            'geolocation': self.geolocation_ttl,
            'threat_analysis': self.threat_analysis_ttl,
            'header_analysis': self.validation_ttl,  # Same as validation
        }
        
        return ttl_map.get(result_type, self.validation_ttl)
    
    def to_dict(self):
        """Convert to dictionary for serialization"""
        return {
            'ttl_settings': {
                'validation_ttl': self.validation_ttl,
                'failure_ttl': self.failure_ttl,
                'geolocation_ttl': self.geolocation_ttl,
                'threat_analysis_ttl': self.threat_analysis_ttl,
            },
            'memory_management': {
                'max_memory_mb': self.max_memory_mb,
                'enable_auto_sizing': self.enable_auto_sizing,
                'memory_usage_threshold': self.memory_usage_threshold,
                'memory_scale_up_threshold': self.memory_scale_up_threshold,
                'emergency_memory_mb': self.emergency_memory_mb,
            },
            'cache_behavior': {
                'cache_policy': self.cache_policy.value,
                'cleanup_interval': self.cleanup_interval,
                'max_entries_per_cache': self.max_entries_per_cache,
            },
            'enabled_caches': {
                'validation': self.enable_validation_cache,
                'geolocation': self.enable_geolocation_cache,
                'threat': self.enable_threat_cache,
                'header_analysis': self.enable_header_analysis_cache,
            }
        }