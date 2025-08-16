"""Smart Cache Implementation - TTL/LRU caching with dynamic resource management"""

import hashlib
import logging
import psutil
import threading
import time
import weakref
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple, Union, List

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
        
        self.logger.info(f"SmartCache '{name}' initialized with policy: {config.cache_policy.value}")
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache with policy-based lookup"""
        if self.config.cache_policy == CachePolicy.BALANCED and self.secondary_cache:
            # Try TTL cache first, then LRU cache
            value = self.primary_cache.get(key)
            if value is not None:
                # Also store in LRU for frequent access tracking
                self.secondary_cache.put(key, value)
                return value
            
            value = self.secondary_cache.get(key)
            if value is not None:
                # Refresh in TTL cache
                self.primary_cache.put(key, value)
                return value
            
            return None
        else:
            return self.primary_cache.get(key)
    
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
        
        metrics = {
            'cache_name': self.name,
            'cache_policy': self.config.cache_policy.value,
            'combined': self.combined_metrics.to_dict(),
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
    
    def shutdown(self):
        """Shutdown cache and cleanup resources"""
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