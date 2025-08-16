"""Smart Caching System - TTL/LRU caching with dynamic resource management"""

from .smart_cache import (
    TTLCache,
    LRUCache, 
    SmartCache,
    AutoSizeCalculator,
    CacheMetrics
)
from .cache_config import CacheConfig, CachePolicy

__all__ = [
    'TTLCache',
    'LRUCache',
    'SmartCache', 
    'AutoSizeCalculator',
    'CacheMetrics',
    'CacheConfig',
    'CachePolicy'
]