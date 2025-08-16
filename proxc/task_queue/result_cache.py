"""
Result Cache for Proxy Hunter Task Queue
========================================

Provides intelligent caching of task results with TTL management,
compression, and cache optimization strategies.
"""

import json
import logging
import time
import zlib
from typing import Optional, Dict, Any, List, Set
from datetime import datetime, timedelta
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    key: str
    value: Any
    created_at: datetime
    accessed_at: datetime
    access_count: int
    size_bytes: int
    compressed: bool = False

class ResultCache:
    """Intelligent result caching with optimization strategies"""
    
    def __init__(self, redis_backend, default_ttl: int = 3600):
        """Initialize result cache with Redis backend
        
        Args:
            redis_backend: Redis backend instance
            default_ttl: Default cache TTL in seconds
        """
        self.redis_backend = redis_backend
        self.default_ttl = default_ttl
        self.compression_threshold = 1024  # Compress results larger than 1KB
        self.max_cache_size = 100_000_000  # 100MB max cache size
        
        # Cache statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'evictions': 0,
            'compressions': 0,
            'decompressions': 0
        }
        
        logger.info(f"Result cache initialized with {default_ttl}s default TTL")
    
    def _generate_cache_key(self, task_id: str, namespace: str = "result") -> str:
        """Generate cache key with namespace"""
        return f"proxc:cache:{namespace}:{task_id}"
    
    def _should_compress(self, data: bytes) -> bool:
        """Determine if data should be compressed"""
        return len(data) >= self.compression_threshold
    
    def _compress_data(self, data: str) -> bytes:
        """Compress data using zlib"""
        try:
            compressed = zlib.compress(data.encode('utf-8'))
            self.stats['compressions'] += 1
            logger.debug(f"Compressed data: {len(data)} -> {len(compressed)} bytes")
            return compressed
        except Exception as e:
            logger.error(f"Compression failed: {e}")
            return data.encode('utf-8')
    
    def _decompress_data(self, data: bytes) -> str:
        """Decompress data using zlib"""
        try:
            decompressed = zlib.decompress(data).decode('utf-8')
            self.stats['decompressions'] += 1
            return decompressed
        except Exception as e:
            logger.error(f"Decompression failed: {e}")
            return data.decode('utf-8')
    
    def cache_result(self, 
                    task_id: str, 
                    result: Dict[str, Any], 
                    ttl: Optional[int] = None,
                    namespace: str = "result") -> bool:
        """Cache task result with optional compression
        
        Args:
            task_id: Task identifier
            result: Result data to cache
            ttl: Time to live in seconds
            namespace: Cache namespace
            
        Returns:
            bool: True if cached successfully
        """
        if not self.redis_backend.is_healthy():
            return False
        
        try:
            cache_key = self._generate_cache_key(task_id, namespace)
            ttl = ttl or self.default_ttl
            
            # Serialize result
            serialized_data = json.dumps(result, default=str)
            
            # Check if compression is beneficial
            if self._should_compress(serialized_data.encode('utf-8')):
                # Compress and store with compression flag
                compressed_data = self._compress_data(serialized_data)
                
                # Store compressed data with metadata
                cache_data = {
                    'data': compressed_data,
                    'compressed': True,
                    'created_at': datetime.utcnow().isoformat(),
                    'size_original': len(serialized_data),
                    'size_compressed': len(compressed_data)
                }
                
                # Use binary-safe storage for compressed data
                pipeline = self.redis_backend.redis_client.pipeline()
                pipeline.hset(cache_key, "compressed_data", compressed_data)
                pipeline.hset(cache_key, "metadata", json.dumps({
                    'compressed': True,
                    'created_at': cache_data['created_at'],
                    'size_original': cache_data['size_original'],
                    'size_compressed': cache_data['size_compressed'],
                    'access_count': 0
                }))
                pipeline.expire(cache_key, ttl)
                pipeline.execute()
                
            else:
                # Store uncompressed
                cache_data = {
                    'data': serialized_data,
                    'compressed': False,
                    'created_at': datetime.utcnow().isoformat(),
                    'size': len(serialized_data),
                    'access_count': 0
                }
                
                self.redis_backend.redis_client.setex(
                    cache_key, 
                    ttl, 
                    json.dumps(cache_data)
                )
            
            self.stats['sets'] += 1
            logger.debug(f"Cached result for task {task_id} (TTL: {ttl}s)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cache result for task {task_id}: {e}")
            return False
    
    def get_cached_result(self, 
                         task_id: str, 
                         namespace: str = "result") -> Optional[Dict[str, Any]]:
        """Retrieve cached result with decompression if needed
        
        Args:
            task_id: Task identifier
            namespace: Cache namespace
            
        Returns:
            Optional[Dict[str, Any]]: Cached result or None
        """
        if not self.redis_backend.is_healthy():
            return None
        
        try:
            cache_key = self._generate_cache_key(task_id, namespace)
            
            # Check if it's a compressed entry (hash) or regular entry
            if self.redis_backend.redis_client.type(cache_key) == 'hash':
                # Compressed entry
                metadata_str = self.redis_backend.redis_client.hget(cache_key, "metadata")
                compressed_data = self.redis_backend.redis_client.hget(cache_key, "compressed_data")
                
                if metadata_str and compressed_data:
                    metadata = json.loads(metadata_str)
                    
                    # Decompress data
                    decompressed_data = self._decompress_data(compressed_data)
                    result = json.loads(decompressed_data)
                    
                    # Update access statistics
                    metadata['access_count'] = metadata.get('access_count', 0) + 1
                    metadata['last_accessed'] = datetime.utcnow().isoformat()
                    
                    self.redis_backend.redis_client.hset(
                        cache_key, "metadata", json.dumps(metadata)
                    )
                    
                    self.stats['hits'] += 1
                    logger.debug(f"Cache hit for task {task_id} (compressed)")
                    return result
                    
            else:
                # Regular entry
                cached_data = self.redis_backend.redis_client.get(cache_key)
                
                if cached_data:
                    cache_entry = json.loads(cached_data)
                    
                    # Update access statistics
                    cache_entry['access_count'] = cache_entry.get('access_count', 0) + 1
                    cache_entry['last_accessed'] = datetime.utcnow().isoformat()
                    
                    # Update cache with new stats (without changing TTL)
                    ttl = self.redis_backend.redis_client.ttl(cache_key)
                    if ttl > 0:
                        self.redis_backend.redis_client.setex(
                            cache_key, ttl, json.dumps(cache_entry)
                        )
                    
                    self.stats['hits'] += 1
                    logger.debug(f"Cache hit for task {task_id}")
                    
                    if cache_entry.get('compressed'):
                        return json.loads(self._decompress_data(cache_entry['data']))
                    else:
                        return json.loads(cache_entry['data'])
            
            # Cache miss
            self.stats['misses'] += 1
            logger.debug(f"Cache miss for task {task_id}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to retrieve cached result for task {task_id}: {e}")
            self.stats['misses'] += 1
            return None
    
    def invalidate_cache(self, task_id: str, namespace: str = "result") -> bool:
        """Invalidate cached result
        
        Args:
            task_id: Task identifier
            namespace: Cache namespace
            
        Returns:
            bool: True if invalidated successfully
        """
        if not self.redis_backend.is_healthy():
            return False
        
        try:
            cache_key = self._generate_cache_key(task_id, namespace)
            deleted = self.redis_backend.redis_client.delete(cache_key)
            
            if deleted:
                logger.debug(f"Invalidated cache for task {task_id}")
                return True
            else:
                logger.debug(f"No cache entry found for task {task_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to invalidate cache for task {task_id}: {e}")
            return False
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics"""
        if not self.redis_backend.is_healthy():
            return {}
        
        try:
            # Get Redis memory info
            redis_info = self.redis_backend.redis_client.info('memory')
            
            # Count cache entries
            cache_pattern = "proxc:cache:*"
            cache_keys = self.redis_backend.redis_client.keys(cache_pattern)
            
            # Calculate cache efficiency
            total_requests = self.stats['hits'] + self.stats['misses']
            hit_rate = self.stats['hits'] / max(1, total_requests)
            
            # Calculate compression stats
            compression_rate = self.stats['compressions'] / max(1, self.stats['sets'])
            
            return {
                'cache_entries': len(cache_keys),
                'total_requests': total_requests,
                'hits': self.stats['hits'],
                'misses': self.stats['misses'],
                'hit_rate': hit_rate,
                'sets': self.stats['sets'],
                'evictions': self.stats['evictions'],
                'compressions': self.stats['compressions'],
                'decompressions': self.stats['decompressions'],
                'compression_rate': compression_rate,
                'redis_memory_used': redis_info.get('used_memory', 0),
                'redis_memory_peak': redis_info.get('used_memory_peak', 0),
            }
            
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {}
    
    def cleanup_expired_entries(self) -> int:
        """Clean up expired cache entries and return count
        
        Returns:
            int: Number of cleaned up entries
        """
        if not self.redis_backend.is_healthy():
            return 0
        
        try:
            cleaned_count = 0
            
            # Get all cache keys
            cache_pattern = "proxc:cache:*"
            cache_keys = self.redis_backend.redis_client.keys(cache_pattern)
            
            for key in cache_keys:
                ttl = self.redis_backend.redis_client.ttl(key)
                
                # Remove expired keys (TTL = -2 means expired, -1 means no expiry)
                if ttl == -2:
                    self.redis_backend.redis_client.delete(key)
                    cleaned_count += 1
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired cache entries")
                self.stats['evictions'] += cleaned_count
            
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired entries: {e}")
            return 0
    
    def optimize_cache(self) -> Dict[str, Any]:
        """Optimize cache by removing least accessed entries if needed
        
        Returns:
            Dict[str, Any]: Optimization results
        """
        if not self.redis_backend.is_healthy():
            return {}
        
        try:
            # Get current memory usage
            redis_info = self.redis_backend.redis_client.info('memory')
            current_memory = redis_info.get('used_memory', 0)
            
            optimization_results = {
                'memory_before': current_memory,
                'entries_removed': 0,
                'memory_saved': 0
            }
            
            # Check if optimization is needed
            if current_memory < self.max_cache_size:
                logger.debug("Cache size within limits, no optimization needed")
                return optimization_results
            
            logger.info(f"Cache optimization needed: {current_memory} bytes > {self.max_cache_size} bytes")
            
            # Get all cache entries with access stats
            cache_pattern = "proxc:cache:result:*"
            cache_keys = self.redis_backend.redis_client.keys(cache_pattern)
            
            # Sort by access count (ascending) to remove least accessed first
            entries_with_stats = []
            
            for key in cache_keys:
                try:
                    if self.redis_backend.redis_client.type(key) == 'hash':
                        # Compressed entry
                        metadata_str = self.redis_backend.redis_client.hget(key, "metadata")
                        if metadata_str:
                            metadata = json.loads(metadata_str)
                            access_count = metadata.get('access_count', 0)
                            entries_with_stats.append((key, access_count))
                    else:
                        # Regular entry
                        cached_data = self.redis_backend.redis_client.get(key)
                        if cached_data:
                            cache_entry = json.loads(cached_data)
                            access_count = cache_entry.get('access_count', 0)
                            entries_with_stats.append((key, access_count))
                            
                except Exception as e:
                    logger.debug(f"Skipping problematic cache key {key}: {e}")
            
            # Sort by access count (least accessed first)
            entries_with_stats.sort(key=lambda x: x[1])
            
            # Remove least accessed entries until we're under the memory limit
            removed_count = 0
            target_removal = min(len(entries_with_stats) // 4, 1000)  # Remove up to 25% or 1000 entries
            
            for key, access_count in entries_with_stats[:target_removal]:
                if self.redis_backend.redis_client.delete(key):
                    removed_count += 1
            
            # Get memory usage after optimization
            redis_info_after = self.redis_backend.redis_client.info('memory')
            memory_after = redis_info_after.get('used_memory', current_memory)
            
            optimization_results.update({
                'entries_removed': removed_count,
                'memory_after': memory_after,
                'memory_saved': current_memory - memory_after
            })
            
            self.stats['evictions'] += removed_count
            
            logger.info(f"Cache optimization completed: removed {removed_count} entries, "
                       f"saved {optimization_results['memory_saved']} bytes")
            
            return optimization_results
            
        except Exception as e:
            logger.error(f"Cache optimization failed: {e}")
            return optimization_results
    
    def clear_namespace(self, namespace: str = "result") -> int:
        """Clear all cache entries in a namespace
        
        Args:
            namespace: Namespace to clear
            
        Returns:
            int: Number of cleared entries
        """
        if not self.redis_backend.is_healthy():
            return 0
        
        try:
            pattern = f"proxc:cache:{namespace}:*"
            keys = self.redis_backend.redis_client.keys(pattern)
            
            if keys:
                deleted = self.redis_backend.redis_client.delete(*keys)
                logger.info(f"Cleared {deleted} entries from namespace {namespace}")
                return deleted
            else:
                logger.debug(f"No entries found in namespace {namespace}")
                return 0
                
        except Exception as e:
            logger.error(f"Failed to clear namespace {namespace}: {e}")
            return 0