"""Persistent Geographical Data Cache

Provides persistent storage for geographical IP data with SQLite backend.
Includes cache invalidation, TTL management, and integration with the geo manager.
"""

import logging
import sqlite3
import json
import time
import threading
import os
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class PersistentGeoCache:
    """SQLite-based persistent cache for geographical data"""
    
    def __init__(self, cache_file: str = "geo_cache.db", ttl: int = 86400, max_entries: int = 100000):
        """
        Initialize persistent geographical cache
        
        Args:
            cache_file: Path to SQLite cache file
            ttl: Time to live for cache entries in seconds (default: 24 hours)
            max_entries: Maximum number of cache entries before cleanup
        """
        self.cache_file = cache_file
        self.ttl = ttl
        self.max_entries = max_entries
        self.lock = threading.RLock()
        
        # Statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'writes': 0,
            'cleanups': 0,
            'errors': 0
        }
        
        # Initialize database
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize SQLite database with proper schema"""
        try:
            # Ensure directory exists
            cache_dir = os.path.dirname(os.path.abspath(self.cache_file))
            if cache_dir:
                os.makedirs(cache_dir, exist_ok=True)
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Create cache table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS geo_cache (
                        ip_address TEXT PRIMARY KEY,
                        geo_data TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        accessed_at INTEGER NOT NULL,
                        access_count INTEGER DEFAULT 1
                    )
                """)
                
                # Create indexes for performance
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_geo_cache_accessed_at 
                    ON geo_cache(accessed_at)
                """)
                
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_geo_cache_created_at 
                    ON geo_cache(created_at)
                """)
                
                # Create metadata table for cache statistics
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS cache_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at INTEGER NOT NULL
                    )
                """)
                
                conn.commit()
                logger.info(f"Geographical cache database initialized: {self.cache_file}")
                
        except Exception as e:
            logger.error(f"Failed to initialize geo cache database: {e}")
            raise
    
    @contextmanager
    def _get_connection(self):
        """Get database connection with proper error handling"""
        conn = None
        try:
            conn = sqlite3.connect(self.cache_file, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA mmap_size=268435456")  # 256MB mmap
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def get(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get cached geographical data for an IP address"""
        with self.lock:
            try:
                current_time = int(time.time())
                
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Get cached data
                    cursor.execute("""
                        SELECT geo_data, created_at, access_count
                        FROM geo_cache 
                        WHERE ip_address = ?
                    """, (ip_address,))
                    
                    row = cursor.fetchone()
                    
                    if row is None:
                        self.stats['misses'] += 1
                        return None
                    
                    geo_data_json, created_at, access_count = row
                    
                    # Check TTL
                    if current_time - created_at > self.ttl:
                        # Entry expired, remove it
                        cursor.execute("DELETE FROM geo_cache WHERE ip_address = ?", (ip_address,))
                        conn.commit()
                        self.stats['misses'] += 1
                        return None
                    
                    # Update access statistics
                    cursor.execute("""
                        UPDATE geo_cache 
                        SET accessed_at = ?, access_count = access_count + 1
                        WHERE ip_address = ?
                    """, (current_time, ip_address))
                    
                    conn.commit()
                    
                    # Parse and return data
                    geo_data = json.loads(geo_data_json)
                    self.stats['hits'] += 1
                    
                    logger.debug(f"Cache hit for {ip_address}")
                    return geo_data
                    
            except Exception as e:
                self.stats['errors'] += 1
                logger.error(f"Error getting cached data for {ip_address}: {e}")
                return None
    
    def set(self, ip_address: str, geo_data: Dict[str, Any]) -> bool:
        """Set cached geographical data for an IP address"""
        with self.lock:
            try:
                current_time = int(time.time())
                geo_data_json = json.dumps(geo_data)
                
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Insert or replace cache entry
                    cursor.execute("""
                        INSERT OR REPLACE INTO geo_cache 
                        (ip_address, geo_data, created_at, accessed_at, access_count)
                        VALUES (?, ?, ?, ?, 1)
                    """, (ip_address, geo_data_json, current_time, current_time))
                    
                    conn.commit()
                    self.stats['writes'] += 1
                    
                    logger.debug(f"Cached geo data for {ip_address}")
                    
                    # Check if cleanup is needed (async to avoid blocking)
                    if self.stats['writes'] % 1000 == 0:  # Check every 1000 writes
                        self._maybe_cleanup()
                    
                    return True
                    
            except Exception as e:
                self.stats['errors'] += 1
                logger.error(f"Error caching data for {ip_address}: {e}")
                return False
    
    def bulk_get(self, ip_addresses: List[str]) -> Dict[str, Optional[Dict[str, Any]]]:
        """Get cached data for multiple IP addresses"""
        results = {}
        
        if not ip_addresses:
            return results
        
        with self.lock:
            try:
                current_time = int(time.time())
                
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Prepare query with placeholders
                    placeholders = ','.join('?' for _ in ip_addresses)
                    
                    cursor.execute(f"""
                        SELECT ip_address, geo_data, created_at, access_count
                        FROM geo_cache 
                        WHERE ip_address IN ({placeholders})
                    """, ip_addresses)
                    
                    # Process results
                    found_ips = set()
                    updates = []
                    
                    for row in cursor.fetchall():
                        ip_address, geo_data_json, created_at, access_count = row
                        
                        # Check TTL
                        if current_time - created_at > self.ttl:
                            # Entry expired
                            results[ip_address] = None
                            continue
                        
                        # Parse data
                        try:
                            geo_data = json.loads(geo_data_json)
                            results[ip_address] = geo_data
                            found_ips.add(ip_address)
                            updates.append((current_time, ip_address))
                            self.stats['hits'] += 1
                        except json.JSONDecodeError:
                            results[ip_address] = None
                            logger.warning(f"Invalid JSON in cache for {ip_address}")
                    
                    # Update access statistics for found entries
                    if updates:
                        cursor.executemany("""
                            UPDATE geo_cache 
                            SET accessed_at = ?, access_count = access_count + 1
                            WHERE ip_address = ?
                        """, updates)
                    
                    # Mark missing IPs as cache misses
                    for ip_address in ip_addresses:
                        if ip_address not in found_ips:
                            results[ip_address] = None
                            self.stats['misses'] += 1
                    
                    conn.commit()
                    
                    logger.debug(f"Bulk cache lookup: {len(found_ips)}/{len(ip_addresses)} hits")
                    
            except Exception as e:
                self.stats['errors'] += 1
                logger.error(f"Error in bulk cache lookup: {e}")
                # Return None for all IPs on error
                for ip_address in ip_addresses:
                    results[ip_address] = None
        
        return results
    
    def bulk_set(self, geo_data_batch: Dict[str, Dict[str, Any]]) -> int:
        """Set cached data for multiple IP addresses"""
        if not geo_data_batch:
            return 0
        
        with self.lock:
            try:
                current_time = int(time.time())
                
                # Prepare batch data
                batch_data = []
                for ip_address, geo_data in geo_data_batch.items():
                    geo_data_json = json.dumps(geo_data)
                    batch_data.append((ip_address, geo_data_json, current_time, current_time))
                
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    
                    cursor.executemany("""
                        INSERT OR REPLACE INTO geo_cache 
                        (ip_address, geo_data, created_at, accessed_at, access_count)
                        VALUES (?, ?, ?, ?, 1)
                    """, batch_data)
                    
                    conn.commit()
                    
                    self.stats['writes'] += len(batch_data)
                    logger.debug(f"Bulk cached {len(batch_data)} geo entries")
                    
                    return len(batch_data)
                    
            except Exception as e:
                self.stats['errors'] += 1
                logger.error(f"Error in bulk cache write: {e}")
                return 0
    
    def _maybe_cleanup(self):
        """Check if cleanup is needed and perform it if necessary"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Count current entries
                cursor.execute("SELECT COUNT(*) FROM geo_cache")
                count = cursor.fetchone()[0]
                
                if count > self.max_entries:
                    self._cleanup_old_entries(conn, count - self.max_entries // 2)
                    
        except Exception as e:
            logger.error(f"Error checking cache size: {e}")
    
    def _cleanup_old_entries(self, conn, entries_to_remove: int):
        """Remove old cache entries"""
        try:
            cursor = conn.cursor()
            
            # Remove oldest entries by access time
            cursor.execute("""
                DELETE FROM geo_cache 
                WHERE ip_address IN (
                    SELECT ip_address FROM geo_cache 
                    ORDER BY accessed_at ASC 
                    LIMIT ?
                )
            """, (entries_to_remove,))
            
            removed = cursor.rowcount
            conn.commit()
            
            self.stats['cleanups'] += 1
            logger.info(f"Cleaned up {removed} old cache entries")
            
        except Exception as e:
            logger.error(f"Error cleaning up cache: {e}")
    
    def cleanup_expired(self) -> int:
        """Remove all expired cache entries"""
        with self.lock:
            try:
                current_time = int(time.time())
                expiry_time = current_time - self.ttl
                
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute("""
                        DELETE FROM geo_cache 
                        WHERE created_at < ?
                    """, (expiry_time,))
                    
                    removed = cursor.rowcount
                    conn.commit()
                    
                    logger.info(f"Removed {removed} expired cache entries")
                    return removed
                    
            except Exception as e:
                self.stats['errors'] += 1
                logger.error(f"Error cleaning up expired entries: {e}")
                return 0
    
    def clear_all(self) -> bool:
        """Clear all cached data"""
        with self.lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM geo_cache")
                    conn.commit()
                    
                    # Reset statistics
                    self.stats = {
                        'hits': 0,
                        'misses': 0,
                        'writes': 0,
                        'cleanups': 0,
                        'errors': 0
                    }
                    
                    logger.info("Cleared all cached geographical data")
                    return True
                    
            except Exception as e:
                self.stats['errors'] += 1
                logger.error(f"Error clearing cache: {e}")
                return False
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get cache information and statistics"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Get entry count
                cursor.execute("SELECT COUNT(*) FROM geo_cache")
                total_entries = cursor.fetchone()[0]
                
                # Get oldest and newest entries
                cursor.execute("""
                    SELECT MIN(created_at), MAX(created_at), 
                           MIN(accessed_at), MAX(accessed_at)
                    FROM geo_cache
                """)
                times = cursor.fetchone()
                
                # Calculate hit rate
                total_requests = self.stats['hits'] + self.stats['misses']
                hit_rate = (self.stats['hits'] / total_requests * 100) if total_requests > 0 else 0
                
                # Get database file size
                file_size = os.path.getsize(self.cache_file) if os.path.exists(self.cache_file) else 0
                
                return {
                    'cache_file': self.cache_file,
                    'total_entries': total_entries,
                    'max_entries': self.max_entries,
                    'ttl_seconds': self.ttl,
                    'file_size_bytes': file_size,
                    'file_size_mb': round(file_size / (1024 * 1024), 2),
                    'oldest_entry': datetime.fromtimestamp(times[0]).isoformat() if times[0] else None,
                    'newest_entry': datetime.fromtimestamp(times[1]).isoformat() if times[1] else None,
                    'oldest_access': datetime.fromtimestamp(times[2]).isoformat() if times[2] else None,
                    'newest_access': datetime.fromtimestamp(times[3]).isoformat() if times[3] else None,
                    'statistics': self.stats.copy(),
                    'hit_rate_percent': round(hit_rate, 2)
                }
                
        except Exception as e:
            logger.error(f"Error getting cache info: {e}")
            return {
                'error': str(e),
                'statistics': self.stats.copy()
            }
    
    def optimize_database(self) -> bool:
        """Optimize the SQLite database"""
        try:
            with self._get_connection() as conn:
                conn.execute("VACUUM")
                conn.execute("ANALYZE")
                logger.info("Geographical cache database optimized")
                return True
                
        except Exception as e:
            logger.error(f"Error optimizing cache database: {e}")
            return False
    
    def close(self):
        """Close the cache and cleanup resources"""
        try:
            # Final cleanup
            self.cleanup_expired()
            logger.info("Geographical cache closed")
        except Exception as e:
            logger.error(f"Error closing cache: {e}")


def create_persistent_geo_cache(cache_file: str = "geo_cache.db", 
                               ttl: int = 86400, 
                               max_entries: int = 100000) -> PersistentGeoCache:
    """Factory function to create persistent geographical cache"""
    return PersistentGeoCache(cache_file, ttl, max_entries)


if __name__ == "__main__":
    # Example usage and testing
    import tempfile
    
    # Create temporary cache for testing
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        test_cache_file = f.name
    
    try:
        # Create cache
        cache = create_persistent_geo_cache(test_cache_file, ttl=60)
        
        # Test data
        test_geo_data = {
            'country': 'United States',
            'country_code': 'US',
            'city': 'Mountain View',
            'region': 'North America',
            'latitude': 37.4223,
            'longitude': -122.0848,
            'source': 'test'
        }
        
        # Test set/get
        print("Testing cache operations...")
        
        # Set data
        success = cache.set('8.8.8.8', test_geo_data)
        print(f"Set operation: {'Success' if success else 'Failed'}")
        
        # Get data
        retrieved = cache.get('8.8.8.8')
        print(f"Get operation: {'Success' if retrieved else 'Failed'}")
        
        if retrieved:
            print(f"Retrieved data: {retrieved}")
        
        # Test bulk operations
        bulk_data = {
            '1.1.1.1': {'country': 'Australia', 'country_code': 'AU'},
            '8.8.4.4': {'country': 'United States', 'country_code': 'US'}
        }
        
        bulk_count = cache.bulk_set(bulk_data)
        print(f"Bulk set: {bulk_count} entries")
        
        bulk_results = cache.bulk_get(['1.1.1.1', '8.8.4.4', '9.9.9.9'])
        print(f"Bulk get results: {bulk_results}")
        
        # Show cache info
        info = cache.get_cache_info()
        print(f"Cache info: {info}")
        
        # Cleanup
        cache.close()
        
    finally:
        # Clean up test file
        import os
        try:
            os.unlink(test_cache_file)
        except:
            pass
        
        print("Test completed")