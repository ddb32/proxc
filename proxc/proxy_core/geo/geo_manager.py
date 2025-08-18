"""Geographic Information Manager

Provides comprehensive geographical data enrichment for proxy IPs using multiple data sources.
Includes intelligent caching, fallback mechanisms, and bulk processing capabilities.
"""

import logging
import json
import time
import os
import random
from typing import Optional, Dict, List, Any, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from ipaddress import ip_address, AddressValueError
import threading

# Optional imports with fallbacks
try:
    import geoip2.database
    import geoip2.errors
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Import persistent cache
try:
    from ...database.geo_cache import PersistentGeoCache, create_persistent_geo_cache
    HAS_PERSISTENT_CACHE = True
except ImportError:
    HAS_PERSISTENT_CACHE = False

logger = logging.getLogger(__name__)


class GeoCache:
    """Thread-safe in-memory cache for geographical data"""
    
    def __init__(self, max_size: int = 10000, ttl: int = 3600):
        self.max_size = max_size
        self.ttl = ttl
        self.cache = {}
        self.timestamps = {}
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached geographical data"""
        with self.lock:
            if key not in self.cache:
                self.misses += 1
                return None
            
            # Check TTL
            if time.time() - self.timestamps[key] > self.ttl:
                del self.cache[key]
                del self.timestamps[key]
                self.misses += 1
                return None
            
            self.hits += 1
            return self.cache[key].copy()
    
    def set(self, key: str, value: Dict[str, Any]):
        """Set cached geographical data"""
        with self.lock:
            # Implement LRU eviction if at capacity
            if len(self.cache) >= self.max_size:
                # Remove oldest entry
                oldest_key = min(self.timestamps.keys(), key=lambda k: self.timestamps[k])
                del self.cache[oldest_key]
                del self.timestamps[oldest_key]
            
            self.cache[key] = value.copy()
            self.timestamps[key] = time.time()
    
    def clear(self):
        """Clear all cached data"""
        with self.lock:
            self.cache.clear()
            self.timestamps.clear()
            self.hits = 0
            self.misses = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'cache_size': len(self.cache),
                'max_size': self.max_size,
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': hit_rate,
                'ttl': self.ttl
            }


class GeoIPManager:
    """Comprehensive geographical IP data manager with multiple data sources"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.cache = GeoCache(
            max_size=self.config.get('cache_max_size', 10000),
            ttl=self.config.get('cache_ttl', 3600)
        )
        
        # Persistent cache
        self.persistent_cache = None
        if HAS_PERSISTENT_CACHE and self.config.get('use_persistent_cache', True):
            cache_file = self.config.get('persistent_cache_file', 'geo_cache.db')
            cache_ttl = self.config.get('persistent_cache_ttl', 86400)  # 24 hours
            try:
                self.persistent_cache = create_persistent_geo_cache(
                    cache_file=cache_file,
                    ttl=cache_ttl,
                    max_entries=self.config.get('persistent_cache_max_entries', 100000)
                )
                logger.info(f"Persistent geographical cache enabled: {cache_file}")
            except Exception as e:
                logger.warning(f"Failed to initialize persistent cache: {e}")
                self.persistent_cache = None
        
        # GeoIP2 database
        self.geoip2_reader = None
        self.geoip2_db_path = self.config.get('geoip2_db_path', None)
        
        # API endpoints for fallback with retry configuration
        self.api_endpoints = self.config.get('api_endpoints', [
            'http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,isp,org,timezone,query',
            'https://ipapi.co/{ip}/json/',
            'http://www.geoplugin.net/json.gp?ip={ip}'
        ])
        
        # Enhanced retry and fallback configuration
        self.api_rate_limit = self.config.get('api_rate_limit', 1.0)  # seconds between API calls
        self.max_retries = self.config.get('max_retries', 3)
        self.retry_delay = self.config.get('retry_delay', 1.0)  # base delay for exponential backoff
        self.max_retry_delay = self.config.get('max_retry_delay', 30.0)
        self.timeout = self.config.get('timeout', 10.0)
        self.last_api_call = 0
        
        # API failure tracking
        self.api_failures = {}  # endpoint -> failure count
        self.api_last_failure = {}  # endpoint -> last failure time
        self.api_backoff_time = self.config.get('api_backoff_time', 300)  # 5 minutes backoff
        
        # Region mapping
        self.region_mapping = {
            'AF': 'Africa',
            'AS': 'Asia', 
            'EU': 'Europe',
            'NA': 'North America',
            'SA': 'South America',
            'OC': 'Oceania',
            'AN': 'Antarctica'
        }
        
        # Country to continent mapping (simplified)
        self.country_to_continent = {
            'US': 'NA', 'CA': 'NA', 'MX': 'NA',
            'GB': 'EU', 'DE': 'EU', 'FR': 'EU', 'IT': 'EU', 'ES': 'EU', 'NL': 'EU', 'RU': 'EU',
            'CN': 'AS', 'JP': 'AS', 'IN': 'AS', 'KR': 'AS', 'SG': 'AS', 'TH': 'AS', 'VN': 'AS',
            'AU': 'OC', 'NZ': 'OC',
            'BR': 'SA', 'AR': 'SA', 'CL': 'SA', 'PE': 'SA', 'CO': 'SA',
            'ZA': 'AF', 'NG': 'AF', 'KE': 'AF', 'EG': 'AF', 'MA': 'AF'
        }
        
        self._initialize_geoip2()
    
    def _initialize_geoip2(self):
        """Initialize GeoIP2 database if available"""
        if not HAS_GEOIP2:
            logger.info("GeoIP2 not available. Install with: pip install geoip2")
            return
        
        # Try to find GeoIP2 database
        potential_paths = [
            self.geoip2_db_path,
            'GeoLite2-City.mmdb',
            'GeoLite2-Country.mmdb',
            '/usr/share/GeoIP/GeoLite2-City.mmdb',
            '/var/lib/GeoIP/GeoLite2-City.mmdb',
            os.path.expanduser('~/GeoLite2-City.mmdb')
        ]
        
        for path in potential_paths:
            if path and os.path.exists(path):
                try:
                    self.geoip2_reader = geoip2.database.Reader(path)
                    logger.info(f"GeoIP2 database loaded from: {path}")
                    return
                except Exception as e:
                    logger.warning(f"Failed to load GeoIP2 database from {path}: {e}")
        
        logger.warning("No GeoIP2 database found. Using API fallback only.")
    
    def get_geographical_info(self, ip_address_str: str, use_cache: bool = True) -> Dict[str, Any]:
        """Get comprehensive geographical information for an IP address with enhanced fallback"""
        try:
            # Validate IP address
            ip_addr = ip_address(ip_address_str)
            if ip_addr.is_private or ip_addr.is_loopback or ip_addr.is_multicast:
                return self._create_default_geo_info(ip_address_str, "Private/Local IP")
        except (AddressValueError, ValueError):
            return self._create_default_geo_info(ip_address_str, "Invalid IP address")
        
        # Multi-tier caching check
        if use_cache:
            # 1. Check in-memory cache first (fastest)
            cached_data = self.cache.get(ip_address_str)
            if cached_data:
                logger.debug(f"Memory cache hit for {ip_address_str}")
                return cached_data
            
            # 2. Check persistent cache (if available)
            if self.persistent_cache:
                persistent_data = self.persistent_cache.get(ip_address_str)
                if persistent_data:
                    logger.debug(f"Persistent cache hit for {ip_address_str}")
                    # Also store in memory cache for faster future access
                    self.cache.set(ip_address_str, persistent_data)
                    return persistent_data
        
        # Try multiple data sources with enhanced fallback
        geo_info = None
        
        # 1. Try GeoIP2 database first (fastest and most reliable)
        try:
            geo_info = self._get_geoip2_info(ip_address_str)
            if geo_info and geo_info.get('status') == 'success':
                logger.debug(f"GeoIP2 success for {ip_address_str}")
            else:
                geo_info = None
        except Exception as e:
            logger.debug(f"GeoIP2 failed for {ip_address_str}: {e}")
            geo_info = None
        
        # 2. Fallback to API with retry logic
        if not geo_info:
            geo_info = self._get_api_info_with_retry(ip_address_str)
        
        # 3. Last resort: try to get partial data from other sources
        if not geo_info:
            geo_info = self._get_fallback_info(ip_address_str)
        
        # Enhance with region information
        if geo_info and geo_info.get('country_code'):
            geo_info['region'] = self._get_region_for_country(geo_info['country_code'])
        
        # Cache the result in both caches
        if use_cache and geo_info and geo_info.get('status') == 'success':
            self.cache.set(ip_address_str, geo_info)
            if self.persistent_cache:
                self.persistent_cache.set(ip_address_str, geo_info)
        
        return geo_info or self._create_default_geo_info(ip_address_str, "No data available")
    
    def _get_geoip2_info(self, ip_address_str: str) -> Optional[Dict[str, Any]]:
        """Get geographical info using GeoIP2 database"""
        if not self.geoip2_reader:
            return None
        
        try:
            response = self.geoip2_reader.city(ip_address_str)
            
            return {
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'city': response.city.name,
                'latitude': float(response.location.latitude) if response.location.latitude else None,
                'longitude': float(response.location.longitude) if response.location.longitude else None,
                'timezone': response.location.time_zone,
                'asn': None,  # Not available in city database
                'isp': None,  # Not available in city database
                'organization': None,
                'source': 'geoip2',
                'status': 'success'
            }
        
        except geoip2.errors.AddressNotFoundError:
            logger.debug(f"IP {ip_address_str} not found in GeoIP2 database")
            return None
        except Exception as e:
            logger.warning(f"GeoIP2 lookup failed for {ip_address_str}: {e}")
            return None
    
    def _get_api_info_with_retry(self, ip_address_str: str) -> Optional[Dict[str, Any]]:
        """Get geographical info using API fallback with retry logic"""
        if not HAS_REQUESTS:
            logger.warning("Requests library not available for API fallback")
            return None
        
        current_time = time.time()
        
        # Try each endpoint with retry logic
        for endpoint in self.api_endpoints:
            # Check if this endpoint is in backoff period
            if endpoint in self.api_last_failure:
                time_since_failure = current_time - self.api_last_failure[endpoint]
                if time_since_failure < self.api_backoff_time:
                    logger.debug(f"Skipping {endpoint} - still in backoff period")
                    continue
            
            # Try this endpoint with retries
            geo_info = self._try_api_endpoint_with_retry(ip_address_str, endpoint)
            if geo_info and geo_info.get('status') == 'success':
                # Reset failure count on success
                self.api_failures.pop(endpoint, None)
                self.api_last_failure.pop(endpoint, None)
                return geo_info
        
        return None
    
    def _try_api_endpoint_with_retry(self, ip_address_str: str, endpoint: str) -> Optional[Dict[str, Any]]:
        """Try a single API endpoint with exponential backoff retry"""
        for attempt in range(self.max_retries):
            try:
                # Rate limiting
                current_time = time.time()
                if current_time - self.last_api_call < self.api_rate_limit:
                    time.sleep(self.api_rate_limit - (current_time - self.last_api_call))
                
                url = endpoint.format(ip=ip_address_str)
                self.last_api_call = time.time()
                
                # Add some jitter to avoid thundering herd
                jitter = random.uniform(0, 0.5)
                if attempt > 0:
                    time.sleep(jitter)
                
                response = requests.get(url, timeout=self.timeout)
                response.raise_for_status()
                
                data = response.json()
                
                # Parse response based on API format
                geo_info = self._parse_api_response(data, endpoint)
                if geo_info and geo_info.get('status') == 'success':
                    logger.debug(f"API lookup successful for {ip_address_str} using {endpoint} (attempt {attempt + 1})")
                    return geo_info
                
            except requests.exceptions.Timeout as e:
                logger.debug(f"Timeout for {ip_address_str} using {endpoint} (attempt {attempt + 1}): {e}")
                self._record_api_failure(endpoint)
                
            except requests.exceptions.RequestException as e:
                logger.debug(f"Request failed for {ip_address_str} using {endpoint} (attempt {attempt + 1}): {e}")
                self._record_api_failure(endpoint)
                
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                logger.debug(f"Invalid response for {ip_address_str} using {endpoint} (attempt {attempt + 1}): {e}")
                # Don't retry on parsing errors
                break
                
            except Exception as e:
                logger.debug(f"Unexpected error for {ip_address_str} using {endpoint} (attempt {attempt + 1}): {e}")
                self._record_api_failure(endpoint)
            
            # Exponential backoff with jitter
            if attempt < self.max_retries - 1:
                delay = min(self.retry_delay * (2 ** attempt), self.max_retry_delay)
                jitter = random.uniform(0, delay * 0.1)  # Add up to 10% jitter
                time.sleep(delay + jitter)
        
        logger.warning(f"All retry attempts failed for {ip_address_str} using {endpoint}")
        return None
    
    def _record_api_failure(self, endpoint: str):
        """Record API failure for backoff management"""
        self.api_failures[endpoint] = self.api_failures.get(endpoint, 0) + 1
        self.api_last_failure[endpoint] = time.time()
        
        failure_count = self.api_failures[endpoint]
        if failure_count >= 5:
            logger.warning(f"API endpoint {endpoint} has {failure_count} consecutive failures")
    
    def _get_fallback_info(self, ip_address_str: str) -> Optional[Dict[str, Any]]:
        """Last resort fallback using simple heuristics"""
        try:
            # Try to infer basic information from IP address patterns
            # This is very basic and should only be used as last resort
            
            # Check if it's a known public DNS or CDN
            known_ips = {
                '8.8.8.8': {'country': 'United States', 'country_code': 'US', 'city': 'Mountain View'},
                '8.8.4.4': {'country': 'United States', 'country_code': 'US', 'city': 'Mountain View'},
                '1.1.1.1': {'country': 'United States', 'country_code': 'US', 'city': 'San Francisco'},
                '1.0.0.1': {'country': 'United States', 'country_code': 'US', 'city': 'San Francisco'},
                '208.67.222.222': {'country': 'United States', 'country_code': 'US', 'city': 'San Francisco'},
                '208.67.220.220': {'country': 'United States', 'country_code': 'US', 'city': 'San Francisco'},
            }
            
            if ip_address_str in known_ips:
                fallback_data = known_ips[ip_address_str].copy()
                fallback_data.update({
                    'latitude': None,
                    'longitude': None,
                    'timezone': None,
                    'asn': None,
                    'isp': None,
                    'organization': None,
                    'source': 'fallback_hardcoded',
                    'status': 'success'
                })
                logger.debug(f"Using hardcoded fallback data for {ip_address_str}")
                return fallback_data
            
            # Try to get country from IP range (very basic)
            # This would need a proper IP-to-country database for real implementation
            fallback_info = self._create_default_geo_info(ip_address_str, "Fallback attempt")
            fallback_info['status'] = 'fallback'
            fallback_info['source'] = 'fallback_basic'
            
            return fallback_info
            
        except Exception as e:
            logger.debug(f"Fallback lookup failed for {ip_address_str}: {e}")
            return None
    
    def _get_api_info(self, ip_address_str: str) -> Optional[Dict[str, Any]]:
        """Get geographical info using API fallback (legacy method)"""
        # Redirect to enhanced method
        return self._get_api_info_with_retry(ip_address_str)
    
    def _parse_api_response(self, data: Dict[str, Any], endpoint: str) -> Optional[Dict[str, Any]]:
        """Parse API response based on endpoint format"""
        try:
            if 'ip-api.com' in endpoint:
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'asn': data.get('as'),
                        'isp': data.get('isp'),
                        'organization': data.get('org'),
                        'source': 'ip-api',
                        'status': 'success'
                    }
            
            elif 'ipapi.co' in endpoint:
                if data.get('error'):
                    return None
                return {
                    'country': data.get('country_name'),
                    'country_code': data.get('country_code'),
                    'city': data.get('city'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'timezone': data.get('timezone'),
                    'asn': data.get('asn'),
                    'isp': data.get('org'),
                    'organization': data.get('org'),
                    'source': 'ipapi',
                    'status': 'success'
                }
            
            elif 'geoplugin.net' in endpoint:
                if data.get('geoplugin_status') == 200:
                    return {
                        'country': data.get('geoplugin_countryName'),
                        'country_code': data.get('geoplugin_countryCode'),
                        'city': data.get('geoplugin_city'),
                        'latitude': float(data.get('geoplugin_latitude')) if data.get('geoplugin_latitude') else None,
                        'longitude': float(data.get('geoplugin_longitude')) if data.get('geoplugin_longitude') else None,
                        'timezone': data.get('geoplugin_timezone'),
                        'asn': None,
                        'isp': None,
                        'organization': None,
                        'source': 'geoplugin',
                        'status': 'success'
                    }
        
        except Exception as e:
            logger.warning(f"Failed to parse API response: {e}")
        
        return None
    
    def _get_region_for_country(self, country_code: str) -> Optional[str]:
        """Get continent/region for a country code"""
        continent_code = self.country_to_continent.get(country_code.upper())
        return self.region_mapping.get(continent_code) if continent_code else None
    
    def _create_default_geo_info(self, ip_address_str: str, reason: str) -> Dict[str, Any]:
        """Create default geo info structure"""
        return {
            'country': None,
            'country_code': None,
            'city': None,
            'latitude': None,
            'longitude': None,
            'timezone': None,
            'asn': None,
            'isp': None,
            'organization': None,
            'region': None,
            'source': 'unknown',
            'status': 'unknown',
            'reason': reason
        }
    
    def bulk_lookup(self, ip_addresses: List[str], max_workers: int = 10) -> Dict[str, Dict[str, Any]]:
        """Perform bulk geographical lookups with enhanced caching and parallel processing"""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        results = {}
        
        # Multi-tier cache check for all IPs
        uncached_ips = []
        
        # 1. Check in-memory cache first
        for ip_addr in ip_addresses:
            cached_data = self.cache.get(ip_addr)
            if cached_data:
                results[ip_addr] = cached_data
            else:
                uncached_ips.append(ip_addr)
        
        # 2. Check persistent cache for remaining IPs
        if uncached_ips and self.persistent_cache:
            persistent_results = self.persistent_cache.bulk_get(uncached_ips)
            newly_uncached = []
            
            for ip_addr in uncached_ips:
                persistent_data = persistent_results.get(ip_addr)
                if persistent_data:
                    results[ip_addr] = persistent_data
                    # Also cache in memory for faster future access
                    self.cache.set(ip_addr, persistent_data)
                else:
                    newly_uncached.append(ip_addr)
            
            uncached_ips = newly_uncached
        
        if not uncached_ips:
            logger.debug(f"All {len(ip_addresses)} IPs found in cache")
            return results
        
        logger.info(f"Performing bulk lookup for {len(uncached_ips)} uncached IPs")
        
        # Process uncached IPs in parallel with enhanced error handling
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit tasks
            future_to_ip = {
                executor.submit(self._safe_geographical_lookup, ip_addr): ip_addr
                for ip_addr in uncached_ips
            }
            
            # Collect results with progress tracking
            completed = 0
            total = len(uncached_ips)
            
            for future in as_completed(future_to_ip):
                ip_addr = future_to_ip[future]
                completed += 1
                
                try:
                    geo_info = future.result()
                    results[ip_addr] = geo_info
                    
                    # Cache successful results in both caches
                    if geo_info and geo_info.get('status') == 'success':
                        self.cache.set(ip_addr, geo_info)
                        if self.persistent_cache:
                            self.persistent_cache.set(ip_addr, geo_info)
                    
                    if completed % 100 == 0 or completed == total:
                        logger.debug(f"Bulk lookup progress: {completed}/{total}")
                        
                except Exception as e:
                    logger.error(f"Bulk lookup failed for {ip_addr}: {e}")
                    results[ip_addr] = self._create_default_geo_info(ip_addr, f"Lookup error: {e}")
        
        # Batch write to persistent cache for better performance
        if self.persistent_cache and uncached_ips:
            successful_results = {
                ip: info for ip, info in results.items() 
                if ip in uncached_ips and info.get('status') == 'success'
            }
            if successful_results:
                self.persistent_cache.bulk_set(successful_results)
        
        logger.info(f"Bulk lookup completed: {len(results)} total results")
        return results
    
    def _safe_geographical_lookup(self, ip_address_str: str) -> Dict[str, Any]:
        """Safe wrapper for geographical lookup with error handling"""
        try:
            return self.get_geographical_info(ip_address_str, use_cache=False)
        except Exception as e:
            logger.error(f"Safe lookup failed for {ip_address_str}: {e}")
            return self._create_default_geo_info(ip_address_str, f"Safe lookup error: {e}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics"""
        stats = {
            'memory_cache': self.cache.get_stats(),
            'persistent_cache': None,
            'api_failures': dict(self.api_failures),
            'api_endpoints_count': len(self.api_endpoints)
        }
        
        if self.persistent_cache:
            try:
                stats['persistent_cache'] = self.persistent_cache.get_cache_info()
            except Exception as e:
                logger.error(f"Error getting persistent cache stats: {e}")
                stats['persistent_cache'] = {'error': str(e)}
        
        return stats
    
    def clear_cache(self):
        """Clear all geographical data caches"""
        self.cache.clear()
        
        if self.persistent_cache:
            try:
                self.persistent_cache.clear_all()
                logger.info("Persistent geographical data cache cleared")
            except Exception as e:
                logger.error(f"Error clearing persistent cache: {e}")
        
        logger.info("Geographical data caches cleared")
    
    def cleanup_expired_cache(self) -> Dict[str, int]:
        """Clean up expired cache entries"""
        results = {'memory_cache': 0, 'persistent_cache': 0}
        
        # Memory cache cleanup (automatic via TTL)
        self.cache.clear()  # Simple approach - could be more sophisticated
        
        # Persistent cache cleanup
        if self.persistent_cache:
            try:
                removed = self.persistent_cache.cleanup_expired()
                results['persistent_cache'] = removed
                logger.info(f"Cleaned up {removed} expired persistent cache entries")
            except Exception as e:
                logger.error(f"Error cleaning up persistent cache: {e}")
        
        return results
    
    def optimize_cache(self) -> bool:
        """Optimize cache databases"""
        if self.persistent_cache:
            try:
                return self.persistent_cache.optimize_database()
            except Exception as e:
                logger.error(f"Error optimizing cache: {e}")
                return False
        return True
    
    def reset_api_failures(self):
        """Reset API failure tracking"""
        self.api_failures.clear()
        self.api_last_failure.clear()
        logger.info("API failure tracking reset")
    
    def close(self):
        """Close all resources"""
        if self.geoip2_reader:
            self.geoip2_reader.close()
            self.geoip2_reader = None
        
        if self.persistent_cache:
            try:
                self.persistent_cache.close()
            except Exception as e:
                logger.error(f"Error closing persistent cache: {e}")
        
        logger.info("Geographical manager closed")


def create_geo_manager(config: Optional[Dict[str, Any]] = None) -> GeoIPManager:
    """Factory function to create geographical manager"""
    return GeoIPManager(config)


# Global manager instance (singleton pattern)
_global_geo_manager = None
_manager_lock = threading.Lock()


def get_global_geo_manager(config: Optional[Dict[str, Any]] = None) -> GeoIPManager:
    """Get or create global geographical manager instance"""
    global _global_geo_manager
    
    with _manager_lock:
        if _global_geo_manager is None:
            _global_geo_manager = create_geo_manager(config)
        return _global_geo_manager


if __name__ == "__main__":
    # Example usage
    import sys
    
    # Create manager
    geo_manager = create_geo_manager()
    
    # Test with a public IP
    test_ips = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
    
    print("Testing individual lookups:")
    for ip in test_ips:
        geo_info = geo_manager.get_geographical_info(ip)
        print(f"{ip}: {geo_info}")
    
    print("\nTesting bulk lookup:")
    bulk_results = geo_manager.bulk_lookup(test_ips)
    for ip, info in bulk_results.items():
        print(f"{ip}: {info}")
    
    print(f"\nCache stats: {geo_manager.get_cache_stats()}")
    
    # Cleanup
    geo_manager.close()