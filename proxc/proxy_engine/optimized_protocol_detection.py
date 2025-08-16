"""
Optimized Protocol Detection Engine - Phase 3.2

High-performance protocol detection system with connection pooling, bulk detection,
persistent caching, UDP-based SOCKS detection, and optimized async patterns.

Key optimizations:
- Connection pooling and reuse for handshakes
- Bulk simultaneous protocol testing
- Persistent fingerprinting cache
- UDP-based SOCKS detection
- Parallel handshake validation
- Advanced confidence scoring
- Fallback chains for ambiguous results
"""

import asyncio
import json
import logging
import pickle
import socket
import struct
import time
import hashlib
import gc
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Set, AsyncIterator
import threading
import weakref

# Optional imports
try:
    import aiohttp
    from aiohttp import ClientSession, ClientTimeout, ClientError, TCPConnector
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import aiofiles
    HAS_AIOFILES = True
except ImportError:
    HAS_AIOFILES = False

from ..proxy_core.models import ProxyInfo, ProxyProtocol
from .protocol_detection import ProtocolDetectionResult, DetectionSummary, DetectionMethod
from ..proxy_cli.cli_imports import log_structured, print_info, print_warning

logger = logging.getLogger(__name__)


@dataclass
class ProtocolFingerprint:
    """Cached protocol detection fingerprint"""
    proxy_address: str
    protocol: ProxyProtocol
    confidence: float
    detection_method: str
    response_signature: str  # Hash of response for caching
    timestamp: datetime
    expiry_time: datetime
    success_count: int = 0
    failure_count: int = 0
    
    @property
    def is_expired(self) -> bool:
        return datetime.now() > self.expiry_time
    
    @property
    def reliability_score(self) -> float:
        """Calculate reliability based on success/failure history"""
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.5
        return self.success_count / total
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            **asdict(self),
            'timestamp': self.timestamp.isoformat(),
            'expiry_time': self.expiry_time.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ProtocolFingerprint':
        """Create from dictionary"""
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        data['expiry_time'] = datetime.fromisoformat(data['expiry_time'])
        return cls(**data)


@dataclass
class ConnectionPoolStats:
    """Statistics for connection pool performance"""
    total_connections: int = 0
    active_connections: int = 0
    reused_connections: int = 0
    pool_hits: int = 0
    pool_misses: int = 0
    avg_connection_time: float = 0.0
    
    def to_dict(self) -> dict:
        return asdict(self)


class OptimizedConnectionPool:
    """
    High-performance connection pool for protocol detection with connection reuse
    """
    
    def __init__(self, max_pool_size: int = 100, max_per_host: int = 10):
        self.max_pool_size = max_pool_size
        self.max_per_host = max_per_host
        
        # Connection pools by host:port
        self.pools: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_per_host))
        self.pool_locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        
        # Connection tracking
        self.active_connections: Set[tuple] = set()
        self.connection_creation_times: Dict[str, float] = {}
        
        # Statistics
        self.stats = ConnectionPoolStats()
        
        # Cleanup task
        self.cleanup_task: Optional[asyncio.Task] = None
        self.start_cleanup_task()
    
    def start_cleanup_task(self):
        """Start background cleanup of stale connections"""
        if self.cleanup_task is None or self.cleanup_task.done():
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def _cleanup_loop(self):
        """Background task to clean up stale connections"""
        while True:
            try:
                await asyncio.sleep(30)  # Cleanup every 30 seconds
                await self._cleanup_stale_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Connection pool cleanup error: {e}")
    
    async def _cleanup_stale_connections(self):
        """Clean up connections older than 60 seconds"""
        current_time = time.time()
        hosts_to_cleanup = []
        
        for host_port, creation_time in list(self.connection_creation_times.items()):
            if current_time - creation_time > 60:  # 1 minute max age
                hosts_to_cleanup.append(host_port)
        
        for host_port in hosts_to_cleanup:
            await self._close_host_connections(host_port)
    
    async def _close_host_connections(self, host_port: str):
        """Close all connections for a specific host"""
        if host_port in self.pools:
            async with self.pool_locks[host_port]:
                pool = self.pools[host_port]
                while pool:
                    try:
                        reader, writer = pool.popleft()
                        if not writer.is_closing():
                            writer.close()
                            await writer.wait_closed()
                    except:
                        pass
                
                # Clean up tracking
                if host_port in self.connection_creation_times:
                    del self.connection_creation_times[host_port]
                
                self.stats.active_connections = max(0, self.stats.active_connections - len(pool))
    
    async def get_connection(self, host: str, port: int, 
                           timeout: float = 5.0) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Get a connection from pool or create new one
        
        Returns:
            (reader, writer) tuple
        """
        host_port = f"{host}:{port}"
        
        async with self.pool_locks[host_port]:
            # Try to get from pool first
            pool = self.pools[host_port]
            
            while pool:
                try:
                    reader, writer = pool.popleft()
                    
                    # Check if connection is still valid
                    if not writer.is_closing():
                        self.stats.pool_hits += 1
                        self.stats.reused_connections += 1
                        return reader, writer
                    else:
                        # Connection is closed, remove from active set
                        conn_id = (host, port, id(writer))
                        self.active_connections.discard(conn_id)
                
                except:
                    continue
            
            # No valid connection in pool, create new one
            self.stats.pool_misses += 1
            start_time = time.time()
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout
                )
                
                connection_time = time.time() - start_time
                self.stats.avg_connection_time = (
                    (self.stats.avg_connection_time * self.stats.total_connections + connection_time) /
                    (self.stats.total_connections + 1)
                )
                
                self.stats.total_connections += 1
                self.stats.active_connections += 1
                
                # Track connection
                conn_id = (host, port, id(writer))
                self.active_connections.add(conn_id)
                self.connection_creation_times[host_port] = time.time()
                
                return reader, writer
                
            except Exception as e:
                log_structured('DEBUG', f"Failed to create connection to {host}:{port}",
                              error=str(e))
                raise
    
    async def return_connection(self, host: str, port: int, 
                              reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                              reusable: bool = True):
        """
        Return connection to pool or close it
        
        Args:
            host: Target host
            port: Target port  
            reader: Stream reader
            writer: Stream writer
            reusable: Whether connection can be reused
        """
        host_port = f"{host}:{port}"
        conn_id = (host, port, id(writer))
        
        try:
            if reusable and not writer.is_closing() and len(self.pools[host_port]) < self.max_per_host:
                # Return to pool
                async with self.pool_locks[host_port]:
                    self.pools[host_port].append((reader, writer))
            else:
                # Close connection
                if not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
                
                self.stats.active_connections = max(0, self.stats.active_connections - 1)
        
        finally:
            # Always remove from active set
            self.active_connections.discard(conn_id)
    
    async def close_all(self):
        """Close all connections in all pools"""
        if self.cleanup_task and not self.cleanup_task.done():
            self.cleanup_task.cancel()
        
        for host_port in list(self.pools.keys()):
            await self._close_host_connections(host_port)
        
        self.pools.clear()
        self.pool_locks.clear()
        self.active_connections.clear()
        self.connection_creation_times.clear()
    
    def get_stats(self) -> ConnectionPoolStats:
        """Get current pool statistics"""
        return self.stats


class ProtocolFingerprintCache:
    """
    Persistent cache for protocol detection fingerprints with LRU eviction
    """
    
    def __init__(self, cache_file: Path = None, max_size: int = 10000, ttl_hours: int = 24):
        self.cache_file = cache_file or Path("protocol_fingerprints.json")
        self.max_size = max_size
        self.ttl_hours = ttl_hours
        self.cache: Dict[str, ProtocolFingerprint] = {}
        self.access_order: deque = deque()  # For LRU
        self.lock = threading.Lock()
        
        # Load existing cache
        self._load_cache()
    
    def _generate_cache_key(self, proxy_address: str, method: str = "") -> str:
        """Generate cache key for proxy and method"""
        return f"{proxy_address}:{method}" if method else proxy_address
    
    def _load_cache(self):
        """Load cache from disk"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                
                for key, fp_data in data.items():
                    try:
                        fingerprint = ProtocolFingerprint.from_dict(fp_data)
                        if not fingerprint.is_expired:
                            self.cache[key] = fingerprint
                            self.access_order.append(key)
                    except Exception as e:
                        logger.debug(f"Failed to load fingerprint {key}: {e}")
                
                log_structured('INFO', f"Loaded {len(self.cache)} protocol fingerprints from cache")
            
            except Exception as e:
                log_structured('WARNING', f"Failed to load protocol cache: {e}")
    
    async def save_cache(self):
        """Save cache to disk asynchronously"""
        try:
            cache_data = {}
            
            with self.lock:
                for key, fingerprint in self.cache.items():
                    if not fingerprint.is_expired:
                        cache_data[key] = fingerprint.to_dict()
            
            # Use aiofiles if available for async I/O
            if HAS_AIOFILES:
                async with aiofiles.open(self.cache_file, 'w') as f:
                    await f.write(json.dumps(cache_data, indent=2))
            else:
                # Fallback to sync I/O in thread
                await asyncio.get_event_loop().run_in_executor(
                    None, 
                    lambda: json.dump(cache_data, open(self.cache_file, 'w'), indent=2)
                )
            
            log_structured('DEBUG', f"Saved {len(cache_data)} fingerprints to cache")
        
        except Exception as e:
            log_structured('ERROR', f"Failed to save protocol cache: {e}")
    
    def get(self, proxy_address: str, method: str = "") -> Optional[ProtocolFingerprint]:
        """Get cached fingerprint"""
        key = self._generate_cache_key(proxy_address, method)
        
        with self.lock:
            fingerprint = self.cache.get(key)
            
            if fingerprint:
                if fingerprint.is_expired:
                    # Remove expired fingerprint
                    del self.cache[key]
                    try:
                        self.access_order.remove(key)
                    except ValueError:
                        pass
                    return None
                
                # Update access order for LRU
                try:
                    self.access_order.remove(key)
                except ValueError:
                    pass
                self.access_order.append(key)
                
                return fingerprint
        
        return None
    
    def put(self, proxy_address: str, result: ProtocolDetectionResult, method: str = ""):
        """Cache a detection result"""
        key = self._generate_cache_key(proxy_address, method)
        
        # Create fingerprint
        response_signature = hashlib.md5(
            str(result.raw_response).encode() + 
            str(result.response_time_ms).encode()
        ).hexdigest()
        
        fingerprint = ProtocolFingerprint(
            proxy_address=proxy_address,
            protocol=result.protocol,
            confidence=result.confidence,
            detection_method=result.method_used,
            response_signature=response_signature,
            timestamp=datetime.now(),
            expiry_time=datetime.now() + timedelta(hours=self.ttl_hours),
            success_count=1 if result.confidence > 0.7 else 0,
            failure_count=0 if result.confidence > 0.7 else 1
        )
        
        with self.lock:
            # Remove oldest entries if cache is full
            while len(self.cache) >= self.max_size and self.access_order:
                oldest_key = self.access_order.popleft()
                self.cache.pop(oldest_key, None)
            
            # Add new fingerprint
            self.cache[key] = fingerprint
            self.access_order.append(key)
    
    def update_stats(self, proxy_address: str, success: bool, method: str = ""):
        """Update success/failure statistics for cached fingerprint"""
        key = self._generate_cache_key(proxy_address, method)
        
        with self.lock:
            fingerprint = self.cache.get(key)
            if fingerprint:
                if success:
                    fingerprint.success_count += 1
                else:
                    fingerprint.failure_count += 1
    
    def get_stats(self) -> Dict[str, any]:
        """Get cache statistics"""
        with self.lock:
            total_entries = len(self.cache)
            expired_count = sum(1 for fp in self.cache.values() if fp.is_expired)
            
            return {
                'total_entries': total_entries,
                'expired_entries': expired_count,
                'max_size': self.max_size,
                'hit_ratio': getattr(self, '_hit_count', 0) / max(getattr(self, '_total_lookups', 1), 1)
            }


class BulkProtocolDetector:
    """
    Advanced bulk protocol detector that tests multiple protocols simultaneously
    """
    
    def __init__(self, connection_pool: OptimizedConnectionPool, 
                 fingerprint_cache: ProtocolFingerprintCache,
                 connect_timeout: float = 3.0,
                 read_timeout: float = 2.0):
        self.connection_pool = connection_pool
        self.fingerprint_cache = fingerprint_cache
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
    
    async def detect_protocol_bulk(self, proxy: ProxyInfo) -> DetectionSummary:
        """
        Detect protocol using simultaneous bulk testing for maximum speed
        """
        start_time = time.time()
        
        # Check cache first
        cached_fingerprint = self.fingerprint_cache.get(proxy.address)
        if cached_fingerprint and cached_fingerprint.reliability_score > 0.8:
            # Use cached result with high reliability
            result = ProtocolDetectionResult(
                protocol=cached_fingerprint.protocol,
                confidence=cached_fingerprint.confidence * cached_fingerprint.reliability_score,
                response_time_ms=0.0,  # Cached
                method_used=f"cached_{cached_fingerprint.detection_method}"
            )
            
            return DetectionSummary(
                proxy_address=proxy.address,
                results=[result],
                total_time_ms=(time.time() - start_time) * 1000
            )
        
        # Create concurrent detection tasks
        detection_tasks = []
        
        # SOCKS5 handshake
        detection_tasks.append(
            asyncio.create_task(self._test_socks5_handshake_optimized(proxy))
        )
        
        # HTTP CONNECT  
        detection_tasks.append(
            asyncio.create_task(self._test_http_connect_optimized(proxy))
        )
        
        # SOCKS4 handshake
        detection_tasks.append(
            asyncio.create_task(self._test_socks4_handshake_optimized(proxy))
        )
        
        # UDP SOCKS detection (new optimization)
        detection_tasks.append(
            asyncio.create_task(self._test_udp_socks_detection(proxy))
        )
        
        # Wait for any successful result or all to complete
        results = []
        completed_tasks = []
        
        try:
            # Use asyncio.wait with FIRST_COMPLETED for early exit on high confidence
            done, pending = await asyncio.wait(
                detection_tasks,
                timeout=self.connect_timeout + self.read_timeout,
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # Process completed tasks
            for task in done:
                try:
                    result = await task
                    if result:
                        results.append(result)
                        completed_tasks.append(task)
                        
                        # Early exit for high confidence
                        if result.confidence >= 0.9:
                            # Cancel remaining tasks
                            for pending_task in pending:
                                pending_task.cancel()
                            break
                except Exception as e:
                    log_structured('DEBUG', f"Detection task failed: {e}")
            
            # Wait for remaining tasks if no high confidence result
            if not results or max(r.confidence for r in results) < 0.9:
                if pending:
                    additional_done, _ = await asyncio.wait(pending, timeout=1.0)
                    for task in additional_done:
                        try:
                            result = await task
                            if result:
                                results.append(result)
                        except:
                            pass
        
        except Exception as e:
            log_structured('WARNING', f"Bulk detection failed for {proxy.address}: {e}")
        
        finally:
            # Ensure all tasks are cancelled
            for task in detection_tasks:
                if not task.done():
                    task.cancel()
        
        # Create summary
        total_time = (time.time() - start_time) * 1000
        summary = DetectionSummary(
            proxy_address=proxy.address,
            results=results,
            total_time_ms=total_time
        )
        
        # Cache best result
        if summary.best_match and summary.best_match.confidence > 0.6:
            self.fingerprint_cache.put(proxy.address, summary.best_match)
        
        return summary
    
    async def _test_socks5_handshake_optimized(self, proxy: ProxyInfo) -> Optional[ProtocolDetectionResult]:
        """Optimized SOCKS5 detection with connection pooling"""
        start_time = time.time()
        reader = None
        writer = None
        
        try:
            reader, writer = await self.connection_pool.get_connection(
                proxy.host, proxy.port, self.connect_timeout
            )
            
            # SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=0
            greeting = b'\x05\x01\x00'
            writer.write(greeting)
            await writer.drain()
            
            # Read response with timeout
            response = await asyncio.wait_for(
                reader.read(2),
                timeout=self.read_timeout
            )
            
            response_time = (time.time() - start_time) * 1000
            
            if len(response) == 2 and response[0] == 0x05:
                if response[1] == 0x00:
                    confidence = 0.95
                elif response[1] == 0xFF:
                    confidence = 0.85
                else:
                    confidence = 0.9
                
                # Connection can be reused for SOCKS5
                await self.connection_pool.return_connection(
                    proxy.host, proxy.port, reader, writer, reusable=True
                )
                
                return ProtocolDetectionResult(
                    protocol=ProxyProtocol.SOCKS5,
                    confidence=confidence,
                    response_time_ms=response_time,
                    method_used="socks5_handshake_optimized",
                    raw_response=response
                )
        
        except Exception as e:
            if reader and writer:
                await self.connection_pool.return_connection(
                    proxy.host, proxy.port, reader, writer, reusable=False
                )
            
            return ProtocolDetectionResult(
                protocol=ProxyProtocol.SOCKS5,
                confidence=0.0,
                response_time_ms=(time.time() - start_time) * 1000,
                method_used="socks5_handshake_optimized",
                error_message=str(e)
            )
        
        return None
    
    async def _test_http_connect_optimized(self, proxy: ProxyInfo) -> Optional[ProtocolDetectionResult]:
        """Optimized HTTP CONNECT test with connection pooling"""
        start_time = time.time()
        reader = None
        writer = None
        
        try:
            reader, writer = await self.connection_pool.get_connection(
                proxy.host, proxy.port, self.connect_timeout
            )
            
            # HTTP CONNECT request
            connect_request = (
                f"CONNECT httpbin.org:80 HTTP/1.1\r\n"
                f"Host: httpbin.org:80\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            
            writer.write(connect_request)
            await writer.drain()
            
            # Read response
            response_line = await asyncio.wait_for(
                reader.readline(),
                timeout=self.read_timeout
            )
            
            response_time = (time.time() - start_time) * 1000
            
            if response_line.startswith(b'HTTP/'):
                if b'200' in response_line:
                    confidence = 0.9
                elif b'407' in response_line:
                    confidence = 0.85
                elif any(code in response_line for code in [b'400', b'403', b'404']):
                    confidence = 0.8
                else:
                    confidence = 0.7
                
                # HTTP connections usually don't allow reuse after CONNECT
                await self.connection_pool.return_connection(
                    proxy.host, proxy.port, reader, writer, reusable=False
                )
                
                return ProtocolDetectionResult(
                    protocol=ProxyProtocol.HTTP,
                    confidence=confidence,
                    response_time_ms=response_time,
                    method_used="http_connect_optimized",
                    raw_response=response_line
                )
        
        except Exception as e:
            if reader and writer:
                await self.connection_pool.return_connection(
                    proxy.host, proxy.port, reader, writer, reusable=False
                )
            
            return ProtocolDetectionResult(
                protocol=ProxyProtocol.HTTP,
                confidence=0.0,
                response_time_ms=(time.time() - start_time) * 1000,
                method_used="http_connect_optimized",
                error_message=str(e)
            )
        
        return None
    
    async def _test_socks4_handshake_optimized(self, proxy: ProxyInfo) -> Optional[ProtocolDetectionResult]:
        """Optimized SOCKS4 detection with connection pooling"""
        start_time = time.time()
        reader = None
        writer = None
        
        try:
            reader, writer = await self.connection_pool.get_connection(
                proxy.host, proxy.port, self.connect_timeout
            )
            
            # SOCKS4 CONNECT to 1.1.1.1:80
            request = struct.pack('!BBH4sB', 4, 1, 80, socket.inet_aton('1.1.1.1'), 0)
            writer.write(request)
            await writer.drain()
            
            response = await asyncio.wait_for(
                reader.read(8),
                timeout=self.read_timeout
            )
            
            response_time = (time.time() - start_time) * 1000
            
            if len(response) >= 2 and response[0] == 0x00:
                rep_code = response[1]
                if rep_code == 0x5A:
                    confidence = 0.95
                elif rep_code in [0x5B, 0x5C, 0x5D]:
                    confidence = 0.85
                else:
                    confidence = 0.7
                
                await self.connection_pool.return_connection(
                    proxy.host, proxy.port, reader, writer, reusable=True
                )
                
                return ProtocolDetectionResult(
                    protocol=ProxyProtocol.SOCKS4,
                    confidence=confidence,
                    response_time_ms=response_time,
                    method_used="socks4_handshake_optimized",
                    raw_response=response
                )
        
        except Exception as e:
            if reader and writer:
                await self.connection_pool.return_connection(
                    proxy.host, proxy.port, reader, writer, reusable=False
                )
            
            return ProtocolDetectionResult(
                protocol=ProxyProtocol.SOCKS4,
                confidence=0.0,
                response_time_ms=(time.time() - start_time) * 1000,
                method_used="socks4_handshake_optimized",
                error_message=str(e)
            )
        
        return None
    
    async def _test_udp_socks_detection(self, proxy: ProxyInfo) -> Optional[ProtocolDetectionResult]:
        """
        UDP-based SOCKS detection for faster initial screening
        Note: This is experimental and may not work with all proxies
        """
        start_time = time.time()
        
        try:
            # Create UDP socket for faster initial probe
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)  # Short timeout for UDP
            
            try:
                # Send a minimal probe packet
                probe_data = b'\x05\x01\x00'  # SOCKS5-like probe
                sock.sendto(probe_data, (proxy.host, proxy.port))
                
                # Try to receive response
                try:
                    response, addr = sock.recvfrom(1024)
                    response_time = (time.time() - start_time) * 1000
                    
                    # Analyze response for SOCKS-like patterns
                    if len(response) >= 2:
                        if response[0] == 0x05:  # SOCKS5-like
                            return ProtocolDetectionResult(
                                protocol=ProxyProtocol.SOCKS5,
                                confidence=0.6,  # Lower confidence for UDP
                                response_time_ms=response_time,
                                method_used="udp_socks_probe",
                                raw_response=response
                            )
                        elif response[0] == 0x00:  # SOCKS4-like
                            return ProtocolDetectionResult(
                                protocol=ProxyProtocol.SOCKS4,
                                confidence=0.6,
                                response_time_ms=response_time,
                                method_used="udp_socks_probe",
                                raw_response=response
                            )
                
                except socket.timeout:
                    # UDP timeout is expected for TCP-only proxies
                    pass
            
            finally:
                sock.close()
        
        except Exception as e:
            log_structured('DEBUG', f"UDP SOCKS probe failed for {proxy.address}: {e}")
        
        return None


class OptimizedProtocolDetector:
    """
    Main optimized protocol detection engine combining all Phase 3.2 improvements
    """
    
    def __init__(self, max_concurrent: int = 100, cache_file: Path = None):
        self.max_concurrent = max_concurrent
        
        # Initialize components
        self.connection_pool = OptimizedConnectionPool(
            max_pool_size=max_concurrent * 2,
            max_per_host=10
        )
        self.fingerprint_cache = ProtocolFingerprintCache(cache_file)
        self.bulk_detector = BulkProtocolDetector(
            self.connection_pool,
            self.fingerprint_cache
        )
        
        # Concurrency control
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        # Statistics
        self.stats = {
            'total_detections': 0,
            'cache_hits': 0,
            'bulk_detections': 0,
            'avg_detection_time': 0.0
        }
    
    async def detect_single_optimized(self, proxy: ProxyInfo) -> DetectionSummary:
        """Optimized single proxy detection"""
        async with self.semaphore:
            start_time = time.time()
            
            try:
                summary = await self.bulk_detector.detect_protocol_bulk(proxy)
                
                detection_time = (time.time() - start_time) * 1000
                self.stats['total_detections'] += 1
                self.stats['avg_detection_time'] = (
                    (self.stats['avg_detection_time'] * (self.stats['total_detections'] - 1) + detection_time) /
                    self.stats['total_detections']
                )
                
                return summary
            
            except Exception as e:
                log_structured('ERROR', f"Optimized detection failed for {proxy.address}: {e}")
                
                # Return minimal result
                return DetectionSummary(
                    proxy_address=proxy.address,
                    results=[],
                    total_time_ms=(time.time() - start_time) * 1000
                )
    
    async def detect_batch_optimized(self, proxies: List[ProxyInfo]) -> Dict[str, DetectionSummary]:
        """Optimized batch detection with maximum concurrency"""
        log_structured('INFO', f"Starting optimized batch detection for {len(proxies)} proxies")
        
        # Create detection tasks
        tasks = [
            self.detect_single_optimized(proxy)
            for proxy in proxies
        ]
        
        # Execute with progress tracking
        results = {}
        completed = 0
        
        for coro in asyncio.as_completed(tasks):
            try:
                summary = await coro
                results[summary.proxy_address] = summary
                completed += 1
                
                # Progress logging every 100 completions
                if completed % 100 == 0:
                    cache_hit_rate = self.stats['cache_hits'] / max(self.stats['total_detections'], 1)
                    log_structured('INFO', f"Batch detection progress: {completed}/{len(proxies)} "
                                         f"(cache hit rate: {cache_hit_rate:.1%})")
            
            except Exception as e:
                log_structured('ERROR', f"Batch detection task failed: {e}")
        
        # Save cache after batch completion
        await self.fingerprint_cache.save_cache()
        
        return results
    
    async def cleanup(self):
        """Clean up resources"""
        await self.connection_pool.close_all()
        await self.fingerprint_cache.save_cache()
    
    def get_performance_stats(self) -> Dict[str, any]:
        """Get comprehensive performance statistics"""
        return {
            'detection_stats': self.stats,
            'connection_pool_stats': self.connection_pool.get_stats().to_dict(),
            'cache_stats': self.fingerprint_cache.get_stats()
        }


# Convenience functions for integration
async def detect_protocols_optimized(proxies: List[ProxyInfo], 
                                   max_concurrent: int = 100,
                                   cache_file: Path = None) -> Dict[str, DetectionSummary]:
    """
    Convenience function for optimized protocol detection
    
    Args:
        proxies: List of proxies to test
        max_concurrent: Maximum concurrent detections
        cache_file: Optional cache file path
        
    Returns:
        Dictionary mapping proxy addresses to detection summaries
    """
    detector = OptimizedProtocolDetector(max_concurrent, cache_file)
    
    try:
        results = await detector.detect_batch_optimized(proxies)
        return results
    finally:
        await detector.cleanup()