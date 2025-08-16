"""
Advanced Port Discovery Engine for Proxy Detection
=================================================

Multi-threaded port scanning optimized for proxy discovery with intelligent
timeout management and proxy-specific port detection patterns.
"""

import asyncio
import logging
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Union

# Third-party imports with fallbacks
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

# Import our core models
from ..proxy_core.models import ProxyInfo, ProxyProtocol, ProxyStatus

logger = logging.getLogger(__name__)


class PortCategory(Enum):
    """Categories of proxy ports"""
    STANDARD_HTTP = "standard_http"
    STANDARD_SOCKS = "standard_socks"
    ALTERNATIVE = "alternative"
    RANDOM_HIGH = "random_high"
    ENTERPRISE = "enterprise"


class CommonProxyPorts:
    """Common proxy port definitions and categorization"""
    
    # Standard HTTP proxy ports
    STANDARD_HTTP = [80, 8080, 3128, 8888, 8000, 8001, 8008]
    
    # Standard SOCKS proxy ports
    STANDARD_SOCKS = [1080, 1081, 9050, 9051]
    
    # Alternative/less common proxy ports
    ALTERNATIVE = [8118, 8123, 3129, 3130, 8090, 8181, 9000, 9080]
    
    # High port ranges often used by proxies
    RANDOM_HIGH = list(range(8000, 9000, 100)) + list(range(3000, 4000, 200))
    
    # Enterprise/corporate proxy ports
    ENTERPRISE = [8080, 3128, 8888, 8000, 8001, 8002, 8008, 8800]
    
    @classmethod
    def get_ports_by_category(cls, category: PortCategory) -> List[int]:
        """Get ports by category"""
        mapping = {
            PortCategory.STANDARD_HTTP: cls.STANDARD_HTTP,
            PortCategory.STANDARD_SOCKS: cls.STANDARD_SOCKS,
            PortCategory.ALTERNATIVE: cls.ALTERNATIVE,
            PortCategory.RANDOM_HIGH: cls.RANDOM_HIGH,
            PortCategory.ENTERPRISE: cls.ENTERPRISE
        }
        return mapping.get(category, [])
    
    @classmethod
    def get_all_common_ports(cls) -> List[int]:
        """Get all common proxy ports"""
        all_ports = set()
        all_ports.update(cls.STANDARD_HTTP)
        all_ports.update(cls.STANDARD_SOCKS)
        all_ports.update(cls.ALTERNATIVE)
        return sorted(list(all_ports))
    
    @classmethod
    def get_scanning_priority_ports(cls) -> List[int]:
        """Get ports in scanning priority order"""
        # Most likely to least likely
        priority_order = [
            8080, 3128, 80, 8888, 1080, 8000, 8001, 8008, 
            8118, 8123, 9000, 9050, 3129, 8090, 8181
        ]
        return priority_order


@dataclass
class PortScanConfig:
    """Configuration for port scanning operations"""
    # Target configuration
    target_ips: List[str] = field(default_factory=list)
    port_categories: List[PortCategory] = field(default_factory=lambda: [
        PortCategory.STANDARD_HTTP, PortCategory.STANDARD_SOCKS
    ])
    custom_ports: List[int] = field(default_factory=list)
    
    # Scanning parameters
    max_workers: int = 100
    timeout: int = 3
    connect_timeout: int = 5
    retries: int = 1
    
    # Advanced options
    scan_random_ports: bool = False
    random_port_count: int = 10
    port_range: Optional[Tuple[int, int]] = None  # e.g., (8000, 9000)
    
    # Performance settings
    rate_limit: float = 0.05  # Small delay between scans
    batch_size: int = 50
    adaptive_timeout: bool = True
    geographic_optimization: bool = True
    
    # Output settings
    min_success_threshold: int = 1
    save_failed_attempts: bool = False
    detailed_timing: bool = True


@dataclass
class PortScanResult:
    """Results from port scanning operation"""
    target_ip: str
    ports_scanned: List[int] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    proxy_candidates: List[ProxyInfo] = field(default_factory=list)
    
    # Performance metrics
    scan_duration: float = 0.0
    avg_port_time: float = 0.0
    success_rate: float = 0.0
    
    # Detailed results
    port_timings: Dict[int, float] = field(default_factory=dict)
    failed_ports: List[int] = field(default_factory=list)
    timeout_ports: List[int] = field(default_factory=list)
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    errors: List[str] = field(default_factory=list)


class GeographicTimeoutCalculator:
    """Calculate optimal timeouts based on geographic location"""
    
    # Regional timeout multipliers (rough estimates)
    REGIONAL_MULTIPLIERS = {
        'local': 1.0,      # Same country/region
        'continental': 1.5, # Same continent
        'intercontinental': 2.0, # Different continent
        'satellite': 3.0    # Satellite connections
    }
    
    @classmethod
    def calculate_timeout(cls, base_timeout: int, region: str = 'continental') -> int:
        """Calculate timeout based on geographic region"""
        multiplier = cls.REGIONAL_MULTIPLIERS.get(region, 1.5)
        return max(int(base_timeout * multiplier), 1)


class ProxyPortScanner:
    """Advanced port scanner optimized for proxy detection"""
    
    def __init__(self, config: PortScanConfig):
        self.config = config
        self.scan_stats = {
            'scanned': 0,
            'open': 0,
            'closed': 0,
            'timeout': 0,
            'error': 0
        }
        self.adaptive_timeouts: Dict[str, int] = {}
    
    def generate_port_list(self, target_ip: str) -> List[int]:
        """Generate optimized port list for scanning"""
        ports = set()
        
        # Add ports from categories
        for category in self.config.port_categories:
            ports.update(CommonProxyPorts.get_ports_by_category(category))
        
        # Add custom ports
        ports.update(self.config.custom_ports)
        
        # Add random ports if enabled
        if self.config.scan_random_ports:
            if self.config.port_range:
                start, end = self.config.port_range
                random_ports = random.sample(
                    range(start, end), 
                    min(self.config.random_port_count, end - start)
                )
            else:
                # Use high ports commonly used by proxies
                high_ports = list(range(8000, 9000)) + list(range(3000, 4000))
                random_ports = random.sample(
                    high_ports, 
                    min(self.config.random_port_count, len(high_ports))
                )
            ports.update(random_ports)
        
        # Sort by scanning priority
        port_list = list(ports)
        priority_ports = CommonProxyPorts.get_scanning_priority_ports()
        
        # Sort with priority ports first
        def port_priority(port):
            try:
                return priority_ports.index(port)
            except ValueError:
                return len(priority_ports) + port
        
        return sorted(port_list, key=port_priority)
    
    def get_adaptive_timeout(self, target_ip: str) -> int:
        """Get adaptive timeout for IP based on previous results"""
        if not self.config.adaptive_timeout:
            return self.config.timeout
        
        # Use cached timeout if available
        if target_ip in self.adaptive_timeouts:
            return self.adaptive_timeouts[target_ip]
        
        # Default with geographic optimization
        if self.config.geographic_optimization:
            return GeographicTimeoutCalculator.calculate_timeout(
                self.config.timeout, 'continental'
            )
        
        return self.config.timeout
    
    async def scan_port_async(
        self, 
        target_ip: str, 
        port: int, 
        session: aiohttp.ClientSession
    ) -> Optional[ProxyInfo]:
        """Asynchronously scan a single port"""
        start_time = time.time()
        timeout = self.get_adaptive_timeout(target_ip)
        
        try:
            # Test basic connectivity first
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            
            # Port is open, test if it's a proxy
            proxy_url = f"http://{target_ip}:{port}"
            
            try:
                async with session.get(
                    'http://httpbin.org/ip',
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        # Found working proxy
                        response_time = (time.time() - start_time) * 1000
                        proxy = ProxyInfo(
                            ip=target_ip,
                            port=port,
                            protocol=ProxyProtocol.HTTP,
                            status=ProxyStatus.WORKING,
                            response_time=response_time,
                            discovered_at=datetime.utcnow(),
                            source="port_scanner"
                        )
                        self.scan_stats['open'] += 1
                        return proxy
            except:
                # Port is open but not a working proxy
                pass
            
            # Port is open but not a proxy
            self.scan_stats['open'] += 1
            return None
            
        except asyncio.TimeoutError:
            self.scan_stats['timeout'] += 1
            return None
        except Exception as e:
            self.scan_stats['error'] += 1
            logger.debug(f"Port scan error {target_ip}:{port}: {e}")
            return None
        finally:
            self.scan_stats['scanned'] += 1
    
    def scan_port_sync(self, target_ip: str, port: int) -> Optional[ProxyInfo]:
        """Synchronously scan a single port"""
        start_time = time.time()
        timeout = self.get_adaptive_timeout(target_ip)
        
        try:
            # Test basic connectivity
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            result = sock.connect_ex((target_ip, port))
            sock.close()
            
            if result == 0:
                # Port is open - create proxy candidate
                response_time = (time.time() - start_time) * 1000
                proxy = ProxyInfo(
                    ip=target_ip,
                    port=port,
                    protocol=ProxyProtocol.HTTP,
                    status=ProxyStatus.UNTESTED,
                    response_time=response_time,
                    discovered_at=datetime.utcnow(),
                    source="port_scanner"
                )
                self.scan_stats['open'] += 1
                return proxy
            else:
                self.scan_stats['closed'] += 1
                return None
                
        except socket.timeout:
            self.scan_stats['timeout'] += 1
            return None
        except Exception as e:
            self.scan_stats['error'] += 1
            logger.debug(f"Port scan error {target_ip}:{port}: {e}")
            return None
        finally:
            self.scan_stats['scanned'] += 1
    
    async def scan_ip_async(self, target_ip: str) -> PortScanResult:
        """Asynchronously scan all ports for a single IP"""
        start_time = time.time()
        port_list = self.generate_port_list(target_ip)
        candidates = []
        open_ports = []
        failed_ports = []
        timeout_ports = []
        port_timings = {}
        
        if not HAS_AIOHTTP:
            return await self._fallback_to_sync_ip(target_ip)
        
        try:
            connector = aiohttp.TCPConnector(
                limit=min(self.config.max_workers, 50),
                ttl_dns_cache=300,
                use_dns_cache=True
            )
            
            async with aiohttp.ClientSession(connector=connector) as session:
                # Scan ports in batches
                for i in range(0, len(port_list), self.config.batch_size):
                    batch = port_list[i:i + self.config.batch_size]
                    tasks = []
                    
                    for port in batch:
                        port_start = time.time()
                        task = self.scan_port_async(target_ip, port, session)
                        tasks.append((port, port_start, task))
                    
                    # Execute batch
                    for port, port_start, task in tasks:
                        try:
                            result = await task
                            port_time = (time.time() - port_start) * 1000
                            port_timings[port] = port_time
                            
                            if result:
                                candidates.append(result)
                                open_ports.append(port)
                        except asyncio.TimeoutError:
                            timeout_ports.append(port)
                        except Exception:
                            failed_ports.append(port)
                    
                    # Rate limiting
                    if self.config.rate_limit > 0:
                        await asyncio.sleep(self.config.rate_limit)
        
        except Exception as e:
            logger.error(f"Async IP scan error for {target_ip}: {e}")
        
        # Create result
        scan_duration = time.time() - start_time
        avg_port_time = sum(port_timings.values()) / len(port_timings) if port_timings else 0
        success_rate = len(open_ports) / len(port_list) if port_list else 0
        
        return PortScanResult(
            target_ip=target_ip,
            ports_scanned=port_list,
            open_ports=open_ports,
            proxy_candidates=candidates,
            scan_duration=scan_duration,
            avg_port_time=avg_port_time,
            success_rate=success_rate,
            port_timings=port_timings,
            failed_ports=failed_ports,
            timeout_ports=timeout_ports
        )
    
    def scan_ip_sync(self, target_ip: str) -> PortScanResult:
        """Synchronously scan all ports for a single IP"""
        start_time = time.time()
        port_list = self.generate_port_list(target_ip)
        candidates = []
        open_ports = []
        failed_ports = []
        timeout_ports = []
        port_timings = {}
        
        try:
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                # Submit port scan tasks
                future_to_port = {}
                
                for port in port_list:
                    future = executor.submit(self.scan_port_sync, target_ip, port)
                    future_to_port[future] = port
                    
                    # Apply rate limiting
                    if self.config.rate_limit > 0:
                        time.sleep(self.config.rate_limit)
                
                # Collect results
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    port_start = time.time()
                    
                    try:
                        result = future.result(timeout=self.config.connect_timeout + 2)
                        port_time = (time.time() - port_start) * 1000
                        port_timings[port] = port_time
                        
                        if result:
                            candidates.append(result)
                            open_ports.append(port)
                    except TimeoutError:
                        timeout_ports.append(port)
                    except Exception:
                        failed_ports.append(port)
        
        except Exception as e:
            logger.error(f"Sync IP scan error for {target_ip}: {e}")
        
        # Create result
        scan_duration = time.time() - start_time
        avg_port_time = sum(port_timings.values()) / len(port_timings) if port_timings else 0
        success_rate = len(open_ports) / len(port_list) if port_list else 0
        
        return PortScanResult(
            target_ip=target_ip,
            ports_scanned=port_list,
            open_ports=open_ports,
            proxy_candidates=candidates,
            scan_duration=scan_duration,
            avg_port_time=avg_port_time,
            success_rate=success_rate,
            port_timings=port_timings,
            failed_ports=failed_ports,
            timeout_ports=timeout_ports
        )
    
    async def _fallback_to_sync_ip(self, target_ip: str) -> PortScanResult:
        """Fallback to sync scanning for single IP"""
        return self.scan_ip_sync(target_ip)


class PortDiscoveryEngine:
    """High-level port discovery engine coordinating multiple IPs"""
    
    def __init__(self, config: PortScanConfig):
        self.config = config
        self.scanner = ProxyPortScanner(config)
        self.results: List[PortScanResult] = []
    
    async def discover_async(self) -> List[PortScanResult]:
        """Asynchronously discover proxies across all target IPs"""
        results = []
        
        try:
            # Scan IPs in parallel but limit concurrency
            semaphore = asyncio.Semaphore(10)  # Max 10 IPs at once
            
            async def scan_with_semaphore(ip):
                async with semaphore:
                    return await self.scanner.scan_ip_async(ip)
            
            tasks = [scan_with_semaphore(ip) for ip in self.config.target_ips]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions
            results = [r for r in results if isinstance(r, PortScanResult)]
            
        except Exception as e:
            logger.error(f"Async discovery error: {e}")
        
        self.results = results
        return results
    
    def discover_sync(self) -> List[PortScanResult]:
        """Synchronously discover proxies across all target IPs"""
        results = []
        
        try:
            with ThreadPoolExecutor(max_workers=5) as executor:  # Limit IP concurrency
                future_to_ip = {
                    executor.submit(self.scanner.scan_ip_sync, ip): ip
                    for ip in self.config.target_ips
                }
                
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        logger.error(f"IP scan failed for {ip}: {e}")
        
        except Exception as e:
            logger.error(f"Sync discovery error: {e}")
        
        self.results = results
        return results
    
    def discover(self, use_async: bool = True) -> List[PortScanResult]:
        """Discover proxies (async or sync)"""
        if use_async and HAS_AIOHTTP:
            return asyncio.run(self.discover_async())
        else:
            return self.discover_sync()
    
    def get_all_proxy_candidates(self) -> List[ProxyInfo]:
        """Get all proxy candidates from all scan results"""
        candidates = []
        for result in self.results:
            candidates.extend(result.proxy_candidates)
        return candidates
    
    def get_summary_stats(self) -> Dict[str, any]:
        """Get summary statistics from all scans"""
        if not self.results:
            return {}
        
        total_scanned = sum(len(r.ports_scanned) for r in self.results)
        total_open = sum(len(r.open_ports) for r in self.results)
        total_candidates = sum(len(r.proxy_candidates) for r in self.results)
        total_duration = sum(r.scan_duration for r in self.results)
        
        return {
            'ips_scanned': len(self.results),
            'total_ports_scanned': total_scanned,
            'total_open_ports': total_open,
            'total_proxy_candidates': total_candidates,
            'total_scan_duration': total_duration,
            'avg_ports_per_ip': total_scanned / len(self.results) if self.results else 0,
            'proxy_discovery_rate': total_candidates / total_scanned if total_scanned else 0
        }