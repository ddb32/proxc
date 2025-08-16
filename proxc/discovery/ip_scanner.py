"""
Advanced IP Range Scanner for Proxy Discovery
=============================================

Intelligent IP range scanning targeting cloud providers and ISP subnets
for discovering proxy servers with optimized scanning patterns.
"""

import asyncio
import ipaddress
import json
import logging
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Union, Iterator
from urllib.parse import urlparse

# Third-party imports with fallbacks
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

# Import our core models
from ..proxy_core.models import ProxyInfo, ProxyProtocol, ProxyStatus
from ..proxy_core.config import ConfigManager

logger = logging.getLogger(__name__)


class CloudProvider(Enum):
    """Supported cloud providers for IP range scanning"""
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    DIGITALOCEAN = "digitalocean"
    OVHCLOUD = "ovh"
    LINODE = "linode"
    VULTR = "vultr"
    ALIBABA = "alibaba"
    

@dataclass
class ScanConfig:
    """Configuration for IP range scanning operations"""
    # Target configuration
    ip_ranges: List[str] = field(default_factory=list)
    cloud_providers: List[CloudProvider] = field(default_factory=list)
    exclude_ranges: List[str] = field(default_factory=list)
    
    # Scanning parameters
    max_workers: int = 50
    timeout: int = 5
    port_list: List[int] = field(default_factory=lambda: [80, 8080, 3128, 8888, 1080])
    scan_random_ports: bool = False
    random_port_count: int = 10
    
    # Performance settings
    rate_limit: float = 0.1  # Delay between scans
    batch_size: int = 100
    retry_attempts: int = 2
    use_geolocation: bool = True
    
    # Filtering
    exclude_private: bool = True
    exclude_localhost: bool = True
    min_success_threshold: int = 1
    
    # Output
    save_intermediate_results: bool = True
    result_cache_ttl: int = 3600


@dataclass
class ScanResult:
    """Results from IP range scanning operation"""
    scan_id: str
    config: ScanConfig
    
    # Discovery results
    total_ips_scanned: int = 0
    open_ports_found: int = 0
    proxy_candidates: List[ProxyInfo] = field(default_factory=list)
    failed_ips: Set[str] = field(default_factory=set)
    
    # Performance metrics
    scan_duration: float = 0.0
    avg_response_time: float = 0.0
    ips_per_second: float = 0.0
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    cloud_ranges_used: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class CloudProviderRanges:
    """Cloud provider IP range management"""
    
    # Static IP ranges for major cloud providers (subset for security)
    CLOUD_RANGES = {
        CloudProvider.AWS: [
            "3.0.0.0/8", "13.0.0.0/8", "15.0.0.0/8", "18.0.0.0/15",
            "34.0.0.0/9", "35.0.0.0/9", "52.0.0.0/8", "54.0.0.0/8"
        ],
        CloudProvider.GCP: [
            "8.34.208.0/20", "8.35.192.0/21", "23.236.48.0/20",
            "34.64.0.0/10", "35.184.0.0/13", "35.192.0.0/14"
        ],
        CloudProvider.AZURE: [
            "13.64.0.0/11", "13.96.0.0/13", "13.104.0.0/14",
            "20.0.0.0/8", "40.64.0.0/10", "52.224.0.0/12"
        ],
        CloudProvider.DIGITALOCEAN: [
            "138.197.0.0/16", "142.93.0.0/16", "143.110.0.0/16",
            "157.230.0.0/16", "159.89.0.0/16", "167.99.0.0/16"
        ],
        CloudProvider.OVHCLOUD: [
            "5.39.0.0/16", "51.15.0.0/16", "51.75.0.0/16",
            "51.77.0.0/16", "51.79.0.0/16", "51.83.0.0/16"
        ]
    }
    
    @classmethod
    def get_ranges(cls, provider: CloudProvider) -> List[str]:
        """Get IP ranges for a specific cloud provider"""
        return cls.CLOUD_RANGES.get(provider, [])
    
    @classmethod
    def get_all_ranges(cls, providers: List[CloudProvider]) -> List[str]:
        """Get combined IP ranges for multiple providers"""
        ranges = []
        for provider in providers:
            ranges.extend(cls.get_ranges(provider))
        return ranges


class ISPSubnetDiscoverer:
    """ISP subnet discovery and expansion"""
    
    # Major ISP ASN ranges for discovery
    ISP_ASN_RANGES = {
        "comcast": [7922, 33650, 33651, 33652, 33653],
        "verizon": [701, 702, 703, 19262],
        "att": [7018, 6389, 13979, 20057],
        "charter": [20115, 11427, 33363],
        "cox": [22773, 394089],
        "centurylink": [209, 3561, 3549]
    }
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.discovered_subnets: Set[str] = set()
    
    def discover_isp_subnets(self, seed_proxies: List[ProxyInfo]) -> List[str]:
        """Discover ISP subnets around successful proxies"""
        subnets = set()
        
        for proxy in seed_proxies:
            try:
                # Expand around successful proxy IPs
                ip = ipaddress.ip_address(proxy.ip)
                if ip.version == 4:
                    # Generate /24 and /16 subnets
                    network_24 = ipaddress.ip_network(f"{ip}/{24}", strict=False)
                    network_16 = ipaddress.ip_network(f"{ip}/{16}", strict=False)
                    
                    subnets.add(str(network_24))
                    subnets.add(str(network_16))
                    
            except (ValueError, ipaddress.AddressValueError) as e:
                logger.warning(f"Invalid IP for subnet discovery: {proxy.ip}: {e}")
        
        return list(subnets)


class IPRangeScanner:
    """Advanced IP range scanner for proxy discovery"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.cloud_ranges = CloudProviderRanges()
        self.isp_discoverer = ISPSubnetDiscoverer(config)
        self.scan_stats = {
            'scanned': 0,
            'found': 0,
            'errors': 0
        }
    
    def generate_scan_targets(self) -> Iterator[Tuple[str, int]]:
        """Generate IP:port combinations for scanning"""
        ip_targets = set()
        
        # Add configured IP ranges
        for range_str in self.config.ip_ranges:
            try:
                network = ipaddress.ip_network(range_str, strict=False)
                ip_targets.update([str(ip) for ip in network.hosts()])
            except (ValueError, ipaddress.AddressValueError) as e:
                logger.error(f"Invalid IP range: {range_str}: {e}")
        
        # Add cloud provider ranges
        if self.config.cloud_providers:
            cloud_ranges = self.cloud_ranges.get_all_ranges(self.config.cloud_providers)
            for range_str in cloud_ranges:
                try:
                    network = ipaddress.ip_network(range_str, strict=False)
                    # Limit to reasonable subnet sizes for cloud scanning
                    if network.prefixlen >= 20:  # /20 = 4096 IPs max
                        ip_targets.update([str(ip) for ip in network.hosts()])
                except (ValueError, ipaddress.AddressValueError) as e:
                    logger.error(f"Invalid cloud range: {range_str}: {e}")
        
        # Filter out excluded ranges
        filtered_targets = self._filter_excluded_ips(ip_targets)
        
        # Generate IP:port combinations
        ports = self._generate_port_list()
        for ip in filtered_targets:
            for port in ports:
                yield ip, port
    
    def _filter_excluded_ips(self, ip_targets: Set[str]) -> Set[str]:
        """Filter out excluded IP addresses"""
        filtered = set()
        
        # Build exclusion networks
        exclude_networks = []
        for exclude_range in self.config.exclude_ranges:
            try:
                exclude_networks.append(ipaddress.ip_network(exclude_range, strict=False))
            except (ValueError, ipaddress.AddressValueError):
                continue
        
        for ip_str in ip_targets:
            try:
                ip = ipaddress.ip_address(ip_str)
                
                # Check exclusions
                if self.config.exclude_private and ip.is_private:
                    continue
                if self.config.exclude_localhost and ip.is_loopback:
                    continue
                
                # Check custom exclusion ranges
                excluded = False
                for network in exclude_networks:
                    if ip in network:
                        excluded = True
                        break
                
                if not excluded:
                    filtered.add(ip_str)
                    
            except (ValueError, ipaddress.AddressValueError):
                continue
        
        return filtered
    
    def _generate_port_list(self) -> List[int]:
        """Generate list of ports to scan"""
        ports = list(self.config.port_list)
        
        if self.config.scan_random_ports:
            # Add random ports commonly used by proxies
            random_ports = [8000, 8001, 8008, 8080, 8081, 8082, 8083, 8090, 8118, 
                          8123, 8888, 9000, 9001, 9080, 9090, 3128, 3129, 3130]
            ports.extend(random.sample(random_ports, 
                                     min(self.config.random_port_count, len(random_ports))))
        
        return list(set(ports))  # Remove duplicates
    
    async def scan_target_async(self, ip: str, port: int, session: aiohttp.ClientSession) -> Optional[ProxyInfo]:
        """Asynchronously scan a single IP:port target"""
        try:
            proxy_url = f"http://{ip}:{port}"
            
            # Test proxy connectivity
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            async with session.get(
                'http://httpbin.org/ip',
                proxy=proxy_url,
                timeout=timeout,
                ssl=False
            ) as response:
                if response.status == 200:
                    # Found potential proxy
                    proxy = ProxyInfo(
                        ip=ip,
                        port=port,
                        protocol=ProxyProtocol.HTTP,
                        status=ProxyStatus.WORKING,
                        response_time=self.config.timeout * 1000,  # Rough estimate
                        discovered_at=datetime.utcnow(),
                        source="ip_scanner"
                    )
                    self.scan_stats['found'] += 1
                    return proxy
                    
        except Exception as e:
            self.scan_stats['errors'] += 1
            logger.debug(f"Scan failed for {ip}:{port}: {e}")
        
        self.scan_stats['scanned'] += 1
        return None
    
    def scan_target_sync(self, ip: str, port: int) -> Optional[ProxyInfo]:
        """Synchronously scan a single IP:port target"""
        try:
            # Quick connection test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                # Port is open, create proxy candidate
                proxy = ProxyInfo(
                    ip=ip,
                    port=port,
                    protocol=ProxyProtocol.HTTP,
                    status=ProxyStatus.UNTESTED,
                    discovered_at=datetime.utcnow(),
                    source="ip_scanner"
                )
                self.scan_stats['found'] += 1
                return proxy
                
        except Exception as e:
            self.scan_stats['errors'] += 1
            logger.debug(f"Scan failed for {ip}:{port}: {e}")
        
        self.scan_stats['scanned'] += 1
        return None
    
    async def scan_async(self) -> ScanResult:
        """Perform asynchronous IP range scanning"""
        if not HAS_AIOHTTP:
            return await self._fallback_to_sync()
        
        scan_id = f"scan_{int(time.time())}"
        start_time = time.time()
        candidates = []
        
        try:
            connector = aiohttp.TCPConnector(
                limit=self.config.max_workers,
                limit_per_host=10,
                ttl_dns_cache=300,
                use_dns_cache=True
            )
            
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            ) as session:
                
                # Generate tasks in batches
                tasks = []
                target_count = 0
                
                for ip, port in self.generate_scan_targets():
                    if len(tasks) >= self.config.batch_size:
                        # Process batch
                        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                        candidates.extend([r for r in batch_results if isinstance(r, ProxyInfo)])
                        tasks = []
                        
                        # Rate limiting
                        if self.config.rate_limit > 0:
                            await asyncio.sleep(self.config.rate_limit)
                    
                    tasks.append(self.scan_target_async(ip, port, session))
                    target_count += 1
                
                # Process remaining tasks
                if tasks:
                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                    candidates.extend([r for r in batch_results if isinstance(r, ProxyInfo)])
        
        except Exception as e:
            logger.error(f"Async scan error: {e}")
        
        # Create result
        scan_duration = time.time() - start_time
        result = ScanResult(
            scan_id=scan_id,
            config=self.config,
            total_ips_scanned=target_count,
            open_ports_found=len(candidates),
            proxy_candidates=candidates,
            scan_duration=scan_duration,
            ips_per_second=target_count / scan_duration if scan_duration > 0 else 0,
            cloud_ranges_used=self.cloud_ranges.get_all_ranges(self.config.cloud_providers)
        )
        
        return result
    
    def scan_sync(self) -> ScanResult:
        """Perform synchronous IP range scanning"""
        scan_id = f"scan_{int(time.time())}"
        start_time = time.time()
        candidates = []
        
        try:
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                # Submit scan tasks
                future_to_target = {}
                target_count = 0
                
                for ip, port in self.generate_scan_targets():
                    future = executor.submit(self.scan_target_sync, ip, port)
                    future_to_target[future] = (ip, port)
                    target_count += 1
                    
                    # Apply rate limiting
                    if self.config.rate_limit > 0:
                        time.sleep(self.config.rate_limit)
                
                # Collect results
                for future in as_completed(future_to_target):
                    try:
                        result = future.result(timeout=self.config.timeout + 5)
                        if result:
                            candidates.append(result)
                    except Exception as e:
                        ip, port = future_to_target[future]
                        logger.debug(f"Future failed for {ip}:{port}: {e}")
        
        except Exception as e:
            logger.error(f"Sync scan error: {e}")
        
        # Create result
        scan_duration = time.time() - start_time
        result = ScanResult(
            scan_id=scan_id,
            config=self.config,
            total_ips_scanned=target_count,
            open_ports_found=len(candidates),
            proxy_candidates=candidates,
            scan_duration=scan_duration,
            ips_per_second=target_count / scan_duration if scan_duration > 0 else 0,
            cloud_ranges_used=self.cloud_ranges.get_all_ranges(self.config.cloud_providers)
        )
        
        return result
    
    async def _fallback_to_sync(self) -> ScanResult:
        """Fallback to sync scanning if async is unavailable"""
        logger.info("aiohttp unavailable, falling back to synchronous scanning")
        return self.scan_sync()
    
    def scan(self, use_async: bool = True) -> ScanResult:
        """Perform IP range scanning (async or sync)"""
        if use_async and HAS_AIOHTTP:
            return asyncio.run(self.scan_async())
        else:
            return self.scan_sync()


# Convenience functions
def create_cloud_scan_config(
    providers: List[CloudProvider],
    max_workers: int = 50,
    timeout: int = 5,
    ports: List[int] = None
) -> ScanConfig:
    """Create scan configuration for cloud provider scanning"""
    if ports is None:
        ports = [80, 8080, 3128, 8888]
    
    return ScanConfig(
        cloud_providers=providers,
        max_workers=max_workers,
        timeout=timeout,
        port_list=ports,
        exclude_private=True,
        exclude_localhost=True
    )


def create_custom_range_config(
    ip_ranges: List[str],
    max_workers: int = 30,
    timeout: int = 8,
    ports: List[int] = None
) -> ScanConfig:
    """Create scan configuration for custom IP ranges"""
    if ports is None:
        ports = [80, 8080, 3128, 8888, 1080, 9050]
    
    return ScanConfig(
        ip_ranges=ip_ranges,
        max_workers=max_workers,
        timeout=timeout,
        port_list=ports,
        scan_random_ports=True,
        random_port_count=5
    )