"""IP Rotation Framework - Professional proxy chain rotation and management"""

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Callable, Any
from collections import deque, defaultdict
from enum import Enum

from ..proxy_core.models import ProxyInfo, ProxyProtocol


class RotationStrategy(Enum):
    """Available IP rotation strategies"""
    ROUND_ROBIN = "round_robin"
    RANDOM = "random"
    WEIGHTED = "weighted"
    HEALTH_BASED = "health_based"
    GEOGRAPHIC = "geographic"
    PROTOCOL_BASED = "protocol_based"


class ProxyHealthStatus(Enum):
    """Proxy health status for rotation decisions"""
    HEALTHY = "healthy"
    DEGRADED = "degraded" 
    FAILING = "failing"
    BLACKLISTED = "blacklisted"


@dataclass
class ProxyHealth:
    """Detailed proxy health information"""
    proxy: ProxyInfo
    status: ProxyHealthStatus = ProxyHealthStatus.HEALTHY
    success_rate: float = 1.0
    avg_response_time: float = 0.0
    consecutive_failures: int = 0
    last_success: Optional[float] = None
    last_failure: Optional[float] = None
    failure_reasons: List[str] = field(default_factory=list)
    reputation_score: float = 1.0
    blacklist_until: Optional[float] = None


@dataclass
class RotationConfig:
    """Configuration for IP rotation"""
    strategy: RotationStrategy = RotationStrategy.HEALTH_BASED
    max_consecutive_failures: int = 3
    blacklist_duration: float = 300.0  # 5 minutes
    health_check_interval: float = 60.0  # 1 minute
    min_success_rate: float = 0.7
    max_response_time: float = 10000.0  # 10 seconds
    rotation_interval: float = 30.0  # 30 seconds
    enable_geographic_rotation: bool = True
    preferred_countries: List[str] = field(default_factory=list)
    avoid_countries: List[str] = field(default_factory=list)
    protocol_weights: Dict[str, float] = field(default_factory=lambda: {
        'http': 1.0,
        'https': 1.2,
        'socks4': 0.8,
        'socks5': 1.1
    })


class IPRotationManager:
    """Professional IP rotation and proxy chain management"""
    
    def __init__(self, config: Optional[RotationConfig] = None):
        self.config = config or RotationConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Proxy pools
        self.active_proxies: List[ProxyInfo] = []
        self.proxy_health: Dict[str, ProxyHealth] = {}
        self.blacklisted_proxies: Set[str] = set()
        
        # Rotation state
        self.current_index = 0
        self.rotation_history: deque = deque(maxlen=1000)
        self.geographic_pools: Dict[str, List[ProxyInfo]] = defaultdict(list)
        self.protocol_pools: Dict[str, List[ProxyInfo]] = defaultdict(list)
        
        # Performance tracking
        self.rotation_stats = {
            'total_rotations': 0,
            'successful_connections': 0,
            'failed_connections': 0,
            'blacklist_events': 0,
            'recovery_events': 0
        }
        
        # Background tasks
        self.health_check_task: Optional[asyncio.Task] = None
        self.rotation_task: Optional[asyncio.Task] = None
        self.running = False
        
        self.logger.info("IP Rotation Manager initialized")
    
    async def start(self):
        """Start the rotation manager"""
        if self.running:
            return
        
        self.running = True
        
        # Start background tasks
        self.health_check_task = asyncio.create_task(self._health_monitor())
        self.rotation_task = asyncio.create_task(self._rotation_manager())
        
        self.logger.info("IP Rotation Manager started")
    
    async def stop(self):
        """Stop the rotation manager"""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel background tasks
        if self.health_check_task:
            self.health_check_task.cancel()
            try:
                await self.health_check_task
            except asyncio.CancelledError:
                pass
        
        if self.rotation_task:
            self.rotation_task.cancel()
            try:
                await self.rotation_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("IP Rotation Manager stopped")
    
    def add_proxies(self, proxies: List[ProxyInfo]):
        """Add proxies to the rotation pool"""
        for proxy in proxies:
            if proxy.address not in self.proxy_health:
                # Initialize health tracking
                self.proxy_health[proxy.address] = ProxyHealth(proxy=proxy)
                self.active_proxies.append(proxy)
                
                # Add to geographic and protocol pools
                if proxy.geo_location and proxy.geo_location.country_code:
                    self.geographic_pools[proxy.geo_location.country_code].append(proxy)
                
                self.protocol_pools[proxy.protocol.value].append(proxy)
        
        self.logger.info(f"Added {len(proxies)} proxies to rotation pool. Total: {len(self.active_proxies)}")
    
    def remove_proxy(self, proxy_address: str):
        """Remove proxy from rotation pool"""
        # Remove from active list
        self.active_proxies = [p for p in self.active_proxies if p.address != proxy_address]
        
        # Remove from health tracking
        if proxy_address in self.proxy_health:
            proxy = self.proxy_health[proxy_address].proxy
            del self.proxy_health[proxy_address]
            
            # Remove from geographic and protocol pools
            if proxy.geo_location and proxy.geo_location.country_code:
                country_pool = self.geographic_pools[proxy.geo_location.country_code]
                self.geographic_pools[proxy.geo_location.country_code] = [
                    p for p in country_pool if p.address != proxy_address
                ]
            
            protocol_pool = self.protocol_pools[proxy.protocol.value]
            self.protocol_pools[proxy.protocol.value] = [
                p for p in protocol_pool if p.address != proxy_address
            ]
        
        self.logger.info(f"Removed proxy {proxy_address} from rotation pool")
    
    def get_next_proxy(self, preferred_protocol: Optional[str] = None,
                      preferred_country: Optional[str] = None) -> Optional[ProxyInfo]:
        """Get next proxy based on rotation strategy"""
        
        if not self.active_proxies:
            return None
        
        # Filter available proxies
        available_proxies = self._get_available_proxies(preferred_protocol, preferred_country)
        
        if not available_proxies:
            return None
        
        # Apply rotation strategy
        selected_proxy = self._select_proxy_by_strategy(available_proxies)
        
        if selected_proxy:
            self.rotation_stats['total_rotations'] += 1
            self.rotation_history.append({
                'timestamp': time.time(),
                'proxy': selected_proxy.address,
                'strategy': self.config.strategy.value,
                'pool_size': len(available_proxies)
            })
        
        return selected_proxy
    
    def _get_available_proxies(self, preferred_protocol: Optional[str] = None,
                              preferred_country: Optional[str] = None) -> List[ProxyInfo]:
        """Get list of available proxies based on filters"""
        
        # Start with all active proxies
        available = []
        
        for proxy in self.active_proxies:
            health = self.proxy_health.get(proxy.address)
            if not health:
                continue
            
            # Skip blacklisted proxies
            if health.status == ProxyHealthStatus.BLACKLISTED:
                if health.blacklist_until and time.time() < health.blacklist_until:
                    continue
                else:
                    # Unblacklist if time has passed
                    health.status = ProxyHealthStatus.HEALTHY
                    health.blacklist_until = None
                    self.blacklisted_proxies.discard(proxy.address)
            
            # Skip failing proxies
            if health.status == ProxyHealthStatus.FAILING:
                continue
            
            # Protocol filter
            if preferred_protocol and proxy.protocol.value != preferred_protocol:
                continue
            
            # Country filter
            if preferred_country:
                if not proxy.geo_location or proxy.geo_location.country_code != preferred_country:
                    continue
            
            # Avoid blocked countries
            if (proxy.geo_location and proxy.geo_location.country_code in 
                self.config.avoid_countries):
                continue
            
            available.append(proxy)
        
        return available
    
    def _select_proxy_by_strategy(self, available_proxies: List[ProxyInfo]) -> Optional[ProxyInfo]:
        """Select proxy based on configured strategy"""
        
        if not available_proxies:
            return None
        
        if self.config.strategy == RotationStrategy.ROUND_ROBIN:
            return self._select_round_robin(available_proxies)
        
        elif self.config.strategy == RotationStrategy.RANDOM:
            return random.choice(available_proxies)
        
        elif self.config.strategy == RotationStrategy.WEIGHTED:
            return self._select_weighted(available_proxies)
        
        elif self.config.strategy == RotationStrategy.HEALTH_BASED:
            return self._select_health_based(available_proxies)
        
        elif self.config.strategy == RotationStrategy.GEOGRAPHIC:
            return self._select_geographic(available_proxies)
        
        elif self.config.strategy == RotationStrategy.PROTOCOL_BASED:
            return self._select_protocol_based(available_proxies)
        
        else:
            return random.choice(available_proxies)
    
    def _select_round_robin(self, available_proxies: List[ProxyInfo]) -> ProxyInfo:
        """Round-robin selection"""
        if self.current_index >= len(available_proxies):
            self.current_index = 0
        
        proxy = available_proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(available_proxies)
        
        return proxy
    
    def _select_weighted(self, available_proxies: List[ProxyInfo]) -> ProxyInfo:
        """Weighted selection based on protocol and health"""
        weights = []
        
        for proxy in available_proxies:
            health = self.proxy_health.get(proxy.address)
            if not health:
                continue
            
            # Base weight from protocol
            base_weight = self.config.protocol_weights.get(proxy.protocol.value, 1.0)
            
            # Adjust by health metrics
            health_multiplier = health.success_rate * health.reputation_score
            
            # Penalize slow proxies
            if health.avg_response_time > 0:
                response_penalty = max(0.1, 1.0 - (health.avg_response_time / self.config.max_response_time))
                health_multiplier *= response_penalty
            
            final_weight = base_weight * health_multiplier
            weights.append(final_weight)
        
        # Weighted random selection
        if weights:
            return random.choices(available_proxies, weights=weights)[0]
        else:
            return random.choice(available_proxies)
    
    def _select_health_based(self, available_proxies: List[ProxyInfo]) -> ProxyInfo:
        """Health-based selection prioritizing best performing proxies"""
        scored_proxies = []
        
        for proxy in available_proxies:
            health = self.proxy_health.get(proxy.address)
            if not health:
                continue
            
            # Calculate composite health score
            health_score = (
                health.success_rate * 0.4 +
                health.reputation_score * 0.3 +
                (1.0 - min(1.0, health.avg_response_time / self.config.max_response_time)) * 0.2 +
                (1.0 - min(1.0, health.consecutive_failures / self.config.max_consecutive_failures)) * 0.1
            )
            
            scored_proxies.append((proxy, health_score))
        
        # Sort by health score (descending) and pick from top 20%
        scored_proxies.sort(key=lambda x: x[1], reverse=True)
        
        top_count = max(1, len(scored_proxies) // 5)  # Top 20%
        top_proxies = scored_proxies[:top_count]
        
        # Randomly select from top performers
        return random.choice(top_proxies)[0]
    
    def _select_geographic(self, available_proxies: List[ProxyInfo]) -> ProxyInfo:
        """Geographic-based selection with country preferences"""
        if self.config.preferred_countries:
            # Try preferred countries first
            for country in self.config.preferred_countries:
                country_proxies = [p for p in available_proxies 
                                 if p.geo_location and p.geo_location.country_code == country]
                if country_proxies:
                    return random.choice(country_proxies)
        
        # Fallback to any available proxy
        return random.choice(available_proxies)
    
    def _select_protocol_based(self, available_proxies: List[ProxyInfo]) -> ProxyInfo:
        """Protocol-based selection with weights"""
        return self._select_weighted(available_proxies)  # Use weighted selection
    
    def record_connection_result(self, proxy_address: str, success: bool, 
                               response_time: float = 0.0, error_reason: Optional[str] = None):
        """Record connection result for health tracking"""
        
        health = self.proxy_health.get(proxy_address)
        if not health:
            return
        
        current_time = time.time()
        
        if success:
            self.rotation_stats['successful_connections'] += 1
            health.last_success = current_time
            health.consecutive_failures = 0
            
            # Update success rate (exponential moving average)
            health.success_rate = health.success_rate * 0.9 + 0.1
            
            # Update response time
            if response_time > 0:
                if health.avg_response_time == 0:
                    health.avg_response_time = response_time
                else:
                    health.avg_response_time = health.avg_response_time * 0.8 + response_time * 0.2
            
            # Improve reputation
            health.reputation_score = min(1.0, health.reputation_score + 0.01)
            
            # Recovery from degraded state
            if health.status == ProxyHealthStatus.DEGRADED and health.success_rate > self.config.min_success_rate:
                health.status = ProxyHealthStatus.HEALTHY
                self.rotation_stats['recovery_events'] += 1
        
        else:
            self.rotation_stats['failed_connections'] += 1
            health.last_failure = current_time
            health.consecutive_failures += 1
            
            if error_reason:
                health.failure_reasons.append(f"{current_time}:{error_reason}")
                # Keep only recent failure reasons
                if len(health.failure_reasons) > 10:
                    health.failure_reasons = health.failure_reasons[-10:]
            
            # Update success rate
            health.success_rate = health.success_rate * 0.9
            
            # Degrade reputation
            health.reputation_score = max(0.1, health.reputation_score - 0.05)
            
            # Update health status based on failures
            if health.consecutive_failures >= self.config.max_consecutive_failures:
                health.status = ProxyHealthStatus.BLACKLISTED
                health.blacklist_until = current_time + self.config.blacklist_duration
                self.blacklisted_proxies.add(proxy_address)
                self.rotation_stats['blacklist_events'] += 1
            elif health.success_rate < self.config.min_success_rate:
                health.status = ProxyHealthStatus.DEGRADED
    
    async def _health_monitor(self):
        """Background health monitoring task"""
        while self.running:
            try:
                await self._perform_health_check()
                await asyncio.sleep(self.config.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Health monitor error: {e}")
                await asyncio.sleep(self.config.health_check_interval)
    
    async def _rotation_manager(self):
        """Background rotation management task"""
        while self.running:
            try:
                await self._manage_rotation()
                await asyncio.sleep(self.config.rotation_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Rotation manager error: {e}")
                await asyncio.sleep(self.config.rotation_interval)
    
    async def _perform_health_check(self):
        """Perform periodic health checks"""
        current_time = time.time()
        
        # Check for proxies to unblacklist
        unblacklist_count = 0
        for address, health in self.proxy_health.items():
            if (health.status == ProxyHealthStatus.BLACKLISTED and 
                health.blacklist_until and current_time >= health.blacklist_until):
                health.status = ProxyHealthStatus.HEALTHY
                health.blacklist_until = None
                health.consecutive_failures = 0
                self.blacklisted_proxies.discard(address)
                unblacklist_count += 1
        
        if unblacklist_count > 0:
            self.logger.info(f"Unblacklisted {unblacklist_count} proxies")
    
    async def _manage_rotation(self):
        """Manage rotation strategy and pool health"""
        # Log rotation statistics
        total_proxies = len(self.active_proxies)
        healthy_proxies = len([h for h in self.proxy_health.values() 
                              if h.status == ProxyHealthStatus.HEALTHY])
        blacklisted_count = len(self.blacklisted_proxies)
        
        self.logger.debug(
            f"Rotation status: {healthy_proxies}/{total_proxies} healthy, "
            f"{blacklisted_count} blacklisted"
        )
    
    def get_rotation_stats(self) -> Dict[str, Any]:
        """Get rotation statistics"""
        total_proxies = len(self.active_proxies)
        healthy_count = len([h for h in self.proxy_health.values() 
                           if h.status == ProxyHealthStatus.HEALTHY])
        degraded_count = len([h for h in self.proxy_health.values() 
                            if h.status == ProxyHealthStatus.DEGRADED])
        blacklisted_count = len(self.blacklisted_proxies)
        
        return {
            'total_proxies': total_proxies,
            'healthy_proxies': healthy_count,
            'degraded_proxies': degraded_count,
            'blacklisted_proxies': blacklisted_count,
            'rotation_strategy': self.config.strategy.value,
            'statistics': self.rotation_stats.copy(),
            'geographic_pools': {country: len(proxies) for country, proxies in self.geographic_pools.items()},
            'protocol_pools': {protocol: len(proxies) for protocol, proxies in self.protocol_pools.items()}
        }
    
    def get_proxy_health_report(self) -> Dict[str, Any]:
        """Get detailed proxy health report"""
        health_report = {}
        
        for address, health in self.proxy_health.items():
            health_report[address] = {
                'status': health.status.value,
                'success_rate': health.success_rate,
                'avg_response_time': health.avg_response_time,
                'consecutive_failures': health.consecutive_failures,
                'reputation_score': health.reputation_score,
                'recent_failures': health.failure_reasons[-5:] if health.failure_reasons else [],
                'blacklisted_until': health.blacklist_until
            }
        
        return health_report


def create_ip_rotation_manager(strategy: str = "health_based", 
                              max_failures: int = 3) -> IPRotationManager:
    """Create IP rotation manager with specified strategy"""
    
    strategy_enum = RotationStrategy(strategy)
    config = RotationConfig(
        strategy=strategy_enum,
        max_consecutive_failures=max_failures
    )
    
    return IPRotationManager(config)