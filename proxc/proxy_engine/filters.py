"""Proxy Engine Filters - Advanced Proxy Filtering System

A comprehensive filtering system for proxy management with enterprise-grade
filtering capabilities, preset configurations, and statistical analysis.

Features:
- Multi-criteria filtering with complex boolean logic
- Geographic filtering with country, region, and ISP support
- Performance-based filtering with response time and success rate criteria
- Security-level filtering with threat assessment integration
- Protocol-specific filtering with SOCKS/HTTP support
- Predefined filter presets for common use cases
- Statistical analysis and filtering performance metrics
- Caching system for improved filtering performance

Version: 3.0.0
Author: Proxy Hunter Development Team
License: MIT
"""

import logging
import re
import statistics
import time
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Union, Callable
from ipaddress import IPv4Network, AddressValueError

# Import our core models (using exact names from models.py)
from ..proxy_core.models import (
    ProxyInfo, ProxyProtocol, AnonymityLevel, ThreatLevel, 
    ProxyStatus, ValidationStatus, SecurityLevel, OperationalGrade
)
from ..proxy_core.config import ConfigManager

# Configure logging
logger = logging.getLogger(__name__)


# ===============================================================================
# FILTER CRITERIA AND CONFIGURATION
# ===============================================================================

@dataclass
class FilterCriteria:
    """Comprehensive filtering criteria for proxy selection"""
    
    # Geographic filters
    countries: Optional[Set[str]] = None              # Include countries (ISO codes)
    exclude_countries: Optional[Set[str]] = None      # Exclude countries
    regions: Optional[Set[str]] = None                # Include regions/states
    cities: Optional[Set[str]] = None                 # Include cities
    asn_ranges: Optional[Set[int]] = None             # Include ASN numbers
    isps: Optional[Set[str]] = None                   # Include ISP names
    ip_networks: Optional[Set[str]] = None            # Include IP networks (CIDR)
    exclude_ip_networks: Optional[Set[str]] = None    # Exclude IP networks
    
    # Protocol and technical filters
    protocols: Optional[Set[ProxyProtocol]] = None    # HTTP, HTTPS, SOCKS4, SOCKS5
    ports: Optional[Set[int]] = None                  # Specific ports
    port_ranges: Optional[List[tuple]] = None         # Port ranges [(min, max), ...]
    requires_auth: Optional[bool] = None              # Authentication required/not
    ssl_support: Optional[bool] = None                # SSL/TLS support required
    
    # Quality and performance filters
    anonymity_levels: Optional[Set[AnonymityLevel]] = None  # Anonymity requirements
    min_anonymity: Optional[AnonymityLevel] = None          # Minimum anonymity level
    threat_levels: Optional[Set[ThreatLevel]] = None        # Allowed threat levels
    max_threat: Optional[ThreatLevel] = None                # Maximum threat level
    security_levels: Optional[Set[SecurityLevel]] = None   # Security requirements
    operational_grades: Optional[Set[OperationalGrade]] = None  # Quality grades
    
    # Performance metrics filters
    max_response_time: Optional[float] = None         # Maximum response time (ms)
    min_response_time: Optional[float] = None         # Minimum response time (ms)
    min_success_rate: Optional[float] = None          # Minimum success rate (0-1)
    max_success_rate: Optional[float] = None          # Maximum success rate (0-1)
    min_uptime: Optional[float] = None                # Minimum uptime percentage
    min_speed: Optional[float] = None                 # Minimum speed (bytes/sec)
    
    # Status and validation filters
    statuses: Optional[Set[ProxyStatus]] = None       # Proxy statuses
    validation_statuses: Optional[Set[ValidationStatus]] = None  # Validation statuses
    exclude_failed: bool = True                       # Exclude failed proxies
    only_validated: bool = False                      # Only validated proxies
    
    # Temporal filters
    discovered_after: Optional[datetime] = None       # Discovered after date
    discovered_before: Optional[datetime] = None      # Discovered before date
    validated_after: Optional[datetime] = None        # Last validated after
    max_age_hours: Optional[int] = None               # Maximum age in hours
    
    # Source and metadata filters
    sources: Optional[Set[str]] = None                # Include sources
    exclude_sources: Optional[Set[str]] = None        # Exclude sources
    tags: Optional[Set[str]] = None                   # Required tags
    exclude_tags: Optional[Set[str]] = None           # Excluded tags
    has_geo_data: Optional[bool] = None               # Geographic data required
    has_metrics: Optional[bool] = None                # Performance metrics required
    
    # Advanced filters
    custom_filters: Optional[List[Callable]] = None   # Custom filter functions
    limit: Optional[int] = None                       # Maximum results
    randomize: bool = False                           # Randomize results
    
    def __post_init__(self):
        """Validate and normalize filter criteria"""
        # Convert string sets to uppercase for countries
        if self.countries:
            self.countries = {c.upper() for c in self.countries}
        if self.exclude_countries:
            self.exclude_countries = {c.upper() for c in self.exclude_countries}
        
        # Validate IP networks
        if self.ip_networks:
            self._validate_ip_networks(self.ip_networks)
        if self.exclude_ip_networks:
            self._validate_ip_networks(self.exclude_ip_networks)
        
        # Validate port ranges
        if self.port_ranges:
            for port_range in self.port_ranges:
                if not (isinstance(port_range, tuple) and len(port_range) == 2):
                    raise ValueError(f"Invalid port range: {port_range}")
                min_port, max_port = port_range
                if not (1 <= min_port <= max_port <= 65535):
                    raise ValueError(f"Invalid port range values: {port_range}")
    
    def _validate_ip_networks(self, networks: Set[str]):
        """Validate IP network CIDR notation"""
        for network in networks:
            try:
                IPv4Network(network, strict=False)
            except AddressValueError as e:
                raise ValueError(f"Invalid IP network '{network}': {e}")
    
    def is_empty(self) -> bool:
        """Check if criteria is effectively empty"""
        return all(
            getattr(self, field.name) is None or 
            (isinstance(getattr(self, field.name), (set, list)) and len(getattr(self, field.name)) == 0)
            for field in self.__dataclass_fields__.values()
            if field.name not in ['exclude_failed', 'only_validated', 'randomize']
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert criteria to dictionary for serialization"""
        result = {}
        for field_name, field_def in self.__dataclass_fields__.items():
            value = getattr(self, field_name)
            if value is not None:
                if isinstance(value, set):
                    # Convert sets to lists for JSON serialization
                    if value and hasattr(next(iter(value)), 'value'):
                        # Handle enums
                        result[field_name] = [item.value for item in value]
                    else:
                        result[field_name] = list(value)
                elif hasattr(value, 'value'):
                    # Handle single enum
                    result[field_name] = value.value
                elif isinstance(value, datetime):
                    result[field_name] = value.isoformat()
                else:
                    result[field_name] = value
        return result


# ===============================================================================
# FILTER PRESETS
# ===============================================================================

class FilterPresets:
    """Predefined filter presets for common use cases"""
    
    @staticmethod
    def fast_proxies() -> FilterCriteria:
        """High-speed proxies with low latency"""
        return FilterCriteria(
            max_response_time=1000,  # Under 1 second
            min_success_rate=0.8,    # 80% success rate
            anonymity_levels={AnonymityLevel.ANONYMOUS, AnonymityLevel.ELITE},
            max_threat=ThreatLevel.MEDIUM,
            statuses={ProxyStatus.ACTIVE},
            only_validated=True,
            exclude_failed=True
        )
    
    @staticmethod
    def high_anonymity() -> FilterCriteria:
        """Maximum anonymity proxies"""
        return FilterCriteria(
            anonymity_levels={AnonymityLevel.ELITE},
            max_threat=ThreatLevel.LOW,
            security_levels={SecurityLevel.HIGH},
            ssl_support=True,
            statuses={ProxyStatus.ACTIVE},
            only_validated=True,
            exclude_failed=True
        )
    
    @staticmethod
    def us_proxies() -> FilterCriteria:
        """United States proxies only"""
        return FilterCriteria(
            countries={'US'},
            statuses={ProxyStatus.ACTIVE},
            anonymity_levels={AnonymityLevel.ANONYMOUS, AnonymityLevel.ELITE},
            max_threat=ThreatLevel.MEDIUM,
            only_validated=True
        )
    
    @staticmethod
    def socks_proxies() -> FilterCriteria:
        """SOCKS protocol proxies (4 and 5)"""
        return FilterCriteria(
            protocols={ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5},
            statuses={ProxyStatus.ACTIVE},
            anonymity_levels={AnonymityLevel.ANONYMOUS, AnonymityLevel.ELITE},
            max_threat=ThreatLevel.MEDIUM,
            only_validated=True
        )
    
    @staticmethod
    def residential_proxies() -> FilterCriteria:
        """Residential-like proxies (non-datacenter)"""
        return FilterCriteria(
            exclude_sources={'datacenter', 'hosting', 'cloud'},
            anonymity_levels={AnonymityLevel.ELITE},
            max_threat=ThreatLevel.LOW,
            statuses={ProxyStatus.ACTIVE},
            min_success_rate=0.7,
            only_validated=True
        )
    
    @staticmethod
    def low_risk_countries() -> FilterCriteria:
        """Proxies from low-risk countries"""
        safe_countries = {
            'US', 'CA', 'GB', 'DE', 'NL', 'FR', 'AU', 'JP', 
            'SE', 'NO', 'DK', 'FI', 'CH', 'AT', 'BE', 'LU'
        }
        return FilterCriteria(
            countries=safe_countries,
            max_threat=ThreatLevel.LOW,
            anonymity_levels={AnonymityLevel.ANONYMOUS, AnonymityLevel.ELITE},
            statuses={ProxyStatus.ACTIVE},
            only_validated=True
        )
    
    @staticmethod
    def enterprise_grade() -> FilterCriteria:
        """Enterprise-grade proxies with highest quality"""
        return FilterCriteria(
            operational_grades={OperationalGrade.ENTERPRISE, OperationalGrade.ELITE},
            anonymity_levels={AnonymityLevel.ELITE},
            security_levels={SecurityLevel.HIGH},
            max_threat=ThreatLevel.LOW,
            max_response_time=500,  # Very fast
            min_success_rate=0.95,  # Very reliable
            ssl_support=True,
            statuses={ProxyStatus.ACTIVE},
            only_validated=True,
            exclude_failed=True
        )
    
    @staticmethod
    def bulk_scraping() -> FilterCriteria:
        """Proxies suitable for bulk data scraping"""
        return FilterCriteria(
            protocols={ProxyProtocol.HTTP, ProxyProtocol.HTTPS},
            anonymity_levels={AnonymityLevel.ANONYMOUS, AnonymityLevel.ELITE},
            max_threat=ThreatLevel.MEDIUM,
            min_success_rate=0.6,
            max_response_time=5000,  # More tolerant for bulk work
            statuses={ProxyStatus.ACTIVE},
            only_validated=True
        )
    
    @staticmethod
    def social_media() -> FilterCriteria:
        """Proxies optimized for social media platforms"""
        return FilterCriteria(
            anonymity_levels={AnonymityLevel.ELITE},
            max_threat=ThreatLevel.LOW,
            residential_only=True,  # Would need implementation
            max_response_time=2000,
            min_success_rate=0.8,
            ssl_support=True,
            statuses={ProxyStatus.ACTIVE},
            only_validated=True
        )
    
    @staticmethod
    def get_all_presets() -> Dict[str, FilterCriteria]:
        """Get all available presets"""
        return {
            'fast': FilterPresets.fast_proxies(),
            'anonymous': FilterPresets.high_anonymity(),
            'us': FilterPresets.us_proxies(),
            'socks': FilterPresets.socks_proxies(),
            'residential': FilterPresets.residential_proxies(),
            'safe': FilterPresets.low_risk_countries(),
            'enterprise': FilterPresets.enterprise_grade(),
            'bulk': FilterPresets.bulk_scraping(),
            'social': FilterPresets.social_media()
        }


# ===============================================================================
# MAIN PROXY FILTER CLASS
# ===============================================================================

class ProxyFilter:
    """Advanced proxy filtering engine with performance optimization"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Filter performance metrics
        self.filter_stats = defaultdict(int)
        self.filter_times = defaultdict(list)
        
        # Caching for improved performance
        self._filter_cache = {}
        self._cache_ttl = 300  # 5 minutes
        self._last_cache_cleanup = time.time()
        
        self.logger.info("ProxyFilter initialized")
    
    def filter_proxies(self, proxies: List[ProxyInfo], 
                      criteria: FilterCriteria) -> List[ProxyInfo]:
        """Apply filtering criteria to proxy list"""
        if not proxies:
            return []
        
        if criteria.is_empty():
            # No filtering criteria - return all or apply limit
            result = list(proxies)
            if criteria.limit:
                result = result[:criteria.limit]
            return result
        
        start_time = time.time()
        
        # Check cache first
        cache_key = self._generate_cache_key(proxies, criteria)
        cached_result = self._get_cached_result(cache_key)
        if cached_result is not None:
            self.logger.debug(f"Cache hit for filter operation")
            return cached_result
        
        # Apply filters
        filtered_proxies = self._apply_filters(proxies, criteria)
        
        # Cache result
        self._cache_result(cache_key, filtered_proxies)
        
        # Record performance metrics
        duration = time.time() - start_time
        self.filter_stats['total_operations'] += 1
        self.filter_times['filter_duration'].append(duration)
        
        self.logger.info(f"Filtered {len(proxies)} → {len(filtered_proxies)} proxies in {duration:.3f}s")
        
        return filtered_proxies
    
    def _apply_filters(self, proxies: List[ProxyInfo], 
                      criteria: FilterCriteria) -> List[ProxyInfo]:
        """Apply all filtering criteria"""
        result = list(proxies)
        
        # Geographic filters
        result = self._apply_geographic_filters(result, criteria)
        
        # Protocol and technical filters
        result = self._apply_protocol_filters(result, criteria)
        
        # Quality and performance filters
        result = self._apply_quality_filters(result, criteria)
        
        # Status and validation filters
        result = self._apply_status_filters(result, criteria)
        
        # Temporal filters
        result = self._apply_temporal_filters(result, criteria)
        
        # Source and metadata filters
        result = self._apply_metadata_filters(result, criteria)
        
        # Custom filters
        result = self._apply_custom_filters(result, criteria)
        
        # Post-processing
        result = self._apply_post_processing(result, criteria)
        
        return result
    
    def _apply_geographic_filters(self, proxies: List[ProxyInfo], 
                                 criteria: FilterCriteria) -> List[ProxyInfo]:
        """Apply geographic filtering criteria"""
        if not any([criteria.countries, criteria.exclude_countries, criteria.regions,
                   criteria.cities, criteria.asn_ranges, criteria.isps,
                   criteria.ip_networks, criteria.exclude_ip_networks]):
            return proxies
        
        filtered = []
        
        for proxy in proxies:
            # Check country inclusion/exclusion
            if criteria.countries or criteria.exclude_countries:
                country = None
                if proxy.geo_location and proxy.geo_location.country_code:
                    country = proxy.geo_location.country_code.upper()
                
                if criteria.countries and (not country or country not in criteria.countries):
                    continue
                if criteria.exclude_countries and country and country in criteria.exclude_countries:
                    continue
            
            # Check regions
            if criteria.regions:
                region = None
                if proxy.geo_location and proxy.geo_location.region:
                    region = proxy.geo_location.region
                if not region or region not in criteria.regions:
                    continue
            
            # Check cities
            if criteria.cities:
                city = None
                if proxy.geo_location and proxy.geo_location.city:
                    city = proxy.geo_location.city
                if not city or city not in criteria.cities:
                    continue
            
            # Check ASN ranges
            if criteria.asn_ranges:
                asn = None
                if proxy.geo_location and proxy.geo_location.asn:
                    asn = proxy.geo_location.asn
                if not asn or asn not in criteria.asn_ranges:
                    continue
            
            # Check ISPs
            if criteria.isps:
                isp = None
                if proxy.geo_location and proxy.geo_location.isp:
                    isp = proxy.geo_location.isp
                if not isp or not any(isp_filter.lower() in isp.lower() 
                                    for isp_filter in criteria.isps):
                    continue
            
            # Check IP networks
            if criteria.ip_networks:
                if not self._ip_in_networks(proxy.host, criteria.ip_networks):
                    continue
            
            if criteria.exclude_ip_networks:
                if self._ip_in_networks(proxy.host, criteria.exclude_ip_networks):
                    continue
            
            filtered.append(proxy)
        
        return filtered
    
    def _apply_protocol_filters(self, proxies: List[ProxyInfo], 
                               criteria: FilterCriteria) -> List[ProxyInfo]:
        """Apply protocol and technical filtering criteria"""
        if not any([criteria.protocols, criteria.ports, criteria.port_ranges,
                   criteria.requires_auth, criteria.ssl_support]):
            return proxies
        
        filtered = []
        
        for proxy in proxies:
            # Check protocols
            if criteria.protocols and proxy.protocol not in criteria.protocols:
                continue
            
            # Check specific ports
            if criteria.ports and proxy.port not in criteria.ports:
                continue
            
            # Check port ranges
            if criteria.port_ranges:
                in_range = False
                for min_port, max_port in criteria.port_ranges:
                    if min_port <= proxy.port <= max_port:
                        in_range = True
                        break
                if not in_range:
                    continue
            
            # Check authentication requirement
            if criteria.requires_auth is not None:
                has_auth = proxy.is_authenticated
                if criteria.requires_auth != has_auth:
                    continue
            
            # Check SSL support (would need additional proxy testing)
            if criteria.ssl_support is not None:
                # This would require checking if proxy supports HTTPS
                # For now, assume HTTPS protocol implies SSL support
                supports_ssl = proxy.protocol in [ProxyProtocol.HTTPS]
                if criteria.ssl_support != supports_ssl:
                    continue
            
            filtered.append(proxy)
        
        return filtered
    
    def _apply_quality_filters(self, proxies: List[ProxyInfo], 
                              criteria: FilterCriteria) -> List[ProxyInfo]:
        """Apply quality and performance filtering criteria"""
        if not any([criteria.anonymity_levels, criteria.min_anonymity, criteria.threat_levels,
                   criteria.max_threat, criteria.security_levels, criteria.operational_grades,
                   criteria.max_response_time, criteria.min_response_time,
                   criteria.min_success_rate, criteria.max_success_rate,
                   criteria.min_uptime, criteria.min_speed]):
            return proxies
        
        filtered = []
        
        for proxy in proxies:
            # Check anonymity levels
            if criteria.anonymity_levels and proxy.anonymity_level not in criteria.anonymity_levels:
                continue
            
            # Check minimum anonymity
            if criteria.min_anonymity:
                anonymity_order = [AnonymityLevel.TRANSPARENT, AnonymityLevel.ANONYMOUS, AnonymityLevel.ELITE]
                if anonymity_order.index(proxy.anonymity_level) < anonymity_order.index(criteria.min_anonymity):
                    continue
            
            # Check threat levels
            if criteria.threat_levels and proxy.threat_level not in criteria.threat_levels:
                continue
            
            # Check maximum threat
            if criteria.max_threat:
                threat_order = [ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
                if threat_order.index(proxy.threat_level) > threat_order.index(criteria.max_threat):
                    continue
            
            # Check security levels
            if criteria.security_levels and proxy.security_level not in criteria.security_levels:
                continue
            
            # Check operational grades
            if criteria.operational_grades and proxy.operational_grade not in criteria.operational_grades:
                continue
            
            # Check response time
            if proxy.metrics.response_time is not None:
                if criteria.max_response_time and proxy.metrics.response_time > criteria.max_response_time:
                    continue
                if criteria.min_response_time and proxy.metrics.response_time < criteria.min_response_time:
                    continue
            
            # Check success rate
            if proxy.metrics.success_rate is not None:
                if criteria.min_success_rate and proxy.metrics.success_rate < criteria.min_success_rate:
                    continue
                if criteria.max_success_rate and proxy.metrics.success_rate > criteria.max_success_rate:
                    continue
            
            # Check uptime
            if criteria.min_uptime and proxy.metrics.uptime_percentage is not None:
                if proxy.metrics.uptime_percentage < criteria.min_uptime:
                    continue
            
            # Check speed
            if criteria.min_speed and proxy.metrics.average_speed is not None:
                if proxy.metrics.average_speed < criteria.min_speed:
                    continue
            
            filtered.append(proxy)
        
        return filtered
    
    def _apply_status_filters(self, proxies: List[ProxyInfo], 
                             criteria: FilterCriteria) -> List[ProxyInfo]:
        """Apply status and validation filtering criteria"""
        filtered = []
        
        for proxy in proxies:
            # Check status
            if criteria.statuses and proxy.status not in criteria.statuses:
                continue
            
            # Check validation status
            if criteria.validation_statuses and proxy.validation_status not in criteria.validation_statuses:
                continue
            
            # Exclude failed proxies
            if criteria.exclude_failed and proxy.status == ProxyStatus.FAILED:
                continue
            
            # Only validated proxies
            if criteria.only_validated and proxy.validation_status != ValidationStatus.VALID:
                continue
            
            filtered.append(proxy)
        
        return filtered
    
    def _apply_temporal_filters(self, proxies: List[ProxyInfo], 
                               criteria: FilterCriteria) -> List[ProxyInfo]:
        """Apply temporal filtering criteria"""
        if not any([criteria.discovered_after, criteria.discovered_before,
                   criteria.validated_after, criteria.max_age_hours]):
            return proxies
        
        filtered = []
        current_time = datetime.utcnow()
        
        for proxy in proxies:
            # Check discovery date
            if criteria.discovered_after and proxy.discovered_at < criteria.discovered_after:
                continue
            if criteria.discovered_before and proxy.discovered_at > criteria.discovered_before:
                continue
            
            # Check validation date
            if criteria.validated_after and proxy.metrics.last_checked:
                if proxy.metrics.last_checked < criteria.validated_after:
                    continue
            
            # Check maximum age
            if criteria.max_age_hours:
                max_age = timedelta(hours=criteria.max_age_hours)
                if current_time - proxy.discovered_at > max_age:
                    continue
            
            filtered.append(proxy)
        
        return filtered
    
    def _apply_metadata_filters(self, proxies: List[ProxyInfo], 
                               criteria: FilterCriteria) -> List[ProxyInfo]:
        """Apply source and metadata filtering criteria"""
        if not any([criteria.sources, criteria.exclude_sources, criteria.tags,
                   criteria.exclude_tags, criteria.has_geo_data, criteria.has_metrics]):
            return proxies
        
        filtered = []
        
        for proxy in proxies:
            # Check sources
            if criteria.sources and (not proxy.source or proxy.source not in criteria.sources):
                continue
            if criteria.exclude_sources and proxy.source and proxy.source in criteria.exclude_sources:
                continue
            
            # Check tags
            if criteria.tags:
                proxy_tags = set(proxy.tags) if proxy.tags else set()
                if not criteria.tags.issubset(proxy_tags):
                    continue
            
            if criteria.exclude_tags:
                proxy_tags = set(proxy.tags) if proxy.tags else set()
                if criteria.exclude_tags.intersection(proxy_tags):
                    continue
            
            # Check geo data requirement
            if criteria.has_geo_data is not None:
                has_geo = proxy.geo_location is not None
                if criteria.has_geo_data != has_geo:
                    continue
            
            # Check metrics requirement
            if criteria.has_metrics is not None:
                has_metrics = (proxy.metrics.response_time is not None or 
                             proxy.metrics.success_rate is not None)
                if criteria.has_metrics != has_metrics:
                    continue
            
            filtered.append(proxy)
        
        return filtered
    
    def _apply_custom_filters(self, proxies: List[ProxyInfo], 
                             criteria: FilterCriteria) -> List[ProxyInfo]:
        """Apply custom filter functions"""
        if not criteria.custom_filters:
            return proxies
        
        filtered = list(proxies)
        
        for filter_func in criteria.custom_filters:
            try:
                filtered = [proxy for proxy in filtered if filter_func(proxy)]
            except Exception as e:
                self.logger.warning(f"Custom filter function failed: {e}")
        
        return filtered
    
    def _apply_post_processing(self, proxies: List[ProxyInfo], 
                              criteria: FilterCriteria) -> List[ProxyInfo]:
        """Apply post-processing like randomization and limiting"""
        result = list(proxies)
        
        # Randomize if requested
        if criteria.randomize:
            import random
            random.shuffle(result)
        
        # Apply limit
        if criteria.limit and len(result) > criteria.limit:
            result = result[:criteria.limit]
        
        return result
    
    def _ip_in_networks(self, ip: str, networks: Set[str]) -> bool:
        """Check if IP address is in any of the specified networks"""
        try:
            from ipaddress import ip_address, ip_network
            ip_obj = ip_address(ip)
            
            for network_str in networks:
                try:
                    network = ip_network(network_str, strict=False)
                    if ip_obj in network:
                        return True
                except Exception:
                    continue
            
            return False
        except Exception:
            return False
    
    def get_filter_statistics(self, original_proxies: List[ProxyInfo],
                             filtered_proxies: List[ProxyInfo],
                             criteria: FilterCriteria) -> Dict[str, Any]:
        """Generate filtering statistics and analysis"""
        original_count = len(original_proxies)
        filtered_count = len(filtered_proxies)
        
        stats = {
            'original_count': original_count,
            'filtered_count': filtered_count,
            'pass_rate': (filtered_count / original_count * 100) if original_count > 0 else 0,
            'filter_efficiency': filtered_count / original_count if original_count > 0 else 0,
            'criteria_applied': self._get_active_criteria(criteria)
        }
        
        # Add distribution analysis
        if filtered_proxies:
            stats.update({
                'protocol_distribution': self._get_protocol_distribution(filtered_proxies),
                'country_distribution': self._get_country_distribution(filtered_proxies),
                'anonymity_distribution': self._get_anonymity_distribution(filtered_proxies),
                'avg_response_time': self._get_average_response_time(filtered_proxies),
                'avg_success_rate': self._get_average_success_rate(filtered_proxies)
            })
        
        return stats
    
    def _get_active_criteria(self, criteria: FilterCriteria) -> List[str]:
        """Get list of active filtering criteria"""
        active = []
        
        if criteria.countries:
            active.append(f"countries: {', '.join(criteria.countries)}")
        if criteria.exclude_countries:
            active.append(f"exclude_countries: {', '.join(criteria.exclude_countries)}")
        if criteria.protocols:
            active.append(f"protocols: {', '.join(p.value for p in criteria.protocols)}")
        if criteria.anonymity_levels:
            active.append(f"anonymity: {', '.join(a.value for a in criteria.anonymity_levels)}")
        if criteria.max_response_time:
            active.append(f"max_response_time: {criteria.max_response_time}ms")
        if criteria.min_success_rate:
            active.append(f"min_success_rate: {criteria.min_success_rate}")
        if criteria.statuses:
            active.append(f"statuses: {', '.join(s.value for s in criteria.statuses)}")
        
        return active
    
    def _get_protocol_distribution(self, proxies: List[ProxyInfo]) -> Dict[str, int]:
        """Get protocol distribution"""
        return dict(Counter(proxy.protocol.value for proxy in proxies))
    
    def _get_country_distribution(self, proxies: List[ProxyInfo]) -> Dict[str, int]:
        """Get country distribution"""
        countries = []
        for proxy in proxies:
            if proxy.geo_location and proxy.geo_location.country_code:
                countries.append(proxy.geo_location.country_code)
            else:
                countries.append('Unknown')
        return dict(Counter(countries))
    
    def _get_anonymity_distribution(self, proxies: List[ProxyInfo]) -> Dict[str, int]:
        """Get anonymity level distribution"""
        return dict(Counter(proxy.anonymity_level.value for proxy in proxies))
    
    def _get_average_response_time(self, proxies: List[ProxyInfo]) -> Optional[float]:
        """Get average response time"""
        times = [p.metrics.response_time for p in proxies 
                if p.metrics.response_time is not None]
        return statistics.mean(times) if times else None
    
    def _get_average_success_rate(self, proxies: List[ProxyInfo]) -> Optional[float]:
        """Get average success rate"""
        rates = [p.metrics.success_rate for p in proxies 
                if p.metrics.success_rate is not None]
        return statistics.mean(rates) if rates else None
    
    def _generate_cache_key(self, proxies: List[ProxyInfo], 
                           criteria: FilterCriteria) -> str:
        """Generate cache key for filter operation"""
        proxy_hash = hash(tuple(p.proxy_id for p in proxies))
        criteria_hash = hash(str(criteria.to_dict()))
        return f"filter_{proxy_hash}_{criteria_hash}"
    
    def _get_cached_result(self, cache_key: str) -> Optional[List[ProxyInfo]]:
        """Get cached filter result"""
        if cache_key in self._filter_cache:
            cached_time, result = self._filter_cache[cache_key]
            if time.time() - cached_time < self._cache_ttl:
                return result
            else:
                del self._filter_cache[cache_key]
        return None
    
    def _cache_result(self, cache_key: str, result: List[ProxyInfo]):
        """Cache filter result"""
        self._filter_cache[cache_key] = (time.time(), result)
        
        # Cleanup old cache entries periodically
        current_time = time.time()
        if current_time - self._last_cache_cleanup > 300:  # Every 5 minutes
            self._cleanup_cache()
            self._last_cache_cleanup = current_time
    
    def _cleanup_cache(self):
        """Remove expired cache entries"""
        current_time = time.time()
        expired_keys = []
        
        for key, (cached_time, _) in self._filter_cache.items():
            if current_time - cached_time > self._cache_ttl:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self._filter_cache[key]
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get filter performance statistics"""
        stats = dict(self.filter_stats)
        
        if self.filter_times['filter_duration']:
            stats['avg_filter_duration'] = statistics.mean(self.filter_times['filter_duration'])
            stats['max_filter_duration'] = max(self.filter_times['filter_duration'])
            stats['min_filter_duration'] = min(self.filter_times['filter_duration'])
        
        stats['cache_size'] = len(self._filter_cache)
        
        return stats


# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def create_filter_criteria(**kwargs) -> FilterCriteria:
    """Create FilterCriteria with keyword arguments"""
    return FilterCriteria(**kwargs)


def create_proxy_filter(config: Optional[ConfigManager] = None) -> ProxyFilter:
    """Create ProxyFilter instance"""
    return ProxyFilter(config)


def quick_filter(proxies: List[ProxyInfo], **criteria_kwargs) -> List[ProxyInfo]:
    """Quick utility function for filtering proxies"""
    criteria = create_filter_criteria(**criteria_kwargs)
    proxy_filter = create_proxy_filter()
    return proxy_filter.filter_proxies(proxies, criteria)


# ===============================================================================
# MODULE EXPORTS
# ===============================================================================

__all__ = [
    'FilterCriteria',
    'FilterPresets', 
    'ProxyFilter',
    'create_filter_criteria',
    'create_proxy_filter',
    'quick_filter'
]

logger.info("Proxy filters module loaded successfully")
