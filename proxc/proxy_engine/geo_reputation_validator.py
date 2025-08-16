"""
Geolocation Accuracy Validation and IP Reputation System - Phase 3.3.3

Advanced geolocation verification and IP reputation checking for proxy validation.
Includes multiple geolocation providers, reputation scoring, and accuracy verification.

Features:
- Multi-provider geolocation verification
- IP reputation scoring from multiple threat intelligence sources
- Geolocation accuracy scoring and consistency checking
- ASN and ISP validation
- Country/region compliance checking
- Threat intelligence integration
- Real-time blacklist checking
- Historical reputation tracking
"""

import asyncio
import json
import logging
import math
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum, IntEnum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Set
import threading
import hashlib

# Network and HTTP imports
try:
    import aiohttp
    import asyncio
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

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

from ..proxy_core.models import ProxyInfo, GeoLocation, ThreatLevel
from ..proxy_cli.cli_imports import log_structured, print_info, print_warning

logger = logging.getLogger(__name__)


class ReputationSource(Enum):
    """IP reputation data sources"""
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    THREATCROWD = "threatcrowd"
    HYBRID_ANALYSIS = "hybrid_analysis"
    URLVOID = "urlvoid"
    SPAMHAUS = "spamhaus"
    BARRACUDA = "barracuda"
    INTERNAL_BLACKLIST = "internal_blacklist"


class GeolocationProvider(Enum):
    """Geolocation service providers"""
    MAXMIND = "maxmind"
    IPAPI = "ipapi"
    IPGEOLOCATION = "ipgeolocation"
    IPINFO = "ipinfo"
    GEOJS = "geojs"
    FREEIPAPI = "freeipapi"


class ThreatCategory(Enum):
    """Threat categories for reputation scoring"""
    MALWARE = "malware"
    PHISHING = "phishing"
    SPAM = "spam"
    BOTNET = "botnet"
    SCANNING = "scanning"
    ABUSE = "abuse"
    PROXY_ABUSE = "proxy_abuse"
    TOR_EXIT = "tor_exit"
    VPN_SERVICE = "vpn_service"
    CLEAN = "clean"


@dataclass
class GeolocationResult:
    """Geolocation provider result"""
    provider: GeolocationProvider
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    confidence: float = 0.0
    response_time_ms: float = 0.0
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            **asdict(self),
            'provider': self.provider.value
        }
    
    def is_valid(self) -> bool:
        """Check if result has minimum required data"""
        return (self.country is not None and 
                self.country_code is not None and
                self.error is None)


@dataclass
class ReputationResult:
    """IP reputation check result"""
    source: ReputationSource
    reputation_score: float = 0.0  # 0-100, higher is better
    threat_categories: List[ThreatCategory] = field(default_factory=list)
    is_malicious: bool = False
    confidence: float = 0.0
    last_seen: Optional[datetime] = None
    detection_count: int = 0
    total_scans: int = 0
    response_time_ms: float = 0.0
    error: Optional[str] = None
    raw_data: Dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            **asdict(self),
            'source': self.source.value,
            'threat_categories': [cat.value for cat in self.threat_categories],
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }


@dataclass
class GeolocationAccuracy:
    """Geolocation accuracy assessment"""
    consensus_country: Optional[str] = None
    consensus_country_code: Optional[str] = None
    country_agreement_percentage: float = 0.0
    coordinate_variance: float = 0.0
    provider_count: int = 0
    accuracy_score: float = 0.0  # 0-100
    confidence: float = 0.0
    inconsistencies: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class IPReputationSummary:
    """Aggregated IP reputation summary"""
    overall_score: float = 0.0  # 0-100, higher is better
    risk_level: ThreatLevel = ThreatLevel.UNKNOWN
    malicious_detections: int = 0
    total_sources: int = 0
    threat_categories: Set[ThreatCategory] = field(default_factory=set)
    consensus_confidence: float = 0.0
    source_results: List[ReputationResult] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            **asdict(self),
            'risk_level': self.risk_level.value,
            'threat_categories': [cat.value for cat in self.threat_categories],
            'source_results': [r.to_dict() for r in self.source_results]
        }


class GeolocationValidator:
    """
    Multi-provider geolocation validation with accuracy scoring
    """
    
    def __init__(self, maxmind_db_path: Path = None, api_keys: Dict[str, str] = None):
        self.maxmind_db_path = maxmind_db_path
        self.api_keys = api_keys or {}
        
        # Provider configurations
        self.provider_configs = {
            GeolocationProvider.IPAPI: {
                'url': 'http://ip-api.com/json/{ip}',
                'rate_limit': 45,  # requests per minute
                'requires_key': False
            },
            GeolocationProvider.IPGEOLOCATION: {
                'url': 'https://api.ipgeolocation.io/ipgeo?apiKey={key}&ip={ip}',
                'rate_limit': 1000,
                'requires_key': True
            },
            GeolocationProvider.IPINFO: {
                'url': 'https://ipinfo.io/{ip}/json?token={key}',
                'rate_limit': 50000,
                'requires_key': True
            },
            GeolocationProvider.GEOJS: {
                'url': 'https://get.geojs.io/v1/ip/geo/{ip}.json',
                'rate_limit': 100,
                'requires_key': False
            },
            GeolocationProvider.FREEIPAPI: {
                'url': 'https://freeipapi.com/api/json/{ip}',
                'rate_limit': 60,
                'requires_key': False
            }
        }
        
        # Rate limiting
        self.rate_limiters = {
            provider: deque(maxlen=config['rate_limit'])
            for provider, config in self.provider_configs.items()
        }
        
        # MaxMind database
        self.maxmind_db = None
        if HAS_GEOIP2 and maxmind_db_path and maxmind_db_path.exists():
            try:
                self.maxmind_db = geoip2.database.Reader(str(maxmind_db_path))
            except Exception as e:
                log_structured('WARNING', f"Failed to load MaxMind database: {e}")
    
    async def validate_geolocation(self, ip_address: str) -> Tuple[List[GeolocationResult], GeolocationAccuracy]:
        """Validate geolocation using multiple providers"""
        
        results = []
        
        # MaxMind local database (if available)
        if self.maxmind_db:
            maxmind_result = await self._query_maxmind(ip_address)
            if maxmind_result:
                results.append(maxmind_result)
        
        # Online providers
        if HAS_AIOHTTP:
            online_results = await self._query_online_providers(ip_address)
            results.extend(online_results)
        
        # Calculate accuracy assessment
        accuracy = self._assess_geolocation_accuracy(results)
        
        return results, accuracy
    
    async def _query_maxmind(self, ip_address: str) -> Optional[GeolocationResult]:
        """Query MaxMind local database"""
        try:
            start_time = time.time()
            response = self.maxmind_db.city(ip_address)
            response_time = (time.time() - start_time) * 1000
            
            return GeolocationResult(
                provider=GeolocationProvider.MAXMIND,
                country=response.country.name,
                country_code=response.country.iso_code,
                region=response.subdivisions.most_specific.name,
                city=response.city.name,
                latitude=float(response.location.latitude) if response.location.latitude else None,
                longitude=float(response.location.longitude) if response.location.longitude else None,
                timezone=response.location.time_zone,
                isp=None,  # Not available in city database
                asn=None,  # Requires ASN database
                confidence=95.0,  # MaxMind is generally reliable
                response_time_ms=response_time
            )
            
        except Exception as e:
            return GeolocationResult(
                provider=GeolocationProvider.MAXMIND,
                error=str(e),
                response_time_ms=0.0
            )
    
    async def _query_online_providers(self, ip_address: str) -> List[GeolocationResult]:
        """Query multiple online geolocation providers"""
        
        tasks = []
        
        for provider, config in self.provider_configs.items():
            # Check API key requirement
            if config['requires_key'] and provider.value not in self.api_keys:
                continue
            
            # Check rate limiting
            if not self._check_rate_limit(provider):
                continue
            
            task = self._query_provider(provider, ip_address, config)
            tasks.append(task)
        
        if not tasks:
            return []
        
        # Execute queries concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and failed results
        valid_results = []
        for result in results:
            if isinstance(result, GeolocationResult) and result.is_valid():
                valid_results.append(result)
        
        return valid_results
    
    async def _query_provider(self, provider: GeolocationProvider, 
                            ip_address: str, config: dict) -> GeolocationResult:
        """Query specific geolocation provider"""
        
        start_time = time.time()
        
        try:
            # Build URL
            url = config['url']
            if config['requires_key']:
                url = url.format(ip=ip_address, key=self.api_keys[provider.value])
            else:
                url = url.format(ip=ip_address)
            
            # Make request
            timeout = aiohttp.ClientTimeout(total=10.0)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_provider_response(provider, data, time.time() - start_time)
                    else:
                        return GeolocationResult(
                            provider=provider,
                            error=f"HTTP {response.status}",
                            response_time_ms=(time.time() - start_time) * 1000
                        )
        
        except Exception as e:
            return GeolocationResult(
                provider=provider,
                error=str(e),
                response_time_ms=(time.time() - start_time) * 1000
            )
    
    def _parse_provider_response(self, provider: GeolocationProvider, 
                               data: dict, elapsed_time: float) -> GeolocationResult:
        """Parse provider-specific response format"""
        
        response_time_ms = elapsed_time * 1000
        
        try:
            if provider == GeolocationProvider.IPAPI:
                return GeolocationResult(
                    provider=provider,
                    country=data.get('country'),
                    country_code=data.get('countryCode'),
                    region=data.get('regionName'),
                    city=data.get('city'),
                    latitude=data.get('lat'),
                    longitude=data.get('lon'),
                    timezone=data.get('timezone'),
                    isp=data.get('isp'),
                    asn=data.get('as'),
                    confidence=80.0,
                    response_time_ms=response_time_ms
                )
            
            elif provider == GeolocationProvider.IPGEOLOCATION:
                return GeolocationResult(
                    provider=provider,
                    country=data.get('country_name'),
                    country_code=data.get('country_code2'),
                    region=data.get('state_prov'),
                    city=data.get('city'),
                    latitude=float(data.get('latitude', 0)) or None,
                    longitude=float(data.get('longitude', 0)) or None,
                    timezone=data.get('time_zone', {}).get('name'),
                    isp=data.get('isp'),
                    asn=data.get('asn'),
                    confidence=85.0,
                    response_time_ms=response_time_ms
                )
            
            elif provider == GeolocationProvider.IPINFO:
                loc = data.get('loc', '').split(',')
                latitude = float(loc[0]) if len(loc) > 0 and loc[0] else None
                longitude = float(loc[1]) if len(loc) > 1 and loc[1] else None
                
                return GeolocationResult(
                    provider=provider,
                    country=data.get('country'),
                    country_code=data.get('country'),
                    region=data.get('region'),
                    city=data.get('city'),
                    latitude=latitude,
                    longitude=longitude,
                    timezone=data.get('timezone'),
                    isp=data.get('org'),
                    asn=None,
                    confidence=90.0,
                    response_time_ms=response_time_ms
                )
            
            elif provider == GeolocationProvider.GEOJS:
                return GeolocationResult(
                    provider=provider,
                    country=data.get('country'),
                    country_code=data.get('country_code'),
                    region=data.get('region'),
                    city=data.get('city'),
                    latitude=float(data.get('latitude', 0)) or None,
                    longitude=float(data.get('longitude', 0)) or None,
                    timezone=data.get('timezone'),
                    isp=data.get('organization'),
                    asn=None,
                    confidence=75.0,
                    response_time_ms=response_time_ms
                )
            
            elif provider == GeolocationProvider.FREEIPAPI:
                return GeolocationResult(
                    provider=provider,
                    country=data.get('countryName'),
                    country_code=data.get('countryCode'),
                    region=data.get('regionName'),
                    city=data.get('cityName'),
                    latitude=data.get('latitude'),
                    longitude=data.get('longitude'),
                    timezone=data.get('timeZone'),
                    isp=None,
                    asn=None,
                    confidence=70.0,
                    response_time_ms=response_time_ms
                )
            
            else:
                return GeolocationResult(
                    provider=provider,
                    error="Unknown provider",
                    response_time_ms=response_time_ms
                )
        
        except Exception as e:
            return GeolocationResult(
                provider=provider,
                error=f"Parse error: {e}",
                response_time_ms=response_time_ms
            )
    
    def _check_rate_limit(self, provider: GeolocationProvider) -> bool:
        """Check if provider rate limit allows request"""
        config = self.provider_configs[provider]
        rate_limiter = self.rate_limiters[provider]
        
        current_time = time.time()
        
        # Remove old timestamps (older than 1 minute)
        while rate_limiter and current_time - rate_limiter[0] > 60:
            rate_limiter.popleft()
        
        # Check if under rate limit
        if len(rate_limiter) < config['rate_limit']:
            rate_limiter.append(current_time)
            return True
        
        return False
    
    def _assess_geolocation_accuracy(self, results: List[GeolocationResult]) -> GeolocationAccuracy:
        """Assess accuracy based on provider consensus"""
        
        valid_results = [r for r in results if r.is_valid()]
        
        if not valid_results:
            return GeolocationAccuracy()
        
        # Country consensus
        countries = [r.country for r in valid_results if r.country]
        country_codes = [r.country_code for r in valid_results if r.country_code]
        
        country_counts = {}
        for country in countries:
            country_counts[country] = country_counts.get(country, 0) + 1
        
        consensus_country = max(country_counts.keys(), key=country_counts.get) if country_counts else None
        country_agreement = (country_counts.get(consensus_country, 0) / len(countries)) * 100 if countries else 0
        
        # Country code consensus
        code_counts = {}
        for code in country_codes:
            code_counts[code] = code_counts.get(code, 0) + 1
        
        consensus_code = max(code_counts.keys(), key=code_counts.get) if code_counts else None
        
        # Coordinate variance
        coordinates = [(r.latitude, r.longitude) for r in valid_results 
                      if r.latitude is not None and r.longitude is not None]
        
        coordinate_variance = 0.0
        if len(coordinates) > 1:
            latitudes = [coord[0] for coord in coordinates]
            longitudes = [coord[1] for coord in coordinates]
            
            lat_variance = statistics.variance(latitudes) if len(latitudes) > 1 else 0
            lon_variance = statistics.variance(longitudes) if len(longitudes) > 1 else 0
            coordinate_variance = math.sqrt(lat_variance + lon_variance)
        
        # Calculate accuracy score
        accuracy_score = 0.0
        
        # Country agreement weight (50%)
        accuracy_score += country_agreement * 0.5
        
        # Coordinate consistency weight (30%)
        if coordinate_variance < 1.0:  # Less than ~111km variance
            coord_score = max(0, 100 - (coordinate_variance * 20))
            accuracy_score += coord_score * 0.3
        
        # Provider count weight (20%)
        provider_score = min(100, (len(valid_results) / 5) * 100)
        accuracy_score += provider_score * 0.2
        
        # Identify inconsistencies
        inconsistencies = []
        if country_agreement < 100:
            inconsistencies.append(f"Country disagreement: {country_agreement:.1f}% consensus")
        
        if coordinate_variance > 2.0:
            inconsistencies.append(f"High coordinate variance: {coordinate_variance:.2f}°")
        
        if len(valid_results) < 2:
            inconsistencies.append("Insufficient provider coverage")
        
        # Calculate confidence based on sample size and agreement
        confidence = min(100, (len(valid_results) * 20) + country_agreement * 0.8)
        
        return GeolocationAccuracy(
            consensus_country=consensus_country,
            consensus_country_code=consensus_code,
            country_agreement_percentage=country_agreement,
            coordinate_variance=coordinate_variance,
            provider_count=len(valid_results),
            accuracy_score=accuracy_score,
            confidence=confidence,
            inconsistencies=inconsistencies
        )


class IPReputationChecker:
    """
    Multi-source IP reputation checking and threat intelligence
    """
    
    def __init__(self, api_keys: Dict[str, str] = None):
        self.api_keys = api_keys or {}
        
        # Source configurations
        self.source_configs = {
            ReputationSource.VIRUSTOTAL: {
                'url': 'https://www.virustotal.com/vtapi/v2/ip-address/report',
                'requires_key': True,
                'rate_limit': 4,  # requests per minute
                'weight': 0.3
            },
            ReputationSource.ABUSEIPDB: {
                'url': 'https://api.abuseipdb.com/api/v2/check',
                'requires_key': True,
                'rate_limit': 1000,
                'weight': 0.25
            },
            ReputationSource.THREATCROWD: {
                'url': 'https://www.threatcrowd.org/searchApi/v2/ip/report/',
                'requires_key': False,
                'rate_limit': 1,
                'weight': 0.15
            }
        }
        
        # Rate limiting
        self.rate_limiters = {
            source: deque(maxlen=config['rate_limit'])
            for source, config in self.source_configs.items()
        }
        
        # Internal blacklists
        self.internal_blacklists = {
            'tor_exits': set(),
            'known_malicious': set(),
            'proxy_abuse': set()
        }
        
        # Reputation cache
        self.reputation_cache: Dict[str, Dict] = {}
        self.cache_expiry = timedelta(hours=6)
    
    async def check_ip_reputation(self, ip_address: str) -> IPReputationSummary:
        """Check IP reputation across multiple sources"""
        
        # Check cache first
        cached_result = self._get_cached_reputation(ip_address)
        if cached_result:
            return cached_result
        
        results = []
        
        # Internal blacklist checks
        internal_result = self._check_internal_blacklists(ip_address)
        if internal_result:
            results.append(internal_result)
        
        # External source checks
        if HAS_AIOHTTP:
            external_results = await self._query_reputation_sources(ip_address)
            results.extend(external_results)
        
        # Aggregate results
        summary = self._aggregate_reputation_results(results)
        
        # Cache result
        self._cache_reputation(ip_address, summary)
        
        return summary
    
    def _check_internal_blacklists(self, ip_address: str) -> Optional[ReputationResult]:
        """Check against internal blacklists"""
        
        threat_categories = []
        is_malicious = False
        
        if ip_address in self.internal_blacklists['tor_exits']:
            threat_categories.append(ThreatCategory.TOR_EXIT)
            is_malicious = True
        
        if ip_address in self.internal_blacklists['known_malicious']:
            threat_categories.append(ThreatCategory.MALWARE)
            is_malicious = True
        
        if ip_address in self.internal_blacklists['proxy_abuse']:
            threat_categories.append(ThreatCategory.PROXY_ABUSE)
            is_malicious = True
        
        if not threat_categories:
            return ReputationResult(
                source=ReputationSource.INTERNAL_BLACKLIST,
                reputation_score=100.0,
                is_malicious=False,
                confidence=90.0
            )
        
        reputation_score = 0.0 if is_malicious else 100.0
        
        return ReputationResult(
            source=ReputationSource.INTERNAL_BLACKLIST,
            reputation_score=reputation_score,
            threat_categories=threat_categories,
            is_malicious=is_malicious,
            confidence=95.0
        )
    
    async def _query_reputation_sources(self, ip_address: str) -> List[ReputationResult]:
        """Query external reputation sources"""
        
        tasks = []
        
        for source, config in self.source_configs.items():
            # Check API key requirement
            if config['requires_key'] and source.value not in self.api_keys:
                continue
            
            # Check rate limiting
            if not self._check_reputation_rate_limit(source):
                continue
            
            task = self._query_reputation_source(source, ip_address, config)
            tasks.append(task)
        
        if not tasks:
            return []
        
        # Execute queries concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and failed results
        valid_results = []
        for result in results:
            if isinstance(result, ReputationResult) and result.error is None:
                valid_results.append(result)
        
        return valid_results
    
    async def _query_reputation_source(self, source: ReputationSource,
                                     ip_address: str, config: dict) -> ReputationResult:
        """Query specific reputation source"""
        
        start_time = time.time()
        
        try:
            if source == ReputationSource.VIRUSTOTAL:
                return await self._query_virustotal(ip_address, start_time)
            elif source == ReputationSource.ABUSEIPDB:
                return await self._query_abuseipdb(ip_address, start_time)
            elif source == ReputationSource.THREATCROWD:
                return await self._query_threatcrowd(ip_address, start_time)
            else:
                return ReputationResult(
                    source=source,
                    error="Unsupported source",
                    response_time_ms=(time.time() - start_time) * 1000
                )
        
        except Exception as e:
            return ReputationResult(
                source=source,
                error=str(e),
                response_time_ms=(time.time() - start_time) * 1000
            )
    
    async def _query_virustotal(self, ip_address: str, start_time: float) -> ReputationResult:
        """Query VirusTotal API"""
        
        url = self.source_configs[ReputationSource.VIRUSTOTAL]['url']
        params = {
            'apikey': self.api_keys.get('virustotal'),
            'ip': ip_address
        }
        
        timeout = aiohttp.ClientTimeout(total=15.0)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_virustotal_response(data, time.time() - start_time)
                else:
                    return ReputationResult(
                        source=ReputationSource.VIRUSTOTAL,
                        error=f"HTTP {response.status}",
                        response_time_ms=(time.time() - start_time) * 1000
                    )
    
    def _parse_virustotal_response(self, data: dict, elapsed_time: float) -> ReputationResult:
        """Parse VirusTotal response"""
        
        response_time_ms = elapsed_time * 1000
        
        if data.get('response_code') != 1:
            return ReputationResult(
                source=ReputationSource.VIRUSTOTAL,
                reputation_score=50.0,  # Neutral score for unknown IPs
                confidence=20.0,
                response_time_ms=response_time_ms
            )
        
        # Parse detection results
        detected_urls = data.get('detected_urls', [])
        detected_samples = data.get('detected_communicating_samples', [])
        
        detection_count = len(detected_urls) + len(detected_samples)
        total_scans = detection_count + len(data.get('undetected_urls', []))
        
        # Calculate reputation score
        if detection_count == 0:
            reputation_score = 100.0
            is_malicious = False
        else:
            # Higher detection count = lower reputation
            reputation_score = max(0, 100 - (detection_count * 10))
            is_malicious = detection_count > 2
        
        # Determine threat categories
        threat_categories = []
        if is_malicious:
            threat_categories.append(ThreatCategory.MALWARE)
        
        return ReputationResult(
            source=ReputationSource.VIRUSTOTAL,
            reputation_score=reputation_score,
            threat_categories=threat_categories,
            is_malicious=is_malicious,
            confidence=90.0,
            detection_count=detection_count,
            total_scans=total_scans,
            response_time_ms=response_time_ms,
            raw_data=data
        )
    
    async def _query_abuseipdb(self, ip_address: str, start_time: float) -> ReputationResult:
        """Query AbuseIPDB API"""
        
        url = self.source_configs[ReputationSource.ABUSEIPDB]['url']
        headers = {
            'Key': self.api_keys.get('abuseipdb'),
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,
            'verbose': ''
        }
        
        timeout = aiohttp.ClientTimeout(total=15.0)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_abuseipdb_response(data, time.time() - start_time)
                else:
                    return ReputationResult(
                        source=ReputationSource.ABUSEIPDB,
                        error=f"HTTP {response.status}",
                        response_time_ms=(time.time() - start_time) * 1000
                    )
    
    def _parse_abuseipdb_response(self, data: dict, elapsed_time: float) -> ReputationResult:
        """Parse AbuseIPDB response"""
        
        response_time_ms = elapsed_time * 1000
        
        if 'data' not in data:
            return ReputationResult(
                source=ReputationSource.ABUSEIPDB,
                error="Invalid response format",
                response_time_ms=response_time_ms
            )
        
        ip_data = data['data']
        abuse_confidence = ip_data.get('abuseConfidencePercentage', 0)
        total_reports = ip_data.get('totalReports', 0)
        
        # Calculate reputation score (inverse of abuse confidence)
        reputation_score = 100 - abuse_confidence
        is_malicious = abuse_confidence > 25
        
        # Determine threat categories based on usage types
        threat_categories = []
        usage_type = ip_data.get('usageType', '')
        if 'malware' in usage_type.lower():
            threat_categories.append(ThreatCategory.MALWARE)
        if 'spam' in usage_type.lower():
            threat_categories.append(ThreatCategory.SPAM)
        
        return ReputationResult(
            source=ReputationSource.ABUSEIPDB,
            reputation_score=reputation_score,
            threat_categories=threat_categories,
            is_malicious=is_malicious,
            confidence=85.0,
            detection_count=total_reports,
            response_time_ms=response_time_ms,
            raw_data=ip_data
        )
    
    async def _query_threatcrowd(self, ip_address: str, start_time: float) -> ReputationResult:
        """Query ThreatCrowd API"""
        
        url = f"{self.source_configs[ReputationSource.THREATCROWD]['url']}?ip={ip_address}"
        
        timeout = aiohttp.ClientTimeout(total=15.0)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_threatcrowd_response(data, time.time() - start_time)
                else:
                    return ReputationResult(
                        source=ReputationSource.THREATCROWD,
                        error=f"HTTP {response.status}",
                        response_time_ms=(time.time() - start_time) * 1000
                    )
    
    def _parse_threatcrowd_response(self, data: dict, elapsed_time: float) -> ReputationResult:
        """Parse ThreatCrowd response"""
        
        response_time_ms = elapsed_time * 1000
        
        if data.get('response_code') != '1':
            return ReputationResult(
                source=ReputationSource.THREATCROWD,
                reputation_score=50.0,  # Neutral for unknown
                confidence=30.0,
                response_time_ms=response_time_ms
            )
        
        # Check for malicious indicators
        hashes = data.get('hashes', [])
        domains = data.get('resolutions', [])
        
        detection_count = len(hashes)
        is_malicious = detection_count > 0
        
        reputation_score = 100.0 if not is_malicious else max(0, 100 - (detection_count * 15))
        
        threat_categories = []
        if is_malicious:
            threat_categories.append(ThreatCategory.MALWARE)
        
        return ReputationResult(
            source=ReputationSource.THREATCROWD,
            reputation_score=reputation_score,
            threat_categories=threat_categories,
            is_malicious=is_malicious,
            confidence=75.0,
            detection_count=detection_count,
            response_time_ms=response_time_ms,
            raw_data=data
        )
    
    def _check_reputation_rate_limit(self, source: ReputationSource) -> bool:
        """Check reputation source rate limit"""
        config = self.source_configs[source]
        rate_limiter = self.rate_limiters[source]
        
        current_time = time.time()
        
        # Remove old timestamps
        while rate_limiter and current_time - rate_limiter[0] > 60:
            rate_limiter.popleft()
        
        # Check if under rate limit
        if len(rate_limiter) < config['rate_limit']:
            rate_limiter.append(current_time)
            return True
        
        return False
    
    def _aggregate_reputation_results(self, results: List[ReputationResult]) -> IPReputationSummary:
        """Aggregate reputation results from multiple sources"""
        
        if not results:
            return IPReputationSummary()
        
        valid_results = [r for r in results if r.error is None]
        
        if not valid_results:
            return IPReputationSummary(source_results=results)
        
        # Calculate weighted average reputation score
        total_weight = 0.0
        weighted_sum = 0.0
        
        for result in valid_results:
            weight = self.source_configs.get(result.source, {}).get('weight', 0.1)
            weighted_sum += result.reputation_score * weight
            total_weight += weight
        
        overall_score = weighted_sum / total_weight if total_weight > 0 else 0.0
        
        # Count malicious detections
        malicious_detections = sum(1 for r in valid_results if r.is_malicious)
        
        # Aggregate threat categories
        all_threats = set()
        for result in valid_results:
            all_threats.update(result.threat_categories)
        
        # Determine risk level
        if malicious_detections == 0:
            risk_level = ThreatLevel.LOW
        elif malicious_detections == 1:
            risk_level = ThreatLevel.MEDIUM
        elif malicious_detections >= 2:
            risk_level = ThreatLevel.HIGH
        else:
            risk_level = ThreatLevel.UNKNOWN
        
        # Calculate consensus confidence
        consensus_confidence = min(100, (len(valid_results) * 25) + (overall_score * 0.5))
        
        return IPReputationSummary(
            overall_score=overall_score,
            risk_level=risk_level,
            malicious_detections=malicious_detections,
            total_sources=len(valid_results),
            threat_categories=all_threats,
            consensus_confidence=consensus_confidence,
            source_results=results
        )
    
    def _get_cached_reputation(self, ip_address: str) -> Optional[IPReputationSummary]:
        """Get cached reputation if not expired"""
        if ip_address in self.reputation_cache:
            cache_entry = self.reputation_cache[ip_address]
            if datetime.now() - cache_entry['timestamp'] < self.cache_expiry:
                return cache_entry['summary']
        return None
    
    def _cache_reputation(self, ip_address: str, summary: IPReputationSummary):
        """Cache reputation result"""
        self.reputation_cache[ip_address] = {
            'timestamp': datetime.now(),
            'summary': summary
        }
        
        # Clean old cache entries
        cutoff = datetime.now() - self.cache_expiry
        self.reputation_cache = {
            k: v for k, v in self.reputation_cache.items()
            if v['timestamp'] >= cutoff
        }


# Export key classes
__all__ = [
    'ReputationSource', 'GeolocationProvider', 'ThreatCategory',
    'GeolocationResult', 'ReputationResult', 'GeolocationAccuracy', 'IPReputationSummary',
    'GeolocationValidator', 'IPReputationChecker'
]