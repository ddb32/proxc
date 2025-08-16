"""
HTTP Header Analysis for Proxy Detection
========================================

Advanced HTTP header analysis for identifying proxy servers, extracting
proxy chains, and detecting proxy behavior patterns.
"""

import logging
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Union, Any

# Import our core types
from . import ProxyType, ConfidenceLevel
from ..proxy_core.models import ProxyInfo

logger = logging.getLogger(__name__)


class HeaderCategory(Enum):
    """Categories of HTTP headers for analysis"""
    PROXY_IDENTIFICATION = "proxy_identification"
    FORWARDING = "forwarding"
    CACHING = "caching"
    SECURITY = "security"
    CUSTOM = "custom"


@dataclass
class HeaderSignature:
    """HTTP header signature for proxy detection"""
    name: str
    category: HeaderCategory
    patterns: List[str] = field(default_factory=list)  # Regex patterns
    proxy_types: Set[ProxyType] = field(default_factory=set)
    confidence_weight: float = 1.0
    description: str = ""
    
    def matches(self, header_name: str, header_value: str) -> bool:
        """Check if header matches this signature"""
        if self.name.lower() != header_name.lower():
            return False
        
        if not self.patterns:
            return True  # Match any value
        
        return any(re.search(pattern, header_value, re.IGNORECASE) for pattern in self.patterns)


@dataclass
class HeaderAnalysisResult:
    """Result of HTTP header analysis"""
    proxy_indicators: List[str] = field(default_factory=list)
    chain_detected: bool = False
    chain_length: int = 0
    proxy_software: Optional[ProxyType] = None
    confidence: ConfidenceLevel = ConfidenceLevel.VERY_LOW
    
    # Detailed analysis
    forwarding_headers: Dict[str, str] = field(default_factory=dict)
    caching_headers: Dict[str, str] = field(default_factory=dict)
    security_headers: Dict[str, str] = field(default_factory=dict)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    # Chain information
    via_chain: List[str] = field(default_factory=list)
    x_forwarded_chain: List[str] = field(default_factory=list)
    
    # Metadata
    analysis_timestamp: datetime = field(default_factory=datetime.utcnow)
    total_headers: int = 0
    proxy_score: float = 0.0


class HeaderPatternLibrary:
    """Library of header patterns for proxy detection"""
    
    def __init__(self):
        self.signatures: List[HeaderSignature] = []
        self._initialize_patterns()
    
    def _initialize_patterns(self):
        """Initialize built-in header patterns"""
        
        # Via header patterns
        self.signatures.append(HeaderSignature(
            name="Via",
            category=HeaderCategory.PROXY_IDENTIFICATION,
            patterns=[
                r".*",  # Any Via header indicates proxy
            ],
            proxy_types={ProxyType.SQUID, ProxyType.APACHE_HTTPD, ProxyType.NGINX},
            confidence_weight=0.9,
            description="Standard proxy Via header"
        ))
        
        # X-Forwarded headers
        forwarded_headers = [
            "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
            "X-Real-IP", "X-Original-For", "X-Client-IP"
        ]
        
        for header in forwarded_headers:
            self.signatures.append(HeaderSignature(
                name=header,
                category=HeaderCategory.FORWARDING,
                patterns=[r".*"],
                proxy_types={ProxyType.NGINX, ProxyType.APACHE_HTTPD, ProxyType.HAPROXY},
                confidence_weight=0.7,
                description=f"Forwarding header: {header}"
            ))
        
        # Proxy-specific headers
        proxy_specific = {
            "Proxy-Connection": {
                "patterns": [r"keep-alive", r"close"],
                "types": {ProxyType.SQUID, ProxyType.TINYPROXY},
                "weight": 0.8
            },
            "Proxy-Authorization": {
                "patterns": [r".*"],
                "types": {ProxyType.SQUID, ProxyType.APACHE_HTTPD},
                "weight": 0.9
            },
            "X-Cache": {
                "patterns": [r"HIT", r"MISS", r".*squid.*", r".*cloudflare.*"],
                "types": {ProxyType.SQUID, ProxyType.CLOUDFLARE},
                "weight": 0.8
            },
            "X-Cache-Lookup": {
                "patterns": [r".*"],
                "types": {ProxyType.SQUID},
                "weight": 0.7
            }
        }
        
        for header_name, config in proxy_specific.items():
            self.signatures.append(HeaderSignature(
                name=header_name,
                category=HeaderCategory.PROXY_IDENTIFICATION,
                patterns=config["patterns"],
                proxy_types=config["types"],
                confidence_weight=config["weight"],
                description=f"Proxy-specific header: {header_name}"
            ))
        
        # Squid-specific headers
        squid_headers = [
            "X-Squid-Error", "X-Cache-Lookup", "X-Cache-Status",
            "X-Squid-Request-Attempts", "X-Cache-Info"
        ]
        
        for header in squid_headers:
            self.signatures.append(HeaderSignature(
                name=header,
                category=HeaderCategory.CUSTOM,
                patterns=[r".*"],
                proxy_types={ProxyType.SQUID},
                confidence_weight=0.95,
                description=f"Squid-specific header: {header}"
            ))
        
        # Cloudflare headers
        cloudflare_headers = [
            "CF-Ray", "CF-Cache-Status", "CF-Request-ID",
            "CF-Visitor", "CF-Connecting-IP", "CF-IPCountry"
        ]
        
        for header in cloudflare_headers:
            self.signatures.append(HeaderSignature(
                name=header,
                category=HeaderCategory.CUSTOM,
                patterns=[r".*"],
                proxy_types={ProxyType.CLOUDFLARE},
                confidence_weight=0.95,
                description=f"Cloudflare header: {header}"
            ))
        
        # CloudFront headers
        cloudfront_headers = [
            "X-Amz-Cf-Id", "X-Cache", "X-Amz-Cf-Pop"
        ]
        
        for header in cloudfront_headers:
            self.signatures.append(HeaderSignature(
                name=header,
                category=HeaderCategory.CUSTOM,
                patterns=[r".*cloudfront.*", r".*"] if header == "X-Cache" else [r".*"],
                proxy_types={ProxyType.CLOUDFRONT},
                confidence_weight=0.9,
                description=f"CloudFront header: {header}"
            ))
        
        # HAProxy headers
        haproxy_headers = [
            "X-Haproxy-Server-State", "X-Load-Balancer"
        ]
        
        for header in haproxy_headers:
            self.signatures.append(HeaderSignature(
                name=header,
                category=HeaderCategory.CUSTOM,
                patterns=[r".*"],
                proxy_types={ProxyType.HAPROXY},
                confidence_weight=0.85,
                description=f"HAProxy header: {header}"
            ))
        
        logger.info(f"Initialized {len(self.signatures)} header signatures")
    
    def get_signatures_for_header(self, header_name: str) -> List[HeaderSignature]:
        """Get all signatures that match a header name"""
        return [sig for sig in self.signatures if sig.name.lower() == header_name.lower()]
    
    def get_signatures_by_category(self, category: HeaderCategory) -> List[HeaderSignature]:
        """Get signatures by category"""
        return [sig for sig in self.signatures if sig.category == category]


class HeaderAnalyzer:
    """Advanced HTTP header analyzer for proxy detection"""
    
    def __init__(self):
        self.pattern_library = HeaderPatternLibrary()
        self.analysis_cache: Dict[str, HeaderAnalysisResult] = {}
    
    def analyze_headers(self, headers: Dict[str, str]) -> HeaderAnalysisResult:
        """Analyze HTTP headers for proxy indicators"""
        
        # Create cache key
        header_hash = hash(frozenset(headers.items()))
        cache_key = str(header_hash)
        
        if cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]
        
        # Perform analysis
        result = self._perform_header_analysis(headers)
        
        # Cache result
        self.analysis_cache[cache_key] = result
        
        return result
    
    def _perform_header_analysis(self, headers: Dict[str, str]) -> HeaderAnalysisResult:
        """Perform actual header analysis"""
        
        result = HeaderAnalysisResult()
        result.total_headers = len(headers)
        
        proxy_indicators = []
        proxy_type_scores = defaultdict(float)
        category_headers = {
            HeaderCategory.FORWARDING: {},
            HeaderCategory.CACHING: {},
            HeaderCategory.SECURITY: {},
            HeaderCategory.CUSTOM: {}
        }
        
        # Analyze each header
        for header_name, header_value in headers.items():
            signatures = self.pattern_library.get_signatures_for_header(header_name)
            
            for signature in signatures:
                if signature.matches(header_name, header_value):
                    proxy_indicators.append(f"{header_name}: {header_value}")
                    
                    # Update proxy type scores
                    for proxy_type in signature.proxy_types:
                        proxy_type_scores[proxy_type] += signature.confidence_weight
                    
                    # Categorize headers
                    if signature.category != HeaderCategory.PROXY_IDENTIFICATION:
                        category_headers[signature.category][header_name] = header_value
        
        # Analyze Via header chain
        result.via_chain = self._parse_via_chain(headers.get("Via", ""))
        result.chain_detected = len(result.via_chain) > 1
        result.chain_length = len(result.via_chain)
        
        # Analyze X-Forwarded-For chain
        result.x_forwarded_chain = self._parse_forwarded_chain(
            headers.get("X-Forwarded-For", "")
        )
        
        # Update chain detection
        if len(result.x_forwarded_chain) > 1:
            result.chain_detected = True
            result.chain_length = max(result.chain_length, len(result.x_forwarded_chain))
        
        # Determine best matching proxy type
        if proxy_type_scores:
            best_type = max(proxy_type_scores.keys(), key=lambda t: proxy_type_scores[t])
            best_score = proxy_type_scores[best_type]
            result.proxy_software = best_type
            result.proxy_score = min(best_score / 3.0, 1.0)  # Normalize score
        
        # Calculate confidence
        result.confidence = self._calculate_confidence(proxy_indicators, proxy_type_scores)
        
        # Set categorized headers
        result.proxy_indicators = proxy_indicators
        result.forwarding_headers = category_headers[HeaderCategory.FORWARDING]
        result.caching_headers = category_headers[HeaderCategory.CACHING]
        result.security_headers = category_headers[HeaderCategory.SECURITY]
        result.custom_headers = category_headers[HeaderCategory.CUSTOM]
        
        return result
    
    def _parse_via_chain(self, via_header: str) -> List[str]:
        """Parse Via header to extract proxy chain"""
        if not via_header:
            return []
        
        # Via header format: "1.1 proxy1.example.com, 1.0 proxy2.example.com"
        chain = []
        
        # Split by comma and clean up
        parts = [part.strip() for part in via_header.split(',')]
        
        for part in parts:
            # Extract hostname/IP from each part
            # Common formats:
            # - "1.1 hostname"
            # - "1.1 hostname (comment)"
            # - "hostname"
            
            # Remove protocol version
            cleaned = re.sub(r'^\d+\.\d+\s+', '', part)
            
            # Remove comments in parentheses
            cleaned = re.sub(r'\s*\([^)]*\)', '', cleaned)
            
            if cleaned:
                chain.append(cleaned.strip())
        
        return chain
    
    def _parse_forwarded_chain(self, forwarded_header: str) -> List[str]:
        """Parse X-Forwarded-For header to extract IP chain"""
        if not forwarded_header:
            return []
        
        # X-Forwarded-For format: "client, proxy1, proxy2"
        chain = [ip.strip() for ip in forwarded_header.split(',')]
        return [ip for ip in chain if ip]  # Remove empty strings
    
    def _calculate_confidence(
        self, 
        proxy_indicators: List[str], 
        proxy_type_scores: Dict[ProxyType, float]
    ) -> ConfidenceLevel:
        """Calculate confidence level based on analysis results"""
        
        indicator_count = len(proxy_indicators)
        max_score = max(proxy_type_scores.values()) if proxy_type_scores else 0
        
        # Strong indicators: Via header, multiple proxy headers, high scores
        strong_indicators = [
            "Via:" in str(proxy_indicators),
            indicator_count >= 3,
            max_score >= 2.0
        ]
        
        if sum(strong_indicators) >= 2:
            return ConfidenceLevel.HIGH
        elif sum(strong_indicators) >= 1 or indicator_count >= 2:
            return ConfidenceLevel.MEDIUM
        elif indicator_count >= 1:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW
    
    def detect_proxy_chain(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Detect and analyze proxy chains from headers"""
        
        analysis = self.analyze_headers(headers)
        
        chain_info = {
            'has_chain': analysis.chain_detected,
            'chain_length': analysis.chain_length,
            'via_chain': analysis.via_chain,
            'forwarded_chain': analysis.x_forwarded_chain,
            'confidence': analysis.confidence.value
        }
        
        # Additional chain analysis
        if analysis.chain_detected:
            # Analyze chain composition
            chain_ips = analysis.x_forwarded_chain
            if chain_ips:
                chain_info['first_proxy'] = chain_ips[0] if len(chain_ips) > 0 else None
                chain_info['last_proxy'] = chain_ips[-1] if len(chain_ips) > 1 else None
                chain_info['total_hops'] = len(chain_ips)
            
            # Check for suspicious patterns
            suspicious_patterns = []
            
            # Check for localhost in chain
            if any('127.0.0.1' in ip or 'localhost' in ip for ip in chain_ips):
                suspicious_patterns.append('localhost_in_chain')
            
            # Check for private IPs
            private_patterns = [
                r'^10\.',
                r'^192\.168\.',
                r'^172\.(1[6-9]|2[0-9]|3[01])\.'
            ]
            
            for ip in chain_ips:
                if any(re.match(pattern, ip) for pattern in private_patterns):
                    suspicious_patterns.append('private_ip_in_chain')
                    break
            
            chain_info['suspicious_patterns'] = suspicious_patterns
        
        return chain_info
    
    def analyze_proxy_behavior(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze proxy behavior based on headers"""
        
        analysis = self.analyze_headers(headers)
        
        behavior = {
            'caching_enabled': bool(analysis.caching_headers),
            'compression_support': 'Content-Encoding' in headers,
            'keep_alive': False,
            'security_headers': bool(analysis.security_headers),
            'custom_modifications': bool(analysis.custom_headers)
        }
        
        # Check connection behavior
        connection_header = headers.get('Connection', '').lower()
        proxy_connection = headers.get('Proxy-Connection', '').lower()
        
        if 'keep-alive' in connection_header or 'keep-alive' in proxy_connection:
            behavior['keep_alive'] = True
        
        # Analyze caching behavior
        if analysis.caching_headers:
            cache_control = headers.get('Cache-Control', '')
            x_cache = headers.get('X-Cache', '')
            
            behavior['cache_status'] = 'unknown'
            if 'HIT' in x_cache.upper():
                behavior['cache_status'] = 'hit'
            elif 'MISS' in x_cache.upper():
                behavior['cache_status'] = 'miss'
            
            behavior['cache_control'] = cache_control
        
        # Check for proxy modifications
        modifications = []
        
        # Common proxy-added headers
        proxy_added = [
            'Via', 'X-Forwarded-For', 'X-Real-IP', 'X-Cache',
            'X-Forwarded-Proto', 'X-Forwarded-Host'
        ]
        
        for header in proxy_added:
            if header in headers:
                modifications.append(header)
        
        behavior['added_headers'] = modifications
        behavior['modification_count'] = len(modifications)
        
        return behavior
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of header analysis results"""
        if not self.analysis_cache:
            return {}
        
        confidence_counts = Counter()
        proxy_type_counts = Counter()
        chain_detected_count = 0
        
        for result in self.analysis_cache.values():
            confidence_counts[result.confidence.value] += 1
            
            if result.proxy_software:
                proxy_type_counts[result.proxy_software.value] += 1
            
            if result.chain_detected:
                chain_detected_count += 1
        
        return {
            'total_analyses': len(self.analysis_cache),
            'confidence_distribution': dict(confidence_counts),
            'proxy_types_detected': dict(proxy_type_counts),
            'chain_detection_rate': chain_detected_count / len(self.analysis_cache),
            'average_indicators_per_analysis': sum(
                len(r.proxy_indicators) for r in self.analysis_cache.values()
            ) / len(self.analysis_cache)
        }