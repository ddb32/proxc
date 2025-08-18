"""Proxy Core Models - Complete Data Models with All Required Classes"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, List, Any, Tuple
from ipaddress import IPv4Address, IPv6Address, AddressValueError


# ===============================================================================
# CORE ENUMERATIONS - ALL REQUIRED ENUMS
# ===============================================================================

class ProxyProtocol(Enum):
    """Supported proxy protocols"""
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


class AnonymityLevel(Enum):
    """Proxy anonymity levels"""
    TRANSPARENT = "transparent"  # Real IP visible
    ANONYMOUS = "anonymous"      # IP hidden but proxy detected
    ELITE = "elite"             # IP hidden and proxy undetected


class ThreatLevel(Enum):
    """Threat assessment levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProxyStatus(Enum):
    """Proxy operational status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    TESTING = "testing"
    FAILED = "failed"


class ValidationStatus(Enum):
    """Validation result status"""
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    ERROR = "error"


class SecurityLevel(Enum):
    """Security classification levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIDENTIAL = "confidential"


class OperationalGrade(Enum):
    """Operational quality grades"""
    BASIC = "basic"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    ELITE = "elite"


class RiskCategory(Enum):
    """Risk category for intelligent proxy management"""
    ACTIVE = "active"        # Recently validated, good performance
    AT_RISK = "at_risk"      # Declining performance, needs monitoring
    INACTIVE = "inactive"    # Poor performance, low priority
    UNKNOWN = "unknown"      # New proxy, not yet categorized


class TierLevel(Enum):
    """Scanning tier levels for differential validation"""
    TIER_1 = 1  # High priority: 24-hour intervals, lightweight validation
    TIER_2 = 2  # Medium priority: 6-12 hour intervals, comprehensive validation  
    TIER_3 = 3  # Low priority: Weekly intervals, basic connectivity checks
    TIER_4 = 4  # Unknown/New: On-demand validation with priority-guided scheduling


# ===============================================================================
# EXCEPTION CLASSES
# ===============================================================================

class ProxyError(Exception):
    """Base exception for all proxy-related errors"""
    
    def __init__(self, message: str, proxy_id: Optional[str] = None):
        super().__init__(message)
        self.proxy_id = proxy_id
        self.timestamp = datetime.utcnow()


class ValidationError(ProxyError):
    """Exception raised during proxy validation"""
    pass


class SecurityError(ProxyError):
    """Exception raised for security-related issues"""
    pass


class NetworkError(ProxyError):
    """Exception raised for network-related issues"""
    pass


class ConfigurationError(ProxyError):
    """Exception raised for configuration issues"""
    pass


class SourceUnavailableError(ProxyError):
    """Exception raised when a proxy source is unavailable"""
    
    def __init__(self, message: str, source_name: str, status_code: Optional[int] = None, suggestions: List[str] = None):
        super().__init__(message)
        self.source_name = source_name
        self.status_code = status_code
        self.suggestions = suggestions or []


class NoProxiesFoundError(ProxyError):
    """Exception raised when no proxies are found from any sources"""
    
    def __init__(self, message: str, attempted_sources: List[str] = None, suggestions: List[str] = None):
        super().__init__(message)
        self.attempted_sources = attempted_sources or []
        self.suggestions = suggestions or []


class RateLimitError(ProxyError):
    """Exception raised when rate limits are exceeded"""
    
    def __init__(self, message: str, source_name: str, retry_after: Optional[int] = None):
        super().__init__(message)
        self.source_name = source_name
        self.retry_after = retry_after  # seconds until retry allowed


# ===============================================================================
# CORE DATA MODELS
# ===============================================================================

@dataclass
class GeoLocation:
    """Geographic location information"""
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    timezone: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'country': self.country,
            'country_code': self.country_code,
            'city': self.city,
            'region': self.region,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'asn': self.asn,
            'isp': self.isp,
            'organization': self.organization,
            'timezone': self.timezone
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'GeoLocation':
        """Create from dictionary"""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ProxyMetrics:
    """Performance and quality metrics"""
    response_time: Optional[float] = None  # milliseconds
    uptime_percentage: Optional[float] = None
    success_rate: Optional[float] = None
    last_checked: Optional[datetime] = None
    check_count: int = 0
    failure_count: int = 0
    total_bytes_transferred: int = 0
    average_speed: Optional[float] = None  # bytes per second
    peak_speed: Optional[float] = None
    downtime_incidents: int = 0
    
    def update_check(self, success: bool, response_time: Optional[float] = None, bytes_transferred: int = 0):
        """Update metrics with new check result"""
        self.check_count += 1
        if not success:
            self.failure_count += 1
        else:
            if bytes_transferred > 0:
                self.total_bytes_transferred += bytes_transferred
        
        if response_time is not None:
            if self.response_time is None:
                self.response_time = response_time
            else:
                # Calculate rolling average
                self.response_time = (self.response_time + response_time) / 2
        
        self.last_checked = datetime.utcnow()
        self.success_rate = (self.check_count - self.failure_count) / self.check_count * 100
        
        if self.check_count > 0:
            self.uptime_percentage = (self.check_count - self.downtime_incidents) / self.check_count * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'response_time': self.response_time,
            'uptime_percentage': self.uptime_percentage,
            'success_rate': self.success_rate,
            'last_checked': self.last_checked.isoformat() if self.last_checked else None,
            'check_count': self.check_count,
            'failure_count': self.failure_count,
            'total_bytes_transferred': self.total_bytes_transferred,
            'average_speed': self.average_speed,
            'peak_speed': self.peak_speed,
            'downtime_incidents': self.downtime_incidents
        }


@dataclass
class SecurityAssessment:
    """Security assessment and threat analysis"""
    threat_level: ThreatLevel = ThreatLevel.LOW
    security_level: SecurityLevel = SecurityLevel.LOW
    is_honeypot: bool = False
    is_blacklisted: bool = False
    reputation_score: float = 50.0  # 0-100 scale
    risk_factors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    last_threat_check: Optional[datetime] = None
    blacklist_sources: List[str] = field(default_factory=list)
    vulnerability_score: float = 0.0
    
    # CAPTCHA and automation blocking detection
    captcha_detected: bool = False
    automation_blocking: bool = False
    blocking_type: Optional[str] = None            # captcha, automation_blocking, bot_detection
    blocking_service: Optional[str] = None         # cloudflare, recaptcha, imperva, etc.
    blocking_confidence: float = 0.0              # 0.0-1.0 confidence score
    blocking_likelihood: float = 0.0              # 0.0-1.0 likelihood of being blocked
    blocking_details: List[str] = field(default_factory=list)  # Detailed blocking indicators
    
    # Proxy chain detection
    is_proxy_chain: bool = False                   # Whether proxy chain is detected
    chain_depth: int = 0                          # Number of proxies in chain
    chain_confidence: float = 0.0                # Confidence in chain detection (0.0-1.0)
    chain_risk_level: str = "low"                # Chain risk level: low, medium, high, critical
    chain_risk_score: float = 0.0                # Numerical chain risk score (0.0-1.0)
    detected_proxies: List[str] = field(default_factory=list)  # List of detected proxy identifiers
    proxy_software: List[str] = field(default_factory=list)    # Detected proxy software
    chain_anomalies: List[str] = field(default_factory=list)   # Chain-related anomalies
    mixed_protocols: bool = False                 # Whether chain uses mixed protocols
    
    def add_risk_factor(self, factor: str):
        """Add a risk factor"""
        if factor not in self.risk_factors:
            self.risk_factors.append(factor)
    
    def add_recommendation(self, recommendation: str):
        """Add a security recommendation"""
        if recommendation not in self.recommendations:
            self.recommendations.append(recommendation)
    
    def update_blocking_info(self, blocking_analysis: Dict[str, Any]):
        """Update blocking information from analysis results"""
        self.captcha_detected = blocking_analysis.get('captcha_detected', False)
        self.automation_blocking = blocking_analysis.get('automation_blocking', False)
        self.blocking_type = blocking_analysis.get('blocking_type')
        self.blocking_service = blocking_analysis.get('blocking_service')
        self.blocking_confidence = blocking_analysis.get('blocking_confidence', 0.0)
        self.blocking_details = blocking_analysis.get('details', [])
        
        # Calculate blocking likelihood (can be used for proxy scoring)
        if self.captcha_detected or self.automation_blocking:
            self.blocking_likelihood = max(0.5, self.blocking_confidence)
            
            # Add to risk factors
            if self.captcha_detected:
                self.add_risk_factor(f"CAPTCHA detected ({self.blocking_service or 'unknown service'})")
            if self.automation_blocking:
                self.add_risk_factor(f"Automation blocking detected ({self.blocking_type})")
        else:
            self.blocking_likelihood = 0.0
    
    def update_chain_info(self, chain_analysis: Dict[str, Any]):
        """Update chain detection information from analysis results"""
        self.is_proxy_chain = chain_analysis.get('is_chain_detected', False)
        self.chain_depth = chain_analysis.get('chain_depth', 0)
        self.chain_confidence = chain_analysis.get('chain_confidence', 0.0)
        self.chain_risk_level = chain_analysis.get('risk_level', 'low')
        self.chain_risk_score = chain_analysis.get('risk_score', 0.0)
        self.detected_proxies = chain_analysis.get('detected_proxies', [])
        self.proxy_software = chain_analysis.get('proxy_software', [])
        self.mixed_protocols = chain_analysis.get('mixed_protocols', False)
        
        # Add chain-related anomalies to the list
        inconsistencies = chain_analysis.get('inconsistencies', [])
        self.chain_anomalies = inconsistencies.copy()
        
        # Add to risk factors if chain is detected
        if self.is_proxy_chain:
            self.add_risk_factor(f"Proxy chain detected (depth: {self.chain_depth})")
            
            if self.chain_risk_level in ['high', 'critical']:
                self.add_risk_factor(f"High-risk proxy chain ({self.chain_risk_level})")
            
            if self.mixed_protocols:
                self.add_risk_factor("Mixed protocol proxy chain")
            
            if len(self.chain_anomalies) > 0:
                self.add_risk_factor(f"Chain anomalies detected ({len(self.chain_anomalies)})")
        
        # Add recommendations
        if self.is_proxy_chain and self.chain_depth > 3:
            self.add_recommendation("Avoid using long proxy chains for better security")
        
        if self.mixed_protocols:
            self.add_recommendation("Be cautious with mixed-protocol proxy chains")
        
        if len(self.chain_anomalies) > 2:
            self.add_recommendation("Investigate proxy chain anomalies before use")
    
    def calculate_overall_score(self) -> float:
        """Calculate overall security score"""
        base_score = self.reputation_score
        
        # Penalties
        if self.is_honeypot:
            base_score -= 50
        if self.is_blacklisted:
            base_score -= 30
        if self.threat_level == ThreatLevel.CRITICAL:
            base_score -= 40
        elif self.threat_level == ThreatLevel.HIGH:
            base_score -= 25
        elif self.threat_level == ThreatLevel.MEDIUM:
            base_score -= 10
        
        # Risk factors penalty
        base_score -= len(self.risk_factors) * 5
        
        return max(0.0, min(100.0, base_score))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'threat_level': self.threat_level.value,
            'security_level': self.security_level.value,
            'is_honeypot': self.is_honeypot,
            'is_blacklisted': self.is_blacklisted,
            'reputation_score': self.reputation_score,
            'risk_factors': self.risk_factors,
            'recommendations': self.recommendations,
            'last_threat_check': self.last_threat_check.isoformat() if self.last_threat_check else None,
            'blacklist_sources': self.blacklist_sources,
            'vulnerability_score': self.vulnerability_score,
            'overall_score': self.calculate_overall_score()
        }


@dataclass
class ProxyInfo:
    """Complete proxy information with all required fields"""
    # Core connection details
    host: str
    port: int
    protocol: ProxyProtocol = ProxyProtocol.HTTP
    
    # Authentication (optional)
    username: Optional[str] = None
    password: Optional[str] = None
    
    # Status and classification
    status: ProxyStatus = ProxyStatus.INACTIVE
    validation_status: ValidationStatus = ValidationStatus.PENDING
    
    # Security and anonymity levels
    anonymity_level: AnonymityLevel = AnonymityLevel.TRANSPARENT
    threat_level: ThreatLevel = ThreatLevel.LOW
    security_level: SecurityLevel = SecurityLevel.LOW
    operational_grade: OperationalGrade = OperationalGrade.BASIC
    
    # Identification and tracking
    proxy_id: str = field(default_factory=lambda: f"PXY-{uuid.uuid4().hex[:8].upper()}")
    source: Optional[str] = None
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    last_updated: datetime = field(default_factory=datetime.utcnow)
    
    # Protocol detection metadata
    protocol_confidence: float = 0.0
    protocol_detection_method: Optional[str] = None
    protocol_detection_time: Optional[datetime] = None
    protocol_fallback_attempted: bool = False
    
    # Enhancement Phase 1: Intelligent Proxy Management Fields
    # Geographical information
    region: Optional[str] = None           # Geographical region (continent level)
    country: Optional[str] = None          # Country code (ISO 3166-1 alpha-2)
    city: Optional[str] = None             # City name for granular filtering
    
    # Risk categorization and tier management
    risk_category: RiskCategory = RiskCategory.UNKNOWN       # Risk assessment category
    scan_priority: int = 5                                   # Priority level (1-10, 1=highest)
    tier_level: TierLevel = TierLevel.TIER_4                # Scanning tier (1-4)
    
    # Intelligent scheduling
    next_scheduled_check: Optional[datetime] = None          # Next scheduled validation
    check_frequency: int = 24                               # Check frequency in hours
    
    # Related data objects
    geo_location: Optional[GeoLocation] = None
    metrics: ProxyMetrics = field(default_factory=ProxyMetrics)
    security_assessment: Optional[SecurityAssessment] = None
    
    # Additional metadata
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate proxy data after initialization"""
        self._validate_host()
        self._validate_port()
        self.last_updated = datetime.utcnow()
        
        # Initialize security assessment if not provided
        if self.security_assessment is None:
            self.security_assessment = SecurityAssessment()
    
    def _validate_host(self):
        """Validate host address"""
        if not self.host or not self.host.strip():
            raise ValidationError("Host cannot be empty", self.proxy_id)
        
        # Try to parse as IP address
        try:
            IPv4Address(self.host)
        except AddressValueError:
            try:
                IPv6Address(self.host)
            except AddressValueError:
                # Not an IP, assume it's a hostname - basic validation
                if len(self.host) > 253:
                    raise ValidationError("Hostname too long", self.proxy_id)
                if '..' in self.host:
                    raise ValidationError("Invalid hostname format", self.proxy_id)
    
    def _validate_port(self):
        """Validate port number"""
        if not isinstance(self.port, int):
            raise ValidationError("Port must be an integer", self.proxy_id)
        if not (1 <= self.port <= 65535):
            raise ValidationError("Port must be between 1 and 65535", self.proxy_id)
    
    @property
    def address(self) -> str:
        """Get full proxy address"""
        return f"{self.host}:{self.port}"
    
    @property
    def url(self) -> str:
        """Get proxy URL format"""
        if self.username and self.password:
            return f"{self.protocol.value}://{self.username}:{self.password}@{self.host}:{self.port}"
        return f"{self.protocol.value}://{self.host}:{self.port}"
    
    @property
    def is_authenticated(self) -> bool:
        """Check if proxy requires authentication"""
        return bool(self.username and self.password)
    
    @property
    def is_healthy(self) -> bool:
        """Check if proxy is considered healthy"""
        return (
            self.status == ProxyStatus.ACTIVE and
            self.validation_status == ValidationStatus.VALID and
            self.threat_level in [ThreatLevel.LOW, ThreatLevel.MEDIUM] and
            (self.metrics.success_rate or 0) > 70
        )
    
    @property
    def protocol_confidence_percentage(self) -> int:
        """Get protocol confidence as percentage (0-100)"""
        return int(self.protocol_confidence * 100)
    
    @property
    def has_high_protocol_confidence(self) -> bool:
        """Check if protocol detection has high confidence (>80%)"""
        return self.protocol_confidence >= 0.8
    
    @property
    def quality_score(self) -> float:
        """Calculate overall quality score (0-100)"""
        score = 50.0  # Base score
        
        # Status bonuses
        if self.status == ProxyStatus.ACTIVE:
            score += 20
        if self.validation_status == ValidationStatus.VALID:
            score += 15
        
        # Anonymity bonuses
        if self.anonymity_level == AnonymityLevel.ELITE:
            score += 15
        elif self.anonymity_level == AnonymityLevel.ANONYMOUS:
            score += 10
        
        # Performance bonuses
        if self.metrics.success_rate and self.metrics.success_rate > 80:
            score += 10
        if self.metrics.response_time and self.metrics.response_time < 1000:
            score += 10
        
        # Security penalties
        if self.security_assessment:
            security_score = self.security_assessment.calculate_overall_score()
            score = (score + security_score) / 2
        
        return max(0.0, min(100.0, score))
    
    # Enhancement Phase 1: New methods for intelligent proxy management
    
    @property
    def is_high_priority(self) -> bool:
        """Check if proxy is high priority (tier 1-2 or priority 1-3)"""
        return self.tier_level.value <= 2 or self.scan_priority <= 3
    
    @property
    def is_due_for_check(self) -> bool:
        """Check if proxy is due for validation check"""
        if not self.next_scheduled_check:
            return True
        return datetime.utcnow() >= self.next_scheduled_check
    
    @property
    def geographical_identifier(self) -> str:
        """Get geographical identifier string"""
        parts = []
        if self.city:
            parts.append(self.city)
        if self.country:
            parts.append(self.country)
        if self.region:
            parts.append(self.region)
        return ", ".join(parts) if parts else "Unknown"
    
    def update_risk_category(self, new_category: RiskCategory, reason: str = ""):
        """Update risk category with tracking"""
        old_category = self.risk_category
        self.risk_category = new_category
        self.last_updated = datetime.utcnow()
        
        # Adjust tier level based on risk category
        if new_category == RiskCategory.ACTIVE:
            self.tier_level = TierLevel.TIER_1
            self.check_frequency = 24
        elif new_category == RiskCategory.AT_RISK:
            self.tier_level = TierLevel.TIER_2
            self.check_frequency = 12
        elif new_category == RiskCategory.INACTIVE:
            self.tier_level = TierLevel.TIER_3
            self.check_frequency = 168  # Weekly
        else:  # UNKNOWN
            self.tier_level = TierLevel.TIER_4
            self.check_frequency = 24
        
        # Add note about category change
        if reason:
            note = f"Risk category changed from {old_category.value} to {new_category.value}: {reason}"
            self.notes = f"{self.notes}\n{datetime.utcnow().isoformat()}: {note}".strip()
    
    def update_geographical_info(self, region: Optional[str] = None, 
                                country: Optional[str] = None, 
                                city: Optional[str] = None):
        """Update geographical information"""
        if region is not None:
            self.region = region
        if country is not None:
            self.country = country
        if city is not None:
            self.city = city
        self.last_updated = datetime.utcnow()
    
    def schedule_next_check(self, hours_from_now: Optional[int] = None):
        """Schedule next validation check"""
        if hours_from_now is None:
            hours_from_now = self.check_frequency
        
        from datetime import timedelta
        self.next_scheduled_check = datetime.utcnow() + timedelta(hours=hours_from_now)
        self.last_updated = datetime.utcnow()
    
    def calculate_tier_score(self) -> float:
        """Calculate score for tier assignment (0-100)"""
        score = 50.0  # Base score
        
        # Recent performance weight
        if self.metrics.success_rate:
            score += (self.metrics.success_rate - 50) * 0.5
        
        # Response time weight
        if self.metrics.response_time:
            if self.metrics.response_time < 5000:  # < 5 seconds
                score += 15
            elif self.metrics.response_time < 10000:  # < 10 seconds
                score += 10
            elif self.metrics.response_time > 30000:  # > 30 seconds
                score -= 15
        
        # Status weight
        if self.status == ProxyStatus.ACTIVE:
            score += 20
        elif self.status == ProxyStatus.FAILED:
            score -= 30
        
        # Security assessment weight
        if self.security_assessment:
            security_score = self.security_assessment.calculate_overall_score()
            score = (score * 0.7) + (security_score * 0.3)
        
        return max(0.0, min(100.0, score))
    
    def update_tier_based_on_performance(self):
        """Automatically update tier based on current performance"""
        tier_score = self.calculate_tier_score()
        
        if tier_score >= 80:
            new_tier = TierLevel.TIER_1
            new_category = RiskCategory.ACTIVE
        elif tier_score >= 60:
            new_tier = TierLevel.TIER_2
            new_category = RiskCategory.AT_RISK if self.risk_category == RiskCategory.INACTIVE else self.risk_category
        elif tier_score >= 30:
            new_tier = TierLevel.TIER_3
            new_category = RiskCategory.AT_RISK
        else:
            new_tier = TierLevel.TIER_4
            new_category = RiskCategory.INACTIVE
        
        # Update if changed
        if new_tier != self.tier_level:
            old_tier = self.tier_level
            self.tier_level = new_tier
            note = f"Tier updated from {old_tier.value} to {new_tier.value} (score: {tier_score:.1f})"
            self.notes = f"{self.notes}\n{datetime.utcnow().isoformat()}: {note}".strip()
        
        if new_category != self.risk_category:
            self.update_risk_category(new_category, f"Performance-based update (score: {tier_score:.1f})")
    
    def add_tag(self, tag: str):
        """Add a tag if not already present"""
        if tag not in self.tags:
            self.tags.append(tag)
    
    def remove_tag(self, tag: str):
        """Remove a tag if present"""
        if tag in self.tags:
            self.tags.remove(tag)
    
    def update_status(self, new_status: ProxyStatus, notes: str = ""):
        """Update proxy status with optional notes"""
        self.status = new_status
        self.last_updated = datetime.utcnow()
        if notes:
            self.notes = f"{self.notes}\n{datetime.utcnow().isoformat()}: {notes}".strip()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "proxy_id": self.proxy_id,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol.value,
            "username": self.username,
            "password": self.password,
            "status": self.status.value,
            "anonymity_level": self.anonymity_level.value,
            "threat_level": self.threat_level.value,
            "security_level": self.security_level.value,
            "validation_status": self.validation_status.value,
            "operational_grade": self.operational_grade.value,
            "address": self.address,
            "url": self.url,
            "is_authenticated": self.is_authenticated,
            "is_healthy": self.is_healthy,
            "quality_score": self.quality_score,
            "source": self.source,
            "discovered_at": self.discovered_at.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "geo_location": self.geo_location.to_dict() if self.geo_location else None,
            "metrics": self.metrics.to_dict(),
            "security_assessment": self.security_assessment.to_dict() if self.security_assessment else None,
            "tags": self.tags,
            "notes": self.notes,
            "metadata": self.metadata,
            # Enhancement Phase 1 fields
            "region": self.region,
            "country": self.country,
            "city": self.city,
            "risk_category": self.risk_category.value,
            "scan_priority": self.scan_priority,
            "tier_level": self.tier_level.value,
            "next_scheduled_check": self.next_scheduled_check.isoformat() if self.next_scheduled_check else None,
            "check_frequency": self.check_frequency,
            "geographical_identifier": self.geographical_identifier,
            "is_high_priority": self.is_high_priority,
            "is_due_for_check": self.is_due_for_check,
            "tier_score": self.calculate_tier_score()
        }
    
    @classmethod
    def from_address(cls, address: str, protocol: ProxyProtocol = ProxyProtocol.HTTP, **kwargs) -> 'ProxyInfo':
        """Create ProxyInfo from address string (host:port)"""
        if ':' not in address:
            raise ValidationError(f"Invalid address format: {address}")
        
        host, port_str = address.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            raise ValidationError(f"Invalid port in address: {address}")
        
        return cls(host=host, port=port, protocol=protocol, **kwargs)
    
    @classmethod
    def from_url(cls, url: str, **kwargs) -> 'ProxyInfo':
        """Create ProxyInfo from proxy URL"""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        if not parsed.hostname or not parsed.port:
            raise ValidationError(f"Invalid proxy URL: {url}")
        
        # Determine protocol
        protocol_map = {
            'http': ProxyProtocol.HTTP,
            'https': ProxyProtocol.HTTPS,
            'socks4': ProxyProtocol.SOCKS4,
            'socks5': ProxyProtocol.SOCKS5
        }
        
        protocol = protocol_map.get(parsed.scheme.lower(), ProxyProtocol.HTTP)
        
        return cls(
            host=parsed.hostname,
            port=parsed.port,
            protocol=protocol,
            username=parsed.username,
            password=parsed.password,
            **kwargs
        )


# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def validate_proxy_list(proxies: List[ProxyInfo]) -> Dict[str, List[ProxyInfo]]:
    """Validate a list of proxies and categorize them"""
    valid = []
    invalid = []
    duplicates = []
    
    seen_addresses = set()
    
    for proxy in proxies:
        try:
            # Check for duplicates
            if proxy.address in seen_addresses:
                duplicates.append(proxy)
                continue
            seen_addresses.add(proxy.address)
            
            # Validate proxy
            proxy._validate_host()
            proxy._validate_port()
            valid.append(proxy)
            
        except ValidationError:
            invalid.append(proxy)
    
    return {
        "valid": valid,
        "invalid": invalid,
        "duplicates": duplicates
    }


def create_proxy_from_dict(data: Dict[str, Any]) -> ProxyInfo:
    """Create ProxyInfo from dictionary"""
    # Handle enums
    if 'protocol' in data and isinstance(data['protocol'], str):
        data['protocol'] = ProxyProtocol(data['protocol'])
    if 'status' in data and isinstance(data['status'], str):
        data['status'] = ProxyStatus(data['status'])
    if 'anonymity_level' in data and isinstance(data['anonymity_level'], str):
        data['anonymity_level'] = AnonymityLevel(data['anonymity_level'])
    if 'threat_level' in data and isinstance(data['threat_level'], str):
        data['threat_level'] = ThreatLevel(data['threat_level'])
    if 'security_level' in data and isinstance(data['security_level'], str):
        data['security_level'] = SecurityLevel(data['security_level'])
    if 'validation_status' in data and isinstance(data['validation_status'], str):
        data['validation_status'] = ValidationStatus(data['validation_status'])
    if 'operational_grade' in data and isinstance(data['operational_grade'], str):
        data['operational_grade'] = OperationalGrade(data['operational_grade'])
    
    # Handle Enhancement Phase 1 enums
    if 'risk_category' in data and isinstance(data['risk_category'], str):
        data['risk_category'] = RiskCategory(data['risk_category'])
    if 'tier_level' in data and isinstance(data['tier_level'], (str, int)):
        if isinstance(data['tier_level'], str):
            # Handle string values like "TIER_1" or "1"
            if data['tier_level'].startswith('TIER_'):
                tier_num = int(data['tier_level'].split('_')[1])
            else:
                tier_num = int(data['tier_level'])
        else:
            tier_num = data['tier_level']
        data['tier_level'] = TierLevel(tier_num)
    
    # Handle datetime fields
    for date_field in ['discovered_at', 'last_updated', 'next_scheduled_check']:
        if date_field in data and isinstance(data[date_field], str):
            data[date_field] = datetime.fromisoformat(data[date_field])
    
    # Handle nested objects
    if 'geo_location' in data and isinstance(data['geo_location'], dict):
        data['geo_location'] = GeoLocation.from_dict(data['geo_location'])
    
    if 'metrics' in data and isinstance(data['metrics'], dict):
        metrics_data = data['metrics']
        if 'last_checked' in metrics_data and isinstance(metrics_data['last_checked'], str):
            metrics_data['last_checked'] = datetime.fromisoformat(metrics_data['last_checked'])
        data['metrics'] = ProxyMetrics(**metrics_data)
    
    if 'security_assessment' in data and isinstance(data['security_assessment'], dict):
        security_data = data['security_assessment']
        if 'threat_level' in security_data and isinstance(security_data['threat_level'], str):
            security_data['threat_level'] = ThreatLevel(security_data['threat_level'])
        if 'security_level' in security_data and isinstance(security_data['security_level'], str):
            security_data['security_level'] = SecurityLevel(security_data['security_level'])
        if 'last_threat_check' in security_data and isinstance(security_data['last_threat_check'], str):
            security_data['last_threat_check'] = datetime.fromisoformat(security_data['last_threat_check'])
        data['security_assessment'] = SecurityAssessment(**security_data)
    
    return ProxyInfo(**{k: v for k, v in data.items() if k in ProxyInfo.__dataclass_fields__})


@dataclass
class ProxyHealthMetrics:
    """Comprehensive health metrics for proxy monitoring"""
    # Response time metrics
    avg_response_time: float = 0.0
    min_response_time: float = 0.0
    max_response_time: float = 0.0
    response_time_std: float = 0.0
    
    # Availability metrics
    uptime_hours: float = 0.0
    downtime_hours: float = 0.0
    availability_percentage: float = 0.0
    
    # Performance metrics
    success_count: int = 0
    failure_count: int = 0
    timeout_count: int = 0
    connection_error_count: int = 0
    
    # Quality metrics
    data_integrity_score: float = 100.0
    consistency_score: float = 100.0
    reliability_score: float = 100.0
    
    # Trend analysis
    performance_trend: str = "stable"  # improving, degrading, stable
    risk_trend: str = "stable"
    quality_trend: str = "stable"
    
    # Historical data
    last_health_check: Optional[datetime] = None
    health_check_interval: int = 3600  # seconds
    metrics_retention_days: int = 30
    
    def calculate_overall_health_score(self) -> float:
        """Calculate overall health score (0-100)"""
        if self.success_count + self.failure_count == 0:
            return 50.0  # Neutral score for new proxies
        
        # Base success rate score
        success_rate = self.success_count / (self.success_count + self.failure_count)
        base_score = success_rate * 100
        
        # Adjust for response time (penalize slow proxies)
        if self.avg_response_time > 5000:  # > 5 seconds
            base_score *= 0.7
        elif self.avg_response_time > 2000:  # > 2 seconds
            base_score *= 0.85
        
        # Adjust for availability
        base_score *= (self.availability_percentage / 100)
        
        # Quality adjustments
        quality_multiplier = (
            self.data_integrity_score +
            self.consistency_score +
            self.reliability_score
        ) / 300
        
        return min(100.0, max(0.0, base_score * quality_multiplier))
    
    def update_metrics(self, success: bool, response_time: Optional[float] = None):
        """Update metrics with new validation result"""
        if success:
            self.success_count += 1
        else:
            self.failure_count += 1
        
        if response_time is not None and response_time > 0:
            # Update response time statistics
            total_checks = self.success_count + self.failure_count
            if total_checks == 1:
                self.avg_response_time = response_time
                self.min_response_time = response_time
                self.max_response_time = response_time
            else:
                self.avg_response_time = (
                    (self.avg_response_time * (total_checks - 1) + response_time) / total_checks
                )
                self.min_response_time = min(self.min_response_time, response_time)
                self.max_response_time = max(self.max_response_time, response_time)
        
        # Update availability
        total_checks = self.success_count + self.failure_count
        if total_checks > 0:
            self.availability_percentage = (self.success_count / total_checks) * 100
        
        self.last_health_check = datetime.utcnow()


@dataclass
class ProxyRiskProfile:
    """Risk assessment profile for intelligent proxy management"""
    # Risk scoring
    overall_risk_score: float = 50.0  # 0-100 scale (0=lowest risk, 100=highest risk)
    geographical_risk: float = 50.0
    performance_risk: float = 50.0
    security_risk: float = 50.0
    reliability_risk: float = 50.0
    
    # Risk factors
    high_risk_country: bool = False
    known_bad_asn: bool = False
    suspicious_behavior: bool = False
    frequent_failures: bool = False
    inconsistent_responses: bool = False
    
    # Trust metrics
    trust_score: float = 50.0
    reputation_history: List[str] = field(default_factory=list)
    confidence_level: float = 50.0
    
    # Categorization
    risk_category: RiskCategory = RiskCategory.UNKNOWN
    recommended_tier: TierLevel = TierLevel.TIER_4
    scan_frequency_hours: int = 24
    
    # Temporal data
    risk_assessment_date: Optional[datetime] = None
    next_risk_review: Optional[datetime] = None
    risk_trend: str = "stable"  # increasing, decreasing, stable
    
    def update_geographical_risk(self, country_code: Optional[str], asn: Optional[int] = None):
        """Update geographical risk based on location"""
        if country_code:
            if country_code in HIGH_RISK_COUNTRIES:
                self.geographical_risk = 85.0
                self.high_risk_country = True
            elif country_code in LOW_RISK_COUNTRIES:
                self.geographical_risk = 15.0
                self.high_risk_country = False
            else:
                self.geographical_risk = 50.0  # Neutral for unknown countries
        
        # ASN-based risk (placeholder logic)
        if asn and asn in []:  # Add known bad ASNs here
            self.known_bad_asn = True
            self.geographical_risk = min(100.0, self.geographical_risk + 20.0)
    
    def update_performance_risk(self, health_metrics: ProxyHealthMetrics):
        """Update performance risk based on health metrics"""
        health_score = health_metrics.calculate_overall_health_score()
        
        # Inverse relationship: high health = low risk
        self.performance_risk = 100.0 - health_score
        
        # Check for frequent failures
        total_checks = health_metrics.success_count + health_metrics.failure_count
        if total_checks > 10:
            failure_rate = health_metrics.failure_count / total_checks
            if failure_rate > 0.3:  # More than 30% failure rate
                self.frequent_failures = True
                self.performance_risk = min(100.0, self.performance_risk + 15.0)
    
    def update_security_risk(self, security_assessment: SecurityAssessment):
        """Update security risk based on security assessment"""
        base_security_risk = 100.0 - security_assessment.calculate_overall_score()
        
        # Adjust based on specific security factors
        if security_assessment.is_honeypot:
            base_security_risk = 100.0
        elif security_assessment.is_blacklisted:
            base_security_risk = min(100.0, base_security_risk + 30.0)
        
        # Threat level adjustments
        threat_multipliers = {
            ThreatLevel.LOW: 0.8,
            ThreatLevel.MEDIUM: 1.0,
            ThreatLevel.HIGH: 1.5,
            ThreatLevel.CRITICAL: 2.0
        }
        multiplier = threat_multipliers.get(security_assessment.threat_level, 1.0)
        
        self.security_risk = min(100.0, base_security_risk * multiplier)
    
    def calculate_overall_risk(self) -> float:
        """Calculate overall risk score from component risks"""
        # Weighted average of risk components
        weights = {
            'geographical': 0.2,
            'performance': 0.3,
            'security': 0.4,
            'reliability': 0.1
        }
        
        weighted_score = (
            self.geographical_risk * weights['geographical'] +
            self.performance_risk * weights['performance'] +
            self.security_risk * weights['security'] +
            self.reliability_risk * weights['reliability']
        )
        
        self.overall_risk_score = weighted_score
        return weighted_score
    
    def determine_tier_and_category(self) -> Tuple[TierLevel, RiskCategory]:
        """Determine appropriate tier and risk category"""
        risk_score = self.calculate_overall_risk()
        
        # Determine risk category
        if risk_score >= 80:
            category = RiskCategory.INACTIVE
            tier = TierLevel.TIER_3
            frequency = 168  # Weekly
        elif risk_score >= 60:
            category = RiskCategory.AT_RISK
            tier = TierLevel.TIER_2
            frequency = 12   # Every 12 hours
        elif risk_score >= 30:
            category = RiskCategory.ACTIVE
            tier = TierLevel.TIER_1
            frequency = 24   # Daily
        else:
            category = RiskCategory.ACTIVE
            tier = TierLevel.TIER_1
            frequency = 24   # Daily
        
        self.risk_category = category
        self.recommended_tier = tier
        self.scan_frequency_hours = frequency
        
        return tier, category
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'overall_risk_score': self.overall_risk_score,
            'geographical_risk': self.geographical_risk,
            'performance_risk': self.performance_risk,
            'security_risk': self.security_risk,
            'reliability_risk': self.reliability_risk,
            'high_risk_country': self.high_risk_country,
            'known_bad_asn': self.known_bad_asn,
            'trust_score': self.trust_score,
            'confidence_level': self.confidence_level,
            'risk_category': self.risk_category.value,
            'recommended_tier': self.recommended_tier.value,
            'scan_frequency_hours': self.scan_frequency_hours,
            'risk_assessment_date': self.risk_assessment_date.isoformat() if self.risk_assessment_date else None,
            'risk_trend': self.risk_trend
        }


# ===============================================================================
# CONSTANTS AND DEFAULTS
# ===============================================================================

# Default proxy ports by protocol
DEFAULT_PORTS = {
    ProxyProtocol.HTTP: 8080,
    ProxyProtocol.HTTPS: 8443,
    ProxyProtocol.SOCKS4: 1080,
    ProxyProtocol.SOCKS5: 1080
}

# Common proxy ports
COMMON_PROXY_PORTS = [80, 3128, 8080, 8118, 8888, 9050, 1080, 9999]

# High-risk countries (example list)
HIGH_RISK_COUNTRIES = ['CN', 'RU', 'KP', 'IR', 'SY']

# Low-risk countries (example list)
LOW_RISK_COUNTRIES = ['US', 'CA', 'GB', 'DE', 'NL', 'FR', 'AU', 'JP', 'SE', 'NO', 'DK', 'FI']