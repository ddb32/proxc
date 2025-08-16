"""Proxy Engine Analyzers - Enhanced Geographic, Threat and Intelligence Analysis"""

import json
import logging
import random
import socket
import statistics
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse

# Third-party imports with safe fallbacks
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import geoip2.database
    import geoip2.errors
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

# Import our models - using exact names from models.py
from ..proxy_core.models import (
    ProxyInfo, ProxyProtocol, AnonymityLevel, ThreatLevel, 
    ProxyStatus, SecurityLevel, OperationalGrade, GeoLocation,
    ValidationError, SecurityError, NetworkError
)
from ..proxy_core.config import ConfigManager
from ..proxy_core.utils import (
    NetworkAnalysis, SecurityAssessment, NetworkIntelligence,
    CombatValidator, PerformanceMetrics
)


# Configure logging
logger = logging.getLogger(__name__)


# ===============================================================================
# ANALYSIS RESULT CLASSES
# ===============================================================================

class AnalysisType(Enum):
    """Types of proxy analysis"""
    GEOGRAPHIC = "geographic"
    THREAT = "threat"
    PERFORMANCE = "performance"
    NETWORK = "network"
    BEHAVIORAL = "behavioral"


@dataclass
class AnalysisResult:
    """Complete analysis result for a proxy"""
    proxy_id: str
    analysis_type: AnalysisType
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0
    confidence: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'proxy_id': self.proxy_id,
            'analysis_type': self.analysis_type.value,
            'success': self.success,
            'data': self.data,
            'score': self.score,
            'confidence': self.confidence,
            'timestamp': self.timestamp.isoformat(),
            'error_message': self.error_message
        }


@dataclass
class CompositeAnalysisResult:
    """Complete analysis result combining all analysis types"""
    proxy_id: str
    overall_score: float = 0.0
    overall_grade: OperationalGrade = OperationalGrade.BASIC
    geographic_analysis: Optional[AnalysisResult] = None
    threat_analysis: Optional[AnalysisResult] = None
    performance_analysis: Optional[AnalysisResult] = None
    network_analysis: Optional[AnalysisResult] = None
    behavioral_analysis: Optional[AnalysisResult] = None
    recommendations: List[str] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    
    def get_analysis_by_type(self, analysis_type: AnalysisType) -> Optional[AnalysisResult]:
        """Get specific analysis result by type"""
        type_mapping = {
            AnalysisType.GEOGRAPHIC: self.geographic_analysis,
            AnalysisType.THREAT: self.threat_analysis,
            AnalysisType.PERFORMANCE: self.performance_analysis,
            AnalysisType.NETWORK: self.network_analysis,
            AnalysisType.BEHAVIORAL: self.behavioral_analysis
        }
        return type_mapping.get(analysis_type)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = {
            'proxy_id': self.proxy_id,
            'overall_score': self.overall_score,
            'overall_grade': self.overall_grade.value,
            'recommendations': self.recommendations,
            'risk_factors': self.risk_factors,
            'analyzed_at': self.analyzed_at.isoformat()
        }
        
        # Add individual analysis results
        for analysis_type in AnalysisType:
            analysis = self.get_analysis_by_type(analysis_type)
            if analysis:
                result[f'{analysis_type.value}_analysis'] = analysis.to_dict()
        
        return result


# ===============================================================================
# GEOGRAPHIC ANALYZER
# ===============================================================================

class GeoAnalyzer:
    """Geographic analysis and intelligence gathering"""
    
    def __init__(self, config: Optional[ConfigManager] = None, 
                 geoip_db_path: Optional[str] = None):
        self.config = config or ConfigManager()
        self.geoip_db_path = geoip_db_path
        self.network_intel = NetworkIntelligence({'geoip_db_path': geoip_db_path})
        self.logger = logging.getLogger(__name__)
    
    def analyze_proxy(self, proxy: ProxyInfo) -> AnalysisResult:
        """Perform geographic analysis of proxy"""
        result = AnalysisResult(
            proxy_id=proxy.proxy_id,
            analysis_type=AnalysisType.GEOGRAPHIC,
            success=False
        )
        
        try:
            # Perform network analysis
            network_analysis = self.network_intel.analyze_ip(proxy.host)
            
            # Extract geographic data
            geo_data = {
                'ip_address': proxy.host,
                'country_code': network_analysis.country_code,
                'region': network_analysis.region,
                'city': network_analysis.city,
                'timezone': network_analysis.timezone,
                'asn': network_analysis.asn,
                'isp': network_analysis.isp,
                'organization': network_analysis.organization,
                'is_hosting': network_analysis.is_hosting,
                'is_mobile': network_analysis.is_mobile
            }
            
            # Calculate geographic score
            score = self._calculate_geo_score(network_analysis)
            
            # Update proxy geo location if not set
            if not proxy.geo_location:
                proxy.geo_location = GeoLocation(
                    country=network_analysis.country_code or 'Unknown',
                    region=network_analysis.region,
                    city=network_analysis.city,
                    latitude=0.0,  # Would need additional GeoIP data
                    longitude=0.0,
                    timezone=network_analysis.timezone
                )
            
            result.success = True
            result.data = geo_data
            result.score = score
            result.confidence = 0.9 if network_analysis.country_code else 0.3
            
            self.logger.debug(f"Geographic analysis completed for {proxy.host}")
            
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            result.score = 0.0
            result.confidence = 0.0
            self.logger.error(f"Geographic analysis failed for {proxy.host}: {e}")
        
        return result
    
    def _calculate_geo_score(self, network_analysis: NetworkAnalysis) -> float:
        """Calculate geographic intelligence score"""
        score = 50.0  # Base score
        
        # Country detection bonus
        if network_analysis.country_code:
            score += 20.0
        
        # ISP/Organization information bonus
        if network_analysis.isp:
            score += 15.0
        
        # ASN information bonus
        if network_analysis.asn:
            score += 10.0
        
        # Hosting provider detection (can be good or bad)
        if network_analysis.is_hosting:
            score += 5.0  # Good for availability
        
        # Mobile network detection
        if network_analysis.is_mobile:
            score -= 10.0  # Generally less stable
        
        return min(100.0, max(0.0, score))


# ===============================================================================
# THREAT ANALYZER
# ===============================================================================

class ThreatAnalyzer:
    """Threat assessment and security analysis"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.network_intel = NetworkIntelligence()
        self.logger = logging.getLogger(__name__)
    
    def analyze_proxy(self, proxy: ProxyInfo) -> AnalysisResult:
        """Perform threat analysis of proxy"""
        result = AnalysisResult(
            proxy_id=proxy.proxy_id,
            analysis_type=AnalysisType.THREAT,
            success=False
        )
        
        try:
            # Perform network analysis for threat detection
            network_analysis = self.network_intel.analyze_ip(proxy.host)
            
            # Analyze threats
            threat_data = {
                'threat_types': network_analysis.threat_types,
                'blacklist_status': network_analysis.blacklist_status,
                'is_tor': network_analysis.is_tor,
                'is_vpn': network_analysis.is_vpn,
                'is_proxy': network_analysis.is_proxy,
                'ports_open': network_analysis.ports_open,
                'services_detected': network_analysis.services_detected
            }
            
            # Calculate threat level and score
            threat_level, threat_score = self._assess_threat_level(network_analysis)
            
            # Update proxy threat level
            proxy.threat_level = threat_level
            
            result.success = True
            result.data = threat_data
            result.score = threat_score
            result.confidence = 0.8
            
            self.logger.debug(f"Threat analysis completed for {proxy.host}")
            
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            result.score = 0.0
            result.confidence = 0.0
            self.logger.error(f"Threat analysis failed for {proxy.host}: {e}")
        
        return result
    
    def _assess_threat_level(self, network_analysis: NetworkAnalysis) -> Tuple[ThreatLevel, float]:
        """Assess threat level and calculate security score"""
        risk_score = 0
        security_score = 100.0
        
        # Check blacklist status
        blacklisted_count = sum(1 for listed in network_analysis.blacklist_status.values() if listed)
        if blacklisted_count > 0:
            risk_score += blacklisted_count * 25
            security_score -= blacklisted_count * 30
        
        # Check for dangerous threat types
        dangerous_threats = ['tor_exit_node', 'blacklisted', 'hosting_provider']
        for threat in network_analysis.threat_types:
            if threat in dangerous_threats:
                risk_score += 20
                security_score -= 25
        
        # Check for suspicious services
        suspicious_ports = [1080, 3128, 8080, 8888, 9050]  # Common proxy/Tor ports
        for port in network_analysis.ports_open:
            if port in suspicious_ports:
                risk_score += 5
                security_score -= 5
        
        # Determine threat level
        if risk_score >= 75:
            threat_level = ThreatLevel.CRITICAL
        elif risk_score >= 50:
            threat_level = ThreatLevel.HIGH
        elif risk_score >= 25:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW
        
        return threat_level, max(0.0, min(100.0, security_score))


# ===============================================================================
# PERFORMANCE ANALYZER
# ===============================================================================

class PerformanceAnalyzer:
    """Performance analysis and benchmarking"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.validator = CombatValidator()
        self.logger = logging.getLogger(__name__)
    
    def analyze_proxy(self, proxy: ProxyInfo) -> AnalysisResult:
        """Perform performance analysis of proxy"""
        result = AnalysisResult(
            proxy_id=proxy.proxy_id,
            analysis_type=AnalysisType.PERFORMANCE,
            success=False
        )
        
        try:
            # Validate proxy and collect performance metrics
            validation_result = self.validator.validate_proxy(proxy)
            
            if not validation_result.is_valid:
                result.success = False
                result.error_message = validation_result.error_message
                return result
            
            # Collect performance data
            perf_data = {
                'response_time': validation_result.response_time,
                'ssl_supported': validation_result.ssl_supported,
                'anonymity_level': validation_result.anonymity_detected.value if validation_result.anonymity_detected else None,
                'dns_leak': validation_result.dns_leak,
                'webrtc_leak': validation_result.webrtc_leak
            }
            
            # Calculate performance score
            score = self._calculate_performance_score(validation_result)
            
            result.success = True
            result.data = perf_data
            result.score = score
            result.confidence = 0.9
            
            self.logger.debug(f"Performance analysis completed for {proxy.host}")
            
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            result.score = 0.0
            result.confidence = 0.0
            self.logger.error(f"Performance analysis failed for {proxy.host}: {e}")
        
        return result
    
    def _calculate_performance_score(self, validation_result) -> float:
        """Calculate performance score based on validation results"""
        score = 50.0  # Base score
        
        # Response time scoring
        if validation_result.response_time:
            if validation_result.response_time < 1.0:
                score += 30.0  # Excellent
            elif validation_result.response_time < 3.0:
                score += 20.0  # Good
            elif validation_result.response_time < 5.0:
                score += 10.0  # Fair
            else:
                score -= 10.0  # Poor
        
        # SSL support bonus
        if validation_result.ssl_supported:
            score += 15.0
        
        # Anonymity level bonus
        if validation_result.anonymity_detected:
            if validation_result.anonymity_detected == AnonymityLevel.ELITE:
                score += 25.0
            elif validation_result.anonymity_detected == AnonymityLevel.ANONYMOUS:
                score += 15.0
            else:  # TRANSPARENT
                score -= 20.0
        
        # Leak detection penalties
        if validation_result.dns_leak:
            score -= 20.0
        
        if validation_result.webrtc_leak:
            score -= 15.0
        
        return min(100.0, max(0.0, score))


# ===============================================================================
# MAIN PROXY ANALYZER
# ===============================================================================

class ProxyAnalyzer:
    """Main proxy analyzer combining all analysis types"""
    
    def __init__(self, config: Optional[ConfigManager] = None,
                 geoip_db_path: Optional[str] = None):
        self.config = config or ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Initialize sub-analyzers
        self.geo_analyzer = GeoAnalyzer(config, geoip_db_path)
        self.threat_analyzer = ThreatAnalyzer(config)
        self.performance_analyzer = PerformanceAnalyzer(config)
    
    def analyze_proxy(self, proxy: ProxyInfo, 
                     analysis_types: Optional[Set[AnalysisType]] = None) -> CompositeAnalysisResult:
        """Perform comprehensive proxy analysis"""
        analysis_types = analysis_types or {
            AnalysisType.GEOGRAPHIC, 
            AnalysisType.THREAT, 
            AnalysisType.PERFORMANCE
        }
        
        result = CompositeAnalysisResult(proxy_id=proxy.proxy_id)
        scores = []
        
        try:
            # Geographic analysis
            if AnalysisType.GEOGRAPHIC in analysis_types:
                geo_result = self.geo_analyzer.analyze_proxy(proxy)
                result.geographic_analysis = geo_result
                if geo_result.success:
                    scores.append(geo_result.score)
            
            # Threat analysis
            if AnalysisType.THREAT in analysis_types:
                threat_result = self.threat_analyzer.analyze_proxy(proxy)
                result.threat_analysis = threat_result
                if threat_result.success:
                    scores.append(threat_result.score)
            
            # Performance analysis
            if AnalysisType.PERFORMANCE in analysis_types:
                perf_result = self.performance_analyzer.analyze_proxy(proxy)
                result.performance_analysis = perf_result
                if perf_result.success:
                    scores.append(perf_result.score)
            
            # Calculate overall score
            if scores:
                result.overall_score = statistics.mean(scores)
            else:
                result.overall_score = 0.0
            
            # Determine operational grade
            result.overall_grade = self._determine_operational_grade(result.overall_score)
            
            # Generate recommendations and risk factors
            self._generate_recommendations(result)
            self._identify_risk_factors(result)
            
            # Update proxy classification
            self._update_proxy_classification(proxy, result)
            
            self.logger.debug(f"Analysis completed for {proxy.host}:{proxy.port} - Score: {result.overall_score:.1f}")
            
        except Exception as e:
            self.logger.error(f"Analysis failed for {proxy.proxy_id}: {e}")
            result.overall_score = 0.0
            result.overall_grade = OperationalGrade.BASIC
        
        return result
    
    def _determine_operational_grade(self, score: float) -> OperationalGrade:
        """Determine operational grade based on score"""
        if score >= 90:
            return OperationalGrade.ELITE
        elif score >= 75:
            return OperationalGrade.ENTERPRISE
        elif score >= 60:
            return OperationalGrade.PROFESSIONAL
        else:
            return OperationalGrade.BASIC
    
    def _generate_recommendations(self, result: CompositeAnalysisResult):
        """Generate recommendations based on analysis results"""
        recommendations = []
        
        # Geographic recommendations
        if result.geographic_analysis and result.geographic_analysis.success:
            geo_data = result.geographic_analysis.data
            if geo_data.get('is_hosting'):
                recommendations.append("Proxy is hosted on hosting provider - good for stability")
            if geo_data.get('is_mobile'):
                recommendations.append("Mobile network detected - may have variable performance")
        
        # Threat recommendations
        if result.threat_analysis and result.threat_analysis.success:
            threat_data = result.threat_analysis.data
            if threat_data.get('threat_types'):
                recommendations.append("Threat indicators detected - use with caution")
            if any(threat_data.get('blacklist_status', {}).values()):
                recommendations.append("IP is blacklisted - avoid for sensitive operations")
        
        # Performance recommendations
        if result.performance_analysis and result.performance_analysis.success:
            perf_data = result.performance_analysis.data
            if perf_data.get('ssl_supported'):
                recommendations.append("SSL support confirmed - suitable for HTTPS traffic")
            if perf_data.get('dns_leak') or perf_data.get('webrtc_leak'):
                recommendations.append("Privacy leaks detected - not suitable for anonymity")
        
        result.recommendations = recommendations
    
    def _identify_risk_factors(self, result: CompositeAnalysisResult):
        """Identify risk factors based on analysis results"""
        risk_factors = []
        
        # Check all analysis results for risk factors
        for analysis in [result.geographic_analysis, result.threat_analysis, result.performance_analysis]:
            if analysis and analysis.success:
                data = analysis.data
                
                # Geographic risks
                if data.get('is_tor'):
                    risk_factors.append("Tor exit node detected")
                if data.get('is_vpn'):
                    risk_factors.append("VPN service detected")
                
                # Security risks
                if any(data.get('blacklist_status', {}).values()):
                    risk_factors.append("IP blacklisted by security services")
                
                # Performance risks
                if data.get('dns_leak'):
                    risk_factors.append("DNS leak vulnerability")
                if data.get('webrtc_leak'):
                    risk_factors.append("WebRTC leak vulnerability")
        
        result.risk_factors = risk_factors
    
    def _update_proxy_classification(self, proxy: ProxyInfo, result: CompositeAnalysisResult):
        """Update proxy classification based on analysis"""
        # Update operational grade
        proxy.operational_grade = result.overall_grade
        
        # Update status based on overall score
        if result.overall_score < 30:
            proxy.status = ProxyStatus.FAILED
        elif result.overall_score < 50:
            proxy.status = ProxyStatus.INACTIVE
        else:
            proxy.status = ProxyStatus.ACTIVE
        
        # Update security level
        if result.overall_score > 80:
            proxy.security_level = SecurityLevel.HIGH
        elif result.overall_score > 60:
            proxy.security_level = SecurityLevel.MEDIUM
        else:
            proxy.security_level = SecurityLevel.LOW
    
    def analyze_proxy_batch(self, proxies: List[ProxyInfo],
                           analysis_types: Optional[Set[AnalysisType]] = None, 
                           max_workers: int = 10) -> List[CompositeAnalysisResult]:
        """Analyze multiple proxies with optional threading"""
        if len(proxies) <= 5:
            # Use sequential processing for small batches
            return self._analyze_proxy_batch_sequential(proxies, analysis_types)
        
        # Use threaded processing for larger batches
        return self._analyze_proxy_batch_threaded(proxies, analysis_types, max_workers)
    
    def _analyze_proxy_batch_sequential(self, proxies: List[ProxyInfo],
                                       analysis_types: Optional[Set[AnalysisType]] = None) -> List[CompositeAnalysisResult]:
        """Sequential analysis (original implementation)"""
        results = []
        
        self.logger.info(f"Starting sequential analysis of {len(proxies)} proxies")
        
        for i, proxy in enumerate(proxies, 1):
            try:
                result = self.analyze_proxy(proxy, analysis_types)
                results.append(result)
                
                if i % 10 == 0:
                    self.logger.info(f"Analyzed {i}/{len(proxies)} proxies")
                    
            except Exception as e:
                self.logger.error(f"Analysis failed for proxy {i}: {e}")
        
        self.logger.info(f"Completed sequential analysis: {len(results)} successful")
        return results
    
    def _analyze_proxy_batch_threaded(self, proxies: List[ProxyInfo],
                                     analysis_types: Optional[Set[AnalysisType]] = None,
                                     max_workers: int = 10) -> List[CompositeAnalysisResult]:
        """Threaded analysis for better performance"""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading
        
        results = []
        lock = threading.Lock()
        processed = 0
        
        self.logger.debug(f"Starting threaded analysis of {len(proxies)} proxies with {max_workers} workers")
        
        def analyze_single(proxy_info):
            """Wrapper function for threaded execution"""
            proxy, index = proxy_info
            try:
                result = self.analyze_proxy(proxy, analysis_types)
                
                # Update progress periodically
                nonlocal processed
                with lock:
                    processed += 1
                    if processed % 10 == 0:
                        self.logger.info(f"Analyzed {processed}/{len(proxies)} proxies")
                
                return (index, result, None)
            except Exception as e:
                self.logger.error(f"Analysis failed for proxy {index + 1}: {e}")
                return (index, None, str(e))
        
        # Create indexed proxy list for maintaining order
        indexed_proxies = [(proxy, i) for i, proxy in enumerate(proxies)]
        
        # Use ThreadPoolExecutor for concurrent analysis
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_index = {executor.submit(analyze_single, proxy_info): i 
                              for i, proxy_info in enumerate(indexed_proxies)}
            
            # Initialize results list with None values
            ordered_results = [None] * len(proxies)
            
            # Collect results as they complete
            for future in as_completed(future_to_index):
                try:
                    index, result, error = future.result()
                    if result is not None:
                        ordered_results[index] = result
                    elif error:
                        self.logger.warning(f"Proxy {index + 1} analysis failed: {error}")
                except Exception as e:
                    future_index = future_to_index[future]
                    self.logger.error(f"Future execution failed for proxy {future_index + 1}: {e}")
            
            # Filter out None results (failed analyses)
            results = [result for result in ordered_results if result is not None]
        
        self.logger.info(f"Completed threaded analysis: {len(results)}/{len(proxies)} successful")
        return results
    
    def analyze_batch(self, proxies: List[ProxyInfo],
                     analysis_types: Optional[Set[AnalysisType]] = None) -> List[CompositeAnalysisResult]:
        """Alias for analyze_proxy_batch for CLI compatibility"""
        return self.analyze_proxy_batch(proxies, analysis_types)


# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def create_geo_analyzer(config: Optional[ConfigManager] = None,
                       geoip_db_path: Optional[str] = None) -> GeoAnalyzer:
    """Create geographic analyzer"""
    return GeoAnalyzer(config, geoip_db_path)


def create_threat_analyzer(config: Optional[ConfigManager] = None) -> ThreatAnalyzer:
    """Create threat analyzer"""
    return ThreatAnalyzer(config)


def create_performance_analyzer(config: Optional[ConfigManager] = None) -> PerformanceAnalyzer:
    """Create performance analyzer"""
    return PerformanceAnalyzer(config)


def create_proxy_analyzer(config: Optional[ConfigManager] = None,
                         geoip_db_path: Optional[str] = None) -> ProxyAnalyzer:
    """Create composite proxy analyzer"""
    return ProxyAnalyzer(config, geoip_db_path)


def analyze_proxy_quick(proxy: ProxyInfo, 
                       geoip_db_path: Optional[str] = None) -> CompositeAnalysisResult:
    """Quick utility function to analyze a single proxy"""
    analyzer = create_proxy_analyzer(geoip_db_path=geoip_db_path)
    return analyzer.analyze_proxy(proxy)


def analyze_proxy_geo_only(proxy: ProxyInfo,
                          geoip_db_path: Optional[str] = None) -> AnalysisResult:
    """Analyze only geographic information"""
    analyzer = create_geo_analyzer(geoip_db_path=geoip_db_path)
    return analyzer.analyze_proxy(proxy)


def analyze_proxy_threats_only(proxy: ProxyInfo) -> AnalysisResult:
    """Analyze only threat information"""
    analyzer = create_threat_analyzer()
    return analyzer.analyze_proxy(proxy)


def analyze_proxy_performance_only(proxy: ProxyInfo) -> AnalysisResult:
    """Analyze only performance information"""
    analyzer = create_performance_analyzer()
    return analyzer.analyze_proxy(proxy)


logger.info("Proxy analyzers module loaded successfully")