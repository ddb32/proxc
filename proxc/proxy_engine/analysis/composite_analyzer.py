"""Composite Analyzer - Main proxy analyzer orchestrating all analysis types"""

import logging
import statistics
from typing import List, Optional, Set

from ...proxy_core.models import (
    ProxyInfo, ProxyStatus, SecurityLevel, OperationalGrade
)
from ...proxy_core.config import ConfigManager
from .analysis_results import AnalysisResult, AnalysisType, CompositeAnalysisResult
from .geo_analyzer import GeoAnalyzer
from .threat_analyzer import ThreatAnalyzer
from .performance_analyzer import PerformanceAnalyzer


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
            # Geographic analysis with fallback
            if AnalysisType.GEOGRAPHIC in analysis_types:
                try:
                    geo_result = self.geo_analyzer.analyze_proxy(proxy)
                    result.geographic_analysis = geo_result
                    if geo_result.success and geo_result.score > 0:
                        scores.append(geo_result.score)
                except Exception as e:
                    self.logger.warning(f"Geographic analysis failed for {proxy.proxy_id}: {e}")
            
            # Threat analysis with fallback
            if AnalysisType.THREAT in analysis_types:
                try:
                    threat_result = self.threat_analyzer.analyze_proxy(proxy)
                    result.threat_analysis = threat_result
                    if threat_result.success and threat_result.score > 0:
                        scores.append(threat_result.score)
                except Exception as e:
                    self.logger.warning(f"Threat analysis failed for {proxy.proxy_id}: {e}")
            
            # Performance analysis with fallback
            if AnalysisType.PERFORMANCE in analysis_types:
                try:
                    perf_result = self.performance_analyzer.analyze_proxy(proxy)
                    result.performance_analysis = perf_result
                    if perf_result.success and perf_result.score > 0:
                        scores.append(perf_result.score)
                except Exception as e:
                    self.logger.warning(f"Performance analysis failed for {proxy.proxy_id}: {e}")
            
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
                           analysis_types: Optional[Set[AnalysisType]] = None) -> List[CompositeAnalysisResult]:
        """Analyze multiple proxies"""
        results = []
        
        self.logger.info(f"Starting batch analysis of {len(proxies)} proxies")
        
        for i, proxy in enumerate(proxies, 1):
            try:
                result = self.analyze_proxy(proxy, analysis_types)
                results.append(result)
                
                if i % 10 == 0:
                    self.logger.info(f"Analyzed {i}/{len(proxies)} proxies")
                    
            except Exception as e:
                self.logger.error(f"Analysis failed for proxy {i}: {e}")
        
        self.logger.info(f"Completed batch analysis: {len(results)} successful")
        return results
    
    def analyze_batch(self, proxies: List[ProxyInfo],
                     analysis_types: Optional[Set[AnalysisType]] = None) -> List[CompositeAnalysisResult]:
        """Alias for analyze_proxy_batch for CLI compatibility"""
        return self.analyze_proxy_batch(proxies, analysis_types)


def create_proxy_analyzer(config: Optional[ConfigManager] = None,
                         geoip_db_path: Optional[str] = None) -> ProxyAnalyzer:
    """Create composite proxy analyzer"""
    return ProxyAnalyzer(config, geoip_db_path)


def analyze_proxy_quick(proxy: ProxyInfo, 
                       geoip_db_path: Optional[str] = None) -> CompositeAnalysisResult:
    """Quick utility function to analyze a single proxy"""
    analyzer = create_proxy_analyzer(geoip_db_path=geoip_db_path)
    return analyzer.analyze_proxy(proxy)