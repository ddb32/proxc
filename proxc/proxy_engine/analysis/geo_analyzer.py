"""Geographic Analyzer - Enhanced IP geolocation and network intelligence analysis"""

import logging
from typing import Optional, Dict, Any

from ...proxy_core.models import ProxyInfo, GeoLocation
from ...proxy_core.config import ConfigManager
from ...proxy_core.utils import NetworkIntelligence, NetworkAnalysis
from .analysis_results import AnalysisResult, AnalysisType


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
                    country=network_analysis.country or 'Unknown',
                    country_code=network_analysis.country_code,
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
        """Calculate comprehensive geographic intelligence score"""
        score = 40.0  # Base score for any analysis
        
        # Geographic data completeness (0-30 points)
        if network_analysis.country_code:
            score += 15.0
            if network_analysis.region:
                score += 8.0
            if network_analysis.city:
                score += 7.0
        
        # Network information completeness (0-25 points)
        if network_analysis.isp:
            score += 12.0
        if network_analysis.asn:
            score += 8.0
        if network_analysis.organization:
            score += 5.0
        
        # Network type assessment (0-15 points)
        if network_analysis.is_hosting:
            score += 15.0  # Hosting providers often more stable
        elif network_analysis.is_mobile:
            score += 5.0   # Mobile networks add variety but less stability
        
        # Additional quality indicators (0-10 points)
        if network_analysis.timezone:
            score += 5.0   # Timezone info indicates good geolocation data
        
        # Ensure score is within bounds
        return min(100.0, max(0.0, score))


def create_geo_analyzer(config: Optional[ConfigManager] = None,
                       geoip_db_path: Optional[str] = None) -> GeoAnalyzer:
    """Create geographic analyzer"""
    return GeoAnalyzer(config, geoip_db_path)


def analyze_proxy_geo_only(proxy: ProxyInfo,
                          geoip_db_path: Optional[str] = None) -> AnalysisResult:
    """Analyze only geographic information"""
    analyzer = create_geo_analyzer(geoip_db_path=geoip_db_path)
    return analyzer.analyze_proxy(proxy)