"""Performance Analyzer - Proxy performance and benchmarking analysis"""

import logging
from typing import Optional

from ...proxy_core.models import (
    ProxyInfo, AnonymityLevel
)
from ...proxy_core.config import ConfigManager
from ...proxy_core.utils import CombatValidator
from .analysis_results import AnalysisResult, AnalysisType


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


def create_performance_analyzer(config: Optional[ConfigManager] = None) -> PerformanceAnalyzer:
    """Create performance analyzer"""
    return PerformanceAnalyzer(config)


def analyze_proxy_performance_only(proxy: ProxyInfo) -> AnalysisResult:
    """Analyze only performance information"""
    analyzer = create_performance_analyzer()
    return analyzer.analyze_proxy(proxy)