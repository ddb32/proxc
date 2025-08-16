"""Analysis Module - Proxy analysis components"""

from .analysis_results import (
    AnalysisResult,
    AnalysisType,
    CompositeAnalysisResult
)
from .geo_analyzer import (
    GeoAnalyzer,
    create_geo_analyzer,
    analyze_proxy_geo_only
)
from .threat_analyzer import (
    ThreatAnalyzer,
    create_threat_analyzer,
    analyze_proxy_threats_only
)
from .performance_analyzer import (
    PerformanceAnalyzer,
    create_performance_analyzer,
    analyze_proxy_performance_only
)
from .composite_analyzer import (
    ProxyAnalyzer,
    create_proxy_analyzer,
    analyze_proxy_quick
)

__all__ = [
    # Result classes
    'AnalysisResult',
    'AnalysisType', 
    'CompositeAnalysisResult',
    
    # Analyzer classes
    'GeoAnalyzer',
    'ThreatAnalyzer',
    'PerformanceAnalyzer',
    'ProxyAnalyzer',
    
    # Factory functions
    'create_geo_analyzer',
    'create_threat_analyzer',
    'create_performance_analyzer',
    'create_proxy_analyzer',
    
    # Utility functions
    'analyze_proxy_geo_only',
    'analyze_proxy_threats_only',
    'analyze_proxy_performance_only',
    'analyze_proxy_quick'
]