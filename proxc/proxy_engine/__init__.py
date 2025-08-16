__version__ = "3.1.0-REFACTORED"

# Import from new modular structure
try:
    # Analysis components
    from .analysis import (
        ProxyAnalyzer, GeoAnalyzer, ThreatAnalyzer, PerformanceAnalyzer,
        AnalysisResult, AnalysisType, CompositeAnalysisResult,
        create_proxy_analyzer, analyze_proxy_quick
    )
    
    # Validation components
    from .validation import (
        SyncProxyValidator, AsyncProxyValidator, BatchValidator,
        ValidationResult, BatchValidationResult, ValidationConfig,
        ValidationMethod, FailureReason,
        validate_proxies, validate_proxies_async, validate_proxies_sync
    )
    
    # Parsing components
    from .parsing import (
        TextProxyParser, HTMLProxyParser, CSVProxyParser, JSONProxyParser,
        ParseResult, FormatDetector,
        parse_proxy_text, parse_proxy_file, parse_html_content
    )
    
    # Keep existing components that haven't been refactored yet
    from .fetchers import ProxyFetcher
    from .filters import ProxyFilter, FilterCriteria
    from .exporters import ExportManager
    from .scanner import ScanManager, ScanMode, ScanConfig
    from .protocol_detection import ProxyProtocolDetector
    
except ImportError as e:
    print(f"Warning: Some proxy engine components could not be imported: {e}")

__all__ = [
    # Analysis
    "ProxyAnalyzer", "GeoAnalyzer", "ThreatAnalyzer", "PerformanceAnalyzer",
    "AnalysisResult", "AnalysisType", "CompositeAnalysisResult",
    "create_proxy_analyzer", "analyze_proxy_quick",
    
    # Validation
    "SyncProxyValidator", "AsyncProxyValidator", "BatchValidator",
    "ValidationResult", "BatchValidationResult", "ValidationConfig",
    "ValidationMethod", "FailureReason",
    "validate_proxies", "validate_proxies_async", "validate_proxies_sync",
    
    # Parsing
    "TextProxyParser", "HTMLProxyParser", "CSVProxyParser", "JSONProxyParser", 
    "ParseResult", "FormatDetector",
    "parse_proxy_text", "parse_proxy_file", "parse_html_content",
    
    # Legacy components (to be refactored)
    "ProxyFetcher", "ProxyFilter", "FilterCriteria", "ExportManager",
    "ScanManager", "ScanMode", "ScanConfig", "ProxyProtocolDetector"
]
