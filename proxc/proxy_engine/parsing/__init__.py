"""Parsing Module - Proxy data parsing from various formats"""

# Pattern library
from .pattern_library import (
    PROXY_PATTERNS,
    PROTOCOL_PATTERNS,
    ANONYMITY_PATTERNS,
    COUNTRY_PATTERNS,
    LOCATION_PATTERNS,
    PERFORMANCE_PATTERNS,
    QUALITY_PATTERNS,
    THREAT_PATTERNS,
    HTML_TABLE_PATTERNS,
    URL_PATTERNS,
    CLEANING_PATTERNS,
    IP_VALIDATION_PATTERNS,
    PORT_VALIDATION_PATTERNS,
    FORMAT_DETECTION_PATTERNS,
    get_pattern_for_protocol,
    get_combined_proxy_pattern,
    get_quality_indicators
)

# Text parsers
from .text_parsers import (
    ParseResult,
    TextProxyParser,
    CSVProxyParser,
    JSONProxyParser,
    FormatDetector,
    parse_proxy_text,
    parse_proxy_file
)

# HTML parsers
from .html_parsers import (
    HTMLProxyParser,
    parse_html_content
)

__all__ = [
    # Pattern library
    'PROXY_PATTERNS',
    'PROTOCOL_PATTERNS',
    'ANONYMITY_PATTERNS',
    'COUNTRY_PATTERNS',
    'LOCATION_PATTERNS',
    'PERFORMANCE_PATTERNS',
    'QUALITY_PATTERNS',
    'THREAT_PATTERNS',
    'HTML_TABLE_PATTERNS',
    'URL_PATTERNS',
    'CLEANING_PATTERNS',
    'IP_VALIDATION_PATTERNS',
    'PORT_VALIDATION_PATTERNS',
    'FORMAT_DETECTION_PATTERNS',
    'get_pattern_for_protocol',
    'get_combined_proxy_pattern',
    'get_quality_indicators',
    
    # Result classes
    'ParseResult',
    
    # Text parsers
    'TextProxyParser',
    'CSVProxyParser',
    'JSONProxyParser',
    'FormatDetector',
    'parse_proxy_text',
    'parse_proxy_file',
    
    # HTML parsers
    'HTMLProxyParser',
    'parse_html_content'
]