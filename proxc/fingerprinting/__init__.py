"""
ProxC Fingerprinting System
=================================

Advanced proxy fingerprinting and signature detection capabilities including:
- HTTP proxy type identification (Squid, TinyProxy, Apache, Nginx, etc.)
- Header analysis and behavioral pattern matching
- SSL/TLS certificate analysis for proxy identification
- Connection behavior analysis and proxy chain detection

Features:
- Comprehensive proxy software detection
- HTTP header signature analysis
- Response timing pattern recognition
- SSL certificate-based identification
- Proxy behavior classification

Author: Proxy Hunter Development Team
Version: 3.2.0-FINGERPRINTING
License: MIT
"""

import logging
from typing import Dict, List, Optional, Any
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

class ProxyType(Enum):
    """Known proxy server types"""
    SQUID = "squid"
    TINYPROXY = "tinyproxy"
    APACHE_HTTPD = "apache_httpd"
    NGINX = "nginx"
    HAPROXY = "haproxy"
    TRAEFIK = "traefik"
    ENVOY = "envoy"
    CLOUDFLARE = "cloudflare"
    CLOUDFRONT = "cloudfront"
    FASTLY = "fastly"
    UNKNOWN = "unknown"

class FingerprintingMethod(Enum):
    """Methods for proxy fingerprinting"""
    HEADER_ANALYSIS = "header_analysis"
    RESPONSE_TIMING = "response_timing"
    SSL_CERTIFICATE = "ssl_certificate"
    BEHAVIOR_PATTERN = "behavior_pattern"
    ERROR_MESSAGE = "error_message"

class ConfidenceLevel(Enum):
    """Confidence levels for fingerprinting results"""
    HIGH = "high"        # >90% confident
    MEDIUM = "medium"    # 70-90% confident
    LOW = "low"          # 50-70% confident
    VERY_LOW = "very_low"  # <50% confident

# Export main classes
from .signature_detector import (
    ProxySignatureDetector,
    SignatureDatabase,
    DetectionResult,
    ProxySignature
)

from .header_analyzer import (
    HeaderAnalyzer,
    HeaderSignature,
    HeaderAnalysisResult,
    HeaderPatternLibrary
)

from .behavior_analyzer import (
    BehaviorAnalyzer,
    BehaviorPattern,
    BehaviorAnalysisResult,
    ConnectionBehaviorTracker
)

__all__ = [
    'ProxyType',
    'FingerprintingMethod',
    'ConfidenceLevel',
    'ProxySignatureDetector',
    'SignatureDatabase',
    'DetectionResult',
    'ProxySignature',
    'HeaderAnalyzer',
    'HeaderSignature',
    'HeaderAnalysisResult',
    'HeaderPatternLibrary',
    'BehaviorAnalyzer',
    'BehaviorPattern',
    'BehaviorAnalysisResult',
    'ConnectionBehaviorTracker'
]

# Version info
__version__ = "3.2.0-FINGERPRINTING"
__author__ = "ProxC Development Team"
__license__ = "MIT"

logger.info("Fingerprinting system initialized successfully")