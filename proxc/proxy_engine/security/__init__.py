"""Security Module - Advanced security analysis and threat detection"""

from .chain_detector import (
    ChainDetector,
    ChainAnalysisResult,
    ChainSignature,
    ProxyChainInfo,
    detect_proxy_chain
)
from .security_config import SecurityConfig, ChainDetectionConfig
from .security_utils import SecurityUtils, parse_proxy_headers, calculate_chain_risk

__all__ = [
    'ChainDetector',
    'ChainAnalysisResult', 
    'ChainSignature',
    'ProxyChainInfo',
    'detect_proxy_chain',
    'SecurityConfig',
    'ChainDetectionConfig',
    'SecurityUtils',
    'parse_proxy_headers',
    'calculate_chain_risk'
]