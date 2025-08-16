"""
ProxC Discovery System
============================

Advanced proxy discovery capabilities including:
- IP range scanning for cloud providers and ISPs
- Port discovery with intelligent timeout optimization
- Connection analysis and proxy detection
- Active scanning with stealth capabilities

Features:
- Multi-threaded IP range scanning
- Cloud provider IP range support (AWS, GCP, Azure, etc.)
- Adaptive port scanning with common proxy ports
- Geographic-aware connection optimization
- Integration with existing validation pipeline

Author: Proxy Hunter Development Team
Version: 3.2.0-DISCOVERY
License: MIT
"""

import logging
from typing import List, Dict, Any, Optional
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

class DiscoveryMode(Enum):
    """Discovery operation modes"""
    PASSIVE = "passive"  # Use existing sources only
    ACTIVE = "active"    # Active IP/port scanning
    HYBRID = "hybrid"    # Combine passive and active methods

class ScanIntensity(Enum):
    """Scanning intensity levels"""
    LIGHT = "light"      # Conservative scanning
    MEDIUM = "medium"    # Balanced performance
    AGGRESSIVE = "aggressive"  # Maximum coverage

# Export main classes
from .ip_scanner import (
    IPRangeScanner,
    CloudProviderRanges,
    ISPSubnetDiscoverer,
    ScanConfig,
    ScanResult
)

from .port_scanner import (
    PortDiscoveryEngine,
    ProxyPortScanner,
    PortScanResult,
    CommonProxyPorts
)

from .connection_optimizer import (
    ConnectionOptimizer,
    GeographicOptimizer,
    TimeoutCalculator,
    OptimizationResult
)

__all__ = [
    'DiscoveryMode',
    'ScanIntensity',
    'IPRangeScanner',
    'CloudProviderRanges',
    'ISPSubnetDiscoverer',
    'ScanConfig',
    'ScanResult',
    'PortDiscoveryEngine',
    'ProxyPortScanner',
    'PortScanResult',
    'CommonProxyPorts',
    'ConnectionOptimizer',
    'GeographicOptimizer',
    'TimeoutCalculator',
    'OptimizationResult'
]

# Version info
__version__ = "3.2.0-DISCOVERY"
__author__ = "ProxC Development Team"
__license__ = "MIT"

logger.info("Discovery system initialized successfully")