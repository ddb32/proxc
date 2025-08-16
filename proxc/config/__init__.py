"""Configuration Management for ProxC

This module provides configuration management capabilities including:
- Dynamic source loading from YAML files
- Configuration validation and error handling
- Hot-reload configuration changes
- Source registry management
"""

from .proxy_sources_config import ProxySourcesConfig, load_proxy_sources
from .source_registry import SourceRegistry

__all__ = [
    'ProxySourcesConfig',
    'load_proxy_sources', 
    'SourceRegistry'
]