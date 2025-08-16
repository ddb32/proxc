"""Proxy Sources Configuration Loader

This module provides configuration loading and management for proxy sources.
It handles YAML parsing, validation, and provides a clean interface for
accessing source configurations.
"""

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = logging.getLogger(__name__)


@dataclass
class CollectionProfile:
    """Configuration profile for proxy collection"""
    name: str
    description: str
    max_duration: int
    max_proxies: int
    sources: List[str]
    quality_threshold: int = 5
    concurrent_sources: int = 3
    include_experimental: bool = False
    require_validation: bool = False
    geographic_filters: Optional[Dict[str, List[str]]] = None


@dataclass
class ProxySourcesConfig:
    """Main configuration class for proxy sources"""
    version: str = "1.0"
    last_updated: Optional[str] = None
    
    # Collection settings
    collection_defaults: Dict[str, Any] = None
    rate_limiting: Dict[str, Any] = None
    quality_filters: Dict[str, Any] = None
    schedules: Dict[str, Any] = None
    
    # Source definitions
    free_sources: Dict[str, Dict[str, Any]] = None
    premium_sources: Dict[str, Dict[str, Any]] = None
    custom_sources: Dict[str, Dict[str, Any]] = None
    
    # Collection profiles
    profiles: Dict[str, CollectionProfile] = None
    
    # Health monitoring
    health_monitoring: Dict[str, Any] = None
    
    # Advanced settings
    advanced: Dict[str, Any] = None
    
    def __post_init__(self):
        # Initialize empty dictionaries if None
        if self.collection_defaults is None:
            self.collection_defaults = {}
        if self.rate_limiting is None:
            self.rate_limiting = {}
        if self.quality_filters is None:
            self.quality_filters = {}
        if self.schedules is None:
            self.schedules = {}
        if self.free_sources is None:
            self.free_sources = {}
        if self.premium_sources is None:
            self.premium_sources = {}
        if self.custom_sources is None:
            self.custom_sources = {}
        if self.profiles is None:
            self.profiles = {}
        if self.health_monitoring is None:
            self.health_monitoring = {}
        if self.advanced is None:
            self.advanced = {}
    
    def get_all_sources(self) -> Dict[str, Dict[str, Any]]:
        """Get all sources from all categories"""
        all_sources = {}
        
        # Add sources with category prefixes
        for name, config in self.free_sources.items():
            all_sources[f"free.{name}"] = config
        
        for name, config in self.premium_sources.items():
            all_sources[f"premium.{name}"] = config
            
        for name, config in self.custom_sources.items():
            all_sources[f"custom.{name}"] = config
        
        return all_sources
    
    def get_enabled_sources(self) -> Dict[str, Dict[str, Any]]:
        """Get only enabled sources"""
        enabled = {}
        
        for name, config in self.get_all_sources().items():
            if config.get('enabled', False):
                enabled[name] = config
        
        return enabled
    
    def get_sources_by_category(self, category: str) -> Dict[str, Dict[str, Any]]:
        """Get sources from a specific category"""
        if category == "free":
            return self.free_sources
        elif category == "premium":
            return self.premium_sources
        elif category == "custom":
            return self.custom_sources
        else:
            return {}
    
    def get_sources_by_quality(self, min_quality: int) -> Dict[str, Dict[str, Any]]:
        """Get sources with minimum quality score"""
        filtered = {}
        
        for name, config in self.get_enabled_sources().items():
            if config.get('quality_score', 0) >= min_quality:
                filtered[name] = config
        
        return filtered
    
    def get_sources_by_protocol(self, protocol: str) -> Dict[str, Dict[str, Any]]:
        """Get sources that support a specific protocol"""
        filtered = {}
        
        for name, config in self.get_enabled_sources().items():
            supported_protocols = config.get('supports_protocols', ['http'])
            if protocol.lower() in [p.lower() for p in supported_protocols]:
                filtered[name] = config
        
        return filtered
    
    def get_profile(self, profile_name: str) -> Optional[CollectionProfile]:
        """Get a collection profile by name"""
        return self.profiles.get(profile_name)
    
    def get_default_rate_limit(self) -> float:
        """Get default rate limit"""
        return self.rate_limiting.get('default_delay', 2.0)
    
    def get_health_monitoring_config(self) -> Dict[str, Any]:
        """Get health monitoring configuration"""
        return self.health_monitoring
    
    def is_source_enabled(self, source_name: str) -> bool:
        """Check if a specific source is enabled"""
        all_sources = self.get_all_sources()
        if source_name in all_sources:
            return all_sources[source_name].get('enabled', False)
        return False
    
    def expand_source_patterns(self, source_patterns: List[str]) -> List[str]:
        """Expand source patterns like 'free.*' to actual source names"""
        expanded = []
        all_sources = self.get_enabled_sources()
        
        for pattern in source_patterns:
            if pattern.endswith('.*'):
                # Wildcard pattern
                prefix = pattern[:-2]  # Remove '.*'
                matching = [name for name in all_sources.keys() if name.startswith(prefix + '.')]
                expanded.extend(matching)
            elif pattern in all_sources:
                # Exact match
                expanded.append(pattern)
            else:
                logger.warning(f"Source pattern '{pattern}' did not match any sources")
        
        return list(set(expanded))  # Remove duplicates


def load_proxy_sources(config_path: Optional[str] = None) -> Optional[ProxySourcesConfig]:
    """Load proxy sources configuration from YAML file"""
    
    if not HAS_YAML:
        logger.error("PyYAML is required for configuration loading. Install with: pip install PyYAML")
        return None
    
    # Determine config file path
    if config_path is None:
        config_path = Path(__file__).parent / "proxy_sources.yaml"
    else:
        config_path = Path(config_path)
    
    if not config_path.exists():
        logger.error(f"Configuration file not found: {config_path}")
        return None
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            raw_config = yaml.safe_load(f)
        
        if not raw_config:
            logger.error("Configuration file is empty or invalid")
            return None
        
        # Extract main sections
        collection_config = raw_config.get('collection', {})
        proxy_sources = raw_config.get('proxy_sources', {})
        profiles_config = raw_config.get('profiles', {})
        health_config = raw_config.get('health_monitoring', {})
        advanced_config = raw_config.get('advanced', {})
        
        # Parse collection profiles
        profiles = {}
        for profile_name, profile_data in profiles_config.items():
            try:
                profiles[profile_name] = CollectionProfile(
                    name=profile_data.get('name', profile_name),
                    description=profile_data.get('description', ''),
                    max_duration=profile_data.get('max_duration', 600),
                    max_proxies=profile_data.get('max_proxies', 1000),
                    sources=profile_data.get('sources', []),
                    quality_threshold=profile_data.get('quality_threshold', 5),
                    concurrent_sources=profile_data.get('concurrent_sources', 3),
                    include_experimental=profile_data.get('include_experimental', False),
                    require_validation=profile_data.get('require_validation', False),
                    geographic_filters=profile_data.get('geographic_filters')
                )
            except Exception as e:
                logger.warning(f"Failed to parse profile '{profile_name}': {e}")
        
        # Create configuration object
        config = ProxySourcesConfig(
            version=raw_config.get('version', '1.0'),
            last_updated=raw_config.get('last_updated'),
            collection_defaults=collection_config.get('defaults', {}),
            rate_limiting=collection_config.get('rate_limiting', {}),
            quality_filters=collection_config.get('quality_filters', {}),
            schedules=collection_config.get('schedules', {}),
            free_sources=proxy_sources.get('free', {}),
            premium_sources=proxy_sources.get('premium', {}),
            custom_sources=proxy_sources.get('custom', {}),
            profiles=profiles,
            health_monitoring=health_config,
            advanced=advanced_config
        )
        
        # Validate configuration
        if not _validate_configuration(config):
            logger.error("Configuration validation failed")
            return None
        
        logger.info(f"Successfully loaded configuration from {config_path}")
        return config
        
    except yaml.YAMLError as e:
        logger.error(f"YAML parsing error: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return None


def _validate_configuration(config: ProxySourcesConfig) -> bool:
    """Validate configuration for common issues"""
    
    try:
        # Check that we have at least some sources
        total_sources = len(config.free_sources) + len(config.premium_sources) + len(config.custom_sources)
        if total_sources == 0:
            logger.warning("No proxy sources defined in configuration")
        
        # Check enabled sources
        enabled_count = len(config.get_enabled_sources())
        if enabled_count == 0:
            logger.warning("No proxy sources are enabled")
        
        # Validate source configurations
        all_sources = config.get_all_sources()
        for source_name, source_config in all_sources.items():
            if not _validate_source_config(source_name, source_config):
                logger.warning(f"Source '{source_name}' has configuration issues")
        
        # Validate profiles
        for profile_name, profile in config.profiles.items():
            if not profile.sources:
                logger.warning(f"Profile '{profile_name}' has no sources defined")
        
        logger.info(f"Configuration validation completed: {total_sources} total, {enabled_count} enabled")
        return True
        
    except Exception as e:
        logger.error(f"Configuration validation error: {e}")
        return False


def _validate_source_config(source_name: str, source_config: Dict[str, Any]) -> bool:
    """Validate individual source configuration"""
    
    required_fields = ['url', 'type']
    for field in required_fields:
        if field not in source_config or not source_config[field]:
            logger.warning(f"Source '{source_name}' missing required field: {field}")
            return False
    
    # Validate source type
    valid_types = ['api', 'html_table', 'text_list', 'multi_source']
    source_type = source_config.get('type')
    if source_type not in valid_types:
        logger.warning(f"Source '{source_name}' has invalid type: {source_type}")
        return False
    
    # Validate rate limit
    rate_limit = source_config.get('rate_limit', 2.0)
    if not isinstance(rate_limit, (int, float)) or rate_limit < 0:
        logger.warning(f"Source '{source_name}' has invalid rate_limit: {rate_limit}")
        return False
    
    # Validate quality score
    quality_score = source_config.get('quality_score', 5)
    if not isinstance(quality_score, int) or not (1 <= quality_score <= 10):
        logger.warning(f"Source '{source_name}' has invalid quality_score: {quality_score}")
        return False
    
    # Validate multi-source URLs
    if source_type == 'multi_source':
        urls = source_config.get('urls', [])
        if not urls or not isinstance(urls, list):
            logger.warning(f"Multi-source '{source_name}' has no URLs defined")
            return False
    
    return True


def get_default_config_path() -> Path:
    """Get the default configuration file path"""
    return Path(__file__).parent / "proxy_sources.yaml"


def create_sample_config(output_path: str) -> bool:
    """Create a sample configuration file"""
    if not HAS_YAML:
        logger.error("PyYAML is required for config creation")
        return False
    
    sample_config = {
        'version': '1.0',
        'last_updated': datetime.utcnow().isoformat(),
        'collection': {
            'defaults': {
                'timeout': 30,
                'max_retries': 3,
                'user_agent_rotation': True
            },
            'rate_limiting': {
                'default_delay': 2.0,
                'jitter_range': [0.1, 0.5]
            }
        },
        'proxy_sources': {
            'free': {
                'example_source': {
                    'enabled': False,
                    'name': 'Example Source',
                    'description': 'Example proxy source',
                    'url': 'https://example.com/proxies',
                    'type': 'text_list',
                    'quality_score': 5,
                    'rate_limit': 2.0,
                    'timeout': 30,
                    'max_proxies': 1000
                }
            }
        },
        'profiles': {
            'quick_scan': {
                'name': 'Quick Scan',
                'description': 'Fast collection for immediate needs',
                'max_duration': 300,
                'max_proxies': 500,
                'sources': ['free.example_source'],
                'quality_threshold': 6
            }
        }
    }
    
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(sample_config, f, default_flow_style=False, indent=2)
        
        logger.info(f"Sample configuration created: {output_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create sample config: {e}")
        return False


# Environment variable substitution for sensitive values
def _substitute_env_vars(value: str) -> str:
    """Substitute environment variables in configuration values"""
    if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
        env_var = value[2:-1]  # Remove ${ and }
        return os.environ.get(env_var, value)
    return value


def preprocess_config_with_env_vars(config_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively substitute environment variables in configuration"""
    if isinstance(config_dict, dict):
        return {
            key: preprocess_config_with_env_vars(value) 
            for key, value in config_dict.items()
        }
    elif isinstance(config_dict, list):
        return [preprocess_config_with_env_vars(item) for item in config_dict]
    elif isinstance(config_dict, str):
        return _substitute_env_vars(config_dict)
    else:
        return config_dict