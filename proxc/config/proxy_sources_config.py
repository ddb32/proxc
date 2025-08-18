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
    
    def get_sources_by_profile(self, profile_name: str) -> Dict[str, Dict[str, Any]]:
        """Get sources that match a specific collection profile"""
        profile = self.get_profile(profile_name)
        if not profile:
            logger.warning(f"Profile '{profile_name}' not found")
            return {}
        
        # Expand source patterns from the profile
        expanded_sources = self.expand_source_patterns(profile.sources)
        
        # Get the actual source configurations
        all_sources = self.get_enabled_sources()
        profile_sources = {}
        
        for source_name in expanded_sources:
            if source_name in all_sources:
                source_config = all_sources[source_name]
                # Filter by quality threshold if specified
                if source_config.get('quality_score', 0) >= profile.quality_threshold:
                    profile_sources[source_name] = source_config
        
        return profile_sources
    
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


def load_proxy_sources(config_path: Optional[str] = None, use_new_structure: bool = True) -> Optional[ProxySourcesConfig]:
    """Load proxy sources configuration from YAML file(s)
    
    Args:
        config_path: Path to configuration directory or legacy file
        use_new_structure: If True, try to load from three-file structure first
    """
    
    if not HAS_YAML:
        logger.error("PyYAML is required for configuration loading. Install with: pip install PyYAML")
        return None
    
    # Determine config directory path
    if config_path is None:
        config_dir = Path(__file__).parent
    else:
        config_path = Path(config_path)
        if config_path.is_file():
            # Legacy single file mode
            return _load_legacy_configuration(config_path)
        else:
            config_dir = config_path
    
    # Try new three-file structure first
    if use_new_structure:
        result = _load_three_file_configuration(config_dir)
        if result is not None:
            return result
        
        logger.warning("Failed to load three-file configuration, trying legacy format")
    
    # Fallback to legacy single file
    legacy_path = config_dir / "proxy_sources.yaml"
    if legacy_path.exists():
        return _load_legacy_configuration(legacy_path)
    
    logger.error(f"No valid configuration found in {config_dir}")
    return None


def _load_three_file_configuration(config_dir: Path) -> Optional[ProxySourcesConfig]:
    """Load configuration from three separate files"""
    
    # Define file paths
    api_sources_path = config_dir / "api_sources.yaml"
    static_sources_path = config_dir / "static_sources.yaml"
    collection_config_path = config_dir / "collection_config.yaml"
    
    # Check that all required files exist
    missing_files = []
    for file_path in [api_sources_path, static_sources_path, collection_config_path]:
        if not file_path.exists():
            missing_files.append(file_path.name)
    
    if missing_files:
        logger.warning(f"Missing configuration files: {', '.join(missing_files)}")
        return None
    
    try:
        # Load all three configuration files
        api_config = _load_yaml_file(api_sources_path)
        static_config = _load_yaml_file(static_sources_path)
        collection_config = _load_yaml_file(collection_config_path)
        
        if not all([api_config, static_config, collection_config]):
            logger.error("One or more configuration files are empty or invalid")
            return None
        
        # Parse and merge source configurations
        merged_sources = _merge_source_configurations(api_config, static_config)
        
        # Extract collection profiles from collection config
        profiles = _parse_collection_profiles(collection_config.get('profiles', {}))
        
        # Create unified configuration object
        config = ProxySourcesConfig(
            version=collection_config.get('version', '1.2'),
            last_updated=collection_config.get('last_updated'),
            collection_defaults=collection_config.get('defaults', {}),
            rate_limiting=collection_config.get('rate_limiting', {}),
            quality_filters=collection_config.get('quality_filters', {}),
            schedules=collection_config.get('schedules', {}),
            free_sources=merged_sources.get('free', {}),
            premium_sources=merged_sources.get('premium', {}),
            custom_sources=merged_sources.get('custom', {}),
            profiles=profiles,
            health_monitoring=collection_config.get('health_monitoring', {}),
            advanced=collection_config.get('advanced', {})
        )
        
        # Validate merged configuration
        if not _validate_configuration(config):
            logger.error("Three-file configuration validation failed")
            return None
        
        logger.info(f"Successfully loaded three-file configuration from {config_dir}")
        return config
        
    except Exception as e:
        logger.error(f"Failed to load three-file configuration: {e}")
        return None


def _load_legacy_configuration(config_path: Path) -> Optional[ProxySourcesConfig]:
    """Load configuration from legacy single YAML file"""
    
    if not config_path.exists():
        logger.error(f"Legacy configuration file not found: {config_path}")
        return None
    
    try:
        raw_config = _load_yaml_file(config_path)
        
        if not raw_config:
            logger.error("Legacy configuration file is empty or invalid")
            return None
        
        # Extract main sections
        collection_config = raw_config.get('collection', {})
        proxy_sources = raw_config.get('proxy_sources', {})
        profiles_config = raw_config.get('profiles', {})
        health_config = raw_config.get('health_monitoring', {})
        advanced_config = raw_config.get('advanced', {})
        
        # Parse collection profiles
        profiles = _parse_collection_profiles(profiles_config)
        
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
            logger.error("Legacy configuration validation failed")
            return None
        
        logger.info(f"Successfully loaded legacy configuration from {config_path}")
        logger.warning("Consider migrating to three-file configuration structure for better maintainability")
        return config
        
    except Exception as e:
        logger.error(f"Failed to load legacy configuration: {e}")
        return None


def _merge_source_configurations(api_config: Dict[str, Any], static_config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Merge API and static source configurations into organized categories"""
    
    merged = {
        'free': {},
        'premium': {},
        'custom': {}
    }
    
    try:
        # Process API sources
        if api_config:
            # Free API sources
            free_apis = api_config.get('free_apis', {})
            if free_apis:
                merged['free'].update(free_apis)
                
            # Premium API sources
            premium_apis = api_config.get('premium_apis', {})
            if premium_apis:
                merged['premium'].update(premium_apis)
                
            # Custom API sources
            custom_apis = api_config.get('custom_apis', {})
            if custom_apis:
                merged['custom'].update(custom_apis)
        
        # Process static sources
        if static_config:
            # GitHub sources (typically free)
            github_sources = static_config.get('github_sources', {})
            if github_sources:
                merged['free'].update(github_sources)
                
            # Text file sources (typically free)
            text_sources = static_config.get('text_file_sources', {})
            if text_sources:
                merged['free'].update(text_sources)
                
            # HTML table sources (typically free)
            html_sources = static_config.get('html_table_sources', {})
            if html_sources:
                merged['free'].update(html_sources)
                
            # Custom static sources
            custom_static = static_config.get('custom_static_sources', {})
            if custom_static:
                merged['custom'].update(custom_static)
        
        logger.debug(f"Merged sources: free={len(merged['free'])}, premium={len(merged['premium'])}, custom={len(merged['custom'])}")
        return merged
        
    except Exception as e:
        logger.error(f"Failed to merge source configurations: {e}")
        return {'free': {}, 'premium': {}, 'custom': {}}


def _parse_collection_profiles(profiles_config: Dict[str, Any]) -> Dict[str, CollectionProfile]:
    """Parse collection profiles from configuration"""
    
    parsed_profiles = {}
    
    try:
        for profile_name, profile_data in profiles_config.items():
            if not isinstance(profile_data, dict):
                logger.warning(f"Invalid profile data for '{profile_name}': not a dictionary")
                continue
                
            try:
                profile = CollectionProfile(
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
                parsed_profiles[profile_name] = profile
                
            except Exception as e:
                logger.warning(f"Failed to parse profile '{profile_name}': {e}")
                continue
        
        logger.debug(f"Parsed {len(parsed_profiles)} collection profiles")
        return parsed_profiles
        
    except Exception as e:
        logger.error(f"Failed to parse collection profiles: {e}")
        return {}


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


def _process_commented_blocks(content: str) -> str:
    """Process comment-based enable/disable functionality in YAML configuration"""
    
    lines = content.split('\n')
    processed_lines = []
    
    for line in lines:
        stripped = line.strip()
        
        # Check if this is a commented configuration block
        if stripped.startswith('#') and (':' in stripped or '-' in stripped):
            # This might be a commented configuration property
            # Remove leading # and any following spaces
            uncommented = line.lstrip('#').lstrip()
            
            # Only uncomment if it looks like a YAML property
            if ':' in uncommented or (uncommented.strip().startswith('-') and ':' in uncommented):
                processed_lines.append(uncommented)
            else:
                processed_lines.append(line)
        else:
            processed_lines.append(line)
    
    return '\n'.join(processed_lines)


def _load_yaml_file(file_path: Path) -> Optional[Dict[str, Any]]:
    """Load and parse a YAML file with error handling and environment variable substitution"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            raw_content = f.read()
        
        # Process comment-based enable/disable before YAML parsing
        processed_yaml_content = _process_commented_blocks(raw_content)
        
        # Parse the processed YAML
        parsed_content = yaml.safe_load(processed_yaml_content)
        
        if not parsed_content:
            logger.warning(f"Configuration file is empty: {file_path}")
            return {}
        
        # Apply environment variable substitution
        processed_content = preprocess_config_with_env_vars(parsed_content)
        
        logger.debug(f"Successfully loaded YAML file: {file_path}")
        return processed_content
        
    except yaml.YAMLError as e:
        logger.error(f"YAML parsing error in {file_path}: {e}")
        return None
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {file_path}")
        return None
    except Exception as e:
        logger.error(f"Failed to load {file_path}: {e}")
        return None


def _process_commented_blocks(yaml_content: str) -> str:
    """Process comment-based enable/disable by detecting commented source blocks"""
    lines = yaml_content.split('\n')
    processed_lines = []
    
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped_line = line.strip()
        
        # Check if this might be a commented source block
        if stripped_line.startswith('#') and ':' in stripped_line and stripped_line.endswith(':'):
            # This looks like a commented source definition (e.g., "# source_name:")
            # Look ahead to see if this is a commented source block
            commented_block_lines = _extract_commented_block(lines, i)
            if commented_block_lines:
                # Skip the entire commented block
                logger.debug(f"Skipped commented source block: {stripped_line[1:].strip()}")
                i += len(commented_block_lines)
                continue
        
        # Not a commented source block, keep the line
        processed_lines.append(line)
        i += 1
    
    return '\n'.join(processed_lines)


def _extract_commented_block(lines: List[str], start_index: int) -> List[str]:
    """Extract a commented source block starting from the given index
    
    Returns the lines that make up the commented block, or empty list if not a block
    """
    if start_index >= len(lines):
        return []
    
    first_line = lines[start_index]
    first_line_stripped = first_line.strip()
    
    # Check if first line looks like a commented source definition
    if not (first_line_stripped.startswith('#') and first_line_stripped.endswith(':') and ':' in first_line_stripped):
        return []
    
    # Get the base indentation (position of # character)
    base_indent = first_line.find('#')
    
    block_lines = [first_line]  # Include the source definition line
    i = start_index + 1
    
    # Look for consecutive commented lines that form a block
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        
        # Empty line - might be part of block, include it
        if not stripped:
            block_lines.append(line)
            i += 1
            continue
        
        # Check if this is a commented line that's part of our block
        if stripped.startswith('#'):
            # Must have similar or greater indentation than the source line
            comment_pos = line.find('#')
            
            # If the comment position is at or after our base indent, it's likely part of the block
            if comment_pos >= base_indent:
                # Get content after the # to see if it looks like a YAML property
                content_after_hash = line[comment_pos + 1:].strip()
                
                # If it contains a colon or common YAML property, it's likely part of our block
                if content_after_hash and (':' in content_after_hash or 
                    content_after_hash.startswith(('name', 'url', 'type', 'enabled', 'description', 'quality_score'))):
                    block_lines.append(line)
                    i += 1
                    continue
                else:
                    # This might be an explanatory comment, include it
                    block_lines.append(line)
                    i += 1
                    continue
            else:
                # Comment at lower indentation level, probably not part of this block
                break
        else:
            # Non-commented line - end of commented block
            break
        
        i += 1
    
    # Validate that this looks like a legitimate source block
    if len(block_lines) < 2:  # Need at least source name + one property
        return []
    
    # Additional validation: check if block contains typical source properties
    block_text = '\n'.join(block_lines)
    # Look for property patterns that may have spaces after the #
    property_patterns = ['name:', 'url:', 'type:', 'enabled:', 'description:', 'quality_score:']
    
    for line in block_lines:
        if line.strip().startswith('#'):
            content_after_hash = line[line.find('#') + 1:].strip()
            if any(content_after_hash.startswith(prop) for prop in property_patterns):
                return block_lines
    
    return []


def _is_source_block_commented(source_name: str, source_config: Dict[str, Any]) -> bool:
    """Check if a source block was originally commented out
    
    This is a fallback check for sources that made it through YAML parsing
    but should be considered disabled due to commenting.
    """
    # This function serves as a backup - most commented blocks should be
    # filtered out during _process_commented_blocks()
    
    # Check for marker that indicates this was from a commented block
    if '_commented_block' in source_config:
        return source_config['_commented_block']
    
    return False


def _merge_source_configurations(api_config: Dict[str, Any], static_config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Merge API and static source configurations into unified structure"""
    merged_sources = {
        'free': {},
        'premium': {},
        'custom': {}
    }
    
    try:
        # Process API sources
        api_sources = api_config.get('free_apis', {})
        premium_apis = api_config.get('premium_apis', {})
        custom_apis = api_config.get('custom_apis', {})
        
        # Filter out commented sources and add to merged config
        merged_sources['free'].update(_filter_enabled_sources(api_sources, 'api'))
        merged_sources['premium'].update(_filter_enabled_sources(premium_apis, 'api'))
        merged_sources['custom'].update(_filter_enabled_sources(custom_apis, 'api'))
        
        # Process static sources
        github_sources = static_config.get('github_sources', {})
        text_sources = static_config.get('text_file_sources', {})
        html_sources = static_config.get('html_table_sources', {})
        js_sources = static_config.get('javascript_sources', {})
        custom_static = static_config.get('custom_static_sources', {})
        
        # Add static sources to free category (most are free)
        merged_sources['free'].update(_filter_enabled_sources(github_sources, 'static'))
        merged_sources['free'].update(_filter_enabled_sources(text_sources, 'static'))
        merged_sources['free'].update(_filter_enabled_sources(html_sources, 'static'))
        merged_sources['free'].update(_filter_enabled_sources(js_sources, 'static'))
        merged_sources['custom'].update(_filter_enabled_sources(custom_static, 'static'))
        
        logger.info(f"Merged sources: {len(merged_sources['free'])} free, {len(merged_sources['premium'])} premium, {len(merged_sources['custom'])} custom")
        return merged_sources
        
    except Exception as e:
        logger.error(f"Failed to merge source configurations: {e}")
        return {'free': {}, 'premium': {}, 'custom': {}}


def _filter_enabled_sources(sources: Dict[str, Any], source_category: str) -> Dict[str, Any]:
    """Filter out commented/disabled sources and add category metadata"""
    enabled_sources = {}
    
    for source_name, source_config in sources.items():
        if not isinstance(source_config, dict):
            continue
        
        # Check if source is enabled (not commented out and enabled=true or missing enabled flag)
        enabled = source_config.get('enabled', True)
        
        # Also check if this was originally a commented block
        if _is_source_block_commented(source_name, source_config):
            enabled = False
            logger.debug(f"Source {source_name} was commented out in configuration file")
        
        if enabled:
            # Add metadata to help with source identification
            source_config_copy = source_config.copy()
            source_config_copy['_source_category'] = source_category
            source_config_copy['_original_file'] = 'api_sources.yaml' if source_category == 'api' else 'static_sources.yaml'
            
            enabled_sources[source_name] = source_config_copy
            logger.debug(f"Enabled {source_category} source: {source_name}")
        else:
            logger.debug(f"Skipped disabled {source_category} source: {source_name}")
    
    return enabled_sources


def _parse_collection_profiles(profiles_config: Dict[str, Any]) -> Dict[str, CollectionProfile]:
    """Parse collection profiles from configuration data"""
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
            logger.debug(f"Parsed collection profile: {profile_name}")
        except Exception as e:
            logger.warning(f"Failed to parse profile '{profile_name}': {e}")
    
    return profiles


def validate_three_file_structure(config_dir: Path) -> Dict[str, Any]:
    """Validate the three-file configuration structure and return status"""
    validation_result = {
        'valid': False,
        'files_found': {},
        'files_missing': [],
        'errors': [],
        'warnings': [],
        'source_counts': {'api': 0, 'static': 0, 'total': 0}
    }
    
    # Check for required files
    required_files = {
        'api_sources.yaml': 'API-based proxy sources',
        'static_sources.yaml': 'Static URL proxy sources', 
        'collection_config.yaml': 'Global collection settings'
    }
    
    for filename, description in required_files.items():
        file_path = config_dir / filename
        if file_path.exists():
            validation_result['files_found'][filename] = description
            try:
                # Try to load and parse file
                config_data = _load_yaml_file(file_path)
                if config_data is None:
                    validation_result['errors'].append(f"Failed to parse {filename}")
                elif not config_data:
                    validation_result['warnings'].append(f"{filename} is empty")
            except Exception as e:
                validation_result['errors'].append(f"Error loading {filename}: {e}")
        else:
            validation_result['files_missing'].append(filename)
    
    # Count sources if files are present
    try:
        if 'api_sources.yaml' in validation_result['files_found']:
            api_config = _load_yaml_file(config_dir / 'api_sources.yaml')
            if api_config:
                api_count = len(api_config.get('free_apis', {})) + len(api_config.get('premium_apis', {})) + len(api_config.get('custom_apis', {}))
                validation_result['source_counts']['api'] = api_count
        
        if 'static_sources.yaml' in validation_result['files_found']:
            static_config = _load_yaml_file(config_dir / 'static_sources.yaml')
            if static_config:
                static_count = (len(static_config.get('github_sources', {})) + 
                              len(static_config.get('text_file_sources', {})) + 
                              len(static_config.get('html_table_sources', {})) + 
                              len(static_config.get('javascript_sources', {})) + 
                              len(static_config.get('custom_static_sources', {})))
                validation_result['source_counts']['static'] = static_count
        
        validation_result['source_counts']['total'] = validation_result['source_counts']['api'] + validation_result['source_counts']['static']
        
    except Exception as e:
        validation_result['errors'].append(f"Error counting sources: {e}")
    
    # Determine overall validity
    validation_result['valid'] = (
        len(validation_result['files_missing']) == 0 and 
        len(validation_result['errors']) == 0 and
        validation_result['source_counts']['total'] > 0
    )
    
    return validation_result


def validate_cross_file_configuration(config_dir: Path) -> Dict[str, Any]:
    """Validate cross-file consistency and detect conflicts
    
    This function performs comprehensive validation across all three configuration files
    to detect conflicts, duplicates, and inconsistencies.
    """
    validation_result = {
        'valid': True,
        'errors': [],
        'warnings': [],
        'conflicts': {
            'duplicate_source_names': [],
            'conflicting_urls': [],
            'inconsistent_settings': []
        },
        'statistics': {
            'total_sources': 0,
            'enabled_sources': 0,
            'api_sources': 0,
            'static_sources': 0
        },
        'recommendations': []
    }
    
    try:
        # Load all three configuration files
        api_config = _load_yaml_file(config_dir / 'api_sources.yaml')
        static_config = _load_yaml_file(config_dir / 'static_sources.yaml')
        collection_config = _load_yaml_file(config_dir / 'collection_config.yaml')
        
        if not all([api_config, static_config, collection_config]):
            validation_result['valid'] = False
            validation_result['errors'].append("One or more configuration files could not be loaded")
            return validation_result
        
        # Collect all sources from all files
        all_sources = {}
        source_locations = {}  # Track where each source is defined
        
        # Process API sources
        if api_config:
            for section_name in ['free_apis', 'premium_apis', 'custom_apis']:
                section = api_config.get(section_name, {})
                if section and isinstance(section, dict):
                    for source_name, source_config in section.items():
                        if isinstance(source_config, dict):
                            full_name = f"api.{source_name}"
                            all_sources[full_name] = source_config
                            source_locations[full_name] = f"api_sources.yaml:{section_name}"
                            validation_result['statistics']['api_sources'] += 1
        
        # Process static sources  
        if static_config:
            for section_name in ['github_sources', 'text_file_sources', 'html_table_sources', 
                               'javascript_sources', 'custom_static_sources']:
                section = static_config.get(section_name, {})
                if section and isinstance(section, dict):
                    for source_name, source_config in section.items():
                        if isinstance(source_config, dict):
                            full_name = f"static.{source_name}"
                            all_sources[full_name] = source_config
                            source_locations[full_name] = f"static_sources.yaml:{section_name}"
                            validation_result['statistics']['static_sources'] += 1
        
        validation_result['statistics']['total_sources'] = len(all_sources)
        validation_result['statistics']['enabled_sources'] = len([
            s for s in all_sources.values() if s.get('enabled', True)
        ])
        
        # Check for duplicate source names (without prefix)
        base_names = {}
        for full_name in all_sources.keys():
            base_name = full_name.split('.', 1)[1]  # Remove api./static. prefix
            if base_name in base_names:
                validation_result['conflicts']['duplicate_source_names'].append({
                    'source_name': base_name,
                    'locations': [base_names[base_name], source_locations[full_name]]
                })
                validation_result['warnings'].append(
                    f"Duplicate source name '{base_name}' found in {base_names[base_name]} and {source_locations[full_name]}"
                )
            else:
                base_names[base_name] = source_locations[full_name]
        
        # Check for conflicting URLs
        url_to_sources = {}
        for full_name, source_config in all_sources.items():
            url = source_config.get('url')
            if url:
                if url in url_to_sources:
                    validation_result['conflicts']['conflicting_urls'].append({
                        'url': url,
                        'sources': [url_to_sources[url], full_name]
                    })
                    validation_result['warnings'].append(
                        f"URL '{url}' is used by multiple sources: {url_to_sources[url]} and {full_name}"
                    )
                else:
                    url_to_sources[url] = full_name
        
        # Check for inconsistent settings
        _validate_source_consistency(all_sources, validation_result)
        
        # Check for profile reference validity
        _validate_profile_references(collection_config, all_sources, validation_result)
        
        # Generate recommendations
        _generate_configuration_recommendations(all_sources, collection_config, validation_result)
        
        # Set overall validity
        validation_result['valid'] = len(validation_result['errors']) == 0
        
        logger.info(f"Cross-file validation completed: {len(validation_result['errors'])} errors, {len(validation_result['warnings'])} warnings")
        
    except Exception as e:
        validation_result['valid'] = False
        validation_result['errors'].append(f"Cross-file validation failed: {e}")
        logger.error(f"Cross-file validation error: {e}")
    
    return validation_result


def _validate_source_consistency(all_sources: Dict[str, Dict[str, Any]], validation_result: Dict[str, Any]):
    """Validate consistency of source configurations"""
    
    # Check for sources with same name but different types
    type_by_base_name = {}
    for full_name, source_config in all_sources.items():
        base_name = full_name.split('.', 1)[1]
        source_type = source_config.get('type', 'unknown')
        
        if base_name in type_by_base_name:
            if type_by_base_name[base_name] != source_type:
                validation_result['conflicts']['inconsistent_settings'].append({
                    'issue': 'conflicting_types',
                    'source_name': base_name,
                    'types': [type_by_base_name[base_name], source_type]
                })
                validation_result['warnings'].append(
                    f"Source '{base_name}' has conflicting types: {type_by_base_name[base_name]} vs {source_type}"
                )
        else:
            type_by_base_name[base_name] = source_type
    
    # Check for suspicious quality scores
    for full_name, source_config in all_sources.items():
        quality_score = source_config.get('quality_score', 5)
        
        if not isinstance(quality_score, int) or not (1 <= quality_score <= 10):
            validation_result['warnings'].append(
                f"Source '{full_name}' has invalid quality score: {quality_score} (should be 1-10)"
            )
        
        # Warn about very low quality scores for enabled sources
        if source_config.get('enabled', True) and quality_score < 3:
            validation_result['warnings'].append(
                f"Source '{full_name}' is enabled but has very low quality score: {quality_score}"
            )


def _validate_profile_references(collection_config: Dict[str, Any], all_sources: Dict[str, Dict[str, Any]], 
                                 validation_result: Dict[str, Any]):
    """Validate that profile source references are valid"""
    
    if not collection_config:
        return
        
    profiles = collection_config.get('profiles', {})
    if not profiles:
        return
        
    available_source_patterns = set()
    
    # Build available source patterns
    for full_name in all_sources.keys():
        if full_name.startswith('api.'):
            base_name = full_name[4:]  # Remove 'api.' prefix
            available_source_patterns.add(f"free.{base_name}")
            available_source_patterns.add(f"premium.{base_name}")
            available_source_patterns.add(f"custom.{base_name}")
        elif full_name.startswith('static.'):
            base_name = full_name[7:]  # Remove 'static.' prefix  
            available_source_patterns.add(f"free.{base_name}")
            available_source_patterns.add(f"custom.{base_name}")
    
    # Add wildcard patterns
    available_source_patterns.add("free.*")
    available_source_patterns.add("premium.*")
    available_source_patterns.add("custom.*")
    
    for profile_name, profile_config in profiles.items():
        if isinstance(profile_config, dict):
            sources = profile_config.get('sources', [])
            
            for source_ref in sources:
                if source_ref not in available_source_patterns:
                    # Check if it's a valid specific source reference
                    found_match = False
                    for pattern in available_source_patterns:
                        if pattern.endswith('.*'):
                            prefix = pattern[:-1]  # Remove '*'
                            if source_ref.startswith(prefix):
                                found_match = True
                                break
                        elif pattern == source_ref:
                            found_match = True
                            break
                    
                    if not found_match:
                        validation_result['warnings'].append(
                            f"Profile '{profile_name}' references unknown source: '{source_ref}'"
                        )


def _generate_configuration_recommendations(all_sources: Dict[str, Dict[str, Any]], 
                                           collection_config: Dict[str, Any], 
                                           validation_result: Dict[str, Any]):
    """Generate recommendations for improving configuration"""
    
    enabled_sources = [s for s in all_sources.values() if s.get('enabled', True)]
    disabled_sources = [s for s in all_sources.values() if not s.get('enabled', True)]
    
    # Recommend enabling high-quality sources
    high_quality_disabled = [
        s for s in disabled_sources 
        if s.get('quality_score', 5) >= 7
    ]
    
    if high_quality_disabled:
        validation_result['recommendations'].append(
            f"Consider enabling {len(high_quality_disabled)} high-quality disabled sources"
        )
    
    # Recommend disabling low-quality sources
    low_quality_enabled = [
        s for s in enabled_sources 
        if s.get('quality_score', 5) <= 3
    ]
    
    if low_quality_enabled:
        validation_result['recommendations'].append(
            f"Consider disabling {len(low_quality_enabled)} low-quality enabled sources"
        )
    
    # Check source distribution
    api_count = len([s for s in all_sources.keys() if s.startswith('api.')])
    static_count = len([s for s in all_sources.keys() if s.startswith('static.')])
    
    if api_count == 0:
        validation_result['recommendations'].append(
            "No API sources configured - consider adding API-based sources for better coverage"
        )
    
    if static_count == 0:
        validation_result['recommendations'].append(
            "No static sources configured - consider adding GitHub or text file sources"
        )
    
    # Check profile coverage
    profiles = collection_config.get('profiles', {})
    if len(profiles) < 3:
        validation_result['recommendations'].append(
            "Consider creating more collection profiles for different use cases"
        )


def test_comment_parsing(file_path: str) -> Dict[str, Any]:
    """Test and debug comment-based parsing on a configuration file
    
    This function helps debug comment parsing by showing what gets filtered out
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()
        
        # Process comments
        processed_content = _process_commented_blocks(original_content)
        
        # Parse both versions
        original_parsed = yaml.safe_load(original_content) or {}
        processed_parsed = yaml.safe_load(processed_content) or {}
        
        # Analyze differences
        original_sources = set()
        processed_sources = set()
        
        # Count sources in original
        for section_name, section in original_parsed.items():
            if isinstance(section, dict):
                for source_name in section.keys():
                    if isinstance(section.get(source_name), dict):
                        original_sources.add(f"{section_name}.{source_name}")
        
        # Count sources in processed
        for section_name, section in processed_parsed.items():
            if isinstance(section, dict):
                for source_name in section.keys():
                    if isinstance(section.get(source_name), dict):
                        processed_sources.add(f"{section_name}.{source_name}")
        
        filtered_out = original_sources - processed_sources
        
        return {
            'original_content_lines': len(original_content.split('\n')),
            'processed_content_lines': len(processed_content.split('\n')),
            'original_sources_count': len(original_sources),
            'processed_sources_count': len(processed_sources),
            'filtered_out_sources': list(filtered_out),
            'filtered_out_count': len(filtered_out),
            'parsing_successful': True
        }
        
    except Exception as e:
        return {
            'parsing_successful': False,
            'error': str(e)
        }


def create_test_commented_config(output_path: str) -> bool:
    """Create a test configuration file with commented sources for testing"""
    test_config = '''# Test Configuration with Commented Sources
version: "1.2"
file_type: "test_config"

# Active API sources
free_apis:
  
  # Active source
  test_active_api:
    name: "Test Active API"
    url: "https://api.example.com/proxies"
    type: "api"
    enabled: true
    quality_score: 5

  # Commented out source block - should be filtered
  # test_commented_api:
  #   name: "Test Commented API"
  #   url: "https://api.disabled.com/proxies"
  #   type: "api"
  #   enabled: true
  #   quality_score: 3

# Static sources section
github_sources:

  active_github_source:
    name: "Active GitHub Source"
    url: "https://raw.githubusercontent.com/example/list.txt"
    type: "text_list"
    enabled: true

  # Another commented source
  # disabled_github_source:
  #   name: "Disabled GitHub Source"
  #   url: "https://raw.githubusercontent.com/disabled/list.txt"
  #   type: "text_list"
  #   enabled: true
  #   notes: "This source is commented out"

# Source with explicit disabled flag
custom_sources:
  
  explicitly_disabled:
    name: "Explicitly Disabled"
    url: "https://example.com/disabled"
    type: "text_list"
    enabled: false  # Disabled via flag, not comments

  active_custom:
    name: "Active Custom"
    url: "https://example.com/active"
    type: "text_list"
    enabled: true
'''

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(test_config)
        
        logger.info(f"Test configuration with commented sources created: {output_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create test config: {e}")
        return False


def validate_cross_file_configuration(config_dir: Path) -> Dict[str, Any]:
    """Validate consistency across the three configuration files"""
    
    result = {
        'valid': True,
        'errors': [],
        'warnings': [],
        'conflicts': {
            'duplicate_source_names': [],
            'conflicting_urls': [],
            'inconsistent_settings': []
        },
        'statistics': {
            'total_sources': 0,
            'api_sources': 0,
            'static_sources': 0,
            'enabled_sources': 0
        },
        'recommendations': []
    }
    
    try:
        # Load the three configuration files
        api_sources_path = config_dir / "api_sources.yaml"
        static_sources_path = config_dir / "static_sources.yaml"
        collection_config_path = config_dir / "collection_config.yaml"
        
        api_config = None
        static_config = None
        collection_config = None
        
        if api_sources_path.exists():
            api_config = _load_yaml_file(api_sources_path)
        if static_sources_path.exists():
            static_config = _load_yaml_file(static_sources_path)
        if collection_config_path.exists():
            collection_config = _load_yaml_file(collection_config_path)
        
        # Check that all files loaded successfully
        if not api_config:
            result['errors'].append("Failed to load api_sources.yaml")
            result['valid'] = False
        if not static_config:
            result['errors'].append("Failed to load static_sources.yaml")
            result['valid'] = False
        if not collection_config:
            result['errors'].append("Failed to load collection_config.yaml")
            result['valid'] = False
        
        if not result['valid']:
            return result
        
        # Collect all sources
        all_sources = {}
        all_urls = {}
        
        # Process API sources
        if api_config:
            for category in ['free_apis', 'premium_apis', 'custom_apis']:
                category_sources = api_config.get(category, {})
                if category_sources:
                    for source_name, source_config in category_sources.items():
                        if source_name in all_sources:
                            result['conflicts']['duplicate_source_names'].append({
                                'source_name': source_name,
                                'locations': [all_sources[source_name]['location'], f'api_sources.{category}']
                            })
                        
                        all_sources[source_name] = {
                            'config': source_config,
                            'location': f'api_sources.{category}',
                            'type': 'api'
                        }
                        
                        # Check URL conflicts
                        url = source_config.get('url', '')
                        if url:
                            if url in all_urls:
                                result['conflicts']['conflicting_urls'].append({
                                    'url': url,
                                    'sources': [all_urls[url], source_name]
                                })
                            else:
                                all_urls[url] = source_name
                        
                        result['statistics']['api_sources'] += 1
                        if source_config.get('enabled', True):
                            result['statistics']['enabled_sources'] += 1
        
        # Process static sources
        if static_config:
            for category in ['github_sources', 'text_file_sources', 'html_table_sources', 'custom_static_sources']:
                category_sources = static_config.get(category, {})
                if category_sources:
                    for source_name, source_config in category_sources.items():
                        if source_name in all_sources:
                            result['conflicts']['duplicate_source_names'].append({
                                'source_name': source_name,
                                'locations': [all_sources[source_name]['location'], f'static_sources.{category}']
                            })
                        
                        all_sources[source_name] = {
                            'config': source_config,
                            'location': f'static_sources.{category}',
                            'type': 'static'
                        }
                        
                        # Check URL conflicts
                        url = source_config.get('url', '')
                        if url:
                            if url in all_urls:
                                result['conflicts']['conflicting_urls'].append({
                                    'url': url,
                                    'sources': [all_urls[url], source_name]
                                })
                            else:
                                all_urls[url] = source_name
                        
                        result['statistics']['static_sources'] += 1
                        if source_config.get('enabled', True):
                            result['statistics']['enabled_sources'] += 1
        
        result['statistics']['total_sources'] = len(all_sources)
        
        # Check for configuration inconsistencies
        if result['statistics']['total_sources'] == 0:
            result['warnings'].append("No proxy sources found in configuration")
        
        if result['statistics']['enabled_sources'] == 0:
            result['warnings'].append("No proxy sources are enabled")
        
        # Check profiles reference valid sources
        profiles = collection_config.get('profiles', {})
        for profile_name, profile_config in profiles.items():
            sources = profile_config.get('sources', [])
            for source_pattern in sources:
                if source_pattern.endswith('.*'):
                    # Wildcard pattern - check if any sources match
                    prefix = source_pattern[:-2]
                    matching = [name for name in all_sources.keys() if name.startswith(prefix)]
                    if not matching:
                        result['warnings'].append(f"Profile '{profile_name}' references pattern '{source_pattern}' but no sources match")
                elif source_pattern not in all_sources:
                    result['warnings'].append(f"Profile '{profile_name}' references unknown source '{source_pattern}'")
        
        # Generate recommendations
        if result['statistics']['total_sources'] > 0:
            enabled_ratio = result['statistics']['enabled_sources'] / result['statistics']['total_sources']
            if enabled_ratio < 0.3:
                result['recommendations'].append("Consider enabling more proxy sources for better coverage")
        
        if result['conflicts']['duplicate_source_names']:
            result['recommendations'].append("Resolve duplicate source names to avoid conflicts")
        
        if result['conflicts']['conflicting_urls']:
            result['recommendations'].append("Review conflicting URLs - they may indicate duplicate sources")
        
        # Final validation
        total_conflicts = sum(len(v) for v in result['conflicts'].values())
        if total_conflicts > 0:
            result['valid'] = False
        
        logger.info(f"Cross-file validation completed: {result['statistics']['total_sources']} sources, {total_conflicts} conflicts")
        
    except Exception as e:
        result['errors'].append(f"Cross-file validation failed: {e}")
        result['valid'] = False
        logger.error(f"Cross-file validation error: {e}")
    
    return result