"""Proxy Core Configuration - Simple Configuration Management"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict


# ===============================================================================
# CONFIGURATION DATA CLASS
# ===============================================================================

@dataclass
class ProxyConfig:
    """Main configuration settings"""
    
    # Database settings
    database_url: str = "sqlite:///proxies.db"
    database_pool_size: int = 5
    database_timeout: int = 30
    
    # Proxy validation settings
    validation_timeout: int = 10
    validation_retries: int = 3
    max_concurrent_validations: int = 50
    
    # Fetching settings
    fetch_timeout: int = 30
    fetch_retries: int = 2
    max_proxies_per_source: int = 1000
    rate_limit_delay: float = 1.0
    
    # Security settings
    enable_ssl_verification: bool = True
    security_level: str = "medium"
    anonymity_required: str = "anonymous"
    
    # Cache settings
    cache_enabled: bool = True
    cache_ttl_hours: int = 24
    cache_max_size: int = 10000
    
    # Export settings
    default_export_format: str = "json"
    export_include_metrics: bool = True
    export_include_geo: bool = True
    
    # Logging settings
    log_level: str = "INFO"
    log_file: str = "proxc.log"
    enable_file_logging: bool = True
    
    # CLI behavior settings
    verbose: bool = False
    quiet: bool = False
    silent: bool = False
    
    # Default CLI parameters
    default_threads: int = 20
    default_timeout: int = 10000
    default_count: int = 100
    default_rate_limit: float = 1.0
    
    # Advanced settings
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    enable_geolocation: bool = True
    enable_threat_check: bool = True


# ===============================================================================
# CONFIGURATION MANAGER
# ===============================================================================

class ConfigManager:
    """Simple and efficient configuration manager"""
    
    def __init__(self, config_path: Optional[str] = None, cli_overrides: Optional[Dict[str, Any]] = None):
        self.config_path = config_path or self._get_default_config_path()
        self.config = ProxyConfig()
        self.cli_overrides = cli_overrides or {}
        self._load_config()
    
    def _get_default_config_path(self) -> str:
        """Get default configuration file path with priority order"""
        home_dir = Path.home()
        
        # Priority order for configuration locations
        config_locations = [
            home_dir / ".proxc" / "config.yaml",    # New preferred location
            home_dir / ".proxyhunter" / "config.yaml",   # Legacy location
        ]
        
        # Check if any existing config files exist
        for config_path in config_locations:
            if config_path.exists():
                return str(config_path)
        
        # If no config exists, create in the preferred new location
        preferred_config = config_locations[0]
        preferred_config.parent.mkdir(exist_ok=True)
        return str(preferred_config)
    
    def _load_config(self):
        """Load configuration from file and apply CLI overrides"""
        # Load from file first
        if not os.path.exists(self.config_path):
            self._create_default_config()
        else:
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    if self.config_path.endswith('.json'):
                        data = json.load(f)
                    else:
                        data = yaml.safe_load(f) or {}
                
                # Update config with loaded values
                for key, value in data.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                        
            except Exception as e:
                print(f"Warning: Failed to load config from {self.config_path}: {e}")
                print("Using default configuration.")
        
        # Apply CLI overrides (highest priority)
        self._apply_cli_overrides()
    
    def _apply_cli_overrides(self):
        """Apply CLI parameter overrides to configuration"""
        for key, value in self.cli_overrides.items():
            if hasattr(self.config, key) and value is not None:
                setattr(self.config, key, value)
    
    def _create_default_config(self):
        """Create default configuration file"""
        try:
            config_data = asdict(self.config)
            
            # Add comments for YAML
            yaml_content = self._generate_yaml_with_comments(config_data)
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                f.write(yaml_content)
                
            print(f"Created default configuration at: {self.config_path}")
            
        except Exception as e:
            print(f"Warning: Failed to create config file: {e}")
    
    def _generate_yaml_with_comments(self, data: Dict) -> str:
        """Generate YAML with helpful comments"""
        return f"""# ProxC Configuration File
# Generated automatically with default values

# Database Configuration
database_url: "{data['database_url']}"          # SQLite database path
database_pool_size: {data['database_pool_size']}                    # Connection pool size
database_timeout: {data['database_timeout']}                      # Query timeout (seconds)

# Proxy Validation Settings
validation_timeout: {data['validation_timeout']}                   # Timeout per proxy (seconds)
validation_retries: {data['validation_retries']}                    # Retry attempts
max_concurrent_validations: {data['max_concurrent_validations']}          # Parallel validations

# Proxy Fetching Settings
fetch_timeout: {data['fetch_timeout']}                      # Fetch timeout (seconds)
fetch_retries: {data['fetch_retries']}                       # Retry attempts
max_proxies_per_source: {data['max_proxies_per_source']}             # Max proxies per source
rate_limit_delay: {data['rate_limit_delay']}                    # Delay between requests

# Security Settings
enable_ssl_verification: {str(data['enable_ssl_verification']).lower()}         # SSL certificate verification
security_level: "{data['security_level']}"               # low, medium, high
anonymity_required: "{data['anonymity_required']}"         # transparent, anonymous, elite

# Cache Settings
cache_enabled: {str(data['cache_enabled']).lower()}                   # Enable caching
cache_ttl_hours: {data['cache_ttl_hours']}                    # Cache TTL in hours
cache_max_size: {data['cache_max_size']}                   # Max cached items

# Export Settings
default_export_format: "{data['default_export_format']}"       # json, csv, txt, xlsx
export_include_metrics: {str(data['export_include_metrics']).lower()}         # Include performance metrics
export_include_geo: {str(data['export_include_geo']).lower()}             # Include geo information

# Logging Settings
log_level: "{data['log_level']}"                    # DEBUG, INFO, WARNING, ERROR
log_file: "{data['log_file']}"          # Log file path
enable_file_logging: {str(data['enable_file_logging']).lower()}            # Enable file logging

# CLI Behavior Settings
verbose: {str(data['verbose']).lower()}                        # Verbose output by default
quiet: {str(data['quiet']).lower()}                          # Quiet mode by default
silent: {str(data['silent']).lower()}                        # Silent mode by default

# Default CLI Parameters
default_threads: {data['default_threads']}                     # Default number of threads
default_timeout: {data['default_timeout']}                    # Default timeout in milliseconds  
default_count: {data['default_count']}                       # Default batch size
default_rate_limit: {data['default_rate_limit']}                  # Default rate limit (requests/sec)

# Advanced Settings
user_agent: "{data['user_agent']}"
enable_geolocation: {str(data['enable_geolocation']).lower()}              # Enable GeoIP lookup
enable_threat_check: {str(data['enable_threat_check']).lower()}            # Enable threat intelligence
"""
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            config_data = asdict(self.config)
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                if self.config_path.endswith('.json'):
                    json.dump(config_data, f, indent=2)
                else:
                    yaml.dump(config_data, f, default_flow_style=False, indent=2)
            
            print(f"Configuration saved to: {self.config_path}")
            
        except Exception as e:
            raise RuntimeError(f"Failed to save config: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return getattr(self.config, key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        if not hasattr(self.config, key):
            raise ValueError(f"Unknown configuration key: {key}")
        setattr(self.config, key, value)
    
    def update(self, **kwargs):
        """Update multiple configuration values"""
        for key, value in kwargs.items():
            self.set(key, value)
    
    def validate(self) -> List[str]:
        """Validate configuration settings"""
        errors = []
        
        # Validate timeouts
        if self.config.validation_timeout <= 0:
            errors.append("validation_timeout must be positive")
        if self.config.fetch_timeout <= 0:
            errors.append("fetch_timeout must be positive")
        
        # Validate retry counts
        if self.config.validation_retries < 0:
            errors.append("validation_retries cannot be negative")
        if self.config.fetch_retries < 0:
            errors.append("fetch_retries cannot be negative")
        
        # Validate pool sizes
        if self.config.database_pool_size <= 0:
            errors.append("database_pool_size must be positive")
        if self.config.max_concurrent_validations <= 0:
            errors.append("max_concurrent_validations must be positive")
        
        # Validate security level
        valid_security_levels = ["low", "medium", "high"]
        if self.config.security_level not in valid_security_levels:
            errors.append(f"security_level must be one of: {valid_security_levels}")
        
        # Validate anonymity level
        valid_anonymity_levels = ["transparent", "anonymous", "elite"]
        if self.config.anonymity_required not in valid_anonymity_levels:
            errors.append(f"anonymity_required must be one of: {valid_anonymity_levels}")
        
        # Validate export format
        valid_export_formats = ["json", "csv", "txt", "xlsx", "yaml"]
        if self.config.default_export_format not in valid_export_formats:
            errors.append(f"default_export_format must be one of: {valid_export_formats}")
        
        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.config.log_level not in valid_log_levels:
            errors.append(f"log_level must be one of: {valid_log_levels}")
        
        return errors
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return asdict(self.config)
    
    def __repr__(self) -> str:
        return f"ConfigManager(config_path='{self.config_path}')"


# ===============================================================================
# CONFIGURATION UTILITIES
# ===============================================================================

def load_config(config_path: Optional[str] = None) -> ConfigManager:
    """Load configuration manager"""
    return ConfigManager(config_path)


def create_config_from_dict(data: Dict[str, Any]) -> ProxyConfig:
    """Create ProxyConfig from dictionary"""
    config = ProxyConfig()
    for key, value in data.items():
        if hasattr(config, key):
            setattr(config, key, value)
    return config


def get_config_template() -> Dict[str, Any]:
    """Get configuration template with all available options"""
    return asdict(ProxyConfig())


def create_cli_overrides(verbose=None, quiet=None, silent=None, threads=None, 
                        timeout=None, count=None, rate=None) -> Dict[str, Any]:
    """Create CLI overrides dictionary from common parameters"""
    overrides = {}
    
    if verbose is not None:
        overrides['verbose'] = verbose
        if verbose:
            overrides['log_level'] = 'DEBUG'
    
    if quiet is not None:
        overrides['quiet'] = quiet
        if quiet:
            overrides['log_level'] = 'WARNING'
    
    if silent is not None:
        overrides['silent'] = silent
        if silent:
            overrides['log_level'] = 'ERROR'
    
    if threads is not None:
        overrides['max_concurrent_validations'] = threads
        overrides['default_threads'] = threads
    
    if timeout is not None:
        overrides['validation_timeout'] = timeout // 1000  # Convert ms to seconds
        overrides['default_timeout'] = timeout
    
    if count is not None:
        overrides['default_count'] = count
    
    if rate is not None:
        overrides['rate_limit_delay'] = 1.0 / rate if rate > 0 else 0.0
        overrides['default_rate_limit'] = rate
    
    return overrides