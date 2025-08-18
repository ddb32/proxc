"""Dynamic Source Registry for ProxyHunter

This module provides dynamic source management capabilities including:
- Runtime source loading and registration
- Source health monitoring and lifecycle management
- Configuration hot-reloading
- Source performance tracking
"""

import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Union
from dataclasses import dataclass, field
from collections import defaultdict
import threading

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from ..proxy_core.models import ProxyInfo, ProxyProtocol
from ..proxy_core.config import ConfigManager
from .proxy_sources_config import load_proxy_sources, ProxySourcesConfig

logger = logging.getLogger(__name__)


@dataclass
class SourceHealthMetrics:
    """Health metrics for a proxy source"""
    name: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    average_response_time: float = 0.0
    proxy_quality_score: float = 0.0
    consecutive_failures: int = 0
    is_healthy: bool = True
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage"""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100
    
    @property
    def failure_rate(self) -> float:
        """Calculate failure rate percentage"""
        return 100.0 - self.success_rate
    
    def record_success(self, response_time: float, proxy_count: int = 0):
        """Record a successful request"""
        self.total_requests += 1
        self.successful_requests += 1
        self.last_success = datetime.utcnow()
        self.consecutive_failures = 0
        
        # Update average response time
        if self.average_response_time == 0:
            self.average_response_time = response_time
        else:
            self.average_response_time = (self.average_response_time + response_time) / 2
    
    def record_failure(self, error_message: str = ""):
        """Record a failed request"""
        self.total_requests += 1
        self.failed_requests += 1
        self.last_failure = datetime.utcnow()
        self.consecutive_failures += 1
    
    def update_health_status(self, failure_threshold: int = 3):
        """Update health status based on consecutive failures"""
        self.is_healthy = self.consecutive_failures < failure_threshold


@dataclass
class ProxySource:
    """Enhanced proxy source definition"""
    # Basic identification
    name: str
    description: str
    url: str
    source_type: str  # api, html_table, text_list, multi_source
    enabled: bool = True
    
    # Quality and trust
    quality_score: int = 5  # 1-10 scale
    trust_level: str = "medium"  # low, medium, high, enterprise
    
    # Request configuration
    rate_limit: float = 2.0
    timeout: int = 30
    max_proxies: int = 1000
    concurrent_requests: int = 1
    max_retries: int = 3
    retry_delay: int = 60
    
    # Headers and authentication
    headers: Dict[str, str] = field(default_factory=dict)
    auth_type: Optional[str] = None  # basic, bearer, header, api_key
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    
    # Parsing configuration
    response_format: Dict[str, Any] = field(default_factory=dict)
    json_path: Optional[str] = None
    table_selector: Optional[str] = None
    row_selector: Optional[str] = None
    column_mapping: Dict[str, Any] = field(default_factory=dict)
    proxy_pattern: Optional[str] = None
    
    # Protocol and feature support
    supports_protocols: List[str] = field(default_factory=lambda: ["http"])
    supports_auth: bool = False
    supports_rotation: bool = False
    geographic_targeting: bool = False
    
    # Multi-source configuration
    urls: List[str] = field(default_factory=list)
    
    # Health and performance
    health_metrics: SourceHealthMetrics = field(init=False)
    last_updated: datetime = field(default_factory=datetime.utcnow)
    
    # Advanced features
    requires_js: bool = False
    cost_per_gb: Optional[float] = None
    notes: str = ""
    
    def __post_init__(self):
        self.health_metrics = SourceHealthMetrics(name=self.name)
        
        # Set default headers if empty
        if not self.headers:
            self.headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
    
    @property
    def is_premium(self) -> bool:
        """Check if this is a premium source"""
        return self.trust_level in ["high", "enterprise"] and (
            self.auth_type is not None or self.cost_per_gb is not None
        )
    
    @property
    def effective_urls(self) -> List[str]:
        """Get all URLs for this source"""
        if self.urls:
            return self.urls
        return [self.url] if self.url else []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'name': self.name,
            'description': self.description,
            'url': self.url,
            'source_type': self.source_type,
            'enabled': self.enabled,
            'quality_score': self.quality_score,
            'trust_level': self.trust_level,
            'rate_limit': self.rate_limit,
            'timeout': self.timeout,
            'max_proxies': self.max_proxies,
            'supports_protocols': self.supports_protocols,
            'is_premium': self.is_premium,
            'health_status': {
                'is_healthy': self.health_metrics.is_healthy,
                'success_rate': self.health_metrics.success_rate,
                'consecutive_failures': self.health_metrics.consecutive_failures,
                'last_success': self.health_metrics.last_success.isoformat() if self.health_metrics.last_success else None
            }
        }


class SourceRegistry:
    """Dynamic registry for managing proxy sources"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Source storage
        self.sources: Dict[str, ProxySource] = {}
        self.source_categories: Dict[str, Set[str]] = defaultdict(set)
        
        # Health monitoring
        self.health_monitoring_enabled = True
        self.health_check_interval = 3600  # 1 hour
        self.failure_threshold = 3
        self.recovery_threshold = 2
        
        # Performance tracking
        self.performance_metrics = defaultdict(list)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Load sources from configuration
        self._load_sources_from_config()
        
        self.logger.info(f"SourceRegistry initialized with {len(self.sources)} sources")
    
    def _load_sources_from_config(self):
        """Load sources from three-file configuration structure"""
        try:
            # Load configuration using the new loader
            config_dir = Path(__file__).parent
            proxy_config = load_proxy_sources(str(config_dir))
            
            if proxy_config is None:
                self.logger.warning("Failed to load proxy sources configuration")
                return
            
            # Load global health monitoring settings
            health_config = proxy_config.get_health_monitoring_config()
            if health_config:
                self.health_monitoring_enabled = health_config.get('enabled', True)
                self.health_check_interval = health_config.get('check_interval', 3600)
                self.failure_threshold = health_config.get('failure_threshold', 3)
                self.recovery_threshold = health_config.get('recovery_threshold', 2)
            
            # Load sources from all categories
            sources_loaded = 0
            
            # Load free sources
            for source_name, source_config in proxy_config.free_sources.items():
                if self._should_load_source(source_config):
                    try:
                        source = self._create_source_from_config(source_name, source_config, "free")
                        self.register_source(source, "free")
                        sources_loaded += 1
                    except Exception as e:
                        self.logger.error(f"Failed to load free source {source_name}: {e}")
            
            # Load premium sources
            for source_name, source_config in proxy_config.premium_sources.items():
                if self._should_load_source(source_config):
                    try:
                        source = self._create_source_from_config(source_name, source_config, "premium")
                        self.register_source(source, "premium")
                        sources_loaded += 1
                    except Exception as e:
                        self.logger.error(f"Failed to load premium source {source_name}: {e}")
            
            # Load custom sources
            for source_name, source_config in proxy_config.custom_sources.items():
                if self._should_load_source(source_config):
                    try:
                        source = self._create_source_from_config(source_name, source_config, "custom")
                        self.register_source(source, "custom")
                        sources_loaded += 1
                    except Exception as e:
                        self.logger.error(f"Failed to load custom source {source_name}: {e}")
            
            self.logger.info(f"Loaded {sources_loaded} sources from three-file configuration")
            
        except Exception as e:
            self.logger.error(f"Failed to load source configuration: {e}")
    
    def _should_load_source(self, source_config: Dict[str, Any]) -> bool:
        """Check if a source should be loaded based on enabled status"""
        # Check explicit enabled flag first
        if 'enabled' in source_config:
            return source_config['enabled']
        
        # If no enabled flag, assume enabled (for backward compatibility)
        return True
    
    def _create_source_from_config(self, name: str, config: Dict[str, Any], category: str) -> ProxySource:
        """Create ProxySource from configuration dictionary"""
        
        # Create source name with category prefix (unless already prefixed)
        source_name = name if '.' in name else f"{category}.{name}"
        
        # Handle both new three-file format and legacy format
        # Extract basic fields with defaults
        source = ProxySource(
            name=source_name,
            description=config.get('description', config.get('name', '')),
            url=config.get('url', ''),
            source_type=config.get('type', 'text_list'),
            enabled=config.get('enabled', True),
            quality_score=config.get('quality_score', 5),
            trust_level=config.get('trust_level', 'medium'),
            rate_limit=config.get('rate_limit', 2.0),
            timeout=config.get('timeout', 30),
            max_proxies=config.get('max_proxies', 1000),
            concurrent_requests=config.get('concurrent_requests', 1),
            max_retries=config.get('max_retries', 3),
            retry_delay=config.get('retry_delay', 60),
            headers=config.get('headers', {}),
            auth_type=config.get('auth_type'),
            username=config.get('username'),
            password=config.get('password'),
            api_key=config.get('api_key'),
            response_format=config.get('response_format', {}),
            json_path=config.get('json_path'),
            table_selector=config.get('table_selector'),
            row_selector=config.get('row_selector'),
            column_mapping=config.get('column_mapping', {}),
            proxy_pattern=config.get('proxy_pattern'),
            supports_protocols=config.get('supports_protocols', ['http']),
            supports_auth=config.get('supports_auth', False),
            supports_rotation=config.get('supports_rotation', False),
            geographic_targeting=config.get('geographic_targeting', False),
            urls=config.get('urls', []),
            requires_js=config.get('requires_js', False),
            cost_per_gb=config.get('cost_per_gb'),
            notes=config.get('notes', '')
        )
        
        return source
    
    def register_source(self, source: ProxySource, category: str = "custom"):
        """Register a new proxy source"""
        with self._lock:
            self.sources[source.name] = source
            self.source_categories[category].add(source.name)
            
            self.logger.info(f"Registered source: {source.name} (category: {category})")
    
    def unregister_source(self, source_name: str) -> bool:
        """Unregister a proxy source"""
        with self._lock:
            if source_name in self.sources:
                del self.sources[source_name]
                
                # Remove from categories
                for category_sources in self.source_categories.values():
                    category_sources.discard(source_name)
                
                self.logger.info(f"Unregistered source: {source_name}")
                return True
            
            return False
    
    def get_source(self, source_name: str) -> Optional[ProxySource]:
        """Get a specific source by name"""
        with self._lock:
            return self.sources.get(source_name)
    
    def get_sources_by_category(self, category: str) -> List[ProxySource]:
        """Get all sources in a specific category"""
        with self._lock:
            if category not in self.source_categories:
                return []
            
            return [
                self.sources[source_name] 
                for source_name in self.source_categories[category]
                if source_name in self.sources
            ]
    
    def get_enabled_sources(self) -> List[ProxySource]:
        """Get all enabled sources"""
        with self._lock:
            return [source for source in self.sources.values() if source.enabled]
    
    def get_healthy_sources(self) -> List[ProxySource]:
        """Get all healthy and enabled sources"""
        with self._lock:
            return [
                source for source in self.sources.values() 
                if source.enabled and source.health_metrics.is_healthy
            ]
    
    def get_sources_by_quality(self, min_quality: int = 5) -> List[ProxySource]:
        """Get sources with minimum quality score"""
        with self._lock:
            return [
                source for source in self.sources.values()
                if source.enabled and source.quality_score >= min_quality
            ]
    
    def get_sources_by_protocol(self, protocol: str) -> List[ProxySource]:
        """Get sources that support a specific protocol"""
        with self._lock:
            return [
                source for source in self.sources.values()
                if source.enabled and protocol.lower() in [p.lower() for p in source.supports_protocols]
            ]
    
    def enable_source(self, source_name: str) -> bool:
        """Enable a source"""
        with self._lock:
            if source_name in self.sources:
                self.sources[source_name].enabled = True
                self.logger.info(f"Enabled source: {source_name}")
                return True
            return False
    
    def disable_source(self, source_name: str) -> bool:
        """Disable a source"""
        with self._lock:
            if source_name in self.sources:
                self.sources[source_name].enabled = False
                self.logger.info(f"Disabled source: {source_name}")
                return True
            return False
    
    def update_source_health(self, source_name: str, success: bool, 
                           response_time: float = 0.0, proxy_count: int = 0, 
                           error_message: str = ""):
        """Update health metrics for a source"""
        with self._lock:
            if source_name not in self.sources:
                return
            
            source = self.sources[source_name]
            
            if success:
                source.health_metrics.record_success(response_time, proxy_count)
            else:
                source.health_metrics.record_failure(error_message)
            
            # Update health status
            source.health_metrics.update_health_status(self.failure_threshold)
            
            # Auto-disable if unhealthy
            if (self.health_monitoring_enabled and 
                not source.health_metrics.is_healthy and source.enabled):
                
                self.logger.warning(
                    f"Auto-disabling unhealthy source: {source_name} "
                    f"(failures: {source.health_metrics.consecutive_failures})"
                )
                source.enabled = False
    
    def get_source_statistics(self) -> Dict[str, Any]:
        """Get comprehensive source statistics"""
        with self._lock:
            total_sources = len(self.sources)
            enabled_sources = len([s for s in self.sources.values() if s.enabled])
            healthy_sources = len([s for s in self.sources.values() if s.health_metrics.is_healthy])
            premium_sources = len([s for s in self.sources.values() if s.is_premium])
            
            category_stats = {}
            for category, source_names in self.source_categories.items():
                category_stats[category] = {
                    'total': len(source_names),
                    'enabled': len([
                        name for name in source_names 
                        if name in self.sources and self.sources[name].enabled
                    ]),
                    'healthy': len([
                        name for name in source_names 
                        if name in self.sources and self.sources[name].health_metrics.is_healthy
                    ])
                }
            
            quality_distribution = defaultdict(int)
            for source in self.sources.values():
                quality_distribution[source.quality_score] += 1
            
            return {
                'total_sources': total_sources,
                'enabled_sources': enabled_sources,
                'healthy_sources': healthy_sources,
                'premium_sources': premium_sources,
                'health_rate': (healthy_sources / total_sources * 100) if total_sources > 0 else 0,
                'category_stats': dict(category_stats),
                'quality_distribution': dict(quality_distribution),
                'protocols_supported': self._get_protocol_support_stats()
            }
    
    def _get_protocol_support_stats(self) -> Dict[str, int]:
        """Get protocol support statistics"""
        protocol_stats = defaultdict(int)
        
        for source in self.sources.values():
            if source.enabled:
                for protocol in source.supports_protocols:
                    protocol_stats[protocol.lower()] += 1
        
        return dict(protocol_stats)
    
    def get_source_health_report(self) -> Dict[str, Any]:
        """Generate comprehensive health report"""
        with self._lock:
            healthy_sources = []
            unhealthy_sources = []
            warning_sources = []
            
            for source in self.sources.values():
                health_data = {
                    'name': source.name,
                    'enabled': source.enabled,
                    'quality_score': source.quality_score,
                    'success_rate': source.health_metrics.success_rate,
                    'consecutive_failures': source.health_metrics.consecutive_failures,
                    'last_success': source.health_metrics.last_success,
                    'last_failure': source.health_metrics.last_failure,
                    'average_response_time': source.health_metrics.average_response_time
                }
                
                if source.health_metrics.is_healthy:
                    healthy_sources.append(health_data)
                else:
                    unhealthy_sources.append(health_data)
                
                # Check for warning conditions
                if (source.health_metrics.success_rate < 50 or 
                    source.health_metrics.consecutive_failures > 1):
                    warning_sources.append(health_data)
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'healthy_sources': healthy_sources,
                'unhealthy_sources': unhealthy_sources,
                'warning_sources': warning_sources,
                'summary': {
                    'healthy_count': len(healthy_sources),
                    'unhealthy_count': len(unhealthy_sources),
                    'warning_count': len(warning_sources),
                    'total_count': len(self.sources)
                }
            }
    
    def reload_configuration(self) -> bool:
        """Reload sources from three-file configuration structure"""
        try:
            with self._lock:
                # Clear existing sources
                old_source_count = len(self.sources)
                self.sources.clear()
                self.source_categories.clear()
                
                # Reload from config using new three-file structure
                self._load_sources_from_config()
                
                new_source_count = len(self.sources)
                self.logger.info(
                    f"Configuration reloaded: {old_source_count} -> {new_source_count} sources"
                )
                
                return True
        
        except Exception as e:
            self.logger.error(f"Failed to reload configuration: {e}")
            return False
    
    def validate_configuration(self) -> Dict[str, Any]:
        """Validate the current three-file configuration structure"""
        try:
            from .proxy_sources_config import validate_three_file_structure
            
            config_dir = Path(__file__).parent
            validation_result = validate_three_file_structure(config_dir)
            
            # Add runtime validation of loaded sources
            validation_result['runtime_validation'] = {
                'sources_loaded': len(self.sources),
                'sources_enabled': len(self.get_enabled_sources()),
                'sources_healthy': len(self.get_healthy_sources()),
                'categories': list(self.source_categories.keys()),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return validation_result
            
        except Exception as e:
            self.logger.error(f"Configuration validation error: {e}")
            return {
                'valid': False,
                'errors': [f"Validation failed: {e}"],
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def validate_cross_file_consistency(self) -> Dict[str, Any]:
        """Validate cross-file consistency and detect conflicts"""
        try:
            from .proxy_sources_config import validate_cross_file_configuration
            
            config_dir = Path(__file__).parent
            validation_result = validate_cross_file_configuration(config_dir)
            
            # Add runtime information from the registry
            validation_result['registry_validation'] = {
                'sources_in_registry': len(self.sources),
                'registry_categories': list(self.source_categories.keys()),
                'healthy_sources_in_registry': len(self.get_healthy_sources()),
                'enabled_sources_in_registry': len(self.get_enabled_sources()),
                'validation_timestamp': datetime.utcnow().isoformat()
            }
            
            return validation_result
            
        except Exception as e:
            self.logger.error(f"Cross-file validation error: {e}")
            return {
                'valid': False,
                'errors': [f"Cross-file validation failed: {e}"],
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def get_comprehensive_health_report(self) -> Dict[str, Any]:
        """Get a comprehensive health report including cross-file validation"""
        # Get basic health report
        health_report = self.get_source_health_report()
        
        # Add cross-file validation
        cross_validation = self.validate_cross_file_consistency()
        
        # Combine the reports
        comprehensive_report = {
            'timestamp': datetime.utcnow().isoformat(),
            'source_health': health_report,
            'configuration_validation': cross_validation,
            'overall_status': {
                'healthy': health_report.get('summary', {}).get('healthy_count', 0),
                'unhealthy': health_report.get('summary', {}).get('unhealthy_count', 0),
                'warnings': len(cross_validation.get('warnings', [])),
                'conflicts': sum(len(v) for v in cross_validation.get('conflicts', {}).values()),
                'recommendations': len(cross_validation.get('recommendations', []))
            }
        }
        
        # Determine overall health status
        overall_health = "healthy"
        if comprehensive_report['overall_status']['unhealthy'] > 0:
            overall_health = "degraded"
        if comprehensive_report['overall_status']['conflicts'] > 0:
            overall_health = "critical"
        if not cross_validation.get('valid', True):
            overall_health = "critical"
        
        comprehensive_report['overall_health'] = overall_health
        
        return comprehensive_report
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """Get a summary of the current configuration setup"""
        try:
            config_dir = Path(__file__).parent
            proxy_config = load_proxy_sources(str(config_dir))
            
            if proxy_config is None:
                return {'error': 'Failed to load configuration'}
            
            return {
                'configuration_type': 'three_file_structure',
                'version': proxy_config.version,
                'last_updated': proxy_config.last_updated,
                'total_sources': {
                    'free': len(proxy_config.free_sources),
                    'premium': len(proxy_config.premium_sources),
                    'custom': len(proxy_config.custom_sources),
                    'total': len(proxy_config.free_sources) + len(proxy_config.premium_sources) + len(proxy_config.custom_sources)
                },
                'enabled_sources': {
                    'free': len([s for s in proxy_config.free_sources.values() if s.get('enabled', True)]),
                    'premium': len([s for s in proxy_config.premium_sources.values() if s.get('enabled', True)]),
                    'custom': len([s for s in proxy_config.custom_sources.values() if s.get('enabled', True)]),
                    'total': len(proxy_config.get_enabled_sources())
                },
                'profiles_available': list(proxy_config.profiles.keys()) if proxy_config.profiles else [],
                'health_monitoring_enabled': proxy_config.health_monitoring.get('enabled', False),
                'loaded_in_registry': len(self.sources),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get configuration summary: {e}")
            return {'error': f'Failed to get summary: {e}'}
    
    def get_sources_by_profile(self, profile_name: str) -> List[ProxySource]:
        """Get sources that match a specific collection profile"""
        try:
            config_dir = Path(__file__).parent
            proxy_config = load_proxy_sources(str(config_dir))
            
            if proxy_config is None:
                return []
            
            profile = proxy_config.get_profile(profile_name)
            if profile is None:
                self.logger.warning(f"Profile '{profile_name}' not found")
                return []
            
            # Expand source patterns to actual source names
            expanded_sources = proxy_config.expand_source_patterns(profile.sources)
            
            # Get matching sources from registry
            matching_sources = []
            for source_pattern in expanded_sources:
                source = self.get_source(source_pattern)
                if source and source.enabled:
                    # Check if source meets profile quality threshold
                    if source.quality_score >= profile.quality_threshold:
                        matching_sources.append(source)
            
            return matching_sources
            
        except Exception as e:
            self.logger.error(f"Failed to get sources for profile '{profile_name}': {e}")
            return []
    
    def export_configuration(self, file_path: str, format_type: str = "legacy") -> bool:
        """Export current source configuration to file
        
        Args:
            file_path: Path to export file
            format_type: 'legacy' for single file, 'three_file' for new structure
        """
        if not HAS_YAML:
            self.logger.error("PyYAML not available for export")
            return False
        
        try:
            if format_type == "three_file":
                return self._export_three_file_configuration(file_path)
            else:
                return self._export_legacy_configuration(file_path)
                
        except Exception as e:
            self.logger.error(f"Failed to export configuration: {e}")
            return False
    
    def _export_legacy_configuration(self, file_path: str) -> bool:
        """Export in legacy single-file format"""
        # Group sources by category
        export_data = {
            'version': '1.0',
            'last_updated': datetime.utcnow().isoformat(),
            'proxy_sources': {}
        }
        
        for category, source_names in self.source_categories.items():
            export_data['proxy_sources'][category] = {}
            
            for source_name in source_names:
                if source_name in self.sources:
                    source = self.sources[source_name]
                    # Remove category prefix from name for export
                    clean_name = source_name.split('.', 1)[-1] if '.' in source_name else source_name
                    export_data['proxy_sources'][category][clean_name] = source.to_dict()
        
        with open(file_path, 'w', encoding='utf-8') as f:
            yaml.dump(export_data, f, default_flow_style=False, indent=2)
        
        self.logger.info(f"Legacy configuration exported to: {file_path}")
        return True
    
    def _export_three_file_configuration(self, base_path: str) -> bool:
        """Export in three-file format to a directory"""
        export_dir = Path(base_path)
        export_dir.mkdir(parents=True, exist_ok=True)
        
        # Prepare three separate configurations
        api_sources = {'free_apis': {}, 'premium_apis': {}, 'custom_apis': {}}
        static_sources = {'github_sources': {}, 'text_file_sources': {}, 'html_table_sources': {}, 'custom_static_sources': {}}
        collection_config = {
            'version': '1.2',
            'last_updated': datetime.utcnow().strftime('%Y-%m-%d'),
            'file_type': 'collection_config'
        }
        
        # Distribute sources based on type and category
        for category, source_names in self.source_categories.items():
            for source_name in source_names:
                if source_name in self.sources:
                    source = self.sources[source_name]
                    clean_name = source_name.split('.', 1)[-1] if '.' in source_name else source_name
                    source_dict = source.to_dict()
                    
                    # Determine target location based on source type
                    if source.source_type == 'api':
                        if category == 'premium':
                            api_sources['premium_apis'][clean_name] = source_dict
                        elif category == 'custom':
                            api_sources['custom_apis'][clean_name] = source_dict
                        else:
                            api_sources['free_apis'][clean_name] = source_dict
                    else:
                        # Static sources
                        if category == 'custom':
                            static_sources['custom_static_sources'][clean_name] = source_dict
                        elif 'github' in source.url.lower():
                            static_sources['github_sources'][clean_name] = source_dict
                        elif source.source_type == 'html_table':
                            static_sources['html_table_sources'][clean_name] = source_dict
                        else:
                            static_sources['text_file_sources'][clean_name] = source_dict
        
        # Write three files
        files_written = 0
        
        # API sources file
        api_file = export_dir / 'api_sources.yaml'
        with open(api_file, 'w', encoding='utf-8') as f:
            yaml.dump(api_sources, f, default_flow_style=False, indent=2)
        files_written += 1
        
        # Static sources file
        static_file = export_dir / 'static_sources.yaml'
        with open(static_file, 'w', encoding='utf-8') as f:
            yaml.dump(static_sources, f, default_flow_style=False, indent=2)
        files_written += 1
        
        # Collection config file
        config_file = export_dir / 'collection_config.yaml'
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(collection_config, f, default_flow_style=False, indent=2)
        files_written += 1
        
        self.logger.info(f"Three-file configuration exported to: {export_dir} ({files_written} files)")
        return True


# Global registry instance
_global_registry: Optional[SourceRegistry] = None


def get_source_registry(config: Optional[ConfigManager] = None) -> SourceRegistry:
    """Get the global source registry instance"""
    global _global_registry
    
    if _global_registry is None:
        _global_registry = SourceRegistry(config)
    
    return _global_registry


def reload_sources() -> bool:
    """Reload sources in the global registry"""
    registry = get_source_registry()
    return registry.reload_configuration()