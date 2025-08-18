#!/usr/bin/env python3
"""
Configuration Migration Tool

This tool helps migrate from legacy single-file proxy source configuration
to the new three-file configuration structure.
"""

import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = logging.getLogger(__name__)


class ConfigurationMigrationTool:
    """Tool for migrating proxy source configuration"""
    
    def __init__(self, config_dir: Path):
        self.config_dir = Path(config_dir)
        self.backup_dir = self.config_dir / "backup"
        self.migration_log = []
        
        if not HAS_YAML:
            raise ImportError("PyYAML is required for configuration migration")
    
    def migrate_legacy_to_three_file(self, legacy_file: str = "proxy_sources.yaml", 
                                   force: bool = False, backup: bool = True) -> Dict[str, Any]:
        """
        Migrate legacy single-file configuration to three-file structure
        
        Args:
            legacy_file: Name of the legacy configuration file
            force: Force migration even if target files exist
            backup: Create backup of existing files
            
        Returns:
            Migration result dictionary
        """
        result = {
            'success': False,
            'migration_log': [],
            'files_created': [],
            'files_backed_up': [],
            'errors': [],
            'warnings': []
        }
        
        try:
            legacy_path = self.config_dir / legacy_file
            
            # Check if legacy file exists
            if not legacy_path.exists():
                result['errors'].append(f"Legacy configuration file not found: {legacy_path}")
                return result
            
            # Load legacy configuration
            legacy_config = self._load_legacy_configuration(legacy_path)
            if not legacy_config:
                result['errors'].append("Failed to load legacy configuration")
                return result
            
            # Check if target files already exist
            target_files = ['api_sources.yaml', 'static_sources.yaml', 'collection_config.yaml']
            existing_files = [f for f in target_files if (self.config_dir / f).exists()]
            
            if existing_files and not force:
                result['errors'].append(
                    f"Target files already exist: {existing_files}. Use force=True to overwrite."
                )
                return result
            
            # Create backup if requested
            if backup:
                backup_result = self._create_backup(legacy_path, existing_files)
                result['files_backed_up'] = backup_result
            
            # Migrate configuration
            migration_data = self._split_legacy_configuration(legacy_config)
            
            # Write new configuration files
            files_written = self._write_three_file_configuration(migration_data, force)
            result['files_created'] = files_written
            
            # Validate migration
            validation_result = self._validate_migration(legacy_config, migration_data)
            result['warnings'].extend(validation_result.get('warnings', []))
            
            # Update result
            result['success'] = True
            result['migration_log'] = self.migration_log
            
            self._log(f"Successfully migrated {legacy_file} to three-file structure")
            
        except Exception as e:
            result['errors'].append(f"Migration failed: {e}")
            logger.error(f"Migration error: {e}")
        
        return result
    
    def migrate_three_file_to_legacy(self, output_file: str = "proxy_sources_merged.yaml",
                                   force: bool = False) -> Dict[str, Any]:
        """
        Migrate three-file configuration back to legacy single-file format
        
        Args:
            output_file: Name of the output legacy file
            force: Force creation even if output file exists
            
        Returns:
            Migration result dictionary
        """
        result = {
            'success': False,
            'migration_log': [],
            'file_created': None,
            'errors': [],
            'warnings': []
        }
        
        try:
            # Check if three-file configuration exists
            required_files = ['api_sources.yaml', 'static_sources.yaml', 'collection_config.yaml']
            missing_files = []
            
            for filename in required_files:
                if not (self.config_dir / filename).exists():
                    missing_files.append(filename)
            
            if missing_files:
                result['errors'].append(f"Missing three-file configuration: {missing_files}")
                return result
            
            # Check if output file exists
            output_path = self.config_dir / output_file
            if output_path.exists() and not force:
                result['errors'].append(f"Output file already exists: {output_path}. Use force=True to overwrite.")
                return result
            
            # Load three-file configuration
            from .proxy_sources_config import load_proxy_sources
            
            proxy_config = load_proxy_sources(str(self.config_dir))
            if not proxy_config:
                result['errors'].append("Failed to load three-file configuration")
                return result
            
            # Convert to legacy format
            legacy_config = self._merge_to_legacy_format(proxy_config)
            
            # Write legacy file
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump(legacy_config, f, default_flow_style=False, indent=2, sort_keys=False)
            
            result['file_created'] = str(output_path)
            result['success'] = True
            
            self._log(f"Successfully merged three-file configuration to {output_file}")
            
        except Exception as e:
            result['errors'].append(f"Reverse migration failed: {e}")
            logger.error(f"Reverse migration error: {e}")
        
        return result
    
    def analyze_legacy_configuration(self, legacy_file: str = "proxy_sources.yaml") -> Dict[str, Any]:
        """
        Analyze legacy configuration to show what will be migrated
        
        Args:
            legacy_file: Name of the legacy configuration file
            
        Returns:
            Analysis result dictionary
        """
        result = {
            'file_found': False,
            'file_size': 0,
            'configuration_valid': False,
            'sources_found': {},
            'profiles_found': {},
            'settings_found': {},
            'migration_recommendations': [],
            'potential_issues': []
        }
        
        try:
            legacy_path = self.config_dir / legacy_file
            
            if not legacy_path.exists():
                result['potential_issues'].append(f"Legacy file not found: {legacy_path}")
                return result
            
            result['file_found'] = True
            result['file_size'] = legacy_path.stat().st_size
            
            # Load and analyze configuration
            legacy_config = self._load_legacy_configuration(legacy_path)
            if not legacy_config:
                result['potential_issues'].append("Failed to parse legacy configuration")
                return result
            
            result['configuration_valid'] = True
            
            # Analyze sources
            proxy_sources = legacy_config.get('proxy_sources', {})
            for category, sources in proxy_sources.items():
                if isinstance(sources, dict):
                    enabled_count = sum(1 for s in sources.values() 
                                      if isinstance(s, dict) and s.get('enabled', True))
                    result['sources_found'][category] = {
                        'total': len(sources),
                        'enabled': enabled_count,
                        'disabled': len(sources) - enabled_count
                    }
            
            # Analyze profiles
            profiles = legacy_config.get('profiles', {})
            if profiles:
                result['profiles_found'] = {
                    'total': len(profiles),
                    'names': list(profiles.keys())
                }
            
            # Analyze settings
            settings_sections = ['collection', 'health_monitoring', 'advanced']
            for section in settings_sections:
                if section in legacy_config:
                    result['settings_found'][section] = True
            
            # Generate recommendations
            total_sources = sum(cat['total'] for cat in result['sources_found'].values())
            
            if total_sources == 0:
                result['potential_issues'].append("No proxy sources found in configuration")
            elif total_sources > 50:
                result['migration_recommendations'].append(
                    "Large number of sources detected - consider organizing by quality/usage"
                )
            
            if not result['profiles_found']:
                result['migration_recommendations'].append(
                    "No collection profiles found - will create default profiles during migration"
                )
            
            # Check for API vs static sources
            api_indicators = ['api_key', 'auth_type', 'json_path']
            static_indicators = ['table_selector', 'proxy_pattern', 'github.com', 'raw.githubusercontent.com']
            
            api_sources = 0
            static_sources = 0
            
            for category, sources in proxy_sources.items():
                if isinstance(sources, dict):
                    for source_config in sources.values():
                        if isinstance(source_config, dict):
                            if any(indicator in source_config for indicator in api_indicators):
                                api_sources += 1
                            elif any(indicator in str(source_config.get('url', '')) 
                                   for indicator in static_indicators):
                                static_sources += 1
                            elif 'url' in source_config:
                                # Default classification based on URL patterns
                                url = source_config['url'].lower()
                                if 'api' in url or 'json' in url:
                                    api_sources += 1
                                else:
                                    static_sources += 1
            
            result['migration_recommendations'].append(
                f"Will distribute {api_sources} API sources and {static_sources} static sources"
            )
            
        except Exception as e:
            result['potential_issues'].append(f"Analysis failed: {e}")
        
        return result
    
    def _load_legacy_configuration(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Load legacy configuration file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self._log(f"Failed to load legacy configuration: {e}")
            return None
    
    def _split_legacy_configuration(self, legacy_config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Split legacy configuration into three-file structure"""
        
        # Initialize the three configuration structures
        api_sources_config = {
            'version': '1.2',
            'last_updated': datetime.now().strftime('%Y-%m-%d'),
            'file_type': 'api_sources',
            'free_apis': {},
            'premium_apis': {},
            'custom_apis': {}
        }
        
        static_sources_config = {
            'version': '1.2',
            'last_updated': datetime.now().strftime('%Y-%m-%d'),
            'file_type': 'static_sources',
            'github_sources': {},
            'text_file_sources': {},
            'html_table_sources': {},
            'custom_static_sources': {}
        }
        
        collection_config = {
            'version': '1.2',
            'last_updated': datetime.now().strftime('%Y-%m-%d'),
            'file_type': 'collection_config'
        }
        
        # Extract proxy sources
        proxy_sources = legacy_config.get('proxy_sources', {})
        
        for category_name, category_sources in proxy_sources.items():
            if not isinstance(category_sources, dict):
                continue
                
            for source_name, source_config in category_sources.items():
                if not isinstance(source_config, dict):
                    continue
                
                # Determine if this is an API or static source
                source_type = self._classify_source_type(source_config)
                
                if source_type == 'api':
                    # Distribute API sources based on category
                    if category_name == 'premium':
                        api_sources_config['premium_apis'][source_name] = source_config
                    elif category_name == 'custom':
                        api_sources_config['custom_apis'][source_name] = source_config
                    else:
                        api_sources_config['free_apis'][source_name] = source_config
                
                else:
                    # Distribute static sources based on URL patterns
                    url = source_config.get('url', '').lower()
                    
                    if 'github.com' in url or 'githubusercontent.com' in url:
                        static_sources_config['github_sources'][source_name] = source_config
                    elif source_config.get('type') == 'html_table':
                        static_sources_config['html_table_sources'][source_name] = source_config
                    elif category_name == 'custom':
                        static_sources_config['custom_static_sources'][source_name] = source_config
                    else:
                        static_sources_config['text_file_sources'][source_name] = source_config
        
        # Extract collection settings
        collection_settings = legacy_config.get('collection', {})
        if collection_settings:
            collection_config.update(collection_settings)
        
        # Extract other settings
        for setting_key in ['health_monitoring', 'advanced', 'profiles']:
            if setting_key in legacy_config:
                collection_config[setting_key] = legacy_config[setting_key]
        
        # Add default profiles if none exist
        if 'profiles' not in collection_config:
            collection_config['profiles'] = self._create_default_profiles()
        
        # Add default settings sections
        if 'defaults' not in collection_config:
            collection_config['defaults'] = self._create_default_settings()
        
        if 'rate_limiting' not in collection_config:
            collection_config['rate_limiting'] = self._create_default_rate_limiting()
        
        if 'quality_filters' not in collection_config:
            collection_config['quality_filters'] = self._create_default_quality_filters()
        
        self._log(f"Split configuration into {len(api_sources_config['free_apis']) + len(api_sources_config['premium_apis']) + len(api_sources_config['custom_apis'])} API sources and {len(static_sources_config['github_sources']) + len(static_sources_config['text_file_sources']) + len(static_sources_config['html_table_sources']) + len(static_sources_config['custom_static_sources'])} static sources")
        
        return {
            'api_sources': api_sources_config,
            'static_sources': static_sources_config,
            'collection_config': collection_config
        }
    
    def _classify_source_type(self, source_config: Dict[str, Any]) -> str:
        """Classify source as API or static based on configuration"""
        
        # Check for API indicators
        api_indicators = [
            'api_key', 'auth_type', 'json_path', 'response_format'
        ]
        
        if any(indicator in source_config for indicator in api_indicators):
            return 'api'
        
        # Check source type field
        source_type = source_config.get('type', '').lower()
        if source_type == 'api':
            return 'api'
        
        # Check URL patterns
        url = source_config.get('url', '').lower()
        if any(pattern in url for pattern in ['api', '/v1/', '/v2/', 'json']):
            return 'api'
        
        # Default to static
        return 'static'
    
    def _create_default_profiles(self) -> Dict[str, Any]:
        """Create default collection profiles"""
        return {
            'quick_scan': {
                'name': 'Quick Scan',
                'description': 'Fast collection from high-quality sources',
                'max_duration': 300,
                'max_proxies': 500,
                'sources': ['free.*'],
                'quality_threshold': 6,
                'concurrent_sources': 2
            },
            'deep_hunt': {
                'name': 'Deep Hunt',
                'description': 'Comprehensive collection from all sources',
                'max_duration': 1800,
                'max_proxies': 5000,
                'sources': ['free.*', 'premium.*'],
                'quality_threshold': 4,
                'concurrent_sources': 5
            },
            'premium_quality': {
                'name': 'Premium Quality',
                'description': 'High-quality sources only',
                'max_duration': 600,
                'max_proxies': 2000,
                'sources': ['premium.*'],
                'quality_threshold': 7,
                'concurrent_sources': 3
            }
        }
    
    def _create_default_settings(self) -> Dict[str, Any]:
        """Create default operational settings"""
        return {
            'timeout': 30,
            'max_retries': 3,
            'retry_delay': 60,
            'user_agent_rotation': True,
            'verify_ssl': False,
            'follow_redirects': True,
            'max_redirects': 3
        }
    
    def _create_default_rate_limiting(self) -> Dict[str, Any]:
        """Create default rate limiting settings"""
        return {
            'default_delay': 2.0,
            'jitter_range': [0.1, 0.5],
            'burst_protection': True,
            'adaptive_delays': True,
            'global_rate_limit': 10
        }
    
    def _create_default_quality_filters(self) -> Dict[str, Any]:
        """Create default quality filter settings"""
        return {
            'min_success_rate': 0.3,
            'max_response_time': 10000,
            'exclude_private_ips': True,
            'exclude_localhost': True,
            'min_proxy_count': 5,
            'max_proxy_count': 10000
        }
    
    def _write_three_file_configuration(self, migration_data: Dict[str, Dict[str, Any]], 
                                      force: bool = False) -> List[str]:
        """Write the three configuration files"""
        files_written = []
        
        file_mapping = {
            'api_sources.yaml': migration_data['api_sources'],
            'static_sources.yaml': migration_data['static_sources'],
            'collection_config.yaml': migration_data['collection_config']
        }
        
        for filename, config_data in file_mapping.items():
            file_path = self.config_dir / filename
            
            if file_path.exists() and not force:
                self._log(f"Skipping existing file: {filename}")
                continue
            
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    yaml.dump(config_data, f, default_flow_style=False, indent=2, sort_keys=False)
                
                files_written.append(filename)
                self._log(f"Created: {filename}")
                
            except Exception as e:
                self._log(f"Failed to write {filename}: {e}")
        
        return files_written
    
    def _create_backup(self, legacy_path: Path, existing_files: List[str]) -> List[str]:
        """Create backup of existing files"""
        if not self.backup_dir.exists():
            self.backup_dir.mkdir(parents=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backed_up = []
        
        # Backup legacy file
        if legacy_path.exists():
            backup_name = f"{legacy_path.stem}_{timestamp}{legacy_path.suffix}"
            backup_path = self.backup_dir / backup_name
            shutil.copy2(legacy_path, backup_path)
            backed_up.append(str(backup_path))
            self._log(f"Backed up: {legacy_path.name} -> {backup_name}")
        
        # Backup existing target files
        for filename in existing_files:
            source_path = self.config_dir / filename
            if source_path.exists():
                name_parts = filename.rsplit('.', 1)
                backup_name = f"{name_parts[0]}_{timestamp}.{name_parts[1]}" if len(name_parts) == 2 else f"{filename}_{timestamp}"
                backup_path = self.backup_dir / backup_name
                shutil.copy2(source_path, backup_path)
                backed_up.append(str(backup_path))
                self._log(f"Backed up: {filename} -> {backup_name}")
        
        return backed_up
    
    def _validate_migration(self, legacy_config: Dict[str, Any], 
                          migration_data: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Validate that migration preserved all important data"""
        result = {
            'warnings': [],
            'source_counts': {
                'legacy': 0,
                'migrated': 0
            }
        }
        
        # Count sources in legacy config
        legacy_sources = legacy_config.get('proxy_sources', {})
        legacy_count = 0
        for category in legacy_sources.values():
            if isinstance(category, dict):
                legacy_count += len(category)
        
        # Count sources in migrated config
        api_config = migration_data['api_sources']
        static_config = migration_data['static_sources']
        
        migrated_count = (
            len(api_config.get('free_apis', {})) +
            len(api_config.get('premium_apis', {})) +
            len(api_config.get('custom_apis', {})) +
            len(static_config.get('github_sources', {})) +
            len(static_config.get('text_file_sources', {})) +
            len(static_config.get('html_table_sources', {})) +
            len(static_config.get('custom_static_sources', {}))
        )
        
        result['source_counts']['legacy'] = legacy_count
        result['source_counts']['migrated'] = migrated_count
        
        if legacy_count != migrated_count:
            result['warnings'].append(
                f"Source count mismatch: {legacy_count} in legacy vs {migrated_count} in migrated config"
            )
        
        # Check for lost profiles
        legacy_profiles = legacy_config.get('profiles', {})
        migrated_profiles = migration_data['collection_config'].get('profiles', {})
        
        if len(legacy_profiles) != len(migrated_profiles):
            result['warnings'].append(
                f"Profile count changed: {len(legacy_profiles)} -> {len(migrated_profiles)}"
            )
        
        return result
    
    def _merge_to_legacy_format(self, proxy_config) -> Dict[str, Any]:
        """Convert three-file configuration back to legacy format"""
        legacy_config = {
            'version': proxy_config.version or '1.0',
            'last_updated': datetime.now().isoformat(),
            'proxy_sources': {
                'free': {},
                'premium': {},
                'custom': {}
            }
        }
        
        # Merge sources back to categories
        # Free sources
        legacy_config['proxy_sources']['free'].update(proxy_config.free_sources)
        
        # Premium sources
        legacy_config['proxy_sources']['premium'].update(proxy_config.premium_sources)
        
        # Custom sources
        legacy_config['proxy_sources']['custom'].update(proxy_config.custom_sources)
        
        # Add other settings
        if proxy_config.profiles:
            legacy_config['profiles'] = {
                name: {
                    'name': profile.name,
                    'description': profile.description,
                    'max_duration': profile.max_duration,
                    'max_proxies': profile.max_proxies,
                    'sources': profile.sources,
                    'quality_threshold': profile.quality_threshold,
                    'concurrent_sources': profile.concurrent_sources
                }
                for name, profile in proxy_config.profiles.items()
            }
        
        if proxy_config.collection_defaults:
            legacy_config['collection'] = {
                'defaults': proxy_config.collection_defaults,
                'rate_limiting': proxy_config.rate_limiting,
                'quality_filters': proxy_config.quality_filters
            }
        
        if proxy_config.health_monitoring:
            legacy_config['health_monitoring'] = proxy_config.health_monitoring
        
        if proxy_config.advanced:
            legacy_config['advanced'] = proxy_config.advanced
        
        return legacy_config
    
    def _log(self, message: str):
        """Add message to migration log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.migration_log.append(log_entry)
        logger.info(log_entry)


def create_migration_tool(config_dir: str = None) -> ConfigurationMigrationTool:
    """Create a configuration migration tool instance"""
    if config_dir is None:
        # Default to the config directory relative to this file
        config_dir = Path(__file__).parent
    
    return ConfigurationMigrationTool(config_dir)


def run_interactive_migration():
    """Run interactive migration with user prompts"""
    print("ProxC Configuration Migration Tool")
    print("=" * 50)
    
    # Get config directory
    config_dir = input("Enter configuration directory path (default: current): ").strip()
    if not config_dir:
        config_dir = Path(__file__).parent
    else:
        config_dir = Path(config_dir)
    
    if not config_dir.exists():
        print(f"❌ Configuration directory not found: {config_dir}")
        return 1
    
    # Create migration tool
    migration_tool = ConfigurationMigrationTool(config_dir)
    
    # Check for legacy configuration
    legacy_file = input("Enter legacy configuration filename (default: proxy_sources.yaml): ").strip()
    if not legacy_file:
        legacy_file = "proxy_sources.yaml"
    
    print(f"\n🔍 Analyzing legacy configuration: {legacy_file}")
    analysis = migration_tool.analyze_legacy_configuration(legacy_file)
    
    if not analysis['file_found']:
        print("❌ Legacy configuration file not found")
        return 1
    
    if not analysis['configuration_valid']:
        print("❌ Legacy configuration is not valid")
        return 1
    
    print("✅ Legacy configuration analysis:")
    print(f"   • File size: {analysis['file_size']} bytes")
    
    sources_found = analysis['sources_found']
    if sources_found:
        total_sources = sum(cat['total'] for cat in sources_found.values())
        total_enabled = sum(cat['enabled'] for cat in sources_found.values())
        print(f"   • Sources found: {total_sources} total, {total_enabled} enabled")
        
        for category, stats in sources_found.items():
            print(f"     - {category}: {stats['total']} total, {stats['enabled']} enabled")
    
    if analysis['profiles_found']:
        print(f"   • Profiles: {analysis['profiles_found']['total']}")
    
    if analysis['migration_recommendations']:
        print("\n💡 Migration recommendations:")
        for rec in analysis['migration_recommendations']:
            print(f"   • {rec}")
    
    if analysis['potential_issues']:
        print("\n⚠️  Potential issues:")
        for issue in analysis['potential_issues']:
            print(f"   • {issue}")
    
    # Confirm migration
    print(f"\n🚀 Ready to migrate to three-file structure")
    confirm = input("Proceed with migration? (y/N): ").strip().lower()
    
    if confirm != 'y':
        print("Migration cancelled")
        return 0
    
    # Run migration
    print("\n🔄 Starting migration...")
    result = migration_tool.migrate_legacy_to_three_file(
        legacy_file=legacy_file,
        force=False,
        backup=True
    )
    
    if result['success']:
        print("✅ Migration completed successfully!")
        
        if result['files_created']:
            print(f"📁 Files created:")
            for filename in result['files_created']:
                print(f"   • {filename}")
        
        if result['files_backed_up']:
            print(f"💾 Files backed up:")
            for backup_path in result['files_backed_up']:
                print(f"   • {backup_path}")
        
        if result['warnings']:
            print(f"⚠️  Warnings:")
            for warning in result['warnings']:
                print(f"   • {warning}")
    
    else:
        print("❌ Migration failed!")
        for error in result['errors']:
            print(f"   • {error}")
        return 1
    
    print(f"\n🎉 Migration complete! You can now use the three-file configuration.")
    return 0


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        sys.exit(run_interactive_migration())
    else:
        print("ProxC Configuration Migration Tool")
        print("Usage:")
        print("  python migration_tool.py --interactive    # Run interactive migration")
        print("  python -c 'from migration_tool import ...'  # Use programmatically")