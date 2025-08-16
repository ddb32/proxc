"""Configuration Profiles System - Phase 4 Implementation

This module implements the configuration profile system that allows users to
invoke complex proxy operations using simple profile names, dramatically
reducing CLI verbosity while maintaining full customization capabilities.
"""

import json
import yaml
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime

from .cli_base import get_cli_logger
from .cli_exceptions import CommandError, ConfigurationError

logger = get_cli_logger("profiles")

# Built-in profiles directory  
BUILTIN_PROFILES_DIR = Path(__file__).parent / "profiles"
USER_PROFILES_DIR = Path.home() / ".config" / "proxc" / "profiles"

class ProfileManager:
    """Manage configuration profiles for common workflows"""
    
    def __init__(self):
        self.builtin_profiles = {}
        self.user_profiles = {}
        self.shared_profiles = {}
        self._load_profiles()
    
    def _load_profiles(self):
        """Load all available profiles"""
        # Load built-in profiles
        if BUILTIN_PROFILES_DIR.exists():
            for profile_file in BUILTIN_PROFILES_DIR.glob("*.yaml"):
                try:
                    profile = self._load_profile_file(profile_file)
                    self.builtin_profiles[profile['profile']] = profile
                except Exception as e:
                    logger.warning(f"Failed to load built-in profile {profile_file}: {e}")
        
        # Load user profiles
        user_dir = USER_PROFILES_DIR / "user"
        if user_dir.exists():
            for profile_file in user_dir.glob("*.yaml"):
                try:
                    profile = self._load_profile_file(profile_file)
                    self.user_profiles[profile['profile']] = profile
                except Exception as e:
                    logger.warning(f"Failed to load user profile {profile_file}: {e}")
        
        # Load shared profiles
        shared_dir = USER_PROFILES_DIR / "shared" 
        if shared_dir.exists():
            for profile_file in shared_dir.glob("*.yaml"):
                try:
                    profile = self._load_profile_file(profile_file)
                    self.shared_profiles[profile['profile']] = profile
                except Exception as e:
                    logger.warning(f"Failed to load shared profile {profile_file}: {e}")
    
    def _load_profile_file(self, file_path: Path) -> Dict:
        """Load a single profile file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            profile = yaml.safe_load(f)
        
        # Validate required fields
        required_fields = ['profile', 'description', 'commands']
        for field in required_fields:
            if field not in profile:
                raise ConfigurationError(f"Profile missing required field: {field}")
        
        # Add metadata
        profile['_source'] = str(file_path)
        profile['_loaded_at'] = datetime.now().isoformat()
        
        return profile
    
    def list_profiles(self, category: Optional[str] = None, tags: Optional[List[str]] = None) -> Dict[str, List]:
        """List available profiles with optional filtering"""
        all_profiles = {
            'builtin': self.builtin_profiles,
            'user': self.user_profiles, 
            'shared': self.shared_profiles
        }
        
        filtered_profiles = {
            'builtin': {},
            'user': {},
            'shared': {}
        }
        
        for profile_type, profiles in all_profiles.items():
            for name, profile in profiles.items():
                # Apply category filter
                if category:
                    profile_category = profile.get('category', 'general')
                    if category.lower() != profile_category.lower():
                        continue
                
                # Apply tags filter
                if tags:
                    profile_tags = profile.get('tags', [])
                    if not any(tag in profile_tags for tag in tags):
                        continue
                
                filtered_profiles[profile_type][name] = profile
        
        return filtered_profiles
    
    def get_profile(self, name: str) -> Optional[Dict]:
        """Get a specific profile by name"""
        # Check user profiles first (override built-in)
        if name in self.user_profiles:
            return self.user_profiles[name]
        elif name in self.shared_profiles:
            return self.shared_profiles[name]
        elif name in self.builtin_profiles:
            return self.builtin_profiles[name]
        else:
            return None
    
    def execute_profile(self, name: str, overrides: Dict[str, Any] = None, 
                       environment: Dict[str, str] = None) -> List[str]:
        """Execute a profile and return the generated commands"""
        profile = self.get_profile(name)
        if not profile:
            raise CommandError(f"Profile not found: {name}")
        
        overrides = overrides or {}
        environment = environment or {}
        
        # Merge environment variables
        env_vars = {**os.environ, **environment}
        
        # Apply profile inheritance
        if 'inherit' in profile:
            base_profile = self.get_profile(profile['inherit'])
            if base_profile:
                profile = self._merge_profiles(base_profile, profile)
        
        # Get defaults and apply overrides
        defaults = profile.get('defaults', {})
        defaults.update(overrides)
        
        # Validate required parameters
        required = profile.get('required', [])
        missing_required = []
        for param in required:
            if param not in defaults and param.replace('-', '_') not in env_vars:
                missing_required.append(param)
        
        if missing_required:
            raise CommandError(f"Missing required parameters: {', '.join(missing_required)}")
        
        # Process commands with variable substitution
        commands = []
        for command_template in profile['commands']:
            if isinstance(command_template, dict):
                # Handle conditional commands
                if 'if' in command_template:
                    condition = self._evaluate_condition(command_template['if'], defaults, env_vars)
                    if condition and 'then' in command_template:
                        command_template = command_template['then']
                    else:
                        continue
            
            # Substitute variables
            command = self._substitute_variables(command_template, defaults, env_vars, profile.get('variables', {}))
            commands.append(command)
        
        return commands
    
    def _merge_profiles(self, base: Dict, override: Dict) -> Dict:
        """Merge profile inheritance"""
        merged = base.copy()
        
        # Merge defaults
        if 'defaults' in override:
            merged_defaults = merged.get('defaults', {})
            merged_defaults.update(override['defaults'])
            merged['defaults'] = merged_defaults
        
        # Apply overrides
        if 'overrides' in override:
            overrides_section = override['overrides']
            for key, value in overrides_section.items():
                merged[key] = value
        
        # Handle command modifications
        if 'commands' in override:
            if isinstance(override['commands'], dict):
                if 'append' in override['commands']:
                    merged['commands'] = merged.get('commands', []) + override['commands']['append']
                elif 'replace' in override['commands']:
                    merged['commands'] = override['commands']['replace']
            else:
                merged['commands'] = override['commands']
        
        return merged
    
    def _substitute_variables(self, template: str, defaults: Dict, env_vars: Dict, variables: Dict) -> str:
        """Substitute variables in command template"""
        import re
        
        # Combine all variable sources
        all_vars = {**variables, **defaults, **env_vars}
        
        # Handle ${VAR} and ${VAR:-default} patterns
        def replace_var(match):
            var_expr = match.group(1)
            if ':-' in var_expr:
                var_name, default_value = var_expr.split(':-', 1)
                return all_vars.get(var_name, default_value)
            else:
                return all_vars.get(var_expr, f"${{{var_expr}}}")  # Keep unresolved
        
        result = re.sub(r'\$\{([^}]+)\}', replace_var, template)
        return result
    
    def _evaluate_condition(self, condition: str, defaults: Dict, env_vars: Dict) -> bool:
        """Evaluate conditional expressions (simplified)"""
        # Very basic condition evaluation - real implementation would be more sophisticated
        all_vars = {**defaults, **env_vars}
        
        # Handle simple boolean conditions
        if condition in all_vars:
            value = all_vars[condition]
            if isinstance(value, bool):
                return value
            elif isinstance(value, str):
                return value.lower() in ['true', '1', 'yes', 'on']
        
        return False
    
    def create_profile(self, name: str, config: Dict, profile_type: str = 'user') -> bool:
        """Create a new profile"""
        if profile_type not in ['user', 'shared']:
            raise ValueError("Profile type must be 'user' or 'shared'")
        
        # Ensure profile directory exists
        if profile_type == 'user':
            profile_dir = USER_PROFILES_DIR / "user"
        else:
            profile_dir = USER_PROFILES_DIR / "shared"
        
        profile_dir.mkdir(parents=True, exist_ok=True)
        
        # Add metadata to config
        config['profile'] = name
        config['created_at'] = datetime.now().isoformat()
        config['version'] = config.get('version', '1.0')
        
        # Write profile file
        profile_file = profile_dir / f"{name}.yaml"
        try:
            with open(profile_file, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            
            # Reload profiles to include the new one
            self._load_profiles()
            return True
            
        except Exception as e:
            logger.error(f"Failed to create profile {name}: {e}")
            return False
    
    def suggest_profiles(self, command_history: List[str] = None, criteria: str = None) -> List[Dict]:
        """Suggest profiles based on usage patterns or criteria"""
        suggestions = []
        
        if criteria:
            # Simple keyword-based suggestions
            criteria_lower = criteria.lower()
            for profile_name, profile in self.builtin_profiles.items():
                description = profile.get('description', '').lower()
                tags = profile.get('tags', [])
                
                if (criteria_lower in description or 
                    any(criteria_lower in tag.lower() for tag in tags)):
                    
                    suggestions.append({
                        'name': profile_name,
                        'description': profile['description'],
                        'match_reason': 'keyword match',
                        'tags': tags
                    })
        
        # Add default recommendations
        if not suggestions:
            default_suggestions = [
                'quick-scan', 'secure-scan', 'enterprise-scan', 'production-quality'
            ]
            for name in default_suggestions:
                if name in self.builtin_profiles:
                    profile = self.builtin_profiles[name]
                    suggestions.append({
                        'name': name,
                        'description': profile['description'],
                        'match_reason': 'popular choice',
                        'tags': profile.get('tags', [])
                    })
        
        return suggestions


# Built-in profile definitions
BUILTIN_PROFILE_DEFINITIONS = {
    'quick-scan': {
        'profile': 'quick-scan',
        'version': '1.0',
        'description': 'Fast proxy discovery with basic validation',
        'category': 'quick',
        'tags': ['fast', 'basic', 'discovery'],
        'commands': [
            'discover scan --count ${COUNT:-200} --validate --threads ${THREADS:-10}'
        ],
        'defaults': {
            'timeout': 10,
            'format': 'json'
        },
        'optional': {
            'count': 200,
            'threads': 10
        }
    },
    
    'secure-scan': {
        'profile': 'secure-scan',
        'version': '1.0', 
        'description': 'Security-focused proxy discovery with comprehensive analysis',
        'category': 'security',
        'tags': ['security', 'analysis', 'fingerprinting'],
        'commands': [
            'discover scan --fingerprint --intelligence --count ${COUNT:-500}',
            'validate test --force-socks5 --strict --success-rate ${SUCCESS_RATE:-0.8}',
            'analyze threat --detect-chains --threat-level ${THREAT_LEVEL:-low} --max-depth 3'
        ],
        'defaults': {
            'threads': 12,
            'confidence': 0.8,
            'format': 'json'
        },
        'optional': {
            'count': 500,
            'success-rate': 0.8,
            'threat-level': 'low'
        }
    },
    
    'enterprise-scan': {
        'profile': 'enterprise-scan',
        'version': '1.0',
        'description': 'Enterprise-grade proxy collection with API export',
        'category': 'enterprise',
        'tags': ['enterprise', 'production', 'api'],
        'commands': [
            'discover scan --fingerprint --intelligence --count ${COUNT:-2000} --validate',
            'validate test --force-socks5 --strict --success-rate 0.9 --target-parallel',
            'analyze threat --detect-chains --threat-level low',
            'export api --api-url ${API_URL} --api-auth bearer --api-token ${API_TOKEN} --batch-size 100 --retry-failed'
        ],
        'defaults': {
            'threads': 25,
            'timeout': 20,
            'adaptive': True
        },
        'required': ['api-url', 'api-token'],
        'optional': {
            'count': 2000
        }
    }
}


def ensure_builtin_profiles():
    """Ensure built-in profiles are available"""
    builtin_dir = BUILTIN_PROFILES_DIR
    if not builtin_dir.exists():
        builtin_dir.mkdir(parents=True, exist_ok=True)
        
        # Create built-in profile files
        for profile_name, profile_config in BUILTIN_PROFILE_DEFINITIONS.items():
            profile_file = builtin_dir / f"{profile_name}.yaml"
            if not profile_file.exists():
                try:
                    with open(profile_file, 'w', encoding='utf-8') as f:
                        yaml.dump(profile_config, f, default_flow_style=False, sort_keys=False)
                except Exception as e:
                    logger.warning(f"Failed to create built-in profile {profile_name}: {e}")


# Initialize built-in profiles on module import
try:
    ensure_builtin_profiles()
except Exception as e:
    logger.warning(f"Failed to initialize built-in profiles: {e}")


if __name__ == '__main__':
    # Simple test interface
    manager = ProfileManager()
    
    print("Available profiles:")
    profiles = manager.list_profiles()
    for profile_type, profile_list in profiles.items():
        if profile_list:
            print(f"\n{profile_type.title()}:")
            for name, profile in profile_list.items():
                print(f"  {name}: {profile['description']}")
    
    if len(sys.argv) > 1:
        profile_name = sys.argv[1]
        print(f"\nExecuting profile: {profile_name}")
        try:
            commands = manager.execute_profile(profile_name)
            for i, cmd in enumerate(commands, 1):
                print(f"  {i}. {cmd}")
        except Exception as e:
            print(f"Error: {e}")