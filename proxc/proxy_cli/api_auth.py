"""API Authentication and Rate Limiting System - Phase 4.2.7 Implementation

This module provides authentication and rate limiting functionality for the REST API,
ensuring secure access control and preventing abuse of API endpoints.
"""

import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

from .cli_base import get_cli_logger
from .cli_exceptions import APIError, CLIErrorHandler


@dataclass
class APIKey:
    """API key data structure"""
    key_id: str
    key_hash: str
    name: str
    permissions: List[str]
    rate_limit: int  # requests per minute
    created_at: datetime
    last_used: Optional[datetime] = None
    is_active: bool = True
    expires_at: Optional[datetime] = None


@dataclass
class RateLimitInfo:
    """Rate limit tracking information"""
    requests: deque
    blocked_until: Optional[datetime] = None
    total_requests: int = 0
    total_blocks: int = 0


class APIKeyManager:
    """Manages API keys and authentication"""
    
    def __init__(self, keys_file: Optional[Path] = None):
        self.logger = get_cli_logger("api_key_manager")
        self.keys_file = keys_file or Path.home() / ".config" / "proxyhunter" / "api_keys.json"
        self.api_keys: Dict[str, APIKey] = {}
        
        # Ensure config directory exists
        self.keys_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing keys
        self._load_keys()
    
    def _load_keys(self):
        """Load API keys from file"""
        try:
            if self.keys_file.exists():
                with open(self.keys_file, 'r') as f:
                    data = json.load(f)
                
                for key_data in data.get('keys', []):
                    api_key = APIKey(
                        key_id=key_data['key_id'],
                        key_hash=key_data['key_hash'],
                        name=key_data['name'],
                        permissions=key_data['permissions'],
                        rate_limit=key_data['rate_limit'],
                        created_at=datetime.fromisoformat(key_data['created_at']),
                        last_used=datetime.fromisoformat(key_data['last_used']) if key_data.get('last_used') else None,
                        is_active=key_data.get('is_active', True),
                        expires_at=datetime.fromisoformat(key_data['expires_at']) if key_data.get('expires_at') else None
                    )
                    self.api_keys[api_key.key_id] = api_key
                
                self.logger.info(f"Loaded {len(self.api_keys)} API keys")
        
        except Exception as e:
            self.logger.error(f"Error loading API keys: {e}")
    
    def _save_keys(self):
        """Save API keys to file"""
        try:
            data = {
                'version': '1.0',
                'keys': []
            }
            
            for api_key in self.api_keys.values():
                key_data = {
                    'key_id': api_key.key_id,
                    'key_hash': api_key.key_hash,
                    'name': api_key.name,
                    'permissions': api_key.permissions,
                    'rate_limit': api_key.rate_limit,
                    'created_at': api_key.created_at.isoformat(),
                    'is_active': api_key.is_active
                }
                
                if api_key.last_used:
                    key_data['last_used'] = api_key.last_used.isoformat()
                if api_key.expires_at:
                    key_data['expires_at'] = api_key.expires_at.isoformat()
                
                data['keys'].append(key_data)
            
            with open(self.keys_file, 'w') as f:
                json.dump(data, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error saving API keys: {e}")
    
    def create_key(self, name: str, permissions: List[str] = None, 
                   rate_limit: int = 100, expires_in_days: Optional[int] = None) -> Tuple[str, str]:
        """Create a new API key"""
        
        # Generate key components
        key_id = secrets.token_urlsafe(16)
        api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Set default permissions if none provided
        if permissions is None:
            permissions = ['read:proxies', 'read:stats', 'read:profiles']
        
        # Calculate expiration
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        
        # Create API key object
        api_key_obj = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            name=name,
            permissions=permissions,
            rate_limit=rate_limit,
            created_at=datetime.utcnow(),
            expires_at=expires_at
        )
        
        # Store the key
        self.api_keys[key_id] = api_key_obj
        self._save_keys()
        
        self.logger.info(f"Created API key '{name}' with ID {key_id}")
        
        # Return the full key (only shown once)
        return f"{key_id}.{api_key}", key_id
    
    def validate_key(self, api_key_string: str) -> Optional[APIKey]:
        """Validate an API key and return the key object if valid"""
        try:
            # Parse key format: key_id.secret
            if '.' not in api_key_string:
                return None
            
            key_id, secret = api_key_string.split('.', 1)
            
            # Find key
            if key_id not in self.api_keys:
                return None
            
            api_key = self.api_keys[key_id]
            
            # Check if key is active
            if not api_key.is_active:
                return None
            
            # Check expiration
            if api_key.expires_at and datetime.utcnow() > api_key.expires_at:
                return None
            
            # Validate hash
            secret_hash = hashlib.sha256(secret.encode()).hexdigest()
            if not hmac.compare_digest(secret_hash, api_key.key_hash):
                return None
            
            # Update last used
            api_key.last_used = datetime.utcnow()
            self._save_keys()
            
            return api_key
            
        except Exception as e:
            self.logger.error(f"Error validating API key: {e}")
            return None
    
    def revoke_key(self, key_id: str) -> bool:
        """Revoke an API key"""
        if key_id in self.api_keys:
            self.api_keys[key_id].is_active = False
            self._save_keys()
            self.logger.info(f"Revoked API key {key_id}")
            return True
        return False
    
    def list_keys(self) -> List[Dict[str, Any]]:
        """List all API keys (without secrets)"""
        keys_info = []
        for api_key in self.api_keys.values():
            keys_info.append({
                'key_id': api_key.key_id,
                'name': api_key.name,
                'permissions': api_key.permissions,
                'rate_limit': api_key.rate_limit,
                'created_at': api_key.created_at.isoformat(),
                'last_used': api_key.last_used.isoformat() if api_key.last_used else None,
                'is_active': api_key.is_active,
                'expires_at': api_key.expires_at.isoformat() if api_key.expires_at else None
            })
        return keys_info
    
    def has_permission(self, api_key: APIKey, permission: str) -> bool:
        """Check if an API key has a specific permission"""
        # Check for wildcard permissions
        if '*' in api_key.permissions or 'admin:*' in api_key.permissions:
            return True
        
        # Check exact permission
        if permission in api_key.permissions:
            return True
        
        # Check wildcard within category (e.g., 'read:*' matches 'read:proxies')
        category = permission.split(':')[0]
        if f"{category}:*" in api_key.permissions:
            return True
        
        return False


class RateLimiter:
    """Rate limiting system for API requests"""
    
    def __init__(self):
        self.logger = get_cli_logger("rate_limiter")
        self.limits: Dict[str, RateLimitInfo] = defaultdict(lambda: RateLimitInfo(requests=deque()))
        self.global_limits: Dict[str, RateLimitInfo] = defaultdict(lambda: RateLimitInfo(requests=deque()))
        
        # Global rate limits (requests per minute)
        self.global_rate_limits = {
            'default': 1000,  # Default limit for anonymous requests
            'burst': 50       # Burst protection
        }
        
        # Cleanup old entries periodically
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes
    
    def is_allowed(self, identifier: str, rate_limit: int, 
                   window_seconds: int = 60) -> Tuple[bool, Dict[str, Any]]:
        """Check if a request is allowed under rate limits"""
        
        current_time = time.time()
        
        # Cleanup old entries
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries()
            self.last_cleanup = current_time
        
        # Get or create rate limit info
        limit_info = self.limits[identifier]
        
        # Check if currently blocked
        if limit_info.blocked_until and datetime.utcnow() < limit_info.blocked_until:
            return False, {
                'allowed': False,
                'reason': 'blocked',
                'blocked_until': limit_info.blocked_until.isoformat(),
                'retry_after': int((limit_info.blocked_until - datetime.utcnow()).total_seconds())
            }
        
        # Remove old requests outside the time window
        window_start = current_time - window_seconds
        while limit_info.requests and limit_info.requests[0] < window_start:
            limit_info.requests.popleft()
        
        # Check rate limit
        request_count = len(limit_info.requests)
        
        if request_count >= rate_limit:
            # Rate limit exceeded - apply temporary block
            block_duration = min(60, request_count * 2)  # Block for up to 60 seconds
            limit_info.blocked_until = datetime.utcnow() + timedelta(seconds=block_duration)
            limit_info.total_blocks += 1
            
            self.logger.warning(f"Rate limit exceeded for {identifier}: {request_count}/{rate_limit}")
            
            return False, {
                'allowed': False,
                'reason': 'rate_limit_exceeded',
                'limit': rate_limit,
                'current': request_count,
                'window_seconds': window_seconds,
                'blocked_until': limit_info.blocked_until.isoformat(),
                'retry_after': block_duration
            }
        
        # Allow request and record it
        limit_info.requests.append(current_time)
        limit_info.total_requests += 1
        
        return True, {
            'allowed': True,
            'limit': rate_limit,
            'remaining': rate_limit - request_count - 1,
            'window_seconds': window_seconds,
            'reset_time': int(current_time + window_seconds)
        }
    
    def _cleanup_old_entries(self):
        """Clean up old rate limit entries to prevent memory leaks"""
        current_time = time.time()
        cleanup_threshold = current_time - 3600  # Remove entries older than 1 hour
        
        # Clean up individual limits
        keys_to_remove = []
        for key, limit_info in self.limits.items():
            # Remove old requests
            while limit_info.requests and limit_info.requests[0] < cleanup_threshold:
                limit_info.requests.popleft()
            
            # Remove empty entries
            if (not limit_info.requests and 
                (not limit_info.blocked_until or datetime.utcnow() > limit_info.blocked_until)):
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.limits[key]
        
        self.logger.debug(f"Cleaned up {len(keys_to_remove)} old rate limit entries")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics"""
        total_requests = sum(info.total_requests for info in self.limits.values())
        total_blocks = sum(info.total_blocks for info in self.limits.values())
        active_limits = len([info for info in self.limits.values() if info.requests])
        
        return {
            'total_requests': total_requests,
            'total_blocks': total_blocks,
            'active_limits': active_limits,
            'tracked_identifiers': len(self.limits)
        }


class APIAuthenticator:
    """Main API authentication and authorization handler"""
    
    def __init__(self):
        self.logger = get_cli_logger("api_authenticator")
        self.error_handler = CLIErrorHandler(self.logger)
        self.key_manager = APIKeyManager()
        self.rate_limiter = RateLimiter()
    
    def authenticate_request(self, headers: Dict[str, str], 
                           client_ip: str = None) -> Tuple[bool, Optional[APIKey], Dict[str, Any]]:
        """Authenticate an API request"""
        
        # Extract API key from headers
        api_key_string = None
        
        # Check Authorization header (Bearer token)
        auth_header = headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            api_key_string = auth_header[7:]
        
        # Check X-API-Key header
        elif 'X-API-Key' in headers:
            api_key_string = headers['X-API-Key']
        
        # No API key provided - allow limited anonymous access
        if not api_key_string:
            client_identifier = client_ip or 'anonymous'
            rate_limit = self.rate_limiter.global_rate_limits['default']
            
            allowed, rate_info = self.rate_limiter.is_allowed(
                f"anon:{client_identifier}", 
                rate_limit=50,  # Lower limit for anonymous
                window_seconds=60
            )
            
            return allowed, None, {
                'authenticated': False,
                'rate_limit': rate_info,
                'permissions': ['read:stats']  # Very limited permissions
            }
        
        # Validate API key
        api_key = self.key_manager.validate_key(api_key_string)
        if not api_key:
            return False, None, {
                'authenticated': False,
                'error': 'invalid_api_key',
                'message': 'Invalid or expired API key'
            }
        
        # Check rate limits
        allowed, rate_info = self.rate_limiter.is_allowed(
            f"key:{api_key.key_id}",
            rate_limit=api_key.rate_limit,
            window_seconds=60
        )
        
        if not allowed:
            return False, api_key, {
                'authenticated': True,
                'rate_limit': rate_info,
                'error': 'rate_limit_exceeded'
            }
        
        # Successful authentication
        return True, api_key, {
            'authenticated': True,
            'key_id': api_key.key_id,
            'permissions': api_key.permissions,
            'rate_limit': rate_info
        }
    
    def check_permission(self, api_key: Optional[APIKey], required_permission: str) -> bool:
        """Check if the API key has the required permission"""
        
        if not api_key:
            # Anonymous permissions
            anonymous_permissions = ['read:stats']
            return required_permission in anonymous_permissions
        
        return self.key_manager.has_permission(api_key, required_permission)
    
    def get_rate_limit_headers(self, auth_info: Dict[str, Any]) -> Dict[str, str]:
        """Get rate limit headers to include in response"""
        headers = {}
        
        if 'rate_limit' in auth_info:
            rate_info = auth_info['rate_limit']
            
            if rate_info.get('allowed', True):
                headers['X-RateLimit-Limit'] = str(rate_info.get('limit', 0))
                headers['X-RateLimit-Remaining'] = str(rate_info.get('remaining', 0))
                headers['X-RateLimit-Reset'] = str(rate_info.get('reset_time', 0))
            else:
                headers['X-RateLimit-Limit'] = str(rate_info.get('limit', 0))
                headers['X-RateLimit-Remaining'] = '0'
                headers['Retry-After'] = str(rate_info.get('retry_after', 60))
        
        return headers


# Permission constants
class APIPermissions:
    """API permission constants"""
    
    # Read permissions
    READ_PROXIES = 'read:proxies'
    READ_STATS = 'read:stats'
    READ_PROFILES = 'read:profiles'
    READ_VALIDATION = 'read:validation'
    
    # Write permissions
    WRITE_PROXIES = 'write:proxies'
    WRITE_PROFILES = 'write:profiles'
    WRITE_VALIDATION = 'write:validation'
    
    # Admin permissions
    ADMIN_KEYS = 'admin:keys'
    ADMIN_SYSTEM = 'admin:system'
    
    # Wildcard permissions
    READ_ALL = 'read:*'
    WRITE_ALL = 'write:*'
    ADMIN_ALL = 'admin:*'
    ALL = '*'


# Default permission sets
DEFAULT_PERMISSION_SETS = {
    'readonly': [
        APIPermissions.READ_PROXIES,
        APIPermissions.READ_STATS,
        APIPermissions.READ_PROFILES
    ],
    'readwrite': [
        APIPermissions.READ_PROXIES,
        APIPermissions.READ_STATS,
        APIPermissions.READ_PROFILES,
        APIPermissions.WRITE_PROXIES,
        APIPermissions.WRITE_VALIDATION
    ],
    'admin': [
        APIPermissions.ALL
    ]
}