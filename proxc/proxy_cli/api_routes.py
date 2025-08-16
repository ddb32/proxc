"""REST API Routes - Phase 4.2.7 Implementation

This module implements RESTful API endpoints for programmatic access to the proxy
hunter system, enabling integration with external applications and automation scripts.
"""

import json
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import parse_qs, urlparse

from .cli_base import get_cli_logger
from .cli_exceptions import APIError, CLIErrorHandler
from .api_auth import APIAuthenticator, APIPermissions
from ..proxy_core.models import ProxyInfo, ProxyProtocol, ProxyStatus, ValidationStatus


class APIRouter:
    """RESTful API router for programmatic access"""
    
    def __init__(self, data_handler):
        self.data_handler = data_handler
        self.logger = get_cli_logger("api_router")
        self.error_handler = CLIErrorHandler(self.logger)
        
        # API versioning
        self.api_version = "v1"
        self.base_path = f"/api/{self.api_version}"
        
        # Authentication and authorization
        self.authenticator = APIAuthenticator()
        
    def route_api_request(self, path: str, method: str, query_params: Dict[str, list], 
                         headers: Dict[str, str] = None, body: bytes = None) -> Tuple[int, str, bytes]:
        """Route API requests to appropriate handlers with authentication"""
        try:
            headers = headers or {}
            
            # Extract client IP for rate limiting (simplified)
            client_ip = headers.get('X-Forwarded-For', '127.0.0.1')
            
            # Authenticate request
            is_allowed, api_key, auth_info = self.authenticator.authenticate_request(headers, client_ip)
            
            # Check if authentication failed
            if not is_allowed:
                response = {
                    'success': False,
                    'error': auth_info.get('error', 'authentication_failed'),
                    'message': auth_info.get('message', 'Authentication failed'),
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                status_code = 429 if 'rate_limit' in auth_info.get('error', '') else 401
                response_headers = self.authenticator.get_rate_limit_headers(auth_info)
                
                json_response = json.dumps(response).encode('utf-8')
                
                # Add rate limit headers to response if needed
                # Note: This is a simplified implementation - full implementation would 
                # modify the web server to support custom headers
                return status_code, 'application/json', json_response
            
            # Remove base path if present
            if path.startswith(self.base_path):
                path = path[len(self.base_path):]
            
            # Route to appropriate endpoint with permission check
            if path.startswith('/proxies'):
                return self._route_proxies(path, method, query_params, headers, body, api_key, auth_info)
            elif path.startswith('/validation'):
                return self._route_validation(path, method, query_params, headers, body, api_key, auth_info)
            elif path.startswith('/export'):
                return self._route_export(path, method, query_params, headers, body, api_key, auth_info)
            elif path.startswith('/stats'):
                return self._route_stats(path, method, query_params, headers, body, api_key, auth_info)
            elif path.startswith('/profiles'):
                return self._route_profiles(path, method, query_params, headers, body, api_key, auth_info)
            elif path.startswith('/auth'):
                return self._route_auth(path, method, query_params, headers, body, api_key, auth_info)
            else:
                return self._api_404()
                
        except Exception as e:
            api_error = APIError(f"API routing error for {method} {path}", endpoint=path, method=method)
            self.error_handler.handle_error(api_error, context={'query_params': query_params})
            return self._api_500(str(api_error))
    
    def _route_proxies(self, path: str, method: str, query_params: Dict[str, list], 
                      headers: Dict[str, str], body: bytes, api_key, auth_info) -> Tuple[int, str, bytes]:
        """Handle /proxies endpoints"""
        
        if path == '/proxies' or path == '/proxies/':
            if method == 'GET':
                if not self._check_permission(api_key, APIPermissions.READ_PROXIES):
                    return self._api_403("Insufficient permissions to read proxies")
                return self._get_proxies(query_params)
            elif method == 'POST':
                if not self._check_permission(api_key, APIPermissions.WRITE_PROXIES):
                    return self._api_403("Insufficient permissions to create proxies")
                return self._create_proxy(body)
            else:
                return self._method_not_allowed(['GET', 'POST'])
                
        elif path.startswith('/proxies/'):
            proxy_id = path.split('/')[-1]
            if method == 'GET':
                return self._get_proxy(proxy_id)
            elif method == 'PUT':
                return self._update_proxy(proxy_id, body)
            elif method == 'DELETE':
                return self._delete_proxy(proxy_id)
            else:
                return self._method_not_allowed(['GET', 'PUT', 'DELETE'])
        
        return self._api_404()
    
    def _route_validation(self, path: str, method: str, query_params: Dict[str, list], 
                         headers: Dict[str, str], body: bytes, api_key, auth_info) -> Tuple[int, str, bytes]:
        """Handle /validation endpoints"""
        
        if path == '/validation/start':
            if method == 'POST':
                return self._start_validation(body)
            else:
                return self._method_not_allowed(['POST'])
                
        elif path == '/validation/status':
            if method == 'GET':
                return self._get_validation_status(query_params)
            else:
                return self._method_not_allowed(['GET'])
                
        elif path.startswith('/validation/'):
            validation_id = path.split('/')[-1]
            if method == 'GET':
                return self._get_validation_result(validation_id)
            else:
                return self._method_not_allowed(['GET'])
        
        return self._api_404()
    
    def _route_export(self, path: str, method: str, query_params: Dict[str, list], 
                     headers: Dict[str, str], body: bytes, api_key, auth_info) -> Tuple[int, str, bytes]:
        """Handle /export endpoints"""
        
        if path == '/export' or path == '/export/':
            if method == 'GET':
                if not self._check_permission(api_key, APIPermissions.READ_PROXIES):
                    return self._api_403("Insufficient permissions to export proxies")
                return self._export_proxies(query_params)
            else:
                return self._method_not_allowed(['GET'])
        
        return self._api_404()
    
    def _route_stats(self, path: str, method: str, query_params: Dict[str, list], 
                    headers: Dict[str, str], body: bytes, api_key, auth_info) -> Tuple[int, str, bytes]:
        """Handle /stats endpoints"""
        
        if path == '/stats' or path == '/stats/':
            if method == 'GET':
                if not self._check_permission(api_key, APIPermissions.READ_STATS):
                    return self._api_403("Insufficient permissions to read statistics")
                return self._get_stats(query_params)
            else:
                return self._method_not_allowed(['GET'])
                
        elif path == '/stats/summary':
            if method == 'GET':
                if not self._check_permission(api_key, APIPermissions.READ_STATS):
                    return self._api_403("Insufficient permissions to read statistics")
                return self._get_stats_summary()
            else:
                return self._method_not_allowed(['GET'])
        
        return self._api_404()
    
    def _route_profiles(self, path: str, method: str, query_params: Dict[str, list], 
                       headers: Dict[str, str], body: bytes, api_key, auth_info) -> Tuple[int, str, bytes]:
        """Handle /profiles endpoints"""
        
        if path == '/profiles' or path == '/profiles/':
            if method == 'GET':
                if not self._check_permission(api_key, APIPermissions.READ_PROFILES):
                    return self._api_403("Insufficient permissions to read profiles")
                return self._get_profiles(query_params)
            elif method == 'POST':
                if not self._check_permission(api_key, APIPermissions.WRITE_PROFILES):
                    return self._api_403("Insufficient permissions to create profiles")
                return self._create_profile(body)
            else:
                return self._method_not_allowed(['GET', 'POST'])
                
        elif path.startswith('/profiles/'):
            profile_name = path.split('/')[-1]
            if method == 'GET':
                if not self._check_permission(api_key, APIPermissions.READ_PROFILES):
                    return self._api_403("Insufficient permissions to read profiles")
                return self._get_profile(profile_name)
            elif method == 'POST':  # Execute profile
                if not self._check_permission(api_key, APIPermissions.WRITE_VALIDATION):
                    return self._api_403("Insufficient permissions to execute profiles")
                return self._execute_profile(profile_name, body)
            else:
                return self._method_not_allowed(['GET', 'POST'])
        
        return self._api_404()
    
    def _route_auth(self, path: str, method: str, query_params: Dict[str, list], 
                   headers: Dict[str, str], body: bytes, api_key, auth_info) -> Tuple[int, str, bytes]:
        """Handle /auth endpoints for API key management"""
        
        if path == '/auth/keys' or path == '/auth/keys/':
            if method == 'GET':
                if not self._check_permission(api_key, APIPermissions.ADMIN_KEYS):
                    return self._api_403("Insufficient permissions to list API keys")
                return self._list_api_keys()
            elif method == 'POST':
                if not self._check_permission(api_key, APIPermissions.ADMIN_KEYS):
                    return self._api_403("Insufficient permissions to create API keys")
                return self._create_api_key(body)
            else:
                return self._method_not_allowed(['GET', 'POST'])
                
        elif path.startswith('/auth/keys/'):
            key_id = path.split('/')[-1]
            if method == 'DELETE':
                if not self._check_permission(api_key, APIPermissions.ADMIN_KEYS):
                    return self._api_403("Insufficient permissions to revoke API keys")
                return self._revoke_api_key(key_id)
            else:
                return self._method_not_allowed(['DELETE'])
        
        return self._api_404()
    
    def _check_permission(self, api_key, required_permission: str) -> bool:
        """Check if the API key has the required permission"""
        return self.authenticator.check_permission(api_key, required_permission)
    
    # Proxy CRUD operations
    def _get_proxies(self, query_params: Dict[str, list]) -> Tuple[int, str, bytes]:
        """GET /proxies - List proxies with filtering and pagination"""
        try:
            # Parse query parameters
            filters = {}
            limit = int(query_params.get('limit', ['100'])[0])
            offset = int(query_params.get('offset', ['0'])[0])
            
            # Apply filters
            for key in ['status', 'protocol', 'country', 'anonymity_level', 'threat_level']:
                if key in query_params:
                    filters[key] = query_params[key][0]
            
            # Get paginated results
            data = self.data_handler.get_proxies_json(filters, limit, offset)
            
            # Add API metadata
            api_response = {
                'success': True,
                'data': data,
                'pagination': {
                    'limit': limit,
                    'offset': offset,
                    'total': data.get('total_count', 0),
                    'has_more': data.get('has_more', False)
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return 200, 'application/json', json.dumps(api_response, indent=2).encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error getting proxies: {e}")
            return self._api_500("Failed to retrieve proxies")
    
    def _get_proxy(self, proxy_id: str) -> Tuple[int, str, bytes]:
        """GET /proxies/{id} - Get specific proxy"""
        try:
            # Find proxy by ID
            proxy = None
            for p in self.data_handler.proxies:
                if p.proxy_id == proxy_id:
                    proxy = p
                    break
            
            if not proxy:
                return self._api_404("Proxy not found")
            
            # Convert to dict
            proxy_data = self.data_handler._proxy_to_dict(proxy, include_all=True)
            
            api_response = {
                'success': True,
                'data': proxy_data,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return 200, 'application/json', json.dumps(api_response, indent=2).encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error getting proxy {proxy_id}: {e}")
            return self._api_500("Failed to retrieve proxy")
    
    def _create_proxy(self, body: bytes) -> Tuple[int, str, bytes]:
        """POST /proxies - Create new proxy"""
        try:
            if not body:
                return self._api_400("Request body is required")
            
            data = json.loads(body.decode('utf-8'))
            
            # Validate required fields
            required_fields = ['host', 'port', 'protocol']
            for field in required_fields:
                if field not in data:
                    return self._api_400(f"Missing required field: {field}")
            
            # Create proxy object
            proxy = ProxyInfo(
                host=data['host'],
                port=int(data['port']),
                protocol=ProxyProtocol(data['protocol'].lower()),
                username=data.get('username'),
                password=data.get('password'),
                source=data.get('source', 'api')
            )
            
            # Add to collection
            self.data_handler.proxies.append(proxy)
            
            api_response = {
                'success': True,
                'data': self.data_handler._proxy_to_dict(proxy, include_all=True),
                'message': 'Proxy created successfully',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return 201, 'application/json', json.dumps(api_response, indent=2).encode('utf-8')
            
        except json.JSONDecodeError:
            return self._api_400("Invalid JSON in request body")
        except ValueError as e:
            return self._api_400(f"Invalid data: {e}")
        except Exception as e:
            self.logger.error(f"Error creating proxy: {e}")
            return self._api_500("Failed to create proxy")
    
    def _update_proxy(self, proxy_id: str, body: bytes) -> Tuple[int, str, bytes]:
        """PUT /proxies/{id} - Update proxy"""
        try:
            if not body:
                return self._api_400("Request body is required")
            
            data = json.loads(body.decode('utf-8'))
            
            # Find proxy
            proxy = None
            for p in self.data_handler.proxies:
                if p.proxy_id == proxy_id:
                    proxy = p
                    break
            
            if not proxy:
                return self._api_404("Proxy not found")
            
            # Update fields
            updatable_fields = ['username', 'password', 'source', 'notes']
            for field in updatable_fields:
                if field in data:
                    setattr(proxy, field, data[field])
            
            proxy.last_updated = datetime.utcnow()
            
            api_response = {
                'success': True,
                'data': self.data_handler._proxy_to_dict(proxy, include_all=True),
                'message': 'Proxy updated successfully',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return 200, 'application/json', json.dumps(api_response, indent=2).encode('utf-8')
            
        except json.JSONDecodeError:
            return self._api_400("Invalid JSON in request body")
        except Exception as e:
            self.logger.error(f"Error updating proxy {proxy_id}: {e}")
            return self._api_500("Failed to update proxy")
    
    def _delete_proxy(self, proxy_id: str) -> Tuple[int, str, bytes]:
        """DELETE /proxies/{id} - Delete proxy"""
        try:
            # Find and remove proxy
            for i, proxy in enumerate(self.data_handler.proxies):
                if proxy.proxy_id == proxy_id:
                    del self.data_handler.proxies[i]
                    
                    api_response = {
                        'success': True,
                        'message': 'Proxy deleted successfully',
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    
                    return 200, 'application/json', json.dumps(api_response).encode('utf-8')
            
            return self._api_404("Proxy not found")
            
        except Exception as e:
            self.logger.error(f"Error deleting proxy {proxy_id}: {e}")
            return self._api_500("Failed to delete proxy")
    
    # Validation endpoints
    def _start_validation(self, body: bytes) -> Tuple[int, str, bytes]:
        """POST /validation/start - Start validation process"""
        try:
            validation_id = str(uuid.uuid4())
            
            # Parse validation parameters if provided
            config = {}
            if body:
                config = json.loads(body.decode('utf-8'))
            
            # TODO: Integrate with actual validation engine
            # For now, return mock response
            
            api_response = {
                'success': True,
                'data': {
                    'validation_id': validation_id,
                    'status': 'started',
                    'config': config,
                    'estimated_duration': '5-10 minutes'
                },
                'message': 'Validation started successfully',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return 202, 'application/json', json.dumps(api_response, indent=2).encode('utf-8')
            
        except json.JSONDecodeError:
            return self._api_400("Invalid JSON in request body")
        except Exception as e:
            self.logger.error(f"Error starting validation: {e}")
            return self._api_500("Failed to start validation")
    
    def _get_validation_status(self, query_params: Dict[str, list]) -> Tuple[int, str, bytes]:
        """GET /validation/status - Get validation status"""
        try:
            # Mock validation status
            api_response = {
                'success': True,
                'data': {
                    'active_validations': 0,
                    'completed_validations': 3,
                    'failed_validations': 1,
                    'total_proxies_validated': len(self.data_handler.proxies)
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return 200, 'application/json', json.dumps(api_response, indent=2).encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error getting validation status: {e}")
            return self._api_500("Failed to get validation status")
    
    # Stats endpoints
    def _get_stats(self, query_params: Dict[str, list]) -> Tuple[int, str, bytes]:
        """GET /stats - Get detailed statistics"""
        try:
            stats_data = self.data_handler.get_summary_json()
            
            api_response = {
                'success': True,
                'data': stats_data,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return 200, 'application/json', json.dumps(api_response, indent=2).encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error getting stats: {e}")
            return self._api_500("Failed to get statistics")
    
    def _get_stats_summary(self) -> Tuple[int, str, bytes]:
        """GET /stats/summary - Get summary statistics"""
        try:
            summary = self.data_handler.get_summary_json()
            
            # Extract key metrics only
            summary_data = {
                'total_proxies': summary.get('total_proxies', 0),
                'active_proxies': summary.get('active_proxies', 0),
                'success_rate': summary.get('success_rate', 0.0),
                'avg_response_time': summary.get('avg_response_time', 0.0)
            }
            
            api_response = {
                'success': True,
                'data': summary_data,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return 200, 'application/json', json.dumps(api_response, indent=2).encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error getting stats summary: {e}")
            return self._api_500("Failed to get statistics summary")
    
    # Profile endpoints
    def _get_profiles(self, query_params: Dict[str, list]) -> Tuple[int, str, bytes]:
        """GET /profiles - List available profiles"""
        try:
            # Import ProfileManager here to avoid circular imports
            from .profiles import ProfileManager
            
            manager = ProfileManager()
            profiles = manager.list_profiles()
            
            api_response = {
                'success': True,
                'data': {
                    'profiles': profiles,
                    'total_count': sum(len(p) for p in profiles.values())
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return 200, 'application/json', json.dumps(api_response, indent=2).encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error getting profiles: {e}")
            return self._api_500("Failed to get profiles")
    
    def _get_profile(self, profile_name: str) -> Tuple[int, str, bytes]:
        """GET /profiles/{name} - Get specific profile"""
        try:
            from .profiles import ProfileManager
            
            manager = ProfileManager()
            profile = manager.get_profile(profile_name)
            
            if not profile:
                return self._api_404("Profile not found")
            
            api_response = {
                'success': True,
                'data': profile,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return 200, 'application/json', json.dumps(api_response, indent=2).encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error getting profile {profile_name}: {e}")
            return self._api_500("Failed to get profile")
    
    def _execute_profile(self, profile_name: str, body: bytes) -> Tuple[int, str, bytes]:
        """POST /profiles/{name} - Execute profile"""
        try:
            from .profiles import ProfileManager
            
            manager = ProfileManager()
            
            # Parse execution parameters
            overrides = {}
            if body:
                data = json.loads(body.decode('utf-8'))
                overrides = data.get('overrides', {})
            
            # Execute profile
            commands = manager.execute_profile(profile_name, overrides)
            
            api_response = {
                'success': True,
                'data': {
                    'profile': profile_name,
                    'commands': commands,
                    'overrides': overrides
                },
                'message': f'Profile {profile_name} executed successfully',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return 200, 'application/json', json.dumps(api_response, indent=2).encode('utf-8')
            
        except json.JSONDecodeError:
            return self._api_400("Invalid JSON in request body")
        except Exception as e:
            self.logger.error(f"Error executing profile {profile_name}: {e}")
            return self._api_500(f"Failed to execute profile: {e}")
    
    # Export endpoints
    def _export_proxies(self, query_params: Dict[str, list]) -> Tuple[int, str, bytes]:
        """GET /export - Export proxies in various formats"""
        try:
            export_format = query_params.get('format', ['json'])[0].lower()
            
            # Apply filters
            filters = {}
            for key in ['status', 'protocol', 'country', 'anonymity_level']:
                if key in query_params:
                    filters[key] = query_params[key][0]
            
            if export_format == 'json':
                data = self.data_handler.get_json_export(filters)
                api_response = {
                    'success': True,
                    'data': data,
                    'format': 'json',
                    'count': len(data),
                    'timestamp': datetime.utcnow().isoformat()
                }
                return 200, 'application/json', json.dumps(api_response, indent=2).encode('utf-8')
                
            elif export_format == 'csv':
                csv_data = self.data_handler.get_csv_export(filters)
                return 200, 'text/csv', csv_data.encode('utf-8')
                
            else:
                return self._api_400(f"Unsupported export format: {export_format}")
            
        except Exception as e:
            self.logger.error(f"Error exporting proxies: {e}")
            return self._api_500("Failed to export proxies")
    
    # API Key management endpoints
    def _list_api_keys(self) -> Tuple[int, str, bytes]:
        """GET /auth/keys - List API keys"""
        try:
            keys = self.authenticator.key_manager.list_keys()
            
            api_response = {
                'success': True,
                'data': {
                    'keys': keys,
                    'total_count': len(keys)
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return 200, 'application/json', json.dumps(api_response, indent=2).encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error listing API keys: {e}")
            return self._api_500("Failed to list API keys")
    
    def _create_api_key(self, body: bytes) -> Tuple[int, str, bytes]:
        """POST /auth/keys - Create new API key"""
        try:
            if not body:
                return self._api_400("Request body is required")
            
            data = json.loads(body.decode('utf-8'))
            
            # Validate required fields
            if 'name' not in data:
                return self._api_400("Missing required field: name")
            
            # Extract parameters
            name = data['name']
            permissions = data.get('permissions', ['read:proxies', 'read:stats'])
            rate_limit = data.get('rate_limit', 100)
            expires_in_days = data.get('expires_in_days')
            
            # Create API key
            full_key, key_id = self.authenticator.key_manager.create_key(
                name=name,
                permissions=permissions,
                rate_limit=rate_limit,
                expires_in_days=expires_in_days
            )
            
            api_response = {
                'success': True,
                'data': {
                    'key_id': key_id,
                    'api_key': full_key,  # Only shown once!
                    'name': name,
                    'permissions': permissions,
                    'rate_limit': rate_limit
                },
                'message': 'API key created successfully. Store the key securely - it will not be shown again.',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return 201, 'application/json', json.dumps(api_response, indent=2).encode('utf-8')
            
        except json.JSONDecodeError:
            return self._api_400("Invalid JSON in request body")
        except Exception as e:
            self.logger.error(f"Error creating API key: {e}")
            return self._api_500("Failed to create API key")
    
    def _revoke_api_key(self, key_id: str) -> Tuple[int, str, bytes]:
        """DELETE /auth/keys/{id} - Revoke API key"""
        try:
            success = self.authenticator.key_manager.revoke_key(key_id)
            
            if not success:
                return self._api_404("API key not found")
            
            api_response = {
                'success': True,
                'message': 'API key revoked successfully',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return 200, 'application/json', json.dumps(api_response).encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error revoking API key {key_id}: {e}")
            return self._api_500("Failed to revoke API key")
    
    # Error response helpers
    def _api_400(self, message: str = "Bad Request") -> Tuple[int, str, bytes]:
        """Return 400 Bad Request"""
        response = {
            'success': False,
            'error': 'Bad Request',
            'message': message,
            'timestamp': datetime.utcnow().isoformat()
        }
        return 400, 'application/json', json.dumps(response).encode('utf-8')
    
    def _api_403(self, message: str = "Forbidden") -> Tuple[int, str, bytes]:
        """Return 403 Forbidden"""
        response = {
            'success': False,
            'error': 'Forbidden',
            'message': message,
            'timestamp': datetime.utcnow().isoformat()
        }
        return 403, 'application/json', json.dumps(response).encode('utf-8')
    
    def _api_404(self, message: str = "Not Found") -> Tuple[int, str, bytes]:
        """Return 404 Not Found"""
        response = {
            'success': False,
            'error': 'Not Found',
            'message': message,
            'timestamp': datetime.utcnow().isoformat()
        }
        return 404, 'application/json', json.dumps(response).encode('utf-8')
    
    def _api_500(self, message: str = "Internal Server Error") -> Tuple[int, str, bytes]:
        """Return 500 Internal Server Error"""
        response = {
            'success': False,
            'error': 'Internal Server Error',
            'message': message,
            'timestamp': datetime.utcnow().isoformat()
        }
        return 500, 'application/json', json.dumps(response).encode('utf-8')
    
    def _method_not_allowed(self, allowed_methods: List[str]) -> Tuple[int, str, bytes]:
        """Return 405 Method Not Allowed"""
        response = {
            'success': False,
            'error': 'Method Not Allowed',
            'message': f"Allowed methods: {', '.join(allowed_methods)}",
            'timestamp': datetime.utcnow().isoformat()
        }
        return 405, 'application/json', json.dumps(response).encode('utf-8')