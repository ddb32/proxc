"""Python SDK for ProxC API - Phase 4.2.7 Implementation

This module provides a Python client SDK for interacting with the ProxC REST API,
offering a convenient interface for programmatic access to proxy management functionality.
"""

import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Iterator
from urllib.parse import urljoin, urlencode
import requests
from dataclasses import dataclass, asdict

from .cli_base import get_cli_logger
from .cli_exceptions import APIError


@dataclass
class ProxyInfo:
    """Proxy information data class"""
    proxy_id: str
    address: str
    host: str
    port: int
    protocol: str
    status: str
    anonymity_level: Optional[str] = None
    threat_level: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    response_time: Optional[float] = None
    success_rate: Optional[float] = None
    last_checked: Optional[str] = None


@dataclass
class APIKeyInfo:
    """API key information data class"""
    key_id: str
    name: str
    permissions: List[str]
    rate_limit: int
    created_at: str
    last_used: Optional[str] = None
    is_active: bool = True
    expires_at: Optional[str] = None


@dataclass
class Statistics:
    """Statistics data class"""
    total_proxies: int
    active_proxies: int
    failed_proxies: int
    success_rate: float
    avg_response_time: float
    country_distribution: Dict[str, int]
    protocol_distribution: Dict[str, int]


class ProxCAPIError(Exception):
    """API client specific exceptions"""
    
    def __init__(self, message: str, status_code: Optional[int] = None, response_data: Optional[Dict] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_data = response_data or {}


class ProxCClient:
    """Python client for ProxC API"""
    
    def __init__(self, base_url: str = "http://localhost:8080", api_key: Optional[str] = None,
                 timeout: int = 30, verify_ssl: bool = True):
        """
        Initialize API client
        
        Args:
            base_url: Base URL of the ProxC server
            api_key: API key for authentication (optional for read-only access)
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip('/')
        self.api_base = f"{self.base_url}/api/v1"
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        self.logger = get_cli_logger("api_client")
        
        # Setup session with common configuration
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
        # Set authentication headers
        if api_key:
            self.session.headers.update({
                'X-API-Key': api_key,
                'User-Agent': 'ProxC-Python-SDK/1.0.0'
            })
    
    def _make_request(self, method: str, endpoint: str, params: Optional[Dict] = None,
                     json_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make HTTP request with error handling"""
        url = f"{self.api_base}{endpoint}"
        
        try:
            self.logger.debug(f"Making {method} request to {url}")
            
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                timeout=self.timeout
            )
            
            # Log rate limit headers if present
            if 'X-RateLimit-Remaining' in response.headers:
                remaining = response.headers['X-RateLimit-Remaining']
                limit = response.headers.get('X-RateLimit-Limit', 'unknown')
                self.logger.debug(f"Rate limit: {remaining}/{limit} remaining")
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', '60'))
                raise ProxCAPIError(
                    f"Rate limit exceeded. Retry after {retry_after} seconds",
                    status_code=429,
                    response_data={'retry_after': retry_after}
                )
            
            # Handle other HTTP errors
            if response.status_code >= 400:
                try:
                    error_data = response.json()
                    error_message = error_data.get('message', f'HTTP {response.status_code} error')
                except:
                    error_message = f'HTTP {response.status_code} error'
                
                raise ProxCAPIError(
                    error_message,
                    status_code=response.status_code,
                    response_data=error_data if 'error_data' in locals() else {}
                )
            
            # Parse JSON response
            return response.json()
            
        except requests.RequestException as e:
            raise ProxyHunterAPIError(f"Request failed: {e}")
    
    def _handle_response(self, response_data: Dict[str, Any]) -> Any:
        """Handle API response and extract data"""
        if not response_data.get('success', False):
            error_msg = response_data.get('message', 'API request failed')
            raise ProxyHunterAPIError(error_msg, response_data=response_data)
        
        return response_data.get('data')
    
    # Proxy management methods
    def list_proxies(self, limit: int = 100, offset: int = 0, status: Optional[str] = None,
                    protocol: Optional[str] = None, country: Optional[str] = None) -> Dict[str, Any]:
        """
        List proxies with optional filtering
        
        Args:
            limit: Number of proxies to return (max 1000)
            offset: Number of proxies to skip
            status: Filter by status (active, inactive, failed)
            protocol: Filter by protocol (http, https, socks4, socks5)
            country: Filter by country code (e.g., 'US', 'GB')
        
        Returns:
            Dictionary containing proxies list and pagination info
        """
        params = {'limit': limit, 'offset': offset}
        
        if status:
            params['status'] = status
        if protocol:
            params['protocol'] = protocol
        if country:
            params['country'] = country
        
        response = self._make_request('GET', '/proxies', params=params)
        return self._handle_response(response)
    
    def get_proxy(self, proxy_id: str) -> ProxyInfo:
        """
        Get detailed information about a specific proxy
        
        Args:
            proxy_id: Unique proxy identifier
        
        Returns:
            ProxyInfo object with proxy details
        """
        response = self._make_request('GET', f'/proxies/{proxy_id}')
        proxy_data = self._handle_response(response)
        
        return ProxyInfo(**{k: v for k, v in proxy_data.items() if k in ProxyInfo.__annotations__})
    
    def create_proxy(self, host: str, port: int, protocol: str, 
                    username: Optional[str] = None, password: Optional[str] = None,
                    source: Optional[str] = None) -> ProxyInfo:
        """
        Create a new proxy
        
        Args:
            host: Proxy hostname or IP address
            port: Proxy port number
            protocol: Proxy protocol (http, https, socks4, socks5)
            username: Optional authentication username
            password: Optional authentication password
            source: Source identifier
        
        Returns:
            ProxyInfo object for the created proxy
        """
        data = {
            'host': host,
            'port': port,
            'protocol': protocol
        }
        
        if username:
            data['username'] = username
        if password:
            data['password'] = password
        if source:
            data['source'] = source
        
        response = self._make_request('POST', '/proxies', json_data=data)
        proxy_data = self._handle_response(response)
        
        return ProxyInfo(**{k: v for k, v in proxy_data.items() if k in ProxyInfo.__annotations__})
    
    def delete_proxy(self, proxy_id: str) -> bool:
        """
        Delete a proxy
        
        Args:
            proxy_id: Unique proxy identifier
        
        Returns:
            True if successful
        """
        response = self._make_request('DELETE', f'/proxies/{proxy_id}')
        self._handle_response(response)
        return True
    
    def get_all_proxies(self, status: Optional[str] = None, protocol: Optional[str] = None,
                       country: Optional[str] = None) -> Iterator[ProxyInfo]:
        """
        Generator to iterate through all proxies with automatic pagination
        
        Args:
            status: Filter by status
            protocol: Filter by protocol 
            country: Filter by country code
        
        Yields:
            ProxyInfo objects
        """
        offset = 0
        limit = 1000
        
        while True:
            result = self.list_proxies(
                limit=limit, 
                offset=offset, 
                status=status, 
                protocol=protocol, 
                country=country
            )
            
            proxies = result.get('proxies', [])
            if not proxies:
                break
            
            for proxy_data in proxies:
                yield ProxyInfo(**{k: v for k, v in proxy_data.items() if k in ProxyInfo.__annotations__})
            
            if not result.get('has_more', False):
                break
                
            offset += limit
    
    # Statistics methods
    def get_statistics(self) -> Statistics:
        """
        Get comprehensive statistics
        
        Returns:
            Statistics object with proxy analytics
        """
        response = self._make_request('GET', '/stats')
        stats_data = self._handle_response(response)
        
        return Statistics(**{k: v for k, v in stats_data.items() if k in Statistics.__annotations__})
    
    def get_statistics_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics
        
        Returns:
            Dictionary with key metrics
        """
        response = self._make_request('GET', '/stats/summary')
        return self._handle_response(response)
    
    # Profile methods
    def list_profiles(self) -> Dict[str, Any]:
        """
        List available configuration profiles
        
        Returns:
            Dictionary containing profiles organized by type
        """
        response = self._make_request('GET', '/profiles')
        return self._handle_response(response)
    
    def get_profile(self, profile_name: str) -> Dict[str, Any]:
        """
        Get specific profile configuration
        
        Args:
            profile_name: Name of the profile
        
        Returns:
            Profile configuration dictionary
        """
        response = self._make_request('GET', f'/profiles/{profile_name}')
        return self._handle_response(response)
    
    def execute_profile(self, profile_name: str, overrides: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Execute a configuration profile
        
        Args:
            profile_name: Name of the profile to execute
            overrides: Parameter overrides
        
        Returns:
            List of commands that would be executed
        """
        data = {}
        if overrides:
            data['overrides'] = overrides
        
        response = self._make_request('POST', f'/profiles/{profile_name}', json_data=data)
        result = self._handle_response(response)
        return result.get('commands', [])
    
    # Export methods
    def export_proxies(self, format: str = 'json', status: Optional[str] = None,
                      protocol: Optional[str] = None, country: Optional[str] = None) -> Union[List[Dict], str]:
        """
        Export proxies in specified format
        
        Args:
            format: Export format (json, csv)
            status: Filter by status
            protocol: Filter by protocol
            country: Filter by country code
        
        Returns:
            List of proxy dictionaries (JSON) or CSV string
        """
        params = {'format': format}
        
        if status:
            params['status'] = status
        if protocol:
            params['protocol'] = protocol
        if country:
            params['country'] = country
        
        if format.lower() == 'csv':
            # For CSV, we need to handle the raw response
            url = f"{self.api_base}/export"
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.text
        else:
            response = self._make_request('GET', '/export', params=params)
            result = self._handle_response(response)
            return result if isinstance(result, list) else result.get('data', [])
    
    # API Key management methods (admin only)
    def list_api_keys(self) -> List[APIKeyInfo]:
        """
        List API keys (admin only)
        
        Returns:
            List of APIKeyInfo objects
        """
        response = self._make_request('GET', '/auth/keys')
        keys_data = self._handle_response(response)
        
        return [APIKeyInfo(**key_data) for key_data in keys_data.get('keys', [])]
    
    def create_api_key(self, name: str, permissions: Optional[List[str]] = None,
                      rate_limit: int = 100, expires_in_days: Optional[int] = None) -> Dict[str, Any]:
        """
        Create new API key (admin only)
        
        Args:
            name: Human-readable key name
            permissions: List of permissions to grant
            rate_limit: Requests per minute limit
            expires_in_days: Optional expiration in days
        
        Returns:
            Dictionary containing new API key information (key shown only once)
        """
        data = {
            'name': name,
            'rate_limit': rate_limit
        }
        
        if permissions:
            data['permissions'] = permissions
        if expires_in_days:
            data['expires_in_days'] = expires_in_days
        
        response = self._make_request('POST', '/auth/keys', json_data=data)
        return self._handle_response(response)
    
    def revoke_api_key(self, key_id: str) -> bool:
        """
        Revoke an API key (admin only)
        
        Args:
            key_id: Key identifier to revoke
        
        Returns:
            True if successful
        """
        response = self._make_request('DELETE', f'/auth/keys/{key_id}')
        self._handle_response(response)
        return True
    
    # Utility methods
    def test_connection(self) -> Dict[str, Any]:
        """
        Test API connection and authentication
        
        Returns:
            Dictionary with connection status and user info
        """
        try:
            # Try to get statistics as a basic connectivity test
            stats = self.get_statistics_summary()
            
            # Check authentication by trying to list API keys
            auth_status = "anonymous"
            try:
                self.list_api_keys()
                auth_status = "admin"
            except ProxyHunterAPIError as e:
                if e.status_code == 403:
                    auth_status = "authenticated"
                elif e.status_code == 401:
                    auth_status = "anonymous"
                else:
                    auth_status = "unknown"
            
            return {
                'connected': True,
                'authentication': auth_status,
                'server_stats': stats,
                'api_base': self.api_base
            }
            
        except Exception as e:
            return {
                'connected': False,
                'error': str(e),
                'api_base': self.api_base
            }
    
    def health_check(self) -> Dict[str, Any]:
        """
        Perform health check
        
        Returns:
            Health status information
        """
        try:
            url = f"{self.base_url}/health"
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }


class AsyncProxyHunterClient:
    """Async version of ProxyHunterClient for high-performance applications"""
    
    def __init__(self, base_url: str = "http://localhost:8080", api_key: Optional[str] = None,
                 timeout: int = 30, verify_ssl: bool = True):
        """
        Initialize async API client
        
        Args:
            base_url: Base URL of the Proxy Hunter server
            api_key: API key for authentication
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip('/')
        self.api_base = f"{self.base_url}/api/v1"
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        self.logger = get_cli_logger("async_api_client")
        
        # Headers
        self.headers = {
            'User-Agent': 'ProxyHunter-Python-SDK/1.0.0-async'
        }
        
        if api_key:
            self.headers['X-API-Key'] = api_key
    
    async def _make_request(self, method: str, endpoint: str, params: Optional[Dict] = None,
                          json_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make async HTTP request - requires aiohttp to be installed"""
        try:
            import aiohttp
        except ImportError:
            raise ImportError("aiohttp is required for async client. Install with: pip install aiohttp")
        
        url = f"{self.api_base}{endpoint}"
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
        
        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=timeout,
            connector=connector
        ) as session:
            
            self.logger.debug(f"Making async {method} request to {url}")
            
            async with session.request(
                method=method,
                url=url,
                params=params,
                json=json_data
            ) as response:
                
                # Handle rate limiting
                if response.status == 429:
                    retry_after = int(response.headers.get('Retry-After', '60'))
                    raise ProxyHunterAPIError(
                        f"Rate limit exceeded. Retry after {retry_after} seconds",
                        status_code=429,
                        response_data={'retry_after': retry_after}
                    )
                
                # Handle other HTTP errors
                if response.status >= 400:
                    try:
                        error_data = await response.json()
                        error_message = error_data.get('message', f'HTTP {response.status} error')
                    except:
                        error_message = f'HTTP {response.status} error'
                        error_data = {}
                    
                    raise ProxyHunterAPIError(
                        error_message,
                        status_code=response.status,
                        response_data=error_data
                    )
                
                return await response.json()
    
    # Async versions of key methods
    async def list_proxies(self, limit: int = 100, offset: int = 0, **filters) -> Dict[str, Any]:
        """Async version of list_proxies"""
        params = {'limit': limit, 'offset': offset}
        params.update(filters)
        
        response = await self._make_request('GET', '/proxies', params=params)
        
        if not response.get('success', False):
            raise ProxyHunterAPIError(response.get('message', 'Request failed'))
        
        return response.get('data')
    
    async def get_statistics(self) -> Statistics:
        """Async version of get_statistics"""
        response = await self._make_request('GET', '/stats')
        
        if not response.get('success', False):
            raise ProxyHunterAPIError(response.get('message', 'Request failed'))
        
        stats_data = response.get('data')
        return Statistics(**{k: v for k, v in stats_data.items() if k in Statistics.__annotations__})


# Convenience functions
def create_client(base_url: str = "http://localhost:8080", api_key: Optional[str] = None) -> ProxyHunterClient:
    """Create a ProxyHunterClient instance with default settings"""
    return ProxyHunterClient(base_url=base_url, api_key=api_key)


def create_async_client(base_url: str = "http://localhost:8080", api_key: Optional[str] = None) -> AsyncProxyHunterClient:
    """Create an AsyncProxyHunterClient instance with default settings"""
    return AsyncProxyHunterClient(base_url=base_url, api_key=api_key)


# Example usage
if __name__ == '__main__':
    # Example synchronous usage
    client = create_client(api_key="your-api-key-here")
    
    # Test connection
    connection_status = client.test_connection()
    print(f"Connection status: {connection_status}")
    
    if connection_status['connected']:
        # Get statistics
        stats = client.get_statistics()
        print(f"Total proxies: {stats.total_proxies}")
        print(f"Active proxies: {stats.active_proxies}")
        print(f"Success rate: {stats.success_rate}%")
        
        # List first 10 active proxies
        result = client.list_proxies(limit=10, status='active')
        print(f"Found {result['total_count']} active proxies")
        
        for proxy_data in result['proxies']:
            proxy = ProxyInfo(**{k: v for k, v in proxy_data.items() if k in ProxyInfo.__annotations__})
            print(f"  {proxy.address} ({proxy.protocol}) - {proxy.country}")
    
    # Example async usage would require running in an async context:
    # import asyncio
    # async def example_async():
    #     async_client = create_async_client(api_key="your-api-key-here")
    #     stats = await async_client.get_statistics()
    #     print(f"Async - Total proxies: {stats.total_proxies}")
    #
    # asyncio.run(example_async())