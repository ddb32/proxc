"""API Export Module - Webhook and HTTP API Integration"""

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union, Tuple
from urllib.parse import urlparse

# Third-party imports with fallbacks
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_RETRY = True
except ImportError:
    HAS_RETRY = False

# Import our models
from ...proxy_core.models import ProxyInfo, ProxyProtocol, AnonymityLevel, ThreatLevel, ProxyStatus
from ...proxy_core.config import ConfigManager


# ===============================================================================
# API CONFIGURATION CLASSES
# ===============================================================================

class APIMethod(Enum):
    """Supported HTTP methods for API export"""
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"


class AuthType(Enum):
    """Supported authentication types"""
    NONE = "none"
    BEARER = "bearer"
    BASIC = "basic"
    API_KEY = "api_key"
    CUSTOM_HEADER = "custom_header"


@dataclass
class APIExportConfig:
    """Configuration for API export operations"""
    url: str
    method: APIMethod = APIMethod.POST
    auth_type: AuthType = AuthType.NONE
    auth_token: Optional[str] = None
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    api_key_header: str = "X-API-Key"
    custom_headers: Dict[str, str] = field(default_factory=dict)
    timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    batch_size: int = 100
    include_metadata: bool = True
    verify_ssl: bool = True


@dataclass
class APIResponse:
    """Response from API export operation"""
    success: bool
    status_code: Optional[int] = None
    response_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    proxies_sent: int = 0
    timestamp: datetime = field(default_factory=datetime.now)


# ===============================================================================
# API EXPORT CLIENT
# ===============================================================================

class APIExportClient:
    """Client for exporting proxy data to HTTP APIs and webhooks"""
    
    def __init__(self, config: APIExportConfig):
        """Initialize API export client
        
        Args:
            config: API export configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = None
        
        if not HAS_REQUESTS:
            raise ImportError("requests library required for API export. Install with: pip install requests")
        
        self._setup_session()
    
    def _setup_session(self):
        """Setup requests session with authentication and retry logic"""
        self.session = requests.Session()
        
        # Configure retries if available
        if HAS_RETRY:
            retry_strategy = Retry(
                total=self.config.max_retries,
                backoff_factor=self.config.retry_delay,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
        
        # Configure authentication
        self._setup_auth()
        
        # Set custom headers
        self.session.headers.update(self.config.custom_headers)
        
        # Set default content type
        self.session.headers['Content-Type'] = 'application/json'
        
        # SSL verification
        self.session.verify = self.config.verify_ssl
    
    def _setup_auth(self):
        """Setup authentication for the session"""
        if self.config.auth_type == AuthType.BEARER:
            if self.config.auth_token:
                self.session.headers['Authorization'] = f'Bearer {self.config.auth_token}'
        
        elif self.config.auth_type == AuthType.BASIC:
            if self.config.auth_username and self.config.auth_password:
                self.session.auth = (self.config.auth_username, self.config.auth_password)
        
        elif self.config.auth_type == AuthType.API_KEY:
            if self.config.auth_token:
                self.session.headers[self.config.api_key_header] = self.config.auth_token
        
        elif self.config.auth_type == AuthType.CUSTOM_HEADER:
            if self.config.auth_token and self.config.api_key_header:
                self.session.headers[self.config.api_key_header] = self.config.auth_token
    
    def export_proxies(self, proxies: List[ProxyInfo], endpoint_name: str = "proxy_export") -> APIResponse:
        """Export proxy list to API endpoint
        
        Args:
            proxies: List of proxy information objects
            endpoint_name: Name/identifier for the export endpoint
            
        Returns:
            APIResponse object with export results
        """
        try:
            # Prepare payload
            payload = self._prepare_payload(proxies, endpoint_name)
            
            # Send request
            response = self.session.request(
                method=self.config.method.value,
                url=self.config.url,
                json=payload,
                timeout=self.config.timeout
            )
            
            # Process response
            return self._process_response(response, len(proxies))
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API export failed: {e}")
            return APIResponse(
                success=False,
                error_message=str(e),
                proxies_sent=0
            )
        
        except Exception as e:
            self.logger.error(f"Unexpected error during API export: {e}")
            return APIResponse(
                success=False,
                error_message=f"Unexpected error: {e}",
                proxies_sent=0
            )
    
    def export_proxies_batch(self, proxies: List[ProxyInfo], endpoint_name: str = "proxy_export") -> List[APIResponse]:
        """Export proxies in batches to avoid payload size limits
        
        Args:
            proxies: List of proxy information objects
            endpoint_name: Name/identifier for the export endpoint
            
        Returns:
            List of APIResponse objects for each batch
        """
        responses = []
        batch_size = self.config.batch_size
        
        for i in range(0, len(proxies), batch_size):
            batch = proxies[i:i + batch_size]
            batch_name = f"{endpoint_name}_batch_{i//batch_size + 1}"
            
            self.logger.info(f"Exporting batch {i//batch_size + 1} with {len(batch)} proxies")
            
            response = self.export_proxies(batch, batch_name)
            responses.append(response)
            
            # Add delay between batches to avoid rate limiting
            if i + batch_size < len(proxies):
                time.sleep(self.config.retry_delay)
        
        return responses
    
    def _prepare_payload(self, proxies: List[ProxyInfo], endpoint_name: str) -> Dict[str, Any]:
        """Prepare JSON payload for API request
        
        Args:
            proxies: List of proxy information objects
            endpoint_name: Name/identifier for the export
            
        Returns:
            JSON-serializable payload dictionary
        """
        # Convert proxies to serializable format
        proxy_data = []
        for proxy in proxies:
            proxy_dict = {
                'address': proxy.address,
                'host': proxy.host,
                'port': proxy.port,
                'protocol': proxy.protocol.value,
                'anonymity_level': proxy.anonymity_level.value,
                'status': proxy.status.value
            }
            
            # Add optional fields if available
            if proxy.geo_location:
                proxy_dict['geo_location'] = {
                    'country': proxy.geo_location.country,
                    'country_code': proxy.geo_location.country_code,
                    'region': proxy.geo_location.region,
                    'city': proxy.geo_location.city,
                    'latitude': proxy.geo_location.latitude,
                    'longitude': proxy.geo_location.longitude
                }
            
            if proxy.metrics:
                proxy_dict['metrics'] = {
                    'response_time': proxy.metrics.response_time,
                    'success_rate': proxy.metrics.success_rate,
                    'last_tested': proxy.metrics.last_tested.isoformat() if proxy.metrics.last_tested else None,
                    'test_count': proxy.metrics.test_count
                }
            
            if proxy.threat_analysis:
                proxy_dict['threat_analysis'] = {
                    'threat_level': proxy.threat_analysis.threat_level.value,
                    'risk_score': proxy.threat_analysis.risk_score,
                    'blacklisted': proxy.threat_analysis.blacklisted,
                    'reputation_score': proxy.threat_analysis.reputation_score
                }
            
            proxy_data.append(proxy_dict)
        
        # Prepare main payload
        payload = {
            'endpoint_name': endpoint_name,
            'timestamp': datetime.now().isoformat(),
            'proxy_count': len(proxies),
            'proxies': proxy_data
        }
        
        # Add metadata if requested
        if self.config.include_metadata:
            payload['metadata'] = {
                'export_method': 'proxyhunter_api_export',
                'batch_size': len(proxies),
                'total_batches': 1,  # Will be updated for batch exports
                'export_config': {
                    'method': self.config.method.value,
                    'auth_type': self.config.auth_type.value
                }
            }
        
        return payload
    
    def _process_response(self, response: requests.Response, proxies_sent: int) -> APIResponse:
        """Process HTTP response and create APIResponse object
        
        Args:
            response: HTTP response from requests
            proxies_sent: Number of proxies sent in the request
            
        Returns:
            APIResponse object with processed results
        """
        try:
            # Try to parse JSON response
            response_data = None
            if response.headers.get('content-type', '').startswith('application/json'):
                response_data = response.json()
        except json.JSONDecodeError:
            response_data = {'raw_response': response.text}
        
        # Determine success based on status code
        success = 200 <= response.status_code < 300
        
        error_message = None
        if not success:
            error_message = f"HTTP {response.status_code}: {response.reason}"
            if response_data and 'error' in response_data:
                error_message = f"{error_message} - {response_data['error']}"
        
        return APIResponse(
            success=success,
            status_code=response.status_code,
            response_data=response_data,
            error_message=error_message,
            proxies_sent=proxies_sent
        )
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test API endpoint connectivity
        
        Returns:
            Tuple of (success, message)
        """
        try:
            # Send a small test payload
            test_payload = {
                'test': True,
                'timestamp': datetime.now().isoformat(),
                'proxy_count': 0,
                'proxies': []
            }
            
            response = self.session.request(
                method=self.config.method.value,
                url=self.config.url,
                json=test_payload,
                timeout=self.config.timeout
            )
            
            if 200 <= response.status_code < 300:
                return True, f"Connection successful (HTTP {response.status_code})"
            else:
                return False, f"HTTP {response.status_code}: {response.reason}"
                
        except requests.exceptions.RequestException as e:
            return False, f"Connection failed: {e}"
        
        except Exception as e:
            return False, f"Unexpected error: {e}"
    
    def close(self):
        """Close the session"""
        if self.session:
            self.session.close()


# ===============================================================================
# API EXPORT MANAGER
# ===============================================================================

class APIExportManager:
    """Manager for multiple API export endpoints"""
    
    def __init__(self, config_manager: Optional[ConfigManager] = None):
        """Initialize API export manager
        
        Args:
            config_manager: Configuration manager instance
        """
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self.clients: Dict[str, APIExportClient] = {}
        self.endpoints: Dict[str, APIExportConfig] = {}
    
    def add_endpoint(self, name: str, config: APIExportConfig) -> bool:
        """Add API endpoint configuration
        
        Args:
            name: Endpoint name/identifier
            config: API export configuration
            
        Returns:
            True if endpoint was added successfully
        """
        try:
            client = APIExportClient(config)
            self.clients[name] = client
            self.endpoints[name] = config
            
            self.logger.info(f"Added API endpoint: {name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add endpoint {name}: {e}")
            return False
    
    def remove_endpoint(self, name: str) -> bool:
        """Remove API endpoint
        
        Args:
            name: Endpoint name/identifier
            
        Returns:
            True if endpoint was removed successfully
        """
        if name in self.clients:
            self.clients[name].close()
            del self.clients[name]
            del self.endpoints[name]
            self.logger.info(f"Removed API endpoint: {name}")
            return True
        return False
    
    def export_to_endpoint(self, endpoint_name: str, proxies: List[ProxyInfo]) -> Optional[APIResponse]:
        """Export proxies to specific endpoint
        
        Args:
            endpoint_name: Name of endpoint to export to
            proxies: List of proxy information objects
            
        Returns:
            APIResponse or None if endpoint not found
        """
        if endpoint_name not in self.clients:
            self.logger.error(f"Endpoint not found: {endpoint_name}")
            return None
        
        client = self.clients[endpoint_name]
        return client.export_proxies(proxies, endpoint_name)
    
    def export_to_all_endpoints(self, proxies: List[ProxyInfo]) -> Dict[str, APIResponse]:
        """Export proxies to all configured endpoints
        
        Args:
            proxies: List of proxy information objects
            
        Returns:
            Dictionary mapping endpoint names to APIResponse objects
        """
        results = {}
        
        for endpoint_name, client in self.clients.items():
            self.logger.info(f"Exporting to endpoint: {endpoint_name}")
            
            try:
                response = client.export_proxies(proxies, endpoint_name)
                results[endpoint_name] = response
                
                if response.success:
                    self.logger.info(f"Successfully exported {response.proxies_sent} proxies to {endpoint_name}")
                else:
                    self.logger.error(f"Failed to export to {endpoint_name}: {response.error_message}")
                    
            except Exception as e:
                self.logger.error(f"Error exporting to {endpoint_name}: {e}")
                results[endpoint_name] = APIResponse(
                    success=False,
                    error_message=str(e),
                    proxies_sent=0
                )
        
        return results
    
    def test_all_endpoints(self) -> Dict[str, Tuple[bool, str]]:
        """Test connectivity to all endpoints
        
        Returns:
            Dictionary mapping endpoint names to (success, message) tuples
        """
        results = {}
        
        for endpoint_name, client in self.clients.items():
            self.logger.info(f"Testing endpoint: {endpoint_name}")
            success, message = client.test_connection()
            results[endpoint_name] = (success, message)
            
            if success:
                self.logger.info(f"Endpoint {endpoint_name}: {message}")
            else:
                self.logger.warning(f"Endpoint {endpoint_name}: {message}")
        
        return results
    
    def close_all(self):
        """Close all client sessions"""
        for client in self.clients.values():
            client.close()
        self.clients.clear()
        self.endpoints.clear()


# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def create_api_export_config(
    url: str,
    method: str = "POST",
    auth_type: str = "none",
    auth_token: Optional[str] = None,
    **kwargs
) -> APIExportConfig:
    """Create API export configuration from parameters
    
    Args:
        url: API endpoint URL
        method: HTTP method (POST, PUT, PATCH)
        auth_type: Authentication type (none, bearer, basic, api_key, custom_header)
        auth_token: Authentication token/key
        **kwargs: Additional configuration parameters
        
    Returns:
        APIExportConfig instance
    """
    return APIExportConfig(
        url=url,
        method=APIMethod(method.upper()),
        auth_type=AuthType(auth_type.lower()),
        auth_token=auth_token,
        **kwargs
    )


def validate_api_url(url: str) -> Tuple[bool, str]:
    """Validate API endpoint URL
    
    Args:
        url: URL to validate
        
    Returns:
        Tuple of (is_valid, message)
    """
    try:
        parsed = urlparse(url)
        
        if not parsed.scheme:
            return False, "URL must include protocol (http:// or https://)"
        
        if parsed.scheme not in ['http', 'https']:
            return False, "URL must use HTTP or HTTPS protocol"
        
        if not parsed.netloc:
            return False, "URL must include hostname"
        
        return True, "URL is valid"
        
    except Exception as e:
        return False, f"Invalid URL format: {e}"