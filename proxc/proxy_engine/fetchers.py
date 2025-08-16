"""Enhanced Proxy Fetchers - High-Quality Proxy Discovery System"""

import asyncio
import json
import logging
import random
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Union
from urllib.parse import urljoin, urlparse

# Third-party imports with fallbacks
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry 
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    from bs4 import BeautifulSoup
    HAS_BEAUTIFULSOUP = True
except ImportError:
    HAS_BEAUTIFULSOUP = False

# Import our core models
from ..proxy_core.models import (
    ProxyInfo, ProxyProtocol, AnonymityLevel, ThreatLevel, 
    ProxyStatus, ValidationStatus, ProxyError
)
from ..proxy_core.config import ConfigManager

# Configure logging
logger = logging.getLogger(__name__)


# ===============================================================================
# ENHANCED DATA CLASSES
# ===============================================================================

class SourceType(Enum):
    """Types of proxy sources"""
    API = "api"
    HTML_TABLE = "html_table"
    TEXT_LIST = "text_list"


@dataclass
class EnhancedProxySource:
    """Enhanced proxy source configuration"""
    name: str
    url: str
    source_type: SourceType
    headers: Dict[str, str] = field(default_factory=dict)
    rate_limit: float = 2.0
    timeout: int = 30
    max_proxies: int = 500
    enabled: bool = True
    
    # Advanced parsing configuration
    json_path: Optional[str] = None  # JSONPath for API responses
    table_selector: Optional[str] = None  # CSS selector for HTML tables
    proxy_pattern: Optional[str] = None  # Regex pattern for text parsing
    
    # Success tracking
    last_success: Optional[datetime] = None
    success_count: int = 0
    failure_count: int = 0
    disabled_until: Optional[datetime] = None  # When to re-enable if disabled
    
    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        return (self.success_count / total * 100) if total > 0 else 0.0


@dataclass 
class EnhancedFetchResult:
    """Enhanced result of fetching operation"""
    source_name: str
    proxies_found: List[ProxyInfo]
    success: bool
    error_message: Optional[str] = None
    fetch_duration: float = 0.0
    raw_data_size: int = 0
    parsed_count: int = 0
    filtered_count: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def proxy_count(self) -> int:
        return len(self.proxies_found)


# ===============================================================================
# HIGH-QUALITY PROXY SOURCES
# ===============================================================================

ENHANCED_SOURCES = [
    EnhancedProxySource(
        name="ProxyScrape_API",
        url="https://api.proxyscrape.com/v2/?request=get&format=json&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
        source_type=SourceType.API,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        },
        rate_limit=3.0,
        json_path="proxies",
        max_proxies=1000
    ),
    
    EnhancedProxySource(
        name="FreeProxyList_API",
        url="https://www.proxy-list.download/api/v1/get?type=http",
        source_type=SourceType.TEXT_LIST,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
        rate_limit=2.0,
        proxy_pattern=r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})',
        max_proxies=500
    ),
    
    EnhancedProxySource(
        name="ProxyList_Plus",
        url="https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-1",
        source_type=SourceType.HTML_TABLE,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
        rate_limit=2.5,
        table_selector="table.bg",
        max_proxies=300
    ),
    
    EnhancedProxySource(
        name="HideMyName",
        url="https://hidemy.name/en/proxy-list/?maxtime=1000&type=h#list",
        source_type=SourceType.HTML_TABLE,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
        rate_limit=4.0,
        table_selector="table.proxy__t",
        max_proxies=200
    )
]


# ===============================================================================
# BASE FETCHER CLASS
# ===============================================================================

class BaseFetcher(ABC):
    """Abstract base class for proxy fetchers"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.logger = logging.getLogger(__name__)
        self._last_request_times = {}
        
        # Setup HTTP session
        if HAS_REQUESTS:
            self.session = requests.Session()
            
            # Configure retries
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS"]
            )
            
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
            
            # Set default headers
            self.session.headers.update({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
    
    def _enforce_rate_limit(self, source: EnhancedProxySource):
        """Enforce rate limiting"""
        source_key = source.name
        current_time = time.time()
        
        if source_key in self._last_request_times:
            elapsed = current_time - self._last_request_times[source_key]
            if elapsed < source.rate_limit:
                sleep_time = source.rate_limit - elapsed
                sleep_time += random.uniform(0.1, 0.5)  # Add jitter
                time.sleep(sleep_time)
        
        self._last_request_times[source_key] = current_time
    
    @abstractmethod
    def fetch_from_source(self, source: EnhancedProxySource) -> EnhancedFetchResult:
        """Fetch proxies from a specific source"""
        pass


# ===============================================================================
# SPECIALIZED FETCHERS
# ===============================================================================

class APIFetcher(BaseFetcher):
    """Specialized fetcher for JSON API sources"""
    
    def fetch_from_source(self, source: EnhancedProxySource) -> EnhancedFetchResult:
        """Fetch proxies from JSON API"""
        start_time = time.time()
        result = EnhancedFetchResult(source_name=source.name, proxies_found=[], success=False)
        
        try:
            # Enforce rate limiting
            self._enforce_rate_limit(source)
            
            # Make request
            self.logger.info(f"Fetching from API: {source.name}")
            response = self.session.get(
                source.url,
                headers=source.headers,
                timeout=source.timeout
            )
            response.raise_for_status()
            
            result.raw_data_size = len(response.content)
            
            # Parse JSON response
            data = response.json()
            proxies = self._parse_api_response(data, source)
            
            # Filter and limit
            proxies = self._filter_proxies(proxies)
            if len(proxies) > source.max_proxies:
                proxies = proxies[:source.max_proxies]
            
            result.proxies_found = proxies
            result.parsed_count = len(proxies)
            result.filtered_count = len(proxies)
            result.success = True
            
            # Update source statistics
            source.success_count += 1
            source.last_success = datetime.utcnow()
            
            self.logger.info(f"Successfully fetched {len(proxies)} proxies from {source.name}")
            
        except requests.exceptions.HTTPError as e:
            # Handle specific HTTP status codes with actionable messages
            status_code = e.response.status_code if e.response else 0
            result.error_message = self._get_http_error_message(status_code, source.name)
            source.failure_count += 1
            
            # Mark source as temporarily disabled for certain errors
            if status_code in [403, 429, 503]:
                source.enabled = False
                # Set cooldown period: 403/503 = 1 hour, 429 = 30 minutes
                cooldown_minutes = 60 if status_code in [403, 503] else 30
                source.disabled_until = datetime.utcnow() + timedelta(minutes=cooldown_minutes)
                self.logger.warning(f"Temporarily disabled {source.name} due to HTTP {status_code} for {cooldown_minutes} minutes")
            
            self.logger.error(f"HTTP {status_code} error for {source.name}: {result.error_message}")
            
        except requests.exceptions.Timeout as e:
            result.error_message = f"Request timeout after {source.timeout}s. Source may be slow or overloaded."
            source.failure_count += 1
            self.logger.error(f"Timeout for {source.name}: {e}")
            
        except requests.exceptions.ConnectionError as e:
            result.error_message = f"Connection failed. Source may be down or unreachable."
            source.failure_count += 1
            self.logger.error(f"Connection error for {source.name}: {e}")
            
        except requests.exceptions.RequestException as e:
            result.error_message = f"Network error: {str(e)}"
            source.failure_count += 1
            self.logger.error(f"Request failed for {source.name}: {e}")
            
        except json.JSONDecodeError as e:
            result.error_message = f"Invalid JSON response. Source may have changed format or returned HTML error page."
            source.failure_count += 1
            self.logger.error(f"JSON parsing failed for {source.name}: {e}")
            
        except Exception as e:
            # Try to provide more specific error context
            if "json" in str(e).lower() or "parsing" in str(e).lower():
                result.error_message = f"Data parsing error: {str(e)}. Source may have changed format."
            elif "beautifulsoup" in str(e).lower() or "html" in str(e).lower():
                result.error_message = f"HTML parsing error: {str(e)}. Source may have changed page structure."
            else:
                result.error_message = f"Unexpected error: {str(e)}"
            
            source.failure_count += 1
            self.logger.error(f"Unexpected error for {source.name}: {e}")
        
        finally:
            result.fetch_duration = time.time() - start_time
        
        return result
    
    def _get_http_error_message(self, status_code: int, source_name: str) -> str:
        """Get user-friendly error message for HTTP status codes"""
        error_messages = {
            400: f"Bad request to {source_name}. Source may have changed its API format.",
            401: f"Authentication required for {source_name}. This source may now require an API key.",
            403: f"Access forbidden to {source_name}. Source may have blocked automated requests or changed access policy.",
            404: f"Source {source_name} not found. URL may have changed or service discontinued.",
            429: f"Rate limit exceeded for {source_name}. Too many requests sent too quickly.",
            500: f"Server error at {source_name}. Source is experiencing technical difficulties.",
            502: f"Bad gateway for {source_name}. Source server is temporarily unavailable.",
            503: f"Service unavailable for {source_name}. Source is temporarily down for maintenance.",
            504: f"Gateway timeout for {source_name}. Source is taking too long to respond."
        }
        
        default_message = f"HTTP {status_code} error for {source_name}. Source may be temporarily unavailable."
        return error_messages.get(status_code, default_message)
    
    def _parse_api_response(self, data: Any, source: EnhancedProxySource) -> List[ProxyInfo]:
        """Parse API response based on source configuration"""
        proxies = []
        
        try:
            # Navigate to proxy data using json_path
            proxy_data = data
            if source.json_path:
                for key in source.json_path.split('.'):
                    if key in proxy_data:
                        proxy_data = proxy_data[key]
                    else:
                        self.logger.warning(f"JSON path {source.json_path} not found in {source.name}")
                        return []
            
            # Handle different data structures
            if isinstance(proxy_data, list):
                for item in proxy_data:
                    proxy = self._parse_proxy_item(item, source)
                    if proxy:
                        proxies.append(proxy)
            elif isinstance(proxy_data, dict):
                # Sometimes the response is a single proxy object
                proxy = self._parse_proxy_item(proxy_data, source)
                if proxy:
                    proxies.append(proxy)
                    
        except Exception as e:
            self.logger.error(f"Error parsing API response from {source.name}: {e}")
        
        return proxies
    
    def _parse_proxy_item(self, item: Any, source: EnhancedProxySource) -> Optional[ProxyInfo]:
        """Parse individual proxy item from API response"""
        try:
            if isinstance(item, dict):
                # Handle different field naming conventions
                ip = (item.get('ip') or item.get('host') or 
                     item.get('address') or item.get('proxy'))
                port = (item.get('port') or item.get('portNumber') or 
                       item.get('proxy_port'))
                
                if ip and port:
                    # Determine protocol
                    protocol_str = item.get('protocol', 'http').lower()
                    try:
                        protocol = ProxyProtocol(protocol_str)
                    except ValueError:
                        protocol = ProxyProtocol.HTTP
                    
                    # Create proxy info
                    proxy = ProxyInfo(
                        host=ip,
                        port=int(port),
                        protocol=protocol
                    )
                    
                    # Set additional fields if available
                    if 'country' in item:
                        from ..proxy_core.models import GeoLocation
                        proxy.geo_location = GeoLocation(
                            country=item['country'],
                            region=item.get('region'),
                            city=item.get('city'),
                            latitude=0.0,
                            longitude=0.0
                        )
                    
                    if 'anonymity' in item:
                        anonymity_str = item['anonymity'].lower()
                        if 'elite' in anonymity_str:
                            proxy.anonymity_level = AnonymityLevel.ELITE
                        elif 'anonymous' in anonymity_str:
                            proxy.anonymity_level = AnonymityLevel.ANONYMOUS
                        else:
                            proxy.anonymity_level = AnonymityLevel.TRANSPARENT
                    
                    return proxy
                    
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Failed to parse proxy item: {e}")
        
        return None
    
    def _filter_proxies(self, proxies: List[ProxyInfo]) -> List[ProxyInfo]:
        """Filter out invalid proxies"""
        filtered = []
        
        for proxy in proxies:
            # Basic validation
            if not self._is_valid_ip(proxy.host):
                continue
            
            if not (1 <= proxy.port <= 65535):
                continue
            
            # Skip private IPs
            if self._is_private_ip(proxy.host):
                continue
            
            filtered.append(proxy)
        
        return filtered
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                if not (0 <= int(part) <= 255):
                    return False
            
            return True
        except (ValueError, AttributeError):
            return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = [int(p) for p in ip.split('.')]
            
            # Private ranges
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:  # Loopback
                return True
            if parts[0] == 169 and parts[1] == 254:  # Link-local
                return True
                
            return False
            
        except (ValueError, IndexError):
            return True  # If we can't parse it, consider it invalid


class HTMLFetcher(BaseFetcher):
    """Specialized fetcher for HTML table sources"""
    
    def fetch_from_source(self, source: EnhancedProxySource) -> EnhancedFetchResult:
        """Fetch proxies from HTML tables"""
        start_time = time.time()
        result = EnhancedFetchResult(source_name=source.name, proxies_found=[], success=False)
        
        if not HAS_BEAUTIFULSOUP:
            result.error_message = "BeautifulSoup4 not available for HTML parsing"
            return result
        
        try:
            # Enforce rate limiting
            self._enforce_rate_limit(source)
            
            # Make request
            self.logger.info(f"Fetching from HTML: {source.name}")
            response = self.session.get(
                source.url,
                headers=source.headers,
                timeout=source.timeout
            )
            response.raise_for_status()
            
            result.raw_data_size = len(response.content)
            
            # Parse HTML content
            soup = BeautifulSoup(response.content, 'html.parser')
            proxies = self._parse_html_tables(soup, source)
            
            # Filter and limit
            proxies = self._filter_proxies(proxies)
            if len(proxies) > source.max_proxies:
                proxies = proxies[:source.max_proxies]
            
            result.proxies_found = proxies
            result.parsed_count = len(proxies)
            result.filtered_count = len(proxies)
            result.success = True
            
            # Update source statistics
            source.success_count += 1
            source.last_success = datetime.utcnow()
            
            self.logger.info(f"Successfully fetched {len(proxies)} proxies from {source.name}")
            
        except requests.exceptions.HTTPError as e:
            # Handle specific HTTP status codes with actionable messages
            status_code = e.response.status_code if e.response else 0
            result.error_message = self._get_http_error_message(status_code, source.name)
            source.failure_count += 1
            
            # Mark source as temporarily disabled for certain errors
            if status_code in [403, 429, 503]:
                source.enabled = False
                # Set cooldown period: 403/503 = 1 hour, 429 = 30 minutes
                cooldown_minutes = 60 if status_code in [403, 503] else 30
                source.disabled_until = datetime.utcnow() + timedelta(minutes=cooldown_minutes)
                self.logger.warning(f"Temporarily disabled {source.name} due to HTTP {status_code} for {cooldown_minutes} minutes")
            
            self.logger.error(f"HTTP {status_code} error for {source.name}: {result.error_message}")
            
        except requests.exceptions.Timeout as e:
            result.error_message = f"Request timeout after {source.timeout}s. Source may be slow or overloaded."
            source.failure_count += 1
            self.logger.error(f"Timeout for {source.name}: {e}")
            
        except requests.exceptions.ConnectionError as e:
            result.error_message = f"Connection failed. Source may be down or unreachable."
            source.failure_count += 1
            self.logger.error(f"Connection error for {source.name}: {e}")
            
        except requests.exceptions.RequestException as e:
            result.error_message = f"Network error: {str(e)}"
            source.failure_count += 1
            self.logger.error(f"Request failed for {source.name}: {e}")
            
        except Exception as e:
            # Try to provide more specific error context
            if "json" in str(e).lower() or "parsing" in str(e).lower():
                result.error_message = f"Data parsing error: {str(e)}. Source may have changed format."
            elif "beautifulsoup" in str(e).lower() or "html" in str(e).lower():
                result.error_message = f"HTML parsing error: {str(e)}. Source may have changed page structure."
            else:
                result.error_message = f"Unexpected error: {str(e)}"
            
            source.failure_count += 1
            self.logger.error(f"Unexpected error for {source.name}: {e}")
        
        finally:
            result.fetch_duration = time.time() - start_time
        
        return result
    
    def _get_http_error_message(self, status_code: int, source_name: str) -> str:
        """Get user-friendly error message for HTTP status codes"""
        error_messages = {
            400: f"Bad request to {source_name}. Source may have changed its API format.",
            401: f"Authentication required for {source_name}. This source may now require an API key.",
            403: f"Access forbidden to {source_name}. Source may have blocked automated requests or changed access policy.",
            404: f"Source {source_name} not found. URL may have changed or service discontinued.",
            429: f"Rate limit exceeded for {source_name}. Too many requests sent too quickly.",
            500: f"Server error at {source_name}. Source is experiencing technical difficulties.",
            502: f"Bad gateway for {source_name}. Source server is temporarily unavailable.",
            503: f"Service unavailable for {source_name}. Source is temporarily down for maintenance.",
            504: f"Gateway timeout for {source_name}. Source is taking too long to respond."
        }
        
        default_message = f"HTTP {status_code} error for {source_name}. Source may be temporarily unavailable."
        return error_messages.get(status_code, default_message)
    
    def _parse_html_tables(self, soup: BeautifulSoup, source: EnhancedProxySource) -> List[ProxyInfo]:
        """Parse proxies from HTML tables"""
        proxies = []
        
        # Find tables
        if source.table_selector:
            tables = soup.select(source.table_selector)
        else:
            tables = soup.find_all('table')
        
        for table in tables:
            rows = table.find_all('tr')
            
            # Skip tables with too few rows
            if len(rows) < 2:
                continue
            
            # Parse rows
            for row in rows[1:]:  # Skip header row
                cells = row.find_all(['td', 'th'])
                if len(cells) < 2:
                    continue
                
                proxy = self._parse_table_row(cells)
                if proxy:
                    proxies.append(proxy)
        
        return proxies
    
    def _parse_table_row(self, cells: List) -> Optional[ProxyInfo]:
        """Parse proxy from table row"""
        try:
            # Extract text from cells
            cell_texts = [cell.get_text().strip() for cell in cells]
            
            ip = None
            port = None
            
            # Look for IP and port in cells
            for text in cell_texts:
                # Check if it's an IP address
                if self._is_valid_ip(text):
                    ip = text
                # Check if it's a port number
                elif text.isdigit() and 1 <= int(text) <= 65535:
                    port = int(text)
            
            if ip and port:
                return ProxyInfo(
                    host=ip,
                    port=port,
                    protocol=ProxyProtocol.HTTP  # Default to HTTP
                )
                
        except Exception as e:
            self.logger.debug(f"Failed to parse table row: {e}")
        
        return None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                if not (0 <= int(part) <= 255):
                    return False
            
            return True
        except (ValueError, AttributeError):
            return False
    
    def _filter_proxies(self, proxies: List[ProxyInfo]) -> List[ProxyInfo]:
        """Filter out invalid proxies"""
        filtered = []
        
        for proxy in proxies:
            # Basic validation
            if not self._is_valid_ip(proxy.host):
                continue
            
            if not (1 <= proxy.port <= 65535):
                continue
            
            # Skip private IPs
            if self._is_private_ip(proxy.host):
                continue
            
            filtered.append(proxy)
        
        return filtered
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = [int(p) for p in ip.split('.')]
            
            # Private ranges
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:  # Loopback
                return True
            if parts[0] == 169 and parts[1] == 254:  # Link-local
                return True
                
            return False
            
        except (ValueError, IndexError):
            return True  # If we can't parse it, consider it invalid


class TextListFetcher(BaseFetcher):
    """Specialized fetcher for text-based proxy lists"""
    
    def fetch_from_source(self, source: EnhancedProxySource) -> EnhancedFetchResult:
        """Fetch proxies from text list"""
        start_time = time.time()
        result = EnhancedFetchResult(source_name=source.name, proxies_found=[], success=False)
        
        try:
            # Enforce rate limiting
            self._enforce_rate_limit(source)
            
            # Make request
            self.logger.info(f"Fetching from text list: {source.name}")
            response = self.session.get(
                source.url,
                headers=source.headers,
                timeout=source.timeout
            )
            response.raise_for_status()
            
            result.raw_data_size = len(response.content)
            
            # Parse text content
            content = response.text
            proxies = self._parse_text_content(content, source)
            
            # Filter and limit
            proxies = self._filter_proxies(proxies)
            if len(proxies) > source.max_proxies:
                proxies = proxies[:source.max_proxies]
            
            result.proxies_found = proxies
            result.parsed_count = len(proxies)
            result.filtered_count = len(proxies)
            result.success = True
            
            # Update source statistics
            source.success_count += 1
            source.last_success = datetime.utcnow()
            
            self.logger.info(f"Successfully fetched {len(proxies)} proxies from {source.name}")
            
        except requests.exceptions.HTTPError as e:
            # Handle specific HTTP status codes with actionable messages
            status_code = e.response.status_code if e.response else 0
            result.error_message = self._get_http_error_message(status_code, source.name)
            source.failure_count += 1
            
            # Mark source as temporarily disabled for certain errors
            if status_code in [403, 429, 503]:
                source.enabled = False
                # Set cooldown period: 403/503 = 1 hour, 429 = 30 minutes
                cooldown_minutes = 60 if status_code in [403, 503] else 30
                source.disabled_until = datetime.utcnow() + timedelta(minutes=cooldown_minutes)
                self.logger.warning(f"Temporarily disabled {source.name} due to HTTP {status_code} for {cooldown_minutes} minutes")
            
            self.logger.error(f"HTTP {status_code} error for {source.name}: {result.error_message}")
            
        except requests.exceptions.Timeout as e:
            result.error_message = f"Request timeout after {source.timeout}s. Source may be slow or overloaded."
            source.failure_count += 1
            self.logger.error(f"Timeout for {source.name}: {e}")
            
        except requests.exceptions.ConnectionError as e:
            result.error_message = f"Connection failed. Source may be down or unreachable."
            source.failure_count += 1
            self.logger.error(f"Connection error for {source.name}: {e}")
            
        except requests.exceptions.RequestException as e:
            result.error_message = f"Network error: {str(e)}"
            source.failure_count += 1
            self.logger.error(f"Request failed for {source.name}: {e}")
            
        except Exception as e:
            # Try to provide more specific error context
            if "json" in str(e).lower() or "parsing" in str(e).lower():
                result.error_message = f"Data parsing error: {str(e)}. Source may have changed format."
            elif "beautifulsoup" in str(e).lower() or "html" in str(e).lower():
                result.error_message = f"HTML parsing error: {str(e)}. Source may have changed page structure."
            else:
                result.error_message = f"Unexpected error: {str(e)}"
            
            source.failure_count += 1
            self.logger.error(f"Unexpected error for {source.name}: {e}")
        
        finally:
            result.fetch_duration = time.time() - start_time
        
        return result
    
    def _parse_text_content(self, content: str, source: EnhancedProxySource) -> List[ProxyInfo]:
        """Parse proxies from text content"""
        proxies = []
        
        try:
            # Use pattern from source or default pattern
            pattern = source.proxy_pattern or r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})'
            
            matches = re.findall(pattern, content)
            
            for match in matches:
                if len(match) >= 2:
                    ip, port = match[0], match[1]
                    
                    try:
                        proxy = ProxyInfo(
                            host=ip,
                            port=int(port),
                            protocol=ProxyProtocol.HTTP
                        )
                        proxies.append(proxy)
                    except ValueError:
                        continue
                        
        except Exception as e:
            self.logger.error(f"Error parsing text content: {e}")
        
        return proxies
    
    def _filter_proxies(self, proxies: List[ProxyInfo]) -> List[ProxyInfo]:
        """Filter out invalid proxies"""
        filtered = []
        
        for proxy in proxies:
            # Basic validation
            if not self._is_valid_ip(proxy.host):
                continue
            
            if not (1 <= proxy.port <= 65535):
                continue
            
            # Skip private IPs
            if self._is_private_ip(proxy.host):
                continue
            
            filtered.append(proxy)
        
        return filtered
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                if not (0 <= int(part) <= 255):
                    return False
            
            return True
        except (ValueError, AttributeError):
            return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = [int(p) for p in ip.split('.')]
            
            # Private ranges
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:  # Loopback
                return True
            if parts[0] == 169 and parts[1] == 254:  # Link-local
                return True
                
            return False
            
        except (ValueError, IndexError):
            return True  # If we can't parse it, consider it invalid


# ===============================================================================
# ENHANCED SOURCE DEFINITIONS
# ===============================================================================

# Define the default enhanced proxy sources based on the YAML config
ENHANCED_SOURCES = [
    # ProxyScrape API Source  
    EnhancedProxySource(
        name="proxyscrape_api",
        url="https://api.proxyscrape.com/v2/?request=get&format=json&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
        source_type=SourceType.API,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Accept": "application/json"},
        rate_limit=3.0,
        timeout=30,
        max_proxies=1000,
        json_path="proxies"
    ),
    
    # FreeProxy.World API
    EnhancedProxySource(
        name="freeproxy_world",
        url="https://www.freeproxy.world/api/proxy",
        source_type=SourceType.API,
        headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"},
        rate_limit=2.0,
        timeout=25,
        max_proxies=500
    ),
    
    # HideMyName HTML Table
    EnhancedProxySource(
        name="hidemy_name",
        url="https://hidemy.name/en/proxy-list/?maxtime=1000&type=h#list",
        source_type=SourceType.HTML_TABLE,
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        rate_limit=4.0,
        timeout=30,
        max_proxies=200,
        table_selector="table.proxy__t"
    ),
    
    # Proxy-List.Download Text List
    EnhancedProxySource(
        name="proxy_list_download",
        url="https://www.proxy-list.download/api/v1/get?type=http",
        source_type=SourceType.TEXT_LIST,
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        rate_limit=2.0,
        timeout=20,
        max_proxies=300,
        proxy_pattern=r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})'
    )
]


# ===============================================================================
# MAIN ENHANCED PROXY FETCHER
# ===============================================================================

class EnhancedProxyFetcher:
    """Enhanced proxy fetcher with intelligent source management"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Initialize sources
        self.sources = {source.name: source for source in ENHANCED_SOURCES}
        
        # Initialize specialized fetchers
        self.api_fetcher = APIFetcher(config)
        self.html_fetcher = HTMLFetcher(config)
        self.text_fetcher = TextListFetcher(config)
        
        # Statistics
        self.fetch_statistics = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'total_proxies_found': 0
        }
        
        self.logger.info("Enhanced proxy fetcher initialized")
    
    def fetch_from_source(self, source_name: str) -> EnhancedFetchResult:
        """Fetch proxies from a specific source"""
        if source_name not in self.sources:
            return EnhancedFetchResult(
                source_name=source_name,
                proxies_found=[],
                success=False,
                error_message=f"Unknown source: {source_name}"
            )
        
        source = self.sources[source_name]
        
        # Check if disabled source should be re-enabled
        self._check_and_reenable_source(source)
        
        if not source.enabled:
            disabled_msg = "Source is disabled"
            if source.disabled_until:
                time_remaining = (source.disabled_until - datetime.utcnow()).total_seconds() / 60
                if time_remaining > 0:
                    disabled_msg = f"Source is temporarily disabled. Will retry in {time_remaining:.0f} minutes."
            
            return EnhancedFetchResult(
                source_name=source_name,
                proxies_found=[],
                success=False,
                error_message=disabled_msg
            )
        
        # Update statistics
        self.fetch_statistics['total_requests'] += 1
        
        # Choose appropriate fetcher
        try:
            if source.source_type == SourceType.API:
                result = self.api_fetcher.fetch_from_source(source)
            elif source.source_type == SourceType.HTML_TABLE:
                result = self.html_fetcher.fetch_from_source(source)
            elif source.source_type == SourceType.TEXT_LIST:
                result = self.text_fetcher.fetch_from_source(source)
            else:
                result = EnhancedFetchResult(
                    source_name=source_name,
                    proxies_found=[],
                    success=False,
                    error_message=f"Unsupported source type: {source.source_type}"
                )
            
            # Update statistics
            if result.success:
                self.fetch_statistics['successful_requests'] += 1
                self.fetch_statistics['total_proxies_found'] += len(result.proxies_found)
            else:
                self.fetch_statistics['failed_requests'] += 1
            
            return result
            
        except Exception as e:
            self.fetch_statistics['failed_requests'] += 1
            self.logger.error(f"Fetching failed for {source_name}: {e}")
            return EnhancedFetchResult(
                source_name=source_name,
                proxies_found=[],
                success=False,
                error_message=str(e)
            )
    
    def fetch_from_all_sources(self) -> List[EnhancedFetchResult]:
        """Fetch proxies from all enabled sources"""
        results = []
        
        for source_name, source in self.sources.items():
            if source.enabled:
                result = self.fetch_from_source(source_name)
                results.append(result)
        
        return results

    def fetch_proxies(self, source_names: Optional[List[str]] = None, 
                        max_proxies: int = 1000) -> List[ProxyInfo]:
            """
            Fetch proxies from specified sources (or all sources)
            Compatible interface for CLI usage
            """
            all_proxies = []
            
            if source_names:
                # Fetch from specific sources
                for source_name in source_names:
                    try:
                        result = self.fetch_from_source(source_name)
                        if result.success:
                            all_proxies.extend(result.proxies_found)
                            self.logger.info(f"Fetched {len(result.proxies_found)} proxies from {source_name}")
                    except Exception as e:
                        self.logger.error(f"Failed to fetch from {source_name}: {e}")
            else:
                # Fetch from all sources
                results = self.fetch_from_all_sources()
                for result in results:
                    if result.success:
                        all_proxies.extend(result.proxies_found)
                        self.logger.info(f"Fetched {len(result.proxies_found)} proxies from {result.source_name}")
            
            # Remove duplicates while preserving order
            seen = set()
            unique_proxies = []
            for proxy in all_proxies:
                proxy_key = f"{proxy.host}:{proxy.port}"
                if proxy_key not in seen:
                    seen.add(proxy_key)
                    unique_proxies.append(proxy)
            
            # Limit results
            if len(unique_proxies) > max_proxies:
                unique_proxies = unique_proxies[:max_proxies]
            
            self.logger.info(f"Total unique proxies fetched: {len(unique_proxies)}")
            return unique_proxies

    def get_source_statistics(self, source_name: str) -> Dict[str, Any]:
        """Get statistics for a specific source"""
        if source_name not in self.sources:
            return {}
        
        source = self.sources[source_name]
        
        stats = {
            'name': source.name,
            'enabled': source.enabled,
            'success_count': source.success_count,
            'failure_count': source.failure_count,
            'success_rate': source.success_rate,
            'last_success': source.last_success.isoformat() if source.last_success else None,
            'source_type': source.source_type.value,
            'rate_limit': source.rate_limit,
            'max_proxies': source.max_proxies
        }
        
        return stats
    
    def get_fetcher_statistics(self) -> Dict[str, Any]:
        """Get overall fetcher statistics"""
        return self.fetch_statistics.copy()
    
    def enable_source(self, source_name: str) -> bool:
        """Enable a proxy source"""
        if source_name in self.sources:
            self.sources[source_name].enabled = True
            self.logger.info(f"Enabled source: {source_name}")
            return True
        return False
    
    def disable_source(self, source_name: str) -> bool:
        """Disable a proxy source"""
        if source_name in self.sources:
            self.sources[source_name].enabled = False
            self.logger.info(f"Disabled source: {source_name}")
            return True
        return False
    
    def get_available_sources(self) -> List[str]:
        """Get list of available source names"""
        return list(self.sources.keys())
    
    def add_custom_source(self, source: EnhancedProxySource):
        """Add a custom proxy source"""
        self.sources[source.name] = source
        self.logger.info(f"Added custom source: {source.name}")
    
    def remove_source(self, source_name: str) -> bool:
        """Remove a proxy source"""
        if source_name in self.sources:
            del self.sources[source_name]
            self.logger.info(f"Removed source: {source_name}")
            return True
        return False
    
    def _check_and_reenable_source(self, source: EnhancedProxySource):
        """Check if a disabled source should be re-enabled after cooldown period"""
        if not source.enabled and source.disabled_until:
            if datetime.utcnow() >= source.disabled_until:
                source.enabled = True
                source.disabled_until = None
                self.logger.info(f"Re-enabled source {source.name} after cooldown period")
    
    def check_all_disabled_sources(self):
        """Check all sources for automatic re-enabling"""
        re_enabled_count = 0
        for source in self.sources.values():
            if not source.enabled and source.disabled_until:
                if datetime.utcnow() >= source.disabled_until:
                    source.enabled = True
                    source.disabled_until = None
                    re_enabled_count += 1
                    self.logger.info(f"Re-enabled source {source.name} after cooldown period")
        
        if re_enabled_count > 0:
            self.logger.info(f"Re-enabled {re_enabled_count} sources after cooldown period")


# ===============================================================================
# COMPATIBILITY LAYER FOR EXISTING CODE
# ===============================================================================

# Maintain compatibility with existing code
ProxyFetcher = EnhancedProxyFetcher
FetchResult = EnhancedFetchResult
ProxySource = EnhancedProxySource

# Export the main classes for CLI integration
__all__ = [
    'EnhancedProxyFetcher',
    'ProxyFetcher',
    'EnhancedFetchResult', 
    'FetchResult',
    'EnhancedProxySource',
    'ProxySource',
    'SourceType',
    'ENHANCED_SOURCES'
]

logger.info("Enhanced proxy fetchers module loaded successfully")
