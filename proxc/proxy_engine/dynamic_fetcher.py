"""Dynamic Proxy Fetcher with Configuration-Driven Sources

This module provides a new generation fetcher that uses the configuration-driven
source system for maximum flexibility and maintainability.
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urljoin, urlparse
import threading

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

try:
    import jsonpath_ng
    HAS_JSONPATH = True
except ImportError:
    HAS_JSONPATH = False

# Import our core modules
from ..proxy_core.models import (
    ProxyInfo, ProxyProtocol, AnonymityLevel, ThreatLevel,
    ProxyStatus, ValidationStatus
)
from ..proxy_core.config import ConfigManager
from ..proxy_core.rate_limiter import get_rate_limiter, RateLimitConfig
from ..proxy_core.deduplication import get_deduplicator
from ..config.source_registry import get_source_registry, ProxySource
from ..config.proxy_sources_config import load_proxy_sources

logger = logging.getLogger(__name__)


@dataclass
class FetchResult:
    """Result of a fetch operation"""
    source_name: str
    proxies_found: List[ProxyInfo]
    success: bool
    error_message: Optional[str] = None
    fetch_duration: float = 0.0
    raw_data_size: int = 0
    parsed_count: int = 0
    filtered_count: int = 0
    deduplication_stats: Optional[Dict[str, Any]] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate based on found proxies"""
        if self.parsed_count == 0:
            return 0.0
        return (len(self.proxies_found) / self.parsed_count) * 100


class SourceParser:
    """Parser for different source types"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def parse_api_response(self, source: ProxySource, response_text: str) -> List[ProxyInfo]:
        """Parse API JSON response"""
        try:
            data = json.loads(response_text)
            proxies = []
            
            # Use JSONPath if available and configured
            if HAS_JSONPATH and source.json_path:
                try:
                    jsonpath_expr = jsonpath_ng.parse(source.json_path)
                    matches = jsonpath_expr.find(data)
                    proxy_data = [match.value for match in matches]
                except Exception as e:
                    self.logger.warning(f"JSONPath failed for {source.name}: {e}")
                    proxy_data = data if isinstance(data, list) else [data]
            else:
                # Fallback to direct parsing
                if isinstance(data, list):
                    proxy_data = data
                elif isinstance(data, dict):
                    # Try common response keys
                    for key in ['proxies', 'data', 'results', 'proxy_list']:
                        if key in data and isinstance(data[key], list):
                            proxy_data = data[key]
                            break
                    else:
                        proxy_data = [data]
                else:
                    proxy_data = []
            
            # Parse individual proxy entries
            for item in proxy_data:
                proxy = self._parse_proxy_item(source, item)
                if proxy:
                    proxies.append(proxy)
            
            return proxies
            
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON decode error for {source.name}: {e}")
            return []
        except Exception as e:
            self.logger.error(f"API parsing error for {source.name}: {e}")
            return []
    
    def parse_html_table(self, source: ProxySource, html_content: str) -> List[ProxyInfo]:
        """Parse HTML table response"""
        if not HAS_BEAUTIFULSOUP:
            self.logger.error("BeautifulSoup4 required for HTML parsing")
            return []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            proxies = []
            
            # Find table using selector
            table_selector = source.table_selector or 'table'
            tables = soup.select(table_selector)
            
            if not tables:
                self.logger.warning(f"No tables found with selector '{table_selector}' for {source.name}")
                return []
            
            table = tables[0]  # Use first table
            
            # Find rows
            row_selector = source.row_selector or 'tr'
            rows = table.select(row_selector)
            
            for row in rows:
                cells = row.find_all(['td', 'th'])
                if len(cells) < 2:  # Need at least IP and port
                    continue
                
                proxy = self._parse_table_row(source, cells)
                if proxy:
                    proxies.append(proxy)
            
            return proxies
            
        except Exception as e:
            self.logger.error(f"HTML parsing error for {source.name}: {e}")
            return []
    
    def parse_text_list(self, source: ProxySource, text_content: str) -> List[ProxyInfo]:
        """Parse text list response"""
        try:
            proxies = []
            
            # Use custom pattern if provided
            if source.proxy_pattern:
                pattern = source.proxy_pattern
            else:
                # Default IP:port pattern
                pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})'
            
            matches = re.findall(pattern, text_content)
            
            for match in matches:
                if isinstance(match, tuple) and len(match) >= 2:
                    try:
                        host = match[0]
                        port = int(match[1])
                        
                        # Validate IP format
                        if self._is_valid_ip(host) and 1 <= port <= 65535:
                            proxy = ProxyInfo(
                                host=host,
                                port=port,
                                protocol=self._infer_protocol(port),
                                source=source.name
                            )
                            proxies.append(proxy)
                            
                    except (ValueError, IndexError):
                        continue
            
            return proxies
            
        except Exception as e:
            self.logger.error(f"Text parsing error for {source.name}: {e}")
            return []
    
    def parse_multi_source(self, source: ProxySource, responses: List[str]) -> List[ProxyInfo]:
        """Parse multiple responses for multi-source"""
        all_proxies = []
        
        for i, response_text in enumerate(responses):
            # Determine format based on content
            if response_text.strip().startswith('{') or response_text.strip().startswith('['):
                proxies = self.parse_api_response(source, response_text)
            elif '<table' in response_text.lower() or '<tr' in response_text.lower():
                proxies = self.parse_html_table(source, response_text)
            else:
                proxies = self.parse_text_list(source, response_text)
            
            # Add URL index to source name for tracking
            for proxy in proxies:
                proxy.source = f"{source.name}[{i}]"
            
            all_proxies.extend(proxies)
        
        return all_proxies
    
    def _parse_proxy_item(self, source: ProxySource, item: Union[Dict, str]) -> Optional[ProxyInfo]:
        """Parse individual proxy item from API response"""
        try:
            if isinstance(item, str):
                # Handle string format like "IP:PORT"
                if ':' in item:
                    parts = item.split(':')
                    host = parts[0].strip()
                    port = int(parts[1].strip())
                else:
                    return None
            elif isinstance(item, dict):
                # Handle dictionary format
                response_format = source.response_format or {}
                
                # Get field mappings
                ip_field = response_format.get('ip_field', 'ip')
                port_field = response_format.get('port_field', 'port')
                protocol_field = response_format.get('protocol_field', 'protocol')
                country_field = response_format.get('country_field', 'country')
                anonymity_field = response_format.get('anonymity_field', 'anonymity')
                
                # Extract values
                host = item.get(ip_field) or item.get('host') or item.get('address')
                port = item.get(port_field)
                protocol = item.get(protocol_field, 'http')
                country = item.get(country_field)
                anonymity = item.get(anonymity_field)
                
                if not host or not port:
                    return None
                
                port = int(port)
            else:
                return None
            
            # Validate IP and port
            if not self._is_valid_ip(host) or not (1 <= port <= 65535):
                return None
            
            # Create proxy info
            proxy = ProxyInfo(
                host=host,
                port=port,
                protocol=self._parse_protocol(protocol) if isinstance(item, dict) else self._infer_protocol(port),
                source=source.name
            )
            
            # Set additional fields if available
            if isinstance(item, dict):
                if country:
                    # Would set geo_location if available
                    pass
                
                if anonymity:
                    proxy.anonymity_level = self._parse_anonymity(anonymity)
            
            return proxy
            
        except (ValueError, KeyError, TypeError) as e:
            self.logger.debug(f"Failed to parse proxy item: {e}")
            return None
    
    def _parse_table_row(self, source: ProxySource, cells) -> Optional[ProxyInfo]:
        """Parse table row into proxy info"""
        try:
            column_mapping = source.column_mapping or {}
            
            # Default column mapping
            ip_col = column_mapping.get('ip', 0)
            port_col = column_mapping.get('port', 1)
            protocol_col = column_mapping.get('protocol', None)
            country_col = column_mapping.get('country', None)
            anonymity_col = column_mapping.get('anonymity', None)
            
            # Extract values
            if len(cells) <= max(ip_col, port_col):
                return None
            
            host = cells[ip_col].get_text(strip=True)
            port_text = cells[port_col].get_text(strip=True)
            
            try:
                port = int(port_text)
            except ValueError:
                return None
            
            # Validate
            if not self._is_valid_ip(host) or not (1 <= port <= 65535):
                return None
            
            # Create proxy
            proxy = ProxyInfo(
                host=host,
                port=port,
                protocol=self._infer_protocol(port),
                source=source.name
            )
            
            # Set additional fields
            if protocol_col is not None and len(cells) > protocol_col:
                protocol_text = cells[protocol_col].get_text(strip=True)
                proxy.protocol = self._parse_protocol(protocol_text)
            
            if anonymity_col is not None and len(cells) > anonymity_col:
                anonymity_text = cells[anonymity_col].get_text(strip=True)
                proxy.anonymity_level = self._parse_anonymity(anonymity_text)
            
            return proxy
            
        except Exception as e:
            self.logger.debug(f"Failed to parse table row: {e}")
            return None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            for part in parts:
                num = int(part)
                if not (0 <= num <= 255):
                    return False
            return True
        except ValueError:
            return False
    
    def _infer_protocol(self, port: int) -> ProxyProtocol:
        """Infer protocol from port number"""
        if port in [1080, 9050, 9150]:
            return ProxyProtocol.SOCKS5
        elif port in [1081, 9051]:
            return ProxyProtocol.SOCKS4
        elif port in [443, 8443]:
            return ProxyProtocol.HTTPS
        else:
            return ProxyProtocol.HTTP
    
    def _parse_protocol(self, protocol_text: str) -> ProxyProtocol:
        """Parse protocol from text"""
        if not protocol_text:
            return ProxyProtocol.HTTP
        
        protocol_lower = protocol_text.lower().strip()
        
        if 'socks5' in protocol_lower or 'socks 5' in protocol_lower:
            return ProxyProtocol.SOCKS5
        elif 'socks4' in protocol_lower or 'socks 4' in protocol_lower:
            return ProxyProtocol.SOCKS4
        elif 'https' in protocol_lower:
            return ProxyProtocol.HTTPS
        else:
            return ProxyProtocol.HTTP
    
    def _parse_anonymity(self, anonymity_text: str) -> AnonymityLevel:
        """Parse anonymity level from text"""
        if not anonymity_text:
            return AnonymityLevel.TRANSPARENT
        
        anonymity_lower = anonymity_text.lower().strip()
        
        if 'elite' in anonymity_lower or 'high' in anonymity_lower:
            return AnonymityLevel.ELITE
        elif 'anonymous' in anonymity_lower or 'medium' in anonymity_lower:
            return AnonymityLevel.ANONYMOUS
        else:
            return AnonymityLevel.TRANSPARENT


class RequestManager:
    """Manages HTTP requests with retries and error handling"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.session = None
        self._init_session()
    
    def _init_session(self):
        """Initialize requests session with retry strategy"""
        if not HAS_REQUESTS:
            self.logger.error("Requests library not available")
            return
        
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def fetch_source(self, source: ProxySource) -> Union[str, List[str]]:
        """Fetch content from a source"""
        if not self.session:
            raise RuntimeError("HTTP session not initialized")
        
        try:
            # Handle multi-source
            if source.source_type == "multi_source" and source.urls:
                return self._fetch_multi_urls(source)
            
            # Single URL fetch
            url = source.url
            if not url:
                raise ValueError(f"No URL configured for source {source.name}")
            
            return self._fetch_single_url(source, url)
            
        except Exception as e:
            self.logger.error(f"Failed to fetch from {source.name}: {e}")
            raise
    
    def _fetch_single_url(self, source: ProxySource, url: str) -> str:
        """Fetch content from a single URL"""
        headers = source.headers.copy()
        
        # Add default headers if not present
        if 'User-Agent' not in headers:
            headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Handle authentication
        auth = None
        if source.auth_type == 'basic' and source.username and source.password:
            auth = (source.username, source.password)
        elif source.auth_type == 'bearer' and source.api_key:
            headers['Authorization'] = f'Bearer {source.api_key}'
        elif source.auth_type == 'api_key' and source.api_key:
            headers['X-API-Key'] = source.api_key
        
        response = self.session.get(
            url,
            headers=headers,
            auth=auth,
            timeout=source.timeout,
            verify=False  # Don't verify SSL for proxy sources
        )
        
        response.raise_for_status()
        return response.text
    
    def _fetch_multi_urls(self, source: ProxySource) -> List[str]:
        """Fetch content from multiple URLs"""
        responses = []
        
        for url in source.urls:
            try:
                response_text = self._fetch_single_url(source, url)
                responses.append(response_text)
            except Exception as e:
                self.logger.warning(f"Failed to fetch from {url}: {e}")
                # Continue with other URLs
                responses.append("")  # Empty response for failed URL
        
        return responses


class DynamicProxyFetcher:
    """Dynamic proxy fetcher using configuration-driven sources"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.source_registry = get_source_registry(config)
        self.rate_limiter = get_rate_limiter()
        self.deduplicator = get_deduplicator()
        self.parser = SourceParser()
        self.request_manager = RequestManager(config)
        
        # Load configuration
        self.sources_config = load_proxy_sources()
        if not self.sources_config:
            self.logger.warning("No proxy sources configuration loaded")
        
        # Performance tracking
        self.fetch_history = []
        self._lock = threading.Lock()
        
        self.logger.info("DynamicProxyFetcher initialized")
    
    def fetch_from_source(self, source_name: str) -> FetchResult:
        """Fetch proxies from a specific source"""
        start_time = time.time()
        
        # Get source configuration
        source = self.source_registry.get_source(source_name)
        if not source:
            return FetchResult(
                source_name=source_name,
                proxies_found=[],
                success=False,
                error_message=f"Source '{source_name}' not found"
            )
        
        if not source.enabled:
            return FetchResult(
                source_name=source_name,
                proxies_found=[],
                success=False,
                error_message=f"Source '{source_name}' is disabled"
            )
        
        self.logger.info(f"Fetching from source: {source_name}")
        
        try:
            # Rate limiting
            rate_config = RateLimitConfig(
                requests_per_second=1.0 / source.rate_limit,
                burst_size=source.concurrent_requests
            )
            
            with self.rate_limiter.rate_limited_request(source_name, rate_config) as request_context:
                # Update headers with anti-detection info
                enhanced_headers = source.headers.copy()
                enhanced_headers.update(request_context['headers'])
                enhanced_headers['User-Agent'] = request_context['user_agent']
                
                # Create temporary source with enhanced headers
                enhanced_source = source
                enhanced_source.headers = enhanced_headers
                
                # Fetch content
                raw_content = self.request_manager.fetch_source(enhanced_source)
                
                # Parse content based on source type
                if source.source_type == "api":
                    proxies = self.parser.parse_api_response(source, raw_content)
                elif source.source_type == "html_table":
                    proxies = self.parser.parse_html_table(source, raw_content)
                elif source.source_type == "text_list":
                    proxies = self.parser.parse_text_list(source, raw_content)
                elif source.source_type == "multi_source":
                    proxies = self.parser.parse_multi_source(source, raw_content)
                else:
                    raise ValueError(f"Unknown source type: {source.source_type}")
                
                # Apply source-specific limits
                if len(proxies) > source.max_proxies:
                    proxies = proxies[:source.max_proxies]
                
                # Deduplication
                unique_proxies, dedup_stats = self.deduplicator.deduplicate_proxies(proxies, source_name)
                
                # Calculate metrics
                fetch_duration = time.time() - start_time
                raw_data_size = len(raw_content) if isinstance(raw_content, str) else sum(len(r) for r in raw_content)
                
                # Update source health
                self.source_registry.update_source_health(
                    source_name, 
                    success=True, 
                    response_time=fetch_duration * 1000,  # Convert to ms
                    proxy_count=len(unique_proxies)
                )
                
                result = FetchResult(
                    source_name=source_name,
                    proxies_found=unique_proxies,
                    success=True,
                    fetch_duration=fetch_duration,
                    raw_data_size=raw_data_size,
                    parsed_count=len(proxies),
                    filtered_count=len(unique_proxies),
                    deduplication_stats=dedup_stats.__dict__ if dedup_stats else None
                )
                
                self.logger.info(
                    f"Fetched {len(unique_proxies)} unique proxies from {source_name} "
                    f"(parsed: {len(proxies)}, duration: {fetch_duration:.2f}s)"
                )
                
                # Record result
                with self._lock:
                    self.fetch_history.append(result)
                    if len(self.fetch_history) > 100:
                        self.fetch_history = self.fetch_history[-100:]
                
                return result
        
        except Exception as e:
            # Update source health with failure
            self.source_registry.update_source_health(
                source_name,
                success=False,
                error_message=str(e)
            )
            
            error_result = FetchResult(
                source_name=source_name,
                proxies_found=[],
                success=False,
                error_message=str(e),
                fetch_duration=time.time() - start_time
            )
            
            self.logger.error(f"Failed to fetch from {source_name}: {e}")
            
            with self._lock:
                self.fetch_history.append(error_result)
            
            return error_result
    
    def fetch_from_sources(self, source_names: List[str], 
                          max_concurrent: int = 3) -> List[FetchResult]:
        """Fetch from multiple sources concurrently"""
        results = []
        
        # Process in batches to respect rate limits
        for i in range(0, len(source_names), max_concurrent):
            batch = source_names[i:i + max_concurrent]
            
            # Use ThreadPoolExecutor for concurrent requests
            import concurrent.futures
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
                future_to_source = {
                    executor.submit(self.fetch_from_source, source_name): source_name
                    for source_name in batch
                }
                
                for future in concurrent.futures.as_completed(future_to_source):
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        source_name = future_to_source[future]
                        self.logger.error(f"Concurrent fetch failed for {source_name}: {e}")
                        results.append(FetchResult(
                            source_name=source_name,
                            proxies_found=[],
                            success=False,
                            error_message=str(e)
                        ))
        
        return results
    
    def fetch_by_profile(self, profile_name: str) -> List[FetchResult]:
        """Fetch using a predefined collection profile"""
        if not self.sources_config:
            raise RuntimeError("No sources configuration available")
        
        profile = self.sources_config.get_profile(profile_name)
        if not profile:
            raise ValueError(f"Profile '{profile_name}' not found")
        
        # Expand source patterns
        source_names = self.sources_config.expand_source_patterns(profile.sources)
        
        # Filter by quality if specified
        if profile.quality_threshold > 0:
            filtered_sources = []
            for source_name in source_names:
                source = self.source_registry.get_source(source_name)
                if source and source.quality_score >= profile.quality_threshold:
                    filtered_sources.append(source_name)
            source_names = filtered_sources
        
        self.logger.info(
            f"Fetching using profile '{profile_name}': {len(source_names)} sources, "
            f"max {profile.max_proxies} proxies"
        )
        
        # Fetch from sources
        results = self.fetch_from_sources(source_names, profile.concurrent_sources)
        
        # Combine and limit results
        all_proxies = []
        for result in results:
            all_proxies.extend(result.proxies_found)
        
        if len(all_proxies) > profile.max_proxies:
            # Sort by quality and take the best
            all_proxies.sort(key=lambda p: (
                p.status.value if hasattr(p.status, 'value') else 0,
                -(p.metrics.response_time or 999999) if p.metrics else 0
            ), reverse=True)
            all_proxies = all_proxies[:profile.max_proxies]
        
        # Update results with limited proxies
        total_found = sum(len(r.proxies_found) for r in results)
        self.logger.info(
            f"Profile '{profile_name}' completed: {total_found} total found, "
            f"{len(all_proxies)} after limits"
        )
        
        return results
    
    def get_available_sources(self) -> List[str]:
        """Get list of available source names"""
        return [name for name, source in self.source_registry.sources.items() if source.enabled]
    
    def get_source_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        return self.source_registry.get_source_statistics()
    
    def get_fetch_history(self, limit: int = 10) -> List[FetchResult]:
        """Get recent fetch history"""
        with self._lock:
            return self.fetch_history[-limit:] if self.fetch_history else []


# Convenience functions
def create_dynamic_fetcher(config: Optional[ConfigManager] = None) -> DynamicProxyFetcher:
    """Create a new dynamic proxy fetcher"""
    return DynamicProxyFetcher(config)


def fetch_proxies_by_profile(profile_name: str, 
                           config: Optional[ConfigManager] = None) -> List[FetchResult]:
    """Fetch proxies using a specific profile"""
    fetcher = create_dynamic_fetcher(config)
    return fetcher.fetch_by_profile(profile_name)