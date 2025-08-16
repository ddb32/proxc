"""
Search Engine Integration for Proxy Discovery
============================================

Integrates with major search engines to discover proxy-related content
using specialized search queries, Google dorks, and automated monitoring.
"""

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
from typing import Dict, List, Optional, Set, Tuple, Union, Any
from urllib.parse import quote_plus, urljoin, urlparse

# Third-party imports with fallbacks
try:
    import requests
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

# Import our core types
from . import SearchEngine, ContentType
from ..proxy_core.models import ProxyInfo

logger = logging.getLogger(__name__)


@dataclass
class SearchConfig:
    """Configuration for search engine operations"""
    # API configuration
    google_api_key: Optional[str] = None
    google_cx: Optional[str] = None  # Custom Search Engine ID
    bing_api_key: Optional[str] = None
    
    # Search parameters
    results_per_query: int = 10
    max_results: int = 100
    search_language: str = "en"
    search_region: str = "US"
    
    # Rate limiting
    requests_per_minute: int = 30
    delay_between_requests: float = 2.0
    retry_attempts: int = 3
    retry_delay: float = 5.0
    
    # Content filtering
    min_content_length: int = 100
    max_content_age_days: int = 30
    exclude_domains: Set[str] = field(default_factory=set)
    include_only_domains: Set[str] = field(default_factory=set)
    
    # Proxy-specific search terms
    proxy_keywords: List[str] = field(default_factory=lambda: [
        "proxy list", "free proxy", "working proxy", "socks proxy",
        "http proxy", "anonymous proxy", "proxy server", "proxy site"
    ])


@dataclass
class SearchResult:
    """Result from search engine query"""
    title: str
    url: str
    snippet: str
    source_engine: SearchEngine
    
    # Content analysis
    content_type: Optional[ContentType] = None
    proxy_indicators: List[str] = field(default_factory=list)
    potential_proxies: List[str] = field(default_factory=list)
    
    # Metadata
    search_timestamp: datetime = field(default_factory=datetime.utcnow)
    relevance_score: float = 0.0
    content_length: Optional[int] = None
    last_modified: Optional[datetime] = None
    
    # Additional data
    domain: Optional[str] = None
    language: Optional[str] = None
    raw_content: Optional[str] = None


class SearchProvider(ABC):
    """Abstract base class for search providers"""
    
    def __init__(self, config: SearchConfig):
        self.config = config
        self.last_request_time = 0.0
        self.request_count = 0
        self.rate_limit_reset_time = time.time() + 60  # Reset every minute
    
    @abstractmethod
    async def search(self, query: str, start: int = 0) -> List[SearchResult]:
        """Perform search query"""
        pass
    
    @abstractmethod
    def get_provider_name(self) -> str:
        """Get provider name"""
        pass
    
    def _apply_rate_limiting(self):
        """Apply rate limiting to requests"""
        current_time = time.time()
        
        # Reset rate limit counter every minute
        if current_time > self.rate_limit_reset_time:
            self.request_count = 0
            self.rate_limit_reset_time = current_time + 60
        
        # Check if we've hit the rate limit
        if self.request_count >= self.config.requests_per_minute:
            sleep_time = self.rate_limit_reset_time - current_time + 1
            logger.info(f"Rate limit reached for {self.get_provider_name()}, sleeping {sleep_time:.1f}s")
            time.sleep(sleep_time)
            self.request_count = 0
            self.rate_limit_reset_time = time.time() + 60
        
        # Apply minimum delay between requests
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.config.delay_between_requests:
            sleep_time = self.config.delay_between_requests - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
        self.request_count += 1


class GoogleSearchProvider(SearchProvider):
    """Google Custom Search API provider"""
    
    def __init__(self, config: SearchConfig):
        super().__init__(config)
        self.base_url = "https://www.googleapis.com/customsearch/v1"
        
        if not config.google_api_key or not config.google_cx:
            logger.warning("Google API key or Custom Search Engine ID not configured")
    
    async def search(self, query: str, start: int = 0) -> List[SearchResult]:
        """Search using Google Custom Search API"""
        if not self.config.google_api_key or not self.config.google_cx:
            return []
        
        self._apply_rate_limiting()
        
        params = {
            'key': self.config.google_api_key,
            'cx': self.config.google_cx,
            'q': query,
            'num': min(self.config.results_per_query, 10),  # Max 10 per request
            'start': start + 1,  # Google uses 1-based indexing
            'lr': f'lang_{self.config.search_language}',
            'gl': self.config.search_region.lower(),
            'safe': 'off'
        }
        
        try:
            if HAS_AIOHTTP:
                return await self._search_async(params)
            else:
                return await self._search_sync(params)
        except Exception as e:
            logger.error(f"Google search failed: {e}")
            return []
    
    async def _search_async(self, params: dict) -> List[SearchResult]:
        """Async search implementation"""
        async with aiohttp.ClientSession() as session:
            async with session.get(self.base_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_google_results(data)
                else:
                    logger.error(f"Google API error: {response.status}")
                    return []
    
    async def _search_sync(self, params: dict) -> List[SearchResult]:
        """Sync search implementation"""
        if not HAS_REQUESTS:
            return []
        
        response = requests.get(self.base_url, params=params, timeout=30)
        if response.status_code == 200:
            return self._parse_google_results(response.json())
        else:
            logger.error(f"Google API error: {response.status_code}")
            return []
    
    def _parse_google_results(self, data: dict) -> List[SearchResult]:
        """Parse Google API response"""
        results = []
        
        for item in data.get('items', []):
            result = SearchResult(
                title=item.get('title', ''),
                url=item.get('link', ''),
                snippet=item.get('snippet', ''),
                source_engine=SearchEngine.GOOGLE,
                domain=urlparse(item.get('link', '')).netloc
            )
            
            # Extract additional metadata
            if 'pagemap' in item:
                pagemap = item['pagemap']
                if 'metatags' in pagemap and pagemap['metatags']:
                    metatags = pagemap['metatags'][0]
                    result.language = metatags.get('language')
            
            results.append(result)
        
        return results
    
    def get_provider_name(self) -> str:
        return "Google Custom Search"


class BingSearchProvider(SearchProvider):
    """Bing Web Search API provider"""
    
    def __init__(self, config: SearchConfig):
        super().__init__(config)
        self.base_url = "https://api.bing.microsoft.com/v7.0/search"
        
        if not config.bing_api_key:
            logger.warning("Bing API key not configured")
    
    async def search(self, query: str, start: int = 0) -> List[SearchResult]:
        """Search using Bing Web Search API"""
        if not self.config.bing_api_key:
            return []
        
        self._apply_rate_limiting()
        
        headers = {
            'Ocp-Apim-Subscription-Key': self.config.bing_api_key,
            'User-Agent': 'ProxyHunter/3.0'
        }
        
        params = {
            'q': query,
            'count': min(self.config.results_per_query, 50),
            'offset': start,
            'mkt': f'{self.config.search_language}-{self.config.search_region}',
            'safeSearch': 'Off',
            'textDecorations': False,
            'textFormat': 'Raw'
        }
        
        try:
            if HAS_AIOHTTP:
                return await self._search_async(headers, params)
            else:
                return await self._search_sync(headers, params)
        except Exception as e:
            logger.error(f"Bing search failed: {e}")
            return []
    
    async def _search_async(self, headers: dict, params: dict) -> List[SearchResult]:
        """Async search implementation"""
        async with aiohttp.ClientSession() as session:
            async with session.get(self.base_url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_bing_results(data)
                else:
                    logger.error(f"Bing API error: {response.status}")
                    return []
    
    async def _search_sync(self, headers: dict, params: dict) -> List[SearchResult]:
        """Sync search implementation"""
        if not HAS_REQUESTS:
            return []
        
        response = requests.get(self.base_url, headers=headers, params=params, timeout=30)
        if response.status_code == 200:
            return self._parse_bing_results(response.json())
        else:
            logger.error(f"Bing API error: {response.status_code}")
            return []
    
    def _parse_bing_results(self, data: dict) -> List[SearchResult]:
        """Parse Bing API response"""
        results = []
        
        for item in data.get('webPages', {}).get('value', []):
            result = SearchResult(
                title=item.get('name', ''),
                url=item.get('url', ''),
                snippet=item.get('snippet', ''),
                source_engine=SearchEngine.BING,
                domain=urlparse(item.get('url', '')).netloc
            )
            
            # Parse last modified date if available
            if 'dateLastCrawled' in item:
                try:
                    result.last_modified = datetime.fromisoformat(
                        item['dateLastCrawled'].replace('Z', '+00:00')
                    )
                except:
                    pass
            
            results.append(result)
        
        return results
    
    def get_provider_name(self) -> str:
        return "Bing Web Search"


class DuckDuckGoProvider(SearchProvider):
    """DuckDuckGo search provider (web scraping)"""
    
    def __init__(self, config: SearchConfig):
        super().__init__(config)
        self.base_url = "https://html.duckduckgo.com/html/"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    async def search(self, query: str, start: int = 0) -> List[SearchResult]:
        """Search using DuckDuckGo web interface"""
        if not HAS_BEAUTIFULSOUP:
            logger.warning("BeautifulSoup not available for DuckDuckGo scraping")
            return []
        
        self._apply_rate_limiting()
        
        params = {
            'q': query,
            'b': start,  # DuckDuckGo uses 'b' for start parameter
            'kl': f'{self.config.search_region.lower()}-{self.config.search_language.lower()}',
            'df': 'm'  # Results from last month
        }
        
        try:
            if HAS_REQUESTS:
                return await self._search_sync(params)
            else:
                return []
        except Exception as e:
            logger.error(f"DuckDuckGo search failed: {e}")
            return []
    
    async def _search_sync(self, params: dict) -> List[SearchResult]:
        """Sync search implementation (DuckDuckGo doesn't have official API)"""
        response = requests.get(
            self.base_url,
            params=params,
            headers=self.headers,
            timeout=30
        )
        
        if response.status_code == 200:
            return self._parse_duckduckgo_results(response.text)
        else:
            logger.error(f"DuckDuckGo error: {response.status_code}")
            return []
    
    def _parse_duckduckgo_results(self, html_content: str) -> List[SearchResult]:
        """Parse DuckDuckGo HTML results"""
        results = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find result links
        result_links = soup.find_all('a', class_='result__a')
        
        for link in result_links:
            title = link.get_text(strip=True)
            url = link.get('href')
            
            if not url or not title:
                continue
            
            # Find corresponding snippet
            snippet = ""
            result_div = link.find_parent('div', class_='result')
            if result_div:
                snippet_element = result_div.find('a', class_='result__snippet')
                if snippet_element:
                    snippet = snippet_element.get_text(strip=True)
            
            result = SearchResult(
                title=title,
                url=url,
                snippet=snippet,
                source_engine=SearchEngine.DUCKDUCKGO,
                domain=urlparse(url).netloc
            )
            
            results.append(result)
        
        return results
    
    def get_provider_name(self) -> str:
        return "DuckDuckGo"


class SearchEngineIntegrator:
    """Main search engine integration controller"""
    
    def __init__(self, config: SearchConfig):
        self.config = config
        self.providers: Dict[SearchEngine, SearchProvider] = {}
        self._initialize_providers()
        
        # Search query templates for proxy discovery
        self.proxy_search_templates = [
            # Basic proxy searches
            '"{}" proxy list',
            '"{}" working proxy',
            'site:pastebin.com "{}" proxy',
            'site:github.com "{}" proxy list',
            
            # Format-specific searches
            'filetype:txt proxy list',
            'filetype:json proxy list',
            'intitle:"proxy list" "{}"',
            
            # Date-specific searches
            '"proxy list" "2024" "{}"',
            '"free proxy" updated "{}"',
            
            # Service-specific
            'squid proxy list',
            'socks5 proxy list',
            'http proxy list',
            
            # Geographic searches
            '"{}" proxy list USA',
            '"{}" proxy list Europe',
            '"{}" proxy list Asia',
        ]
    
    def _initialize_providers(self):
        """Initialize available search providers"""
        # Google Custom Search
        if self.config.google_api_key and self.config.google_cx:
            self.providers[SearchEngine.GOOGLE] = GoogleSearchProvider(self.config)
        
        # Bing Web Search
        if self.config.bing_api_key:
            self.providers[SearchEngine.BING] = BingSearchProvider(self.config)
        
        # DuckDuckGo (always available via scraping)
        if HAS_BEAUTIFULSOUP and HAS_REQUESTS:
            self.providers[SearchEngine.DUCKDUCKGO] = DuckDuckGoProvider(self.config)
        
        logger.info(f"Initialized {len(self.providers)} search providers: {list(self.providers.keys())}")
    
    async def search_for_proxies(
        self,
        keywords: Optional[List[str]] = None,
        search_engines: Optional[List[SearchEngine]] = None,
        max_results_per_engine: int = 50
    ) -> List[SearchResult]:
        """Search for proxy-related content across multiple engines"""
        
        if keywords is None:
            keywords = self.config.proxy_keywords
        
        if search_engines is None:
            search_engines = list(self.providers.keys())
        
        all_results = []
        
        for engine in search_engines:
            if engine not in self.providers:
                continue
            
            provider = self.providers[engine]
            engine_results = []
            
            # Search with different keyword combinations
            for keyword in keywords[:3]:  # Limit to avoid too many requests
                queries = self._generate_search_queries(keyword)
                
                for query in queries[:2]:  # Limit queries per keyword
                    try:
                        results = await provider.search(query, start=0)
                        engine_results.extend(results)
                        
                        # Apply result limit
                        if len(engine_results) >= max_results_per_engine:
                            break
                        
                    except Exception as e:
                        logger.error(f"Search failed for query '{query}' on {engine.value}: {e}")
                
                if len(engine_results) >= max_results_per_engine:
                    break
            
            # Analyze and score results
            analyzed_results = await self._analyze_search_results(engine_results)
            all_results.extend(analyzed_results)
            
            logger.info(f"Found {len(analyzed_results)} results from {engine.value}")
        
        # Remove duplicates and sort by relevance
        unique_results = self._deduplicate_results(all_results)
        sorted_results = sorted(unique_results, key=lambda r: r.relevance_score, reverse=True)
        
        return sorted_results[:self.config.max_results]
    
    def _generate_search_queries(self, base_keyword: str) -> List[str]:
        """Generate search queries from templates"""
        queries = []
        
        for template in self.proxy_search_templates[:5]:  # Limit templates
            try:
                if '"{}"' in template:
                    query = template.format(base_keyword)
                else:
                    query = f"{template} {base_keyword}"
                queries.append(query)
            except:
                continue
        
        return queries
    
    async def _analyze_search_results(self, results: List[SearchResult]) -> List[SearchResult]:
        """Analyze search results for proxy relevance"""
        analyzed_results = []
        
        for result in results:
            # Apply basic filtering
            if not self._passes_basic_filters(result):
                continue
            
            # Calculate relevance score
            result.relevance_score = self._calculate_relevance_score(result)
            
            # Extract proxy indicators
            result.proxy_indicators = self._extract_proxy_indicators(result)
            
            # Classify content type
            result.content_type = self._classify_content_type(result)
            
            analyzed_results.append(result)
        
        return analyzed_results
    
    def _passes_basic_filters(self, result: SearchResult) -> bool:
        """Apply basic filtering to search results"""
        # Domain filtering
        if self.config.exclude_domains and result.domain in self.config.exclude_domains:
            return False
        
        if self.config.include_only_domains and result.domain not in self.config.include_only_domains:
            return False
        
        # Content length filtering
        if len(result.snippet) < self.config.min_content_length:
            return False
        
        # URL validation
        if not result.url or not result.url.startswith(('http://', 'https://')):
            return False
        
        return True
    
    def _calculate_relevance_score(self, result: SearchResult) -> float:
        """Calculate relevance score for search result"""
        score = 0.0
        
        # Title relevance
        title_keywords = ['proxy', 'list', 'free', 'working', 'anonymous', 'socks']
        title_lower = result.title.lower()
        title_matches = sum(1 for keyword in title_keywords if keyword in title_lower)
        score += title_matches * 0.2
        
        # Snippet relevance
        snippet_lower = result.snippet.lower()
        snippet_matches = sum(1 for keyword in title_keywords if keyword in snippet_lower)
        score += snippet_matches * 0.1
        
        # URL relevance
        url_keywords = ['proxy', 'list', 'free']
        url_lower = result.url.lower()
        url_matches = sum(1 for keyword in url_keywords if keyword in url_lower)
        score += url_matches * 0.15
        
        # Bonus for specific patterns
        if re.search(r'\b\d+\.\d+\.\d+\.\d+:\d+\b', result.snippet):
            score += 0.3  # Contains IP:port patterns
        
        if 'updated' in snippet_lower or 'fresh' in snippet_lower:
            score += 0.1  # Recently updated content
        
        # Domain reputation (simple heuristic)
        trusted_domains = ['github.com', 'pastebin.com', 'sourceforge.net']
        if result.domain in trusted_domains:
            score += 0.2
        
        return min(score, 1.0)  # Cap at 1.0
    
    def _extract_proxy_indicators(self, result: SearchResult) -> List[str]:
        """Extract proxy-related indicators from result"""
        indicators = []
        text = f"{result.title} {result.snippet}".lower()
        
        # Protocol indicators
        protocols = ['http', 'https', 'socks4', 'socks5']
        for protocol in protocols:
            if protocol in text:
                indicators.append(f"protocol_{protocol}")
        
        # Anonymity indicators
        anonymity_terms = ['anonymous', 'elite', 'transparent', 'high anonymity']
        for term in anonymity_terms:
            if term in text:
                indicators.append(f"anonymity_{term.replace(' ', '_')}")
        
        # Geographic indicators
        regions = ['usa', 'europe', 'asia', 'global', 'worldwide']
        for region in regions:
            if region in text:
                indicators.append(f"region_{region}")
        
        # Freshness indicators
        freshness_terms = ['updated', 'fresh', 'working', 'alive', 'tested']
        for term in freshness_terms:
            if term in text:
                indicators.append(f"freshness_{term}")
        
        return indicators
    
    def _classify_content_type(self, result: SearchResult) -> ContentType:
        """Classify the type of content"""
        text = f"{result.title} {result.snippet}".lower()
        url_lower = result.url.lower()
        
        # Check for different content types
        if 'list' in text and ('proxy' in text or 'proxies' in text):
            return ContentType.PROXY_LIST
        
        if any(word in text for word in ['announcement', 'release', 'new']):
            return ContentType.PROXY_ANNOUNCEMENT
        
        if any(word in text for word in ['research', 'analysis', 'study']):
            return ContentType.SECURITY_RESEARCH
        
        if any(word in url_lower for word in ['github', 'sourceforge', 'software']):
            return ContentType.PROXY_SOFTWARE
        
        if any(word in text for word in ['config', 'configuration', 'setup']):
            return ContentType.CONFIGURATION
        
        if any(word in url_lower for word in ['forum', 'reddit', 'discussion']):
            return ContentType.DISCUSSION
        
        return ContentType.PROXY_LIST  # Default fallback
    
    def _deduplicate_results(self, results: List[SearchResult]) -> List[SearchResult]:
        """Remove duplicate search results"""
        seen_urls = set()
        unique_results = []
        
        for result in results:
            if result.url not in seen_urls:
                seen_urls.add(result.url)
                unique_results.append(result)
        
        return unique_results
    
    async def monitor_search_terms(
        self,
        terms: List[str],
        interval_hours: int = 24
    ) -> Dict[str, List[SearchResult]]:
        """Monitor search terms for new proxy content"""
        monitoring_results = {}
        
        for term in terms:
            try:
                results = await self.search_for_proxies(
                    keywords=[term],
                    max_results_per_engine=20
                )
                monitoring_results[term] = results
                logger.info(f"Monitoring '{term}': found {len(results)} results")
            except Exception as e:
                logger.error(f"Monitoring failed for term '{term}': {e}")
                monitoring_results[term] = []
        
        return monitoring_results
    
    def get_search_summary(self) -> Dict[str, Any]:
        """Get summary of search capabilities and usage"""
        return {
            'available_providers': list(self.providers.keys()),
            'proxy_keywords': self.config.proxy_keywords,
            'search_templates': len(self.proxy_search_templates),
            'rate_limits': {
                'requests_per_minute': self.config.requests_per_minute,
                'delay_between_requests': self.config.delay_between_requests
            },
            'filtering': {
                'min_content_length': self.config.min_content_length,
                'max_content_age_days': self.config.max_content_age_days,
                'excluded_domains': list(self.config.exclude_domains)
            }
        }