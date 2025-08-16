"""
Advanced Web Scraping Engine
===========================

Multi-engine web scraping system supporting both traditional HTTP scraping
and JavaScript-heavy sites using Playwright for comprehensive proxy discovery.
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
from urllib.parse import urljoin, urlparse, quote

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
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

try:
    import scrapy
    HAS_SCRAPY = True
except ImportError:
    HAS_SCRAPY = False

# Import our core types
from . import ScrapingEngine, ContentFormat
from ..proxy_core.models import ProxyInfo

logger = logging.getLogger(__name__)


@dataclass
class ScrapingConfig:
    """Configuration for web scraping operations"""
    # Target configuration
    target_urls: List[str] = field(default_factory=list)
    scraping_engine: ScrapingEngine = ScrapingEngine.REQUESTS
    
    # Request parameters
    max_retries: int = 3
    retry_delay: float = 2.0
    timeout: int = 30
    concurrent_requests: int = 5
    
    # Browser simulation
    user_agents: List[str] = field(default_factory=lambda: [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    ])
    
    # Content extraction
    content_selectors: Dict[str, List[str]] = field(default_factory=dict)
    proxy_patterns: List[str] = field(default_factory=lambda: [
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\b',
        r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+',
        r'socks[45]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+'
    ])
    
    # Rate limiting
    rate_limit_delay: float = 1.0
    respect_robots_txt: bool = True
    
    # Proxy rotation for scraping
    scraping_proxies: List[ProxyInfo] = field(default_factory=list)
    rotate_proxies: bool = False
    
    # JavaScript handling
    javascript_enabled: bool = False
    wait_for_selector: Optional[str] = None
    page_load_timeout: int = 30
    
    # Filtering
    min_content_length: int = 100
    max_content_length: int = 1024 * 1024  # 1MB
    allowed_content_types: Set[str] = field(default_factory=lambda: {
        'text/html', 'text/plain', 'application/json', 'application/xml'
    })


@dataclass
class ScrapingResult:
    """Result from web scraping operation"""
    url: str
    success: bool
    content: str = ""
    
    # Extraction results
    extracted_proxies: List[str] = field(default_factory=list)
    proxy_indicators: List[str] = field(default_factory=list)
    structured_data: Dict[str, Any] = field(default_factory=dict)
    
    # Response metadata
    status_code: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    content_type: Optional[str] = None
    content_length: int = 0
    
    # Performance metrics
    response_time: float = 0.0
    download_time: float = 0.0
    
    # Error information
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    
    # Metadata
    scraping_timestamp: datetime = field(default_factory=datetime.utcnow)
    engine_used: Optional[ScrapingEngine] = None
    proxy_used: Optional[str] = None


class ContentExtractor:
    """Extract proxy-related content from scraped data"""
    
    def __init__(self):
        # Enhanced proxy patterns
        self.proxy_patterns = [
            # IP:Port patterns
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)\b',
            
            # Protocol-specific patterns
            r'(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)',
            r'(socks[45]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)',
            
            # Formatted lists
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:|,]\s*(\d+)',
            
            # Common separators
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[|]\s*(\d+)',
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d+)'
        ]
        
        # Proxy quality indicators
        self.quality_indicators = [
            'working', 'tested', 'alive', 'fresh', 'updated',
            'verified', 'active', 'online', 'valid'
        ]
        
        # Anonymity indicators
        self.anonymity_indicators = [
            'anonymous', 'elite', 'high anonymity', 'transparent'
        ]
    
    def extract_proxies(self, content: str, url: str = "") -> Tuple[List[str], List[str]]:
        """Extract proxy addresses and indicators from content"""
        proxies = []
        indicators = []
        
        # Extract proxy addresses
        for pattern in self.proxy_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                if len(match.groups()) == 2:
                    ip, port = match.groups()
                    proxy = f"{ip}:{port}"
                elif len(match.groups()) == 1:
                    proxy = match.group(1)
                else:
                    proxy = match.group(0)
                
                if self._validate_proxy_format(proxy):
                    proxies.append(proxy)
        
        # Extract quality indicators
        content_lower = content.lower()
        for indicator in self.quality_indicators:
            if indicator in content_lower:
                indicators.append(f"quality_{indicator}")
        
        for indicator in self.anonymity_indicators:
            if indicator in content_lower:
                indicators.append(f"anonymity_{indicator.replace(' ', '_')}")
        
        # Protocol indicators
        protocols = ['http', 'https', 'socks4', 'socks5']
        for protocol in protocols:
            if f"{protocol}://" in content_lower or f"{protocol} proxy" in content_lower:
                indicators.append(f"protocol_{protocol}")
        
        return list(set(proxies)), indicators
    
    def _validate_proxy_format(self, proxy: str) -> bool:
        """Basic validation of proxy format"""
        try:
            # Remove protocol prefix if present
            if '://' in proxy:
                proxy = proxy.split('://', 1)[1]
            
            if ':' not in proxy:
                return False
            
            ip, port = proxy.rsplit(':', 1)
            
            # Validate IP address
            ip_parts = ip.split('.')
            if len(ip_parts) != 4:
                return False
            
            for part in ip_parts:
                if not part.isdigit() or not 0 <= int(part) <= 255:
                    return False
            
            # Validate port
            if not port.isdigit() or not 1 <= int(port) <= 65535:
                return False
            
            return True
            
        except:
            return False
    
    def extract_structured_data(self, content: str, selectors: Dict[str, List[str]]) -> Dict[str, Any]:
        """Extract structured data using CSS selectors"""
        if not HAS_BEAUTIFULSOUP:
            return {}
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            extracted_data = {}
            
            for data_type, selector_list in selectors.items():
                extracted_data[data_type] = []
                
                for selector in selector_list:
                    elements = soup.select(selector)
                    for element in elements:
                        text = element.get_text(strip=True)
                        if text and len(text) > 5:
                            extracted_data[data_type].append(text)
            
            return extracted_data
            
        except Exception as e:
            logger.error(f"Error extracting structured data: {e}")
            return {}


class BaseScraper(ABC):
    """Abstract base class for scrapers"""
    
    def __init__(self, config: ScrapingConfig):
        self.config = config
        self.content_extractor = ContentExtractor()
        self.current_proxy_index = 0
        
        # Request statistics
        self.stats = {
            'requests_made': 0,
            'requests_successful': 0,
            'requests_failed': 0,
            'total_content_size': 0,
            'average_response_time': 0.0
        }
    
    @abstractmethod
    async def scrape_url(self, url: str) -> ScrapingResult:
        """Scrape a single URL"""
        pass
    
    def get_next_proxy(self) -> Optional[ProxyInfo]:
        """Get next proxy for rotation"""
        if not self.config.scraping_proxies or not self.config.rotate_proxies:
            return None
        
        proxy = self.config.scraping_proxies[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.config.scraping_proxies)
        return proxy
    
    def get_random_user_agent(self) -> str:
        """Get random user agent"""
        return random.choice(self.config.user_agents)
    
    def update_stats(self, result: ScrapingResult):
        """Update scraping statistics"""
        self.stats['requests_made'] += 1
        if result.success:
            self.stats['requests_successful'] += 1
            self.stats['total_content_size'] += result.content_length
        else:
            self.stats['requests_failed'] += 1
        
        # Update average response time
        total_time = self.stats['average_response_time'] * (self.stats['requests_made'] - 1)
        self.stats['average_response_time'] = (total_time + result.response_time) / self.stats['requests_made']


class RequestsScraper(BaseScraper):
    """HTTP scraper using requests library"""
    
    def __init__(self, config: ScrapingConfig):
        super().__init__(config)
        self.session = None
        if HAS_REQUESTS:
            self._setup_session()
    
    def _setup_session(self):
        """Setup requests session with retry strategy"""
        self.session = requests.Session()
        
        # Setup retry strategy
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    async def scrape_url(self, url: str) -> ScrapingResult:
        """Scrape URL using requests"""
        if not HAS_REQUESTS:
            return ScrapingResult(
                url=url,
                success=False,
                error_message="requests library not available"
            )
        
        result = ScrapingResult(url=url, engine_used=ScrapingEngine.REQUESTS)
        start_time = time.time()
        
        try:
            # Apply rate limiting
            time.sleep(self.config.rate_limit_delay)
            
            # Setup request parameters
            headers = {'User-Agent': self.get_random_user_agent()}
            
            proxies = {}
            proxy_info = self.get_next_proxy()
            if proxy_info:
                proxy_url = f"http://{proxy_info.ip}:{proxy_info.port}"
                proxies = {'http': proxy_url, 'https': proxy_url}
                result.proxy_used = proxy_url
            
            # Make request
            response = self.session.get(
                url,
                headers=headers,
                proxies=proxies,
                timeout=self.config.timeout,
                verify=False
            )
            
            result.response_time = (time.time() - start_time) * 1000
            result.status_code = response.status_code
            result.response_headers = dict(response.headers)
            result.content_type = response.headers.get('content-type', '')
            result.content_length = len(response.content)
            
            if response.status_code == 200:
                result.content = response.text
                result.success = True
                
                # Extract proxy data
                proxies, indicators = self.content_extractor.extract_proxies(
                    result.content, url
                )
                result.extracted_proxies = proxies
                result.proxy_indicators = indicators
                
                # Extract structured data
                if self.config.content_selectors:
                    result.structured_data = self.content_extractor.extract_structured_data(
                        result.content, self.config.content_selectors
                    )
            else:
                result.success = False
                result.error_message = f"HTTP {response.status_code}"
                result.error_type = "http_error"
                
        except requests.exceptions.ProxyError as e:
            result.success = False
            result.error_message = f"Proxy error: {str(e)}"
            result.error_type = "proxy_error"
        except requests.exceptions.Timeout as e:
            result.success = False
            result.error_message = f"Timeout: {str(e)}"
            result.error_type = "timeout"
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            result.error_type = "general_error"
        
        self.update_stats(result)
        return result


class PlaywrightScraper(BaseScraper):
    """JavaScript-capable scraper using Playwright"""
    
    def __init__(self, config: ScrapingConfig):
        super().__init__(config)
        self.playwright = None
        self.browser = None
        self.context = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        if HAS_PLAYWRIGHT:
            await self._setup_playwright()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self._cleanup_playwright()
    
    async def _setup_playwright(self):
        """Setup Playwright browser"""
        try:
            self.playwright = await async_playwright().start()
            
            # Launch browser with proxy if configured
            launch_options = {
                'headless': True,
                'timeout': self.config.page_load_timeout * 1000
            }
            
            proxy_info = self.get_next_proxy()
            if proxy_info:
                launch_options['proxy'] = {
                    'server': f"http://{proxy_info.ip}:{proxy_info.port}"
                }
            
            self.browser = await self.playwright.chromium.launch(**launch_options)
            
            # Create context with random user agent
            self.context = await self.browser.new_context(
                user_agent=self.get_random_user_agent()
            )
            
        except Exception as e:
            logger.error(f"Failed to setup Playwright: {e}")
    
    async def _cleanup_playwright(self):
        """Cleanup Playwright resources"""
        try:
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
        except Exception as e:
            logger.error(f"Error cleaning up Playwright: {e}")
    
    async def scrape_url(self, url: str) -> ScrapingResult:
        """Scrape URL using Playwright"""
        if not HAS_PLAYWRIGHT or not self.context:
            return ScrapingResult(
                url=url,
                success=False,
                error_message="Playwright not available or not initialized"
            )
        
        result = ScrapingResult(url=url, engine_used=ScrapingEngine.PLAYWRIGHT)
        start_time = time.time()
        
        try:
            # Apply rate limiting
            await asyncio.sleep(self.config.rate_limit_delay)
            
            # Create new page
            page = await self.context.new_page()
            
            # Navigate to URL
            response = await page.goto(
                url,
                timeout=self.config.page_load_timeout * 1000,
                wait_until='domcontentloaded'
            )
            
            result.response_time = (time.time() - start_time) * 1000
            
            if response:
                result.status_code = response.status
                result.response_headers = dict(response.headers)
            
            # Wait for specific selector if configured
            if self.config.wait_for_selector:
                try:
                    await page.wait_for_selector(
                        self.config.wait_for_selector,
                        timeout=5000
                    )
                except:
                    pass  # Continue even if selector not found
            
            # Get page content
            result.content = await page.content()
            result.content_length = len(result.content)
            result.success = True
            
            # Extract proxy data
            proxies, indicators = self.content_extractor.extract_proxies(
                result.content, url
            )
            result.extracted_proxies = proxies
            result.proxy_indicators = indicators
            
            # Extract structured data
            if self.config.content_selectors:
                result.structured_data = self.content_extractor.extract_structured_data(
                    result.content, self.config.content_selectors
                )
            
            await page.close()
            
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            result.error_type = "playwright_error"
        
        self.update_stats(result)
        return result


class WebScrapingEngine:
    """Main web scraping engine coordinating different scrapers"""
    
    def __init__(self, config: ScrapingConfig):
        self.config = config
        self.scrapers: Dict[ScrapingEngine, BaseScraper] = {}
        self._initialize_scrapers()
    
    def _initialize_scrapers(self):
        """Initialize available scrapers"""
        # Always available if requests is present
        if HAS_REQUESTS and self.config.scraping_engine in [ScrapingEngine.REQUESTS, ScrapingEngine.SCRAPY]:
            self.scrapers[ScrapingEngine.REQUESTS] = RequestsScraper(self.config)
        
        # Note: Playwright scraper is initialized in async context
        logger.info(f"Initialized scrapers: {list(self.scrapers.keys())}")
    
    async def scrape_all(self) -> List[ScrapingResult]:
        """Scrape all configured URLs"""
        results = []
        
        # Determine which scraper to use
        if self.config.javascript_enabled and HAS_PLAYWRIGHT:
            async with PlaywrightScraper(self.config) as scraper:
                for url in self.config.target_urls:
                    try:
                        result = await scraper.scrape_url(url)
                        results.append(result)
                    except Exception as e:
                        logger.error(f"Scraping failed for {url}: {e}")
                        error_result = ScrapingResult(
                            url=url,
                            success=False,
                            error_message=str(e),
                            engine_used=ScrapingEngine.PLAYWRIGHT
                        )
                        results.append(error_result)
        else:
            # Use requests-based scraper
            scraper = self.scrapers.get(ScrapingEngine.REQUESTS)
            if scraper:
                # Process URLs with concurrency control
                semaphore = asyncio.Semaphore(self.config.concurrent_requests)
                
                async def scrape_with_semaphore(url):
                    async with semaphore:
                        return await scraper.scrape_url(url)
                
                tasks = [scrape_with_semaphore(url) for url in self.config.target_urls]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Handle exceptions
                final_results = []
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        error_result = ScrapingResult(
                            url=self.config.target_urls[i],
                            success=False,
                            error_message=str(result),
                            engine_used=ScrapingEngine.REQUESTS
                        )
                        final_results.append(error_result)
                    else:
                        final_results.append(result)
                
                results = final_results
        
        logger.info(f"Scraping completed: {len(results)} URLs processed")
        return results
    
    def get_successful_proxies(self, results: List[ScrapingResult]) -> List[str]:
        """Extract all successfully found proxies from results"""
        all_proxies = []
        
        for result in results:
            if result.success and result.extracted_proxies:
                all_proxies.extend(result.extracted_proxies)
        
        return list(set(all_proxies))  # Remove duplicates
    
    def get_scraping_summary(self, results: List[ScrapingResult]) -> Dict[str, Any]:
        """Get summary of scraping operation"""
        successful_results = [r for r in results if r.success]
        failed_results = [r for r in results if not r.success]
        
        total_proxies = sum(len(r.extracted_proxies) for r in successful_results)
        unique_proxies = len(set().union(*[r.extracted_proxies for r in successful_results]))
        
        # Calculate average response time
        response_times = [r.response_time for r in successful_results if r.response_time > 0]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Error analysis
        error_types = {}
        for result in failed_results:
            error_type = result.error_type or 'unknown'
            error_types[error_type] = error_types.get(error_type, 0) + 1
        
        return {
            'total_urls': len(results),
            'successful_requests': len(successful_results),
            'failed_requests': len(failed_results),
            'success_rate': len(successful_results) / len(results) if results else 0,
            'total_proxies_found': total_proxies,
            'unique_proxies_found': unique_proxies,
            'average_response_time': avg_response_time,
            'error_types': error_types,
            'total_content_size': sum(r.content_length for r in successful_results)
        }