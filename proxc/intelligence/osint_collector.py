"""
OSINT (Open Source Intelligence) Collector
=========================================

Comprehensive OSINT collection framework for proxy discovery through
monitoring of security blogs, forums, RSS feeds, and content change detection.
"""

import asyncio
import hashlib
import json
import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Union, Any
from urllib.parse import urljoin, urlparse

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

try:
    import feedparser
    HAS_FEEDPARSER = True
except ImportError:
    HAS_FEEDPARSER = False

# Import our core types
from . import IntelligenceSource, ContentType

logger = logging.getLogger(__name__)


class OSINTSourceType(Enum):
    """Types of OSINT sources"""
    RSS_FEED = "rss_feed"
    BLOG = "blog"
    FORUM = "forum"
    NEWS_SITE = "news_site"
    SECURITY_SITE = "security_site"
    PASTEBIN = "pastebin"
    CODE_REPOSITORY = "code_repository"


class ContentChangeType(Enum):
    """Types of content changes"""
    NEW_CONTENT = "new_content"
    UPDATED_CONTENT = "updated_content"
    DELETED_CONTENT = "deleted_content"
    STRUCTURE_CHANGE = "structure_change"


@dataclass
class OSINTSource:
    """Configuration for an OSINT source"""
    name: str
    url: str
    source_type: OSINTSourceType
    
    # Monitoring configuration
    check_interval_hours: int = 24
    content_selectors: List[str] = field(default_factory=list)  # CSS selectors for content
    proxy_keywords: List[str] = field(default_factory=list)
    
    # Authentication (if needed)
    auth_headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    
    # Rate limiting
    rate_limit_delay: float = 2.0
    max_retries: int = 3
    
    # Content filtering
    min_content_length: int = 50
    max_content_age_days: int = 7
    language_filter: Optional[str] = None
    
    # Metadata
    last_checked: Optional[datetime] = None
    last_content_hash: Optional[str] = None
    success_count: int = 0
    failure_count: int = 0
    enabled: bool = True


@dataclass
class OSINTResult:
    """Result from OSINT collection"""
    source: OSINTSource
    content: str
    title: Optional[str] = None
    url: Optional[str] = None
    
    # Analysis results
    proxy_indicators: List[str] = field(default_factory=list)
    potential_proxies: List[str] = field(default_factory=list)
    content_type: Optional[ContentType] = None
    relevance_score: float = 0.0
    
    # Change detection
    is_new_content: bool = False
    change_type: Optional[ContentChangeType] = None
    content_hash: Optional[str] = None
    
    # Metadata
    collection_timestamp: datetime = field(default_factory=datetime.utcnow)
    source_timestamp: Optional[datetime] = None
    language: Optional[str] = None
    content_length: int = 0


class ContentMonitor:
    """Monitors content changes on web sources"""
    
    def __init__(self):
        self.content_hashes: Dict[str, str] = {}  # url -> content_hash
        self.content_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    
    def calculate_content_hash(self, content: str) -> str:
        """Calculate hash of content for change detection"""
        # Normalize content for consistent hashing
        normalized = re.sub(r'\s+', ' ', content.strip().lower())
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def detect_changes(self, url: str, content: str) -> Tuple[bool, ContentChangeType]:
        """Detect changes in content"""
        content_hash = self.calculate_content_hash(content)
        
        if url not in self.content_hashes:
            # New content
            self.content_hashes[url] = content_hash
            return True, ContentChangeType.NEW_CONTENT
        
        previous_hash = self.content_hashes[url]
        
        if content_hash != previous_hash:
            # Content changed
            self.content_hashes[url] = content_hash
            
            # Store change in history
            self.content_history[url].append({
                'timestamp': datetime.utcnow().isoformat(),
                'old_hash': previous_hash,
                'new_hash': content_hash,
                'change_type': ContentChangeType.UPDATED_CONTENT.value
            })
            
            # Keep only recent history (last 100 changes)
            if len(self.content_history[url]) > 100:
                self.content_history[url] = self.content_history[url][-100:]
            
            return True, ContentChangeType.UPDATED_CONTENT
        
        return False, None
    
    def get_change_history(self, url: str) -> List[Dict[str, Any]]:
        """Get change history for a URL"""
        return self.content_history.get(url, [])


class ChangeDetector:
    """Advanced change detection with content analysis"""
    
    def __init__(self):
        self.content_monitor = ContentMonitor()
        
        # Proxy-related patterns for detection
        self.proxy_patterns = [
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\b',  # IP:port
            r'\bproxy\s+list\b',
            r'\bfree\s+prox(?:y|ies)\b',
            r'\bworking\s+prox(?:y|ies)\b',
            r'\banonymous\s+prox(?:y|ies)\b',
            r'\bsocks[45]?\s+prox(?:y|ies)\b',
            r'\bhttp\s+prox(?:y|ies)\b'
        ]
    
    def analyze_content_for_proxies(self, content: str) -> Tuple[List[str], List[str]]:
        """Analyze content for proxy indicators and potential proxies"""
        indicators = []
        potential_proxies = []
        
        content_lower = content.lower()
        
        # Check for proxy indicators
        for pattern in self.proxy_patterns:
            matches = re.finditer(pattern, content_lower, re.IGNORECASE)
            for match in matches:
                if pattern.startswith(r'\b\d'):  # IP:port pattern
                    potential_proxies.append(match.group())
                else:
                    indicators.append(match.group())
        
        # Additional proxy extraction
        ip_port_matches = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)\b', content)
        for ip, port in ip_port_matches:
            # Basic validation
            ip_parts = [int(p) for p in ip.split('.')]
            if all(0 <= part <= 255 for part in ip_parts) and 1 <= int(port) <= 65535:
                potential_proxies.append(f"{ip}:{port}")
        
        return list(set(indicators)), list(set(potential_proxies))
    
    def classify_content_type(self, title: str, content: str, url: str) -> ContentType:
        """Classify the type of content found"""
        combined_text = f"{title} {content}".lower()
        url_lower = url.lower()
        
        # Classification patterns
        if 'list' in combined_text and any(word in combined_text for word in ['proxy', 'proxies']):
            return ContentType.PROXY_LIST
        
        if any(word in combined_text for word in ['announcement', 'release', 'new', 'updated']):
            return ContentType.PROXY_ANNOUNCEMENT
        
        if any(word in combined_text for word in ['research', 'analysis', 'study', 'security']):
            return ContentType.SECURITY_RESEARCH
        
        if any(word in url_lower for word in ['github', 'gitlab', 'sourceforge']):
            return ContentType.PROXY_SOFTWARE
        
        if any(word in combined_text for word in ['config', 'configuration', 'setup', 'tutorial']):
            return ContentType.CONFIGURATION
        
        if any(word in url_lower for word in ['forum', 'discussion', 'reddit', 'stackoverflow']):
            return ContentType.DISCUSSION
        
        return ContentType.PROXY_LIST  # Default
    
    def calculate_relevance_score(self, indicators: List[str], proxies: List[str], content: str) -> float:
        """Calculate relevance score for content"""
        score = 0.0
        
        # Score based on proxy indicators
        score += len(indicators) * 0.1
        
        # Score based on potential proxies found
        score += len(proxies) * 0.3
        
        # Score based on content quality indicators
        content_lower = content.lower()
        
        quality_indicators = [
            ('updated', 0.2),
            ('working', 0.2),
            ('tested', 0.15),
            ('alive', 0.15),
            ('fresh', 0.1),
            ('verified', 0.1),
            ('anonymous', 0.1)
        ]
        
        for indicator, weight in quality_indicators:
            if indicator in content_lower:
                score += weight
        
        # Bonus for multiple proxy types mentioned
        proxy_types = ['http', 'https', 'socks4', 'socks5']
        types_mentioned = sum(1 for ptype in proxy_types if ptype in content_lower)
        score += types_mentioned * 0.05
        
        return min(score, 1.0)  # Cap at 1.0


class OSINTCollector:
    """Main OSINT collection engine"""
    
    def __init__(self):
        self.sources: List[OSINTSource] = []
        self.change_detector = ChangeDetector()
        self.collection_history: Dict[str, List[OSINTResult]] = defaultdict(list)
        self._initialize_default_sources()
    
    def _initialize_default_sources(self):
        """Initialize default OSINT sources"""
        
        # Security blogs and news sites
        security_sources = [
            OSINTSource(
                name="KrebsOnSecurity RSS",
                url="https://krebsonsecurity.com/feed/",
                source_type=OSINTSourceType.RSS_FEED,
                check_interval_hours=12,
                proxy_keywords=["proxy", "botnet", "malware", "c2"]
            ),
            OSINTSource(
                name="Bleeping Computer Security RSS",
                url="https://www.bleepingcomputer.com/feed/",
                source_type=OSINTSourceType.RSS_FEED,
                check_interval_hours=6,
                proxy_keywords=["proxy", "malware", "tor", "anonymity"]
            ),
            OSINTSource(
                name="The Hacker News RSS",
                url="https://feeds.feedburner.com/TheHackersNews",
                source_type=OSINTSourceType.RSS_FEED,
                check_interval_hours=8,
                proxy_keywords=["proxy", "vpn", "anonymity", "privacy"]
            )
        ]
        
        # Pastebin-like sources
        pastebin_sources = [
            OSINTSource(
                name="Pastebin Proxy Search",
                url="https://pastebin.com/search?q=proxy+list",
                source_type=OSINTSourceType.PASTEBIN,
                check_interval_hours=2,
                content_selectors=[".paste_box_line1", ".paste_box_line2"],
                proxy_keywords=["proxy", "list", "working"]
            )
        ]
        
        # Code repositories (search APIs)
        repository_sources = [
            OSINTSource(
                name="GitHub Proxy Lists",
                url="https://api.github.com/search/repositories?q=proxy+list&sort=updated",
                source_type=OSINTSourceType.CODE_REPOSITORY,
                check_interval_hours=24,
                proxy_keywords=["proxy", "list", "free"]
            )
        ]
        
        # Add all default sources
        self.sources.extend(security_sources)
        self.sources.extend(pastebin_sources)
        self.sources.extend(repository_sources)
        
        logger.info(f"Initialized {len(self.sources)} default OSINT sources")
    
    def add_source(self, source: OSINTSource):
        """Add custom OSINT source"""
        self.sources.append(source)
        logger.info(f"Added OSINT source: {source.name}")
    
    def remove_source(self, name: str):
        """Remove OSINT source by name"""
        self.sources = [s for s in self.sources if s.name != name]
        logger.info(f"Removed OSINT source: {name}")
    
    async def collect_from_source(self, source: OSINTSource) -> List[OSINTResult]:
        """Collect data from a single OSINT source"""
        if not source.enabled:
            return []
        
        logger.info(f"Collecting from OSINT source: {source.name}")
        
        try:
            # Rate limiting
            time.sleep(source.rate_limit_delay)
            
            # Fetch content based on source type
            if source.source_type == OSINTSourceType.RSS_FEED:
                return await self._collect_from_rss(source)
            elif source.source_type == OSINTSourceType.PASTEBIN:
                return await self._collect_from_web(source)
            elif source.source_type == OSINTSourceType.CODE_REPOSITORY:
                return await self._collect_from_api(source)
            else:
                return await self._collect_from_web(source)
                
        except Exception as e:
            logger.error(f"Collection failed from {source.name}: {e}")
            source.failure_count += 1
            return []
    
    async def _collect_from_rss(self, source: OSINTSource) -> List[OSINTResult]:
        """Collect from RSS feed"""
        if not HAS_FEEDPARSER:
            logger.warning("feedparser not available for RSS collection")
            return []
        
        results = []
        
        try:
            # Parse RSS feed
            feed = feedparser.parse(source.url)
            
            for entry in feed.entries[:20]:  # Limit to recent entries
                # Check content age
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    entry_date = datetime(*entry.published_parsed[:6])
                    age_days = (datetime.utcnow() - entry_date).days
                    if age_days > source.max_content_age_days:
                        continue
                
                # Extract content
                content = ""
                if hasattr(entry, 'summary'):
                    content = entry.summary
                elif hasattr(entry, 'description'):
                    content = entry.description
                
                if len(content) < source.min_content_length:
                    continue
                
                # Check for proxy-related keywords
                content_lower = content.lower()
                keyword_matches = [kw for kw in source.proxy_keywords if kw in content_lower]
                
                if not keyword_matches:
                    continue
                
                # Analyze content
                indicators, proxies = self.change_detector.analyze_content_for_proxies(content)
                
                if not indicators and not proxies:
                    continue
                
                # Create result
                result = OSINTResult(
                    source=source,
                    content=content,
                    title=getattr(entry, 'title', ''),
                    url=getattr(entry, 'link', ''),
                    proxy_indicators=indicators,
                    potential_proxies=proxies,
                    content_length=len(content)
                )
                
                # Set source timestamp
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    result.source_timestamp = datetime(*entry.published_parsed[:6])
                
                # Classify content and calculate score
                result.content_type = self.change_detector.classify_content_type(
                    result.title or '', content, result.url or ''
                )
                result.relevance_score = self.change_detector.calculate_relevance_score(
                    indicators, proxies, content
                )
                
                # Check for content changes
                if result.url:
                    changed, change_type = self.change_detector.content_monitor.detect_changes(
                        result.url, content
                    )
                    result.is_new_content = changed
                    result.change_type = change_type
                
                results.append(result)
            
            source.success_count += 1
            
        except Exception as e:
            logger.error(f"RSS collection error for {source.name}: {e}")
            source.failure_count += 1
        
        source.last_checked = datetime.utcnow()
        return results
    
    async def _collect_from_web(self, source: OSINTSource) -> List[OSINTResult]:
        """Collect from web page"""
        if not HAS_BEAUTIFULSOUP or not HAS_REQUESTS:
            logger.warning("Required libraries not available for web collection")
            return []
        
        results = []
        
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            headers.update(source.auth_headers)
            
            response = requests.get(
                source.url,
                headers=headers,
                cookies=source.cookies,
                timeout=30
            )
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}")
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract content using selectors or full text
            content_elements = []
            
            if source.content_selectors:
                for selector in source.content_selectors:
                    elements = soup.select(selector)
                    content_elements.extend(elements)
            else:
                # Use all text content
                content_elements = [soup]
            
            for element in content_elements:
                content = element.get_text(strip=True)
                
                if len(content) < source.min_content_length:
                    continue
                
                # Check for proxy keywords
                content_lower = content.lower()
                keyword_matches = [kw for kw in source.proxy_keywords if kw in content_lower]
                
                if not keyword_matches and source.proxy_keywords:
                    continue
                
                # Analyze content
                indicators, proxies = self.change_detector.analyze_content_for_proxies(content)
                
                if not indicators and not proxies:
                    continue
                
                # Create result
                result = OSINTResult(
                    source=source,
                    content=content,
                    url=source.url,
                    proxy_indicators=indicators,
                    potential_proxies=proxies,
                    content_length=len(content)
                )
                
                # Classify and score
                result.content_type = self.change_detector.classify_content_type(
                    '', content, source.url
                )
                result.relevance_score = self.change_detector.calculate_relevance_score(
                    indicators, proxies, content
                )
                
                # Check for changes
                changed, change_type = self.change_detector.content_monitor.detect_changes(
                    source.url, content
                )
                result.is_new_content = changed
                result.change_type = change_type
                
                results.append(result)
                break  # Only take first meaningful content block
            
            source.success_count += 1
            
        except Exception as e:
            logger.error(f"Web collection error for {source.name}: {e}")
            source.failure_count += 1
        
        source.last_checked = datetime.utcnow()
        return results
    
    async def _collect_from_api(self, source: OSINTSource) -> List[OSINTResult]:
        """Collect from API endpoint"""
        if not HAS_REQUESTS:
            return []
        
        results = []
        
        try:
            headers = {'User-Agent': 'ProxyHunter/3.0'}
            headers.update(source.auth_headers)
            
            response = requests.get(source.url, headers=headers, timeout=30)
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}")
            
            data = response.json()
            
            # Handle GitHub API response
            if 'github.com' in source.url and 'items' in data:
                for item in data['items'][:10]:  # Limit to recent items
                    content = f"{item.get('name', '')} {item.get('description', '')}"
                    
                    # Analyze content
                    indicators, proxies = self.change_detector.analyze_content_for_proxies(content)
                    
                    if not indicators and not proxies:
                        continue
                    
                    result = OSINTResult(
                        source=source,
                        content=content,
                        title=item.get('name', ''),
                        url=item.get('html_url', ''),
                        proxy_indicators=indicators,
                        potential_proxies=proxies,
                        content_length=len(content)
                    )
                    
                    # Set timestamps
                    if 'updated_at' in item:
                        try:
                            result.source_timestamp = datetime.fromisoformat(
                                item['updated_at'].replace('Z', '+00:00')
                            )
                        except:
                            pass
                    
                    result.content_type = ContentType.PROXY_SOFTWARE
                    result.relevance_score = self.change_detector.calculate_relevance_score(
                        indicators, proxies, content
                    )
                    
                    results.append(result)
            
            source.success_count += 1
            
        except Exception as e:
            logger.error(f"API collection error for {source.name}: {e}")
            source.failure_count += 1
        
        source.last_checked = datetime.utcnow()
        return results
    
    async def collect_all(self, max_concurrent: int = 5) -> List[OSINTResult]:
        """Collect from all enabled sources"""
        
        # Filter sources that need checking
        sources_to_check = []
        current_time = datetime.utcnow()
        
        for source in self.sources:
            if not source.enabled:
                continue
            
            if source.last_checked is None:
                sources_to_check.append(source)
            else:
                time_since_check = current_time - source.last_checked
                if time_since_check >= timedelta(hours=source.check_interval_hours):
                    sources_to_check.append(source)
        
        if not sources_to_check:
            logger.info("No OSINT sources need checking")
            return []
        
        logger.info(f"Checking {len(sources_to_check)} OSINT sources")
        
        # Collect from sources (sequential to respect rate limits)
        all_results = []
        for source in sources_to_check[:max_concurrent]:
            try:
                results = await self.collect_from_source(source)
                all_results.extend(results)
                
                # Store results in history
                if results:
                    self.collection_history[source.name].extend(results)
                    # Keep only recent history
                    if len(self.collection_history[source.name]) > 1000:
                        self.collection_history[source.name] = self.collection_history[source.name][-1000:]
                
            except Exception as e:
                logger.error(f"Error collecting from {source.name}: {e}")
        
        # Sort by relevance score
        all_results.sort(key=lambda r: r.relevance_score, reverse=True)
        
        logger.info(f"Collected {len(all_results)} OSINT results")
        return all_results
    
    def get_collection_summary(self) -> Dict[str, Any]:
        """Get summary of OSINT collection"""
        summary = {
            'total_sources': len(self.sources),
            'enabled_sources': sum(1 for s in self.sources if s.enabled),
            'source_types': {},
            'collection_stats': {},
            'recent_results': 0
        }
        
        # Count by source type
        for source in self.sources:
            source_type = source.source_type.value
            summary['source_types'][source_type] = summary['source_types'].get(source_type, 0) + 1
        
        # Collection statistics
        for source in self.sources:
            if source.last_checked:
                success_rate = source.success_count / (source.success_count + source.failure_count)
                summary['collection_stats'][source.name] = {
                    'last_checked': source.last_checked.isoformat(),
                    'success_count': source.success_count,
                    'failure_count': source.failure_count,
                    'success_rate': success_rate
                }
        
        # Count recent results (last 24 hours)
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        recent_count = 0
        for results in self.collection_history.values():
            recent_count += sum(1 for r in results if r.collection_timestamp > cutoff_time)
        
        summary['recent_results'] = recent_count
        
        return summary
    
    def export_sources_config(self, file_path: str):
        """Export sources configuration to JSON file"""
        sources_data = []
        for source in self.sources:
            source_dict = {
                'name': source.name,
                'url': source.url,
                'source_type': source.source_type.value,
                'check_interval_hours': source.check_interval_hours,
                'proxy_keywords': source.proxy_keywords,
                'enabled': source.enabled
            }
            sources_data.append(source_dict)
        
        with open(file_path, 'w') as f:
            json.dump({'sources': sources_data}, f, indent=2)
        
        logger.info(f"Exported {len(sources_data)} sources to {file_path}")
    
    def import_sources_config(self, file_path: str):
        """Import sources configuration from JSON file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            imported_count = 0
            for source_data in data.get('sources', []):
                source = OSINTSource(
                    name=source_data['name'],
                    url=source_data['url'],
                    source_type=OSINTSourceType(source_data['source_type']),
                    check_interval_hours=source_data.get('check_interval_hours', 24),
                    proxy_keywords=source_data.get('proxy_keywords', []),
                    enabled=source_data.get('enabled', True)
                )
                self.add_source(source)
                imported_count += 1
            
            logger.info(f"Imported {imported_count} sources from {file_path}")
            
        except Exception as e:
            logger.error(f"Failed to import sources: {e}")