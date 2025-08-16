"""
ProxC Intelligence System
===============================

Advanced OSINT (Open Source Intelligence) collection and search engine integration
for automated proxy discovery through various intelligence sources including:
- Search engine integration (Google, Bing, DuckDuckGo)
- Social media monitoring (Twitter, Reddit)
- Security blog and forum monitoring
- RSS feed analysis and content change detection
- Automated proxy-related content discovery

Features:
- Multi-source intelligence aggregation
- Content change detection and alerting
- Automated keyword monitoring
- Rate-limited API integration
- Ethical data collection practices

Author: Proxy Hunter Development Team
Version: 3.2.0-INTELLIGENCE
License: MIT
"""

import logging
from typing import Dict, List, Optional, Any
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

class IntelligenceSource(Enum):
    """Types of intelligence sources"""
    SEARCH_ENGINE = "search_engine"
    SOCIAL_MEDIA = "social_media"
    SECURITY_BLOG = "security_blog"
    RSS_FEED = "rss_feed"
    FORUM = "forum"
    CODE_REPOSITORY = "code_repository"
    NEWS_SITE = "news_site"
    PASTEBIN = "pastebin"

class SearchEngine(Enum):
    """Supported search engines"""
    GOOGLE = "google"
    BING = "bing"
    DUCKDUCKGO = "duckduckgo"
    YANDEX = "yandex"
    BAIDU = "baidu"

class ContentType(Enum):
    """Types of content for intelligence collection"""
    PROXY_LIST = "proxy_list"
    PROXY_ANNOUNCEMENT = "proxy_announcement"
    SECURITY_RESEARCH = "security_research"
    PROXY_SOFTWARE = "proxy_software"
    CONFIGURATION = "configuration"
    DISCUSSION = "discussion"

# Export main classes
from .search_engine import (
    SearchEngineIntegrator,
    SearchResult,
    SearchConfig,
    GoogleSearchProvider,
    BingSearchProvider,
    DuckDuckGoProvider
)

from .osint_collector import (
    OSINTCollector,
    OSINTSource,
    OSINTResult,
    ContentMonitor,
    ChangeDetector
)

from .social_monitor import (
    SocialMediaMonitor,
    TwitterMonitor,
    RedditMonitor,
    SocialPost,
    SocialConfig
)

from .content_analyzer import (
    ContentAnalyzer,
    ContentClassifier,
    ProxyContentExtractor,
    AnalysisResult
)

__all__ = [
    'IntelligenceSource',
    'SearchEngine',
    'ContentType',
    'SearchEngineIntegrator',
    'SearchResult',
    'SearchConfig',
    'GoogleSearchProvider',
    'BingSearchProvider',
    'DuckDuckGoProvider',
    'OSINTCollector',
    'OSINTSource',
    'OSINTResult',
    'ContentMonitor',
    'ChangeDetector',
    'SocialMediaMonitor',
    'TwitterMonitor',
    'RedditMonitor',
    'SocialPost',
    'SocialConfig',
    'ContentAnalyzer',
    'ContentClassifier',
    'ProxyContentExtractor',
    'AnalysisResult'
]

# Version info
__version__ = "3.2.0-INTELLIGENCE"
__author__ = "ProxC Development Team"
__license__ = "MIT"

logger.info("Intelligence system initialized successfully")