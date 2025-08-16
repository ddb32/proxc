"""
ProxC Advanced Collection System
======================================

Advanced web scraping and data mining capabilities for automated proxy
discovery from diverse sources including:
- JavaScript-heavy websites with Playwright
- Code repositories (GitHub, GitLab, Bitbucket)  
- Pastebin and similar paste services
- Network intelligence platforms (Shodan, Censys)
- Rotating proxy support for scraping operations

Features:
- Multi-engine scraping (Scrapy + Playwright)
- Content change detection and alerting
- Rate limiting and ethical scraping practices
- Repository mining with API integration
- Network intelligence integration
- Automated content analysis and extraction

Author: ProxC Development Team
Version: 3.2.0-COLLECTORS
License: MIT
"""

import logging
from typing import Dict, List, Optional, Any
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

class CollectorType(Enum):
    """Types of collectors"""
    WEB_SCRAPER = "web_scraper"
    REPOSITORY_MINER = "repository_miner"
    PASTEBIN_COLLECTOR = "pastebin_collector"
    NETWORK_INTELLIGENCE = "network_intelligence"
    API_COLLECTOR = "api_collector"

class ScrapingEngine(Enum):
    """Scraping engine types"""
    REQUESTS = "requests"
    SCRAPY = "scrapy"
    PLAYWRIGHT = "playwright"
    SELENIUM = "selenium"

class ContentFormat(Enum):
    """Content formats for extraction"""
    HTML = "html"
    JSON = "json"
    TEXT = "text"
    XML = "xml"
    CSV = "csv"

# Export main classes
from .web_scrapers import (
    WebScrapingEngine,
    ScrapingConfig,
    ScrapingResult,
    PlaywrightScraper,
    RequestsScraper,
    ContentExtractor
)

from .repo_miner import (
    RepositoryMiner,
    GitHubMiner,
    GitLabMiner,
    BitbucketMiner,
    RepositoryResult,
    RepoConfig
)

from .pastebin_collector import (
    PastebinCollector,
    PasteConfig,
    PasteResult,
    PastebinMonitor,
    PasteAnalyzer
)

from .network_intel import (
    NetworkIntelligenceCollector,
    ShodanCollector,
    CensysCollector,
    NetworkIntelResult,
    IntelConfig
)

__all__ = [
    'CollectorType',
    'ScrapingEngine', 
    'ContentFormat',
    'WebScrapingEngine',
    'ScrapingConfig',
    'ScrapingResult',
    'PlaywrightScraper',
    'RequestsScraper',
    'ContentExtractor',
    'RepositoryMiner',
    'GitHubMiner',
    'GitLabMiner',
    'BitbucketMiner',
    'RepositoryResult',
    'RepoConfig',
    'PastebinCollector',
    'PasteConfig',
    'PasteResult',
    'PastebinMonitor',
    'PasteAnalyzer',
    'NetworkIntelligenceCollector',
    'ShodanCollector',
    'CensysCollector',
    'NetworkIntelResult',
    'IntelConfig'
]

# Version info
__version__ = "3.2.0-COLLECTORS"
__author__ = "ProxC Development Team"
__license__ = "MIT"

logger.info("Advanced collection system initialized successfully")