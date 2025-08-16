"""
Repository Mining System
========================

Automated mining of code repositories (GitHub, GitLab, Bitbucket) for
proxy lists, configurations, and related content with API integration
and commit monitoring capabilities.
"""

import asyncio
import base64
import json
import logging
import re
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Union, Any
from urllib.parse import urljoin, quote

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

# Import our core types
from ..proxy_core.models import ProxyInfo

logger = logging.getLogger(__name__)


class RepositoryPlatform(Enum):
    """Supported repository platforms"""
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"


class ContentType(Enum):
    """Types of repository content"""
    PROXY_LIST = "proxy_list"
    CONFIG_FILE = "config_file"
    DOCUMENTATION = "documentation"
    SOURCE_CODE = "source_code"
    README = "readme"


@dataclass
class RepoConfig:
    """Configuration for repository mining"""
    # API credentials
    github_token: Optional[str] = None
    gitlab_token: Optional[str] = None
    bitbucket_username: Optional[str] = None
    bitbucket_password: Optional[str] = None
    
    # Search parameters
    search_keywords: List[str] = field(default_factory=lambda: [
        "proxy list", "free proxy", "working proxy", "proxy server",
        "socks proxy", "http proxy", "anonymous proxy"
    ])
    file_extensions: List[str] = field(default_factory=lambda: [
        "txt", "json", "csv", "yml", "yaml", "conf", "cfg", "ini"
    ])
    
    # Content filtering
    min_file_size: int = 100  # bytes
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    max_results_per_platform: int = 100
    min_repo_stars: int = 0
    max_repo_age_days: int = 365
    
    # Rate limiting
    requests_per_minute: int = 60
    delay_between_requests: float = 1.0
    
    # Content analysis
    proxy_patterns: List[str] = field(default_factory=lambda: [
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\b',
        r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+',
        r'socks[45]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+'
    ])


@dataclass
class RepositoryResult:
    """Result from repository mining"""
    platform: RepositoryPlatform
    repository_name: str
    repository_url: str
    file_path: str
    file_url: str
    
    # Content analysis
    content: str = ""
    content_type: ContentType = ContentType.PROXY_LIST
    extracted_proxies: List[str] = field(default_factory=list)
    proxy_count: int = 0
    
    # Repository metadata
    repository_description: Optional[str] = None
    repository_stars: int = 0
    repository_language: Optional[str] = None
    last_updated: Optional[datetime] = None
    
    # File metadata
    file_size: int = 0
    file_encoding: Optional[str] = None
    commit_sha: Optional[str] = None
    
    # Analysis results
    relevance_score: float = 0.0
    quality_indicators: List[str] = field(default_factory=list)
    
    # Collection metadata
    collection_timestamp: datetime = field(default_factory=datetime.utcnow)
    api_rate_limit_remaining: Optional[int] = None


class BaseRepositoryMiner(ABC):
    """Abstract base class for repository miners"""
    
    def __init__(self, config: RepoConfig):
        self.config = config
        self.request_count = 0
        self.last_request_time = 0.0
        self.rate_limit_reset_time = time.time() + 60
    
    @abstractmethod
    async def search_repositories(self, query: str) -> List[Dict[str, Any]]:
        """Search for repositories"""
        pass
    
    @abstractmethod
    async def get_file_content(self, repo_info: Dict[str, Any], file_path: str) -> Optional[str]:
        """Get content of a specific file"""
        pass
    
    @abstractmethod
    def get_platform(self) -> RepositoryPlatform:
        """Get platform type"""
        pass
    
    def _apply_rate_limiting(self):
        """Apply rate limiting to API requests"""
        current_time = time.time()
        
        # Reset rate limit counter
        if current_time > self.rate_limit_reset_time:
            self.request_count = 0
            self.rate_limit_reset_time = current_time + 60
        
        # Check rate limit
        if self.request_count >= self.config.requests_per_minute:
            sleep_time = self.rate_limit_reset_time - current_time + 1
            logger.info(f"Rate limit reached for {self.get_platform().value}, sleeping {sleep_time:.1f}s")
            time.sleep(sleep_time)
            self.request_count = 0
            self.rate_limit_reset_time = time.time() + 60
        
        # Apply minimum delay
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.config.delay_between_requests:
            time.sleep(self.config.delay_between_requests - time_since_last)
        
        self.last_request_time = time.time()
        self.request_count += 1
    
    def _extract_proxies_from_content(self, content: str) -> List[str]:
        """Extract proxy addresses from content"""
        proxies = []
        
        for pattern in self.config.proxy_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                proxy = match.group(0)
                if self._validate_proxy_format(proxy):
                    proxies.append(proxy)
        
        return list(set(proxies))  # Remove duplicates
    
    def _validate_proxy_format(self, proxy: str) -> bool:
        """Validate proxy format"""
        try:
            # Remove protocol if present
            if '://' in proxy:
                proxy = proxy.split('://', 1)[1]
            
            if ':' not in proxy:
                return False
            
            ip, port = proxy.rsplit(':', 1)
            
            # Validate IP
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
    
    def _calculate_relevance_score(self, repo_info: Dict[str, Any], content: str) -> float:
        """Calculate relevance score for repository content"""
        score = 0.0
        
        # Repository popularity (stars)
        stars = repo_info.get('stargazers_count', 0) or repo_info.get('stars', 0)
        if stars > 0:
            score += min(stars / 100.0, 0.5)  # Cap at 0.5
        
        # Content analysis
        content_lower = content.lower()
        
        # Keyword relevance
        for keyword in self.config.search_keywords:
            if keyword.lower() in content_lower:
                score += 0.1
        
        # Proxy count bonus
        proxy_count = len(self._extract_proxies_from_content(content))
        score += min(proxy_count / 50.0, 0.3)  # Cap at 0.3
        
        # Freshness bonus
        last_updated = repo_info.get('updated_at') or repo_info.get('last_activity_at')
        if last_updated:
            try:
                update_date = datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
                days_old = (datetime.utcnow().replace(tzinfo=update_date.tzinfo) - update_date).days
                if days_old < 30:
                    score += 0.2
                elif days_old < 90:
                    score += 0.1
            except:
                pass
        
        return min(score, 1.0)
    
    def _detect_quality_indicators(self, content: str, repo_info: Dict[str, Any]) -> List[str]:
        """Detect quality indicators in content"""
        indicators = []
        content_lower = content.lower()
        
        # Content quality indicators
        quality_terms = [
            'working', 'tested', 'verified', 'updated', 'fresh',
            'alive', 'checked', 'validated', 'active'
        ]
        
        for term in quality_terms:
            if term in content_lower:
                indicators.append(f"content_{term}")
        
        # Repository quality indicators
        stars = repo_info.get('stargazers_count', 0) or repo_info.get('stars', 0)
        if stars > 10:
            indicators.append("popular_repository")
        if stars > 100:
            indicators.append("very_popular_repository")
        
        # Recent activity
        last_updated = repo_info.get('updated_at') or repo_info.get('last_activity_at')
        if last_updated:
            try:
                update_date = datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
                days_old = (datetime.utcnow().replace(tzinfo=update_date.tzinfo) - update_date).days
                if days_old < 7:
                    indicators.append("recently_updated")
                elif days_old < 30:
                    indicators.append("actively_maintained")
            except:
                pass
        
        return indicators


class GitHubMiner(BaseRepositoryMiner):
    """GitHub repository miner"""
    
    def __init__(self, config: RepoConfig):
        super().__init__(config)
        self.base_url = "https://api.github.com"
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'ProxyHunter/3.0'
        }
        
        if config.github_token:
            self.headers['Authorization'] = f'token {config.github_token}'
    
    def get_platform(self) -> RepositoryPlatform:
        return RepositoryPlatform.GITHUB
    
    async def search_repositories(self, query: str) -> List[Dict[str, Any]]:
        """Search GitHub repositories"""
        if not HAS_REQUESTS:
            return []
        
        self._apply_rate_limiting()
        
        search_url = f"{self.base_url}/search/repositories"
        
        # Build search query with filters
        search_query = f"{query} language:* stars:>={self.config.min_repo_stars}"
        
        params = {
            'q': search_query,
            'sort': 'updated',
            'order': 'desc',
            'per_page': min(self.config.max_results_per_platform, 100)
        }
        
        try:
            response = requests.get(search_url, headers=self.headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('items', [])
            elif response.status_code == 403:
                logger.warning("GitHub API rate limit exceeded")
                return []
            else:
                logger.error(f"GitHub search failed: HTTP {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"GitHub search error: {e}")
            return []
    
    async def get_file_content(self, repo_info: Dict[str, Any], file_path: str) -> Optional[str]:
        """Get GitHub file content"""
        if not HAS_REQUESTS:
            return None
        
        self._apply_rate_limiting()
        
        owner = repo_info['owner']['login']
        repo_name = repo_info['name']
        
        content_url = f"{self.base_url}/repos/{owner}/{repo_name}/contents/{file_path}"
        
        try:
            response = requests.get(content_url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                if data['encoding'] == 'base64':
                    content = base64.b64decode(data['content']).decode('utf-8', errors='ignore')
                    return content
                else:
                    return data.get('content', '')
            else:
                logger.debug(f"Failed to get file content: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            logger.debug(f"Error getting file content: {e}")
            return None
    
    async def search_code_files(self, repo_info: Dict[str, Any]) -> List[str]:
        """Search for relevant files in repository"""
        if not HAS_REQUESTS:
            return []
        
        self._apply_rate_limiting()
        
        owner = repo_info['owner']['login']
        repo_name = repo_info['name']
        
        # Search for files with relevant extensions
        relevant_files = []
        
        for extension in self.config.file_extensions:
            search_query = f"extension:{extension} repo:{owner}/{repo_name}"
            
            search_url = f"{self.base_url}/search/code"
            params = {
                'q': search_query,
                'per_page': 20
            }
            
            try:
                response = requests.get(search_url, headers=self.headers, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    for item in data.get('items', []):
                        file_path = item.get('path', '')
                        if self._is_relevant_file(file_path, item.get('name', '')):
                            relevant_files.append(file_path)
                elif response.status_code == 403:
                    logger.warning("GitHub code search rate limit exceeded")
                    break
            except Exception as e:
                logger.debug(f"Code search error: {e}")
                continue
        
        return list(set(relevant_files))  # Remove duplicates
    
    def _is_relevant_file(self, file_path: str, file_name: str) -> bool:
        """Check if file is relevant for proxy mining"""
        # Check for proxy-related keywords in filename/path
        path_lower = f"{file_path} {file_name}".lower()
        
        relevant_keywords = [
            'proxy', 'proxies', 'socks', 'http', 'server', 'list',
            'working', 'free', 'anonymous', 'elite'
        ]
        
        return any(keyword in path_lower for keyword in relevant_keywords)


class GitLabMiner(BaseRepositoryMiner):
    """GitLab repository miner"""
    
    def __init__(self, config: RepoConfig):
        super().__init__(config)
        self.base_url = "https://gitlab.com/api/v4"
        self.headers = {
            'User-Agent': 'ProxyHunter/3.0'
        }
        
        if config.gitlab_token:
            self.headers['Authorization'] = f'Bearer {config.gitlab_token}'
    
    def get_platform(self) -> RepositoryPlatform:
        return RepositoryPlatform.GITLAB
    
    async def search_repositories(self, query: str) -> List[Dict[str, Any]]:
        """Search GitLab repositories"""
        if not HAS_REQUESTS:
            return []
        
        self._apply_rate_limiting()
        
        search_url = f"{self.base_url}/projects"
        
        params = {
            'search': query,
            'order_by': 'updated_at',
            'sort': 'desc',
            'per_page': min(self.config.max_results_per_platform, 100),
            'simple': 'true'
        }
        
        try:
            response = requests.get(search_url, headers=self.headers, params=params, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"GitLab search failed: HTTP {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"GitLab search error: {e}")
            return []
    
    async def get_file_content(self, repo_info: Dict[str, Any], file_path: str) -> Optional[str]:
        """Get GitLab file content"""
        if not HAS_REQUESTS:
            return None
        
        self._apply_rate_limiting()
        
        project_id = repo_info['id']
        encoded_path = quote(file_path, safe='')
        
        content_url = f"{self.base_url}/projects/{project_id}/repository/files/{encoded_path}/raw"
        
        try:
            response = requests.get(content_url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                return response.text
            else:
                logger.debug(f"Failed to get GitLab file content: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            logger.debug(f"Error getting GitLab file content: {e}")
            return None


class BitbucketMiner(BaseRepositoryMiner):
    """Bitbucket repository miner"""
    
    def __init__(self, config: RepoConfig):
        super().__init__(config)
        self.base_url = "https://api.bitbucket.org/2.0"
        self.headers = {
            'User-Agent': 'ProxyHunter/3.0'
        }
        
        if config.bitbucket_username and config.bitbucket_password:
            credentials = base64.b64encode(
                f"{config.bitbucket_username}:{config.bitbucket_password}".encode()
            ).decode()
            self.headers['Authorization'] = f'Basic {credentials}'
    
    def get_platform(self) -> RepositoryPlatform:
        return RepositoryPlatform.BITBUCKET
    
    async def search_repositories(self, query: str) -> List[Dict[str, Any]]:
        """Search Bitbucket repositories"""
        if not HAS_REQUESTS:
            return []
        
        self._apply_rate_limiting()
        
        search_url = f"{self.base_url}/repositories"
        
        params = {
            'q': f'name~"{query}"',
            'sort': '-updated_on',
            'pagelen': min(self.config.max_results_per_platform, 100)
        }
        
        try:
            response = requests.get(search_url, headers=self.headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('values', [])
            else:
                logger.error(f"Bitbucket search failed: HTTP {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Bitbucket search error: {e}")
            return []
    
    async def get_file_content(self, repo_info: Dict[str, Any], file_path: str) -> Optional[str]:
        """Get Bitbucket file content"""
        if not HAS_REQUESTS:
            return None
        
        self._apply_rate_limiting()
        
        full_name = repo_info['full_name']
        content_url = f"{self.base_url}/repositories/{full_name}/src/master/{file_path}"
        
        try:
            response = requests.get(content_url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                return response.text
            else:
                logger.debug(f"Failed to get Bitbucket file content: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            logger.debug(f"Error getting Bitbucket file content: {e}")
            return None


class RepositoryMiner:
    """Main repository mining coordinator"""
    
    def __init__(self, config: RepoConfig):
        self.config = config
        self.miners: Dict[RepositoryPlatform, BaseRepositoryMiner] = {}
        self._initialize_miners()
    
    def _initialize_miners(self):
        """Initialize available miners"""
        # GitHub
        if self.config.github_token or HAS_REQUESTS:
            self.miners[RepositoryPlatform.GITHUB] = GitHubMiner(self.config)
        
        # GitLab
        if self.config.gitlab_token or HAS_REQUESTS:
            self.miners[RepositoryPlatform.GITLAB] = GitLabMiner(self.config)
        
        # Bitbucket
        if (self.config.bitbucket_username and self.config.bitbucket_password) or HAS_REQUESTS:
            self.miners[RepositoryPlatform.BITBUCKET] = BitbucketMiner(self.config)
        
        logger.info(f"Initialized {len(self.miners)} repository miners: {list(self.miners.keys())}")
    
    async def mine_all_platforms(self) -> List[RepositoryResult]:
        """Mine repositories from all platforms"""
        all_results = []
        
        for platform, miner in self.miners.items():
            try:
                logger.info(f"Mining repositories from {platform.value}")
                results = await self._mine_platform(miner)
                all_results.extend(results)
                logger.info(f"Found {len(results)} results from {platform.value}")
            except Exception as e:
                logger.error(f"Mining failed for {platform.value}: {e}")
        
        # Sort by relevance score
        all_results.sort(key=lambda r: r.relevance_score, reverse=True)
        
        logger.info(f"Total mining results: {len(all_results)}")
        return all_results
    
    async def _mine_platform(self, miner: BaseRepositoryMiner) -> List[RepositoryResult]:
        """Mine repositories from a specific platform"""
        results = []
        
        # Search for repositories with different keywords
        for keyword in self.config.search_keywords[:3]:  # Limit to avoid rate limits
            try:
                repos = await miner.search_repositories(keyword)
                
                for repo in repos[:20]:  # Limit per keyword
                    repo_results = await self._mine_repository(miner, repo)
                    results.extend(repo_results)
                
            except Exception as e:
                logger.error(f"Repository search failed for '{keyword}': {e}")
                continue
        
        return results
    
    async def _mine_repository(self, miner: BaseRepositoryMiner, repo_info: Dict[str, Any]) -> List[RepositoryResult]:
        """Mine a specific repository"""
        results = []
        
        try:
            # Get repository URL
            if miner.get_platform() == RepositoryPlatform.GITHUB:
                repo_url = repo_info.get('html_url', '')
                repo_name = repo_info.get('full_name', '')
            elif miner.get_platform() == RepositoryPlatform.GITLAB:
                repo_url = repo_info.get('web_url', '')
                repo_name = repo_info.get('path_with_namespace', '')
            else:  # Bitbucket
                repo_url = repo_info.get('links', {}).get('html', {}).get('href', '')
                repo_name = repo_info.get('full_name', '')
            
            # Common files to check
            common_files = [
                'proxy.txt', 'proxies.txt', 'proxy_list.txt',
                'working_proxies.txt', 'free_proxies.txt',
                'socks.txt', 'http_proxies.txt',
                'README.md', 'config.yml', 'config.json'
            ]
            
            # Try to get file content for common proxy files
            for file_path in common_files:
                content = await miner.get_file_content(repo_info, file_path)
                
                if content and len(content) >= self.config.min_file_size:
                    # Extract proxies
                    proxies = miner._extract_proxies_from_content(content)
                    
                    if proxies:  # Only include if proxies found
                        result = RepositoryResult(
                            platform=miner.get_platform(),
                            repository_name=repo_name,
                            repository_url=repo_url,
                            file_path=file_path,
                            file_url=f"{repo_url}/blob/master/{file_path}",
                            content=content[:5000],  # Truncate content
                            extracted_proxies=proxies,
                            proxy_count=len(proxies),
                            file_size=len(content)
                        )
                        
                        # Set repository metadata
                        result.repository_description = repo_info.get('description')
                        result.repository_stars = repo_info.get('stargazers_count', 0) or repo_info.get('stars', 0)
                        result.repository_language = repo_info.get('language')
                        
                        # Parse last updated
                        last_updated = repo_info.get('updated_at') or repo_info.get('last_activity_at')
                        if last_updated:
                            try:
                                result.last_updated = datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
                            except:
                                pass
                        
                        # Calculate relevance and quality
                        result.relevance_score = miner._calculate_relevance_score(repo_info, content)
                        result.quality_indicators = miner._detect_quality_indicators(content, repo_info)
                        
                        # Determine content type
                        if 'readme' in file_path.lower():
                            result.content_type = ContentType.README
                        elif any(ext in file_path.lower() for ext in ['yml', 'yaml', 'json', 'conf', 'cfg']):
                            result.content_type = ContentType.CONFIG_FILE
                        else:
                            result.content_type = ContentType.PROXY_LIST
                        
                        results.append(result)
            
        except Exception as e:
            logger.error(f"Error mining repository {repo_info.get('name', 'unknown')}: {e}")
        
        return results
    
    def get_all_proxies(self, results: List[RepositoryResult]) -> List[str]:
        """Extract all proxies from mining results"""
        all_proxies = []
        
        for result in results:
            all_proxies.extend(result.extracted_proxies)
        
        return list(set(all_proxies))  # Remove duplicates
    
    def get_mining_summary(self, results: List[RepositoryResult]) -> Dict[str, Any]:
        """Get summary of mining operations"""
        if not results:
            return {}
        
        # Platform statistics
        platform_stats = defaultdict(int)
        for result in results:
            platform_stats[result.platform.value] += 1
        
        # Content type statistics
        content_type_stats = defaultdict(int)
        for result in results:
            content_type_stats[result.content_type.value] += 1
        
        # Quality statistics
        total_proxies = sum(result.proxy_count for result in results)
        unique_proxies = len(set().union(*[result.extracted_proxies for result in results]))
        
        avg_relevance = sum(result.relevance_score for result in results) / len(results)
        high_quality_results = [r for r in results if r.relevance_score > 0.7]
        
        return {
            'total_results': len(results),
            'platform_distribution': dict(platform_stats),
            'content_type_distribution': dict(content_type_stats),
            'total_proxies_found': total_proxies,
            'unique_proxies_found': unique_proxies,
            'average_relevance_score': avg_relevance,
            'high_quality_results': len(high_quality_results),
            'repositories_with_stars': len([r for r in results if r.repository_stars > 0]),
            'recently_updated_repos': len([
                r for r in results 
                if r.last_updated and (datetime.utcnow().replace(tzinfo=r.last_updated.tzinfo) - r.last_updated).days < 30
            ])
        }