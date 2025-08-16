"""Anti-Detection Systems - Professional stealth and evasion mechanisms"""

import random
import time
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Callable
from enum import Enum
import json
import hashlib

from ..proxy_core.models import ProxyInfo


class DetectionVector(Enum):
    """Types of detection methods to evade"""
    USER_AGENT = "user_agent"
    REQUEST_HEADERS = "request_headers"
    REQUEST_TIMING = "request_timing"
    REQUEST_PATTERNS = "request_patterns"
    BROWSER_FINGERPRINT = "browser_fingerprint"
    TLS_FINGERPRINT = "tls_fingerprint"
    CONNECTION_BEHAVIOR = "connection_behavior"
    PROXY_HEADERS = "proxy_headers"


@dataclass
class UserAgentProfile:
    """Complete user agent profile with associated headers"""
    user_agent: str
    browser: str
    version: str
    os: str
    accept: str
    accept_language: str
    accept_encoding: str
    sec_fetch_dest: Optional[str] = None
    sec_fetch_mode: Optional[str] = None
    sec_fetch_site: Optional[str] = None
    upgrade_insecure_requests: Optional[str] = None
    cache_control: Optional[str] = None


@dataclass 
class AntiDetectionConfig:
    """Configuration for anti-detection systems"""
    enable_user_agent_rotation: bool = True
    enable_header_randomization: bool = True
    enable_timing_randomization: bool = True
    enable_pattern_obfuscation: bool = True
    enable_fingerprint_spoofing: bool = True
    
    # Timing randomization
    min_request_delay: float = 0.1
    max_request_delay: float = 3.0
    burst_delay_multiplier: float = 2.0
    
    # Pattern obfuscation
    max_concurrent_per_target: int = 3
    request_interval_variance: float = 0.5
    
    # Header randomization
    header_variation_probability: float = 0.3
    
    # Fingerprint spoofing
    rotate_fingerprint_frequency: int = 100  # requests


class AntiDetectionManager:
    """Professional anti-detection and stealth management"""
    
    def __init__(self, config: Optional[AntiDetectionConfig] = None):
        self.config = config or AntiDetectionConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # User agent profiles (realistic browser combinations)
        self.user_agent_profiles = self._load_user_agent_profiles()
        
        # Current session state
        self.current_profile: Optional[UserAgentProfile] = None
        self.request_count = 0
        self.last_request_time = 0.0
        self.target_request_counts: Dict[str, int] = {}
        
        # Detection evasion stats
        self.evasion_stats = {
            'profiles_rotated': 0,
            'timing_delays_applied': 0,
            'headers_randomized': 0,
            'patterns_obfuscated': 0,
            'fingerprints_spoofed': 0
        }
        
        # Advanced evasion state
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.proxy_session_mapping: Dict[str, str] = {}
        
        self.logger.info("Anti-Detection Manager initialized")
    
    def _load_user_agent_profiles(self) -> List[UserAgentProfile]:
        """Load realistic user agent profiles"""
        
        profiles = [
            # Chrome Windows profiles
            UserAgentProfile(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                browser="Chrome", version="120.0", os="Windows 10",
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                accept_language="en-US,en;q=0.9",
                accept_encoding="gzip, deflate, br",
                sec_fetch_dest="document",
                sec_fetch_mode="navigate",
                sec_fetch_site="none",
                upgrade_insecure_requests="1",
                cache_control="max-age=0"
            ),
            
            # Chrome Mac profiles  
            UserAgentProfile(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                browser="Chrome", version="120.0", os="macOS",
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                accept_language="en-US,en;q=0.9",
                accept_encoding="gzip, deflate, br",
                sec_fetch_dest="document",
                sec_fetch_mode="navigate",
                sec_fetch_site="none",
                upgrade_insecure_requests="1"
            ),
            
            # Firefox Windows profiles
            UserAgentProfile(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
                browser="Firefox", version="120.0", os="Windows 10",
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                accept_language="en-US,en;q=0.5",
                accept_encoding="gzip, deflate, br",
                upgrade_insecure_requests="1"
            ),
            
            # Safari Mac profiles
            UserAgentProfile(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
                browser="Safari", version="17.1", os="macOS",
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                accept_language="en-US,en;q=0.9",
                accept_encoding="gzip, deflate, br"
            ),
            
            # Edge Windows profiles
            UserAgentProfile(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
                browser="Edge", version="120.0", os="Windows 10",
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                accept_language="en-US,en;q=0.9",
                accept_encoding="gzip, deflate, br",
                sec_fetch_dest="document",
                sec_fetch_mode="navigate",
                sec_fetch_site="none",
                upgrade_insecure_requests="1"
            ),
            
            # Chrome Linux profiles
            UserAgentProfile(
                user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                browser="Chrome", version="120.0", os="Linux",
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                accept_language="en-US,en;q=0.9",
                accept_encoding="gzip, deflate, br"
            ),
            
            # Mobile Chrome Android profiles
            UserAgentProfile(
                user_agent="Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                browser="Chrome Mobile", version="120.0", os="Android",
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                accept_language="en-US,en;q=0.9",
                accept_encoding="gzip, deflate, br"
            ),
            
            # Mobile Safari iOS profiles  
            UserAgentProfile(
                user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
                browser="Safari Mobile", version="17.1", os="iOS",
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                accept_language="en-US,en;q=0.9",
                accept_encoding="gzip, deflate, br"
            )
        ]
        
        return profiles
    
    def get_stealth_headers(self, target_url: str, proxy: ProxyInfo) -> Dict[str, str]:
        """Generate stealth headers for a request"""
        
        # Rotate profile if needed
        if (not self.current_profile or 
            self.request_count % self.config.rotate_fingerprint_frequency == 0):
            self._rotate_user_agent_profile()
        
        # Build base headers from profile
        headers = {
            'User-Agent': self.current_profile.user_agent,
            'Accept': self.current_profile.accept,
            'Accept-Language': self.current_profile.accept_language,
            'Accept-Encoding': self.current_profile.accept_encoding,
            'DNT': '1',
            'Connection': 'keep-alive'
        }
        
        # Add browser-specific headers
        if self.current_profile.sec_fetch_dest:
            headers['Sec-Fetch-Dest'] = self.current_profile.sec_fetch_dest
        if self.current_profile.sec_fetch_mode:
            headers['Sec-Fetch-Mode'] = self.current_profile.sec_fetch_mode
        if self.current_profile.sec_fetch_site:
            headers['Sec-Fetch-Site'] = self.current_profile.sec_fetch_site
        if self.current_profile.upgrade_insecure_requests:
            headers['Upgrade-Insecure-Requests'] = self.current_profile.upgrade_insecure_requests
        if self.current_profile.cache_control:
            headers['Cache-Control'] = self.current_profile.cache_control
        
        # Apply header randomization
        if self.config.enable_header_randomization:
            headers = self._randomize_headers(headers)
        
        # Remove proxy-revealing headers
        headers = self._sanitize_proxy_headers(headers)
        
        self.request_count += 1
        self.evasion_stats['headers_randomized'] += 1
        
        return headers
    
    def _rotate_user_agent_profile(self):
        """Rotate to a new user agent profile"""
        self.current_profile = random.choice(self.user_agent_profiles)
        self.evasion_stats['profiles_rotated'] += 1
        
        self.logger.debug(f"Rotated to profile: {self.current_profile.browser} on {self.current_profile.os}")
    
    def _randomize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Apply randomization to headers"""
        
        # Randomly vary Accept-Language
        if random.random() < self.config.header_variation_probability:
            languages = ['en-US,en;q=0.9', 'en-GB,en;q=0.9', 'en-US,en;q=0.8,fr;q=0.6', 'en']
            headers['Accept-Language'] = random.choice(languages)
        
        # Randomly add/remove optional headers
        if random.random() < 0.3:
            headers['Sec-CH-UA-Mobile'] = '?0' if 'Mobile' not in self.current_profile.user_agent else '?1'
        
        if random.random() < 0.2:
            headers['Sec-CH-UA-Platform'] = f'"{self._get_platform_from_ua()}"'
        
        # Randomly vary connection behavior
        if random.random() < 0.2:
            headers['Connection'] = random.choice(['keep-alive', 'close'])
        
        return headers
    
    def _get_platform_from_ua(self) -> str:
        """Extract platform from current user agent"""
        if 'Windows' in self.current_profile.os:
            return 'Windows'
        elif 'Mac' in self.current_profile.os or 'macOS' in self.current_profile.os:
            return 'macOS'
        elif 'Linux' in self.current_profile.os:
            return 'Linux'
        elif 'Android' in self.current_profile.os:
            return 'Android'
        elif 'iOS' in self.current_profile.os:
            return 'iOS'
        else:
            return 'Unknown'
    
    def _sanitize_proxy_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Remove headers that might reveal proxy usage"""
        
        # Headers to remove (proxy-revealing)
        proxy_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'Via',
            'X-Proxy-Connection',
            'Proxy-Connection',
            'X-Forwarded-Proto',
            'X-Forwarded-Host',
            'Forwarded',
            'Client-IP',
            'X-Client-IP',
            'X-Cluster-Client-IP'
        ]
        
        # Remove proxy headers
        for header in proxy_headers:
            headers.pop(header, None)
            headers.pop(header.lower(), None)
        
        return headers
    
    async def apply_request_timing(self, target_url: str) -> float:
        """Apply intelligent request timing delays"""
        
        if not self.config.enable_timing_randomization:
            return 0.0
        
        current_time = time.time()
        target_host = self._extract_host(target_url)
        
        # Track requests per target
        if target_host not in self.target_request_counts:
            self.target_request_counts[target_host] = 0
        
        self.target_request_counts[target_host] += 1
        
        # Calculate base delay
        base_delay = random.uniform(
            self.config.min_request_delay, 
            self.config.max_request_delay
        )
        
        # Increase delay for burst requests to same target
        requests_to_target = self.target_request_counts[target_host]
        if requests_to_target > self.config.max_concurrent_per_target:
            burst_multiplier = min(self.config.burst_delay_multiplier, requests_to_target / 10)
            base_delay *= burst_multiplier
        
        # Add variance to make timing less predictable
        variance = base_delay * self.config.request_interval_variance
        final_delay = base_delay + random.uniform(-variance, variance)
        final_delay = max(0.05, final_delay)  # Minimum 50ms delay
        
        # Apply delay
        if final_delay > 0:
            await asyncio.sleep(final_delay)
            self.evasion_stats['timing_delays_applied'] += 1
        
        self.last_request_time = current_time
        return final_delay
    
    def _extract_host(self, url: str) -> str:
        """Extract host from URL"""
        try:
            if '://' in url:
                url = url.split('://', 1)[1]
            
            host = url.split('/')[0]
            if ':' in host:
                host = host.split(':')[0]
            
            return host
        except:
            return url
    
    def create_session_fingerprint(self, proxy: ProxyInfo) -> str:
        """Create unique session fingerprint for proxy"""
        
        # Create session based on proxy + current profile
        session_data = {
            'proxy': proxy.address,
            'profile': {
                'browser': self.current_profile.browser if self.current_profile else 'unknown',
                'version': self.current_profile.version if self.current_profile else 'unknown',
                'os': self.current_profile.os if self.current_profile else 'unknown'
            },
            'timestamp': int(time.time() / 3600)  # Change hourly
        }
        
        session_json = json.dumps(session_data, sort_keys=True)
        session_id = hashlib.md5(session_json.encode()).hexdigest()
        
        # Track session
        if session_id not in self.active_sessions:
            self.active_sessions[session_id] = {
                'created': time.time(),
                'requests': 0,
                'proxy': proxy.address,
                'profile': self.current_profile
            }
        
        self.proxy_session_mapping[proxy.address] = session_id
        self.evasion_stats['fingerprints_spoofed'] += 1
        
        return session_id
    
    def get_session_consistency_headers(self, proxy: ProxyInfo) -> Dict[str, str]:
        """Get headers for session consistency"""
        
        session_id = self.proxy_session_mapping.get(proxy.address)
        if not session_id or session_id not in self.active_sessions:
            return {}
        
        session = self.active_sessions[session_id]
        session['requests'] += 1
        
        # Session-consistent headers (simulating same browser session)
        headers = {}
        
        # Consistent session timing
        session_age = time.time() - session['created']
        if session_age > 3600:  # 1 hour sessions
            # Start new session
            del self.active_sessions[session_id]
            del self.proxy_session_mapping[proxy.address]
            return {}
        
        # Add session-specific headers
        if session['requests'] > 1:
            headers['Cache-Control'] = 'no-cache'
        
        return headers
    
    def apply_pattern_obfuscation(self, request_params: Dict[str, Any]) -> Dict[str, Any]:
        """Apply pattern obfuscation to request parameters"""
        
        if not self.config.enable_pattern_obfuscation:
            return request_params
        
        # Add random query parameters to break patterns
        if random.random() < 0.1:  # 10% chance
            noise_params = [
                f"_={int(time.time() * 1000)}",  # Timestamp
                f"r={random.randint(100000, 999999)}",  # Random number
                f"v={random.choice(['1.0', '2.0', '3.0'])}"  # Version
            ]
            
            url = request_params.get('url', '')
            if '?' in url:
                url += '&' + '&'.join(noise_params)
            else:
                url += '?' + '&'.join(noise_params)
            
            request_params['url'] = url
        
        self.evasion_stats['patterns_obfuscated'] += 1
        
        return request_params
    
    def generate_realistic_referrer(self, target_url: str) -> Optional[str]:
        """Generate realistic referrer header"""
        
        # Common referrer patterns
        referrers = [
            'https://www.google.com/',
            'https://www.bing.com/',
            'https://duckduckgo.com/',
            'https://search.yahoo.com/',
            None  # No referrer
        ]
        
        # 70% chance of having a referrer
        if random.random() < 0.7:
            return random.choice(referrers[:-1])  # Exclude None
        
        return None
    
    def get_anti_detection_report(self) -> Dict[str, Any]:
        """Get anti-detection statistics and status"""
        
        return {
            'current_profile': {
                'browser': self.current_profile.browser if self.current_profile else None,
                'version': self.current_profile.version if self.current_profile else None,
                'os': self.current_profile.os if self.current_profile else None
            } if self.current_profile else None,
            
            'session_stats': {
                'total_requests': self.request_count,
                'active_sessions': len(self.active_sessions),
                'target_tracking': len(self.target_request_counts)
            },
            
            'evasion_stats': self.evasion_stats.copy(),
            
            'configuration': {
                'user_agent_rotation': self.config.enable_user_agent_rotation,
                'header_randomization': self.config.enable_header_randomization,
                'timing_randomization': self.config.enable_timing_randomization,
                'pattern_obfuscation': self.config.enable_pattern_obfuscation,
                'fingerprint_spoofing': self.config.enable_fingerprint_spoofing,
                'rotation_frequency': self.config.rotate_fingerprint_frequency
            },
            
            'detection_vectors_addressed': len([v for v in DetectionVector if self._is_vector_addressed(v)])
        }
    
    def _is_vector_addressed(self, vector: DetectionVector) -> bool:
        """Check if detection vector is being addressed"""
        
        vector_config_map = {
            DetectionVector.USER_AGENT: self.config.enable_user_agent_rotation,
            DetectionVector.REQUEST_HEADERS: self.config.enable_header_randomization,
            DetectionVector.REQUEST_TIMING: self.config.enable_timing_randomization,
            DetectionVector.REQUEST_PATTERNS: self.config.enable_pattern_obfuscation,
            DetectionVector.BROWSER_FINGERPRINT: self.config.enable_fingerprint_spoofing,
            DetectionVector.PROXY_HEADERS: True,  # Always sanitized
            DetectionVector.CONNECTION_BEHAVIOR: self.config.enable_timing_randomization,
            DetectionVector.TLS_FINGERPRINT: False  # Not yet implemented
        }
        
        return vector_config_map.get(vector, False)
    
    def reset_session_state(self):
        """Reset session state (useful for testing or cleanup)"""
        self.active_sessions.clear()
        self.proxy_session_mapping.clear()
        self.target_request_counts.clear()
        self.request_count = 0
        self.current_profile = None
        
        self.logger.info("Anti-detection session state reset")


def create_anti_detection_manager(enable_all: bool = True) -> AntiDetectionManager:
    """Create anti-detection manager with specified configuration"""
    
    if enable_all:
        config = AntiDetectionConfig(
            enable_user_agent_rotation=True,
            enable_header_randomization=True,
            enable_timing_randomization=True,
            enable_pattern_obfuscation=True,
            enable_fingerprint_spoofing=True
        )
    else:
        config = AntiDetectionConfig()
    
    return AntiDetectionManager(config)