"""Proxy Core Utils - Advanced Validation, Analysis and Security Tools"""

import hashlib
import ipaddress
import json
import logging
import random
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, AddressValueError
from typing import Dict, List, Optional, Any, Tuple, Union, Set
from urllib.parse import urlparse

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
    import geoip2.database
    import geoip2.errors
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

from .models import (
    ProxyInfo, ProxyProtocol, AnonymityLevel, ThreatLevel, ProxyStatus, 
    ValidationStatus, SecurityLevel, OperationalGrade, GeoLocation, 
    ValidationError, SecurityError, NetworkError
)

# Configure logging
logger = logging.getLogger(__name__)


# ===============================================================================
# VALIDATION RESULTS DATA CLASSES
# ===============================================================================

@dataclass
class ValidationResult:
    """Result of proxy validation"""
    is_valid: bool
    response_time: Optional[float] = None
    error_message: Optional[str] = None
    anonymity_detected: Optional[AnonymityLevel] = None
    real_ip_detected: Optional[str] = None
    dns_leak: bool = False
    webrtc_leak: bool = False
    ssl_supported: bool = False
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


@dataclass
class SecurityAssessment:
    """Security assessment result"""
    threat_level: ThreatLevel
    security_level: SecurityLevel
    is_honeypot: bool = False
    is_blacklisted: bool = False
    reputation_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    assessed_at: datetime = field(default_factory=datetime.utcnow)


# NetworkAnalysis dataclass moved to end of file for better organization


@dataclass
class PerformanceMetrics:
    """Performance metrics for proxy testing"""
    connection_time: Optional[float] = None
    dns_resolution_time: Optional[float] = None
    ssl_handshake_time: Optional[float] = None
    first_byte_time: Optional[float] = None
    total_time: Optional[float] = None
    download_speed: Optional[float] = None
    upload_speed: Optional[float] = None
    latency: Optional[float] = None
    jitter: Optional[float] = None
    packet_loss: Optional[float] = None
    measured_at: datetime = field(default_factory=datetime.utcnow)


# ===============================================================================
# ADVANCED VALIDATOR CLASS
# ===============================================================================

class CombatValidator:
    """Advanced proxy validator with comprehensive testing capabilities"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the validator with configuration"""
        self.config = config or {}
        self.timeout = self.config.get('timeout', 10)
        self.max_retries = self.config.get('max_retries', 3)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.user_agents = self._load_user_agents()
        self.test_urls = self._load_test_urls()
        
        # Session configuration for HTTP requests
        if HAS_REQUESTS:
            self.session = requests.Session()
            self.session.headers.update({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
            })
        
    
    def _load_user_agents(self) -> List[str]:
        """Load user agents for testing"""
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
    
    def _load_test_urls(self) -> Dict[str, str]:
        """Load test URLs for different validation scenarios"""
        return {
            'ip_check': 'http://httpbin.org/ip',
            'ip_check_ssl': 'https://httpbin.org/ip',
            'headers': 'http://httpbin.org/headers',
            'user_agent': 'http://httpbin.org/user-agent',
            'delay_test': 'http://httpbin.org/delay/2',
            'json_test': 'http://httpbin.org/json',
            'gzip_test': 'http://httpbin.org/gzip',
            'redirect_test': 'http://httpbin.org/redirect/3'
        }
    
    def validate_proxy(self, proxy: ProxyInfo) -> ValidationResult:
        """Validate a single proxy with comprehensive testing"""
        start_time = time.time()
        
        try:
            # Basic connectivity test
            connectivity_result = self._test_connectivity(proxy)
            if not connectivity_result['success']:
                return ValidationResult(
                    is_valid=False,
                    error_message=connectivity_result['error'],
                    response_time=time.time() - start_time
                )
            
            # Anonymity detection
            anonymity_result = self._test_anonymity(proxy)
            
            # SSL support test
            ssl_result = self._test_ssl_support(proxy)
            
            # Leak detection
            leak_result = self._test_leaks(proxy)
            
            response_time = time.time() - start_time
            
            return ValidationResult(
                is_valid=True,
                response_time=response_time,
                anonymity_detected=anonymity_result.get('level'),
                real_ip_detected=anonymity_result.get('real_ip'),
                dns_leak=leak_result.get('dns_leak', False),
                webrtc_leak=leak_result.get('webrtc_leak', False),
                ssl_supported=ssl_result.get('supported', False)
            )
            
        except Exception as e:
            logger.error(f"Validation failed for {proxy.host}:{proxy.port}: {e}")
            return ValidationResult(
                is_valid=False,
                error_message=str(e),
                response_time=time.time() - start_time
            )
    
    def _test_connectivity(self, proxy: ProxyInfo) -> Dict[str, Any]:
        """Test basic proxy connectivity"""
        if not HAS_REQUESTS:
            return {'success': False, 'error': 'requests library not available'}
        
        try:
            proxy_dict = {
                'http': f"{proxy.protocol.value}://{proxy.host}:{proxy.port}",
                'https': f"{proxy.protocol.value}://{proxy.host}:{proxy.port}"
            }
            
            if proxy.username and proxy.password:
                proxy_dict = {
                    'http': f"{proxy.protocol.value}://{proxy.username}:{proxy.password}@{proxy.host}:{proxy.port}",
                    'https': f"{proxy.protocol.value}://{proxy.username}:{proxy.password}@{proxy.host}:{proxy.port}"
                }
            
            response = self.session.get(
                self.test_urls['ip_check'],
                proxies=proxy_dict,
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers={'User-Agent': random.choice(self.user_agents)}
            )
            
            if response.status_code == 200:
                return {'success': True, 'response': response.json()}
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _test_anonymity(self, proxy: ProxyInfo) -> Dict[str, Any]:
        """Test proxy anonymity level"""
        if not HAS_REQUESTS:
            return {'level': AnonymityLevel.TRANSPARENT}
        
        try:
            # Get real IP first (direct connection)
            real_ip_response = self.session.get(
                self.test_urls['ip_check'],
                timeout=self.timeout
            )
            real_ip = real_ip_response.json().get('origin', '').split(',')[0].strip()
            
            # Test through proxy
            proxy_dict = self._build_proxy_dict(proxy)
            proxy_response = self.session.get(
                self.test_urls['headers'],
                proxies=proxy_dict,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if proxy_response.status_code != 200:
                return {'level': AnonymityLevel.TRANSPARENT, 'real_ip': real_ip}
            
            headers = proxy_response.json().get('headers', {})
            proxy_ip = headers.get('X-Forwarded-For', '').split(',')[0].strip()
            
            # Check for proxy headers that reveal anonymity level
            proxy_headers = [
                'X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP',
                'X-Remote-IP', 'X-Remote-Addr', 'Client-IP'
            ]
            
            # If real IP is visible, it's transparent
            if real_ip in str(headers):
                return {'level': AnonymityLevel.TRANSPARENT, 'real_ip': real_ip}
            
            # If proxy headers exist but no real IP, it's anonymous
            has_proxy_headers = any(header in headers for header in proxy_headers)
            if has_proxy_headers:
                return {'level': AnonymityLevel.ANONYMOUS, 'real_ip': None}
            
            # If no proxy headers detected, it's elite
            return {'level': AnonymityLevel.ELITE, 'real_ip': None}
            
        except Exception as e:
            logger.warning(f"Anonymity test failed: {e}")
            return {'level': AnonymityLevel.TRANSPARENT, 'real_ip': None}
    
    def _test_ssl_support(self, proxy: ProxyInfo) -> Dict[str, Any]:
        """Test SSL/HTTPS support"""
        if not HAS_REQUESTS:
            return {'supported': False}
        
        try:
            proxy_dict = self._build_proxy_dict(proxy)
            response = self.session.get(
                self.test_urls['ip_check_ssl'],
                proxies=proxy_dict,
                timeout=self.timeout,
                verify=False  # Don't verify SSL for testing
            )
            
            return {'supported': response.status_code == 200}
            
        except Exception:
            return {'supported': False}
    
    def _test_leaks(self, proxy: ProxyInfo) -> Dict[str, Any]:
        """Test for DNS and WebRTC leaks"""
        result = {'dns_leak': False, 'webrtc_leak': False}
        
        # DNS leak detection
        if HAS_DNSPYTHON:
            try:
                # This is a simplified DNS leak test
                # In practice, you'd want to check against known DNS servers
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [proxy.host]
                resolver.timeout = 5
                
                # Try to resolve a test domain
                answers = resolver.resolve('example.com', 'A')
                if answers:
                    result['dns_leak'] = False
                    
            except Exception:
                result['dns_leak'] = True
        
        # WebRTC leak detection would require browser automation
        # This is a placeholder for the concept
        result['webrtc_leak'] = False
        
        return result
    
    def _build_proxy_dict(self, proxy: ProxyInfo) -> Dict[str, str]:
        """Build proxy dictionary for requests"""
        if proxy.username and proxy.password:
            proxy_url = f"{proxy.protocol.value}://{proxy.username}:{proxy.password}@{proxy.host}:{proxy.port}"
        else:
            proxy_url = f"{proxy.protocol.value}://{proxy.host}:{proxy.port}"
        
        return {
            'http': proxy_url,
            'https': proxy_url
        }


# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def validate_ip_address(ip_str: str) -> bool:
    """Validate if string is a valid IP address"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_port(port: Union[int, str]) -> bool:
    """Validate if port number is valid"""
    try:
        port_int = int(port)
        return 1 <= port_int <= 65535
    except (ValueError, TypeError):
        return False


def validate_proxy_url(url: str) -> bool:
    """Validate proxy URL format"""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            return False
        
        if parsed.scheme not in ['http', 'https', 'socks4', 'socks5']:
            return False
        
        if parsed.port:
            return validate_port(parsed.port)
        
        return True
        
    except Exception:
        return False


def format_response_time(response_time: Optional[float]) -> str:
    """Format response time for display"""
    if response_time is None:
        return "N/A"
    
    if response_time < 1:
        return f"{response_time * 1000:.0f}ms"
    else:
        return f"{response_time:.2f}s"


def calculate_success_rate(successful: int, total: int) -> float:
    """Calculate success rate percentage"""
    if total == 0:
        return 0.0
    return (successful / total) * 100


def generate_proxy_id(host: str, port: int, protocol: str) -> str:
    """Generate unique proxy ID"""
    data = f"{host}:{port}:{protocol}"
    return hashlib.md5(data.encode()).hexdigest()[:16]


def is_private_ip(ip_address: str) -> bool:
    """Check if IP address is private/internal"""
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        return ip_obj.is_private
    except ValueError:
        return False


def get_ip_version(ip_address: str) -> Optional[int]:
    """Get IP version (4 or 6)"""
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        return ip_obj.version
    except ValueError:
        return None


def normalize_country_code(country_code: Optional[str]) -> Optional[str]:
    """Normalize country code to uppercase"""
    if country_code:
        return country_code.upper()
    return None


def extract_domain_from_hostname(hostname: Optional[str]) -> Optional[str]:
    """Extract domain from hostname"""
    if not hostname:
        return None
    
    parts = hostname.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return hostname


# ===============================================================================
# NETWORK INTELLIGENCE AND ANALYSIS
# ===============================================================================

# Network Analysis dataclass definition
@dataclass
class NetworkAnalysis:
    """Network analysis and intelligence results"""
    ip_address: str
    is_private: bool = False
    ip_version: int = 4
    hostname: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    timezone: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    asn: Optional[int] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_hosting: bool = False
    is_mobile: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    blacklist_status: Dict[str, bool] = field(default_factory=dict)
    threat_types: List[str] = field(default_factory=list)
    ports_open: List[int] = field(default_factory=list)
    services_detected: List[str] = field(default_factory=list)
    analyzed_at: datetime = field(default_factory=datetime.utcnow)


class NetworkIntelligence:
    """Advanced network analysis and threat intelligence"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Handle both old and new constructor calls for backward compatibility
        self.config = config or {}
        
        # Initialize DNS manager for blacklist checks
        try:
            from .dns_config import get_dns_manager
            self.dns_manager = get_dns_manager()
        except ImportError:
            logger.warning("DNS configuration manager not available")
            self.dns_manager = None
        
        # Store GeoIP database path from config
        self.geoip_db_path = self.config.get('geoip_db_path')
        
        # Fallback blacklist services if DNS manager unavailable
        self.fallback_blacklist_services = {
            'spamhaus_zen': 'zen.spamhaus.org',
            'spamhaus_pbl': 'pbl.spamhaus.org',
            'barracuda': 'b.barracudacentral.org',
            'sorbs': 'dnsbl.sorbs.net',
            'abuse_ch': 'drone.abuse.ch'
        }
    
    def analyze_ip(self, ip_address: str) -> NetworkAnalysis:
        """Perform comprehensive network analysis on IP address"""
        analysis = NetworkAnalysis(
            ip_address=ip_address,
            is_private=is_private_ip(ip_address),
            ip_version=get_ip_version(ip_address) or 4
        )
        
        try:
            # Reverse DNS lookup
            try:
                import socket
                analysis.hostname = socket.gethostbyaddr(ip_address)[0]
            except (socket.herror, OSError):
                analysis.hostname = None
            
            # Geolocation lookup
            analysis = self._add_geolocation_info(analysis)
            
            # Blacklist checks
            analysis.blacklist_status = self._check_blacklists(ip_address)
            
            # Threat detection
            analysis.threat_types = self._detect_threats(analysis)
            
            # Additional analysis
            analysis.is_hosting = self._check_hosting_provider(analysis)
            analysis.is_mobile = self._check_mobile_indicators(analysis)
            analysis.is_vpn = self._check_vpn_indicators(analysis)
            analysis.is_tor = self._check_tor_indicators(analysis)
            analysis.is_proxy = self._check_proxy_indicators(analysis)
            
            # Port scanning (basic)
            analysis.ports_open = self._scan_common_ports(ip_address)
            
            logger.debug(f"Completed network analysis for {ip_address}")
            
        except Exception as e:
            logger.error(f"Network analysis failed for {ip_address}: {e}")
        
        return analysis
    
    def _check_blacklists(self, ip_address: str) -> Dict[str, bool]:
        """Check IP against DNS blacklists using platform-aware DNS resolver"""
        results = {}
        
        # Use DNS manager if available (platform-aware)
        if self.dns_manager and self.dns_manager.is_available():
            blacklist_services = self.dns_manager.get_blacklist_services()
            
            for service_name, blacklist_host in blacklist_services.items():
                try:
                    is_listed = self.dns_manager.check_blacklist(ip_address, blacklist_host)
                    results[service_name] = is_listed
                    
                    if is_listed:
                        logger.debug(f"IP {ip_address} listed in {service_name} ({blacklist_host})")
                        
                except Exception as e:
                    logger.debug(f"Blacklist check failed for {service_name}: {e}")
                    results[service_name] = False
        
        # Fallback to direct DNS resolution if DNS manager unavailable
        elif HAS_DNSPYTHON:
            logger.debug("Using fallback DNS blacklist checking")
            
            # Reverse IP for DNS blacklist queries
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                if ip_obj.version == 4:
                    reversed_ip = '.'.join(reversed(ip_address.split('.')))
                else:
                    return results  # IPv6 not supported in fallback
            except ValueError:
                return results
            
            for service_name, blacklist_host in self.fallback_blacklist_services.items():
                try:
                    query_host = f"{reversed_ip}.{blacklist_host}"
                    dns.resolver.resolve(query_host, 'A')
                    results[service_name] = True  # Listed in blacklist
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    results[service_name] = False  # Not listed
                except Exception as e:
                    logger.debug(f"Fallback blacklist check failed for {service_name}: {e}")
                    results[service_name] = False
        
        else:
            logger.debug("DNS blacklist checking not available (no dnspython)")
        
        return results
    
    def _add_geolocation_info(self, analysis: NetworkAnalysis) -> NetworkAnalysis:
        """Add geolocation information to analysis"""
        try:
            geo_data = self._lookup_geolocation_api(analysis.ip_address)
            if geo_data:
                analysis.country = geo_data.get('country')
                analysis.country_code = geo_data.get('country_code')
                analysis.region = geo_data.get('region')
                analysis.city = geo_data.get('city')
                analysis.timezone = geo_data.get('timezone')
                analysis.isp = geo_data.get('isp')
                analysis.organization = geo_data.get('org')
                analysis.asn = self._extract_asn(geo_data.get('as', ''))
                analysis.latitude = geo_data.get('lat')
                analysis.longitude = geo_data.get('lon')
        except Exception as e:
            logger.debug(f"Geolocation lookup failed: {e}")
        
        return analysis
    
    def _extract_asn(self, as_info: str) -> Optional[int]:
        """Extract ASN number from AS info string"""
        if not as_info:
            return None
        
        # AS info format: "AS15169 Google LLC"
        parts = as_info.split()
        if parts and parts[0].startswith('AS'):
            try:
                return int(parts[0][2:])  # Remove 'AS' prefix
            except ValueError:
                pass
        return None
    
    def _detect_threats(self, analysis: NetworkAnalysis) -> List[str]:
        """Detect potential threats based on analysis data"""
        threats = []
        
        # Check for hosting providers (potential proxy hosting)
        if analysis.is_hosting:
            threats.append('hosting_provider')
        
        # Check for VPN/Proxy indicators
        if analysis.is_vpn:
            threats.append('vpn_detected')
        
        if analysis.is_tor:
            threats.append('tor_exit_node')
        
        if analysis.is_proxy:
            threats.append('proxy_detected')
        
        # Check blacklist status
        if any(analysis.blacklist_status.values()):
            threats.append('blacklisted')
        
        # Check for suspicious hostnames
        if analysis.hostname:
            suspicious_patterns = [
                r'proxy', r'vpn', r'tor', r'anonymizer', 
                r'bot', r'crawler', r'scanner', r'malware'
            ]
            hostname_lower = analysis.hostname.lower()
            for pattern in suspicious_patterns:
                if re.search(pattern, hostname_lower):
                    threats.append(f'suspicious_hostname_{pattern}')
        
        return threats
    
    def _check_hosting_provider(self, analysis: NetworkAnalysis) -> bool:
        """Check if IP belongs to a hosting provider"""
        if not analysis.organization:
            return False
        
        hosting_indicators = [
            'hosting', 'cloud', 'server', 'datacenter', 'digital ocean',
            'amazon', 'google cloud', 'microsoft', 'linode', 'vultr'
        ]
        
        org_lower = analysis.organization.lower()
        return any(indicator in org_lower for indicator in hosting_indicators)
    
    def _check_mobile_indicators(self, analysis: NetworkAnalysis) -> bool:
        """Check for mobile network indicators"""
        if not analysis.organization and not analysis.isp:
            return False
        
        mobile_indicators = [
            'mobile', 'cellular', 'wireless', 'telecom', 'gsm', 'lte', '4g', '5g',
            'verizon', 't-mobile', 'att', 'at&t', 'sprint', 'vodafone', 'orange',
            'telefonica', 'china mobile', 'china unicom', 'docomo', 'softbank'
        ]
        
        text_to_check = ' '.join(filter(None, [
            analysis.organization or '',
            analysis.isp or ''
        ])).lower()
        
        return any(indicator in text_to_check for indicator in mobile_indicators)
    
    def _check_vpn_indicators(self, analysis: NetworkAnalysis) -> bool:
        """Check for VPN service indicators"""
        if not analysis.organization and not analysis.hostname:
            return False
        
        vpn_indicators = [
            'vpn', 'virtual private', 'nordvpn', 'expressvpn',
            'surfshark', 'cyberghost', 'privateinternetaccess'
        ]
        
        text_to_check = ' '.join(filter(None, [
            analysis.organization or '',
            analysis.hostname or '',
            analysis.isp or ''
        ])).lower()
        
        return any(indicator in text_to_check for indicator in vpn_indicators)
    
    def _check_tor_indicators(self, analysis: NetworkAnalysis) -> bool:
        """Check for Tor exit node indicators"""
        if not analysis.hostname:
            return False
        
        tor_indicators = ['tor-exit', 'exit.torproject', 'tor.dan.me.uk']
        hostname_lower = analysis.hostname.lower()
        
        return any(indicator in hostname_lower for indicator in tor_indicators)
    
    def _check_proxy_indicators(self, analysis: NetworkAnalysis) -> bool:
        """Check for proxy service indicators"""
        if not analysis.hostname and not analysis.organization:
            return False
        
        proxy_indicators = [
            'proxy', 'anonymizer', 'hide', 'mask',
            'anonymous', 'residential', 'rotating'
        ]
        
        text_to_check = ' '.join(filter(None, [
            analysis.organization or '',
            analysis.hostname or ''
        ])).lower()
        
        return any(indicator in text_to_check for indicator in proxy_indicators)
    
    def _scan_common_ports(self, ip_address: str, timeout: float = 1.0) -> List[int]:
        """Scan common ports for basic service detection"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1080, 3128, 8080, 8888]
        open_ports = []
        
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((ip_address, port))
                    if result == 0:
                        open_ports.append(port)
            except Exception:
                continue
        
        return open_ports
    
    def _lookup_geolocation_api(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Fallback geolocation lookup using public API"""
        if not HAS_REQUESTS:
            return None
            
        try:
            # Use ip-api.com (free, no API key required)
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}",
                timeout=5,
                headers={'User-Agent': 'ProxyHunter/1.0'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country_code': data.get('countryCode'),
                        'country': data.get('country'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon')
                    }
                    
        except Exception as e:
            logger.debug(f"API geolocation lookup failed for {ip_address}: {e}")
            
        return None


# ===============================================================================
# CONSTANTS AND CONFIGURATION
# ===============================================================================

# Default timeout values
DEFAULT_TIMEOUT = 10
DEFAULT_CONNECT_TIMEOUT = 5
DEFAULT_READ_TIMEOUT = 10

# Common proxy ports by protocol
COMMON_PROXY_PORTS = {
    ProxyProtocol.HTTP: [80, 8080, 3128, 8000, 8888],
    ProxyProtocol.HTTPS: [443, 8443],
    ProxyProtocol.SOCKS4: [1080, 1081],
    ProxyProtocol.SOCKS5: [1080, 1081, 1085]
}

# Blacklist check configuration
BLACKLIST_CHECK_TIMEOUT = 5
MAX_BLACKLIST_CHECKS = 5

# Performance thresholds (using constants from constants.py)
EXCELLENT_RESPONSE_TIME = 1.0  # seconds
GOOD_RESPONSE_TIME = 3.0  # seconds
POOR_RESPONSE_TIME = 10.0  # seconds

logger.info("Proxy core utils module loaded successfully")