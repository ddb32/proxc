"""Proxy Engine Parsers - Advanced Proxy Detection and Extraction"""

import json
import logging
import re
import time
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple, Union, Iterator
from urllib.parse import urlparse, unquote

# HTML and XML parsing libraries
try:
    from bs4 import BeautifulSoup, NavigableString
    HAS_BEAUTIFULSOUP = True
except ImportError:
    HAS_BEAUTIFULSOUP = False

try:
    import lxml
    HAS_LXML = True
except ImportError:
    HAS_LXML = False

try:
    from pyquery import PyQuery as pq
    HAS_PYQUERY = True
except ImportError:
    HAS_PYQUERY = False

# Text processing libraries
try:
    import difflib
    HAS_DIFFLIB = True
except ImportError:
    HAS_DIFFLIB = False

try:
    import chardet
    HAS_CHARDET = True
except ImportError:
    HAS_CHARDET = False

# Import our core modules - using exact names from existing files
from ..proxy_core.models import (
    ProxyInfo, ProxyProtocol, AnonymityLevel, ThreatLevel,
    OperationalGrade, SecurityLevel, ValidationError, GeoLocation
)
from ..proxy_core.config import ConfigManager
from ..proxy_core.utils import CombatValidator, validate_ip_address, validate_port

# Configure logging
logger = logging.getLogger(__name__)


# ===============================================================================
# CONSTANTS AND PATTERN LIBRARIES
# ===============================================================================

# Advanced regex patterns for proxy detection
PROXY_PATTERNS = {
    # Standard IP:PORT patterns - using only the precise pattern to avoid duplicates
    "ip_port": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d{1,5}\b',
    
    # Advanced patterns with protocols - more specific to avoid conflicts
    "http_proxy": r'https?://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d{1,5}',
    "socks_proxy": r'socks[45]?://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d{1,5}',
    
    # With authentication
    "proxy_with_auth": r'(?:https?|socks[45]?)://[^:]+:[^@]+@(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d{1,5}',
    
    # Domain-based proxies
    "domain_proxy": r'(?:https?|socks[45]?)://[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*:\d{1,5}',
    
    # Obfuscated patterns
    "encoded_proxy": r'[0-9]{1,3}[.,][0-9]{1,3}[.,][0-9]{1,3}[.,][0-9]{1,3}[:][0-9]{1,5}',
    "hex_encoded": r'0x[0-9a-fA-F]{8}:[0-9]{1,5}',
    
    # Common separators and formats
    "pipe_separated": r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s*\|\s*\d{1,5}',
    "tab_separated": r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s+\d{1,5}',
    "comma_separated": r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s*,\s*\d{1,5}',
    
    # Advanced context patterns
    "proxy_list_context": r'(?:proxy|server|endpoint|gateway).*?(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d{1,5}',
    "config_format": r'(?:host|server|proxy)[\s=:]+(?:[0-9]{1,3}\.){3}[0-9]{1,3}.*?(?:port[\s=:]+)?(\d{1,5})'
}

# Protocol detection patterns
PROTOCOL_PATTERNS = {
    ProxyProtocol.HTTP: [r'http://', r'\bhttp\b', r'port.*80\b'],
    ProxyProtocol.HTTPS: [r'https://', r'\bhttps\b', r'ssl', r'port.*443\b'],
    ProxyProtocol.SOCKS4: [r'socks4://', r'\bsocks4\b', r'port.*1080\b'],
    ProxyProtocol.SOCKS5: [r'socks5://', r'\bsocks5\b', r'socks']
}

# Anonymity level detection patterns
ANONYMITY_PATTERNS = {
    AnonymityLevel.ELITE: [r'elite', r'high.*anonymous', r'level.*3'],
    AnonymityLevel.ANONYMOUS: [r'anonymous', r'medium', r'level.*2'],
    AnonymityLevel.TRANSPARENT: [r'transparent', r'low', r'level.*1']
}

# Context clues for proxy list detection
PROXY_LIST_INDICATORS = [
    'proxy', 'proxies', 'server', 'servers', 'endpoint', 'endpoints',
    'gateway', 'gateways', 'socks', 'http', 'https', 'tunnel', 'tunnels'
]


# ===============================================================================
# PARSING RESULT CLASSES
# ===============================================================================

class ParseMethod(Enum):
    """Methods used for parsing proxies"""
    REGEX = "regex"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    XML = "xml"
    PLAIN_TEXT = "plain_text"


@dataclass
class ParseResult:
    """Result of proxy parsing operation"""
    proxies: List[ProxyInfo] = field(default_factory=list)
    method_used: Optional[ParseMethod] = None
    success: bool = True
    error_message: Optional[str] = None
    parsed_count: int = 0
    duplicate_count: int = 0
    invalid_count: int = 0
    source_url: Optional[str] = None
    parsed_at: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        self.parsed_count = len(self.proxies)


@dataclass
class ProxyCandidate:
    """Candidate proxy found during parsing"""
    host: str
    port: int
    protocol: Optional[ProxyProtocol] = None
    username: Optional[str] = None
    password: Optional[str] = None
    anonymity_level: Optional[AnonymityLevel] = None
    country: Optional[str] = None
    context: Optional[str] = None  # Surrounding text for context analysis
    confidence: float = 1.0
    found_by: Optional[str] = None  # Which pattern found this candidate


# ===============================================================================
# MAIN PARSER CLASSES
# ===============================================================================

class SmartProxyParser:
    """Intelligent proxy parser with multiple parsing strategies"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.validator = CombatValidator()
        self.logger = logging.getLogger(__name__)
        
        # Compilation of regex patterns for performance
        self.compiled_patterns = {}
        for name, pattern in PROXY_PATTERNS.items():
            try:
                self.compiled_patterns[name] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                self.logger.warning(f"Failed to compile pattern {name}: {e}")
        
        # Statistics
        self.parsing_stats = {
            'total_parsed': 0,
            'successful_extractions': 0,
            'methods_used': Counter()
        }
    
    def parse_content(self, content: str, source_url: Optional[str] = None,
                     content_type: Optional[str] = None) -> ParseResult:
        """Parse content using the best available method"""
        start_time = time.time()
        
        try:
            # Detect encoding if needed
            if isinstance(content, bytes):
                content = self._decode_content(content)
            
            # Auto-detect content type if not provided
            if not content_type:
                content_type = self._detect_content_type(content, source_url)
            
            # Choose parsing method based on content type
            result = self._parse_by_content_type(content, content_type, source_url)
            
            # Post-process results
            result = self._post_process_results(result)
            
            # Update statistics
            self.parsing_stats['total_parsed'] += 1
            if result.success:
                self.parsing_stats['successful_extractions'] += 1
                if result.method_used:
                    self.parsing_stats['methods_used'][result.method_used.value] += 1
            
            parse_time = time.time() - start_time
            
            return result
            
        except Exception as e:
            self.logger.error(f"Parsing failed: {e}")
            return ParseResult(
                success=False,
                error_message=str(e),
                source_url=source_url
            )
    
    def _decode_content(self, content: bytes) -> str:
        """Decode content with encoding detection"""
        if HAS_CHARDET:
            detected = chardet.detect(content)
            encoding = detected.get('encoding', 'utf-8')
            confidence = detected.get('confidence', 0.0)
            
            if confidence > 0.7:
                try:
                    return content.decode(encoding)
                except UnicodeDecodeError:
                    pass
        
        # Fallback to common encodings
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                return content.decode(encoding)
            except UnicodeDecodeError:
                continue
        
        # Last resort
        return content.decode('utf-8', errors='ignore')
    
    def _detect_content_type(self, content: str, source_url: Optional[str] = None) -> str:
        """Auto-detect content type"""
        content_lower = content.lower().strip()
        
        # Check URL extension
        if source_url:
            url_lower = source_url.lower()
            if url_lower.endswith('.json'):
                return 'application/json'
            elif url_lower.endswith(('.csv', '.txt')):
                return 'text/csv'
            elif url_lower.endswith(('.xml', '.rss')):
                return 'application/xml'
        
        # Check content patterns
        if content_lower.startswith('{') or content_lower.startswith('['):
            return 'application/json'
        
        if '<html' in content_lower or '<body' in content_lower:
            return 'text/html'
        
        if '<?xml' in content_lower or '<rss' in content_lower:
            return 'application/xml'
        
        if ',' in content and '\n' in content:
            # Possible CSV
            lines = content.split('\n')[:5]  # Check first 5 lines
            csv_like = all(',' in line for line in lines if line.strip())
            if csv_like:
                return 'text/csv'
        
        return 'text/plain'
    
    def _parse_by_content_type(self, content: str, content_type: str, 
                              source_url: Optional[str] = None) -> ParseResult:
        """Parse content based on detected content type"""
        
        if content_type == 'application/json':
            return self._parse_json(content, source_url)
        elif content_type == 'text/html':
            return self._parse_html(content, source_url)
        elif content_type == 'application/xml':
            return self._parse_xml(content, source_url)
        elif content_type == 'text/csv':
            return self._parse_csv(content, source_url)
        else:
            return self._parse_plain_text(content, source_url)
    
    def _parse_json(self, content: str, source_url: Optional[str] = None) -> ParseResult:
        """Parse JSON formatted proxy data"""
        try:
            data = json.loads(content)
            candidates = []
            
            # Handle different JSON structures
            if isinstance(data, list):
                candidates.extend(self._extract_from_json_list(data))
            elif isinstance(data, dict):
                candidates.extend(self._extract_from_json_dict(data))
            
            proxies = [self._candidate_to_proxy(c) for c in candidates if self._validate_candidate(c)]
            
            return ParseResult(
                proxies=proxies,
                method_used=ParseMethod.JSON,
                source_url=source_url
            )
            
        except json.JSONDecodeError as e:
            self.logger.warning(f"JSON parsing failed: {e}")
            # Fallback to regex parsing
            return self._parse_plain_text(content, source_url)
    
    def _parse_html(self, content: str, source_url: Optional[str] = None) -> ParseResult:
        """Parse HTML content for proxy lists"""
        candidates = []
        
        if HAS_BEAUTIFULSOUP:
            try:
                soup = BeautifulSoup(content, 'html.parser')
                
                # Extract from tables (most common)
                candidates.extend(self._extract_from_tables(soup))
                
                # Extract from pre-formatted text
                candidates.extend(self._extract_from_pre_tags(soup))
                
                # Extract from divs and spans with proxy-like content
                candidates.extend(self._extract_from_text_elements(soup))
                
            except Exception as e:
                self.logger.warning(f"BeautifulSoup parsing failed: {e}")
        
        # Fallback to regex if no BS4 or if it failed
        if not candidates:
            regex_result = self._parse_plain_text(content, source_url)
            candidates.extend([self._proxy_to_candidate(p) for p in regex_result.proxies])
        
        proxies = [self._candidate_to_proxy(c) for c in candidates if self._validate_candidate(c)]
        
        return ParseResult(
            proxies=proxies,
            method_used=ParseMethod.HTML,
            source_url=source_url
        )
    
    def _parse_csv(self, content: str, source_url: Optional[str] = None) -> ParseResult:
        """Parse CSV formatted proxy data"""
        candidates = []
        lines = content.strip().split('\n')
        
        # Try to detect CSV structure
        headers = []
        if lines:
            first_line = lines[0]
            if ',' in first_line and not re.search(r'\d+\.\d+\.\d+\.\d+', first_line):
                # First line looks like headers
                headers = [h.strip().lower() for h in first_line.split(',')]
                lines = lines[1:]
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
            
            try:
                if headers:
                    candidate = self._parse_csv_with_headers(line, headers)
                else:
                    candidate = self._parse_csv_without_headers(line)
                
                if candidate:
                    candidate.found_by = f"csv_line_{line_num}"
                    candidates.append(candidate)
                    
            except Exception as e:
                self.logger.debug(f"Failed to parse CSV line {line_num}: {e}")
        
        proxies = [self._candidate_to_proxy(c) for c in candidates if self._validate_candidate(c)]
        
        return ParseResult(
            proxies=proxies,
            method_used=ParseMethod.CSV,
            source_url=source_url
        )
    
    def _parse_plain_text(self, content: str, source_url: Optional[str] = None) -> ParseResult:
        """Parse plain text using regex patterns"""
        candidates = []
        
        # Define pattern priority - protocol patterns first to avoid conflicts
        pattern_priority = [
            'proxy_with_auth', 'http_proxy', 'socks_proxy', 'domain_proxy',
            'ip_port', 'encoded_proxy', 'hex_encoded', 
            'pipe_separated', 'tab_separated', 'comma_separated',
            'proxy_list_context', 'config_format'
        ]
        
        # Apply patterns in priority order
        matched_positions = set()  # Track already matched text positions
        
        for pattern_name in pattern_priority:
            if pattern_name not in self.compiled_patterns:
                continue
                
            compiled_pattern = self.compiled_patterns[pattern_name]
            try:
                for match_obj in compiled_pattern.finditer(content):
                    match = match_obj.group()
                    start, end = match_obj.span()
                    
                    # Skip if this position was already matched by a higher priority pattern
                    if any(start <= pos < end or pos <= start < pos + 10 for pos in matched_positions):
                        continue
                    
                    candidate = self._match_to_candidate(match, pattern_name, content)
                    if candidate:
                        candidates.append(candidate)
                        # Mark this text region as matched
                        for i in range(start, end):
                            matched_positions.add(i)
                            
            except Exception as e:
                self.logger.debug(f"Pattern {pattern_name} failed: {e}")
        
        # Remove duplicates while preserving order  
        unique_candidates = []
        seen = set()
        for candidate in candidates:
            key = f"{candidate.host}:{candidate.port}:{candidate.protocol.value if candidate.protocol else 'none'}"
            if key not in seen:
                seen.add(key)
                unique_candidates.append(candidate)
        
        proxies = [self._candidate_to_proxy(c) for c in unique_candidates if self._validate_candidate(c)]
        
        return ParseResult(
            proxies=proxies,
            method_used=ParseMethod.REGEX,
            source_url=source_url
        )
    
    def _parse_xml(self, content: str, source_url: Optional[str] = None) -> ParseResult:
        """Parse XML formatted proxy data"""
        candidates = []
        
        if HAS_BEAUTIFULSOUP:
            try:
                soup = BeautifulSoup(content, 'xml')
                
                # Look for common XML proxy structures
                proxy_elements = soup.find_all(['proxy', 'server', 'endpoint'])
                for element in proxy_elements:
                    candidate = self._extract_from_xml_element(element)
                    if candidate:
                        candidates.append(candidate)
                        
            except Exception as e:
                self.logger.warning(f"XML parsing failed: {e}")
        
        # Fallback to regex
        if not candidates:
            return self._parse_plain_text(content, source_url)
        
        proxies = [self._candidate_to_proxy(c) for c in candidates if self._validate_candidate(c)]
        
        return ParseResult(
            proxies=proxies,
            method_used=ParseMethod.XML,
            source_url=source_url
        )
    
    def _extract_from_json_list(self, data: List[Any]) -> List[ProxyCandidate]:
        """Extract proxy candidates from JSON list"""
        candidates = []
        
        for item in data:
            if isinstance(item, dict):
                candidate = self._extract_from_json_dict_item(item)
                if candidate:
                    candidates.append(candidate)
            elif isinstance(item, str):
                # String might contain proxy info
                regex_candidates = self._extract_with_regex(item)
                candidates.extend(regex_candidates)
        
        return candidates
    
    def _extract_from_json_dict(self, data: Dict[str, Any]) -> List[ProxyCandidate]:
        """Extract proxy candidates from JSON dictionary"""
        candidates = []
        
        # Look for proxy-like keys
        proxy_keys = ['proxies', 'servers', 'endpoints', 'data', 'results']
        
        for key, value in data.items():
            if key.lower() in proxy_keys and isinstance(value, list):
                candidates.extend(self._extract_from_json_list(value))
            elif isinstance(value, dict):
                candidate = self._extract_from_json_dict_item(value)
                if candidate:
                    candidates.append(candidate)
        
        return candidates
    
    def _extract_from_json_dict_item(self, item: Dict[str, Any]) -> Optional[ProxyCandidate]:
        """Extract proxy candidate from JSON dictionary item"""
        # Common key mappings
        host_keys = ['host', 'ip', 'address', 'server', 'endpoint']
        port_keys = ['port', 'port_number']
        protocol_keys = ['protocol', 'type', 'scheme']
        
        host = None
        port = None
        protocol = None
        
        # Find host
        for key in host_keys:
            if key in item:
                host = str(item[key])
                break
        
        # Find port
        for key in port_keys:
            if key in item:
                try:
                    port = int(item[key])
                    break
                except (ValueError, TypeError):
                    continue
        
        # Find protocol
        for key in protocol_keys:
            if key in item:
                protocol_str = str(item[key]).lower()
                for proto in ProxyProtocol:
                    if proto.value in protocol_str:
                        protocol = proto
                        break
                break
        
        if host and port:
            return ProxyCandidate(
                host=host,
                port=port,
                protocol=protocol,
                username=item.get('username'),
                password=item.get('password'),
                country=item.get('country'),
                found_by="json_extraction"
            )
        
        return None
    
    def _extract_from_tables(self, soup: BeautifulSoup) -> List[ProxyCandidate]:
        """Extract proxies from HTML tables"""
        candidates = []
        
        tables = soup.find_all('table')
        for table in tables:
            rows = table.find_all('tr')
            
            # Skip tables with too few rows
            if len(rows) < 2:
                continue
            
            # Try to identify column structure
            header_row = rows[0]
            headers = [th.get_text().strip().lower() for th in header_row.find_all(['th', 'td'])]
            
            # Look for proxy-related headers
            ip_col = self._find_column_index(headers, ['ip', 'host', 'address', 'server'])
            port_col = self._find_column_index(headers, ['port'])
            protocol_col = self._find_column_index(headers, ['protocol', 'type'])
            country_col = self._find_column_index(headers, ['country', 'location'])
            
            # Parse data rows
            for row in rows[1:]:
                cells = row.find_all(['td', 'th'])
                if len(cells) < 2:
                    continue
                
                candidate = self._extract_from_table_row(cells, ip_col, port_col, protocol_col, country_col)
                if candidate:
                    candidates.append(candidate)
        
        return candidates
    
    def _extract_from_table_row(self, cells: List, ip_col: Optional[int], 
                               port_col: Optional[int], protocol_col: Optional[int],
                               country_col: Optional[int]) -> Optional[ProxyCandidate]:
        """Extract proxy candidate from table row"""
        try:
            # Get IP
            if ip_col is not None and ip_col < len(cells):
                host = cells[ip_col].get_text().strip()
            else:
                # Search for IP in all cells
                host = None
                for cell in cells:
                    text = cell.get_text().strip()
                    if validate_ip_address(text):
                        host = text
                        break
                
                if not host:
                    return None
            
            # Get port
            if port_col is not None and port_col < len(cells):
                port_text = cells[port_col].get_text().strip()
                try:
                    port = int(port_text)
                except ValueError:
                    return None
            else:
                # Search for port in all cells
                port = None
                for cell in cells:
                    text = cell.get_text().strip()
                    if text.isdigit() and validate_port(text):
                        port = int(text)
                        break
                
                if not port:
                    return None
            
            # Get protocol
            protocol = None
            if protocol_col is not None and protocol_col < len(cells):
                protocol_text = cells[protocol_col].get_text().strip().lower()
                for proto in ProxyProtocol:
                    if proto.value in protocol_text:
                        protocol = proto
                        break
            
            # Get country
            country = None
            if country_col is not None and country_col < len(cells):
                country = cells[country_col].get_text().strip()
            
            return ProxyCandidate(
                host=host,
                port=port,
                protocol=protocol,
                country=country,
                found_by="html_table"
            )
            
        except Exception as e:
            logger.debug(f"Failed to extract from table row: {e}")
            return None
    
    def _find_column_index(self, headers: List[str], keywords: List[str]) -> Optional[int]:
        """Find column index by keywords"""
        for i, header in enumerate(headers):
            for keyword in keywords:
                if keyword in header:
                    return i
        return None
    
    def _extract_from_pre_tags(self, soup: BeautifulSoup) -> List[ProxyCandidate]:
        """Extract proxies from <pre> tags"""
        candidates = []
        
        pre_tags = soup.find_all('pre')
        for pre in pre_tags:
            text = pre.get_text()
            regex_candidates = self._extract_with_regex(text)
            candidates.extend(regex_candidates)
        
        return candidates
    
    def _extract_from_text_elements(self, soup: BeautifulSoup) -> List[ProxyCandidate]:
        """Extract proxies from various text elements"""
        candidates = []
        
        # Look in divs and spans that might contain proxy lists
        for tag in soup.find_all(['div', 'span', 'p', 'code']):
            text = tag.get_text()
            if any(indicator in text.lower() for indicator in PROXY_LIST_INDICATORS):
                regex_candidates = self._extract_with_regex(text)
                candidates.extend(regex_candidates)
        
        return candidates
    
    def _extract_with_regex(self, text: str) -> List[ProxyCandidate]:
        """Extract proxy candidates using regex patterns"""
        candidates = []
        
        for pattern_name, compiled_pattern in self.compiled_patterns.items():
            try:
                matches = compiled_pattern.findall(text)
                for match in matches:
                    candidate = self._match_to_candidate(match, pattern_name, text)
                    if candidate:
                        candidates.append(candidate)
            except Exception as e:
                logger.debug(f"Regex pattern {pattern_name} failed: {e}")
        
        return candidates
    
    def _match_to_candidate(self, match: str, pattern_name: str, context: str) -> Optional[ProxyCandidate]:
        """Convert regex match to proxy candidate"""
        try:
            # Clean the match
            match = match.strip()
            
            # Handle different pattern types
            if pattern_name == 'ip_port':
                return self._parse_ip_port_match(match, pattern_name, context)
            elif pattern_name in ['http_proxy', 'socks_proxy']:
                return self._parse_protocol_match(match, pattern_name, context)
            elif pattern_name == 'proxy_with_auth':
                return self._parse_auth_match(match, pattern_name, context)
            else:
                return self._parse_generic_match(match, pattern_name, context)
                
        except Exception as e:
            logger.debug(f"Failed to process match '{match}': {e}")
            return None
    
    def _parse_ip_port_match(self, match: str, pattern_name: str, context: str) -> Optional[ProxyCandidate]:
        """Parse IP:PORT format match"""
        if ':' not in match:
            return None
        
        parts = match.split(':')
        if len(parts) != 2:
            return None
        
        host, port_str = parts
        
        if not validate_ip_address(host):
            return None
        
        try:
            port = int(port_str)
            if not validate_port(port):
                return None
        except ValueError:
            return None
        
        # Try to detect protocol from context
        protocol = self._detect_protocol_from_context(context, port)
        
        return ProxyCandidate(
            host=host,
            port=port,
            protocol=protocol,
            context=context[:100],  # First 100 chars for context
            found_by=pattern_name
        )
    
    def _parse_protocol_match(self, match: str, pattern_name: str, context: str) -> Optional[ProxyCandidate]:
        """Parse protocol://host:port format match"""
        try:
            parsed = urlparse(match)
            
            if not parsed.hostname or not parsed.port:
                return None
            
            # Map scheme to protocol
            protocol_map = {
                'http': ProxyProtocol.HTTP,
                'https': ProxyProtocol.HTTPS,
                'socks4': ProxyProtocol.SOCKS4,
                'socks5': ProxyProtocol.SOCKS5
            }
            
            protocol = protocol_map.get(parsed.scheme.lower())
            
            return ProxyCandidate(
                host=parsed.hostname,
                port=parsed.port,
                protocol=protocol,
                username=parsed.username,
                password=parsed.password,
                context=context[:100],
                found_by=pattern_name
            )
            
        except Exception:
            return None
    
    def _parse_auth_match(self, match: str, pattern_name: str, context: str) -> Optional[ProxyCandidate]:
        """Parse proxy with authentication"""
        try:
            parsed = urlparse(match)
            
            if not parsed.hostname or not parsed.port:
                return None
            
            protocol_map = {
                'http': ProxyProtocol.HTTP,
                'https': ProxyProtocol.HTTPS,
                'socks4': ProxyProtocol.SOCKS4,
                'socks5': ProxyProtocol.SOCKS5
            }
            
            protocol = protocol_map.get(parsed.scheme.lower())
            
            return ProxyCandidate(
                host=parsed.hostname,
                port=parsed.port,
                protocol=protocol,
                username=parsed.username,
                password=parsed.password,
                context=context[:100],
                found_by=pattern_name
            )
            
        except Exception:
            return None
    
    def _parse_generic_match(self, match: str, pattern_name: str, context: str) -> Optional[ProxyCandidate]:
        """Parse generic proxy match"""
        # Try to extract IP and port from the match
        ip_pattern = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
        port_pattern = re.compile(r'\d{1,5}')
        
        ip_match = ip_pattern.search(match)
        port_matches = port_pattern.findall(match)
        
        if not ip_match or not port_matches:
            return None
        
        host = ip_match.group()
        
        # Find valid port
        port = None
        for port_str in port_matches:
            if validate_port(port_str):
                port = int(port_str)
                break
        
        if not port:
            return None
        
        protocol = self._detect_protocol_from_context(context, port)
        
        return ProxyCandidate(
            host=host,
            port=port,
            protocol=protocol,
            context=context[:100],
            found_by=pattern_name
        )
    
    def _parse_csv_with_headers(self, line: str, headers: List[str]) -> Optional[ProxyCandidate]:
        """Parse CSV line with known headers"""
        parts = [p.strip() for p in line.split(',')]
        
        if len(parts) != len(headers):
            return None
        
        data = dict(zip(headers, parts))
        
        # Find required fields
        host = None
        port = None
        
        for key, value in data.items():
            if key in ['ip', 'host', 'address', 'server'] and validate_ip_address(value):
                host = value
            elif key in ['port'] and validate_port(value):
                port = int(value)
        
        if not host or not port:
            return None
        
        # Extract optional fields
        protocol = None
        country = data.get('country')
        username = data.get('username') or data.get('user')
        password = data.get('password') or data.get('pass')
        
        # Detect protocol
        protocol_str = data.get('protocol') or data.get('type', '').lower()
        for proto in ProxyProtocol:
            if proto.value in protocol_str:
                protocol = proto
                break
        
        return ProxyCandidate(
            host=host,
            port=port,
            protocol=protocol,
            username=username,
            password=password,
            country=country,
            found_by="csv_headers"
        )
    
    def _parse_csv_without_headers(self, line: str) -> Optional[ProxyCandidate]:
        """Parse CSV line without headers"""
        parts = [p.strip() for p in line.split(',')]
        
        if len(parts) < 2:
            return None
        
        # Try different combinations
        host = None
        port = None
        
        for part in parts:
            if validate_ip_address(part):
                host = part
            elif part.isdigit() and validate_port(part):
                port = int(part)
        
        if host and port:
            return ProxyCandidate(
                host=host,
                port=port,
                found_by="csv_noheaders"
            )
        
        return None
    
    def _extract_from_xml_element(self, element) -> Optional[ProxyCandidate]:
        """Extract proxy from XML element"""
        try:
            # Look for common XML structures
            host = None
            port = None
            protocol = None
            
            # Try different attribute/tag names
            for attr in ['host', 'ip', 'address']:
                if element.get(attr):
                    host = element.get(attr)
                    break
                elif element.find(attr):
                    host = element.find(attr).get_text()
                    break
            
            for attr in ['port']:
                if element.get(attr):
                    try:
                        port = int(element.get(attr))
                        break
                    except ValueError:
                        pass
                elif element.find(attr):
                    try:
                        port = int(element.find(attr).get_text())
                        break
                    except ValueError:
                        pass
            
            if host and port:
                return ProxyCandidate(
                    host=host,
                    port=port,
                    protocol=protocol,
                    found_by="xml_extraction"
                )
                
        except Exception as e:
            logger.debug(f"XML element extraction failed: {e}")
        
        return None
    
    def _detect_protocol_from_context(self, context: str, port: int) -> Optional[ProxyProtocol]:
        """Detect protocol from context and port"""
        context_lower = context.lower()
        
        # Check explicit protocol mentions
        for protocol, patterns in PROTOCOL_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, context_lower):
                    return protocol
        
        # Guess by port
        if port == 80:
            return ProxyProtocol.HTTP
        elif port == 443:
            return ProxyProtocol.HTTPS
        elif port == 1080:
            return ProxyProtocol.SOCKS5
        elif port in [3128, 8080, 8888]:
            return ProxyProtocol.HTTP
        
        # Default to HTTP for common proxy ports
        return ProxyProtocol.HTTP
    
    def _validate_candidate(self, candidate: ProxyCandidate) -> bool:
        """Validate proxy candidate"""
        if not validate_ip_address(candidate.host):
            return False
        
        if not validate_port(candidate.port):
            return False
        
        # Additional validation rules can be added here
        return True
    
    def _candidate_to_proxy(self, candidate: ProxyCandidate) -> ProxyInfo:
        """Convert candidate to ProxyInfo"""
        return ProxyInfo(
            host=candidate.host,
            port=candidate.port,
            protocol=candidate.protocol or ProxyProtocol.HTTP,
            username=candidate.username,
            password=candidate.password,
            anonymity_level=candidate.anonymity_level or AnonymityLevel.TRANSPARENT,
            operational_grade=OperationalGrade.BASIC,
            geo_location=GeoLocation(
                country=candidate.country or 'Unknown',
                region=None,
                city=None,
                latitude=0.0,
                longitude=0.0
            ) if candidate.country else None
        )
    
    def _proxy_to_candidate(self, proxy: ProxyInfo) -> ProxyCandidate:
        """Convert ProxyInfo to candidate"""
        return ProxyCandidate(
            host=proxy.host,
            port=proxy.port,
            protocol=proxy.protocol,
            username=proxy.username,
            password=proxy.password,
            anonymity_level=proxy.anonymity_level,
            country=proxy.geo_location.country if proxy.geo_location else None
        )
    
    def _post_process_results(self, result: ParseResult) -> ParseResult:
        """Post-process parsing results"""
        if not result.success:
            return result
        
        # Remove duplicates
        unique_proxies = []
        seen = set()
        
        for proxy in result.proxies:
            key = f"{proxy.host}:{proxy.port}:{proxy.protocol.value}"
            if key not in seen:
                seen.add(key)
                unique_proxies.append(proxy)
            else:
                result.duplicate_count += 1
        
        # Validate proxies
        valid_proxies = []
        for proxy in unique_proxies:
            if validate_ip_address(proxy.host) and validate_port(proxy.port):
                valid_proxies.append(proxy)
            else:
                result.invalid_count += 1
        
        result.proxies = valid_proxies
        result.parsed_count = len(valid_proxies)
        
        return result
    
    def parse_proxy_string(self, proxy_string: str) -> Optional[ProxyInfo]:
        """Parse a single proxy string in protocol://IP:PORT format"""
        try:
            proxy_string = proxy_string.strip()
            
            # Remove comments from the line (everything after #)
            if '#' in proxy_string:
                proxy_string = proxy_string.split('#')[0].strip()
            
            # Clean up timing/anonymity data after the port (e.g., "999ms elite")
            if '://' in proxy_string:
                # Split on whitespace and take only the URL part
                url_parts = proxy_string.split()
                if url_parts:
                    proxy_string = url_parts[0]
            
            # Handle protocol://IP:PORT format
            if '://' in proxy_string:
                parsed_url = urlparse(proxy_string)
                
                # Extract protocol
                protocol_str = parsed_url.scheme.lower()
                if protocol_str not in ['http', 'https', 'socks4', 'socks5']:
                    self.logger.warning(f"Unsupported protocol: {protocol_str}")
                    return None
                
                try:
                    protocol = ProxyProtocol(protocol_str)
                except ValueError:
                    self.logger.warning(f"Invalid protocol: {protocol_str}")
                    return None
                
                # Extract host and port
                host = parsed_url.hostname
                port = parsed_url.port
                
                if not host:
                    self.logger.warning(f"No host found in: {proxy_string}")
                    return None
                
                if not port:
                    # Use default ports for protocols
                    default_ports = {
                        'http': 80,
                        'https': 443,
                        'socks4': 1080,
                        'socks5': 1080
                    }
                    port = default_ports.get(protocol_str, 80)
                
                # Extract authentication if present
                username = parsed_url.username
                password = parsed_url.password
                
                # Validate IP and port
                if not validate_ip_address(host) or not validate_port(port):
                    self.logger.warning(f"Invalid IP or port in: {proxy_string}")
                    return None
                
                return ProxyInfo(
                    host=host,
                    port=port,
                    protocol=protocol,
                    username=username,
                    password=password,
                    anonymity_level=AnonymityLevel.TRANSPARENT,
                    operational_grade=OperationalGrade.BASIC
                )
            else:
                # Handle plain IP:PORT format (fallback to existing parser)
                extracted = extract_proxies_from_text(proxy_string)
                return extracted[0] if extracted else None
                
        except Exception as e:
            self.logger.warning(f"Failed to parse proxy string '{proxy_string}': {e}")
            return None
    
    def get_parsing_stats(self) -> Dict[str, Any]:
        """Get parsing statistics"""
        return dict(self.parsing_stats)


# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def create_parser(config: Optional[ConfigManager] = None) -> SmartProxyParser:
    """Create a new smart proxy parser"""
    return SmartProxyParser(config)


def parse_proxy_list(content: str, source_url: Optional[str] = None) -> ParseResult:
    """Quick utility function to parse proxy list"""
    parser = create_parser()
    return parser.parse_content(content, source_url)


def extract_proxies_from_text(text: str, default_protocol: Optional[str] = None) -> List[ProxyInfo]:
    """Extract proxies from plain text with optional default protocol"""
    parser = create_parser()
    result = parser.parse_content(text)
    
    # Apply default protocol if specified and proxy doesn't have a protocol
    if default_protocol:
        try:
            default_proto = ProxyProtocol(default_protocol.lower())
            for proxy in result.proxies:
                # Only apply default if proxy was detected without explicit protocol
                if proxy.protocol == ProxyProtocol.HTTP and '://' not in text:
                    proxy.protocol = default_proto
        except ValueError:
            logger.warning(f"Invalid default protocol: {default_protocol}")
    
    return result.proxies


def validate_proxy_format(proxy_string: str) -> bool:
    """Validate if string matches any known proxy format"""
    for pattern in PROXY_PATTERNS.values():
        if re.search(pattern, proxy_string, re.IGNORECASE):
            return True
    return False


logger.info("Proxy parsers module loaded successfully")
