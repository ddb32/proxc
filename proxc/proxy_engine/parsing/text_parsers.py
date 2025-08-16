"""Text Parsers - Plain text and format-specific proxy parsing"""

import csv
import io
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Iterator, Union
from urllib.parse import urlparse, unquote

from ...proxy_core.models import (
    ProxyInfo, ProxyProtocol, AnonymityLevel, 
    ValidationError, GeoLocation
)
from ...proxy_core.utils import validate_ip_address, validate_port
from .pattern_library import (
    PROXY_PATTERNS, PROTOCOL_PATTERNS, ANONYMITY_PATTERNS,
    CLEANING_PATTERNS, FORMAT_DETECTION_PATTERNS,
    get_combined_proxy_pattern
)


@dataclass
class ParseResult:
    """Result of parsing operation"""
    proxies: List[ProxyInfo] = field(default_factory=list)
    total_found: int = 0
    valid_proxies: int = 0
    invalid_proxies: int = 0
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class TextProxyParser:
    """Parser for plain text proxy lists"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Compile regex patterns for better performance
        self._compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for name, pattern in PROXY_PATTERNS.items()
        }
        
        self._combined_pattern = re.compile(
            get_combined_proxy_pattern(), 
            re.IGNORECASE | re.MULTILINE
        )
    
    def parse_text(self, text: str, default_protocol: ProxyProtocol = ProxyProtocol.HTTP) -> ParseResult:
        """Parse proxies from plain text"""
        result = ParseResult()
        
        if not text or not text.strip():
            result.errors.append("Empty text provided")
            return result
        
        try:
            # Clean text first
            cleaned_text = self._clean_text(text)
            
            # Find all proxy matches
            matches = self._combined_pattern.findall(cleaned_text)
            result.total_found = len(matches)
            
            # Process each match
            for match_groups in matches:
                # match_groups is a tuple from the combined pattern
                for match in match_groups:
                    if match:  # Skip empty groups
                        proxy = self._parse_single_proxy(match, default_protocol)
                        if proxy:
                            result.proxies.append(proxy)
                            result.valid_proxies += 1
                        else:
                            result.invalid_proxies += 1
            
            # Try fallback parsing if no matches found
            if not result.proxies:
                fallback_proxies = self._fallback_parse(cleaned_text, default_protocol)
                result.proxies.extend(fallback_proxies)
                result.valid_proxies = len(fallback_proxies)
            
            result.metadata = {
                'text_length': len(text),
                'cleaned_length': len(cleaned_text),
                'default_protocol': default_protocol.value,
                'parsing_method': 'regex_combined'
            }
            
            self.logger.info(f"Parsed {result.valid_proxies} valid proxies from text")
            
        except Exception as e:
            error_msg = f"Text parsing failed: {e}"
            result.errors.append(error_msg)
            self.logger.error(error_msg)
        
        return result
    
    def _clean_text(self, text: str) -> str:
        """Clean text for better parsing"""
        # Remove HTML tags
        text = re.sub(CLEANING_PATTERNS['html_tags'], '', text)
        
        # Remove comments
        text = re.sub(CLEANING_PATTERNS['comments'], '', text, flags=re.MULTILINE)
        
        # Normalize whitespace
        text = re.sub(CLEANING_PATTERNS['whitespace'], ' ', text)
        
        # Remove empty lines
        text = re.sub(CLEANING_PATTERNS['empty_lines'], '\n', text)
        
        return text.strip()
    
    def _parse_single_proxy(self, proxy_string: str, default_protocol: ProxyProtocol) -> Optional[ProxyInfo]:
        """Parse a single proxy string"""
        try:
            proxy_string = proxy_string.strip()
            
            # Handle URL format (http://ip:port or socks5://ip:port)
            if '://' in proxy_string:
                return self._parse_url_format(proxy_string)
            
            # Handle authentication format (user:pass@ip:port)
            if '@' in proxy_string and ':' in proxy_string:
                return self._parse_auth_format(proxy_string, default_protocol)
            
            # Handle simple IP:PORT format
            if ':' in proxy_string:
                return self._parse_ip_port_format(proxy_string, default_protocol)
            
            # Handle other separators (space, comma, pipe)
            return self._parse_separated_format(proxy_string, default_protocol)
            
        except Exception as e:
            self.logger.debug(f"Failed to parse proxy '{proxy_string}': {e}")
            return None
    
    def _parse_url_format(self, url: str) -> Optional[ProxyInfo]:
        """Parse URL format proxy (protocol://ip:port)"""
        try:
            parsed = urlparse(url)
            
            # Determine protocol
            protocol_map = {
                'http': ProxyProtocol.HTTP,
                'https': ProxyProtocol.HTTPS,
                'socks4': ProxyProtocol.SOCKS4,
                'socks5': ProxyProtocol.SOCKS5
            }
            
            protocol = protocol_map.get(parsed.scheme.lower(), ProxyProtocol.HTTP)
            
            if not parsed.hostname or not parsed.port:
                return None
            
            # Validate IP and port
            if not validate_ip_address(parsed.hostname):
                return None
            
            if not validate_port(parsed.port):
                return None
            
            proxy = ProxyInfo(
                host=parsed.hostname,
                port=parsed.port,
                protocol=protocol,
                username=parsed.username,
                password=parsed.password
            )
            
            return proxy
            
        except Exception:
            return None
    
    def _parse_auth_format(self, auth_string: str, default_protocol: ProxyProtocol) -> Optional[ProxyInfo]:
        """Parse authentication format (user:pass@ip:port)"""
        try:
            # Split auth and proxy parts
            auth_part, proxy_part = auth_string.rsplit('@', 1)
            
            # Parse credentials
            username, password = auth_part.split(':', 1) if ':' in auth_part else (auth_part, None)
            
            # Parse proxy part
            if ':' not in proxy_part:
                return None
            
            host, port_str = proxy_part.rsplit(':', 1)
            port = int(port_str)
            
            # Validate
            if not validate_ip_address(host) or not validate_port(port):
                return None
            
            return ProxyInfo(
                host=host,
                port=port,
                protocol=default_protocol,
                username=username,
                password=password
            )
            
        except Exception:
            return None
    
    def _parse_ip_port_format(self, ip_port: str, default_protocol: ProxyProtocol) -> Optional[ProxyInfo]:
        """Parse simple IP:PORT format"""
        try:
            # Handle encoded formats first
            if ',' in ip_port:
                ip_port = ip_port.replace(',', '.')
            
            if ':' not in ip_port:
                return None
            
            host, port_str = ip_port.rsplit(':', 1)
            port = int(port_str)
            
            # Validate
            if not validate_ip_address(host) or not validate_port(port):
                return None
            
            return ProxyInfo(
                host=host,
                port=port,
                protocol=default_protocol
            )
            
        except Exception:
            return None
    
    def _parse_separated_format(self, proxy_string: str, default_protocol: ProxyProtocol) -> Optional[ProxyInfo]:
        """Parse formats with different separators (space, comma, pipe)"""
        try:
            # Try different separators
            separators = [' ', '\t', '|', ',', ';']
            
            for sep in separators:
                if sep in proxy_string:
                    parts = proxy_string.split(sep)
                    if len(parts) >= 2:
                        # Assume first part is IP, second is port
                        host = parts[0].strip()
                        port_str = parts[1].strip()
                        
                        try:
                            port = int(port_str)
                            if validate_ip_address(host) and validate_port(port):
                                return ProxyInfo(
                                    host=host,
                                    port=port,
                                    protocol=default_protocol
                                )
                        except ValueError:
                            continue
            
            return None
            
        except Exception:
            return None
    
    def _fallback_parse(self, text: str, default_protocol: ProxyProtocol) -> List[ProxyInfo]:
        """Fallback parsing using individual patterns"""
        proxies = []
        
        # Try each pattern individually
        for pattern_name, compiled_pattern in self._compiled_patterns.items():
            matches = compiled_pattern.findall(text)
            
            for match in matches:
                proxy = self._parse_single_proxy(match, default_protocol)
                if proxy and proxy not in proxies:
                    proxies.append(proxy)
        
        return proxies


class CSVProxyParser:
    """Parser for CSV format proxy lists"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def parse_csv(self, csv_text: str, 
                  has_header: bool = True,
                  delimiter: str = ',') -> ParseResult:
        """Parse proxies from CSV text"""
        result = ParseResult()
        
        try:
            # Create CSV reader
            csv_file = io.StringIO(csv_text)
            reader = csv.reader(csv_file, delimiter=delimiter)
            
            # Skip header if present
            if has_header:
                next(reader, None)
            
            # Process rows
            for row_num, row in enumerate(reader, 1):
                if len(row) < 2:
                    continue
                
                try:
                    # Basic parsing: assume first column is IP, second is port
                    host = row[0].strip()
                    port = int(row[1].strip())
                    
                    # Optional protocol column
                    protocol = ProxyProtocol.HTTP
                    if len(row) > 2 and row[2].strip():
                        protocol = self._parse_protocol(row[2].strip())
                    
                    # Optional auth columns
                    username = row[3].strip() if len(row) > 3 else None
                    password = row[4].strip() if len(row) > 4 else None
                    
                    # Validate
                    if not validate_ip_address(host) or not validate_port(port):
                        result.invalid_proxies += 1
                        continue
                    
                    proxy = ProxyInfo(
                        host=host,
                        port=port,
                        protocol=protocol,
                        username=username if username else None,
                        password=password if password else None
                    )
                    
                    result.proxies.append(proxy)
                    result.valid_proxies += 1
                    
                except (ValueError, IndexError) as e:
                    result.invalid_proxies += 1
                    result.errors.append(f"Row {row_num}: {e}")
            
            result.total_found = result.valid_proxies + result.invalid_proxies
            result.metadata = {
                'format': 'csv',
                'delimiter': delimiter,
                'has_header': has_header,
                'rows_processed': row_num if 'row_num' in locals() else 0
            }
            
            self.logger.info(f"Parsed {result.valid_proxies} valid proxies from CSV")
            
        except Exception as e:
            error_msg = f"CSV parsing failed: {e}"
            result.errors.append(error_msg)
            self.logger.error(error_msg)
        
        return result
    
    def _parse_protocol(self, protocol_str: str) -> ProxyProtocol:
        """Parse protocol string to ProxyProtocol enum"""
        protocol_str = protocol_str.lower().strip()
        
        if protocol_str in ['http', 'http-proxy']:
            return ProxyProtocol.HTTP
        elif protocol_str in ['https', 'https-proxy']:
            return ProxyProtocol.HTTPS
        elif protocol_str in ['socks4', 'socks4-proxy']:
            return ProxyProtocol.SOCKS4
        elif protocol_str in ['socks5', 'socks5-proxy']:
            return ProxyProtocol.SOCKS5
        else:
            return ProxyProtocol.HTTP


class JSONProxyParser:
    """Parser for JSON format proxy lists"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def parse_json(self, json_text: str) -> ParseResult:
        """Parse proxies from JSON text"""
        result = ParseResult()
        
        try:
            data = json.loads(json_text)
            
            # Handle different JSON structures
            if isinstance(data, list):
                # Array of proxy objects
                result = self._parse_json_array(data)
            elif isinstance(data, dict):
                # Object containing proxy data
                result = self._parse_json_object(data)
            else:
                result.errors.append("Invalid JSON structure")
            
            result.metadata = {
                'format': 'json',
                'data_type': type(data).__name__,
                'total_items': len(data) if isinstance(data, (list, dict)) else 0
            }
            
            self.logger.info(f"Parsed {result.valid_proxies} valid proxies from JSON")
            
        except json.JSONDecodeError as e:
            error_msg = f"JSON parsing failed: {e}"
            result.errors.append(error_msg)
            self.logger.error(error_msg)
        except Exception as e:
            error_msg = f"JSON processing failed: {e}"
            result.errors.append(error_msg)
            self.logger.error(error_msg)
        
        return result
    
    def _parse_json_array(self, data: list) -> ParseResult:
        """Parse JSON array of proxies"""
        result = ParseResult()
        
        for item in data:
            if isinstance(item, dict):
                proxy = self._parse_json_proxy_object(item)
                if proxy:
                    result.proxies.append(proxy)
                    result.valid_proxies += 1
                else:
                    result.invalid_proxies += 1
            elif isinstance(item, str):
                # String format like "ip:port"
                text_parser = TextProxyParser()
                text_result = text_parser.parse_text(item)
                result.proxies.extend(text_result.proxies)
                result.valid_proxies += text_result.valid_proxies
                result.invalid_proxies += text_result.invalid_proxies
        
        result.total_found = result.valid_proxies + result.invalid_proxies
        return result
    
    def _parse_json_object(self, data: dict) -> ParseResult:
        """Parse JSON object containing proxy data"""
        result = ParseResult()
        
        # Look for common keys that might contain proxy lists
        proxy_keys = ['proxies', 'proxy_list', 'servers', 'data', 'items']
        
        for key in proxy_keys:
            if key in data and isinstance(data[key], list):
                sub_result = self._parse_json_array(data[key])
                result.proxies.extend(sub_result.proxies)
                result.valid_proxies += sub_result.valid_proxies
                result.invalid_proxies += sub_result.invalid_proxies
                break
        else:
            # Try to parse the object itself as a single proxy
            proxy = self._parse_json_proxy_object(data)
            if proxy:
                result.proxies.append(proxy)
                result.valid_proxies = 1
            else:
                result.invalid_proxies = 1
        
        result.total_found = result.valid_proxies + result.invalid_proxies
        return result
    
    def _parse_json_proxy_object(self, obj: dict) -> Optional[ProxyInfo]:
        """Parse a single JSON proxy object"""
        try:
            # Common field mappings
            host_keys = ['host', 'ip', 'address', 'server']
            port_keys = ['port', 'port_number']
            protocol_keys = ['protocol', 'type', 'scheme']
            username_keys = ['username', 'user', 'login']
            password_keys = ['password', 'pass', 'pwd']
            
            # Extract fields
            host = None
            for key in host_keys:
                if key in obj:
                    host = str(obj[key]).strip()
                    break
            
            port = None
            for key in port_keys:
                if key in obj:
                    port = int(obj[key])
                    break
            
            protocol = ProxyProtocol.HTTP
            for key in protocol_keys:
                if key in obj:
                    protocol_str = str(obj[key]).lower().strip()
                    protocol = self._parse_protocol_json(protocol_str)
                    break
            
            username = None
            for key in username_keys:
                if key in obj and obj[key]:
                    username = str(obj[key]).strip()
                    break
            
            password = None
            for key in password_keys:
                if key in obj and obj[key]:
                    password = str(obj[key]).strip()
                    break
            
            # Validate required fields
            if not host or not port:
                return None
            
            if not validate_ip_address(host) or not validate_port(port):
                return None
            
            return ProxyInfo(
                host=host,
                port=port,
                protocol=protocol,
                username=username,
                password=password
            )
            
        except (ValueError, KeyError, TypeError):
            return None
    
    def _parse_protocol_json(self, protocol_str: str) -> ProxyProtocol:
        """Parse protocol string from JSON"""
        if protocol_str in ['http', '1']:
            return ProxyProtocol.HTTP
        elif protocol_str in ['https', '2']:
            return ProxyProtocol.HTTPS
        elif protocol_str in ['socks4', '4']:
            return ProxyProtocol.SOCKS4
        elif protocol_str in ['socks5', '5']:
            return ProxyProtocol.SOCKS5
        else:
            return ProxyProtocol.HTTP


class FormatDetector:
    """Detects the format of proxy data"""
    
    @staticmethod
    def detect_format(text: str) -> str:
        """Detect the format of the input text"""
        text = text.strip()
        
        if not text:
            return 'empty'
        
        # Check each format
        for format_name, pattern in FORMAT_DETECTION_PATTERNS.items():
            if re.match(pattern, text, re.IGNORECASE | re.MULTILINE):
                return format_name.replace('_format', '')
        
        # Default to plain text
        return 'plain_text'


# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def parse_proxy_text(text: str, default_protocol: ProxyProtocol = ProxyProtocol.HTTP) -> ParseResult:
    """Auto-detect format and parse proxy text"""
    format_type = FormatDetector.detect_format(text)
    
    if format_type == 'json':
        parser = JSONProxyParser()
        return parser.parse_json(text)
    elif format_type == 'csv':
        parser = CSVProxyParser()
        return parser.parse_csv(text)
    else:
        # Default to text parser
        parser = TextProxyParser()
        return parser.parse_text(text, default_protocol)


def parse_proxy_file(file_path: str, default_protocol: ProxyProtocol = ProxyProtocol.HTTP) -> ParseResult:
    """Parse proxy file with auto-format detection"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        result = parse_proxy_text(content, default_protocol)
        result.metadata['source_file'] = file_path
        
        return result
        
    except Exception as e:
        result = ParseResult()
        result.errors.append(f"File reading failed: {e}")
        return result