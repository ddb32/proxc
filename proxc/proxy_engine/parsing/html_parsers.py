"""HTML Parsers - HTML and web content proxy parsing"""

import logging
import re
from typing import List, Optional
from urllib.parse import urljoin, urlparse

try:
    from bs4 import BeautifulSoup, NavigableString
    HAS_BEAUTIFULSOUP = True
except ImportError:
    HAS_BEAUTIFULSOUP = False

from ...proxy_core.models import ProxyInfo, ProxyProtocol
from ...proxy_core.utils import validate_ip_address, validate_port
from .pattern_library import HTML_TABLE_PATTERNS, PROXY_PATTERNS
from .text_parsers import ParseResult, TextProxyParser


class HTMLProxyParser:
    """Parser for HTML content containing proxy lists"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.text_parser = TextProxyParser()
    
    def parse_html(self, html_content: str, base_url: str = "") -> ParseResult:
        """Parse proxies from HTML content"""
        result = ParseResult()
        
        if not html_content or not html_content.strip():
            result.errors.append("Empty HTML content")
            return result
        
        try:
            if HAS_BEAUTIFULSOUP:
                result = self._parse_with_beautifulsoup(html_content, base_url)
            else:
                result = self._parse_with_regex(html_content)
            
            result.metadata = {
                'format': 'html',
                'base_url': base_url,
                'parser_used': 'beautifulsoup' if HAS_BEAUTIFULSOUP else 'regex',
                'content_length': len(html_content)
            }
            
            self.logger.info(f"Parsed {result.valid_proxies} valid proxies from HTML")
            
        except Exception as e:
            error_msg = f"HTML parsing failed: {e}"
            result.errors.append(error_msg)
            self.logger.error(error_msg)
        
        return result
    
    def _parse_with_beautifulsoup(self, html_content: str, base_url: str) -> ParseResult:
        """Parse HTML using BeautifulSoup"""
        result = ParseResult()
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Try to find proxy tables first
        tables = soup.find_all('table')
        
        for table in tables:
            table_result = self._parse_table(table)
            if table_result.proxies:
                result.proxies.extend(table_result.proxies)
                result.valid_proxies += table_result.valid_proxies
                result.invalid_proxies += table_result.invalid_proxies
        
        # If no tables found or no proxies in tables, try text extraction
        if not result.proxies:
            # Extract all text and parse
            text_content = soup.get_text()
            text_result = self.text_parser.parse_text(text_content)
            result.proxies.extend(text_result.proxies)
            result.valid_proxies += text_result.valid_proxies
            result.invalid_proxies += text_result.invalid_proxies
            result.errors.extend(text_result.errors)
        
        result.total_found = result.valid_proxies + result.invalid_proxies
        return result
    
    def _parse_with_regex(self, html_content: str) -> ParseResult:
        """Parse HTML using regex patterns"""
        result = ParseResult()
        
        try:
            # Try to extract table content first
            table_matches = re.findall(HTML_TABLE_PATTERNS['table_row'], html_content, re.IGNORECASE | re.DOTALL)
            
            for row_html in table_matches:
                cells = re.findall(HTML_TABLE_PATTERNS['table_cell'], row_html, re.IGNORECASE | re.DOTALL)
                
                if len(cells) >= 2:
                    # Try to extract IP and port from cells
                    ip_text = self._clean_html_text(cells[0])
                    port_text = self._clean_html_text(cells[1])
                    
                    if validate_ip_address(ip_text) and port_text.isdigit():
                        port = int(port_text)
                        if validate_port(port):
                            # Determine protocol from other cells if available
                            protocol = ProxyProtocol.HTTP
                            if len(cells) > 2:
                                protocol_text = self._clean_html_text(cells[2]).lower()
                                if 'socks5' in protocol_text:
                                    protocol = ProxyProtocol.SOCKS5
                                elif 'socks4' in protocol_text:
                                    protocol = ProxyProtocol.SOCKS4
                                elif 'https' in protocol_text:
                                    protocol = ProxyProtocol.HTTPS
                            
                            proxy = ProxyInfo(
                                host=ip_text,
                                port=port,
                                protocol=protocol
                            )
                            result.proxies.append(proxy)
                            result.valid_proxies += 1
            
            # If no table parsing worked, fall back to text parsing
            if not result.proxies:
                # Remove HTML tags and parse as text
                clean_text = re.sub(r'<[^>]+>', '', html_content)
                text_result = self.text_parser.parse_text(clean_text)
                result.proxies.extend(text_result.proxies)
                result.valid_proxies += text_result.valid_proxies
                result.invalid_proxies += text_result.invalid_proxies
            
            result.total_found = result.valid_proxies + result.invalid_proxies
            
        except Exception as e:
            result.errors.append(f"Regex HTML parsing failed: {e}")
        
        return result
    
    def _parse_table(self, table) -> ParseResult:
        """Parse a specific table element"""
        result = ParseResult()
        
        if not HAS_BEAUTIFULSOUP:
            return result
        
        rows = table.find_all('tr')
        
        # Skip header row if present
        start_row = 1 if rows and self._is_header_row(rows[0]) else 0
        
        for row in rows[start_row:]:
            cells = row.find_all(['td', 'th'])
            
            if len(cells) >= 2:
                try:
                    # Extract IP and port
                    ip_text = self._clean_html_text(cells[0].get_text())
                    port_text = self._clean_html_text(cells[1].get_text())
                    
                    if not validate_ip_address(ip_text):
                        continue
                    
                    if not port_text.isdigit():
                        continue
                    
                    port = int(port_text)
                    if not validate_port(port):
                        continue
                    
                    # Try to determine protocol from additional cells
                    protocol = ProxyProtocol.HTTP
                    if len(cells) > 2:
                        protocol_text = self._clean_html_text(cells[2].get_text()).lower()
                        if 'socks5' in protocol_text:
                            protocol = ProxyProtocol.SOCKS5
                        elif 'socks4' in protocol_text:
                            protocol = ProxyProtocol.SOCKS4
                        elif 'https' in protocol_text:
                            protocol = ProxyProtocol.HTTPS
                    
                    proxy = ProxyInfo(
                        host=ip_text,
                        port=port,
                        protocol=protocol
                    )
                    
                    result.proxies.append(proxy)
                    result.valid_proxies += 1
                    
                except (ValueError, IndexError):
                    result.invalid_proxies += 1
                    continue
        
        result.total_found = result.valid_proxies + result.invalid_proxies
        return result
    
    def _is_header_row(self, row) -> bool:
        """Check if a row is a header row"""
        if not HAS_BEAUTIFULSOUP:
            return False
        
        # Check if row contains 'th' elements
        if row.find('th'):
            return True
        
        # Check if text content looks like headers
        text = row.get_text().lower()
        header_indicators = ['ip', 'port', 'protocol', 'country', 'type', 'proxy']
        
        return any(indicator in text for indicator in header_indicators)
    
    def _clean_html_text(self, text: str) -> str:
        """Clean HTML text content"""
        if isinstance(text, NavigableString):
            text = str(text)
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove HTML entities
        text = text.replace('&nbsp;', ' ')
        text = text.replace('&lt;', '<')
        text = text.replace('&gt;', '>')
        text = text.replace('&amp;', '&')
        
        return text.strip()


def parse_html_content(html_content: str, base_url: str = "") -> ParseResult:
    """Utility function to parse HTML content"""
    parser = HTMLProxyParser()
    return parser.parse_html(html_content, base_url)