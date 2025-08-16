"""Pattern Library - Regex patterns and constants for proxy parsing"""

from ...proxy_core.models import ProxyProtocol, AnonymityLevel


# ===============================================================================
# PROXY DETECTION PATTERNS
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
    AnonymityLevel.ELITE: [
        r'elite', r'high.?anonymous', r'level.?1', r'anonymous.?elite'
    ],
    AnonymityLevel.ANONYMOUS: [
        r'anonymous', r'anon', r'level.?2', r'medium.?anonymous'
    ],
    AnonymityLevel.TRANSPARENT: [
        r'transparent', r'level.?3', r'low.?anonymous', r'non.?anonymous'
    ]
}

# Country code patterns
COUNTRY_PATTERNS = {
    'country_code_2': r'\b[A-Z]{2}\b',  # ISO 3166-1 alpha-2
    'country_code_3': r'\b[A-Z]{3}\b',  # ISO 3166-1 alpha-3
    'country_full': r'\b(?:United States|Germany|France|Japan|China|Russia|Brazil|India|Canada|Australia)\b'
}

# Location patterns
LOCATION_PATTERNS = {
    'coordinates': r'(-?\d+\.?\d*),\s*(-?\d+\.?\d*)',
    'city_country': r'([A-Za-z\s]+),\s*([A-Z]{2,3})',
    'timezone': r'[A-Z]{3,4}[+-]\d{1,2}',
    'isp_info': r'(?:ISP|Provider|Organization):\s*([^,\n]+)'
}

# Speed and performance patterns
PERFORMANCE_PATTERNS = {
    'response_time': r'(\d+(?:\.\d+)?)\s*(?:ms|milliseconds?)',
    'uptime': r'(\d+(?:\.\d+)?)\s*%?\s*(?:uptime|online)',
    'speed': r'(\d+(?:\.\d+)?)\s*(?:kbps|mbps|kb/s|mb/s)',
    'last_checked': r'(?:last.?checked|updated):\s*([^,\n]+)'
}

# Quality indicators
QUALITY_PATTERNS = {
    'ssl_support': [r'ssl', r'https', r'secure', r'encryption'],
    'authentication': [r'auth', r'username', r'password', r'login'],
    'google_passed': [r'google.?passed', r'google.?working'],
    'working_status': [r'working', r'online', r'active', r'available'],
    'dead_status': [r'dead', r'offline', r'inactive', r'down']
}

# Threat and security patterns
THREAT_PATTERNS = {
    'malicious_indicators': [
        r'malware', r'virus', r'trojan', r'bot', r'suspicious'
    ],
    'blacklist_indicators': [
        r'blacklist', r'banned', r'blocked', r'flagged'
    ],
    'tor_indicators': [
        r'tor', r'onion', r'darknet', r'hidden.?service'
    ]
}

# ===============================================================================
# HTML PARSING PATTERNS
# ===============================================================================

# Common HTML table patterns for proxy sites
HTML_TABLE_PATTERNS = {
    'table_row': r'<tr[^>]*>(.*?)</tr>',
    'table_cell': r'<td[^>]*>(.*?)</td>',
    'table_header': r'<th[^>]*>(.*?)</th>',
    'proxy_table': r'<table[^>]*proxy[^>]*>(.*?)</table>',
    'ip_column': r'<td[^>]*>\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*</td>',
    'port_column': r'<td[^>]*>\s*(\d{1,5})\s*</td>'
}

# Link and URL patterns
URL_PATTERNS = {
    'proxy_list_urls': r'href=["\']([^"\']*(?:proxy|socks)[^"\']*)["\']',
    'download_links': r'href=["\']([^"\']*\.(?:txt|csv|json|xml)[^"\']*)["\']',
    'api_endpoints': r'(?:api|endpoint).*?(["\']https?://[^"\']+["\'])'
}

# ===============================================================================
# TEXT CLEANING PATTERNS
# ===============================================================================

# Patterns for cleaning extracted text
CLEANING_PATTERNS = {
    'html_tags': r'<[^>]+>',
    'whitespace': r'\s+',
    'special_chars': r'[^\w\s\.\:\-]',
    'empty_lines': r'\n\s*\n',
    'comments': r'#.*?$|//.*?$|/\*.*?\*/',
    'brackets': r'[\[\](){}]'
}

# ===============================================================================
# VALIDATION PATTERNS
# ===============================================================================

# IP address validation
IP_VALIDATION_PATTERNS = {
    'ipv4': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
    'ipv6': r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$',
    'private_ipv4': r'^(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|127\.)',
    'localhost': r'^(?:127\.|::1|localhost)$'
}

# Port validation
PORT_VALIDATION_PATTERNS = {
    'valid_port': r'^(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$',
    'common_proxy_ports': r'^(?:80|8080|3128|8888|1080|9050|443|8443)$',
    'privileged_ports': r'^(?:[1-9]|[1-9]\d|[1-9]\d{2}|102[0-3])$'
}

# ===============================================================================
# FORMAT DETECTION PATTERNS
# ===============================================================================

# Patterns for detecting different file formats
FORMAT_DETECTION_PATTERNS = {
    'json_format': r'^\s*[\[\{]',
    'csv_format': r'^[^,\n]*(?:,[^,\n]*)+$',
    'xml_format': r'^\s*<\?xml|^\s*<[a-zA-Z]',
    'ini_format': r'^\s*\[[^\]]+\]',
    'yaml_format': r'^\s*[a-zA-Z_]+\s*:',
    'plain_text': r'^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s*$'
}

# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def get_pattern_for_protocol(protocol: ProxyProtocol) -> str:
    """Get regex pattern for specific protocol"""
    if protocol == ProxyProtocol.HTTP:
        return PROXY_PATTERNS['http_proxy']
    elif protocol == ProxyProtocol.HTTPS:
        return PROXY_PATTERNS['http_proxy'].replace('http', 'https')
    elif protocol == ProxyProtocol.SOCKS4:
        return PROXY_PATTERNS['socks_proxy'].replace('socks[45]?', 'socks4')
    elif protocol == ProxyProtocol.SOCKS5:
        return PROXY_PATTERNS['socks_proxy'].replace('socks[45]?', 'socks5')
    else:
        return PROXY_PATTERNS['ip_port']


def get_combined_proxy_pattern() -> str:
    """Get combined pattern that matches all proxy formats"""
    patterns = [
        PROXY_PATTERNS['http_proxy'],
        PROXY_PATTERNS['socks_proxy'], 
        PROXY_PATTERNS['proxy_with_auth'],
        PROXY_PATTERNS['domain_proxy'],
        PROXY_PATTERNS['ip_port']
    ]
    return '|'.join(f'({pattern})' for pattern in patterns)


def get_quality_indicators() -> dict:
    """Get all quality indicator patterns"""
    return {
        'positive': QUALITY_PATTERNS['ssl_support'] + QUALITY_PATTERNS['working_status'],
        'negative': QUALITY_PATTERNS['dead_status'],
        'security': QUALITY_PATTERNS['ssl_support'] + QUALITY_PATTERNS['authentication']
    }