"""
ProxC Configuration Constants
Centralized constants to replace hardcoded values throughout the codebase
"""

# Default timeouts (in seconds)
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_READ_TIMEOUT = 20.0
DEFAULT_TOTAL_TIMEOUT = 30.0
DEFAULT_DNS_TIMEOUT = 5.0

# CLI default timeouts (standardized to seconds for user interface)
CLI_DEFAULT_TIMEOUT_SEC = 5
CLI_DEFAULT_THREADS = 50

# Validation settings
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 1.0
DEFAULT_BACKOFF_FACTOR = 1.5
DEFAULT_MAX_WORKERS = 20
MIN_WORKERS = 5
MAX_CONCURRENT_ASYNC = 100

# Common proxy ports by protocol
COMMON_HTTP_PORTS = [8080, 3128, 8118, 8888, 80, 8000, 8008]
COMMON_HTTPS_PORTS = [8443, 443, 8080, 3128]
COMMON_SOCKS4_PORTS = [1080, 1081, 9050]
COMMON_SOCKS5_PORTS = [1080, 1081, 1085, 9050, 9150]

# File format extensions
SUPPORTED_INPUT_FORMATS = {'.txt': 'txt', '.json': 'json', '.csv': 'csv', '.xlsx': 'xlsx', '.xls': 'xlsx'}
SUPPORTED_OUTPUT_FORMATS = {'.txt': 'txt', '.json': 'json', '.csv': 'csv', '.xlsx': 'xlsx'}

# Database settings
DEFAULT_DB_POOL_SIZE = 10
DEFAULT_DB_MAX_OVERFLOW = 20
DEFAULT_DB_POOL_RECYCLE = 3600  # 1 hour

# Export settings
MAX_EXPORT_BATCH_SIZE = 10000
DEFAULT_JSON_INDENT = 2

# Resource limits
MAX_VALIDATION_BATCH_SIZE = 1000
MAX_FILE_SIZE_MB = 100

# Logging configuration
DEFAULT_LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DEFAULT_LOG_LEVEL = 'INFO'

# Third-party loggers to suppress
NOISY_LOGGERS = [
    'requests.packages.urllib3.connectionpool',
    'urllib3.connectionpool', 
    'sqlalchemy.engine.base.Engine',
    'aiohttp.access'
]

# Test endpoints for proxy validation
VALIDATION_TEST_ENDPOINTS = {
    'ip_check': [
        'http://httpbin.org/ip',
        'http://api.ipify.org?format=json',
        'http://checkip.amazonaws.com',
        'http://icanhazip.com',
        'http://ifconfig.me/ip'
    ],
    'headers_check': [
        'http://httpbin.org/headers',
        'http://httpbin.org/get'
    ],
    'https_check': [
        'https://httpbin.org/ip',
        'https://api.ipify.org?format=json'
    ],
    'speed_test': [
        'http://httpbin.org/bytes/1024',  # 1KB
        'http://httpbin.org/bytes/10240'  # 10KB  
    ]
}

# IPv6 test endpoints
IPV6_TEST_ENDPOINTS = [
    'http://v6.ipv6-test.com/api/myip.php',
    'http://ipv6.icanhazip.com'
]

# User agents for testing
DEFAULT_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0'
]

# Performance thresholds (in seconds)
RESPONSE_TIME_EXCELLENT = 1.0
RESPONSE_TIME_GOOD = 3.0
RESPONSE_TIME_POOR = 10.0

# Default batch sizes for processing
DEFAULT_BATCH_SIZE = 100
MAX_BATCH_SIZE = 1000
MIN_BATCH_SIZE = 10