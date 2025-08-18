# ProxC Configuration Guide

## Overview

ProxC uses a **three-file configuration system** that separates proxy sources from operational settings for better organization and ease of use.

### Configuration Files

| File | Purpose | What's Inside |
|------|---------|---------------|
| `api_sources.yaml` | API-based proxy sources | Services that require HTTP requests to APIs |
| `static_sources.yaml` | Static URL sources | Direct links to proxy lists (GitHub, text files, HTML tables) |
| `collection_config.yaml` | Global operational settings | Timeouts, rate limits, quality filters, health monitoring |

## Quick Start

### 🚀 Basic Usage

**List all available sources:**
```bash
proxc --list-sources
```

**Enable/disable a source:**
```yaml
# To disable a source, comment out the entire block:
# proxyscrape_api:
#   name: "ProxyScrape API"
#   url: "https://api.proxyscrape.com/..."
#   # ... rest of configuration

# To enable it, uncomment:
proxyscrape_api:
  name: "ProxyScrape API"
  url: "https://api.proxyscrape.com/..."
  # ... rest of configuration
```

**Check source health:**
```bash
proxc --check-sources
```

### 📁 File Locations

```
proxc/config/
├── api_sources.yaml          # API-based sources
├── static_sources.yaml       # Static URL sources
├── collection_config.yaml    # Global settings
└── README_CONFIGURATION.md   # This guide
```

## Detailed Configuration

### 1. API Sources (`api_sources.yaml`)

**Purpose:** Configure API-based proxy services that require HTTP requests with specific parameters, headers, or authentication.

#### Free API Sources
```yaml
# Enable by uncommenting the entire block
proxyscrape_api:
  name: "ProxyScrape API"
  description: "Popular free proxy API with good coverage"
  url: "https://api.proxyscrape.com/v2/?request=get&format=textplain&protocol=http"
  type: "api"
  rate_limit: 3.0              # Seconds between requests
  timeout: 30                  # Request timeout
  max_proxies: 1000           # Maximum proxies to collect
  quality_score: 7            # 1-10 scale
  enabled: true               # Can also control via commenting

# Disable by commenting the entire block
# freeproxy_world:
#   name: "FreeProxy.World API" 
#   url: "https://www.freeproxy.world/api/proxy"
#   type: "api"
#   # ... configuration
```

#### Premium API Sources
```yaml
# Premium sources require API keys - set via environment variables
# bright_data:
#   name: "Bright Data"
#   url: "https://api.brightdata.com/dca/v2/proxies"
#   type: "api"
#   auth_type: "bearer"
#   api_key: "${BRIGHTDATA_API_KEY}"    # Set in environment
#   rate_limit: 20.0
#   max_proxies: 50000
#   quality_score: 10
```

#### Authentication Types
- **Bearer Token:** `auth_type: "bearer"` + `api_key: "${API_KEY}"`
- **Basic Auth:** `auth_type: "basic"` + `username: "${USER}"` + `password: "${PASS}"`
- **API Key Header:** `auth_type: "api_key"` + `api_key: "${KEY}"`

### 2. Static Sources (`static_sources.yaml`)

**Purpose:** Configure direct links to proxy lists (GitHub raw files, text lists, HTML tables).

#### GitHub Lists
```yaml
# Multi-URL sources for redundancy
github_proxy_lists:
  name: "GitHub Proxy Collections"
  type: "multi_source"
  urls:
    - "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"
    - "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"
  proxy_pattern: '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})'
  rate_limit: 3.0
  quality_score: 6
```

#### Text Lists
```yaml
# Simple text file sources
openproxy_space:
  name: "OpenProxy.Space"
  url: "https://openproxy.space/list/http"
  type: "text_list"
  proxy_pattern: '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})'
  rate_limit: 2.0
  quality_score: 5
```

#### HTML Table Sources
```yaml
# Web scraping from HTML tables
# proxylist_plus:
#   name: "ProxyList Plus"
#   url: "https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-1"
#   type: "html_table"
#   table_selector: "table.bg"
#   row_selector: "tr"
#   column_mapping:
#     ip: 0
#     port: 1
#   rate_limit: 2.5
```

### 3. Global Settings (`collection_config.yaml`)

**Purpose:** Configure operational parameters that apply to all sources.

#### Default Settings
```yaml
defaults:
  timeout: 30                 # Default request timeout
  max_retries: 3             # Retry failed requests
  retry_delay: 60            # Seconds between retries
  user_agent_rotation: true # Rotate user agents
  verify_ssl: false          # Don't verify SSL for proxy sources
```

#### Rate Limiting
```yaml
rate_limiting:
  default_delay: 2.0         # Default seconds between requests
  jitter_range: [0.1, 0.5]   # Random delay variation
  burst_protection: true     # Prevent rapid bursts
  adaptive_delays: true      # Adjust based on response
```

#### Quality Filters
```yaml
quality_filters:
  min_success_rate: 0.3      # 30% minimum success rate
  max_response_time: 10000   # 10 second maximum response time
  exclude_private_ips: true  # Skip private IP ranges
  exclude_localhost: true    # Skip localhost addresses
```

#### Health Monitoring
```yaml
health_monitoring:
  enabled: true              # Monitor source health
  check_interval: 3600       # Check every hour
  failure_threshold: 3       # Disable after 3 failures
  recovery_threshold: 2      # Re-enable after 2 successes
  auto_disable_failed: true  # Auto-disable failing sources
```

## Common Tasks

### Adding a New Source

#### 1. API Source
Add to `api_sources.yaml`:
```yaml
my_api_source:
  name: "My API Source"
  description: "Custom API endpoint"
  url: "https://api.example.com/proxies"
  type: "api"
  rate_limit: 2.0
  timeout: 30
  max_proxies: 500
  quality_score: 5
  headers:
    X-API-Key: "${MY_API_KEY}"
```

#### 2. Static Source
Add to `static_sources.yaml`:
```yaml
my_static_source:
  name: "My Static Source"
  description: "Custom proxy list"
  url: "https://example.com/proxies.txt"
  type: "text_list"
  proxy_pattern: '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})'
  rate_limit: 2.0
  quality_score: 5
```

### Managing Sources

#### Enable/Disable Sources
**Method 1: Commenting (Recommended)**
```yaml
# Disable by commenting entire block
# source_name:
#   name: "Source Name"
#   url: "..."

# Enable by uncommenting
source_name:
  name: "Source Name"
  url: "..."
```

**Method 2: Enabled Flag**
```yaml
source_name:
  name: "Source Name"
  url: "..."
  enabled: false  # Set to true to enable
```

#### Environment Variables for Credentials
```bash
# Set environment variables for API keys
export BRIGHTDATA_API_KEY="your_key_here"
export OXYLABS_USERNAME="your_username"
export OXYLABS_PASSWORD="your_password"

# Then use in configuration
api_key: "${BRIGHTDATA_API_KEY}"
username: "${OXYLABS_USERNAME}"
password: "${OXYLABS_PASSWORD}"
```

### Troubleshooting

#### Common Issues

**1. Source Not Loading**
- Check that the source block is not commented out
- Verify `enabled: true` is set (if using enabled flag)
- Check for YAML syntax errors

**2. Authentication Errors**
- Verify environment variables are set correctly
- Check that API keys/credentials are valid
- Ensure auth_type matches the service requirements

**3. Rate Limiting Issues**
- Increase `rate_limit` value for slower requests
- Check if the source has specific rate requirements
- Monitor logs for rate limit responses

**4. No Proxies Found**
- Verify the source URL is accessible
- Check `proxy_pattern` for text sources
- Validate `table_selector` and `column_mapping` for HTML sources

#### Validation Commands
```bash
# Check configuration syntax
proxc --check-sources

# List all sources and their status
proxc --list-sources

# Test specific source
proxc --scan --source=source_name --verbose

# View detailed logs
proxc --scan --verbose --log debug
```

#### Configuration Validation
```bash
# Validate all configuration files
python -c "
from proxc.config.proxy_sources_config import load_proxy_sources
config = load_proxy_sources()
print(f'Loaded {len(config.get_enabled_sources())} enabled sources')
"
```

## Migration from Legacy Configuration

### Automatic Migration
```bash
# Migrate from old proxy_sources.yaml to new three-file structure
proxc --migrate-config

# Backup old configuration before migration
cp proxc/config/proxy_sources.yaml proxc/config/proxy_sources.yaml.backup
```

### Manual Migration Steps

1. **Backup existing configuration:**
   ```bash
   cp proxc/config/proxy_sources.yaml proxc/config/proxy_sources.yaml.backup
   ```

2. **Create new configuration files:**
   - Copy API sources to `api_sources.yaml`
   - Copy static sources to `static_sources.yaml`
   - Copy global settings to `collection_config.yaml`

3. **Test new configuration:**
   ```bash
   proxc --check-sources
   proxc --list-sources
   ```

4. **Remove old file (optional):**
   ```bash
   # Only after confirming new setup works
   rm proxc/config/proxy_sources.yaml
   ```

## Best Practices

### Security
- **Never commit API keys** to version control
- Use environment variables for all credentials
- Rotate API keys regularly
- Monitor API usage and costs

### Performance
- Set appropriate `rate_limit` values to respect source limits
- Use `max_proxies` to control collection size
- Monitor source health and disable failing sources
- Use quality scores to prioritize better sources

### Maintenance
- Regularly check source health with `--check-sources`
- Update source URLs when they change
- Remove or disable consistently failing sources
- Document any custom sources you add

### Organization
- Group related sources together in files
- Use descriptive names and descriptions
- Add comments explaining custom configurations
- Keep quality scores updated based on performance

## Advanced Configuration

### Custom Source Types
```yaml
# Multi-source with different formats
mixed_source:
  name: "Mixed Format Source"
  type: "multi_source"
  urls:
    - "https://example.com/api/proxies"     # JSON API
    - "https://example.com/proxies.txt"     # Text list
    - "https://example.com/table.html"      # HTML table
  # Parser will auto-detect format for each URL
```

### Geographic Filtering
```yaml
# Source with geographic preferences
geo_source:
  name: "Geo-Targeted Source"
  url: "https://api.example.com/proxies"
  type: "api"
  geographic_filters:
    include_countries: ["US", "GB", "DE", "CA"]
    exclude_countries: ["CN", "RU"]
```

### Custom Headers and Authentication
```yaml
# Complex authentication setup
enterprise_source:
  name: "Enterprise Source"
  url: "https://enterprise-api.example.com/proxies"
  type: "api"
  auth_type: "custom"
  headers:
    Authorization: "Bearer ${API_TOKEN}"
    X-Client-ID: "${CLIENT_ID}"
    X-Signature: "${API_SIGNATURE}"
    User-Agent: "ProxC/1.0 Enterprise"
```

## Support

### Getting Help
- Check this documentation first
- Use `proxc --help` for command reference
- Run `proxc --check-sources` for configuration validation
- Enable verbose logging with `--verbose` flag

### Reporting Issues
When reporting configuration issues, include:
- Configuration file contents (without API keys)
- Full error messages
- ProxC version: `proxc --version`
- Operating system and Python version

### Community Resources
- GitHub Issues: Report bugs and request features
- Documentation: This file and inline comments
- Examples: See working configurations in each file

---

*This documentation is part of ProxC's modular configuration system. For technical details, see the source code in `proxc/config/`.*