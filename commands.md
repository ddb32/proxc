# ProxC Command Reference - Complete Testing Guide

This document provides a comprehensive list of all commands and flags available in ProxC for systematic end-to-end testing.

## Basic Usage

### Core Command Structure
```bash
proxc [OPTIONS] [COMMANDS]
```

---

## Input/Output Commands

### File Operations
```bash
proxc -f INPUT_FILE
```
- **Description**: Specify input file containing proxy list
- **Test**: [ ] Load proxies from a text file with IP:PORT format
- **Test**: [ ] Load proxies from JSON file with metadata
- **Test**: [ ] Handle invalid file paths gracefully

```bash
proxc -o OUTPUT_FILE, proxc --output OUTPUT_FILE
```
- **Description**: Output file (supports txt/json/csv formats with country preservation)
- **Test**: [ ] Save results to .txt format
- **Test**: [ ] Save results to .json format with metadata
- **Test**: [ ] Save results to .csv format with headers
- **Test**: [ ] Verify country information is preserved in output

---

## Validation Commands

### Basic Validation
```bash
proxc -v, proxc --validate
```
- **Description**: Validate proxy connectivity
- **Test**: [ ] Validate basic HTTP proxy connectivity
- **Test**: [ ] Validate SOCKS proxy connectivity
- **Test**: [ ] Handle connection timeouts properly

### Protocol Handling
```bash
proxc -M PROTOCOL_MODE, proxc --protocol-mode PROTOCOL_MODE
```
- **Description**: Protocol handling mode: auto, force:TYPE, detect, from-file
- **Options**: auto, force:http, force:socks4, force:socks5, detect, from-file
- **Test**: [ ] Auto-detect protocol from port/context
- **Test**: [ ] Force HTTP protocol on all proxies
- **Test**: [ ] Force SOCKS4 protocol on all proxies
- **Test**: [ ] Force SOCKS5 protocol on all proxies
- **Test**: [ ] Detect protocol via handshake
- **Test**: [ ] Read protocol from URL prefixes in file

```bash
proxc -P, proxc --protocol-strict
```
- **Description**: Strict protocol validation (fail if detection/validation fails)
- **Test**: [ ] Fail validation when protocol detection fails
- **Test**: [ ] Continue validation when strict mode is disabled

---

## Output Control

### Verbosity Levels
```bash
proxc -V, proxc --verbose
```
- **Description**: Verbose output (DEBUG level)
- **Test**: [ ] Show detailed debug information during operations

```bash
proxc -q, proxc --quiet
```
- **Description**: Quiet mode (WARNING level, minimal output)
- **Test**: [ ] Suppress informational messages, show only warnings/errors

```bash
proxc -N, proxc --silent
```
- **Description**: Silent mode (ERROR level, suppress all output except errors)
- **Test**: [ ] Show only critical errors, suppress all other output

---

## Performance Commands

### Threading and Concurrency
```bash
proxc -t THREADS, proxc --threads THREADS
```
- **Description**: Number of concurrent threads
- **Default**: 20
- **Test**: [ ] Use 1 thread (sequential processing)
- **Test**: [ ] Use 10 threads (moderate concurrency)
- **Test**: [ ] Use 50 threads (high concurrency)

```bash
proxc -T TIMEOUT, proxc --timeout TIMEOUT
```
- **Description**: Request timeout in seconds
- **Default**: 5
- **Test**: [ ] Use short timeout (2 seconds)
- **Test**: [ ] Use long timeout (30 seconds)
- **Test**: [ ] Verify timeout behavior with slow proxies

```bash
proxc -j, proxc --adaptive-threads, proxc --adaptive
```
- **Description**: Enable adaptive dynamic threading based on performance
- **Test**: [ ] Verify threads adjust based on system performance
- **Test**: [ ] Check thread scaling with large proxy lists

### Rate Limiting
```bash
proxc -r RATE, proxc --rate RATE
```
- **Description**: Limit requests per second (rate limit)
- **Test**: [ ] Set rate limit to 1 request/second
- **Test**: [ ] Set rate limit to 10 requests/second
- **Test**: [ ] Verify rate limiting is enforced

---

## Caching Commands

### Cache Configuration
```bash
proxc -K, proxc --cache-validation
```
- **Description**: Enable validation result caching for faster re-validation
- **Test**: [ ] Enable caching and verify faster subsequent runs
- **Test**: [ ] Check cache hit/miss statistics

```bash
proxc -Z CACHE_TTL, proxc --cache-ttl CACHE_TTL
```
- **Description**: Cache time-to-live in seconds (default: 3600)
- **Test**: [ ] Set short TTL (60 seconds) and verify expiration
- **Test**: [ ] Set long TTL (7200 seconds) and verify persistence

```bash
proxc -m MEMORY_MB, proxc --cache-memory-mb MEMORY_MB
```
- **Description**: Maximum cache memory usage in MB
- **Test**: [ ] Set memory limit and verify enforcement
- **Test**: [ ] Test cache behavior when memory limit is reached

```bash
proxc --cache-stats, proxc -S
```
- **Description**: Show cache performance statistics
- **Test**: [ ] Display cache hit/miss ratios
- **Test**: [ ] Show memory usage statistics

---

## Proxy Chain Detection

### Chain Analysis
```bash
proxc -d, proxc --detect-chains
```
- **Description**: Enable proxy chain detection and analysis
- **Test**: [ ] Detect single-hop proxies
- **Test**: [ ] Detect multi-hop proxy chains
- **Test**: [ ] Identify chain depth correctly

```bash
proxc -E DEPTH, proxc --chain-max-depth DEPTH
```
- **Description**: Maximum acceptable chain depth (default: 5)
- **Test**: [ ] Set max depth to 2 and verify filtering
- **Test**: [ ] Test with chains exceeding max depth

```bash
proxc -J TIMEOUT, proxc --chain-timeout TIMEOUT
```
- **Description**: Timeout for chain detection in seconds (default: 15.0)
- **Test**: [ ] Use short timeout for chain detection
- **Test**: [ ] Verify timeout behavior with slow chains

```bash
proxc -O CONFIDENCE, proxc --chain-confidence CONFIDENCE
```
- **Description**: Minimum confidence threshold for chain detection (default: 0.7)
- **Test**: [ ] Set high confidence (0.9) and verify filtering
- **Test**: [ ] Set low confidence (0.5) and check results

```bash
proxc -R SAMPLES, proxc --chain-samples SAMPLES
```
- **Description**: Number of samples for timing analysis (default: 3)
- **Test**: [ ] Use 1 sample for fast detection
- **Test**: [ ] Use 10 samples for accurate analysis

---

## Filtering and Analysis

### Proxy Filtering
```bash
proxc -F FILTER_RULES, proxc --filter FILTER_RULES
```
- **Description**: Filter proxies (e.g., alive,speed:500)
- **Test**: [ ] Filter for alive proxies only
- **Test**: [ ] Filter by response speed threshold
- **Test**: [ ] Combine multiple filter criteria

```bash
proxc -a, proxc --analyze
```
- **Description**: Perform threat analysis and geo lookup
- **Test**: [ ] Enable geo location detection
- **Test**: [ ] Perform threat analysis on proxies
- **Test**: [ ] Verify country information in results

```bash
proxc -i ISP, proxc --isp ISP
```
- **Description**: Filter by ISP
- **Test**: [ ] Filter proxies from specific ISP
- **Test**: [ ] Test with multiple ISP names

```bash
proxc -A ASN, proxc --asn ASN
```
- **Description**: Filter by ASN (Autonomous System Number)
- **Test**: [ ] Filter by specific ASN
- **Test**: [ ] Verify ASN filtering accuracy

### Count and Limits
```bash
proxc -c COUNT, proxc --count COUNT
```
- **Description**: Limit number of proxies to process
- **Test**: [ ] Process only first 10 proxies from large list
- **Test**: [ ] Verify exact count enforcement

```bash
proxc -n TARGET_ALIVE, proxc --target-alive TARGET_ALIVE
```
- **Description**: Continue scanning until N alive proxies found (overrides --count)
- **Test**: [ ] Scan until 5 alive proxies found
- **Test**: [ ] Verify scanning stops when target reached

---

## Proxy Discovery Commands

### Source Discovery
```bash
proxc -s, proxc --scan
```
- **Description**: Discover proxies from online sources
- **Test**: [ ] Discover proxies from configured sources
- **Test**: [ ] Verify discovered proxies are valid format

```bash
proxc -L, proxc --list-sources
```
- **Description**: List all available proxy sources and their status
- **Test**: [ ] Display all configured proxy sources
- **Test**: [ ] Show source status (active/inactive)

```bash
proxc -C, proxc --check-sources
```
- **Description**: Test connectivity to all proxy sources
- **Test**: [ ] Check connectivity to all sources
- **Test**: [ ] Report which sources are accessible

### Discovery Modes
```bash
proxc -Y DISCOVERY_MODE, proxc --discovery-mode DISCOVERY_MODE
```
- **Description**: Discovery mode: passive, active, hybrid
- **Options**: passive, active, hybrid
- **Test**: [ ] Use passive discovery mode
- **Test**: [ ] Use active discovery mode
- **Test**: [ ] Use hybrid discovery mode

### Advanced Discovery Features
```bash
proxc --enable-fingerprinting, proxc --fingerprint, proxc --fp
```
- **Description**: Enable advanced fingerprinting techniques
- **Test**: [ ] Enable fingerprinting and verify additional metadata

```bash
proxc --enable-intelligence, proxc --intelligence, proxc --ai
```
- **Description**: Enable AI-driven intelligence collection
- **Test**: [ ] Enable intelligence features
- **Test**: [ ] Verify enhanced proxy analysis

```bash
proxc --enable-repo-mining, proxc --repo-mining, proxc --rm
```
- **Description**: Enable GitHub repository mining for proxy discovery
- **Test**: [ ] Enable repository mining with GitHub token
- **Test**: [ ] Discover proxies from GitHub repositories

### Scanning Parameters
```bash
proxc -p IP_RANGES, proxc --ip-ranges IP_RANGES
```
- **Description**: Comma-separated IP ranges for active scanning
- **Test**: [ ] Scan specific IP range (e.g., 192.168.1.0/24)
- **Test**: [ ] Scan multiple IP ranges

```bash
proxc -k CLOUD_PROVIDERS, proxc --cloud-providers CLOUD_PROVIDERS
```
- **Description**: Cloud providers for IP scanning (aws,gcp,azure,digitalocean,ovh)
- **Test**: [ ] Scan AWS IP ranges
- **Test**: [ ] Scan multiple cloud providers

```bash
proxc -e SCAN_INTENSITY, proxc --scan-intensity SCAN_INTENSITY
```
- **Description**: Scan intensity: light, medium, aggressive
- **Options**: light, medium, aggressive
- **Test**: [ ] Use light intensity scanning
- **Test**: [ ] Use aggressive intensity scanning

### API Integration
```bash
proxc -g SEARCH_ENGINES, proxc --search-engines SEARCH_ENGINES
```
- **Description**: Search engines for intelligence (google,bing,duckduckgo)
- **Test**: [ ] Use Google search for proxy discovery
- **Test**: [ ] Use multiple search engines

```bash
proxc -H GITHUB_TOKEN, proxc --github-token GITHUB_TOKEN
```
- **Description**: GitHub API token for repository mining
- **Test**: [ ] Set GitHub token and verify repository access
- **Test**: [ ] Test without token (rate-limited access)

```bash
proxc -Q GOOGLE_API_KEY, proxc --google-api-key GOOGLE_API_KEY
```
- **Description**: Google Custom Search API key
- **Test**: [ ] Set Google API key and verify search functionality

```bash
proxc -U GOOGLE_CX, proxc --google-cx GOOGLE_CX
```
- **Description**: Google Custom Search Engine ID
- **Test**: [ ] Configure custom search engine
- **Test**: [ ] Verify search results

```bash
proxc -b BING_API_KEY, proxc --bing-api-key BING_API_KEY
```
- **Description**: Bing Web Search API key
- **Test**: [ ] Set Bing API key and verify search

### Web Scraping
```bash
proxc --enable-scrapers, proxc --scrape, proxc --sc
```
- **Description**: Enable advanced web scraping with JavaScript support
- **Test**: [ ] Enable web scraping features
- **Test**: [ ] Verify JavaScript-rendered content scraping

```bash
proxc -x SCRAPING_ENGINE, proxc --scraping-engine SCRAPING_ENGINE
```
- **Description**: Scraping engine: requests, playwright
- **Options**: requests, playwright
- **Test**: [ ] Use requests engine for scraping
- **Test**: [ ] Use Playwright engine for JavaScript support

### Discovery Limits
```bash
proxc --max-discovery-results MAX_RESULTS, proxc --max-results MAX_RESULTS
```
- **Description**: Maximum results from discovery operations (default: 1000)
- **Test**: [ ] Set max results to 100
- **Test**: [ ] Verify result limiting

```bash
proxc --discovery-timeout TIMEOUT, proxc --timeout-discovery TIMEOUT
```
- **Description**: Discovery operation timeout in seconds (default: 300)
- **Test**: [ ] Set discovery timeout to 60 seconds
- **Test**: [ ] Verify timeout enforcement

---

## Testing and Target Commands

### Custom Testing
```bash
proxc -u URL, proxc --url URL
```
- **Description**: Test proxy connectivity with custom URL (default: httpbin.org)
- **Test**: [ ] Test with custom URL
- **Test**: [ ] Test with HTTPS URL
- **Test**: [ ] Test with different protocols

```bash
proxc -z VIA_PROXY, proxc --via-proxy VIA_PROXY
```
- **Description**: Run tests through another proxy
- **Test**: [ ] Chain tests through another proxy
- **Test**: [ ] Verify proxy chaining works correctly

### Target Testing
```bash
proxc -y TARGET_URLS, proxc --target-urls TARGET_URLS
```
- **Description**: Comma-separated list of target URLs to test
- **Test**: [ ] Test multiple target URLs
- **Test**: [ ] Verify success rates per URL

```bash
proxc -W TARGET_CONFIG, proxc --target-config TARGET_CONFIG
```
- **Description**: YAML file with target test configurations
- **Test**: [ ] Load target configuration from YAML
- **Test**: [ ] Verify custom target settings

```bash
proxc --target-preset PRESET
```
- **Description**: Use predefined target configuration
- **Options**: google, social_media, streaming, e_commerce, news
- **Test**: [ ] Use Google preset for testing
- **Test**: [ ] Use social media preset
- **Test**: [ ] Use streaming services preset
- **Test**: [ ] Use e-commerce preset
- **Test**: [ ] Use news sites preset

```bash
proxc --target-success-rate RATE, proxc --success-rate RATE
```
- **Description**: Required success rate for target tests (0.0-1.0, default: 0.7)
- **Test**: [ ] Set high success rate requirement (0.9)
- **Test**: [ ] Set low success rate requirement (0.5)

```bash
proxc --target-parallel
```
- **Description**: Run target tests in parallel (default: enabled)
- **Test**: [ ] Enable parallel target testing
- **Test**: [ ] Verify performance improvement with parallelism

---

## Database Commands

### Database Operations
```bash
proxc -D, proxc --use-db
```
- **Description**: Enable database mode instead of file mode
- **Test**: [ ] Enable database mode and verify data persistence
- **Test**: [ ] Compare database vs file mode performance

```bash
proxc -B DB_PATH, proxc --db-path DB_PATH
```
- **Description**: Database file location (enables database saving)
- **Test**: [ ] Set custom database path
- **Test**: [ ] Verify database creation and data storage

```bash
proxc -X EXPORT_FILE, proxc --export-from-db EXPORT_FILE
```
- **Description**: Export filtered data from database to JSON/CSV file
- **Test**: [ ] Export database contents to JSON
- **Test**: [ ] Export database contents to CSV
- **Test**: [ ] Apply filters during export

```bash
proxc -I IMPORT_FILE, proxc --import-to-db IMPORT_FILE
```
- **Description**: Import proxies from JSON/CSV file into database
- **Test**: [ ] Import JSON file to database
- **Test**: [ ] Import CSV file to database
- **Test**: [ ] Verify data integrity after import

---

## API Export Commands

### API Configuration
```bash
proxc --api-export API_URL
```
- **Description**: Export results to API endpoint (URL)
- **Test**: [ ] Export to HTTP API endpoint
- **Test**: [ ] Export to HTTPS API endpoint
- **Test**: [ ] Handle API connection failures gracefully

```bash
proxc --api-method METHOD
```
- **Description**: HTTP method for API export
- **Options**: POST, PUT, PATCH
- **Test**: [ ] Use POST method for API export
- **Test**: [ ] Use PUT method for API export
- **Test**: [ ] Use PATCH method for API export

```bash
proxc --api-auth AUTH_TYPE
```
- **Description**: API authentication type
- **Options**: none, bearer, basic, api_key
- **Test**: [ ] No authentication
- **Test**: [ ] Bearer token authentication
- **Test**: [ ] Basic authentication
- **Test**: [ ] API key authentication

```bash
proxc --api-token TOKEN
```
- **Description**: API authentication token/key
- **Test**: [ ] Set API token and verify authentication
- **Test**: [ ] Test with invalid token

```bash
proxc --api-batch-size BATCH_SIZE
```
- **Description**: Batch size for API export (default: 100)
- **Test**: [ ] Set small batch size (10)
- **Test**: [ ] Set large batch size (500)
- **Test**: [ ] Verify batch processing

---

## Web Interface Commands

### Web UI
```bash
proxc -w, proxc --view
```
- **Description**: Launch web browser interface to view results
- **Test**: [ ] Launch web interface
- **Test**: [ ] Verify browser opens automatically
- **Test**: [ ] Check web interface functionality

```bash
proxc --web-port PORT
```
- **Description**: Custom port for web interface (default: auto-select)
- **Test**: [ ] Set custom port (8080)
- **Test**: [ ] Verify port conflict handling
- **Test**: [ ] Test auto-port selection

---

## Queue System Commands

### Redis Queue Configuration
```bash
proxc --enable-queue
```
- **Description**: Enable Redis-based task queue
- **Test**: [ ] Enable queue system with Redis
- **Test**: [ ] Verify task distribution across workers

```bash
proxc --redis-host REDIS_HOST
```
- **Description**: Redis server host (default: localhost)
- **Test**: [ ] Connect to local Redis instance
- **Test**: [ ] Connect to remote Redis server

```bash
proxc --redis-port REDIS_PORT
```
- **Description**: Redis server port (default: 6379)
- **Test**: [ ] Use default Redis port
- **Test**: [ ] Use custom Redis port

```bash
proxc --redis-db REDIS_DB
```
- **Description**: Redis database number (default: 0)
- **Test**: [ ] Use default database (0)
- **Test**: [ ] Use alternate database number

### Queue Management
```bash
proxc --queue-priority PRIORITY
```
- **Description**: Task priority: high, medium, low
- **Options**: high, medium, low
- **Test**: [ ] Set high priority tasks
- **Test**: [ ] Set low priority tasks
- **Test**: [ ] Verify priority ordering

```bash
proxc --max-retry-attempts ATTEMPTS, proxc --max-retries ATTEMPTS
```
- **Description**: Maximum retry attempts (default: 3)
- **Test**: [ ] Set retry limit to 1
- **Test**: [ ] Set retry limit to 5
- **Test**: [ ] Verify retry behavior

```bash
proxc --retry-backoff MULTIPLIER
```
- **Description**: Retry backoff multiplier (default: 2.0)
- **Test**: [ ] Set backoff multiplier to 1.5
- **Test**: [ ] Verify exponential backoff timing

```bash
proxc --queue-stats
```
- **Description**: Show queue statistics
- **Test**: [ ] Display current queue statistics
- **Test**: [ ] Show worker status information

```bash
proxc --clear-queue
```
- **Description**: Clear all queue tasks
- **Test**: [ ] Clear all pending tasks
- **Test**: [ ] Verify queue is empty after clearing

```bash
proxc --queue-worker-mode, proxc --worker-mode
```
- **Description**: Run as queue worker process
- **Test**: [ ] Start worker process
- **Test**: [ ] Verify worker processes tasks from queue

---

## Configuration Commands

### Config Management
```bash
proxc -G CONFIG_FILE, proxc --config CONFIG_FILE
```
- **Description**: Load YAML config file
- **Test**: [ ] Load configuration from YAML file
- **Test**: [ ] Verify config parameters are applied

```bash
proxc -l LOG_FILE, proxc --log LOG_FILE
```
- **Description**: Save session logs to file
- **Test**: [ ] Save logs to custom file
- **Test**: [ ] Verify log file contains session data

```bash
proxc --debug-protocol-detection
```
- **Description**: Enable detailed protocol detection debugging output
- **Test**: [ ] Enable debug output for protocol detection
- **Test**: [ ] Verify detailed debug information

### Config Validation
```bash
proxc --validate-config
```
- **Description**: Validate configuration files and settings
- **Test**: [ ] Validate current configuration
- **Test**: [ ] Detect configuration errors

```bash
proxc --check-conflicts
```
- **Description**: Check for configuration conflicts
- **Test**: [ ] Detect conflicting configuration options
- **Test**: [ ] Verify conflict resolution suggestions

```bash
proxc --config-report
```
- **Description**: Generate comprehensive configuration report
- **Test**: [ ] Generate config report
- **Test**: [ ] Verify report contains all settings

### Config Profiles
```bash
proxc --list-profiles
```
- **Description**: List available configuration profiles
- **Test**: [ ] Display available profiles
- **Test**: [ ] Show profile descriptions

```bash
proxc --profile PROFILE_NAME
```
- **Description**: Load specific configuration profile
- **Test**: [ ] Load named configuration profile
- **Test**: [ ] Verify profile settings are applied

```bash
proxc --source-status SOURCE_NAME
```
- **Description**: Check status of specific proxy source
- **Test**: [ ] Check individual source status
- **Test**: [ ] Verify source connectivity

### Config Migration
```bash
proxc --migrate-config
```
- **Description**: Migrate legacy configuration to new format
- **Test**: [ ] Migrate old configuration files
- **Test**: [ ] Verify migration preserves all settings

```bash
proxc --export-config EXPORT_TYPE
```
- **Description**: Export configuration in specified format
- **Options**: legacy, three_file
- **Test**: [ ] Export in legacy format
- **Test**: [ ] Export in three-file format

```bash
proxc --config-summary
```
- **Description**: Show concise configuration summary
- **Test**: [ ] Display configuration summary
- **Test**: [ ] Verify summary accuracy

### Source Management
```bash
proxc --sources-by-quality QUALITY_SCORE
```
- **Description**: Filter sources by quality score threshold
- **Test**: [ ] Filter high-quality sources (score > 80)
- **Test**: [ ] Filter sources by custom threshold

```bash
proxc --sources-by-type SOURCE_TYPE
```
- **Description**: Filter sources by type
- **Options**: api, static, all
- **Test**: [ ] Show only API sources
- **Test**: [ ] Show only static sources
- **Test**: [ ] Show all source types

```bash
proxc --sources-by-category CATEGORY
```
- **Description**: Filter sources by category
- **Options**: free, premium, custom
- **Test**: [ ] Show only free sources
- **Test**: [ ] Show only premium sources
- **Test**: [ ] Show custom sources

---

## Help and Information

### Help Commands
```bash
proxc -h, proxc --help
```
- **Description**: Show help message and exit
- **Test**: [ ] Display comprehensive help information
- **Test**: [ ] Verify all options are documented

---

## Example Command Combinations

### Basic Operations
```bash
# Basic scan and validate
proxc --scan --validate -o results.txt
```
- **Test**: [ ] Scan and validate proxies, save to results.txt

```bash
# File validation with custom settings
proxc -f input.txt --validate -o valid.txt -t 10 -T 10
```
- **Test**: [ ] Validate file input with 10 threads and 10-second timeout

```bash
# Fast discovery with limited results
proxc --scan --count 50 --threads 20 -o fast.txt
```
- **Test**: [ ] Quick discovery of 50 proxies with high concurrency

### Advanced Operations
```bash
# Protocol detection and validation
proxc -f mixed.txt --protocol-mode detect --validate -o detected.txt
```
- **Test**: [ ] Detect protocols automatically and validate

```bash
# Target testing with preset
proxc --scan --validate --target-preset google -o tested.txt
```
- **Test**: [ ] Test proxies against Google services

```bash
# Database mode with analysis
proxc --scan --validate -D --db-path proxies.db --analyze
```
- **Test**: [ ] Use database storage with geographical analysis

```bash
# API export with authentication
proxc --scan --api-export https://api.example.com/proxies --api-auth bearer --api-token TOKEN
```
- **Test**: [ ] Export results to API with bearer token authentication

```bash
# Chain detection with custom parameters
proxc --scan --validate --detect-chains --chain-max-depth 3 -o secure.txt
```
- **Test**: [ ] Detect proxy chains with maximum depth of 3

```bash
# Web interface launch
proxc --scan --validate --view --web-port 8080 -o results.txt
```
- **Test**: [ ] Launch web interface on port 8080 while processing

```bash
# Advanced discovery with intelligence
proxc --scan --discovery-mode active --enable-intelligence --github-token TOKEN -o advanced.txt
```
- **Test**: [ ] Use active discovery with AI-driven intelligence

### Performance Testing
```bash
# High-performance scanning
proxc --scan --validate --threads 50 --adaptive --cache-validation -o performance.txt
```
- **Test**: [ ] Maximum performance configuration with caching

```bash
# Rate-limited scanning
proxc --scan --validate --rate 5 --timeout 30 -o slow.txt
```
- **Test**: [ ] Rate-limited scanning for respectful discovery

```bash
# Queue-based processing
proxc --scan --validate --enable-queue --queue-priority high --redis-host localhost
```
- **Test**: [ ] Use Redis queue for distributed processing

---

## Testing Checklist Summary

### Core Functionality Tests
- [ ] Basic proxy validation works correctly
- [ ] File input/output operations function properly
- [ ] All output formats (txt, json, csv) generate correctly
- [ ] Protocol detection and forcing works as expected
- [ ] Threading and concurrency options perform correctly

### Advanced Feature Tests
- [ ] Proxy chain detection identifies chains accurately
- [ ] Caching improves performance on subsequent runs
- [ ] API export successfully sends data to endpoints
- [ ] Web interface launches and displays results
- [ ] Database operations store and retrieve data correctly

### Configuration Tests
- [ ] YAML configuration files load and apply correctly
- [ ] All verbosity levels produce appropriate output
- [ ] Error handling and validation work as expected
- [ ] Configuration migration and export functions properly

### Integration Tests
- [ ] Queue system distributes tasks correctly
- [ ] Discovery modes find proxies from various sources
- [ ] Target testing validates proxy functionality
- [ ] All authentication methods work with APIs
- [ ] Performance optimizations provide expected benefits

### Error Handling Tests
- [ ] Invalid inputs produce helpful error messages
- [ ] Network failures are handled gracefully
- [ ] Configuration conflicts are detected and reported
- [ ] Resource limits are respected and enforced
- [ ] Timeouts and retries work as configured

---

## Notes for Systematic Testing

1. **Test Environment Setup**: Ensure Redis, test files, and API endpoints are available
2. **Performance Monitoring**: Monitor resource usage during high-concurrency tests
3. **Network Considerations**: Test with various network conditions and proxy types
4. **Error Scenarios**: Intentionally test invalid inputs and error conditions
5. **Integration Verification**: Test combinations of features together
6. **Output Validation**: Verify output formats and data integrity
7. **Security Testing**: Test authentication and API security features

This comprehensive reference enables systematic validation of all ProxC functionality through structured testing of each command and option combination.