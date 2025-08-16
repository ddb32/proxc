# 🌐 ProxC - Advanced Proxy Discovery & Validation Tool

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-3.1.0-green.svg)](https://github.com/neo/proxc)

ProxC is a professional-grade command-line tool for discovering, validating, and managing proxy servers. Built for security researchers, network administrators, and developers who need reliable proxy intelligence.

## ✨ Features

- **🔍 Multi-Source Discovery**: Aggregate proxies from 40+ online sources
- **⚡ High-Performance Validation**: Concurrent validation with adaptive threading
- **🎯 Smart Filtering**: Advanced filtering by speed, location, protocol, and more
- **🔗 Chain Detection**: Identify and analyze proxy chains for security assessment
- **🌍 Geolocation Analysis**: IP geolocation with threat intelligence integration
- **📊 Multiple Export Formats**: JSON, CSV, TXT with custom formatting
- **🗄️ Database Integration**: SQLite storage with advanced querying
- **🌐 Web Dashboard**: Real-time monitoring with WebSocket updates
- **🔒 Security Features**: Anti-detection, fingerprinting, and anonymity assessment
- **🚀 Advanced Discovery**: Active scanning, OSINT collection, repository mining

## 🚀 Quick Start

### Installation

```bash
# Install from source
git clone https://github.com/neo/proxc.git
cd proxc
pip install -e .

# Or install dependencies manually
pip install -r requirements.txt
```

### Basic Usage

```bash
# Discover and validate proxies
proxc -s -v -o proxies.txt

# Validate existing proxy list
proxc -f input.txt -v -o validated.txt

# Quick filtering for fast proxies
proxc -f input.txt -F "alive,speed:500" -o fast.txt

# Launch web dashboard
proxc -s -v -w
```

## 📖 Usage Examples

### Discovery & Validation

```bash
# Basic proxy discovery
proxc --scan --output proxies.txt

# Advanced discovery with intelligence gathering
proxc -s -Y active -e aggressive --ai -H YOUR_GITHUB_TOKEN -o advanced.txt

# Discovery with specific count and threading
proxc -s -c 500 -t 50 -v -o discovered.txt
```

### Validation & Testing

```bash
# Validate with custom timeout and threading
proxc -f proxies.txt -v -T 15 -t 30 -o validated.txt

# Test against specific targets
proxc -f proxies.txt -v -y "https://httpbin.org,https://google.com" -o tested.txt

# Chain detection and security analysis
proxc -f proxies.txt -v -d -E 3 -J 10 -o secure.txt
```

### Filtering & Analysis

```bash
# Geographic filtering
proxc -f proxies.txt -a -F "country:US,speed:1000" -o us_fast.txt

# ISP and protocol filtering
proxc -f proxies.txt -i "CloudFlare" -M force:http -o cloudflare_http.txt

# Advanced filtering with multiple criteria
proxc -f proxies.txt -F "alive,speed:500,country:US,protocol:http" -o filtered.txt
```

### Database Operations

```bash
# Enable database mode
proxc -s -v -D -B proxies.db

# Export from database with filtering
proxc -X filtered_export.json -F "speed:1000" -D -B proxies.db

# Import proxies to database
proxc -I new_proxies.csv -D -B proxies.db
```

### Advanced Features

```bash
# Web interface with custom port
proxc -s -v -w --web-port 8080

# Rate-limited scanning
proxc -s -r 2.5 -c 200 -o rate_limited.txt

# Cache optimization
proxc -f large_list.txt -v -K -Z 7200 -m 1024 -o cached_results.txt
```

## 🛠️ Configuration

### Command Line Options

| Short | Long | Description |
|-------|------|-------------|
| `-s` | `--scan` | Discover proxies from online sources |
| `-f` | `--file` | Input file of proxies |
| `-v` | `--validate` | Validate proxy connectivity |
| `-o` | `--output` | Output file (auto-detects format) |
| `-w` | `--view` | Launch web dashboard |
| `-D` | `--use-db` | Enable database mode |
| `-a` | `--analyze` | Perform geolocation analysis |
| `-d` | `--detect-chains` | Enable chain detection |
| `-F` | `--filter` | Apply advanced filtering |
| `-t` | `--threads` | Concurrent connections (default: 10) |
| `-T` | `--timeout` | Request timeout in seconds |
| `-V` | `--verbose` | Detailed output |
| `-q` | `--quiet` | Minimal output |

### Discovery Modes

- **Passive** (`-Y passive`): Use existing proxy sources
- **Active** (`-Y active`): IP/port scanning + sources  
- **Hybrid** (`-Y hybrid`): Combined approach

### Filtering Options

```bash
# Speed filtering (response time in ms)
-F "speed:500"

# Geographic filtering
-F "country:US,city:New York"

# Protocol filtering  
-F "protocol:http,protocol:socks5"

# Anonymity filtering
-F "anonymity:elite,anonymity:anonymous"

# Combined filtering
-F "alive,speed:1000,country:US,protocol:http"
```

### Configuration File

Create `config.yaml` for persistent settings:

```yaml
# Default scanning settings
scan:
  sources: ["freeproxy_world", "hidemy_name", "proxyscrape"]
  threads: 20
  timeout: 10
  
# Validation settings
validation:
  test_url: "https://httpbin.org/ip"
  max_retries: 3
  verify_ssl: true

# Output settings
output:
  format: "json"
  include_metadata: true
  
# Database settings
database:
  path: "proxies.db"
  auto_cleanup: true
```

Load with: `proxc -G config.yaml`

## 🏗️ Architecture

ProxC is built with a modular architecture:

- **`proxy_core/`**: Core models, database, and utilities
- **`proxy_engine/`**: Fetching, validation, and analysis engines
- **`proxy_cli/`**: Command-line interface and web dashboard
- **`discovery/`**: Active scanning and intelligence gathering
- **`security/`**: Anti-detection and security features

## 🔧 Development

### Requirements

- Python 3.8+
- Dependencies: `click`, `requests`, `sqlalchemy`, `beautifulsoup4`
- Optional: `aiohttp`, `rich`, `redis` for advanced features

### Optional Dependencies

```bash
# Full feature set
pip install aiohttp rich redis geoip2 openpyxl

# Development tools
pip install pytest black flake8 mypy
```

### API Usage

```python
from proxc import ProxyFetcher, BatchValidator, ProxyAnalyzer

# Fetch proxies
fetcher = ProxyFetcher()
proxies = fetcher.fetch_from_sources(['freeproxy_world'])

# Validate proxies
validator = BatchValidator(max_workers=20)
valid_proxies = validator.validate_batch(proxies)

# Analyze proxies
analyzer = ProxyAnalyzer()
analysis = analyzer.analyze_batch(valid_proxies)
```

## 📊 Performance

ProxC is optimized for high performance:

- **Concurrent Processing**: Up to 100 concurrent connections
- **Adaptive Threading**: Automatic thread pool optimization
- **Smart Caching**: Validation result caching with TTL
- **Memory Efficiency**: Streaming processing for large datasets
- **Rate Limiting**: Configurable request rate limiting

## 🛡️ Security Features

- **Chain Detection**: Identify proxy chains and relays
- **Fingerprinting**: Advanced proxy signature detection
- **Anti-Detection**: Rotate user agents and headers
- **Threat Intelligence**: IP reputation and geolocation analysis
- **Anonymity Assessment**: Evaluate proxy anonymity levels

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Run tests: `pytest`
5. Submit a pull request

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/neo/proxc/issues)
- **Documentation**: [Wiki](https://github.com/neo/proxc/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/neo/proxc/discussions)

## 🎯 Roadmap

- [ ] GraphQL API
- [ ] Docker containerization  
- [ ] Kubernetes deployment
- [ ] Machine learning proxy quality prediction
- [ ] Browser extension
- [ ] Mobile app

---

**⚡ ProxC - Professional proxy intelligence made simple.**