#!/usr/bin/env python3
"""
Test Data Generator - Phase 4.1.8

Comprehensive test data generation for various proxy scenarios and edge cases.
Creates realistic and diverse proxy datasets for comprehensive testing.

Generation Categories:
- Realistic proxy datasets by geographic region
- Protocol-specific proxy scenarios  
- Performance test datasets
- Edge case and malformed data
- Anonymity level test data
- Threat intelligence test data
- Historical performance data
- Configuration test scenarios
"""

import json
import random
import string
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Generator
import ipaddress
import csv

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from proxc.proxy_core.models import (
    ProxyInfo, ProxyProtocol, AnonymityLevel, ThreatLevel, 
    ProxyStatus, ValidationStatus, GeoLocation
)


class TestDataGenerator:
    """Comprehensive test data generator for proxy scenarios"""
    
    def __init__(self, seed: int = None):
        if seed is not None:
            random.seed(seed)
        
        # Geographic regions and their IP ranges
        self.geographic_regions = {
            'North America': {
                'ip_ranges': ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'],
                'countries': ['US', 'CA', 'MX'],
                'cities': ['New York', 'Los Angeles', 'Toronto', 'Mexico City'],
                'isps': ['Comcast', 'Verizon', 'Rogers', 'Telmex']
            },
            'Europe': {
                'ip_ranges': ['185.10.0.0/16', '194.50.0.0/16', '212.100.0.0/16'],
                'countries': ['GB', 'DE', 'FR', 'NL', 'ES'],
                'cities': ['London', 'Berlin', 'Paris', 'Amsterdam', 'Madrid'],
                'isps': ['BT', 'Deutsche Telekom', 'Orange', 'KPN', 'Telefonica']
            },
            'Asia': {
                'ip_ranges': ['118.200.0.0/16', '202.100.0.0/16', '210.50.0.0/16'],
                'countries': ['JP', 'CN', 'KR', 'SG', 'IN'],
                'cities': ['Tokyo', 'Shanghai', 'Seoul', 'Singapore', 'Mumbai'],
                'isps': ['NTT', 'China Telecom', 'KT', 'SingTel', 'BSNL']
            }
        }
        
        # Common proxy ports by protocol
        self.protocol_ports = {
            ProxyProtocol.HTTP: [8080, 3128, 8888, 80, 8000, 8081],
            ProxyProtocol.HTTPS: [8443, 443, 8080, 3129],
            ProxyProtocol.SOCKS4: [1080, 1081, 9050, 9051],
            ProxyProtocol.SOCKS5: [1080, 1081, 9150, 9151, 1085]
        }
        
        # Real-world proxy sources
        self.proxy_sources = [
            'free-proxy-list.net', 'proxy-list.org', 'spys.one',
            'hidemy.name', 'proxylist.geonode.com', 'free-proxy.cz',
            'proxy-daily.com', 'proxyscrape.com', 'github-proxy-list',
            'proxy-spider', 'manual-verification', 'honeypot-detection'
        ]
        
        # Threat categories for malicious proxies
        self.threat_categories = [
            'botnet', 'malware_c2', 'phishing', 'tor_exit',
            'vpn_abuse', 'spam_source', 'scanning', 'bruteforce'
        ]
    
    def generate_ip_address(self, region: str = None) -> str:
        """Generate realistic IP address"""
        if region and region in self.geographic_regions:
            ip_ranges = self.geographic_regions[region]['ip_ranges']
            selected_range = random.choice(ip_ranges)
            network = ipaddress.IPv4Network(selected_range)
            return str(random.choice(list(network.hosts())))
        else:
            # Generate from common proxy IP ranges
            ranges = [
                '192.168.0.0/16',   # Private (for testing)
                '10.0.0.0/8',       # Private (for testing)
                '172.16.0.0/12',    # Private (for testing)
                '192.0.2.0/24',     # TEST-NET-1
                '198.51.100.0/24',  # TEST-NET-2
                '203.0.113.0/24'    # TEST-NET-3
            ]
            
            selected_range = random.choice(ranges)
            network = ipaddress.IPv4Network(selected_range)
            return str(random.choice(list(network.hosts())))
    
    def generate_proxy_info(self, region: str = None, protocol: ProxyProtocol = None,
                           anonymity: AnonymityLevel = None, include_geo: bool = False,
                           include_metadata: bool = False) -> ProxyInfo:
        """Generate realistic proxy information"""
        
        # Generate IP and determine region
        if not region:
            region = random.choice(list(self.geographic_regions.keys()))
        
        ip = self.generate_ip_address(region)
        
        # Select protocol and port
        if not protocol:
            protocol = random.choice(list(ProxyProtocol))
        
        ports = self.protocol_ports.get(protocol, [8080, 3128, 1080])
        port = random.choice(ports)
        
        # Select anonymity level
        if not anonymity:
            anonymity = random.choice(list(AnonymityLevel))
        
        # Select source
        source = random.choice(self.proxy_sources)
        
        # Create base proxy
        proxy = ProxyInfo(
            host=ip,
            port=port,
            protocol=protocol,
            source=source,
            anonymity_level=anonymity
        )
        
        # Add geographic information
        if include_geo:
            region_data = self.geographic_regions[region]
            proxy.country = random.choice(region_data['countries'])
            proxy.city = random.choice(region_data['cities'])
            
            # Generate realistic coordinates
            if region == 'North America':
                proxy.latitude = random.uniform(25.0, 60.0)
                proxy.longitude = random.uniform(-150.0, -50.0)
            elif region == 'Europe':
                proxy.latitude = random.uniform(35.0, 70.0)
                proxy.longitude = random.uniform(-10.0, 40.0)
            elif region == 'Asia':
                proxy.latitude = random.uniform(0.0, 60.0)
                proxy.longitude = random.uniform(60.0, 150.0)
        
        # Add metadata
        if include_metadata:
            region_data = self.geographic_regions[region]
            proxy.isp = random.choice(region_data['isps'])
            proxy.asn = f"AS{random.randint(1000, 99999)}"
            
            # Performance characteristics
            proxy.response_time_ms = random.uniform(50, 2000)
            proxy.uptime_percentage = random.uniform(85, 99.5)
            proxy.last_checked = datetime.now() - timedelta(
                minutes=random.randint(1, 1440)
            )
            
            # Validation status
            if random.random() < 0.8:  # 80% working
                proxy.status = ProxyStatus.WORKING
                proxy.validation_status = ValidationStatus.VALID
            elif random.random() < 0.5:
                proxy.status = ProxyStatus.TIMEOUT
                proxy.validation_status = ValidationStatus.TIMEOUT
            else:
                proxy.status = ProxyStatus.FAILED
                proxy.validation_status = ValidationStatus.INVALID
        
        return proxy
    
    def generate_proxy_dataset(self, count: int, **kwargs) -> List[ProxyInfo]:
        """Generate dataset of proxy information"""
        return [self.generate_proxy_info(**kwargs) for _ in range(count)]
    
    def generate_malicious_proxies(self, count: int) -> List[ProxyInfo]:
        """Generate dataset of malicious/suspicious proxies"""
        malicious_proxies = []
        
        for _ in range(count):
            # Generate base proxy
            proxy = self.generate_proxy_info(include_geo=True, include_metadata=True)
            
            # Add threat characteristics
            proxy.threat_level = random.choice([ThreatLevel.HIGH, ThreatLevel.CRITICAL])
            proxy.threat_categories = random.sample(self.threat_categories, 
                                                   random.randint(1, 3))
            
            # Malicious proxies often have suspicious characteristics
            proxy.anonymity_level = AnonymityLevel.TRANSPARENT  # Often transparent
            proxy.response_time_ms = random.uniform(100, 5000)  # Variable performance
            proxy.uptime_percentage = random.uniform(60, 90)    # Lower uptime
            
            # Add malicious metadata
            proxy.first_seen = datetime.now() - timedelta(
                days=random.randint(1, 30)
            )
            proxy.reputation_score = random.uniform(0, 30)  # Low reputation
            
            malicious_proxies.append(proxy)
        
        return malicious_proxies
    
    def generate_high_quality_proxies(self, count: int) -> List[ProxyInfo]:
        """Generate dataset of high-quality proxies"""
        quality_proxies = []
        
        for _ in range(count):
            # Generate base proxy with good characteristics
            proxy = self.generate_proxy_info(
                protocol=random.choice([ProxyProtocol.HTTP, ProxyProtocol.HTTPS, ProxyProtocol.SOCKS5]),
                anonymity=random.choice([AnonymityLevel.ELITE, AnonymityLevel.ANONYMOUS]),
                include_geo=True,
                include_metadata=True
            )
            
            # High-quality characteristics
            proxy.threat_level = ThreatLevel.LOW
            proxy.response_time_ms = random.uniform(50, 300)   # Fast response
            proxy.uptime_percentage = random.uniform(95, 99.9) # High uptime
            proxy.status = ProxyStatus.WORKING
            proxy.validation_status = ValidationStatus.VALID
            proxy.reputation_score = random.uniform(80, 100)   # High reputation
            
            # Premium proxy sources
            premium_sources = ['premium-proxy-service', 'datacenter-proxy', 
                             'residential-proxy', 'enterprise-proxy']
            proxy.source = random.choice(premium_sources)
            
            quality_proxies.append(proxy)
        
        return quality_proxies
    
    def generate_edge_case_proxies(self) -> List[ProxyInfo]:
        """Generate edge case proxy scenarios"""
        edge_cases = []
        
        # Proxy with minimum port
        edge_cases.append(ProxyInfo(
            host="192.168.1.1",
            port=1,
            protocol=ProxyProtocol.HTTP,
            source="edge_case_min_port"
        ))
        
        # Proxy with maximum port
        edge_cases.append(ProxyInfo(
            host="192.168.1.2", 
            port=65535,
            protocol=ProxyProtocol.HTTP,
            source="edge_case_max_port"
        ))
        
        # IPv6 proxy (if supported)
        edge_cases.append(ProxyInfo(
            host="2001:db8::1",
            port=8080,
            protocol=ProxyProtocol.HTTP,
            source="edge_case_ipv6"
        ))
        
        # Proxy with very long hostname
        long_hostname = "very-long-hostname-" + "x" * 200 + ".example.com"
        edge_cases.append(ProxyInfo(
            host=long_hostname,
            port=8080,
            protocol=ProxyProtocol.HTTP,
            source="edge_case_long_hostname"
        ))
        
        # Proxy with unicode in metadata
        unicode_proxy = ProxyInfo(
            host="192.168.1.3",
            port=8080,
            protocol=ProxyProtocol.HTTP,
            source="edge_case_unicode"
        )
        unicode_proxy.city = "北京"  # Beijing in Chinese
        unicode_proxy.country = "中国"  # China in Chinese
        edge_cases.append(unicode_proxy)
        
        # Proxy with extreme response times
        slow_proxy = ProxyInfo(
            host="192.168.1.4",
            port=8080,
            protocol=ProxyProtocol.HTTP,
            source="edge_case_slow",
            response_time_ms=30000  # 30 seconds
        )
        edge_cases.append(slow_proxy)
        
        # Proxy with zero uptime
        dead_proxy = ProxyInfo(
            host="192.168.1.5",
            port=8080,
            protocol=ProxyProtocol.HTTP,
            source="edge_case_dead",
            uptime_percentage=0.0,
            status=ProxyStatus.FAILED
        )
        edge_cases.append(dead_proxy)
        
        return edge_cases
    
    def generate_performance_test_dataset(self, size_category: str) -> List[ProxyInfo]:
        """Generate datasets for performance testing"""
        
        sizes = {
            'tiny': 100,
            'small': 1000,
            'medium': 10000,
            'large': 100000,
            'huge': 1000000
        }
        
        count = sizes.get(size_category, 1000)
        
        print(f"Generating {size_category} performance dataset ({count:,} proxies)")
        
        # Generate diverse dataset
        proxies = []
        
        # 60% normal proxies
        normal_count = int(count * 0.6)
        proxies.extend(self.generate_proxy_dataset(normal_count, include_metadata=True))
        
        # 20% high-quality proxies
        quality_count = int(count * 0.2)
        proxies.extend(self.generate_high_quality_proxies(quality_count))
        
        # 15% malicious proxies
        malicious_count = int(count * 0.15)
        proxies.extend(self.generate_malicious_proxies(malicious_count))
        
        # 5% edge cases (repeated to fill remaining)
        edge_count = count - len(proxies)
        edge_cases = self.generate_edge_case_proxies()
        for _ in range(edge_count):
            proxies.append(random.choice(edge_cases))
        
        # Shuffle to mix categories
        random.shuffle(proxies)
        
        return proxies[:count]  # Ensure exact count
    
    def export_to_txt(self, proxies: List[ProxyInfo], file_path: Path):
        """Export proxies to TXT format"""
        with open(file_path, 'w') as f:
            for proxy in proxies:
                f.write(f"{proxy.host}:{proxy.port}\n")
    
    def export_to_json(self, proxies: List[ProxyInfo], file_path: Path):
        """Export proxies to JSON format"""
        data = []
        for proxy in proxies:
            proxy_dict = {
                'host': proxy.host,
                'port': proxy.port,
                'protocol': proxy.protocol.value,
                'source': proxy.source
            }
            
            # Add optional fields if present
            if hasattr(proxy, 'anonymity_level') and proxy.anonymity_level:
                proxy_dict['anonymity_level'] = proxy.anonymity_level.value
            if hasattr(proxy, 'country') and proxy.country:
                proxy_dict['country'] = proxy.country
            if hasattr(proxy, 'city') and proxy.city:
                proxy_dict['city'] = proxy.city
            if hasattr(proxy, 'response_time_ms') and proxy.response_time_ms:
                proxy_dict['response_time_ms'] = proxy.response_time_ms
            if hasattr(proxy, 'uptime_percentage') and proxy.uptime_percentage:
                proxy_dict['uptime_percentage'] = proxy.uptime_percentage
            
            data.append(proxy_dict)
        
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def export_to_csv(self, proxies: List[ProxyInfo], file_path: Path):
        """Export proxies to CSV format"""
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            headers = ['host', 'port', 'protocol', 'source', 'anonymity_level', 
                      'country', 'city', 'response_time_ms', 'uptime_percentage']
            writer.writerow(headers)
            
            # Write data
            for proxy in proxies:
                row = [
                    proxy.host,
                    proxy.port,
                    proxy.protocol.value,
                    proxy.source,
                    proxy.anonymity_level.value if hasattr(proxy, 'anonymity_level') and proxy.anonymity_level else '',
                    getattr(proxy, 'country', ''),
                    getattr(proxy, 'city', ''),
                    getattr(proxy, 'response_time_ms', ''),
                    getattr(proxy, 'uptime_percentage', '')
                ]
                writer.writerow(row)
    
    def generate_test_suite_datasets(self, output_dir: Path):
        """Generate comprehensive test datasets for the test suite"""
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"🎯 Generating comprehensive test datasets in {output_dir}")
        
        # Basic datasets
        datasets = {
            'tiny_mixed': self.generate_performance_test_dataset('tiny'),
            'small_quality': self.generate_high_quality_proxies(500),
            'medium_malicious': self.generate_malicious_proxies(1000),
            'edge_cases': self.generate_edge_case_proxies() * 10,  # Repeat edge cases
            'regional_na': self.generate_proxy_dataset(200, region='North America', include_geo=True),
            'regional_eu': self.generate_proxy_dataset(200, region='Europe', include_geo=True),
            'regional_asia': self.generate_proxy_dataset(200, region='Asia', include_geo=True),
            'protocol_http': self.generate_proxy_dataset(300, protocol=ProxyProtocol.HTTP),
            'protocol_socks5': self.generate_proxy_dataset(300, protocol=ProxyProtocol.SOCKS5),
            'anonymous_only': self.generate_proxy_dataset(200, anonymity=AnonymityLevel.ANONYMOUS),
            'elite_only': self.generate_proxy_dataset(200, anonymity=AnonymityLevel.ELITE)
        }
        
        # Export in multiple formats
        for name, proxies in datasets.items():
            print(f"  📄 Exporting {name} ({len(proxies)} proxies)")
            
            # TXT format
            self.export_to_txt(proxies, output_dir / f"{name}.txt")
            
            # JSON format
            self.export_to_json(proxies, output_dir / f"{name}.json")
            
            # CSV format
            self.export_to_csv(proxies, output_dir / f"{name}.csv")
        
        # Performance test datasets
        performance_sizes = ['small', 'medium', 'large']
        for size in performance_sizes:
            print(f"  🚀 Generating {size} performance dataset")
            perf_proxies = self.generate_performance_test_dataset(size)
            
            # Export only TXT for performance tests (faster loading)
            self.export_to_txt(perf_proxies, output_dir / f"performance_{size}.txt")
        
        # Generate configuration test files
        self._generate_config_test_files(output_dir)
        
        print(f"✅ Generated {len(datasets) + len(performance_sizes)} test datasets")
    
    def _generate_config_test_files(self, output_dir: Path):
        """Generate configuration test files"""
        
        config_dir = output_dir / "configs"
        config_dir.mkdir(exist_ok=True)
        
        # Valid configuration
        valid_config = {
            "timeout": 5.0,
            "threads": 10,
            "validation_method": "http",
            "output_format": "json",
            "log_level": "INFO"
        }
        
        with open(config_dir / "valid_config.json", 'w') as f:
            json.dump(valid_config, f, indent=2)
        
        # Invalid configuration (wrong types)
        invalid_config = {
            "timeout": "invalid",
            "threads": -1,
            "validation_method": "unknown",
            "output_format": "invalid_format"
        }
        
        with open(config_dir / "invalid_config.json", 'w') as f:
            json.dump(invalid_config, f, indent=2)
        
        # Malformed JSON configuration
        with open(config_dir / "malformed_config.json", 'w') as f:
            f.write('{"invalid": json syntax}')


# Command-line interface for test data generation
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test Data Generator for Proxy Hunter")
    parser.add_argument("--output-dir", type=str, default="test_data", 
                       help="Output directory for test datasets")
    parser.add_argument("--size", type=str, choices=['tiny', 'small', 'medium', 'large', 'huge'],
                       default='medium', help="Size of performance dataset")
    parser.add_argument("--count", type=int, help="Custom count of proxies to generate")
    parser.add_argument("--format", type=str, choices=['txt', 'json', 'csv', 'all'],
                       default='all', help="Output format")
    parser.add_argument("--seed", type=int, help="Random seed for reproducible results")
    
    args = parser.parse_args()
    
    print("🚀 Starting Test Data Generator - Phase 4.1.8")
    
    generator = TestDataGenerator(seed=args.seed)
    output_dir = Path(args.output_dir)
    
    if args.count:
        # Generate custom dataset
        print(f"Generating custom dataset ({args.count} proxies)")
        proxies = generator.generate_proxy_dataset(args.count, include_metadata=True)
        
        if args.format in ['txt', 'all']:
            generator.export_to_txt(proxies, output_dir / "custom_dataset.txt")
        if args.format in ['json', 'all']:
            generator.export_to_json(proxies, output_dir / "custom_dataset.json")
        if args.format in ['csv', 'all']:
            generator.export_to_csv(proxies, output_dir / "custom_dataset.csv")
    else:
        # Generate comprehensive test suite
        generator.generate_test_suite_datasets(output_dir)
    
    print("✅ Test data generation completed!")