"""Security Utilities - Shared utilities for security analysis"""

import ipaddress
import logging
import re
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class SecurityUtils:
    """Utility functions for security analysis"""
    
    @staticmethod
    def parse_via_header(via_header: str) -> List[Dict[str, str]]:
        """Parse Via header to extract proxy chain information
        
        Via header format: Via: 1.1 proxy1.example.com, 1.0 proxy2.example.com
        """
        proxies = []
        
        if not via_header:
            return proxies
        
        # Split by comma and parse each entry
        via_entries = [entry.strip() for entry in via_header.split(',')]
        
        for entry in via_entries:
            # Parse Via entry: protocol-version proxy-name [comment]
            parts = entry.split(' ', 2)
            if len(parts) >= 2:
                protocol_version = parts[0]
                proxy_name = parts[1]
                comment = parts[2] if len(parts) > 2 else None
                
                proxy_info = {
                    'protocol_version': protocol_version,
                    'proxy_name': proxy_name,
                    'comment': comment,
                    'raw_entry': entry
                }
                proxies.append(proxy_info)
        
        return proxies
    
    @staticmethod
    def parse_x_forwarded_for(xff_header: str) -> List[str]:
        """Parse X-Forwarded-For header to extract IP chain
        
        X-Forwarded-For: client, proxy1, proxy2
        """
        if not xff_header:
            return []
        
        # Split by comma and clean up IPs
        ips = [ip.strip() for ip in xff_header.split(',')]
        
        # Validate IPs
        valid_ips = []
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                # Skip invalid IP addresses
                logger.debug(f"Invalid IP in X-Forwarded-For: {ip}")
                continue
        
        return valid_ips
    
    @staticmethod
    def extract_proxy_headers(headers: Dict[str, str]) -> Dict[str, Any]:
        """Extract all proxy-related headers and parse them"""
        proxy_headers = {}
        
        # Normalize header names to lowercase
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        
        # Via header
        if 'via' in normalized_headers:
            proxy_headers['via'] = SecurityUtils.parse_via_header(normalized_headers['via'])
            proxy_headers['via_raw'] = normalized_headers['via']
        
        # X-Forwarded-For
        if 'x-forwarded-for' in normalized_headers:
            proxy_headers['x_forwarded_for'] = SecurityUtils.parse_x_forwarded_for(
                normalized_headers['x-forwarded-for']
            )
            proxy_headers['x_forwarded_for_raw'] = normalized_headers['x-forwarded-for']
        
        # Other forwarded headers
        forwarded_header_names = [
            'x-forwarded-proto', 'x-forwarded-host', 'x-forwarded-port',
            'x-real-ip', 'x-client-ip', 'x-original-forwarded-for',
            'forwarded', 'x-cluster-client-ip'
        ]
        
        for header_name in forwarded_header_names:
            if header_name in normalized_headers:
                proxy_headers[header_name.replace('-', '_')] = normalized_headers[header_name]
        
        # Proxy-specific headers
        proxy_specific_headers = [
            'proxy-connection', 'x-proxy-connection', 'proxy-authorization'
        ]
        
        for header_name in proxy_specific_headers:
            if header_name in normalized_headers:
                proxy_headers[header_name.replace('-', '_')] = normalized_headers[header_name]
        
        return proxy_headers
    
    @staticmethod
    def calculate_chain_depth(proxy_headers: Dict[str, Any]) -> int:
        """Calculate proxy chain depth from headers"""
        max_depth = 0
        
        # Count Via header entries
        if 'via' in proxy_headers and proxy_headers['via']:
            max_depth = max(max_depth, len(proxy_headers['via']))
        
        # Count X-Forwarded-For entries
        if 'x_forwarded_for' in proxy_headers and proxy_headers['x_forwarded_for']:
            max_depth = max(max_depth, len(proxy_headers['x_forwarded_for']))
        
        return max_depth
    
    @staticmethod
    def detect_mixed_protocols(proxy_headers: Dict[str, Any]) -> bool:
        """Detect if the proxy chain uses mixed protocols"""
        if 'via' not in proxy_headers or not proxy_headers['via']:
            return False
        
        protocols = set()
        for via_entry in proxy_headers['via']:
            protocol_version = via_entry.get('protocol_version', '')
            if '.' in protocol_version:
                protocol = protocol_version.split('.')[0]
                protocols.add(protocol)
        
        return len(protocols) > 1
    
    @staticmethod
    def extract_proxy_software(proxy_headers: Dict[str, Any]) -> List[str]:
        """Extract proxy software information from headers"""
        software_list = []
        
        # From Via headers
        if 'via' in proxy_headers and proxy_headers['via']:
            for via_entry in proxy_headers['via']:
                proxy_name = via_entry.get('proxy_name', '')
                comment = via_entry.get('comment', '')
                
                # Extract software from proxy name (e.g., "squid/3.5.28")
                if '/' in proxy_name:
                    software = proxy_name.split('/')[0]
                    software_list.append(software)
                
                # Extract software from comment
                if comment and '(' in comment and ')' in comment:
                    comment_content = comment.strip('()')
                    software_list.append(comment_content)
        
        # From Server header (if it's a proxy)
        if 'server' in proxy_headers:
            server = proxy_headers['server']
            if any(proxy_keyword in server.lower() for proxy_keyword in 
                   ['squid', 'nginx', 'apache', 'haproxy', 'cloudflare', 'varnish']):
                software_list.append(server)
        
        return list(set(software_list))  # Remove duplicates
    
    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if IP address is in private range"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False
    
    @staticmethod
    def calculate_geographic_anomaly_score(ip_chain: List[str]) -> float:
        """Calculate anomaly score based on geographic routing patterns
        
        This is a placeholder for geographic analysis.
        In a full implementation, this would use IP geolocation data.
        """
        if len(ip_chain) < 2:
            return 0.0
        
        # Placeholder scoring based on IP patterns
        # In reality, this would check geographic distance and routing logic
        anomaly_score = 0.0
        
        # Check for suspicious patterns
        for i in range(len(ip_chain) - 1):
            current_ip = ip_chain[i]
            next_ip = ip_chain[i + 1]
            
            # Placeholder: Check if IPs are in dramatically different ranges
            # This is a very basic heuristic
            try:
                current_network = ipaddress.ip_network(f"{current_ip}/24", strict=False)
                next_network = ipaddress.ip_network(f"{next_ip}/24", strict=False)
                
                if not current_network.overlaps(next_network):
                    anomaly_score += 0.2
            except ValueError:
                anomaly_score += 0.1
        
        return min(1.0, anomaly_score)
    
    @staticmethod
    def detect_header_inconsistencies(proxy_headers: Dict[str, Any]) -> List[str]:
        """Detect inconsistencies in proxy headers that might indicate obfuscation"""
        inconsistencies = []
        
        # Check Via vs X-Forwarded-For count mismatch
        via_count = len(proxy_headers.get('via', []))
        xff_count = len(proxy_headers.get('x_forwarded_for', []))
        
        if via_count > 0 and xff_count > 0 and abs(via_count - xff_count) > 1:
            inconsistencies.append(f"Via header count ({via_count}) differs significantly from X-Forwarded-For count ({xff_count})")
        
        # Check for conflicting protocol information
        if SecurityUtils.detect_mixed_protocols(proxy_headers):
            inconsistencies.append("Mixed protocol versions detected in Via headers")
        
        # Check for suspicious proxy names
        if 'via' in proxy_headers:
            for via_entry in proxy_headers['via']:
                proxy_name = via_entry.get('proxy_name', '')
                # Look for obviously fake or suspicious proxy names
                if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', proxy_name):
                    # Proxy name is just an IP, which is suspicious
                    inconsistencies.append(f"Suspicious proxy name (bare IP): {proxy_name}")
                elif len(proxy_name) < 3:
                    inconsistencies.append(f"Suspiciously short proxy name: {proxy_name}")
        
        return inconsistencies


def parse_proxy_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Convenience function to parse proxy headers"""
    return SecurityUtils.extract_proxy_headers(headers)


def calculate_chain_risk(chain_depth: int, inconsistencies: List[str], 
                        mixed_protocols: bool, geographic_anomaly: float) -> Tuple[str, float]:
    """Calculate overall chain risk score and level"""
    risk_score = 0.0
    
    # Chain depth scoring
    if chain_depth == 0:
        risk_score += 0.0  # No chain detected
    elif chain_depth == 1:
        risk_score += 0.1  # Single proxy (low risk)
    elif chain_depth <= 3:
        risk_score += 0.3  # Short chain (medium risk)
    elif chain_depth <= 5:
        risk_score += 0.6  # Long chain (high risk)
    else:
        risk_score += 0.8  # Very long chain (critical risk)
    
    # Inconsistencies penalty
    risk_score += len(inconsistencies) * 0.2
    
    # Mixed protocols penalty
    if mixed_protocols:
        risk_score += 0.3
    
    # Geographic anomalies
    risk_score += geographic_anomaly * 0.4
    
    # Normalize score
    risk_score = min(1.0, risk_score)
    
    # Determine risk level
    if risk_score < 0.3:
        risk_level = "low"
    elif risk_score < 0.6:
        risk_level = "medium"
    elif risk_score < 0.8:
        risk_level = "high"
    else:
        risk_level = "critical"
    
    return risk_level, risk_score