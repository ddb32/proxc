"""Proxy CLI Web Handler - Data Processing for Web Interface"""

import csv
import io
import json
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Any, Union

# Import our models
from ..proxy_core.models import ProxyInfo, ProxyProtocol, AnonymityLevel, ThreatLevel, ProxyStatus

# Import standardized CLI components
from .cli_base import get_cli_logger
from .cli_exceptions import WebInterfaceError, CLIErrorHandler


class WebDataHandler:
    """Handler for processing proxy data for web interface"""
    
    def __init__(self, proxies: List[ProxyInfo], config: Optional[Any] = None):
        self.proxies = proxies or []
        self.config = config
        self.logger = get_cli_logger("web_handler")
        self.error_handler = CLIErrorHandler(self.logger)
        
        # Cache for expensive operations
        self._summary_cache = None
        self._cache_timestamp = None
        self._cache_ttl = 30  # 30 seconds cache TTL
    
    def get_proxies_json(self, filters: Dict[str, str] = None, 
                        limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        """Get proxies as JSON with filtering and pagination"""
        try:
            filtered_proxies = self._filter_proxies(filters or {})
            total_count = len(filtered_proxies)
            
            # Pagination
            paginated_proxies = filtered_proxies[offset:offset + limit]
            
            # Convert to JSON-serializable format
            proxies_json = [self._proxy_to_dict(proxy) for proxy in paginated_proxies]
            
            return {
                'proxies': proxies_json,
                'total_count': total_count,
                'limit': limit,
                'offset': offset,
                'has_more': offset + limit < total_count
            }
            
        except Exception as e:
            web_error = WebInterfaceError(
                "Failed to get proxies data", 
                endpoint="/api/proxies",
                method="GET"
            )
            self.error_handler.handle_error(web_error, context={'filters': filters, 'limit': limit, 'offset': offset})
            return {'proxies': [], 'total_count': 0, 'limit': limit, 'offset': offset, 'has_more': False, 'error': str(web_error)}
    
    def _is_cache_valid(self) -> bool:
        """Check if summary cache is still valid"""
        if not self._cache_timestamp:
            return False
        return (datetime.utcnow() - self._cache_timestamp).total_seconds() < self._cache_ttl
    
    def get_summary_json(self) -> Dict[str, Any]:
        """Get summary statistics as JSON with caching"""
        try:
            # Return cached summary if still valid
            if self._is_cache_valid() and self._summary_cache:
                return self._summary_cache
            
            # Calculate fresh statistics
            total_proxies = len(self.proxies)
            active_proxies = sum(1 for p in self.proxies if p.status == ProxyStatus.ACTIVE)
            failed_proxies = sum(1 for p in self.proxies if p.status == ProxyStatus.FAILED)
            
            # Calculate success rate
            success_rate = (active_proxies / total_proxies * 100) if total_proxies > 0 else 0.0
            
            # Calculate average response time
            response_times = [p.metrics.response_time for p in self.proxies 
                            if p.metrics and p.metrics.response_time is not None]
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0.0
            
            # Geographic distribution
            country_counts = defaultdict(int)
            for proxy in self.proxies:
                if proxy.geo_location and proxy.geo_location.country_code:
                    country_counts[proxy.geo_location.country_code] += 1
            
            # Protocol distribution
            protocol_counts = defaultdict(int)
            for proxy in self.proxies:
                protocol_counts[proxy.protocol.value] += 1
            
            # Threat level distribution
            threat_counts = defaultdict(int)
            for proxy in self.proxies:
                threat_counts[proxy.threat_level.value] += 1
            
            # Anonymity level distribution
            anonymity_counts = defaultdict(int)
            for proxy in self.proxies:
                anonymity_counts[proxy.anonymity_level.value] += 1
            
            now = datetime.utcnow()
            summary = {
                'timestamp': now.isoformat(),
                'total_proxies': total_proxies,
                'active_proxies': active_proxies,
                'failed_proxies': failed_proxies,
                'inactive_proxies': total_proxies - active_proxies - failed_proxies,
                'success_rate': round(success_rate, 2),
                'avg_response_time': round(avg_response_time, 2),
                'country_distribution': dict(sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
                'protocol_distribution': dict(protocol_counts),
                'threat_distribution': dict(threat_counts),
                'anonymity_distribution': dict(anonymity_counts),
                'top_countries': list(sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
                'response_time_stats': self._get_response_time_stats()
            }
            
            # Cache the result
            self._summary_cache = summary
            self._cache_timestamp = now
            
            return summary
            
        except Exception as e:
            web_error = WebInterfaceError(
                "Failed to generate summary statistics", 
                endpoint="/api/summary",
                method="GET"
            )
            self.error_handler.handle_error(web_error, context={'proxy_count': len(self.proxies)})
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'total_proxies': len(self.proxies),
                'active_proxies': 0,
                'failed_proxies': 0,
                'inactive_proxies': 0,
                'success_rate': 0.0,
                'error': str(web_error),
                'avg_response_time': 0.0,
                'country_distribution': {},
                'protocol_distribution': {},
                'threat_distribution': {},
                'anonymity_distribution': {},
                'top_countries': [],
                'response_time_stats': {}
            }
    
    def get_json_export(self, filters: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """Get filtered proxies for JSON export"""
        try:
            filtered_proxies = self._filter_proxies(filters or {})
            return [self._proxy_to_dict(proxy, include_all=True) for proxy in filtered_proxies]
        except Exception as e:
            self.logger.error(f"Error getting JSON export: {e}")
            return []
    
    def get_csv_export(self, filters: Dict[str, str] = None) -> str:
        """Get filtered proxies as CSV string"""
        try:
            filtered_proxies = self._filter_proxies(filters or {})
            
            # Create CSV in memory
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            headers = [
                'Address', 'Host', 'Port', 'Protocol', 'Status', 'Anonymity Level',
                'Threat Level', 'Country', 'Country Code', 'City', 'Region', 'ISP',
                'ASN', 'Response Time (ms)', 'Success Rate (%)', 'Source',
                'Discovered At', 'Last Updated'
            ]
            writer.writerow(headers)
            
            # Write data rows
            for proxy in filtered_proxies:
                row = [
                    proxy.address,
                    proxy.host,
                    proxy.port,
                    proxy.protocol.value,
                    proxy.status.value,
                    proxy.anonymity_level.value,
                    proxy.threat_level.value,
                    proxy.geo_location.country if proxy.geo_location else '',
                    proxy.geo_location.country_code if proxy.geo_location else '',
                    proxy.geo_location.city if proxy.geo_location else '',
                    proxy.geo_location.region if proxy.geo_location else '',
                    proxy.geo_location.isp if proxy.geo_location else '',
                    proxy.geo_location.asn if proxy.geo_location else '',
                    proxy.metrics.response_time if proxy.metrics and proxy.metrics.response_time else '',
                    proxy.metrics.success_rate if proxy.metrics and proxy.metrics.success_rate else '',
                    proxy.source or '',
                    proxy.discovered_at.isoformat() if proxy.discovered_at else '',
                    proxy.last_updated.isoformat() if proxy.last_updated else ''
                ]
                writer.writerow(row)
            
            return output.getvalue()
            
        except Exception as e:
            self.logger.error(f"Error getting CSV export: {e}")
            return "Error generating CSV export"
    
    def _filter_proxies(self, filters: Dict[str, str]) -> List[ProxyInfo]:
        """Filter proxies based on given criteria"""
        filtered = self.proxies
        
        # Search filter
        if 'search' in filters and filters['search']:
            search_term = filters['search'].lower()
            filtered = [
                proxy for proxy in filtered
                if (search_term in proxy.address.lower() or
                    search_term in proxy.protocol.value.lower() or
                    (proxy.geo_location and proxy.geo_location.country and 
                     search_term in proxy.geo_location.country.lower()) or
                    (proxy.geo_location and proxy.geo_location.country_code and 
                     search_term in proxy.geo_location.country_code.lower()) or
                    (proxy.source and search_term in proxy.source.lower()))
            ]
        
        # Protocol filter
        if 'protocol' in filters and filters['protocol']:
            try:
                protocol_enum = ProxyProtocol(filters['protocol'].lower())
                filtered = [proxy for proxy in filtered if proxy.protocol == protocol_enum]
            except ValueError:
                pass  # Invalid protocol, skip filter
        
        # Status filter
        if 'status' in filters and filters['status']:
            try:
                status_enum = ProxyStatus(filters['status'].upper())
                filtered = [proxy for proxy in filtered if proxy.status == status_enum]
            except ValueError:
                pass  # Invalid status, skip filter
        
        # Country filter
        if 'country' in filters and filters['country']:
            country_code = filters['country'].upper()
            filtered = [
                proxy for proxy in filtered
                if (proxy.geo_location and proxy.geo_location.country_code == country_code)
            ]
        
        # Threat level filter
        if 'threat_level' in filters and filters['threat_level']:
            try:
                threat_enum = ThreatLevel(filters['threat_level'].upper())
                filtered = [proxy for proxy in filtered if proxy.threat_level == threat_enum]
            except ValueError:
                pass  # Invalid threat level, skip filter
        
        return filtered
    
    def _proxy_to_dict(self, proxy: ProxyInfo, include_all: bool = False) -> Dict[str, Any]:
        """Convert ProxyInfo to dictionary"""
        try:
            base_dict = {
                'proxy_id': proxy.proxy_id,
                'address': proxy.address,
                'host': proxy.host,
                'port': proxy.port,
                'protocol': proxy.protocol.value,
                'status': proxy.status.value,
                'anonymity_level': proxy.anonymity_level.value,
                'threat_level': proxy.threat_level.value,
                'security_level': proxy.security_level.value if proxy.security_level else 'unknown'
            }
            
            # Add geographic data
            if proxy.geo_location:
                base_dict.update({
                    'country': proxy.geo_location.country,
                    'country_code': proxy.geo_location.country_code,
                    'city': proxy.geo_location.city,
                    'region': proxy.geo_location.region,
                    'isp': proxy.geo_location.isp,
                    'asn': proxy.geo_location.asn,
                    'latitude': proxy.geo_location.latitude,
                    'longitude': proxy.geo_location.longitude
                })
            else:
                base_dict.update({
                    'country': None,
                    'country_code': None,
                    'city': None,
                    'region': None,
                    'isp': None,
                    'asn': None,
                    'latitude': None,
                    'longitude': None
                })
            
            # Add metrics data
            if proxy.metrics:
                base_dict.update({
                    'response_time': proxy.metrics.response_time,
                    'success_rate': proxy.metrics.success_rate,
                    'uptime_percentage': proxy.metrics.uptime_percentage,
                    'check_count': proxy.metrics.check_count,
                    'last_checked': proxy.metrics.last_checked.isoformat() if proxy.metrics.last_checked else None
                })
            else:
                base_dict.update({
                    'response_time': None,
                    'success_rate': None,
                    'uptime_percentage': None,
                    'check_count': 0,
                    'last_checked': None
                })
            
            # Add additional fields if requested
            if include_all:
                base_dict.update({
                    'source': proxy.source,
                    'discovered_at': proxy.discovered_at.isoformat() if proxy.discovered_at else None,
                    'last_updated': proxy.last_updated.isoformat() if proxy.last_updated else None,
                    'validation_status': proxy.validation_status.value if proxy.validation_status else 'pending',
                    'username': proxy.username,
                    'password': '***' if proxy.password else None,  # Hide password for security
                    'tags': list(proxy.tags) if proxy.tags else [],
                    'notes': proxy.notes
                })
                
                # Add protocol detection info if available
                if hasattr(proxy, 'protocol_confidence'):
                    base_dict['protocol_confidence'] = proxy.protocol_confidence
                if hasattr(proxy, 'protocol_detection_method'):
                    base_dict['protocol_detection_method'] = proxy.protocol_detection_method
                if hasattr(proxy, 'protocol_detection_time'):
                    base_dict['protocol_detection_time'] = proxy.protocol_detection_time.isoformat() if proxy.protocol_detection_time else None
            
            return base_dict
            
        except Exception as e:
            self.logger.error(f"Error converting proxy to dict: {e}")
            return {
                'proxy_id': getattr(proxy, 'proxy_id', 'unknown'),
                'address': getattr(proxy, 'address', 'unknown'),
                'host': getattr(proxy, 'host', 'unknown'),
                'port': getattr(proxy, 'port', 0),
                'protocol': getattr(proxy, 'protocol', ProxyProtocol.HTTP).value,
                'status': getattr(proxy, 'status', ProxyStatus.INACTIVE).value,
                'error': str(e)
            }
    
    def _get_response_time_stats(self) -> Dict[str, float]:
        """Calculate response time statistics"""
        try:
            response_times = [
                p.metrics.response_time for p in self.proxies
                if p.metrics and p.metrics.response_time is not None
            ]
            
            if not response_times:
                return {'min': 0, 'max': 0, 'median': 0, 'p95': 0}
            
            response_times.sort()
            count = len(response_times)
            
            return {
                'min': response_times[0],
                'max': response_times[-1],
                'median': response_times[count // 2],
                'p95': response_times[int(count * 0.95)] if count > 0 else 0
            }
            
        except Exception as e:
            self.logger.error(f"Error calculating response time stats: {e}")
            return {'min': 0, 'max': 0, 'median': 0, 'p95': 0}
    
    def refresh_data(self, new_proxies: List[ProxyInfo]):
        """Update with new proxy data"""
        self.proxies = new_proxies or []
        # Clear cache
        self._summary_cache = None
        self._cache_timestamp = None
        self.logger.info(f"Data refreshed with {len(self.proxies)} proxies")
    
    def get_proxy_count(self) -> int:
        """Get total proxy count"""
        return len(self.proxies)
    
    def get_active_proxy_count(self) -> int:
        """Get active proxy count"""
        return sum(1 for p in self.proxies if p.status == ProxyStatus.ACTIVE)