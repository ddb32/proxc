"""Geographical Data Management Package

Provides comprehensive geographical data enrichment for proxy IPs including:
- GeoIP2 database integration
- API fallback mechanisms
- Intelligent caching
- Bulk processing capabilities
- Risk assessment based on geography
"""

from .geo_manager import GeoIPManager, GeoCache, create_geo_manager, get_global_geo_manager
from .geo_enricher import GeoEnricher, create_geo_enricher

__all__ = [
    'GeoIPManager',
    'GeoCache', 
    'GeoEnricher',
    'create_geo_manager',
    'get_global_geo_manager',
    'create_geo_enricher'
]