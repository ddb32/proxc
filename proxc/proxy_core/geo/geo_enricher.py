"""Geographical Data Enricher

Enriches proxy objects with geographical information using the GeoIP manager.
Provides batch processing capabilities and intelligent updating strategies.
"""

import logging
from typing import List, Dict, Any, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

from ..models import ProxyInfo, GeoLocation
from .geo_manager import get_global_geo_manager, GeoIPManager

logger = logging.getLogger(__name__)


class GeoEnricher:
    """Enriches proxy objects with geographical data"""
    
    def __init__(self, geo_manager: Optional[GeoIPManager] = None):
        self.geo_manager = geo_manager or get_global_geo_manager()
        self.enrichment_stats = {
            'total_processed': 0,
            'successful_enrichments': 0,
            'failed_enrichments': 0,
            'cache_hits': 0,
            'api_calls': 0
        }
    
    def enrich_proxy(self, proxy: ProxyInfo, force_update: bool = False) -> bool:
        """Enrich a single proxy with geographical data"""
        try:
            # Skip if already enriched and not forcing update
            if not force_update and proxy.geo_location and proxy.country:
                logger.debug(f"Proxy {proxy.address} already has geographical data")
                return True
            
            # Get geographical information
            geo_info = self.geo_manager.get_geographical_info(proxy.host)
            
            if geo_info and geo_info.get('status') == 'success':
                # Update proxy geographical fields
                proxy.region = geo_info.get('region')
                proxy.country = geo_info.get('country_code')
                proxy.city = geo_info.get('city')
                
                # Create or update GeoLocation object
                if proxy.geo_location is None:
                    proxy.geo_location = GeoLocation()
                
                proxy.geo_location.country = geo_info.get('country')
                proxy.geo_location.country_code = geo_info.get('country_code')
                proxy.geo_location.city = geo_info.get('city')
                proxy.geo_location.region = geo_info.get('region')
                proxy.geo_location.latitude = geo_info.get('latitude')
                proxy.geo_location.longitude = geo_info.get('longitude')
                proxy.geo_location.timezone = geo_info.get('timezone')
                proxy.geo_location.isp = geo_info.get('isp')
                proxy.geo_location.organization = geo_info.get('organization')
                
                # Parse ASN if available
                asn_info = geo_info.get('asn')
                if asn_info and isinstance(asn_info, str):
                    # Extract ASN number from string like "AS15169 Google LLC"
                    try:
                        if asn_info.startswith('AS'):
                            proxy.geo_location.asn = int(asn_info.split()[0][2:])
                    except (ValueError, IndexError):
                        pass
                
                proxy.last_updated = datetime.utcnow()
                
                self.enrichment_stats['successful_enrichments'] += 1
                logger.debug(f"Successfully enriched {proxy.address} with geo data")
                return True
            
            else:
                self.enrichment_stats['failed_enrichments'] += 1
                logger.debug(f"Failed to get geo data for {proxy.address}: {geo_info.get('reason', 'Unknown error')}")
                return False
        
        except Exception as e:
            self.enrichment_stats['failed_enrichments'] += 1
            logger.error(f"Error enriching proxy {proxy.address}: {e}")
            return False
        
        finally:
            self.enrichment_stats['total_processed'] += 1
    
    def enrich_proxies_batch(self, proxies: List[ProxyInfo], 
                           max_workers: int = 10,
                           force_update: bool = False,
                           progress_callback: Optional[Callable[[int, int], None]] = None) -> Dict[str, Any]:
        """Enrich multiple proxies with geographical data in parallel"""
        
        # Filter proxies that need enrichment
        if not force_update:
            proxies_to_enrich = [
                proxy for proxy in proxies 
                if not proxy.geo_location or not proxy.country
            ]
        else:
            proxies_to_enrich = proxies
        
        if not proxies_to_enrich:
            logger.info("All proxies already have geographical data")
            return {
                'total_proxies': len(proxies),
                'processed': 0,
                'successful': 0,
                'failed': 0,
                'skipped': len(proxies)
            }
        
        logger.info(f"Enriching {len(proxies_to_enrich)} proxies with geographical data")
        
        # Extract unique IP addresses for bulk lookup
        unique_ips = list(set(proxy.host for proxy in proxies_to_enrich))
        
        # Perform bulk geographical lookup
        geo_results = self.geo_manager.bulk_lookup(unique_ips, max_workers=max_workers)
        
        # Apply results to proxies
        successful = 0
        failed = 0
        
        for i, proxy in enumerate(proxies_to_enrich):
            try:
                geo_info = geo_results.get(proxy.host)
                
                if geo_info and geo_info.get('status') == 'success':
                    # Update proxy geographical fields
                    proxy.region = geo_info.get('region')
                    proxy.country = geo_info.get('country_code')
                    proxy.city = geo_info.get('city')
                    
                    # Create or update GeoLocation object
                    if proxy.geo_location is None:
                        proxy.geo_location = GeoLocation()
                    
                    proxy.geo_location.country = geo_info.get('country')
                    proxy.geo_location.country_code = geo_info.get('country_code')
                    proxy.geo_location.city = geo_info.get('city')
                    proxy.geo_location.region = geo_info.get('region')
                    proxy.geo_location.latitude = geo_info.get('latitude')
                    proxy.geo_location.longitude = geo_info.get('longitude')
                    proxy.geo_location.timezone = geo_info.get('timezone')
                    proxy.geo_location.isp = geo_info.get('isp')
                    proxy.geo_location.organization = geo_info.get('organization')
                    
                    # Parse ASN if available
                    asn_info = geo_info.get('asn')
                    if asn_info and isinstance(asn_info, str):
                        try:
                            if asn_info.startswith('AS'):
                                proxy.geo_location.asn = int(asn_info.split()[0][2:])
                        except (ValueError, IndexError):
                            pass
                    
                    proxy.last_updated = datetime.utcnow()
                    successful += 1
                    
                else:
                    failed += 1
                    logger.debug(f"No geo data for {proxy.address}")
                
                # Progress callback
                if progress_callback:
                    progress_callback(i + 1, len(proxies_to_enrich))
            
            except Exception as e:
                failed += 1
                logger.error(f"Error processing {proxy.address}: {e}")
        
        # Update stats
        self.enrichment_stats['total_processed'] += len(proxies_to_enrich)
        self.enrichment_stats['successful_enrichments'] += successful
        self.enrichment_stats['failed_enrichments'] += failed
        
        logger.info(f"Batch enrichment completed: {successful} successful, {failed} failed")
        
        return {
            'total_proxies': len(proxies),
            'processed': len(proxies_to_enrich),
            'successful': successful,
            'failed': failed,
            'skipped': len(proxies) - len(proxies_to_enrich)
        }
    
    def enrich_proxies_by_country(self, proxies: List[ProxyInfo], 
                                target_countries: List[str]) -> List[ProxyInfo]:
        """Filter and enrich proxies from specific countries"""
        
        # First enrich all proxies
        self.enrich_proxies_batch(proxies)
        
        # Filter by target countries
        filtered_proxies = [
            proxy for proxy in proxies
            if proxy.country and proxy.country.upper() in [c.upper() for c in target_countries]
        ]
        
        logger.info(f"Found {len(filtered_proxies)} proxies from target countries: {target_countries}")
        return filtered_proxies
    
    def get_geographical_distribution(self, proxies: List[ProxyInfo]) -> Dict[str, Any]:
        """Get geographical distribution statistics for proxies"""
        
        # Ensure all proxies are enriched
        self.enrich_proxies_batch(proxies)
        
        # Count by country
        country_counts = {}
        region_counts = {}
        city_counts = {}
        
        total_with_geo = 0
        
        for proxy in proxies:
            if proxy.country:
                total_with_geo += 1
                
                # Country distribution
                country_counts[proxy.country] = country_counts.get(proxy.country, 0) + 1
                
                # Region distribution
                if proxy.region:
                    region_counts[proxy.region] = region_counts.get(proxy.region, 0) + 1
                
                # City distribution
                if proxy.city:
                    city_key = f"{proxy.city}, {proxy.country}"
                    city_counts[city_key] = city_counts.get(city_key, 0) + 1
        
        # Sort by count
        country_sorted = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
        region_sorted = sorted(region_counts.items(), key=lambda x: x[1], reverse=True)
        city_sorted = sorted(city_counts.items(), key=lambda x: x[1], reverse=True)
        
        return {
            'total_proxies': len(proxies),
            'proxies_with_geo_data': total_with_geo,
            'coverage_percentage': (total_with_geo / len(proxies) * 100) if proxies else 0,
            'countries': {
                'count': len(country_counts),
                'distribution': country_sorted[:20]  # Top 20 countries
            },
            'regions': {
                'count': len(region_counts),
                'distribution': region_sorted
            },
            'cities': {
                'count': len(city_counts),
                'distribution': city_sorted[:50]  # Top 50 cities
            }
        }
    
    def update_risk_based_on_geography(self, proxies: List[ProxyInfo],
                                     high_risk_countries: Optional[List[str]] = None,
                                     low_risk_countries: Optional[List[str]] = None) -> int:
        """Update proxy risk categories based on geographical information"""
        
        # Default risk categorization
        if high_risk_countries is None:
            high_risk_countries = ['CN', 'RU', 'KP', 'IR', 'SY']
        
        if low_risk_countries is None:
            low_risk_countries = ['US', 'CA', 'GB', 'DE', 'NL', 'FR', 'AU', 'JP', 'SE', 'NO', 'DK', 'FI']
        
        # Ensure geographical data is available
        self.enrich_proxies_batch(proxies)
        
        updated_count = 0
        
        for proxy in proxies:
            if not proxy.country:
                continue
            
            old_category = proxy.risk_category
            
            if proxy.country.upper() in [c.upper() for c in high_risk_countries]:
                from ..models import RiskCategory
                proxy.update_risk_category(RiskCategory.AT_RISK, f"High-risk country: {proxy.country}")
                updated_count += 1
            
            elif proxy.country.upper() in [c.upper() for c in low_risk_countries]:
                from ..models import RiskCategory
                if proxy.risk_category == RiskCategory.UNKNOWN:
                    proxy.update_risk_category(RiskCategory.ACTIVE, f"Low-risk country: {proxy.country}")
                    updated_count += 1
        
        logger.info(f"Updated risk categories for {updated_count} proxies based on geography")
        return updated_count
    
    def get_enrichment_stats(self) -> Dict[str, Any]:
        """Get enrichment statistics"""
        cache_stats = self.geo_manager.get_cache_stats()
        
        return {
            'enrichment': self.enrichment_stats.copy(),
            'cache': cache_stats
        }
    
    def clear_cache(self):
        """Clear geographical data cache"""
        self.geo_manager.clear_cache()


def create_geo_enricher(geo_manager: Optional[GeoIPManager] = None) -> GeoEnricher:
    """Factory function to create geographical enricher"""
    return GeoEnricher(geo_manager)


if __name__ == "__main__":
    # Example usage
    from ..models import ProxyInfo, ProxyProtocol
    
    # Create test proxies
    test_proxies = [
        ProxyInfo(host="8.8.8.8", port=8080, protocol=ProxyProtocol.HTTP),
        ProxyInfo(host="1.1.1.1", port=3128, protocol=ProxyProtocol.HTTP),
        ProxyInfo(host="208.67.222.222", port=8080, protocol=ProxyProtocol.HTTP)
    ]
    
    # Create enricher
    enricher = create_geo_enricher()
    
    # Enrich proxies
    print("Enriching test proxies...")
    results = enricher.enrich_proxies_batch(test_proxies)
    print(f"Enrichment results: {results}")
    
    # Show geographical distribution
    distribution = enricher.get_geographical_distribution(test_proxies)
    print(f"Geographical distribution: {distribution}")
    
    # Show stats
    stats = enricher.get_enrichment_stats()
    print(f"Enrichment stats: {stats}")