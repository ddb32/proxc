"""Bulk Geographical Data Processor

Provides bulk processing capabilities for enriching existing proxy databases
with geographical information. Includes progress tracking, resumable operations,
and database integration.
"""

import logging
import time
import json
from typing import List, Dict, Any, Optional, Callable, Iterator
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

# Conditional imports based on what's available
try:
    from ..proxy_core.models import ProxyInfo, RiskCategory, TierLevel
    from ..proxy_core.geo.geo_manager import get_global_geo_manager, GeoIPManager
    from ..proxy_core.geo.geo_enricher import create_geo_enricher, GeoEnricher
    HAS_MODELS = True
except ImportError:
    HAS_MODELS = False

logger = logging.getLogger(__name__)


@dataclass
class ProcessingStats:
    """Statistics for bulk geo processing"""
    total_proxies: int = 0
    processed: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    already_enriched: int = 0
    errors: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    @property
    def duration(self) -> Optional[timedelta]:
        """Get processing duration"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None
    
    @property
    def success_rate(self) -> float:
        """Get success rate percentage"""
        if self.processed == 0:
            return 0.0
        return (self.successful / self.processed) * 100
    
    @property
    def processing_rate(self) -> float:
        """Get processing rate (proxies per second)"""
        if not self.duration or self.duration.total_seconds() == 0:
            return 0.0
        return self.processed / self.duration.total_seconds()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'total_proxies': self.total_proxies,
            'processed': self.processed,
            'successful': self.successful,
            'failed': self.failed,
            'skipped': self.skipped,
            'already_enriched': self.already_enriched,
            'errors': self.errors,
            'success_rate': round(self.success_rate, 2),
            'processing_rate': round(self.processing_rate, 2),
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self.duration.total_seconds() if self.duration else None
        }


class BulkGeoProcessor:
    """Bulk geographical data processor for existing proxy databases"""
    
    def __init__(self, 
                 database_manager=None,
                 geo_manager: Optional[GeoIPManager] = None,
                 config: Optional[Dict[str, Any]] = None):
        """
        Initialize bulk geo processor
        
        Args:
            database_manager: Database manager instance
            geo_manager: Geographical manager instance
            config: Configuration dictionary
        """
        self.db_manager = database_manager
        self.geo_manager = geo_manager or get_global_geo_manager()
        self.geo_enricher = create_geo_enricher(self.geo_manager)
        
        self.config = config or {}
        
        # Processing configuration
        self.batch_size = self.config.get('batch_size', 1000)
        self.max_workers = self.config.get('max_workers', 10)
        self.progress_interval = self.config.get('progress_interval', 100)
        self.save_interval = self.config.get('save_interval', 500)
        self.force_update = self.config.get('force_update', False)
        
        # Resume capability
        self.checkpoint_file = self.config.get('checkpoint_file', 'geo_processing_checkpoint.json')
        self.enable_checkpoints = self.config.get('enable_checkpoints', True)
        
        # Statistics
        self.stats = ProcessingStats()
        
        # Callbacks
        self.progress_callback: Optional[Callable[[ProcessingStats], None]] = None
        self.error_callback: Optional[Callable[[str, Exception], None]] = None
    
    def set_progress_callback(self, callback: Callable[[ProcessingStats], None]):
        """Set progress callback function"""
        self.progress_callback = callback
    
    def set_error_callback(self, callback: Callable[[str, Exception], None]):
        """Set error callback function"""
        self.error_callback = callback
    
    def process_all_proxies(self, resume_from_checkpoint: bool = True) -> ProcessingStats:
        """Process all proxies in the database"""
        if not self.db_manager:
            raise ValueError("Database manager is required for processing all proxies")
        
        logger.info("Starting bulk geographical enrichment of all proxies")
        
        # Initialize statistics
        self.stats = ProcessingStats()
        self.stats.start_time = datetime.utcnow()
        
        try:
            # Check for resume capability
            checkpoint_data = None
            if resume_from_checkpoint and self.enable_checkpoints:
                checkpoint_data = self._load_checkpoint()
            
            # Get proxy iterator
            if checkpoint_data:
                logger.info(f"Resuming from checkpoint: {checkpoint_data['processed']} proxies processed")
                self.stats.processed = checkpoint_data['processed']
                self.stats.successful = checkpoint_data['successful']
                self.stats.failed = checkpoint_data['failed']
                self.stats.skipped = checkpoint_data['skipped']
                proxy_iterator = self._get_proxy_iterator(skip=checkpoint_data['processed'])
            else:
                proxy_iterator = self._get_proxy_iterator()
            
            # Process in batches
            batch = []
            for proxy in proxy_iterator:
                batch.append(proxy)
                
                if len(batch) >= self.batch_size:
                    self._process_batch(batch)
                    batch = []
                    
                    # Save checkpoint
                    if self.enable_checkpoints and self.stats.processed % self.save_interval == 0:
                        self._save_checkpoint()
            
            # Process remaining batch
            if batch:
                self._process_batch(batch)
            
            # Final checkpoint cleanup
            if self.enable_checkpoints:
                self._cleanup_checkpoint()
            
            self.stats.end_time = datetime.utcnow()
            logger.info(f"Bulk processing completed: {self.stats.to_dict()}")
            
            return self.stats
            
        except Exception as e:
            self.stats.errors += 1
            logger.error(f"Bulk processing failed: {e}")
            if self.error_callback:
                self.error_callback("bulk_processing", e)
            raise
    
    def process_proxy_list(self, proxies: List[ProxyInfo]) -> ProcessingStats:
        """Process a specific list of proxy objects"""
        logger.info(f"Starting geographical enrichment of {len(proxies)} proxies")
        
        self.stats = ProcessingStats()
        self.stats.start_time = datetime.utcnow()
        self.stats.total_proxies = len(proxies)
        
        try:
            # Process in batches
            for i in range(0, len(proxies), self.batch_size):
                batch = proxies[i:i + self.batch_size]
                self._process_proxy_batch(batch)
            
            self.stats.end_time = datetime.utcnow()
            logger.info(f"Proxy list processing completed: {self.stats.to_dict()}")
            
            return self.stats
            
        except Exception as e:
            self.stats.errors += 1
            logger.error(f"Proxy list processing failed: {e}")
            if self.error_callback:
                self.error_callback("proxy_list_processing", e)
            raise
    
    def process_by_criteria(self, 
                          country_filter: Optional[List[str]] = None,
                          region_filter: Optional[List[str]] = None,
                          risk_category_filter: Optional[List[str]] = None,
                          missing_geo_only: bool = True) -> ProcessingStats:
        """Process proxies matching specific criteria"""
        
        criteria = {
            'country_filter': country_filter,
            'region_filter': region_filter,
            'risk_category_filter': risk_category_filter,
            'missing_geo_only': missing_geo_only
        }
        
        logger.info(f"Starting filtered geographical enrichment with criteria: {criteria}")
        
        self.stats = ProcessingStats()
        self.stats.start_time = datetime.utcnow()
        
        try:
            # Get filtered proxy iterator
            proxy_iterator = self._get_filtered_proxy_iterator(**criteria)
            
            # Process in batches
            batch = []
            for proxy in proxy_iterator:
                batch.append(proxy)
                
                if len(batch) >= self.batch_size:
                    self._process_batch(batch)
                    batch = []
            
            # Process remaining batch
            if batch:
                self._process_batch(batch)
            
            self.stats.end_time = datetime.utcnow()
            logger.info(f"Filtered processing completed: {self.stats.to_dict()}")
            
            return self.stats
            
        except Exception as e:
            self.stats.errors += 1
            logger.error(f"Filtered processing failed: {e}")
            if self.error_callback:
                self.error_callback("filtered_processing", e)
            raise
    
    def _process_batch(self, batch: List[Any]):
        """Process a batch of proxy database records"""
        try:
            # Convert database records to ProxyInfo objects if needed
            proxy_objects = []
            for record in batch:
                if hasattr(record, 'to_proxy_info'):
                    proxy_objects.append(record.to_proxy_info())
                elif isinstance(record, dict):
                    proxy_objects.append(self._dict_to_proxy_info(record))
                else:
                    proxy_objects.append(record)  # Assume it's already a ProxyInfo
            
            # Process the batch
            self._process_proxy_batch(proxy_objects)
            
            # Update database with enriched data
            self._update_database_batch(proxy_objects)
            
        except Exception as e:
            self.stats.errors += 1
            logger.error(f"Batch processing failed: {e}")
            if self.error_callback:
                self.error_callback("batch_processing", e)
    
    def _process_proxy_batch(self, proxies: List[ProxyInfo]):
        """Process a batch of ProxyInfo objects"""
        # Filter proxies that need processing
        proxies_to_process = []
        
        for proxy in proxies:
            if self.force_update or not proxy.geo_location or not proxy.country:
                proxies_to_process.append(proxy)
            else:
                self.stats.already_enriched += 1
                self.stats.skipped += 1
        
        if not proxies_to_process:
            return
        
        # Use the geo enricher for batch processing
        try:
            results = self.geo_enricher.enrich_proxies_batch(
                proxies_to_process,
                max_workers=self.max_workers,
                force_update=self.force_update,
                progress_callback=self._batch_progress_callback
            )
            
            # Update statistics
            self.stats.processed += results['processed']
            self.stats.successful += results['successful']
            self.stats.failed += results['failed']
            self.stats.skipped += results['skipped']
            
            # Call progress callback
            if self.progress_callback:
                self.progress_callback(self.stats)
            
        except Exception as e:
            self.stats.errors += 1
            logger.error(f"Proxy batch enrichment failed: {e}")
            if self.error_callback:
                self.error_callback("proxy_batch_enrichment", e)
    
    def _batch_progress_callback(self, current: int, total: int):
        """Internal progress callback for batch processing"""
        if current % self.progress_interval == 0 or current == total:
            logger.debug(f"Batch progress: {current}/{total}")
    
    def _update_database_batch(self, proxies: List[ProxyInfo]):
        """Update database with enriched proxy data"""
        if not self.db_manager:
            return
        
        try:
            # Use database manager to update proxies
            # This would depend on the specific database implementation
            if hasattr(self.db_manager, 'update_proxies_batch'):
                self.db_manager.update_proxies_batch(proxies)
            elif hasattr(self.db_manager, 'update_proxy'):
                for proxy in proxies:
                    self.db_manager.update_proxy(proxy)
            else:
                logger.warning("Database manager doesn't support batch updates")
            
        except Exception as e:
            self.stats.errors += 1
            logger.error(f"Database batch update failed: {e}")
            if self.error_callback:
                self.error_callback("database_update", e)
    
    def _get_proxy_iterator(self, skip: int = 0) -> Iterator[Any]:
        """Get iterator for all proxies in database"""
        if not self.db_manager:
            raise ValueError("Database manager is required")
        
        # This would depend on the specific database implementation
        if hasattr(self.db_manager, 'get_all_proxies_iterator'):
            return self.db_manager.get_all_proxies_iterator(skip=skip)
        elif hasattr(self.db_manager, 'get_all_proxies'):
            proxies = self.db_manager.get_all_proxies()
            return iter(proxies[skip:])
        else:
            raise ValueError("Database manager doesn't support proxy iteration")
    
    def _get_filtered_proxy_iterator(self, **criteria) -> Iterator[Any]:
        """Get iterator for filtered proxies"""
        if not self.db_manager:
            raise ValueError("Database manager is required")
        
        # This would depend on the specific database implementation
        if hasattr(self.db_manager, 'get_filtered_proxies_iterator'):
            return self.db_manager.get_filtered_proxies_iterator(**criteria)
        else:
            # Fallback to getting all and filtering
            all_proxies = self._get_proxy_iterator()
            return self._filter_proxies(all_proxies, **criteria)
    
    def _filter_proxies(self, proxy_iterator: Iterator[Any], **criteria) -> Iterator[Any]:
        """Filter proxy iterator based on criteria"""
        for proxy in proxy_iterator:
            if self._matches_criteria(proxy, **criteria):
                yield proxy
    
    def _matches_criteria(self, proxy: Any, **criteria) -> bool:
        """Check if proxy matches filtering criteria"""
        # Convert to ProxyInfo if needed
        if hasattr(proxy, 'to_proxy_info'):
            proxy_info = proxy.to_proxy_info()
        elif isinstance(proxy, dict):
            proxy_info = self._dict_to_proxy_info(proxy)
        else:
            proxy_info = proxy
        
        # Apply filters
        if criteria.get('missing_geo_only', False):
            if proxy_info.geo_location and proxy_info.country:
                return False
        
        if criteria.get('country_filter'):
            if not proxy_info.country or proxy_info.country not in criteria['country_filter']:
                return False
        
        if criteria.get('region_filter'):
            if not proxy_info.region or proxy_info.region not in criteria['region_filter']:
                return False
        
        if criteria.get('risk_category_filter'):
            if proxy_info.risk_category.value not in criteria['risk_category_filter']:
                return False
        
        return True
    
    def _dict_to_proxy_info(self, data: Dict[str, Any]) -> ProxyInfo:
        """Convert dictionary to ProxyInfo object"""
        # This would use the existing model conversion function
        if HAS_MODELS:
            from ..proxy_core.models import create_proxy_from_dict
            return create_proxy_from_dict(data)
        else:
            # Fallback basic conversion
            return type('ProxyInfo', (), data)()
    
    def _save_checkpoint(self):
        """Save processing checkpoint"""
        if not self.enable_checkpoints:
            return
        
        try:
            checkpoint_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'processed': self.stats.processed,
                'successful': self.stats.successful,
                'failed': self.stats.failed,
                'skipped': self.stats.skipped,
                'errors': self.stats.errors
            }
            
            with open(self.checkpoint_file, 'w') as f:
                json.dump(checkpoint_data, f, indent=2)
            
            logger.debug(f"Checkpoint saved: {self.stats.processed} processed")
            
        except Exception as e:
            logger.warning(f"Failed to save checkpoint: {e}")
    
    def _load_checkpoint(self) -> Optional[Dict[str, Any]]:
        """Load processing checkpoint"""
        try:
            with open(self.checkpoint_file, 'r') as f:
                checkpoint_data = json.load(f)
            
            logger.info(f"Checkpoint loaded: {checkpoint_data}")
            return checkpoint_data
            
        except FileNotFoundError:
            logger.debug("No checkpoint file found")
            return None
        except Exception as e:
            logger.warning(f"Failed to load checkpoint: {e}")
            return None
    
    def _cleanup_checkpoint(self):
        """Clean up checkpoint file after successful completion"""
        try:
            import os
            if os.path.exists(self.checkpoint_file):
                os.remove(self.checkpoint_file)
                logger.debug("Checkpoint file cleaned up")
        except Exception as e:
            logger.warning(f"Failed to cleanup checkpoint: {e}")
    
    def get_processing_stats(self) -> Dict[str, Any]:
        """Get current processing statistics"""
        return self.stats.to_dict()
    
    def estimate_completion_time(self) -> Optional[datetime]:
        """Estimate completion time based on current progress"""
        if self.stats.processing_rate == 0 or self.stats.total_proxies == 0:
            return None
        
        remaining = self.stats.total_proxies - self.stats.processed
        if remaining <= 0:
            return datetime.utcnow()
        
        remaining_seconds = remaining / self.stats.processing_rate
        return datetime.utcnow() + timedelta(seconds=remaining_seconds)


def create_bulk_geo_processor(database_manager=None,
                            geo_manager: Optional[GeoIPManager] = None,
                            config: Optional[Dict[str, Any]] = None) -> BulkGeoProcessor:
    """Factory function to create bulk geo processor"""
    return BulkGeoProcessor(database_manager, geo_manager, config)


if __name__ == "__main__":
    # Example usage
    import sys
    
    # Create processor with test configuration
    config = {
        'batch_size': 100,
        'max_workers': 5,
        'progress_interval': 50,
        'enable_checkpoints': True
    }
    
    processor = create_bulk_geo_processor(config=config)
    
    # Set up callbacks
    def progress_callback(stats: ProcessingStats):
        print(f"Progress: {stats.processed}/{stats.total_proxies} "
              f"({stats.success_rate:.1f}% success rate)")
    
    def error_callback(operation: str, error: Exception):
        print(f"Error in {operation}: {error}")
    
    processor.set_progress_callback(progress_callback)
    processor.set_error_callback(error_callback)
    
    print("Bulk geo processor created successfully")
    print("Note: Requires database manager and proxy data for actual processing")
    
    # Show example statistics
    print(f"Example stats format: {processor.get_processing_stats()}")