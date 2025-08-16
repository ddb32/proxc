"""Batch Validators - High-performance batch proxy validation"""

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Callable

from ...proxy_core.models import ProxyInfo
from .validation_config import ValidationConfig, FailureReason
from .validation_results import ValidationResult, BatchValidationResult
from .sync_validators import SyncProxyValidator
from .async_validators import AsyncProxyValidator


class SyncBatchValidator:
    """Synchronous batch validator using thread pool"""
    
    def __init__(self, config: Optional[ValidationConfig] = None):
        self.config = config or ValidationConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Performance tracking
        self.stats = {
            'total_processed': 0,
            'total_valid': 0,
            'total_invalid': 0,
            'total_errors': 0,
            'start_time': None,
            'end_time': None
        }
        
        self.logger.info("SyncBatchValidator initialized successfully")
    
    def validate_batch(self, proxies: List[ProxyInfo], 
                      max_workers: Optional[int] = None,
                      progress_callback: Optional[Callable] = None) -> BatchValidationResult:
        """Validate proxies using thread pool"""
        
        if not proxies:
            return BatchValidationResult(total_proxies=0, valid_proxies=0, invalid_proxies=0)
        
        self.stats['start_time'] = time.time()
        
        # Calculate optimal workers if not specified
        if max_workers is None:
            max_workers = min(self.config.max_workers, len(proxies))
        
        self.logger.info(f"Starting sync batch validation of {len(proxies)} proxies with {max_workers} workers")
        
        results = []
        completed = 0
        
        # Create validator instances for each worker
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all validation tasks
            future_to_proxy = {}
            for proxy in proxies:
                # Each worker gets its own validator instance to avoid conflicts
                validator = SyncProxyValidator(self.config)
                future = executor.submit(validator.validate_proxy, proxy)
                future_to_proxy[future] = proxy
            
            # Process completed tasks
            for future in as_completed(future_to_proxy):
                proxy = future_to_proxy[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Update stats
                    if result.is_valid:
                        self.stats['total_valid'] += 1
                    else:
                        self.stats['total_invalid'] += 1
                    
                    completed += 1
                    self.stats['total_processed'] = completed
                    
                    # Progress callback
                    if progress_callback:
                        progress_callback(completed, len(proxies), result)
                
                except Exception as e:
                    self.stats['total_errors'] += 1
                    completed += 1
                    self.stats['total_processed'] = completed
                    self.logger.error(f"Validation failed for {proxy.address}: {e}")
                    
                    # Create error result
                    error_result = ValidationResult(proxy=proxy)
                    error_result.failure_reason = FailureReason.UNKNOWN_ERROR
                    error_result.error_message = str(e)
                    results.append(error_result)
        
        self.stats['end_time'] = time.time()
        
        # Create batch result
        batch_result = BatchValidationResult(
            total_proxies=len(proxies),
            valid_proxies=self.stats['total_valid'],
            invalid_proxies=self.stats['total_invalid'],
            results=results,
            total_time=self.stats['end_time'] - self.stats['start_time']
        )
        
        # Calculate statistics
        batch_result.calculate_statistics()
        
        # Log performance
        duration = batch_result.total_time
        proxies_per_second = len(results) / duration if duration > 0 else 0
        
        self.logger.info(
            f"Sync batch validation completed: {batch_result.valid_proxies}/{len(results)} valid "
            f"({batch_result.success_rate:.1f}%) in {duration:.1f}s "
            f"({proxies_per_second:.1f} proxies/s)"
        )
        
        return batch_result


class AsyncBatchValidator:
    """High-performance async batch validator"""
    
    def __init__(self, config: Optional[ValidationConfig] = None):
        self.config = config or ValidationConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Performance tracking
        self.stats = {
            'total_processed': 0,
            'total_valid': 0,
            'total_invalid': 0,
            'total_errors': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Professional performance monitoring
        self.performance_monitor = None
        try:
            from ..performance.performance_monitor import create_performance_monitor
            self.performance_monitor = create_performance_monitor(optimization_enabled=False)
        except ImportError:
            self.logger.warning("Performance monitor not available")
        
        self.logger.info("AsyncBatchValidator initialized with professional monitoring")
    
    async def validate_batch_async(self, proxies: List[ProxyInfo], 
                                 max_concurrent: Optional[int] = None,
                                 progress_callback: Optional[Callable] = None) -> BatchValidationResult:
        """Validate proxies asynchronously with controlled concurrency"""
        
        if not proxies:
            return BatchValidationResult(total_proxies=0, valid_proxies=0, invalid_proxies=0)
        
        self.stats['start_time'] = time.time()
        results = []
        
        # Start performance monitoring
        if self.performance_monitor:
            self.performance_monitor.start_monitoring()
        
        # Calculate optimal concurrency if not specified
        if max_concurrent is None:
            max_concurrent = self._calculate_optimal_concurrency(len(proxies))
        else:
            # Cap at reasonable maximum to prevent overwhelming servers
            max_concurrent = min(max_concurrent, 300)  # Increased for professional use
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        # Create validator instance
        validator = AsyncProxyValidator(self.config)
        
        self.logger.info(f"Starting professional async validation of {len(proxies)} proxies with {max_concurrent} max concurrent")
        
        try:
            # Create tasks for all proxies
            tasks = []
            for proxy in proxies:
                task = validator.validate_single(proxy, semaphore)
                tasks.append(task)
            
            # Execute all tasks concurrently with better error handling
            completed = 0
            for task in asyncio.as_completed(tasks):
                try:
                    result = await task
                    results.append(result)
                    
                    # Update stats
                    if result.is_valid:
                        self.stats['total_valid'] += 1
                    else:
                        self.stats['total_invalid'] += 1
                    
                    completed += 1
                    self.stats['total_processed'] = completed
                    
                    # Record performance metrics
                    if self.performance_monitor:
                        self.performance_monitor.record_proxy_result(
                            result.is_valid, 
                            result.response_time or 0.0
                        )
                    
                    # Progress callback
                    if progress_callback:
                        progress_callback(completed, len(proxies), result)
                
                except Exception as e:
                    self.stats['total_errors'] += 1
                    completed += 1
                    self.stats['total_processed'] = completed
                    self.logger.debug(f"Task failed: {e}")
                    
                    # Create error result for failed task
                    if len(results) + self.stats['total_errors'] <= len(proxies):
                        proxy_index = len(results) + self.stats['total_errors'] - 1
                        error_proxy = proxies[proxy_index] if proxy_index < len(proxies) else proxies[0]
                        error_result = ValidationResult(proxy=error_proxy)
                        error_result.failure_reason = FailureReason.UNKNOWN_ERROR
                        error_result.error_message = str(e)
                        results.append(error_result)
        
        except Exception as e:
            self.logger.error(f"Batch validation failed: {e}")
        
        self.stats['end_time'] = time.time()
        
        # Record batch completion for performance monitoring
        if self.performance_monitor:
            batch_duration = self.stats['end_time'] - self.stats['start_time']
            self.performance_monitor.record_batch_completion(
                len(proxies), self.stats['total_valid'], 
                batch_duration, max_concurrent
            )
            
            # Stop monitoring and get performance report
            self.performance_monitor.stop_monitoring()
            perf_report = self.performance_monitor.get_performance_report()
        
        # Create batch result
        batch_result = BatchValidationResult(
            total_proxies=len(proxies),
            valid_proxies=self.stats['total_valid'],
            invalid_proxies=self.stats['total_invalid'],
            results=results,
            total_time=self.stats['end_time'] - self.stats['start_time']
        )
        
        # Calculate statistics
        batch_result.calculate_statistics()
        
        # Log performance with professional metrics
        duration = batch_result.total_time
        proxies_per_second = len(results) / duration if duration > 0 else 0
        
        if self.performance_monitor and 'current_performance' in perf_report:
            current_perf = perf_report['current_performance']
            system_res = perf_report['system_resources']
            
            self.logger.info(
                f"Professional async validation completed: {batch_result.valid_proxies}/{len(results)} valid "
                f"({batch_result.success_rate:.1f}%) in {duration:.1f}s ({proxies_per_second:.1f} proxies/s) "
                f"| CPU: {system_res['cpu_percent']:.1f}% | Memory: {system_res['memory_percent']:.1f}% "
                f"| Concurrency: {max_concurrent}"
            )
        else:
            self.logger.info(
                f"Async validation completed: {batch_result.valid_proxies}/{len(results)} valid "
                f"({batch_result.success_rate:.1f}%) in {duration:.1f}s "
                f"({proxies_per_second:.1f} proxies/s)"
            )
        
        return batch_result
    
    def _calculate_optimal_concurrency(self, proxy_count: int, max_concurrent: int = 300) -> int:
        """Calculate optimal concurrency based on proxy count and system resources"""
        try:
            import psutil
            cpu_count = psutil.cpu_count() or 4
            memory_gb = psutil.virtual_memory().total / (1024**3)
        except ImportError:
            # Fallback values if psutil not available
            cpu_count = 4
            memory_gb = 8
        
        # Professional-grade concurrency calculation
        if proxy_count <= 10:
            return min(proxy_count, max(5, cpu_count))
        elif proxy_count <= 50:
            return min(proxy_count, max(25, cpu_count * 5))
        elif proxy_count <= 200:
            return min(proxy_count, max(75, cpu_count * 10))
        elif proxy_count <= 1000:
            base_concurrent = cpu_count * 15
            if memory_gb >= 8:
                base_concurrent = min(base_concurrent * 2, 200)
            return min(proxy_count // 5, min(max_concurrent, base_concurrent))
        else:
            base_concurrent = cpu_count * 20
            if memory_gb >= 16:
                base_concurrent = min(base_concurrent * 2, 400)
            elif memory_gb >= 8:
                base_concurrent = min(base_concurrent * 1.5, 300)
            return min(proxy_count // 3, min(max_concurrent, base_concurrent))


class BatchValidator:
    """Unified batch validator that can use sync or async validation"""
    
    def __init__(self, config: Optional[ValidationConfig] = None):
        self.config = config or ValidationConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize sub-validators
        self.sync_validator = SyncBatchValidator(config)
        self.async_validator = AsyncBatchValidator(config)
    
    def validate_batch(self, proxies: List[ProxyInfo],
                      max_workers: Optional[int] = None,
                      progress_callback: Optional[Callable] = None,
                      use_async: Optional[bool] = None) -> BatchValidationResult:
        """Validate batch of proxies using sync or async method"""
        
        # Determine validation method
        if use_async is None:
            use_async = self.config.use_asyncio
        
        if use_async:
            try:
                # Run async validation
                return asyncio.run(self.async_validator.validate_batch_async(
                    proxies, max_workers, progress_callback
                ))
            except Exception as e:
                self.logger.warning(f"Async validation failed, falling back to sync: {e}")
                use_async = False
        
        if not use_async:
            # Use sync validation
            return self.sync_validator.validate_batch(
                proxies, max_workers, progress_callback
            )


# ===============================================================================
# ADAPTIVE VALIDATION INTEGRATION
# ===============================================================================

def create_adaptive_batch_validator(validation_config: Optional[ValidationConfig] = None) -> 'AdaptiveBatchValidator':
    """Create adaptive batch validator with dynamic threading"""
    try:
        from ..performance.thread_pool_manager import AdaptiveBatchValidator, get_optimal_thread_config
        
        # Get optimal thread configuration based on system resources
        thread_config = get_optimal_thread_config(100)  # Default estimate
        
        return AdaptiveBatchValidator(validation_config, thread_config)
    except ImportError:
        # Fallback to regular batch validator if performance module not available
        return BatchValidator(validation_config)


# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def calculate_optimal_concurrency(proxy_count: int, max_concurrent: int = 300) -> int:
    """Calculate optimal concurrency - utility function"""
    # Use the method from AsyncBatchValidator for consistency
    validator = AsyncBatchValidator()
    return validator._calculate_optimal_concurrency(proxy_count, max_concurrent)


async def validate_proxies_async(proxies: List[ProxyInfo], 
                               max_concurrent: Optional[int] = None,
                               config: Optional[ValidationConfig] = None) -> BatchValidationResult:
    """Utility function for async proxy validation with optimal concurrency"""
    if max_concurrent is None:
        max_concurrent = calculate_optimal_concurrency(len(proxies))
    
    validator = AsyncBatchValidator(config)
    return await validator.validate_batch_async(proxies, max_concurrent)


def validate_proxies_sync(proxies: List[ProxyInfo],
                         max_workers: Optional[int] = None,
                         config: Optional[ValidationConfig] = None) -> BatchValidationResult:
    """Utility function for sync proxy validation"""
    validator = SyncBatchValidator(config)
    return validator.validate_batch(proxies, max_workers)


def validate_proxies(proxies: List[ProxyInfo],
                    max_workers: Optional[int] = None,
                    config: Optional[ValidationConfig] = None,
                    use_async: bool = True) -> BatchValidationResult:
    """Unified validation function"""
    validator = BatchValidator(config)
    return validator.validate_batch(proxies, max_workers, use_async=use_async)