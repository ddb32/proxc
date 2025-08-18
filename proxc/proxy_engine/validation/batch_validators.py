"""Batch Validators - High-performance batch proxy validation with enhanced cleanup mechanisms"""

import asyncio
import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Callable, Dict, Any

from ...proxy_core.models import ProxyInfo
from .validation_config import ValidationConfig, FailureReason
from .validation_results import ValidationResult, BatchValidationResult
from .sync_validators import SyncProxyValidator
from .async_validators import AsyncProxyValidator
from .session_cleanup import (
    SessionCleanupManager, ResourceType, CleanupPriority,
    managed_validation_session, register_cleanup_resource
)
from .resource_leak_detector import (
    get_global_leak_detector, register_connection_for_leak_detection,
    unregister_connection_from_leak_detection, register_thread_for_leak_detection,
    unregister_thread_from_leak_detection
)


class SyncBatchValidator:
    """Synchronous batch validator using thread pool with enhanced cleanup mechanisms"""
    
    def __init__(self, config: Optional[ValidationConfig] = None, 
                 cleanup_manager: Optional[SessionCleanupManager] = None):
        self.config = config or ValidationConfig()
        self.cleanup_manager = cleanup_manager or SessionCleanupManager()
        self.leak_detector = get_global_leak_detector()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Performance tracking
        self.stats = {
            'total_processed': 0,
            'total_valid': 0,
            'total_invalid': 0,
            'total_errors': 0,
            'cleanup_operations': 0,
            'interrupted_sessions': 0,
            'resource_leaks_detected': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Resource tracking
        self.active_sessions = set()
        self.thread_pools = {}
        self.validators = {}
        
        self.logger.info("SyncBatchValidator initialized with enhanced cleanup mechanisms and leak detection")
    
    def validate_batch(self, proxies: List[ProxyInfo], 
                      max_workers: Optional[int] = None,
                      progress_callback: Optional[Callable] = None) -> BatchValidationResult:
        """Validate proxies using thread pool with enhanced cleanup and interruption handling"""
        
        if not proxies:
            return BatchValidationResult(total_proxies=0, valid_proxies=0, invalid_proxies=0)
        
        # Create unique session for this batch
        session_id = f"sync_batch_{uuid.uuid4().hex[:8]}"
        
        try:
            with managed_validation_session(session_id, self.cleanup_manager):
                return self._validate_batch_with_cleanup(session_id, proxies, max_workers, progress_callback)
        except KeyboardInterrupt:
            self.logger.warning(f"Batch validation interrupted for session {session_id}")
            self.stats['interrupted_sessions'] += 1
            raise
        except Exception as e:
            self.logger.error(f"Batch validation failed for session {session_id}: {e}")
            raise
    
    def _validate_batch_with_cleanup(self, session_id: str, proxies: List[ProxyInfo],
                                   max_workers: Optional[int], 
                                   progress_callback: Optional[Callable]) -> BatchValidationResult:
        """Internal validation method with cleanup resource management"""
        
        self.stats['start_time'] = time.time()
        self.active_sessions.add(session_id)
        
        # Calculate optimal workers if not specified
        if max_workers is None:
            max_workers = min(self.config.max_workers, len(proxies))
        
        self.logger.info(f"Starting sync batch validation of {len(proxies)} proxies with {max_workers} workers")
        
        results = []
        completed = 0
        executor = None
        shared_validators = []
        
        try:
            # Create shared validator pool for connection reuse optimization
            for i in range(min(max_workers, 10)):  # Limit to reasonable number of shared validators
                validator = SyncProxyValidator(self.config)
                shared_validators.append(validator)
                
                # Register validator for cleanup
                validator_id = f"validator_{session_id}_{i}"
                self.validators[validator_id] = validator
                
                register_cleanup_resource(
                    session_id, validator_id, ResourceType.HTTP_CONNECTION,
                    validator, lambda v=validator: self._cleanup_validator(v),
                    CleanupPriority.HIGH
                )
                
                # Register connection for leak detection
                from datetime import datetime
                register_connection_for_leak_detection(
                    validator_id, "http", created_at=datetime.now()
                )
            
            # Create thread pool executor
            executor = ThreadPoolExecutor(max_workers=max_workers)
            executor_id = f"executor_{session_id}"
            self.thread_pools[executor_id] = executor
            
            # Register thread pool for cleanup
            register_cleanup_resource(
                session_id, executor_id, ResourceType.THREAD_POOL,
                executor, lambda: self._cleanup_thread_pool(executor),
                CleanupPriority.CRITICAL
            )
            
            # Register thread pool for leak detection
            register_thread_for_leak_detection(
                executor_id, f"ThreadPoolExecutor-{session_id}", "batch_validation"
            )
            
            # Submit all validation tasks with shared validators for connection reuse
            future_to_proxy = {}
            for i, proxy in enumerate(proxies):
                # Reuse validators to benefit from persistent connections
                validator = shared_validators[i % len(shared_validators)]
                future = executor.submit(self._safe_validate_proxy, validator, proxy, session_id)
                future_to_proxy[future] = proxy
            
            # Process completed tasks with interruption handling
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
        
        except KeyboardInterrupt:
            self.logger.warning(f"Validation session {session_id} interrupted - triggering cleanup")
            self.cleanup_manager.mark_session_interrupted(session_id, "keyboard_interrupt")
            raise
        
        except Exception as e:
            self.logger.error(f"Validation session {session_id} failed: {e}")
            self.cleanup_manager.mark_session_interrupted(session_id, f"exception_{type(e).__name__}")
            raise
        
        finally:
            # Manual cleanup for immediate resource release
            try:
                self._immediate_cleanup(session_id, executor, shared_validators)
            except Exception as cleanup_error:
                self.logger.error(f"Immediate cleanup failed: {cleanup_error}")
            
            self.active_sessions.discard(session_id)
        
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
    
    def _safe_validate_proxy(self, validator: SyncProxyValidator, proxy: ProxyInfo, session_id: str) -> ValidationResult:
        """Safely validate a proxy with error handling"""
        try:
            return validator.validate_proxy(proxy)
        except Exception as e:
            self.logger.warning(f"Proxy validation failed for {proxy.address} in session {session_id}: {e}")
            error_result = ValidationResult(proxy=proxy)
            error_result.failure_reason = FailureReason.UNKNOWN_ERROR
            error_result.error_message = str(e)
            return error_result
    
    def _cleanup_validator(self, validator: SyncProxyValidator):
        """Clean up a validator instance"""
        try:
            # Find and unregister from leak detection
            for validator_id, stored_validator in self.validators.items():
                if stored_validator is validator:
                    unregister_connection_from_leak_detection(validator_id)
                    break
            
            if hasattr(validator, 'session') and validator.session:
                validator.session.close()
            if hasattr(validator, 'close'):
                validator.close()
            self.stats['cleanup_operations'] += 1
        except Exception as e:
            self.logger.debug(f"Validator cleanup failed: {e}")
    
    def _cleanup_thread_pool(self, executor: ThreadPoolExecutor):
        """Clean up thread pool executor"""
        try:
            # Find and unregister from leak detection
            for executor_id, stored_executor in self.thread_pools.items():
                if stored_executor is executor:
                    unregister_thread_from_leak_detection(executor_id)
                    break
            
            executor.shutdown(wait=False)
            self.stats['cleanup_operations'] += 1
        except Exception as e:
            self.logger.debug(f"Thread pool cleanup failed: {e}")
    
    def _immediate_cleanup(self, session_id: str, executor: Optional[ThreadPoolExecutor], validators: List):
        """Perform immediate cleanup of session resources"""
        try:
            # Clean up validators
            for validator in validators:
                try:
                    self._cleanup_validator(validator)
                except Exception as e:
                    self.logger.debug(f"Validator cleanup failed: {e}")
            
            # Clean up thread pool
            if executor:
                try:
                    self._cleanup_thread_pool(executor)
                except Exception as e:
                    self.logger.debug(f"Executor cleanup failed: {e}")
            
            # Remove from tracking
            validator_ids = [vid for vid in self.validators.keys() if session_id in vid]
            for vid in validator_ids:
                self.validators.pop(vid, None)
            
            executor_ids = [eid for eid in self.thread_pools.keys() if session_id in eid]
            for eid in executor_ids:
                self.thread_pools.pop(eid, None)
            
            self.logger.debug(f"Immediate cleanup completed for session {session_id}")
            
        except Exception as e:
            self.logger.error(f"Immediate cleanup failed for session {session_id}: {e}")
    
    def get_cleanup_status(self) -> Dict[str, Any]:
        """Get cleanup status and resource information"""
        return {
            'active_sessions': len(self.active_sessions),
            'tracked_validators': len(self.validators),
            'tracked_thread_pools': len(self.thread_pools),
            'cleanup_stats': self.stats.copy(),
            'cleanup_manager_status': self.cleanup_manager.get_cleanup_status() if self.cleanup_manager else {}
        }
    
    def shutdown(self):
        """Shutdown validator with cleanup"""
        try:
            # Mark all active sessions as interrupted
            for session_id in list(self.active_sessions):
                self.cleanup_manager.mark_session_interrupted(session_id, "shutdown")
            
            # Cleanup all tracked resources
            for validator in self.validators.values():
                try:
                    self._cleanup_validator(validator)
                except Exception:
                    pass
            
            for executor in self.thread_pools.values():
                try:
                    self._cleanup_thread_pool(executor)
                except Exception:
                    pass
            
            # Shutdown cleanup manager
            if self.cleanup_manager:
                self.cleanup_manager.shutdown()
            
            self.logger.info("SyncBatchValidator shutdown completed")
            
        except Exception as e:
            self.logger.error(f"Shutdown failed: {e}")


class OptimizedConnectionReuseBatchValidator:
    """Advanced batch validator optimized for connection reuse"""
    
    def __init__(self, config: Optional[ValidationConfig] = None):
        self.config = config or ValidationConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Connection reuse optimization settings from config
        self.validator_pool_size = min(self.config.max_workers, 
                                      getattr(self.config, 'validator_pool_size', 15))
        self.connection_affinity_enabled = getattr(self.config, 'enable_connection_affinity', True)
        self.batch_grouping_enabled = getattr(self.config, 'enable_proxy_grouping', True)
        self.prewarm_connections = getattr(self.config, 'prewarm_connections', False)
        
        # Performance tracking
        self.stats = {
            'total_processed': 0,
            'total_valid': 0,
            'total_invalid': 0,
            'total_errors': 0,
            'connection_reuse_count': 0,
            'validator_pool_hits': 0,
            'start_time': None,
            'end_time': None
        }
        
        self.logger.info("OptimizedConnectionReuseBatchValidator initialized")
    
    def validate_batch_optimized(self, proxies: List[ProxyInfo], 
                                max_workers: Optional[int] = None,
                                progress_callback: Optional[Callable] = None) -> BatchValidationResult:
        """Validate batch with advanced connection reuse optimization"""
        
        if not proxies:
            return BatchValidationResult(total_proxies=0, valid_proxies=0, invalid_proxies=0)
        
        self.stats['start_time'] = time.time()
        
        # Calculate optimal workers
        if max_workers is None:
            max_workers = min(self.config.max_workers, len(proxies))
        
        self.logger.info(f"Starting optimized batch validation of {len(proxies)} proxies with connection reuse")
        
        # Group proxies for optimal connection reuse
        if self.batch_grouping_enabled:
            grouped_proxies = self._group_proxies_for_connection_reuse(proxies)
        else:
            grouped_proxies = [proxies]
        
        # Create validator pool for connection reuse
        validator_pool = self._create_validator_pool()
        
        results = []
        completed = 0
        
        # Process groups to maximize connection reuse
        for group in grouped_proxies:
            group_results = self._validate_proxy_group(
                group, validator_pool, max_workers, progress_callback, completed, len(proxies)
            )
            results.extend(group_results)
            completed += len(group_results)
            
            # Update stats
            for result in group_results:
                if result.is_valid:
                    self.stats['total_valid'] += 1
                else:
                    self.stats['total_invalid'] += 1
        
        self.stats['end_time'] = time.time()
        self.stats['total_processed'] = completed
        
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
        
        # Log performance with connection reuse metrics
        duration = batch_result.total_time
        proxies_per_second = len(results) / duration if duration > 0 else 0
        reuse_ratio = self.stats['connection_reuse_count'] / max(1, len(results))
        
        self.logger.info(
            f"Optimized batch validation completed: {batch_result.valid_proxies}/{len(results)} valid "
            f"({batch_result.success_rate:.1f}%) in {duration:.1f}s "
            f"({proxies_per_second:.1f} proxies/s) | Connection reuse: {reuse_ratio:.2f}x"
        )
        
        return batch_result
    
    def _create_validator_pool(self) -> List[SyncProxyValidator]:
        """Create optimized validator pool for connection reuse"""
        validator_pool = []
        for i in range(self.validator_pool_size):
            validator = SyncProxyValidator(self.config)
            # Pre-warm connections if configured
            if self.prewarm_connections:
                self._prewarm_validator_connections(validator)
            validator_pool.append(validator)
        
        self.logger.debug(f"Created validator pool with {len(validator_pool)} validators")
        return validator_pool
    
    def _group_proxies_for_connection_reuse(self, proxies: List[ProxyInfo]) -> List[List[ProxyInfo]]:
        """Group proxies to maximize connection reuse opportunities"""
        # Group by protocol and similar characteristics for better connection reuse
        groups = {}
        
        for proxy in proxies:
            # Create grouping key based on protocol and endpoint affinity
            group_key = self._get_connection_affinity_key(proxy)
            
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(proxy)
        
        # Convert to list and optimize group sizes
        grouped_proxies = list(groups.values())
        
        # Split large groups to maintain parallel processing efficiency
        optimized_groups = []
        for group in grouped_proxies:
            if len(group) > 50:  # Split large groups
                for i in range(0, len(group), 50):
                    optimized_groups.append(group[i:i + 50])
            else:
                optimized_groups.append(group)
        
        self.logger.debug(f"Grouped {len(proxies)} proxies into {len(optimized_groups)} groups for connection reuse")
        return optimized_groups
    
    def _get_connection_affinity_key(self, proxy: ProxyInfo) -> str:
        """Generate key for connection affinity grouping"""
        # Group by protocol primarily, then by auth requirements
        auth_type = "auth" if proxy.username and proxy.password else "no_auth"
        return f"{proxy.protocol.value}_{auth_type}"
    
    def _validate_proxy_group(self, proxy_group: List[ProxyInfo], 
                             validator_pool: List[SyncProxyValidator],
                             max_workers: int,
                             progress_callback: Optional[Callable],
                             base_completed: int,
                             total_proxies: int) -> List[ValidationResult]:
        """Validate a group of proxies with connection reuse optimization"""
        
        results = []
        group_workers = min(max_workers, len(proxy_group), len(validator_pool))
        
        with ThreadPoolExecutor(max_workers=group_workers) as executor:
            future_to_proxy = {}
            
            # Assign proxies to validators with affinity
            for i, proxy in enumerate(proxy_group):
                validator = validator_pool[i % len(validator_pool)]
                self.stats['validator_pool_hits'] += 1
                
                future = executor.submit(self._validate_with_connection_reuse, validator, proxy)
                future_to_proxy[future] = proxy
            
            # Collect results
            completed_in_group = 0
            for future in as_completed(future_to_proxy):
                proxy = future_to_proxy[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    completed_in_group += 1
                    total_completed = base_completed + completed_in_group
                    
                    # Progress callback
                    if progress_callback:
                        progress_callback(total_completed, total_proxies, result)
                
                except Exception as e:
                    self.stats['total_errors'] += 1
                    self.logger.error(f"Validation failed for {proxy.address}: {e}")
                    
                    # Create error result
                    error_result = ValidationResult(proxy=proxy)
                    error_result.failure_reason = FailureReason.UNKNOWN_ERROR
                    error_result.error_message = str(e)
                    results.append(error_result)
        
        return results
    
    def _validate_with_connection_reuse(self, validator: SyncProxyValidator, proxy: ProxyInfo) -> ValidationResult:
        """Validate proxy with connection reuse tracking"""
        result = validator.validate_proxy(proxy)
        
        # Track connection reuse (simplified metric)
        if result.is_valid and result.response_time and result.response_time < 5000:  # Fast response indicates reuse
            self.stats['connection_reuse_count'] += 1
        
        return result
    
    def _prewarm_validator_connections(self, validator: SyncProxyValidator):
        """Pre-warm validator connections for better performance"""
        try:
            # Pre-warm with a quick connection test
            from ...proxy_core.models import ProxyInfo, ProxyProtocol
            test_proxy = ProxyInfo(host="127.0.0.1", port=8080, protocol=ProxyProtocol.HTTP)
            # This will fail but will initialize the connection pools
            try:
                validator.validate_proxy(test_proxy)
            except:
                pass  # Expected to fail, just warming up pools
        except Exception:
            pass  # Prewarm is optional


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
        self.optimized_validator = OptimizedConnectionReuseBatchValidator(config)
    
    def validate_batch(self, proxies: List[ProxyInfo],
                      max_workers: Optional[int] = None,
                      progress_callback: Optional[Callable] = None,
                      use_async: Optional[bool] = None,
                      optimize_connection_reuse: Optional[bool] = None) -> BatchValidationResult:
        """Validate batch of proxies using sync, async, or optimized connection reuse method"""
        
        # Determine if connection reuse optimization should be used
        if optimize_connection_reuse is None:
            # Use optimization based on configuration settings
            threshold = getattr(self.config, 'connection_reuse_threshold', 20)
            reuse_enabled = getattr(self.config, 'enable_connection_reuse_optimization', True)
            optimize_connection_reuse = (len(proxies) >= threshold and 
                                       self.config.enable_connection_pooling and 
                                       reuse_enabled)
        
        # Use optimized connection reuse validator for better performance
        if optimize_connection_reuse:
            try:
                return self.optimized_validator.validate_batch_optimized(
                    proxies, max_workers, progress_callback
                )
            except Exception as e:
                self.logger.warning(f"Optimized validation failed, falling back to standard: {e}")
        
        # Determine validation method (async vs sync)
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
                    use_async: bool = True,
                    optimize_connection_reuse: bool = True) -> BatchValidationResult:
    """Unified validation function with connection reuse optimization"""
    validator = BatchValidator(config)
    return validator.validate_batch(
        proxies, max_workers, use_async=use_async, 
        optimize_connection_reuse=optimize_connection_reuse
    )


def validate_proxies_optimized(proxies: List[ProxyInfo],
                              max_workers: Optional[int] = None,
                              config: Optional[ValidationConfig] = None) -> BatchValidationResult:
    """High-performance validation with optimized connection reuse"""
    validator = OptimizedConnectionReuseBatchValidator(config)
    return validator.validate_batch_optimized(proxies, max_workers)


def create_optimized_batch_validator(config: Optional[ValidationConfig] = None) -> OptimizedConnectionReuseBatchValidator:
    """Create optimized batch validator for maximum connection reuse"""
    return OptimizedConnectionReuseBatchValidator(config)