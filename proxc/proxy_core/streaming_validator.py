"""
Streaming Proxy Validator for Large Datasets

This module implements continuous proxy validation that processes proxies in
streams without accumulating all results in memory. Designed for Phase 3.1
to handle very large proxy datasets efficiently.

Features:
- Streaming validation pipeline
- Memory-efficient result handling
- Adaptive batch processing
- Real-time output streaming
- Garbage collection optimization
"""

import asyncio
import gc
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, List, Optional, Dict, Any, Union, AsyncIterator, Callable
import threading
import queue

from .memory_manager import MemoryMonitor, AdaptiveBatchSizer, MemoryStats
from .models import ProxyInfo, ProxyStatus, ValidationStatus
from ..proxy_cli.cli_imports import log_structured, print_info, print_warning, print_success


@dataclass
class ValidationBatch:
    """A batch of proxies for validation"""
    proxies: List[ProxyInfo]
    batch_id: int
    timestamp: datetime = field(default_factory=datetime.now)
    
    def __len__(self):
        return len(self.proxies)


@dataclass
class ValidationResult:
    """Result of validating a single proxy"""
    proxy: ProxyInfo
    is_valid: bool
    response_time: Optional[float] = None
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'host': self.proxy.host,
            'port': self.proxy.port,
            'protocol': self.proxy.protocol.value,
            'is_valid': self.is_valid,
            'response_time': self.response_time,
            'error_message': self.error_message,
            'timestamp': self.timestamp.isoformat(),
            'source': getattr(self.proxy, 'source', 'unknown')
        }


@dataclass
class BatchResult:
    """Result of validating a batch of proxies"""
    batch_id: int
    results: List[ValidationResult]
    processing_time: float
    valid_count: int
    invalid_count: int
    memory_used_mb: float
    timestamp: datetime = field(default_factory=datetime.now)
    
    def get_valid_results(self) -> List[ValidationResult]:
        """Get only valid proxy results"""
        return [r for r in self.results if r.is_valid]
    
    def get_invalid_results(self) -> List[ValidationResult]:
        """Get only invalid proxy results"""
        return [r for r in self.results if not r.is_valid]


class StreamingOutputWriter:
    """Handles streaming output of validation results to files"""
    
    def __init__(self, output_file: Union[str, Path], output_format: str = 'json'):
        self.output_file = Path(output_file)
        self.output_format = output_format.lower()
        self.file_handle = None
        self.written_count = 0
        self.lock = threading.Lock()
        
        # Ensure output directory exists
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
    
    def __enter__(self):
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def open(self):
        """Open output file for writing"""
        if self.output_format == 'json':
            self.file_handle = open(self.output_file, 'w', encoding='utf-8')
            self.file_handle.write('[\n')  # Start JSON array
        elif self.output_format == 'txt':
            self.file_handle = open(self.output_file, 'w', encoding='utf-8')
        else:
            raise ValueError(f"Unsupported output format: {self.output_format}")
    
    def close(self):
        """Close output file"""
        if self.file_handle:
            if self.output_format == 'json':
                # Close JSON array
                if self.written_count > 0:
                    self.file_handle.write('\n')
                self.file_handle.write(']\n')
            self.file_handle.close()
            self.file_handle = None
            
            log_structured('INFO', f"Output file closed: {self.output_file}",
                          written_count=self.written_count,
                          output_format=self.output_format)
    
    def write_results(self, results: List[ValidationResult], valid_only: bool = True):
        """Write validation results to output file"""
        if not self.file_handle:
            return
        
        with self.lock:
            for result in results:
                if valid_only and not result.is_valid:
                    continue
                
                if self.output_format == 'json':
                    if self.written_count > 0:
                        self.file_handle.write(',\n')
                    json.dump(result.to_dict(), self.file_handle, indent=2)
                elif self.output_format == 'txt':
                    proxy = result.proxy
                    self.file_handle.write(f"{proxy.host}:{proxy.port}\n")
                
                self.written_count += 1
            
            # Flush to ensure data is written
            self.file_handle.flush()


class StreamingValidator:
    """
    Memory-efficient proxy validator that processes proxies in streaming batches
    without accumulating all results in memory.
    """
    
    def __init__(self, max_workers: int = 50, initial_batch_size: int = 100):
        self.max_workers = max_workers
        self.memory_monitor = MemoryMonitor()
        self.batch_sizer = AdaptiveBatchSizer(initial_batch_size=initial_batch_size)
        self.validation_stats = {
            'total_processed': 0,
            'total_valid': 0,
            'total_invalid': 0,
            'batches_processed': 0,
            'start_time': None,
            'errors': 0
        }
        
        # Threading infrastructure
        self.executor: Optional[ThreadPoolExecutor] = None
        self.result_queue: Optional[queue.Queue] = None
        self.stop_processing = threading.Event()
        
        logging.getLogger(__name__).info("StreamingValidator initialized with max_workers=%d", max_workers)
    
    def validate_proxy_simple(self, proxy: ProxyInfo, timeout: float = 10.0) -> ValidationResult:
        """
        Simple proxy validation (placeholder - would use actual validation logic)
        This is a simplified version for demonstration
        """
        start_time = time.time()
        
        try:
            # Simulate validation logic (replace with actual implementation)
            import random
            import socket
            
            # Basic connectivity test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            try:
                result = sock.connect_ex((proxy.host, proxy.port))
                is_valid = result == 0
                response_time = time.time() - start_time
                error_message = None if is_valid else f"Connection failed (error {result})"
            except Exception as e:
                is_valid = False
                response_time = time.time() - start_time
                error_message = str(e)
            finally:
                sock.close()
            
            return ValidationResult(
                proxy=proxy,
                is_valid=is_valid,
                response_time=response_time,
                error_message=error_message
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            return ValidationResult(
                proxy=proxy,
                is_valid=False,
                response_time=response_time,
                error_message=f"Validation error: {e}"
            )
    
    def validate_batch(self, batch: ValidationBatch, timeout: float = 10.0) -> BatchResult:
        """Validate a batch of proxies and return results"""
        start_time = time.time()
        memory_before = self.memory_monitor.get_memory_stats().process_mb
        
        results = []
        
        # Use ThreadPoolExecutor for concurrent validation within batch
        with ThreadPoolExecutor(max_workers=min(len(batch.proxies), self.max_workers)) as executor:
            # Submit all validation tasks
            future_to_proxy = {
                executor.submit(self.validate_proxy_simple, proxy, timeout): proxy
                for proxy in batch.proxies
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_proxy):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    proxy = future_to_proxy[future]
                    error_result = ValidationResult(
                        proxy=proxy,
                        is_valid=False,
                        error_message=f"Validation exception: {e}"
                    )
                    results.append(error_result)
        
        processing_time = time.time() - start_time
        memory_after = self.memory_monitor.get_memory_stats().process_mb
        memory_used = memory_after - memory_before
        
        valid_count = sum(1 for r in results if r.is_valid)
        invalid_count = len(results) - valid_count
        
        # Record batch statistics for adaptive sizing
        self.batch_sizer.record_batch_stats(
            batch_size=len(batch.proxies),
            processing_time=processing_time,
            memory_used_mb=max(memory_used, 0.1),
            items_processed=len(results)
        )
        
        return BatchResult(
            batch_id=batch.batch_id,
            results=results,
            processing_time=processing_time,
            valid_count=valid_count,
            invalid_count=invalid_count,
            memory_used_mb=memory_used
        )
    
    def process_proxy_stream(
        self, 
        proxy_batches: Iterator[List[ProxyInfo]],
        output_writer: Optional[StreamingOutputWriter] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        timeout: float = 10.0,
        valid_only: bool = True
    ) -> Dict[str, Any]:
        """
        Process a stream of proxy batches with memory-efficient validation.
        
        Args:
            proxy_batches: Iterator yielding batches of ProxyInfo objects
            output_writer: Optional writer for streaming results to file
            progress_callback: Optional callback for progress updates
            timeout: Validation timeout per proxy
            valid_only: Whether to output only valid proxies
            
        Returns:
            Final processing statistics
        """
        self.validation_stats['start_time'] = time.time()
        batch_id = 0
        
        # Start memory monitoring
        self.memory_monitor.start_monitoring(check_interval=2.0)
        
        try:
            for proxy_list in proxy_batches:
                if not proxy_list:
                    continue
                
                batch_id += 1
                batch = ValidationBatch(proxies=proxy_list, batch_id=batch_id)
                
                # Adapt batch size based on memory pressure
                current_batch_size = self.batch_sizer.adapt_batch_size()
                
                # Process batch
                log_structured('DEBUG', f"Processing batch {batch_id}",
                              batch_size=len(batch.proxies),
                              current_optimal_batch_size=current_batch_size)
                
                batch_result = self.validate_batch(batch, timeout)
                
                # Update statistics
                self.validation_stats['total_processed'] += len(batch_result.results)
                self.validation_stats['total_valid'] += batch_result.valid_count
                self.validation_stats['total_invalid'] += batch_result.invalid_count
                self.validation_stats['batches_processed'] += 1
                
                # Stream results to output
                if output_writer:
                    try:
                        output_writer.write_results(batch_result.results, valid_only=valid_only)
                    except Exception as e:
                        log_structured('ERROR', f"Failed to write batch {batch_id} results",
                                     error=str(e))
                        self.validation_stats['errors'] += 1
                
                # Progress callback
                if progress_callback:
                    try:
                        progress_info = {
                            'batch_id': batch_id,
                            'batch_size': len(batch.proxies),
                            'valid_count': batch_result.valid_count,
                            'invalid_count': batch_result.invalid_count,
                            'total_processed': self.validation_stats['total_processed'],
                            'total_valid': self.validation_stats['total_valid'],
                            'processing_time': batch_result.processing_time,
                            'memory_used_mb': batch_result.memory_used_mb
                        }
                        progress_callback(progress_info)
                    except Exception as e:
                        log_structured('ERROR', "Progress callback failed", error=str(e))
                
                # Force garbage collection every 10 batches
                if batch_id % 10 == 0:
                    gc.collect()
                    memory_stats = self.memory_monitor.get_memory_stats()
                    log_structured('INFO', f"Memory status after batch {batch_id}",
                                  process_memory_mb=f"{memory_stats.process_mb:.1f}",
                                  system_memory_used_percent=f"{memory_stats.used_percent:.1%}")
        
        finally:
            # Stop memory monitoring
            self.memory_monitor.stop_monitoring()
        
        # Calculate final statistics
        end_time = time.time()
        total_time = end_time - self.validation_stats['start_time']
        
        final_stats = {
            **self.validation_stats,
            'total_time': total_time,
            'throughput': self.validation_stats['total_processed'] / max(total_time, 0.1),
            'success_rate': (self.validation_stats['total_valid'] / 
                           max(self.validation_stats['total_processed'], 1)) * 100
        }
        
        log_structured('INFO', "Streaming validation completed",
                      **{k: v for k, v in final_stats.items() if k != 'start_time'})
        
        return final_stats


class MemoryEfficientProxyInfo:
    """
    Memory-efficient proxy information storage using slots and compressed data.
    Reduces memory footprint compared to full ProxyInfo objects.
    """
    __slots__ = ('_host', '_port', '_protocol', '_source', '_metadata')
    
    def __init__(self, host: str, port: int, protocol: str, source: str = None):
        self._host = host
        self._port = port
        self._protocol = protocol
        self._source = source
        self._metadata = None  # Only created when needed
    
    @property
    def host(self) -> str:
        return self._host
    
    @property 
    def port(self) -> int:
        return self._port
    
    @property
    def protocol(self) -> str:
        return self._protocol
    
    @property
    def source(self) -> Optional[str]:
        return self._source
    
    def to_proxy_info(self) -> ProxyInfo:
        """Convert to full ProxyInfo object when needed"""
        from .models import ProxyProtocol
        return ProxyInfo(
            host=self._host,
            port=self._port,
            protocol=ProxyProtocol(self._protocol),
            source=self._source or "memory_efficient"
        )
    
    def __str__(self):
        return f"{self._host}:{self._port}"
    
    def __repr__(self):
        return f"MemoryEfficientProxyInfo(host='{self._host}', port={self._port}, protocol='{self._protocol}')"


def create_progress_callback(visual_manager) -> Callable[[Dict[str, Any]], None]:
    """Create a progress callback for visual feedback during streaming validation"""
    
    def progress_callback(info: Dict[str, Any]):
        """Progress callback that shows batch processing information"""
        batch_id = info['batch_id']
        
        # Show progress every 10 batches
        if batch_id % 10 == 0:
            throughput = info['total_processed'] / max(info.get('total_time', 1), 0.1)
            success_rate = (info['total_valid'] / max(info['total_processed'], 1)) * 100
            
            print_info(f"Batch {batch_id}: {info['total_processed']:,} processed, "
                      f"{info['total_valid']:,} valid ({success_rate:.1f}%), "
                      f"{throughput:.1f} proxies/sec")
        
        # Show memory warnings if needed
        if info.get('memory_used_mb', 0) > 100:
            print_warning(f"Batch {batch_id}: High memory usage ({info['memory_used_mb']:.1f} MB)")
    
    return progress_callback