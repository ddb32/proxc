"""
Memory Management for Large Proxy Datasets

This module implements memory-efficient components for processing large proxy
datasets without loading everything into memory simultaneously. Designed for
Phase 3.1 of the improvement roadmap to enable processing of 10k+ proxies.

Features:
- Generator-based proxy loading 
- Memory pressure monitoring
- Adaptive batch sizing
- Garbage collection optimization
- Memory usage reporting
"""

import gc
import json
import logging
import os
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, List, Optional, Dict, Any, Union, Tuple, Generator
from threading import Event, Thread
import threading

# Optional imports with fallbacks
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from .models import ProxyInfo, ProxyProtocol
from ..proxy_cli.cli_imports import log_structured, print_warning, print_info

logger = logging.getLogger(__name__)


@dataclass
class MemoryStats:
    """Memory usage statistics"""
    total_mb: float
    available_mb: float
    used_mb: float
    used_percent: float
    process_mb: float
    process_percent: float
    swap_used_mb: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class BatchStats:
    """Statistics for adaptive batch sizing"""
    batch_size: int
    processing_time: float
    memory_used_mb: float
    items_processed: int
    throughput: float  # items per second
    memory_efficiency: float  # items per MB
    timestamp: datetime = field(default_factory=datetime.now)


class MemoryMonitor:
    """Real-time memory pressure monitoring with psutil integration"""
    
    def __init__(self, warning_threshold: float = 0.8, critical_threshold: float = 0.9):
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold
        self.monitoring = False
        self.monitor_thread: Optional[Thread] = None
        self.stop_event = Event()
        self.last_stats: Optional[MemoryStats] = None
        self.pressure_callbacks = []
        
        if not HAS_PSUTIL:
            print_warning("psutil not available - memory monitoring will use basic fallback")
    
    def get_memory_stats(self) -> MemoryStats:
        """Get current memory statistics"""
        if HAS_PSUTIL:
            # Use psutil for accurate monitoring
            memory = psutil.virtual_memory()
            process = psutil.Process()
            process_info = process.memory_info()
            
            try:
                swap = psutil.swap_memory()
                swap_used_mb = swap.used / 1024 / 1024
            except:
                swap_used_mb = 0.0
            
            stats = MemoryStats(
                total_mb=memory.total / 1024 / 1024,
                available_mb=memory.available / 1024 / 1024,
                used_mb=memory.used / 1024 / 1024,
                used_percent=memory.percent / 100.0,
                process_mb=process_info.rss / 1024 / 1024,
                process_percent=process.memory_percent() / 100.0,
                swap_used_mb=swap_used_mb
            )
        else:
            # Fallback using basic system info
            total_mb = 1024  # Assume 1GB if unknown
            try:
                # Try to get some basic info
                if hasattr(os, 'sysconf') and hasattr(os, 'sysconf_names'):
                    if 'SC_PAGE_SIZE' in os.sysconf_names and 'SC_PHYS_PAGES' in os.sysconf_names:
                        page_size = os.sysconf('SC_PAGE_SIZE')
                        phys_pages = os.sysconf('SC_PHYS_PAGES')
                        total_mb = (page_size * phys_pages) / 1024 / 1024
            except:
                pass
            
            # Estimate current process memory
            process_mb = sys.getsizeof(gc.get_objects()) / 1024 / 1024 if hasattr(sys, 'getsizeof') else 50
            
            stats = MemoryStats(
                total_mb=total_mb,
                available_mb=total_mb * 0.5,  # Rough estimate
                used_mb=total_mb * 0.5,
                used_percent=0.5,
                process_mb=process_mb,
                process_percent=process_mb / total_mb
            )
        
        self.last_stats = stats
        return stats
    
    def check_pressure(self) -> str:
        """Check current memory pressure level"""
        stats = self.get_memory_stats()
        
        if stats.used_percent >= self.critical_threshold:
            return "critical"
        elif stats.used_percent >= self.warning_threshold:
            return "warning"
        else:
            return "normal"
    
    def add_pressure_callback(self, callback):
        """Add callback to be called when memory pressure changes"""
        self.pressure_callbacks.append(callback)
    
    def start_monitoring(self, check_interval: float = 5.0):
        """Start background memory monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.stop_event.clear()
        
        def monitor_loop():
            last_pressure = "normal"
            
            while not self.stop_event.wait(check_interval):
                try:
                    current_pressure = self.check_pressure()
                    
                    if current_pressure != last_pressure:
                        log_structured('INFO', f"Memory pressure changed: {last_pressure} -> {current_pressure}",
                                     old_pressure=last_pressure, new_pressure=current_pressure)
                        
                        # Call registered callbacks
                        for callback in self.pressure_callbacks:
                            try:
                                callback(current_pressure, self.last_stats)
                            except Exception as e:
                                logger.error(f"Memory pressure callback failed: {e}")
                        
                        last_pressure = current_pressure
                
                except Exception as e:
                    logger.error(f"Memory monitoring error: {e}")
        
        self.monitor_thread = Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        log_structured('INFO', "Memory monitoring started", 
                      warning_threshold=self.warning_threshold,
                      critical_threshold=self.critical_threshold)
    
    def stop_monitoring(self):
        """Stop background memory monitoring"""
        if not self.monitoring:
            return
        
        self.monitoring = False
        self.stop_event.set()
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
            self.monitor_thread = None
        
        log_structured('INFO', "Memory monitoring stopped")


class AdaptiveBatchSizer:
    """Adaptive batch sizing based on available memory and performance metrics"""
    
    def __init__(self, initial_batch_size: int = 100, min_batch_size: int = 10, max_batch_size: int = 5000):
        self.current_batch_size = initial_batch_size
        self.min_batch_size = min_batch_size
        self.max_batch_size = max_batch_size
        
        # Performance history for adaptive sizing
        self.batch_history: List[BatchStats] = []
        self.memory_monitor = MemoryMonitor()
        
        # Adaptive parameters
        self.target_memory_usage_mb = 100  # Target memory per batch
        self.performance_window = 5  # Number of batches to consider for adaptation
    
    def calculate_optimal_batch_size(self, available_memory_mb: float, item_size_estimate: float = 1.0) -> int:
        """Calculate optimal batch size based on available memory"""
        # Conservative estimate: use 10% of available memory
        target_memory_mb = min(available_memory_mb * 0.1, self.target_memory_usage_mb)
        
        # Estimate items per MB (with some overhead for processing)
        items_per_mb = 1000 / item_size_estimate  # Rough estimate
        optimal_size = int(target_memory_mb * items_per_mb)
        
        # Apply bounds
        return max(self.min_batch_size, min(optimal_size, self.max_batch_size))
    
    def adapt_batch_size(self) -> int:
        """Adapt batch size based on recent performance"""
        if len(self.batch_history) < 2:
            return self.current_batch_size
        
        # Get recent performance data
        recent_batches = self.batch_history[-self.performance_window:]
        avg_throughput = sum(b.throughput for b in recent_batches) / len(recent_batches)
        avg_memory_efficiency = sum(b.memory_efficiency for b in recent_batches) / len(recent_batches)
        
        # Check memory pressure
        memory_stats = self.memory_monitor.get_memory_stats()
        pressure = self.memory_monitor.check_pressure()
        
        if pressure == "critical":
            # Reduce batch size aggressively
            new_size = max(self.min_batch_size, int(self.current_batch_size * 0.5))
            log_structured('WARNING', "Critical memory pressure - reducing batch size",
                          old_batch_size=self.current_batch_size, new_batch_size=new_size)
        elif pressure == "warning":
            # Reduce batch size moderately
            new_size = max(self.min_batch_size, int(self.current_batch_size * 0.8))
            log_structured('INFO', "High memory pressure - reducing batch size",
                          old_batch_size=self.current_batch_size, new_batch_size=new_size)
        elif len(recent_batches) >= 3:
            # Normal pressure - optimize based on performance
            last_batch = recent_batches[-1]
            prev_batch = recent_batches[-2]
            
            # If throughput is improving and memory efficiency is good, try larger batches
            if (last_batch.throughput > prev_batch.throughput * 1.1 and
                last_batch.memory_efficiency > avg_memory_efficiency and
                memory_stats.available_mb > 200):
                new_size = min(self.max_batch_size, int(self.current_batch_size * 1.2))
            # If performance is declining, reduce batch size
            elif last_batch.throughput < prev_batch.throughput * 0.9:
                new_size = max(self.min_batch_size, int(self.current_batch_size * 0.9))
            else:
                new_size = self.current_batch_size
        else:
            new_size = self.current_batch_size
        
        self.current_batch_size = new_size
        return new_size
    
    def record_batch_stats(self, batch_size: int, processing_time: float, 
                          memory_used_mb: float, items_processed: int):
        """Record statistics from a processed batch"""
        if processing_time > 0 and items_processed > 0:
            throughput = items_processed / processing_time
            memory_efficiency = items_processed / max(memory_used_mb, 0.1)
            
            stats = BatchStats(
                batch_size=batch_size,
                processing_time=processing_time,
                memory_used_mb=memory_used_mb,
                items_processed=items_processed,
                throughput=throughput,
                memory_efficiency=memory_efficiency
            )
            
            self.batch_history.append(stats)
            
            # Keep only recent history to avoid memory growth
            if len(self.batch_history) > 20:
                self.batch_history = self.batch_history[-15:]
            
            log_structured('DEBUG', "Batch processing stats recorded",
                          batch_size=batch_size, throughput=f"{throughput:.1f} items/sec",
                          memory_efficiency=f"{memory_efficiency:.1f} items/MB")


class StreamingProxyLoader:
    """Generator-based proxy loader that avoids loading entire files into memory"""
    
    def __init__(self, memory_monitor: Optional[MemoryMonitor] = None):
        self.memory_monitor = memory_monitor or MemoryMonitor()
        self.total_lines_processed = 0
        self.valid_proxies_generated = 0
        self.invalid_lines = 0
    
    def load_proxies_streaming(self, file_path: Union[str, Path], 
                              protocol_mode: str = "auto-detect",
                              target_protocol: Optional[str] = None,
                              batch_size: int = 1000) -> Iterator[List[ProxyInfo]]:
        """
        Stream proxies from file in batches without loading entire file into memory.
        
        Yields:
            List[ProxyInfo]: Batches of parsed proxy objects
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Proxy file not found: {file_path}")
        
        log_structured('INFO', "Starting streaming proxy loading",
                      file_path=str(file_path), batch_size=batch_size,
                      protocol_mode=protocol_mode)
        
        # Detect file format
        file_format = self._detect_file_format(file_path)
        
        if file_format == 'json':
            yield from self._stream_json_file(file_path, batch_size)
        else:
            yield from self._stream_text_file(file_path, protocol_mode, target_protocol, batch_size)
    
    def _detect_file_format(self, file_path: Path) -> str:
        """Detect file format based on extension and content"""
        suffix = file_path.suffix.lower()
        if suffix == '.json':
            return 'json'
        else:
            return 'text'
    
    def _stream_text_file(self, file_path: Path, protocol_mode: str, 
                         target_protocol: Optional[str], batch_size: int) -> Iterator[List[ProxyInfo]]:
        """Stream proxies from text file line by line"""
        batch = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                # Periodically check memory pressure
                if line_num % 1000 == 0:
                    pressure = self.memory_monitor.check_pressure()
                    if pressure == "critical":
                        log_structured('WARNING', "Critical memory pressure during file loading",
                                     line_number=line_num, file_path=str(file_path))
                        # Force garbage collection
                        gc.collect()
                
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                self.total_lines_processed += 1
                
                try:
                    proxy = self._parse_proxy_line(line, protocol_mode, target_protocol, str(file_path))
                    if proxy:
                        batch.append(proxy)
                        self.valid_proxies_generated += 1
                        
                        if len(batch) >= batch_size:
                            yield batch
                            batch = []
                    else:
                        self.invalid_lines += 1
                        
                except Exception as e:
                    log_structured('DEBUG', f"Failed to parse line {line_num}",
                                 line_content=line[:50], error=str(e))
                    self.invalid_lines += 1
        
        # Yield remaining batch
        if batch:
            yield batch
    
    def _stream_json_file(self, file_path: Path, batch_size: int) -> Iterator[List[ProxyInfo]]:
        """Stream proxies from JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            items = []
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict) and 'proxies' in data:
                items = data['proxies']
            
            batch = []
            for item_num, item in enumerate(items, 1):
                self.total_lines_processed += 1
                
                try:
                    proxy = self._parse_json_proxy(item, str(file_path))
                    if proxy:
                        batch.append(proxy)
                        self.valid_proxies_generated += 1
                        
                        if len(batch) >= batch_size:
                            yield batch
                            batch = []
                    else:
                        self.invalid_lines += 1
                        
                except Exception as e:
                    log_structured('DEBUG', f"Failed to parse JSON item {item_num}",
                                 error=str(e))
                    self.invalid_lines += 1
            
            # Yield remaining batch
            if batch:
                yield batch
                
        except Exception as e:
            log_structured('ERROR', "JSON file loading failed", 
                          file_path=str(file_path), error=str(e))
            raise
    
    def _parse_proxy_line(self, line: str, protocol_mode: str, 
                         target_protocol: Optional[str], source: str) -> Optional[ProxyInfo]:
        """Parse a single proxy line (simplified version)"""
        try:
            # This is a simplified parser - in production would use the full parsing logic
            if ':' not in line:
                return None
            
            parts = line.split(':')
            if len(parts) < 2:
                return None
            
            host = parts[0].strip()
            port = int(parts[1].strip())
            
            # Determine protocol
            if target_protocol:
                protocol = ProxyProtocol(target_protocol.lower())
            elif len(parts) > 2:
                protocol_str = parts[2].strip().lower()
                try:
                    protocol = ProxyProtocol(protocol_str)
                except ValueError:
                    protocol = ProxyProtocol.HTTP  # Default fallback
            else:
                protocol = ProxyProtocol.HTTP  # Default
            
            return ProxyInfo(
                host=host,
                port=port,
                protocol=protocol,
                source=source
            )
            
        except Exception:
            return None
    
    def _parse_json_proxy(self, item: Dict, source: str) -> Optional[ProxyInfo]:
        """Parse a single JSON proxy item"""
        try:
            if not isinstance(item, dict):
                return None
            
            host = item.get('host') or item.get('ip')
            port = item.get('port')
            protocol = item.get('protocol', 'http')
            
            if not host or not port:
                return None
            
            return ProxyInfo(
                host=host,
                port=int(port),
                protocol=ProxyProtocol(protocol.lower()),
                source=source
            )
            
        except Exception:
            return None
    
    def get_loading_stats(self) -> Dict[str, Any]:
        """Get statistics about the loading process"""
        return {
            'total_lines_processed': self.total_lines_processed,
            'valid_proxies_generated': self.valid_proxies_generated,
            'invalid_lines': self.invalid_lines,
            'success_rate': (self.valid_proxies_generated / max(self.total_lines_processed, 1)) * 100
        }


@contextmanager
def memory_optimized_processing():
    """Context manager for memory-optimized processing sessions"""
    # Record initial memory state
    monitor = MemoryMonitor()
    initial_stats = monitor.get_memory_stats()
    
    # Start monitoring
    monitor.start_monitoring(check_interval=2.0)
    
    # Force garbage collection before starting
    gc.collect()
    
    try:
        yield monitor
    finally:
        # Clean up
        monitor.stop_monitoring()
        
        # Force garbage collection
        gc.collect()
        
        # Report final memory usage
        final_stats = monitor.get_memory_stats()
        memory_change = final_stats.process_mb - initial_stats.process_mb
        
        log_structured('INFO', "Memory-optimized processing completed",
                      initial_memory_mb=f"{initial_stats.process_mb:.1f}",
                      final_memory_mb=f"{final_stats.process_mb:.1f}",
                      memory_change_mb=f"{memory_change:+.1f}")