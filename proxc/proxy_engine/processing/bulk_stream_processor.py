"""Bulk Stream Processor for Large-Scale Processing Optimization

Advanced streaming system that:
- Implements memory-efficient streaming for large proxy datasets
- Provides adaptive batching based on system resources
- Supports pipeline processing with backpressure handling
- Optimizes I/O operations with async streaming
- Implements data compression and efficient serialization
- Handles large file processing with minimal memory footprint
"""

import asyncio
import logging
import threading
import time
import gzip
import pickle
import json
from collections import deque
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Callable, Any, AsyncIterator, Iterator, Union, Tuple
from dataclasses import dataclass, field
import aiofiles
import hashlib
import os
import io
from concurrent.futures import ThreadPoolExecutor
import csv

from ...proxy_core.models import ProxyInfo, TierLevel, ProxyStatus, ValidationStatus
from ..queue.intelligent_job_queue import ValidationJob, JobBatch, JobType
from ..workers.parallel_worker_system import ParallelWorkerSystem
from ..optimization.resource_optimizer import ResourceOptimizer

logger = logging.getLogger(__name__)


class StreamFormat(Enum):
    """Supported streaming formats"""
    JSON_LINES = "jsonlines"        # Newline-delimited JSON
    CSV = "csv"                     # Comma-separated values
    BINARY = "binary"               # Pickled binary format
    COMPRESSED_JSON = "compressed_json"  # Gzip-compressed JSON


class ProcessingMode(Enum):
    """Processing modes for different scenarios"""
    MEMORY_OPTIMIZED = "memory_optimized"      # Minimize memory usage
    SPEED_OPTIMIZED = "speed_optimized"        # Maximize throughput
    BALANCED = "balanced"                       # Balance memory and speed
    STREAMING_ONLY = "streaming_only"          # Pure streaming, no buffering


class BackpressureStrategy(Enum):
    """Strategies for handling backpressure"""
    BLOCK = "block"                 # Block upstream until downstream catches up
    DROP_OLDEST = "drop_oldest"     # Drop oldest items from buffer
    DROP_NEWEST = "drop_newest"     # Drop newest items when buffer full
    ADAPTIVE_BATCH = "adaptive_batch"  # Adjust batch sizes dynamically


@dataclass
class StreamConfig:
    """Configuration for stream processing"""
    batch_size: int = 1000
    max_memory_mb: int = 512
    buffer_size: int = 10000
    backpressure_strategy: BackpressureStrategy = BackpressureStrategy.ADAPTIVE_BATCH
    compression_enabled: bool = True
    parallel_workers: int = 4
    
    # I/O settings
    read_chunk_size: int = 8192
    write_buffer_size: int = 65536
    
    # Performance tuning
    prefetch_size: int = 3
    processing_timeout: float = 300.0


@dataclass
class StreamStats:
    """Statistics for stream processing"""
    items_processed: int = 0
    items_failed: int = 0
    bytes_processed: int = 0
    processing_time: float = 0.0
    memory_peak_mb: float = 0.0
    throughput_items_per_sec: float = 0.0
    
    def update_throughput(self):
        """Update throughput calculation"""
        if self.processing_time > 0:
            self.throughput_items_per_sec = self.items_processed / self.processing_time


class MemoryMonitor:
    """Monitors memory usage and triggers adaptive behavior"""
    
    def __init__(self, max_memory_mb: int = 512):
        self.max_memory_mb = max_memory_mb
        self.current_usage_mb = 0.0
        self.peak_usage_mb = 0.0
        self.warning_threshold = 0.8  # 80% of max
        self.critical_threshold = 0.95  # 95% of max
        
        # Try to import psutil for accurate monitoring
        self.has_psutil = False
        try:
            import psutil
            self.process = psutil.Process()
            self.has_psutil = True
        except ImportError:
            logger.warning("psutil not available - using basic memory monitoring")
    
    def update_usage(self) -> float:
        """Update and return current memory usage in MB"""
        if self.has_psutil:
            try:
                memory_info = self.process.memory_info()
                self.current_usage_mb = memory_info.rss / (1024 * 1024)
            except Exception:
                # Fallback to basic estimation
                self.current_usage_mb = self._estimate_memory_usage()
        else:
            self.current_usage_mb = self._estimate_memory_usage()
        
        self.peak_usage_mb = max(self.peak_usage_mb, self.current_usage_mb)
        return self.current_usage_mb
    
    def _estimate_memory_usage(self) -> float:
        """Basic memory usage estimation"""
        # This is a rough estimate - in production, psutil should be used
        import sys
        return sys.getsizeof({}) / (1024 * 1024) * 100  # Rough estimate
    
    def is_memory_warning(self) -> bool:
        """Check if memory usage is approaching limits"""
        return self.current_usage_mb > (self.max_memory_mb * self.warning_threshold)
    
    def is_memory_critical(self) -> bool:
        """Check if memory usage is critical"""
        return self.current_usage_mb > (self.max_memory_mb * self.critical_threshold)
    
    def get_usage_ratio(self) -> float:
        """Get memory usage as ratio (0.0 - 1.0)"""
        return min(self.current_usage_mb / self.max_memory_mb, 1.0)


class AdaptiveBatcher:
    """Dynamically adjusts batch sizes based on system conditions"""
    
    def __init__(self, initial_batch_size: int = 1000, min_size: int = 10, max_size: int = 10000):
        self.current_batch_size = initial_batch_size
        self.min_size = min_size
        self.max_size = max_size
        
        # Performance tracking
        self.processing_times = deque(maxlen=20)
        self.memory_usage = deque(maxlen=20)
        self.last_adjustment = datetime.utcnow()
        self.adjustment_cooldown = timedelta(seconds=30)
    
    def adjust_batch_size(self, processing_time: float, memory_usage: float, 
                         memory_pressure: float) -> int:
        """Adjust batch size based on performance metrics"""
        
        # Don't adjust too frequently
        if datetime.utcnow() - self.last_adjustment < self.adjustment_cooldown:
            return self.current_batch_size
        
        self.processing_times.append(processing_time)
        self.memory_usage.append(memory_usage)
        
        # Calculate trends
        if len(self.processing_times) >= 5:
            recent_avg_time = sum(list(self.processing_times)[-5:]) / 5
            older_avg_time = sum(list(self.processing_times)[-10:-5]) / 5 if len(self.processing_times) >= 10 else recent_avg_time
            
            time_trend = recent_avg_time - older_avg_time
            
            # Adjustment logic
            if memory_pressure > 0.8:  # High memory pressure
                self.current_batch_size = max(self.min_size, int(self.current_batch_size * 0.7))
                logger.debug(f"Reduced batch size due to memory pressure: {self.current_batch_size}")
            elif memory_pressure < 0.5 and time_trend < 0:  # Low memory, improving performance
                self.current_batch_size = min(self.max_size, int(self.current_batch_size * 1.2))
                logger.debug(f"Increased batch size due to good performance: {self.current_batch_size}")
            elif time_trend > recent_avg_time * 0.2:  # Performance degrading
                self.current_batch_size = max(self.min_size, int(self.current_batch_size * 0.8))
                logger.debug(f"Reduced batch size due to performance degradation: {self.current_batch_size}")
            
            self.last_adjustment = datetime.utcnow()
        
        return self.current_batch_size


class StreamProcessor:
    """Core streaming processor with memory optimization"""
    
    def __init__(self, config: StreamConfig):
        self.config = config
        self.memory_monitor = MemoryMonitor(config.max_memory_mb)
        self.adaptive_batcher = AdaptiveBatcher(config.batch_size)
        
        # Processing state
        self.stats = StreamStats()
        self.is_running = False
        self.backpressure_active = False
        
        # Buffers and queues
        self.input_buffer = deque(maxlen=config.buffer_size)
        self.output_buffer = deque(maxlen=config.buffer_size)
        self.processing_queue = asyncio.Queue(maxsize=config.buffer_size)
        
        # Async components
        self.executor = ThreadPoolExecutor(max_workers=config.parallel_workers)
        
        logger.info(f"StreamProcessor initialized with {config.batch_size} batch size")
    
    async def process_stream(self, input_stream: AsyncIterator[Any], 
                           processor_func: Callable[[List[Any]], List[Any]],
                           output_stream: Optional[Any] = None) -> StreamStats:
        """Process a stream of data with adaptive batching"""
        
        self.is_running = True
        start_time = time.time()
        current_batch = []
        
        try:
            async for item in input_stream:
                # Monitor memory usage
                self.memory_monitor.update_usage()
                
                # Check for backpressure
                if self._should_apply_backpressure():
                    await self._handle_backpressure()
                
                current_batch.append(item)
                
                # Process batch when it reaches optimal size
                optimal_size = self.adaptive_batcher.current_batch_size
                if len(current_batch) >= optimal_size:
                    await self._process_batch(current_batch, processor_func, output_stream)
                    current_batch = []
            
            # Process remaining items
            if current_batch:
                await self._process_batch(current_batch, processor_func, output_stream)
            
            # Update final statistics
            self.stats.processing_time = time.time() - start_time
            self.stats.memory_peak_mb = self.memory_monitor.peak_usage_mb
            self.stats.update_throughput()
            
            return self.stats
            
        except Exception as e:
            logger.error(f"Stream processing error: {e}")
            raise
        finally:
            self.is_running = False
    
    async def _process_batch(self, batch: List[Any], processor_func: Callable, 
                           output_stream: Optional[Any]):
        """Process a single batch"""
        batch_start = time.time()
        
        try:
            # Process batch in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            processed_batch = await loop.run_in_executor(
                self.executor, processor_func, batch.copy()
            )
            
            # Write to output stream if provided
            if output_stream and processed_batch:
                await self._write_to_output(output_stream, processed_batch)
            
            # Update statistics
            processing_time = time.time() - batch_start
            self.stats.items_processed += len(batch)
            
            # Adjust batch size based on performance
            memory_pressure = self.memory_monitor.get_usage_ratio()
            self.adaptive_batcher.adjust_batch_size(
                processing_time, self.memory_monitor.current_usage_mb, memory_pressure
            )
            
        except Exception as e:
            logger.error(f"Batch processing error: {e}")
            self.stats.items_failed += len(batch)
    
    def _should_apply_backpressure(self) -> bool:
        """Determine if backpressure should be applied"""
        memory_critical = self.memory_monitor.is_memory_critical()
        buffer_full = len(self.input_buffer) >= self.config.buffer_size * 0.9
        
        return memory_critical or buffer_full
    
    async def _handle_backpressure(self):
        """Handle backpressure according to strategy"""
        self.backpressure_active = True
        
        if self.config.backpressure_strategy == BackpressureStrategy.BLOCK:
            # Wait for memory/buffer pressure to decrease
            while (self.memory_monitor.is_memory_critical() or 
                   len(self.input_buffer) >= self.config.buffer_size * 0.8):
                await asyncio.sleep(0.1)
                self.memory_monitor.update_usage()
        
        elif self.config.backpressure_strategy == BackpressureStrategy.DROP_OLDEST:
            # Remove oldest items from buffer
            while len(self.input_buffer) > self.config.buffer_size * 0.7:
                self.input_buffer.popleft()
        
        elif self.config.backpressure_strategy == BackpressureStrategy.DROP_NEWEST:
            # This would be handled by not adding new items
            pass
        
        elif self.config.backpressure_strategy == BackpressureStrategy.ADAPTIVE_BATCH:
            # Reduce batch size temporarily
            self.adaptive_batcher.current_batch_size = max(
                self.adaptive_batcher.min_size,
                int(self.adaptive_batcher.current_batch_size * 0.5)
            )
        
        self.backpressure_active = False
    
    async def _write_to_output(self, output_stream: Any, data: List[Any]):
        """Write processed data to output stream"""
        # This would be implemented based on the output stream type
        # For now, just log the operation
        logger.debug(f"Writing {len(data)} items to output stream")


class FileStreamReader:
    """Efficient file stream reader with format detection"""
    
    def __init__(self, config: StreamConfig):
        self.config = config
    
    async def read_file_stream(self, file_path: str, 
                             format_type: StreamFormat = StreamFormat.JSON_LINES) -> AsyncIterator[Dict[str, Any]]:
        """Read file as async stream"""
        
        file_size = os.path.getsize(file_path)
        logger.info(f"Reading {file_size} byte file: {file_path}")
        
        if format_type == StreamFormat.COMPRESSED_JSON:
            async for item in self._read_compressed_stream(file_path):
                yield item
        elif format_type == StreamFormat.JSON_LINES:
            async for item in self._read_jsonlines_stream(file_path):
                yield item
        elif format_type == StreamFormat.CSV:
            async for item in self._read_csv_stream(file_path):
                yield item
        elif format_type == StreamFormat.BINARY:
            async for item in self._read_binary_stream(file_path):
                yield item
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    async def _read_jsonlines_stream(self, file_path: str) -> AsyncIterator[Dict[str, Any]]:
        """Read JSON Lines format"""
        async with aiofiles.open(file_path, 'r') as f:
            async for line in f:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON line: {e}")
    
    async def _read_csv_stream(self, file_path: str) -> AsyncIterator[Dict[str, Any]]:
        """Read CSV format"""
        async with aiofiles.open(file_path, 'r') as f:
            header = None
            async for line in f:
                line = line.strip()
                if line:
                    if header is None:
                        header = line.split(',')
                    else:
                        values = line.split(',')
                        if len(values) == len(header):
                            yield dict(zip(header, values))
    
    async def _read_compressed_stream(self, file_path: str) -> AsyncIterator[Dict[str, Any]]:
        """Read compressed JSON format"""
        with gzip.open(file_path, 'rt') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON line: {e}")
    
    async def _read_binary_stream(self, file_path: str) -> AsyncIterator[Any]:
        """Read binary pickle format"""
        with open(file_path, 'rb') as f:
            try:
                while True:
                    yield pickle.load(f)
            except EOFError:
                pass


class FileStreamWriter:
    """Efficient file stream writer with compression"""
    
    def __init__(self, config: StreamConfig):
        self.config = config
        self.buffer = io.StringIO()
        self.buffer_size = 0
    
    async def write_stream(self, file_path: str, data_stream: AsyncIterator[Any],
                          format_type: StreamFormat = StreamFormat.JSON_LINES):
        """Write data stream to file"""
        
        if format_type == StreamFormat.COMPRESSED_JSON:
            await self._write_compressed_stream(file_path, data_stream)
        elif format_type == StreamFormat.JSON_LINES:
            await self._write_jsonlines_stream(file_path, data_stream)
        elif format_type == StreamFormat.CSV:
            await self._write_csv_stream(file_path, data_stream)
        elif format_type == StreamFormat.BINARY:
            await self._write_binary_stream(file_path, data_stream)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    async def _write_jsonlines_stream(self, file_path: str, data_stream: AsyncIterator[Any]):
        """Write JSON Lines format"""
        async with aiofiles.open(file_path, 'w') as f:
            async for item in data_stream:
                line = json.dumps(item) + '\n'
                await f.write(line)
    
    async def _write_csv_stream(self, file_path: str, data_stream: AsyncIterator[Dict[str, Any]]):
        """Write CSV format"""
        header_written = False
        async with aiofiles.open(file_path, 'w') as f:
            async for item in data_stream:
                if not header_written and isinstance(item, dict):
                    header = ','.join(item.keys()) + '\n'
                    await f.write(header)
                    header_written = True
                
                if isinstance(item, dict):
                    values = ','.join(str(v) for v in item.values()) + '\n'
                    await f.write(values)
    
    async def _write_compressed_stream(self, file_path: str, data_stream: AsyncIterator[Any]):
        """Write compressed JSON format"""
        with gzip.open(file_path, 'wt') as f:
            async for item in data_stream:
                line = json.dumps(item) + '\n'
                f.write(line)
    
    async def _write_binary_stream(self, file_path: str, data_stream: AsyncIterator[Any]):
        """Write binary pickle format"""
        with open(file_path, 'wb') as f:
            async for item in data_stream:
                pickle.dump(item, f)


class BulkProxyProcessor:
    """Specialized processor for bulk proxy operations"""
    
    def __init__(self, config: StreamConfig, worker_system: Optional[ParallelWorkerSystem] = None):
        self.config = config
        self.worker_system = worker_system
        self.stream_processor = StreamProcessor(config)
        self.file_reader = FileStreamReader(config)
        self.file_writer = FileStreamWriter(config)
    
    async def process_proxy_file(self, input_file: str, output_file: Optional[str] = None,
                               format_type: StreamFormat = StreamFormat.JSON_LINES) -> StreamStats:
        """Process a large proxy file efficiently"""
        
        logger.info(f"Starting bulk processing of {input_file}")
        
        # Create data stream from file
        data_stream = self.file_reader.read_file_stream(input_file, format_type)
        
        # Process stream
        if output_file:
            processed_stream = self._create_processed_stream(data_stream)
            # Write results while processing
            await asyncio.gather(
                self.stream_processor.process_stream(
                    data_stream, self._process_proxy_batch, None
                ),
                self.file_writer.write_stream(output_file, processed_stream, format_type)
            )
        else:
            # Process without output
            stats = await self.stream_processor.process_stream(
                data_stream, self._process_proxy_batch, None
            )
        
        return self.stream_processor.stats
    
    async def _create_processed_stream(self, input_stream: AsyncIterator[Dict[str, Any]]) -> AsyncIterator[Dict[str, Any]]:
        """Create processed data stream"""
        async for item in input_stream:
            # Transform item as needed
            processed_item = self._transform_proxy_data(item)
            yield processed_item
    
    def _process_proxy_batch(self, proxy_data_batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process a batch of proxy data"""
        processed_batch = []
        
        for proxy_data in proxy_data_batch:
            try:
                # Convert to ProxyInfo object
                proxy = self._dict_to_proxy(proxy_data)
                
                # Perform validation or processing
                if self.worker_system:
                    # Submit to worker system
                    job = ValidationJob(
                        proxy=proxy,
                        job_type=JobType.BULK_VALIDATION,
                        priority=0.5,
                        created_at=datetime.utcnow(),
                        source="bulk_processor",
                        tier=proxy.tier_level
                    )
                    self.worker_system.submit_job(job)
                
                # Transform back to dict for output
                processed_data = self._proxy_to_dict(proxy)
                processed_batch.append(processed_data)
                
            except Exception as e:
                logger.warning(f"Failed to process proxy data: {e}")
                # Keep original data but mark as failed
                proxy_data['processing_error'] = str(e)
                processed_batch.append(proxy_data)
        
        return processed_batch
    
    def _dict_to_proxy(self, data: Dict[str, Any]) -> ProxyInfo:
        """Convert dictionary to ProxyInfo object"""
        from ...proxy_core.models import ProxyProtocol
        
        # Extract required fields
        host = data.get('host', data.get('ip', ''))
        port = int(data.get('port', 8080))
        protocol = ProxyProtocol(data.get('protocol', 'http'))
        
        proxy = ProxyInfo(host=host, port=port, protocol=protocol)
        
        # Set optional fields if available
        if 'tier_level' in data:
            proxy.tier_level = TierLevel(int(data['tier_level']))
        if 'country' in data:
            proxy.country = data['country']
        if 'region' in data:
            proxy.region = data['region']
        
        return proxy
    
    def _proxy_to_dict(self, proxy: ProxyInfo) -> Dict[str, Any]:
        """Convert ProxyInfo to dictionary"""
        return {
            'host': proxy.host,
            'port': proxy.port,
            'protocol': proxy.protocol.value,
            'tier_level': proxy.tier_level.value,
            'country': proxy.country,
            'region': proxy.region,
            'status': proxy.status.value,
            'last_checked': proxy.last_checked.isoformat() if proxy.last_checked else None,
            'success_rate': proxy.metrics.success_rate,
            'response_time': proxy.metrics.response_time,
            'processed_at': datetime.utcnow().isoformat()
        }
    
    def _transform_proxy_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform proxy data during processing"""
        # Add processing metadata
        data['processed_at'] = datetime.utcnow().isoformat()
        data['processor_version'] = '1.0'
        
        # Validate and clean data
        if 'host' in data and not data['host']:
            data['validation_error'] = 'Empty host field'
        
        return data
    
    async def validate_large_proxy_list(self, proxy_list: List[ProxyInfo], 
                                      chunk_size: int = 1000) -> AsyncIterator[List[Dict[str, Any]]]:
        """Validate large proxy list in chunks"""
        
        for i in range(0, len(proxy_list), chunk_size):
            chunk = proxy_list[i:i + chunk_size]
            
            # Convert to data format
            chunk_data = [self._proxy_to_dict(proxy) for proxy in chunk]
            
            # Process chunk
            processed_chunk = self._process_proxy_batch(chunk_data)
            
            yield processed_chunk
            
            # Allow other coroutines to run
            await asyncio.sleep(0)


def create_bulk_stream_processor(max_memory_mb: int = 512, 
                                batch_size: int = 1000,
                                worker_system: Optional[ParallelWorkerSystem] = None) -> BulkProxyProcessor:
    """Factory function to create bulk stream processor"""
    config = StreamConfig(
        batch_size=batch_size,
        max_memory_mb=max_memory_mb,
        buffer_size=batch_size * 10,
        compression_enabled=True
    )
    return BulkProxyProcessor(config, worker_system)


async def main():
    """Example usage and testing"""
    import tempfile
    import random
    
    # Create test data file
    test_data = []
    for i in range(5000):
        proxy_data = {
            'host': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            'port': random.choice([8080, 3128, 1080, 9050]),
            'protocol': random.choice(['http', 'https', 'socks4', 'socks5']),
            'tier_level': random.randint(1, 4),
            'country': random.choice(['US', 'UK', 'DE', 'FR', 'JP']),
            'region': f"Region{random.randint(1,10)}"
        }
        test_data.append(proxy_data)
    
    # Write test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        for item in test_data:
            f.write(json.dumps(item) + '\n')
        test_file = f.name
    
    print(f"Created test file with {len(test_data)} proxies: {test_file}")
    
    # Create processor
    processor = create_bulk_stream_processor(max_memory_mb=256, batch_size=500)
    
    # Process file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        output_file = f.name
    
    print("Starting bulk processing...")
    start_time = time.time()
    
    stats = await processor.process_proxy_file(
        test_file, output_file, StreamFormat.JSON_LINES
    )
    
    processing_time = time.time() - start_time
    
    print(f"\nProcessing completed in {processing_time:.2f} seconds")
    print(f"Items processed: {stats.items_processed}")
    print(f"Items failed: {stats.items_failed}")
    print(f"Peak memory: {stats.memory_peak_mb:.1f} MB")
    print(f"Throughput: {stats.throughput_items_per_sec:.1f} items/sec")
    
    # Verify output file
    output_count = 0
    with open(output_file, 'r') as f:
        for line in f:
            if line.strip():
                output_count += 1
    
    print(f"Output file contains {output_count} items")
    
    # Cleanup
    os.unlink(test_file)
    os.unlink(output_file)


if __name__ == "__main__":
    asyncio.run(main())