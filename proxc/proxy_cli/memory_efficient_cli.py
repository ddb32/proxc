"""
Memory-Efficient CLI Extensions

This module provides enhanced CLI commands that use the new memory management
system for processing large proxy datasets. Integrates with existing CLI while
adding streaming, memory-optimized processing capabilities.
"""

import gc
import time
from pathlib import Path
from typing import Optional, Union, Dict, Any

from ..proxy_core.memory_manager import (
    StreamingProxyLoader, MemoryMonitor, memory_optimized_processing
)
from ..proxy_core.streaming_validator import (
    StreamingValidator, StreamingOutputWriter, create_progress_callback
)
from .cli_imports import (
    print_info, print_success, print_warning, print_error,
    log_structured, start_operation_logging, get_log_metrics
)


class MemoryEfficientProcessor:
    """
    High-level interface for memory-efficient proxy processing.
    Combines all Phase 3.1 components into a unified processing pipeline.
    """
    
    def __init__(self, max_workers: int = 50, initial_batch_size: int = 100):
        self.max_workers = max_workers
        self.initial_batch_size = initial_batch_size
        self.processing_stats = {}
    
    def process_large_proxy_file(
        self,
        input_file: Union[str, Path],
        output_file: Union[str, Path],
        protocol_mode: str = "auto-detect",
        target_protocol: Optional[str] = None,
        timeout: float = 10.0,
        valid_only: bool = True,
        output_format: str = "json",
        show_progress: bool = True
    ) -> Dict[str, Any]:
        """
        Process large proxy files with memory-efficient streaming validation.
        
        Args:
            input_file: Path to input proxy file
            output_file: Path to output file for results
            protocol_mode: Protocol detection mode
            target_protocol: Force specific protocol
            timeout: Validation timeout per proxy
            valid_only: Output only valid proxies
            output_format: Output format (json, txt)
            show_progress: Show progress information
            
        Returns:
            Processing statistics
        """
        input_file = Path(input_file)
        output_file = Path(output_file)
        
        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        print_info(f"🚀 Starting memory-efficient processing of {input_file}")
        start_operation_logging("memory_efficient_processing", 0, 
                              input_file=str(input_file),
                              output_file=str(output_file))
        
        with memory_optimized_processing() as memory_monitor:
            # Initialize components
            loader = StreamingProxyLoader(memory_monitor)
            validator = StreamingValidator(
                max_workers=self.max_workers,
                initial_batch_size=self.initial_batch_size
            )
            
            # Set up progress callback
            progress_callback = None
            if show_progress:
                progress_callback = self._create_enhanced_progress_callback()
            
            start_time = time.time()
            
            try:
                # Stream validation with output writing
                with StreamingOutputWriter(output_file, output_format) as writer:
                    # Get proxy stream
                    proxy_stream = loader.load_proxies_streaming(
                        input_file,
                        protocol_mode=protocol_mode,
                        target_protocol=target_protocol,
                        batch_size=self.initial_batch_size
                    )
                    
                    # Process with streaming validation
                    validation_stats = validator.process_proxy_stream(
                        proxy_stream,
                        output_writer=writer,
                        progress_callback=progress_callback,
                        timeout=timeout,
                        valid_only=valid_only
                    )
                
                # Get loading statistics
                loading_stats = loader.get_loading_stats()
                
                # Combine all statistics
                total_time = time.time() - start_time
                self.processing_stats = {
                    'processing_time': total_time,
                    'input_file': str(input_file),
                    'output_file': str(output_file),
                    'file_size_mb': input_file.stat().st_size / 1024 / 1024,
                    **loading_stats,
                    **validation_stats,
                    'memory_efficiency': validation_stats['total_processed'] / max(total_time, 0.1)
                }
                
                # Report results
                self._report_processing_results()
                
                return self.processing_stats
                
            except Exception as e:
                print_error(f"Memory-efficient processing failed: {e}")
                log_structured('ERROR', "Processing failed", 
                              input_file=str(input_file), error=str(e))
                raise
    
    def _create_enhanced_progress_callback(self):
        """Create enhanced progress callback with memory monitoring"""
        last_report_time = time.time()
        
        def enhanced_progress_callback(info: Dict[str, Any]):
            nonlocal last_report_time
            current_time = time.time()
            
            # Report every 5 seconds or every 50 batches
            batch_id = info['batch_id']
            if current_time - last_report_time >= 5.0 or batch_id % 50 == 0:
                total_processed = info['total_processed']
                total_valid = info['total_valid']
                success_rate = (total_valid / max(total_processed, 1)) * 100
                
                # Calculate throughput
                elapsed_time = current_time - self.processing_stats.get('start_time', current_time)
                throughput = total_processed / max(elapsed_time, 0.1)
                
                print_info(f"📊 Batch {batch_id}: {total_processed:,} processed, "
                          f"{total_valid:,} valid ({success_rate:.1f}%), "
                          f"{throughput:.0f} proxies/sec")
                
                # Memory usage info
                memory_mb = info.get('memory_used_mb', 0)
                if memory_mb > 50:
                    print_info(f"💾 Memory usage: {memory_mb:.1f} MB per batch")
                
                last_report_time = current_time
            
            # Log detailed batch information
            log_structured('DEBUG', f"Batch {batch_id} completed",
                          batch_size=info['batch_size'],
                          valid_count=info['valid_count'],
                          processing_time=f"{info['processing_time']:.2f}s",
                          memory_used_mb=f"{info.get('memory_used_mb', 0):.1f}")
        
        return enhanced_progress_callback
    
    def _report_processing_results(self):
        """Report comprehensive processing results"""
        stats = self.processing_stats
        
        print_success(f"✅ Memory-efficient processing completed!")
        
        # File processing summary
        print_info(f"📁 Input file: {stats['input_file']} ({stats['file_size_mb']:.1f} MB)")
        print_info(f"📤 Output file: {stats['output_file']}")
        
        # Processing statistics
        print_info(f"⏱️  Total time: {stats['processing_time']:.1f} seconds")
        print_info(f"🔍 Lines processed: {stats['total_lines_processed']:,}")
        print_info(f"✅ Valid proxies: {stats['total_valid']:,}")
        print_info(f"❌ Invalid proxies: {stats['total_invalid']:,}")
        print_info(f"📈 Success rate: {stats['success_rate']:.1f}%")
        print_info(f"⚡ Throughput: {stats['throughput']:.0f} proxies/second")
        print_info(f"🏗️  Batches processed: {stats['batches_processed']}")
        
        # Memory efficiency
        if stats.get('errors', 0) > 0:
            print_warning(f"⚠️  Processing errors: {stats['errors']}")
        
        # Log detailed metrics
        log_structured('INFO', "Processing completed successfully", **stats)


def estimate_memory_requirements(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Estimate memory requirements for processing a proxy file.
    Provides recommendations for batch sizes and expected resource usage.
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    file_size_mb = file_path.stat().st_size / 1024 / 1024
    
    # Rough estimation based on file size
    # Assume average 20 bytes per proxy line
    estimated_proxy_count = int(file_size_mb * 1024 * 1024 / 20)
    
    # Memory estimates
    # Each proxy in memory ~ 200 bytes (conservative estimate)
    # Validation overhead ~ 100 bytes per proxy
    memory_per_proxy_mb = 0.0003  # ~300 bytes
    
    # Get current memory status
    monitor = MemoryMonitor()
    memory_stats = monitor.get_memory_stats()
    
    # Calculate recommendations
    available_memory_mb = memory_stats.available_mb
    recommended_batch_size = min(5000, int(available_memory_mb * 0.1 / memory_per_proxy_mb))
    recommended_batch_size = max(50, recommended_batch_size)  # Minimum 50
    
    estimated_memory_usage = estimated_proxy_count * memory_per_proxy_mb
    estimated_processing_time = estimated_proxy_count / 500  # Rough estimate: 500 proxies/second
    
    recommendations = {
        'file_size_mb': file_size_mb,
        'estimated_proxy_count': estimated_proxy_count,
        'estimated_memory_usage_mb': estimated_memory_usage,
        'estimated_processing_time_minutes': estimated_processing_time / 60,
        'current_available_memory_mb': available_memory_mb,
        'recommended_batch_size': recommended_batch_size,
        'memory_pressure_level': monitor.check_pressure(),
        'can_process_in_memory': estimated_memory_usage < available_memory_mb * 0.5,
        'streaming_recommended': estimated_memory_usage > available_memory_mb * 0.3
    }
    
    return recommendations


def print_memory_recommendations(file_path: Union[str, Path]):
    """Print memory usage recommendations for processing a file"""
    try:
        recommendations = estimate_memory_requirements(file_path)
        
        print_info("📊 Memory Usage Analysis:")
        print_info(f"  File size: {recommendations['file_size_mb']:.1f} MB")
        print_info(f"  Estimated proxies: {recommendations['estimated_proxy_count']:,}")
        print_info(f"  Estimated processing time: {recommendations['estimated_processing_time_minutes']:.1f} minutes")
        print_info(f"  Available memory: {recommendations['current_available_memory_mb']:.0f} MB")
        print_info(f"  Recommended batch size: {recommendations['recommended_batch_size']:,}")
        
        if recommendations['streaming_recommended']:
            print_success("🔄 Streaming processing recommended for optimal memory usage")
        elif recommendations['can_process_in_memory']:
            print_info("💾 File can be processed entirely in memory")
        else:
            print_warning("⚠️  Large file detected - streaming processing strongly recommended")
        
        pressure = recommendations['memory_pressure_level']
        if pressure == "critical":
            print_warning("🚨 Critical memory pressure detected!")
        elif pressure == "warning":
            print_warning("⚠️  High memory pressure detected")
        else:
            print_success("✅ Memory pressure normal")
            
    except Exception as e:
        print_error(f"Failed to analyze memory requirements: {e}")


# CLI Integration Functions

def process_file_memory_efficient(
    input_file: str,
    output_file: str,
    max_workers: int = 50,
    initial_batch_size: int = 100,
    timeout: float = 10.0,
    protocol_mode: str = "auto-detect",
    target_protocol: Optional[str] = None,
    show_analysis: bool = True
) -> int:
    """
    CLI wrapper function for memory-efficient file processing.
    
    Returns:
        0 for success, 1 for error
    """
    try:
        # Show memory analysis if requested
        if show_analysis:
            print_memory_recommendations(input_file)
            print_info("")  # Add spacing
        
        # Process the file
        processor = MemoryEfficientProcessor(
            max_workers=max_workers,
            initial_batch_size=initial_batch_size
        )
        
        stats = processor.process_large_proxy_file(
            input_file=input_file,
            output_file=output_file,
            protocol_mode=protocol_mode,
            target_protocol=target_protocol,
            timeout=timeout
        )
        
        # Success
        return 0
        
    except Exception as e:
        print_error(f"Memory-efficient processing failed: {e}")
        log_structured('ERROR', "CLI processing failed", 
                      input_file=input_file, error=str(e))
        return 1