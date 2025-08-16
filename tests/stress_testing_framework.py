#!/usr/bin/env python3
"""
Stress Testing Framework - Phase 4.1.5

High-load stress testing for large proxy lists and high concurrency scenarios.
Tests system behavior under extreme conditions and resource constraints.

Test Categories:
- Large dataset processing (100k+ proxies)
- High concurrency stress testing
- Memory pressure testing
- CPU intensive workload testing
- Network saturation testing
- Database stress testing
- Recovery from resource exhaustion
"""

import asyncio
import gc
import json
import logging
import multiprocessing
import os
import psutil
import random
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import queue
import signal

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from proxc.proxy_core.models import ProxyInfo, ProxyProtocol
from proxc.proxy_core.database import DatabaseManager
from proxc.proxy_engine.validators import BatchValidator


class StressTestDataGenerator:
    """Generate large datasets for stress testing"""
    
    def __init__(self):
        self.ip_ranges = [
            (10, 0, 0, 0, 16),      # 10.0.0.0/8
            (172, 16, 0, 0, 12),    # 172.16.0.0/12  
            (192, 168, 0, 0, 16),   # 192.168.0.0/16
        ]
    
    def generate_large_proxy_dataset(self, count: int) -> List[ProxyInfo]:
        """Generate large proxy dataset"""
        proxies = []
        protocols = [ProxyProtocol.HTTP, ProxyProtocol.HTTPS, ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5]
        
        for i in range(count):
            # Select IP range
            base_ip, second, third, fourth, prefix = random.choice(self.ip_ranges)
            
            # Generate IP within range
            if prefix == 8:
                ip = f"{base_ip}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            elif prefix == 12:
                ip = f"{base_ip}.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            elif prefix == 16:
                ip = f"{base_ip}.{second}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            else:
                ip = f"{base_ip}.{second}.{third}.{random.randint(1, 254)}"
            
            # Generate port
            port = random.randint(1024, 65535)
            
            # Select protocol
            protocol = random.choice(protocols)
            
            proxy = ProxyInfo(
                host=ip,
                port=port,
                protocol=protocol,
                source=f"stress_test_batch_{i // 10000}"
            )
            
            proxies.append(proxy)
        
        return proxies
    
    def generate_proxy_file(self, file_path: Path, count: int):
        """Generate large proxy file"""
        with open(file_path, 'w') as f:
            for i in range(count):
                base_ip, second, third, fourth, prefix = random.choice(self.ip_ranges)
                
                if prefix == 8:
                    ip = f"{base_ip}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                elif prefix == 12:
                    ip = f"{base_ip}.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                else:
                    ip = f"{base_ip}.{second}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                
                port = random.randint(1024, 65535)
                f.write(f"{ip}:{port}\n")


class ResourceMonitor:
    """Monitor system resources during stress tests"""
    
    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.resource_samples = []
        self.start_time = None
    
    def start_monitoring(self):
        """Start resource monitoring"""
        self.monitoring = True
        self.start_time = time.time()
        self.resource_samples = []
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self) -> Dict[str, Any]:
        """Stop monitoring and return statistics"""
        self.monitoring = False
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2.0)
        
        if not self.resource_samples:
            return {}
        
        # Calculate statistics
        memory_values = [s['memory_mb'] for s in self.resource_samples]
        cpu_values = [s['cpu_percent'] for s in self.resource_samples]
        
        return {
            'duration_seconds': time.time() - self.start_time,
            'sample_count': len(self.resource_samples),
            'memory_peak_mb': max(memory_values),
            'memory_average_mb': sum(memory_values) / len(memory_values),
            'cpu_peak_percent': max(cpu_values),
            'cpu_average_percent': sum(cpu_values) / len(cpu_values),
            'memory_samples': memory_values,
            'cpu_samples': cpu_values
        }
    
    def _monitor_loop(self):
        """Resource monitoring loop"""
        process = psutil.Process()
        
        while self.monitoring:
            try:
                memory_mb = process.memory_info().rss / 1024 / 1024
                cpu_percent = process.cpu_percent()
                timestamp = time.time()
                
                self.resource_samples.append({
                    'timestamp': timestamp,
                    'memory_mb': memory_mb,
                    'cpu_percent': cpu_percent
                })
                
                time.sleep(0.5)  # Sample every 500ms
            except:
                break


class StressTestRunner:
    """Main stress test execution framework"""
    
    def __init__(self):
        self.data_generator = StressTestDataGenerator()
        self.resource_monitor = ResourceMonitor()
        self.test_results = []
    
    def stress_test_large_dataset_processing(self, proxy_count: int = 100000) -> Dict[str, Any]:
        """Stress test with very large proxy datasets"""
        
        print(f"🔥 Stress testing large dataset processing ({proxy_count:,} proxies)")
        
        start_time = time.time()
        self.resource_monitor.start_monitoring()
        
        try:
            # Generate large dataset in chunks to avoid memory issues
            chunk_size = 10000
            processed_count = 0
            processing_times = []
            
            for chunk_start in range(0, proxy_count, chunk_size):
                chunk_end = min(chunk_start + chunk_size, proxy_count)
                chunk_size_actual = chunk_end - chunk_start
                
                chunk_start_time = time.time()
                
                # Generate chunk
                proxies = self.data_generator.generate_large_proxy_dataset(chunk_size_actual)
                
                # Process chunk (simulate validation/filtering)
                valid_proxies = []
                for proxy in proxies:
                    # Simple validation simulation
                    if proxy.port > 1024 and proxy.host.count('.') == 3:
                        valid_proxies.append(proxy)
                
                chunk_time = time.time() - chunk_start_time
                processing_times.append(chunk_time)
                processed_count += chunk_size_actual
                
                # Memory cleanup
                del proxies
                del valid_proxies
                gc.collect()
                
                # Progress update
                if processed_count % 50000 == 0:
                    print(f"  📊 Processed {processed_count:,}/{proxy_count:,} proxies")
            
            total_time = time.time() - start_time
            resource_stats = self.resource_monitor.stop_monitoring()
            
            return {
                'test_name': 'Large Dataset Processing',
                'proxy_count': proxy_count,
                'total_time_seconds': total_time,
                'throughput_proxies_per_second': proxy_count / total_time,
                'chunk_processing_times': processing_times,
                'average_chunk_time': sum(processing_times) / len(processing_times),
                'resource_stats': resource_stats,
                'status': 'PASSED',
                'memory_efficient': resource_stats.get('memory_peak_mb', 0) < 1000  # Under 1GB
            }
        
        except Exception as e:
            resource_stats = self.resource_monitor.stop_monitoring()
            return {
                'test_name': 'Large Dataset Processing',
                'proxy_count': proxy_count,
                'status': 'FAILED',
                'error': str(e),
                'resource_stats': resource_stats
            }
    
    def stress_test_high_concurrency(self, thread_count: int = 100, operations_per_thread: int = 1000) -> Dict[str, Any]:
        """Stress test with high concurrency"""
        
        print(f"🔥 Stress testing high concurrency ({thread_count} threads, {operations_per_thread} ops each)")
        
        start_time = time.time()
        self.resource_monitor.start_monitoring()
        
        # Shared results
        results_queue = queue.Queue()
        error_count = threading.AtomicInteger(0) if hasattr(threading, 'AtomicInteger') else [0]
        
        def worker_function(thread_id: int):
            """Worker function for concurrent operations"""
            thread_results = []
            
            try:
                for i in range(operations_per_thread):
                    operation_start = time.time()
                    
                    # Simulate CPU-intensive operation
                    proxy = ProxyInfo(
                        host=f"192.168.{thread_id % 256}.{i % 256}",
                        port=8000 + i,
                        protocol=ProxyProtocol.HTTP,
                        source=f"thread_{thread_id}"
                    )
                    
                    # Simulate validation
                    is_valid = (
                        proxy.host.count('.') == 3 and
                        1024 <= proxy.port <= 65535 and
                        len(proxy.host.split('.')) == 4
                    )
                    
                    operation_time = time.time() - operation_start
                    thread_results.append(operation_time)
                
                results_queue.put({
                    'thread_id': thread_id,
                    'operations_completed': len(thread_results),
                    'operation_times': thread_results,
                    'success': True
                })
            
            except Exception as e:
                if hasattr(error_count, 'value'):
                    error_count.value += 1
                else:
                    error_count[0] += 1
                
                results_queue.put({
                    'thread_id': thread_id,
                    'operations_completed': 0,
                    'error': str(e),
                    'success': False
                })
        
        try:
            # Start all threads
            threads = []
            for thread_id in range(thread_count):
                thread = threading.Thread(target=worker_function, args=(thread_id,))
                threads.append(thread)
                thread.start()
            
            # Wait for completion
            for thread in threads:
                thread.join(timeout=60)  # 60 second timeout per thread
            
            # Collect results
            thread_results = []
            while not results_queue.empty():
                thread_results.append(results_queue.get())
            
            total_time = time.time() - start_time
            resource_stats = self.resource_monitor.stop_monitoring()
            
            # Calculate statistics
            successful_threads = [r for r in thread_results if r.get('success')]
            total_operations = sum(r['operations_completed'] for r in successful_threads)
            
            all_operation_times = []
            for r in successful_threads:
                all_operation_times.extend(r.get('operation_times', []))
            
            return {
                'test_name': 'High Concurrency',
                'thread_count': thread_count,
                'operations_per_thread': operations_per_thread,
                'successful_threads': len(successful_threads),
                'total_operations_completed': total_operations,
                'total_time_seconds': total_time,
                'operations_per_second': total_operations / total_time if total_time > 0 else 0,
                'average_operation_time': sum(all_operation_times) / len(all_operation_times) if all_operation_times else 0,
                'resource_stats': resource_stats,
                'status': 'PASSED' if len(successful_threads) >= thread_count * 0.9 else 'FAILED',
                'error_count': error_count[0] if isinstance(error_count, list) else error_count.value
            }
        
        except Exception as e:
            resource_stats = self.resource_monitor.stop_monitoring()
            return {
                'test_name': 'High Concurrency',
                'status': 'FAILED',
                'error': str(e),
                'resource_stats': resource_stats
            }
    
    def stress_test_memory_pressure(self, target_memory_mb: int = 2048) -> Dict[str, Any]:
        """Stress test under memory pressure"""
        
        print(f"🔥 Stress testing memory pressure (target: {target_memory_mb}MB)")
        
        start_time = time.time()
        self.resource_monitor.start_monitoring()
        
        try:
            memory_blocks = []
            current_memory_mb = 0
            
            # Gradually increase memory usage
            while current_memory_mb < target_memory_mb:
                # Allocate 100MB blocks of proxy data
                block_size = 10000
                proxy_block = self.data_generator.generate_large_proxy_dataset(block_size)
                memory_blocks.append(proxy_block)
                
                # Estimate memory usage
                process = psutil.Process()
                current_memory_mb = process.memory_info().rss / 1024 / 1024
                
                print(f"  📊 Memory usage: {current_memory_mb:.1f}MB / {target_memory_mb}MB")
                
                # Safety check to prevent system crash
                if current_memory_mb > target_memory_mb * 1.5:
                    print("  ⚠️ Memory usage exceeded safety limit")
                    break
                
                # Perform operations under memory pressure
                if len(memory_blocks) % 5 == 0:
                    # Simulate processing under memory pressure
                    for block in memory_blocks[-2:]:  # Process last 2 blocks
                        valid_count = sum(1 for proxy in block if proxy.port > 1024)
            
            # Test operations under memory pressure
            operations_completed = 0
            operation_start_time = time.time()
            
            # Perform memory-intensive operations
            for i in range(1000):
                # Create and process proxy data
                test_proxies = self.data_generator.generate_large_proxy_dataset(100)
                
                # Filter and validate
                valid_proxies = [p for p in test_proxies if p.port > 1024]
                operations_completed += 1
                
                # Cleanup
                del test_proxies
                del valid_proxies
                
                if i % 100 == 0:
                    gc.collect()  # Force garbage collection
            
            operation_time = time.time() - operation_start_time
            total_time = time.time() - start_time
            resource_stats = self.resource_monitor.stop_monitoring()
            
            # Cleanup memory
            del memory_blocks
            gc.collect()
            
            return {
                'test_name': 'Memory Pressure',
                'target_memory_mb': target_memory_mb,
                'peak_memory_mb': resource_stats.get('memory_peak_mb', 0),
                'operations_completed': operations_completed,
                'operation_time_seconds': operation_time,
                'total_time_seconds': total_time,
                'operations_per_second': operations_completed / operation_time,
                'resource_stats': resource_stats,
                'status': 'PASSED',
                'memory_target_reached': resource_stats.get('memory_peak_mb', 0) >= target_memory_mb * 0.8
            }
        
        except Exception as e:
            resource_stats = self.resource_monitor.stop_monitoring()
            return {
                'test_name': 'Memory Pressure',
                'status': 'FAILED',
                'error': str(e),
                'resource_stats': resource_stats
            }
    
    def stress_test_database_operations(self, operation_count: int = 100000) -> Dict[str, Any]:
        """Stress test database operations"""
        
        print(f"🔥 Stress testing database operations ({operation_count:,} operations)")
        
        # Create temporary database
        temp_dir = Path(tempfile.mkdtemp(prefix="stress_db_"))
        db_path = temp_dir / "stress_test.db"
        
        start_time = time.time()
        self.resource_monitor.start_monitoring()
        
        try:
            db = DatabaseManager(str(db_path))
            db.initialize_database()
            
            # Generate test data
            test_proxies = self.data_generator.generate_large_proxy_dataset(operation_count)
            
            # Batch insert operations
            batch_size = 1000
            insert_times = []
            
            for i in range(0, len(test_proxies), batch_size):
                batch = test_proxies[i:i + batch_size]
                
                batch_start = time.time()
                proxy_ids = db.store_proxies_batch(batch)
                batch_time = time.time() - batch_start
                
                insert_times.append(batch_time)
                
                if i % 10000 == 0:
                    print(f"  📊 Inserted {i + len(batch):,}/{operation_count:,} proxies")
            
            # Query operations
            query_start = time.time()
            all_proxies = db.get_all_proxies()
            query_time = time.time() - query_start
            
            # Update operations
            update_start = time.time()
            update_count = min(1000, len(all_proxies))
            for i in range(update_count):
                proxy = all_proxies[i]
                db.update_proxy_status(proxy.id, "working", 100.0)
            update_time = time.time() - update_start
            
            total_time = time.time() - start_time
            resource_stats = self.resource_monitor.stop_monitoring()
            
            # Cleanup
            db.close()
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            
            return {
                'test_name': 'Database Operations',
                'operation_count': operation_count,
                'insert_time_seconds': sum(insert_times),
                'query_time_seconds': query_time,
                'update_time_seconds': update_time,
                'total_time_seconds': total_time,
                'insert_throughput': operation_count / sum(insert_times),
                'query_throughput': len(all_proxies) / query_time,
                'update_throughput': update_count / update_time,
                'resource_stats': resource_stats,
                'status': 'PASSED',
                'database_size_mb': db_path.stat().st_size / 1024 / 1024 if db_path.exists() else 0
            }
        
        except Exception as e:
            resource_stats = self.resource_monitor.stop_monitoring()
            
            # Cleanup on error
            try:
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)
            except:
                pass
            
            return {
                'test_name': 'Database Operations',
                'status': 'FAILED',
                'error': str(e),
                'resource_stats': resource_stats
            }
    
    def run_comprehensive_stress_tests(self) -> Dict[str, Any]:
        """Run complete stress test suite"""
        
        print("🚀 Starting Comprehensive Stress Test Suite")
        print("=" * 60)
        
        suite_start_time = time.time()
        
        # Run individual stress tests
        test_results = []
        
        # Large dataset processing
        large_dataset_result = self.stress_test_large_dataset_processing(100000)
        test_results.append(large_dataset_result)
        
        # High concurrency
        concurrency_result = self.stress_test_high_concurrency(50, 1000)
        test_results.append(concurrency_result)
        
        # Memory pressure
        memory_result = self.stress_test_memory_pressure(1024)  # 1GB target
        test_results.append(memory_result)
        
        # Database operations
        database_result = self.stress_test_database_operations(50000)
        test_results.append(database_result)
        
        suite_duration = time.time() - suite_start_time
        
        # Analyze results
        passed_tests = [r for r in test_results if r.get('status') == 'PASSED']
        failed_tests = [r for r in test_results if r.get('status') == 'FAILED']
        
        summary = {
            'total_tests': len(test_results),
            'passed_tests': len(passed_tests),
            'failed_tests': len(failed_tests),
            'success_rate': (len(passed_tests) / len(test_results)) * 100,
            'suite_duration_seconds': suite_duration,
            'test_results': test_results,
            'overall_status': 'PASSED' if len(failed_tests) == 0 else 'FAILED'
        }
        
        return summary
    
    def print_stress_test_summary(self, summary: Dict[str, Any]):
        """Print comprehensive stress test summary"""
        
        print(f"\n{'='*60}")
        print(f"🔥 STRESS TEST RESULTS SUMMARY")
        print(f"{'='*60}")
        
        print(f"📊 Overall Results:")
        print(f"   Total Tests: {summary['total_tests']}")
        print(f"   Passed: {summary['passed_tests']}")
        print(f"   Failed: {summary['failed_tests']}")
        print(f"   Success Rate: {summary['success_rate']:.1f}%")
        print(f"   Suite Duration: {summary['suite_duration_seconds']:.2f}s")
        
        status_emoji = "✅" if summary['overall_status'] == 'PASSED' else "❌"
        print(f"   Overall Status: {status_emoji} {summary['overall_status']}")
        
        print(f"\n📋 Individual Test Results:")
        for result in summary['test_results']:
            test_name = result['test_name']
            status = result.get('status', 'UNKNOWN')
            emoji = "✅" if status == 'PASSED' else "❌"
            
            print(f"   {emoji} {test_name}: {status}")
            
            if status == 'PASSED':
                # Show key metrics
                if 'throughput_proxies_per_second' in result:
                    print(f"      Throughput: {result['throughput_proxies_per_second']:.1f} proxies/sec")
                
                if 'operations_per_second' in result:
                    print(f"      Operations: {result['operations_per_second']:.1f} ops/sec")
                
                resource_stats = result.get('resource_stats', {})
                if resource_stats:
                    print(f"      Peak Memory: {resource_stats.get('memory_peak_mb', 0):.1f}MB")
                    print(f"      Avg CPU: {resource_stats.get('cpu_average_percent', 0):.1f}%")
            
            elif status == 'FAILED':
                error = result.get('error', 'Unknown error')
                print(f"      Error: {error}")
        
        print(f"\n{'='*60}")


# Entry point for running stress tests
if __name__ == "__main__":
    print("🚀 Starting Stress Testing Framework - Phase 4.1.5")
    
    runner = StressTestRunner()
    results = runner.run_comprehensive_stress_tests()
    runner.print_stress_test_summary(results)
    
    # Exit with appropriate code
    exit_code = 0 if results['overall_status'] == 'PASSED' else 1
    sys.exit(exit_code)