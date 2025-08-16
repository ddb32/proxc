#!/usr/bin/env python3
"""
Performance Benchmarking Suite - Phase 4.1.4

Comprehensive performance benchmarking system for regression testing.
Measures and tracks performance metrics across different system components.

Benchmark Categories:
- CLI Command Performance
- Validation Engine Throughput
- Database Operation Speed
- Memory Usage Patterns
- Concurrent Processing Performance
- Network Operation Efficiency
- File I/O Performance
- Advanced Validation Engine Performance
"""

import asyncio
import gc
import json
import logging
import os
import psutil
import statistics
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Callable
import subprocess
import concurrent.futures
from dataclasses import dataclass, field, asdict
from contextlib import contextmanager
import tracemalloc

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from proxc.proxy_cli.cli import detect_file_format, validate_proxy_address
from proxc.proxy_core.models import ProxyInfo, ProxyProtocol
from proxc.proxy_core.database import DatabaseManager
from proxc.proxy_core.utils import parse_proxy_from_line, validate_ip_address
from proxc.proxy_engine.validators import BatchValidator
from proxc.proxy_engine.exporters import ExportManager, ExportFormat
from proxc.proxy_engine.filters import ProxyFilter, FilterCriteria

# Import advanced validation components for benchmarking
from proxc.proxy_engine.advanced_validation_engine import (
    ProxyHealthScorer, ProxyStabilityTester, ResponseTimeMetrics, ValidationHistory
)
from proxc.proxy_engine.sla_monitoring import SLAMonitor, AdaptiveTimeoutManager
from proxc.proxy_engine.intelligent_validation_engine import (
    CircuitBreaker, AdaptiveRateLimiter, SmartRetryManager, ValidationConfidenceScorer
)


@dataclass
class PerformanceMetrics:
    """Performance metrics for a benchmark"""
    name: str
    iterations: int
    total_time: float
    average_time: float
    min_time: float
    max_time: float
    median_time: float
    std_deviation: float
    throughput: float  # operations per second
    memory_peak: float  # MB
    memory_average: float  # MB
    cpu_average: float  # percentage
    success_rate: float  # percentage
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class BenchmarkResult:
    """Complete benchmark result"""
    benchmark_name: str
    timestamp: datetime
    system_info: Dict[str, Any]
    metrics: PerformanceMetrics
    baseline_comparison: Optional[Dict[str, float]] = None
    regression_detected: bool = False
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            **asdict(self),
            'timestamp': self.timestamp.isoformat(),
            'metrics': self.metrics.to_dict()
        }


class SystemProfiler:
    """System resource profiling utilities"""
    
    def __init__(self):
        self.process = psutil.Process()
    
    @contextmanager
    def profile_resources(self):
        """Context manager for profiling system resources"""
        
        # Start memory tracing
        tracemalloc.start()
        
        # Initial measurements
        initial_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        initial_cpu_percent = self.process.cpu_percent()
        
        # Resource tracking
        memory_samples = [initial_memory]
        cpu_samples = [initial_cpu_percent]
        
        start_time = time.time()
        
        class ResourceTracker:
            def __init__(self, profiler_instance):
                self.profiler = profiler_instance
                self.memory_samples = memory_samples
                self.cpu_samples = cpu_samples
                self.monitoring = True
                self.monitor_thread = threading.Thread(target=self._monitor_resources)
                self.monitor_thread.daemon = True
                self.monitor_thread.start()
            
            def _monitor_resources(self):
                """Monitor resources in background thread"""
                while self.monitoring:
                    try:
                        memory_mb = self.profiler.process.memory_info().rss / 1024 / 1024
                        cpu_percent = self.profiler.process.cpu_percent()
                        
                        self.memory_samples.append(memory_mb)
                        self.cpu_samples.append(cpu_percent)
                        
                        time.sleep(0.1)  # Sample every 100ms
                    except:
                        break
            
            def stop_monitoring(self):
                """Stop resource monitoring"""
                self.monitoring = False
                if self.monitor_thread.is_alive():
                    self.monitor_thread.join(timeout=1.0)
                
                # Get memory tracing stats
                current, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                
                return {
                    'peak_memory_mb': max(self.memory_samples),
                    'average_memory_mb': statistics.mean(self.memory_samples),
                    'average_cpu_percent': statistics.mean(self.cpu_samples),
                    'traced_peak_mb': peak / 1024 / 1024,
                    'duration': time.time() - start_time
                }
        
        tracker = ResourceTracker(self)
        
        try:
            yield tracker
        finally:
            resource_stats = tracker.stop_monitoring()
            tracker.resource_stats = resource_stats
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information"""
        
        cpu_info = {}
        try:
            cpu_info = {
                'cpu_count': psutil.cpu_count(),
                'cpu_count_logical': psutil.cpu_count(logical=True),
                'cpu_freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
            }
        except:
            pass
        
        memory_info = {}
        try:
            virtual_memory = psutil.virtual_memory()
            memory_info = {
                'total_memory_gb': virtual_memory.total / 1024 / 1024 / 1024,
                'available_memory_gb': virtual_memory.available / 1024 / 1024 / 1024,
                'memory_percent': virtual_memory.percent
            }
        except:
            pass
        
        disk_info = {}
        try:
            disk_usage = psutil.disk_usage('/')
            disk_info = {
                'total_disk_gb': disk_usage.total / 1024 / 1024 / 1024,
                'free_disk_gb': disk_usage.free / 1024 / 1024 / 1024,
                'disk_percent': (disk_usage.used / disk_usage.total) * 100
            }
        except:
            pass
        
        return {
            'platform': sys.platform,
            'python_version': sys.version,
            'cpu_info': cpu_info,
            'memory_info': memory_info,
            'disk_info': disk_info,
            'process_id': os.getpid()
        }


class PerformanceBenchmark:
    """Individual performance benchmark implementation"""
    
    def __init__(self, name: str, setup_func: Callable = None, teardown_func: Callable = None):
        self.name = name
        self.setup_func = setup_func
        self.teardown_func = teardown_func
        self.profiler = SystemProfiler()
    
    def run_benchmark(self, benchmark_func: Callable, iterations: int = 100, 
                     warmup_iterations: int = 10, **kwargs) -> BenchmarkResult:
        """Run benchmark with comprehensive metrics collection"""
        
        print(f"🏃 Running benchmark: {self.name} ({iterations} iterations)")
        
        # Setup
        if self.setup_func:
            setup_data = self.setup_func()
            if setup_data:
                kwargs.update(setup_data)
        
        try:
            # Warmup runs
            print(f"  🔥 Warmup: {warmup_iterations} iterations...")
            for _ in range(warmup_iterations):
                try:
                    benchmark_func(**kwargs)
                except Exception:
                    pass  # Ignore warmup errors
            
            # Force garbage collection before measurement
            gc.collect()
            
            # Main benchmark run
            print(f"  📊 Measuring: {iterations} iterations...")
            
            execution_times = []
            errors = []
            successful_runs = 0
            
            with self.profiler.profile_resources() as tracker:
                for i in range(iterations):
                    start_time = time.perf_counter()
                    
                    try:
                        benchmark_func(**kwargs)
                        successful_runs += 1
                    except Exception as e:
                        errors.append(f"Iteration {i}: {str(e)}")
                    
                    end_time = time.perf_counter()
                    execution_times.append(end_time - start_time)
            
            # Get resource statistics
            resource_stats = tracker.resource_stats
            
            # Calculate performance metrics
            if execution_times:
                total_time = sum(execution_times)
                average_time = statistics.mean(execution_times)
                min_time = min(execution_times)
                max_time = max(execution_times)
                median_time = statistics.median(execution_times)
                std_deviation = statistics.stdev(execution_times) if len(execution_times) > 1 else 0.0
                throughput = successful_runs / total_time if total_time > 0 else 0.0
                success_rate = (successful_runs / iterations) * 100
            else:
                total_time = average_time = min_time = max_time = median_time = std_deviation = throughput = 0.0
                success_rate = 0.0
            
            metrics = PerformanceMetrics(
                name=self.name,
                iterations=iterations,
                total_time=total_time,
                average_time=average_time,
                min_time=min_time,
                max_time=max_time,
                median_time=median_time,
                std_deviation=std_deviation,
                throughput=throughput,
                memory_peak=resource_stats['peak_memory_mb'],
                memory_average=resource_stats['average_memory_mb'],
                cpu_average=resource_stats['average_cpu_percent'],
                success_rate=success_rate,
                errors=errors[:10]  # Keep first 10 errors
            )
            
            result = BenchmarkResult(
                benchmark_name=self.name,
                timestamp=datetime.now(),
                system_info=self.profiler.get_system_info(),
                metrics=metrics
            )
            
            return result
        
        finally:
            # Teardown
            if self.teardown_func:
                self.teardown_func()


class CLIPerformanceBenchmarks:
    """CLI-specific performance benchmarks"""
    
    def __init__(self):
        self.temp_dir = None
        self.test_files = {}
    
    def setup(self):
        """Set up test environment"""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="perf_test_"))
        
        # Create test files
        self._create_test_files()
        
        return {
            'temp_dir': self.temp_dir,
            'test_files': self.test_files
        }
    
    def teardown(self):
        """Clean up test environment"""
        if self.temp_dir and self.temp_dir.exists():
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _create_test_files(self):
        """Create test data files"""
        
        # Small proxy list (100 proxies)
        small_file = self.temp_dir / "small_proxies.txt"
        with open(small_file, 'w') as f:
            for i in range(100):
                f.write(f"192.168.{i//256}.{i%256}:{8000+i}\n")
        self.test_files['small'] = small_file
        
        # Medium proxy list (1000 proxies)
        medium_file = self.temp_dir / "medium_proxies.txt"
        with open(medium_file, 'w') as f:
            for i in range(1000):
                f.write(f"10.{i//65536}.{(i//256)%256}.{i%256}:{8000+i%1000}\n")
        self.test_files['medium'] = medium_file
        
        # Large proxy list (10000 proxies)
        large_file = self.temp_dir / "large_proxies.txt"
        with open(large_file, 'w') as f:
            for i in range(10000):
                f.write(f"172.16.{(i//256)%256}.{i%256}:{8000+i%10000}\n")
        self.test_files['large'] = large_file
        
        # JSON format
        json_file = self.temp_dir / "proxies.json"
        proxy_data = []
        for i in range(1000):
            proxy_data.append({
                "host": f"172.16.{(i//256)%256}.{i%256}",
                "port": 8000 + i%1000,
                "protocol": "http",
                "source": "test"
            })
        
        with open(json_file, 'w') as f:
            json.dump(proxy_data, f)
        self.test_files['json'] = json_file
    
    def benchmark_file_format_detection(self, temp_dir, test_files, **kwargs):
        """Benchmark file format detection"""
        test_file = test_files['medium']
        detect_file_format(str(test_file))
    
    def benchmark_proxy_validation_function(self, temp_dir, test_files, **kwargs):
        """Benchmark single proxy validation function"""
        validate_proxy_address("192.168.1.1:8080")
    
    def benchmark_ip_validation_function(self, temp_dir, test_files, **kwargs):
        """Benchmark IP validation function"""
        validate_ip_address("192.168.1.1")
    
    def benchmark_proxy_parsing_function(self, temp_dir, test_files, **kwargs):
        """Benchmark proxy parsing function"""
        parse_proxy_from_line("192.168.1.1:8080")
    
    def benchmark_file_reading_small(self, temp_dir, test_files, **kwargs):
        """Benchmark reading small proxy file"""
        with open(test_files['small'], 'r') as f:
            lines = f.readlines()
    
    def benchmark_file_reading_medium(self, temp_dir, test_files, **kwargs):
        """Benchmark reading medium proxy file"""
        with open(test_files['medium'], 'r') as f:
            lines = f.readlines()
    
    def benchmark_file_reading_large(self, temp_dir, test_files, **kwargs):
        """Benchmark reading large proxy file"""
        with open(test_files['large'], 'r') as f:
            lines = f.readlines()
    
    def benchmark_json_parsing(self, temp_dir, test_files, **kwargs):
        """Benchmark JSON parsing performance"""
        with open(test_files['json'], 'r') as f:
            data = json.load(f)


class DatabasePerformanceBenchmarks:
    """Database-specific performance benchmarks"""
    
    def __init__(self):
        self.db_path = None
        self.db = None
        self.test_proxies = []
    
    def setup(self):
        """Set up database test environment"""
        temp_dir = Path(tempfile.mkdtemp(prefix="db_perf_test_"))
        self.db_path = temp_dir / "test_perf.db"
        
        self.db = DatabaseManager(str(self.db_path))
        self.db.initialize_database()
        
        # Create test proxies
        self.test_proxies = []
        for i in range(1000):
            proxy = ProxyInfo(
                host=f"192.168.{i//256}.{i%256}",
                port=8000 + i,
                protocol=ProxyProtocol.HTTP,
                source="performance_test"
            )
            self.test_proxies.append(proxy)
        
        return {
            'db': self.db,
            'test_proxies': self.test_proxies
        }
    
    def teardown(self):
        """Clean up database"""
        if self.db:
            try:
                self.db.close()
            except:
                pass
        
        if self.db_path and self.db_path.exists():
            try:
                self.db_path.unlink()
                self.db_path.parent.rmdir()
            except:
                pass
    
    def benchmark_single_proxy_insert(self, db, test_proxies, **kwargs):
        """Benchmark single proxy insertion"""
        proxy = test_proxies[0]
        db.store_proxy(proxy)
    
    def benchmark_batch_proxy_insert(self, db, test_proxies, **kwargs):
        """Benchmark batch proxy insertion"""
        batch = test_proxies[:100]
        db.store_proxies_batch(batch)
    
    def benchmark_proxy_query_all(self, db, test_proxies, **kwargs):
        """Benchmark querying all proxies"""
        # First insert some data
        db.store_proxies_batch(test_proxies[:100])
        
        # Then query
        proxies = db.get_all_proxies()
    
    def benchmark_proxy_query_by_status(self, db, test_proxies, **kwargs):
        """Benchmark querying proxies by status"""
        # First insert some data
        db.store_proxies_batch(test_proxies[:100])
        
        # Then query by status
        working_proxies = db.get_proxies_by_status("working")
    
    def benchmark_proxy_update_status(self, db, test_proxies, **kwargs):
        """Benchmark updating proxy status"""
        # First insert a proxy
        proxy = test_proxies[0]
        proxy_id = db.store_proxy(proxy)
        
        # Then update its status
        db.update_proxy_status(proxy_id, "working", 150.0)


class ValidationEnginePerformanceBenchmarks:
    """Validation engine performance benchmarks"""
    
    def __init__(self):
        self.test_proxies = []
    
    def setup(self):
        """Set up validation test environment"""
        # Create test proxies (using localhost for consistent testing)
        self.test_proxies = []
        for i in range(100):
            proxy = ProxyInfo(
                host="127.0.0.1",
                port=8000 + i,
                protocol=ProxyProtocol.HTTP,
                source="validation_test"
            )
            self.test_proxies.append(proxy)
        
        return {
            'test_proxies': self.test_proxies
        }
    
    def teardown(self):
        """Clean up validation environment"""
        pass
    
    def benchmark_health_score_calculation(self, test_proxies, **kwargs):
        """Benchmark health score calculation"""
        scorer = ProxyHealthScorer()
        
        # Create mock metrics
        response_metrics = ResponseTimeMetrics()
        response_metrics.add_measurement(100.0)
        response_metrics.add_measurement(150.0)
        response_metrics.add_measurement(120.0)
        
        validation_history = ValidationHistory()
        validation_history.add_result(True)
        validation_history.add_result(True)
        validation_history.add_result(False)
        
        # Calculate health score
        health_score = scorer.calculate_health_score(
            "127.0.0.1:8080", response_metrics, validation_history
        )
    
    def benchmark_sla_monitoring(self, test_proxies, **kwargs):
        """Benchmark SLA monitoring"""
        monitor = SLAMonitor()
        
        # Create mock metrics
        response_metrics = ResponseTimeMetrics()
        response_metrics.add_measurement(100.0)
        
        validation_history = ValidationHistory()
        validation_history.add_result(True)
        
        # Evaluate SLA compliance
        compliance = monitor.evaluate_sla_compliance(
            "127.0.0.1:8080", response_metrics, validation_history
        )
    
    def benchmark_adaptive_timeout_manager(self, test_proxies, **kwargs):
        """Benchmark adaptive timeout manager"""
        manager = AdaptiveTimeoutManager()
        
        # Record performance data
        manager.record_performance("127.0.0.1:8080", True, 100.0, 5.0)
        
        # Get adaptive timeout
        timeout = manager.get_adaptive_timeout("127.0.0.1:8080")
    
    def benchmark_circuit_breaker(self, test_proxies, **kwargs):
        """Benchmark circuit breaker"""
        breaker = CircuitBreaker()
        
        async def test_function():
            return "success"
        
        async def run_test():
            result = await breaker.call(test_function)
        
        # Run the async test
        asyncio.run(run_test())
    
    def benchmark_rate_limiter(self, test_proxies, **kwargs):
        """Benchmark adaptive rate limiter"""
        limiter = AdaptiveRateLimiter()
        
        async def test_acquire():
            acquired = await limiter.acquire()
            limiter.record_response(True, 100.0)
        
        # Run the async test
        asyncio.run(test_acquire())
    
    def benchmark_confidence_scorer(self, test_proxies, **kwargs):
        """Benchmark validation confidence scorer"""
        scorer = ValidationConfidenceScorer()
        
        # Create mock validation results
        from proxc.proxy_engine.intelligent_validation_engine import ValidationResult
        from proxc.proxy_core.models import ValidationStatus
        
        validation_results = [
            ValidationResult(
                proxy_address="127.0.0.1:8080",
                is_valid=True,
                status=ValidationStatus.VALID,
                response_time_ms=100.0,
                confidence_score=0.9,
                validation_method="http_request"
            )
        ]
        
        # Calculate confidence
        confidence = scorer.calculate_confidence(validation_results)


class PerformanceBenchmarkSuite:
    """Complete performance benchmark suite"""
    
    def __init__(self):
        self.results = []
        self.baseline_results = {}
        self.regression_threshold = 0.20  # 20% performance degradation threshold
    
    def load_baseline_results(self, baseline_file: Path):
        """Load baseline performance results for comparison"""
        if baseline_file.exists():
            try:
                with open(baseline_file, 'r') as f:
                    data = json.load(f)
                    
                for result_data in data:
                    result = BenchmarkResult(
                        benchmark_name=result_data['benchmark_name'],
                        timestamp=datetime.fromisoformat(result_data['timestamp']),
                        system_info=result_data['system_info'],
                        metrics=PerformanceMetrics(**result_data['metrics'])
                    )
                    self.baseline_results[result.benchmark_name] = result
                
                print(f"📊 Loaded {len(self.baseline_results)} baseline results")
            
            except Exception as e:
                print(f"⚠️ Failed to load baseline results: {e}")
    
    def save_results_as_baseline(self, baseline_file: Path):
        """Save current results as new baseline"""
        try:
            data = [result.to_dict() for result in self.results]
            
            with open(baseline_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"💾 Saved {len(self.results)} results as baseline")
        
        except Exception as e:
            print(f"⚠️ Failed to save baseline results: {e}")
    
    def detect_regressions(self):
        """Detect performance regressions compared to baseline"""
        
        regressions_detected = []
        
        for result in self.results:
            if result.benchmark_name in self.baseline_results:
                baseline = self.baseline_results[result.benchmark_name]
                current = result.metrics
                baseline_metrics = baseline.metrics
                
                # Compare key metrics
                throughput_change = ((current.throughput - baseline_metrics.throughput) / 
                                   baseline_metrics.throughput) if baseline_metrics.throughput > 0 else 0
                
                avg_time_change = ((current.average_time - baseline_metrics.average_time) / 
                                 baseline_metrics.average_time) if baseline_metrics.average_time > 0 else 0
                
                memory_change = ((current.memory_peak - baseline_metrics.memory_peak) / 
                               baseline_metrics.memory_peak) if baseline_metrics.memory_peak > 0 else 0
                
                # Detect significant regressions
                regression_detected = False
                regression_details = []
                
                if throughput_change < -self.regression_threshold:
                    regression_detected = True
                    regression_details.append(f"Throughput decreased by {abs(throughput_change)*100:.1f}%")
                
                if avg_time_change > self.regression_threshold:
                    regression_detected = True
                    regression_details.append(f"Average time increased by {avg_time_change*100:.1f}%")
                
                if memory_change > self.regression_threshold:
                    regression_detected = True
                    regression_details.append(f"Memory usage increased by {memory_change*100:.1f}%")
                
                result.regression_detected = regression_detected
                result.baseline_comparison = {
                    'throughput_change_percent': throughput_change * 100,
                    'avg_time_change_percent': avg_time_change * 100,
                    'memory_change_percent': memory_change * 100,
                    'regression_details': regression_details
                }
                
                if regression_detected:
                    regressions_detected.append(result)
        
        return regressions_detected
    
    def run_all_benchmarks(self) -> Dict[str, Any]:
        """Run complete benchmark suite"""
        
        print("🚀 Starting Performance Benchmark Suite - Phase 4.1.4")
        print("=" * 60)
        
        start_time = time.time()
        
        # CLI Performance Benchmarks
        print("\n📋 CLI Performance Benchmarks")
        cli_benchmarks = CLIPerformanceBenchmarks()
        
        cli_tests = [
            ("File Format Detection", cli_benchmarks.benchmark_file_format_detection, 1000),
            ("Proxy Validation Function", cli_benchmarks.benchmark_proxy_validation_function, 1000),
            ("IP Validation Function", cli_benchmarks.benchmark_ip_validation_function, 1000),
            ("Proxy Parsing Function", cli_benchmarks.benchmark_proxy_parsing_function, 1000),
            ("Small File Reading", cli_benchmarks.benchmark_file_reading_small, 100),
            ("Medium File Reading", cli_benchmarks.benchmark_file_reading_medium, 50),
            ("Large File Reading", cli_benchmarks.benchmark_file_reading_large, 10),
            ("JSON Parsing", cli_benchmarks.benchmark_json_parsing, 100)
        ]
        
        for name, func, iterations in cli_tests:
            benchmark = PerformanceBenchmark(name, cli_benchmarks.setup, cli_benchmarks.teardown)
            result = benchmark.run_benchmark(func, iterations=iterations)
            self.results.append(result)
        
        # Database Performance Benchmarks
        print("\n🗄️ Database Performance Benchmarks")
        db_benchmarks = DatabasePerformanceBenchmarks()
        
        db_tests = [
            ("Single Proxy Insert", db_benchmarks.benchmark_single_proxy_insert, 1000),
            ("Batch Proxy Insert", db_benchmarks.benchmark_batch_proxy_insert, 100),
            ("Query All Proxies", db_benchmarks.benchmark_proxy_query_all, 100),
            ("Query by Status", db_benchmarks.benchmark_proxy_query_by_status, 100),
            ("Update Proxy Status", db_benchmarks.benchmark_proxy_update_status, 1000)
        ]
        
        for name, func, iterations in db_tests:
            benchmark = PerformanceBenchmark(name, db_benchmarks.setup, db_benchmarks.teardown)
            result = benchmark.run_benchmark(func, iterations=iterations)
            self.results.append(result)
        
        # Validation Engine Performance Benchmarks
        print("\n🔍 Validation Engine Performance Benchmarks")
        validation_benchmarks = ValidationEnginePerformanceBenchmarks()
        
        validation_tests = [
            ("Health Score Calculation", validation_benchmarks.benchmark_health_score_calculation, 1000),
            ("SLA Monitoring", validation_benchmarks.benchmark_sla_monitoring, 1000),
            ("Adaptive Timeout Manager", validation_benchmarks.benchmark_adaptive_timeout_manager, 1000),
            ("Circuit Breaker", validation_benchmarks.benchmark_circuit_breaker, 500),
            ("Rate Limiter", validation_benchmarks.benchmark_rate_limiter, 500),
            ("Confidence Scorer", validation_benchmarks.benchmark_confidence_scorer, 1000)
        ]
        
        for name, func, iterations in validation_tests:
            benchmark = PerformanceBenchmark(name, validation_benchmarks.setup, validation_benchmarks.teardown)
            result = benchmark.run_benchmark(func, iterations=iterations)
            self.results.append(result)
        
        total_duration = time.time() - start_time
        
        # Detect regressions
        regressions = self.detect_regressions()
        
        # Generate summary
        summary = {
            'total_benchmarks': len(self.results),
            'total_duration_seconds': total_duration,
            'regressions_detected': len(regressions),
            'results': [result.to_dict() for result in self.results],
            'regressions': [result.to_dict() for result in regressions]
        }
        
        return summary
    
    def print_summary(self, summary: Dict[str, Any]):
        """Print comprehensive benchmark summary"""
        
        print(f"\n{'='*60}")
        print(f"🏆 PERFORMANCE BENCHMARK RESULTS")
        print(f"{'='*60}")
        
        print(f"📊 Overall Results:")
        print(f"   Total Benchmarks: {summary['total_benchmarks']}")
        print(f"   Total Duration: {summary['total_duration_seconds']:.2f}s")
        print(f"   Regressions Detected: {summary['regressions_detected']}")
        
        print(f"\n📋 Benchmark Results:")
        for result_data in summary['results']:
            metrics = result_data['metrics']
            name = result_data['benchmark_name']
            
            # Performance indicators
            throughput = metrics['throughput']
            avg_time = metrics['average_time'] * 1000  # Convert to ms
            memory_peak = metrics['memory_peak']
            success_rate = metrics['success_rate']
            
            # Regression status
            regression_status = ""
            if result_data.get('regression_detected'):
                regression_status = " ⚠️ REGRESSION"
            elif result_data.get('baseline_comparison'):
                regression_status = " ✅ OK"
            
            print(f"   📈 {name}{regression_status}")
            print(f"      Throughput: {throughput:.1f} ops/sec")
            print(f"      Avg Time: {avg_time:.3f}ms")
            print(f"      Memory Peak: {memory_peak:.1f}MB")
            print(f"      Success Rate: {success_rate:.1f}%")
            
            if result_data.get('baseline_comparison'):
                comparison = result_data['baseline_comparison']
                throughput_change = comparison['throughput_change_percent']
                time_change = comparison['avg_time_change_percent']
                memory_change = comparison['memory_change_percent']
                
                print(f"      vs Baseline: Throughput {throughput_change:+.1f}%, "
                      f"Time {time_change:+.1f}%, Memory {memory_change:+.1f}%")
        
        if summary['regressions_detected'] > 0:
            print(f"\n🚨 Performance Regressions Detected:")
            for regression_data in summary['regressions']:
                name = regression_data['benchmark_name']
                details = regression_data['baseline_comparison']['regression_details']
                print(f"   ❌ {name}: {'; '.join(details)}")
        
        print(f"\n{'='*60}")


# Entry point for running performance benchmarks
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Performance Benchmark Suite")
    parser.add_argument("--baseline", type=str, help="Baseline results file")
    parser.add_argument("--save-baseline", type=str, help="Save results as baseline")
    args = parser.parse_args()
    
    suite = PerformanceBenchmarkSuite()
    
    # Load baseline if provided
    if args.baseline:
        suite.load_baseline_results(Path(args.baseline))
    
    # Run benchmarks
    results = suite.run_all_benchmarks()
    suite.print_summary(results)
    
    # Save as baseline if requested
    if args.save_baseline:
        suite.save_results_as_baseline(Path(args.save_baseline))
    
    # Exit with appropriate code
    exit_code = 0 if results['regressions_detected'] == 0 else 1
    sys.exit(exit_code)