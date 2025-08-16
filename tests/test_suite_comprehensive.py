#!/usr/bin/env python3
"""
Comprehensive Unit Test Suite - Phase 4.1.1

Complete unit test coverage for all CLI functions, core models,
validation engines, and utility functions.

Test Categories:
- CLI Functions and Commands
- Core Models and Data Structures  
- Validation Engines and Algorithms
- Proxy Engine Components
- Configuration Management
- Database Operations
- Export/Import Functions
- Error Handling and Edge Cases
"""

import asyncio
import json
import logging
import os
import pytest
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import threading
import time

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import modules to test
from proxc.proxy_cli.cli import (
    detect_file_format, infer_proxy_protocol, 
    validate_proxy_address, validate_output_format
)
from proxc.proxy_cli.cli_base import CLIFormatterMixin, CLIProgressTracker
from proxc.proxy_cli.cli_exceptions import ProxyCLIError, CommandError, ConfigurationError
from proxc.proxy_cli.command_utils import (
    parse_proxy_string, format_proxy_output, 
    calculate_eta, format_duration
)

from proxc.proxy_core.models import (
    ProxyInfo, ProxyProtocol, AnonymityLevel, ThreatLevel, 
    ProxyStatus, ValidationStatus, GeoLocation
)
from proxc.proxy_core.config import ConfigManager
from proxc.proxy_core.database import DatabaseManager
from proxc.proxy_core.utils import (
    validate_ip_address, parse_proxy_from_line,
    sanitize_filename, create_backup_filename
)
from proxc.proxy_core.metrics import MetricsCollector

from proxc.proxy_engine.validators import ValidationMethod
from proxc.proxy_engine.filters import ProxyFilter, FilterCriteria
from proxc.proxy_engine.exporters import ExportManager, ExportFormat
from proxc.proxy_engine.analyzers import ProxyAnalyzer

# Import advanced validation components
from proxc.proxy_engine.advanced_validation_engine import (
    ProxyHealthScorer, ProxyStabilityTester, HealthScore, 
    ResponseTimeMetrics, ValidationHistory
)
from proxc.proxy_engine.sla_monitoring import (
    SLAMonitor, AdaptiveTimeoutManager, SLATier, SLADefinition
)
from proxc.proxy_engine.intelligent_validation_engine import (
    CircuitBreaker, AdaptiveRateLimiter, SmartRetryManager,
    ValidationConfidenceScorer, ValidationResult
)
from proxc.proxy_engine.geo_reputation_validator import (
    GeolocationValidator, IPReputationChecker
)


class TestCLIFunctions(unittest.TestCase):
    """Test CLI utility functions and command processing"""
    
    def test_detect_file_format(self):
        """Test file format detection from extensions"""
        test_cases = [
            ("proxies.txt", "txt"),
            ("data.json", "json"),
            ("export.csv", "csv"),
            ("results.xlsx", "xlsx"),
            ("legacy.xls", "xlsx"),
            ("unknown.bin", "txt"),  # Default fallback
            ("file_without_extension", "txt")
        ]
        
        for file_path, expected_format in test_cases:
            with self.subTest(file_path=file_path):
                result = detect_file_format(file_path)
                self.assertEqual(result, expected_format)
    
    def test_infer_proxy_protocol(self):
        """Test smart protocol detection from proxy strings"""
        test_cases = [
            ("127.0.0.1:8080", "http"),
            ("192.168.1.1:1080", "socks5"),
            ("proxy.example.com:3128", "http"),
            ("10.0.0.1:9050", "socks5"),
            ("simple_string", "http"),  # Default fallback
            ("", "http")  # Empty string fallback
        ]
        
        for proxy_string, expected_protocol in test_cases:
            with self.subTest(proxy_string=proxy_string):
                result = infer_proxy_protocol(proxy_string)
                self.assertEqual(result, expected_protocol)
    
    def test_validate_proxy_address(self):
        """Test proxy address validation"""
        valid_addresses = [
            "127.0.0.1:8080",
            "192.168.1.1:3128",
            "proxy.example.com:1080",
            "10.0.0.1:9050"
        ]
        
        invalid_addresses = [
            "256.256.256.256:8080",  # Invalid IP
            "127.0.0.1:99999",       # Invalid port
            "127.0.0.1",             # Missing port
            "invalid:port",          # Invalid format
            "",                      # Empty string
            "127.0.0.1:-1"          # Negative port
        ]
        
        # Test valid addresses
        for address in valid_addresses:
            with self.subTest(address=address):
                result = validate_proxy_address(address)
                self.assertTrue(result, f"Address {address} should be valid")
        
        # Test invalid addresses
        for address in invalid_addresses:
            with self.subTest(address=address):
                result = validate_proxy_address(address)
                self.assertFalse(result, f"Address {address} should be invalid")
    
    def test_validate_output_format(self):
        """Test output format validation"""
        valid_formats = ["txt", "json", "csv", "xlsx"]
        invalid_formats = ["xml", "pdf", "invalid", "", None]
        
        for format_name in valid_formats:
            with self.subTest(format_name=format_name):
                result = validate_output_format(format_name)
                self.assertTrue(result)
        
        for format_name in invalid_formats:
            with self.subTest(format_name=format_name):
                result = validate_output_format(format_name)
                self.assertFalse(result)


class TestCLIBase(unittest.TestCase):
    """Test CLI base classes and mixins"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.formatter = CLIFormatterMixin()
        self.progress_tracker = CLIProgressTracker()
    
    def test_cli_formatter_mixin(self):
        """Test CLI formatting utilities"""
        # Test basic formatting
        result = self.formatter.format_success("Test message")
        self.assertIn("Test message", result)
        
        result = self.formatter.format_error("Error message")
        self.assertIn("Error message", result)
        
        result = self.formatter.format_warning("Warning message")
        self.assertIn("Warning message", result)
    
    def test_progress_tracker(self):
        """Test progress tracking functionality"""
        # Initialize progress tracker
        self.progress_tracker.start_progress(total=100, description="Test Progress")
        
        # Update progress
        self.progress_tracker.update_progress(25)
        self.assertEqual(self.progress_tracker.current, 25)
        
        # Update with message
        self.progress_tracker.update_progress(50, message="Halfway done")
        self.assertEqual(self.progress_tracker.current, 50)
        
        # Complete progress
        self.progress_tracker.finish_progress()
        self.assertTrue(self.progress_tracker.completed)


class TestCLIExceptions(unittest.TestCase):
    """Test CLI exception handling"""
    
    def test_proxy_cli_error(self):
        """Test base ProxyCLIError exception"""
        error = ProxyCLIError("Test error message")
        self.assertEqual(str(error), "Test error message")
        self.assertIsInstance(error, Exception)
    
    def test_command_error(self):
        """Test CommandError exception"""
        error = CommandError("Invalid command", exit_code=2)
        self.assertEqual(str(error), "Invalid command")
        self.assertEqual(error.exit_code, 2)
    
    def test_configuration_error(self):
        """Test ConfigurationError exception"""
        error = ConfigurationError("Invalid configuration")
        self.assertEqual(str(error), "Invalid configuration")
        self.assertIsInstance(error, ProxyCLIError)


class TestCommandUtils(unittest.TestCase):
    """Test command utility functions"""
    
    def test_parse_proxy_string(self):
        """Test proxy string parsing"""
        test_cases = [
            ("127.0.0.1:8080", ("127.0.0.1", 8080, None)),
            ("user:pass@proxy.com:3128", ("proxy.com", 3128, ("user", "pass"))),
            ("192.168.1.1:1080", ("192.168.1.1", 1080, None)),
            ("invalid", None)  # Invalid format
        ]
        
        for proxy_string, expected in test_cases:
            with self.subTest(proxy_string=proxy_string):
                result = parse_proxy_string(proxy_string)
                self.assertEqual(result, expected)
    
    def test_format_proxy_output(self):
        """Test proxy output formatting"""
        proxy = ProxyInfo(
            host="127.0.0.1",
            port=8080,
            protocol=ProxyProtocol.HTTP,
            source="test"
        )
        
        # Test different formats
        txt_output = format_proxy_output(proxy, "txt")
        self.assertIn("127.0.0.1:8080", txt_output)
        
        json_output = format_proxy_output(proxy, "json")
        self.assertTrue(json_output.startswith("{"))
    
    def test_calculate_eta(self):
        """Test ETA calculation"""
        start_time = time.time() - 60  # 1 minute ago
        completed = 25
        total = 100
        
        eta = calculate_eta(start_time, completed, total)
        self.assertIsInstance(eta, (int, float))
        self.assertGreater(eta, 0)
    
    def test_format_duration(self):
        """Test duration formatting"""
        test_cases = [
            (0, "0s"),
            (30, "30s"),
            (90, "1m 30s"),
            (3661, "1h 1m 1s"),
            (86400, "1d 0h 0m 0s")
        ]
        
        for seconds, expected in test_cases:
            with self.subTest(seconds=seconds):
                result = format_duration(seconds)
                self.assertEqual(result, expected)


class TestCoreModels(unittest.TestCase):
    """Test core data models"""
    
    def test_proxy_info_creation(self):
        """Test ProxyInfo model creation and validation"""
        proxy = ProxyInfo(
            host="127.0.0.1",
            port=8080,
            protocol=ProxyProtocol.HTTP,
            source="test"
        )
        
        self.assertEqual(proxy.host, "127.0.0.1")
        self.assertEqual(proxy.port, 8080)
        self.assertEqual(proxy.protocol, ProxyProtocol.HTTP)
        self.assertEqual(proxy.address, "127.0.0.1:8080")
    
    def test_proxy_info_equality(self):
        """Test ProxyInfo equality comparison"""
        proxy1 = ProxyInfo("127.0.0.1", 8080, ProxyProtocol.HTTP, "test")
        proxy2 = ProxyInfo("127.0.0.1", 8080, ProxyProtocol.HTTP, "test")
        proxy3 = ProxyInfo("127.0.0.1", 3128, ProxyProtocol.HTTP, "test")
        
        self.assertEqual(proxy1, proxy2)
        self.assertNotEqual(proxy1, proxy3)
    
    def test_proxy_info_serialization(self):
        """Test ProxyInfo serialization to dict"""
        proxy = ProxyInfo(
            host="127.0.0.1",
            port=8080,
            protocol=ProxyProtocol.HTTP,
            source="test",
            anonymity_level=AnonymityLevel.ANONYMOUS
        )
        
        data = proxy.to_dict()
        self.assertIsInstance(data, dict)
        self.assertEqual(data["host"], "127.0.0.1")
        self.assertEqual(data["port"], 8080)
        self.assertEqual(data["protocol"], "http")
    
    def test_geo_location_model(self):
        """Test GeoLocation model"""
        geo = GeoLocation(
            country="United States",
            country_code="US",
            region="California",
            city="San Francisco",
            latitude=37.7749,
            longitude=-122.4194
        )
        
        self.assertEqual(geo.country, "United States")
        self.assertEqual(geo.country_code, "US")
        self.assertAlmostEqual(geo.latitude, 37.7749)
        self.assertAlmostEqual(geo.longitude, -122.4194)


class TestCoreUtils(unittest.TestCase):
    """Test core utility functions"""
    
    def test_validate_ip_address(self):
        """Test IP address validation"""
        valid_ips = [
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.1",
            "8.8.8.8",
            "255.255.255.255"
        ]
        
        invalid_ips = [
            "256.256.256.256",
            "127.0.0",
            "not.an.ip.address",
            "",
            "127.0.0.1.1"
        ]
        
        for ip in valid_ips:
            with self.subTest(ip=ip):
                self.assertTrue(validate_ip_address(ip))
        
        for ip in invalid_ips:
            with self.subTest(ip=ip):
                self.assertFalse(validate_ip_address(ip))
    
    def test_parse_proxy_from_line(self):
        """Test proxy parsing from text lines"""
        test_lines = [
            "127.0.0.1:8080",
            "192.168.1.1:3128 # HTTP proxy",
            "# Comment line",
            "",
            "invalid line",
            "10.0.0.1:1080  # SOCKS5"
        ]
        
        expected_results = [
            ("127.0.0.1", 8080),
            ("192.168.1.1", 3128),
            None,  # Comment
            None,  # Empty
            None,  # Invalid
            ("10.0.0.1", 1080)
        ]
        
        for line, expected in zip(test_lines, expected_results):
            with self.subTest(line=line):
                result = parse_proxy_from_line(line)
                if expected is None:
                    self.assertIsNone(result)
                else:
                    self.assertEqual(result[:2], expected)
    
    def test_sanitize_filename(self):
        """Test filename sanitization"""
        test_cases = [
            ("normal_file.txt", "normal_file.txt"),
            ("file with spaces.txt", "file_with_spaces.txt"),
            ("file/with\\invalid:chars.txt", "file_with_invalid_chars.txt"),
            ("file<>|?*.txt", "file.txt"),
            ("", "sanitized_filename")
        ]
        
        for input_name, expected in test_cases:
            with self.subTest(input_name=input_name):
                result = sanitize_filename(input_name)
                self.assertEqual(result, expected)
    
    def test_create_backup_filename(self):
        """Test backup filename creation"""
        original = "data.json"
        backup = create_backup_filename(original)
        
        self.assertTrue(backup.startswith("data"))
        self.assertTrue(backup.endswith(".json"))
        self.assertIn("backup", backup)


class TestConfigManager(unittest.TestCase):
    """Test configuration management"""
    
    def setUp(self):
        """Set up test configuration"""
        self.config = ConfigManager()
    
    def test_config_loading(self):
        """Test configuration loading"""
        # Test default configuration
        self.assertIsInstance(self.config.get("timeout"), (int, float))
        self.assertIsInstance(self.config.get("threads"), int)
    
    def test_config_validation(self):
        """Test configuration validation"""
        # Test valid values
        self.assertTrue(self.config.validate_timeout(5.0))
        self.assertTrue(self.config.validate_threads(10))
        
        # Test invalid values
        self.assertFalse(self.config.validate_timeout(-1))
        self.assertFalse(self.config.validate_threads(0))
        self.assertFalse(self.config.validate_timeout(1000))
    
    def test_config_updates(self):
        """Test configuration updates"""
        original_timeout = self.config.get("timeout")
        
        # Update configuration
        self.config.set("timeout", 10.0)
        self.assertEqual(self.config.get("timeout"), 10.0)
        
        # Restore original
        self.config.set("timeout", original_timeout)


class TestDatabaseManager(unittest.TestCase):
    """Test database operations"""
    
    def setUp(self):
        """Set up test database"""
        # Use in-memory database for testing
        self.db = DatabaseManager(":memory:")
        self.db.initialize_database()
    
    def test_database_initialization(self):
        """Test database initialization"""
        # Database should be initialized without errors
        self.assertTrue(self.db.is_initialized())
    
    def test_proxy_storage_and_retrieval(self):
        """Test storing and retrieving proxies"""
        proxy = ProxyInfo(
            host="127.0.0.1",
            port=8080,
            protocol=ProxyProtocol.HTTP,
            source="test"
        )
        
        # Store proxy
        proxy_id = self.db.store_proxy(proxy)
        self.assertIsNotNone(proxy_id)
        
        # Retrieve proxy
        retrieved = self.db.get_proxy(proxy_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.host, proxy.host)
        self.assertEqual(retrieved.port, proxy.port)
    
    def test_batch_operations(self):
        """Test batch database operations"""
        proxies = [
            ProxyInfo("127.0.0.1", 8080, ProxyProtocol.HTTP, "test"),
            ProxyInfo("127.0.0.1", 3128, ProxyProtocol.HTTP, "test"),
            ProxyInfo("127.0.0.1", 1080, ProxyProtocol.SOCKS5, "test")
        ]
        
        # Store batch
        proxy_ids = self.db.store_proxies_batch(proxies)
        self.assertEqual(len(proxy_ids), 3)
        
        # Retrieve all
        all_proxies = self.db.get_all_proxies()
        self.assertGreaterEqual(len(all_proxies), 3)


class TestMetricsCollector(unittest.TestCase):
    """Test metrics collection"""
    
    def setUp(self):
        """Set up metrics collector"""
        self.metrics = MetricsCollector()
    
    def test_metrics_initialization(self):
        """Test metrics collector initialization"""
        self.assertIsInstance(self.metrics.get_all_metrics(), dict)
    
    def test_counter_metrics(self):
        """Test counter metrics"""
        # Increment counter
        self.metrics.increment_counter("test_counter")
        self.assertEqual(self.metrics.get_counter("test_counter"), 1)
        
        # Increment by value
        self.metrics.increment_counter("test_counter", 5)
        self.assertEqual(self.metrics.get_counter("test_counter"), 6)
    
    def test_timing_metrics(self):
        """Test timing metrics"""
        # Record timing
        self.metrics.record_timing("test_operation", 1.5)
        
        timings = self.metrics.get_timings("test_operation")
        self.assertEqual(len(timings), 1)
        self.assertEqual(timings[0], 1.5)
    
    def test_metrics_reset(self):
        """Test metrics reset"""
        # Add some metrics
        self.metrics.increment_counter("test")
        self.metrics.record_timing("test", 1.0)
        
        # Reset
        self.metrics.reset_metrics()
        
        # Verify reset
        self.assertEqual(self.metrics.get_counter("test"), 0)
        self.assertEqual(len(self.metrics.get_timings("test")), 0)


class TestAdvancedValidationEngine(unittest.TestCase):
    """Test advanced validation engine components"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.health_scorer = ProxyHealthScorer()
        self.stability_tester = ProxyStabilityTester()
    
    def test_health_score_calculation(self):
        """Test health score calculation"""
        # Create mock response metrics
        response_metrics = ResponseTimeMetrics()
        response_metrics.add_measurement(100.0)
        response_metrics.add_measurement(150.0)
        response_metrics.add_measurement(120.0)
        
        # Create mock validation history
        validation_history = ValidationHistory()
        validation_history.add_result(True)
        validation_history.add_result(True)
        validation_history.add_result(False)
        
        # Calculate health score
        health_score = self.health_scorer.calculate_health_score(
            "127.0.0.1:8080", response_metrics, validation_history
        )
        
        self.assertIsInstance(health_score, HealthScore)
        self.assertGreater(health_score.overall_score, 0)
        self.assertLessEqual(health_score.overall_score, 100)
    
    def test_response_time_metrics(self):
        """Test response time metrics calculation"""
        metrics = ResponseTimeMetrics()
        
        # Add measurements
        test_times = [100, 150, 120, 200, 80, 300, 95, 110, 140, 160]
        for time_ms in test_times:
            metrics.add_measurement(time_ms)
        
        # Verify statistics
        self.assertEqual(len(metrics.measurements), 10)
        self.assertGreater(metrics.p50, 0)
        self.assertGreater(metrics.p95, metrics.p50)
        self.assertGreater(metrics.mean, 0)
    
    def test_validation_history(self):
        """Test validation history tracking"""
        history = ValidationHistory()
        
        # Add some results
        history.add_result(True)
        history.add_result(True)
        history.add_result(False)
        history.add_result(True)
        
        # Test success rate
        success_rate = history.get_success_rate()
        self.assertEqual(success_rate, 75.0)  # 3/4 = 75%
        
        # Test reliability score
        reliability = history.get_reliability_score()
        self.assertGreater(reliability, 0)
        self.assertLessEqual(reliability, 100)


class TestSLAMonitoring(unittest.TestCase):
    """Test SLA monitoring system"""
    
    def setUp(self):
        """Set up SLA monitor"""
        self.sla_monitor = SLAMonitor()
        self.timeout_manager = AdaptiveTimeoutManager()
    
    def test_sla_definitions(self):
        """Test SLA definition creation"""
        sla_defs = SLADefinition.get_default_slas()
        
        self.assertIn(SLATier.PREMIUM, sla_defs)
        self.assertIn(SLATier.BUSINESS, sla_defs)
        self.assertIn(SLATier.STANDARD, sla_defs)
        self.assertIn(SLATier.BASIC, sla_defs)
        
        # Verify premium SLA is most strict
        premium = sla_defs[SLATier.PREMIUM]
        basic = sla_defs[SLATier.BASIC]
        
        self.assertLess(premium.max_response_time_ms, basic.max_response_time_ms)
        self.assertGreater(premium.min_uptime_percentage, basic.min_uptime_percentage)
    
    def test_adaptive_timeout_manager(self):
        """Test adaptive timeout management"""
        proxy_address = "127.0.0.1:8080"
        
        # Record some performance data
        self.timeout_manager.record_performance(proxy_address, True, 100.0, 5.0)
        self.timeout_manager.record_performance(proxy_address, True, 150.0, 5.0)
        self.timeout_manager.record_performance(proxy_address, False, 5000.0, 5.0)
        
        # Get current timeout
        timeout_config = self.timeout_manager.get_adaptive_timeout(proxy_address)
        self.assertIsNotNone(timeout_config)
        self.assertGreater(timeout_config.connect_timeout, 0)


class TestIntelligentValidation(unittest.TestCase):
    """Test intelligent validation components"""
    
    def setUp(self):
        """Set up validation components"""
        self.circuit_breaker = CircuitBreaker()
        self.rate_limiter = AdaptiveRateLimiter()
        self.retry_manager = SmartRetryManager()
        self.confidence_scorer = ValidationConfidenceScorer()
    
    def test_circuit_breaker(self):
        """Test circuit breaker functionality"""
        async def test_function():
            return "success"
        
        async def failing_function():
            raise Exception("Test failure")
        
        # Test successful operation
        async def run_success_test():
            result = await self.circuit_breaker.call(test_function)
            self.assertEqual(result, "success")
        
        # Run the test
        asyncio.run(run_success_test())
    
    def test_rate_limiter(self):
        """Test adaptive rate limiter"""
        # Test token acquisition
        acquired = asyncio.run(self.rate_limiter.acquire())
        self.assertTrue(acquired)
        
        # Record response
        self.rate_limiter.record_response(True, 100.0)
        
        # Get stats
        stats = self.rate_limiter.get_stats()
        self.assertIn("current_rate", stats)
        self.assertIn("available_tokens", stats)
    
    def test_confidence_scorer(self):
        """Test validation confidence scoring"""
        # Create mock validation results
        validation_results = [
            ValidationResult(
                proxy_address="127.0.0.1:8080",
                is_valid=True,
                status=ValidationStatus.VALID,
                response_time_ms=100.0,
                confidence_score=0.9,
                validation_method="http_request"
            ),
            ValidationResult(
                proxy_address="127.0.0.1:8080",
                is_valid=True,
                status=ValidationStatus.VALID,
                response_time_ms=120.0,
                confidence_score=0.85,
                validation_method="http_request"
            )
        ]
        
        # Calculate confidence
        confidence = self.confidence_scorer.calculate_confidence(validation_results)
        
        self.assertGreater(confidence.overall_confidence, 0)
        self.assertLessEqual(confidence.overall_confidence, 100)
        self.assertGreaterEqual(confidence.uncertainty, 0)


class TestFilters(unittest.TestCase):
    """Test proxy filtering functionality"""
    
    def setUp(self):
        """Set up test proxies"""
        self.proxies = [
            ProxyInfo("127.0.0.1", 8080, ProxyProtocol.HTTP, "source1"),
            ProxyInfo("127.0.0.1", 3128, ProxyProtocol.HTTP, "source2"),
            ProxyInfo("127.0.0.1", 1080, ProxyProtocol.SOCKS5, "source1"),
            ProxyInfo("192.168.1.1", 8080, ProxyProtocol.HTTP, "source3")
        ]
        self.filter = ProxyFilter()
    
    def test_protocol_filtering(self):
        """Test filtering by protocol"""
        criteria = FilterCriteria(protocols=[ProxyProtocol.HTTP])
        
        filtered = self.filter.apply_filters(self.proxies, criteria)
        
        self.assertEqual(len(filtered), 3)
        for proxy in filtered:
            self.assertEqual(proxy.protocol, ProxyProtocol.HTTP)
    
    def test_source_filtering(self):
        """Test filtering by source"""
        criteria = FilterCriteria(sources=["source1"])
        
        filtered = self.filter.apply_filters(self.proxies, criteria)
        
        self.assertEqual(len(filtered), 2)
        for proxy in filtered:
            self.assertEqual(proxy.source, "source1")
    
    def test_combined_filtering(self):
        """Test combined filtering criteria"""
        criteria = FilterCriteria(
            protocols=[ProxyProtocol.HTTP],
            sources=["source1"]
        )
        
        filtered = self.filter.apply_filters(self.proxies, criteria)
        
        self.assertEqual(len(filtered), 1)
        proxy = filtered[0]
        self.assertEqual(proxy.protocol, ProxyProtocol.HTTP)
        self.assertEqual(proxy.source, "source1")


class TestExportManager(unittest.TestCase):
    """Test export functionality"""
    
    def setUp(self):
        """Set up test data"""
        self.proxies = [
            ProxyInfo("127.0.0.1", 8080, ProxyProtocol.HTTP, "test"),
            ProxyInfo("127.0.0.1", 3128, ProxyProtocol.HTTP, "test"),
            ProxyInfo("127.0.0.1", 1080, ProxyProtocol.SOCKS5, "test")
        ]
        self.export_manager = ExportManager()
    
    def test_txt_export(self):
        """Test TXT format export"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            temp_path = f.name
        
        try:
            success = self.export_manager.export_proxies(
                self.proxies, temp_path, ExportFormat.TXT
            )
            self.assertTrue(success)
            
            # Verify file contents
            with open(temp_path, 'r') as f:
                content = f.read()
                self.assertIn("127.0.0.1:8080", content)
                self.assertIn("127.0.0.1:3128", content)
                self.assertIn("127.0.0.1:1080", content)
        
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_json_export(self):
        """Test JSON format export"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_path = f.name
        
        try:
            success = self.export_manager.export_proxies(
                self.proxies, temp_path, ExportFormat.JSON
            )
            self.assertTrue(success)
            
            # Verify file contents
            with open(temp_path, 'r') as f:
                data = json.load(f)
                self.assertIsInstance(data, list)
                self.assertEqual(len(data), 3)
        
        finally:
            Path(temp_path).unlink(missing_ok=True)


# Test runner and suite configuration
class TestRunner:
    """Comprehensive test runner with reporting"""
    
    def __init__(self):
        self.test_results = {}
        self.start_time = None
        self.end_time = None
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all test suites and collect results"""
        self.start_time = datetime.now()
        
        # Define test suites
        test_suites = [
            TestCLIFunctions,
            TestCLIBase,
            TestCLIExceptions,
            TestCommandUtils,
            TestCoreModels,
            TestCoreUtils,
            TestConfigManager,
            TestDatabaseManager,
            TestMetricsCollector,
            TestAdvancedValidationEngine,
            TestSLAMonitoring,
            TestIntelligentValidation,
            TestFilters,
            TestExportManager
        ]
        
        total_tests = 0
        passed_tests = 0
        failed_tests = 0
        errors = []
        
        for test_suite_class in test_suites:
            suite_name = test_suite_class.__name__
            print(f"\n🧪 Running {suite_name}...")
            
            # Create test suite
            suite = unittest.TestLoader().loadTestsFromTestCase(test_suite_class)
            
            # Run tests
            runner = unittest.TextTestRunner(verbosity=0, stream=open(os.devnull, 'w'))
            result = runner.run(suite)
            
            # Collect results
            suite_total = result.testsRun
            suite_failures = len(result.failures)
            suite_errors = len(result.errors)
            suite_passed = suite_total - suite_failures - suite_errors
            
            total_tests += suite_total
            passed_tests += suite_passed
            failed_tests += suite_failures + suite_errors
            
            # Store suite results
            self.test_results[suite_name] = {
                'total': suite_total,
                'passed': suite_passed,
                'failed': suite_failures,
                'errors': suite_errors,
                'success_rate': (suite_passed / suite_total) * 100 if suite_total > 0 else 0
            }
            
            # Collect error details
            for failure in result.failures:
                errors.append(f"{suite_name}: {failure[0]} - {failure[1]}")
            
            for error in result.errors:
                errors.append(f"{suite_name}: {error[0]} - {error[1]}")
            
            # Print suite summary
            success_rate = (suite_passed / suite_total) * 100 if suite_total > 0 else 0
            status = "✅" if success_rate == 100 else "⚠️" if success_rate >= 80 else "❌"
            print(f"{status} {suite_name}: {suite_passed}/{suite_total} tests passed ({success_rate:.1f}%)")
        
        self.end_time = datetime.now()
        
        # Generate overall summary
        overall_success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
        duration = (self.end_time - self.start_time).total_seconds()
        
        summary = {
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': failed_tests,
            'success_rate': overall_success_rate,
            'duration_seconds': duration,
            'suite_results': self.test_results,
            'errors': errors[:10],  # First 10 errors
            'status': 'PASSED' if overall_success_rate == 100 else 'FAILED'
        }
        
        return summary
    
    def print_summary(self, summary: Dict[str, Any]):
        """Print comprehensive test summary"""
        print(f"\n{'='*60}")
        print(f"🧪 COMPREHENSIVE TEST SUITE RESULTS")
        print(f"{'='*60}")
        
        print(f"📊 Overall Results:")
        print(f"   Total Tests: {summary['total_tests']}")
        print(f"   Passed: {summary['passed_tests']}")
        print(f"   Failed: {summary['failed_tests']}")
        print(f"   Success Rate: {summary['success_rate']:.1f}%")
        print(f"   Duration: {summary['duration_seconds']:.2f}s")
        
        status_emoji = "✅" if summary['status'] == 'PASSED' else "❌"
        print(f"   Status: {status_emoji} {summary['status']}")
        
        print(f"\n📋 Suite Breakdown:")
        for suite_name, results in summary['suite_results'].items():
            rate = results['success_rate']
            emoji = "✅" if rate == 100 else "⚠️" if rate >= 80 else "❌"
            print(f"   {emoji} {suite_name}: {results['passed']}/{results['total']} ({rate:.1f}%)")
        
        if summary['errors']:
            print(f"\n🚨 Recent Errors (showing first 10):")
            for error in summary['errors']:
                print(f"   - {error}")
        
        print(f"\n{'='*60}")


# Entry point for running tests
if __name__ == "__main__":
    print("🚀 Starting Comprehensive Unit Test Suite - Phase 4.1.1")
    
    runner = TestRunner()
    results = runner.run_all_tests()
    runner.print_summary(results)
    
    # Exit with appropriate code
    exit_code = 0 if results['status'] == 'PASSED' else 1
    sys.exit(exit_code)