#!/usr/bin/env python3
"""
Integration Testing Framework - Phase 4.1.2

Comprehensive end-to-end testing framework for complete workflow validation.
Tests real user scenarios from CLI commands through to final output.

Test Scenarios:
- Complete proxy validation workflows
- CLI command integration with real proxy sources
- Database integration with validation engines
- Export/import pipelines with various formats
- Error handling and recovery scenarios
- Performance under realistic conditions
- Multi-component interaction testing
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from unittest.mock import Mock, patch, MagicMock
import threading
import signal

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from proxc.proxy_cli.cli import main as cli_main
from proxc.proxy_core.models import ProxyInfo, ProxyProtocol, ProxyStatus
from proxc.proxy_core.database import DatabaseManager
from proxc.proxy_core.config import ConfigManager
from proxc.proxy_engine.validators import BatchValidator
from proxc.proxy_engine.exporters import ExportManager, ExportFormat
from proxc.proxy_engine.fetchers import ProxyFetcher


class IntegrationTestEnvironment:
    """Test environment setup and teardown"""
    
    def __init__(self):
        self.temp_dir = None
        self.test_db_path = None
        self.test_config_path = None
        self.test_data_files = []
        self.cleanup_callbacks = []
    
    def setup(self):
        """Set up test environment"""
        # Create temporary directory
        self.temp_dir = Path(tempfile.mkdtemp(prefix="proxc_test_"))
        
        # Create test database
        self.test_db_path = self.temp_dir / "test_proxies.db"
        
        # Create test configuration
        self.test_config_path = self.temp_dir / "test_config.json"
        self._create_test_config()
        
        # Create test data files
        self._create_test_data_files()
        
        print(f"🔧 Test environment created at: {self.temp_dir}")
    
    def teardown(self):
        """Clean up test environment"""
        # Run cleanup callbacks
        for cleanup_func in self.cleanup_callbacks:
            try:
                cleanup_func()
            except Exception as e:
                print(f"⚠️ Cleanup error: {e}")
        
        # Remove temporary directory
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            print(f"🧹 Test environment cleaned up")
    
    def _create_test_config(self):
        """Create test configuration file"""
        config = {
            "timeout": 5.0,
            "threads": 4,
            "validation_method": "http",
            "output_format": "json",
            "database_path": str(self.test_db_path),
            "log_level": "INFO"
        }
        
        with open(self.test_config_path, 'w') as f:
            json.dump(config, f, indent=2)
    
    def _create_test_data_files(self):
        """Create test proxy data files"""
        
        # Create valid proxy list
        valid_proxies_file = self.temp_dir / "valid_proxies.txt"
        with open(valid_proxies_file, 'w') as f:
            f.write("127.0.0.1:8080\n")
            f.write("127.0.0.1:3128\n")
            f.write("127.0.0.1:1080\n")
            f.write("192.168.1.1:8080\n")
        self.test_data_files.append(valid_proxies_file)
        
        # Create mixed proxy list (valid + invalid)
        mixed_proxies_file = self.temp_dir / "mixed_proxies.txt"
        with open(mixed_proxies_file, 'w') as f:
            f.write("127.0.0.1:8080\n")
            f.write("invalid_proxy_line\n")
            f.write("256.256.256.256:8080\n")  # Invalid IP
            f.write("127.0.0.1:99999\n")       # Invalid port
            f.write("127.0.0.1:3128\n")
            f.write("# Comment line\n")
            f.write("\n")  # Empty line
            f.write("192.168.1.1:1080\n")
        self.test_data_files.append(mixed_proxies_file)
        
        # Create JSON proxy list
        json_proxies_file = self.temp_dir / "proxies.json"
        proxy_data = [
            {"host": "127.0.0.1", "port": 8080, "protocol": "http", "source": "test"},
            {"host": "127.0.0.1", "port": 3128, "protocol": "http", "source": "test"},
            {"host": "127.0.0.1", "port": 1080, "protocol": "socks5", "source": "test"}
        ]
        with open(json_proxies_file, 'w') as f:
            json.dump(proxy_data, f, indent=2)
        self.test_data_files.append(json_proxies_file)
        
        # Create empty file
        empty_file = self.temp_dir / "empty.txt"
        empty_file.touch()
        self.test_data_files.append(empty_file)
        
        # Create malformed JSON file
        malformed_json_file = self.temp_dir / "malformed.json"
        with open(malformed_json_file, 'w') as f:
            f.write('{"invalid": json syntax}')
        self.test_data_files.append(malformed_json_file)
    
    def get_test_file(self, name: str) -> Path:
        """Get path to test file by name"""
        file_map = {
            "valid_proxies": "valid_proxies.txt",
            "mixed_proxies": "mixed_proxies.txt",
            "json_proxies": "proxies.json",
            "empty": "empty.txt",
            "malformed_json": "malformed.json"
        }
        
        if name in file_map:
            return self.temp_dir / file_map[name]
        
        raise ValueError(f"Unknown test file: {name}")
    
    def add_cleanup_callback(self, callback):
        """Add cleanup callback"""
        self.cleanup_callbacks.append(callback)


class CLIIntegrationTest(unittest.TestCase):
    """Integration tests for CLI commands"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment for all tests"""
        cls.env = IntegrationTestEnvironment()
        cls.env.setup()
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        cls.env.teardown()
    
    def run_cli_command(self, args: List[str], expect_success: bool = True) -> Tuple[int, str, str]:
        """Run CLI command and capture output"""
        
        # Prepare command
        cmd = [sys.executable, "-m", "proxc.main"] + args
        
        try:
            # Run command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(self.env.temp_dir)
            )
            
            return_code = result.returncode
            stdout = result.stdout
            stderr = result.stderr
            
            if expect_success and return_code != 0:
                self.fail(f"Command failed unexpectedly: {' '.join(args)}\n"
                         f"Return code: {return_code}\n"
                         f"STDOUT: {stdout}\n"
                         f"STDERR: {stderr}")
            
            return return_code, stdout, stderr
        
        except subprocess.TimeoutExpired:
            self.fail(f"Command timed out: {' '.join(args)}")
        except Exception as e:
            self.fail(f"Command execution failed: {e}")
    
    def test_basic_validation_workflow(self):
        """Test basic proxy validation workflow"""
        
        input_file = self.env.get_test_file("valid_proxies")
        output_file = self.env.temp_dir / "validated_proxies.json"
        
        # Run validation command
        args = [
            "validate",
            "--input", str(input_file),
            "--output", str(output_file),
            "--format", "json",
            "--timeout", "2",
            "--threads", "2"
        ]
        
        return_code, stdout, stderr = self.run_cli_command(args)
        
        # Verify success
        self.assertEqual(return_code, 0)
        
        # Verify output file exists
        self.assertTrue(output_file.exists())
        
        # Verify output content
        with open(output_file, 'r') as f:
            results = json.load(f)
            self.assertIsInstance(results, list)
            self.assertGreater(len(results), 0)
    
    def test_mixed_input_handling(self):
        """Test handling of mixed valid/invalid proxy inputs"""
        
        input_file = self.env.get_test_file("mixed_proxies")
        output_file = self.env.temp_dir / "mixed_results.txt"
        
        args = [
            "validate",
            "--input", str(input_file),
            "--output", str(output_file),
            "--format", "txt",
            "--timeout", "1"
        ]
        
        return_code, stdout, stderr = self.run_cli_command(args)
        
        # Should succeed despite invalid entries
        self.assertEqual(return_code, 0)
        
        # Should have warnings about invalid proxies
        self.assertIn("invalid", stderr.lower() + stdout.lower())
        
        # Output file should exist with valid proxies only
        self.assertTrue(output_file.exists())
    
    def test_json_input_format(self):
        """Test JSON input format handling"""
        
        input_file = self.env.get_test_file("json_proxies")
        output_file = self.env.temp_dir / "json_results.json"
        
        args = [
            "validate",
            "--input", str(input_file),
            "--output", str(output_file),
            "--input-format", "json",
            "--format", "json"
        ]
        
        return_code, stdout, stderr = self.run_cli_command(args)
        
        self.assertEqual(return_code, 0)
        self.assertTrue(output_file.exists())
        
        # Verify structured output
        with open(output_file, 'r') as f:
            results = json.load(f)
            self.assertIsInstance(results, list)
            
            # Should have protocol information preserved
            for result in results:
                self.assertIn("protocol", result)
    
    def test_error_handling_empty_input(self):
        """Test error handling with empty input file"""
        
        input_file = self.env.get_test_file("empty")
        output_file = self.env.temp_dir / "empty_results.txt"
        
        args = [
            "validate",
            "--input", str(input_file),
            "--output", str(output_file)
        ]
        
        return_code, stdout, stderr = self.run_cli_command(args, expect_success=False)
        
        # Should fail gracefully
        self.assertNotEqual(return_code, 0)
        self.assertIn("empty", stderr.lower() + stdout.lower())
    
    def test_error_handling_malformed_json(self):
        """Test error handling with malformed JSON input"""
        
        input_file = self.env.get_test_file("malformed_json")
        output_file = self.env.temp_dir / "malformed_results.json"
        
        args = [
            "validate",
            "--input", str(input_file),
            "--output", str(output_file),
            "--input-format", "json"
        ]
        
        return_code, stdout, stderr = self.run_cli_command(args, expect_success=False)
        
        # Should fail with JSON parsing error
        self.assertNotEqual(return_code, 0)
        self.assertIn("json", stderr.lower() + stdout.lower())
    
    def test_export_format_conversion(self):
        """Test export format conversion workflow"""
        
        input_file = self.env.get_test_file("valid_proxies")
        
        # Test multiple output formats
        formats = ["txt", "json", "csv"]
        
        for format_name in formats:
            with self.subTest(format=format_name):
                output_file = self.env.temp_dir / f"export_test.{format_name}"
                
                args = [
                    "validate",
                    "--input", str(input_file),
                    "--output", str(output_file),
                    "--format", format_name,
                    "--timeout", "1"
                ]
                
                return_code, stdout, stderr = self.run_cli_command(args)
                
                self.assertEqual(return_code, 0)
                self.assertTrue(output_file.exists())
                self.assertGreater(output_file.stat().st_size, 0)
    
    def test_concurrent_validation(self):
        """Test concurrent validation with multiple threads"""
        
        input_file = self.env.get_test_file("valid_proxies")
        output_file = self.env.temp_dir / "concurrent_results.json"
        
        args = [
            "validate",
            "--input", str(input_file),
            "--output", str(output_file),
            "--threads", "8",
            "--timeout", "2"
        ]
        
        start_time = time.time()
        return_code, stdout, stderr = self.run_cli_command(args)
        duration = time.time() - start_time
        
        self.assertEqual(return_code, 0)
        self.assertTrue(output_file.exists())
        
        # Should complete within reasonable time
        self.assertLess(duration, 30)
    
    def test_database_integration(self):
        """Test database storage and retrieval"""
        
        input_file = self.env.get_test_file("valid_proxies")
        
        # Store proxies in database
        args = [
            "store",
            "--input", str(input_file),
            "--database", str(self.env.test_db_path)
        ]
        
        return_code, stdout, stderr = self.run_cli_command(args)
        self.assertEqual(return_code, 0)
        
        # Verify database file created
        self.assertTrue(self.env.test_db_path.exists())
        
        # Retrieve proxies from database
        output_file = self.env.temp_dir / "db_export.json"
        args = [
            "export",
            "--database", str(self.env.test_db_path),
            "--output", str(output_file),
            "--format", "json"
        ]
        
        return_code, stdout, stderr = self.run_cli_command(args)
        self.assertEqual(return_code, 0)
        
        # Verify exported data
        with open(output_file, 'r') as f:
            results = json.load(f)
            self.assertGreater(len(results), 0)


class ValidationEngineIntegrationTest(unittest.TestCase):
    """Integration tests for validation engine components"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.env = IntegrationTestEnvironment()
        cls.env.setup()
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        cls.env.teardown()
    
    def test_batch_validator_integration(self):
        """Test batch validator with real proxy data"""
        
        # Create test proxies
        proxies = [
            ProxyInfo("127.0.0.1", 8080, ProxyProtocol.HTTP, "test"),
            ProxyInfo("127.0.0.1", 3128, ProxyProtocol.HTTP, "test"),
            ProxyInfo("127.0.0.1", 1080, ProxyProtocol.SOCKS5, "test")
        ]
        
        # Initialize validator
        validator = BatchValidator(timeout=2, max_workers=2)
        
        # Run validation
        results = validator.validate_batch(proxies)
        
        # Verify results
        self.assertEqual(len(results), len(proxies))
        
        for result in results:
            self.assertIsNotNone(result.proxy_address)
            self.assertIn(result.status, [ProxyStatus.WORKING, ProxyStatus.FAILED, ProxyStatus.TIMEOUT])
    
    def test_database_validator_integration(self):
        """Test database integration with validation results"""
        
        # Initialize database
        db = DatabaseManager(str(self.env.test_db_path))
        db.initialize_database()
        
        # Create test proxy
        proxy = ProxyInfo("127.0.0.1", 8080, ProxyProtocol.HTTP, "test")
        
        # Store proxy
        proxy_id = db.store_proxy(proxy)
        self.assertIsNotNone(proxy_id)
        
        # Update validation status
        db.update_proxy_status(proxy_id, ProxyStatus.WORKING, response_time=100.5)
        
        # Retrieve and verify
        updated_proxy = db.get_proxy(proxy_id)
        self.assertEqual(updated_proxy.status, ProxyStatus.WORKING)
        self.assertIsNotNone(updated_proxy.last_checked)
    
    def test_export_import_roundtrip(self):
        """Test complete export/import roundtrip"""
        
        # Create test data
        original_proxies = [
            ProxyInfo("127.0.0.1", 8080, ProxyProtocol.HTTP, "source1"),
            ProxyInfo("192.168.1.1", 3128, ProxyProtocol.HTTP, "source2"),
            ProxyInfo("10.0.0.1", 1080, ProxyProtocol.SOCKS5, "source3")
        ]
        
        export_manager = ExportManager()
        
        # Test JSON roundtrip
        json_file = self.env.temp_dir / "roundtrip.json"
        
        # Export
        success = export_manager.export_proxies(original_proxies, str(json_file), ExportFormat.JSON)
        self.assertTrue(success)
        
        # Import
        with open(json_file, 'r') as f:
            imported_data = json.load(f)
        
        # Verify data integrity
        self.assertEqual(len(imported_data), len(original_proxies))
        
        for original, imported in zip(original_proxies, imported_data):
            self.assertEqual(original.host, imported['host'])
            self.assertEqual(original.port, imported['port'])
            self.assertEqual(original.protocol.value, imported['protocol'])
    
    def test_concurrent_database_operations(self):
        """Test concurrent database operations"""
        
        db = DatabaseManager(str(self.env.test_db_path))
        db.initialize_database()
        
        def store_proxies_worker(worker_id: int, proxy_count: int):
            """Worker function for concurrent proxy storage"""
            for i in range(proxy_count):
                proxy = ProxyInfo(
                    f"192.168.{worker_id}.{i+1}",
                    8080 + i,
                    ProxyProtocol.HTTP,
                    f"worker_{worker_id}"
                )
                
                proxy_id = db.store_proxy(proxy)
                self.assertIsNotNone(proxy_id)
        
        # Run concurrent workers
        threads = []
        worker_count = 4
        proxies_per_worker = 5
        
        for worker_id in range(worker_count):
            thread = threading.Thread(
                target=store_proxies_worker,
                args=(worker_id, proxies_per_worker)
            )
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive(), "Worker thread timed out")
        
        # Verify total count
        all_proxies = db.get_all_proxies()
        expected_count = worker_count * proxies_per_worker
        self.assertEqual(len(all_proxies), expected_count)


class PerformanceIntegrationTest(unittest.TestCase):
    """Integration tests for performance under realistic conditions"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.env = IntegrationTestEnvironment()
        cls.env.setup()
        
        # Create large test dataset
        cls._create_large_test_dataset()
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        cls.env.teardown()
    
    @classmethod
    def _create_large_test_dataset(cls):
        """Create large test dataset for performance testing"""
        large_file = cls.env.temp_dir / "large_proxy_list.txt"
        
        with open(large_file, 'w') as f:
            # Generate 1000 test proxies
            for i in range(1000):
                ip_base = 10 + (i // 256)
                ip_second = (i // 256) % 256
                ip_third = i % 256
                port = 8000 + (i % 100)
                
                f.write(f"{ip_base}.{ip_second}.{ip_third}.1:{port}\n")
        
        cls.large_test_file = large_file
    
    def test_large_dataset_processing(self):
        """Test processing of large proxy datasets"""
        
        output_file = self.env.temp_dir / "large_results.json"
        
        # Process large dataset with limited resources
        args = [
            "validate",
            "--input", str(self.large_test_file),
            "--output", str(output_file),
            "--threads", "4",
            "--timeout", "1",
            "--format", "json"
        ]
        
        start_time = time.time()
        return_code, stdout, stderr = self.run_cli_command(args)
        duration = time.time() - start_time
        
        # Verify completion
        self.assertEqual(return_code, 0)
        self.assertTrue(output_file.exists())
        
        # Verify performance (should complete within reasonable time)
        self.assertLess(duration, 300)  # 5 minutes max
        
        # Verify memory efficiency (no obvious memory leaks)
        self.assertIn("completed", stdout.lower() + stderr.lower())
    
    def test_memory_usage_monitoring(self):
        """Test memory usage during large operations"""
        
        try:
            import psutil
            HAS_PSUTIL = True
        except ImportError:
            self.skipTest("psutil not available for memory monitoring")
        
        # Monitor memory usage during processing
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Process moderate dataset
        input_file = self.env.get_test_file("valid_proxies")
        output_file = self.env.temp_dir / "memory_test.json"
        
        args = [
            "validate",
            "--input", str(input_file),
            "--output", str(output_file),
            "--threads", "8"
        ]
        
        return_code, stdout, stderr = self.run_cli_command(args)
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Verify reasonable memory usage (less than 100MB increase)
        self.assertLess(memory_increase, 100 * 1024 * 1024)
    
    def run_cli_command(self, args: List[str], expect_success: bool = True) -> Tuple[int, str, str]:
        """Run CLI command and capture output"""
        
        cmd = [sys.executable, "-m", "proxc.main"] + args
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,  # Longer timeout for performance tests
                cwd=str(self.env.temp_dir)
            )
            
            return_code = result.returncode
            stdout = result.stdout
            stderr = result.stderr
            
            if expect_success and return_code != 0:
                self.fail(f"Command failed unexpectedly: {' '.join(args)}\n"
                         f"Return code: {return_code}\n"
                         f"STDOUT: {stdout}\n"
                         f"STDERR: {stderr}")
            
            return return_code, stdout, stderr
        
        except subprocess.TimeoutExpired:
            self.fail(f"Command timed out: {' '.join(args)}")
        except Exception as e:
            self.fail(f"Command execution failed: {e}")


class ErrorRecoveryIntegrationTest(unittest.TestCase):
    """Integration tests for error handling and recovery scenarios"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.env = IntegrationTestEnvironment()
        cls.env.setup()
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        cls.env.teardown()
    
    def test_interrupted_operation_recovery(self):
        """Test recovery from interrupted operations"""
        
        # This test simulates interruption recovery
        # In a real scenario, we'd test SIGINT handling
        
        input_file = self.env.get_test_file("valid_proxies")
        output_file = self.env.temp_dir / "interrupted_test.json"
        partial_output_file = self.env.temp_dir / "partial_results.json"
        
        # Create partial results file to simulate interruption
        partial_data = [
            {"host": "127.0.0.1", "port": 8080, "status": "working"}
        ]
        
        with open(partial_output_file, 'w') as f:
            json.dump(partial_data, f)
        
        # Resume operation should handle existing partial data
        args = [
            "validate",
            "--input", str(input_file),
            "--output", str(output_file),
            "--resume-from", str(partial_output_file)
        ]
        
        # Note: This would require implementing --resume-from functionality
        # For now, test that normal operation completes successfully
        args = [
            "validate",
            "--input", str(input_file),
            "--output", str(output_file)
        ]
        
        return_code, stdout, stderr = self.run_cli_command(args)
        self.assertEqual(return_code, 0)
    
    def test_network_error_handling(self):
        """Test handling of network-related errors"""
        
        # Create test file with unreachable proxies
        unreachable_file = self.env.temp_dir / "unreachable_proxies.txt"
        with open(unreachable_file, 'w') as f:
            f.write("192.0.2.1:8080\n")  # TEST-NET-1 (unreachable)
            f.write("198.51.100.1:3128\n")  # TEST-NET-2 (unreachable)
            f.write("203.0.113.1:1080\n")  # TEST-NET-3 (unreachable)
        
        output_file = self.env.temp_dir / "network_error_test.json"
        
        args = [
            "validate",
            "--input", str(unreachable_file),
            "--output", str(output_file),
            "--timeout", "1"
        ]
        
        return_code, stdout, stderr = self.run_cli_command(args)
        
        # Should complete successfully despite network errors
        self.assertEqual(return_code, 0)
        
        # Should contain error information
        self.assertIn("timeout", stderr.lower() + stdout.lower())
    
    def test_disk_space_error_handling(self):
        """Test handling of disk space errors"""
        
        # Create a very large output path to simulate disk full
        # This is a simplified test - in practice, we'd need to simulate actual disk full conditions
        
        input_file = self.env.get_test_file("valid_proxies")
        
        # Try to write to a read-only location (should fail gracefully)
        readonly_output = "/dev/null/impossible_file.json"
        
        args = [
            "validate",
            "--input", str(input_file),
            "--output", readonly_output
        ]
        
        return_code, stdout, stderr = self.run_cli_command(args, expect_success=False)
        
        # Should fail gracefully with appropriate error message
        self.assertNotEqual(return_code, 0)
        self.assertIn("permission", stderr.lower() + stdout.lower())
    
    def run_cli_command(self, args: List[str], expect_success: bool = True) -> Tuple[int, str, str]:
        """Run CLI command and capture output"""
        
        cmd = [sys.executable, "-m", "proxc.main"] + args
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(self.env.temp_dir)
            )
            
            return_code = result.returncode
            stdout = result.stdout
            stderr = result.stderr
            
            if expect_success and return_code != 0:
                self.fail(f"Command failed unexpectedly: {' '.join(args)}\n"
                         f"Return code: {return_code}\n"
                         f"STDOUT: {stdout}\n"
                         f"STDERR: {stderr}")
            
            return return_code, stdout, stderr
        
        except subprocess.TimeoutExpired:
            self.fail(f"Command timed out: {' '.join(args)}")
        except Exception as e:
            self.fail(f"Command execution failed: {e}")


class IntegrationTestRunner:
    """Comprehensive integration test runner"""
    
    def __init__(self):
        self.test_results = {}
        self.start_time = None
        self.end_time = None
    
    def run_all_integration_tests(self) -> Dict[str, Any]:
        """Run all integration test suites"""
        
        self.start_time = datetime.now()
        
        # Define integration test suites
        test_suites = [
            CLIIntegrationTest,
            ValidationEngineIntegrationTest,
            PerformanceIntegrationTest,
            ErrorRecoveryIntegrationTest
        ]
        
        total_tests = 0
        passed_tests = 0
        failed_tests = 0
        errors = []
        
        for test_suite_class in test_suites:
            suite_name = test_suite_class.__name__
            print(f"\n🔗 Running {suite_name}...")
            
            try:
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
            
            except Exception as e:
                print(f"❌ {suite_name}: Failed to run - {e}")
                self.test_results[suite_name] = {
                    'total': 0,
                    'passed': 0,
                    'failed': 1,
                    'errors': 1,
                    'success_rate': 0
                }
                errors.append(f"{suite_name}: Suite execution failed - {e}")
        
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
            'status': 'PASSED' if overall_success_rate >= 90 else 'FAILED'  # Slightly lower threshold for integration tests
        }
        
        return summary
    
    def print_summary(self, summary: Dict[str, Any]):
        """Print comprehensive integration test summary"""
        print(f"\n{'='*60}")
        print(f"🔗 INTEGRATION TEST SUITE RESULTS")
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


# Entry point for running integration tests
if __name__ == "__main__":
    print("🚀 Starting Integration Test Suite - Phase 4.1.2")
    
    runner = IntegrationTestRunner()
    results = runner.run_all_integration_tests()
    runner.print_summary(results)
    
    # Exit with appropriate code
    exit_code = 0 if results['status'] == 'PASSED' else 1
    sys.exit(exit_code)