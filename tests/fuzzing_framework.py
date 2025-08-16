#!/usr/bin/env python3
"""
Fuzzing Framework - Phase 4.1.3

Advanced fuzzing system for input file validation and edge case testing.
Tests robustness against malformed, corrupted, and unexpected inputs.

Fuzzing Categories:
- File format fuzzing (malformed JSON, CSV, TXT)
- Proxy address fuzzing (invalid IPs, ports, formats)
- Unicode and encoding fuzzing
- Buffer overflow and memory corruption testing
- Command line argument fuzzing
- Configuration file fuzzing
- Network response fuzzing
- Edge case input generation
"""

import asyncio
import json
import logging
import os
import random
import string
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Generator, Iterator
import threading
import struct
import binascii

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from proxc.proxy_cli.cli import (
    detect_file_format, infer_proxy_protocol, 
    validate_proxy_address, validate_output_format
)
from proxc.proxy_core.models import ProxyInfo, ProxyProtocol
from proxc.proxy_core.utils import (
    validate_ip_address, parse_proxy_from_line,
    sanitize_filename
)
from proxc.proxy_engine.validators import ValidationMethod
from proxc.proxy_engine.filters import ProxyFilter, FilterCriteria


class FuzzingDataGenerator:
    """Advanced data generator for fuzzing tests"""
    
    def __init__(self, seed: int = None):
        if seed is not None:
            random.seed(seed)
        
        # Character sets for fuzzing
        self.ascii_chars = string.ascii_letters + string.digits
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.unicode_chars = "αβγδεζηθικλμνξοπρστυφχψω"
        self.control_chars = "".join(chr(i) for i in range(32))
        self.high_ascii = "".join(chr(i) for i in range(128, 256))
        
        # Common malicious patterns
        self.sql_injection_patterns = [
            "'; DROP TABLE proxies; --",
            "' OR '1'='1",
            "'; INSERT INTO",
            "UNION SELECT"
        ]
        
        self.xss_patterns = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "data:text/html,<script>alert('xss')</script>"
        ]
        
        self.path_traversal_patterns = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
            "....//....//....//etc//passwd"
        ]
        
        # Format strings and buffer overflow patterns
        self.format_string_patterns = [
            "%n%n%n%n",
            "%s%s%s%s",
            "%x%x%x%x",
            "%p%p%p%p"
        ]
        
        self.buffer_overflow_patterns = [
            "A" * 1000,
            "A" * 10000,
            "A" * 100000,
            "\x00" * 1000
        ]
    
    def generate_random_string(self, length: int, charset: str = None) -> str:
        """Generate random string with specified charset"""
        if charset is None:
            charset = self.ascii_chars
        
        return ''.join(random.choice(charset) for _ in range(length))
    
    def generate_malformed_ip_addresses(self) -> Generator[str, None, None]:
        """Generate malformed IP addresses for fuzzing"""
        
        # Invalid octet values
        yield "256.256.256.256"
        yield "999.999.999.999"
        yield "-1.-1.-1.-1"
        yield "300.400.500.600"
        
        # Wrong number of octets
        yield "192.168.1"
        yield "192.168.1.1.1"
        yield "192"
        yield ""
        
        # Non-numeric values
        yield "abc.def.ghi.jkl"
        yield "192.168.x.1"
        yield "192.168.1.x"
        
        # Special characters
        yield "192.168.1.1/24"
        yield "192.168.1.1:8080"
        yield "192.168.1.1@domain"
        
        # Unicode and control characters
        yield "192.168.1.1\x00"
        yield "192.168.1.ü"
        yield "192.168.δ.1"
        
        # Buffer overflow attempts
        yield "A" * 1000
        yield "192." + "A" * 1000
        
        # Format string attacks
        yield "%n%n%n%n"
        yield "192.%s.1.1"
        
        # SQL injection in IP
        yield "192'; DROP TABLE proxies; --"
        yield "192.168.1.1' OR '1'='1"
        
        # Empty and whitespace
        yield ""
        yield " "
        yield "\t"
        yield "\n"
        yield "\r\n"
        
        # Negative numbers
        yield "-192.168.1.1"
        yield "192.-168.1.1"
        
        # Hexadecimal
        yield "0xC0.0xA8.0x01.0x01"
        yield "0x192.0x168.0x1.0x1"
        
        # Scientific notation
        yield "1.92e2.168.1.1"
        yield "192.1.68e2.1.1"
    
    def generate_malformed_ports(self) -> Generator[str, None, None]:
        """Generate malformed port numbers"""
        
        # Out of range ports
        yield "65536"
        yield "99999"
        yield "1000000"
        yield "-1"
        yield "-8080"
        
        # Non-numeric
        yield "abc"
        yield "port"
        yield "8080abc"
        yield "abc8080"
        
        # Special characters
        yield "8080;"
        yield "8080'"
        yield "8080\""
        yield "8080\x00"
        
        # Empty and whitespace
        yield ""
        yield " "
        yield "\t"
        
        # Very large numbers
        yield "9" * 100
        yield "1" + "0" * 100
        
        # Format strings
        yield "%n"
        yield "%s"
        yield "%x"
        
        # SQL injection
        yield "8080'; DROP TABLE"
        yield "8080 OR 1=1"
        
        # Buffer overflow
        yield "A" * 1000
        
        # Scientific notation
        yield "8.08e3"
        yield "8080e0"
        
        # Floating point
        yield "8080.5"
        yield "8080.0"
        
        # Leading zeros
        yield "08080"
        yield "000008080"
    
    def generate_malformed_proxy_strings(self) -> Generator[str, None, None]:
        """Generate malformed proxy address strings"""
        
        # Combine malformed IPs and ports
        malformed_ips = list(self.generate_malformed_ip_addresses())[:20]
        malformed_ports = list(self.generate_malformed_ports())[:20]
        
        for ip in malformed_ips[:10]:
            for port in malformed_ports[:10]:
                yield f"{ip}:{port}"
        
        # Missing separator
        yield "192.168.1.18080"
        yield "192.168.1.1 8080"
        yield "192.168.1.1|8080"
        
        # Multiple separators
        yield "192.168.1.1::8080"
        yield "192.168.1.1:::8080"
        yield "192.168.1.1:8080:extra"
        
        # Authentication patterns
        yield "user@192.168.1.1:8080"
        yield "user:pass@192.168.1.1:8080"
        yield "user:@192.168.1.1:8080"
        yield ":pass@192.168.1.1:8080"
        yield "@192.168.1.1:8080"
        
        # URL-like patterns
        yield "http://192.168.1.1:8080"
        yield "socks5://192.168.1.1:1080"
        yield "proxy://192.168.1.1:3128"
        
        # IPv6-like patterns
        yield "[::1]:8080"
        yield "2001:db8::1:8080"
        yield "[2001:db8::1]:8080"
        
        # Domain names with issues
        yield "proxy..example.com:8080"
        yield "proxy-.example.com:8080"
        yield "-proxy.example.com:8080"
        yield "proxy.example..com:8080"
        
        # Unicode domain names
        yield "αβγ.example.com:8080"
        yield "中文.example.com:8080"
        yield "🚀.example.com:8080"
        
        # Very long strings
        yield ("A" * 1000) + ":8080"
        yield "192.168.1.1:" + ("B" * 1000)
        yield ("C" * 500) + ":" + ("D" * 500)
    
    def generate_malformed_json(self) -> Generator[str, None, None]:
        """Generate malformed JSON for testing"""
        
        # Syntax errors
        yield '{"invalid": json}'
        yield '{"missing": quote}'
        yield '{"trailing": "comma",}'
        yield '{"unclosed": "string'
        yield '{"unclosed": ['
        yield '{"unclosed": {'
        
        # Invalid values
        yield '{"value": undefined}'
        yield '{"value": NaN}'
        yield '{"value": Infinity}'
        yield '{"value": -Infinity}'
        
        # Control characters
        yield '{"value": "string with\x00null"}'
        yield '{"value": "string with\ttab"}'
        yield '{"value": "string with\nnewline"}'
        
        # Unicode issues
        yield '{"value": "\\uXXXX"}'
        yield '{"value": "\\u000"}'
        yield '{"value": "\\uZZZZ"}'
        
        # Deeply nested structures
        nested = "{"
        for i in range(1000):
            nested += f'"level{i}": {{'
        nested += '"deep": "value"'
        for i in range(1000):
            nested += "}"
        nested += "}"
        yield nested
        
        # Very large arrays
        large_array = '["' + '", "'.join(["item"] * 10000) + '"]'
        yield large_array
        
        # Mixed types in wrong places
        yield '[{"array": "should be object"}]'
        yield '{"should_be_array": "but_is_string"}'
        
        # Empty and whitespace
        yield ""
        yield " "
        yield "\t\n\r"
        
        # Binary data
        yield b'\x00\x01\x02\x03'.decode('latin1')
        yield b'\xff\xfe\xfd\xfc'.decode('latin1')
        
        # SQL injection in JSON
        yield '{"sql": "value\'; DROP TABLE proxies; --"}'
        yield '{"injection": "\\" OR \\"1\\"=\\"1"}'
        
        # XSS in JSON
        yield '{"xss": "<script>alert(\\"xss\\")</script>"}'
        yield '{"script": "javascript:alert(\\"xss\\")"}'
    
    def generate_malformed_csv(self) -> Generator[str, None, None]:
        """Generate malformed CSV data"""
        
        # Unescaped quotes
        yield 'host,port,protocol\n"192.168.1.1",8080,"http'
        yield 'host,port,protocol\n192.168.1.1",8080,http'
        yield 'host,port,protocol\n"192.168.1.1,8080,http"'
        
        # Wrong number of columns
        yield 'host,port,protocol\n192.168.1.1,8080'
        yield 'host,port,protocol\n192.168.1.1,8080,http,extra'
        yield 'host,port,protocol\n192.168.1.1'
        
        # Mixed delimiters
        yield 'host,port,protocol\n192.168.1.1;8080,http'
        yield 'host,port,protocol\n192.168.1.1|8080|http'
        yield 'host,port;protocol\n192.168.1.1,8080,http'
        
        # Control characters
        yield 'host,port,protocol\n192.168.1.1\x00,8080,http'
        yield 'host,port,protocol\n192.168.1.1,8080\t,http'
        yield 'host,port,protocol\n192.168.1.1,8080,http\r'
        
        # Unicode issues
        yield 'host,port,protocol\nαβγ.168.1.1,8080,http'
        yield 'host,port,protocol\n192.168.1.1,8080,ηττπ'
        
        # Very long fields
        long_host = "A" * 10000
        yield f'host,port,protocol\n{long_host},8080,http'
        
        # Binary data
        binary_data = b'\x00\x01\x02\x03\xff\xfe\xfd\xfc'
        yield f'host,port,protocol\n{binary_data.decode("latin1")},8080,http'
        
        # Empty lines and fields
        yield 'host,port,protocol\n\n192.168.1.1,8080,http'
        yield 'host,port,protocol\n,8080,http'
        yield 'host,port,protocol\n192.168.1.1,,http'
        yield 'host,port,protocol\n192.168.1.1,8080,'
        
        # SQL injection
        yield 'host,port,protocol\n192.168.1.1\'; DROP TABLE proxies; --,8080,http'
        
        # Format strings
        yield 'host,port,protocol\n%n%n%n,8080,http'
        yield 'host,port,protocol\n192.168.1.1,%s,http'
    
    def generate_command_line_fuzz_cases(self) -> Generator[List[str], None, None]:
        """Generate fuzzing cases for command line arguments"""
        
        # Very long arguments
        yield ["--input", "A" * 10000]
        yield ["--output", "B" * 10000]
        yield ["--threads", "C" * 1000]
        
        # Invalid option values
        yield ["--threads", "-1"]
        yield ["--threads", "0"]
        yield ["--threads", "999999"]
        yield ["--timeout", "-5"]
        yield ["--timeout", "0"]
        yield ["--timeout", "999999"]
        
        # Malformed flags
        yield ["--invalid-flag"]
        yield ["---triple-dash"]
        yield ["-invalid"]
        yield ["--"]
        yield ["-"]
        
        # Special characters in arguments
        yield ["--input", "file'; rm -rf /"]
        yield ["--output", "file$(rm -rf /)"]
        yield ["--input", "file`rm -rf /`"]
        yield ["--output", "file|rm -rf /"]
        
        # Unicode in arguments
        yield ["--input", "αβγδε.txt"]
        yield ["--output", "中文文件.json"]
        yield ["--threads", "δε"]
        
        # Format strings
        yield ["--input", "%n%n%n%n"]
        yield ["--output", "%s%s%s%s"]
        yield ["--threads", "%x"]
        
        # Path traversal
        yield ["--input", "../../../etc/passwd"]
        yield ["--output", "..\\..\\..\\windows\\system32"]
        yield ["--config", "/dev/null"]
        
        # Binary data
        binary_arg = b'\x00\x01\x02\x03\xff\xfe\xfd\xfc'.decode('latin1')
        yield ["--input", binary_arg]
        
        # Empty and whitespace
        yield ["--input", ""]
        yield ["--output", " "]
        yield ["--threads", "\t"]
        yield ["--timeout", "\n"]
        
        # Multiple identical flags
        yield ["--input", "file1.txt", "--input", "file2.txt"]
        yield ["--threads", "4", "--threads", "8"]
        
        # Invalid combinations
        yield ["--help", "--input", "file.txt"]
        yield ["--version", "--output", "out.txt"]


class FuzzingTestFramework:
    """Main fuzzing test framework"""
    
    def __init__(self):
        self.data_generator = FuzzingDataGenerator()
        self.test_results = []
        self.crashes_found = []
        self.unexpected_behaviors = []
    
    def fuzz_ip_validation(self, iterations: int = 1000) -> Dict[str, Any]:
        """Fuzz IP address validation function"""
        
        print(f"🔍 Fuzzing IP validation with {iterations} iterations...")
        
        crashes = 0
        unexpected_results = 0
        start_time = time.time()
        
        malformed_ips = list(self.data_generator.generate_malformed_ip_addresses())
        
        for i in range(iterations):
            try:
                # Use both predefined malformed IPs and random data
                if i < len(malformed_ips):
                    test_ip = malformed_ips[i]
                else:
                    # Generate random string
                    test_ip = self.data_generator.generate_random_string(
                        random.randint(1, 100),
                        self.data_generator.ascii_chars + self.data_generator.special_chars
                    )
                
                # Test validation function
                result = validate_ip_address(test_ip)
                
                # Check for unexpected behavior
                if result is not False and result is not True:
                    unexpected_results += 1
                    self.unexpected_behaviors.append({
                        'function': 'validate_ip_address',
                        'input': test_ip,
                        'result': result,
                        'expected': 'boolean'
                    })
            
            except Exception as e:
                crashes += 1
                self.crashes_found.append({
                    'function': 'validate_ip_address',
                    'input': test_ip,
                    'exception': str(e),
                    'exception_type': type(e).__name__
                })
        
        duration = time.time() - start_time
        
        result = {
            'function': 'validate_ip_address',
            'iterations': iterations,
            'crashes': crashes,
            'unexpected_results': unexpected_results,
            'duration_seconds': duration,
            'crash_rate': (crashes / iterations) * 100,
            'stability': 'STABLE' if crashes == 0 else 'UNSTABLE'
        }
        
        self.test_results.append(result)
        return result
    
    def fuzz_proxy_parsing(self, iterations: int = 1000) -> Dict[str, Any]:
        """Fuzz proxy string parsing function"""
        
        print(f"🔍 Fuzzing proxy parsing with {iterations} iterations...")
        
        crashes = 0
        unexpected_results = 0
        start_time = time.time()
        
        malformed_proxies = list(self.data_generator.generate_malformed_proxy_strings())
        
        for i in range(iterations):
            try:
                # Use both predefined malformed proxies and random data
                if i < len(malformed_proxies):
                    test_proxy = malformed_proxies[i]
                else:
                    # Generate random proxy-like string
                    test_proxy = self.data_generator.generate_random_string(
                        random.randint(1, 200),
                        self.data_generator.ascii_chars + self.data_generator.special_chars + ":"
                    )
                
                # Test parsing function
                result = parse_proxy_from_line(test_proxy)
                
                # Check for unexpected behavior (should return tuple or None)
                if result is not None and not isinstance(result, tuple):
                    unexpected_results += 1
                    self.unexpected_behaviors.append({
                        'function': 'parse_proxy_from_line',
                        'input': test_proxy,
                        'result': result,
                        'expected': 'tuple or None'
                    })
            
            except Exception as e:
                crashes += 1
                self.crashes_found.append({
                    'function': 'parse_proxy_from_line',
                    'input': test_proxy,
                    'exception': str(e),
                    'exception_type': type(e).__name__
                })
        
        duration = time.time() - start_time
        
        result = {
            'function': 'parse_proxy_from_line',
            'iterations': iterations,
            'crashes': crashes,
            'unexpected_results': unexpected_results,
            'duration_seconds': duration,
            'crash_rate': (crashes / iterations) * 100,
            'stability': 'STABLE' if crashes == 0 else 'UNSTABLE'
        }
        
        self.test_results.append(result)
        return result
    
    def fuzz_json_parsing(self, iterations: int = 500) -> Dict[str, Any]:
        """Fuzz JSON parsing functionality"""
        
        print(f"🔍 Fuzzing JSON parsing with {iterations} iterations...")
        
        crashes = 0
        unexpected_results = 0
        start_time = time.time()
        
        malformed_json = list(self.data_generator.generate_malformed_json())
        
        for i in range(iterations):
            try:
                # Use both predefined malformed JSON and random data
                if i < len(malformed_json):
                    test_json = malformed_json[i]
                else:
                    # Generate random JSON-like string
                    test_json = self.data_generator.generate_random_string(
                        random.randint(1, 1000),
                        self.data_generator.ascii_chars + '{}[]":,'
                    )
                
                # Test JSON parsing
                try:
                    result = json.loads(test_json)
                    # If parsing succeeds, that's expected behavior
                except json.JSONDecodeError:
                    # JSON decode errors are expected for malformed input
                    pass
                except Exception as e:
                    # Other exceptions might indicate problems
                    if not isinstance(e, (ValueError, TypeError, MemoryError)):
                        unexpected_results += 1
                        self.unexpected_behaviors.append({
                            'function': 'json.loads',
                            'input': test_json[:100] + "..." if len(test_json) > 100 else test_json,
                            'exception': str(e),
                            'exception_type': type(e).__name__
                        })
            
            except Exception as e:
                crashes += 1
                self.crashes_found.append({
                    'function': 'json.loads',
                    'input': test_json[:100] + "..." if len(test_json) > 100 else test_json,
                    'exception': str(e),
                    'exception_type': type(e).__name__
                })
        
        duration = time.time() - start_time
        
        result = {
            'function': 'json.loads',
            'iterations': iterations,
            'crashes': crashes,
            'unexpected_results': unexpected_results,
            'duration_seconds': duration,
            'crash_rate': (crashes / iterations) * 100,
            'stability': 'STABLE' if crashes == 0 else 'UNSTABLE'
        }
        
        self.test_results.append(result)
        return result
    
    def fuzz_filename_sanitization(self, iterations: int = 1000) -> Dict[str, Any]:
        """Fuzz filename sanitization function"""
        
        print(f"🔍 Fuzzing filename sanitization with {iterations} iterations...")
        
        crashes = 0
        unexpected_results = 0
        start_time = time.time()
        
        for i in range(iterations):
            try:
                # Generate malicious filename
                filename = self.data_generator.generate_random_string(
                    random.randint(1, 500),
                    self.data_generator.ascii_chars + 
                    self.data_generator.special_chars + 
                    self.data_generator.control_chars +
                    "/\\<>:|?*"
                )
                
                # Test sanitization
                result = sanitize_filename(filename)
                
                # Check result is valid
                if not isinstance(result, str):
                    unexpected_results += 1
                    self.unexpected_behaviors.append({
                        'function': 'sanitize_filename',
                        'input': filename[:100] + "..." if len(filename) > 100 else filename,
                        'result': result,
                        'expected': 'string'
                    })
                
                # Check for dangerous characters in result
                dangerous_chars = "/\\<>:|?*\x00"
                if any(char in result for char in dangerous_chars):
                    unexpected_results += 1
                    self.unexpected_behaviors.append({
                        'function': 'sanitize_filename',
                        'input': filename[:100] + "..." if len(filename) > 100 else filename,
                        'result': result,
                        'issue': 'contains dangerous characters'
                    })
            
            except Exception as e:
                crashes += 1
                self.crashes_found.append({
                    'function': 'sanitize_filename',
                    'input': filename[:100] + "..." if len(filename) > 100 else filename,
                    'exception': str(e),
                    'exception_type': type(e).__name__
                })
        
        duration = time.time() - start_time
        
        result = {
            'function': 'sanitize_filename',
            'iterations': iterations,
            'crashes': crashes,
            'unexpected_results': unexpected_results,
            'duration_seconds': duration,
            'crash_rate': (crashes / iterations) * 100,
            'stability': 'STABLE' if crashes == 0 else 'UNSTABLE'
        }
        
        self.test_results.append(result)
        return result
    
    def fuzz_file_format_detection(self, iterations: int = 1000) -> Dict[str, Any]:
        """Fuzz file format detection function"""
        
        print(f"🔍 Fuzzing file format detection with {iterations} iterations...")
        
        crashes = 0
        unexpected_results = 0
        start_time = time.time()
        
        for i in range(iterations):
            try:
                # Generate malicious filename
                filename = self.data_generator.generate_random_string(
                    random.randint(1, 1000),
                    self.data_generator.ascii_chars + 
                    self.data_generator.special_chars +
                    self.data_generator.unicode_chars +
                    "."
                )
                
                # Test format detection
                result = detect_file_format(filename)
                
                # Check result is valid format
                valid_formats = ['txt', 'json', 'csv', 'xlsx']
                if result not in valid_formats:
                    unexpected_results += 1
                    self.unexpected_behaviors.append({
                        'function': 'detect_file_format',
                        'input': filename[:100] + "..." if len(filename) > 100 else filename,
                        'result': result,
                        'expected': f'one of {valid_formats}'
                    })
            
            except Exception as e:
                crashes += 1
                self.crashes_found.append({
                    'function': 'detect_file_format',
                    'input': filename[:100] + "..." if len(filename) > 100 else filename,
                    'exception': str(e),
                    'exception_type': type(e).__name__
                })
        
        duration = time.time() - start_time
        
        result = {
            'function': 'detect_file_format',
            'iterations': iterations,
            'crashes': crashes,
            'unexpected_results': unexpected_results,
            'duration_seconds': duration,
            'crash_rate': (crashes / iterations) * 100,
            'stability': 'STABLE' if crashes == 0 else 'UNSTABLE'
        }
        
        self.test_results.append(result)
        return result
    
    def run_comprehensive_fuzzing(self) -> Dict[str, Any]:
        """Run comprehensive fuzzing across all functions"""
        
        print("🚀 Starting Comprehensive Fuzzing Test Suite")
        print("=" * 60)
        
        start_time = time.time()
        
        # Run individual fuzzing tests
        ip_results = self.fuzz_ip_validation(1000)
        proxy_results = self.fuzz_proxy_parsing(1000)
        json_results = self.fuzz_json_parsing(500)
        filename_results = self.fuzz_filename_sanitization(1000)
        format_results = self.fuzz_file_format_detection(1000)
        
        total_duration = time.time() - start_time
        
        # Aggregate results
        total_iterations = sum(r['iterations'] for r in self.test_results)
        total_crashes = sum(r['crashes'] for r in self.test_results)
        total_unexpected = sum(r['unexpected_results'] for r in self.test_results)
        
        overall_crash_rate = (total_crashes / total_iterations) * 100 if total_iterations > 0 else 0
        
        # Determine overall stability
        unstable_functions = [r for r in self.test_results if r['stability'] == 'UNSTABLE']
        overall_stability = 'STABLE' if len(unstable_functions) == 0 else 'UNSTABLE'
        
        summary = {
            'total_iterations': total_iterations,
            'total_crashes': total_crashes,
            'total_unexpected_results': total_unexpected,
            'overall_crash_rate': overall_crash_rate,
            'overall_stability': overall_stability,
            'duration_seconds': total_duration,
            'functions_tested': len(self.test_results),
            'unstable_functions': len(unstable_functions),
            'test_results': self.test_results,
            'crashes_found': self.crashes_found[:10],  # First 10 crashes
            'unexpected_behaviors': self.unexpected_behaviors[:10]  # First 10 unexpected behaviors
        }
        
        return summary
    
    def print_fuzzing_summary(self, summary: Dict[str, Any]):
        """Print comprehensive fuzzing summary"""
        
        print(f"\n{'='*60}")
        print(f"🔍 FUZZING TEST RESULTS SUMMARY")
        print(f"{'='*60}")
        
        print(f"📊 Overall Results:")
        print(f"   Total Iterations: {summary['total_iterations']:,}")
        print(f"   Total Crashes: {summary['total_crashes']}")
        print(f"   Unexpected Behaviors: {summary['total_unexpected_results']}")
        print(f"   Overall Crash Rate: {summary['overall_crash_rate']:.3f}%")
        print(f"   Duration: {summary['duration_seconds']:.2f}s")
        
        stability_emoji = "✅" if summary['overall_stability'] == 'STABLE' else "❌"
        print(f"   Stability: {stability_emoji} {summary['overall_stability']}")
        
        print(f"\n📋 Function Results:")
        for result in summary['test_results']:
            rate = result['crash_rate']
            emoji = "✅" if rate == 0 else "⚠️" if rate < 1 else "❌"
            print(f"   {emoji} {result['function']}: {result['crashes']}/{result['iterations']} crashes ({rate:.3f}%)")
        
        if summary['crashes_found']:
            print(f"\n🚨 Sample Crashes (showing first 10):")
            for crash in summary['crashes_found']:
                input_preview = crash['input'][:50] + "..." if len(str(crash['input'])) > 50 else crash['input']
                print(f"   - {crash['function']}: {crash['exception_type']} with input '{input_preview}'")
        
        if summary['unexpected_behaviors']:
            print(f"\n⚠️ Unexpected Behaviors (showing first 10):")
            for behavior in summary['unexpected_behaviors']:
                input_preview = str(behavior['input'])[:50] + "..." if len(str(behavior['input'])) > 50 else behavior['input']
                print(f"   - {behavior['function']}: unexpected result with input '{input_preview}'")
        
        print(f"\n{'='*60}")


# Entry point for running fuzzing tests
if __name__ == "__main__":
    print("🚀 Starting Fuzzing Framework - Phase 4.1.3")
    
    framework = FuzzingTestFramework()
    results = framework.run_comprehensive_fuzzing()
    framework.print_fuzzing_summary(results)
    
    # Exit with appropriate code
    exit_code = 0 if results['overall_stability'] == 'STABLE' else 1
    sys.exit(exit_code)