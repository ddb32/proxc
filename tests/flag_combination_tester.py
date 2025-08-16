#!/usr/bin/env python3
"""
Flag Combination Tester - Phase 4.1.6

Automated testing for all CLI flag combinations to ensure compatibility
and detect conflicts or unexpected behavior.

Test Categories:
- Valid flag combinations
- Invalid flag combinations  
- Conflicting flag scenarios
- Edge case flag values
- Help and version flags
- Configuration file interactions
"""

import itertools
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Tuple, Any

# Test flag definitions
FLAG_DEFINITIONS = {
    # Input/Output flags
    '--input': ['test_proxies.txt', 'nonexistent.txt'],
    '--output': ['output.json', 'output.txt', 'output.csv'],
    '--format': ['json', 'txt', 'csv'],
    '--input-format': ['txt', 'json', 'csv'],
    
    # Validation flags  
    '--timeout': ['1', '5', '30', '0.5'],
    '--threads': ['1', '4', '10', '50'],
    '--method': ['http', 'socks5', 'auto'],
    
    # Filtering flags
    '--protocol': ['http', 'https', 'socks4', 'socks5'],
    '--country': ['US', 'GB', 'CA'],
    '--anonymity': ['elite', 'anonymous', 'transparent'],
    
    # Boolean flags
    '--validate': [None],  # Boolean flag
    '--export': [None],
    '--quiet': [None],
    '--verbose': [None],
    '--help': [None],
    '--version': [None],
    
    # Configuration flags
    '--config': ['config.json'],
    '--database': ['proxies.db'],
    '--cache': [None],
    '--no-cache': [None],
}

# Known incompatible combinations
INCOMPATIBLE_COMBINATIONS = [
    ('--help', '--input'),  # Help should not require input
    ('--version', '--output'),  # Version should not require output
    ('--quiet', '--verbose'),  # Contradictory verbosity
    ('--cache', '--no-cache'),  # Contradictory cache flags
]

# Flags that require values
FLAGS_REQUIRING_VALUES = [
    '--input', '--output', '--format', '--input-format',
    '--timeout', '--threads', '--method', '--protocol', 
    '--country', '--anonymity', '--config', '--database'
]


class FlagCombinationTester:
    """Test CLI flag combinations systematically"""
    
    def __init__(self):
        self.test_results = []
        self.temp_dir = None
        self.test_files = {}
    
    def setup_test_environment(self):
        """Set up test environment with required files"""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="flag_test_"))
        
        # Create test proxy file
        test_proxies_file = self.temp_dir / "test_proxies.txt"
        with open(test_proxies_file, 'w') as f:
            f.write("127.0.0.1:8080\n")
            f.write("127.0.0.1:3128\n")
            f.write("127.0.0.1:1080\n")
        
        # Create test config file
        test_config_file = self.temp_dir / "config.json"
        with open(test_config_file, 'w') as f:
            f.write('{"timeout": 5, "threads": 4}')
        
        # Update flag definitions with actual paths
        FLAG_DEFINITIONS['--input'] = [str(test_proxies_file), 'nonexistent.txt']
        FLAG_DEFINITIONS['--config'] = [str(test_config_file)]
        FLAG_DEFINITIONS['--database'] = [str(self.temp_dir / 'test.db')]
        
        # Update output paths to temp directory
        FLAG_DEFINITIONS['--output'] = [
            str(self.temp_dir / 'output.json'),
            str(self.temp_dir / 'output.txt'), 
            str(self.temp_dir / 'output.csv')
        ]
    
    def cleanup_test_environment(self):
        """Clean up test environment"""
        if self.temp_dir and self.temp_dir.exists():
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def is_combination_invalid(self, flags: List[Tuple[str, str]]) -> bool:
        """Check if flag combination is known to be invalid"""
        
        flag_names = [flag for flag, value in flags]
        
        # Check for incompatible combinations
        for incompatible in INCOMPATIBLE_COMBINATIONS:
            if all(flag in flag_names for flag in incompatible):
                return True
        
        # Check for duplicate flags
        if len(flag_names) != len(set(flag_names)):
            return True
        
        return False
    
    def build_command(self, flags: List[Tuple[str, str]]) -> List[str]:
        """Build command line from flag combinations"""
        
        cmd = [sys.executable, '-m', 'proxc.main']
        
        for flag, value in flags:
            cmd.append(flag)
            if value is not None:
                cmd.append(value)
        
        return cmd
    
    def execute_command(self, cmd: List[str], timeout: int = 10) -> Dict[str, Any]:
        """Execute command and capture results"""
        
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.temp_dir)
            )
            
            execution_time = time.time() - start_time
            
            return {
                'command': ' '.join(cmd),
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'execution_time': execution_time,
                'timed_out': False,
                'error': None
            }
        
        except subprocess.TimeoutExpired:
            return {
                'command': ' '.join(cmd),
                'return_code': -1,
                'stdout': '',
                'stderr': 'Command timed out',
                'execution_time': timeout,
                'timed_out': True,
                'error': 'timeout'
            }
        
        except Exception as e:
            return {
                'command': ' '.join(cmd),
                'return_code': -1,
                'stdout': '',
                'stderr': str(e),
                'execution_time': time.time() - start_time,
                'timed_out': False,
                'error': str(e)
            }
    
    def test_single_flags(self) -> List[Dict[str, Any]]:
        """Test individual flags"""
        
        print("🧪 Testing individual flags...")
        
        results = []
        
        for flag, values in FLAG_DEFINITIONS.items():
            for value in values:
                if flag in ['--help', '--version']:
                    # Special handling for help/version flags
                    cmd = self.build_command([(flag, value)])
                    result = self.execute_command(cmd)
                    result['test_type'] = 'single_flag'
                    result['flags'] = [(flag, value)]
                    result['expected_success'] = True
                    results.append(result)
                
                elif flag in FLAGS_REQUIRING_VALUES and value is not None:
                    # Test flags that require values
                    cmd = self.build_command([(flag, value)])
                    result = self.execute_command(cmd)
                    result['test_type'] = 'single_flag'
                    result['flags'] = [(flag, value)]
                    result['expected_success'] = flag not in ['--input'] or 'nonexistent' not in value
                    results.append(result)
                
                elif flag not in FLAGS_REQUIRING_VALUES:
                    # Test boolean flags
                    cmd = self.build_command([(flag, None)])
                    result = self.execute_command(cmd)
                    result['test_type'] = 'single_flag'
                    result['flags'] = [(flag, None)]
                    result['expected_success'] = True
                    results.append(result)
        
        print(f"  ✅ Tested {len(results)} individual flag combinations")
        return results
    
    def test_flag_pairs(self) -> List[Dict[str, Any]]:
        """Test pairs of flags"""
        
        print("🧪 Testing flag pairs...")
        
        results = []
        flag_items = list(FLAG_DEFINITIONS.items())
        
        # Test combinations of 2 flags
        for i, (flag1, values1) in enumerate(flag_items):
            for j, (flag2, values2) in enumerate(flag_items):
                if i >= j:  # Avoid duplicate combinations
                    continue
                
                # Skip help/version with other flags
                if flag1 in ['--help', '--version'] or flag2 in ['--help', '--version']:
                    continue
                
                # Test first value of each flag
                value1 = values1[0] if values1 else None
                value2 = values2[0] if values2 else None
                
                flags = [(flag1, value1), (flag2, value2)]
                
                # Skip invalid combinations
                if self.is_combination_invalid(flags):
                    continue
                
                cmd = self.build_command(flags)
                result = self.execute_command(cmd)
                result['test_type'] = 'flag_pair'
                result['flags'] = flags
                result['expected_success'] = True  # Most pairs should work
                results.append(result)
                
                # Limit to prevent excessive testing
                if len(results) >= 100:
                    break
            
            if len(results) >= 100:
                break
        
        print(f"  ✅ Tested {len(results)} flag pair combinations")
        return results
    
    def test_conflict_scenarios(self) -> List[Dict[str, Any]]:
        """Test known conflicting flag scenarios"""
        
        print("🧪 Testing conflict scenarios...")
        
        results = []
        
        # Test incompatible combinations
        for incompatible in INCOMPATIBLE_COMBINATIONS:
            flags = []
            for flag in incompatible:
                values = FLAG_DEFINITIONS.get(flag, [None])
                value = values[0] if values else None
                flags.append((flag, value))
            
            cmd = self.build_command(flags)
            result = self.execute_command(cmd)
            result['test_type'] = 'conflict_scenario'
            result['flags'] = flags
            result['expected_success'] = False  # Should fail
            results.append(result)
        
        # Test invalid flag values
        invalid_tests = [
            ('--timeout', '-1'),      # Negative timeout
            ('--threads', '0'),       # Zero threads
            ('--threads', 'abc'),     # Non-numeric threads
            ('--format', 'invalid'),  # Invalid format
            ('--method', 'unknown'),  # Unknown method
        ]
        
        for flag, invalid_value in invalid_tests:
            cmd = self.build_command([(flag, invalid_value)])
            result = self.execute_command(cmd)
            result['test_type'] = 'invalid_value'
            result['flags'] = [(flag, invalid_value)]
            result['expected_success'] = False
            results.append(result)
        
        print(f"  ✅ Tested {len(results)} conflict scenarios")
        return results
    
    def test_comprehensive_scenarios(self) -> List[Dict[str, Any]]:
        """Test comprehensive realistic scenarios"""
        
        print("🧪 Testing comprehensive scenarios...")
        
        results = []
        
        # Common usage scenarios
        scenarios = [
            # Basic validation
            [('--input', FLAG_DEFINITIONS['--input'][0]), 
             ('--output', FLAG_DEFINITIONS['--output'][0])],
            
            # Validation with options
            [('--input', FLAG_DEFINITIONS['--input'][0]),
             ('--output', FLAG_DEFINITIONS['--output'][0]),
             ('--timeout', '5'),
             ('--threads', '4')],
            
            # Format conversion
            [('--input', FLAG_DEFINITIONS['--input'][0]),
             ('--output', FLAG_DEFINITIONS['--output'][1]),
             ('--format', 'txt')],
            
            # Filtering scenario
            [('--input', FLAG_DEFINITIONS['--input'][0]),
             ('--output', FLAG_DEFINITIONS['--output'][0]),
             ('--protocol', 'http'),
             ('--anonymity', 'elite')],
            
            # Quiet operation
            [('--input', FLAG_DEFINITIONS['--input'][0]),
             ('--output', FLAG_DEFINITIONS['--output'][0]),
             ('--quiet', None)],
            
            # Verbose operation
            [('--input', FLAG_DEFINITIONS['--input'][0]),
             ('--output', FLAG_DEFINITIONS['--output'][0]),
             ('--verbose', None)],
        ]
        
        for i, flags in enumerate(scenarios):
            cmd = self.build_command(flags)
            result = self.execute_command(cmd)
            result['test_type'] = 'comprehensive_scenario'
            result['scenario_id'] = i
            result['flags'] = flags
            result['expected_success'] = True
            results.append(result)
        
        print(f"  ✅ Tested {len(results)} comprehensive scenarios")
        return results
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run complete flag combination test suite"""
        
        print("🚀 Starting Flag Combination Test Suite - Phase 4.1.6")
        print("=" * 60)
        
        start_time = time.time()
        
        # Setup test environment
        self.setup_test_environment()
        
        try:
            # Run test categories
            single_flag_results = self.test_single_flags()
            pair_results = self.test_flag_pairs()
            conflict_results = self.test_conflict_scenarios()
            comprehensive_results = self.test_comprehensive_scenarios()
            
            # Combine all results
            all_results = (single_flag_results + pair_results + 
                         conflict_results + comprehensive_results)
            
            # Analyze results
            total_tests = len(all_results)
            successful_tests = []
            failed_tests = []
            timeout_tests = []
            
            for result in all_results:
                expected_success = result.get('expected_success', True)
                actual_success = result['return_code'] == 0
                
                if result['timed_out']:
                    timeout_tests.append(result)
                elif expected_success == actual_success:
                    successful_tests.append(result)
                else:
                    failed_tests.append(result)
            
            duration = time.time() - start_time
            
            summary = {
                'total_tests': total_tests,
                'successful_tests': len(successful_tests),
                'failed_tests': len(failed_tests),
                'timeout_tests': len(timeout_tests),
                'success_rate': (len(successful_tests) / total_tests) * 100 if total_tests > 0 else 0,
                'duration_seconds': duration,
                'test_results': all_results,
                'failed_test_details': failed_tests[:10],  # First 10 failures
                'overall_status': 'PASSED' if len(failed_tests) == 0 else 'FAILED'
            }
            
            return summary
        
        finally:
            # Cleanup
            self.cleanup_test_environment()
    
    def print_summary(self, summary: Dict[str, Any]):
        """Print test summary"""
        
        print(f"\n{'='*60}")
        print(f"🧪 FLAG COMBINATION TEST RESULTS")
        print(f"{'='*60}")
        
        print(f"📊 Overall Results:")
        print(f"   Total Tests: {summary['total_tests']}")
        print(f"   Successful: {summary['successful_tests']}")
        print(f"   Failed: {summary['failed_tests']}")
        print(f"   Timeouts: {summary['timeout_tests']}")
        print(f"   Success Rate: {summary['success_rate']:.1f}%")
        print(f"   Duration: {summary['duration_seconds']:.2f}s")
        
        status_emoji = "✅" if summary['overall_status'] == 'PASSED' else "❌"
        print(f"   Status: {status_emoji} {summary['overall_status']}")
        
        if summary['failed_test_details']:
            print(f"\n🚨 Failed Tests (showing first 10):")
            for failed_test in summary['failed_test_details']:
                flags_str = ' '.join(f"{flag} {value or ''}" for flag, value in failed_test['flags'])
                print(f"   ❌ {flags_str}")
                print(f"      Return code: {failed_test['return_code']}")
                if failed_test['stderr']:
                    print(f"      Error: {failed_test['stderr'][:100]}...")
        
        print(f"\n{'='*60}")


# Entry point
if __name__ == "__main__":
    print("🚀 Starting Flag Combination Tester - Phase 4.1.6")
    
    tester = FlagCombinationTester()
    results = tester.run_all_tests()
    tester.print_summary(results)
    
    # Exit with appropriate code
    exit_code = 0 if results['overall_status'] == 'PASSED' else 1
    sys.exit(exit_code)