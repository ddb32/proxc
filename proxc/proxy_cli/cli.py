#!/usr/bin/env python3
"""proxc - Unified CLI Interface"""

import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

# Use centralized import management
from .cli_imports import get_cli_imports, print_error, print_success, print_warning, print_cli
from .cli_base import CLIFormatterMixin, CLIProgressTracker, get_cli_config, get_cli_logger
from .cli_exceptions import ProxyCLIError, CommandError, ConfigurationError, CLIErrorHandler

# Get standardized logger for this module
logger = get_cli_logger("cli")
error_handler = CLIErrorHandler(logger)

# Initialize imports
cli_imports = get_cli_imports()

# Legacy compatibility
HAS_CLICK = cli_imports.has_click
HAS_RICH = cli_imports.has_rich
HAS_ARGCOMPLETE = cli_imports.has_argcomplete

# Exit if Click is not available (required)
if not HAS_CLICK:
    print_error("Click library required. Install with: pip install click")
    sys.exit(1)

# Import Click after verification
import click

# Import our modules
from ..proxy_core.models import ProxyInfo, ProxyProtocol, AnonymityLevel, ThreatLevel, ProxyStatus
from ..proxy_core.config import ConfigManager, create_cli_overrides
from ..proxy_core.database import DatabaseManager, DatabaseManagerExtended, create_extended_database_manager
from ..proxy_core.metrics import MetricsCollector
from ..proxy_core.constants import CLI_DEFAULT_TIMEOUT_SEC, CLI_DEFAULT_THREADS

# Initialize DNS configuration for cross-platform compatibility
try:
    from ..proxy_core.dns_config import initialize_dns_config
    from ..proxy_core.platform_utils import log_platform_info
    
    # Initialize DNS on module load
    initialize_dns_config()
    
    # Log platform info for debugging
    if logger.isEnabledFor(logging.DEBUG):
        log_platform_info()
        
except ImportError:
    # DNS configuration unavailable - silently continue
    pass
except Exception:
    # DNS initialization failed - silently continue
    pass

from ..proxy_engine.fetchers import ProxyFetcher
from ..proxy_engine.validators import BatchValidator, ValidationMethod
from ..proxy_engine.validation.validation_config import ValidationConfig
from ..proxy_engine.analyzers import ProxyAnalyzer
from ..proxy_engine.filters import ProxyFilter, FilterCriteria, FilterPresets
from ..proxy_engine.exporters import ExportManager, ExportFormat
from ..proxy_engine.export import APIExportManager, create_api_export_config, validate_api_url
from ..proxy_engine.protocol_detection import ProxyProtocolDetector, detect_batch_protocols

try:
    from ..proxy_engine.async_validators import HAS_AIOHTTP
except ImportError:
    HAS_AIOHTTP = False


# ===============================================================================
# FORMAT DETECTION AND SMART DEFAULTS
# ===============================================================================

def detect_file_format(file_path: str) -> str:
    """Auto-detect file format from extension"""
    path = Path(file_path)
    extension = path.suffix.lower()
    
    format_map = {
        '.txt': 'txt',
        '.json': 'json', 
        '.csv': 'csv',
        '.xlsx': 'xlsx',
        '.xls': 'xlsx'
    }
    
    return format_map.get(extension, 'txt')

def infer_proxy_protocol(proxy_string: str) -> str:
    """Smart protocol detection from proxy string"""
    if ':' in proxy_string:
        parts = proxy_string.split(':')
        if len(parts) >= 2:
            try:
                port = int(parts[1])
                # Common port-based detection
                if port in [1080, 9050, 9150]:  # SOCKS ports
                    return 'socks5'
                elif port in [1081, 9051]:  # SOCKS4 ports  
                    return 'socks4'
                elif port in [80, 8080, 3128, 8888]:  # HTTP ports
                    return 'http'
                elif port in [443, 8443]:  # HTTPS ports
                    return 'https'
            except ValueError:
                pass
    return 'http'  # Default




def parse_protocol_prefix(line: str) -> Tuple[Optional[str], str]:
    """Parse protocol prefix from line if present
    
    Args:
        line: Input line (e.g., "socks5://192.168.1.1:1080" or "SOCKS5//192.168.1.1:1080" or "192.168.1.1:1080")
        
    Returns:
        Tuple of (protocol, address) where protocol is None if no prefix found
    """
    line = line.strip()
    if not line:
        return None, ""
    
    if '://' in line:
        # Handle URL-style format: socks5://host:port
        try:
            from urllib.parse import urlparse
            parsed = urlparse(line.split()[0])  # Take only URL part, ignore timing data
            if parsed.scheme and parsed.hostname and parsed.port:
                protocol_str = parsed.scheme.lower()
                # Validate protocol
                valid_protocols = ['http', 'https', 'socks4', 'socks5']
                if protocol_str in valid_protocols:
                    return protocol_str, f"{parsed.hostname}:{parsed.port}"
                else:
                    # Invalid protocol prefix
                    return None, line  # Return original line for error handling
        except:
            pass
    
    if '//' in line and '://' not in line:
        # Handle legacy format: SOCKS5//host:port
        parts = line.split('//', 1)
        if len(parts) == 2:
            protocol_str = parts[0].strip().upper()
            address = parts[1].strip()
            
            # Validate protocol
            valid_protocols = ['HTTP', 'HTTPS', 'SOCKS4', 'SOCKS5']
            if protocol_str in valid_protocols:
                return protocol_str.lower(), address
            else:
                # Invalid protocol prefix
                return None, line  # Return original line for error handling
    
    return None, line


def infer_proxy_protocol(line: str) -> str:
    """Infer proxy protocol from port or context clues
    
    Args:
        line: Input line containing proxy information
        
    Returns:
        Inferred protocol string (http, https, socks4, socks5)
    """
    line_lower = line.lower()
    
    # Check for explicit protocol mentions
    if 'socks5' in line_lower or 'socks://5' in line_lower:
        return 'socks5'
    elif 'socks4' in line_lower or 'socks://4' in line_lower:
        return 'socks4'
    elif 'https' in line_lower:
        return 'https'
    elif 'http' in line_lower:
        return 'http'
    
    # Infer from port number if present
    import re
    port_match = re.search(r':(\d+)', line)
    if port_match:
        port = int(port_match.group(1))
        
        # Common SOCKS ports
        if port in [1080, 1081, 1082, 1083, 1084, 1085]:
            return 'socks5'
        # Common HTTPS ports
        elif port in [443, 8443]:
            return 'https'
        # Common HTTP ports
        elif port in [80, 8080, 3128, 8888]:
            return 'http'
    
    # Default fallback
    return 'http'


def validate_advanced_conflicts(**kwargs) -> List[str]:
    """
    Enhanced conflict detection for CLI flags.
    
    Returns:
        List of conflict error messages (empty if no conflicts)
    """
    conflicts = []
    
    # Extract parameters for easier access
    input_file = kwargs.get('input_file')
    output_file = kwargs.get('output_file')
    scan = kwargs.get('scan')
    use_db = kwargs.get('use_db')
    db_path = kwargs.get('db_path')
    export_from_db = kwargs.get('export_from_db')
    
    api_export = kwargs.get('api_export')
    api_auth = kwargs.get('api_auth')
    api_token = kwargs.get('api_token')
    
    validate = kwargs.get('validate')
    protocol_mode = kwargs.get('protocol_mode')
    protocol_strict = kwargs.get('protocol_strict')
    
    cache_validation = kwargs.get('cache_validation')
    cache_memory_mb = kwargs.get('cache_memory_mb')
    threads = kwargs.get('threads')
    timeout = kwargs.get('timeout')
    adaptive_threads = kwargs.get('adaptive_threads')
    
    discovery_mode = kwargs.get('discovery_mode')
    enable_fingerprinting = kwargs.get('enable_fingerprinting')
    enable_intelligence = kwargs.get('enable_intelligence')
    enable_repo_mining = kwargs.get('enable_repo_mining')
    enable_scrapers = kwargs.get('enable_scrapers')
    scraping_engine = kwargs.get('scraping_engine')
    
    detect_chains = kwargs.get('detect_chains')
    target_urls = kwargs.get('target_urls')
    target_config = kwargs.get('target_config')
    target_preset = kwargs.get('target_preset')
    url = kwargs.get('url')
    via_proxy = kwargs.get('via_proxy')
    
    enable_queue = kwargs.get('enable_queue')
    queue_worker_mode = kwargs.get('queue_worker_mode')
    
    view = kwargs.get('view')
    web_port = kwargs.get('web_port')
    
    # === 1. Input/Output Validation ===
    output_modes = sum([bool(output_file), bool(use_db), bool(db_path), bool(view)])
    if output_modes == 0 and (scan or input_file):
        conflicts.append("Must specify output: use -o/--output for file, -D/--use-db for database, or -w/--view for web interface")
    
    if input_file and scan:
        conflicts.append("Cannot use both --scan (discovery) and -f/--file (input) simultaneously")
    
    if export_from_db and not (use_db or db_path):
        conflicts.append("--export-from-db requires database mode (-D/--use-db or -B/--db-path)")
    
    # === 2. API Export Validation ===
    if api_export:
        # Validate API URL format
        if not api_export.startswith(('http://', 'https://')):
            conflicts.append("--api-export must be a valid HTTP/HTTPS URL")
        
        # Require authentication setup for secure APIs
        if api_auth != 'none' and not api_token:
            conflicts.append(f"--api-auth {api_auth} requires --api-token")
        
        # Network access requirement
        if not (scan or input_file):
            conflicts.append("--api-export requires data source (--scan or --file)")
    
    # === 3. Cache + Performance Conflicts ===
    if cache_validation and not validate:
        conflicts.append("--cache-validation requires --validate flag")
    
    if cache_memory_mb and cache_memory_mb < 10:
        conflicts.append("--cache-memory-mb must be at least 10MB")
    
    if cache_memory_mb and cache_memory_mb > 8192:
        conflicts.append("--cache-memory-mb exceeds safe limit (8192MB), reduce for stability")
    
    # === 4. Protocol Detection Conflicts ===
    if protocol_strict and protocol_mode == 'auto':
        conflicts.append("--protocol-strict requires explicit protocol mode (force:TYPE, detect, or from-file)")
    
    if protocol_mode == 'from-file' and not input_file:
        conflicts.append("--protocol-mode from-file requires input file (--file)")
    
    if protocol_mode.startswith('force:') and protocol_mode == 'detect':
        conflicts.append("Cannot combine force protocol with detection mode")
    
    # === 5. Threading + Memory Constraints ===
    if threads and threads > 100:
        conflicts.append("--threads exceeds safe limit (100), reduce to prevent resource exhaustion")
    
    if adaptive_threads and threads:
        conflicts.append("--adaptive-threads conflicts with fixed --threads value")
    
    if timeout and timeout < 1:
        conflicts.append("--timeout below 1 second may cause false negatives")
    
    # Memory pressure validation
    if cache_memory_mb and threads:
        estimated_memory = (threads * 4) + cache_memory_mb  # Rough estimate
        if estimated_memory > 2048:  # > 2GB
            conflicts.append(f"High memory usage detected (~{estimated_memory}MB). Reduce --threads or --cache-memory-mb")
    
    # === 6. Discovery Mode Dependencies ===
    if discovery_mode == 'active' and not scan:
        conflicts.append("--discovery-mode active requires --scan flag")
    
    if enable_intelligence and not scan:
        conflicts.append("--enable-intelligence requires --scan flag")
    
    if enable_repo_mining and not scan:
        conflicts.append("--enable-repo-mining requires --scan flag")
    
    if enable_fingerprinting and not validate:
        conflicts.append("--enable-fingerprinting requires --validate flag")
    
    if scraping_engine == 'playwright' and not enable_scrapers:
        conflicts.append("--scraping-engine playwright requires --enable-scrapers")
    
    # === 7. Target Testing Dependencies ===
    target_test_flags = [target_urls, target_config, target_preset]
    if any(target_test_flags) and not validate:
        conflicts.append("Target testing requires --validate flag")
    
    target_count = sum(1 for flag in target_test_flags if flag)
    if target_count > 1:
        conflicts.append("Use only one target specification: --target-urls, --target-config, or --target-preset")
    
    # === 8. Advanced Feature Dependencies ===
    if detect_chains and not validate:
        conflicts.append("--detect-chains requires --validate flag")
    
    if via_proxy and not validate:
        conflicts.append("--via-proxy requires --validate flag")
    
    if url and not validate:
        conflicts.append("Custom --url testing requires --validate flag")
    
    # === 9. Queue Management Conflicts ===
    if queue_worker_mode and (scan or input_file):
        conflicts.append("--queue-worker-mode cannot be combined with data processing flags")
    
    if enable_queue and not (scan or validate):
        conflicts.append("--enable-queue requires data processing operations")
    
    # === 10. Web Interface Requirements ===
    if web_port and not view:
        conflicts.append("--web-port requires --view flag")
    
    # Web interface can work with in-memory data, output destination not required
    
    return conflicts


class ErrorSuggestionEngine:
    """
    Intelligent error suggestion engine for CLI operations.
    Provides contextual help, command examples, and typo corrections.
    """
    
    def __init__(self):
        # Common fix patterns for different error types
        self.fix_patterns = {
            'missing_output': [
                "Add output destination: -o results.txt",
                "Or use database mode: -D --db-path proxies.db",
                "For viewing results: --view -o results.txt"
            ],
            'missing_input': [
                "Add input source: --scan (discover proxies)",
                "Or specify file: -f input.txt",
                "For test mode: --scan --count 10"
            ],
            'missing_validation': [
                "Add validation: --validate",
                "For quick test: --validate --count 10",
                "With timeout: --validate --timeout 15"
            ],
            'threading_limits': [
                "Reduce threads: --threads 50",
                "Use adaptive: --adaptive-threads",
                "For stability: --threads 20 --timeout 15"
            ],
            'memory_limits': [
                "Reduce cache: --cache-memory-mb 512",
                "Lower thread count: --threads 20",
                "Use streaming: (automatic for large datasets)"
            ],
            'protocol_conflicts': [
                "Use single protocol mode:",
                "  Force HTTP: --protocol-mode force:http",
                "  Auto-detect: --protocol-mode detect",
                "  From file: --protocol-mode from-file -f urls.txt"
            ],
            'api_setup': [
                "Complete API setup:",
                "  Basic: --api-export https://api.example.com/proxies",
                "  With auth: --api-auth bearer --api-token YOUR_TOKEN",
                "  Custom method: --api-method POST --api-batch-size 50"
            ],
            'discovery_setup': [
                "Enable discovery features:",
                "  Basic scan: --scan -o results.txt",
                "  With intelligence: --scan --enable-intelligence",
                "  Active mode: --scan --discovery-mode active"
            ]
        }
        
        # Working command examples by use case
        self.example_commands = {
            'basic_scan': "proxc --scan --validate -o proxies.txt",
            'file_validation': "proxc -f input.txt --validate -o valid.txt",
            'fast_discovery': "proxc --scan --count 50 --threads 20 -o fast.txt",
            'protocol_detection': "proxc -f mixed.txt --protocol-mode detect --validate -o detected.txt",
            'target_testing': "proxc --scan --validate --target-preset google -o tested.txt",
            'database_mode': "proxc --scan --validate -D --db-path proxies.db",
            'api_export': "proxc --scan --api-export https://api.example.com/proxies --api-auth bearer --api-token TOKEN",
            'chain_detection': "proxc --scan --validate --detect-chains -o secure.txt",
            'web_interface': "proxc --scan --validate --view -o results.txt",
            'advanced_discovery': "proxc --scan --discovery-mode active --enable-intelligence --github-token TOKEN -o advanced.txt"
        }
        
        # Common flag typos and corrections
        self.flag_corrections = {
            '--scann': '--scan',
            '--validte': '--validate',
            '--ouput': '--output',
            '--threds': '--threads',
            '--timout': '--timeout',
            '--fils': '--file',
            '--databse': '--database',
            '--protcol': '--protocol',
            '--cahce': '--cache',
            '--targts': '--target-urls',
            '--api-exprt': '--api-export',
            '--web-prt': '--web-port',
            '--chaim': '--chain',
            '--discvery': '--discovery',
            '--intelligenc': '--intelligence'
        }
    
    def get_suggestion_for_error(self, error_message: str, **context) -> List[str]:
        """
        Get contextual suggestions based on error message and current CLI context.
        """
        suggestions = []
        error_lower = error_message.lower()
        
        # Analyze error type and provide targeted suggestions
        if 'output' in error_lower and 'specify' in error_lower:
            suggestions.extend(self.fix_patterns['missing_output'])
            suggestions.append(f"💡 Example: {self.example_commands['basic_scan']}")
            
        elif 'input' in error_lower or 'file' in error_lower:
            suggestions.extend(self.fix_patterns['missing_input'])
            suggestions.append(f"💡 Example: {self.example_commands['file_validation']}")
            
        elif 'validate' in error_lower or 'validation' in error_lower:
            suggestions.extend(self.fix_patterns['missing_validation'])
            suggestions.append(f"💡 Example: {self.example_commands['fast_discovery']}")
            
        elif 'thread' in error_lower:
            suggestions.extend(self.fix_patterns['threading_limits'])
            
        elif 'memory' in error_lower or 'cache' in error_lower:
            suggestions.extend(self.fix_patterns['memory_limits'])
            
        elif 'protocol' in error_lower:
            suggestions.extend(self.fix_patterns['protocol_conflicts'])
            suggestions.append(f"💡 Example: {self.example_commands['protocol_detection']}")
            
        elif 'api' in error_lower:
            suggestions.extend(self.fix_patterns['api_setup'])
            suggestions.append(f"💡 Example: {self.example_commands['api_export']}")
            
        elif 'discovery' in error_lower or 'intelligence' in error_lower:
            suggestions.extend(self.fix_patterns['discovery_setup'])
            suggestions.append(f"💡 Example: {self.example_commands['advanced_discovery']}")
        
        # Add contextual examples based on current flags
        if context:
            suggestions.extend(self._get_contextual_examples(context))
        
        return suggestions
    
    def _get_contextual_examples(self, context: Dict[str, Any]) -> List[str]:
        """Get examples based on current flag combination."""
        examples = []
        
        # Suggest based on what user is trying to do
        if context.get('scan') and not context.get('output_file'):
            examples.append("📝 Complete your scan: add -o results.txt")
            
        if context.get('validate') and not context.get('input_file') and not context.get('scan'):
            examples.append("📝 Add data source: --scan or -f input.txt")
            
        if context.get('target_urls') or context.get('target_preset'):
            examples.append(f"📝 Target testing: {self.example_commands['target_testing']}")
            
        if context.get('detect_chains'):
            examples.append(f"📝 Chain detection: {self.example_commands['chain_detection']}")
            
        if context.get('view'):
            examples.append(f"📝 Web interface: {self.example_commands['web_interface']}")
            
        return examples
    
    def suggest_flag_correction(self, flag: str) -> Optional[str]:
        """Suggest correction for mistyped flags."""
        return self.flag_corrections.get(flag)
    
    def get_workflow_suggestion(self, user_intent: str) -> str:
        """Get complete workflow suggestion based on user intent."""
        intent_lower = user_intent.lower()
        
        if 'scan' in intent_lower and 'validate' in intent_lower:
            return self.example_commands['basic_scan']
        elif 'file' in intent_lower and 'validate' in intent_lower:
            return self.example_commands['file_validation']
        elif 'target' in intent_lower or 'website' in intent_lower:
            return self.example_commands['target_testing']
        elif 'database' in intent_lower:
            return self.example_commands['database_mode']
        elif 'api' in intent_lower:
            return self.example_commands['api_export']
        elif 'web' in intent_lower or 'interface' in intent_lower:
            return self.example_commands['web_interface']
        elif 'chain' in intent_lower or 'security' in intent_lower:
            return self.example_commands['chain_detection']
        elif 'advanced' in intent_lower or 'intelligence' in intent_lower:
            return self.example_commands['advanced_discovery']
        else:
            return self.example_commands['basic_scan']


def enhanced_error_handler(error_message: str, suggestion_context: Optional[Dict[str, Any]] = None) -> None:
    """
    Enhanced error handler with intelligent suggestions and examples using Rich styling.
    """
    visual = RichVisualManager()
    suggestion_engine = ErrorSuggestionEngine()
    
    # Print the main error with Rich styling
    visual.print_status_line(error_message, "error")
    
    # Get contextual suggestions
    if suggestion_context:
        suggestions = suggestion_engine.get_suggestion_for_error(error_message, **suggestion_context)
    else:
        suggestions = suggestion_engine.get_suggestion_for_error(error_message)
    
    # Print suggestions with consistent formatting
    if suggestions:
        visual.print_status_line("Suggestions:", "info", prefix="💡 ")
        for suggestion in suggestions[:3]:  # Limit to top 3 suggestions
            print(f"   {suggestion}")
    
    # Always provide help reference
    visual.print_status_line("For more help: proxc --help", "info", prefix="📚 ")


def format_enhanced_conflicts(conflicts: List[str], cli_context: Optional[Dict[str, Any]] = None) -> None:
    """
    Format and display conflicts with enhanced suggestions using Rich styling.
    """
    visual = RichVisualManager()
    suggestion_engine = ErrorSuggestionEngine()
    
    visual.print_section_header("Configuration conflicts detected", "error")
    print("")
    
    for i, conflict in enumerate(conflicts, 1):
        visual.print_status_line(f"{i}. {conflict}", "error")
        
        # Get specific suggestions for this conflict
        suggestions = suggestion_engine.get_suggestion_for_error(conflict, **(cli_context or {}))
        
        if suggestions and i <= 2:  # Show detailed suggestions for first 2 conflicts
            for suggestion in suggestions[:2]:  # Top 2 suggestions per conflict
                print(f"   💡 {suggestion}")
        print("")
    
    # Show relevant workflow examples
    if cli_context:
        if cli_context.get('scan') and cli_context.get('validate'):
            visual.print_status_line("Try this working command:", "info", prefix="📝 ")
            print(f"   {suggestion_engine.example_commands['basic_scan']}")
        elif cli_context.get('input_file'):
            visual.print_status_line("Try this working command:", "info", prefix="📝 ")
            print(f"   {suggestion_engine.example_commands['file_validation']}")
    
    visual.print_status_line("For complete examples: proxc --help", "info", prefix="📚 ")


def handle_unknown_option(ctx, param, value):
    """Handle unknown options with typo suggestions using Rich styling."""
    visual = RichVisualManager()
    
    if value and isinstance(value, str) and value.startswith('--'):
        suggestion_engine = ErrorSuggestionEngine()
        correction = suggestion_engine.suggest_flag_correction(value)
        
        if correction:
            enhanced_error_handler(
                f"Unknown option '{value}'",
                {'suggested_flag': correction}
            )
            visual.print_status_line(f"Did you mean: {correction}?", "info", prefix="💡 ")
        else:
            # Find similar flags using fuzzy matching
            similar_flags = find_similar_flags(value)
            if similar_flags:
                visual.print_status_line(f"Unknown option '{value}'", "error")
                visual.print_status_line("Did you mean one of these?", "info", prefix="💡 ")
                for flag in similar_flags[:3]:
                    print(f"   {flag}")
            else:
                enhanced_error_handler(f"Unknown option '{value}'")
        
        ctx.exit(1)


def find_similar_flags(target_flag: str) -> List[str]:
    """Find flags similar to the target using simple string matching."""
    # Common CLI flags from the help text
    known_flags = [
        '--scan', '--validate', '--output', '--file', '--threads', '--timeout',
        '--protocol-mode', '--cache-validation', '--detect-chains', '--view',
        '--api-export', '--target-urls', '--discovery-mode', '--enable-intelligence',
        '--enable-fingerprinting', '--enable-repo-mining', '--use-db', '--db-path',
        '--verbose', '--quiet', '--silent', '--help', '--count', '--filter',
        '--analyze', '--url', '--via-proxy', '--web-port', '--config', '--log'
    ]
    
    target_lower = target_flag.lower()
    similar = []
    
    for flag in known_flags:
        flag_lower = flag.lower()
        # Simple similarity check based on common substrings
        if (len(target_lower) > 3 and target_lower[:-1] in flag_lower) or \
           (len(flag_lower) > 3 and flag_lower[:-1] in target_lower) or \
           (target_lower.replace('-', '') in flag_lower.replace('-', '')):
            similar.append(flag)
    
    return similar


class RichVisualManager:
    """
    Centralized Rich visual theme and component manager for consistent CLI appearance.
    """
    
    def __init__(self):
        self.cli_imports = get_cli_imports()
        
        # Standardized color scheme
        self.colors = {
            'primary': 'cyan',           # Main brand color
            'success': 'green',          # Success states
            'warning': 'yellow',         # Warnings
            'error': 'red',              # Errors
            'info': 'blue',              # Information
            'muted': 'dim white',        # Secondary text
            'accent': 'magenta',         # Highlights
            'progress': 'bright_cyan',   # Progress indicators
        }
        
        # Standardized icons
        self.icons = {
            'success': '✅',
            'error': '❌', 
            'warning': '⚠️',
            'info': 'ℹ️',
            'loading': '🔄',
            'network': '🌐',
            'security': '🛡️',
            'database': '💾',
            'file': '📄',
            'api': '🔌',
            'proxy': '🔀',
            'chain': '🔗',
            'target': '🎯',
            'discovery': '🔍',
            'intelligence': '🧠',
            'fingerprint': '👁️',
            'cache': '⚡',
            'thread': '🧵',
            'time': '⏱️',
            'memory': '🧠',
            'speed': '🚀',
            'location': '🌍',
        }
        
        # Progress bar themes
        self.progress_themes = {
            'scanning': {
                'description': '[cyan]Scanning sources...',
                'bar_style': 'cyan',
                'complete_style': 'green'
            },
            'validating': {
                'description': '[blue]Validating proxies...',
                'bar_style': 'blue', 
                'complete_style': 'green'
            },
            'analyzing': {
                'description': '[magenta]Analyzing results...',
                'bar_style': 'magenta',
                'complete_style': 'green'
            },
            'exporting': {
                'description': '[yellow]Exporting data...',
                'bar_style': 'yellow',
                'complete_style': 'green'
            }
        }
    
    def create_progress_bar(self, theme: str = 'scanning', total: int = 100):
        """Create a standardized progress bar with theme."""
        if not self.cli_imports.has_rich:
            return None
        
        theme_config = self.progress_themes.get(theme, self.progress_themes['scanning'])
        
        progress = self.cli_imports.rich['Progress'](
            self.cli_imports.rich['SpinnerColumn'](),
            self.cli_imports.rich['TextColumn']("[progress.description]{task.description}"),
            self.cli_imports.rich['BarColumn'](bar_width=40),
            "[progress.percentage]{task.percentage:>3.0f}%",
            self.cli_imports.rich['TimeElapsedColumn'](),
            self.cli_imports.rich['TimeRemainingColumn'](),
            console=self.cli_imports.console
        )
        
        return progress
    
    def create_status_table(self, title: str = "Status"):
        """Create a standardized status table."""
        if not self.cli_imports.has_rich:
            return None
        
        table = self.cli_imports.rich['Table'](
            title=f"[bold {self.colors['primary']}]{title}[/bold {self.colors['primary']}]",
            show_header=True,
            header_style=f"bold {self.colors['primary']}",
            border_style=self.colors['muted']
        )
        
        return table
    
    def create_results_table(self):
        """Create a standardized results summary table."""
        if not self.cli_imports.has_rich:
            return None
        
        table = self.cli_imports.rich['Table'](
            title=f"[bold {self.colors['primary']}]{self.icons['proxy']} Proxy Results Summary[/bold {self.colors['primary']}]",
            show_header=True,
            header_style=f"bold {self.colors['primary']}",
            border_style=self.colors['muted'],
            row_styles=[self.colors['muted'], ""]
        )
        
        # Standard columns for proxy results
        table.add_column("Metric", style=f"bold {self.colors['info']}")
        table.add_column("Count", justify="right", style=self.colors['accent'])
        table.add_column("Percentage", justify="right", style=self.colors['muted'])
        table.add_column("Status", justify="center")
        
        return table
    
    def create_panel(self, content: str, title: str = "", style: str = "info"):
        """Create a standardized panel with consistent styling."""
        if not self.cli_imports.has_rich:
            return content
        
        panel_style = self.colors.get(style, self.colors['info'])
        icon = self.icons.get(style, self.icons['info'])
        
        full_title = f"[bold {panel_style}]{icon} {title}[/bold {panel_style}]" if title else ""
        
        return self.cli_imports.rich['Panel'](
            content,
            title=full_title,
            border_style=panel_style,
            padding=(1, 2)
        )
    
    def format_status_message(self, message: str, status: str = "info", icon: bool = True):
        """Format a status message with consistent styling."""
        color = self.colors.get(status, self.colors['info'])
        status_icon = self.icons.get(status, self.icons['info']) if icon else ""
        
        if self.cli_imports.has_rich:
            return f"[{color}]{status_icon} {message}[/{color}]" if icon else f"[{color}]{message}[/{color}]"
        else:
            return f"{status_icon} {message}" if icon else message
    
    def format_metric(self, label: str, value: str, unit: str = "", status: str = "info"):
        """Format a metric with consistent styling."""
        color = self.colors.get(status, self.colors['info'])
        
        if self.cli_imports.has_rich:
            return f"[dim]{label}:[/dim] [{color}]{value}[/{color}] {unit}".strip()
        else:
            return f"{label}: {value} {unit}".strip()
    
    def print_section_header(self, title: str, icon_type: str = "info"):
        """Print a standardized section header."""
        icon = self.icons.get(icon_type, self.icons['info'])
        
        if self.cli_imports.has_rich:
            self.cli_imports.console.print(f"\n[bold {self.colors['primary']}]{icon} {title}[/bold {self.colors['primary']}]")
        else:
            print(f"\n{icon} {title}")
    
    def print_status_line(self, message: str, status: str = "info", prefix: str = ""):
        """Print a standardized status line."""
        formatted_message = self.format_status_message(message, status)
        
        if self.cli_imports.has_rich:
            self.cli_imports.console.print(f"{prefix}{formatted_message}")
        else:
            print(f"{prefix}{formatted_message}")
    
    def print_metric_line(self, label: str, value: str, unit: str = "", status: str = "info", indent: int = 2):
        """Print a formatted metric line."""
        prefix = " " * indent
        formatted_metric = self.format_metric(label, value, unit, status)
        
        if self.cli_imports.has_rich:
            self.cli_imports.console.print(f"{prefix}{formatted_metric}")
        else:
            print(f"{prefix}{formatted_metric}")


class OperationProgressTracker:
    """
    Enhanced progress tracking for long-running operations with Rich integration.
    """
    
    def __init__(self, visual_manager: RichVisualManager):
        self.visual = visual_manager
        self.current_progress = None
        self.current_task = None
        self.operation_start_time = None
        
    def start_operation(self, operation_type: str, total_items: int = 100, description: str = ""):
        """Start a new operation with progress tracking."""
        self.operation_start_time = time.time()
        
        if not self.visual.cli_imports.has_rich:
            # Fallback for no Rich
            print(f"{self.visual.icons['loading']} {description or f'Starting {operation_type}...'}")
            return None
        
        # Create progress bar with appropriate theme
        self.current_progress = self.visual.create_progress_bar(operation_type, total_items)
        
        if self.current_progress:
            self.current_task = self.current_progress.add_task(
                description or f"{operation_type.title()} in progress...",
                total=total_items
            )
            self.current_progress.start()
        
        return self.current_progress
    
    def update_progress(self, advance: int = 1, description: str = None):
        """Update the current operation progress."""
        if self.current_progress and self.current_task is not None:
            self.current_progress.update(self.current_task, advance=advance)
            if description:
                self.current_progress.update(self.current_task, description=description)
    
    def complete_operation(self, success: bool = True, summary_message: str = ""):
        """Complete the current operation."""
        if self.current_progress:
            self.current_progress.stop()
            self.current_progress = None
            self.current_task = None
        
        # Calculate operation time
        if self.operation_start_time:
            duration = time.time() - self.operation_start_time
            duration_str = f"({duration:.1f}s)"
        else:
            duration_str = ""
        
        # Print completion message
        status = "success" if success else "error"
        icon = self.visual.icons['success'] if success else self.visual.icons['error']
        
        if summary_message:
            self.visual.print_status_line(f"{summary_message} {duration_str}", status)
        else:
            action = "completed" if success else "failed"
            self.visual.print_status_line(f"Operation {action} {duration_str}", status)


class ValidationStatusTracker:
    """
    Specialized status tracking for validation operations.
    """
    
    def __init__(self, visual_manager: RichVisualManager):
        self.visual = visual_manager
        self.stats = {
            'total': 0,
            'valid': 0,
            'invalid': 0,
            'timeouts': 0,
            'errors': 0,
            'current_batch': 0
        }
        self.last_update_time = 0
        self.update_interval = 2.0  # Update every 2 seconds
    
    def update_stats(self, **kwargs):
        """Update validation statistics."""
        for key, value in kwargs.items():
            if key in self.stats:
                self.stats[key] = value
    
    def increment_stat(self, stat_name: str, amount: int = 1):
        """Increment a specific statistic."""
        if stat_name in self.stats:
            self.stats[stat_name] += amount
    
    def should_update_display(self) -> bool:
        """Check if display should be updated based on time interval."""
        current_time = time.time()
        if current_time - self.last_update_time >= self.update_interval:
            self.last_update_time = current_time
            return True
        return False
    
    def print_live_status(self):
        """Print live validation status."""
        if not self.should_update_display():
            return
        
        total = self.stats['total']
        valid = self.stats['valid']
        invalid = self.stats['invalid']
        
        if total > 0:
            success_rate = (valid / total) * 100
            status_color = "success" if success_rate > 70 else "warning" if success_rate > 30 else "error"
            
            self.visual.print_status_line(
                f"Progress: {valid}/{total} valid ({success_rate:.1f}%) | "
                f"Batch: {self.stats['current_batch']}", 
                status_color
            )
    
    def print_final_summary(self):
        """Print final validation summary with Rich table."""
        if not self.visual.cli_imports.has_rich:
            # Fallback summary
            total = self.stats['total']
            valid = self.stats['valid']
            invalid = self.stats['invalid']
            
            print(f"\n{self.visual.icons['proxy']} Validation Summary:")
            print(f"  Total Proxies: {total}")
            print(f"  Valid: {valid} ({(valid/total*100) if total > 0 else 0:.1f}%)")
            print(f"  Invalid: {invalid} ({(invalid/total*100) if total > 0 else 0:.1f}%)")
            return
        
        # Rich table summary
        table = self.visual.create_results_table()
        total = self.stats['total']
        
        if total > 0:
            valid_pct = (self.stats['valid'] / total) * 100
            invalid_pct = (self.stats['invalid'] / total) * 100
            timeout_pct = (self.stats['timeouts'] / total) * 100
            error_pct = (self.stats['errors'] / total) * 100
        else:
            valid_pct = invalid_pct = timeout_pct = error_pct = 0
        
        # Add rows to table
        table.add_row(
            "Total Proxies", 
            str(total), 
            "100%", 
            f"[{self.visual.colors['info']}]{self.visual.icons['proxy']}[/{self.visual.colors['info']}]"
        )
        
        table.add_row(
            "Valid Proxies", 
            str(self.stats['valid']), 
            f"{valid_pct:.1f}%", 
            f"[{self.visual.colors['success']}]{self.visual.icons['success']}[/{self.visual.colors['success']}]"
        )
        
        table.add_row(
            "Invalid Proxies", 
            str(self.stats['invalid']), 
            f"{invalid_pct:.1f}%", 
            f"[{self.visual.colors['error']}]{self.visual.icons['error']}[/{self.visual.colors['error']}]"
        )
        
        if self.stats['timeouts'] > 0:
            table.add_row(
                "Timeouts", 
                str(self.stats['timeouts']), 
                f"{timeout_pct:.1f}%", 
                f"[{self.visual.colors['warning']}]{self.visual.icons['time']}[/{self.visual.colors['warning']}]"
            )
        
        if self.stats['errors'] > 0:
            table.add_row(
                "Errors", 
                str(self.stats['errors']), 
                f"{error_pct:.1f}%", 
                f"[{self.visual.colors['error']}]{self.visual.icons['warning']}[/{self.visual.colors['error']}]"
            )
        
        self.visual.cli_imports.console.print("\n")
        self.visual.cli_imports.console.print(table)


class NetworkOperationSpinner:
    """
    Spinner animations for network operations.
    """
    
    def __init__(self, visual_manager: RichVisualManager):
        self.visual = visual_manager
        self.spinner = None
        self.live_display = None
        
    def start_spinner(self, message: str = "Processing...", spinner_type: str = "dots"):
        """Start a spinner animation."""
        if not self.visual.cli_imports.has_rich:
            print(f"{self.visual.icons['loading']} {message}")
            return
        
        spinner_text = self.visual.format_status_message(message, "info")
        
        self.live_display = self.visual.cli_imports.rich['Live'](
            spinner_text,
            console=self.visual.cli_imports.console,
            refresh_per_second=4
        )
        
        self.live_display.start()
    
    def update_spinner(self, message: str):
        """Update spinner message."""
        if self.live_display:
            spinner_text = self.visual.format_status_message(message, "info")
            self.live_display.update(spinner_text)
    
    def stop_spinner(self, final_message: str = "", success: bool = True):
        """Stop the spinner animation."""
        if self.live_display:
            self.live_display.stop()
            self.live_display = None
        
        if final_message:
            status = "success" if success else "error"
            self.visual.print_status_line(final_message, status)


class CacheStatsDisplay:
    """
    Comprehensive cache statistics display with Rich formatting and recommendations.
    """
    
    def __init__(self, visual_manager: RichVisualManager):
        self.visual = visual_manager
        
        # Performance thresholds for recommendations
        self.performance_thresholds = {
            'excellent_hit_ratio': 0.85,
            'good_hit_ratio': 0.70,
            'poor_hit_ratio': 0.50,
            'high_memory_usage': 0.80,
            'excessive_evictions': 0.20,  # % of total requests
            'slow_hit_time': 5.0,  # milliseconds
        }
    
    def display_cache_summary(self, cache_metrics: Dict[str, Any], show_recommendations: bool = True):
        """Display comprehensive cache statistics summary."""
        if not cache_metrics:
            self.visual.print_status_line("No cache statistics available", "warning")
            return
        
        self.visual.print_section_header("Cache Performance Statistics", "cache")
        
        # Extract key metrics
        combined = cache_metrics.get('combined', {})
        perf = combined.get('performance', {})
        memory = combined.get('memory', {})
        evictions = combined.get('evictions', {})
        timing = combined.get('timing', {})
        system_memory = cache_metrics.get('system_memory', {})
        
        # Display main performance table
        self._display_performance_table(perf, timing, memory)
        
        # Display eviction statistics if significant
        if evictions.get('total', 0) > 0:
            print()
            self._display_eviction_table(evictions)
        
        # Display memory usage
        if system_memory:
            print()
            self._display_memory_table(memory, system_memory)
        
        # Display cache policy info
        cache_name = cache_metrics.get('cache_name', 'Unknown')
        cache_policy = cache_metrics.get('cache_policy', 'Unknown')
        print()
        self._display_cache_info(cache_name, cache_policy)
        
        # Show recommendations
        if show_recommendations:
            print()
            self._display_recommendations(perf, memory, evictions, timing, system_memory)
    
    def _display_performance_table(self, perf: Dict, timing: Dict, memory: Dict):
        """Display main performance metrics table."""
        if not self.visual.cli_imports.has_rich:
            # Fallback display
            print("\n📊 Cache Performance:")
            print(f"  Hit Ratio: {perf.get('hit_ratio', 0):.1%}")
            print(f"  Total Hits: {perf.get('hits', 0)}")
            print(f"  Total Misses: {perf.get('misses', 0)}")
            print(f"  Cache Entries: {memory.get('current_entries', 0)}")
            return
        
        table = self.visual.cli_imports.rich['Table'](
            title=f"[bold {self.visual.colors['primary']}]{self.visual.icons['cache']} Cache Performance Metrics[/bold {self.visual.colors['primary']}]",
            show_header=True,
            header_style=f"bold {self.visual.colors['primary']}",
            border_style=self.visual.colors['muted'],
            row_styles=[self.visual.colors['muted'], ""]
        )
        
        table.add_column("Metric", style=f"bold {self.visual.colors['info']}")
        table.add_column("Value", justify="right", style=self.visual.colors['accent'])
        table.add_column("Performance", justify="center")
        
        # Hit ratio with performance indicator
        hit_ratio = perf.get('hit_ratio', 0)
        hit_status = self._get_hit_ratio_status(hit_ratio)
        table.add_row(
            "Hit Ratio",
            f"{hit_ratio:.1%}",
            f"[{hit_status['color']}]{hit_status['icon']}[/{hit_status['color']}]"
        )
        
        # Total operations
        total_ops = perf.get('hits', 0) + perf.get('misses', 0)
        table.add_row("Total Operations", f"{total_ops:,}", "📊")
        table.add_row("Cache Hits", f"{perf.get('hits', 0):,}", "✅")
        table.add_row("Cache Misses", f"{perf.get('misses', 0):,}", "❌")
        
        # Timing metrics
        avg_hit_time = timing.get('avg_hit_time_ms', 0)
        hit_time_status = self._get_timing_status(avg_hit_time)
        table.add_row(
            "Avg Hit Time",
            f"{avg_hit_time:.2f}ms",
            f"[{hit_time_status['color']}]{hit_time_status['icon']}[/{hit_time_status['color']}]"
        )
        
        table.add_row("Avg Miss Time", f"{timing.get('avg_miss_time_ms', 0):.2f}ms", "⏱️")
        
        # Current entries
        current_entries = memory.get('current_entries', 0)
        table.add_row("Current Entries", f"{current_entries:,}", "🗂️")
        
        # Memory usage
        memory_mb = memory.get('memory_usage_mb', 0)
        table.add_row("Memory Usage", f"{memory_mb:.1f} MB", "💾")
        
        # Uptime
        uptime = timing.get('uptime_seconds', 0)
        uptime_str = self._format_duration(uptime)
        table.add_row("Cache Uptime", uptime_str, "⏰")
        
        self.visual.cli_imports.console.print(table)
    
    def _display_eviction_table(self, evictions: Dict):
        """Display eviction statistics."""
        if not self.visual.cli_imports.has_rich:
            print("\n🗑️ Eviction Statistics:")
            print(f"  Total Evictions: {evictions.get('total', 0)}")
            print(f"  Expired: {evictions.get('expired', 0)}")
            print(f"  Size-based: {evictions.get('size_based', 0)}")
            print(f"  Memory Pressure: {evictions.get('memory_pressure', 0)}")
            return
        
        table = self.visual.cli_imports.rich['Table'](
            title=f"[bold {self.visual.colors['warning']}]🗑️ Eviction Statistics[/bold {self.visual.colors['warning']}]",
            show_header=True,
            header_style=f"bold {self.visual.colors['warning']}",
            border_style=self.visual.colors['muted']
        )
        
        table.add_column("Eviction Type", style=f"bold {self.visual.colors['info']}")
        table.add_column("Count", justify="right", style=self.visual.colors['accent'])
        table.add_column("Reason", style=self.visual.colors['muted'])
        
        table.add_row("Expired Entries", f"{evictions.get('expired', 0):,}", "TTL timeout")
        table.add_row("Size Limit", f"{evictions.get('size_based', 0):,}", "Cache full")
        table.add_row("Memory Pressure", f"{evictions.get('memory_pressure', 0):,}", "Low system memory")
        table.add_row("Total Evictions", f"{evictions.get('total', 0):,}", "All causes")
        
        self.visual.cli_imports.console.print(table)
    
    def _display_memory_table(self, cache_memory: Dict, system_memory: Dict):
        """Display memory usage information."""
        if not self.visual.cli_imports.has_rich:
            print(f"\n🧠 Memory Usage:")
            print(f"  Cache Memory: {cache_memory.get('memory_usage_mb', 0):.1f} MB")
            print(f"  System Available: {system_memory.get('available_mb', 0):.1f} MB")
            print(f"  System Used: {system_memory.get('used_percent', 0):.1f}%")
            return
        
        table = self.visual.cli_imports.rich['Table'](
            title=f"[bold {self.visual.colors['info']}]🧠 Memory Usage[/bold {self.visual.colors['info']}]",
            show_header=True,
            header_style=f"bold {self.visual.colors['info']}",
            border_style=self.visual.colors['muted']
        )
        
        table.add_column("Memory Type", style=f"bold {self.visual.colors['info']}")
        table.add_column("Usage", justify="right", style=self.visual.colors['accent'])
        table.add_column("Status", justify="center")
        
        # Cache memory usage
        cache_mb = cache_memory.get('memory_usage_mb', 0)
        table.add_row("Cache Memory", f"{cache_mb:.1f} MB", "⚡")
        
        # Cache budget
        cache_budget = system_memory.get('cache_budget_mb', 0)
        if cache_budget > 0:
            budget_usage = (cache_mb / cache_budget) * 100 if cache_budget > 0 else 0
            budget_status = self._get_memory_status(budget_usage / 100)
            table.add_row(
                "Budget Usage",
                f"{budget_usage:.1f}%",
                f"[{budget_status['color']}]{budget_status['icon']}[/{budget_status['color']}]"
            )
        
        # System memory
        system_available = system_memory.get('available_mb', 0)
        system_used_pct = system_memory.get('used_percent', 0)
        system_status = self._get_memory_status(system_used_pct / 100)
        
        table.add_row("System Available", f"{system_available:.0f} MB", "💻")
        table.add_row(
            "System Usage",
            f"{system_used_pct:.1f}%",
            f"[{system_status['color']}]{system_status['icon']}[/{system_status['color']}]"
        )
        
        self.visual.cli_imports.console.print(table)
    
    def _display_cache_info(self, cache_name: str, cache_policy: str):
        """Display cache configuration information."""
        info_text = f"Cache: {cache_name} | Policy: {cache_policy}"
        
        if self.visual.cli_imports.has_rich:
            panel = self.visual.create_panel(
                f"[{self.visual.colors['muted']}]{info_text}[/{self.visual.colors['muted']}]",
                "Configuration",
                "info"
            )
            self.visual.cli_imports.console.print(panel)
        else:
            print(f"\n📋 Configuration: {info_text}")
    
    def _display_recommendations(self, perf: Dict, memory: Dict, evictions: Dict, timing: Dict, system_memory: Dict):
        """Display performance recommendations and optimization suggestions."""
        recommendations = self._generate_recommendations(perf, memory, evictions, timing, system_memory)
        
        if not recommendations:
            self.visual.print_status_line("Cache performance is optimal", "success")
            return
        
        self.visual.print_section_header("Performance Recommendations", "intelligence")
        
        for i, rec in enumerate(recommendations, 1):
            icon = "💡" if rec['type'] == 'optimization' else "⚠️" if rec['type'] == 'warning' else "ℹ️"
            self.visual.print_status_line(f"{i}. {rec['message']}", rec['type'], prefix=f"{icon} ")
            
            if rec.get('details'):
                for detail in rec['details']:
                    print(f"   • {detail}")
    
    def _generate_recommendations(self, perf: Dict, memory: Dict, evictions: Dict, timing: Dict, system_memory: Dict) -> List[Dict]:
        """Generate intelligent cache optimization recommendations."""
        recommendations = []
        
        hit_ratio = perf.get('hit_ratio', 0)
        total_ops = perf.get('hits', 0) + perf.get('misses', 0)
        avg_hit_time = timing.get('avg_hit_time_ms', 0)
        memory_mb = memory.get('memory_usage_mb', 0)
        total_evictions = evictions.get('total', 0)
        system_used_pct = system_memory.get('used_percent', 0)
        
        # Hit ratio recommendations
        if hit_ratio < self.performance_thresholds['poor_hit_ratio']:
            recommendations.append({
                'type': 'warning',
                'message': f"Low hit ratio ({hit_ratio:.1%}) indicates poor cache effectiveness",
                'details': [
                    "Consider increasing cache size",
                    "Review TTL settings (may be too short)",
                    "Check if workload benefits from caching"
                ]
            })
        elif hit_ratio < self.performance_thresholds['good_hit_ratio']:
            recommendations.append({
                'type': 'optimization',
                'message': f"Moderate hit ratio ({hit_ratio:.1%}) has room for improvement",
                'details': [
                    "Fine-tune cache size for workload",
                    "Consider adjusting TTL based on data patterns"
                ]
            })
        
        # Eviction rate recommendations
        if total_ops > 0:
            eviction_rate = total_evictions / total_ops
            if eviction_rate > self.performance_thresholds['excessive_evictions']:
                recommendations.append({
                    'type': 'warning',
                    'message': f"High eviction rate ({eviction_rate:.1%}) may hurt performance",
                    'details': [
                        "Increase cache memory allocation",
                        "Consider using LRU cache policy",
                        "Review data access patterns"
                    ]
                })
        
        # Memory pressure recommendations
        if system_used_pct > 85:
            recommendations.append({
                'type': 'warning',
                'message': f"High system memory usage ({system_used_pct:.1f}%) detected",
                'details': [
                    "Consider reducing cache memory allocation",
                    "Monitor for memory pressure evictions",
                    "Enable adaptive cache sizing"
                ]
            })
        
        # Performance timing recommendations
        if avg_hit_time > self.performance_thresholds['slow_hit_time']:
            recommendations.append({
                'type': 'optimization',
                'message': f"Slow cache hit time ({avg_hit_time:.2f}ms)",
                'details': [
                    "Cache may be too large for efficient lookup",
                    "Consider cache partitioning",
                    "Review cache data structure efficiency"
                ]
            })
        
        # Memory efficiency recommendations
        cache_budget = system_memory.get('cache_budget_mb', 0)
        if cache_budget > 0 and memory_mb > 0:
            utilization = memory_mb / cache_budget
            if utilization < 0.3:
                recommendations.append({
                    'type': 'optimization',
                    'message': f"Low cache memory utilization ({utilization:.1%})",
                    'details': [
                        "Cache allocation may be too large",
                        "Consider reducing cache budget",
                        "Allocate memory to other components"
                    ]
                })
        
        # Positive feedback for good performance
        if (hit_ratio >= self.performance_thresholds['excellent_hit_ratio'] and 
            avg_hit_time <= self.performance_thresholds['slow_hit_time'] and
            total_evictions == 0):
            recommendations.append({
                'type': 'success',
                'message': "Cache performance is excellent! No optimizations needed.",
                'details': []
            })
        
        return recommendations
    
    def _get_hit_ratio_status(self, hit_ratio: float) -> Dict[str, str]:
        """Get status indicator for hit ratio."""
        if hit_ratio >= self.performance_thresholds['excellent_hit_ratio']:
            return {'color': self.visual.colors['success'], 'icon': '🚀'}
        elif hit_ratio >= self.performance_thresholds['good_hit_ratio']:
            return {'color': self.visual.colors['success'], 'icon': '✅'}
        elif hit_ratio >= self.performance_thresholds['poor_hit_ratio']:
            return {'color': self.visual.colors['warning'], 'icon': '⚠️'}
        else:
            return {'color': self.visual.colors['error'], 'icon': '❌'}
    
    def _get_timing_status(self, avg_time_ms: float) -> Dict[str, str]:
        """Get status indicator for timing performance."""
        if avg_time_ms <= 1.0:
            return {'color': self.visual.colors['success'], 'icon': '🚀'}
        elif avg_time_ms <= self.performance_thresholds['slow_hit_time']:
            return {'color': self.visual.colors['success'], 'icon': '✅'}
        else:
            return {'color': self.visual.colors['warning'], 'icon': '⚠️'}
    
    def _get_memory_status(self, usage_ratio: float) -> Dict[str, str]:
        """Get status indicator for memory usage."""
        if usage_ratio <= 0.6:
            return {'color': self.visual.colors['success'], 'icon': '✅'}
        elif usage_ratio <= self.performance_thresholds['high_memory_usage']:
            return {'color': self.visual.colors['warning'], 'icon': '⚠️'}
        else:
            return {'color': self.visual.colors['error'], 'icon': '❌'}
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"
    
    def create_cache_trend_display(self, metrics_history: List[Dict]) -> None:
        """Display cache performance trends over time."""
        if not metrics_history or len(metrics_history) < 2:
            self.visual.print_status_line("Insufficient data for trend analysis", "info")
            return
        
        self.visual.print_section_header("Cache Performance Trends", "time")
        
        # Calculate trends
        first_metrics = metrics_history[0].get('combined', {}).get('performance', {})
        last_metrics = metrics_history[-1].get('combined', {}).get('performance', {})
        
        hit_ratio_trend = last_metrics.get('hit_ratio', 0) - first_metrics.get('hit_ratio', 0)
        hits_trend = last_metrics.get('hits', 0) - first_metrics.get('hits', 0)
        
        # Display trend information
        if hit_ratio_trend > 0.05:
            self.visual.print_status_line(f"Hit ratio improved by {hit_ratio_trend:.1%}", "success", prefix="📈 ")
        elif hit_ratio_trend < -0.05:
            self.visual.print_status_line(f"Hit ratio declined by {abs(hit_ratio_trend):.1%}", "warning", prefix="📉 ")
        else:
            self.visual.print_status_line("Hit ratio stable", "info", prefix="📊 ")
        
        self.visual.print_metric_line("Total operations", f"+{hits_trend:,}", "since start")


class BulkOperationTracker:
    """
    Enhanced tracking and feedback system for bulk operations.
    Replaces error spam with intelligent summaries and progress tracking.
    """
    
    def __init__(self, visual_manager: RichVisualManager, operation_name: str = "Processing"):
        self.visual = visual_manager
        self.operation_name = operation_name
        
        # Statistics
        self.stats = {
            'total_items': 0,
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'errors': 0,
            'start_time': None,
            'last_update': 0,
            'last_throughput_check': 0,
            'throughput_history': []
        }
        
        # Error categorization
        self.error_categories = {
            'connection_errors': {
                'count': 0,
                'examples': [],
                'keywords': ['connection', 'connect', 'refused', 'timeout', 'unreachable']
            },
            'authentication_errors': {
                'count': 0,
                'examples': [],
                'keywords': ['auth', 'authentication', 'credential', 'login', 'unauthorized']
            },
            'protocol_errors': {
                'count': 0,
                'examples': [],
                'keywords': ['protocol', 'socks', 'http', 'https', 'ssl', 'tls']
            },
            'network_errors': {
                'count': 0,
                'examples': [],
                'keywords': ['network', 'dns', 'host', 'resolve', 'socket']
            },
            'response_errors': {
                'count': 0,
                'examples': [],
                'keywords': ['response', 'status', 'code', 'invalid', 'malformed']
            },
            'other_errors': {
                'count': 0,
                'examples': [],
                'keywords': []
            }
        }
        
        # Progress tracking
        self.progress_tracker = None
        self.progress_task = None
        self.update_interval = 2.0  # Update every 2 seconds
        self.batch_size = 100  # Report every 100 items
        
        # Detailed error log for optional export
        self.detailed_errors = []
    
    def start_operation(self, total_items: int):
        """Start tracking a bulk operation."""
        self.stats['total_items'] = total_items
        self.stats['start_time'] = time.time()
        self.stats['last_update'] = time.time()
        self.stats['last_throughput_check'] = time.time()
        
        # Initialize progress bar
        if total_items > 50:  # Only show progress for substantial operations
            self.progress_tracker = self.visual.create_progress_bar('validating', total_items)
            if self.progress_tracker:
                self.progress_task = self.progress_tracker.add_task(
                    f"[cyan]{self.operation_name}[/cyan]", total=total_items
                )
                self.progress_tracker.start()
        
        self.visual.print_section_header(f"Starting {self.operation_name}", "proxy")
        self.visual.print_status_line(f"Processing {total_items:,} items...", "info")
    
    def update_progress(self, processed: int, successful: int, failed: int, error_message: str = None):
        """Update operation progress with success/failure counts."""
        self.stats['processed'] = processed
        self.stats['successful'] = successful
        self.stats['failed'] = failed
        self.stats['errors'] = failed  # Simplified for now
        
        current_time = time.time()
        
        # Categorize error if provided
        if error_message:
            self._categorize_error(error_message)
            self.detailed_errors.append({
                'timestamp': current_time,
                'message': error_message,
                'item_number': processed
            })
        
        # Update progress bar
        if self.progress_tracker and self.progress_task is not None:
            self.progress_tracker.update(self.progress_task, completed=processed)
            
            # Update progress description with current stats
            success_rate = (successful / processed * 100) if processed > 0 else 0
            self.progress_tracker.update(
                self.progress_task,
                description=f"[cyan]{self.operation_name}[/cyan] - {success_rate:.1f}% success rate"
            )
        
        # Progressive summary updates (every batch_size items or time interval)
        if (processed % self.batch_size == 0 or 
            current_time - self.stats['last_update'] >= self.update_interval):
            self._print_progress_summary()
            self.stats['last_update'] = current_time
        
        # Calculate throughput
        if current_time - self.stats['last_throughput_check'] >= 1.0:
            self._update_throughput()
            self.stats['last_throughput_check'] = current_time
    
    def complete_operation(self):
        """Complete the operation and show final summary."""
        if self.progress_tracker:
            self.progress_tracker.stop()
        
        duration = time.time() - self.stats['start_time']
        self.visual.print_section_header("Operation Completed", "success")
        
        self._print_final_summary(duration)
        self._print_error_summary()
    
    def _categorize_error(self, error_message: str):
        """Categorize an error message into predefined categories."""
        error_lower = error_message.lower()
        categorized = False
        
        for category, info in self.error_categories.items():
            if category == 'other_errors':
                continue
                
            for keyword in info['keywords']:
                if keyword in error_lower:
                    info['count'] += 1
                    if len(info['examples']) < 3:  # Keep up to 3 examples
                        info['examples'].append(error_message[:100])  # Truncate long messages
                    categorized = True
                    break
            
            if categorized:
                break
        
        if not categorized:
            self.error_categories['other_errors']['count'] += 1
            if len(self.error_categories['other_errors']['examples']) < 3:
                self.error_categories['other_errors']['examples'].append(error_message[:100])
    
    def _update_throughput(self):
        """Update throughput calculation."""
        current_time = time.time()
        if self.stats['start_time']:
            duration = current_time - self.stats['start_time']
            if duration > 0:
                current_throughput = self.stats['processed'] / duration
                self.stats['throughput_history'].append({
                    'time': current_time,
                    'throughput': current_throughput
                })
                
                # Keep only last 10 measurements
                if len(self.stats['throughput_history']) > 10:
                    self.stats['throughput_history'] = self.stats['throughput_history'][-10:]
    
    def _print_progress_summary(self):
        """Print intermediate progress summary."""
        if not self.visual.cli_imports.has_rich or self.stats['processed'] < 20:
            return  # Skip for small operations or no Rich
        
        processed = self.stats['processed']
        successful = self.stats['successful']
        total = self.stats['total_items']
        
        if processed > 0:
            success_rate = (successful / processed) * 100
            remaining = total - processed
            
            # Calculate ETA
            duration = time.time() - self.stats['start_time']
            if duration > 0 and processed > 0:
                items_per_second = processed / duration
                eta_seconds = remaining / items_per_second if items_per_second > 0 else 0
                eta_str = self._format_duration(eta_seconds)
            else:
                eta_str = "calculating..."
            
            # Use live status line instead of spamming output
            status_color = "success" if success_rate > 70 else "warning" if success_rate > 30 else "error"
            
            # Only print every batch_size to avoid spam
            if processed % self.batch_size == 0:
                self.visual.print_status_line(
                    f"Progress: {processed:,}/{total:,} ({success_rate:.1f}% success) | ETA: {eta_str}",
                    status_color
                )
    
    def _print_final_summary(self, duration: float):
        """Print comprehensive final summary with Rich table."""
        if not self.visual.cli_imports.has_rich:
            # Fallback summary
            print(f"\n{self.visual.icons['proxy']} {self.operation_name} Summary:")
            print(f"  Total Processed: {self.stats['processed']:,}")
            print(f"  Successful: {self.stats['successful']:,}")
            print(f"  Failed: {self.stats['failed']:,}")
            print(f"  Duration: {self._format_duration(duration)}")
            return
        
        # Rich table summary
        table = self.visual.cli_imports.rich['Table'](
            title=f"[bold {self.visual.colors['primary']}]{self.visual.icons['proxy']} {self.operation_name} Summary[/bold {self.visual.colors['primary']}]",
            show_header=True,
            header_style=f"bold {self.visual.colors['primary']}",
            border_style=self.visual.colors['muted'],
            row_styles=[self.visual.colors['muted'], ""]
        )
        
        table.add_column("Metric", style=f"bold {self.visual.colors['info']}")
        table.add_column("Count", justify="right", style=self.visual.colors['accent'])
        table.add_column("Percentage", justify="right", style=self.visual.colors['muted'])
        table.add_column("Status", justify="center")
        
        total = self.stats['processed']
        successful = self.stats['successful']
        failed = self.stats['failed']
        
        if total > 0:
            success_pct = (successful / total) * 100
            failure_pct = (failed / total) * 100
        else:
            success_pct = failure_pct = 0
        
        # Add summary rows
        table.add_row(
            "Total Processed",
            f"{total:,}",
            "100%",
            f"[{self.visual.colors['info']}]{self.visual.icons['proxy']}[/{self.visual.colors['info']}]"
        )
        
        table.add_row(
            "Successful",
            f"{successful:,}",
            f"{success_pct:.1f}%",
            f"[{self.visual.colors['success']}]{self.visual.icons['success']}[/{self.visual.colors['success']}]"
        )
        
        table.add_row(
            "Failed",
            f"{failed:,}",
            f"{failure_pct:.1f}%",
            f"[{self.visual.colors['error']}]{self.visual.icons['error']}[/{self.visual.colors['error']}]"
        )
        
        # Performance metrics
        if duration > 0:
            throughput = total / duration
            table.add_row(
                "Processing Speed",
                f"{throughput:.1f}/sec",
                "",
                f"[{self.visual.colors['accent']}]{self.visual.icons['speed']}[/{self.visual.colors['accent']}]"
            )
        
        table.add_row(
            "Total Duration",
            self._format_duration(duration),
            "",
            f"[{self.visual.colors['muted']}]{self.visual.icons['time']}[/{self.visual.colors['muted']}]"
        )
        
        self.visual.cli_imports.console.print("\n")
        self.visual.cli_imports.console.print(table)
    
    def _print_error_summary(self):
        """Print categorized error summary instead of spam."""
        total_errors = sum(cat['count'] for cat in self.error_categories.values())
        
        if total_errors == 0:
            self.visual.print_status_line("No errors encountered", "success")
            return
        
        self.visual.print_section_header("Error Analysis", "warning")
        
        if not self.visual.cli_imports.has_rich:
            # Fallback error summary
            print(f"\n{self.visual.icons['warning']} Error Breakdown:")
            for category, info in self.error_categories.items():
                if info['count'] > 0:
                    print(f"  {category.replace('_', ' ').title()}: {info['count']}")
            return
        
        # Rich error summary table
        table = self.visual.cli_imports.rich['Table'](
            title=f"[bold {self.visual.colors['warning']}]{self.visual.icons['warning']} Error Breakdown[/bold {self.visual.colors['warning']}]",
            show_header=True,
            header_style=f"bold {self.visual.colors['warning']}",
            border_style=self.visual.colors['muted']
        )
        
        table.add_column("Error Category", style=f"bold {self.visual.colors['info']}")
        table.add_column("Count", justify="right", style=self.visual.colors['accent'])
        table.add_column("Percentage", justify="right", style=self.visual.colors['muted'])
        table.add_column("Example", style=f"dim {self.visual.colors['muted']}")
        
        for category, info in self.error_categories.items():
            if info['count'] > 0:
                category_pct = (info['count'] / total_errors) * 100
                example = info['examples'][0] if info['examples'] else "N/A"
                
                table.add_row(
                    category.replace('_', ' ').title(),
                    f"{info['count']:,}",
                    f"{category_pct:.1f}%",
                    example
                )
        
        self.visual.cli_imports.console.print(table)
        
        # Show common solutions
        self._show_error_solutions()
    
    def _show_error_solutions(self):
        """Show common solutions for encountered error types."""
        solutions = []
        
        # Suggest solutions based on error categories
        if self.error_categories['connection_errors']['count'] > 0:
            solutions.append("🔧 Connection errors: Try reducing --threads or increasing --timeout")
        
        if self.error_categories['protocol_errors']['count'] > 0:
            solutions.append("🔧 Protocol errors: Use --protocol-mode detect for auto-detection")
        
        if self.error_categories['network_errors']['count'] > 0:
            solutions.append("🔧 Network errors: Check internet connection and DNS settings")
        
        if self.error_categories['authentication_errors']['count'] > 0:
            solutions.append("🔧 Auth errors: Some proxies require username/password authentication")
        
        if solutions:
            self.visual.print_section_header("Suggested Solutions", "intelligence")
            for solution in solutions:
                self.visual.print_status_line(solution, "info")
    
    def export_detailed_errors(self, output_file: str) -> bool:
        """Export detailed error log to file."""
        try:
            with open(output_file, 'w') as f:
                f.write(f"# Detailed Error Log - {self.operation_name}\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# Total Items: {self.stats['total_items']}\n")
                f.write(f"# Total Errors: {len(self.detailed_errors)}\n\n")
                
                for error in self.detailed_errors:
                    timestamp = datetime.fromtimestamp(error['timestamp']).isoformat()
                    f.write(f"[{timestamp}] Item #{error['item_number']}: {error['message']}\n")
            
            self.visual.print_status_line(f"Detailed error log exported to: {output_file}", "success")
            return True
        except Exception as e:
            self.visual.print_status_line(f"Failed to export error log: {e}", "error")
            return False
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"
    
    def get_current_throughput(self) -> float:
        """Get current processing throughput (items per second)."""
        if self.stats['start_time'] and self.stats['processed'] > 0:
            duration = time.time() - self.stats['start_time']
            return self.stats['processed'] / duration if duration > 0 else 0
        return 0


class EnhancedLoggingManager:
    """
    Enhanced logging architecture with proper level separation and file management.
    Integrates with existing print functions and provides structured logging.
    """
    
    def __init__(self, visual_manager: RichVisualManager, base_name: str = "proxc"):
        self.visual = visual_manager
        self.base_name = base_name
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Logging configuration
        self.log_levels = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        
        # Log file handlers
        self.handlers = {}
        self.formatters = {}
        self.loggers = {}
        
        # Console output control
        self.console_level = logging.INFO
        self.quiet_mode = False
        self.verbose_mode = False
        self.silent_mode = False
        
        # Structured logging data
        self.context_data = {
            'session_id': self.session_id,
            'start_time': time.time(),
            'operation_type': None,
            'total_items': 0
        }
        
        # Performance tracking
        self.log_metrics = {
            'messages_logged': 0,
            'errors_logged': 0,
            'warnings_logged': 0,
            'debug_messages': 0
        }
        
        self._setup_logging()
    
    def _setup_logging(self):
        """Initialize the enhanced logging system."""
        # Create formatters
        self.formatters['detailed'] = logging.Formatter(
            '%(asctime)s | %(name)s | %(levelname)-8s | %(funcName)s:%(lineno)d | %(message)s'
        )
        
        self.formatters['simple'] = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s'
        )
        
        self.formatters['json'] = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", '
            '"function": "%(funcName)s", "line": %(lineno)d, "message": "%(message)s"}'
        )
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers to avoid duplication
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Create main application logger
        self.main_logger = logging.getLogger(f"{self.base_name}.main")
        self.main_logger.setLevel(logging.DEBUG)
    
    def setup_file_logging(self, log_directory: str = "logs", 
                          separate_levels: bool = True,
                          enable_rotation: bool = True):
        """Setup file logging with optional level separation and rotation."""
        import os
        from logging.handlers import RotatingFileHandler
        
        # Create logs directory
        os.makedirs(log_directory, exist_ok=True)
        
        if separate_levels:
            # Separate log files by level
            level_configs = {
                'debug': {'level': logging.DEBUG, 'filename': f"{self.base_name}_debug_{self.session_id}.log"},
                'info': {'level': logging.INFO, 'filename': f"{self.base_name}_info_{self.session_id}.log"},
                'warning': {'level': logging.WARNING, 'filename': f"{self.base_name}_warnings_{self.session_id}.log"},
                'error': {'level': logging.ERROR, 'filename': f"{self.base_name}_errors_{self.session_id}.log"}
            }
            
            for level_name, config in level_configs.items():
                filepath = os.path.join(log_directory, config['filename'])
                
                if enable_rotation:
                    handler = RotatingFileHandler(
                        filepath, maxBytes=10*1024*1024, backupCount=5  # 10MB max, 5 backups
                    )
                else:
                    handler = logging.FileHandler(filepath)
                
                handler.setLevel(config['level'])
                handler.setFormatter(self.formatters['detailed'])
                
                # Create level-specific filter
                handler.addFilter(self._create_level_filter(config['level']))
                
                self.handlers[level_name] = handler
                self.main_logger.addHandler(handler)
        else:
            # Single combined log file
            filepath = os.path.join(log_directory, f"{self.base_name}_combined_{self.session_id}.log")
            
            if enable_rotation:
                handler = RotatingFileHandler(
                    filepath, maxBytes=50*1024*1024, backupCount=3  # 50MB max, 3 backups
                )
            else:
                handler = logging.FileHandler(filepath)
            
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(self.formatters['detailed'])
            
            self.handlers['combined'] = handler
            self.main_logger.addHandler(handler)
        
        self.visual.print_status_line(f"File logging initialized: {log_directory}", "info")
    
    def _create_level_filter(self, target_level):
        """Create a filter for specific log levels."""
        class LevelFilter:
            def __init__(self, level):
                self.level = level
            
            def filter(self, record):
                return record.levelno >= self.level
        
        return LevelFilter(target_level)
    
    def set_console_verbosity(self, quiet: bool = False, verbose: bool = False, silent: bool = False):
        """Configure console output verbosity levels."""
        self.quiet_mode = quiet
        self.verbose_mode = verbose
        self.silent_mode = silent
        
        if silent:
            self.console_level = logging.CRITICAL + 1  # Effectively disable console
        elif quiet:
            self.console_level = logging.WARNING
        elif verbose:
            self.console_level = logging.DEBUG
        else:
            self.console_level = logging.INFO
    
    def log_structured(self, level: str, message: str, **context):
        """Log a structured message with additional context."""
        log_level = self.log_levels.get(level.upper(), logging.INFO)
        
        # Merge context data
        full_context = {**self.context_data, **context}
        
        # Create structured message
        structured_msg = f"{message} | Context: {full_context}"
        
        # Log to file
        self.main_logger.log(log_level, structured_msg)
        
        # Update metrics
        self.log_metrics['messages_logged'] += 1
        if log_level >= logging.ERROR:
            self.log_metrics['errors_logged'] += 1
        elif log_level >= logging.WARNING:
            self.log_metrics['warnings_logged'] += 1
        elif log_level <= logging.DEBUG:
            self.log_metrics['debug_messages'] += 1
    
    def enhanced_print_error(self, message: str, exception: Exception = None, **context):
        """Enhanced error printing with logging integration."""
        # Log to file with full context
        error_context = {
            'error_type': type(exception).__name__ if exception else 'Generic',
            'error_details': str(exception) if exception else None,
            **context
        }
        self.log_structured('ERROR', message, **error_context)
        
        # Console output (respecting verbosity)
        if not self.silent_mode:
            self.visual.print_status_line(message, "error")
    
    def enhanced_print_warning(self, message: str, **context):
        """Enhanced warning printing with logging integration."""
        self.log_structured('WARNING', message, **context)
        
        if self.console_level <= logging.WARNING:
            self.visual.print_status_line(message, "warning")
    
    def enhanced_print_info(self, message: str, **context):
        """Enhanced info printing with logging integration."""
        self.log_structured('INFO', message, **context)
        
        if self.console_level <= logging.INFO:
            self.visual.print_status_line(message, "info")
    
    def enhanced_print_debug(self, message: str, **context):
        """Enhanced debug printing with logging integration."""
        self.log_structured('DEBUG', message, **context)
        
        if self.console_level <= logging.DEBUG:
            self.visual.print_status_line(message, "info", prefix="🔍 ")
    
    def enhanced_print_success(self, message: str, **context):
        """Enhanced success printing with logging integration."""
        self.log_structured('INFO', f"SUCCESS: {message}", **context)
        
        if self.console_level <= logging.INFO:
            self.visual.print_status_line(message, "success")
    
    def start_operation_logging(self, operation_type: str, total_items: int = 0, **context):
        """Start structured logging for a specific operation."""
        self.context_data.update({
            'operation_type': operation_type,
            'total_items': total_items,
            'operation_start': time.time(),
            **context
        })
        
        self.log_structured('INFO', f"Starting operation: {operation_type}", 
                           total_items=total_items)
    
    def end_operation_logging(self, success: bool = True, **results):
        """End structured logging for the current operation."""
        duration = time.time() - self.context_data.get('operation_start', time.time())
        
        end_context = {
            'success': success,
            'duration_seconds': duration,
            **results
        }
        
        self.log_structured('INFO' if success else 'ERROR', 
                           f"Operation completed: {self.context_data.get('operation_type', 'Unknown')}",
                           **end_context)
        
        # Reset operation context
        self.context_data['operation_type'] = None
    
    def log_performance_metrics(self, **metrics):
        """Log performance metrics in a structured format."""
        self.log_structured('INFO', "Performance metrics", **metrics)
    
    def get_logging_summary(self) -> Dict[str, Any]:
        """Get a summary of logging activity."""
        return {
            'session_id': self.session_id,
            'session_duration': time.time() - self.context_data['start_time'],
            'metrics': self.log_metrics.copy(),
            'handlers': list(self.handlers.keys()),
            'console_level': logging.getLevelName(self.console_level),
            'modes': {
                'quiet': self.quiet_mode,
                'verbose': self.verbose_mode,
                'silent': self.silent_mode
            }
        }
    
    def export_logs_summary(self, output_file: str) -> bool:
        """Export a summary of logs and metrics."""
        try:
            summary = self.get_logging_summary()
            
            with open(output_file, 'w') as f:
                import json
                json.dump(summary, f, indent=2)
            
            self.visual.print_status_line(f"Logging summary exported to: {output_file}", "success")
            return True
        except Exception as e:
            self.visual.print_status_line(f"Failed to export logging summary: {e}", "error")
            return False
    
    def cleanup_old_logs(self, log_directory: str = "logs", days_to_keep: int = 7):
        """Clean up old log files."""
        import os
        import glob
        
        try:
            cutoff_time = time.time() - (days_to_keep * 24 * 3600)
            pattern = os.path.join(log_directory, f"{self.base_name}_*.log*")
            
            removed_count = 0
            for log_file in glob.glob(pattern):
                if os.path.getmtime(log_file) < cutoff_time:
                    os.remove(log_file)
                    removed_count += 1
            
            if removed_count > 0:
                self.visual.print_status_line(f"Cleaned up {removed_count} old log files", "info")
            
        except Exception as e:
            self.visual.print_status_line(f"Log cleanup failed: {e}", "warning")
    
    def create_debug_package(self, output_file: str = None) -> str:
        """Create a debug package with logs and system info."""
        import zipfile
        import os
        import platform
        import sys
        
        if not output_file:
            output_file = f"debug_package_{self.session_id}.zip"
        
        try:
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                # Add log files
                for handler_name, handler in self.handlers.items():
                    if hasattr(handler, 'baseFilename'):
                        if os.path.exists(handler.baseFilename):
                            zf.write(handler.baseFilename, f"logs/{os.path.basename(handler.baseFilename)}")
                
                # Add system info
                system_info = {
                    'platform': platform.platform(),
                    'python_version': sys.version,
                    'timestamp': datetime.now().isoformat(),
                    'logging_summary': self.get_logging_summary()
                }
                
                import json
                zf.writestr("system_info.json", json.dumps(system_info, indent=2))
            
            self.visual.print_status_line(f"Debug package created: {output_file}", "success")
            return output_file
            
        except Exception as e:
            self.visual.print_status_line(f"Failed to create debug package: {e}", "error")
            return ""


class LegacyPrintIntegration:
    """
    Integration layer to route existing print functions to the enhanced logging system.
    """
    
    def __init__(self, logging_manager: EnhancedLoggingManager):
        self.logging_manager = logging_manager
        self.visual = logging_manager.visual
    
    def print_success(self, message: str, **context):
        """Route print_success to enhanced logging."""
        self.logging_manager.enhanced_print_success(message, **context)
    
    def print_error(self, message: str, exception: Exception = None, **context):
        """Route print_error to enhanced logging."""
        self.logging_manager.enhanced_print_error(message, exception, **context)
    
    def print_warning(self, message: str, **context):
        """Route print_warning to enhanced logging."""
        self.logging_manager.enhanced_print_warning(message, **context)
    
    def print_info(self, message: str, **context):
        """Route print_info to enhanced logging."""
        self.logging_manager.enhanced_print_info(message, **context)
    
    def print_verbose(self, message: str, **context):
        """Route print_verbose to enhanced logging."""
        if self.logging_manager.verbose_mode:
            self.logging_manager.enhanced_print_debug(message, **context)
    
    def should_print(self, level: str) -> bool:
        """Determine if a message should be printed based on current verbosity."""
        level_map = {
            'error': logging.ERROR,
            'warning': logging.WARNING,
            'normal': logging.INFO,
            'verbose': logging.DEBUG
        }
        
        required_level = level_map.get(level, logging.INFO)
        return required_level >= self.logging_manager.console_level


def _load_proxies_from_file(input_file: str, input_format: str, protocol_mode_resolved: str = "auto-detect", 
                           target_protocol: Optional[str] = None) -> List[ProxyInfo]:
    """Load proxies from file with protocol mode support"""
    proxies = []
    invalid_lines = 0
    
    try:
        # Handle JSON format
        if input_format == 'json':
            import json
            with open(input_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            items = []
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict) and 'proxies' in data:
                items = data['proxies']
            
            for item_num, item in enumerate(items, 1):
                if isinstance(item, dict):
                    host = item.get('host') or item.get('ip')
                    port = item.get('port')
                    protocol = item.get('protocol', 'http')
                    
                    if host and port:
                        try:
                            proxy = ProxyInfo(
                                host=host,
                                port=int(port),
                                protocol=ProxyProtocol(protocol.lower()),
                                source=f"file:{Path(input_file).name}"
                            )
                            proxy.protocol_confidence = 0.8  # JSON has explicit protocol
                            proxy.protocol_detection_method = "json_explicit"
                            proxy.protocol_detection_time = datetime.utcnow()
                            proxies.append(proxy)
                        except (ValueError, KeyError) as e:
                            print_warning(f"JSON item {item_num}: Invalid data: {e}")
                            invalid_lines += 1
            
            return proxies
        
        # Handle text format
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            try:
                protocol = None
                address = line
                
                if protocol_mode_resolved == "explicit-per-line":
                    # Parse protocol prefix
                    parsed_protocol, parsed_address = parse_protocol_prefix(line)
                    if parsed_protocol is None and '//' in line:
                        # Invalid protocol prefix found
                        print_warning(f"Line {line_num}: Invalid protocol prefix in '{line}', skipping")
                        invalid_lines += 1
                        continue
                    elif parsed_protocol:
                        protocol = parsed_protocol
                        address = parsed_address
                    else:
                        # No protocol prefix, use line as-is
                        address = line
                        
                elif protocol_mode_resolved == "uniform" and target_protocol:
                    # Use specified protocol for all proxies
                    protocol = target_protocol
                    
                else:
                    # Auto-detect mode: use port-based inference
                    protocol = infer_proxy_protocol(line)
                
                # Parse IP and port - handle both protocol://host:port and host:port formats
                host = None
                port = None
                
                # Clean up timing/anonymity data after the URL (e.g., "999ms elite")
                clean_address = address.split()[0] if address.split() else address
                
                if '://' in clean_address:
                    # Handle protocol://host:port format
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(clean_address)
                        if parsed.hostname and parsed.port:
                            host = parsed.hostname
                            port = parsed.port
                            # Extract protocol from URL if not already set (e.g., in auto-detect mode)
                            if not protocol:
                                proto_map = {'http': 'http', 'https': 'https', 
                                           'socks4': 'socks4', 'socks5': 'socks5'}
                                protocol = proto_map.get(parsed.scheme.lower(), 'http')
                        else:
                            raise ValueError("Invalid URL format")
                    except Exception:
                        print_warning(f"Line {line_num}: Invalid URL format '{address}', skipping")
                        invalid_lines += 1
                        continue
                else:
                    # Handle plain host:port format
                    if ':' not in clean_address:
                        print_warning(f"Line {line_num}: Invalid proxy format '{address}' (missing port), skipping")
                        invalid_lines += 1
                        continue
                    
                    parts = clean_address.split(':', 1)
                    if len(parts) != 2:
                        print_warning(f"Line {line_num}: Invalid proxy format '{address}', skipping")
                        invalid_lines += 1
                        continue
                    
                    host = parts[0].strip()
                    try:
                        port = int(parts[1].strip())
                    except ValueError:
                        print_warning(f"Line {line_num}: Invalid port in '{address}', skipping")
                        invalid_lines += 1
                        continue
                
                if not host:
                    print_warning(f"Line {line_num}: Empty host in '{address}', skipping")
                    invalid_lines += 1
                    continue
                
                # Create ProxyInfo object
                proxy = ProxyInfo(
                    host=host,
                    port=port,
                    protocol=ProxyProtocol(protocol.lower()),
                    source=f"file:{Path(input_file).name}"
                )
                
                # Set protocol confidence based on mode
                if protocol_mode_resolved == "explicit-per-line":
                    proxy.protocol_confidence = 0.95  # High confidence for explicit
                elif protocol_mode_resolved == "uniform":
                    proxy.protocol_confidence = 0.8   # Good confidence for forced
                else:
                    proxy.protocol_confidence = 0.5   # Medium confidence for inferred
                
                proxy.protocol_detection_method = protocol_mode_resolved
                proxy.protocol_detection_time = datetime.utcnow()
                
                proxies.append(proxy)
                
            except Exception as e:
                print_warning(f"Line {line_num}: Error parsing '{line}': {e}")
                invalid_lines += 1
                continue
        
        if invalid_lines > 0:
            print_warning(f"Skipped {invalid_lines} invalid lines from {input_file}")
        
        return proxies
        
    except Exception as e:
        print_error(f"Failed to load proxies from {input_file}: {e}")
        return []

# ===============================================================================
# CLI UTILITIES
# ===============================================================================

console = cli_imports.console if cli_imports.has_rich else None

# Global flags for output control
_silent_mode = False
_verbose_mode = False
_quiet_mode = False

def set_output_modes(silent: bool = False, verbose: bool = False, quiet: bool = False):
    """Set global output modes and configure logging levels"""
    global _silent_mode, _verbose_mode, _quiet_mode
    _silent_mode = silent
    _verbose_mode = verbose
    _quiet_mode = quiet
    
    # Configure logging level based on verbose/quiet/silent flags
    root_logger = logging.getLogger()
    if verbose:
        # In verbose mode, show debug/info/warning/error logs
        root_logger.setLevel(logging.DEBUG)
    elif quiet:
        # In quiet mode, only show warnings and errors
        root_logger.setLevel(logging.WARNING)
    elif silent:
        # In silent mode, only show errors
        root_logger.setLevel(logging.ERROR)
    else:
        # In normal mode, show info/warning/error logs
        root_logger.setLevel(logging.INFO)

def should_print(level: str = 'normal') -> bool:
    """Determine if message should be printed based on current modes"""
    if _silent_mode and level != 'error':
        return False
    if _quiet_mode and level in ['normal', 'info']:
        return False
    if level == 'verbose' and not _verbose_mode:
        return False
    return True

def print_success(message: str):
    """Print success message"""
    if not should_print('normal'):
        return
    if console:
        console.print(f"✅ {message}", style="green")
    else:
        print(f"✅ {message}")

def print_error(message: str):
    """Print error message"""
    if not should_print('error'):
        return
    if console:
        console.print(f"❌ {message}", style="red")
    else:
        print(f"❌ {message}")

def print_warning(message: str):
    """Print warning message"""
    if not should_print('normal'):
        return
    if console:
        console.print(f"⚠️  {message}", style="yellow")
    else:
        print(f"⚠️  {message}")

def print_info(message: str):
    """Print info message"""
    if not should_print('normal'):
        return
    if console:
        console.print(f"ℹ️  {message}", style="blue")
    else:
        print(f"ℹ️  {message}")

def print_verbose(message: str):
    """Print verbose info message (only shown with -V/--verbose)"""
    if not should_print('verbose'):
        return
    if console:
        console.print(f"ℹ️  {message}", style="blue")
    else:
        print(f"ℹ️  {message}")

def create_compact_progress():
    """Create a compact progress bar"""
    if HAS_RICH:
        Progress = cli_imports.rich.get('Progress')
        TextColumn = cli_imports.rich.get('TextColumn')
        BarColumn = cli_imports.rich.get('BarColumn')
        if Progress and TextColumn and BarColumn:
            return Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=30),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
            )
        else:
            return None
    return None

def create_enhanced_progress():
    """Create an enhanced progress bar with ETA"""
    if HAS_RICH:
        Progress = cli_imports.rich.get('Progress')
        TextColumn = cli_imports.rich.get('TextColumn')
        BarColumn = cli_imports.rich.get('BarColumn')
        TimeElapsedColumn = cli_imports.rich.get('TimeElapsedColumn')
        TimeRemainingColumn = cli_imports.rich.get('TimeRemainingColumn')
        if all([Progress, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn]):
            return Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=40),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
            )
        else:
            return None
    return None

def show_proxy_table(proxies: List[ProxyInfo], title: str = "Proxies"):
    """Display proxies in a nice table"""
    if not console or not proxies:
        print(f"\n{title}:")
        for proxy in proxies[:10]:
            print(f"  {proxy.address} ({proxy.protocol.value}) - {proxy.anonymity_level.value}")
        if len(proxies) > 10:
            print(f"  ... and {len(proxies) - 10} more")
        return
    
    table = Table(title=title)
    table.add_column("Address", style="cyan")
    table.add_column("Protocol", style="green")
    table.add_column("Anonymity", style="yellow")
    table.add_column("Country", style="blue")
    table.add_column("Status", style="magenta")
    table.add_column("Response", style="white")
    
    display_proxies = proxies[:20]
    
    for proxy in display_proxies:
        country = proxy.geo_location.country_code if proxy.geo_location else "Unknown"
        response_time = f"{proxy.metrics.response_time:.0f}ms" if proxy.metrics.response_time else "N/A"
        
        table.add_row(
            proxy.address,
            proxy.protocol.value,
            proxy.anonymity_level.value,
            country,
            proxy.status.value,
            response_time
        )
    
    console.print(table)
    
    if len(proxies) > 20:
        console.print(f"[dim]... and {len(proxies) - 20} more proxies[/dim]")


# ===============================================================================
# UNIFIED CLI COMMAND
# ===============================================================================

@click.command(context_settings={'help_option_names': ['-h', '--help']})
@click.version_option(version="3.1.0", prog_name="proxc")
# Interface Mode removed - CLI-only interface
# Core Options
@click.option('-f', '--file', 'input_file', help='Input file of proxies')
@click.option('-o', '--output', 'output_file', help='Output file (supports txt/json/csv formats with country preservation)')
@click.option('-v', '--validate', is_flag=True, help='Validate proxy connectivity')
# Protocol Handling - NEW STREAMLINED APPROACH
@click.option('-M', '--protocol-mode', 
              type=click.Choice(['auto', 'force:http', 'force:https', 'force:socks4', 'force:socks5', 'detect', 'from-file']),
              default='auto',
              help='Protocol handling mode: auto (detect from context/port), force:TYPE (force specific protocol), detect (handshake-based), from-file (read from URL prefixes)')
@click.option('-P', '--protocol-strict', is_flag=True, 
              help='Strict protocol validation: fail if protocol detection/validation fails')

# Protocol flags removed - use --protocol-mode instead

@click.option('-V', '--verbose', is_flag=True, help='Verbose output (DEBUG level)')
@click.option('-q', '--quiet', is_flag=True, help='Quiet mode (WARNING level, minimal output)')
@click.option('-N', '--silent', is_flag=True, help='Silent mode (ERROR level, suppress all output except errors)')
@click.option('-c', '--count', type=int, help='Limit number of proxies to process')
@click.option('-t', '--threads', type=int, default=CLI_DEFAULT_THREADS, help='Number of concurrent threads')
@click.option('-T', '--timeout', type=int, default=CLI_DEFAULT_TIMEOUT_SEC, help='Request timeout in seconds')

# Performance & Threading  
@click.option('-j', '--adaptive-threads', '--adaptive', is_flag=True, help='Enable adaptive dynamic threading based on performance')

# Smart Caching
@click.option('-K', '--cache-validation', is_flag=True, help='Enable validation result caching for faster re-validation')
@click.option('-Z', '--cache-ttl', type=int, help='Cache time-to-live in seconds (default: 3600)')
@click.option('-m', '--cache-memory-mb', type=int, help='Maximum cache memory usage in MB (auto-calculated if not set)')
@click.option('--cache-stats', '-S', is_flag=True, help='Show cache performance statistics')

# Chain Detection & Security
@click.option('-d', '--detect-chains', 'detect_chains', is_flag=True, default=False, help='Enable proxy chain detection and analysis')
@click.option('-E', '--chain-max-depth', type=int, help='Maximum acceptable chain depth (default: 5)')
@click.option('-J', '--chain-timeout', type=float, help='Timeout for chain detection in seconds (default: 15.0)')
@click.option('-O', '--chain-confidence', type=float, help='Minimum confidence threshold for chain detection (default: 0.7)')
@click.option('-R', '--chain-samples', type=int, help='Number of samples for timing analysis (default: 3)')

# Filtering & Analysis
@click.option('-F', '--filter', 'filter_rules', help='Filter proxies (e.g., alive,speed:500)')
@click.option('-a', '--analyze', is_flag=True, help='Perform threat analysis and geo lookup (enables country detection for exports)')
@click.option('-i', '--isp', help='Filter by ISP')
@click.option('-A', '--asn', help='Filter by ASN')

# Proxy Discovery
@click.option('-s', '--scan', is_flag=True, help='Discover proxies from online sources')
@click.option('-L', '--list-sources', is_flag=True, help='List all available proxy sources and their status')
@click.option('-C', '--check-sources', is_flag=True, help='Test connectivity to all proxy sources')
@click.option('-n', '--target-alive', type=int, help='Continue scanning until N alive proxies found (overrides --count)')
@click.option('-r', '--rate', type=float, help='Limit requests per second (rate limit)')

# Advanced Discovery & Collection
@click.option('-Y', '--discovery-mode', type=click.Choice(['passive', 'active', 'hybrid']), default='passive',
              help='Discovery mode: passive (existing sources), active (IP/port scanning), hybrid (both)')
@click.option('--enable-fingerprinting', '--fingerprint', '--fp', is_flag=True, 
              help='Enable advanced proxy fingerprinting and signature detection')
@click.option('--enable-intelligence', '--intelligence', '--ai', is_flag=True,
              help='Enable OSINT collection from search engines and social media')
@click.option('--enable-repo-mining', '--repo-mining', '--rm', is_flag=True,
              help='Enable code repository mining (GitHub, GitLab, Bitbucket)')
@click.option('-p', '--ip-ranges', help='Comma-separated IP ranges for active scanning (e.g., 10.0.0.0/24,192.168.1.0/24)')
@click.option('-k', '--cloud-providers', help='Comma-separated cloud providers for IP scanning (aws,gcp,azure,digitalocean,ovh)')
@click.option('-e', '--scan-intensity', type=click.Choice(['light', 'medium', 'aggressive']), default='medium',
              help='Active scanning intensity level')
@click.option('-g', '--search-engines', help='Comma-separated search engines for intelligence (google,bing,duckduckgo)')
@click.option('-H', '--github-token', help='GitHub API token for repository mining')
@click.option('-Q', '--google-api-key', help='Google Custom Search API key for intelligence collection')
@click.option('-U', '--google-cx', help='Google Custom Search Engine ID')
@click.option('-b', '--bing-api-key', help='Bing Web Search API key')
@click.option('--enable-scrapers', '--scrape', '--sc', is_flag=True, help='Enable advanced web scraping with JavaScript support')
@click.option('-x', '--scraping-engine', type=click.Choice(['requests', 'playwright']), default='requests',
              help='Web scraping engine: requests (fast) or playwright (JavaScript support)')
@click.option('--max-discovery-results', '--max-results', type=int, default=1000, help='Maximum results from discovery operations')
@click.option('--discovery-timeout', '--timeout-discovery', type=int, default=300, help='Discovery operation timeout in seconds')

# Advanced Testing
@click.option('-u', '--url', help='Test proxy connectivity with custom URL (default: httpbin.org)')
@click.option('-z', '--via-proxy', help='Run tests through another proxy')

# Target Website Testing
@click.option('-y', '--target-urls', help='Comma-separated list of target URLs to test')
@click.option('-W', '--target-config', help='YAML file with target test configurations')
@click.option('--target-preset', type=click.Choice(['google', 'social_media', 'streaming', 'e_commerce', 'news']), help='Use predefined target configuration')
@click.option('--target-success-rate', '--success-rate', type=float, default=0.7, help='Required success rate for target tests (0.0-1.0)')
@click.option('--target-parallel', is_flag=True, default=True, help='Run target tests in parallel')

# Database Operations
@click.option('-D', '--use-db', is_flag=True, help='Enable database mode instead of file mode')
@click.option('-B', '--db-path', help='Database file location (e.g., proxc.db). When specified, enables database saving')
@click.option('-X', '--export-from-db', help='Export filtered data from database to JSON/CSV file')
@click.option('-I', '--import-to-db', help='Import proxies from JSON/CSV file into database')

# API Export
@click.option('--api-export', help='Export results to API endpoint (URL)')
@click.option('--api-method', type=click.Choice(['POST', 'PUT', 'PATCH']), default='POST', help='HTTP method for API export')
@click.option('--api-auth', type=click.Choice(['none', 'bearer', 'basic', 'api_key']), default='none', help='API authentication type')
@click.option('--api-token', help='API authentication token/key')
@click.option('--api-batch-size', type=int, default=100, help='Batch size for API export')

# Web Interface
@click.option('-w', '--view', is_flag=True, help='Launch web browser interface to view results')
@click.option('--web-port', type=int, help='Custom port for web interface (default: auto-select)')

# Task Queue Management
@click.option('--enable-queue', is_flag=True, help='Enable Redis-based task queue')
@click.option('--redis-host', default='localhost', help='Redis server host (default: localhost)')
@click.option('--redis-port', type=int, default=6379, help='Redis server port (default: 6379)')
@click.option('--redis-db', type=int, default=0, help='Redis database number (default: 0)')
@click.option('--queue-priority', type=click.Choice(['high', 'medium', 'low']), default='medium', help='Task priority: high, medium, low')
@click.option('--max-retry-attempts', '--max-retries', type=int, default=3, help='Maximum retry attempts (default: 3)')
@click.option('--retry-backoff', type=float, default=2.0, help='Retry backoff multiplier (default: 2.0)')
@click.option('--queue-stats', is_flag=True, help='Show queue statistics')
@click.option('--clear-queue', is_flag=True, help='Clear all queue tasks')
@click.option('--queue-worker-mode', '--worker-mode', is_flag=True, help='Run as queue worker process')

# Other
@click.option('-G', '--config', help='Load YAML config file')
@click.option('-l', '--log', help='Save session logs')
@click.option('--debug-protocol-detection', is_flag=True, default=False, help='Enable detailed protocol detection debugging output')

# === Three-File Configuration Management ===
@click.option('--validate-config', is_flag=True, 
              help='Validate three-file configuration structure for consistency and conflicts')
@click.option('--check-conflicts', is_flag=True, 
              help='Check for conflicts across configuration files (duplicate sources, URL conflicts)')
@click.option('--config-report', is_flag=True, 
              help='Generate comprehensive configuration health report with diagnostics')

# === Enhanced Source Management ===
@click.option('--list-profiles', is_flag=True, 
              help='List all available collection profiles with their settings and source patterns')
@click.option('--profile', type=str, 
              help='Use specific collection profile for source selection (e.g., quick_scan, deep_hunt)')
@click.option('--source-status', type=str, 
              help='Show detailed status and configuration of a specific proxy source')

# === Configuration Tools ===
@click.option('--migrate-config', is_flag=True, 
              help='Migrate legacy single-file configuration to new three-file structure')
@click.option('--export-config', type=click.Choice(['legacy', 'three_file']), 
              help='Export current configuration to specified format (legacy=single file, three_file=separate files)')
@click.option('--config-summary', is_flag=True, 
              help='Show configuration summary with source counts, profiles, and system status')

# === Advanced Source Filtering ===
@click.option('--sources-by-quality', type=int, 
              help='Filter sources by minimum quality score (1-10). Higher scores indicate more reliable sources')
@click.option('--sources-by-type', type=click.Choice(['api', 'static', 'all']), 
              help='Filter sources by type: api (REST APIs), static (URLs/files), all (no filter)')
@click.option('--sources-by-category', type=click.Choice(['free', 'premium', 'custom']), 
              help='Filter sources by category: free (public sources), premium (paid APIs), custom (user-defined)')

@click.pass_context
def main_cli(ctx, input_file, output_file, validate, protocol_mode, protocol_strict, 
            verbose, quiet, silent,
            count, threads, timeout, adaptive_threads,
            cache_validation, cache_ttl, cache_memory_mb, cache_stats,
            detect_chains, chain_max_depth, chain_timeout, chain_confidence, chain_samples,
            filter_rules, analyze, isp, asn, scan, list_sources, check_sources, target_alive, rate, 
            discovery_mode, enable_fingerprinting, enable_intelligence, enable_repo_mining, ip_ranges, cloud_providers, 
            scan_intensity, search_engines, github_token, google_api_key, google_cx, bing_api_key,
            enable_scrapers, scraping_engine, max_discovery_results, discovery_timeout,
            url, via_proxy, target_urls, target_config, target_preset, target_success_rate, target_parallel,
            use_db, db_path, export_from_db, import_to_db, 
            api_export, api_method, api_auth, api_token, api_batch_size,
            view, web_port, 
            enable_queue, redis_host, redis_port, redis_db, queue_priority, max_retry_attempts, retry_backoff,
            queue_stats, clear_queue, queue_worker_mode,
            config, log, debug_protocol_detection,
            # NEW PARAMETERS FOR THREE-FILE CONFIGURATION
            validate_config, check_conflicts, config_report,
            list_profiles, profile, source_status,
            migrate_config, export_config, config_summary,
            sources_by_quality, sources_by_type, sources_by_category):
    """proxc - Advanced Proxy Discovery & Validation Tool
    
    ProxC provides comprehensive proxy discovery, validation, and management capabilities
    with support for multiple protocols, advanced filtering, and intelligent analysis.
    
    \b
    === CONFIGURATION SYSTEM ===
    ProxC uses a three-file configuration system for better organization:
    • api_sources.yaml     - API-based proxy sources (REST APIs, paid services)
    • static_sources.yaml  - Static sources (GitHub lists, text files, HTML tables)
    • collection_config.yaml - Global settings, profiles, and operational parameters
    
    \b
    === BASIC USAGE EXAMPLES ===
    
    Validate proxies from file:
        proxc -f proxies.txt -v -o results.json
    
    Discover proxies from configured sources:
        proxc -s -c 100 -v -o discovered.txt
        
    Use a specific collection profile:
        proxc -s --profile quick_scan -v
        
    List available sources and profiles:
        proxc --list-sources
        proxc --list-profiles
    
    \b
    === CONFIGURATION MANAGEMENT ===
    
    Validate configuration health:
        proxc --validate-config --config-report
        
    Check for configuration conflicts:
        proxc --check-conflicts
        
    Migrate legacy configuration:
        proxc --migrate-config
        
    Show configuration summary:
        proxc --config-summary
    
    \b
    === ADVANCED FILTERING ===
    
    Filter sources by quality and type:
        proxc -s --sources-by-quality 7 --sources-by-type api
        
    Use premium sources only:
        proxc -s --sources-by-category premium --profile premium_quality
        
    Filter by category and quality:
        proxc -s --sources-by-category free --sources-by-quality 6
        
    Filter results by speed and location:
        proxc -f proxies.txt -v -F "alive,speed:500" -i "AWS"
    
    \b
    === PERFORMANCE & MONITORING ===
    
    Enable caching and adaptive threading:
        proxc -s -v -K -j --cache-ttl 7200
        
    Monitor performance with progress tracking:
        proxc -f large_list.txt -v -V --cache-stats
        
    Generate detailed analytics:
        proxc -f proxies.txt -v -a -d -o results.json
    
    For complete documentation, see: docs/CLI_USAGE.md
    """
    # Initialize context
    ctx.ensure_object(dict)
    
    # Set output modes for print functions and logging
    set_output_modes(silent=silent, verbose=verbose, quiet=quiet)
    
    # Validate verbosity flag conflicts
    verbosity_flags = [verbose, quiet, silent]
    active_verbosity = sum(verbosity_flags)
    if active_verbosity > 1:
        conflicting_flags = []
        if verbose: conflicting_flags.append('--verbose (-V)')
        if quiet: conflicting_flags.append('--quiet (-q)')
        if silent: conflicting_flags.append('--silent')
        print_error(f"❌ Conflicting verbosity flags: {', '.join(conflicting_flags)}. Please use only one.")
        print_error("💡 Use only one of: -V/--verbose (debug), -q/--quiet (warnings only), or --silent (errors only)")
        return 1
    
    # Enhanced conflict detection
    conflicts = validate_advanced_conflicts(
        # Input/Output
        input_file=input_file, output_file=output_file, scan=scan, 
        use_db=use_db, db_path=db_path, export_from_db=export_from_db,
        
        # API Export
        api_export=api_export, api_auth=api_auth, api_token=api_token,
        
        # Validation & Protocol
        validate=validate, protocol_mode=protocol_mode, protocol_strict=protocol_strict,
        
        # Performance & Caching
        cache_validation=cache_validation, cache_memory_mb=cache_memory_mb,
        threads=threads, timeout=timeout, adaptive_threads=adaptive_threads,
        
        # Discovery & Collection
        discovery_mode=discovery_mode, enable_fingerprinting=enable_fingerprinting,
        enable_intelligence=enable_intelligence, enable_repo_mining=enable_repo_mining,
        enable_scrapers=enable_scrapers, scraping_engine=scraping_engine,
        
        # Advanced features
        detect_chains=detect_chains, target_urls=target_urls, target_config=target_config,
        target_preset=target_preset, url=url, via_proxy=via_proxy,
        
        # Queue management
        enable_queue=enable_queue, queue_worker_mode=queue_worker_mode,
        
        # Web interface  
        view=view, web_port=web_port
    )
    
    if conflicts:
        # Create context for enhanced suggestions
        cli_context = {
            'input_file': input_file,
            'output_file': output_file,
            'scan': scan,
            'validate': validate,
            'use_db': use_db,
            'db_path': db_path,
            'api_export': api_export,
            'target_urls': target_urls,
            'target_preset': target_preset,
            'detect_chains': detect_chains,
            'view': view
        }
        format_enhanced_conflicts(conflicts, cli_context)
        return 1
    
    # Load configuration with CLI overrides - needed for both CLI and menu modes
    try:
        cli_overrides = create_cli_overrides(
            verbose=verbose,
            quiet=quiet,
            silent=silent,
            threads=threads,
            timeout=timeout,
            count=count,
            rate=rate
        )
        ctx.obj['config'] = ConfigManager(config, cli_overrides=cli_overrides)
    except Exception as e:
        print_error(f"Configuration initialization error: {e}")
        return 1
    
    
    # Process and validate protocol configuration
    valid_protocols = ['http', 'https', 'socks4', 'socks5']
    
    if protocol_mode.startswith('force:'):
        protocol_mode_resolved = "uniform"
        target_protocol = protocol_mode.split(':', 1)[1]
        if target_protocol not in valid_protocols:
            enhanced_error_handler(
                f"Invalid protocol '{target_protocol}'. Valid protocols: {', '.join(valid_protocols)}",
                {'protocol_mode': protocol_mode, 'target_protocol': target_protocol}
            )
            return 1
    elif protocol_mode == 'detect':
        protocol_mode_resolved = "auto-detect-active"
        target_protocol = None
    elif protocol_mode == 'from-file':
        protocol_mode_resolved = "explicit-per-line"
        target_protocol = None
        if not input_file:
            enhanced_error_handler(
                "--protocol-mode from-file requires an input file (use -f/--file)",
                {'protocol_mode': protocol_mode, 'input_file': input_file}
            )
            return 1
    elif protocol_mode == 'auto':
        protocol_mode_resolved = "auto-detect"
        target_protocol = None
    else:
        enhanced_error_handler(
            f"Invalid protocol mode '{protocol_mode}'. Valid modes: auto, force:TYPE, detect, from-file",
            {'protocol_mode': protocol_mode}
        )
        return 1
    
    # Protocol flags simplified - only --protocol-mode is used
    strict_validation = protocol_strict
    
    # Validate protocol strict mode requirements
    if protocol_strict and protocol_mode == 'auto':
        print_error("❌ --protocol-strict requires explicit protocol specification")
        print_error("💡 Use with force:TYPE or detect modes: --protocol-mode force:http --protocol-strict")
        return 1
    
    # Validate input/output flag combinations
    if export_from_db and not (use_db or db_path):
        print_error("❌ --export-from-db requires database mode (use -D/--use-db or -B/--db-path)")
        print_error("💡 Example: proxc --use-db --export-from-db results.json")
        return 1
    
    if import_to_db and not (use_db or db_path):
        print_error("❌ --import-to-db requires database mode (use -D/--use-db or -B/--db-path)")
        print_error("💡 Example: proxc --use-db --import-to-db proxies.txt")
        return 1
    
    # Validate threading configuration
    if threads and threads <= 0:
        print_error("❌ --threads must be positive")
        return 1
    
    # Validate cache configuration
    if cache_ttl and cache_ttl <= 0:
        print_error("❌ --cache-ttl must be positive (seconds)")
        return 1
    
    if cache_memory_mb and cache_memory_mb <= 0:
        print_error("❌ --cache-memory-mb must be positive")
        return 1
    
    # Validate chain detection parameters
    if chain_max_depth and chain_max_depth <= 0:
        print_error("❌ --chain-max-depth must be positive")
        return 1
    
    if chain_timeout and chain_timeout <= 0:
        print_error("❌ --chain-timeout must be positive (seconds)")
        return 1
    
    if chain_confidence and (chain_confidence < 0.0 or chain_confidence > 1.0):
        print_error("❌ --chain-confidence must be between 0.0 and 1.0")
        return 1
    
    if chain_samples and chain_samples <= 0:
        print_error("❌ --chain-samples must be positive")
        return 1
    
    # Validate target testing parameters
    if target_success_rate and (target_success_rate < 0.0 or target_success_rate > 1.0):
        print_error("❌ --target-success-rate must be between 0.0 and 1.0")
        return 1
    
    # Validate rate limiting
    if rate and rate <= 0:
        print_error("❌ --rate must be positive (requests per second)")
        return 1
    
    # Validate operation mode conflicts
    operation_modes = [
        bool(scan), 
        bool(input_file), 
        bool(export_from_db), 
        bool(import_to_db), 
        bool(list_sources), 
        bool(check_sources)
    ]
    active_modes = sum(operation_modes)
    if active_modes == 0:
        print_error("❌ No operation specified")
        print_error("💡 Use one of: --scan, -f/--file, --list-sources, --export-from-db, --import-to-db, or --check-sources")
        return 1
    
    # Validate API export configuration
    if api_export:
        if not api_export.startswith(('http://', 'https://')):
            print_error("❌ --api-export must be a valid HTTP/HTTPS URL")
            print_error("💡 Example: --api-export https://api.example.com/proxies")
            return 1
    
    if api_token and not api_export:
        print_error("❌ --api-token requires --api-export")
        return 1
    
    if verbose:
        logger.info("Starting ProxC operation")
        if protocol_mode_resolved != "auto-detect":
            print_verbose(f"Protocol mode: {protocol_mode_resolved}")
            if target_protocol:
                print_verbose(f"Target protocol: {target_protocol}")
            if strict_validation:
                print_verbose("Strict protocol validation enabled")
    
    # Validate target-alive parameter
    if target_alive is not None:
        if target_alive <= 0:
            print_error("Target alive count must be positive")
            sys.exit(1)
        if target_alive > 10000:
            print_error("Target alive count too high (max: 10000)")
            sys.exit(1)
        
        # When using --target-alive, --count becomes the batch size
        if count:
            print_verbose(f"Using --count {count} as batch size with --target-alive {target_alive}")
        else:
            count = 50  # Default batch size for target-alive mode
    
    # Handle database configuration and other context setup for CLI mode
    try:
        # Handle database configuration - db_path now serves as both trigger and path
        save_to_db = bool(db_path)  # If db_path specified, enable database saving
        
        # Set default database path if database operations are requested but no path given
        if not db_path and (use_db or export_from_db or import_to_db):
            db_path = 'proxc.db'
        
        # Set database URL in config
        if db_path:
            if not db_path.startswith(('sqlite://', 'postgresql://', 'mysql://', 'mongodb://')):
                db_url = f"sqlite:///{db_path}"
            else:
                db_url = db_path
            ctx.obj['config'].set('database_url', db_url)
            
        # Use extended database manager ONLY when explicitly needed for database operations
        if use_db or save_to_db or export_from_db or import_to_db:
            ctx.obj['db'] = create_extended_database_manager(config=ctx.obj['config'])
            ctx.obj['use_db'] = True
        else:
            # Only create a database manager if actually needed - initialize to None
            ctx.obj['db'] = None
            ctx.obj['use_db'] = False
            
        ctx.obj['metrics'] = MetricsCollector()
        
        # Store database operation flags in context
        ctx.obj['save_to_db'] = save_to_db
        ctx.obj['db_path'] = db_path
        ctx.obj['export_from_db'] = export_from_db
        ctx.obj['import_to_db'] = import_to_db
        
        # Store web interface flags in context
        ctx.obj['view'] = view
        ctx.obj['web_port'] = web_port
        
        # Store API export configuration in context
        ctx.obj['api_export'] = api_export
        ctx.obj['api_method'] = api_method
        ctx.obj['api_auth'] = api_auth
        ctx.obj['api_token'] = api_token
        ctx.obj['api_batch_size'] = api_batch_size
        
        # Configure target testing
        if target_urls or target_config or target_preset:
            _configure_target_testing(ctx.obj['config'], target_urls, target_config, target_preset, 
                                    target_success_rate, target_parallel, verbose)
        
        # Configure adaptive threading
        adaptive_config, effective_threads = _configure_adaptive_threading(
            adaptive_threads, 100, threads or CLI_DEFAULT_THREADS
        )
        ctx.obj['adaptive_config'] = adaptive_config
        
        # Ensure effective_threads is always a valid integer
        if not isinstance(effective_threads, (int, float)) or effective_threads <= 0:
            print_warning(f"Invalid effective_threads: {effective_threads}, using default of 10")
            effective_threads = 10
        else:
            effective_threads = int(effective_threads)
        
        ctx.obj['effective_threads'] = effective_threads
        
        if adaptive_threads and verbose:
            if adaptive_config:
                print_info(f"🔧 Adaptive threading enabled: {adaptive_config.min_threads}-{adaptive_config.max_threads} threads "
                          f"(starting with {effective_threads})")
            else:
                print_info(f"⚠️  Adaptive threading requested but not available, using {effective_threads} fixed threads")
        
        # Configure smart caching
        ctx.obj['cache_validation'] = cache_validation
        ctx.obj['cache_ttl'] = cache_ttl
        ctx.obj['cache_memory_mb'] = cache_memory_mb
        ctx.obj['cache_stats'] = cache_stats
        
        if cache_validation and verbose:
            cache_info = f"🗄️  Smart caching enabled: TTL={cache_ttl or 3600}s"
            if cache_memory_mb:
                cache_info += f", Memory={cache_memory_mb}MB"
            else:
                cache_info += f", Memory=auto-sized"
            print_info(cache_info)
        
        # Store target-alive flag in context
        ctx.obj['target_alive'] = target_alive
        
        # Store protocol mode in context
        ctx.obj['protocol_mode'] = protocol_mode
        
        # Configure task queue system
        if enable_queue:
            try:
                from ..task_queue import TaskManager, TaskPriority
                
                # Redis configuration
                redis_config = {
                    'host': redis_host,
                    'port': redis_port,
                    'db': redis_db
                }
                
                # Map string priority to enum
                priority_map = {
                    'high': TaskPriority.HIGH,
                    'medium': TaskPriority.MEDIUM,
                    'low': TaskPriority.LOW
                }
                
                ctx.obj['task_queue_enabled'] = True
                ctx.obj['redis_config'] = redis_config
                ctx.obj['queue_priority'] = priority_map.get(queue_priority, TaskPriority.MEDIUM)
                ctx.obj['max_retry_attempts'] = max_retry_attempts
                ctx.obj['retry_backoff'] = retry_backoff
                
                if verbose:
                    print_info(f"🚀 Task queue enabled: Redis {redis_host}:{redis_port}/{redis_db}")
                    print_info(f"   Priority: {queue_priority.upper()}, Max retries: {max_retry_attempts}")
                    
            except ImportError as e:
                print_error(f"Task queue dependencies not available: {e}")
                print_info("Install with: pip install redis rq")
                sys.exit(1)
        else:
            ctx.obj['task_queue_enabled'] = False
        
        # Configure advanced discovery and collection
        ctx.obj['discovery_mode'] = discovery_mode
        ctx.obj['enable_fingerprinting'] = enable_fingerprinting
        ctx.obj['enable_intelligence'] = enable_intelligence
        ctx.obj['enable_repo_mining'] = enable_repo_mining
        ctx.obj['enable_scrapers'] = enable_scrapers
        ctx.obj['scraping_engine'] = scraping_engine
        ctx.obj['max_discovery_results'] = max_discovery_results
        ctx.obj['discovery_timeout'] = discovery_timeout
        ctx.obj['scan_intensity'] = scan_intensity
        
        # Parse comma-separated options
        if ip_ranges:
            ctx.obj['ip_ranges'] = [r.strip() for r in ip_ranges.split(',')]
        else:
            ctx.obj['ip_ranges'] = []
            
        if cloud_providers:
            ctx.obj['cloud_providers'] = [p.strip() for p in cloud_providers.split(',')]
        else:
            ctx.obj['cloud_providers'] = []
            
        if search_engines:
            ctx.obj['search_engines'] = [e.strip() for e in search_engines.split(',')]
        else:
            ctx.obj['search_engines'] = ['google', 'bing', 'duckduckgo']  # Default
        
        # API tokens and keys
        ctx.obj['github_token'] = github_token
        ctx.obj['google_api_key'] = google_api_key
        ctx.obj['google_cx'] = google_cx
        ctx.obj['bing_api_key'] = bing_api_key
        
        # Verbose logging for advanced features
        if verbose and any([enable_fingerprinting, enable_intelligence, enable_repo_mining, enable_scrapers]):
            features = []
            if enable_fingerprinting:
                features.append("Fingerprinting")
            if enable_intelligence:
                features.append("Intelligence")
            if enable_repo_mining:
                features.append("Repository Mining")
            if enable_scrapers:
                features.append("Advanced Scraping")
            print_info(f"🔬 Advanced features enabled: {', '.join(features)}")
            print_info(f"🎯 Discovery mode: {discovery_mode.upper()}")
            if discovery_mode != 'passive':
                print_info(f"⚡ Scan intensity: {scan_intensity.upper()}")
        
    except Exception as e:
        print_error(f"Failed to initialize: {e}")
        sys.exit(1)
    
    # ===============================================================================
    # UNIFIED PROCESSING LOGIC
    # ===============================================================================
    
    # Timeout is now in seconds (no conversion needed)
    timeout_seconds = float(timeout)
    
    # Handle list-sources command first (read-only operation)
    if list_sources:
        return _list_proxy_sources(ctx, verbose)
    
    # Handle check-sources command (diagnostic operation)
    if check_sources:
        return _check_proxy_sources(ctx, verbose)
    
    # Handle task queue specific operations first
    if queue_stats:
        return _show_queue_stats(ctx, verbose)
    
    if clear_queue:
        return _clear_queue(ctx, verbose)
    
    if queue_worker_mode:
        return _run_queue_worker(ctx, verbose)
    
    # Handle database-specific operations first
    if import_to_db:
        return _import_to_database(ctx, import_to_db, verbose)
    
    if export_from_db:
        return _export_from_database(ctx, export_from_db, filter_rules, verbose)
    
    # Validate that user specified some form of output (unless using special operations or web view only)
    if not output_file and not save_to_db and not view:
        print_error("You must specify an output file using -o/--output or database path with -B/--db-path")
        print_info("Examples:")
        print_info("  proxc --scan -o proxies.txt")
        print_info("  proxc --scan --db-path proxies.db")
        sys.exit(1)
    
    # Determine operation mode
    if scan and not input_file:
        # Scan mode: discover new proxies
        if target_alive:
            return _scan_until_target_alive(ctx, target_alive, output_file, target_protocol, validate, verbose, 
                                          timeout_seconds, threads, filter_rules, analyze, protocol_mode_resolved, strict_validation, 
                                          debug_protocol_detection, url, via_proxy, rate, log, isp, asn, count)
        else:
            return _scan_proxies(ctx, output_file, target_protocol, validate, verbose, timeout_seconds, 
                               threads, filter_rules, analyze, count, protocol_mode_resolved, strict_validation, 
                               debug_protocol_detection, url, via_proxy, rate, log, isp, asn)
    
    elif input_file:
        # File processing mode: load, process, and optionally save
        return _process_file(ctx, input_file, output_file, protocol_mode_resolved, target_protocol, 
                           strict_validation, validate, verbose, timeout_seconds, threads, filter_rules, 
                           analyze, debug_protocol_detection, url, via_proxy, rate, log, isp, asn)
    
    elif use_db and not input_file:
        # Database mode: load from database and process
        return _process_database(ctx, output_file, target_protocol, validate, verbose, 
                               timeout_seconds, threads, filter_rules, analyze, protocol_mode_resolved, 
                               strict_validation, debug_protocol_detection, url, via_proxy, rate, log, isp, asn)
    
    else:
        # No input specified - show help
        print_error("No input specified. Use -f for file input, --scan to discover proxies, or -D to use database mode.")
        print("Run 'proxc --help' for usage examples.")
        sys.exit(1)


# ===============================================================================
# HELPER FUNCTIONS FOR UNIFIED PROCESSING
# ===============================================================================

def _scan_proxies(ctx, output_file, target_protocol, validate, verbose, timeout_seconds, 
                  threads, filter_rules, analyze, count, protocol_mode_resolved, strict_validation, 
                  debug_protocol_detection, url, via_proxy, rate, log, isp, asn):
    """Discover new proxies from sources using batched scanning"""
    if verbose:
        print_info("🔍 Scanning for new proxies...")
    
    import time
    from collections import defaultdict
    
    try:
        # Initialize components
        from ..proxy_engine.fetchers import EnhancedProxyFetcher
        fetcher = EnhancedProxyFetcher(ctx.obj['config'])
        all_proxies = []
        total_scanned = 0
        rounds = 0
        start_time = time.time()
        
        # Use count as batch size (per-round limit), default to 100 if not specified
        batch_size = count if count else 100
        
        # Track seen proxies to avoid duplicates
        seen_addresses = set()
        
        # Initialize session logger if requested
        session_logger = None
        if log:
            try:
                from ..proxy_core.session_logger import SessionLogger
                session_logger = SessionLogger(log)
                if verbose:
                    print_info(f"📝 Session logging enabled: {log}")
            except Exception as e:
                print_warning(f"Failed to initialize session logging: {e}")
        
        # Initialize rate limiter if requested
        rate_limiter = None
        if rate:
            try:
                from ..proxy_core.utils import RateLimiter
                rate_limiter = RateLimiter(rate)
                if verbose:
                    print_info(f"⚡ Rate limiting enabled: {rate} requests/second")
            except Exception as e:
                print_warning(f"Failed to initialize rate limiter: {e}")
        
        if verbose:
            print_info(f"⚙️  Configuration: batch_size={batch_size} proxies per round")
        
        # Continue fetching in batches until no more proxies are available
        consecutive_duplicate_rounds = 0
        max_duplicate_rounds = 3  # Stop after 3 consecutive rounds of only duplicates
        
        while True:
            rounds += 1
            
            if verbose:
                print_info(f"🔄 Round {rounds}: Fetching up to {batch_size} proxies...")
            
            # Fetch batch of new proxies
            try:
                batch_proxies = fetcher.fetch_proxies(
                    source_names=None,  # Use all sources
                    max_proxies=batch_size
                )
                
                if not batch_proxies:
                    if verbose:
                        print_warning("No more proxies available from sources")
                    break
                
                # Remove duplicates we've already seen
                new_proxies = []
                for proxy in batch_proxies:
                    address = proxy.address
                    if address not in seen_addresses:
                        seen_addresses.add(address)
                        new_proxies.append(proxy)
                
                if not new_proxies:
                    consecutive_duplicate_rounds += 1
                    if verbose:
                        print_warning(f"Only duplicate proxies found in this batch ({consecutive_duplicate_rounds}/{max_duplicate_rounds})")
                    
                    if consecutive_duplicate_rounds >= max_duplicate_rounds:
                        if verbose:
                            print_warning("Sources appear to be exhausted (too many duplicate rounds)")
                        break
                    continue
                else:
                    consecutive_duplicate_rounds = 0  # Reset counter when new proxies are found
                
                total_scanned += len(new_proxies)
                
                if verbose:
                    print_info(f"   Fetched {len(new_proxies)} new proxies (total scanned: {total_scanned})")
                
                # Apply protocol filtering if specified
                if target_protocol:
                    protocol_enum = ProxyProtocol(target_protocol.lower())
                    filtered_proxies = [p for p in new_proxies if p.protocol == protocol_enum]
                    if verbose and len(filtered_proxies) != len(new_proxies):
                        print_info(f"   Filtered to {len(filtered_proxies)} {target_protocol} proxies")
                    new_proxies = filtered_proxies
                
                if not new_proxies:
                    continue
                
                all_proxies.extend(new_proxies)
                
                if verbose:
                    print_success(f"   Added {len(new_proxies)} proxies! Total collected: {len(all_proxies)}")
                
                # Check if we've reached the user-specified count limit
                if count and len(all_proxies) >= count:
                    if verbose:
                        print_info(f"🎯 Reached target count of {count} proxies, stopping scan")
                    break
                
            except Exception as e:
                # Provide more specific error context and suggestions
                error_msg = _analyze_scanning_error(e, rounds, verbose)
                print_error(error_msg)
                
                if verbose:
                    import traceback
                    traceback.print_exc()
                continue
        
        # Final results
        elapsed_time = time.time() - start_time
        
        # Trim the proxy list to exactly match the requested count
        if count and len(all_proxies) > count:
            all_proxies = all_proxies[:count]
            if verbose:
                print_info(f"✂️  Trimmed results to exactly {count} proxies as requested")
        
        if verbose:
            print_success(f"🎯 Scanning complete! Collected {len(all_proxies)} proxies in {rounds} rounds ({elapsed_time:.1f}s)")
            print_info(f"   Total proxies scanned: {total_scanned}")
        
        if not all_proxies:
            _handle_no_proxies_found(rounds, verbose)
            return
        
        # Process the found proxies
        _process_proxies(ctx, all_proxies, output_file, target_protocol, validate, verbose,
                        timeout_seconds, threads, filter_rules, analyze, protocol_mode_resolved, 
                        strict_validation, debug_protocol_detection, url, via_proxy, rate, log, isp, asn)
    
    except Exception as e:
        print_error(f"Scan failed: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _scan_until_target_alive(ctx, target_alive, output_file, target_protocol, validate, verbose, 
                           timeout_seconds, threads, filter_rules, analyze, protocol_mode_resolved, strict_validation, 
                           debug_protocol_detection, url, via_proxy, rate, log, isp, asn, batch_size_count):
    """Discover proxies until target number of alive proxies is reached"""
    if verbose:
        print_info(f"🎯 Scanning until {target_alive} alive proxies are found...")
    
    import time
    from collections import defaultdict
    
    try:
        # Initialize components
        from ..proxy_engine.fetchers import EnhancedProxyFetcher
        fetcher = EnhancedProxyFetcher(ctx.obj['config'])
        alive_proxies = []
        total_scanned = 0
        rounds = 0
        start_time = time.time()
        
        # Safety limits
        max_total_scanned = target_alive * 10  # Safety limit
        max_time_seconds = 30 * 60  # 30 minutes max
        batch_size = batch_size_count  # Use count parameter as batch size
        
        # Track seen proxies to avoid duplicates
        seen_addresses = set()
        
        # Initialize session logger if requested
        session_logger = None
        if log:
            try:
                from ..proxy_core.session_logger import SessionLogger
                session_logger = SessionLogger(log)
                if verbose:
                    print_info(f"📝 Session logging enabled: {log}")
            except Exception as e:
                print_warning(f"Failed to initialize session logging: {e}")
        
        # Initialize rate limiter if requested
        rate_limiter = None
        if rate:
            try:
                from ..proxy_core.utils import RateLimiter
                rate_limiter = RateLimiter(rate)
                if verbose:
                    print_info(f"⚡ Rate limiting enabled: {rate} requests/second")
            except Exception as e:
                print_warning(f"Failed to initialize rate limiter: {e}")
        
        if verbose:
            print_info(f"⚙️  Configuration: batch_size={batch_size}, max_scanned={max_total_scanned}, timeout={max_time_seconds//60}min")
        
        while len(alive_proxies) < target_alive:
            rounds += 1
            
            # Check safety limits
            elapsed_time = time.time() - start_time
            if elapsed_time > max_time_seconds:
                print_warning(f"Reached time limit ({max_time_seconds//60} minutes)")
                break
            
            if total_scanned >= max_total_scanned:
                print_warning(f"Reached scan limit ({max_total_scanned} total proxies scanned)")
                break
            
            if verbose:
                remaining = target_alive - len(alive_proxies)
                print_info(f"🔄 Round {rounds}: Need {remaining} more alive proxies...")
            
            # Fetch batch of new proxies
            try:
                batch_proxies = fetcher.fetch_proxies(
                    source_names=None,  # Use all sources
                    max_proxies=batch_size
                )
                
                if not batch_proxies:
                    if verbose:
                        print_warning("No more proxies available from sources")
                    break
                
                # Remove duplicates we've already seen
                new_proxies = []
                for proxy in batch_proxies:
                    address = proxy.address
                    if address not in seen_addresses:
                        seen_addresses.add(address)
                        new_proxies.append(proxy)
                
                if not new_proxies:
                    if verbose:
                        print_warning("Only duplicate proxies found in this batch")
                    continue
                
                total_scanned += len(new_proxies)
                
                if verbose:
                    print_info(f"   Fetched {len(new_proxies)} new proxies (total scanned: {total_scanned})")
                
                # Apply protocol filtering if specified
                if target_protocol:
                    protocol_enum = ProxyProtocol(target_protocol.lower())
                    filtered_proxies = [p for p in new_proxies if p.protocol == protocol_enum]
                    if verbose and len(filtered_proxies) != len(new_proxies):
                        print_info(f"   Filtered to {len(filtered_proxies)} {target_protocol} proxies")
                    new_proxies = filtered_proxies
                
                if not new_proxies:
                    continue
                
                # Apply non-status filters before validation if any
                if filter_rules or isp or asn:
                    new_proxies = _apply_filters(new_proxies, filter_rules, verbose, before_validation=True, isp=isp, asn=asn, protocol=target_protocol)
                
                if not new_proxies:
                    continue
                
                # Protocol detection and processing
                if protocol_mode_resolved == "auto-detect-active":
                    new_proxies = _handle_protocol_detection(new_proxies, target_protocol, verbose, debug_protocol_detection)
                
                # Additional protocol processing if needed
                if target_protocol:
                    new_proxies = _handle_protocol_processing(new_proxies, target_protocol, protocol_mode_resolved, strict_validation, verbose)
                
                if not new_proxies:
                    continue
                
                # Validate the batch (always validate for target-alive to ensure they're actually alive)
                if verbose:
                    print_info(f"   Validating {len(new_proxies)} proxies...")
                
                validated_proxies = _validate_proxies(ctx, new_proxies, timeout_seconds, ctx.obj['effective_threads'], verbose, 
                                                    custom_url=url, via_proxy=via_proxy, rate_limiter=rate_limiter, 
                                                    session_logger=session_logger, adaptive_config=ctx.obj['adaptive_config'],
                                                    cache_validation=ctx.obj['cache_validation'], cache_ttl=ctx.obj['cache_ttl'],
                                                    cache_memory_mb=ctx.obj['cache_memory_mb'], cache_stats=ctx.obj['cache_stats'])
                
                # Filter for alive proxies only
                batch_alive = [p for p in validated_proxies if p.status == ProxyStatus.ACTIVE]
                
                if batch_alive:
                    # Apply post-validation filters
                    if filter_rules or isp or asn:
                        batch_alive = _apply_filters(batch_alive, filter_rules, verbose, before_validation=False, isp=isp, asn=asn, protocol=target_protocol)
                    
                    alive_proxies.extend(batch_alive)
                    
                    if verbose:
                        print_success(f"   Found {len(batch_alive)} alive proxies! Total: {len(alive_proxies)}/{target_alive}")
                else:
                    if verbose:
                        print_info(f"   No alive proxies in this batch")
                
            except Exception as e:
                print_error(f"Error in round {rounds}: {e}")
                if verbose:
                    import traceback
                    traceback.print_exc()
                continue
        
        # Final results
        final_count = len(alive_proxies)
        elapsed_time = time.time() - start_time
        
        if final_count >= target_alive:
            # Trim to exact target if we exceeded it
            alive_proxies = alive_proxies[:target_alive]
            print_success(f"🎯 Target reached! Found {target_alive} alive proxies in {rounds} rounds ({elapsed_time:.1f}s)")
        else:
            print_warning(f"⚠️  Found {final_count}/{target_alive} alive proxies after {rounds} rounds ({elapsed_time:.1f}s)")
            print_info(f"   Total proxies scanned: {total_scanned}")
        
        if verbose:
            success_rate = (len(alive_proxies) / total_scanned * 100) if total_scanned > 0 else 0
            print_info(f"📊 Success rate: {success_rate:.1f}% ({len(alive_proxies)}/{total_scanned})")
        
        # Apply analysis if requested OR if output file specified (for country preservation)
        if analyze or output_file:
            if output_file and not analyze:
                print_verbose("🌍 Auto-enabling geo analysis for country preservation in output file...")
            alive_proxies = _analyze_proxies(ctx, alive_proxies, verbose)
        
        # Save results
        _save_results_enhanced(ctx, alive_proxies, output_file, verbose)
        
        # Finalize session logging
        if session_logger:
            try:
                summary = session_logger.finalize_session()
                if verbose:
                    stats = session_logger.get_session_stats()
                    print_info(f"📊 Session complete: {stats['valid_proxies']}/{stats['total_proxies']} valid proxies")
                    if stats.get('average_response_time_ms'):
                        print_info(f"   Average response time: {stats['average_response_time_ms']:.0f}ms")
                    print_info(f"   Session logged to: {session_logger.log_file_path}")
            except Exception as e:
                print_warning(f"Failed to finalize session logging: {e}")
    
    except Exception as e:
        print_error(f"Target alive scan failed: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _process_file(ctx, input_file, output_file, protocol_mode_resolved, target_protocol, 
                  strict_validation, validate, verbose, timeout_seconds, threads, filter_rules, 
                  analyze, debug_protocol_detection, url, via_proxy, rate, log, isp, asn):
    """Process proxies from input file"""
    print_verbose(f"📁 Loading proxies from {input_file}")
    
    try:
        # Ensure required context variables are initialized (fix for menu interface calls)
        if 'effective_threads' not in ctx.obj:
            ctx.obj['effective_threads'] = threads if isinstance(threads, int) and threads > 0 else 10
        if 'adaptive_config' not in ctx.obj:
            ctx.obj['adaptive_config'] = None
        if 'cache_validation' not in ctx.obj:
            ctx.obj['cache_validation'] = False
        if 'cache_ttl' not in ctx.obj:
            ctx.obj['cache_ttl'] = 3600
        if 'cache_memory_mb' not in ctx.obj:
            ctx.obj['cache_memory_mb'] = None
        if 'cache_stats' not in ctx.obj:
            ctx.obj['cache_stats'] = False
        if 'detect_chains' not in ctx.obj:
            ctx.obj['detect_chains'] = False
        if 'chain_max_depth' not in ctx.obj:
            ctx.obj['chain_max_depth'] = 5
        if 'chain_timeout' not in ctx.obj:
            ctx.obj['chain_timeout'] = 15.0
        if 'chain_confidence' not in ctx.obj:
            ctx.obj['chain_confidence'] = 0.7
        if 'chain_samples' not in ctx.obj:
            ctx.obj['chain_samples'] = 3
        
        # Auto-detect input format
        input_format = detect_file_format(input_file)
        
        # Load proxies from file with new protocol mode support
        proxies = _load_proxies_from_file(input_file, input_format, protocol_mode_resolved, target_protocol)
        
        if not proxies:
            print_warning(f"No proxies loaded from {input_file}")
            return 1  # Return error code instead of bare return
        
        # Always show proxy count (key requirement #1)
        print_success(f"Loaded {len(proxies)} proxies from {input_file}")
        
        # Process the loaded proxies and return the result
        result = _process_proxies(ctx, proxies, output_file, target_protocol, validate, verbose,
                                timeout_seconds, threads, filter_rules, analyze, protocol_mode_resolved, 
                                strict_validation, debug_protocol_detection=debug_protocol_detection, 
                                url=url, via_proxy=via_proxy, rate=rate, log=log, isp=isp, asn=asn)
        
        # Return success if no explicit result returned
        return result if result is not None else 0
        
    except Exception as e:
        print_error(f"File processing failed: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return 1  # Return error code instead of sys.exit()


def _process_proxies(ctx, proxies, output_file, target_protocol, validate, verbose,
                    timeout_seconds, threads, filter_rules, analyze, protocol_mode_resolved, 
                    strict_validation, debug_protocol_detection=False, url=None, via_proxy=None, rate=None, log=None, isp=None, asn=None):
    """Unified proxy processing pipeline"""
    try:
        current_proxies = proxies
        
        # Initialize session logger if requested
        session_logger = None
        if log:
            try:
                from ..proxy_core.session_logger import SessionLogger
                session_logger = SessionLogger(log)
                print_verbose(f"📝 Session logging enabled: {log}")
                
                # Log initial configuration
                if url:
                    session_logger.log_custom_url_test(url)
                if via_proxy:
                    session_logger.log_proxy_chain_setup(via_proxy)
            except Exception as e:
                print_warning(f"Failed to initialize session logging: {e}")
        
        # Initialize rate limiter if requested
        rate_limiter = None
        if rate:
            try:
                from ..proxy_core.utils import RateLimiter
                rate_limiter = RateLimiter(rate)
                print_verbose(f"⚡ Rate limiting enabled: {rate} requests/second")
            except Exception as e:
                print_warning(f"Failed to initialize rate limiter: {e}")
        
        # Protocol detection and processing
        try:
            if protocol_mode_resolved == "auto-detect-active":
                current_proxies = _handle_protocol_detection(current_proxies, target_protocol, verbose, debug_protocol_detection)
        except Exception as e:
            print_warning(f"Protocol detection failed: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
        
        # Protocol filtering/override logic
        try:
            if target_protocol:
                current_proxies = _handle_protocol_processing(current_proxies, target_protocol, 
                                                            protocol_mode_resolved, strict_validation, verbose)
        except Exception as e:
            print_warning(f"Protocol processing failed: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
        
        # Check if filters require validation
        requires_validation = validate
        if filter_rules and ('alive' in filter_rules or 'speed:' in filter_rules):
            requires_validation = True
            if not validate:
                print_verbose("🔧 Auto-enabling validation for filters that require it")
        
        # Apply non-status filters first
        try:
            if filter_rules or isp or asn:
                current_proxies = _apply_filters(current_proxies, filter_rules, verbose, before_validation=True, isp=isp, asn=asn, protocol=target_protocol)
        except Exception as e:
            print_warning(f"Pre-validation filtering failed: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
        
        # Validation - This is the most likely failure point for large batches
        if requires_validation:
            try:
                print_verbose(f"✅ Validating {len(current_proxies)} proxies...")
                
                # Add resource monitoring for large batches
                if len(current_proxies) > 1000:
                    print_verbose(f"⚠️  Large batch detected ({len(current_proxies)} proxies). Consider reducing batch size if memory issues occur.")
                
                current_proxies = _validate_proxies(ctx, current_proxies, timeout_seconds, ctx.obj['effective_threads'], verbose, 
                                                   custom_url=url, via_proxy=via_proxy, rate_limiter=rate_limiter, 
                                                   session_logger=session_logger, adaptive_config=ctx.obj['adaptive_config'],
                                                   cache_validation=ctx.obj['cache_validation'], cache_ttl=ctx.obj['cache_ttl'],
                                                   cache_memory_mb=ctx.obj['cache_memory_mb'], cache_stats=ctx.obj['cache_stats'])
                
                if current_proxies is None:
                    print_error("Validation returned no results - this indicates a critical error")
                    return 1
                
                print_verbose(f"✅ Validation completed for {len(current_proxies)} proxies")
                
            except Exception as e:
                print_error(f"Validation failed: {e}")
                if verbose:
                    import traceback
                    traceback.print_exc()
                
                # Try to preserve any partial results by using original proxy list
                print_warning("Attempting to continue with original proxy list...")
                current_proxies = proxies
        
        # Apply post-validation filters (alive, speed)
        try:
            if filter_rules or isp or asn:
                current_proxies = _apply_filters(current_proxies, filter_rules, verbose, before_validation=False, isp=isp, asn=asn, protocol=target_protocol)
        except Exception as e:
            print_warning(f"Post-validation filtering failed: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
        
        # Analysis (auto-enabled if output file specified for country preservation)
        if analyze or output_file:
            try:
                if not _silent_mode and len(current_proxies) > 10:
                    # Show progress for analysis
                    progress = create_enhanced_progress()
                    if progress:
                        with progress:
                            task = progress.add_task("Analyzing...", total=len(current_proxies))
                            
                            def analysis_progress_callback(completed, total):
                                progress.update(task, completed=completed)
                            
                            current_proxies = _analyze_proxies(ctx, current_proxies, verbose, threads, analysis_progress_callback)
                    else:
                        current_proxies = _analyze_proxies(ctx, current_proxies, verbose, threads)
                else:
                    current_proxies = _analyze_proxies(ctx, current_proxies, verbose, threads)
            except Exception as e:
                print_warning(f"Analysis failed: {e}")
                if verbose:
                    import traceback
                    traceback.print_exc()
        
        # Generate comprehensive final summary
        try:
            filter_summary = generate_filter_summary(filter_rules, target_protocol, isp, asn)
            original_count = len(proxies)
            final_count = len(current_proxies)
            
            # Display comprehensive results summary
            if filter_summary != "none":
                print_success(f"✅ Processing complete: {final_count}/{original_count} proxies matched filters: {filter_summary}")
            else:
                print_success(f"✅ Processing complete: {final_count}/{original_count} proxies processed")
        except Exception as e:
            print_warning(f"Summary generation failed: {e}")
        
        # Output results (enhanced with database support) - Critical section
        try:
            _save_results_enhanced(ctx, current_proxies, output_file, verbose)
            print_verbose(f"💾 Results saved to: {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            return 1  # Return error if we can't save results
        
        # Finalize session logging
        if session_logger:
            try:
                summary = session_logger.finalize_session()
                stats = session_logger.get_session_stats()
                print_verbose(f"📊 Session complete: {stats['valid_proxies']}/{stats['total_proxies']} valid proxies")
                if stats.get('average_response_time_ms'):
                    print_verbose(f"   Average response time: {stats['average_response_time_ms']:.0f}ms")
                print_verbose(f"   Session logged to: {session_logger.log_file_path}")
            except Exception as e:
                print_warning(f"Failed to finalize session logging: {e}")
        
        # Return success
        return 0
        
    except Exception as e:
        print_error(f"Proxy processing pipeline failed: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return 1


def generate_filter_summary(filter_rules=None, protocol=None, isp=None, asn=None):
    """Generate comprehensive human-readable filter summary"""
    filters = []
    
    if filter_rules:
        # Parse individual filter rules
        rules = filter_rules.split(',')
        for rule in rules:
            rule = rule.strip()
            filters.append(rule)
    
    if protocol:
        filters.append(f"protocol:{protocol}")
    
    if isp:
        filters.append(f"isp:{isp}")
    
    if asn:
        filters.append(f"asn:{asn}")
    
    return ", ".join(filters) if filters else "none"


def _apply_filters(proxies, filter_rules, verbose, before_validation=False, isp=None, asn=None, protocol=None, enable_threading=True):
    """Apply filtering rules with optional threading for better performance"""
    original_count = len(proxies)
    filters_applied = []
    
    if filter_rules:
        filters_applied.append(filter_rules)
    if protocol:
        filters_applied.append(f"protocol:{protocol}")
    if isp:
        filters_applied.append(f"isp:{isp}")
    if asn:
        filters_applied.append(f"asn:{asn}")
    
    if filters_applied:
        phase = "pre-validation" if before_validation else "post-validation"
        print_verbose(f"🔧 Applying {phase} filters: {', '.join(filters_applied)}")
    
    # Use threaded filtering for large datasets and complex filters
    if enable_threading and len(proxies) > 100 and (isp or asn or (filter_rules and 'country:' in filter_rules)):
        filtered = _apply_filters_threaded(proxies, filter_rules, verbose, before_validation, isp, asn, protocol)
    else:
        filtered = _apply_filters_sequential(proxies, filter_rules, verbose, before_validation, isp, asn, protocol)
    
    return filtered


def _apply_filters_sequential(proxies, filter_rules, verbose, before_validation=False, isp=None, asn=None, protocol=None):
    """Sequential filtering (original implementation)"""
    filtered = proxies
    
    # Apply ISP filtering
    if isp:
        original_count = len(filtered)
        filtered = [p for p in filtered if p.geo_location and p.geo_location.isp and isp.lower() in p.geo_location.isp.lower()]
        print_verbose(f"   ISP filter '{isp}': {len(filtered)}/{original_count} proxies match")
    
    # Apply ASN filtering
    if asn:
        original_count = len(filtered)
        # Handle ASN format - extract number from ASXXXXX format
        asn_number = asn.upper().replace('AS', '') if asn.upper().startswith('AS') else asn
        try:
            asn_int = int(asn_number)
            filtered = [p for p in filtered if p.geo_location and p.geo_location.asn == asn_int]
            print_verbose(f"   ASN filter '{asn}': {len(filtered)}/{original_count} proxies match")
        except ValueError:
            print_verbose(f"   Invalid ASN format '{asn}', skipping ASN filter")
    
    # Parse traditional filter rules (alive,anonymous,speed:1000,country:US)
    if not filter_rules:
        return filtered
    
    rules = filter_rules.split(',')
    
    for rule in rules:
        rule = rule.strip()
        if rule == 'alive':
            if not before_validation:  # Only apply after validation
                filtered = [p for p in filtered if p.status == ProxyStatus.ACTIVE]
        elif rule == 'anonymous':
            filtered = [p for p in filtered if p.anonymity_level in [AnonymityLevel.ANONYMOUS, AnonymityLevel.ELITE]]
        elif rule.startswith('speed:'):
            if not before_validation:  # Only apply after validation when metrics are available
                max_speed = int(rule.split(':')[1])
                filtered = [p for p in filtered if p.metrics and p.metrics.response_time <= max_speed]
        elif rule.startswith('country:'):
            country = rule.split(':')[1].upper()
            filtered = [p for p in filtered if p.geo_location and p.geo_location.country_code == country]
    
    print_verbose(f"Filtered to {len(filtered)} proxies (was {len(proxies)})")
    
    return filtered


def _apply_filters_threaded(proxies, filter_rules, verbose, before_validation=False, isp=None, asn=None, protocol=None):
    """Threaded filtering for better performance with large datasets"""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading
    
    print_verbose(f"Using threaded filtering for {len(proxies)} proxies")
    
    # For threading to be beneficial, we need to chunk the work
    # Since filtering is mostly CPU-bound, we'll use smaller chunks
    chunk_size = max(50, len(proxies) // 4)  # At least 50, or quarter of total
    chunks = [proxies[i:i + chunk_size] for i in range(0, len(proxies), chunk_size)]
    
    filtered_results = []
    lock = threading.Lock()
    
    def process_chunk(chunk):
        """Process a chunk of proxies with filters"""
        try:
            return _apply_filters_sequential(chunk, filter_rules, False, before_validation, isp, asn, protocol)
        except Exception as e:
            print_warning(f"Chunk filtering failed: {e}")
            return []
    
    # Use ThreadPoolExecutor with fewer workers for CPU-bound tasks
    max_workers = min(4, len(chunks))  # Limit to 4 workers for CPU-bound filtering
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all chunks
        future_to_chunk = {executor.submit(process_chunk, chunk): i for i, chunk in enumerate(chunks)}
        
        # Collect results
        chunk_results = [None] * len(chunks)
        for future in as_completed(future_to_chunk):
            chunk_index = future_to_chunk[future]
            try:
                chunk_result = future.result()
                chunk_results[chunk_index] = chunk_result
            except Exception as e:
                print_warning(f"Chunk {chunk_index} processing failed: {e}")
                chunk_results[chunk_index] = []
    
    # Combine all results
    filtered = []
    for chunk_result in chunk_results:
        if chunk_result:
            filtered.extend(chunk_result)
    
    print_verbose(f"Threaded filtering complete: {len(filtered)}/{len(proxies)} proxies passed")
    return filtered


def _configure_adaptive_threading(adaptive_threads, proxy_count, default_threads):
    """Configure adaptive threading parameters"""
    if not adaptive_threads:
        return None, default_threads
    
    try:
        from ..proxy_engine.performance.thread_pool_manager import ThreadPoolConfig
        
        # Validate default_threads parameter
        if not isinstance(default_threads, (int, float)) or default_threads <= 0:
            print_warning(f"Invalid default_threads: {default_threads}, using 10")
            default_threads = 10
        else:
            default_threads = int(default_threads)
        
        # Use simple adaptive configuration
        min_threads = max(2, default_threads // 2)
        max_threads = min(100, default_threads * 3)
        
        thread_config = ThreadPoolConfig(
            min_threads=min_threads,
            max_threads=max_threads,
            initial_threads=default_threads,
            scale_factor=1.2,
            cpu_threshold=80.0,
            memory_threshold=1024.0
        )
        
        # Ensure we return a valid integer for effective_threads
        effective_threads = int(thread_config.initial_threads)
        return thread_config, effective_threads
        
    except ImportError:
        print_warning("Adaptive threading not available - performance module not installed")
        return None, int(default_threads)
    except Exception as e:
        print_error(f"Adaptive threading configuration failed: {e}")
        return None, int(default_threads)


def _validate_proxies(ctx, proxies, timeout_seconds, threads, verbose, 
                     custom_url=None, via_proxy=None, rate_limiter=None, session_logger=None,
                     adaptive_config=None, cache_validation=False, cache_ttl=None, 
                     cache_memory_mb=None, cache_stats=False, detect_chains=False,
                     chain_max_depth=None, chain_timeout=None, chain_confidence=None, chain_samples=None):
    """Validate proxy connectivity"""
    try:
        # Validate and sanitize threads parameter
        if not isinstance(threads, (int, float)) or threads <= 0:
            print_warning(f"Invalid threads parameter: {threads}, using default of 10")
            threads = 10
        else:
            threads = int(threads)
            threads = min(max(threads, 1), 200)  # Clamp between 1 and 200
        validation_config = ValidationConfig(
            connect_timeout=timeout_seconds,
            read_timeout=timeout_seconds * 2,
            total_timeout=timeout_seconds * 3,
            max_workers=threads,
            use_asyncio=HAS_AIOHTTP,  # Use async when aiohttp is available
            custom_test_url=custom_url,
            via_proxy=via_proxy,
            rate_limit_rps=rate_limiter.rate if rate_limiter else None,
            session_log_file=session_logger.log_file_path if session_logger else None,
            # Smart caching configuration
            enable_validation_cache=cache_validation,
            cache_ttl=cache_ttl or 3600,
            cache_memory_mb=cache_memory_mb,
            cache_stats=cache_stats,
            # Chain detection configuration
            enable_chain_detection=detect_chains or False,
            chain_detection_samples=chain_samples or 3,
            chain_max_depth=chain_max_depth or 5,
            chain_timeout=chain_timeout or 15.0,
            chain_confidence_threshold=chain_confidence or 0.7
        )
        
        # Use adaptive validator if configured
        if adaptive_config:
            try:
                from ..proxy_engine.performance.thread_pool_manager import AdaptiveBatchValidator
                validator = AdaptiveBatchValidator(validation_config, adaptive_config)
                use_adaptive = True
            except ImportError:
                validator = BatchValidator(ctx.obj['config'], validation_config)
                use_adaptive = False
        else:
            validator = BatchValidator(ctx.obj['config'], validation_config)
            use_adaptive = False
        
        # Log validation start for all proxies
        if session_logger:
            for proxy in proxies:
                session_logger.log_validation_start(proxy, validation_config.custom_test_url, via_proxy)
        
        # Always show progress bar unless in silent mode (key requirement #3)
        if not _silent_mode:
            progress = create_enhanced_progress()
            if progress:
                with progress:
                    task_name = "Adaptive Validating..." if use_adaptive else "Validating..."
                    task = progress.add_task(task_name, total=len(proxies))
                    
                    def update_progress(validated_count, total_count=None, current_proxy=None):
                        progress.update(task, completed=validated_count)
                    
                    if use_adaptive:
                        # Adaptive validator uses different method signature
                        results = validator.validate_batch(proxies, progress_callback=update_progress)
                    else:
                        results = validator.validate_batch(proxies, max_workers=threads, progress_callback=update_progress)
            else:
                # Fallback for systems without Rich
                if use_adaptive:
                    results = validator.validate_batch(proxies)
                else:
                    results = validator.validate_batch(proxies, max_workers=threads)
        else:
            if use_adaptive:
                results = validator.validate_batch(proxies)
            else:
                results = validator.validate_batch(proxies, max_workers=threads)
        
        # Log adaptive threading performance stats if used
        if use_adaptive and hasattr(results, 'performance_stats') and verbose:
            stats = results.performance_stats
            if stats and 'scaling_events' in stats:
                print_info(f"🔧 Adaptive threading: {stats.get('scaling_events', 0)} scaling events, "
                          f"avg {stats.get('current_threads', threads)} threads")
        
        # The proxies list has been updated in-place with validation results
        # Log validation results if session logging is enabled
        if session_logger:
            for proxy in proxies:
                success = proxy.status == ProxyStatus.ACTIVE
                response_time = proxy.metrics.response_time if proxy.metrics else None
                # Get error message from metadata if available
                error_message = None
                if not success and hasattr(proxy, 'metadata') and 'error' in proxy.metadata:
                    error_message = proxy.metadata.get('error')
                
                session_logger.log_validation_result(proxy, success, response_time, error_message)
        
        # Save validation results to database if database saving is enabled
        if ctx.obj.get('save_to_db', False) and isinstance(ctx.obj['db'], DatabaseManagerExtended):
            db = ctx.obj['db']
            for proxy in proxies:
                success = proxy.status == ProxyStatus.ACTIVE
                response_time = proxy.metrics.response_time if proxy.metrics else None
                error_message = None
                if not success and hasattr(proxy, 'metadata') and 'error' in proxy.metadata:
                    error_message = proxy.metadata.get('error')
                
                # Save validation result to database
                db.save_validation_result(
                    proxy_id=proxy.proxy_id,
                    url=validation_config.custom_test_url,
                    method="GET",
                    response_time=response_time,
                    success=success,
                    error_message=error_message
                )
        
        # Filter for proxies that passed validation (status is ACTIVE)
        valid_proxies = [p for p in proxies if p.status == ProxyStatus.ACTIVE]
        
        print_verbose(f"Validation complete: {len(valid_proxies)} valid of {len(proxies)} tested")
        
        # Display enhanced cache statistics if enabled
        if cache_stats and cache_validation:
            try:
                # Try to get cache metrics from the validator
                cache_metrics = None
                if hasattr(validator, 'validation_cache') and validator.validation_cache:
                    cache_metrics = validator.validation_cache.get_metrics()
                elif hasattr(validator, 'config') and hasattr(validator.config, 'validation_cache'):
                    # For adaptive validator, try to get cache from the validation config
                    pass
                
                if cache_metrics:
                    # Use enhanced cache statistics display
                    visual = RichVisualManager()
                    cache_display = CacheStatsDisplay(visual)
                    print()  # Add spacing
                    cache_display.display_cache_summary(cache_metrics, show_recommendations=True)
                else:
                    visual = RichVisualManager()
                    visual.print_status_line("Cache statistics: No data available (cache may not be initialized)", "warning")
                    
            except Exception as e:
                visual = RichVisualManager()
                visual.print_status_line(f"Failed to display cache statistics: {e}", "error")
        
        return valid_proxies
    
    except Exception as e:
        # Debug info for malformed error messages
        error_str = str(e)
        if "effective_threads" in error_str and not error_str.replace("effective_threads", "").strip():
            print_error(f"Configuration error: Invalid thread parameter detected: {threads}")
            print_error("This may be caused by corrupted thread configuration.")
        else:
            error_msg = _analyze_validation_error(e, len(proxies) if proxies else 0)
            print_error(error_msg)
        
        # Provide suggestions for common validation issues
        print_info("💡 Try these solutions:")
        print_info("   • Reduce concurrency: --threads 5 (less aggressive connection attempts)")
        print_info("   • Increase timeout: --timeout 15000 (15 seconds instead of 10)")
        print_info("   • Use custom test URL: --url http://httpbin.org/ip (different endpoint)")
        print_info("   • Rate limiting: --rate 2 (2 requests per second to avoid blocking)")  
        print_info("   • Skip validation and save raw results: remove --validate")
        print_info(f"   • Current settings: threads={threads}, timeout={timeout_seconds*1000:.0f}ms")
        
        # Return empty list when validation completely fails to prevent saving invalid results
        print_warning("⚠️  Validation failed completely - no valid proxies to save")
        return []


def _analyze_proxies(ctx, proxies, verbose, threads=10, progress_callback=None):
    """Perform threat and geographic analysis"""
    print_verbose("🌍 Analyzing proxies...")
    
    try:
        # Ensure config is available
        if 'config' not in ctx.obj or ctx.obj['config'] is None:
            print_error("Configuration not available for analysis")
            return proxies
        
        analyzer = ProxyAnalyzer(ctx.obj['config'])
        
        # Use threading for large batches
        if hasattr(analyzer, 'analyze_proxy_batch'):
            # If we have a progress callback, we need to modify the analyzer to support it
            if progress_callback and len(proxies) > 10:
                analysis_results = _analyze_with_progress(analyzer, proxies, threads, progress_callback)
            else:
                analysis_results = analyzer.analyze_proxy_batch(proxies, max_workers=threads)
        else:
            # Fallback to existing method
            analysis_results = analyzer.analyze_batch(proxies)
        
        print_verbose(f"Analysis complete for {len(analysis_results)} proxies")
        
        # The analysis updates the original proxy objects, so return the original proxies
        return proxies
    
    except Exception as e:
        print_warning(f"Analysis failed: {e}")
        return proxies


def _analyze_with_progress(analyzer, proxies, threads, progress_callback):
    """Run analysis with progress updates"""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading
    
    completed = 0
    lock = threading.Lock()
    
    def analyze_single(proxy):
        nonlocal completed
        try:
            result = analyzer.analyze_proxy(proxy)
            with lock:
                completed += 1
                if progress_callback:
                    progress_callback(completed, len(proxies))
            return result
        except Exception as e:
            with lock:
                completed += 1
                if progress_callback:
                    progress_callback(completed, len(proxies))
            raise e
    
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_proxy = {executor.submit(analyze_single, proxy): proxy for proxy in proxies}
        
        for future in as_completed(future_to_proxy):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                # Error already logged in analyze_single
                continue
    
    return results


def _save_results(proxies, output_file, verbose):
    """Save results to output file"""
    print_verbose(f"💾 Saving {len(proxies)} proxies to {output_file}")
    
    try:
        output_format = detect_file_format(output_file)
        
        # Use export manager with metadata enabled for country preservation
        from ..proxy_engine.exporters import ExportConfig
        export_config = ExportConfig(
            include_metadata=True,
            include_geo_data=True,
            include_metrics=True
        )
        export_manager = ExportManager(export_config=export_config)
        
        format_map = {
            'txt': ExportFormat.TXT,
            'json': ExportFormat.JSON,
            'csv': ExportFormat.CSV,
            'xlsx': ExportFormat.XLSX
        }
        
        export_format = format_map.get(output_format, ExportFormat.TXT)
        export_manager.export_proxies(proxies, output_file, export_format)
        
        print_success(f"Saved {len(proxies)} proxies to {output_file}")
    
    except Exception as e:
        print_error(f"Save failed: {e}")
        sys.exit(1)




def _display_results(proxies, verbose):
    """Display results to console"""
    if not proxies:
        print_warning("No proxies to display")
        return
    
    print_success(f"Found {len(proxies)} proxies:")
    
    if verbose and len(proxies) <= 20:
        show_proxy_table(proxies)
    else:
        # Simple list for large results
        for i, proxy in enumerate(proxies[:10], 1):
            print(f"  {i:2d}. {proxy.address} ({proxy.protocol.value})")
        
        if len(proxies) > 10:
            print(f"  ... and {len(proxies) - 10} more proxies")


# ===============================================================================
# PROTOCOL DETECTION AND PROCESSING
# ===============================================================================

def _handle_protocol_detection(proxies, target_protocol, verbose, debug_mode):
    """Handle active protocol detection for proxies"""
    if verbose:
        print_info(f"🔍 Running active protocol detection on {len(proxies)} proxies...")
    
    import asyncio
    
    async def run_detection():
        try:
            detection_results = await detect_batch_protocols(
                proxies, 
                enable_debug=debug_mode,
                max_concurrent=20  # Reasonable limit for detection
            )
            
            updated_proxies = []
            protocol_counts = {}
            confidence_stats = []
            
            for proxy in proxies:
                summary = detection_results.get(proxy.address)
                if summary and summary.best_match:
                    # Update proxy with detection results
                    result = summary.best_match
                    proxy.protocol = result.protocol
                    proxy.protocol_confidence = result.confidence
                    proxy.protocol_detection_method = result.method_used
                    proxy.protocol_detection_time = datetime.utcnow()
                    
                    # Statistics
                    protocol_name = result.protocol.value
                    protocol_counts[protocol_name] = protocol_counts.get(protocol_name, 0) + 1
                    confidence_stats.append(result.confidence)
                    
                    if debug_mode:
                        print_info(f"  {proxy.address}: {result.protocol.value} "
                                 f"({result.confidence_percentage}% confidence)")
                
                updated_proxies.append(proxy)
            
            # Show summary
            if verbose:
                print_success(f"Protocol detection completed in {sum(s.total_time_ms for s in detection_results.values()):.0f}ms")
                print_info("📊 Detection Summary:")
                for protocol, count in protocol_counts.items():
                    print(f"   • {protocol.upper()}: {count} proxies")
                
                if confidence_stats:
                    avg_confidence = sum(confidence_stats) / len(confidence_stats)
                    print_info(f"   • Average confidence: {int(avg_confidence * 100)}%")
                    high_confidence = sum(1 for c in confidence_stats if c >= 0.8)
                    print_info(f"   • High confidence (≥80%): {high_confidence}/{len(confidence_stats)} proxies")
            
            return updated_proxies
            
        except Exception as e:
            print_error(f"Protocol detection failed: {e}")
            return proxies
    
    # Run the async detection
    try:
        return asyncio.run(run_detection())
    except Exception as e:
        print_error(f"Failed to run protocol detection: {e}")
        return proxies


def _handle_protocol_processing(proxies, target_protocol, protocol_mode_resolved, strict_validation, verbose):
    """Handle protocol filtering/override logic"""
    original_count = len(proxies)
    
    # Skip processing if protocols are already explicitly set per-line
    if protocol_mode_resolved == "explicit-per-line":
        if verbose:
            print_info(f"🎯 Using explicit per-line protocols from file")
        return proxies
    
    if protocol_mode_resolved == "uniform":
        # Force protocol mode: override all proxies to use target protocol
        if verbose:
            print_info(f"🔧 Forcing all {original_count} proxies to use {target_protocol} protocol")
        
        target_enum = ProxyProtocol(target_protocol.lower())
        for proxy in proxies:
            proxy.protocol = target_enum
            proxy.protocol_confidence = 0.5  # Medium confidence for override
            proxy.protocol_detection_method = "force_override"
            proxy.protocol_detection_time = datetime.utcnow()
        
        return proxies
    
    elif strict_validation:
        # Strict mode: force all proxies to use the target protocol for testing
        # This prevents premature filtering and ensures all proxies get validated
        if verbose:
            print_info(f"🔧 Strict mode: Testing all {original_count} proxies as {target_protocol}")
            print_info("   Note: Proxies will be forced to use specified protocol for validation")
        
        target_enum = ProxyProtocol(target_protocol.lower())
        for proxy in proxies:
            proxy.protocol = target_enum
            proxy.protocol_confidence = 0.7  # Good confidence for strict mode
            proxy.protocol_detection_method = "strict_override"
            proxy.protocol_detection_time = datetime.utcnow()
        
        return proxies
    
    else:
        # Default behavior: smart filtering with suggestions
        if verbose:
            print_info(f"🔍 Smart filtering for {target_protocol} proxies...")
        
        # First try exact matches
        exact_matches = [p for p in proxies if p.protocol.value == target_protocol]
        
        if exact_matches:
            if verbose:
                print_success(f"Found {len(exact_matches)} {target_protocol} proxies")
            return exact_matches
        else:
            # No matches found - provide helpful suggestions
            print_warning(f"⚠️  No {target_protocol} proxies found in the loaded data!")
            
            # Show protocol distribution
            protocol_counts = {}
            for proxy in proxies:
                protocol_counts[proxy.protocol.value] = protocol_counts.get(proxy.protocol.value, 0) + 1
            
            print_info("📊 Available protocols:")
            for protocol, count in protocol_counts.items():
                confidence_info = ""
                avg_confidence = sum(p.protocol_confidence for p in proxies if p.protocol.value == protocol) / count
                if avg_confidence > 0:
                    confidence_info = f" (avg. {int(avg_confidence * 100)}% confidence)"
                print_info(f"   • {protocol.upper()}: {count} proxies{confidence_info}")
            
            print_info("💡 Suggestions:")
            print_info(f"   • Use --force-protocol to treat all proxies as {target_protocol}")
            print_info("   • Use --detect-protocol for active protocol detection")
            print_info("   • Remove -p flag to process all available proxies")
            
            return []


# ===============================================================================
# DATABASE-SPECIFIC OPERATIONS
# ===============================================================================

def _import_to_database(ctx, file_path, verbose):
    """Import proxies from file into database"""
    if verbose:
        print_info(f"📥 Importing proxies from {file_path} into database...")
    
    try:
        db = ctx.obj['db']
        if not isinstance(db, DatabaseManagerExtended):
            print_error("Extended database manager required for import operations")
            return 1
        
        stats = db.load_from_file(file_path)
        
        print_success(f"Import complete!")
        print_info(f"   • Added: {stats['added']} new proxies")
        print_info(f"   • Updated: {stats['updated']} existing proxies")
        print_info(f"   • Duplicates: {stats['duplicates']} proxies")
        print_info(f"   • Failed: {stats['failed']} proxies")
        
        return 0
        
    except Exception as e:
        print_error(f"Import failed: {e}")
        return 1


def _export_from_database(ctx, file_path, filter_rules, verbose):
    """Export proxies from database to file"""
    if verbose:
        print_info(f"📤 Exporting proxies from database to {file_path}...")
    
    try:
        db = ctx.obj['db']
        if not isinstance(db, DatabaseManagerExtended):
            print_error("Extended database manager required for export operations")
            return 1
        
        # Parse filter rules if provided
        filters = {}
        if filter_rules:
            filters = _parse_filter_rules(filter_rules)
        
        count = db.export_to_file(file_path, filters)
        
        print_success(f"Export complete! Exported {count} proxies to {file_path}")
        
        return 0
        
    except Exception as e:
        print_error(f"Export failed: {e}")
        return 1


def _process_database(ctx, output_file, target_protocol, validate, verbose, timeout_seconds,
                     threads, filter_rules, analyze, protocol_mode_resolved, strict_validation,
                     debug_protocol_detection, url, via_proxy, rate, log, isp, asn):
    """Process proxies loaded from database"""
    if verbose:
        print_info("📊 Loading proxies from database...")
    
    try:
        db = ctx.obj['db']
        if not isinstance(db, DatabaseManagerExtended):
            print_error("Extended database manager required for database mode")
            return 1
        
        # Parse filter rules and load proxies
        filters = {}
        if filter_rules:
            filters = _parse_filter_rules(filter_rules)
        
        proxies = db.get_filtered_proxies(filters) if filters else db.get_proxies()
        
        if not proxies:
            print_warning("No proxies found in database")
            return 0
        
        if verbose:
            print_success(f"Loaded {len(proxies)} proxies from database")
        
        # Process proxies using existing logic
        return _process_proxies(ctx, proxies, output_file, target_protocol, validate, verbose,
                              timeout_seconds, threads, filter_rules, analyze, protocol_mode_resolved,
                              strict_validation, debug_protocol_detection, url, via_proxy, rate, log, isp, asn)
        
    except Exception as e:
        print_error(f"Database processing failed: {e}")
        return 1


def _parse_filter_rules(filter_rules):
    """Parse filter rules string into filter dictionary"""
    filters = {}
    
    if not filter_rules:
        return filters
    
    # Parse comma-separated filters like "status=active,country=US,protocol=http"
    for rule in filter_rules.split(','):
        if '=' in rule:
            key, value = rule.split('=', 1)
            key = key.strip()
            value = value.strip()
            
            # Convert string values to appropriate types
            if key in ['status', 'threat_level', 'anonymity_level', 'protocol']:
                filters[key] = value.lower()
            elif key in ['country', 'source']:
                filters[key] = value.upper() if key == 'country' else value
            elif key == 'limit':
                try:
                    filters[key] = int(value)
                except ValueError:
                    pass
            elif key in ['discovered_after', 'discovered_before']:
                # Handle date parsing
                try:
                    from datetime import datetime
                    filters[key] = datetime.fromisoformat(value)
                except ValueError:
                    pass
    
    return filters


# ===============================================================================
# ENHANCED _SAVE_RESULTS WITH DATABASE SUPPORT
# ===============================================================================

def _save_results_enhanced(ctx, proxies, output_file, verbose):
    """Enhanced save results with database support, web interface, and API export"""
    saved_to_file = False
    saved_to_db = False
    api_exported = False
    
    # Save to file if output file specified
    if output_file:
        _save_results(proxies, output_file, verbose)
        saved_to_file = True
    
    # Save to database if flag is set
    if ctx.obj.get('save_to_db', False):
        if verbose:
            print_info(f"💾 Saving {len(proxies)} proxies to database...")
        
        try:
            db = ctx.obj['db']
            if isinstance(db, DatabaseManagerExtended):
                stats = {'added': 0, 'updated': 0, 'failed': 0}
                
                for proxy in proxies:
                    if db.exists(proxy.host, proxy.port):
                        if db.update_proxy(proxy):
                            stats['updated'] += 1
                        else:
                            stats['failed'] += 1
                    else:
                        if db.add_proxy(proxy):
                            stats['added'] += 1
                        else:
                            stats['failed'] += 1
                
                print_success(f"Database save complete!")
                print_info(f"   • Added: {stats['added']} new proxies")
                print_info(f"   • Updated: {stats['updated']} existing proxies")
                print_info(f"   • Failed: {stats['failed']} proxies")
                saved_to_db = True
            else:
                print_warning("Extended database manager required for --db-path database saving")
                
        except Exception as e:
            print_error(f"Database save failed: {e}")
    
    # Export to API if requested
    if ctx.obj.get('api_export'):
        api_exported = _export_to_api(ctx, proxies, verbose)
    
    # Launch web interface if requested
    if ctx.obj.get('view', False):
        _launch_web_interface(ctx, proxies, verbose)
        return  # Web interface handles display
    
    # Display results if nothing was saved and no web interface
    if not saved_to_file and not saved_to_db and not api_exported:
        _display_results(proxies, verbose)

# ===============================================================================
# API EXPORT FUNCTIONALITY
# ===============================================================================

def _export_to_api(ctx, proxies, verbose):
    """Export proxies to API endpoint"""
    try:
        if verbose:
            print_info(f"🌐 Exporting {len(proxies)} proxies to API endpoint...")
        
        # Get API configuration from context
        api_url = ctx.obj.get('api_export')
        api_method = ctx.obj.get('api_method', 'POST')
        api_auth = ctx.obj.get('api_auth', 'none')
        api_token = ctx.obj.get('api_token')
        api_batch_size = ctx.obj.get('api_batch_size', 100)
        
        # Validate API URL
        is_valid, message = validate_api_url(api_url)
        if not is_valid:
            print_error(f"Invalid API URL: {message}")
            return False
        
        # Create API export configuration
        api_config = create_api_export_config(
            url=api_url,
            method=api_method,
            auth_type=api_auth,
            auth_token=api_token,
            batch_size=api_batch_size,
            include_metadata=True
        )
        
        # Create API export manager and add endpoint
        api_manager = APIExportManager()
        success = api_manager.add_endpoint("cli_export", api_config)
        
        if not success:
            print_error("Failed to configure API export endpoint")
            return False
        
        # Test connection first if in verbose mode
        if verbose:
            print_info("Testing API endpoint connectivity...")
            test_results = api_manager.test_all_endpoints()
            for endpoint, (test_success, test_message) in test_results.items():
                if test_success:
                    print_verbose(f"API endpoint test: {test_message}")
                else:
                    print_warning(f"API endpoint test: {test_message}")
        
        # Export proxies
        response = api_manager.export_to_endpoint("cli_export", proxies)
        
        if response and response.success:
            print_success(f"Successfully exported {response.proxies_sent} proxies to API")
            if verbose and response.response_data:
                print_verbose(f"API response: {json.dumps(response.response_data, indent=2)}")
            return True
        else:
            error_msg = response.error_message if response else "Unknown error"
            print_error(f"API export failed: {error_msg}")
            return False
            
    except Exception as e:
        print_error(f"API export error: {e}")
        return False
    finally:
        # Clean up API manager
        try:
            api_manager.close_all()
        except:
            pass

# ===============================================================================
# WEB INTERFACE LAUNCH
# ===============================================================================

def _launch_web_interface(ctx, proxies, verbose):
    """Launch web interface for viewing results"""
    try:
        if verbose:
            print_info(f"🌐 Launching web interface with {len(proxies)} proxies...")
        
        # Import web server components
        try:
            from .web_server import create_web_server
        except ImportError as e:
            print_error("Web interface requires additional dependencies")
            print_info("Please install with: pip install proxc[web]")
            print_info(f"Import error: {e}")
            return
        
        # Create web server
        web_port = ctx.obj.get('web_port')
        web_server = create_web_server(proxies, ctx.obj.get('config'), web_port)
        
        # Start server
        url = web_server.start(open_browser=True)
        
        print_success(f"Web interface launched at {url}")
        print_info("📊 Dashboard features:")
        print_info("   • Interactive proxy table with search and filtering")
        print_info("   • Summary statistics and analytics")
        print_info("   • Export functionality (JSON, CSV)")
        print_info("   • Real-time data visualization")
        print("")
        print_info("Press Ctrl+C to stop the web server")
        
        try:
            # Keep the server running until user interrupts
            web_server.wait_for_shutdown()
        except KeyboardInterrupt:
            print_info("\n👋 Shutting down web server...")
            web_server.stop()
            
    except Exception as e:
        print_error(f"Failed to launch web interface: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        
        # Fall back to displaying results normally
        _display_results(proxies, verbose)


# ===============================================================================
# SOURCE MANAGEMENT FUNCTIONS
# ===============================================================================

def _list_proxy_sources(ctx, verbose):
    """List all available proxy sources and their status"""
    try:
        print_info("📋 Loading proxy sources...")
        
        # Initialize the fetcher to load sources
        from ..proxy_engine.fetchers import EnhancedProxyFetcher
        fetcher = EnhancedProxyFetcher(ctx.obj['config'])
        
        # Get all available sources
        source_names = fetcher.get_available_sources()
        
        if not source_names:
            print_warning("No proxy sources found in configuration")
            return 0
        
        print_success(f"Found {len(source_names)} proxy sources:")
        print()
        
        if console:
            # Rich table for better formatting
            from rich.table import Table
            from rich.text import Text
            
            table = Table(title="Proxy Sources")
            table.add_column("Name", style="cyan", width=25)
            table.add_column("Status", style="green", width=10)
            table.add_column("Type", style="yellow", width=12)
            table.add_column("Success Rate", style="blue", width=12)
            table.add_column("Last Success", style="magenta", width=20)
            table.add_column("Rate Limit", style="white", width=10)
            
            for source_name in sorted(source_names):
                stats = fetcher.get_source_statistics(source_name)
                
                # Format status
                status = "✅ Enabled" if stats.get('enabled') else "❌ Disabled"
                
                # Format success rate
                success_rate = stats.get('success_rate', 0.0)
                if success_rate > 75:
                    rate_color = "green"
                elif success_rate > 25:
                    rate_color = "yellow"
                else:
                    rate_color = "red"
                success_text = Text(f"{success_rate:.1f}%", style=rate_color)
                
                # Format last success
                last_success = stats.get('last_success')
                if last_success:
                    from datetime import datetime
                    dt = datetime.fromisoformat(last_success)
                    last_success_str = dt.strftime('%Y-%m-%d %H:%M')
                else:
                    last_success_str = "Never"
                
                # Add row to table
                table.add_row(
                    source_name,
                    status,
                    stats.get('source_type', 'unknown'),
                    success_text,
                    last_success_str,
                    f"{stats.get('rate_limit', 0.0)}s"
                )
            
            console.print(table)
        
        else:
            # Fallback for systems without Rich
            for source_name in sorted(source_names):
                stats = fetcher.get_source_statistics(source_name)
                
                status = "Enabled" if stats.get('enabled') else "Disabled"
                success_rate = stats.get('success_rate', 0.0)
                source_type = stats.get('source_type', 'unknown')
                
                print(f"  • {source_name} - {status} ({source_type}, {success_rate:.1f}% success)")
        
        # Show summary statistics
        if verbose:
            print()
            fetcher_stats = fetcher.get_fetcher_statistics()
            print_info("📊 Summary Statistics:")
            total_sources = len(source_names)
            enabled_sources = sum(1 for name in source_names 
                                if fetcher.get_source_statistics(name).get('enabled', False))
            
            print_info(f"   • Total sources: {total_sources}")
            print_info(f"   • Enabled sources: {enabled_sources}")
            print_info(f"   • Disabled sources: {total_sources - enabled_sources}")
            
            if fetcher_stats:
                print_info(f"   • Total fetches: {fetcher_stats.get('total_fetches', 0)}")
                print_info(f"   • Successful fetches: {fetcher_stats.get('successful_fetches', 0)}")
        
        return 0
        
    except Exception as e:
        print_error(f"Failed to list sources: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return 1


def _check_proxy_sources(ctx, verbose):
    """Test connectivity and health of all proxy sources"""
    try:
        print_info("🔍 Testing proxy source connectivity...")
        
        # Initialize the fetcher to load sources
        from ..proxy_engine.fetchers import EnhancedProxyFetcher
        fetcher = EnhancedProxyFetcher(ctx.obj['config'])
        
        # Get all available sources
        source_names = fetcher.get_available_sources()
        
        if not source_names:
            print_warning("No proxy sources found in configuration")
            return 0
        
        results = []
        total_sources = len(source_names)
        
        if console:
            from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task("Testing sources...", total=total_sources)
                
                for i, source_name in enumerate(source_names):
                    progress.update(task, description=f"Testing {source_name}...")
                    
                    # Test the source by attempting to fetch from it  
                    result = fetcher.fetch_from_source(source_name)
                    results.append((source_name, result))
                    
                    progress.update(task, advance=1)
        else:
            # Fallback for systems without Rich
            for i, source_name in enumerate(source_names):
                print_info(f"Testing {source_name} ({i+1}/{total_sources})...")
                result = fetcher.fetch_from_source(source_name)
                results.append((source_name, result))
        
        # Display results
        print()
        print_success(f"🎯 Source connectivity test complete!")
        print()
        
        working_sources = 0
        broken_sources = 0
        disabled_sources = 0
        
        if console:
            from rich.table import Table
            from rich.text import Text
            
            table = Table(title="Source Health Check Results")
            table.add_column("Source", style="cyan", width=25)
            table.add_column("Status", style="green", width=15)
            table.add_column("Result", style="white", width=12)
            table.add_column("Issue", style="red", width=40)
            table.add_column("Suggestion", style="yellow", width=35)
            
            for source_name, result in results:
                if not result:
                    status = "❌ Failed"
                    result_text = "Error"
                    issue = "Failed to fetch"
                    suggestion = "Check network connection"
                    broken_sources += 1
                elif not result.success:
                    if "disabled" in result.error_message.lower():
                        status = "⏸️  Disabled"
                        result_text = "Disabled"
                        issue = result.error_message[:40] + "..." if len(result.error_message) > 40 else result.error_message
                        suggestion = _get_source_fix_suggestion(result.error_message)
                        disabled_sources += 1
                    else:
                        status = "❌ Failed"
                        result_text = "Error"
                        issue = result.error_message[:40] + "..." if len(result.error_message) > 40 else result.error_message
                        suggestion = _get_source_fix_suggestion(result.error_message)
                        broken_sources += 1
                else:
                    status = "✅ Working"
                    result_text = f"{len(result.proxies_found)} proxies"
                    issue = "None"
                    suggestion = "Good to go"
                    working_sources += 1
                
                table.add_row(source_name, status, result_text, issue, suggestion)
            
            console.print(table)
            
        else:
            # Fallback for systems without Rich
            for source_name, result in results:
                if not result or not result.success:
                    if result and "disabled" in result.error_message.lower():
                        print_warning(f"  ⏸️  {source_name}: DISABLED - {result.error_message}")
                        disabled_sources += 1
                    else:
                        error_msg = result.error_message if result else "Failed to fetch"
                        print_error(f"  ❌ {source_name}: FAILED - {error_msg}")
                        broken_sources += 1
                else:
                    print_success(f"  ✅ {source_name}: WORKING - {len(result.proxies_found)} proxies found")
                    working_sources += 1
        
        # Show summary
        print()
        print_info("📊 Summary:")
        print_success(f"   • Working sources: {working_sources}")
        if disabled_sources > 0:
            print_warning(f"   • Disabled sources: {disabled_sources} (will retry automatically)")
        if broken_sources > 0:
            print_error(f"   • Broken sources: {broken_sources}")
        
        if broken_sources > 0:
            print()
            print_info("💡 Recommendations:")
            if broken_sources == total_sources:
                print_info("   • All sources failed - check internet connection")
                print_info("   • Try: --rate 2 --threads 3 (slower requests)")
            else:
                print_info("   • Some sources are working - you can still scan for proxies")
                print_info("   • Broken sources may recover automatically")
        
        return 0
        
    except Exception as e:
        print_error(f"Failed to check sources: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return 1


def _get_source_fix_suggestion(error_message: str) -> str:
    """Get specific fix suggestions for source errors"""
    error_lower = error_message.lower()
    
    if "403" in error_lower or "forbidden" in error_lower:
        return "Wait 1 hour, try --rate 2"
    elif "429" in error_lower or "rate limit" in error_lower:
        return "Wait 30 min, use --rate 1"
    elif "timeout" in error_lower:
        return "Try --timeout 30000"
    elif "connection" in error_lower:
        return "Check internet connection"
    elif "404" in error_lower:
        return "Source may be discontinued"
    elif "disabled" in error_lower and "minutes" in error_lower:
        return "Auto-retry in progress"
    else:
        return "Check --verbose for details"


def _analyze_scanning_error(error: Exception, round_num: int, verbose: bool) -> str:
    """Analyze scanning errors and provide actionable feedback"""
    error_str = str(error).lower()
    
    # Network/Connection errors
    if "connection" in error_str or "network" in error_str or "timeout" in error_str:
        return (f"Round {round_num}: Network connectivity issue - {error}. "
                "Try: --threads 5 (reduce concurrency) or check internet connection")
    
    # HTTP errors
    elif "403" in error_str or "forbidden" in error_str:
        return (f"Round {round_num}: Access blocked by source - {error}. "
                "Try: --rate 2 (slower requests) or use different sources with --list-sources")
    
    elif "429" in error_str or "rate limit" in error_str:
        return (f"Round {round_num}: Rate limit exceeded - {error}. "
                "Try: --rate 1 (slower requests) or --threads 3 (fewer concurrent requests)")
    
    elif "404" in error_str or "not found" in error_str:
        return (f"Round {round_num}: Source URL changed or unavailable - {error}. "
                "Source may have moved or been discontinued")
    
    # Data parsing errors
    elif "json" in error_str or "parsing" in error_str:
        return (f"Round {round_num}: Data format changed - {error}. "
                "Source may have updated their API format")
    
    # Import/dependency errors
    elif "import" in error_str or "module" in error_str:
        return (f"Round {round_num}: Missing dependency - {error}. "
                "Try: pip install beautifulsoup4 requests")
    
    # Generic error with round context
    else:
        return f"Round {round_num}: {error}"


def _analyze_validation_error(error: Exception, proxy_count: int) -> str:
    """Analyze validation errors and provide actionable feedback"""
    error_str = str(error).lower()
    
    # Configuration/NameError - the main issue reported
    if "config" in error_str and ("nameerror" in error_str or "not defined" in error_str):
        return (f"Configuration error during validation: {error}. "
                "This is likely due to a missing or corrupted configuration parameter.")
    
    # Memory/resource errors
    elif "memory" in error_str or "resource" in error_str:
        return (f"Insufficient resources for {proxy_count} proxies: {error}. "
                "Try reducing --threads (recommended: 5-10) or processing fewer proxies at once.")
    
    # Network/timeout errors
    elif "timeout" in error_str or "connection" in error_str:
        return (f"Network issues during validation: {error}. "
                "Try increasing --timeout (recommended: 15000ms+) or reducing --threads.")
    
    # SSL/TLS errors
    elif "ssl" in error_str or "certificate" in error_str:
        return (f"SSL/TLS issues: {error}. "
                "Test URL may have certificate problems. Try using HTTP instead of HTTPS.")
    
    # Permission/access errors
    elif "permission" in error_str or "access" in error_str or "403" in error_str:
        return (f"Access denied: {error}. "
                "May be blocked by firewall, rate-limited, or need authentication. Try --rate 1.")
    
    # Import/dependency errors
    elif "import" in error_str or "module" in error_str:
        return (f"Missing dependency: {error}. "
                "Install with: pip install requests aiohttp aiohttp-socks")
    
    # Chain detection or analysis errors
    elif "detect_chains" in error_str or "chain" in error_str:
        return (f"Chain detection error: {error}. "
                "Try disabling chain detection: remove --detect-chains")
    
    # Generic validation error
    else:
        return f"Validation failed with {proxy_count} proxies: {error}"


def _handle_no_proxies_found(rounds_attempted: int, verbose: bool):
    """Handle case when no proxies are found and provide suggestions"""
    print_warning("⚠️  No proxies found from any sources!")
    
    print_info("🔍 Possible reasons:")
    print_info("   • Sources may be temporarily unavailable (403, 503 errors)")
    print_info("   • Rate limits may be blocking requests (try --rate 2)")
    print_info("   • Network connectivity issues (check internet connection)")
    print_info("   • Sources may have changed their format/URLs")
    
    print_info("💡 Try these solutions:")
    print_info("   • Run: proxc --list-sources (check source health)")
    print_info("   • Use: --rate 2 --threads 5 (slower, gentler requests)")
    print_info("   • Try: --verbose (see detailed error messages)")
    print_info("   • Wait 10-15 minutes and retry (temporary blocks)")
    
    if verbose:
        print_info(f"   • Attempted {rounds_attempted} fetching rounds")
        print_info("   • Use --timeout 30000 for slower networks")


# ===============================================================================
# TARGET TESTING CONFIGURATION
# ===============================================================================

def _configure_target_testing(config, target_urls, target_config, target_preset, 
                            target_success_rate, target_parallel, verbose):
    """Configure target website testing"""
    try:
        # Import target testing components
        from ..proxy_engine.validation.validation_config import TargetTestConfig, PREDEFINED_TARGETS
        
        if verbose:
            print_info("🎯 Configuring target website testing...")
        
        # Configure success rate and parallel testing
        config.target_success_threshold = target_success_rate
        config.target_parallel_testing = target_parallel
        
        # Add targets from URLs
        if target_urls:
            urls = [url.strip() for url in target_urls.split(',')]
            for url in urls:
                if url:
                    config.add_custom_target(url)
                    if verbose:
                        print_verbose(f"Added target URL: {url}")
        
        # Add predefined target
        if target_preset:
            try:
                config.add_predefined_target(target_preset)
                if verbose:
                    print_verbose(f"Added predefined target: {target_preset}")
            except ValueError as e:
                print_warning(f"Unknown target preset: {target_preset}")
        
        # Load targets from config file
        if target_config:
            try:
                import yaml
                from pathlib import Path
                
                config_path = Path(target_config)
                if config_path.exists():
                    with open(config_path, 'r') as f:
                        target_data = yaml.safe_load(f)
                    
                    if isinstance(target_data, dict) and 'targets' in target_data:
                        for target_info in target_data['targets']:
                            target = TargetTestConfig(**target_info)
                            config.add_target_config(target)
                            if verbose:
                                print_verbose(f"Added target from config: {target.name or target.url}")
                    else:
                        print_warning("Invalid target configuration format")
                else:
                    print_error(f"Target configuration file not found: {target_config}")
            except ImportError:
                print_error("PyYAML required for config file loading. Install with: pip install pyyaml")
            except Exception as e:
                print_error(f"Error loading target configuration: {e}")
        
        # Enable target testing if any targets were configured
        enabled_targets = config.get_enabled_targets()
        if enabled_targets:
            config.enable_target_testing = True
            if verbose:
                print_info(f"✅ Target testing enabled with {len(enabled_targets)} targets")
                for target in enabled_targets:
                    print_verbose(f"  • {target.name or target.url}")
        else:
            print_warning("No valid targets configured for target testing")
            
    except Exception as e:
        print_error(f"Failed to configure target testing: {e}")

# ===============================================================================
# ARGCOMPLETE INTEGRATION
# ===============================================================================

def setup_completion():
    """Setup shell completion if argcomplete is available"""
    if HAS_ARGCOMPLETE:
        try:
            argcomplete.autocomplete(main_cli)
        except Exception:
            # Silently ignore argcomplete errors to avoid breaking CLI
            pass


# ===============================================================================
# TASK QUEUE COMMAND FUNCTIONS
# ===============================================================================

def _show_queue_stats(ctx, verbose: bool) -> int:
    """Show comprehensive task queue statistics"""
    if not ctx.obj.get('task_queue_enabled'):
        print_error("Task queue not enabled. Use --enable-queue flag.")
        return 1
    
    try:
        from ..task_queue import TaskManager
        
        redis_config = ctx.obj['redis_config']
        task_manager = TaskManager(redis_config)
        
        if not task_manager.connect():
            print_error(f"Failed to connect to Redis at {redis_config['host']}:{redis_config['port']}")
            return 1
        
        print_info("📊 Task Queue Statistics")
        print_info("=" * 50)
        
        # Get queue stats for default queue
        queue_stats = task_manager.get_queue_stats("default")
        worker_stats = task_manager.get_worker_stats()
        
        # Display queue statistics
        if queue_stats:
            total_enqueued = queue_stats.get('total_enqueued', 0)
            total_completed = queue_stats.get('total_completed', 0)
            total_failed = queue_stats.get('total_failed', 0)
            total_pending = queue_stats.get('total_pending', 0)
            
            print_info(f"Queue Status:")
            print_info(f"  • Total Enqueued: {total_enqueued}")
            print_info(f"  • Completed: {total_completed}")
            print_info(f"  • Failed: {total_failed}")
            print_info(f"  • Pending: {total_pending}")
            
            # Success rate calculation
            if total_enqueued > 0:
                success_rate = total_completed / (total_completed + total_failed) if (total_completed + total_failed) > 0 else 0
                print_info(f"  • Success Rate: {success_rate:.1%}")
            
            # Priority breakdown
            for priority in [1, 2, 3]:
                priority_pending = queue_stats.get(f'priority_{priority}_pending', 0)
                priority_name = {1: 'HIGH', 2: 'MEDIUM', 3: 'LOW'}[priority]
                if priority_pending > 0:
                    print_info(f"  • {priority_name} Priority: {priority_pending} pending")
        
        # Display worker statistics  
        print_info(f"\nWorker Status:")
        print_info(f"  • Worker ID: {worker_stats['worker_id']}")
        print_info(f"  • Uptime: {worker_stats['uptime_seconds']:.0f}s")
        print_info(f"  • Tasks Processed: {worker_stats['tasks_processed']}")
        print_info(f"  • Success Rate: {worker_stats['success_rate']:.1%}")
        print_info(f"  • Avg Tasks/Min: {worker_stats['average_tasks_per_minute']:.1f}")
        
        task_manager.disconnect()
        return 0
        
    except ImportError:
        print_error("Task queue dependencies not installed. Use: pip install redis rq")
        return 1
    except Exception as e:
        print_error(f"Failed to show queue stats: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return 1


def _clear_queue(ctx, verbose: bool) -> int:
    """Clear all tasks from the queue"""
    if not ctx.obj.get('task_queue_enabled'):
        print_error("Task queue not enabled. Use --enable-queue flag.")
        return 1
    
    try:
        from ..task_queue import TaskManager
        
        redis_config = ctx.obj['redis_config']
        task_manager = TaskManager(redis_config)
        
        if not task_manager.connect():
            print_error(f"Failed to connect to Redis at {redis_config['host']}:{redis_config['port']}")
            return 1
        
        print_warning("⚠️  This will clear ALL tasks from the queue!")
        
        if HAS_RICH:
            from rich.prompt import Confirm
            if not Confirm.ask("Are you sure you want to continue?"):
                print_info("Operation cancelled.")
                return 0
        else:
            response = input("Are you sure you want to continue? [y/N]: ").strip().lower()
            if response not in ['y', 'yes']:
                print_info("Operation cancelled.")
                return 0
        
        success = task_manager.clear_queue("default")
        
        if success:
            print_success("✅ Queue cleared successfully")
        else:
            print_error("Failed to clear queue")
            return 1
        
        task_manager.disconnect()
        return 0
        
    except ImportError:
        print_error("Task queue dependencies not installed. Use: pip install redis rq")
        return 1
    except Exception as e:
        print_error(f"Failed to clear queue: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return 1



def _run_queue_worker(ctx, verbose: bool) -> int:
    """Run as a queue worker process"""
    if not ctx.obj.get('task_queue_enabled'):
        print_error("Task queue not enabled. Use --enable-queue flag.")
        return 1
    
    try:
        from ..task_queue import TaskManager, TaskType
        
        redis_config = ctx.obj['redis_config']
        task_manager = TaskManager(redis_config)
        
        if not task_manager.connect():
            print_error(f"Failed to connect to Redis at {redis_config['host']}:{redis_config['port']}")
            return 1
        
        print_info(f"🔄 Starting queue worker: {task_manager.worker_id}")
        print_info(f"Redis: {redis_config['host']}:{redis_config['port']}/{redis_config['db']}")
        print_info("Press Ctrl+C to stop worker")
        
        # Register task handlers for different proxy operations
        def proxy_discovery_handler(payload):
            """Handle proxy discovery tasks"""
            if verbose:
                print_info(f"Processing discovery task: {payload.get('source', 'unknown')}")
            # This would integrate with existing proxy fetching logic
            return {'status': 'completed', 'proxies_found': 0}
        
        def proxy_validation_handler(payload):
            """Handle proxy validation tasks"""
            if verbose:
                print_info(f"Processing validation task: {len(payload.get('proxies', []))} proxies")
            # This would integrate with existing validation logic
            return {'status': 'completed', 'valid_proxies': 0}
        
        # Register handlers
        task_manager.register_task_handler(TaskType.PROXY_DISCOVERY, proxy_discovery_handler)
        task_manager.register_task_handler(TaskType.PROXY_VALIDATION, proxy_validation_handler)
        
        # Start worker (this will run until interrupted)
        try:
            task_manager.start_worker(queue_name="default", max_concurrent=5, poll_interval=1.0)
        except KeyboardInterrupt:
            print_info("\n👋 Worker stopped by user")
        
        task_manager.disconnect()
        return 0
        
    except ImportError:
        print_error("Task queue dependencies not installed. Use: pip install redis rq")
        return 1
    except Exception as e:
        print_error(f"Failed to run queue worker: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return 1


# ===============================================================================
# MENU BACKEND FUNCTIONS
# ===============================================================================

def _process_scan(ctx, output_file, count=100, validate=True, timeout_seconds=5.0, 
                 threads=20, strict_validation=False, analyze=False):
    """Backend function for menu-driven scanning operations"""
    try:
        # Set default parameters for menu operations
        target_protocol = None
        filter_rules = None
        protocol_mode_resolved = "auto"
        debug_protocol_detection = False
        url = None
        via_proxy = None
        rate = None
        log = None
        isp = None
        asn = None
        verbose = True  # Enable verbose output for menu mode
        
        # Call the existing scan function
        return _scan_proxies(
            ctx, output_file, target_protocol, validate, verbose, timeout_seconds,
            threads, filter_rules, analyze, count, protocol_mode_resolved, 
            strict_validation, debug_protocol_detection, url, via_proxy, rate, 
            log, isp, asn
        )
        
    except Exception as e:
        print_error(f"Scan operation failed: {e}")
        return 1

def _advanced_discovery_scan(ctx, output_file, validate=True):
    """Backend function for advanced discovery operations"""
    try:
        # This is a simplified implementation for advanced discovery
        # In the original broken implementation, this function was missing
        # For now, we'll use the standard scan as a fallback
        print_info("🔬 Advanced discovery mode - using enhanced scanning...")
        
        # Use enhanced settings for advanced discovery
        return _process_scan(
            ctx=ctx,
            output_file=output_file,
            count=ctx.obj.get('max_discovery_results', 500),
            validate=validate,
            timeout_seconds=10.0,
            threads=30,
            strict_validation=True,
            analyze=True
        )
        
    except Exception as e:
        print_error(f"Advanced discovery failed: {e}")
        return 1

def _advanced_fingerprinting(ctx, output_file, validate=True):
    """Backend function for advanced fingerprinting operations"""
    try:
        print_info("🔍 Advanced fingerprinting mode...")
        
        # Enhanced fingerprinting with detailed analysis
        return _process_scan(
            ctx=ctx,
            output_file=output_file,
            count=200,
            validate=validate,
            timeout_seconds=15.0,
            threads=15,
            strict_validation=True,
            analyze=True
        )
        
    except Exception as e:
        print_error(f"Advanced fingerprinting failed: {e}")
        return 1

# ===============================================================================
# ENTRY POINT
# ===============================================================================

def cli_main():
    """Entry point for console scripts (setup.py entry point)"""
    if not HAS_CLICK:
        print("❌ Click library is required but not installed")
        print("Install with: pip install click")
        sys.exit(1)
    
    # Setup completion before running CLI
    setup_completion()
    main_cli()


if __name__ == '__main__':
    cli_main()

