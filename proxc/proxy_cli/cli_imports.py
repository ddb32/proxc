"""Centralized Import Management for CLI Components

This module consolidates all optional dependency handling and provides
a consistent interface for CLI components to access third-party libraries.
Enhanced with integrated logging architecture for proper log level separation.
"""

import logging
import sys
import time
import os
from datetime import datetime
from typing import Optional, Any, Dict
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Use built-in ImportError since there's no custom ImportError in cli_exceptions

logger = logging.getLogger(__name__)


class EnhancedLoggingManager:
    """
    Enhanced logging architecture with proper level separation and file management.
    Integrates with existing print functions and provides structured logging.
    """
    
    def __init__(self, base_name: str = "proxyhunter"):
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
        """Initialize logging system with file separation"""
        # Create logs directory
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Setup formatters
        self.formatters = {
            'detailed': logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
            ),
            'simple': logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'),
            'console': logging.Formatter('%(message)s')
        }
        
        # Setup file handlers for each level
        self._setup_file_handlers(log_dir)
        
        # Setup main logger
        self.main_logger = logging.getLogger(self.base_name)
        self.main_logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers to avoid duplication
        self.main_logger.handlers.clear()
        
        # Add all file handlers to main logger
        for handler in self.handlers.values():
            self.main_logger.addHandler(handler)
    
    def _setup_file_handlers(self, log_dir: Path):
        """Setup rotating file handlers for different log levels"""
        level_files = {
            'DEBUG': 'debug.log',
            'INFO': 'info.log', 
            'WARNING': 'warnings.log',
            'ERROR': 'errors.log'
        }
        
        for level_name, filename in level_files.items():
            file_path = log_dir / filename
            
            # Create rotating file handler (5MB max, 3 backups)
            handler = RotatingFileHandler(
                file_path,
                maxBytes=5*1024*1024,  # 5MB
                backupCount=3
            )
            
            # Set level and formatter
            handler.setLevel(self.log_levels[level_name])
            handler.setFormatter(self.formatters['detailed'])
            
            # Create custom filter for level separation
            handler.addFilter(self._create_level_filter(level_name))
            
            self.handlers[level_name] = handler
    
    def _create_level_filter(self, target_level: str):
        """Create filter to only log specific level messages to specific files"""
        def level_filter(record):
            return record.levelname == target_level
        return level_filter
    
    def set_console_mode(self, quiet: bool = False, verbose: bool = False, silent: bool = False):
        """Configure console output verbosity"""
        self.quiet_mode = quiet
        self.verbose_mode = verbose
        self.silent_mode = silent
        
        if silent:
            self.console_level = logging.CRITICAL + 1  # Above CRITICAL
        elif quiet:
            self.console_level = logging.ERROR
        elif verbose:
            self.console_level = logging.DEBUG
        else:
            self.console_level = logging.INFO
    
    def log_structured(self, level: str, message: str, **context):
        """Log with structured context data"""
        log_level = self.log_levels.get(level.upper(), logging.INFO)
        
        # Merge context with session data
        full_context = {**self.context_data, **context}
        
        # Format message with context
        if context:
            context_str = " | ".join([f"{k}={v}" for k, v in context.items()])
            structured_message = f"{message} | {context_str}"
        else:
            structured_message = message
        
        # Log to file
        self.main_logger.log(log_level, structured_message)
        
        # Update metrics
        self.log_metrics['messages_logged'] += 1
        if level.upper() == 'ERROR':
            self.log_metrics['errors_logged'] += 1
        elif level.upper() == 'WARNING':
            self.log_metrics['warnings_logged'] += 1
        elif level.upper() == 'DEBUG':
            self.log_metrics['debug_messages'] += 1
    
    def start_operation_logging(self, operation_type: str, total_items: int = 0, **context):
        """Start logging for a specific operation"""
        self.context_data.update({
            'operation_type': operation_type,
            'total_items': total_items,
            'operation_start': time.time(),
            **context
        })
        
        self.log_structured('INFO', f"Starting operation: {operation_type}", 
                          total_items=total_items, **context)
    
    def get_log_metrics(self) -> Dict:
        """Get current logging metrics"""
        return {
            **self.log_metrics,
            'session_duration': time.time() - self.context_data['start_time'],
            'session_id': self.session_id
        }


class OptionalImports:
    """Centralized management of optional dependencies with enhanced logging"""
    
    def __init__(self):
        self._rich = None
        self._click = None
        self._console = None
        self._argcomplete = None
        
        # Initialize enhanced logging
        self.enhanced_logger = EnhancedLoggingManager()
        
        # Initialize imports
        self._init_rich()
        self._init_click()
        self._init_argcomplete()
        
    def _init_rich(self) -> None:
        """Initialize Rich library components"""
        try:
            from rich.console import Console
            from rich.table import Table
            from rich.panel import Panel
            from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
            from rich.text import Text
            from rich.prompt import Prompt, Confirm, IntPrompt
            from rich.columns import Columns
            from rich.layout import Layout
            from rich.live import Live
            from rich.align import Align
            from rich.markup import escape
            
            self._rich = {
                'Console': Console,
                'Table': Table,
                'Panel': Panel,
                'Progress': Progress,
                'SpinnerColumn': SpinnerColumn,
                'TextColumn': TextColumn,
                'BarColumn': BarColumn,
                'TimeElapsedColumn': TimeElapsedColumn,
                'TimeRemainingColumn': TimeRemainingColumn,
                'Text': Text,
                'Prompt': Prompt,
                'Confirm': Confirm,
                'IntPrompt': IntPrompt,
                'Columns': Columns,
                'Layout': Layout,
                'Live': Live,
                'Align': Align,
                'escape': escape
            }
            
            # Create console instance
            self._console = Console()
            logger.debug("Rich library initialized successfully")
            
        except ImportError:
            logger.warning("Rich library not available - using fallback text interface")
            self._rich = {}
    
    def _init_click(self) -> None:
        """Initialize Click library"""
        try:
            import click
            self._click = click
            logger.debug("Click library initialized successfully")
        except ImportError:
            logger.error("Click library required but not available")
            self._click = None
    
    def _init_argcomplete(self) -> None:
        """Initialize argcomplete library"""
        try:
            import argcomplete
            self._argcomplete = argcomplete
            logger.debug("Argcomplete library initialized successfully")
        except ImportError:
            logger.debug("Argcomplete library not available - tab completion disabled")
            self._argcomplete = None
    
    @property
    def has_rich(self) -> bool:
        """Check if Rich library is available"""
        return bool(self._rich)
    
    @property
    def has_click(self) -> bool:
        """Check if Click library is available"""
        return self._click is not None
    
    @property
    def has_argcomplete(self) -> bool:
        """Check if argcomplete is available"""
        return self._argcomplete is not None
    
    @property
    def rich(self) -> dict:
        """Get Rich library components"""
        return self._rich or {}
    
    @property
    def click(self):
        """Get Click library"""
        if not self.has_click:
            raise RuntimeError("Click library is required but not available")
        return self._click
    
    @property
    def console(self) -> Optional[Any]:
        """Get Rich console instance"""
        return self._console
    
    @property
    def argcomplete(self):
        """Get argcomplete library"""
        return self._argcomplete
    
    def require_rich(self) -> None:
        """Ensure Rich is available, raise error if not"""
        if not self.has_rich:
            raise RuntimeError("Rich library is required for this operation")
    
    def require_click(self) -> None:
        """Ensure Click is available, raise error if not"""
        if not self.has_click:
            raise RuntimeError("Click library is required for this operation")
    
    def create_table(self, **kwargs) -> Any:
        """Create Rich table with fallback"""
        if self.has_rich:
            return self.rich['Table'](**kwargs)
        else:
            # Fallback table implementation could go here
            return None
    
    def create_panel(self, content: str, **kwargs) -> Any:
        """Create Rich panel with fallback"""
        if self.has_rich:
            return self.rich['Panel'](content, **kwargs)
        else:
            # Fallback: just return content wrapped in basic formatting
            title = kwargs.get('title', '')
            if title:
                return f"\n=== {title} ===\n{content}\n"
            return content
    
    def print(self, *args, **kwargs) -> None:
        """Enhanced print with Rich support"""
        if self._console:
            self._console.print(*args, **kwargs)
        else:
            print(*args)
    
    def print_error(self, message: str, **context) -> None:
        """Print error message with appropriate formatting and logging"""
        # Log to file with structured data
        self.enhanced_logger.log_structured('ERROR', message, **context)
        
        # Console output (if not suppressed by quiet/silent mode)
        if not self.enhanced_logger.silent_mode:
            if self._console:
                self._console.print(f"❌ {message}", style="red")
            else:
                print(f"ERROR: {message}", file=sys.stderr)
    
    def print_warning(self, message: str, **context) -> None:
        """Print warning message with appropriate formatting and logging"""
        # Log to file with structured data
        self.enhanced_logger.log_structured('WARNING', message, **context)
        
        # Console output (respecting quiet mode)
        if not self.enhanced_logger.silent_mode and not self.enhanced_logger.quiet_mode:
            if self._console:
                self._console.print(f"⚠️  {message}", style="yellow")
            else:
                print(f"WARNING: {message}")
    
    def print_success(self, message: str, **context) -> None:
        """Print success message with appropriate formatting and logging"""
        # Log to file with structured data
        self.enhanced_logger.log_structured('INFO', f"SUCCESS: {message}", **context)
        
        # Console output (respecting quiet mode)
        if not self.enhanced_logger.silent_mode:
            if self._console:
                self._console.print(f"✅ {message}", style="green")
            else:
                print(f"SUCCESS: {message}")
    
    def print_info(self, message: str, **context) -> None:
        """Print info message with appropriate formatting and logging"""
        # Log to file with structured data
        self.enhanced_logger.log_structured('INFO', message, **context)
        
        # Console output (respecting quiet mode)
        if not self.enhanced_logger.silent_mode:
            if self._console:
                self._console.print(f"ℹ️  {message}", style="blue")
            else:
                print(f"INFO: {message}")
    
    def print_debug(self, message: str, **context) -> None:
        """Print debug message with appropriate formatting and logging"""
        # Log to file with structured data
        self.enhanced_logger.log_structured('DEBUG', message, **context)
        
        # Console output (only in verbose mode)
        if self.enhanced_logger.verbose_mode and not self.enhanced_logger.silent_mode:
            if self._console:
                self._console.print(f"🔍 {message}", style="dim")
            else:
                print(f"DEBUG: {message}")
    
    def print_header(self, message: str) -> None:
        """Print header message with appropriate formatting"""
        if self._console:
            self._console.print(f"\n🛡️  {message}", style="bold cyan")
        else:
            print(f"\n=== {message} ===")
    
    def print_step(self, step_num: int, message: str) -> None:
        """Print step message with numbering"""
        if self._console:
            self._console.print(f"[bold cyan]{step_num}.[/bold cyan] {message}")
        else:
            print(f"{step_num}. {message}")
    
    def print_result(self, label: str, value: str, success: bool = True) -> None:
        """Print result with label and value"""
        if self._console:
            style = "green" if success else "red"
            self._console.print(f"  [dim]{label}:[/dim] [{style}]{value}[/{style}]")
        else:
            status = "✓" if success else "✗"
            print(f"  {label}: {status} {value}")
    
    def configure_logging(self, quiet: bool = False, verbose: bool = False, silent: bool = False):
        """Configure enhanced logging modes"""
        self.enhanced_logger.set_console_mode(quiet=quiet, verbose=verbose, silent=silent)
    
    def start_operation_logging(self, operation_type: str, total_items: int = 0, **context):
        """Start structured logging for an operation"""
        self.enhanced_logger.start_operation_logging(operation_type, total_items, **context)
    
    def get_log_metrics(self):
        """Get logging performance metrics"""
        return self.enhanced_logger.get_log_metrics()
    
    def log_structured(self, level: str, message: str, **context):
        """Direct access to structured logging"""
        self.enhanced_logger.log_structured(level, message, **context)


# Global instance
_imports = None


def get_cli_imports() -> OptionalImports:
    """Get the global CLI imports instance"""
    global _imports
    if _imports is None:
        _imports = OptionalImports()
    return _imports


# Convenience functions for common operations
def has_rich() -> bool:
    """Check if Rich is available"""
    return get_cli_imports().has_rich


def has_click() -> bool:
    """Check if Click is available"""
    return get_cli_imports().has_click


def get_console() -> Optional[Any]:
    """Get Rich console instance"""
    return get_cli_imports().console


def print_cli(*args, **kwargs) -> None:
    """CLI print with Rich support"""
    get_cli_imports().print(*args, **kwargs)


def print_error(message: str) -> None:
    """Print CLI error message"""
    get_cli_imports().print_error(message)


def print_warning(message: str) -> None:
    """Print CLI warning message"""
    get_cli_imports().print_warning(message)


def print_success(message: str) -> None:
    """Print CLI success message"""
    get_cli_imports().print_success(message)


def print_info(message: str) -> None:
    """Print CLI info message"""
    get_cli_imports().print_info(message)


def print_debug(message: str) -> None:
    """Print CLI debug message"""
    get_cli_imports().print_debug(message)


def print_header(message: str) -> None:
    """Print CLI header message"""
    get_cli_imports().print_header(message)


def print_step(step_num: int, message: str) -> None:
    """Print CLI step message"""
    get_cli_imports().print_step(step_num, message)


def print_result(label: str, value: str, success: bool = True) -> None:
    """Print CLI result message"""
    get_cli_imports().print_result(label, value, success)


# Enhanced logging convenience functions
def configure_logging(quiet: bool = False, verbose: bool = False, silent: bool = False) -> None:
    """Configure enhanced logging modes"""
    get_cli_imports().configure_logging(quiet=quiet, verbose=verbose, silent=silent)


def start_operation_logging(operation_type: str, total_items: int = 0, **context) -> None:
    """Start structured logging for an operation"""
    get_cli_imports().start_operation_logging(operation_type, total_items, **context)


def get_log_metrics() -> Dict:
    """Get logging performance metrics"""
    return get_cli_imports().get_log_metrics()


def log_structured(level: str, message: str, **context) -> None:
    """Direct access to structured logging"""
    get_cli_imports().log_structured(level, message, **context)