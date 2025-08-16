"""Base CLI Components - Common functionality for CLI commands and interfaces"""

import logging
import sys
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .cli_exceptions import CommandError, ValidationError, CLIErrorHandler
from .cli_imports import get_cli_imports, print_error, print_success, print_warning


class CLIFormatterMixin:
    """Mixin class providing consistent formatting utilities for CLI components"""
    
    def __init__(self):
        self.imports = get_cli_imports()
    
    def format_table(self, data: List[Dict[str, Any]], 
                     columns: List[str], 
                     title: Optional[str] = None) -> Any:
        """Format data as a table with consistent styling"""
        if not self.imports.has_rich:
            # Fallback text table
            return self._format_text_table(data, columns, title)
        
        # Rich table
        table = self.imports.create_table(title=title, show_header=True, header_style="bold magenta")
        
        # Add columns
        for column in columns:
            table.add_column(column, style="cyan", no_wrap=False)
        
        # Add rows
        for row in data:
            table.add_row(*[str(row.get(col, "N/A")) for col in columns])
        
        return table
    
    def _format_text_table(self, data: List[Dict[str, Any]], 
                          columns: List[str], 
                          title: Optional[str] = None) -> str:
        """Fallback text table formatting"""
        output = []
        
        if title:
            output.append(f"\n=== {title} ===")
        
        if not data:
            output.append("No data available")
            return "\n".join(output)
        
        # Calculate column widths
        widths = {}
        for col in columns:
            widths[col] = max(len(col), max(len(str(row.get(col, "N/A"))) for row in data))
        
        # Header
        header = " | ".join(col.ljust(widths[col]) for col in columns)
        output.append(header)
        output.append("-" * len(header))
        
        # Rows
        for row in data:
            output.append(" | ".join(str(row.get(col, "N/A")).ljust(widths[col]) for col in columns))
        
        return "\n".join(output)
    
    def format_panel(self, content: str, title: Optional[str] = None, 
                    style: Optional[str] = None) -> Any:
        """Format content as a panel with consistent styling"""
        kwargs = {}
        if title:
            kwargs['title'] = title
        if style:
            kwargs['style'] = style
        
        return self.imports.create_panel(content, **kwargs)
    
    def format_status_indicator(self, status: Union[str, bool], 
                              good_values: Optional[List[str]] = None) -> str:
        """Format status with colored indicators"""
        if good_values is None:
            good_values = ['active', 'valid', 'success', 'ok', True]
        
        status_str = str(status).lower() if status is not None else 'unknown'
        
        if self.imports.has_rich:
            if status_str in [str(v).lower() for v in good_values]:
                return f"[green]✅ {status}[/green]"
            elif status_str in ['failed', 'invalid', 'error', 'false']:
                return f"[red]❌ {status}[/red]"
            else:
                return f"[yellow]⚠️  {status}[/yellow]"
        else:
            if status_str in [str(v).lower() for v in good_values]:
                return f"✅ {status}"
            elif status_str in ['failed', 'invalid', 'error', 'false']:
                return f"❌ {status}"
            else:
                return f"⚠️  {status}"
    
    def format_datetime(self, dt: datetime) -> str:
        """Format datetime consistently"""
        if dt is None:
            return "N/A"
        return dt.strftime("%Y-%m-%d %H:%M:%S")


class BaseCLICommand(ABC, CLIFormatterMixin):
    """Base class for all CLI commands with common functionality"""
    
    def __init__(self, name: str, description: str):
        super().__init__()
        self.name = name
        self.description = description
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @abstractmethod
    def execute(self, *args, **kwargs) -> bool:
        """Execute the command - must be implemented by subclasses"""
        pass
    
    def validate_parameters(self, **kwargs) -> None:
        """Validate command parameters - override in subclasses"""
        pass
    
    def handle_error(self, error: Exception) -> None:
        """Standard error handling for commands"""
        error_msg = str(error)
        self.logger.error(f"Command '{self.name}' failed: {error_msg}")
        print_error(f"Command failed: {error_msg}")
    
    def print_result(self, result: Any, success: bool = True) -> None:
        """Print command result with consistent formatting"""
        if success:
            print_success(f"Command '{self.name}' completed successfully")
            if result is not None:
                self.imports.print(result)
        else:
            print_error(f"Command '{self.name}' failed")


class CLIProgressTracker:
    """Consistent progress tracking across CLI components"""
    
    def __init__(self, description: str = "Processing..."):
        self.imports = get_cli_imports()
        self.description = description
        self._progress = None
        self._task = None
    
    def start(self, total: Optional[int] = None) -> None:
        """Start progress tracking"""
        if self.imports.has_rich:
            self._progress = self.imports.rich['Progress'](
                self.imports.rich['SpinnerColumn'](),
                self.imports.rich['TextColumn']("[bold blue]{task.description}"),
                self.imports.rich['BarColumn'](style="blue", complete_style="green"),
                self.imports.rich['TextColumn']("[progress.percentage]{task.percentage:>3.0f}%"),
                self.imports.rich['TextColumn']("•"),
                self.imports.rich['TextColumn']("{task.completed}/{task.total}"),
                self.imports.rich['TimeElapsedColumn'](),
                self.imports.rich['TimeRemainingColumn'](),
            )
            self._progress.start()
            self._task = self._progress.add_task(self.description, total=total)
        else:
            total_info = f" (0/{total})" if total else ""
            print(f"🚀 {self.description}{total_info}")
    
    def update(self, advance: int = 1, description: Optional[str] = None) -> None:
        """Update progress"""
        if self._progress and self._task:
            if description:
                self._progress.update(self._task, description=description, advance=advance)
            else:
                self._progress.update(self._task, advance=advance)
        else:
            # Show periodic updates for text mode
            current = getattr(self, '_current', 0) + advance
            setattr(self, '_current', current)
            if current % 10 == 0 or advance > 1:
                print(f"  {current} completed...", flush=True)
            else:
                print(".", end="", flush=True)
    
    def complete(self, success: bool = True) -> None:
        """Complete progress tracking"""
        if self._progress:
            self._progress.stop()
        else:
            current = getattr(self, '_current', 0)
            status = "✅ Completed" if success else "❌ Failed"
            print(f"\n{status}! Processed {current} items.")
    
    def set_status(self, status: str) -> None:
        """Set current status description"""
        if self._progress and self._task:
            self._progress.update(self._task, description=f"{self.description} - {status}")
        else:
            print(f"  Status: {status}")
    
    def show_summary(self, stats: Dict[str, Any]) -> None:
        """Show operation summary with key statistics"""
        if self.imports.has_rich:
            from rich.table import Table
            from rich.console import Console
            console = Console()
            
            # Create summary table
            table = Table(title="📊 Operation Summary", show_header=True, header_style="bold cyan")
            table.add_column("Metric", style="cyan", no_wrap=True)
            table.add_column("Value", style="green", no_wrap=True)
            
            # Add statistics
            for key, value in stats.items():
                # Format key nicely
                formatted_key = key.replace('_', ' ').title()
                formatted_value = str(value)
                
                # Add special formatting for certain metrics
                if 'time' in key.lower() or 'duration' in key.lower():
                    try:
                        formatted_value = f"{float(value):.2f}s"
                    except (ValueError, TypeError):
                        pass
                elif 'rate' in key.lower() or 'percentage' in key.lower():
                    try:
                        formatted_value = f"{float(value):.1f}%"
                    except (ValueError, TypeError):
                        pass
                elif 'count' in key.lower() or 'total' in key.lower():
                    try:
                        formatted_value = f"{int(value):,}"
                    except (ValueError, TypeError):
                        pass
                
                table.add_row(formatted_key, formatted_value)
            
            console.print(table)
        else:
            print("\n📊 Operation Summary:")
            print("-" * 30)
            for key, value in stats.items():
                formatted_key = key.replace('_', ' ').title()
                print(f"  {formatted_key}: {value}")
            print("-" * 30)


class CLIConfigManager:
    """Centralized configuration management for CLI components"""
    
    def __init__(self):
        self.settings = {
            'output_format': 'table',  # table, json, text
            'color_output': True,
            'verbose_logging': False,
            'page_size': 50,
            'timeout': 30,
            'max_workers': 10
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.settings.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value"""
        self.settings[key] = value
    
    def update(self, **kwargs) -> None:
        """Update multiple configuration values"""
        self.settings.update(kwargs)
    
    def is_color_enabled(self) -> bool:
        """Check if colored output is enabled"""
        return self.get('color_output', True) and get_cli_imports().has_rich


# Global CLI configuration instance
_cli_config = None


def get_cli_config() -> CLIConfigManager:
    """Get global CLI configuration instance"""
    global _cli_config
    if _cli_config is None:
        _cli_config = CLIConfigManager()
    return _cli_config


class CLILoggingManager:
    """Centralized logging management for CLI operations"""
    
    def __init__(self, name: str = "proxc_cli", log_dir: Optional[Path] = None):
        self.name = name
        self.log_dir = log_dir or Path("logs")
        self.loggers = {}
        self.handlers = {}
        self._setup_base_logging()
    
    def _setup_base_logging(self) -> None:
        """Setup base logging configuration"""
        # Create log directory if it doesn't exist
        self.log_dir.mkdir(exist_ok=True)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers to avoid duplication
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        simple_formatter = logging.Formatter(
            fmt='%(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(simple_formatter)
        root_logger.addHandler(console_handler)
        self.handlers['console'] = console_handler
        
        # File handler for all logs
        file_handler = logging.FileHandler(
            self.log_dir / f"{self.name}.log", mode='a', encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(file_handler)
        self.handlers['file'] = file_handler
        
        # Error file handler
        error_handler = logging.FileHandler(
            self.log_dir / f"{self.name}_errors.log", mode='a', encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(error_handler)
        self.handlers['errors'] = error_handler
    
    def get_logger(self, name: str, level: int = logging.INFO) -> logging.Logger:
        """Get or create a logger with consistent configuration"""
        full_name = f"{self.name}.{name}"
        
        if full_name in self.loggers:
            return self.loggers[full_name]
        
        logger = logging.getLogger(full_name)
        logger.setLevel(level)
        
        # Store logger reference
        self.loggers[full_name] = logger
        
        return logger
    
    def set_console_level(self, level: int) -> None:
        """Set console logging level"""
        if 'console' in self.handlers:
            self.handlers['console'].setLevel(level)
    
    def set_file_level(self, level: int) -> None:
        """Set file logging level"""
        if 'file' in self.handlers:
            self.handlers['file'].setLevel(level)
    
    def enable_verbose_logging(self) -> None:
        """Enable verbose logging (DEBUG level to console)"""
        self.set_console_level(logging.DEBUG)
    
    def disable_verbose_logging(self) -> None:
        """Disable verbose logging (WARNING level to console)"""
        self.set_console_level(logging.WARNING)
    
    def add_command_context(self, logger: logging.Logger, command: str, 
                           user: Optional[str] = None) -> logging.LoggerAdapter:
        """Add command context to logger"""
        extra = {'command': command}
        if user:
            extra['user'] = user
        
        return logging.LoggerAdapter(logger, extra)
    
    def log_command_start(self, logger: logging.Logger, command: str, 
                         parameters: Optional[Dict[str, Any]] = None) -> None:
        """Log command execution start"""
        message = f"Command started: {command}"
        if parameters:
            message += f" with parameters: {parameters}"
        logger.info(message)
    
    def log_command_success(self, logger: logging.Logger, command: str, 
                           duration: Optional[float] = None, 
                           result_summary: Optional[str] = None) -> None:
        """Log successful command completion"""
        message = f"Command completed successfully: {command}"
        if duration:
            message += f" (duration: {duration:.2f}s)"
        if result_summary:
            message += f" - {result_summary}"
        logger.info(message)
    
    def log_command_failure(self, logger: logging.Logger, command: str, 
                           error: Exception, duration: Optional[float] = None) -> None:
        """Log command failure"""
        message = f"Command failed: {command}"
        if duration:
            message += f" (duration: {duration:.2f}s)"
        message += f" - Error: {str(error)}"
        logger.error(message, exc_info=True)
    
    def cleanup_old_logs(self, days_to_keep: int = 7) -> None:
        """Clean up old log files"""
        cutoff_time = datetime.now().timestamp() - (days_to_keep * 24 * 3600)
        
        for log_file in self.log_dir.glob("*.log"):
            if log_file.stat().st_mtime < cutoff_time:
                try:
                    log_file.unlink()
                except OSError:
                    pass  # Ignore if file is locked or permission denied


# Global logging manager instance
_logging_manager = None


def get_cli_logger(name: str) -> logging.Logger:
    """Get a CLI logger with standardized configuration"""
    global _logging_manager
    if _logging_manager is None:
        _logging_manager = CLILoggingManager()
    return _logging_manager.get_logger(name)


def setup_cli_logging(verbose: bool = False, log_dir: Optional[Path] = None) -> CLILoggingManager:
    """Setup CLI logging with optional verbose mode"""
    global _logging_manager
    
    if _logging_manager is None:
        _logging_manager = CLILoggingManager(log_dir=log_dir)
    
    if verbose:
        _logging_manager.enable_verbose_logging()
    
    return _logging_manager