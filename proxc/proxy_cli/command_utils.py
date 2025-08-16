"""CLI Command Utilities - Common patterns and helpers for CLI commands"""

import sys
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from .cli_base import get_cli_logger, CLIProgressTracker
from .cli_exceptions import CommandError, ValidationError, CLIErrorHandler
from .cli_imports import get_cli_imports

# Initialize imports
cli_imports = get_cli_imports()
logger = get_cli_logger("command_utils")


def command_with_error_handling(func: Callable) -> Callable:
    """Decorator that adds standardized error handling to CLI commands"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        error_handler = CLIErrorHandler(logger)
        try:
            return func(*args, **kwargs)
        except Exception as e:
            command_error = CommandError(
                f"Command '{func.__name__}' failed",
                command=func.__name__
            )
            error_handler.handle_error(command_error, context={'original_error': str(e)})
            sys.exit(1)
    return wrapper


def validate_file_path(file_path: str, must_exist: bool = True, create_parent: bool = False) -> Path:
    """Validate and return Path object with optional parent directory creation"""
    try:
        path = Path(file_path)
        
        if must_exist and not path.exists():
            raise ValidationError(
                f"File does not exist: {file_path}",
                field="file_path",
                value=file_path
            )
        
        if create_parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Created parent directory: {path.parent}")
        
        return path
        
    except Exception as e:
        raise ValidationError(
            f"Invalid file path: {file_path}",
            field="file_path", 
            value=file_path
        )


def validate_output_format(format_str: str) -> str:
    """Validate output format and return normalized version"""
    valid_formats = ['json', 'csv', 'txt', 'xlsx']
    format_lower = format_str.lower()
    
    if format_lower not in valid_formats:
        raise ValidationError(
            f"Unsupported output format: {format_str}",
            field="format",
            value=format_str,
            expected_type=f"one of {valid_formats}"
        )
    
    return format_lower


def validate_count_limit(count: Optional[int], max_limit: int = 100000) -> Optional[int]:
    """Validate count parameter with reasonable limits"""
    if count is None:
        return None
    
    if count <= 0:
        raise ValidationError(
            "Count must be a positive integer",
            field="count",
            value=count,
            expected_type="positive integer"
        )
    
    if count > max_limit:
        raise ValidationError(
            f"Count exceeds maximum limit of {max_limit}",
            field="count",
            value=count
        )
    
    return count


def validate_timeout(timeout: Optional[int], min_timeout: int = 1, max_timeout: int = 300) -> Optional[int]:
    """Validate timeout parameter with reasonable bounds"""
    if timeout is None:
        return None
    
    if timeout < min_timeout:
        raise ValidationError(
            f"Timeout must be at least {min_timeout} seconds",
            field="timeout",
            value=timeout
        )
    
    if timeout > max_timeout:
        raise ValidationError(
            f"Timeout cannot exceed {max_timeout} seconds",
            field="timeout",
            value=timeout
        )
    
    return timeout


def show_progress_with_results(
    operation_name: str,
    total_items: Optional[int] = None,
    show_summary: bool = True
) -> CLIProgressTracker:
    """Create and return a progress tracker for operations"""
    tracker = CLIProgressTracker(f"{operation_name}...")
    tracker.start(total=total_items)
    return tracker


def format_duration(seconds: float) -> str:
    """Format duration in a human-readable way"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def format_size(bytes_count: int) -> str:
    """Format byte count in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_count < 1024:
            return f"{bytes_count:.1f}{unit}"
        bytes_count /= 1024
    return f"{bytes_count:.1f}TB"


def print_summary_table(data: List[Dict[str, Any]], title: str = "Summary") -> None:
    """Print a summary table with Rich formatting if available"""
    if not data:
        print(f"{title}: No data to display")
        return
    
    if cli_imports.has_rich:
        from rich.console import Console
        from rich.table import Table
        
        console = Console()
        table = Table(title=title)
        
        # Add columns based on first row keys
        if data:
            for key in data[0].keys():
                table.add_column(key.replace('_', ' ').title(), style="cyan")
            
            # Add rows
            for row in data:
                table.add_row(*[str(value) for value in row.values()])
        
        console.print(table)
    else:
        # Fallback text table
        print(f"\n{title}:")
        print("-" * (len(title) + 1))
        
        if data:
            # Print header
            headers = list(data[0].keys())
            print(" | ".join(header.replace('_', ' ').title() for header in headers))
            print("-" * (len(" | ".join(headers)) + 10))
            
            # Print rows
            for row in data:
                print(" | ".join(str(row.get(header, 'N/A')) for header in headers))


def confirm_destructive_action(action: str, target: str = "") -> bool:
    """Ask for user confirmation on destructive actions"""
    if cli_imports.has_rich:
        from rich.console import Console
        from rich.prompt import Confirm
        
        console = Console()
        message = f"Are you sure you want to {action}"
        if target:
            message += f" {target}"
        message += "?"
        
        return Confirm.ask(f"[yellow]{message}[/yellow]", default=False)
    else:
        # Fallback confirmation
        message = f"Are you sure you want to {action}"
        if target:
            message += f" {target}"
        message += "? (y/N): "
        
        response = input(message).strip().lower()
        return response in ['y', 'yes']


def get_user_input(prompt: str, default: Optional[str] = None, choices: Optional[List[str]] = None) -> str:
    """Get user input with validation and Rich formatting if available"""
    if cli_imports.has_rich:
        from rich.console import Console
        from rich.prompt import Prompt
        
        console = Console()
        
        if choices:
            return Prompt.ask(f"[cyan]{prompt}[/cyan]", choices=choices, default=default)
        else:
            return Prompt.ask(f"[cyan]{prompt}[/cyan]", default=default)
    else:
        # Fallback input
        if choices:
            prompt += f" ({'/'.join(choices)})"
        if default:
            prompt += f" [{default}]"
        prompt += ": "
        
        response = input(prompt).strip()
        return response or default or ""


def handle_file_output(data: Any, output_path: str, format: str = "auto") -> bool:
    """Handle file output with format detection and error handling"""
    try:
        path = validate_file_path(output_path, must_exist=False, create_parent=True)
        
        # Auto-detect format if needed
        if format == "auto":
            format = path.suffix.lower().lstrip('.')
            if not format:
                format = "txt"
        
        format = validate_output_format(format)
        
        # Write file based on format
        if format == "json":
            import json
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        elif format == "csv":
            import csv
            with open(path, 'w', newline='', encoding='utf-8') as f:
                if isinstance(data, list) and data and isinstance(data[0], dict):
                    writer = csv.DictWriter(f, fieldnames=data[0].keys())
                    writer.writeheader()
                    writer.writerows(data)
                else:
                    writer = csv.writer(f)
                    if isinstance(data, list):
                        writer.writerows(data)
                    else:
                        writer.writerow([data])
        else:  # txt format
            with open(path, 'w', encoding='utf-8') as f:
                if isinstance(data, (list, dict)):
                    import json
                    f.write(json.dumps(data, indent=2, ensure_ascii=False))
                else:
                    f.write(str(data))
        
        logger.info(f"Output written to: {path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to write output file: {e}")
        return False


# Common Click option decorators for consistency
def add_output_options(func: Callable) -> Callable:
    """Add common output-related options to a Click command"""
    import click
    
    @click.option('--output', '-o', type=click.Path(), help='Output file path')
    @click.option('--format', '-f', type=click.Choice(['json', 'csv', 'txt']), default='json', help='Output format')
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper


def add_validation_options(func: Callable) -> Callable:
    """Add common validation-related options to a Click command"""
    import click
    
    @click.option('--validate/--no-validate', default=False, help='Enable proxy validation')
    @click.option('--timeout', '-t', type=int, default=10, help='Validation timeout in seconds')
    @click.option('--threads', type=int, default=10, help='Number of validation threads')
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper


def add_common_options(func: Callable) -> Callable:
    """Add the most common CLI options to a command"""
    import click
    
    @click.option('--count', '-c', type=int, help='Limit number of items to process')
    @click.option('--quiet', '-q', is_flag=True, help='Quiet output mode')
    @click.option('--verbose', '-v', is_flag=True, help='Verbose output mode')
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper