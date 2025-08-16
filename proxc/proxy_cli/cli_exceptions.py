"""Proxy CLI Exception Hierarchy - Centralized exception handling for CLI components

This module provides a comprehensive exception hierarchy for CLI operations with
standardized error handling utilities and consistent error reporting.
"""

import logging
import sys
import traceback
from typing import Any, Dict, Optional, List
from datetime import datetime


class ProxyCLIError(Exception):
    """Base exception for all CLI-related errors"""
    
    def __init__(self, message: str, error_code: Optional[str] = None, 
                 context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.context = context or {}
        self.timestamp = datetime.utcnow()
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for logging/reporting"""
        return {
            'error_type': self.__class__.__name__,
            'error_code': self.error_code,
            'message': self.message,
            'context': self.context,
            'timestamp': self.timestamp.isoformat()
        }


class ConfigurationError(ProxyCLIError):
    """Configuration-related errors"""
    
    def __init__(self, message: str, config_file: Optional[str] = None, 
                 config_key: Optional[str] = None):
        context = {}
        if config_file:
            context['config_file'] = config_file
        if config_key:
            context['config_key'] = config_key
        super().__init__(message, "CONFIG_ERROR", context)


class CommandError(ProxyCLIError):
    """Command execution errors"""
    
    def __init__(self, message: str, command: Optional[str] = None, 
                 exit_code: Optional[int] = None):
        context = {}
        if command:
            context['command'] = command
        if exit_code is not None:
            context['exit_code'] = exit_code
        super().__init__(message, "COMMAND_ERROR", context)


class ValidationError(ProxyCLIError):
    """Input validation errors"""
    
    def __init__(self, message: str, field: Optional[str] = None, 
                 value: Optional[Any] = None, expected_type: Optional[str] = None):
        context = {}
        if field:
            context['field'] = field
        if value is not None:
            context['value'] = str(value)
        if expected_type:
            context['expected_type'] = expected_type
        super().__init__(message, "VALIDATION_ERROR", context)


class NetworkError(ProxyCLIError):
    """Network-related CLI errors"""
    
    def __init__(self, message: str, url: Optional[str] = None, 
                 status_code: Optional[int] = None, timeout: Optional[float] = None):
        context = {}
        if url:
            context['url'] = url
        if status_code is not None:
            context['status_code'] = status_code
        if timeout is not None:
            context['timeout'] = timeout
        super().__init__(message, "NETWORK_ERROR", context)


class InterfaceError(ProxyCLIError):
    """UI/Interface rendering errors"""
    
    def __init__(self, message: str, interface_type: Optional[str] = None, 
                 component: Optional[str] = None):
        context = {}
        if interface_type:
            context['interface_type'] = interface_type
        if component:
            context['component'] = component
        super().__init__(message, "INTERFACE_ERROR", context)


class SchedulerError(ProxyCLIError):
    """Scheduler operation errors"""
    
    def __init__(self, message: str, task_id: Optional[str] = None, 
                 scheduler_state: Optional[str] = None):
        context = {}
        if task_id:
            context['task_id'] = task_id
        if scheduler_state:
            context['scheduler_state'] = scheduler_state
        super().__init__(message, "SCHEDULER_ERROR", context)


class WebInterfaceError(ProxyCLIError):
    """Web interface specific errors"""
    
    def __init__(self, message: str, endpoint: Optional[str] = None, 
                 method: Optional[str] = None, port: Optional[int] = None):
        context = {}
        if endpoint:
            context['endpoint'] = endpoint
        if method:
            context['method'] = method
        if port is not None:
            context['port'] = port
        super().__init__(message, "WEB_ERROR", context)


class DependencyError(ProxyCLIError):
    """Missing dependency errors"""
    
    def __init__(self, message: str, package: Optional[str] = None, 
                 version: Optional[str] = None, install_cmd: Optional[str] = None):
        context = {}
        if package:
            context['package'] = package
        if version:
            context['version'] = version
        if install_cmd:
            context['install_cmd'] = install_cmd
        super().__init__(message, "DEPENDENCY_ERROR", context)


class CampaignError(ProxyCLIError):
    """Campaign operation errors"""
    
    def __init__(self, message: str, campaign_name: Optional[str] = None, 
                 operation: Optional[str] = None):
        context = {}
        if campaign_name:
            context['campaign_name'] = campaign_name
        if operation:
            context['operation'] = operation
        super().__init__(message, "CAMPAIGN_ERROR", context)


class SourceError(ProxyCLIError):
    """Source management errors"""
    
    def __init__(self, message: str, source_name: Optional[str] = None, 
                 source_type: Optional[str] = None, health_status: Optional[str] = None):
        context = {}
        if source_name:
            context['source_name'] = source_name
        if source_type:
            context['source_type'] = source_type
        if health_status:
            context['health_status'] = health_status
        super().__init__(message, "SOURCE_ERROR", context)


class CollectionError(ProxyCLIError):
    """Proxy collection errors"""
    
    def __init__(self, message: str, source_count: Optional[int] = None, 
                 proxies_collected: Optional[int] = None, duration: Optional[float] = None):
        context = {}
        if source_count is not None:
            context['source_count'] = source_count
        if proxies_collected is not None:
            context['proxies_collected'] = proxies_collected
        if duration is not None:
            context['duration'] = duration
        super().__init__(message, "COLLECTION_ERROR", context)


class APIError(ProxyCLIError):
    """REST API specific errors"""
    
    def __init__(self, message: str, endpoint: Optional[str] = None, 
                 method: Optional[str] = None, status_code: Optional[int] = None):
        context = {}
        if endpoint:
            context['endpoint'] = endpoint
        if method:
            context['method'] = method
        if status_code is not None:
            context['status_code'] = status_code
        super().__init__(message, "API_ERROR", context)


# Error handling utilities
class CLIErrorHandler:
    """Centralized error handling for CLI operations"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        
    def handle_error(self, error: Exception, context: Optional[Dict[str, Any]] = None, 
                    exit_on_error: bool = False) -> None:
        """Handle and log errors consistently"""
        
        if isinstance(error, ProxyCLIError):
            # Log structured CLI errors
            error_data = error.to_dict()
            if context:
                error_data['context'].update(context)
            
            self.logger.error(
                f"CLI Error: {error.message}",
                extra={'error_data': error_data}
            )
            
            # Print user-friendly error message
            self._print_user_error(error)
            
        else:
            # Handle unexpected errors
            self.logger.error(
                f"Unexpected error: {str(error)}",
                extra={
                    'error_type': type(error).__name__,
                    'traceback': traceback.format_exc(),
                    'context': context or {}
                }
            )
            
            # Print generic error message
            self._print_generic_error(error)
        
        if exit_on_error:
            sys.exit(1)
    
    def _print_user_error(self, error: ProxyCLIError) -> None:
        """Print user-friendly error message with actionable suggestions"""
        try:
            from ..cli_imports import get_cli_imports
            cli_imports = get_cli_imports()
            
            if cli_imports.has_rich:
                from rich.console import Console
                console = Console()
                console.print(f"[red]✗ Error: {error.message}[/red]", err=True)
                
                # Show additional context if available
                if error.context:
                    for key, value in error.context.items():
                        if key not in ['timestamp']:
                            console.print(f"  [dim]{key}: {value}[/dim]", err=True)
                
                # Add actionable suggestions based on error type
                suggestion = self._get_error_suggestion(error)
                if suggestion:
                    console.print(f"[yellow]💡 Suggestion: {suggestion}[/yellow]", err=True)
            else:
                print(f"✗ Error: {error.message}", file=sys.stderr)
                suggestion = self._get_error_suggestion(error)
                if suggestion:
                    print(f"💡 Suggestion: {suggestion}", file=sys.stderr)
                
        except ImportError:
            # Fallback to basic printing
            print(f"✗ {error.message}", file=sys.stderr)
    
    def _get_error_suggestion(self, error: ProxyCLIError) -> Optional[str]:
        """Get actionable suggestion based on error type and context"""
        error_type = type(error).__name__
        
        if error_type == "ConfigurationError":
            if 'config_file' in error.context:
                return f"Check configuration file syntax: {error.context['config_file']}"
            return "Run 'proxc --help' to see all configuration options"
        
        elif error_type == "DependencyError":
            if 'install_cmd' in error.context:
                return f"Install missing dependency: {error.context['install_cmd']}"
            elif 'package' in error.context:
                return f"Install required package: pip install {error.context['package']}"
            return "Run 'pip install proxc[full]' to install all optional dependencies"
        
        elif error_type == "ValidationError":
            if 'field' in error.context and 'expected_type' in error.context:
                return f"Provide valid {error.context['expected_type']} for {error.context['field']}"
            return "Check input format and try again"
        
        elif error_type == "NetworkError":
            if 'url' in error.context:
                return f"Check network connectivity and URL: {error.context['url']}"
            return "Verify network connection and proxy settings"
        
        elif error_type == "CommandError":
            if 'command' in error.context:
                return f"Check command syntax: proxc {error.context['command']} --help"
            return "Run 'proxc --help' to see available commands"
        
        elif error_type == "SourceError":
            if 'source_name' in error.context:
                return f"Check source configuration or try different source than {error.context['source_name']}"
            return "Run 'proxc manage sources list' to see available sources"
        
        elif error_type == "CollectionError":
            return "Try reducing thread count with --threads or increasing timeout with --timeout"
        
        elif error_type == "WebInterfaceError":
            if 'port' in error.context:
                return f"Try different port or check if port {error.context['port']} is already in use"
            return "Check if web server is already running or try different port"
        
        # Default suggestion
        return "Run 'proxc --help' for usage information or check the documentation"
    
    def _print_generic_error(self, error: Exception) -> None:
        """Print generic error message for unexpected errors"""
        try:
            from ..cli_imports import get_cli_imports
            cli_imports = get_cli_imports()
            
            if cli_imports.has_rich:
                from rich.console import Console
                console = Console()
                console.print(f"[red]✗ An unexpected error occurred: {str(error)}[/red]", err=True)
            else:
                print(f"✗ An unexpected error occurred: {str(error)}", file=sys.stderr)
                
        except ImportError:
            print(f"✗ An unexpected error occurred: {str(error)}", file=sys.stderr)


def handle_cli_error(func):
    """Decorator for consistent CLI error handling"""
    def wrapper(*args, **kwargs):
        error_handler = CLIErrorHandler()
        try:
            return func(*args, **kwargs)
        except ProxyCLIError as e:
            error_handler.handle_error(e, context={'function': func.__name__})
        except Exception as e:
            error_handler.handle_error(e, context={'function': func.__name__})
    
    return wrapper