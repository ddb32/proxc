#!/usr/bin/env python3
"""
ProxC - Simplified Main Entry Point

Runs the legacy CLI interface directly for consistent user experience.
"""

import os
import sys

# Add the parent directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .cli_base import get_cli_logger, setup_cli_logging
from .cli_exceptions import CommandError, CLIErrorHandler
from .cli_imports import get_cli_imports

# Setup logging and imports
cli_imports = get_cli_imports()
logger = get_cli_logger("main")
error_handler = CLIErrorHandler(logger)


def main():
    """
    Main entry point - runs the unified CLI interface
    """
    try:
        # Setup basic logging
        setup_cli_logging(verbose=False)
        
        # Import and run the CLI
        from .cli import setup_completion, main_cli
        
        # Setup completion if available
        if cli_imports.has_argcomplete:
            setup_completion()
        
        # Run CLI
        main_cli()
        
    except KeyboardInterrupt:
        print("\n⚡ Interrupted by user")
        sys.exit(130)
    except Exception as e:
        error_handler.handle_error(CommandError(f"Application failed: {e}"))
        sys.exit(1)


# Legacy entry points for backward compatibility
def proxyhunter_main():
    """Legacy entry point name"""
    main()


def proxc_main():
    """Alternative legacy entry point name"""
    main()


if __name__ == '__main__':
    main()