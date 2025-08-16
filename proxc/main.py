#!/usr/bin/env python3
"""
proxc - Main Entry Point
Production-ready main entry point with proper logging
"""

import sys
import os
import logging

def setup_logging():
    """Configure proper logging for the application"""
    # Determine logging level based on command line arguments
    verbose = '--verbose' in sys.argv or '-V' in sys.argv
    quiet = '--quiet' in sys.argv or '-q' in sys.argv
    silent = '--silent' in sys.argv
    
    if silent:
        log_level = logging.ERROR
    elif quiet:
        log_level = logging.WARNING
    elif verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARNING  # Default: minimal output without -V
    
    # Set up basic logging configuration
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set third-party loggers to WARNING to reduce noise
    third_party_loggers = ['requests', 'urllib3', 'sqlalchemy.engine']
    for logger_name in third_party_loggers:
        logging.getLogger(logger_name).setLevel(logging.WARNING)

def main():
    """Main entry point"""
    try:
        # Set up proper logging first
        setup_logging()
        logger = logging.getLogger(__name__)
        
        # Only show startup message in verbose/debug mode
        if '--verbose' in sys.argv or '-V' in sys.argv or '--debug' in sys.argv:
            logger.info("Starting proxc CLI")
        
        # Import simplified CLI after logging setup
        from proxc.proxy_cli.main import main as cli_main
        
        # Execute CLI system
        return cli_main()
        
    except ImportError as e:
        print(f"❌ CLI import error: {e}")
        print("📋 Please ensure the proxc module is properly installed")
        return 1
            
    except KeyboardInterrupt:
        print("\n👋 Cancelled by user, goodbye!")
        return 0
        
    except Exception as e:
        logging.error(f"Unexpected error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())