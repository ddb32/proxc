#!/usr/bin/env python3
"""
Setup configuration for ProxC
Configured to work with the existing project structure
"""

from setuptools import setup, find_packages
import os
from pathlib import Path

# Read the full description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8') if (this_directory / "README.md").exists() else ""

# Read the version from __init__.py file
def get_version():
    """Get the version from __init__.py file"""
    version_file = os.path.join(os.path.dirname(__file__), 'proxc', '__init__.py')
    try:
        with open(version_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip().startswith('__version__'):
                    # Extract the version from the string
                    return line.split('=')[1].strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return "3.0.0"  # Default version

# Essential required dependencies
REQUIRED = [
    "click>=8.0.0",          # CLI interface
    "requests>=2.28.0",      # HTTP requests
    "sqlalchemy>=1.4.0",     # Database ORM
    "pyyaml>=6.0",          # Configuration files
    "beautifulsoup4>=4.10.0", # HTML parser
    "argcomplete>=3.0.0",   # Shell completion
]

# Optional dependencies for advanced features
EXTRAS = {
    'full': [
        "rich>=13.0.0",        # Colorful and beautiful output
        "schedule>=1.2.0",     # Task scheduling
        "openpyxl>=3.0.0",     # Excel export
        "dnspython>=2.2.0",    # DNS checks
        "aiohttp>=3.8.0",      # Asynchronous requests
        "geoip2>=4.6.0",       # Geolocation
        "psutil>=5.9.0",       # System information
        "chardet>=5.0.0",      # Character encoding detection
        "lxml>=4.9.0",         # Fast XML parser
        "pandas>=1.5.0",       # Data analysis
        "prometheus_client>=0.15.0", # Metrics
    ],
    'cli': [
        "rich>=13.0.0",
        "schedule>=1.2.0",
    ],
    'monitoring': [
        "rich>=13.0.0",
        "psutil>=5.9.0",
        "prometheus_client>=0.15.0",
    ],
    'geolocation': [
        "geoip2>=4.6.0",
        "dnspython>=2.2.0",
    ],
    'export': [
        "openpyxl>=3.0.0",
        "pandas>=1.5.0",
    ],
    'async': [
        "aiohttp>=3.8.0",
    ],
    'dev': [
        "pytest>=7.0.0",
        "pytest-asyncio>=0.21.0",
        "pytest-cov>=4.0.0",
        "black>=22.0.0",
        "flake8>=5.0.0",
        "mypy>=1.0.0",
    ]
}

setup(
    # Basic package information
    name="proxc",
    version=get_version(),
    description="Advanced system for proxy management and validation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    
    # Developer information
    author="Neo",
    author_email="neo@example.com",
    url="https://github.com/neo/proxc",
    
    # License and classifications
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Internet :: Proxy Servers",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    keywords="proxy, proxc, validation, anonymity, security, networking",
    
    # Python requirements
    python_requires=">=3.8",
    
    # Packages and files
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'proxc': [
            'proxy_core/*.py',
            'proxy_engine/*.py', 
            'proxy_cli/*.py',
            '*.py',
        ],
    },
    
    # Dependencies
    install_requires=REQUIRED,
    extras_require=EXTRAS,
    
    # Entry points (Console Scripts)
    entry_points={
        'console_scripts': [
            # Main command
            'proxc=proxc.main:main',
            'proxc-cli=proxc.proxy_cli.cli:cli_main',
            'proxc-monitor=proxc.proxy_cli.monitor:start_dashboard_monitoring',
        ],
    },
    
    # Additional settings
    zip_safe=False,
    platforms=["any"],
    
    # Additional data files
    data_files=[],
    
    # System dependencies (if required)
    # dependency_links=[],
)
