"""Platform Detection and Utilities - Cross-platform compatibility helpers"""

import os
import platform
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple, Any
import logging

logger = logging.getLogger(__name__)


def is_termux() -> bool:
    """Detect if running in Termux environment"""
    # Check for Termux-specific environment variables
    termux_indicators = [
        os.getenv('PREFIX', '').startswith('/data/data/com.termux'),
        os.getenv('TERMUX_VERSION') is not None,
        os.path.exists('/data/data/com.termux/files/usr/bin'),
        'com.termux' in os.getenv('PREFIX', '')
    ]
    
    return any(termux_indicators)


def is_android() -> bool:
    """Detect if running on Android (including Termux)"""
    android_indicators = [
        is_termux(),
        os.path.exists('/system/build.prop'),
        os.path.exists('/android_root'),
        'android' in platform.platform().lower(),
        os.path.exists('/data/data'),
        sys.platform == 'linux' and os.path.exists('/proc/version') and _check_android_kernel()
    ]
    
    return any(android_indicators)


def _check_android_kernel() -> bool:
    """Check if kernel indicates Android system"""
    try:
        with open('/proc/version', 'r') as f:
            version_info = f.read().lower()
            android_keywords = ['android', 'lineage', 'cyanogen', 'aosp']
            return any(keyword in version_info for keyword in android_keywords)
    except (FileNotFoundError, PermissionError):
        return False


def get_platform_info() -> Dict[str, Any]:
    """Get comprehensive platform information"""
    info = {
        'system': platform.system(),
        'machine': platform.machine(),
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'is_termux': is_termux(),
        'is_android': is_android(),
        'prefix': os.getenv('PREFIX', ''),
        'termux_version': os.getenv('TERMUX_VERSION', ''),
        'home': os.getenv('HOME', ''),
        'supports_system_dns': not (is_termux() or is_android()),
        'requires_local_dns': is_termux() or is_android()
    }
    
    # Add Termux-specific paths
    if is_termux():
        info.update({
            'termux_prefix': os.getenv('PREFIX'),
            'termux_home': os.getenv('HOME'),
            'termux_tmpdir': os.getenv('TMPDIR'),
        })
    
    return info


def get_dns_config_requirements() -> Tuple[bool, str]:
    """Determine DNS configuration requirements
    
    Returns:
        Tuple[bool, str]: (needs_local_config, reason)
    """
    platform_info = get_platform_info()
    
    if platform_info['is_termux']:
        return True, "Termux environment requires local DNS configuration"
    elif platform_info['is_android']:
        return True, "Android environment may require local DNS configuration"
    elif not _can_access_system_resolv():
        return True, "System resolv.conf not accessible"
    else:
        return False, "System DNS configuration available"


def _can_access_system_resolv() -> bool:
    """Check if system resolv.conf is accessible"""
    system_resolv_paths = [
        '/etc/resolv.conf',
        '/system/etc/resolv.conf',
        '/data/misc/net/resolv.conf'
    ]
    
    for path in system_resolv_paths:
        try:
            with open(path, 'r') as f:
                f.read(1)  # Try to read at least one character
                return True
        except (FileNotFoundError, PermissionError):
            continue
    
    return False


def get_optimal_dns_servers() -> list:
    """Get optimal DNS servers for current platform"""
    # Universal reliable DNS servers
    primary_servers = [
        '1.1.1.1',      # Cloudflare (fast, privacy-focused)
        '1.0.0.1',      # Cloudflare secondary
        '8.8.8.8',      # Google (reliable)
        '8.8.4.4',      # Google secondary
    ]
    
    # Additional servers for specific regions/purposes
    fallback_servers = [
        '9.9.9.9',      # Quad9 (security-focused)
        '208.67.222.222',  # OpenDNS
        '94.140.14.14', # AdGuard DNS
    ]
    
    platform_info = get_platform_info()
    
    if platform_info['is_termux'] or platform_info['is_android']:
        # For mobile/Termux, prioritize fast and reliable servers
        return primary_servers + fallback_servers[:2]
    else:
        # For desktop, use all servers for redundancy
        return primary_servers + fallback_servers


def create_project_config_dir() -> Path:
    """Create and return the project configuration directory"""
    # Find project root (where setup.py or pyproject.toml exists)
    current = Path.cwd()
    project_root = current
    
    for parent in [current] + list(current.parents):
        if (parent / 'setup.py').exists() or (parent / 'pyproject.toml').exists():
            project_root = parent
            break
    
    # Create conf directory in project root
    config_dir = project_root / 'conf'
    config_dir.mkdir(exist_ok=True)
    
    logger.debug(f"Project config directory: {config_dir}")
    return config_dir


def log_platform_info():
    """Log platform information for debugging"""
    info = get_platform_info()
    needs_local, reason = get_dns_config_requirements()
    
    logger.info(f"Platform: {info['system']} ({info['platform']})")
    logger.info(f"Termux: {info['is_termux']}, Android: {info['is_android']}")
    logger.info(f"DNS Config: {'Local' if needs_local else 'System'} - {reason}")
    
    if info['is_termux']:
        logger.debug(f"Termux PREFIX: {info['prefix']}")
        logger.debug(f"Termux HOME: {info['home']}")


if __name__ == '__main__':
    # Quick test when run directly
    print("Platform Detection Test")
    print("=" * 30)
    
    info = get_platform_info()
    for key, value in info.items():
        print(f"{key}: {value}")
    
    print("\nDNS Requirements:")
    needs_local, reason = get_dns_config_requirements()
    print(f"Needs local DNS: {needs_local}")
    print(f"Reason: {reason}")
    
    print(f"\nOptimal DNS servers: {get_optimal_dns_servers()}")