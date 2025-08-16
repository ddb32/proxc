"""
Enhanced Export Utilities for Proxy Results

Handles saving verified proxies to various file formats with proper
formatting and error handling.
"""

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

from .models import ProxyInfo, ProxyProtocol, AnonymityLevel

logger = logging.getLogger(__name__)


def save_proxies_to_file(proxies: List[ProxyInfo], 
                        output_path: str, 
                        format_type: str = "auto") -> str:
    """
    Save proxies to file in specified format
    
    Args:
        proxies: List of ProxyInfo objects to save
        output_path: Output file path
        format_type: Format type (auto, json, csv, txt)
    
    Returns:
        str: Actual output file path used
    """
    if not proxies:
        raise ValueError("No proxies to save")
    
    path = Path(output_path)
    
    # Auto-detect format from extension if needed
    if format_type == "auto":
        format_type = _detect_format_from_path(path)
    
    # Ensure proper file extension
    path = _ensure_proper_extension(path, format_type)
    
    # Create directory if it doesn't exist
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # Save based on format
    if format_type == "json":
        _save_as_json(proxies, path)
    elif format_type == "csv":
        _save_as_csv(proxies, path)
    elif format_type == "txt":
        _save_as_txt(proxies, path)
    else:
        raise ValueError(f"Unsupported format: {format_type}")
    
    logger.info(f"Saved {len(proxies)} proxies to {path} ({format_type.upper()} format)")
    return str(path)


def _detect_format_from_path(path: Path) -> str:
    """Detect format from file extension"""
    ext = path.suffix.lower()
    
    if ext == ".json":
        return "json"
    elif ext == ".csv":
        return "csv"
    elif ext in [".txt", ".list"]:
        return "txt"
    else:
        return "txt"  # Default to txt


def _ensure_proper_extension(path: Path, format_type: str) -> Path:
    """Ensure file has proper extension for format"""
    current_ext = path.suffix.lower()
    
    expected_ext = {
        "json": ".json",
        "csv": ".csv", 
        "txt": ".txt"
    }.get(format_type, ".txt")
    
    if current_ext != expected_ext:
        return path.with_suffix(expected_ext)
    
    return path


def _save_as_json(proxies: List[ProxyInfo], path: Path):
    """Save proxies as JSON format"""
    data = {
        "metadata": {
            "exported_at": datetime.utcnow().isoformat(),
            "total_count": len(proxies),
            "format_version": "1.0"
        },
        "proxies": []
    }
    
    for proxy in proxies:
        proxy_data = {
            "host": proxy.host,
            "port": proxy.port,
            "protocol": proxy.protocol.value,
            "address": proxy.address,
            "source": getattr(proxy, 'source', 'unknown')
        }
        
        # Add optional fields if available
        if proxy.username:
            proxy_data["username"] = proxy.username
        
        if proxy.password:
            proxy_data["password"] = proxy.password
        
        if proxy.anonymity_level:
            proxy_data["anonymity_level"] = proxy.anonymity_level.value
        
        if proxy.geo_location:
            proxy_data["geo_location"] = {
                "country": proxy.geo_location.country,
                "country_code": proxy.geo_location.country_code,
                "city": proxy.geo_location.city,
                "region": proxy.geo_location.region
            }
        
        if proxy.metrics:
            proxy_data["metrics"] = {
                "response_time": proxy.metrics.response_time,
                "success_rate": proxy.metrics.success_rate,
                "check_count": proxy.metrics.check_count,
                "last_checked": proxy.metrics.last_checked.isoformat() if proxy.metrics.last_checked else None
            }
        
        data["proxies"].append(proxy_data)
    
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _save_as_csv(proxies: List[ProxyInfo], path: Path):
    """Save proxies as CSV format"""
    fieldnames = [
        'host', 'port', 'protocol', 'address', 'source',
        'anonymity_level', 'country', 'country_code', 'city',
        'response_time', 'success_rate', 'last_checked'
    ]
    
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for proxy in proxies:
            row = {
                'host': proxy.host,
                'port': proxy.port,
                'protocol': proxy.protocol.value,
                'address': proxy.address,
                'source': getattr(proxy, 'source', 'unknown'),
                'anonymity_level': proxy.anonymity_level.value if proxy.anonymity_level else '',
                'country': proxy.geo_location.country if proxy.geo_location else '',
                'country_code': proxy.geo_location.country_code if proxy.geo_location else '',
                'city': proxy.geo_location.city if proxy.geo_location else '',
                'response_time': proxy.metrics.response_time if proxy.metrics else '',
                'success_rate': proxy.metrics.success_rate if proxy.metrics else '',
                'last_checked': proxy.metrics.last_checked.isoformat() if (proxy.metrics and proxy.metrics.last_checked) else ''
            }
            writer.writerow(row)


def _save_as_txt(proxies: List[ProxyInfo], path: Path):
    """Save proxies as simple text format"""
    with open(path, 'w', encoding='utf-8') as f:
        # Write header comment
        f.write(f"# Proxy list exported at {datetime.utcnow().isoformat()}\n")
        f.write(f"# Total proxies: {len(proxies)}\n")
        f.write(f"# Format: protocol://host:port\n")
        f.write("#\n")
        
        # Write proxies
        for proxy in proxies:
            # Use full URL format for clarity
            proxy_url = f"{proxy.protocol.value}://{proxy.host}:{proxy.port}"
            
            # Add inline comment with additional info if available
            comments = []
            if proxy.anonymity_level:
                comments.append(f"anonymity:{proxy.anonymity_level.value}")
            
            if proxy.geo_location and proxy.geo_location.country_code:
                comments.append(f"country:{proxy.geo_location.country_code}")
            
            if proxy.metrics and proxy.metrics.response_time:
                comments.append(f"response:{proxy.metrics.response_time:.0f}ms")
            
            if comments:
                f.write(f"{proxy_url}  # {', '.join(comments)}\n")
            else:
                f.write(f"{proxy_url}\n")


def load_proxies_from_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Load proxies from file (utility function for reading back saved files)
    
    Args:
        file_path: Path to proxy file
    
    Returns:
        List[Dict]: List of proxy dictionaries
    """
    path = Path(file_path)
    
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    format_type = _detect_format_from_path(path)
    
    if format_type == "json":
        return _load_from_json(path)
    elif format_type == "csv":
        return _load_from_csv(path)
    elif format_type == "txt":
        return _load_from_txt(path)
    else:
        raise ValueError(f"Unsupported format: {format_type}")


def _load_from_json(path: Path) -> List[Dict[str, Any]]:
    """Load proxies from JSON file"""
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    if isinstance(data, dict) and "proxies" in data:
        return data["proxies"]
    elif isinstance(data, list):
        return data
    else:
        raise ValueError("Invalid JSON format")


def _load_from_csv(path: Path) -> List[Dict[str, Any]]:
    """Load proxies from CSV file"""
    proxies = []
    
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Clean empty values
            proxy = {k: v for k, v in row.items() if v}
            proxies.append(proxy)
    
    return proxies


def _load_from_txt(path: Path) -> List[Dict[str, Any]]:
    """Load proxies from text file"""
    proxies = []
    
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Extract URL part (before any comment)
            if '#' in line:
                url_part = line.split('#')[0].strip()
            else:
                url_part = line
            
            # Parse basic URL format
            if '://' in url_part:
                try:
                    protocol, rest = url_part.split('://', 1)
                    if ':' in rest:
                        host, port = rest.rsplit(':', 1)
                        proxies.append({
                            'host': host,
                            'port': int(port),
                            'protocol': protocol,
                            'address': f"{host}:{port}"
                        })
                except ValueError:
                    logger.warning(f"Skipped invalid line: {line}")
            
            # Handle IP:PORT format
            elif ':' in url_part:
                try:
                    host, port = url_part.rsplit(':', 1)
                    proxies.append({
                        'host': host,
                        'port': int(port),
                        'protocol': 'http',  # Default
                        'address': url_part
                    })
                except ValueError:
                    logger.warning(f"Skipped invalid line: {line}")
    
    return proxies


def get_export_stats(file_path: str) -> Dict[str, Any]:
    """Get statistics about an exported proxy file"""
    try:
        proxies = load_proxies_from_file(file_path)
        path = Path(file_path)
        
        # Basic stats
        stats = {
            'file_path': str(path.absolute()),
            'file_size': path.stat().st_size,
            'format': _detect_format_from_path(path),
            'total_proxies': len(proxies),
            'created_at': datetime.fromtimestamp(path.stat().st_ctime).isoformat(),
            'modified_at': datetime.fromtimestamp(path.stat().st_mtime).isoformat()
        }
        
        # Protocol distribution
        protocols = {}
        countries = {}
        anonymity_levels = {}
        
        for proxy in proxies:
            # Protocol stats
            protocol = proxy.get('protocol', 'unknown')
            protocols[protocol] = protocols.get(protocol, 0) + 1
            
            # Country stats
            country = proxy.get('country_code', 'unknown')
            countries[country] = countries.get(country, 0) + 1
            
            # Anonymity stats
            anonymity = proxy.get('anonymity_level', 'unknown')
            anonymity_levels[anonymity] = anonymity_levels.get(anonymity, 0) + 1
        
        stats.update({
            'protocol_distribution': protocols,
            'country_distribution': countries,
            'anonymity_distribution': anonymity_levels
        })
        
        return stats
        
    except Exception as e:
        return {'error': str(e)}


__all__ = [
    'save_proxies_to_file',
    'load_proxies_from_file', 
    'get_export_stats'
]