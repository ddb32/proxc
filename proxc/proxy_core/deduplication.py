"""Advanced Deduplication System for ProxyHunter

This module provides sophisticated deduplication capabilities including:
- Multi-stage deduplication (IP:port, subnet analysis)
- Historical duplicate tracking
- Intelligent proxy merging for multiple sources
- Performance-optimized duplicate detection
"""

import hashlib
import logging
import ipaddress
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple, Any
import threading
from pathlib import Path
import sqlite3

from .models import ProxyInfo, ProxyProtocol, ProxyStatus, ValidationStatus

logger = logging.getLogger(__name__)


@dataclass
class DuplicateEntry:
    """Entry for tracking duplicate proxies"""
    proxy_id: str
    host: str
    port: int
    first_seen: datetime
    last_seen: datetime
    source_count: int = 1
    sources: Set[str] = field(default_factory=set)
    merged_with: Optional[str] = None
    
    def __post_init__(self):
        if isinstance(self.sources, list):
            self.sources = set(self.sources)


@dataclass
class DeduplicationStats:
    """Statistics for deduplication operations"""
    total_processed: int = 0
    duplicates_found: int = 0
    unique_retained: int = 0
    merged_proxies: int = 0
    subnet_duplicates: int = 0
    historical_duplicates: int = 0
    processing_time: float = 0.0
    
    @property
    def duplicate_rate(self) -> float:
        """Calculate duplicate rate percentage"""
        if self.total_processed == 0:
            return 0.0
        return (self.duplicates_found / self.total_processed) * 100
    
    @property
    def retention_rate(self) -> float:
        """Calculate retention rate percentage"""
        if self.total_processed == 0:
            return 0.0
        return (self.unique_retained / self.total_processed) * 100


class SubnetAnalyzer:
    """Analyzer for subnet-based duplicate detection"""
    
    def __init__(self, subnet_threshold: int = 5):
        self.subnet_threshold = subnet_threshold
        self.subnet_cache: Dict[str, Set[str]] = {}
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def analyze_subnets(self, proxies: List[ProxyInfo]) -> Dict[str, List[ProxyInfo]]:
        """Group proxies by subnet and identify potential duplicates"""
        subnet_groups = defaultdict(list)
        
        for proxy in proxies:
            try:
                # Create /24 subnet for IPv4
                ip = ipaddress.IPv4Address(proxy.host)
                subnet = ipaddress.IPv4Network(f"{ip}/{24}", strict=False)
                subnet_key = str(subnet.network_address)
                
                subnet_groups[subnet_key].append(proxy)
                
            except ipaddress.AddressValueError:
                # Handle invalid IPs
                self.logger.debug(f"Invalid IP address: {proxy.host}")
                continue
        
        return dict(subnet_groups)
    
    def identify_subnet_duplicates(self, subnet_groups: Dict[str, List[ProxyInfo]]) -> List[ProxyInfo]:
        """Identify proxies that should be considered duplicates based on subnet concentration"""
        subnet_duplicates = []
        
        for subnet, proxies in subnet_groups.items():
            if len(proxies) >= self.subnet_threshold:
                # Sort by quality and keep only the best ones
                sorted_proxies = sorted(
                    proxies, 
                    key=lambda p: (
                        p.status.value if hasattr(p.status, 'value') else 0,
                        p.validation_status.value if hasattr(p.validation_status, 'value') else 0,
                        -(p.metrics.response_time or 999999) if p.metrics else 0
                    ),
                    reverse=True
                )
                
                # Keep top N proxies, mark rest as duplicates
                keep_count = max(1, len(proxies) // 3)  # Keep 1/3 of proxies
                subnet_duplicates.extend(sorted_proxies[keep_count:])
                
                self.logger.info(
                    f"Subnet {subnet} has {len(proxies)} proxies, "
                    f"keeping {keep_count}, marking {len(proxies) - keep_count} as duplicates"
                )
        
        return subnet_duplicates


class HistoricalTracker:
    """Tracks historically seen proxies for duplicate detection"""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or "proxy_history.db"
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for historical tracking"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS proxy_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        host TEXT NOT NULL,
                        port INTEGER NOT NULL,
                        proxy_id TEXT UNIQUE,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        source_count INTEGER DEFAULT 1,
                        sources TEXT,
                        status TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(host, port)
                    )
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_host_port ON proxy_history(host, port)
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_last_seen ON proxy_history(last_seen)
                """)
        
        except Exception as e:
            self.logger.error(f"Failed to initialize history database: {e}")
    
    def record_proxy(self, proxy: ProxyInfo, source: str = "unknown"):
        """Record a proxy in historical tracking"""
        try:
            now = datetime.utcnow().isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                # Check if proxy exists
                cursor = conn.execute(
                    "SELECT sources, source_count FROM proxy_history WHERE host = ? AND port = ?",
                    (proxy.host, proxy.port)
                )
                result = cursor.fetchone()
                
                if result:
                    # Update existing record
                    existing_sources = set(result[0].split(',') if result[0] else [])
                    existing_sources.add(source)
                    new_sources = ','.join(existing_sources)
                    
                    conn.execute("""
                        UPDATE proxy_history 
                        SET last_seen = ?, source_count = ?, sources = ?, status = ?
                        WHERE host = ? AND port = ?
                    """, (now, len(existing_sources), new_sources, proxy.status.value, proxy.host, proxy.port))
                else:
                    # Insert new record
                    conn.execute("""
                        INSERT INTO proxy_history 
                        (host, port, proxy_id, first_seen, last_seen, source_count, sources, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (proxy.host, proxy.port, proxy.proxy_id, now, now, 1, source, proxy.status.value))
        
        except Exception as e:
            self.logger.error(f"Failed to record proxy in history: {e}")
    
    def is_recently_seen(self, proxy: ProxyInfo, days: int = 7) -> bool:
        """Check if proxy was seen recently"""
        try:
            cutoff_date = (datetime.utcnow() - timedelta(days=days)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT 1 FROM proxy_history WHERE host = ? AND port = ? AND last_seen > ?",
                    (proxy.host, proxy.port, cutoff_date)
                )
                return cursor.fetchone() is not None
        
        except Exception as e:
            self.logger.error(f"Failed to check historical record: {e}")
            return False
    
    def get_proxy_history(self, proxy: ProxyInfo) -> Optional[Dict[str, Any]]:
        """Get historical information for a proxy"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT proxy_id, first_seen, last_seen, source_count, sources, status
                    FROM proxy_history WHERE host = ? AND port = ?
                """, (proxy.host, proxy.port))
                
                result = cursor.fetchone()
                if result:
                    return {
                        'proxy_id': result[0],
                        'first_seen': result[1],
                        'last_seen': result[2],
                        'source_count': result[3],
                        'sources': result[4].split(',') if result[4] else [],
                        'status': result[5]
                    }
        
        except Exception as e:
            self.logger.error(f"Failed to get proxy history: {e}")
        
        return None
    
    def cleanup_old_records(self, days: int = 30):
        """Remove old historical records"""
        try:
            cutoff_date = (datetime.utcnow() - timedelta(days=days)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "DELETE FROM proxy_history WHERE last_seen < ?",
                    (cutoff_date,)
                )
                deleted_count = cursor.rowcount
                
                self.logger.info(f"Cleaned up {deleted_count} old proxy records")
                return deleted_count
        
        except Exception as e:
            self.logger.error(f"Failed to cleanup old records: {e}")
            return 0


class ProxyMerger:
    """Intelligent proxy merging from multiple sources"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def merge_duplicate_proxies(self, proxies: List[ProxyInfo]) -> List[ProxyInfo]:
        """Merge proxies that are duplicates but from different sources"""
        # Group by host:port
        proxy_groups = defaultdict(list)
        
        for proxy in proxies:
            key = f"{proxy.host}:{proxy.port}"
            proxy_groups[key].append(proxy)
        
        merged_proxies = []
        
        for key, group in proxy_groups.items():
            if len(group) == 1:
                # No duplicates
                merged_proxies.append(group[0])
            else:
                # Merge duplicates
                merged_proxy = self._merge_proxy_group(group)
                merged_proxies.append(merged_proxy)
        
        return merged_proxies
    
    def _merge_proxy_group(self, proxies: List[ProxyInfo]) -> ProxyInfo:
        """Merge a group of duplicate proxies into a single proxy"""
        if not proxies:
            raise ValueError("Cannot merge empty proxy group")
        
        if len(proxies) == 1:
            return proxies[0]
        
        # Sort by quality (best first)
        sorted_proxies = sorted(
            proxies,
            key=lambda p: self._calculate_proxy_quality_score(p),
            reverse=True
        )
        
        # Use the best proxy as base
        base_proxy = sorted_proxies[0]
        
        # Merge information from other proxies
        merged_sources = set()
        merged_tags = set()
        
        for proxy in sorted_proxies:
            if proxy.source:
                merged_sources.add(proxy.source)
            if proxy.tags:
                merged_tags.update(proxy.tags)
        
        # Update base proxy with merged information
        base_proxy.source = ','.join(sorted(merged_sources))
        base_proxy.tags = list(merged_tags)
        
        # Use earliest discovery date
        earliest_discovery = min(
            (p.discovered_at for p in sorted_proxies if p.discovered_at),
            default=base_proxy.discovered_at
        )
        base_proxy.discovered_at = earliest_discovery
        
        # Merge notes
        notes = [p.notes for p in sorted_proxies if p.notes and p.notes.strip()]
        if notes:
            base_proxy.notes = '; '.join(notes)
        
        self.logger.debug(f"Merged {len(proxies)} duplicates for {base_proxy.address}")
        
        return base_proxy
    
    def _calculate_proxy_quality_score(self, proxy: ProxyInfo) -> float:
        """Calculate a quality score for proxy ranking"""
        score = 0.0
        
        # Status scoring
        if proxy.status == ProxyStatus.ACTIVE:
            score += 100
        elif proxy.status == ProxyStatus.INACTIVE:
            score += 10
        
        # Validation scoring
        if proxy.validation_status == ValidationStatus.VALID:
            score += 50
        elif proxy.validation_status == ValidationStatus.PENDING:
            score += 25
        
        # Anonymity scoring
        anonymity_scores = {
            'elite': 30,
            'anonymous': 20,
            'transparent': 10
        }
        if hasattr(proxy.anonymity_level, 'value'):
            score += anonymity_scores.get(proxy.anonymity_level.value, 0)
        
        # Threat level scoring (lower is better)
        threat_penalty = {
            'low': 0,
            'medium': -10,
            'high': -25,
            'critical': -50
        }
        if hasattr(proxy.threat_level, 'value'):
            score += threat_penalty.get(proxy.threat_level.value, 0)
        
        # Performance metrics
        if proxy.metrics:
            if proxy.metrics.response_time:
                # Lower response time is better
                score += max(0, 100 - proxy.metrics.response_time / 10)
            
            if proxy.metrics.success_rate:
                score += proxy.metrics.success_rate * 2
            
            if proxy.metrics.uptime_percentage:
                score += proxy.metrics.uptime_percentage
        
        return score


class AdvancedDeduplicator:
    """Main deduplication engine with multiple strategies"""
    
    def __init__(self, enable_historical: bool = True, enable_subnet_analysis: bool = True):
        self.enable_historical = enable_historical
        self.enable_subnet_analysis = enable_subnet_analysis
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.subnet_analyzer = SubnetAnalyzer() if enable_subnet_analysis else None
        self.historical_tracker = HistoricalTracker() if enable_historical else None
        self.proxy_merger = ProxyMerger()
        
        # Performance tracking
        self.stats = DeduplicationStats()
        
        # Thread safety
        self._lock = threading.Lock()
    
    def deduplicate_proxies(self, proxies: List[ProxyInfo], 
                          source: str = "unknown") -> Tuple[List[ProxyInfo], DeduplicationStats]:
        """Main deduplication method with comprehensive strategies"""
        
        start_time = time.time()
        
        with self._lock:
            self.stats = DeduplicationStats()
            self.stats.total_processed = len(proxies)
            
            if not proxies:
                return [], self.stats
            
            self.logger.info(f"Starting deduplication of {len(proxies)} proxies")
            
            # Stage 1: Basic IP:port deduplication
            unique_proxies = self._basic_deduplication(proxies)
            self.logger.info(f"After basic deduplication: {len(unique_proxies)} proxies")
            
            # Stage 2: Historical duplicate detection
            if self.enable_historical and self.historical_tracker:
                unique_proxies = self._historical_deduplication(unique_proxies, source)
                self.logger.info(f"After historical deduplication: {len(unique_proxies)} proxies")
            
            # Stage 3: Subnet analysis
            if self.enable_subnet_analysis and self.subnet_analyzer:
                unique_proxies = self._subnet_deduplication(unique_proxies)
                self.logger.info(f"After subnet deduplication: {len(unique_proxies)} proxies")
            
            # Stage 4: Intelligent merging
            merged_proxies = self.proxy_merger.merge_duplicate_proxies(unique_proxies)
            self.logger.info(f"After intelligent merging: {len(merged_proxies)} proxies")
            
            # Update statistics
            self.stats.unique_retained = len(merged_proxies)
            self.stats.duplicates_found = self.stats.total_processed - self.stats.unique_retained
            self.stats.processing_time = time.time() - start_time
            
            # Record in historical tracker
            if self.enable_historical and self.historical_tracker:
                for proxy in merged_proxies:
                    self.historical_tracker.record_proxy(proxy, source)
            
            self.logger.info(
                f"Deduplication completed: {self.stats.total_processed} -> {self.stats.unique_retained} "
                f"({self.stats.duplicate_rate:.1f}% duplicates) in {self.stats.processing_time:.2f}s"
            )
            
            return merged_proxies, self.stats
    
    def _basic_deduplication(self, proxies: List[ProxyInfo]) -> List[ProxyInfo]:
        """Basic IP:port deduplication"""
        seen = set()
        unique_proxies = []
        
        for proxy in proxies:
            key = f"{proxy.host}:{proxy.port}"
            if key not in seen:
                seen.add(key)
                unique_proxies.append(proxy)
        
        return unique_proxies
    
    def _historical_deduplication(self, proxies: List[ProxyInfo], source: str) -> List[ProxyInfo]:
        """Remove proxies that were recently seen"""
        unique_proxies = []
        
        for proxy in proxies:
            if not self.historical_tracker.is_recently_seen(proxy):
                unique_proxies.append(proxy)
            else:
                self.stats.historical_duplicates += 1
        
        return unique_proxies
    
    def _subnet_deduplication(self, proxies: List[ProxyInfo]) -> List[ProxyInfo]:
        """Remove subnet-based duplicates"""
        subnet_groups = self.subnet_analyzer.analyze_subnets(proxies)
        subnet_duplicates = self.subnet_analyzer.identify_subnet_duplicates(subnet_groups)
        
        self.stats.subnet_duplicates = len(subnet_duplicates)
        
        # Remove subnet duplicates
        duplicate_keys = {f"{p.host}:{p.port}" for p in subnet_duplicates}
        unique_proxies = [
            proxy for proxy in proxies 
            if f"{proxy.host}:{proxy.port}" not in duplicate_keys
        ]
        
        return unique_proxies
    
    def get_deduplication_report(self) -> Dict[str, Any]:
        """Get comprehensive deduplication report"""
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'statistics': {
                'total_processed': self.stats.total_processed,
                'duplicates_found': self.stats.duplicates_found,
                'unique_retained': self.stats.unique_retained,
                'duplicate_rate': self.stats.duplicate_rate,
                'retention_rate': self.stats.retention_rate,
                'processing_time': self.stats.processing_time
            },
            'breakdown': {
                'basic_duplicates': self.stats.duplicates_found - self.stats.historical_duplicates - self.stats.subnet_duplicates,
                'historical_duplicates': self.stats.historical_duplicates,
                'subnet_duplicates': self.stats.subnet_duplicates,
                'merged_proxies': self.stats.merged_proxies
            },
            'configuration': {
                'historical_tracking': self.enable_historical,
                'subnet_analysis': self.enable_subnet_analysis,
                'subnet_threshold': self.subnet_analyzer.subnet_threshold if self.subnet_analyzer else None
            }
        }
        
        return report
    
    def cleanup_historical_data(self, days: int = 30) -> int:
        """Clean up old historical data"""
        if self.historical_tracker:
            return self.historical_tracker.cleanup_old_records(days)
        return 0


# Global deduplicator instance
_global_deduplicator: Optional[AdvancedDeduplicator] = None


def get_deduplicator(enable_historical: bool = True, 
                    enable_subnet_analysis: bool = True) -> AdvancedDeduplicator:
    """Get global deduplicator instance"""
    global _global_deduplicator
    
    if _global_deduplicator is None:
        _global_deduplicator = AdvancedDeduplicator(enable_historical, enable_subnet_analysis)
    
    return _global_deduplicator


def deduplicate_proxy_list(proxies: List[ProxyInfo], 
                          source: str = "unknown") -> Tuple[List[ProxyInfo], DeduplicationStats]:
    """Convenience function for deduplicating a list of proxies"""
    deduplicator = get_deduplicator()
    return deduplicator.deduplicate_proxies(proxies, source)