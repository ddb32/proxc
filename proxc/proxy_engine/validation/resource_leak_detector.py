"""Resource Leak Detection and Prevention System

This module provides comprehensive resource leak detection capabilities for ProxC
validation operations, including memory leaks, connection leaks, thread leaks,
and file handle leaks.
"""

import gc
import logging
import os
import psutil
import threading
import time
import tracemalloc
import weakref
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor

from .session_cleanup import ResourceType, CleanupPriority


class LeakType(Enum):
    """Types of resource leaks that can be detected"""
    MEMORY = "memory"
    CONNECTION = "connection"
    THREAD = "thread"
    FILE_HANDLE = "file_handle"
    SOCKET = "socket"
    SSL_CONTEXT = "ssl_context"
    CACHE_ENTRY = "cache_entry"
    ASYNC_TASK = "async_task"


class LeakSeverity(Enum):
    """Severity levels for detected leaks"""
    LOW = 1      # Minor leak, doesn't impact performance
    MEDIUM = 2   # Moderate leak, may impact performance over time
    HIGH = 3     # Significant leak, requires immediate attention
    CRITICAL = 4 # Severe leak, system stability at risk


@dataclass
class LeakDetection:
    """Represents a detected resource leak"""
    leak_type: LeakType
    severity: LeakSeverity
    resource_id: str
    description: str
    detected_at: datetime = field(default_factory=datetime.now)
    resource_count: int = 0
    memory_usage_mb: float = 0.0
    growth_rate: float = 0.0  # Resources per second
    session_id: Optional[str] = None
    stack_trace: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def age_seconds(self) -> float:
        """Get age of detection in seconds"""
        return (datetime.now() - self.detected_at).total_seconds()


@dataclass
class ResourceSnapshot:
    """Snapshot of system resources at a point in time"""
    timestamp: datetime = field(default_factory=datetime.now)
    memory_mb: float = 0.0
    cpu_percent: float = 0.0
    thread_count: int = 0
    file_handles: int = 0
    network_connections: int = 0
    open_sockets: int = 0
    tracked_resources: Dict[ResourceType, int] = field(default_factory=dict)
    gc_objects: int = 0


class MemoryLeakDetector:
    """Detects memory leaks using tracemalloc and psutil"""
    
    def __init__(self, detection_threshold_mb: float = 50.0, 
                 growth_threshold_mb_per_min: float = 10.0):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.detection_threshold_mb = detection_threshold_mb
        self.growth_threshold_mb_per_min = growth_threshold_mb_per_min
        
        # Memory tracking
        self.memory_snapshots = deque(maxlen=100)  # Keep last 100 snapshots
        self.baseline_memory_mb = 0.0
        self.peak_memory_mb = 0.0
        self.tracemalloc_enabled = False
        
        # Top memory allocations
        self.top_allocations = []
        
        self._start_tracemalloc()
    
    def _start_tracemalloc(self):
        """Start memory tracing if not already started"""
        try:
            if not tracemalloc.is_tracing():
                tracemalloc.start(25)  # Keep 25 frames in traceback
                self.tracemalloc_enabled = True
                self.logger.debug("Memory tracing started")
        except Exception as e:
            self.logger.warning(f"Could not start memory tracing: {e}")
    
    def take_snapshot(self) -> float:
        """Take a memory snapshot and return current memory usage"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            current_memory_mb = memory_info.rss / 1024 / 1024
            
            self.memory_snapshots.append({
                'timestamp': datetime.now(),
                'memory_mb': current_memory_mb,
                'memory_info': memory_info
            })
            
            # Update peak
            if current_memory_mb > self.peak_memory_mb:
                self.peak_memory_mb = current_memory_mb
            
            # Set baseline if first measurement
            if self.baseline_memory_mb == 0:
                self.baseline_memory_mb = current_memory_mb
            
            return current_memory_mb
            
        except Exception as e:
            self.logger.error(f"Failed to take memory snapshot: {e}")
            return 0.0
    
    def detect_memory_leaks(self) -> List[LeakDetection]:
        """Detect memory leaks based on growth patterns"""
        leaks = []
        
        if len(self.memory_snapshots) < 10:
            return leaks  # Need enough data points
        
        current_memory = self.take_snapshot()
        
        # Check absolute memory usage
        memory_increase = current_memory - self.baseline_memory_mb
        if memory_increase > self.detection_threshold_mb:
            severity = LeakSeverity.HIGH if memory_increase > 200 else LeakSeverity.MEDIUM
            
            leak = LeakDetection(
                leak_type=LeakType.MEMORY,
                severity=severity,
                resource_id="memory_growth",
                description=f"Memory usage increased by {memory_increase:.1f}MB from baseline",
                memory_usage_mb=current_memory,
                metadata={
                    'baseline_mb': self.baseline_memory_mb,
                    'increase_mb': memory_increase,
                    'peak_mb': self.peak_memory_mb
                }
            )
            leaks.append(leak)
        
        # Check memory growth rate
        if len(self.memory_snapshots) >= 5:
            recent_snapshots = list(self.memory_snapshots)[-5:]
            time_span = (recent_snapshots[-1]['timestamp'] - recent_snapshots[0]['timestamp']).total_seconds()
            
            if time_span > 0:
                memory_change = recent_snapshots[-1]['memory_mb'] - recent_snapshots[0]['memory_mb']
                growth_rate_mb_per_min = (memory_change / time_span) * 60
                
                if growth_rate_mb_per_min > self.growth_threshold_mb_per_min:
                    severity = LeakSeverity.CRITICAL if growth_rate_mb_per_min > 50 else LeakSeverity.HIGH
                    
                    leak = LeakDetection(
                        leak_type=LeakType.MEMORY,
                        severity=severity,
                        resource_id="memory_growth_rate",
                        description=f"Memory growing at {growth_rate_mb_per_min:.1f}MB/min",
                        memory_usage_mb=current_memory,
                        growth_rate=growth_rate_mb_per_min,
                        metadata={
                            'time_span_seconds': time_span,
                            'memory_change_mb': memory_change
                        }
                    )
                    leaks.append(leak)
        
        # Analyze top memory allocations if tracemalloc is available
        if self.tracemalloc_enabled:
            try:
                snapshot = tracemalloc.take_snapshot()
                top_stats = snapshot.statistics('lineno')
                
                self.top_allocations = []
                for stat in top_stats[:10]:
                    self.top_allocations.append({
                        'filename': stat.traceback.format()[-1] if stat.traceback else 'unknown',
                        'size_mb': stat.size / 1024 / 1024,
                        'count': stat.count
                    })
                
                # Check for large allocations
                for allocation in self.top_allocations[:3]:
                    if allocation['size_mb'] > 20:  # 20MB threshold
                        leak = LeakDetection(
                            leak_type=LeakType.MEMORY,
                            severity=LeakSeverity.MEDIUM,
                            resource_id=f"large_allocation_{hash(allocation['filename'])}",
                            description=f"Large memory allocation: {allocation['size_mb']:.1f}MB",
                            memory_usage_mb=allocation['size_mb'],
                            stack_trace=allocation['filename'],
                            metadata=allocation
                        )
                        leaks.append(leak)
                        
            except Exception as e:
                self.logger.debug(f"Could not analyze memory allocations: {e}")
        
        return leaks
    
    def get_memory_summary(self) -> Dict[str, Any]:
        """Get comprehensive memory usage summary"""
        current_memory = self.take_snapshot()
        
        return {
            'current_mb': current_memory,
            'baseline_mb': self.baseline_memory_mb,
            'peak_mb': self.peak_memory_mb,
            'increase_from_baseline_mb': current_memory - self.baseline_memory_mb,
            'snapshot_count': len(self.memory_snapshots),
            'tracemalloc_enabled': self.tracemalloc_enabled,
            'top_allocations': self.top_allocations[:5],
            'gc_stats': {
                'objects': len(gc.get_objects()),
                'garbage': len(gc.garbage),
                'counts': gc.get_count()
            }
        }


class ConnectionLeakDetector:
    """Detects connection leaks (HTTP, SOCKS, etc.)"""
    
    def __init__(self, max_connections: int = 1000, stale_threshold_seconds: float = 300):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.max_connections = max_connections
        self.stale_threshold_seconds = stale_threshold_seconds
        
        # Connection tracking
        self.tracked_connections = {}  # connection_id -> connection_info
        self.connection_history = deque(maxlen=1000)
        self.connection_lock = threading.RLock()
    
    def register_connection(self, connection_id: str, connection_type: str, 
                          created_at: Optional[datetime] = None, metadata: Optional[Dict] = None):
        """Register a new connection for tracking"""
        with self.connection_lock:
            self.tracked_connections[connection_id] = {
                'type': connection_type,
                'created_at': created_at or datetime.now(),
                'last_used': datetime.now(),
                'metadata': metadata or {}
            }
            
            self.connection_history.append({
                'action': 'created',
                'connection_id': connection_id,
                'timestamp': datetime.now(),
                'type': connection_type
            })
    
    def update_connection_activity(self, connection_id: str):
        """Update last activity time for a connection"""
        with self.connection_lock:
            if connection_id in self.tracked_connections:
                self.tracked_connections[connection_id]['last_used'] = datetime.now()
    
    def unregister_connection(self, connection_id: str):
        """Unregister a connection"""
        with self.connection_lock:
            if connection_id in self.tracked_connections:
                del self.tracked_connections[connection_id]
                
                self.connection_history.append({
                    'action': 'closed',
                    'connection_id': connection_id,
                    'timestamp': datetime.now()
                })
    
    def detect_connection_leaks(self) -> List[LeakDetection]:
        """Detect connection leaks"""
        leaks = []
        current_time = datetime.now()
        
        with self.connection_lock:
            connection_count = len(self.tracked_connections)
            stale_connections = []
            
            # Check for too many connections
            if connection_count > self.max_connections:
                leak = LeakDetection(
                    leak_type=LeakType.CONNECTION,
                    severity=LeakSeverity.HIGH,
                    resource_id="connection_count_exceeded",
                    description=f"Too many connections: {connection_count}/{self.max_connections}",
                    resource_count=connection_count,
                    metadata={'max_allowed': self.max_connections}
                )
                leaks.append(leak)
            
            # Check for stale connections
            for conn_id, conn_info in self.tracked_connections.items():
                age = (current_time - conn_info['last_used']).total_seconds()
                if age > self.stale_threshold_seconds:
                    stale_connections.append((conn_id, age))
            
            if stale_connections:
                # Sort by age (oldest first)
                stale_connections.sort(key=lambda x: x[1], reverse=True)
                
                severity = LeakSeverity.HIGH if len(stale_connections) > 50 else LeakSeverity.MEDIUM
                
                leak = LeakDetection(
                    leak_type=LeakType.CONNECTION,
                    severity=severity,
                    resource_id="stale_connections",
                    description=f"{len(stale_connections)} stale connections detected",
                    resource_count=len(stale_connections),
                    metadata={
                        'oldest_age_seconds': stale_connections[0][1] if stale_connections else 0,
                        'stale_threshold_seconds': self.stale_threshold_seconds,
                        'stale_connection_ids': [conn_id for conn_id, _ in stale_connections[:10]]
                    }
                )
                leaks.append(leak)
        
        return leaks
    
    def get_connection_summary(self) -> Dict[str, Any]:
        """Get connection usage summary"""
        with self.connection_lock:
            connection_types = defaultdict(int)
            total_connections = len(self.tracked_connections)
            
            oldest_connection = None
            newest_connection = None
            
            for conn_info in self.tracked_connections.values():
                connection_types[conn_info['type']] += 1
                
                if oldest_connection is None or conn_info['created_at'] < oldest_connection:
                    oldest_connection = conn_info['created_at']
                
                if newest_connection is None or conn_info['created_at'] > newest_connection:
                    newest_connection = conn_info['created_at']
            
            return {
                'total_connections': total_connections,
                'max_connections': self.max_connections,
                'connection_types': dict(connection_types),
                'oldest_connection_age_seconds': (datetime.now() - oldest_connection).total_seconds() if oldest_connection else 0,
                'newest_connection_age_seconds': (datetime.now() - newest_connection).total_seconds() if newest_connection else 0,
                'history_entries': len(self.connection_history)
            }


class ThreadLeakDetector:
    """Detects thread leaks and runaway threads"""
    
    def __init__(self, max_threads: int = 100, stale_threshold_seconds: float = 600):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.max_threads = max_threads
        self.stale_threshold_seconds = stale_threshold_seconds
        
        # Thread tracking
        self.tracked_threads = {}  # thread_id -> thread_info
        self.thread_snapshots = deque(maxlen=50)
        self.thread_lock = threading.RLock()
        self.baseline_thread_count = threading.active_count()
    
    def register_thread(self, thread_id: str, thread_name: str, purpose: str,
                       created_at: Optional[datetime] = None):
        """Register a thread for tracking"""
        with self.thread_lock:
            self.tracked_threads[thread_id] = {
                'name': thread_name,
                'purpose': purpose,
                'created_at': created_at or datetime.now(),
                'last_seen': datetime.now(),
                'is_alive': True
            }
    
    def update_thread_activity(self, thread_id: str):
        """Update thread activity"""
        with self.thread_lock:
            if thread_id in self.tracked_threads:
                self.tracked_threads[thread_id]['last_seen'] = datetime.now()
    
    def unregister_thread(self, thread_id: str):
        """Unregister a thread"""
        with self.thread_lock:
            if thread_id in self.tracked_threads:
                self.tracked_threads[thread_id]['is_alive'] = False
                # Keep for a while for analysis
                del self.tracked_threads[thread_id]
    
    def take_thread_snapshot(self):
        """Take a snapshot of current thread state"""
        current_count = threading.active_count()
        active_threads = threading.enumerate()
        
        snapshot = {
            'timestamp': datetime.now(),
            'total_count': current_count,
            'active_threads': [
                {
                    'name': t.name,
                    'daemon': t.daemon,
                    'is_alive': t.is_alive()
                }
                for t in active_threads
            ]
        }
        
        self.thread_snapshots.append(snapshot)
        return snapshot
    
    def detect_thread_leaks(self) -> List[LeakDetection]:
        """Detect thread leaks"""
        leaks = []
        current_snapshot = self.take_thread_snapshot()
        current_time = datetime.now()
        
        # Check thread count
        current_count = current_snapshot['total_count']
        if current_count > self.max_threads:
            severity = LeakSeverity.CRITICAL if current_count > self.max_threads * 1.5 else LeakSeverity.HIGH
            
            leak = LeakDetection(
                leak_type=LeakType.THREAD,
                severity=severity,
                resource_id="thread_count_exceeded",
                description=f"Too many threads: {current_count}/{self.max_threads}",
                resource_count=current_count,
                metadata={
                    'max_allowed': self.max_threads,
                    'baseline_count': self.baseline_thread_count,
                    'increase_from_baseline': current_count - self.baseline_thread_count
                }
            )
            leaks.append(leak)
        
        # Check for thread growth
        if len(self.thread_snapshots) >= 5:
            recent_snapshots = list(self.thread_snapshots)[-5:]
            thread_growth = recent_snapshots[-1]['total_count'] - recent_snapshots[0]['total_count']
            time_span = (recent_snapshots[-1]['timestamp'] - recent_snapshots[0]['timestamp']).total_seconds()
            
            if thread_growth > 10 and time_span > 0:  # More than 10 threads created
                growth_rate = thread_growth / time_span * 60  # threads per minute
                
                leak = LeakDetection(
                    leak_type=LeakType.THREAD,
                    severity=LeakSeverity.MEDIUM,
                    resource_id="thread_growth_rate",
                    description=f"Rapid thread creation: {growth_rate:.1f} threads/min",
                    resource_count=current_count,
                    growth_rate=growth_rate,
                    metadata={
                        'thread_growth': thread_growth,
                        'time_span_seconds': time_span
                    }
                )
                leaks.append(leak)
        
        # Check for stale tracked threads
        with self.thread_lock:
            stale_threads = []
            for thread_id, thread_info in self.tracked_threads.items():
                if thread_info['is_alive']:
                    age = (current_time - thread_info['last_seen']).total_seconds()
                    if age > self.stale_threshold_seconds:
                        stale_threads.append((thread_id, age, thread_info))
            
            if stale_threads:
                leak = LeakDetection(
                    leak_type=LeakType.THREAD,
                    severity=LeakSeverity.MEDIUM,
                    resource_id="stale_threads",
                    description=f"{len(stale_threads)} stale threads detected",
                    resource_count=len(stale_threads),
                    metadata={
                        'stale_thread_names': [info['name'] for _, _, info in stale_threads[:5]],
                        'oldest_age_seconds': max(age for _, age, _ in stale_threads)
                    }
                )
                leaks.append(leak)
        
        return leaks
    
    def get_thread_summary(self) -> Dict[str, Any]:
        """Get thread usage summary"""
        current_snapshot = self.take_thread_snapshot()
        
        with self.thread_lock:
            tracked_count = len(self.tracked_threads)
        
        return {
            'current_count': current_snapshot['total_count'],
            'baseline_count': self.baseline_thread_count,
            'max_threads': self.max_threads,
            'tracked_count': tracked_count,
            'daemon_threads': sum(1 for t in current_snapshot['active_threads'] if t['daemon']),
            'non_daemon_threads': sum(1 for t in current_snapshot['active_threads'] if not t['daemon']),
            'snapshot_count': len(self.thread_snapshots)
        }


class FileHandleLeakDetector:
    """Detects file handle leaks"""
    
    def __init__(self, max_file_handles: int = 1000):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.max_file_handles = max_file_handles
        self.baseline_file_handles = self._get_file_handle_count()
        self.file_handle_history = deque(maxlen=100)
    
    def _get_file_handle_count(self) -> int:
        """Get current file handle count"""
        try:
            process = psutil.Process()
            return len(process.open_files())
        except Exception:
            # Fallback to file descriptor count on Unix
            try:
                import resource
                return len(os.listdir('/proc/self/fd'))
            except Exception:
                return 0
    
    def take_file_handle_snapshot(self) -> int:
        """Take a snapshot of file handle usage"""
        current_count = self._get_file_handle_count()
        
        self.file_handle_history.append({
            'timestamp': datetime.now(),
            'count': current_count
        })
        
        return current_count
    
    def detect_file_handle_leaks(self) -> List[LeakDetection]:
        """Detect file handle leaks"""
        leaks = []
        current_count = self.take_file_handle_snapshot()
        
        # Check absolute count
        if current_count > self.max_file_handles:
            severity = LeakSeverity.CRITICAL if current_count > self.max_file_handles * 1.5 else LeakSeverity.HIGH
            
            leak = LeakDetection(
                leak_type=LeakType.FILE_HANDLE,
                severity=severity,
                resource_id="file_handle_count_exceeded",
                description=f"Too many file handles: {current_count}/{self.max_file_handles}",
                resource_count=current_count,
                metadata={
                    'max_allowed': self.max_file_handles,
                    'baseline_count': self.baseline_file_handles
                }
            )
            leaks.append(leak)
        
        # Check for growth
        increase_from_baseline = current_count - self.baseline_file_handles
        if increase_from_baseline > 100:  # 100+ handles since baseline
            severity = LeakSeverity.HIGH if increase_from_baseline > 500 else LeakSeverity.MEDIUM
            
            leak = LeakDetection(
                leak_type=LeakType.FILE_HANDLE,
                severity=severity,
                resource_id="file_handle_growth",
                description=f"File handle count increased by {increase_from_baseline} from baseline",
                resource_count=current_count,
                metadata={
                    'baseline_count': self.baseline_file_handles,
                    'increase': increase_from_baseline
                }
            )
            leaks.append(leak)
        
        return leaks
    
    def get_file_handle_summary(self) -> Dict[str, Any]:
        """Get file handle usage summary"""
        current_count = self.take_file_handle_snapshot()
        
        return {
            'current_count': current_count,
            'baseline_count': self.baseline_file_handles,
            'max_handles': self.max_file_handles,
            'increase_from_baseline': current_count - self.baseline_file_handles,
            'history_entries': len(self.file_handle_history)
        }


class ResourceLeakDetector:
    """Main resource leak detection coordinator"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.config = config or {}
        
        # Initialize detectors
        self.memory_detector = MemoryLeakDetector(
            detection_threshold_mb=self.config.get('memory_threshold_mb', 50.0),
            growth_threshold_mb_per_min=self.config.get('memory_growth_threshold_mb_per_min', 10.0)
        )
        
        self.connection_detector = ConnectionLeakDetector(
            max_connections=self.config.get('max_connections', 1000),
            stale_threshold_seconds=self.config.get('connection_stale_threshold_seconds', 300)
        )
        
        self.thread_detector = ThreadLeakDetector(
            max_threads=self.config.get('max_threads', 100),
            stale_threshold_seconds=self.config.get('thread_stale_threshold_seconds', 600)
        )
        
        self.file_handle_detector = FileHandleLeakDetector(
            max_file_handles=self.config.get('max_file_handles', 1000)
        )
        
        # Detection state
        self.detection_enabled = True
        self.detection_interval = self.config.get('detection_interval_seconds', 60)
        self.detected_leaks = []
        self.leak_callbacks = []  # Callbacks for leak notifications
        
        # Monitoring
        self.detection_timer = None
        self.last_detection_time = None
        self.detection_stats = {
            'total_detections': 0,
            'leaks_by_type': defaultdict(int),
            'leaks_by_severity': defaultdict(int),
            'last_detection_duration': 0.0
        }
        
        self._start_detection_timer()
        self.logger.info("ResourceLeakDetector initialized")
    
    def register_leak_callback(self, callback: Callable[[List[LeakDetection]], None]):
        """Register a callback for leak notifications"""
        self.leak_callbacks.append(callback)
    
    def detect_all_leaks(self) -> List[LeakDetection]:
        """Run all leak detectors and return combined results"""
        start_time = time.time()
        all_leaks = []
        
        try:
            # Run all detectors
            memory_leaks = self.memory_detector.detect_memory_leaks()
            connection_leaks = self.connection_detector.detect_connection_leaks()
            thread_leaks = self.thread_detector.detect_thread_leaks()
            file_handle_leaks = self.file_handle_detector.detect_file_handle_leaks()
            
            all_leaks.extend(memory_leaks)
            all_leaks.extend(connection_leaks)
            all_leaks.extend(thread_leaks)
            all_leaks.extend(file_handle_leaks)
            
            # Update statistics
            self.detection_stats['total_detections'] += 1
            for leak in all_leaks:
                self.detection_stats['leaks_by_type'][leak.leak_type.value] += 1
                self.detection_stats['leaks_by_severity'][leak.severity.value] += 1
            
            # Store recent leaks
            self.detected_leaks.extend(all_leaks)
            if len(self.detected_leaks) > 1000:  # Keep last 1000 leaks
                self.detected_leaks = self.detected_leaks[-1000:]
            
            # Notify callbacks
            if all_leaks:
                for callback in self.leak_callbacks:
                    try:
                        callback(all_leaks)
                    except Exception as e:
                        self.logger.error(f"Leak callback failed: {e}")
            
            detection_duration = time.time() - start_time
            self.detection_stats['last_detection_duration'] = detection_duration
            self.last_detection_time = datetime.now()
            
            if all_leaks:
                self.logger.warning(f"Detected {len(all_leaks)} resource leaks in {detection_duration:.2f}s")
            else:
                self.logger.debug(f"No leaks detected in {detection_duration:.2f}s")
            
            return all_leaks
            
        except Exception as e:
            self.logger.error(f"Leak detection failed: {e}")
            return []
    
    def _start_detection_timer(self):
        """Start periodic leak detection"""
        if not self.detection_enabled:
            return
        
        def detection_cycle():
            try:
                self.detect_all_leaks()
            except Exception as e:
                self.logger.error(f"Detection cycle failed: {e}")
            finally:
                if self.detection_enabled:
                    self.detection_timer = threading.Timer(self.detection_interval, detection_cycle)
                    self.detection_timer.daemon = True
                    self.detection_timer.start()
        
        self.detection_timer = threading.Timer(self.detection_interval, detection_cycle)
        self.detection_timer.daemon = True
        self.detection_timer.start()
    
    def get_comprehensive_status(self) -> Dict[str, Any]:
        """Get comprehensive leak detection status"""
        return {
            'detection_enabled': self.detection_enabled,
            'last_detection': self.last_detection_time.isoformat() if self.last_detection_time else None,
            'statistics': dict(self.detection_stats),
            'recent_leaks': [
                {
                    'type': leak.leak_type.value,
                    'severity': leak.severity.value,
                    'description': leak.description,
                    'detected_at': leak.detected_at.isoformat(),
                    'age_seconds': leak.age_seconds()
                }
                for leak in self.detected_leaks[-10:]  # Last 10 leaks
            ],
            'memory_summary': self.memory_detector.get_memory_summary(),
            'connection_summary': self.connection_detector.get_connection_summary(),
            'thread_summary': self.thread_detector.get_thread_summary(),
            'file_handle_summary': self.file_handle_detector.get_file_handle_summary()
        }
    
    def shutdown(self):
        """Shutdown leak detection"""
        self.logger.info("Shutting down ResourceLeakDetector")
        self.detection_enabled = False
        
        if self.detection_timer:
            self.detection_timer.cancel()
        
        self.logger.info("ResourceLeakDetector shutdown complete")
    
    # Convenience methods for external registration
    def register_connection(self, connection_id: str, connection_type: str, **kwargs):
        """Register a connection for leak detection"""
        self.connection_detector.register_connection(connection_id, connection_type, **kwargs)
    
    def unregister_connection(self, connection_id: str):
        """Unregister a connection"""
        self.connection_detector.unregister_connection(connection_id)
    
    def register_thread(self, thread_id: str, thread_name: str, purpose: str, **kwargs):
        """Register a thread for leak detection"""
        self.thread_detector.register_thread(thread_id, thread_name, purpose, **kwargs)
    
    def unregister_thread(self, thread_id: str):
        """Unregister a thread"""
        self.thread_detector.unregister_thread(thread_id)


# Global leak detector instance
_global_leak_detector: Optional[ResourceLeakDetector] = None


def get_global_leak_detector() -> ResourceLeakDetector:
    """Get or create global leak detector"""
    global _global_leak_detector
    if _global_leak_detector is None:
        _global_leak_detector = ResourceLeakDetector()
    return _global_leak_detector


def register_connection_for_leak_detection(connection_id: str, connection_type: str, **kwargs):
    """Convenience function to register a connection for leak detection"""
    detector = get_global_leak_detector()
    detector.register_connection(connection_id, connection_type, **kwargs)


def unregister_connection_from_leak_detection(connection_id: str):
    """Convenience function to unregister a connection"""
    detector = get_global_leak_detector()
    detector.unregister_connection(connection_id)


def register_thread_for_leak_detection(thread_id: str, thread_name: str, purpose: str, **kwargs):
    """Convenience function to register a thread for leak detection"""
    detector = get_global_leak_detector()
    detector.register_thread(thread_id, thread_name, purpose, **kwargs)


def unregister_thread_from_leak_detection(thread_id: str):
    """Convenience function to unregister a thread"""
    detector = get_global_leak_detector()
    detector.unregister_thread(thread_id)


if __name__ == "__main__":
    # Example usage and testing
    detector = ResourceLeakDetector({
        'detection_interval_seconds': 10,
        'memory_threshold_mb': 25.0
    })
    
    def leak_notification(leaks):
        print(f"LEAK ALERT: {len(leaks)} leaks detected!")
        for leak in leaks:
            print(f"  - {leak.leak_type.value}: {leak.description}")
    
    detector.register_leak_callback(leak_notification)
    
    # Simulate some resource usage
    import uuid
    
    # Register some connections
    for i in range(5):
        conn_id = str(uuid.uuid4())
        detector.register_connection(conn_id, 'http')
        
    # Register some threads
    for i in range(3):
        thread_id = str(uuid.uuid4())
        detector.register_thread(thread_id, f'worker-{i}', 'validation')
    
    # Run detection manually
    leaks = detector.detect_all_leaks()
    print(f"Initial detection found {len(leaks)} leaks")
    
    # Get status
    status = detector.get_comprehensive_status()
    print(f"Status: {status}")
    
    # Wait a bit then shutdown
    time.sleep(5)
    detector.shutdown()