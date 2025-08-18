"""Enhanced Session Cleanup Mechanisms for Interrupted Validation Sessions

This module provides comprehensive cleanup mechanisms for handling interrupted validation
sessions, connection leaks, resource management, and graceful shutdowns.
"""

import atexit
import logging
import signal
import threading
import time
import weakref
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, Future
import psutil
import gc


class CleanupPriority(Enum):
    """Priority levels for cleanup operations"""
    CRITICAL = 1    # Must be cleaned immediately (security/memory critical)
    HIGH = 2        # Should be cleaned soon (resource leaks)
    MEDIUM = 3      # Normal cleanup priority
    LOW = 4         # Can be deferred (optimization)


class ResourceType(Enum):
    """Types of resources that need cleanup"""
    HTTP_CONNECTION = "http_connection"
    SOCKS_CONNECTION = "socks_connection"
    THREAD_POOL = "thread_pool"
    FILE_HANDLE = "file_handle"
    SOCKET = "socket"
    SSL_CONTEXT = "ssl_context"
    CACHE_ENTRY = "cache_entry"
    TEMP_FILE = "temp_file"
    MEMORY_BUFFER = "memory_buffer"
    ASYNC_TASK = "async_task"


@dataclass
class CleanupTask:
    """Represents a cleanup task to be executed"""
    resource_id: str
    resource_type: ResourceType
    cleanup_function: Callable[[], None]
    priority: CleanupPriority
    created_at: datetime = field(default_factory=datetime.now)
    timeout_seconds: float = 30.0
    retries_left: int = 3
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self, max_age_seconds: float = 3600) -> bool:
        """Check if cleanup task has expired"""
        return (datetime.now() - self.created_at).total_seconds() > max_age_seconds


@dataclass
class SessionState:
    """Tracks the state of a validation session"""
    session_id: str
    created_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    resources: Set[str] = field(default_factory=set)
    thread_count: int = 0
    connection_count: int = 0
    is_interrupted: bool = False
    cleanup_scheduled: bool = False
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.now()
    
    def is_stale(self, max_idle_seconds: float = 300) -> bool:
        """Check if session is stale (inactive)"""
        return (datetime.now() - self.last_activity).total_seconds() > max_idle_seconds


class InterruptionHandler:
    """Handles various types of interruptions and triggers appropriate cleanup"""
    
    def __init__(self, cleanup_manager: 'SessionCleanupManager'):
        self.cleanup_manager = cleanup_manager
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._original_handlers = {}
        self._setup_signal_handlers()
        self._setup_exit_handlers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful interruption handling"""
        def signal_handler(signum, frame):
            signal_name = signal.Signals(signum).name
            self.logger.warning(f"Received {signal_name} signal - initiating cleanup")
            self.cleanup_manager.handle_interruption(f"signal_{signal_name}")
        
        # Handle common termination signals
        for sig in [signal.SIGINT, signal.SIGTERM]:
            try:
                self._original_handlers[sig] = signal.signal(sig, signal_handler)
            except (ValueError, OSError) as e:
                self.logger.debug(f"Could not set handler for {sig}: {e}")
    
    def _setup_exit_handlers(self):
        """Setup exit handlers for cleanup on normal termination"""
        def exit_handler():
            self.logger.info("Process exiting - performing final cleanup")
            self.cleanup_manager.perform_emergency_cleanup()
        
        atexit.register(exit_handler)
    
    def restore_handlers(self):
        """Restore original signal handlers"""
        for sig, handler in self._original_handlers.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError) as e:
                self.logger.debug(f"Could not restore handler for {sig}: {e}")


class ResourceTracker:
    """Tracks and monitors system resources"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._tracked_resources = weakref.WeakValueDictionary()
        self._resource_counts = defaultdict(int)
        self._resource_lock = threading.RLock()
        
        # Resource limits
        self.max_connections = 1000
        self.max_threads = 100
        self.max_memory_mb = 512
        
        # Monitoring
        self._last_check = time.time()
        self._check_interval = 30  # seconds
    
    def register_resource(self, resource_id: str, resource_type: ResourceType, 
                         resource_obj: Any, metadata: Optional[Dict] = None):
        """Register a resource for tracking"""
        with self._resource_lock:
            self._tracked_resources[resource_id] = resource_obj
            self._resource_counts[resource_type] += 1
            
            self.logger.debug(f"Registered {resource_type.value} resource: {resource_id}")
            
            # Check if we're approaching limits
            self._check_resource_limits(resource_type)
    
    def unregister_resource(self, resource_id: str, resource_type: ResourceType):
        """Unregister a resource"""
        with self._resource_lock:
            if resource_id in self._tracked_resources:
                del self._tracked_resources[resource_id]
            
            self._resource_counts[resource_type] = max(0, self._resource_counts[resource_type] - 1)
            self.logger.debug(f"Unregistered {resource_type.value} resource: {resource_id}")
    
    def _check_resource_limits(self, resource_type: ResourceType):
        """Check if resource limits are being approached"""
        count = self._resource_counts[resource_type]
        
        if resource_type == ResourceType.HTTP_CONNECTION and count > self.max_connections * 0.8:
            self.logger.warning(f"High connection count: {count}/{self.max_connections}")
        elif resource_type == ResourceType.THREAD_POOL and count > self.max_threads * 0.8:
            self.logger.warning(f"High thread count: {count}/{self.max_threads}")
    
    def get_resource_summary(self) -> Dict[str, int]:
        """Get summary of tracked resources"""
        with self._resource_lock:
            return dict(self._resource_counts)
    
    def check_system_resources(self) -> Dict[str, Any]:
        """Check overall system resource usage"""
        current_time = time.time()
        if current_time - self._last_check < self._check_interval:
            return {}
        
        self._last_check = current_time
        
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            
            return {
                'memory_mb': memory_info.rss / 1024 / 1024,
                'cpu_percent': process.cpu_percent(),
                'thread_count': process.num_threads(),
                'open_files': len(process.open_files()) if hasattr(process, 'open_files') else 0,
                'connections': len(process.connections()) if hasattr(process, 'connections') else 0
            }
        except Exception as e:
            self.logger.debug(f"Could not check system resources: {e}")
            return {}


class SessionCleanupManager:
    """Main cleanup manager for validation sessions"""
    
    def __init__(self, enable_auto_cleanup: bool = True):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Core components
        self.resource_tracker = ResourceTracker()
        self.interruption_handler = InterruptionHandler(self)
        
        # State tracking
        self.sessions: Dict[str, SessionState] = {}
        self.cleanup_tasks: Dict[str, CleanupTask] = {}
        self.session_lock = threading.RLock()
        self.cleanup_lock = threading.RLock()
        
        # Cleanup scheduling
        self.auto_cleanup_enabled = enable_auto_cleanup
        self.cleanup_timer = None
        self.cleanup_interval = 60  # seconds
        self.emergency_cleanup_active = False
        
        # Statistics
        self.cleanup_stats = {
            'total_cleanups': 0,
            'successful_cleanups': 0,
            'failed_cleanups': 0,
            'resources_cleaned': defaultdict(int),
            'last_cleanup': None
        }
        
        if self.auto_cleanup_enabled:
            self._start_cleanup_timer()
        
        self.logger.info("SessionCleanupManager initialized")
    
    def create_session(self, session_id: str) -> str:
        """Create a new validation session"""
        with self.session_lock:
            if session_id in self.sessions:
                self.logger.warning(f"Session {session_id} already exists")
                return session_id
            
            self.sessions[session_id] = SessionState(session_id=session_id)
            self.logger.debug(f"Created session: {session_id}")
            return session_id
    
    def register_session_resource(self, session_id: str, resource_id: str, 
                                 resource_type: ResourceType, resource_obj: Any,
                                 cleanup_function: Callable[[], None],
                                 priority: CleanupPriority = CleanupPriority.MEDIUM):
        """Register a resource associated with a session"""
        with self.session_lock:
            # Ensure session exists
            if session_id not in self.sessions:
                self.create_session(session_id)
            
            session = self.sessions[session_id]
            session.resources.add(resource_id)
            session.update_activity()
            
            # Track resource counts
            if resource_type == ResourceType.THREAD_POOL:
                session.thread_count += 1
            elif resource_type in [ResourceType.HTTP_CONNECTION, ResourceType.SOCKS_CONNECTION]:
                session.connection_count += 1
        
        # Register with resource tracker
        self.resource_tracker.register_resource(resource_id, resource_type, resource_obj)
        
        # Create cleanup task
        cleanup_task = CleanupTask(
            resource_id=resource_id,
            resource_type=resource_type,
            cleanup_function=cleanup_function,
            priority=priority,
            metadata={'session_id': session_id}
        )
        
        with self.cleanup_lock:
            self.cleanup_tasks[resource_id] = cleanup_task
        
        self.logger.debug(f"Registered {resource_type.value} resource {resource_id} for session {session_id}")
    
    def mark_session_interrupted(self, session_id: str, reason: str = "unknown"):
        """Mark a session as interrupted and schedule cleanup"""
        with self.session_lock:
            if session_id not in self.sessions:
                self.logger.warning(f"Cannot mark unknown session as interrupted: {session_id}")
                return
            
            session = self.sessions[session_id]
            session.is_interrupted = True
            session.cleanup_scheduled = True
            
            self.logger.warning(f"Session {session_id} marked as interrupted: {reason}")
            
            # Schedule immediate cleanup for interrupted session
            self._schedule_session_cleanup(session_id, immediate=True)
    
    def handle_interruption(self, interruption_type: str):
        """Handle system-wide interruption"""
        self.logger.warning(f"Handling interruption: {interruption_type}")
        
        # Mark all active sessions as interrupted
        with self.session_lock:
            for session_id, session in self.sessions.items():
                if not session.is_interrupted:
                    session.is_interrupted = True
                    session.cleanup_scheduled = True
        
        # Perform emergency cleanup
        self.perform_emergency_cleanup()
    
    def _schedule_session_cleanup(self, session_id: str, immediate: bool = False):
        """Schedule cleanup for a specific session"""
        if immediate:
            # Run cleanup immediately in background thread
            cleanup_thread = threading.Thread(
                target=self._cleanup_session_resources,
                args=(session_id,),
                name=f"cleanup-{session_id}",
                daemon=True
            )
            cleanup_thread.start()
        else:
            # Will be handled by next cleanup cycle
            pass
    
    def _cleanup_session_resources(self, session_id: str):
        """Clean up all resources associated with a session"""
        with self.session_lock:
            if session_id not in self.sessions:
                return
            
            session = self.sessions[session_id]
            resource_ids = list(session.resources)
        
        cleaned_count = 0
        failed_count = 0
        
        # Sort cleanup tasks by priority
        tasks_to_clean = []
        with self.cleanup_lock:
            for resource_id in resource_ids:
                if resource_id in self.cleanup_tasks:
                    tasks_to_clean.append(self.cleanup_tasks[resource_id])
        
        tasks_to_clean.sort(key=lambda t: t.priority.value)
        
        # Execute cleanup tasks
        for task in tasks_to_clean:
            try:
                self._execute_cleanup_task(task)
                cleaned_count += 1
                
                # Remove from tracking
                with self.cleanup_lock:
                    if task.resource_id in self.cleanup_tasks:
                        del self.cleanup_tasks[task.resource_id]
                
                self.resource_tracker.unregister_resource(task.resource_id, task.resource_type)
                
            except Exception as e:
                failed_count += 1
                self.logger.error(f"Failed to cleanup resource {task.resource_id}: {e}")
        
        # Remove session
        with self.session_lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
        
        self.logger.info(f"Session {session_id} cleanup completed: {cleaned_count} cleaned, {failed_count} failed")
        
        # Update statistics
        self.cleanup_stats['total_cleanups'] += 1
        self.cleanup_stats['successful_cleanups'] += cleaned_count
        self.cleanup_stats['failed_cleanups'] += failed_count
        self.cleanup_stats['last_cleanup'] = datetime.now()
    
    def _execute_cleanup_task(self, task: CleanupTask):
        """Execute a single cleanup task with timeout and retry logic"""
        def timeout_wrapper():
            try:
                task.cleanup_function()
                self.cleanup_stats['resources_cleaned'][task.resource_type] += 1
            except Exception as e:
                if task.retries_left > 0:
                    task.retries_left -= 1
                    self.logger.warning(f"Cleanup failed for {task.resource_id}, retries left: {task.retries_left}")
                    raise
                else:
                    self.logger.error(f"Cleanup permanently failed for {task.resource_id}: {e}")
                    raise
        
        # Execute with timeout
        cleanup_thread = threading.Thread(target=timeout_wrapper, daemon=True)
        cleanup_thread.start()
        cleanup_thread.join(timeout=task.timeout_seconds)
        
        if cleanup_thread.is_alive():
            self.logger.error(f"Cleanup task {task.resource_id} timed out after {task.timeout_seconds}s")
            raise TimeoutError(f"Cleanup timeout for {task.resource_id}")
    
    def perform_emergency_cleanup(self):
        """Perform emergency cleanup of all resources"""
        if self.emergency_cleanup_active:
            return
        
        self.emergency_cleanup_active = True
        start_time = time.time()
        
        try:
            self.logger.warning("Starting emergency cleanup")
            
            # Get all sessions and cleanup tasks
            with self.session_lock:
                session_ids = list(self.sessions.keys())
            
            # Cleanup critical resources first
            critical_tasks = []
            high_priority_tasks = []
            other_tasks = []
            
            with self.cleanup_lock:
                for task in self.cleanup_tasks.values():
                    if task.priority == CleanupPriority.CRITICAL:
                        critical_tasks.append(task)
                    elif task.priority == CleanupPriority.HIGH:
                        high_priority_tasks.append(task)
                    else:
                        other_tasks.append(task)
            
            # Execute in priority order
            for task_group in [critical_tasks, high_priority_tasks, other_tasks]:
                for task in task_group:
                    try:
                        # Reduced timeout for emergency cleanup
                        task.timeout_seconds = min(task.timeout_seconds, 10.0)
                        self._execute_cleanup_task(task)
                        self.resource_tracker.unregister_resource(task.resource_id, task.resource_type)
                    except Exception as e:
                        self.logger.error(f"Emergency cleanup failed for {task.resource_id}: {e}")
            
            # Clear all tracking
            with self.session_lock:
                self.sessions.clear()
            
            with self.cleanup_lock:
                self.cleanup_tasks.clear()
            
            # Force garbage collection
            gc.collect()
            
            duration = time.time() - start_time
            self.logger.warning(f"Emergency cleanup completed in {duration:.2f}s")
            
        finally:
            self.emergency_cleanup_active = False
    
    def _start_cleanup_timer(self):
        """Start periodic cleanup timer"""
        def cleanup_cycle():
            try:
                self._periodic_cleanup()
            except Exception as e:
                self.logger.error(f"Cleanup cycle failed: {e}")
            finally:
                if self.auto_cleanup_enabled:
                    self.cleanup_timer = threading.Timer(self.cleanup_interval, cleanup_cycle)
                    self.cleanup_timer.daemon = True
                    self.cleanup_timer.start()
        
        self.cleanup_timer = threading.Timer(self.cleanup_interval, cleanup_cycle)
        self.cleanup_timer.daemon = True
        self.cleanup_timer.start()
    
    def _periodic_cleanup(self):
        """Perform periodic cleanup of stale sessions and expired tasks"""
        current_time = datetime.now()
        
        # Find stale sessions
        stale_sessions = []
        with self.session_lock:
            for session_id, session in self.sessions.items():
                if session.is_stale() or session.is_interrupted:
                    stale_sessions.append(session_id)
        
        # Cleanup stale sessions
        for session_id in stale_sessions:
            self.logger.debug(f"Cleaning up stale session: {session_id}")
            self._cleanup_session_resources(session_id)
        
        # Find expired cleanup tasks
        expired_tasks = []
        with self.cleanup_lock:
            for task_id, task in self.cleanup_tasks.items():
                if task.is_expired():
                    expired_tasks.append(task_id)
        
        # Remove expired tasks
        with self.cleanup_lock:
            for task_id in expired_tasks:
                if task_id in self.cleanup_tasks:
                    del self.cleanup_tasks[task_id]
        
        if expired_tasks:
            self.logger.debug(f"Removed {len(expired_tasks)} expired cleanup tasks")
        
        # Check system resources
        resource_summary = self.resource_tracker.check_system_resources()
        if resource_summary:
            memory_mb = resource_summary.get('memory_mb', 0)
            if memory_mb > self.resource_tracker.max_memory_mb:
                self.logger.warning(f"High memory usage: {memory_mb:.1f}MB")
    
    def get_cleanup_status(self) -> Dict[str, Any]:
        """Get current cleanup status and statistics"""
        with self.session_lock:
            active_sessions = len(self.sessions)
            interrupted_sessions = sum(1 for s in self.sessions.values() if s.is_interrupted)
        
        with self.cleanup_lock:
            pending_tasks = len(self.cleanup_tasks)
            critical_tasks = sum(1 for t in self.cleanup_tasks.values() 
                               if t.priority == CleanupPriority.CRITICAL)
        
        resource_summary = self.resource_tracker.get_resource_summary()
        system_resources = self.resource_tracker.check_system_resources()
        
        return {
            'sessions': {
                'active': active_sessions,
                'interrupted': interrupted_sessions
            },
            'cleanup_tasks': {
                'pending': pending_tasks,
                'critical': critical_tasks
            },
            'resources': resource_summary,
            'system': system_resources,
            'statistics': self.cleanup_stats.copy(),
            'emergency_cleanup_active': self.emergency_cleanup_active
        }
    
    def shutdown(self):
        """Shutdown cleanup manager gracefully"""
        self.logger.info("Shutting down SessionCleanupManager")
        
        # Stop auto cleanup
        self.auto_cleanup_enabled = False
        if self.cleanup_timer:
            self.cleanup_timer.cancel()
        
        # Perform final cleanup
        self.perform_emergency_cleanup()
        
        # Restore signal handlers
        self.interruption_handler.restore_handlers()
        
        self.logger.info("SessionCleanupManager shutdown complete")


@contextmanager
def managed_validation_session(session_id: str, cleanup_manager: SessionCleanupManager):
    """Context manager for validation sessions with automatic cleanup"""
    cleanup_manager.create_session(session_id)
    try:
        yield session_id
    except KeyboardInterrupt:
        cleanup_manager.mark_session_interrupted(session_id, "keyboard_interrupt")
        raise
    except Exception as e:
        cleanup_manager.mark_session_interrupted(session_id, f"exception_{type(e).__name__}")
        raise
    finally:
        # Ensure cleanup happens
        cleanup_manager._cleanup_session_resources(session_id)


# Global cleanup manager instance
_global_cleanup_manager: Optional[SessionCleanupManager] = None


def get_global_cleanup_manager() -> SessionCleanupManager:
    """Get or create global cleanup manager"""
    global _global_cleanup_manager
    if _global_cleanup_manager is None:
        _global_cleanup_manager = SessionCleanupManager()
    return _global_cleanup_manager


def register_cleanup_resource(session_id: str, resource_id: str, resource_type: ResourceType,
                             resource_obj: Any, cleanup_function: Callable[[], None],
                             priority: CleanupPriority = CleanupPriority.MEDIUM):
    """Convenience function to register a resource for cleanup"""
    manager = get_global_cleanup_manager()
    manager.register_session_resource(session_id, resource_id, resource_type, 
                                    resource_obj, cleanup_function, priority)


def cleanup_session(session_id: str):
    """Convenience function to cleanup a session"""
    manager = get_global_cleanup_manager()
    manager._cleanup_session_resources(session_id)


if __name__ == "__main__":
    # Example usage
    cleanup_manager = SessionCleanupManager()
    
    # Create a test session
    session_id = "test_session_001"
    
    with managed_validation_session(session_id, cleanup_manager):
        # Simulate resource registration
        def dummy_cleanup():
            print("Cleaning up dummy resource")
        
        cleanup_manager.register_session_resource(
            session_id, "test_resource_1", ResourceType.HTTP_CONNECTION,
            object(), dummy_cleanup, CleanupPriority.HIGH
        )
        
        print("Session active...")
        time.sleep(2)
    
    print("Session completed")
    
    # Check status
    status = cleanup_manager.get_cleanup_status()
    print(f"Cleanup status: {status}")
    
    cleanup_manager.shutdown()