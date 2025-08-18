"""Scan Coordinator for Multi-Tiered Proxy Scanning

Coordinates all scanning activities across tiers, manages resource allocation,
and provides a unified interface for proxy scanning operations.
"""

import logging
import asyncio
import threading
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Conditional imports based on what's available
try:
    from ...proxy_core.models import ProxyInfo, TierLevel, ProxyStatus, ValidationStatus
    from .tier_manager import TierManager
    from .scan_scheduler import ScanScheduler, ScheduledScanJob
    from .validation_engine import ValidationEngine, TieredValidator, ValidationResult
    HAS_MODELS = True
except ImportError:
    HAS_MODELS = False
    # Fallback definitions
    class TierLevel(Enum):
        TIER_1 = "tier_1"
        TIER_2 = "tier_2"
        TIER_3 = "tier_3"
        TIER_4 = "tier_4"

logger = logging.getLogger(__name__)


class ScanCoordinatorState(Enum):
    """States of the scan coordinator"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    PAUSING = "pausing"
    PAUSED = "paused"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass
class ScanSession:
    """Represents a scanning session"""
    session_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    proxies_scanned: int = 0
    successful_scans: int = 0
    failed_scans: int = 0
    tier_transitions: int = 0
    average_scan_time: float = 0.0
    tiers_processed: Set[TierLevel] = field(default_factory=set)
    
    @property
    def duration(self) -> Optional[timedelta]:
        if self.end_time:
            return self.end_time - self.start_time
        return datetime.utcnow() - self.start_time
    
    @property
    def success_rate(self) -> float:
        if self.proxies_scanned == 0:
            return 0.0
        return (self.successful_scans / self.proxies_scanned) * 100
    
    @property
    def is_active(self) -> bool:
        return self.end_time is None


@dataclass
class CoordinatorMetrics:
    """Metrics for the scan coordinator"""
    total_sessions: int = 0
    active_sessions: int = 0
    total_proxies_processed: int = 0
    total_successful_scans: int = 0
    total_failed_scans: int = 0
    total_tier_transitions: int = 0
    average_session_duration: float = 0.0
    system_uptime: timedelta = field(default_factory=lambda: timedelta())
    last_updated: datetime = field(default_factory=datetime.utcnow)


class ScanCoordinator:
    """Central coordinator for all proxy scanning operations"""
    
    def __init__(self, tier_manager: TierManager, config: Optional[Dict[str, Any]] = None):
        """
        Initialize scan coordinator
        
        Args:
            tier_manager: TierManager instance
            config: Configuration dictionary
        """
        self.tier_manager = tier_manager
        self.config = config or {}
        
        # Core components
        self.scheduler = ScanScheduler(tier_manager, self.config.get('scheduler', {}))
        self.validation_engine = ValidationEngine(tier_manager, self.config.get('validation', {}))
        self.tiered_validator = TieredValidator(tier_manager, self.validation_engine)
        
        # State management
        self.state = ScanCoordinatorState.STOPPED
        self.state_lock = threading.RLock()
        
        # Session management
        self.current_session: Optional[ScanSession] = None
        self.session_history: List[ScanSession] = []
        self.session_counter = 0
        
        # Metrics and monitoring
        self.metrics = CoordinatorMetrics()
        self.start_time = datetime.utcnow()
        
        # Threading and execution
        self.coordinator_thread: Optional[threading.Thread] = None
        self.execution_pool = ThreadPoolExecutor(
            max_workers=self.config.get('max_workers', 20),
            thread_name_prefix="scan-coordinator"
        )
        
        # Event callbacks
        self.scan_callbacks: List[Callable[[ValidationResult], None]] = []
        self.tier_transition_callbacks: List[Callable[[ProxyInfo, TierLevel, TierLevel], None]] = []
        self.session_callbacks: List[Callable[[ScanSession], None]] = []
        
        # Performance tracking
        self.performance_window = self.config.get('performance_window', 3600)  # 1 hour
        self.performance_history: List[Dict[str, Any]] = []
        
        logger.info("ScanCoordinator initialized successfully")
    
    def start(self) -> bool:
        """
        Start the scan coordinator
        
        Returns:
            True if started successfully, False otherwise
        """
        with self.state_lock:
            if self.state != ScanCoordinatorState.STOPPED:
                logger.warning(f"Cannot start coordinator in state: {self.state.value}")
                return False
            
            self.state = ScanCoordinatorState.STARTING
        
        try:
            # Start scheduler
            self.scheduler.start_scheduler()
            
            # Start coordinator thread
            self.coordinator_thread = threading.Thread(
                target=self._coordinator_loop,
                name="scan-coordinator-main",
                daemon=True
            )
            self.coordinator_thread.start()
            
            # Start new session
            self._start_new_session()
            
            with self.state_lock:
                self.state = ScanCoordinatorState.RUNNING
            
            logger.info("ScanCoordinator started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start ScanCoordinator: {e}")
            with self.state_lock:
                self.state = ScanCoordinatorState.ERROR
            return False
    
    def stop(self) -> bool:
        """
        Stop the scan coordinator
        
        Returns:
            True if stopped successfully, False otherwise
        """
        with self.state_lock:
            if self.state == ScanCoordinatorState.STOPPED:
                return True
            
            self.state = ScanCoordinatorState.STOPPING
        
        try:
            # Stop scheduler
            self.scheduler.stop_scheduler()
            
            # End current session
            if self.current_session:
                self._end_current_session()
            
            # Wait for coordinator thread
            if self.coordinator_thread and self.coordinator_thread.is_alive():
                self.coordinator_thread.join(timeout=10)
            
            # Shutdown execution pool
            self.execution_pool.shutdown(wait=True, timeout=30)
            
            with self.state_lock:
                self.state = ScanCoordinatorState.STOPPED
            
            logger.info("ScanCoordinator stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop ScanCoordinator: {e}")
            with self.state_lock:
                self.state = ScanCoordinatorState.ERROR
            return False
    
    def pause(self) -> bool:
        """Pause scanning operations"""
        with self.state_lock:
            if self.state != ScanCoordinatorState.RUNNING:
                return False
            
            self.state = ScanCoordinatorState.PAUSING
            # Implementation would pause active scans
            self.state = ScanCoordinatorState.PAUSED
            
        logger.info("ScanCoordinator paused")
        return True
    
    def resume(self) -> bool:
        """Resume scanning operations"""
        with self.state_lock:
            if self.state != ScanCoordinatorState.PAUSED:
                return False
            
            self.state = ScanCoordinatorState.RUNNING
        
        logger.info("ScanCoordinator resumed")
        return True
    
    def schedule_proxy_scan(self, proxy: ProxyInfo, priority_override: Optional[float] = None) -> bool:
        """
        Schedule a proxy for scanning
        
        Args:
            proxy: ProxyInfo object to schedule
            priority_override: Optional priority override
            
        Returns:
            True if scheduled successfully
        """
        if self.state != ScanCoordinatorState.RUNNING:
            logger.warning("Cannot schedule scan - coordinator not running")
            return False
        
        return self.scheduler.schedule_proxy_scan(proxy, priority_override)
    
    def schedule_proxy_batch(self, proxies: List[ProxyInfo]) -> int:
        """
        Schedule multiple proxies for scanning
        
        Args:
            proxies: List of ProxyInfo objects to schedule
            
        Returns:
            Number of proxies successfully scheduled
        """
        if self.state != ScanCoordinatorState.RUNNING:
            logger.warning("Cannot schedule batch - coordinator not running")
            return 0
        
        scheduled_count = 0
        for proxy in proxies:
            if self.scheduler.schedule_proxy_scan(proxy):
                scheduled_count += 1
        
        return scheduled_count
    
    def force_scan_proxy(self, proxy: ProxyInfo, tier_override: Optional[TierLevel] = None) -> ValidationResult:
        """
        Force immediate scan of a proxy (bypass scheduling)
        
        Args:
            proxy: ProxyInfo object to scan
            tier_override: Optional tier level override
            
        Returns:
            ValidationResult object
        """
        result = self.validation_engine.validate_proxy(proxy, tier_override)
        
        # Process result
        self._process_scan_result(proxy, result)
        
        return result
    
    def _coordinator_loop(self):
        """Main coordinator loop"""
        logger.info("Coordinator loop started")
        
        while self.state in [ScanCoordinatorState.RUNNING, ScanCoordinatorState.PAUSED]:
            try:
                if self.state == ScanCoordinatorState.RUNNING:
                    self._process_scheduled_scans()
                    self._update_metrics()
                    self._cleanup_old_data()
                
                time.sleep(1)  # Process every second
                
            except Exception as e:
                logger.error(f"Error in coordinator loop: {e}")
                time.sleep(5)  # Wait before retrying
        
        logger.info("Coordinator loop ended")
    
    def _process_scheduled_scans(self):
        """Process scheduled scans from all tiers"""
        # Get ready jobs from scheduler
        ready_jobs = []
        
        for tier in TierLevel:
            tier_jobs = self.scheduler.get_next_jobs(tier, count=5)
            ready_jobs.extend(tier_jobs)
        
        if not ready_jobs:
            return
        
        # Sort by priority
        ready_jobs.sort(key=lambda j: (-j.priority, j.scheduled_time))
        
        # Submit jobs to execution pool
        futures = []
        for job in ready_jobs[:10]:  # Process up to 10 jobs at once
            future = self.execution_pool.submit(self._execute_scan_job, job)
            futures.append((future, job))
        
        # Process completed futures
        for future, job in futures:
            try:
                if future.done():
                    result = future.result(timeout=1)
                    self._process_scan_result(job.proxy, result)
            except Exception as e:
                logger.error(f"Error processing scan job for {job.proxy.proxy_id}: {e}")
                self._handle_scan_failure(job, str(e))
    
    def _execute_scan_job(self, job: ScheduledScanJob) -> ValidationResult:
        """Execute a single scan job"""
        try:
            # Mark job as started
            self.scheduler.complete_job(job.proxy.proxy_id, success=False)  # Will be updated later
            
            # Perform validation and tier update
            result, tier_changed = self.tiered_validator.validate_and_update_tier(job.proxy)
            
            # Update scheduler with actual result
            self.scheduler.complete_job(job.proxy.proxy_id, success=result.success)
            
            # Handle tier transition
            if tier_changed:
                self._handle_tier_transition(job.proxy, job.tier_level, job.proxy.tier_level)
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to execute scan job for {job.proxy.proxy_id}: {e}")
            result = ValidationResult(
                proxy_id=job.proxy.proxy_id,
                success=False,
                response_time=0.0,
                error_message=str(e),
                tier_level=job.tier_level
            )
            self.scheduler.complete_job(job.proxy.proxy_id, success=False, error=str(e))
            return result
    
    def _process_scan_result(self, proxy: ProxyInfo, result: ValidationResult):
        """Process the result of a proxy scan"""
        # Update session metrics
        if self.current_session:
            self.current_session.proxies_scanned += 1
            if result.success:
                self.current_session.successful_scans += 1
            else:
                self.current_session.failed_scans += 1
            
            # Update average scan time
            total_time = (self.current_session.average_scan_time * 
                         (self.current_session.proxies_scanned - 1))
            self.current_session.average_scan_time = (
                (total_time + result.response_time) / self.current_session.proxies_scanned
            )
            
            self.current_session.tiers_processed.add(result.tier_level)
        
        # Call scan callbacks
        for callback in self.scan_callbacks:
            try:
                callback(result)
            except Exception as e:
                logger.error(f"Error in scan callback: {e}")
        
        logger.debug(f"Processed scan result for {proxy.proxy_id}: "
                    f"{'success' if result.success else 'failed'}")
    
    def _handle_tier_transition(self, proxy: ProxyInfo, old_tier: TierLevel, new_tier: TierLevel):
        """Handle proxy tier transition"""
        if self.current_session:
            self.current_session.tier_transitions += 1
        
        # Call tier transition callbacks
        for callback in self.tier_transition_callbacks:
            try:
                callback(proxy, old_tier, new_tier)
            except Exception as e:
                logger.error(f"Error in tier transition callback: {e}")
        
        logger.info(f"Tier transition: {proxy.proxy_id} moved from "
                   f"{old_tier.value} to {new_tier.value}")
    
    def _handle_scan_failure(self, job: ScheduledScanJob, error: str):
        """Handle scan job failure"""
        self.scheduler.complete_job(job.proxy.proxy_id, success=False, error=error)
        
        if self.current_session:
            self.current_session.failed_scans += 1
        
        logger.warning(f"Scan failed for {job.proxy.proxy_id}: {error}")
    
    def _start_new_session(self):
        """Start a new scanning session"""
        self.session_counter += 1
        session_id = f"session_{self.session_counter}_{int(time.time())}"
        
        self.current_session = ScanSession(
            session_id=session_id,
            start_time=datetime.utcnow()
        )
        
        self.metrics.total_sessions += 1
        self.metrics.active_sessions += 1
        
        logger.info(f"Started new scanning session: {session_id}")
    
    def _end_current_session(self):
        """End the current scanning session"""
        if not self.current_session:
            return
        
        self.current_session.end_time = datetime.utcnow()
        self.session_history.append(self.current_session)
        
        # Call session callbacks
        for callback in self.session_callbacks:
            try:
                callback(self.current_session)
            except Exception as e:
                logger.error(f"Error in session callback: {e}")
        
        logger.info(f"Ended scanning session: {self.current_session.session_id}")
        
        self.metrics.active_sessions -= 1
        self.current_session = None
        
        # Limit session history
        if len(self.session_history) > 100:
            self.session_history = self.session_history[-50:]
    
    def _update_metrics(self):
        """Update coordinator metrics"""
        now = datetime.utcnow()
        
        # Update uptime
        self.metrics.system_uptime = now - self.start_time
        
        # Update totals from sessions
        total_proxies = sum(s.proxies_scanned for s in self.session_history)
        total_successful = sum(s.successful_scans for s in self.session_history)
        total_failed = sum(s.failed_scans for s in self.session_history)
        total_transitions = sum(s.tier_transitions for s in self.session_history)
        
        if self.current_session:
            total_proxies += self.current_session.proxies_scanned
            total_successful += self.current_session.successful_scans
            total_failed += self.current_session.failed_scans
            total_transitions += self.current_session.tier_transitions
        
        self.metrics.total_proxies_processed = total_proxies
        self.metrics.total_successful_scans = total_successful
        self.metrics.total_failed_scans = total_failed
        self.metrics.total_tier_transitions = total_transitions
        
        # Update average session duration
        completed_sessions = [s for s in self.session_history if s.end_time]
        if completed_sessions:
            total_duration = sum(s.duration.total_seconds() for s in completed_sessions)
            self.metrics.average_session_duration = total_duration / len(completed_sessions)
        
        self.metrics.last_updated = now
    
    def _cleanup_old_data(self):
        """Clean up old data to prevent memory leaks"""
        # Clean up old performance history
        cutoff_time = datetime.utcnow() - timedelta(seconds=self.performance_window)
        self.performance_history = [
            h for h in self.performance_history 
            if h.get('timestamp', datetime.min) > cutoff_time
        ]
    
    def add_scan_callback(self, callback: Callable[[ValidationResult], None]):
        """Add callback for scan results"""
        self.scan_callbacks.append(callback)
    
    def add_tier_transition_callback(self, callback: Callable[[ProxyInfo, TierLevel, TierLevel], None]):
        """Add callback for tier transitions"""
        self.tier_transition_callbacks.append(callback)
    
    def add_session_callback(self, callback: Callable[[ScanSession], None]):
        """Add callback for session events"""
        self.session_callbacks.append(callback)
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive coordinator status"""
        return {
            'state': self.state.value,
            'uptime_seconds': self.metrics.system_uptime.total_seconds(),
            'current_session': {
                'session_id': self.current_session.session_id if self.current_session else None,
                'duration_seconds': self.current_session.duration.total_seconds() if self.current_session else 0,
                'proxies_scanned': self.current_session.proxies_scanned if self.current_session else 0,
                'success_rate': self.current_session.success_rate if self.current_session else 0,
                'tier_transitions': self.current_session.tier_transitions if self.current_session else 0
            },
            'scheduler_status': self.scheduler.get_queue_status(),
            'validation_stats': self.validation_engine.get_validation_statistics(),
            'tier_performance': self.validation_engine.get_tier_performance_summary(),
            'metrics': {
                'total_sessions': self.metrics.total_sessions,
                'total_proxies_processed': self.metrics.total_proxies_processed,
                'total_successful_scans': self.metrics.total_successful_scans,
                'total_failed_scans': self.metrics.total_failed_scans,
                'overall_success_rate': (
                    (self.metrics.total_successful_scans / 
                     max(self.metrics.total_proxies_processed, 1)) * 100
                ),
                'total_tier_transitions': self.metrics.total_tier_transitions
            }
        }


def create_scan_coordinator(tier_manager: TierManager, 
                          config: Optional[Dict[str, Any]] = None) -> ScanCoordinator:
    """Factory function to create scan coordinator"""
    return ScanCoordinator(tier_manager, config)