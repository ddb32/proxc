"""Automated Resource Cleanup Triggers

This module provides automated cleanup triggers that respond to resource leak
detections and system resource pressure to prevent system degradation.
"""

import logging
import threading
import time
import gc
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field

from .resource_leak_detector import (
    ResourceLeakDetector, LeakDetection, LeakType, LeakSeverity,
    get_global_leak_detector
)
from .session_cleanup import (
    SessionCleanupManager, CleanupPriority, ResourceType,
    get_global_cleanup_manager
)


class TriggerType(Enum):
    """Types of cleanup triggers"""
    LEAK_DETECTION = "leak_detection"
    MEMORY_PRESSURE = "memory_pressure"
    CONNECTION_LIMIT = "connection_limit"
    THREAD_LIMIT = "thread_limit"
    FILE_HANDLE_LIMIT = "file_handle_limit"
    PERIODIC_MAINTENANCE = "periodic_maintenance"
    EMERGENCY_CLEANUP = "emergency_cleanup"


class TriggerAction(Enum):
    """Actions that can be triggered"""
    FORCE_GARBAGE_COLLECTION = "force_gc"
    CLOSE_IDLE_CONNECTIONS = "close_idle_connections"
    CLEANUP_STALE_SESSIONS = "cleanup_stale_sessions"
    REDUCE_THREAD_POOLS = "reduce_thread_pools"
    CLEAR_CACHES = "clear_caches"
    EMERGENCY_SHUTDOWN = "emergency_shutdown"
    NOTIFY_OPERATORS = "notify_operators"
    THROTTLE_NEW_REQUESTS = "throttle_requests"


@dataclass
class TriggerCondition:
    """Defines when a trigger should activate"""
    trigger_type: TriggerType
    threshold_value: float
    comparison_operator: str  # "gt", "lt", "eq", "gte", "lte"
    check_interval_seconds: float = 30.0
    cooldown_seconds: float = 300.0  # Minimum time between triggers
    enabled: bool = True


@dataclass
class CleanupAction:
    """Defines an action to take when triggered"""
    action_type: TriggerAction
    priority: int = 1  # Lower numbers = higher priority
    timeout_seconds: float = 30.0
    enabled: bool = True
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TriggerRule:
    """Complete trigger rule with condition and actions"""
    name: str
    condition: TriggerCondition
    actions: List[CleanupAction]
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0
    enabled: bool = True
    
    def can_trigger(self) -> bool:
        """Check if this rule can be triggered (considering cooldown)"""
        if not self.enabled:
            return False
        
        if self.last_triggered is None:
            return True
        
        cooldown_elapsed = (datetime.now() - self.last_triggered).total_seconds()
        return cooldown_elapsed >= self.condition.cooldown_seconds


class AutomatedCleanupTrigger:
    """Main automated cleanup trigger system"""
    
    def __init__(self, 
                 leak_detector: Optional[ResourceLeakDetector] = None,
                 cleanup_manager: Optional[SessionCleanupManager] = None):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Dependencies
        self.leak_detector = leak_detector or get_global_leak_detector()
        self.cleanup_manager = cleanup_manager or get_global_cleanup_manager()
        
        # Trigger rules
        self.trigger_rules = {}
        self.trigger_lock = threading.RLock()
        
        # Monitoring
        self.monitoring_enabled = True
        self.monitoring_timer = None
        self.monitoring_interval = 30.0  # seconds
        
        # Statistics
        self.trigger_stats = {
            'total_triggers': 0,
            'triggers_by_type': {},
            'triggers_by_rule': {},
            'actions_executed': {},
            'failed_actions': 0,
            'last_trigger_time': None
        }
        
        # Action handlers
        self.action_handlers = {
            TriggerAction.FORCE_GARBAGE_COLLECTION: self._force_garbage_collection,
            TriggerAction.CLOSE_IDLE_CONNECTIONS: self._close_idle_connections,
            TriggerAction.CLEANUP_STALE_SESSIONS: self._cleanup_stale_sessions,
            TriggerAction.REDUCE_THREAD_POOLS: self._reduce_thread_pools,
            TriggerAction.CLEAR_CACHES: self._clear_caches,
            TriggerAction.EMERGENCY_SHUTDOWN: self._emergency_shutdown,
            TriggerAction.NOTIFY_OPERATORS: self._notify_operators,
            TriggerAction.THROTTLE_NEW_REQUESTS: self._throttle_new_requests
        }
        
        # Setup default rules
        self._setup_default_rules()
        
        # Register for leak notifications
        self.leak_detector.register_leak_callback(self._handle_leak_detection)
        
        # Start monitoring
        self._start_monitoring()
        
        self.logger.info("AutomatedCleanupTrigger initialized")
    
    def _setup_default_rules(self):
        """Setup default trigger rules"""
        
        # Memory pressure rules
        self.add_trigger_rule(TriggerRule(
            name="high_memory_pressure",
            condition=TriggerCondition(
                trigger_type=TriggerType.MEMORY_PRESSURE,
                threshold_value=512.0,  # 512MB
                comparison_operator="gt",
                check_interval_seconds=30.0,
                cooldown_seconds=120.0
            ),
            actions=[
                CleanupAction(TriggerAction.FORCE_GARBAGE_COLLECTION, priority=1),
                CleanupAction(TriggerAction.CLEAR_CACHES, priority=2, 
                             parameters={'max_clear_percentage': 50}),
                CleanupAction(TriggerAction.CLEANUP_STALE_SESSIONS, priority=3)
            ]
        ))
        
        self.add_trigger_rule(TriggerRule(
            name="critical_memory_pressure",
            condition=TriggerCondition(
                trigger_type=TriggerType.MEMORY_PRESSURE,
                threshold_value=1024.0,  # 1GB
                comparison_operator="gt",
                check_interval_seconds=15.0,
                cooldown_seconds=60.0
            ),
            actions=[
                CleanupAction(TriggerAction.EMERGENCY_SHUTDOWN, priority=1),
                CleanupAction(TriggerAction.NOTIFY_OPERATORS, priority=1,
                             parameters={'severity': 'critical', 'message': 'Critical memory pressure'})
            ]
        ))
        
        # Connection limit rules
        self.add_trigger_rule(TriggerRule(
            name="high_connection_count",
            condition=TriggerCondition(
                trigger_type=TriggerType.CONNECTION_LIMIT,
                threshold_value=800,  # 80% of default 1000 limit
                comparison_operator="gt",
                check_interval_seconds=60.0,
                cooldown_seconds=180.0
            ),
            actions=[
                CleanupAction(TriggerAction.CLOSE_IDLE_CONNECTIONS, priority=1),
                CleanupAction(TriggerAction.THROTTLE_NEW_REQUESTS, priority=2,
                             parameters={'throttle_percentage': 25})
            ]
        ))
        
        # Thread limit rules
        self.add_trigger_rule(TriggerRule(
            name="high_thread_count",
            condition=TriggerCondition(
                trigger_type=TriggerType.THREAD_LIMIT,
                threshold_value=80,  # 80% of default 100 limit
                comparison_operator="gt",
                check_interval_seconds=45.0,
                cooldown_seconds=300.0
            ),
            actions=[
                CleanupAction(TriggerAction.REDUCE_THREAD_POOLS, priority=1),
                CleanupAction(TriggerAction.CLEANUP_STALE_SESSIONS, priority=2)
            ]
        ))
        
        # Leak detection rules
        self.add_trigger_rule(TriggerRule(
            name="critical_leak_detected",
            condition=TriggerCondition(
                trigger_type=TriggerType.LEAK_DETECTION,
                threshold_value=1,  # Any critical leak
                comparison_operator="gte",
                check_interval_seconds=0,  # Immediate
                cooldown_seconds=30.0
            ),
            actions=[
                CleanupAction(TriggerAction.NOTIFY_OPERATORS, priority=1,
                             parameters={'severity': 'high', 'message': 'Critical resource leak detected'}),
                CleanupAction(TriggerAction.FORCE_GARBAGE_COLLECTION, priority=2),
                CleanupAction(TriggerAction.CLEANUP_STALE_SESSIONS, priority=3)
            ]
        ))
        
        # Periodic maintenance
        self.add_trigger_rule(TriggerRule(
            name="periodic_maintenance",
            condition=TriggerCondition(
                trigger_type=TriggerType.PERIODIC_MAINTENANCE,
                threshold_value=0,  # Always trigger
                comparison_operator="gte",
                check_interval_seconds=1800.0,  # Every 30 minutes
                cooldown_seconds=1800.0
            ),
            actions=[
                CleanupAction(TriggerAction.FORCE_GARBAGE_COLLECTION, priority=1),
                CleanupAction(TriggerAction.CLEANUP_STALE_SESSIONS, priority=2),
                CleanupAction(TriggerAction.CLOSE_IDLE_CONNECTIONS, priority=3)
            ]
        ))
    
    def add_trigger_rule(self, rule: TriggerRule):
        """Add a trigger rule"""
        with self.trigger_lock:
            self.trigger_rules[rule.name] = rule
            self.trigger_stats['triggers_by_rule'][rule.name] = 0
        
        self.logger.debug(f"Added trigger rule: {rule.name}")
    
    def remove_trigger_rule(self, rule_name: str):
        """Remove a trigger rule"""
        with self.trigger_lock:
            if rule_name in self.trigger_rules:
                del self.trigger_rules[rule_name]
                self.logger.debug(f"Removed trigger rule: {rule_name}")
    
    def _handle_leak_detection(self, leaks: List[LeakDetection]):
        """Handle leak detection notifications"""
        if not leaks:
            return
        
        # Count critical leaks
        critical_leaks = [leak for leak in leaks if leak.severity == LeakSeverity.CRITICAL]
        high_leaks = [leak for leak in leaks if leak.severity == LeakSeverity.HIGH]
        
        # Trigger appropriate rules
        if critical_leaks:
            self._check_and_trigger_rule("critical_leak_detected", len(critical_leaks))
        
        # Log leak summary
        self.logger.warning(f"Leak detection: {len(critical_leaks)} critical, {len(high_leaks)} high severity")
    
    def _start_monitoring(self):
        """Start periodic monitoring"""
        if not self.monitoring_enabled:
            return
        
        def monitoring_cycle():
            try:
                self._check_all_trigger_conditions()
            except Exception as e:
                self.logger.error(f"Monitoring cycle failed: {e}")
            finally:
                if self.monitoring_enabled:
                    self.monitoring_timer = threading.Timer(self.monitoring_interval, monitoring_cycle)
                    self.monitoring_timer.daemon = True
                    self.monitoring_timer.start()
        
        self.monitoring_timer = threading.Timer(self.monitoring_interval, monitoring_cycle)
        self.monitoring_timer.daemon = True
        self.monitoring_timer.start()
    
    def _check_all_trigger_conditions(self):
        """Check all trigger conditions"""
        current_time = datetime.now()
        
        # Get current system state
        memory_mb = self._get_current_memory_usage()
        connection_count = self._get_current_connection_count()
        thread_count = self._get_current_thread_count()
        file_handle_count = self._get_current_file_handle_count()
        
        with self.trigger_lock:
            for rule_name, rule in self.trigger_rules.items():
                if not rule.enabled or not rule.can_trigger():
                    continue
                
                # Check if it's time to check this rule
                if rule.condition.check_interval_seconds > 0:
                    if rule.last_triggered is not None:
                        time_since_last_check = (current_time - rule.last_triggered).total_seconds()
                        if time_since_last_check < rule.condition.check_interval_seconds:
                            continue
                
                # Get the value to compare
                current_value = 0
                if rule.condition.trigger_type == TriggerType.MEMORY_PRESSURE:
                    current_value = memory_mb
                elif rule.condition.trigger_type == TriggerType.CONNECTION_LIMIT:
                    current_value = connection_count
                elif rule.condition.trigger_type == TriggerType.THREAD_LIMIT:
                    current_value = thread_count
                elif rule.condition.trigger_type == TriggerType.FILE_HANDLE_LIMIT:
                    current_value = file_handle_count
                elif rule.condition.trigger_type == TriggerType.PERIODIC_MAINTENANCE:
                    current_value = 1  # Always meets condition
                
                # Check condition
                if self._evaluate_condition(current_value, rule.condition):
                    self._trigger_rule(rule, current_value)
    
    def _evaluate_condition(self, current_value: float, condition: TriggerCondition) -> bool:
        """Evaluate if a condition is met"""
        threshold = condition.threshold_value
        op = condition.comparison_operator
        
        if op == "gt":
            return current_value > threshold
        elif op == "gte":
            return current_value >= threshold
        elif op == "lt":
            return current_value < threshold
        elif op == "lte":
            return current_value <= threshold
        elif op == "eq":
            return current_value == threshold
        else:
            return False
    
    def _check_and_trigger_rule(self, rule_name: str, current_value: float):
        """Check and potentially trigger a specific rule"""
        with self.trigger_lock:
            if rule_name not in self.trigger_rules:
                return
            
            rule = self.trigger_rules[rule_name]
            if rule.enabled and rule.can_trigger():
                if self._evaluate_condition(current_value, rule.condition):
                    self._trigger_rule(rule, current_value)
    
    def _trigger_rule(self, rule: TriggerRule, trigger_value: float):
        """Trigger a rule and execute its actions"""
        try:
            current_time = datetime.now()
            rule.last_triggered = current_time
            rule.trigger_count += 1
            
            self.trigger_stats['total_triggers'] += 1
            self.trigger_stats['triggers_by_rule'][rule.name] += 1
            self.trigger_stats['triggers_by_type'][rule.condition.trigger_type.value] = \
                self.trigger_stats['triggers_by_type'].get(rule.condition.trigger_type.value, 0) + 1
            self.trigger_stats['last_trigger_time'] = current_time
            
            self.logger.warning(f"Triggering rule '{rule.name}' (value: {trigger_value}, threshold: {rule.condition.threshold_value})")
            
            # Sort actions by priority
            actions = sorted(rule.actions, key=lambda a: a.priority)
            
            # Execute actions
            for action in actions:
                if action.enabled:
                    self._execute_action(action, rule, trigger_value)
                    
        except Exception as e:
            self.logger.error(f"Failed to trigger rule '{rule.name}': {e}")
    
    def _execute_action(self, action: CleanupAction, rule: TriggerRule, trigger_value: float):
        """Execute a cleanup action"""
        try:
            action_name = action.action_type.value
            self.trigger_stats['actions_executed'][action_name] = \
                self.trigger_stats['actions_executed'].get(action_name, 0) + 1
            
            # Get action handler
            handler = self.action_handlers.get(action.action_type)
            if not handler:
                self.logger.error(f"No handler for action: {action_name}")
                return
            
            self.logger.info(f"Executing action '{action_name}' for rule '{rule.name}'")
            
            # Execute with timeout
            def execute_with_timeout():
                try:
                    handler(action.parameters, rule, trigger_value)
                except Exception as e:
                    self.logger.error(f"Action '{action_name}' failed: {e}")
                    self.trigger_stats['failed_actions'] += 1
            
            action_thread = threading.Thread(target=execute_with_timeout, daemon=True)
            action_thread.start()
            action_thread.join(timeout=action.timeout_seconds)
            
            if action_thread.is_alive():
                self.logger.error(f"Action '{action_name}' timed out after {action.timeout_seconds}s")
                self.trigger_stats['failed_actions'] += 1
                
        except Exception as e:
            self.logger.error(f"Failed to execute action '{action.action_type.value}': {e}")
            self.trigger_stats['failed_actions'] += 1
    
    # Action handlers
    def _force_garbage_collection(self, params: Dict, rule: TriggerRule, trigger_value: float):
        """Force garbage collection"""
        before_objects = len(gc.get_objects())
        collected = gc.collect()
        after_objects = len(gc.get_objects())
        
        self.logger.info(f"Garbage collection: {collected} objects collected, {before_objects} -> {after_objects}")
    
    def _close_idle_connections(self, params: Dict, rule: TriggerRule, trigger_value: float):
        """Close idle connections"""
        # This would interface with connection managers
        max_close = params.get('max_close_count', 100)
        self.logger.info(f"Closing up to {max_close} idle connections")
        
        # Interface with connection detector to close stale connections
        connection_summary = self.leak_detector.connection_detector.get_connection_summary()
        self.logger.info(f"Current connections: {connection_summary.get('total_connections', 0)}")
    
    def _cleanup_stale_sessions(self, params: Dict, rule: TriggerRule, trigger_value: float):
        """Cleanup stale sessions"""
        self.logger.info("Cleaning up stale validation sessions")
        
        # Get cleanup status before
        before_status = self.cleanup_manager.get_cleanup_status()
        before_sessions = before_status['sessions']['active']
        
        # Trigger cleanup
        self.cleanup_manager._periodic_cleanup()
        
        # Get status after
        after_status = self.cleanup_manager.get_cleanup_status()
        after_sessions = after_status['sessions']['active']
        
        cleaned_sessions = before_sessions - after_sessions
        self.logger.info(f"Cleaned up {cleaned_sessions} stale sessions")
    
    def _reduce_thread_pools(self, params: Dict, rule: TriggerRule, trigger_value: float):
        """Reduce thread pool sizes"""
        reduction_percentage = params.get('reduction_percentage', 20)
        self.logger.info(f"Reducing thread pools by {reduction_percentage}%")
        
        # This would interface with thread pool managers
        # For now, just log the action
        thread_summary = self.leak_detector.thread_detector.get_thread_summary()
        current_count = thread_summary.get('current_count', 0)
        target_reduction = int(current_count * reduction_percentage / 100)
        
        self.logger.info(f"Target thread reduction: {target_reduction} threads")
    
    def _clear_caches(self, params: Dict, rule: TriggerRule, trigger_value: float):
        """Clear caches"""
        clear_percentage = params.get('max_clear_percentage', 50)
        self.logger.info(f"Clearing up to {clear_percentage}% of caches")
        
        # This would interface with cache managers
        # For now, just trigger garbage collection as a substitute
        self._force_garbage_collection({}, rule, trigger_value)
    
    def _emergency_shutdown(self, params: Dict, rule: TriggerRule, trigger_value: float):
        """Trigger emergency shutdown procedures"""
        self.logger.critical("EMERGENCY SHUTDOWN TRIGGERED")
        
        # Perform emergency cleanup
        self.cleanup_manager.perform_emergency_cleanup()
        
        # Force garbage collection
        gc.collect()
        
        # This would normally initiate graceful shutdown
        self.logger.critical("Emergency cleanup completed - consider system restart")
    
    def _notify_operators(self, params: Dict, rule: TriggerRule, trigger_value: float):
        """Notify operators of issues"""
        severity = params.get('severity', 'medium')
        message = params.get('message', f'Trigger rule {rule.name} activated')
        
        # This would send notifications via email, Slack, etc.
        self.logger.warning(f"OPERATOR NOTIFICATION [{severity.upper()}]: {message} (trigger_value: {trigger_value})")
    
    def _throttle_new_requests(self, params: Dict, rule: TriggerRule, trigger_value: float):
        """Throttle new requests"""
        throttle_percentage = params.get('throttle_percentage', 50)
        duration_seconds = params.get('duration_seconds', 300)
        
        self.logger.warning(f"Throttling new requests by {throttle_percentage}% for {duration_seconds}s")
        
        # This would interface with request handling systems
        # For now, just log the action
    
    # Helper methods for getting current system state
    def _get_current_memory_usage(self) -> float:
        """Get current memory usage in MB"""
        memory_summary = self.leak_detector.memory_detector.get_memory_summary()
        return memory_summary.get('current_mb', 0.0)
    
    def _get_current_connection_count(self) -> int:
        """Get current connection count"""
        connection_summary = self.leak_detector.connection_detector.get_connection_summary()
        return connection_summary.get('total_connections', 0)
    
    def _get_current_thread_count(self) -> int:
        """Get current thread count"""
        thread_summary = self.leak_detector.thread_detector.get_thread_summary()
        return thread_summary.get('current_count', 0)
    
    def _get_current_file_handle_count(self) -> int:
        """Get current file handle count"""
        file_handle_summary = self.leak_detector.file_handle_detector.get_file_handle_summary()
        return file_handle_summary.get('current_count', 0)
    
    def get_trigger_status(self) -> Dict[str, Any]:
        """Get comprehensive trigger status"""
        with self.trigger_lock:
            rule_status = {}
            for name, rule in self.trigger_rules.items():
                rule_status[name] = {
                    'enabled': rule.enabled,
                    'trigger_count': rule.trigger_count,
                    'last_triggered': rule.last_triggered.isoformat() if rule.last_triggered else None,
                    'can_trigger': rule.can_trigger(),
                    'condition_type': rule.condition.trigger_type.value,
                    'threshold': rule.condition.threshold_value,
                    'cooldown_seconds': rule.condition.cooldown_seconds
                }
        
        return {
            'monitoring_enabled': self.monitoring_enabled,
            'monitoring_interval': self.monitoring_interval,
            'statistics': self.trigger_stats.copy(),
            'rules': rule_status,
            'current_system_state': {
                'memory_mb': self._get_current_memory_usage(),
                'connections': self._get_current_connection_count(),
                'threads': self._get_current_thread_count(),
                'file_handles': self._get_current_file_handle_count()
            }
        }
    
    def shutdown(self):
        """Shutdown automated cleanup triggers"""
        self.logger.info("Shutting down AutomatedCleanupTrigger")
        
        self.monitoring_enabled = False
        if self.monitoring_timer:
            self.monitoring_timer.cancel()
        
        self.logger.info("AutomatedCleanupTrigger shutdown complete")


# Global instance
_global_cleanup_trigger: Optional[AutomatedCleanupTrigger] = None


def get_global_cleanup_trigger() -> AutomatedCleanupTrigger:
    """Get or create global cleanup trigger"""
    global _global_cleanup_trigger
    if _global_cleanup_trigger is None:
        _global_cleanup_trigger = AutomatedCleanupTrigger()
    return _global_cleanup_trigger


if __name__ == "__main__":
    # Example usage
    trigger_system = AutomatedCleanupTrigger()
    
    # Monitor for a while
    print("Monitoring for 30 seconds...")
    time.sleep(30)
    
    # Get status
    status = trigger_system.get_trigger_status()
    print(f"Trigger status: {status}")
    
    trigger_system.shutdown()