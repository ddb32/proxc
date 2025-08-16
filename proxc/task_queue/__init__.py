"""
ProxC Task Queue System
==============================

Advanced task management system with Redis backend for distributed processing.
Provides task prioritization, retry logic, and comprehensive monitoring.

Features:
- Redis-based distributed task queue
- Task prioritization (HIGH, MEDIUM, LOW)
- Exponential backoff retry logic
- Task result caching and status tracking
- Queue health monitoring and metrics
- Integration with proxy collection workflows

Author: Proxy Hunter Development Team
Version: 3.1.0-TASKQUEUE
License: MIT
"""

import logging
from typing import Optional, Dict, Any, List
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

class TaskPriority(Enum):
    """Task priority levels for queue management"""
    HIGH = 1
    MEDIUM = 2
    LOW = 3

class TaskStatus(Enum):
    """Task status tracking"""
    PENDING = "pending"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"

class TaskType(Enum):
    """Types of tasks in the queue system"""
    PROXY_DISCOVERY = "proxy_discovery"
    PROXY_VALIDATION = "proxy_validation"
    PROXY_ANALYSIS = "proxy_analysis"
    SOURCE_HEALTH_CHECK = "source_health_check"
    IP_ROTATION = "ip_rotation"
    SECURITY_SCAN = "security_scan"
    MAINTENANCE = "maintenance"

# Default configuration
DEFAULT_REDIS_CONFIG = {
    'host': 'localhost',
    'port': 6379,
    'db': 0,
    'decode_responses': True,
    'socket_timeout': 30,
    'socket_connect_timeout': 30,
    'retry_on_timeout': True,
    'health_check_interval': 30
}

DEFAULT_QUEUE_CONFIG = {
    'max_retry_attempts': 3,
    'retry_backoff_multiplier': 2.0,
    'default_timeout': 300,  # 5 minutes
    'result_ttl': 3600,      # 1 hour
    'failed_job_ttl': 86400, # 24 hours
    'queue_prefix': 'proxc',
    'enable_monitoring': True
}

# Version and compatibility info
__version__ = "3.1.0-TASKQUEUE"
__author__ = "ProxC Development Team"
__license__ = "MIT"

# Export main classes and functions
from .task_manager import TaskManager
from .redis_backend import RedisBackend
from .retry_handler import RetryHandler
from .result_cache import ResultCache
from .queue_monitor import QueueMonitor

__all__ = [
    'TaskManager',
    'RedisBackend', 
    'RetryHandler',
    'ResultCache',
    'QueueMonitor',
    'TaskPriority',
    'TaskStatus', 
    'TaskType',
    'DEFAULT_REDIS_CONFIG',
    'DEFAULT_QUEUE_CONFIG'
]

# Logging setup
logger.info("Task queue system initialized successfully")