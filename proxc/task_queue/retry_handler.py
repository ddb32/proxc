"""
Retry Handler for Proxy Hunter Task Queue
==========================================

Implements intelligent retry logic with exponential backoff, failure analysis,
and adaptive retry strategies for different types of failures.
"""

import logging
import time
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from .redis_backend import Task, TaskStatus

logger = logging.getLogger(__name__)

class FailureType(Enum):
    """Categories of task failures for retry strategy"""
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    RATE_LIMIT = "rate_limit"
    AUTHENTICATION = "authentication"
    RESOURCE_UNAVAILABLE = "resource_unavailable"
    VALIDATION_ERROR = "validation_error"
    UNKNOWN = "unknown"

@dataclass
class RetryPolicy:
    """Retry policy configuration for different failure types"""
    max_attempts: int
    base_delay: float  # Base delay in seconds
    max_delay: float   # Maximum delay in seconds
    backoff_multiplier: float
    jitter: bool = True  # Add random jitter to delays

# Default retry policies for different failure types
DEFAULT_RETRY_POLICIES = {
    FailureType.TIMEOUT: RetryPolicy(
        max_attempts=3,
        base_delay=5.0,
        max_delay=120.0,
        backoff_multiplier=2.0
    ),
    FailureType.CONNECTION_ERROR: RetryPolicy(
        max_attempts=5,
        base_delay=2.0,
        max_delay=60.0,
        backoff_multiplier=2.0
    ),
    FailureType.RATE_LIMIT: RetryPolicy(
        max_attempts=8,
        base_delay=30.0,
        max_delay=600.0,
        backoff_multiplier=1.5
    ),
    FailureType.AUTHENTICATION: RetryPolicy(
        max_attempts=2,
        base_delay=1.0,
        max_delay=5.0,
        backoff_multiplier=1.0
    ),
    FailureType.RESOURCE_UNAVAILABLE: RetryPolicy(
        max_attempts=4,
        base_delay=10.0,
        max_delay=300.0,
        backoff_multiplier=2.0
    ),
    FailureType.VALIDATION_ERROR: RetryPolicy(
        max_attempts=1,  # Usually not worth retrying
        base_delay=1.0,
        max_delay=1.0,
        backoff_multiplier=1.0
    ),
    FailureType.UNKNOWN: RetryPolicy(
        max_attempts=3,
        base_delay=5.0,
        max_delay=60.0,
        backoff_multiplier=2.0
    )
}

class RetryHandler:
    """Intelligent retry handler with adaptive strategies"""
    
    def __init__(self, retry_policies: Optional[Dict[FailureType, RetryPolicy]] = None):
        """Initialize retry handler with policies"""
        self.retry_policies = retry_policies or DEFAULT_RETRY_POLICIES
        
        # Failure analysis patterns
        self.failure_patterns = {
            FailureType.TIMEOUT: [
                'timeout', 'timed out', 'connection timeout', 'read timeout',
                'request timeout', 'operation timeout'
            ],
            FailureType.CONNECTION_ERROR: [
                'connection error', 'connection refused', 'connection reset',
                'network unreachable', 'host unreachable', 'dns resolution',
                'connection failed', 'connection closed'
            ],
            FailureType.RATE_LIMIT: [
                'rate limit', 'too many requests', '429', 'quota exceeded',
                'throttled', 'rate exceeded', 'request limit'
            ],
            FailureType.AUTHENTICATION: [
                'authentication', 'unauthorized', '401', '403', 'access denied',
                'invalid credentials', 'forbidden', 'authentication failed'
            ],
            FailureType.RESOURCE_UNAVAILABLE: [
                '500', '502', '503', '504', 'internal server error',
                'bad gateway', 'service unavailable', 'gateway timeout',
                'server error', 'resource unavailable'
            ],
            FailureType.VALIDATION_ERROR: [
                'validation error', 'invalid input', 'malformed',
                'bad request', '400', 'invalid parameter', 'parse error'
            ]
        }
        
        logger.info("Retry handler initialized with adaptive policies")
    
    def classify_failure(self, error_message: str) -> FailureType:
        """Classify failure type based on error message
        
        Args:
            error_message: Error message from failed task
            
        Returns:
            FailureType: Classified failure type
        """
        if not error_message:
            return FailureType.UNKNOWN
        
        error_lower = error_message.lower()
        
        # Check patterns for each failure type
        for failure_type, patterns in self.failure_patterns.items():
            if any(pattern in error_lower for pattern in patterns):
                logger.debug(f"Classified failure as {failure_type.value}: {error_message}")
                return failure_type
        
        logger.debug(f"Classified failure as unknown: {error_message}")
        return FailureType.UNKNOWN
    
    def should_retry(self, task: Task, error_message: str = None) -> bool:
        """Determine if task should be retried
        
        Args:
            task: Failed task
            error_message: Optional error message for classification
            
        Returns:
            bool: True if task should be retried
        """
        # Use task's error message if not provided
        if error_message is None:
            error_message = task.error_message or ""
        
        # Check if we've exceeded retry limit
        if task.retry_count >= task.max_retries:
            logger.debug(f"Task {task.task_id} exceeded max retries ({task.max_retries})")
            return False
        
        # Classify failure and check policy
        failure_type = self.classify_failure(error_message)
        policy = self.retry_policies.get(failure_type, self.retry_policies[FailureType.UNKNOWN])
        
        if task.retry_count >= policy.max_attempts:
            logger.debug(f"Task {task.task_id} exceeded policy max attempts for {failure_type.value}")
            return False
        
        logger.debug(f"Task {task.task_id} should be retried (attempt {task.retry_count + 1}/{policy.max_attempts})")
        return True
    
    def calculate_delay(self, task: Task, failure_type: FailureType) -> float:
        """Calculate retry delay with exponential backoff and jitter
        
        Args:
            task: Task being retried
            failure_type: Type of failure
            
        Returns:
            float: Delay in seconds
        """
        policy = self.retry_policies.get(failure_type, self.retry_policies[FailureType.UNKNOWN])
        
        # Calculate exponential backoff delay
        delay = policy.base_delay * (policy.backoff_multiplier ** task.retry_count)
        delay = min(delay, policy.max_delay)
        
        # Add jitter to avoid thundering herd
        if policy.jitter:
            import random
            jitter_amount = delay * 0.1  # 10% jitter
            delay += random.uniform(-jitter_amount, jitter_amount)
        
        # Ensure minimum delay
        delay = max(delay, 1.0)
        
        logger.debug(f"Calculated retry delay for {failure_type.value}: {delay:.2f}s")
        return delay
    
    def prepare_retry(self, task: Task, error_message: str = None) -> Task:
        """Prepare task for retry with updated metadata
        
        Args:
            task: Failed task to retry
            error_message: Error message from failure
            
        Returns:
            Task: Updated task ready for retry
        """
        # Classify failure
        failure_type = self.classify_failure(error_message or task.error_message or "")
        
        # Calculate delay
        retry_delay = self.calculate_delay(task, failure_type)
        
        # Update task for retry
        task.retry_count += 1
        task.status = TaskStatus.PENDING
        task.started_at = None
        task.completed_at = None
        task.worker_id = None
        task.result = None
        
        # Schedule retry
        task.scheduled_at = datetime.utcnow() + timedelta(seconds=retry_delay)
        
        # Add retry metadata to payload
        if 'retry_metadata' not in task.payload:
            task.payload['retry_metadata'] = {}
        
        task.payload['retry_metadata'].update({
            'failure_type': failure_type.value,
            'retry_delay': retry_delay,
            'previous_error': error_message or task.error_message,
            'retry_timestamp': datetime.utcnow().isoformat()
        })
        
        logger.info(f"Prepared task {task.task_id} for retry {task.retry_count} after {retry_delay:.1f}s delay")
        return task
    
    def get_retry_stats(self, tasks: List[Task]) -> Dict[str, Any]:
        """Analyze retry statistics for a list of tasks
        
        Args:
            tasks: List of tasks to analyze
            
        Returns:
            Dict[str, Any]: Retry statistics
        """
        total_tasks = len(tasks)
        if total_tasks == 0:
            return {}
        
        retry_counts = [task.retry_count for task in tasks]
        failed_tasks = [task for task in tasks if task.status == TaskStatus.FAILED]
        
        # Classify failures
        failure_classifications = {}
        for task in failed_tasks:
            failure_type = self.classify_failure(task.error_message or "")
            failure_classifications[failure_type.value] = failure_classifications.get(failure_type.value, 0) + 1
        
        return {
            'total_tasks': total_tasks,
            'tasks_with_retries': len([task for task in tasks if task.retry_count > 0]),
            'average_retry_count': sum(retry_counts) / total_tasks,
            'max_retry_count': max(retry_counts) if retry_counts else 0,
            'total_retries': sum(retry_counts),
            'failed_tasks': len(failed_tasks),
            'failure_rate': len(failed_tasks) / total_tasks,
            'failure_classifications': failure_classifications,
            'retry_success_rate': self._calculate_retry_success_rate(tasks)
        }
    
    def _calculate_retry_success_rate(self, tasks: List[Task]) -> float:
        """Calculate success rate of retried tasks"""
        retried_tasks = [task for task in tasks if task.retry_count > 0]
        if not retried_tasks:
            return 0.0
        
        successful_retries = len([
            task for task in retried_tasks 
            if task.status == TaskStatus.COMPLETED
        ])
        
        return successful_retries / len(retried_tasks)
    
    def update_retry_policy(self, failure_type: FailureType, policy: RetryPolicy):
        """Update retry policy for a specific failure type
        
        Args:
            failure_type: Type of failure
            policy: New retry policy
        """
        self.retry_policies[failure_type] = policy
        logger.info(f"Updated retry policy for {failure_type.value}")
    
    def get_recommended_policy(self, failure_analysis: Dict[str, Any]) -> Dict[FailureType, RetryPolicy]:
        """Get recommended retry policies based on failure analysis
        
        Args:
            failure_analysis: Analysis of historical failures
            
        Returns:
            Dict[FailureType, RetryPolicy]: Recommended policies
        """
        recommended_policies = {}
        
        for failure_type in FailureType:
            current_policy = self.retry_policies.get(failure_type, self.retry_policies[FailureType.UNKNOWN])
            
            # Analyze failure patterns and adjust policy
            failure_count = failure_analysis.get('failure_classifications', {}).get(failure_type.value, 0)
            
            if failure_count > 0:
                # Adjust based on failure frequency
                if failure_count > 10:  # High frequency failures
                    # Increase delays and reduce attempts for problematic failure types
                    recommended_policies[failure_type] = RetryPolicy(
                        max_attempts=max(1, current_policy.max_attempts - 1),
                        base_delay=current_policy.base_delay * 1.5,
                        max_delay=current_policy.max_delay * 1.2,
                        backoff_multiplier=current_policy.backoff_multiplier
                    )
                else:
                    # Keep current policy for moderate failures
                    recommended_policies[failure_type] = current_policy
            else:
                # No failures of this type, can be more aggressive
                recommended_policies[failure_type] = current_policy
        
        return recommended_policies