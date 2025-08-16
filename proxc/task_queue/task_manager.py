"""
Task Manager for Proxy Hunter Task Queue System
===============================================

High-level task management interface that orchestrates task execution,
retry handling, and result processing with comprehensive monitoring.
"""

import asyncio
import logging
import time
import uuid
from typing import Optional, Dict, Any, List, Callable, Awaitable, Union
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .redis_backend import RedisBackend, Task, TaskPriority, TaskStatus, TaskType
from .retry_handler import RetryHandler
from .result_cache import ResultCache
from .queue_monitor import QueueMonitor

logger = logging.getLogger(__name__)

@dataclass
class TaskResult:
    """Result of task execution"""
    task_id: str
    success: bool
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    execution_time: float = 0.0
    retry_count: int = 0

class TaskManager:
    """High-level task management and orchestration"""
    
    def __init__(self, redis_config: Optional[Dict[str, Any]] = None):
        """Initialize task manager with Redis backend"""
        self.redis_backend = RedisBackend(redis_config)
        self.retry_handler = RetryHandler()
        self.result_cache = ResultCache(self.redis_backend)
        self.queue_monitor = QueueMonitor(self.redis_backend)
        
        # Task execution tracking
        self.active_tasks: Dict[str, Task] = {}
        self.task_handlers: Dict[TaskType, Callable] = {}
        self.running = False
        self.worker_id = f"worker-{uuid.uuid4().hex[:8]}"
        
        # Performance metrics
        self.start_time = datetime.utcnow()
        self.tasks_processed = 0
        self.tasks_succeeded = 0
        self.tasks_failed = 0
        
        logger.info(f"Task manager initialized with worker ID: {self.worker_id}")
    
    def connect(self) -> bool:
        """Connect to Redis backend and initialize components"""
        if not self.redis_backend.connect():
            logger.error("Failed to connect to Redis backend")
            return False
        
        # Initialize other components
        self.queue_monitor.start_monitoring()
        logger.info("Task manager connected successfully")
        return True
    
    def disconnect(self):
        """Disconnect from Redis backend and cleanup resources"""
        self.running = False
        self.queue_monitor.stop_monitoring()
        self.redis_backend.disconnect()
        logger.info("Task manager disconnected")
    
    def register_task_handler(self, task_type: TaskType, handler: Callable) -> None:
        """Register a handler function for a specific task type
        
        Args:
            task_type: Type of task to handle
            handler: Function that takes (task_payload) and returns result dict
        """
        self.task_handlers[task_type] = handler
        logger.info(f"Registered handler for task type: {task_type.value}")
    
    def submit_task(self, 
                   task_type: TaskType, 
                   payload: Dict[str, Any],
                   priority: TaskPriority = TaskPriority.MEDIUM,
                   max_retries: int = 3,
                   timeout: int = 300,
                   queue_name: str = "default",
                   scheduled_at: Optional[datetime] = None) -> str:
        """Submit a task to the queue
        
        Args:
            task_type: Type of task
            payload: Task payload data
            priority: Task priority level
            max_retries: Maximum retry attempts
            timeout: Task timeout in seconds
            queue_name: Target queue name
            scheduled_at: Optional scheduled execution time
            
        Returns:
            str: Task ID
        """
        task_id = f"{task_type.value}-{uuid.uuid4().hex}"
        
        task = Task(
            task_id=task_id,
            task_type=task_type,
            priority=priority,
            payload=payload,
            max_retries=max_retries,
            timeout=timeout,
            queue_name=queue_name,
            scheduled_at=scheduled_at
        )
        
        if self.redis_backend.enqueue_task(task, queue_name):
            logger.info(f"Task {task_id} submitted successfully")
            return task_id
        else:
            logger.error(f"Failed to submit task {task_id}")
            return ""
    
    def submit_bulk_tasks(self,
                         tasks: List[Dict[str, Any]],
                         queue_name: str = "default") -> List[str]:
        """Submit multiple tasks efficiently
        
        Args:
            tasks: List of task dictionaries with 'task_type', 'payload', etc.
            queue_name: Target queue name
            
        Returns:
            List[str]: List of task IDs
        """
        task_ids = []
        
        for task_data in tasks:
            task_id = self.submit_task(
                task_type=task_data.get('task_type', TaskType.PROXY_DISCOVERY),
                payload=task_data.get('payload', {}),
                priority=task_data.get('priority', TaskPriority.MEDIUM),
                max_retries=task_data.get('max_retries', 3),
                timeout=task_data.get('timeout', 300),
                queue_name=queue_name,
                scheduled_at=task_data.get('scheduled_at')
            )
            
            if task_id:
                task_ids.append(task_id)
        
        logger.info(f"Submitted {len(task_ids)} tasks to queue {queue_name}")
        return task_ids
    
    def execute_task(self, task: Task) -> TaskResult:
        """Execute a single task with error handling and timing
        
        Args:
            task: Task to execute
            
        Returns:
            TaskResult: Execution result
        """
        start_time = time.time()
        
        try:
            # Check if handler is registered
            if task.task_type not in self.task_handlers:
                error_msg = f"No handler registered for task type: {task.task_type.value}"
                logger.error(error_msg)
                return TaskResult(
                    task_id=task.task_id,
                    success=False,
                    error_message=error_msg,
                    execution_time=time.time() - start_time
                )
            
            # Get handler and execute
            handler = self.task_handlers[task.task_type]
            task.worker_id = self.worker_id
            
            logger.debug(f"Executing task {task.task_id} of type {task.task_type.value}")
            
            # Execute handler
            result = handler(task.payload)
            
            execution_time = time.time() - start_time
            
            # Check for timeout
            if execution_time > task.timeout:
                error_msg = f"Task {task.task_id} exceeded timeout ({task.timeout}s)"
                logger.warning(error_msg)
                return TaskResult(
                    task_id=task.task_id,
                    success=False,
                    error_message=error_msg,
                    execution_time=execution_time
                )
            
            # Success
            logger.debug(f"Task {task.task_id} completed in {execution_time:.2f}s")
            return TaskResult(
                task_id=task.task_id,
                success=True,
                result=result,
                execution_time=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Task {task.task_id} failed with error: {str(e)}"
            logger.error(error_msg)
            
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error_message=error_msg,
                execution_time=execution_time
            )
    
    def process_single_task(self, queue_name: str = "default") -> Optional[TaskResult]:
        """Process one task from the queue
        
        Args:
            queue_name: Queue to process from
            
        Returns:
            Optional[TaskResult]: Result if task was processed
        """
        # Dequeue task
        task = self.redis_backend.dequeue_task(queue_name)
        if not task:
            return None
        
        # Add to active tasks
        self.active_tasks[task.task_id] = task
        
        try:
            # Execute task
            result = self.execute_task(task)
            
            # Handle result
            if result.success:
                self.redis_backend.complete_task(task, result.result)
                self.result_cache.cache_result(task.task_id, result.result)
                self.tasks_succeeded += 1
                logger.info(f"Task {task.task_id} completed successfully")
                
            else:
                # Handle failure with retry logic
                should_retry = self.retry_handler.should_retry(task)
                
                if should_retry:
                    retried_task = self.retry_handler.prepare_retry(task, result.error_message)
                    self.redis_backend.enqueue_task(retried_task, queue_name)
                    logger.info(f"Task {task.task_id} scheduled for retry ({retried_task.retry_count}/{task.max_retries})")
                else:
                    self.redis_backend.fail_task(task, result.error_message)
                    self.tasks_failed += 1
                    logger.warning(f"Task {task.task_id} failed permanently: {result.error_message}")
            
            self.tasks_processed += 1
            return result
            
        finally:
            # Remove from active tasks
            self.active_tasks.pop(task.task_id, None)
    
    def start_worker(self, 
                    queue_name: str = "default", 
                    max_concurrent: int = 5,
                    poll_interval: float = 1.0) -> None:
        """Start worker process to continuously process tasks
        
        Args:
            queue_name: Queue to process
            max_concurrent: Maximum concurrent tasks
            poll_interval: Polling interval in seconds
        """
        if self.running:
            logger.warning("Worker already running")
            return
        
        self.running = True
        logger.info(f"Starting worker for queue {queue_name} (max_concurrent={max_concurrent})")
        
        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            while self.running:
                try:
                    # Process tasks up to max_concurrent limit
                    active_futures = []
                    
                    while len(active_futures) < max_concurrent and self.running:
                        # Submit task processing to thread pool
                        future = executor.submit(self.process_single_task, queue_name)
                        active_futures.append(future)
                    
                    # Wait for at least one task to complete
                    if active_futures:
                        completed_futures = []
                        for future in as_completed(active_futures, timeout=poll_interval):
                            result = future.result()
                            completed_futures.append(future)
                            
                            if result is None:
                                # No tasks available, wait before polling again
                                time.sleep(poll_interval)
                                break
                        
                        # Remove completed futures
                        for future in completed_futures:
                            active_futures.remove(future)
                    else:
                        time.sleep(poll_interval)
                    
                except KeyboardInterrupt:
                    logger.info("Worker interrupted by user")
                    break
                except Exception as e:
                    logger.error(f"Worker error: {e}")
                    time.sleep(poll_interval * 2)  # Back off on error
        
        self.running = False
        logger.info("Worker stopped")
    
    def stop_worker(self):
        """Stop the worker process"""
        self.running = False
        logger.info("Worker stop requested")
    
    def get_worker_stats(self) -> Dict[str, Any]:
        """Get worker performance statistics"""
        uptime = (datetime.utcnow() - self.start_time).total_seconds()
        
        return {
            'worker_id': self.worker_id,
            'uptime_seconds': uptime,
            'tasks_processed': self.tasks_processed,
            'tasks_succeeded': self.tasks_succeeded,
            'tasks_failed': self.tasks_failed,
            'success_rate': self.tasks_succeeded / max(1, self.tasks_processed),
            'average_tasks_per_minute': (self.tasks_processed / max(1, uptime)) * 60,
            'active_tasks': len(self.active_tasks),
            'registered_handlers': list(self.task_handlers.keys())
        }
    
    def get_queue_stats(self, queue_name: str = "default") -> Dict[str, Any]:
        """Get comprehensive queue statistics"""
        return self.redis_backend.get_queue_stats(queue_name)
    
    def clear_queue(self, queue_name: str = "default") -> bool:
        """Clear all tasks from queue"""
        return self.redis_backend.clear_queue(queue_name)
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of specific task"""
        task = self.redis_backend.get_task(task_id)
        if task:
            return {
                'task_id': task.task_id,
                'task_type': task.task_type.value,
                'status': task.status.value,
                'priority': task.priority.value,
                'created_at': task.created_at.isoformat(),
                'started_at': task.started_at.isoformat() if task.started_at else None,
                'completed_at': task.completed_at.isoformat() if task.completed_at else None,
                'retry_count': task.retry_count,
                'max_retries': task.max_retries,
                'worker_id': task.worker_id,
                'error_message': task.error_message
            }
        return None