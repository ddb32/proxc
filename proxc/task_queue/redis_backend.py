"""
Redis Backend for Proxy Hunter Task Queue
==========================================

Provides Redis-based distributed task queue backend with connection management,
health monitoring, and fault tolerance.
"""

import asyncio
import json
import logging
import time
from typing import Optional, Dict, Any, List, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict

try:
    import redis
    from redis.exceptions import ConnectionError, TimeoutError, RedisError
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis = None

from . import TaskPriority, TaskStatus, TaskType, DEFAULT_REDIS_CONFIG

logger = logging.getLogger(__name__)

@dataclass
class Task:
    """Task data structure for queue system"""
    task_id: str
    task_type: TaskType
    priority: TaskPriority
    payload: Dict[str, Any]
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Status tracking
    status: TaskStatus = TaskStatus.PENDING
    retry_count: int = 0
    max_retries: int = 3
    timeout: int = 300  # 5 minutes default
    
    # Results and errors
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    
    # Processing metadata
    worker_id: Optional[str] = None
    queue_name: str = "default"

    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary for JSON serialization"""
        data = asdict(self)
        # Convert datetime objects to ISO format
        for key in ['created_at', 'scheduled_at', 'started_at', 'completed_at']:
            if data[key]:
                data[key] = data[key].isoformat()
        
        # Convert enums to values
        data['task_type'] = self.task_type.value if self.task_type else None
        data['priority'] = self.priority.value if self.priority else None
        data['status'] = self.status.value if self.status else None
        
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Task':
        """Create task from dictionary"""
        # Convert ISO format strings back to datetime
        for key in ['created_at', 'scheduled_at', 'started_at', 'completed_at']:
            if data.get(key):
                data[key] = datetime.fromisoformat(data[key])
        
        # Convert enum values back to enums
        if data.get('task_type'):
            data['task_type'] = TaskType(data['task_type'])
        if data.get('priority'):
            data['priority'] = TaskPriority(data['priority'])  
        if data.get('status'):
            data['status'] = TaskStatus(data['status'])
            
        return cls(**data)


class RedisBackend:
    """Redis backend for distributed task queue"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Redis backend with configuration"""
        if not HAS_REDIS:
            raise ImportError("Redis library not available. Install with: pip install redis")
        
        self.config = {**DEFAULT_REDIS_CONFIG, **(config or {})}
        self.redis_client: Optional[redis.Redis] = None
        self.connected = False
        self.connection_retries = 0
        self.max_connection_retries = 5
        
        logger.info("Redis backend initialized with config")
    
    def connect(self) -> bool:
        """Establish Redis connection with retry logic"""
        try:
            self.redis_client = redis.Redis(
                host=self.config['host'],
                port=self.config['port'],
                db=self.config['db'],
                decode_responses=self.config['decode_responses'],
                socket_timeout=self.config['socket_timeout'],
                socket_connect_timeout=self.config['socket_connect_timeout'],
                retry_on_timeout=self.config['retry_on_timeout'],
                health_check_interval=self.config['health_check_interval']
            )
            
            # Test connection
            self.redis_client.ping()
            self.connected = True
            self.connection_retries = 0
            
            logger.info(f"Connected to Redis at {self.config['host']}:{self.config['port']}")
            return True
            
        except (ConnectionError, TimeoutError) as e:
            self.connection_retries += 1
            logger.error(f"Redis connection failed (attempt {self.connection_retries}): {e}")
            
            if self.connection_retries < self.max_connection_retries:
                retry_delay = 2 ** self.connection_retries  # Exponential backoff
                logger.info(f"Retrying Redis connection in {retry_delay} seconds...")
                time.sleep(retry_delay)
                return self.connect()
            else:
                logger.error(f"Max Redis connection retries ({self.max_connection_retries}) exceeded")
                return False
                
        except Exception as e:
            logger.error(f"Unexpected Redis connection error: {e}")
            return False
    
    def disconnect(self):
        """Close Redis connection"""
        if self.redis_client:
            try:
                self.redis_client.close()
                logger.info("Redis connection closed")
            except Exception as e:
                logger.error(f"Error closing Redis connection: {e}")
        
        self.connected = False
        self.redis_client = None
    
    def is_healthy(self) -> bool:
        """Check Redis connection health"""
        if not self.connected or not self.redis_client:
            return False
        
        try:
            self.redis_client.ping()
            return True
        except (ConnectionError, TimeoutError, RedisError):
            logger.warning("Redis health check failed")
            self.connected = False
            return False
    
    def enqueue_task(self, task: Task, queue_name: str = "default") -> bool:
        """Add task to priority queue"""
        if not self.is_healthy():
            logger.error("Cannot enqueue task - Redis not healthy")
            return False
        
        try:
            task.queue_name = queue_name
            
            # Create queue key with priority
            priority_queue_key = f"proxc:queue:{queue_name}:{task.priority.value}"
            
            # Serialize task
            task_data = json.dumps(task.to_dict())
            
            # Add to priority queue (lower priority value = higher priority)
            score = task.priority.value * 1000000 + int(time.time())  # Priority + timestamp for ordering
            
            success = self.redis_client.zadd(priority_queue_key, {task.task_id: score})
            
            if success:
                # Store full task data
                task_key = f"proxc:task:{task.task_id}"
                self.redis_client.setex(task_key, 86400, task_data)  # 24-hour TTL
                
                # Update queue statistics
                stats_key = f"proxc:stats:{queue_name}"
                self.redis_client.hincrby(stats_key, "total_enqueued", 1)
                self.redis_client.hincrby(stats_key, f"priority_{task.priority.value}_enqueued", 1)
                
                logger.debug(f"Task {task.task_id} enqueued to {queue_name} with priority {task.priority.value}")
                return True
            else:
                logger.error(f"Failed to enqueue task {task.task_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error enqueuing task {task.task_id}: {e}")
            return False
    
    def dequeue_task(self, queue_name: str = "default", timeout: int = 10) -> Optional[Task]:
        """Get highest priority task from queue"""
        if not self.is_healthy():
            return None
        
        try:
            # Check each priority level (HIGH=1, MEDIUM=2, LOW=3)
            for priority in [1, 2, 3]:
                priority_queue_key = f"proxc:queue:{queue_name}:{priority}"
                
                # Get highest priority task (lowest score)
                result = self.redis_client.zpopmin(priority_queue_key)
                
                if result:
                    task_id, score = result[0]
                    
                    # Get full task data
                    task_key = f"proxc:task:{task_id}"
                    task_data = self.redis_client.get(task_key)
                    
                    if task_data:
                        task = Task.from_dict(json.loads(task_data))
                        task.status = TaskStatus.RUNNING
                        task.started_at = datetime.utcnow()
                        
                        # Update task status in Redis
                        self.redis_client.setex(task_key, 86400, json.dumps(task.to_dict()))
                        
                        # Update statistics
                        stats_key = f"proxc:stats:{queue_name}"
                        self.redis_client.hincrby(stats_key, "total_dequeued", 1)
                        
                        logger.debug(f"Task {task.task_id} dequeued from {queue_name}")
                        return task
                    else:
                        logger.warning(f"Task data not found for {task_id}")
            
            return None  # No tasks in any priority queue
            
        except Exception as e:
            logger.error(f"Error dequeuing task from {queue_name}: {e}")
            return None
    
    def complete_task(self, task: Task, result: Optional[Dict[str, Any]] = None) -> bool:
        """Mark task as completed with result"""
        if not self.is_healthy():
            return False
        
        try:
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.utcnow()
            task.result = result
            
            # Update task in Redis
            task_key = f"proxc:task:{task.task_id}"
            task_data = json.dumps(task.to_dict())
            self.redis_client.setex(task_key, 3600, task_data)  # 1-hour TTL for completed tasks
            
            # Update statistics
            stats_key = f"proxc:stats:{task.queue_name}"
            self.redis_client.hincrby(stats_key, "total_completed", 1)
            
            logger.debug(f"Task {task.task_id} completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error completing task {task.task_id}: {e}")
            return False
    
    def fail_task(self, task: Task, error_message: str) -> bool:
        """Mark task as failed with error message"""
        if not self.is_healthy():
            return False
        
        try:
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.utcnow()
            task.error_message = error_message
            
            # Update task in Redis
            task_key = f"proxc:task:{task.task_id}"
            task_data = json.dumps(task.to_dict())
            self.redis_client.setex(task_key, 86400, task_data)  # 24-hour TTL for failed tasks
            
            # Add to failed tasks list
            failed_key = f"proxc:failed:{task.queue_name}"
            self.redis_client.lpush(failed_key, task.task_id)
            self.redis_client.expire(failed_key, 86400)  # 24-hour TTL
            
            # Update statistics
            stats_key = f"proxc:stats:{task.queue_name}"
            self.redis_client.hincrby(stats_key, "total_failed", 1)
            
            logger.warning(f"Task {task.task_id} failed: {error_message}")
            return True
            
        except Exception as e:
            logger.error(f"Error failing task {task.task_id}: {e}")
            return False
    
    def get_queue_stats(self, queue_name: str = "default") -> Dict[str, Any]:
        """Get comprehensive queue statistics"""
        if not self.is_healthy():
            return {}
        
        try:
            stats = {}
            
            # Get basic statistics
            stats_key = f"proxc:stats:{queue_name}"
            redis_stats = self.redis_client.hgetall(stats_key)
            
            for key, value in redis_stats.items():
                try:
                    stats[key] = int(value)
                except ValueError:
                    stats[key] = value
            
            # Get queue lengths for each priority
            total_pending = 0
            for priority in [1, 2, 3]:
                priority_queue_key = f"proxc:queue:{queue_name}:{priority}"
                queue_length = self.redis_client.zcard(priority_queue_key)
                stats[f"priority_{priority}_pending"] = queue_length
                total_pending += queue_length
            
            stats["total_pending"] = total_pending
            
            # Get failed tasks count
            failed_key = f"proxc:failed:{queue_name}"
            stats["failed_in_queue"] = self.redis_client.llen(failed_key)
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting queue stats for {queue_name}: {e}")
            return {}
    
    def clear_queue(self, queue_name: str = "default") -> bool:
        """Clear all tasks from queue"""
        if not self.is_healthy():
            return False
        
        try:
            # Clear priority queues
            for priority in [1, 2, 3]:
                priority_queue_key = f"proxc:queue:{queue_name}:{priority}"
                self.redis_client.delete(priority_queue_key)
            
            # Clear failed tasks
            failed_key = f"proxc:failed:{queue_name}"
            self.redis_client.delete(failed_key)
            
            # Reset statistics
            stats_key = f"proxc:stats:{queue_name}"
            self.redis_client.delete(stats_key)
            
            logger.info(f"Queue {queue_name} cleared successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error clearing queue {queue_name}: {e}")
            return False
    
    def get_task(self, task_id: str) -> Optional[Task]:
        """Retrieve task by ID"""
        if not self.is_healthy():
            return None
        
        try:
            task_key = f"proxc:task:{task_id}"
            task_data = self.redis_client.get(task_key)
            
            if task_data:
                return Task.from_dict(json.loads(task_data))
            else:
                logger.debug(f"Task {task_id} not found")
                return None
                
        except Exception as e:
            logger.error(f"Error retrieving task {task_id}: {e}")
            return None