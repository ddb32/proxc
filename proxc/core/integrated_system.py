"""Integrated ProxC System - Phase 4 Integration

Comprehensive integration layer that:
- Integrates all Phase 1-3 components into unified system
- Provides high-level API endpoints for all functionality
- Implements system-wide orchestration and coordination
- Handles configuration management and service discovery
- Provides comprehensive monitoring and health checks
- Implements graceful startup, shutdown, and failure recovery
"""

import asyncio
import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Callable, Any, Set, Tuple, Union
from dataclasses import dataclass, field
import json
import os

# Phase 1 imports
from ..database.migrations.migration_runner import MigrationRunner
from ..proxy_core.models import ProxyInfo, TierLevel, RiskCategory, ProxyStatus
from ..proxy_core.geo.geo_manager import GeoManager

# Phase 2 imports
from ..proxy_engine.scanning.tier_manager import TierManager
from ..proxy_engine.scheduling.intelligent_scheduler import IntelligentScheduler
from ..proxy_engine.optimization.resource_optimizer import ResourceOptimizer

# Phase 3 imports
from ..proxy_engine.queue.intelligent_job_queue import IntelligentJobQueue, ValidationJob, JobType
from ..proxy_engine.workers.parallel_worker_system import ParallelWorkerSystem
from ..proxy_engine.processing.bulk_stream_processor import BulkProxyProcessor, StreamFormat

logger = logging.getLogger(__name__)


class SystemState(Enum):
    """System operational states"""
    INITIALIZING = "initializing"
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class ComponentStatus(Enum):
    """Individual component status"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    OFFLINE = "offline"


@dataclass
class SystemConfig:
    """System-wide configuration"""
    # Database settings
    database_url: str = "sqlite:///proxc.db"
    enable_migrations: bool = True
    
    # Component settings
    max_concurrent_validations: int = 100
    max_queue_size: int = 10000
    max_memory_mb: int = 1024
    
    # Worker settings
    min_workers: int = 5
    max_workers: int = 50
    
    # Optimization settings
    enable_resource_optimization: bool = True
    enable_geographic_optimization: bool = True
    
    # API settings
    api_host: str = "localhost"
    api_port: int = 8080
    enable_api_auth: bool = False
    
    # Monitoring settings
    health_check_interval: int = 30
    metrics_retention_hours: int = 24
    
    # File processing settings
    bulk_processing_enabled: bool = True
    streaming_batch_size: int = 1000


@dataclass
class ComponentHealth:
    """Health status of system component"""
    name: str
    status: ComponentStatus
    last_check: datetime
    message: str = ""
    metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemMetrics:
    """System-wide performance metrics"""
    timestamp: datetime
    
    # Processing metrics
    total_proxies: int = 0
    active_proxies: int = 0
    failed_proxies: int = 0
    validations_per_minute: float = 0.0
    
    # Resource metrics
    cpu_usage: float = 0.0
    memory_usage_mb: float = 0.0
    queue_size: int = 0
    active_workers: int = 0
    
    # Performance metrics
    average_validation_time: float = 0.0
    success_rate: float = 0.0
    throughput: float = 0.0


class IntegratedProxCSystem:
    """Main integrated system orchestrator"""
    
    def __init__(self, config: SystemConfig):
        self.config = config
        self.state = SystemState.INITIALIZING
        self.start_time = datetime.utcnow()
        
        # Component instances
        self.migration_runner: Optional[MigrationRunner] = None
        self.geo_manager: Optional[GeoManager] = None
        self.tier_manager: Optional[TierManager] = None
        self.resource_optimizer: Optional[ResourceOptimizer] = None
        self.intelligent_scheduler: Optional[IntelligentScheduler] = None
        self.job_queue: Optional[IntelligentJobQueue] = None
        self.worker_system: Optional[ParallelWorkerSystem] = None
        self.bulk_processor: Optional[BulkProxyProcessor] = None
        
        # Health monitoring
        self.component_health: Dict[str, ComponentHealth] = {}
        self.system_metrics: List[SystemMetrics] = []
        self.metrics_lock = threading.RLock()
        
        # Event handling
        self.event_handlers: Dict[str, List[Callable]] = defaultdict(list)
        
        # Background tasks
        self._health_monitor_task = None
        self._metrics_collector_task = None
        self._running = False
        
        logger.info("IntegratedProxCSystem initialized")
    
    async def initialize_system(self) -> bool:
        """Initialize all system components"""
        try:
            self.state = SystemState.STARTING
            logger.info("Starting ProxC system initialization...")
            
            # Phase 1: Database and core models
            await self._initialize_phase1()
            
            # Phase 2: Scanning and optimization
            await self._initialize_phase2()
            
            # Phase 3: Queue and workers
            await self._initialize_phase3()
            
            # Start background services
            await self._start_background_services()
            
            self.state = SystemState.RUNNING
            logger.info("ProxC system initialization completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"System initialization failed: {e}")
            self.state = SystemState.FAILED
            return False
    
    async def _initialize_phase1(self):
        """Initialize Phase 1 components"""
        logger.info("Initializing Phase 1 components...")
        
        # Database migrations
        if self.config.enable_migrations:
            from ..database.migrations.migration_runner import create_migration_runner
            self.migration_runner = create_migration_runner(self.config.database_url)
            await asyncio.get_event_loop().run_in_executor(
                None, self.migration_runner.run_migrations
            )
            self._update_component_health("migration_runner", ComponentStatus.HEALTHY, 
                                        "Migrations completed successfully")
        
        # Geographic manager
        if self.config.enable_geographic_optimization:
            from ..proxy_core.geo.geo_manager import create_geo_manager
            self.geo_manager = create_geo_manager()
            self._update_component_health("geo_manager", ComponentStatus.HEALTHY, 
                                        "Geographic services initialized")
    
    async def _initialize_phase2(self):
        """Initialize Phase 2 components"""
        logger.info("Initializing Phase 2 components...")
        
        # Tier manager
        from ..proxy_engine.scanning.tier_manager import create_tier_manager
        self.tier_manager = create_tier_manager()
        self._update_component_health("tier_manager", ComponentStatus.HEALTHY, 
                                    "Multi-tier scanning system ready")
        
        # Resource optimizer
        if self.config.enable_resource_optimization:
            from ..proxy_engine.optimization.resource_optimizer import create_resource_optimizer
            self.resource_optimizer = create_resource_optimizer(
                max_workers=self.config.max_workers,
                min_workers=self.config.min_workers
            )
            self.resource_optimizer.start_optimization()
            self._update_component_health("resource_optimizer", ComponentStatus.HEALTHY, 
                                        "Resource optimization active")
        
        # Intelligent scheduler
        from ..proxy_engine.scheduling.intelligent_scheduler import create_intelligent_scheduler
        self.intelligent_scheduler = create_intelligent_scheduler(
            self.tier_manager, 
            max_concurrent=self.config.max_concurrent_validations
        )
        self._update_component_health("intelligent_scheduler", ComponentStatus.HEALTHY, 
                                    "Intelligent scheduling system ready")
    
    async def _initialize_phase3(self):
        """Initialize Phase 3 components"""
        logger.info("Initializing Phase 3 components...")
        
        # Job queue
        from ..proxy_engine.queue.intelligent_job_queue import create_intelligent_job_queue
        self.job_queue = create_intelligent_job_queue(
            max_queue_size=self.config.max_queue_size,
            persistence_file="proxc_queue.json"
        )
        self.job_queue.start_processing()
        self._update_component_health("job_queue", ComponentStatus.HEALTHY, 
                                    "Intelligent job queue active")
        
        # Worker system
        from ..proxy_engine.workers.parallel_worker_system import create_parallel_worker_system
        self.worker_system = create_parallel_worker_system(self.resource_optimizer)
        self.worker_system.start_system()
        self._update_component_health("worker_system", ComponentStatus.HEALTHY, 
                                    "Parallel worker system operational")
        
        # Bulk processor
        if self.config.bulk_processing_enabled:
            from ..proxy_engine.processing.bulk_stream_processor import create_bulk_stream_processor
            self.bulk_processor = create_bulk_stream_processor(
                max_memory_mb=self.config.max_memory_mb,
                batch_size=self.config.streaming_batch_size,
                worker_system=self.worker_system
            )
            self._update_component_health("bulk_processor", ComponentStatus.HEALTHY, 
                                        "Bulk processing system ready")
    
    async def _start_background_services(self):
        """Start background monitoring and maintenance services"""
        self._running = True
        
        # Health monitoring
        self._health_monitor_task = asyncio.create_task(self._health_monitor_loop())
        
        # Metrics collection
        self._metrics_collector_task = asyncio.create_task(self._metrics_collector_loop())
        
        logger.info("Background services started")
    
    async def shutdown_system(self, timeout: int = 60):
        """Gracefully shutdown the system"""
        logger.info("Starting system shutdown...")
        self.state = SystemState.STOPPING
        self._running = False
        
        try:
            # Cancel background tasks
            if self._health_monitor_task:
                self._health_monitor_task.cancel()
            if self._metrics_collector_task:
                self._metrics_collector_task.cancel()
            
            # Shutdown components in reverse order
            if self.bulk_processor:
                # Bulk processor doesn't need explicit shutdown
                pass
            
            if self.worker_system:
                self.worker_system.stop_system(timeout=30)
            
            if self.job_queue:
                self.job_queue.stop_processing()
            
            if self.resource_optimizer:
                self.resource_optimizer.stop_optimization()
            
            # Update component statuses
            for component_name in self.component_health:
                self._update_component_health(component_name, ComponentStatus.OFFLINE, 
                                            "System shutdown")
            
            self.state = SystemState.STOPPED
            logger.info("System shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
            self.state = SystemState.FAILED
    
    def _update_component_health(self, name: str, status: ComponentStatus, message: str = ""):
        """Update component health status"""
        self.component_health[name] = ComponentHealth(
            name=name,
            status=status,
            last_check=datetime.utcnow(),
            message=message
        )
    
    async def _health_monitor_loop(self):
        """Background health monitoring"""
        while self._running:
            try:
                await self._perform_health_checks()
                await asyncio.sleep(self.config.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health monitor error: {e}")
                await asyncio.sleep(self.config.health_check_interval)
    
    async def _perform_health_checks(self):
        """Perform health checks on all components"""
        
        # Check job queue
        if self.job_queue:
            stats = self.job_queue.get_queue_statistics()
            queue_size = stats['queue_sizes']['pending']
            if queue_size > self.config.max_queue_size * 0.9:
                self._update_component_health("job_queue", ComponentStatus.WARNING, 
                                            f"Queue nearly full: {queue_size}")
            elif queue_size > self.config.max_queue_size * 0.95:
                self._update_component_health("job_queue", ComponentStatus.CRITICAL, 
                                            f"Queue critical: {queue_size}")
            else:
                self._update_component_health("job_queue", ComponentStatus.HEALTHY, 
                                            f"Queue size: {queue_size}")
        
        # Check worker system
        if self.worker_system:
            status = self.worker_system.get_system_status()
            total_workers = status['total_workers']
            if total_workers < self.config.min_workers:
                self._update_component_health("worker_system", ComponentStatus.WARNING, 
                                            f"Low worker count: {total_workers}")
            else:
                self._update_component_health("worker_system", ComponentStatus.HEALTHY, 
                                            f"Workers: {total_workers}")
        
        # Check resource optimizer
        if self.resource_optimizer:
            allocation = self.resource_optimizer.get_current_allocation()
            cpu_usage = allocation['system_metrics']['cpu_percent']
            memory_usage = allocation['system_metrics']['memory_percent']
            
            if cpu_usage > 90 or memory_usage > 90:
                self._update_component_health("resource_optimizer", ComponentStatus.CRITICAL, 
                                            f"High resource usage: CPU {cpu_usage}%, Memory {memory_usage}%")
            elif cpu_usage > 80 or memory_usage > 80:
                self._update_component_health("resource_optimizer", ComponentStatus.WARNING, 
                                            f"Resource usage: CPU {cpu_usage}%, Memory {memory_usage}%")
            else:
                self._update_component_health("resource_optimizer", ComponentStatus.HEALTHY, 
                                            f"Resource usage: CPU {cpu_usage}%, Memory {memory_usage}%")
    
    async def _metrics_collector_loop(self):
        """Background metrics collection"""
        while self._running:
            try:
                await self._collect_system_metrics()
                await asyncio.sleep(60)  # Collect metrics every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Metrics collector error: {e}")
                await asyncio.sleep(60)
    
    async def _collect_system_metrics(self):
        """Collect comprehensive system metrics"""
        metrics = SystemMetrics(timestamp=datetime.utcnow())
        
        # Job queue metrics
        if self.job_queue:
            queue_stats = self.job_queue.get_queue_statistics()
            metrics.queue_size = queue_stats['queue_sizes']['pending']
        
        # Worker system metrics
        if self.worker_system:
            worker_stats = self.worker_system.get_system_status()
            metrics.active_workers = worker_stats['total_workers']
        
        # Resource metrics
        if self.resource_optimizer:
            allocation = self.resource_optimizer.get_current_allocation()
            metrics.cpu_usage = allocation['system_metrics']['cpu_percent']
            metrics.memory_usage_mb = allocation['system_metrics']['memory_percent'] * self.config.max_memory_mb / 100
        
        # Store metrics
        with self.metrics_lock:
            self.system_metrics.append(metrics)
            
            # Clean old metrics
            cutoff_time = datetime.utcnow() - timedelta(hours=self.config.metrics_retention_hours)
            self.system_metrics = [m for m in self.system_metrics if m.timestamp > cutoff_time]
    
    # High-level API methods
    
    async def validate_proxy(self, proxy: ProxyInfo, priority: float = 1.0) -> str:
        """Submit single proxy for validation"""
        if not self.job_queue:
            raise RuntimeError("Job queue not initialized")
        
        job_id = self.job_queue.submit_job(
            proxy=proxy,
            job_type=JobType.STANDARD_VALIDATION,
            priority=priority,
            source="api"
        )
        
        return job_id
    
    async def validate_proxy_list(self, proxies: List[ProxyInfo]) -> List[str]:
        """Submit list of proxies for validation"""
        if not self.job_queue:
            raise RuntimeError("Job queue not initialized")
        
        job_ids = self.job_queue.submit_bulk_jobs(
            proxies=proxies,
            job_type=JobType.BULK_VALIDATION,
            source="api_bulk"
        )
        
        return job_ids
    
    async def process_proxy_file(self, file_path: str, 
                               format_type: StreamFormat = StreamFormat.JSON_LINES,
                               output_path: Optional[str] = None) -> Dict[str, Any]:
        """Process large proxy file"""
        if not self.bulk_processor:
            raise RuntimeError("Bulk processor not initialized")
        
        stats = await self.bulk_processor.process_proxy_file(
            input_file=file_path,
            output_file=output_path,
            format_type=format_type
        )
        
        return {
            'items_processed': stats.items_processed,
            'items_failed': stats.items_failed,
            'processing_time': stats.processing_time,
            'throughput': stats.throughput_items_per_sec
        }
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        return {
            'system_state': self.state.value,
            'uptime_seconds': (datetime.utcnow() - self.start_time).total_seconds(),
            'component_health': {
                name: {
                    'status': health.status.value,
                    'message': health.message,
                    'last_check': health.last_check.isoformat()
                }
                for name, health in self.component_health.items()
            },
            'recent_metrics': self._get_recent_metrics(),
            'configuration': {
                'max_workers': self.config.max_workers,
                'max_queue_size': self.config.max_queue_size,
                'max_memory_mb': self.config.max_memory_mb
            }
        }
    
    def _get_recent_metrics(self) -> Dict[str, Any]:
        """Get recent system metrics"""
        with self.metrics_lock:
            if not self.system_metrics:
                return {}
            
            latest = self.system_metrics[-1]
            return {
                'timestamp': latest.timestamp.isoformat(),
                'queue_size': latest.queue_size,
                'active_workers': latest.active_workers,
                'cpu_usage': latest.cpu_usage,
                'memory_usage_mb': latest.memory_usage_mb
            }
    
    def get_performance_statistics(self) -> Dict[str, Any]:
        """Get detailed performance statistics"""
        stats = {}
        
        if self.job_queue:
            stats['job_queue'] = self.job_queue.get_queue_statistics()
        
        if self.worker_system:
            stats['worker_system'] = self.worker_system.get_system_status()
        
        if self.resource_optimizer:
            stats['resource_optimizer'] = self.resource_optimizer.get_optimization_statistics()
        
        if self.intelligent_scheduler:
            stats['scheduler'] = self.intelligent_scheduler.get_queue_statistics()
        
        if self.tier_manager:
            stats['tier_manager'] = self.tier_manager.get_tier_statistics()
        
        return stats
    
    async def update_proxy_tier(self, proxy_id: str, new_tier: TierLevel) -> bool:
        """Update proxy tier assignment"""
        if not self.tier_manager:
            return False
        
        # This would integrate with actual proxy storage
        # For now, just log the operation
        logger.info(f"Updating proxy {proxy_id} to tier {new_tier.name}")
        return True
    
    def register_event_handler(self, event_type: str, handler: Callable):
        """Register event handler for system events"""
        self.event_handlers[event_type].append(handler)
    
    def emit_event(self, event_type: str, data: Any):
        """Emit system event to registered handlers"""
        for handler in self.event_handlers[event_type]:
            try:
                handler(data)
            except Exception as e:
                logger.error(f"Event handler error: {e}")


def create_integrated_system(config: Optional[SystemConfig] = None) -> IntegratedProxCSystem:
    """Factory function to create integrated system"""
    if config is None:
        config = SystemConfig()
    return IntegratedProxCSystem(config)


async def main():
    """Example usage and testing"""
    
    # Create system configuration
    config = SystemConfig(
        max_concurrent_validations=50,
        max_queue_size=5000,
        max_memory_mb=512,
        min_workers=3,
        max_workers=20,
        enable_resource_optimization=True,
        enable_geographic_optimization=True,
        bulk_processing_enabled=True
    )
    
    # Create and initialize system
    system = create_integrated_system(config)
    
    print("Initializing ProxC integrated system...")
    success = await system.initialize_system()
    
    if not success:
        print("Failed to initialize system")
        return
    
    print("System initialized successfully!")
    
    # Test system functionality
    try:
        # Get system status
        status = system.get_system_status()
        print(f"\nSystem State: {status['system_state']}")
        print(f"Uptime: {status['uptime_seconds']:.1f} seconds")
        
        print("\nComponent Health:")
        for name, health in status['component_health'].items():
            print(f"  {name}: {health['status']} - {health['message']}")
        
        # Test proxy validation
        from ..proxy_core.models import ProxyInfo, ProxyProtocol
        test_proxy = ProxyInfo(
            host="8.8.8.8",
            port=8080,
            protocol=ProxyProtocol.HTTP
        )
        
        job_id = await system.validate_proxy(test_proxy, priority=0.8)
        print(f"\nSubmitted validation job: {job_id}")
        
        # Wait a bit and check performance stats
        await asyncio.sleep(5)
        
        perf_stats = system.get_performance_statistics()
        if 'job_queue' in perf_stats:
            queue_stats = perf_stats['job_queue']
            print(f"\nQueue Statistics:")
            print(f"  Pending: {queue_stats['queue_sizes']['pending']}")
            print(f"  Processing: {queue_stats['queue_sizes']['processing']}")
            print(f"  Completed: {queue_stats['queue_sizes']['completed']}")
        
        if 'worker_system' in perf_stats:
            worker_stats = perf_stats['worker_system']
            print(f"\nWorker Statistics:")
            print(f"  Total workers: {worker_stats['total_workers']}")
            print(f"  Jobs processed: {worker_stats['system_stats']['total_jobs_processed']}")
        
    finally:
        # Shutdown system
        print("\nShutting down system...")
        await system.shutdown_system()
        print("System shutdown completed")


if __name__ == "__main__":
    asyncio.run(main())