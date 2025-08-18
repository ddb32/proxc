"""Enhanced API Endpoints for ProxC System

Comprehensive REST API that provides:
- Complete proxy validation and management operations
- Real-time system monitoring and health checks
- Bulk processing and file upload capabilities
- Advanced configuration and optimization controls
- WebSocket support for real-time updates
- Comprehensive error handling and rate limiting
"""

import asyncio
import logging
import json
import os
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import asdict
import traceback

# FastAPI imports
try:
    from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, BackgroundTasks
    from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from fastapi.websockets import WebSocket, WebSocketDisconnect
    from pydantic import BaseModel, validator
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    # Fallback for environments without FastAPI
    FASTAPI_AVAILABLE = False
    FastAPI = object
    BaseModel = object

from ..core.integrated_system import IntegratedProxCSystem, SystemConfig, SystemState, ComponentStatus
from ..proxy_core.models import ProxyInfo, ProxyProtocol, TierLevel, RiskCategory, ProxyStatus
from ..proxy_engine.processing.bulk_stream_processor import StreamFormat
from ..proxy_engine.queue.intelligent_job_queue import JobType

logger = logging.getLogger(__name__)


# Pydantic models for API requests/responses
if FASTAPI_AVAILABLE:
    
    class ProxyRequest(BaseModel):
        """Request model for proxy validation"""
        host: str
        port: int
        protocol: str = "http"
        priority: float = 1.0
        tier_level: Optional[int] = None
        
        @validator('protocol')
        def validate_protocol(cls, v):
            valid_protocols = ['http', 'https', 'socks4', 'socks5']
            if v.lower() not in valid_protocols:
                raise ValueError(f'Protocol must be one of {valid_protocols}')
            return v.lower()
        
        @validator('port')
        def validate_port(cls, v):
            if not 1 <= v <= 65535:
                raise ValueError('Port must be between 1 and 65535')
            return v
        
        @validator('priority')
        def validate_priority(cls, v):
            if not 0.0 <= v <= 10.0:
                raise ValueError('Priority must be between 0.0 and 10.0')
            return v
    
    
    class BulkValidationRequest(BaseModel):
        """Request model for bulk proxy validation"""
        proxies: List[ProxyRequest]
        job_type: str = "bulk_validation"
        source: str = "api"
        
        @validator('proxies')
        def validate_proxies(cls, v):
            if len(v) > 10000:
                raise ValueError('Maximum 10,000 proxies per bulk request')
            return v
    
    
    class FileProcessingRequest(BaseModel):
        """Request model for file processing"""
        format_type: str = "jsonlines"
        output_format: Optional[str] = None
        chunk_size: int = 1000
        
        @validator('format_type')
        def validate_format(cls, v):
            valid_formats = ['jsonlines', 'csv', 'binary', 'compressed_json']
            if v not in valid_formats:
                raise ValueError(f'Format must be one of {valid_formats}')
            return v
    
    
    class SystemConfigUpdate(BaseModel):
        """Request model for system configuration updates"""
        max_concurrent_validations: Optional[int] = None
        max_queue_size: Optional[int] = None
        max_workers: Optional[int] = None
        enable_resource_optimization: Optional[bool] = None
        
        @validator('max_concurrent_validations')
        def validate_max_concurrent(cls, v):
            if v is not None and not 1 <= v <= 1000:
                raise ValueError('max_concurrent_validations must be between 1 and 1000')
            return v
    
    
    class ValidationResponse(BaseModel):
        """Response model for validation requests"""
        job_id: str
        status: str = "submitted"
        message: str = "Validation job submitted successfully"
        estimated_completion: Optional[str] = None
    
    
    class SystemStatusResponse(BaseModel):
        """Response model for system status"""
        system_state: str
        uptime_seconds: float
        component_health: Dict[str, Any]
        recent_metrics: Dict[str, Any]
        configuration: Dict[str, Any]
    
    
    class ErrorResponse(BaseModel):
        """Error response model"""
        error: str
        message: str
        details: Optional[Dict[str, Any]] = None
        timestamp: str


class WebSocketManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.client_subscriptions: Dict[WebSocket, Set[str]] = {}
    
    async def connect(self, websocket: WebSocket):
        """Accept new WebSocket connection"""
        await websocket.accept()
        self.active_connections.append(websocket)
        self.client_subscriptions[websocket] = set()
        logger.info(f"WebSocket client connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            if websocket in self.client_subscriptions:
                del self.client_subscriptions[websocket]
        logger.info(f"WebSocket client disconnected. Total connections: {len(self.active_connections)}")
    
    async def subscribe(self, websocket: WebSocket, event_types: List[str]):
        """Subscribe client to specific event types"""
        if websocket in self.client_subscriptions:
            self.client_subscriptions[websocket].update(event_types)
    
    async def broadcast(self, event_type: str, data: Any):
        """Broadcast event to subscribed clients"""
        if not self.active_connections:
            return
        
        message = {
            "event_type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        disconnected = []
        for connection in self.active_connections:
            try:
                if (connection in self.client_subscriptions and 
                    event_type in self.client_subscriptions[connection]):
                    await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for connection in disconnected:
            self.disconnect(connection)


class EnhancedProxCAPI:
    """Enhanced API server for ProxC system"""
    
    def __init__(self, integrated_system: IntegratedProxCSystem):
        self.system = integrated_system
        self.websocket_manager = WebSocketManager()
        
        if not FASTAPI_AVAILABLE:
            raise RuntimeError("FastAPI is required for the enhanced API")
        
        # Create FastAPI app
        self.app = FastAPI(
            title="ProxC Enhanced API",
            description="Comprehensive proxy validation and management system",
            version="2.0.0",
            docs_url="/docs",
            redoc_url="/redoc"
        )
        
        # Add CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Rate limiting and authentication (basic setup)
        self.security = HTTPBearer(auto_error=False)
        self.rate_limiter = self._create_rate_limiter()
        
        # Register routes
        self._register_routes()
        
        # Setup event handlers
        self._setup_event_handlers()
        
        logger.info("Enhanced ProxC API initialized")
    
    def _create_rate_limiter(self):
        """Create basic rate limiter"""
        # This is a simplified rate limiter
        # In production, use Redis-based rate limiting
        from collections import defaultdict
        import time
        
        class SimpleRateLimiter:
            def __init__(self, max_requests=100, window_seconds=60):
                self.max_requests = max_requests
                self.window_seconds = window_seconds
                self.requests = defaultdict(list)
            
            def is_allowed(self, client_id: str) -> bool:
                now = time.time()
                self.requests[client_id] = [
                    req_time for req_time in self.requests[client_id]
                    if now - req_time < self.window_seconds
                ]
                
                if len(self.requests[client_id]) >= self.max_requests:
                    return False
                
                self.requests[client_id].append(now)
                return True
        
        return SimpleRateLimiter()
    
    def _setup_event_handlers(self):
        """Setup event handlers for real-time updates"""
        
        def on_validation_complete(data):
            asyncio.create_task(
                self.websocket_manager.broadcast("validation_complete", data)
            )
        
        def on_system_alert(data):
            asyncio.create_task(
                self.websocket_manager.broadcast("system_alert", data)
            )
        
        self.system.register_event_handler("validation_complete", on_validation_complete)
        self.system.register_event_handler("system_alert", on_system_alert)
    
    def _register_routes(self):
        """Register all API routes"""
        
        # Health and status endpoints
        @self.app.get("/health", response_model=Dict[str, str])
        async def health_check():
            """Basic health check endpoint"""
            return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}
        
        @self.app.get("/status", response_model=SystemStatusResponse)
        async def get_system_status():
            """Get comprehensive system status"""
            try:
                status = self.system.get_system_status()
                return SystemStatusResponse(**status)
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/metrics")
        async def get_system_metrics():
            """Get detailed system metrics"""
            try:
                return self.system.get_performance_statistics()
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        # Proxy validation endpoints
        @self.app.post("/validate/proxy", response_model=ValidationResponse)
        async def validate_single_proxy(
            request: ProxyRequest,
            background_tasks: BackgroundTasks,
            token: HTTPAuthorizationCredentials = Depends(self.security)
        ):
            """Validate a single proxy"""
            try:
                # Rate limiting check
                client_id = getattr(token, 'credentials', 'anonymous') if token else 'anonymous'
                if not self.rate_limiter.is_allowed(client_id):
                    raise HTTPException(status_code=429, detail="Rate limit exceeded")
                
                # Convert request to ProxyInfo
                proxy = ProxyInfo(
                    host=request.host,
                    port=request.port,
                    protocol=ProxyProtocol(request.protocol)
                )
                
                if request.tier_level:
                    proxy.tier_level = TierLevel(request.tier_level)
                
                # Submit for validation
                job_id = await self.system.validate_proxy(proxy, request.priority)
                
                return ValidationResponse(
                    job_id=job_id,
                    estimated_completion=(datetime.utcnow() + timedelta(minutes=2)).isoformat()
                )
                
            except Exception as e:
                logger.error(f"Proxy validation error: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/validate/bulk")
        async def validate_bulk_proxies(
            request: BulkValidationRequest,
            background_tasks: BackgroundTasks,
            token: HTTPAuthorizationCredentials = Depends(self.security)
        ):
            """Validate multiple proxies in bulk"""
            try:
                # Rate limiting check
                client_id = getattr(token, 'credentials', 'anonymous') if token else 'anonymous'
                if not self.rate_limiter.is_allowed(client_id):
                    raise HTTPException(status_code=429, detail="Rate limit exceeded")
                
                # Convert requests to ProxyInfo objects
                proxies = []
                for proxy_req in request.proxies:
                    proxy = ProxyInfo(
                        host=proxy_req.host,
                        port=proxy_req.port,
                        protocol=ProxyProtocol(proxy_req.protocol)
                    )
                    if proxy_req.tier_level:
                        proxy.tier_level = TierLevel(proxy_req.tier_level)
                    proxies.append(proxy)
                
                # Submit for bulk validation
                job_ids = await self.system.validate_proxy_list(proxies)
                
                return {
                    "job_ids": job_ids,
                    "total_submitted": len(job_ids),
                    "estimated_completion": (datetime.utcnow() + timedelta(minutes=10)).isoformat()
                }
                
            except Exception as e:
                logger.error(f"Bulk validation error: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # File processing endpoints
        @self.app.post("/process/file")
        async def process_proxy_file(
            file: UploadFile = File(...),
            request: FileProcessingRequest = Depends(),
            background_tasks: BackgroundTasks = BackgroundTasks(),
            token: HTTPAuthorizationCredentials = Depends(self.security)
        ):
            """Process a proxy file upload"""
            try:
                # Rate limiting check
                client_id = getattr(token, 'credentials', 'anonymous') if token else 'anonymous'
                if not self.rate_limiter.is_allowed(client_id):
                    raise HTTPException(status_code=429, detail="Rate limit exceeded")
                
                # Validate file size (max 100MB)
                max_size = 100 * 1024 * 1024
                if file.size and file.size > max_size:
                    raise HTTPException(status_code=413, detail="File too large (max 100MB)")
                
                # Save uploaded file temporarily
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    content = await file.read()
                    temp_file.write(content)
                    temp_file_path = temp_file.name
                
                # Determine output file path
                output_path = None
                if request.output_format:
                    output_path = temp_file_path + "_output"
                
                # Process file in background
                async def process_file():
                    try:
                        format_type = StreamFormat(request.format_type)
                        result = await self.system.process_proxy_file(
                            temp_file_path, 
                            format_type,
                            output_path
                        )
                        
                        # Broadcast completion event
                        await self.websocket_manager.broadcast("file_processed", {
                            "filename": file.filename,
                            "result": result
                        })
                        
                    except Exception as e:
                        logger.error(f"File processing error: {e}")
                    finally:
                        # Cleanup temporary files
                        try:
                            os.unlink(temp_file_path)
                            if output_path and os.path.exists(output_path):
                                os.unlink(output_path)
                        except:
                            pass
                
                background_tasks.add_task(process_file)
                
                return {
                    "message": "File processing started",
                    "filename": file.filename,
                    "file_size": len(content),
                    "format": request.format_type
                }
                
            except Exception as e:
                logger.error(f"File upload error: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # Configuration endpoints
        @self.app.get("/config")
        async def get_system_configuration():
            """Get current system configuration"""
            return {
                "max_concurrent_validations": self.system.config.max_concurrent_validations,
                "max_queue_size": self.system.config.max_queue_size,
                "max_workers": self.system.config.max_workers,
                "max_memory_mb": self.system.config.max_memory_mb,
                "enable_resource_optimization": self.system.config.enable_resource_optimization,
                "enable_geographic_optimization": self.system.config.enable_geographic_optimization
            }
        
        @self.app.post("/config/update")
        async def update_system_configuration(
            config_update: SystemConfigUpdate,
            token: HTTPAuthorizationCredentials = Depends(self.security)
        ):
            """Update system configuration"""
            try:
                # Rate limiting check
                client_id = getattr(token, 'credentials', 'anonymous') if token else 'anonymous'
                if not self.rate_limiter.is_allowed(client_id):
                    raise HTTPException(status_code=429, detail="Rate limit exceeded")
                
                # Apply configuration updates
                updated_fields = []
                
                if config_update.max_concurrent_validations is not None:
                    self.system.config.max_concurrent_validations = config_update.max_concurrent_validations
                    updated_fields.append("max_concurrent_validations")
                
                if config_update.max_queue_size is not None:
                    self.system.config.max_queue_size = config_update.max_queue_size
                    updated_fields.append("max_queue_size")
                
                if config_update.max_workers is not None:
                    self.system.config.max_workers = config_update.max_workers
                    updated_fields.append("max_workers")
                
                if config_update.enable_resource_optimization is not None:
                    self.system.config.enable_resource_optimization = config_update.enable_resource_optimization
                    updated_fields.append("enable_resource_optimization")
                
                return {
                    "message": "Configuration updated successfully",
                    "updated_fields": updated_fields,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
            except Exception as e:
                logger.error(f"Configuration update error: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # Administrative endpoints
        @self.app.post("/admin/shutdown")
        async def shutdown_system(
            token: HTTPAuthorizationCredentials = Depends(self.security)
        ):
            """Gracefully shutdown the system"""
            try:
                await self.system.shutdown_system()
                return {"message": "System shutdown initiated"}
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/admin/logs")
        async def get_system_logs(
            lines: int = 100,
            level: str = "INFO",
            token: HTTPAuthorizationCredentials = Depends(self.security)
        ):
            """Get recent system logs"""
            # This would integrate with actual logging system
            return {
                "message": "Log retrieval not implemented",
                "requested_lines": lines,
                "requested_level": level
            }
        
        # WebSocket endpoint
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time updates"""
            await self.websocket_manager.connect(websocket)
            try:
                while True:
                    data = await websocket.receive_json()
                    
                    # Handle subscription requests
                    if data.get("action") == "subscribe":
                        event_types = data.get("event_types", [])
                        await self.websocket_manager.subscribe(websocket, event_types)
                        await websocket.send_json({
                            "status": "subscribed",
                            "event_types": event_types
                        })
                    
            except WebSocketDisconnect:
                self.websocket_manager.disconnect(websocket)
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                self.websocket_manager.disconnect(websocket)
        
        # Error handlers
        @self.app.exception_handler(Exception)
        async def global_exception_handler(request, exc):
            """Global exception handler"""
            logger.error(f"Unhandled exception: {exc}\n{traceback.format_exc()}")
            return JSONResponse(
                status_code=500,
                content=ErrorResponse(
                    error="Internal Server Error",
                    message=str(exc),
                    timestamp=datetime.utcnow().isoformat()
                ).dict()
            )
        
        @self.app.exception_handler(404)
        async def not_found_handler(request, exc):
            """404 error handler"""
            return JSONResponse(
                status_code=404,
                content=ErrorResponse(
                    error="Not Found",
                    message="The requested resource was not found",
                    timestamp=datetime.utcnow().isoformat()
                ).dict()
            )
    
    async def start_server(self, host: str = "0.0.0.0", port: int = 8080):
        """Start the API server"""
        config = uvicorn.Config(
            self.app,
            host=host,
            port=port,
            log_level="info",
            access_log=True
        )
        server = uvicorn.Server(config)
        await server.serve()


def create_enhanced_api(integrated_system: IntegratedProxCSystem) -> EnhancedProxCAPI:
    """Factory function to create enhanced API"""
    return EnhancedProxCAPI(integrated_system)


async def main():
    """Example usage and testing"""
    from ..core.integrated_system import create_integrated_system, SystemConfig
    
    # Create system configuration
    config = SystemConfig(
        max_concurrent_validations=50,
        max_queue_size=5000,
        api_host="localhost",
        api_port=8080
    )
    
    # Create and initialize integrated system
    system = create_integrated_system(config)
    success = await system.initialize_system()
    
    if not success:
        print("Failed to initialize system")
        return
    
    try:
        # Create and start API server
        api = create_enhanced_api(system)
        print(f"Starting ProxC API server on {config.api_host}:{config.api_port}")
        print("API documentation available at: http://localhost:8080/docs")
        
        await api.start_server(config.api_host, config.api_port)
        
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        await system.shutdown_system()


if __name__ == "__main__":
    if not FASTAPI_AVAILABLE:
        print("FastAPI is required to run the enhanced API server")
        print("Install with: pip install fastapi uvicorn")
    else:
        asyncio.run(main())