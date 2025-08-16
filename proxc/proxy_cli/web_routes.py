"""Proxy CLI Web Routes - Centralized route handling for web interface"""

import json
from pathlib import Path
from typing import Dict, Any, Callable, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .cli_base import get_cli_logger
from .cli_exceptions import WebInterfaceError, CLIErrorHandler
from .api_routes import APIRouter


class WebRoute:
    """Individual web route definition"""
    
    def __init__(self, path: str, handler: Callable, methods: Optional[list] = None):
        self.path = path
        self.handler = handler
        self.methods = methods or ['GET']
        
    def matches(self, path: str, method: str) -> bool:
        """Check if this route matches the given path and method"""
        return self.path == path and method in self.methods


class WebRouter:
    """Centralized web request router"""
    
    def __init__(self, data_handler, template_dir: Optional[Path] = None):
        self.data_handler = data_handler
        self.template_dir = template_dir or Path(__file__).parent
        self.routes = []
        self.logger = get_cli_logger("web_router")
        self.error_handler = CLIErrorHandler(self.logger)
        
        # Initialize API router
        self.api_router = APIRouter(data_handler)
        
        # Register default routes
        self._register_default_routes()
    
    def _register_default_routes(self):
        """Register default web routes"""
        self.add_route('/', self._handle_dashboard)
        self.add_route('/ws', self._handle_websocket)
        self.add_route('/api/proxies', self._handle_proxies_api)
        self.add_route('/api/summary', self._handle_summary_api)
        self.add_route('/api/export', self._handle_export_api)
        self.add_route('/api/v1/docs', self._handle_api_docs)
        self.add_route('/api/v1/docs/spec', self._handle_api_spec)
        self.add_route('/health', self._handle_health_check)
    
    def add_route(self, path: str, handler: Callable, methods: Optional[list] = None):
        """Add a new route"""
        route = WebRoute(path, handler, methods)
        self.routes.append(route)
        self.logger.debug(f"Added route: {path} -> {handler.__name__}")
    
    def route(self, path: str, method: str, query_params: Dict[str, list], 
             headers: Dict[str, str] = None, body: bytes = None) -> Tuple[int, str, bytes]:
        """Route a request to the appropriate handler"""
        try:
            headers = headers or {}
            
            # Check if this is an API request
            if path.startswith('/api/v1/'):
                return self.api_router.route_api_request(path, method, query_params, headers, body)
            
            # Find matching route for web interface
            for route in self.routes:
                if route.matches(path, method):
                    self.logger.debug(f"Routing {method} {path} to {route.handler.__name__}")
                    return route.handler(query_params)
            
            # No route found
            return self._handle_404()
            
        except Exception as e:
            web_error = WebInterfaceError(
                f"Error processing request {method} {path}",
                endpoint=path,
                method=method
            )
            self.error_handler.handle_error(web_error, context={'query_params': query_params})
            return self._handle_500(str(web_error))
    
    def _handle_dashboard(self, query_params: Dict[str, list]) -> Tuple[int, str, bytes]:
        """Handle dashboard page request"""
        try:
            template_path = self.template_dir / "web_template.html"
            
            if template_path.exists():
                with open(template_path, 'r', encoding='utf-8') as f:
                    html_content = f.read()
                return 200, 'text/html', html_content.encode('utf-8')
            else:
                # Fallback minimal HTML
                fallback_html = self._get_fallback_html()
                return 200, 'text/html', fallback_html.encode('utf-8')
                
        except Exception as e:
            self.logger.error(f"Error serving dashboard: {e}")
            return self._handle_500("Dashboard template error")
    
    def _handle_proxies_api(self, query_params: Dict[str, list]) -> Tuple[int, str, bytes]:
        """Handle proxies API request"""
        try:
            # Extract parameters
            filters = {}
            for key, values in query_params.items():
                if key in ['status', 'protocol', 'country', 'anonymity_level']:
                    filters[key] = values[0] if values else None
            
            limit = int(query_params.get('limit', ['100'])[0])
            offset = int(query_params.get('offset', ['0'])[0])
            
            # Get data
            data = self.data_handler.get_proxies_json(filters, limit, offset)
            json_data = json.dumps(data, indent=2)
            
            return 200, 'application/json', json_data.encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error serving proxies API: {e}")
            error_response = {'error': 'Failed to load proxy data', 'proxies': [], 'total_count': 0}
            return 500, 'application/json', json.dumps(error_response).encode('utf-8')
    
    def _handle_summary_api(self, query_params: Dict[str, list]) -> Tuple[int, str, bytes]:
        """Handle summary API request"""
        try:
            data = self.data_handler.get_summary_json()
            json_data = json.dumps(data, indent=2)
            
            return 200, 'application/json', json_data.encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error serving summary API: {e}")
            error_response = {
                'error': 'Failed to load summary data',
                'total_proxies': 0,
                'active_proxies': 0,
                'success_rate': 0.0
            }
            return 500, 'application/json', json.dumps(error_response).encode('utf-8')
    
    def _handle_export_api(self, query_params: Dict[str, list]) -> Tuple[int, str, bytes]:
        """Handle export API request"""
        try:
            export_format = query_params.get('format', ['json'])[0].lower()
            
            if export_format == 'csv':
                csv_data = self.data_handler.get_proxies_csv()
                return 200, 'text/csv', csv_data.encode('utf-8')
            elif export_format == 'json':
                # Get all proxies for export
                data = self.data_handler.get_proxies_json(limit=10000)
                json_data = json.dumps(data['proxies'], indent=2)
                return 200, 'application/json', json_data.encode('utf-8')
            else:
                error_response = {'error': 'Unsupported export format'}
                return 400, 'application/json', json.dumps(error_response).encode('utf-8')
                
        except Exception as e:
            self.logger.error(f"Error serving export API: {e}")
            error_response = {'error': 'Export failed'}
            return 500, 'application/json', json.dumps(error_response).encode('utf-8')
    
    def _handle_websocket(self, query_params: Dict[str, list]) -> Tuple[int, str, bytes]:
        """Handle WebSocket endpoint (actual upgrade handled by server)"""
        # This is a placeholder - actual WebSocket upgrade is handled by the server
        return 200, 'text/plain', b'WebSocket endpoint'
    
    def _handle_api_docs(self, query_params: Dict[str, list]) -> Tuple[int, str, bytes]:
        """Handle API documentation page"""
        try:
            from .api_docs import OpenAPIGenerator
            
            generator = OpenAPIGenerator()
            html_docs = generator.generate_html_docs("/api/v1/docs/spec")
            
            return 200, 'text/html', html_docs.encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error serving API docs: {e}")
            return 500, 'text/html', b'<h1>Error loading API documentation</h1>'
    
    def _handle_api_spec(self, query_params: Dict[str, list]) -> Tuple[int, str, bytes]:
        """Handle OpenAPI specification JSON"""
        try:
            from .api_docs import OpenAPIGenerator
            
            generator = OpenAPIGenerator()
            spec = generator.generate_spec()
            json_data = json.dumps(spec, indent=2)
            
            return 200, 'application/json', json_data.encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error serving API spec: {e}")
            error_response = {'error': 'Failed to load API specification'}
            return 500, 'application/json', json.dumps(error_response).encode('utf-8')
    
    def _handle_health_check(self, query_params: Dict[str, list]) -> Tuple[int, str, bytes]:
        """Handle health check request"""
        try:
            health_data = {
                'status': 'healthy',
                'proxy_count': len(self.data_handler.proxies),
                'timestamp': self.data_handler.get_summary_json().get('timestamp', 'unknown')
            }
            json_data = json.dumps(health_data)
            return 200, 'application/json', json_data.encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Health check error: {e}")
            error_response = {'status': 'unhealthy', 'error': str(e)}
            return 503, 'application/json', json.dumps(error_response).encode('utf-8')
    
    def _handle_404(self) -> Tuple[int, str, bytes]:
        """Handle 404 Not Found"""
        response = {'error': 'Not Found', 'message': 'The requested resource was not found'}
        return 404, 'application/json', json.dumps(response).encode('utf-8')
    
    def _handle_500(self, error_message: str = "Internal Server Error") -> Tuple[int, str, bytes]:
        """Handle 500 Internal Server Error"""
        response = {'error': 'Internal Server Error', 'message': error_message}
        return 500, 'application/json', json.dumps(response).encode('utf-8')
    
    def _get_fallback_html(self) -> str:
        """Get minimal fallback HTML when template is unavailable"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ProxC Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .error { color: red; padding: 20px; background: #f8f8f8; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>ProxC Dashboard</h1>
    <div class="error">
        <h3>Template Loading Error</h3>
        <p>The dashboard template could not be loaded. Using minimal fallback interface.</p>
        <p>Try accessing the API directly:</p>
        <ul>
            <li><a href="/api/proxies">Proxies API</a></li>
            <li><a href="/api/summary">Summary API</a></li>
            <li><a href="/health">Health Check</a></li>
        </ul>
    </div>
</body>
</html>"""