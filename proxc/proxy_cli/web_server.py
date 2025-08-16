"""Proxy CLI Web Server - Enhanced HTTP/WebSocket Server for Real-time Browser Interface"""

import json
import socket
import threading
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse, parse_qs
import hashlib
import base64
import struct

from .cli_base import get_cli_logger
from .cli_exceptions import WebInterfaceError, CLIErrorHandler
from .web_routes import WebRouter


class ProxyWebHandler(BaseHTTPRequestHandler):
    """Enhanced HTTP/WebSocket request handler with real-time capabilities"""
    
    def __init__(self, request, client_address, server, router, websocket_manager=None):
        self.router = router
        self.websocket_manager = websocket_manager
        self.logger = get_cli_logger("web_handler")
        self.error_handler = CLIErrorHandler(self.logger)
        super().__init__(request, client_address, server)
    
    def do_GET(self):
        """Handle GET requests using router or WebSocket upgrades"""
        try:
            # Check for WebSocket upgrade
            if self._is_websocket_upgrade():
                self._handle_websocket_upgrade()
                return
                
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            query_params = parse_qs(parsed_url.query)
            
            # Route the request
            headers = dict(self.headers)
            status_code, content_type, response_data = self.router.route(path, 'GET', query_params, headers)
            
            # Send response
            self.send_response(status_code)
            self.send_header('Content-Type', content_type)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(response_data)
            
        except Exception as e:
            web_error = WebInterfaceError(
                f"Error handling GET request to {self.path}",
                endpoint=self.path,
                method="GET"
            )
            self.error_handler.handle_error(web_error)
            self._send_500()
    
    def do_POST(self):
        """Handle POST requests using router"""
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            query_params = parse_qs(parsed_url.query)
            
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None
            
            # Route the request
            headers = dict(self.headers)
            status_code, content_type, response_data = self.router.route(path, 'POST', query_params, headers, body)
            
            # Send response
            self.send_response(status_code)
            self.send_header('Content-Type', content_type)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(response_data)
            
        except Exception as e:
            web_error = WebInterfaceError(
                f"Error handling POST request to {self.path}",
                endpoint=self.path,
                method="POST"
            )
            self.error_handler.handle_error(web_error)
            self._send_500()
    
    def do_PUT(self):
        """Handle PUT requests using router"""
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            query_params = parse_qs(parsed_url.query)
            
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None
            
            # Route the request
            headers = dict(self.headers)
            status_code, content_type, response_data = self.router.route(path, 'PUT', query_params, headers, body)
            
            # Send response
            self.send_response(status_code)
            self.send_header('Content-Type', content_type)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(response_data)
            
        except Exception as e:
            web_error = WebInterfaceError(
                f"Error handling PUT request to {self.path}",
                endpoint=self.path,
                method="PUT"
            )
            self.error_handler.handle_error(web_error)
            self._send_500()
    
    def do_DELETE(self):
        """Handle DELETE requests using router"""
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            query_params = parse_qs(parsed_url.query)
            
            # Route the request
            headers = dict(self.headers)
            status_code, content_type, response_data = self.router.route(path, 'DELETE', query_params, headers)
            
            # Send response
            self.send_response(status_code)
            self.send_header('Content-Type', content_type)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(response_data)
            
        except Exception as e:
            web_error = WebInterfaceError(
                f"Error handling DELETE request to {self.path}",
                endpoint=self.path,
                method="DELETE"
            )
            self.error_handler.handle_error(web_error)
            self._send_500()
    
    def _send_500(self):
        """Send 500 Internal Server Error"""
        try:
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            error_response = b'{"error": "Internal Server Error", "message": "An unexpected error occurred"}'
            self.wfile.write(error_response)
        except:
            pass  # Prevent recursive errors
    
    def log_message(self, format, *args):
        """Override log message to use our logger"""
        if self.logger:
            self.logger.debug(format % args)
    
    def _is_websocket_upgrade(self) -> bool:
        """Check if this is a WebSocket upgrade request"""
        return (self.headers.get('Upgrade', '').lower() == 'websocket' and
                self.headers.get('Connection', '').lower() == 'upgrade' and
                'Sec-WebSocket-Key' in self.headers)
    
    def _handle_websocket_upgrade(self):
        """Handle WebSocket upgrade handshake"""
        try:
            websocket_key = self.headers.get('Sec-WebSocket-Key')
            if not websocket_key:
                self.send_response(400)
                self.end_headers()
                return
            
            # Generate WebSocket accept key
            magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
            accept_key = base64.b64encode(
                hashlib.sha1((websocket_key + magic_string).encode()).digest()
            ).decode()
            
            # Send upgrade response
            self.send_response(101, "Switching Protocols")
            self.send_header('Upgrade', 'websocket')
            self.send_header('Connection', 'Upgrade')
            self.send_header('Sec-WebSocket-Accept', accept_key)
            self.end_headers()
            
            # Register WebSocket connection
            if self.websocket_manager:
                self.websocket_manager.add_connection(self.wfile, self.rfile)
                
        except Exception as e:
            self.logger.error(f"WebSocket upgrade error: {e}")
            self.send_response(500)
            self.end_headers()


class WebSocketManager:
    """Manager for WebSocket connections and real-time updates"""
    
    def __init__(self):
        self.connections = []
        self.logger = get_cli_logger("websocket_manager")
        self._lock = threading.Lock()
    
    def add_connection(self, write_file, read_file):
        """Add a new WebSocket connection"""
        with self._lock:
            connection = {
                'wfile': write_file,
                'rfile': read_file,
                'connected': True,
                'last_ping': time.time()
            }
            self.connections.append(connection)
            self.logger.info(f"WebSocket connection added. Total: {len(self.connections)}")
    
    def remove_connection(self, connection):
        """Remove a WebSocket connection"""
        with self._lock:
            if connection in self.connections:
                self.connections.remove(connection)
                self.logger.info(f"WebSocket connection removed. Total: {len(self.connections)}")
    
    def broadcast_message(self, message: Dict[str, Any]):
        """Broadcast message to all connected WebSocket clients"""
        if not self.connections:
            return
            
        message_json = json.dumps(message)
        message_bytes = self._create_websocket_frame(message_json.encode('utf-8'))
        
        dead_connections = []
        with self._lock:
            for connection in self.connections:
                try:
                    connection['wfile'].write(message_bytes)
                    connection['wfile'].flush()
                except Exception as e:
                    self.logger.warning(f"Failed to send message to WebSocket client: {e}")
                    dead_connections.append(connection)
        
        # Remove dead connections
        for dead_conn in dead_connections:
            self.remove_connection(dead_conn)
    
    def _create_websocket_frame(self, payload: bytes) -> bytes:
        """Create a WebSocket frame for text messages"""
        payload_length = len(payload)
        
        # Frame format: FIN(1) + RSV(3) + Opcode(4) + MASK(1) + Payload Length(7/16/64) + Payload
        frame = bytearray()
        frame.append(0x81)  # FIN=1, Opcode=1 (text frame)
        
        if payload_length < 126:
            frame.append(payload_length)
        elif payload_length < 65536:
            frame.append(126)
            frame.extend(struct.pack('!H', payload_length))
        else:
            frame.append(127)
            frame.extend(struct.pack('!Q', payload_length))
        
        frame.extend(payload)
        return bytes(frame)
    
    def get_connection_count(self) -> int:
        """Get number of active connections"""
        return len(self.connections)


class ProxyWebServer:
    """Enhanced web server with real-time monitoring capabilities"""
    
    def __init__(self, data_handler, port: Optional[int] = None):
        self.data_handler = data_handler
        self.port = port or 8080
        self.server = None
        self.server_thread = None
        self.is_running = False
        self.logger = get_cli_logger("web_server")
        self.error_handler = CLIErrorHandler(self.logger)
        
        # Create router and WebSocket manager
        self.router = WebRouter(data_handler)
        self.websocket_manager = WebSocketManager()
        
        # Real-time monitoring
        self._monitoring_thread = None
        self._monitoring_active = False
    
    def find_available_port(self, start_port: int = 8080) -> int:
        """Find an available port starting from the given port"""
        for port in range(start_port, start_port + 100):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('127.0.0.1', port))
                    return port
            except OSError:
                continue
        
        # If no port found in range, use a random one
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]
    
    def start(self, open_browser: bool = True) -> str:
        """Start the web server"""
        try:
            # Find available port
            self.port = self.find_available_port(self.port)
            
            # Create handler factory
            def handler_factory(*args):
                return ProxyWebHandler(*args, self.router, self.websocket_manager)
            
            # Create server
            self.server = HTTPServer(('127.0.0.1', self.port), handler_factory)
            
            # Start server in thread
            self.server_thread = threading.Thread(
                target=self.server.serve_forever, 
                daemon=True,
                name="ProxyWebServer"
            )
            self.server_thread.start()
            self.is_running = True
            
            # Start real-time monitoring
            self._start_monitoring()
            
            url = f"http://127.0.0.1:{self.port}"
            self.logger.info(f"Web server started on {url}")
            
            # Open browser
            if open_browser:
                try:
                    # Small delay to ensure server is ready
                    time.sleep(0.5)
                    webbrowser.open(url)
                    self.logger.info("Opened browser automatically")
                except Exception as e:
                    self.logger.warning(f"Could not open browser automatically: {e}")
            
            return url
            
        except Exception as e:
            web_error = WebInterfaceError(
                f"Failed to start web server on port {self.port}",
                port=self.port
            )
            self.error_handler.handle_error(web_error)
            raise
    
    def stop(self):
        """Stop the web server"""
        try:
            if self.server:
                self.logger.info("Stopping web server...")
                self.server.shutdown()
                self.server.server_close()
                
            if self.server_thread and self.server_thread.is_alive():
                self.server_thread.join(timeout=5)
            
            # Stop monitoring
            self._stop_monitoring()
                
            self.is_running = False
            self.logger.info("Web server stopped")
            
        except Exception as e:
            web_error = WebInterfaceError(
                "Error stopping web server",
                port=self.port
            )
            self.error_handler.handle_error(web_error)
    
    def get_status(self) -> dict:
        """Get server status information"""
        return {
            'is_running': self.is_running,
            'port': self.port,
            'url': f"http://127.0.0.1:{self.port}" if self.is_running else None,
            'thread_alive': self.server_thread.is_alive() if self.server_thread else False,
            'proxy_count': len(self.data_handler.proxies) if self.data_handler else 0
        }
    
    def add_route(self, path: str, handler, methods=None):
        """Add a custom route to the server"""
        self.router.add_route(path, handler, methods)
        self.logger.debug(f"Added custom route: {path}")
    
    def _start_monitoring(self):
        """Start real-time monitoring thread"""
        if not self._monitoring_active:
            self._monitoring_active = True
            self._monitoring_thread = threading.Thread(
                target=self._monitoring_loop,
                daemon=True,
                name="ProxyMonitoring"
            )
            self._monitoring_thread.start()
            self.logger.info("Real-time monitoring started")
    
    def _stop_monitoring(self):
        """Stop real-time monitoring"""
        self._monitoring_active = False
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            self._monitoring_thread.join(timeout=3)
        self.logger.info("Real-time monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop that broadcasts updates"""
        last_update = {}
        
        while self._monitoring_active and self.is_running:
            try:
                # Get current summary data
                current_summary = self.data_handler.get_summary_json()
                
                # Check if data has changed significantly
                if self._should_broadcast_update(current_summary, last_update):
                    # Broadcast update to all connected clients
                    update_message = {
                        'type': 'summary_update',
                        'timestamp': current_summary.get('timestamp'),
                        'data': current_summary
                    }
                    
                    self.websocket_manager.broadcast_message(update_message)
                    last_update = current_summary.copy()
                    
                    self.logger.debug(f"Broadcasted update to {self.websocket_manager.get_connection_count()} clients")
                
                # Sleep before next update
                time.sleep(5)  # Update every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)  # Longer sleep on error
    
    def _should_broadcast_update(self, current: Dict, previous: Dict) -> bool:
        """Determine if an update should be broadcast"""
        if not previous:
            return True
            
        # Check key metrics for changes
        key_fields = ['total_proxies', 'active_proxies', 'success_rate', 'avg_response_time']
        
        for field in key_fields:
            if current.get(field) != previous.get(field):
                return True
        
        # Check if enough time has passed (force update every 30 seconds)
        try:
            current_time = time.time()
            last_broadcast = previous.get('_last_broadcast', 0)
            if current_time - last_broadcast > 30:
                current['_last_broadcast'] = current_time
                return True
        except:
            pass
        
        return False
    
    def broadcast_proxy_update(self, proxy_data: Dict):
        """Manually broadcast a proxy update"""
        update_message = {
            'type': 'proxy_update',
            'timestamp': time.time(),
            'data': proxy_data
        }
        self.websocket_manager.broadcast_message(update_message)


# Convenience function for backward compatibility
def start_web_server(data_handler, port: Optional[int] = None, open_browser: bool = True) -> ProxyWebServer:
    """Start web server with given data handler"""
    server = ProxyWebServer(data_handler, port)
    server.start(open_browser)
    return server