"""
Protocol Detection Engine - Active Proxy Protocol Detection

Provides confidence-based proxy protocol detection using actual handshakes
instead of port-based assumptions. Supports SOCKS4, SOCKS5, HTTP, and HTTPS
detection with fallback mechanisms and confidence scoring.
"""

import asyncio
import logging
import socket
import struct
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union
import ipaddress

# Async imports
try:
    import aiohttp
    from aiohttp import ClientSession, ClientTimeout, ClientError
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

# SOCKS support
try:
    from aiohttp_socks import ProxyConnector, ProxyType
    HAS_AIOHTTP_SOCKS = True
except ImportError:
    HAS_AIOHTTP_SOCKS = False

from ..proxy_core.models import ProxyInfo, ProxyProtocol

logger = logging.getLogger(__name__)


# ===============================================================================
# PROTOCOL DETECTION RESULTS
# ===============================================================================

@dataclass
class ProtocolDetectionResult:
    """Result of protocol detection attempt"""
    protocol: ProxyProtocol
    confidence: float  # 0.0 - 1.0
    response_time_ms: float
    method_used: str
    error_message: Optional[str] = None
    raw_response: Optional[bytes] = None
    
    @property
    def confidence_percentage(self) -> int:
        """Get confidence as percentage (0-100)"""
        return int(self.confidence * 100)


@dataclass
class DetectionSummary:
    """Summary of all detection attempts for a proxy"""
    proxy_address: str
    results: List[ProtocolDetectionResult]
    best_match: Optional[ProtocolDetectionResult] = None
    total_time_ms: float = 0.0
    
    def __post_init__(self):
        if self.results and not self.best_match:
            # Find best match by confidence
            self.best_match = max(self.results, key=lambda r: r.confidence)


class DetectionMethod(Enum):
    """Available detection methods"""
    SOCKS5_HANDSHAKE = "socks5_handshake"
    SOCKS4_HANDSHAKE = "socks4_handshake"
    HTTP_CONNECT = "http_connect"
    HTTP_GET = "http_get"
    PORT_INFERENCE = "port_inference"


# ===============================================================================
# PROTOCOL DETECTION ENGINE
# ===============================================================================

class ProxyProtocolDetector:
    """Advanced proxy protocol detection using active handshakes"""
    
    def __init__(self, 
                 connect_timeout: float = 5.0,
                 read_timeout: float = 3.0,
                 enable_debug: bool = False):
        """
        Initialize protocol detector
        
        Args:
            connect_timeout: Connection timeout in seconds
            read_timeout: Read timeout in seconds
            enable_debug: Enable detailed debug logging
        """
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.enable_debug = enable_debug
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Test endpoints for HTTP detection
        self.test_endpoints = [
            "http://httpbin.org/ip",
            "http://icanhazip.com",
            "http://checkip.amazonaws.com"
        ]
        
        # Common port mappings (fallback only)
        self.port_hints = {
            80: (ProxyProtocol.HTTP, 0.3),
            8080: (ProxyProtocol.HTTP, 0.4),
            3128: (ProxyProtocol.HTTP, 0.5),
            8888: (ProxyProtocol.HTTP, 0.3),
            443: (ProxyProtocol.HTTPS, 0.3),
            8443: (ProxyProtocol.HTTPS, 0.4),
            1080: (ProxyProtocol.SOCKS5, 0.6),
            9050: (ProxyProtocol.SOCKS5, 0.7),
            9150: (ProxyProtocol.SOCKS5, 0.7),
            1081: (ProxyProtocol.SOCKS4, 0.6),
            9051: (ProxyProtocol.SOCKS4, 0.6),
        }
    
    async def detect_protocol(self, proxy: ProxyInfo, 
                            methods: Optional[List[DetectionMethod]] = None) -> DetectionSummary:
        """
        Detect proxy protocol using active methods
        
        Args:
            proxy: Proxy to test
            methods: Detection methods to use (default: all available)
            
        Returns:
            DetectionSummary with all results and best match
        """
        if methods is None:
            methods = [
                DetectionMethod.SOCKS5_HANDSHAKE,
                DetectionMethod.HTTP_CONNECT,
                DetectionMethod.SOCKS4_HANDSHAKE,
                DetectionMethod.PORT_INFERENCE
            ]
        
        start_time = time.time()
        results = []
        
        if self.enable_debug:
            self.logger.info(f"🔍 Starting protocol detection for {proxy.address}")
        
        # Try each detection method
        for method in methods:
            try:
                if method == DetectionMethod.SOCKS5_HANDSHAKE:
                    result = await self._test_socks5_handshake(proxy)
                elif method == DetectionMethod.SOCKS4_HANDSHAKE:
                    result = await self._test_socks4_handshake(proxy)
                elif method == DetectionMethod.HTTP_CONNECT:
                    result = await self._test_http_connect(proxy)
                elif method == DetectionMethod.HTTP_GET:
                    result = await self._test_http_get(proxy)
                elif method == DetectionMethod.PORT_INFERENCE:
                    result = self._infer_from_port(proxy)
                else:
                    continue
                
                if result:
                    results.append(result)
                    
                    if self.enable_debug:
                        self.logger.info(f"  ├── {method.value}: {result.protocol.value} "
                                       f"({result.confidence_percentage}% confidence)")
                    
                    # Early exit for high confidence results
                    if result.confidence >= 0.9:
                        if self.enable_debug:
                            self.logger.info(f"  └── High confidence achieved, stopping detection")
                        break
                        
            except Exception as e:
                if self.enable_debug:
                    self.logger.debug(f"  ├── {method.value}: Failed - {e}")
        
        total_time = (time.time() - start_time) * 1000
        summary = DetectionSummary(
            proxy_address=proxy.address,
            results=results,
            total_time_ms=total_time
        )
        
        if self.enable_debug and summary.best_match:
            self.logger.info(f"  └── Best match: {summary.best_match.protocol.value} "
                           f"({summary.best_match.confidence_percentage}% confidence)")
        
        return summary
    
    async def _test_socks5_handshake(self, proxy: ProxyInfo) -> Optional[ProtocolDetectionResult]:
        """Test SOCKS5 protocol using authentication handshake"""
        start_time = time.time()
        
        try:
            # Create socket connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy.host, proxy.port),
                timeout=self.connect_timeout
            )
            
            try:
                # Send SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
                greeting = b'\x05\x01\x00'
                writer.write(greeting)
                await writer.drain()
                
                # Read response: VER=5, METHOD=selected
                response = await asyncio.wait_for(
                    reader.read(2), 
                    timeout=self.read_timeout
                )
                
                response_time = (time.time() - start_time) * 1000
                
                if len(response) == 2 and response[0] == 0x05:
                    # Valid SOCKS5 response
                    if response[1] == 0x00:  # No auth accepted
                        confidence = 0.95
                    elif response[1] == 0xFF:  # No acceptable methods
                        confidence = 0.8  # Still SOCKS5, just auth issue
                    else:
                        confidence = 0.9  # Other auth method
                    
                    return ProtocolDetectionResult(
                        protocol=ProxyProtocol.SOCKS5,
                        confidence=confidence,
                        response_time_ms=response_time,
                        method_used="socks5_handshake",
                        raw_response=response
                    )
                
            finally:
                writer.close()
                await writer.wait_closed()
                
        except asyncio.TimeoutError:
            return ProtocolDetectionResult(
                protocol=ProxyProtocol.SOCKS5,
                confidence=0.0,
                response_time_ms=(time.time() - start_time) * 1000,
                method_used="socks5_handshake",
                error_message="Timeout"
            )
        except Exception as e:
            return ProtocolDetectionResult(
                protocol=ProxyProtocol.SOCKS5,
                confidence=0.0,
                response_time_ms=(time.time() - start_time) * 1000,
                method_used="socks5_handshake",
                error_message=str(e)
            )
        
        return None
    
    async def _test_socks4_handshake(self, proxy: ProxyInfo) -> Optional[ProtocolDetectionResult]:
        """Test SOCKS4 protocol using connect request"""
        start_time = time.time()
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy.host, proxy.port),
                timeout=self.connect_timeout
            )
            
            try:
                # SOCKS4 CONNECT request to 1.1.1.1:80
                # VER=4, CMD=1 (connect), DSTPORT=80, DSTIP=1.1.1.1, USERID=empty, NULL
                request = struct.pack('!BBH4sB', 4, 1, 80, socket.inet_aton('1.1.1.1'), 0)
                writer.write(request)
                await writer.drain()
                
                # Read response: VER=0, REP, DSTPORT, DSTIP
                response = await asyncio.wait_for(
                    reader.read(8),
                    timeout=self.read_timeout
                )
                
                response_time = (time.time() - start_time) * 1000
                
                if len(response) >= 2 and response[0] == 0x00:
                    # Valid SOCKS4 response format
                    rep_code = response[1]
                    if rep_code == 0x5A:  # Request granted
                        confidence = 0.95
                    elif rep_code in [0x5B, 0x5C, 0x5D]:  # Various rejections
                        confidence = 0.85  # Still valid SOCKS4
                    else:
                        confidence = 0.7
                    
                    return ProtocolDetectionResult(
                        protocol=ProxyProtocol.SOCKS4,
                        confidence=confidence,
                        response_time_ms=response_time,
                        method_used="socks4_handshake",
                        raw_response=response
                    )
                    
            finally:
                writer.close()
                await writer.wait_closed()
                
        except Exception as e:
            return ProtocolDetectionResult(
                protocol=ProxyProtocol.SOCKS4,
                confidence=0.0,
                response_time_ms=(time.time() - start_time) * 1000,
                method_used="socks4_handshake",
                error_message=str(e)
            )
        
        return None
    
    async def _test_http_connect(self, proxy: ProxyInfo) -> Optional[ProtocolDetectionResult]:
        """Test HTTP proxy using CONNECT method"""
        start_time = time.time()
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy.host, proxy.port),
                timeout=self.connect_timeout
            )
            
            try:
                # Send HTTP CONNECT request
                connect_request = (
                    f"CONNECT httpbin.org:80 HTTP/1.1\r\n"
                    f"Host: httpbin.org:80\r\n"
                    f"Proxy-Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode()
                
                writer.write(connect_request)
                await writer.drain()
                
                # Read response line
                response_line = await asyncio.wait_for(
                    reader.readline(),
                    timeout=self.read_timeout
                )
                
                response_time = (time.time() - start_time) * 1000
                
                if response_line.startswith(b'HTTP/'):
                    # Valid HTTP response
                    if b'200' in response_line:
                        confidence = 0.9  # Connection established
                    elif b'407' in response_line:
                        confidence = 0.85  # Proxy auth required
                    elif any(code in response_line for code in [b'400', b'403', b'404', b'500']):
                        confidence = 0.8  # HTTP server, but error
                    else:
                        confidence = 0.7  # HTTP-like response
                    
                    return ProtocolDetectionResult(
                        protocol=ProxyProtocol.HTTP,
                        confidence=confidence,
                        response_time_ms=response_time,
                        method_used="http_connect",
                        raw_response=response_line
                    )
                    
            finally:
                writer.close()
                await writer.wait_closed()
                
        except Exception as e:
            return ProtocolDetectionResult(
                protocol=ProxyProtocol.HTTP,
                confidence=0.0,
                response_time_ms=(time.time() - start_time) * 1000,
                method_used="http_connect",
                error_message=str(e)
            )
        
        return None
    
    async def _test_http_get(self, proxy: ProxyInfo) -> Optional[ProtocolDetectionResult]:
        """Test HTTP proxy using GET request with aiohttp"""
        if not HAS_AIOHTTP:
            return None
        
        start_time = time.time()
        
        try:
            proxy_url = f"http://{proxy.host}:{proxy.port}"
            timeout = aiohttp.ClientTimeout(
                connect=self.connect_timeout,
                total=self.connect_timeout + self.read_timeout
            )
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    "http://httpbin.org/ip",
                    proxy=proxy_url
                ) as response:
                    response_time = (time.time() - start_time) * 1000
                    
                    if response.status == 200:
                        content = await response.text()
                        if '"origin"' in content:  # httpbin.org response format
                            confidence = 0.95
                        else:
                            confidence = 0.8
                    elif response.status == 407:
                        confidence = 0.85  # Auth required
                    elif 400 <= response.status < 500:
                        confidence = 0.7  # Client error but HTTP
                    else:
                        confidence = 0.6  # Server error but HTTP
                    
                    return ProtocolDetectionResult(
                        protocol=ProxyProtocol.HTTP,
                        confidence=confidence,
                        response_time_ms=response_time,
                        method_used="http_get"
                    )
                    
        except Exception as e:
            return ProtocolDetectionResult(
                protocol=ProxyProtocol.HTTP,
                confidence=0.0,
                response_time_ms=(time.time() - start_time) * 1000,
                method_used="http_get",
                error_message=str(e)
            )
        
        return None
    
    def _infer_from_port(self, proxy: ProxyInfo) -> Optional[ProtocolDetectionResult]:
        """Fallback: Infer protocol from port (low confidence)"""
        port_hint = self.port_hints.get(proxy.port)
        
        if port_hint:
            protocol, confidence = port_hint
            return ProtocolDetectionResult(
                protocol=protocol,
                confidence=confidence,
                response_time_ms=0.0,
                method_used="port_inference"
            )
        
        # Default to HTTP with very low confidence
        return ProtocolDetectionResult(
            protocol=ProxyProtocol.HTTP,
            confidence=0.1,
            response_time_ms=0.0,
            method_used="port_inference"
        )


# ===============================================================================
# CONVENIENCE FUNCTIONS
# ===============================================================================

async def detect_proxy_protocol(proxy: ProxyInfo, 
                               enable_debug: bool = False) -> DetectionSummary:
    """Convenience function to detect a single proxy's protocol"""
    detector = ProxyProtocolDetector(enable_debug=enable_debug)
    return await detector.detect_protocol(proxy)


async def detect_batch_protocols(proxies: List[ProxyInfo],
                                enable_debug: bool = False,
                                max_concurrent: int = 50) -> Dict[str, DetectionSummary]:
    """Detect protocols for multiple proxies concurrently"""
    detector = ProxyProtocolDetector(enable_debug=enable_debug)
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def detect_single(proxy: ProxyInfo) -> Tuple[str, DetectionSummary]:
        async with semaphore:
            summary = await detector.detect_protocol(proxy)
            return proxy.address, summary
    
    tasks = [detect_single(proxy) for proxy in proxies]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results
    detection_map = {}
    for result in results:
        if isinstance(result, Exception):
            logger.error(f"Protocol detection failed: {result}")
            continue
        
        address, summary = result
        detection_map[address] = summary
    
    return detection_map