"""Security Module - Professional IP rotation and anti-detection systems"""

from .ip_rotation import (
    IPRotationManager,
    RotationConfig,
    RotationStrategy,
    ProxyHealthStatus,
    create_ip_rotation_manager
)

from .anti_detection import (
    AntiDetectionManager,
    AntiDetectionConfig,
    DetectionVector,
    UserAgentProfile,
    create_anti_detection_manager
)

__all__ = [
    'IPRotationManager',
    'RotationConfig', 
    'RotationStrategy',
    'ProxyHealthStatus',
    'create_ip_rotation_manager',
    'AntiDetectionManager',
    'AntiDetectionConfig',
    'DetectionVector',
    'UserAgentProfile',
    'create_anti_detection_manager',
    'SecurityManager'
]


class SecurityManager:
    """Integrated security manager combining IP rotation and anti-detection"""
    
    def __init__(self, enable_ip_rotation: bool = True, enable_anti_detection: bool = True):
        self.ip_rotation = None
        self.anti_detection = None
        
        if enable_ip_rotation:
            self.ip_rotation = create_ip_rotation_manager()
        
        if enable_anti_detection:
            self.anti_detection = create_anti_detection_manager()
    
    async def start(self):
        """Start all security systems"""
        if self.ip_rotation:
            await self.ip_rotation.start()
    
    async def stop(self):
        """Stop all security systems"""
        if self.ip_rotation:
            await self.ip_rotation.stop()
    
    def get_next_proxy(self, **kwargs):
        """Get next proxy with rotation"""
        if self.ip_rotation:
            return self.ip_rotation.get_next_proxy(**kwargs)
        return None
    
    def get_stealth_headers(self, target_url: str, proxy):
        """Get stealth headers"""
        if self.anti_detection:
            return self.anti_detection.get_stealth_headers(target_url, proxy)
        return {}
    
    async def apply_request_timing(self, target_url: str):
        """Apply request timing delays"""
        if self.anti_detection:
            return await self.anti_detection.apply_request_timing(target_url)
        return 0.0
    
    def record_proxy_result(self, proxy_address: str, success: bool, **kwargs):
        """Record proxy result for health tracking"""
        if self.ip_rotation:
            self.ip_rotation.record_connection_result(proxy_address, success, **kwargs)
    
    def get_security_report(self):
        """Get comprehensive security report"""
        report = {
            'ip_rotation': None,
            'anti_detection': None
        }
        
        if self.ip_rotation:
            report['ip_rotation'] = self.ip_rotation.get_rotation_stats()
        
        if self.anti_detection:
            report['anti_detection'] = self.anti_detection.get_anti_detection_report()
        
        return report