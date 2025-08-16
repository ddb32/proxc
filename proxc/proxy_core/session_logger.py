"""Session Logger - Detailed logging for proxy validation sessions"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict

from .models import ProxyInfo, ProxyStatus, ValidationStatus


@dataclass
class SessionEvent:
    """Individual session event"""
    timestamp: datetime
    event_type: str  # 'validation_start', 'validation_result', 'rate_limit', 'error', etc.
    proxy_address: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'proxy_address': self.proxy_address,
            'details': self.details
        }


@dataclass
class SessionSummary:
    """Session summary statistics"""
    session_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    total_proxies: int = 0
    valid_proxies: int = 0
    invalid_proxies: int = 0
    error_count: int = 0
    total_duration_seconds: float = 0.0
    average_response_time: Optional[float] = None
    rate_limit_delays: int = 0
    custom_test_url: Optional[str] = None
    via_proxy: Optional[str] = None
    config_settings: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        # Convert datetime objects to ISO strings
        data['start_time'] = self.start_time.isoformat()
        if self.end_time:
            data['end_time'] = self.end_time.isoformat()
        return data


class SessionLogger:
    """Comprehensive session logger for proxy validation operations"""
    
    def __init__(self, log_file_path: str, session_id: Optional[str] = None):
        """Initialize session logger.
        
        Args:
            log_file_path: Path to log file
            session_id: Unique session identifier (auto-generated if None)
        """
        self.log_file_path = Path(log_file_path)
        self.session_id = session_id or f"session_{int(time.time() * 1000)}"
        
        # Create log directory if it doesn't exist
        self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Session state
        self.start_time = datetime.utcnow()
        self.events: List[SessionEvent] = []
        self.summary = SessionSummary(
            session_id=self.session_id,
            start_time=self.start_time
        )
        
        # Performance tracking
        self.validation_times: List[float] = []
        self.proxy_results: Dict[str, Dict[str, Any]] = {}
        
        # Python logger for fallback
        self.logger = logging.getLogger(f"{__name__}.{self.session_id}")
        
        # Log session start
        self.log_event("session_start", details={
            "session_id": self.session_id,
            "log_file": str(self.log_file_path)
        })
    
    def log_event(self, event_type: str, proxy_address: Optional[str] = None, 
                  details: Optional[Dict[str, Any]] = None) -> None:
        """Log a session event.
        
        Args:
            event_type: Type of event
            proxy_address: Associated proxy address (if applicable)
            details: Additional event details
        """
        event = SessionEvent(
            timestamp=datetime.utcnow(),
            event_type=event_type,
            proxy_address=proxy_address,
            details=details or {}
        )
        
        self.events.append(event)
        
        # Update summary statistics based on event type
        self._update_summary_from_event(event)
        
        # Write to file immediately for real-time monitoring
        self._write_event_to_file(event)
    
    def log_validation_start(self, proxy: ProxyInfo, test_url: str, 
                           via_proxy: Optional[str] = None) -> None:
        """Log validation start for a proxy"""
        self.log_event("validation_start", proxy.address, {
            "protocol": proxy.protocol.value,
            "test_url": test_url,
            "via_proxy": via_proxy,
            "proxy_id": proxy.proxy_id
        })
    
    def log_validation_result(self, proxy: ProxyInfo, success: bool, 
                            response_time: Optional[float] = None, 
                            error_message: Optional[str] = None) -> None:
        """Log validation result for a proxy"""
        details = {
            "success": success,
            "status": proxy.status.value,
            "validation_status": proxy.validation_status.value,
            "response_time_ms": response_time,
            "proxy_id": proxy.proxy_id
        }
        
        if error_message:
            details["error"] = error_message
        
        if proxy.geo_location:
            details["country"] = proxy.geo_location.country_code
            details["isp"] = proxy.geo_location.isp
            details["asn"] = proxy.geo_location.asn
        
        self.log_event("validation_result", proxy.address, details)
        
        # Track performance metrics
        if response_time is not None:
            self.validation_times.append(response_time)
        
        # Store detailed proxy results
        self.proxy_results[proxy.address] = {
            "success": success,
            "response_time": response_time,
            "error": error_message,
            "final_status": proxy.status.value,
            "geo_info": proxy.geo_location.to_dict() if proxy.geo_location else None
        }
    
    def log_rate_limit_delay(self, delay_seconds: float) -> None:
        """Log rate limiting delay"""
        self.summary.rate_limit_delays += 1
        self.log_event("rate_limit", details={
            "delay_seconds": delay_seconds,
            "total_delays": self.summary.rate_limit_delays
        })
    
    def log_proxy_chain_setup(self, via_proxy: str) -> None:
        """Log proxy chaining setup"""
        self.summary.via_proxy = via_proxy
        self.log_event("proxy_chain_setup", details={
            "via_proxy": via_proxy
        })
    
    def log_custom_url_test(self, test_url: str) -> None:
        """Log custom URL testing setup"""
        self.summary.custom_test_url = test_url
        self.log_event("custom_url_test", details={
            "test_url": test_url
        })
    
    def log_error(self, error_message: str, proxy_address: Optional[str] = None, 
                  exception: Optional[Exception] = None) -> None:
        """Log an error"""
        details = {"error_message": error_message}
        if exception:
            details["exception_type"] = type(exception).__name__
            details["exception_details"] = str(exception)
        
        self.summary.error_count += 1
        self.log_event("error", proxy_address, details)
    
    def finalize_session(self) -> SessionSummary:
        """Finalize session and write summary"""
        self.summary.end_time = datetime.utcnow()
        self.summary.total_duration_seconds = (
            self.summary.end_time - self.summary.start_time
        ).total_seconds()
        
        # Calculate average response time
        if self.validation_times:
            self.summary.average_response_time = sum(self.validation_times) / len(self.validation_times)
        
        # Log session end
        self.log_event("session_end", details=self.summary.to_dict())
        
        # Write complete session summary
        self._write_session_summary()
        
        return self.summary
    
    def _update_summary_from_event(self, event: SessionEvent) -> None:
        """Update summary statistics from event"""
        if event.event_type == "validation_result":
            success = event.details.get("success", False)
            if success:
                self.summary.valid_proxies += 1
            else:
                self.summary.invalid_proxies += 1
            self.summary.total_proxies = self.summary.valid_proxies + self.summary.invalid_proxies
    
    def _write_event_to_file(self, event: SessionEvent) -> None:
        """Write individual event to log file"""
        try:
            with open(self.log_file_path, 'a', encoding='utf-8') as f:
                # Write as JSON lines format for easy parsing
                json.dump(event.to_dict(), f, ensure_ascii=False)
                f.write('\n')
        except Exception as e:
            self.logger.error(f"Failed to write event to log file: {e}")
    
    def _write_session_summary(self) -> None:
        """Write session summary to separate file"""
        try:
            summary_file = self.log_file_path.with_suffix('.summary.json')
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(self.summary.to_dict(), f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"Failed to write session summary: {e}")
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get current session statistics"""
        current_time = datetime.utcnow()
        elapsed_seconds = (current_time - self.start_time).total_seconds()
        
        stats = {
            "session_id": self.session_id,
            "elapsed_time_seconds": elapsed_seconds,
            "total_events": len(self.events),
            "total_proxies": self.summary.total_proxies,
            "valid_proxies": self.summary.valid_proxies,
            "invalid_proxies": self.summary.invalid_proxies,
            "error_count": self.summary.error_count,
            "rate_limit_delays": self.summary.rate_limit_delays
        }
        
        if self.validation_times:
            stats["average_response_time_ms"] = sum(self.validation_times) / len(self.validation_times)
            stats["fastest_response_ms"] = min(self.validation_times)
            stats["slowest_response_ms"] = max(self.validation_times)
        
        return stats
    
    def export_detailed_results(self, export_file: Optional[str] = None) -> str:
        """Export detailed validation results"""
        if export_file is None:
            export_file = str(self.log_file_path.with_suffix('.results.json'))
        
        detailed_results = {
            "session_summary": self.summary.to_dict(),
            "proxy_results": self.proxy_results,
            "session_stats": self.get_session_stats()
        }
        
        with open(export_file, 'w', encoding='utf-8') as f:
            json.dump(detailed_results, f, indent=2, ensure_ascii=False)
        
        return export_file