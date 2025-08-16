"""Proxy CLI Monitor - Real-Time Monitoring Dashboard"""

import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

# Use centralized import management
from .cli_imports import get_cli_imports, print_error, print_success
from .cli_base import CLIFormatterMixin

# Initialize imports
cli_imports = get_cli_imports()
HAS_RICH = cli_imports.has_rich

# Rich imports
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.align import Align
    from rich.layout import Layout
    from rich.live import Live
    from rich.columns import Columns
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
except ImportError:
    Console = Panel = Table = Text = Align = Layout = Live = Columns = Progress = SpinnerColumn = BarColumn = TextColumn = None

# Import our models (using exact names from previous files)
from ..proxy_core.models import ProxyInfo, ProxyStatus, ThreatLevel, AnonymityLevel, ProxyProtocol
from ..proxy_core.config import ConfigManager
from ..proxy_core.database import DatabaseManager
from ..proxy_core.metrics import MetricsCollector, SystemHealth


# ===============================================================================
# MONITORING DATA CLASSES
# ===============================================================================

class MonitoringStats:
    """Real-time monitoring statistics"""
    
    def __init__(self):
        self.start_time = datetime.utcnow()
        self.last_update = datetime.utcnow()
        
        # Proxy counts
        self.total_proxies = 0
        self.active_proxies = 0
        self.valid_proxies = 0
        self.failed_proxies = 0
        
        # Performance metrics
        self.avg_response_time = 0.0
        self.success_rate = 0.0
        self.validation_rate = 0.0  # Validations per minute
        
        # Geographic distribution
        self.country_distribution = defaultdict(int)
        self.threat_distribution = defaultdict(int)
        self.protocol_distribution = defaultdict(int)
        
        # Historical data (last 60 data points)
        self.response_time_history = deque(maxlen=60)
        self.success_rate_history = deque(maxlen=60)
        self.proxy_count_history = deque(maxlen=60)
        
        # Activity counters
        self.validations_last_minute = 0
        self.discoveries_last_minute = 0
        self.errors_last_minute = 0
    
    def update_from_proxies(self, proxies: List[ProxyInfo]):
        """Update stats from proxy list"""
        self.last_update = datetime.utcnow()
        self.total_proxies = len(proxies)
        
        # Reset counters
        self.active_proxies = 0
        self.valid_proxies = 0
        self.failed_proxies = 0
        self.country_distribution.clear()
        self.threat_distribution.clear()
        self.protocol_distribution.clear()
        
        response_times = []
        success_rates = []
        
        for proxy in proxies:
            # Status counts
            if proxy.status == ProxyStatus.ACTIVE:
                self.active_proxies += 1
            elif proxy.status == ProxyStatus.FAILED:
                self.failed_proxies += 1
            
            if proxy.validation_status.value == 'valid':
                self.valid_proxies += 1
            
            # Geographic distribution
            if proxy.geo_location and proxy.geo_location.country_code:
                self.country_distribution[proxy.geo_location.country_code] += 1
            
            # Threat distribution
            self.threat_distribution[proxy.threat_level.value] += 1
            
            # Protocol distribution
            self.protocol_distribution[proxy.protocol.value] += 1
            
            # Performance data
            if proxy.metrics.response_time is not None:
                response_times.append(proxy.metrics.response_time)
            if proxy.metrics.success_rate is not None:
                success_rates.append(proxy.metrics.success_rate)
        
        # Calculate averages
        self.avg_response_time = sum(response_times) / len(response_times) if response_times else 0.0
        self.success_rate = (self.valid_proxies / self.total_proxies * 100) if self.total_proxies > 0 else 0.0
        
        # Add to history
        self.response_time_history.append(self.avg_response_time)
        self.success_rate_history.append(self.success_rate)
        self.proxy_count_history.append(self.total_proxies)
    
    @property
    def uptime_minutes(self) -> float:
        """Get monitoring uptime in minutes"""
        delta = datetime.utcnow() - self.start_time
        return delta.total_seconds() / 60.0


# ===============================================================================
# RICH DASHBOARD COMPONENTS
# ===============================================================================

class DashboardRenderer:
    """Renders Rich dashboard components"""
    
    def __init__(self, console: Console):
        self.console = console
    
    def render_header(self, stats: MonitoringStats) -> Panel:
        """Render dashboard header"""
        uptime = f"{stats.uptime_minutes:.0f}m"
        last_update = stats.last_update.strftime("%H:%M:%S")
        
        header_text = Text()
        header_text.append("🔍 ProxC ", style="bold cyan")
        header_text.append("Real-Time Monitor ", style="bold white")
        header_text.append(f"| Uptime: {uptime} ", style="dim")
        header_text.append(f"| Updated: {last_update}", style="dim")
        
        return Panel(
            Align.center(header_text),
            style="blue",
            padding=(0, 1)
        )
    
    def render_summary_table(self, stats: MonitoringStats) -> Table:
        """Render system summary table"""
        table = Table(title="System Summary", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green", justify="right")
        table.add_column("Status", style="yellow", justify="center")
        
        # Status indicators
        status_good = "🟢"
        status_warning = "🟡"
        status_error = "🔴"
        
        # Add rows with status indicators
        table.add_row(
            "Total Proxies", 
            str(stats.total_proxies),
            status_good if stats.total_proxies > 0 else status_error
        )
        
        table.add_row(
            "Active Proxies", 
            str(stats.active_proxies),
            status_good if stats.active_proxies > 0 else status_warning
        )
        
        table.add_row(
            "Valid Proxies", 
            str(stats.valid_proxies),
            status_good if stats.valid_proxies > 0 else status_warning
        )
        
        table.add_row(
            "Success Rate", 
            f"{stats.success_rate:.1f}%",
            status_good if stats.success_rate > 70 else status_warning if stats.success_rate > 40 else status_error
        )
        
        table.add_row(
            "Avg Response", 
            f"{stats.avg_response_time:.0f}ms",
            status_good if stats.avg_response_time < 1000 else status_warning if stats.avg_response_time < 3000 else status_error
        )
        
        table.add_row(
            "Failed Proxies", 
            str(stats.failed_proxies),
            status_good if stats.failed_proxies == 0 else status_warning
        )
        
        return table
    
    def render_distribution_table(self, stats: MonitoringStats) -> Table:
        """Render distribution tables"""
        table = Table(title="Distribution Analysis", show_header=True, header_style="bold blue")
        table.add_column("Category", style="cyan")
        table.add_column("Top Items", style="white")
        
        # Country distribution (top 5)
        top_countries = sorted(stats.country_distribution.items(), key=lambda x: x[1], reverse=True)[:5]
        countries_text = ", ".join([f"{country}({count})" for country, count in top_countries])
        table.add_row("Countries", countries_text or "No data")
        
        # Protocol distribution
        protocols_text = ", ".join([f"{proto}({count})" for proto, count in stats.protocol_distribution.items()])
        table.add_row("Protocols", protocols_text or "No data")
        
        # Threat distribution
        threats_text = ", ".join([f"{threat}({count})" for threat, count in stats.threat_distribution.items()])
        table.add_row("Threat Levels", threats_text or "No data")
        
        return table
    
    def render_performance_chart(self, stats: MonitoringStats) -> Panel:
        """Render simple ASCII performance chart"""
        if not stats.response_time_history:
            return Panel("No performance data available", title="Performance Trend")
        
        # Simple ASCII chart for response times
        history = list(stats.response_time_history)[-20:]  # Last 20 points
        if not history:
            return Panel("No data", title="Response Time Trend (20min)")
        
        max_val = max(history) if history else 1
        min_val = min(history) if history else 0
        
        # Normalize values to 0-10 range for ASCII bars
        if max_val > min_val:
            normalized = [int((val - min_val) / (max_val - min_val) * 10) for val in history]
        else:
            normalized = [5] * len(history)
        
        # Create ASCII chart
        chart_lines = []
        for i in range(10, -1, -1):
            line = ""
            for val in normalized:
                if val >= i:
                    line += "█"
                else:
                    line += " "
            chart_lines.append(line)
        
        chart_text = "\n".join(chart_lines)
        chart_text += f"\nRange: {min_val:.0f}ms - {max_val:.0f}ms | Latest: {history[-1]:.0f}ms"
        
        return Panel(
            chart_text,
            title="Response Time Trend (20 points)",
            style="green"
        )
    
    def render_activity_panel(self, stats: MonitoringStats) -> Panel:
        """Render recent activity panel"""
        activity_text = f"""
Recent Activity (last minute):
  🔍 Discoveries: {stats.discoveries_last_minute}
  ✅ Validations: {stats.validations_last_minute}  
  ❌ Errors: {stats.errors_last_minute}
  📊 Rate: {stats.validation_rate:.1f} checks/min
        """
        
        return Panel(
            activity_text.strip(),
            title="Activity Monitor",
            style="yellow"
        )


# ===============================================================================
# MAIN PROXY MONITOR CLASS
# ===============================================================================

class ProxyMonitor:
    """Real-time proxy monitoring system"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.db = DatabaseManager(self.config)
        self.metrics = MetricsCollector()
        
        # Rich components
        self.console = Console() if HAS_RICH else None
        self.renderer = DashboardRenderer(self.console) if self.console else None
        
        # Monitoring state
        self.is_running = False
        self.refresh_interval = 2.0  # seconds
        self.stats = MonitoringStats()
        
        # Threading
        self._monitor_thread = None
        self._stop_event = threading.Event()
    
    def start_dashboard(self, refresh_interval: float = 2.0):
        """Start interactive dashboard monitoring"""
        if not HAS_RICH:
            print("❌ Rich library required for dashboard. Falling back to simple monitoring...")
            self.start_simple_monitor()
            return
        
        self.refresh_interval = refresh_interval
        self.is_running = True
        
        try:
            with Live(self._create_dashboard_layout(), refresh_per_second=1/refresh_interval, console=self.console) as live:
                self.logger.info("Dashboard monitoring started")
                
                while self.is_running:
                    try:
                        # Update stats
                        self._update_stats()
                        
                        # Update dashboard
                        live.update(self._create_dashboard_layout())
                        
                        # Sleep
                        time.sleep(refresh_interval)
                        
                    except KeyboardInterrupt:
                        break
                    except Exception as e:
                        self.logger.error(f"Dashboard update error: {e}")
                        time.sleep(refresh_interval)
        
        except KeyboardInterrupt:
            pass
        finally:
            self.is_running = False
            self.logger.info("Dashboard monitoring stopped")
    
    def start_background_monitor(self, refresh_interval: float = 10.0):
        """Start background monitoring without dashboard"""
        self.refresh_interval = refresh_interval
        self.is_running = True
        
        self._monitor_thread = threading.Thread(target=self._background_monitor_loop)
        self._monitor_thread.daemon = True
        self._monitor_thread.start()
        
        self.logger.info(f"Background monitoring started (refresh: {refresh_interval}s)")
    
    def start_simple_monitor(self, refresh_interval: float = 5.0):
        """Start simple text-based monitoring"""
        self.refresh_interval = refresh_interval
        self.is_running = True
        
        try:
            print("🔍 ProxC - Simple Monitor")
            print("Press Ctrl+C to stop")
            print("-" * 50)
            
            while self.is_running:
                try:
                    # Update stats
                    self._update_stats()
                    
                    # Print simple status
                    print(f"\r[{datetime.now().strftime('%H:%M:%S')}] "
                          f"Total: {self.stats.total_proxies} | "
                          f"Active: {self.stats.active_proxies} | "
                          f"Valid: {self.stats.valid_proxies} | "
                          f"Success: {self.stats.success_rate:.1f}% | "
                          f"Response: {self.stats.avg_response_time:.0f}ms", end="")
                    
                    time.sleep(refresh_interval)
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"\nMonitor error: {e}")
                    time.sleep(refresh_interval)
        
        except KeyboardInterrupt:
            pass
        finally:
            self.is_running = False
            print("\n👋 Monitoring stopped")
    
    def stop_monitor(self):
        """Stop monitoring"""
        self.is_running = False
        self._stop_event.set()
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5.0)
        
        self.logger.info("Monitor stopped")
    
    def _background_monitor_loop(self):
        """Background monitoring loop"""
        while self.is_running and not self._stop_event.is_set():
            try:
                self._update_stats()
                
                # Log periodic status
                if int(time.time()) % 60 == 0:  # Every minute
                    self.logger.info(f"Monitor status: {self.stats.active_proxies}/{self.stats.total_proxies} active proxies")
                
                self._stop_event.wait(self.refresh_interval)
                
            except Exception as e:
                self.logger.error(f"Background monitor error: {e}")
                self._stop_event.wait(self.refresh_interval)
    
    def _update_stats(self):
        """Update monitoring statistics"""
        try:
            # Get current proxies
            proxies = self.db.get_proxies()
            
            # Update stats
            self.stats.update_from_proxies(proxies)
            
            # Update activity counters (simplified)
            self.stats.validations_last_minute = len([p for p in proxies if p.metrics.last_checked and 
                                                     p.metrics.last_checked > datetime.utcnow() - timedelta(minutes=1)])
            
        except Exception as e:
            self.logger.error(f"Stats update failed: {e}")
    
    def _create_dashboard_layout(self) -> Layout:
        """Create Rich dashboard layout"""
        if not self.renderer:
            return Layout()
        
        # Create main layout
        layout = Layout()
        
        # Split into sections
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=8)
        )
        
        # Split main section
        layout["main"].split_row(
            Layout(name="left"),
            Layout(name="right")
        )
        
        # Split footer section
        layout["footer"].split_row(
            Layout(name="performance"),
            Layout(name="activity")
        )
        
        # Populate sections
        layout["header"].update(self.renderer.render_header(self.stats))
        layout["left"].update(self.renderer.render_summary_table(self.stats))
        layout["right"].update(self.renderer.render_distribution_table(self.stats))
        layout["performance"].update(self.renderer.render_performance_chart(self.stats))
        layout["activity"].update(self.renderer.render_activity_panel(self.stats))
        
        return layout
    
    def get_current_stats(self) -> Dict[str, Any]:
        """Get current monitoring statistics"""
        return {
            'total_proxies': self.stats.total_proxies,
            'active_proxies': self.stats.active_proxies,
            'valid_proxies': self.stats.valid_proxies,
            'failed_proxies': self.stats.failed_proxies,
            'success_rate': self.stats.success_rate,
            'avg_response_time': self.stats.avg_response_time,
            'uptime_minutes': self.stats.uptime_minutes,
            'last_update': self.stats.last_update.isoformat(),
            'country_distribution': dict(self.stats.country_distribution),
            'protocol_distribution': dict(self.stats.protocol_distribution),
            'threat_distribution': dict(self.stats.threat_distribution)
        }
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate monitoring report"""
        self._update_stats()
        
        report = {
            'report_timestamp': datetime.utcnow().isoformat(),
            'monitoring_duration_minutes': self.stats.uptime_minutes,
            'current_stats': self.get_current_stats(),
            'performance_history': {
                'response_times': list(self.stats.response_time_history),
                'success_rates': list(self.stats.success_rate_history),
                'proxy_counts': list(self.stats.proxy_count_history)
            },
            'activity_summary': {
                'validations_per_minute': self.stats.validation_rate,
                'discoveries_last_minute': self.stats.discoveries_last_minute,
                'errors_last_minute': self.stats.errors_last_minute
            }
        }
        
        return report


# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def create_proxy_monitor(config: Optional[ConfigManager] = None) -> ProxyMonitor:
    """Create proxy monitor instance"""
    return ProxyMonitor(config)


def start_dashboard_monitoring(config: Optional[ConfigManager] = None, 
                             refresh_interval: float = 2.0):
    """Start dashboard monitoring (convenience function)"""
    monitor = create_proxy_monitor(config)
    
    try:
        monitor.start_dashboard(refresh_interval)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop_monitor()


def start_background_monitoring(config: Optional[ConfigManager] = None,
                              refresh_interval: float = 10.0) -> ProxyMonitor:
    """Start background monitoring and return monitor instance"""
    monitor = create_proxy_monitor(config)
    monitor.start_background_monitor(refresh_interval)
    return monitor


def print_simple_status(config: Optional[ConfigManager] = None):
    """Print simple status without Rich"""
    try:
        db = DatabaseManager(config or ConfigManager())
        stats = db.get_statistics()
        
        print("📊 ProxC Status:")
        print(f"  Total proxies: {stats.get('total_proxies', 0)}")
        print(f"  Active proxies: {stats.get('active_proxies', 0)}")
        print(f"  Valid proxies: {stats.get('valid_proxies', 0)}")
        print(f"  Success rate: {stats.get('success_rate', 0):.1f}%")
        
    except Exception as e:
        print(f"❌ Status check failed: {e}")