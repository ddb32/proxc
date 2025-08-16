__version__ = "3.0.0"

try:
    from .cli import main_cli
    from .monitor import ProxyMonitor
    from .scheduler import ProxyScheduler
except ImportError:
    pass

__all__ = [
    "main_cli",
    "ProxyMonitor", 
    "ProxyScheduler"
]
