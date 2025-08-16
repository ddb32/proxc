"""
ProxC Custom Exceptions
Standardized exception hierarchy for better error handling
"""

class ProxCError(Exception):
    """Base exception for all ProxC errors"""
    pass


class ConfigurationError(ProxCError):
    """Configuration-related errors"""
    pass


class DatabaseError(ProxCError):
    """Database operation errors"""
    pass


class ValidationError(ProxCError):
    """Proxy validation errors"""
    pass


class NetworkError(ProxCError):
    """Network connectivity errors"""
    pass


class ParseError(ProxCError):
    """Data parsing errors"""
    pass


class ExportError(ProxCError):
    """Export operation errors"""
    pass


class ImportError(ProxCError):
    """Import operation errors"""
    pass


class ResourceError(ProxCError):
    """Resource management errors (files, connections, etc.)"""
    pass


class TimeoutError(ProxCError):
    """Operation timeout errors"""
    pass