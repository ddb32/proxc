"""Validation Module - Comprehensive proxy validation system"""

# Configuration and results
from .validation_config import (
    ValidationConfig,
    ValidationMethod,
    FailureReason,
    VALIDATION_TEST_ENDPOINTS,
    IPV6_TEST_ENDPOINTS,
    COMMON_PROXY_PORTS
)
from .validation_results import (
    ValidationResult,
    BatchValidationResult
)

# Validators
from .sync_validators import (
    SyncProxyValidator,
    create_sync_validator
)
from .async_validators import (
    AsyncProxyValidator,
    create_async_validator
)
from .batch_validators import (
    SyncBatchValidator,
    AsyncBatchValidator,
    BatchValidator,
    calculate_optimal_concurrency,
    validate_proxies_async,
    validate_proxies_sync,
    validate_proxies
)

__all__ = [
    # Configuration
    'ValidationConfig',
    'ValidationMethod',
    'FailureReason',
    'VALIDATION_TEST_ENDPOINTS',
    'IPV6_TEST_ENDPOINTS',
    'COMMON_PROXY_PORTS',
    
    # Results
    'ValidationResult',
    'BatchValidationResult',
    
    # Single proxy validators
    'SyncProxyValidator',
    'AsyncProxyValidator',
    'create_sync_validator',
    'create_async_validator',
    
    # Batch validators
    'SyncBatchValidator',
    'AsyncBatchValidator', 
    'BatchValidator',
    
    # Utility functions
    'calculate_optimal_concurrency',
    'validate_proxies_async',
    'validate_proxies_sync',
    'validate_proxies'
]