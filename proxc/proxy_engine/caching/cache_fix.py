def create_warming_enabled_cache(config: CacheConfig, warming_config: Optional[Dict] = None) -> Tuple[SmartCache, CacheWarmingManager]:
    """Create a smart cache with warming manager enabled"""
    cache = SmartCache(config, "WarmingEnabledCache")
    
    # Get the warming manager from the cache (it should be created during cache initialization)
    if cache.warming_manager is None:
        # Fallback: create warming manager manually if not created
        cache.warming_manager = CacheWarmingManager(cache, config)
    
    warming_manager = cache.warming_manager
    
    # Apply warming configuration if provided
    if warming_config:
        for key, value in warming_config.items():
            if hasattr(warming_manager, key):
                setattr(warming_manager, key, value)
    
    return cache, warming_manager