"""
Feature flags for gradual rollout of new features

Allows enabling/disabling features without code changes
"""

import os
from typing import Dict, Any


class FeatureFlags:
    """Manage feature flags from environment variables"""
    
    def __init__(self):
        self._flags = {}
        self._load_flags()
    
    def _load_flags(self):
        """Load feature flags from environment variables"""
        # V2 Schema - Host Deduplication
        self._flags['USE_V2_SCHEMA'] = self._get_bool_env('USE_V2_SCHEMA', False)
        self._flags['USE_V2_PARSER'] = self._get_bool_env('USE_V2_PARSER', False)
        self._flags['USE_V2_HOSTS_API'] = self._get_bool_env('USE_V2_HOSTS_API', False)
        
        # Migration flags
        self._flags['MIGRATION_MODE'] = self._get_bool_env('MIGRATION_MODE', False)
        self._flags['DUAL_WRITE_MODE'] = self._get_bool_env('DUAL_WRITE_MODE', False)
        
        # Debug flags
        self._flags['DEBUG_DEDUPLICATION'] = self._get_bool_env('DEBUG_DEDUPLICATION', False)
        self._flags['LOG_SCHEMA_OPERATIONS'] = self._get_bool_env('LOG_SCHEMA_OPERATIONS', False)
    
    def _get_bool_env(self, key: str, default: bool = False) -> bool:
        """Get boolean value from environment variable"""
        value = os.getenv(key, '').lower()
        if value in ('true', '1', 'yes', 'on'):
            return True
        elif value in ('false', '0', 'no', 'off'):
            return False
        else:
            return default
    
    def is_enabled(self, flag_name: str) -> bool:
        """Check if a feature flag is enabled"""
        return self._flags.get(flag_name, False)
    
    def get_flag(self, flag_name: str) -> Any:
        """Get the value of a feature flag"""
        return self._flags.get(flag_name)
    
    def set_flag(self, flag_name: str, value: Any):
        """Set a feature flag (for testing)"""
        self._flags[flag_name] = value
    
    def get_all_flags(self) -> Dict[str, Any]:
        """Get all feature flags"""
        return self._flags.copy()
    
    # Convenience methods for common flags
    @property
    def use_v2_schema(self) -> bool:
        return self.is_enabled('USE_V2_SCHEMA')
    
    @property
    def use_v2_parser(self) -> bool:
        return self.is_enabled('USE_V2_PARSER')
    
    @property
    def use_v2_hosts_api(self) -> bool:
        return self.is_enabled('USE_V2_HOSTS_API')
    
    @property
    def migration_mode(self) -> bool:
        return self.is_enabled('MIGRATION_MODE')
    
    @property
    def dual_write_mode(self) -> bool:
        return self.is_enabled('DUAL_WRITE_MODE')


# Global instance
feature_flags = FeatureFlags()