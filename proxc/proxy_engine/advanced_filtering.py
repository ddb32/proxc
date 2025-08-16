#!/usr/bin/env python3
"""
Advanced Proxy Filtering System - Phase 4.2.5

Sophisticated filtering engine with custom expression support, allowing complex
queries and filtering operations on proxy datasets.

Filtering Capabilities:
- Custom expression language for complex filters
- Mathematical and logical operations
- Performance-based filtering
- Geographic and network filtering
- Quality and reputation filters
- Time-based filtering
- Composite filter expressions
- Filter optimization and caching
"""

import ast
import asyncio
import json
import logging
import operator
import re
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Union, Callable, Set
import ipaddress

from ..proxy_core.models import (
    ProxyInfo, ProxyProtocol, AnonymityLevel, ThreatLevel, ProxyStatus
)
from .quality_scoring import QualityMetrics, QualityTier
from .reputation_system import ReputationScore, ReputationTier


class FilterOperator(Enum):
    """Supported filter operators"""
    EQUALS = "=="
    NOT_EQUALS = "!="
    GREATER_THAN = ">"
    LESS_THAN = "<"
    GREATER_EQUAL = ">="
    LESS_EQUAL = "<="
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    IN = "in"
    NOT_IN = "not_in"
    REGEX = "regex"
    BETWEEN = "between"
    AND = "and"
    OR = "or"
    NOT = "not"


class FilterField(Enum):
    """Available fields for filtering"""
    # Basic proxy fields
    HOST = "host"
    PORT = "port"
    PROTOCOL = "protocol"
    
    # Geographic fields
    COUNTRY = "country"
    CITY = "city"
    LATITUDE = "latitude"
    LONGITUDE = "longitude"
    
    # Performance fields
    RESPONSE_TIME = "response_time_ms"
    UPTIME = "uptime_percentage"
    SUCCESS_RATE = "success_rate"
    
    # Security fields
    ANONYMITY_LEVEL = "anonymity_level"
    THREAT_LEVEL = "threat_level"
    THREAT_CATEGORIES = "threat_categories"
    
    # Quality and reputation
    QUALITY_SCORE = "quality_score"
    QUALITY_TIER = "quality_tier"
    REPUTATION_SCORE = "reputation_score"
    REPUTATION_TIER = "reputation_tier"
    
    # Metadata fields
    SOURCE = "source"
    FIRST_SEEN = "first_seen"
    LAST_CHECKED = "last_checked"
    ASN = "asn"
    ISP = "isp"


@dataclass
class FilterCondition:
    """Single filter condition"""
    field: FilterField
    operator: FilterOperator
    value: Any
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'field': self.field.value,
            'operator': self.operator.value,
            'value': self.value,
            'metadata': self.metadata
        }


@dataclass
class CompositeFilter:
    """Composite filter with multiple conditions"""
    conditions: List[Union[FilterCondition, 'CompositeFilter']]
    operator: FilterOperator  # AND or OR
    name: Optional[str] = None
    description: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'conditions': [
                cond.to_dict() if hasattr(cond, 'to_dict') else cond
                for cond in self.conditions
            ],
            'operator': self.operator.value,
            'name': self.name,
            'description': self.description
        }


class FilterExpressionParser:
    """Parser for custom filter expressions"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Field mappings for natural language
        self.field_aliases = {
            'response_time': FilterField.RESPONSE_TIME,
            'response': FilterField.RESPONSE_TIME,
            'latency': FilterField.RESPONSE_TIME,
            'uptime': FilterField.UPTIME,
            'availability': FilterField.UPTIME,
            'country_code': FilterField.COUNTRY,
            'location': FilterField.COUNTRY,
            'anonymity': FilterField.ANONYMITY_LEVEL,
            'anon': FilterField.ANONYMITY_LEVEL,
            'threat': FilterField.THREAT_LEVEL,
            'quality': FilterField.QUALITY_SCORE,
            'reputation': FilterField.REPUTATION_SCORE,
            'rep': FilterField.REPUTATION_SCORE,
            'ip': FilterField.HOST,
            'address': FilterField.HOST
        }
        
        # Operator mappings
        self.operator_aliases = {
            '=': FilterOperator.EQUALS,
            '==': FilterOperator.EQUALS,
            '!=': FilterOperator.NOT_EQUALS,
            '<>': FilterOperator.NOT_EQUALS,
            '>': FilterOperator.GREATER_THAN,
            '<': FilterOperator.LESS_THAN,
            '>=': FilterOperator.GREATER_EQUAL,
            '<=': FilterOperator.LESS_EQUAL,
            'contains': FilterOperator.CONTAINS,
            'includes': FilterOperator.CONTAINS,
            'has': FilterOperator.CONTAINS,
            'in': FilterOperator.IN,
            'is_in': FilterOperator.IN,
            'not_in': FilterOperator.NOT_IN,
            'regex': FilterOperator.REGEX,
            'matches': FilterOperator.REGEX,
            'between': FilterOperator.BETWEEN,
            'and': FilterOperator.AND,
            'or': FilterOperator.OR,
            'not': FilterOperator.NOT
        }
    
    def parse_expression(self, expression: str) -> CompositeFilter:
        """Parse a custom filter expression into a CompositeFilter"""
        
        try:
            # Tokenize the expression
            tokens = self._tokenize(expression)
            
            # Parse tokens into filter structure
            filter_obj = self._parse_tokens(tokens)
            
            return filter_obj
        
        except Exception as e:
            self.logger.error(f"Error parsing filter expression '{expression}': {e}")
            raise ValueError(f"Invalid filter expression: {e}")
    
    def _tokenize(self, expression: str) -> List[str]:
        """Tokenize expression into components"""
        
        # Handle quoted strings
        tokens = []
        current_token = ""
        in_quotes = False
        quote_char = None
        
        i = 0
        while i < len(expression):
            char = expression[i]
            
            if not in_quotes and char in ['"', "'"]:
                in_quotes = True
                quote_char = char
                current_token += char
            elif in_quotes and char == quote_char:
                in_quotes = False
                current_token += char
                quote_char = None
            elif not in_quotes and char in [' ', '\t', '\n']:
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
            elif not in_quotes and char in ['(', ')', ',']:
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
                tokens.append(char)
            else:
                current_token += char
            
            i += 1
        
        if current_token:
            tokens.append(current_token)
        
        return tokens
    
    def _parse_tokens(self, tokens: List[str]) -> CompositeFilter:
        """Parse tokens into filter structure"""
        
        if not tokens:
            raise ValueError("Empty filter expression")
        
        # Simple implementation for basic expressions
        # Format: "field operator value" or "field operator value AND/OR field operator value"
        
        conditions = []
        current_condition = []
        current_operator = FilterOperator.AND
        
        i = 0
        while i < len(tokens):
            token = tokens[i].lower()
            
            if token in ['and', 'or']:
                if len(current_condition) >= 3:
                    conditions.append(self._create_condition(current_condition))
                    current_condition = []
                
                current_operator = self.operator_aliases.get(token, FilterOperator.AND)
            
            elif token == '(':
                # Handle parentheses (simplified)
                paren_count = 1
                sub_tokens = []
                i += 1
                
                while i < len(tokens) and paren_count > 0:
                    if tokens[i] == '(':
                        paren_count += 1
                    elif tokens[i] == ')':
                        paren_count -= 1
                    
                    if paren_count > 0:
                        sub_tokens.append(tokens[i])
                    
                    i += 1
                
                if sub_tokens:
                    sub_filter = self._parse_tokens(sub_tokens)
                    conditions.append(sub_filter)
                
                i -= 1  # Adjust for loop increment
            
            else:
                current_condition.append(tokens[i])
            
            i += 1
        
        # Handle remaining condition
        if len(current_condition) >= 3:
            conditions.append(self._create_condition(current_condition))
        
        if not conditions:
            raise ValueError("No valid conditions found")
        
        if len(conditions) == 1:
            # Single condition, wrap in composite filter
            if isinstance(conditions[0], FilterCondition):
                return CompositeFilter(conditions, FilterOperator.AND)
            else:
                return conditions[0]
        
        return CompositeFilter(conditions, current_operator)
    
    def _create_condition(self, tokens: List[str]) -> FilterCondition:
        """Create a FilterCondition from tokens"""
        
        if len(tokens) < 3:
            raise ValueError(f"Invalid condition: {' '.join(tokens)}")
        
        field_name = tokens[0].lower()
        operator_name = tokens[1].lower()
        value_str = ' '.join(tokens[2:])
        
        # Map field name
        field = self.field_aliases.get(field_name)
        if not field:
            try:
                field = FilterField(field_name)
            except ValueError:
                raise ValueError(f"Unknown field: {field_name}")
        
        # Map operator
        operator = self.operator_aliases.get(operator_name)
        if not operator:
            raise ValueError(f"Unknown operator: {operator_name}")
        
        # Parse value
        value = self._parse_value(value_str, field, operator)
        
        return FilterCondition(field, operator, value)
    
    def _parse_value(self, value_str: str, field: FilterField, operator: FilterOperator) -> Any:
        """Parse value string based on field type and operator"""
        
        # Remove quotes if present
        if value_str.startswith('"') and value_str.endswith('"'):
            value_str = value_str[1:-1]
        elif value_str.startswith("'") and value_str.endswith("'"):
            value_str = value_str[1:-1]
        
        # Handle special operators
        if operator == FilterOperator.IN or operator == FilterOperator.NOT_IN:
            # Parse list: [value1, value2, value3]
            if value_str.startswith('[') and value_str.endswith(']'):
                list_str = value_str[1:-1]
                return [item.strip().strip('"\'') for item in list_str.split(',')]
            else:
                return [value_str]
        
        elif operator == FilterOperator.BETWEEN:
            # Parse range: value1..value2 or value1,value2
            if '..' in value_str:
                parts = value_str.split('..')
            elif ',' in value_str:
                parts = value_str.split(',')
            else:
                raise ValueError(f"BETWEEN operator requires range: {value_str}")
            
            if len(parts) != 2:
                raise ValueError(f"BETWEEN operator requires exactly 2 values: {value_str}")
            
            return [self._convert_value(parts[0].strip(), field), 
                   self._convert_value(parts[1].strip(), field)]
        
        else:
            return self._convert_value(value_str, field)
    
    def _convert_value(self, value_str: str, field: FilterField) -> Any:
        """Convert string value to appropriate type based on field"""
        
        # Numeric fields
        if field in [FilterField.PORT, FilterField.RESPONSE_TIME, FilterField.UPTIME, 
                    FilterField.QUALITY_SCORE, FilterField.REPUTATION_SCORE,
                    FilterField.LATITUDE, FilterField.LONGITUDE]:
            try:
                if '.' in value_str:
                    return float(value_str)
                else:
                    return int(value_str)
            except ValueError:
                raise ValueError(f"Invalid numeric value for {field.value}: {value_str}")
        
        # Enum fields
        elif field == FilterField.PROTOCOL:
            try:
                return ProxyProtocol(value_str.lower())
            except ValueError:
                raise ValueError(f"Invalid protocol: {value_str}")
        
        elif field == FilterField.ANONYMITY_LEVEL:
            try:
                return AnonymityLevel(value_str.lower())
            except ValueError:
                raise ValueError(f"Invalid anonymity level: {value_str}")
        
        elif field == FilterField.THREAT_LEVEL:
            try:
                return ThreatLevel(value_str.upper())
            except ValueError:
                raise ValueError(f"Invalid threat level: {value_str}")
        
        elif field == FilterField.QUALITY_TIER:
            try:
                return QualityTier(value_str.lower())
            except ValueError:
                raise ValueError(f"Invalid quality tier: {value_str}")
        
        elif field == FilterField.REPUTATION_TIER:
            try:
                return ReputationTier(value_str.lower())
            except ValueError:
                raise ValueError(f"Invalid reputation tier: {value_str}")
        
        # Date fields
        elif field in [FilterField.FIRST_SEEN, FilterField.LAST_CHECKED]:
            try:
                return datetime.fromisoformat(value_str)
            except ValueError:
                raise ValueError(f"Invalid date format for {field.value}: {value_str}")
        
        # String fields (default)
        else:
            return value_str


class ProxyFilter:
    """Advanced proxy filtering engine"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.parser = FilterExpressionParser()
        
        # Operator implementation mapping
        self.operators = {
            FilterOperator.EQUALS: lambda a, b: a == b,
            FilterOperator.NOT_EQUALS: lambda a, b: a != b,
            FilterOperator.GREATER_THAN: lambda a, b: a > b,
            FilterOperator.LESS_THAN: lambda a, b: a < b,
            FilterOperator.GREATER_EQUAL: lambda a, b: a >= b,
            FilterOperator.LESS_EQUAL: lambda a, b: a <= b,
            FilterOperator.CONTAINS: lambda a, b: b in str(a) if a else False,
            FilterOperator.NOT_CONTAINS: lambda a, b: b not in str(a) if a else True,
            FilterOperator.IN: lambda a, b: a in b if isinstance(b, (list, tuple, set)) else a == b,
            FilterOperator.NOT_IN: lambda a, b: a not in b if isinstance(b, (list, tuple, set)) else a != b,
            FilterOperator.REGEX: self._regex_match,
            FilterOperator.BETWEEN: self._between_match
        }
    
    def _regex_match(self, value: Any, pattern: str) -> bool:
        """Check if value matches regex pattern"""
        try:
            return bool(re.search(pattern, str(value)))
        except re.error:
            return False
    
    def _between_match(self, value: Any, range_values: List[Any]) -> bool:
        """Check if value is between two values"""
        if len(range_values) != 2:
            return False
        
        try:
            return range_values[0] <= value <= range_values[1]
        except TypeError:
            return False
    
    def filter_proxies(self, proxies: List[ProxyInfo], 
                      filter_expr: Union[str, CompositeFilter],
                      quality_scores: Dict[str, QualityMetrics] = None,
                      reputation_scores: Dict[str, ReputationScore] = None) -> List[ProxyInfo]:
        """Filter proxies using expression or filter object"""
        
        if isinstance(filter_expr, str):
            filter_obj = self.parser.parse_expression(filter_expr)
        else:
            filter_obj = filter_expr
        
        filtered_proxies = []
        
        for proxy in proxies:
            if self._evaluate_filter(proxy, filter_obj, quality_scores, reputation_scores):
                filtered_proxies.append(proxy)
        
        return filtered_proxies
    
    def _evaluate_filter(self, proxy: ProxyInfo, 
                        filter_obj: Union[FilterCondition, CompositeFilter],
                        quality_scores: Dict[str, QualityMetrics] = None,
                        reputation_scores: Dict[str, ReputationScore] = None) -> bool:
        """Evaluate filter against a proxy"""
        
        if isinstance(filter_obj, FilterCondition):
            return self._evaluate_condition(proxy, filter_obj, quality_scores, reputation_scores)
        
        elif isinstance(filter_obj, CompositeFilter):
            results = []
            
            for condition in filter_obj.conditions:
                result = self._evaluate_filter(condition, proxy, quality_scores, reputation_scores)
                results.append(result)
            
            if filter_obj.operator == FilterOperator.AND:
                return all(results)
            elif filter_obj.operator == FilterOperator.OR:
                return any(results)
            else:
                return False
        
        return False
    
    def _evaluate_condition(self, proxy: ProxyInfo, condition: FilterCondition,
                          quality_scores: Dict[str, QualityMetrics] = None,
                          reputation_scores: Dict[str, ReputationScore] = None) -> bool:
        """Evaluate a single condition against a proxy"""
        
        # Get field value from proxy
        field_value = self._get_field_value(proxy, condition.field, quality_scores, reputation_scores)
        
        if field_value is None and condition.operator not in [FilterOperator.EQUALS, FilterOperator.NOT_EQUALS]:
            return False
        
        # Apply operator
        operator_func = self.operators.get(condition.operator)
        if not operator_func:
            self.logger.warning(f"Unsupported operator: {condition.operator}")
            return False
        
        try:
            return operator_func(field_value, condition.value)
        except Exception as e:
            self.logger.error(f"Error evaluating condition: {e}")
            return False
    
    def _get_field_value(self, proxy: ProxyInfo, field: FilterField,
                        quality_scores: Dict[str, QualityMetrics] = None,
                        reputation_scores: Dict[str, ReputationScore] = None) -> Any:
        """Extract field value from proxy object"""
        
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        # Basic proxy fields
        if field == FilterField.HOST:
            return proxy.host
        elif field == FilterField.PORT:
            return proxy.port
        elif field == FilterField.PROTOCOL:
            return proxy.protocol
        
        # Geographic fields
        elif field == FilterField.COUNTRY:
            return getattr(proxy, 'country', None)
        elif field == FilterField.CITY:
            return getattr(proxy, 'city', None)
        elif field == FilterField.LATITUDE:
            return getattr(proxy, 'latitude', None)
        elif field == FilterField.LONGITUDE:
            return getattr(proxy, 'longitude', None)
        
        # Performance fields
        elif field == FilterField.RESPONSE_TIME:
            return getattr(proxy, 'response_time_ms', None)
        elif field == FilterField.UPTIME:
            return getattr(proxy, 'uptime_percentage', None)
        elif field == FilterField.SUCCESS_RATE:
            return getattr(proxy, 'success_rate', None)
        
        # Security fields
        elif field == FilterField.ANONYMITY_LEVEL:
            return getattr(proxy, 'anonymity_level', None)
        elif field == FilterField.THREAT_LEVEL:
            return getattr(proxy, 'threat_level', None)
        elif field == FilterField.THREAT_CATEGORIES:
            return getattr(proxy, 'threat_categories', [])
        
        # Quality fields
        elif field == FilterField.QUALITY_SCORE:
            if quality_scores and proxy_id in quality_scores:
                return quality_scores[proxy_id].overall_score
            return None
        elif field == FilterField.QUALITY_TIER:
            if quality_scores and proxy_id in quality_scores:
                return quality_scores[proxy_id].quality_tier
            return None
        
        # Reputation fields
        elif field == FilterField.REPUTATION_SCORE:
            if reputation_scores and proxy_id in reputation_scores:
                return reputation_scores[proxy_id].overall_score
            return None
        elif field == FilterField.REPUTATION_TIER:
            if reputation_scores and proxy_id in reputation_scores:
                return reputation_scores[proxy_id].reputation_tier
            return None
        
        # Metadata fields
        elif field == FilterField.SOURCE:
            return getattr(proxy, 'source', None)
        elif field == FilterField.FIRST_SEEN:
            return getattr(proxy, 'first_seen', None)
        elif field == FilterField.LAST_CHECKED:
            return getattr(proxy, 'last_checked', None)
        elif field == FilterField.ASN:
            return getattr(proxy, 'asn', None)
        elif field == FilterField.ISP:
            return getattr(proxy, 'isp', None)
        
        return None


class FilterPresets:
    """Predefined filter presets for common use cases"""
    
    @staticmethod
    def high_quality_proxies() -> CompositeFilter:
        """Filter for high-quality proxies"""
        return CompositeFilter(
            conditions=[
                FilterCondition(FilterField.QUALITY_SCORE, FilterOperator.GREATER_EQUAL, 80),
                FilterCondition(FilterField.UPTIME, FilterOperator.GREATER_EQUAL, 95),
                FilterCondition(FilterField.RESPONSE_TIME, FilterOperator.LESS_THAN, 1000)
            ],
            operator=FilterOperator.AND,
            name="High Quality Proxies",
            description="Proxies with quality score >= 80, uptime >= 95%, response time < 1s"
        )
    
    @staticmethod
    def secure_proxies() -> CompositeFilter:
        """Filter for secure proxies"""
        return CompositeFilter(
            conditions=[
                FilterCondition(FilterField.ANONYMITY_LEVEL, FilterOperator.IN, [AnonymityLevel.ELITE, AnonymityLevel.ANONYMOUS]),
                FilterCondition(FilterField.THREAT_LEVEL, FilterOperator.IN, [ThreatLevel.LOW, None]),
                FilterCondition(FilterField.PROTOCOL, FilterOperator.IN, [ProxyProtocol.HTTPS, ProxyProtocol.SOCKS5])
            ],
            operator=FilterOperator.AND,
            name="Secure Proxies",
            description="Elite/Anonymous proxies with low threat level and secure protocols"
        )
    
    @staticmethod
    def fast_proxies() -> CompositeFilter:
        """Filter for fast-responding proxies"""
        return CompositeFilter(
            conditions=[
                FilterCondition(FilterField.RESPONSE_TIME, FilterOperator.LESS_THAN, 500),
                FilterCondition(FilterField.SUCCESS_RATE, FilterOperator.GREATER_EQUAL, 90)
            ],
            operator=FilterOperator.AND,
            name="Fast Proxies",
            description="Proxies with response time < 500ms and success rate >= 90%"
        )
    
    @staticmethod
    def reliable_proxies() -> CompositeFilter:
        """Filter for reliable proxies"""
        return CompositeFilter(
            conditions=[
                FilterCondition(FilterField.UPTIME, FilterOperator.GREATER_EQUAL, 90),
                FilterCondition(FilterField.REPUTATION_TIER, FilterOperator.IN, [ReputationTier.TRUSTED, ReputationTier.RELIABLE])
            ],
            operator=FilterOperator.AND,
            name="Reliable Proxies",
            description="Proxies with uptime >= 90% and trusted/reliable reputation"
        )
    
    @staticmethod
    def geographic_filter(countries: List[str]) -> CompositeFilter:
        """Filter for specific countries"""
        return CompositeFilter(
            conditions=[
                FilterCondition(FilterField.COUNTRY, FilterOperator.IN, countries)
            ],
            operator=FilterOperator.AND,
            name=f"Geographic Filter ({', '.join(countries)})",
            description=f"Proxies from countries: {', '.join(countries)}"
        )
    
    @staticmethod
    def exclude_threats() -> CompositeFilter:
        """Filter to exclude threatening proxies"""
        return CompositeFilter(
            conditions=[
                FilterCondition(FilterField.THREAT_LEVEL, FilterOperator.NOT_IN, [ThreatLevel.HIGH, ThreatLevel.CRITICAL]),
                FilterCondition(FilterField.REPUTATION_TIER, FilterOperator.NOT_IN, [ReputationTier.BLACKLISTED, ReputationTier.UNRELIABLE])
            ],
            operator=FilterOperator.AND,
            name="Exclude Threats",
            description="Exclude proxies with high threat levels or poor reputation"
        )


class FilterManager:
    """High-level filter management system"""
    
    def __init__(self):
        self.filter_engine = ProxyFilter()
        self.saved_filters: Dict[str, CompositeFilter] = {}
        self.filter_cache: Dict[str, List[ProxyInfo]] = {}
        self.cache_ttl = 300  # 5 minutes
        self.cache_timestamps: Dict[str, float] = {}
        
        # Load presets
        self._load_presets()
    
    def _load_presets(self):
        """Load predefined filter presets"""
        presets = {
            'high_quality': FilterPresets.high_quality_proxies(),
            'secure': FilterPresets.secure_proxies(),
            'fast': FilterPresets.fast_proxies(),
            'reliable': FilterPresets.reliable_proxies(),
            'exclude_threats': FilterPresets.exclude_threats()
        }
        
        self.saved_filters.update(presets)
    
    def apply_filter(self, proxies: List[ProxyInfo], 
                    filter_expr: Union[str, CompositeFilter],
                    quality_scores: Dict[str, QualityMetrics] = None,
                    reputation_scores: Dict[str, ReputationScore] = None,
                    use_cache: bool = True) -> List[ProxyInfo]:
        """Apply filter with caching support"""
        
        # Generate cache key
        if isinstance(filter_expr, str):
            cache_key = f"expr_{hash(filter_expr)}"
        else:
            cache_key = f"filter_{hash(str(filter_expr.to_dict()))}"
        
        # Check cache
        if use_cache and cache_key in self.filter_cache:
            if time.time() - self.cache_timestamps.get(cache_key, 0) < self.cache_ttl:
                return self.filter_cache[cache_key]
        
        # Apply filter
        filtered_proxies = self.filter_engine.filter_proxies(
            proxies, filter_expr, quality_scores, reputation_scores
        )
        
        # Cache result
        if use_cache:
            self.filter_cache[cache_key] = filtered_proxies
            self.cache_timestamps[cache_key] = time.time()
        
        return filtered_proxies
    
    def save_filter(self, name: str, filter_obj: CompositeFilter):
        """Save a filter for reuse"""
        self.saved_filters[name] = filter_obj
    
    def get_filter(self, name: str) -> Optional[CompositeFilter]:
        """Get a saved filter by name"""
        return self.saved_filters.get(name)
    
    def list_filters(self) -> List[str]:
        """List all saved filter names"""
        return list(self.saved_filters.keys())
    
    def create_geographic_filter(self, countries: List[str]) -> CompositeFilter:
        """Create geographic filter for specific countries"""
        return FilterPresets.geographic_filter(countries)
    
    def create_performance_filter(self, min_uptime: float = 90.0,
                                max_response_time: int = 1000,
                                min_success_rate: float = 85.0) -> CompositeFilter:
        """Create performance-based filter"""
        conditions = []
        
        if min_uptime is not None:
            conditions.append(FilterCondition(FilterField.UPTIME, FilterOperator.GREATER_EQUAL, min_uptime))
        
        if max_response_time is not None:
            conditions.append(FilterCondition(FilterField.RESPONSE_TIME, FilterOperator.LESS_THAN, max_response_time))
        
        if min_success_rate is not None:
            conditions.append(FilterCondition(FilterField.SUCCESS_RATE, FilterOperator.GREATER_EQUAL, min_success_rate))
        
        return CompositeFilter(
            conditions=conditions,
            operator=FilterOperator.AND,
            name="Performance Filter",
            description=f"Uptime >= {min_uptime}%, Response time < {max_response_time}ms, Success rate >= {min_success_rate}%"
        )
    
    def optimize_filter_chain(self, filters: List[CompositeFilter]) -> CompositeFilter:
        """Optimize multiple filters into efficient chain"""
        
        if not filters:
            return CompositeFilter([], FilterOperator.AND)
        
        if len(filters) == 1:
            return filters[0]
        
        # Combine all conditions with AND
        all_conditions = []
        for filter_obj in filters:
            all_conditions.extend(filter_obj.conditions)
        
        return CompositeFilter(
            conditions=all_conditions,
            operator=FilterOperator.AND,
            name="Optimized Filter Chain",
            description=f"Combined filter from {len(filters)} individual filters"
        )
    
    def get_filter_statistics(self, proxies: List[ProxyInfo],
                            filter_expr: Union[str, CompositeFilter]) -> Dict[str, Any]:
        """Get statistics about filter results"""
        
        original_count = len(proxies)
        filtered_proxies = self.apply_filter(proxies, filter_expr)
        filtered_count = len(filtered_proxies)
        
        return {
            'original_count': original_count,
            'filtered_count': filtered_count,
            'reduction_percentage': (1 - filtered_count / original_count) * 100 if original_count > 0 else 0,
            'pass_rate': filtered_count / original_count * 100 if original_count > 0 else 0
        }