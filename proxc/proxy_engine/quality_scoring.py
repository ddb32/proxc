#!/usr/bin/env python3
"""
Proxy Quality Scoring Engine - Phase 4.2.1

Advanced multi-factor proxy quality assessment system that evaluates proxies
across multiple dimensions to provide comprehensive quality scores.

Scoring Factors:
- Performance metrics (response time, throughput)
- Reliability metrics (uptime, stability)
- Security assessment (anonymity, threat level)
- Geographic consistency and validation
- Protocol compatibility and features
- Historical behavior patterns
- Provider reputation
- Network characteristics
"""

import asyncio
import json
import logging
import math
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
import numpy as np

from ..proxy_core.models import (
    ProxyInfo, ProxyProtocol, AnonymityLevel, ThreatLevel,
    ProxyStatus, ValidationStatus
)


class QualityTier(Enum):
    """Proxy quality tiers"""
    PREMIUM = "premium"      # 90-100 score
    EXCELLENT = "excellent"  # 80-89 score
    GOOD = "good"           # 70-79 score
    AVERAGE = "average"     # 60-69 score
    POOR = "poor"          # 40-59 score
    UNRELIABLE = "unreliable"  # 0-39 score


@dataclass
class QualityMetrics:
    """Comprehensive quality metrics for a proxy"""
    
    # Performance scores (0-100)
    performance_score: float = 0.0
    reliability_score: float = 0.0
    security_score: float = 0.0
    geographic_score: float = 0.0
    protocol_score: float = 0.0
    
    # Composite scores
    overall_score: float = 0.0
    quality_tier: QualityTier = QualityTier.UNRELIABLE
    
    # Detailed breakdowns
    performance_breakdown: Dict[str, float] = field(default_factory=dict)
    reliability_breakdown: Dict[str, float] = field(default_factory=dict)
    security_breakdown: Dict[str, float] = field(default_factory=dict)
    
    # Metadata
    last_scored: datetime = field(default_factory=datetime.now)
    confidence_level: float = 0.0  # How confident we are in this score
    sample_size: int = 0  # Number of data points used


class QualityScoringEngine:
    """Advanced proxy quality scoring system"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._get_default_config()
        self.logger = logging.getLogger(__name__)
        
        # Scoring weights for different factors
        self.scoring_weights = {
            'performance': 0.30,   # 30% - response time, throughput
            'reliability': 0.25,   # 25% - uptime, stability
            'security': 0.20,      # 20% - anonymity, threat level
            'geographic': 0.15,    # 15% - location accuracy
            'protocol': 0.10       # 10% - protocol features
        }
        
        # Performance benchmarks (percentiles from real data)
        self.performance_benchmarks = {
            'response_time_ms': {
                'excellent': 100,    # <100ms
                'good': 300,         # 100-300ms
                'average': 1000,     # 300-1000ms
                'poor': 3000         # 1000-3000ms
            },
            'uptime_percentage': {
                'excellent': 99.0,   # >99%
                'good': 95.0,        # 95-99%
                'average': 85.0,     # 85-95%
                'poor': 70.0         # 70-85%
            }
        }
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default scoring configuration"""
        return {
            'min_samples_for_confidence': 10,
            'max_response_time_ms': 10000,
            'penalize_failed_attempts': True,
            'geographic_verification': True,
            'protocol_feature_scoring': True,
            'temporal_decay_factor': 0.95,  # Older data has less weight
            'outlier_rejection_threshold': 3.0  # Standard deviations
        }
    
    async def calculate_quality_score(self, proxy: ProxyInfo, 
                                    historical_data: List[Dict] = None) -> QualityMetrics:
        """Calculate comprehensive quality score for a proxy"""
        
        metrics = QualityMetrics()
        
        try:
            # Calculate individual scoring dimensions
            metrics.performance_score = await self._calculate_performance_score(
                proxy, historical_data
            )
            metrics.performance_breakdown = self._get_performance_breakdown(
                proxy, historical_data
            )
            
            metrics.reliability_score = await self._calculate_reliability_score(
                proxy, historical_data
            )
            metrics.reliability_breakdown = self._get_reliability_breakdown(
                proxy, historical_data
            )
            
            metrics.security_score = await self._calculate_security_score(proxy)
            metrics.security_breakdown = self._get_security_breakdown(proxy)
            
            metrics.geographic_score = await self._calculate_geographic_score(proxy)
            
            metrics.protocol_score = await self._calculate_protocol_score(proxy)
            
            # Calculate weighted overall score
            metrics.overall_score = self._calculate_weighted_score(metrics)
            
            # Determine quality tier
            metrics.quality_tier = self._determine_quality_tier(metrics.overall_score)
            
            # Calculate confidence level
            metrics.confidence_level = self._calculate_confidence_level(
                proxy, historical_data
            )
            
            # Set metadata
            metrics.sample_size = len(historical_data) if historical_data else 1
            metrics.last_scored = datetime.now()
            
            return metrics
        
        except Exception as e:
            self.logger.error(f"Error calculating quality score for {proxy.host}:{proxy.port}: {e}")
            return metrics  # Return default metrics on error
    
    async def _calculate_performance_score(self, proxy: ProxyInfo,
                                         historical_data: List[Dict] = None) -> float:
        """Calculate performance-based quality score (0-100)"""
        
        if not historical_data:
            # Use current proxy data if no historical data
            historical_data = [self._proxy_to_dict(proxy)]
        
        response_times = []
        success_rates = []
        throughput_scores = []
        
        # Process historical performance data
        for data_point in historical_data:
            # Response time scoring
            response_time = data_point.get('response_time_ms', 0)
            if response_time > 0:
                response_times.append(response_time)
            
            # Success rate from validation attempts
            validation_status = data_point.get('validation_status')
            if validation_status:
                success_rates.append(1.0 if validation_status == 'valid' else 0.0)
            
            # Throughput scoring (if available)
            throughput = data_point.get('throughput_mbps', 0)
            if throughput > 0:
                throughput_scores.append(min(throughput / 10.0 * 100, 100))  # Scale to 100
        
        # Calculate component scores
        scores = []
        
        # Response time score (lower is better)
        if response_times:
            avg_response_time = statistics.median(response_times)
            if avg_response_time <= self.performance_benchmarks['response_time_ms']['excellent']:
                response_score = 100
            elif avg_response_time <= self.performance_benchmarks['response_time_ms']['good']:
                response_score = 85
            elif avg_response_time <= self.performance_benchmarks['response_time_ms']['average']:
                response_score = 70
            elif avg_response_time <= self.performance_benchmarks['response_time_ms']['poor']:
                response_score = 50
            else:
                response_score = max(20, 100 - (avg_response_time / 100))  # Penalty for very slow
            
            scores.append(response_score * 0.6)  # 60% weight for response time
        
        # Success rate score
        if success_rates:
            avg_success_rate = statistics.mean(success_rates)
            scores.append(avg_success_rate * 100 * 0.3)  # 30% weight for success rate
        
        # Throughput score
        if throughput_scores:
            avg_throughput_score = statistics.mean(throughput_scores)
            scores.append(avg_throughput_score * 0.1)  # 10% weight for throughput
        
        # Return weighted average or default
        return statistics.mean(scores) if scores else 50.0
    
    async def _calculate_reliability_score(self, proxy: ProxyInfo,
                                         historical_data: List[Dict] = None) -> float:
        """Calculate reliability-based quality score (0-100)"""
        
        if not historical_data:
            historical_data = [self._proxy_to_dict(proxy)]
        
        uptime_scores = []
        stability_scores = []
        consistency_scores = []
        
        # Process reliability metrics
        for data_point in historical_data:
            # Uptime scoring
            uptime = data_point.get('uptime_percentage', 0)
            if uptime > 0:
                if uptime >= self.performance_benchmarks['uptime_percentage']['excellent']:
                    uptime_scores.append(100)
                elif uptime >= self.performance_benchmarks['uptime_percentage']['good']:
                    uptime_scores.append(85)
                elif uptime >= self.performance_benchmarks['uptime_percentage']['average']:
                    uptime_scores.append(70)
                elif uptime >= self.performance_benchmarks['uptime_percentage']['poor']:
                    uptime_scores.append(50)
                else:
                    uptime_scores.append(max(10, uptime))
        
        # Calculate response time stability (low variance = high stability)
        response_times = [d.get('response_time_ms', 0) for d in historical_data if d.get('response_time_ms', 0) > 0]
        if len(response_times) >= 3:
            coefficient_of_variation = statistics.stdev(response_times) / statistics.mean(response_times)
            stability_score = max(0, 100 - (coefficient_of_variation * 100))
            stability_scores.append(stability_score)
        
        # Calculate consistency score (same results over time)
        validation_results = [d.get('validation_status') for d in historical_data]
        if len(validation_results) >= 3:
            success_count = sum(1 for r in validation_results if r == 'valid')
            consistency_score = (success_count / len(validation_results)) * 100
            consistency_scores.append(consistency_score)
        
        # Combine scores
        scores = []
        if uptime_scores:
            scores.append(statistics.mean(uptime_scores) * 0.5)  # 50% weight
        if stability_scores:
            scores.append(statistics.mean(stability_scores) * 0.3)  # 30% weight
        if consistency_scores:
            scores.append(statistics.mean(consistency_scores) * 0.2)  # 20% weight
        
        return statistics.mean(scores) if scores else 50.0
    
    async def _calculate_security_score(self, proxy: ProxyInfo) -> float:
        """Calculate security-based quality score (0-100)"""
        
        score = 50.0  # Base score
        
        # Anonymity level scoring
        if hasattr(proxy, 'anonymity_level') and proxy.anonymity_level:
            anonymity_scores = {
                AnonymityLevel.ELITE: 100,
                AnonymityLevel.ANONYMOUS: 80,
                AnonymityLevel.TRANSPARENT: 40
            }
            score = anonymity_scores.get(proxy.anonymity_level, 50)
        
        # Threat level penalty
        if hasattr(proxy, 'threat_level') and proxy.threat_level:
            threat_penalties = {
                ThreatLevel.LOW: 0,      # No penalty
                ThreatLevel.MEDIUM: -20,  # -20 points
                ThreatLevel.HIGH: -40,    # -40 points
                ThreatLevel.CRITICAL: -60  # -60 points
            }
            score += threat_penalties.get(proxy.threat_level, 0)
        
        # Protocol security bonus
        if hasattr(proxy, 'protocol') and proxy.protocol:
            protocol_bonuses = {
                ProxyProtocol.HTTPS: 10,   # +10 for HTTPS
                ProxyProtocol.SOCKS5: 5,   # +5 for SOCKS5
                ProxyProtocol.HTTP: 0,     # No bonus for HTTP
                ProxyProtocol.SOCKS4: -5   # -5 for SOCKS4 (less secure)
            }
            score += protocol_bonuses.get(proxy.protocol, 0)
        
        # Threat categories penalty
        if hasattr(proxy, 'threat_categories') and proxy.threat_categories:
            score -= len(proxy.threat_categories) * 10  # -10 per threat category
        
        # Reputation score integration
        if hasattr(proxy, 'reputation_score') and proxy.reputation_score is not None:
            # Weight reputation score as 30% of security score
            reputation_component = proxy.reputation_score * 0.3
            score = score * 0.7 + reputation_component
        
        return max(0, min(100, score))  # Clamp to 0-100 range
    
    async def _calculate_geographic_score(self, proxy: ProxyInfo) -> float:
        """Calculate geographic consistency and accuracy score (0-100)"""
        
        score = 50.0  # Base score
        
        # Geographic data completeness
        geo_fields = ['country', 'city', 'latitude', 'longitude', 'asn', 'isp']
        available_fields = sum(1 for field in geo_fields if hasattr(proxy, field) and getattr(proxy, field))
        completeness_score = (available_fields / len(geo_fields)) * 100
        
        score = completeness_score * 0.4  # 40% weight for completeness
        
        # Geographic consistency checks
        if hasattr(proxy, 'country') and hasattr(proxy, 'city'):
            # This would normally validate against a geographic database
            # For now, give bonus for having both country and city
            score += 20
        
        # Latitude/longitude validation
        if hasattr(proxy, 'latitude') and hasattr(proxy, 'longitude'):
            lat, lon = proxy.latitude, proxy.longitude
            if lat and lon and -90 <= lat <= 90 and -180 <= lon <= 180:
                score += 20  # Valid coordinates bonus
        
        # ISP/ASN consistency
        if hasattr(proxy, 'isp') and hasattr(proxy, 'asn'):
            if proxy.isp and proxy.asn:
                score += 20  # Both ISP and ASN available
        
        return max(0, min(100, score))
    
    async def _calculate_protocol_score(self, proxy: ProxyInfo) -> float:
        """Calculate protocol-specific quality score (0-100)"""
        
        # Base scores for different protocols
        protocol_base_scores = {
            ProxyProtocol.HTTPS: 90,   # Most secure and featured
            ProxyProtocol.SOCKS5: 85,  # Good features and security
            ProxyProtocol.HTTP: 70,    # Basic functionality
            ProxyProtocol.SOCKS4: 60   # Limited features
        }
        
        base_score = protocol_base_scores.get(proxy.protocol, 50)
        
        # Protocol-specific feature bonuses
        feature_bonuses = 0
        
        # Authentication support (if available in metadata)
        if hasattr(proxy, 'supports_auth') and getattr(proxy, 'supports_auth', False):
            feature_bonuses += 10
        
        # IPv6 support
        if hasattr(proxy, 'supports_ipv6') and getattr(proxy, 'supports_ipv6', False):
            feature_bonuses += 5
        
        # UDP support (for SOCKS5)
        if proxy.protocol == ProxyProtocol.SOCKS5:
            if hasattr(proxy, 'supports_udp') and getattr(proxy, 'supports_udp', False):
                feature_bonuses += 5
        
        return min(100, base_score + feature_bonuses)
    
    def _calculate_weighted_score(self, metrics: QualityMetrics) -> float:
        """Calculate weighted overall quality score"""
        
        weighted_score = (
            metrics.performance_score * self.scoring_weights['performance'] +
            metrics.reliability_score * self.scoring_weights['reliability'] +
            metrics.security_score * self.scoring_weights['security'] +
            metrics.geographic_score * self.scoring_weights['geographic'] +
            metrics.protocol_score * self.scoring_weights['protocol']
        )
        
        return round(weighted_score, 2)
    
    def _determine_quality_tier(self, overall_score: float) -> QualityTier:
        """Determine quality tier based on overall score"""
        
        if overall_score >= 90:
            return QualityTier.PREMIUM
        elif overall_score >= 80:
            return QualityTier.EXCELLENT
        elif overall_score >= 70:
            return QualityTier.GOOD
        elif overall_score >= 60:
            return QualityTier.AVERAGE
        elif overall_score >= 40:
            return QualityTier.POOR
        else:
            return QualityTier.UNRELIABLE
    
    def _calculate_confidence_level(self, proxy: ProxyInfo,
                                  historical_data: List[Dict] = None) -> float:
        """Calculate confidence level in the quality score (0-100)"""
        
        confidence = 50.0  # Base confidence
        
        # Sample size confidence
        sample_size = len(historical_data) if historical_data else 1
        if sample_size >= self.config['min_samples_for_confidence']:
            confidence += 30
        else:
            confidence += (sample_size / self.config['min_samples_for_confidence']) * 30
        
        # Data recency confidence
        if historical_data:
            timestamps = [d.get('timestamp') for d in historical_data if d.get('timestamp')]
            if timestamps:
                most_recent = max(timestamps)
                age_hours = (datetime.now().timestamp() - most_recent) / 3600
                if age_hours <= 24:
                    confidence += 20  # Recent data bonus
                elif age_hours <= 168:  # 1 week
                    confidence += 10
        
        return min(100, confidence)
    
    def _get_performance_breakdown(self, proxy: ProxyInfo,
                                 historical_data: List[Dict] = None) -> Dict[str, float]:
        """Get detailed performance score breakdown"""
        
        breakdown = {}
        
        if historical_data:
            response_times = [d.get('response_time_ms', 0) for d in historical_data if d.get('response_time_ms', 0) > 0]
            if response_times:
                breakdown['avg_response_time_ms'] = statistics.mean(response_times)
                breakdown['median_response_time_ms'] = statistics.median(response_times)
                breakdown['response_time_std'] = statistics.stdev(response_times) if len(response_times) > 1 else 0
        
        return breakdown
    
    def _get_reliability_breakdown(self, proxy: ProxyInfo,
                                 historical_data: List[Dict] = None) -> Dict[str, float]:
        """Get detailed reliability score breakdown"""
        
        breakdown = {}
        
        if historical_data:
            uptime_values = [d.get('uptime_percentage', 0) for d in historical_data if d.get('uptime_percentage', 0) > 0]
            if uptime_values:
                breakdown['avg_uptime_percentage'] = statistics.mean(uptime_values)
                breakdown['min_uptime_percentage'] = min(uptime_values)
                breakdown['max_uptime_percentage'] = max(uptime_values)
        
        return breakdown
    
    def _get_security_breakdown(self, proxy: ProxyInfo) -> Dict[str, Any]:
        """Get detailed security score breakdown"""
        
        breakdown = {}
        
        if hasattr(proxy, 'anonymity_level') and proxy.anonymity_level:
            breakdown['anonymity_level'] = proxy.anonymity_level.value
        
        if hasattr(proxy, 'threat_level') and proxy.threat_level:
            breakdown['threat_level'] = proxy.threat_level.value
        
        if hasattr(proxy, 'threat_categories') and proxy.threat_categories:
            breakdown['threat_categories'] = proxy.threat_categories
        
        if hasattr(proxy, 'reputation_score') and proxy.reputation_score is not None:
            breakdown['reputation_score'] = proxy.reputation_score
        
        return breakdown
    
    def _proxy_to_dict(self, proxy: ProxyInfo) -> Dict[str, Any]:
        """Convert proxy info to dictionary for processing"""
        
        data = {
            'host': proxy.host,
            'port': proxy.port,
            'protocol': proxy.protocol.value if proxy.protocol else None,
            'timestamp': datetime.now().timestamp()
        }
        
        # Add optional fields
        optional_fields = [
            'response_time_ms', 'uptime_percentage', 'validation_status',
            'anonymity_level', 'threat_level', 'reputation_score'
        ]
        
        for field in optional_fields:
            if hasattr(proxy, field):
                value = getattr(proxy, field)
                if value is not None:
                    if hasattr(value, 'value'):  # Enum
                        data[field] = value.value
                    else:
                        data[field] = value
        
        return data


class QualityScoreManager:
    """Manager for proxy quality scoring operations"""
    
    def __init__(self, scoring_engine: QualityScoringEngine = None):
        self.scoring_engine = scoring_engine or QualityScoringEngine()
        self.score_cache = {}
        self.cache_ttl = timedelta(hours=1)
    
    async def score_proxy(self, proxy: ProxyInfo, 
                         historical_data: List[Dict] = None,
                         use_cache: bool = True) -> QualityMetrics:
        """Score a single proxy with caching"""
        
        cache_key = f"{proxy.host}:{proxy.port}"
        
        # Check cache
        if use_cache and cache_key in self.score_cache:
            cached_metrics, cached_time = self.score_cache[cache_key]
            if datetime.now() - cached_time < self.cache_ttl:
                return cached_metrics
        
        # Calculate new score
        metrics = await self.scoring_engine.calculate_quality_score(proxy, historical_data)
        
        # Cache result
        if use_cache:
            self.score_cache[cache_key] = (metrics, datetime.now())
        
        return metrics
    
    async def score_proxy_batch(self, proxies: List[ProxyInfo],
                              historical_data_map: Dict[str, List[Dict]] = None) -> Dict[str, QualityMetrics]:
        """Score multiple proxies efficiently"""
        
        results = {}
        tasks = []
        
        for proxy in proxies:
            cache_key = f"{proxy.host}:{proxy.port}"
            historical_data = historical_data_map.get(cache_key, []) if historical_data_map else []
            
            task = self.score_proxy(proxy, historical_data, use_cache=True)
            tasks.append((cache_key, task))
        
        # Execute all scoring tasks concurrently
        for cache_key, task in tasks:
            try:
                metrics = await task
                results[cache_key] = metrics
            except Exception as e:
                logging.error(f"Error scoring proxy {cache_key}: {e}")
                results[cache_key] = QualityMetrics()  # Default metrics
        
        return results
    
    def get_quality_summary(self, metrics_map: Dict[str, QualityMetrics]) -> Dict[str, Any]:
        """Generate summary statistics for a set of quality metrics"""
        
        if not metrics_map:
            return {}
        
        scores = [m.overall_score for m in metrics_map.values()]
        tier_counts = {}
        
        for metrics in metrics_map.values():
            tier = metrics.quality_tier.value
            tier_counts[tier] = tier_counts.get(tier, 0) + 1
        
        return {
            'total_proxies': len(metrics_map),
            'average_score': statistics.mean(scores),
            'median_score': statistics.median(scores),
            'score_std': statistics.stdev(scores) if len(scores) > 1 else 0,
            'tier_distribution': tier_counts,
            'high_quality_percentage': sum(1 for s in scores if s >= 80) / len(scores) * 100
        }