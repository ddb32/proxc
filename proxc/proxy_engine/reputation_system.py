#!/usr/bin/env python3
"""
Proxy Reputation Scoring System - Phase 4.2.4

Comprehensive reputation management system that tracks proxy trustworthiness,
reliability, and historical behavior to provide reputation scores and rankings.

Reputation Factors:
- Historical performance metrics
- Uptime and reliability history
- Security incident history
- User feedback and ratings
- Provider reputation
- Geographic consistency
- Compliance with standards
- Age and discovery source
"""

import asyncio
import json
import logging
import math
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union
import sqlite3
import hashlib

from ..proxy_core.models import ProxyInfo, ProxyProtocol, ThreatLevel, AnonymityLevel
from .performance_tracking import PerformanceTracker, PerformanceMetric
from .anomaly_detection import AnomalyDetectionEngine, AnomalySeverity


class ReputationTier(Enum):
    """Reputation tiers for proxies"""
    TRUSTED = "trusted"          # 90-100 score
    RELIABLE = "reliable"        # 75-89 score
    ACCEPTABLE = "acceptable"    # 60-74 score
    QUESTIONABLE = "questionable"  # 40-59 score
    UNRELIABLE = "unreliable"    # 20-39 score
    BLACKLISTED = "blacklisted"  # 0-19 score


class ReputationFactor(Enum):
    """Individual reputation factors"""
    PERFORMANCE_HISTORY = "performance_history"
    UPTIME_RELIABILITY = "uptime_reliability"
    SECURITY_RECORD = "security_record"
    USER_FEEDBACK = "user_feedback"
    PROVIDER_REPUTATION = "provider_reputation"
    GEOGRAPHIC_CONSISTENCY = "geographic_consistency"
    COMPLIANCE_RECORD = "compliance_record"
    AGE_AND_STABILITY = "age_and_stability"
    ANOMALY_FREQUENCY = "anomaly_frequency"
    RESPONSE_CONSISTENCY = "response_consistency"


@dataclass
class ReputationEvent:
    """Single reputation-affecting event"""
    timestamp: datetime
    proxy_id: str
    event_type: str
    impact_score: float  # -100 to +100
    description: str
    severity: str
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'proxy_id': self.proxy_id,
            'event_type': self.event_type,
            'impact_score': self.impact_score,
            'description': self.description,
            'severity': self.severity,
            'source': self.source,
            'metadata': json.dumps(self.metadata)
        }


@dataclass
class ReputationScore:
    """Comprehensive reputation score breakdown"""
    proxy_id: str
    overall_score: float  # 0-100
    reputation_tier: ReputationTier
    
    # Factor scores (0-100 each)
    factor_scores: Dict[ReputationFactor, float] = field(default_factory=dict)
    
    # Supporting data
    confidence_level: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)
    data_points: int = 0
    trend_direction: str = "stable"  # improving, stable, declining
    
    # Historical context
    score_history: List[Tuple[datetime, float]] = field(default_factory=list)
    recent_events: List[ReputationEvent] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'proxy_id': self.proxy_id,
            'overall_score': self.overall_score,
            'reputation_tier': self.reputation_tier.value,
            'factor_scores': {k.value: v for k, v in self.factor_scores.items()},
            'confidence_level': self.confidence_level,
            'last_updated': self.last_updated.isoformat(),
            'data_points': self.data_points,
            'trend_direction': self.trend_direction,
            'score_history': [(ts.isoformat(), score) for ts, score in self.score_history],
            'recent_events': [event.to_dict() for event in self.recent_events]
        }


class ReputationDatabase:
    """Database manager for reputation data"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self._init_database()
    
    def _init_database(self):
        """Initialize reputation database"""
        with sqlite3.connect(self.db_path) as conn:
            # Reputation events table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reputation_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    proxy_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    impact_score REAL NOT NULL,
                    description TEXT,
                    severity TEXT,
                    source TEXT,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Reputation scores table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reputation_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    proxy_id TEXT NOT NULL,
                    overall_score REAL NOT NULL,
                    reputation_tier TEXT NOT NULL,
                    factor_scores TEXT,  -- JSON
                    confidence_level REAL,
                    data_points INTEGER,
                    trend_direction TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(proxy_id)
                )
            """)
            
            # User feedback table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    proxy_id TEXT NOT NULL,
                    user_id TEXT,
                    rating INTEGER CHECK(rating >= 1 AND rating <= 5),
                    comment TEXT,
                    timestamp TEXT NOT NULL,
                    verified BOOLEAN DEFAULT FALSE
                )
            """)
            
            # Provider reputation table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS provider_reputation (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider_name TEXT NOT NULL UNIQUE,
                    reputation_score REAL DEFAULT 50.0,
                    proxy_count INTEGER DEFAULT 0,
                    last_updated TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_proxy_timestamp ON reputation_events(proxy_id, timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scores_proxy ON reputation_scores(proxy_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_proxy ON user_feedback(proxy_id)")
    
    def store_event(self, event: ReputationEvent):
        """Store a reputation event"""
        with sqlite3.connect(self.db_path) as conn:
            data = event.to_dict()
            conn.execute("""
                INSERT INTO reputation_events (timestamp, proxy_id, event_type, impact_score, 
                                             description, severity, source, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (data['timestamp'], data['proxy_id'], data['event_type'], 
                  data['impact_score'], data['description'], data['severity'], 
                  data['source'], data['metadata']))
    
    def get_events(self, proxy_id: str = None, 
                  days: int = 30, 
                  event_types: List[str] = None) -> List[ReputationEvent]:
        """Retrieve reputation events"""
        query = "SELECT timestamp, proxy_id, event_type, impact_score, description, severity, source, metadata FROM reputation_events WHERE 1=1"
        params = []
        
        if proxy_id:
            query += " AND proxy_id = ?"
            params.append(proxy_id)
        
        if days:
            cutoff_date = datetime.now() - timedelta(days=days)
            query += " AND timestamp >= ?"
            params.append(cutoff_date.isoformat())
        
        if event_types:
            placeholders = ','.join('?' * len(event_types))
            query += f" AND event_type IN ({placeholders})"
            params.extend(event_types)
        
        query += " ORDER BY timestamp DESC"
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(query, params)
            events = []
            
            for row in cursor.fetchall():
                event = ReputationEvent(
                    timestamp=datetime.fromisoformat(row[0]),
                    proxy_id=row[1],
                    event_type=row[2],
                    impact_score=row[3],
                    description=row[4],
                    severity=row[5],
                    source=row[6],
                    metadata=json.loads(row[7] or '{}')
                )
                events.append(event)
            
            return events
    
    def store_score(self, score: ReputationScore):
        """Store or update reputation score"""
        with sqlite3.connect(self.db_path) as conn:
            factor_scores_json = json.dumps({k.value: v for k, v in score.factor_scores.items()})
            
            conn.execute("""
                INSERT OR REPLACE INTO reputation_scores 
                (proxy_id, overall_score, reputation_tier, factor_scores, confidence_level, 
                 data_points, trend_direction, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (score.proxy_id, score.overall_score, score.reputation_tier.value,
                  factor_scores_json, score.confidence_level, score.data_points,
                  score.trend_direction, datetime.now().isoformat()))
    
    def get_score(self, proxy_id: str) -> Optional[ReputationScore]:
        """Retrieve reputation score"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT proxy_id, overall_score, reputation_tier, factor_scores, 
                       confidence_level, data_points, trend_direction, updated_at
                FROM reputation_scores WHERE proxy_id = ?
            """, (proxy_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            factor_scores = json.loads(row[3] or '{}')
            factor_scores_enum = {ReputationFactor(k): v for k, v in factor_scores.items()}
            
            return ReputationScore(
                proxy_id=row[0],
                overall_score=row[1],
                reputation_tier=ReputationTier(row[2]),
                factor_scores=factor_scores_enum,
                confidence_level=row[4],
                data_points=row[5],
                trend_direction=row[6],
                last_updated=datetime.fromisoformat(row[7])
            )


class ReputationScorer:
    """Core reputation scoring engine"""
    
    def __init__(self, database: ReputationDatabase,
                 performance_tracker: PerformanceTracker = None,
                 config: Dict[str, Any] = None):
        self.database = database
        self.performance_tracker = performance_tracker
        self.config = config or self._get_default_config()
        self.logger = logging.getLogger(__name__)
        
        # Factor weights for overall score calculation
        self.factor_weights = {
            ReputationFactor.PERFORMANCE_HISTORY: 0.20,
            ReputationFactor.UPTIME_RELIABILITY: 0.20,
            ReputationFactor.SECURITY_RECORD: 0.15,
            ReputationFactor.USER_FEEDBACK: 0.10,
            ReputationFactor.PROVIDER_REPUTATION: 0.10,
            ReputationFactor.GEOGRAPHIC_CONSISTENCY: 0.08,
            ReputationFactor.COMPLIANCE_RECORD: 0.07,
            ReputationFactor.AGE_AND_STABILITY: 0.05,
            ReputationFactor.ANOMALY_FREQUENCY: 0.03,
            ReputationFactor.RESPONSE_CONSISTENCY: 0.02
        }
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'score_decay_days': 90,
            'min_events_for_confidence': 10,
            'recent_events_weight': 2.0,
            'anomaly_penalty_factor': 0.8,
            'performance_threshold': 0.8,
            'trend_analysis_days': 30
        }
    
    async def calculate_reputation_score(self, proxy: ProxyInfo) -> ReputationScore:
        """Calculate comprehensive reputation score"""
        
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        # Initialize score object
        score = ReputationScore(proxy_id=proxy_id)
        
        # Calculate individual factor scores
        factor_scores = {}
        
        factor_scores[ReputationFactor.PERFORMANCE_HISTORY] = await self._score_performance_history(proxy)
        factor_scores[ReputationFactor.UPTIME_RELIABILITY] = await self._score_uptime_reliability(proxy)
        factor_scores[ReputationFactor.SECURITY_RECORD] = await self._score_security_record(proxy)
        factor_scores[ReputationFactor.USER_FEEDBACK] = await self._score_user_feedback(proxy)
        factor_scores[ReputationFactor.PROVIDER_REPUTATION] = await self._score_provider_reputation(proxy)
        factor_scores[ReputationFactor.GEOGRAPHIC_CONSISTENCY] = await self._score_geographic_consistency(proxy)
        factor_scores[ReputationFactor.COMPLIANCE_RECORD] = await self._score_compliance_record(proxy)
        factor_scores[ReputationFactor.AGE_AND_STABILITY] = await self._score_age_and_stability(proxy)
        factor_scores[ReputationFactor.ANOMALY_FREQUENCY] = await self._score_anomaly_frequency(proxy)
        factor_scores[ReputationFactor.RESPONSE_CONSISTENCY] = await self._score_response_consistency(proxy)
        
        score.factor_scores = factor_scores
        
        # Calculate weighted overall score
        overall_score = 0.0
        total_weight = 0.0
        
        for factor, factor_score in factor_scores.items():
            if factor_score is not None:  # Skip factors with no data
                weight = self.factor_weights.get(factor, 0.0)
                overall_score += factor_score * weight
                total_weight += weight
        
        # Normalize by actual weights used
        if total_weight > 0:
            score.overall_score = overall_score / total_weight
        else:
            score.overall_score = 50.0  # Default neutral score
        
        # Determine reputation tier
        score.reputation_tier = self._determine_reputation_tier(score.overall_score)
        
        # Calculate confidence level
        score.confidence_level = await self._calculate_confidence(proxy)
        
        # Get recent events for context
        score.recent_events = self.database.get_events(proxy_id, days=7)
        
        # Calculate trend direction
        score.trend_direction = await self._calculate_trend(proxy)
        
        # Set data points count
        all_events = self.database.get_events(proxy_id, days=self.config['score_decay_days'])
        score.data_points = len(all_events)
        
        return score
    
    async def _score_performance_history(self, proxy: ProxyInfo) -> float:
        """Score based on historical performance metrics"""
        
        if not self.performance_tracker:
            return None
        
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        try:
            # Get performance data for key metrics
            response_time_data = await self.performance_tracker.get_performance_history(
                proxy, PerformanceMetric.RESPONSE_TIME, days=30
            )
            
            if not response_time_data:
                return None
            
            response_times = [dp.value for dp in response_time_data]
            
            # Score based on response time performance
            avg_response_time = statistics.mean(response_times)
            
            if avg_response_time <= 100:  # Excellent
                return 95.0
            elif avg_response_time <= 300:  # Good
                return 85.0
            elif avg_response_time <= 1000:  # Average
                return 70.0
            elif avg_response_time <= 3000:  # Poor
                return 50.0
            else:  # Very poor
                return 25.0
        
        except Exception as e:
            self.logger.error(f"Error scoring performance history: {e}")
            return None
    
    async def _score_uptime_reliability(self, proxy: ProxyInfo) -> float:
        """Score based on uptime and reliability"""
        
        if not self.performance_tracker:
            # Use proxy's current uptime if available
            if hasattr(proxy, 'uptime_percentage') and proxy.uptime_percentage is not None:
                return min(100, max(0, proxy.uptime_percentage))
            return None
        
        try:
            uptime_data = await self.performance_tracker.get_performance_history(
                proxy, PerformanceMetric.UPTIME, days=30
            )
            
            if not uptime_data:
                return None
            
            uptime_values = [dp.value for dp in uptime_data]
            avg_uptime = statistics.mean(uptime_values)
            
            return min(100, max(0, avg_uptime))
        
        except Exception as e:
            self.logger.error(f"Error scoring uptime reliability: {e}")
            return None
    
    async def _score_security_record(self, proxy: ProxyInfo) -> float:
        """Score based on security incidents and threat level"""
        
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        # Base score starts high (innocent until proven guilty)
        base_score = 90.0
        
        # Check current threat level
        if hasattr(proxy, 'threat_level') and proxy.threat_level:
            threat_penalties = {
                ThreatLevel.LOW: 0,
                ThreatLevel.MEDIUM: -20,
                ThreatLevel.HIGH: -40,
                ThreatLevel.CRITICAL: -70
            }
            base_score += threat_penalties.get(proxy.threat_level, 0)
        
        # Check security events
        security_events = self.database.get_events(
            proxy_id, days=90, event_types=['security_incident', 'threat_detected', 'malware_detected']
        )
        
        # Penalty for security incidents
        for event in security_events:
            base_score += event.impact_score  # Should be negative for security incidents
        
        # Check threat categories
        if hasattr(proxy, 'threat_categories') and proxy.threat_categories:
            category_penalty = len(proxy.threat_categories) * 5  # -5 per threat category
            base_score -= category_penalty
        
        return max(0, min(100, base_score))
    
    async def _score_user_feedback(self, proxy: ProxyInfo) -> float:
        """Score based on user feedback and ratings"""
        
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        # This would query user feedback from database
        # For now, return neutral score if no feedback system
        try:
            with sqlite3.connect(self.database.db_path) as conn:
                cursor = conn.execute("""
                    SELECT rating FROM user_feedback 
                    WHERE proxy_id = ? AND timestamp >= ?
                """, (proxy_id, (datetime.now() - timedelta(days=180)).isoformat()))
                
                ratings = [row[0] for row in cursor.fetchall()]
                
                if not ratings:
                    return None  # No feedback available
                
                # Convert 1-5 rating to 0-100 score
                avg_rating = statistics.mean(ratings)
                return (avg_rating - 1) * 25  # Scale 1-5 to 0-100
        
        except Exception as e:
            self.logger.error(f"Error scoring user feedback: {e}")
            return None
    
    async def _score_provider_reputation(self, proxy: ProxyInfo) -> float:
        """Score based on provider/source reputation"""
        
        if not hasattr(proxy, 'source') or not proxy.source:
            return None
        
        # Provider reputation mapping (example)
        provider_scores = {
            'premium-proxy-service': 95.0,
            'datacenter-proxy': 85.0,
            'residential-proxy': 80.0,
            'free-proxy-list.net': 60.0,
            'unknown': 50.0,
            'suspicious-source': 20.0
        }
        
        return provider_scores.get(proxy.source, 50.0)
    
    async def _score_geographic_consistency(self, proxy: ProxyInfo) -> float:
        """Score based on geographic data consistency"""
        
        score = 50.0  # Base score
        
        # Check if geographic data is available
        geo_fields = ['country', 'city', 'latitude', 'longitude']
        available_fields = sum(1 for field in geo_fields 
                             if hasattr(proxy, field) and getattr(proxy, field))
        
        # Completeness bonus
        completeness_bonus = (available_fields / len(geo_fields)) * 30
        score += completeness_bonus
        
        # Consistency checks (simplified)
        if hasattr(proxy, 'country') and hasattr(proxy, 'city'):
            if proxy.country and proxy.city:
                # This would normally validate against geographic database
                score += 20  # Assume consistent for now
        
        return min(100, score)
    
    async def _score_compliance_record(self, proxy: ProxyInfo) -> float:
        """Score based on compliance with standards and protocols"""
        
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        base_score = 80.0  # Start with good compliance assumption
        
        # Check for compliance violations
        compliance_events = self.database.get_events(
            proxy_id, days=90, event_types=['protocol_violation', 'compliance_failure']
        )
        
        for event in compliance_events:
            base_score += event.impact_score  # Should be negative
        
        # Protocol compliance bonus
        if hasattr(proxy, 'protocol') and proxy.protocol:
            if proxy.protocol in [ProxyProtocol.HTTPS, ProxyProtocol.SOCKS5]:
                base_score += 10  # Modern protocol bonus
        
        return max(0, min(100, base_score))
    
    async def _score_age_and_stability(self, proxy: ProxyInfo) -> float:
        """Score based on proxy age and stability"""
        
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        # Check first seen date
        if hasattr(proxy, 'first_seen') and proxy.first_seen:
            age_days = (datetime.now() - proxy.first_seen).days
        else:
            # Default to checking when we first recorded an event
            earliest_event = self.database.get_events(proxy_id, days=365)
            if earliest_event:
                age_days = (datetime.now() - earliest_event[-1].timestamp).days
            else:
                age_days = 0
        
        # Age scoring (older = more established = higher score)
        if age_days >= 365:  # 1+ years
            age_score = 90.0
        elif age_days >= 180:  # 6+ months
            age_score = 80.0
        elif age_days >= 90:   # 3+ months
            age_score = 70.0
        elif age_days >= 30:   # 1+ month
            age_score = 60.0
        else:  # New proxy
            age_score = 40.0
        
        return age_score
    
    async def _score_anomaly_frequency(self, proxy: ProxyInfo) -> float:
        """Score based on frequency of anomalies"""
        
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        # Get anomaly events
        anomaly_events = self.database.get_events(
            proxy_id, days=30, event_types=['anomaly_detected', 'performance_anomaly']
        )
        
        base_score = 90.0  # Start high, reduce for anomalies
        
        # Penalty based on anomaly frequency
        if len(anomaly_events) > 10:  # High anomaly frequency
            base_score -= 40
        elif len(anomaly_events) > 5:  # Medium anomaly frequency
            base_score -= 20
        elif len(anomaly_events) > 2:  # Low anomaly frequency
            base_score -= 10
        
        return max(0, base_score)
    
    async def _score_response_consistency(self, proxy: ProxyInfo) -> float:
        """Score based on response time consistency"""
        
        if not self.performance_tracker:
            return None
        
        try:
            response_time_data = await self.performance_tracker.get_performance_history(
                proxy, PerformanceMetric.RESPONSE_TIME, days=14
            )
            
            if len(response_time_data) < 5:
                return None
            
            response_times = [dp.value for dp in response_time_data]
            
            # Calculate coefficient of variation (lower = more consistent)
            mean_time = statistics.mean(response_times)
            std_time = statistics.stdev(response_times)
            
            if mean_time == 0:
                return None
            
            cv = std_time / mean_time
            
            # Score based on consistency (lower CV = higher score)
            if cv <= 0.1:  # Very consistent
                return 95.0
            elif cv <= 0.2:  # Good consistency
                return 85.0
            elif cv <= 0.4:  # Average consistency
                return 70.0
            elif cv <= 0.6:  # Poor consistency
                return 50.0
            else:  # Very inconsistent
                return 25.0
        
        except Exception as e:
            self.logger.error(f"Error scoring response consistency: {e}")
            return None
    
    def _determine_reputation_tier(self, overall_score: float) -> ReputationTier:
        """Determine reputation tier from overall score"""
        
        if overall_score >= 90:
            return ReputationTier.TRUSTED
        elif overall_score >= 75:
            return ReputationTier.RELIABLE
        elif overall_score >= 60:
            return ReputationTier.ACCEPTABLE
        elif overall_score >= 40:
            return ReputationTier.QUESTIONABLE
        elif overall_score >= 20:
            return ReputationTier.UNRELIABLE
        else:
            return ReputationTier.BLACKLISTED
    
    async def _calculate_confidence(self, proxy: ProxyInfo) -> float:
        """Calculate confidence level in the reputation score"""
        
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        # Base confidence
        confidence = 50.0
        
        # Data quantity confidence
        all_events = self.database.get_events(proxy_id, days=90)
        if len(all_events) >= self.config['min_events_for_confidence']:
            confidence += 30
        else:
            confidence += (len(all_events) / self.config['min_events_for_confidence']) * 30
        
        # Data diversity confidence (different types of events)
        event_types = set(event.event_type for event in all_events)
        if len(event_types) >= 3:
            confidence += 20
        else:
            confidence += (len(event_types) / 3) * 20
        
        return min(100, confidence)
    
    async def _calculate_trend(self, proxy: ProxyInfo) -> str:
        """Calculate reputation trend direction"""
        
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        # Get historical scores (if available)
        # For now, analyze recent events to determine trend
        recent_events = self.database.get_events(proxy_id, days=self.config['trend_analysis_days'])
        
        if len(recent_events) < 5:
            return "stable"
        
        # Calculate trend based on impact scores over time
        positive_events = [e for e in recent_events if e.impact_score > 0]
        negative_events = [e for e in recent_events if e.impact_score < 0]
        
        positive_score = sum(e.impact_score for e in positive_events)
        negative_score = sum(e.impact_score for e in negative_events)
        
        net_score = positive_score + negative_score  # negative_score is already negative
        
        if net_score > 10:
            return "improving"
        elif net_score < -10:
            return "declining"
        else:
            return "stable"


class ReputationManager:
    """High-level reputation management system"""
    
    def __init__(self, db_path: str = None,
                 performance_tracker: PerformanceTracker = None,
                 anomaly_detector: AnomalyDetectionEngine = None):
        self.db_path = db_path or "reputation.db"
        self.database = ReputationDatabase(self.db_path)
        self.scorer = ReputationScorer(self.database, performance_tracker)
        self.anomaly_detector = anomaly_detector
        self.logger = logging.getLogger(__name__)
        
        # Event handlers
        self.event_handlers = {
            'performance_improvement': self._handle_performance_improvement,
            'performance_degradation': self._handle_performance_degradation,
            'security_incident': self._handle_security_incident,
            'uptime_achievement': self._handle_uptime_achievement,
            'anomaly_detected': self._handle_anomaly_detected
        }
    
    async def get_reputation(self, proxy: ProxyInfo, use_cache: bool = True) -> ReputationScore:
        """Get current reputation score for a proxy"""
        
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        # Check cache first
        if use_cache:
            cached_score = self.database.get_score(proxy_id)
            if cached_score and (datetime.now() - cached_score.last_updated).hours < 1:
                return cached_score
        
        # Calculate new score
        score = await self.scorer.calculate_reputation_score(proxy)
        
        # Store in database
        self.database.store_score(score)
        
        return score
    
    async def record_event(self, proxy: ProxyInfo, event_type: str,
                          impact_score: float, description: str,
                          severity: str = "medium", source: str = "system",
                          metadata: Dict[str, Any] = None):
        """Record a reputation-affecting event"""
        
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        event = ReputationEvent(
            timestamp=datetime.now(),
            proxy_id=proxy_id,
            event_type=event_type,
            impact_score=impact_score,
            description=description,
            severity=severity,
            source=source,
            metadata=metadata or {}
        )
        
        self.database.store_event(event)
        
        # Handle specific event types
        if event_type in self.event_handlers:
            await self.event_handlers[event_type](proxy, event)
        
        self.logger.info(f"Recorded reputation event: {event_type} for {proxy_id} (impact: {impact_score})")
    
    async def _handle_performance_improvement(self, proxy: ProxyInfo, event: ReputationEvent):
        """Handle performance improvement events"""
        # Could trigger re-scoring or adjust cached scores
        pass
    
    async def _handle_performance_degradation(self, proxy: ProxyInfo, event: ReputationEvent):
        """Handle performance degradation events"""
        # Could trigger alerts or flag for monitoring
        pass
    
    async def _handle_security_incident(self, proxy: ProxyInfo, event: ReputationEvent):
        """Handle security incident events"""
        # Immediate reputation impact and potential blacklisting
        proxy_id = f"{proxy.host}:{proxy.port}"
        
        if event.severity == "critical":
            # Record additional penalty event
            await self.record_event(
                proxy, "security_penalty", -50.0,
                "Critical security incident penalty",
                "critical", "security_system"
            )
    
    async def _handle_uptime_achievement(self, proxy: ProxyInfo, event: ReputationEvent):
        """Handle uptime milestone achievements"""
        # Positive reputation boost for reliability
        pass
    
    async def _handle_anomaly_detected(self, proxy: ProxyInfo, event: ReputationEvent):
        """Handle anomaly detection events"""
        # Investigate and potentially record additional events
        if self.anomaly_detector:
            # Could trigger deeper analysis
            pass
    
    async def get_rankings(self, limit: int = 100) -> List[Tuple[str, float, ReputationTier]]:
        """Get top-ranked proxies by reputation"""
        
        with sqlite3.connect(self.database.db_path) as conn:
            cursor = conn.execute("""
                SELECT proxy_id, overall_score, reputation_tier
                FROM reputation_scores
                ORDER BY overall_score DESC
                LIMIT ?
            """, (limit,))
            
            rankings = []
            for row in cursor.fetchall():
                rankings.append((row[0], row[1], ReputationTier(row[2])))
            
            return rankings
    
    async def get_reputation_summary(self) -> Dict[str, Any]:
        """Get overall reputation system summary"""
        
        with sqlite3.connect(self.database.db_path) as conn:
            # Count by tier
            cursor = conn.execute("""
                SELECT reputation_tier, COUNT(*) 
                FROM reputation_scores 
                GROUP BY reputation_tier
            """)
            tier_counts = dict(cursor.fetchall())
            
            # Average score
            cursor = conn.execute("SELECT AVG(overall_score) FROM reputation_scores")
            avg_score = cursor.fetchone()[0] or 0
            
            # Recent events
            cutoff_date = datetime.now() - timedelta(days=7)
            cursor = conn.execute("""
                SELECT COUNT(*) FROM reputation_events 
                WHERE timestamp >= ?
            """, (cutoff_date.isoformat(),))
            recent_events = cursor.fetchone()[0] or 0
        
        return {
            'total_proxies': sum(tier_counts.values()),
            'average_score': round(avg_score, 2),
            'tier_distribution': tier_counts,
            'recent_events_7d': recent_events,
            'last_updated': datetime.now().isoformat()
        }