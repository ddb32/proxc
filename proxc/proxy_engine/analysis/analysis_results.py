"""Analysis Result Classes - Data structures for proxy analysis results"""

import statistics
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any

from ...proxy_core.models import OperationalGrade


class AnalysisType(Enum):
    """Types of proxy analysis"""
    GEOGRAPHIC = "geographic"
    THREAT = "threat"
    PERFORMANCE = "performance"
    NETWORK = "network"
    BEHAVIORAL = "behavioral"
    HONEYPOT = "honeypot"
    TLS = "tls"


@dataclass
class AnalysisResult:
    """Complete analysis result for a proxy"""
    proxy_id: str
    analysis_type: AnalysisType
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0
    confidence: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'proxy_id': self.proxy_id,
            'analysis_type': self.analysis_type.value,
            'success': self.success,
            'data': self.data,
            'score': self.score,
            'confidence': self.confidence,
            'timestamp': self.timestamp.isoformat(),
            'error_message': self.error_message
        }


@dataclass
class CompositeAnalysisResult:
    """Complete analysis result combining all analysis types"""
    proxy_id: str
    overall_score: float = 0.0
    overall_grade: OperationalGrade = OperationalGrade.BASIC
    geographic_analysis: Optional[AnalysisResult] = None
    threat_analysis: Optional[AnalysisResult] = None
    performance_analysis: Optional[AnalysisResult] = None
    network_analysis: Optional[AnalysisResult] = None
    behavioral_analysis: Optional[AnalysisResult] = None
    honeypot_analysis: Optional[AnalysisResult] = None
    tls_analysis: Optional[AnalysisResult] = None
    recommendations: List[str] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    
    def get_analysis_by_type(self, analysis_type: AnalysisType) -> Optional[AnalysisResult]:
        """Get specific analysis result by type"""
        type_mapping = {
            AnalysisType.GEOGRAPHIC: self.geographic_analysis,
            AnalysisType.THREAT: self.threat_analysis,
            AnalysisType.PERFORMANCE: self.performance_analysis,
            AnalysisType.NETWORK: self.network_analysis,
            AnalysisType.BEHAVIORAL: self.behavioral_analysis,
            AnalysisType.HONEYPOT: self.honeypot_analysis,
            AnalysisType.TLS: self.tls_analysis
        }
        return type_mapping.get(analysis_type)
    
    def calculate_overall_score(self) -> float:
        """Calculate overall score from successful analyses"""
        scores = []
        for analysis in [self.geographic_analysis, self.threat_analysis, 
                        self.performance_analysis, self.network_analysis, 
                        self.behavioral_analysis, self.honeypot_analysis, 
                        self.tls_analysis]:
            if analysis and analysis.success:
                scores.append(analysis.score)
        
        return statistics.mean(scores) if scores else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = {
            'proxy_id': self.proxy_id,
            'overall_score': self.overall_score,
            'overall_grade': self.overall_grade.value,
            'recommendations': self.recommendations,
            'risk_factors': self.risk_factors,
            'analyzed_at': self.analyzed_at.isoformat()
        }
        
        # Add individual analysis results
        for analysis_type in AnalysisType:
            analysis = self.get_analysis_by_type(analysis_type)
            if analysis:
                result[f'{analysis_type.value}_analysis'] = analysis.to_dict()
        
        return result