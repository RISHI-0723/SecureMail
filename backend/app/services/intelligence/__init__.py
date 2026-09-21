"""Phase 4 Intelligence Services.

This package contains the intelligence aggregation and analysis services:
- Intelligence Aggregator: Aggregates Phase 3 findings
- Correlation Engine: Identifies patterns across sessions
- Recommendation Engine: Generates actionable recommendations
"""
from app.services.intelligence.aggregator import IntelligenceAggregator
from app.services.intelligence.correlation_engine import CorrelationEngine
from app.services.intelligence.recommendation_engine import RecommendationEngine

__all__ = [
    "IntelligenceAggregator",
    "CorrelationEngine",
    "RecommendationEngine",
]
