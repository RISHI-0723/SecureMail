"""Phase 4 Machine Learning Services.

This package provides ML-enhanced security analysis:
- Feature Engineering: Extract features from security data
- Model Training: Train and evaluate ML models
- Anomaly Detection: Identify anomalous patterns
- Model Inference: Apply trained models to new data

IMPORTANT: ML enhances but does NOT replace deterministic security analysis.
If ML is unavailable, core forensic analysis continues unaffected.
"""
from app.services.ml.feature_engineering import FeatureEngineer
from app.services.ml.anomaly_detector import AnomalyDetector

__all__ = [
    "FeatureEngineer",
    "AnomalyDetector",
]
