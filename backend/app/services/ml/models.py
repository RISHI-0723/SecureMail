"""ML Service Models - Phase 4.

Pydantic models for ML feature vectors, predictions, and model metadata.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field
import uuid


class ModelType(str, Enum):
    """Types of ML models."""
    RISK_CLASSIFIER = "risk_classifier"
    ANOMALY_DETECTOR = "anomaly_detector"


class PredictionType(str, Enum):
    """Types of ML predictions."""
    RISK_LEVEL = "risk_level"
    ANOMALY_SCORE = "anomaly_score"


def generate_feature_id() -> str:
    """Generate unique feature set ID."""
    return f"feat_{uuid.uuid4().hex[:12]}"


def generate_prediction_id() -> str:
    """Generate unique prediction ID."""
    return f"pred_{uuid.uuid4().hex[:12]}"


class FeatureVector(BaseModel):
    """Feature vector for ML models."""
    feature_id: str = Field(default_factory=generate_feature_id)

    # Target identifier
    target_type: str  # session, certificate, stream
    target_id: str

    # TLS Features
    tls_version_score: float = 0.0  # 0 (bad) to 1 (good)
    cipher_strength_score: float = 0.0
    key_exchange_score: float = 0.0
    forward_secrecy: bool = False

    # Certificate Features
    cert_validity_days: float = 0.0
    cert_key_strength: float = 0.0
    cert_is_self_signed: bool = False
    cert_chain_length: int = 0

    # Protocol Features
    uses_starttls: bool = False
    starttls_success: bool = False
    uses_implicit_tls: bool = False
    is_plaintext: bool = False

    # Finding Features
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    # Risk Features
    risk_score: float = 0.0
    max_severity_score: float = 0.0

    # Derived Features
    security_score: float = 0.0  # Composite score

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_array(self) -> list[float]:
        """Convert to numeric array for ML models."""
        return [
            self.tls_version_score,
            self.cipher_strength_score,
            self.key_exchange_score,
            1.0 if self.forward_secrecy else 0.0,
            self.cert_validity_days / 365.0,  # Normalize to years
            self.cert_key_strength,
            1.0 if self.cert_is_self_signed else 0.0,
            float(self.cert_chain_length),
            1.0 if self.uses_starttls else 0.0,
            1.0 if self.starttls_success else 0.0,
            1.0 if self.uses_implicit_tls else 0.0,
            1.0 if self.is_plaintext else 0.0,
            float(self.finding_count),
            float(self.critical_count),
            float(self.high_count),
            float(self.medium_count),
            float(self.low_count),
            self.risk_score / 100.0,  # Normalize
            self.max_severity_score,
            self.security_score / 100.0,
        ]

    @staticmethod
    def feature_names() -> list[str]:
        """Get feature names for explainability."""
        return [
            "tls_version_score",
            "cipher_strength_score",
            "key_exchange_score",
            "forward_secrecy",
            "cert_validity_years",
            "cert_key_strength",
            "cert_is_self_signed",
            "cert_chain_length",
            "uses_starttls",
            "starttls_success",
            "uses_implicit_tls",
            "is_plaintext",
            "finding_count",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
            "risk_score_normalized",
            "max_severity_score",
            "security_score_normalized",
        ]


class MLPredictionResult(BaseModel):
    """Result of ML prediction."""
    prediction_id: str = Field(default_factory=generate_prediction_id)

    # Model info
    model_name: str
    model_version: str
    model_type: ModelType

    # Prediction
    prediction_type: PredictionType
    predicted_value: Optional[str] = None
    predicted_score: Optional[float] = None
    confidence: float = 0.0

    # Anomaly detection specific
    is_anomaly: bool = False
    anomaly_score: float = 0.0

    # Explainability
    feature_importance: dict[str, float] = Field(default_factory=dict)
    explanation: Optional[str] = None

    # Target
    target_type: str
    target_id: str

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AnomalyResult(BaseModel):
    """Result of anomaly detection."""
    target_type: str
    target_id: str

    is_anomaly: bool
    anomaly_score: float  # -1 to 1, lower is more anomalous

    # Contributing factors
    anomalous_features: list[str] = Field(default_factory=list)
    explanation: str = ""

    # Confidence
    confidence: float = 0.0

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ModelMetadata(BaseModel):
    """Metadata for trained ML models."""
    model_name: str
    model_version: str
    model_type: ModelType

    # Training info
    trained_at: datetime
    training_samples: int
    feature_count: int

    # Performance metrics
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None

    # Model file
    model_path: Optional[str] = None
    is_loaded: bool = False

    # Status
    status: str = "trained"


class MLInsights(BaseModel):
    """ML-generated insights for intelligence report."""
    ml_enabled: bool = False
    model_version: Optional[str] = None

    # Predictions
    total_predictions: int = 0
    anomalies_detected: int = 0

    # Risk distribution from ML
    ml_risk_distribution: dict[str, int] = Field(default_factory=dict)

    # Top anomalies
    top_anomalies: list[AnomalyResult] = Field(default_factory=list)

    # Feature importance (aggregate)
    top_risk_factors: list[tuple[str, float]] = Field(default_factory=list)

    # Confidence
    overall_confidence: float = 0.0

    # Explanation
    summary: str = ""
