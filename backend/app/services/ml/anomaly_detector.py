"""Anomaly Detection - Phase 4.

Uses Isolation Forest for unsupervised anomaly detection.
Identifies unusual patterns in security configurations.

IMPORTANT: Anomaly detection enhances but does NOT replace
deterministic security analysis. If ML fails, core forensics
continues unaffected.
"""
import logging
import pickle
from pathlib import Path
from typing import Optional
import numpy as np

from app.services.ml.models import (
    FeatureVector,
    AnomalyResult,
    MLPredictionResult,
    ModelType,
    PredictionType,
    ModelMetadata,
    MLInsights,
)

logger = logging.getLogger(__name__)

# Model version
MODEL_VERSION = "1.0.0"
MODEL_NAME = "isolation_forest_anomaly"


class AnomalyDetector:
    """
    Anomaly detection using Isolation Forest.

    Identifies sessions with unusual security configurations
    that may warrant additional investigation.

    The detector can:
    1. Fit on session features (training)
    2. Predict anomalies on new sessions
    3. Provide explainability for detected anomalies
    """

    # Default contamination (expected proportion of anomalies)
    DEFAULT_CONTAMINATION = 0.1

    # Anomaly threshold (scores below this are anomalies)
    ANOMALY_THRESHOLD = 0.0

    def __init__(
        self,
        contamination: float = DEFAULT_CONTAMINATION,
        random_state: int = 42,
    ):
        """
        Initialize the anomaly detector.

        Args:
            contamination: Expected proportion of anomalies (0.0-0.5)
            random_state: Random seed for reproducibility
        """
        self.contamination = contamination
        self.random_state = random_state
        self._model = None
        self._is_fitted = False
        self._feature_means: Optional[np.ndarray] = None
        self._feature_stds: Optional[np.ndarray] = None

    def _ensure_sklearn(self):
        """Ensure scikit-learn is available."""
        try:
            from sklearn.ensemble import IsolationForest
            return IsolationForest
        except ImportError:
            logger.warning("scikit-learn not available, anomaly detection disabled")
            return None

    def fit(
        self,
        feature_vectors: list[FeatureVector],
    ) -> bool:
        """
        Fit the anomaly detector on feature vectors.

        Args:
            feature_vectors: List of feature vectors for training

        Returns:
            True if fitting succeeded, False otherwise
        """
        IsolationForest = self._ensure_sklearn()
        if IsolationForest is None:
            return False

        if len(feature_vectors) < 5:
            logger.warning("Not enough samples for anomaly detection training")
            return False

        try:
            # Convert to numpy array
            X = np.array([fv.to_array() for fv in feature_vectors])

            # Store feature statistics for explainability
            self._feature_means = np.mean(X, axis=0)
            self._feature_stds = np.std(X, axis=0) + 1e-10  # Avoid division by zero

            # Create and fit model
            self._model = IsolationForest(
                contamination=self.contamination,
                random_state=self.random_state,
                n_estimators=100,
                max_samples='auto',
            )
            self._model.fit(X)
            self._is_fitted = True

            logger.info(f"Anomaly detector fitted on {len(feature_vectors)} samples")
            return True

        except Exception as e:
            logger.error(f"Failed to fit anomaly detector: {e}")
            return False

    def predict(
        self,
        feature_vector: FeatureVector,
    ) -> AnomalyResult:
        """
        Predict if a single sample is an anomaly.

        Args:
            feature_vector: Feature vector to check

        Returns:
            Anomaly result with score and explanation
        """
        if not self._is_fitted or self._model is None:
            return AnomalyResult(
                target_type=feature_vector.target_type,
                target_id=feature_vector.target_id,
                is_anomaly=False,
                anomaly_score=0.0,
                explanation="Anomaly detector not fitted",
                confidence=0.0,
            )

        try:
            # Convert to array
            X = np.array([feature_vector.to_array()])

            # Get prediction (-1 = anomaly, 1 = normal)
            prediction = self._model.predict(X)[0]

            # Get anomaly score (lower = more anomalous)
            score = self._model.decision_function(X)[0]

            # Identify anomalous features
            anomalous_features = self._identify_anomalous_features(
                feature_vector, X[0]
            )

            # Generate explanation
            explanation = self._generate_explanation(
                feature_vector,
                prediction == -1,
                anomalous_features,
            )

            return AnomalyResult(
                target_type=feature_vector.target_type,
                target_id=feature_vector.target_id,
                is_anomaly=prediction == -1,
                anomaly_score=float(score),
                anomalous_features=anomalous_features,
                explanation=explanation,
                confidence=self._calculate_confidence(score),
            )

        except Exception as e:
            logger.error(f"Anomaly prediction failed: {e}")
            return AnomalyResult(
                target_type=feature_vector.target_type,
                target_id=feature_vector.target_id,
                is_anomaly=False,
                anomaly_score=0.0,
                explanation=f"Prediction error: {str(e)}",
                confidence=0.0,
            )

    def predict_batch(
        self,
        feature_vectors: list[FeatureVector],
    ) -> list[AnomalyResult]:
        """
        Predict anomalies for multiple samples.

        Args:
            feature_vectors: List of feature vectors

        Returns:
            List of anomaly results
        """
        return [self.predict(fv) for fv in feature_vectors]

    def _identify_anomalous_features(
        self,
        feature_vector: FeatureVector,
        feature_array: np.ndarray,
    ) -> list[str]:
        """Identify which features are anomalous (>2 std from mean)."""
        if self._feature_means is None or self._feature_stds is None:
            return []

        feature_names = FeatureVector.feature_names()
        anomalous = []

        z_scores = (feature_array - self._feature_means) / self._feature_stds

        for i, (name, z) in enumerate(zip(feature_names, z_scores)):
            if abs(z) > 2.0:  # More than 2 standard deviations
                anomalous.append(name)

        return anomalous

    def _generate_explanation(
        self,
        feature_vector: FeatureVector,
        is_anomaly: bool,
        anomalous_features: list[str],
    ) -> str:
        """Generate human-readable explanation."""
        if not is_anomaly:
            return "Session security configuration is within normal parameters."

        explanations = []

        # Check specific anomalous conditions
        if feature_vector.is_plaintext:
            explanations.append("Uses plaintext communication (no TLS)")

        if feature_vector.cert_is_self_signed:
            explanations.append("Uses self-signed certificate")

        if feature_vector.cert_validity_days < 0:
            explanations.append("Certificate is expired")

        if feature_vector.tls_version_score < 0.5:
            explanations.append("Uses deprecated TLS version")

        if feature_vector.cipher_strength_score < 0.5:
            explanations.append("Uses weak cipher suite")

        if not feature_vector.forward_secrecy:
            explanations.append("Lacks forward secrecy")

        if feature_vector.critical_count > 0:
            explanations.append(f"Has {feature_vector.critical_count} critical finding(s)")

        if anomalous_features and not explanations:
            explanations.append(
                f"Unusual values for: {', '.join(anomalous_features[:3])}"
            )

        if explanations:
            return "Anomalous session: " + "; ".join(explanations)
        else:
            return "Session flagged as anomalous based on overall feature pattern."

    def _calculate_confidence(self, score: float) -> float:
        """Calculate confidence based on anomaly score."""
        # Normalize score to 0-1 confidence
        # More negative scores = higher confidence in anomaly
        # More positive scores = higher confidence in normality
        if score < -0.5:
            return 0.9
        elif score < -0.2:
            return 0.7
        elif score < 0:
            return 0.5
        elif score < 0.2:
            return 0.6
        else:
            return 0.8

    def get_ml_insights(
        self,
        anomaly_results: list[AnomalyResult],
    ) -> MLInsights:
        """
        Generate ML insights from anomaly detection results.

        Args:
            anomaly_results: Results from anomaly detection

        Returns:
            ML insights summary
        """
        if not anomaly_results:
            return MLInsights(
                ml_enabled=False,
                summary="No anomaly detection performed.",
            )

        anomalies = [r for r in anomaly_results if r.is_anomaly]
        anomalies_sorted = sorted(anomalies, key=lambda x: x.anomaly_score)

        # Aggregate anomalous features
        feature_counts: dict[str, int] = {}
        for r in anomalies:
            for feat in r.anomalous_features:
                feature_counts[feat] = feature_counts.get(feat, 0) + 1

        top_factors = sorted(
            feature_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        # Calculate average confidence
        avg_confidence = (
            sum(r.confidence for r in anomaly_results) / len(anomaly_results)
            if anomaly_results else 0.0
        )

        # Generate summary
        if len(anomalies) == 0:
            summary = "No anomalous sessions detected."
        else:
            summary = (
                f"Detected {len(anomalies)} anomalous session(s) out of "
                f"{len(anomaly_results)} analyzed."
            )

        return MLInsights(
            ml_enabled=True,
            model_version=MODEL_VERSION,
            total_predictions=len(anomaly_results),
            anomalies_detected=len(anomalies),
            top_anomalies=anomalies_sorted[:5],
            top_risk_factors=top_factors,
            overall_confidence=avg_confidence,
            summary=summary,
        )

    def save_model(self, path: Path) -> bool:
        """Save fitted model to disk."""
        if not self._is_fitted or self._model is None:
            return False

        try:
            model_data = {
                'model': self._model,
                'feature_means': self._feature_means,
                'feature_stds': self._feature_stds,
                'version': MODEL_VERSION,
            }
            with open(path, 'wb') as f:
                pickle.dump(model_data, f)
            logger.info(f"Model saved to {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            return False

    def load_model(self, path: Path) -> bool:
        """Load model from disk."""
        try:
            with open(path, 'rb') as f:
                model_data = pickle.load(f)

            self._model = model_data['model']
            self._feature_means = model_data['feature_means']
            self._feature_stds = model_data['feature_stds']
            self._is_fitted = True
            logger.info(f"Model loaded from {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False

    def get_model_metadata(self) -> ModelMetadata:
        """Get model metadata."""
        from datetime import datetime, timezone

        return ModelMetadata(
            model_name=MODEL_NAME,
            model_version=MODEL_VERSION,
            model_type=ModelType.ANOMALY_DETECTOR,
            trained_at=datetime.now(timezone.utc),
            training_samples=0,  # Would need to track this
            feature_count=len(FeatureVector.feature_names()),
            is_loaded=self._is_fitted,
            status="fitted" if self._is_fitted else "not_fitted",
        )

    @property
    def is_fitted(self) -> bool:
        """Check if model is fitted."""
        return self._is_fitted
