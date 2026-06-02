"""Optional ML-based anomaly detection using scikit-learn."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("niro.detection")


class AnomalyDetector:
    """Lightweight anomaly detector based on IsolationForest.

    Requires scikit-learn to be installed. Gracefully degrades when not available.
    """

    def __init__(self) -> None:
        self._model = None
        self._fitted = False
        try:
            from sklearn.ensemble import IsolationForest  # type: ignore[import-untyped]
            self._model_cls = IsolationForest
            self._sklearn_available = True
            logger.info("scikit-learn available: ML anomaly detection enabled")
        except ImportError:
            self._sklearn_available = False
            logger.info("scikit-learn not installed: ML anomaly detection disabled")

    def fit(self, events: list[dict[str, Any]]) -> None:
        """Fit the model on event feature vectors."""
        if not self._sklearn_available or not events:
            return
        features = self._extract_features(events)
        if not features:
            return
        self._model = self._model_cls(contamination=0.1, random_state=42)
        self._model.fit(features)
        self._fitted = True
        logger.info("Anomaly detector fitted on %d events", len(events))

    def score(self, events: list[dict[str, Any]]) -> list[float]:
        """Return anomaly scores (higher = more anomalous). Returns empty list if unavailable."""
        if not self._sklearn_available or not self._fitted or not events:
            return []
        features = self._extract_features(events)
        if not features:
            return []
        # IsolationForest: -1 = anomaly, 1 = normal; convert to 0–1 score
        raw = self._model.decision_function(features)
        # decision_function: lower = more anomalous → invert
        scores = [max(0.0, min(1.0, (1.0 - (r + 1) / 2))) for r in raw]
        return scores

    @staticmethod
    def _extract_features(events: list[dict[str, Any]]) -> list[list[float]]:
        """Extract simple numeric features from events."""
        features: list[list[float]] = []
        for e in events:
            features.append([
                float(e.get("source_port") or 0),
                float(e.get("destination_port") or 0),
                float(e.get("bytes_in", 0)),
                float(e.get("bytes_out", 0)),
                float(hash(e.get("source_ip", "")) % 65535),
                float(hash(e.get("destination_ip", "")) % 65535),
            ])
        return features


# Singleton
anomaly_detector = AnomalyDetector()
