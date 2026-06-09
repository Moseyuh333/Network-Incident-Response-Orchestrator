"""Optional ML-based anomaly detection using scikit-learn."""

from __future__ import annotations

import logging
import ipaddress
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
        """Return anomaly scores (higher = more anomalous)."""
        if not events:
            return []
        if not self._sklearn_available or not self._fitted:
            return self._heuristic_scores(events)
        features = self._extract_features(events)
        if not features:
            return []
        # IsolationForest: -1 = anomaly, 1 = normal; convert to 0–1 score
        raw = self._model.decision_function(features)
        # decision_function: lower = more anomalous → invert
        scores = [max(0.0, min(1.0, (1.0 - (r + 1) / 2))) for r in raw]
        return scores

    def find_anomalies(self, events: list[dict[str, Any]], threshold: float) -> list[dict[str, Any]]:
        """Convert high anomaly scores into detection findings."""
        findings: list[dict[str, Any]] = []
        for event, score in zip(events, self.score(events), strict=False):
            if score < threshold:
                continue
            findings.append({
                "incident_type": "Anomalous Network Activity",
                "severity": "high" if score < 0.98 else "critical",
                "confidence": round(score, 4),
                "source_ip": event.get("source_ip") or "",
                "destination_ip": event.get("destination_ip"),
                "evidence": [
                    f"ML anomaly score {score:.2f} exceeded threshold {threshold:.2f}",
                    f"Destination port: {event.get('destination_port', 'unknown')}",
                    f"Bytes out: {event.get('bytes_out', 0)}",
                ],
                "recommended_actions": [
                    "Review related network flows",
                    "Correlate with endpoint telemetry",
                    "Recommend containment only after analyst approval",
                ],
                "ml_score": round(score, 4),
            })
        return findings

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
                float(_ip_to_numeric(e.get("source_ip", ""))),
                float(_ip_to_numeric(e.get("destination_ip", ""))),
            ])
        return features

    @staticmethod
    def _heuristic_scores(events: list[dict[str, Any]]) -> list[float]:
        """Deterministic fallback scoring when no fitted sklearn model exists."""
        scores: list[float] = []
        sensitive_ports = {22, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200}
        for event in events:
            bytes_out = float(event.get("bytes_out") or 0)
            destination_port = int(event.get("destination_port") or 0)
            score = 0.0
            if bytes_out >= 100 * 1_048_576:
                score += 0.95
            elif bytes_out >= 50 * 1_048_576:
                score += 0.75
            elif bytes_out >= 10 * 1_048_576:
                score += 0.45
            if destination_port in sensitive_ports:
                score += 0.12
            if event.get("event_type") in {"dns", "http"} and bytes_out >= 25 * 1_048_576:
                score += 0.08
            scores.append(max(0.0, min(1.0, score)))
        return scores


def _ip_to_numeric(value: Any) -> int:
    try:
        return int(ipaddress.ip_address(str(value))) % 65535
    except ValueError:
        return 0


# Singleton
anomaly_detector = AnomalyDetector()
