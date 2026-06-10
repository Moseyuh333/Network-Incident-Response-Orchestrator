"""ML-based anomaly detection with model serialization and feature scaling."""

from __future__ import annotations

import datetime
import ipaddress
import json
import logging
import pickle
from typing import Any

from app.core.paths import PI_DIR

logger = logging.getLogger("niro.detection")

MODEL_PATH = PI_DIR / "data" / "models" / "anomaly_model.pkl"
SCALER_PATH = PI_DIR / "data" / "models" / "anomaly_scaler.pkl"
METADATA_PATH = PI_DIR / "data" / "models" / "anomaly_metadata.json"


class AnomalyDetector:
    """ML anomaly detector using IsolationForest and StandardScaler.

    Loads persisted model/scaler if available, otherwise runs heuristic fallback.
    """

    def __init__(self) -> None:
        self.model = None
        self.scaler = None
        self.metadata: dict[str, Any] = {}
        self.model_loaded = False
        
        try:
            from sklearn.ensemble import IsolationForest  # type: ignore[import-untyped]
            from sklearn.preprocessing import StandardScaler  # type: ignore[import-untyped]
            import numpy as np
            self._np = np
            self._IsolationForest = IsolationForest
            self._StandardScaler = StandardScaler
            self._sklearn_available = True
        except ImportError:
            self._sklearn_available = False
            logger.warning("scikit-learn or numpy not installed. ML anomaly detection will use heuristic fallback.")

        self.load_model()

    def load_model(self) -> None:
        """Load the persisted model, scaler, and metadata."""
        if not self._sklearn_available:
            return
        try:
            if MODEL_PATH.exists() and SCALER_PATH.exists() and METADATA_PATH.exists():
                with MODEL_PATH.open("rb") as f:
                    self.model = pickle.load(f)
                with SCALER_PATH.open("rb") as f:
                    self.scaler = pickle.load(f)
                with METADATA_PATH.open("r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                self.model_loaded = True
                logger.info("Persisted ML model version %s loaded", self.metadata.get("version", "unknown"))
        except Exception as e:
            logger.error("Failed to load persisted ML model: %s", e)
            self.model_loaded = False

    def save_model(self, model: Any, scaler: Any, metadata: dict[str, Any]) -> None:
        """Persist the trained model, scaler, and metadata."""
        if not self._sklearn_available:
            return
        try:
            MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
            with MODEL_PATH.open("wb") as f:
                pickle.dump(model, f)
            with SCALER_PATH.open("wb") as f:
                pickle.dump(scaler, f)
            with METADATA_PATH.open("w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2, default=str)
            
            self.model = model
            self.scaler = scaler
            self.metadata = metadata
            self.model_loaded = True
            logger.info("ML model version %s persisted successfully", metadata["version"])
        except Exception as e:
            logger.error("Failed to persist ML model: %s", e)

    def extract_features(self, events: list[dict[str, Any]]) -> list[list[float]]:
        """Extract numeric features from events (excluding IP hashes)."""
        features = []
        for e in events:
            # Protocol number
            proto = str(e.get("protocol") or "").upper()
            proto_num = 6.0 if proto == "TCP" else (17.0 if proto == "UDP" else (1.0 if proto == "ICMP" else 0.0))
            
            # RFC1918 flags
            src_ip = str(e.get("source_ip") or "")
            dst_ip = str(e.get("destination_ip") or "")
            src_private = 1.0 if self._is_private(src_ip) else 0.0
            dst_private = 1.0 if self._is_private(dst_ip) else 0.0

            # Hour of day
            ts = e.get("timestamp")
            if isinstance(ts, str):
                try:
                    dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    hour = float(dt.hour)
                except ValueError:
                    hour = 12.0
            elif isinstance(ts, datetime.datetime):
                hour = float(ts.hour)
            else:
                hour = 12.0

            features.append([
                float(e.get("source_port") or 0),
                float(e.get("destination_port") or 0),
                float(e.get("bytes_in") or 0),
                float(e.get("bytes_out") or 0),
                proto_num,
                src_private,
                dst_private,
                hour
            ])
        return features

    def score(self, events: list[dict[str, Any]]) -> list[float]:
        """Score events: higher is more anomalous (range 0.0 to 1.0)."""
        if not events:
            return []
        if not self._sklearn_available or not self.model_loaded or not self.scaler:
            return self._heuristic_scores(events)
        
        try:
            features = self.extract_features(events)
            scaled = self.scaler.transform(features)
            raw = self.model.decision_function(scaled)
            # IsolationForest decision_function: lower = more anomalous
            # Map typical IF range [-0.5, 0.5] to [0, 1] where 1 is highly anomalous
            scores = []
            for r in raw:
                score = 1.0 - (r + 0.5)
                scores.append(max(0.0, min(1.0, score)))
            return scores
        except Exception as e:
            logger.error("ML inference failed, falling back to heuristics: %s", e)
            return self._heuristic_scores(events)

    def find_anomalies(self, events: list[dict[str, Any]], threshold: float) -> list[dict[str, Any]]:
        """Run anomaly detector and wrap anomalous events as findings."""
        findings = []
        scores = self.score(events)
        is_ml = self._sklearn_available and self.model_loaded

        for event, score in zip(events, scores, strict=False):
            if score < threshold:
                continue
            
            explanation = (
                f"ML Anomaly detected (score: {score:.4f}). "
                f"Features analyzed: Ports ({event.get('source_port')}->{event.get('destination_port')}), "
                f"Bytes (In: {event.get('bytes_in', 0)}, Out: {event.get('bytes_out', 0)})."
            ) if is_ml else (
                f"Heuristic Anomaly detected (score: {score:.2f}). "
                f"Triggered by high bytes_out ({event.get('bytes_out', 0)}) or sensitive ports."
            )

            findings.append({
                "finding_id": f"FND-ML-{id(event) % 100000:05d}",
                "detector_id": "ml-anomaly-detector",
                "detector_version": self.metadata.get("version", "1.0.0-fallback"),
                "incident_type": "Anomalous Network Activity",
                "severity": "critical" if score >= 0.95 else "high",
                "confidence": round(score, 4),
                "source_ip": event.get("source_ip") or "",
                "destination_ip": event.get("destination_ip"),
                "evidence": [
                    f"Anomaly score {score:.2f} exceeded threshold {threshold:.2f}",
                    explanation,
                    f"Model status: {'active' if is_ml else 'unavailable (heuristic fallback)'}"
                ],
                "recommended_actions": [
                    "Recommend firewall block for source IP",
                    "Isolate target host from internal networks",
                    "Review full packet capture features"
                ],
                "ml_score": round(score, 4),
                "explanation": explanation
            })
        return findings

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return True

    @staticmethod
    def _heuristic_scores(events: list[dict[str, Any]]) -> list[float]:
        scores = []
        sensitive_ports = {22, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200}
        for event in events:
            bytes_out = float(event.get("bytes_out") or 0)
            dst_port = int(event.get("destination_port") or 0)
            score = 0.05
            if bytes_out >= 100 * 1024 * 1024:
                score += 0.90
            elif bytes_out >= 10 * 1024 * 1024:
                score += 0.60
            if dst_port in sensitive_ports:
                score += 0.20
            scores.append(max(0.0, min(1.0, score)))
        return scores


# Singleton
anomaly_detector = AnomalyDetector()
