#!/usr/bin/env python3
"""Script to train and persist the ML anomaly detection model."""

from __future__ import annotations

import datetime
import json
import logging
from sqlmodel import Session, select

from app.db.session import engine
from app.models.event import Event
from app.detection.anomaly_detector import AnomalyDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("niro.train_ml")


def train_model() -> None:
    detector = AnomalyDetector()
    if not detector._sklearn_available:
        logger.error("scikit-learn and numpy are required to train the ML model.")
        return

    logger.info("Fetching events from database to train model...")
    with Session(engine) as session:
        events = session.exec(select(Event)).all()
        
    if len(events) < 10:
        logger.warning("Very few events in database. Ingesting mock events for cold-start training...")
        # If no events, we generate some synthetic normal traffic to fit the scaler/model
        mock_events = []
        for i in range(100):
            mock_events.append({
                "source_port": 1024 + (i * 77) % 50000,
                "destination_port": 80 if i % 2 == 0 else 443,
                "bytes_in": 150 + (i * 123) % 2000,
                "bytes_out": 200 + (i * 321) % 4000,
                "protocol": "TCP",
                "source_ip": f"192.168.1.{10+i}",
                "destination_ip": "10.0.0.5",
                "timestamp": datetime.datetime.utcnow() - datetime.timedelta(minutes=i)
            })
        event_dicts = mock_events
    else:
        event_dicts = []
        for e in events:
            event_dicts.append({
                "source_port": e.source_port,
                "destination_port": e.destination_port,
                "bytes_in": e.bytes_in,
                "bytes_out": e.bytes_out,
                "protocol": e.protocol,
                "source_ip": e.source_ip,
                "destination_ip": e.destination_ip,
                "timestamp": e.timestamp
            })

    # Fit scaler and IsolationForest
    features = detector.extract_features(event_dicts)
    
    # Train / Val Split
    train_size = int(len(features) * 0.8)
    train_features = features[:train_size]
    val_features = features[train_size:]
    
    if len(train_features) < 2:
        train_features = features
        val_features = features

    logger.info("Fitting StandardScaler on %d training samples...", len(train_features))
    scaler = detector._StandardScaler()
    scaler.fit(train_features)
    
    logger.info("Training IsolationForest model...")
    model = detector._IsolationForest(contamination=0.1, random_state=42)
    scaled_train = scaler.transform(train_features)
    model.fit(scaled_train)

    # Validate
    scaled_val = scaler.transform(val_features)
    val_scores = model.decision_function(scaled_val)
    mean_val_score = float(detector._np.mean(val_scores)) if len(val_scores) > 0 else 0.0

    metadata = {
        "version": "1.1.0",
        "trained_at": datetime.datetime.utcnow().isoformat(),
        "training_samples": len(train_features),
        "validation_samples": len(val_features),
        "features": ["source_port", "destination_port", "bytes_in", "bytes_out", "protocol_num", "src_private", "dst_private", "hour"],
        "mean_validation_score": round(mean_val_score, 4)
    }

    logger.info("Persisting model, scaler, and metadata to .pi/data/models/...")
    detector.save_model(model, scaler, metadata)
    logger.info("ML training complete. Metadata: %s", json.dumps(metadata, indent=2))


if __name__ == "__main__":
    train_model()
