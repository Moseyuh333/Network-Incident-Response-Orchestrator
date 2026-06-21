# Machine Learning Pipeline

This document describes the design, training, and execution of the Machine Learning (ML) anomaly detection module in N.I.R.O.

---

## 1. Feature Extraction & Engineering

Bidirectional packets from PCAPs or flow logs are processed into a standard 22-dimensional feature vector. The extraction code ensures safe defaults (handling zero duration, NaNs, infs, and empty records):

| Feature Name | Description |
|---|---|
| `duration` | Total duration of the flow in seconds |
| `tot_pkts` | Total packet count (forward + backward) |
| `tot_bytes` | Total byte count (forward + backward) |
| `fwd_bytes` | Total bytes sent in the forward direction |
| `bwd_bytes` | Total bytes sent in the backward direction |
| `fwd_pkts` | Total packets sent in the forward direction |
| `bwd_pkts` | Total packets sent in the backward direction |
| `bytes_per_sec` | Overall byte transfer rate |
| `pkts_per_sec` | Overall packet transfer rate |
| `fwd_len_mean` | Average length of forward packets |
| `fwd_len_std` | Standard deviation of forward packet lengths |
| `bwd_len_mean` | Average length of backward packets |
| `bwd_len_std` | Standard deviation of backward packet lengths |
| `flow_iat_mean` | Average inter-arrival time between packets |
| `flow_iat_std` | Standard deviation of inter-arrival times |
| `syn_count` | Number of packets with the SYN flag set |
| `ack_count` | Number of packets with the ACK flag set |
| `fin_count` | Number of packets with the FIN flag set |
| `rst_count` | Number of packets with the RST flag set |
| `psh_count` | Number of packets with the PSH flag set |
| `fwd_bwd_ratio` | Ratio of forward bytes to backward bytes |
| `active_time` | Total time the flow was actively transmitting data |

---

## 2. Model & Scaler training

- **Algorithm**: `IsolationForest` from scikit-learn. Chosen for its efficiency in unsupervised anomaly detection on tabular flow data.
- **Preprocessing**: Standard scaling using `StandardScaler`.
- **Safe Training**:
  - The scaler is fitted exclusively on normal training data (never on evaluation datasets).
  - Train-test splits are performed strictly to prevent data leakage.
  - No synthetic IP hashes are used as features, preventing the model from over-fitting to specific addresses.
- **Model Storage**: Trained model and scaler are serialized via `pickle` and saved to `models/` with metadata (training timestamp, scikit-learn version, feature names).

---

## 3. Real-Time Inference & Fallback

- **Inference**: During Phase 2 (Detection/ML), the engine passes current flow statistics to the anomaly detector. The detector calculates an anomaly score.
- **Alert Trigger**: If the IsolationForest output score exceeds `settings.ml_anomaly_threshold` (default `0.92`), a `ML Anomaly` finding is created and linked to the incident.
- **Robust Offline Fallback**: If scikit-learn/numpy dependencies are missing, or if the serialized model cannot be loaded, the pipeline logs the failure, marks ML availability as `false` or `offline`, and falls back to deterministic rule checks without interrupting the orchestration loop.
