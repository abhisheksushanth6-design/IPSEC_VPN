# ML Dataset, Features & Traffic Classification Specification

**SIH Problem Statement 26160 — National Technical Research Organisation (NTRO)**  
**Project**: AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

---

## 1. Overview & Objective

In encrypted IPsec VPN communications (ESP tunnels), the packet payload is encrypted under AES-GCM or AES-CBC and cannot be inspected without private key material. To perform security assessment and traffic analysis, the AI engine operates exclusively on **observable side-channel metadata, flow dynamics, statistical properties, and session fingerprints**.

This document describes:
1. The synthetic and real IPsec testbed dataset used for model evaluation.
2. The 6 supported encrypted traffic categories.
3. Feature engineering and extraction pipeline.
4. Models used for protocol classification and encrypted traffic type prediction.
5. Training, validation, and testing methodology with genuine evaluation metrics.

---

## 2. Supported IPsec VPN Configurations

The dataset represents captures generated across all supported IPsec configurations in the testbed environment:

| Configuration Dimension | Supported Values |
|-------------------------|------------------|
| **VPN Modes** | Tunnel Mode, Transport Mode |
| **IP Protocols** | IPv4, IPv6 |
| **Encryption Ciphers** | AES-128-GCM, AES-256-GCM, AES-128-CBC, AES-256-CBC, 3DES (legacy/flagged) |
| **Integrity Algorithms** | HMAC-SHA256-128, HMAC-SHA384-192, HMAC-SHA512-256, HMAC-MD5 (legacy/flagged) |
| **Diffie-Hellman Groups** | Group 2 (MODP 1024), Group 14 (MODP 2048), Group 19 (ECP 256), Group 20 (ECP 384), Group 21 (ECP 521) |
| **Perfect Forward Secrecy (PFS)** | Enabled (PFS Phase 2 DH rekey), Disabled |
| **Key Exchange** | IKEv2 (RFC 7296), IKEv1 (RFC 2409, deprecated) |

---

## 3. Supported Encrypted Traffic Classes

The AI engine classifies traffic flowing inside ESP into 6 target categories:

| Class Label | Description | Distinguishing Statistical Characteristics |
|-------------|-------------|---------------------------------------------|
| `VOIP` | Voice over IP / SIP / RTP traffic | High packet frequency (50–100 pps), small fixed packet sizes (60–200 bytes), near-zero inter-arrival time jitter, bidirectional symmetry. |
| `WEB_BROWSING` | HTTPS / HTTP Web traffic | Interactive request-response bursts, bimodal packet size distribution (small GET requests + MTU-sized responses), idle gaps between page navigations. |
| `EMAIL` | SMTP / IMAP / POP3 email sync | Periodic small polling bursts followed by medium-sized document transfers, low throughput during idle. |
| `ICMP` | Keepalive, ping, and ICMP diagnostics | Extremely low frequency (1–2 pps), strictly uniform small packet sizes (typically 64–84 bytes), low volume. |
| `VIDEO_STREAMING` | Adaptive video streaming (DASH/HLS) | High throughput, large clusters of MTU-sized packets (1400–1500 bytes), high downlink-to-uplink byte ratio (90%+ downlink), periodic buffer refill bursts (every 2–10 sec). |
| `OTHER` | Generic TCP/UDP data or bulk transfer | Uniform continuous transfers or unclassified application traffic. |

---

## 4. Feature Extraction & Engineering (Layer 05 & 06 → `FlowFeatures`, vector v2.0)

Features are computed per session from the **ESP/AH data-plane packets only** (`FlowFeatures.from_packets`); IKE control messages are excluded so that negotiation traffic cannot leak into the flow statistics. No payload byte is inspected — every feature derives from frame lengths, timestamps and direction.

| # | Feature | Meaning |
|---|---|---|
| 1 | `packet_count` | Data-plane packets in the flow |
| 2 | `byte_count` | Bytes on the wire |
| 3 | `duration` | Seconds between first and last data-plane packet |
| 4 | `mean_iat` | Mean inter-arrival time (s) |
| 5 | `iat_cv` | Coefficient of variation of the IAT ($\sigma/\mu$; isochronous VoIP ≈ 0.1, bursty chat > 1.5) |
| 6 | `small_packet_ratio` | Fraction of frames $\le 160$ bytes |
| 7 | `mtu_packet_ratio` | Fraction of frames $\ge 1200$ bytes |
| 8 | `inbound_outbound_byte_ratio` | Responder-to-initiator byte ratio |
| 9 | `packets_per_second` | Mean packet rate |
| 10 | `bytes_per_second` | Mean throughput |
| 11 | `chunk_burst_periodicity` | Period (s) of download bursts, when detected (video segment fetches) |
| 12 | `mos_score_estimate` | ITU-T G.107 E-model estimate from cadence and jitter (only meaningful for voice-like flows) |
| 13 | `direction_asymmetry` | $\lvert R-1\rvert/(R+1)$ of the byte ratio |
| 14 | `mean_packet_length` | Mean frame length |
| 15 | `packet_length_std` | Standard deviation of frame length |
| 16 | `packet_length_cv` | Coefficient of variation of frame length |
| 17 | `uplink_packet_ratio` | Fraction of packets sent by the initiator |
| 18 | `idle_gap_ratio` | Fraction of inter-arrival gaps longer than 1 s |
| 19 | `max_gap_seconds` | Longest silence |
| 20 | `length_entropy_bits` | Shannon entropy of the frame-length histogram |
| 21 | `burst_count` | Number of activity bursts |
| 22 | `median_iat` | Median inter-arrival time (s) |

The model bundle stores the exact feature-name order; `TrafficClassifier` maps the live vector by name so a feature added later cannot silently shift the columns.

---

## 5. Model Architecture & Inference

### A. Multi-Class Encrypted Traffic Classifier (uncertainty-gated ensemble)
- **Supervised model**: `RandomForestClassifier(n_estimators=300, max_depth=16, class_weight="balanced")` over the 22-feature vector, seven classes (`VOIP`, `WHATSAPP`, `EMAIL`, `WEB_BROWSING`, `ICMP`, `VIDEO_STREAMING`, `OTHER`).
- **Signature rules**: physical-constraint scores (20 ms packetisation cadence and MOS for voice, keepalive gaps for chat, command/response + MTU trains for e-mail, periodic chunk bursts for video, 1 s echo cadence for ICMP) turned into probabilities with a softmax.
- **Blend**: $P = w \cdot P_{rules} + (1-w) \cdot P_{model}$ with $w = 0.35$ while the model's top probability is $\ge 0.80$, rising linearly to $w = 0.65$ at $\le 0.50$. When the model is unsure the flow is outside its training distribution and the transferable physical rules take over; the gate is reported in the explanation trail.
- **Physical-constraint calibration**: `ICMP` is zeroed when the cadence is not ~1 s and frames are not uniformly small; `VOIP` is zeroed when jitter or the mean IAT rule out an RTP stream.
- **Abstention**: if no class reaches the 45 % floor, or the features do not come from packets, the prediction is `OTHER` with `abstained = true` — the classifier never guesses.
- **Output**: predicted class, confidence, the full class distribution, `rule_probabilities`, `ml_probabilities`, `model_version` and an explanation list (feature → value → influence → reason).

### B. Unsupervised Behavioral Anomaly Detection (supplementary)
- **Model**: `scikit-learn` Isolation Forest (`sklearn.ensemble.IsolationForest`).
- **Hyperparameters**: `n_estimators=100`, `contamination=0.05`, `random_state=42`.
- **Purpose**: Detect anomalous session characteristics (e.g. data exfiltration tunnels, high-jitter retransmissions, abnormal burst volumes). Explicitly marked as supplementary in the UI.

---

## 6. Dataset, Split & Evaluation Metrics

### A. Dataset v2.0 — provenance
- **Generator**: the software testbed (`layer01_test_environment/software_testbed.py`). Application traffic follows statistical models per class (packet sizes, cadence, bursts, direction); the IPsec framing and the encryption are **real** (RFC 4303 ESP with AES-GCM / AES-CBC+HMAC / 3DES / ChaCha20-Poly1305, IKEv1/IKEv2 exchanges). **No real user traffic** is included.
- **Featurisation**: every flow is written to a PCAP and pushed through the deployed Layer 03 → Layer 07 pipeline (`dataset_builder.features_from_pcap`), so training features and serving features are computed by the same code — no train/serve skew.
- **Size**: 1,400 flows, 200 per class, durations 5–60 s, IKE included in ~60 % of captures; produced from seven configuration profiles (tunnel/transport, AES-128/256, GCM/CBC, IPv4/IPv6, NAT-T, 3DES legacy).
- **Held-out configurations**: `PROFILE-07-TUNNEL-DOWNGRADE-IPV4` and `PROFILE-10-TUNNEL-TFC-PADDED-IPV4` are never used for training; 70 flows of each measure generalisation to unseen IPsec configurations.
- **Artifacts**: `backend/data/datasets/esp_flow_features_v2.0.csv` (+ `esp_flow_dataset_v2.0.json` manifest and sample PCAPs per class), `backend/data/models/traffic_classifier_supervised.joblib`, `backend/data/models/traffic_metrics.json`.
- **Reproduce**: `python -m app.layers.layer08_ai_ml.train_traffic_classifier --samples-per-class 200 --workers 4` (seeded; the generator is deterministic for a given seed).

### B. Data Split
- **Training Set (70 %)**: 980 flows
- **Validation Set (15 %)**: 210 flows
- **Test Set (15 %)**: 210 flows (stratified across all 7 classes, unseen seeds)

### C. Evaluation Metrics (`traffic_metrics.json`)

| Metric | Value |
|---|---|
| Test accuracy / macro-F1 (210 flows) | **1.000 / 1.000** |
| Validation accuracy | 0.995 |
| 5-fold CV macro-F1 (on train+val) | **0.995 ± 0.003** |
| Held-out configuration accuracy (140 flows) | **0.850** (macro-F1 0.843) |
| — `PROFILE-07-TUNNEL-DOWNGRADE-IPV4` | 1.00 |
| — `PROFILE-10-TUNNEL-TFC-PADDED-IPV4` | 0.70 (fixed 1200-byte TFC padding removes every length feature — the intended effect of TFC) |
| Inference latency | ≈ 84 ms per flow (300 trees, single thread) |

Per-class precision/recall/F1 on the test split are 1.00 for all seven classes (30 flows each). The perfect test score reflects that test flows come from the *same generator* as the training flows; the held-out-configuration number and the TFC-padded result are the honest indicators of how the model behaves on traffic shapes it has not seen, and the uncertainty gate exists precisely for that case (the older hand-built fixtures in `tests/backend/synthetic_traffic_generator.py`, which the model has never seen, are classified correctly with 0.69–0.87 confidence because the rules take over).

- **Zero Raw Payload Inspection**: Complies strictly with cryptographic privacy and operational reality.
