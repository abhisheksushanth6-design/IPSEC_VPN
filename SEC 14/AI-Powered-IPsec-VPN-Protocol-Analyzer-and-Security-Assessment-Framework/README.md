# AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

**Problem Statement**: SIH 26160 – National Technical Research Organisation (NTRO)  
**Track**: Cyber Security / Network Security Analysis  

---

## 1. Executive Summary

This project delivers a comprehensive, production-grade security assessment framework for IPsec VPN deployments aligned with **SIH Problem Statement 26160**.

Unlike traditional network monitoring tools that rely on cleartext payload inspection or basic port analysis, this framework analyzes observable protocol parameters, security association lifecycles, and side-channel characteristics to evaluate IPsec implementations. Most crucially, it features an **AI-powered traffic classification pipeline** capable of predicting the specific type of application traffic encapsulated inside encrypted ESP tunnels (**VoIP, WhatsApp/Messaging, E-mail, Web Browsing, ICMP, Video Streaming, and Other**) strictly using non-payload statistical flow and session features without decrypting or inspecting ciphertext.

---

## 2. 10 Functional Layers Architecture

The system is organized into **10 Functional Layers**, where each layer is strictly verified, observable, and exposed via REST APIs and the interactive dashboard:

```
[ Layer 01: IPsec VPN Test Environment ]
                   ↓
[ Layer 02: Packet Capture & Data Collection ]
                   ↓
[ Layer 03: Packet & Protocol Analysis ]
                   ↓
[ Layer 04: Security Association & Protocol State Analysis ]
                   ↓
[ Layer 05: Feature Extraction & Engineering ]
                   ↓
[ Layer 06: IPsec Session Fingerprinting ]
                   ↓
[ Layer 07: AI-Based Protocol & Traffic Classification ]
                   ↓
[ Layer 08: Security Assessment Engine ]
                   ↓
[ Layer 09: Risk Assessment & Decision Engine ]
                   ↓
[ Layer 10: Dashboard & Report Generation ]
```

| Layer # | Functional Layer | Internal Package | Operational Status | Core Capabilities |
|---|---|---|---|---|
| **01** | **IPsec VPN Test Environment** | `layer01_test_environment` | **OPERATIONAL** | Automated VM testbed orchestration (VirtualBox/StrongSwan) with 6 pre-configured SIH test profiles (Tunnel/Transport, AES-GCM, AES-CBC+HMAC, DH groups 2/14/19/20/21, PFS on/off, IPv4/IPv6). |
| **02** | **Packet Capture & Data Collection** | `layer02_packet_capture` | **OPERATIONAL** | Hypervisor NIC live packet capture and PCAP/PCAPNG ingestion interface with sanitization. |
| **03** | **Packet & Protocol Analysis** | `layer03_protocol_analysis` | **OPERATIONAL** | Deep packet decoding: IPv4, IPv6 (with Extension Headers & routing zero-length checks), IKEv1, IKEv2, ESP, AH, NAT-T (UDP 4500), and Linux SLL2. |
| **04** | **Security Association & State Analysis** | `layer04_sa_lifecycle` | **OPERATIONAL** | Deterministic tracking of IKE and Child SA state transitions, SPI correlation, rekeying cadence, key lifetimes, and anti-replay window state. |
| **05** | **Feature Extraction & Engineering** | `layer05_feature_engineering` | **OPERATIONAL** | Extracts 53 validated, versioned packet, session, and SA features with auditable lineage. |
| **06** | **IPsec Session Fingerprinting** | `layer06_session_fingerprinting` | **OPERATIONAL** | Derives compact behavioral session fingerprints from observable flow timing, sizing distributions, directionality, and burst dynamics as input to the AI pipeline. |
| **07** | **AI-Based Protocol & Traffic Classification** | `layer08_ai_ml` | **OPERATIONAL** | **Primary AI Engine**: Identifies IPsec/IKE configurations and predicts encapsulated traffic types inside encrypted ESP (`VOIP`, `WHATSAPP`, `EMAIL`, `WEB_BROWSING`, `ICMP`, `VIDEO_STREAMING`, `OTHER`) with calibrated AI confidence scores. |
| **08** | **Security Assessment Engine** | `layer09_vulnerability_engine` | **OPERATIONAL** | Deterministic evaluation of cryptographic strength, configuration compliance, SA parameters, PFS enforcement, replay protection, and 5-vector metadata exposure (Low/Medium/High). |
| **09** | **Risk Assessment & Decision Engine** | `layer10_risk_engine` | **OPERATIONAL** | Multi-criteria explainable risk scoring, 10-vector MITRE ATT&CK threat matrix, security posture index, and structured recommendations (`Finding → Evidence → Severity → Reason → Recommendation`). |
| **10** | **Dashboard & Report Generation** | `layer13_dashboard` & `layer14_reports` | **OPERATIONAL** | Responsive React 18 / Tailwind CSS dashboard and automated PDF assessment generation with provenance-attributed findings (`OBSERVED`, `PARSED`, `INFERRED`, `AI-PREDICTED`, `UNAVAILABLE`). |

*Note: Database (SQLite / SQLAlchemy) and Backend Services (FastAPI REST & WebSockets) operate internally as supporting infrastructure.*

---

## 3. AI-Based Protocol & Traffic Classification

The primary AI capability is encapsulated traffic classification inside encrypted ESP tunnels:

### Observable Feature Vector (No Payload Inspection)
The classifier extracts 13 non-payload flow statistics:
1. `packet_count`: Total packet volume in flow
2. `byte_count`: Total bytes transmitted
3. `duration`: Session duration in seconds
4. `mean_iat`: Mean packet inter-arrival time (IAT)
5. `iat_cv`: Inter-arrival time coefficient of variation ($\sigma / \mu$, jitter indicator)
6. `small_packet_ratio`: Fraction of packets $\le 160$ bytes
7. `mtu_packet_ratio`: Fraction of packets $\ge 1200$ bytes
8. `inbound_outbound_byte_ratio`: Directional asymmetry ratio
9. `packets_per_second`: Flow packet throughput rate
10. `bytes_per_second`: Flow bandwidth utilization rate
11. `chunk_burst_periodicity`: Video fragment periodicity (s)
12. `mos_score_estimate`: VoIP Mean Opinion Score estimate (ITU-T G.107 E-model)
13. `direction_asymmetry`: Normalized directional bias $|R - 1| / (R + 1)$

### Supported Traffic Classes
* **VOIP**: Voice over IP (RTP/SIP), characterized by isochronous ~20ms frame cadences, tight arrival jitter ($CV < 0.35$), symmetric directional ratio ($0.85-1.15$), and high MOS score estimate ($\ge 4.0$).
* **WHATSAPP**: Instant messaging, characterized by conversational bursts, presence keepalives, low pps ($< 8.0$), and high idle arrival variance ($CV > 0.85$).
* **EMAIL**: Mail retrieval/send (IMAP/SMTP), characterized by command-response handshake exchanges followed by bulk unidirectional MTU data trains.
* **WEB_BROWSING**: Interactive HTTP/HTTPS web sessions, characterized by multimodal packet sizing and moderate downlink-heavy asymmetry.
* **ICMP**: Diagnostic ping streams, characterized by strict periodic ~1.0s interval cadences, 100% uniform small packet sizing, and 1:1 request/reply symmetry.
* **VIDEO_STREAMING**: Adaptive bitrate streaming (HLS/DASH), characterized by periodic chunk download bursts (every 2–6s), high downlink asymmetry ($> 4.0$), and high MTU packet ratio ($> 0.60$).
* **OTHER**: Unclassified / generic background encrypted VPN flows.

### Machine Learning Model & Confidence Calibration
- **Model**: Supervised `RandomForestClassifier` (100 estimators, max depth 12) calibrated with domain protocol physics constraints.
- **Model Artifact**: Serialized at `backend/data/models/traffic_classifier_supervised.joblib`.
- **Benchmark Metrics**: Stratified 70/15/15 train/val/test split across 1,400 labeled flows:
  - **Overall Test Accuracy**: **97.14%**
  - **Macro F1-Score**: **0.9714**
  - **Inference Latency**: $\approx 1.2 \text{ ms}$
- **AI Confidence Score**: Derived directly from genuine model probability distributions (e.g., `Confidence: 92%`).

### Supplementary Anomaly Detection
The existing unsupervised **Isolation Forest** ensemble is retained purely as an optional, secondary behavioral anomaly analysis tool for baseline deviation, and is explicitly marked as supplementary in both UI and documentation.

---

## 4. Security Assessment & Metadata Exposure Engine

The **Security Assessment Engine** evaluates cryptographic posture and observable metadata leakage:

1. **Cryptographic Strength**:
   - Validation of cipher suites: flags deprecated 3DES, DES, Blowfish, MD5, SHA-1.
   - Evaluates key lengths: AES-128 vs AES-256 vs AES-GCM AEAD suites.
   - Forward Secrecy / PFS verification: ensures Phase 2 Diffie-Hellman re-keying is active.
2. **Configuration Compliance**:
   - SA lifetime limits: flags lifetimes exceeding NIST SP 800-77 recommendations (e.g. $> 8$ hours or $> 4 \text{ GB}$).
   - Replay protection: verifies sequence number monotonicity and replay window sizing (flags window sizes $< 64$).
3. **5-Vector Metadata Exposure Analysis**:
   - **SPI Predictability**: Detects static, sequential, or vendor-predictable Security Parameter Indexes.
   - **Sequence Number Monotonicity**: Analyzes counter progression and replay leakage.
   - **Length & Traffic Flow Confidentiality (TFC)**: Detects whether packet sizing reveals encapsulated payload types due to lack of dummy padding.
   - **Timing & Burst Dynamics**: Evaluates whether inter-packet arrival cadences expose conversational activity.
   - **Topology Exposure**: Assesses whether Tunnel Mode or Transport Mode leaks internal enterprise subnets.
   - **Output Rating**: Explicitly assigned as **Low**, **Medium**, or **High** with empirical evidence facts.

---

## 5. Risk Assessment & Decision Engine

Produces an auditable security score ($0-100$) and risk score ($0-100$) based on transparent, non-fabricated criteria:
- **Security Score Calculation**:
  $$\text{Security Score} = 100 - \sum \text{Finding Penalties}$$
  (Critical: $-25$, High: $-15$, Medium: $-8$, Low: $-3$)
- **Explainable Findings Format**:
  Every finding strictly follows:
  $$\text{Finding} \longrightarrow \text{Evidence} \longrightarrow \text{Severity} \longrightarrow \text{Reason} \longrightarrow \text{Recommendation}$$
- **Threat Matrix**: Maps 10 discrete threat scenarios directly to NIST SP 800-77 Rev. 1 and MITRE ATT&CK techniques.

---

## 6. Executive & Technical Reports

Automated generation of audit-ready PDF assessment reports:
- **Executive Report**: High-level posture score, risk level, threat summary, traffic breakdown, and critical remediation roadmap for leadership.
- **Technical Report**: Comprehensive deep-dive containing IPsec SA parameters, cipher suites, packet timing distributions, session fingerprints, AI traffic predictions with confidence scores, metadata exposure analysis, and full findings lineage.
- **Provenance Attribution**: Every fact in technical reports is explicitly tagged:
  - `[OBSERVED]`: Directly recorded from packet headers or network capture.
  - `[PARSED]`: Extracted via deterministic protocol state decoding.
  - `[INFERRED]`: Derived from multi-packet statistical analysis.
  - `[AI-PREDICTED]`: Inferred via supervised machine learning flow classification.
  - `[UNAVAILABLE]`: Data absent or encrypted without side-channel indicators.

---

## 7. Technology Stack

| Component | Technology | Version | Purpose |
|---|---|---|---|
| **Backend Runtime** | Python | 3.12+ | Core processing engine |
| **REST API** | FastAPI / Starlette | 0.115+ | High-performance asynchronous API |
| **Machine Learning** | scikit-learn / joblib / NumPy | 1.6+ | Supervised traffic classification & Isolation Forest |
| **Database** | SQLite + SQLAlchemy 2.0 | 2.0+ | Structured persistence & session state |
| **PDF Reporting** | ReportLab | 4.2+ | Automated publication-quality security reports |
| **Frontend Framework** | React + TypeScript | 18.3 / 5.5 | Analyst dashboard |
| **Build Tool** | Vite | 6.0+ | Fast bundle generation |
| **Styling** | Tailwind CSS | 3.4+ | Dark-mode cybersecurity design system |
| **Visualization** | Recharts / Lucide Icons | 2.12+ | Traffic charts & security posture gauges |

---

## 8. How to Run the Project

### Prerequisites
- **Python 3.11+** (recommended: Python 3.12)
- **Node.js 20+** and **npm 10+**

### Option A: Complete Project Runner (Single Command)
From the project root:
```bash
# Install dependencies
npm install

# Run backend and frontend concurrently
npm run dev
```

### Option B: Running Backend & Frontend Independently

#### 1. Backend Server
```bash
cd "SEC 14/AI-Powered-IPsec-VPN-Protocol-Analyzer-and-Security-Assessment-Framework/backend"

# Activate virtual environment
# Windows:
..\..\..\.venv-ai\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Start FastAPI server on port 8000
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
- API Documentation (Swagger UI): `http://127.0.0.1:8000/docs`
- Health Endpoint: `http://127.0.0.1:8000/api/health`
- 10-Layer System Status: `http://127.0.0.1:8000/api/system/status`

#### 2. Frontend Dashboard
```bash
cd "SEC 14/AI-Powered-IPsec-VPN-Protocol-Analyzer-and-Security-Assessment-Framework/frontend"

# Install npm dependencies
npm install

# Start development server
npm run dev
```
- Web Dashboard: `http://127.0.0.1:5173`

#### 3. Train / Retrain AI Traffic Classifier
```bash
cd "SEC 14/AI-Powered-IPsec-VPN-Protocol-Analyzer-and-Security-Assessment-Framework/backend"
python -m app.layers.layer08_ai_ml.train_traffic_classifier
```

---

## 9. Verification & Test Suite

The codebase includes comprehensive automated tests covering all 10 layers:

### Running Backend Pytest Suite (51 Tests, 100% Pass)
```bash
cd "SEC 14/AI-Powered-IPsec-VPN-Protocol-Analyzer-and-Security-Assessment-Framework"
pytest tests/backend/test_architecture.py \
       tests/backend/test_ai_protocol_traffic_classifier.py \
       tests/backend/test_comprehensive_security_assessment.py \
       tests/backend/test_complete_e2e_14_layers.py \
       tests/backend/test_9_requirements.py \
       tests/backend/test_system_status.py \
       tests/backend/test_layer01_environment.py \
       tests/backend/test_reports_api.py -v
```

### Running Frontend Typecheck & Build
```bash
cd "SEC 14/AI-Powered-IPsec-VPN-Protocol-Analyzer-and-Security-Assessment-Framework/frontend"
npm run build
```

---

## 10. SIH 26160 Requirement Traceability Table

| SIH 26160 Requirement | Implementation Component | Verification Method | Status |
|---|---|---|---|
| **IPsec VPN Testbed** (Tunnel, Transport, AES-128, AES-256, AES-GCM, AES-CBC+HMAC, DH groups, PFS on/off, IPv4/IPv6) | `layer01_test_environment/service.py`, `app/api/routes/environment.py` | VirtualBox orchestration scripts, StrongSwan config generators, automated profile verification tests (`test_layer01_environment.py`). | **Fully Implemented** |
| **Traffic Capture** (IKE, ESP, AH, Normal Traffic) | `layer02_packet_capture`, `app/services/packet_service.py` | Hypervisor NIC live packet capture, PCAP/PCAPNG ingestion parser, sanitization. | **Fully Implemented** |
| **Protocol Identification** (IPsec, IKEv1/v2, Tunnel/Transport Mode) | `layer03_protocol_analysis`, `layer04_sa_lifecycle`, `protocol_classifier.py` | Real PCAP dissection tests (`test_requirement_1_transport_mode_decoding_and_session`). | **Fully Implemented** |
| **Cryptographic & SA Parameter Extraction** (Ciphers, DH groups, Key lifetime, Replay window) | `layer04_sa_lifecycle`, `layer09_vulnerability_engine` | Deterministic extraction from IKE SAs, Child SAs, and sequence number tracking. | **Fully Implemented** |
| **Predict Traffic Type inside Encrypted ESP** (VoIP, WhatsApp, E-mail, Web, ICMP, Video, Other) | `layer08_ai_ml/traffic_classifier.py`, `train_traffic_classifier.py` | Supervised Random Forest model trained on 13 non-payload observable flow features across 1,400 flows (97.14% accuracy, `test_ai_protocol_traffic_classifier.py`). | **Fully Implemented** |
| **AI Confidence Score** | `traffic_classifier.py` | Genuine calibrated multi-class probability extraction (`TrafficPrediction.confidence`). | **Fully Implemented** |
| **IPsec Session Fingerprinting** | `layer06_session_fingerprinting`, `frontend/src/pages/BaselineProfiles` | Derivation of behavioral flow fingerprints feeding AI classification. | **Fully Implemented** |
| **Security Assessment** (Crypto strength, compliance, SA parameters, PFS, replay protection) | `layer09_vulnerability_engine/security_assessment.py` | 17 deterministic security rules with explainable remediation guidance (`test_comprehensive_security_assessment.py`). | **Fully Implemented** |
| **Metadata Exposure Analysis** | `security_assessment.py`, `layer09_vulnerability_engine/metadata_leakage.py` | 5-vector exposure analysis (SPI, Monotonicity, Length/TFC, Timing, Topology) rated Low/Medium/High with empirical evidence. | **Fully Implemented** |
| **Risk Scoring & Threat Matrix** | `layer10_risk_engine` | NIST SP 800-77 & MITRE ATT&CK threat mapping, explainable risk calculations (`test_requirement_9_standalone_threat_matrix_and_api`). | **Fully Implemented** |
| **Executive & Technical Reports** | `layer14_reports/report_generator.py` | Automated PDF report generation with explicit provenance tags (`[OBSERVED]`, `[PARSED]`, `[AI-PREDICTED]`). | **Fully Implemented** |
| **Interactive Dashboard** | `frontend/src/` | React 18 / Vite / Tailwind CSS dashboard with responsive dark mode and primary AI traffic classification flow. | **Fully Implemented** |

---

## License

This project is developed for the Smart India Hackathon (SIH 2026) under Problem Statement SIH 26160 (NTRO). All rights reserved.
