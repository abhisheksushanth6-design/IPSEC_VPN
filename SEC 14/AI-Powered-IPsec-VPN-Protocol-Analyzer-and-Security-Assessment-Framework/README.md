# AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

**Problem Statement**: SIH 26160 – National Technical Research Organisation (NTRO)  
**Track**: Cyber Security / Network Security Analysis  

---

## 1. Executive Summary

This project delivers a comprehensive, production-grade security assessment framework for IPsec VPN deployments aligned with **SIH Problem Statement 26160**.

Unlike traditional network monitoring tools that rely on cleartext payload inspection or basic port analysis, this framework analyzes observable protocol parameters, security association lifecycles, and side-channel characteristics to evaluate IPsec implementations. Most crucially, it features an **AI-powered traffic classification pipeline** capable of predicting the specific type of application traffic encapsulated inside encrypted ESP tunnels (**VoIP, WhatsApp/Messaging, E-mail, Web Browsing, ICMP, Video Streaming, and Other**) strictly using non-payload statistical flow and session features without decrypting or inspecting ciphertext.

The platform is **provenance-first**: every identification and every score states whether it was **OBSERVED** in cleartext protocol fields, **INFERRED** from side channels (frame-length arithmetic, message sizes), **PREDICTED** by the supervised model, **ASSUMED** as a documented default, or is **UNAVAILABLE** because the evidence is encrypted or absent. Scores are computed only over the components the capture actually supports and the coverage is reported alongside the score — nothing is fabricated to fill a gap. See [Section 11](#11-what-makes-this-implementation-different) for the novelty summary.

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
| **01** | **IPsec VPN Test Environment** | `layer01_test_environment` | **OPERATIONAL** (software testbed) · **PARTIALLY_OPERATIONAL** without VirtualBox | VirtualBox/strongSwan VM orchestration **plus a software testbed** (`software_testbed.py`) that emits real IKEv1/IKEv2 exchanges and real RFC 4303 ESP framing with real encryption (AES-GCM, AES-CBC+HMAC, 3DES, ChaCha20-Poly1305, AH) for **10 reproducible, seeded profiles** — Tunnel/Transport, AES-128/256, DH groups 2/5/14/19/20/21/31, PFS on/off, IPv4/IPv6, NAT-T, TFC padding, an IKEv1 aggressive-mode legacy baseline and a downgrade demonstration — each with registered **ground truth** for accuracy checks. |
| **02** | **Packet Capture & Data Collection** | `layer02_packet_capture` | **OPERATIONAL** · **PARTIALLY_OPERATIONAL** without VirtualBox | Hypervisor NIC live packet capture and PCAP/PCAPNG ingestion interface with sanitization (offline ingestion and testbed captures work without a hypervisor). |
| **03** | **Packet & Protocol Analysis** | `layer03_protocol_analysis` | **OPERATIONAL** | Deep packet decoding: IPv4, IPv6 (with Extension Headers & routing zero-length checks), IKEv1, IKEv2, ESP, AH, NAT-T (UDP 4500), and Linux SLL2. |
| **04** | **Security Association & State Analysis** | `layer04_sa_lifecycle` | **OPERATIONAL** | Deterministic tracking of IKE and Child SA state transitions, SPI correlation, rekeying cadence, key lifetimes, and anti-replay window state. |
| **05** | **Feature Extraction & Engineering** | `layer05_feature_engineering` | **OPERATIONAL** | Extracts 53 validated, versioned packet, session, and SA features with auditable lineage. |
| **06** | **IPsec Session Fingerprinting** | `layer06_session_fingerprinting` | **OPERATIONAL** | Derives compact behavioral session fingerprints from observable flow timing, sizing distributions, directionality, and burst dynamics as input to the AI pipeline. |
| **07** | **AI-Based Protocol & Traffic Classification** | `layer08_ai_ml` | **OPERATIONAL** | **Primary AI Engine**: identifies IPsec protocol, IKE version, mode, negotiated cipher suite, DH group, PFS and SA characteristics — each tagged `OBSERVED` / `INFERRED` / `ASSUMED` / `UNAVAILABLE` — and predicts the traffic type inside encrypted ESP (`VOIP`, `WHATSAPP`, `EMAIL`, `WEB_BROWSING`, `ICMP`, `VIDEO_STREAMING`, `OTHER`) with an **uncertainty-gated ensemble** (22-feature Random Forest + physical-signature rules) that **abstains** below a 45 % confidence floor. The overall AI confidence is weighted over the evidence that actually exists. |
| **08** | **Security Assessment Engine** | `layer09_vulnerability_engine` | **OPERATIONAL** | 24 deterministic rules plus: cleartext IKE negotiation extraction, **proposal-downgrade detection**, **ESP framing cipher-family inference** with a coincidence-probability confidence, ESP-NULL entropy check, **per-SPI replay analysis**, **PFS inference** from rekey message sizes, three published **compliance profiles** (IETF RFC 8247/8221/9395, NIST SP 800-77r1/800-131A, CNSA 1.0), **traffic-aware 5-vector metadata exposure**, coverage-aware scoring and a **what-if remediation simulator**. |
| **09** | **Risk Assessment & Decision Engine** | `layer10_risk_engine` | **OPERATIONAL** | Multi-criteria explainable risk scoring, 10-vector MITRE ATT&CK threat matrix, security posture index, and structured recommendations (`Finding → Evidence → Severity → Reason → Recommendation`). |
| **10** | **Dashboard & Report Generation** | `layer13_dashboard` & `layer14_reports` | **OPERATIONAL** | Responsive React 18 / Tailwind CSS dashboard and automated PDF assessment generation with provenance-attributed findings (`OBSERVED`, `PARSED`, `INFERRED`, `AI-PREDICTED`, `UNAVAILABLE`). |

*Note: Database (SQLite / SQLAlchemy) and Backend Services (FastAPI REST & WebSockets) operate internally as supporting infrastructure.*

---

## 3. AI-Based Protocol & Traffic Classification

The primary AI capability is encapsulated traffic classification inside encrypted ESP tunnels:

### Observable Feature Vector (No Payload Inspection)
Features are computed **from the ESP/AH data-plane packets only** (IKE control traffic is excluded so it cannot leak into the flow statistics). The v2.0 vector has 22 non-payload flow statistics:

| Group | Features |
|---|---|
| Volume & rate | `packet_count`, `byte_count`, `duration`, `packets_per_second`, `bytes_per_second` |
| Timing & cadence | `mean_iat`, `median_iat`, `iat_cv` (jitter, $\sigma/\mu$), `idle_gap_ratio`, `max_gap_seconds`, `burst_count`, `chunk_burst_periodicity` (video segment period, s) |
| Size distribution | `small_packet_ratio` ($\le 160$ B), `mtu_packet_ratio` ($\ge 1200$ B), `mean_packet_length`, `packet_length_std`, `packet_length_cv`, `length_entropy_bits` |
| Direction | `inbound_outbound_byte_ratio`, `direction_asymmetry` ($\lvert R-1\rvert/(R+1)$), `uplink_packet_ratio` |
| Voice quality | `mos_score_estimate` (ITU-T G.107 E-model estimate from cadence and jitter) |

### Supported Traffic Classes
* **VOIP**: Voice over IP (RTP/SIP), characterized by isochronous ~20ms frame cadences, tight arrival jitter ($CV < 0.35$), symmetric directional ratio ($0.85-1.15$), and high MOS score estimate ($\ge 4.0$).
* **WHATSAPP**: Instant messaging, characterized by conversational bursts, presence keepalives, low pps ($< 8.0$), and high idle arrival variance ($CV > 0.85$).
* **EMAIL**: Mail retrieval/send (IMAP/SMTP), characterized by command-response handshake exchanges followed by bulk unidirectional MTU data trains.
* **WEB_BROWSING**: Interactive HTTP/HTTPS web sessions, characterized by multimodal packet sizing and moderate downlink-heavy asymmetry.
* **ICMP**: Diagnostic ping streams, characterized by strict periodic ~1.0s interval cadences, 100% uniform small packet sizing, and 1:1 request/reply symmetry.
* **VIDEO_STREAMING**: Adaptive bitrate streaming (HLS/DASH), characterized by periodic chunk download bursts (every 2–6s), high downlink asymmetry ($> 4.0$), and high MTU packet ratio ($> 0.60$).
* **OTHER**: Unclassified / generic background encrypted VPN flows.

### Machine Learning Model & Confidence Calibration
- **Model**: Supervised `RandomForestClassifier` (300 estimators, max depth 16) blended with physical-signature rules in an **uncertainty-gated ensemble**: the rules carry 35 % of the decision while the model's top probability is $\ge 0.80$ and up to 65 % once it falls to $\le 0.50$ (flow outside the training distribution). Physical-constraint calibration zeroes classes whose defining cadence is impossible for the observed flow, and the classifier **abstains** (reports `OTHER`) when no class reaches the 45 % confidence floor.
- **Model Artifact**: `backend/data/models/traffic_classifier_supervised.joblib` (bundle: model, feature names, version) with `traffic_metrics.json` beside it.
- **Dataset (v2.0, no train/serve skew)**: 1,400 flows (200 per class) generated by the **software testbed** — synthetic application traffic models inside **real** RFC 4303 ESP framing with real encryption — and featurised through the deployed Layer 03 → Layer 07 pipeline (`dataset_builder.py`). Seven configuration profiles are used for training; two (the downgrade demo and the TFC-padded profile) are **held out entirely** to measure generalisation to unseen IPsec configurations. No real user traffic is included; see `docs/ml_dataset_and_classification.md`.
- **Benchmark Metrics** (`traffic_metrics.json`, stratified 70/15/15 split of 980/210/210 flows):
  - **Test accuracy / macro-F1**: **100 %** on the 210-flow test split (same generator, unseen seeds)
  - **5-fold CV macro-F1**: **0.995 ± 0.003**
  - **Held-out configuration accuracy**: **85.0 %** (downgrade profile 100 %, TFC-padded profile 70 % — fixed-size padding removes the length features, which is exactly what TFC is for)
  - **Inference latency**: ≈ 84 ms per flow (300-tree forest, single thread)
- **AI Confidence Score**: the ensemble's class probability for the predicted class, reported together with the rule and model probabilities and an explanation trail (`rule_probabilities`, `ml_probabilities`, `explanations`).

### Supplementary Anomaly Detection
The existing unsupervised **Isolation Forest** ensemble is retained purely as an optional, secondary behavioral anomaly analysis tool for baseline deviation, and is explicitly marked as supplementary in both UI and documentation.

---

## 4. Security Assessment & Metadata Exposure Engine

The **Security Assessment Engine** evaluates cryptographic posture and observable metadata leakage:

1. **Cryptographic Strength** (graded only when the suite was observed or decisively inferred):
   - The negotiated suite is read from the cleartext IKEv2 `IKE_SA_INIT` SA/KE payloads or the IKEv1 Phase 1 SA (transforms, DH group, auth method, lifetimes); the responder's selection is cross-checked against the KE group.
   - Weakest-link security strength in bits (NIST SP 800-57 equivalences: AES-128 = 112-bit DH-14 = 112, ECP-256 = 128, ECP-384 = 192, 3DES = 112 deprecated …) → grade A+ … F; deprecated transforms (3DES, DES, Blowfish, MD5, SHA-1, MODP-1024) cap the score.
   - **Proposal-downgrade detection**: a responder that selects a weaker proposal than the strongest one offered (or a deprecated one when a modern one was available) raises `RULE-CRYPTO-006`; weak *offered* transforms raise `RULE-CRYPTO-007`.
   - Without IKE in the capture, **ESP framing arithmetic** (RFC 4303 §2) distinguishes AES-CBC (16-byte IV/blocks) from the 8-byte-IV families (AES-GCM / ChaCha20 / AES-CTR / 3DES) with a stated coincidence probability, refuses to guess on TFC-padded or fixed-size frames, and flags **ESP-NULL** from payload entropy (RFC 5879). The key length is never claimed — it is not observable.
   - **Forward Secrecy**: read from IKEv1 Quick Mode / IKEv2 `CREATE_CHILD_SA` message sizes (a KE payload adds 40–392 bytes); reported `ENABLED` / `DISABLED` / `UNKNOWN`, never a fabricated boolean.
2. **Configuration Compliance**:
   - 24 deterministic rules (crypto, IKE, authentication, protocol, SA lifecycle, configuration) with Finding → Evidence → Severity → Reason → Recommendation.
   - Three published profiles evaluated side by side with per-check coverage: **IETF RFC 8247 / 8221 / 9395**, **NIST SP 800-77 Rev. 1 / SP 800-131A**, **CNSA 1.0**.
   - SA lifetime limits (observed duration/volume and the negotiated IKEv1 lifetime) and **per-SPI replay analysis**: sequence-number monotonicity, duplicates, reorder distance versus the 64-packet window (`PROTECTED` / `DEGRADED` / `REPLAY_INDICATORS`); ESN is reported as not observable rather than assumed.
3. **5-Vector Metadata Exposure Analysis** — traffic-aware:
   - **SPI Predictability**: Detects static, sequential, or vendor-predictable Security Parameter Indexes.
   - **Sequence Number Monotonicity**: Analyzes counter progression and replay leakage.
   - **Length & Traffic Flow Confidentiality (TFC)**: Detects whether packet sizing reveals encapsulated payload types due to lack of dummy padding (judged by frame-size dispersion, so a padded or fixed-size stream is not penalised).
   - **Timing & Burst Dynamics**: Evaluates whether inter-packet arrival cadences expose conversational activity.
   - **Topology Exposure**: Assesses whether Tunnel Mode or Transport Mode leaks internal enterprise subnets.
   - The length and timing vectors are **weighted by the predicted traffic type** with the published attack that applies: VoIP → spoken-phrase / language identification (Wright et al. 2007, 2008), video → title fingerprinting (Schuster et al. 2017), web → website fingerprinting (Panchenko 2011, Wang 2014).
   - **Output Rating**: Explicitly assigned as **Low**, **Medium**, or **High** with empirical evidence facts.
4. **What-if remediation simulator** (`POST /api/security-assessment/what-if/{session_id}`): re-runs the rule set, the profiles and the score with a hypothetical cipher / DH group / PFS / IKE version / mode / TFC setting so an operator can see the gain of a change before touching the gateway. Nothing is written back.

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
- **Security Assessment Engine section** (both report types): session security score with evidence coverage, protocol identification with provenance, the six assessment dimensions, the three compliance profiles and the explainable findings, plus an explicit list of what could **not** be assessed from the capture.
- **Provenance Attribution**: Every fact is explicitly tagged:
  - `[OBSERVED]`: Read directly from cleartext packet or protocol fields.
  - `[INFERRED]`: Derived from side channels (frame-length arithmetic, message sizes, entropy).
  - `[PREDICTED]`: Produced by the supervised traffic classifier.
  - `[ASSUMED]`: A documented default the capture cannot confirm (e.g. tunnel mode for gateway ESP).
  - `[UNAVAILABLE]`: Data absent or encrypted without side-channel indicators.

---

## 7. Technology Stack

| Component | Technology | Version | Purpose |
|---|---|---|---|
| **Backend Runtime** | Python | 3.11+ | Core processing engine |
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

#### 3. Generate a testbed capture (no hypervisor needed)
Open **System → Test Environment → Software Testbed** and press *Generate & load* on a profile, or call the API:
```bash
curl -X POST "http://127.0.0.1:8000/api/environment/simulate-profile/PROFILE-05-TUNNEL-3DESCBC-NOPFS-IPV4?seed=7&duration=30"
curl "http://127.0.0.1:8000/api/environment/ground-truth/<capture_id>"
```
Then open **Security Analysis → Security Posture** for the provenance-tagged assessment, the compliance profiles, the ground-truth comparison and the what-if simulator.

#### 4. Train / Retrain AI Traffic Classifier
```bash
cd "SEC 14/AI-Powered-IPsec-VPN-Protocol-Analyzer-and-Security-Assessment-Framework/backend"
# regenerates backend/data/datasets/esp_flow_features_v2.0.csv through the real pipeline, trains,
# evaluates on the test split, 5-fold CV and the two held-out configuration profiles, and writes
# backend/data/models/traffic_classifier_supervised.joblib + traffic_metrics.json
python -m app.layers.layer08_ai_ml.train_traffic_classifier --samples-per-class 200 --workers 4
```

---

## 9. Verification & Test Suite

The codebase includes comprehensive automated tests covering all 10 layers. Current state (Python 3.11, Node 22):

### Backend pytest suite — 538 passed, 2 skipped
```bash
cd "SEC 14/AI-Powered-IPsec-VPN-Protocol-Analyzer-and-Security-Assessment-Framework"
python -m pytest tests/backend -q        # or: cd backend && python -m pytest -q  (pytest.ini points at ../tests/backend)
```
Highlights: `test_sih_assessment_engine.py` (software testbed, negotiation extraction, downgrade detection,
"never confidently wrong" guarantees for ESP framing / PFS / mode inference, per-SPI replay, what-if, compliance
profiles, PDF section), `test_ai_protocol_traffic_classifier.py` (every SIH traffic class on held-out testbed
seeds, abstention, provenance of the comprehensive analysis), `test_comprehensive_security_assessment.py`
(ESP-only vs. observed strong vs. observed weak suites), `test_complete_e2e_14_layers.py` (22-step pipeline).

### Frontend — typecheck, 209 vitest tests, production build
```bash
cd "SEC 14/AI-Powered-IPsec-VPN-Protocol-Analyzer-and-Security-Assessment-Framework/frontend"
npm run typecheck && npm run test && npm run build
```

### Continuous integration
`.github/workflows/ci.yml` at the repository root runs both suites on every push and pull request.

### Demo walkthrough
`docs/demo/` holds screenshots, a screen recording and sample technical/executive PDF reports produced by
`scripts/demo_walkthrough.cjs` from two software-testbed captures (see `docs/demo/README.md`).

---

## 10. SIH 26160 Requirement Traceability Table

| SIH 26160 Requirement | Implementation Component | Verification Method | Status |
|---|---|---|---|
| **IPsec VPN Testbed** (Tunnel, Transport, AES-128, AES-256, AES-GCM, AES-CBC+HMAC, DH groups, PFS on/off, IPv4/IPv6) | `layer01_test_environment/software_testbed.py`, `service.py`, `app/api/routes/environment.py` | 10 seeded software-testbed profiles with real IKE/ESP/AH framing and real encryption plus registered ground truth (`test_sih_assessment_engine.py`); VirtualBox/strongSwan orchestration for the VM testbed (`test_layer01_environment.py`). | **Fully Implemented** |
| **Traffic Capture** (IKE, ESP, AH, Normal Traffic) | `layer02_packet_capture`, `app/services/packet_service.py` | Hypervisor NIC live packet capture, PCAP/PCAPNG ingestion parser, sanitization; testbed captures load through the same path. | **Fully Implemented** |
| **Protocol Identification** (IPsec, IKEv1/v2, Tunnel/Transport Mode) | `layer03_protocol_analysis`, `crypto_negotiation.py`, `crypto_inference.py`, `protocol_classifier.py` | AH next-header and IKE notifies are `OBSERVED`; ESP mode is `INFERRED` from bare-ACK frame sizes (with the negotiated ICV length) or reported `ASSUMED`/`UNKNOWN` (`test_ai_protocol_traffic_classifier.py`, `test_sih_assessment_engine.py`). | **Fully Implemented** |
| **Cryptographic & SA Parameter Extraction** (Ciphers, DH groups, Key lifetime, Replay window) | `crypto_negotiation.py`, `replay_analysis.py`, `layer04_sa_lifecycle` | Cleartext IKEv2 `IKE_SA_INIT` / IKEv1 Phase 1 transform decoding (incl. IKEv1 lifetimes and auth method), KE cross-check, downgrade detection, per-SPI sequence analysis (`test_sih_assessment_engine.py`). | **Fully Implemented** |
| **Predict Traffic Type inside Encrypted ESP** (VoIP, WhatsApp, E-mail, Web, ICMP, Video, Other) | `layer08_ai_ml/traffic_classifier.py`, `dataset_builder.py`, `train_traffic_classifier.py` | 22-feature Random Forest + rules ensemble trained on 1,400 pipeline-featurised testbed flows; 100 % test accuracy, 0.995 CV macro-F1, 85 % on held-out configurations; held-out seeds in `test_ai_protocol_traffic_classifier.py`. | **Fully Implemented** |
| **AI Confidence Score** | `traffic_classifier.py`, `protocol_classifier.py` | Ensemble class probability with rule/model breakdown and abstention; overall AI confidence weighted over available evidence dimensions. | **Fully Implemented** |
| **IPsec Session Fingerprinting** | `layer06_session_fingerprinting`, `frontend/src/pages/BaselineProfiles` | Derivation of behavioral flow fingerprints feeding AI classification. | **Fully Implemented** |
| **Security Assessment** (Crypto strength, compliance, SA parameters, PFS, replay protection) | `layer09_vulnerability_engine/security_assessment.py`, `compliance_profiles.py`, `rules/` | 24 rules, 3 compliance profiles, provenance-aware grading, coverage reporting and what-if simulation (`test_comprehensive_security_assessment.py`, `test_sih_assessment_engine.py`). | **Fully Implemented** |
| **Metadata Exposure Analysis** | `layer09_vulnerability_engine/metadata_exposure.py` | Traffic-aware 5-vector exposure analysis (SPI, Monotonicity, Length/TFC, Timing, Topology) rated Low/Medium/High with cited attacks. | **Fully Implemented** |
| **Risk Scoring & Threat Matrix** | `layer10_risk_engine`, `threat_matrix.py` | NIST SP 800-77 & MITRE ATT&CK threat mapping fed by the session's observed negotiation and replay analysis (`test_requirement_9_standalone_threat_matrix_and_api`). | **Fully Implemented** |
| **Executive & Technical Reports** | `layer14_reports/pdf_renderer.py` | PDF reports with the Security Assessment Engine section and explicit provenance tags (`test_reports_include_security_assessment_engine_section`). | **Fully Implemented** |
| **Interactive Dashboard** | `frontend/src/` | React 18 / Vite / Tailwind CSS dashboard; **Security Posture** page with provenance badges, compliance profiles, ground-truth comparison and the what-if simulator; software-testbed generator on the Test Environment page. | **Fully Implemented** |

---

## 11. What Makes This Implementation Different

1. **Provenance-first analysis.** Every identification, score and finding is tagged `OBSERVED` / `INFERRED` / `PREDICTED` / `ASSUMED` / `UNAVAILABLE`, and the overall score is computed only over the components the capture supports, with the coverage shown next to it. An ESP-only capture gets an honest "cipher suite not assessable" instead of an invented AES-256.
2. **Cipher-family inference from ESP framing arithmetic.** RFC 4303 padding makes AES-CBC frames avoid one residue class modulo 16; the engine reports the family with the probability that the pattern arose by chance, refuses to conclude on TFC-padded or fixed-size streams, and flags ESP-NULL from payload entropy. It also states what framing *cannot* tell apart (AES-GCM vs. 3DES).
3. **Transport/tunnel inference from bare-ACK frame sizes**, sharpened by the negotiated ICV length, with explicit "ambiguous" outcomes instead of a default.
4. **Proposal-downgrade detection** from the cleartext IKE negotiation: offered vs. selected transforms compared by security strength, with the weak fallback offers listed.
5. **PFS inference** from `CREATE_CHILD_SA` / Quick Mode message sizes (a KE payload cannot hide its length) — `ENABLED` / `DISABLED` / `UNKNOWN`.
6. **Per-SPI replay analysis** (duplicates, reorder distance vs. the 64-packet window, sender-counter integrity) feeding a rule, the threat matrix and the score.
7. **Traffic-aware metadata exposure**: the predicted traffic class selects the published side-channel attack that applies and weights the length/timing vectors accordingly.
8. **Uncertainty-gated AI ensemble with abstention**, trained on a dataset produced by the same pipeline that serves predictions (no train/serve skew), evaluated on unseen seeds *and* on entirely held-out IPsec configurations, with the numbers published as they are.
9. **What-if remediation simulator** and three side-by-side compliance profiles (IETF, NIST, CNSA) so a finding comes with a quantified path to green.
10. **Reproducible software testbed** with registered ground truth: every generated capture can be compared against what the platform inferred, in the UI and in the tests ("never confidently wrong" guarantees are part of the test suite).

---

## License

This project is developed for the Smart India Hackathon (SIH 2026) under Problem Statement SIH 26160 (NTRO). All rights reserved.
