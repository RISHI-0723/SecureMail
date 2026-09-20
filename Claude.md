# SecureMailScope — Claude Code Master Specification

## 1. PROJECT IDENTITY

Project Name:
SecureMailScope

Description:
AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications.

Purpose:
SecureMailScope is a passive network-forensic platform that analyzes PCAP/PCAPNG files containing SMTP, IMAP, and POP3 communications and evaluates their cryptographic security posture.

The system must:

1. Ingest PCAP/PCAPNG evidence.
2. Validate and hash uploaded evidence.
3. Identify SMTP, IMAP, and POP3 traffic.
4. Reconstruct TCP communication streams.
5. Detect plaintext, STARTTLS/STLS, and implicit TLS email sessions.
6. Reconstruct and analyze TLS handshakes.
7. Extract and analyze X.509 certificates.
8. Identify cryptographic weaknesses.
9. Produce explainable security findings.
10. Calculate security posture and risk.
11. Later support AI/ML-based anomaly detection and risk classification.
12. Generate forensic reports.
13. Later support blockchain-based evidence integrity verification.
14. Provide an interactive web dashboard.
15. Be deployable as a real web application.

This is a GREENFIELD project.

At the beginning of Phase 0, assume there is NO existing application implementation.

Do not invent existing files or existing functionality.

---

# 2. CORE ENGINEERING PRINCIPLES

## 2.1 Forensic correctness over visual polish

The analysis engine is more important than the UI.

Never fabricate forensic findings.

If evidence is incomplete, corrupted, unavailable, or ambiguous, report the limitation explicitly.

Never convert missing evidence into a positive security conclusion.

Example:

BAD:
"Certificate is valid."

when the certificate was not fully captured.

GOOD:
"Certificate validation could not be completed because the TLS stream is partial."

---

## 2.2 Evidence-first architecture

Every analysis result must be traceable to evidence.

Findings should contain enough metadata to identify:

- PCAP
- session
- protocol
- source/destination
- timestamp where available
- evidence supporting the finding
- stream integrity
- confidence

---

## 2.3 No silent failures

No component may silently return incomplete or invalid data.

Failures must propagate through structured status/error objects.

Never allow:

TShark failure
→ empty parser result
→ fake "no findings"

Instead:

TShark failure
→ analysis stage FAILED
→ structured error
→ UI displays failure
→ no fabricated security conclusions

---

## 2.4 Optional features must never become core dependencies

The core forensic pipeline must work independently of optional components.

ML is optional.

Blockchain is optional.

Advanced PDF generation is optional.

If ML fails:

Forensics must continue.

If blockchain is unavailable:

Evidence hashing must continue.

If PDF generation fails:

JSON/HTML/dashboard data must continue.

The following dependency rule is mandatory:

CORE FORENSICS
    ↓
must NOT depend on
    ↓
ML / Blockchain / PDF

---

# 3. LOCKED TECHNOLOGY STACK

## Frontend

- React
- TypeScript
- Vite
- Tailwind CSS
- shadcn/ui
- Recharts
- Lucide React

Purpose:

- SOC dashboard
- PCAP upload
- analysis status
- cases
- sessions
- TLS explorer
- certificate explorer
- findings
- reports
- security posture visualization

Do not introduce Three.js unless explicitly required later.

The product should look like a professional cybersecurity/SOC platform, not a gaming website.

---

## Backend

- Python 3.12+
- FastAPI
- Pydantic
- SQLAlchemy
- Alembic
- Uvicorn

---

## Network Forensics

Primary packet-analysis engine:

- TShark

Supporting Python libraries:

- Scapy where required
- PyShark only where useful
- standard Python networking/parsing libraries

TShark is the primary packet-analysis authority.

Do not reimplement a complete packet dissector unnecessarily.

---

## Cryptography

- Python cryptography
- OpenSSL where required

---

## Database

- PostgreSQL

---

## Background Processing

- Redis
- Celery

Long-running PCAP analysis MUST NOT block normal HTTP request handling.

---

## Machine Learning

Primary:

- scikit-learn
- XGBoost where useful

Initial models:

1. Random Forest or XGBoost for supervised risk classification.
2. Isolation Forest for anomaly detection.

ML must be explainable at the application level.

---

## Reports

- JSON
- HTML
- PDF

HTML should be the most reliable report format.

PDF generation must not become a dependency of the analysis pipeline.

---

## Infrastructure

- Docker
- Docker Compose
- NGINX
- HTTPS in deployment
- S3-compatible object storage for production evidence storage where appropriate

---

## Blockchain

Optional evidence-integrity layer.

Only hashes and non-sensitive integrity metadata should be recorded.

Never place PCAP contents or sensitive forensic data directly on-chain.

---

# 4. LOCKED SYSTEM ARCHITECTURE

The target architecture is:

USER
 |
 v
React Frontend
 |
 v
FastAPI
 |
 +------------------+
 |                  |
 v                  v
PostgreSQL         Redis
                      |
                      v
                    Celery
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
       TShark      Crypto        ML
          |           |           |
          +-----------+-----------+
                      |
                      v
                Risk Engine
                      |
                      v
              Recommendations
                      |
                      v
                Report Engine
                      |
                      v
            Optional Blockchain
                      |
                      v
                 Dashboard

---

# 5. REPOSITORY ARCHITECTURE

Target structure:

securemailscope/
│
├── CLAUDE.md
├── README.md
├── .env.example
├── .gitignore
├── docker-compose.yml
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── migrations/
│   ├── tests/
│   └── app/
│       ├── main.py
│       ├── api/
│       │   ├── dependencies.py
│       │   └── routes/
│       ├── core/
│       ├── models/
│       ├── schemas/
│       ├── services/
│       │   ├── ingestion/
│       │   ├── packet/
│       │   ├── protocol/
│       │   ├── tcp/
│       │   ├── email/
│       │   ├── tls/
│       │   ├── certificates/
│       │   ├── crypto/
│       │   ├── risk/
│       │   ├── recommendations/
│       │   └── reports/
│       └── workers/
│
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── components/
│       ├── pages/
│       ├── layouts/
│       ├── hooks/
│       ├── services/
│       ├── types/
│       └── App.tsx
│
├── ml/
│   ├── datasets/
│   ├── generators/
│   ├── feature_engineering/
│   ├── training/
│   ├── evaluation/
│   └── models/
│
├── blockchain/
│   ├── contracts/
│   ├── scripts/
│   └── tests/
│
├── sample_pcaps/
│
├── tests/
│   ├── integration/
│   └── fixtures/
│
└── docs/

Do not create arbitrary duplicate architecture folders.

Inspect the current repository before modifying existing files.

Preserve existing interfaces unless the current phase explicitly requires a change.

---

# 6. PHASE BOUNDARIES

The project is divided into 10 engineering phases.

==================================================
PHASE 0 — FOUNDATION
==================================================

Build:

- repository foundation
- Docker Compose
- FastAPI
- React/Vite
- PostgreSQL
- Redis
- basic Celery configuration
- environment configuration
- health checks
- logging foundation
- initial database structure
- development README
- test infrastructure

Phase 0 must NOT implement full PCAP analysis.

Phase 0 must NOT implement ML.

Phase 0 must NOT implement blockchain.

Definition of Done:

- docker compose starts successfully
- backend starts
- frontend starts
- PostgreSQL is reachable
- Redis is reachable
- backend health endpoint works
- frontend can reach backend
- database migration mechanism works
- basic automated tests run
- no secrets committed
- .env.example exists


==================================================
PHASE 1 — EVIDENCE INGESTION
==================================================

Implement:

- PCAP upload
- PCAPNG upload
- file validation
- file-size validation
- SHA-256 hashing
- evidence metadata
- case creation
- secure storage abstraction
- upload status
- database persistence

Metadata should include where appropriate:

- evidence ID
- filename
- file size
- SHA-256
- format
- upload timestamp
- status
- analysis status

Do not perform full forensic analysis in the upload HTTP request.

Large files must be processed asynchronously.

Definition of Done:

- valid PCAP accepted
- valid PCAPNG accepted
- invalid format rejected
- empty file handled
- oversized file handled
- SHA-256 generated
- metadata stored
- duplicate hash handled deterministically
- upload API tested


==================================================
PHASE 2 — PACKET AND EMAIL PROTOCOL ANALYSIS
==================================================

Implement:

- TShark integration
- packet extraction
- protocol identification
- SMTP detection
- IMAP detection
- POP3 detection
- protocol detection independent of standard ports where feasible

Standard ports must be supported, but port number alone must NOT determine protocol identity.

Examples:

SMTP:
25, 465, 587 and protocol-signature detection

IMAP:
143, 993 and protocol-signature detection

POP3:
110, 995 and protocol-signature detection

Non-standard ports must be considered.

Definition of Done:

- SMTP detected
- IMAP detected
- POP3 detected
- implicit TLS traffic can be identified as encrypted email traffic where evidence supports it
- non-email traffic does not create false email sessions
- TShark errors are handled
- malformed PCAP behavior is tested


==================================================
PHASE 3 — TCP STREAM RECONSTRUCTION
==================================================

This is a critical forensic phase.

Implement:

- TCP conversation identification
- stream IDs
- client/server determination
- sequence-aware reconstruction
- out-of-order handling
- retransmission handling
- duplicate suppression
- missing segment detection
- FIN handling
- RST handling
- partial stream detection
- stream integrity state

Every reconstructed stream must have an integrity state:

- COMPLETE
- PARTIAL
- CORRUPTED
- UNKNOWN

Never silently treat PARTIAL as COMPLETE.

Required acceptance tests:

1. Ordered packets
2. Out-of-order packets
3. Retransmitted packet
4. Duplicate segment
5. Missing segment
6. FIN
7. RST
8. Partial capture
9. Multiple simultaneous TCP sessions
10. TShark failure
11. TShark timeout
12. Invalid/incomplete TShark output

If TShark itself fails:

- capture stderr
- capture exit code
- stop dependent processing
- mark stage as FAILED
- return structured error
- do not generate fabricated downstream findings

Definition of Done:

A TLS parser consuming a COMPLETE stream receives correctly ordered application bytes.

For PARTIAL/CORRUPTED streams, downstream analysis must receive the integrity state.


==================================================
PHASE 4 — EMAIL SECURITY AND TLS TRANSITIONS
==================================================

Implement:

SMTP:
- EHLO/HELO
- STARTTLS detection
- STARTTLS success/failure
- plaintext-to-TLS transition

IMAP:
- CAPABILITY
- STARTTLS detection
- STARTTLS success/failure

POP3:
- CAPA
- STLS detection
- STLS success/failure

MANDATORY:

Implicit TLS detection MUST be implemented.

Support:

SMTP/SMTPS
IMAP/IMAPS
POP3/POP3S

The system must distinguish:

1. plaintext email session
2. STARTTLS/STLS upgraded session
3. implicit TLS session
4. failed/partial TLS transition
5. unknown/ambiguous state

Detect where evidence supports:

- STARTTLS advertised but not used
- STARTTLS attempted but failed
- unexpected transition
- plaintext communication
- implicit TLS

Definition of Done:

The system can represent:

protocol
transport_security_mode
starttls_detected
starttls_success
implicit_tls
tls_detected
stream_integrity


==================================================
PHASE 5 — TLS AND X.509 INTELLIGENCE
==================================================

Implement TLS handshake analysis.

Extract where observable:

- TLS version
- cipher suite
- key exchange mechanism
- signature algorithm
- extensions
- SNI
- supported groups
- ALPN where available
- handshake events
- certificate messages

Support:

TLS 1.0
TLS 1.1
TLS 1.2
TLS 1.3

Analyze:

- deprecated TLS versions
- weak cipher suites
- weak/deprecated algorithms
- key exchange
- forward secrecy
- anomalous handshake behavior

Certificate analysis:

- certificate extraction
- subject
- issuer
- serial number
- validity period
- expiration
- public key algorithm
- public key length
- signature algorithm
- SAN
- key usage where available
- extended key usage where available
- self-signed detection
- certificate chain information
- hostname validation where applicable
- weak certificate properties

Important:

If the TLS stream is PARTIAL, do not claim complete certificate validation.

Represent analysis confidence and evidence quality.

Definition of Done:

TLS sessions contain structured cryptographic metadata.

Certificates are stored separately and linked to TLS sessions.

TLS parsing failure does not crash the entire case.


==================================================
PHASE 6 — CRYPTOGRAPHIC SECURITY ASSESSMENT
==================================================

Build a deterministic and explainable security rules engine.

Potential findings include:

- deprecated TLS version
- weak cipher
- weak cryptographic algorithm
- weak public key
- weak signature algorithm
- expired certificate
- not-yet-valid certificate
- self-signed certificate
- certificate validation issue
- hostname/SAN issue
- no forward secrecy
- insecure STARTTLS behavior
- plaintext email communication
- handshake anomalies

Every finding should contain:

- finding ID
- category
- severity
- confidence
- title
- description
- evidence
- affected session
- affected certificate where relevant
- recommendation
- source stage
- timestamp where available

Do not use ML to replace deterministic cryptographic rules.

Rules must remain explainable.

Risk/posture scoring should combine evidence transparently.

Definition of Done:

A complete case produces:

- findings
- severity
- confidence
- security posture
- recommendations


==================================================
MVP FRONTEND — PHASE 7
==================================================

Build the minimum production-quality dashboard.

Required pages/components:

1. Dashboard
2. PCAP upload
3. Case list
4. Case details
5. Analysis progress
6. Security posture
7. TLS sessions
8. Certificates
9. Findings

The UI must communicate:

- processing
- completed
- failed
- partial analysis
- warnings
- no email traffic
- no findings

MVP must be usable without ML.

Definition of Done:

A user can:

1. Open the web application.
2. Upload a PCAP.
3. See analysis progress.
4. Open the completed case.
5. View protocols.
6. View TLS sessions.
7. View certificates.
8. View findings.
9. View security posture.
10. Understand failures without seeing stack traces.

At this point the project is considered MVP COMPLETE.


==================================================
PHASE 8 — AI / ML
==================================================

ML is an enhancement to the completed forensic engine.

Do NOT block MVP on ML.

Dataset strategy:

Use a controlled synthetic dataset plus carefully selected public network-security datasets where appropriate.

Do not claim that generic datasets are email-TLS-specific.

Synthetic target:

20 core scenarios.

Approximately:

20–50 generated PCAPs

producing approximately:

2,000–5,000 session-level feature samples.

The synthetic scenario matrix should include:

NORMAL:
- TLS 1.3 strong configuration
- TLS 1.2 ECDHE strong configuration
- successful SMTP STARTTLS
- successful IMAP STARTTLS
- successful POP3 STLS

WEAK:
- TLS 1.0
- TLS 1.1
- weak cipher
- no forward secrecy
- deprecated key exchange

CERTIFICATE:
- expired certificate
- not-yet-valid certificate
- self-signed certificate
- weak RSA key
- weak signature algorithm

STARTTLS:
- STARTTLS advertised but unused
- STARTTLS failure
- plaintext session
- abnormal STARTTLS transition

ANOMALOUS:
- repeated handshake failures
- unusual cipher negotiation
- abnormal TLS behavior
- unusual certificate behavior
- mixed anomalies

The dataset generator must be automated.

The ML subsystem should generate:

- features.csv
- labels.csv
- train/test split
- model artifacts
- evaluation metrics
- confusion matrix where applicable

Supervised model:

Random Forest or XGBoost.

Unsupervised model:

Isolation Forest.

Required metrics:

- precision
- recall
- F1
- confusion matrix for supervised classification
- anomaly detection observations

Never claim production-level generalization from synthetic data.

ML must remain optional.

If ML is unavailable:

core analysis continues.


==================================================
PHASE 9 — REPORTS AND EVIDENCE INTEGRITY
==================================================

Implement:

JSON reports
HTML reports
PDF reports

Report contents:

- case metadata
- evidence hash
- packet/session statistics
- protocol analysis
- TLS analysis
- certificate analysis
- findings
- severity
- confidence
- recommendations
- security posture
- ML results where available
- limitations

Blockchain:

Optional evidence-integrity feature.

Store only:

- evidence hash
- report hash
- timestamp
- transaction/integrity identifier

Never store:

- PCAP content
- email content
- credentials
- sensitive packet data

on-chain.


==================================================
PHASE 10 — PRODUCTION HARDENING AND DEPLOYMENT
==================================================

Implement:

- authentication
- authorization/RBAC where required
- upload security
- file-size limits
- MIME/type validation
- filename sanitization
- API validation
- rate limiting
- secure headers
- HTTPS
- secret management
- worker isolation
- logging
- monitoring
- health checks
- resource limits
- timeout handling
- large-PCAP controls
- deployment configuration
- CI/CD
- integration testing
- end-to-end testing

Deployment target should support:

NGINX
React
FastAPI
Celery
Redis
PostgreSQL
TShark

Production evidence should use object storage where appropriate.

---

# 7. SHARED SESSION JSON CONTRACT

All subsystems must agree on a common session representation.

Initial canonical structure:

{
  "session_id": "sess_001",
  "protocol": "SMTP",
  "client_ip": "10.0.0.5",
  "client_port": 52341,
  "server_ip": "10.0.0.10",
  "server_port": 587,

  "start_time": null,
  "end_time": null,

  "starttls": true,
  "starttls_success": true,
  "implicit_tls": false,
  "tls_detected": true,

  "tls_version": "TLS1.2",
  "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
  "key_exchange": "ECDHE",
  "forward_secrecy": true,

  "certificate_valid": true,
  "certificate_expired": false,

  "stream_integrity": "COMPLETE",

  "handshake_failures": 0,

  "analysis_confidence": "HIGH"
}

This contract may be extended.

Do not casually rename fields once consumed by multiple components.

If a breaking schema change is necessary:

1. document it
2. update consumers
3. add migration/tests
4. maintain compatibility where practical

---

# 8. FAILURE MODE SPECIFICATION

Failure behavior is part of the product.

==================================================
INPUT FAILURES
==================================================

## Empty PCAP

Behavior:

- accept as syntactically valid input if format permits
- complete analysis
- report zero packets
- report zero email sessions

Do not crash.

---

## Corrupt PCAP

Behavior:

- detect when possible
- mark evidence/analysis appropriately
- return structured error
- preserve evidence metadata
- do not fabricate results

---

## Unsupported file

Behavior:

- reject upload
- clear user-facing message
- no worker created

---

## Oversized PCAP

Behavior:

- enforce configurable size limit
- reject with structured error

Example configuration:

MAX_PCAP_SIZE_MB

Do not silently truncate unless explicitly implemented and clearly reported.

---

## 4GB PCAP

Do not assume unlimited processing.

Behavior depends on configured MAX_PCAP_SIZE_MB.

If above configured limit:

- reject
- explain maximum supported size

If accepted:

- process asynchronously
- enforce worker resource limits
- expose progress
- enforce timeout/resource policy

---

# TSHARK FAILURES

Possible states:

- TSHARK_EXECUTION_FAILED
- TSHARK_TIMEOUT
- TSHARK_INVALID_OUTPUT
- TSHARK_PARTIAL_OUTPUT
- TSHARK_UNAVAILABLE

Behavior:

- capture stderr
- capture exit code
- log technical details
- expose safe user-facing message
- mark analysis stage failed
- do not continue as though analysis succeeded

---

# NO EMAIL TRAFFIC

This is NOT an error.

Return:

status = COMPLETED

with:

email_protocols_detected = 0

User-facing message:

"No SMTP, IMAP, or POP3 traffic was detected in the supplied evidence."

---

# ONLY NON-EMAIL TRAFFIC

Complete analysis normally.

Do not generate email findings.

---

# IMPLICIT TLS / SMTPS / IMAPS / POP3S

These must be analyzed even without STARTTLS.

Do not require a visible STARTTLS command for TLS analysis.

---

# NON-STANDARD PORT

Do not automatically classify based only on port.

Use application-layer evidence where available.

---

# PARTIAL TCP STREAM

Mark:

stream_integrity = PARTIAL

Downstream components must know the stream is partial.

Do not report complete handshake/certificate validation unless evidence supports it.

---

# MALFORMED TLS

Behavior:

- preserve observed evidence
- mark TLS parsing anomaly
- avoid crashing entire case
- assign confidence based on available evidence

---

# ML FAILURE

Behavior:

- mark ML stage unavailable/failed
- continue deterministic analysis
- generate findings from rules
- dashboard clearly indicates ML unavailable

---

# PDF FAILURE

Behavior:

- preserve case
- preserve JSON/HTML
- expose PDF generation failure

---

# BLOCKCHAIN FAILURE

Behavior:

- preserve evidence hash
- mark blockchain verification unavailable
- do not affect forensic analysis

---

# 9. STREAM INTEGRITY

Every stream MUST expose:

COMPLETE
PARTIAL
CORRUPTED
UNKNOWN

This is mandatory.

Downstream TLS/certificate analysis must respect this state.

A PARTIAL stream cannot be silently represented as COMPLETE.

---

# 10. RISK AND SEVERITY

Use explainable categories:

- CRITICAL
- HIGH
- MEDIUM
- LOW
- INFO

Do not make ML the sole source of severity.

Deterministic cryptographic findings must remain explainable.

Every finding should explain:

WHAT happened
WHY it matters
WHAT evidence supports it
HOW confident the system is
WHAT remediation is recommended

---

# 11. SECURITY POSTURE

The dashboard should eventually expose:

Overall Security Posture

and supporting dimensions such as:

- TLS Security
- Certificate Security
- Protocol Security
- Configuration Security
- Anomaly Risk

The exact scoring formula must be documented and deterministic.

Do not present an arbitrary score without explaining its inputs.

---

# 12. API DESIGN PRINCIPLES

Use versioned APIs:

/api/v1/...

Potential routes:

/api/v1/health
/api/v1/cases
/api/v1/pcaps
/api/v1/analysis
/api/v1/sessions
/api/v1/tls
/api/v1/certificates
/api/v1/findings
/api/v1/reports

Use Pydantic schemas.

Return structured errors.

Do not expose internal Python tracebacks to users.

---

# 13. DATABASE PRINCIPLES

Core entities should eventually include:

cases
pcaps
analysis_jobs
sessions
tls_sessions
certificates
findings
recommendations
reports

Use foreign keys and indexes appropriately.

Evidence metadata must remain linked to the original case.

Do not store huge packet payloads directly in PostgreSQL unless explicitly justified.

---

# 14. ASYNCHRONOUS PROCESSING

Never perform large PCAP analysis directly inside the normal HTTP request lifecycle.

Correct flow:

Upload
→ create evidence
→ create analysis job
→ enqueue Celery task
→ return job ID
→ worker processes evidence
→ update job status
→ frontend polls or receives status
→ dashboard displays results

Supported statuses should include:

QUEUED
RUNNING
COMPLETED
FAILED
PARTIAL
CANCELLED

---

# 15. TESTING REQUIREMENTS

Every phase must introduce tests.

Required categories:

## Unit tests

For:

- parsing
- validation
- rules
- feature extraction
- schemas

## Integration tests

For:

PCAP
→ TShark
→ parser
→ database

## End-to-end tests

For:

upload
→ analysis
→ results
→ dashboard/API

## Failure tests

Mandatory for:

- corrupt PCAP
- empty PCAP
- oversized PCAP
- TShark failure
- TShark timeout
- partial stream
- malformed TLS
- no email traffic
- non-standard port
- implicit TLS
- ML unavailable

---

# 16. DEVELOPMENT RULES FOR CLAUDE CODE

Before making changes:

1. Read CLAUDE.md.
2. Inspect the existing repository.
3. Identify existing implementation.
4. Do not recreate existing components unnecessarily.
5. Follow the current architecture.
6. Preserve working functionality.
7. Add tests with implementation.
8. Run relevant tests after changes.
9. Report files changed.
10. Report tests executed and their results.
11. Report known limitations.
12. Do not claim functionality was tested if it was not tested.

Do not make broad unrelated refactors.

Do not introduce dependencies without justification.

Do not silently replace one technology with another.

Do not delete existing functionality simply to simplify implementation.

---

# 17. CODE QUALITY RULES

Prefer:

- small modules
- clear interfaces
- type hints
- Pydantic validation
- structured logging
- dependency injection where appropriate
- configuration through environment variables
- deterministic behavior
- explicit error handling

Avoid:

- giant files
- hard-coded credentials
- hard-coded absolute paths
- hidden global state
- silent exception handling
- arbitrary magic numbers
- duplicated business logic

---

# 18. ENVIRONMENT CONFIGURATION

Secrets and deployment-specific values must come from environment variables.

Never commit:

- API keys
- database passwords
- JWT secrets
- cloud credentials
- blockchain private keys

Provide:

.env.example

with safe placeholders.

---

# 19. MVP DEFINITION

MVP is COMPLETE when a user can:

1. Open SecureMailScope.
2. Upload a PCAP/PCAPNG.
3. Receive a SHA-256 evidence hash.
4. Start asynchronous analysis.
5. See analysis progress.
6. Detect SMTP/IMAP/POP3 where present.
7. Detect standard and supported non-standard ports.
8. Detect plaintext email.
9. Detect STARTTLS/STLS.
10. Detect implicit TLS/SMTPS/IMAPS/POP3S.
11. Reconstruct TCP streams.
12. Identify stream integrity.
13. Parse TLS where evidence permits.
14. Extract TLS version.
15. Extract cipher suite.
16. Identify key exchange.
17. Assess forward secrecy.
18. Extract X.509 certificates.
19. Check certificate validity.
20. Detect cryptographic weaknesses.
21. Generate explainable findings.
22. Generate recommendations.
23. Calculate security posture.
24. Display results in a functional web dashboard.
25. Handle expected failures gracefully.
26. Run through Docker.
27. Be deployable to a public environment.

MVP DOES NOT require:

- ML
- blockchain
- advanced PDF reports
- live traffic capture
- distributed processing

These are post-MVP enhancements.

---

# 20. POST-MVP PRIORITIES

Priority 1:
ML anomaly detection

Priority 2:
ML risk classification

Priority 3:
HTML/JSON/PDF reports

Priority 4:
Blockchain evidence integrity

Priority 5:
advanced SOC functionality

Priority 6:
production hardening and scaling

---

# 21. ABSOLUTE ARCHITECTURAL RULES

RULE 1:
Never fabricate forensic evidence.

RULE 2:
Never treat incomplete evidence as complete.

RULE 3:
Never allow TShark failure to silently produce empty results.

RULE 4:
Never make ML a dependency of deterministic security analysis.

RULE 5:
Never make blockchain a dependency of forensic analysis.

RULE 6:
Never store sensitive PCAP contents on blockchain.

RULE 7:
Never perform large PCAP processing synchronously inside HTTP requests.

RULE 8:
Never identify email protocols using only port numbers.

RULE 9:
Never claim certificate validation when required certificate evidence is unavailable.

RULE 10:
Every phase must have tests and acceptance criteria.

RULE 11:
Do not implement future phases prematurely unless explicitly requested.

RULE 12:
Preserve the architecture and contracts established by previous phases.

RULE 13:
When uncertain, inspect the repository and existing code before making assumptions.

RULE 14:
When a requirement is impossible with available evidence, report UNKNOWN rather than guessing.

RULE 15:
The core forensic pipeline must remain functional when optional components fail.

---

# 22. CURRENT EXECUTION STATE

The project starts at:

PHASE 0 — FOUNDATION

Do not skip Phase 0.

Do not implement Phase 1+ unless explicitly instructed.

The next implementation task is the Phase 0 prompt supplied separately.

END OF CLAUDE.MD