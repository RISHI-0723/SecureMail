# SecureMailScope

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**

SecureMailScope is a passive network-forensic platform that analyzes PCAP/PCAPNG files containing SMTP, IMAP, and POP3 communications and evaluates their cryptographic security posture.

**Version: 0.5.0 - Production Ready**

---

## Current Status: Phase 5 Complete - Production Ready

All core phases are complete. SecureMailScope provides comprehensive email security forensic analysis:

### Completed Phases

- **Phase 0: Foundation** - Docker infrastructure, FastAPI, React, PostgreSQL, Redis, Celery
- **Phase 1: Evidence Ingestion** - PCAP/PCAPNG upload, validation, SHA-256 hashing
- **Phase 2: Packet Analysis** - TShark integration, protocol detection (SMTP/IMAP/POP3)
- **Phase 3: Security Intelligence** - TCP stream reconstruction, TLS analysis, certificate validation, findings engine
- **Phase 4: Intelligence & Reporting** - Correlation engine, ML anomaly detection, report generation
- **Phase 5: Production Hardening** - JWT authentication, RBAC, security headers, HTTPS ready

### Key Features

- JWT-based authentication with role-based access control (ADMIN, ANALYST, VIEWER)
- PCAP/PCAPNG evidence upload with magic-byte validation
- TShark-based protocol detection (SMTP, IMAP, POP3)
- TLS handshake analysis and cipher suite assessment
- X.509 certificate extraction and validation
- Deterministic security findings with severity levels
- Risk scoring and security posture calculation
- ML-powered anomaly detection (Isolation Forest)
- JSON/HTML report generation
- Evidence integrity verification with SHA-256/SHA-512
- Comprehensive audit logging
- Rate limiting and brute-force protection

---

## Technology Stack

### Backend
- **Python 3.12+** with FastAPI
- **SQLAlchemy** + Alembic for database
- **Celery** + Redis for async tasks
- **TShark** for packet analysis
- **scikit-learn** for ML anomaly detection
- **python-jose** for JWT authentication

### Frontend
- **React 18** with TypeScript
- **Vite** build tool
- **Tailwind CSS** for styling
- **Lucide React** icons

### Infrastructure
- **PostgreSQL 16** - Primary database
- **Redis 7** - Cache and message broker
- **Docker & Docker Compose** - Containerization
- **NGINX** - Reverse proxy (production)

---

## Quick Start

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- Git

### 1. Clone and Configure

```bash
git clone <repository-url>
cd SecureMail
cp .env.example .env
```

Edit `.env` to set secure passwords for:
- `POSTGRES_PASSWORD`
- `SECRET_KEY`
- `ADMIN_PASSWORD`

### 2. Start Services

```bash
docker compose up --build
```

### 3. Run Migrations

```bash
docker compose exec backend alembic upgrade head
```

### 4. Access Application

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/api/docs (development only)

### 5. Login

Use the admin credentials configured in `.env`:
- Username: `admin` (default)
- Password: Set via `ADMIN_PASSWORD` environment variable

---

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | Authenticate user |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| GET | `/api/v1/auth/me` | Get current user info |

### Cases
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/cases` | Create forensic case |
| GET | `/api/v1/cases` | List all cases |
| GET | `/api/v1/cases/{id}` | Get case details |
| PATCH | `/api/v1/cases/{id}` | Update case |
| DELETE | `/api/v1/cases/{id}` | Delete case |

### Evidence
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/cases/{id}/evidence` | Upload PCAP/PCAPNG |
| GET | `/api/v1/cases/{id}/evidence` | List case evidence |
| GET | `/api/v1/evidence/{id}` | Get evidence details |

### Analysis
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/analysis/{job_id}` | Get analysis job status |
| GET | `/api/v1/analysis/{job_id}/summary` | Get analysis summary |
| GET | `/api/v1/analysis/{job_id}/protocols` | Get detected protocols |

### Security Intelligence
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/security/{evidence_id}` | Get security analysis |
| GET | `/api/v1/security/{evidence_id}/findings` | Get security findings |
| GET | `/api/v1/security/{evidence_id}/risk` | Get risk assessment |

### Intelligence & Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/intelligence/{evidence_id}` | Get intelligence report |
| GET | `/api/v1/intelligence/{evidence_id}/report/json` | Download JSON report |
| GET | `/api/v1/intelligence/{evidence_id}/report/html` | Download HTML report |
| GET | `/api/v1/intelligence/{evidence_id}/integrity` | Get integrity info |

---

## Running Tests

```bash
cd backend

# Run all tests
pytest

# Run with coverage
pytest --cov=app tests/

# Run specific test modules
pytest tests/test_phase3_security_analysis.py
pytest tests/test_phase4_intelligence.py
```

Current test status: **172/174 tests passing** (2 TShark path tests skipped on Windows)

---

## Environment Variables

### Required for Production

| Variable | Description |
|----------|-------------|
| `ENVIRONMENT` | Set to `production` |
| `SECRET_KEY` | JWT secret (32+ chars) |
| `POSTGRES_PASSWORD` | Database password |
| `ADMIN_PASSWORD` | Initial admin password |
| `CORS_ORIGINS` | Frontend URL(s) |

### Optional Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | false | Enable debug mode |
| `MAX_PCAP_SIZE_MB` | 500 | Max upload size |
| `TSHARK_TIMEOUT_SECONDS` | 300 | Analysis timeout |
| `ML_ENABLED` | true | Enable ML detection |
| `BLOCKCHAIN_ENABLED` | false | Enable blockchain |

See `backend/.env.production.example` for full configuration.

---

## Security Features

### Authentication
- JWT access tokens (30 min expiry)
- Refresh tokens (7 day expiry)
- Account lockout after 5 failed attempts

### Authorization
- Role-based access control (RBAC)
- ADMIN: Full system access
- ANALYST: Create cases, analyze evidence
- VIEWER: Read-only access

### Security Headers
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Strict-Transport-Security (HTTPS)

### Input Validation
- File size limits
- Magic-byte validation
- Path traversal protection
- Rate limiting

---

## Project Structure

```
securemailscope/
├── backend/
│   ├── app/
│   │   ├── api/routes/           # API endpoints
│   │   ├── core/                 # Config, security, database
│   │   ├── models/               # SQLAlchemy models
│   │   ├── schemas/              # Pydantic schemas
│   │   ├── services/             # Business logic
│   │   │   ├── ingestion/        # Evidence handling
│   │   │   ├── packet/           # TShark integration
│   │   │   ├── tcp/              # Stream reconstruction
│   │   │   ├── tls/              # TLS analysis
│   │   │   ├── certificates/     # X.509 analysis
│   │   │   ├── findings/         # Security findings
│   │   │   ├── risk/             # Risk scoring
│   │   │   ├── intelligence/     # Correlation engine
│   │   │   ├── ml/               # Anomaly detection
│   │   │   ├── reports/          # Report generation
│   │   │   └── integrity/        # Evidence integrity
│   │   └── workers/              # Celery tasks
│   ├── migrations/               # Alembic migrations
│   └── tests/                    # Test suite
│
├── frontend/
│   ├── src/
│   │   ├── components/           # UI components
│   │   ├── pages/                # Page components
│   │   ├── services/             # API client
│   │   └── types/                # TypeScript types
│   └── dist/                     # Production build
│
├── docker-compose.yml            # Development config
├── docker-compose.production.yml # Production config
└── .github/workflows/ci.yml      # CI/CD pipeline
```

---

## Troubleshooting

### Backend Issues

```bash
# Check logs
docker compose logs backend

# Check database
docker compose exec backend alembic current

# Reset database (WARNING: deletes data)
docker compose down -v
docker compose up -d postgres
docker compose exec backend alembic upgrade head
```

### TShark Issues

```bash
# Verify TShark in container
docker compose exec backend tshark --version
```

### Authentication Issues

- Ensure `SECRET_KEY` is set
- Check `ADMIN_PASSWORD` is configured
- Verify token in browser localStorage

---

## CI/CD

GitHub Actions workflow runs on push/PR to main:
- Backend tests with PostgreSQL/Redis
- Frontend build and typecheck
- Security scanning (Bandit, pip-audit)
- Docker image builds

---

## License

[License information to be added]

---

**SecureMailScope v0.5.0** - Production Ready with JWT Authentication, RBAC, and ML-powered Security Analysis
