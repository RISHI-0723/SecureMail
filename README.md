# SecureMailScope

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**

SecureMailScope is a passive network-forensic platform that analyzes PCAP/PCAPNG files containing SMTP, IMAP, and POP3 communications and evaluates their cryptographic security posture.

---

## Current Phase: Phase 2 - Packet and Email Protocol Analysis

This repository is currently at **Phase 2**, which implements Packet and Email Protocol Analysis using TShark. Phase 0 (Foundation) and Phase 1 (Evidence Ingestion) are complete.

### Phase 2 Capabilities

Phase 2 provides:
- ✅ TShark-based packet extraction
- ✅ SMTP protocol detection (ports 25, 465, 587 + TShark dissector)
- ✅ IMAP protocol detection (ports 143, 993 + TShark dissector)
- ✅ POP3 protocol detection (ports 110, 995 + TShark dissector)
- ✅ TLS presence detection (no security analysis yet)
- ✅ Non-standard port detection via TShark dissector
- ✅ Protocol session candidates (packet groupings)
- ✅ TShark binary validation (fails fast if missing)
- ✅ Configurable TShark timeout
- ✅ Analysis job lifecycle (QUEUED → RUNNING → COMPLETED/FAILED/TIMEOUT)
- ✅ Worker crash recovery (RUNNING jobs marked FAILED on restart)
- ✅ REST API for analysis triggers and results
- ✅ Celery retry policy (only DB errors, max 2 retries, 10s backoff)

### Phase 2 Architecture

```
Evidence Upload (Phase 1)
        ↓
Analysis Job (QUEUED)
        ↓
POST /api/v1/evidence/{id}/analyze
        ↓
Celery Worker
        ↓
TShark Binary Validation (fails fast if missing)
        ↓
TShark Packet Extraction
        ↓
Packet Parser
        ↓
Protocol Detector
        ↓
PacketAnalysis Persisted
        ↓
Job COMPLETED
```

### Phase 2 API Endpoints

- `POST /api/v1/evidence/{evidence_id}/analyze` - Trigger analysis
- `GET /api/v1/analysis/{job_id}` - Get job status
- `GET /api/v1/analysis/{job_id}/summary` - Get packet analysis summary
- `GET /api/v1/analysis/{job_id}/protocols` - Get detected protocols

### Phase 2 Boundaries

**Phase 2 implements ONLY:**
- Packet extraction
- Protocol identification

**Phase 2 does NOT implement:**
- ❌ TCP stream reconstruction (Phase 3)
- ❌ STARTTLS/STLS success/failure analysis (Phase 4)
- ❌ TLS security analysis (Phase 5)
- ❌ Certificate validation (Phase 5)
- ❌ Cryptographic security assessment (Phase 6)
- ❌ Risk scoring (Phase 6)
- ❌ Recommendations (Phase 6)
- ❌ Machine learning (Phase 8)
- ❌ Blockchain verification (Phase 9)
- ❌ Report generation (Phase 9)

### Previous Phases

#### Phase 1 - Evidence Ingestion (COMPLETE)
- Forensic case management
- PCAP/PCAPNG file upload
- Magic-byte validation
- SHA-256 evidence hashing
- Duplicate detection
- Secure file storage

#### Phase 0 - Foundation (COMPLETE)
- Docker Compose infrastructure
- FastAPI backend
- React frontend
- PostgreSQL database
- Redis cache
- Celery workers

---

## Technology Stack

### Backend
- **Python 3.12+**
- **FastAPI** - Modern async web framework
- **Pydantic** - Data validation
- **SQLAlchemy** - ORM
- **Alembic** - Database migrations
- **Uvicorn** - ASGI server
- **Redis** - Caching and message broker
- **Celery** - Asynchronous task queue

### Frontend
- **React 18** - UI library
- **TypeScript** - Type safety
- **Vite** - Build tool
- **Tailwind CSS** - Styling
- **Lucide React** - Icons

### Infrastructure
- **PostgreSQL 16** - Primary database
- **Redis 7** - Cache and message broker
- **Docker & Docker Compose** - Containerization

---

## Prerequisites

- **Docker** (version 20.10+)
- **Docker Compose** (version 2.0+)
- **Git**

For local development without Docker:
- **Python 3.12+**
- **Node.js 20+**
- **PostgreSQL 16**
- **Redis 7**

---

## Quick Start with Docker Compose

### 1. Clone the Repository

```bash
git clone <repository-url>
cd SecureMail
```

### 2. Create Environment Configuration

```bash
cp .env.example .env
```

Edit `.env` and update any values as needed (especially `POSTGRES_PASSWORD`).

### 3. Start All Services

```bash
docker compose up --build
```

This will start:
- **Backend API** on http://localhost:8000
- **Frontend** on http://localhost:5173
- **PostgreSQL** on localhost:5432
- **Redis** on localhost:6379
- **Celery Worker** (background)

### 4. Run Database Migrations

```bash
docker compose exec backend alembic upgrade head
```

### 5. Access the Application

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/api/v1/health

---

## API Endpoints

### Health Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Root endpoint with service info |
| GET | `/api/v1/health` | Basic health check |
| GET | `/api/v1/health/dependencies` | Detailed health with dependencies |

### Case Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/cases` | Create a new forensic case |
| GET | `/api/v1/cases` | List all cases |
| GET | `/api/v1/cases/{case_id}` | Get case details |
| PATCH | `/api/v1/cases/{case_id}` | Update case |
| DELETE | `/api/v1/cases/{case_id}` | Delete case |

### Evidence Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/cases/{case_id}/evidence` | Upload PCAP/PCAPNG evidence |
| GET | `/api/v1/cases/{case_id}/evidence` | List case evidence |
| GET | `/api/v1/evidence/{evidence_id}` | Get evidence details |
| DELETE | `/api/v1/evidence/{evidence_id}` | Delete evidence |

### Analysis Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/analysis/{job_id}` | Get analysis job status |
| GET | `/api/v1/evidence/{evidence_id}/analysis` | Get evidence analysis jobs |
| GET | `/api/v1/analysis` | List all analysis jobs |

---

## Evidence Upload

### Supported File Formats
- `.pcap` - Standard PCAP format
- `.pcapng` - Next Generation PCAP format

### File Size Limit
Configurable via `MAX_PCAP_SIZE_MB` environment variable (default: 500 MB).

### Upload Response Example

```json
{
  "success": true,
  "data": {
    "evidence_id": "ev_abc123...",
    "case_id": "case_xyz...",
    "original_filename": "enterprise_mail.pcapng",
    "file_size_bytes": 1839201,
    "file_format": "pcapng",
    "sha256": "a91f3c7e...",
    "evidence_status": "VALIDATED",
    "analysis_job_id": "job_123...",
    "analysis_status": "QUEUED"
  }
}
```

### Error Responses

| Error Code | Description |
|------------|-------------|
| `EMPTY_FILE` | File is empty |
| `FILE_TOO_LARGE` | File exceeds maximum size |
| `UNSUPPORTED_FILE_TYPE` | Not a PCAP/PCAPNG file |
| `INVALID_PCAP` | Has .pcap extension but invalid magic bytes |
| `INVALID_PCAPNG` | Has .pcapng extension but invalid magic bytes |
| `DUPLICATE_EVIDENCE` | Same hash already exists in this case |
| `CASE_NOT_FOUND` | Target case does not exist |

---

## Running Tests

```bash
cd backend

# Run all tests
pytest

# Run with coverage
pytest --cov=app tests/

# Run specific test file
pytest tests/test_validation.py
pytest tests/test_cases_api.py
pytest tests/test_evidence_api.py
pytest tests/test_analysis_api.py

# Run with verbose output
pytest -v
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_USER` | securemailscope | Database user |
| `POSTGRES_PASSWORD` | changeme | Database password (CHANGE THIS!) |
| `POSTGRES_HOST` | postgres | Database host |
| `POSTGRES_DB` | securemailscope | Database name |
| `REDIS_HOST` | redis | Redis host |
| `LOG_LEVEL` | INFO | Logging level |
| `MAX_PCAP_SIZE_MB` | 500 | Max PCAP file size in MB |
| `EVIDENCE_STORAGE_PATH` | /app/data/evidence | Evidence storage directory |

---

## Docker Services

### View Running Services

```bash
docker compose ps
```

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f backend
docker compose logs -f frontend
docker compose logs -f worker
```

### Evidence Storage

Evidence files are stored in a Docker volume (`evidence_data`) that persists across container restarts:

```yaml
volumes:
  evidence_data:  # Persistent evidence storage
```

To verify evidence persistence:
1. Upload a PCAP file
2. Restart containers: `docker compose restart backend`
3. Evidence should still be accessible

---

## Database Migrations

### Create a New Migration

```bash
cd backend
alembic revision --autogenerate -m "Description of changes"
```

### Apply Migrations

```bash
alembic upgrade head
```

### Rollback Migration

```bash
alembic downgrade -1
```

---

## Project Structure

```
securemailscope/
├── backend/                    # FastAPI backend
│   ├── app/
│   │   ├── api/               # API routes
│   │   │   └── routes/
│   │   │       ├── health.py     # Health endpoints
│   │   │       ├── cases.py      # Case endpoints
│   │   │       ├── evidence.py   # Evidence endpoints
│   │   │       └── analysis.py   # Analysis endpoints
│   │   ├── core/              # Core configuration
│   │   ├── models/            # SQLAlchemy models
│   │   │   ├── case.py           # Case model
│   │   │   ├── evidence.py       # Evidence model
│   │   │   └── analysis_job.py   # Analysis job model
│   │   ├── schemas/           # Pydantic schemas
│   │   ├── services/          # Business logic
│   │   │   └── ingestion/        # Evidence ingestion
│   │   │       ├── storage.py       # Storage abstraction
│   │   │       ├── validation.py    # File validation
│   │   │       └── evidence_service.py
│   │   └── workers/           # Celery tasks
│   ├── migrations/            # Alembic migrations
│   ├── tests/                 # Backend tests
│   ├── Dockerfile
│   └── requirements.txt
│
├── frontend/                   # React frontend
│   ├── src/
│   │   ├── components/        # React components
│   │   ├── pages/             # Page components
│   │   │   ├── CasesPage.tsx     # Cases list
│   │   │   └── CaseDetailPage.tsx # Case details + upload
│   │   ├── services/          # API services
│   │   ├── types/             # TypeScript types
│   │   ├── App.tsx            # Main app component
│   │   └── main.tsx           # Entry point
│   ├── Dockerfile
│   └── package.json
│
├── docker-compose.yml         # Docker Compose configuration
├── .env.example               # Environment template
├── Claude.md                  # Project specification
└── README.md
```

---

## Development Roadmap

### Completed
- ✅ Phase 0: Foundation
- ✅ Phase 1: Evidence Ingestion (current)

### Upcoming Phases
- 🔲 Phase 2: Packet and Email Protocol Analysis (TShark integration)
- 🔲 Phase 3: TCP Stream Reconstruction
- 🔲 Phase 4: Email Security and TLS Transitions
- 🔲 Phase 5: TLS and X.509 Intelligence
- 🔲 Phase 6: Cryptographic Security Assessment
- 🔲 Phase 7: MVP Frontend
- 🔲 Phase 8: AI/ML
- 🔲 Phase 9: Reports and Evidence Integrity
- 🔲 Phase 10: Production Hardening

See `Claude.md` for detailed phase specifications.

---

## Current Limitations (Phase 1)

- Analysis jobs are created but not processed (Phase 2+)
- No TLS/certificate analysis (Phase 5)
- No email protocol detection (Phase 2)
- No security findings or recommendations (Phase 6)
- No ML/AI capabilities (Phase 8)
- Authentication not yet implemented (Phase 10)
- No production deployment configuration (Phase 10)

These limitations are intentional for Phase 1. Future phases will progressively add functionality.

---

## Troubleshooting

### Backend won't start

1. Check database connection:
   ```bash
   docker compose logs postgres
   ```
2. Verify environment variables in `.env`
3. Check if port 8000 is already in use

### Evidence upload fails

1. Check file format (.pcap or .pcapng)
2. Verify file size is within limit
3. Check backend logs: `docker compose logs backend`

### Frontend can't connect to backend

1. Verify backend is running: http://localhost:8000/api/v1/health
2. Check CORS configuration in `backend/app/main.py`
3. Clear browser cache and reload

### Database migration issues

```bash
# Reset database (WARNING: deletes all data)
docker compose down -v
docker compose up -d postgres
cd backend
alembic upgrade head
```

---

## Contributing

This project is currently in active development. Phase implementation follows the strict specifications in `Claude.md`.

---

## License

[License information to be added]

---

**Note**: This is Phase 1 - Evidence Ingestion. The system can now accept and validate PCAP/PCAPNG files, but actual forensic analysis (protocol detection, TLS parsing, security assessment) will be added in subsequent phases.
