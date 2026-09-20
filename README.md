# SecureMailScope

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**

SecureMailScope is a passive network-forensic platform that analyzes PCAP/PCAPNG files containing SMTP, IMAP, and POP3 communications and evaluates their cryptographic security posture.

---

## Current Phase: Phase 0 - Foundation

This repository is currently at **Phase 0**, which establishes the foundational infrastructure. PCAP analysis and forensic capabilities will be implemented in subsequent phases.

### Phase 0 Scope

Phase 0 provides:
- ✅ FastAPI backend with structured JSON logging
- ✅ React + TypeScript + Vite frontend with Tailwind CSS
- ✅ PostgreSQL database with SQLAlchemy ORM
- ✅ Alembic database migration system
- ✅ Redis for caching and message broker
- ✅ Celery for asynchronous task processing
- ✅ Docker Compose orchestration
- ✅ Health check endpoints
- ✅ Frontend/backend connectivity
- ✅ Basic test infrastructure

### What's NOT in Phase 0

Phase 0 does NOT include:
- ❌ PCAP file upload or parsing
- ❌ TShark integration
- ❌ Email protocol analysis (SMTP/IMAP/POP3)
- ❌ TCP stream reconstruction
- ❌ TLS/X.509 analysis
- ❌ Cryptographic security assessment
- ❌ Machine learning models
- ❌ Blockchain evidence verification
- ❌ Advanced reporting (PDF/HTML)

These features will be implemented in Phases 1-10 according to the project roadmap in `Claude.md`.

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

### 4. Access the Application

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/api/v1/health

---

## Local Development Setup

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
export POSTGRES_HOST=localhost
export REDIS_HOST=localhost

# Run database migrations
alembic upgrade head

# Start backend server
uvicorn app.main:app --reload
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

### Running Tests

```bash
cd backend

# Run all tests
pytest

# Run with coverage
pytest --cov=app tests/

# Run specific test file
pytest tests/test_health.py
```

---

## API Endpoints

### Phase 0 Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Root endpoint with service info |
| GET | `/api/v1/health` | Basic health check |
| GET | `/api/v1/health/dependencies` | Detailed health with dependencies |

All endpoints return structured JSON responses with proper error handling.

---

## Project Structure

```
securemailscope/
├── backend/                    # FastAPI backend
│   ├── app/
│   │   ├── api/               # API routes
│   │   │   └── routes/        # Route modules
│   │   ├── core/              # Core configuration
│   │   ├── models/            # SQLAlchemy models
│   │   ├── schemas/           # Pydantic schemas
│   │   ├── services/          # Business logic
│   │   └── workers/           # Celery tasks
│   ├── migrations/            # Alembic migrations
│   ├── tests/                 # Backend tests
│   ├── Dockerfile
│   └── requirements.txt
│
├── frontend/                   # React frontend
│   ├── src/
│   │   ├── components/        # React components
│   │   ├── services/          # API services
│   │   ├── types/             # TypeScript types
│   │   ├── App.tsx            # Main app component
│   │   └── main.tsx           # Entry point
│   ├── Dockerfile
│   └── package.json
│
├── ml/                        # ML components (future)
├── blockchain/                # Blockchain integration (future)
├── sample_pcaps/              # Sample PCAP files (future)
├── tests/                     # Integration tests (future)
├── docs/                      # Documentation
│
├── docker-compose.yml         # Docker Compose configuration
├── .env.example               # Environment template
├── .gitignore
├── Claude.md                  # Project specification
└── README.md
```

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

## Environment Variables

Key environment variables (see `.env.example` for complete list):

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_USER` | securemailscope | Database user |
| `POSTGRES_PASSWORD` | changeme | Database password (CHANGE THIS!) |
| `POSTGRES_HOST` | postgres | Database host |
| `POSTGRES_DB` | securemailscope | Database name |
| `REDIS_HOST` | redis | Redis host |
| `LOG_LEVEL` | INFO | Logging level |
| `MAX_PCAP_SIZE_MB` | 500 | Max PCAP file size (future) |

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

### Restart a Service

```bash
docker compose restart backend
```

### Stop All Services

```bash
docker compose down
```

### Clean Up (Remove Volumes)

```bash
docker compose down -v
```

---

## Troubleshooting

### Backend won't start

1. Check database connection:
   ```bash
   docker compose logs postgres
   ```
2. Verify environment variables in `.env`
3. Check if port 8000 is already in use

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

## Current Limitations (Phase 0)

- No PCAP upload or analysis functionality
- No TLS/certificate analysis
- No email protocol detection
- No security findings or recommendations
- No ML/AI capabilities
- Authentication not yet implemented
- No production deployment configuration

These limitations are intentional for Phase 0. Future phases will progressively add functionality.

---

## Development Roadmap

### Completed
- ✅ Phase 0: Foundation (current)

### Upcoming Phases
- 🔲 Phase 1: Evidence Ingestion
- 🔲 Phase 2: Packet and Email Protocol Analysis
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

## Contributing

This project is currently in active development. Phase implementation follows the strict specifications in `Claude.md`.

---

## License

[License information to be added]

---

## Contact

[Contact information to be added]

---

**Note**: This is Phase 0 - Foundation. The system is not yet capable of analyzing PCAPs or assessing email security. These capabilities will be added in subsequent phases according to the project specification.
