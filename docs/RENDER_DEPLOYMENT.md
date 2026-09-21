# SecureMailScope - Render Deployment Guide

**Version:** 0.5.0
**Target Platform:** Render.com
**Date:** 2026-09-21

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Architecture](#architecture)
4. [Pre-Deployment Checklist](#pre-deployment-checklist)
5. [Deployment Steps](#deployment-steps)
6. [Environment Variables](#environment-variables)
7. [Post-Deployment Verification](#post-deployment-verification)
8. [Troubleshooting](#troubleshooting)
9. [Monitoring and Maintenance](#monitoring-and-maintenance)

---

## Overview

This guide provides step-by-step instructions for deploying SecureMailScope to Render's cloud platform. The deployment includes:

- **Backend API** - FastAPI with TShark packet analysis
- **Celery Worker** - Background job processing (Phase 2→3→4 pipeline)
- **Frontend** - React SPA with Vite
- **PostgreSQL** - Primary database
- **Redis** - Celery broker and result backend
- **Persistent Storage** - 20GB disks for evidence and reports

The deployed application will be accessible via public HTTPS URLs and will function independently of the developer's machine.

---

## Prerequisites

### Required Accounts

1. **Render Account** - Sign up at https://render.com
2. **GitHub Account** - For repository integration
3. **Git Repository** - SecureMailScope codebase pushed to GitHub/GitLab

### Local Environment

- Docker and Docker Compose installed (for validation)
- Node.js 18+ (for frontend build testing)
- Python 3.12+ (for backend testing)
- Git CLI

### Pre-Deployment Validation

All production builds MUST be validated locally before deploying:

```bash
# Backend production Docker build
cd backend
docker build -f Dockerfile.production -t securemailscope-backend:prod .
docker run --rm securemailscope-backend:prod tshark --version

# Frontend production build
cd frontend
npm ci
npm run build

# Migration chain test (from clean database)
docker compose down -v
docker compose up -d postgres redis
sleep 10
docker compose run --rm backend alembic upgrade head
```

**Expected Results:**
- Backend build completes successfully
- TShark version 4.4.18+ is installed
- Frontend build produces dist/ folder with no errors
- All 6 migrations complete without errors

---

## Architecture

### Services Overview

```
┌─────────────────────────────────────────────────────────┐
│                   RENDER CLOUD PLATFORM                  │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌─────────────────┐     ┌─────────────────┐            │
│  │  Frontend (Web) │────▶│  Backend (Web)  │            │
│  │   Static Site   │     │    FastAPI      │            │
│  │   React + Vite  │     │  Gunicorn + UV  │            │
│  └─────────────────┘     └────────┬────────┘            │
│         │                         │                      │
│         │                         ├──▶ PostgreSQL       │
│         │                         │    (Database)        │
│         │                         │                      │
│         │                         └──▶ Redis             │
│         │                              (Key-Value)       │
│         │                                   │            │
│         │                    ┌──────────────┘            │
│         │                    │                           │
│         │             ┌──────▼──────┐                    │
│         │             │   Worker    │                    │
│         └────────────▶│   Celery    │                    │
│           (via API)   │  Background │                    │
│                       │  Processing │                    │
│                       └─────────────┘                    │
│                                                           │
│  Storage:                                                │
│  ├─ /app/data (Backend) - 20GB persistent disk          │
│  └─ /app/data (Worker)  - 20GB persistent disk          │
│                                                           │
└─────────────────────────────────────────────────────────┘

Internet → HTTPS → Frontend → Backend API → Worker → Analysis
```

### Service Details

| Service | Type | Runtime | Purpose |
|---------|------|---------|---------|
| `securemailscope-frontend` | Static Site | Node 18 | React UI served via CDN |
| `securemailscope-api` | Web Service | Docker | FastAPI backend with health checks |
| `securemailscope-worker` | Background Worker | Docker | Celery task processing |
| `securemailscope-postgres` | PostgreSQL | Managed DB | Primary data storage |
| `securemailscope-redis` | Redis | Key-Value Store | Celery broker/backend |

---

## Pre-Deployment Checklist

### 1. Code Preparation

- [ ] All changes committed to Git
- [ ] No secrets in source control
- [ ] `.env.example` updated with all required variables
- [ ] `render.yaml` blueprint file exists at repository root
- [ ] Production Dockerfiles tested locally
- [ ] Frontend production build tested
- [ ] Migration chain tested from clean database

### 2. Repository Setup

- [ ] Repository pushed to GitHub/GitLab
- [ ] Repository is public or Render has access
- [ ] Default branch is configured (usually `master` or `main`)

### 3. Render Account Setup

- [ ] Logged into Render dashboard
- [ ] Payment method configured (for Standard plan services)
- [ ] Region selected (Singapore recommended for SIH demo)

---

## Deployment Steps

### Step 1: Connect Repository to Render

1. **Log into Render Dashboard**
   - Navigate to https://dashboard.render.com

2. **Create New Blueprint**
   - Click "Blueprints" in sidebar
   - Click "New Blueprint Instance"
   - Select "Connect a repository"

3. **Connect GitHub/GitLab**
   - Authorize Render to access your repository
   - Select the SecureMailScope repository
   - Click "Connect"

### Step 2: Configure Blueprint

Render will automatically detect `render.yaml` in the repository root.

1. **Review Detected Services**
   - Verify 5 services are detected:
     - securemailscope-api (Web)
     - securemailscope-worker (Worker)
     - securemailscope-frontend (Static Site)
     - securemailscope-postgres (PostgreSQL)
     - securemailscope-redis (Redis)

2. **Configure Service Plans**
   - Backend API: **Standard** ($25/month)
   - Worker: **Standard** ($25/month)
   - Frontend: **Starter** (Free)
   - PostgreSQL: **Standard** ($20/month)
   - Redis: **Standard** ($10/month)

   **Total Estimated Cost:** ~$80/month

3. **Configure Regions**
   - All services should use **Singapore** region (specified in render.yaml)

### Step 3: Configure Environment Variables

Render will auto-generate some environment variables. Verify the following:

#### Backend API (`securemailscope-api`)

| Variable | Source | Value |
|----------|--------|-------|
| `ENVIRONMENT` | render.yaml | `production` |
| `DEBUG` | render.yaml | `false` |
| `PORT` | render.yaml | `8000` |
| `DATABASE_URL` | Auto-generated | From PostgreSQL service |
| `REDIS_URL` | Auto-generated | From Redis service |
| `SECRET_KEY` | Auto-generated | Secure random string |
| `ADMIN_PASSWORD` | Auto-generated | Secure random string |
| `CORS_ORIGINS` | render.yaml | Frontend URL |
| `MAX_PCAP_SIZE_MB` | render.yaml | `500` |
| `ML_ENABLED` | render.yaml | `true` |
| `BLOCKCHAIN_ENABLED` | render.yaml | `false` |
| `LOG_LEVEL` | render.yaml | `INFO` |
| `EVIDENCE_STORAGE_PATH` | render.yaml | `/app/data/evidence` |
| `REPORTS_STORAGE_PATH` | render.yaml | `/app/data/reports` |
| `TSHARK_TIMEOUT_SECONDS` | render.yaml | `300` |

#### Worker (`securemailscope-worker`)

Same as Backend API, except:
- Does not need `ADMIN_PASSWORD`
- `SECRET_KEY` should sync from backend (configured in render.yaml)

#### Frontend (`securemailscope-frontend`)

| Variable | Source | Value |
|----------|--------|-------|
| `VITE_API_URL` | render.yaml | `https://securemailscope-api.onrender.com` |

### Step 4: Deploy

1. **Click "Apply"** to create all services

2. **Monitor Deployment**
   - Render will start building all services
   - Watch the deployment logs for each service
   - Backend will run `alembic upgrade head` before starting
   - First deployment takes ~5-10 minutes

3. **Verify Service URLs**
   - Frontend: `https://securemailscope-frontend.onrender.com`
   - Backend API: `https://securemailscope-api.onrender.com`

### Step 5: Update CORS Origins

After services are deployed, update the backend `CORS_ORIGINS` environment variable with the actual frontend URL:

1. Navigate to `securemailscope-api` service settings
2. Update `CORS_ORIGINS` from placeholder to actual frontend URL
3. Example: `https://securemailscope-frontend.onrender.com`
4. Click "Save Changes" (will trigger redeploy)

---

## Environment Variables

### Required Variables

All services require proper environment configuration. The `render.yaml` blueprint handles most of this automatically.

#### Backend API - Full List

```bash
# Application
ENVIRONMENT=production
DEBUG=false
PORT=8000

# Database (auto-generated from PostgreSQL service)
DATABASE_URL=postgresql://user:pass@host:5432/dbname

# Redis (auto-generated from Redis service)
REDIS_URL=redis://host:6379

# Security (auto-generated)
SECRET_KEY=<auto-generated-64-char-string>
ADMIN_PASSWORD=<auto-generated-strong-password>

# CORS (update after deployment)
CORS_ORIGINS=https://securemailscope-frontend.onrender.com

# File Upload Limits
MAX_PCAP_SIZE_MB=500

# Features
ML_ENABLED=true
BLOCKCHAIN_ENABLED=false

# Logging
LOG_LEVEL=INFO

# Storage Paths (persistent disk)
EVIDENCE_STORAGE_PATH=/app/data/evidence
REPORTS_STORAGE_PATH=/app/data/reports

# Processing
TSHARK_TIMEOUT_SECONDS=300
```

#### Worker - Full List

Same as Backend API, except:
- `SECRET_KEY` syncs from backend (sync: false in render.yaml)
- `ADMIN_PASSWORD` not needed

#### Frontend - Full List

```bash
# Backend API URL
VITE_API_URL=https://securemailscope-api.onrender.com
```

### Secrets Management

**CRITICAL:** Never commit secrets to source control.

- `SECRET_KEY` and `ADMIN_PASSWORD` are auto-generated by Render
- They are stored securely in Render's secret management system
- Use `sync: false` for variables that should not sync between services

---

## Post-Deployment Verification

### 1. Health Check

```bash
# Backend health endpoint
curl https://securemailscope-api.onrender.com/api/v1/health

# Expected response:
# {"status":"healthy","timestamp":"2026-09-21T..."}
```

### 2. Frontend Access

1. Open `https://securemailscope-frontend.onrender.com`
2. Verify login page loads correctly
3. Check browser console for errors

### 3. Authentication Test

1. **Get Admin Credentials**
   - Navigate to Backend API service settings
   - Find `ADMIN_PASSWORD` environment variable
   - Copy the auto-generated password

2. **Login**
   - Username: `admin`
   - Password: `<ADMIN_PASSWORD from environment>`

3. **Expected Result**
   - JWT token received
   - Redirected to dashboard
   - No CORS errors in console

### 4. Evidence Upload Test

1. **Prepare Test PCAP**
   - Use `sample_pcaps/smtp_starttls_demo.pcap` (small test file)

2. **Upload via Dashboard**
   - Navigate to Upload page
   - Select test PCAP file
   - Click "Upload Evidence"

3. **Monitor Processing**
   - Check job status updates
   - Verify Phase 2 → Phase 3 → Phase 4 pipeline runs
   - Wait for "COMPLETED" status

4. **Expected Results**
   - Evidence hash (SHA-256) displayed
   - Case created successfully
   - All 3 phases complete
   - Findings displayed
   - Intelligence report generated

### 5. Worker Verification

Check Render logs for worker service:

```
Expected log entries:
[INFO] celery@worker ready
[INFO] Task app.workers.tasks.analyze_pcap_full received
[INFO] Starting Phase 2: Packet Analysis
[INFO] Phase 2 completed
[INFO] Starting Phase 3: Security Analysis
[INFO] Phase 3 completed
[INFO] Starting Phase 4: Intelligence Aggregation
[INFO] Phase 4 completed
```

### 6. Storage Persistence Test

1. Upload evidence and wait for completion
2. Navigate to Backend service in Render dashboard
3. Click "Restart Service" → Manual Deploy
4. Wait for restart
5. Verify evidence still accessible after restart
6. Check that reports and evidence files persisted

---

## Troubleshooting

### Issue: Backend Health Check Failing

**Symptoms:**
- Backend service shows "Unhealthy"
- 503 Service Unavailable errors

**Solutions:**

1. Check deployment logs:
   ```
   Render Dashboard → securemailscope-api → Logs
   ```

2. Common causes:
   - Migration failed (check `alembic upgrade head` output)
   - Database connection error (verify DATABASE_URL)
   - Missing dependencies (rebuild Docker image)

3. Manual health check:
   ```bash
   # From Render Shell (Dashboard → Shell)
   curl http://localhost:8000/api/v1/health
   ```

### Issue: CORS Errors in Frontend

**Symptoms:**
- Browser console shows CORS policy errors
- API requests fail with "No 'Access-Control-Allow-Origin' header"

**Solutions:**

1. Verify `CORS_ORIGINS` environment variable:
   ```
   Backend API Settings → Environment → CORS_ORIGINS
   ```

2. Must match exact frontend URL (including https://)

3. Update and redeploy:
   ```
   CORS_ORIGINS=https://securemailscope-frontend.onrender.com
   ```

### Issue: Worker Not Processing Jobs

**Symptoms:**
- Jobs stuck in "QUEUED" status
- No worker logs appearing

**Solutions:**

1. Check worker logs:
   ```
   Render Dashboard → securemailscope-worker → Logs
   ```

2. Verify Redis connection:
   ```bash
   # From worker shell
   echo $REDIS_URL
   celery -A app.core.celery_app inspect ping
   ```

3. Restart worker service:
   ```
   Dashboard → securemailscope-worker → Manual Deploy → Deploy
   ```

### Issue: TShark Not Found

**Symptoms:**
- Worker logs show "tshark: command not found"
- Phase 2 fails immediately

**Solutions:**

1. Verify TShark in Docker image:
   ```bash
   # From worker shell
   tshark --version
   which tshark
   ```

2. If missing, check `Dockerfile.production`:
   ```dockerfile
   RUN apt-get install -y tshark
   ```

3. Rebuild and redeploy worker

### Issue: Database Migration Errors

**Symptoms:**
- Pre-deploy command fails
- "duplicate column" or "relation already exists" errors

**Solutions:**

1. Check migration status:
   ```bash
   # From backend shell
   alembic current
   alembic history
   ```

2. For enum errors (SECURITY_ANALYSIS, INTELLIGENCE):
   - Migration 0006_fix_enums should handle this
   - If still failing, manually add enum values:
   ```sql
   ALTER TYPE jobtype ADD VALUE IF NOT EXISTS 'SECURITY_ANALYSIS';
   ALTER TYPE jobtype ADD VALUE IF NOT EXISTS 'INTELLIGENCE';
   ```

### Issue: Large PCAP Upload Fails

**Symptoms:**
- Upload timeout
- Worker killed/OOM
- "Payload too large" errors

**Solutions:**

1. Check file size limit:
   ```
   Backend Settings → MAX_PCAP_SIZE_MB=500
   ```

2. Monitor worker memory during processing:
   ```
   Dashboard → securemailscope-worker → Metrics
   ```

3. For files > 200MB:
   - Increase worker memory (upgrade to Starter Plus or Standard plan)
   - Increase `TSHARK_TIMEOUT_SECONDS` to 600

4. Current limit: 500MB as configured

### Issue: Evidence Not Persisting

**Symptoms:**
- Files disappear after restart
- "Evidence file not found" errors

**Solutions:**

1. Verify persistent disk is mounted:
   ```bash
   # From backend shell
   df -h | grep /app/data
   ls -la /app/data/evidence
   ```

2. Check render.yaml disk configuration:
   ```yaml
   disk:
     name: securemailscope-data
     mountPath: /app/data
     sizeGB: 20
   ```

3. Ensure worker has separate disk (not shared with backend)

---

## Monitoring and Maintenance

### Daily Monitoring

1. **Service Health**
   - Check all 5 services are "Healthy" in dashboard
   - Review error logs for any issues

2. **Resource Usage**
   - Monitor disk space: `/app/data` (20GB limit)
   - Check memory usage on worker during large PCAP processing
   - Review database size growth

3. **Job Processing**
   - Verify jobs are completing successfully
   - Check average processing times
   - Monitor for stuck jobs

### Weekly Maintenance

1. **Database Cleanup**
   - Review old cases and evidence
   - Archive completed analyses
   - Vacuum PostgreSQL if needed

2. **Log Review**
   - Check for recurring errors
   - Review security audit logs
   - Identify performance bottlenecks

3. **Backup Verification**
   - Render automatically backs up PostgreSQL
   - Verify backup retention (7 days for Standard plan)

### Monthly Maintenance

1. **Security Updates**
   - Review Render platform updates
   - Update Python dependencies if needed
   - Rebuild Docker images with latest security patches

2. **Capacity Planning**
   - Review storage usage trends
   - Plan for disk expansion if needed
   - Consider worker scaling for heavy usage

3. **Cost Optimization**
   - Review Render usage and costs
   - Optimize service plans if needed
   - Archive old evidence to reduce storage costs

### Backup Strategy

**Automatic Backups (by Render):**
- PostgreSQL: Daily backups, 7-day retention (Standard plan)
- Persistent disks: Not automatically backed up

**Manual Backup Recommendations:**

1. **Database Backup**
   ```bash
   # From backend shell
   pg_dump $DATABASE_URL > backup_$(date +%Y%m%d).sql
   ```

2. **Evidence Backup**
   - Periodically download critical evidence files
   - Use cloud storage (S3/GCS) for long-term archival
   - Consider implementing automated backup script

### Scaling Considerations

**When to Scale:**

- Worker processing time > 5 minutes for standard PCAPs
- Disk usage > 80% of 20GB
- Concurrent users > 10
- Multiple large PCAPs (>100MB) uploaded daily

**Scaling Options:**

1. **Horizontal Scaling**
   - Add more worker instances
   - Use Render's autoscaling (requires Pro plan)

2. **Vertical Scaling**
   - Upgrade worker to Starter Plus (1GB RAM → 2GB RAM)
   - Upgrade database to larger plan
   - Increase disk size (20GB → 50GB)

3. **Performance Optimization**
   - Implement job prioritization
   - Add caching for frequently accessed reports
   - Optimize database queries

### Update Procedure

**For Code Updates:**

1. Commit changes to repository
2. Push to GitHub/GitLab
3. Render auto-deploys on push (if enabled)
4. Monitor deployment logs
5. Run post-deployment verification tests

**For Configuration Changes:**

1. Update environment variables in Render dashboard
2. Services auto-redeploy on env var changes
3. Monitor health checks during rollout

**For Database Schema Changes:**

1. Create Alembic migration locally
2. Test migration with `docker compose` locally
3. Commit migration to repository
4. Push to trigger deployment
5. Pre-deploy hook runs `alembic upgrade head`
6. Verify migration completed successfully

---

## Production Readiness Checklist

Before going live with SIH demo:

- [ ] All 5 services deployed and healthy
- [ ] Health check endpoint responding
- [ ] Frontend loads without errors
- [ ] Admin login works
- [ ] Test PCAP upload completes successfully
- [ ] Phase 2 → 3 → 4 pipeline executes
- [ ] Findings and intelligence report generated
- [ ] Evidence persists after service restart
- [ ] CORS configured correctly
- [ ] HTTPS working on all endpoints
- [ ] No secrets in source control
- [ ] Monitoring enabled
- [ ] Backup strategy documented
- [ ] 133MB PCAP test completed successfully

---

## Support and Resources

**Render Documentation:**
- https://render.com/docs
- https://render.com/docs/blueprint-spec
- https://render.com/docs/docker

**SecureMailScope Documentation:**
- `CLAUDE.md` - Master specification
- `README.md` - Project overview
- `docs/DEPLOYMENT.md` - Local deployment
- `docs/THREAT_MODEL.md` - Security considerations

**Common Commands:**

```bash
# View service logs
render logs <service-name>

# Restart service
render deploy <service-name>

# Run shell in service
render shell <service-name>

# Database connection
render db connect securemailscope-postgres
```

---

**Deployment Completed:** Ready for SIH Demo
**Support Contact:** See repository maintainers
**Last Updated:** 2026-09-21
