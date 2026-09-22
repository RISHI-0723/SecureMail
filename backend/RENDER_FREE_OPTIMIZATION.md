# Render Free Optimization Guide

## Problem Statement

The demo deployment on Render Free (512MB RAM, 0.1 CPU) was failing with:
```
HTTP health check failed (timed out after 5 seconds) while running your code.
```

Analysis was stuck at `RUNNING (EXTRACTING_PACKETS)` and never completed.

## Root Cause

**Memory pressure from excessive Gunicorn workers**:
- Previous config: **4 workers** on 512MB RAM
- Each Python worker: ~100-150MB
- 4 workers: ~400-600MB just for workers
- When background thread spawned TShark subprocess: **Out of Memory (OOM)**
- Gunicorn workers became unresponsive
- Health checks timed out
- Render killed the instance

## Solution

### 1. Reduced Worker Count (CRITICAL FIX)

**demo-startup.sh**:
```bash
--workers 1  # Changed from 4
```

**Memory breakdown**:
- 1 Gunicorn worker: ~100-150MB
- TShark subprocess (ping PCAP): ~20-50MB
- Python overhead: ~50MB
- Total: ~170-250MB (comfortable within 512MB)

### 2. Optimized Configuration

Added optimizations:
```bash
--worker-tmp-dir /dev/shm  # Use shared memory for worker files
--timeout 120              # Reduced from 360s
--log-level info          # Better diagnostics
```

### 3. Background Analysis Architecture

The demo mode already uses background threads correctly:
1. HTTP POST /analyze returns immediately
2. Background thread spawns
3. TShark runs in background thread
4. Health endpoint remains responsive
5. Frontend polls for completion

**Key insight**: The architecture was correct, only the worker count was wrong.

## Resource Allocation (Render Free)

| Component | Memory Usage | Notes |
|-----------|--------------|-------|
| Gunicorn worker | 100-150MB | Python + FastAPI |
| TShark subprocess | 20-50MB | For small PCAPs |
| PostgreSQL client | 10-20MB | SQLAlchemy pool |
| System overhead | 50-100MB | OS, libs |
| **Total** | **180-320MB** | **Safe margin** |

With 4 workers, total would be 400-700MB = **OOM on 512MB RAM**.

## Health Check Behavior

Render uses: `GET /api/v1/health`

This endpoint is fast and simple:
```python
@router.get("/health")
async def health_check():
    return {"status": "healthy", "service": "SecureMailScope API"}
```

- No database queries
- No Redis checks
- No blocking operations
- Response time: <10ms

The `/health/dependencies` endpoint (not used by Render) checks Redis with 2s timeout.

## TShark Configuration

TShark runs with:
- Timeout: 300s (from env var)
- Process isolation: subprocess.Popen
- Memory efficient: streaming output
- `-n` flag: disables name resolution (prevents delays)

For ping-request-and-reply.pcapng (1KB):
- Expected duration: <2 seconds
- Memory usage: minimal

## Demo Mode Flow

```
Upload PCAP
  ↓
POST /api/v1/evidence/{id}/analyze
  ↓
Create analysis job (status=QUEUED)
  ↓
Return 200 OK immediately ← HTTP request completes
  ↓
[Background Thread Starts]
  ↓
Phase 2: TShark extraction
  ↓
Phase 3: Security analysis
  ↓
Phase 4: Intelligence
  ↓
Update job status=COMPLETED
  ↓
[Frontend polls and retrieves results]
```

**Critical**: The HTTP worker is free during analysis.

## Deployment Verification

After deploying these changes:

1. **Health check should pass**:
   ```
   curl https://your-app.onrender.com/api/v1/health
   ```
   Expected: `{"status": "healthy", ...}` in <1s

2. **Analysis should complete**:
   - Upload ping-request-and-reply.pcapng
   - Job should reach COMPLETED status
   - Results should be available

3. **Memory should be stable**:
   - Check Render metrics
   - Should stay under 300MB during analysis

## Troubleshooting

### If health checks still timeout:

1. Check Render logs for OOM killer
2. Verify worker count is 1
3. Check for blocking operations in health endpoint
4. Verify TShark binary exists

### If analysis hangs:

1. Check job status in database
2. Look for DEMO_PHASE*_FAILED logs
3. Check TShark timeout settings
4. Verify background thread started

### If memory is still high:

1. Reduce max-requests (currently 1000)
2. Check for memory leaks in analysis pipeline
3. Ensure temporary files are cleaned up
4. Monitor SQLAlchemy connection pool

## Production Recommendations

For production with higher traffic:
- Use paid Render plan (1GB+ RAM)
- Increase to 2-4 workers
- Use Celery for background processing
- Enable Redis for task queue
- Scale horizontally with load balancer

## References

- Render Free tier: 512MB RAM, 0.1 CPU
- Gunicorn memory: https://docs.gunicorn.org/en/stable/design.html
- Render health checks: https://render.com/docs/health-checks
