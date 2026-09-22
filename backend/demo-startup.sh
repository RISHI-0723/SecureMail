#!/bin/bash
# =============================================================================
# SecureMailScope Demo Startup Script
# =============================================================================
#
# This script is used ONLY for the FREE demo deployment on Render.
#
# Render's free tier does NOT support preDeployCommand, so we run
# database migrations here before starting the FastAPI server.
#
# Production deployments (render.yaml) use preDeployCommand instead.
#
# =============================================================================

set -e  # Exit on error

echo "==================================================================="
echo "SecureMailScope Demo Startup"
echo "==================================================================="

# Step 1: Run database migrations
echo "[1/2] Running database migrations..."
alembic upgrade head

if [ $? -eq 0 ]; then
    echo "✓ Database migrations completed successfully"
else
    echo "✗ Database migrations failed"
    exit 1
fi

echo ""

# Step 2: Start FastAPI server with Gunicorn
echo "[2/2] Starting FastAPI server (DEMO MODE)..."
echo "   Configuration: Render Free (512MB RAM, 0.1 CPU)"
echo "   Workers: 1 (optimized for demo - 4 workers caused OOM)"
echo "   Timeout: 120s"
echo "   Bind: 0.0.0.0:8000"
echo "   Analysis: Background threads (Redis-free)"
echo "==================================================================="
echo ""

# CRITICAL: Use ONLY 1 worker for Render Free (512MB RAM)
# 4 workers = ~400-600MB just for workers = OOM during TShark analysis
# 1 worker = ~100-150MB = leaves room for TShark subprocess
exec gunicorn app.main:app \
    --worker-class uvicorn.workers.UvicornWorker \
    --workers 1 \
    --bind 0.0.0.0:8000 \
    --timeout 120 \
    --keep-alive 5 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --worker-tmp-dir /dev/shm \
    --access-logfile - \
    --error-logfile - \
    --capture-output \
    --log-level info
