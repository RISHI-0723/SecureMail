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
echo "[2/2] Starting FastAPI server..."
echo "   Workers: 4"
echo "   Timeout: 360s"
echo "   Bind: 0.0.0.0:8000"
echo "==================================================================="
echo ""

exec gunicorn app.main:app \
    --worker-class uvicorn.workers.UvicornWorker \
    --workers 4 \
    --bind 0.0.0.0:8000 \
    --timeout 360 \
    --keep-alive 5 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --access-logfile - \
    --error-logfile - \
    --capture-output
