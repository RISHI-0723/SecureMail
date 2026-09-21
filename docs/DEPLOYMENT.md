# SecureMailScope Deployment Guide

**Version:** 0.5.0
**Last Updated:** 2026-09-21

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Quick Start (Development)](#2-quick-start-development)
3. [Production Deployment](#3-production-deployment)
4. [SSL/TLS Configuration](#4-ssltls-configuration)
5. [Environment Configuration](#5-environment-configuration)
6. [Database Setup](#6-database-setup)
7. [Security Hardening](#7-security-hardening)
8. [Monitoring & Logging](#8-monitoring--logging)
9. [Backup & Recovery](#9-backup--recovery)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Prerequisites

### 1.1 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Storage | 20 GB | 100+ GB SSD |
| OS | Ubuntu 22.04 / Debian 12 | Ubuntu 24.04 LTS |

### 1.2 Software Requirements

```bash
# Docker & Docker Compose
docker --version    # >= 24.0
docker compose version  # >= 2.20

# Git
git --version       # >= 2.30

# OpenSSL (for certificate generation)
openssl version     # >= 3.0
```

### 1.3 Network Requirements

| Port | Service | Description |
|------|---------|-------------|
| 80 | HTTP | Redirects to HTTPS |
| 443 | HTTPS | Main application |
| 5432 | PostgreSQL | Internal only |
| 6379 | Redis | Internal only |
| 8000 | FastAPI | Internal only |

---

## 2. Quick Start (Development)

### 2.1 Clone Repository

```bash
git clone https://github.com/your-org/securemailscope.git
cd securemailscope
```

### 2.2 Start Development Environment

```bash
# Copy environment file
cp .env.example .env

# Start all services
docker compose up -d

# View logs
docker compose logs -f

# Access application
# Frontend: http://localhost:5173
# Backend: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### 2.3 Run Database Migrations

```bash
docker compose exec backend alembic upgrade head
```

---

## 3. Production Deployment

### 3.1 Prepare Environment

```bash
# Clone repository
git clone https://github.com/your-org/securemailscope.git
cd securemailscope

# Copy production environment template
cp backend/.env.production.example .env

# Edit configuration
nano .env
```

### 3.2 Generate Secrets

```bash
# Generate SECRET_KEY
openssl rand -hex 32

# Generate POSTGRES_PASSWORD
openssl rand -hex 16

# Generate strong ADMIN_PASSWORD
# Must include: uppercase, lowercase, digit, special char
```

### 3.3 Configure SSL Certificates

```bash
# Create SSL directory
mkdir -p ssl

# Option 1: Self-signed (testing only)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/key.pem \
  -out ssl/cert.pem \
  -subj "/CN=securemailscope.local"

# Option 2: Let's Encrypt (production)
# See Section 4 for detailed instructions
```

### 3.4 Deploy Application

```bash
# Build and start production containers
docker compose -f docker-compose.production.yml up -d --build

# Run database migrations
docker compose -f docker-compose.production.yml exec backend \
  alembic upgrade head

# Verify deployment
docker compose -f docker-compose.production.yml ps
```

### 3.5 Verify Deployment

```bash
# Check health endpoint
curl -k https://localhost/api/v1/health

# Check all services
docker compose -f docker-compose.production.yml ps

# View logs
docker compose -f docker-compose.production.yml logs -f
```

---

## 4. SSL/TLS Configuration

### 4.1 Let's Encrypt with Certbot

```bash
# Install certbot
sudo apt install certbot

# Generate certificate
sudo certbot certonly --standalone \
  -d securemailscope.yourdomain.com \
  --email admin@yourdomain.com \
  --agree-tos

# Copy certificates
sudo cp /etc/letsencrypt/live/securemailscope.yourdomain.com/fullchain.pem ssl/cert.pem
sudo cp /etc/letsencrypt/live/securemailscope.yourdomain.com/privkey.pem ssl/key.pem
sudo chmod 644 ssl/*.pem
```

### 4.2 Certificate Renewal

```bash
# Test renewal
sudo certbot renew --dry-run

# Add to crontab for auto-renewal
echo "0 3 * * * certbot renew --quiet && docker compose -f docker-compose.production.yml restart frontend" | sudo crontab -
```

### 4.3 Diffie-Hellman Parameters (Optional)

```bash
# Generate DH parameters (enhances security)
openssl dhparam -out ssl/dhparam.pem 2048

# Uncomment in nginx.production.conf:
# ssl_dhparam /etc/nginx/ssl/dhparam.pem;
```

---

## 5. Environment Configuration

### 5.1 Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `ENVIRONMENT` | Deployment environment | `production` |
| `SECRET_KEY` | JWT signing key | `openssl rand -hex 32` |
| `POSTGRES_PASSWORD` | Database password | `openssl rand -hex 16` |
| `ADMIN_PASSWORD` | Initial admin password | Strong password |
| `CORS_ORIGINS` | Allowed CORS origins | `https://yourdomain.com` |

### 5.2 Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | `false` | Enable debug mode |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `MAX_PCAP_SIZE_MB` | `500` | Max upload size |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | JWT token expiry |

### 5.3 Production Checklist

```
[ ] ENVIRONMENT=production
[ ] DEBUG=false
[ ] SECRET_KEY is unique and random (32+ chars)
[ ] POSTGRES_PASSWORD is strong
[ ] ADMIN_PASSWORD is strong
[ ] CORS_ORIGINS only lists your domain(s)
[ ] SSL certificates are valid
[ ] All default passwords changed
```

---

## 6. Database Setup

### 6.1 Initial Setup

```bash
# Run migrations
docker compose -f docker-compose.production.yml exec backend \
  alembic upgrade head
```

### 6.2 Create Admin User

The admin user is created automatically on first startup using:
- `ADMIN_USERNAME`
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`

### 6.3 Database Backup

```bash
# Create backup
docker compose -f docker-compose.production.yml exec postgres \
  pg_dump -U securemailscope securemailscope > backup_$(date +%Y%m%d).sql

# Restore backup
docker compose -f docker-compose.production.yml exec -T postgres \
  psql -U securemailscope securemailscope < backup_20260921.sql
```

---

## 7. Security Hardening

### 7.1 Firewall Configuration

```bash
# UFW example
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### 7.2 Docker Security

The production configuration includes:
- Non-root containers
- Read-only filesystems where possible
- Dropped capabilities
- Resource limits
- No exposed internal ports

### 7.3 Security Headers

The following headers are configured in NGINX:
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `X-XSS-Protection`
- `Referrer-Policy`
- `Permissions-Policy`

### 7.4 Rate Limiting

| Endpoint | Limit | Description |
|----------|-------|-------------|
| General API | 100 req/min | Standard endpoints |
| Login | 5 req/5min | Brute force protection |
| Upload | 10 req/min | File upload limit |

---

## 8. Monitoring & Logging

### 8.1 View Logs

```bash
# All services
docker compose -f docker-compose.production.yml logs -f

# Specific service
docker compose -f docker-compose.production.yml logs -f backend

# Last 100 lines
docker compose -f docker-compose.production.yml logs --tail 100 backend
```

### 8.2 Health Checks

```bash
# API health
curl -k https://localhost/api/v1/health

# Dependencies health
curl -k https://localhost/api/v1/health/dependencies
```

### 8.3 Container Status

```bash
# Check all containers
docker compose -f docker-compose.production.yml ps

# Check resource usage
docker stats
```

### 8.4 Log Rotation

Add to `/etc/docker/daemon.json`:

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "5"
  }
}
```

---

## 9. Backup & Recovery

### 9.1 What to Backup

| Component | Location | Frequency |
|-----------|----------|-----------|
| Database | PostgreSQL container | Daily |
| Evidence | `/app/data/evidence` volume | Daily |
| Reports | `/app/data/reports` volume | Daily |
| Configuration | `.env`, SSL certs | On change |

### 9.2 Automated Backup Script

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backups/securemailscope"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
docker compose -f docker-compose.production.yml exec -T postgres \
  pg_dump -U securemailscope securemailscope | gzip > $BACKUP_DIR/db_$DATE.sql.gz

# Backup evidence volume
docker run --rm \
  -v securemailscope_evidence_data:/data \
  -v $BACKUP_DIR:/backup \
  alpine tar czf /backup/evidence_$DATE.tar.gz -C /data .

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -type f -mtime +30 -delete

echo "Backup completed: $DATE"
```

### 9.3 Recovery Procedure

```bash
# Stop services
docker compose -f docker-compose.production.yml down

# Restore database
gunzip -c backup_20260921.sql.gz | \
  docker compose -f docker-compose.production.yml exec -T postgres \
  psql -U securemailscope securemailscope

# Restore evidence
docker run --rm \
  -v securemailscope_evidence_data:/data \
  -v /backups/securemailscope:/backup \
  alpine tar xzf /backup/evidence_20260921.tar.gz -C /data

# Start services
docker compose -f docker-compose.production.yml up -d
```

---

## 10. Troubleshooting

### 10.1 Common Issues

#### Container won't start

```bash
# Check logs
docker compose -f docker-compose.production.yml logs backend

# Check configuration
docker compose -f docker-compose.production.yml config

# Rebuild containers
docker compose -f docker-compose.production.yml up -d --build --force-recreate
```

#### Database connection errors

```bash
# Check PostgreSQL status
docker compose -f docker-compose.production.yml exec postgres pg_isready

# Test connection
docker compose -f docker-compose.production.yml exec backend \
  python -c "from app.core.database import engine; engine.connect(); print('OK')"
```

#### SSL/Certificate issues

```bash
# Test certificate
openssl s_client -connect localhost:443 -servername securemailscope.local

# Check certificate expiry
openssl x509 -in ssl/cert.pem -noout -dates
```

#### NGINX 502 Bad Gateway

```bash
# Check backend is running
docker compose -f docker-compose.production.yml ps backend

# Check backend logs
docker compose -f docker-compose.production.yml logs backend

# Verify network connectivity
docker compose -f docker-compose.production.yml exec frontend \
  wget -qO- http://backend:8000/api/v1/health
```

### 10.2 Performance Issues

```bash
# Check resource usage
docker stats

# Check disk space
df -h

# Check database connections
docker compose -f docker-compose.production.yml exec postgres \
  psql -U securemailscope -c "SELECT count(*) FROM pg_stat_activity;"
```

### 10.3 Reset Everything

```bash
# WARNING: This deletes all data!
docker compose -f docker-compose.production.yml down -v
docker system prune -a

# Start fresh
docker compose -f docker-compose.production.yml up -d --build
```

---

## Quick Reference

### Start/Stop Commands

```bash
# Start
docker compose -f docker-compose.production.yml up -d

# Stop
docker compose -f docker-compose.production.yml down

# Restart
docker compose -f docker-compose.production.yml restart

# Rebuild
docker compose -f docker-compose.production.yml up -d --build
```

### Useful Commands

```bash
# Enter backend shell
docker compose -f docker-compose.production.yml exec backend bash

# Run migrations
docker compose -f docker-compose.production.yml exec backend alembic upgrade head

# Database shell
docker compose -f docker-compose.production.yml exec postgres psql -U securemailscope

# Redis CLI
docker compose -f docker-compose.production.yml exec redis redis-cli
```

---

*For additional support, please refer to the project documentation or create an issue on GitHub.*
