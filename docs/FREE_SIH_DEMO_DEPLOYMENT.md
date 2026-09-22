# 🚀 SecureMailScope - Free SIH Demo Deployment Guide

**Version:** 1.0.0
**Target:** Public Demo for SIH 2026
**Cost:** $0/month (100% FREE)
**Deployment Time:** ~30 minutes
**PCAP Limit:** 20MB (synchronous execution)

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Step 1: Supabase Storage Setup](#step-1-supabase-storage-setup)
5. [Step 2: Deploy Backend to Render](#step-2-deploy-backend-to-render)
6. [Step 3: Deploy Frontend to Vercel](#step-3-deploy-frontend-to-vercel)
7. [Step 4: Configure CORS](#step-4-configure-cors)
8. [Step 5: Test the Deployment](#step-5-test-the-deployment)
9. [Troubleshooting](#troubleshooting)
10. [Limitations](#limitations)
11. [Upgrading to Production](#upgrading-to-production)

---

## Overview

This guide explains how to deploy SecureMailScope as a **publicly accessible web application** for your SIH 2026 demo using **free and low-cost** hosting services.

### What You'll Deploy

- **Frontend**: React SPA on Vercel (FREE, Hobby tier)
- **Backend**: FastAPI on Render (FREE tier)
- **Database**: PostgreSQL on Render (Starter tier, $7/month)
- **Storage**: Supabase S3-compatible storage (FREE tier)
- **Worker**: None (uses demo mode for synchronous analysis)

### Total Monthly Cost

**$0/month** (100% FREE)

### Public URL

After deployment, you'll have a normal clickable URL like:

```
https://securemailscope.vercel.app
```

That works from ANY computer, including SIH judges' machines.

---

## Architecture

### Demo Mode vs Production Mode

| Component | Production Mode | Demo Mode (This Guide) |
|-----------|----------------|------------------------|
| Frontend | Render Static Site | Vercel (FREE) |
| Backend API | Render Web Service (Paid) | Render Web Service (FREE) |
| Celery Worker | Render Background Worker (Paid) | None |
| Analysis Execution | Asynchronous (Celery) | Synchronous (HTTP request) |
| Redis | Render Redis (Paid) | Not required |
| PostgreSQL | Render PostgreSQL (Paid) | Render PostgreSQL ($7/month minimum) |
| Evidence Storage | S3-compatible | Supabase S3 (FREE) |
| **Total Cost** | **~$80/month** | **$0/month** |

### Demo Mode Architecture

```
Judge's Browser
    ↓
Vercel (Frontend)
    ↓
Render Free Tier (Backend + Analysis)
    ↓
PostgreSQL ($7/month)
    ↓
Supabase S3 (Evidence Storage - FREE)
```

**Key Difference**: Analysis runs **synchronously** in the HTTP request instead of being queued to a Celery worker.

---

## Prerequisites

### Required Accounts (All FREE to create)

1. **GitHub Account** (to host your code)
2. **Render Account** ([dashboard.render.com](https://dashboard.render.com))
3. **Vercel Account** ([vercel.com](https://vercel.com))
4. **Supabase Account** ([supabase.com](https://supabase.com))

### What You'll Need

- Your GitHub repository containing SecureMailScope
- ~30 minutes of time
- A web browser

### Skills Required

- Basic understanding of environment variables
- Ability to copy/paste configuration values
- NO coding or deployment expertise required

### PCAP Size Limit

**Demo deployment accepts PCAP files up to 20MB.**

**Why 20MB limit?**

The demo deployment executes the complete **Phase 2 → Phase 3 → Phase 4** analysis pipeline **synchronously** within a single HTTP request on Render's free tier web service.

- **Phase 2**: TShark packet extraction + protocol detection (~5-15 seconds for 20MB)
- **Phase 3**: TCP streams + TLS + certificates + findings (~10-30 seconds)
- **Phase 4**: Intelligence + correlations + recommendations (~5-10 seconds)
- **Total**: ~20-55 seconds for 20MB PCAP

Render's free tier has a **120-second HTTP request timeout**. Files larger than 20MB risk exceeding this timeout.

**For production deployments** using Celery workers, the limit is 500MB.

---

## Step 1: Supabase Storage Setup

Supabase provides FREE S3-compatible object storage for evidence files.

### 1.1 Create Supabase Project

1. Go to [supabase.com](https://supabase.com) and sign up (FREE)
2. Click "New Project"
3. Choose:
   - **Organization**: Create new or use existing
   - **Project Name**: `securemailscope-demo`
   - **Database Password**: Save this (you won't need it for storage)
   - **Region**: Choose closest to Singapore (e.g., `Southeast Asia`)
4. Click "Create Project" (takes ~2 minutes)

### 1.2 Create Storage Bucket

1. In your Supabase project, go to **Storage** (left sidebar)
2. Click **"New bucket"**
3. Configure:
   - **Name**: `securemailscope-evidence`
   - **Public bucket**: **UNCHECKED** (IMPORTANT: Keep private)
   - **Allowed MIME types**: Leave empty (allows all)
   - **File size limit**: `20971520` (20MB)
4. Click **"Create bucket"**

### 1.3 Generate S3 API Credentials

1. Go to **Settings** → **API** (left sidebar)
2. Scroll down to **"S3 Connection"** section
3. Click **"Generate new credentials"**
4. **SAVE THESE VALUES** (you'll need them later):
   ```
   Access Key ID: [Long string starting with...]
   Secret Access Key: [Long random string...]
   Endpoint: https://[project-id].supabase.co/storage/v1/s3
   Region: ap-southeast-1 (or your chosen region)
   ```

### 1.4 Verify Configuration

Your S3 settings should look like:

```
Endpoint: https://aqdzsopxuheuunpifjks.supabase.co/storage/v1/s3
Bucket: securemailscope-evidence
Region: ap-southeast-1
```

**✅ Supabase storage is ready!**

---

## Step 2: Deploy Backend to Render

### 2.1 Push Code to GitHub

If you haven't already:

```bash
cd /path/to/SecureMail
git add .
git commit -m "Add free demo deployment configuration"
git push origin master
```

### 2.2 Create Render Blueprint Deployment

1. Go to [dashboard.render.com](https://dashboard.render.com)
2. Click **"Blueprints"** in the top navigation
3. Click **"New Blueprint Instance"**
4. **Connect GitHub repository**:
   - If first time: Click "Connect GitHub" and authorize Render
   - Select your `SecureMail` repository
5. **Blueprint Settings**:
   - **Blueprint file**: Select `render.demo.yaml`
   - **Branch**: `master` (or your main branch)
6. Click **"Apply"**

Render will create:
- ✅ Backend API service (FREE tier)
- ✅ PostgreSQL database (Starter tier, $7/month)

**Deployment takes ~5-10 minutes.**

### 2.3 Monitor Deployment

1. Go to **"Services"** in Render dashboard
2. You should see:
   - `securemailscope-demo-api` (deploying...)
   - `securemailscope-demo-db` (available)

3. Click on `securemailscope-demo-api`
4. Watch the **"Logs"** tab for deployment progress
5. Wait for: `✅ Service deployed successfully`

### 2.4 Configure S3 Credentials

**CRITICAL**: Backend needs S3 credentials to store evidence.

1. In `securemailscope-demo-api` service, go to **"Environment"** tab
2. Find these variables (already created by blueprint):
   - `S3_ACCESS_KEY_ID`
   - `S3_SECRET_ACCESS_KEY`
3. Click **"Edit"** for each and paste your **Supabase** credentials from Step 1.3
4. Click **"Save Changes"**

**This triggers a redeploy (~2-3 minutes).**

### 2.5 Get Backend URL

Once deployed successfully:

1. In `securemailscope-demo-api` service page
2. Look for the public URL at the top:
   ```
   https://securemailscope-demo-api.onrender.com
   ```
3. **SAVE THIS URL** (you'll need it for Vercel)

### 2.6 Test Backend Health

Open in browser:

```
https://securemailscope-demo-api.onrender.com/api/v1/health
```

You should see:

```json
{
  "status": "healthy",
  "timestamp": "2026-09-22T...",
  ...
}
```

**✅ Backend is deployed and healthy!**

---

## Step 3: Deploy Frontend to Vercel

### 3.1 Import Repository to Vercel

1. Go to [vercel.com](https://vercel.com) and sign in
2. Click **"Add New..."** → **"Project"**
3. **Import Git Repository**:
   - If first time: Click "Import Git Repository" and connect GitHub
   - Find and select your `SecureMail` repository
4. Click **"Import"**

### 3.2 Configure Build Settings

In the "Configure Project" screen:

1. **Framework Preset**: Leave as `Vite` (auto-detected)
2. **Root Directory**: Change to `frontend` ✅
3. **Build Command**: `npm run build` (auto-filled)
4. **Output Directory**: `dist` (auto-filled)
5. **Install Command**: `npm ci` (auto-filled)

### 3.3 Add Environment Variable

**CRITICAL**: Frontend needs to know where the backend is.

1. In "Configure Project", scroll to **"Environment Variables"**
2. Click **"Add"**
3. Enter:
   - **Key**: `VITE_API_URL`
   - **Value**: `https://securemailscope-demo-api.onrender.com` (your backend URL from Step 2.5)
   - **Environment**: All (Production, Preview, Development)
4. Click **"Add"**

### 3.4 Deploy

1. Click **"Deploy"**
2. Wait ~2-3 minutes for build and deployment
3. You'll see:
   - ✅ Building...
   - ✅ Deploying...
   - ✅ **Success!**

### 3.5 Get Frontend URL

After successful deployment:

1. Vercel shows your public URL:
   ```
   https://secure-mail-xyz123.vercel.app
   ```
2. **SAVE THIS URL** (this is your SIH demo link!)

### 3.6 Optional: Custom Domain

You can add a custom domain in Vercel:

1. Go to **Settings** → **Domains**
2. Add your domain (e.g., `securemailscope.vercel.app`)
3. Follow Vercel's DNS configuration instructions

**✅ Frontend is deployed!**

---

## Step 4: Configure CORS

The backend needs to allow requests from your frontend URL.

### 4.1 Update Backend CORS Setting

1. Go back to Render dashboard
2. Open `securemailscope-demo-api` service
3. Go to **"Environment"** tab
4. Find `CORS_ORIGINS` variable
5. Click **"Edit"**
6. Change value to your **Vercel frontend URL**:
   ```
   https://secure-mail-xyz123.vercel.app
   ```
   (Use your ACTUAL Vercel URL from Step 3.5)
7. Click **"Save Changes"**

**This triggers a redeploy (~2 minutes).**

### 4.2 Verify CORS

Wait for redeploy to complete, then:

1. Open your Vercel frontend URL
2. Open browser DevTools (F12) → Console
3. You should see NO CORS errors

**✅ CORS is configured!**

---

## Step 5: Test the Deployment

### 5.1 Get Admin Credentials

1. Go to Render `securemailscope-demo-api` service
2. Click **"Environment"** tab
3. Find `ADMIN_PASSWORD` variable
4. Click the 👁️ (eye) icon to reveal the password
5. **SAVE THIS PASSWORD**

Default credentials:
- **Username**: `admin`
- **Password**: `[Value from ADMIN_PASSWORD]`

### 5.2 Test Login

1. Open your Vercel frontend URL in a browser
2. You should see the SecureMailScope login page
3. Enter:
   - Username: `admin`
   - Password: `[from Step 5.1]`
4. Click **"Login"**

**✅ You should see the dashboard!**

### 5.3 Test PCAP Upload

1. In the dashboard, click **"Upload Evidence"** or **"New Case"**
2. Create a test case:
   - **Case Name**: `SIH Demo Test`
   - **Description**: `Testing upload and analysis`
3. Upload a test PCAP file (<20MB):
   - Use `sample_pcaps/smtp_starttls_demo.pcap` from your repo
   - OR use your own test PCAP (max 20MB for demo)
4. Click **"Upload"**

### 5.4 Verify Analysis

After upload:

1. Analysis should start automatically
2. You'll see:
   - **Status**: RUNNING → COMPLETED
   - **Phase 2**: Packet analysis results
   - **Phase 3**: Security findings
3. Check for:
   - ✅ Protocol detection (SMTP/IMAP/POP3)
   - ✅ TLS analysis
   - ✅ Security findings
   - ✅ Risk assessment

**Analysis completes in demo mode (synchronous execution).**

### 5.5 Share the Public URL

Your SIH demo link is ready! Share with judges:

```
https://secure-mail-xyz123.vercel.app

Username: admin
Password: [from Step 5.1]
```

**✅ Deployment is complete and working!**

---

## Troubleshooting

### Frontend Can't Connect to Backend

**Symptom**: CORS errors in browser console

**Solution**:
1. Check `CORS_ORIGINS` in Render backend environment
2. Must exactly match your Vercel URL (including `https://`)
3. No trailing slash
4. Redeploy backend after changing

### Backend Shows "Unhealthy"

**Symptom**: Service shows red "Unhealthy" status

**Solution**:
1. Check backend logs in Render
2. Look for errors during startup
3. Common issues:
   - Missing S3 credentials → Add them in Environment
   - Database migration failed → Check `preDeployCommand` logs
   - Invalid environment variable → Check .env.production.example

### Analysis Fails

**Symptom**: Job status shows FAILED

**Solution**:
1. Check backend logs for error details
2. Common causes:
   - S3 storage not configured → Step 2.4
   - PCAP too large (>20MB) → Use smaller file
   - TShark timeout → Increase `TSHARK_TIMEOUT_SECONDS`

### Upload Fails

**Symptom**: "Upload failed" error

**Solution**:
1. Check file size (<20MB for demo)
2. Check S3 credentials in backend
3. Check Supabase bucket exists and is private
4. Look at backend logs for S3 errors

### "Cold Start" Delays

**Symptom**: First request after inactivity takes 30-60 seconds

**Explanation**:
- Render FREE tier spins down after 15 min inactivity
- This is NORMAL and expected for free tier
- **NOT a bug**

**Solution**:
- Warn judges about potential first-load delay
- Keep a browser tab open during demo to prevent spin-down
- Upgrade to paid tier for always-on service

---

## Limitations

### Free Demo Deployment Limitations

| Limitation | Impact | Mitigation |
|-----------|--------|------------|
| **15-min inactivity spin-down** | Cold start delays (30-60s) | Keep browser tab open during demo |
| **Synchronous analysis** | May timeout on large PCAPs | Limit uploads to 20MB |
| **No background worker** | Analysis runs in HTTP request | Use demo mode (already configured) |
| **No Redis** | No job queue resilience | Acceptable for demo purposes |
| **20MB PCAP limit** | Can't analyze large captures | Synchronous execution constraint |
| **ML disabled** | No machine learning features | Acceptable for Phase 2-4 demo |

### Differences from Production

| Feature | Production | Demo |
|---------|-----------|------|
| Celery Worker | ✅ Separate service | ❌ Demo mode |
| Redis | ✅ Required | ❌ Not needed |
| ML Analysis | ✅ Enabled | ❌ Disabled |
| Always-On | ✅ 24/7 | ❌ Spins down |
| PCAP Limit | 500MB | 20MB |
| Cost | ~$80/month | ~$7/month |

---

## Upgrading to Production

When you're ready to deploy for real production use:

### Switch to Production Configuration

1. Use `render.yaml` instead of `render.demo.yaml`
2. This adds:
   - Celery background worker (paid tier)
   - Redis for job queue (paid tier)
   - Always-on backend (paid tier)
   - ML enabled
   - 500MB PCAP limit

### Update Environment Variables

```bash
ANALYSIS_EXECUTION_MODE=celery  # Instead of "demo"
ML_ENABLED=true
MAX_PCAP_SIZE_MB=500
```

### Deploy

```bash
git checkout production
# Update render.yaml with production settings
git push
```

Render will automatically:
- Create Celery worker service
- Add Redis service
- Upgrade to paid tiers

**Production cost: ~$80/month**

---

## Summary

You've successfully deployed SecureMailScope as a publicly accessible web application!

### What You Deployed

✅ **Frontend**: https://[your-vercel-url].vercel.app
✅ **Backend**: https://securemailscope-demo-api.onrender.com
✅ **Database**: PostgreSQL on Render
✅ **Storage**: Supabase S3 (FREE)
✅ **Analysis**: Demo mode (synchronous)

### Total Cost

**~$7/month** (PostgreSQL only)

### Next Steps

1. Share your public URL with SIH judges
2. Test thoroughly before demo day
3. Monitor backend logs during demo
4. Keep browser tab open to prevent spin-down

### Support

For issues:
1. Check [Troubleshooting](#troubleshooting) section
2. Review Render backend logs
3. Check `docs/RENDER_DEPLOYMENT.md` for production deployment

**Good luck with your SIH 2026 demo! 🚀**
