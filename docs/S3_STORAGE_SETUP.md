# S3 Storage Configuration for Render Deployment

**Version:** 0.5.0
**Required for:** Production Render deployment
**Status:** MANDATORY (Render persistent disks cannot be shared between services)

---

## Why S3 Storage is Required

Render's persistent disks are **service-specific** and **cannot be shared** between multiple services. Since SecureMailScope has separate backend and worker services that both need access to uploaded PCAP files:

- Backend uploads PCAP → needs to store evidence
- Worker processes PCAP → needs to retrieve evidence
- **Problem:** Separate services = separate disks = worker cannot access backend uploads
- **Solution:** S3-compatible object storage accessible by both services

---

## Supported S3 Providers

SecureMailScope supports any S3-compatible object storage:

1. **AWS S3** - Full AWS S3 service
2. **Cloudflare R2** - S3-compatible, 10GB free tier, no egress fees
3. **Backblaze B2** - S3-compatible, affordable pricing
4. **DigitalOcean Spaces** - S3-compatible
5. **Wasabi** - S3-compatible
6. **MinIO** - Self-hosted S3-compatible

**Recommended for SIH Demo:** Cloudflare R2 (free tier, fast, reliable)

---

## Cloudflare R2 Setup (Recommended)

### Step 1: Create R2 Bucket

1. Log into Cloudflare Dashboard
2. Navigate to **R2 Object Storage**
3. Click **Create bucket**
4. Bucket name: `securemailscope-evidence` (or similar)
5. Location: **Automatic**
6. Click **Create bucket**

### Step 2: Generate API Token

1. In R2 dashboard, click **Manage R2 API Tokens**
2. Click **Create API token**
3. Token name: `SecureMailScope Production`
4. Permissions: **Object Read & Write**
5. Specify bucket: Select `securemailscope-evidence`
6. Click **Create API Token**
7. **Copy and save:**
   - Access Key ID
   - Secret Access Key
   - Endpoint URL (format: `https://<account-id>.r2.cloudflarestorage.com`)

### Step 3: Configure Render Environment Variables

In Render Dashboard for `securemailscope-api` service:

```
STORAGE_BACKEND=s3
S3_ENDPOINT_URL=https://<your-account-id>.r2.cloudflarestorage.com
S3_ACCESS_KEY_ID=<your-access-key>
S3_SECRET_ACCESS_KEY=<your-secret-key>
S3_BUCKET_NAME=securemailscope-evidence
S3_REGION=auto
```

**Worker will automatically sync these values from backend (configured in render.yaml)**

---

## AWS S3 Setup (Alternative)

### Step 1: Create S3 Bucket

```bash
aws s3 mb s3://securemailscope-evidence --region us-east-1
```

### Step 2: Create IAM User

1. Create IAM user: `securemailscope-app`
2. Attach inline policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::securemailscope-evidence",
        "arn:aws:s3:::securemailscope-evidence/*"
      ]
    }
  ]
}
```

3. Create access key
4. Copy Access Key ID and Secret Access Key

### Step 3: Configure Render

```
STORAGE_BACKEND=s3
S3_ENDPOINT_URL=
S3_ACCESS_KEY_ID=<aws-access-key-id>
S3_SECRET_ACCESS_KEY=<aws-secret-access-key>
S3_BUCKET_NAME=securemailscope-evidence
S3_REGION=us-east-1
```

Leave `S3_ENDPOINT_URL` empty for AWS S3 (uses default endpoints).

---

## How It Works

### Upload Flow

1. User uploads PCAP via frontend
2. Backend receives upload
3. Backend stores to S3 bucket: `s3://bucket/evidence/<uuid>.pcap`
4. Backend saves metadata to PostgreSQL:
   - `stored_filename`: `evidence/<uuid>.pcap`
   - `storage_location`: `s3://bucket/evidence/<uuid>.pcap`
   - `sha256`: evidence hash

### Analysis Flow

1. Worker receives analysis job from Celery/Redis
2. Worker queries PostgreSQL for evidence metadata
3. Worker retrieves `stored_filename` from database
4. Worker calls `evidence_storage.get_path(stored_filename)`
5. S3 storage downloads file to temporary location
6. Worker passes temp file path to TShark
7. TShark analyzes PCAP
8. Worker cleans up temporary file

### Security

- **Credentials:** Stored as Render secrets, never in source control
- **Access:** Private bucket, application-only access via IAM/API tokens
- **Encryption:** S3 server-side encryption (SSE-S3 or SSE-KMS)
- **No public access:** Bucket is private, frontend never gets credentials
- **Authorization:** Backend enforces case/evidence ownership before serving data

---

## Testing S3 Configuration

### Local Testing with S3

Update `docker-compose.yml` environment:

```yaml
backend:
  environment:
    STORAGE_BACKEND: s3
    S3_ENDPOINT_URL: https://<account-id>.r2.cloudflarestorage.com
    S3_ACCESS_KEY_ID: <your-key>
    S3_SECRET_ACCESS_KEY: <your-secret>
    S3_BUCKET_NAME: securemailscope-evidence
    S3_REGION: auto
```

Test upload:
```bash
docker compose up -d
# Upload PCAP via dashboard
# Check S3 bucket for evidence/uuid.pcap file
```

### Verify Worker Access

Upload evidence and check worker logs:
```bash
docker compose logs -f worker
```

Expected output:
```
[INFO] Downloaded S3 object to temp file: evidence/abc123.pcap -> /tmp/tmpXYZ.pcap
[INFO] Starting packet analysis...
[INFO] TShark completed successfully
[INFO] Cleaned up temporary evidence file: /tmp/tmpXYZ.pcap
```

---

## Cost Estimates

### Cloudflare R2

- **Free Tier:** 10GB storage, 10M Class A operations/month
- **Paid (if exceeded):** $0.015/GB/month storage, no egress fees
- **Estimate for 100 PCAPs (13GB total):** ~$0.05/month

### AWS S3

- **Storage:** $0.023/GB/month (us-east-1)
- **GET requests:** $0.0004 per 1000 requests
- **PUT requests:** $0.005 per 1000 requests
- **Data transfer OUT:** $0.09/GB
- **Estimate for 100 PCAPs (13GB total):** ~$0.30/month + transfer costs

### Backblaze B2

- **Storage:** $0.005/GB/month
- **First 10GB free**
- **Downloads:** Free up to 3x storage
- **Estimate for 100 PCAPs (13GB total):** ~$0.015/month

**Recommendation:** Cloudflare R2 for best balance of performance and cost.

---

## Troubleshooting

### Error: "boto3 is required for S3 storage"

**Cause:** boto3 not installed
**Fix:** Ensure `requirements.txt` includes `boto3==1.35.80`

### Error: "S3_BUCKET_NAME must be configured"

**Cause:** Missing S3 configuration
**Fix:** Set all required S3 environment variables in Render

### Error: "Failed to initialize S3 storage"

**Causes:**
1. Invalid credentials
2. Wrong endpoint URL
3. Bucket doesn't exist
4. Network/firewall issues

**Fix:**
- Verify credentials are correct
- Check endpoint URL format
- Ensure bucket exists and is in correct region
- Test connectivity with AWS CLI: `aws s3 ls s3://bucket-name --endpoint-url=...`

### Error: "Failed to download S3 object"

**Causes:**
1. Object deleted
2. Permissions issue
3. Network timeout

**Fix:**
- Check object exists in bucket
- Verify IAM/API token has GetObject permission
- Check worker timeout settings

### Worker Cannot Access Evidence

**Cause:** Worker using different S3 credentials than backend
**Fix:** Verify `render.yaml` configures worker to sync S3 vars from backend:

```yaml
- key: S3_ACCESS_KEY_ID
  fromService:
    type: web
    name: securemailscope-api
    envVarKey: S3_ACCESS_KEY_ID
```

---

## Migration from Local to S3

If you deployed with local storage (incorrect configuration), migrate to S3:

1. Set up S3 bucket
2. Update Render environment variables
3. Redeploy services
4. **Old evidence will be inaccessible** (stored on old persistent disk)
5. Upload new evidence - will go to S3

**Note:** There is no automatic migration. Old evidence remains on service-specific disk.

---

## Security Best Practices

1. **Never commit credentials** - Use Render secrets
2. **Use minimal IAM permissions** - Read/Write only to specific bucket
3. **Enable bucket versioning** - Protects against accidental deletion
4. **Enable server-side encryption** - SSE-S3 or SSE-KMS
5. **Monitor access logs** - Enable S3 access logging
6. **Rotate credentials** - Periodically regenerate API tokens/keys
7. **Use private buckets** - Never enable public access

---

**Documentation Updated:** 2026-09-21
**Status:** Production-ready for Render deployment
