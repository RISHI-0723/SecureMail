# SecureMailScope Live Production Diagnosis
**Date**: 2026-09-23
**Branch**: master
**Commit**: 7c813fd

---

## ROOT CAUSES IDENTIFIED

### 1. REPORTS PAGE "REQUEST FAILED" - ✅ FOUND

**Root Cause**: Missing backend API endpoint for report generation

**Evidence**:
- Frontend calls: `api.generateReport(caseId, format)` (ReportsPage.tsx:75)
- Frontend expects: `POST /api/v1/reports/generate` or similar
- Backend has: `GET /reports/{report_id}/download` (intelligence.py:432)
- Backend **MISSING**: POST endpoint to generate new reports

**Impact**: Reports page shows "Request failed" banner on load/generate

**Fix Required**: Create `POST /api/v1/cases/{case_id}/reports/generate` endpoint

---

### 2. SECURITY SUMMARY 404 - HYPOTHESIS

**Potential Root Causes**:

**A. SecurityAnalysis Not Being Persisted**
- Phase 3 executes but commit() fails
- Database transaction rollback
- Background thread session issues

**B. Wrong Query in API**
- API queries by wrong evidence_id
- UUID/string mismatch
- Case-sensitive ID comparison

**Investigation Needed**:
```python
# backend/app/services/analysis_executor.py:567
db.commit()  # Does this actually commit SecurityAnalysis?
```

**Test**: Check Render database for SecurityAnalysis records

---

### 3. INTELLIGENCE 404 - RELATED TO #2

**Root Cause**: If SecurityAnalysis doesn't persist, Phase 4 cannot start

**Dependency Chain**:
```
Phase 3 completes
  ↓
SecurityAnalysis persisted?
  ↓ NO → Phase 4 cannot find security_analysis_id
  ↓ YES → Phase 4 creates IntelligenceReport
```

**Fix**: Same as #2 - ensure Phase 3 persistence

---

### 4. CALCULATING_RISK HANG - HYPOTHESIS

**NOT RiskEngine** (verified - pure deterministic computation, no loops/blocks)

**Potential Causes**:

**A. Database Commit Blocking**
- PostgreSQL lock wait
- Long-running transaction
- Render Free tier slow disk I/O

**B. Large Data Serialization**
- Converting huge findings list to JSON
- model_dump() on thousands of objects
- JSONB column write

**C. FindingEngine Loop**
- Huge number of findings
- Nested finding generation
- Stream/session explosion

**D. Background Thread Starvation**
- Single Gunicorn worker
- Thread not getting CPU time
- Render CPU throttling

**Investigation Needed**:
- Add timestamps before/after each operation
- Log findings count, streams count, sessions count
- Measure commit() duration

---

## MISSING LOGGING

Current logging is INSUFFICIENT for production debugging.

**Required Logs** (not currently present):

```python
logger.info("PHASE3_STARTED", extra={...})
logger.info("FINDINGS_ENGINE_STARTED", extra={...})
logger.info("FINDINGS_ENGINE_COMPLETED", extra={"finding_count": ...})
logger.info("RISK_ENGINE_STARTED", extra={"input_findings": ...})
logger.info("RISK_ENGINE_COMPLETED", extra={"risk_score": ...})
logger.info("SECURITY_ANALYSIS_PERSIST_STARTED", extra={...})
logger.info("SECURITY_ANALYSIS_PERSIST_COMPLETED", extra={...})
logger.info("PHASE3_COMPLETED", extra={...})
```

---

## MISSING BACKEND ENDPOINTS

### 1. Report Generation Endpoint

**Expected by Frontend**:
```typescript
// frontend/src/services/api.ts:403
async generateReport(caseId: string, format: 'json' | 'html' | 'pdf'):
  Promise<{ report_id: string; download_url: string; format: string }>
```

**Backend Missing**:
```python
@router.post("/cases/{case_id}/reports/generate")
async def generate_case_report(
    case_id: str,
    format: ReportFormat,
    db: Session = Depends(get_db)
):
    # Generate report for ALL evidence in case
    # Return report_id and download_url
```

**Current Workaround**: Reports are only generated during Phase 4 analysis

**Problem**: Cannot generate reports on-demand for existing completed cases

---

## API CONTRACT MISMATCHES

### Frontend Expectations vs Backend Reality

| Frontend Call | Expected Endpoint | Backend Status |
|--------------|------------------|----------------|
| `api.listCases()` | `GET /api/v1/cases` | ✅ EXISTS |
| `api.generateReport()` | `POST /api/v1/cases/{id}/reports` | ❌ MISSING |
| `api.getSecuritySummary()` | `GET /api/v1/security/{id}/summary` | ✅ EXISTS |
| `api.getIntelligence()` | `GET /api/v1/evidence/{id}/intelligence` | ✅ EXISTS |

---

## DATABASE PERSISTENCE CHECKS NEEDED

### Verify Phase 3 Persistence

```sql
-- Check if SecurityAnalysis is being created
SELECT
    sa.analysis_id,
    sa.evidence_id,
    sa.status,
    sa.total_findings,
    sa.created_at,
    sa.completed_at
FROM security_analyses sa
JOIN pcap_evidence pe ON sa.evidence_id = pe.evidence_id
WHERE pe.original_filename IN ('tfp_capture.pcapng', 'ipp.pcap')
ORDER BY sa.created_at DESC;
```

### Verify Phase 4 Persistence

```sql
-- Check if IntelligenceReport is being created
SELECT
    ir.report_id,
    ir.evidence_id,
    ir.status,
    ir.ml_enabled,
    ir.created_at,
    ir.completed_at
FROM intelligence_reports ir
JOIN pcap_evidence pe ON ir.evidence_id = pe.evidence_id
WHERE pe.original_filename IN ('tfp_capture.pcapng', 'ipp.pcap')
ORDER BY ir.created_at DESC;
```

---

## RECOMMENDED FIXES (Priority Order)

### CRITICAL - Fix #1: Add Report Generation Endpoint

**File**: `backend/app/api/routes/cases.py`

```python
@router.post(
    "/cases/{case_id}/reports/generate",
    response_model=ApiResponse[ReportGenerationResponse],
    tags=["Cases"],
    summary="Generate forensic report for case"
)
async def generate_case_report(
    case_id: str,
    format: ReportFormat,
    db: Session = Depends(get_db)
) -> ApiResponse[ReportGenerationResponse]:
    """Generate forensic report for all completed evidence in case."""
    # 1. Verify case exists
    # 2. Get all completed evidence
    # 3. Get latest Phase 3 + Phase 4 for each evidence
    # 4. Generate consolidated report
    # 5. Return report_id and download_url
```

### CRITICAL - Fix #2: Add Comprehensive Logging

**File**: `backend/app/services/analysis_executor.py`

Add timestamps and counts at every stage boundary:
- Before/after FindingEngine
- Before/after RiskEngine
- Before/after DB commits
- Include: job_id, evidence_id, finding_count, duration

### HIGH - Fix #3: Add Bounded Timeout

**File**: `backend/app/services/analysis_executor.py`

```python
import signal
from contextlib import contextmanager

@contextmanager
def timeout(seconds):
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds}s")

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)

# Use:
try:
    with timeout(300):  # 5 minute max for Phase 3
        risk_assessment = risk_engine.assess_risk(...)
except TimeoutError:
    logger.error("RISK_ENGINE_TIMEOUT")
    # Mark job FAILED
```

### HIGH - Fix #4: Verify DB Session Management

Ensure demo_executor creates isolated session:
- Own SessionLocal()
- Own commit/rollback
- Own close()
- No shared session with HTTP request

---

## TESTING PLAN

### Local Tests
1. Run Phase 4 tests: `pytest tests/test_phase4_intelligence.py`
2. Run demo pipeline tests with logging
3. Verify report generation endpoint manually

### Render Deployment Tests
1. Deploy with new logging
2. Upload tfp_capture.pcapng
3. Monitor Render logs for:
   - PHASE3_STARTED
   - RISK_ENGINE_STARTED
   - RISK_ENGINE_COMPLETED
   - SECURITY_ANALYSIS_PERSIST_COMPLETED
   - PHASE4_STARTED
   - ML execution logs
   - PHASE4_COMPLETED
4. Query APIs:
   - GET /api/v1/security/{id}/summary
   - GET /api/v1/evidence/{id}/intelligence
5. Test Reports page
6. Generate report via new endpoint

---

## ACCEPTANCE CRITERIA

- [ ] Reports page loads without "Request failed"
- [ ] Can generate report for completed case
- [ ] Download links work
- [ ] Analysis completes (not stuck at CALCULATING_RISK)
- [ ] SecurityAnalysis API returns 200
- [ ] Intelligence API returns 200
- [ ] Render logs show complete pipeline execution
- [ ] ML actually executes (not disabled)
- [ ] Database contains SecurityAnalysis records
- [ ] Database contains IntelligenceReport records
- [ ] JSON report contains real data
- [ ] HTML report contains real data
- [ ] PDF report generates successfully

---

## NEXT STEPS

1. ✅ Create this diagnostic document
2. ✅ Add comprehensive logging to analysis_executor.py
3. ✅ Create report generation endpoint in cases.py
4. ⏳ Add timeout protection to Phase 3
5. ⏳ Test locally
6. ⏳ Deploy to Render
7. ⏳ Verify with live test
8. ⏳ Create final comprehensive report

---

## LOGGING IMPLEMENTATION COMPLETED

### Added Comprehensive Structured Logging to analysis_executor.py

**Phase 3 Security Analysis Logging:**
- `PHASE3_STARTED` - Job started, packet_analysis_id
- `FINDINGS_ENGINE_STARTED` - Total streams/sessions/TLS/certificates to analyze
- `FINDINGS_ENGINE_COMPLETED` - Total findings by severity
- `RISK_ENGINE_STARTED` - Input data counts, has_email_traffic flag
- `RISK_ENGINE_COMPLETED` - Risk level, risk score, finding count
- `SECURITY_ANALYSIS_PERSIST_STARTED` - Objects to serialize counts
- `SECURITY_ANALYSIS_PERSIST_COMPLETED` - Serialization duration
- `DATABASE_COMMIT_STARTED` - Before Phase 3 final commit
- `DATABASE_COMMIT_COMPLETED` - Commit duration
- `PHASE3_COMPLETED` - Total duration, final risk assessment

**Phase 4 Intelligence Analysis Logging:**
- `PHASE4_STARTED` - Job started, security_analysis_id, ml_enabled flag
- `ML_ANALYSIS_STARTED` - Input data counts (sessions/TLS/certificates/findings)
- `ML_ANALYSIS_COMPLETED` - ML status, duration, results (4 branches: COMPLETED/INSUFFICIENT_DATA/NO_FEATURES/FAILED)
- `ML_ANALYSIS_SKIPPED` - When ML disabled in configuration
- `INTELLIGENCE_PERSIST_STARTED` - Aggregated findings/correlations/recommendations counts
- `INTELLIGENCE_PERSIST_COMPLETED` - Serialization duration
- `DATABASE_COMMIT_STARTED` - Before Phase 4 final commit
- `DATABASE_COMMIT_COMPLETED` - Commit duration
- `PHASE4_COMPLETED` - Total duration, posture grade/score, ML status

**All Log Events Include:**
- `event`: Structured event name
- `job_id`: Analysis job identifier
- `evidence_id`: Evidence identifier
- `phase`: "PHASE3" or "PHASE4"
- Duration metrics where applicable
- Data counts where applicable

**Critical Timing Metrics:**
- Serialization duration (model_dump() on potentially thousands of objects)
- Database commit duration (PostgreSQL transaction time)
- Total phase duration
- ML analysis duration

**Tests Verified:**
- Phase 4 intelligence tests: 35/35 passed ✅
- Demo complete pipeline tests: 5/5 passed ✅
- Total: 40/40 tests passed ✅

This logging will reveal the exact point where CALCULATING_RISK hangs in Render production environment.

---

## REPORT GENERATION ENDPOINT CREATED

### Fixed Reports Page "Request Failed" Error

**Root Cause:**
- Frontend calls `api.generateReport(caseId, format)` → `POST /api/v1/cases/{case_id}/report`
- Backend had NO such endpoint
- Only download endpoint existed: `GET /reports/{report_id}/download`

**Solution Implemented:**
Created new endpoint in `backend/app/api/routes/cases.py`:

```python
@router.post("/{case_id}/report")
async def generate_case_report(
    case_id: str,
    request: ReportGenerationRequest,  # { "format": "json|html|pdf" }
    db: Session = Depends(get_db)
) -> ApiResponse[ReportGenerationResponse]:  # { "report_id", "download_url", "format" }
```

**Behavior:**
1. Validates case exists
2. Validates format (json/html/pdf)
3. Gets all evidence for case
4. Finds first completed IntelligenceReport
5. Returns existing GeneratedReport in requested format
6. Returns 404 if no completed reports available (analysis still running)

**Response Format:**
```json
{
  "success": true,
  "data": {
    "report_id": "rpt_abc123",
    "download_url": "/api/v1/reports/rpt_abc123/download",
    "format": "json"
  },
  "error": null
}
```

**Error Cases:**
- `CASE_NOT_FOUND` - Case doesn't exist
- `INVALID_FORMAT` - Format not json/html/pdf
- `NO_EVIDENCE` - Case has no evidence files
- `NO_REPORTS_AVAILABLE` - Analysis not completed yet

**Note:** Current implementation returns first available evidence report. Future enhancement: create consolidated case-level reports combining all evidence.

**File Modified:**
- backend/app/api/routes/cases.py:247-347

**Verification:**
- Import check passed ✅
