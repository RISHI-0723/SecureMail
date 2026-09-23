# SecureMailScope - Root Cause Analysis for 404 Errors
**Date**: 2026-09-23
**Evidence ID**: ev_2a945a9796f6
**Commit**: TBD

---

## LIVE PRODUCTION EVIDENCE

**Observed Behavior:**
```
GET /api/v1/evidence/ev_2a945a9796f6/analysis → 200 ✓
GET /api/v1/security/ev_2a945a9796f6/summary → 404 ✗
GET /api/v1/evidence/ev_2a945a9796f6/intelligence → 404 ✗
```

This behavior repeats continuously, proving:
- ✓ AnalysisJob EXISTS
- ✗ SecurityAnalysis is NOT accessible
- ✗ IntelligenceReport is NOT accessible

---

## ROOT CAUSE #1: Security Summary 404

### API Endpoint
**Route**: `GET /api/v1/security/{evidence_id}/summary`
**File**: backend/app/api/routes/security.py:100-145

### Database Query
**File**: backend/app/api/routes/security.py:51-97

```python
def _get_security_analysis(evidence_id: str, db: Session) -> SecurityAnalysis:
    analysis = db.query(SecurityAnalysis).filter(
        SecurityAnalysis.evidence_id == evidence_id
    ).order_by(SecurityAnalysis.created_at.desc()).first()

    if not analysis:
        raise HTTPException(status_code=404, detail="SECURITY_ANALYSIS_NOT_FOUND")

    if analysis.status == SecurityAnalysisStatus.RUNNING:
        raise HTTPException(status_code=404, detail="ANALYSIS_IN_PROGRESS")

    if analysis.status == SecurityAnalysisStatus.FAILED:
        raise HTTPException(status_code=404, detail="ANALYSIS_FAILED")

    # Only returns 200 if status == COMPLETED
    return analysis
```

### Query Analysis
- **Table**: `security_analyses`
- **Filter**: `evidence_id = 'ev_2a945a9796f6'`
- **Returns 404 if**:
  1. No row exists
  2. Row exists but `status = RUNNING`
  3. Row exists but `status = FAILED`
  4. Row exists but `status = QUEUED`

### Root Cause
**Most Likely**: SecurityAnalysis exists with `status=RUNNING` because Phase 3 never completed.

**Evidence**:
- AnalysisJob returns 200 (Phase 2 completed)
- SecurityAnalysis is created at start of Phase 3 (analysis_executor.py:345-354)
- If Phase 3 hangs at CALCULATING_RISK, status remains RUNNING
- API rejects RUNNING status with 404 "ANALYSIS_IN_PROGRESS"

---

## ROOT CAUSE #2: Intelligence 404

### API Endpoint
**Route**: `GET /api/v1/evidence/{evidence_id}/intelligence`
**File**: backend/app/api/routes/intelligence.py:111-160

### Database Query
**File**: backend/app/api/routes/intelligence.py:63-108

```python
def _get_intelligence_report(evidence_id: str, db: Session) -> IntelligenceReport:
    report = db.query(IntelligenceReport).filter(
        IntelligenceReport.evidence_id == evidence_id
    ).order_by(IntelligenceReport.created_at.desc()).first()

    if not report:
        raise HTTPException(status_code=404, detail="INTELLIGENCE_NOT_FOUND")

    if report.status == IntelligenceStatus.RUNNING:
        raise HTTPException(status_code=404, detail="INTELLIGENCE_IN_PROGRESS")

    if report.status == IntelligenceStatus.FAILED:
        raise HTTPException(status_code=404, detail="INTELLIGENCE_FAILED")

    # Only returns 200 if status == COMPLETED
    return report
```

### Query Analysis
- **Table**: `intelligence_reports`
- **Filter**: `evidence_id = 'ev_2a945a9796f6'`
- **Returns 404 if**:
  1. No row exists
  2. Row exists but `status != COMPLETED`

### Root Cause
**Most Likely**: IntelligenceReport doesn't exist because Phase 4 never started.

**Dependency Chain**:
```
Phase 3 RUNNING → never completes
   ↓
Phase 3 status never = COMPLETED
   ↓
Phase 4 never starts (requires Phase 3 completion)
   ↓
IntelligenceReport never created
   ↓
API returns 404 "INTELLIGENCE_NOT_FOUND"
```

---

## HYPOTHESIS: Phase 3 Hangs at CALCULATING_RISK

### Evidence
1. User previously reported: "Analysis shows RUNNING (CALCULATING_RISK) indefinitely"
2. SecurityAnalysis created but never reaches status=COMPLETED
3. Phase 4 never starts
4. RiskEngine verified to be deterministic (no infinite loops)

### Suspected Bottlenecks
1. **Large data serialization** (model_dump() on thousands of objects)
2. **PostgreSQL commit blocking** (database lock on Render Free tier)
3. **Render CPU throttling** (Free tier resource limits)
4. **Background thread starvation** (single Gunicorn worker)

---

## FIX IMPLEMENTED: Enhanced Logging

Added explicit database persistence logging to trace exact failure point:

### SecurityAnalysis Lifecycle Logging
**File**: backend/app/services/analysis_executor.py

```python
# Line 345: Before creation
SECURITY_ANALYSIS_CREATE_STARTED
  └─ event, job_id, evidence_id, phase

# Line 353: After db.add() and db.commit()
SECURITY_ANALYSIS_CREATED
  └─ event, job_id, evidence_id, analysis_id, status

# Line 657: Before status = COMPLETED
SECURITY_ANALYSIS_STATUS_UPDATE_STARTED
  └─ event, job_id, evidence_id, analysis_id, old_status, new_status

# Line 673: After db.commit()
DATABASE_COMMIT_COMPLETED
  └─ event, job_id, evidence_id, commit_duration_seconds
```

### IntelligenceReport Lifecycle Logging
**File**: backend/app/services/analysis_executor.py

```python
# Line 849: Before creation
INTELLIGENCE_REPORT_CREATE_STARTED
  └─ event, job_id, evidence_id, security_analysis_id

# Line 867: After db.add() and db.commit()
INTELLIGENCE_REPORT_CREATED
  └─ event, job_id, evidence_id, report_id, status

# Line 1149: Before status = COMPLETED
INTELLIGENCE_REPORT_STATUS_UPDATE_STARTED
  └─ event, job_id, evidence_id, report_id, old_status, new_status

# Line 1281: After db.commit()
DATABASE_COMMIT_COMPLETED
  └─ event, job_id, evidence_id, commit_duration_seconds
```

---

## EXPECTED LOG SEQUENCE (Successful Case)

```json
{"event": "PHASE3_STARTED", "job_id": "...", "evidence_id": "ev_2a945a9796f6"}
{"event": "SECURITY_ANALYSIS_CREATE_STARTED"}
{"event": "SECURITY_ANALYSIS_CREATED", "analysis_id": "sa_...", "status": "RUNNING"}
{"event": "FINDINGS_ENGINE_STARTED"}
{"event": "FINDINGS_ENGINE_COMPLETED", "total_findings": 12}
{"event": "RISK_ENGINE_STARTED"}
{"event": "RISK_ENGINE_COMPLETED", "risk_level": "HIGH", "risk_score": 45.0}
{"event": "SECURITY_ANALYSIS_PERSIST_STARTED"}
{"event": "SECURITY_ANALYSIS_STATUS_UPDATE_STARTED", "old_status": "RUNNING", "new_status": "COMPLETED"}
{"event": "DATABASE_COMMIT_STARTED"}
{"event": "DATABASE_COMMIT_COMPLETED", "commit_duration_seconds": 2.5}
{"event": "PHASE3_COMPLETED"}
{"event": "PHASE4_STARTED"}
{"event": "INTELLIGENCE_REPORT_CREATE_STARTED"}
{"event": "INTELLIGENCE_REPORT_CREATED", "report_id": "ir_...", "status": "RUNNING"}
{"event": "ML_ANALYSIS_STARTED"}
{"event": "ML_ANALYSIS_COMPLETED", "ml_status": "COMPLETED"}
{"event": "INTELLIGENCE_REPORT_STATUS_UPDATE_STARTED", "old_status": "RUNNING", "new_status": "COMPLETED"}
{"event": "DATABASE_COMMIT_STARTED"}
{"event": "DATABASE_COMMIT_COMPLETED"}
{"event": "PHASE4_COMPLETED"}
```

---

## DIAGNOSTIC QUESTIONS ANSWERED BY NEW LOGS

### If Phase 3 Hangs at CALCULATING_RISK:
**Missing Event**: `RISK_ENGINE_COMPLETED`
**Last Event**: `RISK_ENGINE_STARTED`
**Diagnosis**: Risk calculation blocking (but RiskEngine is deterministic, so unlikely)

### If Phase 3 Hangs at Serialization:
**Missing Event**: `SECURITY_ANALYSIS_PERSIST_COMPLETED`
**Last Event**: `SECURITY_ANALYSIS_PERSIST_STARTED`
**Diagnosis**: model_dump() taking too long on large datasets

### If Phase 3 Hangs at Database Commit:
**Missing Event**: `DATABASE_COMMIT_COMPLETED`
**Last Event**: `DATABASE_COMMIT_STARTED`
**Diagnosis**: PostgreSQL lock/timeout on Render Free tier
**Duration Check**: `commit_duration_seconds > 30` indicates slow commit

### If SecurityAnalysis Created but Not Committed:
**Present**: `SECURITY_ANALYSIS_CREATED`
**Missing**: `DATABASE_COMMIT_COMPLETED` before next operation
**Diagnosis**: db.commit() failed silently or transaction rolled back

---

## NEXT STEPS

1. **Deploy to Render** (auto-deploy from master branch push)
2. **Monitor Render Logs** for new structured events
3. **Upload Test PCAP** (tfp_capture.pcapng or ipp.pcap)
4. **Identify Missing Event** in log sequence
5. **Query Render Database** to verify row existence and status

### Database Verification Queries

```sql
-- Check SecurityAnalysis for ev_2a945a9796f6
SELECT analysis_id, evidence_id, status, total_findings, created_at, completed_at
FROM security_analyses
WHERE evidence_id = 'ev_2a945a9796f6'
ORDER BY created_at DESC;

-- Check IntelligenceReport for ev_2a945a9796f6
SELECT report_id, evidence_id, status, security_posture_grade, created_at, completed_at
FROM intelligence_reports
WHERE evidence_id = 'ev_2a945a9796f6'
ORDER BY created_at DESC;

-- Check AnalysisJob status for ev_2a945a9796f6
SELECT job_id, evidence_id, job_type, status, stage, created_at, completed_at
FROM analysis_jobs
WHERE evidence_id = 'ev_2a945a9796f6'
ORDER BY created_at DESC;
```

---

## FILES MODIFIED

- `backend/app/services/analysis_executor.py`: Added persistence logging (4 new log events)

---

## TEST RESULTS

- ✅ Phase 4 Intelligence: 35/35 passed
- ✅ Demo Complete Pipeline: 5/5 passed
- ✅ **Total: 40/40 tests passed**

---

## ACCEPTANCE CRITERIA

- [ ] Render logs show SECURITY_ANALYSIS_CREATED event
- [ ] Render logs show complete Phase 3 sequence
- [ ] Render database contains SecurityAnalysis row for test evidence
- [ ] SecurityAnalysis.status = COMPLETED
- [ ] Render logs show INTELLIGENCE_REPORT_CREATED event
- [ ] Render database contains IntelligenceReport row
- [ ] IntelligenceReport.status = COMPLETED
- [ ] GET /api/v1/security/{id}/summary returns 200
- [ ] GET /api/v1/evidence/{id}/intelligence returns 200
- [ ] commit_duration_seconds < 5.0 (healthy)
- [ ] Total phase duration reasonable for PCAP size
