# SecureMailScope Threat Model

**Version:** 0.5.0
**Last Updated:** 2026-09-21
**Classification:** Internal/Development

## 1. System Overview

SecureMailScope is a network forensic platform that analyzes PCAP/PCAPNG files containing email protocol communications (SMTP, IMAP, POP3) to assess cryptographic security posture.

### 1.1 Architecture Components

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Browser   │────▶│   NGINX     │────▶│   FastAPI   │
│   (User)    │◀────│   (TLS)     │◀────│   Backend   │
└─────────────┘     └─────────────┘     └─────────────┘
                                               │
                    ┌─────────────┐            │
                    │   Redis     │◀───────────┤
                    │   (Cache)   │            │
                    └─────────────┘            │
                                               │
                    ┌─────────────┐     ┌──────▼──────┐
                    │ PostgreSQL  │◀────│   Celery    │
                    │   (Data)    │     │   Worker    │
                    └─────────────┘     └─────────────┘
```

### 1.2 Trust Boundaries

1. **External Boundary**: Internet → NGINX
2. **DMZ Boundary**: NGINX → Backend API
3. **Internal Boundary**: Backend → Database/Redis
4. **Worker Boundary**: Celery → TShark Processing

## 2. Assets

### 2.1 Critical Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| PCAP Evidence | Uploaded network captures | HIGH - May contain sensitive communications |
| User Credentials | Passwords, JWT tokens | HIGH - Authentication material |
| Analysis Results | Security findings | MEDIUM - Forensic intelligence |
| Database | All persistent data | HIGH - Contains all above |
| SSL Certificates | TLS private keys | HIGH - Server identity |
| JWT Secret Key | Token signing key | CRITICAL - Compromises all auth |

### 2.2 Data Classification

- **PUBLIC**: API documentation, health endpoints
- **INTERNAL**: Analysis reports, statistics
- **CONFIDENTIAL**: PCAP files, user data
- **RESTRICTED**: Credentials, secrets, private keys

## 3. Threat Actors

### 3.1 External Threats

| Actor | Motivation | Capability |
|-------|------------|------------|
| Script Kiddies | Curiosity, vandalism | Low - Automated tools |
| Hacktivists | Ideological | Medium - Targeted attacks |
| Cybercriminals | Financial gain | Medium-High - Advanced tools |
| APT Groups | Intelligence | High - Nation-state resources |

### 3.2 Internal Threats

| Actor | Motivation | Capability |
|-------|------------|------------|
| Malicious Insider | Various | High - Legitimate access |
| Compromised Account | N/A | Varies by account role |
| Negligent User | Unintentional | Low - Accidental exposure |

## 4. Threat Analysis (STRIDE)

### 4.1 Spoofing

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| T-S-01 | Session hijacking | JWT tokens with short expiry | ✅ Implemented |
| T-S-02 | Credential stuffing | Rate limiting on login | ✅ Implemented |
| T-S-03 | Token forgery | HMAC signature verification | ✅ Implemented |
| T-S-04 | IP spoofing | X-Forwarded-For validation | ✅ Implemented |

### 4.2 Tampering

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| T-T-01 | Evidence modification | SHA-256 hashing | ✅ Implemented |
| T-T-02 | Request tampering | HTTPS, input validation | ✅ Implemented |
| T-T-03 | Database tampering | Parameterized queries | ✅ Implemented |
| T-T-04 | Log tampering | Append-only audit logs | ✅ Implemented |

### 4.3 Repudiation

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| T-R-01 | Denial of actions | Audit logging | ✅ Implemented |
| T-R-02 | False attribution | Request ID tracking | ✅ Implemented |
| T-R-03 | Timestamp manipulation | Server-side timestamps | ✅ Implemented |

### 4.4 Information Disclosure

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| T-I-01 | PCAP data exposure | RBAC, encryption at rest | ⚠️ Partial |
| T-I-02 | Error message leakage | Generic error responses | ✅ Implemented |
| T-I-03 | Directory traversal | Path sanitization | ✅ Implemented |
| T-I-04 | SQL injection | ORM with parameterization | ✅ Implemented |
| T-I-05 | XSS | CSP headers, React escaping | ✅ Implemented |

### 4.5 Denial of Service

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| T-D-01 | API flooding | Rate limiting | ✅ Implemented |
| T-D-02 | Large file upload | Size limits (500MB) | ✅ Implemented |
| T-D-03 | Resource exhaustion | Worker limits, timeouts | ✅ Implemented |
| T-D-04 | Regex DoS | Timeout on TShark | ✅ Implemented |

### 4.6 Elevation of Privilege

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| T-E-01 | Role escalation | RBAC enforcement | ✅ Implemented |
| T-E-02 | Container escape | Non-root, capabilities | ✅ Implemented |
| T-E-03 | Command injection | Input sanitization | ✅ Implemented |
| T-E-04 | Path traversal | Sandboxed storage | ✅ Implemented |

## 5. Attack Vectors

### 5.1 Web Application Attacks

```
Attack: SQL Injection
Path: User Input → API → Database
Risk: HIGH
Mitigation: SQLAlchemy ORM, parameterized queries
Status: MITIGATED
```

```
Attack: Cross-Site Scripting (XSS)
Path: Stored data → API Response → Browser
Risk: MEDIUM
Mitigation: CSP headers, React auto-escaping
Status: MITIGATED
```

```
Attack: CSRF
Path: Malicious site → User browser → API
Risk: MEDIUM
Mitigation: JWT in Authorization header (not cookies)
Status: MITIGATED
```

### 5.2 Authentication Attacks

```
Attack: Brute Force Login
Path: Attacker → Login Endpoint
Risk: HIGH
Mitigation: Rate limiting (5 attempts/5 min), account lockout
Status: MITIGATED
```

```
Attack: Session Hijacking
Path: Token theft → API access
Risk: HIGH
Mitigation: Short token expiry (30 min), HTTPS only
Status: MITIGATED
```

### 5.3 Infrastructure Attacks

```
Attack: Container Escape
Path: Malicious PCAP → TShark → Container → Host
Risk: CRITICAL
Mitigation: Non-root user, dropped capabilities, resource limits
Status: MITIGATED
```

```
Attack: Denial of Service
Path: Attacker → Multiple requests → Resource exhaustion
Risk: HIGH
Mitigation: Rate limiting, connection limits, timeouts
Status: MITIGATED
```

## 6. Security Controls

### 6.1 Preventive Controls

| Control | Description | Implementation |
|---------|-------------|----------------|
| Authentication | JWT-based auth | `app/core/security.py` |
| Authorization | RBAC | `app/api/dependencies.py` |
| Input Validation | Pydantic schemas | `app/schemas/` |
| Rate Limiting | Request throttling | `slowapi` middleware |
| TLS | HTTPS encryption | NGINX configuration |
| CSP | Content Security Policy | Security headers |

### 6.2 Detective Controls

| Control | Description | Implementation |
|---------|-------------|----------------|
| Audit Logging | All security events | `AuditLog` model |
| Request Tracking | Request ID correlation | Middleware |
| Health Monitoring | Service status | `/api/v1/health` |
| Error Logging | Structured logging | Python logging |

### 6.3 Corrective Controls

| Control | Description | Implementation |
|---------|-------------|----------------|
| Account Lockout | After failed logins | User status management |
| Token Revocation | Invalidate sessions | Refresh token system |
| Graceful Degradation | Failure isolation | Service separation |

## 7. Risk Assessment

### 7.1 Risk Matrix

| Impact ↓ / Likelihood → | Rare | Unlikely | Possible | Likely | Certain |
|-------------------------|------|----------|----------|--------|---------|
| **Critical** | Medium | High | High | Critical | Critical |
| **High** | Low | Medium | High | High | Critical |
| **Medium** | Low | Low | Medium | Medium | High |
| **Low** | Minimal | Low | Low | Medium | Medium |
| **Minimal** | Minimal | Minimal | Low | Low | Low |

### 7.2 Top Risks

| Risk | Likelihood | Impact | Score | Status |
|------|------------|--------|-------|--------|
| Evidence data breach | Unlikely | Critical | HIGH | Mitigated |
| Authentication bypass | Rare | Critical | MEDIUM | Mitigated |
| DoS attack | Possible | High | HIGH | Mitigated |
| Container escape | Rare | Critical | MEDIUM | Mitigated |
| Insider threat | Unlikely | High | MEDIUM | Partial |

## 8. Compliance Considerations

### 8.1 Data Protection

- Evidence files may contain PII
- Implement data retention policies
- Consider encryption at rest
- Audit access to sensitive data

### 8.2 Forensic Integrity

- SHA-256 hash verification
- Chain of custody tracking
- Immutable audit logs
- Evidence tampering detection

## 9. Recommendations

### 9.1 Immediate (Phase 5)

- [x] Implement JWT authentication
- [x] Add RBAC authorization
- [x] Enable HTTPS with TLS 1.2+
- [x] Add security headers
- [x] Implement rate limiting
- [x] Harden Docker containers
- [x] Create audit logging

### 9.2 Short-term

- [ ] Implement encryption at rest for evidence
- [ ] Add 2FA/MFA support
- [ ] Implement API key authentication for automation
- [ ] Add intrusion detection logging
- [ ] Implement backup encryption

### 9.3 Long-term

- [ ] Hardware security module (HSM) for key management
- [ ] Security information and event management (SIEM)
- [ ] Penetration testing program
- [ ] Bug bounty program
- [ ] SOC 2 compliance

## 10. Incident Response

### 10.1 Security Incident Classification

| Level | Description | Response Time |
|-------|-------------|---------------|
| P1 | Active breach, data exfiltration | Immediate |
| P2 | Attempted breach, vulnerability exploited | < 4 hours |
| P3 | Suspicious activity, anomaly detected | < 24 hours |
| P4 | Policy violation, minor issue | < 72 hours |

### 10.2 Response Procedures

1. **Detection**: Audit logs, monitoring alerts
2. **Containment**: Isolate affected systems
3. **Eradication**: Remove threat, patch vulnerability
4. **Recovery**: Restore from clean backup
5. **Lessons Learned**: Update threat model

## 11. Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.5.0 | 2026-09-21 | Phase 5 | Initial threat model |

---

*This document should be reviewed and updated quarterly or after significant system changes.*
