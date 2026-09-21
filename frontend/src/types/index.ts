/**
 * TypeScript type definitions for SecureMailScope
 */

// Health types
export interface HealthResponse {
  status: 'healthy';
  service: string;
  version: string;
}

export interface DependencyStatus {
  name: string;
  status: 'healthy' | 'unhealthy' | 'unknown';
  message?: string;
}

export interface DependenciesHealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  service: string;
  version: string;
  dependencies: DependencyStatus[];
}

// Case types
export type CaseStatus = 'OPEN' | 'PROCESSING' | 'COMPLETED' | 'FAILED' | 'PARTIAL' | 'ARCHIVED';

export interface Case {
  case_id: string;
  case_name: string;
  description: string | null;
  status: CaseStatus;
  created_at: string;
  updated_at: string;
}

export interface CaseWithEvidenceCount extends Case {
  evidence_count: number;
}

export interface CaseCreate {
  case_name: string;
  description?: string;
}

export interface CaseListResponse {
  cases: CaseWithEvidenceCount[];
  total: number;
}

// Evidence types
export type EvidenceStatus = 'PENDING' | 'VALIDATING' | 'VALIDATED' | 'INVALID' | 'STORED' | 'FAILED';
export type FileFormat = 'pcap' | 'pcapng' | 'unknown';

export interface Evidence {
  evidence_id: string;
  case_id: string;
  original_filename: string;
  file_format: FileFormat;
  file_size_bytes: number;
  sha256: string;
  upload_timestamp: string;
  status: EvidenceStatus;
  error_code: string | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
}

export interface EvidenceUploadResponse {
  evidence_id: string;
  case_id: string;
  original_filename: string;
  file_size_bytes: number;
  file_format: FileFormat;
  sha256: string;
  evidence_status: EvidenceStatus;
  analysis_job_id: string;
  analysis_status: string;
}

export interface EvidenceListResponse {
  evidence: Evidence[];
  total: number;
}

// Analysis job types
export type JobStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'PARTIAL' | 'CANCELLED' | 'TIMEOUT';
export type JobType = 'FULL_ANALYSIS' | 'PROTOCOL_DETECTION' | 'TLS_ANALYSIS' | 'CERTIFICATE_ANALYSIS';

export interface AnalysisJob {
  job_id: string;
  evidence_id: string;
  job_type: JobType;
  status: JobStatus;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_code: string | null;
  error_message: string | null;
  progress_percent: string | null;
  stage: string | null;
}

export interface AnalysisJobListResponse {
  jobs: AnalysisJob[];
  total: number;
}

// Phase 2: Packet Analysis Summary
export interface ProtocolDetection {
  protocol: string;
  port: number;
  confidence: string;
  packet_count: number;
  source_ip: string;
  destination_ip: string;
}

export interface SessionCandidate {
  session_id: string;
  protocol: string;
  client_ip: string;
  client_port: number;
  server_ip: string;
  server_port: number;
  packet_count: number;
  tls_detected: boolean;
}

export interface PacketAnalysisSummary {
  analysis_id: string;
  job_id: string;
  evidence_id: string;
  status: JobStatus;
  tshark_version: string | null;
  analysis_timestamp: string;
  duration_seconds: number | null;
  total_packets: number;
  email_packets: number;
  smtp_packets: number;
  imap_packets: number;
  pop3_packets: number;
  tls_packets: number;
  other_packets: number;
  protocols_detected: string[];
  protocol_detections: ProtocolDetection[];
  session_candidates: SessionCandidate[];
  message: string | null;
}

// API response wrapper
export interface ApiResponse<T> {
  success: boolean;
  data: T | null;
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  } | null;
}

// Upload state
export interface UploadState {
  status: 'idle' | 'uploading' | 'success' | 'error';
  progress: number;
  error?: string;
  result?: EvidenceUploadResponse;
}

// Authentication types
export interface LoginRequest {
  username: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface UserInfo {
  user_id: string;
  username: string;
  email: string;
  full_name: string | null;
  role: 'ADMIN' | 'ANALYST' | 'VIEWER';
  permissions: string[];
}

export interface AuthState {
  isAuthenticated: boolean;
  user: UserInfo | null;
  accessToken: string | null;
}

// Phase 3: Security Analysis Types
export interface SecurityAnalysisSummary {
  analysis_id: string;
  job_id: string;
  evidence_id: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  total_streams: number;
  total_sessions: number;
  total_tls_observations: number;
  total_certificates: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  info_findings: number;
  overall_risk_level: string;
  overall_risk_score: number;
  confidence: string;
  coverage: string;
  policy_version: string;
}

export interface TcpStream {
  stream_id: number;
  client_ip: string;
  client_port: number;
  server_ip: string;
  server_port: number;
  integrity: string;
  packet_count: number;
  byte_count: number;
  has_fin: boolean;
  has_rst: boolean;
  termination_type: string | null;
  start_time: string | null;
  end_time: string | null;
}

export interface EmailSession {
  session_id: string;
  stream_id: number;
  protocol: string;
  client_ip: string;
  client_port: number;
  server_ip: string;
  server_port: number;
  transport_security: string;
  starttls_advertised: boolean;
  starttls_state: string;
  tls_detected: boolean;
  implicit_tls: boolean;
  confidence: string;
  coverage: string;
}

export interface TlsObservation {
  observation_id: string;
  session_id: string | null;
  stream_id: number;
  tls_version: string;
  tls_version_security: string;
  cipher_suite: string;
  key_exchange: string;
  has_forward_secrecy: boolean;
  handshake_status: string;
  handshake_timestamp: string | null;
  sni: string | null;
  alpn: string | null;
  confidence: string;
  coverage: string;
}

export interface CertificateInfo {
  certificate_id: string;
  stream_id: number;
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  validity: string;
  key_type: string;
  key_size_bits: number;
  key_strength: string;
  signature_algorithm: string;
  signature_algorithm_security: string;
  is_self_signed: boolean;
  subject_alt_names: string[];
  confidence: string;
  parse_status: string | null;
}

export interface FindingEvidence {
  evidence_type: string;
  reference_id: string;
  stream_id: number | null;
  observed_value: string | null;
  expected_value: string | null;
}

export interface SecurityFinding {
  finding_id: string;
  rule_id: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  evidence: FindingEvidence[];
  session_id: string | null;
  stream_id: number | null;
  certificate_id: string | null;
  confidence: string;
  remediation: string;
  occurrence_count: number;
  affected_streams: number[];
}

export interface DimensionScore {
  dimension: string;
  score: number;
  risk_level: string;
  findings_count: number;
  description: string;
}

export interface RiskAssessment {
  overall_score: number;
  overall_risk: string;
  dimensions: DimensionScore[];
  confidence: string;
  coverage: string;
  summary: string;
  key_findings: string[];
  recommendations: string[];
  assessment_version: string;
  policy_version: string;
}

// Phase 4: Intelligence Analysis Types
export interface IntelligenceSummary {
  report_id: string;
  evidence_id: string;
  security_analysis_id: string;
  status: string;
  created_at: string;
  completed_at: string | null;
  duration_seconds: number | null;
  total_correlations: number;
  total_recommendations: number;
  ml_enabled: boolean;
  ml_predictions_count: number;
  anomalies_detected: number;
  security_posture_score: number;
  security_posture_grade: string;
  tls_security_score: number;
  certificate_security_score: number;
  protocol_security_score: number;
  configuration_security_score: number;
  executive_summary: string | null;
}

export interface Correlation {
  correlation_id: string;
  correlation_type: string;
  strength: number;
  confidence: number;
  title: string;
  description: string;
  linked_findings: string[];
  linked_sessions: string[];
  linked_certificates: string[];
  common_attribute: string | null;
  common_value: string | null;
  combined_severity: string;
  combined_risk_score: number;
  created_at: string;
}

export interface Recommendation {
  recommendation_id: string;
  priority: string;
  category: string;
  title: string;
  description: string;
  remediation_steps: string[];
  estimated_effort: string | null;
  technical_impact: string | null;
  business_impact: string | null;
  affected_findings: string[];
  affected_sessions: string[];
  affected_certificates: string[];
  compliance_references: string | null;
  status: string | null;
  created_at: string;
}

export interface SecurityPosture {
  overall_score: number;
  grade: string;
  tls_security_score: number;
  certificate_security_score: number;
  protocol_security_score: number;
  configuration_security_score: number;
  aggregated_findings: Record<string, unknown>[];
  correlation_summary: Record<string, unknown>;
  recommendation_summary: Record<string, unknown>;
}

export interface MLAnomaly {
  prediction_id: string;
  target_type: string;
  target_id: string;
  anomaly_score: number;
  confidence: number;
  feature_importance: Record<string, number>;
  explanation: string;
}

export interface MLInsights {
  ml_enabled: boolean;
  message?: string;
  model_version: string | null;
  total_predictions: number;
  anomalies_detected: number;
  anomalies: MLAnomaly[];
  top_risk_factors: string[];
  confidence: number;
}

export interface ReportInfo {
  report_id: string;
  format: string;
  status: string;
  filename: string | null;
  file_size_bytes: number | null;
  content_hash: string | null;
  generated_at: string | null;
  error_message: string | null;
}

export interface EvidenceIntegrity {
  integrity_id: string;
  evidence_id: string;
  status: string;
  evidence_sha256: string;
  evidence_sha512: string | null;
  analysis_hash: string | null;
  report_hash: string | null;
  merkle_root: string | null;
  blockchain_enabled: boolean;
  blockchain_network: string | null;
  transaction_hash: string | null;
  block_number: number | null;
  anchor_timestamp: string | null;
  created_at: string;
  verified_at: string | null;
}
