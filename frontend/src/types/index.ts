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
export type JobStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'PARTIAL' | 'CANCELLED';
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
