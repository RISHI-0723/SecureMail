/**
 * API service for communicating with the backend
 */
import type {
  HealthResponse,
  DependenciesHealthResponse,
  CaseCreate,
  CaseWithEvidenceCount,
  CaseListResponse,
  Evidence,
  EvidenceListResponse,
  EvidenceUploadResponse,
  AnalysisJob,
  AnalysisJobListResponse,
  PacketAnalysisSummary,
  LoginRequest,
  TokenResponse,
  UserInfo,
  SecurityAnalysisSummary,
  TcpStream,
  EmailSession,
  TlsObservation,
  CertificateInfo,
  SecurityFinding,
  RiskAssessment,
  IntelligenceSummary,
  Correlation,
  Recommendation,
  SecurityPosture,
  MLInsights,
  ReportInfo,
  EvidenceIntegrity,
} from '@/types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Token storage
let accessToken: string | null = localStorage.getItem('access_token');
let refreshToken: string | null = localStorage.getItem('refresh_token');

export function setTokens(access: string, refresh: string) {
  accessToken = access;
  refreshToken = refresh;
  localStorage.setItem('access_token', access);
  localStorage.setItem('refresh_token', refresh);
}

export function clearTokens() {
  accessToken = null;
  refreshToken = null;
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
}

export function getAccessToken(): string | null {
  return accessToken;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public status?: number,
    public code?: string,
    public data?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }

  // Helper methods to check specific error states
  isNotFound(): boolean {
    return this.status === 404;
  }

  isAnalysisNotStarted(): boolean {
    return this.code === 'ANALYSIS_NOT_STARTED' || this.code === 'SECURITY_ANALYSIS_NOT_FOUND' || this.code === 'INTELLIGENCE_NOT_FOUND';
  }

  isAnalysisInProgress(): boolean {
    return this.code === 'ANALYSIS_IN_PROGRESS' || this.code === 'INTELLIGENCE_IN_PROGRESS';
  }

  isAnalysisFailed(): boolean {
    return this.code === 'ANALYSIS_FAILED' || this.code === 'SECURITY_ANALYSIS_FAILED' || this.code === 'INTELLIGENCE_FAILED';
  }

  isConnectionError(): boolean {
    return this.code === 'CONNECTION_ERROR';
  }
}

async function fetchApi<T>(
  endpoint: string,
  options?: RequestInit,
  requireAuth: boolean = true
): Promise<T> {
  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options?.headers as Record<string, string>),
    };

    if (requireAuth && accessToken) {
      headers['Authorization'] = `Bearer ${accessToken}`;
    }

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });

    const data = await response.json();

    if (!response.ok) {
      const error = data.detail || data.error || { code: 'UNKNOWN', message: response.statusText };
      throw new ApiError(
        error.message || 'Request failed',
        response.status,
        error.code
      );
    }

    // Unwrap API response if it has the wrapper structure
    if (data && typeof data === 'object' && 'success' in data) {
      if (!data.success) {
        throw new ApiError(
          data.error?.message || 'Request failed',
          response.status,
          data.error?.code
        );
      }
      return data.data as T;
    }

    return data as T;
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError('Failed to connect to backend', undefined, 'CONNECTION_ERROR', error);
  }
}

async function uploadFile<T>(
  endpoint: string,
  file: File
): Promise<T> {
  const formData = new FormData();
  formData.append('file', file);

  const headers: Record<string, string> = {};
  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'POST',
      headers,
      body: formData,
    });

    const data = await response.json();

    if (!response.ok) {
      const error = data.detail || data.error || { code: 'UNKNOWN', message: response.statusText };
      throw new ApiError(
        error.message || 'Upload failed',
        response.status,
        error.code
      );
    }

    // Unwrap API response if it has the wrapper structure
    if (data && typeof data === 'object' && 'success' in data) {
      if (!data.success) {
        throw new ApiError(
          data.error?.message || 'Upload failed',
          response.status,
          data.error?.code
        );
      }
      return data.data as T;
    }

    return data as T;
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError('Upload failed', undefined, 'UPLOAD_ERROR', error);
  }
}

export const api = {
  // Auth endpoints
  async login(credentials: LoginRequest): Promise<TokenResponse> {
    const response = await fetchApi<TokenResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    }, false);
    setTokens(response.access_token, response.refresh_token);
    return response;
  },

  async logout(): Promise<void> {
    clearTokens();
  },

  async getCurrentUser(): Promise<UserInfo> {
    return fetchApi<UserInfo>('/api/v1/auth/me');
  },

  async refreshToken(): Promise<TokenResponse> {
    if (!refreshToken) {
      throw new ApiError('No refresh token available', undefined, 'NO_REFRESH_TOKEN');
    }
    const response = await fetchApi<TokenResponse>('/api/v1/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: refreshToken }),
    }, false);
    setTokens(response.access_token, response.refresh_token);
    return response;
  },

  async changePassword(currentPassword: string, newPassword: string): Promise<{ message: string }> {
    return fetchApi<{ message: string }>('/api/v1/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    });
  },

  // User management endpoints (Admin only)
  async listUsers(): Promise<{ users: UserInfo[]; total: number }> {
    return fetchApi<{ users: UserInfo[]; total: number }>('/api/v1/auth/users');
  },

  async createUser(userData: { username: string; email: string; password: string; full_name?: string; role?: string }): Promise<UserInfo> {
    return fetchApi<UserInfo>('/api/v1/auth/users', {
      method: 'POST',
      body: JSON.stringify(userData),
    });
  },

  async updateUser(userId: string, userData: { email?: string; full_name?: string; role?: string; status?: string }): Promise<UserInfo> {
    return fetchApi<UserInfo>(`/api/v1/auth/users/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify(userData),
    });
  },

  async deleteUser(userId: string): Promise<{ deleted: boolean; user_id: string }> {
    return fetchApi<{ deleted: boolean; user_id: string }>(`/api/v1/auth/users/${userId}`, {
      method: 'DELETE',
    });
  },

  // Health endpoints
  async checkHealth(): Promise<HealthResponse> {
    return fetchApi<HealthResponse>('/api/v1/health', undefined, false);
  },

  async checkDependenciesHealth(): Promise<DependenciesHealthResponse> {
    return fetchApi<DependenciesHealthResponse>('/api/v1/health/dependencies', undefined, false);
  },

  // Case endpoints
  async createCase(data: CaseCreate): Promise<CaseWithEvidenceCount> {
    return fetchApi<CaseWithEvidenceCount>('/api/v1/cases', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async listCases(): Promise<CaseListResponse> {
    return fetchApi<CaseListResponse>('/api/v1/cases');
  },

  async getCase(caseId: string): Promise<CaseWithEvidenceCount> {
    return fetchApi<CaseWithEvidenceCount>(`/api/v1/cases/${caseId}`);
  },

  async deleteCase(caseId: string): Promise<{ deleted: boolean; case_id: string }> {
    return fetchApi<{ deleted: boolean; case_id: string }>(`/api/v1/cases/${caseId}`, {
      method: 'DELETE',
    });
  },

  // Evidence endpoints
  async uploadEvidence(caseId: string, file: File): Promise<EvidenceUploadResponse> {
    return uploadFile<EvidenceUploadResponse>(`/api/v1/cases/${caseId}/evidence`, file);
  },

  async listCaseEvidence(caseId: string): Promise<EvidenceListResponse> {
    return fetchApi<EvidenceListResponse>(`/api/v1/cases/${caseId}/evidence`);
  },

  async getEvidence(evidenceId: string): Promise<Evidence> {
    return fetchApi<Evidence>(`/api/v1/evidence/${evidenceId}`);
  },

  async deleteEvidence(evidenceId: string): Promise<{ deleted: boolean; evidence_id: string }> {
    return fetchApi<{ deleted: boolean; evidence_id: string }>(`/api/v1/evidence/${evidenceId}`, {
      method: 'DELETE',
    });
  },

  // Analysis endpoints
  async getAnalysisJob(jobId: string): Promise<AnalysisJob> {
    return fetchApi<AnalysisJob>(`/api/v1/analysis/${jobId}`);
  },

  async getAnalysisSummary(jobId: string): Promise<PacketAnalysisSummary> {
    return fetchApi<PacketAnalysisSummary>(`/api/v1/analysis/${jobId}/summary`);
  },

  async getEvidenceAnalysisJobs(evidenceId: string): Promise<AnalysisJobListResponse> {
    return fetchApi<AnalysisJobListResponse>(`/api/v1/evidence/${evidenceId}/analysis`);
  },

  async listAnalysisJobs(statusFilter?: string): Promise<AnalysisJobListResponse> {
    const params = statusFilter ? `?status_filter=${statusFilter}` : '';
    return fetchApi<AnalysisJobListResponse>(`/api/v1/analysis${params}`);
  },

  async triggerAnalysis(evidenceId: string): Promise<{ job_id: string; status: string; message: string }> {
    return fetchApi<{ job_id: string; status: string; message: string }>(
      `/api/v1/evidence/${evidenceId}/analyze`,
      { method: 'POST' }
    );
  },

  // Phase 3: Security Analysis endpoints
  async getSecuritySummary(evidenceId: string): Promise<SecurityAnalysisSummary> {
    return fetchApi<SecurityAnalysisSummary>(`/api/v1/security/${evidenceId}/summary`);
  },

  async getTcpStreams(evidenceId: string): Promise<{ streams: TcpStream[]; total: number; complete_count: number; partial_count: number }> {
    return fetchApi<{ streams: TcpStream[]; total: number; complete_count: number; partial_count: number }>(`/api/v1/security/${evidenceId}/streams`);
  },

  async getEmailSessions(evidenceId: string): Promise<{ sessions: EmailSession[]; total: number; by_protocol: Record<string, number>; by_transport_security: Record<string, number> }> {
    return fetchApi<{ sessions: EmailSession[]; total: number; by_protocol: Record<string, number>; by_transport_security: Record<string, number> }>(`/api/v1/security/${evidenceId}/sessions`);
  },

  async getTlsObservations(evidenceId: string): Promise<{ observations: TlsObservation[]; total: number; by_version: Record<string, number>; modern_tls_count: number; deprecated_tls_count: number }> {
    return fetchApi<{ observations: TlsObservation[]; total: number; by_version: Record<string, number>; modern_tls_count: number; deprecated_tls_count: number }>(`/api/v1/security/${evidenceId}/tls`);
  },

  async getCertificates(evidenceId: string): Promise<{ certificates: CertificateInfo[]; total: number; valid_count: number; expired_count: number; weak_key_count: number; self_signed_count: number }> {
    return fetchApi<{ certificates: CertificateInfo[]; total: number; valid_count: number; expired_count: number; weak_key_count: number; self_signed_count: number }>(`/api/v1/security/${evidenceId}/certificates`);
  },

  async getSecurityFindings(evidenceId: string): Promise<{ findings: SecurityFinding[]; total: number; by_severity: Record<string, number>; by_category: Record<string, number>; unique_rules: string[] }> {
    return fetchApi<{ findings: SecurityFinding[]; total: number; by_severity: Record<string, number>; by_category: Record<string, number>; unique_rules: string[] }>(`/api/v1/security/${evidenceId}/findings`);
  },

  async getRiskAssessment(evidenceId: string): Promise<RiskAssessment> {
    return fetchApi<RiskAssessment>(`/api/v1/security/${evidenceId}/risk`);
  },

  async triggerSecurityAnalysis(evidenceId: string): Promise<{ job_id: string; status: string; message: string }> {
    return fetchApi<{ job_id: string; status: string; message: string }>(
      `/api/v1/security/${evidenceId}/analyze`,
      { method: 'POST' }
    );
  },

  // Phase 4: Intelligence Analysis endpoints
  async getIntelligenceSummary(evidenceId: string): Promise<IntelligenceSummary> {
    return fetchApi<IntelligenceSummary>(`/api/v1/evidence/${evidenceId}/intelligence`);
  },

  async getSecurityPosture(evidenceId: string): Promise<SecurityPosture> {
    return fetchApi<SecurityPosture>(`/api/v1/evidence/${evidenceId}/intelligence/posture`);
  },

  async getCorrelations(evidenceId: string): Promise<{ correlations: Correlation[]; total: number }> {
    return fetchApi<{ correlations: Correlation[]; total: number }>(`/api/v1/evidence/${evidenceId}/correlations`);
  },

  async getRecommendations(evidenceId: string): Promise<{ recommendations: Recommendation[]; total: number }> {
    return fetchApi<{ recommendations: Recommendation[]; total: number }>(`/api/v1/evidence/${evidenceId}/recommendations`);
  },

  async getMLInsights(evidenceId: string): Promise<MLInsights> {
    return fetchApi<MLInsights>(`/api/v1/evidence/${evidenceId}/ml`);
  },

  async getReports(evidenceId: string): Promise<{ reports: ReportInfo[]; total: number }> {
    return fetchApi<{ reports: ReportInfo[]; total: number }>(`/api/v1/evidence/${evidenceId}/reports`);
  },

  async generateReport(caseId: string, format: 'json' | 'html' | 'pdf'): Promise<{ report_id: string; download_url: string; format: string }> {
    return fetchApi<{ report_id: string; download_url: string; format: string }>(`/api/v1/cases/${caseId}/report`, {
      method: 'POST',
      body: JSON.stringify({ format }),
    });
  },

  async getIntegrity(evidenceId: string): Promise<EvidenceIntegrity> {
    return fetchApi<EvidenceIntegrity>(`/api/v1/evidence/${evidenceId}/integrity`);
  },

  async triggerIntelligenceAnalysis(evidenceId: string): Promise<{ job_id: string; evidence_id: string; status: string; message: string }> {
    return fetchApi<{ job_id: string; evidence_id: string; status: string; message: string }>(
      `/api/v1/evidence/${evidenceId}/intelligence`,
      { method: 'POST' }
    );
  },
};
