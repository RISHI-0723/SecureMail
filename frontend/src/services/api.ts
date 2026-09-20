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
} from '@/types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

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
}

async function fetchApi<T>(
  endpoint: string,
  options?: RequestInit
): Promise<T> {
  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
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

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'POST',
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
  // Health endpoints
  async checkHealth(): Promise<HealthResponse> {
    return fetchApi<HealthResponse>('/api/v1/health');
  },

  async checkDependenciesHealth(): Promise<DependenciesHealthResponse> {
    return fetchApi<DependenciesHealthResponse>('/api/v1/health/dependencies');
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

  async getEvidenceAnalysisJobs(evidenceId: string): Promise<AnalysisJobListResponse> {
    return fetchApi<AnalysisJobListResponse>(`/api/v1/evidence/${evidenceId}/analysis`);
  },

  async listAnalysisJobs(statusFilter?: string): Promise<AnalysisJobListResponse> {
    const params = statusFilter ? `?status_filter=${statusFilter}` : '';
    return fetchApi<AnalysisJobListResponse>(`/api/v1/analysis${params}`);
  },
};
