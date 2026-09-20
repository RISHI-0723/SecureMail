/**
 * API service for communicating with the backend
 */
import type { HealthResponse, DependenciesHealthResponse } from '@/types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

class ApiError extends Error {
  constructor(
    message: string,
    public status?: number,
    public data?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function fetchApi<T>(endpoint: string): Promise<T> {
  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`);

    if (!response.ok) {
      throw new ApiError(
        `API request failed: ${response.statusText}`,
        response.status
      );
    }

    return await response.json();
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError('Failed to connect to backend', undefined, error);
  }
}

export const api = {
  /**
   * Check basic API health
   */
  async checkHealth(): Promise<HealthResponse> {
    return fetchApi<HealthResponse>('/api/v1/health');
  },

  /**
   * Check detailed health including dependencies
   */
  async checkDependenciesHealth(): Promise<DependenciesHealthResponse> {
    return fetchApi<DependenciesHealthResponse>('/api/v1/health/dependencies');
  },
};

export { ApiError };
