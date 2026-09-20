/**
 * TypeScript type definitions for SecureMailScope
 */

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
