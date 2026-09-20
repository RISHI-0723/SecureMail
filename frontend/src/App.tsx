/**
 * Main App component - Phase 0 Foundation
 */
import { useEffect, useState } from 'react';
import { Shield, Activity, Database, Zap } from 'lucide-react';
import { api, ApiError } from '@/services/api';
import type { HealthResponse, DependenciesHealthResponse } from '@/types';
import { StatusBadge } from '@/components/StatusBadge';

type ConnectionStatus = 'loading' | 'connected' | 'disconnected' | 'error';

function App() {
  const [status, setStatus] = useState<ConnectionStatus>('loading');
  const [healthData, setHealthData] = useState<HealthResponse | null>(null);
  const [depsData, setDepsData] = useState<DependenciesHealthResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    checkBackendHealth();
  }, []);

  const checkBackendHealth = async () => {
    setStatus('loading');
    setError(null);

    try {
      // Check basic health
      const health = await api.checkHealth();
      setHealthData(health);

      // Check dependencies
      const deps = await api.checkDependenciesHealth();
      setDepsData(deps);

      setStatus('connected');
    } catch (err) {
      setStatus('error');
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to connect to backend');
      }
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <header className="text-center mb-12">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-16 h-16 text-blue-400" />
          </div>
          <h1 className="text-4xl font-bold text-white mb-2">
            SecureMailScope
          </h1>
          <p className="text-xl text-blue-200">
            AI-Assisted Cryptographic Security Posture Assessment
          </p>
          <p className="text-sm text-blue-300 mt-2">
            Phase 0 - Foundation
          </p>
        </header>

        {/* Status Card */}
        <div className="max-w-4xl mx-auto">
          <div className="bg-white rounded-lg shadow-xl p-8 mb-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-gray-800 flex items-center gap-2">
                <Activity className="w-6 h-6 text-blue-600" />
                System Status
              </h2>
              <StatusBadge
                status={status === 'connected' ? 'healthy' : status === 'loading' ? 'loading' : 'error'}
                text={
                  status === 'connected'
                    ? 'Backend Connected'
                    : status === 'loading'
                    ? 'Connecting...'
                    : 'Backend Disconnected'
                }
              />
            </div>

            {healthData && (
              <div className="mb-6 p-4 bg-blue-50 rounded-lg">
                <p className="text-sm text-gray-600">Service: {healthData.service}</p>
                <p className="text-sm text-gray-600">Version: {healthData.version}</p>
              </div>
            )}

            {error && (
              <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
                <p className="text-sm text-red-800">{error}</p>
              </div>
            )}

            {/* Dependencies */}
            {depsData && (
              <div className="space-y-4">
                <h3 className="text-lg font-semibold text-gray-700 flex items-center gap-2">
                  <Database className="w-5 h-5 text-gray-600" />
                  Dependencies
                </h3>
                <div className="space-y-3">
                  {depsData.dependencies.map((dep, index) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                    >
                      <div className="flex items-center gap-2">
                        <Zap className="w-4 h-4 text-gray-500" />
                        <span className="font-medium text-gray-700">{dep.name}</span>
                      </div>
                      <StatusBadge status={dep.status} />
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="mt-6 pt-6 border-t border-gray-200">
              <button
                onClick={checkBackendHealth}
                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-colors"
                disabled={status === 'loading'}
              >
                {status === 'loading' ? 'Checking...' : 'Refresh Status'}
              </button>
            </div>
          </div>

          {/* Info Card */}
          <div className="bg-white rounded-lg shadow-xl p-8">
            <h3 className="text-xl font-bold text-gray-800 mb-4">About Phase 0</h3>
            <div className="text-gray-600 space-y-2">
              <p>
                Phase 0 establishes the foundational infrastructure for SecureMailScope:
              </p>
              <ul className="list-disc list-inside space-y-1 ml-4">
                <li>FastAPI backend with structured logging</li>
                <li>React frontend with TypeScript and Tailwind CSS</li>
                <li>PostgreSQL database with Alembic migrations</li>
                <li>Redis for caching and message queue</li>
                <li>Celery for asynchronous task processing</li>
                <li>Docker Compose orchestration</li>
              </ul>
              <p className="mt-4 text-sm text-gray-500">
                PCAP analysis functionality will be implemented in subsequent phases.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
