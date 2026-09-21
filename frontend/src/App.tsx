/**
 * Main App component - Phase 5 Production
 */
import { useEffect, useState } from 'react';
import { Shield, Activity, Database, Zap, FolderOpen, Home, LogOut, User } from 'lucide-react';
import { api, ApiError, getAccessToken, clearTokens } from '@/services/api';
import type { HealthResponse, DependenciesHealthResponse, UserInfo } from '@/types';
import { StatusBadge } from '@/components/StatusBadge';
import { CasesPage } from '@/pages/CasesPage';
import { CaseDetailPage } from '@/pages/CaseDetailPage';
import { LoginPage } from '@/pages/LoginPage';

type ConnectionStatus = 'loading' | 'connected' | 'disconnected' | 'error';
type Page = 'dashboard' | 'cases' | 'case-detail';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!getAccessToken());
  const [currentUser, setCurrentUser] = useState<UserInfo | null>(null);
  const [status, setStatus] = useState<ConnectionStatus>('loading');
  const [healthData, setHealthData] = useState<HealthResponse | null>(null);
  const [depsData, setDepsData] = useState<DependenciesHealthResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState<Page>('dashboard');
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);

  useEffect(() => {
    if (isAuthenticated) {
      checkBackendHealth();
      fetchCurrentUser();
    }
  }, [isAuthenticated]);

  const fetchCurrentUser = async () => {
    try {
      const user = await api.getCurrentUser();
      setCurrentUser(user);
    } catch (err) {
      // If user fetch fails, clear auth state
      handleLogout();
    }
  };

  const handleLoginSuccess = () => {
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    clearTokens();
    setIsAuthenticated(false);
    setCurrentUser(null);
    setCurrentPage('dashboard');
  };

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

  const handleSelectCase = (caseId: string) => {
    setSelectedCaseId(caseId);
    setCurrentPage('case-detail');
  };

  const handleBackToCases = () => {
    setSelectedCaseId(null);
    setCurrentPage('cases');
  };

  const renderContent = () => {
    switch (currentPage) {
      case 'cases':
        return <CasesPage onSelectCase={handleSelectCase} />;
      case 'case-detail':
        return selectedCaseId ? (
          <CaseDetailPage caseId={selectedCaseId} onBack={handleBackToCases} />
        ) : (
          <CasesPage onSelectCase={handleSelectCase} />
        );
      default:
        return renderDashboard();
    }
  };

  const renderDashboard = () => (
    <div className="space-y-6">
      {/* Status Card */}
      <div className="bg-white rounded-lg shadow-xl p-8">
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

        <div className="mt-6 pt-6 border-t border-gray-200 flex gap-4">
          <button
            onClick={checkBackendHealth}
            className="flex-1 bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-colors"
            disabled={status === 'loading'}
          >
            {status === 'loading' ? 'Checking...' : 'Refresh Status'}
          </button>
          <button
            onClick={() => setCurrentPage('cases')}
            className="flex-1 bg-green-600 hover:bg-green-700 text-white font-medium py-2 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            <FolderOpen className="w-5 h-5" />
            Go to Cases
          </button>
        </div>
      </div>

      {/* Info Card */}
      <div className="bg-white rounded-lg shadow-xl p-8">
        <h3 className="text-xl font-bold text-gray-800 mb-4">SecureMailScope Capabilities</h3>
        <div className="text-gray-600 space-y-2">
          <p>
            SecureMailScope provides comprehensive email security forensic analysis:
          </p>
          <ul className="list-disc list-inside space-y-1 ml-4">
            <li>Create and manage forensic cases</li>
            <li>Upload PCAP and PCAPNG evidence files</li>
            <li>Protocol detection (SMTP, IMAP, POP3)</li>
            <li>TLS handshake analysis and cipher assessment</li>
            <li>X.509 certificate validation</li>
            <li>Security findings with severity levels</li>
            <li>Risk scoring and security posture</li>
            <li>ML-powered anomaly detection</li>
            <li>Comprehensive forensic reports</li>
          </ul>
          <p className="mt-4 text-sm text-gray-500">
            Version 0.5.0 - Production Ready with JWT Authentication
          </p>
        </div>
      </div>
    </div>
  );

  // Show login page if not authenticated
  if (!isAuthenticated) {
    return <LoginPage onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <header className="text-center mb-8">
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
            v0.5.0 - Production Ready
          </p>
          {currentUser && (
            <div className="mt-4 flex items-center justify-center gap-4">
              <span className="text-sm text-blue-200 flex items-center gap-1">
                <User className="w-4 h-4" />
                {currentUser.username} ({currentUser.role})
              </span>
              <button
                onClick={handleLogout}
                className="text-sm text-blue-200 hover:text-white flex items-center gap-1 transition-colors"
              >
                <LogOut className="w-4 h-4" />
                Sign Out
              </button>
            </div>
          )}
        </header>

        {/* Navigation */}
        <nav className="max-w-4xl mx-auto mb-6">
          <div className="flex gap-2 bg-white/10 rounded-lg p-1">
            <button
              onClick={() => setCurrentPage('dashboard')}
              className={`flex-1 flex items-center justify-center gap-2 py-2 px-4 rounded-lg transition-colors ${
                currentPage === 'dashboard'
                  ? 'bg-blue-600 text-white'
                  : 'text-blue-200 hover:bg-white/10'
              }`}
            >
              <Home className="w-4 h-4" />
              Dashboard
            </button>
            <button
              onClick={() => setCurrentPage('cases')}
              className={`flex-1 flex items-center justify-center gap-2 py-2 px-4 rounded-lg transition-colors ${
                currentPage === 'cases' || currentPage === 'case-detail'
                  ? 'bg-blue-600 text-white'
                  : 'text-blue-200 hover:bg-white/10'
              }`}
            >
              <FolderOpen className="w-4 h-4" />
              Cases
            </button>
          </div>
        </nav>

        {/* Content */}
        <div className="max-w-4xl mx-auto">
          {renderContent()}
        </div>
      </div>
    </div>
  );
}

export default App;
