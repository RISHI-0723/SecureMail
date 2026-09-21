/**
 * Dashboard Page - Security overview with real backend data
 */
import { useState, useEffect } from 'react';
import {
  Shield,
  FolderOpen,
  FileText,
  AlertTriangle,
  Activity,
  TrendingUp,
  CheckCircle,
  XCircle,
  Loader,
  Database,
  Zap,
  Lock,
  Award,
  RefreshCw,
} from 'lucide-react';
import { api, ApiError } from '@/services/api';
import type {
  HealthResponse,
  DependenciesHealthResponse,
  CaseListResponse,
} from '@/types';

interface DashboardPageProps {
  onNavigate: (page: 'cases' | 'findings' | 'reports') => void;
}

interface DashboardStats {
  totalCases: number;
  totalEvidence: number;
  totalAnalyses: number;
  completedAnalyses: number;
  runningAnalyses: number;
  failedAnalyses: number;
}

export function DashboardPage({ onNavigate }: DashboardPageProps) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [deps, setDeps] = useState<DependenciesHealthResponse | null>(null);
  const [stats, setStats] = useState<DashboardStats>({
    totalCases: 0,
    totalEvidence: 0,
    totalAnalyses: 0,
    completedAnalyses: 0,
    runningAnalyses: 0,
    failedAnalyses: 0,
  });
  const [recentCases, setRecentCases] = useState<CaseListResponse['cases']>([]);
  const [refreshing, setRefreshing] = useState(false);

  const loadDashboardData = async () => {
    try {
      const [healthData, depsData, casesData, analysisData] = await Promise.all([
        api.checkHealth(),
        api.checkDependenciesHealth(),
        api.listCases(),
        api.listAnalysisJobs(),
      ]);

      setHealth(healthData);
      setDeps(depsData);
      setRecentCases(casesData.cases.slice(0, 5));

      // Calculate stats
      const totalEvidence = casesData.cases.reduce((sum, c) => sum + c.evidence_count, 0);
      const completedAnalyses = analysisData.jobs.filter(j => j.status === 'COMPLETED').length;
      const runningAnalyses = analysisData.jobs.filter(j => j.status === 'RUNNING' || j.status === 'QUEUED').length;
      const failedAnalyses = analysisData.jobs.filter(j => j.status === 'FAILED' || j.status === 'TIMEOUT').length;

      setStats({
        totalCases: casesData.total,
        totalEvidence,
        totalAnalyses: analysisData.total,
        completedAnalyses,
        runningAnalyses,
        failedAnalyses,
      });

      setError(null);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to load dashboard data');
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
    // Refresh every 30 seconds
    const interval = setInterval(loadDashboardData, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    loadDashboardData();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <Loader className="w-12 h-12 text-cyan-400 animate-spin mx-auto mb-4" />
          <p className="text-slate-400">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with refresh */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
          <p className="text-slate-400 mt-1">Overview of your forensic analysis platform</p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 flex items-center gap-3">
          <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-300">{error}</p>
          <button
            onClick={() => setError(null)}
            className="ml-auto text-red-400 hover:text-red-300"
          >
            &times;
          </button>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={<FolderOpen className="w-6 h-6" />}
          label="Total Cases"
          value={stats.totalCases}
          color="cyan"
          onClick={() => onNavigate('cases')}
        />
        <StatCard
          icon={<FileText className="w-6 h-6" />}
          label="Evidence Files"
          value={stats.totalEvidence}
          color="blue"
        />
        <StatCard
          icon={<Activity className="w-6 h-6" />}
          label="Analyses"
          value={stats.totalAnalyses}
          subValue={`${stats.completedAnalyses} completed`}
          color="green"
        />
        <StatCard
          icon={<AlertTriangle className="w-6 h-6" />}
          label="Active Jobs"
          value={stats.runningAnalyses}
          subValue={stats.failedAnalyses > 0 ? `${stats.failedAnalyses} failed` : undefined}
          color={stats.runningAnalyses > 0 ? 'yellow' : 'slate'}
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Cases */}
        <div className="lg:col-span-2 bg-slate-900/50 border border-slate-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
              <FolderOpen className="w-5 h-5 text-cyan-400" />
              Recent Cases
            </h3>
            <button
              onClick={() => onNavigate('cases')}
              className="text-sm text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              View All &rarr;
            </button>
          </div>

          {recentCases.length === 0 ? (
            <div className="text-center py-8">
              <FolderOpen className="w-12 h-12 text-slate-600 mx-auto mb-3" />
              <p className="text-slate-400">No cases yet</p>
              <button
                onClick={() => onNavigate('cases')}
                className="mt-3 text-sm text-cyan-400 hover:text-cyan-300"
              >
                Create your first case &rarr;
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              {recentCases.map((c) => (
                <div
                  key={c.case_id}
                  className="flex items-center justify-between p-3 bg-slate-800/50 hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
                  onClick={() => onNavigate('cases')}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className={`w-2 h-2 rounded-full ${
                      c.status === 'OPEN' ? 'bg-green-500' :
                      c.status === 'PROCESSING' ? 'bg-yellow-500 animate-pulse' :
                      c.status === 'COMPLETED' ? 'bg-cyan-500' :
                      'bg-slate-500'
                    }`} />
                    <div className="min-w-0">
                      <p className="text-white font-medium truncate">{c.case_name}</p>
                      <p className="text-slate-500 text-xs">{c.evidence_count} evidence files</p>
                    </div>
                  </div>
                  <span className={`px-2 py-1 text-xs rounded ${
                    c.status === 'OPEN' ? 'bg-green-500/20 text-green-400' :
                    c.status === 'PROCESSING' ? 'bg-yellow-500/20 text-yellow-400' :
                    c.status === 'COMPLETED' ? 'bg-cyan-500/20 text-cyan-400' :
                    'bg-slate-500/20 text-slate-400'
                  }`}>
                    {c.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* System Status */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
            <Activity className="w-5 h-5 text-green-400" />
            System Status
          </h3>

          {health && (
            <div className="mb-4 p-3 bg-slate-800/50 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-slate-400 text-sm">API Status</span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                  <span className="text-green-400 text-sm">Online</span>
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400 text-sm">Version</span>
                <span className="text-slate-300 text-sm font-mono">{health.version}</span>
              </div>
            </div>
          )}

          {deps && (
            <div className="space-y-2">
              <p className="text-slate-400 text-sm mb-2">Dependencies</p>
              {deps.dependencies.map((dep, i) => (
                <div key={i} className="flex items-center justify-between p-2 bg-slate-800/30 rounded">
                  <span className="text-slate-300 text-sm flex items-center gap-2">
                    {dep.name === 'database' ? <Database className="w-4 h-4" /> :
                     dep.name === 'redis' ? <Zap className="w-4 h-4" /> :
                     dep.name === 'tshark' ? <Shield className="w-4 h-4" /> :
                     <Activity className="w-4 h-4" />}
                    {dep.name}
                  </span>
                  <span className={`flex items-center gap-1 text-xs ${
                    dep.status === 'healthy' ? 'text-green-400' :
                    dep.status === 'degraded' ? 'text-yellow-400' :
                    'text-red-400'
                  }`}>
                    {dep.status === 'healthy' ? <CheckCircle className="w-3 h-3" /> :
                     dep.status === 'degraded' ? <AlertTriangle className="w-3 h-3" /> :
                     <XCircle className="w-3 h-3" />}
                    {dep.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Capabilities Section */}
      <div className="bg-gradient-to-br from-slate-900/80 to-slate-800/50 border border-slate-700/50 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Award className="w-5 h-5 text-cyan-400" />
          Platform Capabilities
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <CapabilityCard
            icon={<FileText className="w-5 h-5" />}
            title="Evidence Analysis"
            description="PCAP/PCAPNG packet capture analysis with TShark"
          />
          <CapabilityCard
            icon={<Lock className="w-5 h-5" />}
            title="TLS Intelligence"
            description="TLS handshake, cipher, and certificate analysis"
          />
          <CapabilityCard
            icon={<AlertTriangle className="w-5 h-5" />}
            title="Security Findings"
            description="Automated vulnerability and misconfiguration detection"
          />
          <CapabilityCard
            icon={<TrendingUp className="w-5 h-5" />}
            title="Risk Assessment"
            description="Security posture scoring and recommendations"
          />
        </div>
      </div>
    </div>
  );
}

interface StatCardProps {
  icon: React.ReactNode;
  label: string;
  value: number;
  subValue?: string;
  color: 'cyan' | 'blue' | 'green' | 'yellow' | 'red' | 'slate';
  onClick?: () => void;
}

function StatCard({ icon, label, value, subValue, color, onClick }: StatCardProps) {
  const colorClasses = {
    cyan: 'from-cyan-500/20 to-cyan-600/10 border-cyan-500/30 text-cyan-400',
    blue: 'from-blue-500/20 to-blue-600/10 border-blue-500/30 text-blue-400',
    green: 'from-green-500/20 to-green-600/10 border-green-500/30 text-green-400',
    yellow: 'from-yellow-500/20 to-yellow-600/10 border-yellow-500/30 text-yellow-400',
    red: 'from-red-500/20 to-red-600/10 border-red-500/30 text-red-400',
    slate: 'from-slate-500/20 to-slate-600/10 border-slate-500/30 text-slate-400',
  };

  return (
    <div
      className={`
        bg-gradient-to-br ${colorClasses[color]} border rounded-xl p-5
        ${onClick ? 'cursor-pointer hover:scale-[1.02] transition-transform' : ''}
      `}
      onClick={onClick}
    >
      <div className="flex items-center justify-between mb-3">
        <span className={colorClasses[color].split(' ').pop()}>{icon}</span>
      </div>
      <p className="text-3xl font-bold text-white mb-1">{value.toLocaleString()}</p>
      <p className="text-slate-400 text-sm">{label}</p>
      {subValue && <p className="text-slate-500 text-xs mt-1">{subValue}</p>}
    </div>
  );
}

interface CapabilityCardProps {
  icon: React.ReactNode;
  title: string;
  description: string;
}

function CapabilityCard({ icon, title, description }: CapabilityCardProps) {
  return (
    <div className="p-4 bg-slate-800/30 rounded-lg border border-slate-700/50">
      <div className="text-cyan-400 mb-2">{icon}</div>
      <h4 className="text-white font-medium mb-1">{title}</h4>
      <p className="text-slate-400 text-sm">{description}</p>
    </div>
  );
}
