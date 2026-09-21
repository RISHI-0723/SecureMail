/**
 * Findings Page - View all security findings across cases
 */
import { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Shield,
  Search,
  Loader,
  AlertCircle,
  CheckCircle,
  Info,
  FileText,
} from 'lucide-react';
import { api, ApiError } from '@/services/api';
import type { SecurityFinding } from '@/types';

interface FindingWithCase extends SecurityFinding {
  case_name?: string;
  evidence_name?: string;
}

export function FindingsPage() {
  const [findings, setFindings] = useState<FindingWithCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    loadFindings();
  }, []);

  const loadFindings = async () => {
    setLoading(true);
    try {
      // Get all cases and their evidence to collect findings
      const casesResponse = await api.listCases();
      const allFindings: FindingWithCase[] = [];

      for (const c of casesResponse.cases) {
        const evidenceResponse = await api.listCaseEvidence(c.case_id);
        for (const ev of evidenceResponse.evidence) {
          try {
            const findingsResponse = await api.getSecurityFindings(ev.evidence_id);
            for (const finding of findingsResponse.findings) {
              allFindings.push({
                ...finding,
                case_name: c.case_name,
                evidence_name: ev.original_filename,
              });
            }
          } catch {
            // Skip if findings not available
          }
        }
      }

      setFindings(allFindings);
      setError(null);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to load findings');
      }
    } finally {
      setLoading(false);
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return <AlertCircle className="w-5 h-5 text-red-500" />;
      case 'HIGH':
        return <AlertTriangle className="w-5 h-5 text-orange-500" />;
      case 'MEDIUM':
        return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
      case 'LOW':
        return <Info className="w-5 h-5 text-blue-500" />;
      default:
        return <CheckCircle className="w-5 h-5 text-green-500" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/10 border-red-500/30 text-red-400';
      case 'HIGH':
        return 'bg-orange-500/10 border-orange-500/30 text-orange-400';
      case 'MEDIUM':
        return 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400';
      case 'LOW':
        return 'bg-blue-500/10 border-blue-500/30 text-blue-400';
      default:
        return 'bg-green-500/10 border-green-500/30 text-green-400';
    }
  };

  const filteredFindings = findings.filter((finding) => {
    const matchesSeverity = severityFilter === 'all' || finding.severity === severityFilter;
    const matchesSearch =
      searchQuery === '' ||
      finding.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      finding.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      finding.case_name?.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  const severityCounts = findings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <Loader className="w-12 h-12 text-cyan-400 animate-spin mx-auto mb-4" />
          <p className="text-slate-400">Loading security findings...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <AlertTriangle className="w-7 h-7 text-cyan-400" />
          Security Findings
        </h1>
        <p className="text-slate-400 mt-1">
          {findings.length} findings across all analyzed evidence
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((severity) => (
          <button
            key={severity}
            onClick={() => setSeverityFilter(severityFilter === severity ? 'all' : severity)}
            className={`p-4 rounded-xl border transition-all ${
              severityFilter === severity
                ? getSeverityColor(severity) + ' border-2'
                : 'bg-slate-900/50 border-slate-800 hover:border-slate-700'
            }`}
          >
            <p className="text-2xl font-bold text-white">{severityCounts[severity] || 0}</p>
            <p className="text-slate-400 text-sm">{severity}</p>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-col md:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
          <input
            type="text"
            placeholder="Search findings..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900/50 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="bg-slate-900/50 border border-slate-800 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-cyan-500"
        >
          <option value="all">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFO">Info</option>
        </select>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-300">{error}</p>
        </div>
      )}

      {/* Findings List */}
      {filteredFindings.length === 0 ? (
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-12 text-center">
          <Shield className="w-16 h-16 text-slate-600 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-white mb-2">No Findings</h3>
          <p className="text-slate-400">
            {findings.length === 0
              ? 'No security findings detected yet. Upload and analyze evidence to detect security issues.'
              : 'No findings match your current filters.'}
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredFindings.map((finding) => (
            <div
              key={finding.finding_id}
              className={`bg-slate-900/50 border rounded-xl p-5 ${getSeverityColor(finding.severity)}`}
            >
              <div className="flex items-start gap-4">
                <div className="mt-0.5">{getSeverityIcon(finding.severity)}</div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 flex-wrap mb-2">
                    <h3 className="text-lg font-semibold text-white">{finding.title}</h3>
                    <span
                      className={`px-2 py-0.5 text-xs rounded border ${getSeverityColor(finding.severity)}`}
                    >
                      {finding.severity}
                    </span>
                    <span className="px-2 py-0.5 text-xs rounded bg-slate-700 text-slate-300">
                      {finding.category}
                    </span>
                  </div>
                  <p className="text-slate-300 mb-3">{finding.description}</p>

                  {/* Source info */}
                  {(finding.case_name || finding.evidence_name) && (
                    <div className="flex items-center gap-4 text-sm text-slate-500 mb-3">
                      {finding.case_name && (
                        <span className="flex items-center gap-1">
                          <FileText className="w-4 h-4" />
                          {finding.case_name}
                        </span>
                      )}
                      {finding.evidence_name && (
                        <span className="truncate">{finding.evidence_name}</span>
                      )}
                    </div>
                  )}

                  {/* Remediation */}
                  {finding.remediation && (
                    <div className="bg-slate-800/50 rounded-lg p-3 mt-3">
                      <p className="text-sm text-slate-400 mb-1">Remediation:</p>
                      <p className="text-slate-300 text-sm">{finding.remediation}</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
