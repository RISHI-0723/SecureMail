/**
 * Reports Page - Generate and download forensic reports
 */
import { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  FileJson,
  Code,
  File,
  Clock,
  Loader,
  AlertCircle,
  FolderOpen,
} from 'lucide-react';
import { api, ApiError } from '@/services/api';
import type { CaseListResponse } from '@/types';

interface ReportJob {
  caseId: string;
  caseName: string;
  format: 'json' | 'html' | 'pdf';
  status: 'generating' | 'ready' | 'failed';
  url?: string;
}

export function ReportsPage() {
  const [cases, setCases] = useState<CaseListResponse['cases']>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedCase, setSelectedCase] = useState<string>('');
  const [selectedFormat, setSelectedFormat] = useState<'json' | 'html' | 'pdf'>('html');
  const [generating, setGenerating] = useState(false);
  const [recentReports, setRecentReports] = useState<ReportJob[]>([]);

  useEffect(() => {
    loadCases();
  }, []);

  const loadCases = async () => {
    setLoading(true);
    try {
      const response = await api.listCases();
      setCases(response.cases.filter(c => c.status === 'COMPLETED'));
      setError(null);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to load cases');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateReport = async () => {
    if (!selectedCase) return;

    const caseInfo = cases.find(c => c.case_id === selectedCase);
    if (!caseInfo) return;

    setGenerating(true);
    const newReport: ReportJob = {
      caseId: selectedCase,
      caseName: caseInfo.case_name,
      format: selectedFormat,
      status: 'generating',
    };

    setRecentReports(prev => [newReport, ...prev]);

    try {
      // Call report generation API
      const response = await api.generateReport(selectedCase, selectedFormat);

      setRecentReports(prev =>
        prev.map(r =>
          r.caseId === selectedCase && r.format === selectedFormat && r.status === 'generating'
            ? { ...r, status: 'ready', url: response.download_url }
            : r
        )
      );
    } catch (err) {
      setRecentReports(prev =>
        prev.map(r =>
          r.caseId === selectedCase && r.format === selectedFormat && r.status === 'generating'
            ? { ...r, status: 'failed' }
            : r
        )
      );
      if (err instanceof ApiError) {
        setError(err.message);
      }
    } finally {
      setGenerating(false);
    }
  };

  const getFormatIcon = (format: string) => {
    switch (format) {
      case 'json':
        return <FileJson className="w-5 h-5" />;
      case 'html':
        return <Code className="w-5 h-5" />;
      case 'pdf':
        return <File className="w-5 h-5" />;
      default:
        return <FileText className="w-5 h-5" />;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <Loader className="w-12 h-12 text-cyan-400 animate-spin mx-auto mb-4" />
          <p className="text-slate-400">Loading cases...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <FileText className="w-7 h-7 text-cyan-400" />
          Forensic Reports
        </h1>
        <p className="text-slate-400 mt-1">
          Generate and download comprehensive security analysis reports
        </p>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-300">{error}</p>
          <button onClick={() => setError(null)} className="ml-auto text-red-400 hover:text-red-300">
            &times;
          </button>
        </div>
      )}

      {/* Report Generator */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Download className="w-5 h-5 text-cyan-400" />
          Generate Report
        </h3>

        {cases.length === 0 ? (
          <div className="text-center py-8">
            <FolderOpen className="w-12 h-12 text-slate-600 mx-auto mb-3" />
            <p className="text-slate-400">No completed cases available for reporting</p>
            <p className="text-slate-500 text-sm mt-1">
              Complete a case analysis to generate reports
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            <div>
              <label className="block text-slate-400 text-sm mb-2">Select Case</label>
              <select
                value={selectedCase}
                onChange={(e) => setSelectedCase(e.target.value)}
                className="w-full bg-slate-800 text-white border border-slate-700 rounded-lg px-4 py-2.5 focus:outline-none focus:border-cyan-500"
              >
                <option value="">Choose a case...</option>
                {cases.map((c) => (
                  <option key={c.case_id} value={c.case_id}>
                    {c.case_name} ({c.evidence_count} evidence files)
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-slate-400 text-sm mb-2">Report Format</label>
              <div className="grid grid-cols-3 gap-3">
                {(['json', 'html', 'pdf'] as const).map((format) => (
                  <button
                    key={format}
                    onClick={() => setSelectedFormat(format)}
                    className={`
                      p-4 rounded-lg border transition-all flex flex-col items-center gap-2
                      ${selectedFormat === format
                        ? 'bg-cyan-500/10 border-cyan-500/50 text-cyan-400'
                        : 'bg-slate-800/50 border-slate-700 text-slate-400 hover:border-slate-600'
                      }
                    `}
                  >
                    {getFormatIcon(format)}
                    <span className="text-sm font-medium uppercase">{format}</span>
                  </button>
                ))}
              </div>
            </div>

            <button
              onClick={handleGenerateReport}
              disabled={!selectedCase || generating}
              className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {generating ? (
                <>
                  <Loader className="w-5 h-5 animate-spin" />
                  Generating Report...
                </>
              ) : (
                <>
                  <Download className="w-5 h-5" />
                  Generate Report
                </>
              )}
            </button>
          </div>
        )}
      </div>

      {/* Recent Reports */}
      {recentReports.length > 0 && (
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Clock className="w-5 h-5 text-cyan-400" />
            Recent Reports
          </h3>

          <div className="space-y-3">
            {recentReports.map((report, index) => (
              <div
                key={`${report.caseId}-${report.format}-${index}`}
                className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg"
              >
                <div className="flex items-center gap-3">
                  <div className={`
                    w-10 h-10 rounded-lg flex items-center justify-center
                    ${report.status === 'ready' ? 'bg-green-500/20 text-green-400' :
                      report.status === 'generating' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-red-500/20 text-red-400'
                    }
                  `}>
                    {getFormatIcon(report.format)}
                  </div>
                  <div>
                    <p className="text-white font-medium">{report.caseName}</p>
                    <p className="text-slate-500 text-sm">{report.format.toUpperCase()} Report</p>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  {report.status === 'generating' && (
                    <span className="flex items-center gap-2 text-yellow-400 text-sm">
                      <Loader className="w-4 h-4 animate-spin" />
                      Generating...
                    </span>
                  )}
                  {report.status === 'ready' && report.url && (
                    <a
                      href={report.url}
                      download
                      className="flex items-center gap-2 px-3 py-1.5 bg-green-500/20 text-green-400 rounded-lg hover:bg-green-500/30 transition-colors"
                    >
                      <Download className="w-4 h-4" />
                      Download
                    </a>
                  )}
                  {report.status === 'failed' && (
                    <span className="flex items-center gap-2 text-red-400 text-sm">
                      <AlertCircle className="w-4 h-4" />
                      Failed
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Report Info */}
      <div className="bg-slate-900/30 border border-slate-800/50 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Report Contents</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 bg-slate-800/30 rounded-lg">
            <h4 className="text-cyan-400 font-medium mb-2">Executive Summary</h4>
            <p className="text-slate-400 text-sm">
              High-level overview of security posture, key findings, and risk assessment
            </p>
          </div>
          <div className="p-4 bg-slate-800/30 rounded-lg">
            <h4 className="text-cyan-400 font-medium mb-2">Technical Analysis</h4>
            <p className="text-slate-400 text-sm">
              Detailed TLS/SSL analysis, certificate validation, and protocol findings
            </p>
          </div>
          <div className="p-4 bg-slate-800/30 rounded-lg">
            <h4 className="text-cyan-400 font-medium mb-2">Recommendations</h4>
            <p className="text-slate-400 text-sm">
              Actionable remediation steps prioritized by severity and impact
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
