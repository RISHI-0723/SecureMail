/**
 * Case Detail Page - View case details and upload evidence
 */
import { useState, useEffect, useRef, useCallback } from 'react';
import {
  ArrowLeft,
  Upload,
  FileText,
  Hash,
  HardDrive,
  Clock,
  CheckCircle,
  AlertCircle,
  Loader,
  Trash2,
  FileSearch,
} from 'lucide-react';
import { api, ApiError } from '@/services/api';
import type { CaseWithEvidenceCount, Evidence, UploadState } from '@/types';
import { StatusBadge } from '@/components/StatusBadge';

interface CaseDetailPageProps {
  caseId: string;
  onBack: () => void;
}

export function CaseDetailPage({ caseId, onBack }: CaseDetailPageProps) {
  const [caseData, setCaseData] = useState<CaseWithEvidenceCount | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploadState, setUploadState] = useState<UploadState>({ status: 'idle', progress: 0 });
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [caseResponse, evidenceResponse] = await Promise.all([
        api.getCase(caseId),
        api.listCaseEvidence(caseId),
      ]);
      setCaseData(caseResponse);
      setEvidence(evidenceResponse.evidence);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to load case data');
      }
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleUpload = async (file: File) => {
    setUploadState({ status: 'uploading', progress: 0 });
    setError(null);

    try {
      const result = await api.uploadEvidence(caseId, file);
      setUploadState({ status: 'success', progress: 100, result });
      await loadData();
    } catch (err) {
      let errorMessage = 'Upload failed';
      if (err instanceof ApiError) {
        errorMessage = err.message;
      }
      setUploadState({ status: 'error', progress: 0, error: errorMessage });
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      handleUpload(file);
    }
    // Reset input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    const file = e.dataTransfer.files?.[0];
    if (file) {
      handleUpload(file);
    }
  };

  const handleDeleteEvidence = async (evidenceId: string) => {
    if (!confirm('Delete this evidence file?')) return;

    try {
      await api.deleteEvidence(evidenceId);
      await loadData();
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to delete evidence');
      }
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'VALIDATED':
      case 'STORED':
        return 'healthy';
      case 'PENDING':
      case 'VALIDATING':
        return 'loading';
      case 'INVALID':
      case 'FAILED':
        return 'error';
      default:
        return 'unknown';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <Loader className="w-12 h-12 text-blue-400 animate-spin mx-auto mb-4" />
          <p className="text-blue-200">Loading case data...</p>
        </div>
      </div>
    );
  }

  if (!caseData) {
    return (
      <div className="bg-red-900/50 border border-red-500 rounded-lg p-8 text-center">
        <AlertCircle className="w-12 h-12 text-red-400 mx-auto mb-4" />
        <h2 className="text-xl font-semibold text-white mb-2">Case Not Found</h2>
        <p className="text-red-200 mb-4">{error || 'The requested case could not be found.'}</p>
        <button
          onClick={onBack}
          className="bg-slate-600 hover:bg-slate-500 text-white px-4 py-2 rounded-lg"
        >
          Back to Cases
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <button
          onClick={onBack}
          className="p-2 text-blue-300 hover:bg-white/10 rounded-lg transition-colors"
        >
          <ArrowLeft className="w-6 h-6" />
        </button>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-white">{caseData.case_name}</h1>
          {caseData.description && (
            <p className="text-blue-200 text-sm mt-1">{caseData.description}</p>
          )}
        </div>
        <StatusBadge
          status={caseData.status === 'OPEN' ? 'healthy' : caseData.status === 'PROCESSING' ? 'loading' : 'unknown'}
          text={caseData.status}
        />
      </div>

      {/* Case Info */}
      <div className="bg-white/10 rounded-lg p-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <span className="text-blue-300">Case ID</span>
            <p className="text-white font-mono">{caseData.case_id}</p>
          </div>
          <div>
            <span className="text-blue-300">Evidence Files</span>
            <p className="text-white">{caseData.evidence_count}</p>
          </div>
          <div>
            <span className="text-blue-300">Created</span>
            <p className="text-white">{formatDate(caseData.created_at)}</p>
          </div>
          <div>
            <span className="text-blue-300">Updated</span>
            <p className="text-white">{formatDate(caseData.updated_at)}</p>
          </div>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-900/50 border border-red-500 text-red-200 px-4 py-3 rounded-lg">
          {error}
          <button onClick={() => setError(null)} className="float-right text-red-400 hover:text-red-300">
            &times;
          </button>
        </div>
      )}

      {/* Upload Section */}
      <div className="bg-white/10 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Upload className="w-5 h-5 text-blue-400" />
          Upload Evidence
        </h2>

        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileSelect}
          accept=".pcap,.pcapng"
          className="hidden"
        />

        {uploadState.status === 'idle' && (
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors ${
              dragActive
                ? 'border-blue-400 bg-blue-500/20'
                : 'border-blue-400/50 hover:border-blue-400 hover:bg-white/5'
            }`}
          >
            <Upload className="w-12 h-12 text-blue-400 mx-auto mb-4" />
            <p className="text-white font-medium mb-2">
              Drag and drop a PCAP/PCAPNG file here
            </p>
            <p className="text-blue-200 text-sm">or click to select a file</p>
            <p className="text-blue-300 text-xs mt-4">
              Supported formats: .pcap, .pcapng
            </p>
          </div>
        )}

        {uploadState.status === 'uploading' && (
          <div className="border border-blue-400/50 rounded-lg p-8 text-center">
            <Loader className="w-12 h-12 text-blue-400 animate-spin mx-auto mb-4" />
            <p className="text-white font-medium mb-2">Uploading and validating...</p>
            <p className="text-blue-200 text-sm">Please wait while your file is processed</p>
          </div>
        )}

        {uploadState.status === 'success' && uploadState.result && (
          <div className="border border-green-400/50 bg-green-500/10 rounded-lg p-6">
            <div className="flex items-start gap-4">
              <CheckCircle className="w-8 h-8 text-green-400 flex-shrink-0" />
              <div className="flex-1">
                <h3 className="text-lg font-medium text-white mb-2">Upload Successful</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 text-blue-200">
                      <FileText className="w-4 h-4" />
                      <span className="font-mono">{uploadState.result.original_filename}</span>
                    </div>
                    <div className="flex items-center gap-2 text-blue-200">
                      <HardDrive className="w-4 h-4" />
                      <span>{formatFileSize(uploadState.result.file_size_bytes)}</span>
                      <span className="text-blue-400">({uploadState.result.file_format.toUpperCase()})</span>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-start gap-2 text-blue-200">
                      <Hash className="w-4 h-4 mt-0.5" />
                      <span className="font-mono text-xs break-all">{uploadState.result.sha256}</span>
                    </div>
                  </div>
                </div>
                <div className="mt-4 pt-4 border-t border-green-400/30">
                  <div className="flex items-center gap-4 text-sm">
                    <span className="text-blue-200">Evidence Status:</span>
                    <StatusBadge status="healthy" text={uploadState.result.evidence_status} />
                    <span className="text-blue-200 ml-4">Analysis:</span>
                    <StatusBadge status="loading" text={uploadState.result.analysis_status} />
                  </div>
                </div>
                <button
                  onClick={() => setUploadState({ status: 'idle', progress: 0 })}
                  className="mt-4 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm"
                >
                  Upload Another File
                </button>
              </div>
            </div>
          </div>
        )}

        {uploadState.status === 'error' && (
          <div className="border border-red-400/50 bg-red-500/10 rounded-lg p-6">
            <div className="flex items-start gap-4">
              <AlertCircle className="w-8 h-8 text-red-400 flex-shrink-0" />
              <div className="flex-1">
                <h3 className="text-lg font-medium text-white mb-2">Upload Failed</h3>
                <p className="text-red-200">{uploadState.error}</p>
                <button
                  onClick={() => setUploadState({ status: 'idle', progress: 0 })}
                  className="mt-4 bg-slate-600 hover:bg-slate-500 text-white px-4 py-2 rounded-lg text-sm"
                >
                  Try Again
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Evidence List */}
      <div className="bg-white/10 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <FileText className="w-5 h-5 text-blue-400" />
          Evidence Files ({evidence.length})
        </h2>

        {evidence.length === 0 ? (
          <div className="text-center py-8">
            <FileSearch className="w-12 h-12 text-blue-400/50 mx-auto mb-4" />
            <p className="text-blue-200">No evidence files uploaded yet</p>
            <p className="text-blue-300 text-sm mt-1">Upload a PCAP or PCAPNG file to begin analysis</p>
          </div>
        ) : (
          <div className="space-y-3">
            {evidence.map((ev) => (
              <div
                key={ev.evidence_id}
                className="bg-white/5 rounded-lg p-4 hover:bg-white/10 transition-colors group"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-2">
                      <FileText className="w-5 h-5 text-blue-400" />
                      <span className="text-white font-medium truncate">{ev.original_filename}</span>
                      <StatusBadge
                        status={getStatusColor(ev.status) as 'healthy' | 'loading' | 'error' | 'unknown'}
                        text={ev.status}
                      />
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm text-blue-200">
                      <div className="flex items-center gap-1">
                        <HardDrive className="w-3 h-3" />
                        <span>{formatFileSize(ev.file_size_bytes)}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <span className="text-blue-400">{ev.file_format.toUpperCase()}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        <span>{formatDate(ev.upload_timestamp)}</span>
                      </div>
                      <div className="flex items-center gap-1 font-mono text-xs">
                        <Hash className="w-3 h-3" />
                        <span title={ev.sha256}>{ev.sha256.substring(0, 16)}...</span>
                      </div>
                    </div>
                    {ev.error_message && (
                      <p className="text-red-300 text-sm mt-2">{ev.error_message}</p>
                    )}
                  </div>
                  <button
                    onClick={() => handleDeleteEvidence(ev.evidence_id)}
                    className="p-2 text-red-400 hover:bg-red-500/20 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity"
                    title="Delete evidence"
                  >
                    <Trash2 className="w-5 h-5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Phase 1 Note */}
      <div className="bg-amber-500/10 border border-amber-400/50 rounded-lg p-4">
        <p className="text-amber-200 text-sm">
          <strong>Phase 1 Note:</strong> Evidence is validated and stored. Full packet analysis
          (protocol detection, TLS inspection, certificate analysis) will be available in Phase 2.
        </p>
      </div>
    </div>
  );
}
