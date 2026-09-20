/**
 * Cases Page - List and create forensic cases
 */
import { useState, useEffect } from 'react';
import { FolderOpen, Plus, Trash2, ChevronRight, FileSearch } from 'lucide-react';
import { api, ApiError } from '@/services/api';
import type { CaseWithEvidenceCount } from '@/types';
import { StatusBadge } from '@/components/StatusBadge';

interface CasesPageProps {
  onSelectCase: (caseId: string) => void;
}

export function CasesPage({ onSelectCase }: CasesPageProps) {
  const [cases, setCases] = useState<CaseWithEvidenceCount[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newCaseName, setNewCaseName] = useState('');
  const [newCaseDescription, setNewCaseDescription] = useState('');

  useEffect(() => {
    loadCases();
  }, []);

  const loadCases = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.listCases();
      setCases(response.cases);
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

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCaseName.trim()) return;

    setCreating(true);
    try {
      await api.createCase({
        case_name: newCaseName.trim(),
        description: newCaseDescription.trim() || undefined,
      });
      setNewCaseName('');
      setNewCaseDescription('');
      setShowCreateModal(false);
      await loadCases();
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to create case');
      }
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteCase = async (caseId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Delete this case and all associated evidence?')) return;

    try {
      await api.deleteCase(caseId);
      await loadCases();
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to delete case');
      }
    }
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
      case 'OPEN': return 'healthy';
      case 'PROCESSING': return 'loading';
      case 'COMPLETED': return 'healthy';
      case 'FAILED': return 'error';
      case 'PARTIAL': return 'degraded';
      case 'ARCHIVED': return 'unknown';
      default: return 'unknown';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FolderOpen className="w-8 h-8 text-blue-400" />
          <div>
            <h1 className="text-2xl font-bold text-white">Forensic Cases</h1>
            <p className="text-blue-200 text-sm">Manage PCAP analysis cases</p>
          </div>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors"
        >
          <Plus className="w-5 h-5" />
          New Case
        </button>
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

      {/* Cases List */}
      {loading ? (
        <div className="bg-white/10 rounded-lg p-8 text-center">
          <div className="animate-spin w-8 h-8 border-4 border-blue-400 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-blue-200">Loading cases...</p>
        </div>
      ) : cases.length === 0 ? (
        <div className="bg-white/10 rounded-lg p-12 text-center">
          <FileSearch className="w-16 h-16 text-blue-400 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-white mb-2">No Cases Yet</h3>
          <p className="text-blue-200 mb-6">Create your first forensic case to begin analyzing PCAP evidence.</p>
          <button
            onClick={() => setShowCreateModal(true)}
            className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg transition-colors"
          >
            Create First Case
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {cases.map((c) => (
            <div
              key={c.case_id}
              onClick={() => onSelectCase(c.case_id)}
              className="bg-white/10 hover:bg-white/20 rounded-lg p-4 cursor-pointer transition-colors group"
            >
              <div className="flex items-center justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3">
                    <h3 className="text-lg font-semibold text-white truncate">{c.case_name}</h3>
                    <StatusBadge status={getStatusColor(c.status) as 'healthy' | 'degraded' | 'unhealthy' | 'unknown' | 'loading' | 'error'} text={c.status} />
                  </div>
                  {c.description && (
                    <p className="text-blue-200 text-sm mt-1 truncate">{c.description}</p>
                  )}
                  <div className="flex items-center gap-4 mt-2 text-sm text-blue-300">
                    <span>ID: {c.case_id}</span>
                    <span>Evidence: {c.evidence_count}</span>
                    <span>Created: {formatDate(c.created_at)}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={(e) => handleDeleteCase(c.case_id, e)}
                    className="p-2 text-red-400 hover:bg-red-500/20 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity"
                    title="Delete case"
                  >
                    <Trash2 className="w-5 h-5" />
                  </button>
                  <ChevronRight className="w-5 h-5 text-blue-400" />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create Case Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-slate-800 rounded-lg p-6 w-full max-w-md mx-4">
            <h2 className="text-xl font-bold text-white mb-4">Create New Case</h2>
            <form onSubmit={handleCreateCase}>
              <div className="space-y-4">
                <div>
                  <label className="block text-blue-200 text-sm mb-1">Case Name *</label>
                  <input
                    type="text"
                    value={newCaseName}
                    onChange={(e) => setNewCaseName(e.target.value)}
                    className="w-full bg-slate-700 text-white border border-slate-600 rounded-lg px-3 py-2 focus:outline-none focus:border-blue-500"
                    placeholder="Enter case name"
                    required
                    autoFocus
                  />
                </div>
                <div>
                  <label className="block text-blue-200 text-sm mb-1">Description</label>
                  <textarea
                    value={newCaseDescription}
                    onChange={(e) => setNewCaseDescription(e.target.value)}
                    className="w-full bg-slate-700 text-white border border-slate-600 rounded-lg px-3 py-2 focus:outline-none focus:border-blue-500 h-24 resize-none"
                    placeholder="Optional description"
                  />
                </div>
              </div>
              <div className="flex gap-3 mt-6">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="flex-1 bg-slate-600 hover:bg-slate-500 text-white px-4 py-2 rounded-lg transition-colors"
                  disabled={creating}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
                  disabled={creating || !newCaseName.trim()}
                >
                  {creating ? 'Creating...' : 'Create Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
