import {
  Archive,
  CheckCircle2,
  ChevronDown,
  Eye,
  Filter,
  RefreshCw,
  Search,
  ShieldAlert,
  Trash2,
  XCircle,
} from 'lucide-react';
import { useMemo, useState } from 'react';
import {
  getGetAlertsQueryKey,
  getGetDashboardSummaryQueryKey,
  useGetAlerts,
} from '@workspace/api-client-react';
import { useQueryClient } from '@tanstack/react-query';
import {
  EmptyState,
  PageHeader,
  QueryError,
  RevealSection,
  SeverityBadge,
  SkeletonBlock,
  StatusBadge,
  formatTimestamp,
  scoreTone,
} from '@/components/ui-kit';
import { useToast } from '@/hooks/use-toast';

export default function Alerts() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const alertsQuery = useGetAlerts({ query: { queryKey: getGetAlertsQueryKey() } });
  const [filter, setFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [bulkResolving, setBulkResolving] = useState(false);
  const [clearConfirmStep, setClearConfirmStep] = useState<'idle' | 'confirm'>('idle');
  const [clearing, setClearing] = useState(false);

  const alerts = useMemo(
    () =>
      (alertsQuery.data || []).filter(
        (alert) =>
          (filter === 'ALL' || alert.status === filter) &&
          `${alert.title} ${alert.source} ${alert.description}`
            .toLowerCase()
            .includes(search.toLowerCase())
      ),
    [alertsQuery.data, filter, search]
  );

  const activeCount = useMemo(
    () =>
      (alertsQuery.data || []).filter((a) => a.status === 'NEW' || a.status === 'INVESTIGATING')
        .length,
    [alertsQuery.data]
  );

  const handleUpdateStatus = async (
    alertId: string,
    newStatus: 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE'
  ) => {
    try {
      setUpdatingId(alertId);
      const res = await fetch(`/api/alerts/${alertId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        toast({ title: 'Alert Status Updated', description: `Alert marked as ${newStatus.replace('_', ' ')}.` });
        queryClient.invalidateQueries({ queryKey: getGetAlertsQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetDashboardSummaryQueryKey() });
      }
    } catch {
      toast({ title: 'Update Failed', description: 'Could not update alert status.', variant: 'destructive' });
    } finally {
      setUpdatingId(null);
    }
  };

  const handleBulkResolve = async () => {
    try {
      setBulkResolving(true);
      const res = await fetch('/api/alerts/bulk-resolve', {
        method: 'POST',
        headers: { 'X-Workspace-Token': import.meta.env.VITE_WORKSPACE_TOKEN || '' },
      });
      const data = await res.json();
      if (res.ok) {
        toast({ title: 'Queue Resolved', description: data.message || `${data.resolved} alerts marked as RESOLVED.` });
        queryClient.invalidateQueries({ queryKey: getGetAlertsQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetDashboardSummaryQueryKey() });
      } else {
        throw new Error(data.error || 'Unknown error');
      }
    } catch (e: any) {
      toast({ title: 'Bulk Resolve Failed', description: e.message, variant: 'destructive' });
    } finally {
      setBulkResolving(false);
    }
  };

  const handleClearAll = async () => {
    if (clearConfirmStep === 'idle') {
      setClearConfirmStep('confirm');
      return;
    }
    try {
      setClearing(true);
      const res = await fetch('/api/alerts', {
        method: 'DELETE',
        headers: {
          'X-Confirm-Clear': 'yes-delete-all',
          'X-Workspace-Token': import.meta.env.VITE_WORKSPACE_TOKEN || '',
        },
      });
      const data = await res.json();
      if (res.ok) {
        toast({ title: 'Alert Queue Cleared', description: data.message || `${data.deleted} alerts permanently deleted.` });
        queryClient.invalidateQueries({ queryKey: getGetAlertsQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetDashboardSummaryQueryKey() });
        setClearConfirmStep('idle');
      } else {
        throw new Error(data.error || 'Unknown error');
      }
    } catch (e: any) {
      toast({ title: 'Clear Failed', description: e.message, variant: 'destructive' });
    } finally {
      setClearing(false);
    }
  };

  return (
    <div className="cg-page mx-auto max-w-[1220px]">
      <PageHeader
        eyebrow="Detection center · live"
        title="Alerts & Incident Queue"
        description="A real-time queue for security signals that need triage. Disposition decisions update workspace posture in real-time."
        action={
          <div className="flex flex-wrap items-center gap-2">
            {activeCount > 0 && (
              <button
                data-testid="button-bulk-resolve-alerts"
                onClick={handleBulkResolve}
                disabled={bulkResolving}
                className="cg-btn cg-btn-quiet disabled:opacity-60"
              >
                <CheckCircle2 size={13} className={bulkResolving ? 'animate-pulse' : ''} />
                {bulkResolving ? 'Resolving…' : `Resolve all (${activeCount})`}
              </button>
            )}
            <button
              data-testid="button-clear-all-alerts"
              onClick={handleClearAll}
              onBlur={() => { if (clearConfirmStep === 'confirm') setClearConfirmStep('idle'); }}
              disabled={clearing || (alertsQuery.data || []).length === 0}
              className={`cg-btn disabled:opacity-50 ${
                clearConfirmStep === 'confirm'
                  ? 'cg-btn-danger'
                  : 'cg-btn-quiet'
              }`}
            >
              <Trash2 size={13} className={clearing ? 'animate-pulse' : ''} />
              {clearing
                ? 'Clearing…'
                : clearConfirmStep === 'confirm'
                ? 'Tap again to confirm'
                : 'Clear all'}
            </button>
            <button
              data-testid="button-refresh-alerts"
              onClick={() => alertsQuery.refetch()}
              className="cg-btn cg-btn-quiet"
            >
              <RefreshCw size={13} className={alertsQuery.isFetching ? 'animate-spin' : ''} />
              Refresh
            </button>
          </div>
        }
      />

      <RevealSection>
        <section className="cg-panel overflow-hidden">
          {/* Filter bar */}
          <div
            className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between"
            style={{ borderBottom: '1px solid var(--border-warm)', background: 'var(--surface-soft)' }}
          >
            <div className="relative w-full max-w-[340px] flex items-center">
              <div className="cg-input-icon">
                <Search size={15} />
              </div>
              <input
                data-testid="input-search-alerts"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search alert title, source or evidence…"
                className="cg-input cg-input-with-icon h-[40px] text-[12px]"
              />
            </div>
            <div className="flex items-center gap-2.5">
              <span className="cg-kicker hidden text-[9px] sm:inline" style={{ color: 'var(--olive-text)' }}>Status</span>
              <div className="relative flex items-center">
                <select
                  data-testid="select-alert-status-filter"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  className="cg-input h-[40px] w-auto cursor-pointer pr-8 text-[12px]"
                  style={{ minWidth: '140px' }}
                >
                  <option value="ALL">All statuses</option>
                  <option value="NEW">New</option>
                  <option value="INVESTIGATING">Investigating</option>
                  <option value="RESOLVED">Resolved</option>
                  <option value="FALSE_POSITIVE">False positive</option>
                </select>
                <Filter size={13} className="pointer-events-none absolute right-3" style={{ color: 'var(--cg-muted)' }} />
              </div>
            </div>
          </div>

          {/* Alert list */}
          {alertsQuery.isError ? (
            <QueryError onRetry={() => alertsQuery.refetch()} label="Alert queue is temporarily unavailable." />
          ) : alertsQuery.isLoading ? (
            <div>
              {[1, 2, 3].map((i) => (
                <div key={i} className="flex items-center gap-4 px-5 py-4" style={{ borderBottom: '1px solid var(--border-warm)' }}>
                  <SkeletonBlock className="h-9 w-9 shrink-0 rounded-lg" />
                  <div className="flex-1 space-y-2">
                    <SkeletonBlock className="h-3.5 w-1/3" />
                    <SkeletonBlock className="h-2.5 w-1/4" />
                  </div>
                  <SkeletonBlock className="h-5 w-16 rounded-full" />
                </div>
              ))}
            </div>
          ) : alerts.length ? (
            <div>
              {alerts.map((alert) => {
                const isOpen = expanded === alert.id;
                return (
                  <div
                    data-testid={`row-alert-${alert.id}`}
                    key={alert.id}
                    className="kage-row relative"
                    style={{ borderBottom: '1px solid var(--border-warm)' }}
                  >
                    <span className="kage-row-bar" />
                    <button
                      data-testid={`button-expand-alert-${alert.id}`}
                      onClick={() => setExpanded(isOpen ? null : alert.id)}
                      className="cg-focus flex w-full items-center gap-3 px-5 py-4 text-left"
                    >
                      <div
                        className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg"
                        style={{ background: 'rgba(216,115,85,.10)', color: 'var(--terracotta-text)' }}
                      >
                        <ShieldAlert size={14} strokeWidth={1.8} />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className="truncate text-[12px] font-medium"
                            style={{ color: 'var(--text-primary)' }}
                          >
                            {alert.title}
                          </span>
                          <SeverityBadge severity={alert.severity} />
                        </div>
                        <div
                          className="mt-1 flex flex-wrap items-center gap-2 text-[10px]"
                          style={{ color: 'var(--cg-muted)' }}
                        >
                          <span style={{ color: 'var(--text-secondary)' }}>{alert.source}</span>
                          <span className="h-1 w-1 rounded-full" style={{ background: 'var(--border-warm)' }} />
                          <span>{formatTimestamp(alert.timestamp)}</span>
                        </div>
                      </div>
                      <div className={`hidden cg-mono text-[12px] font-medium sm:block ${scoreTone(alert.score)}`}>
                        {alert.score}
                      </div>
                      <StatusBadge status={alert.status} />
                      <ChevronDown
                        size={14}
                        className={`shrink-0 transition-transform ${isOpen ? 'rotate-180' : ''}`}
                        style={{ color: 'var(--cg-muted)' }}
                      />
                    </button>

                    {isOpen && (
                      <div
                        className="ml-[59px] mr-5 space-y-3 py-4"
                        style={{ borderTop: '1px solid var(--border-warm)' }}
                      >
                        <p
                          data-testid={`text-alert-description-${alert.id}`}
                          className="max-w-[820px] text-[12px] leading-relaxed"
                          style={{ color: 'var(--text-secondary)' }}
                        >
                          {alert.description}
                        </p>
                        <div className="flex flex-wrap items-center gap-2 pt-1">
                          <span
                            className="cg-kicker mr-2"
                            style={{ fontSize: '9px', color: 'var(--olive-text)' }}
                          >
                            Triage:
                          </span>
                          {alert.status !== 'INVESTIGATING' && (
                            <button
                              disabled={updatingId === alert.id}
                              onClick={() => handleUpdateStatus(alert.id, 'INVESTIGATING')}
                              className="cg-btn cg-btn-quiet !py-1 !px-2.5 !text-[10px]"
                            >
                              <Eye size={11} /> Investigate
                            </button>
                          )}
                          {alert.status !== 'RESOLVED' && (
                            <button
                              disabled={updatingId === alert.id}
                              onClick={() => handleUpdateStatus(alert.id, 'RESOLVED')}
                              className="cg-btn cg-btn-primary !py-1 !px-2.5 !text-[10px]"
                            >
                              <CheckCircle2 size={11} /> Mark Resolved
                            </button>
                          )}
                          {alert.status !== 'FALSE_POSITIVE' && (
                            <button
                              disabled={updatingId === alert.id}
                              onClick={() => handleUpdateStatus(alert.id, 'FALSE_POSITIVE')}
                              className="cg-btn cg-btn-quiet !py-1 !px-2.5 !text-[10px]"
                              style={{ color: 'var(--cg-muted)' }}
                            >
                              <XCircle size={11} /> False Positive
                            </button>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <EmptyState
              icon={Archive}
              title={search || filter !== 'ALL' ? 'No matching alerts' : 'Your queue is clear'}
              detail={
                search || filter !== 'ALL'
                  ? 'Try a different filter or search phrase.'
                  : 'New signals requiring attention will appear here automatically via live WebSocket telemetry.'
              }
            />
          )}
        </section>
      </RevealSection>
    </div>
  );
}
