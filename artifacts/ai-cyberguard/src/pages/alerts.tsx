import { Archive, ChevronDown, CheckCircle2, Eye, Filter, RefreshCw, Search, ShieldAlert, XCircle } from 'lucide-react';
import { useMemo, useState } from 'react';
import { getGetAlertsQueryKey, getGetDashboardSummaryQueryKey, useGetAlerts } from '@workspace/api-client-react';
import { useQueryClient } from '@tanstack/react-query';
import { EmptyState, PageHeader, QueryError, SeverityBadge, SkeletonBlock, StatusBadge, formatTimestamp, scoreTone } from '@/components/ui-kit';
import { useToast } from '@/hooks/use-toast';

export default function Alerts() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const alertsQuery = useGetAlerts({ query: { queryKey: getGetAlertsQueryKey() } });
  const [filter, setFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  const alerts = useMemo(
    () =>
      (alertsQuery.data || []).filter(
        (alert) =>
          (filter === 'ALL' || alert.status === filter) &&
          `${alert.title} ${alert.source} ${alert.description}`.toLowerCase().includes(search.toLowerCase())
      ),
    [alertsQuery.data, filter, search]
  );

  const handleUpdateStatus = async (alertId: string, newStatus: 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE') => {
    try {
      setUpdatingId(alertId);
      const res = await fetch(`/api/alerts/${alertId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        toast({
          title: 'Alert Status Updated',
          description: `Alert marked as ${newStatus.replace('_', ' ')}.`,
        });
        queryClient.invalidateQueries({ queryKey: getGetAlertsQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetDashboardSummaryQueryKey() });
      }
    } catch (e) {
      toast({
        title: 'Update Failed',
        description: 'Could not update alert status.',
        variant: 'destructive',
      });
    } finally {
      setUpdatingId(null);
    }
  };

  return (
    <div className="cg-page mx-auto max-w-[1220px]">
      <PageHeader
        eyebrow="Detection center · live"
        title="Alerts & Incident Queue"
        description="A real-time queue for security signals that need triage. Disposition decisions update workspace posture in real-time."
        action={
          <button
            data-testid="button-refresh-alerts"
            onClick={() => alertsQuery.refetch()}
            className="cg-btn cg-btn-quiet"
          >
            <RefreshCw size={14} className={alertsQuery.isFetching ? 'animate-spin' : ''} />
            Refresh
          </button>
        }
      />
      <section className="cg-panel overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-border p-4 md:flex-row md:items-center md:justify-between">
          <div className="relative max-w-[330px] flex-1">
            <Search className="absolute left-3 top-3 text-muted-foreground" size={15} />
            <input
              data-testid="input-search-alerts"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search alert title, source or evidence"
              className="cg-input pl-9 text-[11px]"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter size={14} className="text-muted-foreground" />
            <select
              data-testid="select-alert-status-filter"
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              className="cg-input w-auto py-2 text-[11px]"
            >
              <option value="ALL">All statuses</option>
              <option value="NEW">New</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="RESOLVED">Resolved</option>
              <option value="FALSE_POSITIVE">False positive</option>
            </select>
          </div>
        </div>
        {alertsQuery.isError ? (
          <QueryError onRetry={() => alertsQuery.refetch()} label="Alert queue is temporarily unavailable." />
        ) : alertsQuery.isLoading ? (
          <div className="space-y-3 p-5">
            <SkeletonBlock className="h-16" />
            <SkeletonBlock className="h-16" />
            <SkeletonBlock className="h-16" />
          </div>
        ) : alerts.length ? (
          <div className="divide-y divide-border">
            {alerts.map((alert) => {
              const isOpen = expanded === alert.id;
              return (
                <div data-testid={`row-alert-${alert.id}`} key={alert.id} className="transition-colors hover:bg-muted/30">
                  <button
                    data-testid={`button-expand-alert-${alert.id}`}
                    onClick={() => setExpanded(isOpen ? null : alert.id)}
                    className="cg-focus flex w-full items-center gap-3 px-5 py-4 text-left"
                  >
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-destructive/8 text-destructive">
                      <ShieldAlert size={15} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="truncate text-[12px] font-bold">{alert.title}</span>
                        <SeverityBadge severity={alert.severity} />
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
                        <span className="font-semibold text-foreground/80">{alert.source}</span>
                        <span className="h-1 w-1 rounded-full bg-border" />
                        <span>{formatTimestamp(alert.timestamp)}</span>
                      </div>
                    </div>
                    <div className={`hidden cg-mono text-[12px] font-medium sm:block ${scoreTone(alert.score)}`}>
                      {alert.score}
                    </div>
                    <StatusBadge status={alert.status} />
                    <ChevronDown
                      size={15}
                      className={`shrink-0 text-muted-foreground transition-transform ${isOpen ? 'rotate-180' : ''}`}
                    />
                  </button>
                  {isOpen && (
                    <div className="ml-[59px] mr-5 border-t border-border py-4 space-y-3">
                      <p data-testid={`text-alert-description-${alert.id}`} className="max-w-[850px] text-[12px] leading-relaxed text-muted-foreground">
                        {alert.description}
                      </p>
                      <div className="flex flex-wrap items-center gap-2 pt-2">
                        <span className="text-[10px] font-bold text-muted-foreground uppercase mr-2">Triage Action:</span>
                        {alert.status !== 'INVESTIGATING' && (
                          <button
                            disabled={updatingId === alert.id}
                            onClick={() => handleUpdateStatus(alert.id, 'INVESTIGATING')}
                            className="cg-btn cg-btn-quiet !py-1 !px-2.5 !text-[10px]"
                          >
                            <Eye size={12} /> Investigate
                          </button>
                        )}
                        {alert.status !== 'RESOLVED' && (
                          <button
                            disabled={updatingId === alert.id}
                            onClick={() => handleUpdateStatus(alert.id, 'RESOLVED')}
                            className="cg-btn cg-btn-primary !py-1 !px-2.5 !text-[10px]"
                          >
                            <CheckCircle2 size={12} /> Mark Resolved
                          </button>
                        )}
                        {alert.status !== 'FALSE_POSITIVE' && (
                          <button
                            disabled={updatingId === alert.id}
                            onClick={() => handleUpdateStatus(alert.id, 'FALSE_POSITIVE')}
                            className="cg-btn cg-btn-quiet !py-1 !px-2.5 !text-[10px] text-muted-foreground hover:text-foreground"
                          >
                            <XCircle size={12} /> False Positive
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
    </div>
  );
}