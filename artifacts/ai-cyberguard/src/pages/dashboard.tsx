import { ArrowDownRight, ArrowUpRight, ChevronRight, Clock3, ExternalLink, FileSearch, LockKeyhole, Radar, ShieldCheck, Siren } from 'lucide-react';
import { Link } from 'wouter';
import { getGetDashboardSummaryQueryKey, getGetRecentEventsQueryKey, getGetSettingsQueryKey, useGetDashboardSummary, useGetRecentEvents, useGetSettings, type DashboardSummary, type SecurityEvent } from '@workspace/api-client-react';
import { EmptyState, MetricTooltip, PageHeader, QueryError, SeverityBadge, SkeletonBlock, formatTimestamp, scoreTone } from '@/components/ui-kit';

const fallbackSummary: DashboardSummary = { securityScore: 0, threatLevel: 'LOW', critical: 0, high: 0, medium: 0, low: 0, totalScans: 0, scoreTrend: [], distribution: [] };

function ScoreRing({ score }: { score: number }) {
  return <div className="relative flex h-[148px] w-[148px] items-center justify-center rounded-full" style={{ background: `conic-gradient(hsl(var(--primary)) ${score * 3.6}deg, hsl(var(--muted)) 0deg)` }}><div className="flex h-[122px] w-[122px] flex-col items-center justify-center rounded-full bg-card"><span data-testid="value-security-score" className="cg-mono text-[38px] font-medium leading-none tracking-[-.1em]">{score}</span><span className="mt-2 text-[10px] font-bold uppercase tracking-[.12em] text-muted-foreground">security score</span></div></div>;
}

function TrendChart({ points }: { points: { label: string; value: number }[] }) {
  if (!points.length) return <EmptyState icon={Radar} title="Trend is gathering" detail="Score history will appear after your first few scans." />;
  const max = Math.max(...points.map((point) => point.value), 100); const min = Math.min(...points.map((point) => point.value), 0); const range = Math.max(max - min, 1);
  const path = points.map((point, index) => `${index ? 'L' : 'M'} ${index * (100 / Math.max(points.length - 1, 1))} ${88 - ((point.value - min) / range) * 70}`).join(' ');
  return <div className="px-2 pb-1 pt-5"><svg viewBox="0 0 100 100" preserveAspectRatio="none" className="h-[165px] w-full overflow-visible"><defs><linearGradient id="trend-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity=".2" /><stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity="0" /></linearGradient></defs><path d={`${path} L 100 100 L 0 100 Z`} fill="url(#trend-fill)" /><path d={path} fill="none" stroke="hsl(var(--primary))" strokeWidth="1.7" vectorEffect="non-scaling-stroke" strokeLinecap="round" /></svg><div className="mt-2 flex justify-between text-[9px] font-medium text-muted-foreground">{points.map((point) => <span key={point.label}>{point.label}</span>)}</div></div>;
}

function Distribution({ points }: { points: { label: string; value: number; color: string }[] }) {
  if (!points.length) return <EmptyState icon={Radar} title="No scan distribution" detail="Analyze a URL or message to start mapping your threat surface." />;
  const total = points.reduce((sum, point) => sum + point.value, 0) || 1; let offset = 0;
  const gradient = `conic-gradient(${points.map((point) => { const start = offset; offset += (point.value / total) * 100; return `${point.color} ${start}% ${offset}%`; }).join(', ')})`;
  return <div className="flex items-center gap-7 p-5"><div className="relative h-[142px] w-[142px] shrink-0 rounded-full" style={{ background: gradient }}><div className="absolute inset-[18px] flex flex-col items-center justify-center rounded-full bg-card"><span className="cg-mono text-2xl font-medium">{total}</span><span className="cg-kicker !text-[9px]">active alerts</span></div></div><div className="min-w-0 flex-1 space-y-3">{points.map((point) => <div key={point.label} className="flex items-center justify-between gap-3 text-[11px]"><div className="flex items-center gap-2 truncate"><span className="h-2 w-2 shrink-0 rounded-full" style={{ background: point.color }} />{point.label}</div><span className="cg-mono text-muted-foreground">{point.value}</span></div>)}</div></div>;
}

function EventRow({ event }: { event: SecurityEvent }) {
  return <div data-testid={`row-event-${event.id}`} className="group flex items-start gap-3 border-b border-border px-5 py-4 last:border-0"><div className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground"><Siren size={14} /></div><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><span className="truncate text-[12px] font-bold">{event.title}</span><SeverityBadge severity={event.severity} /></div><p className="cg-line-clamp mt-1 text-[11px] text-muted-foreground">{event.detail}</p><div className="mt-2 flex items-center gap-3 text-[9px] text-muted-foreground"><span>{event.source}</span><span className="h-1 w-1 rounded-full bg-border" /><span>{formatTimestamp(event.timestamp)}</span></div></div><div className={`cg-mono text-[11px] font-medium ${scoreTone(event.score)}`}>{event.score}</div></div>;
}

function getGreeting(firstName: string): string {
  const hour = new Date().getHours();
  if (hour < 12) return `Good morning, ${firstName}.`;
  if (hour < 17) return `Good afternoon, ${firstName}.`;
  return `Good evening, ${firstName}.`;
}

export default function Dashboard() {
  const summaryQuery = useGetDashboardSummary({ query: { queryKey: getGetDashboardSummaryQueryKey() } });
  const eventsQuery = useGetRecentEvents({ limit: 8 }, { query: { queryKey: getGetRecentEventsQueryKey({ limit: 8 }) } });
  const settingsQuery = useGetSettings({ query: { queryKey: getGetSettingsQueryKey() } });

  const summary = summaryQuery.data || fallbackSummary;
  const trend = summary.scoreTrend || [];
  const severityItems = [{ label: 'Critical', count: summary.critical, color: 'critical' }, { label: 'High', count: summary.high, color: 'high' }, { label: 'Medium', count: summary.medium, color: 'medium' }, { label: 'Low', count: summary.low, color: 'low' }];
  const delta = trend.length > 1 ? trend[trend.length - 1].value - trend[trend.length - 2].value : 0;

  // Derive first name from persisted settings
  const fullName = settingsQuery.data?.name ?? '';
  const firstName = fullName.split(' ')[0] || fullName || 'there';
  const greeting = getGreeting(firstName);

  return <div className="cg-page mx-auto max-w-[1420px]">
    <PageHeader eyebrow="Security posture · live" title={greeting} description="Your workspace is protected. Here is the signal that matters right now." action={<div className="flex gap-2"><Link href="/url-analyzer" data-testid="link-quick-url-analysis" className="cg-btn cg-btn-primary"><FileSearch size={14} />Scan a URL</Link><Link href="/message-analyzer" data-testid="link-quick-message-analysis" className="cg-btn cg-btn-quiet"><LockKeyhole size={14} />Inspect message</Link></div>} />
    {summaryQuery.isError ? <QueryError onRetry={() => summaryQuery.refetch()} label="Posture data is temporarily unavailable." /> : summaryQuery.isLoading ? <div className="grid gap-4 lg:grid-cols-[1.3fr_1fr]"><SkeletonBlock className="h-[222px]" /><SkeletonBlock className="h-[222px]" /></div> : <div className="grid gap-4 lg:grid-cols-[1.25fr_1fr]">
      <section className="cg-panel cg-grid-bg relative overflow-hidden p-5 md:p-6"><div className="flex items-start justify-between"><div><div className="cg-kicker">Workspace health</div><div className="mt-2 flex items-center gap-2 text-[12px] font-bold text-primary"><span className="cg-alert-dot" />Protected and monitoring</div></div><ShieldCheck className="text-primary" size={19} /></div><div className="mt-4 flex items-center gap-6"><ScoreRing score={summary.securityScore} /><div className="space-y-3"><div><div className="flex items-center gap-1 text-[10px] text-muted-foreground">Threat level <MetricTooltip text="Highest active severity across your workspace" /></div><div data-testid="status-threat-level" className="mt-1 text-[20px] font-extrabold tracking-[-.04em]">{summary.threatLevel || 'LOW'}</div></div><div className="flex items-center gap-2 text-[10px] text-muted-foreground">{delta >= 0 ? <ArrowUpRight size={13} className="text-primary" /> : <ArrowDownRight size={13} className="text-destructive" />} {Math.abs(delta)} pts this period</div></div></div><div className="mt-4 border-t border-border pt-3 text-[10px] text-muted-foreground">Signals are weighted by recency, confidence, and impact.</div></section>
      <section className="cg-panel p-5"><div className="flex items-center justify-between"><div className="cg-kicker">Active findings</div><Link href="/alerts" data-testid="link-view-active-alerts" className="text-[10px] font-bold text-primary">View alerts <ChevronRight className="inline" size={12} /></Link></div><div className="mt-5 grid grid-cols-2 gap-x-4 gap-y-5">{severityItems.map((item) => <div key={item.label}><div className="flex items-center gap-2 text-[10px] text-muted-foreground"><span className={`h-1.5 w-1.5 rounded-full cg-severity-${item.color}`} />{item.label}</div><div data-testid={`value-active-${item.label.toLowerCase()}`} className="cg-mono mt-1 text-[24px]">{item.count}</div></div>)}</div><div className="mt-5 border-t border-border pt-4"><div className="flex justify-between text-[10px] text-muted-foreground"><span>Total scanned</span><span className="cg-mono font-medium text-foreground">{summary.totalScans}</span></div></div></section>
    </div>}
    <div className="mt-4 grid gap-4 xl:grid-cols-[1.35fr_1fr]">
      <section className="cg-panel overflow-hidden"><div className="flex items-center justify-between border-b border-border px-5 py-4"><div><div className="cg-kicker">Posture trajectory</div><h2 className="mt-1 text-[14px] font-extrabold">Security score over time</h2></div><div className="flex items-center gap-2 text-[10px] text-muted-foreground"><span className="h-2 w-2 rounded-full bg-primary" />score</div></div><TrendChart points={trend} /></section>
      <section className="cg-panel overflow-hidden"><div className="border-b border-border px-5 py-4"><div className="cg-kicker">Threat distribution</div><h2 className="mt-1 text-[14px] font-extrabold">What you are seeing</h2></div><Distribution points={summary.distribution || []} /></section>
    </div>
    <section className="cg-panel mt-4 overflow-hidden"><div className="flex items-center justify-between border-b border-border px-5 py-4"><div><div className="cg-kicker">Event stream</div><h2 className="mt-1 text-[14px] font-extrabold">Recent security events</h2></div><Link href="/alerts" data-testid="link-view-all-events" className="flex items-center gap-1 text-[10px] font-bold text-primary">View all <ExternalLink size={12} /></Link></div>{eventsQuery.isError ? <QueryError onRetry={() => eventsQuery.refetch()} /> : eventsQuery.isLoading ? <div className="space-y-3 p-5"><SkeletonBlock className="h-14" /><SkeletonBlock className="h-14" /><SkeletonBlock className="h-14" /></div> : eventsQuery.data?.length ? eventsQuery.data.map((event) => <EventRow key={event.id} event={event} />) : <EmptyState icon={Clock3} title="No events in the stream" detail="New scans and detections will land here as your workspace starts working." />}</section>
  </div>;
}