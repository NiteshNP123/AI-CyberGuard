import {
  ArrowDownRight,
  ArrowUpRight,
  ChevronRight,
  Clock3,
  ExternalLink,
  FileSearch,
  LockKeyhole,
  Radar,
  ShieldCheck,
  Siren,
  Activity,
} from 'lucide-react';
import { Link } from 'wouter';
import {
  getGetDashboardSummaryQueryKey,
  getGetRecentEventsQueryKey,
  getGetSettingsQueryKey,
  useGetDashboardSummary,
  useGetRecentEvents,
  useGetSettings,
  type DashboardSummary,
  type SecurityEvent,
} from '@workspace/api-client-react';
import {
  EmptyState,
  MetricTooltip,
  PageHeader,
  QueryError,
  RevealSection,
  SectionRule,
  SeverityBadge,
  SkeletonBlock,
  formatTimestamp,
  scoreTone,
} from '@/components/ui-kit';
import { NetworkCanvas } from '@/components/network-canvas';

const fallbackSummary: DashboardSummary = {
  securityScore: 0,
  threatLevel: 'LOW',
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  totalScans: 0,
  scoreTrend: [],
  distribution: [],
};

/* ── Score Ring ──────────────────────────────────────────────────────────── */
function ScoreRing({ score }: { score: number }) {
  const deg = score * 3.6;
  // Color the arc for light background: green=healthy, olive=mid, terracotta=low
  const arcColor =
    score >= 70
      ? 'var(--sev-low)'
      : score >= 40
      ? 'var(--olive)'
      : 'var(--terracotta)';
  return (
    <div
      className="relative flex h-[132px] w-[132px] shrink-0 items-center justify-center rounded-full"
      style={{
        background: `conic-gradient(${arcColor} ${deg}deg, rgba(41,43,38,.08) 0deg)`,
      }}
    >
      <div
        className="flex h-[108px] w-[108px] flex-col items-center justify-center rounded-full"
        style={{ background: 'var(--surface)' }}
      >
        <span
          data-testid="value-security-score"
          className="cg-mono text-[36px] font-light leading-none tracking-[-.08em]"
          style={{ color: 'var(--text-primary)' }}
        >
          {score}
        </span>
        <span className="cg-kicker mt-1.5" style={{ fontSize: '8px', color: 'var(--olive-text)' }}>Score</span>
      </div>
    </div>
  );
}

/* ── Trend Chart ─────────────────────────────────────────────────────────── */
function TrendChart({ points }: { points: { label: string; value: number }[] }) {
  if (!points.length)
    return (
      <EmptyState
        icon={Radar}
        title="Trend is gathering"
        detail="Score history will appear after your first few scans."
      />
    );
  const max = Math.max(...points.map((p) => p.value), 100);
  const min = Math.min(...points.map((p) => p.value), 0);
  const range = Math.max(max - min, 1);
  const path = points
    .map(
      (p, i) =>
        `${i ? 'L' : 'M'} ${i * (100 / Math.max(points.length - 1, 1))} ${88 - ((p.value - min) / range) * 70}`
    )
    .join(' ');
  return (
    <div className="px-2 pb-2 pt-4">
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="h-[150px] w-full overflow-visible">
        <defs>
          <linearGradient id="trend-fill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="var(--sev-low)" stopOpacity=".18" />
            <stop offset="100%" stopColor="var(--sev-low)" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={`${path} L 100 100 L 0 100 Z`} fill="url(#trend-fill)" />
        <path
          d={path}
          fill="none"
          stroke="var(--sev-low)"
          strokeWidth="1.6"
          vectorEffect="non-scaling-stroke"
          strokeLinecap="round"
        />
      </svg>
      <div className="mt-2 flex justify-between text-[9px] font-medium" style={{ color: 'var(--cg-muted)' }}>
        {points.map((p) => (
          <span key={p.label}>{p.label}</span>
        ))}
      </div>
    </div>
  );
}

/* ── Distribution ────────────────────────────────────────────────────────── */
function Distribution({ points }: { points: { label: string; value: number; color: string }[] }) {
  if (!points.length)
    return (
      <EmptyState
        icon={Radar}
        title="No scan distribution"
        detail="Analyze a URL or message to start mapping your threat surface."
      />
    );
  const total = points.reduce((sum, p) => sum + p.value, 0) || 1;
  let offset = 0;
  const gradient = `conic-gradient(${points
    .map((p) => {
      const start = offset;
      offset += (p.value / total) * 100;
      return `${p.color} ${start}% ${offset}%`;
    })
    .join(', ')})`;
  return (
    <div className="flex items-center gap-6 p-5">
      <div
        className="relative h-[128px] w-[128px] shrink-0 rounded-full"
        style={{ background: gradient }}
      >
        <div
          className="absolute inset-[16px] flex flex-col items-center justify-center rounded-full"
          style={{ background: 'var(--surface)' }}
        >
          <span className="cg-mono text-[22px] font-light" style={{ color: 'var(--text-primary)' }}>
            {total}
          </span>
          <span className="cg-kicker" style={{ fontSize: '8px', color: 'var(--olive-text)' }}>alerts</span>
        </div>
      </div>
      <div className="min-w-0 flex-1 space-y-2.5">
        {points.map((p) => (
          <div key={p.label} className="flex items-center justify-between gap-3 text-[11px]">
            <div className="flex items-center gap-2 truncate" style={{ color: 'var(--text-secondary)' }}>
              <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: p.color }} />
              {p.label}
            </div>
            <span className="cg-mono" style={{ color: 'var(--cg-muted)' }}>{p.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Event Row ───────────────────────────────────────────────────────────── */
function EventRow({ event }: { event: SecurityEvent }) {
  return (
    <div
      data-testid={`row-event-${event.id}`}
      className="kage-row relative flex items-start gap-3 px-5 py-4"
      style={{ borderBottom: '1px solid var(--border-warm)' }}
    >
      <span className="kage-row-bar" />
      <div
        className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg"
        style={{ background: 'var(--surface-muted)', color: 'var(--olive-text)' }}
      >
        <Siren size={13} strokeWidth={1.5} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="truncate text-[12px] font-medium" style={{ color: 'var(--text-primary)' }}>
            {event.title}
          </span>
          <SeverityBadge severity={event.severity} />
        </div>
        <p className="cg-line-clamp mt-1 text-[11px]" style={{ color: 'var(--cg-muted)' }}>
          {event.detail}
        </p>
        <div className="mt-1.5 flex items-center gap-3 text-[9px]" style={{ color: 'var(--cg-muted)' }}>
          <span>{event.source}</span>
          <span className="h-1 w-1 rounded-full" style={{ background: 'var(--border-warm)' }} />
          <span>{formatTimestamp(event.timestamp)}</span>
        </div>
      </div>
      <div className={`cg-mono text-[11px] font-medium ${scoreTone(event.score)}`}>
        {event.score}
      </div>
    </div>
  );
}

/* ── Greeting ────────────────────────────────────────────────────────────── */
function getGreeting(firstName: string): string {
  const h = new Date().getHours();
  if (h < 12) return `Good morning, ${firstName}.`;
  if (h < 17) return `Good afternoon, ${firstName}.`;
  return `Good evening, ${firstName}.`;
}

/* ── Severity Metric Card ────────────────────────────────────────────────── */
function SeverityCard({
  label,
  count,
  accent,
}: {
  label: string;
  count: number;
  accent: string;
}) {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center gap-1.5 text-[9px] font-medium uppercase tracking-[.12em]" style={{ color: 'var(--cg-muted)' }}>
        <span className="h-1 w-1 rounded-full" style={{ background: accent }} />
        {label}
      </div>
      <div
        className="cg-mono text-[28px] font-light leading-none tracking-[-.04em]"
        style={{ color: 'var(--text-primary)' }}
      >
        {count}
      </div>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════════════════ */
export default function Dashboard() {
  const summaryQuery = useGetDashboardSummary({
    query: { queryKey: getGetDashboardSummaryQueryKey() },
  });
  const eventsQuery = useGetRecentEvents(
    { limit: 8 },
    { query: { queryKey: getGetRecentEventsQueryKey({ limit: 8 }) } }
  );
  const settingsQuery = useGetSettings({ query: { queryKey: getGetSettingsQueryKey() } });

  const summary = summaryQuery.data || fallbackSummary;
  const trend = summary.scoreTrend || [];
  const delta =
    trend.length > 1 ? trend[trend.length - 1].value - trend[trend.length - 2].value : 0;

  const fullName = settingsQuery.data?.name ?? '';
  const firstName = fullName.split(' ')[0] || fullName || 'there';
  const greeting = getGreeting(firstName);

  const threatColor =
    summary.threatLevel === 'CRITICAL'
      ? 'var(--sev-critical)'
      : summary.threatLevel === 'HIGH'
      ? 'var(--sev-high)'
      : summary.threatLevel === 'MEDIUM'
      ? 'var(--olive-text)'
      : 'var(--sev-low)';

  return (
    <div className="cg-page mx-auto max-w-[1420px]">
      <PageHeader
        eyebrow="Security posture · live"
        title={greeting}
        description="Your workspace is under active monitoring. Here is the signal that matters right now."
        action={
          <div className="flex gap-2">
            <Link
              href="/url-analyzer"
              data-testid="link-quick-url-analysis"
              className="cg-btn cg-btn-primary"
            >
              <FileSearch size={13} />
              Scan URL
            </Link>
            <Link
              href="/message-analyzer"
              data-testid="link-quick-message-analysis"
              className="cg-btn cg-btn-quiet"
            >
              <LockKeyhole size={13} />
              Inspect message
            </Link>
          </div>
        }
      />

      {/* ── Hero: posture + network canvas ─────────────────────────── */}
      <RevealSection>
        <div
          className="cg-panel relative mb-5 overflow-hidden"
          style={{ minHeight: '220px', background: 'var(--surface-soft)' }}
        >
          {/* Atmospheric canvas sits behind content */}
          <div className="pointer-events-none absolute inset-0 opacity-30" aria-hidden="true">
            <NetworkCanvas className="h-full w-full" />
          </div>

          {/* Three-part hierarchy: score ring, threat & severity metrics, quick actions */}
          <div className="relative z-10 grid gap-6 p-6 sm:p-7 md:grid-cols-[140px_1fr] lg:grid-cols-[150px_1fr_210px] items-center">
            {/* 1. Score ring */}
            <div className="flex justify-center md:justify-start">
              <ScoreRing score={summary.securityScore} />
            </div>

            {/* 2. Threat & severity metrics */}
            <div className="space-y-4">
              <div>
                <div className="cg-kicker mb-1" style={{ color: 'var(--olive-text)' }}>Threat Level</div>
                <div className="flex items-baseline gap-3">
                  <div
                    data-testid="status-threat-level"
                    className="kage-display text-[32px] md:text-[36px]"
                    style={{ color: threatColor, fontWeight: 500 }}
                  >
                    {summary.threatLevel || 'LOW'}
                  </div>
                  <div className="flex items-center gap-1.5 text-[11px]" style={{ color: 'var(--cg-muted)' }}>
                    {delta >= 0
                      ? <ArrowUpRight size={13} style={{ color: 'var(--sev-low)' }} />
                      : <ArrowDownRight size={13} style={{ color: 'var(--sev-critical)' }} />}
                    <span>{Math.abs(delta)} pts this period</span>
                    <MetricTooltip text="Score trend from the previous evaluation period" />
                  </div>
                </div>
              </div>

              {/* Severity counters */}
              <div
                className="grid grid-cols-2 gap-4 border-t pt-4 sm:grid-cols-4"
                style={{ borderColor: 'var(--border-warm)' }}
              >
                <SeverityCard label="Critical" count={summary.critical} accent="var(--sev-critical)" />
                <SeverityCard label="High"     count={summary.high}     accent="var(--sev-high)" />
                <SeverityCard label="Medium"   count={summary.medium}   accent="var(--sev-medium)" />
                <SeverityCard label="Low"      count={summary.low}      accent="var(--sev-low)" />
              </div>
            </div>

            {/* 3. Quick actions */}
            <div
              className="hidden flex-col gap-2.5 border-t pt-4 lg:flex lg:border-l lg:border-t-0 lg:pl-6 lg:pt-0"
              style={{ borderColor: 'var(--border-warm)' }}
            >
              <div className="cg-kicker mb-0.5" style={{ color: 'var(--olive-text)' }}>Quick Actions</div>
              {[
                { href: '/alerts',           label: 'View alert queue' },
                { href: '/url-analyzer',     label: 'URL analysis' },
                { href: '/message-analyzer', label: 'Message review' },
                { href: '/settings',         label: 'Sensor controls' },
              ].map(({ href, label }) => (
                <Link
                  key={href}
                  href={href}
                  className="group flex items-center justify-between text-[11px] py-1 transition-colors hover:text-[var(--text-primary)]"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  <span>{label}</span>
                  <ChevronRight size={11} className="transition-transform group-hover:translate-x-0.5" />
                </Link>
              ))}
            </div>
          </div>

          {/* Status bar */}
          <div
            className="relative z-10 flex flex-wrap items-center justify-between gap-y-2 px-6 py-2.5 text-[11px]"
            style={{
              borderTop: '1px solid var(--border-warm)',
              background: 'rgba(248,246,242,.60)',
              color: 'var(--cg-muted)',
            }}
          >
            <div className="flex items-center gap-2">
              <ShieldCheck size={13} style={{ color: 'var(--sev-low)' }} />
              <span style={{ color: 'var(--text-secondary)' }}>Protected and monitoring</span>
            </div>
            <div className="flex items-center gap-3 text-[10px]">
              <span className="flex items-center gap-1.5">
                <Activity size={11} style={{ color: 'var(--terracotta)' }} />
                <span>Weighted threat telemetry</span>
              </span>
              <span style={{ color: 'var(--border-warm)' }}>·</span>
              <span className="cg-mono">{summary.totalScans} total scans</span>
            </div>
          </div>
        </div>
      </RevealSection>

      {/* ── Trend + Distribution ────────────────────────────────────── */}
      {summaryQuery.isError ? (
        <QueryError onRetry={() => summaryQuery.refetch()} label="Posture data is temporarily unavailable." />
      ) : summaryQuery.isLoading ? (
        <div className="mb-5 grid gap-5 lg:grid-cols-2 xl:grid-cols-[1.35fr_1fr]">
          <section className="cg-panel p-5 space-y-4">
            <div className="flex justify-between items-center">
              <div className="space-y-1.5">
                <SkeletonBlock className="h-3 w-28" />
                <SkeletonBlock className="h-4 w-44" />
              </div>
              <SkeletonBlock className="h-3 w-12" />
            </div>
            <SkeletonBlock className="h-[140px] w-full" />
          </section>
          <section className="cg-panel p-5 space-y-4">
            <div className="space-y-1.5">
              <SkeletonBlock className="h-3 w-32" />
              <SkeletonBlock className="h-4 w-40" />
            </div>
            <div className="flex items-center gap-6 pt-2">
              <SkeletonBlock className="h-28 w-28 rounded-full shrink-0" />
              <div className="flex-1 space-y-3">
                <SkeletonBlock className="h-3 w-full" />
                <SkeletonBlock className="h-3 w-4/5" />
                <SkeletonBlock className="h-3 w-3/5" />
              </div>
            </div>
          </section>
        </div>
      ) : (
        <RevealSection delay={0.1}>
          <div className="mb-5 grid gap-5 lg:grid-cols-2 xl:grid-cols-[1.35fr_1fr]">
            <section className="cg-panel overflow-hidden">
              <div
                className="flex items-center justify-between px-5 py-4"
                style={{ borderBottom: '1px solid var(--border-warm)' }}
              >
                <div>
                  <div className="cg-kicker" style={{ color: 'var(--olive-text)' }}>Posture Trajectory</div>
                  <h2
                    className="mt-1 text-[14px] font-medium tracking-[-.02em]"
                    style={{ color: 'var(--text-primary)' }}
                  >
                    Security score over time
                  </h2>
                </div>
                <div className="flex items-center gap-1.5 text-[9px]" style={{ color: 'var(--cg-muted)' }}>
                  <span className="h-1.5 w-1.5 rounded-full" style={{ background: 'var(--sev-low)' }} />
                  score
                </div>
              </div>
              <TrendChart points={trend} />
            </section>

            <section className="cg-panel overflow-hidden">
              <div
                className="px-5 py-4"
                style={{ borderBottom: '1px solid var(--border-warm)' }}
              >
                <div className="cg-kicker" style={{ color: 'var(--olive-text)' }}>Threat Distribution</div>
                <h2
                  className="mt-1 text-[14px] font-medium tracking-[-.02em]"
                  style={{ color: 'var(--text-primary)' }}
                >
                  What you are seeing
                </h2>
              </div>
              <Distribution points={summary.distribution || []} />
            </section>
          </div>
        </RevealSection>
      )}

      {/* ── Recent events ───────────────────────────────────────────── */}
      <RevealSection delay={0.18}>
        <section className="cg-panel overflow-hidden">
          <div
            className="flex items-center justify-between px-5 py-4"
            style={{ borderBottom: '1px solid var(--border-warm)' }}
          >
            <div>
              <div className="cg-kicker" style={{ color: 'var(--olive-text)' }}>Event Stream</div>
              <h2
                className="mt-1 text-[14px] font-medium tracking-[-.02em]"
                style={{ color: 'var(--text-primary)' }}
              >
                Recent security events
              </h2>
            </div>
            <Link
              href="/alerts"
              data-testid="link-view-all-events"
              className="flex items-center gap-1 text-[10px] font-medium transition-colors hover:text-[var(--terracotta)]"
              style={{ color: 'var(--cg-muted)' }}
            >
              View all <ExternalLink size={11} />
            </Link>
          </div>
          {eventsQuery.isError ? (
            <QueryError onRetry={() => eventsQuery.refetch()} />
          ) : eventsQuery.isLoading ? (
            <div className="divide-y" style={{ borderColor: 'var(--border-warm)' }}>
              {[1, 2, 3].map((i) => (
                <div key={i} className="flex items-center gap-3 px-5 py-3.5">
                  <SkeletonBlock className="h-7 w-7 rounded-lg shrink-0" />
                  <div className="flex-1 space-y-1.5">
                    <SkeletonBlock className="h-3 w-1/3" />
                    <SkeletonBlock className="h-2.5 w-1/2" />
                  </div>
                  <SkeletonBlock className="h-4 w-12" />
                </div>
              ))}
            </div>
          ) : eventsQuery.data?.length ? (
            eventsQuery.data.map((event) => <EventRow key={event.id} event={event} />)
          ) : (
            <EmptyState
              icon={Clock3}
              title="No events in the stream"
              detail="New scans and detections will land here as your workspace starts working."
            />
          )}
        </section>
      </RevealSection>
    </div>
  );
}
