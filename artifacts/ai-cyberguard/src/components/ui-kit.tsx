import { AlertTriangle, Check, ChevronRight, CircleHelp, Info, RefreshCw, ShieldAlert, ShieldCheck, X } from 'lucide-react';
import { type ReactNode, useEffect, useRef } from 'react';
import { motion, useReducedMotion, useInView } from 'framer-motion';

/* ─── PageHeader ──────────────────────────────────────────────────────────── */
export function PageHeader({
  eyebrow, title, description, action,
}: {
  eyebrow: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="mb-7 flex flex-col justify-between gap-4 md:flex-row md:items-end">
      <div>
        {/* Terracotta eyebrow dot */}
        <div className="cg-kicker mb-2.5 flex items-center gap-2.5">
          <span
            className="h-1.5 w-1.5 rounded-full"
            style={{ background: 'var(--terracotta)' }}
          />
          <span style={{ color: 'var(--olive-text)' }}>{eyebrow}</span>
        </div>
        <h1
          className="text-[26px] leading-tight tracking-[-0.03em] md:text-[32px]"
          style={{ fontWeight: 500, color: 'var(--text-primary)' }}
        >
          {title}
        </h1>
        <p
          className="mt-2 max-w-[620px] text-[13px] leading-relaxed"
          style={{ color: 'var(--text-secondary)', fontWeight: 400 }}
        >
          {description}
        </p>
      </div>
      {action && <div className="shrink-0 flex items-center gap-2.5">{action}</div>}
    </div>
  );
}

/* ─── RevealSection — staggered Framer Motion reveal ─────────────────────── */
export function RevealSection({
  children,
  delay = 0,
  className = '',
}: {
  children: ReactNode;
  delay?: number;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const prefersReduced = useReducedMotion();
  const inView = useInView(ref, { once: true, margin: '-60px' });

  return (
    <motion.div
      ref={ref}
      className={className}
      initial={prefersReduced ? {} : { opacity: 0, y: 22 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.85, ease: [0.16, 1, 0.3, 1], delay }}
    >
      {children}
    </motion.div>
  );
}

/* ─── SeverityBadge ───────────────────────────────────────────────────────── */
export function SeverityBadge({ severity }: { severity?: string }) {
  const value = severity || 'UNKNOWN';
  const cls = value.toLowerCase();
  return (
    <span
      data-testid={`status-severity-${cls}`}
      className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[9px] font-semibold uppercase tracking-[.10em] cg-severity-${cls}`}
    >
      <span className="h-1 w-1 rounded-full bg-current" />
      {value}
    </span>
  );
}

/* ─── StatusBadge ─────────────────────────────────────────────────────────── */
export function StatusBadge({ status }: { status?: string }) {
  const value = status || 'UNKNOWN';
  return (
    <span
      data-testid={`status-alert-${value.toLowerCase()}`}
      className={`rounded-full px-2 py-0.5 text-[9px] font-semibold uppercase tracking-[.10em] cg-status-${value.toLowerCase()}`}
    >
      {value.replace('_', ' ')}
    </span>
  );
}

/* ─── QueryError ──────────────────────────────────────────────────────────── */
export function QueryError({
  onRetry,
  label = 'We could not load this signal.',
}: {
  onRetry?: () => void;
  label?: string;
}) {
  return (
    <div
      className="cg-panel flex min-h-[180px] flex-col items-center justify-center p-8 text-center"
    >
      <div
        className="mb-3 flex h-10 w-10 items-center justify-center rounded-full"
        style={{ background: 'rgba(192,57,43,.10)', color: 'var(--sev-critical)' }}
      >
        <AlertTriangle size={18} />
      </div>
      <div className="text-[13px] font-medium" style={{ color: 'var(--text-primary)' }}>{label}</div>
      <p className="mt-1 text-[11px]" style={{ color: 'var(--text-secondary)' }}>
        The rest of your workspace is still available.
      </p>
      {onRetry && (
        <button
          data-testid="button-retry-query"
          onClick={onRetry}
          className="cg-btn cg-btn-quiet mt-5 text-[10px]"
        >
          <RefreshCw size={12} /> Retry connection
        </button>
      )}
    </div>
  );
}

/* ─── EmptyState ──────────────────────────────────────────────────────────── */
export function EmptyState({
  icon: Icon = CircleHelp,
  title,
  detail,
}: {
  icon?: typeof CircleHelp;
  title: string;
  detail: string;
}) {
  return (
    <div className="flex h-full w-full min-h-[220px] flex-col items-center justify-center p-8 text-center">
      <div
        className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl"
        style={{
          background: 'var(--surface-muted)',
          border: '1px solid var(--border-warm)',
          color: 'var(--olive-text)',
        }}
      >
        <Icon size={20} strokeWidth={1.5} />
      </div>
      <div className="text-[14px] font-medium" style={{ color: 'var(--text-primary)' }}>{title}</div>
      <p
        className="mt-2 max-w-[340px] text-[12px] leading-relaxed"
        style={{ color: 'var(--text-secondary)' }}
      >
        {detail}
      </p>
    </div>
  );
}

/* ─── SkeletonBlock ───────────────────────────────────────────────────────── */
export function SkeletonBlock({ className = '' }: { className?: string }) {
  return <div className={`cg-skeleton ${className}`} aria-label="Loading content" />;
}

/* ─── ClassificationMark ──────────────────────────────────────────────────── */
export function ClassificationMark({ classification }: { classification: string }) {
  const safe = classification.toLowerCase();
  const good = safe === 'safe';
  const bad  = safe === 'malicious';
  return (
    <div
      className="flex h-12 w-12 items-center justify-center rounded-2xl"
      style={{
        background: good
          ? 'rgba(58,125,68,.10)'
          : bad
          ? 'rgba(192,57,43,.10)'
          : 'rgba(139,134,92,.12)',
        color: good ? 'var(--sev-low)' : bad ? 'var(--sev-critical)' : 'var(--olive-text)',
      }}
    >
      {good ? <ShieldCheck size={22} /> : bad ? <ShieldAlert size={22} /> : <AlertTriangle size={22} />}
    </div>
  );
}

/* ─── CheckRow ────────────────────────────────────────────────────────────── */
export function CheckRow({
  children,
  positive = true,
}: {
  children: ReactNode;
  positive?: boolean;
}) {
  return (
    <div className="flex items-start gap-2 text-[12px]" style={{ color: 'var(--text-secondary)' }}>
      <span
        className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full"
        style={{
          background: positive ? 'rgba(58,125,68,.10)' : 'rgba(192,57,43,.10)',
          color: positive ? 'var(--sev-low)' : 'var(--sev-critical)',
        }}
      >
        {positive ? <Check size={9} /> : <X size={9} />}
      </span>
      <span>{children}</span>
    </div>
  );
}

/* ─── MetricTooltip ───────────────────────────────────────────────────────── */
export function MetricTooltip({ text }: { text: string }) {
  return (
    <span title={text} className="inline-flex" style={{ color: 'var(--cg-muted)' }}>
      <Info size={12} />
    </span>
  );
}

/* ─── SectionRule — eyebrow + horizontal rule ─────────────────────────────── */
export function SectionRule({ label, action }: { label: string; action?: ReactNode }) {
  return (
    <div className="mb-5 flex items-center gap-3">
      <span className="cg-kicker" style={{ color: 'var(--olive-text)' }}>{label}</span>
      <div className="kage-rule" />
      {action}
    </div>
  );
}

/* ─── Timestamp ───────────────────────────────────────────────────────────── */
export function formatTimestamp(timestamp?: string) {
  if (!timestamp) return '—';
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return timestamp;
  return new Intl.DateTimeFormat('en', {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(date);
}

/* ─── Score tone helpers ──────────────────────────────────────────────────── */
export function scoreTone(score: number) {
  return score >= 70
    ? 'text-[var(--sev-critical)]'
    : score >= 40
    ? 'text-[var(--olive-text)]'
    : 'text-[var(--sev-low)]';
}

export function scoreLabel(score: number) {
  return score >= 70 ? 'High risk' : score >= 40 ? 'Review needed' : 'Low risk';
}

/* ─── MiniSparkline ───────────────────────────────────────────────────────── */
export function MiniSparkline({
  points,
  color = 'var(--sev-low)',
}: {
  points: number[];
  color?: string;
}) {
  if (!points.length) return <div className="h-12" />;
  const max = Math.max(...points, 1);
  const min = Math.min(...points);
  const range = Math.max(max - min, 1);
  const path = points
    .map(
      (p, i) =>
        `${i ? 'L' : 'M'} ${i * (100 / Math.max(points.length - 1, 1))} ${42 - ((p - min) / range) * 34}`
    )
    .join(' ');
  return (
    <svg viewBox="0 0 100 48" preserveAspectRatio="none" className="h-12 w-full overflow-visible">
      <path d={path} fill="none" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke" strokeLinecap="round" />
    </svg>
  );
}
