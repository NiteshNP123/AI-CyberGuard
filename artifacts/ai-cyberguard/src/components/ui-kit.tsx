import { AlertTriangle, Check, ChevronRight, CircleHelp, Info, RefreshCw, ShieldAlert, ShieldCheck, X } from 'lucide-react';
import type { ReactNode } from 'react';

export function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="mb-7 flex flex-col justify-between gap-4 md:flex-row md:items-end"><div><div className="cg-kicker mb-2 flex items-center gap-2"><span className="h-1.5 w-1.5 rounded-full bg-primary" />{eyebrow}</div><h1 className="text-[27px] font-extrabold tracking-[-.045em] md:text-[32px]">{title}</h1><p className="mt-2 max-w-[620px] text-[13px] leading-relaxed text-muted-foreground">{description}</p></div>{action}</div>;
}

export function SeverityBadge({ severity }: { severity?: string }) {
  const value = severity || 'UNKNOWN'; const cls = value.toLowerCase();
  return <span data-testid={`status-severity-${cls}`} className={`inline-flex items-center gap-1.5 rounded-full px-2 py-1 text-[9px] font-extrabold uppercase tracking-[.08em] cg-severity-${cls}`}><span className="h-1.5 w-1.5 rounded-full bg-current" />{value}</span>;
}

export function StatusBadge({ status }: { status?: string }) {
  const value = status || 'UNKNOWN';
  return <span data-testid={`status-alert-${value.toLowerCase()}`} className={`rounded-full px-2 py-1 text-[9px] font-extrabold uppercase tracking-[.08em] cg-status-${value.toLowerCase()}`}>{value.replace('_', ' ')}</span>;
}

export function QueryError({ onRetry, label = 'We could not load this signal.' }: { onRetry?: () => void; label?: string }) {
  return <div className="cg-panel flex min-h-[180px] flex-col items-center justify-center p-7 text-center"><div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-destructive/10 text-destructive"><AlertTriangle size={19} /></div><div className="text-[13px] font-bold">{label}</div><p className="mt-1 text-[11px] text-muted-foreground">The rest of your workspace is still available.</p>{onRetry && <button data-testid="button-retry-query" onClick={onRetry} className="cg-btn cg-btn-quiet mt-4"><RefreshCw size={13} />Retry connection</button>}</div>;
}

export function EmptyState({ icon: Icon = CircleHelp, title, detail }: { icon?: typeof CircleHelp; title: string; detail: string }) {
  return <div className="flex min-h-[180px] flex-col items-center justify-center p-7 text-center"><div className="mb-3 flex h-11 w-11 items-center justify-center rounded-xl bg-muted text-muted-foreground"><Icon size={20} /></div><div className="text-[13px] font-bold">{title}</div><p className="mt-1 max-w-[320px] text-[11px] leading-relaxed text-muted-foreground">{detail}</p></div>;
}

export function SkeletonBlock({ className = '' }: { className?: string }) { return <div className={`cg-skeleton rounded-lg ${className}`} aria-label="Loading" />; }

export function ClassificationMark({ classification }: { classification: string }) {
  const safe = classification.toLowerCase(); const good = safe === 'safe'; const bad = safe === 'malicious';
  return <div className={`flex h-12 w-12 items-center justify-center rounded-2xl ${good ? 'bg-primary/12 text-primary' : bad ? 'bg-destructive/12 text-destructive' : 'bg-accent/18 text-[hsl(28_81%_44%)]'}`}>{good ? <ShieldCheck size={24} /> : bad ? <ShieldAlert size={24} /> : <AlertTriangle size={24} />}</div>;
}

export function CheckRow({ children, positive = true }: { children: ReactNode; positive?: boolean }) {
  return <div className="flex items-start gap-2 text-[12px] text-muted-foreground"><span className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full ${positive ? 'bg-primary/12 text-primary' : 'bg-destructive/12 text-destructive'}`}>{positive ? <Check size={10} /> : <X size={10} />}</span><span>{children}</span></div>;
}

export function MetricTooltip({ text }: { text: string }) { return <span title={text} className="inline-flex text-muted-foreground"><Info size={13} /></span>; }

export function formatTimestamp(timestamp?: string) {
  if (!timestamp) return '—';
  const date = new Date(timestamp); if (Number.isNaN(date.getTime())) return timestamp;
  return new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).format(date);
}

export function scoreTone(score: number) { return score >= 70 ? 'text-destructive' : score >= 40 ? 'text-[hsl(28_81%_44%)]' : 'text-primary'; }

export function scoreLabel(score: number) { return score >= 70 ? 'High risk' : score >= 40 ? 'Review needed' : 'Low risk'; }

export function MiniSparkline({ points, color = 'hsl(var(--primary))' }: { points: number[]; color?: string }) {
  if (!points.length) return <div className="h-12" />;
  const max = Math.max(...points, 1); const min = Math.min(...points); const range = Math.max(max - min, 1); const path = points.map((point, index) => `${index ? 'L' : 'M'} ${index * (100 / Math.max(points.length - 1, 1))} ${42 - ((point - min) / range) * 34}`).join(' ');
  return <svg viewBox="0 0 100 48" preserveAspectRatio="none" className="h-12 w-full overflow-visible"><path d={path} fill="none" stroke={color} strokeWidth="2.2" vectorEffect="non-scaling-stroke" strokeLinecap="round" /></svg>;
}