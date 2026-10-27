import { ArrowLeft, Radar } from 'lucide-react';
import { Link } from 'wouter';

export default function NotFound() {
  return (
    <div
      className="flex min-h-[70dvh] w-full flex-col items-center justify-center p-8 text-center"
    >
      {/* Large muted numeral */}
      <div
        className="cg-mono mb-4 select-none text-[96px] font-light leading-none tracking-[-.06em]"
        style={{ color: 'rgba(139,134,92,.12)' }}
        aria-hidden="true"
      >
        404
      </div>

      {/* Icon + heading */}
      <div className="mb-4 flex items-center gap-3">
        <div
          className="flex h-10 w-10 items-center justify-center rounded-full"
          style={{ background: 'rgba(216,115,85,.12)', color: 'var(--terracotta-text)' }}
        >
          <Radar size={18} strokeWidth={1.6} />
        </div>
        <div className="text-left">
          <div className="cg-kicker" style={{ color: 'var(--olive-text)' }}>Signal lost</div>
          <h1
            className="mt-0.5 text-[22px] font-medium tracking-[-.04em]"
            style={{ color: 'var(--text-primary)' }}
          >
            Page not found
          </h1>
        </div>
      </div>

      <p
        className="mb-7 max-w-[340px] text-[13px] leading-relaxed"
        style={{ color: 'var(--text-secondary)' }}
      >
        That route is outside the monitored surface. Return to the security console.
      </p>

      <Link
        href="/"
        data-testid="link-back-to-overview"
        className="cg-btn cg-btn-quiet"
      >
        <ArrowLeft size={13} />
        Back to overview
      </Link>
    </div>
  );
}
