import { ClipboardCheck, Copy, Lightbulb, Shield, Target } from 'lucide-react';
import { useState } from 'react';
import type { AnalysisResult } from '@workspace/api-client-react';
import {
  CheckRow,
  ClassificationMark,
  formatTimestamp,
  scoreLabel,
  scoreTone,
} from '@/components/ui-kit';

export function AnalysisResultView({ result }: { result: AnalysisResult }) {
  const [copied, setCopied] = useState(false);

  const copySummary = async () => {
    await navigator.clipboard?.writeText(
      `${result.classification}: ${result.summary}\nRecommendation: ${result.recommendation}`
    );
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div data-testid="panel-analysis-result" className="cg-page space-y-4">
      {/* Verdict header */}
      <section className="cg-panel overflow-hidden">
        <div
          className="flex flex-col gap-4 p-5 md:flex-row md:items-center md:justify-between md:p-6"
          style={{ borderBottom: '1px solid var(--border-warm)' }}
        >
          <div className="flex items-center gap-4">
            <ClassificationMark classification={result.classification} />
            <div>
              <div className="cg-kicker" style={{ color: 'var(--olive-text)' }}>Defensive verdict</div>
              <h2
                data-testid="text-analysis-classification"
                className="mt-1 text-[22px] font-medium tracking-[-.04em]"
                style={{ color: 'var(--text-primary)' }}
              >
                {result.classification}
              </h2>
              <p className="mt-0.5 text-[11px]" style={{ color: 'var(--cg-muted)' }}>
                Analyzed {formatTimestamp(result.analyzedAt)}
              </p>
            </div>
          </div>
          <button
            data-testid="button-copy-analysis"
            onClick={copySummary}
            className="cg-btn cg-btn-quiet self-start"
          >
            {copied ? <ClipboardCheck size={13} /> : <Copy size={13} />}
            {copied ? 'Copied' : 'Copy verdict'}
          </button>
        </div>

        <div className="grid gap-6 p-5 md:grid-cols-[180px_1fr] md:p-6">
          {/* Score */}
          <div>
            <div className="cg-kicker mb-2" style={{ color: 'var(--olive-text)' }}>Risk Score</div>
            <div
              className={`cg-mono text-[48px] font-light leading-none tracking-[-.08em] ${scoreTone(result.riskScore)}`}
            >
              <span data-testid="value-analysis-risk-score">{result.riskScore}</span>
              <span className="text-[18px]" style={{ color: 'var(--cg-muted)' }}>/100</span>
            </div>
            <div className={`mt-2 text-[11px] font-medium ${scoreTone(result.riskScore)}`}>
              {scoreLabel(result.riskScore)}
            </div>
          </div>

          {/* Confidence + Summary */}
          <div className="space-y-4">
            <div>
              <div
                className="mb-2 flex justify-between text-[10px] font-medium"
                style={{ color: 'var(--text-secondary)' }}
              >
                <span>Confidence</span>
                <span className="cg-mono" style={{ color: 'var(--cg-muted)' }}>
                  {result.confidence}%
                </span>
              </div>
              <div
                className="h-1.5 overflow-hidden rounded-full"
                style={{ background: 'var(--border-warm)' }}
              >
                <div
                  className="h-full rounded-full transition-all"
                  style={{
                    width: `${result.confidence}%`,
                    background: 'var(--sev-low)',
                  }}
                />
              </div>
            </div>
            <p
              data-testid="text-analysis-summary"
              className="text-[13px] leading-relaxed"
              style={{ color: 'var(--text-secondary)', fontWeight: 400 }}
            >
              {result.summary}
            </p>
          </div>
        </div>
      </section>

      {/* Evidence + Recommendation */}
      <div className="grid gap-4 lg:grid-cols-[1.05fr_.95fr]">
        <section className="cg-panel p-5 md:p-6">
          <div className="flex items-center gap-2.5">
            <Target size={15} style={{ color: 'var(--olive-text)' }} strokeWidth={1.6} />
            <div>
              <div className="cg-kicker" style={{ color: 'var(--olive-text)' }}>Evidence Map</div>
              <h3 className="mt-0.5 text-[13px] font-medium" style={{ color: 'var(--text-primary)' }}>
                Observed indicators
              </h3>
            </div>
          </div>
          <div className="mt-5 space-y-2.5">
            {result.indicators?.length ? (
              result.indicators.map((indicator, i) => (
                <CheckRow key={`${indicator}-${i}`} positive={result.classification === 'SAFE'}>
                  {indicator}
                </CheckRow>
              ))
            ) : (
              <div className="text-[12px]" style={{ color: 'var(--cg-muted)' }}>
                No direct indicators were returned.
              </div>
            )}
          </div>
        </section>

        <section className="cg-panel p-5 md:p-6">
          <div className="flex items-center gap-2.5">
            <Lightbulb size={15} style={{ color: 'var(--terracotta-text)' }} strokeWidth={1.6} />
            <div>
              <div className="cg-kicker" style={{ color: 'var(--olive-text)' }}>Next Best Action</div>
              <h3 className="mt-0.5 text-[13px] font-medium" style={{ color: 'var(--text-primary)' }}>
                Recommendation
              </h3>
            </div>
          </div>
          <p
            data-testid="text-analysis-recommendation"
            className="mt-5 text-[13px] leading-relaxed"
            style={{ color: 'var(--text-secondary)', fontWeight: 400 }}
          >
            {result.recommendation}
          </p>
        </section>
      </div>

      {/* Signal trace */}
      <section className="cg-panel overflow-hidden">
        <div
          className="flex items-center gap-2.5 px-5 py-4"
          style={{ borderBottom: '1px solid var(--border-warm)' }}
        >
          <Shield size={15} style={{ color: 'var(--sev-low)' }} strokeWidth={1.6} />
          <div>
            <div className="cg-kicker" style={{ color: 'var(--olive-text)' }}>Model Trace</div>
            <h3 className="mt-0.5 text-[13px] font-medium" style={{ color: 'var(--text-primary)' }}>
              Why this verdict was reached
            </h3>
          </div>
        </div>
        {result.signals?.length ? (
          <div>
            {result.signals.map((signal, i) => (
              <div
                data-testid={`row-analysis-signal-${i}`}
                key={`${signal.name}-${i}`}
                className="kage-row relative grid gap-2 px-5 py-4 md:grid-cols-[180px_1fr_56px] md:items-center"
                style={{ borderBottom: '1px solid var(--border-warm)' }}
              >
                <span className="kage-row-bar" />
                <div className="text-[12px] font-medium" style={{ color: 'var(--text-primary)' }}>
                  {signal.name}
                </div>
                <div className="text-[11px] leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                  {signal.detail}
                </div>
                <div
                  className="cg-mono text-right text-[11px]"
                  style={{ color: signal.weight > 0 ? 'var(--sev-critical)' : 'var(--cg-muted)' }}
                >
                  {signal.weight > 0 ? '+' : ''}{signal.weight}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-5 text-[12px]" style={{ color: 'var(--cg-muted)' }}>
            The analysis did not expose weighted signals.
          </div>
        )}
      </section>
    </div>
  );
}
