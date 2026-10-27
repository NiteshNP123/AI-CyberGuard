import { ArrowRight, Globe2, Link2, ScanSearch, ShieldCheck } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useAnalyzeUrl } from '@workspace/api-client-react';
import { AnalysisResultView } from '@/components/analysis-result';
import { EmptyState, PageHeader, QueryError, RevealSection, SkeletonBlock } from '@/components/ui-kit';

export default function UrlAnalyzer() {
  const [url, setUrl] = useState('');
  const analyze = useAnalyzeUrl();
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (url.trim().length >= 3) analyze.mutate({ data: { url: url.trim() } });
  };

  return (
    <div className="cg-page mx-auto max-w-[1120px]">
      <PageHeader
        eyebrow="Analysis lab · URL"
        title="Check before you click."
        description="Paste a link and CyberGuard will unpack the signals behind its risk posture — without visiting it in your browser."
      />
      <RevealSection>
        <div className="grid gap-6 lg:grid-cols-2 items-stretch">
          {/* Input panel */}
          <section className="cg-panel cg-grid-bg flex flex-col justify-between p-6 md:p-7">
            <div>
              <div
                className="flex h-11 w-11 items-center justify-center rounded-xl"
                style={{ background: 'rgba(139,134,92,.12)', color: 'var(--olive-text)', border: '1px solid rgba(139,134,92,.24)' }}
              >
                <Globe2 size={20} strokeWidth={1.6} />
              </div>
              <h2
                className="mt-5 text-[18px] font-medium tracking-[-.02em]"
                style={{ color: 'var(--text-primary)' }}
              >
                URL reputation check
              </h2>
              <p className="cg-prose mt-2 text-[12px] leading-relaxed">
                We look for impersonation, suspicious redirects, domain age patterns, and other defensive indicators.
              </p>

              <form onSubmit={submit} className="mt-6 space-y-3.5">
                <label htmlFor="url-input" className="cg-kicker block" style={{ color: 'var(--olive-text)' }}>URL to inspect</label>
                <div className="relative flex items-center">
                  <div className="cg-input-icon">
                    <Link2 size={16} />
                  </div>
                  <input
                    id="url-input"
                    data-testid="input-url-analysis"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="cg-input cg-input-with-icon"
                    placeholder="https://example.com/login"
                    type="url"
                  />
                </div>
                <button
                  data-testid="button-submit-url-analysis"
                  disabled={analyze.isPending || url.trim().length < 3}
                  className="cg-btn cg-btn-primary h-[42px] w-full disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {analyze.isPending ? (
                    <><ScanSearch size={14} className="animate-pulse" />Inspecting signals…</>
                  ) : (
                    <>Analyze URL <ArrowRight size={14} /></>
                  )}
                </button>
                {analyze.isError && (
                  <div
                    className="rounded-lg p-3 text-[11px]"
                    style={{
                      border: '1px solid rgba(192,57,43,.20)',
                      background: 'rgba(192,57,43,.06)',
                      color: 'var(--sev-critical)',
                    }}
                  >
                    We could not analyze that URL. Check the address and try again.
                  </div>
                )}
              </form>
            </div>

            <div className="mt-8" style={{ borderTop: '1px solid var(--border-warm)', paddingTop: '20px' }}>
              <div className="cg-kicker mb-3" style={{ color: 'var(--olive-text)' }}>Good to know</div>
              <div className="space-y-2.5">
                <div className="flex items-center gap-2.5 text-[12px]" style={{ color: 'var(--text-secondary)' }}>
                  <ShieldCheck size={14} className="shrink-0" style={{ color: 'var(--sev-low)' }} />
                  <span>No page content is loaded in your browser.</span>
                </div>
                <div className="flex items-center gap-2.5 text-[12px]" style={{ color: 'var(--text-secondary)' }}>
                  <ShieldCheck size={14} className="shrink-0" style={{ color: 'var(--sev-low)' }} />
                  <span>Results explain the evidence, not just a label.</span>
                </div>
              </div>
            </div>
          </section>

          {/* Result panel */}
          <section className="flex flex-col min-h-[480px]">
            {analyze.isPending ? (
              <div className="cg-panel h-full space-y-4 p-6">
                <SkeletonBlock className="h-14 w-48" />
                <SkeletonBlock className="h-24" />
                <SkeletonBlock className="h-24" />
                <SkeletonBlock className="h-36" />
              </div>
            ) : analyze.data ? (
              <AnalysisResultView result={analyze.data} />
            ) : analyze.isError ? (
              <QueryError label="Analysis service unavailable." />
            ) : (
              <div className="cg-panel flex h-full min-h-[480px] flex-col items-center justify-center p-8">
                <EmptyState
                  icon={ScanSearch}
                  title="Your result will land here"
                  detail="Enter a URL to see its classification, confidence, evidence, and recommended next step."
                />
              </div>
            )}
          </section>
        </div>
      </RevealSection>
    </div>
  );
}
