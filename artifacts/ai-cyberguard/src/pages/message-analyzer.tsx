import { ArrowRight, FileText, LockKeyhole, MessageSquareText, ScanSearch, ShieldCheck } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useAnalyzeMessage } from '@workspace/api-client-react';
import { AnalysisResultView } from '@/components/analysis-result';
import { EmptyState, PageHeader, QueryError, RevealSection, SkeletonBlock } from '@/components/ui-kit';

export default function MessageAnalyzer() {
  const [message, setMessage] = useState('');
  const analyze = useAnalyzeMessage();
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (message.trim().length >= 10) analyze.mutate({ data: { message: message.trim() } });
  };

  return (
    <div className="cg-page mx-auto max-w-[1120px]">
      <PageHeader
        eyebrow="Analysis lab · message"
        title="Read the pressure behind the words."
        description="Paste an email, SMS, or direct message. We will surface urgency, impersonation, payment pressure, and other fraud signals."
      />
      <RevealSection>
        <div className="grid gap-6 lg:grid-cols-2 items-stretch">
          {/* Input panel */}
          <section className="cg-panel flex flex-col justify-between p-6 md:p-7">
            <div>
              <div
                className="flex h-11 w-11 items-center justify-center rounded-xl"
                style={{ background: 'rgba(216,115,85,.12)', color: 'var(--terracotta-text)', border: '1px solid rgba(216,115,85,.24)' }}
              >
                <MessageSquareText size={20} strokeWidth={1.6} />
              </div>
              <h2
                className="mt-5 text-[18px] font-medium tracking-[-.02em]"
                style={{ color: 'var(--text-primary)' }}
              >
                Message risk review
              </h2>
              <p className="cg-prose mt-2 text-[12px] leading-relaxed">
                Keep the text intact for a stronger read. Remove private details if you do not want them analyzed.
              </p>

              <form onSubmit={submit} className="mt-6 space-y-3.5">
                <div className="flex items-center justify-between">
                  <label htmlFor="message-input" className="cg-kicker" style={{ color: 'var(--olive-text)' }}>Message text</label>
                  <span
                    data-testid="text-message-character-count"
                    className="cg-mono text-[10px]"
                    style={{ color: 'var(--cg-muted)' }}
                  >
                    {message.length} chars
                  </span>
                </div>
                <textarea
                  id="message-input"
                  data-testid="input-message-analysis"
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  className="cg-textarea min-h-[190px] resize-y"
                  placeholder="Paste the message, email, or SMS you want to inspect…"
                />
                <button
                  data-testid="button-submit-message-analysis"
                  disabled={analyze.isPending || message.trim().length < 10}
                  className="cg-btn cg-btn-primary h-[42px] w-full disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {analyze.isPending ? (
                    <><ScanSearch size={14} className="animate-pulse" />Reading signals…</>
                  ) : (
                    <>Analyze message <ArrowRight size={14} /></>
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
                    We could not analyze this message. Try again in a moment.
                  </div>
                )}
              </form>
            </div>

            <div className="mt-8 grid gap-3 sm:grid-cols-2" style={{ borderTop: '1px solid var(--border-warm)', paddingTop: '20px' }}>
              <div
                className="rounded-lg p-3.5"
                style={{ background: 'var(--surface-muted)', border: '1px solid var(--border-warm)' }}
              >
                <div className="flex items-center gap-2">
                  <FileText size={14} style={{ color: 'var(--olive-text)' }} />
                  <span className="text-[11px] font-medium" style={{ color: 'var(--text-primary)' }}>More context helps</span>
                </div>
                <p className="mt-1.5 text-[10px] leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                  Keep the sender, ask, and call to action intact.
                </p>
              </div>
              <div
                className="rounded-lg p-3.5"
                style={{ background: 'var(--surface-muted)', border: '1px solid var(--border-warm)' }}
              >
                <div className="flex items-center gap-2">
                  <LockKeyhole size={14} style={{ color: 'var(--olive-text)' }} />
                  <span className="text-[11px] font-medium" style={{ color: 'var(--text-primary)' }}>Defensive by design</span>
                </div>
                <p className="mt-1.5 text-[10px] leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                  Your text is analyzed only for threat detection.
                </p>
              </div>
            </div>
          </section>

          {/* Result panel */}
          <section className="flex flex-col min-h-[520px]">
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
              <div className="cg-panel flex h-full min-h-[520px] flex-col items-center justify-center p-8">
                <EmptyState
                  icon={ShieldCheck}
                  title="No message in review"
                  detail="Paste a message to reveal its risk signals and get a clear recommendation."
                />
              </div>
            )}
          </section>
        </div>
      </RevealSection>
    </div>
  );
}
