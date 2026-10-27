import {
  Activity,
  BellRing,
  Check,
  ChevronRight,
  FlaskConical,
  Loader2,
  LockKeyhole,
  Power,
  Save,
  SlidersHorizontal,
  UserRound,
} from 'lucide-react';
import { useState, useEffect, type FormEvent } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { getGetSettingsQueryKey, useGetSettings, useUpdateSettings } from '@workspace/api-client-react';
import { PageHeader, RevealSection, SectionRule } from '@/components/ui-kit';
import { useToast } from '@/hooks/use-toast';

/* ── Toggle ─────────────────────────────────────────────────────────────── */
function Toggle({
  label,
  detail,
  value,
  onChange,
  testId,
}: {
  label: string;
  detail: string;
  value: boolean;
  onChange: (v: boolean) => void;
  testId: string;
}) {
  return (
    <button
      data-testid={testId}
      type="button"
      onClick={() => onChange(!value)}
      className="cg-focus flex w-full items-center justify-between gap-4 py-4 text-left transition-colors hover:bg-[var(--surface-muted)]"
    >
      <div>
        <div className="text-[13px] font-medium" style={{ color: 'var(--text-primary)' }}>
          {label}
        </div>
        <div className="mt-1 text-[11px] leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
          {detail}
        </div>
      </div>
      <span
        className="relative h-[22px] w-[42px] shrink-0 rounded-full transition-colors duration-200"
        style={{
          background: value ? 'var(--terracotta)' : 'rgba(41,43,38,.14)',
          border: '1px solid var(--border-warm)',
        }}
      >
        <span
          className="absolute top-[1px] h-[18px] w-[18px] rounded-full shadow-sm transition-transform duration-200"
          style={{
            background: value ? '#fff' : 'rgba(41,43,38,.35)',
            transform: value ? 'translateX(21px)' : 'translateX(2px)',
          }}
        />
      </span>
    </button>
  );
}

/* ── Sensor status hook ──────────────────────────────────────────────────── */
interface SensorStatus {
  enabled: boolean;
  startedAt: string | null;
  stoppedAt: string | null;
  flowsIngested: number;
  message: string;
}

function useSensorStatus() {
  const [sensorStatus, setSensorStatus] = useState<SensorStatus | null>(null);
  const [sensorLoading, setSensorLoading] = useState(false);

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/network/sensor/status');
      if (res.ok) setSensorStatus(await res.json());
    } catch { /* silently ignore */ }
  };

  useEffect(() => { fetchStatus(); }, []);

  const startSensor = async (toast: ReturnType<typeof import('@/hooks/use-toast').useToast>['toast']) => {
    setSensorLoading(true);
    try {
      const res = await fetch('/api/network/sensor/start', { method: 'POST' });
      const data = await res.json();
      setSensorStatus((prev) => prev ? { ...prev, enabled: true, startedAt: data.startedAt, stoppedAt: null } : null);
      fetchStatus();
      toast({ title: 'Network Sensor Started', description: data.message });
    } catch {
      toast({ title: 'Error', description: 'Could not start the network sensor.', variant: 'destructive' });
    } finally {
      setSensorLoading(false);
    }
  };

  const stopSensor = async (toast: ReturnType<typeof import('@/hooks/use-toast').useToast>['toast']) => {
    setSensorLoading(true);
    try {
      const res = await fetch('/api/network/sensor/stop', { method: 'POST' });
      const data = await res.json();
      setSensorStatus((prev) => prev ? { ...prev, enabled: false, stoppedAt: data.stoppedAt } : null);
      fetchStatus();
      toast({ title: 'Network Sensor Stopped', description: data.message });
    } catch {
      toast({ title: 'Error', description: 'Could not stop the network sensor.', variant: 'destructive' });
    } finally {
      setSensorLoading(false);
    }
  };

  return { sensorStatus, sensorLoading, startSensor, stopSensor };
}

/* ── PortScan offline replay metrics ─────────────────────────────────────── */
function PortScanEvaluation() {
  return (
    <RevealSection delay={0.15}>
      <section
        className="cg-panel overflow-hidden"
        style={{ border: '1px solid rgba(139,134,92,.30)' }}
      >
        {/* Section header — OFFLINE REPLAY — EXPERIMENTAL EVALUATION label preserved */}
        <div
          className="flex items-center gap-3 px-5 py-4"
          style={{ borderBottom: '1px solid rgba(139,134,92,.18)', background: 'rgba(139,134,92,.05)' }}
        >
          <FlaskConical size={15} strokeWidth={1.6} style={{ color: 'var(--olive-text)' }} />
          <div className="flex-1">
            <div
              className="cg-kicker"
              style={{ color: 'var(--olive-text)', letterSpacing: '.24em', fontSize: '9px' }}
            >
              Offline Replay — Experimental Evaluation
            </div>
            <h2 className="mt-0.5 text-[13px] font-medium" style={{ color: 'var(--text-primary)' }}>
              Stateful PortScan Detector
            </h2>
          </div>
          <span
            className="rounded-full px-2.5 py-1 text-[9px] font-semibold uppercase tracking-[.12em]"
            style={{
              background: 'rgba(139,134,92,.10)',
              color: 'var(--olive-dark)',
              border: '1px solid rgba(139,134,92,.28)',
            }}
          >
            Prototype · Not Live
          </span>
        </div>

        {/* Metrics grid */}
        <div className="grid gap-px sm:grid-cols-2 lg:grid-cols-4" style={{ background: 'var(--border-warm)' }}>
          {[
            {
              label: 'Flows Replayed',
              value: '450,584',
              sub: 'Offline dataset',
            },
            {
              label: 'Scan Episodes Detected',
              value: '3',
              sub: 'of 3 expected',
            },
            {
              label: 'PortScan Flow Coverage',
              value: '99.68%',
              sub: '158,648 / 159,151 labelled flows',
            },
            {
              label: 'False-Alarm Episodes',
              value: '0',
              sub: 'Evaluated workstation hosts',
            },
          ].map(({ label, value, sub }) => (
            <div
              key={label}
              className="flex flex-col gap-1 px-5 py-5"
              style={{ background: 'var(--surface)' }}
            >
              <div className="cg-kicker" style={{ fontSize: '9px', color: 'var(--olive-text)' }}>{label}</div>
              <div
                className="kage-num text-[28px]"
                style={{ color: 'var(--text-primary)', lineHeight: 1 }}
              >
                {value}
              </div>
              <div className="text-[10px]" style={{ color: 'var(--text-secondary)' }}>{sub}</div>
            </div>
          ))}
        </div>

        {/* Previously missed probes */}
        <div
          className="flex items-center justify-between px-5 py-3.5"
          style={{ borderTop: '1px solid var(--border-warm)', background: 'rgba(139,134,92,.03)' }}
        >
          <span className="text-[11px]" style={{ color: 'var(--text-secondary)' }}>
            Previously missed probing flows covered
          </span>
          <span className="cg-mono text-[14px] font-medium" style={{ color: 'var(--olive-dark)' }}>
            39 / 39
          </span>
        </div>

        {/* Disclaimer */}
        <div
          className="px-5 py-4"
          style={{ borderTop: '1px solid var(--border-warm)' }}
        >
          <p className="text-[11px] leading-relaxed" style={{ color: 'var(--text-secondary)', maxWidth: '72ch' }}>
            The stateful PortScan detector is an isolated research prototype evaluated on a CICIDS2017 offline replay.
            It is <strong style={{ color: 'var(--text-primary)', fontWeight: 500 }}>not integrated into the live detection path</strong>.
            The existing API transition guard continues to handle incompatible stateful-v2 telemetry as unscored telemetry.
            Reported flow coverage is not classification accuracy.
          </p>
        </div>
      </section>
    </RevealSection>
  );
}

/* ── Settings ─────────────────────────────────────────────────────────────── */
const RETENTION_OPTIONS = ['7 days', '30 days', '90 days', '365 days'];

export default function Settings() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const settingsQuery = useGetSettings({ query: { queryKey: getGetSettingsQueryKey() } });
  const updateSettingsMutation = useUpdateSettings();
  const { sensorStatus, sensorLoading, startSensor, stopSensor } = useSensorStatus();

  const [name, setName] = useState('');
  const [workspace, setWorkspace] = useState('');
  const [email, setEmail] = useState('');
  const [notifications, setNotifications] = useState(true);
  const [digest, setDigest] = useState(false);
  const [dataRetention, setDataRetention] = useState('30 days');
  const [scanConfirmation, setScanConfirmation] = useState(true);
  const [saved, setSaved] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  useEffect(() => {
    if (settingsQuery.data) {
      setName(settingsQuery.data.name ?? '');
      setWorkspace(settingsQuery.data.workspaceName ?? '');
      setEmail(settingsQuery.data.notificationEmail ?? '');
      setNotifications(settingsQuery.data.criticalAlerts ?? true);
      setDigest(settingsQuery.data.weeklyDigest ?? false);
      setDataRetention(settingsQuery.data.dataRetention ?? '30 days');
      setScanConfirmation(settingsQuery.data.scanConfirmation ?? true);
    }
  }, [settingsQuery.data]);

  const cycleRetention = () => {
    const idx = RETENTION_OPTIONS.indexOf(dataRetention);
    setDataRetention(RETENTION_OPTIONS[(idx + 1) % RETENTION_OPTIONS.length]);
  };

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    try {
      await updateSettingsMutation.mutateAsync({
        data: {
          name,
          workspaceName: workspace,
          notificationEmail: email,
          criticalAlerts: notifications,
          weeklyDigest: digest,
          dataRetention,
          scanConfirmation,
        },
      });
      queryClient.invalidateQueries({ queryKey: getGetSettingsQueryKey() });
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2200);
      toast({ title: 'Settings saved', description: 'Workspace and account controls have been updated.' });
    } catch (err: any) {
      setSaveError(err?.message || 'Failed to save settings. Please try again.');
      toast({ title: 'Error saving settings', description: err?.message || 'Could not update workspace settings.', variant: 'destructive' });
    }
  };

  /* Section header helper */
  const SectionHead = ({ icon: Icon, kicker, title, iconBg, iconColor }: {
    icon: typeof Activity;
    kicker: string;
    title: string;
    iconBg: string;
    iconColor: string;
  }) => (
    <div
      className="flex items-center gap-3 px-6 py-4"
      style={{ borderBottom: '1px solid var(--border-warm)', background: 'var(--surface-soft)' }}
    >
      <div className="flex h-7 w-7 items-center justify-center rounded-lg" style={{ background: iconBg }}>
        <Icon size={15} strokeWidth={1.6} style={{ color: iconColor }} />
      </div>
      <div>
        <div className="cg-kicker" style={{ color: 'var(--olive-text)' }}>{kicker}</div>
        <h2 className="mt-0.5 text-[14px] font-medium" style={{ color: 'var(--text-primary)' }}>
          {title}
        </h2>
      </div>
    </div>
  );

  return (
    <div className="cg-page mx-auto max-w-[980px]">
      <PageHeader
        eyebrow="Workspace controls"
        title="Settings"
        description={`Tune how CyberGuard works for you and ${workspace || 'your workspace'}.`}
      />

      <form onSubmit={save} className="space-y-4">
        {saveError && (
          <div
            className="rounded-lg p-3 text-[11px]"
            style={{ border: '1px solid rgba(192,57,43,.20)', background: 'rgba(192,57,43,.06)', color: 'var(--sev-critical)' }}
          >
            {saveError}
          </div>
        )}

        {/* Identity */}
        <RevealSection>
          <section className="cg-panel overflow-hidden">
            <SectionHead
              icon={UserRound}
              kicker="Identity"
              title="Account and workspace"
              iconBg="rgba(139,134,92,.12)"
              iconColor="var(--olive-text)"
            />
            <div className="grid gap-5 p-6 md:grid-cols-2">
              <label className="space-y-2">
                <span className="cg-kicker block" style={{ color: 'var(--olive-text)' }}>Your name</span>
                <input
                  data-testid="input-account-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="cg-input"
                  placeholder="Analyst Name"
                />
              </label>
              <label className="space-y-2">
                <span className="cg-kicker block" style={{ color: 'var(--olive-text)' }}>Workspace name</span>
                <input
                  data-testid="input-workspace-name"
                  value={workspace}
                  onChange={(e) => setWorkspace(e.target.value)}
                  className="cg-input"
                  placeholder="SOC Workspace"
                />
              </label>
              <label className="space-y-2 md:col-span-2">
                <span className="cg-kicker block" style={{ color: 'var(--olive-text)' }}>Notification email</span>
                <input
                  data-testid="input-notification-email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="cg-input"
                  placeholder="analyst@company.com"
                />
              </label>
            </div>
          </section>
        </RevealSection>

        {/* Signal delivery */}
        <RevealSection delay={0.06}>
          <section className="cg-panel overflow-hidden px-6">
            <div
              className="-mx-6 flex items-center gap-3 px-6 py-4"
              style={{ borderBottom: '1px solid var(--border-warm)', background: 'var(--surface-soft)' }}
            >
              <div className="flex h-7 w-7 items-center justify-center rounded-lg" style={{ background: 'rgba(216,115,85,.12)' }}>
                <BellRing size={15} strokeWidth={1.6} style={{ color: 'var(--terracotta-text)' }} />
              </div>
              <div>
                <div className="cg-kicker" style={{ color: 'var(--olive-text)' }}>Signal delivery</div>
                <h2 className="mt-0.5 text-[14px] font-medium" style={{ color: 'var(--text-primary)' }}>
                  When CyberGuard should speak up
                </h2>
              </div>
            </div>
            <div style={{ borderBottom: '1px solid var(--border-warm)' }}>
              <Toggle
                label="Critical alert notifications"
                detail="Receive immediate notifications when a critical threat is confirmed."
                value={notifications}
                onChange={setNotifications}
                testId="button-toggle-critical-notifications"
              />
            </div>
            <Toggle
              label="Weekly posture digest"
              detail="A compact summary of score movement, scan totals, and unresolved signals."
              value={digest}
              onChange={setDigest}
              testId="button-toggle-weekly-digest"
            />
          </section>
        </RevealSection>

        {/* Analysis defaults */}
        <RevealSection delay={0.10}>
          <section className="cg-panel overflow-hidden">
            <SectionHead
              icon={SlidersHorizontal}
              kicker="Analysis defaults"
              title="Defensive preferences"
              iconBg="rgba(139,134,92,.12)"
              iconColor="var(--olive-text)"
            />
            <div>
              <button
                type="button"
                data-testid="button-preference-data-retention"
                onClick={cycleRetention}
                className="kage-row relative flex w-full items-center justify-between px-6 py-4 text-left"
                style={{ borderBottom: '1px solid var(--border-warm)' }}
              >
                <span className="kage-row-bar" />
                <div>
                  <div className="text-[13px] font-medium" style={{ color: 'var(--text-primary)' }}>
                    Analysis data retention
                  </div>
                  <div className="mt-1 text-[11px]" style={{ color: 'var(--text-secondary)' }}>
                    Keep results available for {dataRetention}
                  </div>
                </div>
                <div className="flex items-center gap-2 text-[12px] font-medium" style={{ color: 'var(--text-primary)' }}>
                  <span>{dataRetention}</span>
                  <ChevronRight size={14} style={{ color: 'var(--cg-muted)' }} />
                </div>
              </button>
              <button
                type="button"
                data-testid="button-preference-confirmation"
                onClick={() => setScanConfirmation(!scanConfirmation)}
                className="kage-row relative flex w-full items-center justify-between px-6 py-4 text-left"
              >
                <span className="kage-row-bar" />
                <div>
                  <div className="text-[13px] font-medium" style={{ color: 'var(--text-primary)' }}>
                    Scan confirmation
                  </div>
                  <div className="mt-1 text-[11px]" style={{ color: 'var(--text-secondary)' }}>
                    Ask before submitting external content for analysis
                  </div>
                </div>
                <div
                  className="flex items-center gap-2 text-[12px] font-medium"
                  style={{ color: scanConfirmation ? 'var(--sev-low)' : 'var(--cg-muted)' }}
                >
                  <span>{scanConfirmation ? 'On' : 'Off'}</span>
                  <ChevronRight size={14} style={{ color: 'var(--cg-muted)' }} />
                </div>
              </button>
            </div>
          </section>
        </RevealSection>

        {/* Save row */}
        <RevealSection delay={0.12}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-[11px]" style={{ color: 'var(--text-secondary)' }}>
              <LockKeyhole size={12} />
              Workspace controls are private to your account.
            </div>
            <button
              data-testid="button-save-settings"
              type="submit"
              disabled={updateSettingsMutation.isPending}
              className="cg-btn cg-btn-primary disabled:opacity-50"
            >
              {updateSettingsMutation.isPending
                ? <Loader2 size={13} className="animate-spin" />
                : saved
                ? <Check size={13} />
                : <Save size={13} />}
              {updateSettingsMutation.isPending ? 'Saving…' : saved ? 'Saved' : 'Save changes'}
            </button>
          </div>
        </RevealSection>
      </form>

      {/* Network Sensor */}
      <RevealSection delay={0.08} className="mt-5">
        <section className="cg-panel overflow-hidden">
          <div
            className="flex items-center gap-3 px-6 py-4"
            style={{ borderBottom: '1px solid var(--border-warm)', background: 'var(--surface-soft)' }}
          >
            <div className="flex h-7 w-7 items-center justify-center rounded-lg" style={{ background: 'rgba(58,125,68,.10)' }}>
              <Activity size={15} strokeWidth={1.6} style={{ color: 'var(--sev-low)' }} />
            </div>
            <div className="flex-1">
              <div className="cg-kicker" style={{ color: 'var(--olive-text)' }}>Network infrastructure</div>
              <h2 className="mt-0.5 text-[14px] font-medium" style={{ color: 'var(--text-primary)' }}>
                Live network sensor
              </h2>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`h-2 w-2 rounded-full ${sensorStatus?.enabled ? 'animate-pulse' : ''}`}
                style={{ background: sensorStatus?.enabled ? 'var(--sev-low)' : 'var(--cg-muted)' }}
              />
              <span
                className="cg-kicker text-[10px]"
                style={{ color: sensorStatus?.enabled ? 'var(--sev-low)' : 'var(--cg-muted)' }}
              >
                {sensorStatus === null ? 'Loading…' : sensorStatus.enabled ? 'ONLINE' : 'STOPPED'}
              </span>
            </div>
          </div>
          <div className="space-y-4 p-6">
            <p className="text-[12px] leading-relaxed" style={{ color: 'var(--text-secondary)', maxWidth: '720px' }}>
              The network sensor captures real TCP/UDP flow metadata from your authorized local interface and feeds it into the ML-based Network IDS pipeline. Stopping it prevents new telemetry from being ingested and halts new network-sourced alerts — existing alerts are not affected.
            </p>
            {sensorStatus && (
              <div className="grid gap-2 text-[11px] sm:grid-cols-2" style={{ color: 'var(--text-secondary)' }}>
                <div>
                  Flows ingested:{' '}
                  <span className="cg-mono font-medium" style={{ color: 'var(--text-primary)' }}>
                    {sensorStatus.flowsIngested.toLocaleString()}
                  </span>
                </div>
                {sensorStatus.startedAt && (
                  <div>
                    Started:{' '}
                    <span style={{ color: 'var(--text-primary)' }}>
                      {new Date(sensorStatus.startedAt).toLocaleTimeString()}
                    </span>
                  </div>
                )}
                {sensorStatus.stoppedAt && (
                  <div style={{ color: 'var(--sev-critical)' }}>
                    Stopped at:{' '}
                    <span>{new Date(sensorStatus.stoppedAt).toLocaleTimeString()}</span>
                  </div>
                )}
              </div>
            )}
            <div className="flex items-center gap-3 pt-1">
              <button
                data-testid="button-sensor-stop"
                type="button"
                onClick={() => stopSensor(toast)}
                disabled={sensorLoading || !sensorStatus?.enabled}
                className="cg-btn cg-btn-quiet h-[38px] disabled:opacity-50"
              >
                <Power size={13} />
                Stop sensor
              </button>
              <button
                data-testid="button-sensor-start"
                type="button"
                onClick={() => startSensor(toast)}
                disabled={sensorLoading || sensorStatus?.enabled === true}
                className="cg-btn cg-btn-primary h-[38px] disabled:opacity-50"
              >
                {sensorLoading ? <Loader2 size={13} className="animate-spin" /> : <Power size={13} />}
                Start sensor
              </button>
            </div>
          </div>
        </section>
      </RevealSection>

      {/* PortScan Offline Replay — Experimental */}
      <div className="mt-5">
        <PortScanEvaluation />
      </div>
    </div>
  );
}
