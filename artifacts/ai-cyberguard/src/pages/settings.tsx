import { Activity, BellRing, Check, ChevronRight, Loader2, LockKeyhole, Power, Save, SlidersHorizontal, UserRound } from 'lucide-react';
import { useState, useEffect, type FormEvent } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { getGetSettingsQueryKey, useGetSettings, useUpdateSettings } from '@workspace/api-client-react';
import { PageHeader } from '@/components/ui-kit';
import { useToast } from '@/hooks/use-toast';

function Toggle({ label, detail, value, onChange, testId }: { label: string; detail: string; value: boolean; onChange: (value: boolean) => void; testId: string }) {
  return (
    <button data-testid={testId} type="button" onClick={() => onChange(!value)} className="cg-focus flex w-full items-center justify-between gap-4 py-4 text-left">
      <div>
        <div className="text-[12px] font-bold">{label}</div>
        <div className="mt-1 text-[10px] leading-relaxed text-muted-foreground">{detail}</div>
      </div>
      <span className={`relative h-6 w-11 shrink-0 rounded-full transition-colors ${value ? 'bg-primary' : 'bg-muted'}`}>
        <span className={`absolute top-1 h-4 w-4 rounded-full bg-card shadow-sm transition-transform ${value ? 'translate-x-6' : 'translate-x-1'}`} />
      </span>
    </button>
  );
}

const RETENTION_OPTIONS = ['7 days', '30 days', '90 days', '365 days'];

// ---------------------------------------------------------------------------
// Sensor state hook — polls /api/network/sensor/status
// ---------------------------------------------------------------------------
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
      if (res.ok) {
        setSensorStatus(await res.json());
      }
    } catch { /* silently ignore */ }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const startSensor = async (toast: ReturnType<typeof import('@/hooks/use-toast').useToast>['toast']) => {
    setSensorLoading(true);
    try {
      const res = await fetch('/api/network/sensor/start', { method: 'POST' });
      const data = await res.json();
      setSensorStatus(prev => prev ? { ...prev, enabled: true, startedAt: data.startedAt, stoppedAt: null } : null);
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
      setSensorStatus(prev => prev ? { ...prev, enabled: false, stoppedAt: data.stoppedAt } : null);
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

  // Sync state from server when query loads or updates
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
    const currentIndex = RETENTION_OPTIONS.indexOf(dataRetention);
    const nextIndex = (currentIndex + 1) % RETENTION_OPTIONS.length;
    setDataRetention(RETENTION_OPTIONS[nextIndex]);
  };

  const toggleConfirmation = () => setScanConfirmation(!scanConfirmation);

  const save = async (event: FormEvent) => {
    event.preventDefault();
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
          scanConfirmation
        }
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

  return (
    <div className="cg-page mx-auto max-w-[980px]">
      <PageHeader
        eyebrow="Workspace controls"
        title="Settings"
        description={`Tune how CyberGuard works for you and ${workspace || 'your workspace'}.`}
      />

      <form onSubmit={save} className="space-y-4">
        {saveError && (
          <div className="rounded-lg border border-destructive/20 bg-destructive/10 p-3 text-[11px] text-destructive">
            {saveError}
          </div>
        )}

        {/* Identity */}
        <section className="cg-panel overflow-hidden">
          <div className="flex items-center gap-3 border-b border-border px-5 py-4">
            <UserRound size={16} className="text-primary" />
            <div>
              <div className="cg-kicker">Identity</div>
              <h2 className="mt-1 text-[14px] font-extrabold">Account and workspace</h2>
            </div>
          </div>
          <div className="grid gap-5 p-5 md:grid-cols-2 md:p-6">
            <label className="space-y-2">
              <span className="cg-kicker block">Your name</span>
              <input
                data-testid="input-account-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                className="cg-input"
              />
            </label>
            <label className="space-y-2">
              <span className="cg-kicker block">Workspace name</span>
              <input
                data-testid="input-workspace-name"
                value={workspace}
                onChange={(event) => setWorkspace(event.target.value)}
                className="cg-input"
              />
            </label>
            <label className="space-y-2 md:col-span-2">
              <span className="cg-kicker block">Notification email</span>
              <input
                data-testid="input-notification-email"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                className="cg-input"
              />
            </label>
          </div>
        </section>

        {/* Signal delivery */}
        <section className="cg-panel divide-y divide-border overflow-hidden px-5">
          <div className="flex items-center gap-3 py-4">
            <BellRing size={16} className="text-primary" />
            <div>
              <div className="cg-kicker">Signal delivery</div>
              <h2 className="mt-1 text-[14px] font-extrabold">When CyberGuard should speak up</h2>
            </div>
          </div>
          <Toggle
            label="Critical alert notifications"
            detail="Receive an email when a critical signal is detected."
            value={notifications}
            onChange={setNotifications}
            testId="button-toggle-critical-notifications"
          />
          <Toggle
            label="Weekly posture digest"
            detail="A compact summary of score movement and open alerts."
            value={digest}
            onChange={setDigest}
            testId="button-toggle-weekly-digest"
          />
        </section>

        {/* Analysis defaults */}
        <section className="cg-panel overflow-hidden">
          <div className="flex items-center gap-3 border-b border-border px-5 py-4">
            <SlidersHorizontal size={16} className="text-primary" />
            <div>
              <div className="cg-kicker">Analysis defaults</div>
              <h2 className="mt-1 text-[14px] font-extrabold">Defensive preferences</h2>
            </div>
          </div>
          <div className="divide-y divide-border">
            <button
              type="button"
              data-testid="button-preference-data-retention"
              onClick={cycleRetention}
              className="flex w-full items-center justify-between px-5 py-4 text-left hover:bg-muted/30"
            >
              <div>
                <div className="text-[12px] font-bold">Analysis data retention</div>
                <div className="mt-1 text-[10px] text-muted-foreground">Keep results available for {dataRetention}</div>
              </div>
              <div className="flex items-center gap-2 text-[11px] font-bold text-muted-foreground">
                {dataRetention}
                <ChevronRight size={14} />
              </div>
            </button>
            <button
              type="button"
              data-testid="button-preference-confirmation"
              onClick={toggleConfirmation}
              className="flex w-full items-center justify-between px-5 py-4 text-left hover:bg-muted/30"
            >
              <div>
                <div className="text-[12px] font-bold">Scan confirmation</div>
                <div className="mt-1 text-[10px] text-muted-foreground">Ask before submitting external content for analysis</div>
              </div>
              <div className={`flex items-center gap-2 text-[11px] font-bold ${scanConfirmation ? 'text-primary' : 'text-muted-foreground'}`}>
                {scanConfirmation ? 'On' : 'Off'}
                <ChevronRight size={14} />
              </div>
            </button>
          </div>
        </section>

        {/* Save row */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
            <LockKeyhole size={13} />
            Workspace controls are private to your account.
          </div>
          <button
            data-testid="button-save-settings"
            type="submit"
            disabled={updateSettingsMutation.isPending}
            className="cg-btn cg-btn-primary disabled:opacity-50"
          >
            {updateSettingsMutation.isPending ? (
              <Loader2 size={14} className="animate-spin" />
            ) : saved ? (
              <Check size={14} />
            ) : (
              <Save size={14} />
            )}
            {updateSettingsMutation.isPending ? 'Saving…' : saved ? 'Saved' : 'Save changes'}
          </button>
        </div>
      </form>

      {/* Network Sensor Control — separate from analysis preferences */}
      <section className="cg-panel mt-4 overflow-hidden">
        <div className="flex items-center gap-3 border-b border-border px-5 py-4">
          <Activity size={16} className="text-primary" />
          <div>
            <div className="cg-kicker">Network infrastructure</div>
            <h2 className="mt-1 text-[14px] font-extrabold">Live network sensor</h2>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${sensorStatus?.enabled ? 'bg-primary animate-pulse' : 'bg-muted-foreground'}`} />
            <span className={`text-[11px] font-bold ${sensorStatus?.enabled ? 'text-primary' : 'text-muted-foreground'}`}>
              {sensorStatus === null ? 'Loading…' : sensorStatus.enabled ? 'ONLINE' : 'STOPPED'}
            </span>
          </div>
        </div>
        <div className="p-5 space-y-4">
          <p className="text-[11px] leading-relaxed text-muted-foreground max-w-[720px]">
            The network sensor captures real TCP/UDP flow metadata from your authorized local interface and feeds it into the ML-based Network IDS pipeline. Stopping it prevents new telemetry from being ingested and halts new network-sourced alerts — existing alerts are not affected.
          </p>
          {sensorStatus && (
            <div className="grid gap-2 text-[10px] text-muted-foreground sm:grid-cols-2">
              <div>Flows ingested this session: <span className="cg-mono font-semibold text-foreground">{sensorStatus.flowsIngested.toLocaleString()}</span></div>
              {sensorStatus.startedAt && (
                <div>Started: <span className="font-semibold text-foreground">{new Date(sensorStatus.startedAt).toLocaleTimeString()}</span></div>
              )}
              {sensorStatus.stoppedAt && (
                <div className="text-destructive">Stopped at: <span className="font-semibold">{new Date(sensorStatus.stoppedAt).toLocaleTimeString()}</span></div>
              )}
            </div>
          )}
          <div className="flex gap-3 pt-1">
            <button
              data-testid="button-sensor-stop"
              type="button"
              onClick={() => stopSensor(toast)}
              disabled={sensorLoading || !sensorStatus?.enabled}
              className="cg-btn cg-btn-quiet !text-[11px] disabled:opacity-50"
            >
              <Power size={13} />
              Stop sensor
            </button>
            <button
              data-testid="button-sensor-start"
              type="button"
              onClick={() => startSensor(toast)}
              disabled={sensorLoading || sensorStatus?.enabled === true}
              className="cg-btn cg-btn-primary !text-[11px] disabled:opacity-50"
            >
              {sensorLoading ? <Loader2 size={13} className="animate-spin" /> : <Power size={13} />}
              Start sensor
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}