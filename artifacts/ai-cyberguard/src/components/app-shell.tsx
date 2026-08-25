import { Activity, Bell, FileSearch, LayoutDashboard, Menu, MessageSquareText, Settings, ShieldCheck, Wifi } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link, useLocation } from 'wouter';
import { getHealthCheckQueryKey, useHealthCheck, getGetAlertsQueryKey, useGetAlerts } from '@workspace/api-client-react';
import { useRealtimeSoc } from '@/hooks/use-realtime-soc';

const navItems = [
  { href: '/', label: 'Overview', icon: LayoutDashboard },
  { href: '/url-analyzer', label: 'URL analyzer', icon: FileSearch },
  { href: '/message-analyzer', label: 'Message analyzer', icon: MessageSquareText },
  { href: '/alerts', label: 'Alerts', icon: Bell },
  { href: '/settings', label: 'Settings', icon: Settings },
];

function NavItem({ href, label, icon: Icon, alertCount }: (typeof navItems)[number] & { alertCount?: number }) {
  const [location] = useLocation();
  const active = href === '/' ? location === '/' : location.startsWith(href);
  return (
    <Link href={href} data-testid={`link-nav-${label.toLowerCase().replaceAll(' ', '-')}`} className={`group flex items-center gap-3 rounded-lg border px-3 py-2.5 text-[12px] font-semibold transition-colors ${active ? 'cg-nav-active border-transparent' : 'border-transparent text-[hsl(var(--sidebar-foreground)/.65)] hover:border-[hsl(var(--sidebar-border))] hover:bg-[hsl(var(--sidebar-accent))] hover:text-[hsl(var(--sidebar-foreground))]'}`}>
      <Icon size={16} strokeWidth={active ? 2.5 : 1.8} />
      <span>{label}</span>
      {label === 'Alerts' && (alertCount ?? 0) > 0 && (
        <span className="ml-auto rounded-full bg-destructive px-1.5 py-0.5 text-[9px] font-extrabold text-destructive-foreground">
          {alertCount}
        </span>
      )}
    </Link>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const { connected } = useRealtimeSoc();
  const { data: health, isLoading: healthLoading } = useHealthCheck({ query: { queryKey: getHealthCheckQueryKey() } });
  const { data: alerts } = useGetAlerts({ query: { queryKey: getGetAlertsQueryKey() } });
  const activeAlertsCount = (alerts || []).filter((a) => a.status === 'NEW' || a.status === 'INVESTIGATING').length;
  return (
    <div className="flex min-h-[100dvh] bg-background text-foreground">
      <aside className="cg-desktop-nav fixed inset-y-0 left-0 z-20 flex w-[246px] flex-col border-r border-[hsl(var(--sidebar-border))] bg-sidebar text-sidebar-foreground">
        <div className="flex items-center gap-3 px-6 py-6">
          <div className="flex h-9 w-9 items-center justify-center rounded-[10px] bg-[hsl(var(--sidebar-primary))] text-[hsl(var(--sidebar-primary-foreground))]">
            <ShieldCheck size={20} strokeWidth={2.4} />
          </div>
          <div>
            <div className="text-[15px] font-extrabold tracking-[-.03em]">AI CyberGuard</div>
            <div className="cg-kicker !text-[hsl(var(--sidebar-foreground)/.42)]">defensive operations</div>
          </div>
        </div>
        <div className="px-4">
          <div className="mb-3 flex items-center gap-2 px-3"><span className="cg-kicker !text-[hsl(var(--sidebar-foreground)/.4)]">Workspace</span><span className="h-px flex-1 bg-[hsl(var(--sidebar-border))]" /></div>
          <div className="mb-5 flex items-center gap-3 rounded-lg border border-[hsl(var(--sidebar-border))] bg-[hsl(var(--sidebar-accent)/.5)] px-3 py-3">
            <div className="flex h-7 w-7 items-center justify-center rounded-md bg-[hsl(var(--accent)/.16)] text-[hsl(var(--accent))] text-[11px] font-extrabold">NS</div>
            <div className="min-w-0"><div className="truncate text-[12px] font-bold">Northstar Studio</div><div className="cg-kicker !text-[hsl(var(--sidebar-foreground)/.42)]">personal workspace</div></div>
          </div>
          <nav className="space-y-1">{navItems.map((item) => <NavItem key={item.href} {...item} alertCount={activeAlertsCount} />)}</nav>
        </div>
        <div className="mt-auto border-t border-[hsl(var(--sidebar-border))] px-5 py-5">
          <div className="mb-3 flex items-center gap-2 text-[11px] font-semibold text-[hsl(var(--sidebar-foreground)/.72)]">
            <span className={`cg-alert-dot ${connected ? 'bg-primary' : 'bg-amber-500 animate-pulse'}`} />
            {connected ? 'Live SOC Stream' : 'Connecting to SOC...'}
          </div>
          <div className="flex items-center gap-3"><div className="flex h-8 w-8 items-center justify-center rounded-full bg-[hsl(var(--sidebar-primary)/.18)] text-[11px] font-extrabold text-[hsl(var(--sidebar-primary))]">AM</div><div className="min-w-0"><div className="truncate text-[12px] font-bold">Avery Mitchell</div><div className="truncate text-[10px] text-[hsl(var(--sidebar-foreground)/.45)]">Owner · Northstar</div></div><Wifi className="ml-auto text-[hsl(var(--sidebar-foreground)/.4)]" size={14} /></div>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col md:ml-[246px]">
        <header className="flex h-[70px] items-center justify-between border-b border-border bg-background/90 px-5 backdrop-blur-md md:px-9">
          <div className="flex items-center gap-3 md:hidden"><Menu size={18} /><span className="text-[14px] font-extrabold">AI CyberGuard</span></div>
          <div className="hidden items-center gap-2 md:flex"><Activity size={15} className="text-primary" /><span className="cg-mono text-[11px] text-muted-foreground">SOC / NORTHSTAR / LIVE FEED</span></div>
          <div className="ml-auto flex items-center gap-3">
            <div className="hidden items-center gap-2 rounded-full border border-border bg-card px-3 py-1.5 text-[10px] font-bold text-muted-foreground sm:flex">
              <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-primary' : 'bg-amber-500'}`} />
              {connected ? 'Real-Time Telemetry Active' : 'Connecting Stream...'}
            </div>
            <Link href="/alerts" data-testid="button-header-notifications" className="cg-focus relative rounded-lg p-2 text-muted-foreground hover:bg-muted hover:text-foreground">
              <Bell size={17} />
              {activeAlertsCount > 0 && <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-destructive" />}
            </Link>
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10 text-[11px] font-extrabold text-primary">AM</div>
          </div>
        </header>
        <main className="cg-main flex-1 px-4 py-6 md:px-9 md:py-8">{children}</main>
      </div>
      <nav className="cg-mobile-nav fixed bottom-0 left-0 right-0 z-30 items-center justify-around border-t border-border bg-card/95 px-2 py-2 backdrop-blur-xl">
        {navItems.slice(0, 5).map(({ href, label, icon: Icon }) => { const [location] = useLocation(); const active = href === '/' ? location === '/' : location.startsWith(href); return <Link key={href} href={href} data-testid={`link-mobile-${label.toLowerCase().replaceAll(' ', '-')}`} className={`flex min-w-[56px] flex-col items-center gap-1 rounded-lg px-2 py-1.5 text-[9px] font-bold ${active ? 'text-primary' : 'text-muted-foreground'}`}><Icon size={17} /><span>{label === 'Message analyzer' ? 'Message' : label}</span></Link>; })}
      </nav>
    </div>
  );
}