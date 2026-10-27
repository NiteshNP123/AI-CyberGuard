import { useState, useEffect, useRef } from 'react';
import { Activity, Bell, FileSearch, LayoutDashboard, Menu, MessageSquareText, Settings, ShieldCheck, X, Wifi, Radio } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link, useLocation } from 'wouter';
import {
  getHealthCheckQueryKey, useHealthCheck,
  getGetAlertsQueryKey, useGetAlerts,
  getGetSettingsQueryKey, useGetSettings,
} from '@workspace/api-client-react';
import { useRealtimeSoc } from '@/hooks/use-realtime-soc';

const navItems = [
  { href: '/',                 label: 'Overview',          eyebrow: 'SOC',       icon: LayoutDashboard },
  { href: '/url-analyzer',     label: 'URL Analyzer',      eyebrow: 'Analysis',  icon: FileSearch },
  { href: '/message-analyzer', label: 'Message Analyzer',  eyebrow: 'Analysis',  icon: MessageSquareText },
  { href: '/alerts',           label: 'Alerts',            eyebrow: 'Queue',     icon: Bell },
  { href: '/settings',         label: 'Settings',          eyebrow: 'Config',    icon: Settings },
];

function NavItem({
  href, label, icon: Icon, alertCount,
}: (typeof navItems)[number] & { alertCount?: number }) {
  const [location] = useLocation();
  const active = href === '/' ? location === '/' : location.startsWith(href);
  return (
    <Link
      href={href}
      data-testid={`link-nav-${label.toLowerCase().replaceAll(' ', '-')}`}
      className={`cg-focus group relative flex items-center gap-3 rounded-[6px] border px-3 py-2.5 transition-all duration-300 ${
        active
          ? 'cg-nav-active border-transparent'
          : 'border-transparent hover:border-[var(--border-warm)] hover:bg-[var(--surface-muted)]'
      }`}
      style={{ color: active ? 'var(--terracotta-text)' : 'var(--text-secondary)' }}
    >
      <Icon
        size={15}
        strokeWidth={active ? 2.2 : 1.6}
        style={{ color: active ? 'var(--terracotta-btn)' : 'var(--olive-text)' }}
      />
      <span
        className={`text-[11px] tracking-[.04em] uppercase`}
        style={{ fontWeight: active ? 600 : 500 }}
      >
        {label}
      </span>
      {label === 'Alerts' && (alertCount ?? 0) > 0 && (
        <span
          className="ml-auto rounded-full px-1.5 py-0.5 text-[9px] font-bold text-white"
          style={{ background: 'var(--terracotta-btn)' }}
        >
          {alertCount}
        </span>
      )}
    </Link>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const { connected } = useRealtimeSoc();
  const { data: health } = useHealthCheck({ query: { queryKey: getHealthCheckQueryKey() } });
  const { data: alerts } = useGetAlerts({ query: { queryKey: getGetAlertsQueryKey() } });
  const { data: settings } = useGetSettings({ query: { queryKey: getGetSettingsQueryKey() } });

  const [menuOpen, setMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const mainRef = useRef<HTMLDivElement>(null);

  const activeAlertsCount = (alerts || []).filter(
    (a) => a.status === 'NEW' || a.status === 'INVESTIGATING'
  ).length;

  const displayName = settings?.name || 'Analyst';
  const workspaceName = settings?.workspaceName || 'CyberGuard SOC';
  const userInitials = displayName
    .split(' ')
    .filter(Boolean)
    .map((n) => n[0])
    .join('')
    .slice(0, 2)
    .toUpperCase() || 'AN';

  // Track scroll position on the main element for header opacity
  useEffect(() => {
    const el = mainRef.current;
    if (!el) return;
    const parent = el.parentElement;
    if (!parent) return;
    const onScroll = () => setScrolled(parent.scrollTop > 20);
    parent.addEventListener('scroll', onScroll, { passive: true });
    return () => parent.removeEventListener('scroll', onScroll);
  }, []);

  // Close menu on route change
  const [location] = useLocation();
  useEffect(() => { setMenuOpen(false); }, [location]);

  // Prevent body scroll when mobile menu is open
  useEffect(() => {
    document.documentElement.classList.toggle('overflow-hidden', menuOpen);
    return () => document.documentElement.classList.remove('overflow-hidden');
  }, [menuOpen]);

  return (
    <div className="flex min-h-[100dvh] bg-background text-foreground">
      {/* ── Desktop sidebar ─────────────────────────────────────────── */}
      <aside
        className="cg-desktop-nav fixed inset-y-0 left-0 z-20 flex w-[230px] flex-col"
        style={{
          background: 'var(--surface-soft)',
          borderRight: '1px solid var(--border-warm)',
        }}
      >
        {/* Brand */}
        <div className="flex items-center gap-3 px-5 py-6">
          <div
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-[8px]"
            style={{ background: 'rgba(169,81,60,.14)', border: '1px solid rgba(169,81,60,.28)' }}
          >
            <ShieldCheck size={17} strokeWidth={2.2} style={{ color: 'var(--terracotta-btn)' }} />
          </div>
          <div>
            <div
              className="text-[13px] tracking-[.12em] uppercase"
              style={{ fontWeight: 600, color: 'var(--text-primary)' }}
            >
              CyberGuard
            </div>
            <div className="cg-kicker mt-0.5" style={{ letterSpacing: '.18em', color: 'var(--olive-text)' }}>
              AI · SOC Platform
            </div>
          </div>
        </div>

        {/* Divider */}
        <div className="mx-5 mb-3" style={{ height: '1px', background: 'var(--border-warm)' }} />

        {/* Workspace chip */}
        <div className="mx-4 mb-4">
          <div
            className="flex items-center gap-2.5 rounded-[7px] px-3 py-2.5"
            style={{ background: 'var(--surface-muted)', border: '1px solid var(--border-warm)' }}
          >
            <div
              className="flex h-6 w-6 shrink-0 items-center justify-center rounded-[5px] text-[9px] font-bold"
              style={{ background: 'rgba(139,134,92,.18)', color: 'var(--olive-dark)' }}
            >
              {(workspaceName[0] || 'C').toUpperCase()}
            </div>
            <div className="min-w-0">
              <div className="truncate text-[11px] font-medium" style={{ color: 'var(--text-primary)' }}>
                {workspaceName}
              </div>
              <div className="cg-kicker" style={{ fontSize: '9px', color: 'var(--olive-text)' }}>Workspace</div>
            </div>
          </div>
        </div>

        {/* Nav items */}
        <nav className="flex-1 space-y-0.5 px-3">
          {navItems.map((item) => (
            <NavItem key={item.href} {...item} alertCount={activeAlertsCount} />
          ))}
        </nav>

        {/* Footer — live stream status + user */}
        <div className="px-4 pb-5 pt-4" style={{ borderTop: '1px solid var(--border-warm)' }}>
          {/* Stream status */}
          <div className="mb-3 flex items-center gap-2">
            <span
              className={`h-1.5 w-1.5 rounded-full ${connected ? '' : 'animate-pulse'}`}
              style={{ background: connected ? 'var(--sev-low)' : 'var(--sev-medium)' }}
            />
            <span className="cg-kicker" style={{ fontSize: '9px', color: 'var(--olive-text)' }}>
              {connected ? 'Live SOC Stream' : 'Connecting…'}
            </span>
          </div>
          {/* User */}
          <div className="flex items-center gap-2.5">
            <div
              className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-[10px] font-bold"
              style={{ background: 'rgba(169,81,60,.14)', color: 'var(--terracotta-text)' }}
            >
              {userInitials}
            </div>
            <div className="min-w-0 flex-1">
              <div className="truncate text-[11px] font-medium" style={{ color: 'var(--text-primary)' }}>
                {displayName}
              </div>
              <div className="cg-kicker" style={{ fontSize: '9px', color: 'var(--olive-text)' }}>Analyst</div>
            </div>
            <Radio size={12} style={{ color: 'var(--cg-muted)', flexShrink: 0 }} />
          </div>
        </div>
      </aside>

      {/* ── Main content area ────────────────────────────────────────── */}
      <div className="flex min-w-0 flex-1 flex-col md:ml-[230px]">
        {/* Sticky header */}
        <header
          className="sticky top-0 z-10 flex h-[64px] items-center justify-between px-5 md:px-8 transition-all duration-500"
          style={{
            borderBottom: scrolled ? '1px solid var(--border-warm)' : '1px solid transparent',
            background: scrolled
              ? 'rgba(248,246,242,.92)'
              : 'transparent',
            backdropFilter: scrolled ? 'blur(14px) saturate(1.1)' : 'none',
            WebkitBackdropFilter: scrolled ? 'blur(14px) saturate(1.1)' : 'none',
          }}
        >
          {/* Mobile: burger + brand */}
          <div className="flex items-center gap-3 md:hidden">
            <button
              onClick={() => setMenuOpen(!menuOpen)}
              className="cg-focus p-1"
              aria-label={menuOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={menuOpen}
            >
              {menuOpen
                ? <X size={18} style={{ color: 'var(--text-primary)' }} />
                : <Menu size={18} style={{ color: 'var(--text-primary)' }} />}
            </button>
            <span
              className="text-[13px] tracking-[.12em] uppercase"
              style={{ fontWeight: 600, color: 'var(--text-primary)' }}
            >
              CyberGuard
            </span>
          </div>

          {/* Desktop: breadcrumb */}
          <div className="hidden items-center gap-2 md:flex">
            <Activity size={13} style={{ color: 'var(--terracotta-btn)' }} />
            <span className="cg-mono text-[10px]" style={{ color: 'var(--cg-muted)' }}>
              AI-CYBERGUARD / SOC
            </span>
          </div>

          {/* Right — status pill + alerts + user */}
          <div className="ml-auto flex items-center gap-3">
            <div
              className="hidden items-center gap-2 rounded-full px-3 py-1.5 sm:flex"
              style={{
                border: '1px solid var(--border-warm)',
                background: 'var(--surface-muted)',
                fontSize: '10px',
                fontWeight: 500,
                color: 'var(--text-secondary)',
                letterSpacing: '.06em',
              }}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${connected ? '' : 'animate-pulse'}`}
                style={{ background: connected ? 'var(--sev-low)' : 'var(--sev-medium)' }}
              />
              {connected ? 'Real-Time Active' : 'Connecting…'}
            </div>

            <Link
              href="/alerts"
              data-testid="button-header-notifications"
              className="cg-focus relative rounded-lg p-2 transition-colors"
              style={{ color: 'var(--text-secondary)' }}
            >
              <Bell size={16} />
              {activeAlertsCount > 0 && (
                <span
                  className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full"
                  style={{ background: 'var(--terracotta-btn)' }}
                />
              )}
            </Link>

            <div
              className="flex h-8 w-8 items-center justify-center rounded-full text-[10px] font-bold"
              style={{ background: 'rgba(169,81,60,.14)', color: 'var(--terracotta-text)' }}
            >
              {userInitials}
            </div>
          </div>
        </header>

        {/* Page content */}
        <main ref={mainRef} className="cg-main flex-1 px-4 py-7 md:px-8 md:py-8">
          {children}
        </main>
      </div>

      {/* ── Mobile slide-in menu ─────────────────────────────────────── */}
      {menuOpen && (
        <div
          className="fixed inset-0 z-40 md:hidden"
          onClick={() => setMenuOpen(false)}
          aria-hidden="true"
          style={{ background: 'rgba(41,43,38,.40)' }}
        />
      )}
      <nav
        className="fixed inset-y-0 right-0 z-50 flex w-[min(84vw,320px)] flex-col md:hidden"
        style={{
          background: 'var(--surface-soft)',
          borderLeft: '1px solid var(--border-warm)',
          transform: menuOpen ? 'translateX(0)' : 'translateX(100%)',
          transition: 'transform .55s cubic-bezier(.16,1,.3,1)',
        }}
        aria-label="Mobile navigation"
      >
        <div className="flex items-center justify-between px-5 py-5" style={{ borderBottom: '1px solid var(--border-warm)' }}>
          <span className="cg-kicker" style={{ color: 'var(--olive-text)' }}>Navigation</span>
          <button
            onClick={() => setMenuOpen(false)}
            className="cg-focus p-1"
            aria-label="Close navigation"
          >
            <X size={16} style={{ color: 'var(--text-secondary)' }} />
          </button>
        </div>
        <div className="flex-1 space-y-1 p-4">
          {navItems.map((item) => (
            <NavItem key={item.href} {...item} alertCount={activeAlertsCount} />
          ))}
        </div>
        <div className="p-5" style={{ borderTop: '1px solid var(--border-warm)' }}>
          <div className="flex items-center gap-2 text-[10px]" style={{ color: 'var(--text-secondary)' }}>
            <span
              className={`h-1.5 w-1.5 rounded-full ${connected ? '' : 'animate-pulse'}`}
              style={{ background: connected ? 'var(--sev-low)' : 'var(--sev-medium)' }}
            />
            {connected ? 'Live SOC Stream Active' : 'Connecting to SOC…'}
          </div>
        </div>
      </nav>

      {/* ── Mobile bottom nav ────────────────────────────────────────── */}
      <nav
        className="cg-mobile-nav fixed bottom-0 left-0 right-0 z-30 items-center justify-around px-2 py-2"
        style={{
          borderTop: '1px solid var(--border-warm)',
          background: 'rgba(248,246,242,.95)',
          backdropFilter: 'blur(16px)',
          WebkitBackdropFilter: 'blur(16px)',
        }}
      >
        {navItems.slice(0, 5).map(({ href, label, icon: Icon }) => {
          const active = href === '/' ? location === '/' : location.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              data-testid={`link-mobile-${label.toLowerCase().replaceAll(' ', '-')}`}
              className={`flex min-w-[52px] flex-col items-center gap-1 rounded-lg px-2 py-1.5 text-[8px] font-bold uppercase tracking-[.08em] transition-colors`}
              style={{ color: active ? 'var(--terracotta-text)' : 'var(--cg-muted)' }}
            >
              <Icon size={16} strokeWidth={active ? 2.2 : 1.5} />
              <span>{label === 'Message Analyzer' ? 'Message' : label}</span>
            </Link>
          );
        })}
      </nav>
    </div>
  );
}
