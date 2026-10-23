import { useEffect, useState } from "react";
import { FlaskConical, History, LayoutDashboard, Menu, PanelLeftClose, Plus, ShieldCheck, X } from "lucide-react";
import { api, type Health } from "./api";
import { ToastProvider, go, useRoute } from "./ui";
import Dashboard from "./pages/Dashboard";
import NewScan from "./pages/NewScan";
import ScanResults from "./pages/ScanResults";
import HistoryPage from "./pages/History";
import EvaluationPage from "./pages/Evaluation";

const NAV = [
  { path: "/", label: "Dashboard", icon: LayoutDashboard },
  { path: "/new", label: "New scan", icon: Plus },
  { path: "/history", label: "Scan history", icon: History },
  { path: "/evaluation", label: "Evaluation", icon: FlaskConical },
];

export function Logo({ showText = true }: { showText?: boolean }) {
  return (
    <a href="#/" className="flex items-center gap-2.5 overflow-hidden" aria-label="PatchPilot AI home">
      <svg viewBox="0 0 32 32" className="size-8 shrink-0" aria-hidden="true">
        <path d="M16 3.5l10 4.4v6.6c0 6.8-4.4 11.3-10 13.5-5.6-2.2-10-6.7-10-13.5V7.9z" fill="none" stroke="var(--color-teal)" strokeWidth="2" strokeLinejoin="round" />
        <path d="M11 16.2l3.4 3.4 6.8-7.3" fill="none" stroke="var(--color-sky)" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      {showText && (
        <span className="text-[17px] font-extrabold tracking-tight whitespace-nowrap">
          PatchPilot <span className="font-semibold text-teal">AI</span>
        </span>
      )}
    </a>
  );
}

export default function App() {
  const route = useRoute();
  const [health, setHealth] = useState<Health | null>(null);
  const [offline, setOffline] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(() => {
    try {
      return localStorage.getItem("pp_sidebar_open") !== "false";
    } catch {
      return true;
    }
  });
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const toggleSidebar = () => {
    setSidebarOpen((prev) => {
      const next = !prev;
      try {
        localStorage.setItem("pp_sidebar_open", String(next));
      } catch { /* ignore */ }
      return next;
    });
  };

  useEffect(() => {
    api.health().then(setHealth).catch(() => setOffline(true));
  }, []);

  const scanMatch = route.match(/^\/scans\/([\w-]+)/);
  const page = scanMatch ? <ScanResults scanId={scanMatch[1]} key={scanMatch[1]} />
    : route === "/new" ? <NewScan />
    : route === "/history" ? <HistoryPage />
    : route === "/evaluation" ? <EvaluationPage />
    : <Dashboard />;
  const active = scanMatch ? "/history" : route;

  return (
    <ToastProvider>
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-xl focus:bg-teal focus:px-3 focus:py-2 focus:text-ink">Skip to content</a>
      <div className="flex min-h-full p-2.5 sm:p-4 lg:p-6 gap-6">
        {/* Floating Spatial Sidebar (Collapsible with Burger Button) */}
        <aside
          className={`sticky top-6 hidden h-[calc(100vh-3rem)] shrink-0 flex-col liquid-panel p-4 lg:flex shadow-2xl transition-all duration-300 ease-in-out ${
            sidebarOpen ? "w-64" : "w-[76px] items-center"
          }`}
        >
          {/* Header Row with Logo & Burger Button */}
          {sidebarOpen ? (
            <div className="flex items-center justify-between w-full h-10 px-1">
              <Logo showText={true} />
              <button
                type="button"
                onClick={toggleSidebar}
                className="size-8.5 rounded-xl bg-white/10 hover:bg-white/20 active:scale-95 border border-white/15 backdrop-blur-xl flex items-center justify-center text-white/80 hover:text-white transition-all shadow-sm shrink-0"
                title="Hide navigation options"
                aria-label="Hide navigation options"
              >
                <PanelLeftClose className="size-4" />
              </button>
            </div>
          ) : (
            <div className="flex items-center justify-center w-full h-10">
              <button
                type="button"
                onClick={toggleSidebar}
                className="size-11 rounded-2xl bg-white/10 hover:bg-white/20 active:scale-95 border border-white/15 backdrop-blur-xl flex items-center justify-center text-white/90 hover:text-teal transition-all shadow-sm"
                title="Show navigation options"
                aria-label="Show navigation options"
              >
                <Menu className="size-5" />
              </button>
            </div>
          )}

          {sidebarOpen && (
            <p className="mt-2 text-xs leading-relaxed text-muted animate-rise px-1">
              Find vulnerabilities. Fix them with AI. Verify every fix.
            </p>
          )}

          {/* Navigation Options */}
          <nav className="mt-6 flex flex-col gap-1.5 w-full" aria-label="Main">
            {NAV.map(({ path, label, icon: Icon }) => {
              const isSelected = active === path;
              return (
                <a
                  key={path}
                  href={`#${path}`}
                  aria-current={isSelected ? "page" : undefined}
                  title={!sidebarOpen ? label : undefined}
                  className={`flex items-center rounded-2xl text-sm transition-all duration-200 ${
                    sidebarOpen ? "gap-3 px-3.5 py-2.5" : "justify-center size-11 mx-auto"
                  } ${
                    isSelected
                      ? "liquid-pill-active font-semibold shadow-md"
                      : "text-muted hover:bg-white/10 hover:text-fg"
                  }`}
                >
                  <Icon className={`size-4.5 shrink-0 ${isSelected ? "text-teal" : ""}`} />
                  {sidebarOpen && <span className="truncate">{label}</span>}
                </a>
              );
            })}
          </nav>

          {/* Status Box */}
          <div className={`mt-auto rounded-2xl border border-white/10 bg-white/5 text-xs text-muted backdrop-blur-md transition-all ${sidebarOpen ? "p-3.5 space-y-2 w-full animate-rise" : "p-2 flex flex-col items-center"}`}>
            <div className="flex items-center gap-2" title={offline ? "Scanner offline" : health ? `Scanner online · ${health.rules} rules` : "Connecting"}>
              <span className={`size-2.5 rounded-full shrink-0 ${offline ? "bg-crit shadow-[0_0_8px_var(--color-crit)]" : health ? "bg-teal shadow-[0_0_8px_var(--color-teal)]" : "bg-dim"}`} />
              {sidebarOpen && (
                <span className="truncate">
                  {offline ? "Scanner offline" : health ? `Scanner online · ${health.rules} rules` : "Connecting"}
                </span>
              )}
            </div>
            {sidebarOpen && (
              <div className="truncate text-[11px] text-white/60">
                AI: {health?.ai_provider ? <span className="text-fg font-medium">{health.ai_provider}</span> : "built-in (no key set)"}
              </div>
            )}
          </div>
        </aside>

        {/* Main Content Area */}
        <div className="flex min-w-0 flex-1 flex-col">
          {/* Top Bar */}
          <header className="flex items-center justify-between liquid-panel mb-4 px-4 py-3">
            <div className="flex items-center gap-3">
              {/* Mobile Hamburger Button */}
              <button
                type="button"
                onClick={() => setMobileMenuOpen((prev) => !prev)}
                className="size-9 rounded-xl bg-white/10 hover:bg-white/20 active:scale-95 border border-white/15 backdrop-blur-xl flex items-center justify-center text-white/90 hover:text-white transition-all shadow-sm lg:hidden"
                aria-label="Toggle navigation menu"
                title="Toggle menu"
              >
                {mobileMenuOpen ? <X className="size-4.5" /> : <Menu className="size-4.5" />}
              </button>

              {/* Show Logo in top bar only when sidebar is collapsed or on mobile */}
              <div className={sidebarOpen ? "lg:hidden" : "animate-rise"}>
                <Logo showText={true} />
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button onClick={() => go("/new")} className="liquid-btn-primary px-3.5 py-1.5 text-xs sm:text-sm font-semibold flex items-center gap-1.5">
                <Plus className="size-4" />
                <span>New scan</span>
              </button>
            </div>
          </header>

          {/* Mobile Liquid Drawer Menu */}
          {mobileMenuOpen && (
            <div className="liquid-panel mb-4 p-4 lg:hidden animate-rise">
              <nav className="flex flex-col gap-1.5" aria-label="Mobile Navigation">
                {NAV.map(({ path, label, icon: Icon }) => (
                  <a
                    key={path}
                    href={`#${path}`}
                    onClick={() => setMobileMenuOpen(false)}
                    className={`flex items-center gap-3 rounded-2xl px-4 py-2.5 text-sm transition-all ${
                      active === path
                        ? "liquid-pill-active font-semibold shadow-md"
                        : "text-muted hover:bg-white/10 hover:text-fg"
                    }`}
                  >
                    <Icon className={`size-4.5 ${active === path ? "text-teal" : ""}`} />
                    <span>{label}</span>
                  </a>
                ))}
              </nav>
            </div>
          )}

          {offline && (
            <div className="rounded-2xl border border-crit/30 bg-crit/15 px-6 py-2.5 text-sm mb-4 backdrop-blur-md">
              The PatchPilot API is not reachable. Start the backend with <code className="font-mono">uvicorn app.main:app --port 8000</code> in the backend folder.
            </div>
          )}

          <main id="main" className="mx-auto w-full max-w-[1440px] flex-1 pb-6">{page}</main>

          <footer className="flex items-center justify-between px-2 pt-4 pb-2 text-xs text-dim">
            <div className="flex items-center gap-2">
              <ShieldCheck className="size-3.5 text-teal" />
              Automated findings require human review. A clean scan does not prove an application is secure.
            </div>
          </footer>
        </div>
      </div>
    </ToastProvider>
  );
}
