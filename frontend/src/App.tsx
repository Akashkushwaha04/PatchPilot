import { useEffect, useState } from "react";
import { FlaskConical, History, LayoutDashboard, Plus, ShieldCheck } from "lucide-react";
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

export function Logo() {
  return (
    <a href="#/" className="flex items-center gap-2.5" aria-label="PatchPilot AI home">
      <svg viewBox="0 0 32 32" className="size-8" aria-hidden="true">
        <path d="M16 3.5l10 4.4v6.6c0 6.8-4.4 11.3-10 13.5-5.6-2.2-10-6.7-10-13.5V7.9z" fill="none" stroke="var(--color-teal)" strokeWidth="2" strokeLinejoin="round" />
        <path d="M11 16.2l3.4 3.4 6.8-7.3" fill="none" stroke="var(--color-sky)" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <span className="text-[17px] font-extrabold tracking-tight">PatchPilot <span className="font-semibold text-teal">AI</span></span>
    </a>
  );
}

export default function App() {
  const route = useRoute();
  const [health, setHealth] = useState<Health | null>(null);
  const [offline, setOffline] = useState(false);

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
        {/* Floating Spatial Sidebar */}
        <aside className="sticky top-6 hidden h-[calc(100vh-3rem)] w-64 shrink-0 flex-col liquid-panel p-5 lg:flex shadow-2xl">
          <Logo />
          <p className="mt-3 text-xs leading-relaxed text-muted">Find vulnerabilities. Fix them with AI. Verify every fix.</p>
          <nav className="mt-8 flex flex-col gap-1.5" aria-label="Main">
            {NAV.map(({ path, label, icon: Icon }) => (
              <a key={path} href={`#${path}`} aria-current={active === path ? "page" : undefined}
                className={`flex items-center gap-3 rounded-2xl px-3.5 py-2.5 text-sm transition-all duration-200 ${
                  active === path
                    ? "liquid-pill-active font-semibold shadow-md"
                    : "text-muted hover:bg-white/10 hover:text-fg"
                }`}>
                <Icon className={`size-4 ${active === path ? "text-teal" : ""}`} /> {label}
              </a>
            ))}
          </nav>
          <div className="mt-auto space-y-2 rounded-2xl border border-white/10 bg-white/5 p-3.5 text-xs text-muted backdrop-blur-md">
            <div className="flex items-center gap-2">
              <span className={`size-2 rounded-full ${offline ? "bg-crit shadow-[0_0_8px_var(--color-crit)]" : health ? "bg-teal shadow-[0_0_8px_var(--color-teal)]" : "bg-dim"}`} />
              {offline ? "Scanner offline" : health ? `Scanner online · ${health.rules} rules` : "Connecting"}
            </div>
            <div>AI explanations: {health?.ai_provider ? <span className="text-fg font-medium">{health.ai_provider}</span> : "built-in (no AI key set)"}</div>
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          {/* Mobile Liquid Header */}
          <header className="flex items-center justify-between liquid-panel mb-3 px-4 py-3 lg:hidden">
            <Logo />
            <button onClick={() => go("/new")} className="liquid-btn-primary px-3.5 py-1.5 text-sm font-semibold">New scan</button>
          </header>
          <nav className="flex gap-1.5 overflow-x-auto liquid-pill-container mb-4 p-1.5 lg:hidden" aria-label="Main mobile">
            {NAV.map(({ path, label }) => (
              <a key={path} href={`#${path}`} className={`whitespace-nowrap rounded-full px-3.5 py-1.5 text-sm transition-all ${active === path ? "liquid-pill-active font-semibold" : "text-muted hover:text-fg"}`}>{label}</a>
            ))}
          </nav>
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
