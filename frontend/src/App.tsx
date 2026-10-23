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
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-teal focus:px-3 focus:py-2 focus:text-ink">Skip to content</a>
      <div className="flex min-h-full">
        <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-line-soft bg-hull/70 px-4 py-6 lg:flex">
          <Logo />
          <p className="mt-3 text-xs leading-relaxed text-muted">Find vulnerabilities. Fix them with AI. Verify every fix.</p>
          <nav className="mt-8 flex flex-col gap-1" aria-label="Main">
            {NAV.map(({ path, label, icon: Icon }) => (
              <a key={path} href={`#${path}`} aria-current={active === path ? "page" : undefined}
                className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${active === path ? "bg-raised text-fg" : "text-muted hover:bg-raised/60 hover:text-fg"}`}>
                <Icon className={`size-4 ${active === path ? "text-teal" : ""}`} /> {label}
              </a>
            ))}
          </nav>
          <div className="mt-auto space-y-2 rounded-lg border border-line-soft p-3 text-xs text-muted">
            <div className="flex items-center gap-2">
              <span className={`size-2 rounded-full ${offline ? "bg-crit" : health ? "bg-teal" : "bg-dim"}`} />
              {offline ? "Scanner offline" : health ? `Scanner online · ${health.rules} rules` : "Connecting"}
            </div>
            <div>AI explanations: {health?.ai_provider ? <span className="text-fg">{health.ai_provider}</span> : "built-in (no AI key set)"}</div>
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex items-center justify-between border-b border-line-soft px-4 py-3 lg:hidden">
            <Logo />
            <button onClick={() => go("/new")} className="rounded-lg bg-teal px-3 py-1.5 text-sm font-semibold text-ink">New scan</button>
          </header>
          <nav className="flex gap-1 overflow-x-auto border-b border-line-soft px-3 py-2 lg:hidden" aria-label="Main mobile">
            {NAV.map(({ path, label }) => (
              <a key={path} href={`#${path}`} className={`whitespace-nowrap rounded-md px-3 py-1.5 text-sm ${active === path ? "bg-raised text-fg" : "text-muted"}`}>{label}</a>
            ))}
          </nav>
          {offline && (
            <div className="border-b border-crit/30 bg-crit/10 px-6 py-2 text-sm">
              The PatchPilot API is not reachable. Start the backend with <code className="font-mono">uvicorn app.main:app --port 8000</code> in the backend folder.
            </div>
          )}
          <main id="main" className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 sm:px-8 sm:py-8">{page}</main>
          <footer className="flex items-center gap-2 px-8 pb-6 text-xs text-dim">
            <ShieldCheck className="size-3.5" />
            Automated findings require human review. A clean scan does not prove an application is secure.
          </footer>
        </div>
      </div>
    </ToastProvider>
  );
}
