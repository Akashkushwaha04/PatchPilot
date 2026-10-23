import { useEffect, useState } from "react";
import { Activity, FileSearch, FlaskConical, Plus, RefreshCcw, ScanLine, Sparkles, Wrench } from "lucide-react";
import { api, type Dashboard as D, type Severity } from "../api";
import SeverityFindingsDialog from "../components/SeverityFindingsDialog";
import { Button, ErrorBanner, Panel, SEV_COLOR, SEV_LABEL, SEV_ORDER, SeverityBar, Spinner, go, timeAgo } from "../ui";

export function useDemoLauncher() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const launch = async () => {
    setBusy(true);
    setError(null);
    try {
      const s = await api.demoScan();
      go(`/scans/${s.id}`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, launch, clear: () => setError(null) };
}

const ACTIVITY_ICON: Record<string, typeof Activity> = { scan: ScanLine, rescan: RefreshCcw, prompt: Wrench, status: FileSearch };

export default function Dashboard() {
  const [data, setData] = useState<D | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dialogSev, setDialogSev] = useState<Severity | null>(null);
  const demo = useDemoLauncher();

  useEffect(() => {
    api.dashboard().then(setData).catch((e) => setError(e.message));
  }, []);

  if (error) return <ErrorBanner message={error} />;
  if (!data) return <Spinner label="Loading your security overview" />;

  const header = (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-extrabold tracking-tight sm:text-3xl">Security overview</h1>
        <p className="mt-1 text-sm text-muted">Scan source code built with AI tools, fix what's found, and prove the fix with a rescan.</p>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button onClick={demo.launch} busy={demo.busy} icon={<FlaskConical className="size-4" />}>Load demo project</Button>
        <Button variant="primary" onClick={() => go("/new")} icon={<Plus className="size-4" />}>New security scan</Button>
      </div>
    </div>
  );

  if (data.total_scans === 0) {
    return (
      <div className="space-y-6">
        {header}
        {demo.error && <ErrorBanner message={demo.error} onDismiss={demo.clear} />}
        <Panel className="overflow-hidden">
          <div className="grid gap-10 p-6 sm:p-10 lg:grid-cols-[1.1fr_1fr]">
            <div>
              <h2 className="max-w-md text-2xl font-bold leading-snug">No scans yet. Try the full flow on a deliberately broken app in under a minute.</h2>
              <p className="mt-3 max-w-lg text-sm leading-relaxed text-muted">
                The demo project is Campus Bazaar, a small synthetic marketplace with planted mistakes: a leaked API key, unsafe HTML rendering,
                open CORS, a fake admin check and injectable queries. Every credential in it is fake and inert.
              </p>
              <div className="mt-6 flex flex-wrap gap-2">
                <Button variant="primary" onClick={demo.launch} busy={demo.busy} icon={<FlaskConical className="size-4" />}>Load and scan demo project</Button>
                <Button onClick={() => go("/new")} icon={<Plus className="size-4" />}>Scan my own code</Button>
              </div>
            </div>
            <ol className="space-y-4">
              {[
                [ScanLine, "Scan", "Rules read every file and report findings with file, line and evidence. Nothing you upload is executed."],
                [Sparkles, "Fix with AI", "Generate a precise repair prompt for your coding assistant, with constraints and tests."],
                [RefreshCcw, "Verify", "Upload the corrected code. The rescan shows what is resolved, what remains and what is new."],
              ].map(([Icon, title, text], i) => {
                const I = Icon as typeof Activity;
                return (
                  <li key={i} className="flex gap-4 rounded-lg border border-line-soft bg-hull/60 p-4">
                    <span className="flex size-8 shrink-0 items-center justify-center rounded-full border border-teal/40 text-sm font-bold text-teal">{i + 1}</span>
                    <div>
                      <p className="flex items-center gap-2 font-semibold"><I className="size-4 text-sky" /> {title as string}</p>
                      <p className="mt-1 text-sm text-muted">{text as string}</p>
                    </div>
                  </li>
                );
              })}
            </ol>
          </div>
        </Panel>
      </div>
    );
  }

  const distTotal = SEV_ORDER.reduce((a, s) => a + data.severity_distribution[s], 0);
  const stats = [
    { label: "Total scans", value: data.total_scans, def: "Every scan and rescan you have run." },
    { label: "Total findings", value: data.total_findings, def: data.definitions.total_findings },
    { label: "Open critical & high", value: data.open_critical_high, def: data.definitions.open_critical_high, tone: data.open_critical_high ? "text-crit" : "text-teal" },
    { label: "Verified fixed", value: data.resolved, def: data.definitions.resolved, tone: "text-teal" },
  ];

  return (
    <div className="space-y-6">
      {header}
      {demo.error && <ErrorBanner message={demo.error} onDismiss={demo.clear} />}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {stats.map((s) => (
          <Panel key={s.label} className="p-5">
            <p className="text-sm text-muted">{s.label}</p>
            <p className={`mt-2 text-3xl font-extrabold tracking-tight ${s.tone ?? ""}`}>{s.value}</p>
            <p className="mt-2 text-xs leading-snug text-dim">{s.def}</p>
          </Panel>
        ))}
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.6fr_1fr]">
        <Panel>
          <div className="flex items-center justify-between border-b border-line-soft px-5 py-4">
            <h2 className="font-bold">Recent scans</h2>
            <a href="#/history" className="text-sm text-sky hover:underline">View all</a>
          </div>
          <ul className="divide-y divide-line-soft">
            {data.recent_scans.map((s) => (
              <li key={s.id}>
                <a href={`#/scans/${s.id}`} className="grid grid-cols-[3rem_1fr_auto] items-center gap-4 px-5 py-3.5 hover:bg-raised/50 sm:grid-cols-[3rem_1fr_10rem_auto]">
                  <span className="text-xl font-extrabold tabular-nums">{s.score.score}</span>
                  <span className="min-w-0">
                    <span className="block truncate font-semibold">{s.project_name}</span>
                    <span className="block truncate text-xs text-muted">
                      {s.label ?? (s.parent_id ? "Rescan" : "Scan")} · {s.file_count} files · {s.total_findings} findings
                      {s.comparison && ` · ${s.comparison.resolved.length} resolved`}
                    </span>
                  </span>
                  <span className="hidden sm:block"><SeverityBar counts={s.counts} /></span>
                  <span className="text-xs text-dim whitespace-nowrap">{timeAgo(s.created_at)}</span>
                </a>
              </li>
            ))}
          </ul>
        </Panel>

        <div className="space-y-6">
          <Panel className="p-5">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="font-bold">Severity distribution</h2>
                <p className="mt-1 text-xs text-dim">{data.definitions.severity_distribution}</p>
              </div>
              <span className="rounded-md border border-line-soft bg-hull/80 px-2 py-0.5 text-[10px] font-semibold text-sky">
                Click to view
              </span>
            </div>
            <ul className="mt-4 space-y-2">
              {SEV_ORDER.filter((s) => s !== "info").map((s) => {
                const count = data.severity_distribution[s] ?? 0;
                return (
                  <li key={s}>
                    <button
                      type="button"
                      onClick={() => setDialogSev(s)}
                      className="group grid w-full grid-cols-[5rem_1fr_2.5rem] items-center gap-3 rounded-lg px-2.5 py-2 text-left text-sm transition-all duration-150 cursor-pointer hover:bg-raised/70 hover:scale-[1.01] active:scale-[0.99] border border-transparent hover:border-line-soft"
                      title={`Click to view ${count} ${SEV_LABEL[s]} finding${count === 1 ? "" : "s"}`}
                    >
                      <span className="flex items-center gap-1.5 font-medium text-muted group-hover:text-fg transition-colors">
                        <span className="size-2 rounded-full shrink-0" style={{ background: SEV_COLOR[s] }} />
                        {SEV_LABEL[s]}
                      </span>
                      <span className="h-2.5 overflow-hidden rounded-full bg-line-soft group-hover:bg-line transition-colors">
                        <span
                          className="block h-full rounded-full transition-all group-hover:brightness-125"
                          style={{
                            width: `${distTotal ? (count / distTotal) * 100 : 0}%`,
                            background: SEV_COLOR[s],
                          }}
                        />
                      </span>
                      <span className="text-right font-bold tabular-nums text-fg group-hover:underline">
                        {count}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </Panel>

          <Panel className="p-5">
            <h2 className="font-bold">Recent activity</h2>
            <ul className="mt-3 space-y-3">
              {data.activity.map((a, i) => {
                const I = ACTIVITY_ICON[a.kind] ?? Activity;
                return (
                  <li key={i} className="flex gap-3 text-sm">
                    <I className="mt-0.5 size-4 shrink-0 text-sky" />
                    <span className="min-w-0 flex-1">
                      {a.scan_id ? <a href={`#/scans/${a.scan_id}`} className="hover:underline">{a.message}</a> : a.message}
                      <span className="block text-xs text-dim">{timeAgo(a.at)}</span>
                    </span>
                  </li>
                );
              })}
            </ul>
          </Panel>
        </div>
      </div>

      {dialogSev && (
        <SeverityFindingsDialog
          open={dialogSev !== null}
          onClose={() => setDialogSev(null)}
          initialSeverity={dialogSev}
          counts={data.severity_distribution}
        />
      )}
    </div>
  );
}
