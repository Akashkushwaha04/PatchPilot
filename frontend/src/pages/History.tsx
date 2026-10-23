import { useEffect, useState } from "react";
import { CornerDownRight, Plus, Trash2 } from "lucide-react";
import { api, type Scan } from "../api";
import { Button, ErrorBanner, Panel, SeverityBar, Spinner, go, timeAgo, useToast } from "../ui";

export default function HistoryPage() {
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState(false);
  const toast = useToast();

  const load = () => api.scans().then(setScans).catch((e) => setError(e.message));
  useEffect(() => { load(); }, []);

  const clear = async () => {
    try { await api.clearHistory(); setConfirm(false); toast("Scan history cleared"); load(); } catch (e) { setError((e as Error).message); }
  };

  if (error) return <ErrorBanner message={error} />;
  if (!scans) return <Spinner label="Loading scan history" />;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight sm:text-3xl">Scan history</h1>
          <p className="mt-1 text-sm text-muted">Rescans are listed under the scan they verify.</p>
        </div>
        <div className="flex gap-2">
          {scans.length > 0 && (confirm
            ? <><Button variant="danger" onClick={clear} icon={<Trash2 className="size-4" />}>Delete all scans</Button><Button variant="ghost" onClick={() => setConfirm(false)}>Cancel</Button></>
            : <Button variant="ghost" onClick={() => setConfirm(true)} icon={<Trash2 className="size-4" />}>Clear history</Button>)}
          <Button variant="primary" onClick={() => go("/new")} icon={<Plus className="size-4" />}>New security scan</Button>
        </div>
      </div>
      {scans.length === 0 ? (
        <Panel className="px-6 py-14 text-center">
          <p className="font-semibold">No scans yet</p>
          <p className="mt-1 text-sm text-muted">Start a scan, or load the demo project from the dashboard.</p>
        </Panel>
      ) : (
        <Panel>
          <table className="w-full text-sm">
            <thead className="border-b border-line-soft text-left text-xs text-muted">
              <tr>
                <th className="px-5 py-3 font-medium">Project</th>
                <th className="px-3 py-3 font-medium">Score</th>
                <th className="hidden px-3 py-3 font-medium md:table-cell">Findings</th>
                <th className="hidden px-3 py-3 font-medium sm:table-cell">Verification</th>
                <th className="px-5 py-3 text-right font-medium">When</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line-soft">
              {scans.map((s) => (
                <tr key={s.id} className="cursor-pointer hover:bg-raised/50" onClick={() => go(`/scans/${s.id}`)}>
                  <td className="px-5 py-3.5">
                    <a href={`#/scans/${s.id}`} className="flex items-center gap-2 font-semibold" onClick={(e) => e.stopPropagation()}>
                      {s.parent_id && <CornerDownRight className="size-4 text-dim" />}
                      {s.project_name}
                    </a>
                    <span className="text-xs text-muted">{s.label ?? (s.parent_id ? "Rescan" : "Scan")} · {s.file_count} files</span>
                  </td>
                  <td className="px-3 py-3.5 text-lg font-extrabold tabular-nums">{s.score.score}<span className="ml-1 text-xs font-semibold text-muted">{s.score.grade}</span></td>
                  <td className="hidden w-48 px-3 py-3.5 md:table-cell"><SeverityBar counts={s.counts} /><span className="mt-1 block text-xs text-muted">{s.total_findings} total</span></td>
                  <td className="hidden px-3 py-3.5 text-xs text-muted sm:table-cell">
                    {s.comparison ? `${s.comparison.resolved.length} resolved · ${s.comparison.remaining.length} remaining · ${s.comparison.new.length} new` : s.latest_rescan_id ? "Rescanned" : "Not yet rescanned"}
                  </td>
                  <td className="px-5 py-3.5 text-right text-xs text-dim">{timeAgo(s.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  );
}
