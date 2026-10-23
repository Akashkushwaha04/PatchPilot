import { useEffect, useState } from "react";
import { CheckCircle2, CircleAlert, RefreshCcw, XCircle } from "lucide-react";
import { api, type Evaluation } from "../api";
import { Button, ErrorBanner, Panel, Spinner } from "../ui";

export default function EvaluationPage() {
  const [ev, setEv] = useState<Evaluation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = () => {
    setBusy(true);
    api.evaluation().then(setEv).catch((e) => setError(e.message)).finally(() => setBusy(false));
  };
  useEffect(run, []);

  if (error) return <ErrorBanner message={error} />;
  if (!ev) return <Spinner label="Running the scanner on the evaluation set" />;

  const stats = [
    { label: "Planted test cases", value: ev.planted },
    { label: "Detected", value: ev.detected, tone: "text-teal" },
    { label: "Missed", value: ev.missed, tone: ev.missed ? "text-crit" : "" },
    { label: `False positives (of ${ev.safe_cases} safe)`, value: ev.false_positives, tone: ev.false_positives ? "text-high" : "" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight sm:text-3xl">Scanner evaluation</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted">{ev.note}</p>
        </div>
        <Button onClick={run} busy={busy} icon={<RefreshCcw className="size-4" />}>Run again</Button>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {stats.map((s) => (
          <Panel key={s.label} className="p-5">
            <p className="text-sm text-muted">{s.label}</p>
            <p className={`mt-2 text-3xl font-extrabold ${s.tone ?? ""}`}>{s.value}</p>
          </Panel>
        ))}
      </div>

      <div className="flex items-start gap-3 rounded-lg border border-line bg-hull/60 px-4 py-3 text-sm text-muted">
        <CircleAlert className="mt-0.5 size-4 shrink-0 text-med" />
        These cases were written by the PatchPilot team to exercise each rule, so a high score here is expected. Real projects will produce misses and false positives that this set does not capture.
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel>
          <h2 className="border-b border-line-soft px-5 py-4 font-bold">Planted vulnerabilities</h2>
          <ul className="divide-y divide-line-soft">
            {ev.planted_results.map((r) => (
              <li key={r.id} className="flex items-start gap-3 px-5 py-3 text-sm">
                {r.detected ? <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-teal" /> : <XCircle className="mt-0.5 size-4 shrink-0 text-crit" />}
                <span className="flex-1">{r.description}</span>
                <span className="font-mono text-xs text-muted">{r.expected}</span>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel>
          <h2 className="border-b border-line-soft px-5 py-4 font-bold">Safe examples (should stay clean)</h2>
          <ul className="divide-y divide-line-soft">
            {ev.safe_results.map((r) => (
              <li key={r.id} className="flex items-start gap-3 px-5 py-3 text-sm">
                {!r.false_positive ? <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-teal" /> : <XCircle className="mt-0.5 size-4 shrink-0 text-high" />}
                <span className="flex-1">{r.description}</span>
                <span className="font-mono text-xs text-muted">{r.false_positive ? r.rules_fired.join(", ") : "clean"}</span>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </div>
  );
}
