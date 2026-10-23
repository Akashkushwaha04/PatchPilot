import { useState } from "react";
import { ArrowRightLeft, CheckCircle2, CircleDot, PlusCircle, ShieldCheck } from "lucide-react";
import type { Comparison, Finding } from "../api";
import { Panel, SEV_LABEL, ScoreDial, SeverityBadge, gradeFor } from "../ui";

type Group = "resolved" | "remaining" | "new";

function Row({ f, note, extra }: { f: Finding; note?: string; extra?: string }) {
  return (
    <li className="grid grid-cols-[auto_1fr] gap-3 px-4 py-3">
      <SeverityBadge severity={f.severity} compact />
      <div className="min-w-0">
        <p className="text-sm font-semibold">{f.title}</p>
        <p className="font-mono text-xs text-muted">{f.file}:{f.line} · {f.rule_id}{extra && <span className="text-med"> · {extra}</span>}</p>
        {note && <p className="mt-1 text-xs text-dim">{note}</p>}
      </div>
    </li>
  );
}

export default function Verification({ c }: { c: Comparison }) {
  const [tab, setTab] = useState<Group>(c.new.length ? "new" : "resolved");
  const groups: { key: Group; label: string; count: number; icon: typeof CircleDot; tone: string }[] = [
    { key: "resolved", label: "Resolved", count: c.resolved.length, icon: CheckCircle2, tone: "text-teal" },
    { key: "remaining", label: "Remaining", count: c.remaining.length, icon: CircleDot, tone: "text-med" },
    { key: "new", label: "Newly introduced", count: c.new.length, icon: PlusCircle, tone: "text-crit" },
  ];
  const delta = c.after_score - c.before_score;

  return (
    <Panel className="overflow-hidden">
      <div className="grid gap-6 border-b border-line-soft p-6 lg:grid-cols-[auto_1fr]">
        <div className="flex items-center gap-2">
          <ScoreDial score={c.before_score} grade={gradeFor(c.before_score)} size={150} label="Before" />
          <ArrowRightLeft className="size-5 text-dim" aria-hidden="true" />
          <ScoreDial score={c.after_score} grade={gradeFor(c.after_score)} size={150} label={`After rescan (${delta >= 0 ? "+" : ""}${delta})`} ghost={c.before_score} />
        </div>
        <div className="min-w-0">
          <h2 className="flex items-center gap-2 text-lg font-bold"><ShieldCheck className="size-5 text-teal" /> Fix verification</h2>
          <p className="mt-2 text-sm leading-relaxed">{c.summary}</p>
          <p className="mt-3 text-xs leading-relaxed text-dim">
            Verified by running the same scanner on the new upload, not by trusting a claim from you or an AI. {c.method}
          </p>
          {c.severity_changes.length > 0 && (
            <ul className="mt-3 space-y-1 text-xs text-muted">
              {c.severity_changes.map((s, i) => <li key={i}>Severity changed: {s.rule_id} at {s.file}:{s.line}, {SEV_LABEL[s.from]} to {SEV_LABEL[s.to]}</li>)}
            </ul>
          )}
          <a href={`#/scans/${c.parent_id}`} className="mt-3 inline-block text-sm text-sky hover:underline">Open the original scan</a>
        </div>
      </div>
      <div role="tablist" className="flex flex-wrap gap-1 border-b border-line-soft px-3">
        {groups.map(({ key, label, count, icon: Icon, tone }) => (
          <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)}
            className={`-mb-px flex items-center gap-2 border-b-2 px-3 py-3 text-sm ${tab === key ? "border-teal text-fg" : "border-transparent text-muted hover:text-fg"}`}>
            <Icon className={`size-4 ${tone}`} /> {label} <span className="rounded bg-raised px-1.5 text-xs tabular-nums">{count}</span>
          </button>
        ))}
      </div>
      <ul className="max-h-96 divide-y divide-line-soft overflow-y-auto scroll-thin">
        {tab === "resolved" && (c.resolved.length ? c.resolved.map((r) => <Row key={r.finding.fingerprint + r.finding.line} f={r.finding} note={r.verification} />) : <Empty text="Nothing from the original scan was resolved." />)}
        {tab === "remaining" && (c.remaining.length ? c.remaining.map((r) => (
          <Row key={r.after.fingerprint + r.after.line} f={r.after}
            extra={r.before.line !== r.after.line ? `moved from line ${r.before.line}` : undefined}
            note={r.matched_by === "fingerprint" ? "Same rule, file and code line as before." : "Same rule and file, nearby line with edited code."} />
        )) : <Empty text="No original findings remain." />)}
        {tab === "new" && (c.new.length ? c.new.map((f) => <Row key={f.fingerprint + f.line} f={f} note="Not present in the original scan. Fixes sometimes introduce new issues." />) : <Empty text="The rescan introduced no new findings." />)}
      </ul>
    </Panel>
  );
}

const Empty = ({ text }: { text: string }) => <li className="px-4 py-8 text-center text-sm text-muted">{text}</li>;
