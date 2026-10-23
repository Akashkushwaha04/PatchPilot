import { useEffect, useState } from "react";
import { Bot, BookOpen, CheckCircle2, Code2, ExternalLink, Info, RefreshCcw, ShieldCheck, Sparkles, Wrench } from "lucide-react";
import { api, type Explanation, type Finding, type FindingCorrection, type ApplyFixResult, type Status } from "../api";
import { Button, CopyButton, ErrorBanner, KindBadge, SeverityBadge, Spinner, StatusBadge, STATUS_LABEL, useToast } from "../ui";
import CodeViewer, { Snippet } from "./CodeViewer";

const KIND_HELP: Record<Finding["kind"], string> = {
  confirmed: "A precise pattern match in the code.",
  heuristic: "A pattern that is usually risky, but depends on context.",
  review_candidate: "Not enough evidence to confirm. A person should check whether protection exists elsewhere.",
};

type Tab = "evidence" | "code" | "correct" | "explain";

export default function FindingDetail({ scanId, finding, allFindings, onStatus, onFixPrompt }: {
  scanId: string; finding: Finding; allFindings: Finding[]; onStatus: (f: Finding) => void; onFixPrompt: (ids: string[]) => void;
}) {
  const [tab, setTab] = useState<Tab>("evidence");
  const [exp, setExp] = useState<Explanation | null>(null);
  const [expBusy, setExpBusy] = useState(false);
  const [expErr, setExpErr] = useState<string | null>(null);
  const [statusErr, setStatusErr] = useState<string | null>(null);

  const [correction, setCorrection] = useState<FindingCorrection | null>(null);
  const [correctBusy, setCorrectBusy] = useState(false);
  const [correctErr, setCorrectErr] = useState<string | null>(null);
  const [applyBusy, setApplyBusy] = useState(false);
  const [applyResult, setApplyResult] = useState<ApplyFixResult | null>(null);

  const toast = useToast();

  useEffect(() => {
    setExp(null);
    setExpErr(null);
    setStatusErr(null);
    setCorrection(null);
    setCorrectErr(null);
    setApplyResult(null);
  }, [finding.id]);

  useEffect(() => {
    if (tab === "correct" && !correction && !correctBusy && !correctErr) {
      loadCorrection();
    }
  }, [tab, finding.id]);

  const loadCorrection = async () => {
    setCorrectBusy(true);
    setCorrectErr(null);
    try {
      const res = await api.correctFinding(scanId, finding.id);
      setCorrection(res);
    } catch (e) {
      setCorrectErr((e as Error).message);
    } finally {
      setCorrectBusy(false);
    }
  };

  const applyFix = async (rescan: boolean) => {
    setApplyBusy(true);
    try {
      const res = await api.applyFindingFix(scanId, finding.id, { rescan });
      setApplyResult(res);
      toast(res.rescan_id ? "Fix applied and verified with rescan!" : "Fix applied to file!");
    } catch (e) {
      toast((e as Error).message);
    } finally {
      setApplyBusy(false);
    }
  };

  const explain = async () => {
    setExpBusy(true);
    setExpErr(null);
    try { setExp(await api.explain(scanId, finding.id)); } catch (e) { setExpErr((e as Error).message); } finally { setExpBusy(false); }
  };

  const setStatus = async (s: Status) => {
    setStatusErr(null);
    try {
      const f = await api.setStatus(scanId, finding.id, s);
      onStatus(f);
      toast(`Marked ${STATUS_LABEL[s].toLowerCase()}`);
    } catch (e) { setStatusErr((e as Error).message); }
  };

  const firstLine = Math.max(1, finding.line - 2);
  const tabs: [Tab, string, typeof Info][] = [
    ["evidence", "Evidence and fix", BookOpen],
    ["code", "Code", Code2],
    ["correct", "Correct Code", CheckCircle2],
    ["explain", "AI explanation", Sparkles],
  ];

  return (
    <article className="animate-rise" aria-label={`Finding detail: ${finding.title}`}>
      <header className="space-y-3 border-b border-line-soft p-5">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <KindBadge kind={finding.kind} />
          <StatusBadge status={finding.status} />
          {finding.origin === "browser" && <span className="rounded-md bg-sky/10 px-2 py-0.5 text-xs text-sky">Browser-visible</span>}
        </div>
        <h2 className="text-xl font-bold leading-snug">{finding.title}</h2>
        <p className="font-mono text-xs text-muted">{finding.file}:{finding.line} · {finding.rule_id}{finding.cwe && <> · <a className="hover:text-sky" target="_blank" rel="noreferrer noopener" href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace("CWE-", "")}.html`}>{finding.cwe} <ExternalLink className="inline size-3" /></a></>}</p>
      </header>

      <div role="tablist" className="flex gap-1 border-b border-line-soft px-3">
        {tabs.map(([key, label, Icon]) => (
          <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)}
            className={`-mb-px flex items-center gap-2 border-b-2 px-3 py-3 text-sm ${tab === key ? "border-teal text-fg font-medium" : "border-transparent text-muted hover:text-fg"}`}>
            <Icon className="size-4" /> {label}
            {key === "correct" && <span className="rounded-full bg-teal/20 px-1.5 py-0.2 text-[10px] font-bold text-teal">Auto-fix</span>}
          </button>
        ))}
      </div>

      <div className="space-y-5 p-5">
        {tab === "evidence" && (
          <>
            <section>
              <h3 className="text-sm font-semibold">Why this was flagged</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{finding.evidence}</p>
              <p className="mt-2 text-xs text-dim">Confidence {finding.confidence}. {KIND_HELP[finding.kind]}</p>
            </section>
            <Snippet code={finding.snippet} firstLine={firstLine} highlight={finding.line} />
            <section>
              <h3 className="text-sm font-semibold">What could happen</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{finding.impact}</p>
            </section>
            <section className="rounded-lg border border-teal/25 bg-teal/5 p-4">
              <h3 className="flex items-center gap-2 text-sm font-semibold"><Wrench className="size-4 text-teal" /> Recommended fix</h3>
              <p className="mt-1.5 text-sm leading-relaxed">{finding.remediation}</p>
            </section>
            <p className="text-xs text-dim">{finding.description}</p>
          </>
        )}

        {tab === "code" && <CodeViewer scanId={scanId} path={finding.file} focusLine={finding.line} findings={allFindings} />}

        {tab === "correct" && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-teal/20 bg-teal/5 p-4">
              <div>
                <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
                  <ShieldCheck className="size-5 text-teal" />
                  Automated Code Correction
                </h3>
                <p className="mt-1 text-xs text-muted">
                  Inspect the side-by-side security patch. PatchPilot generates exact replacements to neutralize security flaws while preserving application behavior.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Button variant="secondary" onClick={loadCorrection} disabled={correctBusy} icon={<RefreshCcw className={`size-3.5 ${correctBusy ? "animate-spin" : ""}`} />}>
                  Regenerate
                </Button>
              </div>
            </div>

            {correctBusy && <Spinner label="Generating code correction and diff..." />}
            {correctErr && <ErrorBanner message={correctErr} />}

            {correction && (
              <>
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className={`rounded-md px-2 py-0.5 ${correction.source === "ai" ? "bg-sky/10 text-sky border border-sky/20" : "bg-teal/10 text-teal border border-teal/20"}`}>
                    {correction.source === "ai" ? "AI-Powered Remediation" : "Deterministic Pattern Fix"}
                  </span>
                  <span className="text-muted">Target: <code className="font-mono text-fg">{correction.file}:{correction.line}</code></span>
                </div>

                {correction.explanation && (
                  <div className="rounded-lg border border-line-soft bg-hull p-4 text-xs leading-relaxed text-muted">
                    <p className="font-semibold text-fg mb-1">Security Impact & Rationale</p>
                    <p>{correction.explanation}</p>
                  </div>
                )}

                {/* Structured Diff Viewer */}
                <div className="overflow-hidden rounded-lg border border-line bg-ink">
                  <div className="flex items-center justify-between border-b border-line-soft bg-raised/60 px-4 py-2 text-xs">
                    <span className="font-mono text-muted">
                      {correction.file} (Line {correction.line})
                    </span>
                    <div className="flex items-center gap-2">
                      {correction.fixed_line && (
                        <CopyButton text={correction.fixed_line} label="Copy fixed code" done="Copied!" />
                      )}
                      {correction.diff && (
                        <CopyButton text={correction.diff} label="Copy full diff" done="Diff copied!" />
                      )}
                    </div>
                  </div>

                  {correction.diff_lines && correction.diff_lines.length > 0 ? (
                    <div className="font-mono text-[12.5px] leading-6 scroll-thin overflow-x-auto py-2">
                      {correction.diff_lines.map((line, idx) => {
                        const isDel = line.type === "del";
                        const isAdd = line.type === "add";
                        return (
                          <div
                            key={idx}
                            className={`flex px-3 transition-colors ${
                              isDel
                                ? "bg-red/15 text-red-300 border-l-2 border-red-500"
                                : isAdd
                                ? "bg-emerald-500/15 text-emerald-300 border-l-2 border-emerald-500"
                                : "text-muted hover:bg-raised/20"
                            }`}
                          >
                            <span className="w-8 shrink-0 select-none text-right text-xs opacity-40">
                              {line.old_line ?? ""}
                            </span>
                            <span className="w-8 shrink-0 select-none text-right text-xs opacity-40">
                              {line.new_line ?? ""}
                            </span>
                            <span className="w-6 shrink-0 select-none text-center font-bold">
                              {isDel ? "-" : isAdd ? "+" : " "}
                            </span>
                            <span className="whitespace-pre">{line.text}</span>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-line-soft p-3 font-mono text-xs">
                      <div>
                        <div className="text-[11px] font-semibold uppercase text-red-400 mb-1.5 flex items-center gap-1">
                          <span>🔴 Vulnerable Code</span>
                        </div>
                        <pre className="bg-red/10 border border-red/20 rounded p-2 text-red-200 overflow-x-auto">
                          {correction.original_line || correction.original_snippet}
                        </pre>
                      </div>
                      <div className="pt-3 md:pt-0 md:pl-3">
                        <div className="text-[11px] font-semibold uppercase text-emerald-400 mb-1.5 flex items-center gap-1">
                          <span>🟢 Corrected Code</span>
                        </div>
                        <pre className="bg-emerald-500/10 border border-emerald-500/20 rounded p-2 text-emerald-200 overflow-x-auto">
                          {correction.fixed_line || correction.corrected_snippet}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>

                {/* Apply Actions */}
                <div className="rounded-lg border border-line-soft bg-hull/70 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold">Apply Fix Directly</p>
                      <p className="text-xs text-muted">
                        Patch the scan file directly and run an automated rescan to verify that this vulnerability is resolved.
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <Button
                        variant="primary"
                        onClick={() => applyFix(true)}
                        disabled={applyBusy || !correction.can_apply}
                        icon={<RefreshCcw className={`size-4 ${applyBusy ? "animate-spin" : ""}`} />}
                      >
                        ⚡ Apply Fix & Verify Rescan
                      </Button>
                      <Button
                        variant="secondary"
                        onClick={() => applyFix(false)}
                        disabled={applyBusy || !correction.can_apply}
                        icon={<Wrench className="size-4" />}
                      >
                        Apply to File
                      </Button>
                    </div>
                  </div>

                  {applyResult && (
                    <div className="mt-4 rounded-lg border border-teal/30 bg-teal/10 p-3 text-xs text-fg">
                      <div className="flex items-center gap-2 font-semibold text-teal">
                        <CheckCircle2 className="size-4" />
                        {applyResult.message}
                      </div>
                      {applyResult.rescan_id && (
                        <div className="mt-2 pt-2 border-t border-teal/20 flex items-center justify-between">
                          <span className="text-muted">Verification rescan created successfully:</span>
                          <a
                            href={`#/scans/${applyResult.rescan_id}`}
                            className="font-bold text-teal hover:underline inline-flex items-center gap-1"
                          >
                            Open Verified Rescan ({applyResult.rescan_id}) →
                          </a>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        )}

        {tab === "explain" && (
          <div className="space-y-4">
            {!exp && !expBusy && (
              <div className="rounded-lg border border-line-soft bg-hull/60 p-5 text-sm">
                <p className="flex items-center gap-2 font-semibold"><Bot className="size-4 text-sky" /> Plain-language explanation</p>
                <p className="mt-1.5 leading-relaxed text-muted">
                  Explains what the code does, why it's risky, a realistic attack, a safer version and how to verify the fix.
                  Only the masked snippet is sent to the AI provider, and code comments are treated as untrusted data. Without an AI key, a built-in explanation is used.
                </p>
                <Button className="mt-4" variant="primary" onClick={explain} icon={<Sparkles className="size-4" />}>Explain this finding</Button>
              </div>
            )}
            {expBusy && <Spinner label="Asking for an explanation" />}
            {expErr && <ErrorBanner message={expErr} />}
            {exp && (
              <>
                <p className="flex flex-wrap items-center gap-2 text-xs">
                  <span className={`rounded-md px-2 py-0.5 ${exp.source === "ai" ? "bg-sky/10 text-sky" : "bg-raised text-muted"}`}>
                    {exp.source === "ai" ? `AI-generated (${exp.provider})` : "Built-in explanation"}
                  </span>
                  {exp.source === "ai" && <span className="text-dim">AI suggestion: verify before acting. The scanner finding itself is unchanged.</span>}
                </p>
                {exp.ai_error && <p className="rounded-lg border border-line bg-hull px-3 py-2 text-xs text-muted">{exp.ai_error}</p>}
                {([["What the code does", exp.explanation.what_the_code_does], ["Why it's risky", exp.explanation.why_risky], ["Realistic impact", exp.explanation.impact_example], ["Recommended fix", exp.explanation.recommended_fix]] as const).map(([h, t]) => (
                  <section key={h}><h3 className="text-sm font-semibold">{h}</h3><p className="mt-1 text-sm leading-relaxed text-muted">{t}</p></section>
                ))}
                {exp.explanation.safer_code_example && (
                  <section>
                    <h3 className="mb-1.5 text-sm font-semibold">Safer code</h3>
                    <pre className="scroll-thin overflow-x-auto rounded-lg border border-teal/20 bg-ink p-3 font-mono text-[12.5px] leading-6 text-fg">{exp.explanation.safer_code_example}</pre>
                  </section>
                )}
                <section>
                  <h3 className="text-sm font-semibold">How to verify the fix</h3>
                  <ul className="mt-1.5 list-disc space-y-1 pl-5 text-sm text-muted">{exp.explanation.verification_steps.map((s, i) => <li key={i}>{s}</li>)}</ul>
                </section>
              </>
            )}
          </div>
        )}
      </div>

      <footer className="space-y-3 border-t border-line-soft p-5">
        <div className="flex flex-wrap gap-2">
          <Button
            variant="primary"
            onClick={() => {
              setTab("correct");
              if (!correction) loadCorrection();
            }}
            icon={<Wrench className="size-4 text-emerald-400" />}
          >
            Correct the Code
          </Button>
          <Button variant="secondary" onClick={() => onFixPrompt([finding.id])} icon={<Sparkles className="size-4" />}>
            Generate fix prompt
          </Button>
          <CopyButton text={finding.remediation_text} label="Copy remediation" done="Remediation copied" />
        </div>
        {finding.status === "fixed" ? (
          <p className="text-xs text-teal">Verified fixed by rescan <a className="underline" href={`#/scans/${finding.verified_by}`}>{finding.verified_by}</a>. Status is locked.</p>
        ) : (
          <label className="flex items-center gap-3 text-sm text-muted">
            Status
            <select value={finding.status} onChange={(e) => setStatus(e.target.value as Status)}
              className="rounded-lg border border-line bg-hull px-2.5 py-1.5 text-sm text-fg outline-none focus:border-teal">
              <option value="open">Open</option>
              <option value="needs_review">Needs review</option>
              <option value="accepted_risk">Accepted risk</option>
            </select>
            <span className="text-xs text-dim">"Fixed" is set only by a verified rescan.</span>
          </label>
        )}
        {statusErr && <ErrorBanner message={statusErr} />}
      </footer>
    </article>
  );
}

