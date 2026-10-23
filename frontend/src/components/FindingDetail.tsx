import { useEffect, useState } from "react";
import { Bot, BookOpen, CheckCircle2, Code2, ExternalLink, Play, RefreshCcw, ShieldCheck, Sparkles, Wrench, X } from "lucide-react";
import { api, type Explanation, type Finding, type FindingCorrection, type ApplyFixResult, type Status } from "../api";
import { Button, CopyButton, ErrorBanner, KindBadge, SeverityBadge, Spinner, StatusBadge, STATUS_LABEL, SpatialHandle, useToast } from "../ui";
import CodeViewer, { Snippet } from "./CodeViewer";

const KIND_HELP: Record<Finding["kind"], string> = {
  confirmed: "A precise pattern match in the code.",
  heuristic: "A pattern that is usually risky, but depends on context.",
  review_candidate: "Not enough evidence to confirm. A person should check whether protection exists elsewhere.",
};

type Tab = "evidence" | "code" | "correct" | "explain";

export default function FindingDetail({ scanId, finding, allFindings, onStatus, onFixPrompt, onClose }: {
  scanId: string; finding: Finding; allFindings: Finding[]; onStatus: (f: Finding) => void; onFixPrompt: (ids: string[]) => void; onClose?: () => void;
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
  const tabs: [Tab, string, typeof BookOpen][] = [
    ["evidence", "Info", BookOpen],
    ["code", "Code", Code2],
    ["correct", "Correct Code", CheckCircle2],
    ["explain", "AI Explain", Sparkles],
  ];

  return (
    <article className="animate-rise relative flex flex-col liquid-panel p-2 sm:p-5 overflow-hidden" aria-label={`Finding detail: ${finding.title}`}>
      {/* Top VisionOS Liquid Navigation Bar */}
      <div className="flex items-center justify-between gap-3 border-b border-white/10 pb-4 px-2">
        <button
          type="button"
          onClick={onClose}
          className="size-9 shrink-0 rounded-full bg-white/12 hover:bg-white/22 active:scale-95 border border-white/20 backdrop-blur-xl flex items-center justify-center text-white/80 hover:text-white transition-all shadow-sm"
          title="Close details"
          aria-label="Close"
        >
          <X className="size-4" />
        </button>

        {/* Centered Segmented Control */}
        <div role="tablist" className="liquid-pill-container p-1 flex items-center gap-1">
          {tabs.map(([key, label, Icon]) => {
            const isActive = tab === key;
            return (
              <button
                key={key}
                role="tab"
                aria-selected={isActive}
                onClick={() => setTab(key)}
                className={`flex items-center gap-1.5 rounded-full px-3.5 py-1.5 text-xs font-medium transition-all duration-200 ${
                  isActive
                    ? "liquid-pill-active font-semibold shadow-md"
                    : "text-white/60 hover:text-white hover:bg-white/10"
                }`}
              >
                <Icon className="size-3.5" />
                {label}
                {key === "correct" && (
                  <span className="size-1.5 rounded-full bg-teal animate-pulse" />
                )}
              </button>
            );
          })}
        </div>

        <div className="w-9 shrink-0" aria-hidden="true" />
      </div>

      {/* VisionOS Floating Media Header (Astonishing Style Row) */}
      <div className="mt-4 rounded-2xl border border-white/10 bg-white/[0.04] p-4 backdrop-blur-xl">
        <div className="grid grid-cols-1 lg:grid-cols-[200px_minmax(0,1fr)_auto] gap-4 items-center">
          {/* Left Thumbnail / Code Preview Box */}
          <div className="h-28 rounded-xl overflow-hidden border border-white/15 bg-black/40 p-2 font-mono text-[10px] text-muted flex flex-col justify-between shadow-inner relative group">
            <div className="flex items-center justify-between text-dim border-b border-white/10 pb-1">
              <span className="truncate max-w-[120px]">{finding.file.split("/").pop()}</span>
              <span className="text-teal font-semibold">:{finding.line}</span>
            </div>
            <pre className="overflow-hidden leading-tight text-white/80 select-none opacity-90 line-clamp-3">
              {finding.snippet || finding.evidence}
            </pre>
            <div className="flex items-center justify-between text-[9px] text-dim pt-1 border-t border-white/5">
              <span>{finding.rule_id}</span>
              <span className="text-teal/80 font-bold uppercase">{finding.severity}</span>
            </div>
          </div>

          {/* Middle Synopsis & Metadata */}
          <div className="space-y-1.5 min-w-0">
            <h2 className="text-lg sm:text-xl font-extrabold tracking-tight text-white leading-snug truncate">
              {finding.title}
            </h2>
            <p className="text-xs text-white/70 line-clamp-2 leading-relaxed">
              {finding.evidence || finding.impact}
            </p>
            <div className="flex flex-wrap items-center gap-1.5 pt-1 text-xs text-white/60">
              <span className="font-medium text-white/80">{finding.category || "Security"}</span>
              <span>·</span>
              <span className="font-mono">{finding.file}:{finding.line}</span>
              <span>·</span>
              <SeverityBadge severity={finding.severity} compact />
              <KindBadge kind={finding.kind} />
              <StatusBadge status={finding.status} />
              {finding.cwe && (
                <a
                  className="rounded-full border border-white/20 bg-white/5 px-2 py-0.5 text-[11px] font-mono text-white/80 hover:text-teal hover:border-teal/40 transition-colors inline-flex items-center gap-1"
                  target="_blank"
                  rel="noreferrer noopener"
                  href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace("CWE-", "")}.html`}
                >
                  {finding.cwe} <ExternalLink className="size-2.5" />
                </a>
              )}
            </div>
          </div>

          {/* Right Action Glass Buttons (VisionOS Style Vertical Stack) */}
          <div className="flex flex-col sm:flex-row lg:flex-col gap-2 shrink-0">
            <button
              onClick={() => {
                setTab("correct");
                if (!correction) loadCorrection();
              }}
              className="liquid-btn-primary px-4 py-2.5 text-xs font-semibold flex items-center justify-center gap-2 shadow-lg"
            >
              <Play className="size-3.5 fill-current text-teal" />
              <span>Correct the Code</span>
            </button>
            <button
              onClick={() => onFixPrompt([finding.id])}
              className="liquid-btn-secondary px-4 py-2 text-xs font-medium flex items-center justify-center gap-2"
            >
              <Sparkles className="size-3.5 text-sky" />
              <span>Fix Prompt</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Tab Panels */}
      <div className="mt-4 flex-1 space-y-4">
        {tab === "evidence" && (
          <div className="space-y-4">
            <section className="rounded-2xl border border-white/10 bg-white/[0.03] p-4 backdrop-blur-md">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-muted">Flagged Evidence</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-fg">{finding.evidence}</p>
              <p className="mt-2 text-xs text-dim">Confidence: {finding.confidence}. {KIND_HELP[finding.kind]}</p>
            </section>
            <div className="rounded-2xl overflow-hidden border border-white/10 shadow-lg">
              <Snippet code={finding.snippet} firstLine={firstLine} highlight={finding.line} />
            </div>
            <section className="rounded-2xl border border-white/10 bg-white/[0.03] p-4 backdrop-blur-md">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-muted">Security Impact</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-fg">{finding.impact}</p>
            </section>
            <section className="rounded-2xl border border-teal/30 bg-teal/10 p-4 backdrop-blur-md">
              <h3 className="flex items-center gap-2 text-sm font-semibold text-teal"><Wrench className="size-4" /> Recommended Remediation</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-fg/90">{finding.remediation}</p>
            </section>
          </div>
        )}

        {tab === "code" && (
          <div className="rounded-2xl overflow-hidden border border-white/10 shadow-lg">
            <CodeViewer scanId={scanId} path={finding.file} focusLine={finding.line} findings={allFindings} />
          </div>
        )}

        {tab === "correct" && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-teal/30 bg-teal/10 p-4 backdrop-blur-md">
              <div>
                <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
                  <ShieldCheck className="size-5 text-teal" />
                  Automated Security Fix
                </h3>
                <p className="mt-1 text-xs text-muted">
                  Inspect the side-by-side patch. PatchPilot generates exact replacements to neutralize vulnerabilities while preserving application functionality.
                </p>
              </div>
              <Button variant="secondary" onClick={loadCorrection} disabled={correctBusy} icon={<RefreshCcw className={`size-3.5 ${correctBusy ? "animate-spin" : ""}`} />}>
                Regenerate
              </Button>
            </div>

            {correctBusy && <Spinner label="Generating code correction and diff..." />}
            {correctErr && <ErrorBanner message={correctErr} />}

            {correction && (
              <>
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className={`rounded-full px-3 py-0.5 border ${correction.source === "ai" ? "bg-sky/15 text-sky border-sky/30" : "bg-teal/15 text-teal border-teal/30"}`}>
                    {correction.source === "ai" ? "AI-Powered Remediation" : "Deterministic Pattern Fix"}
                  </span>
                  <span className="text-muted">Target: <code className="font-mono text-fg">{correction.file}:{correction.line}</code></span>
                </div>

                {correction.explanation && (
                  <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-4 text-xs leading-relaxed text-muted backdrop-blur-md">
                    <p className="font-semibold text-fg mb-1">Security Impact & Rationale</p>
                    <p>{correction.explanation}</p>
                  </div>
                )}

                {/* Structured Diff Viewer with Liquid Styling */}
                <div className="overflow-hidden rounded-2xl border border-white/15 bg-black/50 shadow-2xl backdrop-blur-xl">
                  <div className="flex items-center justify-between border-b border-white/10 bg-white/[0.04] px-4 py-2.5 text-xs">
                    <span className="font-mono text-white/80">
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
                                ? "bg-red-500/20 text-red-200 border-l-2 border-red-500"
                                : isAdd
                                ? "bg-emerald-500/20 text-emerald-200 border-l-2 border-emerald-400"
                                : "text-white/70 hover:bg-white/[0.03]"
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
                    <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-white/10 p-3 font-mono text-xs">
                      <div>
                        <div className="text-[11px] font-semibold uppercase text-red-400 mb-1.5 flex items-center gap-1">
                          <span>🔴 Vulnerable Code</span>
                        </div>
                        <pre className="bg-red-500/10 border border-red-500/20 rounded-xl p-3 text-red-200 overflow-x-auto">
                          {correction.original_line || correction.original_snippet}
                        </pre>
                      </div>
                      <div className="pt-3 md:pt-0 md:pl-3">
                        <div className="text-[11px] font-semibold uppercase text-emerald-400 mb-1.5 flex items-center gap-1">
                          <span>🟢 Corrected Code</span>
                        </div>
                        <pre className="bg-emerald-500/10 border border-emerald-500/20 rounded-xl p-3 text-emerald-200 overflow-x-auto">
                          {correction.fixed_line || correction.corrected_snippet}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>

                {/* Apply Actions */}
                <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-4 backdrop-blur-md">
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
                    <div className="mt-4 rounded-2xl border border-teal/30 bg-teal/15 p-3 text-xs text-fg backdrop-blur-md">
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
              <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-5 text-sm backdrop-blur-md">
                <p className="flex items-center gap-2 font-semibold"><Bot className="size-4 text-sky" /> Plain-language explanation</p>
                <p className="mt-1.5 leading-relaxed text-muted">
                  Explains what the code does, why it's risky, a realistic attack, a safer version and how to verify the fix.
                  Without an AI key, a built-in explanation is used.
                </p>
                <Button className="mt-4" variant="primary" onClick={explain} icon={<Sparkles className="size-4" />}>Explain this finding</Button>
              </div>
            )}
            {expBusy && <Spinner label="Asking for an explanation" />}
            {expErr && <ErrorBanner message={expErr} />}
            {exp && (
              <>
                <p className="flex flex-wrap items-center gap-2 text-xs">
                  <span className={`rounded-full px-3 py-0.5 border ${exp.source === "ai" ? "bg-sky/15 text-sky border-sky/30" : "bg-white/10 text-muted border-white/15"}`}>
                    {exp.source === "ai" ? `AI-generated (${exp.provider})` : "Built-in explanation"}
                  </span>
                </p>
                {exp.ai_error && <p className="rounded-2xl border border-white/10 bg-white/5 px-3 py-2 text-xs text-muted">{exp.ai_error}</p>}
                {([["What the code does", exp.explanation.what_the_code_does], ["Why it's risky", exp.explanation.why_risky], ["Realistic impact", exp.explanation.impact_example], ["Recommended fix", exp.explanation.recommended_fix]] as const).map(([h, t]) => (
                  <section key={h} className="rounded-2xl border border-white/10 bg-white/[0.03] p-4 backdrop-blur-md">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-muted">{h}</h3>
                    <p className="mt-1 text-sm leading-relaxed text-fg">{t}</p>
                  </section>
                ))}
                {exp.explanation.safer_code_example && (
                  <section className="rounded-2xl border border-white/10 bg-white/[0.03] p-4 backdrop-blur-md">
                    <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">Safer code</h3>
                    <pre className="scroll-thin overflow-x-auto rounded-xl border border-teal/20 bg-black/40 p-3 font-mono text-[12.5px] leading-6 text-fg">{exp.explanation.safer_code_example}</pre>
                  </section>
                )}
                <section className="rounded-2xl border border-white/10 bg-white/[0.03] p-4 backdrop-blur-md">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-muted">How to verify the fix</h3>
                  <ul className="mt-1.5 list-disc space-y-1 pl-5 text-sm text-muted">{exp.explanation.verification_steps.map((s, i) => <li key={i}>{s}</li>)}</ul>
                </section>
              </>
            )}
          </div>
        )}
      </div>

      {/* Footer / Status */}
      <footer className="mt-4 pt-4 border-t border-white/10 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2">
          {finding.status === "fixed" ? (
            <p className="text-teal font-medium flex items-center gap-1.5">
              <CheckCircle2 className="size-4" />
              Verified fixed by rescan <a className="underline" href={`#/scans/${finding.verified_by}`}>{finding.verified_by}</a>
            </p>
          ) : (
            <label className="flex items-center gap-2 text-muted">
              <span>Status:</span>
              <select
                value={finding.status}
                onChange={(e) => setStatus(e.target.value as Status)}
                className="rounded-full border border-white/15 bg-black/40 px-3 py-1 text-xs text-white outline-none focus:border-teal backdrop-blur-md"
              >
                <option value="open">Open</option>
                <option value="needs_review">Needs review</option>
                <option value="accepted_risk">Accepted risk</option>
              </select>
            </label>
          )}
        </div>
        <CopyButton text={finding.remediation_text} label="Copy remediation" done="Remediation copied" />
      </footer>

      {statusErr && <div className="mt-2"><ErrorBanner message={statusErr} /></div>}

      {/* Bottom Spatial Drag Handle from VisionOS Preview */}
      <SpatialHandle className="mt-2" />
    </article>
  );
}

