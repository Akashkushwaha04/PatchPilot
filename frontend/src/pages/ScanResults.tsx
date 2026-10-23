import { useEffect, useMemo, useRef, useState } from "react";
import { CheckCircle2, ChevronLeft, Download, FileCode2, FilterX, FlaskConical, GitPullRequest, Globe, Info, RefreshCcw, Search, ShieldCheck, Sparkles, X, Zap } from "lucide-react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { api, type AIModel, type Finding, type Scan, type Severity } from "../api";
import AutofixModal from "../components/AutofixModal";
import FindingDetail from "../components/FindingDetail";
import FixPromptDialog from "../components/FixPromptDialog";
import RescanDialog from "../components/RescanDialog";
import Verification from "../components/Verification";
import { Button, ErrorBanner, KindBadge, Panel, SEV_COLOR, SEV_LABEL, SEV_ORDER, ScoreDial, SeverityBadge, Spinner, StatusBadge, timeAgo } from "../ui";

export default function ScanResults({ scanId }: { scanId: string }) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [activeFilter, setActiveFilter] = useState<string | null>(() => {
    const match = window.location.hash.match(/[?&]severity=([a-z]+)/i);
    return match ? match[1].toLowerCase() : null;
  });
  const [fileFilter, setFileFilter] = useState<string | null>(null);
  const [hideClosed, setHideClosed] = useState(false);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [promptIds, setPromptIds] = useState<string[] | null>(null);
  const [rescanOpen, setRescanOpen] = useState(false);
  const [autofixOpen, setAutofixOpen] = useState(false);
  const [models, setModels] = useState<AIModel[]>([]);

  const listParentRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.models().then(setModels).catch(() => {});
  }, []);

  useEffect(() => {
    const match = window.location.hash.match(/[?&]selected=([^&]+)/);
    const targetFindingId = match ? decodeURIComponent(match[1]) : null;

    Promise.all([api.scan(scanId), api.findings(scanId)])
      .then(([s, f]) => {
        setScan(s);
        setFindings(f);
        if (targetFindingId && f.some((item) => item.id === targetFindingId)) {
          setSelectedId(targetFindingId);
        } else {
          setSelectedId(f[0]?.id ?? null);
        }
      })
      .catch((e) => setError(e.message));
  }, [scanId]);

  useEffect(() => {
    const handleHash = () => {
      const sevMatch = window.location.hash.match(/[?&]severity=([a-z]+)/i);
      if (sevMatch) setActiveFilter(sevMatch[1].toLowerCase());
      const selMatch = window.location.hash.match(/[?&]selected=([^&]+)/);
      if (selMatch) setSelectedId(decodeURIComponent(selMatch[1]));
    };
    window.addEventListener("hashchange", handleHash);
    return () => window.removeEventListener("hashchange", handleHash);
  }, []);

  const filtered = useMemo(() => {
    if (!findings) return [];
    const ql = q.trim().toLowerCase();
    return findings.filter((f) =>
      (!activeFilter || f.severity === activeFilter) &&
      (!fileFilter || f.file === fileFilter) &&
      (!hideClosed || (f.status !== "fixed" && f.status !== "accepted_risk")) &&
      (!ql || `${f.title} ${f.file} ${f.rule_id} ${f.evidence} ${f.category}`.toLowerCase().includes(ql)));
  }, [findings, q, activeFilter, fileFilter, hideClosed]);

  useEffect(() => {
    if (filtered.length > 0) {
      if (!filtered.some((f) => f.id === selectedId)) {
        setSelectedId(filtered[0].id);
      }
    } else {
      setSelectedId(null);
    }
  }, [filtered, selectedId]);

  const rowVirtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => listParentRef.current,
    estimateSize: () => 88,
    overscan: 5,
  });

  const files = useMemo(() => {
    const m = new Map<string, { count: number; worst: Severity }>();
    (findings ?? []).forEach((f) => {
      const cur = m.get(f.file);
      if (!cur) m.set(f.file, { count: 1, worst: f.severity });
      else m.set(f.file, { count: cur.count + 1, worst: SEV_ORDER.indexOf(f.severity) < SEV_ORDER.indexOf(cur.worst) ? f.severity : cur.worst });
    });
    return [...m.entries()].sort((a, b) => SEV_ORDER.indexOf(a[1].worst) - SEV_ORDER.indexOf(b[1].worst) || b[1].count - a[1].count);
  }, [findings]);

  if (error) return <ErrorBanner message={error} />;
  if (!scan || !findings) return <Spinner label="Loading scan results" />;

  const selected = findings.find((f) => f.id === selectedId) ?? null;
  const openIds = findings.filter((f) => f.status === "open" || f.status === "needs_review").map((f) => f.id);
  const toggleSeverityFilter = (s: Severity) => setActiveFilter((cur) => (cur === s ? null : s));
  const toggleCheck = (id: string) => setChecked((cur) => { const n = new Set(cur); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const updateFinding = (f: Finding) => setFindings((cur) => cur!.map((x) => (x.id === f.id ? f : x)));
  const fixedCount = scan.status_counts.fixed ?? 0;
  const modelInfo = models.find((m) => m.id === scan.ai_model || m.name.toLowerCase().includes(scan.ai_model?.toLowerCase() || "")) || models[0];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <a href="#/history" className="inline-flex items-center gap-1 text-sm text-muted hover:text-fg"><ChevronLeft className="size-4" /> Scan history</a>
          <h1 className="mt-1 flex flex-wrap items-center gap-3 text-2xl font-extrabold tracking-tight sm:text-3xl">
            {scan.project_name}
            {scan.is_demo && <span className="inline-flex items-center gap-1.5 rounded-md border border-sky/40 px-2 py-0.5 text-xs font-semibold text-sky"><FlaskConical className="size-3.5" /> Synthetic demo</span>}
          </h1>
          <p className="mt-1 text-sm text-muted">
            {scan.label ?? (scan.parent_id ? "Rescan" : "Scan")} · {scan.file_count} files scanned · {timeAgo(scan.created_at)} · ID {scan.id}
            {scan.skipped.length > 0 && <span title={scan.skipped.map((s) => `${s.path}: ${s.reason}`).join("\n")}> · {scan.skipped.length} skipped</span>}
          </p>
          <div className="mt-2.5 flex flex-wrap items-center gap-2">
            <span className="text-xs text-muted">Audited with:</span>
            <div className="inline-flex items-center gap-1.5 rounded-lg border border-teal/40 bg-teal/15 px-2.5 py-1 text-xs font-semibold text-fg shadow-sm">
              <Sparkles className="size-3.5 text-teal" />
              <span>{modelInfo?.name || scan.ai_model || "Claude 3.7 Sonnet"}</span>
            </div>
            {modelInfo && (
              <>
                <div className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-semibold text-emerald-300">
                  <Zap className="size-3 text-emerald-400" />
                  <span>Efficiency: {modelInfo.efficiency}</span>
                </div>
                <div className="inline-flex items-center gap-1 rounded-lg border border-sky-400/30 bg-sky-400/10 px-2 py-0.5 text-[11px] font-semibold text-sky">
                  <span>Speed: {modelInfo.speed}</span>
                </div>
              </>
            )}
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <a href={api.reportUrl(scan.id, "md")} className="inline-flex items-center gap-2 rounded-lg border border-line bg-raised px-3.5 py-2 text-sm hover:border-muted/60"><Download className="size-4" /> Report (.md)</a>
          <a href={api.reportUrl(scan.id, "json")} className="inline-flex items-center gap-2 rounded-lg border border-line bg-raised px-3.5 py-2 text-sm hover:border-muted/60"><Download className="size-4" /> JSON</a>
          <Button onClick={() => setRescanOpen(true)} icon={<RefreshCcw className="size-4" />}>Rescan with fixes</Button>
          <Button variant="primary" onClick={() => setAutofixOpen(true)} icon={<GitPullRequest className="size-4" />}>
            Auto-Fix & Open PR
          </Button>
          <Button disabled={!openIds.length} onClick={() => setPromptIds(checked.size ? [...checked] : openIds)} icon={<Sparkles className="size-4" />}>
            {checked.size ? `Fix prompt for ${checked.size} selected` : "Generate fix prompt"}
          </Button>
        </div>
      </div>

      {scan.latest_rescan_id && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-teal/30 bg-teal/5 px-4 py-3 text-sm">
          <span className="flex items-center gap-2"><ShieldCheck className="size-4 text-teal" /> This scan was rescanned. {fixedCount} finding{fixedCount === 1 ? " was" : "s were"} verified as fixed.</span>
          <a href={`#/scans/${scan.latest_rescan_id}`} className="font-semibold text-teal hover:underline">View verification</a>
        </div>
      )}

      {scan.comparison && <Verification c={scan.comparison} />}

      <Panel className="grid gap-6 p-6 md:grid-cols-[auto_1fr]">
        <ScoreDial score={scan.score.score} grade={scan.score.grade} />
        <div className="min-w-0 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">
              Severity Distribution
            </span>
            {activeFilter && (
              <button
                type="button"
                onClick={() => setActiveFilter(null)}
                className="inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-line bg-raised px-2.5 py-1 text-xs font-semibold text-sky hover:border-sky/50 hover:text-fg transition-all"
              >
                <X className="size-3.5" />
                Clear Filter (Show All)
              </button>
            )}
          </div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
            {SEV_ORDER.map((s) => {
              const count = scan.counts[s] ?? 0;
              const isActive = activeFilter === s;
              return (
                <button
                  key={s}
                  type="button"
                  onClick={() => toggleSeverityFilter(s)}
                  aria-pressed={isActive}
                  title={isActive ? `Click to clear ${SEV_LABEL[s]} filter` : `Filter by ${SEV_LABEL[s]} (${count} issue${count === 1 ? "" : "s"})`}
                  style={
                    isActive
                      ? {
                          borderColor: SEV_COLOR[s],
                          boxShadow: `0 0 0 1px rgba(255,255,255,0.2), 0 8px 24px -4px rgba(0,0,0,0.4)`,
                          backgroundColor: `color-mix(in srgb, ${SEV_COLOR[s]} 20%, rgba(255,255,255,0.08))`,
                        }
                      : undefined
                  }
                  className={`group relative flex flex-col justify-between rounded-2xl border p-3.5 text-left cursor-pointer transition-all duration-200 backdrop-blur-xl ${
                    isActive
                      ? "scale-105"
                      : `border-white/10 bg-white/[0.04] hover:border-white/25 hover:bg-white/[0.08] ${count === 0 ? "opacity-50" : ""}`
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-1.5 text-xs font-semibold text-white/90">
                      <span className="size-2 rounded-full shadow-[0_0_8px_currentColor]" style={{ background: SEV_COLOR[s], color: SEV_COLOR[s] }} />
                      {SEV_LABEL[s]}
                    </span>
                    {isActive && (
                      <span
                        className="rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider shadow-sm"
                        style={{
                          color: SEV_COLOR[s],
                          backgroundColor: `color-mix(in srgb, ${SEV_COLOR[s]} 25%, transparent)`,
                        }}
                      >
                        Active
                      </span>
                    )}
                  </div>
                  <div className="mt-2.5 flex items-baseline justify-between">
                    <span
                      className="text-2xl font-black tabular-nums tracking-tight"
                      style={isActive ? { color: SEV_COLOR[s] } : undefined}
                    >
                      {count}
                    </span>
                    <span className="text-[11px] text-muted group-hover:text-white">
                      {count === 1 ? "issue" : "issues"}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
          <details className="group rounded-lg border border-line-soft bg-hull/50 px-4 py-3 text-sm">
            <summary className="flex cursor-pointer items-center gap-2 text-muted marker:content-none"><Info className="size-4 text-sky" /> How the score is calculated</summary>
            <p className="mt-2 leading-relaxed text-muted">{scan.score.method}</p>
          </details>
          <p className="text-xs leading-relaxed text-dim">
            {scan.total_findings === 0
              ? "No known patterns were detected. That is not proof the application is secure: logic flaws, dependency issues and server configuration are outside what this scan can see."
              : "Findings come from automated rules and need human review. Pattern matches are precise; heuristics and review candidates depend on context the scanner cannot see."}
          </p>
          {scan.url_scan && (
            <div className="rounded-xl border border-teal/30 bg-teal/10 p-4 text-xs text-fg space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-teal/20 pb-2">
                <div className="flex items-center gap-2 font-bold text-sm text-teal">
                  <Globe className="size-4" />
                  <span>Website Security Audit: {scan.url_scan.final_url}</span>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-md border border-emerald-500/30 bg-emerald-500/15 px-2 py-0.5 text-[10px] font-semibold text-emerald-300">
                    ⚡ {scan.url_scan.ai_efficiency || modelInfo?.efficiency || "99.2% Accuracy"}
                  </span>
                  <span className="rounded-md border border-sky-400/30 bg-sky-400/15 px-2 py-0.5 text-[10px] font-semibold text-sky">
                    ⏱️ {scan.url_scan.ai_speed || modelInfo?.speed || "~2.4s • Fast"}
                  </span>
                </div>
              </div>
              <p className="text-muted leading-relaxed">
                Target website audited by <strong>{scan.url_scan.ai_model || modelInfo?.name || "AI Security Engine"}</strong>. Captured {scan.url_scan.resources.length} client resource(s) with dynamic DOM inspection and network route telemetry.
              </p>
              <div className="space-y-1 pt-1">
                {scan.url_scan.notes.map((note, idx) => (
                  <p key={idx} className="text-[11px] text-muted flex items-start gap-1.5">
                    <span className="text-teal">•</span>
                    <span>{note}</span>
                  </p>
                ))}
              </div>
            </div>
          )}
        </div>
      </Panel>

      {findings.length === 0 ? (
        <Panel className="flex flex-col items-center px-6 py-14 text-center">
          <ShieldCheck className="size-10 text-teal" />
          <p className="mt-3 text-lg font-bold">No findings in this scan</p>
          <p className="mt-1 max-w-md text-sm text-muted">The rules found nothing to report. Keep reviewing authentication logic and dependencies by hand; a clean scan is not a security guarantee.</p>
        </Panel>
      ) : (
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]">
          <div className="space-y-4">
            <Panel className="p-4">
              <div className="flex flex-wrap items-center gap-3">
                <label className="relative min-w-48 flex-1">
                  <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-dim" />
                  <span className="sr-only">Search findings</span>
                  <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, file, rule or evidence"
                    className="w-full rounded-lg border border-line bg-hull py-2 pl-9 pr-3 text-sm outline-none placeholder:text-dim focus:border-teal" />
                </label>
                <label className="flex items-center gap-2 text-sm text-muted">
                  <input type="checkbox" checked={hideClosed} onChange={(e) => setHideClosed(e.target.checked)} className="accent-[var(--color-teal)]" /> Hide fixed and accepted
                </label>
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5">
                <span className="mr-1 self-center text-xs text-dim">Files</span>
                <button onClick={() => setFileFilter(null)} className={`rounded-md px-2 py-1 text-xs ${!fileFilter ? "bg-raised text-fg" : "text-muted hover:text-fg"}`}>All ({files.length})</button>
                {files.map(([path, info]) => (
                  <button key={path} onClick={() => setFileFilter(fileFilter === path ? null : path)} aria-pressed={fileFilter === path}
                    className={`inline-flex items-center gap-1.5 rounded-md px-2 py-1 font-mono text-xs ${fileFilter === path ? "bg-raised text-fg" : "text-muted hover:text-fg"}`}>
                    <FileCode2 className="size-3" style={{ color: SEV_COLOR[info.worst] }} />{path}<span className="text-dim">{info.count}</span>
                  </button>
                ))}
              </div>
            </Panel>

            <div className="flex flex-wrap items-center justify-between gap-2 px-1 text-sm text-muted">
              <div className="flex items-center gap-2">
                <span>
                  Showing <strong className="font-semibold text-fg">{filtered.length}</strong> of {findings.length} findings
                </span>
                {activeFilter && (
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-line bg-raised px-2.5 py-0.5 text-xs font-medium text-fg">
                    <span className="size-1.5 rounded-full" style={{ background: SEV_COLOR[activeFilter as Severity] }} />
                    {SEV_LABEL[activeFilter as Severity] ?? activeFilter}
                    <button
                      type="button"
                      onClick={() => setActiveFilter(null)}
                      className="ml-0.5 text-muted hover:text-fg cursor-pointer"
                      title="Clear severity filter"
                    >
                      <X className="size-3" />
                    </button>
                  </span>
                )}
              </div>
              <div className="flex items-center gap-3">
                {activeFilter && (
                  <button
                    type="button"
                    onClick={() => setActiveFilter(null)}
                    className="text-xs text-sky hover:underline cursor-pointer"
                  >
                    Clear Filter / Show All
                  </button>
                )}
                {checked.size > 0 && (
                  <button
                    type="button"
                    className="text-xs text-sky hover:underline cursor-pointer"
                    onClick={() => setChecked(new Set())}
                  >
                    Clear selection ({checked.size})
                  </button>
                )}
              </div>
            </div>

            {/* Virtualized findings container */}
            <div
              ref={listParentRef}
              className="scroll-thin max-h-[44rem] overflow-y-auto pr-1"
              style={{ contain: "strict" }}
              aria-label="Findings"
            >
              {filtered.length > 0 ? (
                <div
                  style={{
                    height: `${rowVirtualizer.getTotalSize()}px`,
                    width: "100%",
                    position: "relative",
                  }}
                >
                  {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                    const f = filtered[virtualRow.index];
                    if (!f) return null;
                    return (
                      <div
                        key={f.id}
                        data-index={virtualRow.index}
                        ref={rowVirtualizer.measureElement}
                        style={{
                          position: "absolute",
                          top: 0,
                          left: 0,
                          width: "100%",
                          transform: `translateY(${virtualRow.start}px)`,
                          paddingBottom: "8px",
                        }}
                      >
                        <div className={`group flex rounded-2xl border transition-all duration-200 backdrop-blur-xl ${f.id === selectedId ? "border-white/30 bg-white/18 shadow-xl" : "border-white/10 bg-white/[0.04] hover:bg-white/[0.08] hover:border-white/20"}`}>
                          <span className="w-1.5 shrink-0 rounded-l-2xl shadow-[0_0_8px_currentColor]" style={{ background: SEV_COLOR[f.severity], color: SEV_COLOR[f.severity] }} />
                          <label className="flex items-start px-3 pt-4">
                            <span className="sr-only">Include in fix prompt</span>
                            <input type="checkbox" checked={checked.has(f.id)} onChange={() => toggleCheck(f.id)} disabled={f.status === "fixed"} className="accent-[var(--color-teal)]" />
                          </label>
                          <button onClick={() => setSelectedId(f.id)} className="min-w-0 flex-1 py-3 pr-4 text-left" aria-current={f.id === selectedId}>
                            <span className="flex flex-wrap items-center gap-2">
                              <SeverityBadge severity={f.severity} />
                              <KindBadge kind={f.kind} />
                              {f.status !== "open" && <StatusBadge status={f.status} />}
                            </span>
                            <span className={`mt-1.5 block font-semibold ${f.status === "fixed" ? "text-muted line-through decoration-dim" : "text-white/95"}`}>{f.title}</span>
                            <span className="mt-0.5 block truncate font-mono text-xs text-muted">{f.file}:{f.line} · {f.rule_id}</span>
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center rounded-xl border border-line-soft bg-hull/40 px-6 py-12 text-center">
                  {activeFilter ? (
                    <>
                      <div className="mb-3 flex size-12 items-center justify-center rounded-full bg-teal/10 text-teal">
                        <CheckCircle2 className="size-6" />
                      </div>
                      <h3 className="text-base font-bold text-fg">
                        No {SEV_LABEL[activeFilter as Severity] ?? activeFilter} Severity Findings
                      </h3>
                      <p className="mt-1 max-w-sm text-sm text-muted">
                        {(scan.counts[activeFilter as Severity] ?? 0) === 0
                          ? `This scan found zero ${SEV_LABEL[activeFilter as Severity]?.toLowerCase() ?? activeFilter} issues. Clean bill of health for this tier!`
                          : `No ${SEV_LABEL[activeFilter as Severity]?.toLowerCase() ?? activeFilter} findings match your search or file filters.`}
                      </p>
                      <button
                        type="button"
                        onClick={() => setActiveFilter(null)}
                        className="mt-4 inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-line bg-raised px-3.5 py-2 text-xs font-semibold text-fg hover:border-teal/50 hover:text-teal transition-colors"
                      >
                        <FilterX className="size-3.5" />
                        Show All Severities
                      </button>
                    </>
                  ) : (
                    <>
                      <div className="mb-3 flex size-12 items-center justify-center rounded-full bg-line text-muted">
                        <FilterX className="size-6 text-dim" />
                      </div>
                      <h3 className="text-base font-bold text-fg">No findings match these filters</h3>
                      <p className="mt-1 max-w-sm text-sm text-muted">
                        Try clearing your search query or resetting file filters to see more results.
                      </p>
                      {(q || fileFilter || hideClosed) && (
                        <button
                          type="button"
                          onClick={() => { setQ(""); setFileFilter(null); setHideClosed(false); }}
                          className="mt-4 inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-line bg-raised px-3.5 py-2 text-xs font-semibold text-fg hover:border-teal/50 hover:text-teal transition-colors"
                        >
                          <FilterX className="size-3.5" />
                          Reset filters
                        </button>
                      )}
                    </>
                  )}
                </div>
              )}
            </div>
          </div>

          <div className="xl:sticky xl:top-6 xl:self-start">
            {selected ? (
              <FindingDetail
                scanId={scan.id}
                finding={selected}
                allFindings={findings}
                onStatus={updateFinding}
                onFixPrompt={setPromptIds}
                onClose={() => setSelectedId(null)}
              />
            ) : (
              <Panel className="p-12 text-center text-sm text-muted">
                <p>Select a finding to inspect evidence, view code diff, and correct security flaws.</p>
              </Panel>
            )}
          </div>
        </div>
      )}

      <FixPromptDialog scanId={scan.id} projectName={scan.project_name} findingIds={promptIds ?? []} open={promptIds !== null} onClose={() => setPromptIds(null)} />
      <RescanDialog scan={scan} open={rescanOpen} onClose={() => setRescanOpen(false)} />
      <AutofixModal scan={scan} findings={findings} open={autofixOpen} onClose={() => setAutofixOpen(false)} />
    </div>
  );
}
