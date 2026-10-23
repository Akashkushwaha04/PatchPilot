import { useEffect, useMemo, useState } from "react";
import { ArrowRight, CheckCircle2, FilterX, Search } from "lucide-react";
import { api, type GlobalFinding, type Severity } from "../api";
import Dialog from "./Dialog";
import { SEV_COLOR, SEV_LABEL, SEV_ORDER, SeverityBadge, Spinner, StatusBadge, go } from "../ui";

interface Props {
  open: boolean;
  onClose: () => void;
  initialSeverity: Severity;
  counts: Record<Severity, number>;
}

export default function SeverityFindingsDialog({
  open,
  onClose,
  initialSeverity,
  counts,
}: Props) {
  const [activeSev, setActiveSev] = useState<Severity>(initialSeverity);
  const [findings, setFindings] = useState<GlobalFinding[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  // Sync active severity when modal opens with a new initial severity
  useEffect(() => {
    if (open) {
      setActiveSev(initialSeverity);
      setQuery("");
    }
  }, [open, initialSeverity]);

  // Fetch findings for the active severity tier
  useEffect(() => {
    if (!open) return;
    setLoading(true);
    setError(null);
    api.allFindings(activeSev)
      .then((data) => setFindings(data))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [open, activeSev]);

  const filtered = useMemo(() => {
    if (!findings) return [];
    const q = query.trim().toLowerCase();
    if (!q) return findings;
    return findings.filter((f) =>
      `${f.title} ${f.rule_id} ${f.file} ${f.project_name} ${f.evidence || ""} ${f.snippet || ""}`
        .toLowerCase()
        .includes(q)
    );
  }, [findings, query]);

  const totalForSev = counts[activeSev] ?? (findings?.length || 0);

  const handleOpenScan = (scanId: string, findingId?: string) => {
    onClose();
    // Navigate to scan with severity filter and selected finding ID
    go(`/scans/${scanId}?severity=${activeSev}${findingId ? `&selected=${findingId}` : ""}`);
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`${SEV_LABEL[activeSev]} Findings (${totalForSev})`}
      wide
    >
      <div className="space-y-4">
        {/* Severity selection switcher tabs */}
        <div className="flex flex-wrap items-center gap-2 border-b border-line-soft pb-3">
          <span className="text-xs font-semibold uppercase tracking-wider text-muted mr-1">
            Severity:
          </span>
          {SEV_ORDER.filter((s) => s !== "info" || (counts[s] ?? 0) > 0).map((s) => {
            const count = counts[s] ?? 0;
            const isSelected = activeSev === s;
            return (
              <button
                key={s}
                type="button"
                onClick={() => setActiveSev(s)}
                aria-pressed={isSelected}
                className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold cursor-pointer transition-all duration-150 ${
                  isSelected
                    ? "bg-raised border border-fg/30 text-fg shadow-sm scale-105"
                    : "border border-line-soft bg-hull/40 text-muted hover:border-line hover:text-fg hover:bg-raised/50"
                }`}
              >
                <span className="size-2 rounded-full" style={{ background: SEV_COLOR[s] }} />
                {SEV_LABEL[s]}
                <span className={`rounded-full px-1.5 py-0.2 text-[10px] tabular-nums ${isSelected ? "bg-panel text-fg" : "text-dim"}`}>
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Search bar inside dialog */}
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-dim" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={`Search ${SEV_LABEL[activeSev].toLowerCase()} findings by rule, file, or project...`}
              className="w-full rounded-lg border border-line bg-hull py-2 pl-9 pr-3 text-sm outline-none placeholder:text-dim focus:border-teal"
            />
          </div>
          {query && (
            <button
              type="button"
              onClick={() => setQuery("")}
              className="rounded-lg border border-line px-3 py-2 text-xs font-semibold text-muted hover:text-fg cursor-pointer"
            >
              Clear
            </button>
          )}
        </div>

        {/* Content list */}
        {loading ? (
          <div className="py-12 flex justify-center">
            <Spinner label={`Loading ${SEV_LABEL[activeSev].toLowerCase()} findings...`} />
          </div>
        ) : error ? (
          <div className="rounded-xl border border-crit/40 bg-crit/10 p-4 text-center text-sm text-crit">
            {error}
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-xl border border-line-soft bg-hull/40 px-6 py-12 text-center">
            {query ? (
              <>
                <FilterX className="size-8 text-dim mb-2" />
                <p className="font-semibold text-fg">No matching findings</p>
                <p className="mt-1 text-xs text-muted max-w-sm">
                  No {SEV_LABEL[activeSev].toLowerCase()} findings match query "{query}".
                </p>
                <button
                  type="button"
                  onClick={() => setQuery("")}
                  className="mt-3 inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-line bg-raised px-3 py-1.5 text-xs font-semibold text-fg hover:border-teal/50 hover:text-teal"
                >
                  Clear search
                </button>
              </>
            ) : (
              <>
                <CheckCircle2 className="size-8 text-teal mb-2" />
                <p className="font-semibold text-fg">Zero {SEV_LABEL[activeSev]} Findings</p>
                <p className="mt-1 text-xs text-muted max-w-sm">
                  No issues found for this severity tier across projects' latest scans.
                </p>
              </>
            )}
          </div>
        ) : (
          <div className="max-h-[28rem] space-y-2.5 overflow-y-auto pr-1 scroll-thin">
            {filtered.map((f) => (
              <div
                key={f.id}
                className="group relative flex flex-col gap-2 rounded-xl border border-line-soft bg-hull/50 p-3.5 transition-all duration-150 hover:border-line hover:bg-raised/40 hover:shadow-md"
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={f.severity} compact />
                      <span className="font-semibold text-fg group-hover:text-teal transition-colors">
                        {f.title}
                      </span>
                      <StatusBadge status={f.status} />
                      <span className="rounded-md border border-line bg-panel px-2 py-0.5 font-mono text-[11px] text-muted">
                        {f.project_name}
                      </span>
                    </div>

                    <div className="mt-1 flex flex-wrap items-center gap-2 text-xs font-mono text-muted">
                      <span>{f.file}:{f.line}</span>
                      <span>·</span>
                      <span className="text-dim">{f.rule_id}</span>
                      {f.cwe && (
                        <>
                          <span>·</span>
                          <span className="text-sky/80">{f.cwe}</span>
                        </>
                      )}
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleOpenScan(f.scan_id, f.id)}
                    className="inline-flex cursor-pointer items-center gap-1 rounded-lg border border-line bg-raised px-2.5 py-1 text-xs font-medium text-sky hover:border-sky/50 hover:text-fg transition-colors"
                  >
                    View in Scan
                    <ArrowRight className="size-3" />
                  </button>
                </div>

                {f.snippet && (
                  <pre className="overflow-x-auto rounded-lg border border-line-soft bg-ink/70 p-2 font-mono text-[11px] text-muted group-hover:border-line group-hover:text-fg transition-colors">
                    <code>{f.snippet.trim().split("\n").slice(0, 3).join("\n")}</code>
                  </pre>
                )}
              </div>
            ))}
          </div>
        )}

        <div className="flex items-center justify-between border-t border-line-soft pt-4 text-xs text-muted">
          <span>
            Showing {filtered.length} of {findings?.length || 0} {SEV_LABEL[activeSev].toLowerCase()} findings
          </span>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-line bg-raised px-3 py-1.5 font-semibold text-fg hover:border-line-soft cursor-pointer transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </Dialog>
  );
}
