import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { api, type Finding } from "../api";
import { SEV_COLOR, Spinner } from "../ui";

export function Snippet({ code, firstLine, highlight }: { code: string; firstLine: number; highlight: number }) {
  const lines = useMemo(() => code.split("\n"), [code]);
  const containerRef = useRef<HTMLPreElement>(null);

  const rowVirtualizer = useVirtualizer({
    count: lines.length,
    getScrollElement: () => containerRef.current,
    estimateSize: () => 24,
    overscan: 10,
  });

  return (
    <pre
      ref={containerRef}
      className="scroll-thin relative max-h-64 overflow-y-auto rounded-lg border border-line-soft bg-ink py-2 font-mono text-[12.5px] leading-6"
    >
      <div
        style={{
          height: `${rowVirtualizer.getTotalSize()}px`,
          width: "100%",
          position: "relative",
        }}
      >
        {rowVirtualizer.getVirtualItems().map((virtualRow) => {
          const i = virtualRow.index;
          const ln = lines[i];
          const n = firstLine + i;
          const hot = n === highlight;
          return (
            <div
              key={i}
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                width: "100%",
                transform: `translateY(${virtualRow.start}px)`,
                height: `${virtualRow.size}px`,
              }}
              className={`flex pr-4 ${hot ? "bg-crit/10" : ""}`}
            >
              <span className={`w-12 shrink-0 select-none pr-3 text-right ${hot ? "text-crit" : "text-dim"}`}>{n}</span>
              <code className={`whitespace-pre ${hot ? "text-fg" : "text-muted"}`}>{ln || " "}</code>
            </div>
          );
        })}
      </div>
    </pre>
  );
}

/** Full masked file with every finding in it marked in the gutter (virtualized for long files). */
export default function CodeViewer({ scanId, path, focusLine, findings }: { scanId: string; path: string; focusLine: number; findings: Finding[] }) {
  const [content, setContent] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const boxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setContent(null);
    api.file(scanId, path).then((r) => setContent(r.content)).catch((e) => setError(e.message));
  }, [scanId, path]);

  const lines = useMemo(() => (content !== null ? content.split("\n") : []), [content]);

  const marks = useMemo(() => {
    const m = new Map<number, Finding>();
    findings.filter((f) => f.file === path).forEach((f) => !m.has(f.line) && m.set(f.line, f));
    return m;
  }, [findings, path]);

  const rowVirtualizer = useVirtualizer({
    count: lines.length,
    getScrollElement: () => boxRef.current,
    estimateSize: () => 24,
    overscan: 15,
  });

  useEffect(() => {
    if (content !== null && focusLine > 0 && lines.length > 0) {
      const lineIndex = Math.max(0, Math.min(lines.length - 1, focusLine - 1));
      rowVirtualizer.scrollToIndex(lineIndex, { align: "center", behavior: "auto" });
    }
  }, [content, focusLine, lines.length, rowVirtualizer]);

  if (error) return <p className="text-sm text-crit">{error}</p>;
  if (content === null) return <Spinner label="Loading file" />;

  return (
    <div>
      <p className="mb-2 flex items-center justify-between font-mono text-xs text-muted">
        <span className="truncate">{path}</span>
        <span className="shrink-0">secrets masked · read-only ({lines.length} lines)</span>
      </p>
      <div
        ref={boxRef}
        className="scroll-thin relative max-h-[28rem] overflow-auto rounded-lg border border-line-soft bg-ink py-2 font-mono text-[12.5px] leading-6"
      >
        <div
          style={{
            height: `${rowVirtualizer.getTotalSize()}px`,
            width: "100%",
            position: "relative",
          }}
        >
          {rowVirtualizer.getVirtualItems().map((virtualRow) => {
            const i = virtualRow.index;
            const ln = lines[i];
            const n = i + 1;
            const mark = marks.get(n);
            const focus = n === focusLine;
            return (
              <div
                key={i}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  transform: `translateY(${virtualRow.start}px)`,
                  height: `${virtualRow.size}px`,
                }}
                className={`flex pr-4 ${focus ? "bg-crit/10" : mark ? "bg-raised/50" : ""}`}
              >
                <span className="flex w-14 shrink-0 select-none items-center justify-end gap-1.5 pr-3 text-right text-dim">
                  {mark && <span className="size-1.5 rounded-full" style={{ background: SEV_COLOR[mark.severity] }} title={mark.title} />}
                  <span className={focus ? "text-crit" : ""}>{n}</span>
                </span>
                <code className={`whitespace-pre ${focus ? "text-fg" : "text-muted"}`}>{ln || " "}</code>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
