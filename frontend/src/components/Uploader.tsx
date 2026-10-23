import { useRef, useState } from "react";
import { FileArchive, FileCode2, FolderOpen, Trash2, UploadCloud } from "lucide-react";

export const LIMITS = { archiveMb: 10, fileKb: 1024, maxFiles: 400 };
const EXT = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".htm", ".py", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg"];
const SKIP_DIRS = ["node_modules/", ".git/", "dist/", "build/", ".next/", "__pycache__/", ".venv/", "venv/", "coverage/"];
const LOCKFILES = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"];

export type Selection =
  | { mode: "zip"; archive: File }
  | { mode: "files"; files: { file: File; path: string }[]; ignored: number };

function supported(path: string) {
  const name = path.split("/").pop() ?? "";
  if (/^\.env(\.[\w-]+)?$/.test(name)) return true;
  if (LOCKFILES.includes(name)) return false;
  return EXT.some((e) => name.toLowerCase().endsWith(e));
}

export function appendSelection(form: FormData, sel: Selection) {
  if (sel.mode === "zip") form.append("archive", sel.archive, sel.archive.name);
  else sel.files.forEach(({ file, path }) => form.append("files", file, path));
}

export default function Uploader({ value, onChange, onError, disabled }: {
  value: Selection | null; onChange: (s: Selection | null) => void; onError: (m: string | null) => void; disabled?: boolean;
}) {
  const [mode, setMode] = useState<"zip" | "files">("zip");
  const [drag, setDrag] = useState(false);
  const zipInput = useRef<HTMLInputElement>(null);
  const filesInput = useRef<HTMLInputElement>(null);
  const dirInput = useRef<HTMLInputElement>(null);

  const takeZip = (f: File) => {
    if (!f.name.toLowerCase().endsWith(".zip")) return onError("Choose a .zip archive, or switch to individual files.");
    if (f.size > LIMITS.archiveMb * 1024 * 1024) return onError(`This archive is ${(f.size / 1048576).toFixed(1)} MB. The limit is ${LIMITS.archiveMb} MB; remove node_modules and build folders and try again.`);
    onError(null);
    onChange({ mode: "zip", archive: f });
  };

  const takeFiles = (list: FileList) => {
    const all = Array.from(list).map((file) => ({ file, path: (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name }));
    const kept = all.filter(({ path }) => !SKIP_DIRS.some((d) => path.includes(d)) && supported(path));
    const tooBig = kept.find(({ file }) => file.size > LIMITS.fileKb * 1024);
    if (!kept.length) return onError("None of the selected files are supported source files.");
    if (tooBig) return onError(`${tooBig.path} is larger than ${LIMITS.fileKb} KB.`);
    if (kept.length > LIMITS.maxFiles) return onError(`Too many files (${kept.length}). The limit is ${LIMITS.maxFiles}.`);
    onError(null);
    onChange({ mode: "files", files: kept, ignored: all.length - kept.length });
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDrag(false);
    if (disabled || !e.dataTransfer.files.length) return;
    const first = e.dataTransfer.files[0];
    if (e.dataTransfer.files.length === 1 && first.name.toLowerCase().endsWith(".zip")) {
      setMode("zip");
      takeZip(first);
    } else {
      setMode("files");
      takeFiles(e.dataTransfer.files);
    }
  };

  return (
    <div>
      <div role="tablist" aria-label="Upload type" className="mb-3 inline-flex rounded-lg border border-line bg-hull p-1 text-sm">
        {(["zip", "files"] as const).map((m) => (
          <button key={m} role="tab" aria-selected={mode === m} disabled={disabled}
            onClick={() => { setMode(m); onChange(null); onError(null); }}
            className={`rounded-md px-3 py-1.5 ${mode === m ? "bg-raised text-fg" : "text-muted hover:text-fg"}`}>
            {m === "zip" ? "ZIP archive" : "Source files or folder"}
          </button>
        ))}
      </div>

      {!value ? (
        <div
          onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
          onDragLeave={() => setDrag(false)}
          onDrop={onDrop}
          className={`flex flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-12 text-center transition-colors ${drag ? "border-teal bg-teal/5" : "border-line bg-hull/50"}`}
        >
          <UploadCloud className="size-9 text-sky" />
          <p className="mt-3 font-semibold">{mode === "zip" ? "Drop a ZIP of your project here" : "Drop source files here"}</p>
          <p className="mt-1 max-w-md text-xs text-muted">
            {mode === "zip"
              ? `Up to ${LIMITS.archiveMb} MB · ${LIMITS.maxFiles} source files · ${LIMITS.fileKb} KB per file. Dependency and build folders are ignored.`
              : "JS, TS, JSX, TSX, Vue, Svelte, HTML, Python, JSON, YAML and .env files. Choose a folder to keep relative paths."}
          </p>
          <div className="mt-5 flex flex-wrap justify-center gap-2">
            {mode === "zip" ? (
              <button type="button" disabled={disabled} onClick={() => zipInput.current?.click()} className="inline-flex items-center gap-2 rounded-lg border border-line bg-raised px-3.5 py-2 text-sm hover:border-muted/60">
                <FileArchive className="size-4" /> Choose ZIP
              </button>
            ) : (
              <>
                <button type="button" disabled={disabled} onClick={() => dirInput.current?.click()} className="inline-flex items-center gap-2 rounded-lg border border-line bg-raised px-3.5 py-2 text-sm hover:border-muted/60">
                  <FolderOpen className="size-4" /> Choose folder
                </button>
                <button type="button" disabled={disabled} onClick={() => filesInput.current?.click()} className="inline-flex items-center gap-2 rounded-lg border border-line bg-raised px-3.5 py-2 text-sm hover:border-muted/60">
                  <FileCode2 className="size-4" /> Choose files
                </button>
              </>
            )}
          </div>
          <input ref={zipInput} type="file" accept=".zip,application/zip" hidden onChange={(e) => e.target.files?.[0] && takeZip(e.target.files[0])} />
          <input ref={filesInput} type="file" multiple hidden onChange={(e) => e.target.files && takeFiles(e.target.files)} />
          <input ref={dirInput} type="file" hidden onChange={(e) => e.target.files && takeFiles(e.target.files)}
            {...({ webkitdirectory: "", directory: "" } as Record<string, string>)} />
        </div>
      ) : (
        <div className="flex items-center gap-4 rounded-xl border border-line bg-hull/60 px-4 py-3.5">
          {value.mode === "zip" ? <FileArchive className="size-6 text-teal" /> : <FileCode2 className="size-6 text-teal" />}
          <div className="min-w-0 flex-1">
            <p className="truncate font-semibold">{value.mode === "zip" ? value.archive.name : `${value.files.length} source file${value.files.length > 1 ? "s" : ""}`}</p>
            <p className="truncate text-xs text-muted">
              {value.mode === "zip"
                ? `${(value.archive.size / 1024).toFixed(0)} KB`
                : value.files.slice(0, 4).map((f) => f.path).join(", ") + (value.files.length > 4 ? ` and ${value.files.length - 4} more` : "") + (value.ignored ? ` · ${value.ignored} unsupported or dependency files left out` : "")}
            </p>
          </div>
          <button type="button" disabled={disabled} onClick={() => onChange(null)} className="rounded-md p-2 text-muted hover:bg-raised hover:text-fg" aria-label="Remove selection">
            <Trash2 className="size-4" />
          </button>
        </div>
      )}
    </div>
  );
}

export function Progress({ phase, pct = 0 }: { phase: "uploading" | "scanning" | "fetching"; pct?: number }) {
  const steps = phase === "fetching" || phase === "scanning"
    ? [
        { key: "fetching", label: phase === "fetching" ? "Fetching repository..." : "Fetched" },
        { key: "scanning", label: "Scanning files" },
      ]
    : [
        { key: "uploading", label: phase === "uploading" ? `Uploading ${pct}%` : "Uploaded" },
        { key: "scanning", label: "Scanning files" },
      ];
  return (
    <div className="rounded-xl border border-line bg-hull/60 p-4" role="status" aria-live="polite">
      <div className="h-1.5 overflow-hidden rounded-full bg-line-soft">
        <div className={`h-full rounded-full bg-teal transition-all ${phase === "scanning" || phase === "fetching" ? "animate-pulse" : ""}`}
          style={{ width: phase === "uploading" ? `${Math.max(4, pct * 0.6)}%` : phase === "fetching" ? "45%" : "85%" }} />
      </div>
      <ol className="mt-3 flex gap-6 text-sm">
        {steps.map((s) => (
          <li key={s.key} className={phase === s.key ? "font-semibold text-fg" : "text-dim"}>{s.label}</li>
        ))}
      </ol>
    </div>
  );
}
