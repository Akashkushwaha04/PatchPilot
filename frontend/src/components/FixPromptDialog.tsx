import { useEffect, useState } from "react";
import { Download, ShieldAlert } from "lucide-react";
import { api } from "../api";
import { CopyButton, ErrorBanner, Spinner } from "../ui";
import Dialog from "./Dialog";

export default function FixPromptDialog({ scanId, findingIds, open, onClose, projectName }: {
  scanId: string; findingIds: string[]; open: boolean; onClose: () => void; projectName: string;
}) {
  const [prompt, setPrompt] = useState<{ prompt: string; finding_count: number; notice: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setPrompt(null);
    setError(null);
    api.repairPrompt(scanId, findingIds).then(setPrompt).catch((e) => setError(e.message));
  }, [open, scanId, findingIds.join(",")]); // eslint-disable-line react-hooks/exhaustive-deps

  const download = () => {
    if (!prompt) return;
    const blob = new Blob([prompt.prompt], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `fix-prompt-${projectName.replace(/[^\w-]+/g, "-").toLowerCase()}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <Dialog open={open} onClose={onClose} title="Fix prompt for your AI coding assistant" wide>
      {error && <ErrorBanner message={error} />}
      {!prompt && !error && <Spinner label="Building prompt from the scan evidence" />}
      {prompt && (
        <div className="space-y-4">
          <div className="flex items-start gap-3 rounded-lg border border-med/40 bg-med/10 px-4 py-3 text-sm">
            <ShieldAlert className="mt-0.5 size-4 shrink-0 text-med" />
            <p>{prompt.notice} Paste it into Claude, Cursor, Copilot or a similar tool. Secrets in the code excerpts are masked.</p>
          </div>
          <p className="text-sm text-muted">Covers {prompt.finding_count} finding{prompt.finding_count > 1 ? "s" : ""}, with file paths, line numbers, evidence, constraints, required tests and verification steps.</p>
          <pre className="scroll-thin max-h-[26rem] overflow-auto whitespace-pre-wrap rounded-lg border border-line-soft bg-ink p-4 font-mono text-[12.5px] leading-relaxed text-muted">{prompt.prompt}</pre>
          <div className="flex flex-wrap justify-end gap-2">
            <button onClick={download} className="inline-flex items-center gap-2 rounded-lg border border-line bg-raised px-3.5 py-2 text-sm hover:border-muted/60">
              <Download className="size-4" /> Download .md
            </button>
            <CopyButton text={prompt.prompt} label="Copy prompt" done="Fix prompt copied" variant="primary" />
          </div>
        </div>
      )}
    </Dialog>
  );
}
