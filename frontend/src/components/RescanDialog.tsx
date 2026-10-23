import { useState } from "react";
import { FlaskConical, RefreshCcw } from "lucide-react";
import { api, uploadForm, type Scan } from "../api";
import { Button, ErrorBanner, go } from "../ui";
import Dialog from "./Dialog";
import Uploader, { Progress, appendSelection, type Selection } from "./Uploader";

export default function RescanDialog({ scan, open, onClose }: { scan: Scan; open: boolean; onClose: () => void }) {
  const [sel, setSel] = useState<Selection | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<"idle" | "uploading" | "scanning">("idle");
  const [pct, setPct] = useState(0);
  const [demoBusy, setDemoBusy] = useState(false);
  const busy = phase !== "idle" || demoBusy;

  const upload = async () => {
    if (!sel) return setError("Choose the corrected ZIP or source files first.");
    const form = new FormData();
    appendSelection(form, sel);
    setError(null);
    setPhase("uploading");
    try {
      const next = await uploadForm<Scan>(`/api/scans/${scan.id}/rescan`, form, (p) => { setPct(p); if (p >= 100) setPhase("scanning"); });
      onClose();
      go(`/scans/${next.id}`);
    } catch (e) {
      setError((e as Error).message);
      setPhase("idle");
    }
  };

  const demo = async () => {
    setDemoBusy(true);
    setError(null);
    try {
      const next = await api.demoRescan(scan.id);
      onClose();
      go(`/scans/${next.id}`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setDemoBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={() => !busy && onClose()} title={`Rescan ${scan.project_name}`}>
      <div className="space-y-5">
        <p className="text-sm leading-relaxed text-muted">
          Upload the updated version. The same rules run again, and each original finding is matched by rule, file and code location.
          Findings are marked fixed only if the rescan no longer detects them.
        </p>
        {scan.is_demo && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-teal/30 bg-teal/5 p-4">
            <div className="text-sm">
              <p className="font-semibold">Bundled corrected demo</p>
              <p className="text-muted">Campus Bazaar after an AI assistant applied the fix prompts.</p>
            </div>
            <Button variant="primary" onClick={demo} busy={demoBusy} disabled={phase !== "idle"} icon={<FlaskConical className="size-4" />}>Rescan with corrected demo</Button>
          </div>
        )}
        <Uploader value={sel} onChange={setSel} onError={setError} disabled={busy} />
        {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
        {phase !== "idle" && <Progress phase={phase} pct={pct} />}
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button variant={scan.is_demo ? "secondary" : "primary"} onClick={upload} busy={phase !== "idle"} disabled={!sel || demoBusy} icon={<RefreshCcw className="size-4" />}>Upload and rescan</Button>
        </div>
      </div>
    </Dialog>
  );
}
