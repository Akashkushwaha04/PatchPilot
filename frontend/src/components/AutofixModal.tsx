import { useState } from "react";
import { CheckCircle2, ExternalLink, GitBranch, GitPullRequest, Lock, ShieldAlert, Sparkles } from "lucide-react";
import { api, type AutofixResult, type Finding, type Scan } from "../api";
import Dialog from "./Dialog";
import { Button, ErrorBanner } from "../ui";

interface AutofixModalProps {
  open: boolean;
  onClose: () => void;
  scan: Scan;
  findings: Finding[];
}

export default function AutofixModal({ open, onClose, scan, findings }: AutofixModalProps) {
  const [token, setToken] = useState("");
  const [branch, setBranch] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AutofixResult | null>(null);

  const openFindings = findings.filter((f) => f.status === "open" || f.status === "needs_review");
  const defaultBranch = `patchpilot-fixes-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}`;

  const handleAutofix = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await api.autofix(scan.id, {
        github_token: token.trim() || undefined,
        branch_name: branch.trim() || defaultBranch,
        finding_ids: openFindings.map((f) => f.id),
      });
      setResult(res);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const handleClose = () => {
    setResult(null);
    setError(null);
    onClose();
  };

  return (
    <Dialog open={open} onClose={handleClose} title="AI Auto-Fix & Open Pull Request">
      {result && result.success ? (
        <div className="space-y-5 text-center">
          <div className="mx-auto flex size-12 items-center justify-center rounded-full bg-teal/10 text-teal">
            <CheckCircle2 className="size-8" />
          </div>
          <div>
            <h3 className="text-xl font-bold">Pull Request Created Successfully!</h3>
            <p className="mt-1 text-sm text-muted">
              PatchPilot applied fixes for {result.resolved_count} security finding(s) and pushed to branch <code className="text-teal">{result.branch}</code>.
            </p>
          </div>

          {result.pr_url && (
            <div className="pt-2">
              <a
                href={result.pr_url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 rounded-lg bg-teal px-5 py-2.5 font-semibold text-ink shadow-lg shadow-teal/20 hover:bg-teal-bright"
              >
                <GitPullRequest className="size-4" /> View Pull Request #{result.pr_number} on GitHub <ExternalLink className="size-3.5" />
              </a>
            </div>
          )}

          <div className="border-t border-line-soft pt-4 text-xs text-muted">
            Remember to test and review the diff on GitHub before merging into your production branch.
          </div>
        </div>
      ) : (
        <div className="space-y-5">
          <div className="rounded-xl border border-line-soft bg-hull/60 p-4">
            <p className="text-sm font-semibold">Do you want PatchPilot to automatically fix these issues and create a Pull Request?</p>
            <div className="mt-3 flex flex-wrap gap-4 text-xs text-muted">
              <span className="flex items-center gap-1.5 font-medium text-fg">
                <ShieldAlert className="size-4 text-crit" /> {openFindings.length} open finding(s) to fix
              </span>
              <span className="flex items-center gap-1.5">
                <GitBranch className="size-4 text-sky" /> Target: new branch & PR
              </span>
            </div>
          </div>

          <div className="space-y-4 text-sm">
            <div>
              <label htmlFor="pat" className="block font-semibold">
                GitHub Personal Access Token (PAT) <span className="font-normal text-muted">(requires <code className="text-xs">repo</code> scope)</span>
              </label>
              <input
                id="pat"
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                disabled={busy}
                placeholder="ghp_... (leave empty if token was provided during scan)"
                className="mt-1.5 w-full rounded-lg border border-line bg-hull px-3.5 py-2 text-sm outline-none placeholder:text-dim focus:border-teal"
              />
              <p className="mt-1 flex items-center gap-1.5 text-xs text-dim">
                <Lock className="size-3" /> Token is never saved to the database; it stays in server memory only during this request.
              </p>
            </div>

            <div>
              <label htmlFor="branch_input" className="block font-semibold">
                New Branch Name <span className="font-normal text-muted">(optional)</span>
              </label>
              <input
                id="branch_input"
                type="text"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                disabled={busy}
                placeholder={defaultBranch}
                className="mt-1.5 w-full rounded-lg border border-line bg-hull px-3.5 py-2 text-sm outline-none placeholder:text-dim focus:border-teal"
              />
            </div>
          </div>

          {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

          <div className="flex justify-end gap-2 border-t border-line-soft pt-4">
            <Button variant="ghost" onClick={handleClose} disabled={busy}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleAutofix}
              busy={busy}
              icon={<Sparkles className="size-4" />}
            >
              {busy ? "Generating AI Fixes & Opening PR..." : "Yes, Fix & Create PR"}
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}
