import { useEffect, useState } from "react";
import { FileArchive, FlaskConical, GitBranch, Globe, Lock, ScanLine } from "lucide-react";
import { api, uploadForm, type Health, type Scan } from "../api";
import Uploader, { Progress, appendSelection, type Selection } from "../components/Uploader";
import { Button, ErrorBanner, Panel, go } from "../ui";
import { useDemoLauncher } from "./Dashboard";

export default function NewScan() {
  const [name, setName] = useState("");
  const [sourceType, setSourceType] = useState<"upload" | "github">("upload");
  const [sel, setSel] = useState<Selection | null>(null);
  const [githubUrl, setGithubUrl] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [githubBranch, setGithubBranch] = useState("");
  const [url, setUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<"idle" | "uploading" | "fetching" | "scanning">("idle");
  const [pct, setPct] = useState(0);
  const [health, setHealth] = useState<Health | null>(null);
  const demo = useDemoLauncher();
  const busy = phase !== "idle";

  useEffect(() => { api.health().then(setHealth).catch(() => {}); }, []);
  useEffect(() => {
    if (!name && sel?.mode === "zip") setName(sel.archive.name.replace(/\.zip$/i, ""));
    if (!name && githubUrl.trim()) {
      const parts = githubUrl.trim().replace(/\.git$/, "").split("/").filter(Boolean);
      if (parts.length >= 2) setName(parts[parts.length - 1]);
    }
  }, [sel, githubUrl]); // eslint-disable-line react-hooks/exhaustive-deps

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!name.trim()) return setError("Give the project a name so you can find this scan later.");

    if (sourceType === "github") {
      if (!githubUrl.trim()) return setError("Please enter a valid GitHub repository URL.");
      setPhase("fetching");
      try {
        const scan = await api.scanGithub(
          githubUrl.trim(),
          githubToken.trim() || undefined,
          githubBranch.trim() || undefined,
          name.trim() || undefined
        );
        go(`/scans/${scan.id}`);
      } catch (err) {
        setError((err as Error).message);
        setPhase("idle");
      }
      return;
    }

    if (!sel && !url.trim()) return setError("Upload your source code, or enter a deployed URL.");
    if (url.trim() && !authorized) return setError("Confirm you are authorized to assess this URL before scanning it.");
    const form = new FormData();
    form.append("project_name", name.trim());
    if (sel) appendSelection(form, sel);
    if (url.trim()) form.append("target_url", url.trim());
    setPhase("uploading");
    setPct(0);
    try {
      const scan = await uploadForm<Scan>("/api/scans", form, (p) => {
        setPct(p);
        if (p >= 100) setPhase("scanning");
      });
      go(`/scans/${scan.id}`);
    } catch (err) {
      setError((err as Error).message);
      setPhase("idle");
    }
  };

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl font-extrabold tracking-tight sm:text-3xl">New security scan</h1>
        <p className="mt-1 text-sm text-muted">Upload source code or paste a GitHub repository URL to scan. Files are read as text and never executed. Detected secrets are masked everywhere.</p>
      </div>

      <form onSubmit={submit} className="space-y-6" noValidate>
        <Panel className="space-y-6 p-6">
          <div>
            <label htmlFor="pname" className="text-sm font-semibold">Project name</label>
            <input id="pname" value={name} onChange={(e) => setName(e.target.value)} maxLength={80} disabled={busy}
              placeholder="e.g. my-portfolio-site"
              className="mt-2 w-full rounded-lg border border-line bg-hull px-3.5 py-2.5 text-sm outline-none placeholder:text-dim focus:border-teal" />
          </div>

          <div>
            <div className="mb-3 flex items-center justify-between">
              <p className="text-sm font-semibold">Source code input</p>
              <div className="flex rounded-lg border border-line bg-hull p-1 text-xs">
                <button
                  type="button"
                  onClick={() => setSourceType("upload")}
                  className={`flex items-center gap-1.5 rounded-md px-3 py-1 font-medium transition-colors ${
                    sourceType === "upload" ? "bg-raised text-fg shadow-sm" : "text-muted hover:text-fg"
                  }`}
                >
                  <FileArchive className="size-3.5" /> Upload files / ZIP
                </button>
                <button
                  type="button"
                  onClick={() => setSourceType("github")}
                  className={`flex items-center gap-1.5 rounded-md px-3 py-1 font-medium transition-colors ${
                    sourceType === "github" ? "bg-raised text-fg shadow-sm" : "text-muted hover:text-fg"
                  }`}
                >
                  <GitBranch className="size-3.5" /> GitHub URL
                </button>
              </div>
            </div>

            {sourceType === "upload" ? (
              <Uploader value={sel} onChange={setSel} onError={setError} disabled={busy} />
            ) : (
              <div className="space-y-4 rounded-xl border border-line bg-hull/60 p-4">
                <div>
                  <label htmlFor="gh_url" className="block text-xs font-semibold uppercase tracking-wider text-muted">
                    GitHub Repository URL *
                  </label>
                  <input
                    id="gh_url"
                    type="url"
                    value={githubUrl}
                    onChange={(e) => setGithubUrl(e.target.value)}
                    disabled={busy}
                    placeholder="https://github.com/owner/repository"
                    className="mt-1.5 w-full rounded-lg border border-line bg-hull px-3.5 py-2.5 text-sm outline-none placeholder:text-dim focus:border-teal"
                  />
                </div>

                <div className="grid gap-4 sm:grid-cols-2">
                  <div>
                    <label htmlFor="gh_token" className="block text-xs font-semibold uppercase tracking-wider text-muted">
                      GitHub Token <span className="font-normal lowercase text-dim">(optional, for private repos or PR creation)</span>
                    </label>
                    <input
                      id="gh_token"
                      type="password"
                      value={githubToken}
                      onChange={(e) => setGithubToken(e.target.value)}
                      disabled={busy}
                      placeholder="ghp_..."
                      className="mt-1.5 w-full rounded-lg border border-line bg-hull px-3.5 py-2.5 text-sm outline-none placeholder:text-dim focus:border-teal"
                    />
                  </div>

                  <div>
                    <label htmlFor="gh_branch" className="block text-xs font-semibold uppercase tracking-wider text-muted">
                      Branch / Tag <span className="font-normal lowercase text-dim">(optional, default: default branch)</span>
                    </label>
                    <input
                      id="gh_branch"
                      type="text"
                      value={githubBranch}
                      onChange={(e) => setGithubBranch(e.target.value)}
                      disabled={busy}
                      placeholder="main"
                      className="mt-1.5 w-full rounded-lg border border-line bg-hull px-3.5 py-2.5 text-sm outline-none placeholder:text-dim focus:border-teal"
                    />
                  </div>
                </div>

                <p className="flex items-center gap-1.5 text-xs text-dim">
                  <Lock className="size-3" /> Token is kept strictly in memory for this session and is never written to disk or database.
                </p>
              </div>
            )}
          </div>
        </Panel>

        <Panel className="space-y-4 p-6">
          <div className="flex items-start gap-3">
            <Globe className="mt-0.5 size-5 text-sky" />
            <div>
              <p className="text-sm font-semibold">Deployed URL <span className="font-normal text-muted">(optional)</span></p>
              <p className="mt-1 text-xs leading-relaxed text-muted">
                Checks only what any visitor can download: the page HTML and same-site scripts, for exposed keys and risky patterns.
                It never logs in, submits forms or attempts exploits, and it cannot assess your backend. Private, local and cloud-metadata addresses are blocked.
              </p>
            </div>
          </div>
          {health && !health.url_scanning ? (
            <p className="text-sm text-muted">URL scanning is turned off on this server. Source-code scanning is the supported workflow.</p>
          ) : (
            <>
              <input value={url} onChange={(e) => setUrl(e.target.value)} disabled={busy} type="url" inputMode="url" placeholder="https://your-site.example"
                aria-label="Deployed URL" className="w-full rounded-lg border border-line bg-hull px-3.5 py-2.5 text-sm outline-none placeholder:text-dim focus:border-teal" />
              {url.trim() && (
                <label className="flex items-start gap-2.5 text-sm">
                  <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} className="mt-1 accent-[var(--color-teal)]" />
                  I own this site or have permission to assess it.
                </label>
              )}
            </>
          )}
        </Panel>

        {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
        {busy && <Progress phase={phase as "uploading" | "scanning" | "fetching"} pct={pct} />}

        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="flex items-center gap-2 text-xs text-dim"><Lock className="size-3.5" /> Only masked copies of your files are stored, for the code viewer.</p>
          <div className="flex gap-2">
            <Button type="button" onClick={demo.launch} busy={demo.busy} disabled={busy} icon={<FlaskConical className="size-4" />}>Use demo project</Button>
            <Button type="submit" variant="primary" busy={busy} icon={<ScanLine className="size-4" />}>
              {busy ? (phase === "fetching" ? "Fetching repository..." : "Scanning") : "Start scan"}
            </Button>
          </div>
        </div>
        {demo.error && <ErrorBanner message={demo.error} onDismiss={demo.clear} />}
      </form>
    </div>
  );
}
