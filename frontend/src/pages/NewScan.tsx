import { useEffect, useState } from "react";
import {
  Binary,
  Brain,
  Cpu,
  FileArchive,
  FlaskConical,
  GitBranch,
  Globe,
  Lock,
  ScanLine,
  Shield,
  Sparkles,
  Zap,
} from "lucide-react";
import { api, uploadForm, type AIModel, type Health, type Scan } from "../api";
import Uploader, { Progress, appendSelection, type Selection } from "../components/Uploader";
import { Button, ErrorBanner, Panel, go } from "../ui";
import { useDemoLauncher } from "./Dashboard";

function renderModelIcon(icon: string) {
  switch (icon) {
    case "sparkles": return <Sparkles className="size-5 text-teal" />;
    case "shield": return <Shield className="size-5 text-sky" />;
    case "brain": return <Brain className="size-5 text-purple-300" />;
    case "binary": return <Binary className="size-5 text-emerald-400" />;
    case "zap": return <Zap className="size-5 text-amber-300" />;
    case "lock": return <Lock className="size-5 text-teal" />;
    case "cpu": return <Cpu className="size-5 text-slate-300" />;
    default: return <Sparkles className="size-5 text-teal" />;
  }
}

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
  const [models, setModels] = useState<AIModel[]>([]);
  const [selectedModel, setSelectedModel] = useState<string>("claude-3-7-sonnet");
  const demo = useDemoLauncher();
  const busy = phase !== "idle";

  useEffect(() => {
    api.health().then(setHealth).catch(() => {});
    api.models().then((ms) => {
      setModels(ms);
      const def = ms.find((m) => m.is_default);
      if (def) setSelectedModel(def.id);
    }).catch(() => {});
  }, []);
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
          name.trim() || undefined,
          selectedModel
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
    form.append("ai_model", selectedModel);
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
              <p className="text-sm font-semibold">Deployed URL <span className="font-normal text-muted">(optional website check)</span></p>
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
                <div className="space-y-2 pt-1">
                  <label className="flex items-start gap-2.5 text-sm">
                    <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} className="mt-1 accent-[var(--color-teal)]" />
                    I own this site or have permission to assess it.
                  </label>
                  <div className="flex items-center gap-2 rounded-lg border border-teal/30 bg-teal/10 px-3 py-2 text-xs text-fg">
                    <Sparkles className="size-4 shrink-0 text-teal" />
                    <span>
                      Target website will be assessed with <strong>{models.find(m => m.id === selectedModel)?.name || "Selected AI"}</strong> (<strong>Efficiency:</strong> {models.find(m => m.id === selectedModel)?.efficiency} • <strong>Speed:</strong> {models.find(m => m.id === selectedModel)?.speed}).
                    </span>
                  </div>
                </div>
              )}
            </>
          )}
        </Panel>

        {/* AI Model Selection for Website & Code Security Analysis */}
        <Panel className="space-y-4 p-6">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-start gap-3">
              <Sparkles className="mt-0.5 size-5 text-teal" />
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-semibold">Choose AI Security Engine</h3>
                  <span className="rounded-full border border-teal/30 bg-teal/15 px-2.5 py-0.5 text-[10px] font-semibold text-teal">
                    Multi-Model Audit
                  </span>
                </div>
                <p className="mt-1 text-xs leading-relaxed text-muted">
                  Choose which AI model inspects your website and codebase. Every model's detection efficiency and speed benchmark are displayed in front.
                </p>
              </div>
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-1">
            {models.map((m) => {
              const active = selectedModel === m.id;
              return (
                <div
                  key={m.id}
                  onClick={() => !busy && setSelectedModel(m.id)}
                  className={`group relative cursor-pointer rounded-2xl border p-4 transition-all ${
                    active
                      ? "border-teal/60 bg-teal/12 shadow-[0_4px_24px_rgba(167,199,203,0.18)]"
                      : "border-line bg-hull/50 hover:border-line hover:bg-hull/80"
                  }`}
                >
                  <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                    <div className="flex items-start gap-3.5">
                      <div className={`mt-0.5 flex size-10 shrink-0 items-center justify-center rounded-xl border ${
                        active ? "border-teal/40 bg-teal/20 text-teal" : "border-line bg-raised/40 text-muted"
                      }`}>
                        {renderModelIcon(m.icon)}
                      </div>
                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-semibold text-sm text-fg">{m.name}</span>
                          <span className="text-[11px] text-muted">({m.provider})</span>
                          {m.tag && (
                            <span className="rounded-md border border-teal/40 bg-teal/20 px-1.5 py-0.5 text-[10px] font-bold text-teal">
                              {m.tag}
                            </span>
                          )}
                          <span className="rounded-md border border-line-soft bg-raised/30 px-1.5 py-0.5 text-[10px] text-muted">
                            {m.badge}
                          </span>
                        </div>
                        <p className="text-xs text-muted/90 line-clamp-1">{m.description}</p>
                      </div>
                    </div>

                    {/* Efficiency & Speed prominently displayed in front */}
                    <div className="flex flex-wrap items-center gap-2 md:shrink-0 md:pl-4">
                      <div className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-xs font-semibold text-emerald-300">
                        <Zap className="size-3 text-emerald-400" />
                        <span>Efficiency: {m.efficiency}</span>
                      </div>
                      <div className="flex items-center gap-1.5 rounded-lg border border-sky-400/30 bg-sky-400/10 px-2.5 py-1 text-xs font-semibold text-sky">
                        <span>Speed: {m.speed}</span>
                      </div>
                      <input
                        type="radio"
                        name="ai_model"
                        checked={active}
                        onChange={() => setSelectedModel(m.id)}
                        className="ml-1 size-4 accent-[var(--color-teal)]"
                        disabled={busy}
                      />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
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
