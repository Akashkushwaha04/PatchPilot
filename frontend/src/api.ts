// Typed client for the PatchPilot API. No secrets live in the frontend.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Status = "open" | "fixed" | "accepted_risk" | "needs_review";

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  category: string;
  description: string;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  kind: "confirmed" | "heuristic" | "review_candidate";
  file: string;
  line: number;
  snippet: string;
  evidence: string;
  impact: string;
  remediation: string;
  remediation_text: string;
  cwe: string | null;
  origin: "source" | "browser";
  fingerprint: string;
  status: Status;
  verified_by: string | null;
}

export interface Score { score: number; grade: string; penalty: number; method: string }

export interface Comparison {
  parent_id: string;
  before_score: number;
  after_score: number;
  resolved: { finding: Finding; verification: string }[];
  remaining: { before: Finding; after: Finding; matched_by: string }[];
  new: Finding[];
  severity_changes: { rule_id: string; file: string; line: number; from: Severity; to: Severity }[];
  method: string;
  summary: string;
}

export interface Scan {
  id: string;
  project_name: string;
  created_at: string;
  parent_id: string | null;
  latest_rescan_id: string | null;
  source_kind: string;
  label: string | null;
  is_demo: boolean;
  file_count: number;
  skipped: { path: string; reason: string }[];
  score: Score;
  counts: Record<Severity, number>;
  status_counts: Partial<Record<Status, number>>;
  total_findings: number;
  target_url: string | null;
  url_scan: { resources: { url: string; type: string; bytes: number }[]; notes: string[]; final_url: string } | null;
  comparison: Comparison | null;
}

export interface Dashboard {
  total_scans: number;
  total_findings: number;
  open_critical_high: number;
  resolved: number;
  severity_distribution: Record<Severity, number>;
  recent_scans: Scan[];
  activity: { at: string; scan_id: string | null; kind: string; message: string }[];
  definitions: Record<string, string>;
}

export interface Explanation {
  source: "ai" | "deterministic";
  provider: string | null;
  ai_error: string | null;
  explanation: {
    what_the_code_does: string;
    why_risky: string;
    impact_example: string;
    recommended_fix: string;
    safer_code_example: string;
    verification_steps: string[];
  };
}

export interface Evaluation {
  planted: number;
  detected: number;
  missed: number;
  safe_cases: number;
  false_positives: number;
  detection_rate: number;
  planted_results: { id: string; description: string; expected: string; detected: boolean; rules_fired: string[] }[];
  safe_results: { id: string; description: string; false_positive: boolean; rules_fired: string[] }[];
  note: string;
}

export interface Health { status: string; version: string; rules: number; ai_provider: string | null; url_scanning: boolean }

export class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message);
  }
}

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let msg = `Request failed (HTTP ${res.status}).`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") msg = body.detail;
      else if (Array.isArray(body.detail)) msg = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch { /* keep default */ }
    throw new ApiError(msg, res.status);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

const get = <T,>(url: string) => fetch(url).then((r) => handle<T>(r));
const send = <T,>(url: string, method: string, body?: unknown) =>
  fetch(url, { method, headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).then((r) => handle<T>(r));

export interface GlobalFinding extends Finding {
  scan_id: string;
  project_name: string;
}

export interface AutofixResult {
  success: boolean;
  pr_url?: string;
  pr_number?: number;
  branch?: string;
  message: string;
  resolved_count: number;
  resolved_findings?: Array<{ rule_id: string; title: string; cwe: string | null; file: string; line: number; severity: string }>;
}

export const api = {
  health: () => get<Health>("/api/health"),
  dashboard: () => get<Dashboard>("/api/dashboard"),
  scans: () => get<Scan[]>("/api/scans"),
  clearHistory: () => send<void>("/api/scans", "DELETE"),
  scan: (id: string) => get<Scan>(`/api/scans/${id}`),
  findings: (id: string) => get<Finding[]>(`/api/scans/${id}/findings`),
  allFindings: (severity?: string) =>
    get<GlobalFinding[]>(`/api/findings${severity ? `?severity=${encodeURIComponent(severity)}` : ""}`),
  files: (id: string) => get<{ path: string; size: number }[]>(`/api/scans/${id}/files`),
  file: (id: string, path: string) => get<{ path: string; content: string }>(`/api/scans/${id}/file?path=${encodeURIComponent(path)}`),
  setStatus: (id: string, fid: string, status: Status) => send<Finding>(`/api/scans/${id}/findings/${fid}`, "PATCH", { status }),
  explain: (id: string, fid: string) => send<Explanation>(`/api/scans/${id}/findings/${fid}/explain`, "POST"),
  repairPrompt: (id: string, finding_ids: string[]) =>
    send<{ prompt: string; finding_count: number; notice: string }>(`/api/scans/${id}/repair-prompt`, "POST", { finding_ids }),
  demoScan: () => send<Scan>("/api/demo/scan", "POST"),
  demoRescan: (id: string) => send<Scan>(`/api/scans/${id}/rescan/demo`, "POST"),
  scanGithub: (repo_url: string, github_token?: string, branch?: string, project_name?: string) =>
    send<Scan>("/api/scans/github", "POST", { repo_url, github_token, branch, project_name }),
  autofix: (scanId: string, payload: { github_token?: string; branch_name?: string; finding_ids?: string[] }) =>
    send<AutofixResult>(`/api/scans/${scanId}/autofix`, "POST", payload),
  evaluation: () => get<Evaluation>("/api/evaluation"),
  reportUrl: (id: string, format: "md" | "json") => `/api/scans/${id}/report?format=${format}`,
};

/** Upload with real progress events (fetch has no upload progress). */
export function uploadForm<T>(url: string, form: FormData, onProgress: (pct: number) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(Math.round((e.loaded / e.total) * 100));
    xhr.upload.onload = () => onProgress(100);
    xhr.onerror = () => reject(new ApiError("Network error: could not reach the PatchPilot server.", 0));
    xhr.onload = () => {
      let body: any = null;
      try { body = JSON.parse(xhr.responseText); } catch { /* not json */ }
      if (xhr.status >= 200 && xhr.status < 300) resolve(body as T);
      else reject(new ApiError(typeof body?.detail === "string" ? body.detail : `Upload failed (HTTP ${xhr.status}).`, xhr.status));
    };
    xhr.send(form);
  });
}
