import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { AlertTriangle, Check, Copy, Loader2, X } from "lucide-react";
import type { Finding, Severity, Status } from "./api";

// ------------------------------------------------------------------ routing

export function useRoute(): string {
  const [route, setRoute] = useState(() => window.location.hash.slice(1) || "/");
  useEffect(() => {
    const on = () => setRoute(window.location.hash.slice(1) || "/");
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

export const go = (path: string) => {
  window.location.hash = path;
  window.scrollTo({ top: 0 });
};

// ------------------------------------------------------------------ formatting

export const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
export const SEV_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
export const SEV_COLOR: Record<Severity, string> = {
  critical: "var(--color-crit)", high: "var(--color-high)", medium: "var(--color-med)", low: "var(--color-low)", info: "var(--color-info)",
};
export const STATUS_LABEL: Record<Status, string> = { open: "Open", fixed: "Fixed", accepted_risk: "Accepted risk", needs_review: "Needs review" };
export const KIND_LABEL: Record<Finding["kind"], string> = { confirmed: "Pattern match", heuristic: "Heuristic", review_candidate: "Review candidate" };

export function timeAgo(iso: string): string {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

// ------------------------------------------------------------------ primitives

export function SeverityBadge({ severity, compact = false }: { severity: Severity; compact?: boolean }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold whitespace-nowrap border shadow-sm backdrop-blur-md transition-transform hover:scale-[1.02]"
      style={{
        color: SEV_COLOR[severity],
        background: `color-mix(in srgb, ${SEV_COLOR[severity]} 18%, rgba(255,255,255,0.06))`,
        borderColor: `color-mix(in srgb, ${SEV_COLOR[severity]} 35%, rgba(255,255,255,0.18))`,
      }}
    >
      <span className="size-1.5 rounded-full shadow-[0_0_8px_currentColor]" style={{ background: SEV_COLOR[severity] }} />
      {!compact && SEV_LABEL[severity]}
    </span>
  );
}

const STATUS_STYLE: Record<Status, string> = {
  open: "text-fg bg-white/10 border-white/15",
  needs_review: "text-sky bg-sky/15 border-sky/30",
  accepted_risk: "text-muted bg-white/5 border-white/10",
  fixed: "text-teal bg-teal/15 border-teal/30",
};

export function StatusBadge({ status }: { status: Status }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium whitespace-nowrap backdrop-blur-md shadow-sm ${STATUS_STYLE[status]}`}>
      {status === "fixed" && <Check className="size-3" />}
      {STATUS_LABEL[status]}
    </span>
  );
}

export function KindBadge({ kind }: { kind: Finding["kind"] }) {
  const style = kind === "confirmed" ? "border-white/25 text-fg bg-white/10" : kind === "heuristic" ? "border-white/15 text-muted bg-white/5" : "border-dashed border-sky/50 text-sky bg-sky/5";
  return <span className={`rounded-full border px-2.5 py-0.5 text-xs whitespace-nowrap backdrop-blur-sm ${style}`}>{KIND_LABEL[kind]}</span>;
}

type BtnVariant = "primary" | "secondary" | "ghost" | "danger";
const BTN: Record<BtnVariant, string> = {
  primary: "liquid-btn-primary font-semibold text-white",
  secondary: "liquid-btn-secondary",
  ghost: "text-muted hover:text-fg hover:bg-white/10 rounded-2xl",
  danger: "bg-crit/15 text-crit border border-crit/30 hover:bg-crit/25 rounded-2xl",
};

export function Button({
  variant = "secondary", busy, icon, children, className = "", ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: BtnVariant; busy?: boolean; icon?: ReactNode }) {
  return (
    <button
      {...rest}
      disabled={rest.disabled || busy}
      className={`inline-flex items-center justify-center gap-2 px-4 py-2 text-sm transition-all disabled:cursor-not-allowed disabled:opacity-50 ${BTN[variant]} ${className}`}
    >
      {busy ? <Loader2 className="size-4 animate-spin" /> : icon}
      {children}
    </button>
  );
}

export function Panel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`liquid-panel ${className}`}>{children}</section>;
}

export function SpatialHandle({ className = "" }: { className?: string }) {
  return (
    <div className={`flex items-center justify-center gap-2 py-2 select-none pointer-events-none opacity-60 hover:opacity-100 transition-opacity ${className}`} aria-hidden="true">
      <div className="size-1.5 rounded-full bg-white/40 shadow-[0_0_6px_rgba(255,255,255,0.4)]" />
      <div className="h-1 w-14 rounded-full bg-white/40 shadow-[0_0_6px_rgba(255,255,255,0.2)]" />
    </div>
  );
}

export function CloseGlassButton({ onClick, className = "", label = "Close" }: { onClick?: () => void; className?: string; label?: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      className={`size-9 shrink-0 rounded-full bg-white/12 hover:bg-white/24 active:scale-95 border border-white/20 backdrop-blur-xl flex items-center justify-center text-white/80 hover:text-white transition-all shadow-sm ${className}`}
    >
      <X className="size-4" />
    </button>
  );
}

export function ErrorBanner({ message, onDismiss }: { message: string; onDismiss?: () => void }) {
  return (
    <div role="alert" className="flex items-start gap-3 rounded-lg border border-crit/40 bg-crit/10 px-4 py-3 text-sm text-fg">
      <AlertTriangle className="mt-0.5 size-4 shrink-0 text-crit" />
      <p className="flex-1">{message}</p>
      {onDismiss && (
        <button onClick={onDismiss} aria-label="Dismiss" className="text-muted hover:text-fg"><X className="size-4" /></button>
      )}
    </div>
  );
}

export function Spinner({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-3 py-16 text-muted" role="status">
      <Loader2 className="size-5 animate-spin text-teal" />
      {label}
    </div>
  );
}

// ------------------------------------------------------------------ clipboard & toast

const ToastCtx = createContext<(msg: string) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [msg, setMsg] = useState<string | null>(null);
  const show = useCallback((m: string) => {
    setMsg(m);
    window.setTimeout(() => setMsg((cur) => (cur === m ? null : cur)), 2400);
  }, []);
  return (
    <ToastCtx.Provider value={show}>
      {children}
      <div aria-live="polite" className="pointer-events-none fixed inset-x-0 bottom-6 z-50 flex justify-center px-4">
        {msg && (
          <div className="animate-rise flex items-center gap-2 rounded-lg border border-teal/40 bg-hull px-4 py-2.5 text-sm shadow-2xl shadow-black/40">
            <Check className="size-4 text-teal" /> {msg}
          </div>
        )}
      </div>
    </ToastCtx.Provider>
  );
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for non-secure contexts.
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  }
}

export function CopyButton({ text, label, done = "Copied to clipboard", variant = "secondary" }: { text: string; label: string; done?: string; variant?: BtnVariant }) {
  const toast = useToast();
  const [ok, setOk] = useState(false);
  return (
    <Button
      variant={variant}
      icon={ok ? <Check className="size-4" /> : <Copy className="size-4" />}
      onClick={async () => {
        if (await copyText(text)) {
          setOk(true);
          toast(done);
          window.setTimeout(() => setOk(false), 1800);
        } else toast("Copy failed. Select the text and copy it manually.");
      }}
    >
      {ok ? "Copied" : label}
    </Button>
  );
}

// ------------------------------------------------------------------ the instrument

export const gradeFor = (score: number) => (score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F");

function gradeColor(score: number) {
  if (score >= 90) return "var(--color-teal)";
  if (score >= 75) return "#7fd6a0";
  if (score >= 60) return "var(--color-med)";
  if (score >= 40) return "var(--color-high)";
  return "var(--color-crit)";
}

/** Score dial drawn like a cockpit instrument: tick ring, arc, and a needle. */
export function ScoreDial({ score, grade, size = 200, label = "Security score", ghost }: { score: number; grade: string; size?: number; label?: string; ghost?: number }) {
  const r = 80, cx = 100, cy = 100;
  const start = -210, sweep = 240;
  const ang = (v: number) => ((start + (sweep * v) / 100) * Math.PI) / 180;
  const pt = (v: number, rad: number) => [cx + rad * Math.cos(ang(v)), cy + rad * Math.sin(ang(v))];
  const arcLen = (2 * Math.PI * r * sweep) / 360;
  const [a0x, a0y] = pt(0, r), [a1x, a1y] = pt(100, r);
  const arc = `M ${a0x} ${a0y} A ${r} ${r} 0 1 1 ${a1x} ${a1y}`;
  const [nx, ny] = pt(score, r - 18);
  const color = gradeColor(score);
  return (
    <figure className="flex flex-col items-center" aria-label={`${label}: ${score} out of 100, grade ${grade}`}>
      <svg viewBox="0 0 200 180" width={size} height={size * 0.9} role="img" aria-hidden="true">
        {Array.from({ length: 41 }, (_, i) => {
          const v = i * 2.5;
          const major = i % 4 === 0;
          const [x1, y1] = pt(v, r + 9);
          const [x2, y2] = pt(v, r + (major ? 16 : 12));
          return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke={major ? "var(--color-muted)" : "var(--color-line)"} strokeWidth={major ? 1.6 : 1} />;
        })}
        <path d={arc} fill="none" stroke="var(--color-line-soft)" strokeWidth="12" strokeLinecap="round" />
        {ghost !== undefined && (
          <path d={arc} fill="none" stroke="var(--color-dim)" strokeOpacity="0.5" strokeWidth="12" strokeLinecap="round"
            strokeDasharray={arcLen} strokeDashoffset={arcLen * (1 - ghost / 100)} />
        )}
        <path
          d={arc} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round" strokeDasharray={arcLen}
          style={{ strokeDashoffset: arcLen * (1 - score / 100), ["--from" as string]: arcLen, ["--to" as string]: arcLen * (1 - score / 100), animation: "sweep 0.9s cubic-bezier(.2,.8,.2,1) both" }}
        />
        <line x1={cx} y1={cy} x2={nx} y2={ny} stroke="var(--color-fg)" strokeWidth="2.5" strokeLinecap="round" />
        <circle cx={cx} cy={cy} r="6" fill="var(--color-ink)" stroke="var(--color-fg)" strokeWidth="2" />
        <text x={cx} y={cy + 44} textAnchor="middle" fill="var(--color-fg)" fontSize="34" fontWeight="800" fontFamily="var(--font-sans)">{score}</text>
        <text x={cx} y={cy + 62} textAnchor="middle" fill={color} fontSize="12" fontWeight="700" fontFamily="var(--font-sans)">Grade {grade}</text>
      </svg>
      <figcaption className="-mt-1 text-xs text-muted">{label}</figcaption>
    </figure>
  );
}

export function SeverityBar({ counts }: { counts: Record<Severity, number> }) {
  const total = SEV_ORDER.reduce((a, s) => a + counts[s], 0);
  if (!total) return <div className="h-2 rounded-full bg-teal/30" title="No findings" />;
  return (
    <div className="flex h-2 overflow-hidden rounded-full bg-line-soft" role="img" aria-label={SEV_ORDER.map((s) => `${counts[s]} ${s}`).join(", ")}>
      {SEV_ORDER.map((s) => counts[s] > 0 && <div key={s} style={{ width: `${(counts[s] / total) * 100}%`, background: SEV_COLOR[s] }} />)}
    </div>
  );
}
