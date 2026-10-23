import { useEffect, useRef, type ReactNode } from "react";
import { X } from "lucide-react";

export default function Dialog({ open, onClose, title, children, wide }: { open: boolean; onClose: () => void; title: string; children: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
      prev?.focus();
    };
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-ink/80 p-4 backdrop-blur-sm sm:p-10" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-label={title}
        className={`animate-rise w-full ${wide ? "max-w-4xl" : "max-w-2xl"} rounded-2xl border border-line bg-panel shadow-2xl shadow-black/50 outline-none`}>
        <div className="flex items-center justify-between border-b border-line-soft px-6 py-4">
          <h2 className="text-lg font-bold">{title}</h2>
          <button onClick={onClose} className="rounded-md p-1.5 text-muted hover:bg-raised hover:text-fg" aria-label="Close"><X className="size-5" /></button>
        </div>
        <div className="p-6">{children}</div>
      </div>
    </div>
  );
}
