import type { ReactNode } from "react";
import { strings } from "../strings.js";
import { Button, Spinner } from "./primitives.js";

export function EmptyState({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="flex h-full min-h-32 flex-col items-center justify-center gap-2 p-6 text-center">
      <svg width="28" height="28" viewBox="0 0 28 28" aria-hidden="true" className="text-rj-text-3">
        <rect x="4" y="4" width="20" height="20" rx="3" fill="none" stroke="currentColor" strokeWidth="1.5" strokeDasharray="3 3" />
      </svg>
      <p className="text-[13px] font-medium text-rj-text-2">{title}</p>
      {hint && <p className="max-w-sm text-[12px] text-rj-text-3">{hint}</p>}
      {action}
    </div>
  );
}

export function LoadingState({ label }: { label?: string }) {
  return (
    <div className="flex h-full min-h-32 items-center justify-center gap-2 p-6 text-rj-text-3" role="status">
      <Spinner />
      <span className="text-[12px]">{label ?? strings.states.loading}</span>
    </div>
  );
}

export function ErrorState({
  title,
  detail,
  onRetry,
}: {
  title?: string;
  detail?: string;
  onRetry?: () => void;
}) {
  return (
    <div className="flex h-full min-h-32 flex-col items-center justify-center gap-2 p-6 text-center" role="alert">
      <svg width="28" height="28" viewBox="0 0 28 28" aria-hidden="true" className="text-rj-down">
        <circle cx="14" cy="14" r="11" fill="none" stroke="currentColor" strokeWidth="1.5" />
        <path d="M14 8v7" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
        <circle cx="14" cy="19.5" r="1.2" fill="currentColor" />
      </svg>
      <p className="text-[13px] font-medium text-rj-text">{title ?? strings.states.errorTitle}</p>
      {detail && <p className="max-w-md text-[12px] text-rj-text-3">{detail}</p>}
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry} className="mt-1">
          {strings.states.retry}
        </Button>
      )}
    </div>
  );
}
