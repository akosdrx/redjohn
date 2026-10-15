import { useEffect, useRef, useState, type FormEvent } from "react";
import { strings } from "../strings.js";
import type { AgentRow } from "../types.js";
import { cn } from "../utils.js";
import { Select } from "./primitives.js";

export interface MessageComposerProps {
  agents: AgentRow[];
  /** Recipient agent id; synced with the selected agent. */
  recipientId: string | null;
  onRecipientChange: (agentId: string) => void;
  /** Returns a promise; errors are surfaced inline. */
  onSend: (agentId: string, body: string) => Promise<void>;
  disabled?: boolean;
  className?: string;
}

/** "To: [Web ▾] [Message this agent…] [send]" bar. */
export function MessageComposer({
  agents,
  recipientId,
  onRecipientChange,
  onSend,
  disabled = false,
  className,
}: MessageComposerProps) {
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);
  const sentTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (sentTimerRef.current !== null) {
        clearTimeout(sentTimerRef.current);
        sentTimerRef.current = null;
      }
    };
  }, []);

  async function submit(e: FormEvent): Promise<void> {
    e.preventDefault();
    const text = body.trim();
    if (!text || !recipientId || busy) return;
    setBusy(true);
    setError(null);
    setSent(false);
    try {
      await onSend(recipientId, text);
      setBody("");
      setSent(true);
      if (sentTimerRef.current !== null) clearTimeout(sentTimerRef.current);
      sentTimerRef.current = setTimeout(() => {
        sentTimerRef.current = null;
        setSent(false);
      }, 2000);
    } catch {
      setError(strings.composer.failed);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} className={cn("flex items-center gap-2", className)}>
      <label className="flex shrink-0 items-center gap-1.5 text-[12px] text-rj-text-2">
        {strings.composer.to}
        <Select
          value={recipientId ?? ""}
          onChange={(e) => onRecipientChange(e.target.value)}
          aria-label="Recipient agent"
          disabled={disabled}
          className="h-7 min-w-28 w-40 text-[12px]"
        >
          {recipientId == null && <option value="" disabled>—</option>}
          {agents.map((a) => (
            <option key={a.agentId} value={a.agentId}>
              {a.name}
            </option>
          ))}
        </Select>
      </label>
      <input
        type="text"
        value={body}
        onChange={(e) => {
          setBody(e.target.value);
          if (error) setError(null);
        }}
        placeholder={strings.composer.placeholder}
        aria-label={strings.composer.placeholder}
        disabled={disabled || recipientId == null}
        className="h-8 min-w-0 flex-1 rounded-md border border-rj-border-strong bg-rj-panel-sunken px-2.5 text-[12px] text-rj-text placeholder:text-rj-text-3 outline-none focus:border-rj-accent disabled:opacity-50"
      />
      <button
        type="submit"
        aria-label={strings.composer.send}
        disabled={disabled || busy || !body.trim() || recipientId == null}
        className="shrink-0 cursor-pointer rounded-md bg-rj-accent-strong p-2 text-white hover:bg-rj-accent disabled:opacity-40"
      >
        <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
          <path d="M1 7L13 1 9 13 7 8.5 1 7z" fill="currentColor" stroke="currentColor" strokeWidth="0.8" strokeLinejoin="round" />
        </svg>
      </button>
      {sent && !error && (
        <span role="status" className="shrink-0 text-[11px] text-rj-live">
          {strings.composer.sent}
        </span>
      )}
      {error && (
        <span role="alert" className="shrink-0 text-[11px] text-rj-down">
          {error}
        </span>
      )}
    </form>
  );
}
