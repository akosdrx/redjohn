"use client";

import {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { cn } from "../utils.js";
import { strings } from "../strings.js";
import { colors } from "../tokens.js";
import type { AgentRow } from "../types.js";
import {
  TerminalLineBuffer,
  sanitizeTerminalChunk,
  splitTrailingEscape,
  stripAnsi,
} from "../terminal-core.js";
import { StatusPill } from "./StatusPill.js";

export interface LiveTerminalHandle {
  /**
   * Append terminal output. `chunk` may contain SGR color sequences; all
   * other control sequences are stripped. `agentId` routes the chunk into
   * that agent's tab as well as "all".
   */
  write: (chunk: string, agentId?: string | null) => void;
  clear: () => void;
}

export interface LiveTerminalProps {
  agents: AgentRow[];
  /** null = "All agents" tab. Always synced with the selected agent row. */
  selectedAgentId: string | null;
  onSelectAgent: (agentId: string | null) => void;
  /** Header meta, e.g. "app.acme.test". */
  targetLabel?: string;
  streaming?: boolean;
  maximized?: boolean;
  onToggleMaximize?: () => void;
  follow: boolean;
  onFollowChange: (follow: boolean) => void;
  onOpenLogs?: () => void;
  /** Composer row rendered below the terminal. */
  composer?: React.ReactNode;
  className?: string;
}

const ALL_TAB = "all";
const SCROLLBACK = 2000; // xterm render cap
const BUFFER_LINES = SCROLLBACK; // match xterm scrollback cap so repaint() never feeds discarded lines

export const LiveTerminal = forwardRef<LiveTerminalHandle, LiveTerminalProps>(function LiveTerminal(
  {
    agents,
    selectedAgentId,
    onSelectAgent,
    targetLabel,
    streaming = false,
    maximized = false,
    onToggleMaximize,
    follow,
    onFollowChange,
    onOpenLogs,
    composer,
    className,
  },
  ref,
) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const searchRef = useRef<SearchAddon | null>(null);
  const buffersRef = useRef<Map<string, TerminalLineBuffer>>(new Map([[ALL_TAB, new TerminalLineBuffer(BUFFER_LINES)]]));
  const styledBuffersRef = useRef<Map<string, TerminalLineBuffer>>(new Map([[ALL_TAB, new TerminalLineBuffer(BUFFER_LINES)]]));
  const trailingRef = useRef<Map<string, string>>(new Map()); // partial escape carry
  const lastAllPartialOwnerRef = useRef<string | null>(null);
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [paused, setPaused] = useState(false);
  const [query, setQuery] = useState("");
  const [copied, setCopied] = useState(false);
  const [tabsWithOutput, setTabsWithOutput] = useState<ReadonlySet<string>>(() => new Set());

  const activeTab = selectedAgentId ?? ALL_TAB;
  const activeAgent = agents.find((a) => a.agentId === selectedAgentId) ?? null;
  const hasOutput = tabsWithOutput.has(activeTab);

  // Keep latest values readable from imperative write().
  const liveRef = useRef({ activeTab, paused, follow });
  useEffect(() => {
    liveRef.current = { activeTab, paused, follow };
  }, [activeTab, paused, follow]);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        clearTimeout(copyTimerRef.current);
        copyTimerRef.current = null;
      }
    };
  }, []);

  function bufferFor(key: string): TerminalLineBuffer {
    let b = buffersRef.current.get(key);
    if (!b) {
      b = new TerminalLineBuffer(BUFFER_LINES);
      buffersRef.current.set(key, b);
    }
    return b;
  }

  function styledBufferFor(key: string): TerminalLineBuffer {
    let b = styledBuffersRef.current.get(key);
    if (!b) {
      b = new TerminalLineBuffer(BUFFER_LINES);
      styledBuffersRef.current.set(key, b);
    }
    return b;
  }

  // Prune buffers for agents that are no longer in the agents list.
  useEffect(() => {
    const valid = new Set<string>([ALL_TAB, ...agents.map((a) => a.agentId)]);
    for (const k of buffersRef.current.keys()) {
      if (!valid.has(k)) buffersRef.current.delete(k);
    }
    for (const k of styledBuffersRef.current.keys()) {
      if (!valid.has(k)) styledBuffersRef.current.delete(k);
    }
    for (const k of trailingRef.current.keys()) {
      if (!valid.has(k)) trailingRef.current.delete(k);
    }
  }, [agents]);

  function writeToTerm(chunk: string): void {
    const term = termRef.current;
    if (!term) return;
    term.write(chunk, () => {
      if (liveRef.current.follow) term.scrollToBottom();
    });
  }

  /** Re-render the terminal from the styled buffer (tab switch / resume). */
  function repaint(key: string): void {
    const term = termRef.current;
    if (!term) return;
    term.reset();
    const text = styledBufferFor(key).toTerminalString();
    if (text) writeToTerm(text);
  }

  // Mount xterm once.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const term = new Terminal({
      scrollback: SCROLLBACK,
      disableStdin: true, // read-only display; no shell, no link/clipboard addons
      convertEol: false,
      fontSize: 12,
      fontFamily: 'ui-monospace, "SF Mono", Menlo, Consolas, monospace',
      cursorBlink: false,
      theme: {
        background: colors.terminal,
        foreground: "#c8d0d8",
        cursor: colors.terminal,
        selectionBackground: "#2e3944",
        black: "#0d1116",
        red: colors.accent,
        green: colors.live,
        yellow: colors.medium,
        blue: colors.low,
        magenta: "#b98ae0",
        cyan: "#5cc8c0",
        white: "#e8ebee",
      },
    });
    const fit = new FitAddon();
    const search = new SearchAddon();
    term.loadAddon(fit);
    term.loadAddon(search);
    term.open(el);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;
    searchRef.current = search;

    const ro = new ResizeObserver(() => {
      try {
        fit.fit();
      } catch {
        /* container hidden */
      }
    });
    ro.observe(el);
    repaint(activeTab);
    return () => {
      ro.disconnect();
      term.dispose();
      termRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Repaint when switching tabs.
  const prevTabRef = useRef(activeTab);
  useEffect(() => {
    if (prevTabRef.current !== activeTab) {
      prevTabRef.current = activeTab;
      repaint(activeTab);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  useImperativeHandle(ref, () => ({
    write(chunk, agentId = null) {
      const key = agentId ?? ALL_TAB;
      // Join any partial escape sequence from the previous chunk.
      const carried = (trailingRef.current.get(key) ?? "") + chunk;
      const [complete, rest] = splitTrailingEscape(carried);
      trailingRef.current.set(key, rest);
      const styled = sanitizeTerminalChunk(complete);
      const plain = stripAnsi(complete);
      const allPlain = bufferFor(ALL_TAB);
      const allStyled = styledBufferFor(ALL_TAB);
      let prefixBreak = "";
      if (plain && allPlain.hasPartial && lastAllPartialOwnerRef.current !== null && lastAllPartialOwnerRef.current !== key) {
        allPlain.append("\n");
        allStyled.append("\n");
        prefixBreak = "\r\n";
      }
      allPlain.append(plain);
      allStyled.append(styled);
      lastAllPartialOwnerRef.current = allPlain.hasPartial ? key : null;
      if (agentId) {
        bufferFor(agentId).append(plain);
        styledBufferFor(agentId).append(styled);
      }
      if (plain) {
        setTabsWithOutput((prev) => {
          if (prev.has(ALL_TAB) && (!agentId || prev.has(agentId))) return prev;
          const next = new Set(prev);
          next.add(ALL_TAB);
          if (agentId) next.add(agentId);
          return next;
        });
      }
      const { activeTab: tab, paused: isPaused } = liveRef.current;
      const visible = tab === ALL_TAB || tab === agentId;
      if (!visible) return;
      if (isPaused) return;
      const out = (tab === ALL_TAB ? prefixBreak : "") + styled.replace(/\r?\n/g, "\r\n");
      if (out) writeToTerm(out);
    },
    clear() {
      buffersRef.current.forEach((b) => b.clear());
      styledBuffersRef.current.forEach((b) => b.clear());
      trailingRef.current.clear();
      lastAllPartialOwnerRef.current = null;
      termRef.current?.reset();
      setTabsWithOutput(new Set());
    },
  }), []);

  // The normal bounded buffer also holds paused output in event order.
  const wasPausedRef = useRef(false);
  useEffect(() => {
    if (wasPausedRef.current && !paused) repaint(activeTab);
    wasPausedRef.current = paused;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paused]);

  // Search.
  useEffect(() => {
    const s = searchRef.current;
    if (!s) return;
    if (query) {
      s.findNext(query, { incremental: true, caseSensitive: false });
    } else {
      s.clearDecorations?.();
    }
  }, [query]);

  function copyAll(): void {
    const text = bufferFor(activeTab).toString();
    void navigator.clipboard?.writeText(text).then(
      () => {
        setCopied(true);
        if (copyTimerRef.current !== null) clearTimeout(copyTimerRef.current);
        copyTimerRef.current = setTimeout(() => {
          copyTimerRef.current = null;
          setCopied(false);
        }, 1500);
      },
      () => {
        /* clipboard denied / unfocused / insecure context — ignore */
      },
    );
  }

  function exportLog(): void {
    const text = bufferFor(activeTab).toString();
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `redjohn-terminal-${activeTab}.log`;
    // Attach to the document and revoke after the click is scheduled; revoking
    // synchronously (or never appending) cancels or no-ops the download on
    // Chromium/Firefox/Safari.
    document.body.append(a);
    a.click();
    a.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return (
    <div className={cn("flex min-h-0 flex-col", className)}>
      {/* Agent tabs — synced with the selected agent row. */}
      <div role="tablist" aria-label="Agent output tabs" className="flex items-center gap-1 overflow-x-auto border-b border-rj-border px-2">
        <TabButton active={activeTab === ALL_TAB} onClick={() => onSelectAgent(null)}>
          {strings.terminal.allAgents(agents.length)}
        </TabButton>
        {agents.map((a) => (
          <TabButton
            key={a.agentId}
            active={activeTab === a.agentId}
            onClick={() => onSelectAgent(a.agentId)}
          >
            {a.name}
          </TabButton>
        ))}
      </div>

      {/* Header: agent handle + target + streaming state */}
      <div className="flex items-center justify-between gap-2 border-b border-rj-border px-3 py-1.5">
        <div className="flex min-w-0 items-center gap-2 text-[12px]">
          <span className="font-medium text-rj-text">
            {activeAgent ? `${activeAgent.name}${activeAgent.handle ? ` · ${activeAgent.handle}` : ""}` : "Live output"}
          </span>
          {(activeAgent?.target ?? targetLabel) && (
            <span className="truncate text-rj-text-3">
              {strings.terminal.target} <span className="font-mono text-rj-text-2">{activeAgent?.target ?? targetLabel}</span>
            </span>
          )}
        </div>
        {paused ? (
          <StatusPill kind="service" state="starting" label={strings.terminal.paused} size="sm" />
        ) : streaming ? (
          <StatusPill kind="service" state="live" label={strings.terminal.streaming} size="sm" />
        ) : (
          <StatusPill kind="service" state="not_configured" label={strings.terminal.idle} size="sm" />
        )}
      </div>

      {/* Search + controls */}
      <div className="flex items-center gap-2 px-3 py-1.5">
        <div className="relative ml-auto flex items-center">
          <svg className="pointer-events-none absolute left-2 text-rj-text-3" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
            <circle cx="5" cy="5" r="3.5" fill="none" stroke="currentColor" strokeWidth="1.3" />
            <path d="M7.5 7.5L11 11" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
          </svg>
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && query) {
                e.preventDefault();
                if (e.shiftKey) {
                  searchRef.current?.findPrevious(query, { caseSensitive: false });
                } else {
                  searchRef.current?.findNext(query, { caseSensitive: false });
                }
              }
            }}
            placeholder={strings.terminal.searchPlaceholder}
            aria-label={strings.terminal.searchPlaceholder}
            className="h-7 w-52 rounded-md border border-rj-border-strong bg-rj-panel-sunken pl-7 pr-2 text-[12px] text-rj-text placeholder:text-rj-text-3 outline-none focus:border-rj-accent"
          />
        </div>
        <IconBtn label={paused ? strings.terminal.resume : strings.terminal.pause} onClick={() => setPaused((p) => !p)}>
          {paused ? (
            <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M3 2l7 4-7 4V2z" fill="currentColor" /></svg>
          ) : (
            <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M3 2h2.4v8H3zM6.6 2H9v8H6.6z" fill="currentColor" /></svg>
          )}
        </IconBtn>
        <IconBtn label={maximized ? strings.terminal.restore : strings.terminal.maximize} onClick={onToggleMaximize}>
          <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
            {maximized ? (
              <path d="M2 5h5v5H2zM5 2h5v5" fill="none" stroke="currentColor" strokeWidth="1.2" />
            ) : (
              <path d="M2 2h8v8H2z" fill="none" stroke="currentColor" strokeWidth="1.2" />
            )}
          </svg>
        </IconBtn>
      </div>

      {/* Terminal viewport */}
      <div className="relative min-h-0 flex-1 bg-rj-terminal">
        <div ref={containerRef} className="absolute inset-0 px-2 py-1" data-testid="terminal-viewport" />
        {!hasOutput && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center p-6 text-center text-[12px] text-rj-text-3">
            {strings.terminal.noOutput}
          </div>
        )}
      </div>

      {/* Composer + follow/logs row */}
      {(composer || onOpenLogs) && (
        <div className="flex items-center gap-2 border-t border-rj-border px-3 py-2">
          <div className="min-w-0 flex-1">{composer}</div>
          <button
            type="button"
            onClick={() => onFollowChange(!follow)}
            aria-pressed={follow}
            className={cn(
              "flex shrink-0 cursor-pointer items-center gap-1.5 rounded px-2 py-1 text-[11px]",
              follow ? "text-rj-live" : "text-rj-text-3 hover:text-rj-text",
            )}
          >
            <span aria-hidden="true" className={cn("inline-block size-1.5 rounded-full", follow ? "bg-rj-live" : "bg-rj-idle")} />
            {follow ? strings.terminal.follow : strings.terminal.followOff}
          </button>
          {onOpenLogs && (
            <button type="button" onClick={onOpenLogs} className="shrink-0 cursor-pointer rounded px-2 py-1 text-[11px] text-rj-text-2 hover:text-rj-text">
              {strings.terminal.openLogs}
            </button>
          )}
          <button type="button" onClick={copyAll} className="shrink-0 cursor-pointer rounded px-2 py-1 text-[11px] text-rj-text-2 hover:text-rj-text">
            {copied ? strings.terminal.copied : strings.terminal.copy}
          </button>
          <button type="button" onClick={exportLog} className="shrink-0 cursor-pointer rounded px-2 py-1 text-[11px] text-rj-text-2 hover:text-rj-text">
            {strings.terminal.export}
          </button>
        </div>
      )}
    </div>
  );
});

function TabButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={cn(
        "cursor-pointer whitespace-nowrap px-2.5 py-1.5 text-[12px] transition-colors",
        active
          ? "border-b-2 border-rj-accent font-medium text-rj-text"
          : "border-b-2 border-transparent text-rj-text-3 hover:text-rj-text-2",
      )}
    >
      {children}
    </button>
  );
}

function IconBtn({ label, onClick, children }: { label: string; onClick?: (() => void) | undefined; children: React.ReactNode }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      className="cursor-pointer rounded p-1.5 text-rj-text-3 hover:bg-rj-panel-hover hover:text-rj-text"
    >
      {children}
    </button>
  );
}
