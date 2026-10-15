/**
 * Run event stream client: WebSocket with
 *  - after_seq replay on (re)connect (server hands off replay->live)
 *  - event_id dedup (bounded)
 *  - REST gap-fill via /events when a seq gap is detected
 *  - snapshot resync when the server answers 410 (cursor expired)
 *
 * WS authentication: the token is sent as a Sec-WebSocket-Protocol value
 * (`rj-auth-<base64url(token)>`), never in the URL. NOTE: the contract
 * does not specify the WS auth mechanism — this is the documented desktop
 * choice; coordinate with rj-cli if it picks a different one.
 */
import type { RunEvent } from "./api";
import { ApiError } from "./api";

export type StreamState = "connecting" | "live" | "reconnecting" | "resyncing" | "stopped";

export interface WebSocketLike {
  readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  onopen: (() => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: ((ev: { code: number; reason: string }) => void) | null;
  onerror: (() => void) | null;
}

export interface RunStreamOptions {
  wsUrl: string;
  token: string;
  wsFactory: (url: string, protocols: string[]) => WebSocketLike;
  /** GET /events?after_seq=… — must throw ApiError(410) when expired. */
  replay: (afterSeq: number) => Promise<{ items: RunEvent[]; cursor: number }>;
  /** Refetch the snapshot; resolves with the new cursor. */
  resnapshot: () => Promise<{ cursor: number }>;
  onEvent: (ev: RunEvent) => void;
  onState?: (state: StreamState) => void;
  /** Cap for the event_id dedup set. */
  dedupCap?: number;
  baseBackoffMs?: number;
  maxBackoffMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

export function encodeWsToken(token: string): string {
  // base64url, safe for Sec-WebSocket-Protocol
  const b64 = btoa(token).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `rj-auth-${b64}`;
}

export class RunStream {
  private ws: WebSocketLike | null = null;
  private cursor: number;
  private seen = new Set<string>();
  private dedupQueue: string[] = [];
  private stopped = false;
  private backoff: number;
  private dedupCap: number;
  private processing: Promise<void> = Promise.resolve();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(private opts: RunStreamOptions, startAfterSeq = 0) {
    this.cursor = startAfterSeq;
    this.dedupCap = opts.dedupCap ?? 10_000;
    this.backoff = opts.baseBackoffMs ?? 500;
  }

  get lastSeq(): number {
    return this.cursor;
  }

  private setState(s: StreamState): void {
    this.opts.onState?.(s);
  }

  private sleep(ms: number): Promise<void> {
    if (this.opts.sleep) return this.opts.sleep(ms);
    return new Promise((resolve) => {
      this.reconnectTimer = setTimeout(() => {
        this.reconnectTimer = null;
        resolve();
      }, ms);
    });
  }

  connect(): void {
    if (this.stopped) return;
    this.setState(this.ws ? "reconnecting" : "connecting");
    let ws: WebSocketLike;
    try {
      const url = `${this.opts.wsUrl}?after_seq=${this.cursor}`;
      ws = this.opts.wsFactory(url, ["redjohn-v1", encodeWsToken(this.opts.token)]);
    } catch {
      // The WebSocket constructor throws synchronously on a malformed URL, and
      // btoa() throws on a non-Latin-1 token. Either must not strand the stream
      // permanently in "reconnecting" with no socket and no pending retry —
      // schedule a backoff reconnect instead.
      this.ws = null;
      if (!this.stopped) void this.reconnect();
      return;
    }
    this.ws = ws;

    ws.onopen = () => {
      this.backoff = this.opts.baseBackoffMs ?? 500;
      this.setState("live");
    };
    ws.onmessage = (ev) => {
      const parsed = parseRunEvent(ev.data);
      if (parsed) {
        // Keep replay and live delivery on one queue: later frames must not
        // move the cursor past an in-flight gap fill.
        this.processing = this.processing.then(async () => {
          if (!this.stopped) await this.handleEvent(parsed);
        }).catch(() => {
          // A network error leaves the cursor at the last delivered event.
          // Reconnect from there; stopping during replay is not an error.
          if (!this.stopped && this.ws === ws) ws.close();
        });
      }
    };
    ws.onclose = () => {
      if (this.ws !== ws) return;
      this.ws = null;
      if (!this.stopped) {
        this.setState("reconnecting");
        void this.reconnect();
      }
    };
    ws.onerror = () => {
      try {
        ws.close();
      } catch {
        /* ignored */
      }
    };
  }

  private async reconnect(): Promise<void> {
    const max = this.opts.maxBackoffMs ?? 10_000;
    await this.sleep(this.backoff);
    if (this.stopped) return;
    this.backoff = Math.min(this.backoff * 2, max);
    this.connect();
  }

  private remember(eventId: string): boolean {
    if (this.seen.has(eventId)) return false;
    this.seen.add(eventId);
    this.dedupQueue.push(eventId);
    if (this.dedupQueue.length > this.dedupCap) {
      const oldest = this.dedupQueue.shift()!;
      this.seen.delete(oldest);
    }
    return true;
  }

  private async handleEvent(ev: RunEvent): Promise<void> {
    if (ev.schema_version !== 1 || ev.seq <= this.cursor || this.seen.has(ev.event_id)) return;
    if (ev.seq > this.cursor + 1) await this.fillGap(ev.seq - 1);
    if (this.stopped || ev.seq <= this.cursor || !this.remember(ev.event_id)) return;
    this.cursor = ev.seq;
    this.opts.onEvent(ev);
  }

  private async fillGap(throughSeq: number, resynced = false): Promise<void> {
    while (!this.stopped && this.cursor < throughSeq) {
      try {
        const before = this.cursor;
        const page = await this.opts.replay(before);
        if (this.stopped) return;
        for (const ev of page.items) {
          if (ev.seq <= this.cursor || !this.remember(ev.event_id)) continue;
          this.cursor = ev.seq;
          this.opts.onEvent(ev);
        }
        // REST cursor is the server high-water mark, not the end of this
        // bounded page. Advance only over events actually delivered.
        if (this.cursor <= before) {
          // No progress. After a resync, accept the residual hole (those events
          // are genuinely gone from retention) instead of looping/throwing;
          // before a resync this is the existing "stuck gap" reconnect signal.
          if (resynced) return;
          throw new Error("event replay made no progress");
        }
      } catch (err) {
        if (err instanceof ApiError && err.status === 410) {
          this.setState("resyncing");
          const snap = await this.opts.resnapshot();
          if (this.stopped) return;
          this.cursor = snap.cursor;
          this.setState("live");
          // Do not abandon the rest of the gap: re-fill from the new snapshot
          // cursor so events between it and the live frame (still retained) are
          // delivered rather than silently skipped. Guard against repeated
          // resync — one per gap, then accept whatever remains.
          if (resynced) return;
          resynced = true;
          continue;
        }
        throw err;
      }
    }
  }

  stop(): void {
    this.stopped = true;
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.setState("stopped");
    try {
      this.ws?.close();
    } catch {
      /* ignored */
    }
    this.ws = null;
  }
}

export function parseRunEvent(data: unknown): RunEvent | null {
  try {
    const text = typeof data === "string" ? data : "";
    if (!text) return null;
    const obj = JSON.parse(text) as Partial<RunEvent>;
    if (
      typeof obj !== "object" ||
      obj === null ||
      typeof obj.event_id !== "string" ||
      // seq must be a finite, non-negative integer. A non-finite value from
      // JSON (e.g. 1e999 -> Infinity) or a NaN/fraction would poison the cursor
      // and wedge gap-fill into an unbounded replay; reject it here.
      !Number.isSafeInteger(obj.seq) ||
      (obj.seq as number) < 0 ||
      typeof obj.type !== "string" ||
      typeof obj.schema_version !== "number"
    ) {
      return null;
    }
    return obj as RunEvent;
  } catch {
    return null;
  }
}
