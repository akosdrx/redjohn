/**
 * Terminal output core — pure functions/classes with no DOM or xterm
 * dependency, so they are unit-testable in Node and reusable anywhere.
 *
 * Security model:
 *  - `sanitizeTerminalChunk` allows ONLY SGR color sequences (ESC [ ... m)
 *    and the whitespace controls \t \n \r. Everything else — OSC (title,
 *    clipboard OSC 52, hyperlinks OSC 8), DCS/SOS/PM/APC, C1 codes, charset
 *    switches, cursor controls — is stripped. The terminal never performs
 *    automatic URL or clipboard actions.
 *  - `stripAnsi` removes ALL escape sequences for the plain-text
 *    search/export buffer.
 */

const ESC = "\x1b";

function cleanAnsi(input: string, keepSgr: boolean): string {
  let out = "";
  let i = 0;
  const n = input.length;
  while (i < n) {
    const ch = input[i]!;
    const code = ch.charCodeAt(0);

    // Pass through safe whitespace.
    if (ch === "\t" || ch === "\n" || ch === "\r") {
      out += ch;
      i += 1;
      continue;
    }

    // C0 controls other than whitespace and C1 controls (as raw bytes/chars): strip.
    if ((code < 0x20 && ch !== ESC) || (code >= 0x80 && code <= 0x9f)) {
      i += 1;
      continue;
    }

    if (ch === ESC) {
      const next = input[i + 1];
      if (next === "[") {
        // CSI: ESC [ params(0x30-0x3F) intermediates(0x20-0x2F) final(0x40-0x7E).
        const m = /^\x1b\[([0-?]*)([ -/]*)([@-~])/.exec(input.slice(i));
        if (m) {
          // Keep ONLY SGR when keepSgr is true: final "m", no private-marker
          // params (< = > ?) and no intermediate bytes. Colon sub-parameters
          // (24-bit truecolor `38:2:…`, styled underlines `4:3`) are valid SGR.
          if (keepSgr && m[3] === "m" && !/[<=>?]/.test(m[1]!) && m[2] === "") {
            out += m[0];
          }
          i += m[0].length;
          continue;
        }
        // Incomplete or malformed CSI: drop the ESC, rescan remainder.
        i += 1;
        continue;
      }
      if (next === "]") {
        // OSC: ESC ] ... (BEL | ESC \) — always stripped.
        i = skipOsc(input, i + 2);
        continue;
      }
      if (next === "P" || next === "X" || next === "^" || next === "_") {
        // DCS / SOS / PM / APC: ... ST — always stripped.
        i = skipSt(input, i + 2);
        continue;
      }
      // Any other escape (charset selects, DECSC, etc.): drop ESC + one char.
      i += next === undefined ? 1 : 2;
      continue;
    }

    out += ch;
    i += 1;
  }
  return out;
}

/**
 * Remove dangerous terminal control sequences, keeping only SGR styling.
 * Works on arbitrary chunk boundaries: an incomplete trailing sequence is
 * held back by the caller via `splitTrailingEscape`.
 */
export function sanitizeTerminalChunk(input: string): string {
  return cleanAnsi(input, true);
}

function skipOsc(input: string, i: number): number {
  // Terminated by BEL or ST (ESC \ or C1 ST 0x9c).
  while (i < input.length) {
    if (input[i] === "\x07") return i + 1;
    if (input[i] === ESC && input[i + 1] === "\\") return i + 2;
    if (input[i] === "\x9c") return i + 1;
    i += 1;
  }
  return input.length;
}

function skipSt(input: string, i: number): number {
  while (i < input.length) {
    if (input[i] === ESC && input[i + 1] === "\\") return i + 2;
    if (input[i] === "\x9c") return i + 1;
    i += 1;
  }
  return input.length;
}

/** Remove ALL ANSI/terminal escape sequences — for search & export. */
export function stripAnsi(input: string): string {
  return cleanAnsi(input, false);
}

/**
 * Upper bound on how much is carried over to the next chunk as a (supposedly)
 * incomplete trailing escape. A misbehaving tool can emit an escape introducer
 * (e.g. an OSC `ESC ]`) that it never terminates; without this cap, every
 * following chunk would be absorbed into the carry forever, blanking output and
 * growing memory without limit. Past this size we stop withholding and let the
 * sanitizer strip the runaway sequence instead.
 */
export const MAX_TRAILING_CARRY = 64 * 1024;

/**
 * If a chunk ends mid-escape-sequence, split it so the caller can prepend
 * the remainder to the next chunk before sanitizing.
 */
export function splitTrailingEscape(input: string): [complete: string, rest: string] {
  let i = 0;
  const n = input.length;
  while (i < n) {
    const escIdx = input.indexOf(ESC, i);
    if (escIdx === -1) return [input, ""];
    const next = input[escIdx + 1];
    if (next === undefined) {
      return [input.slice(0, escIdx), ESC];
    }
    if (next === "[") {
      // CSI: ESC [ params(0x30-0x3F) intermediates(0x20-0x2F) final(0x40-0x7E)
      let j = escIdx + 2;
      while (j < n && input.charCodeAt(j) >= 0x30 && input.charCodeAt(j) <= 0x3f) j++;
      while (j < n && input.charCodeAt(j) >= 0x20 && input.charCodeAt(j) <= 0x2f) j++;
      if (j >= n) {
        const tail = input.slice(escIdx);
        if (tail.length > MAX_TRAILING_CARRY) return [input, ""];
        return [input.slice(0, escIdx), tail];
      }
      const finalCode = input.charCodeAt(j);
      if (finalCode >= 0x40 && finalCode <= 0x7e) {
        i = j + 1;
        continue;
      }
      // Malformed CSI: advance past ESC and continue scanning.
      i = escIdx + 1;
      continue;
    }
    if (next === "]" || next === "P" || next === "X" || next === "^" || next === "_") {
      // OSC (terminated by BEL, ESC \, or 0x9c) or DCS/SOS/PM/APC (terminated by ESC \ or 0x9c).
      const allowBel = next === "]";
      let j = escIdx + 2;
      let terminated = false;
      while (j < n) {
        const c = input[j]!;
        if (allowBel && c === "\x07") {
          j += 1;
          terminated = true;
          break;
        }
        if (c === "\x9c") {
          j += 1;
          terminated = true;
          break;
        }
        if (c === ESC && input[j + 1] === "\\") {
          j += 2;
          terminated = true;
          break;
        }
        j += 1;
      }
      if (!terminated) {
        const tail = input.slice(escIdx);
        if (tail.length > MAX_TRAILING_CARRY) return [input, ""];
        return [input.slice(0, escIdx), tail];
      }
      i = j;
      continue;
    }
    if (next.charCodeAt(0) >= 0x20 && next.charCodeAt(0) <= 0x2f) {
      // nF / charset: ESC + intermediates (0x20-0x2F) + final (0x30-0x7E)
      let j = escIdx + 2;
      while (j < n && input.charCodeAt(j) >= 0x20 && input.charCodeAt(j) <= 0x2f) j++;
      if (j >= n) {
        const tail = input.slice(escIdx);
        if (tail.length > MAX_TRAILING_CARRY) return [input, ""];
        return [input.slice(0, escIdx), tail];
      }
      i = j + 1;
      continue;
    }
    // Simple two-char escape.
    i = escIdx + 2;
  }
  return [input, ""];
}

export const DEFAULT_MAX_LINES = 5000;

/**
 * Capped plain-text line buffer backing search/copy/export.
 * Oldest lines are dropped once `maxLines` is exceeded.
 */
export class TerminalLineBuffer {
  private lines: string[] = [];
  private partial = "";
  private dropped = 0;
  /** A `\r` at the end of a chunk whose CRLF/overwrite meaning needs the next byte. */
  private pendingCR = false;

  constructor(public readonly maxLines: number = DEFAULT_MAX_LINES) {}

  /** Append a raw (already sanitized) chunk; returns completed new lines. */
  append(chunk: string): string[] {
    const completed: string[] = [];
    let text = chunk;
    // Resolve a `\r` deferred from the previous chunk now that the next byte is
    // known: `\r\n` split across the boundary is a newline; a bare `\r` is a
    // carriage-return overwrite of the current line.
    if (this.pendingCR) {
      this.pendingCR = false;
      if (text.startsWith("\n")) {
        completed.push(this.partial);
        this.partial = "";
        text = text.slice(1);
      } else {
        this.partial = "";
      }
    }
    text = this.partial + text;
    this.partial = "";
    let start = 0;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i]!;
      if (ch === "\n") {
        completed.push(text.slice(start, i));
        start = i + 1;
      } else if (ch === "\r") {
        if (text[i + 1] === "\n") {
          // CRLF within this chunk.
          completed.push(text.slice(start, i));
          start = i + 2;
          i += 1;
        } else if (i + 1 === text.length) {
          // Trailing `\r`: could be a CRLF split across the next chunk. Hold the
          // line so far and defer the decision rather than discarding it.
          this.partial = text.slice(start, i);
          this.pendingCR = true;
          start = text.length;
        } else {
          // Bare carriage return: discard the current partial line (overwrite).
          start = i + 1;
        }
      }
    }
    if (start < text.length) this.partial = text.slice(start);
    if (completed.length > 0) {
      this.lines.push(...completed);
      if (this.lines.length > this.maxLines) {
        const overflow = this.lines.length - this.maxLines;
        this.lines.splice(0, overflow);
        this.dropped += overflow;
      }
    }
    return completed;
  }

  /** Number of lines dropped due to the cap (for tests/diagnostics). */
  get droppedCount(): number {
    return this.dropped;
  }

  get hasPartial(): boolean {
    return this.partial.length > 0 || this.pendingCR;
  }

  get length(): number {
    return this.lines.length + (this.partial.length > 0 ? 1 : 0);
  }

  /** All lines including the current partial line. */
  getLines(): string[] {
    return this.partial.length > 0 ? [...this.lines, this.partial] : [...this.lines];
  }

  /** Case-insensitive substring search; returns matching line indices. */
  search(query: string): number[] {
    if (!query) return [];
    const q = query.toLowerCase();
    const all = this.getLines();
    const hits: number[] = [];
    for (let i = 0; i < all.length; i++) {
      if (all[i]!.toLowerCase().includes(q)) hits.push(i);
    }
    return hits;
  }

  /** Full plain-text export. */
  toString(): string {
    return this.getLines().join("\n");
  }

  /** Render buffered lines and any trailing partial line for xterm repaint. */
  toTerminalString(): string {
    if (this.lines.length === 0 && this.partial.length === 0) return "";
    const head = this.lines.length > 0 ? `${this.lines.join("\r\n")}\r\n` : "";
    return head + this.partial;
  }

  clear(): void {
    this.lines = [];
    this.partial = "";
    this.pendingCR = false;
  }
}

/**
 * Format a terminal line: `[14:08:21] WEB  message`.
 *
 * `tag` must be the PLAIN label — it is uppercased, padded and truncated here.
 * Pass `colorize` to wrap the already-formatted tag in SGR codes; applying
 * color before formatting would corrupt the escape (toUpperCase/slice mangles
 * and truncates the sequence).
 */
export function formatLogLine(
  occurredAt: string | Date,
  tag: string,
  message: string,
  colorize?: (formattedTag: string) => string,
): string {
  const d = typeof occurredAt === "string" ? new Date(occurredAt) : occurredAt;
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const t = tag.toUpperCase().padEnd(4, " ").slice(0, 8);
  return `[${hh}:${mm}:${ss}] ${colorize ? colorize(t) : t} ${message}`;
}
