import { describe, expect, it } from "vitest";
import {
  MAX_TRAILING_CARRY,
  TerminalLineBuffer,
  formatLogLine,
  sanitizeTerminalChunk,
  splitTrailingEscape,
  stripAnsi,
} from "./terminal-core";

describe("sanitizeTerminalChunk", () => {
  it("passes plain text through", () => {
    expect(sanitizeTerminalChunk("hello world\n")).toBe("hello world\n");
  });

  it("keeps SGR color sequences", () => {
    const input = "\x1b[31mred\x1b[0m";
    expect(sanitizeTerminalChunk(input)).toBe(input);
  });

  it("strips OSC hyperlinks and clipboard sequences", () => {
    expect(sanitizeTerminalChunk("\x1b]8;;https://evil.example\x07link\x1b]8;;\x07")).toBe("link");
    expect(sanitizeTerminalChunk("\x1b]52;c;aGVsbG8=\x07")).toBe("");
    expect(sanitizeTerminalChunk("a\x1b]0;title\x07b")).toBe("ab");
  });

  it("strips DCS/APC sequences", () => {
    expect(sanitizeTerminalChunk("\x1bPq1;2;3\x1b\\ok")).toBe("ok");
    expect(sanitizeTerminalChunk("\x1b_payload\x1b\\ok")).toBe("ok");
  });

  it("strips cursor movement and other CSI but keeps text", () => {
    expect(sanitizeTerminalChunk("\x1b[2J\x1b[10;5Hhello")).toBe("hello");
  });

  it("strips C0 controls except tab/newline/carriage-return", () => {
    expect(sanitizeTerminalChunk("a\x00b\x07c\td\ne")).toBe("abc\td\ne");
  });

  it("strips C1 controls and lone escapes", () => {
    expect(sanitizeTerminalChunk("a\x85b\x9cc")).toBe("abc");
    expect(sanitizeTerminalChunk("x\x1bcy")).toBe("xy");
  });

  it("keeps colon sub-parameter SGR (truecolor / styled underline)", () => {
    // ITU-T T.416 colon form must pass through as SGR, not leak as text.
    expect(sanitizeTerminalChunk("\x1b[38:2:255:0:0mred\x1b[0m")).toBe("\x1b[38:2:255:0:0mred\x1b[0m");
    expect(sanitizeTerminalChunk("\x1b[4:3munder\x1b[0m")).toBe("\x1b[4:3munder\x1b[0m");
  });

  it("strips CSI with non-letter finals and intermediates without leaking text", () => {
    expect(sanitizeTerminalChunk("ab\x1b[2@cd")).toBe("abcd"); // insert-chars
    expect(sanitizeTerminalChunk("\x1b[0 qx")).toBe("x"); // DECSCUSR (intermediate byte)
  });

  it("strips private-mode CSI (sequences with ? / < = >)", () => {
    expect(sanitizeTerminalChunk("\x1b[?25lhidden")).toBe("hidden");
  });
});

describe("stripAnsi", () => {
  it("removes all escape sequences including SGR", () => {
    expect(stripAnsi("\x1b[31mred\x1b[0m plain")).toBe("red plain");
  });
});

describe("splitTrailingEscape", () => {
  it("splits an incomplete trailing sequence", () => {
    expect(splitTrailingEscape("text\x1b[38;2;")).toEqual(["text", "\x1b[38;2;"]);
  });
  it("keeps complete sequences whole", () => {
    expect(splitTrailingEscape("text\x1b[0m")).toEqual(["text\x1b[0m", ""]);
  });
  it("does not withhold a complete sequence that is followed by text", () => {
    // regression: a terminated escape with trailing visible text must pass through
    expect(splitTrailingEscape("a\x1b[0mmore")).toEqual(["a\x1b[0mmore", ""]);
    expect(splitTrailingEscape("a\x1b]0;title\x07b")).toEqual(["a\x1b]0;title\x07b", ""]);
  });
  it("withholds only a genuinely unterminated trailing OSC", () => {
    expect(splitTrailingEscape("a\x1b]8;;http")).toEqual(["a", "\x1b]8;;http"]);
  });
  it("handles no escape", () => {
    expect(splitTrailingEscape("plain")).toEqual(["plain", ""]);
  });
  it("treats a complete colon sub-parameter SGR as whole (not withheld)", () => {
    // Previously the colon broke the CSI matcher, so this and ALL following
    // output was withheld forever and never displayed.
    expect(splitTrailingEscape("\x1b[38:2:255:0:0mred text\n")).toEqual(["\x1b[38:2:255:0:0mred text\n", ""]);
  });
  it("caps a runaway unterminated escape instead of carrying it unbounded", () => {
    // A never-terminated OSC must not absorb every following chunk forever.
    const runaway = "\x1b]" + "x".repeat(MAX_TRAILING_CARRY + 10);
    const [complete, rest] = splitTrailingEscape(runaway);
    expect(rest).toBe("");
    expect(complete).toBe(runaway);
    // The sanitizer then strips the runaway OSC to nothing (bounded work).
    expect(sanitizeTerminalChunk(complete)).toBe("");
  });
  it("withholds the entire OSC/DCS sequence when its ST terminator (ESC \\) is split across chunks", () => {
    const [c1, r1] = splitTrailingEscape("before\x1b]8;;https://evil.example\x1b");
    expect(c1).toBe("before");
    expect(r1).toBe("\x1b]8;;https://evil.example\x1b");
    const [c2, r2] = splitTrailingEscape(r1 + "\\after");
    expect(r2).toBe("");
    expect(sanitizeTerminalChunk(c1 + c2)).toBe("beforeafter");
  });
});

describe("TerminalLineBuffer", () => {
  it("appends lines and tracks partial line", () => {
    const b = new TerminalLineBuffer(10);
    expect(b.append("one\ntwo\nth")).toEqual(["one", "two"]);
    expect(b.getLines()).toEqual(["one", "two", "th"]);
    expect(b.append("ree\n")).toEqual(["three"]);
    expect(b.getLines()).toEqual(["one", "two", "three"]);
  });

  it("caps the buffer and counts dropped lines", () => {
    const b = new TerminalLineBuffer(5);
    for (let i = 0; i < 20; i++) b.append(`line-${i}\n`);
    expect(b.length).toBe(5);
    expect(b.droppedCount).toBe(15);
    expect(b.getLines()[0]).toBe("line-15");
  });

  it("handles CRLF and carriage-return overwrite", () => {
    const b = new TerminalLineBuffer();
    b.append("abc\r\ndef\rXY\n");
    expect(b.getLines()).toEqual(["abc", "XY"]);
  });

  it("preserves a line when CRLF is split across chunk boundaries", () => {
    // A WS frame can split exactly between \r and \n; the line must survive.
    const b = new TerminalLineBuffer();
    b.append("GET /login HTTP/1.1\r");
    b.append("\n401 Unauthorized\r\n");
    expect(b.getLines()).toEqual(["GET /login HTTP/1.1", "401 Unauthorized"]);
  });

  it("treats a bare CR split across chunks as an overwrite", () => {
    const b = new TerminalLineBuffer();
    b.append("old-line\r");
    b.append("new\n");
    expect(b.getLines()).toEqual(["new"]);
  });

  it("searches case-insensitively", () => {
    const b = new TerminalLineBuffer();
    b.append("GET /account 200\nPOST /login 401\n");
    expect(b.search("get")).toEqual([0]);
    expect(b.search("login")).toEqual([1]);
    expect(b.search("")).toEqual([]);
  });

  it("exports plain text", () => {
    const b = new TerminalLineBuffer();
    b.append("a\nb\n");
    expect(b.toString()).toBe("a\nb");
  });

  it("renders terminal string with CRLF only after completed lines and no spurious newline after partial", () => {
    const b = new TerminalLineBuffer();
    b.append("line1\nprompt> ");
    expect(b.toTerminalString()).toBe("line1\r\nprompt> ");
  });
});

describe("formatLogLine", () => {
  it("formats [HH:MM:SS] TAG message", () => {
    const line = formatLogLine("2026-04-09T14:08:21.000Z", "web", "hello");
    expect(line).toMatch(/^\[\d{2}:\d{2}:\d{2}\] WEB\s+ hello$/);
  });
});
