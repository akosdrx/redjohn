import { describe, expect, it } from "vitest";
import { cspDev, CSP_PROD, isAllowedExternal, isTrustedSender } from "../../app/main/security";

describe("openExternal allowlist", () => {
  it("allows https allowlisted hosts", () => {
    expect(isAllowedExternal("https://github.com/redjohn")).toBe(true);
    expect(isAllowedExternal("https://sub.github.com/x")).toBe(true);
  });
  it("rejects non-allowlisted and non-https schemes", () => {
    expect(isAllowedExternal("https://evil.example.com")).toBe(false);
    expect(isAllowedExternal("http://evil.example.com")).toBe(false);
    expect(isAllowedExternal("file:///etc/passwd")).toBe(false);
    expect(isAllowedExternal("javascript:alert(1)")).toBe(false);
    expect(isAllowedExternal("not a url")).toBe(false);
  });
  it("allows loopback http only", () => {
    expect(isAllowedExternal("http://127.0.0.1:8720/docs")).toBe(true);
  });
});

describe("IPC sender validation", () => {
  const prodBase = "file:///app/dist/renderer/";
  it("dev: exact origin only, never a startsWith look-alike host", () => {
    expect(isTrustedSender("http://localhost:5173/page", "http://localhost:5173")).toBe(true);
    expect(isTrustedSender("http://localhost:5173/index.html", "http://localhost:5173")).toBe(true);
    // startsWith would have trusted this impostor host; origin equality rejects it.
    expect(isTrustedSender("http://localhost:5173.evil.com/x", "http://localhost:5173")).toBe(false);
    expect(isTrustedSender("https://evil.example", "http://localhost:5173")).toBe(false);
  });
  it("prod: only documents inside the bundled renderer directory", () => {
    expect(isTrustedSender("file:///app/dist/renderer/index.html", prodBase)).toBe(true);
    expect(isTrustedSender("file:///app/dist/renderer/sub/page.html", prodBase)).toBe(true);
    // arbitrary local files and sibling directories are rejected
    expect(isTrustedSender("file:///etc/passwd", prodBase)).toBe(false);
    expect(isTrustedSender("file:///app/dist/renderer-evil/index.html", prodBase)).toBe(false);
  });
  it("rejects empty / malformed sender URLs", () => {
    expect(isTrustedSender("", prodBase)).toBe(false);
    expect(isTrustedSender("not a url", prodBase)).toBe(false);
  });
});

describe("CSP", () => {
  it("prod CSP disallows remote scripts and objects", () => {
    expect(CSP_PROD).toContain("script-src 'self'");
    expect(CSP_PROD).toContain("object-src 'none'");
    expect(CSP_PROD).toContain("frame-ancestors 'none'");
  });
  it("dev CSP includes the vite origin", () => {
    const csp = cspDev("http://localhost:5173");
    expect(csp).toContain("http://localhost:5173");
    expect(csp).toContain("ws://localhost:5173");
  });
});
