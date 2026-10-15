/**
 * Renderer security: CSP, navigation lock-down, external-URL allowlist,
 * and IPC sender validation.
 */
import { session, shell, type BrowserWindow, type WebContents } from "electron";

/** Hosts that may be opened in the system browser via openExternal. */
export const EXTERNAL_ALLOWLIST: readonly string[] = [
  "github.com",
  "github.dev",
  "redjohn.dev",
  "openviking.dev",
  "auth.openai.com",
  "nvd.nist.gov", // "Get a free NVD API key" onboarding link in Settings → NIST NVD
  "127.0.0.1",
  "localhost",
];

/** Strict CSP for the packaged renderer (delivered via meta tag + header). */
export const CSP_PROD = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'", // Tailwind + dynamic terminal styles
  "img-src 'self' data:",
  "font-src 'self' data:",
  "connect-src 'self' http://127.0.0.1:* ws://127.0.0.1:*",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'none'",
].join("; ");

/** Dev CSP allows the Vite dev server + HMR websocket. */
export function cspDev(viteOrigin: string): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'unsafe-eval' ${viteOrigin}`, // vite dev transform
    `style-src 'self' 'unsafe-inline' ${viteOrigin}`,
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    `connect-src 'self' ${viteOrigin} ${viteOrigin.replace(/^http/, "ws")} http://127.0.0.1:* ws://127.0.0.1:*`,
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'none'", // parity with CSP_PROD; drift here would silently weaken dev
  ].join("; ");
}

/** Inject CSP headers on http(s) responses (dev server). Prod uses the meta tag. */
export function installCspHeaders(viteOrigin: string | null): void {
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    const csp = viteOrigin ? cspDev(viteOrigin) : CSP_PROD;
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        "Content-Security-Policy": [csp],
      },
    });
  });
}

export function isAllowedExternal(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return false;
  if (parsed.protocol === "http:" && !["127.0.0.1", "localhost"].includes(parsed.hostname)) return false;
  return EXTERNAL_ALLOWLIST.some(
    (host) => parsed.hostname === host || parsed.hostname.endsWith(`.${host}`),
  );
}

/** Lock down navigation and window opening for a renderer window. */
export function hardenWindow(win: BrowserWindow, rendererOrigin: string): void {
  const wc: WebContents = win.webContents;

  wc.setWindowOpenHandler(({ url }) => {
    if (isAllowedExternal(url)) {
      void shell.openExternal(url);
    }
    return { action: "deny" };
  });

  wc.on("will-navigate", (event, url) => {
    if (!isTrustedSender(url, rendererOrigin)) {
      event.preventDefault();
      if (isAllowedExternal(url)) void shell.openExternal(url);
    }
  });
}

/**
 * Validate that an IPC sender (or a navigation target) is our own renderer.
 *
 * `rendererOrigin` is the Vite dev origin in development or the bundled
 * renderer directory's file:// URL in production. A bare scheme prefix would
 * trust every local file (prod) or any look-alike host such as
 * `http://localhost:5173.evil.com` (dev), so match precisely instead:
 *   - file:// base  -> the frame must be a file:// URL inside that exact
 *     directory (trailing slash prevents sibling-dir prefix matches);
 *   - http(s) base  -> exact origin equality (scheme + host + port).
 */
export function isTrustedSender(frameUrl: string, rendererOrigin: string): boolean {
  if (!frameUrl) return false;
  let frame: URL;
  let base: URL;
  try {
    frame = new URL(frameUrl);
    base = new URL(rendererOrigin);
  } catch {
    return false;
  }
  if (base.protocol === "file:") {
    const dir = base.href.endsWith("/") ? base.href : `${base.href}/`;
    if (frame.protocol !== "file:" || !frame.href.startsWith(dir)) return false;
    // The WHATWG parser normalizes literal `.`/`..` segments but leaves
    // percent-encoded separators intact, so `renderer/..%2f..%2fetc/passwd`
    // keeps the trusted prefix while the OS file layer may resolve it outside
    // the bundle. Reject encoded separators / dot segments in the remainder.
    const rest = frame.href.slice(dir.length);
    if (/%2e|%2f|%5c/i.test(rest) || /(?:^|\/)\.\.(?:\/|$)/.test(rest)) return false;
    return true;
  }
  return frame.origin !== "null" && frame.origin === base.origin;
}
