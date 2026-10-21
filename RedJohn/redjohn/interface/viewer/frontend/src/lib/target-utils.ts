export interface ParsedTarget {
  display: string;
  href: string | null;
  provider: "github" | "gitlab" | "bitbucket" | null;
}

export function parseTarget(target: string): ParsedTarget {
  // Classify the parsed hostname, never a provider-looking substring in the
  // path, userinfo, or another domain. Keep the actual target visible.
  try {
    const url = new URL(/^https?:\/\//i.test(target) ? target : `https://${target}`);
    const host = url.hostname.toLowerCase().replace(/^www\./, "");
    const providers = { "github.com": "github", "gitlab.com": "gitlab", "bitbucket.org": "bitbucket" } as const;
    const provider = providers[host as keyof typeof providers];
    const parts = url.pathname.split("/").filter(Boolean);
    if (provider && parts.length >= 2 && !url.username && !url.password) {
      const slug = parts.slice(0, 2).join("/").replace(/\.git$/, "");
      return { display: slug, href: `https://${host}/${slug}`, provider };
    }
  } catch {
    // Local paths and instructions are valid targets without a web link.
  }

  // URL with protocol
  if (/^https?:\/\//i.test(target)) {
    return {
      display: target.replace(/^https?:\/\/(www\.)?/, ""),
      href: target,
      provider: null,
    };
  }

  // Bare domain (e.g. "example.com" or "example.com/path")
  if (/^[a-zA-Z0-9][\w.-]*\.[a-zA-Z]{2,}/.test(target)) {
    return { display: target, href: `https://${target}`, provider: null };
  }

  // Not a URL
  return { display: target, href: null, provider: null };
}

/**
 * A clean, human-readable run title derived from the scan target (e.g.
 * "arch.co") rather than the raw run dir name ("arch-co_ca3f"). Falls back to
 * the raw name, then a generic label.
 */
export function runTitle(target: string | null, fallback: string): string {
  if (target) return parseTarget(target).display.replace(/\/$/, "");
  return fallback || "Untitled pentest";
}
