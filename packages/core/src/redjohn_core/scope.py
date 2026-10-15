"""Scope matching helpers — target coverage and tool qualification.

All matching is pure and deterministic; the supervisor and the tool runner
both enforce through these functions so API-time and execution-time checks
cannot drift apart.
"""

from __future__ import annotations

import ipaddress
import posixpath
from pathlib import Path
from urllib.parse import unquote, urlparse, urlsplit


def _host_of(value: str) -> str:
    """Extract a host-ish comparable from a target value (url/domain/ip)."""
    if "://" in value:
        parsed = urlparse(value)
        return (parsed.hostname or value).lower()
    # strip trailing path for bare host/path forms
    return value.split("/")[0].lower() if "/" in value and ":" not in value else value.lower()


def target_covered(value: str, allowed: list[str]) -> bool:
    """True when ``value`` is covered by at least one ``allowed`` entry.

    Coverage rules (first match wins):
      - "*" covers everything
      - exact string equality
      - CIDR entry covers an IP value inside the network
      - "*.example.com" covers subdomains (and the bare domain)
      - URL entries cover same-host URLs; domain entries cover same host
    """
    if not allowed:
        return False
    host = _host_of(value)
    for entry in allowed:
        if entry == "*" or entry == value:
            return True
        # Filesystem roots are authorized by directory, not an empty hostname.
        # Resolve symlinks before deciding containment so descendants cannot
        # escape through a link into another local project.
        if entry.startswith("/"):
            if value.startswith("/") and Path(value).resolve().is_relative_to(Path(entry).resolve()):
                return True
            continue
        if value.startswith("/"):
            continue
        # A repository URL grants access to that repository, never every
        # repository sharing the github.com host.
        parsed_entry = urlparse(entry)
        if parsed_entry.hostname == "github.com" and parsed_entry.path.strip("/"):
            parsed_value = urlparse(value)
            repo_path = posixpath.normpath(unquote(parsed_entry.path)).strip("/")
            value_path = posixpath.normpath(unquote(parsed_value.path)).strip("/")
            repo_path = repo_path.removesuffix(".git").lower()
            value_path = value_path.removesuffix(".git").lower()
            if (parsed_value.hostname == "github.com" and parsed_value.scheme == "https"
                    and parsed_value.username is None and parsed_value.password is None
                    and (value_path == repo_path or value_path.startswith(repo_path + "/"))):
                return True
            continue
        e_host = _host_of(entry)
        # CIDR containment
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            net = None
        if net is not None:
            try:
                if ipaddress.ip_address(host) in net:
                    return True
            except ValueError:
                pass
            continue
        # wildcard domain
        if e_host.startswith("*.") and (host == e_host[2:] or host.endswith(e_host[1:])):
            return True
        # host equality (covers url-vs-domain vs ip string forms)
        if host == e_host:
            return True
    return False


def url_in_scope(value: str, allowed: list[str]) -> bool:
    """Path-aware URL coverage: like :func:`target_covered`, but a URL entry
    that carries a path only covers values whose scheme, port AND path prefix
    match. This is the authorization boundary for every tool that fetches a
    URL (native assessment tools and ``builtin:http_get`` alike), so an agent
    scoped to one app on a shared host cannot reach another path on that host.
    """
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        return False
    path = posixpath.normpath(unquote(parsed.path or "/"))
    for entry in allowed:
        if not target_covered(value, [entry]):
            continue
        if "://" not in entry:
            return True
        allowed_url = urlsplit(entry)
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            allowed_port = allowed_url.port or (443 if allowed_url.scheme == "https" else 80)
        except ValueError:
            return False
        if parsed.scheme != allowed_url.scheme or port != allowed_port:
            continue
        prefix = posixpath.normpath(unquote(allowed_url.path or "/"))
        if prefix == "/" or path == prefix or path.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


def targets_subset(child: list[str], parent: list[str]) -> list[str]:
    """Return child entries NOT covered by the parent scope (empty = subset)."""
    return [c for c in child if not target_covered(c, parent)]


def tool_allowed(tool: str, allowed: list[str], denied: list[str] | None = None) -> bool:
    """Qualified tool name match: exact, ``*``, or prefix wildcard ``foo:*``."""
    for pattern in denied or []:
        if _tool_match(tool, pattern):
            return False
    return any(_tool_match(tool, pattern) for pattern in allowed)


def _tool_match(tool: str, pattern: str) -> bool:
    if pattern == "*" or pattern == tool:
        return True
    return pattern.endswith(":*") and tool.startswith(pattern[:-1])


def tools_subset(child: list[str], parent: list[str]) -> list[str]:
    """Child tool entries not permitted by the parent's tool list."""
    return [c for c in child if not any(_tool_match(c, p) for p in parent)]
