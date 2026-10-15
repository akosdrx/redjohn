#!/usr/bin/env python3
# graphql_dump.py - scope-guarded GraphQL introspection dump and summary.
#
# Sends the standard full IntrospectionQuery (or --query custom document) as
# POST application/json to --endpoint, validates the endpoint against the
# engagement scope BEFORE any socket is opened, saves the response with
# --save PREFIX, and prints schema type/field counts from the response.
#
# Scope: --scope-file PATH or REDJOHN_SCOPE_FILE. Absent/unreadable scope
# file -> exit 1 (refuses to send). Endpoint not in scope -> exit 2.
#
# Determinations: 200 + data.__schema -> "introspection open" (exit 0);
# 200 with errors and no data -> "introspection blocked" determination
# (exit 0, with next-step note: field suggestions per references);
# transport error / non-JSON / non-200 -> exit 1.
#
# Exit codes: 0 success (determination made), 2 scope refusal, 1 other errors.

import argparse
import http.client
import ipaddress
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse

DEFAULT_TIMEOUT = 15.0
BODY_PREVIEW_BYTES = 2048

INTROSPECTION_QUERY = """query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType { kind name }
            }
          }
        }
      }
    }
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
}"""


# ---------------------------------------------------------------------------
# Scope guard (canonical, from library CONVENTIONS.md - copy-adapted)
# ---------------------------------------------------------------------------

def host_allowed(target, scope):
    """Return (allowed, reason). Fail closed on any parse/DNS error."""
    try:
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme not in ("http", "https"):
            return False, "scheme-not-http(s)"
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return False, "no-host"
        try:
            addrs = {info[4][0].split("%", 1)[0] for info in socket.getaddrinfo(host, None)}
        except socket.gaierror:
            return False, "dns-unresolvable"
        if not addrs:
            return False, "dns-unresolvable"
        parsed_addrs = [ipaddress.ip_address(a) for a in addrs]
        nets = []
        for entry in scope.get("allowed", []):
            if entry.get("host", "").lower().rstrip(".") == host:
                return True, "host"
            if "cidr" in entry:
                nets.append(ipaddress.ip_network(entry["cidr"], strict=False))
        if nets and all(any(ip in net for net in nets) for ip in parsed_addrs):
            return True, "cidr"
        return False, "not-in-scope"
    except Exception as exc:  # fail closed on anything unexpected
        return False, "error:%s" % exc


def require_in_scope(target, scope_file):
    """Exit(2) unless target is inside the engagement scope."""
    try:
        with open(scope_file, "r", encoding="utf-8") as fh:
            scope = json.load(fh)
    except (OSError, ValueError) as exc:
        sys.stderr.write(
            "[scope-guard] scope file unreadable (%s): %s\n" % (scope_file, exc)
        )
        sys.exit(1)
    ok, why = host_allowed(target, scope)
    if not ok:
        sys.stderr.write(
            "[scope-guard] refused %s (%s) engagement=%s\n"
            % (target, why, scope.get("engagement", "unnamed"))
        )
        sys.exit(2)
    return scope


# ---------------------------------------------------------------------------
# Sending (network; monkeypatched during self-test)
# ---------------------------------------------------------------------------

def send_introspection(endpoint, query, timeout=DEFAULT_TIMEOUT,
                       insecure_ok=False):
    """POST the query as application/json. Returns result dict."""
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme == "https":
        context = (ssl._create_unverified_context() if insecure_ok
                   else ssl.create_default_context())
        conn = http.client.HTTPSConnection(parsed.hostname, parsed.port,
                                           timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port,
                                          timeout=timeout)
    body = json.dumps({"query": query}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Content-Length": str(len(body)),
    }
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    started = time.perf_counter()
    try:
        conn.request("POST", target, body=body, headers=headers)
        resp = conn.getresponse()
        status, reason = resp.status, resp.reason
        resp_headers = resp.getheaders()
        resp_body = resp.read()
    finally:
        conn.close()
    return {
        "status": status,
        "reason": reason,
        "headers": resp_headers,
        "body": resp_body,
        "time_ms": (time.perf_counter() - started) * 1000.0,
        "request": "POST %s HTTP/1.1\n%s\n\n%s"
                   % (target, "\n".join("%s: %s" % kv for kv in
                                        headers.items()),
                      body.decode("utf-8")),
    }


# ---------------------------------------------------------------------------
# Response summary (pure; unit-tested offline)
# ---------------------------------------------------------------------------

def summarize(payload):
    """Summarize an introspection JSON payload. Raises ValueError on shape
    that is not an introspection response."""
    if not isinstance(payload, dict):
        raise ValueError("response is not a JSON object")
    if "data" not in payload:
        raise ValueError("no 'data' key (not a GraphQL response)")
    schema = (payload.get("data") or {}).get("__schema")
    if not isinstance(schema, dict):
        raise ValueError("no data.__schema (introspection not returned)")
    types = schema.get("types") or []
    if not isinstance(types, list):
        raise ValueError("data.__schema.types is not a list")
    user_types = [t for t in types
                  if not (t.get("name") or "").startswith("__")]
    fields_total = 0
    fields_user = 0
    for t in types:
        count = len(t.get("fields") or [])
        fields_total += count
        if not (t.get("name") or "").startswith("__"):
            fields_user += count
    def _name(key):
        entry = schema.get(key)
        return (entry or {}).get("name") if isinstance(entry, dict) else None
    return {
        "types_total": len(types),
        "types_user": len(user_types),
        "fields_total": fields_total,
        "fields_user": fields_user,
        "query_type": _name("queryType"),
        "mutation_type": _name("mutationType"),
        "subscription_type": _name("subscriptionType"),
        "directives": len(schema.get("directives") or []),
    }


def render_summary(summary):
    lines = [
        "[graphql] introspection OPEN",
        "[graphql] types: %d (user-defined: %d)"
        % (summary["types_total"], summary["types_user"]),
        "[graphql] fields: %d (on user-defined types: %d)"
        % (summary["fields_total"], summary["fields_user"]),
        "[graphql] roots: query=%s mutation=%s subscription=%s"
        % (summary["query_type"], summary["mutation_type"],
           summary["subscription_type"]),
        "[graphql] directives: %d" % summary["directives"],
    ]
    if summary["subscription_type"]:
        lines.append("[graphql] subscription root present - check the WS "
                     "transport checklist (references/websocket-checklist.md)")
    return "\n".join(lines)


def save_evidence(prefix, result, auth_context):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    comment = ("# graphql_dump time=%s auth-context=%s\n" % (stamp, auth_context))
    with open(prefix + ".req.txt", "wb") as fh:
        fh.write(comment.encode("utf-8"))
        fh.write(result["request"].encode("utf-8"))
    status_line = "HTTP/1.1 %d %s" % (result["status"], result["reason"])
    resp_headers = ["%s: %s" % (n, v) for n, v in result["headers"]]
    with open(prefix + ".resp.txt", "wb") as fh:
        fh.write(comment.encode("utf-8"))
        fh.write(("\n".join([status_line] + resp_headers) + "\n\n")
                 .encode("latin-1"))
        fh.write(result["body"])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Scope-guarded GraphQL introspection dump: POSTs the "
        "standard IntrospectionQuery, saves the response, prints "
        "type/field counts. The endpoint is scope-checked BEFORE any "
        "connection is made.",
    )
    ap.add_argument("--scope-file", default=os.environ.get("REDJOHN_SCOPE_FILE"),
                    help="Engagement scope JSON (default: REDJOHN_SCOPE_FILE)")
    ap.add_argument("--endpoint", help="GraphQL endpoint URL (http(s)://...)")
    ap.add_argument("--query", help="Custom GraphQL document (default: "
                    "standard full IntrospectionQuery)")
    ap.add_argument("--save", metavar="PREFIX",
                    help="Save evidence pair as PREFIX.req.txt / PREFIX.resp.txt")
    ap.add_argument("--auth-context", default="unlabeled",
                    help="Auth context label written into saved evidence")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--insecure-ok", action="store_true",
                    help="Skip TLS certificate verification (recorded in evidence)")
    ap.add_argument("--self-test", action="store_true",
                    help="Run offline self-tests (no network) and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.endpoint or not args.scope_file:
        sys.stderr.write("error: --endpoint and --scope-file are required "
                         "(or set REDJOHN_SCOPE_FILE)\n")
        return 1

    # Scope check on the endpoint BEFORE any socket is opened.
    require_in_scope(args.endpoint, args.scope_file)

    query = args.query or INTROSPECTION_QUERY
    sys.stderr.write("[graphql] POST introspection query to %s (%d chars)\n"
                     % (args.endpoint, len(query)))
    try:
        result = send_introspection(args.endpoint, query,
                                    timeout=args.timeout,
                                    insecure_ok=args.insecure_ok)
    except Exception as exc:
        sys.stderr.write("error: request failed: %s\n" % exc)
        return 1

    print("[graphql] status=%d reason=%s time_ms=%.1f"
          % (result["status"], result["reason"], result["time_ms"]))

    payload = None
    try:
        payload = json.loads(result["body"].decode("utf-8", errors="replace"))
    except ValueError:
        pass

    if args.save:
        save_evidence(args.save, result, args.auth_context)
        print("[graphql] evidence pair saved: %s.req.txt / %s.resp.txt"
              % (args.save, args.save))

    if payload is not None:
        try:
            summary = summarize(payload)
        except ValueError as exc:
            payload = {"__parse_note": str(exc), "orig": payload}
            summary = None
    else:
        summary = None

    if summary is not None:
        print(render_summary(summary))
        print("evidence: keep the full request (query document verbatim) + "
              "response pair as evidence/p6-api-graphql-<seq>.{req,resp}.txt; "
              "then diff field visibility per role via 30's token-swap.")
        return 0

    # No usable introspection data: classify.
    if payload is not None and payload.get("errors") and \
            not payload.get("data"):
        print("[graphql] introspection BLOCKED (errors present, no data):")
        for err in payload["errors"][:3]:
            print("  - %s" % (err.get("message") if isinstance(err, dict)
                              else err))
        print("[graphql] next: disabling introspection is NOT access "
              "control - probe field suggestions (Did you mean ...) per "
              "references/graphql-attack-surface.md section 4.")
        return 0

    print("[graphql] no introspection data (status=%d); body preview:"
          % result["status"])
    print(result["body"][:BODY_PREVIEW_BYTES].decode("utf-8", errors="replace"))
    sys.stderr.write("error: response unusable for introspection summary\n")
    return 1


# ---------------------------------------------------------------------------
# Self-test: offline, no network. DNS monkeypatched; sending monkeypatched
# out. Fixtures use documentation domains only.
# ---------------------------------------------------------------------------

FIXTURE_INTROSPECTION = {
    "data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "subscriptionType": None,
        "directives": [{"name": "include"}, {"name": "skip"}],
        "types": [
            {"name": "__Schema", "fields": None},
            {"name": "Query", "fields": [
                {"name": "viewer"}, {"name": "node"},
                {"name": "user"}, {"name": "invoices"},
            ]},
            {"name": "Mutation", "fields": [
                {"name": "updateProfile"}, {"name": "changePassword"},
            ]},
            {"name": "Invoice", "fields": [
                {"name": "id"}, {"name": "totalCents"}, {"name": "owner"},
            ]},
        ],
    }},
}


def self_test():
    checks = 0

    def ok(label):
        nonlocal checks
        checks += 1
        print("[self-test] ok: %s" % label)

    import tempfile

    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *fn_args, **fn_kwargs):
        table = {"example.com": "93.184.216.34", "localhost": "127.0.0.1"}
        if host in table:
            addr = table[host]
        else:
            try:
                ipaddress.ip_address(host)
                addr = host
            except ValueError:
                raise socket.gaierror(-2, "fake NXDOMAIN")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 0))]

    loopback_scope = {
        "engagement": "selftest",
        "allowed": [
            {"host": "localhost"},
            {"cidr": "127.0.0.0/8"},
            {"host": "127.0.0.1"},
        ],
    }
    sent = []
    real_send = send_introspection

    def fake_send(endpoint, query, timeout=DEFAULT_TIMEOUT, insecure_ok=False):
        sent.append((endpoint, query))
        body = json.dumps(FIXTURE_INTROSPECTION).encode("utf-8")
        return {"status": 200, "reason": "OK",
                "headers": [("Content-Type", "application/json")],
                "body": body, "time_ms": 1.0,
                "request": "POST /graphql (fixture)"}

    socket.getaddrinfo = fake_getaddrinfo
    globals()["send_introspection"] = fake_send
    try:
        # --- canonical guard assertions (offline, fake DNS) ---
        res = host_allowed("https://example.com/graphql", loopback_scope)
        assert res == (False, "not-in-scope"), res
        ok("guard refuses public host under localhost-only scope")

        res = host_allowed("http://10.0.0.5/graphql", loopback_scope)
        assert res == (False, "not-in-scope"), res
        ok("guard refuses private IP without explicit CIDR entry")

        res = host_allowed("http://127.0.0.1:8443/graphql", loopback_scope)
        assert res[0] is True and res[1] in ("host", "cidr"), res
        ok("guard allows http://127.0.0.1:PORT when that host is listed")

        res = host_allowed("https://no-such-host.invalid/graphql", loopback_scope)
        assert res == (False, "dns-unresolvable"), res
        ok("guard fails closed on unresolvable host (invalid TLD)")

        res = host_allowed("gopher://127.0.0.1/graphql", loopback_scope)
        assert res == (False, "scheme-not-http(s)"), res
        ok("guard refuses non-http(s) scheme")

        # --- summary parsing (pure) ---
        summary = summarize(FIXTURE_INTROSPECTION)
        assert summary["types_total"] == 4, summary
        assert summary["types_user"] == 3, summary
        assert summary["fields_total"] == 9, summary
        assert summary["fields_user"] == 9, summary
        assert summary["query_type"] == "Query", summary
        assert summary["mutation_type"] == "Mutation", summary
        assert summary["subscription_type"] is None, summary
        assert summary["directives"] == 2, summary
        ok("summarize counts types/fields/roots/directives")

        blocked = {"errors": [{"message": "introspection disabled"}]}
        try:
            summarize(blocked)
            raised = False
        except ValueError:
            raised = True
        assert raised
        ok("summarize rejects non-introspection payload")

        rendered = render_summary(summary)
        assert "types: 4 (user-defined: 3)" in rendered, rendered
        assert "subscription root present" not in rendered, rendered
        ok("render_summary formats counts; subscription note conditional")

        # --- end-to-end dispatch under fake DNS/sender ---
        with tempfile.TemporaryDirectory() as tmp:
            scope_path = os.path.join(tmp, "scope.json")
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump(loopback_scope, fh)

            code = None
            try:
                main(["--scope-file", scope_path,
                      "--endpoint", "https://example.com/graphql"])
            except SystemExit as exc:
                code = exc.code
            assert code == 2 and not sent, (code, sent)
            ok("out-of-scope endpoint -> exit 2 and NOTHING sent")

            code = main(["--scope-file", scope_path,
                         "--endpoint", "http://127.0.0.1:8443/graphql",
                         "--save", os.path.join(tmp, "ev"),
                         "--auth-context", "role:user-a"])
            assert code == 0 and len(sent) == 1, (code, sent)
            endpoint, query = sent[0]
            assert "IntrospectionQuery" in query, query[:80]
            assert os.path.isfile(os.path.join(tmp, "ev.req.txt"))
            assert os.path.isfile(os.path.join(tmp, "ev.resp.txt"))
            ok("in-scope endpoint -> query sent once, evidence pair written")
    finally:
        socket.getaddrinfo = real_getaddrinfo
        globals()["send_introspection"] = real_send

    print("[self-test] graphql_dump: all %d checks passed" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
