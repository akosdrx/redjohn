#!/usr/bin/env python3
"""field_probe.py - mass-assignment field-acceptance probe.

Replays a saved raw HTTP request (captured from the P3 harness) once as a
baseline, then once more per requested field with that field added using a
benign sentinel value. Diffs status/length/sha256 against the baseline and
prints per-field verdicts (REJECTED / ACCEPTED-CANDIDATE / NO-EFFECT) per
references/mass-assignment.md. Confirmation of persistence still requires a
read-back GET - this tool only nominates candidates.

Usage:
  python3 field_probe.py --scope-file scope.json --request-file req.txt \
      --fields role,isAdmin,price [--value fieldprobe-sentinel]

Exit codes: 0 = probe run completed (see verdicts); 2 = scope refusal;
1 = other error (bad args, unparsable request, transport failure).

Evidence expectation: keep the baseline pair and one pair per field as
evidence/p6-massassign-<endpoint>-<field>.{req,resp}.txt; confirm acceptance
with a read-back GET before claiming the finding.
"""

import argparse
import hashlib
import http.client
import ipaddress
import json
import socket
import sys
import time
import urllib.parse

DEFAULT_SENTINEL = "fieldprobe-sentinel"

# ---------------------------------------------------------------- scope guard


_INTERNAL_NETS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)
_PINNED_DNS = {}


def _is_internal_ip(ip_obj):
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped
    return (
        ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_unspecified
        or ip_obj.is_multicast
        or any(ip_obj in net for net in _INTERNAL_NETS)
    )


def host_allowed(target, scope):
    """Return (allowed, reason). Fail closed on any parse/DNS error."""
    try:
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme not in ("http", "https"):
            return False, "scheme-not-http(s)"
        host = (parsed.hostname or "").lower()
        if not host:
            return False, "no-host"
        for denied in scope.get("out_of_scope", []):
            pat = denied.get("pattern", "").lower().lstrip("*.")
            if pat and (host == pat or host.endswith("." + pat)):
                return False, "out-of-scope"
        try:
            addrs = list(dict.fromkeys(
                info[4][0] for info in socket.getaddrinfo(host, None)
            ))
        except socket.gaierror:
            return False, "dns-unresolvable"
        if not addrs:
            return False, "dns-unresolvable"
        try:
            host_ip = ipaddress.ip_address(host)
        except ValueError:
            host_ip = None
        allowed_entries = scope.get("allowed", [])
        matched_reason = None
        for addr in addrs:
            ip_obj = ipaddress.ip_address(addr)
            addr_ok = False
            for entry in allowed_entries:
                ehost = entry.get("host", "").lower()
                if ehost and ehost == host:
                    if (
                        (host_ip is not None and ip_obj == host_ip)
                        or (host == "localhost" and ip_obj.is_loopback)
                        or not _is_internal_ip(ip_obj)
                    ):
                        addr_ok = True
                        matched_reason = matched_reason or "host"
                        break
                if "cidr" in entry:
                    net = ipaddress.ip_network(entry["cidr"], strict=False)
                    if ip_obj in net:
                        addr_ok = True
                        matched_reason = matched_reason or "cidr"
                        break
            if not addr_ok:
                return False, "not-in-scope"
        _PINNED_DNS[host] = tuple(addrs)
        return True, (matched_reason or "host")
    except Exception as exc:  # fail closed on anything unexpected
        return False, "error:%s" % exc


def require_in_scope(target, scope_file):
    """Exit(2) unless target is inside the engagement scope."""
    with open(scope_file, "r", encoding="utf-8") as fh:
        scope = json.load(fh)
    ok, why = host_allowed(target, scope)
    if not ok:
        sys.stderr.write(
            "[scope-guard] refused %s (%s) engagement=%s\n"
            % (target, why, scope.get("engagement", "unnamed"))
        )
        sys.exit(2)
    return scope


# ---------------------------------------------------------------- request file


def parse_request(raw):
    """Parse a raw HTTP request -> (method, path, headers, body)."""
    lines_all = raw.splitlines(keepends=True)
    idx = 0
    while idx < len(lines_all):
        stripped = lines_all[idx].strip()
        if not stripped or stripped.startswith("#"):
            idx += 1
            continue
        break
    trimmed = "".join(lines_all[idx:])
    if not trimmed:
        raise ValueError("empty request")
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in trimmed:
            head, body = trimmed.split(sep, 1)
            break
    else:
        head, body = trimmed, ""
    lines = [ln for ln in head.splitlines()
             if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        raise ValueError("empty request")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError("unparsable request line: %r" % lines[0])
    method, path = parts[0].upper(), parts[1]
    headers = []
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers.append((key.strip(), value.strip()))
    return method, path, headers, body.encode("latin-1")


def host_of(headers):
    for key, value in headers:
        if key.lower() == "host":
            return value.strip()
    raise ValueError("request file has no Host header")


def split_host_port(host_header, scheme):
    host, _, port = host_header.partition(":")
    if not port:
        port = "443" if scheme == "https" else "80"
    return host.strip(), int(port)


def set_header(headers, name, value):
    out = [(k, v) for k, v in headers if k.lower() != name.lower()]
    out.append((name, value))
    return out


def build_raw(method, path, headers, body):
    out = ["%s %s HTTP/1.1" % (method, path)]
    out += ["%s: %s" % (k, v) for k, v in headers]
    return "\r\n".join(out).encode("latin-1") + b"\r\n\r\n" + body


# ---------------------------------------------------------------- mutation


def mutate_json(body, field, value):
    """Return new JSON body bytes, or None when not a JSON object."""
    try:
        obj = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    obj = dict(obj)
    obj[field] = value
    return json.dumps(obj).encode("utf-8")


def mutate_form(body, field, value):
    """Append field=value (urlencoded) to a form body."""
    text = body.decode("utf-8", "replace")
    enc = urllib.parse.quote(str(value), safe="")
    if text.strip() == "":
        return ("%s=%s" % (field, enc)).encode("utf-8")
    return (text + "&%s=%s" % (field, enc)).encode("utf-8")


def mutate_path(path, field, value):
    sep = "&" if "?" in path else "?"
    enc = urllib.parse.quote(str(value), safe="")
    return "%s%s%s=%s" % (path, sep, field, enc)


def apply_field(method, path, headers, body, field, value):
    """Return (method, path, headers, body) with the field added once."""
    if body:
        new_body = mutate_json(body, field, value)
        if new_body is None:
            new_body = mutate_form(body, field, value)
        headers = set_header(headers, "Content-Length",
                             str(len(new_body)))
        return method, path, headers, new_body
    return method, mutate_path(path, field, value), headers, body


# ---------------------------------------------------------------- verdict


def classify(base_status, base_sha, cur_status, cur_sha):
    if cur_status == base_status and cur_sha == base_sha:
        return ("NO-EFFECT",
                "field dropped or ignored server-side (record as negative)")
    if 400 <= cur_status < 500 and not (400 <= base_status < 500):
        return ("REJECTED",
                "schema knows the field, refused it with %d (record as "
                "negative)" % cur_status)
    return ("ACCEPTED-CANDIDATE",
            "response changed (%d vs %d baseline); GET the object back to "
            "confirm persistence" % (cur_status, base_status))


# ---------------------------------------------------------------- transport


def send_once(scheme, host_header, raw, timeout):
    host, port = split_host_port(host_header, scheme)
    connect_host = (_PINNED_DNS.get(host.lower()) or (host,))[0]
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=timeout)
    else:
        conn = http.client.HTTPConnection(connect_host, port, timeout=timeout)
    conn.connect()
    try:
        conn.sock.sendall(raw)
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, body
    finally:
        conn.close()


# ---------------------------------------------------------------- self-test


def _fake_getaddrinfo(host, port, *args, **kwargs):
    """Offline DNS stand-in: canned answers only, no network."""
    fake = {
        "example.com": ["93.184.216.34"],
        "target.example.com": ["203.0.113.10"],
        "localhost": ["127.0.0.1"],
        "127.0.0.1": ["127.0.0.1"],
        "10.0.0.5": ["10.0.0.5"],
    }
    if host in fake:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, port))
            for addr in fake[host]
        ]
    raise socket.gaierror(2, "offline fixture: unknown host")


JSON_REQ = (
    "PUT /api/users/me HTTP/1.1\r\n"
    "Host: target.example.com\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 27\r\n"
    "\r\n"
    '{"display_name":"user-a"}'
)

FORM_REQ = (
    "POST /profile HTTP/1.1\r\n"
    "Host: target.example.com\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 11\r\n"
    "\r\n"
    "display=joe"
)

GET_REQ = "GET /api/settings HTTP/1.1\r\nHost: target.example.com\r\n\r\n"


def self_test():
    # --- mandatory scope-guard assertions (offline via fake DNS) ---
    original = socket.getaddrinfo
    socket.getaddrinfo = _fake_getaddrinfo
    try:
        local_scope = {"engagement": "selftest",
                       "allowed": [{"host": "localhost"}]}
        ok, why = host_allowed("https://example.com", local_scope)
        assert ok is False, "example.com must be refused, got %s" % why
        ok, why = host_allowed("http://10.0.0.5/", local_scope)
        assert ok is False and why == "not-in-scope", why
        loop_scope = {"engagement": "selftest",
                      "allowed": [{"host": "127.0.0.1"}]}
        ok, why = host_allowed("http://127.0.0.1:8080/", loop_scope)
        assert ok is True, "listed loopback must be allowed, got %s" % why
        ok, why = host_allowed("http://target.example.com/api",
                               {"allowed": [{"cidr": "203.0.113.0/24"}]})
        assert ok is True, "cidr entry must allow the documented host"
    finally:
        socket.getaddrinfo = original

    # --- request parsing ---
    m, p, h, b = parse_request("# origin: https://target.example.com\n\n" + JSON_REQ)
    assert (m, p) == ("PUT", "/api/users/me")
    assert host_of(h) == "target.example.com"
    assert b'{"display_name":"user-a"}' == b
    assert parse_request(GET_REQ)[3] == b""
    for bad_req in ("", "# comment only\n"):
        try:
            parse_request(bad_req)
            raise AssertionError("empty request must raise ValueError")
        except ValueError:
            pass

    # --- JSON mutation ---
    nb = mutate_json(b, "role", "fieldprobe-sentinel")
    assert json.loads(nb.decode())["role"] == "fieldprobe-sentinel"
    assert json.loads(nb.decode())["display_name"] == "user-a"
    assert mutate_json(b"[1,2]", "x", "y") is None
    assert mutate_json(b"not json", "x", "y") is None
    # form mutation
    fb = mutate_form(b"display=joe", "isAdmin", "1")
    assert fb == b"display=joe&isAdmin=1", fb
    assert mutate_form(b"", "k", "a b") == b"k=a%20b"
    # path mutation
    assert mutate_path("/s", "role", "1") == "/s?role=1"
    assert mutate_path("/s?x=1", "role", "1") == "/s?x=1&role=1"

    # --- apply_field: content-length rewritten for body mutation ---
    m2, p2, h2, b2 = apply_field(m, p, h, b, "role", "fieldprobe-sentinel")
    assert (m2, p2) == (m, p)
    lens = {v for k, v in h2 if k.lower() == "content-length"}
    assert lens == {str(len(b2))}, lens
    assert json.loads(b2.decode())["role"] == "fieldprobe-sentinel"
    # form request: field appended, length rewritten
    fm, fp, fh, fbb = parse_request(FORM_REQ)
    _m3, _p3, h3, b3 = apply_field(fm, fp, fh, fbb, "isAdmin", "1")
    assert b3 == b"display=joe&isAdmin=1", b3
    assert {v for k, v in h3 if k.lower() == "content-length"} == {"21"}
    # bodyless request: query param appended, no Content-Length invented
    gm, gp, gh, gb = parse_request(GET_REQ)
    _m4, p4, h4, b4 = apply_field(gm, gp, gh, gb, "role", "1")
    assert p4 == "/api/settings?role=1", p4
    assert b4 == b""
    assert not any(k.lower() == "content-length" for k, _v in h4)

    # --- set_header replaces, not duplicates ---
    hh = set_header([("Content-Length", "5"), ("X-A", "1")],
                    "content-length", "9")
    assert len(hh) == 2, hh
    assert [v for k, v in hh if k.lower() == "content-length"] == ["9"], hh
    assert ("X-A", "1") in hh, hh

    # --- verdicts ---
    v = classify(200, "aa", 200, "aa")
    assert v[0] == "NO-EFFECT", v
    v = classify(200, "aa", 400, "bb")
    assert v[0] == "REJECTED", v
    v = classify(200, "aa", 200, "bb")
    assert v[0] == "ACCEPTED-CANDIDATE", v
    v = classify(200, "aa", 500, "bb")
    assert v[0] == "ACCEPTED-CANDIDATE", v  # 5xx divergence, not a refusal
    v = classify(200, "aa", 409, "bb")
    assert v[0] == "REJECTED", v  # 409 is still a 4xx refusal class
    v = classify(400, "aa", 403, "bb")
    assert v[0] == "ACCEPTED-CANDIDATE", v  # baseline already 4xx

    print("[self-test] field_probe: guard(4) + parser + json/form/query "
          "mutators + content-length rewrite + verdict fixtures passed")


# ---------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(description="Mass-assignment field-acceptance probe.")
    parser.add_argument("--scope-file",
                        help="engagement scope JSON (or REDJOHN_SCOPE_FILE)")
    parser.add_argument("--request-file",
                        help="raw HTTP request captured from the harness")
    parser.add_argument("--fields",
                        help="comma-separated field names to probe one at a "
                             "time (e.g. role,isAdmin,price)")
    parser.add_argument("--value", default=DEFAULT_SENTINEL,
                        help="benign sentinel value (default %s)"
                             % DEFAULT_SENTINEL)
    parser.add_argument("--scheme", choices=("http", "https"),
                        default="http",
                        help="scheme toward the Host header (default http)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="per-request timeout seconds (default 10)")
    parser.add_argument("--delay", type=float, default=0.3,
                        help="seconds between replays (default 0.3)")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-test (fixtures) and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    scope_file = args.scope_file
    if not scope_file:
        import os
        scope_file = os.environ.get("REDJOHN_SCOPE_FILE")
    if not scope_file or not args.request_file or not args.fields:
        parser.error("--scope-file, --request-file and --fields are required")
    fields = [f.strip() for f in args.fields.split(",") if f.strip()]
    if not fields:
        parser.error("--fields is empty after parsing")

    try:
        with open(args.request_file, "r", encoding="latin-1") as fh:
            raw_req = fh.read()
    except OSError as err:
        sys.stderr.write("[error] cannot read %s: %s\n"
                         % (args.request_file, err))
        sys.exit(1)

    method, path, headers, body = parse_request(raw_req)
    host_header = host_of(headers)
    _h, port = split_host_port(host_header, args.scheme)
    target = "%s://%s%s" % (args.scheme,
                            host_header if ":" in host_header
                            else "%s:%d" % (host_header, port),
                            path)
    require_in_scope(target, scope_file)

    print("[baseline] replaying %s %s once" % (method, path))
    try:
        base_status, base_body = send_once(
            args.scheme, host_header,
            build_raw(method, path, headers, body), args.timeout)
    except OSError as err:
        sys.stderr.write("[error] baseline replay failed: %s\n" % err)
        sys.exit(1)
    base_sha = hashlib.sha256(base_body).hexdigest()[:12]
    print("[baseline] status=%d len=%d sha=%s"
          % (base_status, len(base_body), base_sha))

    accepted = []
    for field in fields:
        m2, p2, h2, b2 = apply_field(method, path, headers, body,
                                     field, args.value)
        try:
            status, resp_body = send_once(
                args.scheme, host_header, build_raw(m2, p2, h2, b2),
                args.timeout)
        except OSError as err:
            print("[error] %-18s %s" % (field, err))
            continue
        sha = hashlib.sha256(resp_body).hexdigest()[:12]
        verdict, detail = classify(base_status, base_sha, status, sha)
        if verdict == "ACCEPTED-CANDIDATE":
            accepted.append(field)
        print("[%-18s] %-18s status=%d len=%d sha=%s | %s"
              % (field, verdict, status, len(resp_body), sha, detail))
        time.sleep(args.delay)

    print("[summary] %d field(s) probed, %d ACCEPTED-CANDIDATE: %s"
          % (len(fields), len(accepted), ", ".join(accepted) or "none"))
    print("[next] for each ACCEPTED-CANDIDATE: GET the object back and "
          "confirm the sentinel persisted; only persistence makes it a "
          "mass-assignment finding (references/mass-assignment.md)")
    print("[evidence] keep the baseline pair and one pair per field as "
          "evidence/p6-massassign-<endpoint>-<field>.{req,resp}.txt; "
          "restore any persisted sentinel before closing the phase")


if __name__ == "__main__":
    main()
