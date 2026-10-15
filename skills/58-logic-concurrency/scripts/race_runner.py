#!/usr/bin/env python3
"""race_runner.py - aligned parallel request bursts for race-condition tests.

Fires the SAME raw HTTP request (saved from the P3 harness) in N threads,
pre-connecting each session, aligning on a barrier, then releasing all sends
in the same instant (--delay-ms staggers thread k by k*delay if you are
probing a slow window). Prints per-run status/body-hash and a divergence
summary; optionally replays a --verify-file GET once at the end as the
final-state read.

Usage:
  python3 race_runner.py --scope-file scope.json --request-file req.txt \
      --threads 8 [--delay-ms 0] [--rounds 1] [--verify-file final.txt]

Thread ceiling: 32 (RoE; 00-master-pentest-methodology section 0 pace rules;
default 8). Threads > 32 are refused.

Exit codes: 0 = burst run completed (see summary); 2 = scope refusal;
1 = other error (bad args, thread ceiling, transport failure before any
send).

Evidence expectation: keep the burst definition (request file, threads,
rounds), the per-run status/hash output, and the final-state GET pair; D2
requires replaying the burst from a clean state with the same final-state
divergence.
"""

import argparse
import hashlib
import http.client
import ipaddress
import json
import socket
import sys
import threading
import time
import urllib.parse

USER_AGENT_NOTE = "raw replay; original headers preserved"
THREAD_CAP = 32
DEFAULT_THREADS = 8
BARRIER_TIMEOUT = 30.0
ROUND_PAUSE = 1.0

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


def build_raw(method, path, headers, body):
    out = ["%s %s HTTP/1.1" % (method, path)]
    out += ["%s: %s" % (k, v) for k, v in headers]
    return "\r\n".join(out).encode("latin-1") + b"\r\n\r\n" + body


def validate_threads(n):
    """(ok, message) for a thread count under the RoE ceiling."""
    if n < 1:
        return False, "--threads must be >= 1"
    if n > THREAD_CAP:
        return False, (
            "--threads %d exceeds the ceiling %d (rules of engagement: "
            "parallel bursts stay small, default %d; see "
            "00-master-pentest-methodology section 0 pace rules)"
            % (n, THREAD_CAP, DEFAULT_THREADS))
    return True, ""


# ---------------------------------------------------------------- senders


class LiveSender:
    """Pre-connect + raw-socket replay via http.client."""

    def __init__(self, scheme, host_header, raw, timeout):
        self.scheme, self.raw, self.timeout = scheme, raw, timeout
        self.host, self.port = split_host_port(host_header, scheme)

    def preconnect(self, _idx):
        connect_host = (_PINNED_DNS.get(self.host.lower()) or (self.host,))[0]
        if self.scheme == "https":
            conn = http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout)
        else:
            conn = http.client.HTTPConnection(
                connect_host, self.port, timeout=self.timeout)
        conn.connect()
        return conn

    def fire(self, _idx, conn):
        try:
            conn.sock.sendall(self.raw)
            resp = conn.getresponse()
            body = resp.read()
            return resp.status, body
        finally:
            conn.close()


class FakeSender:
    """Offline stand-in: canned outcomes, timestamped fire() calls."""

    def __init__(self, statuses):
        self.statuses = statuses
        self.times = []
        self._lock = threading.Lock()

    def preconnect(self, _idx):
        return None

    def fire(self, idx, _conn):
        with self._lock:
            self.times.append((idx, time.perf_counter()))
        status = self.statuses[idx % len(self.statuses)]
        return status, b"body-%d" % status


# ---------------------------------------------------------------- burst


def run_burst(threads, delay_ms, sender, rounds=1, pause=ROUND_PAUSE):
    """Aligned bursts; returns list (per round) of outcome lists.

    Outcome: (idx, status, length, sha12) or (idx, None, 0, error-text).
    """
    all_rounds = []
    for _rnd in range(rounds):
        barrier = threading.Barrier(threads)
        outcomes = [None] * threads

        def worker(idx):
            conn = None
            fired = False
            try:
                try:
                    conn = sender.preconnect(idx)
                except Exception as exc:  # pre-connect failure recorded, not fatal
                    outcomes[idx] = (idx, None, 0, "preconnect-error: %s" % exc)
                try:
                    barrier.wait(timeout=BARRIER_TIMEOUT)
                except threading.BrokenBarrierError:
                    if outcomes[idx] is None:
                        outcomes[idx] = (idx, None, 0, "barrier-broken")
                    return
                if outcomes[idx] is not None:
                    return  # pre-connect already failed
                if delay_ms:
                    time.sleep(idx * delay_ms / 1000.0)
                try:
                    fired = True
                    status, body = sender.fire(idx, conn)
                    outcomes[idx] = (idx, status, len(body),
                                     hashlib.sha256(body).hexdigest()[:12])
                except Exception as exc:
                    outcomes[idx] = (idx, None, 0, "send-error: %s" % exc)
            finally:
                if conn is not None and not fired and hasattr(conn, "close"):
                    try:
                        conn.close()
                    except Exception:
                        pass

        handles = [threading.Thread(target=worker, args=(i,))
                   for i in range(threads)]
        for h in handles:
            h.start()
        for h in handles:
            h.join()
        all_rounds.append(outcomes)
        if pause and _rnd < rounds - 1:
            time.sleep(pause)
    return all_rounds


def summarize(results):
    """(verdict, details) over all rounds' outcomes."""
    cells = []
    for outcomes in results:
        for _idx, status, _ln, sha in outcomes:
            cells.append((status, sha))
    ok = [c for c in cells if c[0] is not None]
    if len(ok) < len(cells):
        errors = len(cells) - len(ok)
        detail = "%d/%d requests errored" % (errors, len(cells))
    else:
        detail = "%d requests completed" % len(cells)
    distinct = sorted({(str(s), h) for s, h in ok})
    verdict = "DIVERGENT-SIGNAL" if len(distinct) > 1 else "UNIFORM"
    return verdict, "%s; %d distinct (status,sha) pairs: %s" % (
        detail, len(distinct), distinct)


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


FIXTURE_REQ = (
    "POST /api/coupon/redeem HTTP/1.1\r\n"
    "Host: target.example.com\r\n"
    "Content-Type: application/json\r\n"
    "Cookie: session=REDACTED\r\n"
    "Content-Length: 26\r\n"
    "\r\n"
    '{"code":"rj-pt-eng1-ab12"}'
)


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

    # --- thread ceiling ---
    for n in (1, 8, 16, 32):
        ok, msg = validate_threads(n)
        assert ok, (n, msg)
    ok, msg = validate_threads(33)
    assert not ok and "rules of engagement" in msg, msg
    ok, msg = validate_threads(0)
    assert not ok, msg

    # --- request parsing ---
    method, path, headers, body = parse_request(FIXTURE_REQ)
    assert method == "POST" and path == "/api/coupon/redeem"
    assert host_of(headers) == "target.example.com"
    assert len(body) == 26, len(body)
    raw = build_raw(method, path, headers, body)
    method2, path2, headers2, body2 = parse_request(raw.decode("latin-1"))
    assert (method2, path2, headers2, body2) == (method, path, headers, body)
    host, port = split_host_port("target.example.com:8443", "https")
    assert (host, port) == ("target.example.com", 8443)
    host, port = split_host_port("target.example.com", "https")
    assert port == 443
    host, port = split_host_port("target.example.com", "http")
    assert port == 80
    # request without body and with provenance comments
    m3, p3, h3, b3 = parse_request(
        "# origin: https://t.example.com\n# auth: user\n\n"
        "GET /x HTTP/1.1\r\nHost: t.example.com\r\n\r\n")
    assert (m3, p3, b3) == ("GET", "/x", b"")
    for bad_req in ("", "# only comment\n\n", "garbage\r\n\r\n"):
        try:
            parse_request(bad_req)
            raise AssertionError("unparsable request line must raise")
        except ValueError:
            pass

    # --- aligned burst with fake sender (no network) ---
    fake = FakeSender([200])
    results = run_burst(8, 0, fake, rounds=1, pause=0)
    assert len(results) == 1 and len(results[0]) == 8
    assert all(r[1] == 200 for r in results[0]), results[0]
    verdict, detail = summarize(results)
    assert verdict == "UNIFORM", (verdict, detail)
    # alignment: all fires within a loose window (no per-thread delay)
    spread = max(t for _i, t in fake.times) - min(t for _i, t in fake.times)
    assert spread < 2.0, "aligned fires spread %.3fs" % spread

    # stagger honors delay: last fire >= first + (n-1)*delay
    fake2 = FakeSender([200])
    n, delay = 6, 40
    run_burst(n, delay, fake2, rounds=1, pause=0)
    times = [t for _i, t in sorted(fake2.times, key=lambda x: x[1])]
    assert times[-1] - times[0] >= (n - 1) * delay / 1000.0 * 0.8, times

    # divergence summary
    fake3 = FakeSender([200, 409, 403])
    results3 = run_burst(6, 0, fake3, rounds=1, pause=0)
    verdict3, detail3 = summarize(results3)
    assert verdict3 == "DIVERGENT-SIGNAL", (verdict3, detail3)

    # two rounds
    fake4 = FakeSender([200])
    results4 = run_burst(4, 0, fake4, rounds=2, pause=0.01)
    assert len(results4) == 2 and len(fake4.times) == 8

    print("[self-test] race_runner: guard(4) + thread ceiling + request "
          "parser + aligned/staggered burst + divergence summary passed")


# ---------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(
        description="Aligned parallel request bursts for race tests.")
    parser.add_argument("--scope-file",
                        help="engagement scope JSON (or REDJOHN_SCOPE_FILE)")
    parser.add_argument("--request-file",
                        help="raw HTTP request captured from the harness")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help="parallel senders (default %d, cap %d)"
                             % (DEFAULT_THREADS, THREAD_CAP))
    parser.add_argument("--delay-ms", type=int, default=0,
                        help="stagger thread k by k*delay ms (default 0 = "
                             "aligned burst)")
    parser.add_argument("--rounds", type=int, default=1,
                        help="burst repetitions (default 1)")
    parser.add_argument("--verify-file",
                        help="optional raw GET request replayed once after "
                             "the bursts as the final-state read")
    parser.add_argument("--scheme", choices=("http", "https"),
                        default="http",
                        help="scheme toward the Host header (default http; "
                             "request files carry no TLS info)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="per-connection timeout seconds (default 10)")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-test (fixtures) and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    ok, msg = validate_threads(args.threads)
    if not ok:
        sys.stderr.write("[roe] %s\n" % msg)
        sys.exit(1)

    scope_file = args.scope_file
    if not scope_file:
        import os
        scope_file = os.environ.get("REDJOHN_SCOPE_FILE")
    if not scope_file or not args.request_file:
        parser.error("--scope-file and --request-file are required")
    try:
        with open(args.request_file, "r", encoding="latin-1") as fh:
            raw_req = fh.read()
    except OSError as err:
        sys.stderr.write("[error] cannot read %s: %s\n"
                         % (args.request_file, err))
        sys.exit(1)

    method, path, headers, body = parse_request(raw_req)
    host_header = host_of(headers)
    raw = build_raw(method, path, headers, body)
    _h, port = split_host_port(host_header, args.scheme)
    target = "%s://%s%s" % (args.scheme,
                            host_header if ":" in host_header
                            else "%s:%d" % (host_header, port),
                            path)
    require_in_scope(target, scope_file)

    print("[burst] %s %s x%d threads, delay=%dms, rounds=%d"
          % (method, path, args.threads, args.delay_ms, args.rounds))
    sender = LiveSender(args.scheme, host_header, raw, args.timeout)
    try:
        results = run_burst(args.threads, args.delay_ms, sender,
                            rounds=args.rounds)
    except Exception as exc:
        sys.stderr.write("[error] burst failed before any send: %s\n" % exc)
        sys.exit(1)

    for rnd, outcomes in enumerate(results, 1):
        for idx, status, length, sha in sorted(outcomes):
            print("[round %d run %02d] status=%s len=%d sha=%s"
                  % (rnd, idx, status if status is not None else "ERR",
                     length, sha))
    verdict, detail = summarize(results)
    print("[summary] %s - %s" % (verdict, detail))
    print("[note] response divergence alone is NOT the finding; read the "
          "final state (GET the object) to prove divergence from the "
          "single-request outcome")

    if args.verify_file:
        conn = None
        try:
            with open(args.verify_file, "r", encoding="latin-1") as fh:
                vm, vp, vh, vb = parse_request(fh.read())
            if vm != "GET":
                sys.stderr.write(
                    "[error] --verify-file must be a GET request, got %s\n"
                    % vm
                )
                sys.exit(1)
            vraw = build_raw(vm, vp, vh, vb)
            vhost = host_of(vh)
            _vh, vport = split_host_port(vhost, args.scheme)
            vtarget = "%s://%s%s" % (
                args.scheme,
                vhost if ":" in vhost else "%s:%d" % (vhost, vport),
                vp,
            )
            require_in_scope(vtarget, scope_file)
            vsender = LiveSender(args.scheme, vhost, vraw, args.timeout)
            conn = vsender.preconnect(0)
            status, vbody = vsender.fire(0, conn)
            conn = None
            print("[final-state] %s %s -> %d len=%d sha=%s"
                  % (vm, vp, status, len(vbody),
                     hashlib.sha256(vbody).hexdigest()[:12]))
        except (OSError, ValueError) as err:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            sys.stderr.write("[error] verify replay failed: %s\n" % err)
            sys.exit(1)

    print("[evidence] keep the burst definition, this per-run output, and "
          "the final-state GET pair; D2 = replay from a clean state with "
          "the same divergence")


if __name__ == "__main__":
    main()
