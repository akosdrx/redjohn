#!/usr/bin/env python3
# jwt_inspect.py - offline JWT structure triage (decode WITHOUT verification).
#
# Decodes header and payload of a JWS token (three dot-separated base64url
# segments) using only the standard library, and prints checklist verdicts:
# alg risk notes, exp/nbf presence + value, iss/aud emptiness, suspicious
# claims (kid traversal/SQLi shape, jku/x5u, privilege claims).
#
# It NEVER verifies a signature and NEVER contacts the network. Behavioral
# evidence (forged-token acceptance etc.) comes from scope-guarded replays
# per the 30-auth-access-control SKILL; this tool only triages structure.
#
# JWE (5 segments) and non-JSON payloads are reported structurally, not
# decoded further.
#
# Exit codes: 0 success, 1 other errors (bad input, unreadable token).
# Offline analysis script: --self-test runs on fixtures, no network.

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import sys
import time

PRIVILEGE_CLAIMS = (
    "role", "roles", "scope", "scopes", "permissions", "groups",
    "is_admin", "admin", "superuser", "entitlements",
)

SUSPICIOUS_KID_CHARS = ("../", "..\\", "'", '"', ";", "--", "$(", "`",
                        "|", "\x00")


def b64url_decode(segment):
    """Decode one base64url segment, restoring stripped padding."""
    if not isinstance(segment, str) or not segment:
        raise ValueError("empty segment")
    pad = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + pad)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("segment is not valid base64url: %s" % exc)


def decode_token(token):
    """Return dict(header, payload, sig_len, segments, notes). No verification."""
    token = token.strip()
    parts = token.split(".")
    notes = []
    if len(parts) == 5:
        header = None
        try:
            header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
            if not isinstance(header, dict):
                header = None
        except (ValueError, UnicodeDecodeError):
            header = None
        return {"header": header, "payload": None, "sig_len": 0,
                "segments": 5,
                "notes": ["JWE (5 segments): encrypted token; protected "
                          "header decoded if possible, payload is ciphertext "
                          "(not decodable offline without the key)"]}
    if len(parts) != 3:
        raise ValueError("expected 3 dot-separated segments (JWS), got %d"
                         % len(parts))

    header_raw = b64url_decode(parts[0])
    payload_raw = b64url_decode(parts[1])
    try:
        header = json.loads(header_raw.decode("utf-8"))
        if not isinstance(header, dict):
            raise ValueError("header is not a JSON object")
    except (ValueError, UnicodeDecodeError):
        raise ValueError("header segment is not JSON")
    try:
        payload = json.loads(payload_raw.decode("utf-8"))
        if not isinstance(payload, dict):
            payload = {"_raw": payload}
            notes.append("payload JSON is not an object; wrapped under _raw")
    except (ValueError, UnicodeDecodeError):
        payload = None
        notes.append("payload segment is not JSON (opaque/binary)")

    return {"header": header, "payload": payload,
            "sig_len": len(parts[2]), "segments": 3, "notes": notes}


# ---------------------------------------------------------------------------
# Checklist verdicts
# ---------------------------------------------------------------------------

def verdicts(header, payload, now=None):
    """Yield (level, tag, message) verdict lines. Levels: critical/risk/note/ok."""
    now = now if now is not None else time.time()
    out = []

    alg = header.get("alg")
    if alg is None:
        out.append(("critical", "alg", "no alg header; verifier behavior "
                    "undefined - forge test candidate"))
    elif alg.lower() == "none":
        out.append(("critical", "alg:none",
                    "alg=none: send signature-stripped canary token to an "
                    "in-scope endpoint (T1, CWE-347)"))
    elif isinstance(alg, str) and alg.upper().startswith("HS"):
        out.append(("risk", "alg-hmac",
                    "%s symmetric: weak shared key -> hashcat -m 16500 "
                    "handoff (engagement-sanctioned only, via 35)" % alg))
    elif isinstance(alg, str) and alg[:2] in ("RS", "PS", "ES") or alg == "EdDSA":
        out.append(("note", "alg-asym",
                    "%s asymmetric: test RS->HS key confusion if verifier "
                    "trusts the alg header (T2)" % alg))
    else:
        out.append(("risk", "alg-unknown", "unusual alg %r" % alg))

    if "crit" in header:
        out.append(("note", "crit", "crit header present (EMBEDDED JWS): "
                    "check the payload.b64 envelope too"))

    kid = header.get("kid")
    if isinstance(kid, str):
        hits = [c for c in SUSPICIOUS_KID_CHARS if c in kid]
        if hits:
            out.append(("risk", "kid-injection",
                        "kid %r contains suspicious characters %s "
                        "(traversal/SQLi/cmdi shapes, T3)" % (kid, hits)))
        else:
            out.append(("ok", "kid", "kid present, ordinary shape"))
    elif kid is not None:
        out.append(("risk", "kid-type", "kid is not a string (%r)" % (kid,)))

    for hname in ("jku", "x5u", "x5c", "jwk"):
        if hname in header:
            out.append(("risk", hname,
                        "%s header present: unvalidated key URL/key embedded "
                        "in token (T4) - verify how the server resolves it" % hname))

    if payload is None:
        out.append(("risk", "payload", "payload not decodable; manual review"))
        return out

    exp = payload.get("exp")
    if exp is None:
        out.append(("risk", "exp-missing",
                    "no exp claim: token may never expire (CWE-613); test "
                    "replay past the stated session cap"))
    elif not isinstance(exp, (int, float)):
        out.append(("risk", "exp-type", "exp is not numeric (%r)" % (exp,)))
    elif exp < now:
        out.append(("note", "exp-past",
                    "exp=%d already in the past at inspection time" % exp))
    elif exp - now > 86400 * 30:
        out.append(("risk", "exp-far",
                    "exp more than ~30 days out (%d seconds); note the "
                    "policy mismatch if the app states shorter sessions"
                    % int(exp - now)))
    else:
        out.append(("ok", "exp", "exp present and within a sane window"))

    nbf = payload.get("nbf")
    if nbf is None:
        out.append(("note", "nbf-missing", "no nbf claim (optional, common)"))
    elif isinstance(nbf, (int, float)) and nbf > now:
        out.append(("note", "nbf-future",
                    "nbf=%d in the future: accepted-now behavior would show "
                    "nbf is ignored (T5)" % nbf))

    for claim, label in (("iss", "iss"), ("aud", "aud")):
        val = payload.get(claim)
        if val is None or val == "" or val == []:
            out.append(("risk", claim + "-empty",
                        "missing/empty %s claim: audience or issuer isolation "
                        "cannot be claimed (T6)" % label))
        else:
            out.append(("ok", claim, "%s=%r" % (claim, val)))

    present_priv = [c for c in PRIVILEGE_CLAIMS if c in payload]
    if present_priv:
        out.append(("risk", "privilege-claims",
                    "privilege-bearing claims present (%s): confirm the "
                    "server re-checks them server-side (T7 trust boundary)"
                    % ", ".join(present_priv)))

    if "sub" not in payload:
        out.append(("note", "sub-missing", "no sub claim"))
    return out


def format_report(token, info, vs):
    lines = []
    lines.append("jwt: %s...%s (%d segments, signature %d chars)"
                 % (token[:12], token[-6:], info["segments"], info["sig_len"]))
    for note in info["notes"]:
        lines.append("note: %s" % note)
    if info["header"] is not None:
        lines.append("header:  %s"
                     % json.dumps(info["header"], ensure_ascii=True,
                                  sort_keys=True))
    if info["payload"] is not None:
        lines.append("payload: %s"
                     % json.dumps(info["payload"], ensure_ascii=True,
                                  sort_keys=True, default=str))
    lines.append("---- checklist verdicts (structure only; no verification) ----")
    for level, tag, msg in vs:
        lines.append("%-8s %-18s %s" % ("[%s]" % level, tag, msg))
    lines.append("reminder: acceptance evidence must come from scope-guarded "
                 "replays (30 SKILL methodology); this tool never verifies "
                 "signatures and never touches the network.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Offline JWT triage: decode header/payload without "
        "verification and print checklist verdicts (alg risk, exp/nbf, "
        "iss/aud, suspicious claims). No network, no signature checks.",
    )
    ap.add_argument("--jwt", help="The JWT string (JWS, 3 segments)")
    ap.add_argument("--self-test", action="store_true",
                    help="Run offline self-tests (fixtures, no network)")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.jwt:
        sys.stderr.write("error: --jwt is required\n")
        return 1
    try:
        info = decode_token(args.jwt)
        if info["header"] is not None:
            vs = verdicts(info["header"], info["payload"])
        else:
            vs = [("risk", "header", "protected header not decodable; "
                   "manual review")]
    except ValueError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 1
    print(format_report(args.jwt, info, vs))
    print("evidence: pair any behavioral follow-up (forged-token replay) as "
          "evidence/p4-jwt-<seq>.{req,resp}.txt with canary claims.")
    return 0


# ---------------------------------------------------------------------------
# Self-test: fully offline. The HS256 fixture token is hand-built here with
# hmac + base64 over a dummy local key that guards nothing ("selftest-dummy").
# ---------------------------------------------------------------------------

def b64u_str(obj):
    """base64url-encode a JSON object, padding stripped, as str."""
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def make_hs256_fixture(header, payload, key=b"selftest-dummy-key"):
    """Hand-rolled HS256 assembly (stdlib hmac+base64 only)."""
    h = b64u_str(header)
    p = b64u_str(payload)
    sig = hmac.new(key, ("%s.%s" % (h, p)).encode(), hashlib.sha256).digest()
    return "%s.%s.%s" % (h, p,
                         base64.urlsafe_b64encode(sig).rstrip(b"=").decode())


def self_test():
    checks = 0

    def ok(label):
        nonlocal checks
        checks += 1
        print("[self-test] ok: %s" % label)

    # --- hand-built HS256 fixture (hmac + base64, offline, dummy key) ---
    tok = make_hs256_fixture(
        {"alg": "HS256", "typ": "JWT"},
        {"iss": "issuer.example.oauth", "aud": "app.example",
         "sub": "user-a@example.com", "iat": 1735689600,
         "exp": int(time.time()) + 3600, "scope": "invoices:read"})
    info = decode_token(tok)
    assert info["segments"] == 3 and info["sig_len"] == 43, info
    assert info["header"]["alg"] == "HS256"
    assert info["payload"]["iss"] == "issuer.example.oauth"
    assert info["payload"]["exp"] > int(time.time()) - 5
    ok("hand-built HS256 token decodes (header+payload, no verification)")

    vs = dict((tag, level) for level, tag, _m in
              verdicts(info["header"], info["payload"]))
    assert vs.get("alg-hmac") == "risk"
    assert vs.get("exp") == "ok"
    assert vs.get("iss") == "ok" and vs.get("aud") == "ok"
    assert "privilege-claims" in vs  # scope claim triggers trust-boundary note
    ok("healthy token: risk note on HS alg, ok on exp/iss/aud, "
       "privilege-claim note")

    # --- alg:none ---
    none_tok = "%s.%s." % (b64u_str({"alg": "none", "typ": "JWT"}),
                           b64u_str({"sub": "admin@example.com",
                                     "role": "admin"}))
    info = decode_token(none_tok)
    vs = verdicts(info["header"], info["payload"])
    assert ("critical", "alg:none") in [(l, t) for l, t, _m in vs], vs
    ok("alg:none token flagged critical")

    # --- kid traversal ---
    tok = make_hs256_fixture(
        {"alg": "HS256", "typ": "JWT", "kid": "../../../../dev/null"},
        {"sub": "user-a@example.com", "exp": int(time.time()) + 600})
    info = decode_token(tok)
    vs = verdicts(info["header"], info["payload"])
    assert any(t == "kid-injection" and l == "risk" for l, t, _m in vs), vs
    ok("kid path traversal flagged")

    # --- missing exp + empty iss/aud ---
    tok = make_hs256_fixture({"alg": "HS256", "typ": "JWT"},
                             {"sub": "user-b@example.com"})
    info = decode_token(tok)
    vs = verdicts(info["header"], info["payload"])
    tags = [(l, t) for l, t, _m in vs]
    assert ("risk", "exp-missing") in tags, tags
    assert ("risk", "iss-empty") in tags and ("risk", "aud-empty") in tags
    ok("thin token: exp-missing + iss/aud emptiness flagged")

    # --- expired exp vs fixed 'now' ---
    tok = make_hs256_fixture({"alg": "HS256", "typ": "JWT"},
                             {"sub": "user-a@example.com",
                              "exp": 946684800})
    info = decode_token(tok)
    vs = verdicts(info["header"], info["payload"], now=946684801)
    assert ("note", "exp-past") in [(l, t) for l, t, _m in vs]
    ok("expired exp detected against injected clock")

    # --- far-future exp ---
    tok = make_hs256_fixture({"alg": "HS256", "typ": "JWT"},
                             {"sub": "user-a@example.com",
                              "exp": int(time.time()) + 86400 * 400})
    vs = verdicts(decode_token(tok)["header"], decode_token(tok)["payload"])
    assert ("risk", "exp-far") in [(l, t) for l, t, _m in vs]
    ok("far-future exp flagged")

    # --- RS256 + jku ---
    tok = make_hs256_fixture(
        {"alg": "RS256", "typ": "JWT",
         "jku": "https://keys.attacker.example/jwks.json", "kid": "k1"},
        {"sub": "user-a@example.com", "exp": int(time.time()) + 600})
    info = decode_token(tok)
    vs = verdicts(info["header"], info["payload"])
    tags = {(l, t) for l, t, _m in vs}
    assert ("note", "alg-asym") in tags and ("risk", "jku") in tags, tags
    ok("RS256 + jku header: confusion note + jku risk")

    # --- JWE shape ---
    info = decode_token("a.b.c.d.e")
    assert info["segments"] == 5 and "JWE" in info["notes"][0]
    assert info["header"] is None  # 'a' is not decodable JSON
    jwe_hdr = ("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0"  # {"alg":"dir","enc":"A128GCM"}
               ".b.c.d.e")
    info = decode_token(jwe_hdr)
    assert info["segments"] == 5 and info["header"]["enc"] == "A128GCM"
    ok("5-segment JWE reported structurally, protected header decoded "
       "when JSON")

    # --- payload not JSON (opaque) -> decoded with note, not an error ---
    opaque = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
              ".AAAA.c2ln")
    info = decode_token(opaque)
    assert info["payload"] is None and info["notes"], info
    ok("opaque (non-JSON) payload decoded with a note")

    # --- malformed inputs ---
    for bad in ("", "not-a-jwt", "a.b", "!!!.b.c", "*.*.*"):
        try:
            decode_token(bad)
            raised = False
        except ValueError:
            raised = True
        assert raised, bad
    ok("malformed tokens rejected with ValueError")

    # --- CLI paths ---
    tok = make_hs256_fixture({"alg": "HS256", "typ": "JWT"},
                             {"iss": "issuer.example.oauth",
                              "aud": "app.example",
                              "sub": "user-a@example.com",
                              "exp": int(time.time()) + 900})
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(["--jwt", tok])
    assert code == 0 and "checklist verdicts" in buf.getvalue()
    ok("--jwt happy path exits 0 with a verdict block")

    assert main(["--jwt", "a.b"]) == 1
    ok("malformed token via CLI -> exit 1")

    print("[self-test] jwt_inspect: all %d checks passed" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
