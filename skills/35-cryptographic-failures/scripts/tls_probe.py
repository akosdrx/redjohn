#!/usr/bin/env python3
# tls_probe.py - scope-guarded TLS negotiated-parameters probe (stdlib ssl).
#
# Connects to --host[:port] (default 443) and reports: negotiated TLS
# version + cipher, compression, certificate subject/issuer/notAfter,
# signature algorithm, public-key type and size (hand-rolled DER walk over
# the peer certificate - no third-party libs), SAN/CN hostname match, and
# the chain-verification verdict (verified / self-signed / unknown-ca /
# expired / hostname-mismatch). At most TWO handshakes per host: one
# verifying; a second unverified one to collect details if the first fails.
#
# Renegotiation behavior and full suite enumeration are NOT observable via
# the Python stdlib - use the openssl s_client / testssl.sh commands in
# references/tls-audit.md for those.
#
# Scope: --scope-file PATH or REDJOHN_SCOPE_FILE; the host is resolved and
# validated against the engagement scope BEFORE any socket is opened.
# Absent scope file -> exit 1. Out of scope -> exit 2, nothing sent.
#
# Exit codes: 0 success, 2 scope refusal, 1 other errors.

import argparse
import ipaddress
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse

DEFAULT_TIMEOUT = 15.0

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
        sys.stderr.write("[scope-guard] scope file unreadable (%s): %s\n"
                         % (scope_file, exc))
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
# host[:port] parsing (pure; unit-tested offline)
# ---------------------------------------------------------------------------

def parse_port(text):
    if not text.isdigit():
        raise ValueError("port must be numeric, got %r" % text)
    port = int(text)
    if not 1 <= port <= 65535:
        raise ValueError("port out of range: %d" % port)
    return port


def parse_hostport(value):
    """Parse HOST[:PORT] -> (host, port). Default port 443. No schemes."""
    value = value.strip()
    if not value:
        raise ValueError("empty host")
    if "://" in value:
        raise ValueError("host must not contain a scheme (use HOST[:PORT])")
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise ValueError("unterminated IPv6 literal")
        host = value[1:end]
        rest = value[end + 1:]
        if rest == "":
            port = 443
        elif rest.startswith(":"):
            port = parse_port(rest[1:])
        else:
            raise ValueError("junk after IPv6 literal: %r" % rest)
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise ValueError("bracketed host is not an IPv6 literal")
        return host, port
    if value.count(":") == 1:
        host, port_text = value.split(":")
        if not host:
            raise ValueError("empty host")
        return host, parse_port(port_text)
    if ":" in value:  # bare IPv6 literal
        try:
            ipaddress.IPv6Address(value)
        except ValueError:
            raise ValueError("multiple ':' without brackets is only valid "
                             "for bare IPv6 literals")
        return value, 443
    return value, 443


# ---------------------------------------------------------------------------
# Minimal DER walk (X.509 facts the ssl module does not expose)
# ---------------------------------------------------------------------------

SIG_OIDS = {
    "1.2.840.113549.1.1.4": ("md5WithRSAEncryption", True),
    "1.2.840.113549.1.1.5": ("sha1WithRSAEncryption", True),
    "1.2.840.10045.4.1": ("ecdsa-with-SHA1", True),
    "1.2.840.10040.4.3": ("dsaWith-SHA1", True),
    "1.2.840.113549.1.1.11": ("sha256WithRSAEncryption", False),
    "1.2.840.113549.1.1.12": ("sha384WithRSAEncryption", False),
    "1.2.840.113549.1.1.13": ("sha512WithRSAEncryption", False),
    "1.2.840.10045.4.3.2": ("ecdsa-with-SHA256", False),
    "1.2.840.10045.4.3.3": ("ecdsa-with-SHA384", False),
    "1.2.840.10045.4.3.4": ("ecdsa-with-SHA512", False),
    "1.3.101.112": ("Ed25519", False),
}

SPKI_OIDS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.2.840.10040.4.1": "DSA",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}

CURVE_OIDS = {
    "1.2.840.10045.3.1.7": ("prime256v1 (P-256)", 256),
    "1.3.132.0.34": ("secp384r1 (P-384)", 384),
    "1.3.132.0.35": ("secp521r1 (P-521)", 521),
    "1.3.132.0.33": ("secp224r1 (P-224)", 224),
}


def der_read(data, off):
    """Read one TLV; return (tag, content_off, content_len). Raise ValueError."""
    if off >= len(data):
        raise ValueError("der: offset past end")
    tag = data[off]
    o = off + 1
    if o >= len(data):
        raise ValueError("der: truncated length")
    first = data[o]
    o += 1
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4:
            raise ValueError("der: unsupported length form")
        if o + n > len(data):
            raise ValueError("der: truncated long length")
        length = int.from_bytes(data[o:o + n], "big")
        o += n
    if o + length > len(data):
        raise ValueError("der: content overruns buffer")
    return tag, o, length


def der_children(data, start, end):
    """List (tag, content_off, content_len) elements in data[start:end]."""
    out = []
    off = start
    while off < end:
        tag, cstart, clen = der_read(data, off)
        out.append((tag, cstart, clen))
        off = cstart + clen
    if off != end:
        raise ValueError("der: children overrun parent")
    return out


def decode_oid(content):
    """Decode OID content bytes to dotted text."""
    if not content:
        raise ValueError("der: empty OID")
    parts = [content[0] // 40, content[0] % 40]
    val = 0
    for b in content[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def first_oid(data, tag, start, end):
    """First OID inside a SEQUENCE (or the element itself if it is an OID)."""
    if tag == 0x06:
        return decode_oid(data[start:end])
    if tag == 0x30:
        for ctag, cstart, clen in der_children(data, start, end):
            if ctag == 0x06:
                return decode_oid(data[cstart:cstart + clen])
    raise ValueError("der: no OID found")


def rsa_key_bits(key_der):
    """RSAPublicKey SEQUENCE -> modulus bit length."""
    tag, cstart, clen = der_read(key_der, 0)
    if tag != 0x30:
        raise ValueError("rsa: public key is not a SEQUENCE")
    kids = der_children(key_der, cstart, cstart + clen)
    if len(kids) < 2 or kids[0][0] != 0x02:
        raise ValueError("rsa: expected modulus+exponent INTEGERs")
    mt, ms, ml = kids[0]
    modulus = int.from_bytes(key_der[ms:ms + ml], "big")
    return modulus.bit_length()


# --- name / validity / SAN parsing (for CERT_NONE collection passes,
# --- where getpeercert() returns an empty dict) ---

NAME_OIDS = {
    "2.5.4.3": "commonName",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "countryName",
    "2.5.4.7": "localityName",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.9": "streetAddress",
    "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationalUnitName",
    "1.2.840.113549.1.9.1": "emailAddress",
}

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _decode_string(raw):
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.hex()


def parse_name(data, start, end):
    """RDNSequence -> getpeercert-style tuple of RDN tuples."""
    rdns = []
    for set_tag, sstart, slen in der_children(data, start, end):
        if set_tag != 0x31:
            raise ValueError("der: RDN is not a SET")
        rdn = []
        for atv_tag, astart, alen in der_children(data, sstart,
                                                  sstart + slen):
            kids = der_children(data, astart, astart + alen)
            if len(kids) < 2 or kids[0][0] != 0x06:
                raise ValueError("der: malformed AttributeTypeAndValue")
            oid = decode_oid(data[kids[0][1]:kids[0][1] + kids[0][2]])
            vt, vs, vl = kids[1]
            rdn.append((NAME_OIDS.get(oid, oid),
                        _decode_string(data[vs:vs + vl])))
        rdns.append(tuple(rdn))
    return tuple(rdns)


def parse_time(data, tag, start, end):
    """UTCTime/GeneralizedTime -> getpeercert-style 'Mon DD HH:MM:SS YYYY GMT'."""
    text = data[start:end].decode("ascii", "replace").strip()
    try:
        if tag == 0x17 and len(text) >= 12:        # UTCTime YYMMDDHHMMSSZ
            two = int(text[:2])
            year = two + (2000 if two < 50 else 1900)
            mon, day = int(text[2:4]), int(text[4:6])
            hh, mm, ss = text[6:8], text[8:10], text[10:12]
        elif tag == 0x18 and len(text) >= 14:      # GeneralizedTime
            year, mon, day = int(text[:4]), int(text[4:6]), int(text[6:8])
            hh, mm, ss = text[8:10], text[10:12], text[12:14]
        else:
            return text
        return "%s %02d %s:%s:%s %d GMT" % (MONTHS[mon - 1], day,
                                            hh, mm, ss, year)
    except (ValueError, IndexError):
        return text


def _parse_san_ext(data, start, end):
    """[3] Extensions content -> subjectAltName tuple (DNS, IP Address)."""
    for xtag, xs, xl in der_children(data, start, end):
        if xtag != 0x30:
            continue  # the Extensions SEQUENCE itself
        for etag, es, el in der_children(data, xs, xs + xl):
            if etag != 0x30:
                continue
            kids = der_children(data, es, es + el)
            if not kids or kids[0][0] != 0x06:
                continue
            if decode_oid(data[kids[0][1]:kids[0][1] + kids[0][2]]) \
                    != "2.5.29.17":
                continue
            for kt, ks, kl in kids[1:]:
                if kt != 0x04:  # extnValue OCTET STRING
                    continue
                _it, is_, il = der_read(data, ks)
                sans = []
                for gt, gs, gl in der_children(data, is_, is_ + il):
                    if gt == 0x82:  # [2] dNSName
                        sans.append(("DNS",
                                     data[gs:gs + gl].decode("latin-1")))
                    elif gt == 0x87:  # [7] iPAddress
                        try:
                            sans.append(("IP Address", str(ipaddress.ip_address(
                                data[gs:gs + gl]))))
                        except ValueError:
                            pass
                return tuple(sans)
    return ()


def cert_from_der(der):
    """Minimal X.509 fields from DER (subject/issuer/notBefore/notAfter/SAN)
    in the getpeercert() dict shape, for collection passes where the ssl
    module returns an empty dict."""
    tag, cstart, clen = der_read(der, 0)
    if tag != 0x30:
        raise ValueError("cert: top level is not a SEQUENCE")
    top = der_children(der, cstart, cstart + clen)
    tbs_tag, tbs_start, tbs_len = top[0]
    if tbs_tag != 0x30:
        raise ValueError("cert: tbsCertificate is not a SEQUENCE")
    tbs = der_children(der, tbs_start, tbs_start + tbs_len)
    idx = 1 if (tbs and tbs[0][0] == 0xA0) else 0
    if len(tbs) < idx + 6:
        raise ValueError("cert: tbsCertificate too short")
    cert = {}
    try:
        cert["issuer"] = parse_name(der, tbs[idx + 2][1],
                                    tbs[idx + 2][1] + tbs[idx + 2][2])
        cert["subject"] = parse_name(der, tbs[idx + 4][1],
                                     tbs[idx + 4][1] + tbs[idx + 4][2])
        _vt, vs, vl = tbs[idx + 3]
        times = der_children(der, vs, vs + vl)
        if len(times) >= 2:
            cert["notBefore"] = parse_time(der, times[0][0], times[0][1],
                                           times[0][1] + times[0][2])
            cert["notAfter"] = parse_time(der, times[1][0], times[1][1],
                                          times[1][1] + times[1][2])
    except ValueError:
        pass  # keep whatever parsed
    for etag, es, el in tbs[idx + 6:]:
        if etag == 0xA3:
            try:
                cert["subjectAltName"] = _parse_san_ext(der, es, es + el)
            except ValueError:
                pass
    return cert


def extract_cert_facts(der):
    """Certificate DER -> {sig_alg, sig_weak, key_type, key_bits, key_detail}."""
    tag, cstart, clen = der_read(der, 0)
    if tag != 0x30:
        raise ValueError("cert: top level is not a SEQUENCE")
    top = der_children(der, cstart, cstart + clen)
    if len(top) < 3:
        raise ValueError("cert: too few top-level elements")
    tbs_tag, tbs_start, tbs_len = top[0]
    if tbs_tag != 0x30:
        raise ValueError("cert: tbsCertificate is not a SEQUENCE")

    sig_oid = first_oid(der, top[1][0], top[1][1], top[1][1] + top[1][2])
    sig_name, sig_weak = SIG_OIDS.get(
        sig_oid, ("unknown(%s)" % sig_oid, None))

    tbs = der_children(der, tbs_start, tbs_start + tbs_len)
    idx = 1 if (tbs and tbs[0][0] == 0xA0) else 0  # skip [0] version
    # tbs order: serial, signature, issuer, validity, subject, SPKI, ...
    if len(tbs) < idx + 6:
        raise ValueError("cert: tbsCertificate too short")
    spki_tag, spki_start, spki_len = tbs[idx + 5]
    if spki_tag != 0x30:
        raise ValueError("cert: SPKI is not a SEQUENCE")
    spki = der_children(der, spki_start, spki_start + spki_len)
    if len(spki) < 2 or spki[0][0] != 0x30 or spki[1][0] != 0x03:
        raise ValueError("cert: malformed SPKI")
    alg_oid = first_oid(der, spki[0][0], spki[0][1], spki[0][1] + spki[0][2])
    key_type = SPKI_OIDS.get(alg_oid, "unknown(%s)" % alg_oid)

    bt, bs, bl = spki[1]
    bitstring = der[bs:bs + bl]
    if not bitstring or bitstring[0] != 0:
        raise ValueError("cert: unexpected BIT STRING unused bits")

    key_bits = None
    key_detail = None
    if key_type == "RSA":
        key_bits = rsa_key_bits(bitstring[1:])
    elif key_type == "EC":
        alg_kids = der_children(der, spki[0][1], spki[0][1] + spki[0][2])
        oids = [decode_oid(der[cstart2:cstart2 + clen2])
                for ctag, cstart2, clen2 in alg_kids if ctag == 0x06]
        # AlgorithmIdentifier = SEQUENCE { OID ecPublicKey, OID curve }
        curve = oids[1] if len(oids) > 1 else None
        name, bits = CURVE_OIDS.get(curve, ("unknown curve(%s)" % curve,
                                            None))
        key_detail = name
        key_bits = bits
    else:
        key_detail = "fixed-size algorithm"

    return {"sig_alg": sig_name, "sig_weak": sig_weak, "key_type": key_type,
            "key_bits": key_bits, "key_detail": key_detail}


# ---------------------------------------------------------------------------
# Hostname matching + verification classification (pure)
# ---------------------------------------------------------------------------

def _pattern_match(host, pattern):
    """Single-label wildcard DNS match."""
    if pattern.startswith("*."):
        suffix = pattern[1:]
        label = host[:len(host) - len(suffix)]
        return (host.endswith(suffix) and label
                and "." not in label)
    return host == pattern


def match_hostname(host, cert):
    """Return (ok, detail) for host vs SAN/CN in a getpeercert() dict."""
    host = host.lower().rstrip(".")
    sans = cert.get("subjectAltName", ())
    dns_names = [v.lower() for kind, v in sans if kind == "DNS"]
    ip_addrs = [v for kind, v in sans if kind == "IP Address"]
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if dns_names or ip_addrs:
        if is_ip:
            return host in ip_addrs, "IP SAN %s" % (ip_addrs or ["none"])
        for name in dns_names:
            if _pattern_match(host, name):
                return True, "SAN DNS %s" % name
        return False, "host not covered by SAN %s" % dns_names
    # CN fallback (legacy certs without SAN)
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName" and _pattern_match(host,
                                                      value.lower().rstrip(".")):
                return True, "CN fallback %s" % value
    return False, "no SAN and CN does not match"


def classify_verify_error(exc):
    """Map an SSLCertVerificationError to a short verdict label."""
    msg = str(exc).lower()
    if "doesn't match" in msg or "hostname mismatch" in msg:
        return "hostname-mismatch"
    if "self signed" in msg or "self-signed" in msg:
        return "self-signed"
    if "unable to get local issuer" in msg:
        return "unknown-ca"
    if "has expired" in msg or "expired" in msg:
        return "expired"
    if "not yet valid" in msg:
        return "not-yet-valid"
    return "verify-failed"


def cert_self_signed(cert):
    """Issuer == subject heuristic from the getpeercert() dict."""
    subj = [v for rdn in cert.get("subject", ()) for _k, v in rdn]
    iss = [v for rdn in cert.get("issuer", ()) for _k, v in rdn]
    return bool(subj) and subj == iss


def cert_expired(cert, now=None):
    """(expired, days_left, notAfter) from the cert dict."""
    not_after = cert.get("notAfter")
    if not not_after:
        return None, None, None
    try:
        expires = ssl.cert_time_to_seconds(not_after)
    except ValueError:
        return None, None, not_after
    now = now if now is not None else time.time()
    days = int((expires - now) // 86400)
    return days < 0, days, not_after


# ---------------------------------------------------------------------------
# Findings + report (pure)
# ---------------------------------------------------------------------------

def findings(version, compression, verify_verdict, facts, cert, host_ok):
    """Return [(level, tag, message)] against the 35 SKILL thresholds."""
    out = []
    if version in ("TLSv1", "TLSv1.0", "SSLv3", "SSLv2", "TLSv1.1"):
        out.append(("finding", "tls-version",
                    "%s negotiated/accepted (threshold: > TLS 1.1; "
                    "CWE-326/CWE-327)" % version))
    if compression:
        out.append(("finding", "tls-compression",
                    "TLS compression enabled (%s) - CRIME class (CWE-327)"
                    % compression))
    if verify_verdict == "chain-verified":
        pass
    elif verify_verdict == "hostname-mismatch":
        out.append(("finding", "hostname-mismatch",
                    "certificate does not match the requested hostname "
                    "(CWE-295)"))
    elif verify_verdict == "expired":
        out.append(("finding", "cert-expired",
                    "certificate has expired (CWE-295)"))
    elif verify_verdict == "not-yet-valid":
        out.append(("finding", "cert-not-yet-valid", "certificate not yet "
                    "valid (CWE-295)"))
    else:
        out.append(("finding", "chain-not-verifiable",
                    "chain verification failed (%s) - acceptable only for "
                    "sanctioned lab fixtures (CWE-295)" % verify_verdict))
    if facts.get("sig_weak"):
        out.append(("finding", "weak-signature",
                    "certificate signed with %s (CWE-328)" % facts["sig_alg"]))
    if facts.get("key_type") == "RSA" and facts.get("key_bits", 0) < 2048:
        out.append(("finding", "small-key",
                    "RSA public key %d bits < 2048 (CWE-326)"
                    % facts["key_bits"]))
    expired, days, _na = cert_expired(cert)
    if expired:
        out.append(("finding", "cert-expired",
                    "notAfter in the past (%d days overdue)" % -days))
    if not host_ok:
        out.append(("finding", "hostname-mismatch",
                    "hostname not covered by SAN/CN (CWE-295)"))
    return out


def format_report(host, port, data, found):
    f = data.get("facts") or {}
    lines = ["[tls] host=%s port=%d" % (host, port)]
    if data.get("error"):
        lines.append("[tls] probe error: %s" % data["error"])
        return "\n".join(lines)
    lines.append("[tls] negotiated: %s cipher=%s (%s, %s secret bits)"
                 % (data["version"], data["cipher_name"],
                    data["cipher_proto"], data["cipher_bits"]))
    lines.append("[tls] compression: %s"
                 % (data["compression"] or "None"))
    lines.append("[tls] verification: %s" % data["verify_verdict"])
    cert = data["cert"]
    if cert:
        subj = ", ".join(v for rdn in cert.get("subject", ())
                         for _k, v in rdn) or "?"
        iss = ", ".join(v for rdn in cert.get("issuer", ())
                        for _k, v in rdn) or "?"
        lines.append("[tls] cert subject: %s" % subj)
        lines.append("[tls] cert issuer:  %s" % iss)
        _exp, days, not_after = cert_expired(cert)
        if not_after:
            if days is not None and days >= 0:
                lines.append("[tls] cert notAfter: %s (%d days left)"
                             % (not_after, days))
            else:
                lines.append("[tls] cert notAfter: %s (EXPIRED)" % not_after)
    if f:
        lines.append("[tls] signature algorithm: %s" % f["sig_alg"])
        key = "%s %s bits" % (f["key_type"], f["key_bits"])
        if f["key_detail"]:
            key += " (%s)" % f["key_detail"]
        lines.append("[tls] public key: %s" % key)
    lines.append("[tls] hostname match: %s (%s)"
                 % ("ok" if data["host_ok"] else "MISMATCH",
                    data["host_detail"]))
    lines.append("[tls] ---- findings ----")
    if found:
        for level, tag, msg in found:
            lines.append("[tls] %s %s: %s" % (level, tag, msg))
    else:
        lines.append("[tls] none at the 35 thresholds; record for the "
                     "coverage statement.")
    lines.append("[tls] note: renegotiation + full suite enumeration need "
                 "openssl s_client / testssl.sh (references/tls-audit.md).")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Probe (network; guard runs first in main)
# ---------------------------------------------------------------------------

def _collect(tls_sock):
    cert = tls_sock.getpeercert()
    der = tls_sock.getpeercert(binary_form=True)
    facts = extract_cert_facts(der) if der else {}
    if not cert and der:
        # CERT_NONE collection pass: the dict form comes back empty, so
        # parse the needed fields from the DER ourselves.
        try:
            cert = cert_from_der(der)
        except ValueError:
            cert = {}
    cipher = tls_sock.cipher() or ("?", "?", -1)
    return {
        "version": tls_sock.version(),
        "cipher_name": cipher[0],
        "cipher_proto": cipher[1],
        "cipher_bits": cipher[2],
        "compression": tls_sock.compression(),
        "cert": cert if cert else {},
        "facts": facts,
    }


def _looks_like_sni_refusal(exc):
    """True when the build refuses server_hostname (not a cert failure)."""
    msg = str(exc).lower()
    return ("server_hostname" in msg or "check_hostname" in msg
            or "ip address" in msg)


def _one_handshake(host, port, context, timeout, sni):
    """Fresh connection + single handshake; returns collected dict.

    Each call opens its OWN connection: a failed handshake leaves the raw
    socket in an undefined state, so any retry reconnects fresh.
    """
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        if sni:
            tls = context.wrap_socket(raw, server_hostname=host)
        else:
            tls = context.wrap_socket(raw)
    except Exception:
        try:
            raw.close()
        except OSError:
            pass
        raise
    try:
        return _collect(tls)
    finally:
        try:
            tls.close()
        except OSError:
            pass


VERIFY_EXC = (ssl.SSLCertVerificationError, ssl.SSLError, ValueError,
              OSError)


def probe(host, port, timeout=DEFAULT_TIMEOUT):
    """At most three handshakes: verified (+SNI), verified chain-only
    fallback when the build refuses the server_hostname form, then one
    unverified collection pass if verification failed."""
    data = {"error": None}
    collected = None
    verdict = None

    try:
        vctx = ssl.create_default_context()
        collected = _one_handshake(host, port, vctx, timeout, sni=True)
        verdict = "chain-verified"
    except VERIFY_EXC as exc:
        if isinstance(exc, ValueError) and _looks_like_sni_refusal(exc):
            # Build rejects this host form as server_hostname (typical for
            # IP literals): retry chain-only verification without SNI; the
            # hostname match is done manually from SAN/CN either way.
            try:
                vctx2 = ssl.create_default_context()
                vctx2.check_hostname = False
                collected = _one_handshake(host, port, vctx2, timeout,
                                           sni=False)
                verdict = "chain-verified (chain-only; hostname matched " \
                          "manually)"
            except VERIFY_EXC as exc2:
                verdict = classify_verify_error(exc2)
        else:
            # Includes older builds that raise ValueError for certificate
            # verification failures; classify by message either way.
            verdict = classify_verify_error(exc)

    if collected is None:
        try:
            uctx = ssl._create_unverified_context()
            collected = _one_handshake(host, port, uctx, timeout, sni=True)
        except VERIFY_EXC as exc2:
            if isinstance(exc2, ValueError) and _looks_like_sni_refusal(exc2):
                try:
                    collected = _one_handshake(host, port, uctx, timeout,
                                               sni=False)
                except Exception as exc3:
                    data["error"] = ("verification failed (%s); unverified "
                                     "collect also failed: %s"
                                     % (verdict, exc3))
            else:
                data["error"] = ("verification failed (%s); unverified "
                                 "collect also failed: %s" % (verdict, exc2))

    data.update({
        "verify_verdict": verdict or "unknown",
        "version": collected.get("version") if collected else None,
        "cipher_name": collected.get("cipher_name") if collected else "?",
        "cipher_proto": collected.get("cipher_proto") if collected else "?",
        "cipher_bits": collected.get("cipher_bits") if collected else -1,
        "compression": collected.get("compression") if collected else None,
        "cert": collected.get("cert") if collected else {},
        "facts": collected.get("facts") if collected else {},
    })
    if data["error"] is not None:
        data["host_ok"], data["host_detail"] = False, "n/a"
        return data

    if data["cert"]:
        data["host_ok"], data["host_detail"] = match_hostname(
            host, data["cert"])
        if cert_self_signed(data["cert"]) and \
                data["verify_verdict"].startswith("chain-verified"):
            data["verify_verdict"] = "self-signed (issuer == subject)"
    else:
        data["host_ok"], data["host_detail"] = False, "no certificate"
    return data


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Scope-guarded TLS probe: negotiated version/cipher, "
        "cert subject/issuer/notAfter/signature algorithm/public-key type+"
        "size (hand-rolled DER walk), SAN hostname match, chain-verification "
        "verdict. Renegotiation/suite matrices: use openssl s_client / "
        "testssl.sh per references/tls-audit.md.",
    )
    ap.add_argument("--scope-file", default=os.environ.get("REDJOHN_SCOPE_FILE"),
                    help="Engagement scope JSON (default: REDJOHN_SCOPE_FILE)")
    ap.add_argument("--host", help="Target host[:port] (default port 443)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help="Socket timeout in seconds")
    ap.add_argument("--self-test", action="store_true",
                    help="Run offline self-tests (no network) and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.host or not args.scope_file:
        sys.stderr.write("error: --host and --scope-file are required "
                         "(or set REDJOHN_SCOPE_FILE)\n")
        return 1

    try:
        host, port = parse_hostport(args.host)
    except ValueError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 1

    # Guard resolves the host and validates it BEFORE any socket opens.
    if ":" in host:  # bare/bracketed IPv6 -> bracketed URL form
        target = "https://[%s]:%d" % (host, port)
    else:
        target = "https://%s:%d" % (host, port)
    require_in_scope(target, args.scope_file)

    sys.stderr.write("[tls] probing %s:%d (max two handshakes)\n"
                     % (host, port))
    data = probe(host, port, timeout=args.timeout)
    found = []
    if not data.get("error"):
        found = findings(data["version"], data["compression"],
                         data["verify_verdict"], data["facts"],
                         data["cert"], data["host_ok"])
    print(format_report(host, port, data, found))
    print("evidence: save this output as evidence/p2-tls-<host>-<seq>.txt "
          "plus the openssl transcript for any threshold finding; record "
          "tool version with the result.")
    if data.get("error"):
        return 1
    return 0


# ---------------------------------------------------------------------------
# Self-test: offline, no network. DNS monkeypatched; probe never runs.
# A live TLS fixture is NOT feasible in pure stdlib: generating an X.509
# certificate requires the openssl CLI or the cryptography package, both
# outside the stdlib-only script rules. Per the skill spec, the self-test
# therefore covers the guard, host[:port] parsing, DER decoding, hostname
# matching, verification classification and findings paths only.
# ---------------------------------------------------------------------------

def self_test():
    checks = 0

    def ok(label):
        nonlocal checks
        checks += 1
        print("[self-test] ok: %s" % label)

    import tempfile

    # --- test-local DER encoders to build a synthetic certificate ---
    def enc_len(n):
        if n < 0x80:
            return bytes([n])
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(body)]) + body

    def tlv(tag, content):
        return bytes([tag]) + enc_len(len(content)) + content

    def seq(*parts):
        return tlv(0x30, b"".join(parts))

    def enc_oid(dotted):
        nums = [int(x) for x in dotted.split(".")]
        body = bytearray([nums[0] * 40 + nums[1]])
        for n in nums[2:]:
            chunk = [n & 0x7F]
            n >>= 7
            while n:
                chunk.append((n & 0x7F) | 0x80)
                n >>= 7
            body.extend(reversed(chunk))
        return tlv(0x06, bytes(body))

    def enc_int(value):
        body = value.to_bytes((value.bit_length() + 8) // 8 or 1, "big")
        return tlv(0x02, body)

    def bitstring(content):
        return tlv(0x03, b"\x00" + content)

    def rdn(oid_text, value):
        # SET OF AttributeTypeAndValue (UTF8String value)
        return tlv(0x31, seq(enc_oid(oid_text) + tlv(0x0C, value.encode())))

    def build_cert(sig_oid, spki_alg_oid, spki_params, pub_payload):
        modulus, exponent = (1 << 2047) | 0xA5A5, 65537
        rsa_pub = seq(enc_int(modulus), enc_int(exponent))
        spki = seq(seq(enc_oid(spki_alg_oid) + spki_params),
                   bitstring(pub_payload(rsa_pub)))
        issuer = seq(rdn("2.5.4.3", "issuer.example"))
        subject = seq(rdn("2.5.4.3", "target.example.com"))
        validity = seq(tlv(0x17, b"270101000000Z"),     # UTCTime 2027
                       tlv(0x18, b"20280101000000Z"))   # GeneralizedTime 2028
        san_ext = seq(enc_oid("2.5.29.17") +
                      tlv(0x04, seq(tlv(0x82, b"target.example.com") +
                                    tlv(0x87, bytes([203, 0, 113, 10])))))
        extensions = tlv(0xA3, seq(san_ext))
        tbs = seq(
            tlv(0xA0, enc_int(2)),                 # [0] version v3
            enc_int(0x1234),                        # serial
            seq(enc_oid(sig_oid)),                  # signature (inner)
            issuer,
            validity,
            subject,
            spki,
            extensions,
        )
        return seq(tbs, seq(enc_oid(sig_oid)), bitstring(b"\x01" * 64))

    rsa_sha256 = build_cert("1.2.840.113549.1.1.11",
                            "1.2.840.113549.1.1.1", b"",
                            lambda rsa_pub: rsa_pub)
    facts = extract_cert_facts(rsa_sha256)
    assert facts["sig_alg"] == "sha256WithRSAEncryption", facts
    assert facts["sig_weak"] is False
    assert facts["key_type"] == "RSA" and facts["key_bits"] == 2048, facts
    ok("DER walk: sha256WithRSAEncryption + RSA 2048 bits extracted")

    rsa_sha1 = build_cert("1.2.840.113549.1.1.5",
                          "1.2.840.113549.1.1.1", b"",
                          lambda rsa_pub: rsa_pub)
    facts = extract_cert_facts(rsa_sha1)
    assert facts["sig_alg"] == "sha1WithRSAEncryption", facts
    assert facts["sig_weak"] is True
    ok("DER walk: SHA-1 signature flagged weak")

    p256 = enc_oid("1.2.840.10045.3.1.7")
    ec_cert = build_cert("1.2.840.10045.4.3.2", "1.2.840.10045.2.1", p256,
                         lambda _rsa: b"\x04" + b"\x41" * 64)
    facts = extract_cert_facts(ec_cert)
    assert facts["key_type"] == "EC" and facts["key_bits"] == 256, facts
    assert facts["key_detail"].startswith("prime256v1"), facts
    ok("DER walk: EC P-256 curve + bit size extracted")

    small_rsa = build_cert("1.2.840.113549.1.1.11",
                           "1.2.840.113549.1.1.1", b"",
                           lambda rsa_pub: seq(enc_int(1 << 1023 | 0x33),
                                               enc_int(65537)))
    facts = extract_cert_facts(small_rsa)
    assert facts["key_bits"] == 1024, facts
    ok("DER walk: 1024-bit RSA modulus size detected")

    try:
        extract_cert_facts(b"\x00\x01\x02")
        raised = False
    except ValueError:
        raised = True
    assert raised
    ok("malformed DER rejected with ValueError")

    # --- cert_from_der: names, validity (both time forms), SAN ---
    fields = cert_from_der(rsa_sha256)
    assert fields["subject"] == ((("commonName", "target.example.com"),),), \
        fields["subject"]
    assert fields["issuer"] == ((("commonName", "issuer.example"),),)
    assert fields["notBefore"] == "Jan 01 00:00:00 2027 GMT", fields
    assert fields["notAfter"] == "Jan 01 00:00:00 2028 GMT", fields
    assert fields["subjectAltName"] == (("DNS", "target.example.com"),
                                        ("IP Address", "203.0.113.10")), fields
    assert cert_self_signed(fields) is False
    ok("cert_from_der: subject/issuer/UTCTime+GeneralizedTime/SAN extracted")

    self_signed_fields = dict(fields)
    self_signed_fields["issuer"] = fields["subject"]
    assert cert_self_signed(self_signed_fields) is True
    ok("self-signed heuristic: issuer == subject")

    # --- host[:port] parsing ---
    assert parse_hostport("target.example.com") == ("target.example.com", 443)
    assert parse_hostport("target.example.com:8443") == \
        ("target.example.com", 8443)
    assert parse_hostport("[::1]:8443") == ("::1", 8443)
    assert parse_hostport("[2001:db8::1]") == ("2001:db8::1", 443)
    assert parse_hostport("::1") == ("::1", 443)
    ok("host[:port] parsing incl. IPv6 literal forms")

    for bad in ("https://example.com", "example.com:abc", "example.com:",
                ":443", "", "[::1", "[example.com]:443", "a:b:c"):
        try:
            parse_hostport(bad)
            raised = False
        except ValueError:
            raised = True
        assert raised, bad
    ok("bad host[:port] forms rejected")

    # --- hostname matching ---
    cert_san = {"subjectAltName": (("DNS", "target.example.com"),
                                   ("DNS", "*.wild.example"))}
    assert match_hostname("target.example.com", cert_san)[0] is True
    assert match_hostname("a.wild.example", cert_san)[0] is True
    assert match_hostname("a.b.wild.example", cert_san)[0] is False
    assert match_hostname("wild.example", cert_san)[0] is False
    assert match_hostname("other.example", cert_san)[0] is False
    ok("SAN matching: exact, single-label wildcard, non-match")

    cert_ip = {"subjectAltName": (("IP Address", "203.0.113.10"),)}
    assert match_hostname("203.0.113.10", cert_ip)[0] is True
    assert match_hostname("203.0.113.11", cert_ip)[0] is False
    ok("SAN IP address matching")

    cert_cn = {"subject": ((("commonName", "Target.Example.com."),),)}
    assert match_hostname("target.example.com", cert_cn)[0] is True
    assert match_hostname("other.example", cert_cn)[0] is False
    ok("CN fallback matching with case/trailing-dot normalization")

    # --- verification classification ---
    class FakeErr(Exception):
        pass
    assert classify_verify_error(
        FakeErr("certificate verify failed: self signed certificate")) == \
        "self-signed"
    assert classify_verify_error(
        FakeErr("certificate verify failed: unable to get local issuer "
                "certificate")) == "unknown-ca"
    assert classify_verify_error(
        FakeErr("certificate verify failed: certificate has expired")) == \
        "expired"
    assert classify_verify_error(
        FakeErr("hostname 'x' doesn't match either of ...")) == \
        "hostname-mismatch"
    assert classify_verify_error(FakeErr("something else")) == \
        "verify-failed"
    ok("verification error classification table")

    # --- findings thresholds ---
    good_facts = {"sig_alg": "sha256WithRSAEncryption", "sig_weak": False,
                  "key_type": "RSA", "key_bits": 2048, "key_detail": None}
    good_cert = {"notAfter": time.strftime("%b %d %H:%M:%S %Y GMT",
                                           time.gmtime(time.time() + 86400))}
    assert findings("TLSv1.3", None, "chain-verified", good_facts,
                    good_cert, True) == []
    ok("clean baseline produces no findings")

    tags = lambda fs: [t for _l, t, _m in fs]
    assert "tls-version" in tags(findings("TLSv1.1", None, "chain-verified",
                                          good_facts, good_cert, True))
    assert "tls-compression" in tags(findings("TLSv1.2", "zlib",
                                              "chain-verified", good_facts,
                                              good_cert, True))
    weak_facts = dict(good_facts, sig_alg="sha1WithRSAEncryption",
                      sig_weak=True, key_bits=1024)
    got = tags(findings("TLSv1.2", None, "chain-verified", weak_facts,
                        good_cert, True))
    assert "weak-signature" in got and "small-key" in got, got
    expired_cert = {"notAfter": "Jan  1 00:00:00 2000 GMT"}
    assert "cert-expired" in tags(findings("TLSv1.2", None, "chain-verified",
                                           good_facts, expired_cert, True))
    assert "hostname-mismatch" in tags(findings("TLSv1.2", None,
                                                "chain-verified", good_facts,
                                                good_cert, False))
    assert "chain-not-verifiable" in tags(findings("TLSv1.2", None,
                                                   "self-signed", good_facts,
                                                   good_cert, True))
    ok("findings thresholds: version/compression/SHA-1/small-key/expiry/"
       "hostname/chain")

    # --- canonical guard assertions (fake DNS, no network) ---
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *fn_args, **fn_kwargs):
        if host.endswith(".invalid"):
            raise socket.gaierror(-2, "fake NXDOMAIN for .invalid")
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

    loopback_scope = {"engagement": "selftest",
                      "allowed": [{"host": "localhost"},
                                  {"cidr": "127.0.0.0/8"},
                                  {"host": "127.0.0.1"}]}
    socket.getaddrinfo = fake_getaddrinfo
    try:
        res = host_allowed("https://example.com/", loopback_scope)
        assert res == (False, "not-in-scope"), res
        ok("guard refuses public host under localhost-only scope")

        res = host_allowed("http://10.0.0.5/", loopback_scope)
        assert res == (False, "not-in-scope"), res
        ok("guard refuses private IP without explicit CIDR entry")

        res = host_allowed("http://127.0.0.1:8443/x", loopback_scope)
        assert res[0] is True and res[1] in ("host", "cidr"), res
        ok("guard allows http://127.0.0.1:PORT when that host is listed")

        res = host_allowed("https://no-such-host.invalid/", loopback_scope)
        assert res == (False, "dns-unresolvable"), res
        ok("guard fails closed on unresolvable host (invalid TLD)")

        res = host_allowed("https://[2001:db8::1]:443/", loopback_scope)
        assert res == (False, "not-in-scope"), res
        ok("guard refuses IPv6 literal not in scope")

        # main() scope refusal BEFORE any socket: probe is monkeypatched
        # to fail loudly if it ever runs.
        def fake_probe(host, port, timeout=DEFAULT_TIMEOUT):
            raise AssertionError("probe() must not run on scope refusal")
        real_probe = probe
        globals()["probe"] = fake_probe
        try:
            with tempfile.TemporaryDirectory() as tmp:
                scope_path = os.path.join(tmp, "scope.json")
                with open(scope_path, "w", encoding="utf-8") as fh:
                    json.dump(loopback_scope, fh)
                code = None
                try:
                    main(["--scope-file", scope_path,
                          "--host", "example.com:443"])
                except SystemExit as exc:
                    code = exc.code
                assert code == 2, code
                ok("out-of-scope --host -> exit 2 and probe() never runs")

                code = main(["--scope-file", scope_path])
                assert code == 1
                ok("missing --host -> exit 1")

                code = main(["--scope-file", scope_path, "--host",
                             "https://example.com"])
                assert code == 1
                ok("scheme inside --host rejected at parse (exit 1)")
        finally:
            globals()["probe"] = real_probe
    finally:
        socket.getaddrinfo = real_getaddrinfo

    print("[self-test] tls_probe: all %d checks passed" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
