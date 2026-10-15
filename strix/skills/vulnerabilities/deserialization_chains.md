---
name: deserialization_chains
description: Deserialization chains (CWE-502) (from rce_fast_path_verification specialist
  reference library)
---

# Deserialization chains (CWE-502)

Magic-byte table, per-language chain summaries, canary gadget examples, and
the delivery vector checklist. Gadget generation happens offline with named
tools; the command slot is always a benign proof (`id`, canary echo).

## 1. Format fingerprint table

| Runtime | Raw marker | Base64 marker | Where commonly found |
|---|---|---|---|
| Java | `aced 0005` stream header | `rO0AB` prefix | remember-me cookies, HTTP session blobs, RMI/T3, JMS messages, cache files |
| PHP | `O:<N>:"Class":<N>:{...}`, `a:<N>:{...}`, `R:n` references | often plain in cookies/params | session handlers, custom "object" cookies |
| Python pickle | protocol markers `\x80\x02` .. `\x80\x05`, opcodes `cos\nsystem\n` / `__reduce__` shapes | `gAJ` (proto 2), `gAN` (3), `gASV` (4), `gAWV` (5) prefixes | Django/Flask signed cookies (`itsdangerous` base64 payloads), Celery/Redis values, cache entries |
| .NET | `00 01 00 00 00 ff ff ff ff` (NRBF header) | `AAEAAAD/////` prefix | `__VIEWSTATE` (when not MAC-protected), `LosFormatter` blobs, remoting |
| Ruby Marshal | `\x04\x08` version + `o:<Class>` | base64 `BAhO...` (`\x04\x08o:`) | Rails cookie store (legacy), cache |
| Node | `_$$ND_FUNC$$_` marker (`node-serialize`) | base64 in tokens | custom auth tokens, session files |

Fingerprinting steps: URL-decode, then base64-decode when it round-trips, then
hex-dump the first bytes. Record the runtime + library version (session
cookie names, framework banners from `10`/`70`) before choosing a gadget.

## 2. Per-language chain summaries

### Java
- Entry: any code path calling `ObjectInputStream.readObject()` on the blob.
- Chains: CommonsCollections (multiple), CommonsBeanutils, Spring, Hibernate,
  Jackson polymorphic typing (`@class`), JRE-only chains (e.g. via
  `javax.naming`).
- Generate offline: `java -jar ysoserial.jar CommonsCollections5 'echo
  rj-pt-<engagement>-<nonce>' > payload.bin` — pick the gadget matching the
  fingerprinted library version from `70-exploit-intel`.
- Delivery: replace the blob in the cookie/field; keep the transport encoding
  (base64/hex) the application used.

### PHP
- Entry: `unserialize()` on user input; POP gadget chains depend on the
  application's classes (source code) or framework (Laravel/Monolog gadgets).
- Generate offline: `./phpggc Laravel/RCE1 'echo rj-pt-<engagement>-<nonce>'`
  (base64 wrapper when the transport needs it).
- Phar deserialization: `phar://` stream triggers metadata `__destruct` —
  needs a reachable `phar://` consumer; treat as upload-chain crossover.

### Python
- Entry: `pickle.loads()` / `yaml.load()` (unsafe Loader) on user bytes.
- Canary gadget (canonical `__reduce__` form):

```python
import pickle, base64
class Canary:
    def __reduce__(self):
        return (print, ("rj-pt-<engagement>-<nonce>",))
print(base64.b64encode(pickle.dumps(Canary())))
```

- Signed-cookie stacks (itsdangerous) only deserialize after signature checks
  — finding a signing-key leak (`50-config-baseline`) is part of the chain.

### .NET
- Entry: `BinaryFormatter`/`ObjectStateFormatter`/`LosFormatter` on input;
  `__VIEWSTATE` without MAC/validation or with a leaked `machineKey`.
- Generate offline: `ysoserial.net -f BinaryFormatter -g ViewState -c "id"`.
- TypeConfuseDelegate / TextFormattingRunProperties are the classic gadgets;
  match .NET version from headers.

### Ruby / Node
- Ruby Marshal chains (erb/ERB, gem-dependent); Node: `node-serialize`
  IIFE-in-string (`{"rce":"_$$ND_FUNC$$_function(){require('child_process')
  .exec('id')}()"}`) — canonical textbook form, command slot stays benign.

## 3. Delivery vector checklist

- Cookie values (remember-me, session, "user" blobs) — keep original encoding
  and separators; watch `Set-Cookie` shapes first.
- Hidden form fields (`<input type=hidden name=... value=blob>`).
- Custom headers (`X-Auth-User`, `X-Serialized-Object`).
- JSON bodies where a base64 string field round-trips through pickle/java.
- Uploaded files consumed by a loader (import/export features).
- Cache values (Redis/Memcached keys observed via SSRF from `40`).

For each: send an unmodified re-serialization first (mutation-free round-trip
check) to prove the endpoint really deserializes, then the canary gadget.

## 4. Safe verification

- Gadget command = `echo rj-pt-<engagement>-<nonce>` (or `id`).
- In-band: canary appears in the response; keep the pair.
- Blind: DNS-safe `ping -c 1 -W 1 <canary-domain>` — one packet, bounded
  wait, verified on the `20` OOB listener. No other network commands.
- Never: reverse shells, downloaders, sleep loops, file writes beyond
  operator-approved canary files.
- If the blob is MAC/signed and the key is unknown, the finding is
  "unsigned/pickle-capable format" with its exact limits — no execution claim.

## 5. Evidence requirements

- Fingerprint proof (hex dump excerpt + where the blob was found).
- Round-trip re-serialization request/response (proves deserialization).
- Canary gadget request/response (or OOB listener log excerpt).
- Generation command verbatim (tool + gadget + version match note).
- Both D2 runs + cleanup confirmation (no artifacts created by this class
  beyond requests, unless a canary file was authorized — then its deletion).

