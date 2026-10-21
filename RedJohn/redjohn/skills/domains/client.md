---
name: client
description: CSRF, open redirects, postMessage, and browser-state traps. A missing header or a 30x to another host is not yet the bug.
---

# Client

Confirm the victim's browser, or the response that browser would render. Your own session doing the action is not CSRF.

## CSRF

The action has to change state, and a third-party page has to be able to trigger it with the victim's cookies. A SameSite cookie, a checked custom header, or a token bound to the session defeats it. Content-Type `application/json` with a strict parser often defeats a simple form, until you find a content-type the parser also accepts. Login CSRF and logout CSRF matter when you can show the victim landing in an attacker-controlled account or a session the attacker then rides.

## Open redirect

A 302 to an external host is a low finding on its own. It becomes part of a real bug when an OAuth `redirect_uri`, a password-reset link, or a token in the URL is delivered to a host you control. Show that delivery. A parameter named `next` that only accepts relative paths is the control; say so and rule it out.

## postMessage and frames

The bug is a handler that trusts `event.data` without checking `event.origin`, or that sends a secret with `targetOrigin: "*"`. Trace what the handler does with the data: a DOM write is XSS, a navigation or a token reply is the impact. Clickjacking on a sensitive action needs a frameable page and an action the victim can be tricked into; a missing `X-Frame-Options` on a marketing page is informational.

## Browser state

Service-worker scope wider than the app, a cache that stores an authenticated response and replays it, and CORS that reflects an arbitrary `Origin` with credentials are the cases worth a report. CORS that reflects the origin without credentials, on a response with no sensitive data, is not.

Prototype pollution is a finding when you show it changing a property the server or the page uses for a security decision. A polluted `__proto__` in a JSON body that nothing reads is a lead.
