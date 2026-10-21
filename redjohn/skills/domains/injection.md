---
name: injection
description: Proof bar for SQL, NoSQL, XSS, SSTI, XXE, SSRF, and prompt injection. A reflection or an error string is not the bug.
---

# Injection

Pick the class from the sink you can see. One confirmed sink is worth more than a payload list sprayed at every parameter.

## Proof bar

**SQL.** A boolean or time difference you measured against a baseline, a union row that was not in the benign response, or an error that includes your marker and a query fragment. An ORM that parameterizes values can still concatenate identifiers and `ORDER BY`. Second-order injection shows up on a later request; store the marker and go find where it is read.

**NoSQL.** Operator injection (`{"$gt": ""}`) and JavaScript in a `$where` are the usual shape. A 500 with no behavior change is a lead, not a finding.

**XSS.** The context decides the payload: HTML body, attribute, URL, JavaScript string, or a template that escapes the wrong one. Reflected content that is encoded for the context it landed in is not XSS. Stored XSS is confirmed when a second principal's browser (or a raw response they would render) runs it. Self-XSS is low.

**SSTI.** `{{7*7}}` rendering `49`, or the engine's equivalent, is the proof. A reflected `{{7*7}}` is not. Confirm the engine before you reach for code execution, and hand execution to the `rce` proof ceiling.

**XXE.** An external entity that fetches a URL you observe, or a file you chose and can show in the response. Billion-laughs and entity expansion that only burns CPU are not the test.

**SSRF.** The server requested a host you control, or you read cloud metadata / an internal response through it. A URL parameter that the browser follows is an open redirect, not SSRF. IMDSv2 needs a token request; v1-style `GET` to the metadata IP failing does not mean the sink is safe.

**Prompt and tool injection.** The finding is the action the model took with authority it should not have had: a tool call, a fetched secret, a changed record. Jailbreak text in a chat window, with no effect on a tool or on another user's data, is not that finding.

## False friends

A WAF block is not a control until you have seen the query, template, or request never leave the app. Encode and structure around the block once; do not spend the mission on a bypass catalog. Record a clean parameter as `no_issue_found` with the evidence, and move to the next sink.
