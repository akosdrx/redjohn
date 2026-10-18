---
name: recon
description: Map the attack surface and broadcast what you find. Fingerprints and routes are useless while they sit in your transcript.
---

# Recon

Map what is in scope, then hand it to the swarm. A fingerprint or an admin route that you do not `swarm_broadcast` does not exist for anyone else.

Broadcast `fingerprint` with the product and version as soon as you have them, and `endpoint` for auth, upload, admin, and API routes. Call `lookup_cve` when a version is real (a banner you fetched, a file you read, a header the app sets), not when a path merely looks like a product.

## What to come back with

Hosts and ports that answered. Routes, methods, and parameters, including ones that only appear in JavaScript. Auth entry points and the roles you can distinguish. Where files, URLs, XML, and templates are accepted. A soft-404 baseline, so a wordlist hit is not "every path returns 200."

Read the app. Schemas (OpenAPI, GraphQL, WSDL, Postman) and bundled JS usually beat a blind wordlist. Fuzz a directory when the surface is still thin, with a small list and a matcher you calibrated against the baseline.

## Traps

A technology guess is not a version. Record how you learned the version, and say so in the broadcast. Tier guesses stay hints; they are not CVE findings.

Out-of-scope hosts, third-party SaaS you were not given, and the contents of a response that is just a framework default are observations. Note them. Do not turn them into a vulnerability report.

Subdomain takeover needs a dangling record you can show and a service that will still claim it. A CNAME to a vendor is not that.

Stop when the next specialist can work. Deep exploitation is their mission, and you say that by broadcasting the lead.
