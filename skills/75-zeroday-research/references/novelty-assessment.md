# Novelty assessment

Search-source checklist, downgrade rules, and the documentation format that
makes "no public record" an evidence-backed statement instead of a feeling.

## 1. Search-source checklist (in order; record every step)

| # | Source | Query shape | What counts as a hit |
|---|---|---|---|
| 1 | NVD / CVE search | component name + version + bug-class keywords (`struts fileupload ogln` style) | any CVE whose description matches the surface |
| 2 | Vendor advisory / PSIRT + release changelog | component + "security" | advisory, security note, or a marked security fix |
| 3 | GitHub Advisory Database (GHSA) | package name | any GHSA for the package |
| 4 | searchsploit (local, offline) | `searchsploit <component>`, `--id <CVE>` | exploit rows naming the component |
| 5 | nuclei template corpus (local) | grep template ids/descriptions for component + CVE | a template implying known vuln coverage |
| 6 | Upstream issue tracker (GitHub Issues/Jira/redmine) | component + crash/exception keywords, error strings from your probe | a filed issue describing the same behavior |
| 7 | Mailing lists: oss-security, fulldisclosure archives | component name | any report/writeup |
| 8 | General web / writeup search | component + bug-class + "vulnerability" | blog posts, conference talks, exploit writeups |
| 9 | CISA KEV catalog | component / CVE | listed CVE (also supports E:A in CVSS) |

Also re-check the exact ERROR STRINGS your probe produced — error text is
the highest-yield search key for niche software (someone else hit it first
and pasted it into a tracker).

## 2. Downgrade rules

- Public writeup OR advisory OR CVE exists -> **not a zero-day**. Hand back
  to `70-exploit-intel` as an n-day: correlate, classify, verify in-scope;
  attach this trail.
- Public PoC exists (even without a writeup) -> not novel; treat as n-day
  with exploit-availability evidence.
- **Silent fix** (patch landed without advisory/CVE) -> the vulnerability
  is undisclosed-but-known-to-the-vendor. Report as "n-day rediscovered
  via patch diffing (silent fix, no advisory as of <date>)" — never as
  novel. Re-check for an advisory before delivery; vendors often publish
  after the fact.
- Same bug class in a DIFFERENT component (e.g. the CVE is for the library
  but your finding is in the app's custom wrapper) -> not a downgrade;
  document the distinction explicitly so the report cannot be read as a
  duplicate.
- Nothing found anywhere: "potentially novel" — a negative-evidence claim
  with a freshness bound, never "confirmed zero-day" (you cannot prove the
  absence of private knowledge).

## 3. Documentation format (the search trail is evidence)

Save as `evidence/p8-novelty-<component>.md`:

```text
novelty-trail | component=ExampleWidget | version=2.3.0 | surface=custom DSL parser
searched=2026-10-12 | by=<operator/agent run id>

| # | source                    | query                              | result | relevant hits |
|---|---------------------------|------------------------------------|--------|---------------|
| 1 | NVD                       | "ExampleWidget" parser injection   | 0      | -             |
| 2 | vendor PSIRT + CHANGELOG  | security section 2.3.0..2.3.1      | 1      | silent fix candidate (commit 4f2a9c1) |
| 3 | GHSA                      | example-widget                     | 0      | -             |
| 4 | searchsploit              | ExampleWidget                      | 0      | -             |
| 5 | nuclei corpus             | grep examplewidget                 | 0      | -             |
| 6 | upstream issues           | "ParseException" depth             | 0      | -             |
| 7 | oss-security archive      | ExampleWidget                      | 0      | -             |
| 8 | web search                | ExampleWidget parser vulnerability | 0      | -             |
| 9 | CISA KEV                  | -                                  | 0      | -             |

conclusion: silent-fix candidate only; no advisory/CVE/writeup found as of
2026-10-12. Report as n-day rediscovered via patch diffing; re-run this
trail before report delivery.
```

Rules: dates on every row; error-string queries recorded verbatim; the
conclusion uses the permitted phrasing only ("no public advisory, PoC, or
writeup found across sources 1-9 as of <date>"); the trail is re-run before
report delivery and both runs are kept.
