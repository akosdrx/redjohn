---
name: ssti_and_expression_rce
description: Non-Destructive Template & Expression Evaluation Verification (P1.5 /
  P5) (from rce_fast_path_verification specialist reference library)
---

# Non-Destructive Template & Expression Evaluation Verification (P1.5 / P5)

Reference guide for distinguishing true Server-Side Template Injection (SSTI)
and Expression Language (EL) evaluation from literal reflection or client-side
template rendering. All verification under `45-rce-exploitation` is strictly
non-destructive and stops at evaluation proof (D2).

---

## 1. Two-Probe Differential Verification Protocol (D2)

Never claim template or expression evaluation from a single reflected string or
an HTTP 500 status code alone. Every candidate sink requires two paired
requests recorded in the engagement workspace:

1. **Negative Control (Inert Baseline):**
   - Supply an inert alphanumeric canary with matching delimiters removed or
     escaped (e.g., `rj-ctrl-7391`).
   - Record status code, response headers, and body hash (`baseline.req.txt` /
     `baseline.resp.txt`).
2. **Benign Evaluation Check (Computed Canary):**
   - Supply a side-effect-free arithmetic or string-concatenation expression
     native to the suspected template family, paired with a static prefix/suffix
     tag (`rj-eval-<expr>`).
   - **Verified (D2)** only if the response contains the *computed* output
     (and *not* the unrendered expression text alone) across two independent
     runs, while the negative control does not.

---

## 2. Engine Identification Matrix (Safe Benign Indicators)

Use the engine family already fingerprinted in `10` or `15` to choose a single
family-appropriate benign check rather than spraying polyglots across every
parameter:

| Stack / Framework | Template / Expression Engine | Delimiter Family | Benign Verification Signal | CWE |
|---|---|---|---|---|
| PHP (Shopware, Craft, Symfony) | Twig | `{{ ... }}` | Computed integer/string filter output vs literal `{{` reflection | CWE-1336 |
| PHP (PrestaShop, legacy CMS) | Smarty | `{ ... }` | Evaluated mathematical/variable tag output in rendered HTML/email preview | CWE-1336 |
| PHP (Laravel, Statamic) | Blade | `{{ ... }}` / `@` | Unescaped directive rendering in dynamic view strings (`Blade::render`) | CWE-1336 |
| Python (Flask, Django, FastAPI) | Jinja2 / Django | `{{ ... }}` | Evaluated arithmetic/filter expression in dynamic template string | CWE-1336 |
| Java (Spring Boot, MVC) | Thymeleaf / SpEL | `${ ... }` / `*{ ... }` | View-name or fragment expression evaluation differential | CWE-917 |
| Java (Freemarker, Velocity) | FreeMarker / Velocity | `${ ... }` / `#set` | Built-in string/number formatting evaluation in preview/template endpoints | CWE-1336 |
| Java (Struts / legacy web) | OGNL | `%{ ... }` | Evaluated arithmetic attribute value in tag/action response | CWE-917 |
| Node.js (Express, Next, Nunjucks) | EJS / Pug / Nunjucks / Handlebars | `<%= ... %>` / `{{ ... }}` | Computed expression output in server-rendered HTML fragment | CWE-1336 |

---

## 3. High-Probability Sinks in E-Commerce & CMS Targets

Prioritize these endpoints when `15-cms-ecommerce-rce` or `10-recon-endpoint-mapping`
identifies a CMS or storefront:

- **Email & Invoice Preview Endpoints:** Order confirmation previews, PDF
  invoice renderers, and transactional email template testers.
- **Dynamic CMS Blocks & Theme Filters:** Custom CMS page preview endpoints,
  dynamic block renderers, and search/sort filter expressions.
- **Webhook & Rule Evaluators:** Promotion/cart price rule condition preview
  endpoints and custom export formatters.

---

## 4. False-Positive Rejection Rules

- **Client-Side Angular/Vue/React Rendering:** If the raw HTTP response body
  from `curl` or `rce_verify.py` still contains the literal `{{ ... }}` syntax
  uncomputed, the expression was not evaluated server-side. Reclassify as
  client-side template reflection (`55-client-side-attacks`), never `45`.
- **Generic 500 Internal Server Error:** A syntax error from malformed brackets
  proves only an unvalidated parser boundary (Information/Low or D1 candidate),
  never `Verified` RCE/SSTI.
- **No OS Process Spawning Needed for D2:** Once deterministic server-side
  expression evaluation is proven via computed output + negative control on a
  documented engine sink, stop and hand off to `95-finding-verifier` and `90`.

