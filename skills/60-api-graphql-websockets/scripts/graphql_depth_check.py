#!/usr/bin/env python3
# graphql_depth_check.py - OFFLINE GraphQL query depth/complexity scorer.
#
# No network access whatsoever. Parses a GraphQL document (queries,
# mutations, subscriptions, named/inline fragments, aliases, arguments,
# directives), resolves named fragments, and reports:
#   - max selection depth per operation and overall
#   - complexity = total field selections after fragment resolution
#     (each aliased field counts separately)
#   - field counts per level, alias count
#   - fragment cycles (reported, never expanded)
# Thresholds exceeded are reported with an RoE pointer (master methodology
# section 0: no resource-exhaustion techniques beyond written engagement
# authorization - score documents BEFORE sending any probe).
#
# Usage: --query 'query {...}' or --query-file doc.graphql
#        [--max-depth N] [--max-complexity N]
#
# Exit codes: 0 analysis completed (threshold report is output, not an
# error), 1 other errors (missing input, unreadable file, parse error).

import argparse
import os
import re
import sys

DEFAULT_MAX_DEPTH = 10
DEFAULT_MAX_COMPLEXITY = 1000

ROE_NOTE = ("RoE: master methodology section 0 - resource-exhaustion "
            "techniques require written engagement authorization; send at "
            "most one bounded probe per limit class and never sweep depths.")


class ParseError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

def tokenize(text):
    """Tokenize GraphQL into ('name', s) / ('punct', s) / ('str', s)."""
    tokens = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n,\ufeff":
            i += 1
        elif c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith('"""', i):
            j = i + 3
            while j < n:
                if text.startswith('\\"""', j):
                    j += 4
                    continue
                if text.startswith('"""', j):
                    break
                j += 1
            if j >= n:
                raise ParseError("unterminated block string at offset %d" % i)
            tokens.append(("str", text[i:j + 3]))
            i = j + 3
        elif c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    break
                j += 1
            if j >= n:
                raise ParseError("unterminated string at offset %d" % i)
            tokens.append(("str", text[i:j + 1]))
            i = j + 1
        elif c.isalnum() or c == "_":  # lenient: also covers int/float literals
            j = i
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            tokens.append(("name", text[i:j]))
            i = j
        elif text.startswith("...", i):
            tokens.append(("punct", "..."))
            i += 3
        elif c in "{}():@[]|$=!.&-":  # ! non-null, & iface, . digits, - sign
            tokens.append(("punct", c))
            i += 1
        else:
            raise ParseError("unexpected character %r at offset %d" % (c, i))
    return tokens


# ---------------------------------------------------------------------------
# Parser (GraphQL selection-set subset)
# ---------------------------------------------------------------------------

class Parser:
    def __init__(self, tokens):
        self.toks = tokens
        self.pos = 0

    def peek(self):
        if self.pos < len(self.toks):
            return self.toks[self.pos]
        return (None, None)

    def advance(self):
        tok = self.peek()
        self.pos += 1
        return tok

    def expect_punct(self, p):
        kind, val = self.advance()
        if kind != "punct" or val != p:
            raise ParseError("expected %r, got %r" % (p, val))

    def accept_punct(self, p):
        kind, val = self.peek()
        if kind == "punct" and val == p:
            self.pos += 1
            return True
        return False

    def skip_balanced(self, open_p, close_p):
        """Skip a balanced (...) or [...] group."""
        self.expect_punct(open_p)
        depth = 1
        while depth > 0:
            kind, val = self.advance()
            if kind is None:
                raise ParseError("unbalanced %r group" % open_p)
            if kind == "punct" and val == open_p:
                depth += 1
            elif kind == "punct" and val == close_p:
                depth -= 1

    def skip_directives(self):
        while self.accept_punct("@"):
            kind, val = self.advance()
            if kind != "name":
                raise ParseError("expected directive name after @")
            if self.peek() == ("punct", "("):
                self.skip_balanced("(", ")")

    def parse_selection_set(self):
        """Parse '{ ... }'. Returns list of selection nodes."""
        self.expect_punct("{")
        selections = []
        while True:
            kind, val = self.peek()
            if kind is None:
                raise ParseError("unterminated selection set")
            if kind == "punct" and val == "}":
                self.pos += 1
                return selections
            selections.append(self.parse_selection())

    def parse_selection(self):
        kind, val = self.peek()
        if kind == "punct" and val == "...":
            self.pos += 1
            kind2, val2 = self.peek()
            if kind2 == "name" and val2 == "on":
                self.pos += 1
                kind3, val3 = self.advance()
                if kind3 != "name":
                    raise ParseError("expected type name after 'on'")
                self.skip_directives()
                body = self.parse_selection_set()
                return ("inline", val3, body)
            if kind2 == "punct" and val2 == "{":
                self.skip_directives()
                return ("inline", None, self.parse_selection_set())
            if kind2 == "name":
                self.pos += 1
                self.skip_directives()
                return ("spread", val2)
            raise ParseError("dangling spread")
        if kind == "name":
            first = self.advance()[1]
            field_name, alias = first, None
            if self.accept_punct(":"):
                kind2, val2 = self.advance()
                if kind2 != "name":
                    raise ParseError("expected field name after alias")
                alias, field_name = first, val2
            if self.peek() == ("punct", "("):
                self.skip_balanced("(", ")")
            self.skip_directives()
            children = None
            if self.peek() == ("punct", "{"):
                children = self.parse_selection_set()
            return ("field", field_name, alias, children)
        raise ParseError("unexpected token %r in selection set" % (val,))


def parse_document(text):
    """Parse a GraphQL document.

    Returns (operations, fragments):
      operations: list of (kind, name, selections)
      fragments:  dict name -> (on_type, selections)
    """
    p = Parser(tokenize(text))
    operations = []
    fragments = {}
    while p.peek()[0] is not None:
        kind, val = p.peek()
        if kind == "name" and val in ("query", "mutation", "subscription"):
            p.pos += 1
            op_name = None
            if p.peek()[0] == "name":
                op_name = p.advance()[1]
            if p.peek() == ("punct", "("):
                p.skip_balanced("(", ")")
            p.skip_directives()
            selections = p.parse_selection_set()
            operations.append((val, op_name, selections))
        elif kind == "name" and val == "fragment":
            p.pos += 1
            kind2, frag_name = p.advance()
            if kind2 != "name":
                raise ParseError("expected fragment name")
            kind3, kw = p.advance()
            if kind3 != "name" or kw != "on":
                raise ParseError("expected 'on' in fragment definition")
            kind4, on_type = p.advance()
            if kind4 != "name":
                raise ParseError("expected type name after 'on'")
            p.skip_directives()
            selections = p.parse_selection_set()
            fragments[frag_name] = (on_type, selections)
        elif kind == "punct" and val == "{":
            selections = p.parse_selection_set()
            operations.append(("query", None, selections))
        else:
            raise ParseError("unexpected token %r at document level" % (val,))
    if not operations and not fragments:
        raise ParseError("empty document")
    return operations, fragments


# ---------------------------------------------------------------------------
# Analysis (pure)
# ---------------------------------------------------------------------------

def _summarize_selections(selections, fragments, frag_stack, memo):
    rel_levels = {}
    total_fields = 0
    aliases = 0
    cycles = set()
    used_stack = False
    for node in selections:
        if node[0] == "field":
            _, _field_name, alias, children = node
            rel_levels[0] = rel_levels.get(0, 0) + 1
            total_fields += 1
            if alias:
                aliases += 1
            if children:
                c_lvls, c_tot, c_al, c_cyc, c_stk = _summarize_selections(
                    children, fragments, frag_stack, memo
                )
                for r_lvl, cnt in c_lvls.items():
                    rel_levels[r_lvl + 1] = rel_levels.get(r_lvl + 1, 0) + cnt
                total_fields += c_tot
                aliases += c_al
                cycles.update(c_cyc)
                used_stack = used_stack or c_stk
        elif node[0] == "inline":
            c_lvls, c_tot, c_al, c_cyc, c_stk = _summarize_selections(
                node[2], fragments, frag_stack, memo
            )
            for r_lvl, cnt in c_lvls.items():
                rel_levels[r_lvl] = rel_levels.get(r_lvl, 0) + cnt
            total_fields += c_tot
            aliases += c_al
            cycles.update(c_cyc)
            used_stack = used_stack or c_stk
        elif node[0] == "spread":
            name = node[1]
            if name not in fragments:
                raise ParseError("unknown fragment '%s'" % name)
            if name in frag_stack:
                cycles.add(name)
                used_stack = True
                continue
            if name in memo:
                c_lvls, c_tot, c_al, c_cyc = memo[name]
                c_stk = False
            else:
                frag_stack.add(name)
                c_lvls, c_tot, c_al, c_cyc, c_stk = _summarize_selections(
                    fragments[name][1], fragments, frag_stack, memo
                )
                frag_stack.discard(name)
                if not c_stk:
                    memo[name] = (c_lvls, c_tot, c_al, c_cyc)
            for r_lvl, cnt in c_lvls.items():
                rel_levels[r_lvl] = rel_levels.get(r_lvl, 0) + cnt
            total_fields += c_tot
            aliases += c_al
            cycles.update(c_cyc)
            used_stack = used_stack or c_stk
        else:
            raise ParseError("bad node %r" % (node,))
    return rel_levels, total_fields, aliases, cycles, used_stack


def _walk(selections, level, fragments, frag_stack, acc, memo=None):
    if memo is None:
        memo = {}
    rel_levels, total_fields, aliases, cycles, _ = _summarize_selections(
        selections, fragments, frag_stack, memo
    )
    for r_lvl, cnt in rel_levels.items():
        acc["by_level"][level + r_lvl] = acc["by_level"].get(level + r_lvl, 0) + cnt
    acc["total_fields"] += total_fields
    acc["aliases"] += aliases
    acc["cycles"].update(cycles)


def analyze_document(text):
    """Analyze a document. Returns list of per-operation dicts."""
    operations, fragments = parse_document(text)
    results = []
    memo = {}
    for op_kind, op_name, selections in operations:
        acc = {"total_fields": 0, "aliases": 0, "by_level": {},
               "cycles": set()}
        _walk(selections, 1, fragments, set(), acc, memo)
        depth = max(acc["by_level"].keys(), default=0)
        results.append({
            "kind": op_kind,
            "name": op_name or "<anonymous>",
            "depth": depth,
            "complexity": acc["total_fields"],
            "by_level": dict(sorted(acc["by_level"].items())),
            "aliases": acc["aliases"],
            "cycles": sorted(acc["cycles"]),
        })
    return results


def render(results, max_depth, max_complexity):
    out = []
    exceeded = False
    for res in results:
        header = "%s %s" % (res["kind"], res["name"])
        out.append("%s: depth=%d complexity=%d aliases=%d"
                   % (header, res["depth"], res["complexity"],
                      res["aliases"]))
        levels = ", ".join("L%d:%d" % (lvl, cnt)
                           for lvl, cnt in res["by_level"].items())
        out.append("  fields per level: %s" % (levels or "(none)"))
        if res["cycles"]:
            out.append("  FRAGMENT CYCLE: %s (unbounded shape; a depth "
                       "limiter must reject the expanded form)"
                       % ", ".join(res["cycles"]))
            exceeded = True
        if res["depth"] > max_depth:
            out.append("  THRESHOLD EXCEEDED: depth %d > max-depth %d"
                       % (res["depth"], max_depth))
            exceeded = True
        if res["complexity"] > max_complexity:
            out.append("  THRESHOLD EXCEEDED: complexity %d > "
                       "max-complexity %d"
                       % (res["complexity"], max_complexity))
            exceeded = True
    if exceeded:
        out.append(ROE_NOTE)
    else:
        out.append("within thresholds (depth<=%d, complexity<=%d)"
                   % (max_depth, max_complexity))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="OFFLINE: score a GraphQL document's depth and "
        "complexity (aliases and fragment contents counted) before sending "
        "anything. No network access.",
    )
    ap.add_argument("--query", help="GraphQL document as a string")
    ap.add_argument("--query-file", help="Path to a .graphql document")
    ap.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH,
                    help="Depth threshold (default %d)" % DEFAULT_MAX_DEPTH)
    ap.add_argument("--max-complexity", type=int,
                    default=DEFAULT_MAX_COMPLEXITY,
                    help="Complexity threshold (default %d)"
                         % DEFAULT_MAX_COMPLEXITY)
    ap.add_argument("--self-test", action="store_true",
                    help="Run offline self-tests with fixture queries and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.query_file:
        try:
            with open(args.query_file, "r", encoding="utf-8",
                      errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            sys.stderr.write("error: cannot read %s: %s\n"
                             % (args.query_file, exc))
            return 1
    elif args.query:
        text = args.query
    else:
        sys.stderr.write("error: --query or --query-file is required\n")
        return 1

    try:
        results = analyze_document(text)
    except ParseError as exc:
        sys.stderr.write("error: GraphQL parse failure: %s\n" % exc)
        return 1

    print(render(results, args.max_depth, args.max_complexity))
    print("evidence: if a threshold probe is authorized, keep the exact "
          "document scored here plus its request/response pair as "
          "evidence/p6-api-graphql-<seq>.{req,resp}.txt with an RoE note.")
    return 0


# ---------------------------------------------------------------------------
# Self-test (offline, fixture documents only)
# ---------------------------------------------------------------------------

FIXTURE_SIMPLE = """
query Viewer {            # L1
  viewer {                # L1 field
    id                    # L2
    email                 # L2
    invoices(first: 5) {  # L2
      edges {             # L3
        node {            # L4
          id              # L5
        }
      }
    }
  }
}
"""

FIXTURE_DEEP = "query Deep {" + " a {" * 12 + " id " + " }" * 13

FIXTURE_ALIASES = """
query AliasProbe {
  a1: node(id: "4") { id secretField }
  a2: node(id: "4") { id secretField }
  a3: node(id: "4") { id secretField }
  a4: node(id: "4") { id secretField }
  a5: node(id: "4") { id secretField }
}
"""

FIXTURE_FRAGMENTS = """
query WithFrag { ...userFields viewer { profile { ...profileFields } } }
fragment userFields on Query { id email orders { id } }
fragment profileFields on Profile { displayName avatar }
"""

FIXTURE_CYCLE = """
query FragCycle { ...a }
fragment a on Query { ...b __typename }
fragment b on Query { ...a __typename }
"""

FIXTURE_INLINE = """
mutation M($id: ID!) {          # variables skipped
  updateProfile(input: {id: $id, role: "ADMIN"}) @validate {
    ok
    ... on ProfileError { message }
  }
}
"""


def self_test():
    checks = 0

    def ok(label):
        nonlocal checks
        checks += 1
        print("[self-test] ok: %s" % label)

    # simple: depth 5, complexity 7
    res = analyze_document(FIXTURE_SIMPLE)
    assert len(res) == 1, res
    r = res[0]
    assert r["depth"] == 5, r
    assert r["complexity"] == 7, r   # viewer,id,email,invoices,edges,node,id
    assert r["aliases"] == 0, r
    assert r["by_level"] == {1: 1, 2: 3, 3: 1, 4: 1, 5: 1}, r
    ok("simple query: depth/complexity/per-level counts correct")

    # deep: exceeds default threshold
    res = analyze_document(FIXTURE_DEEP)
    assert res[0]["depth"] == 13, res
    rendered = render(res, DEFAULT_MAX_DEPTH, DEFAULT_MAX_COMPLEXITY)
    assert "THRESHOLD EXCEEDED: depth 13 > max-depth 10" in rendered, rendered
    assert ROE_NOTE in rendered
    ok("deep query flagged with threshold line and RoE pointer")

    # aliases: each aliased field counts toward complexity
    res = analyze_document(FIXTURE_ALIASES)
    r = res[0]
    assert r["depth"] == 2, r
    assert r["complexity"] == 15, r   # 5 nodes + 5 x (id, secretField)
    assert r["aliases"] == 5, r
    assert r["by_level"] == {1: 5, 2: 10}, r
    ok("aliasing counted: 5 aliased nodes -> complexity 15")

    # named fragments resolved; spread fields land at the spread's level
    res = analyze_document(FIXTURE_FRAGMENTS)
    r = res[0]
    # L1: userFields spread -> id,email,orders (+viewer) = 4; orders.id = L2;
    # profile = L2; profileFields spread fields (displayName,avatar) = L3
    assert r["depth"] == 3, r
    assert r["complexity"] == 8, r
    assert r["by_level"] == {1: 4, 2: 2, 3: 2}, r
    ok("named fragments resolved into depth/complexity")

    # cycle: reported, not expanded; no infinite loop
    res = analyze_document(FIXTURE_CYCLE)
    r = res[0]
    assert r["cycles"] == ["a"], r
    assert r["complexity"] == 2, r     # two __typename fields
    rendered = render(res, DEFAULT_MAX_DEPTH, DEFAULT_MAX_COMPLEXITY)
    assert "FRAGMENT CYCLE: a" in rendered, rendered
    ok("fragment cycle detected and reported, not expanded")

    # mutation with variables, inline fragment, directive
    res = analyze_document(FIXTURE_INLINE)
    r = res[0]
    assert r["kind"] == "mutation", r
    assert r["depth"] == 2, r          # inline-fragment fields stay at L2
    assert r["complexity"] == 3, r     # updateProfile, ok, message
    assert r["by_level"] == {1: 1, 2: 2}, r
    ok("mutation/variables/directives/inline fragment parsed")

    # parse errors fail cleanly
    for bad in ("query {", "query { user ", "fragment F { }",
                "query { f("):
        try:
            analyze_document(bad)
            raised = False
        except ParseError:
            raised = True
        assert raised, bad
    ok("malformed documents raise ParseError")

    # anonymous shorthand operation
    res = analyze_document("{ status }")
    assert res[0]["name"] == "<anonymous>" and res[0]["complexity"] == 1, res
    ok("anonymous shorthand query parsed")

    # block strings and fragment DAG memoization
    res = analyze_document('mutation { post(body: """hello "world" \\""" ok""") { id } }')
    assert res[0]["depth"] == 2 and res[0]["complexity"] == 2, res
    dag_lines = ["query Dag { ...f0 }"]
    for idx in range(25):
        dag_lines.append("fragment f%d on Query { ...f%d ...f%d }" % (idx, idx + 1, idx + 1))
    dag_lines.append("fragment f25 on Query { id }")
    res = analyze_document("\n".join(dag_lines))
    assert res[0]["complexity"] == (1 << 25), res
    ok("block strings and 25-level fragment DAG evaluated in O(N)")

    print("[self-test] graphql_depth_check: all %d checks passed" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
