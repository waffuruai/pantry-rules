"""Translate betterleaks' rules into Pantry's YARA secret rules, with test cases betterleaks confirms.

    python3 -I tools/betterleaks.py            write rules/any/secret/ from vendor/betterleaks/betterleaks.toml
    python3 -I tools/betterleaks.py --check    translate into a temporary directory; fail on any difference

Each betterleaks rule becomes `rules/any/secret/Any.Secret.<Name>.yar`. Its regex is the string
`$secret`, and what YARA has no syntax for goes in meta:

| Meta | Meaning |
|---|---|
| `id` | betterleaks' rule id, which findings and `.gitleaksignore` fingerprints use |
| `keyword` (repeated) | the rule counts in a fragment only if one of these is in it, in any case |
| `confidence` | `high`, `medium` or `low`, as betterleaks rates the rule |
| `secret_group` | the capture group holding the secret (default: the first that matched) |
| `specificity` | betterleaks' tie-break between rules that find the same secret |
| `skip_entropy_le`, `skip_entropy_lt` | skipped when the secret's Shannon entropy is ≤ or < this |
| `skip_token_ratio_ge` | skipped when the secret's characters per cl100k token are ≥ this |
| `skip_token_efficiency` | skipped when betterleaks' readable-text heuristic says so |
| `skip_regex_<t>`, `skip_word_<t>` (repeated) | skipped when `<t>` matches the regex, or contains the word |
| `require_<t>` (repeated) | skipped unless `<t>` matches each of these |
| `component<N>`, `component<N>_within`, `component<N>_optional` | parts a multipart finding needs |
| `filter_expr` | a filter too involved for meta: betterleaks' Expr program, as written (also in the comment above the rule), which Pantry runs |

`<t>` is `secret`, `match` (the whole regex match), `line` (the match's line) or `path`. Meta
regexes are Go's RE2, as betterleaks wrote them; only `$secret` is folded into plain YARA. A
rule betterleaks never reports on its own (`skipReport`, a component of others) is a YARA
`private rule`. Live checks against providers (`validate`) aren't translated: see
https://github.com/waffuruai/pantry/issues/190.

The global prefilter (files never read) and filter (secrets never reported) are the private
rules in `Any.Secret.Prefilter.yar` and `Any.Secret.Filter.yar`. Go's inline flags become
explicit `[aA]` classes, so every file is plain YARA in the strict dialect.

Each rule gets a `.test.toml` with a positive case and a negative one, sampled from its regex.
betterleaks must report the positive under that rule alone, and report nothing for the negative.
Each case's text is stored reversed (`reversed_text`), so no file holds anything a secret scanner
(GitHub's push protection included) takes for a key; the catalogue shows each sample's shape.
Every pattern and test-data line also ends in a `gitleaks:allow` comment, which gitleaks,
betterleaks and Pantry honour: those lines are never secrets.
"""

import argparse
import filecmp
import hashlib
import json
import pathlib
import random
import re
import re._constants as C
import re._parser as P
import subprocess
import sys
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "vendor" / "betterleaks" / "betterleaks.toml"
OUT = ROOT / "rules" / "any" / "secret"
VERSION = "v1.10.0"
REFERENCE = f"https://github.com/betterleaks/betterleaks/blob/{VERSION}/config/betterleaks.toml"
VALIDATE_ISSUE = "https://github.com/waffuruai/pantry/issues/190"
OURS = {"Any.Secret.PantryFilter.yar"}  # written by hand, not by this translator
CATALOGUE = "README.md"

SEVERITY = {"high": ("high", 80), "medium": ("medium", 50), "low": ("low", 30)}
TARGETS = {("finding", "secret"): "secret", ("finding", "match"): "match",
           ("finding", "line"): "line", ("attributes", "path"): "path"}

ROUNDS = 120     # sampling rounds before a rule is left without cases
SPREAD = 8       # how far past its minimum a sampled repeat may run
GAP = "\n" * 12  # between candidates sampled in one betterleaks run
POSIX = {"alnum": "A-Za-z0-9", "alpha": "A-Za-z", "digit": "0-9", "upper": "A-Z", "lower": "a-z",
         "space": r" \t\r\n\f\v", "xdigit": "0-9A-Fa-f", "punct": r"!-\/:-@\[-`\{-~", "word": "A-Za-z0-9_"}
ALLOW = "gitleaks:allow"  # on every pattern and test-data line: secret scanners skip them
PATTERN_KEYS = ("skip_regex_", "skip_word_", "require_")
ESCAPES = {"z": "$", "A": "^"}  # Go's \z and \A; YARA has no multiline mode, so $ and ^ mean the same
CLASS_ESCAPES = "dDwWsSbBnrtfvx"


class Unsupported(ValueError):
    pass


# ---------------------------------------------------------------- regexes

def swap(c):
    return c.swapcase() if c.isascii() and c.isalpha() else None


def flip(ci, on, off):
    if "i" in off:
        return False
    return True if "i" in on else ci


def fold(src):
    """`src` (Go RE2) without inline flags: case-insensitive scopes become `[aA]` classes, `/` and
    literal braces are escaped, POSIX classes are spelled out. The result is YARA (strict
    dialect) and Python regex alike."""
    out, i, ci, stack, n = [], 0, False, [], len(src)
    while i < n:
        c = src[i]
        if c == "\\":
            e = src[i + 1]
            if e in ESCAPES:
                out.append(ESCAPES[e])
            elif ci and swap(e) and e not in CLASS_ESCAPES:
                out.append("[" + e + swap(e) + "]")
            else:
                out.append("\\" + e)
            i += 2
        elif c == "(":
            m = re.match(r"\(\?([a-zA-Z]*)(?:-([a-zA-Z]*))?\)", src[i:])
            if m:  # (?flags): the rest of this group
                ci = flip(ci, m.group(1), m.group(2) or "")
                i += len(m.group(0))
                continue
            stack.append(ci)
            m = re.match(r"\(\?([a-zA-Z]*)(?:-([a-zA-Z]*))?:", src[i:])
            if m:
                ci = flip(ci, m.group(1), m.group(2) or "")
                out.append("(?:")
                i += len(m.group(0))
                continue
            m = re.match(r"\(\?P?<\w+>", src[i:])
            if m:
                out.append("(")
                i += len(m.group(0))
                continue
            if src.startswith("(?", i):
                raise Unsupported(f"group syntax at {i} in {src!r}")
            out.append("(")
            i += 1
        elif c == ")":
            ci = stack.pop() if stack else ci
            out.append(")")
            i += 1
        elif c == "[":
            i = klass(src, i, ci, out)
        elif c == "{":
            m = re.match(r"\{(\d+)(,(\d*))?\}", src[i:])
            if m:
                out.append(m.group(0))
                i += len(m.group(0))
            else:
                out.append("\\{")
                i += 1
        elif c == "}":
            out.append("\\}")
            i += 1
        else:
            if ci and swap(c):
                out.append("[" + c + swap(c) + "]")
            elif c == "/":
                out.append("\\/")
            else:
                out.append(c)
            i += 1
    return "".join(out)


def klass(src, i, ci, out):
    """Copy the class at `src[i]` to `out`, folding letters when `ci`; return the index after it."""
    j = i + 1
    negate = src[j:j + 1] == "^"
    if negate:
        j += 1
    items, first = [], True
    while first or src[j] != "]":
        first = False
        if src.startswith("[:", j):
            k = src.index(":]", j)
            items.append(POSIX[src[j + 2:k]])
            j = k + 2
        elif src[j] == "\\":
            items.append(src[j:j + 2])
            j += 2
        elif src[j] in "/[{}":
            items.append("\\" + src[j])
            j += 1
        else:
            items.append(src[j])
            j += 1
    body = "".join(items)
    extra = []
    if ci:
        k = 0
        while k < len(body):
            if body[k] == "\\":
                if swap(body[k + 1]) and body[k + 1] not in CLASS_ESCAPES:
                    extra.append(swap(body[k + 1]))
                k += 2
            elif k + 2 < len(body) and body[k + 1] == "-" and swap(body[k]) and swap(body[k + 2]):
                extra.append(swap(body[k]) + "-" + swap(body[k + 2]))
                k += 3
            else:
                if swap(body[k]):
                    extra.append(swap(body[k]))
                k += 1
    # The swapped letters go first, so a trailing `-` stays literal.
    out.append("[" + ("^" if negate else "") + "".join(extra) + body + "]")
    return j + 1


# ---------------------------------------------------------------- filters (an Expr subset)

TOKEN = re.compile(r"""\s+|//[^\n]*|(?P<op>\|\||&&|<=|>=|==|!=|[!()\[\],<>])|(?P<num>\d+(?:\.\d+)?)
                       |(?P<raw>`[^`]*`)|(?P<str>"(?:\\.|[^"\\])*")|(?P<name>[A-Za-z_][\w.]*)""", re.X)


def tokens(src):
    out, i = [], 0
    while i < len(src):
        m = TOKEN.match(src, i)
        if not m:
            raise Unsupported(f"filter syntax at {i}")
        i = m.end()
        kind = m.lastgroup
        if kind == "raw":
            out.append(("str", m.group(kind)[1:-1]))
        elif kind == "str":
            out.append(("str", json.loads(m.group(kind))))
        elif kind == "num":
            out.append(("num", m.group(kind)))
        elif kind:
            out.append((kind, m.group(kind)))
    return out


class Parser:
    """`a || b`, `a && b`, `!a`, `(a)`, calls, and `call <op> number` comparisons."""

    def __init__(self, src):
        self.t, self.i = tokens(src), 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, value=None):
        tok = self.peek()
        if value is not None and tok[1] != value:
            raise Unsupported(f"expected {value!r}, got {tok[1]!r}")
        self.i += 1
        return tok

    def parse(self):
        e = self.disjunction()
        if self.i != len(self.t):
            raise Unsupported(f"trailing {self.peek()[1]!r}")
        return e

    def disjunction(self):
        terms = [self.conjunction()]
        while self.peek()[1] == "||":
            self.take()
            terms.append(self.conjunction())
        return terms[0] if len(terms) == 1 else ("or", terms)

    def conjunction(self):
        terms = [self.unary()]
        while self.peek()[1] == "&&":
            self.take()
            terms.append(self.unary())
        return terms[0] if len(terms) == 1 else ("and", terms)

    def unary(self):
        if self.peek()[1] == "!":
            self.take()
            return ("not", self.unary())
        return self.primary()

    def primary(self):
        kind, value = self.peek()
        if value == "(":
            self.take()
            e = self.disjunction()
            self.take(")")
            return e
        if kind != "name" or value == "let":
            raise Unsupported(f"unexpected {value!r}")
        self.take()
        self.take("(")
        args = []
        while self.peek()[1] != ")":
            args.append(self.arg())
            if self.peek()[1] == ",":
                self.take()
        self.take(")")
        call = ("call", value.removeprefix("filter."), args)
        if self.peek()[1] in ("<", "<=", ">", ">="):
            op = self.take()[1]
            return ("cmp", call, op, self.take()[1])
        return call

    def arg(self):
        kind, value = self.peek()
        if value == "[":
            self.take()
            items = []
            while self.peek()[1] != "]":
                items.append(self.take()[1])
                if self.peek()[1] == ",":
                    self.take()
            self.take("]")
            return ("list", items)
        if kind == "name" and value in ("finding", "attributes"):
            self.take()
            self.take("[")
            key = self.take()[1]
            self.take("]")
            if (value, key) not in TARGETS:
                raise Unsupported(f"target {value}[{key!r}]")
            return ("target", TARGETS[(value, key)])
        raise Unsupported(f"argument {value!r}")


def filter_meta(src):
    """The meta for a filter that is `||` of plain checks; Unsupported for anything else."""
    e = Parser(src).parse()
    meta = []
    for term in e[1] if e[0] == "or" else [e]:
        meta.append(term_meta(term))
    return meta


def term_meta(term):
    def target(call, want="secret"):
        args = call[2]
        if not args or args[0][0] != "target" or (want and args[0][1] != want):
            raise Unsupported(f"{call[1]} on {args[:1]}")
        return args[0][1]

    def patterns(call):
        if len(call[2]) != 2 or call[2][1][0] != "list":
            raise Unsupported(f"{call[1]} without a list")
        return call[2][1][1]

    if term[0] == "cmp" and term[1][1] in ("entropy", "tokenRatio"):
        target(term[1])
        key = {("entropy", "<="): "skip_entropy_le", ("entropy", "<"): "skip_entropy_lt",
               ("tokenRatio", ">="): "skip_token_ratio_ge"}.get((term[1][1], term[2]))
        if not key:
            raise Unsupported(f"{term[1][1]} {term[2]}")
        return [(key, meta_str(repr(float(term[3]))))]
    if term[0] == "call" and term[1] == "failsTokenEfficiency":
        target(term)
        return [("skip_token_efficiency", "true")]
    if term[0] == "call" and term[1] in ("matchesAny", "containsAny"):
        t = target(term, None)
        if term[1] == "matchesAny":
            return [(f"skip_regex_{t}", meta_str(p)) for p in patterns(term)]
        return [(f"skip_word_{t}", meta_str(w)) for w in patterns(term)]
    if term[0] == "not" and term[1][0] == "call" and term[1][1] == "matchesAny":
        t = target(term[1], None)
        alts = patterns(term[1])
        return [(f"require_{t}", meta_str(alts[0] if len(alts) == 1 else "|".join(f"(?:{a})" for a in alts)))]
    raise Unsupported(f"filter term {term[0]}")


# ---------------------------------------------------------------- rule files

def camel(rule_id):
    return "".join(p[:1].upper() + p[1:] for p in re.split(r"[^A-Za-z0-9]+", rule_id) if p)


def meta_str(s):
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 32 or ord(ch) > 126:
            out.extend(f"\\x{b:02x}" for b in ch.encode())
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def flat(meta):
    return [kv for item in meta for kv in (item if isinstance(item, list) else [item])]


def block(name, meta, strings, condition, private=False, notes=()):
    width = max(len(k) for k, _ in meta)
    lines = list(notes)
    lines += ["", f"{'private ' if private else ''}rule {name}", "{", "    meta:"]
    lines += [f"        {k.ljust(width)} = {v}" + (f"  // {ALLOW}" if k.startswith(PATTERN_KEYS) else "") for k, v in meta]
    if strings:
        lines += ["", "    strings:"] + [f"        {s}  // {ALLOW}" for s in strings]
    lines += ["", "    condition:", f"        {condition}", "}", ""]
    return "\n".join(lines)


def header(what):
    return [f"// betterleaks {VERSION}'s {what} (MIT: see NOTICE), translated by tools/betterleaks.py.",
            "// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own."]


def rule_text(r):
    name = camel(r["id"])
    severity, score = SEVERITY[r.get("confidence", "high")]
    meta = [("description", meta_str(r["description"])), ("author", '"betterleaks"'),
            ("reference", meta_str(REFERENCE)), ("license", '"MIT"'), ("os", '"any"'),
            ("category", '"secret"'), ("family", meta_str(name)), ("severity", meta_str(severity)),
            ("score", str(score)), ("id", meta_str(r["id"])),
            ("confidence", meta_str(r.get("confidence", "high")))]
    meta += [("keyword", meta_str(k)) for k in r.get("keywords", [])]
    if r.get("secretGroup"):
        meta.append(("secret_group", str(r["secretGroup"])))
    if "specificity" in r:
        meta.append(("specificity", str(r["specificity"])))
    for n, comp in enumerate(r.get("components", []), 1):
        meta.append((f"component{n}", meta_str(comp["id"])))
        if comp.get("within"):
            meta.append((f"component{n}_within", meta_str(comp["within"])))
        if comp.get("optional"):
            meta.append((f"component{n}_optional", "true"))
    notes = header(f"{r['id']} rule")
    if r.get("filter"):
        try:
            meta += flat(filter_meta(r["filter"]))
        except Unsupported:
            meta.append(("filter_expr", meta_str(r["filter"].strip())))
            notes += ["//", "// Its filter, a program Pantry runs as written (filter_expr):", "//"]
            notes += [("// " + line).rstrip() for line in r["filter"].strip().splitlines()]
    if r.get("validate"):
        notes.append(f"// betterleaks can check this secret with its provider; Pantry doesn't ({VALIDATE_ISSUE}).")
    strings, cond = [], []
    if r.get("regex"):
        dotall = "(?s)" in r["regex"]
        strings.append(f"$secret = /{fold(r['regex'].replace('(?s)', ''))}/{'s' if dotall else ''}")
        cond.append("$secret")
    if r.get("path"):
        cond.append(f"filepath matches /{fold(r['path'])}/")
    return name, block(f"Any_Secret_{name}", meta, strings, " and ".join(cond), private=r.get("skipReport", False),
                       notes=notes)


def global_text(kind, src):
    what = {"Prefilter": "files Pantry never reads for secrets",
            "Filter": "secrets Pantry never reports, whatever rule finds them"}[kind]
    meta = [("description", meta_str(f"betterleaks' global {kind.lower()}: {what}")), ("author", '"betterleaks"'),
            ("reference", meta_str(REFERENCE)), ("license", '"MIT"'), ("os", '"any"'), ("category", '"secret"')]
    meta += flat(filter_meta(src))
    notes = header(f"global {kind.lower()}") + ["// It never matches: the scanner reads its meta."]
    return block(f"Any_Secret_{kind}", meta, [], "false", private=True, notes=notes)


# ---------------------------------------------------------------- test cases

PRINTABLE = [chr(c) for c in range(33, 127)]
SECRETISH = [c for c in PRINTABLE if c.isalnum()]


def category(av):
    return {C.CATEGORY_DIGIT: "0123456789", C.CATEGORY_WORD: "".join(SECRETISH) + "_",
            C.CATEGORY_SPACE: " ", C.CATEGORY_NOT_DIGIT: "abcXYZ", C.CATEGORY_NOT_WORD: " ",
            C.CATEGORY_NOT_SPACE: "".join(SECRETISH)}[av]


def chars_of(items):
    allowed, negate = set(), False
    for op, av in items:
        if op is C.NEGATE:
            negate = True
        elif op is C.LITERAL:
            allowed.add(chr(av))
        elif op is C.RANGE:
            allowed.update(chr(c) for c in range(av[0], min(av[1], 126) + 1))
        elif op is C.CATEGORY:
            allowed.update(category(av))
        else:
            raise Unsupported(f"class item {op}")
    pool = [c for c in PRINTABLE + [" "] if (c in allowed) != negate]
    return pool or sorted(allowed)


def pick(rng, pool):
    alnum = [c for c in pool if c.isalnum()]
    return rng.choice(alnum if alnum and rng.random() < 0.9 else pool)


def sample(rng, parsed):
    out = []
    for op, av in parsed:
        if op is C.LITERAL:
            out.append(chr(av))
        elif op is C.NOT_LITERAL:
            out.append(pick(rng, [c for c in SECRETISH if c != chr(av)]))
        elif op is C.ANY:
            out.append(pick(rng, SECRETISH))
        elif op is C.IN:
            out.append(pick(rng, chars_of(av)))
        elif op is C.BRANCH:
            out.append(sample(rng, rng.choice(av[1])))
        elif op is C.SUBPATTERN:
            out.append(sample(rng, av[3]))
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT):
            lo, hi, sub = av
            hi = lo + SPREAD if hi is C.MAXREPEAT else min(hi, lo + SPREAD)
            out.extend(sample(rng, sub) for _ in range(rng.randint(lo, hi)))
        elif op is C.AT:
            pass
        elif op is C.CATEGORY:
            out.append(pick(rng, category(av)))
        else:
            raise Unsupported(f"regex op {op}")
    return "".join(out)


def betterleaks(text):
    """betterleaks' findings on `text`: (rule id, secret, start line) per finding."""
    with tempfile.TemporaryDirectory() as d:
        report = pathlib.Path(d) / "r.json"
        subprocess.run(["betterleaks", "stdin", "--no-banner", "--log-level", "error", "--exit-code", "0",
                        "--config", str(SOURCE), "--report-format", "json", "--report-path", str(report)],
                       input=text.encode(), capture_output=True, check=True)
        return [(f["RuleID"], f["Secret"], f["StartLine"]) for f in json.loads(report.read_text() or "[]")]


class Sampler:
    def __init__(self, rule, rules):
        self.rule = rule
        self.parts = [rule] + [rules[c["id"]] for c in rule.get("components", []) if not c.get("optional")]
        self.parsed = [P.parse(fold(r["regex"].replace("(?s)", "")), re.S if "(?s)" in r["regex"] else 0)
                       for r in self.parts]
        seed = int.from_bytes(hashlib.sha256(rule["id"].encode()).digest()[:8], "big")
        self.rng = random.Random(seed)

    def next(self):
        # Components first, each on its own line just above the secret.
        return "\n".join(sample(self.rng, p) for p in reversed(self.parsed)) + "\n"


def accepted(rule, text, found):
    """The case for `text` if betterleaks found this rule's secret alone in it, else None."""
    if [f[0] for f in found] != [rule["id"]]:
        return None
    secret = found[0][1]
    if not secret or text.count(secret) != 1 or "{secret}" in text:
        return None
    return secret


def cases(rules):
    """Each reportable rule's cases: a positive, and its negative when betterleaks agrees."""
    todo = {}
    for r in rules.values():
        if r.get("skipReport") or not r.get("regex") or r.get("path"):
            continue
        try:
            todo[r["id"]] = Sampler(r, rules)
        except Unsupported:
            continue
    found_cases = {}
    for _ in range(ROUNDS):
        if not todo:
            break
        batch, spans, line = [], [], 1
        for rid, s in todo.items():
            try:
                text = s.next()
            except Unsupported:
                continue
            n = text.count("\n")
            batch.append(text)
            spans.append((rid, text, line, line + n))
            line += n + GAP.count("\n")
        hits = betterleaks(GAP.join(batch))
        for rid, text, lo, hi in spans:
            inside = [f for f in hits if lo <= f[2] < hi]
            if accepted(rules[rid], text, inside) and accepted(rules[rid], text, betterleaks(text)):
                found_cases[rid] = text
                del todo[rid]
    out = {}
    for rid, text in found_cases.items():
        secret = accepted(rules[rid], text, betterleaks(text))
        name = f"Any_Secret_{camel(rid)}"
        cs = [{"name": f"{rid}: a secret", "text": text, "secret": secret, "rules": [name]}]
        negative = text.replace(secret, "x" * len(secret))
        if not betterleaks(negative):
            cs.append({"name": f"{rid}: the same text, the secret masked", "text": negative, "rules": []})
        out[rid] = cs
    return out


def toml_str(s):
    return json.dumps(s, ensure_ascii=True)


def cases_text(name, cs):
    lines = [f"# Cases for Any.Secret.{name}.yar, generated by tools/betterleaks.py and confirmed by betterleaks.",
             "# Each text is stored reversed (`reversed_text`): read backwards, it must match exactly the",
             "# rules in `rules` (none: it must match nothing)."]
    for c in cs:
        lines += ["", "[[case]]", f"name = {toml_str(c['name'])}", f"reversed_text = {toml_str(c['text'][::-1])}  # {ALLOW}"]
        lines.append("rules = [" + ", ".join(toml_str(x) for x in c["rules"]) + "]")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- main

def write(dest):
    cfg = tomllib.loads(SOURCE.read_text())
    rules = {r["id"]: r for r in cfg["rules"]}
    dest.mkdir(parents=True, exist_ok=True)
    names = {}
    for r in rules.values():
        name, text = rule_text(r)
        if name in names:
            raise SystemExit(f"{r['id']} and {names[name]} both translate to {name}")
        names[name] = r["id"]
        (dest / f"Any.Secret.{name}.yar").write_text(text)
    (dest / "Any.Secret.Prefilter.yar").write_text(global_text("Prefilter", cfg["prefilter"]))
    (dest / "Any.Secret.Filter.yar").write_text(global_text("Filter", cfg["filter"]))
    generated = cases(rules)
    for rid, cs in generated.items():
        (dest / f"Any.Secret.{camel(rid)}.test.toml").write_text(cases_text(camel(rid), cs))
    (dest / CATALOGUE).write_text(catalogue(rules, generated))
    reportable = [r["id"] for r in rules.values() if not r.get("skipReport")]
    return sorted(set(reportable) - set(generated))


def shape(secret, keep=4, width=80):
    """A sample's shape: its first `keep` characters, then each run of letters and digits as its
    length (`‹32›`), other characters as they are. It shows what a key looks like, and no scanner
    (GitHub's push protection matches a prefix and a run of letters and digits) takes it for one."""
    head, tail = secret[:keep], secret[keep:]
    out, run = [head], 0
    for c in tail:
        if c.isascii() and c.isalnum():
            run += 1
            continue
        if run:
            out.append(f"‹{run}›")
            run = 0
        out.append(c)
    if run:
        out.append(f"‹{run}›")
    s = "".join(out)
    return s if len(s) <= width else s[:width] + "…"


def cell(s):
    return s.replace("|", "\\|").replace("\n", " ").replace("`", "'")


def catalogue(rules, generated):
    """rules/any/secret/README.md: every secret rule, what it finds and a sample of it."""
    rows = []
    for r in sorted(rules.values(), key=lambda r: r["id"]):
        if r.get("skipReport"):
            continue
        name = camel(r["id"])
        cs = generated.get(r["id"])
        sample = f"<code>{cell(shape(cs[0]['secret']))}</code>" if cs else "no sample"
        parts = ", ".join(c["id"] for c in r.get("components", []) if not c.get("optional"))
        what = cell(r["description"]) + (f" Needs {parts} nearby." if parts else "")
        rows.append(f"| [{r['id']}](Any.Secret.{name}.yar) | {what} | {r.get('confidence', 'high')} | {sample} | <!-- {ALLOW} -->")
    with_cases = sum(1 for r in rules.values() if r["id"] in generated)
    reportable = sum(1 for r in rules.values() if not r.get("skipReport"))
    return "\n".join([
        "# Secret rules",
        "",
        f"Every secret Pantry looks for: betterleaks {VERSION}'s {reportable} reportable rules, translated by",
        "`tools/betterleaks.py` (`mise run gen` rewrites this file). Each sample is the shape of the secret in",
        "the rule's `.test.toml`: its first four characters, then each run of letters and digits as its length",
        "(`ghp_‹36›` is `ghp_` and 36 letters and digits).",
        "The full samples (random, confirmed by betterleaks, checked by Pantry's tests) are in the test files,",
        "stored reversed.",
        "",
        f"- {with_cases} rules have a sample. The rest need text the sampler can't make: a path, a document or a checksum.",
        "- Components (`private rule`s) are reported only as part of the rules that need them, and aren't listed.",
        "- Confidence is betterleaks': Pantry fails on `high` and asks for review on the others.",
        "",
        "| Rule | Finds | Confidence | Sample | |",
        "|---|---|---|---|---|",
        *rows,
        "",
    ])


def ours(directory):
    names = {f.name for f in directory.glob("Any.Secret.*") if f.name not in OURS}
    return names | ({CATALOGUE} if (directory / CATALOGUE).exists() else set())


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if rules/any/secret/ differs from a fresh translation")
    args = ap.parse_args()
    if not args.check:
        for name in ours(OUT) if OUT.exists() else ():  # the catalogue too
            (OUT / name).unlink()
        missing = write(OUT)
        print(f"wrote {OUT.relative_to(ROOT)}; rules without generated cases ({len(missing)}): {', '.join(missing)}")
        return 0
    with tempfile.TemporaryDirectory() as d:
        fresh = pathlib.Path(d)
        write(fresh)
        have, want = ours(OUT), ours(fresh)
        diff = sorted(have ^ want) + sorted(n for n in have & want if not filecmp.cmp(OUT / n, fresh / n, shallow=False))
        if diff:
            print("out of date (run `mise run gen`):", *diff, sep="\n  ")
            return 1
    print("rules/any/secret/ matches betterleaks", VERSION)
    return 0


if __name__ == "__main__":
    sys.exit(main())
