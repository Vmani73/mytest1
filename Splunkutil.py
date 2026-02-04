"""
splunk_evidence_engine.py  (single-file production blueprint)

GOAL
- Generate compact, rich evidence.json from Splunk for a perf test window (hours long).
- Works across apps with inconsistent logging by doing:
  (1) discovery (general + error-focused)
  (2) dynamic field mapping
  (3) normalized evidence queries
  (4) bounded samples + redaction
- K8s safe: bounded outputs, concurrency limits, timeouts, retries, circuit breaker.

OUTPUT
- One JSON file: evidence.json
  Contains:
    - metadata
    - discovery summary (embedded)
    - field_map used
    - evidence results per query (tables + key highlights)
    - regression deltas (baseline optional)
    - bounded redacted samples

DEPENDENCIES
- python >=3.10
- aiohttp (recommended for async HTTP)

If you cannot install aiohttp, you can adapt to requests + threads, but asyncio is cleaner.

NOTE
- You must know: Splunk base_url, token, and have permission for /services/search/jobs/export
- Provide earliest/latest in Splunk format: e.g. "-15h" or "2026-02-04T10:00:00"
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    import aiohttp
except ImportError:
    aiohttp = None


# ---------------------------
# Strict production defaults
# ---------------------------

DEFAULT_MAX_CONCURRENCY = 6            # protect Splunk + your pod
DEFAULT_QUERY_TIMEOUT_S = 90           # each query max wall time
DEFAULT_TOTAL_TIMEOUT_S = 20 * 60      # whole run max wall time
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF_BASE_S = 1.5

DEFAULT_SAMPLE_N_GENERAL = 200
DEFAULT_SAMPLE_N_ERROR = 200

DEFAULT_TOPN_ERRORS = 100
DEFAULT_TOPN_ENDPOINTS = 100
DEFAULT_TOPN_HOSTS = 50

DEFAULT_BOUNDED_SAMPLES = 200          # max sample rows total
DEFAULT_TIMECHART_POINTS_SOFT = 2000   # if too many, we increase span

DEFAULT_MAX_ROWS_PER_QUERY = 50_000    # hard cap any query results returned
DEFAULT_MAX_BYTES_PER_QUERY = 15 * 1024 * 1024  # 15MB cap on parsed results per query (safety)

# Circuit breaker
CB_FAIL_THRESHOLD = 4
CB_OPEN_COOLDOWN_S = 60


# ---------------------------
# Canonical fields & candidates
# Extend over time. This is maintainable and scalable.
# ---------------------------

DEFAULT_CANDIDATES: Dict[str, List[str]] = {
    "http_status": ["status", "http_status", "httpStatus", "status_code", "statusCode", "response_status", "resp_status"],
    "dur_ms": ["duration_ms", "elapsed_ms", "latency_ms", "response_time_ms", "responseTimeMs", "duration", "elapsed", "latency"],
    "api": ["uri_path", "path", "endpoint", "route", "uri", "url_path", "request_path", "resource", "operation"],
    "method": ["method", "http_method", "httpMethod", "verb"],
    "service": ["service", "app", "application", "component", "svc", "service_name", "serviceName"],
    "pod": ["pod", "pod_name", "k8s.pod_name", "kubernetes.pod_name"],
    "host": ["host", "hostname", "k8s.node_name", "kubernetes.node_name"],
    "trace_id": ["trace_id", "traceId", "x_b3_traceid", "b3_traceid"],
    "span_id": ["span_id", "spanId", "x_b3_spanid", "b3_spanid"],
    "request_id": ["request_id", "requestId", "req_id", "correlation_id", "correlationId"],
    "level": ["level", "log_level", "logLevel", "severity"],
    "message": ["message", "msg", "log", "event", "message.body", "log_message"],
}


# ---------------------------
# PII redaction (strict baseline)
# You MUST tune patterns for your org.
# ---------------------------

RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_UUID = re.compile(r"\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\b")
RE_LONG_NUM = re.compile(r"\b\d{12,19}\b")  # possible card/account; high false positives, adjust if needed
RE_TOKENISH = re.compile(r"(?i)\b(bearer|token|apikey|api_key|authorization)\b[\"'=: ]+([A-Za-z0-9\-_\.=]{12,})")

def redact_text(s: str) -> str:
    if not s:
        return s
    s = RE_EMAIL.sub("<redacted_email>", s)
    s = RE_IP.sub("<redacted_ip>", s)
    s = RE_UUID.sub("<redacted_uuid>", s)
    s = RE_LONG_NUM.sub("<redacted_number>", s)
    s = RE_TOKENISH.sub(lambda m: f"{m.group(1)}=<redacted_secret>", s)
    return s


# ---------------------------
# Utility
# ---------------------------

def now_ms() -> int:
    return int(time.time() * 1000)

def clamp_list(rows: List[Dict[str, Any]], max_rows: int) -> List[Dict[str, Any]]:
    if len(rows) <= max_rows:
        return rows
    return rows[:max_rows]

def estimate_json_bytes(obj: Any) -> int:
    try:
        return len(json.dumps(obj, default=str).encode("utf-8"))
    except Exception:
        return 0

def choose_span(earliest: str, latest: str) -> str:
    """
    Without parsing absolute timestamps (can be many formats), we choose a conservative default.
    You can replace with real duration parse if your inputs are epoch or ISO.
    """
    # Use 5m as safe default for very long windows; 1m for smaller windows.
    # If you pass earliest=-15h style, you can detect hours.
    m = re.match(r"^-(\d+)(h|m|d)$", str(earliest).strip())
    if m:
        n = int(m.group(1))
        unit = m.group(2)
        if unit == "m" and n <= 360:
            return "1m"
        if unit == "h" and n <= 6:
            return "1m"
        if unit == "h" and n <= 24:
            return "5m"
        if unit == "d":
            return "15m"
    return "5m"


# ---------------------------
# Circuit Breaker
# ---------------------------

@dataclass
class CircuitBreaker:
    fail_count: int = 0
    open_until: float = 0.0

    def allow(self) -> bool:
        return time.time() >= self.open_until

    def record_success(self) -> None:
        self.fail_count = 0
        self.open_until = 0.0

    def record_failure(self) -> None:
        self.fail_count += 1
        if self.fail_count >= CB_FAIL_THRESHOLD:
            self.open_until = time.time() + CB_OPEN_COOLDOWN_S


# ---------------------------
# Splunk client (async REST export)
# ---------------------------

@dataclass
class SplunkConfig:
    base_url: str          # e.g. https://splunk.company.com:8089
    token: str             # Splunk token
    verify_ssl: bool = True
    proxies: Optional[Dict[str, str]] = None
    app_name: str = "search"  # Splunk app context in URL; often "search"


class SplunkClient:
    """
    Uses /services/search/jobs/export (streaming results).
    output_mode=json => line-delimited JSON objects.
    """
    def __init__(self, cfg: SplunkConfig):
        if aiohttp is None:
            raise RuntimeError("aiohttp not installed. Install aiohttp or adapt to your existing HTTP layer.")
        self.cfg = cfg
        self.cb = CircuitBreaker()

    async def _export_search(self, session: aiohttp.ClientSession, search: str, timeout_s: int) -> List[Dict[str, Any]]:
        if not self.cb.allow():
            raise RuntimeError("Circuit breaker open: Splunk unhealthy. Skipping query temporarily.")

        url = f"{self.cfg.base_url}/services/search/jobs/export"
        headers = {"Authorization": f"Bearer {self.cfg.token}"}

        data = {
            "search": search,
            "output_mode": "json",
            "count": "0",  # streaming; Splunk ignores for export in many cases
        }

        # NOTE: verify_ssl mapping for aiohttp is via ssl param; we keep simple.
        timeout = aiohttp.ClientTimeout(total=timeout_s)

        async with session.post(url, headers=headers, data=data, timeout=timeout, ssl=self.cfg.verify_ssl) as resp:
            txt_ct = resp.headers.get("Content-Type", "")
            if resp.status != 200:
                body = await resp.text()
                raise RuntimeError(f"Splunk export failed HTTP {resp.status} CT={txt_ct} body={body[:500]}")

            rows: List[Dict[str, Any]] = []
            approx_bytes = 0

            async for line_b in resp.content:
                # Splunk export returns \n separated json lines.
                line = line_b.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    # Some splunk configs may emit non-JSON lines; ignore safely.
                    continue

                # The actual event is in obj["result"] for export output_mode=json
                result = obj.get("result")
                if isinstance(result, dict):
                    rows.append(result)

                    # hard safety caps
                    approx_bytes += len(line_b)
                    if len(rows) >= DEFAULT_MAX_ROWS_PER_QUERY:
                        break
                    if approx_bytes >= DEFAULT_MAX_BYTES_PER_QUERY:
                        break

            return rows

    async def run(self, search: str, timeout_s: int = DEFAULT_QUERY_TIMEOUT_S, retries: int = DEFAULT_RETRIES) -> List[Dict[str, Any]]:
        backoff = DEFAULT_BACKOFF_BASE_S
        last_err: Optional[Exception] = None

        async with aiohttp.ClientSession() as session:
            for attempt in range(retries + 1):
                try:
                    rows = await self._export_search(session, search, timeout_s)
                    self.cb.record_success()
                    return rows
                except Exception as e:
                    last_err = e
                    self.cb.record_failure()
                    if attempt < retries:
                        await asyncio.sleep(backoff)
                        backoff *= 2
                        continue
                    raise


# ---------------------------
# Discovery & field mapping (strict improvements)
# ---------------------------

def base_search(index: str, sourcetype: str, source: str, earliest: str, latest: str) -> str:
    return (
        f"search index={index} "
        f'sourcetype="{sourcetype}" '
        f'source="{source}" '
        f"earliest={earliest} latest={latest}"
    )

async def discover(
    client: SplunkClient,
    base: str,
    sample_n_general: int = DEFAULT_SAMPLE_N_GENERAL,
    sample_n_error: int = DEFAULT_SAMPLE_N_ERROR,
) -> Dict[str, Any]:
    """
    Strict: two samples to avoid missing rare error-only fields.
    """
    q_types = f"{base} | stats count as c by sourcetype | sort -c | head 20"
    q_sources = f"{base} | stats count as c by source | sort -c | head 20"

    # General sample
    q_gen = f"{base} | head {sample_n_general} | fields *"

    # Error-focused sample (broad "error-ish" filter that works even without fields)
    # Note: keyword match only for sampling (cheap) not for full metrics
    q_err = (
        f"{base} "
        f'| where match(lower(_raw), "error|exception|timeout|fail|reset|refused|unavailable|gateway|503|502|500|429|408") '
        f"| head {sample_n_error} | fields *"
    )

    top_types, top_sources, sample_general, sample_error = await asyncio.gather(
        client.run(q_types),
        client.run(q_sources),
        client.run(q_gen),
        client.run(q_err),
    )

    def field_presence(events: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        pres: Dict[str, Dict[str, Any]] = {}
        for ev in events:
            for k, v in ev.items():
                if k not in pres:
                    pres[k] = {"count": 0, "example": None}
                pres[k]["count"] += 1
                if pres[k]["example"] is None and v not in (None, "", "null"):
                    pres[k]["example"] = str(v)[:200]
        return pres

    return {
        "top_sourcetypes": top_types,
        "top_sources": top_sources,
        "field_presence_general": field_presence(sample_general),
        "field_presence_error": field_presence(sample_error),
        "sample_sizes": {"general": len(sample_general), "error": len(sample_error)},
    }

def build_field_map(discovery: Dict[str, Any], candidates: Dict[str, List[str]] = DEFAULT_CANDIDATES) -> Dict[str, Optional[str]]:
    """
    Strict: choose fields that appear in error-sample first (more valuable),
    then fall back to general sample.
    """
    err = discovery.get("field_presence_error", {})
    gen = discovery.get("field_presence_general", {})
    out: Dict[str, Optional[str]] = {}

    for canon, opts in candidates.items():
        chosen = None
        for f in opts:
            if f in err:
                chosen = f
                break
        if chosen is None:
            for f in opts:
                if f in gen:
                    chosen = f
                    break
        out[canon] = chosen
    return out

def normalize_spl(field_map: Dict[str, Optional[str]]) -> str:
    """
    Build SPL fragment that normalizes fields into canonical names.
    Uses coalesce with available candidates; missing fields left null then rex fallback may fill.
    """
    def fmt_field(f: str) -> str:
        return f"'{f}'" if "." in f else f

    def coalesce_from(options: List[str]) -> str:
        parts = []
        for f in options:
            parts.append(fmt_field(f))
        return "coalesce(" + ", ".join(parts) + ")"

    # For each canonical, build coalesce from ALL candidates but place chosen first if exists.
    def ordered_candidates(canon: str) -> List[str]:
        opts = list(DEFAULT_CANDIDATES[canon])
        chosen = field_map.get(canon)
        if chosen and chosen in opts:
            opts.remove(chosen)
            opts.insert(0, chosen)
        return opts

    status_expr = coalesce_from(ordered_candidates("http_status"))
    dur_expr = coalesce_from(ordered_candidates("dur_ms"))
    api_expr = coalesce_from(ordered_candidates("api"))
    method_expr = coalesce_from(ordered_candidates("method"))
    svc_expr = coalesce_from(ordered_candidates("service"))
    pod_expr = coalesce_from(ordered_candidates("pod"))
    host_expr = coalesce_from(ordered_candidates("host"))
    trace_expr = coalesce_from(ordered_candidates("trace_id"))
    span_expr = coalesce_from(ordered_candidates("span_id"))
    req_expr = coalesce_from(ordered_candidates("request_id"))
    level_expr = coalesce_from(ordered_candidates("level"))
    msg_expr = coalesce_from(ordered_candidates("message") + ["_raw"])

    return rf"""
| eval http_status = tonumber({status_expr})
| eval dur_ms = tonumber({dur_expr})
| eval api = {api_expr}
| eval method = {method_expr}
| eval service = {svc_expr}
| eval pod = {pod_expr}
| eval host_norm = coalesce({host_expr}, host, hostname)
| eval trace_id = {trace_expr}
| eval span_id = {span_expr}
| eval request_id = {req_expr}
| eval level_norm = upper({level_expr})
| eval msg = {msg_expr}
| eval msg = replace(tostring(msg), "\s+", " ")
""".strip()

def rex_fallback_spl() -> str:
    """
    Apply only when key fields missing; but safe to run always.
    Kept broad but not insane.
    """
    return r"""
| rex field=_raw "(?i)\b(status|httpStatus|status_code)\b[\"'=: ]+(?<rex_status>\d{3})"
| rex field=_raw "(?i)\b(latency|duration|elapsed|responseTime|rt)\b[\"'=: ]+(?<rex_dur>\d+(\.\d+)?)"
| rex field=_raw "(?i)\b(path|uri|endpoint|route)\b[\"'=: ]+(?<rex_api>\/[^\s\"',}]+)"
| rex field=_raw "(?i)\b(trace_id|traceId|span_id|spanId|request_id|requestId|correlation_id|correlationId)\b[\"'=: ]+(?<rex_id>[A-Za-z0-9\-_]+)"
| eval http_status = coalesce(http_status, tonumber(rex_status))
| eval dur_ms = coalesce(dur_ms, tonumber(rex_dur))
| eval api = coalesce(api, rex_api)
| eval request_id = coalesce(request_id, rex_id)
""".strip()


# ---------------------------
# Evidence queries (strict + production oriented)
# ---------------------------

def errorish_where() -> str:
    """
    Strict and unbiased:
    - include 5xx
    - include 429/408 (perf throttling/timeouts)
    - include explicit ERROR
    - include common network/proxy failure phrases
    """
    return r"""
| eval _raw_l = lower(_raw)
| where (http_status>=500)
    OR (http_status IN (429,408))
    OR (level_norm="ERROR")
    OR match(_raw_l, "exception|timeout|timed out|reset by peer|connection reset|connection refused|broken pipe|upstream|gateway|unavailable|circuit|throttl")
""".strip()

def build_queries(
    index: str,
    sourcetype: str,
    source: str,
    earliest: str,
    latest: str,
    field_map: Dict[str, Optional[str]],
    span: str,
) -> Dict[str, str]:
    base = base_search(index, sourcetype, source, earliest, latest)
    norm = normalize_spl(field_map)
    rex = rex_fallback_spl()
    errwhere = errorish_where()

    # Baseline regression is handled by running same queries with baseline window and computing deltas in Python.
    return {
        "window_overview": f"""
{base}
{norm}
{rex}
| stats count as events,
        min(_time) as min_time,
        max(_time) as max_time,
        dc(sourcetype) as sourcetypes,
        dc(source) as sources,
        dc(host_norm) as hosts,
        dc(service) as services
""".strip(),

        "traffic_timeseries": f"""
{base}
{norm}
{rex}
| timechart span={span}
    count as hits,
    count(eval(http_status>=500)) as e5xx,
    count(eval(http_status>=400 AND http_status<500)) as e4xx,
    count(eval(http_status IN (429,408))) as special_4xx
| eval e5xx_rate = if(hits>0, round(100*e5xx/hits,2), 0)
""".strip(),

        "latency_timeseries": f"""
{base}
{norm}
{rex}
| where isnotnull(dur_ms)
| timechart span={span}
    perc95(dur_ms) as p95_ms,
    perc99(dur_ms) as p99_ms,
    avg(dur_ms) as avg_ms
""".strip(),

        "endpoint_summary": f"""
{base}
{norm}
{rex}
| eval api = coalesce(api, "UNKNOWN_API")
| eval service = coalesce(service, "UNKNOWN_SERVICE")
| stats count as hits,
        count(eval(http_status>=500)) as e5xx,
        count(eval(http_status IN (429,408))) as e_429_408,
        perc95(dur_ms) as p95_ms,
        perc99(dur_ms) as p99_ms
        by service, api
| eval err_rate = if(hits>0, round(100*e5xx/hits,2), 0)
| sort -e5xx -p99_ms -hits
| head {DEFAULT_TOPN_ENDPOINTS}
""".strip(),

        "top_error_signatures": f"""
{base}
{norm}
{rex}
{errwhere}
| eval service = coalesce(service, "UNKNOWN_SERVICE")
| eval sig = substr(msg, 1, 200)
| stats count as occurrences,
        dc(request_id) as uniq_request_ids,
        dc(trace_id) as uniq_trace_ids,
        values(http_status) as statuses
        by service, sig
| sort -occurrences
| head {DEFAULT_TOPN_ERRORS}
""".strip(),

        "infra_hotspots": f"""
{base}
{norm}
{rex}
| eval service = coalesce(service, "UNKNOWN_SERVICE")
| stats count as events,
        count(eval(http_status>=500 OR level_norm="ERROR")) as errors,
        perc95(dur_ms) as p95_ms
        by service, pod, host_norm
| eval err_rate = if(events>0, round(100*errors/events,2), 0)
| sort -err_rate -errors
| head {DEFAULT_TOPN_HOSTS}
""".strip(),

        # Better bounded samples: keep up to N samples per top signature by using streamstats
        # We first find signature, then keep first 2 samples per signature (configurable)
        "bounded_samples": f"""
{base}
{norm}
{rex}
{errwhere}
| eval service = coalesce(service, "UNKNOWN_SERVICE")
| eval api = coalesce(api, "UNKNOWN_API")
| eval sig = substr(msg, 1, 160)
| sort 0 -_time
| streamstats count as sig_rank by sig
| where sig_rank <= 2
| head {DEFAULT_BOUNDED_SAMPLES}
| fields _time, service, api, method, http_status, dur_ms, request_id, trace_id, span_id, host_norm, pod, sig, msg
""".strip(),
    }


# ---------------------------
# Regression computation (strict)
# ---------------------------

def compute_regression(run_rows: List[Dict[str, Any]], base_rows: List[Dict[str, Any]], key_fields: List[str]) -> Dict[str, Any]:
    """
    Compute deltas for tables that share same grouping keys.
    Works for endpoint_summary and infra_hotspots and top_error_signatures.
    """
    def key_of(r: Dict[str, Any]) -> Tuple:
        return tuple(str(r.get(k, "")) for k in key_fields)

    run_map = {key_of(r): r for r in run_rows}
    base_map = {key_of(r): r for r in base_rows}

    deltas = []
    for k, rr in run_map.items():
        br = base_map.get(k, {})
        d = {"key": dict(zip(key_fields, k))}
        # numeric deltas
        for fld in ["hits", "events", "e5xx", "errors", "p95_ms", "p99_ms", "err_rate", "occurrences"]:
            if fld in rr or fld in br:
                rv = rr.get(fld)
                bv = br.get(fld)
                try:
                    rvf = float(rv) if rv not in (None, "") else None
                    bvf = float(bv) if bv not in (None, "") else None
                except Exception:
                    rvf, bvf = None, None
                d[fld] = {"run": rv, "base": bv, "delta": (rvf - bvf) if (rvf is not None and bvf is not None) else None}
        deltas.append(d)

    # sort by worst regression heuristic
    def score(x: Dict[str, Any]) -> float:
        # prioritize error rate delta then p99
        s = 0.0
        er = x.get("err_rate", {}).get("delta")
        p99 = x.get("p99_ms", {}).get("delta")
        if isinstance(er, (int, float)):
            s += er * 1000
        if isinstance(p99, (int, float)):
            s += p99
        return s

    deltas.sort(key=score, reverse=True)
    return {"key_fields": key_fields, "rows": deltas[:200]}  # cap


# ---------------------------
# Orchestrator (single entry)
# ---------------------------

@dataclass
class EvidenceRequest:
    # Required
    index: str
    sourcetype: str = "*"
    source: str = "*"
    earliest: str = "-15h"
    latest: str = "now"

    # Optional baseline window for regression
    baseline_earliest: Optional[str] = None
    baseline_latest: Optional[str] = None

    # Output
    output_path: str = "evidence.json"

    # Controls
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY
    query_timeout_s: int = DEFAULT_QUERY_TIMEOUT_S
    total_timeout_s: int = DEFAULT_TOTAL_TIMEOUT_S


async def generate_evidence(cfg: SplunkConfig, req: EvidenceRequest) -> Dict[str, Any]:
    """
    Main function: returns evidence dict. Caller writes JSON.
    Strict: bounded, concurrency-limited, resilient.
    """
    started = now_ms()
    span = choose_span(req.earliest, req.latest)

    client = SplunkClient(cfg)

    base = base_search(req.index, req.sourcetype, req.source, req.earliest, req.latest)

    # 1) Discovery
    discovery = await discover(client, base)

    # 2) Field map
    field_map = build_field_map(discovery)

    # 3) Queries
    queries = build_queries(req.index, req.sourcetype, req.source, req.earliest, req.latest, field_map, span)

    # 4) Run queries with concurrency limit
    sem = asyncio.Semaphore(req.max_concurrency)

    async def run_named(name: str, spl: str) -> Tuple[str, Dict[str, Any]]:
        async with sem:
            t0 = now_ms()
            try:
                rows = await client.run(spl, timeout_s=req.query_timeout_s)
                rows = clamp_list(rows, DEFAULT_MAX_ROWS_PER_QUERY)
                result = {"ok": True, "rows": rows, "ms": now_ms() - t0}
            except Exception as e:
                result = {"ok": False, "error": str(e), "rows": [], "ms": now_ms() - t0}
            return name, result

    tasks = [run_named(name, spl) for name, spl in queries.items()]
    # total timeout guard
    try:
        done = await asyncio.wait_for(asyncio.gather(*tasks), timeout=req.total_timeout_s)
    except asyncio.TimeoutError:
        done = []
        # We still return partial evidence
    results: Dict[str, Any] = {k: v for k, v in done}

    # 5) Redact samples (only bounded samples + any signature text)
    if "bounded_samples" in results and results["bounded_samples"].get("ok"):
        red = []
        for r in results["bounded_samples"]["rows"]:
            r2 = dict(r)
            r2["msg"] = redact_text(str(r2.get("msg", "")))
            r2["sig"] = redact_text(str(r2.get("sig", "")))
            red.append(r2)
        results["bounded_samples"]["rows"] = red

    if "top_error_signatures" in results and results["top_error_signatures"].get("ok"):
        red = []
        for r in results["top_error_signatures"]["rows"]:
            r2 = dict(r)
            r2["sig"] = redact_text(str(r2.get("sig", "")))
            red.append(r2)
        results["top_error_signatures"]["rows"] = red

    # 6) Baseline (optional) + regression deltas
    regression: Dict[str, Any] = {"enabled": False}
    if req.baseline_earliest and req.baseline_latest:
        regression["enabled"] = True
        base_queries = build_queries(req.index, req.sourcetype, req.source,
                                     req.baseline_earliest, req.baseline_latest,
                                     field_map, choose_span(req.baseline_earliest, req.baseline_latest))
        base_tasks = [run_named(f"base__{name}", spl) for name, spl in base_queries.items()]
        try:
            base_done = await asyncio.wait_for(asyncio.gather(*base_tasks), timeout=req.total_timeout_s)
        except asyncio.TimeoutError:
            base_done = []
        base_results = {k: v for k, v in base_done}

        # compute deltas for key tables
        def get_rows(res: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
            rr = res.get(key, {})
            return rr.get("rows", []) if rr.get("ok") else []

        regression["endpoint_summary"] = compute_regression(
            get_rows(results, "endpoint_summary"),
            get_rows(base_results, "base__endpoint_summary"),
            key_fields=["service", "api"],
        )
        regression["infra_hotspots"] = compute_regression(
            get_rows(results, "infra_hotspots"),
            get_rows(base_results, "base__infra_hotspots"),
            key_fields=["service", "pod", "host_norm"],
        )
        regression["top_error_signatures"] = compute_regression(
            get_rows(results, "top_error_signatures"),
            get_rows(base_results, "base__top_error_signatures"),
            key_fields=["service", "sig"],
        )

        regression["baseline_window"] = {"earliest": req.baseline_earliest, "latest": req.baseline_latest}

    # 7) Key highlights (so LLM doesn’t need to compute everything)
    highlights: Dict[str, Any] = {}

    # a) worst endpoints (top 10 by e5xx then p99)
    if results.get("endpoint_summary", {}).get("ok"):
        rows = results["endpoint_summary"]["rows"]
        def sort_key(r):
            e5 = float(r.get("e5xx", 0) or 0)
            p99 = float(r.get("p99_ms", 0) or 0)
            hits = float(r.get("hits", 0) or 0)
            return (e5, p99, hits)
        worst = sorted(rows, key=sort_key, reverse=True)[:10]
        highlights["worst_endpoints"] = worst

    # b) top error signatures (top 10)
    if results.get("top_error_signatures", {}).get("ok"):
        highlights["top_error_signatures"] = results["top_error_signatures"]["rows"][:10]

    # c) hotspots (top 10)
    if results.get("infra_hotspots", {}).get("ok"):
        highlights["infra_hotspots"] = results["infra_hotspots"]["rows"][:10]

    # 8) Build final evidence object (single JSON)
    evidence: Dict[str, Any] = {
        "version": "1.0",
        "generated_at_ms": now_ms(),
        "request": {
            "index": req.index,
            "sourcetype": req.sourcetype,
            "source": req.source,
            "earliest": req.earliest,
            "latest": req.latest,
            "span": span,
            "baseline": {"earliest": req.baseline_earliest, "latest": req.baseline_latest} if regression.get("enabled") else None,
        },
        "runtime": {
            "started_ms": started,
            "ended_ms": now_ms(),
            "duration_ms": now_ms() - started,
            "limits": {
                "max_concurrency": req.max_concurrency,
                "query_timeout_s": req.query_timeout_s,
                "total_timeout_s": req.total_timeout_s,
                "max_rows_per_query": DEFAULT_MAX_ROWS_PER_QUERY,
                "max_bytes_per_query": DEFAULT_MAX_BYTES_PER_QUERY,
            },
        },
        "discovery": discovery,     # embedded (you asked one file only)
        "field_map": field_map,
        "results": results,
        "highlights": highlights,
        "regression": regression,
        "notes_for_llm": [
            "This evidence is aggregated over the entire window; bounded_samples are representative, redacted examples.",
            "If deeper forensic proof is needed, run drilldown queries for the specific hotspot windows/services/pods shown in highlights.",
        ],
    }

    # Safety: ensure evidence size reasonable (you can enforce a hard cap here)
    approx = estimate_json_bytes(evidence)
    evidence["runtime"]["approx_evidence_bytes"] = approx

    return evidence


def write_evidence(path: str, evidence: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2, ensure_ascii=False, default=str)


# ---------------------------
# CLI (optional)
# ---------------------------

def _env(name: str, default: Optional[str] = None) -> str:
    v = os.getenv(name, default)
    if v is None:
        raise RuntimeError(f"Missing env var: {name}")
    return v

async def _main():
    cfg = SplunkConfig(
        base_url=_env("SPLUNK_BASE_URL"),
        token=_env("SPLUNK_TOKEN"),
        verify_ssl=os.getenv("SPLUNK_VERIFY_SSL", "true").lower() == "true",
    )

    req = EvidenceRequest(
        index=_env("SPLUNK_INDEX"),
        sourcetype=os.getenv("SPLUNK_SOURCETYPE", "*"),
        source=os.getenv("SPLUNK_SOURCE", "*"),
        earliest=os.getenv("SPLUNK_EARLIEST", "-15h"),
        latest=os.getenv("SPLUNK_LATEST", "now"),
        baseline_earliest=os.getenv("SPLUNK_BASELINE_EARLIEST"),
        baseline_latest=os.getenv("SPLUNK_BASELINE_LATEST"),
        output_path=os.getenv("EVIDENCE_OUT", "evidence.json"),
        max_concurrency=int(os.getenv("MAX_CONCURRENCY", str(DEFAULT_MAX_CONCURRENCY))),
        query_timeout_s=int(os.getenv("QUERY_TIMEOUT_S", str(DEFAULT_QUERY_TIMEOUT_S))),
        total_timeout_s=int(os.getenv("TOTAL_TIMEOUT_S", str(DEFAULT_TOTAL_TIMEOUT_S))),
    )

    evidence = await generate_evidence(cfg, req)
    write_evidence(req.output_path, evidence)
    print(f"Wrote evidence to {req.output_path} (approx {evidence['runtime']['approx_evidence_bytes']} bytes)")

if __name__ == "__main__":
    asyncio.run(_main())
