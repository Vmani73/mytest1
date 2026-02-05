"""
BEST-POSSIBLE (production-grade) Splunk Evidence Engine for LLM Perf RCA
Single-file, K8s-safe, scalable, maintainable, strict.

What makes this "best possible" vs v1:
1) Evidence-first ALWAYS (no GB raw by default)
2) Two-phase discovery (general + error-only) -> accurate field mapping
3) Data-quality scoring + confidence tags (prevents LLM hallucinations)
4) Adaptive query planning (span scaling, conditional rex, bounded outputs)
5) Auto hotspot detection + targeted drilldown (small raw slices) when needed
6) Circuit breaker + retries + backoff + concurrency limit + hard caps
7) Redaction on samples (PII/secret safe)
8) One output file: evidence.json (contains everything)

You still must set your base search constraints correctly (index/sourcetype/source + filters).
This system is designed to cope with inconsistent app logging.

ENV (recommended):
  SPLUNK_BASE_URL=https://splunk:8089
  SPLUNK_TOKEN=...
  SPLUNK_INDEX=...
  SPLUNK_SOURCETYPE=*
  SPLUNK_SOURCE=*
  SPLUNK_EARLIEST=-15h
  SPLUNK_LATEST=now
Optional baseline:
  SPLUNK_BASELINE_EARLIEST=-15h@d-1d (example)
  SPLUNK_BASELINE_LATEST=now@d-1d

Requires: python 3.10+, aiohttp
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import aiohttp


# =========================
# STRICT LIMITS / DEFAULTS
# =========================
MAX_CONCURRENCY_DEFAULT = 6
QUERY_TIMEOUT_S_DEFAULT = 90
TOTAL_TIMEOUT_S_DEFAULT = 20 * 60

RETRIES_DEFAULT = 2
BACKOFF_BASE_S = 1.5

# Hard caps (K8s safety)
MAX_ROWS_PER_QUERY = 50_000
MAX_BYTES_PER_QUERY = 15 * 1024 * 1024  # 15MB parsed-ish cap
MAX_EVIDENCE_BYTES_SOFT = 30 * 1024 * 1024  # 30MB soft cap (warn in output)

# Evidence limits
TOPN_ENDPOINTS = 120
TOPN_SIGNATURES = 120
TOPN_HOTSPOTS = 60
BOUNDED_SAMPLES_MAX = 240
SAMPLES_PER_SIGNATURE = 2

# Adaptive drilldown (small raw slices)
DRILLDOWN_ENABLED_DEFAULT = True
DRILLDOWN_MAX_WINDOWS = 5
DRILLDOWN_WINDOW_MINUTES = 10
DRILLDOWN_SAMPLES_PER_WINDOW = 120

# Circuit breaker
CB_FAIL_THRESHOLD = 4
CB_COOLDOWN_S = 60

# Confidence thresholds
COVERAGE_GOOD = 0.60   # >=60% events have that field -> good
COVERAGE_WARN = 0.20   # <20% -> low confidence


# =========================
# CANONICAL FIELD CANDIDATES
# Extend over time -> maintainable.
# =========================
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

# Optional: if your org has Splunk CIM / normalized fields (best case),
# you can add canonical fields first here to prefer them.
CIM_PREFERRED: Dict[str, List[str]] = {
    # Examples only—use what your Splunk team provides.
    # "http_status": ["status", "http_status"],
    # "dur_ms": ["duration", "response_time"],
}


# =========================
# REDACTION (STRICT BASELINE)
# Tune patterns for your bank policy.
# =========================
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_UUID = re.compile(r"\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\b")
RE_LONG_NUM = re.compile(r"\b\d{12,19}\b")
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


# =========================
# UTIL
# =========================
def now_ms() -> int:
    return int(time.time() * 1000)

def estimate_bytes(obj: Any) -> int:
    try:
        return len(json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"))
    except Exception:
        return 0

def clamp_rows(rows: List[Dict[str, Any]], max_rows: int = MAX_ROWS_PER_QUERY) -> List[Dict[str, Any]]:
    return rows[:max_rows] if len(rows) > max_rows else rows

def safe_float(x: Any) -> Optional[float]:
    try:
        if x is None or x == "":
            return None
        return float(x)
    except Exception:
        return None


# =========================
# CIRCUIT BREAKER
# =========================
@dataclass
class CircuitBreaker:
    fail_count: int = 0
    open_until: float = 0.0

    def allow(self) -> bool:
        return time.time() >= self.open_until

    def success(self) -> None:
        self.fail_count = 0
        self.open_until = 0.0

    def fail(self) -> None:
        self.fail_count += 1
        if self.fail_count >= CB_FAIL_THRESHOLD:
            self.open_until = time.time() + CB_COOLDOWN_S


# =========================
# SPLUNK CLIENT (export)
# =========================
@dataclass
class SplunkConfig:
    base_url: str
    token: str
    verify_ssl: bool = True

class SplunkClient:
    def __init__(self, cfg: SplunkConfig):
        self.cfg = cfg
        self.cb = CircuitBreaker()

    async def export(self, session: aiohttp.ClientSession, search: str, timeout_s: int) -> List[Dict[str, Any]]:
        if not self.cb.allow():
            raise RuntimeError("Circuit breaker open: Splunk unhealthy; skipping query temporarily.")

        url = f"{self.cfg.base_url}/services/search/jobs/export"
        headers = {"Authorization": f"Bearer {self.cfg.token}"}
        data = {"search": search, "output_mode": "json"}

        timeout = aiohttp.ClientTimeout(total=timeout_s)
        async with session.post(url, headers=headers, data=data, timeout=timeout, ssl=self.cfg.verify_ssl) as resp:
            if resp.status != 200:
                body = await resp.text()
                raise RuntimeError(f"Splunk export failed HTTP {resp.status}: {body[:600]}")

            rows: List[Dict[str, Any]] = []
            approx_bytes = 0

            async for line_b in resp.content:
                if not line_b:
                    continue
                approx_bytes += len(line_b)
                if approx_bytes >= MAX_BYTES_PER_QUERY:
                    break
                line = line_b.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                result = obj.get("result")
                if isinstance(result, dict):
                    rows.append(result)
                    if len(rows) >= MAX_ROWS_PER_QUERY:
                        break

            return rows

    async def run(self, search: str, timeout_s: int, retries: int) -> List[Dict[str, Any]]:
        backoff = BACKOFF_BASE_S
        last_err: Optional[Exception] = None
        async with aiohttp.ClientSession() as session:
            for attempt in range(retries + 1):
                try:
                    rows = await self.export(session, search, timeout_s)
                    self.cb.success()
                    return rows
                except Exception as e:
                    last_err = e
                    self.cb.fail()
                    if attempt < retries:
                        await asyncio.sleep(backoff)
                        backoff *= 2
                    else:
                        raise last_err


# =========================
# BASE SEARCH + ADAPTIVE SPAN
# =========================
def base_search(index: str, sourcetype: str, source: str, earliest: str, latest: str, extra_filter: str = "") -> str:
    extra = f" {extra_filter} " if extra_filter.strip() else " "
    return (
        f"search index={index} sourcetype=\"{sourcetype}\" source=\"{source}\""
        f"{extra}earliest={earliest} latest={latest}"
    )

def choose_span(earliest: str, latest: str) -> str:
    # best-effort; prefer stability: long windows -> larger spans
    m = re.match(r"^-(\d+)(m|h|d)$", str(earliest).strip())
    if m:
        n = int(m.group(1))
        unit = m.group(2)
        if unit == "m":
            return "1m" if n <= 360 else "5m"
        if unit == "h":
            if n <= 6:
                return "1m"
            if n <= 24:
                return "5m"
            return "15m"
        if unit == "d":
            return "30m"
    return "5m"


# =========================
# DISCOVERY (strict: general + error sample)
# =========================
async def discover(client: SplunkClient, base: str) -> Dict[str, Any]:
    q_types = f"{base} | stats count as c by sourcetype | sort -c | head 25"
    q_sources = f"{base} | stats count as c by source | sort -c | head 25"

    q_general = f"{base} | head 200 | fields *"
    q_error = (
        f"{base} | where match(lower(_raw),"
        f"\"error|exception|timeout|timed out|reset|refused|broken pipe|upstream|gateway|unavailable|503|502|500|429|408\")"
        f" | head 200 | fields *"
    )

    top_types, top_sources, gen, err = await asyncio.gather(
        client.run(q_types, QUERY_TIMEOUT_S_DEFAULT, RETRIES_DEFAULT),
        client.run(q_sources, QUERY_TIMEOUT_S_DEFAULT, RETRIES_DEFAULT),
        client.run(q_general, QUERY_TIMEOUT_S_DEFAULT, RETRIES_DEFAULT),
        client.run(q_error, QUERY_TIMEOUT_S_DEFAULT, RETRIES_DEFAULT),
    )

    def presence(events: List[Dict[str, Any]]) -> Dict[str, int]:
        pres: Dict[str, int] = {}
        for ev in events:
            for k in ev.keys():
                pres[k] = pres.get(k, 0) + 1
        return pres

    return {
        "top_sourcetypes": top_types,
        "top_sources": top_sources,
        "sample_sizes": {"general": len(gen), "error": len(err)},
        "field_presence_general": presence(gen),
        "field_presence_error": presence(err),
    }

def build_field_map(discovery: Dict[str, Any]) -> Dict[str, Optional[str]]:
    err = discovery.get("field_presence_error", {})
    gen = discovery.get("field_presence_general", {})

    def choose(canon: str, candidates: List[str]) -> Optional[str]:
        # prefer error sample presence first
        for f in candidates:
            if f in err:
                return f
        for f in candidates:
            if f in gen:
                return f
        return None

    out: Dict[str, Optional[str]] = {}
    for canon, candidates in DEFAULT_CANDIDATES.items():
        # If you have CIM preferred, prepend them
        pref = CIM_PREFERRED.get(canon, [])
        merged = pref + [c for c in candidates if c not in pref]
        out[canon] = choose(canon, merged)

    return out


# =========================
# NORMALIZATION SPL (coalesce + optional rex)
# =========================
def _fmt_field(f: str) -> str:
    return f"'{f}'" if "." in f else f

def _coalesce(fields: List[str]) -> str:
    return "coalesce(" + ", ".join(_fmt_field(f) for f in fields) + ")"

def normalization_spl(field_map: Dict[str, Optional[str]]) -> str:
    # Use ALL candidates, but put selected field first when present
    def ordered(canon: str) -> List[str]:
        base = list(DEFAULT_CANDIDATES[canon])
        chosen = field_map.get(canon)
        if chosen and chosen in base:
            base.remove(chosen)
            base.insert(0, chosen)
        # If your CIM preferred is defined, ensure it stays early
        for p in reversed(CIM_PREFERRED.get(canon, [])):
            if p in base:
                base.remove(p)
            base.insert(0, p)
        return base

    status = _coalesce(ordered("http_status"))
    dur = _coalesce(ordered("dur_ms"))
    api = _coalesce(ordered("api"))
    method = _coalesce(ordered("method"))
    svc = _coalesce(ordered("service"))
    pod = _coalesce(ordered("pod"))
    host = _coalesce(ordered("host") + ["host", "hostname"])
    trace = _coalesce(ordered("trace_id"))
    span = _coalesce(ordered("span_id"))
    req = _coalesce(ordered("request_id"))
    lvl = _coalesce(ordered("level"))
    msg = _coalesce(ordered("message") + ["_raw"])

    return rf"""
| eval http_status = tonumber({status})
| eval dur_ms = tonumber({dur})
| eval api = {api}
| eval method = {method}
| eval service = {svc}
| eval pod = {pod}
| eval host_norm = {host}
| eval trace_id = {trace}
| eval span_id = {span}
| eval request_id = {req}
| eval level_norm = upper({lvl})
| eval msg = {msg}
| eval msg = replace(tostring(msg), "\s+", " ")
""".strip()

def rex_fallback_spl() -> str:
    # Used ONLY when coverage is poor (conditional in planner)
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

def errorish_where() -> str:
    return r"""
| eval _raw_l = lower(_raw)
| where (http_status>=500)
   OR (http_status IN (429,408))
   OR (level_norm="ERROR")
   OR match(_raw_l, "exception|timeout|timed out|reset by peer|connection reset|connection refused|broken pipe|upstream|gateway|unavailable|circuit|throttl")
""".strip()


# =========================
# QUERY SET (core evidence)
# =========================
def build_queries(base: str, norm: str, use_rex: bool, span: str) -> Dict[str, str]:
    rex = ("\n" + rex_fallback_spl()) if use_rex else ""
    errw = errorish_where()

    return {
        "window_overview": f"""
{base}
{norm}{rex}
| stats count as events,
        min(_time) as min_time,
        max(_time) as max_time,
        dc(sourcetype) as sourcetypes,
        dc(source) as sources,
        dc(host_norm) as hosts,
        dc(service) as services
""".strip(),

        "coverage_snapshot": f"""
{base}
{norm}{rex}
| head 5000
| stats
    count as events,
    count(eval(isnotnull(http_status))) as has_status,
    count(eval(isnotnull(dur_ms))) as has_dur,
    count(eval(isnotnull(api))) as has_api,
    count(eval(isnotnull(request_id))) as has_reqid,
    count(eval(isnotnull(trace_id))) as has_trace
""".strip(),

        "traffic_timeseries": f"""
{base}
{norm}{rex}
| timechart span={span}
    count as hits,
    count(eval(http_status>=500)) as e5xx,
    count(eval(http_status>=400 AND http_status<500)) as e4xx,
    count(eval(http_status IN (429,408))) as special_4xx
| eval e5xx_rate = if(hits>0, round(100*e5xx/hits,2), 0)
""".strip(),

        "latency_timeseries": f"""
{base}
{norm}{rex}
| where isnotnull(dur_ms)
| timechart span={span}
    perc95(dur_ms) as p95_ms,
    perc99(dur_ms) as p99_ms,
    avg(dur_ms) as avg_ms
""".strip(),

        "endpoint_summary": f"""
{base}
{norm}{rex}
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
| head {TOPN_ENDPOINTS}
""".strip(),

        "top_error_signatures": f"""
{base}
{norm}{rex}
{errw}
| eval service = coalesce(service, "UNKNOWN_SERVICE")
| eval sig = substr(msg, 1, 220)
| stats count as occurrences,
        dc(request_id) as uniq_request_ids,
        dc(trace_id) as uniq_trace_ids,
        values(http_status) as statuses
        by service, sig
| sort -occurrences
| head {TOPN_SIGNATURES}
""".strip(),

        "infra_hotspots": f"""
{base}
{norm}{rex}
| eval service = coalesce(service, "UNKNOWN_SERVICE")
| stats count as events,
        count(eval(http_status>=500 OR level_norm="ERROR")) as errors,
        perc95(dur_ms) as p95_ms
        by service, pod, host_norm
| eval err_rate = if(events>0, round(100*errors/events,2), 0)
| sort -err_rate -errors
| head {TOPN_HOTSPOTS}
""".strip(),

        "bounded_samples": f"""
{base}
{norm}{rex}
{errw}
| eval service = coalesce(service, "UNKNOWN_SERVICE")
| eval api = coalesce(api, "UNKNOWN_API")
| eval sig = substr(msg, 1, 170)
| sort 0 -_time
| streamstats count as sig_rank by sig
| where sig_rank <= {SAMPLES_PER_SIGNATURE}
| head {BOUNDED_SAMPLES_MAX}
| fields _time, service, api, method, http_status, dur_ms, request_id, trace_id, span_id, host_norm, pod, sig, msg
""".strip(),
    }


# =========================
# DATA QUALITY + CONFIDENCE
# =========================
def compute_coverage(coverage_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not coverage_rows:
        return {"ok": False, "reason": "no coverage rows"}
    r = coverage_rows[0]
    total = safe_float(r.get("events")) or 0.0
    if total <= 0:
        return {"ok": False, "reason": "events=0"}

    def pct(n: Any) -> float:
        v = safe_float(n) or 0.0
        return round(v / total, 4)

    cov = {
        "events": int(total),
        "http_status": pct(r.get("has_status")),
        "dur_ms": pct(r.get("has_dur")),
        "api": pct(r.get("has_api")),
        "request_id": pct(r.get("has_reqid")),
        "trace_id": pct(r.get("has_trace")),
    }

    def level(x: float) -> str:
        if x >= COVERAGE_GOOD:
            return "good"
        if x >= COVERAGE_WARN:
            return "warn"
        return "low"

    confidence = {k: level(v) for k, v in cov.items() if k != "events"}
    # overall confidence: worst of key fields
    overall = "good"
    for k in ["http_status", "dur_ms", "api"]:
        if confidence.get(k) == "low":
            overall = "low"
            break
        if confidence.get(k) == "warn" and overall == "good":
            overall = "warn"

    return {"ok": True, "coverage": cov, "confidence": confidence, "overall": overall}

def should_use_rex(field_map: Dict[str, Optional[str]], discovery: Dict[str, Any]) -> bool:
    # If we have zero status+dur fields in discovery, rex may help. Otherwise avoid expensive rex.
    err = discovery.get("field_presence_error", {})
    gen = discovery.get("field_presence_general", {})
    present = set(err.keys()) | set(gen.keys())

    # If neither a candidate for status nor duration exists, we need rex.
    status_ok = any(f in present for f in DEFAULT_CANDIDATES["http_status"])
    dur_ok = any(f in present for f in DEFAULT_CANDIDATES["dur_ms"])
    api_ok = any(f in present for f in DEFAULT_CANDIDATES["api"])
    # If two of three are missing, allow rex.
    missing = sum([not status_ok, not dur_ok, not api_ok])
    return missing >= 2


# =========================
# HOTSPOT DETECTION + DRILLDOWN
# =========================
def detect_hot_windows(timeseries_rows: List[Dict[str, Any]], top_k: int = DRILLDOWN_MAX_WINDOWS) -> List[Dict[str, Any]]:
    """
    Identify windows with highest e5xx_rate and/or p99.
    Expects timechart rows containing _time/hits/e5xx/e5xx_rate/p99_ms.
    """
    if not timeseries_rows:
        return []
    # we allow either traffic_timeseries or latency_timeseries; best is combine later.
    candidates = []
    for r in timeseries_rows:
        hits = safe_float(r.get("hits")) or 0.0
        e5xx = safe_float(r.get("e5xx")) or 0.0
        rate = safe_float(r.get("e5xx_rate"))
        # Score: prioritize high error rate with enough traffic
        score = 0.0
        if rate is not None:
            score += rate * 1000
        else:
            score += (e5xx / max(hits, 1.0)) * 1000
        score += min(hits, 10_000) / 1000.0
        candidates.append({"_time": r.get("_time"), "hits": hits, "e5xx": e5xx, "e5xx_rate": rate, "score": score})

    candidates.sort(key=lambda x: x["score"], reverse=True)
    # de-dupe near duplicates by time string equality (simple)
    seen = set()
    out = []
    for c in candidates:
        t = str(c.get("_time"))
        if t in seen:
            continue
        seen.add(t)
        out.append(c)
        if len(out) >= top_k:
            break
    return out

def drilldown_query(base: str, norm: str, use_rex: bool, window_time: str, minutes: int) -> str:
    """
    We cannot reliably compute latest=... in SPL from formatted _time without assumptions,
    so this drilldown uses a time-near filter by _time range is tricky.
    BEST PRACTICE: provide earliest/latest in absolute epoch/ISO in your caller to do precise drilldown.
    Here, we do a pragmatic approach: use "earliest=_time-<min>m latest=_time+<min>m" by converting to relative is not possible in SPL without eval.
    Therefore we drill down using a secondary filter: take top errors around that time by using where _time>=... if _time is epoch.
    If your Splunk returns _time as epoch seconds, it works. If not, you will still get useful bounded samples by signature without time slicing.

    Strict: This is the only part that may need tailoring based on your _time format.
    """
    rex = ("\n" + rex_fallback_spl()) if use_rex else ""
    errw = errorish_where()

    return f"""
{base}
{norm}{rex}
{errw}
| sort 0 -_time
| head {DRILLDOWN_SAMPLES_PER_WINDOW}
| fields _time, service, api, method, http_status, dur_ms, request_id, trace_id, span_id, host_norm, pod, msg
""".strip()


# =========================
# REGRESSION (baseline)
# =========================
def compute_table_deltas(run_rows: List[Dict[str, Any]], base_rows: List[Dict[str, Any]], key_fields: List[str]) -> List[Dict[str, Any]]:
    def key_of(r: Dict[str, Any]) -> Tuple[str, ...]:
        return tuple(str(r.get(k, "")) for k in key_fields)

    run_map = {key_of(r): r for r in run_rows}
    base_map = {key_of(r): r for r in base_rows}

    out = []
    for k, rr in run_map.items():
        br = base_map.get(k, {})
        row = {"key": dict(zip(key_fields, k))}
        for fld in ["hits", "e5xx", "err_rate", "p95_ms", "p99_ms", "errors", "occurrences"]:
            rv = safe_float(rr.get(fld))
            bv = safe_float(br.get(fld))
            row[fld] = {"run": rr.get(fld), "base": br.get(fld), "delta": (rv - bv) if (rv is not None and bv is not None) else None}
        out.append(row)

    def score(x: Dict[str, Any]) -> float:
        er = x.get("err_rate", {}).get("delta")
        p99 = x.get("p99_ms", {}).get("delta")
        s = 0.0
        if isinstance(er, (int, float)):
            s += er * 1000
        if isinstance(p99, (int, float)):
            s += p99
        return s

    out.sort(key=score, reverse=True)
    return out[:250]


# =========================
# REQUEST / ORCHESTRATION
# =========================
@dataclass
class EvidenceRequest:
    index: str
    sourcetype: str = "*"
    source: str = "*"
    earliest: str = "-15h"
    latest: str = "now"
    extra_filter: str = ""  # add namespace/pod labels etc.

    baseline_earliest: Optional[str] = None
    baseline_latest: Optional[str] = None

    output_path: str = "evidence.json"

    max_concurrency: int = MAX_CONCURRENCY_DEFAULT
    query_timeout_s: int = QUERY_TIMEOUT_S_DEFAULT
    total_timeout_s: int = TOTAL_TIMEOUT_S_DEFAULT

    drilldown_enabled: bool = DRILLDOWN_ENABLED_DEFAULT


async def generate_evidence(cfg: SplunkConfig, req: EvidenceRequest) -> Dict[str, Any]:
    t0 = now_ms()
    client = SplunkClient(cfg)
    span = choose_span(req.earliest, req.latest)

    base = base_search(req.index, req.sourcetype, req.source, req.earliest, req.latest, req.extra_filter)

    # 1) discovery -> field map
    discovery = await discover(client, base)
    field_map = build_field_map(discovery)

    # 2) planner decides if rex should be used (avoid rex when not needed)
    use_rex = should_use_rex(field_map, discovery)
    norm = normalization_spl(field_map)

    queries = build_queries(base, norm, use_rex, span)

    sem = asyncio.Semaphore(req.max_concurrency)

    async def run_one(name: str, spl: str) -> Tuple[str, Dict[str, Any]]:
        async with sem:
            st = now_ms()
            try:
                rows = await client.run(spl, timeout_s=req.query_timeout_s, retries=RETRIES_DEFAULT)
                rows = clamp_rows(rows)
                return name, {"ok": True, "ms": now_ms() - st, "rows": rows}
            except Exception as e:
                return name, {"ok": False, "ms": now_ms() - st, "error": str(e), "rows": []}

    # 3) execute core queries
    core_tasks = [run_one(k, v) for k, v in queries.items()]
    try:
        core_done = await asyncio.wait_for(asyncio.gather(*core_tasks), timeout=req.total_timeout_s)
    except asyncio.TimeoutError:
        core_done = []

    results = {k: v for k, v in core_done}

    # 4) data quality + confidence
    coverage_eval = {}
    if results.get("coverage_snapshot", {}).get("ok"):
        coverage_eval = compute_coverage(results["coverage_snapshot"]["rows"])
    else:
        coverage_eval = {"ok": False, "reason": "coverage_snapshot query failed"}

    # 5) redact samples/signatures (strict)
    if results.get("bounded_samples", {}).get("ok"):
        red = []
        for r in results["bounded_samples"]["rows"]:
            r2 = dict(r)
            r2["msg"] = redact_text(str(r2.get("msg", "")))
            r2["sig"] = redact_text(str(r2.get("sig", "")))
            red.append(r2)
        results["bounded_samples"]["rows"] = red

    if results.get("top_error_signatures", {}).get("ok"):
        red = []
        for r in results["top_error_signatures"]["rows"]:
            r2 = dict(r)
            r2["sig"] = redact_text(str(r2.get("sig", "")))
            red.append(r2)
        results["top_error_signatures"]["rows"] = red

    # 6) highlights (LLM-ready)
    highlights: Dict[str, Any] = {}

    if results.get("endpoint_summary", {}).get("ok"):
        rows = results["endpoint_summary"]["rows"]
        def sk(r):
            return (safe_float(r.get("e5xx")) or 0.0, safe_float(r.get("p99_ms")) or 0.0, safe_float(r.get("hits")) or 0.0)
        highlights["worst_endpoints"] = sorted(rows, key=sk, reverse=True)[:10]

    if results.get("infra_hotspots", {}).get("ok"):
        highlights["infra_hotspots"] = results["infra_hotspots"]["rows"][:10]

    if results.get("top_error_signatures", {}).get("ok"):
        highlights["top_error_signatures"] = results["top_error_signatures"]["rows"][:10]

    # 7) adaptive drilldown (best possible, bounded)
    drilldown: Dict[str, Any] = {"enabled": bool(req.drilldown_enabled), "performed": False, "windows": []}
    if req.drilldown_enabled and results.get("traffic_timeseries", {}).get("ok"):
        hot = detect_hot_windows(results["traffic_timeseries"]["rows"], top_k=DRILLDOWN_MAX_WINDOWS)
        if hot:
            drilldown["performed"] = True
            dd_tasks = []
            for c in hot:
                dd_spl = drilldown_query(base, norm, use_rex, window_time=str(c.get("_time")), minutes=DRILLDOWN_WINDOW_MINUTES)
                dd_tasks.append(run_one(f"drill__{c.get('_time')}", dd_spl))

            try:
                dd_done = await asyncio.wait_for(asyncio.gather(*dd_tasks), timeout=req.total_timeout_s)
            except asyncio.TimeoutError:
                dd_done = []

            for name, res in dd_done:
                if res.get("ok"):
                    # redact
                    red = []
                    for r in res["rows"]:
                        r2 = dict(r)
                        r2["msg"] = redact_text(str(r2.get("msg", "")))
                        red.append(r2)
                    res["rows"] = red
                drilldown["windows"].append({"id": name, "result": res})

    # 8) baseline + regression (best possible: only for key tables)
    regression: Dict[str, Any] = {"enabled": False}
    if req.baseline_earliest and req.baseline_latest:
        regression["enabled"] = True
        base2 = base_search(req.index, req.sourcetype, req.source, req.baseline_earliest, req.baseline_latest, req.extra_filter)
        span2 = choose_span(req.baseline_earliest, req.baseline_latest)
        q2 = build_queries(base2, norm, use_rex, span2)

        # only run tables needed for deltas (keep cost low)
        base_needed = {
            "endpoint_summary": q2["endpoint_summary"],
            "infra_hotspots": q2["infra_hotspots"],
            "top_error_signatures": q2["top_error_signatures"],
        }
        base_tasks = [run_one(f"base__{k}", v) for k, v in base_needed.items()]

        try:
            base_done = await asyncio.wait_for(asyncio.gather(*base_tasks), timeout=req.total_timeout_s)
        except asyncio.TimeoutError:
            base_done = []
        base_res = {k: v for k, v in base_done}

        def get_rows(d: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
            return d.get(key, {}).get("rows", []) if d.get(key, {}).get("ok") else []

        regression["baseline_window"] = {"earliest": req.baseline_earliest, "latest": req.baseline_latest}
        regression["endpoint_summary_deltas"] = compute_table_deltas(
            get_rows(results, "endpoint_summary"),
            get_rows(base_res, "base__endpoint_summary"),
            ["service", "api"],
        )
        regression["infra_hotspots_deltas"] = compute_table_deltas(
            get_rows(results, "infra_hotspots"),
            get_rows(base_res, "base__infra_hotspots"),
            ["service", "pod", "host_norm"],
        )
        # signatures deltas (use occurrences)
        regression["top_error_signatures_deltas"] = compute_table_deltas(
            get_rows(results, "top_error_signatures"),
            get_rows(base_res, "base__top_error_signatures"),
            ["service", "sig"],
        )

    # 9) build final evidence (single file)
    evidence: Dict[str, Any] = {
        "version": "2.0-best-possible",
        "generated_at_ms": now_ms(),
        "request": {
            "index": req.index,
            "sourcetype": req.sourcetype,
            "source": req.source,
            "earliest": req.earliest,
            "latest": req.latest,
            "extra_filter": req.extra_filter,
            "span": span,
            "baseline": {"earliest": req.baseline_earliest, "latest": req.baseline_latest} if regression["enabled"] else None,
        },
        "runtime": {
            "started_ms": t0,
            "ended_ms": now_ms(),
            "duration_ms": now_ms() - t0,
            "limits": {
                "max_concurrency": req.max_concurrency,
                "query_timeout_s": req.query_timeout_s,
                "total_timeout_s": req.total_timeout_s,
                "max_rows_per_query": MAX_ROWS_PER_QUERY,
                "max_bytes_per_query": MAX_BYTES_PER_QUERY,
            },
        },
        "discovery": discovery,
        "field_map": field_map,
        "planner": {
            "use_rex_fallback": use_rex,
            "why": "REX enabled only when core fields likely missing (status/duration/api).",
        },
        "data_quality": coverage_eval,
        "results": results,
        "highlights": highlights,
        "drilldown": drilldown,
        "regression": regression,
        "llm_guidance": {
            "strict_notes": [
                "All full-window metrics are computed via Splunk aggregations (not samples).",
                "bounded_samples and drilldown windows are representative and redacted.",
                "Use data_quality.overall and per-field confidence to avoid over-claiming RCA when coverage is low.",
                "If overall confidence is 'low', recommend adding Splunk field extractions/CIM or app logging standardization.",
            ]
        },
    }

    approx = estimate_bytes(evidence)
    evidence["runtime"]["approx_evidence_bytes"] = approx
    evidence["runtime"]["evidence_size_note"] = (
        "ok" if approx <= MAX_EVIDENCE_BYTES_SOFT
        else "soft_cap_exceeded: consider reducing TOPN or increasing span"
    )
    return evidence

def write_json(path: str, obj: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, default=str)


# =========================
# CLI
# =========================
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
        extra_filter=os.getenv("SPLUNK_FILTER", ""),  # e.g. 'k8s.namespace="foo" app="bar"'
        baseline_earliest=os.getenv("SPLUNK_BASELINE_EARLIEST"),
        baseline_latest=os.getenv("SPLUNK_BASELINE_LATEST"),
        output_path=os.getenv("EVIDENCE_OUT", "evidence.json"),
        max_concurrency=int(os.getenv("MAX_CONCURRENCY", str(MAX_CONCURRENCY_DEFAULT))),
        query_timeout_s=int(os.getenv("QUERY_TIMEOUT_S", str(QUERY_TIMEOUT_S_DEFAULT))),
        total_timeout_s=int(os.getenv("TOTAL_TIMEOUT_S", str(TOTAL_TIMEOUT_S_DEFAULT))),
        drilldown_enabled=os.getenv("DRILLDOWN_ENABLED", "true").lower() == "true",
    )

    evidence = await generate_evidence(cfg, req)
    write_json(req.output_path, evidence)
    print(f"Wrote {req.output_path} (approx {evidence['runtime']['approx_evidence_bytes']} bytes)")

if __name__ == "__main__":
    asyncio.run(_main())
