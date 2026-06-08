#!/usr/bin/env python3
"""
log_adapter.py: Convert gateway logs to mcp-detect's JSONL format.

Reads logs from various MCP gateways and produces JSONL compatible
with mcp-detect's expected schema. Enables running the same detection
rules against traffic captured by any source.

Supported formats:
  - mcp-tap: native format, no conversion needed (passthrough)
  - bifrost: Bifrost gateway SQLite logs.db (mcp_tool_logs table)
  - bifrost-json: Bifrost logs exported as JSON (legacy/API export)
  - generic: any JSON log with method/params/timestamp fields

Usage:
    python log_adapter.py --input bifrost-data/logs.db --format bifrost --output adapted.jsonl
    python log_adapter.py --input bifrost-export.json --format bifrost-json --output adapted.jsonl
    python log_adapter.py --input gateway.log --format generic --output adapted.jsonl

Then run detection:
    python mcp_detect.py --log adapted.jsonl --rules all
"""

import argparse
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


def adapt_bifrost(input_path: str, output_path: str, server_id: str = "bifrost",
                  start_ts: datetime = None, end_ts: datetime = None):
    """
    Adapt Bifrost gateway logs from SQLite (logs.db) to mcp-detect format.

    Reads the mcp_tool_logs table. Each row represents one tool execution
    (request + response bundled). We split each into two mcp-detect entries:
    a tools/call request and a response.

    Input: path to Bifrost's logs.db SQLite file.

    Optional time-window filtering (used by the experiment orchestrator's
    slicer to extract per-scenario subsets from a single shared logs.db):
      start_ts: include rows with timestamp >= start_ts (inclusive lower bound)
      end_ts:   include rows with timestamp <  end_ts   (exclusive upper bound)
    Both must be timezone-aware datetime objects when provided. Rows whose
    `timestamp` field cannot be parsed are dropped with a warning to stderr
    when window args are present (otherwise included as before).
    """
    if (start_ts is None) != (end_ts is None):
        raise ValueError("start_ts and end_ts must both be provided or both omitted")
    if start_ts is not None and end_ts <= start_ts:
        raise ValueError(f"end_ts ({end_ts}) must be > start_ts ({start_ts})")
    windowed = start_ts is not None

    conn = sqlite3.connect(input_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, request_id, timestamp, tool_name, server_label,
               arguments, result, error_details, latency, status,
               metadata, created_at
        FROM mcp_tool_logs
        ORDER BY timestamp ASC, id ASC
    """)

    rows = cursor.fetchall()
    conn.close()

    adapted = []
    sequence = 0
    skipped_unparseable = 0

    for row in rows:
        ts = row["timestamp"] or row["created_at"] or datetime.now(timezone.utc).isoformat()

        # Window filtering when start_ts/end_ts provided
        if windowed:
            row_dt = _parse_timestamp(ts)
            if row_dt is None:
                skipped_unparseable += 1
                print(f"WARN: log_adapter: dropping row {row['id']} with "
                      f"unparseable timestamp: {ts!r}", file=sys.stderr)
                continue
            if row_dt < start_ts or row_dt >= end_ts:
                continue
        tool_name = row["tool_name"] or "unknown"
        srv = row["server_label"] or server_id
        request_id = row["request_id"] or row["id"]
        latency = row["latency"]

        # Parse arguments. Bifrost double-encodes: the SQLite cell contains
        # JSON whose `arguments` value is itself a JSON-encoded string.
        # Decode both layers so downstream rules see a dict (matching the
        # mcp-tap shape).
        args = _parse_possibly_double_encoded(row["arguments"])

        # Parse result (same double-encoding pattern in some Bifrost versions)
        result = _parse_possibly_double_encoded(row["result"])

        # Parse error
        error = _parse_possibly_double_encoded(row["error_details"])

        has_error = row["status"] == "error" or error is not None

        # Entry 1: the tools/call request
        sequence += 1
        adapted.append({
            "timestamp": ts,
            "sequence": sequence,
            "session_id": request_id,
            "server_id": srv,
            "direction": "client_to_server",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": args},
            "message_id": str(sequence),
            "message_type": "request",
            "latency_ms": None,
            "hmac": None,
            "prev_hmac": None,
        })

        # Entry 2: the response
        sequence += 1
        # Compute response timestamp from request + latency
        resp_ts = ts
        if latency is not None:
            try:
                req_dt = _parse_timestamp(ts)
                if req_dt:
                    from datetime import timedelta
                    resp_dt = req_dt + timedelta(milliseconds=latency)
                    resp_ts = resp_dt.isoformat()
            except Exception:
                pass

        adapted.append({
            "timestamp": resp_ts,
            "sequence": sequence,
            "session_id": request_id,
            "server_id": srv,
            "direction": "server_to_client",
            "method": None,
            "params": error if has_error else result,
            "message_id": str(sequence - 1),  # matches request
            "message_type": "response",
            "is_error": has_error,
            "latency_ms": round(latency, 2) if latency is not None else None,
            "hmac": None,
            "prev_hmac": None,
        })

    _write_output(adapted, output_path)
    return len(adapted)


def _normalize_microseconds(ts: str) -> str:
    """
    Truncate fractional seconds to 6 digits (microsecond precision).

    Python's stdlib `%f` strptime directive only handles 1-6 digit
    fractional seconds. Some log sources (Bifrost via Go's RFC3339Nano,
    some Rust libraries) write 7+ digit fractional seconds — typically
    100ns "ticks" — which strptime cannot parse.

    This helper trims fractional digits to 6 if longer, leaving everything
    else untouched. Naive timestamps without fractional seconds, with
    timezone suffixes, or with 1-6 digit fractions all pass through
    unchanged.

    Examples:
      "2026-05-01 21:25:34.0455463+00:00" → "2026-05-01 21:25:34.045546+00:00"
      "2026-05-01 21:25:34.045546+00:00"  → unchanged (already 6 digits)
      "2026-05-01 21:25:34+00:00"         → unchanged (no fractional part)
      "2026-05-01T21:25:34.0455463Z"      → "2026-05-01T21:25:34.045546Z"
    """
    if not isinstance(ts, str) or "." not in ts:
        return ts
    # Match: prefix up through ".", then 7+ digits, then suffix (tz or end)
    m = re.match(r"^(.*\.)(\d{7,})(.*)$", ts)
    if not m:
        return ts
    prefix, frac, suffix = m.groups()
    return f"{prefix}{frac[:6]}{suffix}"


def _parse_timestamp(ts: str):
    """Best-effort parse of various timestamp formats. Returns None on failure.

    Normalizes 7+ digit fractional seconds to 6 digits before parsing
    (see _normalize_microseconds). Tries 8 ISO 8601 variants covering
    space-separated and T-separated, with and without microseconds,
    with and without timezone offset.
    """
    if not ts or not isinstance(ts, str):
        return None
    ts_clean = _normalize_microseconds(ts).replace("Z", "+00:00")
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ]:
        try:
            return datetime.strptime(ts_clean, fmt)
        except ValueError:
            continue
    return None


def _parse_possibly_double_encoded(value):
    """Parse a value that may be JSON-encoded once or twice.

    Bifrost stores tool call arguments (and sometimes results/errors) as
    double-encoded JSON: the SQLite cell contains JSON, and the inner
    `arguments` field within that JSON is itself a JSON-encoded string.

    Without recursive parsing, downstream rules see `arguments` as a
    string and skip the message (BIO-004a's gate `isinstance(args, dict)`
    rejects strings). The mcp-tap capture path stores `arguments` as a
    dict directly, so adapting Bifrost output requires the second parse.

    Strategy: try to parse once. If the result is a string that looks
    like JSON, parse again. Returns the most-decoded form.

    Returns None if value is empty/None.
    Returns the value as-is if parsing fails at any layer.
    """
    if not value:
        return None
    try:
        first = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value

    # If the parse yielded a string that itself looks like JSON, parse again
    if isinstance(first, str) and first.strip().startswith(("{", "[", '"')):
        try:
            return json.loads(first)
        except (json.JSONDecodeError, TypeError):
            return first

    # If first level is a dict, check whether any value is a JSON string
    # that should be deserialized (Bifrost's pattern: outer dict has
    # `arguments` as a stringified JSON object)
    if isinstance(first, dict):
        for k, v in list(first.items()):
            if isinstance(v, str) and v.strip().startswith(("{", "[")):
                try:
                    first[k] = json.loads(v)
                except (json.JSONDecodeError, TypeError):
                    pass  # leave as-is if inner parse fails
    return first


def adapt_bifrost_json(input_path: str, output_path: str, server_id: str = "bifrost"):
    """
    Adapt Bifrost gateway logs exported as JSON to mcp-detect format.

    Use this for logs exported via the Bifrost API or manually extracted.
    For direct SQLite access, use adapt_bifrost instead.

    Expected input: JSON array or newline-delimited JSON objects with fields:
      - timestamp (ISO 8601 or Unix epoch)
      - request.method / response.status
      - request.body / response.body (JSON-RPC content)
      - latency_ms or duration_ms
      - tool_name (if MCP tool call)
    """
    entries = _read_input(input_path)
    adapted = []
    sequence = 0

    for entry in entries:
        sequence += 1

        # Extract timestamp
        ts = (entry.get("timestamp") or entry.get("time") or
              entry.get("@timestamp") or entry.get("created_at") or
              datetime.now(timezone.utc).isoformat())
        if isinstance(ts, (int, float)):
            ts = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

        # Try to find JSON-RPC content in various locations
        body = (entry.get("request", {}).get("body") or
                entry.get("body") or
                entry.get("message") or
                entry.get("data") or
                entry)

        if isinstance(body, str):
            try:
                body = json.loads(body)
            except (json.JSONDecodeError, TypeError):
                body = {}

        # Classify as request or response
        method = body.get("method")
        msg_id = body.get("id")
        params = body.get("params")
        result = body.get("result")
        error = body.get("error")

        if method:
            direction = "client_to_server"
            message_type = "request" if msg_id is not None else "notification"
        elif result is not None or error is not None:
            direction = "server_to_client"
            message_type = "response"
            params = result if result is not None else error
        else:
            # Can't classify, use what we have
            direction = entry.get("direction", "unknown")
            message_type = entry.get("type", "unknown")

        # Extract latency
        latency = (entry.get("latency_ms") or entry.get("duration_ms") or
                   entry.get("response_time_ms") or entry.get("latency") or
                   entry.get("duration"))
        if latency is not None:
            try:
                latency = round(float(latency), 2)
            except (ValueError, TypeError):
                latency = None

        # Extract tool name if available
        tool_name = (entry.get("tool_name") or entry.get("tool") or
                     (params.get("name") if isinstance(params, dict) else None))

        adapted.append({
            "timestamp": ts,
            "sequence": sequence,
            "session_id": entry.get("session_id", "bifrost"),
            "server_id": entry.get("server_id") or entry.get("mcp_server") or server_id,
            "direction": direction,
            "method": method or entry.get("mcp_method"),
            "params": params,
            "message_id": str(msg_id) if msg_id is not None else None,
            "message_type": message_type,
            "latency_ms": latency,
            "hmac": None,       # gateways don't produce HMAC chains
            "prev_hmac": None,  # chain integrity not available from gateways
        })

    _write_output(adapted, output_path)
    return len(adapted)


def adapt_generic(input_path: str, output_path: str, server_id: str = "gateway"):
    """
    Adapt generic JSON logs to mcp-detect format.

    Accepts any JSON with at least a timestamp and some indication
    of what happened. Best-effort field mapping.
    """
    entries = _read_input(input_path)
    adapted = []
    sequence = 0

    for entry in entries:
        sequence += 1

        ts = (entry.get("timestamp") or entry.get("time") or
              entry.get("@timestamp") or
              datetime.now(timezone.utc).isoformat())
        if isinstance(ts, (int, float)):
            ts = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

        adapted.append({
            "timestamp": ts,
            "sequence": sequence,
            "session_id": entry.get("session_id", "generic"),
            "server_id": entry.get("server_id") or server_id,
            "direction": entry.get("direction", "unknown"),
            "method": entry.get("method"),
            "params": entry.get("params") or entry.get("arguments") or entry.get("data"),
            "message_id": str(entry["id"]) if "id" in entry else None,
            "message_type": entry.get("message_type") or entry.get("type", "unknown"),
            "latency_ms": entry.get("latency_ms") or entry.get("duration_ms"),
            "hmac": None,
            "prev_hmac": None,
        })

    _write_output(adapted, output_path)
    return len(adapted)


# ---------------------------------------------------------------------------
# pipelock adapter
# ---------------------------------------------------------------------------
#
# pipelock (https://github.com/luckyPipewrench/pipelock) writes hash-chained
# "recorder JSONL" evidence: one JSON object per line, each a recorder.Entry
# wrapping a CaptureSummary in its `detail` field. Capture is verdict-oriented
# (one entry per scanned surface), NOT a full request/response transcript, so
# this adapter maps each capture entry to a single mcp-detect record rather
# than synthesizing both sides of a call.
#
# Schema source: pipelock internal/recorder/entry.go (Entry) and
# internal/capture/types.go (CaptureSummary, CaptureRequest, Finding).
#   recorder.Entry keys: v, seq, ts, session_id, trace_id, type, event_kind,
#                        transport, summary, detail, raw_ref, prev_hash, hash
#   CaptureSummary (entry.detail) keys used: surface, subsurface, request,
#                        raw_findings, effective_findings, effective_action,
#                        outcome, skip_reason, agent, profile, action_class,
#                        batch_index, config_hash, build_version, build_sha
#   CaptureRequest keys: method, url, tool_name, tool_args_json, mcp_method,
#                        and (once the luckyPipewrench/pipelock PR lands) rpc_id
#
# Mapping decisions (locked):
#   * One capture entry -> one record. Non-"capture" entries (checkpoint,
#     capture_drop, action_receipt, proxy_decision) are skipped.
#   * direction/message_type by surface:
#       request side : dlp, cee, tool_policy, url -> client_to_server / request
#       response side: response, tool_scan        -> server_to_client / response
#   * method   <- request.mcp_method on requests, None on responses.
#   * params   : tool call   -> {"name": tool_name, "arguments": <parsed args>}
#                url surface  -> {"url": request.url}
#                otherwise    -> None
#                responses    -> None. pipelock capture does not retain full
#                response content (only truncated, often-redacted samples), so
#                response-content rules cannot run against pipelock data. This
#                is a property of verdict-oriented capture, not a bug.
#   * message_id <- canonical rpc_id (the JSON-RPC id the pipelock PR adds),
#     stringified via json.dumps so numeric 1 and string "1" stay distinct.
#     Set on BOTH request and response (the server echoes the id); that is how
#     mcp-detect pairs them. None until rpc_id ships. pipelock internal
#     trace_id is deliberately NOT used here: it does not reliably correlate a
#     request to its response across capture surfaces.
#   * latency_ms : best-effort. On a response, join to the most recent prior
#     request sharing (session_id, transport, rpc_id) and take the timestamp
#     delta. None when either side is missing or rpc_id is absent. rpc_ids are
#     reused within a session, so the join is qualified by session+transport
#     and is best-effort per call, matching pipelock own guidance.
#   * is_error : responses only. True when pipelock outcome stopped the call
#     (blocked, fail_closed). Reflects pipelock verdict, NOT a server-side
#     JSON-RPC error (real response content is not captured).
#   * server_id <- CaptureSummary.agent, else profile, else the server_id arg.
#   * hmac / prev_hmac : None. pipelock chains entries with a SHA-256 hash
#     chain (entry.hash / entry.prev_hash), not an HMAC; those values are
#     preserved in the _pipelock sidecar and verified separately, not folded
#     into mcp-tap HMAC fields.
#   * _pipelock sidecar: every record carries an optional "_pipelock" object
#     with pipelock own verdict (surface, outcome, effective_action, raw and
#     effective findings, etc.) plus chain fields, so analyze.py can compare
#     mcp-detect findings against pipelock on the same traffic. mcp-detect
#     ignores unknown keys, so the core schema is unaffected.

_PIPELOCK_REQUEST_SURFACES = {"dlp", "cee", "tool_policy", "url"}
_PIPELOCK_RESPONSE_SURFACES = {"response", "tool_scan"}


def _ts_aware(ts):
    """Parse a timestamp to a tz-aware UTC datetime, or None.

    Wraps _parse_timestamp and promotes naive results to UTC so request and
    response timestamps from different parse paths stay comparable.
    """
    dt = _parse_timestamp(ts)
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _pipelock_rpc_key(request: dict):
    """Canonical string join key for a JSON-RPC id, or None.

    pipelock stores rpc_id as the raw JSON token, so after json.loads it is an
    int, str, or (rarely) another JSON scalar. json.dumps with sorted keys
    gives a stable string that keeps numeric 1 distinct from string "1"
    (1 -> "1", "1" -> the quoted form), matching pipelock byte-identical
    join-key intent. Returns None when the id is absent or JSON null.
    """
    if not isinstance(request, dict) or "rpc_id" not in request:
        return None
    rid = request["rpc_id"]
    if rid is None:
        return None
    try:
        return json.dumps(rid, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(rid)


def _read_pipelock_entries(input_path: str) -> list[dict]:
    """Read pipelock recorder JSONL entries from a file or a capture directory.

    If input_path is a directory, every evidence-*.jsonl beneath it is read
    (pipelock writes one hash-chained file per session, sometimes in
    per-session subdirectories). Each file is newline-delimited JSON; blank and
    malformed lines are skipped. Entries are returned in file order; global
    ordering is re-derived by timestamp in adapt_pipelock, since each file has
    its own seq and chain and seq is not globally meaningful.
    """
    import os
    import glob

    if os.path.isdir(input_path):
        paths = sorted(glob.glob(os.path.join(input_path, "**", "evidence-*.jsonl"),
                                 recursive=True))
    else:
        paths = [input_path]

    entries = []
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError as e:
            print(f"WARN: log_adapter: cannot read {p}: {e}", file=sys.stderr)
    return entries


def adapt_pipelock(input_path: str, output_path: str, server_id: str = "pipelock"):
    """Adapt pipelock recorder JSONL evidence to mcp-detect format.

    input_path may be a single evidence-*.jsonl file or a capture directory
    (every evidence-*.jsonl beneath it is read). See the module-level comment
    block above for the full field-by-field mapping and the rationale.
    """
    import bisect

    raw_entries = _read_pipelock_entries(input_path)

    captures = [e for e in raw_entries
                if isinstance(e, dict) and e.get("type") == "capture"]

    parsed = []
    for idx, e in enumerate(captures):
        detail = e.get("detail")
        if not isinstance(detail, dict):
            detail = {}
        request = detail.get("request")
        if not isinstance(request, dict):
            request = {}
        surface = detail.get("surface") or e.get("event_kind") or ""
        transport = detail.get("subsurface") or e.get("transport") or ""
        if surface in _PIPELOCK_RESPONSE_SURFACES:
            side = "response"
        elif surface in _PIPELOCK_REQUEST_SURFACES:
            side = "request"
        else:
            side = "unknown"
        parsed.append({
            "entry": e,
            "detail": detail,
            "request": request,
            "surface": surface,
            "transport": transport,
            "side": side,
            "dt": _ts_aware(e.get("ts")),
            "rpc_key": _pipelock_rpc_key(request),
            "session_id": e.get("session_id"),
            "idx": idx,
        })

    def _sort_key(p):
        if p["dt"] is not None:
            return (0, p["dt"], p["entry"].get("seq", 0))
        return (1, p["idx"], 0)
    parsed.sort(key=_sort_key)

    req_index = {}
    for p in parsed:
        if p["side"] == "request" and p["rpc_key"] is not None and p["dt"] is not None:
            req_index.setdefault(
                (p["session_id"], p["transport"], p["rpc_key"]), []
            ).append(p["dt"])
    for key in req_index:
        req_index[key].sort()

    def _latency_for_response(p):
        if p["rpc_key"] is None or p["dt"] is None:
            return None
        reqs = req_index.get((p["session_id"], p["transport"], p["rpc_key"]))
        if not reqs:
            return None
        pos = bisect.bisect_right(reqs, p["dt"]) - 1
        if pos < 0:
            return None
        delta_ms = (p["dt"] - reqs[pos]).total_seconds() * 1000.0
        if delta_ms < 0:
            return None
        return round(delta_ms, 2)

    adapted = []
    sequence = 0
    for p in parsed:
        e = p["entry"]
        detail = p["detail"]
        request = p["request"]
        surface = p["surface"]
        side = p["side"]

        if side == "response":
            direction = "server_to_client"
            message_type = "response"
            method = None
        elif side == "request":
            direction = "client_to_server"
            message_type = "request"
            method = request.get("mcp_method")
        else:
            direction = "unknown"
            message_type = "unknown"
            method = request.get("mcp_method")

        params = None
        if side == "request":
            tool_name = request.get("tool_name")
            if tool_name or request.get("mcp_method") == "tools/call":
                args = _parse_possibly_double_encoded(request.get("tool_args_json"))
                if args is None:
                    args = {}
                params = {"name": tool_name, "arguments": args}
            elif surface == "url":
                params = {"url": request.get("url")}

        server_id_val = detail.get("agent") or detail.get("profile") or server_id

        sequence += 1
        record = {
            "timestamp": e.get("ts"),
            "sequence": sequence,
            "session_id": e.get("session_id"),
            "server_id": server_id_val,
            "direction": direction,
            "method": method,
            "params": params,
            "message_id": p["rpc_key"],
            "message_type": message_type,
            "latency_ms": _latency_for_response(p) if side == "response" else None,
            "hmac": None,
            "prev_hmac": None,
        }
        if side == "response":
            record["is_error"] = detail.get("outcome") in ("blocked", "fail_closed")

        record["_pipelock"] = {
            "surface": surface,
            "subsurface": p["transport"],
            "trace_id": e.get("trace_id"),
            "seq": e.get("seq"),
            "prev_hash": e.get("prev_hash"),
            "hash": e.get("hash"),
            "outcome": detail.get("outcome"),
            "effective_action": detail.get("effective_action"),
            "raw_findings": detail.get("raw_findings"),
            "effective_findings": detail.get("effective_findings"),
            "skip_reason": detail.get("skip_reason"),
            "action_class": detail.get("action_class"),
            "agent": detail.get("agent"),
            "profile": detail.get("profile"),
            "batch_index": detail.get("batch_index"),
            "config_hash": detail.get("config_hash"),
            "build_version": detail.get("build_version"),
            "build_sha": detail.get("build_sha"),
        }

        adapted.append(record)

    _write_output(adapted, output_path)
    return len(adapted)


def passthrough(input_path: str, output_path: str, **kwargs):
    """mcp-tap format: just copy (already in the right format)."""
    import shutil
    shutil.copy2(input_path, output_path)
    with open(input_path) as f:
        return sum(1 for line in f if line.strip())


def _read_input(path: str) -> list[dict]:
    """Read JSON input (array or newline-delimited)."""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    # Try JSON array first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return data
        else:
            return [data]
    except json.JSONDecodeError:
        pass

    # Try newline-delimited JSON
    entries = []
    for line in content.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def _write_output(entries: list[dict], path: str):
    """Write JSONL output."""
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")


ADAPTERS = {
    "mcp-tap": passthrough,
    "bifrost": adapt_bifrost,
    "bifrost-json": adapt_bifrost_json,
    "generic": adapt_generic,
    "pipelock": adapt_pipelock,
}


def main():
    parser = argparse.ArgumentParser(
        prog="log_adapter",
        description="Convert gateway logs to mcp-detect JSONL format.",
    )
    parser.add_argument("--input", required=True, help="Path to input log file")
    parser.add_argument("--format", required=True, choices=list(ADAPTERS.keys()),
                        help="Input log format")
    parser.add_argument("--output", required=True, help="Path to output JSONL file")
    parser.add_argument("--server-id", default=None,
                        help="Server ID to assign if not present in logs")
    parser.add_argument("--start-ts", default=None,
                        help="ISO 8601 lower bound (inclusive) for row timestamp. "
                             "Bifrost format only. Must be used with --end-ts.")
    parser.add_argument("--end-ts", default=None,
                        help="ISO 8601 upper bound (exclusive) for row timestamp. "
                             "Bifrost format only. Must be used with --start-ts.")

    args = parser.parse_args()

    # Validate window args
    if (args.start_ts is None) != (args.end_ts is None):
        parser.error("--start-ts and --end-ts must be used together")
    if args.start_ts is not None and args.format != "bifrost":
        parser.error("--start-ts/--end-ts only supported with --format bifrost")

    adapter = ADAPTERS[args.format]
    kwargs = {}
    if args.server_id:
        kwargs["server_id"] = args.server_id
    if args.start_ts is not None:
        start_dt = _parse_timestamp(args.start_ts)
        end_dt = _parse_timestamp(args.end_ts)
        if start_dt is None:
            parser.error(f"--start-ts could not be parsed: {args.start_ts!r}")
        if end_dt is None:
            parser.error(f"--end-ts could not be parsed: {args.end_ts!r}")
        kwargs["start_ts"] = start_dt
        kwargs["end_ts"] = end_dt

    count = adapter(args.input, args.output, **kwargs)
    print(f"Adapted {count} entries from {args.format} format to {args.output}")


if __name__ == "__main__":
    main()
