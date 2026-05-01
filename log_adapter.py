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
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


def adapt_bifrost(input_path: str, output_path: str, server_id: str = "bifrost"):
    """
    Adapt Bifrost gateway logs from SQLite (logs.db) to mcp-detect format.

    Reads the mcp_tool_logs table. Each row represents one tool execution
    (request + response bundled). We split each into two mcp-detect entries:
    a tools/call request and a response.

    Input: path to Bifrost's logs.db SQLite file.
    """
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

    for row in rows:
        ts = row["timestamp"] or row["created_at"] or datetime.now(timezone.utc).isoformat()
        tool_name = row["tool_name"] or "unknown"
        srv = row["server_label"] or server_id
        request_id = row["request_id"] or row["id"]
        latency = row["latency"]

        # Parse arguments
        args = None
        if row["arguments"]:
            try:
                args = json.loads(row["arguments"])
            except (json.JSONDecodeError, TypeError):
                args = row["arguments"]

        # Parse result
        result = None
        if row["result"]:
            try:
                result = json.loads(row["result"])
            except (json.JSONDecodeError, TypeError):
                result = row["result"]

        # Parse error
        error = None
        if row["error_details"]:
            try:
                error = json.loads(row["error_details"])
            except (json.JSONDecodeError, TypeError):
                error = row["error_details"]

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


def _parse_timestamp(ts: str):
    """Best-effort parse of various timestamp formats."""
    if not ts or not isinstance(ts, str):
        return None
    # Strip trailing Z
    ts_clean = ts.replace("Z", "+00:00")
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

    args = parser.parse_args()

    adapter = ADAPTERS[args.format]
    kwargs = {}
    if args.server_id:
        kwargs["server_id"] = args.server_id

    count = adapter(args.input, args.output, **kwargs)
    print(f"Adapted {count} entries from {args.format} format to {args.output}")


if __name__ == "__main__":
    main()
