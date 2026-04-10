#!/usr/bin/env python3
"""
log_adapter.py: Convert gateway logs to mcp-detect's JSONL format.

Reads logs from various MCP gateways and produces JSONL compatible
with mcp-detect's expected schema. Enables running the same detection
rules against traffic captured by any source.

Supported formats:
  - mcp-tap: native format, no conversion needed (passthrough)
  - bifrost: Bifrost gateway request logs (JSON)
  - generic: any JSON log with method/params/timestamp fields

Usage:
    python log_adapter.py --input bifrost-logs.json --format bifrost --output adapted.jsonl
    python log_adapter.py --input gateway.log --format generic --output adapted.jsonl

Then run detection:
    python mcp_detect.py --log adapted.jsonl --rules all
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def adapt_bifrost(input_path: str, output_path: str, server_id: str = "bifrost"):
    """
    Adapt Bifrost gateway logs to mcp-detect format.

    Bifrost logs requests and responses with OTel-aligned telemetry.
    Expected input: JSON array or newline-delimited JSON objects with fields:
      - timestamp (ISO 8601 or Unix epoch)
      - request.method / response.status
      - request.body / response.body (JSON-RPC content)
      - latency_ms or duration_ms
      - tool_name (if MCP tool call)

    Since Bifrost's exact log format depends on version and config,
    this adapter is lenient: it extracts whatever fields it finds
    and maps them to the mcp-detect schema. Fields it can't find
    are set to None.
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
