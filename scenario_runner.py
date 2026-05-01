#!/usr/bin/env python3
"""
scenario_runner.py: Execute attack scenarios through different MCP transports.

Supports three transport modes:
  - stdio: pipe JSON-RPC to a local MCP server process
  - stdio-tap: pipe through mcp-tap wrapping a server (Group C)
  - http: POST JSON-RPC to Bifrost /mcp endpoint (Group B)

Usage:
    python scenario_runner.py --scenario s01 --transport stdio --server "mcp-server-filesystem DATA_DIR"
    python scenario_runner.py --scenario s01 --transport http --url http://localhost:9090/mcp
    python scenario_runner.py --scenario all --transport stdio --server "..."
    python scenario_runner.py --scenario baseline --transport stdio --server "..."
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import requests

from scenarios import ALL_SCENARIOS

DATA_DIR = r"C:\Users\Anna\PycharmProjects\mcp-tap\experiment\data"


def resolve_args(args, data_dir):
    """Replace {DATA} placeholder in tool call arguments."""
    if isinstance(args, str):
        return args.replace("{DATA}", data_dir)
    if isinstance(args, dict):
        return {k: resolve_args(v, data_dir) for k, v in args.items()}
    if isinstance(args, list):
        return [resolve_args(v, data_dir) for v in args]
    return args


class StdioTransport:
    """Send JSON-RPC over stdio to a subprocess."""

    def __init__(self, server_cmd, tool_prefix=""):
        self.server_cmd = server_cmd
        self.tool_prefix = tool_prefix
        self.proc = None
        self.msg_id = 0

    def start(self):
        self.proc = subprocess.Popen(
            self.server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=(os.name == "nt"),
        )

    def send(self, msg):
        """Send a JSON-RPC message, return response (or None for notifications)."""
        raw = json.dumps(msg) + "\n"
        self.proc.stdin.write(raw.encode())
        self.proc.stdin.flush()

        if "id" not in msg:
            return None  # notification, no response expected

        # Read response line
        line = self.proc.stdout.readline()
        if not line:
            return {"error": "no response (server closed)"}
        try:
            return json.loads(line.decode())
        except json.JSONDecodeError:
            return {"error": f"invalid JSON: {line.decode()[:200]}"}

    def initialize(self):
        self.msg_id = 0
        self.msg_id += 1
        resp = self.send({
            "jsonrpc": "2.0", "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "scenario_runner", "version": "1.0"},
            },
            "id": self.msg_id,
        })
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return resp

    def call_tool(self, tool_name, arguments):
        self.msg_id += 1
        return self.send({
            "jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": self.tool_prefix + tool_name, "arguments": arguments},
            "id": self.msg_id,
        })

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)


class HttpTransport:
    """Send JSON-RPC over HTTP to Bifrost /mcp endpoint."""

    def __init__(self, url, tool_prefix="filesystem-"):
        self.url = url
        self.tool_prefix = tool_prefix
        self.msg_id = 0
        self.session = requests.Session()
        self.session.headers["Content-Type"] = "application/json"

    def start(self):
        pass  # server already running

    def send(self, msg):
        try:
            r = self.session.post(self.url, json=msg, timeout=30)
            if r.status_code == 202:
                return None  # accepted (notification)
            return r.json()
        except Exception as e:
            return {"error": str(e)}

    def initialize(self):
        self.msg_id = 0
        self.msg_id += 1
        resp = self.send({
            "jsonrpc": "2.0", "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "scenario_runner", "version": "1.0"},
            },
            "id": self.msg_id,
        })
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return resp

    def call_tool(self, tool_name, arguments):
        self.msg_id += 1
        return self.send({
            "jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": self.tool_prefix + tool_name, "arguments": arguments},
            "id": self.msg_id,
        })

    def stop(self):
        self.session.close()


def run_scenario(transport, scenario_def, data_dir=DATA_DIR):
    """Execute a scenario through a transport, return results."""
    calls = scenario_def["calls"]
    results = []

    # Initialize session
    init_resp = transport.initialize()
    results.append({
        "step": "initialize",
        "response": init_resp,
        "timestamp": time.time(),
    })

    for i, call in enumerate(calls):
        delay = call.get("delay", 0)
        if delay > 0:
            time.sleep(delay)

        tool = call["tool"]
        args = resolve_args(call["args"], data_dir)

        t0 = time.time()
        resp = transport.call_tool(tool, args)
        t1 = time.time()

        results.append({
            "step": i + 1,
            "tool": tool,
            "args": args,
            "response": resp,
            "latency_ms": round((t1 - t0) * 1000, 1),
            "timestamp": t0,
        })

        # Truncate response for logging
        status = "ok"
        if resp and "error" in resp:
            status = "error"
        elif resp and resp.get("result", {}).get("isError"):
            status = "tool_error"

        print(f"  [{i+1}/{len(calls)}] {tool}: {status} ({results[-1]['latency_ms']}ms)")

    return results


def main():
    parser = argparse.ArgumentParser(
        prog="scenario_runner",
        description="Execute attack scenarios through MCP transports.",
    )
    parser.add_argument("--scenario", required=True,
                        help="Scenario ID (s01, s02, ...) or 'all' or 'baseline'")
    parser.add_argument("--transport", required=True,
                        choices=["stdio", "http"],
                        help="Transport: stdio (direct/mcp-tap) or http (Bifrost)")
    parser.add_argument("--server", default=None,
                        help="Server command for stdio transport")
    parser.add_argument("--url", default="http://localhost:9090/mcp",
                        help="Bifrost URL for http transport")
    parser.add_argument("--tool-prefix", default=None,
                        help="Tool name prefix (default: '' for stdio, 'filesystem-' for http)")
    parser.add_argument("--data-dir", default=DATA_DIR,
                        help="Path to test data directory")
    parser.add_argument("--output-dir", default=None,
                        help="Directory to save results JSON")

    args = parser.parse_args()

    # Build transport
    if args.transport == "stdio":
        if not args.server:
            print("Error: --server required for stdio transport", file=sys.stderr)
            sys.exit(1)
        prefix = args.tool_prefix if args.tool_prefix is not None else ""
        transport = StdioTransport(args.server, tool_prefix=prefix)
    else:
        prefix = args.tool_prefix if args.tool_prefix is not None else "filesystem-"
        transport = HttpTransport(args.url, tool_prefix=prefix)

    # Determine which scenarios to run
    if args.scenario == "all":
        scenario_ids = [k for k in ALL_SCENARIOS if k != "baseline"]
    else:
        scenario_ids = [args.scenario]

    for sid in scenario_ids:
        if sid not in ALL_SCENARIOS:
            print(f"Error: unknown scenario '{sid}'", file=sys.stderr)
            print(f"Available: {', '.join(ALL_SCENARIOS.keys())}", file=sys.stderr)
            sys.exit(1)

    # Execute
    for sid in scenario_ids:
        scenario_def = ALL_SCENARIOS[sid]()
        print(f"\n=== {scenario_def['name']} ===")
        print(f"  {scenario_def['description']}")

        transport.start()
        try:
            results = run_scenario(transport, scenario_def, args.data_dir)
        finally:
            transport.stop()

        # Save results
        if args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
            out_path = os.path.join(args.output_dir, f"{sid}_{args.transport}.json")
            with open(out_path, "w") as f:
                json.dump({
                    "scenario": scenario_def,
                    "transport": args.transport,
                    "results": results,
                }, f, indent=2, default=str)
            print(f"  Saved: {out_path}")

        print(f"  {len(results)-1} tool calls executed")


if __name__ == "__main__":
    main()
