# mcp-tap

Transparent infrastructure-sampled behavioral evidence for MCP servers.

A stdio wrapper that sits between an MCP client and any MCP server, captures all JSON-RPC traffic, and produces a tamper-evident JSONL audit log. The server doesn't know it's there. The agent doesn't know it's there.

## What this solves

MCP gateways (Bifrost, ToolHive, MintMCP) capture traffic for HTTP-transport servers. But most community MCP servers run on stdio, where no network traffic exists for a gateway to intercept. mcp-tap covers the transport nobody else covers.

The detection rules (mcp-detect) are transport-agnostic and operate on traffic from any source: mcp-tap, Bifrost, or direct SIEM ingestion.

## Install

```bash
git clone https://github.com/annawhooo/mcp-tap.git
cd mcp-tap
# No dependencies to install. Python 3.10+ standard library only.
```

## Quick start

Wrap any MCP server:

```bash
python mcp_tap.py \
    --server "npx -y @modelcontextprotocol/server-filesystem ./data" \
    --log ./audit.jsonl \
    --server-id filesystem
```

That's it. The filesystem server runs normally. The agent sees no difference. All JSON-RPC traffic is logged to `audit.jsonl` with HMAC chain integrity.

## Use in Claude Desktop

In `claude_desktop_config.json`, wrap the server command:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "python",
      "args": [
        "path/to/mcp_tap.py",
        "--server", "npx -y @modelcontextprotocol/server-filesystem ./data",
        "--log", "C:/Users/you/mcp-logs/filesystem.jsonl",
        "--server-id", "filesystem"
      ]
    }
  }
}
```

## CLI Options

| Option | Required | Description |
|--------|----------|-------------|
| `--server` | Yes | Server command to wrap |
| `--log` | Yes | Path to JSONL audit log (must be OUTSIDE server's accessible scope) |
| `--server-id` | No | Identifier for this server (default: "unknown") |
| `--session-id` | No | Shared ID for correlating logs across multiple mcp-tap instances |
| `--sensitivity` | No | Data handling: `full` (default), `redact`, `hash`, `metadata` |

## Log Format

Each line is a JSON object:

```json
{
  "timestamp": "2026-04-08T14:30:00.000Z",
  "sequence": 42,
  "session_id": "abc123",
  "server_id": "filesystem",
  "direction": "client_to_server",
  "method": "tools/call",
  "params": {"name": "read_file", "arguments": {"path": "/data/report.txt"}},
  "message_id": "42",
  "message_type": "request",
  "latency_ms": null,
  "hmac": "a1b2c3...",
  "prev_hmac": "d4e5f6..."
}
```

### HMAC Chain

Each entry's HMAC includes the previous entry's HMAC. If any entry is modified, deleted, or inserted, the chain breaks. Verify with:

```python
import json, hmac, hashlib

with open("audit.jsonl") as f:
    entries = [json.loads(line) for line in f]

for i in range(1, len(entries)):
    assert entries[i]["prev_hmac"] == entries[i-1]["hmac"], f"Chain broken at {i}"
print("Chain intact.")
```

### Sensitive Data Modes

| Mode | What's logged | Use case |
|------|--------------|----------|
| `full` | Everything including credential values | Controlled test environments |
| `redact` | Regex-replaces common secret patterns | Development with real credentials |
| `hash` | SHA-256 hashes of param values | Behavioral analysis without content exposure |
| `metadata` | Method and timing only, no params | Minimum footprint production monitoring |

## Run Detection Rules

mcp-detect reads mcp-tap's JSONL and evaluates detection rules:

```bash
python mcp_detect.py --log ./audit.jsonl --rules bio-derived
python mcp_detect.py --log ./audit.jsonl --rules conventional
python mcp_detect.py --log ./audit.jsonl --rules all
```

## Known Limitations

### 1. Log file accessible to agent (mitigated)
If the agent can write to the directory containing the log file, it can tamper with or delete the log. mcp-tap refuses to start if the log path is inside the server's directory, but this check is heuristic. Always place the log file in a directory the agent's MCP servers cannot reach.

### 2. Timing side channel
mcp-tap adds latency to every message (JSON parse, HMAC compute, file write). A sophisticated agent could detect the wrapper by measuring round-trip time differences. For a research tool this is acceptable. For production, async logging (write to buffer, flush in background thread) would reduce the timing signature.

### 3. Observer detection on Linux
On Linux, a process can read `/proc/self/fd/` to discover its file descriptor topology, potentially detecting the pipe wrapper. On Windows this is harder. Document assumes the agent does not perform process introspection.

### 4. Regex redaction is non-exhaustive
The `redact` mode catches common patterns (Bearer tokens, `sk-` prefixed keys, password fields). It will miss: base64-encoded credentials, JWTs, multiline secrets, and credentials in deeply nested JSON. Use `hash` mode for stronger coverage at the cost of readability.

### 5. No log rotation
The JSONL file grows unbounded. For long-running production monitoring, implement external log rotation (logrotate, PowerShell scheduled task) or use the `metadata` sensitivity mode to reduce log volume.

### 6. stdio transport only (v1)
mcp-tap covers stdio-transport MCP servers. For HTTP/SSE-transport servers, use an existing gateway (Bifrost, ToolHive). The detection rules (mcp-detect) work on traffic from either source.

### 7. Log shipping constraint
stdio transport uses stdin/stdout for the MCP relay and stderr for server error passthrough. There is no spare output stream for real-time log shipping. v1 writes to file only. Future HTTP transport version would not have this constraint.

### 8. Single-threaded HMAC chain
The HMAC chain uses a single lock for both latency tracking and log writing. Under very high throughput (hundreds of messages per second), this may become a bottleneck. Current MCP deployments are well below this threshold.

## Research Context

mcp-tap implements Design Principle #2 ("Infrastructure-sampled behavioral evidence") from "Biomimetic Gap Analysis: Immune System Structural Patterns Applied to Agentic AI Security."

The paper is available at: https://doi.org/10.5281/zenodo.19393455

## Related Tools

| Tool | What it does | Transport |
|------|-------------|-----------|
| mcp-tap | Passive capture, tamper-evident log | stdio |
| mcp-detect | Detection rules (conventional + bio-derived) | reads JSONL from any source |
| Bifrost | Active gateway, policy enforcement, audit | HTTP |
| ToolHive | Container-native gateway, K8s RBAC | HTTP |
| coffer-mcp | Encrypted credential vault with self-reported audit | stdio |

## AARM Alignment

mcp-tap is aligned with the [Autonomous Action Runtime Management (AARM) specification](https://aarm.dev), an open specification for securing AI-driven actions at runtime, stewarded by the CSAI Foundation.

mcp-tap addresses three of the AARM [system components](https://aarm.dev/components/overview):

- **Action Mediation Layer:** intercepts MCP tool calls at the stdio transport layer
- **Context Accumulator:** maintains a tamper-evident, HMAC-chained log of every action and its surrounding context
- **Receipt Generator:** each log entry is a cryptographically chained receipt binding the action, message ID, sequence, and timing

mcp-tap is a passive observer, not a pre-execution enforcement point. It captures and preserves evidence of agent actions for forensic analysis and compliance audit. AARM-Conformant systems require pre-execution interception with policy evaluation and one of five authorization decisions (allow, deny, modify, step-up, defer). mcp-tap is positioned as **AARM-Aligned** rather than AARM-Conformant.

For pre-execution enforcement on HTTP-transport MCP servers, mcp-tap is designed to interoperate with active gateways (Bifrost, ToolHive, MintMCP), leaving mcp-tap to cover the stdio transport that other gateways do not.

The companion tool [coffer-mcp](https://github.com/annawhooo/coffer-mcp) addresses the AARM [Over-Privileged Credentials threat](https://aarm.dev/threats/over-privileged-credentials) by ensuring credentials are resolved server-side and never enter the LLM context.

## Issues and Security

For bug reports and feature requests, use [GitHub Issues](https://github.com/annawhooo/mcp-tap/issues).

For security vulnerabilities, report privately via [GitHub Security Advisories](https://github.com/annawhooo/mcp-tap/security/advisories/new). Do not open a public issue for security reports.

mcp-tap is a single-maintainer research project. Response times are best-effort, not an SLA.

## License

Apache 2.0

## Author

Anna Hix
