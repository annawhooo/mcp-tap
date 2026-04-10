#!/usr/bin/env python3
"""
mcp-tap: Infrastructure-sampled behavioral evidence for MCP servers.

A transparent stdio wrapper that sits between an MCP client and ANY
MCP server, captures all JSON-RPC traffic, and produces a tamper-evident
JSONL audit log. The server doesn't know it's there. The agent doesn't
know it's there.

This is Design Principle #2 from "Biomimetic Gap Analysis: Immune System
Structural Patterns Applied to Agentic AI Security" implemented as a tool.

Usage:
    python -m mcp_tap --server "npx @modelcontextprotocol/server-filesystem ./data" \
                      --log ./audit.jsonl \
                      --server-id filesystem

In Claude Desktop config (claude_desktop_config.json):
    {
      "mcpServers": {
        "filesystem": {
          "command": "python",
          "args": ["-m", "mcp_tap",
                   "--server", "npx @modelcontextprotocol/server-filesystem ./data",
                   "--log", "./audit.jsonl",
                   "--server-id", "filesystem"]
        }
      }
    }

Zero external dependencies. Python 3.10+. Windows/Mac/Linux.
"""

import argparse
import hashlib
import hmac as hmac_mod
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# HMAC Chain (reuses coffer-mcp pattern)
# ---------------------------------------------------------------------------

def get_hmac_key() -> bytes:
    """
    Retrieve or generate the HMAC key.

    Priority:
      1. MCP_TAP_HMAC_KEY environment variable (hex-encoded)
      2. .mcp-tap-key file in the log directory
      3. Generate a new key and write it to .mcp-tap-key

    For production: replace with OS keyring or external secret store.
    """
    env_key = os.environ.get("MCP_TAP_HMAC_KEY")
    if env_key:
        return bytes.fromhex(env_key)

    key_path = Path.home() / ".mcp-tap-key"
    if key_path.exists():
        return bytes.fromhex(key_path.read_text().strip())

    new_key = os.urandom(32)
    key_path.write_text(new_key.hex())
    # Restrict permissions on Unix; best-effort on Windows
    try:
        key_path.chmod(0o600)
    except OSError:
        pass
    return new_key


def compute_hmac(data: str, key: bytes) -> str:
    """HMAC-SHA256 of the given string data."""
    return hmac_mod.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Sensitive Data Handling
# ---------------------------------------------------------------------------

# Common secret patterns (Bearer tokens, API keys, passwords)
SECRET_PATTERNS = [
    (re.compile(r"(Bearer\s+)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(sk-[a-zA-Z0-9_-])[a-zA-Z0-9_-]{20,}"), r"\1...[REDACTED]"),
    (re.compile(r"(key[\"']?\s*[:=]\s*[\"']?)[a-zA-Z0-9_-]{16,}", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(password[\"']?\s*[:=]\s*[\"']?)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token[\"']?\s*[:=]\s*[\"']?)[a-zA-Z0-9_-]{16,}", re.IGNORECASE), r"\1[REDACTED]"),
]


def redact_secrets(text: str) -> str:
    """Replace common secret patterns with [REDACTED]."""
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def hash_params(params: dict) -> dict:
    """Replace all string values with SHA-256 hashes."""
    if params is None:
        return None
    result = {}
    for k, v in params.items():
        if isinstance(v, str):
            result[k] = f"sha256:{hashlib.sha256(v.encode()).hexdigest()[:16]}"
        elif isinstance(v, dict):
            result[k] = hash_params(v)
        elif isinstance(v, list):
            result[k] = [
                hash_params(i) if isinstance(i, dict)
                else f"sha256:{hashlib.sha256(str(i).encode()).hexdigest()[:16]}"
                if isinstance(i, str) else i
                for i in v
            ]
        else:
            result[k] = v
    return result


def process_params(params, mode: str):
    """Process params according to the configured sensitivity mode."""
    if params is None:
        return None
    if mode == "full":
        return params
    elif mode == "redact":
        return json.loads(redact_secrets(json.dumps(params)))
    elif mode == "hash":
        return hash_params(params) if isinstance(params, dict) else params
    elif mode == "metadata":
        return {"_redacted": True, "_keys": list(params.keys()) if isinstance(params, dict) else None}
    return params


# ---------------------------------------------------------------------------
# JSON-RPC Message Parsing
# ---------------------------------------------------------------------------

def classify_message(msg: dict) -> tuple[str, str | None, dict | None, str | None]:
    """
    Classify a JSON-RPC message.

    Returns: (message_type, method, params, message_id)
    """
    msg_id = msg.get("id")

    if "method" in msg:
        method = msg["method"]
        params = msg.get("params")
        if msg_id is not None:
            return ("request", method, params, msg_id)
        else:
            return ("notification", method, params, None)
    elif "result" in msg or "error" in msg:
        # Check key existence, not truthiness. A response with
        # result=null or result=0 is valid and must not be treated
        # as an error just because the value is falsy.
        if "result" in msg:
            return ("response", None, msg.get("result"), msg_id)
        else:
            return ("response", None, msg.get("error"), msg_id)
    else:
        return ("unknown", None, None, msg_id)


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """Tamper-evident JSONL audit logger with HMAC chain."""

    def __init__(self, log_path: str, server_id: str, sensitivity: str,
                 hmac_key: bytes, session_id: str = None):
        self.log_path = Path(log_path)
        self.server_id = server_id
        self.session_id = session_id or hashlib.sha256(os.urandom(16)).hexdigest()[:12]
        self.sensitivity = sensitivity
        self.hmac_key = hmac_key
        self.sequence = 0
        self.prev_hmac = "genesis"
        self.lock = threading.Lock()
        self.pending_requests: dict[str, float] = {}  # message_id -> timestamp

        # Ensure log directory exists
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        # Open persistent file handle (avoids per-write open/close overhead)
        self._log_file = open(self.log_path, "a", encoding="utf-8")

        # Write genesis entry
        self._write_entry({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sequence": 0,
            "server_id": self.server_id,
            "event": "genesis",
            "version": "mcp-tap-0.1.0",
            "session_id": self.session_id,
            "sensitivity_mode": self.sensitivity,
            "hmac": "",
            "prev_hmac": "",
        })

    def close(self):
        """Close the log file handle."""
        if self._log_file and not self._log_file.closed:
            self._log_file.flush()
            self._log_file.close()

    def log_message(self, direction: str, raw_line: str):
        """Parse a JSON-RPC message and write an audit entry."""
        try:
            msg = json.loads(raw_line)
        except json.JSONDecodeError:
            # Not valid JSON; log as raw
            self._write_raw(direction, raw_line)
            return

        msg_type, method, params, msg_id = classify_message(msg)
        now = time.time()
        now_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()

        # Latency tracking
        latency_ms = None
        if msg_type == "request" and msg_id is not None:
            with self.lock:
                self.pending_requests[str(msg_id)] = now
        elif msg_type == "response" and msg_id is not None:
            with self.lock:
                req_time = self.pending_requests.pop(str(msg_id), None)
            if req_time is not None:
                latency_ms = round((now - req_time) * 1000, 2)

        entry = {
            "timestamp": now_iso,
            "sequence": None,  # filled by _write_entry
            "session_id": self.session_id,
            "server_id": self.server_id,
            "direction": direction,
            "method": method,
            "params": process_params(params, self.sensitivity),
            "message_id": str(msg_id) if msg_id is not None else None,
            "message_type": msg_type,
            "latency_ms": latency_ms,
            "hmac": "",       # filled by _write_entry
            "prev_hmac": "",  # filled by _write_entry
        }

        self._write_entry(entry)

    def _write_entry(self, entry: dict):
        """Write a single JSONL entry with HMAC chain."""
        with self.lock:
            self.sequence += 1
            entry["sequence"] = self.sequence
            entry["prev_hmac"] = self.prev_hmac

            # Compute HMAC over all fields except hmac itself
            entry["hmac"] = ""
            chain_data = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            entry["hmac"] = compute_hmac(chain_data, self.hmac_key)
            self.prev_hmac = entry["hmac"]

            line = json.dumps(entry, separators=(",", ":"))
            self._log_file.write(line + "\n")
            self._log_file.flush()

    def _write_raw(self, direction: str, raw_line: str):
        """Log a non-JSON message (shouldn't happen in MCP, but be safe)."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sequence": None,
            "session_id": self.session_id,
            "server_id": self.server_id,
            "direction": direction,
            "method": None,
            "params": None,
            "message_id": None,
            "message_type": "raw",
            "latency_ms": None,
            "raw": raw_line.strip()[:1000],  # truncate for safety
            "hmac": "",
            "prev_hmac": "",
        }
        self._write_entry(entry)

    def log_lifecycle(self, event: str, details: dict | None = None):
        """Log a lifecycle event (start, stop, error)."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sequence": None,
            "session_id": self.session_id,
            "server_id": self.server_id,
            "event": event,
            "details": details,
            "hmac": "",
            "prev_hmac": "",
        }
        self._write_entry(entry)


# ---------------------------------------------------------------------------
# Stdio Relay
# ---------------------------------------------------------------------------

def relay_stream(
    source,
    dest,
    logger: AuditLogger,
    direction: str,
    shutdown_event: threading.Event,
    close_on_eof=None,
):
    """
    Read JSON-RPC messages from source, log them, write to dest.
    Runs in a dedicated thread.

    Handles both spec-compliant servers (one JSON per line) and
    non-conformant servers (pretty-printed multiline JSON) by
    accumulating bytes until a complete JSON object is parsed.

    close_on_eof: if provided, close this stream when source reaches EOF.
    Used for client_to_server: when client stdin closes, close server stdin
    so the server knows input is done and can flush responses.
    """
    buffer = b""

    try:
        while not shutdown_event.is_set():
            chunk = source.readline()
            if not chunk:
                # EOF: if there's leftover buffer, try to process it
                if buffer.strip():
                    _try_log_and_forward(buffer, dest, logger, direction)
                break

            buffer += chunk

            # Try to parse complete JSON objects from the buffer.
            # Fast path: most MCP servers send one JSON per line.
            # Slow path: accumulate until valid JSON is found.
            while buffer:
                stripped = buffer.strip()
                if not stripped:
                    buffer = b""
                    break

                try:
                    decoded = stripped.decode("utf-8")
                except UnicodeDecodeError:
                    decoded = stripped.decode("utf-8", errors="replace")

                try:
                    json.loads(decoded)
                    # Complete JSON object found. Log and forward.
                    logger.log_message(direction, decoded)
                    try:
                        dest.write(buffer)
                        dest.flush()
                    except (BrokenPipeError, OSError):
                        shutdown_event.set()
                        break
                    buffer = b""
                    break
                except json.JSONDecodeError:
                    # Incomplete JSON. If the chunk ended with a newline
                    # and we still can't parse, this might be a non-JSON
                    # line (e.g., server stderr leaking to stdout).
                    # If the chunk did NOT end with a newline, the message
                    # might be multiline — keep accumulating.
                    if chunk.endswith(b"\n") and b"\n" in buffer[:-1]:
                        # Multiple complete lines that don't parse as one
                        # JSON object. Try forwarding line by line.
                        lines = buffer.split(b"\n")
                        buffer = b""
                        for line in lines:
                            line_stripped = line.strip()
                            if not line_stripped:
                                continue
                            try:
                                line_decoded = line_stripped.decode("utf-8")
                            except UnicodeDecodeError:
                                line_decoded = line_stripped.decode("utf-8", errors="replace")
                            try:
                                json.loads(line_decoded)
                                logger.log_message(direction, line_decoded)
                            except json.JSONDecodeError:
                                logger.log_message(direction, line_decoded)
                            try:
                                dest.write(line + b"\n")
                                dest.flush()
                            except (BrokenPipeError, OSError):
                                shutdown_event.set()
                                break
                        break
                    else:
                        # Keep accumulating — message may be multiline
                        break

    except Exception as e:
        logger.log_lifecycle("relay_error", {"direction": direction, "error": str(e)})
    finally:
        if close_on_eof is not None:
            try:
                close_on_eof.close()
            except OSError:
                pass


def _try_log_and_forward(buffer: bytes, dest, logger, direction: str):
    """Attempt to log and forward remaining buffer content."""
    stripped = buffer.strip()
    if not stripped:
        return
    try:
        decoded = stripped.decode("utf-8")
    except UnicodeDecodeError:
        decoded = stripped.decode("utf-8", errors="replace")
    logger.log_message(direction, decoded)
    try:
        dest.write(buffer)
        dest.flush()
    except (BrokenPipeError, OSError):
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_server_command(cmd: str) -> list[str]:
    """
    Parse a server command string into a list for subprocess.

    Handles both:
      --server "npx @modelcontextprotocol/server-filesystem ./data"
      --server npx --server-args "@modelcontextprotocol/server-filesystem ./data"
    """
    if os.name == "nt":
        # shlex.split doesn't handle Windows paths well; use a simpler split
        # but preserve quoted strings
        try:
            return shlex.split(cmd, posix=False)
        except ValueError:
            return cmd.split()
    else:
        return shlex.split(cmd)


def main():
    parser = argparse.ArgumentParser(
        prog="mcp-tap",
        description="Transparent MCP stdio monitor. Wraps any MCP server, "
                    "captures all JSON-RPC traffic to a tamper-evident audit log.",
    )
    parser.add_argument(
        "--server",
        required=True,
        help="Server command to wrap (e.g., 'npx @modelcontextprotocol/server-filesystem ./data')",
    )
    parser.add_argument(
        "--log",
        required=True,
        help="Path to the JSONL audit log file. MUST be outside the agent's accessible scope.",
    )
    parser.add_argument(
        "--server-id",
        default="unknown",
        help="Identifier for this server instance (used in log entries for multi-server correlation).",
    )
    parser.add_argument(
        "--sensitivity",
        choices=["full", "redact", "hash", "metadata"],
        default="full",
        help="Sensitive data handling mode. "
             "full=log everything (default, for testing). "
             "redact=regex-replace common secrets. "
             "hash=SHA-256 hash param values. "
             "metadata=log method/timing only, no params.",
    )
    parser.add_argument(
        "--session-id",
        default=None,
        help="Shared session identifier for correlating logs across "
             "multiple mcp-tap instances in the same experiment run. "
             "If not provided, a random ID is generated.",
    )

    args = parser.parse_args()

    # Validate log path is not inside an agent-accessible directory
    log_path = Path(args.log).resolve()

    # Extract the server's working directory from the command
    # (heuristic: last argument that looks like a path)
    server_parts = args.server.split()
    for part in reversed(server_parts):
        candidate = Path(part)
        try:
            resolved = candidate.resolve()
            if resolved.is_dir():
                if str(log_path).startswith(str(resolved)):
                    print(
                        f"mcp-tap: REFUSING to start. Log path ({log_path}) "
                        f"is inside the server's directory ({resolved}). "
                        f"An agent with filesystem access could tamper with the log. "
                        f"Use a log path OUTSIDE the server's scope.",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                break
        except (OSError, ValueError):
            continue

    # Initialize HMAC key
    hmac_key = get_hmac_key()

    # Initialize logger
    logger = AuditLogger(
        log_path=str(log_path),
        server_id=args.server_id,
        sensitivity=args.sensitivity,
        hmac_key=hmac_key,
        session_id=args.session_id,
    )

    # Parse and spawn the server
    server_cmd = parse_server_command(args.server)
    logger.log_lifecycle("server_start", {"command": server_cmd})

    try:
        proc = subprocess.Popen(
            server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as e:
        logger.log_lifecycle("server_start_failed", {"error": str(e)})
        print(f"mcp-tap: failed to start server: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        logger.log_lifecycle("server_start_failed", {"error": str(e)})
        print(f"mcp-tap: failed to start server: {e}", file=sys.stderr)
        sys.exit(1)

    logger.log_lifecycle("server_started", {"pid": proc.pid})

    # Set up shutdown coordination
    shutdown = threading.Event()

    # Relay threads
    # client_to_server: read from OUR stdin, forward to server's stdin
    # When client stdin closes (EOF), close server's stdin so server
    # can flush responses and exit naturally.
    c2s = threading.Thread(
        target=relay_stream,
        args=(sys.stdin.buffer, proc.stdin, logger, "client_to_server", shutdown),
        kwargs={"close_on_eof": proc.stdin},
        daemon=True,
        name="mcp-tap-c2s",
    )

    # server_to_client: read from server's stdout, forward to OUR stdout
    # When server stdout closes (server exited), set shutdown.
    s2c = threading.Thread(
        target=relay_stream,
        args=(proc.stdout, sys.stdout.buffer, logger, "server_to_client", shutdown),
        daemon=True,
        name="mcp-tap-s2c",
    )

    # stderr passthrough (no logging, just forward for debugging)
    def relay_stderr():
        try:
            for line in iter(proc.stderr.readline, b""):
                if shutdown.is_set():
                    break
                sys.stderr.buffer.write(line)
                sys.stderr.buffer.flush()
        except Exception:
            pass

    stderr_thread = threading.Thread(target=relay_stderr, daemon=True, name="mcp-tap-stderr")

    # Start all relay threads
    c2s.start()
    s2c.start()
    stderr_thread.start()

    # Wait for the server process to exit or shutdown signal
    try:
        proc.wait()
    except KeyboardInterrupt:
        logger.log_lifecycle("interrupted")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    shutdown.set()

    # Log final state
    exit_code = proc.returncode
    logger.log_lifecycle("server_stopped", {"exit_code": exit_code})
    logger.close()

    # Wait briefly for relay threads to drain
    c2s.join(timeout=2)
    s2c.join(timeout=2)

    sys.exit(exit_code if exit_code is not None else 0)


if __name__ == "__main__":
    main()
