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
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Cross-platform exclusive file lock (sidecar .lock file)
# ---------------------------------------------------------------------------
#
# Two mcp-tap instances writing to the same log file would silently
# corrupt the HMAC chain: each writer computes prev_hmac from its own
# last entry, so interleaved lines produce a chain that BIO-001 will
# flag as "tampered" even though the real cause is concurrency. The
# fix is to refuse to start if another process already holds the log.
#
# We use a sidecar <logfile>.lock rather than locking bytes in the
# log itself, which avoids edge cases with locking byte-ranges of an
# empty file (particularly on Windows msvcrt.locking).

if os.name == "nt":
    import msvcrt

    def _try_exclusive_lock(fileobj) -> bool:
        # msvcrt.locking locks a byte range at the current file offset.
        # Ensure there's a byte at offset 0 to lock; seek there; lock it.
        # Any OSError/PermissionError along the way (including another
        # process already holding the range) means "couldn't acquire".
        try:
            fileobj.seek(0, 2)  # end
            if fileobj.tell() == 0:
                fileobj.write(b"\0")
                fileobj.flush()
            fileobj.seek(0)
            msvcrt.locking(fileobj.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False

    def _release_lock(fileobj) -> None:
        try:
            fileobj.seek(0)
            msvcrt.locking(fileobj.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
else:
    import fcntl

    def _try_exclusive_lock(fileobj) -> bool:
        try:
            fcntl.flock(fileobj.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def _release_lock(fileobj) -> None:
        try:
            fcntl.flock(fileobj.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass


def _acquire_log_lock(log_path: Path):
    """
    Acquire an exclusive sidecar lock for `log_path`.

    Returns the open lock file handle on success. Exits with code 1 if
    another process holds the lock — concurrent writers would corrupt
    the HMAC chain.
    """
    lock_path = log_path.with_name(log_path.name + ".lock")
    # Open with "ab+" (append-binary, read/write, no truncate). Truncation
    # via "wb" could race with another process's pending lock on byte 0
    # and surface as a PermissionError on close.
    try:
        lock_file = open(lock_path, "ab+")
    except OSError as e:
        print(f"mcp-tap: cannot open lock file {lock_path}: {e}", file=sys.stderr)
        sys.exit(1)

    if not _try_exclusive_lock(lock_file):
        # Best-effort close; if another process holds the lock, close may
        # still succeed even though we never acquired the range.
        try:
            lock_file.close()
        except OSError:
            pass
        print(
            f"mcp-tap: another process is already writing to {log_path} "
            f"(lock held on {lock_path}). Concurrent writers would corrupt "
            f"the HMAC chain. Refusing to start.",
            file=sys.stderr,
        )
        sys.exit(1)
    return lock_file


# ---------------------------------------------------------------------------
# HMAC Chain (reuses coffer-mcp pattern)
# ---------------------------------------------------------------------------

HMAC_KEY_BYTES = 32  # 256 bits, matches SHA-256 block size

# Cap on the per-stream relay buffer. JSON-RPC messages should never
# approach this; typical MCP traffic is a few hundred KB at most.
# A pathological or hostile server emitting an unbounded stream of bytes
# without a parseable JSON terminator would otherwise cause buffer growth
# without limit until OOM. On overflow we drop the buffer, emit a
# 'relay_buffer_overflow' lifecycle event, and continue reading — the
# wrapper survives, the audit log records the event, and downstream
# detection rules can flag repeated overflows as their own signal.
MAX_RELAY_BUFFER_BYTES = 16 * 1024 * 1024  # 16 MB


def _load_key_file(key_path: Path) -> bytes:
    """Read and validate a hex-encoded key file. Raises SystemExit on invalid content."""
    raw = key_path.read_text().strip()
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        print(
            f"mcp-tap: key file {key_path} does not contain valid hex. "
            f"Delete it to regenerate, or restore a valid key.",
            file=sys.stderr,
        )
        sys.exit(1)
    if len(key) < 16:
        print(
            f"mcp-tap: key file {key_path} holds a {len(key)}-byte key, "
            f"which is too short. Delete it to regenerate.",
            file=sys.stderr,
        )
        sys.exit(1)
    return key


def _validate_production_keyfile(key_path: Path) -> None:
    """
    Strict checks for an HMAC keyfile in production mode.

    Production mode requires the key to live somewhere the wrapped agent
    cannot reach. We can't prove that mechanically, but we can catch the
    obvious mistakes:
      - Path under the user's home directory (the most common laptop default)
      - Permissive file mode (only 0600 or tighter is acceptable on POSIX)
    Anything else is allowed; production deployments are expected to mount
    keys from /run/secrets, /var/run, or a similar isolated path.
    """
    resolved = key_path.resolve()
    home = Path.home().resolve()
    try:
        if resolved.is_relative_to(home):
            print(
                f"mcp-tap: --production refuses HMAC keyfile under $HOME "
                f"({resolved}). The agent runs as the same user and can read "
                f"any file in $HOME. Mount the key from /run/secrets, a "
                f"separate volume, or use MCP_TAP_HMAC_KEY from a secret "
                f"manager. See docs/production-deployment.md.",
                file=sys.stderr,
            )
            sys.exit(1)
    except AttributeError:
        # Py 3.8 fallback
        try:
            resolved.relative_to(home)
            under_home = True
        except ValueError:
            under_home = False
        if under_home:
            print(
                f"mcp-tap: --production refuses HMAC keyfile under $HOME "
                f"({resolved}).",
                file=sys.stderr,
            )
            sys.exit(1)

    if os.name != "nt":
        try:
            mode = key_path.stat().st_mode & 0o777
            if mode & 0o077:
                print(
                    f"mcp-tap: --production requires HMAC keyfile mode 0600 "
                    f"or tighter; {key_path} has {oct(mode)}.",
                    file=sys.stderr,
                )
                sys.exit(1)
        except OSError as e:
            print(f"mcp-tap: cannot stat HMAC keyfile {key_path}: {e}",
                  file=sys.stderr)
            sys.exit(1)


def get_hmac_key(production_mode: bool = False,
                 keyfile: "Path | None" = None) -> bytes:
    """
    Retrieve or generate the HMAC key.

    Laptop mode (default) priority:
      1. MCP_TAP_HMAC_KEY environment variable (hex-encoded)
      2. ~/.mcp-tap-key file (hex-encoded, 600 on POSIX)
      3. Generate a new key and persist it to ~/.mcp-tap-key

    Production mode (--production) priority:
      1. --hmac-key-file PATH (must be outside $HOME, mode 0600)
      2. MCP_TAP_HMAC_KEY environment variable
      No fallback: production refuses to start without one of these.
      Auto-generation to $HOME is disabled because the agent runs as the
      same user and can read anything in $HOME.

    For deployment: source MCP_TAP_HMAC_KEY from a secret manager (GCP
    Secret Manager, AWS Secrets Manager, HashiCorp Vault) at startup.
    """
    # Production mode: explicit keyfile path takes priority.
    if production_mode and keyfile is not None:
        _validate_production_keyfile(keyfile)
        return _load_key_file(keyfile)

    env_key = os.environ.get("MCP_TAP_HMAC_KEY")
    if env_key:
        try:
            key = bytes.fromhex(env_key.strip())
        except ValueError:
            print(
                "mcp-tap: MCP_TAP_HMAC_KEY is not valid hex.",
                file=sys.stderr,
            )
            sys.exit(1)
        if len(key) < 16:
            print(
                f"mcp-tap: MCP_TAP_HMAC_KEY is only {len(key)} bytes "
                f"(need >= 16).",
                file=sys.stderr,
            )
            sys.exit(1)
        return key

    if production_mode:
        print(
            "mcp-tap: --production refuses to start without an external HMAC "
            "key. Provide one via:\n"
            "  --hmac-key-file PATH  (path must be outside $HOME, mode 0600)\n"
            "  MCP_TAP_HMAC_KEY env  (hex-encoded, sourced from a secret "
            "manager)\n"
            "Auto-generation to ~/.mcp-tap-key is disabled in production "
            "mode because the agent runs as the same user and could read "
            "the key. See docs/production-deployment.md.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Laptop mode fallback: keyfile in $HOME, auto-generate if missing.
    key_path = Path.home() / ".mcp-tap-key"
    if key_path.exists():
        # Best-effort warning if the key file is readable by others on POSIX.
        if os.name != "nt":
            try:
                mode = key_path.stat().st_mode & 0o777
                if mode & 0o077:
                    print(
                        f"mcp-tap: warning: {key_path} has permissive mode "
                        f"{oct(mode)}; tightening to 0600.",
                        file=sys.stderr,
                    )
                    key_path.chmod(0o600)
            except OSError:
                pass
        return _load_key_file(key_path)

    new_key = os.urandom(HMAC_KEY_BYTES)
    key_path.write_text(new_key.hex())
    # Restrict permissions on Unix; best-effort on Windows.
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
#
# All modes operate structurally on the parsed params tree — never by
# serializing to JSON and regex-replacing. Serialize-then-regex can
# destroy JSON punctuation (e.g. greedy \S+ eating `","next":"value`)
# and leave the mode unable to round-trip through json.loads.

# Keys whose *value* should always be replaced wholesale, regardless
# of the value's content. Matched case-insensitively against the key name.
SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|auth|credential|bearer)",
    re.IGNORECASE,
)

# Patterns applied to string *values* whose key didn't match above.
# Replacements include the literal [REDACTED] marker so downstream
# readers can distinguish redacted from original content.
VALUE_PATTERNS = [
    (re.compile(r"Bearer\s+\S+", re.IGNORECASE), "Bearer [REDACTED]"),
    (re.compile(r"sk-[a-zA-Z0-9_-]{20,}"), "[REDACTED]"),
    (re.compile(r"ghp_[a-zA-Z0-9]{30,}"), "[REDACTED]"),  # GitHub PATs
    (re.compile(r"xox[baprs]-[a-zA-Z0-9-]{10,}"), "[REDACTED]"),  # Slack tokens
]


def _hash_str(s: str) -> str:
    return f"sha256:{hashlib.sha256(s.encode('utf-8')).hexdigest()[:16]}"


def _redact_str(s: str) -> str:
    for pattern, replacement in VALUE_PATTERNS:
        s = pattern.sub(replacement, s)
    return s


def _walk(obj, string_fn, key=None):
    """
    Walk a JSON-like tree, applying string_fn(value, key) to every string.
    Recurses into dicts and lists. Non-string scalars pass through unchanged.
    """
    if isinstance(obj, dict):
        return {k: _walk(v, string_fn, key=k) for k, v in obj.items()}
    if isinstance(obj, list):
        # List elements inherit the parent key (e.g. params["tokens"][i])
        return [_walk(v, string_fn, key=key) for v in obj]
    if isinstance(obj, str):
        return string_fn(obj, key)
    return obj


def _redact_value(s: str, key) -> str:
    if key and SENSITIVE_KEY_RE.search(str(key)):
        return "[REDACTED]"
    return _redact_str(s)


def _hash_value(s: str, key) -> str:
    return _hash_str(s)


def process_params(params, mode: str):
    """Process params according to the configured sensitivity mode."""
    if params is None or mode == "full":
        return params
    if mode == "metadata":
        return {
            "_redacted": True,
            "_keys": list(params.keys()) if isinstance(params, dict) else None,
        }
    if mode == "redact":
        return _walk(params, _redact_value)
    if mode == "hash":
        return _walk(params, _hash_value)
    return params


# ---------------------------------------------------------------------------
# JSON-RPC Message Parsing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClassifiedMessage:
    """
    Structured result of classifying a JSON-RPC message.

    Fields:
      message_type: "request" | "notification" | "response" | "unknown"
      method:       JSON-RPC method name (None for responses)
      params:       For requests/notifications, the params object.
                    For responses, either the result or the error object.
      message_id:   JSON-RPC id (None for notifications / unknown).
      is_error:     True iff this is a response carrying an error object
                    (i.e. the message had an "error" key, not "result").
                    Lets downstream rules distinguish success from error
                    responses without substring-searching params.
    """
    message_type: str
    method: Optional[str]
    params: Any
    message_id: Any
    is_error: bool = False


def classify_message(msg: dict) -> ClassifiedMessage:
    """Classify a JSON-RPC message."""
    msg_id = msg.get("id")

    if "method" in msg:
        method = msg["method"]
        params = msg.get("params")
        if msg_id is not None:
            return ClassifiedMessage("request", method, params, msg_id)
        return ClassifiedMessage("notification", method, params, None)

    if "result" in msg or "error" in msg:
        # Check key existence, not truthiness. A response with
        # result=null or result=0 is valid and must not be treated
        # as an error just because the value is falsy.
        if "result" in msg:
            return ClassifiedMessage("response", None, msg.get("result"), msg_id, is_error=False)
        return ClassifiedMessage("response", None, msg.get("error"), msg_id, is_error=True)

    return ClassifiedMessage("unknown", None, None, msg_id)


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """Tamper-evident JSONL audit logger with HMAC chain."""

    # Cap on in-flight request tracking. If a server never responds to a
    # request, its entry would otherwise live forever. Evict the oldest
    # when the cap is hit; latency for those responses will be logged as
    # None, which is strictly better than growing memory unbounded.
    MAX_PENDING_REQUESTS = 10_000

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
        # OrderedDict so we can cheaply evict the oldest entry when the
        # cap is hit. popitem(last=False) is FIFO eviction.
        self.pending_requests: "OrderedDict[str, float]" = OrderedDict()

        # Ensure log directory exists
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        # Acquire an exclusive lock BEFORE opening the log for append.
        # Exits if another mcp-tap is already writing this file.
        self._lock_file = _acquire_log_lock(self.log_path)

        # Open persistent file handle (avoids per-write open/close overhead).
        # Atomic create-with-mode 0600 so the file is never world-readable,
        # even briefly, on multi-user hosts. POSIX honors the mode argument;
        # on Windows the third argument is ignored and ACL inheritance applies.
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        # On Windows, also set O_BINARY-equivalent semantics via os.open's
        # default text translation off. Python opens with default umask
        # masking applied to the mode; explicit 0o600 keeps it tight even
        # if the user's umask is loose.
        fd = os.open(self.log_path, flags, 0o600)
        self._log_file = os.fdopen(fd, "a", encoding="utf-8")

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
        """Close the log file handle and release the sidecar lock."""
        if self._log_file and not self._log_file.closed:
            self._log_file.flush()
            self._log_file.close()
        lock_file = getattr(self, "_lock_file", None)
        if lock_file is not None and not lock_file.closed:
            _release_lock(lock_file)
            lock_file.close()

    def log_message(self, direction: str, raw_line: str):
        """Parse a JSON-RPC message and write an audit entry."""
        try:
            msg = json.loads(raw_line)
        except json.JSONDecodeError:
            # Not valid JSON; log as raw
            self._write_raw(direction, raw_line)
            return

        cm = classify_message(msg)
        now = time.time()
        now_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()

        # Latency tracking
        latency_ms = None
        if cm.message_type == "request" and cm.message_id is not None:
            with self.lock:
                self.pending_requests[str(cm.message_id)] = now
                # Bound the in-flight table. If a server drops responses
                # the table would otherwise grow without limit; evict FIFO
                # on overflow. Latency for evicted requests will be None.
                while len(self.pending_requests) > self.MAX_PENDING_REQUESTS:
                    self.pending_requests.popitem(last=False)
        elif cm.message_type == "response" and cm.message_id is not None:
            with self.lock:
                req_time = self.pending_requests.pop(str(cm.message_id), None)
            if req_time is not None:
                latency_ms = round((now - req_time) * 1000, 2)

        entry = {
            "timestamp": now_iso,
            "sequence": None,  # filled by _write_entry
            "session_id": self.session_id,
            "server_id": self.server_id,
            "direction": direction,
            "method": cm.method,
            "params": process_params(cm.params, self.sensitivity),
            "message_id": str(cm.message_id) if cm.message_id is not None else None,
            "message_type": cm.message_type,
            "is_error": cm.is_error if cm.message_type == "response" else None,
            "latency_ms": latency_ms,
            "hmac": "",       # filled by _write_entry
            "prev_hmac": "",  # filled by _write_entry
        }

        self._write_entry(entry)

    def _write_entry(self, entry: dict):
        """Write a single JSONL entry with HMAC chain."""
        with self.lock:
            # Defensive: if close() has already run, silently drop. The
            # alternative is a ValueError from writing to a closed file,
            # which would propagate up through a relay thread.
            if self._log_file is None or self._log_file.closed:
                return

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

            # Buffer cap: a server that streams unparseable bytes without
            # a JSON terminator would otherwise grow the buffer without
            # bound. On overflow, drop the buffer, log a lifecycle event,
            # and continue reading. The wrapper survives a misbehaving
            # server; the audit log records the overflow event so a
            # detection rule can flag it.
            if len(buffer) > MAX_RELAY_BUFFER_BYTES:
                logger.log_lifecycle("relay_buffer_overflow", {
                    "direction": direction,
                    "dropped_bytes": len(buffer),
                    "cap": MAX_RELAY_BUFFER_BYTES,
                })
                buffer = b""
                # Skip parsing this round; resume reading on next iteration.
                continue

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
    parser.add_argument(
        "--production",
        action="store_true",
        help="Enable production deployment posture. Refuses to start without "
             "an external HMAC key (MCP_TAP_HMAC_KEY env or --hmac-key-file "
             "outside $HOME), requires explicit --server-scope, and forces "
             "sensitivity to 'redact' or stricter. The shipped tool is the "
             "reference implementation for laptop use; --production makes "
             "the deployment posture described in the paper demonstrable in "
             "code. See docs/production-deployment.md.",
    )
    parser.add_argument(
        "--hmac-key-file",
        type=Path,
        default=None,
        help="Path to a file containing the hex-encoded HMAC key. In "
             "--production mode the path MUST be outside $HOME and the file "
             "MUST be mode 0600 or tighter on POSIX.",
    )
    parser.add_argument(
        "--server-scope",
        type=Path,
        default=None,
        help="Directory the wrapped server is allowed to access. Used to "
             "verify the audit log lives outside that scope. Required in "
             "--production mode; in laptop mode, falls back to the "
             "best-effort heuristic that scans the --server command for a "
             "trailing path argument.",
    )

    args = parser.parse_args()

    # ---- Production-mode validation ----
    # Order matters: validate the request before doing any I/O so failures
    # are clean refusals to start, not partial state on disk.
    if args.production:
        # Force minimum sensitivity: redact-or-stricter.
        # 'full' logs plaintext credentials; that's wrong posture for any
        # deployment whose logs ship off-host.
        if args.sensitivity == "full":
            print(
                "mcp-tap: --production forces --sensitivity to at least "
                "'redact' (was 'full'). Plaintext credentials must not "
                "land in audit logs that ship off-host. Re-run with "
                "--sensitivity redact / hash / metadata.",
                file=sys.stderr,
            )
            sys.exit(1)

        # --server-scope is required in production. The laptop heuristic
        # (scan --server for a trailing path) fails open in too many
        # configurations to rely on for a deployment posture.
        if args.server_scope is None:
            print(
                "mcp-tap: --production requires --server-scope PATH. "
                "Name the directory the wrapped server is allowed to "
                "access; mcp-tap will verify the audit log lives outside "
                "that scope before starting.",
                file=sys.stderr,
            )
            sys.exit(1)

    # Validate log path is not inside an agent-accessible directory.
    log_path = Path(args.log).resolve()

    # Server scope: explicit --server-scope wins (required in production,
    # optional in laptop). Without it, fall back to the heuristic that
    # scans the --server command for a trailing path argument.
    explicit_scope: "Path | None" = None
    if args.server_scope is not None:
        try:
            explicit_scope = args.server_scope.resolve()
        except (OSError, ValueError) as e:
            print(f"mcp-tap: cannot resolve --server-scope "
                  f"({args.server_scope}): {e}", file=sys.stderr)
            sys.exit(1)
        if not explicit_scope.is_dir():
            print(f"mcp-tap: --server-scope ({explicit_scope}) is not an "
                  f"existing directory.", file=sys.stderr)
            sys.exit(1)

    def _log_inside(scope: Path) -> bool:
        """True if log_path is inside `scope`."""
        try:
            return log_path.is_relative_to(scope)
        except AttributeError:
            try:
                log_path.relative_to(scope)
                return True
            except ValueError:
                return False

    if explicit_scope is not None:
        # Explicit scope: hard check, fail closed if log_path is inside.
        if _log_inside(explicit_scope):
            print(
                f"mcp-tap: REFUSING to start. Log path ({log_path}) is "
                f"inside --server-scope ({explicit_scope}). An agent with "
                f"filesystem access could tamper with the log.",
                file=sys.stderr,
            )
            sys.exit(1)
    elif args.production:
        # Unreachable: production validation above already required scope.
        # Belt-and-suspenders — keep this so a future change doesn't
        # silently relax the production posture.
        print("mcp-tap: --production requires --server-scope.",
              file=sys.stderr)
        sys.exit(1)
    else:
        # Laptop mode, no explicit scope: best-effort heuristic.
        # Scan --server (whitespace split — accepted as a known limitation
        # of laptop mode; production users provide --server-scope).
        scope_inferred = False
        server_parts = args.server.split()
        for part in reversed(server_parts):
            try:
                resolved = Path(part).resolve()
            except (OSError, ValueError):
                continue
            if not resolved.is_dir():
                continue
            scope_inferred = True
            if _log_inside(resolved):
                print(
                    f"mcp-tap: REFUSING to start. Log path ({log_path}) "
                    f"is inside the inferred server directory ({resolved}). "
                    f"Use a log path OUTSIDE the server's scope, or pass "
                    f"--server-scope explicitly.",
                    file=sys.stderr,
                )
                sys.exit(1)
            break

        if not scope_inferred:
            # Fail-open prevention: warn loudly so the user knows the
            # safeguard didn't engage. Laptop mode does not refuse to
            # start here (that would break too many existing setups);
            # production mode would have already exited above.
            print(
                "mcp-tap: warning: could not infer server scope from "
                "--server command. The log-path tamper check did not "
                "engage. If the log path is inside the server's accessible "
                "directory, an agent could tamper with it. Pass "
                "--server-scope PATH to make this check explicit.",
                file=sys.stderr,
            )

    # Initialize HMAC key
    hmac_key = get_hmac_key(
        production_mode=args.production,
        keyfile=args.hmac_key_file,
    )

    # Initialize logger
    logger = AuditLogger(
        log_path=str(log_path),
        server_id=args.server_id,
        sensitivity=args.sensitivity,
        hmac_key=hmac_key,
        session_id=args.session_id,
    )

    # Record startup posture in the audit log so readers can tell which
    # mode produced this log. lifecycle entries chain into the HMAC like
    # everything else, so this is tamper-evident.
    logger.log_lifecycle("startup_posture", {
        "production_mode": bool(args.production),
        "explicit_server_scope": str(explicit_scope) if explicit_scope else None,
        "sensitivity": args.sensitivity,
    })

    # Parse and spawn the server
    server_cmd = parse_server_command(args.server)
    logger.log_lifecycle("server_start", {"command": server_cmd})

    try:
        proc = subprocess.Popen(
            server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # On Windows, commands like npx/node are .cmd wrappers that
            # require shell=True to resolve. The command comes from the
            # user's own --server argument, so no injection risk.
            shell=(os.name == "nt"),
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

    # Drain relay threads BEFORE closing the log. Otherwise a thread
    # still holding a JSON line mid-parse would write to a closed file.
    # The c2s thread may be blocked in sys.stdin.readline(); it's a
    # daemon, so we bound the join and move on if it won't exit.
    c2s.join(timeout=2)
    s2c.join(timeout=2)

    # Now that no more log_message calls are in flight, it's safe to
    # write the final lifecycle entry and close the file.
    exit_code = proc.returncode
    logger.log_lifecycle("server_stopped", {"exit_code": exit_code})
    logger.close()

    sys.exit(exit_code if exit_code is not None else 0)


if __name__ == "__main__":
    main()
