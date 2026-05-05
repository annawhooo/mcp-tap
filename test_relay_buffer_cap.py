"""
Tests for fix #9 - MAX_RELAY_BUFFER_BYTES cap in relay_stream.

The relay_stream function reads bytes from `source` (typically a process
stdout pipe), accumulates them into a buffer until a complete JSON-RPC
message is parsed, then forwards to `dest`. Without the cap, a server
that streams unparseable bytes without a JSON terminator would grow the
buffer until OOM.

These tests use BytesIO + a Done sentinel to simulate a bytes-producing
source without involving real subprocesses. relay_stream's interface
makes it cleanly testable: it takes file-like objects, a logger, and
a shutdown event.
"""

import io
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

import mcp_tap
from mcp_tap import (
    AuditLogger,
    MAX_RELAY_BUFFER_BYTES,
    relay_stream,
)


class _BlockingBytesSource:
    """
    File-like source that returns chunks one readline() at a time, then
    blocks (or returns b'' for EOF). Used to drive relay_stream in tests
    without spinning up a real subprocess.
    """
    def __init__(self, chunks: list[bytes]):
        self._chunks = list(chunks)
        self._lock = threading.Lock()
        self._eof = False

    def readline(self) -> bytes:
        with self._lock:
            if self._chunks:
                return self._chunks.pop(0)
            self._eof = True
            return b""


class TestRelayBufferCap(unittest.TestCase):
    """Verify the MAX_RELAY_BUFFER_BYTES cap drops oversized buffers."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="mcp-tap-fix9-")
        self.log_path = Path(self.tmpdir) / "audit.jsonl"
        self.test_key = bytes.fromhex(os.urandom(32).hex())
        self.logger = AuditLogger(
            log_path=str(self.log_path),
            server_id="test",
            sensitivity="full",
            hmac_key=self.test_key,
            session_id="fix9-test",
        )
        self.shutdown = threading.Event()

    def tearDown(self):
        self.logger.close()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _read_log_entries(self) -> list[dict]:
        import json
        with open(self.log_path, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_oversized_buffer_triggers_overflow_event(self):
        """
        A single chunk larger than MAX_RELAY_BUFFER_BYTES (no JSON
        terminator) should be dropped, log a relay_buffer_overflow
        lifecycle event, and the wrapper should survive (no crash,
        no exception propagation).
        """
        # 17 MB of newlineless garbage — definitely over the 16 MB cap.
        # Single chunk so it lands in the buffer in one readline() call.
        big_chunk = b"x" * (MAX_RELAY_BUFFER_BYTES + 1024 * 1024)
        source = _BlockingBytesSource([big_chunk])
        dest = io.BytesIO()

        relay_stream(
            source=source,
            dest=dest,
            logger=self.logger,
            direction="server_to_client",
            shutdown_event=self.shutdown,
        )

        entries = self._read_log_entries()
        overflow_events = [e for e in entries
                           if e.get("event") == "relay_buffer_overflow"]
        self.assertEqual(len(overflow_events), 1,
                         f"Expected exactly one overflow event, got "
                         f"{len(overflow_events)}: {overflow_events}")
        details = overflow_events[0].get("details") or {}
        self.assertEqual(details.get("direction"), "server_to_client")
        self.assertGreater(details.get("dropped_bytes"), MAX_RELAY_BUFFER_BYTES)
        self.assertEqual(details.get("cap"), MAX_RELAY_BUFFER_BYTES)

    def test_relay_continues_after_overflow(self):
        """
        After dropping an oversized buffer, the relay must keep reading
        the next chunk. A valid JSON message arriving after the overflow
        should be logged and forwarded normally.
        """
        big_chunk = b"x" * (MAX_RELAY_BUFFER_BYTES + 1024)
        valid_json = (b'{"jsonrpc":"2.0","method":"tools/list",'
                      b'"params":{},"id":1}\n')
        source = _BlockingBytesSource([big_chunk, valid_json])
        dest = io.BytesIO()

        relay_stream(
            source=source,
            dest=dest,
            logger=self.logger,
            direction="client_to_server",
            shutdown_event=self.shutdown,
        )

        entries = self._read_log_entries()

        # Overflow event should be present
        overflow_events = [e for e in entries
                           if e.get("event") == "relay_buffer_overflow"]
        self.assertEqual(len(overflow_events), 1)

        # The valid JSON that came after should also have been logged
        message_events = [e for e in entries
                          if e.get("method") == "tools/list"]
        self.assertEqual(len(message_events), 1,
                         "Valid JSON after overflow should still be logged")

        # And forwarded to dest
        self.assertIn(b"tools/list", dest.getvalue(),
                      "Valid JSON after overflow should still reach dest")

    def test_normal_traffic_does_not_trigger_overflow(self):
        """
        Sanity check: ordinary-sized JSON-RPC messages don't trip the cap.
        Three modest messages, total well under the cap.
        """
        msgs = [
            b'{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}\n',
            b'{"jsonrpc":"2.0","result":{"tools":[]},"id":1}\n',
            b'{"jsonrpc":"2.0","method":"tools/call",'
            b'"params":{"name":"x"},"id":2}\n',
        ]
        source = _BlockingBytesSource(msgs)
        dest = io.BytesIO()

        relay_stream(
            source=source,
            dest=dest,
            logger=self.logger,
            direction="server_to_client",
            shutdown_event=self.shutdown,
        )

        entries = self._read_log_entries()
        overflow_events = [e for e in entries
                           if e.get("event") == "relay_buffer_overflow"]
        self.assertEqual(len(overflow_events), 0,
                         "Normal traffic should not trigger overflow")

    def test_chain_intact_after_overflow(self):
        """
        The overflow lifecycle entry must be HMAC-chained correctly.
        BIO-001 (chain integrity) should still pass over the resulting log.
        """
        big_chunk = b"x" * (MAX_RELAY_BUFFER_BYTES + 1024)
        source = _BlockingBytesSource([big_chunk])
        dest = io.BytesIO()

        relay_stream(
            source=source,
            dest=dest,
            logger=self.logger,
            direction="server_to_client",
            shutdown_event=self.shutdown,
        )

        entries = self._read_log_entries()
        # Verify chain continuity: each entry's prev_hmac equals the
        # previous entry's hmac.
        for i in range(1, len(entries)):
            self.assertEqual(
                entries[i]["prev_hmac"], entries[i - 1]["hmac"],
                f"HMAC chain broken at entry {i} ({entries[i].get('event')})")


if __name__ == "__main__":
    unittest.main()
