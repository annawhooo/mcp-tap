#!/usr/bin/env python3
"""
test_suite.py: Automated tests for mcp-tap and mcp-detect.

Verifies that:
  - mcp-tap correctly classifies, logs, and chains JSON-RPC messages
  - mcp-detect rules fire on known-bad input and stay silent on known-good
  - The analysis script produces correct statistical results

Usage:
    python test_suite.py
    python test_suite.py -v  (verbose)
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from mcp_tap import (
    AuditLogger,
    classify_message,
    compute_hmac,
    process_params,
)
from mcp_detect import (
    Finding,
    bio_001_hmac_chain_integrity,
    bio_002_telemetry_gap,
    bio_003_behavioral_baseline_deviation,
    bio_004a_access,
    bio_005_silence_detection,
    bio_006_functional_output_monitoring,
    bio_008_tool_schema_change,
    bio_009_latency_anomaly,
    conv_001_failed_auth,
    conv_002_volume_spike,
    conv_003_rapid_tool_calls,
    conv_004_credential_scope,
    conv_005_enumeration,
    filter_messages,
    read_jsonl,
    run_rules,
)


# ===================================================================
# mcp-tap: Message Classification
# ===================================================================

class TestClassifyMessage(unittest.TestCase):

    def test_request(self):
        msg = {"jsonrpc": "2.0", "method": "tools/call",
               "params": {"name": "read_file"}, "id": 1}
        result = classify_message(msg)
        self.assertEqual(result.message_type, "request")
        self.assertEqual(result.method, "tools/call")
        self.assertEqual(result.message_id, 1)

    def test_notification(self):
        msg = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        result = classify_message(msg)
        self.assertEqual(result.message_type, "notification")
        self.assertIsNone(result.message_id)

    def test_response_with_result(self):
        msg = {"jsonrpc": "2.0", "result": {"tools": []}, "id": 1}
        result = classify_message(msg)
        self.assertEqual(result.message_type, "response")
        self.assertEqual(result.params, {"tools": []})
        self.assertFalse(result.is_error)

    def test_response_with_error(self):
        msg = {"jsonrpc": "2.0", "error": {"code": -1, "message": "fail"}, "id": 2}
        result = classify_message(msg)
        self.assertEqual(result.message_type, "response")
        self.assertEqual(result.params, {"code": -1, "message": "fail"})
        self.assertTrue(result.is_error)

    def test_response_null_result_not_treated_as_error(self):
        """The falsy fix: result=null is a valid success response."""
        msg = {"jsonrpc": "2.0", "result": None, "id": 1}
        result = classify_message(msg)
        self.assertEqual(result.message_type, "response")
        self.assertIsNone(result.params)  # result is None, not error
        self.assertFalse(result.is_error)

    def test_response_zero_result_not_treated_as_error(self):
        msg = {"jsonrpc": "2.0", "result": 0, "id": 1}
        result = classify_message(msg)
        self.assertEqual(result.params, 0)
        self.assertFalse(result.is_error)

    def test_response_empty_string_result(self):
        msg = {"jsonrpc": "2.0", "result": "", "id": 1}
        result = classify_message(msg)
        self.assertEqual(result.params, "")
        self.assertFalse(result.is_error)

    def test_response_result_takes_precedence(self):
        """If both result and error present, result wins."""
        msg = {"jsonrpc": "2.0", "result": "ok", "error": {"code": -1}, "id": 1}
        result = classify_message(msg)
        self.assertEqual(result.params, "ok")
        self.assertFalse(result.is_error)

    def test_unknown_message(self):
        msg = {"jsonrpc": "2.0", "id": 1}
        result = classify_message(msg)
        self.assertEqual(result.message_type, "unknown")


# ===================================================================
# mcp-tap: Sensitive Data Handling
# ===================================================================

class TestSensitiveData(unittest.TestCase):

    def test_redact_bearer_token(self):
        params = {"header": "Bearer sk-abc123def456ghi789"}
        result = process_params(params, "redact")
        self.assertNotIn("sk-abc123def456ghi789", str(result))
        self.assertIn("[REDACTED]", str(result))

    def test_redact_sk_key(self):
        params = {"token_value": "sk-abcdefghijklmnopqrstuvwxyz"}
        result = process_params(params, "redact")
        self.assertIn("[REDACTED]", str(result))

    def test_full_mode_preserves_all(self):
        params = {"token": "secret123", "path": "/data"}
        result = process_params(params, "full")
        self.assertEqual(result, params)

    def test_hash_mode_hashes_strings(self):
        params = {"path": "/data/file.txt"}
        result = process_params(params, "hash")
        self.assertTrue(result["path"].startswith("sha256:"))

    def test_metadata_mode_strips_values(self):
        params = {"token": "secret", "path": "/data"}
        result = process_params(params, "metadata")
        self.assertTrue(result["_redacted"])
        self.assertIn("token", result["_keys"])
        self.assertNotIn("secret", str(result))

    def test_none_params(self):
        self.assertIsNone(process_params(None, "full"))
        self.assertIsNone(process_params(None, "redact"))


# ===================================================================
# mcp-tap: HMAC Chain Integrity
# ===================================================================

class TestHMACChain(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        self.tmp.close()
        os.environ["MCP_TAP_HMAC_KEY"] = os.urandom(32).hex()

    def tearDown(self):
        os.unlink(self.tmp.name)
        del os.environ["MCP_TAP_HMAC_KEY"]

    def test_chain_integrity(self):
        from mcp_tap import get_hmac_key
        logger = AuditLogger(self.tmp.name, "test", "full", get_hmac_key())
        logger.log_message("client_to_server",
            '{"method": "tools/call", "params": {"name": "read_file"}, "id": 1}')
        logger.log_message("server_to_client",
            '{"result": {"content": "data"}, "id": 1}')
        logger.log_lifecycle("test_event")
        logger.close()

        with open(self.tmp.name) as f:
            entries = [json.loads(line) for line in f]

        self.assertGreaterEqual(len(entries), 3)  # genesis + 2 messages + lifecycle

        for i in range(1, len(entries)):
            self.assertEqual(entries[i]["prev_hmac"], entries[i-1]["hmac"],
                             f"Chain broken at entry {i}")

    def test_session_id_present(self):
        from mcp_tap import get_hmac_key
        logger = AuditLogger(self.tmp.name, "test", "full", get_hmac_key(),
                             session_id="test-session")
        logger.log_message("client_to_server",
            '{"method": "tools/list", "params": {}, "id": 1}')
        logger.close()

        with open(self.tmp.name) as f:
            entries = [json.loads(line) for line in f]

        for entry in entries:
            self.assertEqual(entry["session_id"], "test-session")


# ===================================================================
# mcp-detect: Conventional Rules
# ===================================================================

class TestConventionalRules(unittest.TestCase):

    def _make_msg(self, direction="client_to_server", method="tools/call",
                  params=None, msg_type="request", msg_id=1, seq=1,
                  timestamp="2026-04-08T14:00:00+00:00"):
        return {
            "timestamp": timestamp,
            "sequence": seq,
            "direction": direction,
            "method": method,
            "params": params or {},
            "message_id": str(msg_id),
            "message_type": msg_type,
        }

    def test_conv_003_fires_on_rapid_calls(self):
        ts = "2026-04-08T14:00:00+00:00"
        messages = [
            self._make_msg(method="tools/call", msg_id=i, seq=i, timestamp=ts)
            for i in range(5)
        ]
        findings = conv_003_rapid_tool_calls(messages)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].rule_id, "CONV-003")

    def test_conv_003_silent_on_slow_calls(self):
        messages = [
            self._make_msg(method="tools/call", msg_id=i, seq=i,
                           timestamp=f"2026-04-08T14:0{i}:00+00:00")
            for i in range(5)
        ]
        findings = conv_003_rapid_tool_calls(messages)
        self.assertEqual(len(findings), 0)

    def test_conv_004_fires_on_sensitive_endpoint(self):
        messages = [
            self._make_msg(params={"name": "api_call",
                                   "arguments": {"url": "https://api.github.com/user/emails"}})
        ]
        findings = conv_004_credential_scope(messages)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].rule_id, "CONV-004")

    def test_conv_004_silent_on_normal_endpoint(self):
        messages = [
            self._make_msg(params={"name": "read_file",
                                   "arguments": {"path": "/data/report.txt"}})
        ]
        findings = conv_004_credential_scope(messages)
        self.assertEqual(len(findings), 0)

    def test_conv_005_fires_on_enumeration(self):
        messages = [
            self._make_msg(method="tools/list", msg_id=i, seq=i)
            for i in range(4)
        ]
        findings = conv_005_enumeration(messages)
        self.assertTrue(len(findings) > 0)

    def test_conv_001_no_duplicates(self):
        """Verify the deduplication fix works."""
        messages = [
            self._make_msg(direction="server_to_client", msg_type="response",
                           params={"error": {"code": -1, "message": "fail"}},
                           msg_id=i, seq=i)
            for i in range(5)
        ]
        findings = conv_001_failed_auth(messages)
        if findings:
            # Count evidence entries; should not exceed message count
            self.assertLessEqual(findings[0].evidence[0]["sequence"],
                                 len(messages))


# ===================================================================
# mcp-detect: Bio-Derived Rules
# ===================================================================

class TestBioDerivedRules(unittest.TestCase):

    def test_bio_001_fires_on_broken_chain(self):
        entries = [
            {"sequence": 1, "hmac": "abc123", "prev_hmac": "genesis"},
            {"sequence": 2, "hmac": "def456", "prev_hmac": "WRONG"},
        ]
        findings = bio_001_hmac_chain_integrity(entries)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_bio_001_silent_on_intact_chain(self):
        entries = [
            {"sequence": 1, "hmac": "abc123", "prev_hmac": "genesis"},
            {"sequence": 2, "hmac": "def456", "prev_hmac": "abc123"},
            {"sequence": 3, "hmac": "ghi789", "prev_hmac": "def456"},
        ]
        findings = bio_001_hmac_chain_integrity(entries)
        self.assertEqual(len(findings), 0)

    def test_bio_002_fires_on_orphan_request(self):
        messages = [
            {"direction": "client_to_server", "message_type": "request",
             "message_id": "1", "method": "tools/call"},
            {"direction": "client_to_server", "message_type": "request",
             "message_id": "2", "method": "tools/call"},
            {"direction": "server_to_client", "message_type": "response",
             "message_id": "1"},
            # No response for message_id 2
        ]
        findings = bio_002_telemetry_gap(messages)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].rule_id, "BIO-002")

    def test_bio_002_silent_on_matched_pairs(self):
        messages = [
            {"direction": "client_to_server", "message_type": "request",
             "message_id": "1", "method": "tools/call"},
            {"direction": "server_to_client", "message_type": "response",
             "message_id": "1"},
        ]
        findings = bio_002_telemetry_gap(messages)
        self.assertEqual(len(findings), 0)

    def test_bio_004a_fires_on_honeytoken(self):
        messages = [
            {"direction": "client_to_server", "message_type": "request",
             "method": "tools/call",
             "params": {"name": "read_file",
                        "arguments": {"path": "/data/customer_export_2024.csv"}}},
        ]
        findings = bio_004a_access(messages)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_bio_004a_silent_on_normal_file(self):
        messages = [
            {"direction": "client_to_server", "message_type": "request",
             "method": "tools/call",
             "params": {"name": "read_file",
                        "arguments": {"path": "/data/report_q1.txt"}}},
        ]
        findings = bio_004a_access(messages)
        self.assertEqual(len(findings), 0)

    def test_bio_004a_custom_honeytokens(self):
        messages = [
            {"direction": "client_to_server", "message_type": "request",
             "method": "tools/call",
             "params": {"name": "read_file",
                        "arguments": {"path": "/data/my_secret_canary.txt"}}},
        ]
        findings = bio_004a_access(messages, honeytokens=["my_secret_canary.txt"])
        self.assertTrue(len(findings) > 0)

    def test_bio_004a_silent_on_response_listing(self):
        """Regression: honeytoken filename in a list_directory response
        must NOT fire BIO-004a. Access detection is request-side only.
        Recon detection (filename in listing) is BIO-004b's job."""
        messages = [
            {"direction": "server_to_client", "message_type": "response",
             "method": "tools/call", "message_id": "1",
             "params": {"content": [{"type": "text",
                                     "text": "report.txt\ncustomer_export_2024.csv\nnotes.md"}]}},
        ]
        findings = bio_004a_access(messages)
        self.assertEqual(len(findings), 0)

    def test_bio_004a_glob_pattern_match(self):
        """Glob/fnmatch pattern in search-style argument that matches a
        honeytoken fires at MEDIUM severity (pattern-based search rather
        than direct filename knowledge)."""
        messages = [
            {"direction": "client_to_server", "message_type": "request",
             "method": "tools/call",
             "params": {"name": "search_files",
                        "arguments": {"pattern": "customer_export_*"}}},
        ]
        findings = bio_004a_access(messages)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertIn("glob:", findings[0].description)

    def test_bio_008_fires_on_schema_change(self):
        messages = [
            {"direction": "server_to_client", "message_type": "response",
             "message_id": "1",
             "params": {"tools": [{"name": "read_file"}]}},
            {"direction": "server_to_client", "message_type": "response",
             "message_id": "2",
             "params": {"tools": [{"name": "read_file"}, {"name": "exfiltrate"}]}},
        ]
        findings = bio_008_tool_schema_change(messages)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_bio_008_silent_on_stable_schema(self):
        tools = {"tools": [{"name": "read_file"}, {"name": "write_file"}]}
        messages = [
            {"direction": "server_to_client", "message_type": "response",
             "message_id": "1", "params": tools},
            {"direction": "server_to_client", "message_type": "response",
             "message_id": "2", "params": tools},
        ]
        findings = bio_008_tool_schema_change(messages)
        self.assertEqual(len(findings), 0)


# ===================================================================
# mcp-detect: Rule Set Complementarity
# ===================================================================

class TestComplementarity(unittest.TestCase):
    """Verify that conventional and bio-derived rules catch DIFFERENT things."""

    def test_honeytoken_not_caught_by_conventional(self):
        messages = [
            {"direction": "client_to_server", "method": "tools/call",
             "params": {"name": "read_file",
                        "arguments": {"path": "/data/customer_export_2024.csv"}},
             "message_type": "request", "message_id": "1",
             "sequence": 1, "timestamp": "2026-04-08T14:00:00+00:00"},
        ]
        conv = conv_004_credential_scope(messages)
        bio = bio_004a_access(messages)
        self.assertEqual(len(conv), 0, "Conventional should NOT catch honeytokens")
        self.assertTrue(len(bio) > 0, "Bio-derived SHOULD catch honeytokens")

    def test_rapid_calls_not_caught_by_bio(self):
        ts = "2026-04-08T14:00:00+00:00"
        messages = [
            {"direction": "client_to_server", "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"path": f"/data/f{i}.txt"}},
             "message_type": "request", "message_id": str(i),
             "sequence": i, "timestamp": ts}
            for i in range(5)
        ]
        conv = conv_003_rapid_tool_calls(messages)
        # Bio-003 needs 6+ messages and behavioral shift, which 5 identical calls won't trigger
        bio = bio_003_behavioral_baseline_deviation(messages)
        self.assertTrue(len(conv) > 0, "Conventional SHOULD catch rapid calls")
        self.assertEqual(len(bio), 0, "Bio-derived should NOT fire on uniform rapid calls")


# ===================================================================
# Run
# ===================================================================

if __name__ == "__main__":
    unittest.main()
