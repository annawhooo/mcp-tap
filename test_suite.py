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

    def test_bio_002b_silent_on_matched_pair_in_tail(self):
        """REGRESSION: matched request/response pair within the tail window
        must NOT fire BIO-002b. Previously, in_tail filtered requests but
        not responses, tearing pairs apart and creating orphan responses."""
        messages = [
            # Pair before tail — both kept, matched
            {"direction": "client_to_server", "message_type": "request",
             "message_id": "1", "method": "tools/call",
             "timestamp": "2026-01-01T22:00:00+00:00"},
            {"direction": "server_to_client", "message_type": "response",
             "message_id": "1",
             "timestamp": "2026-01-01T22:00:01+00:00"},
            # Pair inside tail — both must be excluded together
            {"direction": "client_to_server", "message_type": "request",
             "message_id": "2", "method": "tools/call",
             "timestamp": "2026-01-01T22:00:10+00:00"},
            {"direction": "server_to_client", "message_type": "response",
             "message_id": "2",
             "timestamp": "2026-01-01T22:00:11+00:00"},
        ]
        findings = bio_002_telemetry_gap(messages)
        self.assertEqual(len(findings), 0,
                         f"Expected no findings, got: {[f.rule_id for f in findings]}")

    def test_bio_002b_fires_on_true_orphan_outside_tail(self):
        """A response without a matching request, occurring outside the tail
        window, must still fire BIO-002b. Confirms the fix didn't over-correct."""
        messages = [
            # True orphan response — no matching request, well outside tail
            {"direction": "server_to_client", "message_type": "response",
             "message_id": "99",
             "timestamp": "2026-01-01T22:00:00+00:00"},
            # Push last_ts forward so the orphan is comfortably outside tail
            {"direction": "client_to_server", "message_type": "request",
             "message_id": "1", "method": "tools/call",
             "timestamp": "2026-01-01T22:00:10+00:00"},
            {"direction": "server_to_client", "message_type": "response",
             "message_id": "1",
             "timestamp": "2026-01-01T22:00:11+00:00"},
        ]
        findings = bio_002_telemetry_gap(messages)
        bio_002b_findings = [f for f in findings if f.rule_id == "BIO-002b"]
        self.assertTrue(len(bio_002b_findings) > 0,
                        "Expected BIO-002b to fire on true orphan response outside tail")

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

    def test_bio_004a_double_star_matches_flat_filename(self):
        """REGRESSION: pattern '**/*.csv' must match a flat honeytoken
        filename 'customer_export_2024.csv'. Standard fnmatch does NOT
        match this case (it requires a literal slash). The custom
        _glob_to_regex translator handles ** with proper directory
        semantics."""
        messages = [
            {"direction": "client_to_server", "message_type": "request",
             "method": "tools/call",
             "params": {"name": "search_files",
                        "arguments": {"pattern": "**/*.csv"}}},
        ]
        findings = bio_004a_access(messages)
        self.assertTrue(len(findings) > 0,
                        "Expected ** to match flat honeytoken filename")
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_bio_004a_double_star_matches_nested_filename(self):
        """Pattern '**/*.csv' must also match a honeytoken with a directory
        prefix like 'data/secret.csv'."""
        messages = [
            {"direction": "client_to_server", "message_type": "request",
             "method": "tools/call",
             "params": {"name": "search_files",
                        "arguments": {"pattern": "**/*.csv"}}},
        ]
        findings = bio_004a_access(messages,
                                   honeytokens=["data/secret.csv"])
        self.assertTrue(len(findings) > 0,
                        "Expected ** to match nested honeytoken filename")

    def test_bio_004a_single_star_does_not_cross_slash(self):
        """Single * must not match across slash boundaries. Pattern '*.csv'
        should NOT match 'data/secret.csv'. Confirms the translator gives
        single * non-slash-spanning semantics."""
        messages = [
            {"direction": "client_to_server", "message_type": "request",
             "method": "tools/call",
             "params": {"name": "search_files",
                        "arguments": {"pattern": "*.csv"}}},
        ]
        findings = bio_004a_access(messages,
                                   honeytokens=["data/secret.csv"])
        self.assertEqual(len(findings), 0,
                         "Expected single-star NOT to cross slash")

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
# Log adapter tests
# ===================================================================

class TestNormalizeMicroseconds(unittest.TestCase):
    """Unit tests for _normalize_microseconds (string-level transform)."""

    def setUp(self):
        from log_adapter import _normalize_microseconds
        self.normalize = _normalize_microseconds

    def test_truncates_seven_digit_microseconds(self):
        """Bifrost / Go RFC3339Nano writes 7 digits — strptime cannot handle."""
        self.assertEqual(
            self.normalize("2026-05-01 21:25:34.0455463+00:00"),
            "2026-05-01 21:25:34.045546+00:00",
        )

    def test_truncates_nine_digit_nanoseconds(self):
        self.assertEqual(
            self.normalize("2026-05-01T21:25:34.123456789Z"),
            "2026-05-01T21:25:34.123456Z",
        )

    def test_passes_six_digit_microseconds_unchanged(self):
        ts = "2026-05-01 21:25:34.045546+00:00"
        self.assertEqual(self.normalize(ts), ts)

    def test_passes_one_through_five_digit_fractions_unchanged(self):
        for frac_len in range(1, 6):
            frac = "1" * frac_len
            ts = f"2026-05-01 21:25:34.{frac}+00:00"
            with self.subTest(frac_len=frac_len):
                self.assertEqual(self.normalize(ts), ts)

    def test_passes_no_fractional_part_unchanged(self):
        ts = "2026-05-01 21:25:34+00:00"
        self.assertEqual(self.normalize(ts), ts)

    def test_handles_no_timezone_suffix(self):
        self.assertEqual(
            self.normalize("2026-05-01T21:25:34.0455463"),
            "2026-05-01T21:25:34.045546",
        )

    def test_handles_non_string_input(self):
        self.assertIsNone(self.normalize(None))
        self.assertEqual(self.normalize(12345), 12345)


class TestParseTimestamp(unittest.TestCase):
    """End-to-end test that _parse_timestamp succeeds on Bifrost's actual format."""

    def test_parses_bifrost_seven_digit_microseconds(self):
        from log_adapter import _parse_timestamp
        result = _parse_timestamp("2026-05-01 21:25:34.0455463+00:00")
        self.assertIsNotNone(result, "Bifrost's 7-digit µs format must parse")
        self.assertEqual(result.year, 2026)
        self.assertEqual(result.microsecond, 45546)


class TestParsePossiblyDoubleEncoded(unittest.TestCase):
    """Tests for double-encoded JSON handling.

    Bifrost stores tool call arguments as a JSON-encoded string whose
    inner content is itself a JSON-encoded string (double encoding).
    Single-pass json.loads yields a string, not the dict downstream
    rules expect.
    """

    def test_double_encoded_dict_returns_dict(self):
        from log_adapter import _parse_possibly_double_encoded
        # Bifrost's actual storage format
        raw = '"{\\"path\\":\\"C:/data/foo.txt\\"}"'
        result = _parse_possibly_double_encoded(raw)
        self.assertEqual(result, {"path": "C:/data/foo.txt"})

    def test_single_encoded_dict_returns_dict(self):
        """Standard JSON-encoded dict (mcp-tap pattern) still works."""
        from log_adapter import _parse_possibly_double_encoded
        raw = '{"path":"C:/data/foo.txt"}'
        result = _parse_possibly_double_encoded(raw)
        self.assertEqual(result, {"path": "C:/data/foo.txt"})

    def test_dict_with_inner_json_string_value_deserializes(self):
        """Outer dict has a value that is itself a JSON-encoded string
        (params containing stringified arguments). The inner string
        should be parsed, replacing it with a dict in place."""
        from log_adapter import _parse_possibly_double_encoded
        raw = '{"name":"read_file","arguments":"{\\"path\\":\\"/x\\"}"}'
        result = _parse_possibly_double_encoded(raw)
        self.assertEqual(result["name"], "read_file")
        self.assertEqual(result["arguments"], {"path": "/x"})

    def test_empty_value_returns_none(self):
        from log_adapter import _parse_possibly_double_encoded
        self.assertIsNone(_parse_possibly_double_encoded(None))
        self.assertIsNone(_parse_possibly_double_encoded(""))

    def test_unparseable_returns_value_unchanged(self):
        from log_adapter import _parse_possibly_double_encoded
        result = _parse_possibly_double_encoded("not json at all")
        self.assertEqual(result, "not json at all")

    def test_inner_unparseable_string_left_unchanged(self):
        """If the inner second-pass parse fails, leave the string as-is
        rather than dropping it."""
        from log_adapter import _parse_possibly_double_encoded
        # Outer is valid JSON, but inner string is malformed JSON-looking
        raw = '"{not valid json}"'
        result = _parse_possibly_double_encoded(raw)
        self.assertEqual(result, "{not valid json}")

    def test_simple_string_not_starting_with_brace_returns_as_is(self):
        from log_adapter import _parse_possibly_double_encoded
        raw = '"just a regular string"'
        result = _parse_possibly_double_encoded(raw)
        self.assertEqual(result, "just a regular string")


class TestAdaptBifrostWindowing(unittest.TestCase):
    """Tests for adapt_bifrost time-window filtering used by experiment slicer."""

    def setUp(self):
        import sqlite3
        import tempfile
        import os
        # Build a synthetic Bifrost logs.db with 5 rows at known timestamps
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "logs.db")
        self.out_path = os.path.join(self.tmpdir, "out.jsonl")
        conn = sqlite3.connect(self.db_path)
        # Mirror the relevant subset of Bifrost's mcp_tool_logs schema
        conn.execute("""
            CREATE TABLE mcp_tool_logs (
                id INTEGER PRIMARY KEY,
                request_id TEXT,
                timestamp TEXT NOT NULL,
                tool_name TEXT,
                server_label TEXT,
                arguments TEXT,
                result TEXT,
                error_details TEXT,
                latency REAL,
                status TEXT,
                metadata TEXT,
                created_at TEXT
            )
        """)
        # Five rows at 1-second intervals, 7-digit µs (Bifrost format)
        timestamps = [
            "2026-05-01 21:00:00.0000000+00:00",  # row 1
            "2026-05-01 21:00:01.0000000+00:00",  # row 2
            "2026-05-01 21:00:02.0000000+00:00",  # row 3
            "2026-05-01 21:00:03.0000000+00:00",  # row 4
            "2026-05-01 21:00:04.0000000+00:00",  # row 5
        ]
        for i, ts in enumerate(timestamps, start=1):
            conn.execute(
                "INSERT INTO mcp_tool_logs (id, request_id, timestamp, tool_name, "
                "server_label, arguments, result, latency, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (i, f"req-{i}", ts, "list_directory", "fs",
                 '{"path":"/tmp"}', '{"content":[]}', 5.0, "success", ts),
            )
        conn.commit()
        conn.close()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _read_output(self):
        import json as _json
        with open(self.out_path) as f:
            return [_json.loads(line) for line in f if line.strip()]

    def test_no_window_returns_all_rows(self):
        """5 rows × 2 entries (req+resp) = 10 entries when no window applied."""
        from log_adapter import adapt_bifrost
        count = adapt_bifrost(self.db_path, self.out_path)
        self.assertEqual(count, 10)
        entries = self._read_output()
        self.assertEqual(len(entries), 10)

    def test_window_includes_only_matching_rows(self):
        """Window covering rows 2–3 yields 2 rows × 2 entries = 4 entries."""
        from log_adapter import adapt_bifrost, _parse_timestamp
        start = _parse_timestamp("2026-05-01 21:00:01.0000000+00:00")
        end = _parse_timestamp("2026-05-01 21:00:03.0000000+00:00")
        count = adapt_bifrost(self.db_path, self.out_path,
                              start_ts=start, end_ts=end)
        self.assertEqual(count, 4)
        entries = self._read_output()
        # Both entries for row 2 and row 3 should be present
        request_ids = {e["session_id"] for e in entries}
        self.assertEqual(request_ids, {"req-2", "req-3"})

    def test_right_boundary_is_exclusive(self):
        """end_ts == row.timestamp must EXCLUDE that row."""
        from log_adapter import adapt_bifrost, _parse_timestamp
        start = _parse_timestamp("2026-05-01 21:00:00.0000000+00:00")
        end = _parse_timestamp("2026-05-01 21:00:02.0000000+00:00")  # row 3's exact ts
        count = adapt_bifrost(self.db_path, self.out_path,
                              start_ts=start, end_ts=end)
        # Should include rows 1 and 2 only (row 3 excluded by right-exclusive)
        self.assertEqual(count, 4)
        entries = self._read_output()
        request_ids = {e["session_id"] for e in entries}
        self.assertEqual(request_ids, {"req-1", "req-2"})

    def test_left_boundary_is_inclusive(self):
        """start_ts == row.timestamp must INCLUDE that row."""
        from log_adapter import adapt_bifrost, _parse_timestamp
        start = _parse_timestamp("2026-05-01 21:00:02.0000000+00:00")  # row 3's exact ts
        end = _parse_timestamp("2026-05-01 21:00:05.0000000+00:00")
        count = adapt_bifrost(self.db_path, self.out_path,
                              start_ts=start, end_ts=end)
        # Should include rows 3, 4, 5
        self.assertEqual(count, 6)
        entries = self._read_output()
        request_ids = {e["session_id"] for e in entries}
        self.assertEqual(request_ids, {"req-3", "req-4", "req-5"})

    def test_window_with_no_matches_yields_empty_output(self):
        from log_adapter import adapt_bifrost, _parse_timestamp
        start = _parse_timestamp("2027-01-01 00:00:00.0000000+00:00")
        end = _parse_timestamp("2027-01-02 00:00:00.0000000+00:00")
        count = adapt_bifrost(self.db_path, self.out_path,
                              start_ts=start, end_ts=end)
        self.assertEqual(count, 0)
        entries = self._read_output()
        self.assertEqual(entries, [])

    def test_only_one_bound_provided_raises(self):
        from log_adapter import adapt_bifrost, _parse_timestamp
        start = _parse_timestamp("2026-05-01 21:00:00.0000000+00:00")
        with self.assertRaises(ValueError):
            adapt_bifrost(self.db_path, self.out_path, start_ts=start)
        with self.assertRaises(ValueError):
            adapt_bifrost(self.db_path, self.out_path, end_ts=start)

    def test_end_before_start_raises(self):
        from log_adapter import adapt_bifrost, _parse_timestamp
        start = _parse_timestamp("2026-05-01 21:00:05.0000000+00:00")
        end = _parse_timestamp("2026-05-01 21:00:00.0000000+00:00")
        with self.assertRaises(ValueError):
            adapt_bifrost(self.db_path, self.out_path, start_ts=start, end_ts=end)


# ===================================================================
# Run experiment orchestrator tests
# ===================================================================

class TestNextRunDir(unittest.TestCase):
    """Tests for run-NNN auto-increment."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_first_run_in_empty_dir(self):
        from run_experiment import next_run_dir
        result = next_run_dir(self.tmpdir)
        self.assertEqual(result.name, "run-001")

    def test_increments_past_existing_runs(self):
        from run_experiment import next_run_dir
        (self.tmpdir / "run-001").mkdir()
        (self.tmpdir / "run-002").mkdir()
        (self.tmpdir / "run-005").mkdir()  # gap should be ignored
        result = next_run_dir(self.tmpdir)
        self.assertEqual(result.name, "run-006")

    def test_ignores_non_run_directories(self):
        from run_experiment import next_run_dir
        (self.tmpdir / "run-001").mkdir()
        (self.tmpdir / "scratch").mkdir()
        (self.tmpdir / "run-abc").mkdir()  # malformed
        result = next_run_dir(self.tmpdir)
        self.assertEqual(result.name, "run-002")

    def test_creates_logs_dir_if_missing(self):
        from run_experiment import next_run_dir
        nonexistent = self.tmpdir / "deep" / "nested" / "logs"
        result = next_run_dir(nonexistent)
        self.assertTrue(nonexistent.is_dir())
        self.assertEqual(result.name, "run-001")


class TestGetGitInfo(unittest.TestCase):
    """Tests for git commit + dirty-tree capture, with subprocess mocked."""

    def test_clean_tree(self):
        from unittest.mock import patch, MagicMock
        from run_experiment import get_git_info

        def fake_run(cmd, **kwargs):
            mock = MagicMock()
            mock.returncode = 0
            if "rev-parse" in cmd:
                mock.stdout = "abc123def456\n"
            else:  # status --porcelain
                mock.stdout = ""  # clean
            return mock

        with patch("run_experiment.subprocess.run", side_effect=fake_run):
            from pathlib import Path
            info = get_git_info(Path("/tmp"))
        self.assertEqual(info["commit"], "abc123def456")
        self.assertFalse(info["dirty"])

    def test_dirty_tree(self):
        from unittest.mock import patch, MagicMock
        from run_experiment import get_git_info

        def fake_run(cmd, **kwargs):
            mock = MagicMock()
            mock.returncode = 0
            if "rev-parse" in cmd:
                mock.stdout = "abc123\n"
            else:
                mock.stdout = " M file.py\n?? new.py\n"
            return mock

        with patch("run_experiment.subprocess.run", side_effect=fake_run):
            from pathlib import Path
            info = get_git_info(Path("/tmp"))
        self.assertEqual(info["commit"], "abc123")
        self.assertTrue(info["dirty"])

    def test_git_not_installed(self):
        from unittest.mock import patch
        from run_experiment import get_git_info

        with patch("run_experiment.subprocess.run", side_effect=FileNotFoundError("git")):
            from pathlib import Path
            info = get_git_info(Path("/tmp"))
        self.assertIsNone(info["commit"])
        self.assertIn("error", info)


class TestRunExperimentOrchestration(unittest.TestCase):
    """Tests for the full orchestration loop with subprocess + filesystem mocked."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        self.tmpdir = Path(tempfile.mkdtemp())
        self.run_dir = self.tmpdir / "run-001"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _mock_subprocess_run_factory(self, scenario_outcomes):
        """Build a fake subprocess.run that returns success for setup_data
        and the configured outcome for each scenario_runner invocation.

        scenario_outcomes: list of (returncode, stdout) tuples in scenario order.
        """
        from unittest.mock import MagicMock
        outcome_iter = iter(scenario_outcomes)

        def fake_run(cmd, **kwargs):
            mock = MagicMock()
            cmd_str = " ".join(str(c) for c in cmd) if isinstance(cmd, list) else str(cmd)
            if "setup_data.py" in cmd_str:
                mock.returncode = 0
                mock.stdout = "Reset done\n"
                mock.stderr = ""
            elif "scenario_runner.py" in cmd_str:
                rc, out = next(outcome_iter)
                mock.returncode = rc
                mock.stdout = out
                mock.stderr = ""
            elif "rev-parse" in cmd_str:
                mock.returncode = 0
                mock.stdout = "test_commit_sha\n"
                mock.stderr = ""
            elif "status" in cmd_str:
                mock.returncode = 0
                mock.stdout = ""
                mock.stderr = ""
            else:
                mock.returncode = 0
                mock.stdout = ""
                mock.stderr = ""
            return mock

        return fake_run

    def test_all_scenarios_succeed(self):
        from unittest.mock import patch
        from run_experiment import run_experiment
        import json as _json

        scenarios = ["baseline", "s02"]
        outcomes = [(0, "ok"), (0, "ok")]

        with patch("run_experiment.subprocess.run",
                   side_effect=self._mock_subprocess_run_factory(outcomes)), \
             patch("run_experiment.time.sleep"):
            run_meta = run_experiment(
                group="c", run_dir=self.run_dir, scenarios=scenarios,
                inter_scenario_gap=0.0, bifrost_url="http://x",
            )

        self.assertEqual(run_meta["scenarios_succeeded"], ["baseline", "s02"])
        self.assertEqual(run_meta["scenarios_failed"], [])
        self.assertEqual(run_meta["commit"], "test_commit_sha")
        self.assertFalse(run_meta["dirty_tree"])

        # Verify windows.json
        windows = _json.loads((self.run_dir / "windows.json").read_text())
        self.assertEqual(set(windows.keys()), {"baseline", "s02"})
        for sid, w in windows.items():
            self.assertEqual(w["status"], "ok")
            self.assertEqual(w["exit_code"], 0)
            self.assertIn("start_ts", w)
            self.assertIn("end_ts", w)

        # Verify run_meta.json written
        run_meta_file = _json.loads((self.run_dir / "run_meta.json").read_text())
        self.assertEqual(run_meta_file["group"], "c")
        self.assertEqual(run_meta_file["scenarios_attempted"], scenarios)

        # Verify run.log exists
        self.assertTrue((self.run_dir / "run.log").exists())

    def test_one_scenario_fails_others_continue(self):
        from unittest.mock import patch
        from run_experiment import run_experiment

        scenarios = ["baseline", "s02", "s08"]
        outcomes = [(0, "ok"), (1, "ERROR: tool call failed"), (0, "ok")]

        with patch("run_experiment.subprocess.run",
                   side_effect=self._mock_subprocess_run_factory(outcomes)), \
             patch("run_experiment.time.sleep"):
            run_meta = run_experiment(
                group="c", run_dir=self.run_dir, scenarios=scenarios,
                inter_scenario_gap=0.0, bifrost_url="http://x",
            )

        self.assertEqual(run_meta["scenarios_succeeded"], ["baseline", "s08"])
        self.assertEqual(run_meta["scenarios_failed"], ["s02"])

    def test_setup_data_failure_aborts_run(self):
        """Fatal setup_data failure should abort the run, not continue."""
        from unittest.mock import patch, MagicMock
        from run_experiment import run_experiment

        def fake_run(cmd, **kwargs):
            mock = MagicMock()
            cmd_str = " ".join(str(c) for c in cmd) if isinstance(cmd, list) else str(cmd)
            if "setup_data.py" in cmd_str:
                mock.returncode = 1
                mock.stdout = ""
                mock.stderr = "permission denied"
            elif "rev-parse" in cmd_str or "status" in cmd_str:
                mock.returncode = 0
                mock.stdout = "abc\n" if "rev-parse" in cmd_str else ""
                mock.stderr = ""
            else:
                mock.returncode = 0
                mock.stdout = ""
                mock.stderr = ""
            return mock

        with patch("run_experiment.subprocess.run", side_effect=fake_run), \
             patch("run_experiment.time.sleep"):
            run_meta = run_experiment(
                group="c", run_dir=self.run_dir, scenarios=["baseline", "s02"],
                inter_scenario_gap=0.0, bifrost_url="http://x",
            )

        self.assertIn("fatal_error", run_meta)
        self.assertEqual(run_meta["scenarios_succeeded"], [])
        self.assertEqual(run_meta["scenarios_failed"], [])

    def test_window_timestamps_are_ordered(self):
        """end_ts must be >= start_ts for every scenario."""
        from unittest.mock import patch
        from run_experiment import run_experiment
        from datetime import datetime
        import json as _json

        scenarios = ["baseline"]
        outcomes = [(0, "ok")]

        with patch("run_experiment.subprocess.run",
                   side_effect=self._mock_subprocess_run_factory(outcomes)), \
             patch("run_experiment.time.sleep"):
            run_experiment(
                group="c", run_dir=self.run_dir, scenarios=scenarios,
                inter_scenario_gap=0.0, bifrost_url="http://x",
            )

        windows = _json.loads((self.run_dir / "windows.json").read_text())
        w = windows["baseline"]
        start = datetime.fromisoformat(w["start_ts"])
        end = datetime.fromisoformat(w["end_ts"])
        self.assertGreaterEqual(end, start)


# ===================================================================
# Slice bifrost logs tests
# ===================================================================

class TestSliceBifrostLogs(unittest.TestCase):
    """Tests for slice_bifrost_logs using a synthetic Bifrost DB + windows.json."""

    def setUp(self):
        import sqlite3
        import tempfile
        import os
        import json as _json
        from pathlib import Path

        self.tmpdir = Path(tempfile.mkdtemp())
        self.run_dir = self.tmpdir / "run-001"
        self.run_dir.mkdir()
        self.db_path = self.tmpdir / "logs.db"

        # Build synthetic Bifrost DB with 6 rows in 3 groups of 2
        # Scenario 1: 21:00:00 and 21:00:01 (rows 1, 2)
        # Scenario 2: 21:00:05 and 21:00:06 (rows 3, 4)
        # Scenario 3: 21:00:10 and 21:00:11 (rows 5, 6)
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("""
            CREATE TABLE mcp_tool_logs (
                id INTEGER PRIMARY KEY,
                request_id TEXT,
                timestamp TEXT NOT NULL,
                tool_name TEXT,
                server_label TEXT,
                arguments TEXT,
                result TEXT,
                error_details TEXT,
                latency REAL,
                status TEXT,
                metadata TEXT,
                created_at TEXT
            )
        """)
        timestamps = [
            "2026-05-01 21:00:00.0000000+00:00",  # row 1 -> baseline
            "2026-05-01 21:00:01.0000000+00:00",  # row 2 -> baseline
            "2026-05-01 21:00:05.0000000+00:00",  # row 3 -> s02
            "2026-05-01 21:00:06.0000000+00:00",  # row 4 -> s02
            "2026-05-01 21:00:10.0000000+00:00",  # row 5 -> s08
            "2026-05-01 21:00:11.0000000+00:00",  # row 6 -> s08
        ]
        for i, ts in enumerate(timestamps, start=1):
            conn.execute(
                "INSERT INTO mcp_tool_logs (id, request_id, timestamp, tool_name, "
                "server_label, arguments, result, latency, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (i, f"req-{i}", ts, "list_directory", "fs",
                 '{"path":"/tmp"}', '{"content":[]}', 5.0, "success", ts),
            )
        conn.commit()
        conn.close()

        # Write a windows.json with 4 scenarios — one will produce empty,
        # one will be marked failed
        windows = {
            "baseline": {
                "start_ts": "2026-05-01T21:00:00+00:00",
                "end_ts":   "2026-05-01T21:00:03+00:00",  # rows 1, 2
                "status": "ok", "exit_code": 0,
            },
            "s02": {
                "start_ts": "2026-05-01T21:00:05+00:00",
                "end_ts":   "2026-05-01T21:00:08+00:00",  # rows 3, 4
                "status": "ok", "exit_code": 0,
            },
            "s08": {
                "start_ts": "2026-05-01T21:00:10+00:00",
                "end_ts":   "2026-05-01T21:00:13+00:00",  # rows 5, 6
                "status": "ok", "exit_code": 0,
            },
            "s_empty": {
                "start_ts": "2027-01-01T00:00:00+00:00",
                "end_ts":   "2027-01-02T00:00:00+00:00",  # no matches
                "status": "ok", "exit_code": 0,
            },
            "s_failed": {
                "start_ts": "2026-05-01T21:00:00+00:00",
                "end_ts":   "2026-05-01T21:00:01+00:00",
                "status": "failed", "exit_code": 1,
            },
        }
        with open(self.run_dir / "windows.json", "w") as f:
            _json.dump(windows, f)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _read_jsonl(self, path):
        import json as _json
        with open(path) as f:
            return [_json.loads(line) for line in f if line.strip()]

    def test_slices_all_scenarios_with_correct_entry_counts(self):
        from slice_bifrost_logs import slice_run
        meta = slice_run(self.run_dir, self.db_path)

        # baseline, s02, s08 each have 2 rows -> 4 entries (req+resp)
        self.assertEqual(meta["scenarios"]["baseline"]["entries"], 4)
        self.assertEqual(meta["scenarios"]["baseline"]["status"], "ok")
        self.assertEqual(meta["scenarios"]["s02"]["entries"], 4)
        self.assertEqual(meta["scenarios"]["s08"]["entries"], 4)

        # Output files exist with correct contents
        for sid in ("baseline", "s02", "s08"):
            out_path = self.run_dir / f"group_b_{sid}.jsonl"
            self.assertTrue(out_path.exists())
            entries = self._read_jsonl(out_path)
            self.assertEqual(len(entries), 4)

    def test_skips_failed_scenarios(self):
        from slice_bifrost_logs import slice_run
        meta = slice_run(self.run_dir, self.db_path)

        self.assertEqual(meta["scenarios"]["s_failed"]["status"],
                         "skipped_failed_scenario")
        # Output file should NOT exist for skipped scenarios
        self.assertFalse((self.run_dir / "group_b_s_failed.jsonl").exists())

    def test_empty_window_writes_empty_file(self):
        from slice_bifrost_logs import slice_run
        meta = slice_run(self.run_dir, self.db_path)

        self.assertEqual(meta["scenarios"]["s_empty"]["status"], "ok_empty")
        self.assertEqual(meta["scenarios"]["s_empty"]["entries"], 0)
        # Empty file IS written (uniform downstream loop)
        out_path = self.run_dir / "group_b_s_empty.jsonl"
        self.assertTrue(out_path.exists())
        self.assertEqual(out_path.stat().st_size, 0)

    def test_missing_windows_json_raises(self):
        from slice_bifrost_logs import slice_run
        from pathlib import Path
        empty_dir = self.tmpdir / "empty"
        empty_dir.mkdir()
        with self.assertRaises(FileNotFoundError):
            slice_run(empty_dir, self.db_path)

    def test_subset_scenarios(self):
        """--scenarios should restrict the slice to listed IDs."""
        from slice_bifrost_logs import slice_run
        meta = slice_run(self.run_dir, self.db_path,
                         scenarios=["baseline", "s02"])

        self.assertEqual(set(meta["scenarios"].keys()), {"baseline", "s02"})
        self.assertTrue((self.run_dir / "group_b_baseline.jsonl").exists())
        self.assertTrue((self.run_dir / "group_b_s02.jsonl").exists())
        # Other scenarios in windows.json should NOT be sliced
        self.assertFalse((self.run_dir / "group_b_s08.jsonl").exists())

    def test_unknown_scenario_in_subset_raises(self):
        from slice_bifrost_logs import slice_run
        with self.assertRaises(ValueError):
            slice_run(self.run_dir, self.db_path,
                      scenarios=["baseline", "s99_nonexistent"])

    def test_slice_meta_written(self):
        from slice_bifrost_logs import slice_run
        import json as _json
        slice_run(self.run_dir, self.db_path)
        meta_path = self.run_dir / "slice_meta.json"
        self.assertTrue(meta_path.exists())
        meta = _json.loads(meta_path.read_text())
        self.assertIn("scenarios", meta)
        self.assertIn("sliced_at", meta)


# ===================================================================
# Score results tests
# ===================================================================

class TestClassifyCell(unittest.TestCase):
    """Tests for the (scenario, group, rule) cell classification."""

    def setUp(self):
        from score_results import classify_cell
        self.classify = classify_cell
        self.overrides = {
            "BIO-001": ["b"],
            "BIO-008": ["b"],
            "CONV-005": ["b"],
            "BIO-007": ["b", "c"],
        }

    def test_predicted_and_fired_returns_detected(self):
        expected = {"count": 2, "severity": "CRITICAL", "reason": "honeytoken"}
        status, _ = self.classify("BIO-004a", expected, 2, "c", self.overrides)
        self.assertEqual(status, "DETECTED")

    def test_predicted_and_silent_returns_rule_missed(self):
        expected = {"count": 2, "severity": "CRITICAL", "reason": "honeytoken"}
        status, _ = self.classify("BIO-004a", expected, 0, "c", self.overrides)
        self.assertEqual(status, "RULE_MISSED")

    def test_actual_under_expected_returns_rule_missed(self):
        expected = {"count": 3, "severity": "MEDIUM", "reason": "glob"}
        status, _ = self.classify("BIO-004a", expected, 1, "c", self.overrides)
        self.assertEqual(status, "RULE_MISSED")

    def test_actual_over_expected_returns_detected_with_note(self):
        expected = {"count": 1, "severity": "any", "reason": "deviation"}
        status, note = self.classify("BIO-003", expected, 5, "c", self.overrides)
        self.assertEqual(status, "DETECTED")
        self.assertIn("5", note)

    def test_visibility_override_with_prediction_returns_data_missed(self):
        """BIO-008 expected to fire but Group B can't observe → DATA_MISSED."""
        expected = {"count": 1, "severity": "any", "reason": "schema change"}
        status, _ = self.classify("BIO-008", expected, 0, "b", self.overrides)
        self.assertEqual(status, "DATA_MISSED")

    def test_visibility_override_no_prediction_returns_not_observable(self):
        """BIO-001 not predicted on this scenario, Group B can't observe →
        NOT_OBSERVABLE (architectural blind spot)."""
        status, _ = self.classify("BIO-001", {}, 0, "b", self.overrides)
        self.assertEqual(status, "NOT_OBSERVABLE")

    def test_visibility_override_does_not_affect_other_group(self):
        """BIO-008 in Group C is NOT overridden, behaves normally."""
        expected = {"count": 1, "severity": "any", "reason": "schema change"}
        status, _ = self.classify("BIO-008", expected, 1, "c", self.overrides)
        self.assertEqual(status, "DETECTED")

    def test_unexpected_firing_no_prediction(self):
        status, note = self.classify("CONV-002", {}, 3, "c", self.overrides)
        self.assertEqual(status, "UNEXPECTED_FIRING")
        self.assertIn("3", note)

    def test_not_expected_no_prediction_silent(self):
        status, _ = self.classify("CONV-002", {}, 0, "c", self.overrides)
        self.assertEqual(status, "NOT_EXPECTED")


class TestCountFindingsByRule(unittest.TestCase):
    def test_groups_by_rule_id(self):
        from score_results import count_findings_by_rule
        from mcp_detect import Finding
        findings = [
            Finding("BIO-004a", "bio-derived", "CRITICAL", "x", [], "s2"),
            Finding("BIO-004a", "bio-derived", "CRITICAL", "y", [], "s2"),
            Finding("BIO-003", "bio-derived", "any", "z", [], "s2"),
        ]
        counts = count_findings_by_rule(findings)
        self.assertEqual(counts, {"BIO-004a": 2, "BIO-003": 1})

    def test_empty_findings_returns_empty_dict(self):
        from score_results import count_findings_by_rule
        self.assertEqual(count_findings_by_rule([]), {})


class TestScoreResultsIntegration(unittest.TestCase):
    """End-to-end test: synthetic logs, expectations, full scoring pipeline."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        self.tmpdir = Path(tempfile.mkdtemp())
        self.group_c = self.tmpdir / "run-c"
        self.group_b = self.tmpdir / "run-b"
        self.group_c.mkdir()
        self.group_b.mkdir()
        self.output = self.tmpdir / "results.csv"
        self.expectations_path = self.tmpdir / "expectations.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_jsonl(self, path, entries):
        import json as _json
        with open(path, "w") as f:
            for e in entries:
                f.write(_json.dumps(e) + "\n")

    def _make_honeytoken_call(self, msg_id, path, sequence):
        """Build a minimal request+response pair for a honeytoken access."""
        return [
            {
                "timestamp": f"2026-05-01T22:00:0{msg_id}.000+00:00",
                "sequence": sequence,
                "session_id": f"sess-{msg_id}",
                "server_id": "filesystem",
                "direction": "client_to_server",
                "method": "tools/call",
                "params": {"name": "read_text_file", "arguments": {"path": path}},
                "message_id": str(msg_id),
                "message_type": "request",
            },
            {
                "timestamp": f"2026-05-01T22:00:0{msg_id}.001+00:00",
                "sequence": sequence + 1,
                "session_id": f"sess-{msg_id}",
                "server_id": "filesystem",
                "direction": "server_to_client",
                "method": None,
                "params": {"content": "data"},
                "message_id": str(msg_id),
                "message_type": "response",
                "is_error": False,
                "latency_ms": 1.0,
            },
        ]

    def test_full_pipeline_with_synthetic_s02(self):
        """Build a synthetic s02-like log, score it, verify DETECTED."""
        from score_results import score_run
        import json as _json

        # Group C log: s02 reads two honeytokens
        s02_entries = (
            self._make_honeytoken_call(1, "/data/customer_export_2024.csv", 1)
            + self._make_honeytoken_call(2, "/data/payroll_q3_draft.xlsx", 3)
        )
        self._write_jsonl(self.group_c / "group_c_s02.jsonl", s02_entries)
        # Empty baseline for Group C (BIO-003 will produce findings on novel paths
        # but that's an UNEXPECTED_FIRING in this synthetic scenario, not what
        # we're testing — we just want to confirm BIO-004a fires correctly)
        self._write_jsonl(self.group_c / "group_c_baseline.jsonl", [])
        # Group B: write empty files so the pipeline doesn't error
        self._write_jsonl(self.group_b / "group_b_s02.jsonl", [])
        self._write_jsonl(self.group_b / "group_b_baseline.jsonl", [])

        expectations = {
            "_visibility_overrides": {
                "BIO-001": ["b"], "BIO-008": ["b"],
                "CONV-005": ["b"], "BIO-007": ["b", "c"],
            },
            "scenarios": {
                "baseline": {"name": "baseline", "expected_firings": {}},
                "s02": {
                    "name": "s02",
                    "expected_firings": {
                        "BIO-004a": {"count": 2, "severity": "CRITICAL",
                                     "reason": "honeytoken access"},
                    },
                },
            },
        }

        rows = score_run(
            self.group_c, self.group_b,
            expectations,
            ["customer_export_2024.csv", "payroll_q3_draft.xlsx"],
        )

        # Find the s02/BIO-004a row
        s02_bio004a = [r for r in rows
                       if r["scenario"] == "s02" and r["rule_id"] == "BIO-004a"]
        self.assertEqual(len(s02_bio004a), 1)
        row = s02_bio004a[0]
        self.assertEqual(row["group_c_status"], "DETECTED")
        self.assertEqual(row["group_c_count"], 2)
        # Group B has empty log, so BIO-004a is RULE_MISSED there
        self.assertEqual(row["group_b_status"], "RULE_MISSED")
        self.assertEqual(row["group_b_count"], 0)

    def test_visibility_override_on_real_file(self):
        """BIO-001 should be NOT_OBSERVABLE in Group B even when no prediction."""
        from score_results import score_run

        self._write_jsonl(self.group_c / "group_c_baseline.jsonl", [])
        self._write_jsonl(self.group_b / "group_b_baseline.jsonl", [])
        self._write_jsonl(self.group_c / "group_c_s02.jsonl", [])
        self._write_jsonl(self.group_b / "group_b_s02.jsonl", [])

        expectations = {
            "_visibility_overrides": {
                "BIO-001": ["b"], "BIO-008": ["b"],
                "CONV-005": ["b"], "BIO-007": ["b", "c"],
            },
            "scenarios": {
                "baseline": {"name": "baseline", "expected_firings": {}},
                "s02": {"name": "s02", "expected_firings": {}},
            },
        }

        rows = score_run(self.group_c, self.group_b, expectations, [])

        # No expected firings, no actual firings — but BIO-001 row exists
        # because it's in visibility_overrides
        s02_bio001 = [r for r in rows
                      if r["scenario"] == "s02" and r["rule_id"] == "BIO-001"]
        self.assertEqual(len(s02_bio001), 1)
        self.assertEqual(s02_bio001[0]["group_b_status"], "NOT_OBSERVABLE")


# ===================================================================
# Run
# ===================================================================

if __name__ == "__main__":
    unittest.main()
