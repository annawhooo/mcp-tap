#!/usr/bin/env python3
"""
mcp-detect: Detection rules for MCP agent behavioral analysis.

Reads JSONL audit logs from mcp-tap (stdio capture) or compatible
sources and evaluates detection rules against them.

Two rule sets:
  - Conventional: standard security engineering rules (Group B)
  - Bio-derived: biologically-derived behavioral rules (Group C)

Usage:
    python mcp_detect.py --log ./audit.jsonl --rules conventional
    python mcp_detect.py --log ./audit.jsonl --rules bio-derived
    python mcp_detect.py --log ./audit.jsonl --rules all
"""

import argparse
import fnmatch
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Log Reader (input-source-agnostic)
# ---------------------------------------------------------------------------

def read_jsonl(path: str) -> list[dict]:
    """Read a JSONL audit log. Accepts mcp-tap format."""
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"Warning: invalid JSON on line {line_num}", file=sys.stderr)
    return entries


def filter_messages(entries: list[dict]) -> list[dict]:
    """Filter to only message entries (exclude lifecycle events)."""
    return [e for e in entries if "direction" in e]


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

class Finding:
    def __init__(self, rule_id: str, rule_set: str, severity: str,
                 description: str, evidence: list[dict], scenario: str = None):
        self.rule_id = rule_id
        self.rule_set = rule_set  # "conventional" or "bio-derived"
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW
        self.description = description
        self.evidence = evidence  # list of log entries that triggered this
        self.scenario = scenario  # which attack scenario this maps to, if any

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_set": self.rule_set,
            "severity": self.severity,
            "description": self.description,
            "scenario": self.scenario,
            "evidence_count": len(self.evidence),
            "evidence_sequences": [e.get("sequence") for e in self.evidence],
        }


# ---------------------------------------------------------------------------
# GROUP B: Conventional Detection Rules
# ---------------------------------------------------------------------------
# These are rules a competent security engineer would write WITHOUT
# reading the biomimetic paper. Standard security practices.
#
# Derivation sources (for academic reproducibility):
#   CONV-001: OWASP API Security Top 10 (2023), API2 Broken Authentication.
#             SANS CIS Control 6: Access Control Management.
#   CONV-002: NIST SP 800-92 Guide to Computer Security Log Management,
#             Section 4.2 (volume-based anomaly detection).
#   CONV-003: OWASP Testing Guide v4, OTG-AUTHN-004 (brute force testing).
#             CrowdStrike Falcon default rule: "Rapid API calls" threshold.
#   CONV-004: OWASP API Security Top 10 (2023), API1 Broken Object Level
#             Authorization. Standard WAF/API gateway scope enforcement.
#   CONV-005: MITRE ATT&CK T1087 Account Discovery, T1083 File and
#             Directory Discovery. Standard SIEM enumeration detection.

def _is_jsonrpc_error_response(m: dict) -> bool:
    """
    True iff m is a JSON-RPC error response.

    Prefer mcp-tap's explicit `is_error` field (set by classify_message).
    Fall back to a structural shape check (JSON-RPC 2.0 error objects are
    required to have an integer `code` and a string `message`, spec §5.1)
    for older logs and for logs produced by adapters that don't emit the
    field. Either path avoids false positives on successful responses
    whose result merely contains the word "error".
    """
    if m.get("message_type") != "response":
        return False
    if m.get("is_error") is True:
        return True
    if m.get("is_error") is False:
        return False
    # Field absent — fall back to shape inspection.
    p = m.get("params")
    if not isinstance(p, dict):
        return False
    return isinstance(p.get("code"), int) and isinstance(p.get("message"), str)


def conv_001_failed_auth(messages: list[dict]) -> list[Finding]:
    """CONV-001: Failed authentication/operation attempts."""
    failures = [m for m in messages if _is_jsonrpc_error_response(m)]
    if len(failures) < 3:
        return []
    return [Finding(
        rule_id="CONV-001",
        rule_set="conventional",
        severity="MEDIUM",
        description=f"Multiple failed operations detected: {len(failures)} error responses",
        evidence=failures[:10],
    )]


def conv_002_volume_spike(messages: list[dict]) -> list[Finding]:
    """CONV-002: Anomalous request volume in short window."""
    findings = []
    # Group by 60-second windows
    windows = defaultdict(list)
    for m in messages:
        if m.get("direction") == "client_to_server":
            ts = m.get("timestamp", "")
            # Truncate to minute
            window = ts[:16]  # "2026-04-08T14:30"
            windows[window].append(m)

    for window, msgs in windows.items():
        if len(msgs) > 20:  # arbitrary threshold
            findings.append(Finding(
                rule_id="CONV-002",
                rule_set="conventional",
                severity="MEDIUM",
                description=f"Volume spike: {len(msgs)} requests in window {window}",
                evidence=msgs[:5],
            ))
    return findings


def conv_003_rapid_tool_calls(messages: list[dict]) -> list[Finding]:
    """CONV-003: Rapid successive tool calls (possible brute force)."""
    findings = []
    tool_calls = [m for m in messages
                  if m.get("method") == "tools/call"
                  and m.get("direction") == "client_to_server"]

    for i in range(len(tool_calls) - 2):
        ts_a = tool_calls[i].get("timestamp", "")
        ts_c = tool_calls[i + 2].get("timestamp", "")
        if ts_a and ts_c:
            try:
                t_a = datetime.fromisoformat(ts_a)
                t_c = datetime.fromisoformat(ts_c)
                delta = (t_c - t_a).total_seconds()
                if delta < 2.0:  # 3 tool calls in under 2 seconds
                    findings.append(Finding(
                        rule_id="CONV-003",
                        rule_set="conventional",
                        severity="HIGH",
                        description=f"Rapid tool calls: 3 calls in {delta:.1f}s",
                        evidence=tool_calls[i:i+3],
                    ))
                    break  # one finding per pattern
            except (ValueError, TypeError):
                pass
    return findings


def conv_004_credential_scope(messages: list[dict]) -> list[Finding]:
    """CONV-004: Credential used outside defined scope."""
    findings = []
    # Look for tool calls with URL parameters that don't match the server
    tool_calls = [m for m in messages if m.get("method") == "tools/call"]
    for tc in tool_calls:
        params = tc.get("params", {})
        if isinstance(params, dict):
            args = params.get("arguments", {})
            if isinstance(args, dict):
                url = args.get("url", "")
                # Flag any URL that looks like it's hitting an internal/sensitive endpoint
                sensitive_patterns = ["/admin", "/internal", "/.env", "/etc/passwd",
                                      "/user/emails", "/v1/balance"]
                for pattern in sensitive_patterns:
                    if pattern in str(url).lower():
                        findings.append(Finding(
                            rule_id="CONV-004",
                            rule_set="conventional",
                            severity="HIGH",
                            description=f"Sensitive endpoint access: {pattern}",
                            evidence=[tc],
                        ))
    return findings


def conv_005_enumeration(messages: list[dict]) -> list[Finding]:
    """CONV-005: Resource enumeration (listing without using)."""
    findings = []
    list_calls = [m for m in messages
                  if m.get("method") in ("tools/list", "resources/list")
                  and m.get("direction") == "client_to_server"]
    if len(list_calls) >= 3:
        findings.append(Finding(
            rule_id="CONV-005",
            rule_set="conventional",
            severity="LOW",
            description=f"Multiple enumeration calls: {len(list_calls)} list operations",
            evidence=list_calls[:5],
        ))
    return findings


CONVENTIONAL_RULES = [
    conv_001_failed_auth,
    conv_002_volume_spike,
    conv_003_rapid_tool_calls,
    conv_004_credential_scope,
    conv_005_enumeration,
]


# ---------------------------------------------------------------------------
# GROUP C: Bio-Derived Detection Rules
# ---------------------------------------------------------------------------
# These rules are derived from the biomimetic gap analysis paper.
# Each maps to a specific design principle and attack scenario.

# Default honeytokens for testing. In production, provide a custom
# list via --honeytokens to prevent attacker evasion.
DEFAULT_HONEYTOKENS = [
    "customer_export_2024.csv",
    "payroll_q3_draft.xlsx",
    "admin_credentials_backup.txt",
    "ssh_keys_old.tar.gz",
    "database_dump_prod.sql",
]

def bio_001_hmac_chain_integrity(entries: list[dict]) -> list[Finding]:
    """
    BIO-001: Audit log integrity verification.
    Principle: #1 (Default suspicion). Scenario: #1 (Telemetry Suppression).

    Check HMAC chain continuity. Any break indicates tampering or data loss.
    This is a Criterion #1 (Structural Mutation) rule.
    """
    findings = []
    for i in range(1, len(entries)):
        current = entries[i]
        previous = entries[i - 1]
        if current.get("prev_hmac") != previous.get("hmac"):
            findings.append(Finding(
                rule_id="BIO-001",
                rule_set="bio-derived",
                severity="CRITICAL",
                description=f"HMAC chain broken at sequence {current.get('sequence')}. "
                            f"Expected prev_hmac={previous.get('hmac', '')[:16]}..., "
                            f"got {current.get('prev_hmac', '')[:16]}...",
                evidence=[previous, current],
                scenario="#1 Telemetry Suppression",
            ))
            break  # one finding is enough
    return findings


def _parse_ts(ts: str):
    """Parse an ISO 8601 timestamp, tolerating trailing 'Z'. Returns None on failure."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


# Tail window: messages in the last N seconds of the log are excluded
# from orphan detection symmetrically (both requests and responses),
# since the log snapshot always truncates mid-conversation. Asymmetric
# exclusion would tear matched pairs apart and create false positives
# on the side that wasn't filtered.
BIO_002_TAIL_SECONDS = 5.0


def bio_002_telemetry_gap(messages: list[dict],
                          tail_seconds: float = BIO_002_TAIL_SECONDS) -> list[Finding]:
    """
    BIO-002: Telemetry gap detection (missing-self signal).
    Principle: #2 (Infrastructure-sampled evidence). Scenario: #1.

    If there are requests without matching responses (or vice versa),
    something is being suppressed or dropped. The ABSENCE of expected
    messages is the signal (NK cell missing-self model).

    Messages within `tail_seconds` of the last observed message are
    excluded SYMMETRICALLY (both requests and responses) — the log may
    have been truncated mid-exchange, and we can't reliably distinguish
    "truly orphan" from "pair member not yet flushed." Excluding tail
    messages as a unit keeps matched pairs together; excluding only
    requests would tear pairs apart and create BIO-002b false positives
    on responses whose requests got tail-filtered.

    Tradeoff: a true orphan response within the tail window will be
    missed (false negative). Acceptable because tail data is incomplete
    by definition.
    """
    findings = []

    # Find the last timestamp in the log. Requests arriving within
    # tail_seconds of it are treated as "still in flight".
    last_ts = None
    for m in messages:
        t = _parse_ts(m.get("timestamp", ""))
        if t is not None and (last_ts is None or t > last_ts):
            last_ts = t

    def in_tail(m: dict) -> bool:
        if last_ts is None:
            return False
        t = _parse_ts(m.get("timestamp", ""))
        if t is None:
            return False
        return (last_ts - t).total_seconds() < tail_seconds

    requests = {str(m.get("message_id")): m for m in messages
                if m.get("message_type") == "request"
                and m.get("message_id")
                and not in_tail(m)}
    responses = {str(m.get("message_id")): m for m in messages
                 if m.get("message_type") == "response"
                 and m.get("message_id")
                 and not in_tail(m)}

    orphan_requests = set(requests.keys()) - set(responses.keys())
    orphan_responses = set(responses.keys()) - set(requests.keys())

    if orphan_requests:
        findings.append(Finding(
            rule_id="BIO-002",
            rule_set="bio-derived",
            severity="HIGH",
            description=f"Requests without responses (possible suppression): "
                        f"message IDs {list(orphan_requests)[:5]}",
            evidence=[requests[k] for k in list(orphan_requests)[:5]],
            scenario="#1 Telemetry Suppression",
        ))
    if orphan_responses:
        findings.append(Finding(
            rule_id="BIO-002b",
            rule_set="bio-derived",
            severity="HIGH",
            description=f"Responses without requests (possible injection): "
                        f"message IDs {list(orphan_responses)[:5]}",
            evidence=[responses[k] for k in list(orphan_responses)[:5]],
            scenario="#3 Protocol-Level Deception",
        ))
    return findings


def bio_003_behavioral_baseline_deviation(messages: list[dict],
                                          baseline_messages: list[dict] = None) -> list[Finding]:
    """
    BIO-003: Behavioral baseline deviation scoring.
    Principle: #25 (Behavioral continuity). Scenario: #2 (Behavioral Camouflage).

    If a baseline log is provided (--baseline), compare the current session's
    tool call profile against the baseline. If no baseline is provided, fall
    back to comparing the first half vs second half of the current session
    (less reliable, but still useful).
    """
    findings = []
    tool_calls = [m for m in messages
                  if m.get("method") == "tools/call"
                  and m.get("direction") == "client_to_server"]

    if len(tool_calls) < 4:
        return findings  # not enough data

    def tool_names(calls):
        names = []
        for c in calls:
            p = c.get("params", {})
            if isinstance(p, dict):
                names.append(p.get("name", "unknown"))
        return Counter(names)

    if baseline_messages is not None:
        # Compare current session against provided baseline
        baseline_calls = [m for m in baseline_messages
                          if m.get("method") == "tools/call"
                          and m.get("direction") == "client_to_server"]
        if not baseline_calls:
            return findings
        dist_baseline = tool_names(baseline_calls)
        dist_current = tool_names(tool_calls)
    else:
        # Fallback: compare first half vs second half (naive)
        if len(tool_calls) < 6:
            return findings
        mid = len(tool_calls) // 2
        dist_baseline = tool_names(tool_calls[:mid])
        dist_current = tool_names(tool_calls[mid:])

    # Check for tools that appear in current but not in baseline
    new_tools = set(dist_current.keys()) - set(dist_baseline.keys())
    if new_tools:
        source = "baseline" if baseline_messages is not None else "first half"
        findings.append(Finding(
            rule_id="BIO-003",
            rule_set="bio-derived",
            severity="MEDIUM",
            description=f"New tool usage not in {source}: {new_tools}. "
                        f"{source.capitalize()} used: {set(dist_baseline.keys())}",
            evidence=tool_calls[-3:],
            scenario="#2 Behavioral Camouflage",
        ))
    return findings


def _honeytoken_regex(token: str) -> "re.Pattern":
    """
    Build a match pattern for a honeytoken that anchors on non-word
    boundaries. A substring check would match 'admin.txt' inside
    'sysadmin.txt_notes'; anchoring requires that the character before
    and after (if any) is not a word/path continuation character, so
    the token must appear as a standalone path component or filename.
    """
    # Allowed "adjacent" characters: anything that isn't alphanumeric,
    # underscore, hyphen, or dot. Path separators (/, \) and quotes,
    # braces, spaces all qualify as boundaries.
    boundary = r"(?:^|[^A-Za-z0-9_.\-])"
    end = r"(?:[^A-Za-z0-9_.\-]|$)"
    return re.compile(boundary + re.escape(token) + end, re.IGNORECASE)


def bio_004a_access(messages: list[dict], honeytokens: list[str] = None) -> list[Finding]:
    """
    BIO-004a: Honeytoken access detection (request-side).
    Principle: #2 (Infrastructure-sampled evidence). Scenario: #8 (Sleeper).

    Detects tools/call requests that target honeytoken file paths. Triple-gated
    (direction + message_type + method) for high specificity, since CRITICAL
    findings need low false positive rates.

    Severity tiered by attacker knowledge level:
      - CRITICAL "direct_reference": exact honeytoken filename in argument
        value. Boundary-anchored to prevent matching 'admin.txt' inside
        'sysadmin.txt_notes'.
      - MEDIUM "glob:<pattern>": glob/fnmatch pattern in argument that would
        match a honeytoken. Indicates pattern-based search rather than
        direct knowledge of filename.

    The triple-gate filter excludes responses, which is critical for avoiding
    false positives when list_directory or search_files responses contain
    honeytoken filenames in their result text. BIO-004a is access-only:
    response-side detection is split into BIO-004b (recon, filename in
    listing) and BIO-004c (exfil, canary in response content). See
    TODO_pre_publication.md for the BIO-004 family roadmap.

    KNOWN LIMITATIONS (in scope to address before publication):
      - Symlink/hardlink/copy evasion: agent accesses honeytoken via a
        different path. To be addressed by BIO-004c (content canaries)
        and BIO-004d (file mtime/atime tracking).

    KNOWN LIMITATIONS (future research):
      - Full path-independent verification requires OS-level audit hooks
        (Linux auditd, Windows Object Access Auditing, macOS Endpoint
        Security framework). This is a separate research artifact.

    IMPORTANT: The default honeytoken list is for TESTING ONLY. For real
    deployments, provide a custom list via --honeytokens CLI argument.
    Honeytokens hard-coded in source can be evaded by attackers who read
    the source.
    """
    if honeytokens is None:
        honeytokens = DEFAULT_HONEYTOKENS

    patterns = [(t, _honeytoken_regex(t)) for t in honeytokens]
    findings = []

    for m in messages:
        # Triple-gate: direction + message_type + method
        if (m.get("direction") != "client_to_server" or
                m.get("message_type") != "request" or
                m.get("method") != "tools/call"):
            continue

        params = m.get("params")
        if not isinstance(params, dict):
            continue
        args = params.get("arguments")
        if not isinstance(args, dict):
            continue

        hits = _check_arguments_against_honeytokens(args, honeytokens, patterns)
        for token, severity, reason in hits:
            findings.append(Finding(
                rule_id="BIO-004a",
                rule_set="bio-derived",
                severity=severity,
                description=f"Honeytoken access via path: '{token}' ({reason})",
                evidence=[m],
                scenario="#8 The Sleeper / #2 Behavioral Camouflage",
            ))

    return findings


def _check_arguments_against_honeytokens(args: dict,
                                         honeytokens: list[str],
                                         patterns: list) -> list[tuple]:
    """
    Check tool call arguments against the honeytoken list.
    Returns list of (token, severity, reason) tuples.

    Tiers:
      - CRITICAL "direct_reference": boundary-anchored exact match of a
        honeytoken filename in any argument value
      - MEDIUM "glob:<pattern>": glob/fnmatch pattern in known pattern-arg
        keys that would match a honeytoken (without an exact reference
        also being present for that token)
    """
    hits = []
    args_str = json.dumps(args)

    # Tier 1: boundary-anchored exact match in argument values (CRITICAL)
    for token, pattern in patterns:
        if pattern.search(args_str):
            hits.append((token, "CRITICAL", "direct_reference"))

    # Tier 2: glob/fnmatch pattern in known pattern-arg keys (MEDIUM)
    pattern_keys = ("pattern", "glob", "query", "filter", "search")
    for key in pattern_keys:
        pattern_val = args.get(key)
        if not isinstance(pattern_val, str) or not pattern_val:
            continue
        for token in honeytokens:
            if fnmatch.fnmatch(token.lower(), pattern_val.lower()):
                # Skip if this token already captured at CRITICAL tier
                if not any(h[0] == token and h[1] == "CRITICAL" for h in hits):
                    hits.append((token, "MEDIUM", f"glob:{pattern_val}"))

    return hits


def bio_005_silence_detection(messages: list[dict]) -> list[Finding]:
    """
    BIO-005: Silence-based alerting (privileged zone monitoring).
    Principle: #10 (Dynamic containment). Scenario: #6 (Privileged Zone).

    If a server_id has active connections (requests flowing) but zero
    tool call responses over a time window, something is wrong. The
    privileged zone is being accessed but producing no observable output.
    """
    findings = []
    by_server = defaultdict(lambda: {"requests": 0, "responses": 0})

    for m in messages:
        sid = m.get("server_id", "unknown")
        if m.get("direction") == "client_to_server":
            by_server[sid]["requests"] += 1
        elif m.get("direction") == "server_to_client":
            by_server[sid]["responses"] += 1

    for sid, counts in by_server.items():
        if counts["requests"] > 3 and counts["responses"] == 0:
            findings.append(Finding(
                rule_id="BIO-005",
                rule_set="bio-derived",
                severity="HIGH",
                description=f"Server '{sid}' received {counts['requests']} requests "
                            f"but produced 0 responses (silence in monitored zone)",
                evidence=[],
                scenario="#6 Privileged Zone Exploitation",
            ))
    return findings


def bio_006_functional_output_monitoring(messages: list[dict]) -> list[Finding]:
    """
    BIO-006: Control functional output monitoring.
    Principle: #9 (Cheap collectors, smart analyzer). Scenario: #9 (Defense Neutralization).

    If a tool that SHOULD produce variable output is returning identical
    responses, it may have been neutralized (always-pass, always-succeed).
    The caterpillar detoxification pattern: control is present but inert.
    """
    findings = []
    # Group responses by method they're replying to
    request_methods = {}
    for m in messages:
        if m.get("message_type") == "request" and m.get("message_id"):
            request_methods[str(m["message_id"])] = m.get("method")

    response_by_method = defaultdict(list)
    for m in messages:
        if m.get("message_type") == "response" and m.get("message_id"):
            method = request_methods.get(str(m["message_id"]), "unknown")
            response_by_method[method].append(m)

    for method, responses in response_by_method.items():
        if method == "tools/call" and len(responses) >= 3:
            # Check if all responses are identical
            params_set = set()
            for r in responses:
                p = r.get("params")
                params_set.add(json.dumps(p, sort_keys=True) if p else "null")

            if len(params_set) == 1:
                findings.append(Finding(
                    rule_id="BIO-006",
                    rule_set="bio-derived",
                    severity="MEDIUM",
                    description=f"Tool '{method}' returned identical responses "
                                f"{len(responses)} times (possible neutralization)",
                    evidence=responses[:3],
                    scenario="#9 Defense Neutralization",
                ))
    return findings


def bio_007_cross_server_correlation(messages: list[dict]) -> list[Finding]:
    """
    BIO-007: Cross-server credential correlation.
    Principle: #5 (Complementary detection). Scenario: #12 (Identity Rotation).

    If the same agent accesses multiple servers with different credentials
    in a short time window, flag it. Legitimate workflows typically use
    one credential path per task.
    """
    findings = []
    servers_accessed = defaultdict(list)

    for m in messages:
        if m.get("direction") == "client_to_server" and m.get("method") == "tools/call":
            sid = m.get("server_id", "unknown")
            ts = m.get("timestamp", "")
            servers_accessed[ts[:16]].append(sid)  # group by minute

    for window, servers in servers_accessed.items():
        unique_servers = set(servers)
        if len(unique_servers) >= 2:
            # Multiple servers accessed in same minute
            # This is informational, not necessarily malicious
            findings.append(Finding(
                rule_id="BIO-007",
                rule_set="bio-derived",
                severity="LOW",
                description=f"Cross-server access in window {window}: {unique_servers}",
                evidence=[],
                scenario="#12 Identity Rotation",
            ))
    return findings


def bio_008_tool_schema_change(messages: list[dict]) -> list[Finding]:
    """
    BIO-008: Tool registration integrity (schema change detection).
    Principle: #15 (Continuous tolerance). Scenario: #22 (Tool Substitution).

    If tools/list is called multiple times and the tool schema changes
    between calls, a tool may have been substituted. The cuckoo bird
    pattern: same nest, different egg.
    """
    findings = []
    list_responses = []
    for m in messages:
        if m.get("message_type") == "response" and m.get("direction") == "server_to_client":
            params = m.get("params", {})
            if isinstance(params, dict) and "tools" in params:
                list_responses.append(m)

    if len(list_responses) >= 2:
        first = json.dumps(list_responses[0].get("params"), sort_keys=True)
        for subsequent in list_responses[1:]:
            current = json.dumps(subsequent.get("params"), sort_keys=True)
            if current != first:
                findings.append(Finding(
                    rule_id="BIO-008",
                    rule_set="bio-derived",
                    severity="CRITICAL",
                    description="Tool schema changed between list calls (possible tool substitution)",
                    evidence=[list_responses[0], subsequent],
                    scenario="#22 Tool Substitution",
                ))
                break
    return findings


def bio_009_latency_anomaly(messages: list[dict]) -> list[Finding]:
    """
    BIO-009: Latency anomaly detection.
    Principle: #25 (Behavioral continuity). Scenario: #22 (Tool Substitution).

    If a tool's response latency changes significantly, the tool may have
    been replaced with a different implementation. A shadow tool will have
    different performance characteristics than the original.

    Latencies are grouped by the originating request's method (and, for
    tools/call, by tool name) so that a shift in *one* tool isn't diluted
    by unrelated traffic.
    """
    findings = []

    # Build a map: message_id -> key describing what was called.
    # For tools/call we use "tools/call:<tool_name>" so different tools
    # are tracked independently.
    key_by_id: dict[str, str] = {}
    for m in messages:
        if m.get("message_type") != "request" or not m.get("message_id"):
            continue
        method = m.get("method") or "unknown"
        key = method
        if method == "tools/call":
            p = m.get("params")
            if isinstance(p, dict):
                tool_name = p.get("name")
                if tool_name:
                    key = f"tools/call:{tool_name}"
        key_by_id[str(m["message_id"])] = key

    latencies_by_key: dict[str, list[float]] = defaultdict(list)
    for m in messages:
        lat = m.get("latency_ms")
        if lat is None or not m.get("message_id"):
            continue
        key = key_by_id.get(str(m["message_id"]))
        if key is None:
            continue
        latencies_by_key[key].append(lat)

    for key, lats in latencies_by_key.items():
        if len(lats) < 4:
            continue
        mid = len(lats) // 2
        first_avg = sum(lats[:mid]) / mid
        second_avg = sum(lats[mid:]) / (len(lats) - mid)
        if first_avg <= 0:
            continue
        change = abs(second_avg - first_avg) / first_avg
        if change > 0.5:
            findings.append(Finding(
                rule_id="BIO-009",
                rule_set="bio-derived",
                severity="MEDIUM",
                description=f"Latency shift for {key}: first half avg={first_avg:.1f}ms, "
                            f"second half avg={second_avg:.1f}ms "
                            f"({change * 100:.0f}% change, n={len(lats)})",
                evidence=[],
                scenario="#22 Tool Substitution",
            ))
    return findings


BIO_DERIVED_RULES = [
    bio_001_hmac_chain_integrity,
    bio_002_telemetry_gap,
    bio_003_behavioral_baseline_deviation,
    bio_004a_access,
    bio_005_silence_detection,
    bio_006_functional_output_monitoring,
    bio_007_cross_server_correlation,
    bio_008_tool_schema_change,
    bio_009_latency_anomaly,
]

# Note: BIO-001 operates on ALL entries (including lifecycle).
# All other rules operate on messages only.


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_rules(entries: list[dict], rule_set: str,
              honeytokens: list[str] = None,
              baseline_entries: list[dict] = None) -> list[Finding]:
    """Run the specified rule set against the log entries."""
    messages = filter_messages(entries)
    findings = []

    if rule_set in ("conventional", "all"):
        for rule in CONVENTIONAL_RULES:
            findings.extend(rule(messages))

    if rule_set in ("bio-derived", "all"):
        # BIO-001 needs all entries (checks HMAC chain)
        findings.extend(bio_001_hmac_chain_integrity(entries))
        # BIO-004a uses custom honeytokens if provided
        findings.extend(bio_004a_access(messages, honeytokens=honeytokens))
        # BIO-003 uses baseline if provided
        findings.extend(bio_003_behavioral_baseline_deviation(
            messages, baseline_messages=filter_messages(baseline_entries) if baseline_entries else None))
        # Rest operate on messages only (skip 001, 003, 004a already ran)
        for rule in BIO_DERIVED_RULES:
            if rule in (bio_001_hmac_chain_integrity, bio_003_behavioral_baseline_deviation, bio_004a_access):
                continue
            findings.extend(rule(messages))

    return findings


def main():
    parser = argparse.ArgumentParser(
        prog="mcp-detect",
        description="Run detection rules against MCP audit logs.",
    )
    parser.add_argument(
        "--log",
        required=True,
        help="Path to the JSONL audit log (mcp-tap format).",
    )
    parser.add_argument(
        "--rules",
        choices=["conventional", "bio-derived", "all"],
        default="all",
        help="Which rule set to run.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    parser.add_argument(
        "--honeytokens",
        default=None,
        help="Path to a file containing honeytoken names, one per line. "
             "Overrides the default test list. REQUIRED for production use.",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Path to a baseline JSONL log (Phase 0 legitimate traffic). "
             "Used by BIO-003 for behavioral deviation comparison instead "
             "of the naive first-half/second-half split.",
    )

    args = parser.parse_args()

    entries = read_jsonl(args.log)
    if not entries:
        print("No entries found in log file.", file=sys.stderr)
        sys.exit(1)

    # Load custom honeytokens if provided
    honeytokens = None
    if args.honeytokens:
        with open(args.honeytokens, "r") as f:
            honeytokens = [line.strip() for line in f if line.strip()]

    # Load baseline if provided
    baseline_entries = None
    if args.baseline:
        baseline_entries = read_jsonl(args.baseline)

    findings = run_rules(entries, args.rules,
                         honeytokens=honeytokens,
                         baseline_entries=baseline_entries)

    if args.format == "json":
        output = {
            "log_file": args.log,
            "rule_set": args.rules,
            "total_entries": len(entries),
            "total_messages": len(filter_messages(entries)),
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"Log: {args.log}")
        print(f"Rules: {args.rules}")
        print(f"Entries: {len(entries)}  Messages: {len(filter_messages(entries))}")
        print(f"Findings: {len(findings)}")
        print()

        if not findings:
            print("No findings.")
        else:
            # Sort by severity
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            findings.sort(key=lambda f: severity_order.get(f.severity, 99))

            for f in findings:
                scenario_tag = f" [{f.scenario}]" if f.scenario else ""
                print(f"  [{f.severity:8s}] {f.rule_id} ({f.rule_set}): "
                      f"{f.description}{scenario_tag}")
            print()

            # Summary by rule set
            by_set = defaultdict(list)
            for f in findings:
                by_set[f.rule_set].append(f)
            print("Summary:")
            for rule_set, fs in by_set.items():
                by_sev = Counter(f.severity for f in fs)
                parts = [f"{count} {sev}" for sev, count in
                         sorted(by_sev.items(), key=lambda x: severity_order.get(x[0], 99))]
                print(f"  {rule_set}: {len(fs)} findings ({', '.join(parts)})")


if __name__ == "__main__":
    main()
