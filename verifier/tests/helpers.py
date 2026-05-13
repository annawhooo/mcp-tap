"""
helpers.py: Chain construction and corruption helpers for adversarial tests.

These helpers reproduce mcp_tap.AuditLogger._write_entry's canonicalization
exactly. Test cases build clean chains with build_clean_chain(), apply
corruption with the corrupt_* functions, and feed the result through
verifier.chain.verify_stream.

The (entry, object_name) tuple format is the same format used by
verifier.readers.stream_records_local and stream_records_gcs, so test
chains exercise the same code path the production verifier uses.
"""

import hashlib
import hmac
import json
from typing import Iterator, Optional


def _compute_hmac(data: str, key: bytes) -> str:
    """Reproduce mcp_tap.compute_hmac byte-for-byte."""
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()


def build_clean_chain(key: bytes, n_records: int = 5) -> list[dict]:
    """Build a clean N-record chain matching mcp_tap.AuditLogger output.

    Each record has the same shape mcp_tap produces for message entries:
    timestamp, sequence, session_id, server_id, direction, method, params,
    message_id, message_type, is_error, latency_ms, hmac, prev_hmac.

    Sequence starts at 1 (matching mcp_tap, which increments before
    assignment in _write_entry). The first record's prev_hmac is the
    literal sentinel "genesis".
    """
    sequence = 0
    prev_hmac = "genesis"
    entries: list[dict] = []
    for i in range(n_records):
        entry = {
            "timestamp": f"2026-05-13T12:00:{i:02d}.000+00:00",
            "sequence": None,
            "session_id": "test-session-fixture",
            "server_id": "test",
            "direction": "client_to_server" if i % 2 == 0 else "server_to_client",
            "method": "tools/call" if i % 2 == 0 else None,
            "params": {"index": i, "msg": f"record {i}"},
            "message_id": str(i),
            "message_type": "request" if i % 2 == 0 else "response",
            "is_error": None if i % 2 == 0 else False,
            "latency_ms": None if i % 2 == 0 else 42.5,
            "hmac": "",
            "prev_hmac": "",
        }
        sequence += 1
        entry["sequence"] = sequence
        entry["prev_hmac"] = prev_hmac
        entry["hmac"] = ""
        chain_data = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        entry["hmac"] = _compute_hmac(chain_data, key)
        prev_hmac = entry["hmac"]
        entries.append(entry)
    return entries


def to_stream(
    entries: list[dict],
    object_name: str = "test:single",
) -> Iterator[tuple[dict, str]]:
    """Convert a list of entries into the (entry, object_name) stream format."""
    for entry in entries:
        yield entry, object_name


def to_stream_split(
    entries: list[dict],
    splits: list[int],
    object_prefix: str = "test:obj",
) -> Iterator[tuple[dict, str]]:
    """Split entries across multiple synthetic objects for multi-object tests.

    `splits` is a list of indices where new objects begin (inclusive). For
    example, splits=[2, 4] with 5 entries produces three objects:
    obj-000 (entries 0-1), obj-001 (entries 2-3), obj-002 (entry 4).

    This simulates the GCS multi-object case without needing actual GCS.
    The verifier walks the chain across object boundaries identically to
    a single-object stream.
    """
    boundaries = [0] + splits + [len(entries)]
    for obj_idx in range(len(boundaries) - 1):
        start = boundaries[obj_idx]
        end = boundaries[obj_idx + 1]
        object_name = f"{object_prefix}-{obj_idx:03d}"
        for entry in entries[start:end]:
            yield entry, object_name


# ---------------------------------------------------------------------------
# Corruption helpers. Each mutates the entries list in place and returns it
# for chaining. Callers pass the result through to_stream or to_stream_split.
# ---------------------------------------------------------------------------


def corrupt_inline(
    entries: list[dict],
    index: int,
    field: str,
    new_value,
) -> list[dict]:
    """Modify a field at a specific record without updating its hmac.

    Produces a record whose content no longer matches its hmac field.
    Expected detection: HMAC_MISMATCH at this record.
    """
    entries[index][field] = new_value
    return entries


def corrupt_remove(entries: list[dict], index: int) -> list[dict]:
    """Remove a record from the chain.

    Produces a chain where record (index+1)'s prev_hmac references a
    record that is no longer in the stream.
    Expected detection: PREV_HMAC_MISMATCH at the record after the gap.
    """
    del entries[index]
    return entries


def corrupt_swap(entries: list[dict], i: int, j: int) -> list[dict]:
    """Swap two records' positions in the stream.

    Each swapped record's prev_hmac no longer points to its actual
    predecessor in the modified order.
    Expected detection: PREV_HMAC_MISMATCH at one or more positions
    depending on which records were swapped.
    """
    entries[i], entries[j] = entries[j], entries[i]
    return entries


def corrupt_strip_hmac(entries: list[dict], index: int) -> list[dict]:
    """Remove the hmac field from a record.

    Expected detection: MISSING_HMAC_FIELD at this record.
    """
    del entries[index]["hmac"]
    return entries


def corrupt_strip_prev_hmac(entries: list[dict], index: int) -> list[dict]:
    """Remove the prev_hmac field from a record.

    Expected detection: MISSING_PREV_HMAC_FIELD at this record.
    """
    del entries[index]["prev_hmac"]
    return entries


def corrupt_make_malformed(entries: list[dict], index: int) -> list[dict]:
    """Replace a record with a malformed-record marker.

    This mirrors what verifier.readers produces when a JSONL line fails
    to parse as JSON. Using the marker form directly (rather than mutating
    the stream serialization) lets tests stay at the entry-stream layer.
    Expected detection: MALFORMED_RECORD at this record.
    """
    entries[index] = {"_malformed": True, "_raw": "garbage that is not json"}
    return entries


def corrupt_genesis_sentinel(entries: list[dict], new_value: str) -> list[dict]:
    """Replace the first record's prev_hmac with something other than 'genesis'.

    Expected detection: PREV_HMAC_MISMATCH at the first record.
    The verifier requires the literal sentinel string 'genesis' for the
    first record's prev_hmac.
    """
    entries[0]["prev_hmac"] = new_value
    return entries
