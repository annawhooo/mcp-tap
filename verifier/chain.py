"""
chain.py: HMAC chain verification for mcp-tap audit logs.

Reproduces the canonicalization mcp-tap uses when writing the chain
(see mcp_tap.AuditLogger._write_entry). Any deviation in canonicalization
fails verification on otherwise-valid data, so this module mirrors the
writer's serialization exactly:

    entry["hmac"] = ""
    chain_data = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    hmac_hex = hmac.new(key, chain_data.encode("utf-8"), hashlib.sha256).hexdigest()

The first record in any stream must have prev_hmac == "genesis" (the
literal sentinel string set by AuditLogger.__init__).
"""

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator, Optional


GENESIS_SENTINEL = "genesis"


class BreakKind(Enum):
    """Categories of chain integrity failure."""
    HMAC_MISMATCH = "hmac_mismatch"
    PREV_HMAC_MISMATCH = "prev_hmac_mismatch"
    MISSING_HMAC_FIELD = "missing_hmac_field"
    MISSING_PREV_HMAC_FIELD = "missing_prev_hmac_field"
    MALFORMED_RECORD = "malformed_record"


@dataclass(frozen=True)
class ChainBreak:
    """A single chain integrity failure with enough context to investigate."""
    kind: BreakKind
    record_index: int            # 0-based index across the full stream
    sequence: Optional[int]      # value of the record's `sequence` field, if any
    object_name: Optional[str]   # GCS object name or local path, if known
    expected: Optional[str]      # what verification computed/expected
    actual: Optional[str]        # what was found in the record
    detail: str                  # human-readable description


@dataclass
class VerificationResult:
    """Outcome of verifying a stream of records."""
    records_verified: int = 0
    breaks: list[ChainBreak] = field(default_factory=list)
    last_hmac: Optional[str] = None
    first_sequence: Optional[int] = None
    last_sequence: Optional[int] = None

    @property
    def is_valid(self) -> bool:
        return len(self.breaks) == 0


def _canonicalize(entry: dict) -> str:
    """Reproduce mcp_tap's canonicalization of an entry for HMAC computation.

    Mirrors AuditLogger._write_entry: set the hmac field to empty string,
    then serialize with sort_keys=True and compact separators. Field order
    in the on-disk JSONL is irrelevant since both writer and verifier
    re-serialize with sort_keys=True before HMAC computation.
    """
    canonical = dict(entry)
    canonical["hmac"] = ""
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"))


def compute_expected_hmac(entry: dict, key: bytes) -> str:
    """Compute the HMAC-SHA256 hex digest that should appear in entry["hmac"]."""
    chain_data = _canonicalize(entry)
    return hmac.new(key, chain_data.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_stream(
    records: Iterator[tuple[dict, Optional[str]]],
    key: bytes,
) -> VerificationResult:
    """Verify a chain of records.

    Performs both checks needed for tamper evidence:
      1. Recompute each record's HMAC and compare to its claimed value.
         Catches in-place content modification.
      2. Verify each record's prev_hmac equals the previous record's hmac
         (or "genesis" for the first record).
         Catches insertion, deletion, reordering, and missing objects.

    Both checks are needed. A tamperer who updates a record's content can
    also update its hmac field, so the prev_hmac check alone is insufficient.
    A tamperer who reorders records can preserve each record's internal
    hmac, so the recompute check alone is insufficient. Together they
    constrain both axes.

    Records arrive as (entry_dict, object_name) tuples. object_name is
    optional but used in break reports for multi-object verification.

    Constant-time comparison via hmac.compare_digest prevents timing
    side channels from leaking HMAC bits, though in this context the
    verifier is a defender tool and the attacker is hypothetical.
    """
    result = VerificationResult()
    prev_hmac_expected: Optional[str] = None  # None until first record sets it

    for idx, (entry, object_name) in enumerate(records):
        # Detect malformed records emitted by readers when JSON parsing fails
        if entry.get("_malformed"):
            result.breaks.append(ChainBreak(
                kind=BreakKind.MALFORMED_RECORD,
                record_index=idx,
                sequence=None,
                object_name=object_name,
                expected=None,
                actual=str(entry.get("_raw", ""))[:200],
                detail="record could not be parsed as JSON",
            ))
            continue

        # Field presence
        if "hmac" not in entry:
            result.breaks.append(ChainBreak(
                kind=BreakKind.MISSING_HMAC_FIELD,
                record_index=idx,
                sequence=entry.get("sequence"),
                object_name=object_name,
                expected=None,
                actual=None,
                detail="record has no 'hmac' field",
            ))
            continue
        if "prev_hmac" not in entry:
            result.breaks.append(ChainBreak(
                kind=BreakKind.MISSING_PREV_HMAC_FIELD,
                record_index=idx,
                sequence=entry.get("sequence"),
                object_name=object_name,
                expected=None,
                actual=None,
                detail="record has no 'prev_hmac' field",
            ))
            continue

        claimed_hmac = entry["hmac"]
        prev_hmac_actual = entry["prev_hmac"]

        # HMAC recompute check
        expected = compute_expected_hmac(entry, key)
        if not hmac.compare_digest(claimed_hmac, expected):
            result.breaks.append(ChainBreak(
                kind=BreakKind.HMAC_MISMATCH,
                record_index=idx,
                sequence=entry.get("sequence"),
                object_name=object_name,
                expected=expected,
                actual=claimed_hmac,
                detail=(
                    "record content does not match its hmac field "
                    "(likely in-place content tamper)"
                ),
            ))

        # prev_hmac chain check
        expected_prev = (
            GENESIS_SENTINEL if prev_hmac_expected is None
            else prev_hmac_expected
        )
        if not hmac.compare_digest(prev_hmac_actual, expected_prev):
            result.breaks.append(ChainBreak(
                kind=BreakKind.PREV_HMAC_MISMATCH,
                record_index=idx,
                sequence=entry.get("sequence"),
                object_name=object_name,
                expected=expected_prev,
                actual=prev_hmac_actual,
                detail=(
                    "prev_hmac does not match preceding record's hmac "
                    "(likely insertion, deletion, reordering, or missing "
                    "object boundary)"
                ),
            ))

        # Advance expected prev_hmac. Use the claimed_hmac value, not the
        # recomputed expected, so that if the current record was tampered
        # the next record's break surfaces accurately as either
        # PREV_HMAC_MISMATCH (chain re-stitched poorly) or a passing chain
        # check (chain stitched correctly after tamper, in which case the
        # HMAC_MISMATCH above is the load-bearing detection).
        prev_hmac_expected = claimed_hmac
        result.last_hmac = claimed_hmac

        seq = entry.get("sequence")
        if result.first_sequence is None and isinstance(seq, int):
            result.first_sequence = seq
        if isinstance(seq, int):
            result.last_sequence = seq

        result.records_verified += 1

    return result
