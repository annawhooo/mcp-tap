"""
test_chain.py: Adversarial corruption tests for verifier.chain.

Each test follows the same pattern:
  1. Build a clean N-record chain with build_clean_chain
  2. Apply a specific corruption via one of the corrupt_* helpers
  3. Stream the corrupted entries through verify_stream
  4. Assert the verification result matches the expected break kind,
     break count, and break location

Happy-path tests verify the verifier does not produce false positives
on valid chains. Negative-path tests verify it produces the right kind
of break for each corruption.

Failure mode taxonomy:
  HMAC_MISMATCH         - content tamper without re-signing
  PREV_HMAC_MISMATCH    - insertion, deletion, reorder, or wrong genesis
  MISSING_HMAC_FIELD    - hmac field stripped
  MISSING_PREV_HMAC_FIELD - prev_hmac field stripped
  MALFORMED_RECORD      - line could not be parsed as JSON
"""

from verifier.chain import BreakKind, verify_stream

from .helpers import (
    build_clean_chain,
    corrupt_genesis_sentinel,
    corrupt_inline,
    corrupt_make_malformed,
    corrupt_remove,
    corrupt_strip_hmac,
    corrupt_strip_prev_hmac,
    corrupt_swap,
    to_stream,
    to_stream_split,
)


# ---------------------------------------------------------------------------
# Happy-path tests: clean chains must pass without false positives.
# ---------------------------------------------------------------------------


def test_clean_chain_5_records_passes(key):
    entries = build_clean_chain(key, n_records=5)
    result = verify_stream(to_stream(entries), key)
    assert result.is_valid, f"clean chain failed: {result.breaks}"
    assert result.records_verified == 5
    assert result.first_sequence == 1
    assert result.last_sequence == 5


def test_clean_chain_single_record_passes(key):
    entries = build_clean_chain(key, n_records=1)
    result = verify_stream(to_stream(entries), key)
    assert result.is_valid, f"single-record chain failed: {result.breaks}"
    assert result.records_verified == 1
    assert entries[0]["prev_hmac"] == "genesis"


def test_clean_chain_100_records_passes(key):
    """Larger chain stress-tests the loop without stressing the algorithm."""
    entries = build_clean_chain(key, n_records=100)
    result = verify_stream(to_stream(entries), key)
    assert result.is_valid
    assert result.records_verified == 100


def test_empty_stream_passes_trivially(key):
    result = verify_stream(iter([]), key)
    assert result.is_valid
    assert result.records_verified == 0
    assert result.first_sequence is None
    assert result.last_sequence is None
    assert result.last_hmac is None


# ---------------------------------------------------------------------------
# HMAC_MISMATCH: content tamper without updating the hmac field.
# ---------------------------------------------------------------------------


def test_inline_tamper_middle_record_detects_hmac_mismatch(key):
    entries = build_clean_chain(key, n_records=5)
    corrupt_inline(entries, index=2, field="params", new_value={"TAMPERED": True})
    result = verify_stream(to_stream(entries), key)

    assert not result.is_valid
    hmac_breaks = [b for b in result.breaks if b.kind == BreakKind.HMAC_MISMATCH]
    assert len(hmac_breaks) == 1
    assert hmac_breaks[0].sequence == 3  # record at index 2 has sequence 3
    assert hmac_breaks[0].record_index == 2


def test_inline_tamper_first_record_detects_hmac_mismatch(key):
    entries = build_clean_chain(key, n_records=5)
    corrupt_inline(entries, index=0, field="method", new_value="tampered/method")
    result = verify_stream(to_stream(entries), key)

    assert not result.is_valid
    hmac_breaks = [b for b in result.breaks if b.kind == BreakKind.HMAC_MISMATCH]
    assert len(hmac_breaks) == 1
    assert hmac_breaks[0].record_index == 0


def test_inline_tamper_last_record_detects_hmac_mismatch(key):
    entries = build_clean_chain(key, n_records=5)
    corrupt_inline(entries, index=4, field="latency_ms", new_value=99999.0)
    result = verify_stream(to_stream(entries), key)

    assert not result.is_valid
    hmac_breaks = [b for b in result.breaks if b.kind == BreakKind.HMAC_MISMATCH]
    assert len(hmac_breaks) == 1
    assert hmac_breaks[0].record_index == 4


# ---------------------------------------------------------------------------
# PREV_HMAC_MISMATCH: structural tamper (insertion/deletion/reorder/wrong
# genesis sentinel).
# ---------------------------------------------------------------------------


def test_record_removal_detects_prev_hmac_mismatch(key):
    entries = build_clean_chain(key, n_records=5)
    corrupt_remove(entries, index=2)  # remove record at index 2
    result = verify_stream(to_stream(entries), key)

    assert not result.is_valid
    prev_breaks = [b for b in result.breaks if b.kind == BreakKind.PREV_HMAC_MISMATCH]
    assert len(prev_breaks) == 1
    # The record that was originally at index 3 is now at index 2; its
    # prev_hmac references the removed record, not the record now in front of it.
    assert prev_breaks[0].record_index == 2


def test_record_swap_detects_prev_hmac_mismatch(key):
    entries = build_clean_chain(key, n_records=5)
    corrupt_swap(entries, i=1, j=3)
    result = verify_stream(to_stream(entries), key)

    assert not result.is_valid
    prev_breaks = [b for b in result.breaks if b.kind == BreakKind.PREV_HMAC_MISMATCH]
    # Swapping non-adjacent records breaks the chain at multiple positions.
    assert len(prev_breaks) >= 1


def test_wrong_genesis_sentinel_detects_prev_hmac_mismatch(key):
    entries = build_clean_chain(key, n_records=5)
    corrupt_genesis_sentinel(entries, new_value="not-genesis")
    result = verify_stream(to_stream(entries), key)

    assert not result.is_valid
    prev_breaks = [b for b in result.breaks if b.kind == BreakKind.PREV_HMAC_MISMATCH]
    assert len(prev_breaks) >= 1
    assert prev_breaks[0].record_index == 0
    assert prev_breaks[0].expected == "genesis"
    assert prev_breaks[0].actual == "not-genesis"


# ---------------------------------------------------------------------------
# MISSING_HMAC_FIELD / MISSING_PREV_HMAC_FIELD: field stripped from record.
# ---------------------------------------------------------------------------


def test_stripped_hmac_field_detects_missing_hmac(key):
    entries = build_clean_chain(key, n_records=5)
    corrupt_strip_hmac(entries, index=2)
    result = verify_stream(to_stream(entries), key)

    assert not result.is_valid
    breaks = [b for b in result.breaks if b.kind == BreakKind.MISSING_HMAC_FIELD]
    assert len(breaks) == 1
    assert breaks[0].record_index == 2


def test_stripped_prev_hmac_field_detects_missing_prev_hmac(key):
    entries = build_clean_chain(key, n_records=5)
    corrupt_strip_prev_hmac(entries, index=2)
    result = verify_stream(to_stream(entries), key)

    assert not result.is_valid
    breaks = [b for b in result.breaks if b.kind == BreakKind.MISSING_PREV_HMAC_FIELD]
    assert len(breaks) == 1
    assert breaks[0].record_index == 2


# ---------------------------------------------------------------------------
# MALFORMED_RECORD: line failed JSON parsing at the reader layer.
# ---------------------------------------------------------------------------


def test_malformed_record_detects_malformed(key):
    entries = build_clean_chain(key, n_records=5)
    corrupt_make_malformed(entries, index=2)
    result = verify_stream(to_stream(entries), key)

    assert not result.is_valid
    breaks = [b for b in result.breaks if b.kind == BreakKind.MALFORMED_RECORD]
    assert len(breaks) == 1
    assert breaks[0].record_index == 2


# ---------------------------------------------------------------------------
# Wrong key: every record fails HMAC_MISMATCH.
# ---------------------------------------------------------------------------


def test_wrong_key_fails_every_record(key, other_key):
    entries = build_clean_chain(key, n_records=5)
    # Verify with a different key than the one used to sign
    result = verify_stream(to_stream(entries), other_key)

    assert not result.is_valid
    hmac_breaks = [b for b in result.breaks if b.kind == BreakKind.HMAC_MISMATCH]
    assert len(hmac_breaks) == 5
    # Every record's hmac should fail because every record was signed with key,
    # not other_key. The prev_hmac chain itself remains internally consistent
    # because we are using the actual signed values without modification.


# ---------------------------------------------------------------------------
# Non-short-circuiting: verifier reports all breaks, not just the first.
# ---------------------------------------------------------------------------


def test_multiple_breaks_all_reported(key):
    """Two independent corruptions should produce two breaks in the report."""
    entries = build_clean_chain(key, n_records=5)
    corrupt_inline(entries, index=1, field="method", new_value="tampered1")
    corrupt_inline(entries, index=3, field="method", new_value="tampered3")
    result = verify_stream(to_stream(entries), key)

    assert not result.is_valid
    hmac_breaks = [b for b in result.breaks if b.kind == BreakKind.HMAC_MISMATCH]
    assert len(hmac_breaks) == 2
    assert {b.record_index for b in hmac_breaks} == {1, 3}


# ---------------------------------------------------------------------------
# Multi-object scenarios: chain spans multiple synthetic GCS objects.
# ---------------------------------------------------------------------------


def test_clean_chain_across_multiple_objects_passes(key):
    """A chain split across 3 'objects' verifies identically to one."""
    entries = build_clean_chain(key, n_records=6)
    # Split: obj-000 has entries 0-1, obj-001 has 2-3, obj-002 has 4-5
    stream = to_stream_split(entries, splits=[2, 4])
    result = verify_stream(stream, key)

    assert result.is_valid
    assert result.records_verified == 6


def test_missing_entire_object_detects_prev_hmac_mismatch(key):
    """Simulate the case where one whole GCS object in the middle is missing.

    Build a 6-record chain split into 3 objects (2 records each), then
    drop the middle 2 records (the entire middle object). The first record
    of the third 'object' will reference an hmac that no longer exists
    in the stream.
    """
    entries = build_clean_chain(key, n_records=6)
    # Remove entries 2 and 3 (the middle 'object')
    del entries[2:4]
    # The remaining 4 entries: indices 0,1 from object 0; 4,5 from object 2
    # In the synthetic split, this looks like obj-000 (0-1) followed by
    # obj-001 (originally 4-5, but in the new list at indices 2-3)
    stream = to_stream_split(entries, splits=[2])
    result = verify_stream(stream, key)

    assert not result.is_valid
    prev_breaks = [b for b in result.breaks if b.kind == BreakKind.PREV_HMAC_MISMATCH]
    assert len(prev_breaks) >= 1
    # The break occurs at record_index 2 (the first record after the gap)
    assert prev_breaks[0].record_index == 2


def test_multi_object_break_reports_correct_object_name(key):
    """Verify the break report includes the object name where the break occurred."""
    entries = build_clean_chain(key, n_records=6)
    # Tamper a record in what would be the second 'object'
    corrupt_inline(entries, index=3, field="method", new_value="tampered")
    stream = to_stream_split(entries, splits=[2, 4])
    result = verify_stream(stream, key)

    assert not result.is_valid
    hmac_breaks = [b for b in result.breaks if b.kind == BreakKind.HMAC_MISMATCH]
    assert len(hmac_breaks) == 1
    assert hmac_breaks[0].record_index == 3
    # Record 3 falls in the second synthetic object (splits at 2 puts
    # index 2-3 in obj-001)
    assert hmac_breaks[0].object_name == "test:obj-001"
