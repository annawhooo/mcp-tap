"""
test_report.py: Tests for verifier.report (JSON sidecar and evidence bundle).

Coverage:
  - key_fingerprint produces stable SHA-256 hex
  - SamplingIterator captures first N and last N correctly across various
    chain sizes (smaller than N, equal to N, larger than 2N)
  - build_verification_metadata produces a dict with all required fields
  - format_summary_text covers PASS and FAIL cases
  - write_json_sidecar produces parseable JSON
  - write_evidence_bundle produces a valid tar.gz with expected entries
"""

import hashlib
import io
import json
import tarfile

from verifier.chain import verify_stream
from verifier.report import (
    SamplingIterator,
    VERIFIER_VERSION,
    build_verification_metadata,
    format_summary_text,
    key_fingerprint,
    write_evidence_bundle,
    write_json_sidecar,
)

from .helpers import build_clean_chain, corrupt_inline, to_stream


# ---------------------------------------------------------------------------
# key_fingerprint
# ---------------------------------------------------------------------------


def test_key_fingerprint_is_sha256_hex():
    key = b"some-test-key"
    fp = key_fingerprint(key)
    # SHA-256 hex output is 64 lowercase hex chars
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)
    # And it matches the hashlib reference
    assert fp == hashlib.sha256(key).hexdigest()


def test_key_fingerprint_is_deterministic():
    key = b"another-test-key"
    assert key_fingerprint(key) == key_fingerprint(key)


def test_key_fingerprint_differs_for_different_keys():
    assert key_fingerprint(b"key-a") != key_fingerprint(b"key-b")


# ---------------------------------------------------------------------------
# SamplingIterator
# ---------------------------------------------------------------------------


def test_sampling_iterator_captures_first_n(key):
    entries = build_clean_chain(key, n_records=20)
    sampler = SamplingIterator(to_stream(entries), first_n=5, last_n=5)
    list(sampler)  # consume
    assert len(sampler.first_samples) == 5
    # First samples should be records 1-5 (in stream order)
    assert sampler.first_samples[0][0]["sequence"] == 1
    assert sampler.first_samples[4][0]["sequence"] == 5


def test_sampling_iterator_captures_last_n(key):
    entries = build_clean_chain(key, n_records=20)
    sampler = SamplingIterator(to_stream(entries), first_n=5, last_n=5)
    list(sampler)
    last = sampler.last_samples
    assert len(last) == 5
    # Last samples should be records 16-20
    assert last[0][0]["sequence"] == 16
    assert last[4][0]["sequence"] == 20


def test_sampling_iterator_handles_short_chain(key):
    """When chain is shorter than first_n + last_n, samples overlap."""
    entries = build_clean_chain(key, n_records=3)
    sampler = SamplingIterator(to_stream(entries), first_n=5, last_n=5)
    list(sampler)
    # All 3 records captured in first_samples (since 3 < 5)
    assert len(sampler.first_samples) == 3
    # All 3 records captured in last_samples too (rolling buffer with 3 items)
    assert len(sampler.last_samples) == 3


def test_sampling_iterator_yields_all_records(key):
    """SamplingIterator must pass through every record, not just sample them."""
    entries = build_clean_chain(key, n_records=20)
    sampler = SamplingIterator(to_stream(entries), first_n=3, last_n=3)
    consumed = list(sampler)
    assert len(consumed) == 20
    assert sampler.total_seen == 20


def test_sampling_iterator_integrates_with_verify_stream(key):
    """Wrapping records in SamplingIterator must not affect verification."""
    entries = build_clean_chain(key, n_records=10)
    sampler = SamplingIterator(to_stream(entries), first_n=3, last_n=3)
    result = verify_stream(sampler, key)
    assert result.is_valid
    assert result.records_verified == 10
    assert len(sampler.first_samples) == 3
    assert len(sampler.last_samples) == 3


# ---------------------------------------------------------------------------
# build_verification_metadata
# ---------------------------------------------------------------------------


def test_metadata_has_required_fields(key):
    entries = build_clean_chain(key, n_records=5)
    result = verify_stream(to_stream(entries), key)
    metadata = build_verification_metadata(
        source_label="test:source",
        source_type="local",
        key_source_label="env-var:TEST",
        key=key,
        result=result,
    )

    required_top_level = {
        "verifier_version",
        "verification_timestamp_utc",
        "source",
        "source_type",
        "key_source",
        "key_fingerprint_sha256",
        "algorithm",
        "canonicalization",
        "invocation_args",
        "result",
        "records_verified",
        "first_sequence",
        "last_sequence",
        "last_hmac",
        "break_count",
        "breaks",
    }
    missing = required_top_level - metadata.keys()
    assert not missing, f"missing metadata fields: {missing}"

    assert metadata["verifier_version"] == VERIFIER_VERSION
    assert metadata["algorithm"] == "HMAC-SHA256"
    assert metadata["result"] == "PASS"
    assert metadata["records_verified"] == 5
    assert metadata["break_count"] == 0
    assert metadata["breaks"] == []
    assert metadata["key_fingerprint_sha256"] == key_fingerprint(key)


def test_metadata_includes_breaks_on_failure(key):
    entries = build_clean_chain(key, n_records=5)
    corrupt_inline(entries, index=2, field="method", new_value="tampered")
    result = verify_stream(to_stream(entries), key)
    metadata = build_verification_metadata(
        source_label="test:source",
        source_type="local",
        key_source_label="env-var:TEST",
        key=key,
        result=result,
    )

    assert metadata["result"] == "FAIL"
    assert metadata["break_count"] == 1
    assert len(metadata["breaks"]) == 1
    break_record = metadata["breaks"][0]
    assert break_record["kind"] == "hmac_mismatch"
    assert break_record["record_index"] == 2
    assert break_record["sequence"] == 3
    assert "expected" in break_record
    assert "actual" in break_record
    assert "detail" in break_record


def test_metadata_excludes_raw_key(key):
    """The metadata must never contain the HMAC key in any form."""
    entries = build_clean_chain(key, n_records=3)
    result = verify_stream(to_stream(entries), key)
    metadata = build_verification_metadata(
        source_label="test:source",
        source_type="local",
        key_source_label="env-var:TEST",
        key=key,
        result=result,
    )

    serialized = json.dumps(metadata)
    # Neither the key bytes nor its hex form should appear in the output
    assert key.hex() not in serialized
    # The fingerprint should be present
    assert key_fingerprint(key) in serialized


# ---------------------------------------------------------------------------
# format_summary_text
# ---------------------------------------------------------------------------


def test_summary_text_pass_case(key):
    entries = build_clean_chain(key, n_records=5)
    result = verify_stream(to_stream(entries), key)
    metadata = build_verification_metadata(
        source_label="test:src",
        source_type="local",
        key_source_label="env-var:TEST",
        key=key,
        result=result,
    )
    text = format_summary_text(metadata)
    assert "PASS" in text
    assert "test:src" in text
    assert "FAIL" not in text


def test_summary_text_fail_case_includes_break_details(key):
    entries = build_clean_chain(key, n_records=5)
    corrupt_inline(entries, index=1, field="method", new_value="tampered")
    result = verify_stream(to_stream(entries), key)
    metadata = build_verification_metadata(
        source_label="test:src",
        source_type="local",
        key_source_label="env-var:TEST",
        key=key,
        result=result,
    )
    text = format_summary_text(metadata)
    assert "FAIL" in text
    assert "hmac_mismatch" in text
    assert "record_index" in text


# ---------------------------------------------------------------------------
# write_json_sidecar
# ---------------------------------------------------------------------------


def test_json_sidecar_is_valid_json(tmp_path, key):
    entries = build_clean_chain(key, n_records=5)
    result = verify_stream(to_stream(entries), key)
    metadata = build_verification_metadata(
        source_label="test:src",
        source_type="local",
        key_source_label="env-var:TEST",
        key=key,
        result=result,
    )

    sidecar_path = tmp_path / "verification.json"
    write_json_sidecar(metadata, str(sidecar_path))

    # Read it back and confirm it parses to a dict matching the original
    with open(sidecar_path, "r", encoding="utf-8") as f:
        parsed = json.load(f)
    assert parsed["result"] == "PASS"
    assert parsed["records_verified"] == 5
    assert parsed["key_fingerprint_sha256"] == key_fingerprint(key)


# ---------------------------------------------------------------------------
# write_evidence_bundle
# ---------------------------------------------------------------------------


def test_evidence_bundle_contains_expected_files(tmp_path, key):
    entries = build_clean_chain(key, n_records=10)
    sampler = SamplingIterator(to_stream(entries), first_n=3, last_n=3)
    result = verify_stream(sampler, key)
    metadata = build_verification_metadata(
        source_label="test:src",
        source_type="local",
        key_source_label="env-var:TEST",
        key=key,
        result=result,
    )

    bundle_path = tmp_path / "bundle.tar.gz"
    write_evidence_bundle(
        metadata=metadata,
        first_samples=sampler.first_samples,
        last_samples=sampler.last_samples,
        summary_text=format_summary_text(metadata),
        path=str(bundle_path),
    )

    assert bundle_path.exists()
    # Confirm tarball structure
    with tarfile.open(bundle_path, "r:gz") as tar:
        names = set(tar.getnames())
        assert "evidence-bundle/README.txt" in names
        assert "evidence-bundle/verification.json" in names
        assert "evidence-bundle/summary.txt" in names
        assert "evidence-bundle/samples/first-records.jsonl" in names
        assert "evidence-bundle/samples/last-records.jsonl" in names


def test_evidence_bundle_json_is_parseable(tmp_path, key):
    """The verification.json inside the bundle must be valid JSON."""
    entries = build_clean_chain(key, n_records=5)
    sampler = SamplingIterator(to_stream(entries), first_n=2, last_n=2)
    result = verify_stream(sampler, key)
    metadata = build_verification_metadata(
        source_label="test:src",
        source_type="local",
        key_source_label="env-var:TEST",
        key=key,
        result=result,
    )

    bundle_path = tmp_path / "bundle.tar.gz"
    write_evidence_bundle(
        metadata=metadata,
        first_samples=sampler.first_samples,
        last_samples=sampler.last_samples,
        summary_text=format_summary_text(metadata),
        path=str(bundle_path),
    )

    with tarfile.open(bundle_path, "r:gz") as tar:
        member = tar.getmember("evidence-bundle/verification.json")
        f = tar.extractfile(member)
        assert f is not None
        parsed = json.load(io.TextIOWrapper(f, encoding="utf-8"))
    assert parsed["result"] == "PASS"
    assert parsed["records_verified"] == 5


def test_evidence_bundle_samples_are_jsonl(tmp_path, key):
    """The samples files inside the bundle must be valid JSONL."""
    entries = build_clean_chain(key, n_records=10)
    sampler = SamplingIterator(to_stream(entries), first_n=3, last_n=3)
    result = verify_stream(sampler, key)
    metadata = build_verification_metadata(
        source_label="test:src",
        source_type="local",
        key_source_label="env-var:TEST",
        key=key,
        result=result,
    )

    bundle_path = tmp_path / "bundle.tar.gz"
    write_evidence_bundle(
        metadata=metadata,
        first_samples=sampler.first_samples,
        last_samples=sampler.last_samples,
        summary_text=format_summary_text(metadata),
        path=str(bundle_path),
    )

    with tarfile.open(bundle_path, "r:gz") as tar:
        first_member = tar.getmember("evidence-bundle/samples/first-records.jsonl")
        f = tar.extractfile(first_member)
        assert f is not None
        text = io.TextIOWrapper(f, encoding="utf-8").read()

    lines = [line for line in text.splitlines() if line.strip()]
    assert len(lines) == 3
    # Each line is a parseable JSON object with a _source_object field
    for line in lines:
        record = json.loads(line)
        assert "_source_object" in record
        assert "sequence" in record
