"""
report.py: JSON sidecar and evidence-bundle generation for compliance handoff.

Two output products:

1. **JSON sidecar** (`--output-json PATH`): structured verification record
   suitable for downstream re-verification. Contains the cryptographic
   parameters (algorithm, canonicalization rules, key fingerprint), the
   verification result, and the full breaks list. A downstream party
   could re-implement the verifier from this metadata alone.

2. **Evidence bundle** (`--evidence-bundle PATH`): tar.gz containing the
   JSON sidecar, a human-readable summary, first/last N sample records,
   and a README explaining the bundle. Suitable for compliance handoff
   (e.g. state AG proceedings) where the recipient may not have access
   to the original source.

The key fingerprint is SHA-256 of the key, hex-encoded. This proves which
key was used for verification without revealing the key itself. Anyone
holding the same key can compute the same fingerprint and confirm key
identity.
"""

import hashlib
import io
import json
import tarfile
from collections import deque
from datetime import datetime, timezone
from typing import Iterator, Optional


VERIFIER_VERSION = "0.1.0"


def key_fingerprint(key: bytes) -> str:
    """SHA-256 hex digest of the key.

    Used as a stable, non-revealing identifier of which key was used for
    verification. Two parties holding the same key compute the same
    fingerprint. The fingerprint reveals nothing about the key under
    standard cryptographic assumptions (SHA-256 preimage resistance).
    """
    return hashlib.sha256(key).hexdigest()


class SamplingIterator:
    """Wrapper that captures first-N and last-N samples while iterating.

    The verifier consumes records via a one-pass iterator. To collect
    samples for the evidence bundle without holding the entire chain in
    memory, this wrapper captures the first N records in a list and
    maintains a rolling buffer of the last N records. Memory is bounded
    at 2N regardless of chain length.

    If total records < first_n + last_n, the first and last buffers
    will overlap. The caller is responsible for deduplicating if needed
    (or accepting the overlap as a feature: it means the entire chain
    fits in the sample).
    """

    def __init__(
        self,
        records: Iterator[tuple[dict, Optional[str]]],
        first_n: int = 10,
        last_n: int = 10,
    ):
        self._records = records
        self._first_n = first_n
        self._last_n = last_n
        self.first_samples: list[tuple[dict, Optional[str]]] = []
        self._last_buffer: deque = deque(maxlen=last_n)
        self.total_seen = 0

    def __iter__(self):
        for item in self._records:
            if len(self.first_samples) < self._first_n:
                self.first_samples.append(item)
            self._last_buffer.append(item)
            self.total_seen += 1
            yield item

    @property
    def last_samples(self) -> list[tuple[dict, Optional[str]]]:
        """Last N records seen, in order."""
        return list(self._last_buffer)


def build_verification_metadata(
    source_label: str,
    source_type: str,
    key_source_label: str,
    key: bytes,
    result,  # chain.VerificationResult, untyped here to avoid circular import
    invocation_args: Optional[list[str]] = None,
) -> dict:
    """Build the structured metadata dict that becomes verification.json.

    Captures everything a downstream party needs to re-verify or audit
    the verification: source identification, key fingerprint, algorithm
    and canonicalization parameters, verification timestamp, and the
    full breaks list with all context fields.

    Excludes: the HMAC key itself (only its fingerprint), any credentials,
    raw payload data beyond what is needed to identify breaks.
    """
    return {
        "verifier_version": VERIFIER_VERSION,
        "verification_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source": source_label,
        "source_type": source_type,
        "key_source": key_source_label,
        "key_fingerprint_sha256": key_fingerprint(key),
        "algorithm": "HMAC-SHA256",
        "canonicalization": {
            "serialization": "json.dumps with sort_keys=True, separators=(',', ':')",
            "encoding": "utf-8",
            "hmac_field_treatment": "set to empty string before HMAC computation",
            "genesis_sentinel": "genesis",
            "sequence_starts_at": 1,
            "output_format": "hex digest, lowercase",
        },
        "invocation_args": invocation_args or [],
        "result": "PASS" if result.is_valid else "FAIL",
        "records_verified": result.records_verified,
        "first_sequence": result.first_sequence,
        "last_sequence": result.last_sequence,
        "last_hmac": result.last_hmac,
        "break_count": len(result.breaks),
        "breaks": [
            {
                "kind": b.kind.value,
                "record_index": b.record_index,
                "sequence": b.sequence,
                "object_name": b.object_name,
                "expected": b.expected,
                "actual": b.actual,
                "detail": b.detail,
            }
            for b in result.breaks
        ],
    }


def write_json_sidecar(metadata: dict, path: str) -> None:
    """Write the verification metadata to a JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, sort_keys=True)
        f.write("\n")


def format_summary_text(metadata: dict) -> str:
    """Format the verification metadata as a human-readable summary."""
    lines = [
        "=" * 70,
        "mcp-tap verifier - verification summary",
        "=" * 70,
        f"Verifier version: {metadata['verifier_version']}",
        f"Run timestamp:    {metadata['verification_timestamp_utc']}",
        f"Source:           {metadata['source']}",
        f"Source type:      {metadata['source_type']}",
        f"Key source:       {metadata['key_source']}",
        f"Key fingerprint:  {metadata['key_fingerprint_sha256']}",
        f"Algorithm:        {metadata['algorithm']}",
        "-" * 70,
        f"Records verified: {metadata['records_verified']}",
    ]
    if metadata["first_sequence"] is not None:
        lines.append(
            f"Sequence range:   "
            f"{metadata['first_sequence']} -> {metadata['last_sequence']}"
        )
    lines.append(f"Last HMAC:        {metadata['last_hmac']}")
    lines.append("-" * 70)
    lines.append(f"Result:           {metadata['result']}")
    if metadata["break_count"] > 0:
        lines.append(f"Break count:      {metadata['break_count']}")
        lines.append("")
        for i, b in enumerate(metadata["breaks"], start=1):
            lines.append(f"Break {i}: {b['kind']}")
            lines.append(f"  record_index: {b['record_index']}")
            lines.append(f"  sequence:     {b['sequence']}")
            lines.append(f"  object:       {b['object_name']}")
            lines.append(f"  expected:     {b['expected']}")
            lines.append(f"  actual:       {b['actual']}")
            lines.append(f"  detail:       {b['detail']}")
            lines.append("")
    return "\n".join(lines) + "\n"


def _samples_to_jsonl_bytes(
    samples: list[tuple[dict, Optional[str]]],
) -> bytes:
    """Serialize a list of (entry, object_name) samples to JSONL bytes.

    Each line is the entry dict serialized with sort_keys=True for
    consistent output. The object_name is preserved in a sidecar field
    `_source_object` so the reviewer can correlate samples back to
    their source GCS object.
    """
    lines = []
    for entry, object_name in samples:
        record = dict(entry)
        record["_source_object"] = object_name
        lines.append(json.dumps(record, sort_keys=True))
    return ("\n".join(lines) + "\n").encode("utf-8")


_BUNDLE_README = """\
mcp-tap verifier evidence bundle
=================================

This bundle contains evidence of an HMAC chain integrity verification
performed by the mcp-tap verifier (https://github.com/annawhooo/mcp-tap).

Contents
--------

verification.json
    Structured verification record. Contains all parameters needed for
    a downstream party to independently re-verify the chain: source
    identification, key fingerprint (SHA-256 of the HMAC key, not the
    key itself), algorithm, canonicalization rules, verification result,
    and full breaks list.

summary.txt
    Human-readable PASS/FAIL summary of the verification, including
    each break's record index, sequence number, object name, and
    expected/actual HMAC values where applicable.

samples/first-records.jsonl
samples/last-records.jsonl
    First and last N records from the verified stream, verbatim. Each
    record's source object name is preserved in a `_source_object` field
    appended to the record. These samples allow a reviewer to confirm
    the chain's extent and inspect representative content without
    requiring access to the original source.

How to re-verify
----------------

A downstream party with access to the original source can re-implement
the verification using the parameters in verification.json:

  1. Read records in order from the source identified by `source`.
  2. For each record, set the `hmac` field to "" and serialize the
     record with json.dumps using sort_keys=True and compact separators
     (",", ":").
  3. Compute HMAC-SHA256 over the UTF-8 encoded serialization, using
     a key whose SHA-256 fingerprint matches `key_fingerprint_sha256`.
  4. Compare the computed digest to the record's `hmac` field.
  5. Verify the record's `prev_hmac` field matches the previous record's
     `hmac` (or the literal string "genesis" for the first record).

If the re-verification produces the same `result`, `records_verified`,
and `breaks` list as this bundle, the verification is reproducible.
"""


def write_evidence_bundle(
    metadata: dict,
    first_samples: list[tuple[dict, Optional[str]]],
    last_samples: list[tuple[dict, Optional[str]]],
    summary_text: str,
    path: str,
) -> None:
    """Write an evidence bundle tarball (.tar.gz).

    Layout inside the tarball:
        evidence-bundle/
        ├── README.txt
        ├── verification.json
        ├── summary.txt
        └── samples/
            ├── first-records.jsonl
            └── last-records.jsonl

    All files are streamed into the tarball in memory (no temp files
    on disk). Compression: gzip.
    """
    json_bytes = (
        json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    summary_bytes = summary_text.encode("utf-8")
    first_bytes = _samples_to_jsonl_bytes(first_samples)
    last_bytes = _samples_to_jsonl_bytes(last_samples)
    readme_bytes = _BUNDLE_README.encode("utf-8")

    files = [
        ("evidence-bundle/README.txt", readme_bytes),
        ("evidence-bundle/verification.json", json_bytes),
        ("evidence-bundle/summary.txt", summary_bytes),
        ("evidence-bundle/samples/first-records.jsonl", first_bytes),
        ("evidence-bundle/samples/last-records.jsonl", last_bytes),
    ]

    with tarfile.open(path, "w:gz") as tar:
        for name, data in files:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = int(datetime.now(timezone.utc).timestamp())
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
