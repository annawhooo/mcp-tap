"""
readers.py: Stream JSONL records from local files or GCS objects.

Two source types are supported:
  - Local file (single JSONL on disk)
  - GCS prefix (multiple objects sharing a gs://bucket/prefix)

Both readers yield (entry_dict, object_name) tuples. For local files the
object name is the file path. For GCS, the object name is the GCS object
name within its bucket.

GCS objects are listed under the given prefix and sorted lexically by
name before reading. This works for any Fluentd output convention that
puts a sortable timestamp first in the object name (the fluent-plugin-gcs
default with time_slice_format = %Y%m%d-%H%M%S satisfies this). If
records appear out of chain order, the verifier will surface that as a
prev_hmac mismatch, which is the right behavior: ambiguity about order
should be a chain break, not a silent reorder.

The GCS reader uses google-cloud-storage with ADC. It performs read-only
operations only: list_blobs and blob.open("r"). No write or delete
operations are issued.
"""

import json
from typing import Iterator, Optional


def _parse_line(line: str, object_name: str) -> tuple[dict, str]:
    """Parse a single JSONL line into (entry, object_name).

    Malformed lines yield a synthetic record with _malformed=True so the
    verifier can surface them as a chain break with context, rather than
    crashing the stream.
    """
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        entry = {"_malformed": True, "_raw": line[:500]}
    return entry, object_name


def stream_records_local(path: str) -> Iterator[tuple[dict, str]]:
    """Stream JSONL records from a local file in order.

    The path is used as the object_name in break reports, so a verifier
    operating on local files still produces actionable breaks.
    """
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield _parse_line(line, path)


def parse_gs_url(url: str) -> tuple[str, str]:
    """Parse a gs://bucket/prefix URL into (bucket, prefix).

    Strict parsing: prefix may be empty (bucket-wide read) but bucket
    must be present. Anything else raises ValueError before any network
    operations are attempted.
    """
    if not url.startswith("gs://"):
        raise ValueError(f"GCS URL must start with 'gs://': {url!r}")
    rest = url[len("gs://"):]
    if "/" in rest:
        bucket, prefix = rest.split("/", 1)
    else:
        bucket, prefix = rest, ""
    if not bucket:
        raise ValueError(f"GCS URL missing bucket name: {url!r}")
    return bucket, prefix


def stream_records_gcs(
    gs_url: str,
    *,
    project: Optional[str] = None,
) -> Iterator[tuple[dict, str]]:
    """Stream JSONL records from GCS objects matching the prefix.

    Lists all objects under the given gs://bucket/prefix, sorts them
    lexically by name (which puts time-prefixed Fluentd output in chain
    order), and streams records from each object in turn.

    READ-ONLY by design: this function only calls list_blobs and
    blob.open("r"). It never issues write, update, or delete operations
    against the bucket. A retention-locked bucket would refuse writes
    anyway, but the verifier's read-only posture is structural, not
    incidental: it should be impossible to mutate the bucket through
    this code path even if the configured credentials had write
    permissions.
    """
    try:
        from google.cloud import storage
    except ImportError as e:
        raise RuntimeError(
            "google-cloud-storage is required for GCS reading. "
            "Install with: pip install google-cloud-storage"
        ) from e

    bucket_name, prefix = parse_gs_url(gs_url)

    # ADC: storage.Client() with no args resolves credentials via the
    # default credential chain (metadata server, gcloud, etc.).
    client = storage.Client(project=project)
    bucket = client.bucket(bucket_name)

    # Materialize the list so we can sort. For very large buckets this
    # could be optimized to a sorted iterator, but for the privacy-links
    # agent's volume the full list fits comfortably in memory.
    blobs = sorted(bucket.list_blobs(prefix=prefix), key=lambda b: b.name)

    for blob in blobs:
        with blob.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                yield _parse_line(line, blob.name)
