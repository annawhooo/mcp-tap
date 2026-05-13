"""
verify.py: CLI entry point for the mcp-tap verifier.

Invocation:
    python -m verifier.verify --local PATH --key-source env
    python -m verifier.verify --gcs gs://bucket/prefix --key-source gcp-secret-manager --secret-name NAME

The verifier picks exactly one input source (--local or --gcs) and
exactly one key source. Output is a human-readable PASS/FAIL summary
on stdout. Exit codes:
    0 = chain integrity verified
    1 = one or more chain breaks detected
    2 = configuration or fetch error (could not run verification)
"""

import argparse
import sys
from typing import Optional

from . import chain
from . import key_sources
from . import readers
from . import report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-tap-verifier",
        description=(
            "Verify HMAC chain integrity of mcp-tap audit logs. "
            "Recomputes each record's HMAC and verifies the prev_hmac chain "
            "across one or more JSONL objects."
        ),
    )

    # Input source: exactly one of --local or --gcs
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--local",
        metavar="PATH",
        help="Local JSONL file path",
    )
    src.add_argument(
        "--gcs",
        metavar="GS_URL",
        help="GCS URL (gs://bucket/prefix). Objects under prefix are read "
             "in lexical name order. Read-only operations only.",
    )
    parser.add_argument(
        "--project",
        help="GCP project ID. If omitted, resolved via ADC.",
    )


    # Key source: exactly one of six
    parser.add_argument(
        "--key-source",
        required=True,
        choices=[
            "gcp-secret-manager",
            "aws-secrets-manager",
            "azure-key-vault",
            "hashicorp-vault",
            "env",
            "file",
        ],
        help="Where to fetch the HMAC key. Cloud SDKs are imported lazily; "
             "only the SDK for the chosen source needs to be installed.",
    )

    # Per-source options. Validation that the right ones are set for the
    # chosen source happens after parsing.
    parser.add_argument("--secret-name", help="GCP/Azure secret name")
    parser.add_argument("--secret-version", default=None,
                        help="Cloud secret version (default: latest)")
    parser.add_argument("--secret-id", help="AWS secret ID")
    parser.add_argument("--region", help="AWS region (or use AWS_REGION env)")
    parser.add_argument("--vault-url", help="Azure Key Vault URL or "
                                            "HashiCorp Vault address")
    parser.add_argument("--vault-path", help="HashiCorp Vault secret path")
    parser.add_argument("--vault-field", default="key",
                        help="HashiCorp Vault field name (default: 'key')")
    parser.add_argument("--vault-mount", default="secret",
                        help="HashiCorp Vault mount point (default: 'secret')")
    parser.add_argument("--env-var", default="MCP_TAP_HMAC_KEY",
                        help="Env var name for --key-source env")
    parser.add_argument("--key-file", help="File path for --key-source file")

    # Output options
    parser.add_argument(
        "--output-json",
        metavar="PATH",
        help="Write structured verification record (JSON) to PATH. Contains "
             "all parameters needed for downstream re-verification: source, "
             "key fingerprint (SHA-256 of key, not key itself), algorithm, "
             "canonicalization, result, breaks list.",
    )
    parser.add_argument(
        "--evidence-bundle",
        metavar="PATH",
        help="Write compliance-grade evidence bundle (tar.gz) to PATH. "
             "Contains verification.json, summary.txt, first/last N sample "
             "records, and a README. Suitable for handoff to non-technical "
             "reviewers (e.g. state AG proceedings).",
    )
    parser.add_argument(
        "--bundle-sample-count",
        type=int,
        default=10,
        metavar="N",
        help="Number of records to include from each of the first and last "
             "of the chain in the evidence bundle (default: 10). Memory is "
             "bounded at 2N regardless of chain length.",
    )

    return parser


def build_key_source(args) -> key_sources.KeySource:
    """Construct the chosen KeySource from CLI args. Validates required flags."""
    src = args.key_source

    if src == "gcp-secret-manager":
        if not args.secret_name:
            raise SystemExit(
                "verifier: --secret-name is required for "
                "--key-source gcp-secret-manager"
            )
        version = args.secret_version or "latest"
        return key_sources.GCPSecretManagerKeySource(
            secret_name=args.secret_name,
            project=args.project,
            version=version,
        )

    if src == "aws-secrets-manager":
        if not args.secret_id:
            raise SystemExit(
                "verifier: --secret-id is required for "
                "--key-source aws-secrets-manager"
            )
        return key_sources.AWSSecretsManagerKeySource(
            secret_id=args.secret_id,
            region=args.region,
        )

    if src == "azure-key-vault":
        if not (args.vault_url and args.secret_name):
            raise SystemExit(
                "verifier: --vault-url and --secret-name are required for "
                "--key-source azure-key-vault"
            )
        return key_sources.AzureKeyVaultKeySource(
            vault_url=args.vault_url,
            secret_name=args.secret_name,
            version=args.secret_version,
        )

    if src == "hashicorp-vault":
        if not (args.vault_url and args.vault_path):
            raise SystemExit(
                "verifier: --vault-url and --vault-path are required for "
                "--key-source hashicorp-vault"
            )
        return key_sources.HashiCorpVaultKeySource(
            vault_addr=args.vault_url,
            secret_path=args.vault_path,
            field=args.vault_field,
            mount_point=args.vault_mount,
        )

    if src == "env":
        return key_sources.EnvVarKeySource(var_name=args.env_var)

    if src == "file":
        if not args.key_file:
            raise SystemExit(
                "verifier: --key-file is required for --key-source file"
            )
        return key_sources.FileKeySource(path=args.key_file)

    # argparse choices guards this, but defensive in case the choice list
    # is edited in one place and forgotten here.
    raise SystemExit(f"verifier: unknown key source {src!r}")


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    # Fetch HMAC key
    try:
        key_src = build_key_source(args)
        key = key_src.get_key()
    except key_sources.KeySourceError as e:
        print(f"verifier: key fetch failed: {e}", file=sys.stderr)
        return 2

    # Stream records from the chosen source
    if args.local:
        raw_records = readers.stream_records_local(args.local)
        source_label = f"local:{args.local}"
        source_type = "local"
    else:
        try:
            raw_records = readers.stream_records_gcs(
                args.gcs, project=args.project
            )
        except (ValueError, RuntimeError) as e:
            print(f"verifier: GCS source error: {e}", file=sys.stderr)
            return 2
        source_label = args.gcs
        source_type = "gcs"

    # Wrap in sampling iterator only when we need samples for the bundle.
    # Memory cost: bounded at 2 * bundle_sample_count records.
    sampled: Optional[report.SamplingIterator] = None
    if args.evidence_bundle:
        sampled = report.SamplingIterator(
            raw_records,
            first_n=args.bundle_sample_count,
            last_n=args.bundle_sample_count,
        )
        records = sampled
    else:
        records = raw_records

    # Verify
    try:
        result = chain.verify_stream(records, key)
    except Exception as e:
        # Reader-level errors that surface late (e.g. GCS auth failure on
        # first list_blobs call) end up here. Return 2 (config/fetch error),
        # not 1 (chain break), since we never got to verify.
        print(f"verifier: error while reading records: {e}", file=sys.stderr)
        return 2

    # Build verification metadata used for stdout, JSON sidecar, and bundle
    invocation_args = sys.argv[1:] if argv is None else list(argv)
    metadata = report.build_verification_metadata(
        source_label=source_label,
        source_type=source_type,
        key_source_label=key_src.describe(),
        key=key,
        result=result,
        invocation_args=invocation_args,
    )

    # Human-readable summary to stdout (always)
    print(report.format_summary_text(metadata), end="")

    # Optional JSON sidecar
    if args.output_json:
        try:
            report.write_json_sidecar(metadata, args.output_json)
            print(
                f"JSON sidecar written: {args.output_json}",
                file=sys.stderr,
            )
        except OSError as e:
            print(
                f"verifier: failed to write JSON sidecar: {e}",
                file=sys.stderr,
            )
            return 2

    # Optional evidence bundle
    if args.evidence_bundle:
        try:
            report.write_evidence_bundle(
                metadata=metadata,
                first_samples=sampled.first_samples if sampled else [],
                last_samples=sampled.last_samples if sampled else [],
                summary_text=report.format_summary_text(metadata),
                path=args.evidence_bundle,
            )
            print(
                f"Evidence bundle written: {args.evidence_bundle}",
                file=sys.stderr,
            )
        except OSError as e:
            print(
                f"verifier: failed to write evidence bundle: {e}",
                file=sys.stderr,
            )
            return 2

    return 0 if result.is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
