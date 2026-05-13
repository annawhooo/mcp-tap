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


def print_text_report(
    source_label: str,
    key_source_label: str,
    result: chain.VerificationResult,
) -> None:
    """Print a human-readable PASS/FAIL summary to stdout.

    Phase (c) will add JSON sidecar and evidence-bundle output. This MVP
    text output is enough for engineer-facing verification.
    """
    print("=" * 70)
    print("mcp-tap verifier")
    print("=" * 70)
    print(f"Source:       {source_label}")
    print(f"Key source:   {key_source_label}")
    print(f"Records:      {result.records_verified}")
    if result.first_sequence is not None:
        print(
            f"Seq range:    {result.first_sequence} -> {result.last_sequence}"
        )
    print(f"Last HMAC:    {result.last_hmac}")
    print("-" * 70)

    if result.is_valid:
        print("RESULT: PASS — chain integrity verified")
        return

    print(f"RESULT: FAIL — {len(result.breaks)} chain break(s) detected")
    print()
    for i, b in enumerate(result.breaks, start=1):
        print(f"Break {i}: {b.kind.value}")
        print(f"  record_index: {b.record_index}")
        print(f"  sequence:     {b.sequence}")
        print(f"  object:       {b.object_name}")
        print(f"  expected:     {b.expected}")
        print(f"  actual:       {b.actual}")
        print(f"  detail:       {b.detail}")
        print()


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
        records = readers.stream_records_local(args.local)
        source_label = f"local:{args.local}"
    else:
        try:
            records = readers.stream_records_gcs(args.gcs, project=args.project)
        except (ValueError, RuntimeError) as e:
            print(f"verifier: GCS source error: {e}", file=sys.stderr)
            return 2
        source_label = args.gcs

    # Verify
    try:
        result = chain.verify_stream(records, key)
    except Exception as e:
        # Reader-level errors that surface late (e.g. GCS auth failure on
        # first list_blobs call) end up here. Return 2 (config/fetch error),
        # not 1 (chain break), since we never got to verify.
        print(f"verifier: error while reading records: {e}", file=sys.stderr)
        return 2

    print_text_report(source_label, key_src.describe(), result)
    return 0 if result.is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
