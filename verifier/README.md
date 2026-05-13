# mcp-tap verifier

Verify HMAC chain integrity of mcp-tap audit logs across one or more JSONL objects.

## What it does

mcp-tap writes a JSONL audit log where each record contains an `hmac` field and a `prev_hmac` field. The chain is tamper-evident: modifying any record breaks the chain. The shipped one-liner in the mcp-tap README only checks the `prev_hmac` chain — a tamperer who carefully updates both fields can bypass that. This verifier does the full check:

1. **Recompute each record's HMAC** and compare to its claimed value. Catches in-place content tamper.
2. **Verify each record's `prev_hmac`** equals the previous record's `hmac` (or the `"genesis"` sentinel for the first record). Catches insertion, deletion, reordering, and missing object boundaries.

Both checks are required. Either alone has a defeat path.

## Install

Python 3.10+ with the cloud SDK for whichever key source you use:

```bash
# Always required for GCS reading
pip install google-cloud-storage

# Pick one of these for your HMAC key source
pip install google-cloud-secret-manager   # GCP Secret Manager
pip install boto3                          # AWS Secrets Manager
pip install azure-identity azure-keyvault-secrets  # Azure Key Vault
pip install hvac                           # HashiCorp Vault
# No package needed for env var or file key sources
```

## Quick start

### Local file (smoke test)

```powershell
python -m verifier.verify --local C:\path\to\audit.jsonl --key-source env
```

(Set `MCP_TAP_HMAC_KEY` in the environment first.)

### GCS bucket with key from GCP Secret Manager

```powershell
python -m verifier.verify `
    --gcs gs://privacy-links-audit/2026/ `
    --key-source gcp-secret-manager `
    --secret-name mcp-tap-hmac-key
```

ADC handles auth. Run `gcloud auth application-default login` locally, or rely on the metadata server in GCE/GKE/Cloud Run.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | PASS — chain integrity verified |
| 1 | FAIL — one or more chain breaks detected |
| 2 | Configuration or fetch error (verification did not run) |

## Key sources

Six sources are supported. Pick exactly one per invocation; the verifier does not fall back between sources because ambiguity about which key was used would weaken the evidence.

| `--key-source` | Required flags | SDK |
|---|---|---|
| `gcp-secret-manager` | `--secret-name` | google-cloud-secret-manager |
| `aws-secrets-manager` | `--secret-id` (optional `--region`) | boto3 |
| `azure-key-vault` | `--vault-url --secret-name` | azure-identity, azure-keyvault-secrets |
| `hashicorp-vault` | `--vault-url --vault-path` | hvac |
| `env` | (optional `--env-var`, default `MCP_TAP_HMAC_KEY`) | none |
| `file` | `--key-file` | none |

Auth for cloud sources:

- **GCP**: Application Default Credentials. No explicit credential flag. The `GOOGLE_APPLICATION_CREDENTIALS` environment variable still works as one of ADC's resolution paths if needed.
- **AWS**: boto3 default credential chain (env vars, profile, instance role).
- **Azure**: `DefaultAzureCredential` (env vars, managed identity, az login, etc.).
- **HashiCorp Vault**: `VAULT_TOKEN` and `VAULT_ADDR` environment variables, or pass `--vault-url` explicitly.

## Read-only by design

The GCS reader uses `list_blobs` and `blob.open("r")` only. It never issues write, update, or delete operations against the bucket. A retention-locked bucket would refuse writes anyway, but the read-only posture is structural in the code, not incidental: it is impossible to mutate the bucket through the verifier even if the configured credentials had write permissions.

## GCS object naming convention

The verifier lists all objects matching the `--gcs` prefix and sorts them lexically by name. For chain order to be preserved across objects, Fluentd's GCS plugin must write object names with a sortable timestamp prefix. The `fluent-plugin-gcs` default with a sortable `time_slice_format` satisfies this.

### Reference Fluentd config snippet

```conf
<match mcp-tap.audit.**>
  @type gcs
  project YOUR_GCP_PROJECT
  bucket privacy-links-audit
  object_key_format %{path}%{time_slice}_%{index}.%{file_extension}
  path 2026/
  time_slice_format %Y%m%d-%H%M%S
  <buffer time>
    @type file
    path /var/log/fluentd-buffer/mcp-tap
    timekey 600          # 10-minute objects
    timekey_wait 60      # wait 1 minute after window for late data
    chunk_limit_size 32m
    flush_at_shutdown true
  </buffer>
  <format>
    @type single_value
    message_key log
    add_newline false
  </format>
</match>
```

What matters for the verifier:

- `time_slice_format` puts the timestamp first in the object name (sortable)
- `%{index}` disambiguates multiple chunks within the same time window (also sortable lexically as `_0001`, `_0002`, etc.)
- `<format> @type single_value` writes the raw JSONL lines straight through without Fluentd-added wrapping that would break chain canonicalization

If you use a different object naming convention, the verifier will still attempt to sort lexically. If records appear out of chain order, that will surface as a `prev_hmac` mismatch rather than silent acceptance, which is the correct behavior: ambiguity about order should be a chain break, not silent reorder.

## Break kinds and what they mean

The verifier categorizes failures so you can triage:

| Kind | Likely cause |
|---|---|
| `hmac_mismatch` | In-place content tamper. Field values changed but the hmac field was not (or was incorrectly) updated. |
| `prev_hmac_mismatch` | Insertion, deletion, or reordering of records, OR a missing GCS object in the prefix range, OR Fluentd wrote objects out of order. |
| `missing_hmac_field` | Record lacks the `hmac` field. Possibly a malformed or partial write, or wrong file format. |
| `missing_prev_hmac_field` | Record lacks `prev_hmac` field. Same possibilities as above. |
| `malformed_record` | Line could not be parsed as JSON. Possibly truncation, encoding corruption, or non-JSONL content in the prefix. |

The verifier reports all breaks, not just the first. A run with multiple breaks tells you whether the corruption is localized (one bad record) or systemic (many breaks suggesting wrong key, wrong canonicalization, or wrong source).

## Compute environment

The verifier runs locally by default. For compliance-grade evidence (e.g. state AG proceedings), running it from a dedicated service identity on GCE/GKE/Cloud Run gives stronger provenance than running it from a laptop. The verifier code is identical in either case — the deployment is the difference.

Phase (c) (planned) will add JSON sidecar output and an evidence-bundle tarball suitable for compliance handoff.

## Phase status

- **(a) MVP**: this version. Local + GCS sources, 6 key sources, text PASS/FAIL output.
- **(b) Adversarial tests**: deliberate corruption fixtures exercising every break kind.
- **(c) Compliance output**: JSON sidecar + evidence-bundle tarball.
