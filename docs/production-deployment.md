# Production Deployment Guide

This document is for the **paper audience** — security teams adopting the mcp-tap pattern in a production environment. The shipped tool is a reference implementation primarily aimed at researchers and developers running on their own laptop. `--production` mode bridges the two by making the production deployment posture demonstrable in code.

If you are running mcp-tap on your laptop to capture local MCP traffic, you do not need this document. Use `python -m mcp_tap --server "..." --log ./audit.jsonl` and ignore everything below.

## What `--production` does

When `--production` is set, mcp-tap refuses to start unless all of the following are true:

1. **External HMAC key is provided.** Either via the `MCP_TAP_HMAC_KEY` environment variable (hex-encoded) sourced from a secret manager, or via `--hmac-key-file PATH` where the file is mode 0600 or tighter and lives outside `$HOME`. Auto-generation to `~/.mcp-tap-key` is disabled because the agent runs as the same user and could read anything in `$HOME`.

2. **`--server-scope PATH` is provided explicitly.** The wrapped server's accessible directory is named at the command line. mcp-tap verifies the audit log path lives outside that scope before starting. The laptop heuristic (scan `--server` for a trailing path) is too easy to misconfigure for a deployment posture.

3. **`--sensitivity` is `redact`, `hash`, or `metadata`.** The default `full` mode logs plaintext credentials. That is wrong for any deployment whose logs ship off-host.

If any of these is missing, mcp-tap exits with code 1 and a clear stderr message naming what is missing and what to do.

## Why these requirements

The audit log's tamper-evident property depends on the HMAC key being unreachable from whoever is being audited. On a laptop, the wrapper, the key, and the agent all run as the same user. That is fine for local research — there is no adversary. In production, the LLM agent has tool access to the filesystem; a key auto-generated to `~/.mcp-tap-key` is something the agent can read, regenerate the chain after tampering, and produce a log that verifies cleanly.

The same reasoning applies to log placement. If the audit log lives inside the directory the agent's MCP server can access, the agent can rewrite or truncate it. The log must live outside that scope. `--server-scope` makes the boundary explicit and machine-checked.

Plaintext credentials in audit logs is the opposite of what audit logs are for. Logs that ship off-host (to a SIEM, to GCS, to a retention-locked archive) become a credential disclosure surface. `redact` is the minimum defensible posture; `metadata` is stricter and recommended for high-sensitivity environments.

## Recommended deployment shape

The pattern the paper describes:

```
mcp-tap (writes JSONL)
  -> local disk
  -> Fluentd (fluent-plugin-gcs)
  -> retention-locked GCS bucket
  -> SIEM / log review tooling
```

Key handling at startup, in order of preference:

1. **Secret Manager + env var.** A startup hook fetches the HMAC key from GCP Secret Manager / AWS Secrets Manager / HashiCorp Vault, exports `MCP_TAP_HMAC_KEY=<hex>`, then execs mcp-tap. The key never lands on disk.

2. **Mounted secret file.** Kubernetes-style secret mounted at `/run/secrets/mcp-tap-key` with mode 0400, owned by a service account the wrapped agent does not run as. Pass `--hmac-key-file /run/secrets/mcp-tap-key`.

3. **Bind-mounted file from a separate volume.** For non-Kubernetes deployments, bind-mount a tmpfs or separate volume that the agent's MCP server has no access to.

What you should NOT do:

- Auto-generate to `~/.mcp-tap-key` in production. (Refused by `--production`.)
- Place the keyfile under `$HOME`. (Refused by `--production`.)
- Leave the keyfile world-readable. (Refused by `--production` on POSIX.)
- Run with `--sensitivity full` in production. (Refused by `--production`.)

## Log destination

The on-disk log path is the local landing point. The retention-locked archive is what carries the long-term audit story. Fluentd is the ship-off-host mechanism the paper describes; alternatives include rsyslog, Filebeat, or a custom shipping daemon.

Two properties matter for the destination:

- **Append-only to the agent.** The agent must not be able to delete or modify shipped logs. GCS retention lock or S3 Object Lock both provide this.
- **Time-bounded retention.** Different deployments need different retention windows. The paper's privacy-compliance use case targets 7 years; security-monitoring use cases may target 90 days. The bucket lock duration is irreversible — set the right one before turning the lock on.

## Verification at run time

The startup posture is recorded in the audit log itself, in a `startup_posture` lifecycle entry that chains into the HMAC like every other entry. This means:

- A log produced under `--production` says so.
- A log produced under laptop defaults says so.
- A log whose `startup_posture` entry was tampered with breaks the chain (BIO-001 fires).

When auditing logs, check the `startup_posture` entry first. If `production_mode` is `false` and the log was supposed to come from a production deployment, that is a significant finding by itself.

## When `--production` is the wrong tool

`--production` is for the case where you can run mcp-tap as a Python process under your control. That does not cover:

- **Embedded agents** where the MCP server is launched from a vendor binary you do not control. mcp-tap is a wrapper; if you can't insert it in the launch path, it can't help.
- **Browser-based agents** where there is no stdio. mcp-tap captures stdio JSON-RPC; a different capture surface (extension API, network proxy) is needed there.
- **Multi-tenant SaaS** where the agent runs under another user's account. The pattern still applies but the deployment shape needs adapting.

The paper describes the pattern; this tool is the reference implementation. For deployments outside the supported shape, take the design and adapt it.

## See also

- `THREAT_MODEL.md` (in the coffer-mcp repo) for the credential-handling threat model that mcp-tap inherits when used together.
- The biomimetic gap analysis paper (Zenodo DOI 10.5281/zenodo.19393455) for the design rationale.
- `TODO_pre_publication.md` for known gaps and roadmap items.
