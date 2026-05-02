# Scenario Inventory & Expected Detection Signatures

This document defines, per scenario, what each detection rule SHOULD do when run against the captured logs. It exists so that scoring can use a 4-state taxonomy with intent rather than rubber-stamping any rule firing as "detected."

## 4-State Scoring Taxonomy

| State | Meaning |
|-------|---------|
| **DETECTED** | Expected rule fired correctly on the captured log |
| **RULE_MISSED** | Data was present in the log but no rule fired (rule weakness) |
| **DATA_MISSED** | Attack happened but the captured data didn't include what the rule needed (capture-tool weakness) |
| **NOT_OBSERVABLE** | The attack is invisible at this transport layer regardless of rule set (architectural blind spot) |

The distinction between RULE_MISSED, DATA_MISSED, and NOT_OBSERVABLE is the experiment's core contribution. Conflating them obscures the motion-detector visibility gap.

## Honeytoken Set

From `experiment/honeytokens.txt`:
- `customer_export_2024.csv`
- `payroll_q3_draft.xlsx`
- `admin_credentials_backup.txt`
- `aws_keys_old.env`
- `database_dump_prod.sql`

Privileged-directory files are NOT in the honeytoken set. This is intentional: keeps the canary set small and meaningful. Scenarios that read privileged files trigger BIO-003 (deviation), not BIO-004a (honeytoken access).

## Visibility Constraints (Group B vs Group C)

Bifrost only logs tool *executions*, not full MCP protocol traffic. So Group B has structural blind spots that produce DATA_MISSED or NOT_OBSERVABLE for certain rules:

| Rule | Group C (mcp-tap) | Group B (Bifrost) | Reason |
|------|-------------------|-------------------|--------|
| CONV-001 | full | full | error responses captured by both |
| CONV-002 | full | full | request timestamps captured by both |
| CONV-003 | full | full | tools/call timestamps captured by both |
| CONV-004 | full | full | tool args captured by both |
| CONV-005 | full | **NOT_OBSERVABLE** | needs `tools/list` METHOD calls; Bifrost only logs tool executions |
| BIO-001 | full | **NOT_OBSERVABLE** | HMAC chain is mcp-tap-only |
| BIO-002 / 002b | full | full | request/response pairing captured by both |
| BIO-003 | full | full | tools/call distribution captured by both |
| BIO-004a | full | full | tool args captured by both |
| BIO-005 | full | partial | Bifrost rows are inherently paired request+response, may obscure silence |
| BIO-006 | full | partial | response content captured by both, but Bifrost may normalize differently |
| BIO-007 | n/a | n/a | single-server experiment; rule fires on multi-server correlation |
| BIO-008 | full | **NOT_OBSERVABLE** | needs `tools/list` responses; Bifrost only logs tool executions |
| BIO-009 | full | full | latency captured by both |

## Scenario State Changes (Data Reset Required)

| Scenario | Modifies state? | Notes |
|----------|-----------------|-------|
| baseline | No | read-only |
| s01 | No | read-only |
| s02 | No | read-only |
| s03 | No (writes invalid args, but server rejects) | error responses only |
| s06 | No | read-only |
| s07 | No | read-only |
| s08 | No | read-only |
| **s09** | **YES** | overwrites `security_policy_draft.txt`, creates `privileged/.allowed` |
| s12 | No | read-only |
| s13 | No | read-only (but reads `security_policy_draft.txt` — affected if s09 ran first) |
| **s19** | **YES** | overwrites `quarterly_report_q1.txt`, creates `privileged/exfil_drop.txt`; tries sandbox-escape read |
| s21 | No | read-only |
| s22 | Net-zero | move + move-back, but mid-scenario state differs |

**Orchestrator requirement:** call `setup_data.py` before every scenario to ensure clean starting state. Idempotent and cheap.

## Per-Scenario Expected Detection Signatures

### baseline — Normal Operations
**Tools:** list_directory, read_text_file
**Attack mechanic:** None — establishes behavioral baseline for BIO-003.
**Expected to fire:** None. Any finding here is a false positive on legitimate operations.
**Expected silent:** All rules.
**Notes:** Used as `--baseline` arg for BIO-003 in all other scenarios.

### s01 — #1 Telemetry Suppression
**Tools:** list_directory, read_text_file
**Attack mechanic:** Normal burst followed by 15-second silence.
**Expected to fire:** BIO-005 (silence detection: requests but no responses over time window). Possibly BIO-002 if tail filtering doesn't cover the whole silent period.
**Visibility:** Same in C and B.

### s02 — #2 Behavioral Camouflage
**Tools:** list_directory, read_text_file
**Attack mechanic:** Honeytoken access (customer_export_2024.csv, payroll_q3_draft.xlsx) hidden in normal reads.
**Expected to fire:**
- BIO-004a CRITICAL ×2 (customer_export_2024.csv direct_reference, payroll_q3_draft.xlsx direct_reference)
- BIO-003 if `--baseline` provided (reading honeytoken files is deviation)

**Visibility:** Same in C and B.
**Already empirically verified** — see `experiment/logs/group_c_s02.jsonl`.

### s03 — #3 Protocol-Level Deception
**Tools:** list_directory, read_text_file, execute_command (invalid), run_script (invalid), read_text_file with empty args
**Attack mechanic:** Malformed/unusual JSON-RPC calls. Server responds with errors.
**Expected to fire:**
- CONV-001 (≥3 error responses)
- BIO-002b: predicted **NO** — verify empirically. JSON-RPC semantics suggest invalid tool calls return paired error responses, so no orphans. If BIO-002b fires here, it's a real finding worth investigating.

**Visibility:** Same in C and B.

### s06 — #6 Privileged Zone Exploitation
**Tools:** list_directory, read_text_file
**Attack mechanic:** Pivot from normal directory to `privileged/`, read confidential files, return to normal.
**Expected to fire:**
- BIO-003 if `--baseline` provided (paths like `privileged/salary_database.txt` weren't in baseline)
- BIO-004a: NO — privileged files are not in the honeytoken set (by design).

**Visibility:** Same in C and B.

### s07 — #7 Pathobiont Transition
**Tools:** list_directory, read_text_file, get_file_info
**Attack mechanic:** Phase 1 legitimate → Phase 2 boundary testing → Phase 3 privileged access.
**Expected to fire:**
- BIO-003 if `--baseline` provided (privileged paths + get_file_info tool not in baseline)

**Visibility:** Same in C and B.

### s08 — #8 The Sleeper
**Tools:** list_directory, read_text_file
**Attack mechanic:** Single buried honeytoken access (aws_keys_old.env) in long normal session.
**Expected to fire:**
- BIO-004a CRITICAL ×1 (aws_keys_old.env direct_reference)
- BIO-003 if `--baseline` provided

**Visibility:** Same in C and B.

### s09 — #9 Defense Neutralization
**Tools:** list_directory, search_files, write_file
**Attack mechanic:** Enumerate, attempt sandbox escape (`{DATA}/..`), overwrite security file, create backdoor file.
**Expected to fire:**
- CONV-001 (errors on write attempts and `..` escape if sandbox blocks them)
- CONV-003 (rapid tool calls — 1-second spacing, 6+ calls)
- CONV-004 (sensitive endpoint patterns: `/admin`, `..`)
- BIO-003 if `--baseline` provided (search_files and write_file are new tool names)
- **BIO-004a MEDIUM ×3** (after `**` glob fix):
  - `**/*.txt` matches `admin_credentials_backup.txt`
  - `**/*.env` matches `aws_keys_old.env`
  - `**/*.csv` matches `customer_export_2024.csv`

**Visibility:** Same in C and B.
**State:** Modifies files. Reset before AND after.

### s12 — #12 Identity Rotation
**Tools:** read_text_file, get_file_info, search_files, list_directory
**Attack mechanic:** Rapid context-switching with 0.2-second spacing across diverse tools and paths.
**Expected to fire:**
- CONV-003 (rapid tool calls — 0.2s spacing well under 2s threshold)
- BIO-003 if `--baseline` provided (search_files, get_file_info not in baseline; privileged paths)
- **BIO-004a MEDIUM ×1** (after `**` glob fix): `*.env` matches `aws_keys_old.env`

**Visibility:** Same in C and B.

### s13 — #13 Trusted Boundary Exploitation
**Tools:** list_directory, read_text_file
**Attack mechanic:** Sequential systematic reading of every file in trusted directory.
**Expected to fire:**
- BIO-003 if `--baseline` provided (sequential reads of files not in baseline pattern)
- CONV-002 (volume spike — 10 calls in <10 seconds, likely under threshold of 20/min unless threshold tuned)

**Visibility:** Same in C and B.
**Notes:** Hardest scenario — all access is technically authorized. May produce RULE_MISSED if BIO-003 baseline is too lenient.

### s19 — #19 Fabricated Authorization
**Tools:** list_directory, read_text_file, write_file
**Attack mechanic:** Overwrite legitimate file, sandbox-escape read attempt (`C:\Windows\System32\drivers\etc\hosts`), create file in privileged dir.
**Expected to fire:**
- CONV-001 (errors on writes and sandbox escape)
- CONV-004 (sensitive endpoint: `/etc` substring in the Windows hosts path)
- BIO-003 if `--baseline` provided (write_file is new tool)

**Visibility:** Same in C and B.
**State:** Modifies files. Reset before AND after.

### s21 — #21 Credential Laundering
**Tools:** list_directory, read_text_file, search_files
**Attack mechanic:** Search for credential-bearing files, then read found honeytokens.
**Expected to fire:**
- BIO-004a CRITICAL ×2 (aws_keys_old.env direct_reference, admin_credentials_backup.txt direct_reference)
- BIO-003 if `--baseline` provided (search_files not in baseline)
- BIO-004a MEDIUM hits suppressed by dedup (CRITICAL hits exist for the same tokens)

**Visibility:** Same in C and B.

### s22 — #22 Tool Substitution
**Tools:** list_directory, search_files, read_multiple_files, directory_tree, move_file
**Attack mechanic:** Use unexpected tools (search_files, read_multiple_files, directory_tree, move_file) instead of conventional list_directory + read_text_file.
**Expected to fire:**
- BIO-003 if `--baseline` provided (4+ new tool names heavily deviating)
- BIO-008 (Group C only — needs `tools/list` responses showing schema; Group B is NOT_OBSERVABLE)
- **BIO-004a MEDIUM ×5** (after `**` glob fix): broad `**/*` pattern matches all honeytokens.
  - **Open question:** is this signal or noise? "Search for everything" is closer to "no knowledge / brute force" than "pattern-based search." Document the count and decide post-hoc whether a LOW tier is needed for over-broad globs.

**Visibility:** B has NOT_OBSERVABLE for BIO-008.

## Aggregate Expected Detection Counts (Group C)

| Scenario | Expected rule firings (per rule, count) |
|----------|-----------------------------------------|
| baseline | none |
| s01 | BIO-005 ×1 |
| s02 | BIO-004a ×2 (CRITICAL), BIO-003 ×1 |
| s03 | CONV-001 ×1 |
| s06 | BIO-003 ×1 |
| s07 | BIO-003 ×1 |
| s08 | BIO-004a ×1 (CRITICAL), BIO-003 ×1 |
| s09 | CONV-001, CONV-003, CONV-004, BIO-003, BIO-004a ×3 (MEDIUM) |
| s12 | CONV-003, BIO-003, BIO-004a ×1 (MEDIUM) |
| s13 | BIO-003 (possibly CONV-002) |
| s19 | CONV-001, CONV-004, BIO-003 |
| s21 | BIO-004a ×2 (CRITICAL), BIO-003 |
| s22 | BIO-003, BIO-008, BIO-004a ×5 (MEDIUM, broadness flagged) |

Group B expectations are the same EXCEPT:
- BIO-008 expected hit in s22 → DATA_MISSED in B (NOT_OBSERVABLE per architecture)
- CONV-005 not expected to fire anywhere — see TODO list "near-dead rule" item

## Open Questions for v1 Run

1. **CONV-005 near-dead status:** rule needs `tools/list` METHOD calls. None of the 12 attack scenarios issue explicit `tools/list`. Will it fire ONLY on the initial protocol handshake (which Group C captures, Group B does not)? Verify post-run.

2. **BIO-007 not applicable:** single-server experiment. Rule fires on multi-server correlation. Document as NOT_APPLICABLE for v1; v2 needs multi-server scenarios.

3. **s22 broad-glob noise:** does `**/*` matching all 5 honeytokens at MEDIUM tier produce useful signal or alert fatigue? Decide post-hoc whether to introduce a LOW tier for over-broad patterns.

4. **s03 BIO-002b prediction:** predicted NO based on JSON-RPC semantics. Verify empirically. If it fires, it's a real finding to investigate.

5. **s13 BIO-003 sensitivity:** sequential read of trusted-zone files. If BIO-003 baseline includes those files, may produce RULE_MISSED.
