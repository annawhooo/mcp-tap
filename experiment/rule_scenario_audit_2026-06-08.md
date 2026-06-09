# Rule / Scenario Consistency Audit + Correction Tracker
Generated 2026-06-08. Working doc; check items off as resolved.

## Context
- Pre-headline-results. Smoke test (run-001) surfaced s01 BIO-005 miss.
- Full static + empirical audit vs frozen commit 3cc75bf (tag experiment-frozen-2026-06-08),
  Group C capture in experiment/logs/run-002.
- Finding: 9 of 13 scenarios misaligned. Pattern: several rules implemented narrower
  than the concept the scenarios/expectations assume.
- Decision (Anna, 2026-06-08): implement the recommended corrections ("leanings");
  defer ALL docstring fixes to a final pass after rule+scenario errors are resolved.

## Legend
[ ] todo   [~] in progress   [x] done   [-] deferred

## Empirical matrix (run-002, frozen rules)
| scenario | expected | actually fired | verdict |
|---|---|---|---|
| baseline | (none) | (none) | clean |
| s01 | BIO-005 | (none) | BIO-005 missed |
| s02 | BIO-003, BIO-004a | BIO-004a x2 | BIO-003 missed |
| s03 | CONV-001 | BIO-003 | CONV-001 missed; BIO-003 unexpected |
| s06 | BIO-003 | (none) | BIO-003 missed |
| s07 | BIO-003 | BIO-003 | OK |
| s08 | BIO-003, BIO-004a | BIO-004a | BIO-003 missed |
| s09 | BIO-003, BIO-004a, CONV-001, CONV-003, CONV-004 | BIO-004a x3, BIO-003 | CONV-001/003/004 missed |
| s12 | BIO-003, BIO-004a, CONV-003 | all 3 | OK |
| s13 | BIO-003 | CONV-003 | BIO-003 missed; CONV-003 unexpected |
| s19 | BIO-003, CONV-001, CONV-004 | BIO-003 | CONV-001/004 missed |
| s21 | BIO-003, BIO-004a | BIO-004a x5, BIO-003 | OK |
| s22 | BIO-003, BIO-004a, BIO-008 | BIO-004a x5, BIO-003 | BIO-008 missed |

## Corrections - RULES (mcp_detect.py)
[x] R1  CONV-001 MCP-error awareness. Counts only JSON-RPC error responses; MCP tool
        failures return as result.isError=true (verified s03: 3 isError results, basis=0).
        Fix: helper _is_failed_operation(m) = JSON-RPC error OR (response & params.isError True);
        CONV-001 counts those, threshold stays >=3. Affects s03, s09, s19.
[x] R2  CONV-004 scope/path awareness. Inspects only args.url; filesystem uses path/source/
        destination. Fix: inspect path-like args for scope violations: parent traversal '..',
        absolute paths outside the data sandbox (C:\, /etc, system dirs), plus existing
        sensitive substrings. Affects s09, s19.
[x] R3  BIO-003 path/resource deviation. DONE: deviation = (new tool names) UNION (new
        directory ZONES = non-final path segments not in baseline). Zone-level, not per-file
        (per-file too noisy). Verified: s06 now fires via 'privileged' zone; s07/s09/s12/s19/
        s21/s22 still fire; baseline/s01 clean. NOTE for E2: s02/s08 do NOT fire (their
        deviation is honeytoken access -> BIO-004a is the catch) and s13 does not fire (same
        dir+tools) -> DROP BIO-003 from s02/s08/s13 expectations. s03 fires via invalid new
        tool names (run_script/execute_command) -> consider ADDING BIO-003 to s03 in E2.
[x] R4  BIO-002 / BIO-005 consolidation + cadence rule. DONE via REPURPOSE (changed approach
        from add-BIO-010): BIO-005's dark-server check (requests>3 & responses==0) was a strict
        subset of BIO-002 orphan-requests and fired on zero scenarios -> replaced BIO-005 body
        with a TEMPORAL cadence-drop detector (max inter-call gap >= 5.0s AND > 4x median gap,
        after >=4 tool calls). Keeps rule count at 9, removes the BIO-002 overlap, aligns with
        BIO-005's existing 'silence over a time window' docstring, and s01's expected id stays
        BIO-005. Verified: s01 fires (15.0s gap vs 1.0s median); fires on no other scenario;
        BIO-002 quiet everywhere. Fully-dark case remains covered by BIO-002. Docstring -> D1.

## Corrections - SCENARIOS (scenarios.py)
[x] S1  s22 / BIO-008. CONFIRMED unexercisable: the scripted runner makes ZERO tools/list
        calls in any capture (0 tools-bearing responses in baseline & s22), and the real
        filesystem server has a static schema, so no schema-change stimulus can exist.
        RESOLUTION: drop BIO-008 from s22 expected_firings (in E2); treat BIO-008 as an
        out-of-corpus structural rule (substitution vector absent), like BIO-007.
[x] S2  BIO-006 added as scenario s09b (Control Neutralization): 5 identical read_text_file
        calls -> BIO-006 fires (5 identical responses), nothing else. Corpus now 14 scenarios.
        Registered in scenarios.ALL_SCENARIOS and run_experiment.ALL_SCENARIO_IDS. Verified in
        run-003. BIO-009 SCOPED OUT (user-approved): latency shift not deterministically
        reproducible vs a real filesystem server (ms-scale, machine-dependent; forced shift =
        contrived + log bloat + flaky P1). Treated as structural/out-of-corpus like BIO-007/008.

## Corrections - EXPECTATIONS (scenario-expectations.json)
[x] E1  CONV-003 timing alignment. Predict for s12 (0.2s) and s13 (0.5s); remove from s09
        (1s spacing = exactly 2.0s, below <2.0 threshold).
[x] E2  Re-derive ALL expected_firings to match corrected rules+scenarios. DONE: rewrote
        scenario-expectations.json (14 scenarios) to the verified firing sets. Changes: s02/s08/
        s13 BIO-003 dropped; s03 +BIO-003; s09 +CONV-004 -CONV-001 -CONV-003; s19 +CONV-004
        -CONV-001; s22 -BIO-008; s09b +BIO-006 (new). Meta keys + visibility_overrides preserved.
        - EMPIRICAL (post R1/R2): s09 & s19 produce only 1 failed op each (server allows
          writes), so CONV-001 cannot fire there -> dropped from s09/s19; CONV-004 is their
          conventional catch. CONV-001 stays for s03 (3 isError results).

## Deferred to FINAL pass
[-] D1  Docstring accuracy: BIO-005 ('over a time window', scenario tag), BIO-003 ('scoring/
        profile' vs set-diff), BIO-006 ('a tool' vs lumped tools/call), BIO-007 ('different
        credentials' vs server-id count), scenario Detection: lines vs JSON (s01,s02,s03,s06...).
        Do AFTER R/S/E so docstrings describe final behavior.

## Process
[x] P1  DONE (run-004, fresh full re-run of all 14, Group C): expected == actual for every
        scenario, 0 MISSED / 0 UNEXPECTED, baseline clean. Deterministic incl. BIO-005 cadence
        & CONV-003. Supersedes the single-scenario smoke (P3 smoke now redundant).
[ ] P2  Re-freeze: new commit + new annotated tag superseding experiment-frozen-2026-06-08;
        message notes audit-driven amendment, still pre-headline-results.
[ ] P3  Re-run 1-scenario smoke, then headline run (Group C, then Group B).

## Notes
- Fairness: most conventional-rule misses (CONV-001 jsonrpc-only, CONV-004 url-only,
  CONV-003 timing) stem from rules written for HTTP/REST, not MCP/filesystem. R1/R2/E1
  adapt them to the test context so bio-vs-conventional is a fair contest.
- All edits on live repo; git commit 3cc75bf is the rollback point.
