# A/B/C Experiment: 2x2 Factorial Design (v2)
# Capture Tool x Rule Set, plus no-monitoring control

## Research Questions

1. Does monitoring help at all? (Group A vs any monitoring)
2. Do bio-derived rules detect more than conventional rules?
   (holding capture tool constant)
3. Does mcp-tap capture things Bifrost misses?
   (holding rule set constant)
4. Is there an interaction effect?
   (does the bio methodology help MORE on one transport?)

## Design

### Control
- **Group A**: No monitoring. Raw filesystem server, default config.
  Native server logs only.

### 2x2 Factorial

|                     | Conventional rules | Bio-derived rules |
|---------------------|-------------------|-------------------|
| **Bifrost (HTTP)**  | Cell B-conv       | Cell B-bio        |
| **mcp-tap (stdio)** | Cell C-conv       | Cell C-bio        |

### What each cell means
- **B-conv**: Bifrost captures HTTP traffic, conventional rules run
  against Bifrost logs (via log_adapter -> mcp-detect --rules conventional)
- **B-bio**: Bifrost captures HTTP traffic, bio-derived rules run
  against Bifrost logs (via log_adapter -> mcp-detect --rules bio)
- **C-conv**: mcp-tap captures stdio traffic, conventional rules run
  against mcp-tap JSONL (mcp-detect --rules conventional)
- **C-bio**: mcp-tap captures stdio traffic, bio-derived rules run
  against mcp-tap JSONL (mcp-detect --rules bio)

## Execution Protocol

### Per scenario (12 scenarios total):

1. Execute scenario against raw server (Group A)
   - Record native server logs
   - Score: DETECTED / OBSERVABLE / MISSED

2. Execute scenario against mcp-tap-wrapped server
   - Produces: mcp-tap JSONL audit log
   - Run mcp-detect --rules conventional -> score Cell C-conv
   - Run mcp-detect --rules bio -> score Cell C-bio

3. Execute scenario against supergateway + Bifrost server
   - Produces: Bifrost gateway logs
   - Run log_adapter to convert Bifrost logs -> mcp-detect format
   - Run mcp-detect --rules conventional -> score Cell B-conv
   - Run mcp-detect --rules bio -> score Cell B-bio

### Per scenario output: 5 scores
- Group A:  DETECTED / OBSERVABLE / MISSED
- B-conv:   DETECTED / OBSERVABLE / MISSED
- B-bio:    DETECTED / OBSERVABLE / MISSED
- C-conv:   DETECTED / OBSERVABLE / MISSED
- C-bio:    DETECTED / OBSERVABLE / MISSED

## Statistical Analysis

### Primary analysis: 2x2 factorial
Collapse to binary (DETECTED vs not-detected).
12 scenarios x 4 cells = 48 observations.

Main effects:
- **Rule set effect**: (B-bio + C-bio) vs (B-conv + C-conv)
  -> Does biology help?
- **Capture tool effect**: (C-conv + C-bio) vs (B-conv + B-bio)
  -> Does mcp-tap see more than Bifrost?
- **Interaction**: Does the bio advantage differ by transport?

Use Cochran's Q across all 4 cells (omnibus), then pairwise
McNemar's with Bonferroni correction for specific contrasts:
- B-conv vs B-bio (bio rules on same Bifrost data)
- C-conv vs C-bio (bio rules on same mcp-tap data)
- B-conv vs C-conv (transport effect, same conventional rules)
- B-bio vs C-bio (transport effect, same bio rules)

### Control comparison
- A vs best-performing cell (sanity check)
- Report A detection rate as baseline

### Descriptive supplement
Three-category scoring (DETECTED/OBSERVABLE/MISSED) as a
secondary descriptive table. OBSERVABLE is important because
it captures "the data was there but no rule caught it."

## What This Proves

If bio rules outperform conventional on the SAME Bifrost logs
(B-bio > B-conv), the methodology works regardless of capture tool.
No reviewer can say "you just built a better capture tool."

If mcp-tap captures things Bifrost misses with the SAME rules
(C-conv > B-conv), the transport coverage matters.

If BOTH effects are significant, the paper has two contributions
instead of one: the methodology AND the capture architecture.

## Updated Tooling Requirement

Each scenario requires:
- 3 server executions (A, mcp-tap, Bifrost)
- 4 mcp-detect invocations (2 rule sets x 2 log sources)
- 5 scored results

log_adapter.py already handles Bifrost -> mcp-detect format.
analyze.py needs updating for 2x2 factorial (replace 3-group
Cochran's Q with 4-cell factorial analysis).
