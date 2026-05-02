# TODO: Pre-Publication / Pre-Conference

Items that must be completed before publishing or presenting at a conference.

## Detection Rule Family Expansions

### BIO-004 family (honeytoken detection)
BIO-004 is a **rule family**, not a single rule. Each sub-rule detects a different attacker behavior with a different biological analog. They have complementary blind spots and the gaps between them carry signal.

| Sub-rule | Biological analog | Event detected | Status |
|----------|-------------------|----------------|--------|
| BIO-004a | TLR / pattern recognition receptor | Access intent (request names honeytoken) | **Implemented** |
| BIO-004b | MHC presentation | Visibility / recon (filename in listing response) | TODO |
| BIO-004c | Effluent / fluorescent tracer | Exfiltration (canary string in response content) | TODO |
| BIO-004d | DAMP / host stress signal | Stealth access (mtime/atime delta, no logged tool call) | TODO |

**BIO-004b (recon detection):**
- Response-side, 2-gated (direction=server_to_client + message_type=response, no method filter)
- Severity tiered by attacker knowledge level:
  - LOW: broad listing, low ratio of honeytokens to total items returned (30,000 ft surveillance)
  - MEDIUM: targeted listing, high ratio or shallow path
  - HIGH: deep path with honeytoken hit (boots on the ground)
- Tier signals: path depth (separator count) and response breadth (honeytoken-to-total ratio)

**BIO-004c (exfil detection):**
- Response-side, 2-gated (direction=server_to_client + message_type=response, no method filter)
- Severity CRITICAL — canary in response means the file was actually read (path-independent verification)
- Defeats symlink/hardlink/copy evasion that BIO-004a misses
- Requires honeytoken files to contain unique canary strings; new --canaries CLI arg
- Known limitation: defeated by content transformation (base64, encryption, partial reads)

**BIO-004d (stealth access detection):**
- Out-of-band: mcp-tap stats honeytoken paths, watches for atime/mtime changes that don't correspond to logged tool calls
- Severity HIGH — indirect evidence of access without exfil
- Requires file-watch APIs (inotify/fanotify on Linux, ReadDirectoryChangesW on Windows, FSEvents on macOS)
- Stepping stone toward path D (OS-level audit hooks)

### BIO-010: chemotaxis pattern (progressive narrowing)
- Distinct from BIO-004 family; detects attacker's *search behavior* rather than honeytoken hits
- Pattern: agent's list_directory sequence shows refining: `/` → `/data/` → `/data/finance/` → `/data/finance/q3/`
- Biological analog: chemotaxis — moving up a gradient toward a target
- Threat model: attacker has partial knowledge and is narrowing in
- Severity tiered by depth of narrowing and time-clustering

## Code Quality

### Uniformity sweep across all detection rules
The current rule code is inconsistent in how it filters messages — some use direction+method, some use message_type, some use no gate. The biomimetic principle is **uniform mechanisms, varied specificity**: filter primitives should be consistent vocabulary, but how each rule combines them is intentional per its sensitivity/specificity tradeoff.

Tasks:
- Audit every rule for filter consistency
- Document the gate-count → severity mapping per rule (see methodology section)
- Bundle BIO-002 / BIO-002b rename with this sweep (BIO-002 is a family, sub-rules should be 002a / 002b for orphan-request / orphan-response, matching BIO-004 family pattern)

## Methodology Section (Motion Detector Paper)

Capture the framework that emerged from the BIO-004 review session:

**Core principle:** Specificity (engineering choice — how to get low FP) and severity (threat-model claim — how bad if true) are **independent axes**. Rules must declare both. Reviewers conflate them; the paper should push back.

**Gating tier framework:**

| Gates | Detection style | Specificity source | Typical severity |
|-------|----------------|-------------------|------------------|
| 3 (triple) | Specific signature, low FP tolerance | All three primitives narrow the message set | CRITICAL |
| 2 (pair) | Structural pattern across one boundary | Two primitives + signal uniqueness | HIGH |
| 1 (single) | Aggregate / statistical trend | One primitive + threshold | MEDIUM |
| 0 (broad) | Recon / enumeration surveillance | None — broad capture | LOW |

**Note:** Specificity can also come from **signal uniqueness** (e.g., a canary string is high-specificity even with only 2 gates because the string itself is unique to the canary set). Gate count is one engineering lever, not the only one.

**Biological grounding:** Biology is uniform at the *mechanism* level (signal transduction cascades) and unique at the *specificity* level (what each receptor binds, what each cell responds to). Detection rules should mirror this: uniform vocabulary at the filter primitives, intentional variation at the rule strategy. T cells need three signals to activate (TCR + co-stim + cytokine context); innate cells need one signal (PAMP). Both are valid; they trade off sensitivity vs specificity for different roles in the immune response.

**Multi-sensor complementarity:** Different sensors have different blind spots. The gaps between them are themselves signals. Combinations carry information:
- BIO-004a + BIO-004c = standard attack (named it, exfiltrated it)
- NOT BIO-004a + BIO-004c = symlink/copy evasion (innocent path, canary leaked)
- BIO-004a + NOT BIO-004c = blocked or read-only learning (intent observed, no exfil)
- BIO-004d alone = full bypass (no logged access but file shows engagement)

**Gating vs completeness as orthogonal framework concerns:** Two distinct framework-level concerns surface in detection rule design, and they must not be conflated:

| Concern | Question | Bug example | Fix shape |
|---------|----------|-------------|-----------|
| **Gating** | Which messages does the rule examine? | BIO-004 firing on responses (false positive) | Add filter primitives (direction, message_type, method) |
| **Completeness** | When is the data complete enough to draw a conclusion? | BIO-002b firing on tail-window pairs (false positive) | Apply temporal/contextual filters symmetrically across paired entities |

Gating bugs produce *over-firing on the wrong message types*. Completeness bugs produce *over-firing on incomplete data slices*. They have different mental models for diagnosis and different fix shapes. A rule can be correctly gated and still have completeness bugs (or vice versa). Both must be reasoned about explicitly per rule.

This is paper-worthy framing for the methodology section.

## Future Research (Out of Scope for This Paper)

### Path D: OS-level audit hooks
- Linux auditd watch rules (`-w /path -p ra`) for read access
- Windows Object Access Auditing
- macOS Endpoint Security framework
- Cross-platform parity is hard
- Full subject correlation (PID/process at OS layer correlated with MCP session at app layer) is the research artifact
- Independent trust domain from mcp-tap — survives transport compromise

### Content transformation evasion
- Attackers who base64/encrypt/partially-read honeytoken content defeat BIO-004c canary detection
- Open question: behavioral detection of transformation operations as a separate signal

## Bug Fix History (for paper limitations / methodology section)

Fixes worth documenting in the paper as evidence that the framework surfaced real issues during empirical testing:

### BIO-004 false positive on directory listings (FIXED, commit 39ee276)
**Symptom:** BIO-004 fired on `list_directory` responses that contained honeytoken filenames in their result text, even when no actual access occurred.
**Root cause:** Rule did not gate by direction or method; it string-matched honeytokens against the entire `params` blob of every message.
**Framework concern:** Gating.
**Fix:** Triple-gate (direction + message_type + method) restricting rule to `tools/call` requests. Renamed BIO-004 → BIO-004a to reserve the family namespace for the recon (004b), exfil (004c), and stealth (004d) sub-rules.

### BIO-002b false positive on tail-window pairs (FIXED)
**Symptom:** BIO-002b fired on matched request/response pairs occurring within the tail window at log truncation.
**Root cause originally suspected:** Lifecycle events (genesis, server_start). This was wrong — lifecycle events don't have a `direction` field and are already filtered by `filter_messages()`.
**Actual root cause:** Asymmetric `in_tail` filtering. The tail-window filter was applied to requests only (correctly preventing BIO-002 false positives on requests whose responses hadn't arrived yet), but NOT to responses. This tore matched pairs apart: requests excluded, responses retained as "orphans" → BIO-002b false positive.
**Framework concern:** Completeness.
**Fix:** Apply `in_tail` symmetrically to both requests and responses. Tradeoff: a true orphan response within the tail window is now a false negative — acceptable because tail data is incomplete by definition.
