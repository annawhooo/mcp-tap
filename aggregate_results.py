"""aggregate_results.py: Convert score_results.py output to analyze.py input format.

Bridges the two existing CSV formats:

  Input (from score_results.py):
    Per-(scenario, rule_id) rows. Two groups (B, C). 5-state taxonomy:
    DETECTED, RULE_MISSED, DATA_MISSED, NOT_OBSERVABLE, NOT_EXPECTED, UNEXPECTED_FIRING.

  Output (consumed by analyze.py):
    Per-scenario rows. Five cells: group_a, b_conv, b_bio, c_conv, c_bio.
    Same 5-state taxonomy preserved end-to-end. The statistical tests
    binarize internally (DETECTED == 1, anything else == 0), so keeping
    five states adds descriptive richness without affecting inference.

Usage:
    python aggregate_results.py \
        --input experiment/results/results-v1.csv \
        --output experiment/results/results-v1-factorial.csv

Then feed the output to analyze.py:
    python analyze.py --results experiment/results/results-v1-factorial.csv

Aggregation rules (documented here so they can be argued with rather than reverse-engineered):

  Rule-set assignment by rule_id prefix:
    CONV-* -> conv
    BIO-*  -> bio
    Anything else (including the spurious "_comment" rows that score_results.py
    emits -- see Note below) is filtered out with a stderr warning.

  Cell aggregation across rules within a (scenario, rule_set, transport) cell.
  When a cell has multiple rules' results to combine, the highest-priority
  state wins. Precedence (highest first):

    DETECTED            -- a rule fired as predicted, conclusive positive
    UNEXPECTED_FIRING   -- a rule fired without prediction; needs review
    RULE_MISSED         -- rule could see evidence at this transport but didn't fire
                           (rule weakness; stronger negative signal than transport-blind)
    DATA_MISSED         -- transport didn't have the data the rule needed
                           (capture-tool weakness)
    NOT_OBSERVABLE      -- architectural blind spot for this transport
    NOT_EXPECTED        -- no prediction; absence is correct (lowest priority)

  Rationale for RULE_MISSED > DATA_MISSED: "we had the data and the rule
  missed it" is a stronger negative signal than "we never had the data."
  Aggregating UP to RULE_MISSED preserves that stronger signal when both
  are present in the same cell.

  Empty cell (no rules in this rule_set for this scenario) -> NOT_EXPECTED.

  group_a (the no-monitoring control) is mechanically NOT_OBSERVABLE for
  every scenario. No detection mechanism is running in Group A by definition,
  so every scenario is structurally invisible there.

Baseline handling:
  By default, the "baseline" scenario is excluded from the output because
  analyze.py is structured to analyze attack scenarios (the baseline exists
  for BIO-003 reference data, not for detection-rate measurement). Pass
  --include-baseline to keep it. Note that any DETECTED in baseline = false
  positive on legitimate operations.

Note on score_results.py "_comment" rows:
  score_results.py iterates `visibility_overrides.keys()` which includes the
  JSON doc's "_comment" key, so the output CSV contains rows where
  rule_id="_comment". These are spurious. We filter them silently (warning
  printed once). Worth fixing in score_results.py so this aggregator doesn't
  have to compensate.
"""

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Aggregation precedence -- pulled to module level so it's argueable, not buried.
# Order matters: index 0 = lowest priority, index -1 = highest.
# When aggregating multiple rules' states into one cell, the highest-priority
# state present wins.
# ---------------------------------------------------------------------------

AGGREGATION_PRECEDENCE = [
    "NOT_EXPECTED",
    "NOT_OBSERVABLE",
    "DATA_MISSED",
    "RULE_MISSED",
    "UNEXPECTED_FIRING",
    "DETECTED",
]

KNOWN_STATES = set(AGGREGATION_PRECEDENCE)

# Group A is the no-monitoring control. Mechanically NOT_OBSERVABLE for
# every scenario -- no detection mechanism is running, so every scenario
# is structurally invisible there.
GROUP_A_STATE = "NOT_OBSERVABLE"


def aggregate_cell(states: list[str]) -> str:
    """
    Aggregate a list of 5-state values into a single 5-state value, using
    AGGREGATION_PRECEDENCE. Empty list -> NOT_EXPECTED (no rules in this
    rule_set means there was nothing to predict and nothing to detect).
    """
    if not states:
        return "NOT_EXPECTED"
    best_idx = -1
    best = "NOT_EXPECTED"
    for s in states:
        if s not in KNOWN_STATES:
            raise ValueError(
                f"Unknown state {s!r}; known: {sorted(KNOWN_STATES)}"
            )
        idx = AGGREGATION_PRECEDENCE.index(s)
        if idx > best_idx:
            best_idx = idx
            best = s
    return best


def rule_set_for(rule_id: str) -> str | None:
    """Return 'conv', 'bio', or None for non-rule rows."""
    if rule_id.startswith("CONV-"):
        return "conv"
    if rule_id.startswith("BIO-"):
        return "bio"
    return None


# ---------------------------------------------------------------------------
# Main aggregation
# ---------------------------------------------------------------------------

def aggregate(rows: list[dict], include_baseline: bool = False
              ) -> tuple[list[dict], list[str]]:
    """
    Aggregate score_results rows into the analyze.py factorial format.

    Returns (output_rows, warnings) where warnings is a list of strings
    that should be emitted to stderr by the caller.

    Each output row has columns:
      scenario, group_a, b_conv, b_bio, c_conv, c_bio
    where every cell value is one of the 5-state taxonomy values.
    """
    warnings = []
    skipped_rule_ids = set()
    unexpected_firings = []

    # Collect cell states grouped by (scenario, rule_set, transport).
    # cells[scenario][rule_set][transport] = list of states from individual rules.
    cells: dict[str, dict[str, dict[str, list[str]]]] = defaultdict(
        lambda: {"conv": {"b": [], "c": []}, "bio": {"b": [], "c": []}}
    )

    for row in rows:
        rule_id = (row.get("rule_id") or "").strip()
        rule_set = rule_set_for(rule_id)
        if rule_set is None:
            # Spurious row (e.g., "_comment" from score_results bug). Skip.
            skipped_rule_ids.add(rule_id)
            continue

        scenario = (row.get("scenario") or "").strip()
        if not scenario:
            warnings.append(f"row with missing scenario, skipping: {row}")
            continue

        c_status = (row.get("group_c_status") or "").strip()
        b_status = (row.get("group_b_status") or "").strip()

        for transport, status in (("c", c_status), ("b", b_status)):
            if not status:
                continue
            if status not in KNOWN_STATES:
                warnings.append(
                    f"{scenario}/{rule_id}/{transport}: unknown state "
                    f"{status!r}; treating as NOT_EXPECTED"
                )
                status = "NOT_EXPECTED"
            if status == "UNEXPECTED_FIRING":
                unexpected_firings.append((scenario, rule_id, transport))
            cells[scenario][rule_set][transport].append(status)

    if skipped_rule_ids:
        warnings.append(
            f"filtered {len(skipped_rule_ids)} non-rule row id(s): "
            f"{sorted(skipped_rule_ids)} "
            f"(score_results.py emits these from _visibility_overrides keys; "
            f"see aggregate_results.py header for context)"
        )

    if unexpected_firings:
        warnings.append(
            f"{len(unexpected_firings)} UNEXPECTED_FIRING cells preserved as "
            f"distinct state. Review these in case they should be predicted "
            f"instead:"
        )
        for sid, rid, transport in unexpected_firings:
            warnings.append(f"  {sid}/{rid}/{transport}")

    # Aggregate per scenario.
    output = []
    for scenario in sorted(cells.keys()):
        if scenario == "baseline" and not include_baseline:
            continue
        scenario_cells = cells[scenario]
        output.append({
            "scenario": scenario,
            "group_a": GROUP_A_STATE,
            "b_conv": aggregate_cell(scenario_cells["conv"]["b"]),
            "b_bio":  aggregate_cell(scenario_cells["bio"]["b"]),
            "c_conv": aggregate_cell(scenario_cells["conv"]["c"]),
            "c_bio":  aggregate_cell(scenario_cells["bio"]["c"]),
        })

    return output, warnings


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------

def read_input(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_output(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["scenario", "group_a", "b_conv", "b_bio", "c_conv", "c_bio"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(
        prog="aggregate_results",
        description=(
            "Convert score_results.py per-(scenario, rule) output into the "
            "per-scenario factorial format consumed by analyze.py. "
            "Preserves the full 5-state taxonomy."
        ),
    )
    parser.add_argument("--input", required=True,
                        help="Path to results CSV from score_results.py")
    parser.add_argument("--output", required=True,
                        help="Path to write aggregated CSV (analyze.py format)")
    parser.add_argument("--include-baseline", action="store_true",
                        help="Include the 'baseline' scenario in the output. "
                             "Default omits it because baseline is for BIO-003 "
                             "reference, not detection-rate measurement.")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    if not input_path.is_file():
        parser.error(f"--input not found: {input_path}")

    rows = read_input(input_path)
    output, warnings = aggregate(rows, include_baseline=args.include_baseline)

    for w in warnings:
        print(f"WARN: {w}", file=sys.stderr)

    write_output(output, output_path)
    print(f"Wrote {len(output)} scenario rows to {output_path}")


if __name__ == "__main__":
    main()
