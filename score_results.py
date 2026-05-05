"""score_results.py: Classify each (scenario, group, rule) cell using the 4-state taxonomy.

Reads scenario expectations from experiment/scenario-expectations.json,
runs mcp_detect on each captured log file (Group C and Group B), and
produces results.csv with one row per (scenario, rule_id) showing both
groups' classifications side by side.

5-state classification (4 for paper, 5th for review):
  DETECTED          - rule fired with count >= expected
  RULE_MISSED       - rule predicted to fire but didn't
  DATA_MISSED       - rule predicted to fire but data missing at this transport
  NOT_OBSERVABLE    - rule never expected at this transport (architectural)
  UNEXPECTED_FIRING - rule fired without prediction; review needed

Visibility overrides (from inventory): BIO-001, BIO-008, CONV-005 are
NOT_OBSERVABLE in Group B. BIO-007 is NOT_OBSERVABLE in both (single-server
experiment).

Usage:
    python score_results.py \\
        --group-c-dir experiment/logs/run-001 \\
        --group-b-dir experiment/logs/run-002 \\
        --expectations experiment/scenario-expectations.json \\
        --honeytokens experiment/honeytokens.txt \\
        --output experiment/results/results-v1.csv
"""

import argparse
import csv
import json
import sys
from pathlib import Path

from mcp_detect import read_jsonl, run_rules


# ---------------------------------------------------------------------------
# Cell classification
# ---------------------------------------------------------------------------

def classify_cell(
    rule_id: str,
    expected: dict,
    actual_count: int,
    group: str,
    visibility_overrides: dict,
) -> tuple:
    """Classify a single (scenario, group, rule) cell.

    Returns (status, note) where status is one of the 5 taxonomy states
    and note is a short string for the CSV's notes column (or '').
    """
    # Visibility override: rule is structurally unobservable in this group
    if group in visibility_overrides.get(rule_id, []):
        if expected:
            return "DATA_MISSED", "predicted but transport lacks required data"
        return "NOT_OBSERVABLE", "architectural blind spot"

    # No prediction for this rule on this scenario
    if not expected:
        if actual_count > 0:
            return "UNEXPECTED_FIRING", f"fired {actual_count}× without prediction"
        return "NOT_EXPECTED", ""

    # Prediction exists
    expected_count = expected.get("count", 1)
    if actual_count == 0:
        return "RULE_MISSED", f"expected {expected_count}× ({expected.get('reason', '')})"
    if actual_count >= expected_count:
        if actual_count > expected_count:
            return "DETECTED", f"got {actual_count}× (expected {expected_count}×)"
        return "DETECTED", ""
    # actual > 0 but actual < expected_count
    return "RULE_MISSED", f"got {actual_count}×, expected {expected_count}×"


# ---------------------------------------------------------------------------
# Per-scenario rule firing collection
# ---------------------------------------------------------------------------

def count_findings_by_rule(findings: list) -> dict:
    """Group Finding objects by rule_id, return counts."""
    counts = {}
    for f in findings:
        rid = f.rule_id if hasattr(f, "rule_id") else f["rule_id"]
        counts[rid] = counts.get(rid, 0) + 1
    return counts


def detect_for_scenario(
    log_path: Path,
    baseline_log_path: Path,
    honeytokens: list,
) -> dict:
    """Run all rules on a scenario log; return rule_id → count."""
    if not log_path.is_file() or log_path.stat().st_size == 0:
        return {}
    entries = read_jsonl(str(log_path))
    baseline_entries = None
    if baseline_log_path.is_file() and baseline_log_path.stat().st_size > 0:
        baseline_entries = read_jsonl(str(baseline_log_path))
    findings = run_rules(
        entries, "all",
        honeytokens=honeytokens,
        baseline_entries=baseline_entries,
    )
    return count_findings_by_rule(findings)


# ---------------------------------------------------------------------------
# Main scoring loop
# ---------------------------------------------------------------------------

def score_run(
    group_c_dir: Path,
    group_b_dir: Path,
    expectations: dict,
    honeytokens: list,
) -> list:
    """Build the results table.

    Returns a list of dict rows for results.csv. Each row is a
    (scenario, rule_id) pair with both groups' classifications.
    """
    visibility_overrides = expectations.get("_visibility_overrides", {})
    scenarios = expectations["scenarios"]

    # Determine the union of all rule IDs that are expected anywhere OR
    # that fired anywhere (so we don't miss UNEXPECTED_FIRING rows)
    expected_rule_ids = set()
    for sdef in scenarios.values():
        expected_rule_ids.update(sdef.get("expected_firings", {}).keys())
    # Only pull actual rule IDs (CONV-* / BIO-*) from visibility_overrides.
    # The JSON doc includes a "_comment" key alongside real rule keys, and
    # without this filter it leaks into the output CSV as a spurious row.
    expected_rule_ids.update(
        k for k in visibility_overrides.keys()
        if k.startswith("CONV-") or k.startswith("BIO-")
    )

    # First pass: collect actual counts per scenario per group
    baseline_c = group_c_dir / "group_c_baseline.jsonl"
    baseline_b = group_b_dir / "group_b_baseline.jsonl"

    counts_c = {}
    counts_b = {}
    for sid in scenarios:
        log_c = group_c_dir / f"group_c_{sid}.jsonl"
        log_b = group_b_dir / f"group_b_{sid}.jsonl"
        counts_c[sid] = detect_for_scenario(log_c, baseline_c, honeytokens)
        counts_b[sid] = detect_for_scenario(log_b, baseline_b, honeytokens)

    # Update rule_id universe with anything that actually fired
    for cmap in (counts_c, counts_b):
        for sid_counts in cmap.values():
            expected_rule_ids.update(sid_counts.keys())

    # Build rows
    rows = []
    rule_id_order = sorted(expected_rule_ids)
    for sid in scenarios:
        sdef = scenarios[sid]
        expected_firings = sdef.get("expected_firings", {})
        for rid in rule_id_order:
            expected = expected_firings.get(rid, {})
            count_c = counts_c[sid].get(rid, 0)
            count_b = counts_b[sid].get(rid, 0)
            status_c, note_c = classify_cell(rid, expected, count_c, "c", visibility_overrides)
            status_b, note_b = classify_cell(rid, expected, count_b, "b", visibility_overrides)

            # Skip rows where both cells are NOT_EXPECTED — keeps results.csv readable
            # (otherwise every scenario × every rule = lots of zeros)
            if status_c == "NOT_EXPECTED" and status_b == "NOT_EXPECTED":
                continue

            rows.append({
                "scenario": sid,
                "rule_id": rid,
                "group_c_status": status_c,
                "group_b_status": status_b,
                "group_c_count": count_c,
                "group_b_count": count_b,
                "expected_count": expected.get("count") if expected else "",
                "expected_severity": expected.get("severity") if expected else "",
                "notes_c": note_c,
                "notes_b": note_b,
                "expected_reason": expected.get("reason") if expected else "",
            })

    return rows


# ---------------------------------------------------------------------------
# CSV writer + summary
# ---------------------------------------------------------------------------

def write_results_csv(rows: list, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "scenario", "rule_id",
        "group_c_status", "group_b_status",
        "group_c_count", "group_b_count",
        "expected_count", "expected_severity",
        "notes_c", "notes_b", "expected_reason",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def print_summary(rows: list) -> None:
    """Print state-tally summary per group."""
    from collections import Counter
    states_c = Counter(r["group_c_status"] for r in rows)
    states_b = Counter(r["group_b_status"] for r in rows)
    states_all = sorted(set(states_c) | set(states_b))

    print("\n=== summary ===")
    print(f"  total cells: {len(rows)} (per group)")
    print(f"  {'state':<22} {'group_c':>8} {'group_b':>8}")
    print(f"  {'-'*22} {'-'*8} {'-'*8}")
    for state in states_all:
        print(f"  {state:<22} {states_c.get(state, 0):>8} {states_b.get(state, 0):>8}")

    # Highlight UNEXPECTED_FIRING and RULE_MISSED for review
    unexpected = [r for r in rows
                  if r["group_c_status"] == "UNEXPECTED_FIRING"
                  or r["group_b_status"] == "UNEXPECTED_FIRING"]
    if unexpected:
        print(f"\n  UNEXPECTED_FIRING rows ({len(unexpected)} for review):")
        for r in unexpected:
            print(f"    {r['scenario']:<10} {r['rule_id']:<10} "
                  f"c={r['group_c_status']}({r['group_c_count']}) "
                  f"b={r['group_b_status']}({r['group_b_count']})")

    rule_missed = [r for r in rows
                   if r["group_c_status"] == "RULE_MISSED"
                   or r["group_b_status"] == "RULE_MISSED"]
    if rule_missed:
        print(f"\n  RULE_MISSED rows ({len(rule_missed)} for review):")
        for r in rule_missed:
            print(f"    {r['scenario']:<10} {r['rule_id']:<10} "
                  f"c={r['group_c_status']}({r['group_c_count']}) "
                  f"b={r['group_b_status']}({r['group_b_count']})")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def load_honeytokens(path: Path) -> list:
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def main():
    parser = argparse.ArgumentParser(
        prog="score_results",
        description="Classify (scenario, group, rule) cells using the 4-state taxonomy.",
    )
    parser.add_argument("--group-c-dir", required=True,
                        help="Path to run-NNN/ for Group C (mcp-tap stdio)")
    parser.add_argument("--group-b-dir", required=True,
                        help="Path to run-NNN/ for Group B (Bifrost HTTP, sliced)")
    parser.add_argument("--expectations", required=True,
                        help="Path to scenario-expectations.json")
    parser.add_argument("--honeytokens", default=None,
                        help="Path to honeytokens.txt (for BIO-004a)")
    parser.add_argument("--output", required=True,
                        help="Path to write results.csv")

    args = parser.parse_args()

    group_c_dir = Path(args.group_c_dir)
    group_b_dir = Path(args.group_b_dir)
    expectations = json.loads(Path(args.expectations).read_text())
    honeytokens = load_honeytokens(Path(args.honeytokens)) if args.honeytokens else []
    output_path = Path(args.output)

    if not group_c_dir.is_dir():
        parser.error(f"--group-c-dir not a directory: {group_c_dir}")
    if not group_b_dir.is_dir():
        parser.error(f"--group-b-dir not a directory: {group_b_dir}")

    print(f"Group C: {group_c_dir}")
    print(f"Group B: {group_b_dir}")
    print(f"Honeytokens: {len(honeytokens)} loaded")

    rows = score_run(group_c_dir, group_b_dir, expectations, honeytokens)
    write_results_csv(rows, output_path)
    print(f"\nWrote {len(rows)} rows to {output_path}")

    print_summary(rows)


if __name__ == "__main__":
    main()
