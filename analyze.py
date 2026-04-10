#!/usr/bin/env python3
"""
analyze.py: Statistical analysis for the A/B/C MCP detection experiment.

Reads a results CSV with columns:
  scenario, group_a, group_b, group_c

Where each cell is: DETECTED, OBSERVABLE, or MISSED

Runs:
  1. Cochran's Q test (omnibus: do the three groups differ?)
  2. Pairwise McNemar's with Bonferroni correction
  3. Descriptive three-category breakdown
  4. Per-scenario comparison table

Usage:
    python analyze.py --results results.csv
    python analyze.py --example  # generate example CSV and run
"""

import argparse
import csv
import sys
from collections import Counter
from io import StringIO


def read_results(path: str) -> list[dict]:
    """Read results CSV."""
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        return list(reader)


def cochrans_q(data: list[dict]) -> dict:
    """
    Cochran's Q test for k related samples with binary outcomes.

    Tests H0: the proportion of DETECTED is equal across all groups.
    """
    n = len(data)
    k = 3  # groups A, B, C

    # Convert to binary: DETECTED=1, else=0
    binary = []
    for row in data:
        binary.append([
            1 if row["group_a"] == "DETECTED" else 0,
            1 if row["group_b"] == "DETECTED" else 0,
            1 if row["group_c"] == "DETECTED" else 0,
        ])

    # Column totals (Tj = total detections per group)
    T = [sum(row[j] for row in binary) for j in range(k)]

    # Row totals (Li = total detections per scenario across groups)
    L = [sum(row) for row in binary]

    # Cochran's Q statistic
    T_sum = sum(T)
    T_sq_sum = sum(t**2 for t in T)
    L_sq_sum = sum(l**2 for l in L)
    L_sum = sum(L)

    numerator = (k - 1) * (k * T_sq_sum - T_sum**2)
    denominator = k * L_sum - L_sq_sum

    if denominator == 0:
        return {"Q": 0, "df": k - 1, "p_approx": 1.0,
                "note": "All groups identical (denominator=0)"}

    Q = numerator / denominator
    df = k - 1

    # Approximate p-value using chi-squared distribution
    # For df=2: p < 0.05 requires Q > 5.99
    # For df=2: p < 0.01 requires Q > 9.21
    # Simple lookup for common thresholds
    if Q > 9.21:
        p_approx = "< 0.01"
    elif Q > 5.99:
        p_approx = "< 0.05"
    elif Q > 4.61:
        p_approx = "< 0.10"
    else:
        p_approx = "> 0.10"

    return {
        "Q": round(Q, 3),
        "df": df,
        "p_approx": p_approx,
        "group_detections": {"A": T[0], "B": T[1], "C": T[2]},
        "n": n,
    }


def mcnemars_test(data: list[dict], col1: str, col2: str) -> dict:
    """
    McNemar's test for paired binary data.

    Compares two groups on the same scenarios.
    Uses exact test (appropriate for small n).
    """
    # Count discordant pairs
    b = 0  # detected in col2 but not col1
    c = 0  # detected in col1 but not col2

    for row in data:
        d1 = row[col1] == "DETECTED"
        d2 = row[col2] == "DETECTED"
        if d2 and not d1:
            b += 1
        elif d1 and not d2:
            c += 1

    n_discordant = b + c

    if n_discordant == 0:
        return {
            "comparison": f"{col1} vs {col2}",
            "b": b, "c": c,
            "statistic": 0,
            "p_approx": 1.0,
            "note": "No discordant pairs",
        }

    # McNemar's chi-squared (with continuity correction for small n)
    statistic = (abs(b - c) - 1)**2 / (b + c) if (b + c) > 0 else 0

    # Significance thresholds (chi-squared df=1)
    # p < 0.05 requires stat > 3.84
    # p < 0.01 requires stat > 6.63
    if statistic > 6.63:
        p_approx = "< 0.01"
    elif statistic > 3.84:
        p_approx = "< 0.05"
    elif statistic > 2.71:
        p_approx = "< 0.10"
    else:
        p_approx = "> 0.10"

    return {
        "comparison": f"{col1} vs {col2}",
        "b": b,
        "c": c,
        "n_discordant": n_discordant,
        "statistic": round(statistic, 3),
        "p_approx": p_approx,
    }


def descriptive_table(data: list[dict]) -> str:
    """Generate the per-scenario comparison table."""
    lines = []
    lines.append(f"{'Scenario':<35} {'Group A':<12} {'Group B':<12} {'Group C':<12}")
    lines.append("-" * 71)

    for row in data:
        lines.append(
            f"{row['scenario']:<35} "
            f"{row['group_a']:<12} "
            f"{row['group_b']:<12} "
            f"{row['group_c']:<12}"
        )

    lines.append("-" * 71)

    # Summary counts
    for category in ["DETECTED", "OBSERVABLE", "MISSED"]:
        a = sum(1 for r in data if r["group_a"] == category)
        b = sum(1 for r in data if r["group_b"] == category)
        c = sum(1 for r in data if r["group_c"] == category)
        lines.append(f"{category:<35} {a:<12} {b:<12} {c:<12}")

    return "\n".join(lines)


def generate_example_csv() -> str:
    """Generate plausible example results for testing the analysis."""
    # Predicted results based on our knowledge of the rule sets
    rows = [
        "scenario,group_a,group_b,group_c",
        "#1 Telemetry Suppression,MISSED,MISSED,DETECTED",
        "#2 Behavioral Camouflage,MISSED,MISSED,DETECTED",
        "#3 Protocol-Level Deception,MISSED,OBSERVABLE,DETECTED",
        "#6 Privileged Zone Exploitation,MISSED,MISSED,DETECTED",
        "#7 Pathobiont Transition,MISSED,OBSERVABLE,OBSERVABLE",
        "#8 The Sleeper,MISSED,MISSED,DETECTED",
        "#9 Defense Neutralization,MISSED,MISSED,DETECTED",
        "#12 Identity Rotation,MISSED,DETECTED,DETECTED",
        "#13 Trusted Boundary Exploitation,MISSED,DETECTED,OBSERVABLE",
        "#19 Fabricated Authorization,MISSED,MISSED,OBSERVABLE",
        "#21 Credential Laundering,MISSED,OBSERVABLE,DETECTED",
        "#22 Tool Substitution,MISSED,MISSED,DETECTED",
    ]
    return "\n".join(rows)


def main():
    parser = argparse.ArgumentParser(
        prog="analyze",
        description="Statistical analysis for A/B/C MCP detection experiment.",
    )
    parser.add_argument("--results", help="Path to results CSV")
    parser.add_argument("--example", action="store_true",
                        help="Generate and analyze example data")
    args = parser.parse_args()

    if args.example:
        csv_text = generate_example_csv()
        print("=== EXAMPLE DATA (predicted results) ===")
        print(csv_text)
        print()
        reader = csv.DictReader(StringIO(csv_text))
        data = list(reader)
    elif args.results:
        data = read_results(args.results)
    else:
        parser.print_help()
        sys.exit(1)

    n = len(data)
    print(f"=== A/B/C EXPERIMENT ANALYSIS (n={n}) ===")
    print()

    # 1. Descriptive table
    print("--- Per-Scenario Results ---")
    print(descriptive_table(data))
    print()

    # 2. Detection rates
    for group in ["group_a", "group_b", "group_c"]:
        detected = sum(1 for r in data if r[group] == "DETECTED")
        label = group.replace("group_", "Group ").upper()
        print(f"{label} detection rate: {detected}/{n} ({detected/n*100:.0f}%)")
    print()

    # 3. Cochran's Q
    print("--- Cochran's Q Test (omnibus) ---")
    q_result = cochrans_q(data)
    print(f"Q = {q_result['Q']}, df = {q_result['df']}, p {q_result['p_approx']}")
    print(f"Detections per group: A={q_result['group_detections']['A']}, "
          f"B={q_result['group_detections']['B']}, "
          f"C={q_result['group_detections']['C']}")
    print()

    # 4. Pairwise McNemar's with Bonferroni
    print("--- Pairwise McNemar's (Bonferroni-corrected, alpha=0.05/3=0.017) ---")
    pairs = [
        ("group_a", "group_b", "A vs B (sanity check)"),
        ("group_a", "group_c", "A vs C (expected)"),
        ("group_b", "group_c", "B vs C (THE CLAIM)"),
    ]
    for col1, col2, label in pairs:
        result = mcnemars_test(data, col1, col2)
        print(f"{label}:")
        print(f"  Discordant pairs: b={result['b']} (detected in {col2.split('_')[1].upper()} only), "
              f"c={result['c']} (detected in {col1.split('_')[1].upper()} only)")
        print(f"  McNemar's stat = {result.get('statistic', 'N/A')}, p {result['p_approx']}")
        # Bonferroni: need p < 0.017 for significance
        if result['p_approx'] in ("< 0.01",):
            print(f"  ** Significant after Bonferroni correction **")
        elif result['p_approx'] in ("< 0.05",):
            print(f"  * Significant at 0.05 but NOT after Bonferroni correction *")
        print()

    # 5. Complementarity analysis
    print("--- Complementarity Analysis ---")
    both_detect = sum(1 for r in data
                      if r["group_b"] == "DETECTED" and r["group_c"] == "DETECTED")
    b_only = sum(1 for r in data
                 if r["group_b"] == "DETECTED" and r["group_c"] != "DETECTED")
    c_only = sum(1 for r in data
                 if r["group_c"] == "DETECTED" and r["group_b"] != "DETECTED")
    neither = sum(1 for r in data
                  if r["group_b"] != "DETECTED" and r["group_c"] != "DETECTED")
    print(f"Both B and C detect:    {both_detect}/{n}")
    print(f"Only B detects:         {b_only}/{n}")
    print(f"Only C detects:         {c_only}/{n}")
    print(f"Neither detects:        {neither}/{n}")
    print(f"Combined B+C coverage:  {both_detect + b_only + c_only}/{n}")
    print()

    if c_only > b_only:
        print(f"Bio-derived rules uniquely detect {c_only} scenarios that "
              f"conventional rules miss.")
    if b_only > 0:
        print(f"Conventional rules uniquely detect {b_only} scenarios that "
              f"bio-derived rules miss.")
    if c_only > 0 and b_only > 0:
        print(f"The rule sets are COMPLEMENTARY: combined coverage "
              f"({both_detect + b_only + c_only}/{n}) exceeds either alone.")


if __name__ == "__main__":
    main()
