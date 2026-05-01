#!/usr/bin/env python3
"""
analyze.py: Statistical analysis for the 2x2 factorial MCP detection experiment.

Design:
  Group A: No monitoring (control)
  2x2 factorial:
    Capture tool (Bifrost HTTP vs mcp-tap stdio)
    x Rule set (conventional vs bio-derived)

CSV columns:
  scenario, group_a, b_conv, b_bio, c_conv, c_bio

Where each cell is: DETECTED, OBSERVABLE, or MISSED

Runs:
  1. Detection rates per cell
  2. Main effects (rule set effect, capture tool effect)
  3. Cochran's Q (omnibus: do the four factorial cells differ?)
  4. Pairwise McNemar's with Bonferroni correction
  5. Interaction analysis
  6. Descriptive three-category breakdown
  7. Complementarity analysis

Usage:
    python analyze.py --results results.csv
    python analyze.py --example  # generate example data and run
"""

import argparse
import csv
import sys
from collections import Counter
from io import StringIO


FACTORIAL_CELLS = ["b_conv", "b_bio", "c_conv", "c_bio"]
ALL_CELLS = ["group_a"] + FACTORIAL_CELLS

CELL_LABELS = {
    "group_a": "Group A (none)",
    "b_conv": "Bifrost+Conv",
    "b_bio": "Bifrost+Bio",
    "c_conv": "mcp-tap+Conv",
    "c_bio": "mcp-tap+Bio",
}


def read_results(path: str) -> list[dict]:
    """Read results CSV."""
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        return list(reader)


def _detected(row: dict, col: str) -> int:
    """Return 1 if DETECTED, 0 otherwise."""
    return 1 if row[col] == "DETECTED" else 0


def cochrans_q(data: list[dict], columns: list[str]) -> dict:
    """
    Cochran's Q test for k related samples with binary outcomes.
    Tests H0: the proportion of DETECTED is equal across all groups.
    """
    n = len(data)
    k = len(columns)

    binary = []
    for row in data:
        binary.append([_detected(row, col) for col in columns])

    # Column totals (Tj = total detections per group)
    T = [sum(row[j] for row in binary) for j in range(k)]

    # Row totals (Li = total detections per scenario across groups)
    L = [sum(row) for row in binary]

    T_sum = sum(T)
    T_sq_sum = sum(t**2 for t in T)
    L_sq_sum = sum(l**2 for l in L)
    L_sum = sum(L)

    numerator = (k - 1) * (k * T_sq_sum - T_sum**2)
    denominator = k * L_sum - L_sq_sum

    if denominator == 0:
        return {"Q": 0, "df": k - 1, "p_approx": 1.0,
                "note": "All groups identical"}

    Q = numerator / denominator
    df = k - 1

    # Chi-squared critical values for common thresholds
    # df=3: 0.05->7.81, 0.01->11.34
    # df=4: 0.05->9.49, 0.01->13.28
    chi2_05 = {1: 3.84, 2: 5.99, 3: 7.81, 4: 9.49}
    chi2_01 = {1: 6.63, 2: 9.21, 3: 11.34, 4: 13.28}

    if Q > chi2_01.get(df, 13.28):
        p_approx = "< 0.01"
    elif Q > chi2_05.get(df, 9.49):
        p_approx = "< 0.05"
    else:
        p_approx = "> 0.05"

    detections = {col: T[i] for i, col in enumerate(columns)}
    return {"Q": round(Q, 3), "df": df, "p_approx": p_approx,
            "detections": detections, "n": n}


def mcnemars_test(data: list[dict], col1: str, col2: str) -> dict:
    """
    McNemar's test for paired binary data.
    Compares two groups on the same scenarios.
    Uses continuity correction (appropriate for small n).
    """
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
        return {"comparison": f"{CELL_LABELS.get(col1, col1)} vs "
                              f"{CELL_LABELS.get(col2, col2)}",
                "b": b, "c": c, "n_discordant": 0,
                "statistic": 0, "p_approx": 1.0,
                "note": "No discordant pairs"}

    statistic = (abs(b - c) - 1)**2 / (b + c)

    if statistic > 6.63:
        p_approx = "< 0.01"
    elif statistic > 3.84:
        p_approx = "< 0.05"
    elif statistic > 2.71:
        p_approx = "< 0.10"
    else:
        p_approx = "> 0.10"

    return {
        "comparison": f"{CELL_LABELS.get(col1, col1)} vs "
                      f"{CELL_LABELS.get(col2, col2)}",
        "b": b, "c": c, "n_discordant": n_discordant,
        "statistic": round(statistic, 3),
        "p_approx": p_approx,
    }


def main_effects(data: list[dict]) -> dict:
    """
    Compute main effects and interaction for the 2x2 factorial.

    Rule set effect:  (b_bio + c_bio) vs (b_conv + c_conv)
    Capture effect:   (c_conv + c_bio) vs (b_conv + b_bio)
    Interaction:      does bio advantage differ by transport?
    """
    n = len(data)

    # Detection counts per cell
    counts = {col: sum(_detected(row, col) for row in data)
              for col in FACTORIAL_CELLS}

    # Main effect: rule set (bio vs conventional)
    bio_total = counts["b_bio"] + counts["c_bio"]
    conv_total = counts["b_conv"] + counts["c_conv"]
    rule_effect = (bio_total - conv_total) / (2 * n)

    # Main effect: capture tool (mcp-tap vs Bifrost)
    tap_total = counts["c_conv"] + counts["c_bio"]
    bifrost_total = counts["b_conv"] + counts["b_bio"]
    capture_effect = (tap_total - bifrost_total) / (2 * n)

    # Interaction: bio advantage on mcp-tap vs bio advantage on Bifrost
    bio_advantage_tap = counts["c_bio"] - counts["c_conv"]
    bio_advantage_bifrost = counts["b_bio"] - counts["b_conv"]
    interaction = (bio_advantage_tap - bio_advantage_bifrost) / n

    return {
        "counts": counts,
        "rule_effect": round(rule_effect, 3),
        "capture_effect": round(capture_effect, 3),
        "interaction": round(interaction, 3),
        "bio_total": bio_total,
        "conv_total": conv_total,
        "tap_total": tap_total,
        "bifrost_total": bifrost_total,
        "bio_advantage_tap": bio_advantage_tap,
        "bio_advantage_bifrost": bio_advantage_bifrost,
    }


def descriptive_table(data: list[dict]) -> str:
    """Generate the per-scenario comparison table."""
    lines = []
    header = (f"{'Scenario':<35} {'A (none)':<12} {'B+Conv':<12} "
              f"{'B+Bio':<12} {'C+Conv':<12} {'C+Bio':<12}")
    lines.append(header)
    lines.append("-" * 95)

    for row in data:
        lines.append(
            f"{row['scenario']:<35} "
            f"{row['group_a']:<12} "
            f"{row['b_conv']:<12} "
            f"{row['b_bio']:<12} "
            f"{row['c_conv']:<12} "
            f"{row['c_bio']:<12}"
        )

    lines.append("-" * 95)

    for category in ["DETECTED", "OBSERVABLE", "MISSED"]:
        counts = []
        for col in ALL_CELLS:
            counts.append(sum(1 for r in data if r[col] == category))
        lines.append(
            f"{category:<35} "
            + "".join(f"{c:<12}" for c in counts)
        )

    return "\n".join(lines)


def generate_example_csv() -> str:
    """
    Generate plausible example results for testing the analysis.

    Predictions based on knowledge of rule sets and transport coverage:
    - Conventional rules catch: failed auth, volume spikes, rapid calls,
      credential scope, enumeration
    - Bio rules catch: HMAC tampering, telemetry gaps, behavioral deviation,
      honeytokens, silence, functional output, tool schema changes, latency
    - mcp-tap sees stdio-level detail Bifrost may miss
    - Bifrost sees HTTP-level detail mcp-tap may miss
    """
    rows = [
        "scenario,group_a,b_conv,b_bio,c_conv,c_bio",
        "#1 Telemetry Suppression,MISSED,MISSED,MISSED,MISSED,DETECTED",
        "#2 Behavioral Camouflage,MISSED,MISSED,OBSERVABLE,MISSED,DETECTED",
        "#3 Protocol-Level Deception,MISSED,OBSERVABLE,OBSERVABLE,OBSERVABLE,DETECTED",
        "#6 Privileged Zone Exploitation,MISSED,MISSED,MISSED,MISSED,DETECTED",
        "#7 Pathobiont Transition,MISSED,OBSERVABLE,OBSERVABLE,OBSERVABLE,OBSERVABLE",
        "#8 The Sleeper,MISSED,MISSED,MISSED,MISSED,DETECTED",
        "#9 Defense Neutralization,MISSED,MISSED,MISSED,MISSED,DETECTED",
        "#12 Identity Rotation,MISSED,DETECTED,DETECTED,DETECTED,DETECTED",
        "#13 Trusted Boundary,MISSED,DETECTED,DETECTED,DETECTED,OBSERVABLE",
        "#19 Fabricated Authorization,MISSED,MISSED,OBSERVABLE,MISSED,OBSERVABLE",
        "#21 Credential Laundering,MISSED,OBSERVABLE,OBSERVABLE,OBSERVABLE,DETECTED",
        "#22 Tool Substitution,MISSED,MISSED,MISSED,MISSED,DETECTED",
    ]
    return "\n".join(rows)


def main():
    parser = argparse.ArgumentParser(
        prog="analyze",
        description="Statistical analysis for 2x2 factorial MCP detection experiment.",
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
    print(f"=== 2x2 FACTORIAL EXPERIMENT ANALYSIS (n={n}) ===")
    print()

    # 1. Descriptive table
    print("--- Per-Scenario Results ---")
    print(descriptive_table(data))
    print()

    # 2. Detection rates
    print("--- Detection Rates ---")
    for col in ALL_CELLS:
        detected = sum(1 for r in data if r[col] == "DETECTED")
        print(f"  {CELL_LABELS[col]:<20}: {detected}/{n} ({detected/n*100:.0f}%)")
    print()

    # 3. Main effects
    print("--- Main Effects (2x2 Factorial) ---")
    effects = main_effects(data)
    print(f"  Rule set effect (bio - conv):     {effects['rule_effect']:+.3f}")
    print(f"    Bio detections:  {effects['bio_total']}/{2*n}  "
          f"Conv detections: {effects['conv_total']}/{2*n}")
    print(f"  Capture tool effect (tap - bifrost): {effects['capture_effect']:+.3f}")
    print(f"    mcp-tap detections: {effects['tap_total']}/{2*n}  "
          f"Bifrost detections: {effects['bifrost_total']}/{2*n}")
    print(f"  Interaction:                      {effects['interaction']:+.3f}")
    print(f"    Bio advantage on mcp-tap:  {effects['bio_advantage_tap']:+d}")
    print(f"    Bio advantage on Bifrost:  {effects['bio_advantage_bifrost']:+d}")
    if abs(effects['interaction']) > 0:
        if effects['interaction'] > 0:
            print("    -> Bio rules gain MORE on mcp-tap than on Bifrost")
        else:
            print("    -> Bio rules gain MORE on Bifrost than on mcp-tap")
    print()

    # 4. Cochran's Q across factorial cells
    print("--- Cochran's Q Test (omnibus, 4 factorial cells) ---")
    q_result = cochrans_q(data, FACTORIAL_CELLS)
    print(f"  Q = {q_result['Q']}, df = {q_result['df']}, "
          f"p {q_result['p_approx']}")
    for col in FACTORIAL_CELLS:
        print(f"    {CELL_LABELS[col]:<20}: {q_result['detections'][col]} detections")
    print()

    # 5. Pairwise McNemar's — 4 key contrasts
    # Bonferroni: alpha = 0.05 / 4 = 0.0125
    print("--- Pairwise McNemar's (Bonferroni alpha=0.05/4=0.0125) ---")
    contrasts = [
        ("b_conv", "b_bio",  "Rule effect on Bifrost"),
        ("c_conv", "c_bio",  "Rule effect on mcp-tap"),
        ("b_conv", "c_conv", "Capture effect (conv rules)"),
        ("b_bio",  "c_bio",  "Capture effect (bio rules)"),
    ]
    for col1, col2, label in contrasts:
        result = mcnemars_test(data, col1, col2)
        d1_name = CELL_LABELS[col1].split("+")[-1] if "+" in CELL_LABELS[col1] else col1
        d2_name = CELL_LABELS[col2].split("+")[-1] if "+" in CELL_LABELS[col2] else col2
        print(f"  {label}:")
        print(f"    Discordant: b={result['b']} (detected in "
              f"{CELL_LABELS[col2]} only), c={result['c']} (detected in "
              f"{CELL_LABELS[col1]} only)")
        print(f"    McNemar's = {result.get('statistic', 'N/A')}, "
              f"p {result['p_approx']}")
        if result['p_approx'] in ("< 0.01",):
            print(f"    ** Significant after Bonferroni **")
        elif result['p_approx'] in ("< 0.05",):
            print(f"    * Marginal (sig at 0.05, not after Bonferroni) *")
        print()

    # 6. Control comparison
    print("--- Control (Group A) vs Best Factorial Cell ---")
    best_col = max(FACTORIAL_CELLS,
                   key=lambda c: sum(_detected(r, c) for r in data))
    best_count = sum(_detected(r, best_col) for r in data)
    a_count = sum(_detected(r, "group_a") for r in data)
    print(f"  Group A: {a_count}/{n} detected")
    print(f"  Best cell ({CELL_LABELS[best_col]}): {best_count}/{n} detected")
    control_result = mcnemars_test(data, "group_a", best_col)
    print(f"  McNemar's = {control_result.get('statistic', 'N/A')}, "
          f"p {control_result['p_approx']}")
    print()

    # 7. Complementarity: what does combining rules + transports give you?
    print("--- Complementarity Analysis ---")
    any_conv = sum(1 for r in data
                   if r["b_conv"] == "DETECTED" or r["c_conv"] == "DETECTED")
    any_bio = sum(1 for r in data
                  if r["b_bio"] == "DETECTED" or r["c_bio"] == "DETECTED")
    any_bifrost = sum(1 for r in data
                      if r["b_conv"] == "DETECTED" or r["b_bio"] == "DETECTED")
    any_tap = sum(1 for r in data
                  if r["c_conv"] == "DETECTED" or r["c_bio"] == "DETECTED")
    any_at_all = sum(1 for r in data
                     if any(r[c] == "DETECTED" for c in FACTORIAL_CELLS))

    print(f"  Any conventional rule detects: {any_conv}/{n}")
    print(f"  Any bio rule detects:          {any_bio}/{n}")
    print(f"  Any Bifrost capture detects:   {any_bifrost}/{n}")
    print(f"  Any mcp-tap capture detects:   {any_tap}/{n}")
    print(f"  Any cell at all detects:       {any_at_all}/{n}")
    print()

    # Best single cell vs combined coverage
    print(f"  Best single cell: {best_count}/{n}")
    print(f"  All cells combined: {any_at_all}/{n}")
    if any_at_all > best_count:
        print(f"  -> Combined coverage adds {any_at_all - best_count} "
              f"scenarios over best single cell")


if __name__ == "__main__":
    main()
