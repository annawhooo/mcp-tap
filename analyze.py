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
from math import comb, exp, lgamma, log


FACTORIAL_CELLS = ["b_conv", "b_bio", "c_conv", "c_bio"]
ALL_CELLS = ["group_a"] + FACTORIAL_CELLS

# Bonferroni-corrected alpha for the 4 pairwise contrasts in the factorial
# design (rule effect on each transport, capture effect under each rule set).
# Pulled out so it can be referenced from both mcnemars_test and main().
BONFERRONI_ALPHA = 0.05 / 4  # 0.0125


# ---------------------------------------------------------------------------
# Chi-squared survival function (stdlib only).
# Numerical Recipes pattern: series expansion of P(a, x) when x < a+1, and
# continued fraction for Q(a, x) when x >= a+1. P + Q = 1 always.
# Verified against textbook critical values for df 1..4 to 4 decimal places.
# ---------------------------------------------------------------------------

def _gser(a: float, x: float, ITMAX: int = 200, EPS: float = 3e-16) -> float:
    """Series representation of regularized lower incomplete gamma P(a, x)."""
    if x == 0:
        return 0.0
    ap = a
    sum_ = 1.0 / a
    term = sum_
    for _ in range(ITMAX):
        ap += 1
        term *= x / ap
        sum_ += term
        if abs(term) < abs(sum_) * EPS:
            return sum_ * exp(-x + a * log(x) - lgamma(a))
    raise RuntimeError("gser failed to converge")


def _gcf(a: float, x: float, ITMAX: int = 200, EPS: float = 3e-16,
         FPMIN: float = 1e-300) -> float:
    """Continued-fraction representation of regularized upper incomplete gamma Q(a, x)."""
    b = x + 1.0 - a
    c = 1.0 / FPMIN
    d = 1.0 / b
    h = d
    for i in range(1, ITMAX + 1):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < FPMIN:
            d = FPMIN
        c = b + an / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < EPS:
            return h * exp(-x + a * log(x) - lgamma(a))
    raise RuntimeError("gcf failed to converge")


def _chi2_sf(x: float, df: int) -> float:
    """Survival function (1 - CDF) of chi-squared with df degrees of freedom."""
    if x <= 0:
        return 1.0
    a = df / 2.0
    z = x / 2.0
    if z < a + 1:
        return 1.0 - _gser(a, z)
    return _gcf(a, z)

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


def _detected(row: dict, col: str, lenient: bool = False) -> int:
    """Binarize a 5-state cell value to 1 (detected) or 0 (not detected).

    Pre-registered primary specification: STRICT. A cell counts as detected
    only when its state is DETECTED — i.e., a predicted rule fired as
    predicted. UNEXPECTED_FIRING (a rule fired without prediction) and all
    failure modes (RULE_MISSED, DATA_MISSED, NOT_OBSERVABLE, NOT_EXPECTED)
    count as 0.

    Rationale for strict-as-primary:
    - The experiment's prediction file (scenario-expectations.json) names
      which rules should fire on which scenarios. The primary claim is
      that *predicted* detection mechanisms fire as predicted, not that
      the system flags the scenario by any means.
    - UNEXPECTED_FIRING is a separate signal preserved end-to-end through
      the 5-state taxonomy. Counting it as DETECTED would conflate "we got
      what we expected" with "we got something else useful." Both are
      interesting; they're different findings.
    - Strict is the rigorous reading of the experiment claim. Pre-registered
      before looking at real-data analysis output.

    Sensitivity analysis (--lenient flag): when lenient=True,
    UNEXPECTED_FIRING also counts as 1. Reported as a sensitivity check
    alongside the primary strict analysis, never as a substitute for it.
    """
    state = row[col]
    if state == "DETECTED":
        return 1
    if lenient and state == "UNEXPECTED_FIRING":
        return 1
    return 0


def cochrans_q(data: list[dict], columns: list[str], lenient: bool = False) -> dict:
    """
    Cochran's Q test for k related samples with binary outcomes.
    Tests H0: the proportion of DETECTED is equal across all groups.

    Returns a real p-value via the chi-squared survival function with df=k-1.
    The bucketed p_approx string is preserved for backward compat.

    `lenient` is forwarded to _detected; see its docstring for the
    pre-registration rationale.
    """
    n = len(data)
    k = len(columns)

    binary = []
    for row in data:
        binary.append([_detected(row, col, lenient=lenient) for col in columns])

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
        return {"Q": 0, "df": k - 1, "p_exact": 1.0, "p_approx": "> 0.05",
                "detections": {col: T[i] for i, col in enumerate(columns)},
                "n": n, "note": "All groups identical"}

    Q = numerator / denominator
    df = k - 1

    p_exact = _chi2_sf(Q, df)

    # Bucketed string derived from the real p-value, kept for backward compat.
    if p_exact < 0.01:
        p_approx = "< 0.01"
    elif p_exact < 0.05:
        p_approx = "< 0.05"
    else:
        p_approx = "> 0.05"

    detections = {col: T[i] for i, col in enumerate(columns)}
    return {"Q": round(Q, 3), "df": df,
            "p_exact": p_exact, "p_approx": p_approx,
            "detections": detections, "n": n}


def mcnemars_test(data: list[dict], col1: str, col2: str,
                  lenient: bool = False) -> dict:
    """
    McNemar's exact (binomial) test for paired binary data.

    Under H0, each discordant pair is equally likely to land in cell b or
    cell c, so the count in one cell follows Binomial(n_discordant, 0.5).
    Two-sided p-value:

        p = min(2 * P(X <= min(b, c)), 1.0)  where X ~ Binomial(n, 0.5)

    The chi-squared statistic with continuity correction is also returned
    for the printout, but inference (significance, Bonferroni) uses
    p_exact. The previous implementation used only the chi-squared
    approximation, which is unreliable at small n_discordant.

    `lenient` is forwarded to _detected; see its docstring for the
    pre-registration rationale.
    """
    b = 0  # detected in col2 but not col1
    c = 0  # detected in col1 but not col2

    for row in data:
        d1 = _detected(row, col1, lenient=lenient) == 1
        d2 = _detected(row, col2, lenient=lenient) == 1
        if d2 and not d1:
            b += 1
        elif d1 and not d2:
            c += 1

    n_discordant = b + c

    if n_discordant == 0:
        return {"comparison": f"{CELL_LABELS.get(col1, col1)} vs "
                              f"{CELL_LABELS.get(col2, col2)}",
                "b": b, "c": c, "n_discordant": 0,
                "statistic": 0, "p_exact": 1.0, "p_approx": "> 0.05",
                "significant_bonferroni": False,
                "note": "No discordant pairs"}

    # Exact two-sided binomial p-value.
    mn = min(b, c)
    tail = sum(comb(n_discordant, k) for k in range(mn + 1)) * (0.5 ** n_discordant)
    p_exact = min(2 * tail, 1.0)

    # Chi-squared statistic with continuity correction — kept for printout,
    # NOT for inference. Inference uses p_exact.
    statistic = (abs(b - c) - 1)**2 / (b + c)

    if p_exact < 0.01:
        p_approx = "< 0.01"
    elif p_exact < 0.05:
        p_approx = "< 0.05"
    else:
        p_approx = "> 0.05"

    return {
        "comparison": f"{CELL_LABELS.get(col1, col1)} vs "
                      f"{CELL_LABELS.get(col2, col2)}",
        "b": b, "c": c, "n_discordant": n_discordant,
        "statistic": round(statistic, 3),
        "p_exact": p_exact,
        "p_approx": p_approx,
        "significant_bonferroni": p_exact < BONFERRONI_ALPHA,
    }


def main_effects(data: list[dict], lenient: bool = False) -> dict:
    """
    Compute main effects and interaction for the 2x2 factorial.

    Rule set effect:  (b_bio + c_bio) vs (b_conv + c_conv)
    Capture effect:   (c_conv + c_bio) vs (b_conv + b_bio)
    Interaction:      does bio advantage differ by transport?

    `lenient` is forwarded to _detected; see its docstring for the
    pre-registration rationale.
    """
    n = len(data)

    # Detection counts per cell
    counts = {col: sum(_detected(row, col, lenient=lenient) for row in data)
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
    """Generate the per-scenario comparison table.

    Cell values are 5-state taxonomy: DETECTED, UNEXPECTED_FIRING,
    RULE_MISSED, DATA_MISSED, NOT_OBSERVABLE, NOT_EXPECTED. The state
    breakdown at the bottom shows how each cell decomposed across
    those states.
    """
    # State column width chosen to fit the longest taxonomy value
    # ("UNEXPECTED_FIRING" = 17 chars) plus padding.
    cw = 19
    label_w = 22
    lines = []
    header = (f"{'Scenario':<{label_w}} {'A (none)':<{cw}} {'B+Conv':<{cw}} "
              f"{'B+Bio':<{cw}} {'C+Conv':<{cw}} {'C+Bio':<{cw}}")
    lines.append(header)
    sep_width = label_w + 1 + (cw + 1) * 5
    lines.append("-" * sep_width)

    for row in data:
        lines.append(
            f"{row['scenario']:<{label_w}} "
            f"{row['group_a']:<{cw}} "
            f"{row['b_conv']:<{cw}} "
            f"{row['b_bio']:<{cw}} "
            f"{row['c_conv']:<{cw}} "
            f"{row['c_bio']:<{cw}}"
        )

    lines.append("-" * sep_width)

    # State breakdown across all five cells. Order from "most positive"
    # to "least informative" so the eye reads the table top-down.
    state_order = [
        "DETECTED",
        "UNEXPECTED_FIRING",
        "RULE_MISSED",
        "DATA_MISSED",
        "NOT_OBSERVABLE",
        "NOT_EXPECTED",
    ]
    for state in state_order:
        counts = []
        for col in ALL_CELLS:
            counts.append(sum(1 for r in data if r[col] == state))
        # Suppress all-zero rows so the bottom of the table doesn't get
        # cluttered with states that never occurred in this run.
        if not any(counts):
            continue
        lines.append(
            f"{state:<{label_w}} "
            + " ".join(f"{c:<{cw}}" for c in counts)
        )

    return "\n".join(lines)


def generate_example_csv() -> str:
    """
    Generate plausible example results for testing the analysis.

    Cells use the 5-state taxonomy that flows from score_results.py through
    aggregate_results.py to here:
      DETECTED, UNEXPECTED_FIRING, RULE_MISSED, DATA_MISSED,
      NOT_OBSERVABLE, NOT_EXPECTED.

    group_a is mechanically NOT_OBSERVABLE for every scenario (no monitoring
    in the control). Other cells reflect predictions based on rule sets and
    transport coverage:
    - Conventional rules catch: failed auth, volume spikes, rapid calls,
      credential scope, enumeration
    - Bio rules catch: HMAC tampering, telemetry gaps, behavioral deviation,
      honeytokens, silence, functional output, tool schema changes, latency
    - mcp-tap sees stdio-level detail Bifrost may miss
    - Bifrost sees HTTP-level detail mcp-tap may miss
    """
    rows = [
        "scenario,group_a,b_conv,b_bio,c_conv,c_bio",
        "s01,NOT_OBSERVABLE,NOT_EXPECTED,RULE_MISSED,NOT_EXPECTED,DETECTED",
        "s02,NOT_OBSERVABLE,NOT_EXPECTED,RULE_MISSED,NOT_EXPECTED,DETECTED",
        "s03,NOT_OBSERVABLE,RULE_MISSED,RULE_MISSED,RULE_MISSED,DETECTED",
        "s06,NOT_OBSERVABLE,NOT_EXPECTED,RULE_MISSED,NOT_EXPECTED,DETECTED",
        "s07,NOT_OBSERVABLE,RULE_MISSED,RULE_MISSED,RULE_MISSED,RULE_MISSED",
        "s08,NOT_OBSERVABLE,NOT_EXPECTED,RULE_MISSED,NOT_EXPECTED,DETECTED",
        "s09,NOT_OBSERVABLE,RULE_MISSED,RULE_MISSED,RULE_MISSED,DETECTED",
        "s12,NOT_OBSERVABLE,DETECTED,DETECTED,DETECTED,DETECTED",
        "s13,NOT_OBSERVABLE,DETECTED,DETECTED,DETECTED,RULE_MISSED",
        "s19,NOT_OBSERVABLE,NOT_EXPECTED,RULE_MISSED,NOT_EXPECTED,RULE_MISSED",
        "s21,NOT_OBSERVABLE,RULE_MISSED,RULE_MISSED,RULE_MISSED,DETECTED",
        "s22,NOT_OBSERVABLE,DATA_MISSED,DATA_MISSED,RULE_MISSED,DETECTED",
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
    parser.add_argument(
        "--lenient", action="store_true",
        help="Sensitivity analysis: also count UNEXPECTED_FIRING as detected. "
             "Default (strict) is the pre-registered primary specification: "
             "only DETECTED counts as detected, because the experiment tests "
             "whether *predicted* rules fire as predicted. Run with --lenient "
             "as a sensitivity check, never as a substitute for the primary "
             "strict analysis."
    )
    args = parser.parse_args()
    lenient = args.lenient

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
    mode_label = "LENIENT (SENSITIVITY)" if lenient else "STRICT (PRIMARY)"
    print(f"=== 2x2 FACTORIAL EXPERIMENT ANALYSIS (n={n}) ===")
    print(f"=== Binarization mode: {mode_label} ===")
    if lenient:
        print("    UNEXPECTED_FIRING counted as DETECTED for binarization.")
        print("    This is a sensitivity analysis, not the primary result.")
    else:
        print("    Only DETECTED counts as detected.")
        print("    UNEXPECTED_FIRING and all failure states count as 0.")
    print()

    # 1. Descriptive table
    print("--- Per-Scenario Results ---")
    print(descriptive_table(data))
    print()

    # 2. Detection rates
    print("--- Detection Rates ---")
    for col in ALL_CELLS:
        detected = sum(_detected(r, col, lenient=lenient) for r in data)
        print(f"  {CELL_LABELS[col]:<20}: {detected}/{n} ({detected/n*100:.0f}%)")
    print()

    # 3. Main effects
    print("--- Main Effects (2x2 Factorial) ---")
    effects = main_effects(data, lenient=lenient)
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
    q_result = cochrans_q(data, FACTORIAL_CELLS, lenient=lenient)
    print(f"  Q = {q_result['Q']}, df = {q_result['df']}, "
          f"p = {q_result['p_exact']:.4f}")
    for col in FACTORIAL_CELLS:
        print(f"    {CELL_LABELS[col]:<20}: {q_result['detections'][col]} detections")
    print()

    # 5. Pairwise McNemar's — 4 key contrasts
    print(f"--- Pairwise McNemar's exact test "
          f"(Bonferroni alpha = 0.05/4 = {BONFERRONI_ALPHA:.4f}) ---")
    contrasts = [
        ("b_conv", "b_bio",  "Rule effect on Bifrost"),
        ("c_conv", "c_bio",  "Rule effect on mcp-tap"),
        ("b_conv", "c_conv", "Capture effect (conv rules)"),
        ("b_bio",  "c_bio",  "Capture effect (bio rules)"),
    ]
    for col1, col2, label in contrasts:
        result = mcnemars_test(data, col1, col2, lenient=lenient)
        print(f"  {label}:")
        print(f"    Discordant: b={result['b']} (detected in "
              f"{CELL_LABELS[col2]} only), c={result['c']} (detected in "
              f"{CELL_LABELS[col1]} only)")
        print(f"    Exact p = {result['p_exact']:.4f}  "
              f"(chi-sq stat = {result['statistic']})")
        if result['significant_bonferroni']:
            print(f"    ** Significant after Bonferroni "
                  f"(p < {BONFERRONI_ALPHA:.4f}) **")
        elif result['p_exact'] < 0.05:
            print(f"    * Marginal (sig at 0.05, not after Bonferroni) *")
        else:
            print(f"    Not significant at alpha=0.05")
        print()

    # 6. Control comparison
    print("--- Control (Group A) vs Best Factorial Cell ---")
    best_col = max(FACTORIAL_CELLS,
                   key=lambda c: sum(_detected(r, c, lenient=lenient) for r in data))
    best_count = sum(_detected(r, best_col, lenient=lenient) for r in data)
    a_count = sum(_detected(r, "group_a", lenient=lenient) for r in data)
    print(f"  Group A: {a_count}/{n} detected")
    print(f"  Best cell ({CELL_LABELS[best_col]}): {best_count}/{n} detected")
    control_result = mcnemars_test(data, "group_a", best_col, lenient=lenient)
    print(f"  Exact p = {control_result['p_exact']:.4f}  "
          f"(chi-sq stat = {control_result['statistic']})")
    print()

    # 7. Complementarity: what does combining rules + transports give you?
    print("--- Complementarity Analysis ---")
    any_conv = sum(1 for r in data
                   if _detected(r, "b_conv", lenient=lenient)
                   or _detected(r, "c_conv", lenient=lenient))
    any_bio = sum(1 for r in data
                  if _detected(r, "b_bio", lenient=lenient)
                  or _detected(r, "c_bio", lenient=lenient))
    any_bifrost = sum(1 for r in data
                      if _detected(r, "b_conv", lenient=lenient)
                      or _detected(r, "b_bio", lenient=lenient))
    any_tap = sum(1 for r in data
                  if _detected(r, "c_conv", lenient=lenient)
                  or _detected(r, "c_bio", lenient=lenient))
    any_at_all = sum(1 for r in data
                     if any(_detected(r, c, lenient=lenient)
                            for c in FACTORIAL_CELLS))

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
