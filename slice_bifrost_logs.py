"""slice_bifrost_logs.py: Slice a shared Bifrost logs.db into per-scenario JSONLs.

After `run_experiment.py --group b` completes, you have:
  - one shared experiment/bifrost-data/logs.db (all scenarios mixed)
  - run-NNN/windows.json (per-scenario start_ts/end_ts)

This script reads windows.json and calls log_adapter.adapt_bifrost once per
scenario with that scenario's time window, writing group_b_<sid>.jsonl into
the same run-NNN/ dir. Mirrors the Group C output convention so downstream
scoring can treat both groups uniformly.

Usage:
    # Slice all scenarios from a completed Group B run
    python slice_bifrost_logs.py --run-dir experiment/logs/run-001 \\
        --bifrost-db experiment/bifrost-data/logs.db

    # Re-slice just a subset (e.g., after fixing a bad slice)
    python slice_bifrost_logs.py --run-dir experiment/logs/run-001 \\
        --bifrost-db experiment/bifrost-data/logs.db \\
        --scenarios baseline,s02

Files written to <run-dir>:
    group_b_<sid>.jsonl  - per-scenario adapted output (one per ok scenario)
    slice_meta.json      - { sid: { entries, status, error? } } for all sliced
                           scenarios. Lets you debug "did the window match?"
                           without re-reading 13 JSONLs.

Failed scenarios in windows.json are skipped (not sliced). Empty windows
produce empty JSONL files so the downstream scoring loop has uniform inputs.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from log_adapter import adapt_bifrost


def slice_one_scenario(
    sid: str,
    window: dict,
    bifrost_db: Path,
    out_path: Path,
) -> dict:
    """Slice one scenario's window from the shared Bifrost DB.

    Returns a metadata record for slice_meta.json. Does not raise on
    adapter failures — captures them in the record so the caller can
    continue with other scenarios.
    """
    record = {
        "sid": sid,
        "start_ts": window.get("start_ts"),
        "end_ts": window.get("end_ts"),
        "output": str(out_path),
        "entries": 0,
        "status": None,
    }

    if window.get("status") != "ok":
        record["status"] = "skipped_failed_scenario"
        record["scenario_run_status"] = window.get("status")
        return record

    try:
        start_dt = datetime.fromisoformat(window["start_ts"])
        end_dt = datetime.fromisoformat(window["end_ts"])
    except (KeyError, ValueError, TypeError) as e:
        record["status"] = "error"
        record["error"] = f"window timestamp parse: {e}"
        return record

    try:
        count = adapt_bifrost(
            str(bifrost_db),
            str(out_path),
            server_id="bifrost",
            start_ts=start_dt,
            end_ts=end_dt,
        )
        record["entries"] = count
        record["status"] = "ok" if count > 0 else "ok_empty"
    except Exception as e:
        record["status"] = "error"
        record["error"] = f"adapt_bifrost: {type(e).__name__}: {e}"

    return record


def slice_run(
    run_dir: Path,
    bifrost_db: Path,
    scenarios: list = None,
) -> dict:
    """Slice all (or a subset of) scenarios from a completed Group B run.

    Returns the slice_meta dict (also written to slice_meta.json).
    """
    windows_path = run_dir / "windows.json"
    if not windows_path.is_file():
        raise FileNotFoundError(f"windows.json not found: {windows_path}")

    with open(windows_path) as f:
        windows = json.load(f)

    if scenarios is not None:
        unknown = [s for s in scenarios if s not in windows]
        if unknown:
            raise ValueError(
                f"scenarios not in windows.json: {unknown}. "
                f"Available: {list(windows.keys())}"
            )
        targets = scenarios
    else:
        targets = list(windows.keys())

    slice_meta = {
        "run_dir": str(run_dir),
        "bifrost_db": str(bifrost_db),
        "sliced_at": datetime.utcnow().isoformat() + "+00:00",
        "scenarios": {},
    }

    for sid in targets:
        out_path = run_dir / f"group_b_{sid}.jsonl"
        record = slice_one_scenario(sid, windows[sid], bifrost_db, out_path)
        slice_meta["scenarios"][sid] = record

        status_str = record["status"]
        entries = record.get("entries", 0)
        if status_str == "ok":
            print(f"[{sid}] {entries} entries -> {out_path.name}")
        elif status_str == "ok_empty":
            print(f"[{sid}] 0 entries (empty window) -> {out_path.name}")
        elif status_str == "skipped_failed_scenario":
            print(f"[{sid}] SKIPPED (scenario run status: "
                  f"{record.get('scenario_run_status')})")
        elif status_str == "error":
            print(f"[{sid}] ERROR: {record.get('error')}")
        else:
            print(f"[{sid}] {status_str}")

    with open(run_dir / "slice_meta.json", "w") as f:
        json.dump(slice_meta, f, indent=2)

    return slice_meta


def main():
    parser = argparse.ArgumentParser(
        prog="slice_bifrost_logs",
        description="Slice a shared Bifrost logs.db into per-scenario JSONLs "
                    "using a run-NNN/windows.json from run_experiment.py.",
    )
    parser.add_argument("--run-dir", required=True,
                        help="Path to run-NNN/ directory (contains windows.json)")
    parser.add_argument("--bifrost-db", required=True,
                        help="Path to Bifrost SQLite logs.db")
    parser.add_argument("--scenarios", default=None,
                        help="Comma-separated scenario IDs to slice. "
                             "Default: all scenarios in windows.json")

    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    bifrost_db = Path(args.bifrost_db)

    if not run_dir.is_dir():
        parser.error(f"--run-dir not a directory: {run_dir}")
    if not bifrost_db.is_file():
        parser.error(f"--bifrost-db not a file: {bifrost_db}")

    scenarios = None
    if args.scenarios:
        scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip()]

    try:
        slice_meta = slice_run(run_dir, bifrost_db, scenarios=scenarios)
    except (FileNotFoundError, ValueError) as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(1)

    # Summary
    statuses = [r["status"] for r in slice_meta["scenarios"].values()]
    n_ok = sum(1 for s in statuses if s == "ok")
    n_empty = sum(1 for s in statuses if s == "ok_empty")
    n_skip = sum(1 for s in statuses if s == "skipped_failed_scenario")
    n_err = sum(1 for s in statuses if s == "error")
    print(f"\n=== slice complete ===")
    print(f"  ok:      {n_ok}")
    print(f"  empty:   {n_empty}")
    print(f"  skipped: {n_skip}")
    print(f"  errors:  {n_err}")
    print(f"  meta:    {run_dir / 'slice_meta.json'}")


if __name__ == "__main__":
    main()
