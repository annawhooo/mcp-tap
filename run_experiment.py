"""run_experiment.py: Orchestrate the 2x2 factorial experiment.

Loops over baseline + 12 attack scenarios, invoking scenario_runner per
scenario through the requested transport (stdio for Group C, http for
Group B). Records per-scenario time windows for post-hoc slicing of
shared Bifrost logs.

Usage:
    # Run all scenarios through Group C (mcp-tap stdio capture)
    python run_experiment.py --group c

    # Run all scenarios through Group B (Bifrost HTTP capture)
    # Requires supergateway and Bifrost to already be running
    python run_experiment.py --group b

    # Run a subset
    python run_experiment.py --group c --scenarios baseline,s02,s08

Files written to <run-dir>:
    run_meta.json   - run metadata (commit, group, timestamps, status)
    windows.json    - { scenario_id: { start_ts, end_ts, status, exit_code } }
    run.log         - stdout/stderr from scenario_runner invocations
    group_c_<sid>.jsonl  - mcp-tap output (Group C only)

Default --run-dir auto-increments: experiment/logs/run-001/, run-002/, etc.
The orchestrator does NOT start/stop Bifrost or supergateway. For Group B,
start those manually before running, stop manually after.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(r"C:\Users\Anna\PycharmProjects\mcp-tap")
PYTHON = r"C:\Users\Anna\AppData\Local\Programs\Python\Python311\python.exe"
EXPERIMENT_DIR = REPO_ROOT / "experiment"
DATA_DIR = EXPERIMENT_DIR / "data"
SETUP_SCRIPT = EXPERIMENT_DIR / "setup_data.py"
SCENARIO_RUNNER = REPO_ROOT / "scenario_runner.py"
GROUP_C_SERVER_BAT = EXPERIMENT_DIR / "group_c_server.bat"
DEFAULT_LOGS_DIR = EXPERIMENT_DIR / "logs"

# All scenario IDs in execution order. Baseline must be first so BIO-003
# can use it as the comparison baseline for all attack scenarios.
ALL_SCENARIO_IDS = [
    "baseline",
    "s01", "s02", "s03", "s06", "s07", "s08",
    "s09", "s12", "s13", "s19", "s21", "s22",
    "s09b",
]


def get_git_info(repo_root: Path) -> dict:
    """Return current commit SHA and dirty-tree status.

    Records `<sha>-dirty` if working tree has uncommitted changes, so
    reproducibility claims are honest.
    """
    info = {"commit": None, "dirty": None}
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root, capture_output=True, text=True, timeout=10,
        )
        if sha.returncode == 0:
            info["commit"] = sha.stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_root, capture_output=True, text=True, timeout=10,
        )
        if status.returncode == 0:
            info["dirty"] = bool(status.stdout.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        info["error"] = str(e)
    return info


def next_run_dir(logs_dir: Path) -> Path:
    """Find the next available run-NNN/ directory under logs_dir."""
    logs_dir.mkdir(parents=True, exist_ok=True)
    existing = [d.name for d in logs_dir.iterdir() if d.is_dir()]
    pattern = re.compile(r"^run-(\d{3})$")
    used = sorted(int(m.group(1)) for m in (pattern.match(n) for n in existing) if m)
    next_num = (used[-1] + 1) if used else 1
    return logs_dir / f"run-{next_num:03d}"


def reset_data_dir(setup_script: Path, log_handle) -> None:
    """Run setup_data.py to wipe and recreate experiment/data/."""
    result = subprocess.run(
        [PYTHON, str(setup_script)],
        capture_output=True, text=True, timeout=60,
    )
    log_handle.write(f"=== setup_data ===\n")
    log_handle.write(result.stdout)
    if result.stderr:
        log_handle.write(f"STDERR:\n{result.stderr}\n")
    if result.returncode != 0:
        raise RuntimeError(
            f"setup_data.py failed (exit {result.returncode}). See run.log."
        )


def run_one_scenario(
    sid: str,
    group: str,
    run_dir: Path,
    bifrost_url: str,
    log_handle,
) -> dict:
    """Execute one scenario, return window record."""
    start_ts = datetime.now(timezone.utc)

    if group == "c":
        log_path = run_dir / f"group_c_{sid}.jsonl"
        # group_c_server.bat takes the log path as %1
        server_cmd = f'"{GROUP_C_SERVER_BAT}" "{log_path}"'
        cmd = [
            PYTHON, str(SCENARIO_RUNNER),
            "--scenario", sid,
            "--transport", "stdio",
            "--server", server_cmd,
        ]
    elif group == "b":
        cmd = [
            PYTHON, str(SCENARIO_RUNNER),
            "--scenario", sid,
            "--transport", "http",
            "--url", bifrost_url,
        ]
    else:
        raise ValueError(f"unknown group: {group}")

    log_handle.write(f"\n=== scenario {sid} ===\n")
    log_handle.write(f"start_ts: {start_ts.isoformat()}\n")
    log_handle.write(f"cmd: {cmd}\n")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
        )
        log_handle.write(result.stdout)
        if result.stderr:
            log_handle.write(f"STDERR:\n{result.stderr}\n")
        exit_code = result.returncode
        status = "ok" if exit_code == 0 else "failed"
    except subprocess.TimeoutExpired as e:
        log_handle.write(f"TIMEOUT: {e}\n")
        exit_code = -1
        status = "timeout"
    except Exception as e:
        log_handle.write(f"EXCEPTION: {e}\n")
        exit_code = -2
        status = "crashed"

    end_ts = datetime.now(timezone.utc)
    log_handle.write(f"end_ts: {end_ts.isoformat()}\n")
    log_handle.write(f"status: {status} (exit {exit_code})\n")

    return {
        "start_ts": start_ts.isoformat(),
        "end_ts": end_ts.isoformat(),
        "status": status,
        "exit_code": exit_code,
    }


def run_experiment(
    group: str,
    run_dir: Path,
    scenarios: list,
    inter_scenario_gap: float,
    bifrost_url: str,
) -> dict:
    """Execute all scenarios. Returns run summary dict."""
    run_dir.mkdir(parents=True, exist_ok=True)

    # Capture run metadata up front
    started_at = datetime.now(timezone.utc)
    git_info = get_git_info(REPO_ROOT)
    run_meta = {
        "group": group,
        "started_at": started_at.isoformat(),
        "completed_at": None,
        "commit": git_info.get("commit"),
        "dirty_tree": git_info.get("dirty"),
        "python_version": sys.version,
        "platform": sys.platform,
        "scenarios_attempted": list(scenarios),
        "scenarios_succeeded": [],
        "scenarios_failed": [],
        "inter_scenario_gap": inter_scenario_gap,
        "bifrost_url": bifrost_url if group == "b" else None,
    }

    windows = {}
    log_path = run_dir / "run.log"

    with open(log_path, "w", encoding="utf-8") as log_handle:
        log_handle.write(f"# run_experiment\n")
        log_handle.write(f"# group: {group}\n")
        log_handle.write(f"# run_dir: {run_dir}\n")
        log_handle.write(f"# started_at: {started_at.isoformat()}\n")
        log_handle.write(f"# git: {git_info}\n\n")

        for sid in scenarios:
            print(f"\n[{sid}] resetting data dir...")
            try:
                reset_data_dir(SETUP_SCRIPT, log_handle)
            except RuntimeError as e:
                print(f"[{sid}] FATAL: {e}")
                log_handle.write(f"FATAL: {e}\n")
                run_meta["fatal_error"] = str(e)
                break

            print(f"[{sid}] running...")
            window = run_one_scenario(sid, group, run_dir, bifrost_url, log_handle)
            windows[sid] = window

            if window["status"] == "ok":
                run_meta["scenarios_succeeded"].append(sid)
                print(f"[{sid}] ok")
            else:
                run_meta["scenarios_failed"].append(sid)
                print(f"[{sid}] {window['status']} (exit {window['exit_code']})")

            if sid != scenarios[-1] and inter_scenario_gap > 0:
                log_handle.write(f"\n=== sleeping {inter_scenario_gap}s ===\n")
                time.sleep(inter_scenario_gap)

    run_meta["completed_at"] = datetime.now(timezone.utc).isoformat()

    with open(run_dir / "windows.json", "w") as f:
        json.dump(windows, f, indent=2)
    with open(run_dir / "run_meta.json", "w") as f:
        json.dump(run_meta, f, indent=2)

    return run_meta


def main():
    parser = argparse.ArgumentParser(
        prog="run_experiment",
        description="Orchestrate the 2x2 factorial experiment.",
    )
    parser.add_argument("--group", required=True, choices=["b", "c"],
                        help="b = Bifrost HTTP capture, c = mcp-tap stdio capture")
    parser.add_argument("--run-dir", default=None,
                        help="Output directory. Default: auto-increment "
                             "experiment/logs/run-NNN/")
    parser.add_argument("--scenarios", default=None,
                        help=f"Comma-separated scenario IDs. Default: all "
                             f"({len(ALL_SCENARIO_IDS)} including baseline)")
    parser.add_argument("--inter-scenario-gap", type=float, default=2.0,
                        help="Seconds to sleep between scenarios. Default: 2.0")
    parser.add_argument("--bifrost-url", default="http://localhost:9090/mcp",
                        help="Bifrost endpoint URL (Group B only)")

    args = parser.parse_args()

    if args.run_dir:
        run_dir = Path(args.run_dir)
    else:
        run_dir = next_run_dir(DEFAULT_LOGS_DIR)

    if args.scenarios:
        scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip()]
        unknown = [s for s in scenarios if s not in ALL_SCENARIO_IDS]
        if unknown:
            parser.error(f"unknown scenario IDs: {unknown}. "
                         f"Valid: {ALL_SCENARIO_IDS}")
    else:
        scenarios = list(ALL_SCENARIO_IDS)

    print(f"Group:     {args.group}")
    print(f"Run dir:   {run_dir}")
    print(f"Scenarios: {scenarios}")
    print(f"Gap:       {args.inter_scenario_gap}s")
    if args.group == "b":
        print(f"Bifrost:   {args.bifrost_url}")
        print(f"NOTE: ensure supergateway and Bifrost are running before this script.")
    print()

    run_meta = run_experiment(
        group=args.group,
        run_dir=run_dir,
        scenarios=scenarios,
        inter_scenario_gap=args.inter_scenario_gap,
        bifrost_url=args.bifrost_url,
    )

    print(f"\n=== run complete ===")
    print(f"  succeeded: {len(run_meta['scenarios_succeeded'])} "
          f"({run_meta['scenarios_succeeded']})")
    print(f"  failed:    {len(run_meta['scenarios_failed'])} "
          f"({run_meta['scenarios_failed']})")
    if run_meta.get("fatal_error"):
        print(f"  FATAL: {run_meta['fatal_error']}")
        sys.exit(1)
    print(f"  output:    {run_dir}")


if __name__ == "__main__":
    main()
