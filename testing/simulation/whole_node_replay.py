#!/usr/bin/env python3
"""Run independent whole-node simulations and retain replay evidence."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import resource
import signal
import subprocess
import sys
import threading
import time


ROOT = Path(__file__).resolve().parents[2]
BUILD = ["cargo", "build", "--config", ".cargo/config-simulation.toml", "--release",
         "-p", "simulator", "--features", "spec-minimal", "--bin", "deterministic-simulation"]
BINARY = ROOT / "target/x86_64-unknown-linux-gnu/release/deterministic-simulation"
SCENARIOS = ("baseline", "faults", "discovery", "restart", "storage", "forks")
FAULTS = ("partition", "heal", "execution_syncing", "execution_valid")


def positive_seconds(value):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return number


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_json(path, value):
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")


def git_metadata():
    result = {}
    for key, arguments in (("revision", ["rev-parse", "HEAD"]),
                           ("status", ["status", "--porcelain", "--untracked-files=normal"])):
        try:
            process = subprocess.run(["git", *arguments], cwd=ROOT, capture_output=True,
                                     text=True, timeout=10, check=False)
            if process.returncode:
                result[key + "_error"] = process.stderr.strip()
            else:
                result[key] = process.stdout.rstrip("\n")
        except (OSError, subprocess.TimeoutExpired) as error:
            result[key + "_error"] = str(error)
    result["dirty"] = bool(result["status"]) if "status" in result else None
    return result


def execute(command, label, output, timeout, cancelled):
    """Direct output to files, bounding the lifetime of the entire process group."""
    stdout = output / (label + ".stdout.jsonl")
    stderr = output / (label + ".stderr.log")
    result = {"command": command, "cwd": str(ROOT), "exit_status": None,
              "stdout": stdout.name, "stderr": stderr.name, "errors": []}
    started = time.monotonic()
    process = None
    with stdout.open("xb") as out, stderr.open("xb") as err:
        try:
            if cancelled.is_set():
                result["errors"].append("cancelled before launch")
            else:
                process = subprocess.Popen(command, cwd=ROOT, stdout=out, stderr=err,
                                           start_new_session=True)
                deadline = started + timeout
                while process.poll() is None:
                    if cancelled.is_set() or time.monotonic() >= deadline:
                        result["errors"].append("cancelled" if cancelled.is_set()
                                                else "timeout after {} seconds".format(timeout))
                        break
                    cancelled.wait(min(0.2, max(0, deadline - time.monotonic())))
        except OSError as error:
            result["errors"].append(str(error))
        finally:
            if process is not None:
                # Kill descendants even if the runtime wrapper has already exited.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                result["exit_status"] = process.wait()
    if result["exit_status"] != 0:
        result["errors"].append("process exit status: {}".format(result["exit_status"]))
    result["elapsed_seconds"] = time.monotonic() - started
    result["trace_sha256"] = sha256(stdout)
    result["stderr_sha256"] = sha256(stderr)
    return result


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key: " + key)
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("invalid JSON number: " + value)


def inspect_trace(path, seed, scenario):
    events = []
    try:
        with path.open(encoding="utf-8") as trace:
            for line_number, line in enumerate(trace, 1):
                try:
                    event = json.loads(line, object_pairs_hook=unique_object,
                                       parse_constant=reject_constant)
                    if not isinstance(event, dict) or not isinstance(event.get("event"), str):
                        raise ValueError("expected an event object")
                    # Also reject numbers which overflow Python's finite float range.
                    json.dumps(event, allow_nan=False)
                except ValueError as error:
                    return None, None, ["invalid JSONL at line {}: {}".format(line_number, error)]
                events.append(event)
    except (OSError, UnicodeError) as error:
        return None, None, ["cannot read JSONL: " + str(error)]

    errors = []
    names = [event["event"] for event in events]
    if names[-2:] != ["passed", "stopped"] or names.count("passed") != 1 or names.count("stopped") != 1:
        errors.append("trace must end with exactly one passed followed by exactly one stopped")
    manifest = events[0] if events and names[0] == "manifest" else None
    schedule = None
    if manifest is None or names.count("manifest") != 1:
        errors.append("expected exactly one manifest as the first event")
    elif type(manifest.get("seed")) is not int or manifest["seed"] != seed or manifest.get("scenario") != scenario:
        errors.append("manifest seed/scenario does not match command")
    elif any(type(manifest.get(key)) is not int or manifest[key] < 0
             for key in (*FAULTS, "late_join", "end")):
        errors.append("manifest schedule fields must be nonnegative integers")
    else:
        expected = ([(action, manifest[action]) for action in FAULTS]
                    if scenario in ("faults", "discovery", "forks") else [])
        expected.append(("late_join", manifest["late_join"]))
        for action, enabled in (("process_crash", scenario == "restart"),
                                ("storage_failure", scenario == "storage")):
            value = manifest.get(action)
            if enabled:
                if type(value) is not int or value < 0:
                    errors.append(action + " must be a nonnegative integer")
                else:
                    expected.append((action, value))
            elif value is not None:
                errors.append(action + " must be null for this scenario")
        expected.sort(key=lambda item: item[1])
        actual = [(event.get("action"), event.get("slot")) for event in events
                  if event["event"] == "fault"]
        if any(type(slot) is not int for _, slot in actual) or actual != expected:
            errors.append("actual fault events do not match the expanded manifest schedule")
        else:
            schedule = actual
        if manifest.get("fork_slots") != ([96] if scenario == "forks" else [0]):
            errors.append("unexpected fork-transition schedule")
    if names.count("passed") == 1:
        passed = next(event for event in events if event["event"] == "passed")
        if passed.get("restarted") is not (scenario in ("restart", "storage")):
            errors.append("restart invariant was not established for this scenario")
        if passed.get("storage_failure_observed") is not (scenario == "storage"):
            errors.append("storage-failure invariant was not established for this scenario")
    crashes = [event for event in events if event["event"] == "crash"]
    restarts = [event for event in events if event["event"] == "restarted"]
    if scenario in ("restart", "storage"):
        if len(crashes) != 1 or len(restarts) != 1:
            errors.append("expected exactly one crash and one fresh restart")
        elif (crashes[0].get("mode") != ("process" if scenario == "restart" else "power_loss")
              or restarts[0].get("slot") != crashes[0].get("slot", -2) + 2
              or not 0 < restarts[0].get("head_slot", 0) <= crashes[0].get("head_slot", 0)
              or (scenario == "storage" and crashes[0].get("observed_storage_faults", 0) < 1)):
            errors.append("crash/restart evidence violates the storage recovery contract")
    elif crashes or restarts:
        errors.append("unexpected crash/restart events")
    # Full event stream: only insignificant whitespace and object key order are ignored.
    semantic = [json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False)
                for event in events]
    return semantic, schedule, errors


def main():
    parser = argparse.ArgumentParser(
        description="Build and replay independent whole-node simulations: each selected scenario "
                    "at seed42 twice, and each non-baseline scenario at seed7 once. "
                    "Validate full semantic JSONL replay, successful completion, and seed-dependent "
                    "actual fault schedules. The binary checks consensus and recovery invariants.",
        epilog="Evidence is never deleted or overwritten. On failure all selected runs are still "
               "collected (unless building fails or the runner is interrupted). "
               "Example: python3 testing/simulation/whole_node_replay.py --output /tmp/replay-001")
    parser.add_argument("--output", required=True, type=Path,
                        help="new evidence directory; must not already exist")
    parser.add_argument("--binary", type=Path, default=BINARY,
                        help="driver executable (default: repository target/x86_64-unknown-linux-gnu/"
                             "release/deterministic-simulation); custom paths require --skip-build")
    parser.add_argument("--skip-build", action="store_true", help="use the existing executable without rebuilding")
    parser.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=SCENARIOS,
                        help="scenarios to qualify (default: all six)")
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=1,
                        help="maximum concurrent processes (default: 1; capped at 2)")
    parser.add_argument("--timeout", type=positive_seconds, default=1800,
                        help="wall-clock seconds per run, then kill its entire process group (default: 1800)")
    parser.add_argument("--build-timeout", type=positive_seconds, default=3600,
                        help="wall-clock build timeout in seconds (default: 3600)")
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("POSIX process groups are required")
    binary = args.binary.resolve()
    if binary != BINARY and not args.skip_build:
        parser.error("a custom --binary requires --skip-build")
    scenarios = list(dict.fromkeys(args.scenarios))
    runs = []
    for scenario in scenarios:
        runs.extend([(scenario + "42-a", 42, scenario), (scenario + "42-b", 42, scenario)])
        if scenario != "baseline":
            runs.append((scenario + "7", 7, scenario))
    output = args.output.resolve()
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        parser.error("cannot create new evidence directory: " + str(error))
    # A guard violation should preserve logs, not dump a full beacon-node heap.
    # Set this before creating worker threads; every child inherits the limit.
    _, core_hard_limit = resource.getrlimit(resource.RLIMIT_CORE)
    resource.setrlimit(resource.RLIMIT_CORE, (0, core_hard_limit))

    cancelled = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda _signum, _frame: cancelled.set())
    metadata = {"started_utc": datetime.now(timezone.utc).isoformat(), "cwd": str(ROOT),
                "runner_command": [sys.executable, *sys.argv], "platform": platform.platform(),
                "python": sys.version, "git": git_metadata(), "binary": str(binary),
                "rust_log": os.environ.get("RUST_LOG"),
                "jobs": args.jobs, "timeout_seconds": args.timeout,
                "build_timeout_seconds": args.build_timeout, "build_command": BUILD,
                "build_skipped": args.skip_build,
                "commands": [[str(binary), str(seed), scenario] for _, seed, scenario in runs]}
    errors = []
    results = {}
    try:
        metadata["cargo_lock_sha256"] = sha256(ROOT / "Cargo.lock")
        metadata["simulation_config_sha256"] = sha256(ROOT / ".cargo/config-simulation.toml")
        if not args.skip_build:
            build = execute(BUILD, "build", output, args.build_timeout, cancelled)
            save_json(output / "build.result.json", build)
            if build["errors"]:
                errors.extend("build: " + error for error in build["errors"])
        if not errors:
            metadata["executable_sha256"] = sha256(binary)
        save_json(output / "metadata.json", metadata)
        if not errors:
            def run(spec):
                label, seed, scenario = spec
                result = execute([str(binary), str(seed), scenario], label, output, args.timeout, cancelled)
                semantic, schedule, trace_errors = inspect_trace(output / result["stdout"], seed, scenario)
                result["errors"].extend(trace_errors)
                result["actual_fault_schedule"] = schedule
                save_json(output / (label + ".result.json"), result)
                return label, result, semantic

            traces = {}
            with ThreadPoolExecutor(max_workers=args.jobs) as pool:
                futures = [(spec[0], pool.submit(run, spec)) for spec in runs]
                for label, future in futures:
                    try:
                        _, result, traces[label] = future.result()
                        results[label] = result
                        errors.extend(label + ": " + error for error in result["errors"])
                    except Exception as error:
                        errors.append(label + ": " + str(error))
            for name in scenarios:
                scenario = name + "42"
                left, right = traces.get(scenario + "-a"), traces.get(scenario + "-b")
                if left is None or right is None:
                    errors.append(scenario + ": full semantic replay comparison unavailable")
                elif left != right:
                    mismatch = next((index + 1 for index, pair in enumerate(zip(left, right))
                                     if pair[0] != pair[1]), min(len(left), len(right)) + 1)
                    errors.append(scenario + ": full semantic replay differs at event " + str(mismatch))
            for scenario in scenarios:
                if scenario == "baseline":
                    continue
                schedule42 = results.get(scenario + "42-a", {}).get("actual_fault_schedule")
                schedule7 = results.get(scenario + "7", {}).get("actual_fault_schedule")
                if not schedule42 or not schedule7:
                    errors.append(scenario + ": cross-seed actual fault schedule comparison unavailable")
                elif schedule42 == schedule7:
                    errors.append(scenario + ": actual fault schedule unchanged between seeds 42 and 7")
    except (OSError, ValueError) as error:
        errors.append(str(error))
        if not (output / "metadata.json").exists():
            save_json(output / "metadata.json", metadata)
    if cancelled.is_set():
        errors.append("runner interrupted")
    save_json(output / "summary.json", {"success": not errors, "errors": errors, "runs": results})
    for error in errors:
        print(error, file=sys.stderr)
    print("{}; evidence: {}".format("FAIL" if errors else "PASS", output))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
