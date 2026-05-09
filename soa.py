#!/usr/bin/env python3
"""
SOA Master Launcher (L15 Full Agentic Loop)
Orchestrates all phases in sequence with pause/resume support.

Usage:
  python3 run_soa.py --target uber
  python3 run_soa.py --target uber --resume
  python3 run_soa.py --target uber --phase 2

CTRL+C → pause at next phase boundary.
Resume picks up from last completed phase.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime

BASE_DIR     = os.path.expanduser("~/son-of-anton")
MEMORY_DIR   = os.path.join(BASE_DIR, "memory")
PROJECTS_DIR = os.path.join(BASE_DIR, "projects")
STATE_PATH   = os.path.join(MEMORY_DIR, "self-state.json")
sys.path.insert(0, BASE_DIR)

try:
    from rich.console import Console
    from rich.rule import Rule
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None


def print_ok(msg):
    if RICH: console.print(f"[green]✓[/green] {msg}")
    else:    print(f"✓ {msg}")

def print_err(msg):
    if RICH: console.print(f"[red]✗[/red] {msg}")
    else:    print(f"✗ {msg}", file=sys.stderr)

def print_info(msg):
    if RICH: console.print(f"[cyan]→[/cyan] {msg}")
    else:    print(f"→ {msg}")

def print_warn(msg):
    if RICH: console.print(f"[yellow]⚠[/yellow]  {msg}")
    else:    print(f"⚠  {msg}")

def print_phase(msg):
    if RICH: console.rule(f"[bold cyan]{msg}[/bold cyan]")
    else:    print(f"\n{'='*60}\n{msg}\n{'='*60}")


# ── State management ──────────────────────────────────────────────────────────

def session_path(target):
    return os.path.join(PROJECTS_DIR, target, "session.json")


def load_session(target):
    path = session_path(target)
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def save_session(target, data):
    path = session_path(target)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data["last_updated"] = datetime.utcnow().isoformat() + "Z"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def create_session(target):
    path = session_path(target)
    if os.path.exists(path):
        return load_session(target)
    now = datetime.utcnow()
    data = {
        "target":               target,
        "session_date":         now.strftime("%Y-%m-%d"),
        "session_start":        now.strftime("%H:%M"),
        "phase_current":        "1a",
        "phases_completed":     [],
        "phases_failed":        [],
        "open_anomalies":       [],
        "tried_steps":          [],
        "active_hypotheses":    [],
        "decisions_log":        [],
        "findings_this_session":[],
        "curious_items":        [],
        "last_updated":         now.isoformat() + "Z",
        "soa_run_id":           f"{target}-{now.strftime('%Y%m%d-%H%M%S')}",
    }
    save_session(target, data)
    return data


def mark_phase_complete(target, phase_id):
    sess = load_session(target)
    completed = sess.get("phases_completed", [])
    if phase_id not in completed:
        completed.append(phase_id)
    sess["phases_completed"] = completed
    sess["phase_current"]    = phase_id
    save_session(target, sess)


def mark_phase_failed(target, phase_id):
    sess = load_session(target)
    failed = sess.get("phases_failed", [])
    if phase_id not in failed:
        failed.append(phase_id)
    sess["phases_failed"] = failed
    save_session(target, sess)


def last_completed_phase(target):
    sess = load_session(target)
    completed = sess.get("phases_completed", [])
    return completed[-1] if completed else None


# ── Script runner ─────────────────────────────────────────────────────────────

def run_script(script_rel, extra_args=None, timeout=3600):
    """
    Run a Python script in a subprocess. Returns (returncode, stdout, stderr).
    script_rel: path relative to BASE_DIR
    """
    script_path = os.path.join(BASE_DIR, script_rel)
    if not os.path.exists(script_path):
        return -1, "", f"Script not found: {script_path}"

    cmd = [sys.executable, script_path] + (extra_args or [])
    print_info(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            cwd=BASE_DIR,
            timeout=timeout,
            capture_output=False,   # let output flow to terminal
            text=True,
        )
        return result.returncode, "", ""
    except subprocess.TimeoutExpired:
        return -2, "", f"Timeout after {timeout}s"
    except Exception as e:
        return -3, "", str(e)


def run_parallel(script_args_list, timeout=3600):
    """
    Run multiple (script_rel, extra_args) pairs in parallel threads.
    Returns dict of {script_rel: returncode}.
    """
    results = {}
    threads = []

    def _run(script_rel, extra_args):
        rc, _, _ = run_script(script_rel, extra_args, timeout=timeout)
        results[script_rel] = rc

    for script_rel, extra_args in script_args_list:
        t = threading.Thread(
            target=_run,
            args=(script_rel, extra_args),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return results


# ── EventBus integration ──────────────────────────────────────────────────────

def get_bus():
    try:
        from phases.brain.event_bus import EventBus
        return EventBus.instance()
    except ImportError:
        return None


def emit(event_name, data):
    try:
        from phases.brain.event_bus import EventBus, SOAEvent
        bus   = EventBus.instance()
        event = SOAEvent[event_name]
        bus.emit(event, data, source="run_soa")
    except Exception:
        pass


# ── FP suppressor integration ─────────────────────────────────────────────────

def run_fp_checks(target, phase3_dir):
    """Check all phase3 result JSONs against suppression list."""
    try:
        sys.path.insert(0, os.path.join(BASE_DIR, "phases", "phase3"))
        from phases.phase3.fp_suppressor import is_suppressed_pattern
    except ImportError:
        print_warn("fp_suppressor not importable — skipping FP checks")
        return []

    passing = []
    if not os.path.isdir(phase3_dir):
        return passing

    for fname in os.listdir(phase3_dir):
        if not fname.endswith("-results.json"):
            continue
        tool = fname.replace("-results.json", "")
        fpath = os.path.join(phase3_dir, fname)
        try:
            with open(fpath) as f:
                data = json.load(f)
        except Exception:
            continue

        results = data.get("results", [])
        for item in results:
            url = item.get("url") or item.get("host") or ""
            if url and not is_suppressed_pattern(target, url, tool):
                passing.append({"url": url, "tool": tool, "data": item})
                emit("FINDING_DETECTED", {
                    "target": target,
                    "url":    url,
                    "tool":   tool,
                })

    return passing


# ── Phase definitions ─────────────────────────────────────────────────────────

PHASE_ORDER = ["1a", "1b", "1c", "1d", "2-eye", "2-score", "2-plan", "3-hunt", "final"]

PHASE_SCRIPTS = {
    "1a":      ("phases/phase1/phase1a_passive.py",  ["--target", "{target}"]),
    "1b":      ("phases/phase1/phase1b_active.py",   ["--target", "{target}"]),
    "1c":      ("phases/phase1/phase1c_probing.py",  ["--target", "{target}"]),
    "1d":      ("phases/phase1/phase1d_bucktes.py",  ["--target", "{target}"]),
    "2-eye":   ("phases/phase2/second_eye.py",       ["--target", "{target}"]),
    "2-score": ("phases/phase2/anomaly_scorer.py",   ["--target", "{target}"]),
    "2-plan":  ("phases/phase2/hunt_planner.py",     ["--target", "{target}"]),
    "final":   ("phases/brain/episodic_write.py",    ["--target", "{target}"]),
}

PHASE_NAMES = {
    "1a":      "Phase 1A — Passive Recon",
    "1b":      "Phase 1B — Active Recon",
    "1c":      "Phase 1C — Probing",
    "1d":      "Phase 1D — Bucketing",
    "2-eye":   "Phase 2 — Second Eye (Claude)",
    "2-score": "Phase 2 — Anomaly Scorer",
    "2-plan":  "Phase 2 — Hunt Planner (Claude)",
    "3-hunt":  "Phase 3 — Hunt Scripts",
    "final":   "Final — Episodic Memory Write",
}


# ── Pause/Resume controller ───────────────────────────────────────────────────

class RunController:
    def __init__(self):
        self._paused   = False
        self._stop     = False
        self._lock     = threading.Lock()
        signal.signal(signal.SIGINT, self._handle_sigint)

    def _handle_sigint(self, signum, frame):
        with self._lock:
            if not self._paused:
                self._paused = True
                print_warn("\nCtrl+C received — will pause at next phase boundary")
                print_info("Session state saved. Resume with: python3 run_soa.py --target <name> --resume")
            else:
                self._stop = True
                print_err("Second interrupt — aborting")
                sys.exit(1)

    def check_pause(self, target, current_phase):
        """Call at each phase boundary. Blocks if paused, returns False if should stop."""
        with self._lock:
            paused = self._paused
            stop   = self._stop

        if stop:
            return False

        if paused:
            # Save current phase so resume knows where to start
            sess = load_session(target)
            sess["paused_at_phase"] = current_phase
            save_session(target, sess)
            print_warn(f"Paused at phase boundary: {current_phase}")
            print_info("To resume: python3 run_soa.py --target <name> --resume")
            return False

        return True

    def is_paused(self):
        with self._lock:
            return self._paused


# ── Bucket fill events ────────────────────────────────────────────────────────

def emit_bucket_events(target):
    bucket_dir = os.path.join(PROJECTS_DIR, target, "phase1", "buckets")
    if not os.path.isdir(bucket_dir):
        return
    for fname in os.listdir(bucket_dir):
        if not fname.endswith(".txt"):
            continue
        fpath = os.path.join(bucket_dir, fname)
        try:
            with open(fpath) as f:
                count = sum(1 for line in f if line.strip())
        except Exception:
            count = 0
        emit("BUCKET_FILLED", {"target": target, "bucket": fname, "count": count})


# ── Phase runner ──────────────────────────────────────────────────────────────

def determine_start_phase(target, resume, force_phase):
    if force_phase:
        # Convert "2" → "2-eye", etc.
        phase_map = {
            "1": "1a", "1a": "1a", "1b": "1b", "1c": "1c", "1d": "1d",
            "2": "2-eye", "2-eye": "2-eye", "2-score": "2-score", "2-plan": "2-plan",
            "3": "3-hunt", "final": "final",
        }
        return phase_map.get(str(force_phase), "1a")

    if resume:
        sess = load_session(target)
        paused_at = sess.get("paused_at_phase")
        if paused_at and paused_at in PHASE_ORDER:
            print_info(f"Resuming from: {paused_at}")
            return paused_at
        # Fall through to last completed + 1
        last = last_completed_phase(target)
        if last and last in PHASE_ORDER:
            idx = PHASE_ORDER.index(last)
            if idx + 1 < len(PHASE_ORDER):
                next_phase = PHASE_ORDER[idx + 1]
                print_info(f"Last completed: {last} → resuming at: {next_phase}")
                return next_phase
        print_info("No previous state found — starting from 1a")

    return "1a"


def run_phase_3_hunt(target, ctrl):
    """Run hunt scripts from hunt-plan.json in parallel groups."""
    plan_path = os.path.join(PROJECTS_DIR, target, "phase2", "hunt", "hunt-plan.json")
    if not os.path.exists(plan_path):
        print_warn("hunt-plan.json not found — running all hunt stubs")
        hunt_scripts = [
            "phases/hunt/takeover.py",
            "phases/hunt/auth401.py",
            "phases/hunt/devstaging.py",
            "phases/hunt/admin_panels.py",
            "phases/hunt/config_hunt.py",
            "phases/hunt/api_hunt.py",
        ]
        pairs = [(s, ["--target", target]) for s in hunt_scripts
                 if os.path.exists(os.path.join(BASE_DIR, s))]
        run_parallel(pairs)
        return

    try:
        with open(plan_path) as f:
            plan = json.load(f)
    except Exception:
        print_err("Failed to load hunt-plan.json")
        return

    script_map = {
        "takeover":      "phases/hunt/takeover.py",
        "401":           "phases/hunt/auth401.py",
        "dev-staging":   "phases/hunt/devstaging.py",
        "admin-panels":  "phases/hunt/admin_panels.py",
        "config":        "phases/hunt/config_hunt.py",
        "api":           "phases/hunt/api_hunt.py",
        "ssrf-redirect": "phases/hunt/ssrf_hunt.py",
        "params":        "phases/hunt/xss_hunt.py",
        "js":            "phases/hunt/js_hunt.py",
        "cloud":         "phases/hunt/cloud_hunt.py",
        "cms":           "phases/hunt/cms_hunt.py",
        "interesting":   "phases/hunt/interesting_hunt.py",
        "login":         "phases/hunt/login_hunt.py",
    }

    # Process each parallel group
    for group_idx, group in enumerate(plan.get("parallel_groups", []), 1):
        if not ctrl.check_pause(target, f"3-hunt-group-{group_idx}"):
            break

        # Gather tasks in this group
        tasks_in_group = [
            t for t in plan.get("tasks", [])
            if str(t["id"]) in [str(g) for g in group]
        ]

        if not tasks_in_group:
            continue

        print_phase(f"Hunt Group {group_idx} — {len(tasks_in_group)} task(s) in parallel")

        pairs = []
        for task in tasks_in_group:
            bucket = task.get("bucket", "")
            script = script_map.get(bucket)
            if script and os.path.exists(os.path.join(BASE_DIR, script)):
                emit("HUNT_TRIGGERED", {
                    "target":  target,
                    "bucket":  bucket,
                    "script":  script,
                    "task_id": task["id"],
                })
                pairs.append((script, ["--target", target]))
            else:
                print_warn(f"No script for bucket: {bucket}")

        if pairs:
            run_parallel(pairs)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOA Master Launcher")
    parser.add_argument("--target",  required=True, help="Target name (e.g. uber)")
    parser.add_argument("--resume",  action="store_true", help="Resume from last checkpoint")
    parser.add_argument("--phase",   help="Start from specific phase (1/1a/1b/2/3/final)")
    parser.add_argument("--dry-run", action="store_true", help="Show plan without running")
    args = parser.parse_args()

    target     = args.target
    ctrl       = RunController()
    start_time = datetime.utcnow()

    if RICH:
        console.rule(f"[bold green]SOA — {target}[/bold green]")
    print_info(f"Target: {target}")
    print_info(f"Started: {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # ── Setup ─────────────────────────────────────────────────────────────────
    sess = create_session(target)
    emit("PHASE_STARTED", {"target": target, "session_id": sess.get("soa_run_id", "")})

    # Load AgentController for state tracking
    try:
        from phases.brain.agent_controller import AgentController
        agent = AgentController(
            session_id=sess.get("soa_run_id", f"{target}-run"),
            target=target,
            phase="full-run",
        )
        agent.start()
    except ImportError:
        agent = None

    # Determine where to start
    start_phase = determine_start_phase(target, args.resume, args.phase)
    start_idx   = PHASE_ORDER.index(start_phase) if start_phase in PHASE_ORDER else 0

    print_info(f"Starting at phase: {start_phase} (index {start_idx})")

    if args.dry_run:
        print_info("Dry-run mode — phases that would run:")
        for phase in PHASE_ORDER[start_idx:]:
            script, _ = PHASE_SCRIPTS.get(phase, ("(no script)", []))
            print(f"  [{phase}] {PHASE_NAMES.get(phase, phase)} → {script}")
        return

    # ── Phase 1 — Sequential ──────────────────────────────────────────────────
    for phase_id in ["1a", "1b", "1c", "1d"]:
        if PHASE_ORDER.index(phase_id) < start_idx:
            print_info(f"Skipping {phase_id} (already completed)")
            continue

        if not ctrl.check_pause(target, phase_id):
            sys.exit(0)

        print_phase(PHASE_NAMES[phase_id])
        emit("PHASE_STARTED", {"target": target, "phase": phase_id})

        script, arg_template = PHASE_SCRIPTS[phase_id]
        extra_args = [a.replace("{target}", target) for a in arg_template]
        rc, _, err = run_script(script, extra_args)

        if rc == 0:
            mark_phase_complete(target, phase_id)
            emit("PHASE_COMPLETED", {"target": target, "phase": phase_id})
            print_ok(f"{phase_id} complete")
        else:
            mark_phase_failed(target, phase_id)
            print_err(f"{phase_id} failed (rc={rc}): {err}")
            if phase_id in ("1a", "1b"):
                print_err("Critical phase failed — aborting")
                sys.exit(1)
            else:
                print_warn(f"{phase_id} failed but continuing")

    # After 1d — emit BUCKET_FILLED events
    if PHASE_ORDER.index("1d") >= start_idx:
        emit_bucket_events(target)

    # ── Phase 2 — Parallel eye + scorer, then planner ─────────────────────────
    for phase_id in ["2-eye", "2-score"]:
        if PHASE_ORDER.index(phase_id) < start_idx:
            print_info(f"Skipping {phase_id}")
            continue

        if not ctrl.check_pause(target, phase_id):
            sys.exit(0)

    # Run second_eye + anomaly_scorer in parallel
    if PHASE_ORDER.index("2-eye") >= start_idx or PHASE_ORDER.index("2-score") >= start_idx:
        print_phase("Phase 2 — Second Eye + Anomaly Scorer (parallel)")
        emit("PHASE_STARTED", {"target": target, "phase": "phase2-parallel"})

        parallel_results = run_parallel([
            ("phases/phase2/second_eye.py",    ["--target", target]),
            ("phases/phase2/anomaly_scorer.py", ["--target", target]),
        ])

        for script, rc in parallel_results.items():
            phase_tag = "2-eye" if "second_eye" in script else "2-score"
            if rc == 0:
                mark_phase_complete(target, phase_tag)
                emit("PHASE_COMPLETED", {"target": target, "phase": phase_tag})
                print_ok(f"{phase_tag} complete")
            else:
                mark_phase_failed(target, phase_tag)
                print_warn(f"{phase_tag} failed (rc={rc}) — continuing")

    # Hunt Planner
    if PHASE_ORDER.index("2-plan") >= start_idx:
        if ctrl.check_pause(target, "2-plan"):
            print_phase(PHASE_NAMES["2-plan"])
            emit("PHASE_STARTED", {"target": target, "phase": "2-plan"})
            rc, _, err = run_script("phases/phase2/hunt_planner.py", ["--target", target])
            if rc == 0:
                mark_phase_complete(target, "2-plan")
                emit("PHASE_COMPLETED", {"target": target, "phase": "2-plan"})
                print_ok("hunt-plan complete")
            else:
                print_warn(f"hunt_planner failed (rc={rc}) — continuing with default plan")

    # ── Phase 3 — Hunt scripts ────────────────────────────────────────────────
    if PHASE_ORDER.index("3-hunt") >= start_idx:
        if ctrl.check_pause(target, "3-hunt"):
            print_phase(PHASE_NAMES["3-hunt"])
            emit("PHASE_STARTED", {"target": target, "phase": "3-hunt"})
            run_phase_3_hunt(target, ctrl)
            emit("PHASE_COMPLETED", {"target": target, "phase": "3-hunt"})
            mark_phase_complete(target, "3-hunt")

    # ── FP check on all phase3 results ────────────────────────────────────────
    phase3_dir = os.path.join(PROJECTS_DIR, target, "phase3")
    passing    = run_fp_checks(target, phase3_dir)
    print_info(f"FP check: {len(passing)} result(s) passed suppression filter")

    # ── Update self-state ─────────────────────────────────────────────────────
    run_script("phases/brain/self_state_updater.py", [])

    # ── Final — episodic memory write ─────────────────────────────────────────
    if PHASE_ORDER.index("final") >= start_idx:
        if ctrl.check_pause(target, "final"):
            print_phase(PHASE_NAMES["final"])
            rc, _, _ = run_script("phases/brain/episodic_write.py", ["--target", target])
            if rc == 0:
                mark_phase_complete(target, "final")
                print_ok("Episodic memory written")
            else:
                print_warn("episodic_write failed")

    # ── Wrap up ───────────────────────────────────────────────────────────────
    duration = (datetime.utcnow() - start_time).total_seconds()
    sess = load_session(target)
    sess["session_end"]      = datetime.utcnow().strftime("%H:%M")
    sess["duration_secs"]    = int(duration)
    sess.pop("paused_at_phase", None)
    save_session(target, sess)

    emit("SESSION_ENDED", {
        "target":         target,
        "session_id":     sess.get("soa_run_id", ""),
        "duration_secs":  int(duration),
        "phases_done":    sess.get("phases_completed", []),
    })

    if agent:
        agent.complete(reason="run_soa finished")

    elapsed = f"{int(duration // 60)}m {int(duration % 60)}s"
    if RICH:
        console.rule(f"[bold green]SOA run complete — {elapsed}[/bold green]")
    else:
        print(f"\n{'='*60}\nSOA run complete — {elapsed}\n{'='*60}")

    print_info(f"Phases completed: {sess.get('phases_completed', [])}")
    print_info(f"session.json:     {session_path(target)}")


if __name__ == "__main__":
    main()
