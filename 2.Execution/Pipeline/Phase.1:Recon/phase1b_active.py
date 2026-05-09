#!/usr/bin/env python3
"""
Son-of-Anton — Phase 1b: DNS Resolution
puredns resolve -q all-passive.txt -w puredns.txt
dnsx -l puredns.txt -re -a -cname -ns -j -o dnsx.json
"""

import os
import sys
import subprocess
import shutil
import argparse
import json
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich import box

console = Console()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_tool(name):
    go = os.path.expanduser(f"~/go/bin/{name}")
    if os.path.exists(go):
        return go
    return shutil.which(name)


def log_message(log_file, message):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, 'a') as fh:
        fh.write(f"[{ts}] {message}\n")


def log_error(error_file, tool_name, error_msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(error_file, 'a') as fh:
        fh.write(f"[{ts}] {tool_name}: {error_msg}\n")


def count_lines(filepath):
    try:
        with open(filepath, 'r') as fh:
            return sum(1 for line in fh if line.strip())
    except Exception:
        return 0


def read_lines(filepath):
    try:
        with open(filepath, 'r') as fh:
            return [line.strip() for line in fh if line.strip()]
    except Exception:
        return []


def run_tool(name, cmd, outfile, timeout=300, debug=False,
             log_file=None, error_file=None):
    """
    Run a subprocess with a spinner. Tool writes its own outfile via -o/-w flags.
    Returns: (status, elapsed)  status: 'success' | 'skipped'
    """
    start_time = time.time()
    Path(outfile).parent.mkdir(parents=True, exist_ok=True)

    if debug:
        console.print(f"[dim]CMD: {' '.join(str(c) for c in cmd)}[/dim]")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[bold cyan]{name}[/bold cyan]"),
            TimeElapsedColumn(),
            console=console,
            transient=False
        ) as progress:
            progress.add_task("", total=None)
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        elapsed = time.time() - start_time

        if not (os.path.exists(outfile) and os.path.getsize(outfile) > 0):
            with open(outfile, 'w') as fh:
                fh.write(proc.stdout if proc.stdout else "")

        if debug and proc.stdout:
            console.print(f"[dim]{proc.stdout[:600]}[/dim]")

        if proc.returncode != 0:
            err = f"exit {proc.returncode}: {proc.stderr[:200]}"
            if log_file:   log_message(log_file, f"{name} failed: {err}")
            if error_file: log_error(error_file, name, err)
            console.print(f"  [yellow]⚠[/yellow] {name} failed — auto-skipped")
            return 'skipped', elapsed

        if log_file:
            log_message(log_file, f"{name} done")
        return 'success', elapsed

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_time
        err = f"timeout after {timeout}s"
        if log_file:   log_message(log_file, f"{name} {err}")
        if error_file: log_error(error_file, name, err)
        console.print(f"  [yellow]⚠[/yellow] {name} timed out — skipped")
        if not os.path.exists(outfile):
            open(outfile, 'w').close()
        return 'skipped', elapsed

    except Exception as exc:
        elapsed = time.time() - start_time
        err = str(exc)
        if log_file:   log_message(log_file, f"{name} error: {err}")
        if error_file: log_error(error_file, name, err)
        console.print(f"  [red]✗[/red] {name} error: {err}")
        if not os.path.exists(outfile):
            open(outfile, 'w').close()
        return 'skipped', elapsed


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def auto_detect_project_dir():
    projects_root = os.path.expanduser("~/SOA/4.Interface/Projects")
    if not os.path.exists(projects_root):
        return None
    dirs = [d for d in Path(projects_root).iterdir() if d.is_dir()]
    if not dirs:
        return None
    dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    return str(dirs[0])


def main():
    parser = argparse.ArgumentParser(description="Phase 1b: DNS Resolution")
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('-f', '--file', default=None,
                        help='Path to all-passive.txt')
    parser.add_argument('--target', default=None, help='Target name — resolves to ~/SOA/4.Interface/Projects/<target>')
    parser.add_argument('--projectdir', default=None,
                        help='Path to project directory')
    args = parser.parse_args()

    debug_mode = args.debug

    if args.projectdir:
        project_dir = os.path.expanduser(args.projectdir)
        passive_file = os.path.join(project_dir, "phase1", "passive", "all-passive.txt")
    elif args.file:
        passive_file = os.path.expanduser(args.file)
        project_dir = str(Path(passive_file).parents[2])
    else:
        project_dir = auto_detect_project_dir()
        if not project_dir:
            console.print("[red]✗ Could not auto-detect project dir.[/red]")
            sys.exit(1)
        passive_file = os.path.join(project_dir, "phase1", "passive", "all-passive.txt")

    if not os.path.exists(passive_file):
        console.print(f"[red]✗ all-passive.txt not found: {passive_file}[/red]")
        sys.exit(1)

    outdir     = os.path.join(project_dir, "phase1", "active")
    Path(outdir).mkdir(parents=True, exist_ok=True)
    log_file   = os.path.join(outdir, "phase1b.log")
    error_file = os.path.join(outdir, "errors.log")

    targets_file   = os.path.join(project_dir, "phase0", "phase1_targets.txt")
    target_domains = read_lines(targets_file) if os.path.exists(targets_file) else []
    target         = target_domains[0] if target_domains else "unknown"

    passive_count = count_lines(passive_file)
    log_message(log_file, f"=== Phase 1b started — {passive_count} passive subs ===")

    console.print(Panel(
        f"[bold white]Phase 1b — DNS Resolution[/bold white]\n"
        f"[dim]{passive_count} passive subs | {project_dir}[/dim]",
        box=box.DOUBLE, border_style="cyan", padding=(0, 1)
    ))

    phase_start = time.time()

    # -----------------------------------------------------------------------
    # STEP 1 — PUREDNS RESOLVE
    # -----------------------------------------------------------------------
    console.print(Panel(
        "[bold white]Step 1 — puredns resolve[/bold white]",
        box=box.DOUBLE, border_style="cyan", padding=(0, 1)
    ))

    puredns_bin = find_tool('puredns')
    if not puredns_bin:
        console.print("[red]✗ puredns not found[/red]")
        log_error(error_file, "puredns", "tool not found")
        sys.exit(1)

    puredns_out = os.path.join(outdir, "puredns.txt")
    cmd = [puredns_bin, 'resolve', '-q', passive_file, '-w', puredns_out]
    status, elapsed = run_tool(
        'puredns/resolve', cmd, puredns_out,
        timeout=900, debug=debug_mode,
        log_file=log_file, error_file=error_file
    )
    puredns_count = count_lines(puredns_out)
    icon = "[green]✓[/green]" if status == 'success' else "[yellow]⚠[/yellow]"
    console.print(f"  {icon} {puredns_count} resolved ({elapsed:.1f}s)")
    log_message(log_file, f"puredns resolve: {puredns_count}")

    # -----------------------------------------------------------------------
    # STEP 2 — DNSX RECORD EXTRACTION
    # -----------------------------------------------------------------------
    console.print(Panel(
        "[bold white]Step 2 — dnsx record extraction[/bold white]",
        box=box.DOUBLE, border_style="cyan", padding=(0, 1)
    ))

    dnsx_bin = find_tool('dnsx')
    if not dnsx_bin:
        console.print("[red]✗ dnsx not found[/red]")
        log_error(error_file, "dnsx", "tool not found")
        sys.exit(1)

    dnsx_out = os.path.join(outdir, "dnsx.json")
    cmd = [
        dnsx_bin,
        '-l', puredns_out,
        '-re', '-a', '-cname', '-ns',
        '-j',
        '-o', dnsx_out,
    ]
    status, elapsed = run_tool(
        'dnsx', cmd, dnsx_out,
        timeout=600, debug=debug_mode,
        log_file=log_file, error_file=error_file
    )
    dnsx_count = count_lines(dnsx_out)
    icon = "[green]✓[/green]" if status == 'success' else "[yellow]⚠[/yellow]"
    console.print(f"  {icon} {dnsx_count} records ({elapsed:.1f}s)")
    log_message(log_file, f"dnsx records: {dnsx_count}")

    # -----------------------------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------------------------
    phase_elapsed = time.time() - phase_start

    summary = {
        "targets":          target_domains,
        "timestamp":        datetime.now().isoformat(),
        "passive_input":    passive_count,
        "puredns_resolved": puredns_count,
        "dnsx_records":     dnsx_count,
        "puredns_file":     "puredns.txt",
        "dnsx_file":        "dnsx.json",
    }
    summary_file = os.path.join(outdir, "active-summary.json")
    with open(summary_file, 'w') as fh:
        json.dump(summary, fh, indent=2)

    console.print(Panel(
        f"[bold white]Phase 1b complete[/bold white] — "
        f"puredns: {puredns_count} | dnsx: {dnsx_count} | {phase_elapsed:.1f}s",
        box=box.DOUBLE, border_style="cyan", padding=(0, 1)
    ))
    log_message(log_file, f"=== Phase 1b complete — {puredns_count} resolved, {dnsx_count} records ===")

    notify_bin = find_tool("notify")
    if notify_bin:
        try:
            subprocess.run(
                [notify_bin, "-bulk", "-data",
                 f"Phase 1b complete — {target} — {puredns_count} resolved"],
                capture_output=True, timeout=5, check=False
            )
        except Exception:
            pass

    # Chain to phase1c
    phase1c = os.path.expanduser("~/SOA/2.Execution/Pipeline/Phase.1:Recon/phase1c_probing.py")
    if os.path.exists(phase1c):
        console.print(Panel(
            f"[bold white]→ Phase 1c — HTTP Probing[/bold white]\n"
            f"[dim]{puredns_count} hosts | {project_dir}[/dim]",
            box=box.DOUBLE, border_style="cyan", padding=(0, 1)
        ))
        subprocess.run(["python3", phase1c, "--projectdir", project_dir])
    else:
        console.print(f"[yellow]⚠ phase1c not found at {phase1c}[/yellow]")
        console.print(f"[dim]Run: python3 {phase1c} --projectdir {project_dir}[/dim]")


if __name__ == "__main__":
    main()
