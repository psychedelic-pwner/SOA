#!/usr/bin/env python3
"""
Son-of-Anton — Phase 1c: HTTP Probing
Single run: httpx -l puredns.txt -silent -td -sc -cl -ct -sr -ip -threads 50 -timeout 10 -j -o httpx.json
Extract:    jq -r '.url' httpx.json > live-domain.txt  (Python equivalent)
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
    parser = argparse.ArgumentParser(description="Phase 1c: HTTP Probing")
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--projectdir', default=None)
    args = parser.parse_args()

    debug_mode = args.debug

    if args.projectdir:
        project_dir = os.path.expanduser(args.projectdir)
    else:
        project_dir = auto_detect_project_dir()
        if not project_dir:
            console.print("[red]✗ Could not auto-detect project dir. Use --projectdir <path>[/red]")
            sys.exit(1)

    active_dir  = os.path.join(project_dir, "phase1", "active")
    probing_dir = os.path.join(project_dir, "phase1", "probing")
    resp_dir    = os.path.join(project_dir, "phase1", "responses")
    Path(probing_dir).mkdir(parents=True, exist_ok=True)
    Path(resp_dir).mkdir(parents=True, exist_ok=True)

    log_file   = os.path.join(probing_dir, "phase1c.log")
    error_file = os.path.join(probing_dir, "errors.log")

    puredns_file = os.path.join(active_dir, "puredns.txt")
    if not os.path.exists(puredns_file):
        console.print(f"[red]✗ puredns.txt not found: {puredns_file}[/red]")
        sys.exit(1)

    targets_file   = os.path.join(project_dir, "phase0", "phase1_targets.txt")
    target_domains = read_lines(targets_file) if os.path.exists(targets_file) else []
    target         = target_domains[0] if target_domains else "unknown"

    input_count = count_lines(puredns_file)
    log_message(log_file, f"=== Phase 1c started — {input_count} hosts ===")

    console.print(Panel(
        f"[bold white]Phase 1c — HTTP Probing[/bold white]\n"
        f"[dim]{input_count} hosts | {project_dir}[/dim]",
        box=box.DOUBLE, border_style="cyan", padding=(0, 1)
    ))

    phase_start = time.time()

    httpx_bin = find_tool('httpx')
    if not httpx_bin:
        console.print("[red]✗ httpx not found[/red]")
        log_error(error_file, "httpx", "tool not found")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # STEP 1 — httpx: full fingerprint + JSON output (single run)
    # input:  phase1/active/puredns.txt
    # output: phase1/probing/httpx.json
    # -----------------------------------------------------------------------
    console.print(Panel(
        "[bold white]Step 1 — httpx fingerprinting[/bold white]",
        box=box.DOUBLE, border_style="cyan", padding=(0, 1)
    ))

    httpx_json = os.path.join(probing_dir, "httpx.json")
    cmd = [
        httpx_bin,
        '-l', puredns_file,
        '-silent',
        '-td', '-sc', '-cl', '-ct',
        '-sr', '-srd', resp_dir,
        '-ip',
        '-threads', '50',
        '-timeout', '10',
        '-j',
        '-o', httpx_json,
    ]
    status, elapsed = run_tool(
        'httpx', cmd, httpx_json,
        timeout=3600, debug=debug_mode,
        log_file=log_file, error_file=error_file
    )
    httpx_count = count_lines(httpx_json)
    icon = "[green]✓[/green]" if status == 'success' else "[yellow]⚠[/yellow]"
    console.print(f"  {icon} {httpx_count} records ({elapsed:.1f}s)")
    log_message(log_file, f"httpx: {httpx_count} records")

    if httpx_count == 0:
        console.print("[yellow]⚠ httpx produced no output — stopping[/yellow]")
        log_message(log_file, "WARNING: httpx empty")
        sys.exit(0)

    # -----------------------------------------------------------------------
    # STEP 2 — Extract live URLs from JSON
    # equivalent: jq -r '.url' httpx.json > live-domain.txt
    # -----------------------------------------------------------------------
    console.print(Panel(
        "[bold white]Step 2 — extracting live URLs[/bold white]",
        box=box.DOUBLE, border_style="cyan", padding=(0, 1)
    ))

    live_domain_file = os.path.join(probing_dir, "live-domain.txt")
    live_urls = []
    with open(httpx_json, 'r') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                url = rec.get('url', '')
                if url:
                    live_urls.append(url)
            except json.JSONDecodeError:
                pass

    with open(live_domain_file, 'w') as fh:
        for url in live_urls:
            fh.write(url + '\n')

    live_count = len(live_urls)
    console.print(f"  [green]✓[/green] {live_count} live URLs → live-domain.txt")
    log_message(log_file, f"live URLs extracted: {live_count}")

    # -----------------------------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------------------------
    phase_elapsed = time.time() - phase_start

    summary = {
        "targets":        target_domains,
        "timestamp":      datetime.now().isoformat(),
        "input_hosts":    input_count,
        "httpx_records":  httpx_count,
        "live_urls":      live_count,
        "httpx_json":     "httpx.json",
        "live_domain":    "live-domain.txt",
    }
    with open(os.path.join(probing_dir, "probing-summary.json"), 'w') as fh:
        json.dump(summary, fh, indent=2)

    console.print(Panel(
        f"[bold white]Phase 1c complete[/bold white] — "
        f"records: {httpx_count} | live: {live_count} | {phase_elapsed:.1f}s",
        box=box.DOUBLE, border_style="cyan", padding=(0, 1)
    ))
    log_message(log_file, f"=== Phase 1c complete — {httpx_count} records, {live_count} live ===")

    notify_bin = find_tool("notify")
    if notify_bin:
        try:
            subprocess.run(
                [notify_bin, "-bulk", "-data",
                 f"Phase 1c complete — {target} — {live_count} live URLs"],
                capture_output=True, timeout=5, check=False
            )
        except Exception:
            pass

    # Chain to phase1d
    phase1d = os.path.expanduser("~/SOA/2.Execution/Pipeline/Phase.1:Recon/phase1d_bucktes.py")
    if os.path.exists(phase1d):
        console.print(Panel(
            f"[bold white]→ Phase 1d — Bucket Filtering[/bold white]\n"
            f"[dim]{live_count} live URLs | {project_dir}[/dim]",
            box=box.DOUBLE, border_style="cyan", padding=(0, 1)
        ))
        subprocess.run(["python3", phase1d, "--projectdir", project_dir])
    else:
        console.print(f"[yellow]⚠ phase1d not found at {phase1d}[/yellow]")
        console.print(f"[dim]Run: python3 {phase1d} --projectdir {project_dir}[/dim]")


if __name__ == "__main__":
    main()
