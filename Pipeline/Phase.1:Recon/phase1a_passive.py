#!/usr/bin/env python3
"""
Son-of-Anton — Phase 1a: Passive Subdomain Enumeration
Active stack: subfinder, github-subdomains, chaos — run simultaneously via ThreadPoolExecutor
"""

import os
import sys
import subprocess
import shutil
import argparse
import json
import time
import re
import threading
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich import box

console = Console()

_VALID_DOMAIN_RE = re.compile(r'^[a-z0-9.\-]+$')
_log_lock = threading.Lock()


# ── Helpers ──────────────────────────────────────────────────────────────────

def find_tool(name):
    go_path = os.path.expanduser(f"~/go/bin/{name}")
    if os.path.exists(go_path):
        return go_path
    return shutil.which(name)


def log_message(log_file, message):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _log_lock:
        with open(log_file, 'a') as f:
            f.write(f"[{ts}] {message}\n")


def log_error(error_file, tool_name, msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _log_lock:
        with open(error_file, 'a') as f:
            f.write(f"[{ts}] {tool_name}: {msg}\n")


def auto_detect_project_dir():
    """Return most recently modified project directory under ~/SOA/4.Interface/Projects/."""
    projects_root = os.path.expanduser("~/SOA/4.Interface/Projects")
    if not os.path.exists(projects_root):
        return None
    dirs = [d for d in Path(projects_root).iterdir() if d.is_dir()]
    if not dirs:
        return None
    dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    return str(dirs[0])


def clean_domain_file(filepath, targets, label=""):
    """
    Clean a domain output file in-place:
    - Lowercase, strip http(s):// prefixes, no spaces, max 253 chars
    - Only a-z, 0-9, hyphens, dots
    - Last label >= 2 chars
    - Must match a target domain (endswith or ==)
    Returns (before_count, after_count).
    """
    if not os.path.exists(filepath):
        return 0, 0
    with open(filepath) as f:
        lines = [l.strip().lower() for l in f if l.strip()]
    before = len(lines)
    clean = []
    for d in lines:
        if d.startswith('http://') or d.startswith('https://'):
            continue
        if ' ' in d:
            continue
        if len(d) > 253:
            continue
        if not _VALID_DOMAIN_RE.match(d):
            continue
        last_label = d.rsplit('.', 1)[-1]
        if len(last_label) < 2:
            continue
        if not any(d == t or d.endswith('.' + t) for t in targets):
            continue
        clean.append(d)
    clean = list(set(clean))
    with open(filepath, 'w') as f:
        for d in clean:
            f.write(d + '\n')
    return before, len(clean)


def load_targets(project_dir):
    """Load targets from config → phase1_targets.txt. Strips *.domain → domain."""
    config_path = os.path.join(project_dir, "phase0", "config.json")
    if not os.path.exists(config_path):
        console.print(f"[red]✗ config.json not found: {config_path}[/red]")
        sys.exit(1)
    with open(config_path) as f:
        config = json.load(f)

    targets_file = os.path.join(project_dir,
        config.get("phase1_targets", "phase0/phase1_targets.txt"))
    if not os.path.exists(targets_file):
        console.print(f"[red]✗ phase1_targets.txt not found: {targets_file}[/red]")
        sys.exit(1)

    targets = []
    with open(targets_file) as f:
        for line in f:
            t = line.strip()
            if not t or t.startswith('#'):
                continue
            if t.startswith('*.'):
                t = t[2:]
            targets.append(t)

    targets = list(set(targets))
    if not targets:
        console.print("[red]✗ No targets found[/red]")
        sys.exit(1)
    return targets, config


def write_targets_file(outdir, targets):
    """Write clean domain list for tools that accept -dL."""
    tfile = os.path.join(outdir, "targets-clean.txt")
    with open(tfile, 'w') as f:
        for t in targets:
            f.write(f"{t}\n")
    return tfile


def dedupe_file(filepath):
    """Deduplicate lines in a file in-place. Returns final line count."""
    if not os.path.exists(filepath):
        return 0
    with open(filepath) as f:
        lines = list(set(l.strip() for l in f if l.strip()))
    with open(filepath, 'w') as f:
        for l in lines:
            f.write(f"{l}\n")
    return len(lines)


def append_file(src, dst):
    """Append src contents to dst if src exists and has content."""
    if os.path.exists(src) and os.path.getsize(src) > 0:
        with open(src) as s, open(dst, 'a') as d:
            d.write(s.read())


# ── Subprocess runner (no Progress — used inside threads) ─────────────────────

def _subprocess_raw(name, cmd, outfile, timeout=300, debug=False,
                    log_file=None, error_file=None):
    """
    Run a subprocess without a Progress spinner (called from worker threads).
    Saves stdout to outfile if the tool didn't write it directly.
    Returns (ok: bool, line_count: int, elapsed: float, stderr: str).
    """
    start = time.time()
    Path(outfile).parent.mkdir(parents=True, exist_ok=True)

    if debug:
        console.print(f"[dim]  ▶ {name}: {' '.join(str(c) for c in cmd)}[/dim]")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = time.time() - start

        # Save output only if the tool didn't write the file itself
        if not (os.path.exists(outfile) and os.path.getsize(outfile) > 0):
            output = result.stdout if result.stdout.strip() else result.stderr
            with open(outfile, 'w') as f:
                f.write(output)

        with open(outfile) as f:
            line_count = sum(1 for l in f if l.strip())

        ok = result.returncode == 0 or line_count > 0
        return ok, line_count, elapsed, result.stderr

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        msg = f"timeout after {timeout}s"
        if log_file:   log_message(log_file, f"{name} {msg}")
        if error_file: log_error(error_file, name, msg)
        if not os.path.exists(outfile):
            open(outfile, 'w').close()
        return False, 0, elapsed, msg

    except Exception as e:
        elapsed = time.time() - start
        msg = str(e)
        if log_file:   log_message(log_file, f"{name} error: {msg}")
        if error_file: log_error(error_file, name, msg)
        if not os.path.exists(outfile):
            open(outfile, 'w').close()
        return False, 0, elapsed, msg


# ── Thread workers ────────────────────────────────────────────────────────────

def _run_subfinder(targets_file, sf_outfile, targets, tools, outdir,
                   progress, task_id, debug, log_file, error_file):
    """
    Thread worker: subfinder -dL targets-clean.txt -all -silent [-pc provider]
    Runs as single subprocess, cleans output, updates shared progress row.
    """
    if not tools['subfinder']:
        progress.update(task_id, total=1, completed=1,
                        description="[yellow]⚠ subfinder — not found[/yellow]")
        return {'found': 0, 'status': 'not_found', 'time': 0.0}

    progress.update(task_id, description="[cyan]subfinder[/cyan] running...")

    sf_provider = os.path.expanduser(
        "~/Library/Application Support/subfinder/provider-config.yaml")
    cmd = [tools['subfinder'], '-dL', targets_file, '-silent', '-all', '-recursive']
    if os.path.exists(sf_provider):
        cmd.extend(['-pc', sf_provider])

    ok, count, elapsed, stderr = _subprocess_raw(
        'subfinder', cmd, sf_outfile, timeout=300, debug=debug,
        log_file=log_file, error_file=error_file)

    clean_domain_file(sf_outfile, targets)
    count = sum(1 for _ in open(sf_outfile) if _.strip()) if os.path.exists(sf_outfile) else 0

    if ok:
        status = 'success'
        log_message(log_file, f"subfinder done: {count} results")
        progress.update(task_id, total=1, completed=1,
                        description=f"[green]✓ subfinder — {count}[/green]")
    else:
        status = 'skipped'
        log_error(error_file, 'subfinder', stderr[:200])
        progress.update(task_id, total=1, completed=1,
                        description=f"[yellow]⚠ subfinder — failed ({stderr[:60].strip()})[/yellow]")

    return {'found': count, 'status': status, 'time': elapsed}


def _run_github(targets, outdir, gh_outfile, github_token, tools,
                progress, task_id, debug, log_file, error_file):
    """
    Thread worker: github-subdomains via parallel -j 4 (max 4 domains at a time).
    Falls back to sequential loop if parallel is not found.
    Merges all per-domain files → github.txt, then deletes per-domain files.
    """
    if not tools['github-subdomains']:
        progress.update(task_id, total=1, completed=1,
                        description="[yellow]⚠ github-subdomains — not found[/yellow]")
        return {'found': 0, 'status': 'not_found', 'time': 0.0}

    if not github_token:
        progress.update(task_id, total=1, completed=1,
                        description="[yellow]⚠ github-subdomains — GITHUB_TOKEN not set[/yellow]")
        return {'found': 0, 'status': 'not_found', 'time': 0.0}

    parallel_bin = find_tool('parallel')
    open(gh_outfile, 'w').close()
    gh_start  = time.time()
    gh_status = 'success'

    if parallel_bin:
        progress.update(task_id,
                        description=f"[cyan]github-subdomains[/cyan] parallel -j 4 ({len(targets)} domains)...")

        # {} is parallel's per-job placeholder — expanded to each domain at runtime
        job_template = (
            f"{tools['github-subdomains']} -d {{}} -q -raw "
            f"-t $GITHUB_TOKEN -o {outdir}/github-{{}}.txt"
        )
        cmd = [parallel_bin, '--env', 'GITHUB_TOKEN', '-j', '4',
               job_template, ':::'] + list(targets)

        if debug:
            console.print(f"[dim]  ▶ {' '.join(cmd)}[/dim]")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=600,
                env=os.environ.copy()
            )
            if result.returncode != 0 and result.stderr.strip():
                log_error(error_file, 'github-subdomains/parallel', result.stderr[:200])
                gh_status = 'skipped'
        except subprocess.TimeoutExpired:
            log_error(error_file, 'github-subdomains/parallel', 'timeout after 600s')
            gh_status = 'skipped'
        except Exception as e:
            log_error(error_file, 'github-subdomains/parallel', str(e))
            gh_status = 'skipped'

    else:
        # Fallback: sequential loop (parallel not installed)
        log_message(log_file, "parallel not found — github-subdomains running sequentially")
        for idx, target in enumerate(targets, 1):
            progress.update(task_id,
                            description=f"[cyan]github-subdomains[/cyan] [{idx}/{len(targets)}] {target}")
            per_file = os.path.join(outdir, f"github-{target}.txt")
            cmd = [tools['github-subdomains'],
                   '-d', target, '-q', '-raw', '-t', github_token, '-o', per_file]
            ok, _, _, stderr = _subprocess_raw(
                f'github-subdomains/{target}', cmd, per_file,
                timeout=300, debug=debug, log_file=log_file, error_file=error_file)
            if not ok:
                gh_status = 'skipped'
                log_error(error_file, f'github-subdomains/{target}', stderr[:200])

    # Clean per-domain files and merge into github.txt
    gh_total = 0
    for target in targets:
        per_file = os.path.join(outdir, f"github-{target}.txt")
        if os.path.exists(per_file):
            clean_domain_file(per_file, [target])
            gh_total += sum(1 for _ in open(per_file) if _.strip())
            append_file(per_file, gh_outfile)

    dedupe_file(gh_outfile)

    # Delete per-domain files
    for target in targets:
        per_file = os.path.join(outdir, f"github-{target}.txt")
        try:
            os.remove(per_file)
        except Exception as e:
            log_error(error_file, 'github-subdomains-cleanup',
                      f"failed to delete {per_file}: {e}")
    console.print("[dim]✓ cleaned up github-<domain>.txt files[/dim]")

    elapsed = time.time() - gh_start

    if gh_status == 'success':
        log_message(log_file, f"github-subdomains done: {gh_total} results")
        progress.update(task_id, total=1, completed=1,
                        description=f"[green]✓ github-subdomains — {gh_total}[/green]")
    else:
        progress.update(task_id, total=1, completed=1,
                        description=f"[yellow]⚠ github-subdomains — {gh_total} (some failed)[/yellow]")

    return {'found': gh_total, 'status': gh_status, 'time': elapsed}


def _run_chaos(targets, outdir, ch_outfile, chaos_key, tools,
               progress, task_id, debug, log_file, error_file):
    """
    Thread worker: chaos -d <domain> -key KEY -silent -o chaos-<domain>.txt
    Loops per domain sequentially within this thread, merges to chaos.txt.
    """
    if not tools['chaos']:
        progress.update(task_id, total=1, completed=1,
                        description="[yellow]⚠ chaos — not found[/yellow]")
        return {'found': 0, 'status': 'not_found', 'time': 0.0}

    if not chaos_key:
        progress.update(task_id, total=1, completed=1,
                        description="[yellow]⚠ chaos — CHAOS_KEY not set[/yellow]")
        return {'found': 0, 'status': 'not_found', 'time': 0.0}

    open(ch_outfile, 'w').close()
    ch_total = 0
    ch_time  = 0.0
    ch_status = 'success'

    for idx, target in enumerate(targets, 1):
        progress.update(task_id,
                        description=f"[cyan]chaos[/cyan] [{idx}/{len(targets)}] {target}")
        per_file = os.path.join(outdir, f"chaos-{target}.txt")
        cmd = [tools['chaos'], '-d', target, '-key', chaos_key, '-silent', '-o', per_file]

        ok, count, elapsed, stderr = _subprocess_raw(
            f'chaos/{target}', cmd, per_file,
            timeout=300, debug=debug,
            log_file=log_file, error_file=error_file)

        clean_domain_file(per_file, [target])
        count = sum(1 for _ in open(per_file) if _.strip()) if os.path.exists(per_file) else 0
        ch_total += count
        ch_time  += elapsed

        if not ok and count == 0:
            ch_status = 'skipped'
            log_error(error_file, f'chaos/{target}', stderr[:200])

        append_file(per_file, ch_outfile)

    dedupe_file(ch_outfile)

    # Clean up per-domain files
    for target in targets:
        per_file = os.path.join(outdir, f"chaos-{target}.txt")
        try:
            os.remove(per_file)
        except Exception as e:
            log_error(error_file, 'chaos-cleanup', f"failed to delete {per_file}: {e}")
    console.print("[dim]✓ cleaned up chaos-<domain>.txt files[/dim]")

    if ch_status == 'success':
        log_message(log_file, f"chaos done: {ch_total} results")
        progress.update(task_id, total=1, completed=1,
                        description=f"[green]✓ chaos — {ch_total}[/green]")
    else:
        progress.update(task_id, total=1, completed=1,
                        description=f"[yellow]⚠ chaos — {ch_total} (some failed)[/yellow]")

    return {'found': ch_total, 'status': ch_status, 'time': ch_time}


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Phase 1a: Passive Subdomain Enumeration")
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('-f', '--file', default=None,
                        help='Path to project directory')
    parser.add_argument('--target', default=None, help='Target name — resolves to ~/SOA/4.Interface/Projects/<target>')
    parser.add_argument('--projectdir', default=None,
                        help='Path to project directory (alias for -f)')
    args = parser.parse_args()

    # --target is the preferred argument; --projectdir/--file kept for backward compat
    if args.target:
        raw_dir = os.path.expanduser(f"~/SOA/4.Interface/Projects/{args.target}")
    else:
        raw_dir = args.projectdir or getattr(args, "file", None)
    if raw_dir:
        project_dir = os.path.expanduser(raw_dir)
    else:
        project_dir = auto_detect_project_dir()
        if not project_dir:
            console.print("[red]✗ Could not auto-detect project dir. Use --projectdir <path>[/red]")
            sys.exit(1)
        console.print(f"[dim]Auto-detected project: {project_dir}[/dim]")

    debug_mode = args.debug

    targets, config = load_targets(project_dir)

    outdir     = os.path.join(project_dir, "phase1", "passive")
    Path(outdir).mkdir(parents=True, exist_ok=True)
    log_file   = os.path.join(outdir, "phase1a.log")
    error_file = os.path.join(outdir, "errors.log")

    log_message(log_file, f"=== Phase 1a started — {len(targets)} targets ===")
    console.print(Panel(
        f"[bold white]Phase 1a — Passive Subdomain Enumeration[/bold white]\n"
        f"[dim]{len(targets)} targets | {project_dir}[/dim]",
        box=box.DOUBLE, border_style="cyan", padding=(0, 1)
    ))

    targets_file = write_targets_file(outdir, targets)
    if debug_mode:
        console.print(f"[dim]  {', '.join(targets)}[/dim]")

    tools = {
        'subfinder':         find_tool('subfinder'),
        'github-subdomains': find_tool('github-subdomains'),
        'chaos':             find_tool('chaos'),
    }

    github_token = os.getenv('GITHUB_TOKEN')
    chaos_key    = os.getenv('CHAOS_KEY')

    if not github_token:
        console.print("[yellow]⚠ GITHUB_TOKEN not set — github-subdomains will be skipped[/yellow]")
    if not chaos_key:
        console.print("[yellow]⚠ CHAOS_KEY not set — chaos will be skipped[/yellow]")

    sf_outfile = os.path.join(outdir, "subfinder.txt")
    gh_outfile = os.path.join(outdir, "github.txt")
    ch_outfile = os.path.join(outdir, "chaos.txt")

    # ════════════════════════════════════════════════════════════════
    # PARALLEL EXECUTION — all 3 tools start simultaneously
    # ════════════════════════════════════════════════════════════════
    console.print(Panel(
        "[bold white]subfinder  ·  github-subdomains  ·  chaos[/bold white]",
        box=box.DOUBLE, border_style="cyan", padding=(0, 1)
    ))

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        sf_task = progress.add_task("[cyan]subfinder[/cyan] queued...",        total=None)
        gh_task = progress.add_task("[cyan]github-subdomains[/cyan] queued...", total=None)
        ch_task = progress.add_task("[cyan]chaos[/cyan] queued...",            total=None)

        with ThreadPoolExecutor(max_workers=3) as executor:
            sf_future = executor.submit(
                _run_subfinder,
                targets_file, sf_outfile, targets, tools, outdir,
                progress, sf_task, debug_mode, log_file, error_file
            )
            gh_future = executor.submit(
                _run_github,
                targets, outdir, gh_outfile, github_token, tools,
                progress, gh_task, debug_mode, log_file, error_file
            )
            ch_future = executor.submit(
                _run_chaos,
                targets, outdir, ch_outfile, chaos_key, tools,
                progress, ch_task, debug_mode, log_file, error_file
            )

    sf_result = sf_future.result()
    gh_result = gh_future.result()
    ch_result = ch_future.result()

    tool_results = {
        'subfinder':         sf_result,
        'github-subdomains': gh_result,
        'chaos':             ch_result,
    }

    for tname, data in tool_results.items():
        st = data['status']
        icon = "[green]✓[/green]" if st == 'success' else "[yellow]⚠[/yellow]"
        console.print(f"  {icon} {tname}: {data['found']} subdomains ({data['time']:.1f}s)")

    # ════════════════════════════════════════════════════════════════
    # MERGE ALL → all-passive.txt  (via anew)
    # ════════════════════════════════════════════════════════════════
    console.print(Panel(
        "[bold white]Merging results → all-passive.txt[/bold white]",
        box=box.DOUBLE, border_style="cyan", padding=(0, 1)
    ))
    anew_bin = find_tool('anew')

    merged_file = os.path.join(outdir, "all-passive.txt")

    # Collect all domains from the 3 tool output files (already cleaned per tool)
    all_domains = set()
    for file_path in [sf_outfile, gh_outfile, ch_outfile]:
        if os.path.exists(file_path):
            with open(file_path) as f:
                for line in f:
                    d = line.strip()
                    if d:
                        all_domains.add(d)

    if anew_bin:
        open(merged_file, 'w').close()
        input_data = '\n'.join(all_domains) + '\n' if all_domains else ''
        result = subprocess.run(
            [anew_bin, merged_file],
            input=input_data, text=True, capture_output=True
        )
        if result.returncode != 0:
            log_error(error_file, 'anew', result.stderr[:200])
    else:
        with open(merged_file, 'w') as f:
            for d in all_domains:
                f.write(f"{d}\n")
        log_message(log_file, "WARNING: anew not found — used Python dedup for merge")

    total_count = sum(1 for _ in open(merged_file) if _.strip())
    console.print(f"  [green]✓[/green] {total_count} unique subdomains → all-passive.txt")

    # ════════════════════════════════════════════════════════════════
    # SUMMARY JSON
    # ════════════════════════════════════════════════════════════════
    summary = {
        "targets":   targets,
        "timestamp": datetime.now().isoformat(),
        "total":     total_count,
        "per_tool":  {n: d['found'] for n, d in tool_results.items()},
        "file":      "all-passive.txt",
    }
    summary_file = os.path.join(outdir, "passive-summary.json")
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)

    console.print(Panel(
        f"[bold white]Phase 1a complete[/bold white] — {total_count} subdomains → all-passive.txt",
        box=box.DOUBLE, border_style="cyan", padding=(0, 1)
    ))
    log_message(log_file, f"=== Phase 1a complete — {total_count} subdomains ===")

    notify_cmd = find_tool('notify')
    if notify_cmd:
        try:
            subprocess.run(
                [notify_cmd, '-bulk', '-data',
                 f"Phase 1a complete — {len(targets)} targets — {total_count} subdomains"],
                capture_output=True, timeout=5, check=False)
        except Exception:
            pass

    # Chain to Phase 1b
    phase1b = os.path.expanduser("~/SOA/2.Execution/Pipeline/Phase.1:Recon/phase1b_active.py")
    if os.path.exists(phase1b):
        console.print(Panel(
            f"[bold white]→ Phase 1b — DNS Resolution[/bold white]\n"
            f"[dim]{total_count} subdomains | {project_dir}[/dim]",
            box=box.DOUBLE, border_style="cyan", padding=(0, 1)
        ))
        subprocess.run(["python3", phase1b, "--projectdir", project_dir])
    else:
        console.print(f"[yellow]⚠ phase1b not found at {phase1b}[/yellow]")
        console.print(f"[dim]Run: python3 {phase1b} --projectdir {project_dir}[/dim]")


if __name__ == "__main__":
    main()
