#!/usr/bin/env python3
"""
Son-of-Anton — Phase 1d: Bucket Filtering
Input:  phase1/probing/httpx.json  (NDJSON from httpx -j)

Buckets from httpx.json:
  404s.txt              — 404/410 status + subdomain takeover cname fingerprint
  internal.txt          — internal IP responses (SSRF gold)
  dev-staging.txt       — dev/staging/test/beta subdomains
  login-pages.txt       — login/signin/portal title match
  forbidden.txt         — 403/access denied title match
  unavailable.txt       — 502/503 (misconfig)
  error-pages.txt       — 500 server errors
  cloud-storage.txt     — cloud cname fingerprint (S3/Azure/GCP)
  cms.txt               — WordPress/Joomla/Drupal
  legacy.txt            — legacy/old/v1/v2 subdomains
  exposed-services.txt  — admin panels (Jenkins/Grafana/Kibana/phpMyAdmin)
  interesting.txt       — 200 OK with non-empty title

On completion: auto-launches phase2/takeover.py (subdomain takeover hunt)
"""

import os
import sys
import re
import json
import subprocess
import shutil
import argparse
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

# ─── Regex patterns ─────────────────────────────────────────────────────────

TAKEOVER_CNAME = re.compile(
    r'azurewebsites|cloudapp|trafficmanager|cloudfront|s3\.amazonaws|'
    r'elasticbeanstalk|herokudns|herokuapp|ghost\.io|surge\.sh|readme\.io|'
    r'zendesk|netlify|vercel|feedpress',
    re.IGNORECASE
)
CLOUD_CNAME = re.compile(
    r's3|amazonaws|azure|blob|cloudapp|googleapis',
    re.IGNORECASE
)
INTERNAL_IP = re.compile(
    r'^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\.'
)
DEV_STAGING = re.compile(
    r'(^|//)dev\.|staging\.|old\.|beta\.|test\.|sandbox\.|qa\.|uat\.|build\.|ci\.',
    re.IGNORECASE
)
LEGACY_URL = re.compile(
    r'(^|//)legacy\.|v1\.|v2\.|old\.|archive\.',
    re.IGNORECASE
)
LOGIN_TITLE = re.compile(
    r'login|signin|sign in|portal|dashboard',
    re.IGNORECASE
)
FORBIDDEN_TITLE = re.compile(
    r'forbidden|access denied|unauthorized',
    re.IGNORECASE
)
ADMIN_TITLE = re.compile(
    r'jenkins|grafana|kibana|phpmyadmin|adminer|admin',
    re.IGNORECASE
)
CMS_TECH = re.compile(
    r'WordPress|Joomla|Drupal',
    re.IGNORECASE
)
# ─── Helpers ────────────────────────────────────────────────────────────────

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


def write_lines(filepath, lines):
    with open(filepath, 'w') as fh:
        for line in sorted(set(lines)):
            fh.write(line + '\n')


def auto_detect_project_dir():
    projects_root = os.path.expanduser("~/SOA/4.Interface/Projects")
    if not os.path.exists(projects_root):
        return None
    dirs = [d for d in Path(projects_root).iterdir() if d.is_dir()]
    if not dirs:
        return None
    dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    return str(dirs[0])


def get_cname(record):
    """Return cname as a single string regardless of httpx version (str or list)."""
    cname = record.get('cname')
    if not cname:
        return ''
    if isinstance(cname, list):
        return ' '.join(str(c) for c in cname)
    return str(cname)


def get_technologies(record):
    """Return technologies list (handles 'tech' vs 'technologies' key)."""
    tech = record.get('technologies') or record.get('tech') or []
    if isinstance(tech, str):
        return [tech]
    return list(tech)


def load_ndjson(filepath):
    """Load newline-delimited JSON file into list of dicts."""
    records = []
    with open(filepath, 'r') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return records


# ─── Bucket filtering from httpx.json ───────────────────────────────────────

def filter_buckets(records):
    """
    Single-pass classification of httpx.json records into all buckets.
    Returns dict of bucket_name → list of URLs.
    """
    buckets = {
        '404s':              [],
        '401':               [],
        'internal':          [],
        'dev-staging':       [],
        'login-pages':       [],
        'forbidden':         [],
        'unavailable':       [],
        'error-pages':       [],
        'cloud-storage':     [],
        'cms':               [],
        'legacy':            [],
        'exposed-services':  [],
        'interesting':       [],
    }

    for rec in records:
        url    = rec.get('url', '')
        status = rec.get('status_code', 0)
        title  = rec.get('title', '') or ''
        ip     = rec.get('ip', '') or ''
        cname  = get_cname(rec)
        techs  = get_technologies(rec)

        if not url:
            continue

        # 404s — subdomain takeover candidates (404 and 410 only)
        if status in (404, 410):
            buckets['404s'].append(url)
        if cname and TAKEOVER_CNAME.search(cname):
            if url not in buckets['404s']:
                buckets['404s'].append(url)

        # 401 — auth-protected / unauthorised (separate bucket)
        if status == 401:
            buckets['401'].append(url)

        # Internal IPs — SSRF gold
        if ip and INTERNAL_IP.match(ip):
            buckets['internal'].append(url)

        # Dev / staging / test
        if DEV_STAGING.search(url):
            buckets['dev-staging'].append(url)

        # Login pages
        if title and LOGIN_TITLE.search(title):
            buckets['login-pages'].append(url)

        # Forbidden / access denied
        if status == 403 or (title and FORBIDDEN_TITLE.search(title)):
            buckets['forbidden'].append(url)

        # Service unavailable — misconfig
        if status in (502, 503):
            buckets['unavailable'].append(url)

        # Server errors
        if status == 500:
            buckets['error-pages'].append(url)

        # Cloud storage
        if cname and CLOUD_CNAME.search(cname):
            buckets['cloud-storage'].append(url)

        # CMS
        if techs and any(CMS_TECH.search(t) for t in techs):
            buckets['cms'].append(url)

        # Legacy / old versions
        if LEGACY_URL.search(url):
            buckets['legacy'].append(url)

        # Exposed admin panels / services
        if title and ADMIN_TITLE.search(title):
            buckets['exposed-services'].append(url)

        # Interesting — 200 OK with real content
        if status == 200 and title and title.strip():
            buckets['interesting'].append(url)

    return buckets


# ─── MAIN ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Phase 1d: Bucket Filtering")
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--projectdir', default=None)
    parser.add_argument('--skip-phase2', action='store_true',
                        help='Do not auto-launch takeover.py after completion')
    args = parser.parse_args()

    if args.projectdir:
        project_dir = os.path.expanduser(args.projectdir)
    else:
        project_dir = auto_detect_project_dir()
        if not project_dir:
            console.print("[red]✗ Could not auto-detect project dir. Use --projectdir <path>[/red]")
            sys.exit(1)

    probing_dir = os.path.join(project_dir, "phase1", "probing")
    buckets_dir = os.path.join(project_dir, "phase1", "buckets")
    Path(buckets_dir).mkdir(parents=True, exist_ok=True)

    log_file   = os.path.join(buckets_dir, "phase1d.log")

    httpx_json = os.path.join(probing_dir, "httpx.json")

    if not os.path.exists(httpx_json):
        console.print(f"[red]✗ httpx.json not found: {httpx_json}[/red]")
        sys.exit(1)

    targets_file   = os.path.join(project_dir, "phase0", "phase1_targets.txt")
    target_domains = read_lines(targets_file) if os.path.exists(targets_file) else []
    target         = target_domains[0] if target_domains else "unknown"

    record_count = count_lines(httpx_json)
    log_message(log_file, f"=== Phase 1d started — {record_count} records ===")

    console.print(Panel(
        f"[bold white]Phase 1d — Bucket Filtering[/bold white]\n"
        f"[dim]{record_count} records | {project_dir}[/dim]",
        box=box.DOUBLE, border_style="cyan", padding=(0, 1)
    ))

    phase_start = time.time()

    # ─── STEP 1: Load + classify httpx.json ──────────────────────────────────
    console.print(Panel(
        "[bold white]Step 1 — classifying httpx.json[/bold white]",
        box=box.DOUBLE, border_style="cyan", padding=(0, 1)
    ))

    records = load_ndjson(httpx_json)
    buckets = filter_buckets(records)

    bucket_counts = {}
    for bucket_name, urls in buckets.items():
        outfile = os.path.join(buckets_dir, f"{bucket_name}.txt")
        write_lines(outfile, urls)
        bucket_counts[bucket_name] = len(urls)
        icon = "[green]✓[/green]" if urls else "[dim]—[/dim]"
        console.print(f"  {icon} {bucket_name}.txt — {len(urls)}")

    log_message(log_file, f"bucket filtering done: {sum(bucket_counts.values())} total entries")

    # ─── SUMMARY ─────────────────────────────────────────────────────────────
    phase_elapsed = time.time() - phase_start

    summary = {
        "targets":    target_domains,
        "timestamp":  datetime.now().isoformat(),
        "input":      record_count,
        "buckets":    bucket_counts,
    }
    with open(os.path.join(buckets_dir, "bucket-summary.json"), 'w') as fh:
        json.dump(summary, fh, indent=2)

    tbl = Table(box=box.SIMPLE, show_header=True)
    tbl.add_column("Bucket", style="cyan")
    tbl.add_column("Entries", justify="right", style="white")
    for bname, cnt in sorted(bucket_counts.items(), key=lambda x: -x[1]):
        icon = "[green]●[/green]" if cnt > 0 else "[dim]○[/dim]"
        tbl.add_row(f"{icon} {bname}", str(cnt))
    console.print(tbl)

    console.print(Panel(
        f"[bold white]Phase 1d complete[/bold white] — "
        f"{len(bucket_counts)} buckets | {sum(bucket_counts.values())} total entries | {phase_elapsed:.1f}s",
        box=box.DOUBLE, border_style="cyan", padding=(0, 1)
    ))
    log_message(log_file, f"=== Phase 1d complete — {sum(bucket_counts.values())} entries ===")

    notify_bin = find_tool("notify")
    if notify_bin:
        try:
            subprocess.run(
                [notify_bin, "-bulk", "-data",
                 f"Phase 1d complete — {target} — {sum(bucket_counts.values())} bucket entries"],
                capture_output=True, timeout=5, check=False
            )
        except Exception:
            pass

    # ─── AUTO-LAUNCH PHASE 2: takeover hunt ──────────────────────────────────
    if args.skip_phase2:
        console.print("  [dim]Phase 2 skipped (--skip-phase2)[/dim]")
        return

    takeover_script = os.path.expanduser('~/SOA/1.Core/Agents/Hunters/takeover.py')
    if not os.path.exists(takeover_script):
        console.print(f"[yellow]⚠ takeover.py not found: {takeover_script}[/yellow]")
        return

    fourohfour = os.path.join(buckets_dir, "404s.txt")
    if not os.path.exists(fourohfour) or os.path.getsize(fourohfour) == 0:
        console.print("[yellow]⚠ 404s.txt is empty — skipping phase 2[/yellow]")
        return

    console.print(Panel(
        "[bold white]Phase 2 — Subdomain Takeover Hunt[/bold white]\n"
        f"[dim]launching takeover.py → {project_dir}[/dim]",
        box=box.DOUBLE, border_style="red", padding=(0, 1)
    ))
    log_message(log_file, "=== launching phase2/takeover.py ===")

    try:
        subprocess.run(
            [sys.executable, takeover_script, '--projectdir', project_dir]
            + (['--debug'] if args.debug else []),
            check=False
        )
    except Exception as e:
        console.print(f"[red]✗ failed to launch takeover.py: {e}[/red]")
        log_message(log_file, f"ERROR launching takeover.py: {e}")


if __name__ == "__main__":
    main()
