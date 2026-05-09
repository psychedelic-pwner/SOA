#!/usr/bin/env python3
"""
SOA — Phase 2 Intel: JavaScript Analysis
Source: claude desktop recommendation + son-of-anton js hunter (extended)

Statically extracts from JS files stored in phase1/responses/:
  - Endpoints and API paths  (linkfinder)
  - Secrets / credentials    (secretfinder, trufflehog)
  - Hidden parameters        (linkfinder regex patterns)
  - Internal subdomains

Feeds discovered endpoints BACK into phase1/buckets/:
  - api-endpoints.txt  ← new endpoints found
  - params.txt / parameterized-urls.txt  ← new parameter-bearing URLs

This is DIFFERENT from Hunters/js_hunt.py (which scans LIVE JS files with
nuclei). This phase runs OFFLINE on stored response content before hunting.

Input:
  ~/SOA/4.Interface/Projects/<target>/phase1/buckets/js-files.txt  (live JS URLs)
  ~/SOA/4.Interface/Projects/<target>/phase1/responses/            (stored content)

Output:
  ~/SOA/4.Interface/Projects/<target>/phase2/js/js-endpoints.json
  ~/SOA/4.Interface/Projects/<target>/phase2/js/js-secrets.json
  ~/SOA/4.Interface/Projects/<target>/phase1/buckets/api-endpoints.txt  (appended)

Usage:
  python3 js_analysis.py --target uber [--debug]
  python3 js_analysis.py --projectdir ~/SOA/4.Interface/Projects/uber
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

PROJECTS_DIR = os.path.expanduser("~/SOA/4.Interface/Projects")


def find_tool(name):
    go = os.path.expanduser(f"~/go/bin/{name}")
    if os.path.exists(go): return go
    return shutil.which(name)


def print_ok(msg):
    if RICH: console.print(f"[green]✓[/green] {msg}")
    else: print(f"✓ {msg}")

def print_err(msg):
    if RICH: console.print(f"[red]✗[/red] {msg}")
    else: print(f"✗ {msg}", file=sys.stderr)

def print_info(msg):
    if RICH: console.print(f"[cyan]→[/cyan] {msg}")
    else: print(f"→ {msg}")

def print_warn(msg):
    if RICH: console.print(f"[yellow]⚠[/yellow]  {msg}")
    else: print(f"⚠  {msg}")


# ── Endpoint extraction patterns ──────────────────────────────────────────────

# Common JS endpoint patterns (subset of what linkfinder does in Python)
_ENDPOINT_RE = re.compile(
    r'(?:"|\'|`)(/(?:api|v[0-9]+|rest|graphql|admin|internal|auth|oauth|user|account|data)[^\s"\'`<>]*)',
    re.IGNORECASE
)
_PARAM_URL_RE = re.compile(
    r'(?:"|\'|`)(https?://[^"\'`\s]+\?[^"\'`\s]+)',
    re.IGNORECASE
)
_SECRET_RE = re.compile(
    r'(?:api[_-]?key|secret|token|password|passwd|pwd|auth|bearer|private[_-]?key'
    r'|access[_-]?key|client[_-]?secret)["\s:=]+(["\']?)([A-Za-z0-9_\-\.\/+]{16,})\1',
    re.IGNORECASE
)
_INTERNAL_SUBDOMAIN_RE = re.compile(
    r'(?:"|\'|`)((?:[a-z0-9\-]+\.)+(?:internal|corp|local|dev|staging|stg|prod|[a-z]{2,}))',
    re.IGNORECASE
)


def extract_from_content(content: str, source_url: str) -> dict:
    """Run all extraction patterns on JS content string."""
    endpoints = list(set(m.group(1) for m in _ENDPOINT_RE.finditer(content)))
    param_urls = list(set(m.group(1) for m in _PARAM_URL_RE.finditer(content)))
    secrets = []
    for m in _SECRET_RE.finditer(content):
        key_type = m.group(0).split('=')[0].split(':')[0].strip().strip('"\'')
        secrets.append({
            "key_type": key_type,
            "value_preview": m.group(2)[:8] + "..." if len(m.group(2)) > 8 else m.group(2),
            "source": source_url,
        })
    subdomains = list(set(m.group(1) for m in _INTERNAL_SUBDOMAIN_RE.finditer(content)))

    return {
        "source": source_url,
        "endpoints": endpoints[:100],
        "param_urls": param_urls[:50],
        "secrets": secrets[:20],
        "subdomains": subdomains[:30],
    }


def run_linkfinder(js_url_file: str, out_dir: str, debug=False) -> list[str]:
    """
    Run linkfinder against a list of JS URLs.
    Returns list of discovered endpoint strings.
    Source: linkfinder tool (darkmatter7/LinkFinder).
    """
    linkfinder = find_tool("linkfinder") or find_tool("python3")
    linkfinder_script = os.path.expanduser("~/go/bin/linkfinder") or shutil.which("linkfinder")

    # Try system linkfinder binary
    lf = find_tool("linkfinder")
    if not lf:
        if debug: print_info("linkfinder not found — using regex-only extraction")
        return []

    endpoints = []
    out_file = os.path.join(out_dir, "linkfinder-raw.txt")

    try:
        result = subprocess.run(
            [lf, "-i", js_url_file, "-o", "cli"],
            capture_output=True, text=True, timeout=300
        )
        with open(out_file, "w") as f:
            f.write(result.stdout)
        endpoints = [
            line.strip() for line in result.stdout.splitlines()
            if line.strip() and line.startswith("/")
        ]
        print_ok(f"linkfinder: {len(endpoints)} endpoints")
    except subprocess.TimeoutExpired:
        print_warn("linkfinder timed out")
    except Exception as e:
        if debug: print_warn(f"linkfinder error: {e}")

    return endpoints


def run_secretfinder(js_url_file: str, out_dir: str, debug=False) -> list[dict]:
    """
    Run secretfinder against a list of JS URLs.
    Returns list of secret dicts.
    Source: m4ll0k/SecretFinder.
    """
    sf = find_tool("secretfinder")
    if not sf:
        if debug: print_info("secretfinder not found — using regex-only extraction")
        return []

    secrets = []
    out_file = os.path.join(out_dir, "secretfinder-raw.json")

    try:
        with open(js_url_file) as f:
            urls = [l.strip() for l in f if l.strip()]

        all_output = []
        for url in urls[:50]:  # cap at 50 URLs to avoid rate limiting
            try:
                result = subprocess.run(
                    [sf, "-i", url, "-o", "cli"],
                    capture_output=True, text=True, timeout=60
                )
                if result.stdout.strip():
                    all_output.append({"url": url, "output": result.stdout[:500]})
            except Exception:
                continue

        with open(out_file, "w") as f:
            json.dump(all_output, f, indent=2)

        for item in all_output:
            if item.get("output"):
                secrets.append({
                    "source": item["url"],
                    "output_preview": item["output"][:200],
                })
        print_ok(f"secretfinder: {len(secrets)} hits")
    except Exception as e:
        if debug: print_warn(f"secretfinder error: {e}")

    return secrets


def regex_extract_from_responses(responses_dir: str, debug=False) -> dict:
    """
    Regex-based extraction from stored HTTP response files.
    Returns aggregated endpoints, param_urls, secrets, subdomains.
    """
    all_endpoints = set()
    all_param_urls = set()
    all_secrets = []
    all_subdomains = set()

    if not os.path.isdir(responses_dir):
        return {"endpoints": [], "param_urls": [], "secrets": [], "subdomains": []}

    js_files = [f for f in Path(responses_dir).rglob("*.js")]
    if not js_files:
        # Also scan .txt response dumps
        js_files = [f for f in Path(responses_dir).rglob("*") if f.suffix in (".txt", ".html")]

    for fpath in js_files[:200]:  # cap at 200 files
        try:
            content = fpath.read_text(errors="ignore")[:500_000]  # 500KB cap per file
            result = extract_from_content(content, str(fpath))
            all_endpoints.update(result["endpoints"])
            all_param_urls.update(result["param_urls"])
            all_secrets.extend(result["secrets"])
            all_subdomains.update(result["subdomains"])
        except Exception:
            continue

    if debug:
        print_info(f"regex: {len(all_endpoints)} endpoints, {len(all_secrets)} secrets from {len(js_files)} files")

    return {
        "endpoints": list(all_endpoints)[:500],
        "param_urls": list(all_param_urls)[:200],
        "secrets": all_secrets[:100],
        "subdomains": list(all_subdomains)[:100],
    }


def update_bucket(bucket_path: str, new_urls: list[str]) -> int:
    """Append new unique entries to a bucket file. Returns count added."""
    existing = set()
    if os.path.exists(bucket_path):
        with open(bucket_path) as f:
            existing = {l.strip() for l in f if l.strip()}

    new_entries = [u for u in new_urls if u and u not in existing]
    if new_entries:
        os.makedirs(os.path.dirname(bucket_path), exist_ok=True)
        with open(bucket_path, "a") as f:
            for entry in new_entries:
                f.write(entry + "\n")
    return len(new_entries)


def main():
    parser = argparse.ArgumentParser(description="SOA Phase 2 Intel: JS Analysis")
    parser.add_argument("--target",     default=None, help="Target name")
    parser.add_argument("--projectdir", default=None, help="Path to project directory")
    parser.add_argument("--debug",      action="store_true")
    args = parser.parse_args()

    if args.target:
        project_dir = os.path.join(PROJECTS_DIR, args.target)
    elif args.projectdir:
        project_dir = os.path.expanduser(args.projectdir)
    else:
        # Auto-detect most recently modified project
        if os.path.isdir(PROJECTS_DIR):
            dirs = sorted(Path(PROJECTS_DIR).iterdir(), key=lambda d: d.stat().st_mtime, reverse=True)
            project_dir = str(dirs[0]) if dirs else None
        if not project_dir:
            print_err("No target or projectdir specified")
            sys.exit(1)
        print_info(f"Auto-detected: {project_dir}")

    if not os.path.isdir(project_dir):
        print_err(f"Project directory not found: {project_dir}")
        sys.exit(1)

    target   = os.path.basename(project_dir)
    out_dir  = os.path.join(project_dir, "phase2", "js")
    os.makedirs(out_dir, exist_ok=True)

    js_bucket    = os.path.join(project_dir, "phase1", "buckets", "js-files.txt")
    responses_dir = os.path.join(project_dir, "phase1", "responses")

    print_info(f"Target: {target}")

    if RICH:
        console.print(Panel(
            f"[bold white]Phase 2 — JS Analysis[/bold white]\n[dim]{project_dir}[/dim]",
            box=box.DOUBLE, border_style="cyan", padding=(0, 1)
        ))

    # ── 1. linkfinder on live JS URLs ──────────────────────────────────────────
    lf_endpoints = []
    if os.path.exists(js_bucket):
        js_count = sum(1 for _ in open(js_bucket) if _.strip())
        print_info(f"JS bucket: {js_count} URLs")
        lf_endpoints = run_linkfinder(js_bucket, out_dir, debug=args.debug)
    else:
        print_warn("js-files.txt bucket not found — skipping linkfinder")

    # ── 2. secretfinder on live JS URLs ───────────────────────────────────────
    sf_secrets = []
    if os.path.exists(js_bucket):
        sf_secrets = run_secretfinder(js_bucket, out_dir, debug=args.debug)

    # ── 3. Regex extraction from stored responses ──────────────────────────────
    print_info(f"Scanning responses dir: {responses_dir}")
    regex_result = regex_extract_from_responses(responses_dir, debug=args.debug)

    # ── 4. Merge results ───────────────────────────────────────────────────────
    all_endpoints = list(set(lf_endpoints + regex_result["endpoints"]))
    all_param_urls = regex_result["param_urls"]
    all_secrets = sf_secrets + regex_result["secrets"]
    all_subdomains = regex_result["subdomains"]

    # Write endpoints JSON
    endpoints_out = {
        "target":    target,
        "generated": datetime.utcnow().isoformat() + "Z",
        "endpoints": all_endpoints,
        "param_urls": all_param_urls,
        "subdomains": all_subdomains,
        "total":     len(all_endpoints),
    }
    with open(os.path.join(out_dir, "js-endpoints.json"), "w") as f:
        json.dump(endpoints_out, f, indent=2)
    print_ok(f"js-endpoints.json → {len(all_endpoints)} endpoints")

    # Write secrets JSON
    secrets_out = {
        "target":    target,
        "generated": datetime.utcnow().isoformat() + "Z",
        "secrets":   all_secrets,
        "total":     len(all_secrets),
    }
    with open(os.path.join(out_dir, "js-secrets.json"), "w") as f:
        json.dump(secrets_out, f, indent=2)
    print_ok(f"js-secrets.json → {len(all_secrets)} secrets")

    # ── 5. Feed back into buckets ──────────────────────────────────────────────
    buckets_dir = os.path.join(project_dir, "phase1", "buckets")

    # API endpoints that look like actual API paths → api-endpoints.txt
    api_endpoints = [e for e in all_endpoints
                     if any(k in e.lower() for k in ("/api/", "/v1/", "/v2/", "/graphql", "/rest/"))]
    added_api = update_bucket(
        os.path.join(buckets_dir, "api-endpoints.txt"), api_endpoints
    )
    if added_api:
        print_ok(f"api-endpoints.txt ← +{added_api} new API paths")

    # Parameterized URLs → parameterized-urls.txt
    added_params = update_bucket(
        os.path.join(buckets_dir, "parameterized-urls.txt"), all_param_urls
    )
    if added_params:
        print_ok(f"parameterized-urls.txt ← +{added_params} new param URLs")

    # Internal subdomains found → passive/internal-from-js.txt (not a bucket, but useful)
    if all_subdomains:
        with open(os.path.join(project_dir, "phase1", "passive", "internal-from-js.txt"), "w") as f:
            f.write("\n".join(all_subdomains))
        print_ok(f"internal-from-js.txt ← {len(all_subdomains)} subdomains")

    # Print summary
    if RICH:
        tbl = Table(title="JS Analysis Summary", box=box.SIMPLE_HEAD)
        tbl.add_column("Category", style="cyan")
        tbl.add_column("Count", justify="right", style="white")
        tbl.add_row("Endpoints extracted",  str(len(all_endpoints)))
        tbl.add_row("Param URLs",           str(len(all_param_urls)))
        tbl.add_row("Secrets detected",     str(len(all_secrets)))
        tbl.add_row("Internal subdomains",  str(len(all_subdomains)))
        tbl.add_row("→ api-endpoints.txt",  f"+{added_api}")
        tbl.add_row("→ parameterized-urls", f"+{added_params}")
        console.print(tbl)
    else:
        print(f"\nJS Analysis: {len(all_endpoints)} endpoints, "
              f"{len(all_secrets)} secrets, {len(all_subdomains)} subdomains")


if __name__ == "__main__":
    main()
