#!/usr/bin/env python3
"""
SOA — Phase 2 Intel: Secret & Credential Hunt
Source: claude desktop recommendation (genuinely new — partially overlaps
with js_hunt.py but operates on stored content, not live scanning)

Runs trufflehog/gitleaks on:
  1. Stored HTTP responses (phase1/responses/)
  2. Dev-staging hosts (phase1/buckets/dev-staging.txt) — tries to clone
     /.git or check for exposed git repos
  3. Config exposure bucket (phase1/buckets/config-exposure.txt)

Produces secrets.json with all found credentials for manual review.
High-confidence secrets are flagged as FINDING in soa.db.

This is DIFFERENT from Hunters/config_hunt.py (which runs nuclei against
live config endpoints) and js_hunt.py (which runs nuclei on live JS).
This script scans STORED content offline with secret-detection tools.

Input:
  ~/SOA/4.Interface/Projects/<target>/phase1/responses/  (stored HTTP content)
  ~/SOA/4.Interface/Projects/<target>/phase1/buckets/dev-staging.txt
  ~/SOA/4.Interface/Projects/<target>/phase1/buckets/config-exposure.txt

Output:
  ~/SOA/4.Interface/Projects/<target>/phase2/intel/secrets.json
  ~/SOA/4.Interface/Projects/<target>/phase2/intel/git-exposure.json

Usage:
  python3 secret_hunt.py --target uber [--debug]
  python3 secret_hunt.py --projectdir ~/SOA/4.Interface/Projects/uber
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
    from rich.table import Table
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

PROJECTS_DIR = os.path.expanduser("~/SOA/4.Interface/Projects")
MEMORY_DIR   = os.path.expanduser("~/SOA/1.Core/Memory")


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


# ── Regex-based secret detection (no external tool needed) ────────────────────

_SECRET_PATTERNS = [
    ("aws_access_key",      re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret",          re.compile(r"(?:aws[_-]?secret|secret[_-]?access[_-]?key)[\"'\s:=]+([A-Za-z0-9/+=]{40})", re.IGNORECASE)),
    ("github_token",        re.compile(r"ghp_[A-Za-z0-9_]{36}|github[_-]?token[\"'\s:=]+([A-Za-z0-9_]{40})", re.IGNORECASE)),
    ("google_api_key",      re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("jwt_token",           re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")),
    ("generic_api_key",     re.compile(r"(?:api[_-]?key|apikey)[\"'\s:=]+([\"']?)([A-Za-z0-9_\-]{20,})\1", re.IGNORECASE)),
    ("generic_secret",      re.compile(r"(?:secret|password|passwd)[\"'\s:=]+([\"']?)([A-Za-z0-9_@!#$%^&*\-\.]{8,})\1", re.IGNORECASE)),
    ("private_key",         re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
    ("slack_token",         re.compile(r"xox[baprs]-[A-Za-z0-9\-]+")),
    ("stripe_key",          re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}")),
    ("sendgrid_key",        re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}")),
]


def regex_scan_file(filepath: str) -> list[dict]:
    """Scan a single file for secrets using regex patterns."""
    findings = []
    try:
        content = Path(filepath).read_text(errors="ignore")[:1_000_000]  # 1MB cap
    except Exception:
        return []

    for pattern_name, pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(content):
            # Get line number
            line_no = content[:m.start()].count("\n") + 1
            value = m.group(0)
            # Redact most of the value for safety
            if len(value) > 12:
                redacted = value[:6] + "..." + value[-4:]
            else:
                redacted = value[:4] + "..."

            findings.append({
                "file":    os.path.relpath(filepath),
                "line":    line_no,
                "type":    pattern_name,
                "preview": redacted,
                "length":  len(value),
            })

    return findings


def run_trufflehog(scan_dir: str, out_dir: str, debug=False) -> list[dict]:
    """
    Run trufflehog filesystem scan on a directory.
    Returns list of finding dicts.
    """
    trufflehog = find_tool("trufflehog")
    if not trufflehog:
        if debug: print_info("trufflehog not found — using regex-only scan")
        return []

    out_file = os.path.join(out_dir, "trufflehog-raw.json")
    findings = []

    try:
        result = subprocess.run(
            [trufflehog, "filesystem", "--directory", scan_dir,
             "--json", "--no-update"],
            capture_output=True, text=True, timeout=300
        )
        output = result.stdout.strip()
        if output:
            with open(out_file, "w") as f:
                f.write(output)
            for line in output.splitlines():
                try:
                    obj = json.loads(line)
                    findings.append({
                        "tool":         "trufflehog",
                        "detector":     obj.get("DetectorName", "?"),
                        "verified":     obj.get("Verified", False),
                        "file":         obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "?"),
                        "raw_preview":  (obj.get("Raw", "") or "")[:20] + "...",
                    })
                except Exception:
                    continue
        print_ok(f"trufflehog: {len(findings)} finding(s)")
    except subprocess.TimeoutExpired:
        print_warn("trufflehog timed out")
    except Exception as e:
        if debug: print_warn(f"trufflehog error: {e}")

    return findings


def run_gitleaks(scan_dir: str, out_dir: str, debug=False) -> list[dict]:
    """
    Run gitleaks detect on a directory.
    Returns list of finding dicts.
    """
    gitleaks = find_tool("gitleaks")
    if not gitleaks:
        if debug: print_info("gitleaks not found — skipping")
        return []

    out_file = os.path.join(out_dir, "gitleaks-raw.json")
    findings = []

    try:
        result = subprocess.run(
            [gitleaks, "detect", "--source", scan_dir,
             "--report-format", "json", "--report-path", out_file,
             "--no-banner", "--exit-code", "0"],
            capture_output=True, text=True, timeout=300
        )
        if os.path.exists(out_file):
            with open(out_file) as f:
                data = json.load(f)
            for item in (data if isinstance(data, list) else []):
                findings.append({
                    "tool":     "gitleaks",
                    "rule_id":  item.get("RuleID", "?"),
                    "file":     item.get("File", "?"),
                    "line":     item.get("StartLine", 0),
                    "preview":  (item.get("Secret", "") or "")[:10] + "...",
                    "commit":   item.get("Commit", ""),
                })
        print_ok(f"gitleaks: {len(findings)} finding(s)")
    except subprocess.TimeoutExpired:
        print_warn("gitleaks timed out")
    except Exception as e:
        if debug: print_warn(f"gitleaks error: {e}")

    return findings


def check_git_exposure(urls: list[str], out_dir: str, debug=False) -> list[dict]:
    """
    Check URLs in dev-staging bucket for exposed .git directories.
    Tests /.git/HEAD, /.git/config, /.git/COMMIT_EDITMSG.
    Returns list of exposed hosts.
    """
    import urllib.request

    exposed = []
    git_paths = ["/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG"]

    for url in urls[:50]:  # cap at 50
        url = url.strip()
        if not url: continue
        if not url.startswith("http"):
            url = "https://" + url

        for gpath in git_paths:
            test_url = url.rstrip("/") + gpath
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "SOA-SecretHunt/1.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    content = resp.read(1000).decode(errors="ignore")
                    if resp.status == 200 and ("ref:" in content or "[core]" in content or "commit" in content.lower()):
                        exposed.append({
                            "url":         test_url,
                            "host":        url,
                            "path":        gpath,
                            "indicator":   content[:100].strip(),
                            "severity":    "HIGH",
                        })
                        print_warn(f"GIT EXPOSED: {test_url}")
                        break  # one hit per host is enough
            except Exception:
                continue

    if exposed:
        with open(os.path.join(out_dir, "git-exposure.json"), "w") as f:
            json.dump({"exposed": exposed, "total": len(exposed)}, f, indent=2)

    return exposed


def main():
    parser = argparse.ArgumentParser(description="SOA Phase 2 Intel: Secret Hunt")
    parser.add_argument("--target",     default=None)
    parser.add_argument("--projectdir", default=None)
    parser.add_argument("--debug",      action="store_true")
    parser.add_argument("--skip-git",   action="store_true", help="Skip .git exposure check")
    args = parser.parse_args()

    if args.target:
        project_dir = os.path.join(PROJECTS_DIR, args.target)
    elif args.projectdir:
        project_dir = os.path.expanduser(args.projectdir)
    else:
        if os.path.isdir(PROJECTS_DIR):
            dirs = sorted(Path(PROJECTS_DIR).iterdir(), key=lambda d: d.stat().st_mtime, reverse=True)
            project_dir = str(dirs[0]) if dirs else None
        if not project_dir:
            print_err("No target specified")
            sys.exit(1)

    if not os.path.isdir(project_dir):
        print_err(f"Project directory not found: {project_dir}")
        sys.exit(1)

    target       = os.path.basename(project_dir)
    out_dir      = os.path.join(project_dir, "phase2", "intel")
    responses_dir = os.path.join(project_dir, "phase1", "responses")
    dev_staging  = os.path.join(project_dir, "phase1", "buckets", "dev-staging.txt")
    config_exp   = os.path.join(project_dir, "phase1", "buckets", "config-exposure.txt")
    os.makedirs(out_dir, exist_ok=True)

    print_info(f"Target: {target}")

    all_secrets  = []
    git_exposed  = []

    # ── 1. trufflehog on responses/ ───────────────────────────────────────────
    if os.path.isdir(responses_dir):
        print_info(f"Running trufflehog on responses/...")
        th_findings = run_trufflehog(responses_dir, out_dir, debug=args.debug)
        all_secrets.extend(th_findings)
    else:
        print_warn("phase1/responses/ not found — skipping trufflehog")

    # ── 2. gitleaks on responses/ ─────────────────────────────────────────────
    if os.path.isdir(responses_dir):
        print_info("Running gitleaks on responses/...")
        gl_findings = run_gitleaks(responses_dir, out_dir, debug=args.debug)
        all_secrets.extend(gl_findings)

    # ── 3. Regex fallback scan on responses/ ──────────────────────────────────
    if os.path.isdir(responses_dir) and not find_tool("trufflehog") and not find_tool("gitleaks"):
        print_info("No secret-detection tools found — using regex scan...")
        regex_findings = []
        for fpath in list(Path(responses_dir).rglob("*"))[:500]:
            if fpath.is_file() and fpath.suffix in (".txt", ".js", ".json", ".html", ".xml", ".yaml", ".yml"):
                for finding in regex_scan_file(str(fpath)):
                    finding["tool"] = "regex"
                    regex_findings.append(finding)
        all_secrets.extend(regex_findings[:200])
        print_ok(f"regex: {len(regex_findings)} finding(s)")

    # ── 4. .git exposure check on dev-staging ────────────────────────────────
    if not args.skip_git:
        for bucket_file in [dev_staging, config_exp]:
            if os.path.exists(bucket_file):
                with open(bucket_file) as f:
                    urls = [l.strip() for l in f if l.strip()]
                if urls:
                    print_info(f"Checking .git exposure on {os.path.basename(bucket_file)} ({len(urls)} URLs)...")
                    exposed = check_git_exposure(urls, out_dir, debug=args.debug)
                    git_exposed.extend(exposed)

    # ── 5. Write secrets.json ─────────────────────────────────────────────────
    # Categorize by confidence
    high_conf = [s for s in all_secrets if s.get("verified") or s.get("type") in (
        "aws_access_key", "github_token", "google_api_key", "private_key", "jwt_token")]
    med_conf  = [s for s in all_secrets if s not in high_conf]

    output = {
        "target":          target,
        "generated":       datetime.utcnow().isoformat() + "Z",
        "high_confidence": high_conf,
        "medium_confidence": med_conf,
        "git_exposed":     git_exposed,
        "summary": {
            "total_secrets":     len(all_secrets),
            "high_confidence":   len(high_conf),
            "medium_confidence": len(med_conf),
            "git_exposed_hosts": len(git_exposed),
        }
    }

    out_path = os.path.join(out_dir, "secrets.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print_ok(f"secrets.json → {out_path}")

    # ── Summary ───────────────────────────────────────────────────────────────
    s = output["summary"]
    if RICH:
        tbl = Table(title=f"Secret Hunt — {target}", box=box.SIMPLE_HEAD)
        tbl.add_column("Category",       style="cyan")
        tbl.add_column("Count",          justify="right")
        tbl.add_row("[red]High Confidence Secrets[/red]",   f"[red]{s['high_confidence']}[/red]")
        tbl.add_row("[yellow]Medium Confidence[/yellow]",   str(s['medium_confidence']))
        tbl.add_row("[red].git Exposed Hosts[/red]",        f"[red]{s['git_exposed_hosts']}[/red]")
        tbl.add_row("Total",                                 str(s['total_secrets']))
        console.print(tbl)

        if high_conf:
            console.print(f"\n[bold red]⚠ {len(high_conf)} HIGH-CONFIDENCE SECRET(S) — review secrets.json immediately[/bold red]")
        if git_exposed:
            console.print(f"\n[bold red]⚠ {len(git_exposed)} .git EXPOSED HOST(S) — check git-exposure.json[/bold red]")
    else:
        print(f"\nSecret Hunt: {s['total_secrets']} total, "
              f"{s['high_confidence']} high-conf, "
              f"{s['git_exposed_hosts']} .git exposed")


if __name__ == "__main__":
    main()
