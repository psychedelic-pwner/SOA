#!/usr/bin/env python3
"""
SOA — Phase 2 Intel: Tech Stack Intelligence
Source: claude desktop recommendation (genuinely new — not in son-of-anton)

Maps detected technology stack → known CVEs and relevant HackerOne reports.
Feeds findings into RAG intel_kb (04_rag_query.py) for use by second_eye
and hunt_planner prompts.

Operations:
  1. Load tech stack from phase1/probing/httpx.json (detected_technology field)
  2. Query NVD API for CVEs per technology (cached in phase2/intel/)
  3. Query H1 Hacktivity API for public reports matching tech stack (if H1_TOKEN set)
  4. Write tech-intel.json with CVE list + H1 report summaries
  5. Index findings into RAG intel_kb (category: tech_intel)

Input:
  ~/SOA/4.Interface/Projects/<target>/phase1/probing/httpx.json

Output:
  ~/SOA/4.Interface/Projects/<target>/phase2/intel/tech-intel.json
  ~/SOA/1.Core/Memory/soa.db intel_kb (via RAG indexer)

Usage:
  python3 tech_intel.py --target uber [--debug]
  python3 tech_intel.py --projectdir ~/SOA/4.Interface/Projects/uber
"""

import argparse
import importlib.util
import json
import os
import re
import sys
import time
import urllib.request
import urllib.parse
from collections import defaultdict
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

# NVD API v2 — rate: 5 req/30s without key, 50/30s with key
NVD_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY  = os.environ.get("NVD_API_KEY", "")

# H1 Hacktivity API (public, no auth for public reports)
H1_BASE      = "https://hackerone.com/graphql"
H1_TOKEN     = os.environ.get("H1_TOKEN", "")

# Maximum CVEs to fetch per technology
MAX_CVES_PER_TECH = 5
MAX_TECHS         = 10


def find_tool(name):
    go = os.path.expanduser(f"~/go/bin/{name}")
    if os.path.exists(go): return go
    import shutil; return shutil.which(name)


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


# ── Load RAG from Memory ───────────────────────────────────────────────────────

def _load_rag():
    try:
        path = os.path.join(MEMORY_DIR, "04_rag_query.py")
        spec = importlib.util.spec_from_file_location("rag_query", path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None

_rag = _load_rag()


# ── Tech stack extraction ─────────────────────────────────────────────────────

def extract_tech_stack(project_dir: str) -> dict[str, int]:
    """
    Parse httpx.json and count occurrences of each technology.
    Returns {tech_name: count} sorted by count desc.
    """
    httpx_path = os.path.join(project_dir, "phase1", "probing", "httpx.json")
    if not os.path.exists(httpx_path):
        return {}

    tech_counts = defaultdict(int)
    try:
        with open(httpx_path) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                for key in ("tech", "technologies", "detected_technology"):
                    val = r.get(key)
                    if isinstance(val, list):
                        for t in val:
                            name = str(t).split("/")[0].strip().lower()
                            if name:
                                tech_counts[name] += 1
                    elif isinstance(val, str) and val:
                        name = val.split("/")[0].strip().lower()
                        if name:
                            tech_counts[name] += 1
    except Exception as e:
        print_warn(f"httpx parse error: {e}")

    return dict(sorted(tech_counts.items(), key=lambda x: -x[1]))


def _http_get(url: str, headers: dict = None, retries=3) -> dict | None:
    """Simple HTTP GET with retry and rate-limit backoff."""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers or {})
            req.add_header("User-Agent", "SOA-TechIntel/1.0")
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            if "429" in str(e) or "rate" in str(e).lower():
                wait = 35 * (attempt + 1)
                print_warn(f"Rate limited — waiting {wait}s")
                time.sleep(wait)
            elif attempt < retries - 1:
                time.sleep(5)
            else:
                return None
    return None


# ── NVD API queries ───────────────────────────────────────────────────────────

def query_nvd_cves(tech: str) -> list[dict]:
    """
    Query NVD API v2 for CVEs matching a technology name.
    Returns list of CVE summary dicts sorted by CVSS score desc.
    """
    params = urllib.parse.urlencode({
        "keywordSearch": tech,
        "keywordExactMatch": "",
        "resultsPerPage": MAX_CVES_PER_TECH,
        "startIndex": 0,
    })
    url = f"{NVD_BASE}?{params}"
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    data = _http_get(url, headers=headers)
    if not data:
        return []

    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "?")
        desc   = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:200]
                break

        # CVSS v3.1 score
        score = 0.0
        severity = "UNKNOWN"
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(metric_key, [])
            if metrics:
                cvss = metrics[0].get("cvssData", {})
                score    = cvss.get("baseScore", 0.0)
                severity = cvss.get("baseSeverity", "UNKNOWN")
                break

        published = cve.get("published", "")[:10]
        cves.append({
            "cve_id":    cve_id,
            "score":     score,
            "severity":  severity,
            "published": published,
            "summary":   desc,
        })

    # Sort by CVSS score descending
    cves.sort(key=lambda x: -x["score"])
    return cves


# ── H1 Hacktivity query ───────────────────────────────────────────────────────

def query_h1_reports(tech: str) -> list[dict]:
    """
    Query HackerOne Hacktivity for public reports mentioning a technology.
    Returns list of report summary dicts.
    Only works if H1_TOKEN is set; gracefully skips if not.
    """
    if not H1_TOKEN:
        return []

    # H1 GraphQL query for hacktivity
    query = """
    query HacktivitySearchQuery($query: String!, $limit: Int!) {
      search(query: $query, product_area: "hacktivity", product_feature: "all") {
        edges {
          node {
            ... on HackeroneReport {
              id
              title
              severity { rating }
              bounty_amount
              disclosed_at
              reporter { username }
            }
          }
        }
      }
    }
    """
    payload = json.dumps({
        "query": query,
        "variables": {"query": tech, "limit": 5}
    }).encode()

    try:
        req = urllib.request.Request(
            H1_BASE,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"token {H1_TOKEN}",
                "User-Agent": "SOA-TechIntel/1.0",
            }
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        reports = []
        for edge in data.get("data", {}).get("search", {}).get("edges", []):
            node = edge.get("node", {})
            if node.get("title"):
                reports.append({
                    "id":       node.get("id"),
                    "title":    node.get("title", "")[:100],
                    "severity": (node.get("severity") or {}).get("rating", "?"),
                    "bounty":   node.get("bounty_amount"),
                    "date":     (node.get("disclosed_at") or "")[:10],
                })
        return reports
    except Exception:
        return []


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOA Phase 2 Intel: Tech Stack Intelligence")
    parser.add_argument("--target",     default=None)
    parser.add_argument("--projectdir", default=None)
    parser.add_argument("--debug",      action="store_true")
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

    target  = os.path.basename(project_dir)
    out_dir = os.path.join(project_dir, "phase2", "intel")
    os.makedirs(out_dir, exist_ok=True)

    print_info(f"Target: {target}")
    if not NVD_API_KEY:
        print_warn("NVD_API_KEY not set — rate limited to 5 req/30s (set it for faster queries)")
    if not H1_TOKEN:
        print_warn("H1_TOKEN not set — H1 Hacktivity queries skipped")

    # ── 1. Extract tech stack ─────────────────────────────────────────────────
    print_info("Extracting tech stack from httpx.json...")
    tech_stack = extract_tech_stack(project_dir)
    if not tech_stack:
        print_warn("No tech stack detected — check phase1/probing/httpx.json")
        tech_stack = {}

    top_techs = list(tech_stack.items())[:MAX_TECHS]
    print_ok(f"Tech stack: {', '.join(t for t, _ in top_techs)}")

    # ── 2. Query NVD for CVEs ─────────────────────────────────────────────────
    all_cves = {}
    for tech, count in top_techs:
        print_info(f"Querying NVD for: {tech} ({count} hosts)")
        cves = query_nvd_cves(tech)
        if cves:
            all_cves[tech] = cves
            print_ok(f"  {tech}: {len(cves)} CVE(s), top={cves[0]['cve_id']} ({cves[0]['score']})")
        else:
            all_cves[tech] = []
        # NVD rate limit: 5 req/30s without key
        if not NVD_API_KEY:
            time.sleep(7)
        else:
            time.sleep(0.5)

    # ── 3. Query H1 Hacktivity ────────────────────────────────────────────────
    all_h1 = {}
    for tech, _ in top_techs[:5]:  # limit H1 queries
        reports = query_h1_reports(tech)
        if reports:
            all_h1[tech] = reports
            print_ok(f"  H1 {tech}: {len(reports)} report(s)")

    # ── 4. Write tech-intel.json ─────────────────────────────────────────────
    output = {
        "target":     target,
        "generated":  datetime.utcnow().isoformat() + "Z",
        "tech_stack": [{"tech": t, "host_count": c} for t, c in top_techs],
        "cves":       all_cves,
        "h1_reports": all_h1,
        "summary": {
            "techs_analyzed": len(top_techs),
            "total_cves":     sum(len(v) for v in all_cves.values()),
            "critical_cves":  sum(
                1 for cves in all_cves.values()
                for c in cves if c.get("score", 0) >= 9.0
            ),
            "h1_reports":     sum(len(v) for v in all_h1.values()),
        }
    }

    out_path = os.path.join(out_dir, "tech-intel.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print_ok(f"tech-intel.json → {out_path}")

    # ── 5. Index into RAG ─────────────────────────────────────────────────────
    if _rag:
        for tech, cves in all_cves.items():
            if not cves: continue
            content_lines = [f"Technology: {tech} (found on {tech_stack.get(tech, 0)} hosts)"]
            for cve in cves:
                content_lines.append(
                    f"CVE: {cve['cve_id']} CVSS={cve['score']} ({cve['severity']}) "
                    f"Published={cve['published']} — {cve['summary']}"
                )
            if tech in all_h1:
                content_lines.append(f"H1 Reports for {tech}:")
                for r in all_h1[tech]:
                    content_lines.append(
                        f"  [{r['severity']}] {r['title']} (${r.get('bounty','?')} bounty)"
                    )

            try:
                _rag.index_document(
                    source=f"tech_intel:{target}:{tech}",
                    date=datetime.utcnow().strftime("%Y-%m-%d"),
                    category="tech_intel",
                    content="\n".join(content_lines),
                    tags=[tech, "cve", "nvd", target],
                )
            except Exception as e:
                if args.debug: print_warn(f"RAG index error for {tech}: {e}")

        print_ok(f"RAG: indexed {len(all_cves)} tech entries into intel_kb")
    else:
        print_warn("04_rag_query not available — skipping RAG indexing")

    # ── Summary table ─────────────────────────────────────────────────────────
    if RICH:
        tbl = Table(title=f"Tech Intel — {target}", box=box.SIMPLE_HEAD)
        tbl.add_column("Tech",      style="cyan",   max_width=20)
        tbl.add_column("Hosts",     justify="right")
        tbl.add_column("CVEs",      justify="right")
        tbl.add_column("Top CVE",   style="white")
        tbl.add_column("H1 Reports", justify="right")
        for tech, count in top_techs:
            cves    = all_cves.get(tech, [])
            h1_cnt  = len(all_h1.get(tech, []))
            top_cve = f"{cves[0]['cve_id']} ({cves[0]['score']})" if cves else "-"
            cve_style = "red" if cves and cves[0]["score"] >= 9.0 else "yellow" if cves and cves[0]["score"] >= 7.0 else "white"
            tbl.add_row(tech, str(count), str(len(cves)), f"[{cve_style}]{top_cve}[/{cve_style}]", str(h1_cnt))
        console.print(tbl)
    else:
        s = output["summary"]
        print(f"\nTech Intel: {s['techs_analyzed']} techs, {s['total_cves']} CVEs "
              f"({s['critical_cves']} critical), {s['h1_reports']} H1 reports")


if __name__ == "__main__":
    main()
