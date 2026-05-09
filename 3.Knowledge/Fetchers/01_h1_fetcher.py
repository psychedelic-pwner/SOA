#!/usr/bin/env python3
"""
SOA Ring 3 — H1 Fetcher  [Knowledge-01]
Source: original — no prior equivalent in son-of-anton

Fetches disclosed HackerOne reports via GraphQL API.
Indexes high/critical findings into intel_kb for use by
second_eye, hunt_planner, and attack_chains at runtime.

Auth: H1_TOKEN env var (optional — skips gracefully if missing)

Output:
  ~/SOA/3.Knowledge/Intel/h1/YYYY-MM-DD/<report_id>.json
  ~/SOA/3.Knowledge/Intel/h1/YYYY-MM-DD/summary.json
  → indexed into soa.db intel_kb

Usage:
  python3 01_h1_fetcher.py [--debug] [--limit 100]
"""

import importlib.util
import json
import os
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, date
from pathlib import Path

BASE_DIR     = os.path.expanduser("~/SOA")
MEMORY_DIR   = os.path.join(BASE_DIR, "1.Core", "Memory")
INTEL_DIR    = os.path.join(BASE_DIR, "3.Knowledge", "Intel", "h1")
TODAY        = date.today().isoformat()
H1_TOKEN     = os.environ.get("H1_TOKEN", "")
H1_GRAPHQL   = "https://hackerone.com/graphql"

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None


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


# ── Load RAG indexer ──────────────────────────────────────────────────────────

def _load_rag():
    try:
        path = os.path.join(MEMORY_DIR, "04_rag_query.py")
        spec = importlib.util.spec_from_file_location("rag_query", path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception as e:
        print_warn(f"04_rag_query not loadable: {e}")
        return None

_rag = _load_rag()


# ── H1 GraphQL ────────────────────────────────────────────────────────────────

_HACKTIVITY_QUERY = """
query HacktivitySearch($cursor: String, $limit: Int!) {
  hacktivity_items(
    secure_order_by: { disclosed_at: { _direction: DESC } }
    where: {
      report: {
        disclosed_at: { _is_null: false }
        severity_rating: { _in: [high, critical] }
      }
    }
    count: $limit
    cursor: $cursor
  ) {
    edges {
      node {
        ... on HackerOneUserToTeamProvidedGuidanceHacktivityDocument {
          id
          report {
            id
            title
            url
            disclosed_at
            severity_rating
            weakness {
              name
              external_id
            }
            reporter {
              username
            }
            team {
              name
              handle
            }
          }
        }
      }
    }
    total_count
    pageInfo {
      endCursor
      hasNextPage
    }
  }
}
"""


def _gql_request(query: str, variables: dict) -> dict | None:
    """POST a GraphQL request to H1. Returns parsed JSON or None."""
    payload = json.dumps({"query": query, "variables": variables}).encode()
    headers = {
        "Content-Type":  "application/json",
        "User-Agent":    "SOA-H1Fetcher/1.0",
    }
    if H1_TOKEN:
        headers["Authorization"] = f"token {H1_TOKEN}"

    try:
        req = urllib.request.Request(H1_GRAPHQL, data=payload, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print_warn(f"H1 HTTP {e.code}: {e.reason}")
        return None
    except Exception as e:
        print_warn(f"H1 request error: {e}")
        return None


def fetch_reports(limit: int = 100, debug: bool = False) -> list[dict]:
    """
    Fetch up to `limit` disclosed high/critical reports from H1.
    Returns list of normalized report dicts.
    """
    if not H1_TOKEN:
        print_warn("H1_TOKEN not set — skipping H1 fetch (set H1_TOKEN to enable)")
        return []

    print_info(f"Fetching up to {limit} H1 high/critical disclosed reports...")
    data = _gql_request(_HACKTIVITY_QUERY, {"limit": min(limit, 100), "cursor": None})
    if not data:
        print_err("H1 GraphQL returned no data")
        return []

    if "errors" in data:
        for err in data["errors"]:
            print_err(f"H1 GraphQL error: {err.get('message', err)}")
        return []

    edges = (
        data.get("data", {})
            .get("hacktivity_items", {})
            .get("edges", [])
    )
    if debug:
        print_info(f"Raw edges: {len(edges)}")

    reports = []
    for edge in edges:
        node = edge.get("node", {})
        rep  = node.get("report")
        if not rep:
            continue

        weakness = rep.get("weakness") or {}
        reporter = rep.get("reporter") or {}
        team     = rep.get("team") or {}

        reports.append({
            "id":             str(rep.get("id", "")),
            "title":          rep.get("title", ""),
            "url":            rep.get("url", ""),
            "severity":       rep.get("severity_rating", "unknown"),
            "disclosed_at":   (rep.get("disclosed_at") or "")[:10],
            "weakness_name":  weakness.get("name", ""),
            "weakness_cwe":   weakness.get("external_id", ""),
            "reporter":       reporter.get("username", ""),
            "team_name":      team.get("name", ""),
            "team_handle":    team.get("handle", ""),
        })

    return reports


# ── Pattern extraction ────────────────────────────────────────────────────────

_VULN_CLASS_MAP = {
    "Cross-Site Scripting":          "xss",
    "SQL Injection":                 "sqli",
    "Server-Side Request Forgery":   "ssrf",
    "Insecure Direct Object Reference": "idor",
    "Remote Code Execution":         "rce",
    "Open Redirect":                 "redirect",
    "Business Logic":                "logic",
    "Authentication":                "auth",
    "Authorization":                 "authz",
    "Information Disclosure":        "info-disclosure",
    "Denial of Service":             "dos",
    "Subdomain Takeover":            "takeover",
    "Path Traversal":                "traversal",
    "File Upload":                   "upload",
    "Race Condition":                "race",
    "XML External Entity":           "xxe",
    "Memory Corruption":             "memory",
    "Cryptographic":                 "crypto",
    "Injection":                     "injection",
}


def _classify_vuln(weakness_name: str, title: str) -> str:
    """Map weakness name → normalized vuln class."""
    text = (weakness_name + " " + title).lower()
    for keyword, vuln_class in _VULN_CLASS_MAP.items():
        if keyword.lower() in text:
            return vuln_class
    return "other"


def _extract_tech_hints(title: str, team_handle: str) -> list[str]:
    """Extract technology hints from title text."""
    hints = []
    tech_keywords = [
        "api", "graphql", "oauth", "aws", "s3", "gcp", "azure",
        "php", "node", "django", "rails", "spring", "nginx", "apache",
        "wordpress", "drupal", "jenkins", "gitlab", "github", "jira",
        "kubernetes", "docker", "redis", "elasticsearch", "mongodb",
        "react", "angular", "vue", "next.js", "jwt", "saml", "ldap",
    ]
    text = title.lower()
    for kw in tech_keywords:
        if kw in text:
            hints.append(kw)
    return hints


# ── Save + index ──────────────────────────────────────────────────────────────

def save_and_index(reports: list[dict], out_dir: str, debug: bool = False) -> int:
    """Save each report as JSON and index into intel_kb. Returns indexed count."""
    os.makedirs(out_dir, exist_ok=True)
    indexed = 0

    for rep in reports:
        report_id = rep["id"] or "unknown"
        vuln_class = _classify_vuln(rep["weakness_name"], rep["title"])
        tech_hints = _extract_tech_hints(rep["title"], rep["team_handle"])

        # Augment with extracted fields
        rep["vuln_class"]    = vuln_class
        rep["tech_hints"]    = tech_hints
        rep["fetched_date"]  = TODAY

        # Save raw
        out_path = os.path.join(out_dir, f"{report_id}.json")
        try:
            with open(out_path, "w") as f:
                json.dump(rep, f, indent=2)
        except Exception as e:
            if debug: print_warn(f"Save failed for {report_id}: {e}")
            continue

        # Build indexable content
        content_parts = [
            f"Title: {rep['title']}",
            f"Severity: {rep['severity']}",
            f"Weakness: {rep['weakness_name']}",
            f"CWE: {rep['weakness_cwe']}",
            f"Team: {rep['team_name']} (@{rep['team_handle']})",
            f"Reporter: {rep['reporter']}",
            f"Disclosed: {rep['disclosed_at']}",
            f"URL: {rep['url']}",
        ]
        if tech_hints:
            content_parts.append(f"Tech hints: {', '.join(tech_hints)}")

        # Tags: severity + vuln_class + team_handle
        tags_list = [rep["severity"], vuln_class]
        if rep["team_handle"]:
            tags_list.append(rep["team_handle"])
        if tech_hints:
            tags_list.extend(tech_hints[:3])

        if _rag:
            ok = _rag.index_document(
                source   = "h1",
                date     = rep["disclosed_at"] or TODAY,
                category = vuln_class,
                content  = "\n".join(content_parts),
                tags     = " ".join(tags_list),
            )
            if ok:
                indexed += 1
            elif debug:
                print_warn(f"index_document failed for {report_id}")
        else:
            indexed += 1  # count as "saved" even if no RAG

    return indexed


def write_summary(reports: list[dict], out_dir: str, indexed: int) -> None:
    by_vuln  = {}
    by_team  = {}
    by_sev   = {"critical": 0, "high": 0}

    for r in reports:
        vc = r.get("vuln_class", "other")
        by_vuln[vc] = by_vuln.get(vc, 0) + 1
        th = r.get("team_handle", "unknown")
        by_team[th] = by_team.get(th, 0) + 1
        sev = r.get("severity", "")
        if sev in by_sev:
            by_sev[sev] += 1

    summary = {
        "fetched_date": TODAY,
        "total_fetched": len(reports),
        "total_indexed": indexed,
        "by_severity": by_sev,
        "top_vuln_classes": sorted(by_vuln.items(), key=lambda x: -x[1])[:10],
        "top_teams": sorted(by_team.items(), key=lambda x: -x[1])[:10],
    }

    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SOA Ring 3: H1 Fetcher")
    parser.add_argument("--limit", type=int, default=100, help="Max reports to fetch (default 100)")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    out_dir = os.path.join(INTEL_DIR, TODAY)

    if not H1_TOKEN:
        print_warn("H1_TOKEN not set — no reports will be fetched")
        print_info("Set H1_TOKEN env var to enable: export H1_TOKEN=your_token")
        print_info(f"Output dir would be: {out_dir}")
        return

    reports = fetch_reports(limit=args.limit, debug=args.debug)
    if not reports:
        print_warn("No reports fetched")
        return

    print_info(f"Fetched {len(reports)} reports, saving + indexing...")
    indexed = save_and_index(reports, out_dir, debug=args.debug)
    write_summary(reports, out_dir, indexed)

    print_ok(f"Fetched:  {len(reports)} reports")
    print_ok(f"Indexed:  {indexed} into intel_kb")
    print_ok(f"Summary:  {os.path.join(out_dir, 'summary.json')}")

    if not _rag:
        print_warn("RAG not available — reports saved to disk but not indexed into intel_kb")

    if RICH:
        # Show vuln class breakdown
        tbl = Table(title="H1 Fetch Results", box=box.SIMPLE_HEAD)
        tbl.add_column("Severity", style="cyan")
        tbl.add_column("Vuln Class")
        tbl.add_column("Team")
        tbl.add_column("Disclosed")
        for r in reports[:15]:
            sev = r.get("severity", "")
            sc  = "red" if sev == "critical" else "yellow"
            tbl.add_row(
                f"[{sc}]{sev}[/{sc}]",
                r.get("vuln_class", ""),
                r.get("team_handle", ""),
                r.get("disclosed_at", ""),
            )
        console.print(tbl)
        if len(reports) > 15:
            console.print(f"[dim]... and {len(reports) - 15} more (see summary.json)[/dim]")
    else:
        for r in reports[:10]:
            print(f"  [{r.get('severity','?')}] {r.get('title','')[:70]} — {r.get('team_handle','')}")


if __name__ == "__main__":
    main()
