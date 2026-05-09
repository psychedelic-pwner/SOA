#!/usr/bin/env python3
"""
SOA Ring 3 — GitHub Fetcher  [Knowledge-03]
Source: original

Fetches security methodology and checklist READMEs from GitHub
via Search API. Deduplicates against already-indexed repos this week.

Auth: GITHUB_TOKEN from os.environ (optional — unauthenticated is heavily
rate-limited: 10 req/min; authenticated: 30 req/min)

Search queries:
  1. "bug bounty checklist" in:readme stars:>50
  2. "web application pentest checklist" in:readme
  3. "OWASP testing methodology" in:readme
  4. "API security checklist" in:readme stars:>100

Output:
  ~/SOA/3.Knowledge/Intel/github/YYYY-MM-DD/<repo_name>.md
  ~/SOA/3.Knowledge/Intel/github/YYYY-MM-DD/summary.json
  → indexed into soa.db intel_kb (category: methodology)

Usage:
  python3 03_github_fetcher.py [--debug]
"""

import importlib.util
import json
import os
import re
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
import base64
from datetime import datetime, date, timedelta
from pathlib import Path

BASE_DIR     = os.path.expanduser("~/SOA")
MEMORY_DIR   = os.path.join(BASE_DIR, "1.Core", "Memory")
INTEL_DIR    = os.path.join(BASE_DIR, "3.Knowledge", "Intel", "github")
TODAY        = date.today().isoformat()
GH_TOKEN     = os.environ.get("GITHUB_TOKEN", "")
GH_API       = "https://api.github.com"

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


# ── GitHub API helpers ────────────────────────────────────────────────────────

def _gh_request(path: str, params: dict = None) -> dict | list | None:
    """GET GitHub API endpoint. Returns parsed JSON or None."""
    url = f"{GH_API}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)

    headers = {
        "Accept":     "application/vnd.github+json",
        "User-Agent": "SOA-GHFetcher/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            # Check rate limit headers
            remaining = resp.headers.get("X-RateLimit-Remaining", "999")
            if int(remaining) < 5:
                reset_at  = int(resp.headers.get("X-RateLimit-Reset", "0"))
                wait_secs = max(0, reset_at - int(time.time())) + 5
                print_warn(f"GitHub rate limit low ({remaining} left) — sleeping {wait_secs}s")
                time.sleep(wait_secs)
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print_warn("GitHub 403 — rate limited, sleeping 60s")
            time.sleep(60)
        elif e.code == 422:
            pass  # Unprocessable entity — skip silently
        else:
            print_warn(f"GitHub HTTP {e.code}: {e.reason}")
        return None
    except Exception as e:
        print_warn(f"GitHub request error: {e}")
        return None


def _fetch_readme(owner: str, repo: str) -> str | None:
    """Fetch raw README content for a repo. Returns text or None."""
    data = _gh_request(f"/repos/{owner}/{repo}/readme")
    if not data or not isinstance(data, dict):
        return None

    encoding = data.get("encoding", "")
    content  = data.get("content", "")

    if encoding == "base64":
        try:
            return base64.b64decode(content).decode("utf-8", errors="ignore")
        except Exception:
            return None

    # Fallback: fetch download_url directly
    download_url = data.get("download_url", "")
    if download_url:
        try:
            req = urllib.request.Request(
                download_url,
                headers={"User-Agent": "SOA-GHFetcher/1.0"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read().decode("utf-8", errors="ignore")
        except Exception:
            pass

    return None


# ── Dedup check ───────────────────────────────────────────────────────────────

def _already_indexed_this_week(repo_full: str) -> bool:
    """
    Check intel_kb to see if this repo was indexed in the last 7 days.
    Uses search_intel with the repo name as query.
    """
    if not _rag:
        return False

    # Check on-disk: if any file in recent YYYY-MM-DD dirs matches
    week_ago = (date.today() - timedelta(days=7)).isoformat()
    for day_dir in sorted(Path(INTEL_DIR).iterdir(), reverse=True)[:7]:
        if not day_dir.is_dir():
            continue
        if day_dir.name < week_ago:
            continue
        # Repo name is <owner>-<repo>.md (slashes replaced with dashes)
        fname = repo_full.replace("/", "-") + ".md"
        if (day_dir / fname).exists():
            return True

    return False


# ── Search + fetch ────────────────────────────────────────────────────────────

_SEARCH_QUERIES = [
    ("bug bounty checklist", "bug-bounty-checklist"),
    ("web application pentest checklist", "pentest-checklist"),
    ("OWASP testing methodology", "owasp-methodology"),
    ("API security checklist", "api-security"),
]


def search_repos(query: str, max_results: int = 5, debug: bool = False) -> list[dict]:
    """Search GitHub for repos matching `query`. Returns list of repo dicts."""
    params = {
        "q":        query,
        "sort":     "stars",
        "order":    "desc",
        "per_page": max_results,
        "page":     1,
    }
    data = _gh_request("/search/repositories", params)
    if not data or not isinstance(data, dict):
        return []

    items = data.get("items", [])
    if debug:
        print_info(f"  search '{query[:40]}': {len(items)} results (total: {data.get('total_count', 0)})")

    return [
        {
            "full_name":    item.get("full_name", ""),
            "owner":        item.get("owner", {}).get("login", ""),
            "name":         item.get("name", ""),
            "stars":        item.get("stargazers_count", 0),
            "description":  (item.get("description") or "")[:200],
            "topics":       item.get("topics", []),
            "url":          item.get("html_url", ""),
            "default_branch": item.get("default_branch", "main"),
        }
        for item in items
        if item.get("full_name")
    ]


def _slugify(s: str) -> str:
    """Replace non-alphanumeric chars with dashes."""
    return re.sub(r"[^a-zA-Z0-9\-_]", "-", s).strip("-")


# ── Save + index ──────────────────────────────────────────────────────────────

def process_repo(repo: dict, query_tag: str, out_dir: str, debug: bool = False) -> bool:
    """
    Fetch README, save .md, index into intel_kb.
    Returns True if successfully indexed.
    """
    full_name = repo["full_name"]
    owner, name = repo["owner"], repo["name"]

    if _already_indexed_this_week(full_name):
        if debug:
            print_info(f"  Skip (already indexed this week): {full_name}")
        return False

    readme = _fetch_readme(owner, name)
    if not readme:
        if debug:
            print_warn(f"  No README for {full_name}")
        return False

    # Truncate for storage
    readme_trunc = readme[:50_000]

    # Save .md
    fname    = _slugify(full_name) + ".md"
    out_path = os.path.join(out_dir, fname)
    try:
        with open(out_path, "w") as f:
            f.write(f"# {full_name}\n")
            f.write(f"Stars: {repo['stars']} | {repo['url']}\n\n")
            f.write(readme_trunc)
    except Exception as e:
        if debug: print_warn(f"Save failed for {full_name}: {e}")
        return False

    if not _rag:
        return True

    # Build tags: query_tag + topics (up to 5)
    topics   = repo.get("topics", [])[:5]
    tags_list = [query_tag, "methodology"] + topics
    if repo["stars"] >= 1000:
        tags_list.append("popular")

    # Content: description + first 5000 chars of README
    content = (
        f"Repository: {full_name}\n"
        f"Stars: {repo['stars']}\n"
        f"Description: {repo['description']}\n"
        f"URL: {repo['url']}\n"
        f"Topics: {', '.join(topics)}\n\n"
        + readme[:5000]
    )

    ok = _rag.index_document(
        source   = "github",
        date     = TODAY,
        category = "methodology",
        content  = content,
        tags     = " ".join(tags_list),
    )
    return ok


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SOA Ring 3: GitHub Fetcher")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    out_dir = os.path.join(INTEL_DIR, TODAY)
    os.makedirs(out_dir, exist_ok=True)

    if not GH_TOKEN:
        print_warn("GITHUB_TOKEN not set — unauthenticated (10 req/min rate limit)")
        print_info("Set GITHUB_TOKEN for higher rate limits: export GITHUB_TOKEN=ghp_...")

    total_fetched = 0
    total_indexed = 0
    results_by_query = {}

    for query, query_tag in _SEARCH_QUERIES:
        print_info(f"Searching: {query}")
        repos = search_repos(query, max_results=5, debug=args.debug)
        if not repos:
            print_warn(f"  No results for: {query}")
            results_by_query[query_tag] = 0
            time.sleep(2)
            continue

        q_indexed = 0
        for repo in repos:
            if args.debug:
                print_info(f"  [{repo['stars']}★] {repo['full_name']}")

            ok = process_repo(repo, query_tag, out_dir, debug=args.debug)
            if ok:
                q_indexed += 1
                print_ok(f"  Indexed: {repo['full_name']} ({repo['stars']}★)")
            total_fetched += 1

            # Rate limit: 2s between README fetches
            time.sleep(2)

        total_indexed += q_indexed
        results_by_query[query_tag] = q_indexed
        print_ok(f"Query '{query_tag}': {q_indexed}/{len(repos)} indexed")

        # Pause between search queries to respect rate limit
        time.sleep(5)

    # Write summary
    summary = {
        "date":          TODAY,
        "total_fetched": total_fetched,
        "total_indexed": total_indexed,
        "by_query":      results_by_query,
        "rag_available": _rag is not None,
    }
    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print_ok(f"Fetched:  {total_fetched} repos")
    print_ok(f"Indexed:  {total_indexed} into intel_kb")
    print_ok(f"Output:   {out_dir}")

    if not _rag:
        print_warn("RAG not available — files saved to disk but not indexed into intel_kb")


if __name__ == "__main__":
    main()
