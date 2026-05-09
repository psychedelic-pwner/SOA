#!/usr/bin/env python3
"""
SOA Ring 3 — NVD Fetcher  [Knowledge-02]
Source: original — extends tech_intel.py (phase2) with daily pull + cross-ref

Fetches HIGH and CRITICAL CVEs from NVD API v2 published in the last 7 days.
Cross-references against active target tech stacks from self-state.json.
Indexes into intel_kb for use by second_eye + hunt_planner.

No auth required. Rate limit: 5 req/30s → sleep(6) between calls.
Set NVD_API_KEY env var to increase rate to 50 req/30s (sleep(0.5)).

Output:
  ~/SOA/3.Knowledge/Intel/nvd/YYYY-MM-DD/<cve_id>.json
  ~/SOA/3.Knowledge/Intel/nvd/YYYY-MM-DD/flagged.json
  ~/SOA/3.Knowledge/Intel/nvd/YYYY-MM-DD/summary.json
  → indexed into soa.db intel_kb

Usage:
  python3 02_nvd_fetcher.py [--days 7] [--debug]
"""

import importlib.util
import json
import os
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, date, timedelta
from pathlib import Path

BASE_DIR     = os.path.expanduser("~/SOA")
MEMORY_DIR   = os.path.join(BASE_DIR, "1.Core", "Memory")
INTEL_DIR    = os.path.join(BASE_DIR, "3.Knowledge", "Intel", "nvd")
TODAY        = date.today().isoformat()
NVD_API_KEY  = os.environ.get("NVD_API_KEY", "")
NVD_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
STATE_PATH   = os.path.join(MEMORY_DIR, "self-state.json")

# Rate limits: 5 req/30s without key → 6s sleep; 50/30s with key → 0.5s
_SLEEP_SECS  = 0.5 if NVD_API_KEY else 6.0

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


# ── NVD API ───────────────────────────────────────────────────────────────────

def _nvd_get(params: dict) -> dict | None:
    """GET NVD API with rate-limit retry. Returns parsed JSON or None."""
    url = f"{NVD_BASE}?{urllib.parse.urlencode(params)}"
    headers = {"User-Agent": "SOA-NVDFetcher/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print_warn(f"NVD 403 — sleeping 35s (rate limit)")
                time.sleep(35)
            elif e.code == 404:
                return None
            else:
                print_warn(f"NVD HTTP {e.code}")
                time.sleep(5)
        except Exception as e:
            print_warn(f"NVD request error (attempt {attempt+1}): {e}")
            time.sleep(5)
    return None


def _parse_cve(vuln: dict) -> dict | None:
    """Parse one NVD vulnerability entry into a normalized dict."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # English description
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    # CVSS score + severity (v3.1 preferred, then v3.0, then v2)
    score    = 0.0
    severity = "UNKNOWN"
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(metric_key, [])
        if metrics:
            cvss     = metrics[0].get("cvssData", {})
            score    = cvss.get("baseScore", 0.0)
            severity = cvss.get("baseSeverity", "UNKNOWN")
            break

    # CPE list (affected products)
    cpe_list = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                uri = cpe_match.get("criteria", "")
                if uri:
                    cpe_list.append(uri)

    # Affected product names (from CPE: cpe:2.3:a:vendor:product:version)
    products = []
    for cpe in cpe_list[:20]:
        parts = cpe.split(":")
        if len(parts) >= 5:
            vendor  = parts[3]
            product = parts[4]
            if vendor != "*" and product != "*":
                products.append(f"{vendor}/{product}")

    return {
        "cve_id":      cve_id,
        "description": description[:500],
        "score":       score,
        "severity":    severity.upper(),
        "published":   cve.get("published", "")[:10],
        "modified":    cve.get("lastModified", "")[:10],
        "cpe_list":    cpe_list[:30],
        "products":    list(set(products))[:20],
        "references":  [r.get("url", "") for r in cve.get("references", [])[:5]],
        "fetched_date": TODAY,
    }


def fetch_cves(days: int = 7, debug: bool = False) -> list[dict]:
    """
    Fetch HIGH + CRITICAL CVEs published in the last `days` days from NVD.
    Returns list of normalized CVE dicts.
    """
    cves     = []
    end_dt   = datetime.utcnow()
    start_dt = end_dt - timedelta(days=days)

    # NVD API expects ISO 8601 with milliseconds
    pub_start = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end   = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

    for severity in ("HIGH", "CRITICAL"):
        print_info(f"Fetching {severity} CVEs ({pub_start[:10]} → {pub_end[:10]})...")
        start_index = 0
        page_size   = 100

        while True:
            params = {
                "cvssV3Severity":  severity,
                "pubStartDate":    pub_start,
                "pubEndDate":      pub_end,
                "resultsPerPage":  page_size,
                "startIndex":      start_index,
            }

            data = _nvd_get(params)
            if not data:
                print_warn(f"No data returned for {severity} at startIndex={start_index}")
                break

            vulns = data.get("vulnerabilities", [])
            total = data.get("totalResults", 0)

            for vuln in vulns:
                parsed = _parse_cve(vuln)
                if parsed:
                    cves.append(parsed)

            if debug:
                print_info(f"  {severity}: got {len(vulns)}, total={total}, offset={start_index}")

            start_index += len(vulns)
            if start_index >= total or not vulns:
                break

            time.sleep(_SLEEP_SECS)

        time.sleep(_SLEEP_SECS)

    print_ok(f"NVD: {len(cves)} CVEs fetched")
    return cves


# ── Target cross-reference ────────────────────────────────────────────────────

def load_active_tech_stacks() -> dict[str, list[str]]:
    """
    Read self-state.json → extract tech stacks per active target.
    Returns {target_name: [tech1, tech2, ...]}
    """
    if not os.path.exists(STATE_PATH):
        return {}

    try:
        with open(STATE_PATH) as f:
            state = json.load(f)
    except Exception:
        return {}

    tech_map = {}
    active_targets = state.get("active_targets", [])

    # active_targets may be a list of strings or list of dicts
    for entry in active_targets:
        if isinstance(entry, str):
            target_name = entry
            # Try to read tech from project's httpx output
            httpx_path = os.path.join(
                BASE_DIR, "4.Interface", "Projects", target_name,
                "phase1", "probing", "httpx.json"
            )
            techs = _read_tech_from_httpx(httpx_path)
            if techs:
                tech_map[target_name] = techs
        elif isinstance(entry, dict):
            target_name = entry.get("name", "")
            techs = entry.get("tech_stack", [])
            if isinstance(techs, list):
                tech_map[target_name] = [str(t).lower() for t in techs]

    # Also check phase2 tech-intel.json for richer data
    projects_dir = os.path.join(BASE_DIR, "4.Interface", "Projects")
    if os.path.isdir(projects_dir):
        for proj in os.listdir(projects_dir):
            if proj in tech_map:
                continue  # already populated
            tech_intel_path = os.path.join(
                projects_dir, proj, "phase2", "intel", "tech-intel.json"
            )
            if os.path.exists(tech_intel_path):
                try:
                    with open(tech_intel_path) as f:
                        ti = json.load(f)
                    techs = [entry["tech"] for entry in ti.get("tech_stack", [])]
                    if techs:
                        tech_map[proj] = techs
                except Exception:
                    pass

    return tech_map


def _read_tech_from_httpx(httpx_path: str) -> list[str]:
    """Parse httpx.json to extract detected tech stack names."""
    if not os.path.exists(httpx_path):
        return []
    techs = set()
    try:
        with open(httpx_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                for key in ("tech", "technologies", "detected_technology"):
                    val = r.get(key)
                    if isinstance(val, list):
                        for t in val:
                            techs.add(str(t).split("/")[0].strip().lower())
                    elif isinstance(val, str) and val:
                        techs.add(val.split("/")[0].strip().lower())
    except Exception:
        pass
    return list(techs)


def cross_reference(cves: list[dict], tech_stacks: dict[str, list[str]]) -> list[dict]:
    """
    For each CVE, check if its products/CPEs match any active target's tech stack.
    Returns list of flagged dicts: {cve_id, score, severity, target, matched_tech, ...}
    """
    flagged = []

    for cve in cves:
        cve_products_text = " ".join(cve.get("products", []) + cve.get("cpe_list", []) + [cve.get("description", "")]).lower()

        for target, techs in tech_stacks.items():
            for tech in techs:
                tech_lower = tech.lower()
                if tech_lower and tech_lower in cve_products_text:
                    flagged.append({
                        "cve_id":       cve["cve_id"],
                        "score":        cve["score"],
                        "severity":     cve["severity"],
                        "description":  cve["description"][:200],
                        "published":    cve["published"],
                        "target":       target,
                        "matched_tech": tech,
                    })
                    break  # one match per target per CVE is enough

    return flagged


# ── Save + index ──────────────────────────────────────────────────────────────

def save_and_index(cves: list[dict], out_dir: str, debug: bool = False) -> int:
    """Save each CVE as JSON and index into intel_kb. Returns indexed count."""
    os.makedirs(out_dir, exist_ok=True)
    indexed = 0

    for cve in cves:
        cve_id = cve["cve_id"].replace("/", "_")
        out_path = os.path.join(out_dir, f"{cve_id}.json")
        try:
            with open(out_path, "w") as f:
                json.dump(cve, f, indent=2)
        except Exception as e:
            if debug: print_warn(f"Save failed for {cve['cve_id']}: {e}")
            continue

        if not _rag:
            continue

        content_parts = [
            f"CVE: {cve['cve_id']}",
            f"Score: {cve['score']} ({cve['severity']})",
            f"Published: {cve['published']}",
            f"Description: {cve['description']}",
        ]
        if cve.get("products"):
            content_parts.append(f"Affected products: {', '.join(cve['products'][:10])}")

        tags_list = ["cve", cve["severity"].lower(), cve["cve_id"]]

        ok = _rag.index_document(
            source   = "nvd",
            date     = cve["published"] or TODAY,
            category = "cve",
            content  = "\n".join(content_parts),
            tags     = " ".join(tags_list),
        )
        if ok:
            indexed += 1
        elif debug:
            print_warn(f"index_document failed for {cve['cve_id']}")

    return indexed


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SOA Ring 3: NVD Fetcher")
    parser.add_argument("--days",  type=int, default=7,    help="Days back to fetch (default 7)")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    out_dir = os.path.join(INTEL_DIR, TODAY)

    if not NVD_API_KEY:
        print_warn("NVD_API_KEY not set — rate limited to 5 req/30s (set for faster pulls)")

    cves = fetch_cves(days=args.days, debug=args.debug)
    if not cves:
        print_warn("No CVEs fetched")
        return

    print_info(f"Saving {len(cves)} CVEs and indexing into intel_kb...")
    indexed = save_and_index(cves, out_dir, debug=args.debug)

    # Cross-reference with active targets
    tech_stacks = load_active_tech_stacks()
    flagged     = []
    if tech_stacks:
        print_info(f"Cross-referencing against {len(tech_stacks)} target(s)...")
        flagged = cross_reference(cves, tech_stacks)
        if flagged:
            flagged_path = os.path.join(out_dir, "flagged.json")
            with open(flagged_path, "w") as f:
                json.dump({"date": TODAY, "flagged": flagged}, f, indent=2)
            print_ok(f"Flagged {len(flagged)} CVE(s) matching active target tech stacks")
            print_ok(f"flagged.json → {flagged_path}")
        else:
            print_info("No CVEs match active target tech stacks")
    else:
        print_info("No active target tech stacks found — skipping cross-reference")

    # Summary
    critical = sum(1 for c in cves if c["severity"] == "CRITICAL")
    high     = sum(1 for c in cves if c["severity"] == "HIGH")
    summary  = {
        "date":         TODAY,
        "days_window":  args.days,
        "total_cves":   len(cves),
        "critical":     critical,
        "high":         high,
        "indexed":      indexed,
        "flagged":      len(flagged),
    }
    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print_ok(f"CVEs:     {len(cves)} total ({critical} critical, {high} high)")
    print_ok(f"Indexed:  {indexed} into intel_kb")
    print_ok(f"Flagged:  {len(flagged)} match active targets")
    print_ok(f"Output:   {out_dir}")

    if not _rag:
        print_warn("RAG not available — CVEs saved to disk but not indexed into intel_kb")

    if RICH and flagged:
        tbl = Table(title="Flagged CVEs (match active targets)", box=box.SIMPLE_HEAD)
        tbl.add_column("CVE",      style="cyan")
        tbl.add_column("Score",    justify="right")
        tbl.add_column("Target")
        tbl.add_column("Matched Tech")
        for f in flagged[:20]:
            sc = "red" if f["score"] >= 9.0 else "yellow"
            tbl.add_row(
                f["cve_id"],
                f"[{sc}]{f['score']}[/{sc}]",
                f["target"],
                f["matched_tech"],
            )
        console.print(tbl)


if __name__ == "__main__":
    main()
