#!/usr/bin/env python3
"""
SOA Ring 3 — Writeup Fetcher  [Knowledge-04]
Source: original

Fetches bug bounty writeups from public sources:
  1. pentester.land/writeups — public writeup list, top 20 most recent
  2. github.com/ngalongc/bug-bounty-reference — vuln-categorized reference

Extracts: vuln_class, technique, endpoint_type, target_type.
Indexes into intel_kb for second_eye + hunt_planner context.

No auth required. Gracefully skips unreachable sources.

Output:
  ~/SOA/3.Knowledge/Intel/writeups/YYYY-MM-DD/<slug>.json
  ~/SOA/3.Knowledge/Intel/writeups/YYYY-MM-DD/summary.json
  → indexed into soa.db intel_kb

Usage:
  python3 04_writeup_fetcher.py [--debug] [--limit 20]
"""

import importlib.util
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import date
from html.parser import HTMLParser
from pathlib import Path

BASE_DIR   = os.path.expanduser("~/SOA")
MEMORY_DIR = os.path.join(BASE_DIR, "1.Core", "Memory")
INTEL_DIR  = os.path.join(BASE_DIR, "3.Knowledge", "Intel", "writeups")
TODAY      = date.today().isoformat()

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


# ── HTTP helpers ──────────────────────────────────────────────────────────────

_HEADERS = {
    "User-Agent":      "Mozilla/5.0 (compatible; SOA-WriteupFetcher/1.0)",
    "Accept":          "text/html,application/xhtml+xml,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}


def _get(url: str, timeout: int = 15) -> str | None:
    """GET a URL and return text content. Returns None on failure."""
    try:
        req = urllib.request.Request(url, headers=_HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type", "")
            charset = "utf-8"
            if "charset=" in ct:
                charset = ct.split("charset=")[-1].split(";")[0].strip()
            return resp.read().decode(charset, errors="ignore")
    except urllib.error.HTTPError as e:
        print_warn(f"HTTP {e.code}: {url}")
        return None
    except urllib.error.URLError as e:
        print_warn(f"URL error: {url} — {e.reason}")
        return None
    except Exception as e:
        print_warn(f"Fetch error: {url} — {e}")
        return None


# ── Vuln classification ───────────────────────────────────────────────────────

_VULN_KEYWORDS = {
    "xss":          ["xss", "cross-site scripting", "cross site scripting"],
    "ssrf":         ["ssrf", "server-side request forgery", "server side request"],
    "sqli":         ["sql injection", "sqli", "sql"],
    "idor":         ["idor", "insecure direct object", "broken access control"],
    "rce":          ["rce", "remote code execution", "command injection", "code exec"],
    "redirect":     ["open redirect", "open redirection", "url redirect"],
    "auth":         ["authentication bypass", "auth bypass", "login bypass"],
    "authz":        ["authorization", "privilege escalation", "access control"],
    "info-disclosure": ["information disclosure", "sensitive data", "data leak", "leak"],
    "takeover":     ["subdomain takeover", "account takeover"],
    "upload":       ["file upload", "unrestricted upload"],
    "xxe":          ["xxe", "xml external entity"],
    "csrf":         ["csrf", "cross-site request forgery"],
    "logic":        ["business logic", "logic flaw", "race condition"],
    "ssti":         ["ssti", "server-side template injection", "template injection"],
    "deserialization": ["deserialization", "deserialize"],
    "traversal":    ["path traversal", "directory traversal", "../"],
    "prototype":    ["prototype pollution"],
    "graphql":      ["graphql", "introspection"],
}

_TECH_KEYWORDS = [
    "api", "graphql", "oauth", "saml", "jwt", "aws", "s3", "gcp", "azure",
    "php", "node", "python", "ruby", "java", "golang", "laravel", "django",
    "rails", "spring", "wordpress", "drupal", "jira", "confluence", "jenkins",
    "nginx", "apache", "kubernetes", "docker", "react", "angular",
]

_ENDPOINT_KEYWORDS = {
    "login":    ["login", "signin", "sign-in"],
    "api":      ["/api/", "api endpoint", "rest api"],
    "upload":   ["upload", "file", "attachment"],
    "search":   ["search", "query", "filter"],
    "redirect": ["redirect", "return_url", "next=", "url="],
    "admin":    ["admin", "dashboard", "panel"],
    "profile":  ["profile", "account", "user"],
    "checkout": ["checkout", "payment", "cart"],
    "graphql":  ["graphql"],
    "oauth":    ["oauth", "callback", "authorization"],
}


def _classify(text: str) -> tuple[str, str, list[str]]:
    """
    Returns (vuln_class, endpoint_type, tech_hints) from text.
    """
    text_lower = text.lower()

    # Vuln class
    vuln_class = "other"
    for cls, keywords in _VULN_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            vuln_class = cls
            break

    # Endpoint type
    endpoint_type = "general"
    for ep, keywords in _ENDPOINT_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            endpoint_type = ep
            break

    # Tech hints
    tech_hints = [kw for kw in _TECH_KEYWORDS if kw in text_lower]

    return vuln_class, endpoint_type, tech_hints[:5]


def _target_type(text: str) -> str:
    text_lower = text.lower()
    if any(k in text_lower for k in ["mobile", "android", "ios", "app"]):
        return "mobile"
    if any(k in text_lower for k in ["/api/", "rest", "graphql", "grpc"]):
        return "api"
    return "web"


def _slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9\-]", "-", s.lower().strip())[:80].strip("-")


# ── Source 1: pentester.land ──────────────────────────────────────────────────

class _LinkParser(HTMLParser):
    """Minimal HTML parser to extract href links."""
    def __init__(self, base_url: str):
        super().__init__()
        self.links     = []
        self.base_url  = base_url.rstrip("/")

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        for name, val in attrs:
            if name == "href" and val:
                if val.startswith("http"):
                    self.links.append(val)
                elif val.startswith("/"):
                    self.links.append(self.base_url + val)


def fetch_pentesterland(limit: int = 20, debug: bool = False) -> list[dict]:
    """
    Fetch top recent writeups from pentester.land/writeups.
    Returns list of writeup dicts with extracted fields.
    """
    print_info("Fetching pentester.land/writeups...")
    BASE_URL  = "https://pentester.land"
    LIST_URL  = f"{BASE_URL}/writeups"

    html = _get(LIST_URL)
    if not html:
        print_warn("pentester.land unreachable — skipping")
        return []

    # Extract writeup links: pentester.land/writeups/<slug>
    parser = _LinkParser(BASE_URL)
    parser.feed(html)

    writeup_links = [
        lnk for lnk in parser.links
        if "/writeups/" in lnk and lnk != LIST_URL and not lnk.endswith("/writeups")
    ]
    # Deduplicate while preserving order
    seen = set()
    unique_links = []
    for lnk in writeup_links:
        if lnk not in seen:
            seen.add(lnk)
            unique_links.append(lnk)

    if debug:
        print_info(f"  Found {len(unique_links)} unique writeup links")

    writeups = []
    for url in unique_links[:limit]:
        time.sleep(2)  # polite rate limit

        page = _get(url)
        if not page:
            continue

        # Extract title from <title> or <h1>
        title_match = re.search(r"<title>([^<]+)</title>", page, re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else url.split("/")[-1]
        title = re.sub(r"\s*[-|]\s*pentester\.land.*$", "", title, flags=re.IGNORECASE).strip()

        # Extract visible text (strip HTML tags)
        text = re.sub(r"<[^>]+>", " ", page)
        text = re.sub(r"\s+", " ", text).strip()[:3000]

        vuln_class, endpoint_type, tech_hints = _classify(title + " " + text)
        target_type = _target_type(title + " " + text)

        writeups.append({
            "title":         title,
            "url":           url,
            "source":        "pentester.land",
            "vuln_class":    vuln_class,
            "endpoint_type": endpoint_type,
            "target_type":   target_type,
            "tech_hints":    tech_hints,
            "excerpt":       text[:500],
            "fetched_date":  TODAY,
        })

        if debug:
            print_info(f"  [{vuln_class}] {title[:60]}")

    print_ok(f"pentester.land: {len(writeups)} writeups fetched")
    return writeups


# ── Source 2: ngalongc/bug-bounty-reference ───────────────────────────────────

_BB_REF_URL = "https://raw.githubusercontent.com/ngalongc/bug-bounty-reference/master/README.md"

# Map README section headers to vuln classes
_SECTION_MAP = {
    "xss":                   "xss",
    "cross-site scripting":  "xss",
    "sql injection":         "sqli",
    "ssrf":                  "ssrf",
    "server side request":   "ssrf",
    "idor":                  "idor",
    "insecure direct":       "idor",
    "rce":                   "rce",
    "remote code":           "rce",
    "open redirect":         "redirect",
    "subdomain":             "takeover",
    "authentication":        "auth",
    "information disclosure":"info-disclosure",
    "file upload":           "upload",
    "csrf":                  "csrf",
    "xxe":                   "xxe",
    "template injection":    "ssti",
    "ssti":                  "ssti",
    "race condition":        "logic",
    "business logic":        "logic",
    "privilege":             "authz",
    "access control":        "authz",
}


def _section_to_vuln_class(header: str) -> str:
    header_lower = header.lower()
    for keyword, cls in _SECTION_MAP.items():
        if keyword in header_lower:
            return cls
    return "other"


def fetch_bb_reference(debug: bool = False) -> list[dict]:
    """
    Fetch and parse ngalongc/bug-bounty-reference README.
    Extracts per-section writeup links with vuln class labels.
    Returns list of writeup dicts.
    """
    print_info("Fetching ngalongc/bug-bounty-reference...")

    content = _get(_BB_REF_URL)
    if not content:
        print_warn("bug-bounty-reference unreachable — skipping")
        return []

    writeups  = []
    current_section = "general"
    current_class   = "other"

    for line in content.splitlines():
        # Section headers: ## XSS, ### SQL Injection, etc.
        header_match = re.match(r"^#{1,4}\s+(.+)", line)
        if header_match:
            current_section = header_match.group(1).strip()
            current_class   = _section_to_vuln_class(current_section)
            continue

        # Markdown links: - [title](url) or * [title](url)
        link_match = re.match(r"[-*]\s+\[([^\]]+)\]\((https?://[^\)]+)\)", line)
        if not link_match:
            continue

        title = link_match.group(1).strip()
        url   = link_match.group(2).strip()
        if not title or not url:
            continue

        _, endpoint_type, tech_hints = _classify(title + " " + current_section)
        target_type = _target_type(title)

        writeups.append({
            "title":         title,
            "url":           url,
            "source":        "bug-bounty-reference",
            "section":       current_section,
            "vuln_class":    current_class,
            "endpoint_type": endpoint_type,
            "target_type":   target_type,
            "tech_hints":    tech_hints,
            "excerpt":       f"Section: {current_section}. {title}",
            "fetched_date":  TODAY,
        })

    print_ok(f"bug-bounty-reference: {len(writeups)} entries parsed")
    return writeups


# ── Save + index ──────────────────────────────────────────────────────────────

def save_and_index(writeups: list[dict], out_dir: str, debug: bool = False) -> int:
    """Save each writeup as JSON and index into intel_kb. Returns indexed count."""
    os.makedirs(out_dir, exist_ok=True)
    indexed = 0

    for wu in writeups:
        slug = _slugify(wu.get("title", "writeup"))
        if not slug:
            slug = _slugify(wu.get("url", "unknown")[-40:])
        out_path = os.path.join(out_dir, f"{slug}.json")

        try:
            with open(out_path, "w") as f:
                json.dump(wu, f, indent=2)
        except Exception as e:
            if debug: print_warn(f"Save failed for {slug}: {e}")
            continue

        if not _rag:
            continue

        content_parts = [
            f"Title: {wu['title']}",
            f"Source: {wu['source']}",
            f"Vuln class: {wu['vuln_class']}",
            f"Endpoint type: {wu['endpoint_type']}",
            f"Target type: {wu['target_type']}",
            f"URL: {wu['url']}",
        ]
        if wu.get("excerpt"):
            content_parts.append(f"Excerpt: {wu['excerpt']}")
        if wu.get("tech_hints"):
            content_parts.append(f"Tech: {', '.join(wu['tech_hints'])}")

        tags_list = [wu["vuln_class"], wu["target_type"], wu["source"]]
        tags_list += wu.get("tech_hints", [])[:3]

        ok = _rag.index_document(
            source   = "writeup",
            date     = TODAY,
            category = wu["vuln_class"],
            content  = "\n".join(content_parts),
            tags     = " ".join(tags_list),
        )
        if ok:
            indexed += 1
        elif debug:
            print_warn(f"index_document failed for {slug}")

    return indexed


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SOA Ring 3: Writeup Fetcher")
    parser.add_argument("--limit", type=int, default=20, help="Max pentester.land writeups (default 20)")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    out_dir = os.path.join(INTEL_DIR, TODAY)

    # Source 1: pentester.land
    pl_writeups = fetch_pentesterland(limit=args.limit, debug=args.debug)
    # Source 2: bug-bounty-reference
    bb_writeups = fetch_bb_reference(debug=args.debug)

    all_writeups = pl_writeups + bb_writeups
    if not all_writeups:
        print_warn("No writeups fetched from any source")
        return

    print_info(f"Saving {len(all_writeups)} writeups and indexing...")
    indexed = save_and_index(all_writeups, out_dir, debug=args.debug)

    # Vuln class breakdown
    by_class = {}
    for wu in all_writeups:
        cls = wu.get("vuln_class", "other")
        by_class[cls] = by_class.get(cls, 0) + 1

    summary = {
        "date":            TODAY,
        "total_writeups":  len(all_writeups),
        "indexed":         indexed,
        "pentesterland":   len(pl_writeups),
        "bb_reference":    len(bb_writeups),
        "by_vuln_class":   sorted(by_class.items(), key=lambda x: -x[1]),
        "rag_available":   _rag is not None,
    }
    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print_ok(f"Writeups: {len(all_writeups)} total ({len(pl_writeups)} pentester.land + {len(bb_writeups)} bb-ref)")
    print_ok(f"Indexed:  {indexed} into intel_kb")
    print_ok(f"Output:   {out_dir}")

    if not _rag:
        print_warn("RAG not available — writeups saved to disk but not indexed into intel_kb")

    if RICH:
        tbl = Table(title="Writeup Vuln Classes", box=box.SIMPLE_HEAD)
        tbl.add_column("Vuln Class", style="cyan")
        tbl.add_column("Count",      justify="right")
        for cls, cnt in sorted(by_class.items(), key=lambda x: -x[1])[:15]:
            tbl.add_row(cls, str(cnt))
        console.print(tbl)


if __name__ == "__main__":
    main()
