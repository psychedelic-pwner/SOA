#!/usr/bin/env python3
"""
SOA Ring 3 — Semantic Extractor  [Knowledge-05]
Source: original — implements the "semantic memory layer" described in
        son-of-anton docs but never built there.

Nightly script. Reads intel_kb + episodic memory → calls Claude API →
extracts and merges patterns into semantic JSON files.

Semantic files live in ~/SOA/1.Core/Memory/semantic/ and are queried
at runtime by second_eye and hunt_planner via inject_context().

Files managed:
  tech-patterns.json   — per-tech vulnerability patterns
  vuln-patterns.json   — vuln class → technique patterns
  program-patterns.json — per-program behavioral patterns (likes/dislikes)

Process:
  1. Read recent Intel/h1/ + Intel/writeups/ JSON files
  2. Read episodic/<target>/*.json files
  3. Batch content → Claude API (claude-sonnet-4-6)
  4. Parse returned JSON
  5. Merge/append into existing semantic files (never overwrite)
  6. Print extraction summary

Usage:
  python3 05_semantic_extractor.py [--debug] [--dry-run]
"""

import importlib.util
import json
import os
import re
import sys
from datetime import date, datetime
from pathlib import Path

BASE_DIR     = os.path.expanduser("~/SOA")
MEMORY_DIR   = os.path.join(BASE_DIR, "1.Core", "Memory")
SEMANTIC_DIR = os.path.join(MEMORY_DIR, "semantic")
EPISODIC_DIR = os.path.join(MEMORY_DIR, "episodic")
INTEL_DIR    = os.path.join(BASE_DIR, "3.Knowledge", "Intel")
TODAY        = date.today().isoformat()

CLAUDE_MODEL = "claude-sonnet-4-6"
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

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


# ── Load existing semantic files ──────────────────────────────────────────────

def _load_semantic(filename: str) -> dict:
    path = os.path.join(SEMANTIC_DIR, filename)
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_semantic(filename: str, data: dict) -> None:
    os.makedirs(SEMANTIC_DIR, exist_ok=True)
    path = os.path.join(SEMANTIC_DIR, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# ── Content collection ────────────────────────────────────────────────────────

def collect_h1_content(max_docs: int = 50) -> list[str]:
    """Read recent H1 intel JSON files. Returns list of content strings."""
    chunks = []
    h1_dir = os.path.join(INTEL_DIR, "h1")
    if not os.path.isdir(h1_dir):
        return chunks

    # Walk day dirs sorted newest-first
    day_dirs = sorted(Path(h1_dir).iterdir(), reverse=True)
    count = 0
    for day_dir in day_dirs:
        if not day_dir.is_dir():
            continue
        for fpath in day_dir.glob("*.json"):
            if fpath.name == "summary.json":
                continue
            try:
                data = json.loads(fpath.read_text())
            except Exception:
                continue
            title   = data.get("title", "")
            vuln_cls = data.get("vuln_class", "")
            weakness = data.get("weakness_name", "")
            team     = data.get("team_handle", "")
            severity = data.get("severity", "")
            hints    = ", ".join(data.get("tech_hints", []))

            chunk = (
                f"H1 {severity.upper()}: {title}\n"
                f"Vuln: {vuln_cls} | Weakness: {weakness}\n"
                f"Team: {team} | Tech: {hints}"
            )
            chunks.append(chunk)
            count += 1
            if count >= max_docs:
                return chunks
    return chunks


def collect_writeup_content(max_docs: int = 50) -> list[str]:
    """Read recent writeup JSON files. Returns list of content strings."""
    chunks = []
    wr_dir = os.path.join(INTEL_DIR, "writeups")
    if not os.path.isdir(wr_dir):
        return chunks

    day_dirs = sorted(Path(wr_dir).iterdir(), reverse=True)
    count = 0
    for day_dir in day_dirs:
        if not day_dir.is_dir():
            continue
        for fpath in day_dir.glob("*.json"):
            if fpath.name == "summary.json":
                continue
            try:
                data = json.loads(fpath.read_text())
            except Exception:
                continue
            title    = data.get("title", "")
            vuln_cls = data.get("vuln_class", "")
            endpoint = data.get("endpoint_type", "")
            target_t = data.get("target_type", "")
            tech     = ", ".join(data.get("tech_hints", []))
            excerpt  = data.get("excerpt", "")[:200]

            chunk = (
                f"Writeup [{vuln_cls}]: {title}\n"
                f"Endpoint: {endpoint} | Target: {target_t} | Tech: {tech}\n"
                f"{excerpt}"
            )
            chunks.append(chunk)
            count += 1
            if count >= max_docs:
                return chunks
    return chunks


def collect_episodic_content(max_targets: int = 10) -> list[str]:
    """Read episodic memory files. Returns list of content strings."""
    chunks = []
    if not os.path.isdir(EPISODIC_DIR):
        return chunks

    for target_dir in sorted(Path(EPISODIC_DIR).iterdir())[:max_targets]:
        if not target_dir.is_dir():
            continue
        target_name = target_dir.name
        for fpath in sorted(target_dir.glob("*.json"), reverse=True)[:3]:
            try:
                data = json.loads(fpath.read_text())
            except Exception:
                continue

            findings = data.get("findings", [])
            vulns    = [f.get("vuln_class", "") for f in findings if f.get("vuln_class")]
            tech     = data.get("tech_stack", [])
            if isinstance(tech, list):
                tech_str = ", ".join(str(t) for t in tech[:5])
            else:
                tech_str = str(tech)

            chunk_parts = [f"Program: {target_name}"]
            if tech_str:
                chunk_parts.append(f"Tech stack: {tech_str}")
            if vulns:
                chunk_parts.append(f"Found vulns: {', '.join(set(vulns))}")
            # Any decisions or hypotheses
            decisions = data.get("decisions_log", [])
            if decisions:
                chunk_parts.append(f"Decisions: {decisions[0][:100]}")

            chunks.append("\n".join(chunk_parts))

    return chunks


def collect_manual_content() -> list[str]:
    """Read manual intel files (.md or .json)."""
    chunks = []
    manual_dir = os.path.join(INTEL_DIR, "manual")
    if not os.path.isdir(manual_dir):
        return chunks

    for fpath in Path(manual_dir).rglob("*"):
        if fpath.suffix not in (".md", ".json", ".txt"):
            continue
        try:
            text = fpath.read_text(errors="ignore")[:2000]
            chunks.append(f"[Manual Intel: {fpath.name}]\n{text}")
        except Exception:
            continue
    return chunks


# ── Claude API call ───────────────────────────────────────────────────────────

_EXTRACT_PROMPT = """\
You are a bug bounty pattern extractor. I will give you security intel (H1 reports, writeups, program history).
Extract reusable patterns. Return ONLY valid JSON — no markdown, no prose, exactly this structure:

{
  "tech_patterns": {
    "<tech_name>": ["<pattern1>", "<pattern2>"]
  },
  "vuln_patterns": {
    "<vuln_class>": ["<technique1>", "<technique2>"]
  },
  "program_patterns": {
    "<program_name>": {
      "likes": ["<finding_type1>"],
      "dislikes": ["<finding_type1>"],
      "tech": ["<tech1>"]
    }
  }
}

Rules:
- tech_patterns: map technology names to common vulnerability patterns seen with that tech
- vuln_patterns: map vuln classes to specific attack techniques (be concrete, e.g. "blind SSRF via webhook URL parameter")
- program_patterns: only include programs explicitly mentioned in the content
- Keep patterns short and actionable (under 120 chars each)
- Maximum 5 patterns per key
- If no data for a category, use empty dict {}

Content to analyze:
"""


def call_claude(content: str, debug: bool = False) -> dict | None:
    """
    Call Claude API with batched content.
    Returns parsed JSON dict or None on failure.
    """
    if not ANTHROPIC_KEY:
        print_warn("ANTHROPIC_API_KEY not set — skipping Claude extraction")
        return None

    # Try to use 07_agent_backend.py (async streaming)
    backend_path = os.path.join(MEMORY_DIR, "07_agent_backend.py")
    if os.path.exists(backend_path):
        try:
            spec = importlib.util.spec_from_file_location("agent_backend", backend_path)
            mod  = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            text, cost = mod.run_query(
                prompt      = _EXTRACT_PROMPT + content,
                system_prompt = "You extract patterns from security intel. Return only valid JSON.",
                model       = CLAUDE_MODEL,
            )
            if debug and cost:
                print_info(f"Claude cost: ${cost:.4f}")
            return _parse_json_response(text)
        except Exception as e:
            if debug: print_warn(f"agent_backend failed: {e} — falling back to direct SDK")

    # Fallback: direct anthropic SDK
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
        msg    = client.messages.create(
            model      = CLAUDE_MODEL,
            max_tokens = 2048,
            system     = "You extract patterns from security intel. Return only valid JSON.",
            messages   = [{"role": "user", "content": _EXTRACT_PROMPT + content}],
        )
        text = msg.content[0].text if msg.content else ""
        return _parse_json_response(text)
    except ImportError:
        print_warn("anthropic SDK not installed — pip install anthropic")
        return None
    except Exception as e:
        print_err(f"Claude API call failed: {e}")
        return None


def _parse_json_response(text: str) -> dict | None:
    """Extract JSON from Claude response (handles markdown code fences)."""
    if not text:
        return None

    # Strip markdown fences
    text = text.strip()
    fence_match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
    if fence_match:
        text = fence_match.group(1)

    # Find first { ... } block
    brace_match = re.search(r"\{[\s\S]+\}", text)
    if brace_match:
        text = brace_match.group(0)

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        return None


# ── Merge patterns ────────────────────────────────────────────────────────────

def _merge_list_patterns(existing: list, new_items: list, max_per_key: int = 20) -> list:
    """Append new items to existing list, deduplicating."""
    existing_set = {s.lower() for s in existing}
    for item in new_items:
        if isinstance(item, str) and item.lower() not in existing_set:
            existing.append(item)
            existing_set.add(item.lower())
    return existing[:max_per_key]


def merge_tech_patterns(existing: dict, extracted: dict) -> tuple[dict, int]:
    """Merge new tech patterns into existing. Returns (merged, added_count)."""
    added = 0
    for tech, patterns in extracted.items():
        if not isinstance(patterns, list):
            continue
        if tech not in existing:
            existing[tech] = []
        before = len(existing[tech])
        existing[tech] = _merge_list_patterns(existing[tech], patterns)
        added += len(existing[tech]) - before
    return existing, added


def merge_vuln_patterns(existing: dict, extracted: dict) -> tuple[dict, int]:
    """Merge new vuln patterns into existing."""
    added = 0
    for vuln_class, techniques in extracted.items():
        if not isinstance(techniques, list):
            continue
        if vuln_class not in existing:
            existing[vuln_class] = []
        before = len(existing[vuln_class])
        existing[vuln_class] = _merge_list_patterns(existing[vuln_class], techniques)
        added += len(existing[vuln_class]) - before
    return existing, added


def merge_program_patterns(existing: dict, extracted: dict) -> tuple[dict, int]:
    """Merge new program patterns into existing."""
    added = 0
    for program, data in extracted.items():
        if not isinstance(data, dict):
            continue
        if program not in existing:
            existing[program] = {"likes": [], "dislikes": [], "tech": []}
        prog = existing[program]
        for key in ("likes", "dislikes", "tech"):
            new_vals = data.get(key, [])
            if isinstance(new_vals, list):
                before = len(prog.get(key, []))
                prog[key] = _merge_list_patterns(prog.get(key, []), new_vals)
                added += len(prog[key]) - before
    return existing, added


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SOA Ring 3: Semantic Extractor")
    parser.add_argument("--debug",   action="store_true")
    parser.add_argument("--dry-run", action="store_true",
                        help="Collect + print content, skip Claude call")
    args = parser.parse_args()

    os.makedirs(SEMANTIC_DIR, exist_ok=True)

    # ── 1. Collect content ─────────────────────────────────────────────────────
    print_info("Collecting intel content...")
    h1_chunks       = collect_h1_content(max_docs=40)
    writeup_chunks  = collect_writeup_content(max_docs=40)
    episodic_chunks = collect_episodic_content(max_targets=10)
    manual_chunks   = collect_manual_content()

    all_chunks = h1_chunks + writeup_chunks + episodic_chunks + manual_chunks
    print_info(f"  H1 reports:    {len(h1_chunks)}")
    print_info(f"  Writeups:      {len(writeup_chunks)}")
    print_info(f"  Episodic:      {len(episodic_chunks)}")
    print_info(f"  Manual intel:  {len(manual_chunks)}")
    print_info(f"  Total chunks:  {len(all_chunks)}")

    if not all_chunks:
        print_warn("No content found — run fetchers first")
        return

    # Batch into ~4000-char chunks (stay well under token limits)
    # We'll send one representative batch to Claude
    batch_text = "\n\n---\n\n".join(all_chunks[:60])[:12_000]

    if args.dry_run:
        print_info("Dry-run — first 500 chars of batch content:")
        print(batch_text[:500])
        print_info("Dry-run complete — no Claude call made")
        return

    if not ANTHROPIC_KEY:
        print_warn("ANTHROPIC_API_KEY not set — cannot run extraction")
        print_info("Set it: export ANTHROPIC_API_KEY=sk-ant-...")
        print_info("Files saved to disk are still searchable manually")
        return

    # ── 2. Call Claude ─────────────────────────────────────────────────────────
    print_info(f"Calling Claude ({CLAUDE_MODEL}) for pattern extraction...")
    extracted = call_claude(batch_text, debug=args.debug)

    if not extracted:
        print_err("Pattern extraction failed — no usable JSON returned")
        return

    if args.debug:
        print_info(f"Extracted keys: {list(extracted.keys())}")

    # ── 3. Load existing semantic files ────────────────────────────────────────
    tech_existing    = _load_semantic("tech-patterns.json")
    vuln_existing    = _load_semantic("vuln-patterns.json")
    program_existing = _load_semantic("program-patterns.json")

    # ── 4. Merge ───────────────────────────────────────────────────────────────
    tech_merged,    tech_added    = merge_tech_patterns(
        tech_existing, extracted.get("tech_patterns", {}))
    vuln_merged,    vuln_added    = merge_vuln_patterns(
        vuln_existing, extracted.get("vuln_patterns", {}))
    program_merged, prog_added    = merge_program_patterns(
        program_existing, extracted.get("program_patterns", {}))

    # ── 5. Save ────────────────────────────────────────────────────────────────
    # Add metadata
    meta = {"last_updated": TODAY, "source_docs": len(all_chunks)}
    tech_merged["_meta"]    = meta
    vuln_merged["_meta"]    = meta
    program_merged["_meta"] = meta

    _save_semantic("tech-patterns.json",    tech_merged)
    _save_semantic("vuln-patterns.json",    vuln_merged)
    _save_semantic("program-patterns.json", program_merged)

    # ── 6. Also index summary into intel_kb ────────────────────────────────────
    rag_path = os.path.join(MEMORY_DIR, "04_rag_query.py")
    if os.path.exists(rag_path):
        try:
            spec = importlib.util.spec_from_file_location("rag_query", rag_path)
            mod  = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            # Index a digest of the top vuln patterns
            top_vulns = [
                f"{cls}: {', '.join(v[:2])}"
                for cls, v in vuln_merged.items()
                if cls != "_meta" and isinstance(v, list)
            ][:10]
            if top_vulns:
                mod.index_document(
                    source   = "semantic",
                    date     = TODAY,
                    category = "patterns",
                    content  = "Extracted vuln patterns:\n" + "\n".join(top_vulns),
                    tags     = "semantic patterns vuln_techniques",
                )
        except Exception as e:
            if args.debug: print_warn(f"RAG index error: {e}")

    # ── Summary ────────────────────────────────────────────────────────────────
    tech_count    = len([k for k in tech_merged    if k != "_meta"])
    vuln_count    = len([k for k in vuln_merged    if k != "_meta"])
    program_count = len([k for k in program_merged if k != "_meta"])

    print_ok(f"tech-patterns.json:    {tech_count} techs, +{tech_added} new patterns")
    print_ok(f"vuln-patterns.json:    {vuln_count} classes, +{vuln_added} new patterns")
    print_ok(f"program-patterns.json: {program_count} programs, +{prog_added} new patterns")
    print_ok(f"Semantic dir:          {SEMANTIC_DIR}")

    if RICH:
        tbl = Table(title="Semantic Extraction Summary", box=box.SIMPLE_HEAD)
        tbl.add_column("File",          style="cyan")
        tbl.add_column("Keys",          justify="right")
        tbl.add_column("New Patterns",  justify="right")
        tbl.add_row("tech-patterns.json",    str(tech_count),    f"+{tech_added}")
        tbl.add_row("vuln-patterns.json",    str(vuln_count),    f"+{vuln_added}")
        tbl.add_row("program-patterns.json", str(program_count), f"+{prog_added}")
        console.print(tbl)

        if vuln_merged:
            tbl2 = Table(title="Top Vuln Patterns", box=box.SIMPLE_HEAD)
            tbl2.add_column("Vuln Class",  style="yellow")
            tbl2.add_column("Techniques")
            for cls, techniques in list(vuln_merged.items())[:8]:
                if cls == "_meta": continue
                if isinstance(techniques, list):
                    tbl2.add_row(cls, "; ".join(techniques[:2]))
            console.print(tbl2)


if __name__ == "__main__":
    main()
