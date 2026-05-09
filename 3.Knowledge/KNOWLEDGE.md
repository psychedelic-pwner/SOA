# Ring 3 — Knowledge Pipeline

Ring 3 is the learning pipeline. It continuously fetches security intel from external sources, indexes everything into `soa.db`'s `intel_kb` FTS5 table, and extracts reusable patterns into semantic JSON files. Everything here feeds the AI components at runtime: `second_eye`, `hunt_planner`, and `attack_chains` all query this KB when analyzing a target.

---

## Directory Structure

```
~/SOA/3.Knowledge/
├── Intel/
│   ├── h1/YYYY-MM-DD/        H1 disclosed reports (raw JSON + summary)
│   ├── writeups/YYYY-MM-DD/  Bug bounty writeups (parsed + indexed)
│   ├── github/YYYY-MM-DD/    Methodology READMEs from GitHub
│   ├── nvd/YYYY-MM-DD/       NVD CVE data (raw + flagged.json)
│   ├── twitter/YYYY-MM-DD/   (reserved — future)
│   ├── htb/                  (reserved — HackTheBox writeups)
│   └── manual/               Drop files here to add manual intel
└── Fetchers/
    ├── 01_h1_fetcher.py
    ├── 02_nvd_fetcher.py
    ├── 03_github_fetcher.py
    ├── 04_writeup_fetcher.py
    └── 05_semantic_extractor.py
```

Semantic output lives in `~/SOA/1.Core/Memory/semantic/`:
```
semantic/
├── tech-patterns.json    { PHP: ["pattern1", ...], nodejs: [...] }
├── vuln-patterns.json    { ssrf: ["technique1", ...], xss: [...] }
└── program-patterns.json { uber: { likes: [...], dislikes: [...], tech: [...] } }
```

---

## How Intel Flows into RAG

Every fetcher calls `04_rag_query.index_document()` after parsing each document:

```python
index_document(
    source   = "h1",            # source name
    date     = "2025-04-10",    # publication/fetch date
    category = "ssrf",          # vuln class or "cve" or "methodology"
    content  = "...",           # full searchable text
    tags     = "critical ssrf uber",  # space-separated
)
```

At runtime, `second_eye` and `hunt_planner` call:
```python
inject_context(query, prompt, top_k=3)
# → prepends [INTEL CONTEXT] block with top-k BM25 matches to the prompt
```

The semantic files (`tech-patterns.json`, etc.) are loaded directly by analysis scripts as structured lookup tables, separate from the FTS5 search.

---

## Running Each Fetcher Manually

```bash
# Requires: H1_TOKEN
python3 ~/SOA/3.Knowledge/Fetchers/01_h1_fetcher.py --limit 100

# No auth required (set NVD_API_KEY for higher rate limits)
python3 ~/SOA/3.Knowledge/Fetchers/02_nvd_fetcher.py --days 7

# Requires: GITHUB_TOKEN (works without but rate-limited)
python3 ~/SOA/3.Knowledge/Fetchers/03_github_fetcher.py

# No auth required
python3 ~/SOA/3.Knowledge/Fetchers/04_writeup_fetcher.py --limit 20

# Requires: ANTHROPIC_API_KEY (reads all Intel/ + episodic/ → extracts patterns)
python3 ~/SOA/3.Knowledge/Fetchers/05_semantic_extractor.py

# Dry-run (no Claude call — just shows what would be processed)
python3 ~/SOA/3.Knowledge/Fetchers/05_semantic_extractor.py --dry-run
```

---

## Adding Manual Intel

Drop any `.md`, `.json`, or `.txt` file into `Intel/manual/` and run the semantic extractor:

```bash
# Example: add a private writeup
cp my_writeup.md ~/SOA/3.Knowledge/Intel/manual/

# Re-run extractor to index it
python3 ~/SOA/3.Knowledge/Fetchers/05_semantic_extractor.py
```

The extractor reads all files in `manual/` and includes them in the Claude batch. The indexed content will appear in intel_kb searches within the same run.

To manually index a document without running the full extractor:
```python
# From Python or REPL
import importlib.util, os
path = os.path.expanduser("~/SOA/1.Core/Memory/04_rag_query.py")
spec = importlib.util.spec_from_file_location("rag_query", path)
mod  = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

mod.index_document(
    source   = "manual",
    date     = "2025-04-10",
    category = "ssrf",          # or any vuln class
    content  = "Your content here",
    tags     = "manual ssrf your_target",
)
```

---

## Required Environment Variables

| Variable          | Used by           | Required?      |
|-------------------|-------------------|----------------|
| `H1_TOKEN`        | 01_h1_fetcher     | Yes (skip if missing) |
| `NVD_API_KEY`     | 02_nvd_fetcher    | No (higher rate limit) |
| `GITHUB_TOKEN`    | 03_github_fetcher | No (lower rate limit without) |
| `ANTHROPIC_API_KEY` | 05_semantic_extractor | Yes (skip if missing) |

All keys read via `os.environ`. None are hardcoded. Missing keys → warn + skip gracefully.

---

## Fetcher Schedule (Cron)

Recommended schedule in `~/SOA/1.Core/Agents/CronJobs/cron_nightly.sh`:

| Fetcher              | Frequency | Notes |
|----------------------|-----------|-------|
| `01_h1_fetcher.py`   | Weekly    | Rate-limited by H1 GraphQL |
| `02_nvd_fetcher.py`  | Daily     | `--days 7` catches new HIGH/CRITICAL |
| `03_github_fetcher.py` | Weekly  | Deduplicates via on-disk check |
| `04_writeup_fetcher.py` | Daily  | pentester.land updates frequently |
| `05_semantic_extractor.py` | Nightly | Runs after all fetchers complete |

Add to `cron_nightly.sh`:
```bash
# Ring 3 — knowledge pipeline
FETCHERS="$SOA_DIR/3.Knowledge/Fetchers"
python3 "$FETCHERS/02_nvd_fetcher.py" --days 1 >> "$LOG_PATH" 2>&1
python3 "$FETCHERS/04_writeup_fetcher.py" --limit 10 >> "$LOG_PATH" 2>&1
python3 "$FETCHERS/05_semantic_extractor.py" >> "$LOG_PATH" 2>&1
```

Weekly (separate cron entry, e.g. Sunday 03:00):
```bash
python3 "$FETCHERS/01_h1_fetcher.py" --limit 100 >> "$LOG_PATH" 2>&1
python3 "$FETCHERS/03_github_fetcher.py" >> "$LOG_PATH" 2>&1
```

---

## Verifying the KB

```bash
# Count indexed documents
python3 ~/SOA/1.Core/Memory/04_rag_query.py

# Test a search
python3 -c "
import importlib.util, os
path = os.path.expanduser('~/SOA/1.Core/Memory/04_rag_query.py')
spec = importlib.util.spec_from_file_location('rag', path)
mod  = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
for r in mod.search_intel('ssrf open redirect', top_k=3):
    print(r['source'], r['category'], r['content'][:80])
"
```
