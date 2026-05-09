# 🧠 Son-of-Anton (SOA) — Master Blueprint
> Version: 2.0 | Status: Active Build | Last updated: 2026-04-09
> Vision: Autonomous bug bounty hunting agent with persistent memory, continuous learning, and reasoning brain.

---

## 🪪 Identity

SOA is not a scanner. SOA is not a script runner.
SOA is a fully agentic bug bounty hunting cognitive architecture — autonomous, self-learning, reasoning.

Two operating modes:
- 🔴 **SON-OF-ANTON** — Bug bounty. High/critical only. Aggressive recon. No reporting.
- 🔵 **ANTON** — Client work. All severities. Professional tone. Penligent integrated.

🎯 Platform: HackerOne
📋 Targets: Uber → Playtika → Nextcloud → DoD VDP
🧪 Test only: olacabs.com

---

## 🎯 Hunting Philosophy

**Two-Eye Approach:**
- First Eye = Systematic. Every subdomain, endpoint, parameter. Full pipeline always runs.
- Second Eye = Intuition. Claude unstructured pass after First Eye. No rules. Pure reasoning.

**Core Methodology:**
> "Shallow pass everything. Deep dive on signal. That's the whole game."

**Opportunistic Flow (post-httpx):**
```
Step 1 → Second Eye pass (Claude reads all output, flags anomalies)
Step 2 → Bucket ROI triage (red→orange→yellow priority)
Step 3 → Fast wins sweep (subzy, nuclei default-logins, git-config — automated)
Step 4 → Signal check (exploitable? scoped? duplicate?)
Step 5 → Manual Burp (YOU ONLY — read logic, find flaw, 30min timebox)
Step 6 → Pivot (confirmed→PoC+genealogy / dead→curious.json)
Step 7 → URL collection background (gau+katana parallel)

SOA automates: 1,2,3,4,6,7
Vaibhav owns: Step 5 only
```

**Reasoning Principles:**
- ARC: Every SOA decision must be explainable in plain language. Cannot explain = goes to curious.json.
- Winograd: SOA must resolve ambiguity using context — program notes, triage behavior, tech stack.

---

## 🖥️ System Architecture

```
MAC (primary)                    WINDOWS (manual testing)
─────────────────────            ──────────────────────────
Terminal                         Claude Desktop
Claude Code (CC)                 Burp Suite Pro + Logger++
claude.ai (web)                  Browser + Claude Extension
SOA pipeline scripts             Ollama (local models)
Dashboard (Flask)                Manual hunt sessions
soa.db + brain files
```

**Infrastructure:**
| Component | Detail |
|---|---|
| 💻 Mac | M1 Air, macOS, hostname: hackerbook |
| 🖥️ Windows | 32GB RAM, Kali VM 16GB |
| 🌐 VPS | Hetzner CX43, HEX, Ubuntu 24.04, psychichacker.xyz |
| 🐙 GitHub | github.com/psyc177 (private: Son-of-Anton-SOA) |

---

## 📁 Full Directory Structure

```
~/son-of-anton/
│
├── 📋 CLAUDE.md                        # Identity layer — read every session
├── 🚀 run_soa.py                       # Full agentic loop launcher
│
├── phases/                             # COMPONENT 1: PIPELINE
│   ├── phase0/
│   │   └── phase0.py                   # Scope ingestion, project setup
│   ├── phase1/
│   │   ├── phase1a.py                  # Passive: subfinder+github-subs+chaos
│   │   ├── phase1b.py                  # Resolve: puredns+dnsx
│   │   ├── phase1c.py                  # Probe: httpx (flags locked)
│   │   └── phase1d_buckets.py          # Bucket classification (18 buckets)
│   ├── phase2/                         # Logic layer scripts
│   │   ├── second_eye.py               # L9 Intuition — Claude unstructured pass
│   │   ├── anomaly_scorer.py           # L2 Scoring — scores every host 1-10
│   │   ├── confidence_scorer.py        # L2 Scoring — finding confidence 1-10
│   │   ├── hunt_planner.py             # L12 Planning — dynamic hunt plan
│   │   ├── attack_chains.py            # L11 Creative — attack chain CoT
│   │   └── creative_leads.py           # L11 Creative — novel hypotheses
│   ├── phase3/
│   │   ├── triage.py                   # L8 Judgment — quality gate
│   │   ├── fp_suppressor.py            # L13 Learning — FP suppress list
│   │   └── scope_check.py              # L14 Instinct — hard scope rules
│   ├── phase4/                         # Enum scripts (nmap, dirsearch, arjun)
│   ├── hunt/                           # HUNT SCRIPTS (bucket-triggered)
│   │   ├── hunt_watcher.py             # File watcher — triggers on bucket fill
│   │   ├── takeover.py                 # 404 bucket: subzy+subjack+nuclei+curl
│   │   ├── devstaging.py               # dev-staging: git-config+env exposure
│   │   ├── admin_panels.py             # exposed-services: default creds
│   │   ├── cloud.py                    # cloud bucket: S3/Azure/GCP misconfig
│   │   ├── cms.py                      # cms bucket: nuclei WP/Joomla
│   │   ├── api_hunt.py                 # api bucket: IDOR+auth+mass-assign
│   │   ├── ssrf_hunt.py                # ssrf-redirect: ssrfmap
│   │   ├── xss_hunt.py                 # params: kxss→dalfox
│   │   ├── sqli_hunt.py                # params: sqlmap
│   │   └── js_hunt.py                  # js-files: secretfinder+trufflehog
│   └── brain/                          # BRAIN SCRIPTS
│       ├── soa_memory.py               # CLI: init/session/episodic/targets
│       ├── episodic_write.py           # L4 Episodic writer
│       ├── self_state_updater.py       # L3 State — updates self-state.json
│       └── semantic_extractor.py       # L5 Semantic — extracts patterns nightly
│
├── memory/                             # COMPONENT 2: BRAIN STORAGE
│   ├── soa.db                          # L7 LTM — SQLite permanent storage
│   ├── self-state.json                 # L3 State — SOA current state
│   ├── episodic/
│   │   └── <target>/
│   │       └── YYYY-MM-DD.json         # L4 Episodic — per-hunt records
│   ├── semantic/
│   │   ├── tech-patterns.json          # L5 Semantic — tech→known vulns
│   │   ├── vuln-patterns.json          # L5 Semantic — param type→vuln class
│   │   └── program-patterns.json       # L5 Semantic — program triage behavior
│   └── suppressions/
│       └── <target>.json               # L13 Learning — per-target FP list
│
├── intel/                              # COMPONENT 3: LEARNING PIPELINE
│   ├── h1/                             # H1 disclosed reports via API
│   ├── writeups/                       # Medium/blogs via Google dork
│   ├── github/                         # Checklists/README via GitHub dork
│   ├── htb/                            # HTB/Burp labs solutions
│   ├── twitter/                        # Grok API fetch
│   ├── manual/                         # Vaibhav's manual feeds
│   └── lessons/                        # Processed → feeds semantic/*.json
│
├── projects/                           # PER-TARGET WORKING DIRS
│   └── <target>/
│       ├── session.json                # L3 Working memory — current hunt
│       ├── curious.json                # L10 Curiosity — unclassified
│       ├── creative-leads.json         # L11 Creative — manual hunt leads
│       ├── phase0/
│       │   ├── config.json
│       │   ├── domains.txt
│       │   ├── urls.txt
│       │   ├── wildcards.txt
│       │   └── out-of-scope.txt
│       ├── phase1/
│       │   ├── passive/
│       │   │   ├── all-passive.txt
│       │   │   ├── subfinder.txt
│       │   │   ├── github.txt
│       │   │   ├── chaos.txt
│       │   │   └── passive-summary.json
│       │   ├── active/
│       │   │   ├── puredns.txt
│       │   │   ├── dnsx.json
│       │   │   └── active-summary.json
│       │   ├── probing/
│       │   │   ├── httpx.json
│       │   │   ├── live-domain.txt
│       │   │   └── probing-summary.json
│       │   ├── buckets/
│       │   │   ├── takeover.txt        # 404s
│       │   │   ├── 401.txt             # Unauthorized
│       │   │   ├── dev-staging.txt
│       │   │   ├── login.txt
│       │   │   ├── forbidden.txt
│       │   │   ├── errors.txt          # 5xx
│       │   │   ├── cloud.txt
│       │   │   ├── cms.txt
│       │   │   ├── legacy.txt
│       │   │   ├── admin-panels.txt
│       │   │   ├── interesting.txt     # 200
│       │   │   ├── config.txt
│       │   │   ├── params.txt
│       │   │   ├── ssrf-redirect.txt
│       │   │   ├── api.txt
│       │   │   ├── js.txt
│       │   │   ├── internal.txt        # RFC1918 IPs
│       │   │   └── bucket-summary.json
│       │   ├── urls/
│       │   │   ├── urls.txt
│       │   │   ├── gau.txt
│       │   │   └── katana.txt
│       │   └── responses/              # httpx stored responses
│       ├── phase2/
│       │   ├── hunt/
│       │   │   ├── scored-hosts.json   # L2 anomaly scores
│       │   │   ├── anomaly-ranked.json # L9 Second Eye output
│       │   │   ├── hunt-plan.json      # L12 dynamic plan
│       │   │   ├── 1-takeover/
│       │   │   │   ├── subzy-result.json
│       │   │   │   ├── subjack-result.json
│       │   │   │   ├── nuclei-result.json
│       │   │   │   ├── curl-results.json
│       │   │   │   └── final-takeover-report.json
│       │   │   ├── 2-devstaging/
│       │   │   ├── 3-admin/
│       │   │   ├── 4-api/
│       │   │   └── ...
│       │   ├── intel/                  # per-target CVE/H1 intel
│       │   ├── js/                     # JS analysis output
│       │   └── mindmap/
│       ├── phase3/
│       │   ├── vuln-candidates/        # gf pattern output
│       │   └── vuln-results/           # confirmed findings
│       ├── phase3_5/                   # WAF canary
│       ├── phase4/                     # enum results
│       ├── manual/                     # Manual testing queue
│       │   └── session-YYYYMMDD.md     # Hunt session notes
│       ├── finished/                   # Completed targets
│       └── logs/
│           ├── phase1a.log
│           ├── phase1b.log
│           ├── phase1c.log
│           ├── phase1d.log
│           ├── manual-YYYYMMDD.log     # script session log
│           ├── moves.log
│           └── errors.log
│
├── dashboard/                          # COMPONENT 4: INTERFACE
│   ├── app.py                          # Flask backend
│   ├── templates/
│   └── static/
│
├── resources/
│   ├── wordlists/
│   │   ├── best-dns-wordlist.txt
│   │   ├── permutations.txt
│   │   └── api-endpoints.txt
│   ├── patterns/                       # L8 Judgment fingerprints
│   │   └── *.yaml                      # response signatures
│   ├── resolvers.txt
│   └── .api-keys.txt                   # reference only
│
└── crons/                              # COMPONENT 5: NIGHTLY (L15 Flow)
    ├── cron_nightly.sh                 # master cron runner
    ├── git_push.py                     # nightly git commit+push
    ├── readme_gen.py                   # README template gen
    ├── nuclei_update.py                # nuclei -ut daily
    ├── subdomain_monitor.py            # diff new subs → notify
    └── semantic_cron.py                # episodic→semantic extraction
```

---

## 🧠 COMPONENT 2: BRAIN — 15 Layers

> Build order: L7→L3→L4→L2→L13→L10→L5→L12→L9→L8→L11→L14→L15→L1→Flow

### L1 — Perception
**What**: Raw data ingestion
**Scripts**: phase1a.py, phase1b.py, phase1c.py, phase1d_buckets.py
**Output**: httpx.json, dnsx.json, all-passive.txt, bucket files
**Rule**: All outputs normalized to JSON before reasoning layer reads them

### L2 — Scoring (Anomaly + Confidence merged)
**What**: What deserves focus + how confident are we
**Scripts**: anomaly_scorer.py, confidence_scorer.py
**Input**: httpx.json
**Output**: scored-hosts.json (anomaly 1-10), finding confidence in soa.db
**Rule**: High score → Phase 3 priority. ARC test must pass for high confidence.

### L3 — State (Working Memory + Self-awareness merged)
**What**: SOA knows where it is — this hunt and globally
**Files**: session.json (per target), self-state.json (global)
**session.json holds**: current phase, completed steps, open anomalies, hypotheses, decisions
**self-state.json holds**: active targets, last 10 decisions, uncertainty flags, global stats
**Updates**: after every phase, after every decision, end of session

### L4 — Episodic Memory
**What**: Record of every past hunt
**Script**: episodic_write.py
**Output**: memory/episodic/<target>/YYYY-MM-DD.json
**Holds**: phases run, findings, failures, anomalies, decisions, next focus
**When**: run manually at end of every hunt session

### L5 — Semantic Memory
**What**: Extracted wisdom from all experiences
**Files**: semantic/tech-patterns.json, vuln-patterns.json, program-patterns.json
**Feeds from**: episodic/ (weekly cron) + intel/ (daily cron)
**Example**: "Nextcloud exposes /ocs/v2.php" / "Uber triages IDOR fast"

### L6 — Procedural Memory
**What**: How to do things — automatic execution
**Scripts**: All phase scripts + hunt scripts
**Rule**: Each phase reads session.json on start, writes completion on end

### L7 — Long-term Memory (soa.db)
**What**: Everything permanent
**File**: memory/soa.db (SQLite)
**Tables**: targets, subdomains, findings, false_positives, decisions, hunt_sessions
**Rule**: Never store absolute paths — target name + relative paths only

### L8 — Judgment (Pattern Recognition + Triage merged)
**What**: Classify things + quality gate before findings reach Vaibhav
**Scripts**: triage.py + resources/patterns/*.yaml
**Input**: hunt results, httpx responses
**Output**: verdict (confirmed/FP/needs-more/duplicate)
**Rule**: Winograd test — would THIS program's triager accept this?

### L9 — Intuition (Second Eye)
**What**: Fast unstructured judgment — no rules
**Script**: second_eye.py
**Input**: httpx.json + all bucket files
**Output**: anomaly-ranked.json (plain language reasoning per anomaly)
**When**: After Phase 1 completes, before hunt scripts start
**Rule**: ARC principle — if SOA can't explain why → curious.json not findings

### L10 — Curiosity
**What**: Investigate the unknown instead of discarding
**File**: projects/<target>/curious.json
**When**: Anything SOA can't classify → goes here
**Rule**: Reviewed end of each phase. Never discarded.

### L11 — Creative (Imagination + Creativity merged)
**What**: Novel attack chains + unchained hypotheses
**Scripts**: attack_chains.py, creative_leads.py
**Output**: creative-leads.json (manual leads for Vaibhav)
**When**: After Phase 2 mindmap, before Phase 3
**Rule**: ARC — must be reasoned from first principles, not pattern-matched

### L12 — Planning (Planning + Decision Making merged)
**What**: Multi-step goal pursuit + fork decisions
**Script**: hunt_planner.py
**Output**: hunt-plan.json written to session.json
**When**: Hunt start — plan generated, adapts if Phase 1 finds anomalies
**Rule**: Bucket filter for clear cases, Claude for ambiguous forks

### L13 — Learning (FP Suppressor)
**What**: Gets smarter from your decisions
**Script**: fp_suppressor.py
**Files**: memory/suppressions/<target>.json
**Loop**: Your confirm/reject → soa.db → suppress list → next scan skips

### L14 — Instinct (Hard Rules)
**What**: Non-negotiable reflexes — never overridden by reasoning
**Scripts**: scope_check.py, rate_limiter.py (embedded in every script)
**Rules**: Scope check before every request. Rate limit always enforced.
**Rule**: These are if-statements, not AI decisions. Instinct is never bypassed.

### L15 — Flow (Agentic Loop + Crons merged)
**What**: Full autonomous execution + nightly offline work
**Scripts**: run_soa.py (agentic loop), crons/ (4 nightly jobs)
**Crons**: git push, README gen, nuclei -ut, subdomain monitor
**Flow**: reads L3+L4+L5 → runs phases adaptively → stops for findings or completion

---

## 📚 COMPONENT 3: LEARNING PIPELINE

> All feeds → intel/ → semantic_extractor.py → semantic/*.json → L5 Semantic

```
SOURCE                    METHOD                    FREQUENCY
──────────────────────────────────────────────────────────────
H1 disclosed reports      H1 API (H1_TOKEN)         Daily cron
Writeups / blogs          Google dork automation    Daily cron
GitHub checklists         GitHub dork automation    Daily cron
HTB / Burp labs           GitHub scrape             Weekly
Personal hunt data        episodic_write.py         Per hunt
Twitter/X intel           Grok API                  Daily cron
Manual feeds              Vaibhav direct inject     On demand
NVD / CISA KEV / GHSA    API pull                  Daily cron
```

**intel/ structure:**
```
intel/
├── h1/YYYY-MM-DD/          # raw H1 reports
├── writeups/YYYY-MM-DD/    # blog/writeup content
├── github/YYYY-MM-DD/      # checklist content
├── htb/                    # HTB writeups
├── twitter/YYYY-MM-DD/     # X/Twitter intel
├── nvd/YYYY-MM-DD/         # CVE data
├── manual/                 # direct feeds
└── lessons/                # processed output → feeds semantic/
```

---

## 🔄 COMPONENT 4: FEEDBACK LOOP

```
SOA finds something
      ↓
L8 Judgment pre-validates (triage.py)
      ↓
Vaibhav reviews
      ↓
CONFIRMED / FALSE POSITIVE / NEEDS MORE
      ↓
Decision written to soa.db
      ↓
FP → suppressions/<target>.json (L13)
CONFIRMED → pattern → semantic memory (L5)
NEEDS MORE → requeued with note
      ↓
Next hunt SOA is smarter
```

---

## 🚀 COMPONENT 5: PIPELINE (Phase Order)

```
Phase 0   → Scope ingestion, project setup, config.json
Phase 1a  → Passive: subfinder + github-subdomains + chaos
Phase 1b  → Resolve: puredns (wildcard filter) + dnsx
Phase 1c  → Probe: httpx (flags locked) → httpx.json + live-domain.txt
Phase 1d  → Buckets: classify httpx.json into 18 buckets
            ↓ (bucket files written → hunt_watcher.py triggers)
Phase 2   → Hunt scripts run per bucket (parallel, not sequential)
            + Second Eye pass
            + Anomaly scoring
            + Attack chain generation
Phase 3   → VA: nuclei per bucket + gf patterns + kxss→dalfox + cors
Phase 3.5 → WAF canary probe
Phase 4   → Enum: nmap (ports) + dirsearch + arjun (params) [on signal only]
Phase 5   → Wordlists (ongoing)
Phase 6   → Dashboard (built)
Phase 7   → Reporting (on hold — ANTON mode)
```

**httpx flags (locked):**
```
-td -ip -cname -cdn -favicon -pa -fr -tls-probe -csp-probe
-fpt parked -fd -sr -srd ./responses -j -o httpx.json
-threads 50 -timeout 10
```

**18 Buckets:**
```
takeover (404)    401-unauthorized   dev-staging      login
forbidden         errors (5xx)       cloud            cms
legacy            admin-panels       interesting(200)  config
params            ssrf-redirect      api              js
internal          redirects(301/302/307)
```

---

## 🖥️ COMPONENT 6: INTERFACE

**Dashboard** (Flask, localhost:5000):
- Read-only from soa.db + project files
- Never writes to brain
- Project switcher (sidebar)
- Bucket grid (hunting + status merged)
- Special queues: DNS Records / Manual Queue / Finished
- Hunt results per bucket (subzy/subjack/nuclei/curl dots)
- Search + select + copy in every bucket

**Claude Project Instructions** (paste into Project settings):
```
You are SOA — Son-of-Anton. Autonomous BB hunting brain.
Read ~/son-of-anton/CLAUDE.md at start of every session.
Mode: SON-OF-ANTON (BB only — high/critical, aggressive recon).
Philosophy: Shallow pass everything. Deep dive on signal.
ARC: Every decision explainable in plain language.
Winograd: Resolve ambiguity using program context not keywords.
Push back when there's a genuinely better option.
Ask before assuming. Never run blindly.
```

---

## 💻 OS Handling

```python
import platform
OS = platform.system()  # "Darwin" or "Linux"

def find_tool(name):
    import os, shutil
    go = os.path.expanduser(f"~/go/bin/{name}")
    if os.path.exists(go): return go
    return shutil.which(name)
```

**macOS config paths (critical):**
- subfinder, httpx, nuclei, katana, dnsx, ffuf → `~/Library/Application Support/<tool>/config.yaml`
- alterx → `~/.config/alterx/` (exception)

**NEVER:** `grep -P` / `sed -i` without `''` / hardcode paths / assume PATH

---

## 🔑 API Keys (env only, never hardcode)

```
GITHUB_TOKEN    CHAOS_KEY       SHODAN_API_KEY
H1_TOKEN        PDCP_API_KEY    TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID               GROK_API_KEY (planned)
```

---

## 🏗️ Build Status

```
✅ DONE
Phase 0 complete
Phase 1a/1b/1c complete
Phase 1d (buckets) complete
soa.db schema built
session.json template built
episodic_write.py built
Dashboard built (Flask)
takeover.py hunt script built
CLAUDE.md complete

🔄 IN PROGRESS
self-state.json builder
hunt_watcher.py
Remaining hunt scripts (devstaging, admin, api, ssrf, xss, sqli, js)

❌ NOT STARTED
anomaly_scorer.py (L2)
second_eye.py (L9)
fp_suppressor.py (L13)
hunt_planner.py (L12)
attack_chains.py (L11)
triage.py (L8)
run_soa.py (L15 agentic loop)
Learning pipeline (intel/ + semantic_extractor.py)
Nightly crons
```

---

## 🎮 SOA Game Progress

```
✅ Level 1 — "The Setup"        +50 XP
✅ Level 2 — "The Map"          +200 XP
✅ Level 3 — "The Brain Blueprint" +500 XP
🔄 Level 4 — "First Blood"      ACTIVE — 0/1 valid findings
🔒 Level 5 — "The Brain Wakes"  soa.db + 3 hunts needed
🔒 Level 6 — "Pattern Recognition"
🔒 Level 7 — "Novel Discovery"  CVE generation

Current XP: 750 / 2000 to Level 4
```

---

## 🧑‍💻 What SOA Cannot Replace

- Novel logic flaws requiring business context understanding
- Final report quality and tone
- Program-specific human intuition
- The anomaly you flag before you can explain why

> SOA handles 80-90%. You handle 10-20%. That 10-20% is where the highest-value findings live.
