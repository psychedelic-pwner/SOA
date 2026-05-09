# Son-of-Anton (SOA) — Claude Code Context

## Methodology
~/son-of-anton/son-of-anton.md

## Project
Full BB hunting brain. Autonomous, self-learning security assistant.
Basedir: ~/son-of-anton/
Projects: ~/son-of-anton/projects/<target>/
Dashboard: ~/son-of-anton/dashboard/
Phases: ~/son-of-anton/phases/phase0/, phase1/, phase2/, phase3/, phase3_5/, phase4/

## OS Support
Always support both macOS (Darwin) and Linux (Ubuntu).
Detect with: import platform; OS = platform.system()

NEVER use:
- grep -P (not macOS compatible) → use Python re module
- sed -i without '' on macOS → use Python string manipulation
- Assume tool is in PATH → always use find_tool() helper

## Tool Paths
Primary: /Users/hackerbook/go/bin/<tool>
Fallback: brew (/opt/homebrew/bin/)
Config files: /Users/hackerbook/.config/<tool>/
Exception nuclei: stays brew for now
notify: /Users/hackerbook/go/bin/notify

Tool detection (use in every script):
def find_tool(name):
    import os, shutil
    go = os.path.expanduser(f"~/go/bin/{name}")
    if os.path.exists(go): return go
    found = shutil.which(name)
    return found if found else None

## API Keys
Read from os.environ only. Never source any file.
Keys available: GITHUB_TOKEN, CHAOS_KEY, SHODAN_API_KEY,
H1_TOKEN, INTIGRITI_TOKEN, PDCP_API_KEY,
TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

## Project Structure (per target)
projects/<target>/
├── phase0/          # scope, domains, config.json, vuln-scope
├── phase1/
│   ├── passive/     # subfinder, amass, ct, wayback, all-passive.txt
│   ├── active/      # brute, shuffled, dnsgen, final-subs.txt
│   ├── probing/     # results.json, wafw00f, fingerprint
│   ├── ports/       # ips.txt, rustscan
│   ├── urls/        # gau, wayback, katana, all-urls, urls-clean
│   ├── buckets/     # all 22 buckets
│   └── responses/   # httpx stored responses
├── phase2/          # intel, mindmap, js, js-analysis
├── phase3/          # vuln-candidates, vuln-results
├── phase3_5/        # waf-canary
├── phase4/          # enum results
└── logs/            # all phase logs + errors

KEEP EVERY individual tool output — never discard raw files.

## httpx Flags (locked)
-td -ip -cname -cdn -favicon -pa -fr -tls-probe -csp-probe
-fpt parked -fd -sr -srd ./responses -j -o results.json
-threads 50 -timeout 10

## 22 Buckets (phase1/buckets/)
404s, dev-staging, login-pages, forbidden, unavailable,
cloud-storage, cms, legacy, exposed-services, interesting,
config-exposure, ssrf-redirect-params, api-endpoints,
graphql, js-files, parameterized-urls, cors-candidates,
auth-endpoints, upload-endpoints, redirect-params,
error-pages, identified-servers

## Script Requirements (all phase scripts)
1. Import banner: sys.path.insert(0, ~/son-of-anton); from banner import show_banner
2. Rich terminal: progress bars, colors, live status
3. Error handler on every subprocess:
   On failure → [S]kip / [R]etry / [A]bort menu
   Log to phase/errors.log
4. --debug flag: show every command + raw output
5. Per-tool status: ✓ done / ✗ failed / ⚠ skipped
6. Notify on phase complete (not per command):
   find_tool("notify") → send bulk notification
7. Save passive-summary.json per phase with counts
8. OS-specific commands handled via Python — no shell grep/sed

## Two-Eye Approach
First Eye: systematic coverage of every subdomain/endpoint/parameter
Second Eye: intuition — exposed creds, forgotten subs, admin panels
Every output matters — UI needs full data, nothing discarded

## Pipeline Order
Phase 0 → Project setup, scope, platform, TLD handling
Phase 1 → Recon (passive→active→probing→ports→urls→buckets)
Phase 2 → Logic (intel, mindmap, JS analysis, secrets)
Phase 3 → VA (nuclei per bucket, gf patterns, kxss→dalfox, cors, crlf)
Phase 3.5 → WAF canary probe
Phase 4 → Enum (nmap, feroxbuster, gobuster, dirsearch, arjun, sqlmap)
Phase 5 → Wordlists (ongoing)
Phase 6 → UI (on hold)
Phase 7 → Reporting (on hold)

## On Hold
- Telegram notifications (notify setup in progress)
- UI dashboard
- Reporting + validation
- Brain/Learner architecture
- Source code review, Android/iOS, LLM attacks

## Key Resources
Wordlists: ~/son-of-anton/resources/wordlists/
Scripts: ~/son-of-anton/resources/scripts/
API keys file: ~/son-of-anton/resources/.api-keys.txt (reference only)
Resolvers: ~/son-of-anton/resources/resolvers.txt
Permutations: ~/son-of-anton/resources/wordlists/permutations.txt
GF patterns: ~/.gf/
Nuclei templates: auto-updated via nuclei -update-templates