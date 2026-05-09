~/SOA/
│
├── CLAUDE.md                    # Identity — above all rings
├── README.md                    # Auto-generated nightly
│
├── ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
├── RING 1 — CORE (thinks)
├── ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
│
├── memory/
│   ├── soa.db
│   ├── self-state.json
│   ├── episodic/<target>/YYYY-MM-DD.json
│   ├── semantic/tech-patterns.json
│   ├── semantic/vuln-patterns.json
│   ├── semantic/program-patterns.json
│   └── suppressions/<target>.json
│
├── agents/
│   ├── orchestrator.py
│   ├── watcher.py
│   ├── perceiver.py
│   ├── second_eye.py
│   ├── planner.py
│   ├── judge.py
│   ├── learner.py
│   ├── controller.py
│   ├── event_bus.py
│   ├── rag_query.py
│   └── hunt/
│       ├── takeover.py
│       ├── devstaging.py
│       ├── admin_panels.py
│       ├── config_hunt.py
│       ├── api_hunt.py
│       ├── ssrf_hunt.py
│       ├── xss_hunt.py
│       ├── sqli_hunt.py
│       ├── js_hunt.py
│       ├── cloud_hunt.py
│       ├── cms_hunt.py
│       ├── login_hunt.py
│       └── auth401.py
│
└── skills/
    ├── recon.md
    ├── hunting.md
    ├── second_eye.md
    ├── triage.md
    ├── attack_chains.md
    ├── learning.md
    └── report.md
│
├── ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
├── RING 2 — EXECUTION (executes)
├── ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
│
├── pipeline/
│   ├── phase0/phase0.py
│   ├── phase1/
│   │   ├── 1a_passive.py
│   │   ├── 1b_resolve.py
│   │   ├── 1c_probe.py
│   │   └── 1d_buckets.py
│   ├── phase2/
│   │   ├── attack_chains.py
│   │   └── creative_leads.py
│   ├── phase3/
│   │   ├── va_runner.py
│   │   ├── scope_check.py
│   │   └── rate_limiter.py
│   ├── phase3_5/waf_canary.py
│   └── phase4/
│       ├── port_scan.py
│       ├── dir_fuzz.py
│       └── param_discovery.py
│
└── crons/
    ├── cron_nightly.sh
    ├── git_push.py
    ├── nuclei_update.py
    ├── subdomain_monitor.py
    └── readme_gen.py
│
├── ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
├── RING 3 — KNOWLEDGE (learns)
├── ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
│
└── intel/
    ├── h1/YYYY-MM-DD/
    ├── writeups/YYYY-MM-DD/
    ├── github/YYYY-MM-DD/
    ├── nvd/YYYY-MM-DD/
    ├── twitter/YYYY-MM-DD/
    ├── htb/
    ├── manual/
    ├── lessons/
    └── fetchers/
        ├── h1_fetcher.py
        ├── nvd_fetcher.py
        ├── github_fetcher.py
        └── writeup_fetcher.py
│
├── ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
├── RING 4 — INTERFACE (shows)
├── ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
│
├── dashboard/
│   ├── app.py
│   ├── templates/
│   └── static/
│
├── projects/<target>/
│   ├── session.json
│   ├── curious.json
│   ├── creative-leads.json
│   ├── phase0/ → phase4/
│   ├── manual/
│   ├── finished/
│   └── logs/
│
└── resources/
    ├── wordlists/
    ├── patterns/
    ├── fingerprints/
    └── resolvers.txt
