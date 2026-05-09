# Son-of-Anton — Full BB Hunting Pipeline
> Vision: Full AI brain — not just a recon tool. Autonomous, self-learning security assistant.
> Architecture: Brain (hunting logic) + UI (dashboard) + Learner (auto-learning loop)
> Status: Pipeline locked. Brain architecture pending. UI + Reporting on hold.

---

## Status Tracker

- [x] Phase 0 — Scope ingestion + monitoring + multi-TLD
- [x] Phase 1 — Recon tech stack locked
- [x] Phase 1 — Bucket filter finalized (22 buckets)
- [x] Phase 1 — httpx flags locked
- [x] Phase 3.5 — WAF canary probe added
- [x] Commands/flags finalized per tool
- [x] Config files (httpx, subfinder, amass)
- [ ] Recursive enum (on hold — large targets only)
- [x] Shodan API key (free tier — done)
- [ ] Rapid7 FDNS (on hold — large targets only)
- [ ] Telegram notifications (on hold — pending setup)
- [x] son-of-anton.sh built (Phase 1 complete)
- [ ] Phase 2 logic scripts (learn.py, mindmap.py) — pending
- [ ] Phase 3 VA scripts — pending
- [ ] Phase 4 Enum scripts — pending
- [ ] Brain architecture (Orchestrator/Executor/Validator pattern)
- [ ] UI dashboard (on hold)
- [ ] Reporting + validation (on hold)
- [ ] Learner component — patt-fetcher + auto-learning loop (on hold)
- [ ] techstack-identification 26 sub-agents (on hold)

---

## Two-Eye Approach — Core Hunting Philosophy
**First Eye:** Systematic coverage — test every gathered subdomain, endpoint, parameter for common vulnerabilities.
**Second Eye:** Intuition-driven — focus on interesting anomalies (exposed creds, forgotten subdomains, admin panels, anything that feels off).

If vulnerability found → create PoC → test full impact.
If nothing found → pivot deeper on unique subdomains/endpoints.

---

## Phase 0 — Pre-Recon Setup

### 0a. Scope Ingestion — All Platforms
```bash
# bounty-targets-data — hourly updated, no auth needed (primary)
curl -s https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json \
  | jq -r '.[].targets.in_scope[].asset_identifier' | anew scope.txt

curl -s https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json \
  | jq -r '.[].targets.in_scope[].target' | anew scope.txt

curl -s https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json \
  | jq -r '.[].targets.in_scope[].endpoint' | anew scope.txt

# HackerOne — fetch.php (EdOverflow/megplus) as fallback
php fetch.php <H1_TOKEN> | anew scope.txt

# Intigriti API
curl -s "https://api.intigriti.com/core/researcher/program" \
  -H "Authorization: Bearer <INTIGRITI_TOKEN>" \
  | jq -r '.[].domains[]' | anew scope.txt

# YesWeHack
curl -s "https://api.yeswehack.com/programs" \
  -H "Authorization: Bearer <YESWEHACK_TOKEN>" \
  | jq -r '.[].scopes[].scope' | anew scope.txt

# bbscope — covers H1 + Bugcrowd + Intigriti in one tool
# github.com/sw33tLie/bbscope
bbscope bc -t <BUGCROWD_TOKEN> | anew scope.txt
```

### 0b. Target Scoring
Score programs by bounty range, response time, disclosure rate, scope width.
Pick high-ROI programs first.
```bash
python3 target_selector.py --top 10 > targets/selected_targets.json
```

### 0c. Continuous Monitoring + Chaos Updates
```bash
# cron — every 24 hours
0 0 * * * /path/to/son-of-anton.sh >> /path/to/recon.log 2>&1

# Chaos — new subdomains → Telegram alert via anew
chaos -d target.com -key <CHAOS_KEY> | anew all-subs.txt | \
  while read sub; do
    curl -s "https://api.telegram.org/bot<BOT_TOKEN>/sendMessage" \
      -d "chat_id=<CHAT_ID>&text=New subdomain: $sub"
  done
```
**Telegram bot:** pending full setup.

### 0d. Multi-TLD Scope Handling
```bash
# Build domains.txt from program scope
cat > domains.txt << EOF
target1.com
target2.io
target3.in
EOF

# Loop all passive tools over every TLD
while read domain; do
  subfinder -d $domain -silent | anew all-subs.txt
  curl -s "https://crt.sh/?q=%.$domain&output=json" \
    | jq -r '.[].name_value' | grep -v '^\*' | sort -u | anew all-subs.txt
  amass enum --passive -d $domain | anew all-subs.txt
  chaos -d $domain -key <CHAOS_KEY> | anew all-subs.txt
done < domains.txt

# Scope validation — auto-filter out-of-scope
DOMAIN=$1
while read tld; do
  if [[ "$DOMAIN" == *".$tld" ]] || [[ "$DOMAIN" == "$tld" ]]; then
    echo "IN SCOPE: $DOMAIN"; exit 0
  fi
done < domains.txt
echo "OUT OF SCOPE: $DOMAIN"; exit 1
```

---

## Phase 1 — Recon

### 1a. Passive Subdomain Enumeration
> Goal: collect as many subdomains as possible without touching target.

```bash
# 1. subfinder — primary passive tool
subfinder -d target.com -silent -all -recursive -o subfinder.txt

# 2. assetfinder — hits different sources than subfinder
assetfinder --subs-only target.com | anew assetfinder.txt

# 3. findomain — different API sources again
findomain -t target.com -q | anew findomain.txt

# 4. amass passive
amass enum --passive -d target.com -o amass.txt

# 5. crt.sh — CT logs (finds historical certs)
curl -s "https://crt.sh/?q=%.target.com&output=json" \
  | jq -r '.[].name_value' | grep -v '^\*' | sort -u | anew ct.txt

# 6. github-subdomains — leaked in repos
github-subdomains -d target.com -t <GITHUB_TOKEN> -o github.txt

# 7. Wayback Machine CDX — historical subdomains
curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" \
  | sed 's|https\?://||' | cut -d'/' -f1 | sort -u | anew wayback-subs.txt

# 8. SPF + DNS records — free infra intel
dig TXT target.com +short   # SPF → mail servers + IP ranges
dig MX target.com +short    # dangling MX candidates
dig NS target.com +short    # dangling NS candidates

# 9. CSP header mining
curl -si https://target.com | grep -i content-security-policy \
  | grep -oP 'https?://[^ ;>]+' | sed 's|https\?://||' \
  | cut -d'/' -f1 | sort -u | anew csp-domains.txt

# 10. Merge all passive
cat subfinder.txt assetfinder.txt findomain.txt amass.txt \
  ct.txt github.txt wayback-subs.txt csp-domains.txt \
  | sort -u | anew all-passive.txt

echo "Total passive: $(wc -l < all-passive.txt)"
```

### 1b. Active Subdomain Enumeration
> Goal: find subdomains passive tools miss via brute-force + permutations + resolution.

```bash
# Wordlist setup (one-time download)
wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt
# + commonspeak2: github.com/assetnote/commonspeak2-wordlists
# + jhaddix all.txt: github.com/danielmiessler/SecLists/Discovery/DNS/
cat commonspeak2.txt best-dns-wordlist.txt jhaddix-all.txt | sort -u > combined-wordlist.txt

# Step 1 — generate permutations from passive subs
# dnsgen — mathematical mutation of existing subdomains
cat all-passive.txt | dnsgen - | anew dnsgen-perms.txt

# gotator — wordlist-based permutations
gotator -sub all-passive.txt -perm permutations.txt -depth 1 -numbers 3 \
  | anew gotator-perms.txt

# combine permutations with main wordlist
cat dnsgen-perms.txt gotator-perms.txt combined-wordlist.txt \
  | sort -u > full-wordlist.txt

# Step 2 — puredns brute-force + wildcard filter (uses massdns internally)
puredns bruteforce full-wordlist.txt target.com -r resolvers.txt -w brute.txt

# Step 3 — shuffledns resolves full passive list with wildcard handling
shuffledns -d target.com -list all-passive.txt -r resolvers.txt -o shuffled.txt

# Step 4 — dnsx bulk DNS resolution + record extraction
dnsx -l all-passive.txt -resp -a -cname -o resolved.txt

# Step 5 — merge everything
cat all-passive.txt brute.txt shuffled.txt resolved.txt \
  | sort -u | anew final-subs.txt

echo "Total after active: $(wc -l < final-subs.txt)"
```
**On hold:** Recursive enum — large targets only.

### 1c. HTTP Probing + Fingerprinting
```bash
# wafw00f — identify WAF before probing
wafw00f https://target.com -a -o wafw00f-results.txt

# httpx — central probing tool (flags locked)
cat final-subs.txt | httpx \
  -td \          # tech detection
  -ip \          # host IP
  -cname \       # CNAME chain
  -cdn \         # CDN/WAF detection
  -favicon \     # favicon hash
  -pa \          # probe all IPs
  -fr \          # follow redirects
  -tls-probe \   # new subdomains from TLS certs
  -csp-probe \   # new subdomains from CSP headers
  -fpt parked \  # filter parked domains
  -fd \          # filter near-duplicates
  -sr \          # store full responses
  -srd ./responses \
  -j -o results.json \
  -threads 50 -timeout 10

# fingerprintx — service fingerprinting on open ports
cat results.json | jq -r '.ip' | sort -u > ips.txt
fingerprintx -i ips.txt -o fingerprint-results.json

# dnsx reverse DNS on extracted IPs — finds hostnames not in DNS
dnsx -ptr -l ips.txt -resp-only -o reverse-dns.txt
cat reverse-dns.txt | anew final-subs.txt

# feed new subdomains from tls-probe/csp-probe back into pipeline
cat results.json | jq -r '.fqdn[]?' | sort -u | anew final-subs.txt
```

### 1d. Port Discovery
```bash
# rustscan — fast all-port discovery, feeds into nmap
rustscan -a ips.txt --ulimit 5000 -b 1000 -- -sV -sC \
  | tee rustscan-results.txt

# extract interesting open ports for deep nmap in Phase 4
grep "Open" rustscan-results.txt | awk '{print $1}' | sort -u > open-ports.txt
```

### 1e. Bucket Filtering
> Goal: split results.json into 22 targeted buckets. Each bucket feeds specific tools only.

```bash
mkdir -p buckets/

# 1. Takeover candidates
jq -r 'select(.status_code==404) | .url' results.json > buckets/404s.txt
jq -r 'select(.cname != null and (.cname | test("azurewebsites|cloudapp|trafficmanager|cloudfront|s3\.amazonaws|elasticbeanstalk|herokudns|herokuapp|ghost\.io|surge\.sh|readme\.io|zendesk|netlify|vercel|feedpress"; "i"))) | .url' \
  results.json >> buckets/404s.txt

# 2. Dev/staging — git/exposure candidates
jq -r '.url' results.json | grep -iE "dev\.|staging\.|old\.|beta\.|test\.|sandbox\.|qa\.|uat\.|build\.|ci\." \
  > buckets/dev-staging.txt

# 3. Login pages → manual Burp
jq -r 'select(.title != null and (.title | test("login|signin|sign in|portal|dashboard"; "i"))) | .url' \
  results.json > buckets/login-pages.txt

# 4. Forbidden → 403 bypass
jq -r 'select(.title != null and (.title | test("forbidden|access denied|unauthorized"; "i"))) | .url' \
  results.json > buckets/forbidden.txt

# 5. 502/503 — misconfigured/unavailable
jq -r 'select(.status_code == 502 or .status_code == 503) | .url' \
  results.json > buckets/unavailable.txt

# 6. Cloud storage → S3/Azure/GCP
jq -r 'select(.cname != null and (.cname | test("s3|amazonaws|azure|blob|cloudapp|googleapis"; "i"))) | .url' \
  results.json > buckets/cloud-storage.txt

# 7. CMS — WordPress/Joomla/Drupal
jq -r 'select(.technologies != null and (.technologies[] | test("WordPress|Joomla|Drupal"; "i"))) | .url' \
  results.json > buckets/cms.txt

# 8. Legacy/CVE candidates
jq -r '.url' results.json | grep -iE "legacy\.|v1\.|v2\.|old\.|archive\." \
  > buckets/legacy.txt

# 9. Exposed services — admin panels
jq -r 'select(.title != null and (.title | test("jenkins|grafana|kibana|phpmyadmin|adminer|admin|zabbix|nagios|splunk"; "i"))) | .url' \
  results.json > buckets/exposed-services.txt

# 10. Interesting — 200 with real content
jq -r 'select(.status_code == 200 and .title != null and .title != "") | .url' \
  results.json > buckets/interesting.txt

# 11. Config file exposure (content-type validated — not HTML)
while read url; do
  for path in /.env /env.js /app_env.js /.env.local /.env.production \
    /config.js /config.json /settings.py /database.yml /wp-config.php /config.php; do
    ct=$(curl -si "$url$path" --max-time 5 | grep -i content-type | head -1)
    code=$(curl -so /dev/null -w "%{http_code}" "$url$path" --max-time 5)
    if [[ "$code" == "200" ]] && ! echo "$ct" | grep -qi "text/html"; then
      echo "$url$path" | anew buckets/config-exposure.txt
    fi
  done
done < buckets/interesting.txt

# 12. SSRF/redirect parameter candidates
cat urls.txt | grep -iE "[?&](url|redirect|next|return|callback|dest|file|path|template|include|src|ref|uri|link|target|goto|out|redir|return_url|continue|forward)=" \
  | anew buckets/ssrf-redirect-params.txt

# 13. API endpoints
jq -r 'select(.url | test("/api/|/v[0-9]+/|/graphql|/rest/|/gql"; "i")) | .url' \
  results.json > buckets/api-endpoints.txt

# 14. GraphQL specifically
jq -r 'select(.url | test("/graphql|/gql|/graphiql|/playground"; "i")) | .url' \
  results.json > buckets/graphql.txt

# 15. JS files
jq -r 'select(.url | test("\\.js$"; "i")) | .url' \
  results.json > buckets/js-files.txt

# 16. Parameterized URLs (uro dedup first)
cat urls.txt | grep "=" | uro > buckets/parameterized-urls.txt

# 17. CORS candidates
jq -r 'select(.status_code == 200) | select(.url | test("/api/|/v[0-9]+/"; "i")) | .url' \
  results.json > buckets/cors-candidates.txt

# 18. Auth endpoints
jq -r 'select(.url | test("/auth|/token|/oauth|/jwt|/login|/signin"; "i")) | .url' \
  results.json > buckets/auth-endpoints.txt

# 19. Upload endpoints
cat urls.txt | grep -iE "upload|file|attach|import|document|image|media|photo|avatar" \
  > buckets/upload-endpoints.txt

# 20. Redirect candidates
cat urls.txt | gf redirect > buckets/redirect-params.txt

# 21. Error pages — verbose errors, version leaks
jq -r 'select(.status_code == 500 or .status_code == 503) | .url' \
  results.json > buckets/error-pages.txt

# 22. Identified servers — for CVE matching
jq -r 'select(.status_code == 200) | select(.webserver != null) | .url' \
  results.json > buckets/identified-servers.txt
```

### CNAME Suffix Reference (takeover candidates)
```
# Azure (NVHO — NXDOMAIN = takeover, NOT HTTP 404)
azurewebsites.net, cloudapp.net, trafficmanager.net, azureedge.net,
azure-api.net, blob.core.windows.net, cloudapp.azure.com

# AWS (VHO — check error fingerprint in response)
cloudfront.net, s3.amazonaws.com, elasticbeanstalk.com

# Others (VHO)
herokudns.com, herokuapp.com, netlify.app, netlify.com,
vercel.app, ghost.io, surge.sh, readme.io, zendesk.com,
freshdesk.com, shopify.com, github.io, feedpress.me
```

---

## Phase 2 — Logic Layer

### 2a. Intel Fetching
After httpx tech detection — fetch CVEs + disclosed H1 reports for detected stack.
```bash
# extract detected tech from httpx
cat results.json | jq -r '.technologies[]?' | sort -u | tr '\n' ',' > tech-stack.txt

# learn.py — GitHub Advisory + NVD CVE API + H1 Hacktivity GraphQL
python3 learn.py --tech "$(cat tech-stack.txt)" --target target.com
# output: intel.md — CVEs sorted by severity + grep patterns + H1 links
```

### 2b. Attack Mindmap
```bash
python3 mindmap.py --target target.com --type api --tech "$(cat tech-stack.txt)"
# output: mindmap.md — priority table HIGH → MED → LOW
```

### 2c. JS Analysis + Secret Extraction
```bash
# getJS — fetch all JS file URLs from target
getJS --url https://target.com --output js-files.txt

# linkfinder — thorough endpoint extraction from JS
python3 linkfinder.py -i js-files.txt -o js-analysis/endpoints.txt

# secretfinder — secrets in live JS endpoints
python3 SecretFinder.py -i js-files.txt -o js-analysis/secrets.txt

# trufflehog — secrets in stored responses
trufflehog filesystem ./responses/ --only-verified

# gitleaks — for exposed .git directories found in dev-staging bucket
while read url; do
  if curl -si "$url/.git/HEAD" | grep -q "ref:"; then
    gitleaks detect --source "$url" -r gitleaks-results.json
    echo "GIT EXPOSED: $url" | anew buckets/git-exposed.txt
  fi
done < buckets/dev-staging.txt

# git history — deleted secrets still in commit objects
# run on any cloned repos found
git log --all --full-history -- "*.env" "*.key" "*.pem" "*.secret"
```

---

## Phase 3 — Vulnerability Assessment

### 3a. Nuclei — Targeted Per Bucket
```bash
# update templates first
nuclei -update-templates

# Takeover
nuclei -l buckets/404s.txt -t http/takeovers/ -o vuln-results/takeovers.txt
subzy run --targets buckets/404s.txt --concurrency 100
subjack -w buckets/404s.txt -t 100 -timeout 30 -ssl

# Dev/staging — exposure + git
nuclei -l buckets/dev-staging.txt -t http/exposures/ -t http/misconfiguration/
nuclei -l buckets/dev-staging.txt -t http/exposures/git-config.yaml

# Cloud storage + cloud_enum
nuclei -l buckets/cloud-storage.txt -t http/misconfiguration/
cloud_enum -k target.com -b wordlists/cloud-buckets.txt -o buckets/cloud-enum-results.txt
# manual S3 access test
aws s3 ls s3://<bucket_name> --no-sign-request

# CMS
nuclei -l buckets/cms.txt -t http/vulnerabilities/wordpress/
nuclei -l buckets/cms.txt -t http/vulnerabilities/joomla/

# Legacy — CVEs only
nuclei -l buckets/legacy.txt -t http/cves/
nuclei -l buckets/identified-servers.txt -t http/cves/

# Exposed services
nuclei -l buckets/exposed-services.txt -t http/exposed-panels/

# Login pages — default creds + screenshots
nuclei -l buckets/login-pages.txt -t http/default-logins/
gowitness file -f buckets/login-pages.txt --threads 20 --timeout 10
gowitness file -f buckets/exposed-services.txt --threads 20 --timeout 10

# 403 bypass
python3 403_bypass.py --targets buckets/forbidden.txt

# Upload endpoints
nuclei -l buckets/upload-endpoints.txt -t http/vulnerabilities/ -tags fileupload

# Error pages — version extraction
nuclei -l buckets/error-pages.txt -t http/exposures/
```

### 3b. URL Collection + GF Pattern Matching
```bash
# endpoint discovery
echo "target.com" | gau | anew urls.txt
katana -u https://target.com -d 3 -jc | anew urls.txt

# uro — deduplicate before gf runs (critical — removes noise)
cat urls.txt | uro | anew urls-clean.txt

# gf patterns on clean URL list
cat urls-clean.txt | gf sqli     | anew vuln-candidates/sqli.txt
cat urls-clean.txt | gf xss      | anew vuln-candidates/xss.txt
cat urls-clean.txt | gf ssrf     | anew vuln-candidates/ssrf.txt
cat urls-clean.txt | gf aws-keys | anew vuln-candidates/aws-keys.txt
cat urls-clean.txt | gf redirect | anew vuln-candidates/redirects.txt
cat urls-clean.txt | gf rce      | anew vuln-candidates/rce.txt
cat urls-clean.txt | gf idor     | anew vuln-candidates/idor.txt
cat urls-clean.txt | gf lfi      | anew vuln-candidates/lfi.txt
cat urls-clean.txt | gf csrf     | anew vuln-candidates/csrf.txt
cat urls-clean.txt | gf ssti     | anew vuln-candidates/ssti.txt
cat urls-clean.txt | gf xxe      | anew vuln-candidates/xxe.txt
cat urls-clean.txt | gf debug    | anew vuln-candidates/debug.txt
cat urls-clean.txt | gf upload   | anew vuln-candidates/upload.txt

# kxss — fast reflected param finder before dalfox
cat vuln-candidates/xss.txt | kxss | anew vuln-candidates/reflected-params.txt

# dalfox — XSS on confirmed reflected params only
dalfox file vuln-candidates/reflected-params.txt -o vuln-results/xss-confirmed.txt

# corscanner — CORS misconfig on API endpoints
python3 corscanner.py -i buckets/cors-candidates.txt -t 50 \
  -o vuln-results/cors-results.txt

# crlfuzz — CRLF injection
crlfuzz -l buckets/interesting.txt -o vuln-results/crlf-results.txt

# ssrfmap — SSRF on parameter candidates
python3 ssrfmap.py -r buckets/ssrf-redirect-params.txt \
  -o vuln-results/ssrf-results.txt

# second-order subdomain takeover
second-order -base https://target.com
```

### 3c. Second Order Subdomain Takeover
```bash
second-order -base https://target.com
```

### 3d. Two-Eye Manual Triage
```bash
# visual screenshots for manual review
gowitness file -f buckets/interesting.txt --threads 20
gowitness file -f buckets/api-endpoints.txt --threads 20
# review gowitness report — apply Second Eye here
```

---

## Phase 3.5 — WAF Consistency Probe
> Run between Phase 3 and Phase 4.
> Goal: find endpoints that bypass WAF or have inconsistent coverage.
> Attack unprotected endpoints with full payloads. Use bypass techniques on protected ones.

```bash
# identify WAF type
wafw00f https://target.com -a -o wafw00f-results.txt

# canary probe across all interesting endpoints
# harmless payload — just detects WAF presence per endpoint
while read url; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 5 "$url?test=<script>canary</script>")
  if [[ "$response" != "403" && "$response" != "406" \
     && "$response" != "429" && "$response" != "444" ]]; then
    echo "UNPROTECTED: $url ($response)" | anew waf-gaps.txt
  else
    echo "PROTECTED: $url ($response)" | anew waf-protected.txt
  fi
done < buckets/interesting.txt

# unprotected → attack with full payload lists in Phase 3b
# protected → use encoding/bypass techniques
```

---

## Phase 4 — Enumeration

### 4a. Deep Port Scanning
```bash
# nmap deep scan on ports found by rustscan
nmap -sV -sC -p $(cat open-ports.txt | tr '\n' ',') \
  -iL ips.txt -oN nmap-results.txt --open
```

### 4b. Directory/Path Fuzzing
```bash
# feroxbuster — recursive discovery
feroxbuster -u https://target.com -w wordlists/content-discovery.txt \
  -r -t 20 -rate 50 -o dirs/feroxbuster-results.txt

# gobuster — extension-specific
gobuster dir -u https://target.com -w wordlists/content-discovery.txt \
  -x php,asp,aspx,jsp,json,txt,xml,bak,sql,env \
  -t 30 -o dirs/gobuster-results.txt

# dirsearch — fast with good defaults
dirsearch -l buckets/interesting.txt -e php,html,js,json,txt,xml \
  -x 404 -o dirs/dirsearch-results.txt

# ffuf with assetnote API wordlists for API endpoints
ffuf -u https://api.target.com/FUZZ -w wordlists/api-endpoints.txt \
  -mc 200,201,301,302,403,405 -t 20 -rate 50 \
  -o dirs/api-routes.json -of json
```

### 4c. Parameter Discovery
```bash
# paramspider — historical params from Wayback (passive, run first)
python3 paramspider.py --domain target.com \
  --exclude woff,css,js,png,jpg,svg \
  --output params/paramspider.txt

# arjun — hidden params on live endpoints (active, run after)
cat urls-clean.txt | grep -iE "api|admin|user|search|query" \
  | arjun --urls -m GET -o params/arjun-params.txt

# on SSRF/redirect bucket
arjun --urls buckets/ssrf-redirect-params.txt -m GET \
  -o params/ssrf-params.txt
```

### 4d. SQLi Testing
```bash
cat vuln-candidates/sqli.txt | while read url; do
  sqlmap -u "$url" --batch --dbs --level 3 --risk 2 \
    --random-agent -o --output-dir=sqli-results/
done
```

### 4e. GraphQL Testing
```bash
# graphql-cop — security testing for GraphQL
python3 graphql-cop.py -t https://target.com/graphql \
  -o vuln-results/graphql-results.json
```

---

## Phase 5 — Wordlists / Resources
> Ongoing — keep updating as new sources found.

### DNS / Subdomain Wordlists
```bash
# assetnote best-dns-wordlist
wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt

# commonspeak2 — data-driven from real subdomain usage
# github.com/assetnote/commonspeak2-wordlists

# jhaddix all.txt
# github.com/danielmiessler/SecLists/Discovery/DNS/

# gotator permutation words
# github.com/six2dez/gotator/permutations.txt

# combine into one
cat commonspeak2.txt best-dns-wordlist.txt jhaddix-all.txt \
  | sort -u > combined-wordlist.txt
```

### API / Endpoint Wordlists (from shuvonsec)
```
wordlists/graphql-queries.txt     # GraphQL introspection + common queries
wordlists/api-endpoints.txt       # REST API path discovery
wordlists/params.txt              # Parameter fuzzing
wordlists/js-variables.txt        # JS variable names for secret extraction
wordlists/cloud-buckets.txt       # Cloud bucket name permutations
```

### GF Patterns
```bash
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
```

### Payload Lists
```
seclists              # github.com/danielmiessler/SecLists
payloadsallthethings  # github.com/swisskyrepo/PayloadsAllTheThings
fuzzdb                # broader payload coverage
```

---

## Phase 6 — UI (ON HOLD)
> Visual dashboard for Son-of-Anton results.
> Build after all pipeline phases are locked and tested.

---

## Phase 7 — Reporting (ON HOLD)
> Report generation after UI is complete.

### Planned — validate.py (from shuvonsec)
4-gate validation before writing report:
1. **Real?** — Reproduced 3x, works without Burp, no special state
2. **In scope?** — Asset listed, not excluded, version matches
3. **Impact?** — CVSS 3.1 calculated
4. **Duplicate?** — Live H1 GraphQL scope check

### Planned — Finding Format (from transilienceai)
```
finding-NNN/
├── description.md      # vuln + CVSS + business impact + remediation
├── poc.py             # runnable exploit
├── poc_output.txt     # execution proof with timestamp
├── workflow.md        # manual reproduction steps
└── evidence/
    ├── raw-source.txt  # raw tool output (required for validation)
    ├── request.txt
    ├── response.txt
    └── screenshot.png
```

### Planned — Validator 5-Check Pattern (from transilienceai)
1. CVSS score must match severity label exactly
2. All evidence files must exist
3. PoC must parse + run + reference target URL
4. Every factual claim must appear in raw scan files
5. Log timestamps must have 2+ second gaps — bulk timestamps = fabrication = rejected

---

## Brain Architecture (PENDING)
> Son-of-Anton is NOT just a recon tool.
> It is a full AI brain: autonomous, self-learning, looping.

### Three Components
```
Brain   → Orchestrator/Executor/Validator pattern (from transilienceai)
          Hunting logic, pipeline decisions, agent coordination
UI      → Dashboard for results, visual triage, finding management
Learner → Auto-learning loop:
          - Fetch H1 disclosed reports
          - Medium blogs via Google dorking
          - GitHub CVEs via GitHub dorking
          - New techniques → update skill files
          - patt-fetcher pattern (haiku agent → PayloadsAllTheThings)
          - Learn from HTB machines (test + solution pairs)
```

### Future Phases (roadmap)
- Source code review pipeline
- Android + iOS pentest
- LLM/AI specific attacks (OWASP LLM Top 10)
- techstack-identification 26 sub-agents

---

## Config Files — TODO
- [x] `~/Library/Application Support/httpx/config.yaml`
- [x] `~/Library/Application Support/subfinder/provider-config.yaml` (API keys)
- [x] `~/Library/Application Support/amass/config.ini` (API keys — pending)
- [x] `~/Library/Application Support/chaos/config.yaml` (Chaos API key)

---

## Imports Table

| Component | Source | Phase | Status |
|---|---|---|---|
| Wayback CDX subdomain pull | shuvonsec repo 1 | Phase 1a | ✅ Added |
| Config file exposure check | shuvonsec repo 1 | Phase 1e | ✅ Added |
| SSRF param flagging | shuvonsec repo 1 | Phase 1e | ✅ Added |
| learn.py intel fetching | shuvonsec repo 1 | Phase 2a | ✅ Added |
| mindmap.py attack map | shuvonsec repo 1 | Phase 2b | ✅ Added |
| sneaky_bits / secretfinder | shuvonsec repo 1 | Phase 2c | ✅ Added |
| 403 bypass module | shuvonsec repo 1 | Phase 3a | ✅ Added |
| target_selector.py | shuvonsec repo 1 | Phase 0b | ✅ Added |
| validate.py 4-gate | shuvonsec repo 1 | Phase 7 | 🔜 On hold |
| report_generator skeleton | shuvonsec repo 1 | Phase 7 | 🔜 On hold |
| Custom wordlists | shuvonsec repo 1 | Phase 5 | ✅ Added |
| shuffledns | repo 2 amrelsagaei | Phase 1b | ✅ Added |
| dnsx reverse DNS | repo 2 amrelsagaei | Phase 1c | ✅ Added |
| cloud_enum | repo 2 amrelsagaei | Phase 3a | ✅ Added |
| feroxbuster | repo 2 amrelsagaei | Phase 4b | ✅ Added |
| gobuster | repo 2 amrelsagaei | Phase 4b | ✅ Added |
| paramspider | repo 2 amrelsagaei | Phase 4c | ✅ Added |
| sqlmap | repo 2 amrelsagaei | Phase 4d | ✅ Added |
| linkfinder | repo 2 amrelsagaei | Phase 2c | ✅ Added |
| gf extra patterns (csrf/ssti/xxe/debug/upload) | repo 2 | Phase 3b | ✅ Added |
| Two-Eye approach | repo 2 amrelsagaei | Philosophy | ✅ Added |
| Orchestrator/Executor/Validator pattern | repo 3 transilienceai | Brain | 🔜 Pending |
| Phase 3.5 WAF canary probe | repo 3 transilienceai | Phase 3.5 | ✅ Added |
| 5-check validator pattern | repo 3 transilienceai | Phase 7 | 🔜 On hold |
| Finding output format standard | repo 3 transilienceai | Phase 7 | 🔜 On hold |
| patt-fetcher pattern | repo 3 transilienceai | Learner | 🔜 On hold |
| techstack-identification 26 sub-agents | repo 3 transilienceai | Phase 2a | 🔜 On hold |
| assetfinder | tools review | Phase 1a | ✅ Added |
| findomain | tools review | Phase 1a | ✅ Added |
| dnsgen | tools review | Phase 1b | ✅ Added |
| rustscan | tools review | Phase 1d | ✅ Added (replaces naabu) |
| getJS | tools review | Phase 2c | ✅ Added |
| gitleaks | tools review | Phase 2c | ✅ Added |
| uro | tools review | Phase 3b | ✅ Added |
| kxss | tools review | Phase 3b | ✅ Added |
| dalfox | tools review | Phase 3b | ✅ Added |
| crlfuzz | tools review | Phase 3b | ✅ Added |
| corscanner | tools review | Phase 3b | ✅ Added |
| fingerprintx | tools review | Phase 1c | ✅ Added |
| graphql-cop | tools review | Phase 4e | ✅ Added |
| bounty-targets-data | scope research | Phase 0a | ✅ Added |
| wafw00f | all reviews | Phase 1c + 3.5 | ✅ Added |

---

## References
- can-i-take-over-xyz → github.com/EdOverflow/can-i-take-over-xyz
- can-i-take-over-dns → github.com/indianajson/can-i-take-over-dns
- bounty-targets-data → github.com/arkadiyt/bounty-targets-data
- shuvonsec repo → github.com/shuvonsec/claude-bug-bounty
- amrelsagaei repo → github.com/amrelsagaei/Bug-Bounty-Hunting-Methodology-2025
- transilienceai repo → github.com/transilienceai/communitytools
- bbscope → github.com/sw33tLie/bbscope
- Chaos API → chaos.projectdiscovery.io
- 0xpatrik subdomain takeover series → 0xpatrik.com
- PayloadsAllTheThings → github.com/swisskyrepo/PayloadsAllTheThings
