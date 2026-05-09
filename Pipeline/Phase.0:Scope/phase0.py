#!/usr/bin/env python3
"""
Son-of-Anton — Phase 0: Project Setup & Scope Discovery
Interactive setup for bug bounty recon projects.
"""

import os
import sys
import re
import json
import subprocess
import shutil
import argparse
import time
from datetime import datetime
from pathlib import Path

import requests
import tldextract

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box

console = Console()

DEBUG = False


def debug(msg):
    if DEBUG:
        console.print(f"[dim cyan][DEBUG] {msg}[/dim cyan]")


def find_tool(name):
    go_path = os.path.expanduser(f"~/go/bin/{name}")
    if os.path.exists(go_path):
        return go_path
    found = shutil.which(name)
    return found if found else None


def clean_domain(input_str):
    domain = input_str.strip()
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r'^www\.', '', domain)
    domain = domain.split('/')[0].strip()
    domain = domain.split(':')[0].strip()
    return domain


def extract_project_name(domain):
    extracted = tldextract.extract(domain)
    return extracted.domain


def create_project_structure(base_dir, project_name):
    proj_dir = os.path.join(base_dir, "4.Interface", "Projects", project_name)
    directories = [
        "phase0",
        "phase1/passive",
        "phase1/active",
        "phase1/probing",
        "phase1/ports",
        "phase1/urls",
        "phase1/buckets",
        "phase1/responses",
        "phase2/intel",
        "phase2/mindmap",
        "phase2/js",
        "phase3/vuln-candidates",
        "phase3_5",
        "phase4/enum",
        "logs",
    ]
    for d in directories:
        Path(os.path.join(proj_dir, d)).mkdir(parents=True, exist_ok=True)
    return proj_dir


def classify_scope(scope_items, platform='hackerone'):
    """
    Classify scope items into categories:
    - wildcards: WILDCARD type assets
    - urls: URL type assets
    - others: OTHER type filtered assets (web/api)
    - skipped: mobile/hardware/app IDs/descriptions
    """
    urls = []
    wildcards = []
    others = []
    skipped_items = []

    for item in scope_items:
        if platform == 'hackerone':
            asset = item.get('asset_identifier', '')
            asset_type = item.get('asset_type', '').upper()
        elif platform == 'bugcrowd':
            asset = item.get('target', '')
            asset_type = item.get('type', '').upper()
        elif platform == 'intigriti':
            asset = item.get('endpoint', '')
            asset_type = item.get('type', '').upper()
        else:
            continue

        if not asset:
            continue

        # Check asset_identifier first — force WILDCARD if starts with *.
        if asset.startswith('*.') or (asset.startswith('*') and not asset.startswith('http')):
            wildcards.append(item)
            continue

        if asset_type == "WILDCARD":
            wildcards.append(item)
        elif asset_type == "URL":
            urls.append(item)
        elif asset_type == "OTHER":
            asset_lower = asset.lower()

            if re.match(r'^\d+$', asset):
                skipped_items.append((item, 'app_id'))
                continue
            if 'steam' in asset_lower:
                skipped_items.append((item, 'steam'))
                continue
            if re.match(r'^Tier\s+\d*', asset, re.IGNORECASE):
                skipped_items.append((item, 'tier_description'))
                continue
            if re.match(r'^[A-Za-z\s]+$', asset) and '.' not in asset:
                skipped_items.append((item, 'description'))
                continue
            if re.match(r'^[a-zA-Z0-9]{8,}$', asset) and '.' not in asset:
                skipped_items.append((item, 'store_id'))
                continue
            if any(keyword in asset_lower for keyword in ['apple', 'ios', 'app store']):
                skipped_items.append((item, 'mobile_ios'))
                continue
            if any(keyword in asset_lower for keyword in ['google play', 'android']):
                skipped_items.append((item, 'mobile_android'))
                continue
            if any(keyword in asset_lower for keyword in ['hardware', 'iot', 'connected']):
                skipped_items.append((item, 'hardware'))
                continue

            android_prefixes = ('com.', 'net.', 'org.', 'io.', 'air.', 'mobi.',
                                'fi.', 'lol.', 'tv.', 'app.')
            if asset.lower().startswith(android_prefixes):
                skipped_items.append((item, 'android_package'))
                continue
            if 'apps.facebook.com' in asset_lower:
                skipped_items.append((item, 'facebook_app'))
                continue
            if asset.count('_') >= 2 and '/' not in asset:
                skipped_items.append((item, 'app_bundle'))
                continue
            if '.' not in asset:
                skipped_items.append((item, 'app_identifier'))
                continue

            if re.match(r'^(https?://)?[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}(/.*)?$', asset):
                others.append(item)
            else:
                skipped_items.append((item, 'other'))
        else:
            if '.' in asset and not re.match(r'^\d+$', asset):
                others.append(item)
            else:
                skipped_items.append((item, 'unknown_type'))

    return {
        'urls': urls,
        'wildcards': wildcards,
        'others': others,
        'skipped': skipped_items
    }


def get_multiline_input(prompt_text):
    console.print(f"[cyan]{prompt_text}[/cyan]")
    console.print("[dim](Enter blank line when done)[/dim]")
    lines = []
    while True:
        line = input()
        if not line.strip():
            break
        lines.append(line.strip())
    return lines


def extract_base_domain(asset, platform='hackerone'):
    if platform == 'hackerone':
        domain = asset.get('asset_identifier', '')
    elif platform == 'bugcrowd':
        domain = asset.get('target', '')
    elif platform == 'intigriti':
        domain = asset.get('endpoint', '')
    else:
        return None

    if domain.startswith('*.'):
        domain = domain[2:]
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0].strip()
    return domain if domain and '.' in domain else None


def main():
    parser = argparse.ArgumentParser(description="Phase 0: Project Setup & Scope Discovery")
    parser.add_argument('--resume', type=str, help='Resume existing project by name')
    parser.add_argument('--debug', action='store_true', help='Show detailed debug output')
    args = parser.parse_args()

    global DEBUG
    DEBUG = args.debug

    base_dir = os.path.expanduser("~/SOA")

    # ═══════════════════════════════════════
    # HEADER
    # ═══════════════════════════════════════
    console.print(Panel(
        "[bold white]Phase 0 — Project Setup & Scope Discovery[/bold white]",
        border_style="cyan",
        box=box.DOUBLE,
        padding=(0, 1)
    ))

    # ═══════════════════════════════════════
    # RESUME
    # ═══════════════════════════════════════
    if args.resume:
        config_path = os.path.join(base_dir, "4.Interface", "Projects", args.resume, "phase0", "config.json")
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)

            console.print(Panel(
                f"[bold white]Resuming project:[/bold white] [cyan]{args.resume}[/cyan]\n"
                f"[dim]Target: {config.get('target')}[/dim]\n"
                f"[dim]Platform: {config.get('platform', 'unknown')}[/dim]\n"
                f"[dim]Created: {config.get('created', 'unknown')}[/dim]",
                title="Resume Mode",
                border_style="cyan",
                box=box.DOUBLE
            ))

            console.print(json.dumps(config, indent=2))

            if not Confirm.ask("Continue with this configuration?"):
                console.print("[yellow]Restart without --resume to create new project[/yellow]")
                sys.exit(0)

            console.print("[green]✓ Configuration loaded[/green]")

            phase1_targets_file = os.path.join(config['project_dir'], "phase0", "phase1_targets.txt")
            if os.path.exists(phase1_targets_file):
                with open(phase1_targets_file, 'r') as f:
                    first_target = f.readline().strip()
                    if first_target:
                        console.print(f"\nRun Phase 1 with:")
                        console.print(f"[bold cyan]python3 ~/SOA/2.Execution/Pipeline/Phase.1:Recon/phase1a_passive.py --projectdir {config['project_dir']}[/bold cyan]")

            sys.exit(0)
        else:
            console.print(f"[red]Error: Project '{args.resume}' not found[/red]")
            sys.exit(1)

    # ═══════════════════════════════════════
    # DOMAIN INPUT
    # ═══════════════════════════════════════
    while True:
        domain_input = Prompt.ask("[bold white]Enter target domain or URL[/bold white]")
        domain = clean_domain(domain_input)
        project_name = extract_project_name(domain)

        debug(f"Target extracted: {domain}")
        debug(f"Project name: {project_name}")

        console.print(f"\n  Target: [bold cyan]{domain}[/bold cyan]")
        break

    # ═══════════════════════════════════════
    # CREATE PROJECT DIRECTORY
    # ═══════════════════════════════════════
    proj_dir = create_project_structure(base_dir, project_name)
    debug(f"Project dir: {proj_dir}")
    console.print(f"[dim]✓ Project created at: {proj_dir}[/dim]\n")

    config = {
        "target": domain,
        "project_name": project_name,
        "project_dir": proj_dir,
        "created": datetime.now().isoformat(),
        "platform": None,
        "program_handle": None,
        "program_name": None,
        "testing_scope": None,
        "scope_file": "phase0/wildcards.txt",
        "urls_file": "phase0/urls.txt",
        "others_file": "phase0/others.txt",
        "phase1_targets": "phase0/phase1_targets.txt",
        "domains_file": "phase0/domains.txt",
        "out_of_scope_file": "phase0/out-of-scope.txt",
        "multi_tld": False,
        "tld_count": 0,
        "phase0_complete": False
    }

    # ═══════════════════════════════════════
    # PLATFORM DETECTION (H1)
    # ═══════════════════════════════════════
    debug("Searching HackerOne...")
    h1_matches = []
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data"
            "/main/data/hackerone_data.json",
            timeout=15
        )
        debug(f"H1 fetch status: {r.status_code} length: {len(r.text)}")
        if r.status_code == 200 and r.text.strip():
            data = r.json()
            for prog in data:
                name = prog.get('name', '')
                handle = prog.get('handle', '')
                if (project_name.lower() in name.lower() or
                    project_name.lower() in handle.lower()):
                    h1_matches.append({
                        'platform': 'HackerOne',
                        'name': name,
                        'handle': handle,
                        'data': prog
                    })
                    debug(f"H1 match: {name} / {handle}")
    except Exception as e:
        debug(f"H1 fetch error: {e}")
        console.print(f"[yellow]⚠ HackerOne fetch failed: {e}[/yellow]")

    debug(f"H1 matches found: {len(h1_matches)}")

    confirmed_program = None
    scope_manually_set = False

    if h1_matches:
        if len(h1_matches) == 1:
            console.print(
                f"\n  Found: [bold cyan]HackerOne[/bold cyan]"
                f" — [bold white]{h1_matches[0]['name']}[/bold white]"
            )
            choice = Prompt.ask(
                "  Press Enter to confirm or [[bold yellow]R[/bold yellow]]eject",
                default=""
            ).strip().lower()
            if choice == 'r':
                confirmed_program = None
            else:
                confirmed_program = h1_matches[0]
                scope_manually_set = False
        else:
            match_table = Table(box=box.SIMPLE, show_header=True)
            match_table.add_column("#", style="dim", width=3)
            match_table.add_column("Program", style="white")
            match_table.add_column("Handle", style="dim")
            for i, m in enumerate(h1_matches, 1):
                match_table.add_row(str(i), m['name'], m['handle'])
            console.print(match_table)
            num = Prompt.ask("  Select program number", default="1").strip()
            try:
                confirmed_program = h1_matches[int(num)-1]
                scope_manually_set = False
            except:
                confirmed_program = None
    else:
        console.print(f"[yellow]  Not found on HackerOne.[/yellow]")
        confirmed_program = None

    if not confirmed_program:
        console.print()
        console.print(
            f"  Press Enter to continue with "
            f"[bold cyan]{domain}[/bold cyan]"
            f"  |  [[bold yellow]F[/bold yellow]]ile path"
            f"  |  custom [[bold yellow]L[/bold yellow]]ink"
        )
        fallback = Prompt.ask("  Choice", default="").strip().lower()

        if fallback == '':
            scope_type = Prompt.ask(
                f"  Use as [[bold yellow]W[/bold yellow]]ildcard"
                f" or actual [[bold yellow]U[/bold yellow]]RL",
                default="w"
            ).strip().lower()
            if scope_type in ['w', '']:
                wildcards_list = [{'asset_identifier': f"*.{domain}", 'asset_type': 'WILDCARD'}]
                urls_list = []
            else:
                wildcards_list = []
                urls_list = [{'asset_identifier': domain, 'asset_type': 'URL'}]
            others_list = []
            scope_manually_set = True
            console.print(f"  [green]✓ Scope locked[/green]")

        elif fallback == 'f':
            file_path = Prompt.ask("  File path").strip()
            file_path = os.path.expanduser(file_path)
            if os.path.exists(file_path):
                with open(file_path) as f:
                    lines = [l.strip() for l in f if l.strip()]
                wildcards = [l for l in lines if l.startswith('*')]
                urls = [l for l in lines if not l.startswith('*') and l]
                wildcards_list = [{'asset_identifier': w, 'asset_type': 'WILDCARD'} for w in wildcards]
                urls_list = [{'asset_identifier': u, 'asset_type': 'URL'} for u in urls]
                others_list = []
                scope_manually_set = True
                console.print(
                    f"  [green]✓[/green] Wildcards: {len(wildcards_list)}"
                    f" | URLs: {len(urls_list)}"
                )
                confirm = Prompt.ask(
                    "  Press Enter to confirm or [[bold yellow]E[/bold yellow]]dit",
                    default=""
                ).strip().lower()
                if confirm == 'e':
                    extra = Prompt.ask("  Add entries (comma separated)", default="").strip()
                    if extra:
                        for e in extra.split(','):
                            e = e.strip()
                            if e.startswith('*'):
                                wildcards_list.append({'asset_identifier': e, 'asset_type': 'WILDCARD'})
                            elif e:
                                urls_list.append({'asset_identifier': e, 'asset_type': 'URL'})
            else:
                console.print(f"[red]  File not found: {file_path}[/red]")
                wildcards_list = []
                urls_list = [{'asset_identifier': domain, 'asset_type': 'URL'}]
                others_list = []
                scope_manually_set = True

        elif fallback == 'l':
            link = Prompt.ask("  Enter URL").strip()
            try:
                lr = requests.get(link, timeout=15)
                content = lr.text
                debug(f"Link fetch: {len(content)} chars")
                wildcards = list(set(re.findall(
                    r'\*\.[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+', content
                )))
                url_hits = re.findall(r'https?://[a-zA-Z0-9\-\.]+', content)
                urls = list(set([
                    re.sub(r'^https?://', '', u)
                    for u in url_hits
                    if project_name.lower() in u.lower()
                ]))
                wildcards_list = [{'asset_identifier': w, 'asset_type': 'WILDCARD'} for w in wildcards]
                urls_list = [{'asset_identifier': u, 'asset_type': 'URL'} for u in urls]
                others_list = []
                scope_manually_set = True
                console.print(
                    f"  [green]✓[/green] Wildcards: {len(wildcards_list)}"
                    f" | URLs: {len(urls_list)}"
                )
            except Exception as e:
                console.print(f"[red]  Fetch failed: {e}[/red]")
                wildcards_list = []
                urls_list = [{'asset_identifier': domain, 'asset_type': 'URL'}]
                others_list = []
                scope_manually_set = True

    # ═══════════════════════════════════════
    # EXTRACT SCOPE FROM CONFIRMED PROGRAM
    # ═══════════════════════════════════════
    all_scope_items = []
    out_of_scope_items = []

    if confirmed_program:
        prog_data = confirmed_program['data']
        config['platform'] = confirmed_program['platform'].lower()
        config['program_name'] = confirmed_program['name']
        config['program_handle'] = confirmed_program['handle']

        all_scope_items = prog_data.get('targets', {}).get('in_scope', [])
        out_of_scope_items = prog_data.get('targets', {}).get('out_of_scope', [])

    debug("✓ Platform detection complete\n")

    # ═══════════════════════════════════════
    # CLASSIFY SCOPE
    # ═══════════════════════════════════════
    if scope_manually_set:
        skipped_list = []
        skipped_counts = {}
    elif all_scope_items:
        debug("Classifying scope...")
        debug(f"Scope items raw: {len(all_scope_items)}")
        classified = classify_scope(all_scope_items, config['platform'])

        urls_list = classified['urls']
        wildcards_list = classified['wildcards']
        others_list = classified['others']
        skipped_list = classified['skipped']

        debug(f"Wildcards: {len(wildcards_list)}")
        debug(f"URLs: {len(urls_list)}")
        debug(f"Others: {len(others_list)}")
        debug(f"Skipped: {len(skipped_list)}")

        skipped_counts = {}
        for item, reason in skipped_list:
            skipped_counts[reason] = skipped_counts.get(reason, 0) + 1

        # Save out-of-scope
        oos_file = os.path.join(proj_dir, "phase0", "out-of-scope.txt")
        if out_of_scope_items:
            with open(oos_file, 'w') as f:
                for item in out_of_scope_items:
                    asset = item.get('asset_identifier', '')
                    if asset:
                        f.write(f"{asset}\n")
            console.print(f"[green]✓ {len(out_of_scope_items)} out-of-scope items saved[/green]")
        else:
            console.print("[yellow]No out-of-scope data found[/yellow]")
            if Confirm.ask("Provide custom URL to fetch out-of-scope?", default=False):
                oos_url = Prompt.ask("Enter URL")
                try:
                    response = requests.get(oos_url, timeout=10)
                    oos_raw_file = os.path.join(proj_dir, "phase0", "oos-raw.txt")
                    with open(oos_raw_file, 'w') as f:
                        f.write(response.text)
                    console.print(f"[green]✓ Raw out-of-scope saved to {oos_raw_file}[/green]")
                except Exception as e:
                    console.print(f"[yellow]Could not fetch: {e}[/yellow]")

        # Display out-of-scope
        console.print("\n[bold]Out of Scope[/bold]")
        if out_of_scope_items:
            oos_table = Table(box=box.SIMPLE, show_header=True)
            oos_table.add_column("Asset", style="red")
            oos_table.add_column("Type", style="dim")
            for item in out_of_scope_items:
                identifier = item.get('asset_identifier', '')
                atype = item.get('asset_type', '')
                if any(c in identifier for c in ['.', '/']):
                    oos_table.add_row(identifier, atype)
            if oos_table.row_count > 0:
                console.print(oos_table)
            else:
                console.print("  [dim]No domain-based out-of-scope items[/dim]")
        else:
            console.print("  [dim]No out-of-scope data found[/dim]")

        # Display trimmed items
        console.print("\n[bold]Removed from scope (not relevant for web/api hunting)[/bold]")
        trim_table = Table(box=box.SIMPLE, show_header=True)
        trim_table.add_column("Asset", style="dim")
        trim_table.add_column("Type", style="dim")
        trim_table.add_column("Reason", style="dim red")

        reason_map = {
            'mobile_ios': 'iOS app — mobile scope',
            'mobile_android': 'Android app — mobile scope',
            'hardware': 'IoT/Hardware — out of web scope',
            'app_id': 'App store ID',
            'description': 'Description text — not a domain',
            'tier_description': 'Description text — not a domain',
            'steam': 'Steam app ID',
            'store_id': 'Windows app store ID',
            'other': 'Not a valid domain',
            'unknown_type': 'Unknown type'
        }

        domain_trimmed_count = 0
        non_domain_trimmed_count = 0

        for item, reason in skipped_list:
            if config['platform'] == 'hackerone':
                asset = item.get('asset_identifier', '')
                asset_type = item.get('asset_type', '')
            elif config['platform'] == 'bugcrowd':
                asset = item.get('target', '')
                asset_type = item.get('type', '')
            elif config['platform'] == 'intigriti':
                asset = item.get('endpoint', '')
                asset_type = item.get('type', '')
            else:
                continue

            if '.' in asset:
                readable_reason = reason_map.get(reason, reason)
                trim_table.add_row(asset, asset_type, readable_reason)
                domain_trimmed_count += 1
            else:
                non_domain_trimmed_count += 1

        if trim_table.row_count > 0:
            console.print(trim_table)
            console.print(f"  [dim]+ {non_domain_trimmed_count} app IDs and descriptions removed (not shown)[/dim]")
        else:
            console.print("  [dim]Nothing trimmed[/dim]")

        # Not-eligible check
        not_eligible_items = []
        eligible_urls = []
        eligible_wildcards = []
        eligible_others = []

        for item in urls_list:
            if config['platform'] == 'hackerone':
                if not item.get('eligible_for_bounty', True):
                    not_eligible_items.append(('URL', item))
                else:
                    eligible_urls.append(item)
            else:
                eligible_urls.append(item)

        for item in wildcards_list:
            if config['platform'] == 'hackerone':
                if not item.get('eligible_for_bounty', True):
                    not_eligible_items.append(('WILDCARD', item))
                else:
                    eligible_wildcards.append(item)
            else:
                eligible_wildcards.append(item)

        for item in others_list:
            if config['platform'] == 'hackerone':
                if not item.get('eligible_for_bounty', True):
                    not_eligible_items.append(('OTHER', item))
                else:
                    eligible_others.append(item)
            else:
                eligible_others.append(item)

        include_not_eligible = False
        if not_eligible_items:
            not_eligible_count = len(not_eligible_items)
            console.print(f"\n  [yellow]⚠ {not_eligible_count} scope items marked NOT eligible for bounty[/yellow]")
            choice = Prompt.ask(
                "  Press Enter to skip or [bold yellow]I[/bold yellow] to include anyway",
                default=""
            ).strip().lower()
            include_not_eligible = (choice == 'i')

            if not include_not_eligible:
                not_eligible_file = os.path.join(proj_dir, "phase0", "not-eligible.txt")
                with open(not_eligible_file, 'w') as f:
                    for item_type, item in not_eligible_items:
                        if config['platform'] == 'hackerone':
                            asset = item.get('asset_identifier', '')
                        elif config['platform'] == 'bugcrowd':
                            asset = item.get('target', '')
                        elif config['platform'] == 'intigriti':
                            asset = item.get('endpoint', '')
                        else:
                            asset = ''
                        if asset:
                            f.write(f"{item_type}: {asset}\n")
                console.print(f"[dim]✓ Not-eligible items saved[/dim]")
            else:
                for item_type, item in not_eligible_items:
                    if item_type == 'URL':
                        eligible_urls.append(item)
                    elif item_type == 'WILDCARD':
                        eligible_wildcards.append(item)
                    elif item_type == 'OTHER':
                        eligible_others.append(item)

        urls_list = eligible_urls
        wildcards_list = eligible_wildcards
        others_list = eligible_others

        # ═══════════════════════════════════════
        # TESTING SCOPE
        # ═══════════════════════════════════════
        console.print()
        console.print(Panel("[bold white]Testing Scope[/bold white]", box=box.DOUBLE, border_style="cyan"))
        console.print("What are we testing?\n")
        console.print("  1. Web + API (default — Press Enter)")
        console.print("  2. Web only")
        console.print("  3. API only")
        console.print("  4. Mobile only")
        console.print()

        testing_choice = Prompt.ask("  Select testing scope", default="1").strip()

        if testing_choice == '' or testing_choice == '1':
            config['testing_scope'] = 'web+api'
        elif testing_choice == '2':
            config['testing_scope'] = 'web'
        elif testing_choice == '3':
            config['testing_scope'] = 'api'
        elif testing_choice == '4':
            mobile_choice = Prompt.ask(
                "  Mobile: [bold yellow]A[/bold yellow]ndroid / "
                "[bold yellow]I[/bold yellow]OS / "
                "[bold yellow]B[/bold yellow]oth",
                default="b"
            ).strip().lower()
            mobile_map = {'a': 'android', 'i': 'ios', 'b': 'mobile-both'}
            config['testing_scope'] = mobile_map.get(mobile_choice, 'mobile-both')
        else:
            config['testing_scope'] = 'web+api'

        testing_scope = config['testing_scope']
        console.print(f"\n[bold]Trimming based on testing scope: {testing_scope.replace('+', ' + ').title()}[/bold]")

        excluded_types = []
        if testing_scope in ['web', 'api', 'web+api']:
            excluded_types = ['mobile_ios', 'mobile_android', 'hardware']

        if excluded_types:
            trim_summary = Table(box=box.SIMPLE, show_header=False)
            trim_summary.add_column("Category", style="dim")
            trim_summary.add_column("Count", style="dim red")

            type_labels = {
                'mobile_ios': 'iOS apps',
                'mobile_android': 'Android apps',
                'hardware': 'IoT/Hardware'
            }

            for excluded_type in excluded_types:
                count = skipped_counts.get(excluded_type, 0)
                if count > 0:
                    label = type_labels.get(excluded_type, excluded_type)
                    trim_summary.add_row(f"  ✗ {label}", str(count))

            if trim_summary.row_count > 0:
                console.print(trim_summary)
            else:
                console.print("  [dim]No items excluded by this testing scope[/dim]")
        else:
            console.print("  [dim]Full scope selected — no exclusions[/dim]")

        console.print()

        # ═══════════════════════════════════════
        # DISPLAY SCOPE
        # ═══════════════════════════════════════
        console.print("\n[bold]Scope Summary:[/bold]\n")

        if wildcards_list:
            console.print("[bold cyan]═══ Wildcards (subdomain enum targets) ═══[/bold cyan]")
            wildcard_table = Table(box=box.SIMPLE)
            wildcard_table.add_column("Program", style="dim")
            wildcard_table.add_column("Scope", style="cyan")
            wildcard_table.add_column("Type", style="cyan")
            wildcard_table.add_column("Eligible", style="green")

            for item in wildcards_list:
                if config['platform'] == 'hackerone':
                    asset = item.get('asset_identifier', '')
                    eligible = "[green]✓[/green]" if item.get('eligible_for_bounty', True) else "[red]✗[/red]"
                elif config['platform'] == 'bugcrowd':
                    asset = item.get('target', '')
                    eligible = "[green]✓[/green]"
                elif config['platform'] == 'intigriti':
                    asset = item.get('endpoint', '')
                    eligible = "[green]✓[/green]"
                else:
                    continue
                wildcard_table.add_row(config['program_name'] or config['platform'], asset, "WILDCARD", eligible)

            console.print(wildcard_table)
            console.print()

        if urls_list:
            console.print("[bold magenta]═══ URLs (direct targets) ═══[/bold magenta]")
            url_table = Table(box=box.SIMPLE)
            url_table.add_column("Program", style="dim")
            url_table.add_column("Scope", style="magenta")
            url_table.add_column("Type", style="dim magenta")
            url_table.add_column("Eligible", style="dim")

            for item in urls_list:
                if config['platform'] == 'hackerone':
                    asset = item.get('asset_identifier', '')
                    eligible = "[green]✓[/green]" if item.get('eligible_for_bounty', True) else "[red]✗[/red]"
                elif config['platform'] == 'bugcrowd':
                    asset = item.get('target', '')
                    eligible = "[green]✓[/green]"
                elif config['platform'] == 'intigriti':
                    asset = item.get('endpoint', '')
                    eligible = "[green]✓[/green]"
                else:
                    continue
                url_table.add_row(config['program_name'] or config['platform'], asset, "URL", eligible)

            console.print(url_table)
            console.print("[dim]URLs are direct targets only — not enumerated in Phase 1[/dim]")
            console.print()

        if others_list:
            console.print("[bold yellow]═══ Others (web/api assets) ═══[/bold yellow]")
            other_table = Table(box=box.SIMPLE)
            other_table.add_column("Program", style="dim")
            other_table.add_column("Scope", style="yellow")
            other_table.add_column("Type", style="yellow")
            other_table.add_column("Eligible", style="green")

            for item in others_list:
                if config['platform'] == 'hackerone':
                    asset = item.get('asset_identifier', '')
                    eligible = "[green]✓[/green]" if item.get('eligible_for_bounty', True) else "[red]✗[/red]"
                elif config['platform'] == 'bugcrowd':
                    asset = item.get('target', '')
                    eligible = "[green]✓[/green]"
                elif config['platform'] == 'intigriti':
                    asset = item.get('endpoint', '')
                    eligible = "[green]✓[/green]"
                else:
                    continue
                other_table.add_row(config['program_name'] or config['platform'], asset, "OTHER", eligible)

            console.print(other_table)
            console.print()

        if skipped_counts:
            skipped_parts = []
            if 'mobile_ios' in skipped_counts:
                skipped_parts.append(f"{skipped_counts['mobile_ios']} mobile iOS")
            if 'mobile_android' in skipped_counts:
                skipped_parts.append(f"{skipped_counts['mobile_android']} mobile Android")
            if 'hardware' in skipped_counts:
                skipped_parts.append(f"{skipped_counts['hardware']} hardware")
            if 'app_id' in skipped_counts:
                skipped_parts.append(f"{skipped_counts['app_id']} app IDs")
            if 'description' in skipped_counts or 'tier_description' in skipped_counts:
                desc_count = skipped_counts.get('description', 0) + skipped_counts.get('tier_description', 0)
                skipped_parts.append(f"{desc_count} descriptions")
            if 'store_id' in skipped_counts:
                skipped_parts.append(f"{skipped_counts['store_id']} store IDs")
            if 'steam' in skipped_counts:
                skipped_parts.append(f"{skipped_counts['steam']} steam")
            if 'other' in skipped_counts or 'unknown_type' in skipped_counts:
                other_count = skipped_counts.get('other', 0) + skipped_counts.get('unknown_type', 0)
                skipped_parts.append(f"{other_count} other")

        # Save skipped items
        if skipped_list:
            skipped_file = os.path.join(proj_dir, "phase0", "skipped-scope.txt")
            with open(skipped_file, 'w') as f:
                for item, reason in skipped_list:
                    if config['platform'] == 'hackerone':
                        asset = item.get('asset_identifier', '')
                    elif config['platform'] == 'bugcrowd':
                        asset = item.get('target', '')
                    elif config['platform'] == 'intigriti':
                        asset = item.get('endpoint', '')
                    else:
                        asset = ''
                    if asset:
                        f.write(f"{reason}: {asset}\n")

        # Save scope files
        urls_file = os.path.join(proj_dir, "phase0", "urls.txt")
        with open(urls_file, 'w') as f:
            for item in urls_list:
                asset = extract_base_domain(item, config['platform'])
                if asset:
                    f.write(f"{asset}\n")

        wildcards_file = os.path.join(proj_dir, "phase0", "wildcards.txt")
        with open(wildcards_file, 'w') as f:
            for item in wildcards_list:
                if config['platform'] == 'hackerone':
                    asset = item.get('asset_identifier', '')
                elif config['platform'] == 'bugcrowd':
                    asset = item.get('target', '')
                elif config['platform'] == 'intigriti':
                    asset = item.get('endpoint', '')
                else:
                    asset = ''
                if asset:
                    f.write(f"{asset}\n")

        with open(wildcards_file, 'r') as f:
            raw_lines = [l.strip() for l in f if l.strip()]
        before_count = len(raw_lines)
        clean_lines = [l[2:] if l.startswith('*.') else l for l in raw_lines]
        clean_lines = sorted(set(clean_lines))
        after_count = len(clean_lines)
        with open(wildcards_file, 'w') as f:
            f.write('\n'.join(clean_lines) + '\n')
        console.print(f"[dim]  wildcards.txt: {before_count} → {after_count} clean domains[/dim]")

        others_file = os.path.join(proj_dir, "phase0", "others.txt")
        with open(others_file, 'w') as f:
            for item in others_list:
                if config['platform'] == 'hackerone':
                    asset = item.get('asset_identifier', '')
                elif config['platform'] == 'bugcrowd':
                    asset = item.get('target', '')
                elif config['platform'] == 'intigriti':
                    asset = item.get('endpoint', '')
                else:
                    asset = ''
                if asset:
                    f.write(f"{asset}\n")

        console.print(f"\n[dim]✓ Scope files saved[/dim]")

        response = Prompt.ask("Is the scope correct? (Press Enter to continue, [bold yellow]E[/bold yellow] to edit)", default="")
        if response.lower() == "e":
            lines = get_multiline_input("Add additional scope entries (one per line):")
            if lines:
                with open(wildcards_file, 'a') as f:
                    for line in lines:
                        f.write(f"{line}\n")
                console.print(f"[green]✓ Added {len(lines)} entries to wildcards[/green]")

        # ═══════════════════════════════════════
        # SUBDOMAIN ENUMERATION ELIGIBILITY
        # ═══════════════════════════════════════
        phase1_targets = []
        for item in wildcards_list:
            if config['platform'] == 'hackerone':
                asset = item.get('asset_identifier', '')
            elif config['platform'] == 'bugcrowd':
                asset = item.get('target', '')
            elif config['platform'] == 'intigriti':
                asset = item.get('endpoint', '')
            else:
                continue

            if asset.startswith('*.'):
                base_domain = asset[2:]
            elif asset.startswith('*'):
                base_domain = asset[1:].lstrip('.')
            else:
                base_domain = asset

            if base_domain and '.' in base_domain:
                phase1_targets.append(base_domain)

        phase1_targets = sorted(set(phase1_targets))
        debug(f"Phase1 targets: {len(phase1_targets)}")

        phase1_targets_file = os.path.join(proj_dir, "phase0", "phase1_targets.txt")
        with open(phase1_targets_file, 'w') as f:
            for target in phase1_targets:
                f.write(f"{target}\n")

        # ═══════════════════════════════════════
        # MULTI-TLD HANDLING
        # ═══════════════════════════════════════
        all_domains = set()
        for target in phase1_targets:
            all_domains.add(target)
        for item in urls_list:
            domain = extract_base_domain(item, config['platform'])
            if domain:
                all_domains.add(domain)

        all_domains = sorted(all_domains)
        domains_file = os.path.join(proj_dir, "phase0", "domains.txt")
        with open(domains_file, 'w') as f:
            for d in all_domains:
                f.write(f"{d}\n")

        config['multi_tld'] = len(all_domains) > 1
        config['tld_count'] = len(all_domains)

    else:
        console.print("[yellow]No scope data available — continuing with empty scope[/yellow]")
        config['testing_scope'] = 'web+api'
        for filename in ['urls.txt', 'wildcards.txt', 'others.txt', 'phase1_targets.txt', 'domains.txt', 'out-of-scope.txt']:
            filepath = os.path.join(proj_dir, "phase0", filename)
            with open(filepath, 'w') as f:
                f.write("")

    # ═══════════════════════════════════════
    # SAVE CONFIG
    # ═══════════════════════════════════════
    config['phase0_complete'] = True
    config_file = os.path.join(proj_dir, "phase0", "config.json")
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    debug(f"Config saved to: {config_file}")
    console.print(f"\n[dim]✓ Configuration saved[/dim]")

    # ═══════════════════════════════════════
    # FINAL SUMMARY
    # ═══════════════════════════════════════
    wildcards_count = len(wildcards_list) if all_scope_items else 0
    urls_count      = len(urls_list)      if all_scope_items else 0
    others_count    = len(others_list)    if all_scope_items else 0
    oos_count       = len(out_of_scope_items) if all_scope_items else 0
    phase1_count    = len(phase1_targets) if all_scope_items else 0

    summary_text = (
        f"[bold white]Project:[/bold white]    {project_name}\n"
        f"[bold white]Platform:[/bold white]   {config['platform'].title() if config['platform'] else 'N/A'} — {config['program_name'] or 'N/A'}\n"
        f"[bold white]Testing:[/bold white]    {config['testing_scope'] or 'N/A'}\n\n"
        f"[bold white]Wildcards:[/bold white]  {wildcards_count}  ✓ subdomain enum targets\n"
        f"[bold white]URLs:[/bold white]       {urls_count}   direct targets only\n"
        f"[bold white]Others:[/bold white]     {others_count}   web/api assets\n"
        f"[bold white]Out of scope:[/bold white] {oos_count} items excluded\n\n"
        f"[bold white]Phase 1 targets:[/bold white] {phase1_count} domains ready"
    )

    console.print()
    console.print(Panel(
        summary_text,
        title="[bold white]Phase 0 Complete[/bold white]",
        box=box.DOUBLE,
        border_style="cyan"
    ))

    # ═══════════════════════════════════════
    # CHAIN TO PHASE 1a
    # ═══════════════════════════════════════
    phase1_targets_file = Path(proj_dir) / "phase0" / "phase1_targets.txt"
    with open(phase1_targets_file) as f:
        targets = [line.strip() for line in f if line.strip()]

    if targets:
        phase1a = os.path.expanduser("~/SOA/2.Execution/Pipeline/Phase.1:Recon/phase1a_passive.py")
        if os.path.exists(phase1a):
            console.print()
            console.print(Panel(
                f"[bold white]→ Phase 1a — Passive Subdomain Enumeration[/bold white]\n"
                f"[dim]{len(targets)} targets | {proj_dir}[/dim]",
                box=box.DOUBLE,
                border_style="cyan",
                padding=(0, 1)
            ))
            subprocess.run(["python3", phase1a, "--projectdir", str(proj_dir)])
        else:
            console.print(f"[yellow]⚠ phase1a not found at {phase1a}[/yellow]")
            console.print(f"[dim]Run: python3 ~/SOA/2.Execution/Pipeline/Phase.1:Recon/phase1a_passive.py --projectdir {proj_dir}[/dim]")
    else:
        console.print("[red]✗ No Phase 1 targets found — check phase1_targets.txt[/red]")

    console.print()


if __name__ == "__main__":
    main()
