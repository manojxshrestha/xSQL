<h1 align="center">
  <br>
  <a href="https://github.com/manojxshrestha/">
    <img src="https://github.com/user-attachments/assets/f13b5818-01be-4333-bed1-71c22434b21b" alt="xSQL" width="450">
 </a>
  <br>
  xSQL
  <br>
</h1>


<p align="center">
A powerful recon and scanning tool for bug hunters, automating subdomain enumeration, URL crawling, and SQLi/XSS vulnerability testing with advanced WAF bypass capabilities.
</p>

<div align="center">

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/) 
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/manojxshrestha/xSQL/blob/main/LICENSE) 
[![GitHub Repo](https://img.shields.io/badge/repo-GitHub-black?logo=github)](https://github.com/manojxshrestha/xSQL) 
[![Issues](https://img.shields.io/github/issues/manojxshrestha/xSQL)](https://github.com/manojxshrestha/xSQL/issues) 
[![Stars](https://img.shields.io/github/stars/manojxshrestha/xSQL?style=social)](https://github.com/manojxshrestha/xSQL)

</div>

---
xSQL is a powerful, automated tool designed for bug hunters and security researchers to perform reconnaissance and scan for **SQL Injection (SQLi)** and **Cross-Site Scripting (XSS)** vulnerabilities in web applications. It integrates a suite of open-source tools to streamline subdomain enumeration, URL crawling, live filtering, and Web Application Firewall (WAF) detection, with advanced WAF bypass techniques. Featuring rich console output, HTML reporting, and scan resuming capabilities, xSQL is your go-to tool for efficient and ethical vulnerability discovery.

---

**Disclaimer**: xSQL is for **ethical security testing** only. Use it **only with explicit permission** from the target owner. Unauthorized scanning is illegal and unethical. You must confirm "I AGREE" when prompted by the tool.

## Features

- **Subdomain Enumeration**: Discover subdomains using `subfinder`, `assetfinder`, and `findomain`, with DNS resolution via `dnsx`.
- **URL Crawling**: Extract URLs from subdomains with `katana` or fetch historical URLs for single domains using `waybackurls` and `gau`.
- **Live Filtering**: Filter live subdomains and URLs with `httpx`, supporting custom ports (80, 443, 8080, 8443, 8000, 8888) and status codes (200, 204, 301, 302, 307, 401, 403, 500).
- **WAF Detection and Bypass**: Detect WAFs with `wafw00f` and bypass them using encoded payloads from `waf_bypass_payloads.txt` (supports URL, double URL, HTML, mixed case, Unicode, and Base64 encodings).
- **Vulnerability Testing**: Test for SQLi (error-based and blind) and XSS (reflected) using customizable payloads from `sqlipayloads.txt` and `xsspayloads.txt`.
- **Advanced WAF Evasion**: Apply multiple encoding techniques and randomized HTTP headers to evade WAFs.
- **Randomized Requests**: Use random User-Agents, custom headers, and delays to mimic legitimate traffic and avoid rate-limiting.
- **Rich Console Output**: Display progress bars and logs using the `rich` library for a user-friendly experience.
- **HTML Reporting**: Generate detailed HTML reports (`results/xsql_report.html`) with vulnerabilities, WAF details, and encodings used.
- **Scan Resuming**: Resume interrupted scans from checkpoints stored in `results/xsql_state.json`.
- **Proxy Support**: Route requests through a proxy (e.g., Burp Suite) for manual inspection.
- **Debug Mode**: Enable verbose logging to troubleshoot issues.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/manojxshrestha/xSQL.git
   cd xSQL
   ```

2. **Run the Installer Script**:
   The `installer.sh` script sets up a Python virtual environment and installs required tools (`subfinder`, `assetfinder`, `findomain`, `dnsx`, `httpx`, `katana`, `waybackurls`, `gau`, `uro`, `anew`, `wafw00f`) and Python dependencies (`requests`, `rich`, `tldextract`):
   ```bash
   chmod +x installer.sh
   ./installer.sh
   ```

3. **Activate the Virtual Environment**:
   ```bash
   source venv/bin/activate
   ```

4. **Prepare Payload Files**:
   Create or customize these files in the project directory:
   - `sqlipayloads.txt`: SQLi payloads (one per line, e.g., `' OR '1'='1`).
   - `xsspayloads.txt`: XSS payloads (one per line, e.g., `<script>alert(1)</script>`).
   - `waf_bypass_payloads.txt`: WAF bypass payloads for SQLi and XSS (one per line, e.g., `1' UNION SELECT NULL--` or `<svg/onload=alert(1)>`).

## Integrated Tools and Their Roles

xSQL leverages the following open-source tools to enhance its reconnaissance and scanning capabilities:

- **subfinder**: Discovers subdomains using passive sources (e.g., VirusTotal, Shodan).
- **assetfinder**: Finds subdomains from public sources like Certificate Transparency logs.
- **findomain**: Enumerates subdomains with high accuracy, supporting multiple sources.
- **dnsx**: Resolves subdomains to verify their DNS records (e.g., A records).
- **httpx**: Filters live subdomains and URLs, checking for specific ports and status codes.
- **katana**: Crawls live subdomains to extract URLs for vulnerability testing.
- **waybackurls**: Fetches historical URLs from the Wayback Machine for single-domain scans.
- **gau**: Retrieves archived URLs from Common Crawl and other sources.
- **uro**: Filters and deduplicates URLs to reduce noise.
- **anew**: Appends unique entries to output files, preventing duplicates.
- **wafw00f**: Detects WAFs on target URLs, identifying vendors like Cloudflare or ModSecurity.

## Subdomain Enumeration and Flags

### `--subdomains`
- **What It Does**: Enables subdomain enumeration for the target domain using `subfinder`, `assetfinder`, and `findomain`. The results are saved to `results/subdomains.txt` and filtered for live subdomains using `dnsx` and `httpx` (ports: 80, 443, 8080, 8443, 8000, 8888; status codes: 200, 204, 301, 302, 307, 401, 403, 500). Live subdomains are stored in `results/alivesubs.txt` and crawled with `katana` to extract URLs for vulnerability testing.
- **When to Use**: Use this flag when you want to expand the attack surface by testing subdomains (e.g., `sub.testphp.vulnweb.com`) in addition to the main domain.
- **Impact**: Increases scan scope but may take longer and generate more URLs, especially for large domains.

### `--skip-subdomains`
- **What It Does**: Skips subdomain enumeration and focuses only on the main domain (e.g., `testphp.vulnweb.com`). URLs are fetched using `waybackurls` and `gau` (historical data) instead of crawling subdomains with `katana`. This reduces scan time and focuses testing on the primary domain.
- **When to Use**: Use this flag for quick scans, when subdomains are out of scope, or when you want to target a single domain with historical URLs.
- **Impact**: Faster scans but misses potential vulnerabilities on subdomains.

**Note**: You cannot use both `--subdomains` and `--skip-subdomains` together, as they are mutually exclusive.

## Usage Commands

Below are example commands showcasing different use cases, including the use of `--subdomains` and `--skip-subdomains`:

1. **Full Scan with Subdomains (Recommended for Comprehensive Testing)**:
   ```bash
   python3 xsql.py -d testphp.vulnweb.com --live --subdomains --test-both --test-waf-urls --debug
   ```
   - Enumerates subdomains, filters live ones, crawls URLs with `katana`, tests for SQLi and XSS, and attempts WAF bypasses.
   - Debug mode provides verbose logs in `results/xsql.log`.

2. **Quick Scan without Subdomains**:
   ```bash
   python3 xsql.py -d testphp.vulnweb.com --live --skip-subdomains --test-both --test-waf-urls
   ```
   - Skips subdomain enumeration, fetches URLs with `waybackurls` and `gau`, and tests for SQLi and XSS with WAF bypass attempts.

3. **SQLi-Only Scan with Proxy**:
   ```bash
   python3 xsql.py -d testphp.vulnweb.com --live --subdomains --test-sqli --proxy http://127.0.0.1:8080
   ```
   - Enumerates subdomains, tests only for SQLi, and routes requests through a proxy (e.g., Burp Suite).

4. **XSS-Only Scan without WAF Testing**:
   ```bash
   python3 xsql.py -d testphp.vulnweb.com --live --skip-subdomains --test-xss
   ```
   - Skips subdomains and WAF testing, focuses on XSS vulnerabilities using `xsspayloads.txt`.

5. **Custom Payloads and Delay**:
   ```bash
   python3 xsql.py -d testphp.vulnweb.com --live --subdomains --test-both --waf-bypass-payload-file custom_waf_payloads.txt --delay 0.5
   ```
   - Uses a custom WAF bypass payload file and increases request delay to 0.5 seconds to avoid rate-limiting.

## Help Usage

Run the following command to view all available options:
```bash
python3 xsql.py --help
```

### Available Flags
| Flag | Description | Default |
|------|-------------|---------|
| `-d`, `--domain` | Target domain (e.g., `testphp.vulnweb.com`). | Required |
| `--live` | Filter live subdomains and URLs using `httpx`. | Disabled |
| `--subdomains` | Enumerate subdomains with `subfinder`, `assetfinder`, `findomain`. | Disabled |
| `--skip-subdomains` | Skip subdomain enumeration, focus on main domain. | Disabled |
| `--test-sqli` | Test for SQL Injection vulnerabilities. | Disabled |
| `--test-xss` | Test for Cross-Site Scripting vulnerabilities. | Disabled |
| `--test-both` | Test for both SQLi and XSS vulnerabilities. | Disabled |
| `--test-waf-urls` | Test WAF-protected URLs with bypass payloads. | Disabled |
| `--waf-test-percentage` | Percentage of URLs to test for WAFs (1-100). | 100 |
| `--waf-bypass-payload-file` | Custom WAF bypass payload file. | `waf_bypass_payloads.txt` |
| `--proxy` | Proxy for requests (e.g., `http://127.0.0.1:8080`). | None |
| `--delay` | Base delay between requests in seconds. | 0.3 |
| `--resume` | Resume scan from `results/xsql_state.json`. | Disabled |
| `--debug` | Enable verbose logging to console and `results/xsql.log`. | Disabled |

### Example Output
```
[*] Starting subdomain enumeration for testphp.vulnweb.com...
[+] Found 3 subdomains: sub1.testphp.vulnweb.com, sub2.testphp.vulnweb.com, sub3.testphp.vulnweb.com
[*] Filtering live subdomains with dnsx and httpx...
[+] Found 1 live subdomains: sub1.testphp.vulnweb.com
[*] Crawling URLs with katana...
[+] Found 10 URLs for testing
[*] Detecting WAFs with wafw00f...
[+] WAF detected on 2 URLs: Cloudflare
[*] Testing for SQLi and XSS vulnerabilities...
[green][SQLi] Vulnerable (WAF bypassed): http://sub1.testphp.vulnweb.com/test.php?id=1%27%20OR%20%271%27%3D%271 (encoding: url, WAF: Cloudflare)[/green]
[green][XSS] Vulnerable: http://sub1.testphp.vulnweb.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E[/green]
[+] Report generated: results/xsql_report.html
```

## Best Practices for Usage

1. **Start with a Quick Scan**:
   - Use `--skip-subdomains` for initial testing to focus on the main domain and historical URLs:
     ```bash
     python3 xsql.py -d testphp.vulnweb.com --live --skip-subdomains --test-both
     ```

2. **Comprehensive Recon**:
   - Enable `--subdomains` for thorough scans, especially for large domains with many subdomains:
     ```bash
     python3 xsql.py -d testphp.vulnweb.com --live --subdomains --test-both --test-waf-urls --debug
     ```

3. **WAF Evasion**:
   - Customize `waf_bypass_payloads.txt` with advanced payloads from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings).
   - Use `--test-waf-urls` to attempt bypassing detected WAFs.
   - Increase `--delay` (e.g., 0.5) to avoid rate-limiting.

4. **Proxy Integration**:
   - Route traffic through Burp Suite or similar for manual verification:
     ```bash
     python3 xsql.py -d testphp.vulnweb.com --live --subdomains --test-both --proxy http://127.0.0.1:8080
     ```

5. **Debug and Analyze**:
   - Use `--debug` to troubleshoot issues and check `results/xsql.log` for detailed logs.
   - Manually verify vulnerabilities using tools like Burp Suite or a browser.

6. **Resume Scans**:
   - If a scan is interrupted, resume it with:
     ```bash
     python3 xsql.py -d testphp.vulnweb.com --resume
     ```

7. **Optimize Payloads**:
   - Tailor `sqlipayloads.txt` and `xsspayloads.txt` to the target’s technology stack (e.g., MySQL-specific SQLi payloads).
   - Add database-specific WAF bypass payloads (e.g., `PG_SLEEP` for PostgreSQL).

## Output Files

- `results/subdomains.txt`: Enumerated subdomains.
- `results/alivesubs.txt`: Live subdomains filtered by `dnsx` and `httpx`.
- `results/urls.txt`: Crawled or fetched URLs.
- `results/waf_results.json`: WAF detection results.
- `results/vulnerable_urls.txt`: Detected vulnerabilities (non-WAF).
- `results/waf_bypassed_vulnerable_urls.txt`: Vulnerabilities bypassing WAFs.
- `results/xsql_report.html`: HTML report with scan results.
- `results/xsql_state.json`: Scan state for resuming.
- `results/xsql.log`: Debug logs (if `--debug` is enabled).

## Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/new-feature`).
3. Commit your changes (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature/new-feature`).
5. Open a Pull Request.

Please report issues or suggest features via the [Issues](https://github.com/manojxshrestha/xSQL/issues) tab.

## License

xSQL is licensed under the [MIT License](LICENSE). See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built ❤️ by [me](https://github.com/manojxshrestha).
- Thanks to the open-source community for tools like `subfinder`, `assetfinder`, `findomain`, `dnsx`, `httpx`, `katana`, and `wafw00f`.

## Contact

For questions or support, open an issue on [GitHub](https://github.com/manojxshrestha/xSQL/issues) or reach out via [Instagram](https://www.instagram.com/manojxshrestha).

---

Happy Hunting! 🚀
