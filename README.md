# AlanScan v3.1.0

**AlanScan** is a hybrid, modular vulnerability scanner for web applications and network hosts. It combines deterministic detection modules, evidence validation, CVSS v3.1 scoring, optional AI-assisted narrative analysis, and multi-format reporting (HTML dashboard, print-ready PDF, JSON). It is designed for **authorised security assessments**, coursework, and research prototypes that require reproducible methodology and professional deliverables.

---

## What's New in v3.1.0

| Area | Upgrade |
|------|---------|
| **New Modules** | Open Redirect scanner (`open_redirect.py`) |
| **New Modules** | HTTP Method Tampering (`method_tampering.py`) — TRACE/XST, method override |
| **New Modules** | Enhanced Security Headers Plus (`security_headers_plus.py`) — COEP/COOP/CORP, Cache-Control |
| **Attack Chains** | 4 new chain rules: Open Redirect+API, IDOR+WeakAuth, Enumeration+RateLimit, SQLi+HTTP |
| **config.py** | `OPEN_REDIRECT_PAYLOADS`, `IDOR_SENSITIVE_PARAMS`, `COMPLIANCE_FRAMEWORKS`, `MITRE_ATTACK_MAPPING` |
| **Reports HTML** | Compliance matrix, MITRE ATT&CK table, Remediation Timeline, Methodology section |
| **Reports PDF** | Compliance page, MITRE page, Methodology appendix |
| **Reports JSON** | `compliance_summary` block per framework with requirement IDs |
| **AI Analyst** | Open Redirect and Method Tampering analysis blocks added |
| **AI Model** | Confirmed `claude-sonnet-4-20250514` |
| **Bug Fix** | Duplicate `VERSION` declaration in `config.py` removed |
| **Bug Fix** | `chainer.py` severity label colour (CRITICAL=RED, HIGH=YELLOW) |

---

## Features at a glance

| Area | Capability |
|------|------------|
| **Web** | SQLi (error / boolean / time), XSS (reflected + static DOM sink hints), CSRF, SSRF, CMDi, XXE, LFI, headers, cookies, SSL/TLS, directory discovery, WAF detection |
| **API** | Swagger/OpenAPI exposure (consolidated finding + supporting assets), GraphQL introspection |
| **Auth** | Default / weak credential checks, username-enumeration heuristics, optional `--credentials` for authenticated re-scan |
| **Access control** | IDOR heuristics (session-aware when login succeeds) |
| **Quality** | Evidence validator (confidence, deduplication), PoC / steps / impact enrichment, HTTP response capture for SQLi/CMDi, PDF includes response excerpts |
| **Risk** | CVSS v3.1 vectors from metadata + base score calculation, severity normalisation, vulnerability chaining |
| **Reporting** | Interactive HTML, PDF, JSON (validation stats, timings, cipher appendix where applicable) |
| **AI** | Optional executive summary, top priorities (deduplicated by type + base URL), remediation narrative (Anthropic API) |

---

## Architecture

High-level pipeline for a **web scan**:

1. **Crawl** — Same-origin URL discovery and parameter harvesting.  
2. **Authentication audit** — Login form discovery; default-cred attempts; enumeration probes; optional user-supplied credentials; established session forwarded to selected modules.  
3. **Recon & controls** — WAF, headers, SSL/TLS, cookies, directories, API checks.  
4. **Vulnerability modules** — Parallel testing across URLs (with WAF bypass payload sets when a WAF is detected).  
5. **Chaining** — Multi-finding attack paths for prioritisation.  
6. **Evidence validation** — Confidence scoring, false-positive reduction, duplicate folding.  
7. **CVSS scoring** — Vector-based base score and consistent severity bands.  
8. **Report enrichment** — Deterministic PoC, steps, and impact text per finding class.  
9. **Evidence collection** — Optional replay for SQLi/CMDi/CSRF to attach HTTP bodies and raw transcripts.  
10. **AI analysis** (optional) — Target-specific narrative blocks.  
11. **Export** — HTML + PDF + JSON under `output/`.

Network scans follow a shorter path: port scan → banners → CVE correlation → validation → scoring → reports.

```
AlanScan/
├── AlanScan.py                 # CLI
├── config.py                   # Payloads, signatures, OWASP/CVSS metadata
├── requirements.txt
├── scanner/
│   ├── controller.py           # Orchestration
│   ├── evidence_validator.py
│   ├── evidence_collector.py
│   ├── scoring_engine.py
│   ├── cvss31.py
│   ├── report_enricher.py
│   ├── chainer.py
│   ├── ai_analyst.py
│   ├── web/
│   │   ├── base.py             # Shared HTTP session
│   │   ├── auth_audit.py       # Credentials + enumeration + session
│   │   ├── crawler.py
│   │   ├── api_security.py    # Swagger consolidation + GraphQL
│   │   ├── sqli.py, xss.py, csrf.py, ssrf.py, cmdi.py, xxe.py, lfi.py
│   │   ├── headers.py, cookies.py, ssl_tls.py, directories.py, waf.py
│   │   ├── idor.py, rate_limit.py
│   └── network/
│       ├── portscan.py, banner.py, cve.py
└── reports/
    ├── html_reporter.py
    ├── pdf_reporter.py
    └── reporter.py
```

---

## Installation

**Python 3.10+** recommended (modern type hints throughout).

```bash
pip install -r requirements.txt
```

Dependencies include `requests`, `beautifulsoup4`, `colorama`, `lxml`, `urllib3`, `reportlab`, and `chardet`.

---

## Usage

### Web scan (default full coverage)

```bash
python AlanScan.py -u https://target.example
```

The default profile enables all web modules when no profile flag is given (see `--list-profiles`).

### Authenticated assessment

After crawl, the tool attempts login where forms exist, tries a small default-credential set, and can use your pair for a real session. Cookies are propagated into **SQLi, XSS, CMDi, and IDOR** workers so authenticated-only issues are more likely to surface.

```bash
python AlanScan.py -u https://target.example --web-scan --credentials admin:admin
```

### Tuning

```bash
python AlanScan.py -u https://target.example -d 5 -t 20 --timeout 8 --output-dir reports
```

### Intercepting proxy (Burp / ZAP)

```bash
python AlanScan.py -u https://target.example --proxy http://127.0.0.1:8080
```

Ensure **intercept is off** for long scans, or the crawler will stall.

### Network scan

```bash
python AlanScan.py -ip 192.168.1.100 --network-scan
```

### Scan profiles

- `--full-scan` — All web modules (and ports when included in profile).  
- `--quick-scan`, `--web-scan`, `--stealth-scan`, `--injection-scan`, `--owasp-scan`, `--fast-scan`  
- `--network-scan` — Host-only.

Combine profiles with **additive** flags, e.g. `--quick-scan --cmdi`.

```bash
python AlanScan.py --list-profiles
```

### AI narrative (optional)

Set an API key once; the CLI enables AI by default unless `--no-ai` is passed.

```bash
# Windows
setx ANTHROPIC_API_KEY "sk-ant-api03-..."

# Linux / macOS
export ANTHROPIC_API_KEY="sk-ant-api03-..."
```

---

## Reports and artefacts

All outputs land in **`output/`** (or `--output-dir`):

| File | Purpose |
|------|---------|
| `alanscan_*_*.html` | Interactive dashboard: filters, finding cards, HTTP evidence panels for SQLi/CMDi/CSRF |
| `alanscan_*_*.pdf` | Executive-style PDF: severity summary, chains, per-finding tables, **HTTP excerpts** for injection findings |
| `alanscan_*_*.json` | Machine-readable: findings, scoring, validation summary, scan metrics, extra TLS/port metadata |

---

## Methodology notes (for academic / professional write-ups)

- **Reproducibility** — Fixed pipeline order; configuration centralised in `config.py`; version in tool banner.  
- **False-positive control** — Validator uses module-specific rules (e.g. redirect-only directory hits penalised unless validated).  
- **Deduplication** — URL/query normalisation and logical grouping (e.g. Swagger assets → single exposure finding).  
- **CVSS** — Metadata carries CWE, OWASP mapping, and CVSS:3.1 vectors; base scores computed where vectors are valid.  
- **Ethics** — Only targets you own or have **written permission** to test.

---

## Limitations (honest scope for a masters report)

- Automated scanners complement — they do not replace — manual expert testing.  
- **Authenticated** coverage depends on successful login and app-specific flows (MFA, CAPTCHA, SSO are out of scope).  
- **IDOR** results are heuristic; confirm with business context and authorisation models.  
- **AI** text is advisory; findings and evidence objects remain the source of truth.

---

## Contributing / extending

- Add payloads or signatures in `config.py`.  
- New modules: implement a `scan() -> list[dict]` with keys `type`, `url`, `parameter`, `payload`, `severity`, `evidence`, then register in `scanner/controller.py`.  
- New finding types: add `VULN_METADATA` entries for consistent CVSS and report text.

---

## License and ethics

Use **only** on systems you are authorised to assess. Unauthorised scanning may violate computer misuse and privacy laws. AlanScan is provided for education and authorised security work.

---

## Acknowledgements

OWASP, MITRE CWE, and NIST CVSS v3.1 specifications inform severity metadata and terminology. Optional AI analysis uses the Anthropic API when configured.