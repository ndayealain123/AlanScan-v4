#!/usr/bin/env python3
"""
AlanScan v3.1.0 — Advanced Hybrid AI-Augmented Vulnerability Scanner
=====================================================================
Author  : Alain NDAYE
Purpose : Automated Web & Network Vulnerability Assessment

Usage:
  # Scan profiles:
  python AlanScan.py -u https://target.com --full-scan
  python AlanScan.py -u https://target.com --quick-scan
  python AlanScan.py -u https://target.com --web-scan
  python AlanScan.py -u https://target.com --stealth-scan
  python AlanScan.py -u https://target.com --injection-scan
  python AlanScan.py -u https://target.com --owasp-scan
  python AlanScan.py -ip 192.168.1.1 --network-scan

  # Additive — combine profile + extra modules:
  python AlanScan.py -u https://target.com --quick-scan --xxe --cmdi
  python AlanScan.py -u https://target.com --web-scan --ports

  # Individual modules:
  python AlanScan.py -u https://target.com --sqli --xss --csrf

  # Utility:
  python AlanScan.py --list-profiles
  python AlanScan.py --version
  python AlanScan.py -u target.com --full-scan --output-dir /reports
  python AlanScan.py -u https://target.com --full-scan --credentials admin:admin
"""

import argparse
import sys
import os
import time
from scanner.scan_logger import (
    Fore,
    Style,
    configure_scanner_console_logging,
    init_terminal_colors,
    logger,
)
from scanner.controller import ScannerController
import config

def _configure_console_encoding() -> None:
    """
    Windows terminals often default to cp1252, which breaks Unicode box-drawing
    characters used by this CLI.

    We reconfigure stdout/stderr to UTF-8 before Colorama wraps streams.
    """
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        # If reconfigure is unavailable, we continue; safe fallbacks exist for banner.
        pass


_configure_console_encoding()
init_terminal_colors()
configure_scanner_console_logging()

try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# ── Banner ──────────────────────────────────────────────────────────────────
# Inner width = 65 chars exactly. All 8 letters of ALANSCAN visible in GREEN.
# Box border = 67 ═ chars. Every line padded precisely with _b().

def _b(s, width=65):
    """Pad to exactly width chars. Box: ║ SPACE _b(65) SPACE ║ = 69 inner."""
    s = str(s)
    if len(s) >= width:
        return s[:width]
    return s + " " * (width - len(s))


def _make_banner():
    """Build banner string with ALANSCAN in GREEN and N visible."""
    W = Fore.WHITE
    C = Fore.CYAN
    G = Fore.GREEN
    Y = Fore.YELLOW
    RS = Style.RESET_ALL
    v = config.VERSION
    a = config.AUTHOR
    
    # ASCII Art Logo - ALANSCAN in GREEN
    art = [
        " █████╗ ██╗      █████╗ ███╗  ██╗███████╗ ██████╗ █████╗ ███╗  ",
        "██╔══██╗██║     ██╔══██╗████╗ ██║██╔════╝██╔════╝██╔══██╗████╗ ",
        "███████║██║     ███████║██╔██╗██║███████╗██║     ███████║██╔██╗ ",
        "██╔══██║██║     ██╔══██║██║╚████║╚════██║██║     ██╔══██║██║╚██╗",
        "██║  ██║███████╗██║  ██║██║ ╚███║███████║╚██████╗██║  ██║██║ ╚██╗",
        "╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝ ╚═╝",
    ]
    
    border = "═" * 69
    b = f"\n{C}╔{border}╗\n"
    
    # Print ASCII art lines in GREEN
    for line in art:
        b += f"║ {G}{_b(line)} {C}║\n"
    
    b += f"║ {_b(chr(32))} ║\n"
    
    # ALANSCAN text in GREEN with stars
    b += f"║ {G}{_b(chr(32)*7 + chr(9733) + chr(32)*2 + 'A' + chr(32)*2 + 'L' + chr(32)*2 + 'A' + chr(32)*2 + 'N' + chr(32)*2 + 'S' + chr(32)*2 + 'C' + chr(32)*2 + 'A' + chr(32)*2 + 'N' + chr(32)*2 + chr(9733))} {C}║\n"
    
    b += f"║ {_b(chr(32))} ║\n"
    b += f"╠{border}╣\n"
    
    # Description lines
    b += f"║ {W}{_b(chr(32)*2 + 'Automated Web & Network Vulnerability Scanner' + chr(32)*12 + 'v' + str(v))} {C}║\n"
    b += f"║ {W}{_b(chr(32)*2 + 'Author: ' + str(a) + chr(32)*2 + '|' + chr(32)*2 + 'Hybrid AI-Augmented Scanner')} {C}║\n"
    b += f"║ {Y}{_b(chr(32)*2 + chr(9888) + chr(32)*2 + 'For authorised security assessments only')} {C}║\n"
    b += f"╚{border}╝{RS}\n"
    
    return b


BANNER = _make_banner()
#
# Some Windows terminals default to cp1252 encoding. If the banner contains
# characters the console can't encode, the CLI crashes before the scan starts.
# We keep the original banner as the default, but fall back to ASCII-only when
# a UnicodeEncodeError occurs.
BANNER_ASCII = (
    "ALANSCAN - Automated Web & Network Vulnerability Scanner\n"
    "For authorised security assessments only\n"
    f"Version: {config.VERSION} | Author: {config.AUTHOR}"
)


def safe_print_banner() -> None:
    try:
        logger.info(BANNER)
    except UnicodeEncodeError:
        logger.info(BANNER_ASCII)

# ══════════════════════════════════════════════════════════════════════════════
# SCAN PROFILES
# ══════════════════════════════════════════════════════════════════════════════
PROFILES = {
    "full-scan": {
        "description": "All 15 modules — complete assessment (recommended)",
        "modules": {
            "sqli":True,"xss":True,"csrf":True,"ssrf":True,"cmdi":True,
            "xxe":True,"lfi":True,"headers":True,"ssl":True,"cookies":True,
            "dirs":True,"waf":True,"api":True,"idor":True,"rate":True,
            "ports":True,"chain":True,
            "redirect":True,"method":True,"headers_plus":True,
        }
    },
    "quick-scan": {
        "description": "Fast — headers, SSL, cookies, WAF, dirs, chain only",
        "modules": {
            "sqli":False,"xss":False,"csrf":False,"ssrf":False,"cmdi":False,
            "xxe":False,"lfi":False,"headers":True,"ssl":True,"cookies":True,
            "dirs":True,"waf":True,"api":True,"idor":False,"rate":False,
            "ports":False,"chain":True,
        }
    },
    "web-scan": {
        "description": "All web modules — no network port scanning",
        "modules": {
            "sqli":True,"xss":True,"csrf":True,"ssrf":True,"cmdi":True,
            "xxe":True,"lfi":True,"headers":True,"ssl":True,"cookies":True,
            "dirs":True,"waf":True,"api":True,"idor":True,"rate":True,
            "ports":False,"chain":True,
        }
    },
    "stealth-scan": {
        "description": "Low-noise — headers, SSL, cookies, WAF only",
        "modules": {
            "sqli":False,"xss":False,"csrf":False,"ssrf":False,"cmdi":False,
            "xxe":False,"lfi":False,"headers":True,"ssl":True,"cookies":True,
            "dirs":False,"waf":True,"api":False,"idor":False,"rate":False,
            "ports":False,"chain":False,
        }
    },
    "injection-scan": {
        "description": "All injection vectors — SQLi, XSS, CMDi, XXE, LFI, SSRF",
        "modules": {
            "sqli":True,"xss":True,"csrf":False,"ssrf":True,"cmdi":True,
            "xxe":True,"lfi":True,"headers":False,"ssl":False,"cookies":False,
            "dirs":False,"waf":True,"api":False,"idor":False,"rate":False,
            "ports":False,"chain":True,
        }
    },
    "owasp-scan": {
        "description": "OWASP Top 10:2021 — all A01–A10 categories",
        "modules": {
            "sqli":True,"xss":True,"csrf":True,"ssrf":True,"cmdi":True,
            "xxe":True,"lfi":True,"headers":True,"ssl":True,"cookies":True,
            "dirs":True,"waf":True,"api":True,"idor":True,"rate":True,
            "ports":False,"chain":True,
        }
    },
    "fast-scan": {
        "description": "Fast external scan — reduced payloads, high threads, low timeout",
        "modules": {
            "sqli":True,"xss":True,"csrf":True,"ssrf":False,"cmdi":False,
            "xxe":False,"lfi":True,"headers":True,"ssl":True,"cookies":True,
            "dirs":True,"waf":True,"api":True,"idor":False,"rate":False,
            "ports":False,"chain":True,
        }
    },
    "network-scan": {
        "description": "Network only — ports, banners, CVE correlation",
        "modules": {
            "sqli":False,"xss":False,"csrf":False,"ssrf":False,"cmdi":False,
            "xxe":False,"lfi":False,"headers":False,"ssl":False,"cookies":False,
            "dirs":False,"waf":False,"ports":True,"chain":True,
            "redirect":True,"method":True,"headers_plus":True,
        }
    },
}


def print_profiles():
    safe_print_banner()
    print(f"{Fore.CYAN}  Available Scan Profiles\n  {'─'*65}")
    for name, data in PROFILES.items():
        mods = data.get("modules") or PROFILES.get("full-scan", {}).get("modules") or {}
        enabled  = [k.upper() for k, v in mods.items() if v]
        disabled = [k.upper() for k, v in mods.items() if not v]
        color = Fore.GREEN if name == "full-scan" else \
                Fore.YELLOW if name in ("stealth-scan","quick-scan") else Fore.WHITE
        print(f"\n  {color}--{name:<20}{Fore.CYAN}  {data['description']}")
        print(f"  {Fore.GREEN}  ON : {', '.join(enabled) or 'none'}")
        if disabled:
            print(f"  {Fore.RED}  OFF: {', '.join(disabled)}")
    print(f"\n{Fore.CYAN}  {'─'*65}")
    print(f"  {Fore.WHITE}Profiles are ADDITIVE — extend with individual flags:")
    print(f"  {Fore.YELLOW}  python AlanScan.py -u target.com --quick-scan --xxe --cmdi")
    print(f"{Style.RESET_ALL}")


def print_version():
    safe_print_banner()
    print(f"  {Fore.WHITE}Tool      : {Fore.CYAN}{config.TOOL_NAME}")
    print(f"  {Fore.WHITE}Version   : {Fore.CYAN}{config.VERSION}")
    print(f"  {Fore.WHITE}Author    : {Fore.CYAN}{config.AUTHOR}")
    print(f"  {Fore.WHITE}Type      : {Fore.CYAN}Hybrid AI-Augmented Vulnerability Scanner")
    print(f"  {Fore.WHITE}Modules   : {Fore.CYAN}18 detection + Chaining Engine + AI Analyst + 3 reporters")
    print(f"  {Fore.WHITE}OWASP     : {Fore.CYAN}A01–A10:2021 (Complete)")
    _ai_model = os.environ.get("ANTHROPIC_MODEL", "claude-3-sonnet-20240229")
    print(f"  {Fore.WHITE}AI Model  : {Fore.CYAN}{_ai_model} (Anthropic Messages API){Style.RESET_ALL}\n")


def build_parser():
    p = argparse.ArgumentParser(
        prog="AlanScan",
        description=(
            "AlanScan v3.1.0 — Hybrid AI-Augmented Vulnerability Scanner\n"
            "Covers: SQLi · XSS · CSRF · SSRF · CMDi · XXE · LFI · Headers ·\n"
            "        SSL/TLS · Cookies · Directories · WAF · Ports · CVE · Chains · AI"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "──────────────────────────────────────────────────────\n"
            "EXAMPLES:\n"
            "  python AlanScan.py -u https://target.com --full-scan\n"
            "  python AlanScan.py -u https://target.com --quick-scan --xxe\n"
            "  python AlanScan.py -u https://target.com --injection-scan\n"
            "  python AlanScan.py -u https://target.com --owasp-scan\n"
            "  python AlanScan.py -ip 192.168.1.1 --network-scan\n"
            "  python AlanScan.py --list-profiles\n"
            "  python AlanScan.py --version\n"
            "  python AlanScan.py -u https://target.com --web-scan --credentials user:pass\n"
            "──────────────────────────────────────────────────────\n"
            "NOTE: AI analysis runs automatically.\n"
            "      Set ANTHROPIC_API_KEY once on your computer:\n"
            "      Windows : setx ANTHROPIC_API_KEY \"sk-ant-...\"\n"
            "      Linux   : export ANTHROPIC_API_KEY=\"sk-ant-...\"\n"
            "──────────────────────────────────────────────────────\n"
        )
    )

    # ── Utility ───────────────────────────────────────────────────────────
    util = p.add_argument_group("Utility")
    util.add_argument("--list-profiles", action="store_true",
                      help="Show all scan profiles and exit")
    util.add_argument("--version", action="store_true",
                      help="Show version information and exit")

    # ── Target ────────────────────────────────────────────────────────────
    tgt = p.add_argument_group("Target  (choose one)")
    tgt.add_argument("-u",  "--url", metavar="URL",
                     help="Target URL  (e.g. https://target.com)")
    tgt.add_argument("-ip", "--ip",  metavar="IP",
                     help="Target IP   (e.g. 192.168.1.1)")

    # ── Scan Profiles ─────────────────────────────────────────────────────
    prof = p.add_argument_group("Scan Profiles  (single flag — see --list-profiles)")
    prof.add_argument("--full-scan",      action="store_true",
                      help="All 15 modules (recommended)")
    prof.add_argument("--quick-scan",     action="store_true",
                      help="Fast: headers, SSL, cookies, WAF, dirs")
    prof.add_argument("--web-scan",       action="store_true",
                      help="All web modules — no ports")
    prof.add_argument("--stealth-scan",   action="store_true",
                      help="Low-noise: headers, SSL, cookies, WAF only")
    prof.add_argument("--injection-scan", action="store_true",
                      help="Injection focus: SQLi, XSS, CMDi, XXE, LFI, SSRF")
    prof.add_argument("--owasp-scan",     action="store_true",
                      help="OWASP Top 10:2021 — A01–A10 complete")
    prof.add_argument("--fast-scan",       action="store_true",
                      help="Fast external scan ~5-10 min (SQLi,XSS,LFI,headers,dirs)")
    prof.add_argument("--network-scan",   action="store_true",
                      help="Network only: ports, banners, CVE")

    # ── Individual Modules ────────────────────────────────────────────────
    mod = p.add_argument_group("Individual Modules  (additive on top of any profile)")
    mod.add_argument("--all",     action="store_true", help="Enable all modules")
    mod.add_argument("--sqli",    action="store_true", help="SQL Injection (error/blind/time)")
    mod.add_argument("--xss",     action="store_true", help="XSS + WAF bypass + DOM + SSTI")
    mod.add_argument("--csrf",    action="store_true", help="CSRF token + origin + weak token")
    mod.add_argument("--ssrf",    action="store_true", help="SSRF cloud metadata + internal")
    mod.add_argument("--cmdi",    action="store_true", help="OS Command Injection")
    mod.add_argument("--xxe",     action="store_true", help="XXE Injection (8 variants)")
    mod.add_argument("--lfi",     action="store_true", help="LFI / Path Traversal")
    mod.add_argument("--headers", action="store_true", help="Security Headers (10 headers)")
    mod.add_argument("--ssl",     action="store_true", help="SSL/TLS cert + protocol + cipher")
    mod.add_argument("--cookies", action="store_true", help="Cookie HttpOnly/Secure/SameSite")
    mod.add_argument("--dirs",    action="store_true", help="Directory & file discovery")
    mod.add_argument("--waf",     action="store_true", help="WAF detection & fingerprinting")
    mod.add_argument("--api",     action="store_true", help="API security testing (Swagger/GraphQL)")
    mod.add_argument("--idor",    action="store_true", help="IDOR heuristics (parameter differential)")
    mod.add_argument("--rate",    action="store_true", help="Rate limiting heuristics")
    mod.add_argument("--redirect",action="store_true", help="Open redirect vulnerability checks (NEW)")
    mod.add_argument("--method",  action="store_true", help="HTTP method tampering checks (NEW)")
    mod.add_argument("--hplus",   action="store_true", help="Enhanced security header analysis (NEW)")
    mod.add_argument("--ports",   action="store_true", help="Port scan (24 ports TCP connect)")
    mod.add_argument("--chain",   action="store_true", help="Vulnerability Chaining Engine")

    # ── Scan Options ──────────────────────────────────────────────────────
    opt = p.add_argument_group("Scan Options")
    opt.add_argument("-t",  "--threads", type=int, default=config.DEFAULT_THREADS,
                     metavar="N",   help=f"Worker threads (default: {config.DEFAULT_THREADS})")
    opt.add_argument("-d",  "--depth",   type=int, default=config.CRAWL_DEPTH,
                     metavar="N",   help=f"Crawler depth  (default: {config.CRAWL_DEPTH})")
    opt.add_argument("--timeout", type=int, default=config.TIMEOUT,
                     metavar="SEC", help=f"Timeout seconds (default: {config.TIMEOUT})")
    opt.add_argument(
        "--intensity",
        choices=["light", "medium", "aggressive"],
        default=getattr(config, "SCAN_INTENSITY_DEFAULT", "medium"),
        metavar="LEVEL",
        help="Scan intensity: light (safe, small payloads) | medium | aggressive (full payloads + SQLi time-blind)",
    )
    opt.add_argument(
        "--rate-limit",
        type=float,
        default=10.0,
        dest="rate_limit",
        metavar="RPS",
        help="HTTP throttle: max sustained requests/sec per host via token bucket (default: 10)",
    )
    opt.add_argument(
        "--delay",
        type=float,
        default=float(getattr(config, "REQUEST_THROTTLE_DELAY_SEC", 0.05)),
        metavar="SEC",
        help="Minimum pause (seconds) after each throttled request (default: config REQUEST_THROTTLE_DELAY_SEC)",
    )
    opt.add_argument(
        "--max-requests",
        type=int,
        default=5000,
        dest="max_requests",
        metavar="N",
        help="Circuit-breaker budget: max guarded HTTP units per scan (default: 5000)",
    )
    opt.add_argument("--proxy", metavar="URL",
                     help="HTTP proxy  (e.g. http://127.0.0.1:8080 for Burp Suite)")
    opt.add_argument("--output-dir", metavar="DIR", default="output",
                     help="Report output directory (default: output/)")
    opt.add_argument(
        "--bearer-token",
        metavar="TOKEN",
        help="Optional Bearer token (e.g. JWT) sent as Authorization on all HTTP requests",
    )
    opt.add_argument("--credentials", metavar="USER:PASS",
                     help="Credentials for authenticated scanning (e.g. admin:admin)")

    # ── Output ────────────────────────────────────────────────────────────
    out = p.add_argument_group("Output  —  HTML + PDF + JSON always auto-generated")
    out.add_argument("--report", default="html",
                     choices=["json", "txt", "html"],
                     help="Primary display format (default: html)")
    out.add_argument(
        "--compare-previous",
        metavar="JSON",
        dest="compare_previous",
        default="",
        help="Optional path to a prior AlanScan JSON report for delta (new/resolved/severity changes)",
    )

    # ── AI Analysis ───────────────────────────────────────────────────────
    ai = p.add_argument_group(
        "AI Analysis  — ON by default  (set ANTHROPIC_API_KEY on your computer)"
    )
    ai.add_argument("--ai",      action="store_true", default=True,
                    help="AI analysis is ON by default — no flag needed")
    ai.add_argument("--no-ai",   action="store_true", default=False,
                    help="Disable AI analysis")
    ai.add_argument("--api-key", metavar="KEY",
                    help="Anthropic API key (or set ANTHROPIC_API_KEY env var)")

    return p


def resolve_modules(args) -> tuple[dict, str]:
    """
    Resolve which modules to run. Returns (modules_dict, profile_label).
    Priority:
      1. Profile flag → base modules
      2. Individual flags → added on top (ADDITIVE)
      3. --all → everything ON
      4. Nothing → full-scan default
    """
    individual = [
        args.sqli, args.xss, args.csrf, args.ssrf, args.cmdi,
        args.xxe, args.lfi, args.headers, args.ssl, args.cookies,
        args.dirs, args.waf, args.api, args.idor, args.rate, args.ports, args.chain,
        getattr(args,'redirect',False), getattr(args,'method',False), getattr(args,'hplus',False),
    ]

    # Detect profile
    base_modules  = None
    profile_label = "FULL SCAN"

    for pname in PROFILES:
        flag_attr = pname.replace("-", "_")
        if getattr(args, flag_attr, False):
            profile_label = pname.upper().replace("-", " ")
            prof = PROFILES[pname]
            base_modules = dict(
                prof.get("modules") or PROFILES["full-scan"]["modules"]
            )
            break

    if base_modules is None:
        if args.all or not any(individual):
            base_modules  = dict(PROFILES["full-scan"]["modules"])
            profile_label = "ALL MODULES" if args.all else "FULL SCAN"
        else:
            base_modules  = {k: False for k in PROFILES["full-scan"]["modules"]}
            profile_label = "CUSTOM"

    # Additive step
    flag_map = {
        "sqli":args.sqli,"xss":args.xss,"csrf":args.csrf,
        "ssrf":args.ssrf,"cmdi":args.cmdi,"xxe":args.xxe,
        "lfi":args.lfi,"headers":args.headers,"ssl":args.ssl,
        "cookies":args.cookies,"dirs":args.dirs,"waf":args.waf,
        "api":args.api,"idor":args.idor,"rate":args.rate,
        "ports":args.ports,"chain":args.chain,
        "redirect":getattr(args,"redirect",False),"method":getattr(args,"method",False),"headers_plus":getattr(args,"hplus",False),
    }
    added = [m.upper() for m, flag in flag_map.items()
             if flag and not base_modules.get(m, False)]
    for m in added:
        base_modules[m.lower()] = True
    if added:
        profile_label += f" + {', '.join(added)}"

    if args.all:
        base_modules  = {k: True for k in base_modules}
        profile_label = "ALL MODULES"

    return base_modules, profile_label


def print_config(args, modules: dict, profile_label: str) -> None:
    target  = args.url or args.ip
    mode    = "Web Application" if args.url else "Network / Host"
    enabled = "  ".join(k.upper() for k,v in modules.items() if v)
    out_dir = getattr(args, "output_dir", "output")
    ai_on   = not getattr(args, "no_ai", False)

    print(f"{Fore.CYAN}  ┌{'─'*67}┐")
    print(f"  │{'  SCAN CONFIGURATION':^67}│")
    print(f"  ├{'─'*67}┤")
    print(f"  │  {Fore.WHITE}Profile  :{Fore.YELLOW} {profile_label:<55}{Fore.CYAN}  │")
    print(f"  │  {Fore.WHITE}Target   :{Fore.YELLOW} {target:<55}{Fore.CYAN}  │")
    print(f"  │  {Fore.WHITE}Mode     :{Fore.YELLOW} {mode:<55}{Fore.CYAN}  │")
    print(f"  │  {Fore.WHITE}Threads  :{Fore.YELLOW} {args.threads:<55}{Fore.CYAN}  │")
    print(f"  │  {Fore.WHITE}Intensity:{Fore.YELLOW} {str(getattr(args, 'intensity', 'medium')):<55}{Fore.CYAN}  │")
    print(f"  │  {Fore.WHITE}Rate lim :{Fore.YELLOW} {str(getattr(args, 'rate_limit', 10))+' rps':<55}{Fore.CYAN}  │")
    print(f"  │  {Fore.WHITE}Delay    :{Fore.YELLOW} {str(getattr(args, 'delay', 0.05))+'s':<55}{Fore.CYAN}  │")
    print(f"  │  {Fore.WHITE}Max req  :{Fore.YELLOW} {str(getattr(args, 'max_requests', 5000)):<55}{Fore.CYAN}  │")
    print(f"  │  {Fore.WHITE}Depth    :{Fore.YELLOW} {args.depth:<55}{Fore.CYAN}  │")
    print(f"  │  {Fore.WHITE}Timeout  :{Fore.YELLOW} {str(args.timeout)+'s':<55}{Fore.CYAN}  │")
    print(f"  │  {Fore.WHITE}Output   :{Fore.YELLOW} {out_dir:<55}{Fore.CYAN}  │")
    print(f"  │  {Fore.WHITE}AI Module:{Fore.GREEN} {'ENABLED (auto)' if ai_on else 'DISABLED (--no-ai)':<55}{Fore.CYAN}  │")
    if args.proxy:
        print(f"  │  {Fore.WHITE}Proxy    :{Fore.YELLOW} {args.proxy:<55}{Fore.CYAN}  │")
    if args.credentials:
        print(f"  │  {Fore.WHITE}Creds    :{Fore.YELLOW} {'provided (masked)':<55}{Fore.CYAN}  │")
    cmp_path = getattr(args, "compare_previous", "") or ""
    if cmp_path.strip():
        disp = cmp_path if len(cmp_path) <= 55 else ("…" + cmp_path[-53:])
        print(f"  │  {Fore.WHITE}Compare  :{Fore.YELLOW} {disp:<55}{Fore.CYAN}  │")
    print(f"  ├{'─'*67}┤")
    print(f"  │  {Fore.GREEN}Modules  : {enabled[:54]:<54}{Fore.CYAN}  │")
    if len(enabled) > 54:
        print(f"  │  {Fore.GREEN}           {enabled[54:108]:<54}{Fore.CYAN}  │")
    print(f"  │  {Fore.WHITE}Reports  :{Fore.YELLOW} HTML + PDF + JSON  →  {out_dir}/{'':<28}{Fore.CYAN}  │")
    print(f"  └{'─'*67}┘{Style.RESET_ALL}\n")


def print_summary(findings: list, elapsed: float,
                  profile_label: str, output_dir: str) -> None:
    """Print colored scan summary with severity bars."""
    m, s = int(elapsed // 60), elapsed % 60
    time_str = f"{m}m {s:.1f}s" if m else f"{s:.2f}s"
    total = len([f for f in findings if not f.get("chain")])
    chains = len([f for f in findings if f.get("chain")])
    
    # Count findings by severity
    crit = sum(1 for f in findings if f.get("severity") == "CRITICAL" and not f.get("chain"))
    high = sum(1 for f in findings if f.get("severity") == "HIGH" and not f.get("chain"))
    med = sum(1 for f in findings if f.get("severity") == "MEDIUM" and not f.get("chain"))
    low = sum(1 for f in findings if f.get("severity") == "LOW" and not f.get("chain"))
    info = sum(1 for f in findings if f.get("severity") == "INFO" and not f.get("chain"))

    # Industry Standard Professional Color Palette (Advanced)
    RED    = Fore.LIGHTRED_EX + Style.BRIGHT   # Critical - Vivid Crimson
    ORANGE = Fore.RED + Style.BRIGHT           # High - Burnt Orange
    AMBER  = Fore.YELLOW + Style.BRIGHT        # Medium - Golden Amber
    GREEN  = Fore.GREEN + Style.BRIGHT         # Low - Emerald Green
    BLUE   = Fore.BLUE + Style.BRIGHT          # Info - Royal Blue
    WHITE  = Fore.WHITE + Style.BRIGHT
    CYAN   = Fore.CYAN
    RESET  = Style.RESET_ALL

    # Function to create bar based on count (max bar length = 30)
    def make_bar(count, max_count=50):
        if max_count == 0:
            return ""
        bar_length = min(30, int(count * 30 / max(max_count, 1)))
        return "█" * bar_length

    # Find max count for scaling bars
    max_count = max(crit, high, med, low, info) if any([crit, high, med, low, info]) else 1

    # Header
    print(f"\n{CYAN}╔{'═'*60}╗")
    print(f"║  {GREEN}✓  SCAN COMPLETE{CYAN}{'':<46}║")
    print(f"╠{'═'*60}╣")
    print(f"║  {WHITE}Profile{CYAN}{'':<11}: {AMBER}{profile_label}{CYAN}{'':<{60-len(profile_label)-15}}║")
    print(f"║  {WHITE}Time{CYAN}{'':<13}: {AMBER}{time_str}{CYAN}{'':<{60-len(time_str)-15}}║")
    print(f"║  {WHITE}Total{CYAN}{'':<12}: {GREEN}{total}{CYAN}{'':<{60-len(str(total))-15}}║")
    print(f"╠{'─'*60}╣")

    # Severity bars with professional enterprise colors
    if crit > 0:
        bar = make_bar(crit, max_count)
        print(f"║  {RED}CRITICAL{CYAN}{'':<9} {RED}{crit:>4}{CYAN}  {RED}{bar}{CYAN}{'':<{60-18-len(bar)}}║")
    
    if high > 0:
        bar = make_bar(high, max_count)
        print(f"║  {ORANGE}HIGH{CYAN}{'':<13} {ORANGE}{high:>4}{CYAN}  {ORANGE}{bar}{CYAN}{'':<{60-18-len(bar)}}║")
    
    if med > 0:
        bar = make_bar(med, max_count)
        print(f"║  {AMBER}MEDIUM{CYAN}{'':<11} {AMBER}{med:>4}{CYAN}  {AMBER}{bar}{CYAN}{'':<{60-18-len(bar)}}║")
    
    if low > 0:
        bar = make_bar(low, max_count)
        print(f"║  {GREEN}LOW{CYAN}{'':<14} {GREEN}{low:>4}{CYAN}  {GREEN}{bar}{CYAN}{'':<{60-18-len(bar)}}║")
    
    if info > 0:
        bar = make_bar(info, max_count)
        print(f"║  {BLUE}INFO{CYAN}{'':<13} {BLUE}{info:>4}{CYAN}  {BLUE}{bar}{CYAN}{'':<{60-18-len(bar)}}║")

    # Attack Chains
    print(f"╠{'─'*60}╣")
    chain_color = RED if chains > 0 else GREEN
    print(f"║  {chain_color}Attack Chains{CYAN}{'':<6} {chain_color}{chains:>4}{CYAN}{'':<{60-18-len(str(chains))}}║")
    
    # Reports
    print(f"╠{'─'*60}╣")
    print(f"║  {WHITE}Reports saved{CYAN}{'':<6} {GREEN}{output_dir}/ (HTML+PDF+JSON){CYAN}{'':<{60-30-len(output_dir)}}║")
    print(f"╚{'═'*60}╝{RESET}\n")


def main():
    parser = build_parser()
    args   = parser.parse_args()

    # ── Utility ──────────────────────────────────────────────────────────
    if args.list_profiles:
        print_profiles()
        sys.exit(0)
    if args.version:
        print_version()
        sys.exit(0)

    safe_print_banner()

    # ── Validate target ───────────────────────────────────────────────────
    if not args.url and not args.ip:
        parser.print_help()
        print(Fore.RED + "\n[-] Error: Provide a target with  -u URL  or  -ip IP")
        sys.exit(1)
    if args.url and args.ip:
        print(Fore.RED + "[-] Error: Specify either -u OR -ip, not both")
        sys.exit(1)

    # ── Resolve modules ───────────────────────────────────────────────────
    modules, profile_label = resolve_modules(args)

    # ── AI enabled unless --no-ai ─────────────────────────────────────────
    ai_enabled = not getattr(args, "no_ai", False)

    # ── API key: use --api-key flag first, then env var ───────────────────
    api_key = getattr(args, "api_key", None) or os.environ.get("ANTHROPIC_API_KEY", "")
    if api_key:
        print(Fore.GREEN + f"[*] Anthropic API key found — AI analysis will run\n")
    else:
        print(Fore.YELLOW + "[!] No API key found — AI analysis will be skipped")
        print(Fore.YELLOW + "    Set key: setx ANTHROPIC_API_KEY \"sk-ant-...\" then restart terminal\n")

    # ── Output directory ──────────────────────────────────────────────────
    output_dir = getattr(args, "output_dir", "output")
    os.makedirs(output_dir, exist_ok=True)

    print_config(args, modules, profile_label)

    # ── Run scanner ───────────────────────────────────────────────────────
    controller = ScannerController(
        threads    = args.threads,
        timeout    = args.timeout,
        proxy      = args.proxy,
        report_format = args.report,
        ai_enabled = ai_enabled,
        api_key    = api_key,
        modules    = modules,
        output_dir = output_dir,
        credentials = args.credentials,
        bearer_token=args.bearer_token,
        throttle_rps    = getattr(args, "rate_limit", 10.0),
        request_delay_sec = getattr(args, "delay", None),
        max_requests    = getattr(args, "max_requests", 5000),
        scan_intensity  = getattr(args, "intensity", "medium"),
        compare_report_path=(getattr(args, "compare_previous", "") or "").strip() or None,
    )

    start = time.perf_counter()

    try:
        if args.url:
            print(Fore.YELLOW + f"[*] Starting {profile_label} → {args.url}\n")
            controller.scan_web(args.url, depth=args.depth)
        else:
            print(Fore.YELLOW + f"[*] Starting {profile_label} → {args.ip}\n")
            controller.scan_network(args.ip)

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n[!] Interrupted — saving partial report...")
        from reports.reporter import Reporter
        Reporter(args.url or args.ip, controller.findings,
                 "json", output_dir=output_dir).save()
        sys.exit(0)
    except Exception as exc:
        print(Fore.RED + f"\n[-] Unexpected error: {exc}")
        raise

    elapsed = time.perf_counter() - start
    print_summary(controller.findings, elapsed, profile_label, output_dir)


if __name__ == "__main__":
    main()