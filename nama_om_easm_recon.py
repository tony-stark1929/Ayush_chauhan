#!/usr/bin/env python3
"""
nama_om_easm_recon.py

Single-script orchestrator for the *.nama.om EASM Reconnaissance Guide.
Runs Phases 1-7 (passive discovery, network exposure, web layer, certs,
email security, DNS hygiene, and lightweight secrets exposure checks)
against a target domain and writes everything to a timestamped output
folder, plus a consolidated summary report.

Requires on PATH: dig, whois, nmap, openssl, curl (used via subprocess
where they're simpler/more reliable than reimplementing in pure Python).
Python deps: requests  (pip install requests)

Usage:
    python3 nama_om_easm_recon.py nama.om
    python3 nama_om_easm_recon.py nama.om --subs subdomains.txt
    python3 nama_om_easm_recon.py nama.om --skip nmap,secrets

Only run this against assets you are authorized to test.
"""

import argparse
import concurrent.futures
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import textwrap
from datetime import datetime

try:
    import requests
except ImportError:
    print("[!] Missing dependency: pip install requests")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TIMEOUT = 8
HEADERS = {"User-Agent": "nama-om-easm-recon/1.0"}


def run_cmd(cmd, timeout=60):
    """Run a shell command list, return (stdout, stderr, returncode)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout, p.stderr, p.returncode
    except FileNotFoundError:
        return "", f"[tool not found: {cmd[0]}]", 1
    except subprocess.TimeoutExpired:
        return "", "[timed out]", 1


def tool_available(name):
    return shutil.which(name) is not None


def safe_get(url, **kwargs):
    try:
        return requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False, **kwargs)
    except requests.RequestException as e:
        return None


def safe_options(url, headers=None):
    try:
        return requests.options(url, headers={**HEADERS, **(headers or {})}, timeout=TIMEOUT, verify=False)
    except requests.RequestException:
        return None


class Report:
    """Accumulates findings per section and writes them to files."""

    def __init__(self, outdir):
        self.outdir = outdir
        self.sections = {}

    def add(self, section, title, content):
        self.sections.setdefault(section, []).append((title, content))
        # also write a per-section raw file incrementally
        path = os.path.join(self.outdir, f"{section}.txt")
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"\n{'=' * 70}\n# {title}\n{'=' * 70}\n{content}\n")

    def write_summary(self, target):
        path = os.path.join(self.outdir, "SUMMARY.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# EASM Recon Summary — {target}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")
            for section, entries in self.sections.items():
                f.write(f"\n## {section}\n\n")
                for title, content in entries:
                    snippet = content.strip()
                    if len(snippet) > 800:
                        snippet = snippet[:800] + "\n...[truncated, see raw file]..."
                    f.write(f"### {title}\n```\n{snippet}\n```\n\n")
        print(f"[*] Summary written to {path}")


# ---------------------------------------------------------------------------
# Phase 1: Passive Asset Discovery
# ---------------------------------------------------------------------------

def phase1_passive_discovery(target, report):
    print("[*] Phase 1: Passive asset discovery")

    # 1.1 DNS basics
    for rtype in ["A", "AAAA", "NS", "MX", "TXT"]:
        out, err, _ = run_cmd(["dig", target, rtype, "+short"])
        report.add("phase1_dns", f"dig {target} {rtype}", out or err)

    # 1.1 Certificate Transparency (crt.sh)
    try:
        r = safe_get(f"https://crt.sh/?q=%25.{target}&output=json")
        subs = set()
        if r is not None and r.status_code == 200:
            try:
                data = r.json()
                for entry in data:
                    for name in entry.get("name_value", "").split("\n"):
                        subs.add(name.strip().lstrip("*."))
            except json.JSONDecodeError:
                pass
        subs_sorted = "\n".join(sorted(subs))
        report.add("phase1_dns", "crt.sh subdomains", subs_sorted or "[no results / crt.sh unreachable]")
        if subs:
            with open(os.path.join(report.outdir, "discovered_subdomains.txt"), "w") as f:
                f.write(subs_sorted + "\n")
    except Exception as e:
        report.add("phase1_dns", "crt.sh subdomains", f"[error: {e}]")

    # 1.1 Common subdomain brute force (small built-in wordlist)
    common_subs = ["api", "admin", "dev", "staging", "test", "mail", "smtp", "dns",
                   "ftp", "ssh", "rdp", "vpn", "backup", "cdn", "git", "jenkins",
                   "internal", "uat", "prod"]

    def check_sub(sub):
        fqdn = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(fqdn)
            return f"{fqdn} -> {ip}"
        except socket.gaierror:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        results = [r for r in ex.map(check_sub, common_subs) if r]
    report.add("phase1_dns", "Common subdomain brute force", "\n".join(results) or "[none resolved]")

    # 1.3 ASN / netblock
    out, err, _ = run_cmd(["whois", target])
    origin_lines = [l for l in out.splitlines() if "origin" in l.lower() or "netname" in l.lower()]
    report.add("phase1_asn", "whois origin/netname", "\n".join(origin_lines) or (out[:500] or err))

    # 1.5 Shadow IT: cloud bucket guesses
    base = target.split(".")[0]
    bucket_names = [base, f"{base}-backup", f"{base}-assets", f"{base}-cdn",
                    f"{base}-storage", f"{base}-archive", f"{base}-logs",
                    f"{base}-data", f"{base}-public"]
    bucket_results = []
    for b in bucket_names:
        # S3
        r = safe_get(f"https://{b}.s3.amazonaws.com/")
        if r is not None:
            bucket_results.append(f"S3 {b}: HTTP {r.status_code}")
        # GCS
        r = safe_get(f"https://storage.googleapis.com/{b}/")
        if r is not None:
            bucket_results.append(f"GCS {b}: HTTP {r.status_code}")
        # Azure
        r = safe_get(f"https://{b}storage.blob.core.windows.net/?restype=container&comp=list")
        if r is not None:
            bucket_results.append(f"Azure {b}storage: HTTP {r.status_code}")
    report.add("phase1_cloud", "Bucket existence probes (S3/GCS/Azure)", "\n".join(bucket_results) or "[no responses]")


# ---------------------------------------------------------------------------
# Phase 2: Network Exposure (delegates heavy lifting to nmap)
# ---------------------------------------------------------------------------

def phase2_network_exposure(target, report):
    print("[*] Phase 2: Network exposure scanning (nmap)")
    if not tool_available("nmap"):
        report.add("phase2_network", "nmap", "[nmap not found on PATH — skipping Phase 2]")
        return

    scans = {
        "top1000": ["nmap", "-sV", "-sC", target],
        "highrisk_services": ["nmap", "-p", "21,22,23,139,161,445,873,2049,3389,5900",
                               "-sV", target],
        "databases_caches": ["nmap", "-p", "27017,9200,6379,11211,3306,5432,1433,5984,5601",
                              "-sV", target],
        "containers_orchestration": ["nmap", "-p", "2375,2376,6443,10250,2379,2380,8080,8443,8081",
                                      "-sV", target],
        "edge_vpn_mgmt": ["nmap", "-p", "443,8443", "-sV",
                           "--script", "ssl-enum-ciphers,http-title", target],
        "mft": ["nmap", "-p", "443,8443,8001,9001,5080,5443", "-sV", target],
        "admin_ifaces": ["nmap", "-p", "80,443,554,623,3000,5900,8080,8443,9000", "-sV", target],
        "ics_scada": ["nmap", "-p", "102,502,2222,20000,44818", "-sV", target],
        "amplification": ["nmap", "-p", "53,123,389,1900", "-sU",
                           "--script", "dns-recursion,ntp-monlist", target],
    }

    for name, cmd in scans.items():
        print(f"    -> nmap: {name}")
        out, err, _ = run_cmd(cmd, timeout=300)
        report.add("phase2_network", f"nmap {name} ({' '.join(cmd)})", out or err)

    print("    -> nmap: full port + vuln scan (slow, run separately if you like:")
    print(f"       sudo nmap -p- -sV -sC -O -A --script vuln {target}")


# ---------------------------------------------------------------------------
# Phase 3: Web & Application Layer
# ---------------------------------------------------------------------------

def phase3_web_layer(target, report):
    print("[*] Phase 3: Web & application layer")
    base_url = f"https://{target}"

    r = safe_get(base_url)
    if r is None:
        report.add("phase3_web", "Base request", f"[could not connect to {base_url}]")
        return

    # 3.2/3.6 Headers
    hdr_dump = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    report.add("phase3_web", "Response headers", hdr_dump)

    security_headers = ["Content-Security-Policy", "Strict-Transport-Security",
                         "X-Frame-Options", "X-Content-Type-Options",
                         "Referrer-Policy", "Permissions-Policy"]
    missing = [h for h in security_headers if h not in r.headers]
    report.add("phase3_web", "Missing security headers", "\n".join(missing) or "[none missing]")

    # 3.7 Cookies
    cookie_notes = []
    for c in r.cookies:
        flags = []
        if not c.secure:
            flags.append("MISSING Secure")
        if not c.has_nonstandard_attr("HttpOnly") and "httponly" not in str(c._rest).lower():
            flags.append("MISSING HttpOnly (best-effort check)")
        cookie_notes.append(f"{c.name}: {', '.join(flags) if flags else 'looks OK (basic check)'}")
    report.add("phase3_web", "Cookie flags (basic check)", "\n".join(cookie_notes) or "[no cookies set]")

    # 3.1 / 3.10 CDN/WAF + tech fingerprint hints
    server_hdr = r.headers.get("Server", "")
    powered_by = r.headers.get("X-Powered-By", "")
    cdn_hints = [k for k in r.headers if k.lower().startswith("cf-") or k.lower() in ("x-cdn",)]
    report.add("phase3_web", "Tech / CDN hints",
               f"Server: {server_hdr}\nX-Powered-By: {powered_by}\nCDN-ish headers: {cdn_hints}")

    # 3.3 Sensitive paths
    sensitive_paths = [".git/config", ".env", ".svn/entries", ".DS_Store", "config.php",
                       "settings.json", "secrets.json", ".aws/credentials",
                       "backup.zip", "backup.tar.gz", "wp-admin/", "administrator/",
                       "admin/", "sites/default/files/"]
    path_results = []
    for p in sensitive_paths:
        pr = safe_get(f"{base_url}/{p}")
        if pr is not None:
            path_results.append(f"/{p}: HTTP {pr.status_code}")
    report.add("phase3_web", "Sensitive path probes", "\n".join(path_results) or "[no responses]")

    # 3.4 API discovery
    api_paths = ["swagger.json", "api/swagger.json", "v1/api-docs", "api/docs",
                 "openapi.json", "api/openapi.json", "graphql"]
    api_results = []
    for p in api_paths:
        pr = safe_get(f"{base_url}/{p}")
        if pr is not None:
            api_results.append(f"/{p}: HTTP {pr.status_code}")
    # GraphQL introspection attempt
    gr = safe_get(f"{base_url}/graphql", params={"query": "{__schema{types{name}}}"})
    if gr is not None:
        api_results.append(f"/graphql introspection: HTTP {gr.status_code}")
    report.add("phase3_web", "API endpoint probes", "\n".join(api_results) or "[no responses]")

    # 3.8 CORS
    cors_r = safe_options(f"{base_url}/api/endpoint",
                           headers={"Origin": "https://evil.example",
                                    "Access-Control-Request-Method": "GET"})
    if cors_r is not None:
        acao = cors_r.headers.get("Access-Control-Allow-Origin", "[not present]")
        report.add("phase3_web", "CORS check (OPTIONS /api/endpoint)", f"Access-Control-Allow-Origin: {acao}")

    # 3.11 Non-production environments
    nonprod = ["dev", "test", "staging", "uat", "internal", "api-dev", "api-test"]
    nonprod_results = []
    for sub in nonprod:
        pr = safe_get(f"https://{sub}.{target}")
        if pr is not None:
            nonprod_results.append(f"{sub}.{target}: HTTP {pr.status_code}")
    report.add("phase3_web", "Non-production subdomain probes", "\n".join(nonprod_results) or "[none reachable]")


# ---------------------------------------------------------------------------
# Phase 4: Certificates & Encryption
# ---------------------------------------------------------------------------

def phase4_certificates(target, report):
    print("[*] Phase 4: Certificates & encryption")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert(binary_form=False) or {}
                cipher = ssock.cipher()
        report.add("phase4_certs", "TLS handshake info", f"Cipher: {cipher}")
    except Exception as e:
        report.add("phase4_certs", "TLS handshake info", f"[error: {e}]")

    if tool_available("openssl"):
        out, err, _ = run_cmd(
            ["bash", "-c", f"echo | openssl s_client -connect {target}:443 -servername {target} 2>/dev/null "
                           f"| openssl x509 -noout -dates -subject -issuer"],
            timeout=20,
        )
        report.add("phase4_certs", "openssl cert dates/subject/issuer", out or err)
    else:
        report.add("phase4_certs", "openssl", "[openssl not found on PATH]")

    # Wildcard cert check via crt.sh (reuse Phase 1 results if present)
    try:
        r = safe_get(f"https://crt.sh/?q=%25.{target}&output=json")
        if r is not None and r.status_code == 200:
            data = r.json()
            wildcards = sorted({e["name_value"] for e in data if e.get("name_value", "").startswith("*.")})
            report.add("phase4_certs", "Wildcard certs (crt.sh)", "\n".join(wildcards) or "[none found]")
    except Exception as e:
        report.add("phase4_certs", "Wildcard certs (crt.sh)", f"[error: {e}]")


# ---------------------------------------------------------------------------
# Phase 5: Email Security Posture
# ---------------------------------------------------------------------------

def phase5_email_security(target, report):
    print("[*] Phase 5: Email security posture")

    out, err, _ = run_cmd(["dig", target, "TXT", "+short"])
    spf = [l for l in out.splitlines() if "spf1" in l.lower()]
    report.add("phase5_email", "SPF record", "\n".join(spf) or "[no SPF record found]")

    selectors = ["default", "selector1", "k1", "dkim", "google", "mail"]
    dkim_results = []
    for sel in selectors:
        out, _, _ = run_cmd(["dig", f"{sel}._domainkey.{target}", "TXT", "+short"])
        if out.strip():
            dkim_results.append(f"{sel}: {out.strip()}")
    report.add("phase5_email", "DKIM selectors found", "\n".join(dkim_results) or "[none of the common selectors resolved]")

    out, _, _ = run_cmd(["dig", f"_dmarc.{target}", "TXT", "+short"])
    report.add("phase5_email", "DMARC record", out or "[no DMARC record found]")

    for label, qname in [
        ("MTA-STS TXT", f"_mta-sts.{target}"),
        ("TLS-RPT", f"_tlsrpt.{target}"),
        ("DANE TLSA (443/tcp)", f"_443._tcp.{target}"),
        ("BIMI", f"default._bimi.{target}"),
    ]:
        out, _, _ = run_cmd(["dig", qname, "TXT" if "TLSA" not in label else "TLSA", "+short"])
        report.add("phase5_email", label, out or "[not found]")

    mta_sts_url = f"https://mta-sts.{target}/.well-known/mta-sts.txt"
    r = safe_get(mta_sts_url)
    if r is not None:
        report.add("phase5_email", "MTA-STS policy file", f"HTTP {r.status_code}\n{r.text[:500]}")

    out, _, _ = run_cmd(["dig", target, "MX", "+short"])
    report.add("phase5_email", "MX records", out or "[no MX records]")


# ---------------------------------------------------------------------------
# Phase 6: DNS Hygiene
# ---------------------------------------------------------------------------

def phase6_dns_hygiene(target, report):
    print("[*] Phase 6: DNS hygiene")

    out, _, _ = run_cmd(["dig", target, "NS", "+short"])
    nameservers = [l.strip().rstrip(".") for l in out.splitlines() if l.strip()]
    report.add("phase6_dns", "Nameservers", "\n".join(nameservers) or "[none found]")

    axfr_results = []
    for ns in nameservers:
        out, err, _ = run_cmd(["dig", "axfr", target, f"@{ns}"], timeout=20)
        flag = "POSSIBLE ZONE TRANSFER SUCCESS" if out and "Transfer failed" not in out and len(out.splitlines()) > 3 else "refused/failed (expected)"
        axfr_results.append(f"@{ns}: {flag}")
    report.add("phase6_dns", "AXFR zone transfer attempts", "\n".join(axfr_results) or "[no nameservers to test]")

    out, _, _ = run_cmd(["dig", target, "+dnssec"])
    report.add("phase6_dns", "DNSSEC check", out or "[no output]")

    out, _, _ = run_cmd(["dig", target, "CAA", "+short"])
    report.add("phase6_dns", "CAA records", out or "[no CAA records — any CA can issue certs for this domain]")

    out, err, _ = run_cmd(["whois", target])
    expiry_lines = [l for l in out.splitlines() if "expir" in l.lower() or "registrar" in l.lower() or "status" in l.lower()]
    report.add("phase6_dns", "WHOIS expiry / registrar / status", "\n".join(expiry_lines) or (out[:500] or err))


# ---------------------------------------------------------------------------
# Phase 7: Secrets & Data Exposure (lightweight, automatable parts only)
# ---------------------------------------------------------------------------

def phase7_secrets_exposure(target, report):
    print("[*] Phase 7: Secrets & data exposure (lightweight checks)")
    base_url = f"https://{target}"

    env_files = [".env", ".env.local", ".env.development", ".env.production", "docker.env"]
    results = []
    for f in env_files:
        r = safe_get(f"{base_url}/{f}")
        if r is not None:
            results.append(f"/{f}: HTTP {r.status_code}")
    report.add("phase7_secrets", "Exposed env file probes", "\n".join(results) or "[no responses]")

    report.add(
        "phase7_secrets",
        "Manual OSINT reminders (not automated here)",
        textwrap.dedent(f"""
            These need manual review / are ToS-restricted for automated scraping:
              - GitHub code search: https://github.com/search?q={target}
              - GitLab / Bitbucket search for "{target}"
              - Pastebin / Gist / raw.githubusercontent search for "{target}"
              - Docker Hub, npm, PyPI, Maven Central search for the org name
              - Atlassian (Jira/Confluence), Trello, Notion, SharePoint, Airtable
                for publicly exposed org workspaces
        """).strip(),
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

PHASES = {
    "passive": phase1_passive_discovery,
    "nmap": phase2_network_exposure,
    "web": phase3_web_layer,
    "certs": phase4_certificates,
    "email": phase5_email_security,
    "dns": phase6_dns_hygiene,
    "secrets": phase7_secrets_exposure,
}


def main():
    parser = argparse.ArgumentParser(description="All-in-one EASM recon for a target domain.")
    parser.add_argument("target", help="Target domain, e.g. nama.om")
    parser.add_argument("--skip", default="", help="Comma-separated phases to skip: "
                                                     "passive,nmap,web,certs,email,dns,secrets")
    parser.add_argument("--only", default="", help="Comma-separated phases to run exclusively")
    args = parser.parse_args()

    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    only = {s.strip() for s in args.only.split(",") if s.strip()}

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = f"easm_recon_{args.target}_{ts}"
    os.makedirs(outdir, exist_ok=True)
    report = Report(outdir)

    print(f"[*] Target: {args.target}")
    print(f"[*] Output directory: {outdir}\n")

    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        pass

    for name, func in PHASES.items():
        if only and name not in only:
            continue
        if name in skip:
            print(f"[*] Skipping phase: {name}")
            continue
        try:
            func(args.target, report)
        except Exception as e:
            report.add(f"phase_{name}_error", "Unhandled exception", str(e))
            print(f"[!] Phase {name} raised: {e}")
        print()

    report.write_summary(args.target)
    print(f"\n[*] Done. All output in: {outdir}/")
    print(f"[*] Start with {outdir}/SUMMARY.md for a quick read, raw per-phase .txt files have full output.")


if __name__ == "__main__":
    main()
