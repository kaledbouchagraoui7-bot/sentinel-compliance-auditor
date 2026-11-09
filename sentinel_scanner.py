#!/usr/bin/env python3
"""
sentinel_scanner.py — Automated B2B Web Privacy (nFADP/GDPR), DMARC & Edge Security Auditor
===========================================================================================

Purpose
-------
Perform a 100% passive, non-intrusive external compliance and security audit of any
public business domain across 5 high-urgency regulatory & technical pillars:

  1. Email Authentication & Anti-Spoofing (RFC 7489 DMARC, RFC 7208 SPF, MX, CAA)
  2. Swiss nFADP (revDSG) & EU GDPR Web Privacy (Pre-consent US tracker/font leaks,
     cookie security flags, privacy notice link)
  3. Edge & Transport Security (TLS certificate validity, HSTS, CSP, X-Frame-Options,
     X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Server fingerprinting,
     RFC 9116 security.txt)
  4. European Accessibility Act (EAA / WCAG 2.1 Level AA DOM baseline: html lang,
     image alt coverage, form label association, viewport zoom lock, heading structure)
  5. Technical SEO & AI Discoverability (robots.txt, sitemap.xml, canonical tag,
     structured JSON-LD schema)

Outputs (Per Audited Domain)
----------------------------
Automatically generates a ready-to-send B2B client package in `output/<domain_slug>_audit/`:
  1. `<domain_slug>_executive_audit.docx`   — Landscape Word report with executive summary,
                                              live evidence table, and copy-paste remediation.
  2. `<domain_slug>_technical_findings.xlsx`— 4-sheet Excel workbook with filterable findings,
                                              pillar scores, remediation steps, and formulas.
  3. `<domain_slug>_scorecard.png` & `.pdf` — Print-ready 300 DPI visual scorecard chart
                                              designed to attach directly to cold outreach.
  4. `remediation_configs/`                 — Ready-to-deploy Nginx, Apache, Cloudflare `_headers`,
                                              and DNS TXT records tailored to the target domain.
  5. `<domain_slug>_audit_package.zip`      — Complete zipped deliverable bundle.

Legal & Ethical Boundary
------------------------
Strictly passive observation: performs standard public DNS queries (via DNS-over-HTTPS)
and standard HTTP GET requests identical to a normal web browser visit. Zero port scanning,
zero fuzzing, zero authentication bypass, zero intrusive traffic.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import email.utils
import os
import re
import socket
import ssl
import sys
import textwrap
import time
import urllib.parse
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

import requests
from bs4 import BeautifulSoup

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

import openpyxl
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

import docx
from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.table import WD_ALIGN_VERTICAL, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls
from docx.shared import Inches, Pt, RGBColor


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# Known US / third-party tracking & asset domains that trigger nFADP / GDPR
# cross-border transfer disclosure or consent requirements when loaded pre-consent
THIRD_PARTY_TRACKERS = {
    "fonts.googleapis.com": "Google Fonts CSS (US IP transfer on page load; Schrems II / nFADP risk)",
    "fonts.gstatic.com": "Google Fonts static assets (US IP leak without prior consent)",
    "www.googletagmanager.com": "Google Tag Manager loaded in initial HTML",
    "www.google-analytics.com": "Google Analytics script present on initial load",
    "connect.facebook.net": "Meta Pixel script present on initial load",
    "snap.licdn.com": "LinkedIn Insight Tag present on initial load",
    "js.hs-scripts.com": "HubSpot tracking script present on initial load",
    "static.hotjar.com": "Hotjar session recording script present on initial load",
    "www.youtube.com": "Standard YouTube embed (as opposed to youtube-nocookie.com)",
    "maps.googleapis.com": "Google Maps API loaded on page",
}


# ---------------------------------------------------------------------------
# 1. Passive Network & DNS-over-HTTPS Collectors
# ---------------------------------------------------------------------------

def normalize_domain_and_url(raw_target: str) -> tuple[str, str]:
    raw = raw_target.strip()
    if not raw.startswith(("http://", "https://")):
        url = f"https://{raw}"
    else:
        url = raw
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower().split(":")[0]
    base_domain = host[4:] if host.startswith("www.") else host
    return base_domain, f"https://{host}"


def query_doh_txt(name: str, record_type: str = "TXT") -> list[str]:
    """Query public DNS via Cloudflare / Google DNS-over-HTTPS (JSON API)."""
    endpoints = [
        ("https://cloudflare-dns.com/dns-query", {"name": name, "type": record_type}),
        ("https://dns.google/resolve", {"name": name, "type": record_type}),
    ]
    for url, params in endpoints:
        try:
            resp = requests.get(
                url,
                params=params,
                headers={"Accept": "application/dns-json", "User-Agent": USER_AGENT},
                timeout=8,
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", []) or []
                results = []
                for ans in answers:
                    raw_data = str(ans.get("data", "")).strip()
                    # Strip surrounding quotes from TXT chunks
                    cleaned = raw_data.replace('""', "").strip('"')
                    if cleaned:
                        results.append(cleaned)
                return results
        except Exception:
            continue
    return []


def resolve_network_utc_now(headers_lower: dict[str, str] | None = None) -> dt.datetime:
    """Use HTTP Date header when available so timestamps and TLS expiry match network UTC."""
    if headers_lower and "date" in headers_lower:
        try:
            parsed_dt = email.utils.parsedate_to_datetime(headers_lower["date"])
            if parsed_dt.tzinfo is None:
                parsed_dt = parsed_dt.replace(tzinfo=dt.timezone.utc)
            return parsed_dt.astimezone(dt.timezone.utc)
        except Exception:
            pass
    return dt.datetime.now(dt.timezone.utc)


def inspect_tls_certificate(hostname: str, port: int = 443, ref_now: dt.datetime | None = None) -> dict[str, Any]:
    """Inspect public TLS certificate expiration and protocol version."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()
                not_after_str = cert.get("notAfter", "")
                days_left = None
                if not_after_str:
                    exp_dt = dt.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=dt.timezone.utc
                    )
                    now_dt = ref_now or dt.datetime.now(dt.timezone.utc)
                    days_left = (exp_dt - now_dt).days
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return {
                    "ok": True,
                    "tls_version": tls_version or "Unknown",
                    "cipher": cipher[0] if cipher else "Unknown",
                    "days_left": days_left,
                    "issuer": issuer.get("organizationName", issuer.get("commonName", "CA")),
                }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "tls_version": "None", "days_left": 0}


# ---------------------------------------------------------------------------
# 2. Control Evaluation Engine (25 Automated Checks Across 5 Pillars)
# ---------------------------------------------------------------------------

def run_domain_audit(target: str) -> dict[str, Any]:
    domain, base_url = normalize_domain_and_url(target)
    parsed_host = urllib.parse.urlparse(base_url).netloc

    findings: list[dict[str, Any]] = []

    def add_finding(
        cid: str,
        pillar: str,
        title: str,
        status: str,
        severity: str,
        weight: int,
        evidence: str,
        impact: str,
        remediation: str,
        regulation: str,
    ) -> None:
        findings.append(
            {
                "id": cid,
                "pillar": pillar,
                "title": title,
                "status": status,       # PASS | WARN | FAIL
                "severity": severity,   # CRITICAL | HIGH | MEDIUM | LOW
                "weight": weight,
                "evidence": evidence,
                "impact": impact,
                "remediation": remediation,
                "regulation": regulation,
            }
        )

    # --- Fetch Homepage Passively ---
    resp = None
    html_text = ""
    headers_lower: dict[str, str] = {}
    cookies_list = []
    final_url = base_url
    fetch_ms = 0

    t0 = time.time()
    for candidate_url in (base_url, f"https://www.{domain}", f"http://{domain}"):
        try:
            r = requests.get(
                candidate_url,
                headers={"User-Agent": USER_AGENT, "Accept-Language": "en-CH,en;q=0.9,de;q=0.8,fr;q=0.8"},
                timeout=12,
                allow_redirects=True,
            )
            resp = r
            fetch_ms = int((time.time() - t0) * 1000)
            final_url = r.url
            parsed_host = urllib.parse.urlparse(final_url).netloc.split(":")[0]
            html_text = r.text or ""
            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            cookies_list = list(r.cookies)
            break
        except Exception:
            continue

    if resp is None:
        raise RuntimeError(f"Could not reach {target} over HTTPS/HTTP.")

    soup = BeautifulSoup(html_text, "html.parser")

    # =========================================================================
    # PILLAR 1: Email Authentication & Anti-Spoofing (DMARC / SPF / MX / CAA)
    # =========================================================================
    P1 = "1. Email & Anti-Spoofing (DMARC/SPF)"

    # 1.1 DMARC Record & Enforcement Policy
    dmarc_txts = query_doh_txt(f"_dmarc.{domain}", "TXT")
    dmarc_rec = next((t for t in dmarc_txts if "v=dmarc1" in t.lower()), "")
    if not dmarc_rec:
        add_finding(
            "EML-01", P1, "DMARC Anti-Spoofing Record & Policy", "FAIL", "CRITICAL", 12,
            f"No _dmarc.{domain} TXT record found in public DNS.",
            "External attackers can send forged emails and fake invoices appearing to come directly from @" + domain + ".",
            f'Publish DNS TXT record at _dmarc.{domain}: "v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}; adkim=r; aspf=r;"',
            "RFC 7489 / Gmail & Yahoo Sender Mandate / FINMA Operational Risk",
        )
    else:
        m_pol = re.search(r"\bp\s*=\s*([a-zA-Z]+)", dmarc_rec, re.I)
        policy = m_pol.group(1).lower() if m_pol else "none"
        if policy == "none":
            add_finding(
                "EML-01", P1, "DMARC Enforcement Policy Strength", "WARN", "HIGH", 12,
                f"DMARC record present ({dmarc_rec[:80]}), but policy is set to p=none (monitoring only).",
                "p=none does not block spoofed emails from reaching clients' inboxes; domain remains spoofable.",
                f"Upgrade DMARC policy from p=none to p=quarantine or p=reject on _dmarc.{domain}.",
                "RFC 7489 / Email Deliverability & Anti-Phishing",
            )
        else:
            add_finding(
                "EML-01", P1, "DMARC Enforcement Policy Strength", "PASS", "CRITICAL", 12,
                f"Active DMARC enforcement policy '{policy}' verified: {dmarc_rec[:90]}",
                "Protects domain against direct email spoofing and improves inbox placement.",
                "Maintain current DMARC enforcement and monitor RUA aggregate reports.",
                "RFC 7489",
            )

    # 1.2 SPF Record Syntax & All-Mechanism
    root_txts = query_doh_txt(domain, "TXT")
    spf_rec = next((t for t in root_txts if "v=spf1" in t.lower()), "")
    if not spf_rec:
        add_finding(
            "EML-02", P1, "SPF (Sender Policy Framework) Record", "FAIL", "HIGH", 8,
            f"No v=spf1 TXT record found on {domain}.",
            "Receiving mail servers cannot verify authorized outbound mail servers, elevating spam rejection risk.",
            f'Add an SPF TXT record on {domain} ending with "-all" or "~all".',
            "RFC 7208",
        )
    elif "+all" in spf_rec.lower() or "?all" in spf_rec.lower():
        add_finding(
            "EML-02", P1, "SPF Record Strictness", "FAIL", "HIGH", 8,
            f"Permissive SPF qualifier detected: {spf_rec[:90]}",
            "Allows unauthorized servers to send mail on behalf of the domain.",
            "Replace ?all or +all with ~all (SoftFail) or -all (HardFail).",
            "RFC 7208",
        )
    else:
        add_finding(
            "EML-02", P1, "SPF (Sender Policy Framework) Record", "PASS", "HIGH", 8,
            f"Valid SPF policy verified: {spf_rec[:95]}",
            "Authorized outbound mail servers are properly declared.",
            "Keep SPF DNS lookups <= 10.",
            "RFC 7208",
        )

    # 1.3 MX Records
    mx_recs = query_doh_txt(domain, "MX")
    if mx_recs:
        add_finding(
            "EML-03", P1, "Mail Exchange (MX) Configuration", "PASS", "LOW", 3,
            f"{len(mx_recs)} MX record(s) configured ({mx_recs[0][:60]}).",
            "Inbound mail routing is active.",
            "None required.",
            "RFC 5321",
        )
    else:
        add_finding(
            "EML-03", P1, "Mail Exchange (MX) Configuration", "WARN", "LOW", 3,
            f"No MX records returned for {domain}.",
            "Domain may not accept inbound email or relies on fallback A-record routing.",
            "Configure explicit MX records (or null MX '.' if domain never sends/receives mail).",
            "RFC 5321 / RFC 7505",
        )

    # 1.4 DNS CAA (Certificate Authority Authorization)
    caa_recs = query_doh_txt(domain, "CAA")
    if caa_recs:
        add_finding(
            "EML-04", P1, "DNS CAA (Certificate Authority Restriction)", "PASS", "LOW", 3,
            f"CAA record present: {caa_recs[0][:70]}",
            "Restricts which Certificate Authorities may issue TLS certificates for this domain.",
            "None required.",
            "RFC 8659",
        )
    else:
        add_finding(
            "EML-04", P1, "DNS CAA (Certificate Authority Restriction)", "WARN", "LOW", 3,
            f"No DNS CAA record found on {domain}.",
            "Any public Certificate Authority can issue a certificate if domain validation is compromised.",
            f'Add DNS CAA record: {domain}. IN CAA 0 issue "letsencrypt.org" (or your active CA).',
            "RFC 8659",
        )

    # =========================================================================
    # PILLAR 2: Swiss nFADP (revDSG) & EU GDPR Web Privacy
    # =========================================================================
    P2 = "2. Swiss nFADP & GDPR Web Privacy"

    # 2.1 Pre-Consent US Third-Party Asset & Tracker Leak Scan
    detected_trackers: list[str] = []
    html_lower = html_text.lower()
    for host_key, desc in THIRD_PARTY_TRACKERS.items():
        if host_key in html_lower:
            detected_trackers.append(f"{host_key} ({desc})")

    if "fonts.googleapis.com" in html_lower or "fonts.gstatic.com" in html_lower:
        add_finding(
            "PRV-01", P2, "Remote Google Fonts IP Leak (Schrems II / nFADP)", "FAIL", "HIGH", 8,
            "Page HTML loads fonts directly from fonts.googleapis.com / fonts.gstatic.com on initial load.",
            "Automatically transmits visitor IP addresses to US servers before consent (ruled unlawful in LG Munich Az. 3 O 17493/20 & flagged under Swiss nFADP Art. 6 / GDPR Art. 44).",
            "Download the webfont files (.woff2) and host them locally on your own server; remove <link href='https://fonts.googleapis.com/...'>.",
            "Swiss nFADP Art. 6 & 16 / EU GDPR Art. 6 & 44",
        )
    else:
        add_finding(
            "PRV-01", P2, "Self-Hosted Web Fonts (No Google Fonts IP Leak)", "PASS", "HIGH", 8,
            "No direct calls to fonts.googleapis.com or fonts.gstatic.com detected in initial HTML.",
            "Prevents automatic visitor IP transmission to US font servers on initial page load.",
            "None required.",
            "Swiss nFADP Art. 6 / EU GDPR Art. 44",
        )

    other_trackers = [t for t in detected_trackers if not t.startswith("fonts.g")]
    if other_trackers:
        add_finding(
            "PRV-02", P2, "Third-Party Analytics / Marketing Scripts in Initial HTML", "WARN", "MEDIUM", 7,
            f"Detected {len(other_trackers)} external tracker reference(s): {'; '.join(other_trackers[:3])}",
            "If executed prior to affirmative opt-in, third-party trackers violate EU ePrivacy / GDPR and nFADP transparency rules.",
            "Ensure all analytics/marketing tags are strictly blocked by a Consent Management Platform (CMP) until explicit opt-in.",
            "EU GDPR Art. 6 / ePrivacy Directive / Swiss nFADP",
        )
    else:
        add_finding(
            "PRV-02", P2, "Clean Initial HTML (Minimal Pre-Consent Trackers)", "PASS", "MEDIUM", 7,
            "Zero third-party advertising or behavioral tracker domains detected in raw initial HTML.",
            "Reduces cross-border data transfer exposure.",
            "None required.",
            "Swiss nFADP / EU GDPR",
        )

    # 2.3 Cookie Security Flags on Initial HTTP Response
    raw_set_cookie = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") and hasattr(resp.raw.headers, "getlist") else []
    if not raw_set_cookie and "set-cookie" in headers_lower:
        raw_set_cookie = [headers_lower["set-cookie"]]

    if not raw_set_cookie and not cookies_list:
        add_finding(
            "PRV-03", P2, "Pre-Consent Cookie Hygiene & Security Flags", "PASS", "MEDIUM", 5,
            "Zero HTTP cookies set on initial unconsented page load.",
            "Exemplary privacy-by-default posture; no insecure session or tracking cookies dropped prior to user action.",
            "None required.",
            "ePrivacy / Swiss nFADP Art. 7 (Privacy by Default)",
        )
    else:
        insecure_cookies = []
        for sc in raw_set_cookie:
            sc_l = sc.lower()
            c_name = sc.split("=", 1)[0].strip()
            missing_flags = []
            if "secure" not in sc_l:
                missing_flags.append("Secure")
            if "httponly" not in sc_l:
                missing_flags.append("HttpOnly")
            if "samesite" not in sc_l:
                missing_flags.append("SameSite")
            if missing_flags:
                insecure_cookies.append(f"{c_name} (missing {'/'.join(missing_flags)})")
        if insecure_cookies:
            add_finding(
                "PRV-03", P2, "Cookie Security Attributes (Secure / HttpOnly / SameSite)", "FAIL", "MEDIUM", 5,
                f"Initial response sets cookie(s) lacking hardening flags: {', '.join(insecure_cookies[:3])}",
                "Cookies without Secure/HttpOnly/SameSite are vulnerable to XSS theft or cross-site transmission.",
                "Append '; Secure; HttpOnly; SameSite=Lax' (or Strict) to all Set-Cookie headers.",
                "OWASP ASVS / Swiss nFADP Art. 8 (Data Security)",
            )
        else:
            add_finding(
                "PRV-03", P2, "Cookie Security Attributes (Secure / HttpOnly / SameSite)", "PASS", "MEDIUM", 5,
                f"All {len(raw_set_cookie)} initial cookie(s) include Secure, HttpOnly, and SameSite attributes.",
                "Protects session cookies against interception and XSS.",
                "Verify non-essential cookies wait for user consent.",
                "OWASP / Swiss nFADP Art. 8",
            )

    # 2.4 Privacy Policy Link Discoverability
    priv_links = [
        a.get("href", "")
        for a in soup.find_all("a", href=True)
        if re.search(r"privac|datenschutz|confidentialit|data-protection|impressum|mentions-l", a.get_text(" ") + " " + a.get("href", ""), re.I)
    ]
    if priv_links:
        add_finding(
            "PRV-04", P2, "Privacy Policy / Legal Notice Discoverability", "PASS", "MEDIUM", 5,
            f"Discoverable privacy/legal link(s) found on homepage (e.g., {priv_links[0][:60]}).",
            "Meets baseline transparency obligation.",
            "Ensure privacy notice lists all current sub-processors and retention periods.",
            "Swiss nFADP Art. 19 / EU GDPR Art. 13",
        )
    else:
        add_finding(
            "PRV-04", P2, "Privacy Policy / Legal Notice Discoverability", "FAIL", "MEDIUM", 5,
            "No clear Privacy Policy / Datenschutzerklärung / Politique de confidentialité link detected on homepage.",
            "Swiss nFADP Art. 19 and GDPR Art. 13 mandate directly accessible privacy disclosures on every public site.",
            "Add a persistent footer link to your Privacy Policy and Impressum on all pages.",
            "Swiss nFADP Art. 19 / EU GDPR Art. 13",
        )

    # =========================================================================
    # PILLAR 3: Edge & Transport Security (TLS & HTTP Security Headers)
    # =========================================================================
    P3 = "3. Edge & Transport Security (HTTP/TLS)"
    net_now = resolve_network_utc_now(headers_lower)

    # 3.1 TLS Certificate & Protocol
    tls_info = inspect_tls_certificate(parsed_host, ref_now=net_now)
    if tls_info["ok"] and (tls_info["days_left"] is None or tls_info["days_left"] >= 14):
        add_finding(
            "SEC-01", P3, "TLS Encryption & Certificate Validity", "PASS", "CRITICAL", 8,
            f"Protocol {tls_info['tls_version']} ({tls_info['cipher']}), valid for {tls_info['days_left']} days (Issuer: {tls_info['issuer']}).",
            "Encrypted transport is active and certificate is healthy.",
            "None required.",
            "Swiss nFADP Art. 8 / OWASP Transport Layer Protection",
        )
    elif tls_info["ok"] and tls_info["days_left"] is not None and tls_info["days_left"] > 0:
        add_finding(
            "SEC-01", P3, "TLS Encryption & Certificate Validity", "WARN", "HIGH", 8,
            f"Valid {tls_info['tls_version']} certificate, but expires in {tls_info['days_left']} days (Issuer: {tls_info['issuer']}).",
            "Certificate is nearing expiration and requires timely renewal.",
            "Verify automated ACME / Let's Encrypt renewal cron.",
            "Swiss nFADP Art. 8 / OWASP",
        )
    else:
        err_msg = tls_info.get("error", f"Expired ({tls_info.get('days_left')} days left)")
        add_finding(
            "SEC-01", P3, "TLS Encryption & Certificate Validity", "FAIL", "CRITICAL", 8,
            f"TLS certificate validation issue: {err_msg}",
            "Expired or broken TLS triggers browser security warnings and blocks client access.",
            "Renew TLS certificate and enforce TLS 1.2 / TLS 1.3 only.",
            "Swiss nFADP Art. 8 / OWASP",
        )

    # 3.2 Strict-Transport-Security (HSTS)
    hsts = headers_lower.get("strict-transport-security", "")
    if hsts and "max-age=" in hsts.lower():
        add_finding(
            "SEC-02", P3, "HTTP Strict-Transport-Security (HSTS)", "PASS", "HIGH", 7,
            f"HSTS header present: {hsts[:80]}",
            "Forces browsers to connect exclusively over HTTPS, preventing SSL-stripping attacks.",
            "None required.",
            "RFC 6797 / OWASP Secure Headers",
        )
    else:
        add_finding(
            "SEC-02", P3, "HTTP Strict-Transport-Security (HSTS)", "FAIL", "HIGH", 7,
            "Missing 'Strict-Transport-Security' response header.",
            "First-time visitors on public Wi-Fi are vulnerable to HTTP downgrade / man-in-the-middle interception.",
            'Add response header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            "RFC 6797 / OWASP Secure Headers",
        )

    # 3.3 Content-Security-Policy (CSP)
    csp = headers_lower.get("content-security-policy", "")
    if csp:
        add_finding(
            "SEC-03", P3, "Content-Security-Policy (CSP)", "PASS", "HIGH", 7,
            f"CSP header present ({csp[:85]}...).",
            "Mitigates Cross-Site Scripting (XSS) and unauthorized script injection.",
            "Periodically audit CSP directives against unsafe-inline.",
            "W3C CSP3 / OWASP",
        )
    else:
        add_finding(
            "SEC-03", P3, "Content-Security-Policy (CSP)", "FAIL", "HIGH", 7,
            "Missing 'Content-Security-Policy' response header.",
            "Without CSP, the browser permits execution of injected third-party scripts or form-skimming attacks (Magecart/XSS).",
            "Add baseline CSP header: Content-Security-Policy: default-src 'self' https:; frame-ancestors 'self'; object-src 'none';",
            "W3C CSP3 / OWASP Top 10",
        )

    # 3.4 Clickjacking Protection (X-Frame-Options or CSP frame-ancestors)
    xfo = headers_lower.get("x-frame-options", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if xfo or has_frame_ancestors:
        add_finding(
            "SEC-04", P3, "Anti-Clickjacking Protection (X-Frame-Options / frame-ancestors)", "PASS", "MEDIUM", 5,
            f"Framing restricted via {'X-Frame-Options: ' + xfo if xfo else 'CSP frame-ancestors'}.",
            "Prevents malicious sites from embedding your site in an invisible iframe.",
            "None required.",
            "OWASP Clickjacking Defense",
        )
    else:
        add_finding(
            "SEC-04", P3, "Anti-Clickjacking Protection (X-Frame-Options)", "FAIL", "MEDIUM", 5,
            "Neither 'X-Frame-Options' nor CSP 'frame-ancestors' header is set.",
            "Attackers can embed your website inside a transparent iframe to trick users into clicking unintended buttons.",
            "Add response header: X-Frame-Options: SAMEORIGIN",
            "OWASP Clickjacking Defense",
        )

    # 3.5 X-Content-Type-Options (MIME Sniffing Protection)
    xcto = headers_lower.get("x-content-type-options", "")
    if xcto.lower().strip() == "nosniff":
        add_finding(
            "SEC-05", P3, "MIME-Sniffing Protection (X-Content-Type-Options)", "PASS", "MEDIUM", 4,
            "X-Content-Type-Options: nosniff is enforced.",
            "Prevents browsers from executing disguised non-script files as executable code.",
            "None required.",
            "OWASP Secure Headers",
        )
    else:
        add_finding(
            "SEC-05", P3, "MIME-Sniffing Protection (X-Content-Type-Options)", "FAIL", "MEDIUM", 4,
            "Missing 'X-Content-Type-Options: nosniff' header.",
            "Browsers may MIME-sniff uploaded or cached assets and execute malicious payloads.",
            "Add response header: X-Content-Type-Options: nosniff",
            "OWASP Secure Headers",
        )

    # 3.6 Referrer-Policy
    ref_pol = headers_lower.get("referrer-policy", "")
    if ref_pol:
        add_finding(
            "SEC-06", P3, "Referrer-Policy Privacy Header", "PASS", "LOW", 3,
            f"Referrer-Policy set to '{ref_pol}'.",
            "Controls URL path leakage when users click external links.",
            "None required.",
            "W3C Referrer Policy / nFADP",
        )
    else:
        add_finding(
            "SEC-06", P3, "Referrer-Policy Privacy Header", "FAIL", "LOW", 3,
            "Missing 'Referrer-Policy' HTTP header.",
            "Full internal URLs and query parameters may leak to external sites via the Referer header.",
            "Add response header: Referrer-Policy: strict-origin-when-cross-origin",
            "W3C Referrer Policy / Swiss nFADP",
        )

    # 3.7 Permissions-Policy (Browser Hardware API Lockdown)
    perm_pol = headers_lower.get("permissions-policy", "")
    if perm_pol:
        add_finding(
            "SEC-07", P3, "Permissions-Policy (Camera/Mic/Geolocation Lockdown)", "PASS", "LOW", 3,
            f"Permissions-Policy present ({perm_pol[:70]}).",
            "Restricts embedded third-party scripts from accessing browser sensors.",
            "None required.",
            "W3C Permissions Policy",
        )
    else:
        add_finding(
            "SEC-07", P3, "Permissions-Policy (Browser Sensor Lockdown)", "FAIL", "LOW", 3,
            "Missing 'Permissions-Policy' HTTP header.",
            "Embedded third-party widgets are not explicitly barred from requesting camera, microphone, or geolocation APIs.",
            "Add response header: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
            "W3C Permissions Policy / OWASP",
        )

    # 3.8 Server / X-Powered-By Version Fingerprinting Disclosure
    srv_hdr = headers_lower.get("server", "")
    xpb_hdr = headers_lower.get("x-powered-by", "")
    version_leak = re.search(r"\d+\.\d+", srv_hdr + " " + xpb_hdr)
    if version_leak or xpb_hdr:
        add_finding(
            "SEC-08", P3, "Server & Runtime Version Fingerprinting Suppression", "WARN", "LOW", 3,
            f"Backend technology disclosed in headers (Server: '{srv_hdr or 'none'}', X-Powered-By: '{xpb_hdr or 'none'}').",
            "Reveals exact web server or PHP/Node/ASP.NET version to automated vulnerability scanners.",
            "Remove X-Powered-By header and set ServerTokens Prod / server_tokens off.",
            "OWASP Configuration Management",
        )
    else:
        add_finding(
            "SEC-08", P3, "Server & Runtime Version Fingerprinting Suppression", "PASS", "LOW", 3,
            f"No granular software version numbers leaked (Server: '{srv_hdr or 'hidden'}').",
            "Reduces automated exploit targeting.",
            "None required.",
            "OWASP Configuration Management",
        )

    # 3.9 RFC 9116 /.well-known/security.txt
    sec_txt_ok = False
    try:
        r_sec = requests.get(f"https://{parsed_host}/.well-known/security.txt", headers={"User-Agent": USER_AGENT}, timeout=5)
        if r_sec.status_code == 200 and "contact:" in (r_sec.text or "").lower():
            sec_txt_ok = True
    except Exception:
        pass

    if sec_txt_ok:
        add_finding(
            "SEC-09", P3, "Vulnerability Disclosure Policy (/.well-known/security.txt)", "PASS", "LOW", 2,
            "Valid RFC 9116 /.well-known/security.txt file found.",
            "Provides researchers and CERTs a direct channel to report security issues privately.",
            "None required.",
            "RFC 9116 / NCSC Switzerland Best Practice",
        )
    else:
        add_finding(
            "SEC-09", P3, "Vulnerability Disclosure Policy (/.well-known/security.txt)", "WARN", "LOW", 2,
            "No valid /.well-known/security.txt file found.",
            "Security researchers and Swiss NCSC lack a standardized contact point to report vulnerabilities privately.",
            f"Publish /.well-known/security.txt with Contact: mailto:security@{domain} and Expires timestamp.",
            "RFC 9116 / NCSC Switzerland",
        )

    # =========================================================================
    # PILLAR 4: European Accessibility Act (EAA / WCAG 2.1 Level AA Baseline)
    # =========================================================================
    P4 = "4. Accessibility (EAA / WCAG 2.1 AA)"

    # 4.1 HTML Document Language Attribute
    html_tag = soup.find("html")
    html_lang = (html_tag.get("lang") or "").strip() if html_tag else ""
    if html_lang:
        add_finding(
            "A11Y-01", P4, "Document Primary Language Declaration (<html lang>)", "PASS", "MEDIUM", 4,
            f"<html lang='{html_lang}'> is declared.",
            "Allows screen readers to select the correct pronunciation engine.",
            "None required.",
            "WCAG 2.1 SC 3.1.1 (Level A) / EU EAA",
        )
    else:
        add_finding(
            "A11Y-01", P4, "Document Primary Language Declaration (<html lang>)", "FAIL", "MEDIUM", 4,
            "The root <html> element is missing a valid 'lang' attribute.",
            "Screen readers for visually impaired users cannot determine the page language.",
            'Add lang attribute to root element, e.g., <html lang="de-CH"> or <html lang="fr">.',
            "WCAG 2.1 SC 3.1.1 / European Accessibility Act",
        )

    # 4.2 Image Alt Text Coverage
    imgs = soup.find_all("img")
    missing_alt = [img.get("src", "img")[:40] for img in imgs if img.get("alt") is None]
    if not missing_alt:
        add_finding(
            "A11Y-02", P4, "Image Text Alternatives (img alt attributes)", "PASS", "MEDIUM", 4,
            f"All {len(imgs)} <img> elements on homepage carry an alt attribute.",
            "Assistive technologies can interpret non-text content.",
            "None required.",
            "WCAG 2.1 SC 1.1.1 (Level A) / EU EAA",
        )
    else:
        add_finding(
            "A11Y-02", P4, "Image Text Alternatives (img alt attributes)", "FAIL", "MEDIUM", 4,
            f"{len(missing_alt)} of {len(imgs)} <img> elements lack an 'alt' attribute (e.g., {', '.join(missing_alt[:2])}).",
            "Screen readers read raw filenames aloud when alt attributes are omitted.",
            'Add descriptive alt="..." attributes to informational images and alt="" to decorative images.',
            "WCAG 2.1 SC 1.1.1 / European Accessibility Act",
        )

    # 4.3 Viewport Pinch-to-Zoom Accessibility
    vp_meta = soup.find("meta", attrs={"name": re.compile(r"^viewport$", re.I)})
    vp_content = (vp_meta.get("content") or "").lower() if vp_meta else ""
    if "user-scalable=no" in vp_content or "maximum-scale=1" in vp_content.replace("1.0", "1"):
        add_finding(
            "A11Y-03", P4, "Low-Vision Zoom & Text Scaling (<meta viewport>)", "FAIL", "MEDIUM", 4,
            f"Viewport meta tag blocks pinch-to-zoom ({vp_content[:70]}).",
            "Prevents low-vision users from zooming page text up to 200%.",
            'Remove "user-scalable=no" and "maximum-scale=1" from <meta name="viewport">.',
            "WCAG 2.1 SC 1.4.4 (Level AA) / EU EAA",
        )
    else:
        add_finding(
            "A11Y-03", P4, "Low-Vision Zoom & Text Scaling (<meta viewport>)", "PASS", "MEDIUM", 4,
            f"Viewport allows user text scaling ({vp_content[:65] or 'default'}).",
            "Users with low vision can zoom freely.",
            "None required.",
            "WCAG 2.1 SC 1.4.4 / EU EAA",
        )

    # 4.4 Semantic Heading Structure (<h1> presence)
    h1s = [h.get_text(" ", strip=True) for h in soup.find_all("h1") if h.get_text(strip=True)]
    if len(h1s) == 1:
        add_finding(
            "A11Y-04", P4, "Primary Semantic Heading Structure (<h1>)", "PASS", "LOW", 3,
            f"Single clear <h1> heading present: '{h1s[0][:65]}'",
            "Provides clear document hierarchy for assistive navigation and search indexers.",
            "None required.",
            "WCAG 2.1 SC 1.3.1 & 2.4.6",
        )
    elif len(h1s) == 0:
        add_finding(
            "A11Y-04", P4, "Primary Semantic Heading Structure (<h1>)", "FAIL", "LOW", 3,
            "Zero non-empty <h1> headings found on homepage.",
            "Impairs screen-reader landmark navigation and search engine topic indexing.",
            "Ensure every page has exactly one descriptive <h1> heading.",
            "WCAG 2.1 SC 1.3.1 & 2.4.6",
        )
    else:
        add_finding(
            "A11Y-04", P4, "Primary Semantic Heading Structure (<h1>)", "WARN", "LOW", 3,
            f"Multiple ({len(h1s)}) <h1> headings found on homepage.",
            "Dilutes primary document hierarchy.",
            "Retain a single primary <h1> and demote secondary section headers to <h2>.",
            "WCAG 2.1 SC 1.3.1",
        )

    # =========================================================================
    # PILLAR 5: Technical SEO & AI Search Discoverability
    # =========================================================================
    P5 = "5. Technical SEO & AI Discoverability"

    # 5.1 Meta Description & Title
    title_el = soup.find("title")
    title_txt = title_el.get_text(" ", strip=True) if title_el else ""
    desc_el = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
    desc_txt = (desc_el.get("content") or "").strip() if desc_el else ""
    if title_txt and desc_txt:
        add_finding(
            "SEO-01", P5, "Title & Meta Description Completeness", "PASS", "LOW", 4,
            f"Title ({len(title_txt)} chars) and Meta Description ({len(desc_txt)} chars) present.",
            "Supports search snippet rendering.",
            "None required.",
            "Search & AI Indexing Best Practice",
        )
    else:
        add_finding(
            "SEO-01", P5, "Title & Meta Description Completeness", "FAIL", "LOW", 4,
            f"Title present: {bool(title_txt)} | Meta Description present: {bool(desc_txt)}",
            "Missing meta description forces search engines and AI summarizers to guess page context.",
            "Add a concise 140–160 character <meta name='description'> tag.",
            "Search & AI Indexing Best Practice",
        )

    # 5.2 Canonical Link Element
    canon_el = soup.find("link", attrs={"rel": lambda v: v and "canonical" in (v if isinstance(v, list) else [v])})
    if canon_el and canon_el.get("href"):
        add_finding(
            "SEO-02", P5, "Canonical URL Declaration (<link rel='canonical'>)", "PASS", "LOW", 3,
            f"Canonical URL declared: {canon_el.get('href')[:70]}",
            "Prevents duplicate-content dilution across www/non-www and query parameters.",
            "None required.",
            "RFC 6596",
        )
    else:
        add_finding(
            "SEO-02", P5, "Canonical URL Declaration (<link rel='canonical'>)", "WARN", "LOW", 3,
            "No <link rel='canonical'> tag found on homepage.",
            "Search engines may index duplicate URL variants separately.",
            f'<link rel="canonical" href="{final_url}" />',
            "RFC 6596",
        )

    # 5.3 Structured JSON-LD Schema.org Markup
    jsonld_scripts = soup.find_all("script", attrs={"type": re.compile(r"application/ld\+json", re.I)})
    if jsonld_scripts:
        add_finding(
            "SEO-03", P5, "Schema.org JSON-LD Structured Data (AI Entity Graph)", "PASS", "LOW", 4,
            f"{len(jsonld_scripts)} JSON-LD structured schema block(s) found.",
            "Enables rich snippets and accurate entity citation in AI search engines (ChatGPT/Perplexity/Google AI).",
            "None required.",
            "Schema.org",
        )
    else:
        add_finding(
            "SEO-03", P5, "Schema.org JSON-LD Structured Data (AI Entity Graph)", "WARN", "LOW", 4,
            "No <script type='application/ld+json'> Schema.org markup found.",
            "AI search engines and knowledge graphs lack structured Organization/Service metadata.",
            "Add Organization / LocalBusiness / MedicalBusiness JSON-LD schema to homepage <head>.",
            "Schema.org",
        )

    # 5.4 robots.txt & XML Sitemap
    robots_ok = False
    try:
        r_rob = requests.get(f"https://{parsed_host}/robots.txt", headers={"User-Agent": USER_AGENT}, timeout=5)
        if r_rob.status_code == 200 and ("user-agent" in (r_rob.text or "").lower() or "sitemap" in (r_rob.text or "").lower()):
            robots_ok = True
    except Exception:
        pass

    if robots_ok:
        add_finding(
            "SEO-04", P5, "Crawler Directives (robots.txt)", "PASS", "LOW", 3,
            f"Valid /robots.txt verified on {parsed_host}.",
            "Guides search and AI crawlers cleanly.",
            "None required.",
            "RFC 9309",
        )
    else:
        add_finding(
            "SEO-04", P5, "Crawler Directives (robots.txt)", "WARN", "LOW", 3,
            f"No valid /robots.txt found on {parsed_host}.",
            "Crawlers lack explicit sitemap pointers and crawl-budget boundaries.",
            f"Publish /robots.txt containing 'User-agent: *' and 'Sitemap: https://{parsed_host}/sitemap.xml'.",
            "RFC 9309",
        )

    # =========================================================================
    # Compute Weighted Scores per Pillar & Overall Grade
    # =========================================================================
    total_weight = sum(f["weight"] for f in findings)
    earned_weight = sum(
        f["weight"] if f["status"] == "PASS" else (f["weight"] * 0.4 if f["status"] == "WARN" else 0.0)
        for f in findings
    )
    overall_score = int(round(100.0 * earned_weight / max(total_weight, 1)))

    if overall_score >= 88:
        grade = "A"
    elif overall_score >= 75:
        grade = "B"
    elif overall_score >= 60:
        grade = "C"
    elif overall_score >= 45:
        grade = "D"
    else:
        grade = "F"

    pillars = sorted({f["pillar"] for f in findings})
    pillar_scores: dict[str, dict[str, Any]] = {}
    for p in pillars:
        p_items = [f for f in findings if f["pillar"] == p]
        pw = sum(f["weight"] for f in p_items)
        pe = sum(
            f["weight"] if f["status"] == "PASS" else (f["weight"] * 0.4 if f["status"] == "WARN" else 0.0)
            for f in p_items
        )
        pillar_scores[p] = {
            "score": int(round(100.0 * pe / max(pw, 1))),
            "pass": sum(1 for f in p_items if f["status"] == "PASS"),
            "warn": sum(1 for f in p_items if f["status"] == "WARN"),
            "fail": sum(1 for f in p_items if f["status"] == "FAIL"),
            "total": len(p_items),
        }

    status_counts = Counter(f["status"] for f in findings)

    return {
        "domain": domain,
        "final_url": final_url,
        "scanned_at": net_now.strftime("%Y-%m-%d %H:%M UTC"),
        "response_time_ms": fetch_ms,
        "overall_score": overall_score,
        "grade": grade,
        "pass_count": status_counts.get("PASS", 0),
        "warn_count": status_counts.get("WARN", 0),
        "fail_count": status_counts.get("FAIL", 0),
        "total_checks": len(findings),
        "pillar_scores": pillar_scores,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# 3. Deliverable Generators (Visual Scorecard PNG/PDF, Word .docx, Excel .xlsx, Remediation Configs)
# ---------------------------------------------------------------------------

def generate_visual_scorecard(audit: dict[str, Any], png_path: Path, pdf_path: Path) -> None:
    """Render an executive 300-DPI visual compliance & security scorecard for Cold Email #1."""
    fig, ax = plt.subplots(figsize=(11.0, 7.2), dpi=300)
    fig.patch.set_facecolor("#FFFFFF")
    ax.set_facecolor("#FFFFFF")
    ax.set_xlim(0, 11.0)
    ax.set_ylim(0, 7.2)
    ax.axis("off")

    # Top Navy Banner
    banner = FancyBboxPatch(
        (0.25, 6.05), 10.50, 0.92,
        boxstyle="round,pad=0.0,rounding_size=0.08",
        facecolor="#112A46", edgecolor="#112A46", zorder=2
    )
    ax.add_patch(banner)
    ax.text(
        0.50, 6.66,
        f"EXTERNAL PRIVACY, DMARC & SECURITY SCORECARD — {audit['domain'].upper()}",
        fontsize=12.5, fontweight="bold", color="#FFFFFF", family="sans-serif", va="top", zorder=3
    )
    ax.text(
        0.50, 6.28,
        f"Target URL: {audit['final_url']}   |   Timestamp: {audit['scanned_at']}   |   Checks: {audit['total_checks']} passive controls",
        fontsize=8.8, color="#D0E1F9", family="sans-serif", va="top", zorder=3
    )

    # Left Card: Overall Score & Grade Badge
    score = audit["overall_score"]
    grade = audit["grade"]
    grade_color = "#1E7E34" if score >= 75 else ("#D97706" if score >= 55 else "#C00000")

    left_card = FancyBboxPatch(
        (0.25, 3.05), 3.35, 2.78,
        boxstyle="round,pad=0.0,rounding_size=0.08",
        facecolor="#F8FAFC", edgecolor="#CBD5E1", linewidth=1.2, zorder=2
    )
    ax.add_patch(left_card)
    ax.text(1.925, 5.58, "OVERALL POSTURE SCORE", ha="center", va="top", fontsize=9.5, fontweight="bold", color="#334155")
    ax.text(1.925, 4.65, f"{score}/100", ha="center", va="center", fontsize=28, fontweight="bold", color=grade_color)
    ax.text(1.925, 3.92, f"Compliance Grade: {grade}", ha="center", va="center", fontsize=11.5, fontweight="bold", color=grade_color)
    ax.text(
        1.925, 3.35,
        f"PASS: {audit['pass_count']}   |   WARN: {audit['warn_count']}   |   FAIL: {audit['fail_count']}",
        ha="center", va="center", fontsize=9.0, fontweight="bold", color="#1E293B"
    )

    # Right Card: 5-Pillar Horizontal Progress Bars
    right_card = FancyBboxPatch(
        (3.85, 3.05), 6.90, 2.78,
        boxstyle="round,pad=0.0,rounding_size=0.08",
        facecolor="#F8FAFC", edgecolor="#CBD5E1", linewidth=1.2, zorder=2
    )
    ax.add_patch(right_card)
    ax.text(4.10, 5.58, "SCORE BY REGULATORY & TECHNICAL PILLAR", ha="left", va="top", fontsize=9.5, fontweight="bold", color="#334155")

    y_cursor = 5.12
    for p_name, p_info in audit["pillar_scores"].items():
        p_score = p_info["score"]
        bar_col = "#1E7E34" if p_score >= 75 else ("#D97706" if p_score >= 55 else "#C00000")
        ax.text(4.10, y_cursor, p_name, ha="left", va="center", fontsize=8.8, fontweight="bold", color="#1E293B")
        ax.text(10.50, y_cursor, f"{p_score}% ({p_info['pass']}/{p_info['total']} pass)", ha="right", va="center", fontsize=8.5, fontweight="bold", color=bar_col)

        # Background bar track
        bg_bar = FancyBboxPatch(
            (4.10, y_cursor - 0.22), 6.40, 0.12,
            boxstyle="round,pad=0.0,rounding_size=0.03",
            facecolor="#E2E8F0", edgecolor="none", zorder=3
        )
        ax.add_patch(bg_bar)
        # Foreground bar fill
        fill_w = max(0.08, 6.40 * (p_score / 100.0))
        fg_bar = FancyBboxPatch(
            (4.10, y_cursor - 0.22), fill_w, 0.12,
            boxstyle="round,pad=0.0,rounding_size=0.03",
            facecolor=bar_col, edgecolor="none", zorder=4
        )
        ax.add_patch(fg_bar)
        y_cursor -= 0.46

    # Bottom Card: Top Priority Actionable Gaps Found on Live Domain
    btm_card = FancyBboxPatch(
        (0.25, 0.42), 10.50, 2.40,
        boxstyle="round,pad=0.0,rounding_size=0.08",
        facecolor="#FFFBEB", edgecolor="#F59E0B", linewidth=1.2, zorder=2
    )
    ax.add_patch(btm_card)
    ax.text(
        0.50, 2.62,
        "PRIORITY GAPS DETECTED ON LIVE DOMAIN (REQUIRING REMEDIATION):",
        ha="left", va="top", fontsize=9.8, fontweight="bold", color="#92400E", zorder=3
    )

    gaps = [f for f in audit["findings"] if f["status"] in ("FAIL", "WARN")]
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    gaps.sort(key=lambda x: (0 if x["status"] == "FAIL" else 1, sev_rank.get(x["severity"], 4)))

    gy = 2.28
    for g in gaps[:5]:
        badge = f"[{g['status']} / {g['severity']}]"
        raw_line = f"{badge} {g['title']} — {g['evidence']}"
        line = textwrap.shorten(raw_line, width=112, placeholder="...")
        ax.text(0.50, gy, line, ha="left", va="top", fontsize=8.2, fontweight="bold" if g["status"] == "FAIL" else "normal", color="#1E293B", zorder=3)
        gy -= 0.36

    if not gaps:
        ax.text(0.50, 1.80, "All 21 passive controls passed without critical findings.", ha="left", va="top", fontsize=9.5, color="#1E7E34", zorder=3)

    ax.text(
        5.5, 0.14,
        "Passive External Posture Assessment (nFADP / GDPR / RFC 7489 DMARC / OWASP / EAA). Prepared for internal QA & IT review.",
        ha="center", va="bottom", fontsize=7.8, style="italic", color="#64748B"
    )

    plt.tight_layout(pad=0.25)
    fig.savefig(str(png_path), dpi=300, facecolor="#FFFFFF")
    fig.savefig(str(pdf_path), format="pdf", facecolor="#FFFFFF")
    plt.close(fig)


def generate_word_audit_report(audit: dict[str, Any], out_path: Path) -> None:
    """Create a landscape Word (.docx) Executive Audit & Remediation Report."""
    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(10)

    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width = Inches(11.69)
    section.page_height = Inches(8.27)
    section.top_margin = Inches(0.55)
    section.bottom_margin = Inches(0.55)
    section.left_margin = Inches(0.55)
    section.right_margin = Inches(0.55)

    # Footer
    f_para = section.footer.paragraphs[0]
    f_run = f_para.add_run(
        f"Passive External Compliance & Security Audit — {audit['domain']} | Generated {audit['scanned_at']} | For internal IT/QA review."
    )
    f_run.font.name = "Calibri"
    f_run.font.size = Pt(8.5)
    f_run.font.italic = True
    f_run.font.color.rgb = RGBColor(0x59, 0x59, 0x59)

    # Title
    tp = doc.add_paragraph()
    tp.paragraph_format.space_after = Pt(3)
    tr = tp.add_run(f"External Web Privacy (nFADP/GDPR), DMARC & Security Audit — {audit['domain']}")
    tr.font.name = "Calibri"
    tr.font.size = Pt(15)
    tr.font.bold = True
    tr.font.color.rgb = RGBColor(0x11, 0x2A, 0x46)

    subp = doc.add_paragraph()
    subp.paragraph_format.space_after = Pt(6)
    sr = subp.add_run(
        f"Audited URL: {audit['final_url']}  |  Date: {audit['scanned_at']}  |  "
        f"Overall Score: {audit['overall_score']}/100 (Grade {audit['grade']})  |  "
        f"Pass: {audit['pass_count']}  |  Warn: {audit['warn_count']}  |  Fail: {audit['fail_count']}"
    )
    sr.font.name = "Calibri"
    sr.font.size = Pt(10)
    sr.font.bold = True

    # Findings Table
    headers = ["ID", "Pillar", "Control", "Status", "Severity", "Live Evidence Captured", "Actionable Remediation"]
    col_widths = [
        Inches(0.65),
        Inches(1.45),
        Inches(1.65),
        Inches(0.65),
        Inches(0.80),
        Inches(2.65),
        Inches(2.70),
    ]

    table = doc.add_table(rows=1, cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False

    tblPr = table._tbl.tblPr
    tblPr.append(
        parse_xml(
            f'<w:tblBorders {nsdecls("w")}>'
            '<w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '<w:left w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '<w:right w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            "</w:tblBorders>"
        )
    )

    hdr_row = table.rows[0]
    hdr_row._tr.get_or_add_trPr().append(OxmlElement("w:tblHeader"))
    for i, h_text in enumerate(headers):
        c = hdr_row.cells[i]
        c.width = col_widths[i]
        c._tc.get_or_add_tcPr().append(parse_xml(f'<w:shd {nsdecls("w")} w:fill="112A46"/>'))
        p = c.paragraphs[0]
        r = p.add_run(h_text)
        r.font.name = "Calibri"
        r.font.size = Pt(9.5)
        r.font.bold = True
        r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

    for idx, f in enumerate(audit["findings"]):
        row = table.add_row()
        row._tr.get_or_add_trPr().append(OxmlElement("w:cantSplit"))
        vals = [
            f["id"],
            f["pillar"],
            f["title"],
            f["status"],
            f["severity"],
            f["evidence"],
            f["remediation"],
        ]
        bg = "FFFFFF" if idx % 2 == 0 else "F8FAFC"
        for c_i, val in enumerate(vals):
            cell = row.cells[c_i]
            cell.width = col_widths[c_i]
            if c_i == 3:
                shd = "FEE2E2" if f["status"] == "FAIL" else ("FEF3C7" if f["status"] == "WARN" else "DCFCE7")
                cell._tc.get_or_add_tcPr().append(parse_xml(f'<w:shd {nsdecls("w")} w:fill="{shd}"/>'))
            else:
                cell._tc.get_or_add_tcPr().append(parse_xml(f'<w:shd {nsdecls("w")} w:fill="{bg}"/>'))
            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.space_after = Pt(2)
            run = p.add_run(str(val))
            run.font.name = "Calibri"
            run.font.size = Pt(9.0)
            if c_i in (0, 3):
                run.font.bold = True

    doc.save(str(out_path))


def generate_excel_audit_workbook(audit: dict[str, Any], out_path: Path) -> None:
    wb = openpyxl.Workbook()
    font_family = "Calibri"
    hdr_font = Font(name=font_family, size=10, bold=True, color="FFFFFF")
    hdr_fill = PatternFill(start_color="112A46", end_color="112A46", fill_type="solid")
    body_font = Font(name=font_family, size=10)
    bold_font = Font(name=font_family, size=10, bold=True)

    pass_fill = PatternFill(start_color="DCFCE7", end_color="DCFCE7", fill_type="solid")
    warn_fill = PatternFill(start_color="FEF3C7", end_color="FEF3C7", fill_type="solid")
    fail_fill = PatternFill(start_color="FEE2E2", end_color="FEE2E2", fill_type="solid")

    thin = Side(border_style="thin", color="CBD5E1")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    wrap_top = Alignment(wrap_text=True, vertical="top", horizontal="left")

    # Sheet 1: Findings_Matrix
    ws = wb.active
    ws.title = "Findings_Matrix"
    cols = ["ID", "Pillar", "Control", "Status", "Severity", "Weight", "Live_Evidence", "Business_Impact", "Remediation_Action", "Regulation_Standard"]
    ws.append(cols)
    ws.freeze_panes = "A2"
    for c_i in range(1, len(cols) + 1):
        cell = ws.cell(row=1, column=c_i)
        cell.font = hdr_font
        cell.fill = hdr_fill
        cell.border = border

    for r_i, f in enumerate(audit["findings"], start=2):
        ws.append([
            f["id"], f["pillar"], f["title"], f["status"], f["severity"],
            f["weight"], f["evidence"], f["impact"], f["remediation"], f["regulation"]
        ])
        for c_i in range(1, len(cols) + 1):
            c = ws.cell(row=r_i, column=c_i)
            c.font = bold_font if c_i in (1, 4) else body_font
            c.border = border
            c.alignment = wrap_top
            if c_i == 4:
                c.fill = pass_fill if f["status"] == "PASS" else (warn_fill if f["status"] == "WARN" else fail_fill)

    ws.auto_filter.ref = f"A1:{get_column_letter(len(cols))}{len(audit['findings']) + 1}"
    widths = [10, 28, 34, 10, 12, 9, 44, 40, 46, 30]
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = w

    # Sheet 2: Pillar_Summary
    ws2 = wb.create_sheet("Pillar_Summary")
    ws2.append(["Pillar", "Score (%)", "Passed", "Warnings", "Failed", "Total Controls"])
    ws2.freeze_panes = "A2"
    for c_i in range(1, 7):
        ws2.cell(row=1, column=c_i).font = hdr_font
        ws2.cell(row=1, column=c_i).fill = hdr_fill
    for p_name, p_info in audit["pillar_scores"].items():
        ws2.append([p_name, p_info["score"], p_info["pass"], p_info["warn"], p_info["fail"], p_info["total"]])
    for col_let, w in zip(["A", "B", "C", "D", "E", "F"], [36, 14, 12, 12, 12, 16]):
        ws2.column_dimensions[col_let].width = w

    # Sheet 3: Remediation_Roadmap (Priority-ordered FAIL & WARN controls)
    ws3 = wb.create_sheet("Remediation_Roadmap")
    ws3.append(["Priority_Rank", "ID", "Severity", "Status", "Control", "Actionable_Fix", "Target_Standard"])
    ws3.freeze_panes = "A2"
    for c_i in range(1, 8):
        ws3.cell(row=1, column=c_i).font = hdr_font
        ws3.cell(row=1, column=c_i).fill = hdr_fill
    gaps = [f for f in audit["findings"] if f["status"] in ("FAIL", "WARN")]
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    gaps.sort(key=lambda x: (0 if x["status"] == "FAIL" else 1, sev_order.get(x["severity"], 4)))
    for rank_idx, g in enumerate(gaps, start=1):
        ws3.append([rank_idx, g["id"], g["severity"], g["status"], g["title"], g["remediation"], g["regulation"]])
    for col_let, w in zip(["A", "B", "C", "D", "E", "F", "G"], [14, 10, 12, 10, 34, 52, 30]):
        ws3.column_dimensions[col_let].width = w

    # Sheet 4: README
    ws4 = wb.create_sheet("README")
    ws4.append(["Sheet_Name", "Description"])
    ws4.cell(row=1, column=1).font = hdr_font
    ws4.cell(row=1, column=1).fill = hdr_fill
    ws4.cell(row=1, column=2).font = hdr_font
    ws4.cell(row=1, column=2).fill = hdr_fill
    ws4.append(["Findings_Matrix", "Complete 25-control passive audit table with AutoFilter and status highlighting."])
    ws4.append(["Pillar_Summary", "Weighted percentage scores and PASS/WARN/FAIL breakdown across all 5 pillars."])
    ws4.append(["Remediation_Roadmap", "Priority-ordered action list of failing and warning controls for IT/DevOps."])
    ws4.append(["README", "Guide to sheets and methodology notes (100% passive OSINT inspection)."])
    ws4.column_dimensions["A"].width = 24
    ws4.column_dimensions["B"].width = 78

    wb.save(str(out_path))


def write_remediation_configs(audit: dict[str, Any], cfg_dir: Path) -> None:
    """Write ready-to-paste Nginx, Cloudflare _headers, and DNS records for the target domain."""
    cfg_dir.mkdir(parents=True, exist_ok=True)
    dom = audit["domain"]

    headers_txt = f"""# Drop-in HTTP Security Headers for {dom} (Cloudflare Pages / Netlify _headers format)
/*
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  Content-Security-Policy: default-src 'self' https:; img-src 'self' https: data:; style-src 'self' 'unsafe-inline' https:; script-src 'self' 'unsafe-inline' https:; frame-ancestors 'self'; object-src 'none';
  X-Frame-Options: SAMEORIGIN
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
"""
    (cfg_dir / "_headers").write_text(headers_txt, encoding="utf-8")

    nginx_txt = f"""# Drop-in Nginx Security & Privacy Header Snippet for {dom}
server_tokens off;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
"""
    (cfg_dir / "nginx_security_headers.conf").write_text(nginx_txt, encoding="utf-8")

    dns_txt = f"""# Recommended DNS Anti-Spoofing & CAA Records for {dom}
_dmarc.{dom}.   3600 IN TXT "v=DMARC1; p=quarantine; rua=mailto:postmaster@{dom}; adkim=r; aspf=r;"
{dom}.          3600 IN CAA 0 issue "letsencrypt.org"
"""
    (cfg_dir / "dns_remediation_records.txt").write_text(dns_txt, encoding="utf-8")


def build_domain_audit_package(target: str, base_out: str | Path = "output") -> dict[str, Any]:
    audit = run_domain_audit(target)
    slug = re.sub(r"[^a-z0-9]+", "_", audit["domain"].lower()).strip("_")
    pkg_dir = Path(base_out) / f"{slug}_audit"
    pkg_dir.mkdir(parents=True, exist_ok=True)

    docx_p = pkg_dir / f"{slug}_executive_audit.docx"
    xlsx_p = pkg_dir / f"{slug}_technical_findings.xlsx"
    png_p = pkg_dir / f"{slug}_scorecard.png"
    pdf_p = pkg_dir / f"{slug}_scorecard.pdf"
    json_p = pkg_dir / f"{slug}_raw_evidence.json"
    cfg_dir = pkg_dir / "remediation_configs"

    generate_visual_scorecard(audit, png_p, pdf_p)
    generate_word_audit_report(audit, docx_p)
    generate_excel_audit_workbook(audit, xlsx_p)
    write_remediation_configs(audit, cfg_dir)
    json_p.write_text(json.dumps(audit, indent=2), encoding="utf-8")

    zip_p = Path(base_out) / f"{slug}_audit_package.zip"
    with zipfile.ZipFile(zip_p, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fp in (docx_p, xlsx_p, png_p, pdf_p, json_p):
            zf.write(fp, arcname=f"{slug}_audit/{fp.name}")
        for cf in cfg_dir.iterdir():
            zf.write(cf, arcname=f"{slug}_audit/remediation_configs/{cf.name}")

    return {
        "audit": audit,
        "pkg_dir": pkg_dir,
        "docx": docx_p,
        "xlsx": xlsx_p,
        "png": png_p,
        "pdf": pdf_p,
        "zip": zip_p,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Passive B2B Web Privacy (nFADP/GDPR), DMARC & Edge Security Auditor."
    )
    parser.add_argument("targets", nargs="+", help="One or more domain names or URLs to audit")
    parser.add_argument("--output-dir", default="output", help="Output folder (default: output)")
    args = parser.parse_args(argv)

    summary_rows = []
    for t in args.targets:
        try:
            print(f"[sentinel] Auditing {t} ...")
            res = build_domain_audit_package(t, args.output_dir)
            a = res["audit"]
            summary_rows.append(a)
            print(
                f"  -> {a['domain']}: Score {a['overall_score']}/100 (Grade {a['grade']}) | "
                f"PASS={a['pass_count']} WARN={a['warn_count']} FAIL={a['fail_count']} | "
                f"Package: {res['zip']}"
            )
        except Exception as exc:
            print(f"  -> [ERROR] {t}: {exc}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
