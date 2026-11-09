#!/usr/bin/env python3
"""Generate a synthetic demonstration audit package in examples/sample_swiss_sme_audit/ for public repository showcase."""

from pathlib import Path
from sentinel_scanner import (
    generate_excel_audit_workbook,
    generate_visual_scorecard,
    generate_word_audit_report,
    write_remediation_configs,
)


def main() -> None:
    out_dir = Path(__file__).resolve().parent / "examples" / "sample_swiss_sme_audit"
    out_dir.mkdir(parents=True, exist_ok=True)

    demo_audit = {
        "domain": "alpine-treuhand-demo.ch",
        "final_url": "https://www.alpine-treuhand-demo.ch/",
        "scanned_at": "2026-03-02 17:30 UTC (Fictional Demo Sample)",
        "response_time_ms": 138,
        "overall_score": 49,
        "grade": "D",
        "pass_count": 12,
        "warn_count": 4,
        "fail_count": 9,
        "total_checks": 25,
        "pillar_scores": {
            "1. Email & Anti-Spoofing (DMARC/SPF)": {"score": 38, "pass": 2, "warn": 1, "fail": 1, "total": 4},
            "2. Swiss nFADP & GDPR Web Privacy": {"score": 40, "pass": 1, "warn": 1, "fail": 2, "total": 4},
            "3. Edge & Transport Security (HTTP/TLS)": {"score": 32, "pass": 2, "warn": 2, "fail": 5, "total": 9},
            "4. Accessibility (EAA / WCAG 2.1 AA)": {"score": 73, "pass": 3, "warn": 0, "fail": 1, "total": 4},
            "5. Technical SEO & AI Discoverability": {"score": 100, "pass": 4, "warn": 0, "fail": 0, "total": 4},
        },
        "findings": [
            {
                "id": "EML-01",
                "pillar": "1. Email & Anti-Spoofing (DMARC/SPF)",
                "title": "DMARC Anti-Spoofing Record & Policy",
                "status": "FAIL",
                "severity": "CRITICAL",
                "weight": 12,
                "evidence": "No _dmarc.alpine-treuhand-demo.ch TXT record found in public DNS.",
                "impact": "External attackers can send forged emails and fake invoices appearing to come from @alpine-treuhand-demo.ch.",
                "remediation": 'Publish DNS TXT record at _dmarc.alpine-treuhand-demo.ch: "v=DMARC1; p=quarantine; rua=mailto:postmaster@alpine-treuhand-demo.ch;"',
                "regulation": "RFC 7489 / FINMA Operational Risk",
            },
            {
                "id": "PRV-01",
                "pillar": "2. Swiss nFADP & GDPR Web Privacy",
                "title": "Remote Google Fonts IP Leak (Schrems II / nFADP)",
                "status": "FAIL",
                "severity": "HIGH",
                "weight": 8,
                "evidence": "Page HTML loads fonts directly from fonts.googleapis.com / fonts.gstatic.com on initial load.",
                "impact": "Automatically transmits visitor IP addresses to US servers before consent (Swiss nFADP Art. 6 & 16 / GDPR Art. 44).",
                "remediation": "Download webfont files (.woff2) and host them locally; remove remote fonts.googleapis.com stylesheet link.",
                "regulation": "Swiss nFADP Art. 6 & 16 / EU GDPR Art. 44",
            },
            {
                "id": "SEC-02",
                "pillar": "3. Edge & Transport Security (HTTP/TLS)",
                "title": "HTTP Strict-Transport-Security (HSTS)",
                "status": "FAIL",
                "severity": "HIGH",
                "weight": 7,
                "evidence": "Missing 'Strict-Transport-Security' response header.",
                "impact": "First-time visitors on public Wi-Fi are vulnerable to SSL-stripping / downgrade interception.",
                "remediation": "Add response header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                "regulation": "RFC 6797 / OWASP Secure Headers",
            },
            {
                "id": "SEC-03",
                "pillar": "3. Edge & Transport Security (HTTP/TLS)",
                "title": "Content-Security-Policy (CSP)",
                "status": "FAIL",
                "severity": "HIGH",
                "weight": 7,
                "evidence": "Missing 'Content-Security-Policy' response header.",
                "impact": "Browser permits execution of injected third-party scripts or form-skimming attacks (XSS).",
                "remediation": "Add baseline CSP header restricting default-src and frame-ancestors.",
                "regulation": "W3C CSP3 / OWASP Top 10",
            },
            {
                "id": "SEC-04",
                "pillar": "3. Edge & Transport Security (HTTP/TLS)",
                "title": "Anti-Clickjacking Protection (X-Frame-Options)",
                "status": "FAIL",
                "severity": "MEDIUM",
                "weight": 5,
                "evidence": "Neither 'X-Frame-Options' nor CSP 'frame-ancestors' header is set.",
                "impact": "Website can be embedded inside a transparent iframe on third-party domains.",
                "remediation": "Add response header: X-Frame-Options: SAMEORIGIN",
                "regulation": "OWASP Clickjacking Defense",
            },
        ],
    }

    generate_visual_scorecard(
        demo_audit,
        out_dir / "alpine_treuhand_demo_ch_scorecard.png",
        out_dir / "alpine_treuhand_demo_ch_scorecard.pdf",
    )
    generate_word_audit_report(demo_audit, out_dir / "alpine_treuhand_demo_ch_executive_audit.docx")
    generate_excel_audit_workbook(demo_audit, out_dir / "alpine_treuhand_demo_ch_technical_findings.xlsx")
    write_remediation_configs(demo_audit, out_dir / "remediation_configs")
    print(f"Generated synthetic demo audit in {out_dir}")


if __name__ == "__main__":
    main()
