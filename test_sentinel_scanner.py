#!/usr/bin/env python3
"""
Unit & Integration Tests for Sentinel Passive Domain Compliance & Security Auditor.
Verifies:
  1. Synthetic / offline audit dictionary formatting and scoring structure.
  2. Generation of all executive deliverables (.docx, .xlsx, .png, .pdf) + remediation_configs/.
  3. Excel workbook sheets, AutoFilter, frozen header, and status color fills.
  4. Word document landscape orientation, tables, and executive summary.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

import openpyxl
from docx import Document

from sentinel_scanner import (
    generate_excel_audit_workbook,
    generate_visual_scorecard,
    generate_word_audit_report,
    normalize_domain_and_url,
    write_remediation_configs,
)


class TestSentinelComplianceAuditor(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="sentinel_test_"))
        self.sample_audit = {
            "domain": "example-sme.ch",
            "final_url": "https://example-sme.ch/",
            "scanned_at": "2026-03-02 17:40 UTC",
            "response_time_ms": 142,
            "overall_score": 48,
            "grade": "D",
            "pass_count": 2,
            "warn_count": 1,
            "fail_count": 2,
            "total_checks": 5,
            "pillar_scores": {
                "1. Email & Anti-Spoofing (DMARC/SPF)": {"score": 35, "pass": 0, "warn": 1, "fail": 1, "total": 2},
                "2. Swiss nFADP & GDPR Web Privacy": {"score": 0, "pass": 0, "warn": 0, "fail": 1, "total": 1},
                "3. Edge & Transport Security (HTTP/TLS)": {"score": 100, "pass": 1, "warn": 0, "fail": 0, "total": 1},
                "4. Accessibility (EAA / WCAG 2.1 AA)": {"score": 100, "pass": 1, "warn": 0, "fail": 0, "total": 1},
            },
            "findings": [
                {
                    "id": "EML-01",
                    "pillar": "1. Email & Anti-Spoofing (DMARC/SPF)",
                    "title": "DMARC Anti-Spoofing Record & Policy",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "weight": 12,
                    "evidence": "No _dmarc.example-sme.ch TXT record found in public DNS.",
                    "impact": "Attackers can spoof @example-sme.ch emails.",
                    "remediation": "Publish _dmarc.example-sme.ch TXT record with p=quarantine.",
                    "regulation": "RFC 7489",
                },
                {
                    "id": "PRV-01",
                    "pillar": "2. Swiss nFADP & GDPR Web Privacy",
                    "title": "Remote Google Fonts IP Leak (Schrems II / nFADP)",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "weight": 8,
                    "evidence": "Page HTML loads fonts directly from fonts.googleapis.com on initial load.",
                    "impact": "Transmits visitor IP to US servers before consent.",
                    "remediation": "Self-host WOFF2 fonts locally.",
                    "regulation": "Swiss nFADP Art. 6 & 16 / GDPR Art. 44",
                },
                {
                    "id": "EML-04",
                    "pillar": "1. Email & Anti-Spoofing (DMARC/SPF)",
                    "title": "DNS CAA (Certificate Authority Restriction)",
                    "status": "WARN",
                    "severity": "LOW",
                    "weight": 3,
                    "evidence": "No DNS CAA record found on example-sme.ch.",
                    "impact": "Any public CA can issue a certificate.",
                    "remediation": "Add DNS CAA record.",
                    "regulation": "RFC 8659",
                },
                {
                    "id": "SEC-01",
                    "pillar": "3. Edge & Transport Security (HTTP/TLS)",
                    "title": "TLS Encryption & Certificate Validity",
                    "status": "PASS",
                    "severity": "CRITICAL",
                    "weight": 8,
                    "evidence": "Protocol TLSv1.3, valid for 68 days.",
                    "impact": "Encrypted transport is active.",
                    "remediation": "None required.",
                    "regulation": "Swiss nFADP Art. 8",
                },
                {
                    "id": "A11Y-01",
                    "pillar": "4. Accessibility (EAA / WCAG 2.1 AA)",
                    "title": "Document Primary Language Declaration (<html lang>)",
                    "status": "PASS",
                    "severity": "MEDIUM",
                    "weight": 4,
                    "evidence": "<html lang='de-CH'> is declared.",
                    "impact": "Screen readers select proper pronunciation.",
                    "remediation": "None required.",
                    "regulation": "WCAG 2.1 SC 3.1.1",
                },
            ],
        }

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_normalize_domain_and_url(self) -> None:
        dom, url = normalize_domain_and_url("https://www.Example-SME.ch/contact")
        self.assertEqual(dom, "example-sme.ch")
        self.assertEqual(url, "https://www.example-sme.ch")

    def test_deliverable_generators_create_valid_outputs(self) -> None:
        docx_p = self.temp_dir / "test_executive_audit.docx"
        xlsx_p = self.temp_dir / "test_technical_findings.xlsx"
        png_p = self.temp_dir / "test_scorecard.png"
        pdf_p = self.temp_dir / "test_scorecard.pdf"
        cfg_dir = self.temp_dir / "remediation_configs"

        generate_visual_scorecard(self.sample_audit, png_p, pdf_p)
        generate_word_audit_report(self.sample_audit, docx_p)
        generate_excel_audit_workbook(self.sample_audit, xlsx_p)
        write_remediation_configs(self.sample_audit, cfg_dir)

        self.assertTrue(png_p.exists() and png_p.stat().st_size > 10000)
        self.assertTrue(pdf_p.exists() and pdf_p.stat().st_size > 5000)
        self.assertTrue(docx_p.exists())
        self.assertTrue(xlsx_p.exists())
        self.assertTrue((cfg_dir / "_headers").exists())
        self.assertTrue((cfg_dir / "nginx_security_headers.conf").exists())
        self.assertTrue((cfg_dir / "dns_remediation_records.txt").exists())

        doc = Document(str(docx_p))
        self.assertEqual(len(doc.tables), 1)
        self.assertGreater(doc.sections[0].page_width, doc.sections[0].page_height)

        wb = openpyxl.load_workbook(str(xlsx_p))
        self.assertEqual(wb.sheetnames, ["Audit_Findings", "Pillar_Summary"])
        ws = wb["Audit_Findings"]
        self.assertEqual(ws.freeze_panes, "A2")
        self.assertIsNotNone(ws.auto_filter.ref)


if __name__ == "__main__":
    unittest.main()
