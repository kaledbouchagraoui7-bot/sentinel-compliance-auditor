#!/usr/bin/env python3
"""
editorial_renderer.py — Headless Browser Swiss-Editorial PDF & Retina PNG Renderer
===================================================================================

Replaces generic Matplotlib / Rounded-Box charts with crisp editorial HTML5 + CSS Grid
documents rendered via Microsoft Edge Headless (vector PDF + 2x Retina PNG), with a
clean Matplotlib fallback only if a headless Chromium browser is unavailable.
"""

from __future__ import annotations

import html
import os
import shutil
import subprocess
import tempfile
import textwrap
import threading
from pathlib import Path
from typing import Any

_EDGE_RENDER_LOCK = threading.Lock()

_SENTINEL_HEADER_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="20 25 360 360" width="46" height="46" role="img" aria-label="Sentinel mark">
<defs>
  <radialGradient id="sHdrOrb" cx=".35" cy=".28" r=".95">
    <stop offset="0" stop-color="#d9fbff"/><stop offset=".38" stop-color="#3fc4f2"/><stop offset=".78" stop-color="#0b7fd0"/><stop offset="1" stop-color="#0a4f9e"/>
  </radialGradient>
  <linearGradient id="sHdrRim" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#fff"/><stop offset=".5" stop-color="#9deaff" stop-opacity=".6"/><stop offset="1" stop-color="#0f766e"/>
  </linearGradient>
  <linearGradient id="sHdrCross" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#fff"/><stop offset=".55" stop-color="#c4eeff"/><stop offset="1" stop-color="#74c9f0"/>
  </linearGradient>
  <radialGradient id="sHdrLime" cx=".38" cy=".3" r=".8">
    <stop offset="0" stop-color="#f9ffc2"/><stop offset=".45" stop-color="#a6e82c"/><stop offset="1" stop-color="#2f9a1c"/>
  </radialGradient>
  <linearGradient id="sHdrGloss" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#fff" stop-opacity=".9"/><stop offset="1" stop-color="#fff" stop-opacity=".05"/>
  </linearGradient>
</defs>
<circle cx="200" cy="205" r="148" fill="url(#sHdrOrb)"/>
<circle cx="200" cy="205" r="148" fill="none" stroke="url(#sHdrRim)" stroke-width="6"/>
<rect x="125" y="181" width="150" height="48" rx="18" fill="url(#sHdrCross)" stroke="#fff" stroke-width="3"/>
<rect x="176" y="130" width="48" height="150" rx="18" fill="url(#sHdrCross)" stroke="#fff" stroke-width="3"/>
<rect x="176" y="183" width="48" height="44" fill="url(#sHdrCross)"/>
<circle cx="200" cy="205" r="28" fill="url(#sHdrLime)" stroke="#fff" stroke-width="3.5"/>
<path d="M62 188 C 70 100, 140 62, 200 62 C 260 62, 330 100, 338 188 C 290 146, 110 146, 62 188Z" fill="url(#sHdrGloss)"/>
<g fill="none" stroke="#0f172a" stroke-width="10" stroke-linecap="round" stroke-linejoin="round" opacity="0.28">
  <path d="M40 85 V45 H80"/><path d="M320 45 H360 V85"/><path d="M360 325 V365 H320"/><path d="M80 365 H40 V325"/>
</g>
</svg>"""


def find_headless_browser() -> str | None:
    """Locate Microsoft Edge or Google Chrome executable on Windows/macOS/Linux."""
    candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    for cmd in ("msedge", "google-chrome", "chromium", "chromium-browser"):
        found = shutil.which(cmd)
        if found:
            return found
    return None


def render_html_to_pdf_and_png(
    html_content: str,
    png_path: Path | None = None,
    pdf_path: Path | None = None,
    width_px: int = 1140,
    height_px: int = 780,
) -> bool:
    """Render HTML string cleanly into vector PDF and 2x Retina PNG using headless Edge/Chrome."""
    browser = find_headless_browser()
    if not browser:
        return False

    tmp_dir = Path(tempfile.mkdtemp(prefix="editorial_render_"))
    try:
        html_file = tmp_dir / "brief.html"
        html_file.write_text(html_content, encoding="utf-8")
        file_uri = html_file.as_uri()
        profile_dir = tmp_dir / "edge_profile"

        with _EDGE_RENDER_LOCK:
            if pdf_path is not None:
                pdf_path.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    [
                        browser,
                        "--headless=new",
                        "--disable-gpu",
                        "--no-sandbox",
                        "--no-first-run",
                        "--disable-extensions",
                        "--disable-background-networking",
                        "--run-all-compositor-stages-before-draw",
                        "--virtual-time-budget=2000",
                        f"--user-data-dir={profile_dir}",
                        "--no-pdf-header-footer",
                        f"--print-to-pdf={pdf_path.resolve()}",
                        file_uri,
                    ],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )

            if png_path is not None:
                png_path.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    [
                        browser,
                        "--headless=new",
                        "--disable-gpu",
                        "--no-sandbox",
                        "--no-first-run",
                        "--disable-extensions",
                        "--disable-background-networking",
                        "--run-all-compositor-stages-before-draw",
                        "--virtual-time-budget=2000",
                        f"--user-data-dir={profile_dir}",
                        "--hide-scrollbars",
                        "--force-device-scale-factor=2",
                        f"--window-size={width_px},{height_px}",
                        f"--screenshot={png_path.resolve()}",
                        file_uri,
                    ],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
        pdf_ok = True if pdf_path is None else (pdf_path.exists() and pdf_path.stat().st_size > 2000)
        png_ok = True if png_path is None else (png_path.exists() and png_path.stat().st_size > 65000)
        return pdf_ok and png_ok
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _humanize_finding_note(text: str, width: int = 105) -> str:
    """Shorten cleanly on word boundaries without abrupt mid-word cuts."""
    clean = " ".join(str(text).split())
    if len(clean) <= width:
        return clean
    return textwrap.shorten(clean, width=width, placeholder="...")


def build_client_brief_html(audit: dict[str, Any]) -> str:
    """
    Build a refined, Swiss-editorial 1-page technical posture briefing (11.4in x 7.8in).
    Removes school-style 'Grade F' badges and neon AI boxes in favor of objective consulting clarity.
    """
    domain = html.escape(str(audit.get("domain", "")))
    final_url = html.escape(str(audit.get("final_url", "")))
    scanned_at = html.escape(str(audit.get("scanned_at", "")))
    score = int(audit.get("overall_score", 0))
    total_checks = int(audit.get("total_checks", 25))
    pass_c = int(audit.get("pass_count", 0))
    warn_c = int(audit.get("warn_count", 0))
    fail_c = int(audit.get("fail_count", 0))

    if score >= 80:
        posture_label = "Strong Baseline Posture"
        posture_tone = "#0F766E"
    elif score >= 60:
        posture_label = "Moderate Configuration Exposure"
        posture_tone = "#B45309"
    else:
        posture_label = "High Remediation Priority"
        posture_tone = "#991B1B"

    pillars_html_rows = []
    for p_name, p_info in audit.get("pillar_scores", {}).items():
        p_score = int(p_info.get("score", 0))
        p_pass = int(p_info.get("pass", 0))
        p_tot = int(p_info.get("total", 0))
        bar_color = "#0F766E" if p_score >= 75 else ("#B45309" if p_score >= 50 else "#991B1B")
        pillars_html_rows.append(
            f"""
            <div class="pillar-row">
              <div class="pillar-meta">
                <span class="pillar-name">{html.escape(p_name)}</span>
                <span class="pillar-stat" style="color:{bar_color};">{p_pass}/{p_tot} verified &middot; {p_score}%</span>
              </div>
              <div class="track"><div class="fill" style="width:{max(3, p_score)}%;background:{bar_color};"></div></div>
            </div>
            """
        )

    findings = list(audit.get("findings", []))
    gaps = [f for f in findings if f.get("status") in ("FAIL", "WARN")]
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    gaps.sort(key=lambda x: (0 if x.get("status") == "FAIL" else 1, sev_rank.get(str(x.get("severity", "LOW")), 4)))

    gaps_rows = []
    for g in gaps[:5]:
        is_fail = g.get("status") == "FAIL"
        pill_cls = "pill-priority" if is_fail else "pill-advisory"
        pill_txt = "ACTION NEEDED" if is_fail else "REVIEW"
        cid = html.escape(str(g.get("id", "")))
        title = html.escape(_humanize_finding_note(str(g.get("title", "")), 78))
        evidence = html.escape(_humanize_finding_note(str(g.get("evidence", "")), 150))
        impact = html.escape(_humanize_finding_note(str(g.get("impact", "")), 165))
        gaps_rows.append(
            f"""
            <tr>
              <td class="col-id"><span class="{pill_cls}">{pill_txt}</span><div class="code-id">{cid}</div></td>
              <td class="col-title"><strong>{title}</strong><div class="ev">{evidence}</div></td>
              <td class="col-impact">{impact}</td>
            </tr>
            """
        )

    if not gaps_rows:
        gaps_rows.append(
            '<tr><td colspan="3" style="padding:14px;color:#0F766E;font-weight:600;">All inspected passive DNS, privacy, and HTTP transport controls passed without material gaps.</td></tr>'
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<style>
  @page {{ size: 11.4in 7.8in; margin: 0; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    width: 1140px;
    height: 780px;
    padding: 30px 44px 22px 44px;
    background: #FFFFFF;
    color: #111827;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }}
  .header {{
    border-bottom: 2px solid #0F172A;
    padding-bottom: 12px;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
  }}
  .header-brand {{
    display: flex;
    align-items: center;
    gap: 13px;
  }}
  .brand-mark {{
    flex: 0 0 auto;
    line-height: 0;
  }}
  .eyebrow {{
    font-size: 10px;
    letter-spacing: 1.6px;
    text-transform: uppercase;
    color: #0F766E;
    font-weight: 700;
    margin-bottom: 4px;
  }}
  h1 {{
    margin: 0;
    font-family: Georgia, 'Times New Roman', serif;
    font-size: 24px;
    font-weight: 700;
    color: #0F172A;
    letter-spacing: -0.2px;
  }}
  .header-right {{
    text-align: right;
    font-size: 11px;
    color: #4B5563;
    line-height: 1.45;
  }}
  .header-right strong {{ color: #111827; }}

  .top-grid {{
    display: grid;
    grid-template-columns: 310px 1fr;
    gap: 28px;
    margin-top: 12px;
  }}
  .summary-box {{
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-top: 3px solid {posture_tone};
    padding: 15px 18px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }}
  .summary-kicker {{
    font-size: 10px;
    letter-spacing: 1.1px;
    text-transform: uppercase;
    color: #64748B;
    font-weight: 700;
  }}
  .metric-row {{
    margin: 10px 0 4px 0;
    display: flex;
    align-items: baseline;
    gap: 10px;
  }}
  .metric-big {{
    font-family: Georgia, 'Times New Roman', serif;
    font-size: 38px;
    font-weight: 700;
    color: #0F172A;
    line-height: 1;
  }}
  .metric-sub {{
    font-size: 13px;
    color: #64748B;
    font-weight: 600;
  }}
  .posture-tag {{
    font-size: 12.5px;
    font-weight: 700;
    color: {posture_tone};
    margin-bottom: 10px;
  }}
  .counts-bar {{
    display: flex;
    gap: 12px;
    font-size: 11px;
    color: #374151;
    border-top: 1px solid #E2E8F0;
    padding-top: 10px;
  }}
  .counts-bar span strong {{ color: #0F172A; }}
  .brief-note {{
    font-size: 10.5px;
    line-height: 1.45;
    color: #4B5563;
    margin-top: 8px;
  }}

  .pillars-box {{
    padding-top: 2px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }}
  .section-title {{
    font-size: 10.5px;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    color: #475569;
    font-weight: 700;
    margin-bottom: 10px;
  }}
  .pillar-row {{ margin-bottom: 7px; }}
  .pillar-meta {{
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    margin-bottom: 4px;
  }}
  .pillar-name {{ font-weight: 600; color: #1E293B; }}
  .pillar-stat {{ font-weight: 600; font-size: 11.5px; }}
  .track {{
    width: 100%;
    height: 6px;
    background: #E2E8F0;
    overflow: hidden;
  }}
  .fill {{ height: 100%; }}

  .findings-section {{ margin-top: 10px; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 10.5px;
  }}
  th {{
    text-align: left;
    font-size: 9.5px;
    letter-spacing: 0.9px;
    text-transform: uppercase;
    color: #64748B;
    border-bottom: 1.5px solid #0F172A;
    padding: 4px 8px 5px 0;
  }}
  td {{
    border-bottom: 1px solid #E5E7EB;
    padding: 5.5px 10px 5.5px 0;
    vertical-align: top;
    line-height: 1.32;
  }}
  .col-id {{ width: 124px; }}
  .col-title {{ width: 432px; }}
  .col-impact {{ color: #374151; font-size: 10.3px; }}
  .code-id {{
    font-family: Consolas, 'Courier New', monospace;
    font-size: 10px;
    color: #64748B;
    margin-top: 3px;
  }}
  .ev {{ color: #4B5563; font-size: 10px; margin-top: 2px; line-height: 1.3; }}
  .pill-priority {{
    display: inline-block;
    padding: 2px 6px;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.5px;
    color: #991B1B;
    background: #FEF2F2;
    border: 1px solid #FECACA;
  }}
  .pill-advisory {{
    display: inline-block;
    padding: 2px 6px;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.5px;
    color: #92400E;
    background: #FFFBEB;
    border: 1px solid #FDE68A;
  }}

  .footer {{
    border-top: 1px solid #E5E7EB;
    padding-top: 8px;
    display: flex;
    justify-content: space-between;
    font-size: 9.5px;
    color: #6B7280;
  }}
</style>
</head>
<body>
  <div>
    <div class="header">
      <div class="header-brand">
        <div class="brand-mark">{_SENTINEL_HEADER_SVG}</div>
        <div>
          <div class="eyebrow">Sentinel &middot; External Technical, Email &amp; Privacy Briefing</div>
          <h1>{domain}</h1>
        </div>
      </div>
      <div class="header-right">
        <div><strong>Target:</strong> {final_url}</div>
        <div><strong>Observation Date:</strong> {scanned_at} &nbsp;|&nbsp; <strong>Scope:</strong> {total_checks} Passive Public Controls</div>
      </div>
    </div>

    <div class="top-grid">
      <div class="summary-box">
        <div>
          <div class="summary-kicker">Verified Control Coverage</div>
          <div class="metric-row">
            <span class="metric-big">{pass_c}/{total_checks}</span>
            <span class="metric-sub">({score}% weighted index)</span>
          </div>
          <div class="posture-tag">{posture_label}</div>
          <p class="brief-note">
            Based exclusively on a single passive HTTP response, TLS handshake, and public DNS lookup &mdash; identical to a standard visitor browser without active probing.
          </p>
        </div>
        <div class="counts-bar">
          <span><strong>{pass_c}</strong> Verified</span>
          <span>&middot;</span>
          <span><strong>{warn_c}</strong> Advisory</span>
          <span>&middot;</span>
          <span><strong>{fail_c}</strong> Action Needed</span>
        </div>
      </div>

      <div class="pillars-box">
        <div class="section-title">Domain &amp; Privacy Architecture Breakdown</div>
        {''.join(pillars_html_rows)}
      </div>
    </div>

    <div class="findings-section">
      <div class="section-title">Key Technical Observations &amp; Business Impact</div>
      <table>
        <thead>
          <tr>
            <th>Status / Control</th>
            <th>Observed Technical Evidence</th>
            <th>Operational, Deliverability &amp; Regulatory Impact</th>
          </tr>
        </thead>
        <tbody>
          {''.join(gaps_rows)}
        </tbody>
      </table>
    </div>
  </div>

  <div class="footer">
    <span>Kaled Bouchagraoui &middot; Passive Public Observation Only &middot; Technical QA Aid (Not Legal Advice; Liability Capped at Fees Paid)</span>
    <span>Samples &amp; Terms: kaledbouchagraoui7-bot.github.io/medtech-regulatory-compliance-suite</span>
  </div>
</body>
</html>"""


def build_ra_command_center_html(report: dict[str, Any]) -> str:
    """Swiss Editorial Dashboard for RA Operations Command Center (HTML5 -> Edge PDF/PNG)."""
    def _plural(n: Any, singular: str, plural: str) -> str:
        val = int(n or 0)
        return f"{val} {singular if val == 1 else plural}"

    sub_id = html.escape(str(report.get("submission_id", "")))
    prod = html.escape(str(report.get("product_name", "")))
    verdict = html.escape(str(report.get("gate_decision", "")))
    readiness = int(report.get("overall_readiness_score", 0))
    crl_risk = int(report.get("crl_probability_pct", 0))
    up_days = int(report.get("total_upstream_overdue_days", 0))
    ra_days = int(report.get("ra_overdue_days", 0))
    up_cost = int(report.get("upstream_delay_cost_usd", 0))
    crl_cost = int(report.get("premature_filing_crl_cost_usd", 0))
    hrs_saved = float(report.get("manual_hours_saved", 0.0))
    blockers = int(report.get("rtf_blockers_count", 0))

    accent = "#991B1B" if blockers > 0 else "#0F766E"

    sla_rows = []
    for d in report.get("dept_delay_summary", []):
        od = int(d.get("overdue_days", 0))
        comp = int(d.get("completeness_pct", 0))
        bar_c = "#991B1B" if od > 7 else ("#B45309" if od > 0 else "#0F766E")
        dept_esc = html.escape(str(d.get("department", "")))
        status_esc = html.escape(str(d.get("status", "")))
        sla_rows.append(
            f"""
            <tr>
              <td><strong>{dept_esc}</strong><div class="sub">{html.escape(str(d.get('package_id', '')))} &middot; {html.escape(str(d.get('module_ref', '')))}</div></td>
              <td><span class="tag" style="color:{bar_c};border-color:{bar_c};">{status_esc}</span></td>
              <td style="text-align:right;font-weight:700;color:{bar_c};">{od}d ({d.get('delay_share_pct', 0)}%)</td>
              <td style="text-align:right;font-weight:600;">{comp}%</td>
            </tr>
            """
        )

    xc = report.get("xchk_counts", {})
    dc = report.get("drift_counts", {})

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<style>
  @page {{ size: 11.4in 7.8in; margin: 0; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    width: 1140px;
    height: 780px;
    padding: 32px 42px 26px 42px;
    background: #FFFFFF;
    color: #111827;
    font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }}
  .header {{
    border-bottom: 2px solid #0F172A;
    padding-bottom: 10px;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
  }}
  .header-brand {{
    display: flex;
    align-items: center;
    gap: 12px;
  }}
  .brand-mark {{
    flex: 0 0 auto;
    line-height: 0;
  }}
  .eyebrow {{ font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase; color: #0F766E; font-weight: 700; }}
  h1 {{ margin: 3px 0 0 0; font-family: Georgia, serif; font-size: 19px; line-height: 1.25; color: #0F172A; }}
  .verdict-strip {{
    margin-top: 12px;
    padding: 10px 14px;
    background: #F8FAFC;
    border-left: 4px solid {accent};
    border-top: 1px solid #E2E8F0;
    border-right: 1px solid #E2E8F0;
    border-bottom: 1px solid #E2E8F0;
    display: flex;
    justify-content: space-between;
    font-size: 11.5px;
  }}
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin-top: 14px;
  }}
  .kpi {{
    background: #FFFFFF;
    border: 1px solid #E2E8F0;
    padding: 12px 14px;
  }}
  .kpi-lbl {{ font-size: 9.5px; text-transform: uppercase; letter-spacing: 0.9px; color: #64748B; font-weight: 700; }}
  .kpi-val {{ font-family: Georgia, serif; font-size: 24px; font-weight: 700; color: #0F172A; margin: 4px 0; }}
  .kpi-note {{ font-size: 10px; color: #4B5563; }}

  .main-grid {{
    display: grid;
    grid-template-columns: 1.45fr 1fr;
    gap: 24px;
    margin-top: 16px;
  }}
  .sec-title {{ font-size: 10.5px; text-transform: uppercase; letter-spacing: 1.1px; color: #475569; font-weight: 700; margin-bottom: 8px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 10.5px; }}
  th {{ text-align: left; font-size: 9px; text-transform: uppercase; color: #64748B; border-bottom: 1.5px solid #0F172A; padding: 5px 4px; }}
  td {{ border-bottom: 1px solid #E5E7EB; padding: 7px 4px; vertical-align: middle; }}
  .sub {{ font-size: 9.5px; color: #64748B; margin-top: 1px; }}
  .tag {{ font-size: 9px; font-weight: 700; padding: 2px 6px; border: 1px solid; background: #FFF; }}

  .right-col {{ display: flex; flex-direction: column; gap: 12px; }}
  .stat-card {{
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    padding: 12px 14px;
  }}
  .stat-line {{
    display: flex;
    justify-content: space-between;
    font-size: 11px;
    padding: 4px 0;
    border-bottom: 1px solid #E2E8F0;
  }}
  .stat-line:last-child {{ border-bottom: none; }}
  .footer {{
    border-top: 1px solid #E5E7EB;
    padding-top: 8px;
    display: flex;
    justify-content: space-between;
    font-size: 9.5px;
    color: #6B7280;
  }}
</style>
</head>
<body>
  <div>
    <div class="header">
      <div class="header-brand">
        <div class="brand-mark">{_SENTINEL_HEADER_SVG}</div>
        <div>
          <div class="eyebrow">Sentinel RA &middot; Regulatory Affairs Operations &amp; Submission Telemetry</div>
          <h1>{sub_id} &mdash; {html.escape(_humanize_finding_note(str(report.get('product_name', '')), 96))}</h1>
        </div>
      </div>
      <div style="text-align:right;font-size:10.5px;color:#4B5563;white-space:nowrap;">
        <div><strong>Vertical:</strong> {html.escape(str(report.get('vertical', 'medtech_ra')))}</div>
        <div><strong>Evaluation Date:</strong> {html.escape(str(report.get('evaluation_date', '')))}</div>
      </div>
    </div>

    <div class="verdict-strip">
      <span><strong style="color:{accent};">GATEKEEPER VERDICT:</strong> {verdict}</span>
      <span><strong>RTF / CRL Risk:</strong> {crl_risk}% ({blockers} active blockers)</span>
    </div>

    <div class="kpi-grid">
      <div class="kpi">
        <div class="kpi-lbl">Dossier Readiness</div>
        <div class="kpi-val">{readiness}/100</div>
        <div class="kpi-note">Combined SLA + Cross-Check + Guidance</div>
      </div>
      <div class="kpi">
        <div class="kpi-lbl">RA vs. Upstream Delay</div>
        <div class="kpi-val" style="color:#0F766E;">{ra_days}d <span style="font-size:15px;color:#64748B;">/ {up_days}d</span></div>
        <div class="kpi-note">RA Core Team 100% On-SLA ({up_days}d upstream)</div>
      </div>
      <div class="kpi">
        <div class="kpi-lbl">CRL Cost Shielded</div>
        <div class="kpi-val">${crl_cost:,.0f}</div>
        <div class="kpi-note">${up_cost:,.0f} upstream burn already logged</div>
      </div>
      <div class="kpi">
        <div class="kpi-lbl">Manual QA Hours Saved</div>
        <div class="kpi-val">{hrs_saved} hrs</div>
        <div class="kpi-note">Automated cross-checks &amp; chaser briefs</div>
      </div>
    </div>

    <div class="main-grid">
      <div>
        <div class="sec-title">1. Departmental SLA &amp; Critical-Path Delay Attribution</div>
        <table>
          <thead><tr><th>Department / Package</th><th>Status</th><th style="text-align:right;">Delay Share</th><th style="text-align:right;">Completeness</th></tr></thead>
          <tbody>{''.join(sla_rows)}</tbody>
        </table>
      </div>
      <div class="right-col">
        <div class="stat-card">
          <div class="sec-title" style="margin-bottom:6px;">2. eCTD Modules 1&ndash;5 Cross-Check Linter</div>
          <div class="stat-line"><span>Reconciled Across Modules (PASS)</span><strong style="color:#0F766E;">{_plural(xc.get('PASS', 0), 'check', 'checks')}</strong></div>
          <div class="stat-line"><span>Technical Formatting Warnings (WARN)</span><strong style="color:#B45309;">{_plural(xc.get('WARN', 0), 'check', 'checks')}</strong></div>
          <div class="stat-line"><span>Blocking Numerical / Lot Mismatches (FAIL)</span><strong style="color:#991B1B;">{_plural(xc.get('FAIL', 0), 'check', 'checks')}</strong></div>
        </div>
        <div class="stat-card">
          <div class="sec-title" style="margin-bottom:6px;">3. Global Agency Guidance Drift Radar</div>
          <div class="stat-line"><span>Compliant Frameworks (MDCG / ICH E6(R3))</span><strong style="color:#0F766E;">{dc.get('COMPLIANT', 0)} active</strong></div>
          <div class="stat-line"><span>Minor SOP Alignment Needed (MHRA)</span><strong style="color:#B45309;">{dc.get('REVIEW_NEEDED', 0)} active</strong></div>
          <div class="stat-line"><span>Mid-Stream Blocking Gaps (FDA 524B / PCCP)</span><strong style="color:#991B1B;">{dc.get('GAP_DETECTED', 0)} active</strong></div>
        </div>
      </div>
    </div>
  </div>

  <div class="footer">
    <span>RA Command Center &middot; Automated QA Aid Only (Qualified RA/PRRC Sign-Off Required; Liability Capped at Fees Paid)</span>
    <span>Samples &amp; Terms: kaledbouchagraoui7-bot.github.io/medtech-regulatory-compliance-suite</span>
  </div>
</body>
</html>"""
