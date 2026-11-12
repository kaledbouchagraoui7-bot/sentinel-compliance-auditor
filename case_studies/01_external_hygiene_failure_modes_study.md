# Technical Note 01: Common Passive External Compliance & Email Deliverability Failure Modes in Regulated Sectors

**Standards Referenced:** RFC 7489 (DMARC) · RFC 7208 (SPF) · RFC 8659 (CAA) · RFC 9116 (`security.txt`) · Swiss nFADP Art. 8 & 16–19 · EU GDPR · European Accessibility Act (EAA / WCAG 2.1 AA)  
**Audit Engine:** [`../sentinel_scanner.py`](../sentinel_scanner.py)  

---

## 1. Purpose & Non-Intrusive Scope

Regulated European SMEs (MedTech manufacturers, CROs, diagnostics labs, and legal/fiduciary practices) frequently pass internal quality paperwork while failing simple, publicly observable external hygiene checks. This technical note documents the **four highest-impact failure modes** observed in passive external reviews — strictly anonymized (zero named private organizations) and reproducibly detectable using read-only DNS-over-HTTPS and standard HTTPS GET requests.

---

## 2. Four High-Friction External Failure Modes

### 2.1 Silent Email Rejection via RFC 7208 `PermError` (`>10` SPF Lookups)

- **Mechanism:** Under RFC 7208 §4.6.4, receiving mail exchangers (Google Workspace, Microsoft 365, Swiss banking/hospital gateways) **must abort SPF evaluation with `PermError`** if resolving `include:`, `a`, `mx`, `ptr`, or `redirect=` requires more than **10 DNS-querying mechanisms**.
- **Typical Root Cause:** Stacking marketing, CRM, ticketing, invoicing, and HR SaaS tools (e.g., HubSpot + Zendesk + Mailchimp + Salesforce + M365) without flattening mechanisms. Real-world MedTech portals routinely reach `11–20` recursive lookups.
- **Deterministic Remediation:** Flatten static third-party `include:` blocks, prune retired vendors, and monitor lookup budget (`<= 8` lookups) via `sentinel_scanner.py`.

### 2.2 Unenforced DMARC (`p=none` or Missing `_dmarc`) Combined with Missing `CAA`

- **Mechanism:** Without `_dmarc.<domain>` set to `p=quarantine` or `p=reject`, third parties can spoof executive or accounting domains for Business Email Compromise (BEC) invoice fraud. Missing DNS `CAA` records similarly fail to restrict which Certificate Authorities may issue TLS certificates for the domain.
- **Safe Rollout Progression:** Audit third-party DKIM/SPF alignment under `p=none` telemetry (`rua=`) first, then step up `p=quarantine; pct=25 -> 100` before enforcing `p=reject`. Automated scripts should **never** push `p=reject` blindly without confirming ERP/CRM mailer DKIM alignment.

### 2.3 Pre-Consent Third-Party Asset Transfers & Non-Symmetric Cookie Banners

- **Mechanism:** Loading remote third-party fonts (`fonts.googleapis.com`) or analytics/ad pixels before explicit opt-in leaks visitor IP addresses internationally — triggering Swiss **nFADP Art. 16–19** and EU **GDPR** jurisprudence (e.g., *LG München I, 3 O 17493/20*). Additionally, cookie banners lacking an equally prominent first-layer **"Reject All / Necessary Only"** action fail CNIL and FDPIC symmetry guidance.
- **Deterministic Fix:** Self-host static WOFF2 font subsets locally under `Same-Origin` and gate third-party tags behind first-layer opt-in consent.

### 2.4 Missing `/.well-known/security.txt` (RFC 9116) & Missing HTTP Edge Headers

- **Mechanism:** Missing `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options: nosniff`, or RFC 9116 vulnerability contact metadata slows vendor security due-diligence questionnaires and medical-device procurement onboarding.

---

## 3. Passive Verification vs. Human Architecture Judgment

| Check | Safe to Verify Passively (`sentinel_scanner.py`) | Requires Human IT / DPO / Legal Judgment |
|---|---|---|
| **SPF `<= 10` DNS lookups & DMARC tag syntax** | Exact recursive lookup count & TXT policy string | Confirming legacy billing/ERP servers before switching `p=none -> p=reject` |
| **Remote fonts / pre-consent tracker DOM requests** | Presence of external script/stylesheet URLs on initial load | Evaluating legal basis, DPA adequacy, and internal CMP JavaScript callbacks |
| **HTTP TLS & edge security headers** | Header presence/absence on public apex response | Testing strict `CSP` directives against live portals to avoid breaking scripts |
