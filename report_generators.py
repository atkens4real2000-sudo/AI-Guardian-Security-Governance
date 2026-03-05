"""
Report Generation Module for AI Guardian Toolkit.

Generates three report formats from assessment data:
- HTML executive dashboard (self-contained, no external dependencies)
- Markdown technical report
- JSON export

All generators receive assessment data as plain dicts (from assessment.to_dict())
to avoid circular imports. This module does NOT import from assessment_engine.py.

Usage:
    from report_generators import generate_all_reports
    paths = generate_all_reports(assessment_data, output_dir="./reports")
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from ai_frameworks import OWASP_LLM_TOP_10, get_framework_summary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe(value, default="N/A"):
    """Return *value* if truthy, otherwise *default*."""
    return value if value else default


def _severity_color(severity: str) -> str:
    """Map severity string to a CSS colour."""
    s = (severity or "").upper()
    return {"HIGH": "#e94560", "MEDIUM": "#f39c12", "LOW": "#2ecc71"}.get(s, "#aaa")


def _tier_color(tier: str) -> str:
    """Map EU AI Act tier to badge colour."""
    t = (tier or "").upper()
    return {
        "UNACCEPTABLE": "#e94560",
        "HIGH": "#e07020",
        "LIMITED": "#f39c12",
        "MINIMAL": "#2ecc71",
    }.get(t, "#888")


def _grade_color(grade: str) -> str:
    """Map letter grade to a CSS colour."""
    g = (grade or "F")[0].upper()
    return {
        "A": "#2ecc71", "B": "#27ae60", "C": "#f39c12",
        "D": "#e07020", "F": "#e94560",
    }.get(g, "#e94560")


def _score_color(score: float) -> str:
    """Return a CSS colour for a 0-100 risk score."""
    if score <= 30:
        return "#2ecc71"
    if score <= 60:
        return "#f39c12"
    return "#e94560"


def _escape_html(text: str) -> str:
    """Minimal HTML entity escaping."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# HTML Report Generator
# ---------------------------------------------------------------------------

class HTMLReportGenerator:
    """Generate a self-contained HTML executive dashboard report."""

    def generate(self, assessment_data: Dict, output_path: str) -> str:
        """Generate HTML executive dashboard report. Returns *output_path*."""
        d = assessment_data
        meta = d.get("metadata") or {}
        risk = d.get("risk_classification") or {}
        red_team = d.get("red_team_results") or {}
        compliance = d.get("compliance_results") or {}
        gaps = d.get("priority_gaps") or []
        doc_audit = d.get("documentation_audit") or {}
        remediation = d.get("remediation_roadmap") or []

        org = _safe(meta.get("organization"), "Unknown Organization")
        system = _safe(meta.get("system_name"), "AI System")
        date = _safe(meta.get("assessment_date"), datetime.now().strftime("%Y-%m-%d"))
        assessor = _safe(meta.get("assessor"), "AI Guardian")
        tier = _safe(risk.get("tier"), "UNKNOWN")
        overall_score = risk.get("overall_risk_score", 0)
        security_grade = _safe(risk.get("security_posture_grade"), "N/A")
        vuln_count = red_team.get("total_vulnerabilities", 0)
        high_sev = red_team.get("high_severity_count", 0)
        med_sev = red_team.get("medium_severity_count", 0)
        low_sev = red_team.get("low_severity_count", 0)
        comp_score = compliance.get("overall_compliance_pct", 0)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Guardian Assessment Report &mdash; {_escape_html(org)}</title>
<style>
/* ---- Base ---- */
*,*::before,*::after{{box-sizing:border-box}}
body{{margin:0;padding:0;background:#1a1a2e;color:#eee;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;line-height:1.6}}
.container{{max-width:1200px;margin:0 auto;padding:20px}}
h1,h2,h3{{margin-top:0}}
a{{color:#3498db}}
code,pre,.mono{{font-family:'Cascadia Code','Fira Code','Consolas',monospace}}

/* ---- Header ---- */
.header{{text-align:center;padding:40px 20px 20px;border-bottom:2px solid #333}}
.header h1{{font-size:2rem;margin-bottom:4px;color:#fff}}
.header .sub{{color:#aaa;font-size:0.95rem}}

/* ---- Tier Badge ---- */
.tier-badge{{display:inline-block;padding:12px 36px;border-radius:8px;font-size:1.6rem;font-weight:700;margin:20px 0;letter-spacing:1px;color:#fff;background:{_tier_color(tier)}}}

/* ---- Cards Row ---- */
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin:24px 0}}
.card{{background:#16213e;border-radius:10px;padding:20px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.4)}}
.card .label{{color:#aaa;font-size:0.85rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}}
.card .value{{font-size:2.2rem;font-weight:700}}
.card .detail{{color:#aaa;font-size:0.8rem;margin-top:4px}}

/* ---- Section ---- */
.section{{background:#16213e;border-radius:10px;padding:24px;margin:24px 0;box-shadow:0 2px 8px rgba(0,0,0,0.3)}}
.section h2{{border-bottom:1px solid #333;padding-bottom:8px;margin-bottom:16px;color:#fff}}
.collapsible-toggle{{cursor:pointer;user-select:none}}
.collapsible-toggle::before{{content:'\\25BC ';font-size:0.75em}}
.collapsible-toggle.collapsed::before{{content:'\\25B6 '}}
.collapsible-body.hidden{{display:none}}

/* ---- Table ---- */
table{{width:100%;border-collapse:collapse;margin-top:12px}}
th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid #2a2a4a}}
th{{background:#0f3460;color:#fff;font-size:0.85rem;text-transform:uppercase;letter-spacing:0.5px}}
tr:hover{{background:rgba(52,152,219,0.08)}}
.badge{{display:inline-block;padding:2px 10px;border-radius:4px;font-size:0.78rem;font-weight:600;color:#fff}}

/* ---- Filter Buttons ---- */
.filters{{margin-bottom:12px}}
.filters button{{background:#0f3460;color:#eee;border:1px solid #333;padding:6px 16px;border-radius:4px;cursor:pointer;margin-right:6px;font-size:0.82rem}}
.filters button.active{{background:#3498db;border-color:#3498db;color:#fff}}
.filters button:hover{{opacity:0.85}}

/* ---- Compliance Grid ---- */
.comp-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}}
.comp-card{{background:#0f3460;border-radius:8px;padding:16px;text-align:center}}
.comp-card .pct{{font-size:2rem;font-weight:700}}
.comp-card .fname{{color:#aaa;font-size:0.85rem;margin-top:4px}}

/* ---- Gap List ---- */
.gap-item{{background:#0f3460;border-radius:8px;padding:14px 18px;margin-bottom:10px}}
.gap-item .gap-head{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap}}
.gap-item .gap-head .ctrl{{font-weight:600;color:#3498db;margin-right:8px}}

/* ---- Roadmap ---- */
.road-item{{background:#0f3460;border-radius:8px;padding:14px 18px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap}}
.effort{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;color:#fff}}

/* ---- Footer ---- */
.footer{{text-align:center;padding:30px 20px;color:#666;font-size:0.82rem;border-top:1px solid #2a2a4a;margin-top:30px}}

/* ---- Print ---- */
@media print{{
  body{{background:#fff;color:#111}}
  .card,.section,.comp-card,.gap-item,.road-item{{background:#f5f5f5;box-shadow:none;border:1px solid #ddd}}
  th{{background:#ddd;color:#111}}
  .filters{{display:none}}
  .tier-badge{{border:2px solid #333}}
  .footer{{color:#555}}
}}
</style>
</head>
<body>
<div class="container">

<!-- HEADER -->
<div class="header">
<h1>AI Guardian Assessment Report</h1>
<p class="sub">{_escape_html(org)} &mdash; {_escape_html(system)}</p>
<p class="sub">Date: {_escape_html(date)} &nbsp;|&nbsp; Assessor: {_escape_html(assessor)}</p>
<div><span class="tier-badge">{_escape_html(tier)} RISK</span></div>
</div>

<!-- SCORE CARDS -->
<div class="cards">
  <div class="card">
    <div class="label">Overall Risk Score</div>
    <div class="value mono" style="color:{_score_color(overall_score)}">{overall_score}</div>
    <div class="detail">out of 100</div>
  </div>
  <div class="card">
    <div class="label">Security Posture</div>
    <div class="value" style="color:{_grade_color(security_grade)}">{_escape_html(security_grade)}</div>
    <div class="detail">grade</div>
  </div>
  <div class="card">
    <div class="label">Vulnerabilities Found</div>
    <div class="value mono" style="color:{'#e94560' if vuln_count else '#2ecc71'}">{vuln_count}</div>
    <div class="detail">H:{high_sev} M:{med_sev} L:{low_sev}</div>
  </div>
  <div class="card">
    <div class="label">Compliance Score</div>
    <div class="value mono" style="color:{_score_color(100 - comp_score)}">{comp_score}%</div>
    <div class="detail">across all frameworks</div>
  </div>
</div>

{self._build_owasp_section(red_team)}
{self._build_compliance_section(compliance)}
{self._build_gaps_section(gaps)}
{self._build_doc_audit_section(doc_audit)}
{self._build_roadmap_section(remediation)}

<!-- FOOTER -->
<div class="footer">
  Generated by <strong>AI Guardian</strong> | AI Security &amp; Governance Assessment Toolkit | Author: Akintade Akinokun
</div>

</div><!-- /container -->

<!-- JAVASCRIPT -->
<script>
/* Filter buttons for OWASP table */
(function(){{
  var btns=document.querySelectorAll('.filters button[data-filter]');
  btns.forEach(function(btn){{
    btn.addEventListener('click',function(){{
      var filter=this.getAttribute('data-filter');
      btns.forEach(function(b){{b.classList.remove('active')}});
      this.classList.add('active');
      var rows=document.querySelectorAll('#owasp-table tbody tr');
      rows.forEach(function(row){{
        if(filter==='all'){{row.style.display=''}}
        else if(filter==='vuln'){{row.style.display=row.getAttribute('data-vuln')==='yes'?'':'none'}}
        else if(filter==='pass'){{row.style.display=row.getAttribute('data-vuln')==='no'?'':'none'}}
      }});
    }});
  }});
}})();

/* Collapsible sections */
(function(){{
  document.querySelectorAll('.collapsible-toggle').forEach(function(el){{
    el.addEventListener('click',function(){{
      this.classList.toggle('collapsed');
      var body=this.nextElementSibling;
      if(body)body.classList.toggle('hidden');
    }});
  }});
}})();
</script>
</body>
</html>"""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return output_path

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------

    def _build_owasp_section(self, red_team: Dict) -> str:
        """Build OWASP Top 10 results table with filter buttons."""
        suite_results = red_team.get("suite_results", {})
        if not suite_results:
            return ""

        rows = ""
        for owasp_id in sorted(suite_results.keys()):
            sr = suite_results[owasp_id]
            owasp_info = OWASP_LLM_TOP_10.get(owasp_id, {})
            name = _escape_html(owasp_info.get("name", owasp_id))
            total = sr.get("total_attacks", 0)
            vulns = sr.get("successful_attacks", 0)
            severity = owasp_info.get("severity", "MEDIUM")
            passed = "FAIL" if vulns > 0 else "PASS"
            vuln_flag = "yes" if vulns > 0 else "no"
            status_color = "#e94560" if vulns > 0 else "#2ecc71"
            sev_color = _severity_color(severity)

            rows += (
                f'<tr data-vuln="{vuln_flag}">'
                f'<td class="mono">{owasp_id}</td>'
                f'<td>{name}</td>'
                f'<td class="mono">{total}</td>'
                f'<td class="mono">{vulns}</td>'
                f'<td><span class="badge" style="background:{sev_color}">{severity}</span></td>'
                f'<td><span class="badge" style="background:{status_color}">{passed}</span></td>'
                f'</tr>\n'
            )

        return f"""
<!-- OWASP RESULTS -->
<div class="section">
<h2 class="collapsible-toggle">OWASP LLM Top 10 &mdash; Red Team Results</h2>
<div class="collapsible-body">
<div class="filters">
  <button data-filter="all" class="active">Show All</button>
  <button data-filter="vuln">Vulnerable Only</button>
  <button data-filter="pass">Passed Only</button>
</div>
<table id="owasp-table">
<thead><tr><th>ID</th><th>Category</th><th>Attacks</th><th>Vulns</th><th>Severity</th><th>Status</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</div>
</div>"""

    def _build_compliance_section(self, compliance: Dict) -> str:
        """Build compliance scorecard with 4-column layout."""
        frameworks = compliance.get("framework_scores", {})
        if not frameworks:
            return ""

        cards = ""
        for fw_name, pct in frameworks.items():
            pct_val = pct if isinstance(pct, (int, float)) else 0
            color = _score_color(100 - pct_val)
            cards += (
                f'<div class="comp-card">'
                f'<div class="pct mono" style="color:{color}">{pct_val}%</div>'
                f'<div class="fname">{_escape_html(fw_name)}</div>'
                f'</div>\n'
            )

        return f"""
<!-- COMPLIANCE SCORECARD -->
<div class="section">
<h2 class="collapsible-toggle">Compliance Scorecard</h2>
<div class="collapsible-body">
<div class="comp-grid">
{cards}
</div>
</div>
</div>"""

    def _build_gaps_section(self, gaps: List) -> str:
        """Build top priority gaps section."""
        if not gaps:
            return ""

        items = ""
        for i, gap in enumerate(gaps[:10], start=1):
            fw = _escape_html(_safe(gap.get("framework"), ""))
            ctrl = _escape_html(_safe(gap.get("control_id"), ""))
            desc = _escape_html(_safe(gap.get("description"), ""))
            sev = _safe(gap.get("severity"), "MEDIUM").upper()
            remediation = _escape_html(_safe(gap.get("remediation"), ""))
            sev_color = _severity_color(sev)
            items += (
                f'<div class="gap-item">'
                f'<div class="gap-head">'
                f'<div><strong>#{i}</strong> <span class="ctrl">[{fw}] {ctrl}</span></div>'
                f'<span class="badge" style="background:{sev_color}">{sev}</span>'
                f'</div>'
                f'<p style="margin:6px 0 2px;color:#ccc">{desc}</p>'
                f'<p style="margin:2px 0;color:#888;font-size:0.85rem"><em>Remediation:</em> {remediation}</p>'
                f'</div>\n'
            )

        return f"""
<!-- TOP PRIORITY GAPS -->
<div class="section">
<h2 class="collapsible-toggle">Top Priority Gaps</h2>
<div class="collapsible-body">
{items}
</div>
</div>"""

    def _build_doc_audit_section(self, doc_audit: Dict) -> str:
        """Build documentation findings table."""
        findings = doc_audit.get("findings", [])
        if not findings:
            return ""

        rows = ""
        status_colors = {
            "ADEQUATE": "#2ecc71",
            "PARTIAL": "#f39c12",
            "INADEQUATE": "#e94560",
        }
        for f in findings:
            question = _escape_html(_safe(f.get("question"), ""))
            response = _escape_html(_safe(f.get("response"), ""))
            status = _safe(f.get("assessment") or f.get("status"), "UNKNOWN").upper()
            sc = status_colors.get(status, "#aaa")
            rows += (
                f'<tr>'
                f'<td>{question}</td>'
                f'<td style="max-width:400px">{response}</td>'
                f'<td><span class="badge" style="background:{sc}">{status}</span></td>'
                f'</tr>\n'
            )

        return f"""
<!-- DOCUMENTATION FINDINGS -->
<div class="section">
<h2 class="collapsible-toggle">Documentation Audit Findings</h2>
<div class="collapsible-body">
<table>
<thead><tr><th>Question</th><th>Response</th><th>Status</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</div>
</div>"""

    def _build_roadmap_section(self, remediation: List) -> str:
        """Build remediation roadmap section."""
        if not remediation:
            return ""

        effort_colors = {
            "LOW": "#2ecc71", "MEDIUM": "#f39c12", "HIGH": "#e94560",
        }
        impact_colors = {
            "HIGH": "#2ecc71", "MEDIUM": "#f39c12", "LOW": "#888",
        }

        items = ""
        for i, action in enumerate(remediation, start=1):
            desc = _escape_html(_safe(action.get("action"), ""))
            effort = _safe(action.get("effort"), "MEDIUM").upper()
            impact = _safe(action.get("impact"), "MEDIUM").upper()
            ec = effort_colors.get(effort, "#f39c12")
            ic = impact_colors.get(impact, "#f39c12")
            items += (
                f'<div class="road-item">'
                f'<div><strong>#{i}</strong> &nbsp;{desc}</div>'
                f'<div>'
                f'<span class="effort" style="background:{ec}">Effort: {effort}</span> '
                f'<span class="effort" style="background:{ic}">Impact: {impact}</span>'
                f'</div>'
                f'</div>\n'
            )

        return f"""
<!-- REMEDIATION ROADMAP -->
<div class="section">
<h2 class="collapsible-toggle">Remediation Roadmap</h2>
<div class="collapsible-body">
{items}
</div>
</div>"""


# ---------------------------------------------------------------------------
# Markdown Report Generator
# ---------------------------------------------------------------------------

class MarkdownReportGenerator:
    """Generate a detailed Markdown technical report."""

    def generate(self, assessment_data: Dict, output_path: str) -> str:
        """Generate detailed Markdown technical report. Returns *output_path*."""
        d = assessment_data
        meta = d.get("metadata") or {}
        risk = d.get("risk_classification") or {}
        red_team = d.get("red_team_results") or {}
        compliance = d.get("compliance_results") or {}
        gaps = d.get("priority_gaps") or []
        doc_audit = d.get("documentation_audit") or {}
        remediation = d.get("remediation_roadmap") or []

        org = _safe(meta.get("organization"), "Unknown Organization")
        system = _safe(meta.get("system_name"), "AI System")
        date = _safe(meta.get("assessment_date"), datetime.now().strftime("%Y-%m-%d"))
        assessor = _safe(meta.get("assessor"), "AI Guardian")

        lines: List[str] = []
        _a = lines.append

        # Title
        _a(f"# AI Guardian Assessment Report")
        _a(f"**Organization:** {org}  ")
        _a(f"**System:** {system}  ")
        _a(f"**Date:** {date}  ")
        _a(f"**Assessor:** {assessor}")
        _a("")

        # Executive Summary
        _a("## Executive Summary")
        tier = _safe(risk.get("tier"), "UNKNOWN")
        score = risk.get("overall_risk_score", 0)
        grade = _safe(risk.get("security_posture_grade"), "N/A")
        comp_pct = compliance.get("overall_compliance_pct", 0)
        total_vulns = red_team.get("total_vulnerabilities", 0)
        _a(f"The AI system **{system}** operated by **{org}** has been assessed against "
           f"OWASP LLM Top 10, NIST AI RMF, EU AI Act, and ISO/IEC 42001 frameworks.")
        _a("")
        _a(f"| Metric | Value |")
        _a(f"|--------|-------|")
        _a(f"| EU AI Act Risk Tier | **{tier}** |")
        _a(f"| Overall Risk Score | {score} / 100 |")
        _a(f"| Security Posture Grade | {grade} |")
        _a(f"| Vulnerabilities Found | {total_vulns} |")
        _a(f"| Compliance Score | {comp_pct}% |")
        _a("")

        # Risk Classification
        _a("## Risk Classification")
        _a(f"**Tier:** {tier}  ")
        confidence = risk.get("confidence", 0)
        _a(f"**Confidence:** {confidence:.0%}" if isinstance(confidence, float) else f"**Confidence:** {confidence}")
        reasons = risk.get("reasons", [])
        if reasons:
            _a("")
            _a("**Key Factors:**")
            for r in reasons:
                _a(f"- {r}")
        _a("")

        # Red Team Results
        suite_results = red_team.get("suite_results", {})
        if suite_results:
            _a("## Red Team Assessment Results")
            for owasp_id in sorted(suite_results.keys()):
                sr = suite_results[owasp_id]
                owasp_info = OWASP_LLM_TOP_10.get(owasp_id, {})
                name = owasp_info.get("name", owasp_id)
                total = sr.get("total_attacks", 0)
                vulns = sr.get("successful_attacks", 0)
                status = "FAIL" if vulns > 0 else "PASS"
                _a(f"### {owasp_id}: {name}")
                _a(f"- **Attacks Run:** {total}")
                _a(f"- **Vulnerabilities Found:** {vulns}")
                _a(f"- **Status:** {status}")
                individual = sr.get("results", [])
                if individual:
                    vuln_results = [r for r in individual if r.get("success")]
                    if vuln_results:
                        _a("- **Successful Attack Details:**")
                        for vr in vuln_results[:5]:
                            _a(f"  - `{vr.get('attack_name', 'N/A')}` "
                               f"(severity: {vr.get('severity', 'N/A')}, "
                               f"confidence: {vr.get('confidence', 0):.2f}) "
                               f"-- {vr.get('detection_reason', '')}")
                _a("")

        # Compliance Mapping
        fw_scores = compliance.get("framework_scores", {})
        if fw_scores:
            _a("## Compliance Mapping Summary")
            _a("| Framework | Compliance |")
            _a("|-----------|-----------|")
            for fw, pct in fw_scores.items():
                _a(f"| {fw} | {pct}% |")
            _a("")

        # Priority Gaps
        if gaps:
            _a("## Priority Gaps")
            for i, gap in enumerate(gaps[:10], start=1):
                fw = _safe(gap.get("framework"), "")
                ctrl = _safe(gap.get("control_id"), "")
                desc = _safe(gap.get("description"), "")
                sev = _safe(gap.get("severity"), "MEDIUM")
                rem = _safe(gap.get("remediation"), "")
                _a(f"{i}. **[{fw}] {ctrl}** ({sev})  ")
                _a(f"   {desc}  ")
                _a(f"   *Remediation:* {rem}")
            _a("")

        # Documentation Audit
        findings = doc_audit.get("findings", [])
        if findings:
            _a("## Documentation Audit Results")
            _a("| Question | Status |")
            _a("|----------|--------|")
            for f in findings:
                q = _safe(f.get("question"), "")
                st = _safe(f.get("assessment") or f.get("status"), "UNKNOWN")
                _a(f"| {q} | **{st}** |")
            _a("")

        # Recommendations
        if remediation:
            _a("## Recommendations")
            for i, action in enumerate(remediation, start=1):
                desc = _safe(action.get("action"), "")
                effort = _safe(action.get("effort"), "MEDIUM")
                impact = _safe(action.get("impact"), "MEDIUM")
                _a(f"{i}. {desc} *(Effort: {effort}, Impact: {impact})*")
            _a("")

        # Footer
        _a("---")
        _a("*Generated by AI Guardian | AI Security & Governance Assessment Toolkit | Author: Akintade Akinokun*")

        content = "\n".join(lines) + "\n"
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return output_path


# ---------------------------------------------------------------------------
# JSON Exporter
# ---------------------------------------------------------------------------

class JSONExporter:
    """Export full assessment data as formatted JSON."""

    def generate(self, assessment_data: Dict, output_path: str) -> str:
        """Export full assessment data as formatted JSON. Returns *output_path*."""
        export = {
            "export_metadata": {
                "generator": "AI Guardian",
                "author": "Akintade Akinokun",
                "export_date": datetime.now().isoformat(),
                "framework_summary": get_framework_summary(),
            },
            "assessment": assessment_data,
        }
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(export, fh, indent=2, default=str)
        return output_path


# ---------------------------------------------------------------------------
# Factory / convenience function
# ---------------------------------------------------------------------------

def _normalize_assessment_data(raw: Dict) -> Dict:
    """Normalize flat ``GuardianAssessment.to_dict()`` output into the
    nested structure the report generators expect.

    If the data already contains a ``metadata`` key it is returned as-is.
    """
    if "metadata" in raw:
        return raw  # already in expected format

    # Build nested structure from flat to_dict() output
    gm = raw.get("governance_mapping") or {}
    rt = raw.get("red_team_results") or {}

    # Compliance scores — prefer top-level, fallback to governance mapping
    comp_scores = raw.get("compliance_scores") or {}
    overall_comp = sum(comp_scores.values()) / len(comp_scores) if comp_scores else 0

    # Priority gaps from governance mapping
    priority_gaps = gm.get("priority_gaps", [])

    # Documentation findings
    doc_findings = raw.get("documentation_findings", [])

    return {
        "metadata": {
            "organization": raw.get("organization", ""),
            "system_name": raw.get("system_name", ""),
            "assessment_date": raw.get("created_at", ""),
            "assessor": raw.get("assessor", ""),
            "assessment_mode": raw.get("assessment_mode", "docs"),
            "assessment_id": raw.get("assessment_id", ""),
        },
        "risk_classification": {
            "tier": (raw.get("risk_classification") or {}).get("tier", "UNKNOWN"),
            "confidence": (raw.get("risk_classification") or {}).get("confidence", 0),
            "overall_risk_score": raw.get("overall_risk_score", 0),
            "security_posture_grade": raw.get("security_posture_grade", "N/A"),
            "reasons": (raw.get("risk_classification") or {}).get("reasons", []),
            "obligations": (raw.get("risk_classification") or {}).get("obligations", []),
        },
        "red_team_results": rt if rt else {},
        "compliance_results": {
            "overall_compliance_pct": round(overall_comp, 1),
            "framework_scores": comp_scores,
        },
        "priority_gaps": priority_gaps,
        "documentation_audit": {
            "findings": doc_findings,
            "total": len(doc_findings),
        },
        "remediation_roadmap": [],
        "governance_mapping": gm,
    }


def generate_all_reports(assessment_data: Dict, output_dir: str) -> Dict[str, str]:
    """Generate all report formats. Returns ``{format: filepath}``."""
    os.makedirs(output_dir, exist_ok=True)

    data = _normalize_assessment_data(assessment_data)
    meta = data.get("metadata", {})
    org_slug = (meta.get("organization") or "report").replace(" ", "_").lower()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"ai_guardian_{org_slug}_{timestamp}"

    html_path = os.path.join(output_dir, f"{base}.html")
    md_path = os.path.join(output_dir, f"{base}.md")
    json_path = os.path.join(output_dir, f"{base}.json")

    paths: Dict[str, str] = {}
    paths["html"] = HTMLReportGenerator().generate(data, html_path)
    paths["markdown"] = MarkdownReportGenerator().generate(data, md_path)
    paths["json"] = JSONExporter().generate(data, json_path)

    return paths
