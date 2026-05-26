import json
import logging
import os
from datetime import datetime

from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


import re

class ReporterAgent(BaseAgent):
    def __init__(self):
        super().__init__("reporter")

    @staticmethod
    def _md_to_html(text: str) -> str:
        if not text:
            return ""
        html = text
        # Escape HTML chars
        html = html.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        lines = html.split("\n")
        out = []
        in_list = False
        for line in lines:
            # Standalone **Header** on its own line
            sh = re.match(r"^\*\*(.+?)\*\*$", line)
            if sh:
                if in_list: out.append("</ul>"); in_list = False
                out.append(f"<h2>{sh.group(1)}</h2>")
                continue
            # # headers
            hm = re.match(r"^(#{1,3})\s+(.+)$", line)
            if hm:
                if in_list: out.append("</ul>"); in_list = False
                tag = "h3" if len(hm.group(1)) == 3 else "h2"
                out.append(f"<{tag}>{hm.group(2)}</{tag}>")
                continue
            # Inline bold/italic
            line = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", line)
            line = re.sub(r"\*(.+?)\*", r"<em>\1</em>", line)
            # Bullet
            bm = re.match(r"^[\s]*[-*]\s+(.*)", line)
            if bm:
                if not in_list: out.append("<ul>"); in_list = True
                out.append(f"<li>{bm.group(1)}</li>")
            else:
                if in_list: out.append("</ul>"); in_list = False
                if line.strip() == "":
                    out.append("</p><p>")
                else:
                    out.append(line)
        if in_list: out.append("</ul>")
        return "<p>" + "".join(out) + "</p>"

    def run(self, context: dict) -> dict:
        os.makedirs(REPORT_DIR, exist_ok=True)

        findings = context.get("findings", [])
        summary = context.get("summary", {})
        exec_summary = context.get("executive_summary", "")
        enum_data = context.get("enumeration", {})

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(REPORT_DIR, f"vboxaudit_{timestamp}.json")
        html_path = os.path.join(REPORT_DIR, f"vboxaudit_{timestamp}.html")
        pdf_path = os.path.join(REPORT_DIR, f"vboxaudit_{timestamp}.pdf")

        report = {
            "generated_at": datetime.now().isoformat(),
            "tool": "VBoxAuditor",
            "executive_summary": exec_summary,
            "summary": summary,
            "findings": findings,
            "environment": {
                "vm_count": len(enum_data.get("vms", [])),
                "running_vms": enum_data.get("running_vms", []),
            },
        }

        self.emit_thinking("Generating JSON report...")
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)
        self.emit_output(f"JSON report saved")

        self.emit_thinking("Generating HTML report...")
        html = self._build_html_report(report)
        with open(html_path, "w") as f:
            f.write(html)
        self.emit_output(f"HTML report saved")

        self.emit_thinking("Generating PDF report...")
        try:
            self._generate_pdf(report, pdf_path)
            self.emit_output(f"PDF report saved")
        except Exception as e:
            logger.warning(f"PDF generation failed: {e}")
            self.emit_output(f"PDF generation skipped ({e})")
            pdf_path = ""

        self.emit_result({
            "status": "complete",
            "json_path": json_path,
            "html_path": html_path,
            "pdf_path": pdf_path,
        })

        return {"json_path": json_path, "html_path": html_path, "pdf_path": pdf_path}

    def _generate_pdf(self, report: dict, path: str):
        from fpdf import FPDF

        BLACK = (0, 0, 0)
        DARK = (30, 30, 30)
        GRAY = (80, 80, 80)
        LIGHT = (120, 120, 120)
        WHITE = (255, 255, 255)
        DIVIDER = (200, 200, 200)
        SEV_COLORS = {
            "critical": (220, 38, 38),
            "high": (234, 88, 12),
            "medium": (202, 138, 4),
            "low": (2, 132, 199),
            "info": (100, 100, 100),
        }

        pdf = FPDF()
        pdf.add_page()
        MARGIN = 10
        PAGE_W = 210

        def divider():
            pdf.set_draw_color(*DIVIDER)
            pdf.line(MARGIN, pdf.get_y(), PAGE_W - MARGIN, pdf.get_y())
            pdf.ln(6)

        def section_header(num, title):
            if pdf.get_y() > 240:
                pdf.add_page()
            pdf.set_font("Helvetica", "B", 15)
            pdf.set_text_color(*BLACK)
            pdf.cell(0, 10, f"{num}. {title}")
            pdf.ln(10)

        def severity_badge(label):
            sev = label.lower()
            c = SEV_COLORS.get(sev, (100, 100, 100))
            pdf.set_fill_color(*c)
            pdf.set_text_color(*WHITE)
            pdf.set_font("Helvetica", "B", 8)
            txt = f"  {label}  "
            w = pdf.get_string_width(txt)
            pdf.cell(w + 2, 6, txt, fill=True)

        # ===================== TITLE HEADER =====================
        pdf.set_font("Helvetica", "B", 26)
        pdf.set_text_color(*BLACK)
        pdf.cell(0, 14, "VBoxAuditor", align="L")
        pdf.ln(8)
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(*DARK)
        pdf.cell(0, 6, "VirtualBox Attack Surface Audit Report", align="L")
        pdf.ln(8)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*GRAY)
        pdf.cell(0, 6, f"Generated: {report.get('generated_at', '')[:19]}", align="L")
        pdf.ln(10)

        divider()

        # ===================== 1. EXECUTIVE SUMMARY =====================
        section_header("1", "Executive Summary")
        exec_text = report.get("executive_summary", "N/A")
        for line in exec_text.split("\n"):
            stripped = line.strip()
            if not stripped:
                pdf.ln(3)
                continue
            # Standalone **Section Header**
            sh = re.match(r"^\*\*(.+?)\*\*$", stripped)
            if sh:
                pdf.set_font("Helvetica", "B", 12)
                pdf.set_text_color(*BLACK)
                pdf.cell(0, 7, sh.group(1))
                pdf.ln(8)
                continue
            # Bullet line
            if stripped.startswith("- ") or stripped.startswith("* "):
                pdf.set_font("Helvetica", "", 10)
                pdf.set_text_color(*DARK)
                pdf.cell(5)
                pdf.cell(0, 5.5, "  - " + stripped[2:])
                pdf.ln(5.5)
                continue
            # Regular text
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(*DARK)
            pdf.multi_cell(0, 5.2, stripped)
        pdf.ln(4)

        vectors = summary.get("primary_attack_vectors", [])
        if vectors:
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*BLACK)
            pdf.cell(0, 6, "Attack Vectors Identified:")
            pdf.ln(8)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(*DARK)
            for v in vectors:
                pdf.cell(0, 5, f"  - {v}")
                pdf.ln(5)
            pdf.ln(2)

        divider()

        # ===================== 2. FINDINGS OVERVIEW =====================
        section_header("2", "Findings Overview")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*DARK)
        pdf.cell(0, 6, f"Total Findings: {summary.get('total_findings', 0)}")
        pdf.ln(10)

        sev_order = ["critical", "high", "medium", "low", "info"]
        sev_labels = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
        for sev in sev_order:
            cnt = summary.get(sev, 0)
            if cnt:
                severity_badge(sev_labels[sev])
                pdf.set_text_color(*BLACK)
                pdf.set_font("Helvetica", "", 10)
                pdf.cell(0, 6, f"   {cnt} finding(s)")
                pdf.ln(7)

        pdf.ln(4)
        divider()

        # ===================== 3. DETAILED FINDINGS =====================
        findings = report.get("findings", [])
        if findings:
            section_header("3", "Detailed Findings")

            for i, f in enumerate(findings):
                if pdf.get_y() > 230:
                    pdf.add_page()

                sev = f.get("severity", "INFO").lower()
                sc = SEV_COLORS.get(sev, (100, 100, 100))

                # Severity badge + ID and title
                pdf.set_fill_color(*sc)
                pdf.set_text_color(*WHITE)
                pdf.set_font("Helvetica", "B", 9)
                sev_label = f" {f.get('severity', 'INFO')} "
                sw = pdf.get_string_width(sev_label)
                pdf.cell(sw + 2, 7, sev_label, fill=True)

                pdf.set_text_color(*BLACK)
                pdf.set_font("Helvetica", "B", 11)
                pdf.cell(0, 7, f"  {f.get('id', '')} - {f.get('title', '')}")
                pdf.ln(10)

                # Metadata
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*GRAY)
                pdf.cell(0, 5, f"CVSS: {f.get('cvss_score', 'N/A')}   |   Component: {f.get('affected_component', 'N/A')}")
                pdf.ln(7)

                # Description
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*BLACK)
                pdf.cell(0, 5, "Description:")
                pdf.ln(6)
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*DARK)
                pdf.multi_cell(0, 4.5, f.get("description", "N/A"))
                pdf.ln(3)

                # Attack scenario
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*BLACK)
                pdf.cell(0, 5, "Attack Scenario:")
                pdf.ln(6)
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*DARK)
                pdf.multi_cell(0, 4.5, f.get("attack_scenario", "N/A"))
                pdf.ln(3)

                # Remediation
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*BLACK)
                pdf.cell(0, 5, "Remediation:")
                pdf.ln(6)
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*DARK)
                pdf.multi_cell(0, 4.5, f.get("remediation", "N/A"))
                pdf.ln(3)

                # References
                refs = f.get("references", [])
                if refs:
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.set_text_color(*BLACK)
                    pdf.cell(0, 5, "References:")
                    pdf.ln(6)
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_text_color(*GRAY)
                    for r in refs:
                        pdf.cell(0, 4, f"  - {r}")
                        pdf.ln(4)
                    pdf.ln(2)

                divider()

        # ===================== 4. CONCLUSION =====================
        if pdf.get_y() > 230:
            pdf.add_page()

        section_header("4", "Conclusion")

        high_crit = summary.get("critical", 0) + summary.get("high", 0)
        med = summary.get("medium", 0)
        low_info = summary.get("low", 0) + summary.get("info", 0)
        total = summary.get("total_findings", 0)

        lines = [
            f"This audit identified {total} security-relevant configuration issues across the VirtualBox environment."
        ]
        if high_crit:
            lines.append(
                f"Of these, {high_crit} are classified as High or Critical severity, "
                f"representing immediate risks that should be addressed as a priority."
            )
        if med:
            lines.append(
                f"There are {med} Medium severity findings that should be addressed "
                f"in the near term to reduce the overall attack surface."
            )
        if low_info:
            lines.append(
                f"The remaining {low_info} findings are Lower severity or informational, "
                f"providing guidance for security hardening best practices."
            )
        lines.append("")
        lines.append(
            "The findings highlight attack vectors that could be exploited by an adversary "
            "with access to the VirtualBox environment. Key areas of concern include unencrypted "
            "disk images, exposed remote desktop services, USB passthrough configurations, "
            "and network exposure through bridged or host-only adapters. Each finding includes "
            "specific, actionable remediation steps to harden the environment against these threats."
        )
        lines.append("")
        lines.append(
            "It is recommended that the remediation steps outlined in this report be reviewed "
            "and implemented according to the severity priority. Regular audits should be conducted "
            "to ensure ongoing security posture maintenance, particularly after configuration changes, "
            "VM deployments, or VirtualBox version updates."
        )

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*DARK)
        for line in lines:
            if line == "":
                pdf.ln(4)
            else:
                pdf.multi_cell(0, 5, line)
                pdf.ln(1)
        pdf.ln(6)

        # ===================== FOOTER =====================
        divider()
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*LIGHT)
        pdf.cell(
            0, 5,
            f"VBoxAuditor - VirtualBox Attack Surface Audit - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            align="C",
        )

        pdf.output(path)

    def _build_html_report(self, report: dict) -> str:
        findings_rows = ""
        for f in report.get("findings", []):
            severity_class = f.get("severity", "INFO").lower()
            remediation = f.get("remediation", "")
            attack = f.get("attack_scenario", "")
            refs = "<br>".join(f.get("references", []))
            findings_rows += f"""
            <tr>
                <td>{f.get('id', '')}</td>
                <td><span class="severity {severity_class}">{f.get('severity', 'INFO')}</span></td>
                <td>{f.get('title', '')}</td>
                <td>{f.get('cvss_score', 'N/A')}</td>
                <td>{f.get('affected_component', '')}</td>
                <td>{f.get('description', '')}</td>
                <td><em>{attack}</em></td>
                <td>{remediation}</td>
                <td style="font-size:11px;color:var(--accent-cyan)">{refs}</td>
            </tr>"""

        summary = report.get("summary", {})
        summary = report.get("summary", {})

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VBoxAuditor Security Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #07070f; color: #d0d0e0; padding: 40px; }}
    .container {{ max-width: 1400px; margin: auto; }}
    h1 {{ background: linear-gradient(135deg,#00bcd4,#b388ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-size: 28px; margin-bottom: 4px; }}
    h2 {{ color: #00e676; font-size: 20px; margin: 30px 0 12px; }}
    .subtitle {{ color: #9090b0; margin-bottom: 30px; font-size: 14px; }}
    .summary-cards {{ display: flex; gap: 16px; margin-bottom: 30px; flex-wrap: wrap; }}
    .card {{ background: #111128; border-radius: 8px; padding: 20px; min-width: 140px; flex: 1; border: 1px solid #1e1e3a; }}
    .card h3 {{ font-size: 12px; color: #606080; margin-bottom: 6px; text-transform: uppercase; letter-spacing: .5px; }}
    .card .value {{ font-size: 32px; font-weight: 700; }}
    .card .value.critical {{ color: #ff1744; }}
    .card .value.high {{ color: #ff6f3c; }}
    .card .value.medium {{ color: #ffd740; }}
    .card .value.low {{ color: #00bcd4; }}
    .card .value.info {{ color: #606080; }}
    table {{ width: 100%; border-collapse: collapse; background: #111128; border-radius: 8px; overflow: hidden; border: 1px solid #1e1e3a; }}
    th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #1e1e3a; font-size: 13px; }}
    th {{ background: #0c0c1a; color: #00bcd4; font-size: 11px; text-transform: uppercase; letter-spacing: .5px; }}
    td {{ font-size: 13px; }}
    .severity {{ display: inline-block; padding: 2px 10px; border-radius: 4px; font-weight: 600; font-size: 11px; }}
    .severity.critical {{ background: rgba(255,23,68,.15); color: #ff1744; }}
    .severity.high {{ background: rgba(255,111,60,.15); color: #ff6f3c; }}
    .severity.medium {{ background: rgba(255,215,64,.15); color: #ffd740; }}
    .severity.low {{ background: rgba(0,188,212,.15); color: #00bcd4; }}
    .severity.info {{ background: rgba(96,96,128,.15); color: #606080; }}
    .exec-summary {{ background: #111128; border-radius: 8px; padding: 24px; line-height: 1.7; border: 1px solid #1e1e3a; }}
    .exec-summary h2 {{ color: #ffd740; font-size: 16px; margin: 18px 0 8px; }}
    .exec-summary h3 {{ color: #00bcd4; font-size: 14px; margin: 14px 0 6px; }}
    .exec-summary strong {{ color: #ff6f3c; }}
    .exec-summary ul {{ margin: 8px 0; padding-left: 22px; }}
    .exec-summary li {{ margin-bottom: 4px; font-size: 13px; }}
    .exec-summary p {{ margin-bottom: 10px; }}
    .footer {{ margin-top: 40px; color: #404060; font-size: 12px; text-align: center; }}
    .vectors {{ display: flex; gap: 6px; flex-wrap: wrap; margin-top: 12px; }}
    .vector {{ background: rgba(255,111,60,.08); border: 1px solid rgba(255,111,60,.15); color: #ff6f3c; padding: 4px 10px; border-radius: 4px; font-size: 11px; }}
</style>
</head>
<body>
<div class="container">
    <h1>VBoxAuditor</h1>
    <div class="subtitle">VirtualBox Attack Surface Audit Report &middot; Generated: {report.get('generated_at', '')[:19]}</div>

    <h2>Executive Summary</h2>
    <div class="exec-summary">{self._md_to_html(report.get('executive_summary', 'N/A'))}
    <div class="vectors">{''.join(f'<span class="vector">{v}</span>' for v in summary.get('primary_attack_vectors', []))}</div>
    </div>

    <h2>Findings Overview</h2>
    <div class="summary-cards">
        <div class="card"><h3>Total</h3><div class="value">{summary.get('total_findings', 0)}</div></div>
        <div class="card"><h3>Critical</h3><div class="value critical">{summary.get('critical', 0)}</div></div>
        <div class="card"><h3>High</h3><div class="value high">{summary.get('high', 0)}</div></div>
        <div class="card"><h3>Medium</h3><div class="value medium">{summary.get('medium', 0)}</div></div>
        <div class="card"><h3>Low</h3><div class="value low">{summary.get('low', 0)}</div></div>
        <div class="card"><h3>Info</h3><div class="value info">{summary.get('info', 0)}</div></div>
    </div>

    <h2>Detailed Findings</h2>
    <table>
        <thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>CVSS</th><th>Component</th><th>Description</th><th>Attack Scenario</th><th>Remediation</th><th>References</th></tr></thead>
        <tbody>{findings_rows if findings_rows else '<tr><td colspan="9">No findings identified.</td></tr>'}</tbody>
    </table>

    <div class="footer">VBoxAuditor - VirtualBox Attack Surface Enumeration &middot; {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
</div>
</body>
</html>"""
