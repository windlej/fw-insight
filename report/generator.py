"""PDF report generator using WeasyPrint."""

import logging
from pathlib import Path

from weasyprint import HTML

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"
STYLES_FILE = TEMPLATES_DIR / ".." / "styles.css"


def generate_pdf(session: dict, findings: list[dict], raw_config: bytes | None = None) -> bytes:
    """Generate a PDF report from a session and its findings.

    Args:
        session: Session dict from storage
        findings: List of finding dicts
        raw_config: Optional raw config bytes for inclusion

    Returns:
        PDF file bytes
    """
    html_content = _build_report_html(session, findings)
    styles_path = Path(__file__).parent / "styles.css"

    html_doc = HTML(string=html_content)
    pdf_bytes = html_doc.write_pdf(stylesheets=[str(styles_path)])

    logger.info("Generated PDF report: %d bytes", len(pdf_bytes))
    return pdf_bytes


def _build_report_html(session: dict, findings: list[dict]) -> str:
    """Build the complete HTML report."""
    severity_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#2563eb",
        "info": "#6b7280",
    }

    finding_counts = session.get("finding_counts", {})

    html_parts = [
        '<!DOCTYPE html>',
        '<html>',
        '<head><meta charset="utf-8">',
        '<style>',
        '@page { size: letter; margin: 2cm; @bottom-center { content: "Page " counter(page) " of " counter(pages); } }',
        'body { font-family: sans-serif; font-size: 10pt; line-height: 1.4; }',
        'h1 { font-size: 18pt; border-bottom: 2px solid #333; padding-bottom: 4pt; }',
        'h2 { font-size: 14pt; border-bottom: 1px solid #999; padding-bottom: 2pt; margin-top: 16pt; }',
        'h3 { font-size: 12pt; margin-top: 12pt; }',
        'table { width: 100%; border-collapse: collapse; margin: 8pt 0; font-size: 9pt; }',
        'th { background: #f3f4f6; border: 1px solid #d1d5db; padding: 4pt 6pt; text-align: left; font-weight: bold; }',
        'td { border: 1px solid #d1d5db; padding: 4pt 6pt; }',
        '.score { font-size: 36pt; font-weight: bold; text-align: center; padding: 16pt; }',
        '.score-good { color: #16a34a; }',
        '.score-warn { color: #ca8a04; }',
        '.score-bad { color: #dc2626; }',
        '.badge { display: inline-block; padding: 2pt 6pt; border-radius: 3pt; color: white; font-size: 8pt; font-weight: bold; }',
        '.finding { page-break-inside: avoid; margin: 8pt 0; padding: 8pt; border-left: 4pt solid #ccc; background: #f9fafb; }',
        '.refs { font-size: 8pt; color: #6b7280; }',
        '</style>',
        '</head>',
        '<body>',
    ]

    health_score = session.get("health_score", 100)
    score_class = "score-good" if health_score >= 70 else "score-warn" if health_score >= 40 else "score-bad"

    html_parts.extend([
        '<h1>Firewall Configuration Analysis Report</h1>',
        '<div class="score {0}">{1}/100</div>'.format(score_class, health_score),
        '<p style="text-align:center;color:#6b7280;">Policy Health Score</p>',
        '<h2>Firewall Information</h2>',
        '<table>',
        '<tr><th style="width:30%">Property</th><th>Value</th></tr>',
        '<tr><td>Vendor</td><td>{}</td></tr>'.format(session.get("vendor", "N/A")),
        '<tr><td>Hostname</td><td>{}</td></tr>'.format(session.get("hostname") or "N/A"),
        '<tr><td>Version</td><td>{}</td></tr>'.format(session.get("vendor_version") or "N/A"),
        '<tr><td>Source File</td><td>{}</td></tr>'.format(session.get("source_filename") or "N/A"),
        '<tr><td>Security Policies</td><td>{}</td></tr>'.format(len(session.get("security_policies", []))),
        '<tr><td>NAT Rules</td><td>{}</td></tr>'.format(len(session.get("nat_rules", []))),
        '<tr><td>Address Objects</td><td>{}</td></tr>'.format(len(session.get("address_objects", []))),
        '<tr><td>Service Objects</td><td>{}</td></tr>'.format(len(session.get("service_objects", []))),
        '</table>',
    ])

    html_parts.extend([
        '<h2>Finding Summary</h2>',
        '<table>',
        '<tr><th>Severity</th><th>Count</th></tr>',
    ])

    for sev in ["critical", "high", "medium", "low", "info"]:
        count = finding_counts.get(sev, 0)
        if count > 0:
            color = severity_colors.get(sev, "#6b7280")
            html_parts.append(
                '<tr><td><span class="badge" style="background:{0}">{1}</span></td><td>{2}</td></tr>'.format(
                    color, sev.upper(), count
                )
            )

    html_parts.append('</table>')

    if findings:
        html_parts.append('<h2>Findings Detail</h2>')
        for f in findings:
            color = severity_colors.get(f.get("severity", "info"), "#6b7280")
            html_parts.extend([
                '<div class="finding" style="border-left-color:{0}">'.format(color),
                '<strong>{0} - {1}</strong><br>'.format(f.get("check_id", ""), f.get("title", "")),
                '<span class="badge" style="background:{0}">{1}</span><br><br>'.format(
                    color, f.get("severity", "info").upper()
                ),
                '<em>Affected:</em> {0}<br>'.format(f.get("entity_id", "")),
                '{0}<br>'.format(f.get("description", "")),
            ])
            refs = f.get("references", [])
            if refs:
                html_parts.append('<span class="refs">References: ' + "; ".join(refs) + "</span>")
            html_parts.append("</div>")

    policies = session.get("security_policies", [])
    if policies:
        html_parts.extend([
            '<h2>Security Policies</h2>',
            '<table>',
            '<tr>',
            '<th>#</th><th>Name</th><th>Source</th><th>Destination</th>',
            '<th>Service</th><th>Action</th><th>Logging</th>',
            '</tr>',
        ])
        for p in policies:
            src = ", ".join(p.get("source", {}).get("addresses", []) or [])
            dst = ", ".join(p.get("destination", {}).get("addresses", []) or [])
            svcs = ", ".join(
                f"{s.get('protocol', 'any')}/{','.join(s.get('ports', []) or ['any'])}"
                for s in p.get("services", [])
            )
            log = "Yes" if p.get("logging", {}).get("log_end") else "No"
            action_color = "#16a34a" if p.get("action") == "allow" else "#dc2626"
            html_parts.extend([
                '<tr>',
                '<td>{}</td>'.format(p.get("position", "")),
                '<td>{}</td>'.format(p.get("name") or p.get("id", "")),
                '<td style="font-size:8pt">{}</td>'.format(src[:50]),
                '<td style="font-size:8pt">{}</td>'.format(dst[:50]),
                '<td>{}</td>'.format(svcs),
                '<td style="color:{0};font-weight:bold">{1}</td>'.format(action_color, p.get("action", "")),
                '<td>{}</td>'.format(log),
                '</tr>',
            ])
        html_parts.append('</table>')

    html_parts.extend(['</body>', '</html>'])
    return "\n".join(html_parts)
