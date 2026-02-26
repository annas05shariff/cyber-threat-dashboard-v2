"""
report_generator.py — PDF Report Generator (Module 4)
Generates an executive-ready PDF report from current dashboard data.
Includes summary stats, all key charts as images, CVE table, and recommendations.

Dependencies: kaleido (chart export) + reportlab (PDF assembly)
Both are in requirements.txt

Usage:
    from dashboard.report_generator import generate_pdf_report
    pdf_path = generate_pdf_report(hours_back=24)
"""

import logging
import os
import io
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


# ── ReportLab imports ──────────────────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.units import cm, mm
    from reportlab.lib.colors import (
        HexColor, white, black
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        Image, PageBreak, HRFlowable, KeepTogether
    )
    from reportlab.platypus.flowables import HRFlowable
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False
    logger.warning("reportlab not installed — run: pip install reportlab")

# ── Kaleido for chart export ───────────────────────────────────────────────────
try:
    import kaleido  # noqa — just checking it's installed
    KALEIDO_OK = True
except ImportError:
    KALEIDO_OK = False
    logger.warning("kaleido not installed — run: pip install kaleido")


# ── Design colors ──────────────────────────────────────────────────────────────
C_BG       = HexColor("#050a0f")
C_PANEL    = HexColor("#0a1520")
C_CYAN     = HexColor("#00d4ff")
C_GREEN    = HexColor("#00ff88")
C_RED      = HexColor("#ff3355")
C_ORANGE   = HexColor("#ff6b35")
C_YELLOW   = HexColor("#ffd700")
C_PURPLE   = HexColor("#a78bfa")
C_TEXT     = HexColor("#c8e6f5")
C_MUTED    = HexColor("#527a99")
C_DARK     = HexColor("#0a1520")
C_BORDER   = HexColor("#0f3a5c")

SEVERITY_COLORS = {
    "Critical": C_RED,
    "High":     C_ORANGE,
    "Medium":   C_YELLOW,
    "Low":      C_GREEN,
}


def _export_chart_as_image(fig, width_px: int = 900, height_px: int = 400) -> Optional[bytes]:
    """
    Export a Plotly figure to PNG bytes using kaleido.
    Returns None if kaleido is not available.
    """
    if not KALEIDO_OK:
        return None
    try:
        return fig.to_image(format="png", width=width_px, height=height_px, scale=1.5)
    except Exception as e:
        logger.warning(f"Chart export failed: {e}")
        return None


def generate_pdf_report(
    hours_back:  int  = 24,
    output_path: str  = None,
) -> Optional[str]:
    """
    Generate a complete executive PDF report.

    Args:
        hours_back:  Time window for report data (default 24h)
        output_path: Where to save the PDF. If None, saves to /tmp/

    Returns:
        Path to the generated PDF file, or None if generation failed.
    """
    if not REPORTLAB_OK:
        logger.error("reportlab not installed — cannot generate PDF")
        return None

    # ── Load data ──────────────────────────────────────────────────────────
    try:
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

        from config.database import (
            get_recent_events, get_attack_type_counts,
            get_hourly_counts, get_country_counts,
            get_top_cves, get_severity_distribution,
            get_mitre_technique_counts,
        )
        from visualizations.charts import (
            build_timeseries_chart, build_attack_type_bar,
            build_severity_donut, build_top_countries_bar,
            compute_kpi_stats,
        )
        from visualizations.geo_charts import (
            build_choropleth_map, build_mitre_treemap,
        )

        events        = get_recent_events(limit=500, hours_back=hours_back)
        hourly        = get_hourly_counts(hours_back=hours_back)
        country       = get_country_counts(hours_back=hours_back)
        attack_counts = get_attack_type_counts(hours_back=hours_back)
        severity_data = get_severity_distribution(hours_back=hours_back)
        cves          = get_top_cves(limit=15)
        mitre_data    = get_mitre_technique_counts(hours_back=hours_back)
        kpis          = compute_kpi_stats(events)

    except Exception as e:
        logger.error(f"Failed to load data for report: {e}")
        return None

    # ── Output path ────────────────────────────────────────────────────────
    if output_path is None:
        ts          = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
        output_path = os.path.join(tempfile.gettempdir(), f"threat_report_{ts}.pdf")

    # ── Build PDF ──────────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        output_path,
        pagesize    = A4,
        leftMargin  = 1.5 * cm,
        rightMargin = 1.5 * cm,
        topMargin   = 1.5 * cm,
        bottomMargin= 1.5 * cm,
    )

    story = []
    styles = _build_styles()
    now_str = datetime.now(timezone.utc).strftime("%B %d, %Y — %H:%M UTC")

    # ══ PAGE 1: Cover ══════════════════════════════════════════════════════

    story.append(Spacer(1, 2 * cm))

    # Title block
    story.append(Paragraph("CYBER THREAT INTELLIGENCE", styles["label"]))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("Executive Security Report", styles["cover_title"]))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(f"Reporting Period: Last {hours_back} Hours", styles["cover_sub"]))
    story.append(Paragraph(f"Generated: {now_str}", styles["cover_sub"]))

    story.append(Spacer(1, 0.8 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=C_CYAN))
    story.append(Spacer(1, 0.8 * cm))

    # ── KPI Summary Table ──────────────────────────────────────────────────
    story.append(Paragraph("KEY METRICS", styles["section_label"]))
    story.append(Spacer(1, 0.3 * cm))

    kpi_data = [
        ["Total Events",       "Critical Events",   "Countries",          "Avg Severity",       "Top Attack Type"],
        [
            str(kpis.get("total_events", 0)),
            str(kpis.get("critical_count", 0)),
            str(kpis.get("unique_countries", 0)),
            str(kpis.get("avg_severity", 0)),
            str(kpis.get("top_attack_type", "N/A")),
        ]
    ]

    kpi_table = Table(kpi_data, colWidths=[3.5 * cm] * 5)
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), C_DARK),
        ("BACKGROUND",  (0, 1), (-1, 1), C_PANEL),
        ("TEXTCOLOR",   (0, 0), (-1, 0), C_MUTED),
        ("TEXTCOLOR",   (0, 1), (-1, 1), C_CYAN),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, 0), 7),
        ("FONTNAME",    (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 1), (-1, 1), 14),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_DARK, C_PANEL]),
        ("BOX",         (0, 0), (-1, -1), 1, C_BORDER),
        ("INNERGRID",   (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",  (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 0.8 * cm))

    # ── Severity breakdown table ───────────────────────────────────────────
    if severity_data:
        story.append(Paragraph("SEVERITY DISTRIBUTION", styles["section_label"]))
        story.append(Spacer(1, 0.3 * cm))

        sev_rows = [["Severity Level", "Event Count", "% of Total"]]
        total    = sum(s.get("count", 0) for s in severity_data)
        for s in sorted(severity_data, key=lambda x: ["Critical","High","Medium","Low"].index(x.get("severity","Low")) if x.get("severity") in ["Critical","High","Medium","Low"] else 99):
            pct = f"{(s['count']/total*100):.1f}%" if total else "0%"
            sev_rows.append([s.get("severity","?"), str(s.get("count",0)), pct])

        sev_table = Table(sev_rows, colWidths=[6 * cm, 5 * cm, 5 * cm])
        sev_style = [
            ("BACKGROUND",  (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",   (0, 0), (-1, 0), C_MUTED),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica"),
            ("FONTSIZE",    (0, 0), (-1, -1), 10),
            ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
            ("BOX",         (0, 0), (-1, -1), 1, C_BORDER),
            ("INNERGRID",   (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",  (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]
        for i, row in enumerate(sev_rows[1:], 1):
            sev_level = row[0]
            color     = SEVERITY_COLORS.get(sev_level, C_TEXT)
            sev_style.append(("TEXTCOLOR", (0, i), (0, i), color))
            sev_style.append(("FONTNAME",  (0, i), (-1, i), "Helvetica-Bold"))
            sev_style.append(("BACKGROUND",(0, i), (-1, i), C_PANEL if i % 2 else C_DARK))

        sev_table.setStyle(TableStyle(sev_style))
        story.append(sev_table)

    story.append(PageBreak())

    # ══ PAGE 2: Charts ═════════════════════════════════════════════════════

    story.append(Paragraph("ATTACK TREND ANALYSIS", styles["section_title"]))
    story.append(Spacer(1, 0.3 * cm))

    # Time series chart
    try:
        fig_ts  = build_timeseries_chart(hourly)
        img_ts  = _export_chart_as_image(fig_ts, 900, 320)
        if img_ts:
            story.append(Image(io.BytesIO(img_ts), width=17 * cm, height=6 * cm))
            story.append(Paragraph(
                "Figure 1: Attack frequency over the reporting period. Spikes indicate potential coordinated attack waves.",
                styles["caption"]
            ))
    except Exception as e:
        logger.warning(f"Time series chart failed: {e}")

    story.append(Spacer(1, 0.5 * cm))

    # Side-by-side: attack bar + severity donut
    try:
        fig_bar  = build_attack_type_bar(attack_counts)
        fig_sev  = build_severity_donut(severity_data)
        img_bar  = _export_chart_as_image(fig_bar, 500, 300)
        img_sev  = _export_chart_as_image(fig_sev, 400, 300)

        if img_bar and img_sev:
            chart_row = [[
                Image(io.BytesIO(img_bar), width=9 * cm, height=5.5 * cm),
                Image(io.BytesIO(img_sev), width=7 * cm, height=5.5 * cm),
            ]]
            chart_table = Table(chart_row, colWidths=[9.5 * cm, 7.5 * cm])
            chart_table.setStyle(TableStyle([("VALIGN", (0,0), (-1,-1), "TOP")]))
            story.append(chart_table)
            story.append(Paragraph(
                "Figure 2 (left): Attack distribution by type. Figure 3 (right): Severity level breakdown.",
                styles["caption"]
            ))
    except Exception as e:
        logger.warning(f"Bar/donut charts failed: {e}")

    story.append(PageBreak())

    # ══ PAGE 3: Geographic Analysis ════════════════════════════════════════

    story.append(Paragraph("GEOGRAPHIC THREAT ANALYSIS", styles["section_title"]))
    story.append(Spacer(1, 0.3 * cm))

    try:
        fig_map = build_choropleth_map(country)
        img_map = _export_chart_as_image(fig_map, 900, 400)
        if img_map:
            story.append(Image(io.BytesIO(img_map), width=17 * cm, height=7.5 * cm))
            story.append(Paragraph(
                "Figure 4: Global attack origin map. Darker regions indicate higher threat event volume.",
                styles["caption"]
            ))
    except Exception as e:
        logger.warning(f"Map chart failed: {e}")

    story.append(Spacer(1, 0.5 * cm))

    # Top countries table
    if country:
        story.append(Paragraph("TOP ATTACK SOURCE COUNTRIES", styles["section_label"]))
        story.append(Spacer(1, 0.3 * cm))

        ctry_rows = [["Rank", "Country", "Country Code", "Events", "Avg Severity"]]
        for i, c in enumerate(country[:10], 1):
            ctry_rows.append([
                str(i),
                c.get("country", "Unknown"),
                c.get("country_code", "??"),
                str(c.get("count", 0)),
                f"{c.get('avg_severity', 0):.1f}",
            ])

        ctry_table = Table(ctry_rows, colWidths=[1.5*cm, 5*cm, 3*cm, 3*cm, 4.5*cm])
        ctry_table.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",    (0, 0), (-1, 0), C_MUTED),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica"),
            ("FONTSIZE",     (0, 0), (-1, -1), 9),
            ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
            ("BOX",          (0, 0), (-1, -1), 1, C_BORDER),
            ("INNERGRID",    (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",   (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_PANEL, C_DARK]),
            ("TEXTCOLOR",    (0, 1), (-1, -1), C_TEXT),
            ("FONTNAME",     (0, 1), (-1, -1), "Helvetica"),
        ]))
        story.append(ctry_table)

    story.append(PageBreak())

    # ══ PAGE 4: MITRE ATT&CK ═══════════════════════════════════════════════

    story.append(Paragraph("MITRE ATT&CK COVERAGE", styles["section_title"]))
    story.append(Spacer(1, 0.3 * cm))

    try:
        fig_tree = build_mitre_treemap(mitre_data)
        img_tree = _export_chart_as_image(fig_tree, 900, 420)
        if img_tree:
            story.append(Image(io.BytesIO(img_tree), width=17 * cm, height=8 * cm))
            story.append(Paragraph(
                "Figure 5: MITRE ATT&CK technique coverage. Rectangle size indicates event volume; color indicates average severity.",
                styles["caption"]
            ))
    except Exception as e:
        logger.warning(f"Treemap chart failed: {e}")

    story.append(PageBreak())

    # ══ PAGE 5: CVE Intelligence ════════════════════════════════════════════

    story.append(Paragraph("CRITICAL VULNERABILITY INTELLIGENCE", styles["section_title"]))
    story.append(Spacer(1, 0.3 * cm))

    if cves:
        cve_rows = [["CVE ID", "CVSS", "Severity", "Vendor", "Product", "Description"]]
        for cve in cves[:12]:
            score    = cve.get("cvss_score") or 0
            sev      = cve.get("cvss_severity") or "N/A"
            desc     = (cve.get("description") or "")[:60] + ("..." if len(cve.get("description","")) > 60 else "")
            cve_rows.append([
                cve.get("cve_id", ""),
                f"{score:.1f}" if score else "N/A",
                sev,
                (cve.get("affected_vendor")  or "?")[:12],
                (cve.get("affected_product") or "?")[:14],
                desc,
            ])

        cve_table = Table(
            cve_rows,
            colWidths=[2.8*cm, 1.4*cm, 1.8*cm, 2.2*cm, 2.5*cm, 6.3*cm]
        )
        cve_style = [
            ("BACKGROUND",   (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",    (0, 0), (-1, 0), C_MUTED),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica"),
            ("FONTSIZE",     (0, 0), (-1, -1), 7.5),
            ("ALIGN",        (0, 0), (-1, -1), "LEFT"),
            ("ALIGN",        (1, 0), (2, -1), "CENTER"),
            ("BOX",          (0, 0), (-1, -1), 1, C_BORDER),
            ("INNERGRID",    (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_PANEL, C_DARK]),
            ("TEXTCOLOR",    (0, 1), (-1, -1), C_TEXT),
            ("FONTNAME",     (0, 1), (0, -1), "Helvetica-Bold"),  # CVE ID bold
        ]
        # Color-code severity column
        for i, cve in enumerate(cves[:12], 1):
            score = cve.get("cvss_score") or 0
            color = C_RED if score >= 9 else C_ORANGE if score >= 7 else C_YELLOW if score >= 4 else C_GREEN
            cve_style.append(("TEXTCOLOR", (1, i), (2, i), color))

        cve_table.setStyle(TableStyle(cve_style))
        story.append(cve_table)
        story.append(Spacer(1, 0.5 * cm))

    # ══ PAGE 6: Recommendations ═════════════════════════════════════════════

    story.append(PageBreak())
    story.append(Paragraph("SECURITY RECOMMENDATIONS", styles["section_title"]))
    story.append(Spacer(1, 0.5 * cm))

    recommendations = _generate_recommendations(kpis, attack_counts, cves)
    for i, rec in enumerate(recommendations, 1):
        story.append(Paragraph(f"{i}. {rec['title']}", styles["rec_title"]))
        story.append(Paragraph(rec["detail"], styles["rec_detail"]))
        story.append(Spacer(1, 0.4 * cm))

    # Footer
    story.append(Spacer(1, 1 * cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        f"This report was automatically generated by the Cyber Threat Visualization Dashboard on {now_str}. "
        f"Data sourced from NVD CVE Feed, AlienVault OTX, and AbuseIPDB.",
        styles["footer"]
    ))

    # ── Build PDF ──────────────────────────────────────────────────────────
    try:
        doc.build(story, onFirstPage=_page_template, onLaterPages=_page_template)
        logger.info(f"PDF report generated: {output_path}")
        return output_path
    except Exception as e:
        logger.error(f"PDF build failed: {e}")
        return None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _build_styles() -> dict:
    """Return all custom paragraph styles for the report."""
    return {
        "label": ParagraphStyle("label",
            fontName="Helvetica", fontSize=8, textColor=C_MUTED,
            spaceAfter=4, letterSpacing=3, alignment=TA_LEFT,
        ),
        "cover_title": ParagraphStyle("cover_title",
            fontName="Helvetica-Bold", fontSize=28, textColor=C_CYAN,
            spaceAfter=8, leading=32,
        ),
        "cover_sub": ParagraphStyle("cover_sub",
            fontName="Helvetica", fontSize=11, textColor=C_MUTED,
            spaceAfter=4,
        ),
        "section_title": ParagraphStyle("section_title",
            fontName="Helvetica-Bold", fontSize=14, textColor=C_CYAN,
            spaceAfter=8,
        ),
        "section_label": ParagraphStyle("section_label",
            fontName="Helvetica", fontSize=8, textColor=C_MUTED,
            spaceAfter=4, letterSpacing=2,
        ),
        "caption": ParagraphStyle("caption",
            fontName="Helvetica", fontSize=8, textColor=C_MUTED,
            spaceAfter=8, spaceBefore=4, alignment=TA_CENTER,
        ),
        "rec_title": ParagraphStyle("rec_title",
            fontName="Helvetica-Bold", fontSize=11, textColor=C_GREEN,
            spaceAfter=3,
        ),
        "rec_detail": ParagraphStyle("rec_detail",
            fontName="Helvetica", fontSize=9, textColor=C_TEXT,
            spaceAfter=4, leftIndent=12,
        ),
        "footer": ParagraphStyle("footer",
            fontName="Helvetica", fontSize=7, textColor=C_MUTED,
            alignment=TA_CENTER,
        ),
    }


def _page_template(canvas, doc):
    """Draw page header/footer on every page."""
    canvas.saveState()
    w, h = A4

    # Top bar
    canvas.setFillColor(C_DARK)
    canvas.rect(0, h - 1.2*cm, w, 1.2*cm, fill=1, stroke=0)
    canvas.setFillColor(C_CYAN)
    canvas.rect(0, h - 1.2*cm, 4*mm, 1.2*cm, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(C_TEXT)
    canvas.drawString(1*cm, h - 0.8*cm, "CYBER THREAT INTELLIGENCE REPORT")
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(C_MUTED)
    canvas.drawRightString(w - 1*cm, h - 0.8*cm,
        datetime.now(timezone.utc).strftime("%Y-%m-%d"))

    # Bottom bar
    canvas.setFillColor(C_DARK)
    canvas.rect(0, 0, w, 0.8*cm, fill=1, stroke=0)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_MUTED)
    canvas.drawCentredString(w/2, 0.3*cm, f"Page {doc.page} — CONFIDENTIAL")

    canvas.restoreState()


def _generate_recommendations(kpis: dict, attack_counts: list, cves: list) -> list:
    """Generate context-aware recommendations based on actual data."""
    recs = []

    # Based on top attack type
    top_type = kpis.get("top_attack_type", "")
    if top_type == "Ransomware":
        recs.append({
            "title": "Immediate Ransomware Mitigation",
            "detail": "Ransomware is the dominant threat. Verify all backups are offline and tested. "
                      "Enforce application whitelisting and restrict macro execution in Office documents. "
                      "Ensure EDR solutions are active on all endpoints."
        })
    elif top_type in ("Brute Force", "Port Scan"):
        recs.append({
            "title": "Strengthen Authentication Controls",
            "detail": "Brute force and scanning activity is elevated. Enable account lockout policies, "
                      "enforce MFA on all remote access services, and review exposed RDP/SSH ports. "
                      "Consider IP allowlisting for administrative interfaces."
        })
    elif top_type == "Phishing":
        recs.append({
            "title": "Email Security Enhancement",
            "detail": "Phishing campaigns are the dominant threat vector. Review email gateway rules, "
                      "enable DMARC/DKIM/SPF validation, and run security awareness training. "
                      "Consider deploying a sandboxed email attachment scanner."
        })
    elif top_type == "DDoS":
        recs.append({
            "title": "DDoS Resilience Review",
            "detail": "High DDoS activity detected. Verify CDN and DDoS scrubbing services are active. "
                      "Review rate limiting on public-facing services and ensure failover capacity is available."
        })

    # Based on critical CVEs
    critical_cve_count = sum(1 for c in cves if (c.get("cvss_score") or 0) >= 9.0)
    if critical_cve_count > 0:
        recs.append({
            "title": f"Patch {critical_cve_count} Critical CVE(s) Immediately",
            "detail": f"{critical_cve_count} critical vulnerabilities (CVSS ≥ 9.0) were published in this "
                      "reporting period. Cross-reference affected vendors/products against your asset inventory "
                      "and prioritize patching within 24 hours for internet-facing systems."
        })

    # Based on avg severity
    avg_sev = float(kpis.get("avg_severity", 0))
    if avg_sev >= 7.0:
        recs.append({
            "title": "Elevate Security Posture — High Average Severity",
            "detail": f"Average event severity is {avg_sev:.1f}/10 — above normal thresholds. "
                      "Consider moving to heightened monitoring mode: increase SIEM alerting sensitivity, "
                      "activate 24/7 SOC coverage, and review incident response playbooks."
        })

    # Standard recommendations always included
    recs.append({
        "title": "Review Threat Intelligence Feed Coverage",
        "detail": "Ensure AlienVault OTX, AbuseIPDB, and NVD feeds are ingesting continuously. "
                  "Cross-reference top attacking IPs against your firewall blocklists and update "
                  "threat intelligence platform (TIP) with current indicators of compromise (IOCs)."
    })
    recs.append({
        "title": "Log Retention and SIEM Tuning",
        "detail": "Retain raw security logs for minimum 90 days. Review SIEM correlation rules against "
                  "the MITRE ATT&CK techniques active in this report. Tune detection rules for "
                  "techniques with high frequency but low current alert coverage."
    })

    return recs[:6]   # cap at 6 recommendations per report
