"""
NETGUARD - Member 6: PDF Security Audit Report Generator
Creates executive-ready, professional cybersecurity audit reports using ReportLab.
"""

from io import BytesIO
from typing import Dict
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)


def generate_pdf_report(scan_data: Dict) -> bytes:
    """
    Generates a professional, branded PDF cybersecurity audit report.
    Returns the PDF as raw bytes ready for streaming or download.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom Cyber SaaS Styles
    primary_color = colors.HexColor("#0A0F1D")
    accent_blue = colors.HexColor("#0070F3")
    accent_cyan = colors.HexColor("#00C2FF")
    danger_red = colors.HexColor("#EF4444")
    warning_yellow = colors.HexColor("#F59E0B")
    success_green = colors.HexColor("#10B981")
    text_dark = colors.HexColor("#1E293B")
    text_muted = colors.HexColor("#64748B")

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=primary_color,
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=accent_blue,
        spaceAfter=12
    )

    h2_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=primary_color,
        spaceBefore=14,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=text_dark
    )

    body_bold = ParagraphStyle(
        "ReportBodyBold",
        parent=body_style,
        fontName="Helvetica-Bold"
    )

    meta_style = ParagraphStyle(
        "MetaText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=text_muted
    )

    elements = []

    # 1. Header & Branding Banner
    scan_id = scan_data.get("scan_id", "N/A")
    target = scan_data.get("target", "N/A")
    scan_time = scan_data.get("scan_time", "N/A")
    scan_mode = scan_data.get("scan_mode", "real").upper()
    score = scan_data.get("risk_score", 100)
    devices = scan_data.get("devices", [])
    findings = scan_data.get("findings", [])
    recommendations = scan_data.get("recommendations", [])

    elements.append(Paragraph("NETGUARD", title_style))
    elements.append(Paragraph("Small Business Network Security Audit Report", subtitle_style))
    elements.append(Paragraph(
        f"<b>Audit Reference:</b> {scan_id} &nbsp;|&nbsp; <b>Target:</b> {target} &nbsp;|&nbsp; "
        f"<b>Timestamp:</b> {scan_time} &nbsp;|&nbsp; <b>Mode:</b> {scan_mode}",
        meta_style
    ))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=2, color=accent_blue, spaceAfter=14))

    # 2. Executive Summary Metrics Table
    crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    med_count = sum(1 for f in findings if f.get("severity") == "Medium")
    low_count = sum(1 for f in findings if f.get("severity") == "Low")
    total_ports = sum(len(d.get("open_ports", [])) for d in devices)

    if score >= 90:
        score_badge = "EXCELLENT"
        score_color = success_green
    elif score >= 75:
        score_badge = "GOOD"
        score_color = accent_cyan
    elif score >= 50:
        score_badge = "NEEDS ATTENTION"
        score_color = warning_yellow
    else:
        score_badge = "CRITICAL / POOR"
        score_color = danger_red

    metrics_data = [
        [
            Paragraph("<b>Security Score</b>", body_style),
            Paragraph("<b>Discovered Hosts</b>", body_style),
            Paragraph("<b>Open Ports</b>", body_style),
            Paragraph("<b>Security Findings</b>", body_style)
        ],
        [
            Paragraph(f"<font size='16' color='{score_color.hexval()}'><b>{score}/100</b></font><br/>{score_badge}", body_style),
            Paragraph(f"<font size='16'><b>{len(devices)}</b></font><br/>Active Devices", body_style),
            Paragraph(f"<font size='16'><b>{total_ports}</b></font><br/>Listening Services", body_style),
            Paragraph(
                f"<font size='16'><b>{len(findings)}</b></font><br/>"
                f"<font color='#EF4444'>{crit_count} Crit</font> | "
                f"<font color='#F97316'>{high_count} High</font> | "
                f"<font color='#F59E0B'>{med_count} Med</font>",
                body_style
            )
        ]
    ]

    metrics_table = Table(metrics_data, colWidths=[130, 130, 130, 150])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(metrics_table)
    elements.append(Spacer(1, 14))

    # 3. Discovered Network Devices Table
    elements.append(Paragraph("1. Discovered Network Assets", h2_style))
    dev_table_data = [
        [
            Paragraph("<b>IP Address</b>", body_bold),
            Paragraph("<b>Hostname</b>", body_bold),
            Paragraph("<b>MAC Address</b>", body_bold),
            Paragraph("<b>Open Ports</b>", body_bold),
            Paragraph("<b>Services</b>", body_bold)
        ]
    ]

    for d in devices:
        ports_str = ", ".join(str(p["port"]) for p in d.get("open_ports", [])) or "None"
        services_str = ", ".join(d.get("services_summary", [])) or "None detected"
        dev_table_data.append([
            Paragraph(d.get("ip", "N/A"), body_style),
            Paragraph(d.get("hostname", "Unknown"), body_style),
            Paragraph(d.get("mac") or "N/A", body_style),
            Paragraph(ports_str, body_style),
            Paragraph(services_str, body_style)
        ])

    dev_table = Table(dev_table_data, colWidths=[90, 110, 100, 70, 170])
    dev_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0A0F1D")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
    ]))
    elements.append(dev_table)
    elements.append(Spacer(1, 14))

    # 4. Detailed Security Findings Section
    elements.append(Paragraph("2. Prioritized Security Findings & Remediation", h2_style))

    if not findings:
        elements.append(Paragraph("No critical or high-severity vulnerabilities were identified during this audit.", body_style))
    else:
        for f in findings:
            sev = f.get("severity", "Low")
            sev_color = danger_red if sev == "Critical" else (
                colors.HexColor("#F97316") if sev == "High" else (
                    warning_yellow if sev == "Medium" else colors.HexColor("#3B82F6")
                )
            )

            finding_box = [
                [
                    Paragraph(f"<b>[{sev.upper()}] {f.get('title')}</b>", ParagraphStyle("FTitle", parent=body_bold, textColor=sev_color, fontSize=11)),
                    Paragraph(f"<b>Device:</b> {f.get('device_ip')} ({f.get('hostname')}) | Port {f.get('port')}", body_style)
                ],
                [
                    Paragraph(f"<b>Evidence:</b> {f.get('evidence')}", meta_style),
                    Paragraph(f"<b>ID:</b> {f.get('id', 'FIND-')}", meta_style)
                ],
                [
                    Paragraph(f"<b>Why this matters:</b> {f.get('explanation')}", body_style),
                    Paragraph(f"<b>Solution:</b><br/>{f.get('solution')}", body_style)
                ],
                [
                    Paragraph(f"<b>Verification Method:</b> {f.get('verification')}", meta_style),
                    Paragraph("<b>Manual Check:</b> Yes" if f.get("requires_manual_verification") else "<b>Manual Check:</b> Automated", meta_style)
                ]
            ]

            f_table = Table(finding_box, colWidths=[270, 270])
            f_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ('BOX', (0, 0), (-1, -1), 1, sev_color),
                ('LINEBELOW', (0, 0), (-1, 0), 0.5, colors.HexColor("#E2E8F0")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))

            elements.append(KeepTogether([f_table, Spacer(1, 8)]))

    elements.append(Spacer(1, 10))

    # 5. Remediation Action Checklist
    elements.append(Paragraph("3. Remediation Action Tracker", h2_style))
    rec_table_data = [
        [
            Paragraph("<b>Priority</b>", body_bold),
            Paragraph("<b>Target Host</b>", body_bold),
            Paragraph("<b>Recommended Action</b>", body_bold),
            Paragraph("<b>Status</b>", body_bold)
        ]
    ]

    for r in recommendations:
        p_color = danger_red if r.get("priority") == "Critical" else (
            colors.HexColor("#F97316") if r.get("priority") == "High" else warning_yellow
        )
        rec_table_data.append([
            Paragraph(f"<font color='{p_color.hexval()}'><b>{r.get('priority')}</b></font>", body_style),
            Paragraph(r.get("device_ip", ""), body_style),
            Paragraph(f"<b>{r.get('title')}</b><br/>{r.get('action')}", body_style),
            Paragraph(f"<b>{r.get('status', 'Pending')}</b>", body_style)
        ])

    if len(rec_table_data) > 1:
        rec_table = Table(rec_table_data, colWidths=[70, 90, 310, 70])
        rec_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(rec_table)
    else:
        elements.append(Paragraph("No remediation tasks pending.", body_style))

    elements.append(Spacer(1, 14))

    # 6. Final Security Summary & Disclaimer
    elements.append(Paragraph("4. Executive Conclusion & Advisory Disclaimer", h2_style))
    elements.append(Paragraph(
        "<b>Executive Summary:</b> Network security in small business environments requires continuous vigilance. "
        "Adhering to the principle of least privilege by closing legacy unencrypted services (such as Telnet and cleartext FTP) "
        "and isolating critical administrative interfaces behind encrypted protocols dramatically reduces risk from automated attacks.",
        body_style
    ))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        "<b>Notice:</b> This audit report is generated automatically by NETGUARD based strictly on observed port and service responses. "
        "It provides indicative security advice and does not guarantee complete absence of vulnerabilities, nor does it substitute for "
        "a certified external regulatory compliance audit. Users should only scan networks they own or are authorized to audit.",
        meta_style
    ))

    # Build PDF
    doc.build(elements)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
