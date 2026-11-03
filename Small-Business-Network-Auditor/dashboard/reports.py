"""
NETGUARD - Page 12: PDF Security Audit Report
Executive reporting dashboard providing on-demand ReportLab PDF compilation,
report preview, XP awards, and instantaneous PDF file downloads.
"""

import textwrap
import streamlit as st
from database import get_all_scans, get_scan, award_xp
from reports import generate_pdf_report
from config import CYBER_PALETTE


def render_reports_page():
    """Renders the executive PDF report generator and download center."""
    st.html(textwrap.dedent("""
    <div class="netguard-card" style="margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div>
                <div style="font-size: 0.78rem; font-weight: 700; color: #00D9FF; letter-spacing: 0.08em; text-transform: uppercase;">
                    MISSION 05: EXECUTIVE INTELLIGENCE DOSSIER
                </div>
                <h2 style="color: #F3F7FF; font-size: 1.55rem; font-weight: 800; margin: 2px 0 0 0;">
                    Executive PDF Audit Reports
                </h2>
                <p style="color: #91A3B8; font-size: 0.88rem; margin-top: 4px; margin-bottom: 0;">
                    Compile formal, board-ready cybersecurity documentation with ReportLab for underwriters, franchisors, and compliance auditors.
                </p>
            </div>
            <div>
                <span class="badge-commander">PDF Engine v3.0</span>
            </div>
        </div>
    </div>
    """))

    all_scans = get_all_scans()
    if not all_scans:
        st.info("No audit history found. Please run a network audit first.")
        return

    # Scan selector
    scan_options = {
        f"{s['scan_id']} ({s['target']}) - Score: {s['risk_score']}/100 [{s['scan_time'][:16]}]": s["scan_id"]
        for s in all_scans
    }

    selected_label = st.selectbox("Select Audit to Generate PDF Report For", options=list(scan_options.keys()))
    selected_scan_id = scan_options[selected_label]
    scan_data = get_scan(selected_scan_id)

    if not scan_data:
        st.error("Could not retrieve scan details.")
        return

    # Audit Overview Preview Box
    score = scan_data.get("risk_score", 100)
    devices = scan_data.get("devices", [])
    findings = scan_data.get("findings", [])
    recommendations = scan_data.get("recommendations", [])
    total_ports = sum(len(d.get("open_ports", [])) for d in devices)

    crit_cnt = sum(1 for f in findings if f.get("severity") == "Critical")
    high_cnt = sum(1 for f in findings if f.get("severity") == "High")

    find_col = CYBER_PALETTE["critical"] if (crit_cnt + high_cnt) > 0 else CYBER_PALETTE["neon_green"]
    preview_html = textwrap.dedent(f"""
    <div class="netguard-card" style="background: #111C2E; border: 1px solid #1E2D4A; margin-bottom: 20px;">
        <h3 style="color: #F3F7FF; font-size: 1.25rem; font-weight: 800; margin-bottom: 8px;">
            Dossier Package Preview: {scan_data.get('scan_id')}
        </h3>
        <div style="font-size: 0.85rem; color: #91A3B8; margin-bottom: 16px;">
            <b>Target Network:</b> <span style="color: #00D9FF;">{scan_data.get('target')}</span> &nbsp;|&nbsp; 
            <b>Audit Timestamp:</b> {scan_data.get('scan_time')[:19].replace('T', ' ')} &nbsp;|&nbsp;
            <b>Scan Mode:</b> {scan_data.get('scan_mode', 'real').upper()}
        </div>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 14px; margin-bottom: 18px;">
            <div style="background: #0D1422; border: 1px solid #1E2D4A; padding: 14px; border-radius: 8px;">
                <span style="font-size: 0.75rem; color: #91A3B8; text-transform: uppercase; font-weight: 600;">Hygiene Score</span>
                <div style="font-size: 1.45rem; font-weight: 800; color: #00D9FF; font-family: monospace;">{score}/100</div>
            </div>
            <div style="background: #0D1422; border: 1px solid #1E2D4A; padding: 14px; border-radius: 8px;">
                <span style="font-size: 0.75rem; color: #91A3B8; text-transform: uppercase; font-weight: 600;">Assets Audited</span>
                <div style="font-size: 1.45rem; font-weight: 800; color: #F3F7FF; font-family: monospace;">{len(devices)}</div>
            </div>
            <div style="background: #0D1422; border: 1px solid #1E2D4A; padding: 14px; border-radius: 8px;">
                <span style="font-size: 0.75rem; color: #91A3B8; text-transform: uppercase; font-weight: 600;">Open Ports</span>
                <div style="font-size: 1.45rem; font-weight: 800; color: #8B5CF6; font-family: monospace;">{total_ports}</div>
            </div>
            <div style="background: #0D1422; border: 1px solid #1E2D4A; padding: 14px; border-radius: 8px;">
                <span style="font-size: 0.75rem; color: #91A3B8; text-transform: uppercase; font-weight: 600;">Risk Findings</span>
                <div style="font-size: 1.45rem; font-weight: 800; color: {find_col}; font-family: monospace;">{len(findings)}</div>
            </div>
        </div>

        <div style="color: #CBD5E1; font-size: 0.85rem; line-height: 1.5;">
            <b>Included Sections in PDF Document:</b>
            <ul style="margin: 6px 0 0 16px; padding: 0; color: #91A3B8;">
                <li>Executive Summary & Quantitative Security Metrics</li>
                <li>Discovered Subnet Endpoint Inventory & Listening Port Analysis</li>
                <li>Prioritized Vulnerability Findings (with Evidence, Impact & Solutions)</li>
                <li>Remediation Action Checklist (Pending vs Resolved Tracker)</li>
                <li>Verification Methodologies & Advisory Disclaimer</li>
            </ul>
        </div>
    </div>
    """)
    st.html(preview_html)

    # PDF Generation & Download Action
    with st.spinner("Compiling ReportLab PDF Document..."):
        try:
            pdf_bytes = generate_pdf_report(scan_data)
            file_name = f"NetGuard_Audit_{scan_data.get('scan_id')}.pdf"

            # Award XP for generating report (prevents duplicates via award_xp)
            award_xp("REPORT_GENERATED", scan_data.get("scan_id"), 100, f"Generated audit PDF for {scan_data.get('scan_id')}")

            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                st.download_button(
                    label="📥 DOWNLOAD EXECUTIVE PDF AUDIT REPORT",
                    data=pdf_bytes,
                    file_name=file_name,
                    mime="application/pdf",
                    use_container_width=True
                )
        except Exception as e:
            st.error(f"Failed to generate PDF report: {str(e)}")
