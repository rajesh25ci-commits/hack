"""
NETGUARD - Page 8: Security Recommendations
Actionable remediation center allowing business owners to prioritize fixes,
track resolution status (Pending/Resolved), record notes, earn XP, and persist progress in SQLite.
"""

import textwrap
import streamlit as st
from database import get_latest_scan, update_recommendation, award_xp
from config import CYBER_PALETTE


def render_recommendations_page():
    """Renders the interactive remediation center."""
    active_scan = st.session_state.get("active_scan")
    if not active_scan:
        active_scan = get_latest_scan()
        if active_scan:
            st.session_state["active_scan"] = active_scan

    if not active_scan:
        st.info("No audit active. Please run a scan from the Network Scanner page first.")
        return

    recommendations = active_scan.get("recommendations", [])
    findings = active_scan.get("findings", [])

    st.html(textwrap.dedent("""
    <div class="netguard-card" style="margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div>
                <div style="font-size: 0.78rem; font-weight: 700; color: #00D9FF; letter-spacing: 0.08em; text-transform: uppercase;">
                    MISSION 04: CITADEL HARDENING & REMEDIATION
                </div>
                <h2 style="color: #F3F7FF; font-size: 1.55rem; font-weight: 800; margin: 2px 0 0 0;">
                    Network Remediation & Action Tracker
                </h2>
                <p style="color: #91A3B8; font-size: 0.88rem; margin-top: 4px; margin-bottom: 0;">
                    Execute priority configuration fixes to eliminate open attack vectors.
                    Mark tasks resolved after applying changes to earn Commander XP and fortify network posture.
                </p>
            </div>
            <div>
                <span class="badge-commander">Hardening Center</span>
            </div>
        </div>
    </div>
    """))

    if not recommendations:
        st.success("🎉 All clear! Zero remediation tasks required for the current network.")
        return

    # Completion Progress Bar
    total_recs = len(recommendations)
    resolved_count = sum(1 for r in recommendations if r.get("status") == "Resolved")
    pct_resolved = (resolved_count / total_recs) if total_recs > 0 else 1.0

    st.html(textwrap.dedent(f"""
    <div style="background: #111C2E; border: 1px solid #1E2D4A; border-radius: 10px; padding: 16px 20px; margin-bottom: 16px;">
        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
            <span style="font-size: 0.92rem; font-weight: 700; color: #F3F7FF;">Remediation Completion Status</span>
            <span style="font-size: 0.92rem; font-weight: 700; color: #00F5A0;">{resolved_count} of {total_recs} Hardened ({int(pct_resolved*100)}%)</span>
        </div>
        <div class="xp-bar-bg" style="height: 10px;">
            <div class="xp-bar-fill" style="width: {min(100, max(4, pct_resolved * 100))}%;"></div>
        </div>
    </div>
    """))

    # Filter Controls
    c_st, c_pr = st.columns([1, 1])
    with c_st:
        status_filter = st.selectbox("Filter Status", options=["All Tasks", "Pending Only", "Resolved Only"])
    with c_pr:
        priority_filter = st.selectbox("Filter Priority", options=["All Priorities", "Critical", "High", "Medium", "Low"])

    filtered_recs = []
    for r in recommendations:
        if status_filter == "Pending Only" and r.get("status") != "Pending":
            continue
        if status_filter == "Resolved Only" and r.get("status") != "Resolved":
            continue
        if priority_filter != "All Priorities" and r.get("priority") != priority_filter:
            continue
        filtered_recs.append(r)

    st.markdown(f"**Showing {len(filtered_recs)} tasks**")
    st.html("<div style='margin-bottom: 16px;'></div>")

    verif_map = {f.get("id"): f.get("verification", "") for f in findings}

    for idx, r in enumerate(filtered_recs):
        f_id = r.get("finding_id", f"REC-{idx}")
        title = r.get("title", "")
        ip = r.get("device_ip", "")
        priority = r.get("priority", "Medium")
        category = r.get("category", "General")
        action = r.get("action", "")
        impact = r.get("impact", "")
        status = r.get("status", "Pending")
        notes = r.get("notes", "")
        verification = verif_map.get(f_id, "Re-run scan to verify.")

        p_color = CYBER_PALETTE["critical"] if priority == "Critical" else (
            CYBER_PALETTE["warning"] if priority == "High" else "#F59E0B"
        )
        is_resolved = (status == "Resolved")

        card_bg = "#111C2E" if not is_resolved else "#0D1E1A"
        border_col = p_color if not is_resolved else CYBER_PALETTE["neon_green"]
        status_pill = '<span class="badge-secure">✓ RESOLVED (+50 XP)</span>' if is_resolved else '<span class="badge-critical">ACTION PENDING</span>'

        st.html(textwrap.dedent(f"""
        <div style="background: {card_bg}; border: 1px solid #1E2D4A; border-left: 5px solid {border_col}; border-radius: 10px; padding: 18px 22px; margin-bottom: 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <div>
                    <span style="font-size: 0.8rem; color: {p_color}; font-weight: 700; text-transform: uppercase;">[{priority} Priority] • {category}</span>
                    <h3 style="color: #F3F7FF; font-size: 1.2rem; font-weight: 700; margin: 2px 0;">{title}</h3>
                    <span style="color: #91A3B8; font-size: 0.85rem;">Device: <b style="color: #00D9FF;">{ip}</b></span>
                </div>
                <div>
                    {status_pill}
                </div>
            </div>

            <div style="margin: 10px 0; color: #CBD5E1; font-size: 0.9rem; line-height: 1.5;">
                <b style="color: #F3F7FF;">Required Action:</b> {action}
            </div>

            <div style="color: #91A3B8; font-size: 0.85rem; margin-bottom: 6px;">
                <b>Defensive Impact:</b> {impact}
            </div>

            <div style="color: #91A3B8; font-size: 0.85rem;">
                <b>Verification Step:</b> <span style="font-family: monospace; color: #00F5A0;">{verification}</span>
            </div>
        </div>
        """))

        # Interactive controls to toggle status & save notes
        col_ctrl1, col_ctrl2 = st.columns([1.5, 3])
        with col_ctrl1:
            if not is_resolved:
                if st.button("✅ MARK AS RESOLVED", key=f"btn_res_{f_id}_{idx}", use_container_width=True):
                    update_recommendation(f_id, "Resolved", notes)
                    r["status"] = "Resolved"
                    award_xp("REMEDIATION_RESOLVED", f_id, 50, f"Resolved remediation task {f_id}")
                    st.toast("🎉 Threat Hardened! +50 XP Awarded to Commander Dossier.")
                    st.rerun()
            else:
                if st.button("↩️ Reopen Task (Pending)", key=f"btn_pen_{f_id}_{idx}", use_container_width=True):
                    update_recommendation(f_id, "Pending", notes)
                    r["status"] = "Pending"
                    st.rerun()

        with col_ctrl2:
            note_val = st.text_input(
                "Internal Engineer Note",
                value=notes or "",
                key=f"note_input_{f_id}_{idx}",
                placeholder="e.g. Disabled Telnet service via systemctl; firewall rule added."
            )
            if note_val != (notes or ""):
                update_recommendation(f_id, status, note_val)
                r["notes"] = note_val
