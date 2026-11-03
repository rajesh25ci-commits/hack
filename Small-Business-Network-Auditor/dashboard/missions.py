"""
NETGUARD - Page: Missions & Achievements Hub
Gamified cybersecurity operations center:
- Commander Dossier (Level, Rank, XP Progress Bar)
- Tactical Missions (Missions 01-06 with real-time status and deploy triggers)
- Collectible Cyber Achievement Badges (locked vs glowing unlocked states)
- Verified XP Activity Ledger
"""

import textwrap
import streamlit as st
from config import MISSIONS_LIST, ACHIEVEMENTS_LIST, COMMANDER_RANKS, CYBER_PALETTE
from database import get_gamification_profile, get_db_connection


def render_missions_page():
    """Renders the gamified missions and achievements command center."""
    profile = get_gamification_profile()

    level = profile.get("level", 1)
    rank = profile.get("rank", "Cyber Recruit")
    total_xp = profile.get("total_xp", 0)
    current_tier_xp = profile.get("current_tier_xp", 0)
    needed_tier_xp = profile.get("needed_tier_xp", 100)
    progress_pct = profile.get("progress_pct", 0)
    next_rank = profile.get("next_rank", "Max Rank")

    stats = profile.get("stats", {})
    scans_count = stats.get("total_scans", 0)
    devices_count = stats.get("total_devices", 0)
    findings_count = stats.get("total_findings", 0)
    resolved_count = stats.get("resolved_count", 0)

    missions = profile.get("missions", [])
    unlocked_badges = profile.get("unlocked_achievements", {})
    completed_missions_count = sum(1 for m in missions if m.get("status") == "Completed")

    # 1. Commander Profile Dossier Card
    st.html(textwrap.dedent(f"""
    <div class="netguard-card" style="padding: 24px 28px; margin-bottom: 24px; position: relative; overflow: hidden;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 20px;">
            <div style="display: flex; align-items: center; gap: 20px;">
                <div style="width: 76px; height: 76px; border-radius: 50%; background: linear-gradient(135deg, #17243A, #0D1422); border: 2px solid #00D9FF; display: flex; align-items: center; justify-content: center; font-size: 2.2rem; box-shadow: 0 0 25px rgba(0, 217, 255, 0.3);">
                    ⚔️
                </div>
                <div>
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px;">
                        <span style="font-size: 0.8rem; font-weight: 700; color: #00F5A0; text-transform: uppercase; letter-spacing: 0.08em; font-family: monospace;">
                            COMMANDER LEVEL {level:02d}
                        </span>
                        <span class="badge-commander">Tactical Officer</span>
                    </div>
                    <h1 style="font-size: 1.85rem; font-weight: 800; color: #F3F7FF; margin: 0; letter-spacing: -0.02em;">
                        {rank}
                    </h1>
                    <div style="font-size: 0.85rem; color: #91A3B8; margin-top: 4px;">
                        Next Promotion: <b style="color: #00D9FF;">{next_rank}</b> • Defensive Cybersecurity Directive
                    </div>
                </div>
            </div>
            <div style="min-width: 260px; text-align: right;">
                <div style="font-size: 0.8rem; color: #91A3B8; margin-bottom: 4px;">Current Progression</div>
                <div style="font-size: 1.6rem; font-weight: 800; color: #00F5A0; font-family: 'JetBrains Mono', monospace;">
                    {current_tier_xp} <span style="font-size: 1rem; color: #64748B;">/ {needed_tier_xp} XP</span>
                </div>
                <div class="xp-bar-bg" style="height: 10px; margin-top: 6px;">
                    <div class="xp-bar-fill" style="width: {min(100, max(4, progress_pct))}%;"></div>
                </div>
                <div style="font-size: 0.72rem; color: #91A3B8; margin-top: 4px;">
                    {int(progress_pct)}% to promotion • Total Career XP: <b style="color: #F3F7FF;">{total_xp}</b>
                </div>
            </div>
        </div>
    </div>
    """))

    # Quick Stats Row
    col_s1, col_s2, col_s3, col_s4 = st.columns(4)
    with col_s1:
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Audits Completed</span>
            <span class="metric-value">{scans_count}</span>
            <span style="font-size: 0.75rem; color: #00D9FF; margin-top: 4px;">Subnet Sweeps</span>
        </div>
        """))
    with col_s2:
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Hosts Discovered</span>
            <span class="metric-value">{devices_count}</span>
            <span style="font-size: 0.75rem; color: #91A3B8; margin-top: 4px;">Audited Assets</span>
        </div>
        """))
    with col_s3:
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Threats Mitigated</span>
            <span class="metric-value" style="color: #00F5A0;">{resolved_count}</span>
            <span style="font-size: 0.75rem; color: #91A3B8; margin-top: 4px;">Hardened Weaknesses</span>
        </div>
        """))
    with col_s4:
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Missions Cleared</span>
            <span class="metric-value" style="color: #8B5CF6;">{completed_missions_count}/{len(missions)}</span>
            <span style="font-size: 0.75rem; color: #91A3B8; margin-top: 4px;">Tactical Objectives</span>
        </div>
        """))

    st.markdown("### 🎯 Tactical Defense Missions")
    st.caption("Complete operational network security objectives to fortify your business defenses and earn Commander XP.")

    # Render Missions Grid
    col_m_left, col_m_right = st.columns(2)

    for idx, m in enumerate(missions):
        target_col = col_m_left if idx % 2 == 0 else col_m_right
        m_id = m.get("id")
        m_title = m.get("title")
        m_desc = m.get("desc")
        m_xp = m.get("xp", 100)
        m_status = m.get("status", "Available")
        m_prog = m.get("progress", 0)
        m_route = m.get("page_target", "Dashboard")

        if m_status == "Completed":
            badge_html = '<span class="badge-secure">✓ COMPLETED</span>'
            border_style = "border-color: rgba(0, 245, 160, 0.45); box-shadow: 0 0 16px rgba(0, 245, 160, 0.1);"
        elif m_status == "In Progress":
            badge_html = '<span class="badge-high">⚡ IN PROGRESS</span>'
            border_style = "border-color: rgba(255, 176, 32, 0.45);"
        else:
            badge_html = '<span class="badge-low">ACTIVE MISSION</span>'
            border_style = "border-color: #1E2D4A;"

        with target_col:
            with st.container(border=True):
                st.html(textwrap.dedent(f"""
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                    <div>
                        <span style="font-size: 0.75rem; font-weight: 700; color: #00D9FF; font-family: monospace;">{m_id}</span>
                        <h3 style="font-size: 1.15rem; font-weight: 700; color: #F3F7FF; margin: 2px 0 0 0;">{m_title}</h3>
                    </div>
                    <div style="text-align: right;">
                        {badge_html}
                        <div style="font-size: 0.75rem; color: #00F5A0; font-weight: 700; margin-top: 4px;">+{m_xp} XP</div>
                    </div>
                </div>
                <p style="font-size: 0.86rem; color: #91A3B8; margin-bottom: 12px; min-height: 40px;">
                    {m_desc}
                </p>
                <div style="display: flex; justify-content: space-between; font-size: 0.72rem; color: #91A3B8; margin-bottom: 4px;">
                    <span>Mission Completion</span>
                    <span>{int(m_prog)}%</span>
                </div>
                <div class="xp-bar-bg" style="height: 6px; margin-bottom: 12px;">
                    <div class="xp-bar-fill" style="width: {m_prog}%;"></div>
                </div>
                """))

                if st.button(f"🚀 Deploy: {m_title}", key=f"btn_deploy_{m_id}", use_container_width=True):
                    st.session_state["current_page"] = m_route
                    st.rerun()

    st.markdown("---")

    # 3. Collectible Achievement Trophies Showcase
    st.markdown("### 🏆 Cyber Defense Trophy Vault")
    st.caption("Rare commemorative awards unlocked upon achieving specific operational milestones.")

    # 4 columns of badges
    b_cols = st.columns(4)
    for b_idx, badge in enumerate(ACHIEVEMENTS_LIST):
        b_col = b_cols[b_idx % 4]
        b_id = badge["id"]
        is_unlocked = b_id in unlocked_badges
        unlocked_at = unlocked_badges.get(b_id, "")[:10] if is_unlocked else None

        with b_col:
            if is_unlocked:
                card_style = "border: 1px solid rgba(0, 245, 160, 0.5); box-shadow: 0 0 20px rgba(0, 245, 160, 0.15); background: linear-gradient(145deg, #111C2E, #14283D);"
                icon_glow = "filter: drop-shadow(0 0 10px #00F5A0);"
                status_pill = f'<span style="font-size: 0.7rem; color: #00F5A0; font-weight: 700;">★ UNLOCKED ({unlocked_at})</span>'
            else:
                card_style = "border: 1px solid #1E2D4A; opacity: 0.65; background: #0D1422;"
                icon_glow = "filter: grayscale(80%);"
                status_pill = '<span style="font-size: 0.7rem; color: #64748B; font-weight: 600;">🔒 LOCKED</span>'

            b_name = badge.get('name') or badge.get('title', 'Achievement')
            b_desc = badge.get('description') or badge.get('desc', '')
            st.html(textwrap.dedent(f"""
            <div style="{card_style} border-radius: 12px; padding: 16px; text-align: center; margin-bottom: 16px; min-height: 220px; display: flex; flex-direction: column; justify-content: space-between;">
                <div>
                    <div style="font-size: 2.6rem; margin-bottom: 8px; {icon_glow}">{badge['icon']}</div>
                    <div style="font-size: 0.95rem; font-weight: 700; color: #F3F7FF; margin-bottom: 4px;">{b_name}</div>
                    <div style="font-size: 0.78rem; color: #91A3B8; line-height: 1.4; margin-bottom: 10px;">{b_desc}</div>
                </div>
                <div>
                    <div style="font-size: 0.72rem; color: #00D9FF; font-weight: 700; margin-bottom: 4px;">+{badge['xp']} XP Reward</div>
                    {status_pill}
                </div>
            </div>
            """))

    # 4. Verified XP Ledger
    st.markdown("---")
    with st.expander("📜 View Verified Commander XP Ledger", expanded=False):
        try:
            conn = get_db_connection()
            events = conn.execute("SELECT event_type, event_key, xp_awarded, timestamp FROM gamification_events ORDER BY timestamp DESC LIMIT 20").fetchall()
            conn.close()

            if events:
                for ev in events:
                    c1, c2, c3 = st.columns([2, 3, 1])
                    with c1:
                        st.caption(f"🕒 {ev['timestamp'][:19].replace('T', ' ')}")
                    with c2:
                        st.write(f"**{ev['event_type']}** (`{ev['event_key']}`)")
                    with c3:
                        st.markdown(f"<span style='color:#00F5A0; font-weight:700;'>+{ev['xp_awarded']} XP</span>", unsafe_allow_html=True)
            else:
                st.caption("No XP events recorded yet. Run your first network audit to begin earning XP!")
        except Exception as e:
            st.caption(f"XP Ledger initialized: {e}")
