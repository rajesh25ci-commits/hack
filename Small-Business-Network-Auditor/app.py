"""
NETGUARD - Main Application Entrypoint
Small Business Network Auditor & Gamified Cybersecurity Command Center
"Know Your Network. Find Your Risks. Secure Your Business."
"""

import textwrap
import streamlit as st
from config import APP_NAME, APP_SUBTITLE, APP_TAGLINE, APP_VERSION
from database import init_db, get_latest_scan, get_gamification_profile
from dashboard.styles import (
    apply_custom_theme,
    render_top_nav,
    get_logo_html,
    render_commander_sidebar_widget
)

# Import all 13 page views
from dashboard.home import render_landing_page
from dashboard.overview import render_overview_page
from dashboard.missions import render_missions_page
from dashboard.scanner import render_scanner_page
from dashboard.devices import render_devices_page
from dashboard.port_analysis import render_port_analysis_page
from dashboard.security import render_security_page
from dashboard.ai_assistant import render_ai_assistant_page
from dashboard.recommendations import render_recommendations_page
from dashboard.score import render_score_page
from dashboard.history import render_history_page
from dashboard.comparison import render_comparison_page
from dashboard.reports import render_reports_page


def main():
    """Main Streamlit application lifecycle."""
    # 1. Streamlit Page Configuration
    st.set_page_config(
        page_title="NETGUARD — Small Business Network Auditor",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # 2. Initialize Database & Styles
    init_db()
    apply_custom_theme()

    # 3. Session State & Profile Initialization
    if "current_page" not in st.session_state:
        st.session_state["current_page"] = "Landing Page"

    if "active_scan" not in st.session_state:
        latest = get_latest_scan()
        st.session_state["active_scan"] = latest

    active_scan = st.session_state.get("active_scan")
    profile = get_gamification_profile()

    # 4. Sidebar Navigation & Commander Dossier
    with st.sidebar:
        st.html(get_logo_html(40))
        st.caption(f"**{APP_SUBTITLE}** • `{APP_VERSION}`")

        # Live Commander Rank & XP Progress Widget
        render_commander_sidebar_widget(profile)

        st.divider()

        nav_options = [
            "🏠 Command Home",
            "📊 SOC Dashboard",
            "🏆 Missions & Trophies",
            "⚡ Network Scanner",
            "🖥️ Device Discovery",
            "🔌 Open Port Analysis",
            "🛡️ Security Findings",
            "🧠 AI Security Assistant",
            "📋 Recommendations",
            "🎯 Security Score",
            "🕒 Scan History",
            "📈 Before & After Comparison",
            "📄 PDF Audit Reports"
        ]

        # Map internal page name to radio label
        page_to_nav = {
            "Landing Page": "🏠 Command Home",
            "Dashboard": "📊 SOC Dashboard",
            "Missions & Achievements": "🏆 Missions & Trophies",
            "Network Scanner": "⚡ Network Scanner",
            "Device Discovery": "🖥️ Device Discovery",
            "Open Port Analysis": "🔌 Open Port Analysis",
            "Security Findings": "🛡️ Security Findings",
            "AI Security Assistant": "🧠 AI Security Assistant",
            "Recommendations": "📋 Recommendations",
            "Security Score": "🎯 Security Score",
            "Scan History": "🕒 Scan History",
            "Before & After Comparison": "📈 Before & After Comparison",
            "PDF Audit Reports": "📄 PDF Audit Reports"
        }

        curr_label = page_to_nav.get(st.session_state["current_page"], "🏠 Command Home")
        default_idx = nav_options.index(curr_label) if curr_label in nav_options else 0

        selected_nav = st.radio("Navigation Console", nav_options, index=default_idx)

        # Reverse map selection back to page name
        nav_to_page = {v: k for k, v in page_to_nav.items()}
        target_page = nav_to_page[selected_nav]

        if target_page != st.session_state["current_page"]:
            st.session_state["current_page"] = target_page
            st.rerun()

        st.divider()

        # Quick Demo Action in Sidebar
        st.markdown("##### Tactical Quick Actions")
        if st.button("🎮 Load Demo Network", use_container_width=True, help="Immediately populate realistic small business audit findings (Retail POS, Router, NAS)."):
            st.session_state["auto_load_demo"] = True
            st.session_state["current_page"] = "Network Scanner"
            st.rerun()

        st.html(textwrap.dedent("""
        <div style="font-size: 0.72rem; color: #64748B; text-align: center; border-top: 1px solid #1E2D4A; padding-top: 10px; margin-top: 14px;">
            NETGUARD Command Engine<br/>
            Defensive Network Auditing<br/>
            RFC 1918 Private Scopes
        </div>
        """))

    # 5. Top Navigation Header Bar (except on Landing Page)
    if st.session_state["current_page"] != "Landing Page":
        render_top_nav(active_scan, profile=profile)

    # 6. Page Routing
    current_page = st.session_state["current_page"]

    if current_page == "Landing Page":
        render_landing_page()
    elif current_page == "Dashboard":
        render_overview_page()
    elif current_page == "Missions & Achievements":
        render_missions_page()
    elif current_page == "Network Scanner":
        render_scanner_page()
    elif current_page == "Device Discovery":
        render_devices_page()
    elif current_page == "Open Port Analysis":
        render_port_analysis_page()
    elif current_page == "Security Findings":
        render_security_page()
    elif current_page == "AI Security Assistant":
        render_ai_assistant_page()
    elif current_page == "Recommendations":
        render_recommendations_page()
    elif current_page == "Security Score":
        render_score_page()
    elif current_page == "Scan History":
        render_history_page()
    elif current_page == "Before & After Comparison":
        render_comparison_page()
    elif current_page == "PDF Audit Reports":
        render_reports_page()


if __name__ == "__main__":
    main()
