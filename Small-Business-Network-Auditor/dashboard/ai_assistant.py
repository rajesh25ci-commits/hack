"""
NETGUARD - Page 7: AI Security Assistant
Futuristic cybersecurity AI interface:
- NETGUARD AI CORE with glowing neural orb visual
- Context-aware 5-point structured finding breakdown
- Interactive advisory chat with pre-configured quick prompts
- Mission 06 XP award integration
"""

import textwrap
import streamlit as st
from datetime import datetime
from security_analysis import (
    generate_ai_finding_explanation,
    ask_ai_security_assistant
)
from database import get_latest_scan, award_xp
from config import GEMINI_API_KEY, OPENAI_API_KEY, CYBER_PALETTE


def render_ai_assistant_page():
    """Renders the futuristic AI Security Assistant interface."""
    active_scan = st.session_state.get("active_scan")
    if not active_scan:
        active_scan = get_latest_scan()
        if active_scan:
            st.session_state["active_scan"] = active_scan

    # Futuristic AI Header Banner with Animated Orb
    st.html(textwrap.dedent("""
    <div class="netguard-card" style="margin-bottom: 20px; position: relative; overflow: hidden;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
            <div style="display: flex; align-items: center; gap: 18px;">
                <div style="width: 58px; height: 58px; border-radius: 50%; background: radial-gradient(circle, #00D9FF 0%, #8B5CF6 60%, #070B14 100%); display: flex; align-items: center; justify-content: center; font-size: 1.8rem; box-shadow: 0 0 24px rgba(0, 217, 255, 0.45); border: 2px solid #00D9FF;">
                    🧠
                </div>
                <div>
                    <div style="font-size: 0.78rem; font-weight: 700; color: #00D9FF; letter-spacing: 0.08em; text-transform: uppercase;">
                        MISSION 06: AI NEURAL SYNC
                    </div>
                    <h2 style="color: #F3F7FF; font-size: 1.55rem; font-weight: 800; margin: 2px 0 0 0;">
                        NETGUARD AI CORE ADVISORY
                    </h2>
                    <p style="color: #91A3B8; font-size: 0.88rem; margin-top: 4px; margin-bottom: 0;">
                        Context-aware cybersecurity neural engine translating technical vulnerabilities into actionable plain-English defense tactics.
                    </p>
                </div>
            </div>
            <div>
                <span class="badge-commander">Neural Engine v2.4</span>
            </div>
        </div>
    </div>
    """))

    # Engine Status Bar
    has_api_key = bool(GEMINI_API_KEY or OPENAI_API_KEY or st.session_state.get("custom_api_key"))
    engine_name = "Gemini / OpenAI High-Reasoning LLM Online" if has_api_key else "Deterministic Rule-Based Intelligence Active (Zero Setup Needed)"
    engine_badge = '<span class="badge-secure">⚡ Cloud Neural Model</span>' if has_api_key else '<span class="badge-medium">🛡️ Deterministic Rule Engine</span>'

    st.html(textwrap.dedent(f"""
    <div style="background: #111C2E; border: 1px solid #1E2D4A; border-radius: 8px; padding: 10px 18px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
        <span style="font-size: 0.85rem; color: #CBD5E1;">
            <b>Active Intelligence Mode:</b> {engine_name}
        </span>
        {engine_badge}
    </div>
    """))

    # Tab Interface: 1. Structured Finding Explainer | 2. Interactive Advisory Chat
    tab_explainer, tab_chat = st.tabs(["📋 Structured Finding Breakdown", "💬 Interactive Advisory Chat"])

    # TAB 1: Structured Finding Breakdown
    with tab_explainer:
        st.markdown("#### Select a Network Risk Finding to Analyze")

        if not active_scan or not active_scan.get("findings"):
            st.info("No security findings recorded. Run a scan from the Network Scanner or deploy the simulated demo network.")
        else:
            findings = active_scan.get("findings", [])
            finding_options = {f"{f.get('id')} — [{f.get('severity')}] {f.get('title')} ({f.get('device_ip')})": f for f in findings}

            pre_selected = st.session_state.get("selected_finding_for_ai")
            default_index = 0
            if pre_selected:
                for idx, (label, f_obj) in enumerate(finding_options.items()):
                    if f_obj.get("id") == pre_selected.get("id"):
                        default_index = idx
                        break

            chosen_label = st.selectbox("Choose Threat Finding", options=list(finding_options.keys()), index=default_index)
            chosen_finding = finding_options[chosen_label]

            if st.button("✨ Synthesize AI Remediation Intelligence", use_container_width=True):
                with st.spinner("Analyzing threat vector, blast radius, and tactical remediation..."):
                    breakdown = generate_ai_finding_explanation(chosen_finding)
                    st.session_state[f"breakdown_{chosen_finding['id']}"] = breakdown
                    award_xp("AI_CONSULTATION", f"AI-EXPL-{chosen_finding['id']}", 50, f"Consulted AI on {chosen_finding.get('title')}")

            f_key = f"breakdown_{chosen_finding['id']}"
            if f_key in st.session_state:
                bd = st.session_state[f_key]
                st.html(textwrap.dedent(f"""
                <div style="background: #111C2E; border: 1px solid #1E2D4A; border-radius: 12px; padding: 22px 26px; margin-top: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; border-bottom: 1px solid #1E2D4A; padding-bottom: 10px;">
                        <span style="font-size: 1.15rem; font-weight: 800; color: #00D9FF;">{chosen_finding.get('title')}</span>
                        <span class="badge-low">{bd.get('source', 'Security Engine')}</span>
                    </div>

                    <div style="margin-bottom: 14px;">
                        <b style="color: #F3F7FF; font-size: 0.95rem;">1. What happened?</b>
                        <p style="color: #91A3B8; font-size: 0.88rem; margin: 4px 0 0 0; line-height: 1.5;">{bd.get('what')}</p>
                    </div>

                    <div style="margin-bottom: 14px;">
                        <b style="color: #FF4560; font-size: 0.95rem;">2. Why is this risky?</b>
                        <p style="color: #91A3B8; font-size: 0.88rem; margin: 4px 0 0 0; line-height: 1.5;">{bd.get('why')}</p>
                    </div>

                    <div style="margin-bottom: 14px;">
                        <b style="color: #FFB020; font-size: 0.95rem;">3. How could this affect the business?</b>
                        <p style="color: #91A3B8; font-size: 0.88rem; margin: 4px 0 0 0; line-height: 1.5;">{bd.get('impact')}</p>
                    </div>

                    <div style="margin-bottom: 14px; background: rgba(0, 217, 255, 0.06); padding: 14px; border-radius: 8px; border-left: 3px solid #00D9FF;">
                        <b style="color: #00D9FF; font-size: 0.95rem;">4. How can you fix it?</b>
                        <div style="color: #E2E8F0; font-size: 0.88rem; white-space: pre-line; margin-top: 4px; line-height: 1.5;">{bd.get('fix')}</div>
                    </div>

                    <div style="background: rgba(0, 245, 160, 0.06); padding: 14px; border-radius: 8px; border-left: 3px solid #00F5A0;">
                        <b style="color: #00F5A0; font-size: 0.95rem;">5. How can you verify the fix?</b>
                        <div style="color: #E2E8F0; font-size: 0.88rem; white-space: pre-line; margin-top: 4px; line-height: 1.5;">{bd.get('verify')}</div>
                    </div>
                </div>
                """))

    # TAB 2: Interactive Advisory Chat
    with tab_chat:
        st.markdown("#### NETGUARD AI Security Advisor")
        st.caption("Direct neural link with NetGuard AI. Ask about port configurations, firewall settings, or ransomware prevention.")

        # Suggested Questions Pills
        st.markdown("**Suggested Inquiries:**")
        q_cols = st.columns(4)
        quick_questions = [
            "Explain my network risk score.",
            "What does this open port mean?",
            "How can I secure this device?",
            "Which security issue should I fix first?"
        ]

        preset_to_send = None
        for i, q_text in enumerate(quick_questions):
            with q_cols[i]:
                if st.button(f"💡 {q_text}", key=f"quick_q_{i}", use_container_width=True):
                    preset_to_send = q_text

        # Chat history state
        if "chat_messages" not in st.session_state:
            st.session_state["chat_messages"] = [
                {
                    "role": "assistant",
                    "content": "Commander, I am your **NETGUARD AI Security Advisor**. I have access to your network telemetry and findings. Ask me anything about securing your business network."
                }
            ]

        # Display history
        for msg in st.session_state["chat_messages"]:
            if msg["role"] == "user":
                with st.chat_message("user"):
                    st.write(msg["content"])
            else:
                with st.chat_message("assistant"):
                    st.markdown(msg["content"])

        # Handle Prompt Input
        user_input = st.chat_input("Enter your cybersecurity query...") or preset_to_send

        if user_input:
            # User message
            st.session_state["chat_messages"].append({"role": "user", "content": user_input})
            with st.chat_message("user"):
                st.write(user_input)

            # AI Response
            with st.chat_message("assistant"):
                with st.spinner("Consulting cybersecurity knowledgebase..."):
                    context_data = {
                        "active_scan": active_scan,
                        "score": active_scan.get("risk_score", 100) if active_scan else 100,
                        "findings": active_scan.get("findings", []) if active_scan else [],
                        "devices": active_scan.get("devices", []) if active_scan else []
                    }
                    ai_reply = ask_ai_security_assistant(user_input, context=context_data)
                    st.markdown(ai_reply)

            st.session_state["chat_messages"].append({"role": "assistant", "content": ai_reply})

            # Award XP for genuine interaction
            award_xp("AI_CONSULTATION", f"AI-CHAT-{datetime.now().strftime('%Y%m%d%H%M%S')}", 25, "Consulted NETGUARD AI Advisor")
            st.rerun()
