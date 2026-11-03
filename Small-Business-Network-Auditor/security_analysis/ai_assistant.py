"""
NETGUARD - Member 4: AI Security Assistant Module
Provides context-aware security explanations, remediation guides,
LLM API integration (Gemini / OpenAI), and robust rule-based fallback.
"""

import json
import os
import requests
from typing import Dict, List, Optional
from config import GEMINI_API_KEY, OPENAI_API_KEY


# Pre-crafted high-fidelity defensive knowledge base for rule-based fallback
KNOWLEDGE_BASE = {
    "telnet": {
        "what": "NetGuard detected that Port 23 is open and running a Telnet server.",
        "why": "Telnet is an obsolete remote terminal protocol created over 40 years ago. It has zero encryption, meaning all text, usernames, and passwords pass over your local cables and Wi-Fi as raw plaintext.",
        "impact": "If an infected device or unauthorized person connects to your office Wi-Fi, they can use free packet-sniffing software to capture administrative passwords and take full control of the device.",
        "fix": "1. Open the device's management interface.\n2. Locate 'Remote Management' or 'Services'.\n3. Disable the Telnet service entirely.\n4. Enable SSH (Secure Shell on Port 22) if remote command-line access is required.",
        "verify": "Run the command 'Test-NetConnection -ComputerName <IP> -Port 23' in PowerShell or run a new NetGuard scan. The port must report as Closed or Timed Out."
    },
    "ftp": {
        "what": "Cleartext File Transfer Protocol (Port 21) was identified listening for incoming connections.",
        "why": "Standard FTP does not secure transmission channels. Both user login credentials and uploaded business documents are exposed in plaintext.",
        "impact": "Confidential financial spreadsheets, customer databases, or proprietary files transferred via FTP can be snooped or altered during transit by attackers on the network.",
        "fix": "1. Migrate file transfers to SFTP (SSH File Transfer Protocol) which uses encrypted Port 22.\n2. If using an on-premise NAS (e.g. Synology, QNAP), disable FTP in Control Panel > File Services and turn on SFTP/FTPS.\n3. Verify anonymous FTP logins are blocked.",
        "verify": "Attempt to connect using an SFTP client (like FileZilla over SFTP port 22) and confirm that Port 21 no longer responds to connection requests."
    },
    "smb": {
        "what": "Windows Server Message Block (SMB) file sharing ports (445 and/or 139) are accessible over the network.",
        "why": "SMB enables network folder sharing. However, legacy versions (specifically SMBv1) possess known protocol vulnerabilities that allow automated worm-like malware propagation.",
        "impact": "Famous ransomware outbreaks (like WannaCry and NotPetya) spread across small business networks by exploiting vulnerable SMB services, encrypting all company shared drives in minutes.",
        "fix": "1. Ensure SMBv1 is disabled on all Windows systems via Windows Features.\n2. Restrict SMB sharing so only designated central file servers share folders, not everyday checkout or staff laptops.\n3. Enforce SMB signing and require passwords for all shared folders.",
        "verify": "Open Windows PowerShell as Administrator and run: 'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'. State should be 'Disabled'."
    },
    "rdp": {
        "what": "Microsoft Remote Desktop Protocol (RDP) listening on Port 3389.",
        "why": "RDP allows remote users to interact with a full Windows desktop. It is the single most targeted protocol by cybercriminals scanning for remote access points.",
        "impact": "If weak or reused passwords exist on user accounts, automated bots can brute-force the login and gain complete desktop control, installing spyware or ransomware.",
        "fix": "1. Enforce Network Level Authentication (NLA) under System Properties > Remote.\n2. Ensure strong, 14+ character unique passwords for all Windows accounts.\n3. Never forward Port 3389 through your router directly to the Internet; always require a secure VPN.",
        "verify": "Verify Remote Settings: Confirm 'Allow connections only from computers running Remote Desktop with Network Level Authentication' is checked."
    },
    "database": {
        "what": "A database server (MySQL, MSSQL, PostgreSQL, Redis, or MongoDB) is listening on an exposed network port.",
        "why": "Database servers contain raw business data. Exposing them to the entire local subnet means any device (including guest phones or POS tablets) can attempt database connections.",
        "impact": "Unauthorized employees, contractors, or rogue devices could dump customer records, point-of-sale sales logs, or delete database tables.",
        "fix": "1. If the database only serves local software on the same machine, edit the configuration to set 'bind-address = 127.0.0.1'.\n2. If other servers need access, configure the host firewall to whitelist specific IP addresses only.\n3. Change all default passwords (such as 'root' with empty password).",
        "verify": "From a different machine on the network, try running 'Test-NetConnection -ComputerName <IP> -Port <PORT>'. The firewall should reject or drop the connection."
    },
    "vnc": {
        "what": "VNC (Virtual Network Computing) remote desktop listener identified on Port 5900.",
        "why": "Standard VNC uses weak DES-based authentication (often limited to 8 characters) and transmits screen displays unencrypted.",
        "impact": "Attackers can intercept live screen captures of cashier checkouts, credit card input screens, or administrator consoles.",
        "fix": "1. Turn off VNC on workstations where not required.\n2. If needed for remote support, use encrypted solutions like AnyDesk/TeamViewer or tunnel VNC over an SSH tunnel.\n3. Never leave VNC open without a strong password.",
        "verify": "Run NetGuard scanner again to ensure Port 5900 is closed."
    },
    "http": {
        "what": "Device administration panel running over plain HTTP (Port 80/8080) without HTTPS.",
        "why": "Cleartext HTTP does not encrypt session tokens or login passwords entered into web forms.",
        "impact": "Anyone on the same Wi-Fi or local network switch can intercept administrator passwords entered on router or printer login pages.",
        "fix": "1. Enable HTTPS / SSL in the device settings.\n2. Force automatic HTTP-to-HTTPS redirect.\n3. Change factory default passwords immediately.",
        "verify": "Navigate to https://<IP> in your browser and confirm that HTTPS loads."
    }
}


def call_gemini_api(prompt: str, api_key: str) -> Optional[str]:
    """
    Direct Gemini REST API integration using official Google endpoint.
    Uses google gemini-1.5-flash or gemini-2.0-flash.
    """
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 800
            }
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "")
    except Exception:
        pass
    return None


def call_openai_api(prompt: str, api_key: str) -> Optional[str]:
    """
    Direct OpenAI REST API integration.
    """
    try:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        payload = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "system", "content": "You are NetGuard AI, an expert cybersecurity consultant for small businesses. Explain network security findings clearly and provide actionable, step-by-step remediation advice. Do not hallucinate or claim to have fixed anything."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 800
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")
    except Exception:
        pass
    return None


def generate_ai_finding_explanation(finding: Dict) -> Dict[str, str]:
    """
    Generates structured 5-part explanation for any finding:
    1. What happened?
    2. Why is this risky?
    3. How could it affect the business?
    4. How can the user fix it?
    5. How can the user verify the fix?
    Uses LLM API if key is present, otherwise falls back to deterministic rule-based knowledge.
    """
    title = finding.get("title", "")
    ip = finding.get("device_ip", "")
    port = finding.get("port", "")
    service = str(finding.get("service", "")).lower()
    evidence = finding.get("evidence", "")

    # Try LLM if configured
    prompt = (
        f"You are NetGuard AI, a friendly cybersecurity auditor for small business owners.\n"
        f"Analyze this security finding:\n"
        f"Device: {ip}\n"
        f"Finding: {title}\n"
        f"Port: {port}\n"
        f"Service: {service}\n"
        f"Evidence: {evidence}\n\n"
        f"Format your response as valid JSON with exactly these 5 keys:\n"
        f'{{"what_happened": "...", "why_risky": "...", "business_impact": "...", "how_to_fix": "...", "how_to_verify": "..."}}\n'
        f"Keep the language plain, non-academic, and easy for non-technical retail or office managers."
    )

    llm_response = None
    if GEMINI_API_KEY:
        llm_response = call_gemini_api(prompt, GEMINI_API_KEY)
    elif OPENAI_API_KEY:
        llm_response = call_openai_api(prompt, OPENAI_API_KEY)

    if llm_response:
        try:
            # Clean markdown code blocks if returned
            clean_json = llm_response.strip()
            if clean_json.startswith("```json"):
                clean_json = clean_json[7:]
            if clean_json.startswith("```"):
                clean_json = clean_json[3:]
            if clean_json.endswith("```"):
                clean_json = clean_json[:-3]
            data = json.loads(clean_json.strip())
            return {
                "what": data.get("what_happened", finding.get("explanation", "")),
                "why": data.get("why_risky", ""),
                "impact": data.get("business_impact", ""),
                "fix": data.get("how_to_fix", finding.get("solution", "")),
                "verify": data.get("how_to_verify", finding.get("verification", "")),
                "source": "AI Generated (Live LLM)"
            }
        except Exception:
            pass

    # High-quality Rule-based Fallback
    matched_kb = None
    for key, kb in KNOWLEDGE_BASE.items():
        if key in title.lower() or key in service or (isinstance(port, int) and (
            (key == "telnet" and port == 23) or
            (key == "ftp" and port == 21) or
            (key == "smb" and port in [139, 445]) or
            (key == "rdp" and port == 3389) or
            (key == "vnc" and port == 5900) or
            (key == "database" and port in [1433, 3306, 5432, 6379, 27017]) or
            (key == "http" and port in [80, 8080])
        )):
            matched_kb = kb
            break

    if matched_kb:
        return {
            "what": matched_kb["what"].replace("<IP>", ip).replace("<PORT>", str(port)),
            "why": matched_kb["why"],
            "impact": matched_kb["impact"],
            "fix": matched_kb["fix"],
            "verify": matched_kb["verify"].replace("<IP>", ip).replace("<PORT>", str(port)),
            "source": "Rule-Based Security Engine (Active Fallback)"
        }

    # Generic defensive fallback
    return {
        "what": f"NetGuard identified service '{service}' listening on port {port} on device {ip}.",
        "why": "Unnecessary open ports broaden the attack surface and may expose services with unpatched bugs or weak default passwords.",
        "impact": "Attackers can probe open services to identify software versions and exploit unpatched security flaws.",
        "fix": finding.get("solution", "Review device configuration and close any ports not strictly required."),
        "verify": finding.get("verification", f"Re-scan host {ip} to confirm port {port} is closed."),
        "source": "Rule-Based Security Engine (Active Fallback)"
    }


def ask_ai_security_assistant(
    user_query: str,
    scan_context: Optional[Dict] = None,
    conversation_history: Optional[List[Dict]] = None
) -> str:
    """
    Interactive Q&A cybersecurity assistant.
    Provides context-aware answers based on current scan findings.
    """
    if not user_query or not user_query.strip():
        return "Please ask a question regarding your network security or scan results."

    # Format context summary
    context_str = "No scan performed yet."
    if scan_context:
        target = scan_context.get("target", "N/A")
        dev_count = len(scan_context.get("devices", []))
        findings = scan_context.get("findings", [])
        score = scan_context.get("risk_score", "N/A")
        crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
        high_count = sum(1 for f in findings if f.get("severity") == "High")
        context_str = (
            f"Target Network: {target}\n"
            f"Total Discovered Devices: {dev_count}\n"
            f"Security Score: {score}/100\n"
            f"Critical Findings: {crit_count}\n"
            f"High Findings: {high_count}\n"
            f"Findings summary: {', '.join([f['title'] for f in findings[:5]])}"
        )

    prompt = (
        f"You are NetGuard AI, an expert cybersecurity advisor assisting a small business owner.\n"
        f"Current Network Audit Context:\n{context_str}\n\n"
        f"User Question: {user_query}\n\n"
        f"Instructions:\n"
        f"- Give practical, concise, safe instructions.\n"
        f"- Emphasize defense, least privilege, and practical verification.\n"
        f"- Never claim to fix systems automatically."
    )

    if GEMINI_API_KEY:
        ans = call_gemini_api(prompt, GEMINI_API_KEY)
        if ans:
            return ans
    elif OPENAI_API_KEY:
        ans = call_openai_api(prompt, OPENAI_API_KEY)
        if ans:
            return ans

    # Intelligent fallback responses for common SMB questions
    q_lower = user_query.lower()
    if "telnet" in q_lower:
        return (
            "**NetGuard Security Advisory on Telnet:**\n\n"
            "Telnet is highly vulnerable because it transmits usernames and passwords across the network in unencrypted plaintext. "
            "Anyone running network capture software on your office network can steal those credentials instantly.\n\n"
            "**Recommended Action:**\n"
            "1. Log into your device's administrative settings.\n"
            "2. Turn off Telnet service completely.\n"
            "3. Enable SSH (Secure Shell on port 22) instead for secure, encrypted management."
        )
    elif "ftp" in q_lower:
        return (
            "**NetGuard Security Advisory on FTP:**\n\n"
            "Cleartext FTP exposes transferred files and passwords to anyone on the same local network. "
            "For small businesses handling customer records, payroll, or business documents, this presents a severe data privacy risk.\n\n"
            "**Recommended Action:**\n"
            "Transition to **SFTP** (over SSH port 22) or **FTPS** (FTP with TLS/SSL). Both encrypt your files and credentials."
        )
    elif "smb" in q_lower or "ransomware" in q_lower:
        return (
            "**NetGuard Security Advisory on SMB & Ransomware:**\n\n"
            "Server Message Block (SMB) on ports 445 and 139 is the primary mechanism malicious software and ransomware (like WannaCry) "
            "use to spread laterally across office computers.\n\n"
            "**Recommended Action:**\n"
            "1. Disable legacy SMBv1 on all computers.\n"
            "2. Ensure only designated file servers share folders.\n"
            "3. Keep all Windows computers fully patched."
        )
    elif "score" in q_lower:
        return (
            "**How NetGuard Security Scoring Works:**\n\n"
            "NetGuard calculates an indicative 0-100 hygiene score based on discovered network services:\n"
            "- Critical Risks (e.g. Telnet, unprotected caches): -25 pts\n"
            "- High Risks (e.g. unencrypted FTP, exposed SMB, raw databases): -15 pts\n"
            "- Medium Risks (e.g. unencrypted HTTP admin interfaces): -8 pts\n"
            "- Low Risks (e.g. excessive open ports): -3 pts\n\n"
            "Resolving high and critical findings will quickly elevate your security score to **Good** (75+) or **Excellent** (90+)."
        )
    elif "wifi" in q_lower or "guest" in q_lower:
        return (
            "**Wi-Fi Security Best Practices for Small Businesses:**\n\n"
            "1. **Isolate Guest Wi-Fi:** Always create a separate 'Guest' network for customers and personal phones with Client Isolation enabled.\n"
            "2. **Protect Business Systems:** Keep POS terminals, office PCs, and file servers on a private, encrypted WPA3 or WPA2-Enterprise Wi-Fi network.\n"
            "3. **Change Router Defaults:** Change default router admin passwords and disable remote management over WAN."
        )
    else:
        return (
            f"**NetGuard Security Assistant:**\n\n"
            f"Based on your current network posture ({context_str.splitlines()[2] if 'Security Score' in context_str else 'Ready to audit'}), "
            f"our key recommendation is to review any detected Critical and High severity findings first in the **Recommendations** tab.\n\n"
            f"Key hygiene steps:\n"
            f"1. Close unused ports and disable legacy protocols (Telnet, FTP, SMBv1).\n"
            f"2. Enforce encrypted protocols (SSH, HTTPS, SFTP).\n"
            f"3. Re-run an audit to verify your score improvement."
        )


def generate_security_briefing(scan_data: Dict) -> str:
    """
    Generates an executive briefing paragraph summarizing the audit findings.
    """
    score = scan_data.get("risk_score", 100)
    devices = scan_data.get("devices", [])
    findings = scan_data.get("findings", [])
    crit = sum(1 for f in findings if f.get("severity") == "Critical")
    high = sum(1 for f in findings if f.get("severity") == "High")

    if score >= 90:
        return (
            f"Executive Summary: Network audit of {len(devices)} device(s) demonstrates strong security hygiene "
            f"with a score of {score}/100. No critical security exposures were detected."
        )
    elif score >= 75:
        return (
            f"Executive Summary: Audit completed with an overall score of {score}/100 across {len(devices)} device(s). "
            f"Network exhibits acceptable hygiene, but {high} high-priority finding(s) require remediation."
        )
    else:
        return (
            f"Executive Summary: Action required. Audit identified {crit} critical and {high} high-risk exposures "
            f"across {len(devices)} device(s), resulting in a security score of {score}/100. Prioritize immediate remediation "
            f"of unencrypted and exposed administrative protocols."
        )
