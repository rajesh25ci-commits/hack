# NETGUARD — Small Business Network Auditor

<p align="center">
  <img src="https://img.shields.io/badge/Security-Defensive_Auditor-00E5FF?style=for-the-badge&logo=shield" alt="Security" />
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python" alt="Python" />
  <img src="https://img.shields.io/badge/Frontend-Streamlit-FF4B4B?style=for-the-badge&logo=streamlit" alt="Streamlit" />
  <img src="https://img.shields.io/badge/Database-SQLite-003B57?style=for-the-badge&logo=sqlite" alt="SQLite" />
  <img src="https://img.shields.io/badge/Tests-Pytest_Passing-10B981?style=for-the-badge&logo=pytest" alt="Pytest" />
</p>

> **"Know Your Network. Find Your Risks. Secure Your Business."**

**NETGUARD** is a commercial-grade, defensive cybersecurity auditing web application engineered specifically for retail stores, supermarkets, clinics, and small offices. Non-technical business owners can scan authorized private local networks, identify exposed legacy protocols, understand their risks in plain English, track remediation actions, and download board-ready executive PDF audit reports.

---

## 📑 Table of Contents

- [Key Capabilities & Features](#-key-capabilities--features)
- [Application Views & Workflow](#-application-views--workflow)
- [Technology Stack](#-technology-stack)
- [Six-Member Hackathon Team Responsibilities](#-six-member-hackathon-team-responsibilities)
- [Installation & Setup](#-installation--setup)
- [Optional Nmap Installation](#-optional-nmap-installation)
- [AI API Configuration](#-ai-api-configuration)
- [Running the Application](#-running-the-application)
- [How to Use the Network Scanner](#-how-to-use-the-network-scanner)
- [Safety & Ethical Constraints](#-safety--ethical-constraints)
- [Verification & Test Suite](#-verification--test-suite)

---

## 🌟 Key Capabilities & Features

1. **Defensive Subnet Validation:**
   - Strictly enforces private RFC 1918 and loopback scopes (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`).
   - Rejects public IP scanning and limits subnet size to `/24` to prevent denial of service or network congestion.
   - Requires explicit ownership/authorization confirmation before any probe begins.

2. **Dual Scanning Engines (Nmap + Native Python Sockets):**
   - Automatically utilizes `nmap` if installed on the host.
   - Seamlessly falls back to a multi-threaded native `socket` scanner with banner grabbing and timeouts when Nmap is not present.
   - Includes a safe, clearly labelled **Simulated Demo Mode** modeling a retail point-of-sale (POS) environment for instant evaluation.

3. **Deterministic Security Analysis Engine:**
   - Detects Telnet exposure (Port 23 - Critical).
   - Detects cleartext FTP (Port 21 - High).
   - Detects exposed SMB / NetBIOS (Ports 445/139 - High).
   - Detects Remote Desktop Protocol without NLA (Port 3389 - High).
   - Detects exposed database listeners (MySQL, MSSQL, PostgreSQL, Redis, MongoDB).
   - Detects unencrypted VNC screen sharing (Port 5900 - High).
   - Detects plain HTTP web administrative portals lacking HTTPS (Ports 80/8080 - Medium).
   - Detects broad attack surface / excessive listening ports (Low).

4. **AI Cybersecurity Assistant:**
   - Generates structured 5-part breakdowns for every finding:
     1. *What happened?*
     2. *Why is this risky?*
     3. *How could it affect the business?*
     4. *How can the user fix it?*
     5. *How can the user verify the fix?*
   - Interactive conversational chat providing guidance on Wi-Fi isolation, POS security, and ransomware defense.
   - Active offline rule-based knowledge base fallback ensuring 100% functionality even without an API key.

5. **Transparent Security Hygiene Score (0-100):**
   - Deterministic mathematical deduction formula:
     - Critical: -25 pts (capped at -60)
     - High: -15 pts (capped at -45)
     - Medium: -8 pts (capped at -30)
     - Low: -3 pts (capped at -15)
   - Categorized into *Excellent (90-100)*, *Good (75-89)*, *Needs Improvement (50-74)*, and *Poor (0-49)*.

6. **Actionable Remediation Center:**
   - Track recommendations by priority and status (`Pending` vs `Resolved`).
   - Add internal notes and engineer verification logs persisted in SQLite.

7. **Before & After Comparison:**
   - Quantifies security improvements across historical audits.
   - Highlights newly detected exposures and confirmed remediated risks.

8. **Executive PDF Audit Reports:**
   - Generates branded, board-ready audit reports using ReportLab.
   - One-click instant PDF download.

---

## 🖥️ Application Views & Workflow

| Page # | View Name | Purpose |
|---|---|---|
| **Page 1** | **Landing Page** | Product introduction, value proposition, why SMBs need network security, and quick-start actions. |
| **Page 2** | **Dashboard / Overview** | Metric cards, Plotly score gauge, risk severity donut, open port frequencies, and recent scan logs. |
| **Page 3** | **Network Scanner** | Target input, private CIDR validation, port presets, authorization checkbox, and progress bar. |
| **Page 4** | **Device Discovery** | Inventory of discovered network devices, MAC addresses, hostnames, and risk levels. |
| **Page 5** | **Open Port Analysis** | Port-by-port technical inspection, banner identification, and protocol security context. |
| **Page 6** | **Security Findings** | Algorithmic findings ledger with evidence strings, solutions, and verification commands. |
| **Page 7** | **AI Security Assistant** | 5-point structured finding explainer + interactive context-aware cybersecurity chat. |
| **Page 8** | **Recommendations** | Actionable checklist with pending/resolved status toggles and engineer notes. |
| **Page 9** | **Security Score** | Interactive Plotly gauge, score deduction ledger, and tier explanations. |
| **Page 10** | **Scan History** | Persistent SQLite audit records with search, details loading, and JSON export. |
| **Page 11** | **Before & After Comparison** | Side-by-side delta between two scans (score progression, new vs resolved risks). |
| **Page 12** | **PDF Audit Reports** | Executive ReportLab PDF generation with single-click download. |

---

## 🛠️ Technology Stack

- **Frontend:** Streamlit 1.35+, Custom Cybersecurity CSS, Plotly Dark Theme
- **Backend:** Python 3.10+, Socket, IPAddress, Subprocess, Python-Nmap
- **Security Engine:** Rule-based expert system, deterministic deduction scoring
- **AI Integration:** Google Gemini API / OpenAI API with rich offline rule-based fallback
- **Database:** SQLite3 with relational foreign keys and parameterized SQL queries
- **Reports:** ReportLab 5.0+ PDF compiler
- **Test Harness:** Pytest 8.0+

---

## 👥 Six-Member Hackathon Team Responsibilities

```
                                  NETGUARD PLATFORM
                                         │
        ┌────────────────────────────────┼────────────────────────────────┐
        │                                │                                │
     TEAM 1                           TEAM 2                           TEAM 3
Network Scanning             Security Analysis & AI            Dashboard & Persistence
        │                                │                                │
  ┌─────┴─────┐                    ┌─────┴─────┐                    ┌─────┴─────┐
  │           │                    │           │                    │           │
Member 1    Member 2             Member 3    Member 4             Member 5    Member 6
Device      Port                 Security    AI                   Frontend    Database &
Discovery   Scanner              Analyzer    Assistant            UI / UX     PDF Reports
```

- **Member 1 (Device Discovery):** Implemented `network_scanner/device_discovery.py` covering local IP detection, private subnet boundary validation, ARP MAC lookup, reverse DNS resolution, and simulated retail host generation.
- **Member 2 (Port Scanner):** Implemented `network_scanner/port_scanner.py` covering Nmap unprivileged TCP connect integration, native socket scanner fallback, service banner grabbing, timeouts, and JSON output formatting.
- **Member 3 (Security Analyzer):** Implemented `security_analysis/security_analyzer.py` and `security_analysis/risk_scoring.py` covering the deterministic vulnerability rule engine, finding generation, and weighted risk deductions.
- **Member 4 (AI Assistant):** Implemented `security_analysis/ai_assistant.py` covering LLM API connectivity, context injection, 5-point structured finding explanations, and offline expert knowledge-base fallback.
- **Member 5 (Frontend Developer):** Implemented `app.py` and all 12 page views in `dashboard/` with the dark navy cybersecurity SaaS design system, responsive layouts, and Plotly visualizations.
- **Member 6 (Database & Reports):** Implemented `database/database.py` (relational SQLite schema with 5 tables and comparisons) and `reports/report_generator.py` (ReportLab executive PDF generation).

---

## 📥 Installation & Setup

### 1. Clone or Open the Workspace
```bash
git clone https://github.com/your-org/Small-Business-Network-Auditor.git
cd Small-Business-Network-Auditor
```

### 2. Create and Activate a Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🔧 Optional Nmap Installation

NetGuard **does not require Nmap** because it includes a built-in multi-threaded Python socket scanner that works out of the box on any system. However, for enhanced OS detection:

- **Windows:** Download the official setup from [nmap.org/download.html](https://nmap.org/download.html) and ensure Nmap is added to your system `PATH`.
- **Linux (Ubuntu/Debian):**
  ```bash
  sudo apt-get update && sudo apt-get install -y nmap
  ```
- **macOS:**
  ```bash
  brew install nmap
  ```

---

## 🔑 AI API Configuration

NetGuard runs **100% functional out of the box** using its built-in rule-based knowledge engine. If you wish to enable live LLM generation:

1. Copy the example configuration:
   ```bash
   cp .env.example .env
   ```
2. Open `.env` and configure your API key:
   ```env
   # Google Gemini API
   GEMINI_API_KEY=your_gemini_api_key_here

   # Or OpenAI API
   OPENAI_API_KEY=your_openai_api_key_here
   ```

---

## 🚀 Running the Application

Launch the Streamlit web server:
```bash
python -m streamlit run app.py
```
Open your browser at:
```
http://localhost:8501
```

---

## 🔍 How to Use the Network Scanner

1. **Navigate to the Scanner:** Select `⚡ Network Scanner` in the sidebar or click `🚀 Launch Network Audit Now` on the Landing Page.
2. **Review Target Range:** NetGuard automatically detects your local IP and suggests a `/24` private subnet (e.g., `192.168.1.0/24` or `127.0.0.1`).
3. **Select Scan Mode:**
   - **Real Network Scan:** Safely audits your live authorized private network.
   - **Simulated Demo Network:** Immediately generates a realistic retail SMB network with a router, POS terminal, NAS, printer, and legacy workstations.
4. **Select Port Preset:** Choose between *Quick Top 20*, *Standard Top 60*, or *High-Risk Insecure Protocols*.
5. **Confirm Authorization:** Check the mandatory authorization confirmation box.
6. **Click Execute Security Audit:** Watch the live progress bar as devices are discovered, ports are audited, rules are evaluated, and results are saved to SQLite.
7. **Review & Remediate:** Navigate to the Dashboard, inspect findings, consult the AI Assistant, mark fixes as resolved in Recommendations, and download your branded PDF report.

---

## 🔒 Safety & Ethical Constraints

- **Strictly Defensive:** NetGuard does not contain any exploitation modules, payloads, brute-force engines, or password crackers.
- **RFC 1918 Enforced:** Only private/local address spaces (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`) can be audited. External/public IP scanning is strictly blocked.
- **Subnet Capped:** Scans are limited to `/24` (maximum 256 addresses) to safeguard network stability.
- **SQL Injection Guard:** All database transactions use parameterized queries.
- **Indicative Assessment:** Scores and reports clearly state they are automated hygiene assessments for guidance and do not substitute for certified regulatory compliance audits.

---

## 🧪 Verification & Test Suite

NetGuard features a comprehensive Pytest test suite covering all modules:
```bash
python -m pytest tests/ -v
```

Expected output:
```
============================= test session starts =============================
tests/test_database.py::test_save_and_retrieve_scan PASSED               [  3%]
tests/test_database.py::test_update_recommendation_status PASSED         [  7%]
tests/test_database.py::test_compare_scans PASSED                        [ 11%]
tests/test_database.py::test_delete_scan PASSED                          [ 15%]
tests/test_reports.py::test_generate_pdf_report_valid_data PASSED        [ 19%]
tests/test_reports.py::test_generate_pdf_empty_findings PASSED           [ 23%]
tests/test_scanner.py::test_valid_private_ip PASSED                      [ 26%]
tests/test_scanner.py::test_valid_private_cidr PASSED                    [ 30%]
tests/test_scanner.py::test_loopback_ip PASSED                           [ 34%]
tests/test_scanner.py::test_public_ip_rejected PASSED                    [ 38%]
tests/test_scanner.py::test_invalid_cidr_format PASSED                   [ 42%]
tests/test_scanner.py::test_subnet_too_large PASSED                      [ 46%]
tests/test_scanner.py::test_empty_input PASSED                           [ 50%]
tests/test_scanner.py::test_simulated_device_generation PASSED           [ 53%]
tests/test_scanner.py::test_scan_device_ports_fallback PASSED            [ 57%]
tests/test_scanner.py::test_local_ip_detection PASSED                    [ 61%]
tests/test_scoring.py::test_perfect_score_zero_findings PASSED           [ 65%]
tests/test_scoring.py::test_critical_deduction PASSED                    [ 69%]
tests/test_scoring.py::test_score_floor_and_caps PASSED                  [ 73%]
tests/test_scoring.py::test_medium_and_low_deductions PASSED             [ 76%]
tests/test_security.py::test_empty_devices_analysis PASSED               [ 80%]
tests/test_security.py::test_telnet_detection PASSED                     [ 84%]
tests/test_security.py::test_ftp_and_smb_detection PASSED                [ 88%]
tests/test_security.py::test_exposed_database_detection PASSED           [ 92%]
tests/test_security.py::test_ai_finding_explanation_fallback PASSED      [ 96%]
tests/test_security.py::test_ask_ai_assistant_fallback PASSED            [100%]
============================= 26 passed in 8.50s ==============================
```

---

<p align="center">
  <b>NETGUARD Cybersecurity Systems</b><br/>
  Defensive Network Auditing for Small Business Resilience
</p>
