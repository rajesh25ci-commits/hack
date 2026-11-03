"""
NETGUARD - Interactive Plotly Chart Visualizations
Generates high-tech cyber defense visualizations:
- 2D Network Topology Node-Link Graph
- Security Score Circular/Semi-circular Gauge
- Vulnerability Severity Donut Chart
- Open Ports Frequency Bar Chart
- Security Trend Line Chart
- Device Role Distribution
"""

import math
import plotly.graph_objects as go
import plotly.express as px
from config import CYBER_PALETTE, COLORS


def create_network_topology_graph(devices: list, findings: list, target: str = "192.168.1.0/24") -> go.Figure:
    """
    Creates an interactive 2D node-link network topology graph.
    - Central gateway router node at (0, 0)
    - Surrounding connected device satellite nodes positioned in a circle
    - Edges connecting gateway to each device
    - Nodes color-coded by security risk severity
    """
    fig = go.Figure()

    if not devices:
        # Empty graph state
        fig.add_annotation(
            text="No active hosts detected on subnet.<br>Run a network scan to visualize topology.",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=14, color=CYBER_PALETTE["text_muted"])
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=340,
            margin=dict(l=10, r=10, t=20, b=20)
        )
        return fig

    # Map finding severities by IP
    device_max_sev = {}
    for f in findings:
        ip = f.get("ip")
        sev = f.get("severity", "Low")
        curr = device_max_sev.get(ip, "Secure")
        rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Secure": 0}
        if rank.get(sev, 0) > rank.get(curr, 0):
            device_max_sev[ip] = sev

    # Coordinates calculation
    n_devices = len(devices)
    radius = 2.4
    gateway_x, gateway_y = 0.0, 0.0

    edge_x = []
    edge_y = []
    node_x = [gateway_x]
    node_y = [gateway_y]
    node_text = [f"<b>GATEWAY / ROUTER</b><br>Subnet: {target}<br>Status: Core Infrastructure"]
    node_colors = [CYBER_PALETTE["cyan"]]
    node_sizes = [28]
    node_symbols = ["diamond"]

    sev_colors = {
        "Critical": CYBER_PALETTE["critical"],
        "High": CYBER_PALETTE["warning"],
        "Medium": "#F59E0B",
        "Low": CYBER_PALETTE["cyan"],
        "Secure": CYBER_PALETTE["neon_green"]
    }

    for i, dev in enumerate(devices):
        angle = (2 * math.pi / n_devices) * i
        dx = radius * math.cos(angle)
        dy = radius * math.sin(angle)

        # Connection line
        edge_x.extend([gateway_x, dx, None])
        edge_y.extend([gateway_y, dy, None])

        # Node position
        node_x.append(dx)
        node_y.append(dy)

        ip = dev.get("ip", "Unknown")
        hostname = dev.get("hostname", "Host")
        ports = dev.get("open_ports", [])
        port_list = ", ".join(str(p.get("port")) for p in ports[:4])
        if len(ports) > 4:
            port_list += f" (+{len(ports)-4} more)"
        if not port_list:
            port_list = "None detected"

        sev = device_max_sev.get(ip, "Secure")
        color = sev_colors.get(sev, CYBER_PALETTE["neon_green"])

        hover_html = (
            f"<b>{hostname}</b><br>"
            f"IP: {ip}<br>"
            f"MAC: {dev.get('mac', 'N/A')}<br>"
            f"Risk: <b style='color:{color}'>{sev}</b><br>"
            f"Open Ports: {port_list}"
        )
        node_text.append(hover_html)
        node_colors.append(color)
        node_sizes.append(22)
        node_symbols.append("circle")

    # Add edges
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        line=dict(color="rgba(0, 217, 255, 0.28)", width=1.8),
        hoverinfo="none",
        showlegend=False
    ))

    # Add nodes
    fig.add_trace(go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        marker=dict(
            symbol=node_symbols,
            size=node_sizes,
            color=node_colors,
            line=dict(color="#070B14", width=2.5)
        ),
        text=["Gateway"] + [d.get("ip", "").split(".")[-1] for d in devices],
        textposition="bottom center",
        textfont=dict(color=CYBER_PALETTE["text_muted"], size=10, family="JetBrains Mono, monospace"),
        hovertext=node_text,
        hoverinfo="text",
        showlegend=False
    ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        margin=dict(l=10, r=10, t=15, b=25),
        height=350,
        hoverlabel=dict(
            bgcolor="#111C2E",
            bordercolor="#00D9FF",
            font=dict(color="#F3F7FF", size=12)
        )
    )
    return fig


def create_security_gauge(score: int) -> go.Figure:
    """Creates a semi-circular cyber security health gauge."""
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={'suffix': "/100", 'font': {'color': "#F3F7FF", 'size': 32, 'family': 'JetBrains Mono'}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#2A3B58"},
            'bar': {'color': CYBER_PALETTE["cyan"], 'thickness': 0.28},
            'bgcolor': CYBER_PALETTE["card_bg"],
            'borderwidth': 1,
            'bordercolor': "#1F314D",
            'steps': [
                {'range': [0, 50], 'color': 'rgba(255, 69, 96, 0.35)'},
                {'range': [50, 75], 'color': 'rgba(255, 176, 32, 0.35)'},
                {'range': [75, 90], 'color': 'rgba(0, 217, 255, 0.30)'},
                {'range': [90, 100], 'color': 'rgba(0, 245, 160, 0.35)'}
            ]
        }
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=20, r=20, t=20, b=10),
        height=220
    )
    return fig


def create_vulnerability_donut(findings: list) -> go.Figure:
    """Creates a risk severity donut chart with cyber palette."""
    crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    med_count = sum(1 for f in findings if f.get("severity") == "Medium")
    low_count = sum(1 for f in findings if f.get("severity") == "Low")

    sev_data = {
        "Severity": ["Critical", "High", "Medium", "Low"],
        "Count": [crit_count, high_count, med_count, low_count]
    }
    colors_map = {
        "Critical": CYBER_PALETTE["critical"],
        "High": CYBER_PALETTE["warning"],
        "Medium": "#F59E0B",
        "Low": CYBER_PALETTE["cyan"]
    }
    fig = px.pie(
        sev_data,
        names="Severity",
        values="Count",
        hole=0.62,
        color="Severity",
        color_discrete_map=colors_map
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        legend=dict(font=dict(color="#E2E8F0")),
        margin=dict(l=10, r=10, t=10, b=10),
        height=220
    )
    return fig


def create_open_ports_bar(devices: list) -> go.Figure:
    """Creates a horizontal bar chart of commonly detected ports and services."""
    port_counts = {}
    for dev in devices:
        for p in dev.get("open_ports", []):
            p_label = f"Port {p['port']} ({p.get('service', 'unknown')})"
            port_counts[p_label] = port_counts.get(p_label, 0) + 1

    if not port_counts:
        fig = go.Figure()
        fig.add_annotation(
            text="No open listening ports detected.",
            xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
            font=dict(size=13, color=CYBER_PALETTE["text_muted"])
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=220,
            margin=dict(l=10, r=10, t=10, b=10)
        )
        return fig

    sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    labels = [x[0] for x in sorted_ports]
    counts = [x[1] for x in sorted_ports]

    fig = px.bar(
        x=counts,
        y=labels,
        orientation='h',
        labels={'x': 'Number of Hosts', 'y': 'Port / Protocol'},
        color_discrete_sequence=[CYBER_PALETTE["cyan"]]
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(showgrid=True, gridcolor="#17243A", color=CYBER_PALETTE["text_muted"]),
        yaxis=dict(color="#E2E8F0"),
        margin=dict(l=10, r=10, t=10, b=10),
        height=220
    )
    return fig


def create_security_trend_chart(all_scans: list) -> go.Figure:
    """Creates a historical security trend line chart showing score progression."""
    if not all_scans:
        fig = go.Figure()
        fig.add_annotation(
            text="No historical scans recorded yet.",
            xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
            font=dict(size=13, color=CYBER_PALETTE["text_muted"])
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=220,
            margin=dict(l=10, r=10, t=10, b=10)
        )
        return fig

    # Reverse chronologically to show left-to-right progression
    sorted_scans = list(reversed(all_scans[:10]))
    timestamps = [s.get("scan_time", "")[:16].replace("T", " ") for s in sorted_scans]
    scores = [s.get("risk_score", 100) for s in sorted_scans]
    targets = [s.get("target", "Subnet") for s in sorted_scans]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=timestamps,
        y=scores,
        mode="lines+markers",
        line=dict(color=CYBER_PALETTE["neon_green"], width=3, shape="spline"),
        marker=dict(color=CYBER_PALETTE["cyan"], size=9, line=dict(color="#070B14", width=2)),
        text=[f"Target: {t}<br>Score: {sc}/100" for t, sc in zip(targets, scores)],
        hoverinfo="text"
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(showgrid=False, color=CYBER_PALETTE["text_muted"], tickangle=-20),
        yaxis=dict(showgrid=True, gridcolor="#17243A", range=[0, 105], color=CYBER_PALETTE["text_muted"]),
        margin=dict(l=10, r=10, t=20, b=20),
        height=220
    )
    return fig
