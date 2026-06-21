#!/usr/bin/env python3
"""
SOC Dashboard — Real-time SIEM Threat Monitoring

Reads threat alerts from the Silver layer and renders a live
cybersecurity dashboard with KPIs, charts, and alert tables.

Usage:
    cd dashboard && streamlit run soc_dashboard.py
"""

import time
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ---------------------------------------------------------------------------
# Page config — dark cybersecurity theme
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="SOC Dashboard — SIEM",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# Custom CSS for dark theme
# ---------------------------------------------------------------------------

st.markdown(
    """
<style>
    /* Global dark background */
    .stApp {
        background-color: #0d1117;
    }
    /* Metric cards */
    [data-testid="stMetric"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 12px 16px;
    }
    [data-testid="stMetric"] label {
        color: #8b949e !important;
    }
    [data-testid="stMetricValue"] {
        color: #e6edf3 !important;
        font-size: 2rem !important;
    }
    /* Dataframe */
    [data-testid="stDataFrame"] {
        background-color: #161b22;
    }
    /* Headers */
    h1, h2, h3 {
        color: #58a6ff !important;
    }
    /* Auto-refresh indicator */
    .refresh-indicator {
        color: #8b949e;
        font-size: 0.8rem;
        text-align: right;
    }
</style>
""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
SILVER_FILE = (SCRIPT_DIR / "../data_lake/silver/threat_alerts.csv").resolve()
REFRESH_SECONDS = 7

# ---------------------------------------------------------------------------
# Data loader
# ---------------------------------------------------------------------------

@st.cache_data(ttl=REFRESH_SECONDS)
def load_threats() -> pd.DataFrame:
    if not SILVER_FILE.exists():
        return pd.DataFrame()

    df = pd.read_csv(SILVER_FILE)

    if "detection_timestamp" in df.columns:
        df["detection_timestamp"] = pd.to_datetime(
            df["detection_timestamp"], utc=True, errors="coerce"
        )
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(
            df["timestamp"], utc=True, errors="coerce"
        )

    return df.sort_values("detection_timestamp", ascending=False)


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

def render():
    df = load_threats()

    # ---- Header ----
    col_title, col_refresh = st.columns([4, 1])
    with col_title:
        st.title("🛡️ SOC Dashboard — Real-Time Threat Monitor")
    with col_refresh:
        st.markdown(
            f'<p class="refresh-indicator">Auto-refresh: {REFRESH_SECONDS}s</p>',
            unsafe_allow_html=True,
        )

    st.markdown("---")

    if df.empty:
        st.info("No threat alerts detected yet. Waiting for data...")
        time.sleep(REFRESH_SECONDS)
        st.rerun()

    # ---- KPI Metrics ----
    total_threats = len(df)
    unique_ips = df["attacker_ip"].nunique()
    critical_count = (df["threat_severity"] == "CRITICAL").sum()
    high_count = (df["threat_severity"] == "HIGH").sum()

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total Threats Detected", total_threats)
    k2.metric("Unique Attacking IPs", unique_ips)
    k3.metric("CRITICAL Threats", critical_count, delta_color="inverse")
    k4.metric("HIGH Threats", high_count, delta_color="inverse")

    st.markdown("---")

    # ---- Charts Row 1 ----
    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("Top 5 Attacking IPs")
        ip_counts = df["attacker_ip"].value_counts().nlargest(5).reset_index()
        ip_counts.columns = ["IP", "Count"]
        fig_bar = px.bar(
            ip_counts,
            x="IP",
            y="Count",
            color="Count",
            color_continuous_scale="reds",
            text="Count",
        )
        fig_bar.update_traces(textposition="outside")
        fig_bar.update_layout(
            paper_bgcolor="#0d1117",
            plot_bgcolor="#0d1117",
            font_color="#e6edf3",
            margin=dict(t=10, b=10),
            coloraxis_showscale=False,
        )
        fig_bar.update_xaxes(gridcolor="#21262d")
        fig_bar.update_yaxes(gridcolor="#21262d")
        st.plotly_chart(fig_bar, use_container_width=True)

    with col_right:
        st.subheader("Threat Type Distribution")
        type_counts = df["threat_type"].value_counts().reset_index()
        type_counts.columns = ["Type", "Count"]
        fig_pie = px.pie(
            type_counts,
            names="Type",
            values="Count",
            hole=0.45,
            color_discrete_sequence=px.colors.sequential.Reds_r,
        )
        fig_pie.update_layout(
            paper_bgcolor="#0d1117",
            font_color="#e6edf3",
            margin=dict(t=10, b=10),
        )
        fig_pie.update_traces(
            textinfo="label+percent",
            textfont_color="#e6edf3",
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    # ---- Charts Row 2 ----
    st.subheader("Threats Over Time")

    time_col = (
        "detection_timestamp" if "detection_timestamp" in df.columns else "timestamp"
    )
    if time_col in df.columns:
        df_time = df.dropna(subset=[time_col]).copy()
        df_time["minute_bucket"] = df_time[time_col].dt.floor("min")
        timeline = (
            df_time.groupby(["minute_bucket", "threat_type"])
            .size()
            .reset_index(name="count")
        )

        fig_line = px.line(
            timeline,
            x="minute_bucket",
            y="count",
            color="threat_type",
            markers=True,
            color_discrete_sequence=["#ff7b72", "#d2a8ff", "#79c0ff"],
        )
        fig_line.update_layout(
            paper_bgcolor="#0d1117",
            plot_bgcolor="#0d1117",
            font_color="#e6edf3",
            legend_title_text="",
            margin=dict(t=10, b=10),
            hovermode="x unified",
        )
        fig_line.update_xaxes(gridcolor="#21262d", title_text="")
        fig_line.update_yaxes(gridcolor="#21262d", title_text="Alert Count")
        st.plotly_chart(fig_line, use_container_width=True)

    # ---- Raw Alerts Table ----
    st.markdown("---")
    st.subheader("Latest Threat Alerts")

    display_cols = [
        "detection_timestamp",
        "threat_type",
        "threat_severity",
        "attacker_ip",
        "threat_detail",
    ]
    available_cols = [c for c in display_cols if c in df.columns]

    st.dataframe(
        df[available_cols].head(100),
        use_container_width=True,
        hide_index=True,
    )

    # ---- Auto-refresh ----
    time.sleep(REFRESH_SECONDS)
    st.rerun()


if __name__ == "__main__":
    render()
