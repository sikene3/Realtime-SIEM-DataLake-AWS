#!/usr/bin/env python3
import io
import time
from datetime import datetime, timezone

import boto3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import pyarrow.parquet as pq
import streamlit as st

SILVER_BUCKET = "siem-datalake-silver"
SAFE_PREFIX = "data/status=safe/"
THREAT_PREFIX = "data/status=threat/"
DEFAULT_REFRESH = 10

st.set_page_config(
    page_title="SOC Dashboard — SIEM",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
    .stApp { background-color: #0d1117; }
    [data-testid="stMetric"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 12px 16px;
    }
    [data-testid="stMetric"] label { color: #8b949e !important; }
    [data-testid="stMetricValue"] { color: #e6edf3 !important; font-size: 2rem !important; }
    [data-testid="stDataFrame"] { background-color: #161b22; }
    h1, h2, h3 { color: #58a6ff !important; }
    .refresh-indicator { color: #8b949e; font-size: 0.8rem; text-align: right; }
    .threat-metric [data-testid="stMetricValue"] { color: #ff7b72 !important; }
</style>
""",
    unsafe_allow_html=True,
)


def list_parquet_keys(s3_client, prefix: str) -> list[str]:
    keys = []
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=SILVER_BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            if obj["Key"].endswith(".parquet"):
                keys.append(obj["Key"])
    return keys


def read_parquet_from_s3(s3_client, key: str) -> pd.DataFrame:
    resp = s3_client.get_object(Bucket=SILVER_BUCKET, Key=key)
    buffer = io.BytesIO(resp["Body"].read())
    table = pq.read_table(buffer)
    return table.to_pandas()


@st.cache_data(ttl=DEFAULT_REFRESH)
def load_all_data(_s3_client) -> tuple[pd.DataFrame, pd.DataFrame]:
    safe_keys = list_parquet_keys(_s3_client, SAFE_PREFIX)
    threat_keys = list_parquet_keys(_s3_client, THREAT_PREFIX)

    safe_dfs = []
    for key in safe_keys:
        safe_dfs.append(read_parquet_from_s3(_s3_client, key))

    threat_dfs = []
    for key in threat_keys:
        threat_dfs.append(read_parquet_from_s3(_s3_client, key))

    safe_df = pd.concat(safe_dfs, ignore_index=True) if safe_dfs else pd.DataFrame()
    threat_df = pd.concat(threat_dfs, ignore_index=True) if threat_dfs else pd.DataFrame()

    for df in [safe_df, threat_df]:
        if not df.empty and "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")

    if not threat_df.empty and "detection_timestamp" in threat_df.columns:
        threat_df["detection_timestamp"] = pd.to_datetime(
            threat_df["detection_timestamp"], utc=True, errors="coerce"
        )

    return safe_df, threat_df


def render():
    st.sidebar.title("⚙️ Dashboard Controls")
    refresh_secs = st.sidebar.slider("Auto-refresh (seconds)", 5, 60, DEFAULT_REFRESH, 5)
    auto_refresh = st.sidebar.checkbox("Enable auto-refresh", value=True)

    st.title("🛡️ SOC Dashboard — Real-Time Threat Monitor")
    st.markdown("---")

    s3_client = boto3.client("s3")
    safe_df, threat_df = load_all_data(s3_client)

    total_safe = len(safe_df)
    total_threats = len(threat_df)
    total_logs = total_safe + total_threats

    if total_logs == 0:
        st.info("⏳ Waiting for cloud data... No Parquet files found in the Silver bucket yet.")
        if auto_refresh:
            time.sleep(refresh_secs)
            st.rerun()
        return

    critical_count = 0
    if not threat_df.empty and "threat_severity" in threat_df.columns:
        critical_count = (threat_df["threat_severity"] == "CRITICAL").sum()

    health_status = "🟢 Healthy" if total_threats == 0 else ("🟡 Warning" if critical_count == 0 else "🔴 Critical")

    k1, k2, k3 = st.columns(3)
    k1.metric("Total Logs Analyzed", f"{total_logs:,}")
    with k2:
        st.markdown('<div class="threat-metric">', unsafe_allow_html=True)
        st.metric("Total Threats Detected", f"{total_threats:,}", delta=f"{critical_count} critical" if critical_count else None)
        st.markdown('</div>', unsafe_allow_html=True)
    k3.metric("System Health Status", health_status)

    st.markdown("---")

    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("Safe Logs vs. Threat Logs")
        pie_data = pd.DataFrame({
            "Category": ["Safe Logs", "Threat Logs"],
            "Count": [total_safe, total_threats],
        })
        fig_pie = px.pie(
            pie_data,
            names="Category",
            values="Count",
            hole=0.5,
            color="Category",
            color_discrete_map={"Safe Logs": "#3fb950", "Threat Logs": "#ff7b72"},
        )
        fig_pie.update_layout(
            paper_bgcolor="#0d1117",
            font_color="#e6edf3",
            margin=dict(t=10, b=10),
        )
        fig_pie.update_traces(textinfo="label+value+percent", textfont_color="#e6edf3")
        st.plotly_chart(fig_pie, use_container_width=True)

    with col_right:
        st.subheader("Threat Type Distribution")
        if not threat_df.empty and "threat_type" in threat_df.columns:
            type_counts = threat_df["threat_type"].value_counts().reset_index()
            type_counts.columns = ["Type", "Count"]
            fig_bar = px.bar(
                type_counts,
                x="Type",
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
        else:
            st.info("No threat data to display.")

    st.markdown("---")
    st.subheader("Threat Events Over Time")

    if not threat_df.empty:
        time_col = "detection_timestamp" if "detection_timestamp" in threat_df.columns else "timestamp"
        if time_col in threat_df.columns:
            df_time = threat_df.dropna(subset=[time_col]).copy()
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
    else:
        st.info("No threat timeline data available.")

    st.markdown("---")
    st.subheader("Latest Critical Threat Alerts")

    if not threat_df.empty:
        display_cols = []
        col_map = {
            "timestamp": "Timestamp",
            "detection_timestamp": "Timestamp",
            "source_ip": "Source IP",
            "attacker_ip": "Source IP",
            "threat_type": "Threat Type",
            "message": "Log Message",
            "threat_detail": "Log Message",
            "threat_severity": "Severity",
        }
        for col, label in col_map.items():
            if col in threat_df.columns and label not in [c for _, c in display_cols]:
                display_cols.append((col, label))

        table_df = threat_df[[c for c, _ in display_cols]].copy()
        table_df.columns = [l for _, l in display_cols]

        if "Timestamp" in table_df.columns:
            table_df = table_df.sort_values("Timestamp", ascending=False)

        st.dataframe(
            table_df.head(50),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No threat alerts to display.")

    if auto_refresh:
        time.sleep(refresh_secs)
        st.rerun()


if __name__ == "__main__":
    render()
