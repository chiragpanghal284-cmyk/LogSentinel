"""
app.py — LogSentinel: Security Log Analyzer
=============================================
Streamlit web interface. All detection logic lives in detector.py.

DISCLAIMER: This application is for educational and portfolio purposes only.
It does not connect to any real systems, scan external IPs, or handle real
credentials. Flagged activity does not automatically prove an attack — it
indicates patterns that warrant investigation by a qualified analyst.
"""

import io
import pathlib

import pandas as pd
import streamlit as st
import altair as alt

import detector

# ─── Page configuration ───────────────────────────────────────────────────────
st.set_page_config(
    page_title="LogSentinel – Security Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS (minimal, professional cybersecurity palette) ─────────────────
st.markdown(
    """
    <style>
    /* ── Global typography ── */
    html, body, [class*="css"] { font-family: 'Segoe UI', system-ui, sans-serif; }

    /* ── Sidebar ── */
    [data-testid="stSidebar"] { background-color: #0d1117; }
    [data-testid="stSidebar"] * { color: #c9d1d9 !important; }
    [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3 { color: #58a6ff !important; }

    /* ── Metric cards ── */
    [data-testid="metric-container"] {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 16px;
    }
    [data-testid="metric-container"] label { color: #8b949e !important; }
    [data-testid="metric-container"] [data-testid="stMetricValue"] {
        color: #58a6ff !important; font-size: 2rem !important;
    }

    /* ── Severity badge helpers ── */
    .badge-critical { background:#ff4444;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:700; }
    .badge-high     { background:#ff8c00;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:700; }
    .badge-medium   { background:#e6c229;color:#1a1a1a;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:700; }
    .badge-low      { background:#3fb950;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:700; }

    /* ── Alert section ── */
    .alert-box {
        border-left: 4px solid #ff4444;
        background: #1a0000;
        padding: 12px 16px;
        border-radius: 0 6px 6px 0;
        margin-bottom: 8px;
    }
    .alert-box p { margin: 0; color: #f0f0f0; font-size: 13px; }

    /* ── Main container tone ── */
    .main .block-container { background-color: #0d1117; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────
SEVERITY_ORDER = {
    detector.SEVERITY_CRITICAL: 4,
    detector.SEVERITY_HIGH: 3,
    detector.SEVERITY_MEDIUM: 2,
    detector.SEVERITY_LOW: 1,
}

SEVERITY_COLORS = {
    detector.SEVERITY_CRITICAL: "#ff4444",
    detector.SEVERITY_HIGH: "#ff8c00",
    detector.SEVERITY_MEDIUM: "#e6c229",
    detector.SEVERITY_LOW: "#3fb950",
}


def severity_badge(sev: str) -> str:
    cls = f"badge-{sev.lower()}"
    return f'<span class="{cls}">{sev}</span>'


def color_severity_row(row):
    """Return CSS for DataFrame row styling based on severity."""
    colors = {
        detector.SEVERITY_CRITICAL: "background-color:#3d0000;color:#ffcccc",
        detector.SEVERITY_HIGH: "background-color:#2d1a00;color:#ffd580",
        detector.SEVERITY_MEDIUM: "background-color:#2a2000;color:#fff3b0",
        detector.SEVERITY_LOW: "background-color:#001a00;color:#b3ffb3",
    }
    style = colors.get(row["severity"], "")
    return [style] * len(row)


@st.cache_data(show_spinner=False)
def load_sample_data() -> bytes:
    sample_path = pathlib.Path(__file__).parent / "data" / "sample_auth_logs.csv"
    return sample_path.read_bytes()


# ─── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ LogSentinel")
    st.markdown("*Security Log Analyzer*")
    st.markdown("---")

    st.markdown("### ⚙️ Detection Settings")
    threshold = st.slider(
        "Failed-login threshold",
        min_value=2,
        max_value=20,
        value=5,
        help="Minimum failed logins within the time window to raise an alert.",
    )
    window_minutes = st.slider(
        "Time window (minutes)",
        min_value=1,
        max_value=60,
        value=10,
        help="Rolling window length used for counting failed attempts.",
    )

    st.markdown("---")
    st.markdown("### 📂 Log File")
    uploaded_file = st.file_uploader(
        "Upload CSV log file",
        type=["csv"],
        help="Must contain: timestamp, ip_address, username, event_type, status",
    )

    st.markdown("---")
    st.download_button(
        label="⬇️ Download sample dataset",
        data=load_sample_data(),
        file_name="sample_auth_logs.csv",
        mime="text/csv",
        use_container_width=True,
    )

    st.markdown("---")
    st.markdown(
        """
        <small>
        ⚠️ **Disclaimer**<br>
        For educational use only.<br>
        Flagged IPs do **not** prove an attack.
        Always consult a qualified analyst.
        </small>
        """,
        unsafe_allow_html=True,
    )

# ─── Main header ──────────────────────────────────────────────────────────────
st.markdown(
    """
    <h1 style="color:#58a6ff;margin-bottom:0;">🛡️ LogSentinel</h1>
    <p style="color:#8b949e;margin-top:4px;font-size:16px;">
        Security Log Analyzer &amp; Suspicious Login Detection System
    </p>
    """,
    unsafe_allow_html=True,
)

# ─── Resolve data source ───────────────────────────────────────────────────────
use_sample = uploaded_file is None

if use_sample:
    st.info(
        "📄 No file uploaded — showing results for the **built-in sample dataset**. "
        "Upload your own CSV via the sidebar.",
        icon="ℹ️",
    )
    raw_bytes = load_sample_data()
    source_label = "sample_auth_logs.csv (built-in)"
else:
    raw_bytes = uploaded_file.read()
    source_label = uploaded_file.name

# ─── Parse and validate ────────────────────────────────────────────────────────
try:
    df_raw = pd.read_csv(io.BytesIO(raw_bytes))
except Exception as exc:
    st.error(f"❌ Could not parse the uploaded file as CSV: {exc}")
    st.stop()

validation = detector.validate_log_dataframe(df_raw)
if not validation.ok:
    st.error("❌ File validation failed:")
    for err in validation.errors:
        st.markdown(f"- {err}")
    st.stop()

df = detector.load_and_clean(df_raw)
dropped = df.attrs.get("dropped_bad_timestamps", 0)

# ─── Run detection ─────────────────────────────────────────────────────────────
alerts = detector.detect_brute_force(df, threshold=threshold, window_minutes=window_minutes)
alerts_df = detector.alerts_to_dataframe(alerts)

# ─── Top metric bar ───────────────────────────────────────────────────────────
st.markdown("---")
total_events = len(df)
failed_logins = df[
    df["event_type"].isin({"login", "authentication", "auth"})
    & df["status"].isin({"failed", "failure", "fail"})
].shape[0]
successful_logins = df[
    df["event_type"].isin({"login", "authentication", "auth"})
    & df["status"].isin({"success", "ok"})
].shape[0]
unique_ips = df["ip_address"].nunique()
num_alerts = len(alerts)
critical_count = sum(1 for a in alerts if a.severity == detector.SEVERITY_CRITICAL)

col1, col2, col3, col4, col5, col6 = st.columns(6)
col1.metric("📋 Total Events", total_events)
col2.metric("🟢 Successful Logins", successful_logins)
col3.metric("🔴 Failed Logins", failed_logins)
col4.metric("🌐 Unique IPs", unique_ips)
col5.metric("🚨 Alerts Generated", num_alerts)
col6.metric("💀 Critical Alerts", critical_count)

if dropped:
    st.warning(f"⚠️ {dropped} row(s) had unparseable timestamps and were skipped.")

# ─── Tabs ──────────────────────────────────────────────────────────────────────
tab_alerts, tab_viz, tab_logs, tab_how = st.tabs(
    ["🚨 Security Alerts", "📊 Visualizations", "📋 Log Explorer", "❓ How It Works"]
)

# ── Tab 1: Security Alerts ────────────────────────────────────────────────────
with tab_alerts:
    st.markdown(
        f"**Source:** `{source_label}` &nbsp;|&nbsp; "
        f"**Threshold:** {threshold} failures &nbsp;|&nbsp; "
        f"**Window:** {window_minutes} min"
    )

    if not alerts:
        st.success(
            "✅ No suspicious activity detected with the current settings. "
            "Try lowering the threshold or uploading a different log file."
        )
    else:
        # Sort by severity (worst first) then by first_seen
        alerts_df["_sev_order"] = alerts_df["severity"].map(SEVERITY_ORDER)
        alerts_df = alerts_df.sort_values(
            ["_sev_order", "first_seen"], ascending=[False, True]
        ).drop(columns=["_sev_order"])

        st.markdown(
            f"**{len(alerts)} alert(s) detected.** "
            "Flagged activity indicates patterns worth investigating — "
            "it does **not** automatically confirm a malicious attack."
        )
        st.markdown("---")

        # Alert cards
        for _, row in alerts_df.iterrows():
            badge = severity_badge(row["severity"])
            st.markdown(
                f"""
                <div class="alert-box">
                <p><strong>🌐 {row['ip_address']}</strong> &nbsp; {badge} &nbsp;
                   <span style="color:#8b949e;font-size:12px;">
                   {row['first_seen'].strftime('%Y-%m-%d %H:%M:%S')} →
                   {row['last_seen'].strftime('%H:%M:%S')}
                   </span></p>
                <p style="margin-top:4px;">
                   👤 <strong>User(s):</strong> {row['usernames']} &nbsp;|&nbsp;
                   🔢 <strong>Failed attempts:</strong> {row['failed_count']} in {row['window_minutes']} min
                </p>
                <p style="margin-top:4px;color:#aaa;">{row['reason']}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("---")
        st.markdown("### 📥 Download Alert Report")

        export_df = alerts_df.copy()
        export_df["first_seen"] = export_df["first_seen"].astype(str)
        export_df["last_seen"] = export_df["last_seen"].astype(str)

        csv_bytes = export_df.to_csv(index=False).encode()
        st.download_button(
            label="⬇️ Download alerts as CSV",
            data=csv_bytes,
            file_name="logsentinel_alerts.csv",
            mime="text/csv",
            use_container_width=True,
        )

        st.markdown("### 📊 Alert Table")
        display_df = alerts_df.copy()
        display_df["first_seen"] = display_df["first_seen"].astype(str)
        display_df["last_seen"] = display_df["last_seen"].astype(str)
        st.dataframe(
            display_df.style.apply(color_severity_row, axis=1),
            use_container_width=True,
            hide_index=True,
        )

# ── Tab 2: Visualizations ─────────────────────────────────────────────────────
with tab_viz:
    st.markdown("### 📊 Security Event Visualizations")

    if df.empty:
        st.warning("No log data to visualize.")
    else:
        viz_col1, viz_col2 = st.columns(2)

        # Chart 1: Login outcomes over time (hourly)
        with viz_col1:
            st.markdown("#### Login Outcomes Over Time")
            login_df = df[df["event_type"].isin({"login", "authentication", "auth"})].copy()
            login_df["hour"] = login_df["timestamp"].dt.floor("H")
            hourly = (
                login_df.groupby(["hour", "status"])
                .size()
                .reset_index(name="count")
            )
            if not hourly.empty:
                chart_time = (
                    alt.Chart(hourly)
                    .mark_bar()
                    .encode(
                        x=alt.X("hour:T", title="Hour", axis=alt.Axis(format="%H:%M")),
                        y=alt.Y("count:Q", title="Event Count"),
                        color=alt.Color(
                            "status:N",
                            scale=alt.Scale(
                                domain=["failed", "failure", "fail", "success", "ok"],
                                range=["#ff4444", "#ff4444", "#ff4444", "#3fb950", "#3fb950"],
                            ),
                            title="Status",
                        ),
                        tooltip=["hour:T", "status:N", "count:Q"],
                    )
                    .properties(height=280)
                    .configure_view(strokeOpacity=0)
                    .configure_axis(
                        gridColor="#30363d", labelColor="#8b949e", titleColor="#8b949e"
                    )
                )
                st.altair_chart(chart_time, use_container_width=True)

        # Chart 2: Top IPs by failed logins
        with viz_col2:
            st.markdown("#### Top IPs by Failed Logins")
            failed_df = df[
                df["event_type"].isin({"login", "authentication", "auth"})
                & df["status"].isin({"failed", "failure", "fail"})
            ]
            top_ips = (
                failed_df.groupby("ip_address")
                .size()
                .reset_index(name="failed_count")
                .nlargest(10, "failed_count")
            )
            if not top_ips.empty:
                chart_ip = (
                    alt.Chart(top_ips)
                    .mark_bar(color="#ff4444")
                    .encode(
                        x=alt.X("failed_count:Q", title="Failed Logins"),
                        y=alt.Y(
                            "ip_address:N",
                            sort="-x",
                            title="IP Address",
                        ),
                        tooltip=["ip_address:N", "failed_count:Q"],
                    )
                    .properties(height=280)
                    .configure_view(strokeOpacity=0)
                    .configure_axis(
                        gridColor="#30363d", labelColor="#8b949e", titleColor="#8b949e"
                    )
                )
                st.altair_chart(chart_ip, use_container_width=True)

        viz_col3, viz_col4 = st.columns(2)

        # Chart 3: Alert severity breakdown
        with viz_col3:
            st.markdown("#### Alert Severity Breakdown")
            if not alerts_df.empty:
                sev_counts = (
                    alerts_df.groupby("severity")
                    .size()
                    .reset_index(name="count")
                )
                chart_sev = (
                    alt.Chart(sev_counts)
                    .mark_arc(innerRadius=50)
                    .encode(
                        theta=alt.Theta("count:Q"),
                        color=alt.Color(
                            "severity:N",
                            scale=alt.Scale(
                                domain=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                                range=["#ff4444", "#ff8c00", "#e6c229", "#3fb950"],
                            ),
                        ),
                        tooltip=["severity:N", "count:Q"],
                    )
                    .properties(height=280)
                )
                st.altair_chart(chart_sev, use_container_width=True)
            else:
                st.info("No alerts to display.")

        # Chart 4: Failed logins per username (top 10)
        with viz_col4:
            st.markdown("#### Top Targeted Usernames")
            failed_by_user = (
                failed_df.groupby("username")
                .size()
                .reset_index(name="count")
                .nlargest(10, "count")
            )
            if not failed_by_user.empty:
                chart_user = (
                    alt.Chart(failed_by_user)
                    .mark_bar(color="#e6c229")
                    .encode(
                        x=alt.X("count:Q", title="Failed Logins"),
                        y=alt.Y("username:N", sort="-x", title="Username"),
                        tooltip=["username:N", "count:Q"],
                    )
                    .properties(height=280)
                    .configure_view(strokeOpacity=0)
                    .configure_axis(
                        gridColor="#30363d", labelColor="#8b949e", titleColor="#8b949e"
                    )
                )
                st.altair_chart(chart_user, use_container_width=True)

# ── Tab 3: Log Explorer ───────────────────────────────────────────────────────
with tab_logs:
    st.markdown("### 📋 Raw Log Explorer")

    # Filter controls
    fc1, fc2, fc3 = st.columns(3)
    with fc1:
        status_filter = st.multiselect(
            "Filter by status",
            options=sorted(df["status"].unique()),
            default=[],
        )
    with fc2:
        event_filter = st.multiselect(
            "Filter by event type",
            options=sorted(df["event_type"].unique()),
            default=[],
        )
    with fc3:
        ip_search = st.text_input("Search by IP address", value="")

    filtered_df = df.copy()
    if status_filter:
        filtered_df = filtered_df[filtered_df["status"].isin(status_filter)]
    if event_filter:
        filtered_df = filtered_df[filtered_df["event_type"].isin(event_filter)]
    if ip_search.strip():
        filtered_df = filtered_df[
            filtered_df["ip_address"].str.contains(ip_search.strip(), na=False)
        ]

    st.markdown(f"Showing **{len(filtered_df)}** of **{len(df)}** events")
    display_log = filtered_df.copy()
    display_log["timestamp"] = display_log["timestamp"].astype(str)
    st.dataframe(display_log, use_container_width=True, hide_index=True)

# ── Tab 4: How It Works ───────────────────────────────────────────────────────
with tab_how:
    st.markdown("### ❓ How LogSentinel Works")
    st.markdown(
        """
        #### Detection Rule: Rolling-Window Brute-Force Detection

        LogSentinel uses a **transparent, rule-based heuristic**. No machine learning
        or external IP intelligence is used — every decision is explainable:

        1. **Filter** — Only `login` / `authentication` events with status `failed`
           are considered. All other events are ignored.
        2. **Group** — Events are grouped by `ip_address`.
        3. **Slide a time window** — For each IP, a rolling window of configurable
           width (default **10 minutes**) is slid across the event timeline.
        4. **Count & compare** — If the number of failed events inside the window
           reaches or exceeds the configurable threshold (default **5**), an alert
           is raised.
        5. **Advance** — After raising an alert, the window advances past the last
           counted event to prevent double-counting the same burst.

        #### Severity Levels

        | Severity | Rule |
        |---|---|
        | 🟢 LOW | ≥ 1× threshold |
        | 🟡 MEDIUM | ≥ 1.5× threshold |
        | 🟠 HIGH | ≥ 2× threshold |
        | 🔴 CRITICAL | ≥ 4× threshold |

        #### ⚠️ Important Limitations

        - **Not proof of attack.** A high failed-login count can result from a
          forgotten password, a misconfigured application, or a shared NAT gateway.
        - **No IP geo-intelligence.** Private/RFC-1918 addresses are treated the
          same as public ones.
        - **No velocity deceleration.** Slow and distributed attacks (low-and-slow,
          many IPs each contributing few attempts) will not be flagged.
        - **No account-level lockout simulation.** The tool is read-only — it does
          not modify anything.
        - **Required columns:** `timestamp`, `ip_address`, `username`,
          `event_type`, `status`.

        #### Required CSV Format

        ```
        timestamp,ip_address,username,event_type,status
        2024-06-15 08:07:45,10.0.0.5,charlie,login,failed
        2024-06-15 08:08:10,10.0.0.5,charlie,login,failed
        ```

        Timestamps must be in ISO-8601 format (e.g. `YYYY-MM-DD HH:MM:SS`).
        Additional columns (e.g. `user_agent`, `location`) are accepted but ignored.
        """,
        unsafe_allow_html=False,
    )
