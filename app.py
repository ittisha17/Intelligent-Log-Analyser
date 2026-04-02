import time
import queue

import streamlit as st
import pandas as pd
import plotly.express as px

from parser import parse_logs
from detector import detect_threats
from risk import calculate_risk
from ai_summary import generate_summary
from report import generate_report
from alerts import send_alerts

# Optional modules — degrade gracefully if not installed / not built yet
try:
    from log_tailer import start_watcher
    WATCHDOG_OK = True
except ImportError:
    WATCHDOG_OK = False

try:
    from threat_intel import enrich_threats
    INTEL_OK = True
except ImportError:
    INTEL_OK = False


# ══════════════════════════════════════════════════════════════════════════════
#  PAGE CONFIG  (must be first Streamlit call)
# ══════════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="SIEM Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ══════════════════════════════════════════════════════════════════════════════
#  SIDEBAR — log source + filters
# ══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.title("🛡️ SIEM Dashboard")
    st.caption("AI-Powered Threat Detection")
    st.divider()

    st.subheader("📂 Log source")
    uploaded_file = st.file_uploader("Upload log file", type=["log", "txt"])
    use_sample    = st.button("⚡ Use sample logs", use_container_width=True)

    st.divider()
    st.subheader("🔎 Filters")
    risk_filter   = st.multiselect(
        "Risk level",
        ["High", "Medium", "Low"],
        default=["High", "Medium", "Low"],
    )
    attack_filter = st.text_input("Attack type contains", placeholder="e.g. brute")

    st.divider()
    if INTEL_OK:
        st.success("✅ Threat intel active")
    else:
        st.warning("⚠️ threat_intel.py not found")
    if WATCHDOG_OK:
        st.success("✅ Live monitor active")
    else:
        st.warning("⚠️ watchdog not installed")

    st.divider()
    st.caption("B.Tech Cybersecurity Project · 2024")


# ══════════════════════════════════════════════════════════════════════════════
#  LOAD & PROCESS LOGS
# ══════════════════════════════════════════════════════════════════════════════
logs = None

if uploaded_file:
    logs = uploaded_file.read().decode("utf-8").split("\n")
elif use_sample:
    with open("sample.log", "r") as f:
        logs = f.readlines()

# Core pipeline
df          = pd.DataFrame(columns=["ip", "attack", "owasp", "count", "risk"])
parsed_data = []

if logs:
    parsed_data = parse_logs(logs)
    threats     = detect_threats(parsed_data)
    threats     = calculate_risk(threats)

    # Optional threat intelligence enrichment
    if INTEL_OK and threats:
        with st.spinner("Enriching IPs with threat intelligence..."):
            threats = enrich_threats(threats)

    df = pd.DataFrame(threats) if threats else pd.DataFrame(
        columns=["ip", "attack", "owasp", "count", "risk"]
    )

    # Send alerts only for high-risk (avoid alert fatigue)
    if not df.empty and "risk" in df.columns:
        high_risk_list = [t for t in threats if t.get("risk") == "High"]
        if high_risk_list:
            send_alerts(high_risk_list)

    # Apply sidebar filters
    if not df.empty:
        if risk_filter:
            df = df[df["risk"].isin(risk_filter)]
        if attack_filter:
            df = df[df["attack"].str.contains(attack_filter, case=False, na=False)]


# ══════════════════════════════════════════════════════════════════════════════
#  TABS
# ══════════════════════════════════════════════════════════════════════════════
tab_dashboard, tab_live, tab_ai, tab_report = st.tabs([
    "📊 Dashboard",
    "⚡ Live Monitor",
    "🤖 AI Insights",
    "📄 Report",
])


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 1 — DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
with tab_dashboard:
    if not logs:
        st.info("👈 Upload a log file or click 'Use sample logs' in the sidebar.")

    elif df.empty:
        st.success("✅ No threats found matching current filters.")

    else:
        # ── Metric cards ─────────────────────────────────────────────────────
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total log lines",  len(parsed_data))
        m2.metric("Threats detected", len(df))
        high_count = int(df[df["risk"] == "High"].shape[0]) if "risk" in df.columns else 0
        m3.metric(
            "High risk", high_count,
            delta="Action needed" if high_count else None,
            delta_color="inverse",
        )
        m4.metric("Unique IPs", df["ip"].nunique() if "ip" in df.columns else 0)

        st.divider()

        # ── Threat table ─────────────────────────────────────────────────────
        st.subheader("Threat log")

        # Build display_df — apply emoji labels BEFORE deriving show_cols
        display_df = df.copy()
        RISK_EMOJI = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}
        if "risk" in display_df.columns:
            display_df["risk"] = display_df["risk"].map(
                lambda r: f"{RISK_EMOJI.get(r, '')} {r}"
            )

        # Column order — safe against missing enrichment columns
        enriched_cols = [
            "ip", "attack", "risk", "abuse_score", "threat_label",
            "country", "city", "isp", "is_tor", "owasp", "count",
        ]
        show_cols = [c for c in enriched_cols if c in display_df.columns]

        # Alert banners — always check raw df, not display_df
        if "is_tor" in df.columns and df["is_tor"].any():
            st.error(
                "⚠️ TOR exit node detected — treat all traffic from this IP as hostile."
            )

        if "abuse_score" in df.columns:
            known_bad = df[df["abuse_score"] >= 80]
            if not known_bad.empty:
                ips = ", ".join(known_bad["ip"].unique()[:5])
                st.warning(f"🔴 Known malicious IPs (AbuseIPDB ≥80): **{ips}**")

        st.dataframe(display_df[show_cols], use_container_width=True, height=280)

        st.divider()

        # ── Charts ───────────────────────────────────────────────────────────
        st.subheader("Threat analysis")
        c1, c2 = st.columns(2)

        with c1:
            attack_counts = df["attack"].value_counts().reset_index()
            attack_counts.columns = ["Attack type", "Count"]
            fig_bar = px.bar(
                attack_counts,
                x="Attack type", y="Count",
                color="Count",
                color_continuous_scale="Reds",
                title="Attack distribution",
            )
            fig_bar.update_layout(
                showlegend=False,
                coloraxis_showscale=False,
                margin=dict(t=40, b=0, l=0, r=0),
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        with c2:
            risk_counts = df["risk"].value_counts().reset_index()
            risk_counts.columns = ["Risk", "Count"]
            fig_pie = px.pie(
                risk_counts,
                names="Risk", values="Count",
                hole=0.45,
                color="Risk",
                color_discrete_map={
                    "High": "#e74c3c",
                    "Medium": "#f39c12",
                    "Low":  "#2ecc71",
                },
                title="Risk distribution",
            )
            fig_pie.update_layout(margin=dict(t=40, b=0, l=0, r=0))
            st.plotly_chart(fig_pie, use_container_width=True)

        # Top offending IPs
        if "ip" in df.columns and "count" in df.columns:
            st.subheader("Top offending IPs")
            top_ips = (
                df.groupby("ip")["count"]
                .sum()
                .sort_values(ascending=True)
                .tail(10)
                .reset_index()
            )
            fig_ip = px.bar(
                top_ips, x="count", y="ip",
                orientation="h",
                title="Requests per IP (top 10)",
                color="count",
                color_continuous_scale="OrRd",
            )
            fig_ip.update_layout(
                showlegend=False,
                coloraxis_showscale=False,
                margin=dict(t=40, b=0, l=0, r=0),
            )
            st.plotly_chart(fig_ip, use_container_width=True)

        # GeoIP world map — only rendered when country data is available
        if "country" in df.columns:
            st.subheader("Attack origin map")
            geo_counts = df["country"].value_counts().reset_index()
            geo_counts.columns = ["Country", "Threats"]
            fig_map = px.choropleth(
                geo_counts,
                locations="Country",
                locationmode="country names",
                color="Threats",
                color_continuous_scale="Reds",
                title="Threats by country",
            )
            fig_map.update_layout(margin=dict(t=40, b=0, l=0, r=0))
            st.plotly_chart(fig_map, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 2 — LIVE MONITOR
# ══════════════════════════════════════════════════════════════════════════════
with tab_live:
    st.subheader("Real-time log monitor")

    if not WATCHDOG_OK:
        st.warning("`watchdog` not installed.")
        st.code("pip install watchdog")
    else:
        log_path = st.text_input(
            "Log file path to watch",
            value="sample.log",
            help="Absolute or relative path to a live-updating log file.",
        )

        # Session state initialisation
        for key, default in [("lq", None), ("lb", []), ("obs", None)]:
            if key not in st.session_state:
                st.session_state[key] = default

        col_start, col_stop, col_clear = st.columns(3)

        if col_start.button("▶ Start", use_container_width=True):
            if st.session_state.obs is None:
                st.session_state.lq  = queue.Queue()
                st.session_state.obs = start_watcher(log_path, st.session_state.lq)
                st.success(f"Watching {log_path}")

        if col_stop.button("⏹ Stop", use_container_width=True):
            if st.session_state.obs:
                st.session_state.obs.stop()
                st.session_state.obs.join()
                st.session_state.obs = None
                st.info("Stopped.")

        if col_clear.button("🗑 Clear buffer", use_container_width=True):
            st.session_state.lb = []

        # Drain the queue into the line buffer
        if st.session_state.lq:
            try:
                from parser import parse_log_line
                HAS_LINE_PARSER = True
            except ImportError:
                HAS_LINE_PARSER = False
                st.warning(
                    "`parse_log_line` not found in parser.py — "
                    "add a single-line parsing function to enable live mode."
                )

            if HAS_LINE_PARSER:
                while not st.session_state.lq.empty():
                    raw    = st.session_state.lq.get_nowait()
                    parsed = parse_log_line(raw)
                    if parsed:
                        st.session_state.lb.append(parsed)
                st.session_state.lb = st.session_state.lb[-200:]

        buf = st.session_state.lb
        if buf:
            live_threats = calculate_risk(detect_threats(buf))
            live_df      = pd.DataFrame(live_threats) if live_threats else pd.DataFrame()

            lm1, lm2, lm3 = st.columns(3)
            lm1.metric("Lines buffered", len(buf))
            lm2.metric("Live threats",   len(live_df))
            live_high = (
                int(live_df[live_df["risk"] == "High"].shape[0])
                if not live_df.empty and "risk" in live_df.columns
                else 0
            )
            lm3.metric(
                "High risk", live_high,
                delta=f"+{live_high}" if live_high else None,
                delta_color="inverse",
            )

            if not live_df.empty:
                live_show = [
                    c for c in ["ip", "attack", "risk", "count"]
                    if c in live_df.columns
                ]
                st.dataframe(live_df[live_show], use_container_width=True)
        else:
            st.info("No data yet — press ▶ Start above.")

        # Auto-rerun every 2 s while the observer is active
        if st.session_state.obs:
            time.sleep(2)
            st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 3 — AI INSIGHTS
# ══════════════════════════════════════════════════════════════════════════════
with tab_ai:
    st.subheader("AI Security Insights")
    st.caption("Powered by Google Gemini — analysis is generated on demand.")

    if not logs:
        st.info("Load logs in the Dashboard tab first.")
    elif df.empty:
        st.info("No threats to analyse after current filters.")
    else:
        # Quick summary before user clicks generate
        high   = int(df[df["risk"] == "High"].shape[0])   if "risk" in df.columns else 0
        medium = int(df[df["risk"] == "Medium"].shape[0]) if "risk" in df.columns else 0
        low    = int(df[df["risk"] == "Low"].shape[0])    if "risk" in df.columns else 0

        sc1, sc2, sc3 = st.columns(3)
        sc1.metric("High threats",   high)
        sc2.metric("Medium threats", medium)
        sc3.metric("Low threats",    low)

        st.divider()

        if st.button("🤖 Generate AI analysis", type="primary", use_container_width=True):
            with st.spinner("Gemini is analysing your threats…"):
                summary = generate_summary(df)

            # Render markdown headings as headings, everything else as info boxes
            for section in summary.split("\n\n"):
                section = section.strip()
                if not section:
                    continue
                if section.startswith("#"):
                    st.markdown(section)
                else:
                    st.info(section)


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 4 — REPORT
# ══════════════════════════════════════════════════════════════════════════════
with tab_report:
    st.subheader("Security Report")

    if not logs:
        st.info("Load logs in the Dashboard tab first.")
    elif df.empty:
        st.info("No threats to report after current filters.")
    else:
        report = generate_report(df)

        st.text_area("Report preview", report, height=420)

        st.download_button(
            label="⬇️ Download report (.txt)",
            data=report,
            file_name="security_report.txt",
            mime="text/plain",
            use_container_width=True,
        )