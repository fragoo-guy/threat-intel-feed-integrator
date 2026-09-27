import json
import os
from pathlib import Path
import sys
from typing import Any

# Ensure project root is in sys.path so modules resolve whether run from root or dashboard dir
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import streamlit as st

try:
    from dashboard.api_client import ThreatIntelAPIClient
    from dashboard.mitre import generate_suricata_rule, get_mitre_context
except ModuleNotFoundError:
    from api_client import ThreatIntelAPIClient
    from mitre import generate_suricata_rule, get_mitre_context


# ---------------------------------------------------------
# Page Configuration & Styling
# ---------------------------------------------------------
st.set_page_config(
    page_title="Threat Intel SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .main {
        background-color: #0e1117;
    }
    .metric-card {
        background-color: #1e222d;
        border: 1px solid #2e3646;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }
    .tag-badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: 600;
        margin-right: 4px;
        background-color: #ff4b4b22;
        color: #ff4b4b;
        border: 1px solid #ff4b4b66;
    }
    .status-ok {
        color: #00d26a;
        font-weight: bold;
    }
    .status-err {
        color: #f83245;
        font-weight: bold;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------
# Backend API Client Initialization
# ---------------------------------------------------------
api_url = os.getenv("API_URL", "http://127.0.0.1:8000")
client = ThreatIntelAPIClient(base_url=api_url)

# ---------------------------------------------------------
# Sidebar: System Health & Ingestion Controls
# ---------------------------------------------------------
with st.sidebar:
    st.title("🛡️ Threat Intel")
    st.caption("Centralized CTI Aggregation & Analysis")

    st.markdown("---")
    st.subheader("System Health")
    is_online = client.check_connection()

    if is_online:
        st.markdown("🟢 **FastAPI Backend:** `Online`")
    else:
        st.markdown("🔴 **FastAPI Backend:** `Offline`")
        st.warning(f"Could not reach API at `{api_url}`. Start backend with `uvicorn app.main:app --reload`.")

    health_data = client.get_health() if is_online else None
    feeds = health_data.get("feeds", {}) if health_data else {}

    with st.expander("Threat Feed Status", expanded=True):
        registered_providers = ["otx", "abuseipdb", "virustotal"]
        for prov in registered_providers:
            info = feeds.get(prov, {})
            status = info.get("status", "idle")
            last_run = info.get("end_time", "No runs recorded")
            if status == "success":
                st.markdown(f"**{prov.upper()}:** 🟢 `Active`")
            elif status == "failed":
                st.markdown(f"**{prov.upper()}:** 🔴 `Error`")
            else:
                st.markdown(f"**{prov.upper()}:** ⚪ `Idle`")

            # On-demand sync trigger
            if is_online and st.button(f"Sync {prov.upper()}", key=f"sync_{prov}"):
                with st.spinner(f"Triggering sync for {prov.upper()}..."):
                    sync_res = client.trigger_sync(prov)
                    if sync_res and sync_res.get("result", {}).get("status") == "success":
                        st.success(f"{prov.upper()} synchronized successfully!")
                        st.rerun()
                    else:
                        st.error(f"{prov.upper()} sync failed or skipped (check API keys).")

    st.markdown("---")
    st.subheader("Filter & Search")

    search_indicator = st.text_input("Search Indicator (IP, domain, hash, URL):", placeholder="e.g. 198.51.100 or evil.com")

    filter_type = st.selectbox(
        "Indicator Type:",
        ["All", "ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "file_name"],
    )
    filter_type_val = None if filter_type == "All" else filter_type

    filter_tag = st.selectbox(
        "Threat Tag:",
        ["All", "malware", "phishing", "c2", "botnet", "exploit", "suspicious"],
    )
    filter_tag_val = None if filter_tag == "All" else filter_tag

    filter_provider = st.selectbox(
        "Feed Provider:",
        ["All", "otx", "abuseipdb", "virustotal"],
    )
    filter_provider_val = None if filter_provider == "All" else filter_provider

    min_confidence = st.slider("Minimum Confidence Score:", min_value=0, max_value=100, value=0, step=5)
    limit = st.select_slider("Page Size:", options=[25, 50, 100, 250], value=50)

# ---------------------------------------------------------
# Main SOC Dashboard
# ---------------------------------------------------------
st.title("Cyber Threat Intelligence Operations Center")
st.markdown("Normalized, deduplicated, and corroborated threat intelligence from multiple open-source feeds.")

# Fetch Metrics
metrics = client.get_metrics() if is_online else None
total_iocs = metrics.get("total_iocs", 0) if metrics else 0
high_conf = metrics.get("high_confidence_count", 0) if metrics else 0
by_type = metrics.get("by_indicator_type", {}) if metrics else {}
by_tag = metrics.get("by_threat_tag", {}) if metrics else {}
by_provider = metrics.get("by_provider", {}) if metrics else {}

# 1. Top Metrics Cards
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Active IOCs", f"{total_iocs:,}")
with col2:
    st.metric("High-Confidence Threats (≥80%)", f"{high_conf:,}")
with col3:
    st.metric("Connected Feeds", f"{len(by_provider)}")
with col4:
    corroborated_ratio = round((high_conf / max(total_iocs, 1)) * 100, 1)
    st.metric("High-Certainty Ratio", f"{corroborated_ratio}%")

st.markdown("---")

# 2. Threat Analytics Charts
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.subheader("Threat Classification Distribution")
    if by_tag:
        df_tags = pd.DataFrame(list(by_tag.items()), columns=["Threat Tag", "Count"]).sort_values("Count", ascending=False)
        st.bar_chart(df_tags.set_index("Threat Tag"), color="#ff4b4b")
    else:
        st.info("No threat tags recorded yet. Sync feeds to populate intelligence.")

with chart_col2:
    st.subheader("Indicator Type Distribution")
    if by_type:
        df_types = pd.DataFrame(list(by_type.items()), columns=["Indicator Type", "Count"]).sort_values("Count", ascending=False)
        st.bar_chart(df_types.set_index("Indicator Type"), color="#29b5e8")
    else:
        st.info("No indicator types recorded yet.")

st.markdown("---")

# 3. Interactive IOC Table
st.subheader("Search & Investigation Grid")

iocs = []
if is_online:
    iocs = client.query_iocs(
        indicator=search_indicator if search_indicator else None,
        indicator_type=filter_type_val,
        tag=filter_tag_val,
        provider=filter_provider_val,
        min_confidence=min_confidence if min_confidence > 0 else None,
        limit=limit,
    )

if iocs:
    # Build clean display rows
    table_rows = []
    for item in iocs:
        sources_list = [s.get("provider") for s in item.get("sources", [])]
        table_rows.append(
            {
                "Indicator": item.get("indicator"),
                "Type": item.get("indicator_type"),
                "Threat Tags": ", ".join(item.get("threat_tags", [])),
                "Confidence": f"{item.get('confidence_score', 0):.0f}%",
                "Sources Count": len(sources_list),
                "Sources": ", ".join(sources_list),
                "Last Seen": item.get("last_seen", "")[:19].replace("T", " ") if item.get("last_seen") else "Unknown",
                "deduplication_key": item.get("deduplication_key"),
            }
        )

    df_display = pd.DataFrame(table_rows)
    st.dataframe(
        df_display.drop(columns=["deduplication_key"]),
        use_container_width=True,
        hide_index=True,
    )
    st.caption(f"Showing {len(iocs)} indicators matching current filter criteria.")
else:
    if is_online:
        st.info("No indicators matched the specified filter criteria.")
    else:
        st.error("Connect to the backend API to search indicators.")

st.markdown("---")

# 4. Deep-Dive Indicator Inspector
st.subheader("Deep-Dive Indicator Inspection")

if iocs:
    key_options = [item["deduplication_key"] for item in iocs]
    selected_key = st.selectbox("Select an indicator to inspect detailed evidence:", key_options)

    selected_ioc = next((item for item in iocs if item["deduplication_key"] == selected_key), None)
    if selected_ioc:
        d_col1, d_col2 = st.columns([1, 1])

        with d_col1:
            st.markdown(f"#### `{selected_ioc['indicator']}`")
            st.markdown(f"**Canonical Key:** `{selected_ioc['deduplication_key']}`")
            st.markdown(f"**Indicator Type:** `{selected_ioc['indicator_type'].upper()}`")
            st.markdown(f"**Confidence Score:** `{selected_ioc['confidence_score']:.1f}%`")
            st.markdown(f"**First Observed:** `{selected_ioc.get('first_seen') or 'N/A'}`")
            st.markdown(f"**Last Observed:** `{selected_ioc.get('last_seen') or 'N/A'}`")
            st.markdown(f"**Threat Tags:** {', '.join(selected_ioc.get('threat_tags', []))}")

        with d_col2:
            st.markdown("#### Corroborating Feed Sources")
            for src in selected_ioc.get("sources", []):
                p_name = src.get("provider", "unknown").upper()
                s_score = src.get("confidence_score")
                s_url = src.get("source_url")
                st.markdown(f"- **{p_name}** | Confidence: `{s_score if s_score is not None else 'N/A'}`")
                if s_url:
                    st.markdown(f"  *Reference:* [{s_url}]({s_url})")

        # MITRE ATT&CK Mapping Section
        st.markdown("---")
        st.markdown("#### MITRE ATT&CK® Enterprise TTP Mapping")
        mitre_entries = get_mitre_context(selected_ioc.get("threat_tags", []))
        if mitre_entries:
            m_cols = st.columns(len(mitre_entries))
            for idx, entry in enumerate(mitre_entries):
                with m_cols[idx]:
                    st.info(
                        f"**{entry['technique_id']}**\n\n"
                        f"*{entry['technique_name']}*\n\n"
                        f"**Tactic:** {entry['tactic']}\n\n"
                        f"[View MITRE Docs]({entry['url']})"
                    )
        else:
            st.caption("No specific MITRE ATT&CK mappings associated with these tags.")

        # Suricata Detection Rule Section
        st.markdown("---")
        st.markdown("#### Actionable Suricata / Snort NIDS Detection Rule")
        suricata_rule = generate_suricata_rule(selected_ioc)
        st.code(suricata_rule, language="bash")
        st.caption("Copy this rule into your Suricata `local.rules` or Snort ruleset for active perimeter defense.")

        with st.expander("Inspect Raw Provider Metadata"):
            st.json(selected_ioc.get("raw_metadata", {}))

# ---------------------------------------------------------
# 5. SOC Analyst Export Center
# ---------------------------------------------------------
st.markdown("---")
st.subheader("Export Threat Intelligence")

exp_col1, exp_col2 = st.columns(2)

with exp_col1:
    st.markdown("**Spreadsheet Triage (CSV)**")
    if is_online:
        csv_data = client.get_csv_export(
            indicator=search_indicator if search_indicator else None,
            indicator_type=filter_type_val,
            tag=filter_tag_val,
            provider=filter_provider_val,
            min_confidence=min_confidence if min_confidence > 0 else None,
        )
        if csv_data:
            st.download_button(
                label="📥 Download Filtered IOCs as CSV",
                data=csv_data,
                file_name="threat_intel_iocs.csv",
                mime="text/csv",
                use_container_width=True,
            )
    else:
        st.button("CSV Export (Offline)", disabled=True, use_container_width=True)

with exp_col2:
    st.markdown("**SIEM / SOAR Exchange (STIX 2.1 JSON Bundle)**")
    if is_online:
        stix_data = client.get_stix_export(
            indicator=search_indicator if search_indicator else None,
            indicator_type=filter_type_val,
            tag=filter_tag_val,
            provider=filter_provider_val,
            min_confidence=min_confidence if min_confidence > 0 else None,
        )
        if stix_data:
            st.download_button(
                label="📥 Download STIX 2.1 JSON Bundle",
                data=json.dumps(stix_data, indent=2),
                file_name="threat_intel_stix2.json",
                mime="application/json",
                use_container_width=True,
            )
    else:
        st.button("STIX 2.1 Export (Offline)", disabled=True, use_container_width=True)
