import streamlit as st
import pandas as pd
import os
import subprocess
import sys

LOG_FILE = "logs.csv"
TEST_LOG_FILE = "test_logs.csv"
ALERT_FILE = "alerts.csv"

st.set_page_config(
    page_title="SentinelX Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SentinelX")
st.caption("Security Monitoring & Threat Detection Platform")

st.sidebar.title("SentinelX")

mode = st.sidebar.radio(
    "Select Mode",
    [
        "📊 Security Dashboard",
        "🧪 Attack Simulator"
    ]
)

if mode == "🧪 Attack Simulator":

    st.header("🧪 Attack Simulation Lab")
    st.write(
        "Generate safe synthetic security events and test "
        "SentinelX without performing a real attack."
    )

    scenario = st.selectbox(
        "Choose Attack Scenario",
        [
            "Brute Force",
            "Multi-Account Attack",
            "Credential Attack Pattern",
            "Failed Login → Successful Login",
            "Combined Attack"
        ]
    )

    scenario_map = {
        "Brute Force": "1",
        "Multi-Account Attack": "2",
        "Credential Attack Pattern": "3",
        "Failed Login → Successful Login": "4",
        "Combined Attack": "5"
    }

    if st.button("🚀 Run Simulation", use_container_width=True):

        try:
            process = subprocess.run(
                [sys.executable, "simulator.py"],
                input=scenario_map[scenario] + "\n",
                text=True,
                capture_output=True
            )

            if process.returncode == 0:
                st.success("Simulation completed successfully.")

                if os.path.exists(TEST_LOG_FILE):
                    df = pd.read_csv(TEST_LOG_FILE)

                    st.subheader("Generated Security Events")

                    st.dataframe(
                        df,
                        use_container_width=True,
                        height=400
                    )

                    st.info(
                        "The events above are synthetic. "
                        "No real attack was performed."
                    )

            else:
                st.error("Simulation failed.")
                st.code(process.stderr)

        except FileNotFoundError:
            st.error(
                "simulator.py was not found. "
                "Make sure it is in the SentinelX folder."
            )

    st.divider()

    st.subheader("Available Simulations")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Brute Force", "10 failures")

    with col2:
        st.metric("Multi-Account", "4 users")

    with col3:
        st.metric("Combined Attack", "Multiple patterns")


elif mode == "📊 Security Dashboard":

    st.header("📊 Security Dashboard")

    log_source = st.radio(
        "Log Source",
        [
            "Real Windows Logs",
            "Simulation Logs"
        ],
        horizontal=True
    )

    selected_file = (
        LOG_FILE
        if log_source == "Real Windows Logs"
        else TEST_LOG_FILE
    )

    if not os.path.exists(selected_file):

        st.warning(
            f"{selected_file} does not exist yet."
        )

        if log_source == "Simulation Logs":
            st.info(
                "Go to Attack Simulator and generate test data first."
            )

    else:

        try:
            logs = pd.read_csv(selected_file)

            total_events = len(logs)

            failed_events = len(
                logs[
                    logs["status"]
                    .astype(str)
                    .str.upper()
                    == "FAILED"
                ]
            )

            successful_events = len(
                logs[
                    logs["status"]
                    .astype(str)
                    .str.upper()
                    == "SUCCESS"
                ]
            )

            unique_ips = (
                logs["ip"]
                .astype(str)
                .nunique()
            )

            if os.path.exists(ALERT_FILE):

                alerts = pd.read_csv(ALERT_FILE)

                total_alerts = len(alerts)

                critical_alerts = len(
                    alerts[
                        alerts["severity"]
                        .astype(str)
                        .str.upper()
                        == "CRITICAL"
                    ]
                )

                high_alerts = len(
                    alerts[
                        alerts["severity"]
                        .astype(str)
                        .str.upper()
                        == "HIGH"
                    ]
                )

                average_risk = (
                    alerts["risk_score"].mean()
                    if total_alerts > 0
                    else 0
                )

            else:

                alerts = pd.DataFrame()

                total_alerts = 0
                critical_alerts = 0
                high_alerts = 0
                average_risk = 0

            st.subheader("Security Overview")

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric(
                    "Total Events",
                    total_events
                )

            with col2:
                st.metric(
                    "Failed Logins",
                    failed_events
                )

            with col3:
                st.metric(
                    "Alerts",
                    total_alerts
                )

            with col4:
                st.metric(
                    "Critical Alerts",
                    critical_alerts
                )

            st.divider()

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric(
                    "Successful Logins",
                    successful_events
                )

            with col2:
                st.metric(
                    "Unique IPs",
                    unique_ips
                )

            with col3:
                st.metric(
                    "High Alerts",
                    high_alerts
                )

            with col4:
                st.metric(
                    "Average Risk",
                    f"{average_risk:.1f}/100"
                )

            st.divider()

            if total_alerts > 0:

                st.subheader("🚨 Detected Threats")

                display_columns = [
                    "ip",
                    "username",
                    "detections",
                    "failed_attempts",
                    "risk_score",
                    "severity"
                ]

                available_columns = [
                    column
                    for column in display_columns
                    if column in alerts.columns
                ]

                st.dataframe(
                    alerts[available_columns],
                    use_container_width=True,
                    height=350
                )

                st.subheader("📈 Risk Distribution")

                risk_distribution = (
                    alerts["severity"]
                    .value_counts()
                )

                st.bar_chart(risk_distribution)

                st.subheader("🎯 Risk Scores")

                risk_chart = alerts[
                    ["ip", "risk_score"]
                ].copy()

                risk_chart = risk_chart.set_index("ip")

                st.bar_chart(risk_chart)

            else:

                st.success(
                    "No security alerts detected."
                )

            st.divider()

            st.subheader("📋 Raw Security Logs")

            st.dataframe(
                logs,
                use_container_width=True,
                height=350
            )

        except Exception as error:

            st.error(
                f"Unable to load security data: {error}"
            )