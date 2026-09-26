# dashboard.py

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


# ============================================================
# ATTACK SIMULATOR
# ============================================================

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

    if st.button(
        "🚀 Run Simulation",
        use_container_width=True
    ):

        try:

            process = subprocess.run(
                [
                    sys.executable,
                    "simulator.py",
                    scenario_map[scenario]
                ],
                capture_output=True,
                text=True,
                cwd=os.path.dirname(
                    os.path.abspath(__file__)
                )
            )

            if process.returncode == 0:

                st.success(
                    "Simulation completed successfully."
                )

                if os.path.exists(TEST_LOG_FILE):

                    df = pd.read_csv(TEST_LOG_FILE)

                    st.subheader(
                        "📋 Generated Security Events"
                    )

                    st.dataframe(
                        df,
                        use_container_width=True,
                        height=400
                    )

                    st.info(
                        "These events are synthetic. "
                        "No real attack was performed."
                    )

            else:

                st.error("Simulation failed.")

                if process.stderr:
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
        st.metric(
            "Brute Force",
            "10 failures"
        )

    with col2:
        st.metric(
            "Multi-Account",
            "4 users"
        )

    with col3:
        st.metric(
            "Combined Attack",
            "Multiple patterns"
        )


# ============================================================
# SECURITY DASHBOARD
# ============================================================

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
                "Go to Attack Simulator and "
                "generate test data first."
            )

    else:

        try:

            # ==================================================
            # LOAD LOGS
            # ==================================================

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


            # ==================================================
            # LOAD ALERTS
            # ==================================================

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


            # ==================================================
            # SECURITY OVERVIEW
            # ==================================================

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


            # ==================================================
            # ALERT HISTORY
            # ==================================================

            if total_alerts > 0:

                st.header("🚨 Alert History")

                st.caption(
                    "All security alerts detected by SentinelX."
                )

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


                # ==================================================
                # ALERT INVESTIGATION
                # ==================================================

                st.divider()

                st.header("🔍 Alert Investigation")

                if "ip" in alerts.columns:

                    alert_ips = (
                        alerts["ip"]
                        .astype(str)
                        .unique()
                        .tolist()
                    )

                    selected_ip = st.selectbox(
                        "Select an IP to investigate",
                        alert_ips
                    )

                    selected_alerts = alerts[
                        alerts["ip"]
                        .astype(str)
                        == selected_ip
                    ]

                    selected_alert = (
                        selected_alerts.iloc[0]
                    )


                    # ==============================================
                    # ALERT SUMMARY
                    # ==============================================

                    st.subheader(
                        f"Investigation: {selected_ip}"
                    )

                    col1, col2, col3, col4 = st.columns(4)

                    with col1:

                        st.metric(
                            "Risk Score",
                            f"{selected_alert.get('risk_score', 0)}/100"
                        )

                    with col2:

                        st.metric(
                            "Severity",
                            selected_alert.get(
                                "severity",
                                "UNKNOWN"
                            )
                        )

                    with col3:

                        st.metric(
                            "Failed Attempts",
                            selected_alert.get(
                                "failed_attempts",
                                0
                            )
                        )

                    with col4:

                        username = selected_alert.get(
                            "username",
                            "UNKNOWN"
                        )

                        st.metric(
                            "Username",
                            username
                        )


                    # ==============================================
                    # DETECTION DETAILS
                    # ==============================================

                    st.subheader(
                        "🧠 Detection Details"
                    )

                    detections = str(
                        selected_alert.get(
                            "detections",
                            "No detection information"
                        )
                    )

                    st.info(
                        f"SentinelX detected: {detections}"
                    )


                    # ==============================================
                    # INVESTIGATION EXPLANATION
                    # ==============================================

                    st.subheader(
                        "📖 Why Was This Alert Triggered?"
                    )

                    risk_score = int(
                        selected_alert.get(
                            "risk_score",
                            0
                        )
                    )

                    failed_attempts = int(
                        selected_alert.get(
                            "failed_attempts",
                            0
                        )
                    )

                    explanation = []

                    if failed_attempts >= 10:

                        explanation.append(
                            "• High number of failed login attempts detected."
                        )

                    elif failed_attempts >= 5:

                        explanation.append(
                            "• Repeated failed login attempts detected."
                        )

                    elif failed_attempts >= 3:

                        explanation.append(
                            "• Multiple failed login attempts detected."
                        )

                    detection_text = detections.upper()

                    if (
                        "MULTIPLE" in detection_text
                        or "USER" in detection_text
                    ):

                        explanation.append(
                            "• Multiple usernames were targeted from the same IP."
                        )

                    if (
                        "SUCCESS" in detection_text
                        or "FOLLOWED" in detection_text
                    ):

                        explanation.append(
                            "• A successful login occurred after suspicious failed attempts."
                        )

                    if risk_score >= 80:

                        explanation.append(
                            "• Combined risk indicators produced a critical risk score."
                        )

                    elif risk_score >= 60:

                        explanation.append(
                            "• Multiple suspicious indicators produced a high risk score."
                        )

                    elif risk_score >= 30:

                        explanation.append(
                            "• Suspicious activity produced a medium risk score."
                        )

                    else:

                        explanation.append(
                            "• Limited suspicious activity produced a low risk score."
                        )

                    for item in explanation:

                        st.write(item)


                    # ==============================================
                    # EVIDENCE TIMELINE
                    # ==============================================

                    st.subheader(
                        "🕒 Evidence Timeline"
                    )

                    if (
                        "ip" in logs.columns
                        and "time" in logs.columns
                    ):

                        investigation_logs = logs[
                            logs["ip"]
                            .astype(str)
                            == selected_ip
                        ].copy()

                        if len(investigation_logs) > 0:

                            investigation_logs = (
                                investigation_logs
                                .sort_values("time")
                            )

                            st.dataframe(
                                investigation_logs[
                                    [
                                        column
                                        for column in [
                                            "time",
                                            "username",
                                            "ip",
                                            "status"
                                        ]
                                        if column
                                        in investigation_logs.columns
                                    ]
                                ],
                                use_container_width=True,
                                height=300
                            )

                        else:

                            st.info(
                                "No matching log evidence found "
                                "for this IP in the selected log source."
                            )


                # ==================================================
                # RISK DISTRIBUTION
                # ==================================================

                st.divider()

                st.subheader("📈 Risk Distribution")

                risk_distribution = (
                    alerts["severity"]
                    .value_counts()
                )

                st.bar_chart(
                    risk_distribution
                )


                # ==================================================
                # RISK SCORES
                # ==================================================

                st.subheader("🎯 Risk Scores")

                if (
                    "ip" in alerts.columns
                    and "risk_score" in alerts.columns
                ):

                    risk_chart = alerts[
                        [
                            "ip",
                            "risk_score"
                        ]
                    ].copy()

                    risk_chart = (
                        risk_chart
                        .set_index("ip")
                    )

                    st.bar_chart(
                        risk_chart
                    )


            else:

                st.success(
                    "No security alerts detected."
                )


            # ==================================================
            # RAW SECURITY LOGS
            # ==================================================

            st.divider()

            st.subheader(
                "📋 Raw Security Logs"
            )

            st.dataframe(
                logs,
                use_container_width=True,
                height=350
            )


        except Exception as error:

            st.error(
                f"Unable to load security data: {error}"
            )