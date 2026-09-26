from flask import Flask, jsonify, request, render_template_string
import csv
import os
import re
import sys
import subprocess
from datetime import datetime

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

REAL_LOG_FILE = os.path.join(BASE_DIR, "logs.csv")
TEST_LOG_FILE = os.path.join(BASE_DIR, "test_logs.csv")
ALERT_FILE = os.path.join(BASE_DIR, "alerts.csv")
HISTORY_FILE = os.path.join(BASE_DIR, "alert_history.csv")


# ============================================================
# TIMESTAMP HANDLING
# ============================================================

def format_timestamp(value):
    """
    Converts:
        /Date(1790243964378)/
    into:
        24 Sep 2026, 09:59:24 AM

    Also supports normal ISO timestamps and common date formats.
    """

    if value is None:
        return "Unknown"

    value = str(value).strip()

    if not value or value in ["-", "None", "null", "N/A"]:
        return "Unknown"

    # PowerShell / .NET timestamp:
    # /Date(1790243964378)/
    match = re.search(r"/Date\((\d+)(?:[+-]\d+)?\)/", value)

    if match:
        try:
            milliseconds = int(match.group(1))
            dt = datetime.fromtimestamp(milliseconds / 1000)
            return dt.strftime("%d %b %Y, %I:%M:%S %p")
        except Exception:
            pass

    # Unix milliseconds
    if value.isdigit() and len(value) >= 12:
        try:
            dt = datetime.fromtimestamp(int(value) / 1000)
            return dt.strftime("%d %b %Y, %I:%M:%S %p")
        except Exception:
            pass

    # Unix seconds
    if value.isdigit() and len(value) <= 11:
        try:
            dt = datetime.fromtimestamp(int(value))
            return dt.strftime("%d %b %Y, %I:%M:%S %p")
        except Exception:
            pass

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%d-%m-%Y %H:%M:%S",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.strftime("%d %b %Y, %I:%M:%S %p")
        except Exception:
            continue

    return value


def parse_datetime(value):
    """
    Returns a datetime object for sorting.
    """

    if value is None:
        return datetime.min

    value = str(value).strip()

    match = re.search(r"/Date\((\d+)", value)

    if match:
        try:
            return datetime.fromtimestamp(int(match.group(1)) / 1000)
        except Exception:
            return datetime.min

    if value.isdigit():
        try:
            number = int(value)

            if len(value) >= 12:
                return datetime.fromtimestamp(number / 1000)

            return datetime.fromtimestamp(number)
        except Exception:
            return datetime.min

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%d-%m-%Y %H:%M:%S",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except Exception:
            continue

    return datetime.min


# ============================================================
# FILE HELPERS
# ============================================================

def read_csv_file(filename):
    if not os.path.exists(filename):
        return []

    try:
        with open(filename, "r", newline="", encoding="utf-8-sig") as file:
            reader = csv.DictReader(file)
            return list(reader)
    except Exception:
        return []


def write_csv_file(filename, rows, fieldnames):
    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(rows)


# ============================================================
# LOG NORMALIZATION
# ============================================================

def normalize_event(row):
    timestamp = (
        row.get("time")
        or row.get("timestamp")
        or row.get("TimeGenerated")
        or row.get("Time")
        or row.get("date")
        or ""
    )

    username = (
        row.get("username")
        or row.get("user")
        or row.get("UserName")
        or "UNKNOWN"
    )

    ip = (
        row.get("ip")
        or row.get("source_ip")
        or row.get("SourceIP")
        or "-"
    )

    status = (
        row.get("status")
        or row.get("Status")
        or "UNKNOWN"
    )

    return {
        "time_raw": str(timestamp),
        "time": format_timestamp(timestamp),
        "username": str(username),
        "ip": str(ip),
        "status": str(status).upper()
    }


def get_current_logs():
    """
    Real logs take priority when they exist.

    If real logs do not exist, use simulation logs.
    """

    real_logs = read_csv_file(REAL_LOG_FILE)

    if real_logs:
        return [
            normalize_event(row)
            for row in real_logs
        ]

    test_logs = read_csv_file(TEST_LOG_FILE)

    return [
        normalize_event(row)
        for row in test_logs
    ]


# ============================================================
# DETECTION ENGINE
# ============================================================

INVALID_VALUES = {
    "",
    "-",
    "UNKNOWN",
    "N/A",
    "NULL",
    "NONE"
}

LOCAL_IPS = {
    "LOCAL",
    "127.0.0.1",
    "::1",
    "0.0.0.0"
}


def analyze_events(events):
    """
    SentinelX detection rules.

    Rule 1:
        Repeated failed logins

    Rule 2:
        Multiple usernames from same IP

    Rule 3:
        Failed login followed by successful login
    """

    grouped = {}

    for event in events:

        ip = event["ip"].strip()

        if ip.upper() in INVALID_VALUES:
            continue

        if ip.upper() in LOCAL_IPS:
            continue

        if ip not in grouped:
            grouped[ip] = []

        grouped[ip].append(event)

    alerts = []

    for ip, ip_events in grouped.items():

        ip_events.sort(
            key=lambda x: parse_datetime(x["time_raw"])
        )

        failed_events = [
            event
            for event in ip_events
            if event["status"] == "FAILED"
        ]

        success_events = [
            event
            for event in ip_events
            if event["status"] == "SUCCESS"
        ]

        usernames = {
            event["username"]
            for event in ip_events
            if event["username"].upper() not in INVALID_VALUES
        }

        detections = []
        risk_score = 0

        # ----------------------------------------------------
        # RULE 1 — REPEATED FAILED LOGINS
        # ----------------------------------------------------

        failed_count = len(failed_events)

        if failed_count >= 10:

            detections.append(
                "Repeated Failed Logins"
            )

            risk_score += 50

        elif failed_count >= 5:

            detections.append(
                "Repeated Failed Logins"
            )

            risk_score += 35

        elif failed_count >= 3:

            detections.append(
                "Repeated Failed Logins"
            )

            risk_score += 20

        # ----------------------------------------------------
        # RULE 2 — MULTIPLE USERNAMES
        # ----------------------------------------------------

        if len(usernames) >= 3:

            detections.append(
                "Multiple Users Targeted"
            )

            risk_score += 20

        # ----------------------------------------------------
        # RULE 3 — FAILED -> SUCCESS
        # ----------------------------------------------------

        failed_then_success = False

        if failed_events and success_events:

            last_failed = max(
                parse_datetime(event["time_raw"])
                for event in failed_events
            )

            first_success = min(
                parse_datetime(event["time_raw"])
                for event in success_events
            )

            if first_success >= last_failed:
                failed_then_success = True

        if failed_then_success:

            detections.append(
                "Failed Login Followed By Success"
            )

            risk_score += 30

        # ----------------------------------------------------
        # NO DETECTION
        # ----------------------------------------------------

        if not detections:
            continue

        risk_score = min(risk_score, 100)

        if risk_score >= 80:
            severity = "CRITICAL"

        elif risk_score >= 60:
            severity = "HIGH"

        elif risk_score >= 30:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        timestamps = [
            parse_datetime(event["time_raw"])
            for event in ip_events
            if parse_datetime(event["time_raw"]) != datetime.min
        ]

        first_seen = min(timestamps) if timestamps else datetime.min
        last_seen = max(timestamps) if timestamps else datetime.min

        usernames_text = ", ".join(
            sorted(usernames)
        )

        alerts.append({
            "ip": ip,
            "username": usernames_text,
            "detections": " | ".join(detections),
            "failed_attempts": failed_count,
            "risk_score": risk_score,
            "severity": severity,
            "first_seen": (
                first_seen.strftime("%d %b %Y, %I:%M:%S %p")
                if first_seen != datetime.min
                else "Unknown"
            ),
            "last_seen": (
                last_seen.strftime("%d %b %Y, %I:%M:%S %p")
                if last_seen != datetime.min
                else "Unknown"
            ),
            "event_count": len(ip_events)
        })

    return alerts


def run_detection(events):
    alerts = analyze_events(events)

    fieldnames = [
        "ip",
        "username",
        "detections",
        "failed_attempts",
        "risk_score",
        "severity",
        "first_seen",
        "last_seen",
        "event_count"
    ]

    write_csv_file(
        ALERT_FILE,
        alerts,
        fieldnames
    )

    update_alert_history(alerts)

    return alerts


# ============================================================
# REAL ALERT HISTORY
# ============================================================

def update_alert_history(alerts):

    existing = read_csv_file(HISTORY_FILE)

    fieldnames = [
        "ip",
        "username",
        "detections",
        "failed_attempts",
        "risk_score",
        "severity",
        "first_seen",
        "last_seen",
        "event_count"
    ]

    existing_keys = {
        (
            row.get("ip", ""),
            row.get("username", ""),
            row.get("detections", ""),
            row.get("first_seen", ""),
            row.get("last_seen", "")
        )
        for row in existing
    }

    for alert in alerts:

        key = (
            alert["ip"],
            alert["username"],
            alert["detections"],
            alert["first_seen"],
            alert["last_seen"]
        )

        if key not in existing_keys:

            existing.append(alert)
            existing_keys.add(key)

    write_csv_file(
        HISTORY_FILE,
        existing,
        fieldnames
    )


# ============================================================
# DASHBOARD API
# ============================================================

@app.route("/api/dashboard")
def dashboard_api():

    events = get_current_logs()

    alerts = read_csv_file(ALERT_FILE)

    # If alerts.csv exists, use it.
    # Otherwise calculate from current events.
    if not alerts and events:

        alerts = run_detection(events)

    total_events = len(events)

    failed_events = sum(
        1
        for event in events
        if event["status"] == "FAILED"
    )

    successful_events = sum(
        1
        for event in events
        if event["status"] == "SUCCESS"
    )

    critical = sum(
        1
        for alert in alerts
        if alert.get("severity") == "CRITICAL"
    )

    high = sum(
        1
        for alert in alerts
        if alert.get("severity") == "HIGH"
    )

    medium = sum(
        1
        for alert in alerts
        if alert.get("severity") == "MEDIUM"
    )

    low = sum(
        1
        for alert in alerts
        if alert.get("severity") == "LOW"
    )

    return jsonify({
        "total_events": total_events,
        "failed_events": failed_events,
        "successful_events": successful_events,
        "total_alerts": len(alerts),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    })


# ============================================================
# ALERTS API
# ============================================================

@app.route("/api/alerts")
def alerts_api():

    alerts = read_csv_file(HISTORY_FILE)

    alerts.sort(
        key=lambda row: parse_datetime(
            row.get("last_seen", "")
        ),
        reverse=True
    )

    return jsonify(alerts)


# ============================================================
# LOGS API
# ============================================================

@app.route("/api/logs")
def logs_api():

    events = get_current_logs()

    events.sort(
        key=lambda x: parse_datetime(
            x["time_raw"]
        ),
        reverse=True
    )

    return jsonify(events)


# ============================================================
# INVESTIGATION API
# ============================================================

@app.route("/api/investigate/<path:ip>")
def investigate(ip):

    events = get_current_logs()

    related = [
        event
        for event in events
        if event["ip"] == ip
    ]

    related.sort(
        key=lambda x: parse_datetime(
            x["time_raw"]
        )
    )

    alerts = read_csv_file(HISTORY_FILE)

    alert = None

    for item in alerts:

        if item.get("ip") == ip:

            alert = item
            break

    return jsonify({
        "ip": ip,
        "alert": alert,
        "events": related,
        "event_count": len(related)
    })


# ============================================================
# THREAT SIMULATION
# ============================================================

@app.route("/api/simulate/<scenario>", methods=["POST"])
def simulate(scenario):

    valid_scenarios = {
        "1": "Brute Force",
        "2": "Multi-Account Attack",
        "3": "Credential Attack",
        "4": "Failed Login → Successful Login",
        "5": "Combined Attack"
    }

    if scenario not in valid_scenarios:

        return jsonify({
            "success": False,
            "message": "Invalid simulation scenario."
        }), 400

    try:

        # ----------------------------------------------------
        # RUN THE USER'S EXISTING simulator.py
        # ----------------------------------------------------

        result = subprocess.run(
            [
                sys.executable,
                os.path.join(
                    BASE_DIR,
                    "simulator.py"
                ),
                scenario
            ],
            capture_output=True,
            text=True,
            cwd=BASE_DIR
        )

        if result.returncode != 0:

            return jsonify({
                "success": False,
                "message": "Simulation failed.",
                "details": result.stderr
            }), 500

        # ----------------------------------------------------
        # READ THE NEW SYNTHETIC EVENTS
        # ----------------------------------------------------

        simulated_rows = read_csv_file(
            TEST_LOG_FILE
        )

        simulated_events = [
            normalize_event(row)
            for row in simulated_rows
        ]

        # ----------------------------------------------------
        # RUN DETECTION IMMEDIATELY
        # ----------------------------------------------------

        alerts = run_detection(
            simulated_events
        )

        failed_count = sum(
            1
            for event in simulated_events
            if event["status"] == "FAILED"
        )

        success_count = sum(
            1
            for event in simulated_events
            if event["status"] == "SUCCESS"
        )

        return jsonify({
            "success": True,
            "scenario": valid_scenarios[scenario],
            "events_generated": len(simulated_events),
            "failed_events": failed_count,
            "successful_events": success_count,
            "alerts_detected": len(alerts),
            "message": (
                f"✓ {valid_scenarios[scenario]} simulation completed. "
                f"{len(simulated_events)} synthetic security events "
                f"were generated and {len(alerts)} alert(s) detected."
            ),
            "details": (
                result.stdout.strip()
                if result.stdout
                else "Simulation completed successfully."
            )
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "message": "Unable to execute the threat simulation.",
            "details": str(error)
        }), 500


# ============================================================
# REFRESH / REPROCESS
# ============================================================

@app.route("/api/refresh", methods=["POST"])
def refresh():

    events = get_current_logs()

    alerts = run_detection(events)

    return jsonify({
        "success": True,
        "events": len(events),
        "alerts": len(alerts),
        "message": (
            f"SentinelX refreshed successfully. "
            f"{len(events)} events analyzed and "
            f"{len(alerts)} alert(s) detected."
        )
    })


# ============================================================
# FRONTEND
# ============================================================

HTML = r"""
<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>SentinelX Security Operations Center</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background:
        radial-gradient(circle at top right, rgba(0, 180, 255, .08), transparent 30%),
        radial-gradient(circle at bottom left, rgba(0, 255, 170, .05), transparent 30%),
        #050911;
    color: #dce7f5;
    font-family: Arial, Helvetica, sans-serif;
}

.app {
    display: flex;
    min-height: 100vh;
}

/* SIDEBAR */

.sidebar {
    width: 245px;
    border-right: 1px solid #182333;
    background: rgba(5, 10, 18, .95);
    padding: 25px 18px;
    position: fixed;
    height: 100vh;
}

.logo {
    font-size: 25px;
    font-weight: 800;
    letter-spacing: 3px;
    color: #55dfff;
    margin-bottom: 5px;
}

.logo-sub {
    font-size: 10px;
    color: #64748b;
    letter-spacing: 2px;
    margin-bottom: 35px;
}

.nav {
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.nav button {
    background: transparent;
    border: 1px solid transparent;
    color: #8291a7;
    padding: 13px 15px;
    text-align: left;
    border-radius: 8px;
    cursor: pointer;
    font-size: 13px;
}

.nav button:hover,
.nav button.active {
    background: #0c1725;
    border-color: #18334c;
    color: #55dfff;
}

/* MAIN */

.main {
    margin-left: 245px;
    width: calc(100% - 245px);
    padding: 28px;
}

.topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 25px;
}

.title {
    font-size: 25px;
    font-weight: 700;
}

.subtitle {
    color: #64748b;
    font-size: 12px;
    margin-top: 5px;
}

.system-status {
    border: 1px solid #153b35;
    background: #071511;
    color: #50e3b2;
    padding: 9px 14px;
    border-radius: 7px;
    font-size: 11px;
}

/* CARDS */

.metrics {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 15px;
    margin-bottom: 20px;
}

.card {
    background: rgba(8, 15, 26, .92);
    border: 1px solid #182536;
    border-radius: 10px;
    padding: 20px;
    position: relative;
    overflow: hidden;
}

.card::after {
    content: "";
    position: absolute;
    height: 1px;
    left: 0;
    right: 0;
    top: 0;
    background: linear-gradient(
        90deg,
        transparent,
        #22d3ee,
        transparent
    );
    opacity: .45;
}

.card-label {
    font-size: 10px;
    color: #6f8096;
    letter-spacing: 1.5px;
    text-transform: uppercase;
}

.card-value {
    font-size: 30px;
    font-weight: 700;
    margin-top: 8px;
    color: #edf6ff;
}

/* PANELS */

.panel {
    background: rgba(7, 14, 24, .92);
    border: 1px solid #182536;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 20px;
}

.panel-title {
    font-size: 13px;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: #9eb1c8;
    margin-bottom: 18px;
}

/* TABLE */

.table-wrap {
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th {
    text-align: left;
    color: #607086;
    font-size: 10px;
    letter-spacing: 1px;
    padding: 12px;
    border-bottom: 1px solid #172231;
}

td {
    padding: 13px 12px;
    font-size: 12px;
    border-bottom: 1px solid #111b28;
    color: #b9c6d7;
}

tr:hover {
    background: #091321;
}

.status-success {
    color: #4ade80;
}

.status-failed {
    color: #fb7185;
}

/* BADGES */

.badge {
    display: inline-block;
    padding: 5px 8px;
    border-radius: 5px;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: .8px;
}

.badge-CRITICAL {
    background: rgba(239, 68, 68, .13);
    color: #ff6b6b;
}

.badge-HIGH {
    background: rgba(249, 115, 22, .13);
    color: #fb923c;
}

.badge-MEDIUM {
    background: rgba(234, 179, 8, .13);
    color: #facc15;
}

.badge-LOW {
    background: rgba(59, 130, 246, .13);
    color: #60a5fa;
}

/* SIMULATOR */

.sim-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 15px;
}

.sim-card {
    border: 1px solid #1b2b3e;
    background: #08111d;
    padding: 20px;
    border-radius: 10px;
    transition: .2s;
}

.sim-card:hover {
    transform: translateY(-3px);
    border-color: #2b6177;
}

.sim-name {
    font-weight: 700;
    color: #dbeafe;
    margin-bottom: 7px;
}

.sim-description {
    color: #687b91;
    font-size: 11px;
    min-height: 34px;
    margin-bottom: 15px;
}

.sim-btn {
    width: 100%;
    padding: 10px;
    border: 1px solid #1e5367;
    background: #0b202c;
    color: #55dfff;
    border-radius: 6px;
    cursor: pointer;
    font-weight: 600;
}

.sim-btn:hover {
    background: #103444;
}

.sim-btn:disabled {
    opacity: .5;
    cursor: wait;
}

/* MESSAGE */

.message {
    display: none;
    padding: 14px 17px;
    border-radius: 8px;
    margin-bottom: 20px;
    font-size: 12px;
}

.message.success {
    display: block;
    background: #071a13;
    border: 1px solid #164e3d;
    color: #5ee7b7;
}

.message.error {
    display: block;
    background: #1a0b0d;
    border: 1px solid #5c2027;
    color: #fb7185;
}

/* EMPTY */

.empty {
    text-align: center;
    padding: 45px;
    color: #526277;
    font-size: 12px;
}

/* GRID */

.two-column {
    display: grid;
    grid-template-columns: 1.5fr 1fr;
    gap: 20px;
}

/* RESPONSIVE */

@media(max-width: 1000px) {

    .sidebar {
        display: none;
    }

    .main {
        margin-left: 0;
        width: 100%;
    }

    .metrics {
        grid-template-columns: repeat(2, 1fr);
    }

    .sim-grid {
        grid-template-columns: 1fr;
    }

    .two-column {
        grid-template-columns: 1fr;
    }
}

</style>
</head>

<body>

<div class="app">

    <aside class="sidebar">

        <div class="logo">
            SENTINELX
        </div>

        <div class="logo-sub">
            SECURITY OPERATIONS CENTER
        </div>

        <div class="nav">

            <button
                class="active"
                onclick="showSection('overview', this)">
                ◈ Overview
            </button>

            <button
                onclick="showSection('alerts', this)">
                ⚠ Alert History
            </button>

            <button
                onclick="showSection('logs', this)">
                ◉ Security Logs
            </button>

            <button
                onclick="showSection('simulator', this)">
                ⌁ Threat Simulation
            </button>

        </div>

    </aside>


    <main class="main">

        <div class="topbar">

            <div>
                <div class="title">
                    Security Operations Dashboard
                </div>

                <div class="subtitle">
                    Real-time security event monitoring
                </div>
            </div>

            <div class="system-status">
                ● SYSTEM ONLINE
            </div>

        </div>


        <div id="message"
             class="message">
        </div>


        <!-- ================================================= -->
        <!-- OVERVIEW -->
        <!-- ================================================= -->

        <section id="overview">

            <div class="metrics">

                <div class="card">
                    <div class="card-label">
                        Total Events
                    </div>

                    <div id="totalEvents"
                         class="card-value">
                        0
                    </div>
                </div>


                <div class="card">
                    <div class="card-label">
                        Failed Logins
                    </div>

                    <div id="failedEvents"
                         class="card-value">
                        0
                    </div>
                </div>


                <div class="card">
                    <div class="card-label">
                        Successful Logins
                    </div>

                    <div id="successEvents"
                         class="card-value">
                        0
                    </div>
                </div>


                <div class="card">
                    <div class="card-label">
                        Detected Alerts
                    </div>

                    <div id="totalAlerts"
                         class="card-value">
                        0
                    </div>
                </div>

            </div>


            <div class="two-column">

                <div class="panel">

                    <div class="panel-title">
                        Event Distribution
                    </div>

                    <canvas id="eventChart"></canvas>

                </div>


                <div class="panel">

                    <div class="panel-title">
                        Severity Distribution
                    </div>

                    <canvas id="severityChart"></canvas>

                </div>

            </div>


            <div class="panel">

                <div class="panel-title">
                    Current Detected Threats
                </div>

                <div id="overviewAlerts">
                </div>

            </div>

        </section>


        <!-- ================================================= -->
        <!-- ALERT HISTORY -->
        <!-- ================================================= -->

        <section id="alerts"
                 style="display:none">

            <div class="panel">

                <div class="panel-title">
                    Alert History
                </div>

                <div id="alertHistory">
                </div>

            </div>

        </section>


        <!-- ================================================= -->
        <!-- LOGS -->
        <!-- ================================================= -->

        <section id="logs"
                 style="display:none">

            <div class="panel">

                <div class="panel-title">
                    Security Event Stream
                </div>

                <div id="logsTable">
                </div>

            </div>

        </section>


        <!-- ================================================= -->
        <!-- SIMULATOR -->
        <!-- ================================================= -->

        <section id="simulator"
                 style="display:none">

            <div class="panel">

                <div class="panel-title">
                    Safe Threat Simulation Lab
                </div>

                <p style="
                    color:#66788e;
                    font-size:12px;
                    margin-bottom:20px;
                ">
                    Generates synthetic security events locally.
                    No real attack is performed.
                </p>


                <div class="sim-grid">

                    <div class="sim-card">

                        <div class="sim-name">
                            Brute Force
                        </div>

                        <div class="sim-description">
                            Generates repeated failed
                            authentication attempts.
                        </div>

                        <button
                            class="sim-btn"
                            onclick="runSimulation('1', this)">
                            RUN SIMULATION
                        </button>

                    </div>


                    <div class="sim-card">

                        <div class="sim-name">
                            Multi-Account Attack
                        </div>

                        <div class="sim-description">
                            Simulates one source targeting
                            multiple accounts.
                        </div>

                        <button
                            class="sim-btn"
                            onclick="runSimulation('2', this)">
                            RUN SIMULATION
                        </button>

                    </div>


                    <div class="sim-card">

                        <div class="sim-name">
                            Credential Attack
                        </div>

                        <div class="sim-description">
                            Simulates repeated attempts
                            against different usernames.
                        </div>

                        <button
                            class="sim-btn"
                            onclick="runSimulation('3', this)">
                            RUN SIMULATION
                        </button>

                    </div>


                    <div class="sim-card">

                        <div class="sim-name">
                            Failed → Success
                        </div>

                        <div class="sim-description">
                            Simulates failed authentication
                            followed by a successful login.
                        </div>

                        <button
                            class="sim-btn"
                            onclick="runSimulation('4', this)">
                            RUN SIMULATION
                        </button>

                    </div>


                    <div class="sim-card">

                        <div class="sim-name">
                            Combined Attack
                        </div>

                        <div class="sim-description">
                            Runs multiple synthetic attack
                            patterns together.
                        </div>

                        <button
                            class="sim-btn"
                            onclick="runSimulation('5', this)">
                            RUN SIMULATION
                        </button>

                    </div>

                </div>

            </div>

        </section>


    </main>

</div>


<script>

let eventChart = null;
let severityChart = null;


/* =========================================================
   NAVIGATION
========================================================= */

function showSection(section, button) {

    document
        .querySelectorAll("main section")
        .forEach(element => {
            element.style.display = "none";
        });

    document.getElementById(section)
        .style.display = "block";


    document
        .querySelectorAll(".nav button")
        .forEach(element => {
            element.classList.remove("active");
        });

    button.classList.add("active");


    if(section === "overview") {
        loadDashboard();
    }

    if(section === "alerts") {
        loadAlerts();
    }

    if(section === "logs") {
        loadLogs();
    }
}


/* =========================================================
   MESSAGE
========================================================= */

function showMessage(text, type) {

    const box =
        document.getElementById("message");

    box.className =
        "message " + type;

    box.innerText = text;

    setTimeout(() => {
        box.className = "message";
        box.innerText = "";
    }, 7000);
}


/* =========================================================
   DASHBOARD
========================================================= */

async function loadDashboard() {

    const response =
        await fetch("/api/dashboard");

    const data =
        await response.json();


    document.getElementById("totalEvents")
        .innerText = data.total_events;

    document.getElementById("failedEvents")
        .innerText = data.failed_events;

    document.getElementById("successEvents")
        .innerText = data.successful_events;

    document.getElementById("totalAlerts")
        .innerText = data.total_alerts;


    updateEventChart(data);

    updateSeverityChart(data);

    loadOverviewAlerts();
}


/* =========================================================
   CHARTS
========================================================= */

function updateEventChart(data) {

    if(eventChart) {
        eventChart.destroy();
    }

    eventChart =
        new Chart(
            document.getElementById("eventChart"),
            {
                type: "doughnut",

                data: {
                    labels: [
                        "SUCCESS",
                        "FAILED"
                    ],

                    datasets: [{
                        data: [
                            data.successful_events,
                            data.failed_events
                        ]
                    }]
                },

                options: {
                    plugins: {
                        legend: {
                            labels: {
                                color: "#9eb1c8"
                            }
                        }
                    }
                }
            }
        );
}


function updateSeverityChart(data) {

    if(severityChart) {
        severityChart.destroy();
    }

    severityChart =
        new Chart(
            document.getElementById("severityChart"),
            {
                type: "bar",

                data: {
                    labels: [
                        "LOW",
                        "MEDIUM",
                        "HIGH",
                        "CRITICAL"
                    ],

                    datasets: [{
                        label: "Alerts",

                        data: [
                            data.low,
                            data.medium,
                            data.high,
                            data.critical
                        ]
                    }]
                },

                options: {

                    scales: {

                        x: {
                            ticks: {
                                color: "#718198"
                            }
                        },

                        y: {
                            beginAtZero: true,

                            ticks: {
                                color: "#718198"
                            }
                        }
                    },

                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            }
        );
}


/* =========================================================
   OVERVIEW ALERTS
========================================================= */

async function loadOverviewAlerts() {

    const response =
        await fetch("/api/alerts");

    const alerts =
        await response.json();

    const container =
        document.getElementById("overviewAlerts");


    if(alerts.length === 0) {

        container.innerHTML = `
            <div class="empty">
                No detected threats.
                SentinelX has no alert data yet.
            </div>
        `;

        return;
    }


    container.innerHTML =
        alerts.slice(0, 5)
        .map(alert => `

            <div style="
                display:flex;
                justify-content:space-between;
                align-items:center;
                padding:15px 0;
                border-bottom:1px solid #111b28;
            ">

                <div>

                    <div style="
                        font-size:12px;
                        color:#dbeafe;
                        margin-bottom:5px;
                    ">
                        ${escapeHtml(alert.ip)}
                    </div>

                    <div style="
                        font-size:10px;
                        color:#65758a;
                    ">
                        ${escapeHtml(alert.detections)}
                    </div>

                </div>

                <div style="text-align:right">

                    <span class="badge badge-${alert.severity}">
                        ${alert.severity}
                    </span>

                    <div style="
                        font-size:10px;
                        color:#607086;
                        margin-top:6px;
                    ">
                        Risk ${alert.risk_score}/100
                    </div>

                </div>

            </div>

        `)
        .join("");
}


/* =========================================================
   ALERT HISTORY
========================================================= */

async function loadAlerts() {

    const response =
        await fetch("/api/alerts");

    const alerts =
        await response.json();

    const container =
        document.getElementById("alertHistory");


    if(alerts.length === 0) {

        container.innerHTML = `
            <div class="empty">
                Alert history is empty.
                No real SentinelX detections have been recorded yet.
            </div>
        `;

        return;
    }


    container.innerHTML = `

        <div class="table-wrap">

            <table>

                <thead>

                    <tr>

                        <th>LAST SEEN</th>
                        <th>FIRST SEEN</th>
                        <th>SOURCE IP</th>
                        <th>USERNAME(S)</th>
                        <th>DETECTION</th>
                        <th>RISK</th>
                        <th>SEVERITY</th>

                    </tr>

                </thead>

                <tbody>

                    ${
                        alerts.map(alert => `

                            <tr>

                                <td>
                                    ${escapeHtml(alert.last_seen)}
                                </td>

                                <td>
                                    ${escapeHtml(alert.first_seen)}
                                </td>

                                <td>
                                    ${escapeHtml(alert.ip)}
                                </td>

                                <td>
                                    ${escapeHtml(alert.username)}
                                </td>

                                <td>
                                    ${escapeHtml(alert.detections)}
                                </td>

                                <td>
                                    ${escapeHtml(alert.risk_score)}/100
                                </td>

                                <td>
                                    <span class="
                                        badge
                                        badge-${alert.severity}
                                    ">
                                        ${escapeHtml(alert.severity)}
                                    </span>
                                </td>

                            </tr>

                        `).join("")
                    }

                </tbody>

            </table>

        </div>
    `;
}


/* =========================================================
   LOG STREAM
========================================================= */

async function loadLogs() {

    const response =
        await fetch("/api/logs");

    const logs =
        await response.json();

    const container =
        document.getElementById("logsTable");


    if(logs.length === 0) {

        container.innerHTML = `
            <div class="empty">
                No security events have been collected yet.
            </div>
        `;

        return;
    }


    container.innerHTML = `

        <div class="table-wrap">

            <table>

                <thead>

                    <tr>

                        <th>EVENT TIME</th>
                        <th>USERNAME</th>
                        <th>SOURCE IP</th>
                        <th>RESULT</th>

                    </tr>

                </thead>

                <tbody>

                    ${
                        logs.map(event => `

                            <tr>

                                <td>
                                    ${escapeHtml(event.time)}
                                </td>

                                <td>
                                    ${escapeHtml(event.username)}
                                </td>

                                <td>
                                    ${escapeHtml(event.ip)}
                                </td>

                                <td class="${
                                    event.status === "SUCCESS"
                                    ? "status-success"
                                    : "status-failed"
                                }">

                                    ${
                                        event.status === "SUCCESS"
                                        ? "● SUCCESS"
                                        : "● FAILED"
                                    }

                                </td>

                            </tr>

                        `).join("")
                    }

                </tbody>

            </table>

        </div>
    `;
}


/* =========================================================
   SIMULATION
========================================================= */

async function runSimulation(scenario, button) {

    button.disabled = true;

    button.innerText =
        "RUNNING...";


    showMessage(
        "SentinelX is generating synthetic security events...",
        "success"
    );


    try {

        const response =
            await fetch(
                `/api/simulate/${scenario}`,
                {
                    method: "POST"
                }
            );


        const data =
            await response.json();


        if(data.success) {

            showMessage(
                data.message,
                "success"
            );

            await loadDashboard();

        } else {

            showMessage(
                data.message ||
                "Simulation failed.",
                "error"
            );
        }

    }

    catch(error) {

        showMessage(
            "Could not connect to the SentinelX backend.",
            "error"
        );

    }

    finally {

        button.disabled = false;

        button.innerText =
            "RUN SIMULATION";
    }
}


/* =========================================================
   HTML ESCAPE
========================================================= */

function escapeHtml(value) {

    if(value === null ||
       value === undefined) {
        return "";
    }

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


/* =========================================================
   INITIAL LOAD
========================================================= */

loadDashboard();

</script>

</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(HTML)


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("              SENTINELX SOC")
    print("=" * 60)
    print()
    print("Dashboard:")
    print("http://127.0.0.1:5000")
    print()
    print("Simulator:")
    print("Connected to existing simulator.py")
    print()
    print("No mock dashboard data is generated.")
    print("All events and alerts come from CSV data.")
    print()
    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )