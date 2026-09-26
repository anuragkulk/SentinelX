import csv
from collections import defaultdict

LOG_FILE = "test_logs.csv"
ALERT_FILE = "alerts.csv"

logs = []

try:
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            logs.append(row)

except FileNotFoundError:
    print("ERROR: logs.csv not found.")
    exit()


print("=" * 60)
print("                    SENTINELX")
print("              SECURITY MONITORING")
print("=" * 60)

print(f"\nTotal events collected: {len(logs)}")


# -----------------------------------------
# LOG NORMALIZATION
# -----------------------------------------

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


def clean_username(username):

    if not username:
        return None

    username = username.strip()

    if username.upper() in INVALID_VALUES:
        return None

    return username


def clean_ip(ip):

    if not ip:
        return None

    ip = ip.strip()

    if ip.upper() in INVALID_VALUES:
        return None

    if ip.upper() in LOCAL_IPS:
        return None

    return ip


# -----------------------------------------
# ANALYZE CLEANED LOGS
# -----------------------------------------

failed_by_ip = defaultdict(int)
users_by_ip = defaultdict(set)
events_by_ip = defaultdict(list)

valid_events = 0
ignored_events = 0


for log in logs:

    raw_ip = log.get("ip", "")
    raw_username = log.get("username", "")
    status = log.get("status", "").strip().upper()

    ip = clean_ip(raw_ip)
    username = clean_username(raw_username)

    # Ignore events without a valid external IP
    if ip is None:
        ignored_events += 1
        continue

    valid_events += 1

    # Use a safe username for event tracking
    if username is None:
        username = "UNKNOWN"

    if status == "FAILED":
        failed_by_ip[ip] += 1

    # Only count real usernames
    if username != "UNKNOWN":
        users_by_ip[ip].add(username)

    events_by_ip[ip].append({
        "time": log.get("time", ""),
        "username": username,
        "status": status
    })


print(f"Valid external events: {valid_events}")
print(f"Ignored local/invalid events: {ignored_events}")


# -----------------------------------------
# RISK ENGINE
# -----------------------------------------

alerts = []

for ip in events_by_ip:

    failed_count = failed_by_ip[ip]
    users = users_by_ip[ip]
    events = events_by_ip[ip]

    risk_score = 0
    detections = []

    # -----------------------------------------
    # RULE 1: REPEATED FAILED LOGINS
    # -----------------------------------------

    if failed_count >= 3:

        if failed_count >= 10:
            risk_score += 50

        elif failed_count >= 5:
            risk_score += 35

        else:
            risk_score += 20

        detections.append("Repeated Failed Logins")


    # -----------------------------------------
    # RULE 2: MULTIPLE USERS TARGETED
    # -----------------------------------------

    if len(users) >= 3:

        risk_score += 20

        detections.append("Multiple Users Targeted")


    # -----------------------------------------
    # RULE 3: FAILED -> SUCCESS
    # -----------------------------------------

    failed_then_success = False

    for i in range(1, len(events)):

        previous = events[i - 1]
        current = events[i]

        if (
            previous["status"] == "FAILED"
            and current["status"] == "SUCCESS"
        ):

            failed_then_success = True
            break

    if failed_then_success:

        risk_score += 30

        detections.append("Failed Login Followed By Success")


    # -----------------------------------------
    # LIMIT SCORE
    # -----------------------------------------

    risk_score = min(risk_score, 100)


    # -----------------------------------------
    # SEVERITY
    # -----------------------------------------

    if risk_score >= 80:
        severity = "CRITICAL"

    elif risk_score >= 60:
        severity = "HIGH"

    elif risk_score >= 30:
        severity = "MEDIUM"

    elif risk_score > 0:
        severity = "LOW"

    else:
        severity = "NONE"


    # -----------------------------------------
    # CREATE ALERT
    # -----------------------------------------

    if risk_score > 0:

        alerts.append({
            "ip": ip,
            "username": ", ".join(users) if users else "UNKNOWN",
            "detections": ", ".join(detections),
            "failed_attempts": failed_count,
            "risk_score": risk_score,
            "severity": severity
        })


# -----------------------------------------
# DISPLAY ALERTS
# -----------------------------------------

print("\n" + "=" * 60)
print("                   SECURITY ALERTS")
print("=" * 60)


if not alerts:

    print("\nNo suspicious external activity detected.")

else:

    for number, alert in enumerate(alerts, start=1):

        print(f"\nALERT #{number}")
        print("-" * 50)

        print(f"IP Address       : {alert['ip']}")
        print(f"Username         : {alert['username']}")
        print(f"Detections       : {alert['detections']}")
        print(f"Failed Attempts  : {alert['failed_attempts']}")
        print(f"Risk Score       : {alert['risk_score']}/100")
        print(f"Severity         : {alert['severity']}")


# -----------------------------------------
# SAVE ALERTS
# -----------------------------------------

with open(
    ALERT_FILE,
    "w",
    newline="",
    encoding="utf-8"
) as file:

    fieldnames = [
        "ip",
        "username",
        "detections",
        "failed_attempts",
        "risk_score",
        "severity"
    ]

    writer = csv.DictWriter(
        file,
        fieldnames=fieldnames
    )

    writer.writeheader()

    for alert in alerts:
        writer.writerow(alert)


# -----------------------------------------
# SUMMARY
# -----------------------------------------

print("\n" + "=" * 60)
print("                     SUMMARY")
print("=" * 60)

print(f"Events collected   : {len(logs)}")
print(f"Valid events       : {valid_events}")
print(f"Ignored events     : {ignored_events}")
print(f"Alerts detected    : {len(alerts)}")
print(f"Alerts saved       : {ALERT_FILE}")

print("\nSentinelX analysis complete.")