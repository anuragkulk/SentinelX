import csv
import random
import sys
from datetime import datetime, timedelta

TEST_LOG_FILE = "test_logs.csv"


def add_event(events, time, username, ip, status):
    events.append({
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "username": username,
        "ip": ip,
        "status": status
    })


def brute_force(events):
    ip = "192.168.1.201"
    username = "admin"
    start = datetime.now()

    for i in range(10):
        add_event(
            events,
            start + timedelta(seconds=i * 5),
            username,
            ip,
            "FAILED"
        )


def multi_account(events):
    ip = "192.168.1.202"
    start = datetime.now()

    users = ["admin", "user1", "user2", "guest"]

    for i, username in enumerate(users):
        add_event(
            events,
            start + timedelta(seconds=i * 8),
            username,
            ip,
            "FAILED"
        )

    add_event(
        events,
        start + timedelta(seconds=40),
        "guest",
        ip,
        "SUCCESS"
    )


def credential_attack(events):
    ip = "192.168.1.203"
    start = datetime.now()

    users = [
        "admin",
        "administrator",
        "root",
        "test",
        "guest"
    ]

    for i in range(8):
        add_event(
            events,
            start + timedelta(seconds=i * 6),
            random.choice(users),
            ip,
            "FAILED"
        )


def failed_then_success(events):
    ip = "192.168.1.204"
    username = "admin"
    start = datetime.now()

    for i in range(4):
        add_event(
            events,
            start + timedelta(seconds=i * 5),
            username,
            ip,
            "FAILED"
        )

    add_event(
        events,
        start + timedelta(seconds=30),
        username,
        ip,
        "SUCCESS"
    )


def combined_attack(events):
    ip = "192.168.1.205"
    start = datetime.now()

    users = ["admin", "user1", "user2", "guest"]

    for i in range(8):
        add_event(
            events,
            start + timedelta(seconds=i * 4),
            users[i % len(users)],
            ip,
            "FAILED"
        )

    add_event(
        events,
        start + timedelta(seconds=40),
        "admin",
        ip,
        "SUCCESS"
    )


def normal_activity(events):
    ip = "192.168.1.210"
    start = datetime.now()

    for i in range(3):
        add_event(
            events,
            start + timedelta(seconds=i * 20),
            "normaluser",
            ip,
            "SUCCESS"
        )


def save_logs(events):
    with open(
        TEST_LOG_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "time",
                "username",
                "ip",
                "status"
            ]
        )

        writer.writeheader()
        writer.writerows(events)


def run_simulation(choice):
    events = []

    if choice == "1":
        brute_force(events)
        scenario = "Brute Force Simulation"

    elif choice == "2":
        multi_account(events)
        scenario = "Multi-Account Attack Simulation"

    elif choice == "3":
        credential_attack(events)
        scenario = "Credential Attack Pattern Simulation"

    elif choice == "4":
        failed_then_success(events)
        scenario = "Failed Login -> Successful Login Simulation"

    elif choice == "5":
        brute_force(events)
        multi_account(events)
        credential_attack(events)
        failed_then_success(events)
        combined_attack(events)
        normal_activity(events)
        scenario = "Combined Attack Simulation"

    else:
        print("Invalid simulation choice.")
        return False

    save_logs(events)

    print("=" * 60)
    print("              SENTINELX SIMULATOR")
    print("=" * 60)
    print("Scenario:", scenario)
    print("Events generated:", len(events))
    print("Output file:", TEST_LOG_FILE)
    print()
    print("Synthetic security events generated successfully.")
    print("No real attack was performed.")

    return True


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("python simulator.py <scenario>")
        print()
        print("Scenarios:")
        print("1 = Brute Force")
        print("2 = Multi-Account Attack")
        print("3 = Credential Attack")
        print("4 = Failed Login -> Successful Login")
        print("5 = Combined Attack")
        return

    choice = sys.argv[1]

    run_simulation(choice)


if __name__ == "__main__":
    main()