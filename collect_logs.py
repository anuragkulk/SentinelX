import subprocess
import csv
import json

OUTPUT_FILE = "logs.csv"

# Windows Security Event IDs:
# 4624 = Successful login
# 4625 = Failed login

command = [
    "powershell",
    "-Command",
    """
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 100 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()

        [PSCustomObject]@{
            Time = $_.TimeCreated
            EventID = $_.Id
            Username = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
            IP = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
        }
    } | ConvertTo-Json -Depth 3
    """
]

try:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True
    )

    if not result.stdout.strip():
        print("No Windows Security events found.")
        exit()

    data = json.loads(result.stdout)

    if isinstance(data, dict):
        data = [data]

    logs = []

    for event in data:

        event_id = event.get("EventID")

        if event_id == 4624:
            status = "SUCCESS"
        elif event_id == 4625:
            status = "FAILED"
        else:
            continue

        username = event.get("Username") or "UNKNOWN"
        ip = event.get("IP") or "LOCAL"

        logs.append({
            "time": str(event.get("Time", "")),
            "username": username,
            "ip": ip,
            "status": status
        })

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:

        fieldnames = [
            "time",
            "username",
            "ip",
            "status"
        ]

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(logs)

    print(f"Collected {len(logs)} Windows security events.")
    print(f"Saved to {OUTPUT_FILE}")

except subprocess.CalledProcessError:
    print("Could not access Windows Security logs.")
    print("Try running the terminal as Administrator.")

except json.JSONDecodeError:
    print("Could not read the Windows Event Log data.")

except Exception as e:
    print("Error:", e)