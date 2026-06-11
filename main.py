from datetime import datetime
from detections.failed_logins import detect_failed_logins
from detections.user_creation import detect_user_creation
from detections.admin_login import detect_admin_login

alerts = []

alerts.extend(detect_failed_logins("logs/auth.log"))
alerts.extend(detect_user_creation("logs/windows-security.log"))
alerts.extend(detect_admin_login("logs/windows-security.log"))

print("\nGenerated:", datetime.now())

print("\n" + "=" * 50)
print(" MINI SIEM ALERT DASHBOARD ")
print("=" * 50)

for alert in alerts:

    print("\n" + "-" * 50)

    print(f"Severity : {alert['severity']}")
    print(f"Rule     : {alert['rule']}")

    if "ip" in alert:
        print(f"Source IP: {alert['ip']}")

    if "count" in alert:
        print(f"Attempts : {alert['count']}")

    if "event" in alert:
        print(f"Event ID : {alert['event']}")

    if "mitre" in alert:
        print(f"MITRE    : {alert['mitre']}")

print("\n" + "=" * 50)

with open("reports/report.txt", "w") as report:

    report.write("MINI SIEM INCIDENT REPORT\n")
    report.write("=" * 50 + "\n\n")

    for alert in alerts:

        report.write(f"Severity: {alert['severity']}\n")
        report.write(f"Rule: {alert['rule']}\n")

        if "ip" in alert:
            report.write(f"Source IP: {alert['ip']}\n")

        if "count" in alert:
            report.write(f"Attempts: {alert['count']}\n")

        if "event" in alert:
            report.write(f"Event ID: {alert['event']}\n")

        if "mitre" in alert:
            report.write(f"MITRE: {alert['mitre']}\n")

        report.write("\n")

high = 0
medium = 0
low = 0

for alert in alerts:

    if alert["severity"] == "HIGH":
        high += 1

    elif alert["severity"] == "MEDIUM":
        medium += 1

    elif alert["severity"] == "LOW":
        low += 1

print("\nSummary")
print("=" * 50)
print(f"HIGH Alerts   : {high}")
print(f"MEDIUM Alerts : {medium}")
print(f"LOW Alerts    : {low}")

from datetime import datetime

print("\nGenerated:", datetime.now())

