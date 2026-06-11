def detect_user_creation(filepath):

    alerts = []

    with open(filepath, "r") as logfile:

        for line in logfile:

            if "4720" in line:

                alerts.append({
                    "severity": "MEDIUM",
                    "rule": "User Creation",
                    "event": "4720",
                    "mitre": "T1136"
                })

    return alerts