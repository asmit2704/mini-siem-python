def detect_admin_login(filepath):

    alerts = []

    with open(filepath, "r") as logfile:

        for line in logfile:

            if "4672" in line:

                alerts.append({
                    "severity": "MEDIUM",
                    "rule": "Administrative Login",
                    "event": "4672"
                })

    return alerts