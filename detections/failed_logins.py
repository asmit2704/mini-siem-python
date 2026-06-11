import re
from collections import Counter

def detect_failed_logins(filepath):

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    counter = Counter()

    with open(filepath, "r") as logfile:

        for line in logfile:

            if "Failed password" in line:

                match = re.search(ip_pattern, line)

                if match:
                    counter[match.group()] += 1

    alerts = []

    for ip, count in counter.items():

        if count > 5:

            alerts.append({
                "severity": "HIGH",
                "rule": "SSH Brute Force",
                "ip": ip,
                "count": count,
                "mitre": "T1110"
            })

    return alerts