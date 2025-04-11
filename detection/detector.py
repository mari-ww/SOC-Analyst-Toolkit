import json
import re
from pathlib import Path
from ipaddress import ip_address

LOGS_FILE = Path("normalized_logs/normalized_logs.json")
RULES_FILE = Path("detection/rules.json")
ALERTS_FILE = Path("alerts/alerts.json")

PRIVATE_IP_RANGES = [
    re.compile(r"^192\.168\..*"),
    re.compile(r"^10\..*"),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\..*")
]

def is_external_ip(ip):
    return not any(pattern.match(ip) for pattern in PRIVATE_IP_RANGES)

def match_rule(log, rule):
    for key, expected in rule["match"].items():
        parts = key.split(".")
        value = log
        for part in parts:
            value = value.get(part, {})
        if expected == "EXTERNAL":
            if not value or not is_external_ip(value):
                return False
        elif isinstance(value, str):
            if expected.lower() not in value.lower():
                return False
        elif value != expected:
            return False
    return True

def run_detection():
    with open(LOGS_FILE) as f:
        logs = json.load(f)
    with open(RULES_FILE) as f:
        rules = json.load(f)

    alerts = []

    for log in logs:
        for rule in rules:
            if match_rule(log, rule):
                alerts.append({
                    "timestamp": log.get("timestamp", ""),
                    "event_type": log.get("event_type", ""),
                    "rule_id": rule["id"],
                    "description": rule["name"],
                    "severity": rule["severity"],
                    "log": log
                })

    Path("alerts").mkdir(exist_ok=True)
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=2)

    print(f"[✔] {len(alerts)} alertas salvos em {ALERTS_FILE}")

if __name__ == "__main__":
    run_detection()
