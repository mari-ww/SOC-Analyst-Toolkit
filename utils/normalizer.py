import json
import os
from pathlib import Path
from datetime import datetime

LOG_DIR = Path("logs/")
OUTPUT_FILE = Path("normalized_logs/normalized_logs.json")

def normalize_log(log, source_type):
    """Padroniza os logs em um formato comum"""
    normalized = {
        "timestamp": log.get("timestamp", ""),
        "source_type": source_type,
        "event_type": "",
        "source_ip": "",
        "destination_ip": "",
        "user": "",
        "details": {}
    }

    if source_type == "windows":
        normalized["event_type"] = log.get("event_type", "")
        normalized["source_ip"] = log.get("source_ip", "")
        normalized["user"] = log.get("user", "")
        normalized["details"] = log

    elif source_type == "linux":
        normalized["event_type"] = log.get("process", "")
        if "from" in log.get("message", ""):
            try:
                ip = log["message"].split("from")[1].split()[0]
                normalized["source_ip"] = ip
            except IndexError:
                pass
        normalized["user"] = "root" if "root" in log.get("message", "") else ""
        normalized["details"] = log

    elif source_type == "firewall":
        normalized["event_type"] = "firewall_connection"
        normalized["source_ip"] = log.get("source_ip", "")
        normalized["destination_ip"] = log.get("destination_ip", "")
        normalized["details"] = log

    elif source_type == "ids":
        normalized["event_type"] = log.get("alert", {}).get("signature", "")
        normalized["source_ip"] = log.get("src_ip", "")
        normalized["destination_ip"] = log.get("dest_ip", "")
        normalized["details"] = log

    return normalized

def load_logs(file_path, source_type):
    """Lê e normaliza os logs de um arquivo"""
    with open(file_path, "r") as f:
        logs = json.load(f)
        return [normalize_log(log, source_type) for log in logs]

def main():
    all_logs = []

    for file in LOG_DIR.glob("*.json"):
        if "windows" in file.name:
            all_logs.extend(load_logs(file, "windows"))
        elif "linux" in file.name:
            all_logs.extend(load_logs(file, "linux"))
        elif "firewall" in file.name:
            all_logs.extend(load_logs(file, "firewall"))
        elif "ids" in file.name or "suricata" in file.name:
            all_logs.extend(load_logs(file, "ids"))

    OUTPUT_FILE.parent.mkdir(exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(all_logs, f, indent=2)

    print(f"[✔] Logs normalizados salvos em {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
