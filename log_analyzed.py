import csv
import json
from collections import Counter
from pathlib import Path
from datetime import datetime

csv_path = Path(__file__).with_name("security_events.csv")
alerts_path = Path(__file__).with_name("alerts.txt")
state_path = Path(__file__).with_name("alert_state.json")
skipped_path = Path(__file__).with_name("skipped_events.txt")
if not csv_path.exists():
    print("ERROR: security_events.csv was not found.")
    print("Place it in the same folder as this Python script.")
    raise SystemExit(1)

failed_logins = Counter()
processed_events = 0
skipped_events = 0
skip_reasons = Counter()
successful_logins = 0
with csv_path.open(newline="", encoding="utf-8-sig") as file:
    reader = csv.DictReader(file)
    required_columns = {"timestamp", "username", "source_ip", "status"}
    missing_columns = required_columns - set(reader.fieldnames or [])

    if missing_columns:
        print("ERROR: Missing CSV columns:", ", ".join(sorted(missing_columns)))
        raise SystemExit(1)

    for event in reader:
        if any(not (event.get(column) or "").strip() for column in required_columns):
            print(f"WARNING: Skipping incomplete event: {event}")
            skipped_events += 1
            skip_reasons["missing required field"] += 1
            with skipped_path.open("a", encoding="utf-8") as skipped_file:
                skipped_file.write(json.dumps({"logged_at": datetime.now().isoformat(timespec="seconds"), "reason": "missing required field", "event": event}) + "\n")
            continue
        if event["status"].strip().lower() not in {"success", "failed"}:
            print(f"WARNING: Skipping event with invalid status: {event}")
            skipped_events += 1
            skip_reasons["invalid status"] += 1
            with skipped_path.open("a", encoding="utf-8") as skipped_file:
                skipped_file.write(json.dumps({"logged_at": datetime.now().isoformat(timespec="seconds"), "reason": "invalid status", "event": event}) + "\n")
            continue
        processed_events += 1
        if event["status"].strip().lower() == "success":
            successful_logins += 1
        if event["status"].strip().lower() == "failed":
            key = (event["username"], event["source_ip"])
            failed_logins[key] += 1

if state_path.exists():
    with state_path.open(encoding="utf-8") as state_file:
        reported_counts = json.load(state_file)
else:
    reported_counts = {}

new_alerts = 0

with alerts_path.open("a", encoding="utf-8") as alerts_file:
    for (username, source_ip), count in failed_logins.items():
        print(f"{username} from {source_ip}: {count} failed login(s)")
        state_key = json.dumps([username, source_ip])
        previous_count = reported_counts.get(state_key, 0)

        if count >= 3 and count > previous_count:
            alert_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alert = (
                f"[{alert_time}] ALERT: {username} from {source_ip} "
                f"had {count} failed logins"
            )
            print(alert)
            alerts_file.write(alert + "\n")
            reported_counts[state_key] = count
            new_alerts += 1

with state_path.open("w", encoding="utf-8") as state_file:
    json.dump(reported_counts, state_file, indent=2)

print(f"New alerts saved: {new_alerts}")
print(f"Complete events processed: {processed_events}")
print(f"Incomplete events skipped: {skipped_events}")


report_path = Path(__file__).with_name("processing_summary.txt")

with report_path.open("w", encoding="utf-8") as report_file:
    report_file.write("Security Event Processing Summary\n")
    report_file.write(f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}\n")
    report_file.write(f"Total events read: {processed_events + skipped_events}\n")
    report_file.write(f"Complete events processed: {processed_events}\n")
    report_file.write(f"Invalid events skipped: {skipped_events}\n")    
    total_events = processed_events + skipped_events
    invalid_percentage = (skipped_events / total_events * 100) if total_events else 0
    report_file.write(f"Invalid-event percentage: {invalid_percentage:.1f}%\n")
    for reason, count in skip_reasons.items():
        report_file.write(f"  {reason}: {count}\n")
    report_file.write(f"New alerts saved: {new_alerts}\n")
    report_file.write(f"Total failed logins: {sum(failed_logins.values())}\n")
    report_file.write(f"Total successful logins: {successful_logins}\n")
    failure_percentage = (sum(failed_logins.values()) / processed_events * 100) if processed_events else 0
    report_file.write(f"Failed-login percentage: {failure_percentage:.1f}%\n")
    report_file.write(f"Username/IP pairs with failures: {len(failed_logins)}\n")
    report_file.write("\nFailed logins by username and IP:\n")
    for (username, source_ip), count in failed_logins.most_common():
        report_file.write(f"{username} from {source_ip}: {count} failed logins\n")
print(f"Summary saved to: {report_path}")
