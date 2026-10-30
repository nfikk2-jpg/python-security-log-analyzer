# Python Security Log Analyzer

Analyzes simulated login events, detects repeated failed logins, validates records, and generates a summary report.

## Features

- Counts successful and failed logins.
- Groups failures by username and source IP.
- Generates alerts for three or more failures.
- Remembers reported counts to avoid duplicate alerts when counts are unchanged.
- Skips records with missing fields or unsupported statuses.
- Logs skipped events with timestamps and reasons.
- Reports totals, percentages, skip reasons, and failures ranked highest first.

## Requirements

Python 3. No external packages are required.

## Run

Keep `log_analyzed.py` and `security_events.csv` in the same folder.

On Windows, open a terminal in that folder and run:

```powershell
py .\log_analyzed.py
```

## Input

The CSV must contain these columns:

```csv
timestamp,username,source_ip,status
```

Supported statuses are `success` and `failed`. The sample data is simulated.

## Generated Files

- `alerts.txt`: Timestamped failed-login alerts; appended on each new qualifying count.
- `alert_state.json`: Previously reported failure counts.
- `skipped_events.txt`: Invalid records with logging timestamps and reasons; appended on every run.
- `processing_summary.txt`: Summary of the latest run; replaced each time.

## Detection Scope

Failures are counted across the entire CSV, separately for each username/IP pair. The analyzer does not apply a time window or reset failures after a successful login.

Keep `alert_state.json` between runs to preserve duplicate-alert tracking.
