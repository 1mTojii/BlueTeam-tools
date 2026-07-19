# BruteSentry

A lightweight bruteforce login detector. Feed it an auth log and it flags
IPs hammering login attempts, scores severity, and can export results or
fire a webhook alert — with zero external dependencies.

```
 ____                 _        ____             _
| __ ) _ __ _   _ ___| |_ ___ / ___|  ___ _ __ | |_ _ __ _   _
|  _ \| '__| | | / _ \ __/ _ \\___ \ / _ \ '_ \| __| '__| | | |
| |_) | |  | |_| |  __/ ||  __/___) |  __/ | | | |_| |  | |_| |
|____/|_|   \__,_|\___|\__\___|____/ \___|_| |_|\__|_|   \__, |
                                                          |___/
```

## How it works

BruteSentry tracks failed login attempts per source IP using a sliding time
window. Once an IP crosses a configurable failure threshold inside that
window, it gets flagged with a severity level ("LOW", "MEDIUM", "HIGH" ,
"CRITICAL") based on how far over the threshold it went and how fast the
attempts came in. A successful login clears an IP's slate.

That's the entire core algorithm, a per-IP sliding window counter. The rest
of the project is presentation: parsing, live tailing, colored CLI output,
exports, and webhook alerts.

## Features

- **Sliding-window detection** — configurable failure threshold and time window
- **Two log formats supported out of the box**: JSON-lines, and standard sshd
  auth.log syntax (`Failed password for X from Y`)
- **Live tail mode** (`--follow`) — watch a log file in real time like `tail -f`
- **Severity scoring** — LOW/MEDIUM/HIGH/CRITICAL based on overshoot and attempt rate
- **JSON/CSV export** of flagged IPs
- **Webhook alerts** — POSTs to any Slack/Discord-compatible incoming webhook
- **No dependencies** — pure Python standard library

## Quick start
Note: maybe you will have to switch the "py" to python for it to work in the cmd

```bash
# Generate a sample log with normal traffic + 2 injected brute-force attacks
py generate_sample_log.py

# Run the detector against it
py -m brutesentry.cli --log sample_logs/auth.log

# Tune sensitivity
py -m brutesentry.cli --log sample_logs/auth.log --threshold 4 --window 30

# Export results
py -m brutesentry.cli --log sample_logs/auth.log --json alerts.json --csv alerts.csv

# Watch the tool live 
py -m brutesentry.cli --log sample_logs\auth.log --follow
# In second cmd window type 3 or 4 times
echo {"ts": 1900000000.0, "ip": "6.6.6.6", "user": "root", "success": false} >> sample_logs\auth.log
#and the return should be a critical.. cool right?
<img width="932" height="332" alt="image" src="https://github.com/user-attachments/assets/f93035b1-3410-4d51-aeab-1528b3ce76ec" />

# Send alerts to a Discord/Slack webhook as they happen
py -m brutesentry.cli --log sample_logs/auth.log --webhook https://discord.com/api/webhooks/...
```

## Sample output

```
[HIGH] 45.33.12.201 flagged -- 5 failed logins in 18:47:50→18:47:53 (2.09 attempts/sec, last user tried: 'administrator')
[LOW]  185.220.101.9 flagged -- 5 failed logins in 18:49:36→18:49:50 (0.37 attempts/sec, last user tried: 'admin')

------------------------------------------------------------
Summary
  events processed : 76
  ips flagged      : 2
  HIGH     : 1
  LOW      : 1
------------------------------------------------------------
```

## Running tests

```bash
python tests/test_detector.py
```

## Why this exists

Built while working through web fundamentals and access-control concepts on
HTB Academy. Its a simple pass time project, it was built using my own knowledge from my python course from school and AI. It was a simple line of code but instead of cramping everyhting into one file i made it look more structured and organized using Claude. 

## Ideas for extending it

- Add IP reputation lookups (AbuseIPDB, etc.) to enrich alerts
- Persist state to disk so detection survives restarts
- Add a `--geo` flag to resolve attacker IPs to country/city
- Wrap it in a small Flask dashboard instead of CLI-only output
- Auto-generate iptables/fail2ban rules for CRITICAL-severity IPs

## License

Check the other file i linked. 
