"""
Generates sample_logs/auth.log -- a mix of normal login traffic and a few
injected brute-force bursts, in the JSON-lines format brutesentry understands.

Run: python generate_sample_log.py
"""

import json
import random
from pathlib import Path

random.seed(7)

OUT_DIR = Path(__file__).parent / "sample_logs"
OUT_DIR.mkdir(exist_ok=True)

NORMAL_USERS = ["dave", "priya", "wei", "amara", "tojii", "sam"]
NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 25)]

ATTACKER_IPS = ["45.33.12.201", "185.220.101.9"]
ATTACK_USERNAMES = ["admin", "root", "administrator", "test", "user", "postgres", "sa"]

events = []
t = 1_752_000_000.0  # arbitrary base epoch

# --- normal background traffic: occasional single failed attempt, then success ---
for _ in range(40):
    ip = random.choice(NORMAL_IPS)
    user = random.choice(NORMAL_USERS)
    t += random.uniform(2, 20)
    if random.random() < 0.15:
        events.append({"ts": t, "ip": ip, "user": user, "success": False})
        t += random.uniform(1, 4)
    events.append({"ts": t, "ip": ip, "user": user, "success": True})

# --- injected brute-force burst #1: fast, single IP, many usernames ---
t += 15
burst_start = t
for i in range(12):
    t += random.uniform(0.3, 1.2)
    events.append({
        "ts": t,
        "ip": ATTACKER_IPS[0],
        "user": random.choice(ATTACK_USERNAMES),
        "success": False,
    })

# --- some normal traffic in between ---
for _ in range(10):
    ip = random.choice(NORMAL_IPS)
    user = random.choice(NORMAL_USERS)
    t += random.uniform(3, 10)
    events.append({"ts": t, "ip": ip, "user": user, "success": True})

# --- injected brute-force burst #2: slower, second IP, targeting one username ---
t += 25
for i in range(8):
    t += random.uniform(2, 5)
    events.append({
        "ts": t,
        "ip": ATTACKER_IPS[1],
        "user": "admin",
        "success": False,
    })

events.sort(key=lambda e: e["ts"])

out_path = OUT_DIR / "auth.log"
with open(out_path, "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

print(f"Wrote {len(events)} events to {out_path}")
print(f"Attacker IPs to look for: {ATTACKER_IPS}")
