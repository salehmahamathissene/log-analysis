#!/usr/bin/env python3
import re
import json
from collections import Counter
from datetime import datetime

def classify_command(cmd: str) -> str:
    c = (cmd or "").lower()

    if "ufw" in c:
        return "firewall_change"
    if "resolvectl" in c or "systemd-resolved" in c or "/etc/resolv.conf" in c:
        return "dns_change"
    if "apt " in c:
        return "package_mgmt"
    if "systemctl disable" in c or "systemctl stop" in c:
        return "service_disabled"
    if "sed -i" in c and ("/etc/apt" in c or "sources" in c):
        return "repo_source_change"
    if "reboot" in c:
        return "reboot"

    return "other_admin"


# ✅ Use your sanitized evidence file (because you removed auth.log from git)
AUTH_LOG = "evidence/auth_sudo_only.log"

REPORT_JSON = "reports/alerts.json"
REPORT_TXT = "reports/alerts.txt"
REPORT_TIMELINE = "reports/timeline.txt"
REPORT_JSONL = "reports/events.jsonl"

# --- Detection rules (simple but SOC-real) ---
FAILED_THRESHOLD = 3              # brute-force threshold
SUDO_BURST_THRESHOLD = 8          # many sudo commands (coarse threshold)

SENSITIVE_KEYWORDS = [
    "/etc/resolv.conf",
    "systemd-resolved",
    "resolvectl",
    "/etc/apt/sources.list",
    "ubuntu.sources",
    "ufw ",
    "disable --now",
    "apt purge",
    "cups",
    "avahi",
]

failed_by_ip = Counter()
sudo_by_user = Counter()
sensitive_hits = []
raw_sudo_lines = []
sudo_events = []   # structured sudo events

# ✅ Timestamp regex supports:
# 2026-02-02T11:39:08+00:00
# 2026-02-02T13:47:31.335626+02:00
# 2026-02-02T11:35:58.425526Z
ts_re = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2})?)"
)

ip_re = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")

def parse_ts(line: str):
    m = ts_re.search(line)
    if not m:
        return None
    try:
        # Python fromisoformat doesn't accept 'Z' in some versions -> convert to +00:00
        ts = m.group(1).replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except Exception:
        return None


with open(AUTH_LOG, "r", errors="ignore") as f:
    for line in f:
        line = line.rstrip("\n")

        # Failed SSH (may be absent in sudo-only file, but keep logic)
        if "Failed password" in line:
            m = ip_re.search(line)
            if m:
                failed_by_ip[m.group(1)] += 1

        # Sudo usage (THIS IS YOUR MAIN SIGNAL)
        if " sudo:" in line:
            # user extraction
            m_user = re.search(r"sudo:\s+(\S+)\s+:\s+TTY=", line)
            user = m_user.group(1) if m_user else "unknown"

            sudo_by_user[user] += 1
            raw_sudo_lines.append(line)

            # parse more fields
            ts = parse_ts(line)
            cmd_match = re.search(r"COMMAND=(.*)$", line)
            pwd_match = re.search(r"PWD=([^;]+)", line)

            cmd = cmd_match.group(1).strip() if cmd_match else ""
            pwd = pwd_match.group(1).strip() if pwd_match else ""

            sudo_events.append({
                "ts": ts.isoformat() if ts else None,
                "user": user,
                "pwd": pwd,
                "command": cmd,
                "classification": classify_command(cmd),
                "raw": line,
            })

        # Sensitive changes (hits from sudo lines too)
        for kw in SENSITIVE_KEYWORDS:
            if kw in line:
                sensitive_hits.append(line)
                break


alerts = []

# Alert 1: brute force
for ip, count in failed_by_ip.items():
    if count >= FAILED_THRESHOLD:
        alerts.append({
            "type": "BRUTE_FORCE_SUSPECTED",
            "severity": "high",
            "indicator": ip,
            "count": count,
            "explain": f"{count} failed SSH logins from {ip}",
        })

# Alert 2: heavy sudo usage
for user, count in sudo_by_user.items():
    if count >= SUDO_BURST_THRESHOLD:
        alerts.append({
            "type": "PRIVILEGE_ACTIVITY_HIGH",
            "severity": "medium",
            "indicator": user,
            "count": count,
            "explain": f"{count} sudo commands executed by {user} (review for risky admin actions)",
        })

# Alert 3: sensitive changes present
if sensitive_hits:
    alerts.append({
        "type": "SENSITIVE_SYSTEM_CHANGES",
        "severity": "medium",
        "indicator": "system-config",
        "count": len(sensitive_hits),
        "explain": "Sensitive configuration / hardening commands detected (DNS, apt sources, firewall, service disable/purge). Review the change log.",
    })


report = {
    "generated_at": datetime.now().isoformat(timespec="seconds"),
    "source": AUTH_LOG,
    "summary": {
        "failed_login_ips": len(failed_by_ip),
        "total_failed_logins": sum(failed_by_ip.values()),
        "sudo_users": len(sudo_by_user),
        "total_sudo_events": sum(sudo_by_user.values()),
        "sensitive_hits": len(sensitive_hits),
        "alerts": len(alerts),
    },
    "top": {
        "failed_by_ip": failed_by_ip.most_common(10),
        "sudo_by_user": sudo_by_user.most_common(10),
    },
    "alerts": alerts,
    "evidence": {
        "sample_sudo_lines": raw_sudo_lines[:12],
        "sample_sensitive_hits": sensitive_hits[:20],
    }
}

# -------------------------
# Write main reports
# -------------------------
with open(REPORT_JSON, "w") as f:
    json.dump(report, f, indent=2)

with open(REPORT_TXT, "w") as f:
    f.write("=== SOC ALERT REPORT ===\n")
    f.write(json.dumps(report["summary"], indent=2))
    f.write("\n\n=== ALERTS ===\n")
    if not alerts:
        f.write("No alerts triggered.\n")
    else:
        for a in alerts:
            f.write(f"- [{a['severity']}] {a['type']}: {a['explain']}\n")

    f.write("\n\n=== SAMPLE EVIDENCE (sudo) ===\n")
    for line in report["evidence"]["sample_sudo_lines"]:
        f.write(line + "\n")

    f.write("\n\n=== SAMPLE EVIDENCE (sensitive changes) ===\n")
    for line in report["evidence"]["sample_sensitive_hits"]:
        f.write(line + "\n")


# -------------------------
# ✅ Write timeline + JSONL
# -------------------------
sudo_events_sorted = sorted(
    [e for e in sudo_events if e["ts"]],
    key=lambda x: x["ts"]
)

with open(REPORT_TIMELINE, "w") as f:
    f.write("=== CHANGE TIMELINE (sudo events) ===\n")
    for e in sudo_events_sorted:
        f.write(f'{e["ts"]} | user={e["user"]} | {e["classification"]} | {e["command"]}\n')

with open(REPORT_JSONL, "w") as f:
    for e in sudo_events_sorted:
        out = {
            "@timestamp": e["ts"],
            "event": {"category": "process", "type": "change"},
            "user": {"name": e["user"]},
            "host": {"name": "saleh-VMware-Virtual-Platform"},
            "process": {
                "command_line": e["command"],
                "working_directory": e["pwd"],
            },
            "labels": {
                "detector": "soc-change-detection-v1",
                "classification": e["classification"],
            },
        }
        f.write(json.dumps(out) + "\n")


print("✅ Report written:")
print(" -", REPORT_TXT)
print(" -", REPORT_JSON)
print("✅ Extra reports written:")
print(" -", REPORT_TIMELINE)
print(" -", REPORT_JSONL)
print("\nSummary:", report["summary"])
