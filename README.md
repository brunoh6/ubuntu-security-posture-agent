# Ubuntu Security Posture & Detection Agent

A lightweight, read-only security posture and detection agent for Ubuntu systems.

This project inspects **system configuration and logs**, produces **structured output**, and is designed to be executed periodically via **systemd**.  
It focuses on **clarity, correctness, and defendable engineering decisions**, not on replacing enterprise IDS/SIEM solutions.

---

## Purpose

The goal of this agent is to provide **basic but meaningful security signals** about an Ubuntu system:

- What is exposed?
- What is running?
- What privileges exist?
- What recent authentication or system events deserve attention?

This project is intentionally **not** a vulnerability scanner, IDS, or remediation tool.

---

## Key Characteristics

- **Read-only** (no system modifications)
- **Stateless** (no daemon, no background process)
- **Modular** and extensible
- **Minimal dependencies** (Python stdlib-first)
- **Machine-readable output (JSON)**
- **systemd-native execution**

---

## Architecture Overview

The agent is composed of four main layers:

CLI (main.py)  
↓  
Runner (orchestration & aggregation)  
↓  
Inspectors / Log Checks (data collection)  
↓  
Output & Exit Codes  

### Design Principles

- Each module has **one responsibility**
- Failures in one check **do not break execution**
- All findings follow a **consistent schema**
- Severity is **explicit**, not scored or inferred

---

## What the Agent Inspects

### System Posture (Configuration State)

- **Users**
  - Multiple UID 0 users
  - Interactive shells
- **Sudo Privileges**
  - Users in `sudo` group
  - `NOPASSWD` rules
  - Broad `ALL=(ALL)` rules
- **systemd Services**
  - Enabled and running services
  - Sensitive services (e.g. SSH, Docker)
- **Listening Network Ports**
  - TCP/UDP sockets
  - Sensitive ports (SSH, DBs, etc.)
- **Running Processes**
  - Processes running as `root`
  - Executables from suspicious paths
- **Filesystem Permissions**
  - World-writable files
  - SUID binaries in critical paths

---

### Log-Based Detection

- **Authentication Logs (`/var/log/auth.log`)**
  - Multiple failed login attempts
  - Sudo usage
- **journald**
  - High-priority log messages
  - Frequent service restarts

---

### Heuristic Correlation

Simple, explicit correlations are applied after data collection, for example:

- Failed login attempts **combined with** sudo usage  
  → Possible compromise signal (severity escalation)

No opaque scoring or machine learning is used.

---

## Output Format

### JSON (machine-readable)

{
  "metadata": {
    "hostname": "host01",
    "timestamp": "2026-02-08T14:32:10Z",
    "agent_version": "0.1.0"
  },
  "checks": [
    {
      "id": "sudo.users",
      "category": "privilege",
      "severity": "warning",
      "message": "Users with sudo privileges detected",
      "data": {
        "users": ["admin"]
      }
    }
  ],
  "summary": {
    "info": 3,
    "warnings": 5,
    "critical": 0
  }
}

### Console Output (human-readable)

Ubuntu Security Posture Agent  
Summary:  
Warnings: 5  
Critical: 0  

---

## Exit Codes

The agent uses exit codes suitable for automation and systemd:

0  No findings  
1  Warnings present  
2  Critical findings  
3  Execution error  

---

## Running the Agent

Development (recommended):

python3 -m agent.main  
python3 -m agent.main --json  

Version:

python3 -m agent.main --version  

---

## systemd Integration

The agent is designed to run as a **oneshot systemd service** with a timer.

- No daemon
- No polling loop
- No background process

Files Provided:

- systemd/ubuntu-security-agent.service
- systemd/ubuntu-security-agent.timer

Example Installation:

sudo mkdir -p /opt/ubuntu-security-posture-agent  
sudo cp -r agent /opt/ubuntu-security-posture-agent/  

sudo cp systemd/*.service systemd/*.timer /etc/systemd/system/  
sudo systemctl daemon-reload  

sudo systemctl enable ubuntu-security-agent.timer  
sudo systemctl start ubuntu-security-agent.timer  

Check execution:

journalctl -u ubuntu-security-agent.service  

---

## What This Agent Does NOT Do!

This is intentional.

- No vulnerability exploitation
- No blocking or remediation
- No continuous daemon
- No SIEM replacement
- No machine-learning heuristics

This tool focuses on **signal quality and engineering clarity**, not feature count.

---

## Testing -> Tested on Ubuntu!

This agent was tested on Ubuntu 22.04.5 LTS in a virtualized environment (VMWare)

The following real system events were generated to validate detection logic:

- Multiple failed SSH login attempts
- Legitimate sudo usage by a local user
- systemd-managed SSH service enabled and running

After these events, the agent correctly escalated severity using heuristic
correlation (failed authentication attempts combined with sudo usage),
resulting in a `Critical` finding.

Screenshots included in `docs/screenshots/` show:
- Baseline execution
- Post-event execution
- Corresponding authentication log entries

---

## Author & Motivation

Bruno Paolo Huaman Vela
Cybersecurity Specialist

This project was built to demonstrate **real-world Ubuntu engineering practices**, security-minded design, and tooling discipline suitable for:

- Ubuntu / Linux Engineering
- SOC Analyst
- Security Analyst
- DevSecOps
