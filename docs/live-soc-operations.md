# Project AEGIS — Live SOC Operations & Screenshot Guide

## Overview

Project AEGIS is equipped with an autonomous live security operations center (SOC) simulation daemon and War Room dashboard server: `scripts/run_live_soc.py`.

The server runs continuously in the background until **19:00:00 (7:00 PM)**, simulating realistic multi-account AWS telemetry traffic, periodic Purple-Team attack lab scenarios, real-time deterministic detection, OpenCypher/Neptune attack-path graphing, explainable risk scoring, automated Step Functions self-healing containment, and WORM-compliant digital forensics evidence capture.

At **19:00:00 (7:00 PM)**, the simulation automatically finalizes its metrics and transitions to `TARGET_TIME_REACHED_READY_FOR_SCREENSHOTS`, keeping the web dashboard and REST API live indefinitely so you can explore, navigate, and capture high-resolution screenshots at your convenience.

---

## Accessing the Live War Room Dashboard

Open your web browser and navigate to:
```
http://localhost:8000
```
*(Or `http://127.0.0.1:8000`)*

### Live Capabilities on the Dashboard
1. **Live Header & Countdown**: Displays multi-account organization ID (`o-aegis-enterprise`), live local time, countdown timer to 19:00:00 (7:00 PM), and active defense status.
2. **Executive KPI Cards**: Real-time calibrated health posture score (`94.2/100`), Mean Time to Detect (MTTD: `1.2s`), Mean Time to Contain (MTTC: `3.4s`), total telemetry events ingested, 100% containment rate, and DynamoDB idempotent lock SLA.
3. **Attack Path & Blast Radius Visualizer**: High-resolution interactive visual diagram mapping the attacker's trajectory across account boundaries (`contractor-alice` in Account `333333333333` -> `DevEngineer` role -> cross-account STS trust hop -> Account `111111111111` -> `prod-customer-pii-vault`), with glowing green automated containment boundaries.
4. **MITRE ATT&CK Matrix**: Coverage tiles across Initial Access (T1078.004), Persistence (T1098.001), Privilege Escalation (T1078), Defense Evasion (T1562.001), Lateral Movement (T1550.001), and Impact/Exfiltration (T1530).
5. **Incident Dossier Table**: Real-time listing of active and contained incidents, severity badges (`CRITICAL`, `HIGH`), risk scores, lifecycle states, and Step Functions response actions.
6. **Digital Forensics Vault**: Display of immutable S3 Object Lock compliance retention (7 years), cryptographic SHA-256 evidence digests, and 6-stage chain-of-custody verification.
7. **Live SOC Terminal Stream**: Scrolling console with color-coded log entries: `[INGEST]`, `[ATTACK]`, `[DETECTION]`, `[REMEDIATION]`, and `[FORENSICS]`.
8. **Manual Trigger Action**: Red `"Trigger Attack Lab"` button to execute instant on-demand attacks if desired.

---

## Recommended Screenshots for Senior Security Portfolio

When capturing screenshots at 7:00 PM (or anytime while running):

1. **Executive SOC Overview (Full Page)**:
   - Capture the top navigation bar with the `FABRIC RUNNING` / `FINALIZED AT 19:00:00` indicator, the countdown, and the 6 executive KPI cards.
2. **Multi-Account Attack-Path & Blast Radius Canvas**:
   - Zoom into the middle section showing the visual graph from `contractor-alice` across accounts to `prod-pii-vault` and the glowing Step Functions containment badge.
3. **MITRE ATT&CK Matrix & Incident Feed**:
   - Capture the side-by-side view of the ATT&CK coverage grid and the table of automated incident remediations.
4. **Digital Forensics & Immutable Vault**:
   - Capture the S3 Object Lock vault cards showing SHA-256 evidence digests and legal hold compliance status.
5. **Terminal / Shell Logs**:
   - Capture a screenshot of the PowerShell terminal showing the structured AEGIS banner, real-time detection logs, and automated remediation passes.

---

## REST API Endpoints

The server also exposes clean JSON REST APIs:
- `GET http://localhost:8000/api/status` — Current countdown, running status, and ingested event counts.
- `GET http://localhost:8000/api/posture` — Aggregate organization posture summary and SLA metrics.
- `GET http://localhost:8000/api/incidents` — List of all detected and remediated incidents.
- `GET http://localhost:8000/api/incidents/<id>` — Detailed incident dossier with graph nodes and edges.
- `GET http://localhost:8000/api/events` — Recent rolling SOC event stream.
- `POST http://localhost:8000/api/trigger_scenario` — Trigger an immediate purple-team scenario.
- `POST http://localhost:8000/api/approve` — Human-in-the-loop containment approval.

---

## Process & Log Management

- **Live Log File**: `reports/live_soc_simulation.log`
- **Streaming JSONL**: `reports/live_soc_events.jsonl`
- **Start / Restart Command**:
  ```powershell
  .\.venv\Scripts\python.exe scripts\run_live_soc.py
  ```
- **Stop Server**: Press `Ctrl+C` in the running terminal or kill the background process.
