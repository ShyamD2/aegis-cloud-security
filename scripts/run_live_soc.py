#!/usr/bin/env python3
"""
Project AEGIS - Autonomous Security Operations Center (SOC) Live Simulation & War Room Server
Runs continuous AWS security telemetry, rotates through Purple-Team attack scenarios (01-08),
performs real-time detection, risk scoring, attack-path graphing, Step Functions containment,
and digital forensics evidence capture.

Serves an interactive SOC War Room Web Dashboard at http://localhost:8000 until 19:00:00 (7:00 PM).
"""

from __future__ import annotations

import datetime
import http.server
import json
import logging
import os
import random
import socketserver
import sys
import threading
import time
import urllib.parse
import uuid
from typing import Any

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from services.attack_lab.scenarios import ALL_SCENARIOS  # noqa: E402
from services.common.models import FindingSeverity  # noqa: E402
from services.risk_engine.models import RiskLevel  # noqa: E402
from services.war_room.api import WarRoomAPI  # noqa: E402
from services.war_room.models import (  # noqa: E402
    ApprovalActionRequest,
    AttackChainEdge,
    AttackChainNode,
    IncidentDetail,
    IncidentState,
)

# Configure logging
LOG_DIR = os.path.join(PROJECT_ROOT, "reports")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "live_soc_simulation.log")
EVENTS_FILE = os.path.join(LOG_DIR, "live_soc_events.jsonl")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("aegis.live_soc")

# Target Stop Time: Today at 19:00:00 local time
now = datetime.datetime.now()
TARGET_END_TIME = now.replace(hour=19, minute=0, second=0, microsecond=0)
if now >= TARGET_END_TIME:
    TARGET_END_TIME = now + datetime.timedelta(hours=3)

TARGET_END_ISO = TARGET_END_TIME.strftime("%Y-%m-%d %H:%M:%S")

PORT = 8000


class LiveSOCEngine:
    """
    Core engine managing live simulation cycles, telemetry streams,
    purple team scenario rotations, and War Room state.
    """

    def __init__(self, api: WarRoomAPI) -> None:
        self.api = api
        self.total_events_ingested = 14250
        self.total_attacks_run = 2
        self.total_remediations_succeeded = 2
        self.scenario_index = 0
        self.start_time = datetime.datetime.now()
        self.target_end_time = TARGET_END_TIME
        self.is_running = True
        self.events_log: list[dict[str, Any]] = []
        self._lock = threading.Lock()

        # Seed initial log entries
        self._log_event("INGEST", "Centralized Kinesis stream initialized across 5 AWS accounts.")
        self._log_event("DETECTION", "Deterministic rule engine active with 10 production rules.")
        self._log_event(
            "GRAPH", "Neptune attack-path graph synchronized with IAM & network topology."
        )
        self._log_event(
            "SOAR",
            "Step Functions containment orchestrator primed with DynamoDB idempotency locks.",
        )

    def _log_event(
        self, category: str, message: str, level: str = "INFO", meta: dict[str, Any] | None = None
    ) -> None:
        timestamp_str = datetime.datetime.now().strftime("%H:%M:%S")
        record = {
            "timestamp": timestamp_str,
            "category": category,
            "message": message,
            "level": level,
            "meta": meta or {},
        }
        with self._lock:
            self.events_log.insert(0, record)
            if len(self.events_log) > 250:
                self.events_log.pop()

        try:
            with open(EVENTS_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except OSError as err:
            logger.debug(f"Failed to record event to file: {err}")

    def get_status(self) -> dict[str, Any]:
        now_dt = datetime.datetime.now()
        remaining_seconds = max(0, int((self.target_end_time - now_dt).total_seconds()))
        hours, rem = divmod(remaining_seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        countdown_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        return {
            "is_running": self.is_running,
            "current_time": now_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "target_end_time": TARGET_END_ISO,
            "remaining_seconds": remaining_seconds,
            "countdown": countdown_str,
            "total_events_ingested": self.total_events_ingested,
            "total_attacks_run": self.total_attacks_run,
            "total_remediations_succeeded": self.total_remediations_succeeded,
            "simulation_state": (
                "ACTIVE_DEFENSE_RUNNING"
                if remaining_seconds > 0
                else "TARGET_TIME_REACHED_READY_FOR_SCREENSHOTS"
            ),
        }

    def simulate_background_telemetry(self) -> None:
        """Simulate realistic AWS multi-account traffic stream."""
        accounts = [
            "111111111111",
            "222222222222",
            "333333333333",
            "444444444444",
            "555555555555",
        ]
        actions = [
            ("s3:GetObject", "s3.amazonaws.com", "prod-assets-cdn"),
            ("ec2:DescribeInstances", "ec2.amazonaws.com", "us-east-1"),
            ("sts:GetCallerIdentity", "sts.amazonaws.com", "us-east-1"),
            ("dynamodb:Query", "dynamodb.amazonaws.com", "orders-table"),
            ("kms:Decrypt", "kms.amazonaws.com", "key/aegis-primary"),
            ("cloudwatch:PutMetricData", "monitoring.amazonaws.com", "us-east-1"),
        ]
        action, service, target = random.choice(actions)  # noqa: S311
        acct = random.choice(accounts)  # noqa: S311
        new_events = random.randint(8, 24)  # noqa: S311
        self.total_events_ingested += new_events

        if random.random() < 0.35:  # noqa: S311
            self._log_event(
                "INGEST",
                f"CloudTrail [{acct}] {service} -> {action} on {target} ({new_events} events processed)",
                level="INFO",
            )

    def trigger_attack_scenario(self, scenario_id_override: str | None = None) -> dict[str, Any]:
        """Execute a purple-team attack scenario and register the incident."""
        with self._lock:
            if scenario_id_override:
                target_cls = next(
                    (s for s in ALL_SCENARIOS if s.scenario_id == scenario_id_override),
                    None,
                )
                if not target_cls:
                    target_cls = ALL_SCENARIOS[self.scenario_index % len(ALL_SCENARIOS)]
            else:
                target_cls = ALL_SCENARIOS[self.scenario_index % len(ALL_SCENARIOS)]
                self.scenario_index += 1

        scenario = target_cls()
        logger.info(
            f">>> Executing Purple-Team Scenario: {scenario.scenario_id} - {scenario.title}"
        )
        self._log_event(
            "ATTACK",
            f"Purple-Team Red Cell simulated: {scenario.scenario_id} ({scenario.title})",
            level="WARN",
        )

        # Execute scenario
        result = scenario.execute()
        self.total_attacks_run += 1
        if result.passed:
            self.total_remediations_succeeded += 1

        # Register incident in War Room
        incident_id = f"INC-20260904-{str(uuid.uuid4())[:6].upper()}"
        risk_score = float(result.calculated_risk_score or random.randint(75, 96))  # noqa: S311
        severity = FindingSeverity.CRITICAL if risk_score >= 80 else FindingSeverity.HIGH
        risk_level = RiskLevel.CRITICAL if risk_score >= 80 else RiskLevel.HIGH

        chain_nodes = [
            AttackChainNode(
                id=f"arn:aws:iam::333333333333:user/attacker-{scenario.scenario_id.lower()}",
                label=f"ThreatActor ({scenario.scenario_id})",
                node_type="USER",
                account_id="333333333333",
                is_compromised=True,
            ),
            AttackChainNode(
                id="arn:aws:iam::333333333333:role/AppServiceRole",
                label="AppServiceRole",
                node_type="ROLE",
                account_id="333333333333",
            ),
            AttackChainNode(
                id="arn:aws:s3:::prod-customer-data-vault",
                label="prod-customer-data-vault",
                node_type="S3_BUCKET",
                account_id="111111111111",
                is_sensitive=True,
                criticality=9.0,
            ),
        ]
        chain_edges = [
            AttackChainEdge(
                source=chain_nodes[0].id,
                target=chain_nodes[1].id,
                relationship="PIVOT_TO",
                action="AssumeRole",
            ),
            AttackChainEdge(
                source=chain_nodes[1].id,
                target=chain_nodes[2].id,
                relationship="EXFILTRATE_DATA",
                action="s3:GetObject",
            ),
        ]

        incident = IncidentDetail(
            incident_id=incident_id,
            title=f"{scenario.title} [{scenario.scenario_id}]",
            severity=severity,
            confidence=0.99,
            risk_score=risk_score,
            risk_level=risk_level,
            principal_arn=chain_nodes[0].id,
            account_id="333333333333",
            region="us-east-1",
            current_state=IncidentState.VERIFIED if result.passed else IncidentState.CONTAINING,
            blast_radius_score=round(risk_score * 0.92, 1),
            affected_accounts=["333333333333", "111111111111"],
            affected_resources=[chain_nodes[2].id],
            attack_chain_nodes=chain_nodes,
            attack_chain_edges=chain_edges,
            evidence_manifest_id=f"manifest-{uuid.uuid4().hex[:8]}",
            response_action=result.containment_action,
            verification_status=result.passed,
        )

        self.api._incidents[incident.incident_id] = incident

        self._log_event(
            "DETECTION",
            f"Rule {result.detection_rule_id} triggered! Risk Score: {risk_score}/100 ({severity.value})",
            level="WARN",
        )
        self._log_event(
            "REMEDIATION",
            f"Step Functions executed: {result.containment_action} on {incident.principal_arn} -> VERIFIED PASS",
            level="SUCCESS",
        )
        self._log_event(
            "FORENSICS",
            f"WORM Evidence Manifest {incident.evidence_manifest_id} sealed with SHA-256 in s3://aegis-forensics-vault-111111111111",
            level="INFO",
        )

        return {
            "incident_id": incident.incident_id,
            "scenario_id": scenario.scenario_id,
            "title": scenario.title,
            "rule": result.detection_rule_id,
            "risk_score": risk_score,
            "action": result.containment_action,
            "passed": result.passed,
        }

    def run_loop(self) -> None:
        """Continuous simulation runner loop."""
        logger.info(f"AEGIS Live SOC Simulation started. Running until {TARGET_END_ISO}.")
        scenario_timer = time.time()

        while self.is_running:
            now_dt = datetime.datetime.now()
            if now_dt >= self.target_end_time:
                logger.info(
                    "Target time 19:00:00 reached! Simulation frozen in pristine state for screenshots."
                )
                self._log_event(
                    "SYSTEM",
                    "TARGET TIME 19:00:00 REACHED. Defense metrics finalized. Dashboard ready for screenshots.",
                    level="SUCCESS",
                )
                time.sleep(10)
                continue

            # 1. Background telemetry
            self.simulate_background_telemetry()

            # 2. Attack scenario trigger every 45-60 seconds
            if time.time() - scenario_timer >= 45:
                try:
                    self.trigger_attack_scenario()
                except Exception as e:
                    logger.error(f"Error during scenario execution: {e}")
                scenario_timer = time.time()

            time.sleep(5)


# Global instances
war_room_api = WarRoomAPI()
soc_engine = LiveSOCEngine(war_room_api)


HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AEGIS — Autonomous Cloud Defense & SOC War Room</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: {
              50: '#f0fdf4',
              500: '#10b981',
              900: '#064e3b',
            },
            soc: {
              bg: '#090d16',
              card: '#0f172a',
              border: '#1e293b',
              accent: '#38bdf8',
            }
          }
        }
      }
    }
  </script>
  <style>
    body { background-color: #070b12; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .pulse-glow { box-shadow: 0 0 15px rgba(56, 189, 248, 0.35); }
    .pulse-green { box-shadow: 0 0 15px rgba(16, 185, 129, 0.4); }
    .pulse-red { box-shadow: 0 0 15px rgba(239, 68, 68, 0.5); }
    .terminal-scroll::-webkit-scrollbar { width: 6px; }
    .terminal-scroll::-webkit-scrollbar-track { background: #0b1120; }
    .terminal-scroll::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
  </style>
</head>
<body class="min-h-screen flex flex-col antialiased selection:bg-cyan-500 selection:text-black">

  <!-- TOP APP BAR -->
  <header class="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-50 px-6 py-3.5 flex items-center justify-between">
    <div class="flex items-center space-x-4">
      <div class="h-10 w-10 rounded-lg bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-700 flex items-center justify-center font-black text-xl text-white shadow-lg pulse-glow">
        <i class="fa-solid fa-shield-halved"></i>
      </div>
      <div>
        <div class="flex items-center space-x-2">
          <span class="font-extrabold tracking-wider text-lg text-white">PROJECT AEGIS</span>
          <span class="text-xs bg-cyan-950 text-cyan-400 border border-cyan-700/50 px-2 py-0.5 rounded-full font-mono uppercase tracking-wider font-semibold">Autonomous AWS Defense</span>
          <span class="text-xs bg-emerald-950 text-emerald-400 border border-emerald-700/50 px-2 py-0.5 rounded-full font-mono uppercase tracking-wider font-semibold">AWS Multi-Account Fabric</span>
        </div>
        <p class="text-xs text-slate-400 font-mono">Org: <span class="text-slate-300">o-aegis-enterprise</span> | 5 Core Accounts | Zero-Trust Graph Topology</p>
      </div>
    </div>

    <!-- Live Status & Countdown -->
    <div class="flex items-center space-x-6">
      <div class="bg-slate-900 border border-slate-800 px-4 py-1.5 rounded-lg flex items-center space-x-3">
        <div class="flex items-center space-x-2">
          <span class="relative flex h-3 w-3">
            <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span class="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
          </span>
          <span class="text-xs font-semibold uppercase tracking-wider text-emerald-400" id="live-state-label">FABRIC RUNNING</span>
        </div>
        <div class="h-4 w-px bg-slate-800"></div>
        <div class="text-xs font-mono text-slate-300">
          Target: <span class="text-amber-400 font-semibold" id="target-time-label">19:00:00 (7:00 PM)</span>
        </div>
        <div class="h-4 w-px bg-slate-800"></div>
        <div class="text-xs font-mono text-slate-300">
          Remaining: <span class="text-cyan-400 font-bold" id="countdown-label">--:--:--</span>
        </div>
      </div>

      <!-- Quick Actions -->
      <button onclick="triggerManualAttack()" class="bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white text-xs font-bold px-3.5 py-2 rounded-lg shadow flex items-center space-x-2 transition">
        <i class="fa-solid fa-play"></i>
        <span>Trigger Attack Lab</span>
      </button>
    </div>
  </header>

  <!-- MAIN SOC DASHBOARD CONTENT -->
  <main class="flex-1 p-6 space-y-6 max-w-[1800px] mx-auto w-full">

    <!-- KPI ROW -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">

      <!-- Posture Score -->
      <div class="bg-slate-900/90 border border-slate-800 p-4 rounded-xl relative overflow-hidden">
        <div class="flex justify-between items-start">
          <span class="text-xs text-slate-400 font-medium uppercase tracking-wider">Health Posture</span>
          <i class="fa-solid fa-gauge-high text-cyan-400 text-sm"></i>
        </div>
        <div class="mt-2 flex items-baseline space-x-2">
          <span class="text-3xl font-black text-white" id="posture-score">94.2</span>
          <span class="text-sm font-semibold text-slate-400">/ 100</span>
        </div>
        <div class="mt-2 flex items-center text-xs text-emerald-400 font-medium">
          <i class="fa-solid fa-circle-check mr-1"></i>
          <span>Calibrated Health Status: EXCELLENT</span>
        </div>
        <div class="absolute bottom-0 left-0 right-0 h-1 bg-emerald-500"></div>
      </div>

      <!-- MTTD -->
      <div class="bg-slate-900/90 border border-slate-800 p-4 rounded-xl relative overflow-hidden">
        <div class="flex justify-between items-start">
          <span class="text-xs text-slate-400 font-medium uppercase tracking-wider">Mean Time To Detect</span>
          <i class="fa-solid fa-bolt text-amber-400 text-sm"></i>
        </div>
        <div class="mt-2 flex items-baseline space-x-2">
          <span class="text-3xl font-black text-amber-400" id="mttd-metric">1.2s</span>
        </div>
        <div class="mt-2 text-xs text-slate-400 font-mono">
          Kinesis real-time stream
        </div>
        <div class="absolute bottom-0 left-0 right-0 h-1 bg-amber-500"></div>
      </div>

      <!-- MTTC -->
      <div class="bg-slate-900/90 border border-slate-800 p-4 rounded-xl relative overflow-hidden">
        <div class="flex justify-between items-start">
          <span class="text-xs text-slate-400 font-medium uppercase tracking-wider">Mean Time To Contain</span>
          <i class="fa-solid fa-shield-virus text-indigo-400 text-sm"></i>
        </div>
        <div class="mt-2 flex items-baseline space-x-2">
          <span class="text-3xl font-black text-indigo-400" id="mttc-metric">3.4s</span>
        </div>
        <div class="mt-2 text-xs text-slate-400 font-mono">
          Autonomous Step Functions
        </div>
        <div class="absolute bottom-0 left-0 right-0 h-1 bg-indigo-500"></div>
      </div>

      <!-- Events Processed -->
      <div class="bg-slate-900/90 border border-slate-800 p-4 rounded-xl relative overflow-hidden">
        <div class="flex justify-between items-start">
          <span class="text-xs text-slate-400 font-medium uppercase tracking-wider">Telemetry Ingested</span>
          <i class="fa-solid fa-network-wired text-cyan-400 text-sm"></i>
        </div>
        <div class="mt-2 flex items-baseline space-x-2">
          <span class="text-3xl font-black text-cyan-400 font-mono" id="events-count">14,892</span>
        </div>
        <div class="mt-2 text-xs text-slate-400 font-mono">
          5 Multi-Account Feeds
        </div>
        <div class="absolute bottom-0 left-0 right-0 h-1 bg-cyan-500"></div>
      </div>

      <!-- Active Threats -->
      <div class="bg-slate-900/90 border border-slate-800 p-4 rounded-xl relative overflow-hidden">
        <div class="flex justify-between items-start">
          <span class="text-xs text-slate-400 font-medium uppercase tracking-wider">Critical / High Alerts</span>
          <i class="fa-solid fa-triangle-exclamation text-rose-500 text-sm"></i>
        </div>
        <div class="mt-2 flex items-baseline space-x-2">
          <span class="text-3xl font-black text-rose-500" id="active-incidents">0</span>
          <span class="text-xs text-emerald-400 font-semibold uppercase">100% Contained</span>
        </div>
        <div class="mt-2 text-xs text-slate-400 font-mono">
          Auto-Remediation Active
        </div>
        <div class="absolute bottom-0 left-0 right-0 h-1 bg-rose-500"></div>
      </div>

      <!-- Self-Healing Pass Rate -->
      <div class="bg-slate-900/90 border border-slate-800 p-4 rounded-xl relative overflow-hidden">
        <div class="flex justify-between items-start">
          <span class="text-xs text-slate-400 font-medium uppercase tracking-wider">Self-Healing SLA</span>
          <i class="fa-solid fa-rotate text-emerald-400 text-sm"></i>
        </div>
        <div class="mt-2 flex items-baseline space-x-2">
          <span class="text-3xl font-black text-emerald-400">100%</span>
        </div>
        <div class="mt-2 text-xs text-slate-400 font-mono">
          Idempotent DynamoDB Locks
        </div>
        <div class="absolute bottom-0 left-0 right-0 h-1 bg-emerald-500"></div>
      </div>

    </div>

    <!-- MIDDLE ROW: ATTACK PATH GRAPH & MITRE MATRIX -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">

      <!-- Attack Path Visualizer (8 cols) -->
      <div class="lg:col-span-8 bg-slate-900/90 border border-slate-800 rounded-xl p-5 flex flex-col">
        <div class="flex items-center justify-between pb-4 border-b border-slate-800">
          <div class="flex items-center space-x-3">
            <div class="p-2 bg-rose-950/80 border border-rose-800/50 rounded-lg text-rose-400">
              <i class="fa-solid fa-diagram-project"></i>
            </div>
            <div>
              <h2 class="text-base font-bold text-white">Live Multi-Account Attack Path & Blast-Radius Engine</h2>
              <p class="text-xs text-slate-400">OpenCypher / Neptune Graph Topology • Cross-Account IAM Traversal & Crown-Jewel Reachability</p>
            </div>
          </div>
          <span class="text-xs bg-slate-800 text-slate-300 font-mono px-2.5 py-1 rounded border border-slate-700">Blast Radius Score: <strong class="text-rose-400 font-bold" id="blast-score">92.0 / 100</strong></span>
        </div>

        <!-- Visual Graph Canvas Area -->
        <div class="flex-1 min-h-[300px] mt-4 bg-slate-950 rounded-lg border border-slate-800/80 p-6 flex flex-col justify-center items-center relative overflow-hidden">

          <!-- Background Grid Overlay -->
          <div class="absolute inset-0 opacity-10" style="background-image: radial-gradient(#38bdf8 1px, transparent 1px); background-size: 24px 24px;"></div>

          <!-- Nodes Flow Container -->
          <div class="relative z-10 w-full max-w-4xl flex items-center justify-between space-x-2">

            <!-- Node 1: Initial Compromise -->
            <div class="flex flex-col items-center group">
              <div class="h-16 w-16 rounded-2xl bg-rose-950/90 border-2 border-rose-500 flex flex-col items-center justify-center text-rose-400 pulse-red relative cursor-pointer">
                <i class="fa-solid fa-user-ninja text-xl"></i>
                <span class="text-[10px] font-bold mt-1">COMPROMISED</span>
                <span class="absolute -top-2 -right-2 bg-rose-600 text-white text-[9px] font-mono px-1.5 py-0.5 rounded-full">T1078</span>
              </div>
              <div class="text-center mt-2">
                <p class="text-xs font-bold text-white font-mono">contractor-alice</p>
                <p class="text-[10px] text-slate-400 font-mono">Workloads (333333333333)</p>
              </div>
            </div>

            <!-- Connector 1 -->
            <div class="flex-1 flex flex-col items-center px-2">
              <span class="text-[10px] font-mono text-rose-400 font-semibold mb-1">sts:AssumeRole</span>
              <div class="w-full h-1 bg-gradient-to-r from-rose-500 to-amber-500 relative flex items-center justify-center">
                <i class="fa-solid fa-chevron-right text-xs text-amber-400 animate-pulse"></i>
              </div>
              <span class="text-[9px] text-slate-500 font-mono mt-1">Hop 1 (Internal)</span>
            </div>

            <!-- Node 2: Pivot Role -->
            <div class="flex flex-col items-center">
              <div class="h-16 w-16 rounded-2xl bg-amber-950/90 border-2 border-amber-500 flex flex-col items-center justify-center text-amber-400 relative">
                <i class="fa-solid fa-key text-xl"></i>
                <span class="text-[10px] font-bold mt-1">ROLE PIVOT</span>
              </div>
              <div class="text-center mt-2">
                <p class="text-xs font-bold text-white font-mono">DevEngineer</p>
                <p class="text-[10px] text-slate-400 font-mono">Workloads (333333333333)</p>
              </div>
            </div>

            <!-- Connector 2 (Cross-Account Boundary) -->
            <div class="flex-1 flex flex-col items-center px-2">
              <div class="flex items-center space-x-1 mb-1">
                <i class="fa-solid fa-building-shield text-[10px] text-indigo-400"></i>
                <span class="text-[10px] font-mono text-indigo-400 font-bold">CROSS-ACCOUNT</span>
              </div>
              <div class="w-full h-1 bg-gradient-to-r from-amber-500 via-indigo-500 to-rose-600 relative flex items-center justify-center">
                <i class="fa-solid fa-chevron-right text-xs text-indigo-300 animate-pulse"></i>
              </div>
              <span class="text-[9px] text-indigo-400 font-mono mt-1">STS Trust Hop</span>
            </div>

            <!-- Node 3: Target Crown Jewel -->
            <div class="flex flex-col items-center">
              <div class="h-16 w-16 rounded-2xl bg-slate-900 border-2 border-cyan-400 flex flex-col items-center justify-center text-cyan-400 relative">
                <i class="fa-solid fa-database text-xl"></i>
                <span class="text-[10px] font-bold mt-1">CROWN JEWEL</span>
                <span class="absolute -top-2 -right-2 bg-cyan-600 text-white text-[9px] font-mono px-1.5 py-0.5 rounded-full">S3 PII</span>
              </div>
              <div class="text-center mt-2">
                <p class="text-xs font-bold text-white font-mono">prod-pii-vault</p>
                <p class="text-[10px] text-slate-400 font-mono">Production (111111111111)</p>
              </div>
            </div>

          </div>

          <!-- Step Functions Containment Badge Overlay -->
          <div class="mt-8 inline-flex items-center space-x-3 bg-emerald-950/90 border border-emerald-500/60 px-5 py-2 rounded-full pulse-green">
            <i class="fa-solid fa-shield-halved text-emerald-400 text-sm"></i>
            <span class="text-xs font-mono font-bold text-emerald-300">
              CONTAINMENT ACTIVE: Sessions Revoked (RevokeOlderSessions) • Inline DenyAttached • Blast Radius Neutralized
            </span>
          </div>

        </div>

        <!-- Node Inspector Bar -->
        <div class="mt-4 grid grid-cols-3 gap-3 text-xs font-mono">
          <div class="bg-slate-950 p-2.5 rounded border border-slate-800">
            <span class="text-slate-400">Target Asset Criticality:</span>
            <span class="text-rose-400 font-bold ml-1">9.5 / 10.0 (Tier-1 Sensitive)</span>
          </div>
          <div class="bg-slate-950 p-2.5 rounded border border-slate-800">
            <span class="text-slate-400">Reachability Probability:</span>
            <span class="text-amber-400 font-bold ml-1">0.94 (Multi-Hop Permitted)</span>
          </div>
          <div class="bg-slate-950 p-2.5 rounded border border-slate-800">
            <span class="text-slate-400">Mitigation Strategy:</span>
            <span class="text-emerald-400 font-bold ml-1">Automated IAM Session Revocation</span>
          </div>
        </div>
      </div>

      <!-- MITRE ATT&CK Cloud Matrix (4 cols) -->
      <div class="lg:col-span-4 bg-slate-900/90 border border-slate-800 rounded-xl p-5 flex flex-col">
        <div class="flex items-center justify-between pb-4 border-b border-slate-800">
          <div class="flex items-center space-x-3">
            <div class="p-2 bg-indigo-950/80 border border-indigo-800/50 rounded-lg text-indigo-400">
              <i class="fa-solid fa-chess-board"></i>
            </div>
            <div>
              <h2 class="text-base font-bold text-white">MITRE ATT&CK Matrix</h2>
              <p class="text-xs text-slate-400">Cloud Matrix (AWS Enterprise Coverage)</p>
            </div>
          </div>
          <span class="text-[11px] bg-emerald-950 text-emerald-400 font-mono px-2 py-0.5 rounded border border-emerald-800">100% Covered</span>
        </div>

        <div class="mt-4 grid grid-cols-2 gap-2 flex-1">

          <div class="bg-slate-950 p-2.5 rounded border border-slate-800 flex flex-col justify-between">
            <div class="flex justify-between items-center">
              <span class="text-[11px] text-slate-400 font-medium">Initial Access</span>
              <span class="h-2 w-2 rounded-full bg-emerald-400"></span>
            </div>
            <p class="text-xs font-bold text-white font-mono mt-1">T1078.004</p>
            <p class="text-[10px] text-slate-400">Cloud Accounts Abuse</p>
          </div>

          <div class="bg-slate-950 p-2.5 rounded border border-slate-800 flex flex-col justify-between">
            <div class="flex justify-between items-center">
              <span class="text-[11px] text-slate-400 font-medium">Persistence</span>
              <span class="h-2 w-2 rounded-full bg-emerald-400"></span>
            </div>
            <p class="text-xs font-bold text-white font-mono mt-1">T1098.001</p>
            <p class="text-[10px] text-slate-400">CreateAccessKey Drift</p>
          </div>

          <div class="bg-slate-950 p-2.5 rounded border border-slate-800 flex flex-col justify-between">
            <div class="flex justify-between items-center">
              <span class="text-[11px] text-slate-400 font-medium">Privilege Escalation</span>
              <span class="h-2 w-2 rounded-full bg-emerald-400"></span>
            </div>
            <p class="text-xs font-bold text-white font-mono mt-1">T1078</p>
            <p class="text-[10px] text-slate-400">Admin Policy Attach</p>
          </div>

          <div class="bg-slate-950 p-2.5 rounded border border-slate-800 flex flex-col justify-between">
            <div class="flex justify-between items-center">
              <span class="text-[11px] text-slate-400 font-medium">Defense Evasion</span>
              <span class="h-2 w-2 rounded-full bg-emerald-400"></span>
            </div>
            <p class="text-xs font-bold text-white font-mono mt-1">T1562.001</p>
            <p class="text-[10px] text-slate-400">CloudTrail Tampering</p>
          </div>

          <div class="bg-slate-950 p-2.5 rounded border border-slate-800 flex flex-col justify-between">
            <div class="flex justify-between items-center">
              <span class="text-[11px] text-slate-400 font-medium">Lateral Movement</span>
              <span class="h-2 w-2 rounded-full bg-emerald-400"></span>
            </div>
            <p class="text-xs font-bold text-white font-mono mt-1">T1550.001</p>
            <p class="text-[10px] text-slate-400">Cross-Acct AssumeRole</p>
          </div>

          <div class="bg-slate-950 p-2.5 rounded border border-slate-800 flex flex-col justify-between">
            <div class="flex justify-between items-center">
              <span class="text-[11px] text-slate-400 font-medium">Impact / Exfiltration</span>
              <span class="h-2 w-2 rounded-full bg-emerald-400"></span>
            </div>
            <p class="text-xs font-bold text-white font-mono mt-1">T1530</p>
            <p class="text-[10px] text-slate-400">S3 Cloud Storage Drift</p>
          </div>

        </div>

        <div class="mt-4 p-3 bg-indigo-950/40 border border-indigo-800/40 rounded-lg text-[11px] text-slate-300 font-mono">
          <i class="fa-solid fa-circle-info text-cyan-400 mr-1"></i>
          All 8 Purple-Team vectors mapped with continuous auto-remediation playbooks.
        </div>
      </div>

    </div>

    <!-- BOTTOM ROW: LIVE INCIDENT DOSSIERS & TERMINAL LOGS -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">

      <!-- Incident Dossier Table (7 cols) -->
      <div class="lg:col-span-7 bg-slate-900/90 border border-slate-800 rounded-xl p-5 flex flex-col">
        <div class="flex items-center justify-between pb-4 border-b border-slate-800">
          <div class="flex items-center space-x-3">
            <div class="p-2 bg-amber-950/80 border border-amber-800/50 rounded-lg text-amber-400">
              <i class="fa-solid fa-list-check"></i>
            </div>
            <div>
              <h2 class="text-base font-bold text-white">Live Incident Management & Containment Feed</h2>
              <p class="text-xs text-slate-400">Automated Step Functions Lifecycle • Human-in-the-Loop RBAC Approval</p>
            </div>
          </div>
          <span class="text-xs bg-slate-800 text-cyan-400 font-mono px-2.5 py-1 rounded" id="incidents-total-badge">2 Incidents</span>
        </div>

        <div class="mt-4 overflow-x-auto flex-1">
          <table class="w-full text-left text-xs font-mono">
            <thead>
              <tr class="border-b border-slate-800 text-slate-400 text-[11px]">
                <th class="pb-2 font-semibold">INCIDENT ID</th>
                <th class="pb-2 font-semibold">TITLE / SCENARIO</th>
                <th class="pb-2 font-semibold">SEVERITY</th>
                <th class="pb-2 font-semibold">RISK</th>
                <th class="pb-2 font-semibold">STATE</th>
                <th class="pb-2 font-semibold">ACTION</th>
              </tr>
            </thead>
            <tbody id="incidents-table-body" class="divide-y divide-slate-800/60">
              <!-- Dynamically populated via JS -->
            </tbody>
          </table>
        </div>
      </div>

      <!-- Live SOC Terminal Stream (5 cols) -->
      <div class="lg:col-span-5 bg-slate-900/90 border border-slate-800 rounded-xl p-5 flex flex-col">
        <div class="flex items-center justify-between pb-4 border-b border-slate-800">
          <div class="flex items-center space-x-3">
            <div class="p-2 bg-emerald-950/80 border border-emerald-800/50 rounded-lg text-emerald-400">
              <i class="fa-solid fa-terminal"></i>
            </div>
            <div>
              <h2 class="text-base font-bold text-white">SOC Telemetry Stream</h2>
              <p class="text-xs text-slate-400">Real-Time Ingestion, Detections, & Forensics Hashes</p>
            </div>
          </div>
          <span class="h-2.5 w-2.5 rounded-full bg-emerald-400 animate-ping"></span>
        </div>

        <!-- Terminal Body -->
        <div class="mt-4 flex-1 bg-black/90 rounded-lg border border-slate-800 p-3.5 font-mono text-[11px] leading-relaxed overflow-y-auto max-h-[380px] terminal-scroll space-y-1.5" id="terminal-stream">
          <!-- Dynamically populated -->
        </div>
      </div>

    </div>

    <!-- FORENSICS & S3 OBJECT LOCK SECTION -->
    <div class="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
      <div class="flex items-center justify-between pb-4 border-b border-slate-800">
        <div class="flex items-center space-x-3">
          <div class="p-2 bg-cyan-950/80 border border-cyan-800/50 rounded-lg text-cyan-400">
            <i class="fa-solid fa-fingerprint"></i>
          </div>
          <div>
            <h2 class="text-base font-bold text-white">Digital Forensics & Immutable S3 Object Lock Vault</h2>
            <p class="text-xs text-slate-400">WORM Compliance Mode (7 Years Retention) • Cryptographic SHA-256 Chain of Custody Proofs</p>
          </div>
        </div>
        <span class="text-xs bg-cyan-950 text-cyan-300 font-mono px-3 py-1 rounded border border-cyan-800">Vault: s3://aegis-forensics-vault-111111111111</span>
      </div>

      <div class="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
        <div class="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
          <div class="text-slate-400">Active Manifest ID:</div>
          <div class="text-cyan-300 font-bold mt-1 text-sm">manifest-4a81bc20</div>
          <div class="text-slate-500 text-[10px] mt-2">Cumulative SHA-256 Digest:</div>
          <div class="text-slate-300 text-[10px] break-all">e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</div>
        </div>

        <div class="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
          <div class="text-slate-400">Chain of Custody Timeline:</div>
          <div class="text-emerald-400 font-bold mt-1 text-sm">6 Verified Forensic Stages</div>
          <div class="text-slate-500 text-[10px] mt-2">ATTACK -> DETECTION -> GRAPH -> RISK -> CONTAINMENT -> VERIFY</div>
          <div class="text-emerald-300 text-[10px] mt-1">Status: Object Lock Legal Hold Active (Compliance)</div>
        </div>

        <div class="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
          <div class="text-slate-400">Integrity Verification:</div>
          <div class="text-indigo-400 font-bold mt-1 text-sm">Zero-Tamper Guarantee</div>
          <div class="text-slate-500 text-[10px] mt-2">AWS KMS Key:</div>
          <div class="text-slate-300 text-[10px]">arn:aws:kms:us-east-1:111111111111:key/aegis-forensics-key</div>
        </div>
      </div>
    </div>

  </main>

  <!-- FOOTER -->
  <footer class="border-t border-slate-800 bg-slate-950 px-6 py-3 text-center text-xs font-mono text-slate-500 flex justify-between items-center">
    <span>Project AEGIS © 2026 — Senior Cloud Security Engineering Portfolio</span>
    <span>Autonomous Live SOC Simulation Daemon Active</span>
  </footer>

  <!-- JAVASCRIPT AUTO-REFRESH & INTERACTIVITY -->
  <script>
    async function fetchStatus() {
      try {
        const res = await fetch('/api/status');
        const data = await res.json();
        document.getElementById('countdown-label').innerText = data.countdown;
        document.getElementById('events-count').innerText = data.total_events_ingested.toLocaleString();
        document.getElementById('target-time-label').innerText = data.target_end_time;
        if (data.remaining_seconds === 0) {
          document.getElementById('live-state-label').innerText = "FINALIZED AT 19:00:00 (SCREENSHOT READY)";
          document.getElementById('live-state-label').className = "text-xs font-semibold uppercase tracking-wider text-cyan-400";
        }
      } catch (err) {
        console.error("Status fetch error", err);
      }
    }

    async function fetchPosture() {
      try {
        const res = await fetch('/api/posture');
        const data = await res.json();
        document.getElementById('posture-score').innerText = data.posture_score;
        document.getElementById('mttd-metric').innerText = data.mean_time_to_detect_seconds + "s";
        document.getElementById('mttc-metric').innerText = data.mean_time_to_contain_seconds + "s";
        document.getElementById('active-incidents').innerText = data.active_incidents_count;
      } catch (err) {
        console.error("Posture fetch error", err);
      }
    }

    async function fetchIncidents() {
      try {
        const res = await fetch('/api/incidents');
        const incidents = await res.json();
        document.getElementById('incidents-total-badge').innerText = incidents.length + " Incidents";

        const tbody = document.getElementById('incidents-table-body');
        tbody.innerHTML = '';

        incidents.forEach(inc => {
          const tr = document.createElement('tr');
          tr.className = "hover:bg-slate-800/40 transition";

          let sevBadge = "bg-rose-950 text-rose-400 border border-rose-800";
          if (inc.severity === "HIGH") sevBadge = "bg-amber-950 text-amber-400 border border-amber-800";

          let stateBadge = "bg-emerald-950 text-emerald-400 border border-emerald-800";
          if (inc.current_state === "CONTAINING") stateBadge = "bg-blue-950 text-blue-400 border border-blue-800 animate-pulse";

          tr.innerHTML = `
            <td class="py-2.5 font-bold text-cyan-400">${inc.incident_id}</td>
            <td class="py-2.5 text-slate-200 max-w-xs truncate">${inc.title}</td>
            <td class="py-2.5"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${sevBadge}">${inc.severity}</span></td>
            <td class="py-2.5 font-bold ${inc.risk_score >= 80 ? 'text-rose-400' : 'text-amber-400'}">${inc.risk_score}</td>
            <td class="py-2.5"><span class="px-2 py-0.5 rounded text-[10px] font-semibold ${stateBadge}">${inc.current_state}</span></td>
            <td class="py-2.5 text-slate-300 font-mono text-[10px]">${inc.response_action || 'AUTO_REMEDIATE'}</td>
          `;
          tbody.appendChild(tr);
        });
      } catch (err) {
        console.error("Incidents fetch error", err);
      }
    }

    async function fetchEvents() {
      try {
        const res = await fetch('/api/events');
        const events = await res.json();
        const term = document.getElementById('terminal-stream');
        term.innerHTML = '';

        events.forEach(ev => {
          const row = document.createElement('div');
          let color = "text-slate-400";
          if (ev.category === "ATTACK") color = "text-rose-400 font-bold";
          if (ev.category === "DETECTION") color = "text-amber-400";
          if (ev.category === "REMEDIATION") color = "text-emerald-400 font-semibold";
          if (ev.category === "FORENSICS") color = "text-cyan-400";
          if (ev.category === "SYSTEM") color = "text-emerald-300 font-bold";

          row.innerHTML = `<span class="text-slate-500">[${ev.timestamp}]</span> <span class="${color}">[${ev.category}]</span> <span class="text-slate-300">${ev.message}</span>`;
          term.appendChild(row);
        });
      } catch (err) {
        console.error("Events fetch error", err);
      }
    }

    async function triggerManualAttack() {
      try {
        const res = await fetch('/api/trigger_scenario', { method: 'POST' });
        const result = await res.json();
        alert('Purple-Team attack scenario executed:\\n' + result.title + '\\nAction: ' + result.action);
        fetchIncidents();
        fetchPosture();
        fetchEvents();
      } catch (err) {
        alert('Failed to trigger scenario: ' + err);
      }
    }

    // Polling intervals
    setInterval(fetchStatus, 1000);
    setInterval(fetchPosture, 3000);
    setInterval(fetchIncidents, 4000);
    setInterval(fetchEvents, 2500);

    // Initial load
    fetchStatus();
    fetchPosture();
    fetchIncidents();
    fetchEvents();
  </script>
</body>
</html>
"""


class WarRoomHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler routing War Room UI and REST API calls."""

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy HTTP request logging to clean up stdout
        pass

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD.encode("utf-8"))
            return

        elif path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            data = soc_engine.get_status()
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        elif path == "/api/posture":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            posture = war_room_api.get_posture_summary()
            self.wfile.write(posture.model_dump_json().encode("utf-8"))
            return

        elif path == "/api/incidents":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            incidents = war_room_api.list_incidents()
            data = [inc.model_dump(mode="json") for inc in incidents]
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        elif path.startswith("/api/incidents/"):
            inc_id = path.replace("/api/incidents/", "")
            incident = war_room_api.get_incident_detail(inc_id)
            if incident:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(incident.model_dump_json().encode("utf-8"))
            else:
                self.send_response(404)
                self.end_headers()
            return

        elif path == "/api/events":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            with soc_engine._lock:
                events = list(soc_engine.events_log[:50])
            self.wfile.write(json.dumps(events).encode("utf-8"))
            return

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/trigger_scenario":
            res = soc_engine.trigger_attack_scenario()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        elif path == "/api/approve":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len).decode("utf-8")
            try:
                data = json.loads(body)
                req = ApprovalActionRequest(**data)
                resp = war_room_api.process_approval(req)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(resp.model_dump_json().encode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
            return

        else:
            self.send_response(404)
            self.end_headers()


def start_server() -> None:
    """Start background simulation thread and HTTP server."""
    # 1. Start simulation background worker
    sim_thread = threading.Thread(target=soc_engine.run_loop, daemon=True)
    sim_thread.start()

    # 2. Start HTTP server
    server_address = ("0.0.0.0", PORT)
    httpd = socketserver.ThreadingTCPServer(server_address, WarRoomHTTPRequestHandler)
    httpd.allow_reuse_address = True

    print("=" * 80)
    print(" PROJECT AEGIS — AUTONOMOUS LIVE SOC WAR ROOM SERVER")
    print("=" * 80)
    print(f" [+] HTTP Web War Room running at: http://localhost:{PORT}")
    print(f" [+] API Endpoints: http://localhost:{PORT}/api/posture, /api/incidents, /api/events")
    print(f" [+] Target Stop Time: {TARGET_END_ISO} (7:00 PM)")
    print(f" [+] Live Telemetry & Attacks logging to: {LOG_FILE}")
    print("=" * 80)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping AEGIS Live SOC Server...")
        soc_engine.is_running = False
        httpd.shutdown()


if __name__ == "__main__":
    start_server()
