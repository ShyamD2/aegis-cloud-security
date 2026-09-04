"""
Project AEGIS - End-to-End Lifecycle Latency Benchmarking Suite
Empirically measures and validates p50, p90, p95, and p99 execution latencies across
all 7 core architectural stages of the AEGIS pipeline.
"""

from __future__ import annotations

import math
import statistics
import time
import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from detection_engine.enrichment import EventEnricher
from detection_engine.evaluator import DetectionEvaluator
from services.attack_path import build_enterprise_attack_graph
from services.forensics import EvidenceCollector, EvidenceType
from services.remediation import (
    RemediationAction,
    RemediationOrchestrator,
    RemediationRequest,
)
from services.risk_engine import (
    ExposureLevel,
    PrivilegeLevel,
    RiskContext,
    RiskEngine,
)
from services.telemetry.parser import parse_cloudtrail_event


class StageLatencyMetric(BaseModel):
    """Percentile latency metrics for a discrete processing stage."""

    model_config = ConfigDict(extra="forbid")

    stage_name: str
    sample_count: int
    min_ms: float
    max_ms: float
    mean_ms: float
    p50_ms: float
    p90_ms: float
    p95_ms: float
    p99_ms: float


class BenchmarkReport(BaseModel):
    """Overall pipeline benchmarking report with SLAs."""

    model_config = ConfigDict(extra="forbid")

    total_events: int
    overall_p50_ms: float
    overall_p90_ms: float
    overall_p95_ms: float
    overall_p99_ms: float
    stages: dict[str, StageLatencyMetric]
    sla_passed: bool
    summary: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class LifecycleLatencyBenchmark:
    """
    Executes repeated end-to-end security lifecycle events and calculates
    high-resolution latency profiles.
    """

    def __init__(self) -> None:
        self.evaluator = DetectionEvaluator()
        self.risk_engine = RiskEngine()
        self.orchestrator = RemediationOrchestrator()
        self.graph = build_enterprise_attack_graph()

    @staticmethod
    def _compute_percentiles(samples: list[float], stage_name: str) -> StageLatencyMetric:
        if not samples:
            return StageLatencyMetric(
                stage_name=stage_name,
                sample_count=0,
                min_ms=0.0,
                max_ms=0.0,
                mean_ms=0.0,
                p50_ms=0.0,
                p90_ms=0.0,
                p95_ms=0.0,
                p99_ms=0.0,
            )

        samples_sorted = sorted(samples)
        count = len(samples_sorted)

        def percentile(p: float) -> float:
            if count == 1:
                return samples_sorted[0]
            k = (count - 1) * p
            f = math.floor(k)
            c = math.ceil(k)
            if f == c:
                return samples_sorted[int(k)]
            d0 = samples_sorted[int(f)] * (c - k)
            d1 = samples_sorted[int(c)] * (k - f)
            return d0 + d1

        return StageLatencyMetric(
            stage_name=stage_name,
            sample_count=count,
            min_ms=round(samples_sorted[0], 3),
            max_ms=round(samples_sorted[-1], 3),
            mean_ms=round(statistics.mean(samples_sorted), 3),
            p50_ms=round(percentile(0.50), 3),
            p90_ms=round(percentile(0.90), 3),
            p95_ms=round(percentile(0.95), 3),
            p99_ms=round(percentile(0.99), 3),
        )

    def run_benchmark(
        self,
        iterations: int = 50,
        target_p95_sla_ms: float = 500.0,
    ) -> BenchmarkReport:
        """
        Execute end-to-end lifecycle iterations and capture per-stage timing.
        """
        stage_times: dict[str, list[float]] = {
            "1_telemetry_normalization": [],
            "2_context_enrichment": [],
            "3_detection_evaluation": [],
            "4_attack_path_blast_radius": [],
            "5_risk_score_calculation": [],
            "6_remediation_orchestration": [],
            "7_forensic_manifest_hashing": [],
            "total_e2e_lifecycle": [],
        }

        for i in range(iterations):
            t_total_start = time.perf_counter()

            raw_event = {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": f"AIDA{uuid.uuid4().hex[:12].upper()}",
                    "arn": "arn:aws:iam::333333333333:user/contractor-alice",
                    "accountId": "333333333333",
                    "userName": "contractor-alice",
                },
                "eventTime": datetime.now(UTC).isoformat(),
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateAccessKey",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "198.51.100.45",
                "userAgent": "aws-cli/2.15.0",
                "requestParameters": {"userName": "contractor-alice"},
                "responseElements": {
                    "accessKey": {"accessKeyId": f"AKIA{uuid.uuid4().hex[:16].upper()}"}
                },
                "eventID": f"bench-evt-{i}-{uuid.uuid4().hex[:8]}",
                "eventType": "AwsApiCall",
                "recipientAccountId": "333333333333",
            }

            # 1. Normalization
            t0 = time.perf_counter()
            norm_event = parse_cloudtrail_event(raw_event)
            stage_times["1_telemetry_normalization"].append((time.perf_counter() - t0) * 1000)

            # 2. Enrichment
            t1 = time.perf_counter()
            _ = EventEnricher.enrich(norm_event)
            stage_times["2_context_enrichment"].append((time.perf_counter() - t1) * 1000)

            # 3. Detection
            t2 = time.perf_counter()
            _, findings = self.evaluator.evaluate_event(norm_event)
            stage_times["3_detection_evaluation"].append((time.perf_counter() - t2) * 1000)

            finding = findings[0] if findings else None

            # 4. Attack Path Blast Radius
            t3 = time.perf_counter()
            blast = self.graph.calculate_blast_radius(
                "arn:aws:iam::333333333333:user/contractor-alice"
            )
            stage_times["4_attack_path_blast_radius"].append((time.perf_counter() - t3) * 1000)

            # 5. Risk Scoring
            t4 = time.perf_counter()
            context = RiskContext(
                finding_id=finding.finding_id if finding else "f-synthetic",
                detection_severity=finding.severity if finding else "HIGH",
                confidence=finding.confidence if finding else 0.85,
                asset_criticality=5.0,
                privilege_level=PrivilegeLevel.IAM_WRITE,
                exposure_level=ExposureLevel.INTERNET_FACING,
                blast_radius_score=blast.score,
                anomaly_score=0.85,
            )
            risk = self.risk_engine.evaluate(context)
            stage_times["5_risk_score_calculation"].append((time.perf_counter() - t4) * 1000)

            # 6. Remediation Orchestration
            t5 = time.perf_counter()
            rem_req = RemediationRequest(
                remediation_id=f"rem-bench-{i}",
                finding_id=context.finding_id,
                action=RemediationAction.DEACTIVATE_ACCESS_KEY,
                target_resource_id="arn:aws:iam::333333333333:user/contractor-alice",
                account_id="333333333333",
                risk_score=risk.risk_score,
                idempotency_key=f"idem-bench-{i}-{uuid.uuid4().hex[:6]}",
                parameters={"access_key_id": "AKIAEXAMPLETARGET"},
            )
            _ = self.orchestrator.execute(rem_req)
            stage_times["6_remediation_orchestration"].append((time.perf_counter() - t5) * 1000)

            # 7. Forensics Manifest Hashing
            t6 = time.perf_counter()
            collector = EvidenceCollector(vault_bucket="aegis-forensic-vault-lab")
            rec = collector.capture_record(
                incident_id=f"inc-bench-{i}",
                evidence_type=EvidenceType.CLOUDTRAIL_RECORD,
                source_service="cloudtrail",
                account_id="333333333333",
                raw_data=raw_event,
            )
            _ = collector.assemble_manifest(
                incident_id=f"inc-bench-{i}",
                account_id="333333333333",
                evidence_items=[rec],
                timeline=[],
            )
            stage_times["7_forensic_manifest_hashing"].append((time.perf_counter() - t6) * 1000)

            # Total E2E
            stage_times["total_e2e_lifecycle"].append((time.perf_counter() - t_total_start) * 1000)

        # Calculate metrics
        metrics: dict[str, StageLatencyMetric] = {}
        for stage_name, samples in stage_times.items():
            metrics[stage_name] = self._compute_percentiles(samples, stage_name)

        overall = metrics["total_e2e_lifecycle"]
        sla_passed = overall.p95_ms <= target_p95_sla_ms

        summary = (
            f"AEGIS Benchmark completed across {iterations} iterations. "
            f"Overall p50: {overall.p50_ms}ms, p95: {overall.p95_ms}ms, p99: {overall.p99_ms}ms. "
            f"SLA Target ({target_p95_sla_ms}ms): {'PASSED' if sla_passed else 'FAILED'}."
        )

        return BenchmarkReport(
            total_events=iterations,
            overall_p50_ms=overall.p50_ms,
            overall_p90_ms=overall.p90_ms,
            overall_p95_ms=overall.p95_ms,
            overall_p99_ms=overall.p99_ms,
            stages=metrics,
            sla_passed=sla_passed,
            summary=summary,
        )
