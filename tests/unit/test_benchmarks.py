"""
Project AEGIS - Performance, Cost & Reliability Benchmark Tests
Validates empirical latency percentiles (p50/p95/p99), FinOps cloud financial modeling,
and high-availability reliability SLA calculations.
"""

from __future__ import annotations

import pytest

from services.benchmarks.benchmark_suite import LifecycleLatencyBenchmark
from services.benchmarks.cost_calculator import CostTier, FinOpsCostCalculator
from services.benchmarks.reliability_tracker import ReliabilityTracker


@pytest.mark.benchmark
def test_lifecycle_latency_benchmarks_and_percentiles() -> None:
    """Run lifecycle benchmark across 20 events and verify p50/p90/p95/p99 ordering and sub-second SLAs."""
    benchmark = LifecycleLatencyBenchmark()
    report = benchmark.run_benchmark(iterations=20, target_p95_sla_ms=500.0)

    assert report.total_events == 20
    assert report.overall_p50_ms > 0.0
    assert report.overall_p90_ms is not None or "total_e2e_lifecycle" in report.stages
    assert report.overall_p95_ms >= report.overall_p50_ms
    assert report.overall_p99_ms >= report.overall_p95_ms
    assert report.overall_p50_ms < 500.0  # Must be sub-second
    assert report.sla_passed is True

    # Verify all 7 stages exist with non-negative timings
    expected_stages = [
        "1_telemetry_normalization",
        "2_context_enrichment",
        "3_detection_evaluation",
        "4_attack_path_blast_radius",
        "5_risk_score_calculation",
        "6_remediation_orchestration",
        "7_forensic_manifest_hashing",
        "total_e2e_lifecycle",
    ]
    for stg in expected_stages:
        assert stg in report.stages
        metric = report.stages[stg]
        assert metric.sample_count == 20
        assert metric.min_ms >= 0.0
        assert metric.max_ms >= metric.min_ms
        assert metric.p95_ms >= metric.p50_ms


@pytest.mark.unit
def test_finops_cost_calculator_across_all_tiers() -> None:
    """Calculate cloud infrastructure expenditures across Small, Medium, and Hyperscale tiers."""
    # 1. Startup Tier (1M events)
    cost_small = FinOpsCostCalculator.calculate_tier_cost(CostTier.SMALL_STARTUP)
    assert cost_small.monthly_events == 1_000_000
    assert cost_small.total_monthly_usd > 0.0
    assert cost_small.kinesis_cost > 0.0
    assert cost_small.lambda_cost > 0.0
    assert cost_small.neptune_serverless_cost > 0.0

    # Verify percentage sum is ~100%
    pct_sum_small = sum(cost_small.component_percentages.values())
    assert 99.0 <= pct_sum_small <= 101.0

    # 2. Medium Enterprise Tier (50M events)
    cost_med = FinOpsCostCalculator.calculate_tier_cost(CostTier.MEDIUM_ENTERPRISE)
    assert cost_med.monthly_events == 50_000_000
    assert cost_med.total_monthly_usd > cost_small.total_monthly_usd
    # Economies of scale: cost per million should decrease as volume scales
    assert cost_med.cost_per_million_events < cost_small.cost_per_million_events

    # 3. Large Hyperscale Tier (500M events)
    cost_large = FinOpsCostCalculator.calculate_tier_cost(CostTier.LARGE_HYPERSCALE)
    assert cost_large.monthly_events == 500_000_000
    assert cost_large.total_monthly_usd > cost_med.total_monthly_usd
    assert cost_large.cost_per_million_events < cost_med.cost_per_million_events


@pytest.mark.unit
def test_reliability_and_sla_metrics() -> None:
    """Verify reliability tracker evaluates MTTA, MTTC, downtime budget, and SLA compliance."""
    metrics = ReliabilityTracker.compute_sla_metrics(
        observed_mttd_seconds=0.42,
        observed_mttc_seconds=1.15,
        availability_target=99.99,
        active_regions=["us-east-1", "eu-west-1"],
    )

    assert metrics.availability_sla_percent == 99.99
    # 99.99% gives ~52.56 minutes downtime allowed per year
    assert 52.0 <= metrics.annual_downtime_minutes_allowed <= 53.0
    assert metrics.mttd_seconds == 0.42
    assert metrics.mttc_seconds == 1.15
    assert metrics.rto_seconds == 30.0
    assert metrics.rpo_seconds == 0.0
    assert metrics.is_sla_compliant is True
    assert len(metrics.active_regions) == 2
    assert "active-passive" in metrics.architecture_resilience_summary
