#!/usr/bin/env python3
"""
Project AEGIS - AWS Operational Cost Calculator CLI
Estimates monthly cloud spend across event ingestion rates and account scales,
comparing AEGIS Enterprise Full Architecture vs AEGIS Lite Architecture.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def calculate_monthly_cost(
    events_per_sec: float,
    account_count: int = 1,
    retention_days: int = 90,
) -> dict[str, Any]:
    """
    Computes detailed line-item cost projections for Full vs Lite architectures.
    Assumptions:
      - Average event size: 1.5 KB
      - Month: 30.5 days = 2,635,200 seconds
    """
    seconds_in_month = 30.5 * 24 * 3600
    monthly_events = events_per_sec * seconds_in_month
    monthly_gb_ingested = (monthly_events * 1.5) / (1024 * 1024)

    # -------------------------------------------------------------
    # 1. AEGIS Enterprise Full Architecture (Multi-Account Standard)
    # -------------------------------------------------------------
    # Kinesis Data Streams: 1 shard per 1,000 events/sec ($0.015/shard-hour + $0.014/million PUT units)
    required_shards = max(1, int(events_per_sec / 1000) + 1)
    kinesis_cost = (required_shards * 0.015 * 730) + ((monthly_events / 1_000_000) * 0.014)

    # AWS Lambda: 128 MB, ~20ms execution per batch of 50 events
    lambda_invocations = monthly_events / 50.0
    lambda_compute_gb_sec = lambda_invocations * (128 / 1024) * 0.025
    lambda_cost = (lambda_invocations / 1_000_000 * 0.20) + (lambda_compute_gb_sec * 0.0000166667)

    # Amazon Neptune Serverless: Minimum 1.0 NCU base ($0.10/NCU-hour) + dynamic scaling under load
    neptune_ncu = max(1.0, 1.0 + (events_per_sec / 10000.0) * 1.5)
    neptune_cost = neptune_ncu * 0.10 * 730

    # Amazon SageMaker Serverless Inference: $0.000020 per compute second + $0.20/million requests
    # Batch inference: 1 call per 100 events
    sagemaker_invocations = monthly_events / 100.0
    sagemaker_cost = (sagemaker_invocations / 1_000_000 * 0.20) + (sagemaker_invocations * 0.030 * 0.000020)

    # Step Functions (Standard): Only triggers on HIGH/CRITICAL findings (~0.05% of events)
    remediation_events = monthly_events * 0.0005
    step_functions_cost = (remediation_events * 5 / 1000.0) * 0.025

    # DynamoDB (Pay-per-request): Idempotency & state tables
    dynamo_cost = (monthly_events / 1_000_000 * 1.25) + (remediation_events / 1_000_000 * 1.25)

    # Amazon S3 WORM Forensic Vault: Storage ($0.023/GB) + API calls
    cumulative_stored_gb = monthly_gb_ingested * (retention_days / 30.5)
    s3_cost = (cumulative_stored_gb * 0.023) + (monthly_events / 1_000_000 * 0.005)

    # AWS KMS Customer Managed Keys: $1/key/month (3 keys) + $0.03 per 10,000 requests
    kms_cost = (3.0 * account_count) + ((monthly_events * 0.10 / 10_000) * 0.03)

    full_total = (
        kinesis_cost
        + lambda_cost
        + neptune_cost
        + sagemaker_cost
        + step_functions_cost
        + dynamo_cost
        + s3_cost
        + kms_cost
    )

    # -------------------------------------------------------------
    # 2. AEGIS Lite Architecture (Single-Account Startup / Cost-Optimized)
    # -------------------------------------------------------------
    # Replaces Kinesis with Amazon SQS ($0.40 per million requests)
    sqs_cost = (monthly_events / 1_000_000) * 0.40

    # Replaces Neptune with DynamoDB Single-Table Graph Store ($1.25/million writes, $0.25/million reads)
    lite_graph_cost = (monthly_events / 1_000_000) * 0.50

    # Replaces SageMaker Serverless with in-process centroid scoring in Lambda (+$0.000002/inv)
    lite_ml_cost = 0.0  # Evaluated directly in Lambda worker memory

    # Step Functions Express: $1.00 per million executions + duration
    lite_sfn_cost = (remediation_events / 1_000_000) * 1.00

    # Single KMS Key
    lite_kms_cost = 1.0 + ((remediation_events / 10_000) * 0.03)

    lite_total = (
        sqs_cost
        + lambda_cost
        + lite_graph_cost
        + lite_ml_cost
        + lite_sfn_cost
        + s3_cost
        + lite_kms_cost
    )

    return {
        "parameters": {
            "events_per_sec": events_per_sec,
            "monthly_events": int(monthly_events),
            "monthly_gb_ingested": round(monthly_gb_ingested, 2),
            "account_count": account_count,
            "retention_days": retention_days,
        },
        "enterprise_full": {
            "kinesis": round(kinesis_cost, 2),
            "lambda": round(lambda_cost, 2),
            "neptune_serverless": round(neptune_cost, 2),
            "sagemaker_inference": round(sagemaker_cost, 2),
            "step_functions": round(step_functions_cost, 2),
            "dynamodb": round(dynamo_cost, 2),
            "s3_worm_vault": round(s3_cost, 2),
            "kms": round(kms_cost, 2),
            "total_monthly": round(full_total, 2),
        },
        "aegis_lite": {
            "sqs": round(sqs_cost, 2),
            "lambda": round(lambda_cost, 2),
            "dynamodb_graph": round(lite_graph_cost, 2),
            "in_process_ml": 0.0,
            "step_functions_express": round(lite_sfn_cost, 2),
            "s3_worm_vault": round(s3_cost, 2),
            "kms": round(lite_kms_cost, 2),
            "total_monthly": round(lite_total, 2),
        },
        "savings_percentage": round(((full_total - lite_total) / full_total) * 100, 1),
    }


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="AEGIS AWS Operational Cost Calculator CLI")
    parser.add_argument("--rate", "-r", type=float, default=1000.0, help="Ingestion rate in events/second")
    parser.add_argument("--accounts", "-a", type=int, default=3, help="Number of monitored AWS accounts")
    parser.add_argument("--retention", type=int, default=90, help="S3 Object Lock retention days")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()
    report = calculate_monthly_cost(args.rate, args.accounts, args.retention)

    if args.json:
        print(json.dumps(report, indent=2))
        return

    p = report["parameters"]
    f = report["enterprise_full"]
    l = report["aegis_lite"]

    print("\n" + "=" * 76)
    print("[AEGIS COST CALCULATOR] PROJECTED AWS MONTHLY OPERATIONAL SPEND")
    print("=" * 76)
    print(f"Ingestion Throughput:  {p['events_per_sec']:,.0f} events/sec ({p['monthly_events']:,} events/month)")
    print(f"Monthly Data Volume:   {p['monthly_gb_ingested']:,.2f} GB/month")
    print(f"Monitored Accounts:    {p['account_count']} AWS Accounts")
    print(f"Evidence Retention:    {p['retention_days']} Days (S3 Object Lock COMPLIANCE)")
    print("-" * 76)
    print(f"{'AWS Service / Component':<32} | {'Enterprise Full':<16} | {'AEGIS Lite':<16}")
    print("-" * 76)
    print(f"{'Ingestion (Kinesis vs SQS)':<32} | ${f['kinesis']:>14.2f} | ${l['sqs']:>14.2f}")
    print(f"{'Lambda Event Processors':<32} | ${f['lambda']:>14.2f} | ${l['lambda']:>14.2f}")
    print(f"{'Attack Graph (Neptune vs Dynamo)':<32} | ${f['neptune_serverless']:>14.2f} | ${l['dynamodb_graph']:>14.2f}")
    print(f"{'Anomaly Engine (SageMaker vs In-Mem)':<32} | ${f['sagemaker_inference']:>14.2f} | ${l['in_process_ml']:>14.2f}")
    print(f"{'SOAR Orchestrator (SFn Standard/Exp)':<32} | ${f['step_functions']:>14.2f} | ${l['step_functions_express']:>14.2f}")
    print(f"{'Forensic S3 WORM Vault':<32} | ${f['s3_worm_vault']:>14.2f} | ${l['s3_worm_vault']:>14.2f}")
    print(f"{'Customer-Managed KMS Keys':<32} | ${f['kms']:>14.2f} | ${l['kms']:>14.2f}")
    print("-" * 76)
    print(f"{'TOTAL MONTHLY ESTIMATE':<32} | \033[94m${f['total_monthly']:>14.2f}\033[0m | \033[92m${l['total_monthly']:>14.2f}\033[0m")
    print("=" * 76)
    print(f"Cost Reduction with AEGIS Lite: {report['savings_percentage']}% savings")
    print("Recommendation:")
    if args.rate <= 2000:
        print("  -> Use AEGIS Lite: Ideal for staging, startups, and workloads under 2,000 events/sec.")
    else:
        print("  -> Use Enterprise Full: Ideal for multi-account enterprise estates with complex attack graphs.")
    print("-" * 76 + "\n")


if __name__ == "__main__":
    main()
