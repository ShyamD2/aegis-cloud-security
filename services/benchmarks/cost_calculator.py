"""
Project AEGIS - FinOps Cloud Cost Modeling Engine
Computes granular monthly AWS expenditure estimates across Small, Medium, and High enterprise
traffic tiers based on real AWS pricing dimensions.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class CostTier(StrEnum):
    """Standardized enterprise scale tiers for Project AEGIS telemetry."""

    SMALL_STARTUP = "SMALL_STARTUP"  # 1 Million events / month (~0.4 events/sec)
    MEDIUM_ENTERPRISE = "MEDIUM_ENTERPRISE"  # 50 Million events / month (~20 events/sec)
    LARGE_HYPERSCALE = "LARGE_HYPERSCALE"  # 500 Million events / month (~200 events/sec)


class CostEstimate(BaseModel):
    """Detailed AWS monthly cost breakdown for an operational tier."""

    model_config = ConfigDict(extra="forbid")

    tier: CostTier
    monthly_events: int
    kinesis_cost: float
    lambda_cost: float
    dynamodb_cost: float
    s3_storage_cost: float
    neptune_serverless_cost: float
    sagemaker_serverless_cost: float
    sqs_eventbridge_cost: float
    kms_cost: float
    total_monthly_usd: float
    cost_per_million_events: float
    component_percentages: dict[str, float]


class FinOpsCostCalculator:
    """
    Mathematical cloud cost model for Project AEGIS infrastructure based on AWS US East (N. Virginia)
    published pricing dimensions.
    """

    # AWS Pricing Baselines (us-east-1)
    KINESIS_SHARD_HOUR_USD = 0.015  # per shard-hour (~$10.80/month/shard)
    KINESIS_PUT_UNIT_USD = 0.014 / 1_000_000  # per 25KB PUT payload unit
    LAMBDA_PER_REQ_USD = 0.20 / 1_000_000  # $0.20 per 1M invocations
    LAMBDA_GB_SEC_USD = 0.0000166667  # x86 architecture per GB-second
    DYNAMODB_WRITE_RRU_USD = 1.25 / 1_000_000  # per million write request units
    DYNAMODB_READ_RRU_USD = 0.25 / 1_000_000  # per million read request units
    S3_STANDARD_PER_GB_USD = 0.023  # per GB-month
    S3_PUT_PER_1K_USD = 0.005 / 1000  # per PUT request
    NEPTUNE_NCU_HOUR_USD = 0.10  # per Neptune Capacity Unit (NCU) hour
    SAGEMAKER_SERVERLESS_USD_PER_SEC = 0.000020  # per 1GB-second serverless inference
    EVENTBRIDGE_CUSTOM_PER_M_USD = 1.00 / 1_000_000  # per million custom events
    KMS_KEY_MONTH_USD = 1.00  # per customer managed KMS key
    KMS_API_PER_10K_USD = 0.03 / 10_000  # per KMS decrypt/encrypt call

    @classmethod
    def calculate_tier_cost(cls, tier: CostTier) -> CostEstimate:
        """Calculate complete monthly infrastructure expenditure for a given scale tier."""
        if tier == CostTier.SMALL_STARTUP:
            events = 1_000_000
            shards = 1
            lambda_avg_ms = 45.0
            lambda_memory_mb = 512
            avg_event_size_kb = 2.0
            neptune_avg_ncus = 0.5  # scaled down min baseline
            sagemaker_inferences = 10_000  # only scored anomalies
            kms_keys = 3
        elif tier == CostTier.MEDIUM_ENTERPRISE:
            events = 50_000_000
            shards = 4
            lambda_avg_ms = 50.0
            lambda_memory_mb = 512
            avg_event_size_kb = 2.5
            neptune_avg_ncus = 2.5
            sagemaker_inferences = 250_000
            kms_keys = 5
        else:  # LARGE_HYPERSCALE
            events = 500_000_000
            shards = 20
            lambda_avg_ms = 60.0
            lambda_memory_mb = 1024
            avg_event_size_kb = 2.5
            neptune_avg_ncus = 8.0
            sagemaker_inferences = 2_500_000
            kms_keys = 8

        hours_per_month = 730.0

        # 1. Kinesis Data Streams
        kinesis_shards = shards * cls.KINESIS_SHARD_HOUR_USD * hours_per_month
        kinesis_puts = events * cls.KINESIS_PUT_UNIT_USD
        kinesis_cost = kinesis_shards + kinesis_puts

        # 2. AWS Lambda
        lambda_invocations = events * cls.LAMBDA_PER_REQ_USD
        gb_seconds = events * (lambda_avg_ms / 1000.0) * (lambda_memory_mb / 1024.0)
        lambda_compute = gb_seconds * cls.LAMBDA_GB_SEC_USD
        lambda_cost = lambda_invocations + lambda_compute

        # 3. DynamoDB (Idempotency + State)
        # 1 write + 1 read per ingested event
        dynamo_writes = events * cls.DYNAMODB_WRITE_RRU_USD
        dynamo_reads = events * cls.DYNAMODB_READ_RRU_USD
        dynamodb_cost = dynamo_writes + dynamo_reads

        # 4. Amazon S3 Storage (Compressed JSON gzip ~85% ratio)
        compressed_gb = (events * avg_event_size_kb * 0.15) / (1024.0 * 1024.0)
        s3_storage = compressed_gb * cls.S3_STANDARD_PER_GB_USD
        s3_api = events * cls.S3_PUT_PER_1K_USD
        s3_cost = s3_storage + s3_api

        # 5. Neptune Serverless
        neptune_cost = neptune_avg_ncus * cls.NEPTUNE_NCU_HOUR_USD * hours_per_month

        # 6. SageMaker Serverless Inference
        sagemaker_cost = sagemaker_inferences * 0.10 * cls.SAGEMAKER_SERVERLESS_USD_PER_SEC

        # 7. SQS & EventBridge
        eventbridge_cost = events * cls.EVENTBRIDGE_CUSTOM_PER_M_USD

        # 8. AWS KMS
        kms_fixed = kms_keys * cls.KMS_KEY_MONTH_USD
        kms_calls = events * cls.KMS_API_PER_10K_USD
        kms_cost = kms_fixed + kms_calls

        total_usd = (
            kinesis_cost
            + lambda_cost
            + dynamodb_cost
            + s3_cost
            + neptune_cost
            + sagemaker_cost
            + eventbridge_cost
            + kms_cost
        )

        cost_per_m = (total_usd / events) * 1_000_000

        percentages = {
            "kinesis": round((kinesis_cost / total_usd) * 100, 2),
            "lambda": round((lambda_cost / total_usd) * 100, 2),
            "dynamodb": round((dynamodb_cost / total_usd) * 100, 2),
            "s3": round((s3_cost / total_usd) * 100, 2),
            "neptune": round((neptune_cost / total_usd) * 100, 2),
            "sagemaker": round((sagemaker_cost / total_usd) * 100, 2),
            "eventbridge": round((eventbridge_cost / total_usd) * 100, 2),
            "kms": round((kms_cost / total_usd) * 100, 2),
        }

        return CostEstimate(
            tier=tier,
            monthly_events=events,
            kinesis_cost=round(kinesis_cost, 2),
            lambda_cost=round(lambda_cost, 2),
            dynamodb_cost=round(dynamodb_cost, 2),
            s3_storage_cost=round(s3_cost, 2),
            neptune_serverless_cost=round(neptune_cost, 2),
            sagemaker_serverless_cost=round(sagemaker_cost, 2),
            sqs_eventbridge_cost=round(eventbridge_cost, 2),
            kms_cost=round(kms_cost, 2),
            total_monthly_usd=round(total_usd, 2),
            cost_per_million_events=round(cost_per_m, 3),
            component_percentages=percentages,
        )
