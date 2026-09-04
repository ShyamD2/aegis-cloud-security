# AEGIS Real-Time Security Event Pipeline
## Resilient Streaming Architecture, Latency Benchmarking & Failure Handling

### 1. Streaming Pipeline Topology

The AEGIS real-time pipeline connects raw multi-account telemetry sources into a high-throughput, failure-safe ingestion and detection stream:

```mermaid
flowchart LR
    Telemetry["Multi-Account Telemetry\n(CloudTrail, VPC Flow, DNS)"] --> Kinesis["Amazon Kinesis Data Stream\n(aegis-security-events)"]
    Kinesis --> Lambda["Event Processing Lambda\n(services/pipeline/processor.py)"]
    
    Lambda -->|Unrecoverable Errors (3 Retries)| SQS_DLQ["Amazon SQS Dead Letter Queue\n(aegis-pipeline-dlq)"]
    Lambda --> Idempotency["DynamoDB Idempotency Cache\n(Duplicate Drop)"]
    Lambda --> DetEngine["AEGIS Detection Engine"]
    DetEngine --> EventBridge["Amazon EventBridge Bus\n(aegis-findings-bus)"]
    
    subgraph Latency["Measured Latency Milestones"]
        T1["T0: event_received"] --> T2["T1: processing_started"]
        T2 --> T3["T2: finding_created"]
        T3 --> T4["T3: processing_completed"]
    end
```

---

### 2. Resilience & Reliability Requirements

1. **Correlation IDs**: Every event entering the pipeline is assigned a UUIDv4 `correlation_id` (or inherits existing `requestID`), which is propagated through normalization, detection, findings, and DLQ errors for complete traceability.
2. **Idempotency & Duplicate Suppression**: Events are fingerprinted using SHA-256 (`account_id:event_id`). Repeated deliveries from Kinesis or EventBridge within a 15-minute window are detected and dropped.
3. **Dead-Letter Handling (DLQ)**: If an unhandled exception or malformed payload is encountered:
   - Event source mapping uses `bisect_batch_on_function_error = true`.
   - Max retry attempts = 3 with exponential backoff.
   - Unrecoverable events are published to SQS DLQ with full stack trace and error metadata.
4. **Out-of-Order Handling**: Network streams can deliver events out of order. AEGIS parses the authoritative event timestamp (`eventTime`) rather than ingestion arrival time, sorting sequence evaluation buffers chronologically.

---

### 3. Latency Measurement Model

AEGIS measures execution time across 4 explicit milestones:
- `event_received_at`: Timestamp when the batch arrived at the ingestion worker.
- `processing_started_at`: Timestamp when record deserialization began.
- `finding_created_at`: Timestamp when a detection rule or finding was emitted.
- `processing_completed_at`: Timestamp when the finding was dispatched to EventBridge.

Processing Latency is calculated across batches:
- **p50 (Median)**: Expected typical processing time under normal load.
- **p95**: 95th percentile latency accounting for cold starts or JSON deserialization spikes.
- **p99**: Worst-case tail latency.

> [!NOTE]
> AEGIS reports only real, measured benchmark numbers from unit and lab test runs. Sub-second processing claims are verified with empirical benchmarks.
