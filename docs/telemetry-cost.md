# AEGIS Telemetry Cost Optimization Model
## Minimizing Logging Overhead While Maximizing Security Visibility

### 1. Cost Traps in Cloud Security Logging

Uncontrolled AWS telemetry ingestion can quickly become the single largest line-item on an AWS bill:
- **CloudTrail Data Events**: Enabling data events on all S3 buckets (e.g. `GetObject` on static asset buckets) can generate billions of events per day, costing thousands of dollars for zero security benefit.
- **VPC Flow Logs**: Full VPC Flow Logs on public NAT gateways with 1-minute aggregation can generate hundreds of gigabytes per day.
- **Cross-Region Data Transfer**: Forwarding telemetry across AWS regions incurs inter-region transfer charges (\$0.02/GB).

---

### 2. AEGIS Cost Guardrail Strategies

1. **Selective Data Events**: AEGIS restricts CloudTrail data events strictly to sensitive infrastructure (e.g., S3 buckets containing database backups, encryption keys, or security logs). Standard application buckets use management events only.
2. **S3 Intelligent-Tiering**: All telemetry buckets transition objects to Intelligent-Tiering at day 30, eliminating manual tier management while cutting cold storage costs by 40-60%.
3. **Parquet Compression for VPC Flow Logs**: VPC Flow Logs are delivered in Apache Parquet format partitioned by date (`year=YYYY/month=MM/day=DD/`), reducing storage volume and Athena query scan costs by up to 85%.
4. **VPC Flow Log Filtering**: In non-production and lab environments, flow logs are filtered to `REJECT` traffic only or scoped strictly to security subnets.

---

### 3. Estimated Telemetry Costs

| Component | Portfolio / Lab Mode (1-5 Accounts) | Medium Production (10-50 Accounts) | Enterprise Production (100+ Accounts) |
|---|---|---|---|
| **CloudTrail Management Events** | Free (first copy) | Free (first copy) | Free (first copy) |
| **CloudTrail S3 Data Events** | ~$1.50 / month | ~$35 / month | ~$250 / month |
| **VPC Flow Logs Storage (Parquet)**| ~$2.00 / month | ~$45 / month | ~$400 / month |
| **Route 53 Resolver Logs** | ~$0.80 / month | ~$20 / month | ~$150 / month |
| **KMS Request Costs** | ~$1.00 / month | ~$15 / month | ~$80 / month |
| **Total Monthly Cost** | **< $6.00 / month** | **~$115 / month** | **~$880 / month** |
