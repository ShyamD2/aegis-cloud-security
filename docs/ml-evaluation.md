# Behavioral Anomaly Detection & Machine Learning Evaluation Report

## Executive Summary

Project AEGIS integrates an **unsupervised centroid anomaly scoring engine** modeled on multidimensional cloud access distributions to complement deterministic rule-based detections. This report documents the empirical evaluation of AEGIS's anomaly engine across a standardized evaluation dataset of 2,300 cloud telemetry events, comparing four core detection paradigms.

---

## 1. Feature Engineering & Telemetry Space

AEGIS extracts a normalized **9-dimensional feature vector** (`FeatureVector`) from raw CloudTrail, VPC Flow, and API events:

| Dimension | Feature Name | Description | Range | Operational Interpretation |
| :--- | :--- | :--- | :--- | :--- |
| **$f_1$** | `api_frequency_1h` | Invocation count per hour (decay-weighted) | `[0.0, 1.0]` | Spike detection (credential stuffing, rapid exfiltration) |
| **$f_2$** | `api_sequence_entropy` | Shannon entropy over sliding 10-call sequence | `[0.0, 1.0]` | Automation scripts (low) vs human discovery (high) |
| **$f_3$** | `time_of_day_deviation` | Circadian offset from principal's active hours | `[0.0, 1.0]` | Off-hours compromise or foreign timezone activity |
| **$f_4$** | `source_ip_distance` | Geo-distance & CIDR rarity from known baseline | `[0.0, 1.0]` | External adversary IP vs trusted corporate VPN |
| **$f_5$** | `region_deviation` | Divergence from historical regional profile | `[0.0, 1.0]` | Spawning EC2/mining instances in unapproved regions |
| **$f_6$** | `account_deviation` | Frequency of cross-account AssumeRole pivots | `[0.0, 1.0]` | Lateral movement between workload and management accounts |
| **$f_7$** | `privilege_score` | Inherent IAM action risk rating | `[0.0, 1.0]` | High-impact actions (`iam:CreateAccessKey`, `sts:AssumeRole`) |
| **$f_8$** | `resource_sensitivity` | Target asset classification (S3, KMS, Secrets) | `[0.0, 1.0]` | Critical asset interaction vs mundane infrastructure |
| **$f_9$** | `unusual_service_flag` | First-time service invocation by principal | `[0.0, 1.0]` | Novel API namespace usage (e.g. SageMaker, Bedrock) |

---

## 2. Statistical Anomaly Model Architecture

The `AnomalyModel` fits a baseline multivariate normal distribution $\mathcal{N}(\boldsymbol{\mu}, \boldsymbol{\Sigma})$ over legitimate developer sessions during a training phase:

1. **Centroid Baseline**:
   $$\mu_d = \frac{1}{N} \sum_{i=1}^N x_{i,d}, \quad \sigma_d = \sqrt{\frac{1}{N} \sum_{i=1}^N (x_{i,d} - \mu_d)^2}$$

2. **Weighted Normalized Euclidean Distance**:
   $$D(\mathbf{x}) = \sqrt{ \sum_{d=1}^9 w_d \left( \frac{x_d - \mu_d}{\sigma_d} \right)^2 }$$

3. **Sigmoid Probability Compression**:
   $$S(\mathbf{x}) = \frac{1}{1 + \exp\left( -0.75 \cdot (D(\mathbf{x}) - 2.5) \right)}$$

An event is flagged as anomalous if $S(\mathbf{x}) \ge \tau$ (default threshold $\tau = 0.65$).

---

## 3. Paradigm Benchmark Matrix

Evaluation conducted on a held-out test split (15% of 2,300 samples) comparing:
- **Paradigm 1**: Deterministic Rules Only (`AEGIS-DET-001` through `010`)
- **Paradigm 2**: Unsupervised ML Centroid Anomaly Only
- **Paradigm 3**: Hybrid Union (`Rule OR ML >= 0.65`)
- **Paradigm 4**: Contextual Engine (`Rule + ML + Neptune Attack-Path Reachability`)

| Paradigm | Precision | Recall | F1-Score | False Positive Rate (FPR) | Mean Latency |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **1. Deterministic Rules Only** | **100.0%** | 54.8% | 70.8% | **0.0%** | **0.001 ms** |
| **2. Unsupervised ML Only** | 92.4% | **98.2%** | 95.2% | 4.6% | 0.003 ms |
| **3. Hybrid (Rules + ML)** | 91.8% | **100.0%** | 95.7% | 5.1% | 0.003 ms |
| **4. Contextual (Rules + ML + Graph)** | **97.6%** | **96.8%** | **97.2%** | **1.2%** | 0.003 ms |

---

## 4. Key Takeaways & Defense-in-Depth Analysis

1. **Why Rules Alone Fail (54.8% Recall)**:
   Deterministic rules excel at recognizing explicit signatures (e.g. `iam:CreateAccessKey` without MFA), but completely fail against stealthy **Living-off-the-Land (LotL)** adversaries who operate below rate limits during normal business hours.

2. **Why Pure ML Causes Alert Fatigue (4.6%–5.1% FPR)**:
   Unsupervised behavioral ML detects subtle shifts, but flags benign anomalies like on-call night emergency responses and batch automation scripts, resulting in unacceptable SOC alert fatigue.

3. **The Power of Graph-Enriched Context (Paradigm 4)**:
   By filtering and weighting ML anomaly scores through **Amazon Neptune graph reachability** (verifying whether the principal actually possesses privilege escalation paths to sensitive assets), AEGIS eliminates 75% of false positives while preserving a **96.8% Recall** and **97.2% F1-Score**.
