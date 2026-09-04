# Security Operations War Room
## Project AEGIS - Phase 12 Architecture & Technical Specification

```
                   ┌─────────────────────────────────────────┐
                   │    SOC Responder (Web Browser)          │
                   └────────────────────┬────────────────────┘
                                        │ HTTPS / TLS 1.3
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │      Amazon CloudFront CDN              │
                   │    (AWS WAF + Origin Access Control)    │
                   └────────────────────┬────────────────────┘
                                        │
             ┌──────────────────────────┴──────────────────────────┐
             ▼                                                     ▼
┌─────────────────────────┐                               ┌─────────────────────────┐
│  S3 Static Hosting      │                               │ Amazon Cognito          │
│  (React + TypeScript)   │                               │ User Pool (MFA / SRP)   │
└─────────────────────────┘                               └────────────┬────────────┘
                                                                       │ JWT Bearer Token
                                                                       ▼
                                                          ┌─────────────────────────┐
                                                          │ API Gateway HTTP API    │
                                                          │ (JWT Authorizer)        │
                                                          └────────────┬────────────┘
                                                                       │
                                                                       ▼
                                                          ┌─────────────────────────┐
                                                          │  AEGIS War Room Lambda  │
                                                          │  - RBAC Enforcement     │
                                                          │  - Neptune Graph Query  │
                                                          │  - SFN Containment Gate │
                                                          └─────────────────────────┘
```

---

### 1. Zero-Credential Architecture & Browser Security

> [!IMPORTANT]
> **No AWS access keys, secret keys, or long-lived credentials ever touch the browser.**
>
> 1. Authentication executes via **Amazon Cognito** using the Secure Remote Password (SRP) protocol. Passwords are never transmitted in cleartext.
> 2. The client receives short-lived (60-minute) OIDC JWT tokens (`IdToken` and `AccessToken`).
> 3. All API Gateway requests include `Authorization: Bearer <JWT>`. The gateway validates the signature against Cognito's JWKS endpoint before dispatching to backend Lambda handlers.
> 4. Backend Lambdas assume short-lived, least-privilege IAM roles to interact with DynamoDB, Neptune, or Step Functions.

---

### 2. Role-Based Access Control (RBAC) Matrix

| Action | `SOC_VIEWER` | `SOC_ANALYST` | `SOC_LEAD` | `SECURITY_ADMIN` |
| :--- | :---: | :---: | :---: | :---: |
| View Posture Score & Incidents | ✅ | ✅ | ✅ | ✅ |
| Inspect Graph Attack Paths & Blast Radius | ✅ | ✅ | ✅ | ✅ |
| Retrieve Forensics Evidence Manifest | ❌ | ✅ | ✅ | ✅ |
| Initiate Targeted Containment (Risk < 75) | ❌ | ✅ | ✅ | ✅ |
| **Authorize Critical Containment (Risk >= 75)**| ❌ | ❌ | ✅ *(MFA Req.)* | ✅ *(MFA Req.)* |
| **Authorize Account Quarantine** | ❌ | ❌ | ✅ *(MFA Req.)* | ✅ *(MFA Req.)* |

---

### 3. Attack Chain Visualizer Specification

The War Room dashboard renders dynamic attack-chain representations:
```
[User: contractor-alice] ──(sts:AssumeRole)──► [Role: DevEngineer]
                                                      │
                                               (sts:AssumeRole)
                                                      │
                                                      ▼
[S3: prod-customer-pii-vault] ◄──(s3:GetObject)─── [Role: CrossAccountProdReader]
   (CRITICAL SENSITIVE)                                (Account: 111111111111)
```

#### Incident Progression Stages:
1. `DETECTED`: Initial alert flagged by rule engine or GuardDuty.
2. `ANALYZING`: Attack graph compiled, blast radius quantified, SageMaker anomaly evaluated.
3. `CONTAINING`: Step Functions executing specialized remediator or awaiting SOC lead approval.
4. `VERIFIED`: Post-action inspection confirmed containment active; incident evidence sealed.
