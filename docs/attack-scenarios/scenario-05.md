# SCENARIO-05: Dangerous Security Group Modification

### 1. Scenario ID
`SCENARIO-05`

### 2. Threat Model
- **MITRE ATT&CK**: T1046 (Network Service Discovery) & T1190 (Exploit Public-Facing Application)
- **Threat Actor**: Attacker attempting to open administrative ports (SSH 22 or RDP 3389) to `0.0.0.0/0` on compute instances.

### 3. Prerequisites
- Target security group `sg-bastion-exposed` and compute instance `i-bastion-01`.

### 4. Simulation
`ec2:AuthorizeSecurityGroupIngress` called with CIDR `0.0.0.0/0` on port 22.

### 5. Expected Telemetry
CloudTrail record with `eventSource`: `ec2.amazonaws.com`, `eventName`: `AuthorizeSecurityGroupIngress`, `fromPort: 22`, `cidrIp: 0.0.0.0/0`.

### 6. Expected Detection
- **Detection Rule**: `AEGIS-005` (Security-Group Dangerous Ingress Modification)
- **Severity**: `CRITICAL`
- **Confidence**: `0.95`

### 7. Expected Correlation
Identifies internet exposure on compute node connected to internal VPC subnets.

### 8. Expected Risk
- **Risk Score**: `88.0` (`CRITICAL`)
- **Primary Drivers**: Unrestricted Public Ingress, Port 22 Exposure.

### 9. Expected Blast Radius
- **Blast Score**: `65.0 / 100`

### 10. Expected Response
`EC2Remediator` isolates the instance by attaching quarantine security group with zero ingress/egress.

### 11. Expected Verification
Verification validates instance has only the quarantine security group attached.

### 12. Cleanup
Rollback restores original security groups.
