import React, { useState } from 'react';
import { SecurityPostureHeader } from './components/SecurityPostureHeader';
import { AttackChainVisualizer } from './components/AttackChainVisualizer';
import { IncidentTable } from './components/IncidentTable';
import { IncidentDetailModal } from './components/IncidentDetailModal';
import { ApprovalModal } from './components/ApprovalModal';
import { IncidentDetail, SecurityPostureSummary, UserRole } from './types';

const INITIAL_SUMMARY: SecurityPostureSummary = {
  posture_score: 82.5,
  critical_findings_count: 1,
  high_findings_count: 1,
  active_incidents_count: 2,
  contained_incidents_count: 14,
  mean_time_to_detect_seconds: 12.4,
  mean_time_to_contain_seconds: 18.6,
  total_protected_accounts: 5,
  total_protected_resources: 142,
  last_updated: new Date().toISOString(),
};

const INITIAL_INCIDENTS: IncidentDetail[] = [
  {
    incident_id: 'INC-2026-0904-001',
    title: 'Cross-Account IAM Lateral Movement to Sensitive Customer PII Vault',
    severity: 'CRITICAL',
    confidence: 0.98,
    risk_score: 94.2,
    risk_level: 'CRITICAL',
    principal_arn: 'arn:aws:iam::333333333333:user/contractor-alice',
    account_id: '333333333333',
    region: 'us-east-1',
    current_state: 'CONTAINING',
    blast_radius_score: 100.0,
    affected_accounts: ['333333333333', '111111111111'],
    affected_resources: [
      'arn:aws:s3:::prod-customer-pii-vault',
      'arn:aws:secretsmanager:us-east-1:111111111111:secret:prod-db-master-creds',
      'arn:aws:rds:us-east-1:111111111111:db:prod-core-aurora',
    ],
    attack_chain_nodes: [
      { id: '1', label: 'contractor-alice', node_type: 'USER', account_id: '333333333333', is_compromised: true, criticality: 2.0 },
      { id: '2', label: 'DevEngineer', node_type: 'ROLE', account_id: '333333333333', criticality: 3.0 },
      { id: '3', label: 'CrossAccountProdReader', node_type: 'ROLE', account_id: '111111111111', criticality: 7.0 },
      { id: '4', label: 'prod-customer-pii-vault', node_type: 'S3_BUCKET', account_id: '111111111111', is_sensitive: true, criticality: 9.5 },
    ],
    attack_chain_edges: [
      { source: '1', target: '2', relationship: 'ASSUME_ROLE' },
      { source: '2', target: '3', relationship: 'ASSUME_ROLE' },
      { source: '3', target: '4', relationship: 'CAN_ACCESS' },
    ],
    timeline: [],
    evidence_manifest_id: 'manifest-4a81bc20',
    response_action: 'REVOKE_IAM_SESSIONS',
    verification_status: true,
    created_at: new Date().toISOString(),
  },
  {
    incident_id: 'INC-2026-0904-002',
    title: 'Dangerous Security Group Ingress 0.0.0.0/0 on SSH Port 22',
    severity: 'HIGH',
    confidence: 1.0,
    risk_score: 68.5,
    risk_level: 'HIGH',
    principal_arn: 'arn:aws:iam::111111111111:role/CI-CD-Deployer',
    account_id: '111111111111',
    region: 'us-east-1',
    current_state: 'VERIFIED',
    blast_radius_score: 45.0,
    affected_accounts: ['111111111111'],
    affected_resources: ['i-0123456789abcdef0'],
    attack_chain_nodes: [
      { id: '10', label: 'CI-CD-Deployer', node_type: 'ROLE', account_id: '111111111111', criticality: 4.0 },
      { id: '11', label: 'i-0123456789abcdef0', node_type: 'EC2_INSTANCE', account_id: '111111111111', criticality: 5.0 },
    ],
    attack_chain_edges: [{ source: '10', target: '11', relationship: 'CAN_ACCESS' }],
    timeline: [],
    response_action: 'ISOLATE_EC2_INSTANCE',
    verification_status: true,
    created_at: new Date().toISOString(),
  },
];

export const App: React.FC = () => {
  const [summary] = useState<SecurityPostureSummary>(INITIAL_SUMMARY);
  const [incidents, setIncidents] = useState<IncidentDetail[]>(INITIAL_INCIDENTS);
  const [selectedIncident, setSelectedIncident] = useState<IncidentDetail | null>(null);
  const [approvalTarget, setApprovalTarget] = useState<IncidentDetail | null>(null);
  const [focusedAttackChain, setFocusedAttackChain] = useState<IncidentDetail>(INITIAL_INCIDENTS[0]);

  const handleConfirmApproval = (
    incidentId: string,
    action: string,
    role: UserRole,
    rationale: string,
    mfa: string
  ) => {
    alert(`Containment Authorized for ${incidentId} by ${role}! Token generated and dispatched to AWS Step Functions.`);
    setIncidents((prev) =>
      prev.map((inc) =>
        inc.incident_id === incidentId ? { ...inc, current_state: 'VERIFIED' as const } : inc
      )
    );
  };

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#020617', fontFamily: 'system-ui, -apple-system, sans-serif' }}>
      <SecurityPostureHeader summary={summary} />

      <main style={{ maxWidth: '1400px', margin: '0 auto', padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        <AttackChainVisualizer
          nodes={focusedAttackChain.attack_chain_nodes}
          currentState={focusedAttackChain.current_state}
          blastRadiusScore={focusedAttackChain.blast_radius_score}
        />

        <IncidentTable
          incidents={incidents}
          onSelectIncident={(inc) => {
            setSelectedIncident(inc);
            setFocusedAttackChain(inc);
          }}
          onOpenApproval={(inc) => setApprovalTarget(inc)}
        />
      </main>

      <IncidentDetailModal
        incident={selectedIncident}
        onClose={() => setSelectedIncident(null)}
      />

      <ApprovalModal
        incident={approvalTarget}
        onClose={() => setApprovalTarget(null)}
        onConfirmApproval={handleConfirmApproval}
      />
    </div>
  );
};
