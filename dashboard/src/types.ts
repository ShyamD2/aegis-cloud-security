/**
 * Project AEGIS - SOC War Room TypeScript Interfaces
 */

export type FindingSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type IncidentState = 'DETECTED' | 'ANALYZING' | 'CONTAINING' | 'VERIFIED' | 'CLOSED';
export type UserRole = 'SOC_VIEWER' | 'SOC_ANALYST' | 'SOC_LEAD' | 'SECURITY_ADMIN';

export interface SecurityPostureSummary {
  posture_score: number;
  critical_findings_count: number;
  high_findings_count: number;
  active_incidents_count: number;
  contained_incidents_count: number;
  mean_time_to_detect_seconds: number;
  mean_time_to_contain_seconds: number;
  total_protected_accounts: number;
  total_protected_resources: number;
  last_updated: string;
}

export interface AttackChainNode {
  id: string;
  label: string;
  node_type: string;
  account_id: string;
  is_compromised?: boolean;
  is_sensitive?: boolean;
  criticality: number;
}

export interface AttackChainEdge {
  source: string;
  target: string;
  relationship: string;
  action?: string;
}

export interface TimelineEvent {
  stage: string;
  timestamp: string;
  summary: string;
  actor: string;
  target_resource: string;
  evidence_id: string;
}

export interface IncidentDetail {
  incident_id: string;
  title: string;
  severity: FindingSeverity;
  confidence: number;
  risk_score: number;
  risk_level: string;
  principal_arn: string;
  account_id: string;
  region: string;
  current_state: IncidentState;
  blast_radius_score: number;
  affected_accounts: string[];
  affected_resources: string[];
  attack_chain_nodes: AttackChainNode[];
  attack_chain_edges: AttackChainEdge[];
  timeline: TimelineEvent[];
  evidence_manifest_id?: string;
  response_action?: string;
  verification_status: boolean;
  created_at: string;
}

export interface ApprovalActionRequest {
  incident_id: string;
  action: string;
  operator_role: UserRole;
  operator_id: string;
  decision: 'APPROVE' | 'REJECT';
  rationale: string;
  mfa_code?: string;
}

export interface ApprovalActionResponse {
  approval_id: string;
  incident_id: string;
  approved: boolean;
  status: string;
  approval_token?: string;
  timestamp: string;
}
