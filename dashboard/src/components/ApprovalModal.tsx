import React, { useState } from 'react';
import { IncidentDetail, UserRole } from '../types';

interface ApprovalProps {
  incident: IncidentDetail | null;
  onClose: () => void;
  onConfirmApproval: (incidentId: string, action: string, role: UserRole, rationale: string, mfa: string) => void;
}

export const ApprovalModal: React.FC<ApprovalProps> = ({ incident, onClose, onConfirmApproval }) => {
  const [role, setRole] = useState<UserRole>('SOC_LEAD');
  const [rationale, setRationale] = useState('');
  const [mfaCode, setMfaCode] = useState('');

  if (!incident) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!rationale.trim() || !mfaCode.trim()) {
      alert('Rationale and MFA code are required.');
      return;
    }
    onConfirmApproval(incident.incident_id, incident.response_action || 'REVOKE_IAM_SESSIONS', role, rationale, mfaCode);
    onClose();
  };

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        padding: '1.5rem',
      }}
      onClick={onClose}
    >
      <div
        style={{
          backgroundColor: '#0f172a',
          border: '1.5px solid #ef4444',
          borderRadius: '8px',
          width: '100%',
          maxWidth: '550px',
          padding: '2rem',
          color: '#f8fafc',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <h3 style={{ color: '#f87171', margin: '0 0 0.5rem 0' }}>Authorize Autonomous Containment</h3>
        <p style={{ fontSize: '0.85rem', color: '#94a3b8', margin: '0 0 1.5rem 0' }}>
          Authorizing containment will trigger targeted AWS Step Functions remediation against principal <code style={{ color: '#38bdf8' }}>{incident.principal_arn}</code>.
        </p>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', color: '#cbd5e1', marginBottom: '0.3rem' }}>Operator Role:</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as UserRole)}
              style={{ width: '100%', backgroundColor: '#1e293b', border: '1px solid #475569', color: '#f8fafc', padding: '0.5rem', borderRadius: '4px' }}
            >
              <option value="SOC_LEAD">SOC_LEAD (Authorized for Critical Containment)</option>
              <option value="SECURITY_ADMIN">SECURITY_ADMIN (Full Authority)</option>
              <option value="SOC_ANALYST">SOC_ANALYST (Triage Only)</option>
            </select>
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', color: '#cbd5e1', marginBottom: '0.3rem' }}>Operational Rationale:</label>
            <textarea
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
              placeholder="State justification for containment (e.g. Confirmed lateral movement into prod DB)"
              rows={3}
              style={{ width: '100%', backgroundColor: '#1e293b', border: '1px solid #475569', color: '#f8fafc', padding: '0.5rem', borderRadius: '4px' }}
            />
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', color: '#cbd5e1', marginBottom: '0.3rem' }}>Cognito Hardware/Virtual MFA Token (6-digit):</label>
            <input
              type="text"
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value)}
              placeholder="123456"
              maxLength={6}
              style={{ width: '100%', backgroundColor: '#1e293b', border: '1px solid #475569', color: '#f8fafc', padding: '0.5rem', borderRadius: '4px', letterSpacing: '0.2em', fontFamily: 'monospace' }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
            <button
              type="button"
              onClick={onClose}
              style={{ backgroundColor: '#334155', color: '#cbd5e1', border: 'none', padding: '0.5rem 1rem', borderRadius: '4px', cursor: 'pointer' }}
            >
              Cancel
            </button>
            <button
              type="submit"
              style={{ backgroundColor: '#b91c1c', color: 'white', border: 'none', padding: '0.5rem 1rem', borderRadius: '4px', fontWeight: 600, cursor: 'pointer' }}
            >
              Sign & Authorize
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
