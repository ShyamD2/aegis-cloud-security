import React from 'react';
import { IncidentDetail } from '../types';

interface ModalProps {
  incident: IncidentDetail | null;
  onClose: () => void;
}

export const IncidentDetailModal: React.FC<ModalProps> = ({ incident, onClose }) => {
  if (!incident) return null;

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.75)',
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
          border: '1px solid #334155',
          borderRadius: '8px',
          width: '100%',
          maxWidth: '850px',
          maxHeight: '90vh',
          overflowY: 'auto',
          padding: '2rem',
          color: '#f8fafc',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <span style={{ fontFamily: 'monospace', color: '#38bdf8', fontSize: '0.85rem' }}>{incident.incident_id}</span>
            <h2 style={{ margin: '0.25rem 0', fontSize: '1.4rem' }}>{incident.title}</h2>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: '#94a3b8', fontSize: '1.5rem', cursor: 'pointer' }}
          >
            ✕
          </button>
        </div>

        {/* Key Metrics Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', margin: '1.5rem 0' }}>
          <div style={{ backgroundColor: '#1e293b', padding: '0.75rem', borderRadius: '6px' }}>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Risk Score</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, color: incident.risk_score >= 75 ? '#ef4444' : '#f59e0b' }}>
              {incident.risk_score} / 100
            </div>
          </div>
          <div style={{ backgroundColor: '#1e293b', padding: '0.75rem', borderRadius: '6px' }}>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Blast Radius</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#38bdf8' }}>
              {incident.blast_radius_score} / 100
            </div>
          </div>
          <div style={{ backgroundColor: '#1e293b', padding: '0.75rem', borderRadius: '6px' }}>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Confidence</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#10b981' }}>
              {Math.round(incident.confidence * 100)}%
            </div>
          </div>
          <div style={{ backgroundColor: '#1e293b', padding: '0.75rem', borderRadius: '6px' }}>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>State</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f1f5f9' }}>
              {incident.current_state}
            </div>
          </div>
        </div>

        {/* Affected Scope */}
        <div style={{ marginBottom: '1.5rem' }}>
          <h4 style={{ color: '#cbd5e1', marginBottom: '0.5rem' }}>Affected Resources ({incident.affected_resources.length})</h4>
          <div style={{ backgroundColor: '#1e293b', padding: '0.75rem', borderRadius: '6px', fontSize: '0.85rem' }}>
            {incident.affected_resources.map((res) => (
              <div key={res} style={{ fontFamily: 'monospace', color: '#e2e8f0', margin: '0.25rem 0' }}>• {res}</div>
            ))}
          </div>
        </div>

        {/* Forensic Evidence Manifest ID */}
        {incident.evidence_manifest_id && (
          <div style={{ backgroundColor: '#1e293b', padding: '0.75rem 1rem', borderRadius: '6px', marginBottom: '1.5rem', borderLeft: '4px solid #10b981' }}>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Forensic Vault Object Lock Manifest:</div>
            <div style={{ fontFamily: 'monospace', color: '#34d399', fontWeight: 600 }}>{incident.evidence_manifest_id} (Immutable SHA-256)</div>
          </div>
        )}

        <div style={{ textAlign: 'right' }}>
          <button
            onClick={onClose}
            style={{ backgroundColor: '#334155', color: 'white', border: 'none', borderRadius: '4px', padding: '0.5rem 1rem', cursor: 'pointer' }}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
