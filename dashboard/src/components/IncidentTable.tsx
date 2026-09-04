import React from 'react';
import { IncidentDetail } from '../types';

interface TableProps {
  incidents: IncidentDetail[];
  onSelectIncident: (incident: IncidentDetail) => void;
  onOpenApproval: (incident: IncidentDetail) => void;
}

export const IncidentTable: React.FC<TableProps> = ({
  incidents,
  onSelectIncident,
  onOpenApproval,
}) => {
  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return { bg: '#450a0a', text: '#f87171', border: '#b91c1c' };
      case 'HIGH':
        return { bg: '#431407', text: '#fb923c', border: '#c2410c' };
      case 'MEDIUM':
        return { bg: '#422006', text: '#facc15', border: '#a16207' };
      default:
        return { bg: '#064e3b', text: '#34d399', border: '#047857' };
    }
  };

  return (
    <div style={{ backgroundColor: '#1e293b', borderRadius: '8px', border: '1px solid #334155', overflow: 'hidden', color: '#f8fafc' }}>
      <div style={{ padding: '1rem 1.5rem', borderBottom: '1px solid #334155', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3 style={{ margin: 0, fontSize: '1.1rem' }}>Active Security Incidents</h3>
        <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Total Incidents: {incidents.length}</span>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
          <thead>
            <tr style={{ backgroundColor: '#0f172a', borderBottom: '1px solid #334155', color: '#94a3b8', textTransform: 'uppercase', fontSize: '0.75rem' }}>
              <th style={{ padding: '0.75rem 1rem' }}>Incident ID</th>
              <th style={{ padding: '0.75rem 1rem' }}>Title & Principal</th>
              <th style={{ padding: '0.75rem 1rem' }}>Severity</th>
              <th style={{ padding: '0.75rem 1rem' }}>Risk Score</th>
              <th style={{ padding: '0.75rem 1rem' }}>Account / Region</th>
              <th style={{ padding: '0.75rem 1rem' }}>State</th>
              <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((inc) => {
              const badge = getSeverityBadge(inc.severity);
              return (
                <tr
                  key={inc.incident_id}
                  style={{ borderBottom: '1px solid #334155', cursor: 'pointer' }}
                  onClick={() => onSelectIncident(inc)}
                >
                  <td style={{ padding: '0.875rem 1rem', fontFamily: 'monospace', fontWeight: 600, color: '#38bdf8' }}>
                    {inc.incident_id}
                  </td>
                  <td style={{ padding: '0.875rem 1rem' }}>
                    <div style={{ fontWeight: 600, color: '#f1f5f9' }}>{inc.title}</div>
                    <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.2rem' }}>
                      {inc.principal_arn}
                    </div>
                  </td>
                  <td style={{ padding: '0.875rem 1rem' }}>
                    <span
                      style={{
                        backgroundColor: badge.bg,
                        color: badge.text,
                        border: `1px solid ${badge.border}`,
                        padding: '0.2rem 0.5rem',
                        borderRadius: '4px',
                        fontSize: '0.7rem',
                        fontWeight: 700,
                      }}
                    >
                      {inc.severity}
                    </span>
                  </td>
                  <td style={{ padding: '0.875rem 1rem' }}>
                    <span style={{ fontWeight: 700, color: inc.risk_score >= 75 ? '#ef4444' : '#f59e0b' }}>
                      {inc.risk_score}
                    </span>
                    <span style={{ fontSize: '0.75rem', color: '#64748b' }}>/100</span>
                  </td>
                  <td style={{ padding: '0.875rem 1rem', fontSize: '0.8rem' }}>
                    <div>{inc.account_id}</div>
                    <div style={{ color: '#64748b' }}>{inc.region}</div>
                  </td>
                  <td style={{ padding: '0.875rem 1rem' }}>
                    <span style={{ backgroundColor: '#0f172a', padding: '0.25rem 0.6rem', borderRadius: '4px', border: '1px solid #475569', fontSize: '0.75rem' }}>
                      {inc.current_state}
                    </span>
                  </td>
                  <td style={{ padding: '0.875rem 1rem', textAlign: 'right' }}>
                    <button
                      style={{
                        backgroundColor: '#0284c7',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px',
                        padding: '0.35rem 0.75rem',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        cursor: 'pointer',
                        marginRight: '0.5rem',
                      }}
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectIncident(inc);
                      }}
                    >
                      Inspect
                    </button>
                    {inc.risk_score >= 50 && (
                      <button
                        style={{
                          backgroundColor: '#b91c1c',
                          color: 'white',
                          border: 'none',
                          borderRadius: '4px',
                          padding: '0.35rem 0.75rem',
                          fontSize: '0.75rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                        }}
                        onClick={(e) => {
                          e.stopPropagation();
                          onOpenApproval(inc);
                        }}
                      >
                        Contain
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
