import React from 'react';
import { SecurityPostureSummary } from '../types';

interface HeaderProps {
  summary: SecurityPostureSummary;
}

export const SecurityPostureHeader: React.FC<HeaderProps> = ({ summary }) => {
  const getScoreColor = (score: number) => {
    if (score >= 80) return '#10b981'; // Green
    if (score >= 60) return '#f59e0b'; // Amber
    return '#ef4444'; // Red
  };

  return (
    <header style={{ backgroundColor: '#0f172a', borderBottom: '1px solid #334155', padding: '1.25rem 2rem', color: '#f8fafc' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '0.05em', color: '#38bdf8' }}>PROJECT AEGIS</span>
            <span style={{ backgroundColor: '#1e293b', border: '1px solid #475569', borderRadius: '4px', padding: '0.2rem 0.5rem', fontSize: '0.75rem', fontWeight: 600 }}>
              SECURITY OPERATIONS WAR ROOM
            </span>
          </div>
          <p style={{ margin: '0.25rem 0 0 0', color: '#94a3b8', fontSize: '0.875rem' }}>
            Autonomous AWS Cloud Defense, Attack-Path Analysis & Self-Healing Security Fabric
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
          {/* Posture Score Ring */}
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: getScoreColor(summary.posture_score) }}>
              {summary.posture_score}<span style={{ fontSize: '1rem', color: '#64748b' }}>/100</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Posture Score</div>
          </div>

          {/* Active Counters */}
          <div style={{ display: 'flex', gap: '1rem' }}>
            <div style={{ backgroundColor: '#1e293b', padding: '0.5rem 0.75rem', borderRadius: '6px', textAlign: 'center', borderLeft: '4px solid #ef4444' }}>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#f87171' }}>{summary.critical_findings_count}</div>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Critical</div>
            </div>
            <div style={{ backgroundColor: '#1e293b', padding: '0.5rem 0.75rem', borderRadius: '6px', textAlign: 'center', borderLeft: '4px solid #f97316' }}>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#fb923c' }}>{summary.high_findings_count}</div>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>High</div>
            </div>
            <div style={{ backgroundColor: '#1e293b', padding: '0.5rem 0.75rem', borderRadius: '6px', textAlign: 'center', borderLeft: '4px solid #38bdf8' }}>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#38bdf8' }}>{summary.active_incidents_count}</div>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Active Incidents</div>
            </div>
          </div>

          {/* Latency SLAs */}
          <div style={{ borderLeft: '1px solid #334155', paddingLeft: '1.5rem', fontSize: '0.8rem', color: '#cbd5e1' }}>
            <div>MTTD: <strong style={{ color: '#38bdf8' }}>{summary.mean_time_to_detect_seconds}s</strong></div>
            <div>MTTC: <strong style={{ color: '#10b981' }}>{summary.mean_time_to_contain_seconds}s</strong></div>
            <div style={{ color: '#64748b', fontSize: '0.75rem' }}>Protected Accounts: {summary.total_protected_accounts}</div>
          </div>
        </div>
      </div>
    </header>
  );
};
