import React from 'react';
import { AttackChainNode, IncidentState } from '../types';

interface VisualizerProps {
  nodes: AttackChainNode[];
  currentState: IncidentState;
  blastRadiusScore: number;
}

const LIFECYCLE_STAGES: IncidentState[] = ['DETECTED', 'ANALYZING', 'CONTAINING', 'VERIFIED'];

export const AttackChainVisualizer: React.FC<VisualizerProps> = ({
  nodes,
  currentState,
  blastRadiusScore,
}) => {
  const getStageIndex = (state: IncidentState) => {
    return LIFECYCLE_STAGES.indexOf(state);
  };

  const currentIndex = getStageIndex(currentState);

  return (
    <div style={{ backgroundColor: '#1e293b', borderRadius: '8px', padding: '1.5rem', border: '1px solid #334155', color: '#f8fafc' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: '1.1rem', color: '#f1f5f9' }}>Attack Path & Lateral Movement Graph</h3>
          <p style={{ margin: '0.2rem 0 0 0', fontSize: '0.8rem', color: '#94a3b8' }}>
            Traversable permissions discovered via Amazon Neptune openCypher engine
          </p>
        </div>
        <div style={{ backgroundColor: '#0f172a', padding: '0.4rem 0.8rem', borderRadius: '4px', border: '1px solid #475569' }}>
          <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Blast Radius Impact: </span>
          <strong style={{ color: blastRadiusScore >= 70 ? '#ef4444' : '#f59e0b', fontSize: '0.95rem' }}>
            {blastRadiusScore}/100
          </strong>
        </div>
      </div>

      {/* Lifecycle Progression Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', margin: '1.5rem 0', backgroundColor: '#0f172a', padding: '1rem', borderRadius: '6px' }}>
        {LIFECYCLE_STAGES.map((stage, idx) => {
          const isDone = idx < currentIndex;
          const isCurrent = idx === currentIndex;
          let badgeColor = '#475569';
          let textColor = '#64748b';

          if (isDone) {
            badgeColor = '#10b981';
            textColor = '#10b981';
          } else if (isCurrent) {
            badgeColor = '#38bdf8';
            textColor = '#38bdf8';
          }

          return (
            <React.Fragment key={stage}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span
                  style={{
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    backgroundColor: badgeColor,
                    color: '#0f172a',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '0.75rem',
                    fontWeight: 700,
                  }}
                >
                  {isDone ? '✓' : idx + 1}
                </span>
                <span style={{ fontSize: '0.85rem', fontWeight: 600, color: textColor }}>
                  {stage}
                </span>
              </div>
              {idx < LIFECYCLE_STAGES.length - 1 && (
                <div style={{ flex: 1, height: '2px', backgroundColor: idx < currentIndex ? '#10b981' : '#334155', margin: '0 1rem' }} />
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* Nodes Linear Chain Representation */}
      <div style={{ display: 'flex', alignItems: 'center', overflowX: 'auto', padding: '1rem 0', gap: '0.75rem' }}>
        {nodes.map((node, i) => (
          <React.Fragment key={node.id}>
            <div
              style={{
                backgroundColor: node.is_compromised ? '#450a0a' : node.is_sensitive ? '#422006' : '#0f172a',
                border: `1.5px solid ${node.is_compromised ? '#ef4444' : node.is_sensitive ? '#f59e0b' : '#38bdf8'}`,
                borderRadius: '6px',
                padding: '0.75rem 1rem',
                minWidth: '180px',
              }}
            >
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase', display: 'flex', justifyContent: 'space-between' }}>
                <span>{node.node_type}</span>
                {node.is_sensitive && <span style={{ color: '#f59e0b', fontWeight: 700 }}>SENSITIVE</span>}
                {node.is_compromised && <span style={{ color: '#ef4444', fontWeight: 700 }}>COMPROMISED</span>}
              </div>
              <div style={{ fontWeight: 600, fontSize: '0.9rem', marginTop: '0.25rem', color: '#f8fafc', wordBreak: 'break-all' }}>
                {node.label}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.2rem' }}>
                Acc: {node.account_id}
              </div>
            </div>

            {i < nodes.length - 1 && (
              <div style={{ color: '#38bdf8', fontSize: '1.25rem', fontWeight: 700, padding: '0 0.25rem' }}>
                ➔
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
};
