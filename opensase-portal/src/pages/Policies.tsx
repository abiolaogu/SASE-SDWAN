import { useState } from 'react';
import { FileText, Plus, Edit2, Trash2, Check, X } from 'lucide-react';

const policiesData = [
    {
        id: '1',
        name: 'corp-via-hub',
        description: 'Route corporate traffic via PoP for inspection',
        type: 'Routing',
        segment: 'corp',
        action: 'Route to Hub',
        priority: 100,
        enabled: true,
        sites: ['All Sites']
    },
    {
        id: '2',
        name: 'guest-local-breakout',
        description: 'Direct internet access for guest segment',
        type: 'Routing',
        segment: 'guest',
        action: 'Local Breakout',
        priority: 100,
        enabled: true,
        sites: ['branch-a', 'branch-b', 'branch-c']
    },
    {
        id: '3',
        name: 'voice-priority',
        description: 'Low latency path for VoIP traffic',
        type: 'QoS',
        segment: 'corp',
        action: 'Prefer MPLS',
        priority: 50,
        enabled: true,
        sites: ['All Sites']
    },
    {
        id: '4',
        name: 'block-social-media',
        description: 'Block social media on corporate segment',
        type: 'Security',
        segment: 'corp',
        action: 'Block',
        priority: 200,
        enabled: false,
        sites: ['branch-a']
    },
];

export default function Policies() {
    const [filter, setFilter] = useState<string>('all');

    const filteredPolicies = filter === 'all'
        ? policiesData
        : policiesData.filter(p => p.type.toLowerCase() === filter);

    return (
        <div>
            <div className="page-header">
                <h2>Policies</h2>
                <p>Unified policy management for SD-WAN and security</p>
            </div>

            {/* Filter Tabs */}
            <div style={{ display: 'flex', gap: '8px', marginBottom: '24px' }}>
                {['all', 'routing', 'security', 'qos'].map(tab => (
                    <button
                        key={tab}
                        onClick={() => setFilter(tab)}
                        className={`btn ${filter === tab ? 'btn-primary' : 'btn-secondary'}`}
                        style={{ textTransform: 'capitalize' }}
                    >
                        {tab === 'all' ? 'All Policies' : tab}
                    </button>
                ))}
                <div style={{ flex: 1 }} />
                <button className="btn btn-primary">
                    <Plus size={18} />
                    Create Policy
                </button>
            </div>

            {/* Policies Cards */}
            <div style={{ display: 'grid', gap: '16px' }}>
                {filteredPolicies.map(policy => (
                    <div key={policy.id} className="card" style={{
                        opacity: policy.enabled ? 1 : 0.6,
                        borderLeft: `3px solid ${policy.type === 'Routing' ? 'var(--accent-primary)' :
                                policy.type === 'Security' ? 'var(--accent-danger)' :
                                    'var(--accent-secondary)'
                            }`
                    }}>
                        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                            <div style={{ display: 'flex', gap: '16px', alignItems: 'flex-start' }}>
                                <div style={{
                                    width: '44px',
                                    height: '44px',
                                    borderRadius: '10px',
                                    background: 'var(--bg-tertiary)',
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'center'
                                }}>
                                    <FileText size={22} />
                                </div>
                                <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '4px' }}>
                                        <h4 style={{ fontSize: '16px', fontWeight: 600 }}>{policy.name}</h4>
                                        <span className={`badge ${policy.type === 'Routing' ? 'badge-info' :
                                                policy.type === 'Security' ? 'badge-danger' :
                                                    'badge-success'
                                            }`}>
                                            {policy.type}
                                        </span>
                                        {!policy.enabled && (
                                            <span className="badge" style={{ background: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                                                Disabled
                                            </span>
                                        )}
                                    </div>
                                    <p style={{ color: 'var(--text-secondary)', marginBottom: '12px' }}>
                                        {policy.description}
                                    </p>
                                    <div style={{ display: 'flex', gap: '24px', fontSize: '14px' }}>
                                        <div>
                                            <span style={{ color: 'var(--text-secondary)' }}>Segment: </span>
                                            <span style={{ fontWeight: 500 }}>{policy.segment}</span>
                                        </div>
                                        <div>
                                            <span style={{ color: 'var(--text-secondary)' }}>Action: </span>
                                            <span style={{ fontWeight: 500 }}>{policy.action}</span>
                                        </div>
                                        <div>
                                            <span style={{ color: 'var(--text-secondary)' }}>Priority: </span>
                                            <span style={{ fontWeight: 500 }}>{policy.priority}</span>
                                        </div>
                                        <div>
                                            <span style={{ color: 'var(--text-secondary)' }}>Sites: </span>
                                            <span style={{ fontWeight: 500 }}>{policy.sites.join(', ')}</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div style={{ display: 'flex', gap: '8px' }}>
                                <button className="btn btn-secondary" style={{ padding: '8px' }}>
                                    <Edit2 size={16} />
                                </button>
                                <button className="btn btn-secondary" style={{ padding: '8px' }}>
                                    {policy.enabled ? <X size={16} /> : <Check size={16} />}
                                </button>
                                <button className="btn btn-secondary" style={{ padding: '8px', color: 'var(--accent-danger)' }}>
                                    <Trash2 size={16} />
                                </button>
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}
