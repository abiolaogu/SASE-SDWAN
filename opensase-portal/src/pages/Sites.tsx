import { useState } from 'react';
import { Network, MapPin, Wifi, WifiOff, Plus, Search } from 'lucide-react';

const sitesData = [
    {
        id: '1',
        name: 'pop-nyc',
        type: 'Hub',
        location: 'New York, US',
        status: 'online',
        devices: 2,
        wanLinks: [
            { name: 'WAN1', status: 'up', bandwidth: '10 Gbps', latency: '2ms' },
            { name: 'WAN2', status: 'up', bandwidth: '10 Gbps', latency: '3ms' }
        ],
        segments: ['corp', 'guest'],
        tunnels: 5,
        throughput: '45.2 Gbps'
    },
    {
        id: '2',
        name: 'branch-a',
        type: 'Branch',
        location: 'Los Angeles, US',
        status: 'online',
        devices: 1,
        wanLinks: [
            { name: 'WAN1', status: 'up', bandwidth: '1 Gbps', latency: '15ms' },
            { name: 'WAN2', status: 'up', bandwidth: '500 Mbps', latency: '18ms' }
        ],
        segments: ['corp', 'guest'],
        tunnels: 2,
        throughput: '850 Mbps'
    },
    {
        id: '3',
        name: 'branch-b',
        type: 'Branch',
        location: 'Chicago, US',
        status: 'online',
        devices: 1,
        wanLinks: [
            { name: 'WAN1', status: 'up', bandwidth: '1 Gbps', latency: '22ms' },
            { name: 'WAN2', status: 'down', bandwidth: '500 Mbps', latency: '-' }
        ],
        segments: ['corp'],
        tunnels: 2,
        throughput: '720 Mbps'
    },
    {
        id: '4',
        name: 'branch-c',
        type: 'Branch',
        location: 'Miami, US',
        status: 'offline',
        devices: 1,
        wanLinks: [
            { name: 'WAN1', status: 'down', bandwidth: '1 Gbps', latency: '-' },
            { name: 'WAN2', status: 'down', bandwidth: '500 Mbps', latency: '-' }
        ],
        segments: ['corp', 'guest'],
        tunnels: 0,
        throughput: '0 Mbps'
    },
];

export default function Sites() {
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedSite, setSelectedSite] = useState<string | null>(null);

    const filteredSites = sitesData.filter(site =>
        site.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        site.location.toLowerCase().includes(searchQuery.toLowerCase())
    );

    const selectedSiteData = sitesData.find(s => s.id === selectedSite);

    return (
        <div>
            <div className="page-header">
                <h2>Sites & Devices</h2>
                <p>Manage your SD-WAN sites and edge devices</p>
            </div>

            {/* Actions Bar */}
            <div style={{ display: 'flex', gap: '12px', marginBottom: '24px' }}>
                <div style={{
                    flex: 1,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    background: 'var(--bg-secondary)',
                    padding: '10px 16px',
                    borderRadius: '8px',
                    border: '1px solid var(--border-color)'
                }}>
                    <Search size={18} color="var(--text-secondary)" />
                    <input
                        type="text"
                        placeholder="Search sites..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        style={{
                            background: 'transparent',
                            border: 'none',
                            outline: 'none',
                            color: 'var(--text-primary)',
                            fontSize: '14px',
                            flex: 1
                        }}
                    />
                </div>
                <button className="btn btn-primary">
                    <Plus size={18} />
                    Add Site
                </button>
            </div>

            <div className="grid-2">
                {/* Sites List */}
                <div className="card">
                    <div className="card-header">
                        <h3 className="card-title">All Sites ({filteredSites.length})</h3>
                    </div>
                    <div>
                        {filteredSites.map(site => (
                            <div
                                key={site.id}
                                onClick={() => setSelectedSite(site.id)}
                                style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '12px',
                                    padding: '16px',
                                    borderRadius: '8px',
                                    cursor: 'pointer',
                                    background: selectedSite === site.id ? 'var(--bg-tertiary)' : 'transparent',
                                    marginBottom: '8px',
                                    transition: 'var(--transition-fast)'
                                }}
                            >
                                <div style={{
                                    width: '40px',
                                    height: '40px',
                                    borderRadius: '8px',
                                    background: site.status === 'online' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    color: site.status === 'online' ? 'var(--accent-success)' : 'var(--accent-danger)'
                                }}>
                                    {site.status === 'online' ? <Wifi size={20} /> : <WifiOff size={20} />}
                                </div>
                                <div style={{ flex: 1 }}>
                                    <div style={{ fontWeight: 600 }}>{site.name}</div>
                                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                        <MapPin size={12} /> {site.location}
                                    </div>
                                </div>
                                <span className={`badge ${site.type === 'Hub' ? 'badge-info' : 'badge-success'}`}>
                                    {site.type}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Site Details */}
                <div className="card">
                    <div className="card-header">
                        <h3 className="card-title">Site Details</h3>
                    </div>
                    {selectedSiteData ? (
                        <div>
                            <div style={{ marginBottom: '20px' }}>
                                <h4 style={{ fontSize: '20px', marginBottom: '4px' }}>{selectedSiteData.name}</h4>
                                <p style={{ color: 'var(--text-secondary)' }}>{selectedSiteData.location}</p>
                            </div>

                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px' }}>
                                <div style={{ padding: '12px', background: 'var(--bg-tertiary)', borderRadius: '8px' }}>
                                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Throughput</div>
                                    <div style={{ fontSize: '18px', fontWeight: 600 }}>{selectedSiteData.throughput}</div>
                                </div>
                                <div style={{ padding: '12px', background: 'var(--bg-tertiary)', borderRadius: '8px' }}>
                                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Active Tunnels</div>
                                    <div style={{ fontSize: '18px', fontWeight: 600 }}>{selectedSiteData.tunnels}</div>
                                </div>
                            </div>

                            <h5 style={{ marginBottom: '12px', color: 'var(--text-secondary)', fontSize: '12px', textTransform: 'uppercase' }}>
                                WAN Links
                            </h5>
                            {selectedSiteData.wanLinks.map(wan => (
                                <div key={wan.name} style={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    padding: '12px',
                                    background: 'var(--bg-tertiary)',
                                    borderRadius: '8px',
                                    marginBottom: '8px'
                                }}>
                                    <div>
                                        <div style={{ fontWeight: 500 }}>{wan.name}</div>
                                        <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                                            {wan.bandwidth} • {wan.latency} latency
                                        </div>
                                    </div>
                                    <span className={`badge ${wan.status === 'up' ? 'badge-success' : 'badge-danger'}`}>
                                        {wan.status}
                                    </span>
                                </div>
                            ))}

                            <h5 style={{ marginTop: '20px', marginBottom: '12px', color: 'var(--text-secondary)', fontSize: '12px', textTransform: 'uppercase' }}>
                                Segments
                            </h5>
                            <div style={{ display: 'flex', gap: '8px' }}>
                                {selectedSiteData.segments.map(seg => (
                                    <span key={seg} className="badge badge-info">{seg}</span>
                                ))}
                            </div>
                        </div>
                    ) : (
                        <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-secondary)' }}>
                            <Network size={48} style={{ opacity: 0.5, marginBottom: '12px' }} />
                            <p>Select a site to view details</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
