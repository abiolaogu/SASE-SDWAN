import { Route, ArrowRight, Wifi, Circle } from 'lucide-react';

const tunnelsData = [
    {
        id: '1',
        name: 'pop-nyc-to-branch-a',
        source: { site: 'pop-nyc', interface: 'wg0' },
        destination: { site: 'branch-a', interface: 'wg0' },
        status: 'up',
        type: 'WireGuard',
        latency: '15ms',
        loss: '0.0%',
        bandwidth: '950 Mbps',
        uptime: '14d 5h'
    },
    {
        id: '2',
        name: 'pop-nyc-to-branch-b',
        source: { site: 'pop-nyc', interface: 'wg0' },
        destination: { site: 'branch-b', interface: 'wg0' },
        status: 'up',
        type: 'WireGuard',
        latency: '22ms',
        loss: '0.1%',
        bandwidth: '720 Mbps',
        uptime: '14d 5h'
    },
    {
        id: '3',
        name: 'pop-nyc-to-branch-c',
        source: { site: 'pop-nyc', interface: 'wg0' },
        destination: { site: 'branch-c', interface: 'wg0' },
        status: 'down',
        type: 'WireGuard',
        latency: '-',
        loss: '100%',
        bandwidth: '0 Mbps',
        uptime: '-'
    },
    {
        id: '4',
        name: 'branch-a-to-branch-b',
        source: { site: 'branch-a', interface: 'wg1' },
        destination: { site: 'branch-b', interface: 'wg1' },
        status: 'up',
        type: 'WireGuard',
        latency: '35ms',
        loss: '0.2%',
        bandwidth: '480 Mbps',
        uptime: '7d 12h'
    },
];

export default function Tunnels() {
    const upTunnels = tunnelsData.filter(t => t.status === 'up').length;
    const downTunnels = tunnelsData.filter(t => t.status === 'down').length;

    return (
        <div>
            <div className="page-header">
                <h2>Tunnels</h2>
                <p>SD-WAN overlay tunnel management</p>
            </div>

            {/* Stats */}
            <div className="stats-grid" style={{ marginBottom: '24px' }}>
                <div className="stat-card">
                    <div className="stat-icon green">
                        <Route size={24} />
                    </div>
                    <div className="stat-content">
                        <h3>{upTunnels}</h3>
                        <p>Tunnels Up</p>
                    </div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon red">
                        <Route size={24} />
                    </div>
                    <div className="stat-content">
                        <h3>{downTunnels}</h3>
                        <p>Tunnels Down</p>
                    </div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon blue">
                        <Wifi size={24} />
                    </div>
                    <div className="stat-content">
                        <h3>18.2ms</h3>
                        <p>Avg Latency</p>
                    </div>
                </div>
            </div>

            {/* Topology Visualization */}
            <div className="card" style={{ marginBottom: '24px' }}>
                <div className="card-header">
                    <h3 className="card-title">Network Topology</h3>
                </div>
                <div className="topology-map" style={{ padding: '40px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    {/* Simple topology visualization */}
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '40px' }}>
                        {/* Hub */}
                        <div style={{
                            padding: '20px 40px',
                            background: 'rgba(59, 130, 246, 0.15)',
                            borderRadius: '12px',
                            border: '2px solid var(--accent-primary)',
                            textAlign: 'center'
                        }}>
                            <div style={{ fontWeight: 600, marginBottom: '4px' }}>pop-nyc</div>
                            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Hub</div>
                        </div>

                        {/* Connections */}
                        <div style={{ display: 'flex', gap: '60px' }}>
                            {['branch-a', 'branch-b', 'branch-c'].map(branch => (
                                <div key={branch} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
                                    <div style={{ width: '2px', height: '30px', background: branch === 'branch-c' ? 'var(--accent-danger)' : 'var(--accent-success)' }} />
                                    <div style={{
                                        padding: '16px 24px',
                                        background: 'var(--bg-tertiary)',
                                        borderRadius: '12px',
                                        textAlign: 'center',
                                        border: `1px solid ${branch === 'branch-c' ? 'var(--accent-danger)' : 'var(--border-color)'}`
                                    }}>
                                        <div style={{ fontWeight: 600, marginBottom: '4px' }}>{branch}</div>
                                        <span className={`badge ${branch === 'branch-c' ? 'badge-danger' : 'badge-success'}`}>
                                            {branch === 'branch-c' ? 'offline' : 'online'}
                                        </span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            {/* Tunnels Table */}
            <div className="card">
                <div className="card-header">
                    <h3 className="card-title">All Tunnels</h3>
                    <button className="btn btn-primary">Create Tunnel</button>
                </div>
                <table className="data-table">
                    <thead>
                        <tr>
                            <th>Tunnel</th>
                            <th>Endpoints</th>
                            <th>Type</th>
                            <th>Status</th>
                            <th>Latency</th>
                            <th>Loss</th>
                            <th>Bandwidth</th>
                            <th>Uptime</th>
                        </tr>
                    </thead>
                    <tbody>
                        {tunnelsData.map(tunnel => (
                            <tr key={tunnel.id}>
                                <td style={{ fontWeight: 500 }}>{tunnel.name}</td>
                                <td>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                        <span>{tunnel.source.site}</span>
                                        <ArrowRight size={14} color="var(--text-secondary)" />
                                        <span>{tunnel.destination.site}</span>
                                    </div>
                                </td>
                                <td>{tunnel.type}</td>
                                <td>
                                    <span className={`badge ${tunnel.status === 'up' ? 'badge-success' : 'badge-danger'}`}>
                                        <Circle size={8} fill="currentColor" />
                                        {tunnel.status}
                                    </span>
                                </td>
                                <td>{tunnel.latency}</td>
                                <td style={{ color: parseFloat(tunnel.loss) > 1 ? 'var(--accent-danger)' : 'inherit' }}>
                                    {tunnel.loss}
                                </td>
                                <td>{tunnel.bandwidth}</td>
                                <td style={{ color: 'var(--text-secondary)' }}>{tunnel.uptime}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
